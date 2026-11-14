"""Compact ONLY the helper's disposable baseline, then enforce real tmpfs reserve."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import time

ROOT = Path('/tmp/openclaw-worktree-test')
RECEIPT = Path('/tmp/b-capacity-admission')
CAP = 3 * 1024**3
RESERVE = 1024**3
MARGIN = 64 * 1024**2


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def space(path):
    s = os.statvfs(path)
    return s.f_blocks * s.f_frsize, s.f_bavail * s.f_frsize


def capacity(total, available, needed):
    require(0 < total <= CAP and 0 <= available <= total, 'tmpfs capacity outside bound')
    require(available >= needed, 'insufficient available bytes: %s < %s' % (available, needed))


def git(root, *args):
    env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
    env.update(GIT_NO_LAZY_FETCH='1', GIT_OPTIONAL_LOCKS='0', GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null')
    return subprocess.check_output(['git', '-C', str(root), *args], env=env, timeout=120)


def safe_root(root):
    require(root == ROOT and root.resolve() == root and not root.is_symlink(), 'unsafe source root')
    gd = root / '.git'
    require(gd.is_dir() and not gd.is_symlink() and gd.resolve() == gd, 'unsafe Git root')
    require(git(root, 'rev-parse', '--absolute-git-dir').decode().strip() == str(gd), 'external Git directory')
    require(git(root, 'rev-parse', '--git-common-dir').decode().strip() in ('.git', str(gd)), 'external common directory')
    require(git(root, 'rev-parse', '--show-toplevel').decode().strip() == str(root), 'wrong Git worktree')
    for base, dirs, files in os.walk(gd):
        for name in dirs + files:
            require(not (Path(base) / name).is_symlink(), 'symlink in disposable Git metadata')
    require(not (gd / 'objects/info/alternates').exists(), 'external alternates')
    require(not (gd / 'objects/info/http-alternates').exists(), 'external HTTP alternates')
    require(not git(root, 'remote').strip(), 'disposable Git has remotes')
    require(git(root, 'log', '-1', '--format=%B') == b'isolated validation baseline\n\n', 'wrong baseline message')
    require(git(root, 'rev-list', '--count', 'HEAD').strip() == b'1', 'baseline has ancestry')


def state(root):
    require(not git(root, 'status', '--porcelain', '--untracked-files=no').strip(), 'baseline not clean')
    return {'head': git(root, 'rev-parse', 'HEAD').decode().strip(),
            'tree': git(root, 'rev-parse', 'HEAD^{tree}').decode().strip(),
            'indexSha256': hashlib.sha256((root / '.git/index').read_bytes()).hexdigest(),
            'refs': git(root, 'show-ref').decode()}


def object_bytes(root):
    rows = git(root, 'cat-file', '--batch-all-objects', '--batch-check=%(objectsize)').splitlines()
    require(rows and len(rows) <= 100000, 'object count outside bound')
    require(all(re.fullmatch(rb'[0-9]+', x) for x in rows), 'invalid object sizes')
    return sum(map(int, rows))


def diagnostic(root, phase, total, available, uncompressed, m, image, digest):
    gd = root / '.git'
    allocated = {'pack': 0, 'loose': 0, 'other': 0}
    counts = {'pack': 0, 'loose': 0, 'other': 0}
    for base, dirs, files in os.walk(gd):
        for name in files:
            path = Path(base) / name
            rel = path.relative_to(gd).parts
            category = ('pack' if rel[:2] == ('objects', 'pack') else
                        'loose' if len(rel) == 3 and rel[0] == 'objects' and re.fullmatch(r'[0-9a-f]{2}', rel[1]) else 'other')
            st = path.stat(follow_symlinks=False)
            allocated[category] += st.st_blocks * 512
            counts[category] += 1
            require(sum(counts.values()) <= 200000, 'Git metadata file count outside bound')
    idx = gd / 'index'
    row = {'schema': 1, 'status': 'DIAGNOSTIC_ONLY', 'phase': phase,
           'source': m['source'], 'sourceTree': m['tree'], 'workflow': m['workflow'],
           'imageId': image, 'manifestSha256': digest,
           'capacityBytes': total, 'availableBytes': available,
           'gitObjectCounts': git(root, 'count-objects', '-v').decode().splitlines(),
           'gitDirAllocatedBytes': allocated, 'gitDirFileCounts': counts,
           'indexBytes': idx.stat().st_size if idx.exists() else 0,
           'gitUncompressedBytes': uncompressed,
           'prepackRequiredBytes': uncompressed + MARGIN,
           'worstTemporaryPackGrowthBytes': uncompressed + MARGIN,
           'generatedReserveBytes': RESERVE}
    require(len(row['gitObjectCounts']) <= 16 and all(len(x) <= 128 for x in row['gitObjectCounts']), 'object diagnostics outside bound')
    print(json.dumps(row, sort_keys=True), flush=True)


def admit(root, image, digest, receipt):
    require(re.fullmatch(r'sha256:[0-9a-f]{64}', image), 'invalid image identity')
    require(re.fullmatch(r'[0-9a-f]{64}', digest), 'invalid manifest digest')
    require(not receipt.exists() and not receipt.is_symlink(), 'stale admission receipt')
    safe_root(root)
    # The sealed full-source verifier is also run by the caller's EXIT trap.
    spec = importlib.util.spec_from_file_location('b_guard', root / '.github/qualification/b-tree-guard.py')
    guard = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(guard)
    manifest = root / '.github/qualification/b-full-source.json'
    m = guard.load_manifest(manifest, digest)
    m['requireProjector'] = True
    guard.verify(root, m)
    before = state(root)
    total, available = space('/tmp')
    require(space(root)[0] == total and os.stat(root).st_dev == os.stat('/tmp').st_dev, 'source not on tmp filesystem')
    # Linux mountinfo is authoritative: do not admit disk-backed or oversized /tmp.
    mounts = Path('/proc/self/mountinfo').read_text().splitlines()
    require(any(row.split()[4] == '/tmp' and row.split(' - ', 1)[1].split()[0] == 'tmpfs' for row in mounts), '/tmp is not tmpfs')
    uncompressed = object_bytes(root)
    diagnostic(root, 'BEFORE_PACK', total, available, uncompressed, m, image, digest)
    capacity(total, available, uncompressed + MARGIN)
    git(root, '-c', 'pack.threads=1', '-c', 'pack.window=10', '-c', 'pack.depth=20', '-c', 'pack.windowMemory=16m',
        '-c', 'pack.deltaCacheSize=16m', '-c', 'core.compression=6', 'repack', '-a', '-d', '-f', '--no-write-bitmap-index')
    safe_root(root)
    require(state(root) == before, 'baseline HEAD/tree/index/refs changed')
    guard.verify(root, m)
    post_total, post_available = space('/tmp')
    diagnostic(root, 'AFTER_PACK', post_total, post_available, uncompressed, m, image, digest)
    require(post_total == total, 'filesystem capacity changed')
    capacity(post_total, post_available, RESERVE)
    data = {'schema': 1, 'status': 'ADMITTED', 'source': m['source'], 'sourceTree': m['tree'],
            'workflow': m['workflow'], 'imageId': image, 'manifestSha256': digest,
            'baseline': before, 'capacityBytes': total, 'preAvailableBytes': available,
            'gitUncompressedBytes': uncompressed, 'prepackRequiredBytes': uncompressed + MARGIN,
            'postAvailableBytes': post_available, 'generatedReserveBytes': RESERVE,
            'createdNs': time.time_ns()}
    # Atomic exclusive publication: an old receipt can never authorize this run.
    temp = receipt.with_name(receipt.name + '.tmp')
    owned_temp = False
    try:
        with temp.open('x') as f:
            owned_temp = True
            json.dump(data, f, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        final_total, final_available = space('/tmp')
        require(final_total == total, 'filesystem capacity changed')
        capacity(final_total, final_available, RESERVE)
        os.link(temp, receipt)
    finally:
        if owned_temp:
            temp.unlink()
    print(json.dumps(data, sort_keys=True))
    return data


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--image-id', required=True)
    p.add_argument('--manifest-sha', required=True)
    args = p.parse_args()
    admit(ROOT, args.image_id, args.manifest_sha, RECEIPT)
