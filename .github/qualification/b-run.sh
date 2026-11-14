#!/usr/bin/env bash
set -euo pipefail
[[ $# -eq 4 && "$1" == --image-id && "$2" =~ ^sha256:[0-9a-f]{64}$ && "$3" == --manifest-sha && "$4" =~ ^[0-9a-f]{64}$ ]]
manifest_sha=$4
image_id=$2
export CI=true OPENCLAW_BUILD_ALL_NO_PNPM=1 COREPACK_ENABLE_NETWORK=0
test "$(node -p process.versions.node)" = 24.16.0
test "$(pnpm --version)" = 12.9.0
export B_EXPECTED_TESTS='["ui/src/pages/chat/chat-composer-queue.test.ts","ui/src/pages/chat/chat-thread-input-order.test.ts","ui/src/pages/chat/chat-pending-inputs.test.ts","ui/src/pages/chat/user-message-content.test.ts"]'
export B_INVENTORY_DIR=/tmp/b-inventory

test ! -e "$B_INVENTORY_DIR"
mkdir "$B_INVENTORY_DIR"
export GIT_COMMIT=$(cat .github/qualification/input-source-sha)
[[ "$GIT_COMMIT" =~ ^[0-9a-f]{40}$ ]]
manifest_path="$PWD/.github/qualification/b-full-source.json"
python3 .github/qualification/b-tree-guard.py verify . "$manifest_path" "$manifest_sha"
cp .github/qualification/b-tree-guard.py /tmp/b-sealed-tree-guard.py
sealed_sha=$(sha256sum /tmp/b-sealed-tree-guard.py | cut -d' ' -f1)
trap 'status=$?; trap - EXIT; if echo "$sealed_sha  /tmp/b-sealed-tree-guard.py" | sha256sum -c -; then python3 /tmp/b-sealed-tree-guard.py verify "$PWD" "$manifest_path" "$manifest_sha" || status=1; else status=1; fi; exit "$status"' EXIT
python3 -B .github/qualification/b-capacity-admit.py --image-id "$image_id" --manifest-sha "$manifest_sha"
node .github/qualification/b-project-ui.mjs
python3 .github/qualification/b-expect-probe.py --image-id "$image_id"
python3 .github/qualification/b-source-check.py .
files=(ui/src/i18n/locales/en.ts ui/src/pages/chat/chat-composer-queue.test.ts ui/src/pages/chat/chat-thread-inputs.ts ui/src/pages/chat/chat-thread-items.ts ui/src/pages/chat/components/chat-composer-queue.ts ui/src/pages/chat/user-message-content.ts)
if pnpm exec oxfmt --check "${files[@]}"; then
  :
else
  format_status=$?
  # Diagnostic-only, never normalizes or writes immutable source.
  python3 -B - <<'B_FORMAT_REPAIR_PY' || echo "B_FORMAT_REPAIR_DIAGNOSTIC_FAILED (original formatter failure retained)" >&2
import base64, hashlib, json, os, pathlib, re, signal, subprocess, time
class DiagnosticInterrupted(Exception): pass
def interrupted(signum, frame):
    raise DiagnosticInterrupted('diagnostic signal '+str(signum))
CLEANUP_SIGNALS = {signal.SIGALRM, signal.SIGTERM}
for sig in CLEANUP_SIGNALS: signal.signal(sig, interrupted)
signal.alarm(30)
root = pathlib.Path.cwd()
def sha(b): return hashlib.sha256(b).hexdigest()
def read_bounded(p):
    with p.open('rb') as f: b = f.read(65537)
    assert len(b) <= 65536, 'input/config size cap'
    return b
def configs():
    paths = sorted(p for d in (root, root/'ui') for p in d.glob('.oxfmtrc.*'))
    assert len(paths) <= 16, 'config count cap'
    return {str(p.relative_to(root)): sha(read_bounded(p)) for p in paths if p.is_file()}
def run(args, data=None):
    # Pipes are drained with a hard byte ceiling, not unbounded capture_output.
    import selectors
    # Block termination across spawn/registration, so finally owns every new session.
    old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, CLEANUP_SIGNALS)
    p = None
    sel = None
    try:
        p = subprocess.Popen(args, cwd=root, stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        pgid = p.pid
        assert pgid > 1 and pgid != os.getpgrp()
        signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
        if data is not None:
            # At most 64 KiB; communicate writer runs independently of pipe readers.
            import threading
            def feed():
                try: p.stdin.write(data); p.stdin.close()
                except BrokenPipeError: pass
            threading.Thread(target=feed, daemon=True).start()
        sel = selectors.DefaultSelector()
        for pipe in (p.stdout, p.stderr): sel.register(pipe, selectors.EVENT_READ)
        outputs = {p.stdout: bytearray(), p.stderr: bytearray()}; deadline = time.monotonic()+10
        while sel.get_map():
            assert time.monotonic() < deadline, 'child deadline'
            for key, _ in sel.select(min(.1, max(0, deadline-time.monotonic()))):
                chunk = os.read(key.fileobj.fileno(), 8192)
                if not chunk: sel.unregister(key.fileobj); continue
                outputs[key.fileobj].extend(chunk)
                assert len(outputs[key.fileobj]) <= 65536, 'child output cap'
        assert p.wait(timeout=max(.01, deadline-time.monotonic())) == 0, 'formatter nonzero'
        return bytes(outputs[p.stdout])
    finally:
        # Both signals stay blocked until bounded teardown completes. A pending signal
        # may raise only after the owned group has been killed and leader reaped.
        signal.pthread_sigmask(signal.SIG_BLOCK, CLEANUP_SIGNALS)
        try:
            if p is not None:
                assert p.pid > 1 and p.pid != os.getpgrp()
                def send_group(sig):
                    try: os.killpg(p.pid, sig)
                    except ProcessLookupError: pass
                send_group(signal.SIGTERM)
                time.sleep(0.1)
                # Always kill the group, even when pnpm already exited successfully.
                send_group(signal.SIGKILL)
                p.wait(timeout=1)
                if sel is not None: sel.close()
                if p.stdin is not None: p.stdin.close()
                p.stdout.close(); p.stderr.close()
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
manifest_bytes = read_bounded(root/'.github/qualification/b-manifest.json')
manifest = json.loads(manifest_bytes)
assert manifest['inputSourceSha'] == 'eabe9c6c7a0d56b401f6b7abe600e5736efd7984'
paths = ['ui/src/pages/chat/chat-composer-queue.test.ts', 'ui/src/pages/chat/user-message-content.ts']
pre = {path: read_bounded(root/path) for path in paths}
for path, b in pre.items(): assert sha(b) == manifest['sourcePins'][path], 'source preimage pin'
before = configs()
version_stdout = run(['pnpm','exec','oxfmt','--version'])
version_receipt = {'schema':1,'name':'oxfmt','source':manifest['inputSourceSha'],'tree':'6020382bb65c9e29f3c7b778173747553da95235','stdoutBytes':len(version_stdout),'stdoutBase64':base64.b64encode(version_stdout[:96]).decode(),'decodedText':version_stdout[:96].decode('utf-8',errors='backslashreplace'),'truncated':len(version_stdout)>96}
version_line = 'B_FORMAT_REPAIR_VERSION='+json.dumps(version_receipt,sort_keys=True,separators=(',',':'),ensure_ascii=True)
assert len(version_line.encode()) <= 1024, 'version receipt cap'
print(version_line, flush=True)
assert len(version_stdout) <= 96, 'version stdout cap'
version = version_stdout.decode('utf-8').strip()
assert version in ('0.71.0', 'oxfmt 0.71.0', 'Version: 0.71.0'), 'wrong pinned formatter version'
records = []
for path in paths:
    args = ['pnpm','exec','oxfmt','--stdin-filepath='+path,'--threads=1']
    post = run(args, pre[path])
    assert post and b'\0' not in post, 'empty/NUL output'
    post.decode('utf-8')
    assert run(args, post) == post, 'nonidempotent formatter output'
    records.append({'schema':1,'status':'DIAGNOSTIC_ONLY_NOT_PRODUCT_PASS','source':manifest['inputSourceSha'],'tree':'6020382bb65c9e29f3c7b778173747553da95235','workflow':os.environ.get('GITHUB_SHA'),'currentManifestSha256':sha(manifest_bytes),'version':'0.71.0','path':path,'preSha256':sha(pre[path]),'postSha256':sha(post),'postBytes':len(post),'base64output':base64.b64encode(post).decode(),'base64configFingerprint':base64.b64encode(json.dumps(before,sort_keys=True,separators=(',',':')).encode()).decode()})
assert configs() == before, 'config changed'
for path in paths: assert read_bounded(root/path) == pre[path], 'source changed'
lines = ['B_FORMAT_REPAIR_POSTIMAGE='+json.dumps(row,sort_keys=True,separators=(',',':')) for row in records]
assert sum(len(line.encode())+1 for line in lines) < 80*1024, 'combined receipt cap'
print('\n'.join(lines), flush=True)
B_FORMAT_REPAIR_PY
  exit "$format_status"
fi
pnpm exec oxlint --tsconfig ui/tsconfig.json "${files[@]}"
pnpm test ui/src/pages/chat/chat-composer-queue.test.ts ui/src/pages/chat/chat-thread-input-order.test.ts ui/src/pages/chat/chat-pending-inputs.test.ts ui/src/pages/chat/user-message-content.test.ts --maxWorkers=1 -- --expect.requireAssertions --reporter=default --reporter="$PWD/.github/qualification/b-inventory-reporter.mjs"
node .github/qualification/b-inventory-check.mjs
pnpm tsgo:ui
pnpm tsgo:test:ui
pnpm ui:build
python3 .github/qualification/b-source-check.py .
