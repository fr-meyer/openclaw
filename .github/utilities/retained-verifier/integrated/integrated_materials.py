"""Pure deterministic current-build runtime and guest-source byte packaging.

These helpers validate representations only. A genuine bootstrap capability and
Prepared instance must supply their source bytes; no JSON verdict grants trust.
"""
from __future__ import annotations

import gzip
import hashlib
from io import BytesIO
import json
from pathlib import PurePosixPath
import re
import tarfile

ARCHIVE_CAP = 64 * 1024 * 1024
EXPANDED_CAP = 100 * 1024 * 1024
SOURCE_CAP = 64 * 1024 * 1024
MANIFEST_CAP = 16384
SOURCE_FILES_MAX = 128
MATERIALS = {
    'archive': ('public-runtime/public-tooling.tar.gz', ARCHIVE_CAP),
    'verification': ('public-runtime/ATTESTATION-VERIFIED.private.json', 16384),
    'host': ('public-runtime/host-result.json', 262144),
    'exact': ('public-runtime/exact-worker-result.json', 16384),
    'roster': ('public-runtime/PUBLIC-RUNTIME-ROSTER.private.json', 262144),
}
CODE_NAMES = ('worker.py', 'protocol.py', 'hosted_export.py', 'hosted_privacy.py',
              'public-member-comparisons-v105-workboard.json')


class Refusal(ValueError):
    pass


def need(ok, code):
    if not ok: raise Refusal(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def sha(raw):
    need(type(raw) is bytes, 'integrated_materials.bytes')
    return hashlib.sha256(raw).hexdigest()


def path(name):
    need(type(name) is str and 0 < len(name) <= 256 and not name.startswith('/') and
         re.fullmatch('[A-Za-z0-9_./+-]+', name) and str(PurePosixPath(name)) == name and
         not {'.', '..'} & set(PurePosixPath(name).parts), 'integrated_materials.path')
    return name


def archive_bytes(files):
    need(type(files) is dict and 0 < len(files) <= 8192, 'integrated_materials.roster')
    total = 0
    for name, row in files.items():
        path(name)
        need(type(row) is tuple and len(row) == 2 and type(row[0]) is bytes and
             type(row[1]) is int and row[1] in (0o444, 0o555), 'integrated_materials.row')
        total += len(row[0]); need(total <= EXPANDED_CAP, 'integrated_materials.expanded_cap')
    need(all('/'.join(PurePosixPath(name).parts[:i]) not in files for name in files
             for i in range(1, len(PurePosixPath(name).parts))), 'integrated_materials.file_parent')
    output = BytesIO()
    with gzip.GzipFile(fileobj=output, mode='wb', mtime=0, filename='') as compressed:
        with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.PAX_FORMAT) as archive:
            for name, (raw, mode) in sorted(files.items()):
                member = tarfile.TarInfo(name); member.size = len(raw); member.mode = mode
                member.uid = member.gid = member.mtime = 0; member.uname = member.gname = ''
                archive.addfile(member, BytesIO(raw))
    raw = output.getvalue(); need(len(raw) <= ARCHIVE_CAP, 'integrated_materials.archive_cap')
    return raw


def runtime_archive(rows, payloads):
    need(type(rows) is list and 0 < len(rows) <= 8192 and type(payloads) is dict,
         'integrated_materials.runtime_count')
    files, result, total = {}, [], 0
    for row in rows:
        need(type(row) is dict and set(row) == {'path', 'archivePath', 'bytes', 'sha256', 'mode'},
             'integrated_materials.runtime_row')
        name = path(row['path']); archive_name = path(row['archivePath'])
        need(name == 'code/static-entry' or name.startswith(('usr/', 'lib/', 'lib64/')),
             'integrated_materials.runtime_path')
        need(archive_name == ('static-entry' if name == 'code/static-entry' else 'runtime/' + name) and
             archive_name not in files and type(row['bytes']) is int and
             0 <= row['bytes'] <= 32*1024*1024 and type(row['mode']) is int and
             row['mode'] in (0o444, 0o555) and type(row['sha256']) is str and
             re.fullmatch('[0-9a-f]{64}', row['sha256']), 'integrated_materials.runtime_shape')
        raw = payloads.get(name)
        need(type(raw) is bytes and len(raw) == row['bytes'] and sha(raw) == row['sha256'],
             'integrated_materials.runtime_pin')
        files[archive_name] = (raw, row['mode']); result.append(dict(row)); total += len(raw)
    names = {row['path'] for row in result}
    need(len(names) == len(rows) and names == set(payloads) and total <= EXPANDED_CAP and
         {'usr/bin/python3.11', 'lib64/ld-linux-x86-64.so.2', 'code/static-entry'} <= names,
         'integrated_materials.runtime_closure')
    return archive_bytes(files), sorted(result, key=lambda row: row['path'])


def current_runtime_materials(rows, payloads, origin):
    """Byte representation only; `origin` is never an authenticity permit."""
    keys = {'schema', 'sourceCommit', 'runId', 'sourceManifestSha256', 'bootId',
            'runtimeControlSha256', 'toolControlSha256', 'metadataProofSha256',
            'compatibilitySha256', 'qualificationProofComplete', 'nativeAuthorityFromReceipt'}
    need(type(origin) is dict and set(origin) == keys and
         origin['schema'] == 'ocv.current-authenticated-bootstrap-origin.v1' and
         origin['qualificationProofComplete'] is False and origin['nativeAuthorityFromReceipt'] is False,
         'integrated_materials.origin_schema')
    archive, rows = runtime_archive(rows, payloads)
    materials = {'archive': archive, 'verification': canonical(origin),
        'host': canonical(dict(origin, schema='ocv.current-bootstrap-host-binding.v1')),
        'exact': canonical(dict(origin, schema='ocv.integrated-proof-pending.v1')),
        'roster': canonical({'schema': 'ocv.current-build-runtime-roster.v1',
                             'privateWorkerIncluded': False, 'files': rows})}
    need(all(type(materials[role]) is bytes and 0 < len(materials[role]) <= cap
             for role, (_name, cap) in MATERIALS.items()), 'integrated_materials.material_caps')
    return materials, rows


def bundle_payloads(exported, runtime_materials):
    need(type(exported) is dict and 'PUBLIC-INTEGRATED-SOURCE-MANIFEST.json' in exported and
         type(runtime_materials) is dict and set(runtime_materials) == set(MATERIALS),
         'integrated_materials.bundle_inputs')
    files = {}
    for name, raw in exported.items():
        path(name)
        need(type(raw) is bytes and len(raw) <= 262144, 'integrated_materials.source_file_cap')
        # The source loader and native components share this physical guest/
        # tree. Fixture-only disk seed data stays in the separately built TEST.
        if not name.startswith('fixture/'):
            files['guest/' + name] = raw
    for name in CODE_NAMES:
        need(name in exported, 'integrated_materials.code_missing')
        files['code/' + name] = exported[name]
    for role, (name, cap) in MATERIALS.items():
        raw = runtime_materials[role]
        need(type(raw) is bytes and 0 < len(raw) <= cap, 'integrated_materials.material_cap')
        files[name] = raw
    need(len(files) <= SOURCE_FILES_MAX and sum(len(v) for v in files.values()) <= SOURCE_CAP,
         'integrated_materials.bundle_cap')
    rows = [{'path': name, 'bytes': len(raw), 'sha256': sha(raw), 'mode': 0o444}
            for name, raw in sorted(files.items())]
    closure = sha(canonical(rows))
    manifest = canonical({'schema': 'openclaw.native-guest-source-bundle.v1',
        'files': rows, 'sourceClosureSha256': closure})
    need(len(manifest) <= MANIFEST_CAP, 'integrated_materials.manifest_cap')
    files['SOURCE-MANIFEST.private.json'] = manifest
    return files, {'sourceClosureSha256': closure, 'sourceManifestSha256': sha(manifest)}


if __name__ == '__main__': raise SystemExit('integrated_materials_inert')
