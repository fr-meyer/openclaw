"""Inert, offline inspection of the three signed run57 public subjects.

This code does not verify a new signature, stage files, launch processes, or
issue private admission. The saved gh verification receipt and every input are
accepted only at independently reviewed, source-fixed digests.
"""
from __future__ import annotations

from io import BytesIO
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import tarfile

ARMED = False
SOURCE_COMMIT = '7f2a6a7890a40e2738aa335bfa8f66d746be83c1'
RUN_ID = '40623663825'
ARCHIVE_SHA256 = '5a8697e732bf828ddab6edff69b68773e8aab51d6a014afc45fce3128b48b1a7'
VERIFICATION_SHA256 = '847f1fe66092ec2932b0f6700fdb8104bae8039075372ec2b27c799c8b86cf17'
HOST_RESULT_SHA256 = '8af49bec2bcc83d42c07ef0c3f934e0bbbc7950b98719978f2cf7fcdc45cce49'
EXACT_RESULT_SHA256 = '4b56e297abd8b0bb680540ec81cc182785c8be7cd389def01e597f84805c478f'
TOOLING_MANIFEST_SHA256 = '4fbc8cc499d5bcec09838845e237e8cee583ed904537201d97c6ded8c5805400'
RUNTIME_ROSTER_SHA256 = '7f88704bfd36136cf8d8a8aad44d549f92b270a13da235dda4601e393f395f8b'
GENERIC_SOURCE_SHA256 = '6463a0d0e25b0fb2b2ecde3f39b10f9d08032c4b48344a0ecbc5913d1c45a065'
PROFILE_SHA256 = 'b8a07a61d42f685a8fd557c80f8f39e991f6089c3130c934a0bbf2bc4a7945e7'
WORKER_SHA256 = 'ed1c9906e49c762caaf68056e2e4697c426c629d094953dc2011bca3e7f57a69'
PROTOCOL_SHA256 = 'df3ad90e894610f05c25c4521c9bc702421b3c6bb5d70af2e5b888a8271651b9'
HELPER_SHA256 = '0039f448059652d87fdfe49cf2de875a38bfe2224c2711c17cc2c837f9c7c88a'
REPORT_SHA256 = '0c2019ff9bd14f93681037d9961ac4c80a14600ef0fe0a99a5065a8aedc5b813'
CLOSURE_SHA256 = '64da321e7e56a56599a15d7c20d660924d6ee44e4b3ac04638f9082579b11969'
SIGNER = ('https://github.com/fr-meyer/openclaw/.github/workflows/'
          'authorized-beta-focused-validation.yml@refs/heads/retained-verifier-prerequisites')
ARCHIVE_CAP = 64 * 1024 * 1024
EXPANDED_CAP = 100 * 1024 * 1024


class Refusal(RuntimeError):
    pass


def require(ok, code):
    if not ok:
        raise Refusal(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, 'runtime.duplicate_json_key')
        result[key] = value
    return result


def _json(raw, cap):
    require(type(raw) is bytes and len(raw) <= cap, 'runtime.json_cap')
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite')))
    except (ValueError, UnicodeError, RecursionError):
        raise Refusal('runtime.json_invalid') from None


def _name(value):
    return (type(value) is str and 0 < len(value) <= 256 and
            not value.startswith('/') and '\\' not in value and '\x00' not in value and
            str(PurePosixPath(value)) == value and
            all(part not in ('.', '..') for part in PurePosixPath(value).parts) and
            re.fullmatch(r'[A-Za-z0-9_./+-]+', value) is not None)


def _regular(path, cap):
    """Bounded local read with no symlink or inode replacement acceptance."""
    path = Path(path)
    require(path.is_absolute() and path.resolve() == path and not path.is_symlink(), 'runtime.path')
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
            before.st_uid == os.getuid() and not stat.S_IMODE(before.st_mode) & 0o022 and
            before.st_size <= cap, 'runtime.file_identity')
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
                          s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        parts, total = [], 0
        while total <= cap:
            chunk = os.read(fd, min(65536, cap + 1 - total))
            if not chunk:
                break
            parts.append(chunk); total += len(chunk)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    require(total == before.st_size and total <= cap and
            identity(before) == identity(opened) == identity(after) == identity(path.lstat()),
            'runtime.file_changed')
    return b''.join(parts)


def _elf_static(raw):
    require(len(raw) >= 64 and raw[:4] == b'\x7fELF' and raw[4:6] == b'\x02\x01',
            'runtime.helper_elf')
    kind, machine = struct.unpack_from('<HH', raw, 16)
    offset = struct.unpack_from('<Q', raw, 32)[0]
    size, count = struct.unpack_from('<HH', raw, 54)
    require(kind == 2 and machine == 62 and size >= 56 and 1 <= count <= 64 and
            offset >= 64 and offset + size * count <= len(raw), 'runtime.helper_elf')
    types = [struct.unpack_from('<I', raw, offset + i * size)[0] for i in range(count)]
    require(2 not in types and 3 not in types, 'runtime.helper_dynamic')


def inspect(archive_raw, verified_raw, host_raw, exact_raw, roster_raw):
    """Return bounded public-runtime facts, never an operational permit."""
    require(type(archive_raw) is bytes and 0 < len(archive_raw) <= ARCHIVE_CAP and
            sha(archive_raw) == ARCHIVE_SHA256, 'runtime.archive_pin')
    for raw, digest, code, cap in ((verified_raw, VERIFICATION_SHA256, 'receipt', 16384),
                                   (host_raw, HOST_RESULT_SHA256, 'host', 262144),
                                   (exact_raw, EXACT_RESULT_SHA256, 'exact', 16384),
                                   (roster_raw, RUNTIME_ROSTER_SHA256, 'roster', 262144)):
        require(type(raw) is bytes and len(raw) <= cap, 'runtime.' + code + '_cap')
        require(type(raw) is bytes and sha(raw) == digest, 'runtime.' + code + '_pin')
    verified = _json(verified_raw, 16384)
    require(type(verified) is dict and set(verified) == {'certificate', 'subject'},
            'runtime.receipt_schema')
    cert = verified['certificate']
    require(type(cert) is dict and cert.get('githubWorkflowRepository') == 'fr-meyer/openclaw' and
            cert.get('githubWorkflowSHA') == SOURCE_COMMIT and
            cert.get('sourceRepositoryDigest') == SOURCE_COMMIT and
            cert.get('sourceRepositoryRef') == 'refs/heads/retained-verifier-prerequisites' and
            cert.get('buildSignerURI') == SIGNER and cert.get('buildSignerDigest') == SOURCE_COMMIT and
            cert.get('runInvocationURI') ==
            'https://github.com/fr-meyer/openclaw/actions/runs/' + RUN_ID + '/attempts/1' and
            cert.get('runnerEnvironment') == 'github-hosted' and
            cert.get('buildTrigger') == 'workflow_dispatch' and
            cert.get('issuer') == 'https://token.actions.githubusercontent.com' and
            cert.get('sourceRepositoryVisibilityAtSigning') == 'public',
            'runtime.signer_binding')
    subjects = verified['subject']
    expected = {'public-tooling.tar.gz': ARCHIVE_SHA256,
                'host-result.json': HOST_RESULT_SHA256,
                'exact-worker-result.json': EXACT_RESULT_SHA256}
    require(type(subjects) is list and len(subjects) == 3 and
            all(type(row) is dict and set(row) == {'name', 'digest'} and
                type(row['name']) is str and type(row['digest']) is dict and
                set(row['digest']) == {'sha256'} and
                type(row['digest']['sha256']) is str for row in subjects) and
            {row['name']: row['digest']['sha256'] for row in subjects} == expected,
            'runtime.subject_binding')
    host = _json(host_raw, 262144)
    require(type(host) is dict, 'runtime.host_proof')
    identity = host.get('runIdentity', {}) if type(host) is dict else {}
    require(type(identity) is dict and host.get('schema') == 'ocv.host-mission-step.v1' and
            host.get('status') == 'passed' and host.get('phase') == 'complete' and
            host.get('failure') is None and host.get('linuxIsolationProof') is True and
            host.get('candidateQualified') is False and
            host.get('sourceManifestSha256') == GENERIC_SOURCE_SHA256 and
            identity.get('repository') == 'fr-meyer/openclaw' and
            identity.get('sourceCommit') == SOURCE_COMMIT and identity.get('runId') == RUN_ID and
            identity.get('runAttempt') == '1' and
            identity.get('workflowRef') ==
            'fr-meyer/openclaw/.github/workflows/authorized-beta-focused-validation.yml@refs/heads/retained-verifier-prerequisites',
            'runtime.host_proof')
    exact = _json(exact_raw, 16384)
    require(type(exact) is dict, 'runtime.exact_proof')
    require(type(exact) is dict and exact.get('schema') == 'openclaw.exact-worker-linux-synthetic.v1' and
            exact.get('status') == 'passed' and exact.get('sourceCommit') == SOURCE_COMMIT and
            exact.get('runId') == RUN_ID and exact.get('fixtureOnly') is True and
            exact.get('candidateImage') is False and exact.get('privateVmAdmission') is False and
            all(exact.get(key) is True for key in
                ('nativeNonrootWorker', 'actualSyntheticConsumer', 'coreUnitPropertiesReadBack',
                 'syntheticGate', 'ownedUnitStopped', 'ownedCgroupEmpty')) and
            exact.get('workerSha256') == WORKER_SHA256 and
            exact.get('protocolSha256') == PROTOCOL_SHA256 and
            exact.get('profileSha256') == PROFILE_SHA256 and
            exact.get('privacyReceiptSha256') == REPORT_SHA256 and
            exact.get('ociClosureSha256') == CLOSURE_SHA256 and
            exact.get('runtime') == {'bytes': 35563665, 'files': 626,
                                     'helperSha256': HELPER_SHA256},
            'runtime.exact_proof')
    roster = _json(roster_raw, 262144)
    require(type(roster) is dict and set(roster) ==
            {'schema', 'activationAuthority', 'privateWorkerIncluded', 'filesCount', 'totalBytes', 'files'} and
            roster['schema'] == 'openclaw.authenticated-public-runtime-roster.v1' and
            roster['activationAuthority'] is False and roster['privateWorkerIncluded'] is False and
            roster['filesCount'] == 626 and roster['totalBytes'] == 35563665 and
            type(roster['files']) is list and len(roster['files']) == 626,
            'runtime.roster_schema')
    try:
        archive = tarfile.open(fileobj=BytesIO(archive_raw), mode='r:gz')
    except (tarfile.TarError, OSError, EOFError):
        raise Refusal('runtime.tar_invalid') from None
    with archive:
        members = archive.getmembers()
        require(len(members) == 718 and all(_name(m.name) and m.isfile() and
                    m.mode in (0o444, 0o555) for m in members) and
                len({m.name for m in members}) == len(members) and
                'PUBLIC-TOOLING-MANIFEST.json' in {m.name for m in members},
                'runtime.tar_members')
        manifest_member = archive.getmember('PUBLIC-TOOLING-MANIFEST.json')
        require(manifest_member.size <= 1048576, 'runtime.manifest_cap')
        manifest_raw = archive.extractfile(manifest_member).read(1048577)
        require(sha(manifest_raw) == TOOLING_MANIFEST_SHA256, 'runtime.manifest_pin')
        manifest = _json(manifest_raw, 1048576)
        require(type(manifest) is dict and set(manifest) ==
                {'schema', 'fixtureOnly', 'candidateImage', 'files'} and
                manifest['schema'] == 'ocv-public-tooling-v1' and
                manifest['fixtureOnly'] is True and manifest['candidateImage'] is False and
                type(manifest['files']) is list and len(manifest['files']) == 717,
                'runtime.manifest_schema')
        rows = {}
        for row in manifest['files']:
            require(type(row) is dict and set(row) == {'path', 'bytes', 'sha256', 'mode'} and
                    _name(row['path']) and row['path'] not in rows and
                    type(row['bytes']) is int and 0 <= row['bytes'] <= EXPANDED_CAP and
                    type(row['mode']) is int and row['mode'] in (0o444, 0o555) and
                    type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']),
                    'runtime.manifest_row')
            rows[row['path']] = row
        require(set(rows) == {m.name for m in members} - {'PUBLIC-TOOLING-MANIFEST.json'},
                'runtime.tar_closure')
        selected, total = [], 0
        for member in members:
            if member.name == 'PUBLIC-TOOLING-MANIFEST.json':
                continue
            row = rows[member.name]
            require(member.size == row['bytes'] and member.mode == row['mode'],
                    'runtime.member_shape')
            total += member.size
            require(total <= EXPANDED_CAP, 'runtime.expanded_cap')
            raw = archive.extractfile(member).read(member.size + 1)
            require(len(raw) == member.size and sha(raw) == row['sha256'], 'runtime.member_hash')
            if member.name == 'static-entry':
                require(len(raw) == 17888 and sha(raw) == HELPER_SHA256, 'runtime.helper_pin')
                _elf_static(raw)
            if member.name == 'static-entry' or member.name.startswith('runtime/'):
                path = 'code/static-entry' if member.name == 'static-entry' else member.name[8:]
                require(path == 'code/static-entry' or path.startswith(('usr/', 'lib/', 'lib64/')),
                        'runtime.selected_path')
                selected.append({'archivePath': member.name, 'path': path,
                                 'bytes': row['bytes'], 'mode': row['mode'],
                                 'sha256': row['sha256']})
    ordered = sorted(selected, key=lambda r: r['path'])
    require(len(selected) == 626 and len({r['path'] for r in selected}) == 626 and
            sum(r['bytes'] for r in selected) == 35563665 and
            {'usr/bin/python3.11', 'lib64/ld-linux-x86-64.so.2',
             'code/static-entry'} <= {r['path'] for r in selected} and
            ordered == roster['files'],
            'runtime.selected_roster')
    return {'schema': 'openclaw.offline-run57-runtime-inspection.v1',
            'activationAuthority': False, 'privateVmAdmission': False,
            'stagePermitted': False, 'privateWorkerIncluded': False,
            'sourceCommit': SOURCE_COMMIT,
            'runId': RUN_ID, 'archiveSha256': ARCHIVE_SHA256,
            'verificationSha256': VERIFICATION_SHA256,
            'hostResultSha256': HOST_RESULT_SHA256,
            'exactResultSha256': EXACT_RESULT_SHA256,
            'toolingManifestSha256': TOOLING_MANIFEST_SHA256,
            'runtimeFiles': 626, 'runtimeBytes': 35563665,
            'helperSha256': HELPER_SHA256,
            'runtimeRosterSha256': RUNTIME_ROSTER_SHA256,
            'files': ordered}


def inspect_paths(archive_path, verified_path, host_path, exact_path, roster_path):
    """Same inspection for canonical current-user, immutable local files."""
    return inspect(_regular(archive_path, ARCHIVE_CAP), _regular(verified_path, 16384),
                   _regular(host_path, 262144), _regular(exact_path, 16384),
                   _regular(roster_path, 262144))


if __name__ == '__main__':
    raise SystemExit('offline_inspector_only')
