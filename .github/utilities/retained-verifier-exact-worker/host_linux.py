"""Synthetic, exact-definition worker check on a Linux systemd host.

The public worker/protocol definitions are exported from pinned private sources
with only top-level fixture constants changed. This runner proves a native
nonroot invocation and the synthetic consumer. It does not adjudicate private
VM admission, issue a private gate, or touch a candidate image.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import time

HERE = Path(__file__).resolve().parent
ARTIFACT = Path(os.environ.get('RUNNER_TEMP', '/tmp')) / 'ocv-ci-artifacts'
ARCHIVE = ARTIFACT / 'public-tooling.tar.gz'
RESULT = ARTIFACT / 'exact-worker-result.json'
ROOTS = Path('/var/lib/openclaw-retained-verifier')
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_TOTAL = 100 * 1024 * 1024
EXPECTED_FILES = 626
EXPECTED_BYTES = 35555273
EXPECTED_CLOSURE = '64da321e7e56a56599a15d7c20d660924d6ee44e4b3ac04638f9082579b11969'
SOURCE = '8770609a78d68f6b53607ce3199baf0aa08687cf'
SCANNER = 'd658c890f5684b2dbe8468449a7fed17bb46055d'
INDEX = 'sha256:2577bfdfb50ee4411f69b90bf8b4347b8e476c2bc82bb982005515c46ebe59cc'
REPORT_SHA = '0c2019ff9bd14f93681037d9961ac4c80a14600ef0fe0a99a5065a8aedc5b813'
PROFILE_SHA = '82a14f80bc5987bc1fc32b9e13de63fd113d1d7be9012d38ef78126608ce96e6'


def need(ok, code):
    if not ok:
        raise RuntimeError(code)


def sha(raw): return hashlib.sha256(raw).hexdigest()
def canonical(value): return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
def stamp(value): return value.strftime('%Y-%m-%dT%H:%M:%SZ')


def read(path, cap):
    value = path.read_bytes()
    need(len(value) <= cap, 'exact.read_cap')
    return value


def sources():
    manifest_raw = read(HERE / 'PUBLIC-EXACT-SOURCE-MANIFEST.json', 16384)
    need(sha(manifest_raw) == os.environ.get('OCV_EXACT_MANIFEST_SHA'), 'exact.manifest_pin')
    doc = json.loads(manifest_raw)
    need(doc.get('schema') == 'openclaw.exact-worker-public-sources.v1' and
         doc.get('fixtureOnly') is True and doc.get('candidateImage') is False and
         type(doc.get('files')) is list, 'exact.manifest_schema')
    rows = doc['files']
    actual = {str(p.relative_to(HERE)) for p in HERE.rglob('*') if p.is_file()}
    need(actual == {r['path'] for r in rows} | {'PUBLIC-EXACT-SOURCE-MANIFEST.json'} and
         len(rows) == len({r['path'] for r in rows}), 'exact.source_roster')
    for row in rows:
        need(set(row) == {'path', 'bytes', 'sha256'} and
             re.fullmatch(r'[A-Za-z0-9_./-]+', row['path']) and
             '..' not in PurePosixPath(row['path']).parts and
             len(read(HERE / row['path'], 262144)) == row['bytes'] and
             sha(read(HERE / row['path'], 262144)) == row['sha256'],
             'exact.source_pin')
    need(sha(read(HERE / 'CI-PROFILE.json', 16384)) == PROFILE_SHA, 'exact.profile_pin')
    return {r['path']: r for r in rows}


def stage_runtime(root):
    """Stage only the manifest-checked public runtime and static entry."""
    need(ARCHIVE.is_file() and ARCHIVE.stat().st_size <= MAX_ARCHIVE,
         'exact.archive_cap')
    with tarfile.open(ARCHIVE, 'r:gz') as archive:
        members = archive.getmembers()
        need(1 <= len(members) <= 8192 and len({m.name for m in members}) == len(members) and
             all(m.isfile() and m.mode in (0o444, 0o555) for m in members),
             'exact.archive_roster')
        manifest = json.loads(archive.extractfile('PUBLIC-TOOLING-MANIFEST.json').read(1048577))
        rows = {r['path']: r for r in manifest['files']}
        need(len(rows) == len(manifest['files']) and
             set(rows) == {m.name for m in members} - {'PUBLIC-TOOLING-MANIFEST.json'},
             'exact.archive_manifest')
        copied = 0
        count = 0
        for member in members:
            name = member.name
            if name == 'PUBLIC-TOOLING-MANIFEST.json': continue
            if name.startswith('runtime/'):
                relative = name[len('runtime/'):]
                need(relative.startswith(('usr/', 'lib/', 'lib64/')), 'exact.runtime_path')
            elif name == 'static-entry': relative = 'code/static-entry'
            else: continue
            need(re.fullmatch(r'[A-Za-z0-9_./+-]+', relative) and
                 '..' not in PurePosixPath(relative).parts and
                 str(PurePosixPath(relative)) == relative, 'exact.runtime_path')
            row = rows[name]
            need(set(row) == {'path', 'bytes', 'sha256', 'mode'} and
                 row['bytes'] == member.size and row['mode'] == member.mode,
                 'exact.runtime_row')
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            need(not target.exists(), 'exact.runtime_duplicate')
            data = archive.extractfile(member).read(member.size + 1)
            need(len(data) == member.size and sha(data) == row['sha256'], 'exact.runtime_hash')
            target.write_bytes(data)
            target.chmod(member.mode)
            copied += len(data);count += 1
            need(copied <= MAX_TOTAL, 'exact.runtime_cap')
    need(count == EXPECTED_FILES and copied == EXPECTED_BYTES and
         (root / 'usr/bin/python3.11').is_file() and
         (root / 'lib64/ld-linux-x86-64.so.2').is_file(), 'exact.runtime_binding')
    return {'files': count, 'bytes': copied, 'helperSha256': sha((root / 'code/static-entry').read_bytes())}


def put(root, relative, raw, mode):
    target = root / relative
    need(not target.exists() and type(raw) is bytes, 'exact.put_once')
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    target.write_bytes(raw)
    target.chmod(mode)


def command(*argv, timeout=15):
    value = subprocess.run(argv, capture_output=True, timeout=timeout,
                           env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'})
    need(value.returncode == 0 and len(value.stdout) <= 16384 and
         len(value.stderr) <= 16384,
         'exact.command_' + Path(argv[0]).name)
    return value.stdout.decode()


def show(unit, keys):
    raw = command('/usr/bin/systemctl', 'show', '--no-pager',
                  '--property=' + ','.join(keys), unit)
    values = dict(line.split('=', 1) for line in raw.splitlines() if '=' in line)
    need(set(keys) <= set(values), 'exact.unit_readback')
    return values


def wait_line(path, schema, seconds):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if path.exists():
            raw = read(path, 65536)
            for line in raw.splitlines():
                try: value = json.loads(line)
                except (ValueError, UnicodeError): continue
                if type(value) is dict and value.get('schema') == schema: return value
        time.sleep(0.05)
    raise RuntimeError('exact.frame_timeout_' + schema)


def process_start(pid):
    raw = read(Path('/proc') / str(pid) / 'stat', 4096).decode()
    return int(raw[raw.rfind(')') + 2:].split()[19])


def failure_diagnostics(stderr, unit):
    """Bounded, projected facts for this synthetic unit, never raw log bytes."""
    result = {'schema': 'openclaw.exact-worker-failure-diagnostic.v1'}
    try:
        fd = os.open(stderr, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try: raw = os.read(fd, 65537)
        finally: os.close(fd)
        result['stderrBytesRead'] = min(len(raw), 65536)
        result['stderrTruncated'] = len(raw) > 65536
        result['stderrPrefixSha256'] = sha(raw[:65536])
        markers, frames = [], []
        for line in raw[:65536].splitlines()[:16]:
            if line in (b'entry_refused', b'entry_exec_failed'):
                markers.append(line.decode('ascii'))
                continue
            try: value = json.loads(line)
            except (ValueError, UnicodeError):
                if b'Traceback (most recent call last)' in line: markers.append('pythonTraceback')
                continue
            if type(value) is dict and value.get('schema') in (
                    'openclaw.retained-verifier-ready.v1',
                    'openclaw.retained-verifier-worker-final.v1'):
                frame = {'schema': value['schema']}
                for key in ('status', 'reasonCode'):
                    item = value.get(key)
                    if type(item) is str and re.fullmatch(r'[a-z][a-z0-9_-]{0,95}', item):
                        frame[key] = item
                frames.append(frame)
        result['markers'] = markers[:8]
        result['frames'] = frames[:8]
    except (OSError, RuntimeError):
        result['stderrUnavailable'] = True
    keys = ('ActiveState', 'SubState', 'Result', 'ExecMainCode',
            'ExecMainStatus', 'MainPID')
    try:
        outcome = subprocess.run(('/usr/bin/systemctl', 'show', '--no-pager',
                                  '--property=' + ','.join(keys), unit),
                                 capture_output=True, timeout=5,
                                 env={'PATH': '/usr/bin', 'LANG': 'C', 'LC_ALL': 'C'})
        result['unitQueryExitCode'] = outcome.returncode
        if outcome.returncode == 0 and len(outcome.stdout) <= 4096:
            values = dict(line.split('=', 1) for line in
                          outcome.stdout.decode('ascii').splitlines() if '=' in line)
            if set(keys) <= set(values) and all(re.fullmatch(r'[a-z0-9_.-]{1,64}', values[k])
                                                    for k in keys[:3]) and all(
                    re.fullmatch(r'[0-9]{1,10}', values[k]) for k in keys[3:]):
                result['unit'] = {k: values[k] for k in keys}
    except (OSError, subprocess.TimeoutExpired, UnicodeError, ValueError):
        result['unitQueryUnavailable'] = True
    return result


def run():
    need(sys.platform == 'linux' and os.uname().machine == 'x86_64' and os.geteuid() == 0 and
         os.environ.get('GITHUB_REPOSITORY') == 'fr-meyer/openclaw' and
         os.environ.get('GITHUB_RUN_ATTEMPT') == '1', 'exact.linux_runner_identity')
    rows = sources()
    sys.path.insert(0, str(HERE))
    import ci_profile
    session = sha((os.environ['GITHUB_RUN_ID'] + ':' + os.environ['GITHUB_SHA']).encode())[:32]
    unit = 'ocv-' + session + '.service'
    identity = 'ocv-' + session[:24]
    base = ROOTS / session
    need(not base.exists(), 'exact.session_exists')
    ROOTS.mkdir(mode=0o700, exist_ok=True)
    need(ROOTS.stat().st_uid == 0 and stat.S_IMODE(ROOTS.stat().st_mode) == 0o700,
         'exact.root_parent')
    base.mkdir(mode=0o700)
    root = base / 'root';root.mkdir(mode=0o755)
    evidence = base / 'evidence';evidence.mkdir(mode=0o700)
    stdout = evidence / 'worker.stdout';stderr = evidence / 'worker.stderr'
    stdout.touch(mode=0o600);stderr.touch(mode=0o600)
    for relative in ('run','tmp','var/tmp','dev/mqueue','proc','sys','input/oci','control'):
        (root / relative).mkdir(parents=True, exist_ok=True, mode=0o755)
    submitted = False
    cgroup = None
    result = {'schema': 'openclaw.exact-worker-linux-synthetic.v1', 'status': 'failed',
              'fixtureOnly': True, 'candidateImage': False, 'privateVmAdmission': False,
              'runId': os.environ['GITHUB_RUN_ID'], 'sourceCommit': os.environ['GITHUB_SHA']}
    try:
        runtime = stage_runtime(root)
        for name in ('worker.py', 'protocol.py', 'hosted_export.py', 'hosted_privacy.py',
                     'public-member-comparisons-v105-workboard.json'):
            put(root, 'code/' + name, read(HERE / name, 262144), 0o444)
        fixture = HERE / 'fixture'
        files = sorted(p for p in fixture.rglob('*') if p.is_file())
        need(len(files) == 10, 'exact.fixture_roster')
        manifest = []
        for p in files:
            relative = str(p.relative_to(fixture))
            raw = read(p, 131072)
            put(root, 'input/' + relative, raw, 0o444)
            manifest.append({'path': relative, 'bytes': len(raw), 'sha256': sha(raw)})
        need(sha((root/'input/privacy.json').read_bytes()) == REPORT_SHA,
             'exact.report_pin')
        (root/'input').chmod(0)
        boot = read(Path('/proc/sys/kernel/random/boot_id'), 128).decode().strip()
        now = dt.datetime.now(dt.timezone.utc)
        context = {'schema': 'openclaw.retained-verifier-context.v1',
                   'sessionId': session, 'unitName': unit, 'bootId': boot, 'vmId': '1',
                   'identityName': identity, 'contextNonce': sha((session+boot).encode()),
                   'workerDeadlineUtc': stamp(now+dt.timedelta(seconds=300)),
                   'maxJobSeconds': 300, 'operation': 'retained-report-only',
                   'mountPropagation': 'private', 'sourceSha': SOURCE, 'scannerSha': SCANNER,
                   'indexDigest': INDEX, 'privacySha256': REPORT_SHA,
                   'privacyBytes': len((root/'input/privacy.json').read_bytes()),
                   'consumerCode': {name: {'bytes': rows[name]['bytes'], 'sha256': rows[name]['sha256']}
                                    for name in ('hosted_export.py', 'hosted_privacy.py',
                                                 'public-member-comparisons-v105-workboard.json')},
                   'profileSha256': PROFILE_SHA, 'entrySha256': runtime['helperSha256'],
                   'workerSha256': rows['worker.py']['sha256'],
                   'runtimeManifestSha256': sha(canonical(runtime)),
                   'inputManifestSha256': sha(canonical(manifest))}
        put(root, 'control/context.json', canonical(context), 0o444)
        put(root, 'control/admission.json', b'', 0o600)
        props = ci_profile.properties(read(HERE/'CI-PROFILE.json', 16384), session, str(base))
        need('PrivateNetwork=yes' in props and 'MountFlags=private' in props and
             any(v.startswith('RootDirectory=') for v in props), 'exact.profile_required')
        argv = ['/usr/bin/systemd-run', '--unit='+unit]
        for prop in props:
            if prop.startswith('ExecStart='): continue
            argv += ['--property', prop]
        argv += ['/code/static-entry', identity]
        submitted = True
        command(*argv, timeout=15)
        ready = wait_line(stderr, 'openclaw.retained-verifier-ready.v1', 30)
        need(ready == {'schema': 'openclaw.retained-verifier-ready.v1',
                       'status': 'ready', 'pid': ready.get('pid'),
                       'uid': ready.get('uid'), 'gid': ready.get('gid'),
                       'contextSha256': sha(canonical(context)),
                       'workerSha256': rows['worker.py']['sha256']} and
             type(ready['pid']) is int and ready['pid'] > 1 and
             type(ready['uid']) is int and type(ready['gid']) is int,
             'exact.ready_binding')
        pid = ready['pid']
        unit_fields = show(unit, ('MainPID','DynamicUser','User','Group','PrivateNetwork',
                                  'NoNewPrivileges','RootDirectory','InvocationID','ControlGroup'))
        need(int(unit_fields['MainPID']) == pid and unit_fields['DynamicUser'] == 'yes' and
             unit_fields['User'] == unit_fields['Group'] == identity and
             unit_fields['PrivateNetwork'] == unit_fields['NoNewPrivileges'] == 'yes' and
             unit_fields['RootDirectory'] == str(root) and
             re.fullmatch('[0-9a-f]{32}', unit_fields['InvocationID']) and
             unit_fields['ControlGroup'] == '/system.slice/' + unit,
             'exact.unit_binding')
        cgroup = unit_fields['ControlGroup']
        status = read(Path('/proc')/str(pid)/'status', 16384).decode()
        uid = int(re.search(r'^Uid:\s+(\d+)', status, re.M).group(1))
        gid = int(re.search(r'^Gid:\s+(\d+)', status, re.M).group(1))
        need(61184 <= uid <= 65519 and uid == ready['uid'] and gid == ready['gid'] and
             os.readlink(Path('/proc')/str(pid)/'ns/net') !=
             os.readlink('/proc/1/ns/net'), 'exact.process_identity')
        checked = dt.datetime.now(dt.timezone.utc)
        gate = {key: context[key] for key in (
            'sessionId','unitName','bootId','vmId','identityName','workerDeadlineUtc',
            'profileSha256','entrySha256','workerSha256','runtimeManifestSha256',
            'inputManifestSha256','sourceSha','scannerSha','indexDigest','privacySha256',
            'privacyBytes','consumerCode','mountPropagation')}
        gate.update(schema='openclaw.retained-verifier-admission.v1', pid=pid,
                    startTimeTicks=process_start(pid), uid=uid, gid=gid,
                    checkedAt=stamp(checked), expiresAt=stamp(checked+dt.timedelta(seconds=30)),
                    # This is intentionally a synthetic worker gate. It is
                    # never evidence of full private host admission.
                    proofSha256=sha(b'synthetic-exact-worker-gate-no-host-proof'), status='passed',
                    inputReleased=True, contextSha256=sha(canonical(context)),
                    invocationId=unit_fields['InvocationID'])
        (root/'input').chmod(0o555)
        gate_path = root/'control/admission.json'
        gate_path.write_bytes(canonical(gate));gate_path.chmod(0o444)
        final = wait_line(stderr, 'openclaw.retained-verifier-worker-final.v1', 240)
        output = json.loads(read(stdout, 4096))
        need(final.get('status') == 'consumer_returned' and
             final.get('pid') == pid and
             final.get('contextSha256') == sha(canonical(context)) and
             final.get('readyEmitted') is True and
             final.get('consumerExitCode') == 0 and final.get('timedOut') is False and
             final.get('reasonCode') is None and
             output == {'status': 'passed', 'privacyReceiptSha256': REPORT_SHA,
                        'ociClosureSha256': EXPECTED_CLOSURE}, 'exact.consumer_result')
        result.update(status='consumer-passed-pending-closeout', nativeNonrootWorker=True,
                      actualSyntheticConsumer=True, coreUnitPropertiesReadBack=True,
                      syntheticGate=True,
                      workerSha256=rows['worker.py']['sha256'],
                      protocolSha256=rows['protocol.py']['sha256'],
                      profileSha256=PROFILE_SHA, runtime=runtime,
                      privacyReceiptSha256=REPORT_SHA,
                      ociClosureSha256=EXPECTED_CLOSURE,
                      stdoutSha256=sha(read(stdout, 4096)),
                      stderrSha256=sha(read(stderr, 65536)))
    except BaseException as error:
        reason = (str(error) if type(error) is RuntimeError and
                  re.fullmatch(r'exact\.[a-z0-9_.-]{1,120}', str(error))
                  else type(error).__name__[:48])
        result['reason'] = reason
        result['primaryReason'] = reason
        raise
    finally:
        if submitted:
            if result['status'] == 'failed':
                try: result['diagnostics'] = failure_diagnostics(stderr, unit)
                except BaseException: result['diagnostics'] = {'status': 'unavailable'}
            try:
                stopped = subprocess.run(('/usr/bin/systemctl','stop',unit), capture_output=True,
                                         timeout=15)
                need(stopped.returncode == 0, 'exact.normal_stop_failed')
                closed = show(unit, ('ActiveState','MainPID'))
                need(closed['ActiveState'] == 'inactive' and closed['MainPID'] == '0',
                     'exact.unit_not_inactive')
                if cgroup is not None:
                    need(re.fullmatch(r'/system.slice/ocv-[0-9a-f]{32}\.service', cgroup),
                         'exact.cgroup_path')
                    members = Path('/sys/fs/cgroup'+cgroup+'/cgroup.procs')
                    need(not members.exists() or read(members, 4096).strip() == b'',
                         'exact.cgroup_not_empty')
                result['ownedUnitStopped'] = True
                result['ownedCgroupEmpty'] = cgroup is not None
            except BaseException as error:
                result['status'] = 'failed'
                result['closeoutReason'] = ('exact.closeout_' + type(error).__name__)[:100]
        if result['status'] == 'consumer-passed-pending-closeout':
            if result.get('ownedUnitStopped') is True and result.get('ownedCgroupEmpty') is True:
                result['status'] = 'passed'
            else:
                result.update(status='failed', reason='exact.closeout_unproven')
        ARTIFACT.mkdir(parents=True, exist_ok=True)
        RESULT.write_bytes(canonical(result))
        if result['status'] == 'passed': shutil.rmtree(base)
    need(result['status'] == 'passed', 'exact.proof_failed')
    return result


if __name__ == '__main__':
    outcome = run()
    print(canonical({'status': outcome['status'], 'nativeNonrootWorker': True,
                     'actualSyntheticConsumer': True}).decode())
