"""Proposed standard runner bootstrap. Entry refuses before environment/IO.

No GCP/SSH/data route. Runs a clean Debian12 systemd manager in a container.
Activation requires frozen commit/run identity and all three source guards.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys
import time
import types

EXECUTION_AUTHORIZED = True
CONTROLLER_SHA = '52202680e22de6d6c8224ee9b6d5d32c1b9cf18cd6b641fc4c4eca006c2c87e3'
SNAPSHOT = 'https://snapshot.debian.org/archive/debian/20260927T000000Z/'

def require(value, code):
    if not value:
        raise RuntimeError(code)

def command(argv, timeout, input=None):
    # Bootstrap/boot output may be long. Do not persist or publish raw logs.
    require(input is None, 'COMMAND_HOLD')
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True,
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin',
                                 'LC_ALL': 'C', 'DEBIAN_FRONTEND': 'noninteractive'})
    try:
        proc.wait(timeout=timeout)
    except BaseException:
        # Bootstrap descendants remain in this new owned process group.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(timeout=3)
        raise
    require(proc.returncode == 0, 'COMMAND_HOLD')

def selected(argv, timeout=3):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout,
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    require(len(result.stdout) + len(result.stderr) <= 4096, 'METADATA_CAP')
    return result

def identity(env):
    require(env.get('GITHUB_REPOSITORY') == 'fr-meyer/openclaw', 'REPOSITORY_HOLD')
    require(env.get('GITHUB_REPOSITORY_ID') == '1309456040', 'REPOSITORY_ID_HOLD')
    require(env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch', 'EVENT_HOLD')
    approved = env.get('SYNTHETIC124_APPROVED_COMMIT')
    require(type(approved) is str and re.fullmatch('[0-9a-f]{40}', approved), 'UNBOUND_COMMIT')
    run_id = env.get('GITHUB_RUN_ID')
    require(type(run_id) is str and re.fullmatch('[0-9]{1,20}', run_id), 'UNBOUND_RUN')
    require(env.get('GITHUB_SHA') == approved, 'COMMIT_HOLD')
    require(env.get('GITHUB_RUN_ATTEMPT') == '1', 'RUN_HOLD')
    require(env.get('GITHUB_REF') == 'refs/heads/qualification/synthetic124-sanitized-debian12-20261007', 'REF_HOLD')
    return run_id

def validate_receipt(raw, verifier):
    """Accept a full schema-checked controller pass; never print raw output."""
    require(len(raw) <= 20480, 'RECEIPT_CAP')
    lines = raw.splitlines()
    require(len(lines) == 4 and all(len(line) <= 16384 for line in lines), 'RECEIPT_SCHEMA')
    try:
        rows = [json.loads(line) for line in lines]
    except (ValueError, UnicodeError):
        raise RuntimeError('RECEIPT_SCHEMA') from None
    require(all(type(row) is dict for row in rows), 'RECEIPT_SCHEMA')
    require([row.get('kind') for row in rows] == ['fresh_preflight', 'diagnostic_result', 'cleanup', 'terminal'], 'RECEIPT_SCHEMA')
    preflight, diagnostic, cleanup, terminal = rows
    expected = {'admitted': True, 'scope': 'DISPOSABLE_HOSTED_DEBIAN12_SYNTHETIC_ONLY',
                'exact_runtime': {'Python': '3.11.2', 'SQLite': '3.40.1', 'systemd': '252', 'architecture': 'x86_64'},
                'fixtures_started': False, 'production_data_access': False}
    require(set(preflight) == {'kind', 'facts'} and preflight['facts'] == expected, 'RECEIPT_SCHEMA')
    require(all(type(preflight['facts'][key]) is bool for key in ('admitted', 'fixtures_started', 'production_data_access')), 'RECEIPT_SCHEMA')
    require(set(diagnostic) == {'kind', 'facts'}, 'RECEIPT_SCHEMA')
    facts = diagnostic['facts']
    require(type(facts) is dict and set(facts) == {'events', 'first_failure', 'protocol_failure', 'transport_failure',
            'exit', 'elapsed_seconds', 'input_bytes_sent', 'stdout_bytes', 'stderr_bytes'}, 'RECEIPT_SCHEMA')
    require(all(facts[key] is None for key in ('first_failure', 'protocol_failure', 'transport_failure')), 'CONTROLLER_HOLD')
    require(type(facts['exit']) is int and facts['exit'] == 0, 'CONTROLLER_HOLD')
    require(type(facts['events']) is list and len(facts['events']) == 3, 'RECEIPT_SCHEMA')
    parsed = verifier.parse_child(b'\n'.join(json.dumps(event, allow_nan=False).encode() for event in facts['events']))
    require(parsed['first_failure'] is None and parsed['protocol_failure'] is None
            and parsed['events'] == facts['events'], 'RECEIPT_SCHEMA')
    suite = facts['events'][1]['facts']
    require(suite['runtime'] == {'Python': '3.11.2', 'SQLite': '3.40.1', 'platform': 'linux', 'architecture': 'x86_64'}, 'RECEIPT_SCHEMA')
    require(type(facts['input_bytes_sent']) is int and facts['input_bytes_sent'] == len(verifier.PAYLOAD.encode()), 'RECEIPT_SCHEMA')
    require(all(type(facts[key]) is int and 0 <= facts[key] <= 16384 for key in ('stdout_bytes', 'stderr_bytes'))
            and facts['stdout_bytes'] + facts['stderr_bytes'] <= 16384, 'RECEIPT_CAP')
    require(type(facts['elapsed_seconds']) in (int, float) and 0 <= facts['elapsed_seconds'] <= 35, 'RECEIPT_SCHEMA')
    require(set(cleanup) == {'kind', 'facts'} and cleanup['facts'] == {'unit_absent': True, 'own_cgroup_absent': True, 'namespace_removed': True}
            and all(type(value) is bool for value in cleanup['facts'].values()), 'RECEIPT_SCHEMA')
    require(terminal == {'kind': 'terminal', 'status': 'COMPLETE', 'dispatch_attempts': 1, 'fixture_cases_reported': 124,
                        'fixture_execution': 'RESULT_REPORTED', 'first_failure': None, 'cleanup_failure': None,
                        'cleanup_ok': True, 'no_automatic_retry': True}
            and type(terminal['dispatch_attempts']) is int and type(terminal['fixture_cases_reported']) is int
            and type(terminal['cleanup_ok']) is bool and type(terminal['no_automatic_retry']) is bool, 'CONTROLLER_HOLD')
    return {'fixtures': 124, 'counts': [29, 95], 'scope_verified': True, 'controller_cleanup_verified': True,
            'exact_userland': expected['exact_runtime'], 'scope': expected['scope']}

def main():
    failure = None
    clean = True
    launched = False
    validated = None
    unit = root = machine = None
    try:
        run = identity(os.environ)
        require(os.geteuid() == 0 and sys.platform == 'linux' and platform.machine() == 'x86_64', 'HOST_HOLD')
        controller = Path(__file__).resolve().with_name('controller.py').read_bytes()
        require(hashlib.sha256(controller).hexdigest() == CONTROLLER_SHA, 'CONTROLLER_HASH')
        require(not controller.endswith(b'    raise SystemExit(78)\n'), 'CONTROLLER_NOT_ACTIVATED')
        verifier = types.ModuleType('frozen_synthetic_controller_validator')
        exec(compile(controller, 'frozen_synthetic_controller_validator', 'exec'), verifier.__dict__)
        machine = 'synthetic124-' + run
        unit = machine + '.service'
        root = Path('/var/lib/machines') / machine
        require(not root.exists() and not root.is_symlink(), 'ROOT_EXISTS')
        state = selected(['/usr/bin/systemctl', 'show', unit, '-p', 'LoadState', '--value'])
        require(state.returncode == 0 and state.stdout.strip() == b'not-found', 'UNIT_EXISTS')
        # Public runner tools only; no production/cost/IAP/source disks.
        command(['/usr/bin/apt-get', '-o', 'Acquire::Retries=0', '-o', 'Acquire::https::Timeout=20', 'update'], 30)
        command(['/usr/bin/apt-get', '-y', '--no-install-recommends', '-o', 'Acquire::Retries=0',
                 'install', 'debootstrap', 'debian-archive-keyring', 'systemd-container'], 60)
        command(['/usr/sbin/debootstrap', '--arch=amd64', '--variant=minbase',
                 '--force-check-gpg',
                 '--include=python3,systemd-sysv,dbus',
                 '--keyring=/usr/share/keyrings/debian-archive-keyring.gpg',
                 'bookworm', str(root), SNAPSHOT], 240)
        target = root / 'opt/qualification'
        target.mkdir(mode=0o700, parents=True)
        (target / 'controller.py').write_bytes(controller)
        # No host path binds, veth, cloud interfaces or host network changes.
        launched = True  # Cleanup covers uncertain launch delivery too.
        command(['/usr/bin/systemd-run', '--unit=' + unit,
                 '--property=Description=' + machine,
                 '--property=Delegate=yes', '--property=KillMode=mixed',
                 '--property=TasksMax=256', '--property=MemoryMax=12G',
                 '--property=RuntimeMaxSec=120s', '--property=TimeoutStopSec=10s',
                 '/usr/bin/systemd-nspawn', '--keep-unit', '--boot', '--quiet',
                 '--settings=no', '--private-network', '--register=yes',
                 '--resolv-conf=off', '--link-journal=no', '--console=pipe',
                 '--directory=' + str(root), '--machine=' + machine], 10)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            state = selected(['/usr/bin/systemctl', '--machine=' + machine, 'is-system-running'])
            if state.returncode == 0 and state.stdout.strip() == b'running':
                break
            time.sleep(1)
        else:
            raise RuntimeError('CONTAINER_READINESS_HOLD')
        # The controller validates PID1/manager252, exact Python/linked SQLite,
        # cgroup controllers, >=8GiB available, PSI and unchanged fixture caps.
        # Live frozen diagnostics only. Outer timeout bounds lost pipe/client.
        with subprocess.Popen(['/usr/bin/systemd-run', '--machine=' + machine,
                               '--unit=synthetic124-controller.service', '--wait', '--pipe', '--quiet',
                               '/usr/bin/python3', '-I', '-S', '-B', '-u', '/opt/qualification/controller.py'],
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}) as proc:
            data = bytearray()
            import selectors
            selector = selectors.DefaultSelector()
            os.set_blocking(proc.stdout.fileno(), False)
            selector.register(proc.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + 35
            try:
                while selector.get_map() and time.monotonic() < deadline:
                    for key, _ in selector.select(.05):
                        chunk = os.read(key.fd, 4096)
                        if not chunk:
                            selector.unregister(key.fileobj)
                        else:
                            data.extend(chunk)
                            require(len(data) <= 20480, 'RECEIPT_CAP')
                require(not selector.get_map(), 'CONTROLLER_TIMEOUT')
                proc.wait(timeout=max(.01, deadline - time.monotonic()))
                require(proc.returncode == 0, 'CONTROLLER_HOLD')
                validated = validate_receipt(bytes(data), verifier)
            finally:
                selector.close()
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=3)
    except BaseException as exc:
        # Never export exception strings, package/boot logs or arbitrary values.
        known = {'REPOSITORY_HOLD', 'REPOSITORY_ID_HOLD', 'EVENT_HOLD', 'UNBOUND_COMMIT', 'UNBOUND_RUN',
                 'COMMIT_HOLD', 'RUN_HOLD', 'REF_HOLD', 'HOST_HOLD', 'CONTROLLER_HASH',
                 'CONTROLLER_NOT_ACTIVATED', 'ROOT_EXISTS', 'UNIT_EXISTS', 'COMMAND_HOLD', 'METADATA_CAP',
                 'CONTAINER_READINESS_HOLD', 'RECEIPT_CAP', 'RECEIPT_SCHEMA', 'CONTROLLER_TIMEOUT', 'CONTROLLER_HOLD'}
        failure = str(exc) if type(exc) is RuntimeError and str(exc) in known else 'FIXED_RUNTIME_HOLD'
    finally:
        if launched:
            try:
                # Exact run-bound service only; preserve the rootfs on uncertainty.
                actual = selected(['/usr/bin/systemctl', 'show', unit, '-p', 'Description', '--value'])
                require(actual.returncode == 0 and actual.stdout.strip().decode('ascii') == machine, 'OWNERSHIP_HOLD')
                command(['/usr/bin/systemctl', 'stop', unit], 12)
                command(['/usr/bin/systemctl', 'reset-failed', unit], 3)
                state = selected(['/usr/bin/systemctl', 'show', unit, '-p', 'LoadState', '--value'])
                require(state.returncode == 0 and state.stdout.strip() == b'not-found', 'CLEANUP_HOLD')
                require(not Path('/sys/fs/cgroup/system.slice', unit).exists(), 'CLEANUP_HOLD')
                require(not Path('/run/systemd/machines', machine).exists(), 'CLEANUP_HOLD')
            except BaseException:
                clean = False
        # No recursive deletion: clean rootfs remains only on disposable runner.
        print(json.dumps({'kind': 'hosted_route_terminal', 'failure': failure,
                          'method_qualification': validated,
                          'complete': validated is not None and failure is None and clean,
                          'commit': os.environ.get('GITHUB_SHA') if validated else None,
                          'run_id': run if validated else None,
                          'controller_SHA256': CONTROLLER_SHA if validated else None,
                          'fixture_payload_SHA256': verifier.PAYLOAD_SHA if validated else None,
                          'snapshot': SNAPSHOT if validated else None,
                          'host_kernel': platform.release() if validated else None,
                          'container_started_or_uncertain': launched,
                          'owned_container_cleanup_ok': clean,
                          'rootfs_disposal_expected': 'GITHUB_DISPOSABLE_RUNNER_TEARDOWN_NOT_LOCALLY_VERIFIED',
                          'preservation_inspection_performed': False}))
    return 0 if validated is not None and failure is None and clean else 4

if __name__ == '__main__':
    if not EXECUTION_AUTHORIZED:
        print('{"status":"SOURCE_ONLY_NO_HOSTED_EXECUTION_AUTHORITY"}')
        raise SystemExit(78)
    sys.exit(main())
