"""Proposed standard runner bootstrap. Entry refuses before environment/IO.

No GCP/SSH/data route. Runs a clean Debian12 systemd manager in a container.
Activation requires frozen commit/run identity and all three source guards.
"""
import hashlib
import json
import math
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
CONTROLLER_SHA = '12753c1b906904dcef68e82eacf2f1fe55b6e75866267f2c3c725e314f10bf17'
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

def suite_diagnostics(suite, verifier):
    """Export schema-checked synthetic facts only, with explicit omissions."""
    verifier.validate_facts(suite, verifier.POLICY)
    groups = []
    for group in suite['groups']:
        cases = []
        for case, outcome, exception, reason, count in group['case_records']:
            cases.append({'case': verifier.POLICY['cases'][case] if case >= 0 else 'UNRECOGNIZED_CASE',
                          'stage': 'fixtures.suite', 'outcome': verifier.OUTCOMES[outcome],
                          'exception': verifier.EXCEPTIONS[exception],
                          'assertion_reason': verifier.REASONS[reason], 'events': count})
        details = [dict(detail, stage='fixtures.suite',
                        assertion_reason=verifier.assertion_reason(detail))
                   for detail in group['details']]
        groups.append({'run': group['run'], 'issue_count': group['issue_count'],
                       'unrecognized_cases': group['unrecognized_cases'],
                       'cases': cases, 'expanded_case_events_omitted': 0,
                       'case_records': [list(record) for record in group['case_records']],
                       'case_records_omitted': group['case_records_omitted'],
                       'details': details, 'details_omitted': group['details_omitted'],
                       'case_records_complete': group['case_records_omitted'] == 0,
                       'expanded_cases_complete': group['case_records_omitted'] == 0})
    # The expanded public IDs also have a fixed cap; retain cases before stacks.
    while len(json.dumps(groups, allow_nan=False).encode()) > 8192:
        detailed = [group for group in groups if group['details']]
        if detailed:
            group = max(detailed, key=lambda group:len(group['details']))
            group['details'].pop()
            group['details_omitted'] += 1
        else:
            group = max(groups, key=lambda group:len(group['cases']))
            group['expanded_case_events_omitted'] += group['cases'].pop()['events']
            group['expanded_cases_complete'] = False
    require(len(json.dumps(groups, allow_nan=False).encode()) <= 8192, 'RECEIPT_CAP')
    return groups
def controller_diagnostic(raw, verifier):
    """Retain closed failure facts before the exit gate; never export raw rows."""
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, 'RECEIPT_SCHEMA')
            value[key] = item
        return value
    def integer(value, low, high):
        return type(value) is int and low <= value <= high
    def failure(value):
        require(value is None or verifier.valid_failure(value), 'RECEIPT_SCHEMA')
        return value
    require(len(raw) <= 20480, 'RECEIPT_CAP')
    lines = raw.splitlines()
    require(2 <= len(lines) <= 5 and all(len(line) <= 16384 for line in lines), 'RECEIPT_SCHEMA')
    try:
        rows = [json.loads(line, object_pairs_hook=pairs,
                           parse_constant=lambda _: require(False, 'RECEIPT_SCHEMA')) for line in lines]
    except (ValueError, UnicodeError):
        raise RuntimeError('RECEIPT_SCHEMA') from None
    require(all(type(row) is dict for row in rows), 'RECEIPT_SCHEMA')
    order = {'fresh_preflight': 0, 'diagnostic_result': 1, 'controller_hold': 2,
             'cleanup': 3, 'cleanup_hold': 3, 'terminal': 4}
    kinds = [row.get('kind') for row in rows]
    require(all(type(k) is str and k in order for k in kinds)
            and kinds[-1] == 'terminal'
            and all(order[a] < order[b] for a, b in zip(kinds, kinds[1:])), 'RECEIPT_SCHEMA')
    terminal = rows[-1]
    require(set(terminal) == {'kind', 'status', 'dispatch_attempts', 'fixture_cases_reported',
            'fixture_execution', 'first_failure', 'cleanup_failure', 'cleanup_ok', 'no_automatic_retry'}, 'RECEIPT_SCHEMA')
    require(terminal['status'] in ('COMPLETE', 'FIXED_HOLD')
            and integer(terminal['dispatch_attempts'], 0, 1)
            and type(terminal['cleanup_ok']) is bool
            and terminal['no_automatic_retry'] is True, 'RECEIPT_SCHEMA')
    first = failure(terminal['first_failure'])
    cleanup_failure = failure(terminal['cleanup_failure'])
    diagnostic = suite = hold = cleanup = None
    for row in rows[:-1]:
        kind = row['kind']
        if kind == 'fresh_preflight':
            expected = {'admitted': True, 'scope': 'DISPOSABLE_HOSTED_DEBIAN12_SYNTHETIC_ONLY',
                        'exact_runtime': {'Python': '3.11.2', 'SQLite': '3.40.1', 'systemd': '252', 'architecture': 'x86_64'},
                        'fixtures_started': False, 'production_data_access': False}
            require(set(row) == {'kind', 'facts'} and row['facts'] == expected
                    and all(type(row['facts'][key]) is bool for key in
                            ('admitted', 'fixtures_started', 'production_data_access')), 'RECEIPT_SCHEMA')
        elif kind == 'diagnostic_result':
            require(kinds[0] == 'fresh_preflight' and set(row) == {'kind', 'facts'}, 'RECEIPT_SCHEMA')
            diagnostic = row['facts']
            require(type(diagnostic) is dict and set(diagnostic) == {'events', 'first_failure', 'protocol_failure',
                    'transport_failure', 'exit', 'elapsed_seconds', 'input_bytes_sent', 'stdout_bytes', 'stderr_bytes'}, 'RECEIPT_SCHEMA')
            require(type(diagnostic['events']) is list and len(diagnostic['events']) <= 3, 'RECEIPT_SCHEMA')
            parsed = verifier.parse_child(b'\n'.join(json.dumps(event, allow_nan=False).encode()
                                                   for event in diagnostic['events']))
            protocol = failure(diagnostic['protocol_failure'])
            # The frozen controller omits a rejected raw line from events.
            # Preserve its closed protocol code without claiming to recheck it.
            require(parsed['events'] == diagnostic['events']
                    and (protocol is None or protocol['stage'] == 'transport.protocol')
                    and (parsed['protocol_failure'] is None or protocol is not None), 'RECEIPT_SCHEMA')
            transport = failure(diagnostic['transport_failure'])
            child = next((event['failure'] for event in parsed['events']
                          if event.get('kind') in ('synthetic_setup_hold', 'synthetic_resource_hold')), None)
            suite = next((event['facts'] for event in parsed['events']
                          if event.get('scope') == 'LINUX_SYNTHETIC_UNIT_SUITE_ONLY'), None)
            require(diagnostic['exit'] is None or integer(diagnostic['exit'], -255, 255), 'RECEIPT_SCHEMA')
            exit_failure = {'stage': 'transport.exit', 'error': 'NONZERO_EXIT'} if diagnostic['exit'] not in (0, None) else None
            primary = ({'stage': 'fixtures.suite', 'error': 'SUITE_FAILURE'} if suite and not suite['ok'] else None) \
                      or child or transport or exit_failure or protocol
            require(failure(diagnostic['first_failure']) == primary, 'RECEIPT_SCHEMA')
            require(integer(diagnostic['input_bytes_sent'], 0, len(verifier.PAYLOAD.encode()))
                    and all(integer(diagnostic[key], 0, 16384) for key in ('stdout_bytes', 'stderr_bytes'))
                    and diagnostic['stdout_bytes'] + diagnostic['stderr_bytes'] <= 16384, 'RECEIPT_SCHEMA')
            elapsed = diagnostic['elapsed_seconds']
            require(type(elapsed) in (int, float) and math.isfinite(elapsed) and 0 <= elapsed <= 35, 'RECEIPT_SCHEMA')
        elif kind == 'controller_hold':
            require(set(row) == {'kind', 'failure', 'dispatch_attempted'}
                    and type(row['dispatch_attempted']) is bool
                    and int(row['dispatch_attempted']) == terminal['dispatch_attempts'], 'RECEIPT_SCHEMA')
            hold = failure(row['failure'])
            require(hold is not None, 'RECEIPT_SCHEMA')
        elif kind == 'cleanup':
            require(kinds[0] == 'fresh_preflight' and set(row) == {'kind', 'facts'}
                    and row['facts'] == {'unit_absent': True, 'own_cgroup_absent': True, 'namespace_removed': True}
                    and all(type(value) is bool for value in row['facts'].values()), 'RECEIPT_SCHEMA')
            cleanup = True
        elif kind == 'cleanup_hold':
            require(kinds[0] == 'fresh_preflight' and set(row) == {'kind', 'failure'}
                    and failure(row['failure']) is not None and row['failure'] == cleanup_failure, 'RECEIPT_SCHEMA')
            cleanup = False
    require(first == (hold or (diagnostic or {}).get('first_failure'))
            and (cleanup_failure is None if cleanup is not False else cleanup_failure is not None), 'RECEIPT_SCHEMA')
    require(cleanup is None or terminal['cleanup_ok'] is cleanup, 'RECEIPT_SCHEMA')
    require(not terminal['dispatch_attempts'] or diagnostic is not None or hold is not None, 'RECEIPT_SCHEMA')
    if diagnostic is not None:
        require(terminal['dispatch_attempts'] == 1, 'RECEIPT_SCHEMA')
    setup_hold = any(event.get('kind') == 'synthetic_setup_hold' for event in (diagnostic or {}).get('events', []))
    execution = 'NOT_STARTED' if not terminal['dispatch_attempts'] or setup_hold else ('RESULT_REPORTED' if suite else 'UNVERIFIED')
    cases = sum(suite['counts']) if suite else None
    require(terminal['fixture_execution'] == execution and terminal['fixture_cases_reported'] == cases
            and (cases is None or type(terminal['fixture_cases_reported']) is int), 'RECEIPT_SCHEMA')
    if terminal['status'] == 'COMPLETE':
        validate_receipt(raw, verifier)  # Existing success admission stays exact.
    else:
        require(first is not None or cleanup_failure is not None, 'RECEIPT_SCHEMA')
    return {'status': terminal['status'], 'first_failure': first, 'cleanup_failure': cleanup_failure,
            'protocol_failure': (diagnostic or {}).get('protocol_failure'),
            'transport_failure': (diagnostic or {}).get('transport_failure'),
            'dispatch_attempts': terminal['dispatch_attempts'], 'fixture_execution': execution,
            'fixture_cases_reported': cases, 'cases_executed': 0 if execution == 'NOT_STARTED' else cases,
            'suite_counts': [dict((key, group[key]) for key in ('run', 'failures', 'errors', 'skipped',
                              'expected_failures', 'unexpected_successes')) for group in suite['groups']] if suite else None,
            'suite_diagnostics': suite_diagnostics(suite, verifier) if suite else None,
            'suite_case_codebook': {'case_index': 'FROZEN_SYNTHETIC_POLICY_ORDER',
                                   'outcomes': list(verifier.OUTCOMES),
                                   'exceptions': list(verifier.EXCEPTIONS),
                                   'reasons': list(verifier.REASONS),
                                   'payload_SHA256': verifier.PAYLOAD_SHA} if suite else None,
            'cleanup_ok': terminal['cleanup_ok']}

def container_unit_state(unit, timeout=3):
    result = selected(['/usr/bin/systemctl', 'show', unit, '-p', 'LoadState', '-p', 'Description',
                       '-p', 'Transient', '-p', 'ActiveState', '-p', 'MainPID'], timeout)
    require(result.returncode == 0, 'METADATA_HOLD')
    values = {}
    for line in result.stdout.decode('ascii').splitlines():
        key, separator, value = line.partition('=')
        require(separator and key not in values, 'METADATA_HOLD')
        values[key] = value
    require(set(values) == {'LoadState', 'Description', 'Transient', 'ActiveState', 'MainPID'}
            and values['Transient'] in ('yes', 'no')
            and re.fullmatch('[0-9]{1,10}', values['MainPID']), 'METADATA_HOLD')
    return values

def cleanup_container(unit, machine):
    """Stop only the exact owned service; success requires fresh absence proof."""
    summary = {'verified_absent': False, 'stage': 'METADATA', 'stop_returncode': None,
               'reset_returncode': None, 'last_observation': None}
    def owned(state):
        if state['LoadState'] == 'not-found':
            require(state['ActiveState'] == 'inactive' and state['MainPID'] == '0', 'CLEANUP_HOLD')
            return False
        summary['stage'] = 'OWNERSHIP'
        require(state['LoadState'] == 'loaded' and state['Description'] == machine
                and state['Transient'] == 'yes', 'OWNERSHIP_HOLD')
        return True
    def action(verb, timeout):
        try:
            result = selected(['/usr/bin/systemctl', verb, unit], timeout)
            require(type(result.returncode) is int and -255 <= result.returncode <= 255, 'CLEANUP_HOLD')
            return result.returncode
        except BaseException:
            return None  # Delivery uncertain; never retry. Verify final state.
    def state(timeout=3):
        summary['stage'] = 'METADATA'
        return container_unit_state(unit, timeout)
    try:
        current = state()
        if owned(current):
            summary['stage'] = 'STOP'
            summary['stop_returncode'] = action('stop', 12)
            current = state()
            if owned(current) and current['ActiveState'] == 'failed' and current['MainPID'] == '0':
                summary['stage'] = 'RESET'
                summary['reset_returncode'] = action('reset-failed', 3)
                current = state()
        deadline = time.monotonic() + 2
        while True:
            present = owned(current)
            summary['stage'] = 'VERIFY'
            cgroup_absent = not os.path.lexists('/sys/fs/cgroup/system.slice/' + unit)
            machine_absent = not os.path.lexists('/run/systemd/machines/' + machine)
            summary['last_observation'] = {'unit_absent': not present, 'own_cgroup_absent': cgroup_absent,
                                           'machine_registration_absent': machine_absent}
            resources_absent = cgroup_absent and machine_absent
            if not present and resources_absent:
                summary.update(verified_absent=True, stage='ABSENT')
                break
            if time.monotonic() >= deadline:
                break
            time.sleep(min(.1, max(0, deadline - time.monotonic())))
            current = state(max(.01, min(.5, deadline - time.monotonic())))
    except BaseException:
        pass  # Only this finite summary is exported, never metadata/errors.
    return summary

def main():
    failure = None
    clean = True
    launched = False
    validated = None
    diagnostic = None
    controller_returncode = None
    outer_cleanup = None
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
                if type(proc.returncode) is int and -255 <= proc.returncode <= 255:
                    controller_returncode = proc.returncode
                diagnostic = controller_diagnostic(bytes(data), verifier)
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
            outer_cleanup = cleanup_container(unit, machine)
            clean = outer_cleanup['verified_absent']
        # No recursive deletion: clean rootfs remains only on disposable runner.
        print(json.dumps({'kind': 'hosted_route_terminal', 'failure': failure,
                          'method_qualification': validated,
                          'controller_returncode': controller_returncode,
                          'controller_diagnostic': diagnostic,
                          'outer_cleanup': outer_cleanup,
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
