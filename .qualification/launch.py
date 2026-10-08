"""Closed synthetic telemetry only. No logs, paths, argv, env or exception text.

Embedded into each of the three reviewed programs by assemble.py. The numeric
codebook is source-bound. Observations are supplemental: they cannot admit a
runtime, fixture namespace, private inspector or preservation result.
"""
import math
DIAGNOSTIC_SCHEMA = 1
DIAGNOSTIC_COMPONENT = 'launcher'
DIAGNOSTIC_CODEBOOK_SHA = '577a4142a9c026126bbe19b348c338e66b1a772fe7739f3477bcd460e60998d8'
DIAGNOSTIC_GUARD_COUNT = 92
DIAGNOSTIC_PHASES = ('launch.identity', 'launch.bootstrap.update', 'launch.bootstrap.install', 'launch.bootstrap.debian', 'launch.container', 'launch.readiness', 'launch.controller', 'launch.cleanup', 'launch.cleanup.metadata', 'launch.cleanup.ownership', 'launch.cleanup.stop', 'launch.cleanup.reset', 'launch.cleanup.verify', 'launch.cleanup.absent')
DIAGNOSTIC_CONFIGS = {'controller': ['c4f34741a488de715b00f34afc586fa9bf71f1d6a944628810efdd7fb57272c0', 106, ['cleanup.cgroup', 'cleanup.inventory', 'cleanup.marker', 'cleanup.mounts', 'cleanup.remove', 'cleanup.unit', 'cleanup.unit_reset', 'cleanup.unit_stop', 'cleanup.verify', 'controller.identity', 'controller.interrupted', 'controller.marker', 'controller.namespace', 'controller.output', 'controller.payload', 'controller.preflight', 'controller.unit_absent', 'fixtures.suite', 'preflight.controllers', 'preflight.disk', 'preflight.healthz', 'preflight.identity', 'preflight.memory', 'preflight.metadata', 'preflight.paths', 'preflight.pressure', 'preflight.readyz', 'preflight.systemd', 'preflight.unit', 'scope.cpu', 'scope.identity', 'scope.memory_max', 'scope.namespace.absent', 'scope.namespace.incoming', 'scope.namespace.proc', 'scope.namespace.root', 'scope.namespace.run', 'scope.namespace.sys', 'scope.namespace.systemd', 'scope.namespace.var', 'scope.oom_group', 'scope.own_group', 'scope.pids_max', 'scope.priority', 'scope.readonly.bin', 'scope.readonly.lib', 'scope.readonly.lib64', 'scope.readonly.liblink', 'scope.readonly.limits', 'scope.resources', 'scope.rlimit_address', 'scope.rlimit_core', 'scope.rlimit_cpu', 'scope.rlimit_file', 'scope.swap_max', 'scope.temp', 'transport.deadline', 'transport.exit', 'transport.launch', 'transport.output_cap', 'transport.pipe', 'transport.protocol']], 'payload': ['230e77e080fcf92a6d3570afb87da2d7b54fe45353c02724f165d6e1686cacda', 55, ['cleanup.cgroup', 'cleanup.inventory', 'cleanup.marker', 'cleanup.mounts', 'cleanup.remove', 'cleanup.unit', 'cleanup.unit_reset', 'cleanup.unit_stop', 'cleanup.verify', 'controller.identity', 'controller.interrupted', 'controller.marker', 'controller.namespace', 'controller.output', 'controller.payload', 'controller.preflight', 'controller.unit_absent', 'fixtures.suite', 'preflight.controllers', 'preflight.disk', 'preflight.healthz', 'preflight.identity', 'preflight.memory', 'preflight.metadata', 'preflight.paths', 'preflight.pressure', 'preflight.readyz', 'preflight.systemd', 'preflight.unit', 'scope.cpu', 'scope.identity', 'scope.memory_max', 'scope.namespace.absent', 'scope.namespace.incoming', 'scope.namespace.proc', 'scope.namespace.root', 'scope.namespace.run', 'scope.namespace.sys', 'scope.namespace.systemd', 'scope.namespace.var', 'scope.oom_group', 'scope.own_group', 'scope.pids_max', 'scope.priority', 'scope.readonly.bin', 'scope.readonly.lib', 'scope.readonly.lib64', 'scope.readonly.liblink', 'scope.readonly.limits', 'scope.resources', 'scope.rlimit_address', 'scope.rlimit_core', 'scope.rlimit_cpu', 'scope.rlimit_file', 'scope.swap_max', 'scope.temp', 'transport.deadline', 'transport.exit', 'transport.launch', 'transport.output_cap', 'transport.pipe', 'transport.protocol']], 'launcher': ['577a4142a9c026126bbe19b348c338e66b1a772fe7739f3477bcd460e60998d8', 92, ['launch.identity', 'launch.bootstrap.update', 'launch.bootstrap.install', 'launch.bootstrap.debian', 'launch.container', 'launch.readiness', 'launch.controller', 'launch.cleanup', 'launch.cleanup.metadata', 'launch.cleanup.ownership', 'launch.cleanup.stop', 'launch.cleanup.reset', 'launch.cleanup.verify', 'launch.cleanup.absent']]}
METRIC_SPECS = (('mem_available', 'GITHUB_VM_GLOBAL', 'bytes', 'GE', 8589934592, 2 ** 53), ('memory_full_avg10', 'GITHUB_VM_GLOBAL', 'percent', 'LT', 1, 100), ('io_some_avg10', 'GITHUB_VM_GLOBAL', 'percent', 'LT', 5, 100), ('memory_max', 'OWN_FIXTURE_CGROUP', 'bytes', 'EQ', 134217728, 2 ** 53), ('swap_max', 'OWN_FIXTURE_CGROUP', 'bytes', 'EQ', 0, 2 ** 53), ('pids_max', 'OWN_FIXTURE_CGROUP', 'tasks', 'EQ', 4, 2 ** 53), ('oom_group', 'OWN_FIXTURE_CGROUP', 'boolean_integer', 'EQ', 1, 2 ** 53), ('cpu_quota', 'OWN_FIXTURE_CGROUP', 'microseconds', 'RELATED', None, 2 ** 53), ('cpu_period', 'OWN_FIXTURE_CGROUP', 'microseconds', 'RELATED', None, 2 ** 53), ('rlimit_cpu_soft', 'OWN_FIXTURE_PROCESS', 'seconds', 'LE', 5, 2 ** 53), ('rlimit_cpu_hard', 'OWN_FIXTURE_PROCESS', 'seconds', 'LE', 5, 2 ** 53), ('rlimit_file_soft', 'OWN_FIXTURE_PROCESS', 'bytes', 'LE', 4194304, 2 ** 53), ('rlimit_file_hard', 'OWN_FIXTURE_PROCESS', 'bytes', 'LE', 4194304, 2 ** 53), ('rlimit_address_soft', 'OWN_FIXTURE_PROCESS', 'bytes', 'LE', 536870912, 2 ** 53), ('rlimit_address_hard', 'OWN_FIXTURE_PROCESS', 'bytes', 'LE', 536870912, 2 ** 53), ('rlimit_core_soft', 'OWN_FIXTURE_PROCESS', 'bytes', 'LE', 0, 2 ** 53), ('rlimit_core_hard', 'OWN_FIXTURE_PROCESS', 'bytes', 'LE', 0, 2 ** 53), ('nice', 'OWN_FIXTURE_PROCESS', 'priority', 'EQ', 19, 100), ('temp_capacity', 'OWN_FIXTURE_NAMESPACE', 'bytes', 'LE', 16777216, 2 ** 53), ('metadata_bytes', 'CLEAN_SYNTHETIC_METADATA', 'bytes', 'RELATED', None, 2 ** 31), ('metadata_cap', 'CLEAN_SYNTHETIC_METADATA', 'bytes', 'RELATED', None, 2 ** 31), ('metadata_read_request', 'CLEAN_SYNTHETIC_METADATA', 'bytes', 'RELATED', None, 2 ** 31), ('metadata_accepted_bytes', 'CLEAN_SYNTHETIC_METADATA', 'bytes', 'RELATED', None, 2 ** 31), ('returncode', 'OWN_SYNTHETIC_COMMAND', 'exit_code', 'EQ', 0, 255), ('command_elapsed', 'OWN_SYNTHETIC_COMMAND', 'seconds', 'RELATED', None, 600), ('command_timeout', 'OWN_SYNTHETIC_COMMAND', 'seconds', 'RELATED', None, 600), ('stdout_bytes', 'OWN_SYNTHETIC_COMMAND', 'bytes', 'RELATED', None, 2 ** 31), ('stderr_bytes', 'OWN_SYNTHETIC_COMMAND', 'bytes', 'RELATED', None, 2 ** 31), ('systemd_version', 'CLEAN_SYNTHETIC_RUNTIME', 'version_integer', 'EQ', 252, 99999), ('systemd_manager_version', 'CLEAN_SYNTHETIC_RUNTIME', 'version_integer', 'EQ', 252, 99999), ('uid', 'OWN_SYNTHETIC_METADATA', 'uid', 'RELATED', None, 2 ** 32), ('gid', 'OWN_SYNTHETIC_METADATA', 'gid', 'EQ', 0, 2 ** 32), ('mode', 'OWN_SYNTHETIC_METADATA', 'permission_bits', 'RELATED', None, 4095), ('nlink', 'OWN_SYNTHETIC_METADATA', 'links', 'RELATED', None, 2 ** 32), ('size', 'OWN_SYNTHETIC_METADATA', 'bytes', 'RELATED', None, 2 ** 53), ('inventory_count', 'OWN_SYNTHETIC_NAMESPACE', 'entries', 'LT', 24, 2 ** 20), ('readiness_elapsed', 'GITHUB_VM_READINESS', 'seconds', 'LE', 20, 600), ('readiness_samples', 'GITHUB_VM_READINESS', 'samples', 'LE', 11, 11), ('outer_elapsed', 'OWN_CONTAINER', 'seconds', 'LT', 50, 600), ('load_state', 'OWN_SYNTHETIC_UNIT', 'closed_enum', 'RELATED', None, 20), ('active_state', 'OWN_SYNTHETIC_UNIT', 'closed_enum', 'RELATED', None, 20), ('transient', 'OWN_SYNTHETIC_UNIT', 'closed_enum', 'RELATED', None, 20), ('mainpid_zero', 'OWN_SYNTHETIC_UNIT', 'boolean_integer', 'RELATED', None, 1), ('file_kind', 'OWN_SYNTHETIC_METADATA', 'closed_enum', 'RELATED', None, 8), ('cgroup_absent', 'OWN_SYNTHETIC_CGROUP', 'boolean_integer', 'EQ', 1, 1), ('machine_absent', 'OWN_CONTAINER_REGISTRATION', 'boolean_integer', 'EQ', 1, 1), ('unit_absent', 'OWN_SYNTHETIC_UNIT', 'boolean_integer', 'EQ', 1, 1), ('prefix_absent', 'OWN_SYNTHETIC_NAMESPACE', 'boolean_integer', 'EQ', 1, 1), ('prefix_not_symlink', 'OWN_SYNTHETIC_NAMESPACE', 'boolean_integer', 'EQ', 1, 1), ('python_major', 'CLEAN_SYNTHETIC_RUNTIME', 'version_part', 'EQ', 3, 99999), ('python_minor', 'CLEAN_SYNTHETIC_RUNTIME', 'version_part', 'EQ', 11, 99999), ('python_patch', 'CLEAN_SYNTHETIC_RUNTIME', 'version_part', 'EQ', 2, 99999), ('sqlite_major', 'CLEAN_SYNTHETIC_RUNTIME', 'version_part', 'EQ', 3, 99999), ('sqlite_minor', 'CLEAN_SYNTHETIC_RUNTIME', 'version_part', 'EQ', 40, 99999), ('sqlite_patch', 'CLEAN_SYNTHETIC_RUNTIME', 'version_part', 'EQ', 1, 99999), ('architecture', 'CLEAN_SYNTHETIC_RUNTIME', 'closed_enum', 'EQ', 1, 3), ('platform', 'CLEAN_SYNTHETIC_RUNTIME', 'closed_enum', 'EQ', 1, 2), *(('preflight_path_' + str(i), 'CLEAN_SYNTHETIC_RUNTIME', 'boolean_integer', 'EQ', 1, 1) for i in range(8)))
STATE_ENUMS = {'LoadState': ('OTHER', 'loaded', 'not-found', 'error', 'bad-setting', 'masked', 'stub'), 'ActiveState': ('OTHER', 'active', 'reloading', 'inactive', 'failed', 'activating', 'deactivating', 'maintenance'), 'Transient': ('OTHER', 'yes', 'no'), 'architecture': ('OTHER', 'x86_64', 'aarch64', 'arm64'), 'platform': ('OTHER', 'linux', 'darwin')}
METRIC_NAMES = tuple((x[0] for x in METRIC_SPECS))
CATEGORIES = ('VALID', 'MISSING', 'MALFORMED', 'OUT_OF_DOMAIN', 'OS_ERROR', 'TIMEOUT', 'NONZERO_EXIT', 'OUTPUT_CAP', 'INTERRUPTED', 'PERMISSION_DENIED', 'MEMORY_ERROR', 'UNEXPECTED_EXCEPTION')
MAX_ROWS = 256
MAX_VALUES = 64
MAX_COUNT = 1048576
MAX_DIAGNOSTIC_BYTES = 5000
FLOAT_METRICS = frozenset(('memory_full_avg10', 'io_some_avg10', 'command_elapsed', 'command_timeout', 'readiness_elapsed', 'outer_elapsed'))

def category(exc):
    import subprocess
    hold = globals().get('ReadinessHold')
    if hold is not None and type(exc) is hold and (len(exc.args) == 1) and (type(exc.args[0]) is str) and (exc.args[0] in ('MALFORMED', 'OUT_OF_DOMAIN', 'OUTPUT_CAP')):
        return exc.args[0]
    for (kind, code) in ((PermissionError, 'PERMISSION_DENIED'), (FileNotFoundError, 'MISSING'), (subprocess.TimeoutExpired, 'TIMEOUT'), (subprocess.CalledProcessError, 'NONZERO_EXIT'), (KeyboardInterrupt, 'INTERRUPTED'), (MemoryError, 'MEMORY_ERROR'), (OSError, 'OS_ERROR'), (ValueError, 'MALFORMED')):
        if isinstance(exc, kind):
            return code
    return 'UNEXPECTED_EXCEPTION'

class DiagnosticLedger:

    def __init__(self):
        self.phase = DIAGNOSTIC_PHASES[0]
        self.guards = {}
        self.metrics = {}
        self.errors = {}
        self.incomplete = False
        self.omitted = 0

    def at(self, phase):
        if phase not in DIAGNOSTIC_PHASES:
            raise ValueError('DIAGNOSTIC_PHASE')
        self.phase = phase

    def _count(self, table, key):
        if key not in table and len(table) >= MAX_ROWS:
            self.incomplete = True
            self.omitted = min(MAX_COUNT, self.omitted + 1)
            return
        count = table.get(key, 0)
        if count >= MAX_COUNT:
            self.incomplete = True
            self.omitted = min(MAX_COUNT, self.omitted + 1)
            return
        table[key] = count + 1

    def guard(self, ident, value, phase=None):
        if type(ident) is not int or not 0 <= ident < DIAGNOSTIC_GUARD_COUNT:
            raise ValueError('DIAGNOSTIC_GUARD')
        phase = self.phase if phase is None else phase
        if phase not in DIAGNOSTIC_PHASES:
            raise ValueError('DIAGNOSTIC_PHASE')
        self._count(self.guards, (ident, DIAGNOSTIC_PHASES.index(phase), bool(value)))
        return value

    def error(self, exc, phase=None):
        phase = self.phase if phase is None else phase
        if phase not in DIAGNOSTIC_PHASES:
            raise ValueError('DIAGNOSTIC_PHASE')
        self._count(self.errors, (DIAGNOSTIC_PHASES.index(phase), CATEGORIES.index(category(exc))))

    def metric(self, name, value=None, status='VALID'):
        if name not in METRIC_NAMES or status not in CATEGORIES:
            raise ValueError('DIAGNOSTIC_METRIC')
        ident = METRIC_NAMES.index(name)
        if status == 'VALID':
            maximum = METRIC_SPECS[ident][-1]
            low = -255 if name == 'returncode' else -20 if name == 'nice' else -1 if name.startswith('rlimit_') else 0
            if type(value) not in (int, float) or not math.isfinite(value) or (name not in FLOAT_METRICS and type(value) is not int):
                (status, value) = ('MALFORMED', None)
            elif not low <= value <= maximum:
                (status, value) = ('OUT_OF_DOMAIN', None)
        else:
            value = None
        key = (ident, DIAGNOSTIC_PHASES.index(self.phase), CATEGORIES.index(status))
        if key not in self.metrics and len(self.metrics) >= MAX_ROWS:
            self.incomplete = True
            self.omitted = min(MAX_COUNT, self.omitted + 1)
            return
        values = self.metrics.setdefault(key, {})
        if value not in values and len(values) >= MAX_VALUES:
            self.incomplete = True
            self.omitted = min(MAX_COUNT, self.omitted + 1)
            return
        if values.get(value, 0) >= MAX_COUNT:
            self.incomplete = True
            self.omitted = min(MAX_COUNT, self.omitted + 1)
            return
        values[value] = values.get(value, 0) + 1

    def snapshot(self):
        body = {'schema': DIAGNOSTIC_SCHEMA, 'component': DIAGNOSTIC_COMPONENT, 'codebook_SHA256': DIAGNOSTIC_CODEBOOK_SHA, 'guards': [[*k, count] for (k, count) in sorted(self.guards.items())], 'metrics': [[*k, [[v, n] for (v, n) in values.items()]] for (k, values) in sorted(self.metrics.items())], 'errors': [[*k, count] for (k, count) in sorted(self.errors.items())], 'incomplete': self.incomplete, 'observations_omitted': self.omitted}
        import json
        body['guards'].sort(key=lambda row: row[2])

        def metric_priority(row):
            if row[2] != CATEGORIES.index('VALID'):
                return 0
            spec = METRIC_SPECS[row[0]]

            def satisfies(value):
                if spec[3] == 'GE':
                    return value >= spec[4]
                if spec[3] == 'LT':
                    return value < spec[4]
                if spec[3] == 'LE':
                    return value <= spec[4]
                if spec[3] == 'EQ':
                    return value == spec[4]
                return False
            return int(all((satisfies(value) for (value, _) in row[3])))
        body['metrics'].sort(key=metric_priority)
        source_rows = {key: body[key] for key in ('guards', 'metrics', 'errors')}
        for key in source_rows:
            body[key] = []
        reserve = dict(body, observations_omitted=MAX_COUNT, incomplete=False)
        remaining = MAX_DIAGNOSTIC_BYTES - len(json.dumps(reserve, sort_keys=True, allow_nan=False).encode())

        def omitted(count):
            body['incomplete'] = True
            body['observations_omitted'] = min(MAX_COUNT, body['observations_omitted'] + count)

        def keep(key, row):
            nonlocal remaining
            cost = len(json.dumps(row, allow_nan=False).encode()) + (2 if body[key] else 0)
            if cost <= remaining:
                body[key].append(row)
                remaining -= cost
            else:
                omitted(row[-1])
        for row in source_rows['errors']:
            keep('errors', row)
        for row in source_rows['guards']:
            if not row[2]:
                keep('guards', row)
        for row in source_rows['metrics']:
            retained = []
            overhead = len(json.dumps(row[:3] + [[]], allow_nan=False).encode()) + (2 if body['metrics'] else 0)
            for pair in row[3]:
                cost = len(json.dumps(pair, allow_nan=False).encode()) + (2 if retained else overhead)
                if cost <= remaining:
                    retained.append(pair)
                    remaining -= cost
                else:
                    omitted(pair[1])
            if retained:
                body['metrics'].append(row[:3] + [retained])
        for row in source_rows['guards']:
            if row[2]:
                keep('guards', row)
        validate_diagnostics(body)
        return body

def observed(name, value):
    D.metric(name, value)
    return value

def observed_stat(name, value):
    import stat
    D.metric(name, stat.S_IMODE(value) if name == 'mode' else value)
    if name == 'mode':
        types = (stat.S_IFDIR, stat.S_IFREG, stat.S_IFLNK, stat.S_IFSOCK, stat.S_IFIFO, stat.S_IFCHR, stat.S_IFBLK)
        kind = stat.S_IFMT(value)
        D.metric('file_kind', types.index(kind) + 1 if kind in types else 0)
    return value

def observed_state(key, value):
    if key == 'MainPID':
        D.metric('mainpid_zero', int(value in ('0', 0)))
    elif key in STATE_ENUMS:
        enums = STATE_ENUMS[key]
        name = {'LoadState': 'load_state', 'ActiveState': 'active_state', 'Transient': 'transient'}.get(key, key)
        D.metric(name, enums.index(value) if value in enums else 0)
    return value

def observed_version(name, value):
    if type(value) is str and len(value) <= 24 and (len(value.split('.')) == 3) and all((part.isascii() and part.isdigit() and (0 < len(part) <= 5) for part in value.split('.'))):
        for (label, part) in zip(('major', 'minor', 'patch'), value.split('.')):
            D.metric(name + '_' + label, int(part))
    else:
        for label in ('major', 'minor', 'patch'):
            D.metric(name + '_' + label, status='MALFORMED')
    return value

def observed_rlimit(label, value):
    D.metric('rlimit_' + label + '_soft', value[0])
    D.metric('rlimit_' + label + '_hard', value[1])
    return value

def observed_bytes(value, cap):
    D.metric('metadata_bytes', len(value))
    D.metric('metadata_read_request', cap)
    return value

def observed_run(*args, **kwargs):
    import subprocess
    import time
    start = time.monotonic()
    timeout = kwargs.get('timeout')
    if timeout is not None:
        D.metric('command_timeout', timeout)
    try:
        result = subprocess.run(*args, **kwargs)
        D.metric('returncode', result.returncode)
        if type(result.stdout) in (bytes, str):
            D.metric('stdout_bytes', len(result.stdout))
        if type(result.stderr) in (bytes, str):
            D.metric('stderr_bytes', len(result.stderr))
        return result
    except BaseException as exc:
        D.error(exc)
        if isinstance(exc, subprocess.CalledProcessError):
            D.metric('returncode', exc.returncode)
        raise
    finally:
        D.metric('command_elapsed', round(time.monotonic() - start, 6))

def validate_diagnostics(body, component=None):
    component = DIAGNOSTIC_COMPONENT if component is None else component
    if component not in DIAGNOSTIC_CONFIGS:
        raise ValueError('DIAGNOSTIC_COMPONENT')
    (codebook_sha, guard_count, phases) = DIAGNOSTIC_CONFIGS[component]

    def need(value):
        if not value:
            raise ValueError('DIAGNOSTIC_SCHEMA')

    def integer(value, high=MAX_COUNT):
        return type(value) is int and 0 <= value <= high
    need(type(body) is dict and set(body) == {'schema', 'component', 'codebook_SHA256', 'guards', 'metrics', 'errors', 'incomplete', 'observations_omitted'})
    need(type(body['schema']) is int and body['schema'] == DIAGNOSTIC_SCHEMA and (type(body['component']) is str) and (body['component'] == component) and (type(body['codebook_SHA256']) is str) and (body['codebook_SHA256'] == codebook_sha) and (type(body['incomplete']) is bool))
    need(integer(body['observations_omitted']) and (body['incomplete'] or body['observations_omitted'] == 0))
    import json
    need(len(json.dumps(body, sort_keys=True, allow_nan=False).encode()) <= MAX_DIAGNOSTIC_BYTES)
    for (key, length) in (('guards', 4), ('metrics', 4), ('errors', 3)):
        rows = body[key]
        need(type(rows) is list and len(rows) <= MAX_ROWS)
        seen = set()
        for row in rows:
            need(type(row) is list and len(row) == length)
            prefix = row[:3] if key != 'errors' else row[:2]
            need(all((type(x) in (int, bool) for x in prefix)))
            need(tuple(prefix) not in seen)
            seen.add(tuple(prefix))
            phase = prefix[0] if key == 'errors' else prefix[1]
            need(integer(phase, len(phases) - 1))
            if key == 'guards':
                need(integer(prefix[0], guard_count - 1) and type(prefix[2]) is bool and integer(row[3]) and (row[3] > 0))
            elif key == 'errors':
                need(integer(prefix[1], len(CATEGORIES) - 1) and integer(row[2]) and (row[2] > 0))
            else:
                need(integer(prefix[0], len(METRIC_SPECS) - 1) and integer(prefix[2], len(CATEGORIES) - 1) and (type(row[3]) is list) and (0 < len(row[3]) <= MAX_VALUES))
                observed = set()
                for pair in row[3]:
                    need(type(pair) is list and len(pair) == 2 and integer(pair[1]) and (pair[1] > 0))
                    value = pair[0]
                    need(type(value) in (int, float, type(None)))
                    if prefix[2] == 0:
                        spec = METRIC_SPECS[prefix[0]]
                        low = -255 if spec[0] == 'returncode' else -20 if spec[0] == 'nice' else -1 if spec[0].startswith('rlimit_') else 0
                        need(type(value) in (int, float) and math.isfinite(value) and (low <= value <= spec[-1]))
                        need(spec[0] in FLOAT_METRICS or type(value) is int)
                    else:
                        need(value is None)
                    need(value not in observed)
                    observed.add(value)
    return body
D = DiagnosticLedger() if DIAGNOSTIC_PHASES else None
'Bounded GitHub VM readiness sampling; never samples private GCP data.\n\nThe launcher uses these host /proc readings before the nspawn controller. Both\nobserve the same VM kernel globals. The controller still takes a fresh sample.\n'
import math
import time

class ReadinessHold(ValueError):
    pass

def bounded_ascii(path, maximum):
    ledger = globals().get('D')
    if ledger is not None:
        ledger.metric('metadata_cap', maximum)
    with open(path, 'rb') as stream:
        raw = stream.read(maximum + 1)
    if ledger is not None:
        ledger.metric('metadata_bytes', len(raw))
        ledger.metric('metadata_read_request', maximum + 1)
    if len(raw) > maximum:
        raise ReadinessHold('OUTPUT_CAP')
    return raw.decode('ascii')

def parse_memory(text):
    rows = [line.split() for line in text.splitlines() if line.startswith('MemAvailable:')]
    if len(rows) != 1 or len(rows[0]) != 3 or rows[0][0] != 'MemAvailable:' or (rows[0][2] != 'kB') or (not rows[0][1].isascii()) or (not rows[0][1].isdigit()) or (len(rows[0][1]) > 20):
        raise ReadinessHold('MALFORMED')
    value = int(rows[0][1]) * 1024
    if not 0 <= value <= 2 ** 53:
        raise ReadinessHold('OUT_OF_DOMAIN')
    return value

def parse_pressure(text, kind):
    rows = [line for line in text.splitlines() if line.startswith(kind + ' ')]
    if len(rows) != 1:
        raise ReadinessHold('MALFORMED')
    values = [field[6:] for field in rows[0].split() if field.startswith('avg10=')]
    if len(values) != 1 or len(values[0]) > 32 or (not values[0].isascii()):
        raise ReadinessHold('MALFORMED')
    try:
        value = float(values[0])
    except ValueError:
        raise ReadinessHold('MALFORMED') from None
    if not math.isfinite(value) or not 0 <= value <= 100:
        raise ReadinessHold('OUT_OF_DOMAIN')
    return value

def sample(read=bounded_ascii):
    observations = {}
    for (key, path, maximum, parser) in (('mem_available', '/proc/meminfo', 32768, parse_memory), ('memory_full_avg10', '/proc/pressure/memory', 1024, lambda text: parse_pressure(text, 'full')), ('io_some_avg10', '/proc/pressure/io', 1024, lambda text: parse_pressure(text, 'some'))):
        try:
            observations[key] = ['VALID', parser(read(path, maximum))]
        except BaseException as exc:
            if type(exc) is ReadinessHold and len(exc.args) == 1 and (type(exc.args[0]) is str) and (exc.args[0] in ('MALFORMED', 'OUT_OF_DOMAIN', 'OUTPUT_CAP')):
                code = exc.args[0]
            elif isinstance(exc, PermissionError):
                code = 'PERMISSION_DENIED'
            elif isinstance(exc, FileNotFoundError):
                code = 'MISSING'
            elif isinstance(exc, UnicodeError):
                code = 'MALFORMED'
            elif isinstance(exc, OSError):
                code = 'OS_ERROR'
            elif isinstance(exc, KeyboardInterrupt):
                code = 'INTERRUPTED'
            elif isinstance(exc, MemoryError):
                code = 'MEMORY_ERROR'
            else:
                code = 'UNEXPECTED_EXCEPTION'
            observations[key] = [code, None]
    return observations

def healthy(observations):
    if type(observations) is not dict or set(observations) != {'mem_available', 'memory_full_avg10', 'io_some_avg10'}:
        return False
    for (key, pair) in observations.items():
        if type(pair) is not list or len(pair) != 2 or pair[0] != 'VALID' or (type(pair[1]) not in (int, float)) or (not math.isfinite(pair[1])) or (not 0 <= pair[1] <= (2 ** 53 if key == 'mem_available' else 100)) or (key == 'mem_available' and type(pair[1]) is not int):
            return False
    return all((value[0] == 'VALID' for value in observations.values())) and observations['mem_available'][1] >= 8589934592 and (observations['memory_full_avg10'][1] < 1) and (observations['io_some_avg10'][1] < 5)

def settle(outer_start, identity, observe=sample, clock=time.monotonic, sleep=time.sleep):
    """At most20s/11 samples; reserve70s of the outer120s lifetime.

    No fixture or controller dispatch occurs here. Never retry malformed or
    unavailable metadata. Two complete consecutive samples2s apart are required.
    Caller always retains the returned closed receipt, including expiry/identity
    failure. The admission decision rejects observations completed at deadline.
    """
    start = clock()
    deadline = min(start + 20, outer_start + 50)
    receipt = {'scope': 'GITHUB_VM_GLOBAL_READINESS_ONLY', 'status': 'TIME_BUDGET_HOLD', 'thresholds': {'mem_available_GE_bytes': 8589934592, 'memory_full_avg10_LT_percent': 1, 'io_some_avg10_LT_percent': 5}, 'samples': [], 'elapsed_seconds': 0.0, 'fixture_dispatches': 0, 'max_seconds': 20, 'max_samples': 11, 'required_consecutive': 2, 'interval_seconds': 2, 'outer_lifetime_seconds': 120, 'reserved_controller_and_cleanup_seconds': 70, 'available_window_seconds': max(0.0, min(20.0, deadline - start))}
    consecutive = 0
    while clock() < deadline and len(receipt['samples']) < 11:
        try:
            identity()
        except BaseException:
            receipt['status'] = 'IDENTITY_HOLD'
            break
        if clock() >= deadline:
            break
        values = observe()
        now = clock()
        receipt['samples'].append({'elapsed_seconds': round(max(0, now - start), 6), 'observations': values})
        if any((value[0] != 'VALID' for value in values.values())):
            receipt['status'] = 'METADATA_HOLD'
            break
        if now >= deadline:
            break
        consecutive = consecutive + 1 if healthy(values) else 0
        if consecutive >= 2:
            receipt['status'] = 'READY'
            break
        remaining = deadline - clock()
        if remaining < 2:
            break
        sleep(2)
    receipt['elapsed_seconds'] = round(max(0, clock() - start), 6)
    if receipt['status'] == 'TIME_BUDGET_HOLD' and receipt['samples']:
        receipt['status'] = 'SETTLING_EXPIRED'
    return receipt

def validate_readiness(body):

    def need(value):
        if not value:
            raise ValueError('READINESS_SCHEMA')
    expected = settle(0, lambda : None, clock=lambda : 50, sleep=lambda _: None)
    need(type(body) is dict and set(body) == set(expected))
    for key in expected:
        if key not in ('status', 'samples', 'elapsed_seconds', 'available_window_seconds'):

            def same(actual, wanted):
                return type(actual) is type(wanted) and (set(actual) == set(wanted) and all((same(actual[k], wanted[k]) for k in wanted)) if type(wanted) is dict else actual == wanted)
            need(same(body[key], expected[key]))
    need(type(body['available_window_seconds']) in (int, float) and math.isfinite(body['available_window_seconds']) and (0 <= body['available_window_seconds'] <= 20))
    need(type(body['status']) is str and body['status'] in ('READY', 'TIME_BUDGET_HOLD', 'IDENTITY_HOLD', 'METADATA_HOLD', 'SETTLING_EXPIRED'))
    need(type(body['elapsed_seconds']) in (int, float) and math.isfinite(body['elapsed_seconds']) and (0 <= body['elapsed_seconds'] <= 120))
    need(type(body['samples']) is list and len(body['samples']) <= 11)
    previous = -2
    for row in body['samples']:
        need(type(row) is dict and set(row) == {'elapsed_seconds', 'observations'})
        elapsed = row['elapsed_seconds']
        need(type(elapsed) in (int, float) and math.isfinite(elapsed) and (previous + 2 <= elapsed <= 120))
        need(elapsed <= body['elapsed_seconds'])
        previous = elapsed
        values = row['observations']
        need(type(values) is dict and set(values) == {'mem_available', 'memory_full_avg10', 'io_some_avg10'})
        for (key, pair) in values.items():
            need(type(pair) is list and len(pair) == 2)
            need(type(pair[0]) is str and pair[0] in ('VALID', 'MALFORMED', 'OUT_OF_DOMAIN', 'OUTPUT_CAP', 'PERMISSION_DENIED', 'MISSING', 'OS_ERROR', 'INTERRUPTED', 'MEMORY_ERROR', 'UNEXPECTED_EXCEPTION'))
            if pair[0] == 'VALID':
                high = 2 ** 53 if key == 'mem_available' else 100
                need(type(pair[1]) in (int, float) and math.isfinite(pair[1]) and (0 <= pair[1] <= high))
                if key == 'mem_available':
                    need(type(pair[1]) is int)
            else:
                need(pair[1] is None)
    if body['status'] == 'READY':
        need(len(body['samples']) >= 2 and body['elapsed_seconds'] < 20 and (body['elapsed_seconds'] < body['available_window_seconds']) and (body['samples'][-1]['elapsed_seconds'] <= body['elapsed_seconds']) and all((healthy(row['observations']) for row in body['samples'][-2:])))
    return body
'Proposed standard runner bootstrap. Entry refuses before environment/IO.\n\nNo GCP/SSH/data route. Runs a clean Debian12 systemd manager in a container.\nActivation requires frozen commit/run identity and all three source guards.\n'
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
CONTROLLER_SHA = '5840a15c1444f00b3c3699ec73da3aa452f411b4d044095b46998e4a7bb31189'
SNAPSHOT = 'https://snapshot.debian.org/archive/debian/20260927T000000Z/'

def require(value, code):
    if not value:
        raise RuntimeError(code)

def command(argv, timeout, input=None):
    D.metric('command_timeout', timeout)
    command_start = time.monotonic()
    require(D.guard(0, input is None), 'COMMAND_HOLD')
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'DEBIAN_FRONTEND': 'noninteractive'})
    try:
        proc.wait(timeout=timeout)
    except BaseException as exc:
        D.error(exc)
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError as diagnostic_exception:
            D.error(diagnostic_exception)
            pass
        proc.wait(timeout=3)
        raise
    finally:
        D.metric('command_elapsed', time.monotonic() - command_start)
        D.metric('returncode', proc.returncode) if type(proc.returncode) is int else None
    require(D.guard(1, proc.returncode == 0), 'COMMAND_HOLD')

def selected(argv, timeout=3):
    result = observed_run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    require(D.guard(2, len(result.stdout) + len(result.stderr) <= 4096), 'METADATA_CAP')
    return result

def identity(env):
    require(D.guard(3, env.get('GITHUB_REPOSITORY') == 'fr-meyer/openclaw'), 'REPOSITORY_HOLD')
    require(D.guard(4, env.get('GITHUB_REPOSITORY_ID') == '1309456040'), 'REPOSITORY_ID_HOLD')
    require(D.guard(5, env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'), 'EVENT_HOLD')
    approved = env.get('SYNTHETIC124_APPROVED_COMMIT')
    require(D.guard(6, type(approved) is str and re.fullmatch('[0-9a-f]{40}', approved)), 'UNBOUND_COMMIT')
    run_id = env.get('GITHUB_RUN_ID')
    require(D.guard(7, type(run_id) is str and re.fullmatch('[0-9]{1,20}', run_id)), 'UNBOUND_RUN')
    require(D.guard(8, env.get('GITHUB_SHA') == approved), 'COMMIT_HOLD')
    require(D.guard(9, env.get('GITHUB_RUN_ATTEMPT') == '1'), 'RUN_HOLD')
    require(D.guard(10, env.get('GITHUB_REF') == 'refs/heads/qualification/synthetic124-sanitized-debian12-20261007'), 'REF_HOLD')
    return run_id

def validate_receipt(raw, verifier):
    """Accept a full schema-checked controller pass; never print raw output."""
    require(D.guard(11, len(raw) <= 20480), 'RECEIPT_CAP')
    lines = raw.splitlines()
    require(D.guard(12, len(lines) == 4 and all((len(line) <= 16384 for line in lines))), 'RECEIPT_SCHEMA')
    try:
        rows = [json.loads(line) for line in lines]
    except (ValueError, UnicodeError) as diagnostic_exception:
        D.error(diagnostic_exception)
        raise RuntimeError('RECEIPT_SCHEMA') from None
    require(D.guard(13, all((type(row) is dict for row in rows))), 'RECEIPT_SCHEMA')
    require(D.guard(14, [row.get('kind') for row in rows] == ['fresh_preflight', 'diagnostic_result', 'cleanup', 'terminal']), 'RECEIPT_SCHEMA')
    (preflight, diagnostic, cleanup, terminal) = rows
    expected = {'admitted': True, 'scope': 'DISPOSABLE_HOSTED_DEBIAN12_SYNTHETIC_ONLY', 'exact_runtime': {'Python': '3.11.2', 'SQLite': '3.40.1', 'systemd': '252', 'architecture': 'x86_64'}, 'fixtures_started': False, 'production_data_access': False}
    require(D.guard(15, set(preflight) == {'kind', 'facts'} and preflight['facts'] == expected), 'RECEIPT_SCHEMA')
    require(D.guard(16, all((type(preflight['facts'][key]) is bool for key in ('admitted', 'fixtures_started', 'production_data_access')))), 'RECEIPT_SCHEMA')
    require(D.guard(17, set(diagnostic) == {'kind', 'facts'}), 'RECEIPT_SCHEMA')
    facts = diagnostic['facts']
    require(D.guard(18, type(facts) is dict and set(facts) == {'events', 'first_failure', 'protocol_failure', 'transport_failure', 'exit', 'elapsed_seconds', 'input_bytes_sent', 'stdout_bytes', 'stderr_bytes'}), 'RECEIPT_SCHEMA')
    require(D.guard(19, all((facts[key] is None for key in ('first_failure', 'protocol_failure', 'transport_failure')))), 'CONTROLLER_HOLD')
    require(D.guard(20, type(facts['exit']) is int and facts['exit'] == 0), 'CONTROLLER_HOLD')
    require(D.guard(21, type(facts['events']) is list and len(facts['events']) == 3), 'RECEIPT_SCHEMA')
    parsed = verifier.parse_child(b'\n'.join((json.dumps(event, allow_nan=False).encode() for event in facts['events'])))
    require(D.guard(22, parsed['first_failure'] is None and parsed['protocol_failure'] is None and (parsed['events'] == facts['events'])), 'RECEIPT_SCHEMA')
    suite = facts['events'][1]['facts']
    require(D.guard(23, suite['runtime'] == {'Python': '3.11.2', 'SQLite': '3.40.1', 'platform': 'linux', 'architecture': 'x86_64'}), 'RECEIPT_SCHEMA')
    require(D.guard(24, type(facts['input_bytes_sent']) is int and facts['input_bytes_sent'] == len(verifier.PAYLOAD.encode())), 'RECEIPT_SCHEMA')
    require(D.guard(25, all((type(facts[key]) is int and 0 <= facts[key] <= 16384 for key in ('stdout_bytes', 'stderr_bytes'))) and facts['stdout_bytes'] + facts['stderr_bytes'] <= 16384), 'RECEIPT_CAP')
    require(D.guard(26, type(facts['elapsed_seconds']) in (int, float) and 0 <= facts['elapsed_seconds'] <= 35), 'RECEIPT_SCHEMA')
    require(D.guard(27, set(cleanup) == {'kind', 'facts'} and cleanup['facts'] == {'unit_absent': True, 'own_cgroup_absent': True, 'namespace_removed': True} and all((type(value) is bool for value in cleanup['facts'].values()))), 'RECEIPT_SCHEMA')
    require(D.guard(28, terminal == {'kind': 'terminal', 'status': 'COMPLETE', 'dispatch_attempts': 1, 'fixture_cases_reported': 124, 'fixture_execution': 'RESULT_REPORTED', 'first_failure': None, 'cleanup_failure': None, 'cleanup_ok': True, 'no_automatic_retry': True} and type(terminal['dispatch_attempts']) is int and (type(terminal['fixture_cases_reported']) is int) and (type(terminal['cleanup_ok']) is bool) and (type(terminal['no_automatic_retry']) is bool)), 'CONTROLLER_HOLD')
    return {'fixtures': 124, 'counts': [29, 95], 'scope_verified': True, 'controller_cleanup_verified': True, 'exact_userland': expected['exact_runtime'], 'scope': expected['scope']}

def suite_diagnostics(suite, verifier):
    """Export schema-checked synthetic facts only, with explicit omissions."""
    verifier.validate_facts(suite, verifier.POLICY)
    groups = []
    for group in suite['groups']:
        cases = []
        for (case, outcome, exception, reason, count) in group['case_records']:
            cases.append({'case': verifier.POLICY['cases'][case] if case >= 0 else 'UNRECOGNIZED_CASE', 'stage': 'fixtures.suite', 'outcome': verifier.OUTCOMES[outcome], 'exception': verifier.EXCEPTIONS[exception], 'assertion_reason': verifier.REASONS[reason], 'events': count})
        details = [dict(detail, stage='fixtures.suite', assertion_reason=verifier.assertion_reason(detail)) for detail in group['details']]
        groups.append({'run': group['run'], 'issue_count': group['issue_count'], 'unrecognized_cases': group['unrecognized_cases'], 'cases': cases, 'expanded_case_events_omitted': 0, 'case_records': [list(record) for record in group['case_records']], 'case_records_omitted': group['case_records_omitted'], 'details': details, 'details_omitted': group['details_omitted'], 'case_records_complete': group['case_records_omitted'] == 0, 'expanded_cases_complete': group['case_records_omitted'] == 0})
    while len(json.dumps(groups, allow_nan=False).encode()) > 8192:
        detailed = [group for group in groups if group['details']]
        if detailed:
            group = max(detailed, key=lambda group: len(group['details']))
            group['details'].pop()
            group['details_omitted'] += 1
        else:
            group = max(groups, key=lambda group: len(group['cases']))
            group['expanded_case_events_omitted'] += group['cases'].pop()['events']
            group['expanded_cases_complete'] = False
    require(D.guard(29, len(json.dumps(groups, allow_nan=False).encode()) <= 8192), 'RECEIPT_CAP')
    return groups

def controller_diagnostic(raw, verifier):
    """Retain closed failure facts before the exit gate; never export raw rows."""

    def pairs(items):
        value = {}
        for (key, item) in items:
            require(D.guard(30, key not in value), 'RECEIPT_SCHEMA')
            value[key] = item
        return value

    def integer(value, low, high):
        return type(value) is int and low <= value <= high

    def failure(value):
        require(D.guard(31, value is None or verifier.valid_failure(value)), 'RECEIPT_SCHEMA')
        return value
    require(D.guard(32, len(raw) <= 20480), 'RECEIPT_CAP')
    lines = raw.splitlines()
    require(D.guard(33, 2 <= len(lines) <= 5 and all((len(line) <= 16384 for line in lines))), 'RECEIPT_SCHEMA')
    try:
        rows = [json.loads(line, object_pairs_hook=pairs, parse_constant=lambda _: require(D.guard(34, False), 'RECEIPT_SCHEMA')) for line in lines]
    except (ValueError, UnicodeError) as diagnostic_exception:
        D.error(diagnostic_exception)
        raise RuntimeError('RECEIPT_SCHEMA') from None
    require(D.guard(35, all((type(row) is dict for row in rows))), 'RECEIPT_SCHEMA')
    order = {'fresh_preflight': 0, 'diagnostic_result': 1, 'controller_hold': 2, 'cleanup': 3, 'cleanup_hold': 3, 'terminal': 4}
    kinds = [row.get('kind') for row in rows]
    require(D.guard(36, all((type(k) is str and k in order for k in kinds)) and kinds[-1] == 'terminal' and all((order[a] < order[b] for (a, b) in zip(kinds, kinds[1:])))), 'RECEIPT_SCHEMA')
    terminal = rows[-1]
    require(D.guard(37, set(terminal) == {'kind', 'status', 'dispatch_attempts', 'fixture_cases_reported', 'fixture_execution', 'first_failure', 'cleanup_failure', 'cleanup_ok', 'no_automatic_retry'}), 'RECEIPT_SCHEMA')
    require(D.guard(38, terminal['status'] in ('COMPLETE', 'FIXED_HOLD') and integer(terminal['dispatch_attempts'], 0, 1) and (type(terminal['cleanup_ok']) is bool) and (terminal['no_automatic_retry'] is True)), 'RECEIPT_SCHEMA')
    first = failure(terminal['first_failure'])
    cleanup_failure = failure(terminal['cleanup_failure'])
    diagnostic = suite = hold = cleanup = None
    for row in rows[:-1]:
        kind = row['kind']
        if kind == 'fresh_preflight':
            expected = {'admitted': True, 'scope': 'DISPOSABLE_HOSTED_DEBIAN12_SYNTHETIC_ONLY', 'exact_runtime': {'Python': '3.11.2', 'SQLite': '3.40.1', 'systemd': '252', 'architecture': 'x86_64'}, 'fixtures_started': False, 'production_data_access': False}
            require(D.guard(39, set(row) == {'kind', 'facts'} and row['facts'] == expected and all((type(row['facts'][key]) is bool for key in ('admitted', 'fixtures_started', 'production_data_access')))), 'RECEIPT_SCHEMA')
        elif kind == 'diagnostic_result':
            require(D.guard(40, kinds[0] == 'fresh_preflight' and set(row) == {'kind', 'facts'}), 'RECEIPT_SCHEMA')
            diagnostic = row['facts']
            require(D.guard(41, type(diagnostic) is dict and set(diagnostic) == {'events', 'first_failure', 'protocol_failure', 'transport_failure', 'exit', 'elapsed_seconds', 'input_bytes_sent', 'stdout_bytes', 'stderr_bytes'}), 'RECEIPT_SCHEMA')
            require(D.guard(42, type(diagnostic['events']) is list and len(diagnostic['events']) <= 3), 'RECEIPT_SCHEMA')
            parsed = verifier.parse_child(b'\n'.join((json.dumps(event, allow_nan=False).encode() for event in diagnostic['events'])))
            protocol = failure(diagnostic['protocol_failure'])
            require(D.guard(43, parsed['events'] == diagnostic['events'] and (protocol is None or protocol['stage'] == 'transport.protocol') and (parsed['protocol_failure'] is None or protocol is not None)), 'RECEIPT_SCHEMA')
            transport = failure(diagnostic['transport_failure'])
            child = next((event['failure'] for event in parsed['events'] if event.get('kind') in ('synthetic_setup_hold', 'synthetic_resource_hold')), None)
            suite = next((event['facts'] for event in parsed['events'] if event.get('scope') == 'LINUX_SYNTHETIC_UNIT_SUITE_ONLY'), None)
            require(D.guard(44, diagnostic['exit'] is None or integer(diagnostic['exit'], -255, 255)), 'RECEIPT_SCHEMA')
            exit_failure = {'stage': 'transport.exit', 'error': 'NONZERO_EXIT'} if diagnostic['exit'] not in (0, None) else None
            primary = ({'stage': 'fixtures.suite', 'error': 'SUITE_FAILURE'} if suite and (not suite['ok']) else None) or child or transport or exit_failure or protocol
            require(D.guard(45, failure(diagnostic['first_failure']) == primary), 'RECEIPT_SCHEMA')
            require(D.guard(46, integer(diagnostic['input_bytes_sent'], 0, len(verifier.PAYLOAD.encode())) and all((integer(diagnostic[key], 0, 16384) for key in ('stdout_bytes', 'stderr_bytes'))) and (diagnostic['stdout_bytes'] + diagnostic['stderr_bytes'] <= 16384)), 'RECEIPT_SCHEMA')
            elapsed = diagnostic['elapsed_seconds']
            require(D.guard(47, type(elapsed) in (int, float) and math.isfinite(elapsed) and (0 <= elapsed <= 35)), 'RECEIPT_SCHEMA')
        elif kind == 'controller_hold':
            require(D.guard(48, set(row) == {'kind', 'failure', 'dispatch_attempted'} and type(row['dispatch_attempted']) is bool and (int(row['dispatch_attempted']) == terminal['dispatch_attempts'])), 'RECEIPT_SCHEMA')
            hold = failure(row['failure'])
            require(D.guard(49, hold is not None), 'RECEIPT_SCHEMA')
        elif kind == 'cleanup':
            require(D.guard(50, kinds[0] == 'fresh_preflight' and set(row) == {'kind', 'facts'} and (row['facts'] == {'unit_absent': True, 'own_cgroup_absent': True, 'namespace_removed': True}) and all((type(value) is bool for value in row['facts'].values()))), 'RECEIPT_SCHEMA')
            cleanup = True
        elif kind == 'cleanup_hold':
            require(D.guard(51, kinds[0] == 'fresh_preflight' and set(row) == {'kind', 'failure'} and (failure(row['failure']) is not None) and (row['failure'] == cleanup_failure)), 'RECEIPT_SCHEMA')
            cleanup = False
    require(D.guard(52, first == (hold or (diagnostic or {}).get('first_failure')) and (cleanup_failure is None if cleanup is not False else cleanup_failure is not None)), 'RECEIPT_SCHEMA')
    require(D.guard(53, cleanup is None or terminal['cleanup_ok'] is cleanup), 'RECEIPT_SCHEMA')
    require(D.guard(54, not terminal['dispatch_attempts'] or diagnostic is not None or hold is not None), 'RECEIPT_SCHEMA')
    if diagnostic is not None:
        require(D.guard(55, terminal['dispatch_attempts'] == 1), 'RECEIPT_SCHEMA')
    setup_hold = any((event.get('kind') == 'synthetic_setup_hold' for event in (diagnostic or {}).get('events', [])))
    execution = 'NOT_STARTED' if not terminal['dispatch_attempts'] or setup_hold else 'RESULT_REPORTED' if suite else 'UNVERIFIED'
    cases = sum(suite['counts']) if suite else None
    require(D.guard(56, terminal['fixture_execution'] == execution and terminal['fixture_cases_reported'] == cases and (cases is None or type(terminal['fixture_cases_reported']) is int)), 'RECEIPT_SCHEMA')
    if terminal['status'] == 'COMPLETE':
        validate_receipt(raw, verifier)
    else:
        require(D.guard(57, first is not None or cleanup_failure is not None), 'RECEIPT_SCHEMA')
    return {'status': terminal['status'], 'first_failure': first, 'cleanup_failure': cleanup_failure, 'protocol_failure': (diagnostic or {}).get('protocol_failure'), 'transport_failure': (diagnostic or {}).get('transport_failure'), 'dispatch_attempts': terminal['dispatch_attempts'], 'fixture_execution': execution, 'fixture_cases_reported': cases, 'cases_executed': 0 if execution == 'NOT_STARTED' else cases, 'suite_counts': [dict(((key, group[key]) for key in ('run', 'failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes'))) for group in suite['groups']] if suite else None, 'suite_diagnostics': suite_diagnostics(suite, verifier) if suite else None, 'suite_case_codebook': {'case_index': 'FROZEN_SYNTHETIC_POLICY_ORDER', 'outcomes': list(verifier.OUTCOMES), 'exceptions': list(verifier.EXCEPTIONS), 'reasons': list(verifier.REASONS), 'payload_SHA256': verifier.PAYLOAD_SHA} if suite else None, 'cleanup_ok': terminal['cleanup_ok']}

def container_unit_state(unit, timeout=3):
    result = selected(['/usr/bin/systemctl', 'show', unit, '-p', 'LoadState', '-p', 'Description', '-p', 'Transient', '-p', 'ActiveState', '-p', 'MainPID'], timeout)
    require(D.guard(58, result.returncode == 0), 'METADATA_HOLD')
    values = {}
    for line in result.stdout.decode('ascii').splitlines():
        (key, separator, value) = line.partition('=')
        require(D.guard(59, separator and key not in values), 'METADATA_HOLD')
        values[key] = value
    require(D.guard(60, set(values) == {'LoadState', 'Description', 'Transient', 'ActiveState', 'MainPID'} and observed_state('Transient', values['Transient']) in ('yes', 'no') and re.fullmatch('[0-9]{1,10}', observed_state('MainPID', values['MainPID']))), 'METADATA_HOLD')
    return values

def cleanup_container(unit, machine):
    """Stop only the exact owned service; success requires fresh absence proof."""
    D.at('launch.cleanup')
    summary = {'verified_absent': False, 'stage': 'METADATA', 'stop_returncode': None, 'reset_returncode': None, 'last_observation': None}

    def owned(state):
        if observed_state('LoadState', state['LoadState']) == 'not-found':
            require(D.guard(61, observed_state('ActiveState', state['ActiveState']) == 'inactive' and observed_state('MainPID', state['MainPID']) == '0'), 'CLEANUP_HOLD')
            return False
        summary['stage'] = 'OWNERSHIP'
        D.at('launch.cleanup.ownership')
        require(D.guard(62, observed_state('LoadState', state['LoadState']) == 'loaded' and state['Description'] == machine and (observed_state('Transient', state['Transient']) == 'yes')), 'OWNERSHIP_HOLD')
        return True

    def action(verb, timeout):
        try:
            result = selected(['/usr/bin/systemctl', verb, unit], timeout)
            require(D.guard(63, type(result.returncode) is int and -255 <= result.returncode <= 255), 'CLEANUP_HOLD')
            return result.returncode
        except BaseException as exc:
            D.error(exc)
            return None

    def state(timeout=3):
        summary['stage'] = 'METADATA'
        D.at('launch.cleanup.metadata')
        return container_unit_state(unit, timeout)
    try:
        current = state()
        if owned(current):
            summary['stage'] = 'STOP'
            D.at('launch.cleanup.stop')
            summary['stop_returncode'] = action('stop', 12)
            current = state()
            if owned(current) and observed_state('ActiveState', current['ActiveState']) == 'failed' and (observed_state('MainPID', current['MainPID']) == '0'):
                summary['stage'] = 'RESET'
                D.at('launch.cleanup.reset')
                summary['reset_returncode'] = action('reset-failed', 3)
                current = state()
        deadline = time.monotonic() + 2
        while True:
            present = owned(current)
            summary['stage'] = 'VERIFY'
            D.at('launch.cleanup.verify')
            cgroup_absent = not os.path.lexists('/sys/fs/cgroup/system.slice/' + unit)
            D.metric('cgroup_absent', int(cgroup_absent))
            machine_absent = not os.path.lexists('/run/systemd/machines/' + machine)
            D.metric('machine_absent', int(machine_absent))
            summary['last_observation'] = {'unit_absent': not present, 'own_cgroup_absent': cgroup_absent, 'machine_registration_absent': machine_absent}
            resources_absent = cgroup_absent and machine_absent
            if not present and resources_absent:
                summary.update(verified_absent=True, stage='ABSENT')
                break
            if time.monotonic() >= deadline:
                break
            time.sleep(min(0.1, max(0, deadline - time.monotonic())))
            current = state(max(0.01, min(0.5, deadline - time.monotonic())))
    except BaseException as exc:
        D.error(exc)
        pass
    return summary

def main():
    D.at('launch.identity')
    closed_diagnostics = None
    recovered_diagnostics = None
    readiness_receipt = None
    outer_start = None
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
        require(D.guard(64, observed('uid', os.geteuid()) == 0 and sys.platform == 'linux' and (platform.machine() == 'x86_64')), 'HOST_HOLD')
        controller = Path(__file__).resolve().with_name('controller.py').read_bytes()
        require(D.guard(65, hashlib.sha256(controller).hexdigest() == CONTROLLER_SHA), 'CONTROLLER_HASH')
        require(D.guard(66, not controller.endswith(b'    raise SystemExit(78)\n')), 'CONTROLLER_NOT_ACTIVATED')
        verifier = types.ModuleType('frozen_synthetic_controller_validator')
        exec(compile(controller, 'frozen_synthetic_controller_validator', 'exec'), verifier.__dict__)
        machine = 'synthetic124-' + run
        unit = machine + '.service'
        root = Path('/var/lib/machines') / machine
        require(D.guard(67, not root.exists() and (not root.is_symlink())), 'ROOT_EXISTS')
        state = selected(['/usr/bin/systemctl', 'show', unit, '-p', 'LoadState', '--value'])
        require(D.guard(68, state.returncode == 0 and state.stdout.strip() == b'not-found'), 'UNIT_EXISTS')
        D.at('launch.bootstrap.update')
        command(['/usr/bin/apt-get', '-o', 'Acquire::Retries=0', '-o', 'Acquire::https::Timeout=20', 'update'], 30)
        D.at('launch.bootstrap.install')
        command(['/usr/bin/apt-get', '-y', '--no-install-recommends', '-o', 'Acquire::Retries=0', 'install', 'debootstrap', 'debian-archive-keyring', 'systemd-container'], 60)
        D.at('launch.bootstrap.debian')
        command(['/usr/sbin/debootstrap', '--arch=amd64', '--variant=minbase', '--force-check-gpg', '--include=python3,systemd-sysv,dbus', '--keyring=/usr/share/keyrings/debian-archive-keyring.gpg', 'bookworm', str(root), SNAPSHOT], 240)
        target = root / 'opt/qualification'
        target.mkdir(mode=448, parents=True)
        (target / 'controller.py').write_bytes(controller)
        launched = True
        D.at('launch.container')
        outer_start = time.monotonic()
        D.at('launch.container')
        command(['/usr/bin/systemd-run', '--unit=' + unit, '--property=Description=' + machine, '--property=Delegate=yes', '--property=KillMode=mixed', '--property=TasksMax=256', '--property=MemoryMax=12G', '--property=RuntimeMaxSec=120s', '--property=TimeoutStopSec=10s', '/usr/bin/systemd-nspawn', '--keep-unit', '--boot', '--quiet', '--settings=no', '--private-network', '--register=yes', '--resolv-conf=off', '--link-journal=no', '--console=pipe', '--directory=' + str(root), '--machine=' + machine], 10)
        deadline = min(time.monotonic() + 60, outer_start + 50)
        while time.monotonic() < deadline:
            state = selected(['/usr/bin/systemctl', '--machine=' + machine, 'is-system-running'])
            if state.returncode == 0 and state.stdout.strip() == b'running':
                break
            time.sleep(1)
        else:
            raise RuntimeError('CONTAINER_READINESS_HOLD')
        D.at('launch.readiness')

        def own_ready():
            current = container_unit_state(unit, timeout=1)
            require(D.guard(69, observed_state('LoadState', current['LoadState']) == 'loaded' and observed_state('Transient', current['Transient']) == 'yes' and (current['Description'] == machine) and (observed_state('ActiveState', current['ActiveState']) == 'active') and (observed_state('MainPID', current['MainPID']) != '0')), 'OWNERSHIP_HOLD')
        readiness_receipt = settle(outer_start, own_ready)
        validate_readiness(readiness_receipt)
        for reading in readiness_receipt['samples']:
            for (name, (status, value)) in reading['observations'].items():
                D.metric(name, value, status)
        D.metric('readiness_elapsed', readiness_receipt['elapsed_seconds'])
        D.metric('readiness_samples', len(readiness_receipt['samples']))
        D.metric('outer_elapsed', time.monotonic() - outer_start)
        require(D.guard(70, readiness_receipt['status'] == 'READY'), 'READINESS_SETTLING_HOLD')
        D.at('launch.controller')
        with subprocess.Popen(['/usr/bin/systemd-run', '--machine=' + machine, '--unit=synthetic124-controller.service', '--wait', '--pipe', '--quiet', '/usr/bin/python3', '-I', '-S', '-B', '-u', '/opt/qualification/controller.py'], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}) as proc:
            data = bytearray()
            import selectors
            selector = selectors.DefaultSelector()
            os.set_blocking(proc.stdout.fileno(), False)
            selector.register(proc.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + 35
            try:
                while selector.get_map() and time.monotonic() < deadline:
                    for (key, _) in selector.select(0.05):
                        chunk = os.read(key.fd, 4096)
                        if not chunk:
                            selector.unregister(key.fileobj)
                        else:
                            data.extend(chunk)
                            require(D.guard(71, len(data) <= 20480), 'RECEIPT_CAP')
                require(D.guard(72, not selector.get_map()), 'CONTROLLER_TIMEOUT')
                proc.wait(timeout=max(0.01, deadline - time.monotonic()))
                if type(proc.returncode) is int and -255 <= proc.returncode <= 255:
                    controller_returncode = proc.returncode
                (normalized, closed_diagnostics) = split_diagnostics(bytes(data), verifier)
                diagnostic = controller_diagnostic(normalized, verifier)
                require(D.guard(73, closed_diagnostics['controller'] is not None and (closed_diagnostics['payload'] is not None if diagnostic['dispatch_attempts'] else True) and (not any((ledger and ledger['incomplete'] for ledger in closed_diagnostics.values())))), 'DIAGNOSTIC_INCOMPLETE_HOLD')
                require(D.guard(74, proc.returncode == 0), 'CONTROLLER_HOLD')
                validated = validate_receipt(normalized, verifier)
            finally:
                selector.close()
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=3)
    except BaseException as exc:
        D.error(exc)
        known = {'REPOSITORY_HOLD', 'REPOSITORY_ID_HOLD', 'EVENT_HOLD', 'UNBOUND_COMMIT', 'UNBOUND_RUN', 'COMMIT_HOLD', 'RUN_HOLD', 'REF_HOLD', 'HOST_HOLD', 'CONTROLLER_HASH', 'CONTROLLER_NOT_ACTIVATED', 'ROOT_EXISTS', 'UNIT_EXISTS', 'COMMAND_HOLD', 'METADATA_CAP', 'CONTAINER_READINESS_HOLD', 'RECEIPT_CAP', 'RECEIPT_SCHEMA', 'CONTROLLER_TIMEOUT', 'CONTROLLER_HOLD', 'READINESS_SETTLING_HOLD', 'OWNERSHIP_HOLD', 'DIAGNOSTIC_INCOMPLETE_HOLD'}
        failure = str(exc) if type(exc) is RuntimeError and str(exc) in known else 'FIXED_RUNTIME_HOLD'
        if 'data' in locals() and 'verifier' in locals():
            recovered_diagnostics = recover_diagnostics(bytes(data), verifier)
    finally:
        if launched:
            outer_cleanup = cleanup_container(unit, machine)
            clean = outer_cleanup['verified_absent']
        own_diagnostics = D.snapshot()
        if own_diagnostics['incomplete']:
            failure = failure or 'DIAGNOSTIC_INCOMPLETE_HOLD'
            validated = None
        print(json.dumps({'kind': 'hosted_route_terminal', 'failure': failure, 'method_qualification': validated, 'controller_returncode': controller_returncode, 'controller_diagnostic': diagnostic, 'outer_cleanup': outer_cleanup, 'complete': validated is not None and failure is None and clean, 'commit': os.environ.get('GITHUB_SHA') if validated else None, 'run_id': run if validated else None, 'controller_SHA256': CONTROLLER_SHA if validated else None, 'fixture_payload_SHA256': verifier.PAYLOAD_SHA if validated else None, 'snapshot': SNAPSHOT if validated else None, 'host_kernel': platform.release() if validated else None, 'container_started_or_uncertain': launched, 'owned_container_cleanup_ok': clean, 'rootfs_disposal_expected': 'GITHUB_DISPOSABLE_RUNNER_TEARDOWN_NOT_LOCALLY_VERIFIED', 'preservation_inspection_performed': False, 'gate_diagnostics': {'launcher': own_diagnostics, 'received': closed_diagnostics, 'recovered': recovered_diagnostics}, 'readiness': readiness_receipt}))
    return 0 if validated is not None and failure is None and clean else 4

def split_diagnostics(raw, verifier):
    require(D.guard(75, len(raw) <= 20480), 'RECEIPT_CAP')
    rows = raw.splitlines()
    require(D.guard(76, 2 <= len(rows) <= 6 and all((len(row) <= 16384 for row in rows))), 'RECEIPT_SCHEMA')
    normalized = []
    controller_ledger = payload_ledger = None
    for (index, line) in enumerate(rows):
        body = json.loads(line, object_pairs_hook=closed_pairs, parse_constant=lambda _: require(D.guard(77, False), 'RECEIPT_SCHEMA'))
        require(D.guard(78, type(body) is dict), 'RECEIPT_SCHEMA')
        if body.get('kind') == 'gate_diagnostics':
            require(D.guard(79, controller_ledger is None and index == len(rows) - 2 and (set(body) == {'kind', 'facts'})), 'RECEIPT_SCHEMA')
            try:
                controller_ledger = verifier.validate_diagnostics(body['facts'], 'controller')
            except BaseException as diagnostic_exception:
                D.error(diagnostic_exception)
                controller_ledger = None
            continue
        if body.get('kind') == 'diagnostic_result':
            require(D.guard(80, type(body.get('facts')) is dict), 'RECEIPT_SCHEMA')
            payload_ledger = body['facts'].pop('gate_diagnostics', None)
            if payload_ledger is not None:
                try:
                    verifier.validate_diagnostics(payload_ledger, 'payload')
                except BaseException as diagnostic_exception:
                    D.error(diagnostic_exception)
                    payload_ledger = None
        normalized.append(json.dumps(body, allow_nan=False).encode())
    return (b'\n'.join(normalized), {'controller': controller_ledger, 'payload': payload_ledger})

def closed_pairs(items):
    body = {}
    for (key, value) in items:
        require(D.guard(81, key not in body), 'RECEIPT_SCHEMA')
        body[key] = value
    return body

def recover_diagnostics(raw, verifier):
    projected = {'controller': None, 'payload': None, 'first_reported_failure': None, 'cleanup_reported_failure': None, 'rejected_rows': 0, 'scope': 'CLOSED_REPORTED_FACTS_ONLY_NO_ADMISSION'}
    if len(raw) > 20480:
        projected['rejected_rows'] = 1
        return projected
    for line in raw.splitlines()[:6]:
        try:
            require(D.guard(82, len(line) <= 16384), 'RECEIPT_CAP')
            body = json.loads(line, object_pairs_hook=closed_pairs, parse_constant=lambda _: require(D.guard(83, False), 'RECEIPT_SCHEMA'))
            require(D.guard(84, type(body) is dict), 'RECEIPT_SCHEMA')
            kind = body.get('kind')
            if kind == 'gate_diagnostics':
                require(D.guard(85, set(body) == {'kind', 'facts'}), 'RECEIPT_SCHEMA')
                ledger = verifier.validate_diagnostics(body['facts'], 'controller')
                require(D.guard(86, projected['controller'] is None), 'RECEIPT_SCHEMA')
                projected['controller'] = ledger
            elif kind == 'diagnostic_result':
                facts = body.get('facts')
                require(D.guard(87, type(facts) is dict), 'RECEIPT_SCHEMA')
                if facts.get('gate_diagnostics') is not None:
                    require(D.guard(88, projected['payload'] is None), 'RECEIPT_SCHEMA')
                    projected['payload'] = verifier.validate_diagnostics(facts['gate_diagnostics'], 'payload')
                first = facts.get('first_failure')
                if first is not None:
                    require(D.guard(89, verifier.valid_failure(first)), 'RECEIPT_SCHEMA')
                    projected['first_reported_failure'] = projected['first_reported_failure'] or first
            elif kind in ('controller_hold', 'cleanup_hold'):
                require(D.guard(90, verifier.valid_failure(body.get('failure'))), 'RECEIPT_SCHEMA')
                key = 'cleanup_reported_failure' if kind == 'cleanup_hold' else 'first_reported_failure'
                projected[key] = projected[key] or body['failure']
            elif kind == 'terminal':
                for (field, key) in (('first_failure', 'first_reported_failure'), ('cleanup_failure', 'cleanup_reported_failure')):
                    value = body.get(field)
                    if value is not None:
                        require(D.guard(91, verifier.valid_failure(value)), 'RECEIPT_SCHEMA')
                        projected[key] = projected[key] or value
        except BaseException as diagnostic_exception:
            D.error(diagnostic_exception)
            projected['rejected_rows'] += 1
    return projected
if __name__ == '__main__':
    if not EXECUTION_AUTHORIZED:
        print('{"status":"SOURCE_ONLY_NO_HOSTED_EXECUTION_AUTHORITY"}')
        raise SystemExit(78)
    sys.exit(main())
