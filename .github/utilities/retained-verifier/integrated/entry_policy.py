"""Source-faithful policy model, not a compiled/qualified Linux entry."""
import re

ENTRY = '/code/static-entry'
PYTHON_ARGV = ('/usr/bin/python3.11', '-I', '-S', '-B', '/code/worker.py')
PYTHON_ENV = ('PATH=/usr/bin', 'LANG=C', 'LC_ALL=C', 'HOME=/')
REQUIRED = {'PATH': '/usr/bin', 'LANG': 'C', 'LC_ALL': 'C', 'HOME': '/',
            'SHELL': '/nonexistent', 'USER': None, 'LOGNAME': None}
OPTIONAL = {'INVOCATION_ID', 'SYSTEMD_EXEC_PID'}


class Refusal(RuntimeError):
    def __init__(self, code='entry_refused'):
        super().__init__(code)


def require(value):
    if not value: raise Refusal()


def inspect(argv, assignments, pid):
    """Inspect explicit synthetic kernel startup facts; make no host call.

    The 512-byte assignment and 8192-byte total include terminating NULs, as in
    the C source. Return only the fixed replacement argv/environment.
    """
    require(type(argv) in (list, tuple) and len(argv) == 2 and argv[0] == ENTRY)
    name = argv[1]
    require(type(name) is str and re.fullmatch('ocv-[0-9a-f]{24}', name))
    require(type(pid) is int and 0 < pid <= 2147483647)
    require(type(assignments) in (list, tuple) and len(assignments) <= 16)
    seen, total = set(), 0
    for raw in assignments:
        require(type(raw) is bytes and b'\0' not in raw and 0 < len(raw) <= 511)
        total += len(raw) + 1
        require(total <= 8192 and b'=' in raw)
        key_raw, value_raw = raw.split(b'=', 1)
        try: key, value = key_raw.decode('ascii'), value_raw.decode('ascii')
        except UnicodeError: raise Refusal() from None
        require(key in set(REQUIRED) | OPTIONAL and key not in seen)
        seen.add(key)
        if key in REQUIRED:
            require(value == (name if key in ('USER', 'LOGNAME') else REQUIRED[key]))
        elif key == 'INVOCATION_ID':
            require(re.fullmatch('[0-9a-f]{32}', value))
        else:
            require(re.fullmatch('[1-9][0-9]{0,9}', value) and int(value) <= 2147483647 and int(value) == pid)
    require(set(REQUIRED) <= seen)
    return {'argv': PYTHON_ARGV, 'environment': PYTHON_ENV, 'pidPreservedByExecve': True,
            'linuxHandoffVerified': False}


def model_exec_result(returned):
    """execve success does not return; model failure without a fallback."""
    if returned:
        raise Refusal('entry_exec_failed')
    return {'replacementOnly': True, 'nativeProof': False}


if __name__ == '__main__':
    raise SystemExit('model_only_no_linux_execution')
