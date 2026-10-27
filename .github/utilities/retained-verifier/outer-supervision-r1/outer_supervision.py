"""One owned QEMU-command supervision contract; all native effects disarmed.

The guest's poweroff acknowledgement is not an outer-exit proof. No cloud API
or credentials are used. Tests use only explicitly synthetic process ports.
"""
from dataclasses import dataclass
import math
import os
import selectors
import signal
import subprocess
import time


_PUBLISHED_CI_SCOPE = None
STREAM_CAP = 1048576


class Refusal(ValueError):
    pass


class SpawnedRefusal(Refusal):
    def __init__(self, process):
        super().__init__('spawned_setup_refused')
        self.process = process


def require(ok, reason):
    if not ok:
        raise Refusal(reason)


def append_bounded(record, channel, raw):
    require(channel in ('stdout', 'stderr') and type(raw) is bytes, 'stream_shape')
    room = STREAM_CAP - len(record[channel])
    record[channel] += raw[:room]
    if len(raw) > room:
        record['truncated'] = True


def supervise(ops, argv, *, cwd, environment, deadline, grace=10.0):
    """Exactly one spawn; no child receipt can assert process/group closure."""
    require(isinstance(argv, tuple) and argv and all(type(v) is str and v and
            '\x00' not in v for v in argv), 'argv')
    remaining = deadline - ops.now() if type(deadline) in (int, float) else -1
    require(type(deadline) in (int, float) and math.isfinite(deadline) and
            0 < remaining <= 1800 and type(grace) in (int, float) and
            math.isfinite(grace) and 0 < grace <= 30, 'deadline')
    result = {'spawned': False, 'stdout': b'', 'stderr': b'', 'truncated': False,
              'timedOut': False, 'returncode': None, 'outerExited': False,
              'ownedGroupGone': False, 'status': 'refused',
              'shutdownRequestedByGuest': None, 'synthetic': ops.synthetic}
    process = None
    reason = None
    try:
        process = ops.spawn(argv, cwd, environment)
        result['spawned'] = True
        while True:
            for channel, raw in ops.drain(process, min(0.1, max(0, deadline - ops.now()))):
                append_bounded(result, channel, raw)
            if result['truncated']:
                reason = 'output_limit'
                break
            code = ops.poll(process)
            late = ops.now() >= deadline
            if late:
                result['timedOut'] = True
                reason = 'guest_deadline'
            if type(code) is int:
                result['returncode'] = code
                if code != 0 and reason is None:
                    reason = 'command_exit_nonzero'
                break
            require(code is None, 'poll_shape')
            if late:
                break
    except BaseException as error:
        # Error text/env/argv data are not published as diagnosis. Exact bounded
        # output retained above is independent of later JSON/exit judgements.
        reason = 'outer_' + type(error).__name__
        if process is None and isinstance(error, SpawnedRefusal):
            process = error.process
            result['spawned'] = True
    finally:
        if process is not None:
            cleanup_errors = []
            try:
                # Covers a failed/finished mkosi parent with a remaining owned
                # child, too. This group was created by this exact spawn only.
                if ops.group_alive(process):
                    if result['returncode'] is not None and reason is None:
                        reason = 'owned_group_straggler'
                    ops.signal_group(process, 'TERM')
                stop_deadline = ops.now() + grace
                while ops.group_alive(process) and ops.now() < stop_deadline:
                    for channel, raw in ops.drain(process, 0.1):
                        append_bounded(result, channel, raw)
                if ops.group_alive(process):
                    ops.signal_group(process, 'KILL')
                code = ops.wait(process, grace)
                require(type(code) is int, 'wait_shape')
                result['returncode'] = code
                result['outerExited'] = True
                gone_deadline = ops.now() + grace
                while ops.group_alive(process) and ops.now() < gone_deadline:
                    for channel, raw in ops.drain(process, 0.1):
                        append_bounded(result, channel, raw)
                result['ownedGroupGone'] = not ops.group_alive(process)
            except BaseException as error:
                cleanup_errors.append(type(error).__name__)
            finally:
                try:
                    for channel, raw in ops.drain(process, 0):
                        append_bounded(result, channel, raw)
                except BaseException as error:
                    cleanup_errors.append(type(error).__name__)
                try:
                    ops.close(process)
                except BaseException as error:
                    cleanup_errors.append(type(error).__name__)
            if cleanup_errors:
                reason = 'outer_cleanup_' + '_'.join(cleanup_errors[:3])
    result['reason'] = reason
    if (reason is None and not result['timedOut'] and not result['truncated'] and
            result['returncode'] == 0 and result['outerExited'] and result['ownedGroupGone']):
        result['status'] = 'outer_exit_passed'
    return result


@dataclass(frozen=True)
class Owned:
    child: object
    selector: object
    pgid: int


@dataclass(frozen=True)
class ReviewedScope:
    argv: tuple
    cwd: str
    environment: tuple


class NativeOps:
    """Concrete Linux source only; workflow capability has not been issued."""
    synthetic = False

    def __init__(self, capability):
        require(type(_PUBLISHED_CI_SCOPE) is ReviewedScope and capability is _PUBLISHED_CI_SCOPE,
                'unissued_ci_scope')
        self.scope = capability
        self.owned = {}

    def now(self):
        return time.monotonic()

    def spawn(self, argv, cwd, environment):
        # Future reviewed owner supplies only its literal mkosi command and
        # curated public source/config dir. No shell or inherited token/env.
        require(type(environment) is dict and set(environment) == {'PATH','LANG','LC_ALL','HOME'}
                and environment['PATH'] == '/usr/bin:/bin' and
                environment['LANG'] == environment['LC_ALL'] == 'C', 'environment')
        require(argv == self.scope.argv and cwd == self.scope.cwd and
                tuple(sorted(environment.items())) == self.scope.environment,
                'scope_binding')
        selector = selectors.DefaultSelector()
        try:
            child = subprocess.Popen(argv, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     close_fds=True, start_new_session=True)
        except BaseException:
            selector.close()
            raise
        owned = Owned(child, selector, child.pid)
        self.owned[id(owned)] = owned
        try:
            for name in ('stdout','stderr'):
                stream = getattr(child, name)
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
        except BaseException:
            # Preserve exact owned handle even when post-spawn setup fails.
            raise SpawnedRefusal(owned) from None
        return owned

    def _owned(self, process):
        require(self.owned.get(id(process)) is process and
                process.pgid == process.child.pid, 'not_owned')

    def drain(self, process, duration):
        self._owned(process)
        result = []
        for key, _ in process.selector.select(max(0, duration)):
            try:
                raw = os.read(key.fileobj.fileno(), 65536)
            except BlockingIOError:
                continue
            if raw:
                result.append((key.data, raw))
            else:
                process.selector.unregister(key.fileobj)
        return result

    def poll(self, process):
        self._owned(process)
        return process.child.poll()

    def group_alive(self, process):
        self._owned(process)
        try:
            os.killpg(process.pgid, 0)
            return True
        except ProcessLookupError:
            return False

    def signal_group(self, process, which):
        self._owned(process)
        require(which in ('TERM','KILL'), 'signal')
        try:
            os.killpg(process.pgid, signal.SIGTERM if which == 'TERM' else signal.SIGKILL)
        except ProcessLookupError:
            pass

    def wait(self, process, timeout):
        self._owned(process)
        return process.child.wait(timeout=timeout)

    def close(self, process):
        self._owned(process)
        failures = []
        for close in (process.selector.close, process.child.stdout.close,
                      process.child.stderr.close):
            try:
                close()
            except BaseException as error:
                failures.append(type(error).__name__)
        if failures:
            raise Refusal('stream_close_failed')
        del self.owned[id(process)]


if __name__ == '__main__':
    raise SystemExit('disarmed_unissued_publication_context')
