"""Versioned one-spawn outer supervision; native authority remains unissued."""
from dataclasses import dataclass, field
import math
import os
import selectors
import signal
import subprocess
import time

_PUBLISHED_CI_SCOPE = None
_CONSUMED_SCOPES = set()
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


def append_bounded(record, channel, raw, limit=STREAM_CAP):
    require(channel in ('stdout','stderr') and type(raw) is bytes, 'stream_shape')
    require(type(limit)is int and STREAM_CAP<=limit<=6*1024*1024,'stream_cap')
    room = limit - len(record[channel])
    record[channel] += raw[:room]
    if len(raw) > room:
        record['truncated'] = True


def supervise(ops, argv, *, cwd, environment, deadline, grace=10.0):
    require(isinstance(argv, tuple) and argv and all(type(v) is str and v and
            '\x00' not in v for v in argv), 'argv')
    remaining = deadline - ops.now() if type(deadline) in (int,float) else -1
    require(type(deadline) in (int,float) and math.isfinite(deadline) and
            0 < remaining <= 2000 and type(grace) in (int,float) and
            math.isfinite(grace) and 0 < grace <= 30, 'deadline')
    result = {'spawned':False,'stdout':b'','stderr':b'','truncated':False,
              'timedOut':False,'returncode':None,'outerExited':False,
              'ownedGroupGone':False,'streamsEOF':False,'streamsClosed':False,
              'ownershipRetained':False,'status':'refused','synthetic':ops.synthetic,
              'shutdownRequestedByGuest':None}
    process = None
    limits={'stdout':6*1024*1024 if argv[0]=='/usr/bin/qemu-system-x86_64' else STREAM_CAP,
            'stderr':STREAM_CAP}
    reason = None
    errors = []

    def fail(error):
        if len(errors) < 16:
            errors.append(type(error).__name__)

    def drain(duration):
        try:
            for channel, raw in ops.drain(process, duration):
                append_bounded(result, channel, raw, limits[channel])
        except BaseException as error:
            fail(error)
            # A failed read must not stall the bounded shutdown clock or skip
            # independent TERM/KILL/wait. Native pause is monotonic sleep.
            try:
                ops.pause(max(0.01, duration))
            except BaseException as pause_error:
                fail(pause_error)
                return False
        return True

    def group():
        try:
            value = ops.group_alive(process)
            require(type(value) is bool, 'group_shape')
            return value
        except BaseException as error:
            fail(error)
            return None

    def signal_owned(which):
        try:
            ops.signal_group(process, which)
        except BaseException as error:
            fail(error)

    def eof():
        try:
            value = ops.eof(process)
            require(type(value) is bool, 'eof_shape')
            return value
        except BaseException as error:
            fail(error)
            return False

    try:
        process = ops.spawn(argv, cwd, environment)
        result['spawned'] = True
        while True:
            if not drain(min(0.1,max(0,deadline-ops.now()))):
                reason = 'capture_clock_refused';break
            if errors:
                reason = 'capture_refused';break
            if result['truncated']:
                reason = 'output_limit';break
            code = ops.poll(process)
            late = ops.now() >= deadline
            if late:
                result['timedOut'] = True;reason = 'guest_deadline'
            if type(code) is int:
                result['returncode'] = code
                if code != 0 and reason is None:reason = 'command_exit_nonzero'
                break
            require(code is None, 'poll_shape')
            if late:break
    except BaseException as error:
        reason = 'outer_' + type(error).__name__
        if process is None and isinstance(error, SpawnedRefusal):
            process = error.process;result['spawned'] = True
    finally:
        if process is not None:
            alive = group()
            if alive is not False:
                if result['returncode'] is not None and reason is None:
                    reason = 'owned_group_straggler'
                signal_owned('TERM')
            term_end = ops.now() + grace
            while group() is not False and ops.now() < term_end:
                if not drain(0.1):break
            if group() is not False:
                signal_owned('KILL')
            # Always attempt wait even if capture/observation/TERM failed.
            try:
                code = ops.wait(process, grace)
                require(type(code) is int, 'wait_shape')
                result['returncode'] = code;result['outerExited'] = True
            except BaseException as error:
                fail(error)
            gone_end = ops.now() + grace
            while group() is not False and ops.now() < gone_end:
                if not drain(0.1):break
            result['ownedGroupGone'] = group() is False
            # Read until BOTH actual pipes report EOF. Parent exit does not
            # imply no queued output. This interval shares final closeout.
            eof_end = gone_end
            while not eof() and ops.now() < eof_end:
                if not drain(0.1):break
            result['streamsEOF'] = eof()
            settled = result['outerExited'] and result['ownedGroupGone']
            result['ownershipRetained'] = True
            try:
                closed = ops.close(process, settled=settled)
                require(closed is True, 'close_shape')
                result['streamsClosed'] = True
                result['ownershipRetained'] = not settled
            except BaseException as error:
                fail(error)
    if result['truncated'] and reason is None:
        reason = 'output_limit'
    result['cleanupErrors'] = errors
    result['reason'] = reason or ('outer_cleanup_refused' if errors else
                                  'streams_incomplete' if not result['streamsEOF'] else None)
    if (result['reason'] is None and not result['timedOut'] and not result['truncated']
            and result['returncode']==0 and result['outerExited'] and result['ownedGroupGone']
            and result['streamsEOF'] and result['streamsClosed'] and not result['ownershipRetained']):
        result['status'] = 'outer_exit_passed'
    return result


@dataclass(frozen=True)
class Owned:
    child:object
    selector:object
    pgid:int
    eof:set = field(default_factory=set)


@dataclass(frozen=True)
class ReviewedScope:
    argv:tuple
    cwd:str
    environment:tuple


class NativeOps:
    synthetic=False
    def __init__(self,capability):
        require(type(_PUBLISHED_CI_SCOPE) is ReviewedScope and
                capability is _PUBLISHED_CI_SCOPE,'unissued_ci_scope')
        self.scope=capability;self.owned={};self.closed=set();self.spawn_intent=False
    def now(self):return time.monotonic()
    def pause(self,duration):time.sleep(duration)
    def spawn(self,argv,cwd,environment):
        require(not self.spawn_intent and id(self.scope) not in _CONSUMED_SCOPES,
                'spawn_already_attempted')
        require(type(environment) is dict and set(environment)=={'PATH','LANG','LC_ALL','HOME'}
                and environment['PATH']=='/usr/bin:/bin' and
                environment['LANG']==environment['LC_ALL']=='C','environment')
        require(argv==self.scope.argv and cwd==self.scope.cwd and
                tuple(sorted(environment.items()))==self.scope.environment,'scope_binding')
        self.spawn_intent=True
        _CONSUMED_SCOPES.add(id(self.scope))
        selector=selectors.DefaultSelector()
        try:
            child=subprocess.Popen(argv,cwd=cwd,env=environment,stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True,start_new_session=True)
        except BaseException:
            selector.close();raise
        owned=Owned(child,selector,child.pid);self.owned[id(owned)]=owned
        try:
            for name in ('stdout','stderr'):
                stream=getattr(child,name);os.set_blocking(stream.fileno(),False)
                selector.register(stream,selectors.EVENT_READ,name)
        except BaseException:
            raise SpawnedRefusal(owned) from None
        return owned
    def _owned(self,p):
        require(self.owned.get(id(p)) is p and p.pgid==p.child.pid,'not_owned')
    def drain(self,p,duration):
        self._owned(p)
        if id(p) in self.closed:return []
        result=[]
        for key,_ in p.selector.select(max(0,duration)):
            try:raw=os.read(key.fileobj.fileno(),65536)
            except BlockingIOError:continue
            if raw:result.append((key.data,raw))
            else:p.eof.add(key.data);p.selector.unregister(key.fileobj)
        return result
    def eof(self,p):self._owned(p);return p.eof=={'stdout','stderr'}
    def poll(self,p):self._owned(p);return p.child.poll()
    def group_alive(self,p):
        self._owned(p)
        try:os.killpg(p.pgid,0);return True
        except ProcessLookupError:return False
    def signal_group(self,p,which):
        self._owned(p);require(which in ('TERM','KILL'),'signal')
        try:os.killpg(p.pgid,signal.SIGTERM if which=='TERM' else signal.SIGKILL)
        except ProcessLookupError:pass
    def wait(self,p,timeout):self._owned(p);return p.child.wait(timeout=timeout)
    def close(self,p,*,settled):
        self._owned(p);require(type(settled) is bool,'settled_shape');errors=[]
        for close in (p.selector.close,p.child.stdout.close,p.child.stderr.close):
            try:close()
            except BaseException as error:errors.append(type(error).__name__)
        if errors:raise Refusal('stream_close_failed')
        self.closed.add(id(p))
        if settled:del self.owned[id(p)];self.closed.discard(id(p))
        return True


if __name__=='__main__':raise SystemExit('disarmed_unissued_publication_context')
