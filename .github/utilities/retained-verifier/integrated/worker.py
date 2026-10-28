"""Disarmed public bootstrap for the reviewed nonroot retained-report reader.

No operation occurs on import. The source's CLI remains inert. Dependency
injection is an internal synthetic-test API, never a CLI/JSON arming interface.
No /proc, mount, namespace, network, subprocess or privilege setup is here.
"""
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import sys
import time
import types

ARMED = True
PROTOCOL_SHA256 = 'df3ad90e894610f05c25c4521c9bc702421b3c6bb5d70af2e5b888a8271651b9'
PROFILE_SHA256 = '6d722273e097424e6e59a1abd10703193f2e8e08c885b35b12b450c3410d4adb'
CONTEXT_PATH = '/control/context.json'
GATE_PATH = '/control/admission.json'
CODE_ROOT = '/code'
CONSUMER = {'hosted_export.py': {'bytes': 20523, 'sha256': '4469f534a4c61678e951a1542e6e5caa69ac8fd7431729b6cfedeaef0f084e3c'}, 'hosted_privacy.py': {'bytes': 69776, 'sha256': 'b6f9d4736b0051361aacc7c56f562de135a41c9662babae7e20cbdee436495b9'}, 'public-member-comparisons-v105-workboard.json': {'bytes': 547, 'sha256': 'b172ee3c6cdf34d983cdb4b1452924b5931762020b94596b4405e7a6fdeb03df'}}
SOURCE = '8770609a78d68f6b53607ce3199baf0aa08687cf'
SCANNER = 'd658c890f5684b2dbe8468449a7fed17bb46055d'
INDEX = 'sha256:2577bfdfb50ee4411f69b90bf8b4347b8e476c2bc82bb982005515c46ebe59cc'
REPORT_SHA256 = '0c2019ff9bd14f93681037d9961ac4c80a14600ef0fe0a99a5065a8aedc5b813'
REPORT_BYTES = 4315
CONTEXT_KEYS = frozenset(('schema','sessionId','unitName','bootId','vmId','identityName','contextNonce',
    'workerDeadlineUtc','maxJobSeconds','operation','mountPropagation','sourceSha','scannerSha','indexDigest','privacySha256',
    'privacyBytes','consumerCode','profileSha256','entrySha256','workerSha256','runtimeManifestSha256','inputManifestSha256'))
GATE_KEYS = frozenset(('schema','sessionId','unitName','bootId','vmId','pid','startTimeTicks','uid','gid',
    'identityName','checkedAt','expiresAt','workerDeadlineUtc','profileSha256','entrySha256','workerSha256',
    'runtimeManifestSha256','inputManifestSha256','sourceSha','scannerSha','indexDigest','privacySha256',
    'privacyBytes','consumerCode','proofSha256','status','mountPropagation','inputReleased','contextSha256','invocationId'))
CONTEXT_SCHEMA = 'openclaw.retained-verifier-context.v1'
GATE_SCHEMA = 'openclaw.retained-verifier-admission.v1'


class BootstrapRefusal(RuntimeError):
    pass


class WorkerTimeout(RuntimeError):
    pass


def _need(value, code):
    if not value: raise BootstrapRefusal(code)


def _sha(raw): return hashlib.sha256(raw).hexdigest()


class NativeFiles:
    """Only fixed root-owned public bootstrap/control files before admission."""
    def read_public(self, name, cap, *, pending=False):
        _need(name in (CONTEXT_PATH, GATE_PATH, '/code/worker.py', '/code/protocol.py')
              or name in {'/code/' + n for n in CONSUMER}, 'worker_fixed_path')
        path = Path(name)
        try:
            _need(path.resolve() == path, 'worker_path_changed')
            before = path.lstat()
            _need(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                  and before.st_nlink == 1 and 0 <= before.st_size <= cap, 'worker_public_identity')
            mode = stat.S_IMODE(before.st_mode)
            if pending and mode == 0o600: return None  # Root publisher has not released it.
            _need(mode == 0o444, 'worker_public_mode')
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except (FileNotFoundError, PermissionError):
            if pending: return None
            raise BootstrapRefusal('worker_public_unavailable') from None
        def identity(info):
            return tuple(getattr(info, k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid',
                'st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
        with os.fdopen(fd, 'rb', buffering=0) as stream:
            opened = os.fstat(stream.fileno())
            _need(identity(opened) == identity(before), 'worker_public_changed')
            raw = stream.read(cap + 1)
            after = os.fstat(stream.fileno())
        _need(len(raw) == before.st_size and len(raw) <= cap and identity(after) == identity(before)
              and identity(path.lstat()) == identity(before), 'worker_public_changed')
        return raw

    def input_released(self):
        path = Path('/input');info = path.lstat()
        _need(path.resolve() == path and stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
              and stat.S_IMODE(info.st_mode) == 0o555, 'worker_input_not_released')


class NativeProcess:
    def snapshot(self):
        return {'pid':os.getpid(),'uid':os.getuid(),'euid':os.geteuid(),
                'gid':os.getgid(),'egid':os.getegid(),'groups':os.getgroups()}


class NativeClock:
    def utc(self): return dt.datetime.now(dt.timezone.utc)
    def monotonic(self): return time.monotonic()
    def sleep(self, seconds): time.sleep(seconds)


class NativeTimer:
    def call(self, seconds, function):
        _need(type(seconds) in (int,float) and math.isfinite(seconds) and 0 < seconds <= 240,
              'worker_consumer_budget')
        _need(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), 'worker_existing_timer')
        previous = signal.getsignal(signal.SIGALRM)
        def expired(number, frame): raise WorkerTimeout('worker_consumer_timeout')
        signal.signal(signal.SIGALRM, expired)
        try:
            signal.setitimer(signal.ITIMER_REAL, seconds)
            return function()
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)


def load_protocol(files):
    raw = files.read_public('/code/protocol.py',65536)
    _need(type(PROTOCOL_SHA256) is str and _sha(raw) == PROTOCOL_SHA256, 'worker_protocol_pin')
    module = types.ModuleType('retained_worker_protocol')
    module.__file__ = '/code/protocol.py'
    exec(compile(raw,module.__file__,'exec'),module.__dict__)
    return module


def _hex(value, width=64):
    return type(value) is str and re.fullmatch('[0-9a-f]{'+str(width)+'}',value) is not None


def validate_context(value, p, now, worker_sha):
    p.require(type(value) is dict and set(value) == CONTEXT_KEYS and value['schema'] == CONTEXT_SCHEMA,
              'worker_context_schema')
    session = value['sessionId']
    p.require(_hex(session,32) and value['identityName'] == 'ocv-'+session[:24]
              and value['unitName'] == 'ocv-'+session+'.service' and _hex(value['contextNonce']),
              'worker_context_identity')
    p.require(type(value['vmId']) is str and re.fullmatch('[1-9][0-9]{0,19}',value['vmId'])
              and type(value['bootId']) is str and re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}',value['bootId']),
              'worker_context_generation')
    fixed={'sourceSha':SOURCE,'scannerSha':SCANNER,'indexDigest':INDEX,'privacySha256':REPORT_SHA256,
           'privacyBytes':REPORT_BYTES,'consumerCode':CONSUMER,'profileSha256':PROFILE_SHA256,
           'workerSha256':worker_sha,'maxJobSeconds':300,'operation':'retained-report-only',
           'mountPropagation':'private'}
    p.require(all(type(value[k]) is type(expected) and value[k] == expected for k,expected in fixed.items()),
              'worker_context_pin')
    p.require(all(_hex(value[k]) for k in ('entrySha256','workerSha256','runtimeManifestSha256','inputManifestSha256')),
              'worker_context_hash_shape')
    deadline = p.utc(value['workerDeadlineUtc'])
    p.require(0 < (deadline-now).total_seconds() <= 300, 'worker_context_deadline')
    return deadline


def validate_gate(value, context, context_sha, own, p, now):
    p.require(type(value) is dict and set(value) == GATE_KEYS and value['schema'] == GATE_SCHEMA,
              'worker_gate_schema')
    joined=('sessionId','unitName','bootId','vmId','identityName','workerDeadlineUtc','profileSha256',
            'entrySha256','workerSha256','runtimeManifestSha256','inputManifestSha256',
            'sourceSha','scannerSha','indexDigest','privacySha256','privacyBytes','consumerCode','mountPropagation')
    p.require(all(type(value[k]) is type(context[k]) and value[k] == context[k] for k in joined)
              and value['contextSha256'] == context_sha, 'worker_gate_binding')
    p.require(value['status'] == 'passed' and value['inputReleased'] is True
              and all(type(value[k]) is int and value[k] == own[k] and value[k] > 0 for k in ('pid','uid','gid'))
              and type(value['startTimeTicks']) is int and value['startTimeTicks'] > 0
              and _hex(value['proofSha256']) and _hex(value['invocationId'],32), 'worker_gate_process')
    checked,expires = p.utc(value['checkedAt']),p.utc(value['expiresAt'])
    p.require(checked <= now < expires <= p.utc(context['workerDeadlineUtc'])
              and 0 < (expires-checked).total_seconds() <= 30, 'worker_gate_time')


def load_consumer(context, files, p):
    """Exact public bytes, fixed sibling import, no private input until call."""
    p.require(not any(n in sys.modules for n in ('hosted_privacy','hosted_export')), 'worker_ambient_consumer')
    sources={}
    for name,row in CONSUMER.items():
        raw=files.read_public('/code/'+name,row['bytes'])
        p.require(len(raw)==row['bytes'] and p.sha(raw)==row['sha256'],'worker_consumer_pin')
        sources[name]=raw
    # Isolated Python excludes script siblings. Add only this fixed verified
    # read-only path; PYTHONPATH/user/current-directory paths are never used.
    if CODE_ROOT not in sys.path: sys.path.insert(0,CODE_ROOT)
    for name in ('hosted_privacy','hosted_export'):
        module=types.ModuleType(name);module.__file__='/code/'+name+'.py';sys.modules[name]=module
        exec(compile(sources[name+'.py'],module.__file__,'exec'),module.__dict__)
    arguments=['--privacy','/input/privacy.json','--sha256',REPORT_SHA256,
               '--source-sha',SOURCE,'--tooling-sha',SCANNER,'--index-digest',INDEX,'--oci','/input/oci']
    return lambda: sys.modules['hosted_export'].check_privacy(arguments)


def run_once(*, files=None, process=None, clock=None, timer=None, emit=None, consumer_loader=None, protocol=None):
    if ARMED is not True: raise BootstrapRefusal('worker_disarmed')
    files,process,clock,timer = files or NativeFiles(),process or NativeProcess(),clock or NativeClock(),timer or NativeTimer()
    emit = emit or (lambda value: print(json.dumps(value,sort_keys=True,separators=(',',':')),file=sys.stderr,flush=True))
    started=clock.monotonic();last=started
    _need(type(started) in (int,float) and math.isfinite(started),'worker_clock')
    p=protocol or load_protocol(files)
    context_sha=None;own=None;ready=False;timed_out=False;consumer_exit=None;reason=None
    def remaining(deadline):
        nonlocal last
        current=clock.monotonic()
        p.require(type(current) in (int,float) and math.isfinite(current) and current>=last,'worker_clock')
        last=current
        value=min(300-(current-started),(deadline-clock.utc()).total_seconds())
        p.require(value>0,'worker_budget_expired')
        return value
    try:
        raw=files.read_public(CONTEXT_PATH,16384);context_sha=p.sha(raw)
        public_worker=files.read_public('/code/worker.py',262144)
        context=p.decode(raw,16384);deadline=validate_context(context,p,clock.utc(),p.sha(public_worker))
        own=process.snapshot()
        p.require(type(own) is dict and set(own)=={'pid','uid','euid','gid','egid','groups'}
                  and all(type(own[k]) is int and own[k]>0 for k in ('pid','uid','euid','gid','egid'))
                  and own['uid']==own['euid'] and own['gid']==own['egid']
                  and own['groups'] in ([], [own['gid']]),
                  'worker_nonroot_identity')
        emit({'schema':'openclaw.retained-verifier-ready.v1','status':'ready','pid':own['pid'],
              'uid':own['uid'],'gid':own['gid'],'contextSha256':context_sha,'workerSha256':p.sha(public_worker)})
        ready=True
        for iteration in range(601):
            p.require(clock.monotonic()-started<30,'worker_gate_wait_expired');remaining(deadline)
            raw_gate=files.read_public(GATE_PATH,16384,pending=True)
            if raw_gate is not None:
                gate=p.decode(raw_gate,16384);validate_gate(gate,context,context_sha,own,p,clock.utc());break
            clock.sleep(0.05)
        else:raise p.Refusal('worker_gate_wait_expired')
        p.require(process.snapshot()==own,'worker_process_changed')
        files.input_released()  # No private path observation before valid gate.
        function=(consumer_loader or load_consumer)(context,files,p)
        seconds=min(240,remaining(deadline)-30)
        p.require(seconds>0,'worker_completion_reserve')
        consumer_began=clock.monotonic()
        consumer_exit=timer.call(seconds,function)
        if clock.monotonic()-consumer_began>seconds:raise WorkerTimeout('worker_consumer_timeout')
        p.require(type(consumer_exit) is int and consumer_exit in (0,1),'worker_consumer_exit')
        remaining(deadline)
        p.require(process.snapshot()==own,'worker_process_changed')
        if consumer_exit!=0: reason='worker_consumer_refused'
    except WorkerTimeout:
        timed_out=True;reason='worker_consumer_timeout'
    except BaseException as error:
        reason=getattr(error,'code',None) if type(error) is p.Refusal else (str(error) if type(error) is BootstrapRefusal else None)
        if type(reason) is not str or re.fullmatch('[a-z][a-z0-9_.]{0,95}',reason) is None:reason='worker_refused'
    current=clock.monotonic();elapsed=current-started
    if not (type(elapsed) in (int,float) and math.isfinite(elapsed) and elapsed>=0):elapsed=0;reason='worker_clock'
    final={'schema':'openclaw.retained-verifier-worker-final.v1','status':'consumer_returned' if reason is None else 'refused',
           'pid':None if own is None else own['pid'],'contextSha256':context_sha,'readyEmitted':ready,
           'consumerExitCode':consumer_exit,'timedOut':timed_out,'reasonCode':reason,'elapsedMilliseconds':int(elapsed*1000)}
    emit(final)
    return final


def main():
    if ARMED is not True: raise BootstrapRefusal('worker_disarmed')
    result=run_once()
    return 0 if result['status']=='consumer_returned' and result['consumerExitCode']==0 and not result['timedOut'] else 1


if __name__ == '__main__':
    if ARMED is not True: raise SystemExit('worker_disarmed')
    raise SystemExit(main())
