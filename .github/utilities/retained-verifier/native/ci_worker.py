"""CI-only worker logic; injected ports, inert CLI, no native/privilege setup."""
import datetime as dt
import math
import re
import hashlib
import os
from pathlib import Path
import signal
import stat
import sys
import time

# Python -I excludes script siblings. The future exact reviewed CI source may
# bind this *public dependency-only* manifest; no caller JSON can set the pin.
# It excludes this worker and fresh runtime/context hashes to avoid a hash cycle.
CI_IMPORT_MANIFEST_SHA256=None

def _bootstrap_read(path,cap):
    p=Path(path)
    if p.resolve()!=p:raise RuntimeError('ci.bootstrap_path')
    info=p.lstat()
    if not(stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==0 and info.st_nlink==1 and
           stat.S_IMODE(info.st_mode)==0o444 and 0<=info.st_size<=cap):raise RuntimeError('ci.bootstrap_identity')
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        opened=os.fstat(fd);raw=os.read(fd,cap+1);after=os.fstat(fd)
    finally:os.close(fd)
    def identity(v):return tuple(getattr(v,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
    if len(raw)!=info.st_size or identity(info)!=identity(opened) or identity(info)!=identity(after) or identity(info)!=identity(p.lstat()):
        raise RuntimeError('ci.bootstrap_changed')
    return raw

def _bootstrap_imports():
    if CI_IMPORT_MANIFEST_SHA256 is None:raise RuntimeError('ci.worker_disarmed')
    raw=_bootstrap_read('/control/imports.json',16384)
    if hashlib.sha256(raw).hexdigest()!=CI_IMPORT_MANIFEST_SHA256:raise RuntimeError('ci.bootstrap_pin')
    import json
    def pairs(rows):
        value={}
        for key,item in rows:
            if key in value:raise RuntimeError('ci.bootstrap_duplicate')
            value[key]=item
        return value
    doc=json.loads(raw,object_pairs_hook=pairs)
    if set(doc)!={'schema','codeFiles'} or doc['schema']!='ci.public-imports.v1' or set(doc['codeFiles'])!={'ci_protocol.py','ci_fixture.py','ci_profile.py'}:
        raise RuntimeError('ci.bootstrap_schema')
    for name,row in doc['codeFiles'].items():
        if set(row)!={'bytes','sha256'}:raise RuntimeError('ci.bootstrap_row')
        source=_bootstrap_read('/code/'+name,131072)
        if len(source)!=row['bytes'] or hashlib.sha256(source).hexdigest()!=row['sha256']:raise RuntimeError('ci.bootstrap_code_pin')
    # Only this hash-verified readonly root-owned directory is admitted.
    sys.path.insert(0,'/code')

if __name__=='__main__':_bootstrap_imports()
import ci_fixture as fixture
from ci_protocol import Refusal,canonical,closed,decode,require,sha,utc
from ci_profile import DESIGN_PROFILE_SHA
ARMED=False
CI_CONTEXT_MANIFEST_SHA256=None
CONTEXT_KEYS={'schema','sessionId','unitName','bootId','vmId','identityName','contextNonce','workerDeadlineUtc',
 'maxJobSeconds','operation','mountPropagation','sourceSha','scannerSha','indexDigest','privacySha256','privacyBytes',
 'consumerCode','profileSha256','entrySha256','workerSha256','runtimeManifestSha256','inputManifestSha256'}
GATE_KEYS={'schema','sessionId','unitName','bootId','vmId','pid','startTimeTicks','uid','gid','identityName',
 'checkedAt','expiresAt','workerDeadlineUtc','profileSha256','entrySha256','workerSha256','runtimeManifestSha256',
 'inputManifestSha256','sourceSha','scannerSha','indexDigest','privacySha256','privacyBytes','consumerCode',
 'proofSha256','status','mountPropagation','inputReleased','contextSha256','invocationId'}
FIXTURE_SOURCE=sha(b'generic-synthetic-source-v1')[:40]
FIXTURE_SCANNER=sha(b'generic-synthetic-scanner-v1')[:40]
FIXTURE_INDEX='sha256:'+sha(b'generic-synthetic-index-v1')


class WorkerTimeout(RuntimeError):pass


def validate_context(value,now,code):
    closed(value,CONTEXT_KEYS,'ci.worker_context_schema')
    require(value['schema']=='openclaw.retained-verifier-context.v1' and
      re.fullmatch('[0-9a-f]{32}',value['sessionId'] or '') and
      value['identityName']=='ocv-'+value['sessionId'][:24] and value['unitName']=='ocv-'+value['sessionId']+'.service',
      'ci.worker_identity')
    require(re.fullmatch('[0-9a-f]{64}',value['contextNonce'] or '') and value['vmId']=='1' and
      re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}',value['bootId'] or ''),'ci.worker_generation')
    fixed={'maxJobSeconds':300,'operation':'retained-report-only','mountPropagation':'private','sourceSha':FIXTURE_SOURCE,
      'scannerSha':FIXTURE_SCANNER,'indexDigest':FIXTURE_INDEX,'privacySha256':fixture.REPORT_SHA,
      'privacyBytes':len(fixture.REPORT),'consumerCode':code['consumerCode'],'profileSha256':DESIGN_PROFILE_SHA,
      'entrySha256':code['entrySha256'],'workerSha256':code['workerSha256'],'runtimeManifestSha256':code['runtimeManifestSha256']}
    require(all(type(value[k]) is type(v) and value[k]==v for k,v in fixed.items()),'ci.worker_pin')
    require(all(type(value[k]) is str and re.fullmatch('[0-9a-f]{64}',value[k]) for k in
      ('inputManifestSha256','entrySha256','workerSha256','runtimeManifestSha256')),'ci.worker_hash')
    require(0<(utc(value['workerDeadlineUtc'])-now).total_seconds()<=300,'ci.worker_deadline')


class Worker:
    """One-process logic only. No caller JSON or method flips ARMED."""
    def __init__(self,*,code,files,process,clock,timer,consumer=fixture.consume):
        self.code,self.files,self.process,self.clock,self.timer,self.consumer=code,files,process,clock,timer,consumer
        self.used=False;self.ready_used=False;self.stdout=[];self.stderr=[]
    def ready(self,raw):
        require(not self.ready_used,'ci.worker_ready_once');self.ready_used=True
        self.started=self.clock.monotonic();self.last=self.started
        require(type(self.started) in (int,float) and math.isfinite(self.started),'ci.worker_clock')
        self.context=decode(raw,16384);validate_context(self.context,self.clock.utc(),self.code)
        require(sha(self.files.read_public('/code/worker.py',262144))==self.context['workerSha256'],'ci.worker_source')
        self.raw=raw;self.own=self.process.snapshot()
        closed(self.own,{'pid','uid','euid','gid','egid','groups'},'ci.worker_process_schema')
        require(all(type(self.own[k]) is int and self.own[k]>0 for k in ('pid','uid','euid','gid','egid')) and
          self.own['uid']==self.own['euid'] and self.own['gid']==self.own['egid'] and
          type(self.own['groups']) is list and self.own['groups'] in ([],[self.own['gid']]),
          'ci.worker_nonroot')
        frame={'schema':'openclaw.retained-verifier-ready.v1','status':'ready','pid':self.own['pid'],
          'uid':self.own['uid'],'gid':self.own['gid'],'contextSha256':sha(raw),'workerSha256':self.context['workerSha256']}
        self.stderr.append(canonical(frame));return canonical(frame)
    def finish(self,gate_raw):
        require(self.ready_used and not self.used,'ci.worker_once');self.used=True
        timed=False;reason=None;code=None
        try:
            now=self.clock.utc();elapsed=self.clock.monotonic()-self.started
            require(math.isfinite(elapsed) and 0<=elapsed<30,'ci.worker_gate_wait')
            gate=closed(decode(gate_raw,16384),GATE_KEYS,'ci.worker_gate_schema')
            joined=CONTEXT_KEYS-{'schema','contextNonce','operation','maxJobSeconds'}
            require(gate['schema']=='openclaw.retained-verifier-admission.v1' and
              all(type(gate[k]) is type(self.context[k]) and gate[k]==self.context[k] for k in joined) and
              gate['contextSha256']==sha(self.raw),'ci.worker_gate_join')
            require(gate['status']=='passed' and gate['inputReleased'] is True and
              all(type(gate[k]) is int and gate[k]==self.own[k] for k in ('pid','uid','gid')) and
              type(gate['startTimeTicks']) is int and gate['startTimeTicks']>0 and
              re.fullmatch('[0-9a-f]{64}',gate['proofSha256'] or '') and re.fullmatch('[0-9a-f]{32}',gate['invocationId'] or ''),
              'ci.worker_gate_process')
            checked,expires=utc(gate['checkedAt']),utc(gate['expiresAt'])
            require(checked<=now<expires<=utc(self.context['workerDeadlineUtc']) and 0<(expires-checked).total_seconds()<=30,
              'ci.worker_gate_time')
            require(self.process.snapshot()==self.own,'ci.worker_process_changed')
            self.files.input_released()
            remaining=min(300-elapsed,(utc(self.context['workerDeadlineUtc'])-now).total_seconds())
            seconds=min(240,remaining-30);require(seconds>0,'ci.worker_completion_reserve')
            began=self.clock.monotonic()
            code=self.timer.call(seconds,lambda:self.consumer(self.files.read_input,self.stdout.append))
            if self.clock.monotonic()-began>seconds:raise WorkerTimeout()
            require(type(code) is int and code==0,'ci.worker_consumer_exit')
            require(self.process.snapshot()==self.own,'ci.worker_process_changed')
        except WorkerTimeout:timed=True;reason='ci.worker_timeout'
        except BaseException as error:reason=error.code if isinstance(error,Refusal) else 'ci.worker_refused'
        elapsed=self.clock.monotonic()-self.started
        if not isinstance(elapsed,(int,float)) or not math.isfinite(elapsed) or elapsed<0:elapsed=0;reason='ci.worker_clock'
        frame={'schema':'openclaw.retained-verifier-worker-final.v1','status':'consumer_returned' if reason is None else 'refused',
          'pid':self.own['pid'],'contextSha256':sha(self.raw),'readyEmitted':True,'consumerExitCode':code,
          'timedOut':timed,'reasonCode':reason,'elapsedMilliseconds':int(elapsed*1000)}
        self.stderr.append(canonical(frame))
        return {'stdout':b''.join(self.stdout),'stderr':b'\n'.join(self.stderr)+b'\n','returncode':0 if reason is None else 1,'timedOut':timed}


class NativeFiles:
    def __init__(self):self.released=False
    def read_public(self,path,cap,pending=False):
        require(path in ('/control/context.json','/control/admission.json','/code/worker.py',
          '/code/ci_fixture.py','/control/imports.json'),'ci.worker_public_path')
        try:return _bootstrap_read(path,cap)
        except (FileNotFoundError,PermissionError):
            if pending:return None
            raise
    def input_released(self):
        info=Path('/input').lstat()
        require(Path('/input').resolve()==Path('/input') and stat.S_ISDIR(info.st_mode) and info.st_uid==info.st_gid==0 and
          stat.S_IMODE(info.st_mode)==0o555,'ci.worker_input_not_released')
        self.released=True
    def read_input(self,path,cap):
        require(self.released and path in ('/input/privacy.json','/input/oci/synthetic.bin'),'ci.worker_input_path')
        return _bootstrap_read(path,cap)


class NativeProcess:
    def snapshot(self):return {'pid':os.getpid(),'uid':os.getuid(),'euid':os.geteuid(),'gid':os.getgid(),'egid':os.getegid(),'groups':os.getgroups()}


class NativeClock:
    def utc(self):return dt.datetime.now(dt.timezone.utc)
    def monotonic(self):return time.monotonic()
    def sleep(self,seconds):time.sleep(seconds)


class NativeTimer:
    def call(self,seconds,function):
        require(type(seconds) in (int,float) and math.isfinite(seconds) and 0<seconds<=240,'ci.worker_timer_bound')
        require(signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0),'ci.worker_existing_timer')
        old=signal.getsignal(signal.SIGALRM)
        def expired(number,frame):raise WorkerTimeout()
        signal.signal(signal.SIGALRM,expired)
        try:signal.setitimer(signal.ITIMER_REAL,seconds);return function()
        finally:signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,old)


_BOUND_WORKER_CONTEXT=None

def run_bound_native(context):
    require(_BOUND_WORKER_CONTEXT is not None and context is _BOUND_WORKER_CONTEXT,
            'ci.worker_capability_unissued')
    files=NativeFiles();clock=NativeClock()
    job=Worker(code=context.code,files=files,process=NativeProcess(),clock=clock,timer=NativeTimer())
    raw=files.read_public('/control/context.json',16384)
    ready=job.ready(raw);sys.stderr.buffer.write(ready+b'\n');sys.stderr.buffer.flush()
    gate_raw=None
    for _ in range(601):
        require(clock.monotonic()-job.started<30,'ci.worker_gate_wait')
        gate_raw=files.read_public('/control/admission.json',16384,pending=True)
        if gate_raw is not None:break
        clock.sleep(.05)
    require(gate_raw is not None,'ci.worker_gate_wait')
    result=job.finish(gate_raw)
    sys.stdout.buffer.write(result['stdout']);sys.stdout.buffer.flush()
    final=job.stderr[-1]+b'\n';sys.stderr.buffer.write(final);sys.stderr.buffer.flush()
    return result['returncode']


def main():
    require(ARMED is True and CI_CONTEXT_MANIFEST_SHA256 is not None and CI_IMPORT_MANIFEST_SHA256 is not None,
            'ci.worker_disarmed')
    return run_bound_native(_BOUND_WORKER_CONTEXT)


if __name__=='__main__':raise SystemExit(main())
