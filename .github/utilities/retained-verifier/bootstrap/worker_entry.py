"""Verified CI worker entry at /code/worker.py; no issuer/ARM globals patched.

Imports/default CLI on a non-Linux/non-worker host refuse before file access.
Root-owned immutable staging is trusted only in the observed nonroot unit; the
host gate still proves actual isolation before these tiny inputs are released.
"""
import hashlib,json,os,stat,sys,time
from pathlib import Path


class Refusal(RuntimeError):pass


def need(ok,code):
 if not ok:raise Refusal(code)

def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()

def decode(raw):
 need(type(raw)is bytes and len(raw)<=16384,'worker_boot.cap')
 def pairs(rows):
  out={}
  for k,v in rows:need(k not in out,'worker_boot.duplicate');out[k]=v
  return out
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'worker_boot.nonfinite'))


class NativeWorkerFiles:
 def __init__(self):
  uid,euid,gid,egid,groups=os.getuid(),os.geteuid(),os.getgid(),os.getegid(),os.getgroups()
  checks={'linux':sys.platform=='linux','uidRange':61184<=uid<=65519,
          'uidEqEuid':uid==euid,'gidEqEgid':gid==egid,
          'noSupplementary':groups==[],'codePath':str(Path(__file__).resolve())=='/code/worker.py'}
  if not all(checks.values()):
   # This worker is only built into a synthetic no-NIC CI guest. The bounded
   # numeric/boolean diagnostic carries no report, credential or file bytes.
   sys.stderr.write('OCV_WORKER_IDENTITY_V1:'+canonical({'checks':checks,'uid':uid,'gid':gid,
     'groupCount':len(groups),'groupsHead':groups[:8]}).decode()+'\n')
   raise Refusal('worker_boot.native_unit_required')
 def pending(self,path,cap):
  need(path=='/control/admission.json','worker_boot.pending_path')
  try:s=Path(path).lstat()
  except FileNotFoundError:return None
  need(stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and s.st_nlink==1,'worker_boot.pending_identity')
  if stat.S_IMODE(s.st_mode)==0o600:return None
  return self.file(path,cap)
 def file(self,path,cap):
  p=Path(path);need(str(p.resolve())==path,'worker_boot.path')
  s=p.lstat();need(stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o444 and
    s.st_nlink==1 and 0<=s.st_size<=cap,'worker_boot.identity')
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  try:
   opened=os.fstat(fd);out=bytearray()
   while len(out)<=cap:
    b=os.read(fd,min(65536,cap+1-len(out)))
    if not b:break
    out.extend(b)
   after=os.fstat(fd)
  finally:os.close(fd)
  identity=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  need(identity(s)==identity(opened)==identity(after)==identity(p.lstat()) and len(out)==s.st_size,'worker_boot.changed')
  return bytes(out)


def verify(files,process):
 own=process.snapshot()
 need(type(own)is dict and set(own)=={'pid','uid','euid','gid','egid','groups'} and own['pid']>1 and
  61184<=own['uid']<=65519 and own['uid']==own['euid'] and own['gid']==own['egid'] and own['groups']==[],
  'worker_boot.nonroot')
 raw=files.file('/control/context.json',16384);context=decode(raw)
 boot=decode(files.file('/control/worker-bootstrap.json',16384))
 need(set(boot)=={'schema','contextSha256','sourceManifestSha256','codeFiles','code'} and
  boot['schema']=='ocv-worker-bootstrap-v1' and boot['contextSha256']==sha(raw),'worker_boot.context_binding')
 names={'ci_protocol.py','ci_profile.py','ci_fixture.py','ci_worker_core.py'}
 need(type(boot['codeFiles'])is dict and set(boot['codeFiles'])==names,'worker_boot.code_roster')
 for name,row in boot['codeFiles'].items():
  need(set(row)=={'bytes','sha256'},'worker_boot.row')
  code=files.file('/code/'+name,131072);need(len(code)==row['bytes'] and sha(code)==row['sha256'],'worker_boot.code_pin')
 consumers=boot['code']['consumerCode']
 need(type(consumers)is dict and set(consumers)=={'ci_fixture.py','native_cases.py','hosted_export.py','hosted_privacy.py',
  'public-member-comparisons-v105-workboard.json'} and context['consumerCode']==consumers,'worker_boot.consumer_roster')
 for name,row in consumers.items():
  need(type(row)is dict and set(row)=={'bytes','sha256'},'worker_boot.consumer_row')
  code=files.file('/code/'+name,131072)
  need(len(code)==row['bytes'] and sha(code)==row['sha256'],'worker_boot.consumer_pin')
 worker=files.file('/code/worker.py',131072)
 need(sha(worker)==context['workerSha256']==boot['code']['workerSha256'] and
  consumers['ci_fixture.py']==boot['codeFiles']['ci_fixture.py'],'worker_boot.self_consumer')
 return {'contextRaw':raw,'bootstrap':boot,'own':own}


def begin_with_dependencies(plan,core,files,process,clock,timer,emit,*,after_gate=None,validate_cases=None):
 # Explicit local test seam produces only normal worker logic, never root/native
 # capabilities. Actual native main passes the verified NativeWorkerFiles path.
 need(callable(after_gate)and callable(validate_cases),'worker_boot.native_cases_unbound')
 holder={}
 def checked_consumer(read,emit):
  job=holder['job']
  # This callback is called only by unchanged Worker.finish AFTER its complete
  # gate/process/time checks and files.input_released() positive validation.
  summary=after_gate(job,files)
  raw=canonical(summary);need(len(raw)<=4096,'worker_boot.native_cases_cap')
  job.native_case_raw=raw
  validate_cases(summary,expected_pid=plan['own']['pid'],expected_context_sha=sha(plan['contextRaw']))
  need(summary.get('status')=='passed','worker_boot.native_cases_refused')
  return core.fixture.consume(read,emit)
 job=core.Worker(code=plan['bootstrap']['code'],files=files,process=process,clock=clock,timer=timer,consumer=checked_consumer)
 holder['job']=job
 ready=job.ready(plan['contextRaw']);emit(ready+b'\n')
 return job


def finish_with_native_frame(job,gate):
 outcome=job.finish(gate)
 raw=getattr(job,'native_case_raw',None)
 if raw is not None:outcome={**outcome,'stderr':outcome['stderr']+raw+b'\n'}
 return outcome


def run_checked_native_cases(module,job,files):
 try:
  actual=module.NativeIO.for_checked_worker(job,files)
  return module.run_cases(actual)
 except (module.Refusal,OSError) as error:
  # Preserve a fixed source-owned factory/case cause as the same third frame.
  # Outer WorkerTimeout is deliberately not absorbed by this boundary.
  return module.failure_summary(job,error)


class RuntimeFiles:
 def __init__(self,core,verified):self.base=core.NativeFiles();self.verified=verified
 def read_public(self,path,cap,pending=False):
  if pending:return self.verified.pending(path,cap)
  return self.verified.file(path,cap)
 def input_released(self):return self.base.input_released()
 def read_input(self,path,cap):return self.base.read_input(path,cap)


def main():
 need(sys.platform=='linux' and 61184<=os.getuid()<=65519 and len(sys.argv)==1,'worker_boot.native_unit_required')
 files=NativeWorkerFiles()
 class Process:
  def snapshot(self):return {'pid':os.getpid(),'uid':os.getuid(),'euid':os.geteuid(),'gid':os.getgid(),'egid':os.getegid(),'groups':os.getgroups()}
 process=Process();plan=verify(files,process)
 # Only the four root-owned/hashchecked dependency files enter this fixed path.
 sys.path.insert(0,'/code');import ci_worker_core as core
 import native_cases
 safe=RuntimeFiles(core,files);clock=core.NativeClock();timer=core.NativeTimer()
 def checked_cases(job,runtime_files):
  return run_checked_native_cases(native_cases,job,runtime_files)
 job=begin_with_dependencies(plan,core,safe,process,clock,timer,lambda raw:sys.stderr.buffer.write(raw) and sys.stderr.buffer.flush(),
  after_gate=checked_cases,validate_cases=native_cases.validate_result)
 gate=None
 for _ in range(601):
  need(clock.monotonic()-job.started<30,'worker_boot.gate_wait')
  gate=safe.read_public('/control/admission.json',16384,pending=True)
  if gate is not None:break
  clock.sleep(.05)
 need(gate is not None and process.snapshot()==plan['own'],'worker_boot.process_or_gate')
 outcome=finish_with_native_frame(job,gate)
 sys.stdout.buffer.write(outcome['stdout']);sys.stdout.buffer.flush()
 sys.stderr.buffer.write(job.stderr[-1]+b'\n');sys.stderr.buffer.flush()
 if getattr(job,'native_case_raw',None)is not None:
  sys.stderr.buffer.write(job.native_case_raw+b'\n');sys.stderr.buffer.flush()
 return outcome['returncode']


if __name__=='__main__':raise SystemExit(main())
