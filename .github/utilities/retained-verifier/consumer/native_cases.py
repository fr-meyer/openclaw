"""Finite CI-only isolation cases, after the positive worker gate.

Pure run_cases accepts injected observations. NativeIO can be constructed only
by the explicit future checked Linux worker path; import/default CLI does no
I/O. Local tests never construct it or fork. No case connects/sends, writes
payload bytes, supplies a mount target, or reads operational data.
"""
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import sys
import time
import types

CASE_IDS=('readonly-code','management-paths','unix-socket','mount','entry-bad-argv','entry-bad-env','timer-late-zero')
MANAGEMENT=('/run/docker.sock','/var/run/docker.sock','/run/systemd/private','/run/dbus/system_bus_socket')
IMPORT_PINS={
 'hosted_export.py':'4469f534a4c61678e951a1542e6e5caa69ac8fd7431729b6cfedeaef0f084e3c',
 'hosted_privacy.py':'b6f9d4736b0051361aacc7c56f562de135a41c9662babae7e20cbdee436495b9',
 'public-member-comparisons-v105-workboard.json':'b172ee3c6cdf34d983cdb4b1452924b5931762020b94596b4405e7a6fdeb03df'}
BLOCKED={errno.EPERM,errno.EACCES}
UNAVAILABLE={errno.ENOENT,errno.ENOTDIR,errno.EACCES,errno.EPERM}
MAX_SECONDS=30
MAX_FRAME=4096
ERROR_PHASES=frozenset({'run_child_boundary','fork','selector_create','clock','select','wait_poll','control_decode',
 'cleanup_kill','cleanup_wait','cleanup_clock','cleanup_sleep','cleanup_selector'}|
 {prefix+'_'+channel for prefix in('pipe','nonblocking','register','read','unregister','close_read','close_write')
  for channel in('control','stdout','stderr')})
ERROR_TYPES=frozenset({'OSError','PermissionError','FileNotFoundError','BlockingIOError','InterruptedError',
 'ChildProcessError','TimeoutError','ProcessLookupError','ValueError','KeyError','TypeError','RuntimeError',
 'AssertionError','Refusal','JSONDecodeError','BoundaryError'})
EMPTY_SHA=hashlib.sha256(b'').hexdigest()
_NATIVE_KEY=object()
FAILURE_REASONS={'imports_refused','case_refused','case_boundary','clock_refused','deadline','factory_refused',
 'native.import_roster','native.import_pin','native.ambient_import','native.import_catalog','native.identity','native.deadline',
 'native.worker_path','native.positive_gate','native.worker_identity','native.timer_source','native.code_pin','native.entry_pin',
 'native.file_path','native.file_identity','native.file_changed','native.file_missing','native.file_permission','native.file_io'}


class Refusal(ValueError):
 def __init__(self,code):super().__init__(code);self.code=code
NativeCasesRefusal=Refusal


def need(value,code):
 if not value:raise Refusal(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def integer(value,low=0,high=(1<<63)-1):return type(value)is int and low<=value<=high
def hash_value(value):return type(value)is str and re.fullmatch('[0-9a-f]{64}',value)is not None
def closed(value,keys,code):need(type(value)is dict and set(value)==set(keys),code);return value


def error_record(phase,error):
 need(phase in ERROR_PHASES,'native.error_phase')
 kind=type(error).__name__
 number=getattr(error,'errno',None)
 return {'phase':phase,'type':kind if kind in ERROR_TYPES else'BoundaryError',
         'errno':number if integer(number,1,4095)else None}


def empty_errors():return {'first':None,'cleanup':[],'omitted':0}


def validate_errors(value):
 closed(value,{'first','cleanup','omitted'},'native.errors_schema')
 need(type(value['cleanup'])is list and len(value['cleanup'])<=2 and integer(value['omitted'],0,32),'native.errors_shape')
 for row in ([value['first']]if value['first']is not None else[])+value['cleanup']:
  closed(row,{'phase','type','errno'},'native.error_schema')
  need(type(row['phase'])is str and row['phase']in ERROR_PHASES and type(row['type'])is str and row['type']in ERROR_TYPES and
       (row['errno']is None or integer(row['errno'],1,4095)),'native.error_shape')
 need(value['first']is not None or(not value['cleanup']and value['omitted']==0),'native.error_first')
 need(value['omitted']==0 or len(value['cleanup'])==2,'native.error_omitted')
 return value


REPORT_SHA=sha(canonical({'schema':'generic.synthetic-receipt.v1','status':'passed'}))
CLOSURE_SHA=sha(canonical({'report':REPORT_SHA,'blob':sha(b'Public disposable synthetic payload.\n')}))
TIMER_OUTPUT=canonical({'status':'passed','privacyReceiptSha256':REPORT_SHA,'ociClosureSha256':CLOSURE_SHA})+b'\n'


def validate_imports(sources):
 """Import only exact supplied immutable public bytes; no report is consumed."""
 closed(sources,IMPORT_PINS,'native.import_roster')
 for name,raw in sources.items():
  need(type(raw)is bytes and len(raw)<=131072 and sha(raw)==IMPORT_PINS[name],'native.import_pin')
 need(not any(name in sys.modules for name in ('hosted_privacy','hosted_export')),'native.ambient_import')
 modules={}
 try:
  for name in ('hosted_privacy','hosted_export'):
   module=types.ModuleType(name);module.__file__='/code/'+name+'.py';sys.modules[name]=module
   exec(compile(sources[name+'.py'],module.__file__,'exec'),module.__dict__);modules[name]=module
  plan=json.loads(sources['public-member-comparisons-v105-workboard.json'])
  need(plan['sourceSha']==modules['hosted_privacy'].PUBLIC_MEMBER_QUALIFICATION['sourceSha'] and
       sha(sources['public-member-comparisons-v105-workboard.json'])==
       modules['hosted_privacy'].PUBLIC_MEMBER_QUALIFICATION['planSha256'],'native.import_catalog')
 finally:
  for name in ('hosted_privacy','hosted_export'):sys.modules.pop(name,None)
 return dict(IMPORT_PINS)


def _classify(case,record):
 closed(record,{'exitCode','signal','errno','timedOut','reaped','outputComplete','stdout','stderr','detail','errors'},'native.observation_schema')
 need((record['exitCode']is None or integer(record['exitCode'],0,255)) and
      (record['signal']is None or integer(record['signal'],1,64)) and
      (record['errno']is None or integer(record['errno'],1,4095)) and
      type(record['timedOut'])is bool and type(record['reaped'])is bool and type(record['outputComplete'])is bool and
      type(record['stdout'])is bytes and len(record['stdout'])<=256 and type(record['stderr'])is bytes and len(record['stderr'])<=256 and
      type(record['detail'])is str and re.fullmatch('[a-z0-9_:,.-]{1,80}',record['detail']),
      'native.observation_shape')
 validate_errors(record['errors'])
 common=(record['errors']==empty_errors() and record['timedOut']is False and record['reaped']is True and record['outputComplete']is True and
         ((record['exitCode']is not None) != (record['signal']is not None)))
 blocked=(record['signal']==int(signal.SIGSYS) and record['exitCode']is None and record['errno']is None and
          record['detail']=='sigsys') or (record['exitCode']==0 and record['signal']is None and record['errno'] in BLOCKED and
                                         record['detail']=='blocked')
 if case=='readonly-code':
  passed=(record['exitCode']==0 and record['signal']is None and record['errno'] in BLOCKED|{errno.EROFS} and
          record['detail']=='readonly_denied' and record['stdout']==record['stderr']==b'')
 elif case=='management-paths':
  prefix='unavailable:';items=record['detail'][len(prefix):].split(',') if record['detail'].startswith(prefix) else []
  passed=(record['exitCode']==0 and record['signal']is None and record['errno']is None and len(items)==len(MANAGEMENT) and
          all(re.fullmatch('[1-9][0-9]*',v) and int(v)in UNAVAILABLE for v in items) and
          record['stdout']==record['stderr']==b'')
 elif case in ('unix-socket','mount'):
  passed=blocked and record['stdout']==record['stderr']==b''
 elif case in ('entry-bad-argv','entry-bad-env'):
  passed=(record['exitCode']==111 and record['signal']is None and record['errno']is None and
          record['stdout']==b'' and record['stderr']==b'entry_refused\n' and record['detail']=='exec_refused')
 else:
  passed=(record['exitCode']==0 and record['signal']is None and record['errno']is None and
          record['stdout']==TIMER_OUTPUT and record['stderr']==b'' and record['detail']=='timer_timeout')
 return bool(common and passed)


def _row(case,record):
 passed=_classify(case,record)
 return {'id':case,'status':'passed' if passed else 'failed',
         **{key:record[key]for key in ('exitCode','signal','errno','timedOut','reaped','outputComplete','detail','errors')},
         'stdoutBytes':len(record['stdout']),'stdoutSha256':sha(record['stdout']),
         'stderrBytes':len(record['stderr']),'stderrSha256':sha(record['stderr'])}


def _failure(detail='boundary_refused',error=None):
 return {'exitCode':None,'signal':None,'errno':getattr(error,'errno',None) if integer(getattr(error,'errno',None),1,4095) else None,
         'timedOut':False,'reaped':False,'outputComplete':False,'stdout':b'','stderr':b'','detail':detail,
         'errors':{'first':error_record('run_child_boundary',error)if error is not None else None,'cleanup':[],'omitted':0}}


def failure_summary(job,error):
 """Known pre-case refusal after the core gate; no native operation or echo."""
 pid=job.own['pid'];context=sha(job.raw)
 need(integer(pid,2,4194304)and hash_value(context),'native.failure_identity')
 reason=error.code if isinstance(error,Refusal)and error.code in FAILURE_REASONS else'factory_refused'
 return {'schema':'ocv.native-isolation-cases.v1','status':'failed','pid':pid,'contextSha256':context,'cases':[],
         'producer':'not_issued',
         'importHashes':dict(IMPORT_PINS),'importsPassed':False,'allChildrenReaped':True,'elapsedMilliseconds':0,
         'reason':reason,'fixtureOnly':True,'candidateImage':False}


def run_cases(io):
 """One finite injected sequence. Native callers use only the checked factory."""
 start=io.monotonic();identity=io.identity();pid=identity.get('pid');context=identity.get('contextSha256')
 result={'schema':'ocv.native-isolation-cases.v1','status':'failed','pid':pid,'contextSha256':context,'cases':[],
         'producer':'native_linux'if type(io)is NativeIO else'synthetic_injected',
         'importHashes':dict(IMPORT_PINS),'importsPassed':False,'allChildrenReaped':True,'elapsedMilliseconds':0,
         'reason':'imports_refused','fixtureOnly':True,'candidateImage':False}
 try:
  need(integer(pid,2,4194304) and hash_value(context) and type(start)in(int,float)and math.isfinite(start),'native.identity')
  validate_imports(io.import_sources());result['importsPassed']=True
  for case in CASE_IDS:
   elapsed=io.monotonic()-start
   need(type(elapsed)in(int,float)and math.isfinite(elapsed)and 0<=elapsed<MAX_SECONDS,'native.deadline')
   try:observation=io.run_child(case,3)
   except BaseException as error:
    timeout_type=getattr(io,'outer_timeout_type',())
    if isinstance(timeout_type,type)and isinstance(error,timeout_type):raise
    observation=_failure(error=error)
   row=_row(case,observation);result['cases'].append(row)
   result['allChildrenReaped'] &= row['reaped']
   if row['status']!='passed':result['reason']='case_refused';break
  else:result.update(status='passed',reason=None)
 except BaseException as error:
  timeout_type=getattr(io,'outer_timeout_type',())
  if isinstance(timeout_type,type)and isinstance(error,timeout_type):raise
  result['reason']=error.code if isinstance(error,Refusal)and error.code in FAILURE_REASONS else(
    'imports_refused' if not result['importsPassed'] else 'case_boundary')
 elapsed=io.monotonic()-start
 if type(elapsed)not in(int,float)or not math.isfinite(elapsed)or elapsed<0:
  elapsed=0;result.update(status='failed',reason='clock_refused')
 if elapsed>MAX_SECONDS:result.update(status='failed',reason='deadline')
 result['elapsedMilliseconds']=int(elapsed*1000)
 need(len(canonical(result))<=MAX_FRAME,'native.frame_cap')
 return result


def validate_result(value,expected_pid=None,expected_context_sha=None,allow_failure=False,allow_synthetic=False):
 closed(value,{'schema','status','pid','contextSha256','cases','importHashes','importsPassed','allChildrenReaped',
               'elapsedMilliseconds','reason','fixtureOnly','candidateImage','producer'},'native.result_schema')
 need(value['schema']=='ocv.native-isolation-cases.v1' and value['status']in('passed','failed') and
      integer(value['pid'],2,4194304)and hash_value(value['contextSha256']) and value['fixtureOnly']is True and
      value['candidateImage']is False and type(value['importsPassed'])is bool and type(value['allChildrenReaped'])is bool and
      integer(value['elapsedMilliseconds'],0,MAX_SECONDS*1000+10000) and value['importHashes']==IMPORT_PINS and
      type(value['importHashes'])is dict and type(value['cases'])is list and len(value['cases'])<=len(CASE_IDS) and
      value['reason']in FAILURE_REASONS|{None} and value['producer']in('native_linux','synthetic_injected','not_issued'),
      'native.result_shape')
 if expected_pid is not None:need(type(expected_pid)is int and value['pid']==expected_pid,'native.result_pid')
 if expected_context_sha is not None:need(value['contextSha256']==expected_context_sha,'native.result_context')
 for index,row in enumerate(value['cases']):
  closed(row,{'id','status','exitCode','signal','errno','timedOut','reaped','outputComplete','stdoutBytes','stdoutSha256',
              'stderrBytes','stderrSha256','detail','errors'},'native.case_schema')
  need(row['id']==CASE_IDS[index] and row['status']in('passed','failed') and integer(row['stdoutBytes'],0,256)and
       integer(row['stderrBytes'],0,256)and hash_value(row['stdoutSha256'])and hash_value(row['stderrSha256']),
       'native.case_shape')
  # Reconstruct only the two source-known outputs. Unknown bytes cannot clear.
  stdout=TIMER_OUTPUT if row['id']=='timer-late-zero' else b''
  stderr=b'entry_refused\n' if row['id']in('entry-bad-argv','entry-bad-env')else b''
  outputs=(row['stdoutBytes']==len(stdout)and row['stdoutSha256']==sha(stdout)and
           row['stderrBytes']==len(stderr)and row['stderrSha256']==sha(stderr))
  observed={key:row[key]for key in ('exitCode','signal','errno','timedOut','reaped','outputComplete','detail','errors')}
  observed.update(stdout=stdout,stderr=stderr)
  passed=_classify(row['id'],observed)and outputs
  need((row['status']=='passed')==passed,'native.case_verdict')
  if not passed:need(index==len(value['cases'])-1,'native.after_failure')
 need(value['allChildrenReaped']==all(row['reaped']for row in value['cases']),'native.reap_join')
 success=(len(value['cases'])==len(CASE_IDS)and all(row['status']=='passed'for row in value['cases'])and
          value['importsPassed']is True and value['allChildrenReaped']is True and value['reason']is None and
          value['elapsedMilliseconds']<=MAX_SECONDS*1000)
 need((value['status']=='passed')==success,'native.result_verdict')
 if value['producer']=='not_issued':need(not success and not value['cases'],'native.producer_unissued')
 if success:need(value['producer']=='native_linux'or(allow_synthetic is True and value['producer']=='synthetic_injected'),
                 'native.synthetic_producer')
 if not allow_failure:need(success,'native.cases_failed')
 need(len(canonical(value))<=MAX_FRAME,'native.frame_cap')
 return value


class NativeIO:
 """Explicit future nonroot worker adapter. Never instantiated by local tests."""
 def __init__(self,key,job):
  need(key is _NATIVE_KEY,'native.unissued')
  self.job=job;self.outer_timeout_type=sys.modules['ci_worker_core'].WorkerTimeout
  self._identity={'pid':os.getpid(),'contextSha256':sha(job.raw)}
  self.children={}
 @classmethod
 def for_checked_worker(cls,job,files):
  need(sys.platform=='linux' and os.uname().machine=='x86_64'and
       str(Path(__file__).resolve())=='/code/native_cases.py','native.worker_path')
  core=sys.modules.get('ci_worker_core')
  need(core is not None and type(job)is core.Worker and job.ready_used is True and job.used is True and
       getattr(getattr(files,'base',None),'released',False)is True,'native.positive_gate')
  own=job.process.snapshot()
  need(own==job.own and own=={'pid':os.getpid(),'uid':os.getuid(),'euid':os.geteuid(),
       'gid':os.getgid(),'egid':os.getegid(),'groups':os.getgroups()}and
       61184<=own['uid']<=65519 and own['uid']==own['euid']and own['gid']==own['egid']and own['groups']==[],
       'native.worker_identity')
  need(type(job.timer)is core.NativeTimer,'native.timer_source')
  result=cls(_NATIVE_KEY,job)
  try:
   for name in ('native_cases.py','ci_fixture.py'):
    row=job.context['consumerCode'][name];raw=result._file('/code/'+name,131072,0o444)
    need(len(raw)==row['bytes']and sha(raw)==row['sha256'],'native.code_pin')
   need(sha(result._file('/code/static-entry',262144,0o555))==job.context['entrySha256'],'native.entry_pin')
  except FileNotFoundError:raise Refusal('native.file_missing')from None
  except PermissionError:raise Refusal('native.file_permission')from None
  except OSError:raise Refusal('native.file_io')from None
  return result
 def identity(self):return dict(self._identity)
 def monotonic(self):return time.monotonic()
 def _file(self,path,cap,mode):
  p=Path(path);need(str(p.resolve())==path,'native.file_path');before=p.lstat()
  need(stat.S_ISREG(before.st_mode)and before.st_uid==before.st_gid==0 and before.st_nlink==1 and
       stat.S_IMODE(before.st_mode)==mode and 0<=before.st_size<=cap,'native.file_identity')
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  try:
   opened=os.fstat(fd);data=bytearray()
   while len(data)<=cap:
    raw=os.read(fd,min(65536,cap+1-len(data)))
    if not raw:break
    data.extend(raw)
   after=os.fstat(fd)
  finally:os.close(fd)
  identity=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  need(identity(before)==identity(opened)==identity(after)==identity(p.lstat())and len(data)==before.st_size,'native.file_changed')
  return bytes(data)
 def import_sources(self):
  try:return {name:self._file('/code/'+name,131072,0o444)for name in IMPORT_PINS}
  except FileNotFoundError:raise Refusal('native.file_missing')from None
  except PermissionError:raise Refusal('native.file_permission')from None
  except OSError:raise Refusal('native.file_io')from None
 def _child(self,case,control):
  if case=='readonly-code':
   try:
    fd=os.open('/code/ci_fixture.py',os.O_WRONLY|os.O_NOFOLLOW|os.O_CLOEXEC);os.close(fd)
    return {'outcome':'write_allowed','errno':None}
   except OSError as error:return {'outcome':'readonly_denied','errno':error.errno}
  if case=='management-paths':
   values=[]
   for path in MANAGEMENT:
    try:os.lstat(path);return {'outcome':'management_present','errno':None}
    except OSError as error:values.append(error.errno)
   return {'outcome':'unavailable','errnos':values}
  if case=='unix-socket':
   import socket
   try:
    opened=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);opened.close()
    return {'outcome':'socket_allowed','errno':None}
   except OSError as error:return {'outcome':'blocked','errno':error.errno}
  if case=='mount':
   # Linux v6.1 arch/x86/entry/syscalls/syscall_64.tbl:165=mount.
   # Every pointer is NULL: this cannot name/create any real mount even if
   # policy is unexpectedly permissive. EFAULT/other results are failures.
   import ctypes
   libc=ctypes.CDLL(None,use_errno=True);libc.syscall.restype=ctypes.c_long
   answer=libc.syscall(ctypes.c_long(165),ctypes.c_void_p(0),ctypes.c_void_p(0),ctypes.c_void_p(0),ctypes.c_ulong(0),ctypes.c_void_p(0))
   return {'outcome':'blocked'if answer==-1 else'mount_allowed','errno':ctypes.get_errno()if answer==-1 else None}
  if case in('entry-bad-argv','entry-bad-env'):
   name=self.job.context['identityName']
   args=['/code/static-entry']if case=='entry-bad-argv'else['/code/static-entry',name]
   env={'PATH':'/usr/bin','LANG':'C','LC_ALL':'C','HOME':'/','SHELL':'/nonexistent','USER':name,'LOGNAME':name}
   if case=='entry-bad-env':env['OCV_UNEXPECTED']='1'
   os.execve('/code/static-entry',args,env)
   return {'outcome':'exec_returned','errno':None}
  timer=type(self.job.timer)()
  def late():os.write(1,TIMER_OUTPUT);time.sleep(.2);return 0
  try:
   answer=timer.call(.03,late)
   return {'outcome':'timer_returned','errno':None}
  except self.outer_timeout_type:return {'outcome':'timer_timeout','errno':None}
 def run_child(self,case,timeout):
  need(case in CASE_IDS and timeout==3,'native.child_role')
  fds=set();pipes={};pid=None;reaped=False;status=None;selector=None;complete=True;timed=False;detail='boundary_refused'
  views={'control':bytearray(),'stdout':bytearray(),'stderr':bytearray()};eof=set();outer_error=None
  errors=empty_errors();phase='fork'
  def note(error,where,cleanup=False):
   nonlocal complete,outer_error
   complete=False;row=error_record(where,error)
   if errors['first']is None:errors['first']=row
   if cleanup:
    if len(errors['cleanup'])<2:errors['cleanup'].append(row)
    else:errors['omitted']=min(32,errors['omitted']+1)
   if isinstance(error,self.outer_timeout_type):outer_error=error
  def close(fd,where,cleanup=False):
   if fd not in fds:return
   try:os.close(fd);fds.remove(fd)
   except BaseException as error:
    if isinstance(error,OSError)and error.errno==errno.EBADF:fds.remove(fd)
    else:note(error,where,cleanup)
  try:
   for channel in views:
    phase='pipe_'+channel
    read,write=os.pipe2(os.O_CLOEXEC);fds.update((read,write));pipes[channel]=(read,write)
   phase='fork';pid=os.fork()
   if pid==0:
    try:
     for read,write in pipes.values():os.close(read)
     os.dup2(pipes['stdout'][1],1);os.dup2(pipes['stderr'][1],2)
     os.close(pipes['stdout'][1]);os.close(pipes['stderr'][1])
     control=pipes['control'][1]
     try:value=self._child(case,control)
     except BaseException as error:
      name=re.sub('[^a-z0-9_]','',type(error).__name__.lower())[:32]
      value={'outcome':'boundary_'+name,'errno':getattr(error,'errno',None)}
     raw=canonical(value);need(len(raw)<=512,'native.child_control_cap')
     os.write(control,raw);os.close(control);os._exit(0)
    except BaseException:os._exit(124)
   # Record the exact returned child before selector/fd setup can fail.
   self.children[pid]={'pid':pid,'reaped':False}
   for channel,(read,write)in pipes.items():close(write,'close_write_'+channel)
   phase='selector_create';selector=selectors.DefaultSelector()
   for channel,(read,write) in pipes.items():
    phase='nonblocking_'+channel;os.set_blocking(read,False)
    phase='register_'+channel;selector.register(read,selectors.EVENT_READ,channel)
   phase='clock';deadline=time.monotonic()+timeout
   while not(reaped and len(eof)==3):
    phase='clock'
    if time.monotonic()>=deadline:timed=True;break
    phase='select'
    for key,_event in selector.select(.02):
     phase='read_'+key.data
     try:raw=os.read(key.fd,4096)
     except BlockingIOError:continue
     if not raw:
      eof.add(key.data);phase='unregister_'+key.data;selector.unregister(key.fd);continue
     cap=512 if key.data=='control'else 256;view=views[key.data];room=cap-len(view);view.extend(raw[:max(0,room)])
     if len(raw)>room:complete=False;detail='output_limit';break
    if not complete:break
    if not reaped:
     phase='wait_poll';answer,observed=os.waitpid(pid,os.WNOHANG)
     if answer==pid:status=observed;reaped=True;self.children[pid]['reaped']=True
   if len(eof)!=3:complete=False
  except BaseException as error:note(error,phase)
  finally:
   if pid is not None and pid>0 and not reaped:
    try:os.kill(pid,signal.SIGKILL)
    except ProcessLookupError:pass
    except BaseException as error:note(error,'cleanup_kill',True)
    try:end=time.monotonic()+1
    except BaseException as error:note(error,'cleanup_clock',True);end=None
    # Retain a bounded reap path even if the clock itself is unavailable.
    for _poll in range(101):
     try:
      answer,observed=os.waitpid(pid,os.WNOHANG)
      if answer==pid:status=observed;reaped=True;self.children[pid]['reaped']=True;break
     except BaseException as error:note(error,'cleanup_wait',True);break
     if end is None:break
     try:
      if time.monotonic()>=end:break
     except BaseException as error:note(error,'cleanup_clock',True);break
     try:time.sleep(.01)
     except BaseException as error:note(error,'cleanup_sleep',True);break
   if selector is not None:
    try:selector.close()
    except BaseException as error:note(error,'cleanup_selector',True)
   roles={fd:'close_'+side+'_'+channel for channel,pair in pipes.items()for side,fd in zip(('read','write'),pair)}
   for fd in tuple(fds):close(fd,roles[fd],True)
   if reaped and pid in self.children:self.children.pop(pid)
  if outer_error is not None:raise outer_error
  exit_code=os.WEXITSTATUS(status)if reaped and os.WIFEXITED(status)else None
  term_signal=os.WTERMSIG(status)if reaped and os.WIFSIGNALED(status)else None
  code=None
  try:
   if views['control']:
    def pairs(rows):
     out={}
     for key,value in rows:need(key not in out,'native.control_duplicate');out[key]=value
     return out
    code=json.loads(bytes(views['control']),object_pairs_hook=pairs)
  except BaseException as error:note(error,'control_decode')
  error_number=None
  if case in('entry-bad-argv','entry-bad-env')and not views['control']:detail='exec_refused'
  elif term_signal==int(signal.SIGSYS)and not views['control']:detail='sigsys'
  elif type(code)is dict and set(code)=={'outcome','errno'}:
   detail=code['outcome'];error_number=code['errno']
  elif type(code)is dict and set(code)=={'outcome','errnos'}and code['outcome']=='unavailable'and type(code['errnos'])is list:
   detail='unavailable:'+','.join(str(x)for x in code['errnos'])
  else:complete=False
  if fds or self.children:complete=False
  if outer_error is not None:raise outer_error
  return {'exitCode':exit_code,'signal':term_signal,'errno':error_number,'timedOut':timed,'reaped':reaped,
          'outputComplete':complete,'stdout':bytes(views['stdout']),'stderr':bytes(views['stderr']),'detail':detail,'errors':errors}


if __name__=='__main__':raise SystemExit('inert_requires_checked_nonroot_worker')
