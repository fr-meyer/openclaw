"""Source-owned GitHub-hosted Ubuntu role and one-owned-command context.

No native call occurs on import/main. Pure fact validation never issues a
permit. The actual factory reads only selected public role/source facts and
fixed Git metadata; no token or broad environment is read or forwarded.
These runner variables are an execution-context check, not cryptographic
protection against a compromised runner/kernel or trusted source owner.
"""
from dataclasses import dataclass
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import re
import selectors
import signal
import stat
import subprocess
import sys
import time

ARMED=False
REPOSITORY='fr-meyer/openclaw'
REF='refs/heads/retained-verifier-prerequisites'
WORKFLOW_PATH='.github/workflows/authorized-beta-focused-validation.yml'
WORKFLOW_REF=REPOSITORY+'/'+WORKFLOW_PATH+'@'+REF
OUTER_SHA='78912c5d52f5a186fa3078b6768f7412356fd9d981c57f409e43dd037e8b9be6'
EXPECTED_KEYS={'expected_source','expected_tree','workflow_sha','source_manifest_sha','source_manifest_path','run_id'}
ENV={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','HOME':'/nonexistent'}
ROLE_MAP={
 'git_read':('host/command_factories.py','git_read'),
 'ubuntu_apt_update':('host/command_factories.py','ubuntu_apt_update'),
 'ubuntu_apt_install':('host/command_factories.py','ubuntu_apt_install'),
 'debian_metadata_curl':('host/command_factories.py','debian_metadata_curl'),
 'gpgv_metadata':('host/command_factories.py','gpgv_metadata'),
 'dpkg_query':('host/command_factories.py','dpkg_query'),
 'own_project_chown':('host/command_factories.py','own_project_chown'),
 'own_mkosi_outputs':('host/command_factories.py','own_mkosi_outputs'),
 'freeze_public_outputs':('host/command_factories.py','freeze_public_outputs'),
 'python_tests':('host/command_factories.py','python_tests'),
 'mkosi_build':('build/build_recipe.py','mkosi_argv'),
 'partition_read':('build/build_recipe.py','partition_argv'),
 'qemu_once':('build/build_recipe.py','qemu_argv')}
PROGRAMS={'/usr/bin/git','/usr/bin/sudo','/usr/bin/mkosi','/usr/bin/curl','/usr/bin/gpgv',
 '/usr/bin/dpkg-query','/usr/bin/python3','/usr/sbin/sfdisk','/usr/bin/qemu-system-x86_64'}
_ISSUED={};_KEY=object()


class Refusal(RuntimeError):pass

def need(ok,why):
 if not ok:raise Refusal(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(value,n=64):return type(value)is str and re.fullmatch('[0-9a-f]{'+str(n)+'}',value) is not None


def validate_role_facts(facts,expected,mission_id):
 """Pure checks return descriptive facts only; cannot mint a permit."""
 need(type(expected)is dict and set(expected)==EXPECTED_KEYS,'host.expected_schema')
 need(digest(expected['expected_source'],40) and digest(expected['expected_tree'],40)
      and digest(expected['workflow_sha']) and digest(expected['source_manifest_sha']) and digest(mission_id,32)
      and type(expected['run_id'])is str and re.fullmatch('[1-9][0-9]{0,19}',expected['run_id']), 'host.expected_identity')
 need(type(expected['source_manifest_path'])is str and not expected['source_manifest_path'].startswith('/')
      and '..'not in Path(expected['source_manifest_path']).parts
      and re.fullmatch('[A-Za-z0-9_./-]{1,256}',expected['source_manifest_path'])
      and str(Path(expected['source_manifest_path']))==expected['source_manifest_path'],'host.manifest_path')
 need(type(facts)is dict and set(facts)=={'platform','machine','ubuntuId','ubuntuVersion','uid','gid','environment'},
      'host.fact_schema')
 need(facts['platform']=='linux' and facts['machine']=='x86_64' and facts['ubuntuId']=='ubuntu'
      and facts['ubuntuVersion']=='24.04' and type(facts['uid'])is int and facts['uid']>0
      and type(facts['gid'])is int and facts['gid']>0,'host.native_role')
 wanted={'GITHUB_ACTIONS':'true','RUNNER_OS':'Linux','RUNNER_ARCH':'X64','RUNNER_ENVIRONMENT':'github-hosted',
  'GITHUB_REPOSITORY':REPOSITORY,'GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_REF':REF,
  'GITHUB_WORKFLOW_REF':WORKFLOW_REF,'GITHUB_SHA':expected['expected_source'],
  'GITHUB_RUN_ID':expected['run_id'],'GITHUB_RUN_ATTEMPT':'1'}
 need(type(facts['environment'])is dict and facts['environment']==wanted,'host.github_role')
 return {'schema':'ocv-host-role-facts-v1','repository':REPOSITORY,'workflowRef':WORKFLOW_REF,
  'sourceCommit':expected['expected_source'],'runId':expected['run_id'],'runAttempt':'1',
  'uid':facts['uid'],'gid':facts['gid'],'missionId':mission_id,'nativePermitIssued':False}


def _read_regular(path,cap,*,uid=None):
 path=Path(path);need(path.is_absolute() and path.resolve()==path,'host.canonical_source')
 before=path.lstat();need(stat.S_ISREG(before.st_mode) and before.st_nlink==1
  and before.st_uid in(0,os.getuid() if uid is None else uid) and not before.st_mode&0o022 and before.st_size<=cap,
  'host.source_identity')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  opened=os.fstat(fd);need((opened.st_dev,opened.st_ino)==(before.st_dev,before.st_ino),'host.source_changed')
  raw=bytearray()
  for _ in range(4096):
   part=os.read(fd,min(65536,cap+1-len(raw)))
   if not part:break
   raw.extend(part);need(len(raw)<=cap,'host.source_cap')
  else:raise Refusal('host.source_read_budget')
  after=os.fstat(fd)
  need(len(raw)==before.st_size and all(getattr(before,k)==getattr(after,k) for k in
   ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')),'host.source_changed')
 finally:os.close(fd)
 return bytes(raw)


def _os_release():
 # Ubuntu's /etc/os-release may be a distribution-owned symlink.
 path=Path('/etc/os-release').resolve();need(str(path)in('/etc/os-release','/usr/lib/os-release'),'host.os_release_path')
 raw=_read_regular(path,8192,uid=0);fields={}
 for row in raw.decode('ascii').splitlines():
  if not row or row.startswith('#'):continue
  need('='in row,'host.os_release_shape');key,value=row.split('=',1)
  need(key not in fields,'host.os_release_duplicate')
  if value.startswith('"')and value.endswith('"'):value=value[1:-1]
  fields[key]=value
 return fields.get('ID'),fields.get('VERSION_ID')


def _actual_role(expected,mission):
 # Before even distro/source/Git reads, reject Mac and non-GHA invocation.
 need(sys.platform=='linux' and platform.machine()=='x86_64' and os.environ.get('GITHUB_ACTIONS')=='true'
      and os.environ.get('RUNNER_OS')=='Linux' and os.environ.get('RUNNER_ARCH')=='X64', 'host.native_role')
 distro,version=_os_release()
 names=('GITHUB_ACTIONS','RUNNER_OS','RUNNER_ARCH','RUNNER_ENVIRONMENT','GITHUB_REPOSITORY','GITHUB_EVENT_NAME',
        'GITHUB_REF','GITHUB_WORKFLOW_REF','GITHUB_SHA','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT')
 facts={'platform':sys.platform,'machine':platform.machine(),'ubuntuId':distro,'ubuntuVersion':version,
        'uid':os.getuid(),'gid':os.getgid(),'environment':{k:os.environ.get(k) for k in names}}
 validate_role_facts(facts,expected,mission);return facts


def _load(path,pin):
 raw=_read_regular(path,262144);need(sha(raw)==pin,'host.module_pin')
 name='_ocv_host_'+sha(raw)[:24]
 if name in sys.modules:return sys.modules[name]
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
 sys.modules[name]=module
 try:exec(compile(raw,str(path),'exec'),module.__dict__)
 except BaseException:sys.modules.pop(name,None);raise
 return module


class NativeIO:
 synthetic=False
 def selector(self):return selectors.DefaultSelector()
 def spawn(self,argv,cwd,environment):return subprocess.Popen(argv,cwd=cwd,env=environment,stdin=subprocess.DEVNULL,
  stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True,start_new_session=True)
 def nonblocking(self,fd):os.set_blocking(fd,False)
 def read(self,fd,cap):return os.read(fd,cap)
 def killpg(self,pid,signal_value):return os.killpg(pid,signal_value)
 def now(self):return time.monotonic()
 def pause(self,seconds):time.sleep(seconds)


class _OwnedOps:
 """R2 native ownership semantics with only native IO made injectable."""
 def __init__(self,outer,argv,cwd,environment,io,before_spawn):
  self.outer=outer;self.argv=argv;self.cwd=cwd;self.environment=environment;self.io=io
  self.before_spawn=before_spawn;self.synthetic=io.synthetic;self.owned={};self.closed=set();self.spawn_intent=False
  self.setupCause=None
 def now(self):return self.io.now()
 def pause(self,duration):self.io.pause(duration)
 def _pre_spawn_cause(self,phase,error):
  number=getattr(error,'errno',None)
  code=str(error) if type(error)is Refusal and re.fullmatch('host\\.[A-Za-z0-9_.-]{1,75}',str(error)) else None
  self.setupCause={'phase':phase,'exceptionType':type(error).__name__ if type(error).__name__ in
                   {'OSError','BlockingIOError','PermissionError','FileExistsError','ValueError','KeyError',
                    'TypeError','RuntimeError','Refusal'} else 'other',
                   'errno':number if type(number)is int and 1<=number<=4095 else None,'reason':code}
 def spawn(self,argv,cwd,environment):
  try:
   need(not self.spawn_intent,'host.spawn_consumed')
   need(argv==self.argv and cwd==self.cwd and environment==self.environment,'host.command_scope')
   self.spawn_intent=True;self.before_spawn()
  except BaseException as error:
   self._pre_spawn_cause('before_spawn',error)
   raise
  try:selector=self.io.selector()
  except BaseException as error:
   self._pre_spawn_cause('selector_create',error);raise
  try:child=self.io.spawn(argv,cwd,environment)
  except BaseException as error:
   self._pre_spawn_cause('process_spawn',error)
   try:selector.close()
   except BaseException as close_error:
    name=type(close_error).__name__
    known={'OSError','BlockingIOError','PermissionError','ValueError','RuntimeError'}
    self.setupCause['selectorCloseExceptionType']=name if name in known else 'other'
   raise
  owned=self.outer.Owned(child,selector,child.pid);self.owned[id(owned)]=owned
  phase='stdout_fileno'
  try:
   for name in('stdout','stderr'):
    phase=name+'_fileno';stream=getattr(child,name);fd=stream.fileno()
    phase=name+'_nonblocking';self.io.nonblocking(fd)
    phase=name+'_register';selector.register(stream,1,name)
  except BaseException as error:
   number=getattr(error,'errno',None)
   known={'OSError','BlockingIOError','PermissionError','ValueError','KeyError','TypeError','RuntimeError'}
   self.setupCause={'phase':phase,'exceptionType':type(error).__name__ if type(error).__name__ in known else 'other',
                    'errno':number if type(number)is int and 1<=number<=4095 else None}
   refused=self.outer.SpawnedRefusal(owned);refused.setupCause=dict(self.setupCause)
   raise refused from None
  return owned
 def _owned(self,p):need(self.owned.get(id(p))is p and p.pgid==p.child.pid,'host.not_owned')
 def drain(self,p,duration):
  self._owned(p)
  if id(p)in self.closed:return []
  result=[]
  for key,_ in p.selector.select(max(0,duration)):
   try:raw=self.io.read(key.fileobj.fileno(),65536)
   except BlockingIOError:continue
   if raw:result.append((key.data,raw))
   else:p.eof.add(key.data);p.selector.unregister(key.fileobj)
  return result
 def eof(self,p):self._owned(p);return p.eof=={'stdout','stderr'}
 def poll(self,p):self._owned(p);return p.child.poll()
 def group_alive(self,p):
  self._owned(p)
  try:self.io.killpg(p.pgid,0);return True
  except ProcessLookupError:return False
 def signal_group(self,p,which):
  self._owned(p);need(which in('TERM','KILL'),'host.signal')
  try:self.io.killpg(p.pgid,signal.SIGTERM if which=='TERM' else signal.SIGKILL)
  except ProcessLookupError:pass
 def wait(self,p,timeout):self._owned(p);return p.child.wait(timeout=timeout)
 def close(self,p,*,settled):
  self._owned(p);need(type(settled)is bool,'host.settled_shape');errors=[]
  for close in(p.selector.close,p.child.stdout.close,p.child.stderr.close):
   try:close()
   except BaseException as error:errors.append(type(error).__name__)
  if errors:raise Refusal('host.stream_close_failed')
  self.closed.add(id(p))
  if settled:del self.owned[id(p)];self.closed.discard(id(p))
  return True


class SyntheticProcessOps(_OwnedOps):
 """Tests only: no native permit is minted and no default IO is available."""
 def __init__(self,outer,argv,cwd,environment,io):
  need(type(io)is not NativeIO and getattr(io,'synthetic',None)is True,'host.synthetic_io_required')
  super().__init__(outer,argv,cwd,environment,io,lambda:None)


class NativePermit:
 def __init__(self,key,**fields):
  need(key is _KEY,'host.permit_unissued');self.__dict__.update(fields);self.scopes={};self.consumed=set()


def _permit(value):
 need(type(value)is NativePermit and _ISSUED.get(id(value))is value,'host.permit_unissued')
 need(os.environ.get('GITHUB_RUN_ID')==value.run_id and os.environ.get('GITHUB_RUN_ATTEMPT')=='1', 'host.run_changed')
 return value


def _source_manifest(raw):
 def pairs(rows):
  out={}
  for k,v in rows:need(k not in out,'host.duplicate_json');out[k]=v
  return out
 value=json.loads(raw,object_pairs_hook=pairs)
 need(type(value)is dict and value.get('schema')=='ocv-public-source-v1' and type(value.get('files'))is list,
      'host.manifest_schema')
 need(1<=len(value['files'])<=512,'host.manifest_cap');result={}
 for row in value['files']:
  need(type(row)is dict and set(row)=={'path','bytes','sha256','mode'} and row['mode']==0o444
       and type(row['path'])is str and re.fullmatch('[A-Za-z0-9_./-]{1,256}',row['path'])
       and not row['path'].startswith('/') and '..'not in Path(row['path']).parts and row['path']not in result
       and type(row['bytes'])is int and 0<row['bytes']<=4*1024**2 and digest(row['sha256']), 'host.manifest_row')
  result[row['path']]=row
 need({'host/host_context.py','host/outer_supervision.py','host/command_factories.py','build/build_recipe.py'}<=set(result),
      'host.manifest_required')
 return result


def _bootstrap_git(outer,workspace,kind):
 table={'head':('rev-parse','HEAD'),'tree':('rev-parse','HEAD^{tree}'),
  'clean':('diff','--quiet','--exit-code','--','.github/utilities/retained-verifier',WORKFLOW_PATH)}
 need(kind in table,'host.git_kind')
 argv=('/usr/bin/git','--no-optional-locks','-c','core.fsmonitor=false','-c','core.hooksPath=/dev/null','-C',workspace)+table[kind]
 ops=_OwnedOps(outer,argv,workspace,dict(ENV),NativeIO(),lambda:None)
 result=_supervise_owned(ops,argv,cwd=workspace,environment=dict(ENV),deadline=ops.now()+15)
 need(result['status']=='outer_exit_passed' and not result['synthetic'],'host.git_observation')
 need(len(result['stdout'])<=256000 and len(result['stderr'])<=8192,'host.git_output_cap')
 return result['stdout']


def _public_project_root():
 # APT's _apt user needs traversable ancestors. RUNNER_TEMP may be private;
 # this fresh public/synthetic project uses the canonical sticky host temp root.
 root=Path('/tmp');info=root.lstat()
 need(root.resolve()==root and stat.S_ISDIR(info.st_mode) and info.st_uid==0
      and stat.S_IMODE(info.st_mode)==0o1777,'host.public_project_root')
 return root


def make_native_permit(source_root,expected_source,mission_id):
 facts=_actual_role(expected_source,mission_id)
 workspace=Path(os.environ.get('GITHUB_WORKSPACE',''));temp=Path(os.environ.get('RUNNER_TEMP',''))
 source=Path(source_root)
 for path in(workspace,temp,source):
  need(path.is_absolute() and path.resolve()==path and path.is_dir(),'host.directory')
 need(source.is_relative_to(workspace/'.github/utilities/retained-verifier'),'host.source_root')
 info=source.stat();need(info.st_uid==facts['uid'] and not info.st_mode&0o022,'host.source_root_owner')
 raw=_read_regular(source/expected_source['source_manifest_path'],1048576)
 need(sha(raw)==expected_source['source_manifest_sha'],'host.manifest_hash');rows=_source_manifest(raw)
 for name,row in rows.items():
  data=_read_regular(source/name,4*1024**2)
  need(len(data)==row['bytes'] and sha(data)==row['sha256'],'host.source_hash')
 need((source/'host/host_context.py').resolve()==Path(__file__).resolve(),'host.self_source')
 outer_path=source/'host/outer_supervision.py';need(rows['host/outer_supervision.py']['sha256']==OUTER_SHA,'host.outer_pin')
 outer=_load(outer_path,OUTER_SHA)
 workflow=_read_regular(workspace/WORKFLOW_PATH,1048576)
 need(sha(workflow)==expected_source['workflow_sha'],'host.workflow_hash')
 need(_bootstrap_git(outer,str(workspace),'head').decode('ascii').strip()==expected_source['expected_source']
      and _bootstrap_git(outer,str(workspace),'tree').decode('ascii').strip()==expected_source['expected_tree']
      and _bootstrap_git(outer,str(workspace),'clean')==b'','host.git_source')
 permit=NativePermit(_KEY,source=source,workspace=workspace,temp=temp,project=_public_project_root()/('ocv-'+mission_id),
  expected=dict(expected_source),mission=mission_id,rows=rows,outer=outer,uid=facts['uid'],gid=facts['gid'],run_id=expected_source['run_id'])
 _ISSUED[id(permit)]=permit;return permit


def _environment(role,environment):
 expected=dict(ENV)
 if role in('ubuntu_apt_update','ubuntu_apt_install'):expected['DEBIAN_FRONTEND']='noninteractive'
 need(type(environment)is dict and environment==expected,'host.closed_environment')
 return expected


def _project(permit,project,*,allow_negative=False):
 allowed={permit.project}
 if allow_negative:allowed.add(permit.project/'negative')
 path=Path(project)
 need(type(project)is str and path in allowed and path.resolve()==path and path.is_dir(),'host.owned_project')
 info=path.stat()
 # Every byte in this disposable CI project is public/synthetic. Native APT
 # must retain its _apt sandbox: mode0755 and traversable ancestors avoid an
 # inaccessible dedicated lists/cache path and an unsandboxed-root fallback.
 # Private intents remain0700; this does not change any GCP/private BOOT mode.
 need(info.st_uid==permit.uid and stat.S_IMODE(info.st_mode)==0o755,'host.owned_project_mode')
 for parent in path.parents:
  facts=parent.stat()
  need(stat.S_ISDIR(facts.st_mode) and facts.st_mode&stat.S_IXOTH,'host.project_ancestor_traverse')
 return project


def _prepare_tree(project):
 for target in('extra','pkgmngr'):
  top=Path(project)/target
  need(top.is_dir() and top.resolve()==top,'host.chown_target')
  count=0
  for directory,dirs,files in os.walk(top,followlinks=False):
   for name in dirs+files:
    child=Path(directory)/name;count+=1
    need(count<=50000,'host.chown_tree')
    if not child.is_symlink():continue
    exact=top/'etc/systemd/system/multi-user.target.wants/ocv-ci-proof.service'
    destination=top/'etc/systemd/system/ocv-ci-proof.service'
    # Sole generated WantedBy link from build_recipe.recipe_symlinks().
    # Both literal target and resolved, existing regular destination are bound;
    # no other link or escape can reach the recursive root-owned chown.
    need(target=='extra' and child==exact and os.readlink(child)=='../ocv-ci-proof.service'
         and child.resolve()==destination and destination.resolve()==destination
         and destination.is_file() and not destination.is_symlink(),'host.chown_tree')


def _allow_negative(role,arguments):
 return role=='mkosi_build' or role=='own_project_chown' and arguments.get('phase')=='prepare'


def _prepare_chown(arguments):
 # Output stays root-owned/read-only; only prepare's two owned trees are valid.
 need(arguments.get('phase')=='prepare' and arguments.get('owner')=='0:0','host.output_owner')
 _prepare_tree(arguments['project'])


def _qemu_arguments(permit,arguments):
 need(arguments.get('session')==permit.mission and type(arguments.get('bound'))is dict
      and arguments['bound'].get('directory')==str(permit.project/'out')
      and arguments['bound'].get('sourceManifestSha256')==permit.expected['source_manifest_sha']
      and arguments['bound'].get('runIdentity')=={'repository':REPOSITORY,'workflowRef':WORKFLOW_REF,
        'sourceCommit':permit.expected['expected_source'],'runId':permit.run_id,'runAttempt':'1'},'host.qemu_arg')


def _freeze_outputs(project):
 # There is no mkosi20 OutputMode knob. Only these fresh root-owned public
 # artifacts receive exact0444, after checked build settlement, before QEMU.
 for name in('ocv-test.raw','kernel.bin','initrd.img'):
  path=Path(project)/'out'/name
  need(path.resolve()==path and not path.is_symlink(),'host.freeze_target')
  info=path.lstat()
  need(stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==0 and info.st_nlink==1
       and not info.st_mode&0o022,'host.freeze_identity')


MKOSI_STAGE_FILES={
 'apt-export.json':8*1024**2,'static-entry':1024**2,
 'runtime.json':16*1024**2,'tools.json':16*1024**2,'imports.json':16*1024**2,
 'apt.json':16*1024**2,'package-inventory.json':16*1024**2,
 'helper-proof.json':16*1024**2,'build-signature.json':16*1024**2,
 'tool-aliases.json':16*1024**2,'build-stage-result.json':16*1024**2,
 'kernel.bin':128*1024**2,'initrd.img':512*1024**2,'build.json':16*1024**2}
MKOSI_STAGE_DIRS=('apt-data','runtime')


def _normalize_mkosi_roster(project,uid,gid):
 """Undo mkosi20.2's exact output prefix for known synthetic sidecars."""
 out=Path(project)/'out';info=out.lstat()
 need(out.resolve()==out and stat.S_ISDIR(info.st_mode) and info.st_uid==uid
      and info.st_gid==gid and stat.S_IMODE(info.st_mode)==0o755,'host.mkosi_output_dir')
 rows=[]
 for name in (*MKOSI_STAGE_DIRS,*MKOSI_STAGE_FILES):
  source=out/('ocv-test-'+name);target=out/name
  need(os.path.lexists(source) and source.resolve()==source and not source.is_symlink() and
       not os.path.lexists(target),'host.mkosi_stage_path')
  fact=source.lstat()
  if name in MKOSI_STAGE_DIRS:
   need(stat.S_ISDIR(fact.st_mode) and fact.st_uid==fact.st_gid==0
        and stat.S_IMODE(fact.st_mode)==0o755,'host.mkosi_stage_directory')
  else:
   need(stat.S_ISREG(fact.st_mode) and fact.st_uid==uid and fact.st_gid==gid
        and fact.st_nlink==1 and 0<fact.st_size<=MKOSI_STAGE_FILES[name]
        and not fact.st_mode&0o022,'host.mkosi_stage_file')
  rows.append((source,target,(fact.st_dev,fact.st_ino,fact.st_mode,
                              fact.st_uid,fact.st_gid,fact.st_size)))
 for source,target,identity in rows:
  os.rename(source,target)
  fact=target.lstat()
  need(not os.path.lexists(source) and
       (fact.st_dev,fact.st_ino,fact.st_mode,fact.st_uid,fact.st_gid,fact.st_size)==identity,
       'host.mkosi_stage_changed')


def normalize_mkosi_outputs(permit,project):
 permit=_permit(permit)
 _project(permit,project)
 _normalize_mkosi_roster(project,permit.uid,permit.gid)


def _preflight_mkosi_outputs(permit,arguments):
 need(set(arguments)=={'project','uid','gid'} and arguments['uid']==permit.uid
      and arguments['gid']==permit.gid,'host.mkosi_outputs_owner')
 for name,cap in (('ocv-test.raw',6*1024**3),('kernel.bin',128*1024**2),
                  ('initrd.img',512*1024**2)):
  path=Path(arguments['project'])/'out'/name
  need(path.resolve()==path and not path.is_symlink(),'host.mkosi_outputs_path')
  info=path.lstat()
  need(stat.S_ISREG(info.st_mode) and info.st_uid==permit.uid and info.st_gid==permit.gid
       and info.st_nlink==1 and 0<info.st_size<=cap and not info.st_mode&0o022,
       'host.mkosi_outputs_identity')


def _freeze_vector(project,argv):
 exact=('/usr/bin/sudo','-n','--','/usr/bin/chmod','0444','--')+tuple(
  str(Path(project)/'out'/name)for name in('ocv-test.raw','kernel.bin','initrd.img'))
 need(argv==exact,'host.freeze_argv')


@dataclass(frozen=True)
class _Scope:
 permit:object
 role:str
 argv:tuple
 cwd:str
 environment_items:tuple
 key:str
 @property
 def environment(self):return dict(self.environment_items)
 @property
 def consumed(self):return self.key in self.permit.consumed


def seal_command(permit,role,arguments,*,cwd,environment):
 permit=_permit(permit);need(role in ROLE_MAP and type(arguments)is dict,'host.factory_role')
 relative,function_name=ROLE_MAP[role];row=permit.rows[relative]
 module=_load(permit.source/relative,row['sha256']);factory=getattr(module,function_name)
 environment=_environment(role,environment)
 if role in('ubuntu_apt_update','ubuntu_apt_install'):
  need(arguments.get('project')==str(permit.project),'host.apt_project')
  need(_read_regular(permit.project/'ubuntu.sources.list',8192)==module.ubuntu_sources(),'host.official_ubuntu_sources')
 if 'project'in arguments:_project(permit,arguments['project'],allow_negative=_allow_negative(role,arguments))
 if 'workspace'in arguments:need(arguments['workspace']==str(permit.workspace),'host.workspace_arg')
 if 'source_root'in arguments:need(arguments['source_root']==str(permit.source),'host.source_arg')
 if role=='own_project_chown':_prepare_chown(arguments)
 if role=='own_mkosi_outputs':_preflight_mkosi_outputs(permit,arguments)
 if role=='freeze_public_outputs':_freeze_outputs(arguments['project'])
 if role=='partition_read':need(arguments.get('image')==str(permit.project/'out/ocv-test.raw'),'host.partition_arg')
 if role=='qemu_once':_qemu_arguments(permit,arguments)
 try:argv=factory(**arguments)
 except (TypeError,ValueError) as error:raise Refusal('host.factory_arguments') from None
 need(type(argv)is tuple and argv and argv[0]in PROGRAMS and all(type(a)is str and a and '\x00'not in a for a in argv),
      'host.factory_argv')
 if role=='freeze_public_outputs':_freeze_vector(arguments['project'],argv)
 if role=='own_mkosi_outputs':
  need(argv==('/usr/bin/sudo','-n','--','/usr/bin/chown',
       '--from='+str(permit.uid)+':'+str(permit.gid),'--','0:0',
       *(str(permit.project/'out'/name) for name in
         ('ocv-test.raw','kernel.bin','initrd.img'))),'host.mkosi_outputs_argv')
 if argv[0]=='/usr/bin/sudo':need(len(argv)>4 and argv[:3]==('/usr/bin/sudo','-n','--')
  and (argv[3]in('/usr/bin/apt-get','/usr/bin/chown')
   or role=='freeze_public_outputs' and argv[3]=='/usr/bin/chmod'),'host.sudo_command')
 if role=='mkosi_build':argv=('/usr/bin/sudo','-n','--')+argv
 cwdpath=Path(cwd)
 negative_allowed=_allow_negative(role,arguments)
 need(cwdpath.resolve()==cwdpath and (cwdpath==permit.source or cwdpath==permit.project
      or role=='git_read' and cwdpath==permit.workspace
      or negative_allowed and cwdpath==permit.project/'negative'),'host.cwd')
 key=sha(canonical({'role':role,'argv':argv,'cwd':str(cwdpath),'environment':environment}))
 scope=_Scope(permit,role,argv,str(cwdpath),tuple(sorted(environment.items())),key)
 need(scope.key not in permit.scopes,'host.scope_already_sealed')
 permit.scopes[scope.key]=scope;return scope


def _intent(scope):
 permit=_permit(scope.permit);need(not scope.consumed,'host.scope_consumed');permit.consumed.add(scope.key)
 _project(permit,str(permit.project));directory=permit.project/'.host-intents'
 try:directory.mkdir(mode=0o700)
 except FileExistsError:pass
 need(directory.resolve()==directory and directory.stat().st_uid==permit.uid
      and stat.S_IMODE(directory.stat().st_mode)==0o700,'host.intent_directory')
 fd=os.open(directory/(scope.key+'.json'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  raw=canonical({'schema':'ocv-host-command-intent-v1','missionId':permit.mission,'runId':permit.run_id,
   'role':scope.role,'scopeSha256':scope.key,'sourceCommit':permit.expected['expected_source'],'automaticRetry':False})
  with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
 except BaseException:raise


class HostProcessOps(_OwnedOps):
 def __init__(self,permit,scope):
  permit=_permit(permit)
  need(type(scope)is _Scope and scope.permit is permit and permit.scopes.get(scope.key)is scope,'host.scope_unissued')
  _environment(scope.role,scope.environment)
  super().__init__(permit.outer,scope.argv,scope.cwd,scope.environment,NativeIO(),lambda:_intent(scope))


def _supervise_owned(ops,argv,*,cwd,environment,deadline,grace=10.0):
 # Keep reviewed independent cleanup unchanged. Pipe setup diagnostics are
 # owned by this successor and carried alongside the exact outer record.
 result=ops.outer.supervise(ops,argv,cwd=cwd,environment=environment,deadline=deadline,grace=grace)
 result['setupCause']=dict(ops.setupCause) if ops.setupCause is not None else None
 return result


def run_owned(permit,argv,*,cwd,environment,deadline):
 permit=_permit(permit)
 if type(argv)is _Scope:scope=argv
 else:
  candidates=[s for s in permit.scopes.values() if s.argv==argv and s.cwd==cwd and s.environment==environment]
  need(len(candidates)==1,'host.scope_unissued');scope=candidates[0]
 need(scope.cwd==cwd and scope.environment==environment and not scope.consumed,'host.scope_consumed')
 ops=HostProcessOps(permit,scope)
 return _supervise_owned(ops,scope.argv,cwd=cwd,environment=environment,deadline=deadline)


def main(_argv=None):raise Refusal('host.explicit_checked_ci_entry_required')


if __name__=='__main__':main()
