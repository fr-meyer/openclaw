"""Successor CI-only issuers. R3 ARM/global/context objects are never changed."""
from dataclasses import dataclass,replace
import datetime as dt
import importlib,sys
from pathlib import Path
from types import SimpleNamespace
from guard import Refusal,need,closed,sha,canonical,decode,file_bytes,validate_runtime,SOURCE,CONTROL,hex64
from native_io import NativeEvidenceIO

_SEAL=object()
_PREPARED_SEAL=object()
_COMPATIBILITY_SEAL=object()


@dataclass(frozen=True)
class Compatibility:
 _seal:object
 io:object
 plan:object
 raw:bytes


@dataclass(frozen=True)
class Prepared:
 _seal:object
 io:object
 plan:object
 aliases:dict
 tools:dict
 metadataProof:dict
 imports:dict
 compatibility:object=None
 def __getitem__(self,key):return getattr(self,key)


@dataclass(frozen=True)
class NativeCapability:
 seal:object
 io:object
 plan:object
 aliases:dict
 tools:dict
 expires:float
 def check(self,*,cleanup=False):
  need(self.seal is _SEAL and type(self.io)is NativeEvidenceIO and self.io.claimed,'boot.native_capability_required')
  need((cleanup or self.io.monotonic()<self.expires) and self.io.current_boot(cleanup=cleanup)==self.plan.boot_id,
       'boot.native_capability_expired_or_boot_changed')


def load_program(plan,io):
 need(type(io)is NativeEvidenceIO,'boot.native_loader_required')
 # verify() has checked every immutable code row and exact source roster.
 for directory in (SOURCE+'/native',SOURCE+'/runtime',SOURCE+'/consumer'):
  if directory not in sys.path:sys.path.insert(0,directory)
 program=SimpleNamespace(native=importlib.import_module('ci_native_port'),metadata=importlib.import_module('ci_metadata'),
   entry=importlib.import_module('ci_entry'),worker=importlib.import_module('ci_worker'),profile=importlib.import_module('ci_profile'),
   fixture=importlib.import_module('ci_fixture'),runtime=importlib.import_module('runtime_prepare'),consumer=importlib.import_module('consumer_compat'),
   native_cases=importlib.import_module('native_cases'))
 for name,directory in (('native','native/ci_native_port.py'),('metadata','native/ci_metadata.py'),('entry','native/ci_entry.py'),
   ('worker','native/ci_worker.py'),('profile','native/ci_profile.py'),('fixture','native/ci_fixture.py'),
   ('runtime','runtime/runtime_prepare.py'),('consumer','consumer/consumer_compat.py'),('native_cases','consumer/native_cases.py')):
  need(str(Path(getattr(program,name).__file__).resolve())==SOURCE+'/'+directory,'boot.ambient_module')
 return program


def compatibility_result(value,plan):
 closed(value,{'schema','status','testsRun','failures','sourceHashes','elapsedMilliseconds','fixtureOnly','nativeProof'},'boot.compatibility_schema')
 rows={r['path']:r for r in plan.source['files']}
 expected={name:rows['consumer/'+name]['sha256'] for name in
  ('hosted_export.py','hosted_privacy.py','public-member-comparisons-v105-workboard.json')}
 need(value['schema']=='ocv.consumer-compat.v1' and value['status']=='passed' and type(value['testsRun'])is int and value['testsRun']==7 and
   value['failures']==[] and value['sourceHashes']==expected and value['fixtureOnly']is True and value['nativeProof']is False and
   type(value['elapsedMilliseconds'])is int and 0<=value['elapsedMilliseconds']<=240000,'boot.consumer_compatibility_refused')
 raw=canonical(value);need(len(raw)<=12288,'boot.compatibility_cap');return raw


def complete_compatibility(plan,io,prepared,program,source_root,scratchroot):
 """Call the actual source-pinned suite; a saved verdict never enters here.

 Pure/fake data can exercise this function but cannot pass issue_native().
 """
 need(type(prepared)is Prepared and prepared._seal is _PREPARED_SEAL and prepared.io is io and prepared.plan is plan and
  prepared.compatibility is None and not getattr(io,'compatibility_started',False),'boot.compatibility_once')
 native=type(io)is NativeEvidenceIO
 need(not native or source_root==SOURCE+'/consumer','boot.compatibility_source_root')
 runner=Path(program.consumer.__file__).resolve()
 source_rows={r['path']:r for r in plan.source['files']}
 raw=file_bytes(io,SOURCE+'/consumer/consumer_compat.py',131072)
 need(sha(raw)==source_rows['consumer/consumer_compat.py']['sha256'] and
  (not native or str(runner)==SOURCE+'/consumer/consumer_compat.py'),'boot.compatibility_runner')
 io.compatibility_started=True
 try:value=program.consumer.run_suite(source_root,scratchroot)
 except (program.consumer.CompatibilityRefusal,program.consumer.CompatibilityTimeout) as error:
  detail=str(error)
  need(__import__('re').fullmatch('[a-z_]{1,80}',detail) is not None,'boot.compatibility_unknown_boundary')
  raise Refusal('boot.consumer_suite_boundary',{'subcheck':detail}) from None
 # Preserve the source-owned actual return before semantic adjudication.
 actual=canonical(value);need(len(actual)<=12288,'boot.compatibility_cap')
 io.compatibility_raw=actual
 actual=compatibility_result(value,plan)
 return replace(prepared,compatibility=Compatibility(_COMPATIBILITY_SEAL,io,plan,actual))


def verify_packages(io,plan,tools):
 # Use the fixed installed-status database; no expansion of R3's finite native
 # command whitelist is needed. Signed index binding was checked separately.
 raw=io.read('/var/lib/dpkg/status',8*1024*1024);found={};wanted={r['package'] for r in tools.values()}
 for stanza in raw.split(b'\n\n'):
  need(len(stanza)<=131072,'boot.installed_stanza_cap');fields={}
  for line in stanza.splitlines():
   if line.startswith((b' ',b'\t'))or b':'not in line:continue
   key,value=line.split(b':',1)
   if key in(b'Package',b'Version',b'Architecture',b'Status'):
    need(key not in fields,'boot.installed_duplicate');fields[key]=value.strip().decode('ascii')
  name=fields.get(b'Package')
  if name in wanted:
   need(name not in found,'boot.installed_duplicate');found[name]=fields
 for row in tools.values():
  pkg=row['package'];need(type(pkg)is str and __import__('re').fullmatch('[a-z0-9][a-z0-9+.-]{0,127}',pkg),'boot.package_name')
  actual=found.get(pkg,{})
  need(actual.get(b'Version')==row['version'] and actual.get(b'Architecture')in('amd64','all') and
    actual.get(b'Status')=='install ok installed','boot.package_version_changed')
 need(tools['systemd']['version']==plan.build['systemdVersion'],'boot.systemd_package_version')
 exe=io.readlink('/proc/1/exe');need(exe==tools['systemd']['path'],'boot.pid1_executable')


class ExportAdmission:
 def __init__(self,program,ops,apt,clock):
  closed(apt,{'schema','paths','keyringSha256','sourceProofSha256'},'boot.apt_schema')
  expected={'release':CONTROL+'/apt-data/InRelease','packages':CONTROL+'/apt-data/Packages','keyring':CONTROL+'/apt-data/keyring.gpg'}
  need(apt['schema']=='ocv-apt-v1' and apt['paths']==expected,'boot.apt_export_paths')
  virtual={'release':'/var/lib/apt/lists/ocv_InRelease','packages':'/var/lib/apt/lists/ocv_Packages',
    'keyring':'/usr/share/keyrings/debian-archive-keyring.gpg'}
  actual_argv=('/usr/bin/gpgv','--status-fd=1','--keyring',expected['keyring'],expected['release'])
  self.evidence=None;self.actual_argv=actual_argv
  class ExactCopies:
   def read(self,path,cap):
    matches=[k for k,v in virtual.items()if v==path];need(len(matches)==1,'boot.apt_alias_path')
    return ops.read(expected[matches[0]],cap)
   def command(self,argv,timeout):
    need(tuple(argv)==('/usr/bin/gpgv','--status-fd=1','--keyring',virtual['keyring'],virtual['release']),'boot.apt_alias_command')
    return ops.command(actual_argv,timeout)
  self.inner=program.metadata.Admission(ExactCopies(),virtual,apt['keyringSha256'],clock)
 def run(self):
  try:return self.inner.run()
  finally:
   if self.inner.evidence is not None:self.evidence={'argv':list(self.actual_argv),'outcome':self.inner.evidence['outcome']}


def verify_signed_package_bindings(io,plan,tools):
 runtime=plan.controls['runtime'];packages=runtime['packages'];ownership=runtime['packageOwnership']
 need(type(packages)is list and 4<=len(packages)<=512 and type(ownership)is list,'boot.package_manifest')
 by_name={}
 for row in packages:
  closed(row,{'name','version','architecture','debSha256'},'boot.package_row')
  need(row['name']not in by_name and row['architecture']in('amd64','all') and hex64(row['debSha256']),'boot.package_row')
  by_name[row['name']]=row
 files={r['path']:r for r in runtime['files']};seen=set()
 for row in ownership:
  closed(row,{'path','package','version','packageFileSha256','symlinkChainSha256'},'boot.owner_row')
  need(row['path']in files and row['path']not in seen and row['package']in by_name and
   row['version']==by_name[row['package']]['version'] and row['packageFileSha256']==files[row['path']]['sha256'] and
   hex64(row['symlinkChainSha256']),'boot.owner_changed');seen.add(row['path'])
 need(seen==set(files),'boot.owner_roster')
 for row in tools.values():
  need(row['package']in by_name and row['version']==by_name[row['package']]['version'] and
   row['debSha256']==by_name[row['package']]['debSha256'],'boot.tool_package_changed')
 raw=io.read(plan.controls['apt']['paths']['packages'],64*1024*1024)
 # Fresh ExportAdmission has already authenticated/hash-bound these exact bytes.
 wanted={(r['name'],r['version'],r['architecture']):r['debSha256'] for r in packages};matched=set()
 for stanza in raw.split(b'\n\n'):
  need(len(stanza)<=131072,'boot.index_stanza_cap');fields={}
  for line in stanza.splitlines():
   if line.startswith((b' ',b'\t'))or b':'not in line:continue
   key,value=line.split(b':',1)
   if key in(b'Package',b'Version',b'Architecture',b'SHA256'):
    need(key not in fields,'boot.index_duplicate');fields[key]=value.strip().decode('ascii')
  key=tuple(fields.get(k)for k in(b'Package',b'Version',b'Architecture'))
  if key in wanted:
   need(fields.get(b'SHA256')==wanted[key],'boot.package_index_hash');matched.add(key)
 need(matched==set(wanted),'boot.package_not_in_authenticated_index')


def prepare(plan,io,program):
 aliases,tools=validate_runtime(io,plan)
 apt=closed(plan.controls['apt'],{'schema','paths','keyringSha256','sourceProofSha256'},'boot.apt_schema')
 need(apt['schema']=='ocv-apt-v1' and apt['sourceProofSha256']==plan.controls['runtime']['sourceProofSha256'],'boot.apt_binding')
 admission=ExportAdmission(program,io,apt,io)
 proof=admission.run()  # fresh fixed gpgv process + literal BOOKWORM byte policy, not a saved verdict
 need(proof.get('status')=='classified' and proof.get('nativeAuthenticationIssued') is False,'boot.metadata_refused')
 verify_signed_package_bindings(io,plan,tools)
 verify_packages(io,plan,tools)
 helper=file_bytes(io,CONTROL+'/static-entry',8*1024*1024,readonly=False)
 elf=program.runtime.validate_static_elf(helper)
 need(elf['sha256']==plan.build['helperSha256'] and plan.controls['runtime']['helper'].get('sourceSha256')==next(r['sha256']for r in plan.source['files']if r['path']=='native/static_entry.c'),'boot.elf_binding')
 source_rows={r['path']:r for r in plan.source['files']}
 names={'ci_protocol.py':'native/ci_protocol.py','ci_profile.py':'native/ci_profile.py','ci_fixture.py':'native/ci_fixture.py',
        'ci_worker_core.py':'native/ci_worker.py','worker.py':'bootstrap/worker_entry.py'}
 for target,relative in names.items():
  row=source_rows[relative];aliases['/seed/code/'+target]={'path':'code/'+target,'sourcePath':SOURCE+'/'+relative,
    'bytes':row['bytes'],'sha256':row['sha256'],'mode':0o444}
 for name in ('native_cases.py','hosted_export.py','hosted_privacy.py','public-member-comparisons-v105-workboard.json'):
  row=source_rows['consumer/'+name]
  aliases['/seed/code/'+name]={'path':'code/'+name,'sourcePath':SOURCE+'/consumer/'+name,
    'bytes':row['bytes'],'sha256':row['sha256'],'mode':0o444}
 profile=source_rows['native/CI-PROFILE.json']
 aliases['/seed/CI-PROFILE.json']={'path':'CI-PROFILE.json','sourcePath':SOURCE+'/native/CI-PROFILE.json',
   'bytes':profile['bytes'],'sha256':profile['sha256'],'mode':0o444}
 imports=closed(plan.controls['imports'],{'schema','codeFiles'},'boot.imports_schema')
 expected={name:{'bytes':aliases['/seed/code/'+name]['bytes'],'sha256':aliases['/seed/code/'+name]['sha256']}
           for name in ('ci_protocol.py','ci_profile.py','ci_fixture.py','ci_worker_core.py')}
 need(imports=={'schema':'ocv-imports-v1','codeFiles':expected},'boot.imports_changed')
 return Prepared(_PREPARED_SEAL,io,plan,aliases,tools,proof,expected)


def issue_native(plan,io,prepared):
 # Fake I/O can validate data but can NEVER produce a native capability.
 from guard import _PLAN_SEAL
 need(type(io)is NativeEvidenceIO and io.own is not None and io.own[2]==plan.boot_id and
   plan._seal is _PLAN_SEAL and plan._verified_io is io and type(prepared)is Prepared and
   prepared._seal is _PREPARED_SEAL and prepared.io is io and prepared.plan is plan,'boot.native_issuer_required')
 evidence=prepared.compatibility
 need(type(evidence)is Compatibility and evidence._seal is _COMPATIBILITY_SEAL and evidence.io is io and evidence.plan is plan and
   compatibility_result(__import__('guard').decode(evidence.raw,12288),plan)==evidence.raw,'boot.compatibility_required')
 actual=io.facts();need(actual['platform']=='linux' and actual['euid']==actual['egid']==0 and actual['pid']==plan.facts['pid'],'boot.native_root_changed')
 io.claim_boot(plan.markers['ocv.session'])
 need(io.monotonic()<io.started+2000,'boot.wrapper_deadline')
 return NativeCapability(_SEAL,io,plan,prepared['aliases'],prepared['tools'],io.started+2000)


def successor_ops(program,cap):
 cap.check()
 class IssuedCommands(program.native.NativeCommandIO):
  def __init__(self):cap.check()
  def spawn(self,argv):
   cleanup=(argv==('/usr/bin/systemctl','poweroff','--no-block') or
    len(argv)==3 and argv[:2]==('/usr/bin/systemctl','stop') and argv[2]=='ocv-'+cap.plan.markers['ocv.session']+'.service' or
    argv[0]=='/usr/bin/busctl' and '/org/freedesktop/systemd1/unit/ocv_2d'+cap.plan.markers['ocv.session']+'_2eservice' in argv)
   cap.check(cleanup=cleanup)
   if argv==('/usr/bin/systemctl','poweroff','--no-block'):cap.io.shutdown_intent=True
   return super().spawn(argv)
 class IssuedOps(program.native.NativeOps):
  def __init__(self):
   cap.check();program.native.CommandCapture.__init__(self,IssuedCommands())
  def read(self,path,limit):
   if path in cap.aliases:
    row=cap.aliases[path];raw=file_bytes(cap.io,row['sourcePath'],limit,readonly=False)
    need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'boot.seed_alias_changed');return raw
   return super().read(path,limit)
 return IssuedOps()


def plan_native_job(plan,prepared,program,now):
 aliases=prepared['aliases'];files=[]
 for seed,row in aliases.items():
  if seed=='/seed/CI-PROFILE.json':continue
  files.append({'path':row['path'],'seedPath':seed,'bytes':row['bytes'],'sha256':row['sha256'],'mode':row['mode']})
 files.sort(key=lambda r:r['path'])
 code={'entrySha256':plan.build['helperSha256'],'workerSha256':aliases['/seed/code/worker.py']['sha256'],
       'runtimeManifestSha256':sha(canonical(files)),
       'consumerCode':{name:{'bytes':aliases['/seed/code/'+name]['bytes'],'sha256':aliases['/seed/code/'+name]['sha256']}
        for name in ('ci_fixture.py','native_cases.py','hosted_export.py','hosted_privacy.py','public-member-comparisons-v105-workboard.json')}}
 session=plan.markers['ocv.session'];profile=program.profile.DESIGN_PROFILE_SHA
 context={'schema':'openclaw.retained-verifier-context.v1','sessionId':session,'unitName':'ocv-'+session+'.service',
  'bootId':plan.boot_id,'vmId':'1','identityName':'ocv-'+session[:24],'contextNonce':sha((session+plan.boot_id).encode()),
  'workerDeadlineUtc':(now+dt.timedelta(seconds=300)).strftime('%Y-%m-%dT%H:%M:%SZ'),'maxJobSeconds':300,
  'operation':'retained-report-only','mountPropagation':'private','sourceSha':program.worker.FIXTURE_SOURCE,
  'scannerSha':program.worker.FIXTURE_SCANNER,'indexDigest':program.worker.FIXTURE_INDEX,
  'privacySha256':program.fixture.REPORT_SHA,'privacyBytes':len(program.fixture.REPORT),'profileSha256':profile,
  'inputManifestSha256':sha(canonical({'report':program.fixture.REPORT_SHA,'blob':program.fixture.BLOB_SHA})),**code}
 manifest={'files':files,'code':code,'tools':{'selinuxenabledSha256':prepared['tools']['selinuxenabled']['sha256']}}
 return manifest,context


def port_successor(program,ops,manifest,context,plan,prepared,clock):
 class SourceBoundPort(program.native.Port):
  def __init__(self,*args,**kwargs):
   super().__init__(*args,**kwargs);self.bootstrap_custody={};self.bridge_outcome=None;self.bridge_failed=False;self.observed_pid=None
  def owned_observation(self,context):
   expected,unit=super().owned_observation(context)
   # Source-derived manager/anchor facts, captured before the actual probe.
   for role,value,cap in (('host-expectation',expected,12288),('unit-readback',unit,4096)):
    raw=canonical(value);need(len(raw)<=cap,'boot.host_observation_cap')
    self.bootstrap_custody[role]=raw
   self.observed_pid=expected['pid']
   return expected,unit
  def collect_owned_outputs(self):
   if self.bridge_outcome is not None:
    return dict(self.outputs or self.bridge_outcome)
   original=super().collect_owned_outputs()
   raw=original['stderr'];self.bridge_outcome=dict(original)
   # Capture the complete bounded source stream before any line/JSON checks.
   self.bootstrap_custody['worker-stderr-raw']=raw
   try:
    need(type(raw)is bytes and len(raw)<=8192,'boot.worker_raw_stderr_cap')
    lines=raw.splitlines(keepends=True)
    need(len(lines)==3 and all(line.endswith(b'\n') and line.strip() for line in lines),'boot.worker_native_frame_count')
    third=lines[2][:-1];summary=decode(third,4096)
    need(canonical(summary)==third,'boot.worker_native_frame_canonical')
    self.bootstrap_custody['native-isolation-cases']=third
    program.native_cases.validate_result(summary,expected_pid=self.observed_pid,expected_context_sha=sha(canonical(context)))
    clean={**original,'stderr':b''.join(lines[:2])}
    self.bridge_outcome=clean
    return clean
   except BaseException:
    self.bridge_failed=True
    # The R3 controller preserves the failed result; it cannot see an accepted
    # two-frame proof unless the exact third frame was independently checked.
    raise program.native.Refusal('ci.native_case_summary_refused') from None
  def release_inputs_and_gate(self,raw):
   self.effect('gate');self.ops.chmod(self.root+'/root/input',0o555)
   target=self.root+'/root/control/admission.json'
   self.ops.stage_file(target,raw,0o600)  # Not readable during incomplete write.
   self.ops.chmod(target,0o444)          # Publish only after stage_file fsync.
   self.files.append(target)
  def stage_public_inputs(self,context):
   result=super().stage_public_inputs(context)
   raw=canonical({'schema':'ocv-worker-bootstrap-v1','contextSha256':sha(canonical(context)),
     'sourceManifestSha256':plan.markers['ocv.source'],'codeFiles':prepared['imports'],'code':manifest['code']})
   target=self.root+'/root/control/worker-bootstrap.json';self.ops.stage_file(target,raw,0o444);self.files.append(target)
   return result
 apt=plan.controls['apt'];admission=ExportAdmission(program,ops,apt,clock)
 return SourceBoundPort(ops,manifest,session_root='/var/lib/ci-verifier/'+context['sessionId'],clock=clock,metadata_admission=admission)
