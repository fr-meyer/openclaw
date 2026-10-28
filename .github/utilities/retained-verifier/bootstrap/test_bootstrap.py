"""Source/file/process-fact tests only. No native capability is ever issued."""
import base64,copy,datetime as dt,hashlib,importlib.util,io,json,os,sys,tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import guard,issuer,native_io,guest_boot,worker_entry,result_frame,serial_io

B=Path(__file__).resolve().parent
R=B.parents[1]
ASSEMBLY=B.parent
N=ASSEMBLY/'native' if (ASSEMBLY/'native').is_dir() else R/'native-ci-adapter-r3'
RT=ASSEMBLY/'runtime'
CONSUMER=ASSEMBLY/'consumer'
STATIC=N/'static_entry.c' if (N/'static_entry.c').is_file() else R.parent/'public-source-preparation-r1/export/static_entry.c'
for path in (N,RT,CONSUMER):sys.path.insert(0,str(path))
import ci_native_port,ci_metadata,ci_worker,ci_entry,ci_profile,ci_fixture,runtime_prepare
import consumer_compat
import native_cases
import test_native_cases as native_case_fixtures
import test_ci_adapter as old_fixtures
spec=importlib.util.spec_from_file_location('public_elf_fixture',RT/'test_runtime_prepare.py')
elf_fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(elf_fixture)


class FakeIO:
 def __init__(self):
  self.files={};self.modes={};self.owners={};self.calls=[];self.own=None;self.commands=object();self.shutdown_intent=False
  self.seconds=0;self.started=0;self.claimed=False;self.sent=[];self.session='a'*32;self.boot='aaaabbbb-1234-5678-9abc-123456789abc'
  self.values={'platform':'linux','machine':'x86_64','euid':0,'egid':0,'pid':99,'kernelVersion':'6.1-ci-fixture',
    'rootFreeBytes':3*1024**3,'availableMemoryBytes':4*1024**3,'swapTotalBytes':0}
 def put(self,path,raw,mode=0o444):self.files[path]=raw;self.modes[path]=mode;return {'bytes':len(raw),'sha256':guard.sha(raw)}
 def file(self,path,cap):
  raw=self.files[path];guard.need(len(raw)<=cap,'fake.cap')
  return {'raw':raw,'uid':self.owners.get(path,0),'gid':0,'mode':self.modes[path],'regular':True,'canonicalPath':path}
 def read(self,path,cap):
  self.calls.append(('read',path,cap))
  proc={'/proc/cmdline':self.cmdline,'/proc/1/comm':b'systemd\n','/proc/sys/kernel/random/boot_id':(self.boot+'\n').encode(),
    '/proc/net/dev':b'Inter-| Receive\n face | bytes\n lo: 0 0 0\n'}
  if path in proc:return proc[path]
  if path in self.files:return self.file(path,cap)['raw']
  if Path(path).is_file():return Path(path).read_bytes()  # Exact disposable test custody only.
  raise FileNotFoundError(path)
 def readlink(self,path):
  if path=='/proc/1/exe':return '/usr/lib/systemd/systemd'
  return path.rsplit('/',1)[-1]+':[10]'
 def facts(self):return dict(self.values)
 def utc(self):return dt.datetime(2030,1,1,tzinfo=dt.timezone.utc)+dt.timedelta(seconds=self.seconds)
 def monotonic(self):return self.seconds
 def check_source_roster(self,expected):
  actual={p[len(guard.SOURCE)+1:]for p in self.files if p.startswith(guard.SOURCE+'/')}
  guard.need(actual==set(expected),'boot.source_roster_changed')
 def own_guest_checkpoint(self,markers,build,boot):self.own=(markers,build,boot)
 def command(self,argv,timeout):
  self.calls.append(('command',argv,timeout))
  if argv[0]=='/usr/bin/gpgv':raw=self.status
  elif argv[0]=='/usr/bin/dpkg-query':
   p=self.packages[argv[-1]];raw=(p['name']+'\t'+p['version']+'\t'+p['architecture']+'\n').encode()
  elif argv==('/usr/bin/systemctl','poweroff','--no-block'):self.shutdown_intent=True;raw=b''
  else:raise AssertionError('unexpected fake command')
  return {'stdout':raw,'stderr':b'','exitCode':0,'timedOut':False,'captureComplete':True,'streamsEOF':True,'streamsClosed':True,
    'ownedChildExited':True,'ownershipRetained':False,'refusalCode':None,
    'stdoutFacts':{'bytes':len(raw),'sha256':guard.sha(raw),'truncated':False},'stderrFacts':{'bytes':0,'sha256':guard.sha(b''),'truncated':False}}
 def claim_boot(self,session):raise AssertionError('fake evidence must not issue authority')
 def emit(self,raw):self.sent.append(raw)
 def poweroff(self):self.shutdown_intent=True;self.calls.append(('poweroff',));return {'pending':True}
 def write_failure(self,session,raw):
  directory='/fake/'+session+'/failure';meta={'bytes':len(raw),'sha256':guard.sha(raw),'truncated':False,'viewBytes':len(raw),'viewSha256':guard.sha(raw)}
  self.put(directory+'/host-diagnostics.private.bin',raw,0o600);self.put(directory+'/host-diagnostics.private.json',guard.canonical(meta),0o600)
  return directory


def setup_io():
 io=FakeIO();source=[]
 for relative,path in [(f'bootstrap/{p.name}',p)for p in B.glob('*.py')if not p.name.startswith('test_')]:
  raw=path.read_bytes();io.put(guard.SOURCE+'/'+relative,raw);source.append({'path':relative,'bytes':len(raw),'sha256':guard.sha(raw),'mode':0o444})
 for p in N.glob('*.py'):
  if p.name.startswith('test_'):continue
  raw=p.read_bytes();io.put(guard.SOURCE+'/native/'+p.name,raw);source.append({'path':'native/'+p.name,'bytes':len(raw),'sha256':guard.sha(raw),'mode':0o444})
 for relative,path in [('native/CI-PROFILE.json',N/'CI-PROFILE.json'),('native/static_entry.c',STATIC),
                       ('runtime/runtime_prepare.py',RT/'runtime_prepare.py')]:
  raw=path.read_bytes();io.put(guard.SOURCE+'/'+relative,raw);source.append({'path':relative,'bytes':len(raw),'sha256':guard.sha(raw),'mode':0o444})
 for name in ('consumer_compat.py','native_cases.py','hosted_export.py','hosted_privacy.py','public-member-comparisons-v105-workboard.json'):
  raw=(CONSUMER/name).read_bytes();relative='consumer/'+name
  io.put(guard.SOURCE+'/'+relative,raw);source.append({'path':relative,'bytes':len(raw),'sha256':guard.sha(raw),'mode':0o444})
 source_raw=guard.canonical({'schema':'ocv-public-source-v1','files':source});io.put(guard.SOURCE+'/PUBLIC-SOURCE-MANIFEST.json',source_raw)
 package_names=['python3.11-minimal','libpython3.11-minimal','libpython3.11-stdlib','libc6','systemd','gpgv','dpkg','selinux-utils']
 io.packages={n:{'name':n,'version':'252.39-1~deb12u2'if n=='systemd'else'1','architecture':'amd64','debSha256':guard.sha(n.encode())}for n in package_names}
 io.put('/var/lib/dpkg/status',b'\n\n'.join(('Package: '+p['name']+'\nStatus: install ok installed\nVersion: '+p['version']+
  '\nArchitecture: '+p['architecture']).encode()for p in io.packages.values())+b'\n')
 runtimes=[];ownership=[]
 for path,pkg,raw in [('/usr/bin/python3.11','python3.11-minimal',b'public-python-fixture'),('/usr/lib/ld-linux-x86-64.so.2','libc6',b'public-loader-fixture'),
  ('/usr/lib/python3.11/encodings/__init__.py','libpython3.11-minimal',b'#public encoding fixture'),('/usr/lib/python3.11/os.py','libpython3.11-stdlib',b'#public os fixture')]:
  io.put(path,raw,0o644);relative='lib64/ld-linux-x86-64.so.2'if'ld-linux'in path else path[1:]
  runtimes.append({'path':relative,'sourcePath':path,'bytes':len(raw),'sha256':guard.sha(raw),'mode':0o555 if relative in('usr/bin/python3.11','lib64/ld-linux-x86-64.so.2') else 0o444})
  ownership.append({'path':relative,'package':pkg,'version':'1','packageFileSha256':guard.sha(raw),'symlinkChainSha256':'e'*64})
 helper=elf_fixture.elf_fixture();io.put(guard.CONTROL+'/static-entry',helper,0o555)
 csha=next(r['sha256']for r in source if r['path']=='native/static_entry.c')
 proof=guard.sha(b'public historical-fixture proof')
 runtime={'schema':'ocv-runtime-v1','architecture':'linux-amd64','files':runtimes,
  'helper':{'path':'code/static-entry','bytes':len(helper),'sha256':guard.sha(helper),'sourceSha256':csha},
  'packageOwnership':ownership,'packages':list(io.packages.values()),'sourceProofSha256':proof,'standardResolutionSha256':'e'*64,
  'runtimeBytes':sum(r['bytes']for r in runtimes),'nativeImportsVerified':False,'maintainedConsumerCompatibilityVerified':False}
 tools=[]
 rolepaths={'python':('/usr/bin/python3.11','python3.11-minimal'),'systemd':('/usr/lib/systemd/systemd','systemd'),
 'gpgv':('/usr/bin/gpgv','gpgv'),'busctl':('/usr/bin/busctl','systemd'),'systemctl':('/usr/bin/systemctl','systemd'),
 'systemd-run':('/usr/bin/systemd-run','systemd'),'selinuxenabled':('/usr/sbin/selinuxenabled','selinux-utils'),
 'dpkg-query':('/usr/bin/dpkg-query','dpkg')}
 for role,(path,pkg)in rolepaths.items():
  raw=io.files.get(path,('public-'+role).encode());io.put(path,raw,0o755);p=io.packages[pkg]
  tools.append({'role':role,'path':path,'bytes':len(raw),'sha256':guard.sha(raw),'package':pkg,'version':p['version'],'debSha256':p['debSha256']})
 packages=b'\n\n'.join(('Package: '+p['name']+'\nVersion: '+p['version']+'\nArchitecture: '+p['architecture']+'\nSHA256: '+p['debSha256']).encode()for p in io.packages.values())+b'\n'
 body=('Origin: Debian\nCodename: bookworm\nVersion: fixture\nDate: Fri, 01 Jan 2010 00:00:00 UTC\nSHA256:\n '+guard.sha(packages)+' '+str(len(packages))+' main/binary-amd64/Packages\n')
 release=('-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n'+body+'-----BEGIN PGP SIGNATURE-----\npublic-fake-signature\n-----END PGP SIGNATURE-----\n').encode()
 key=b'public fake keyring';paths={k:guard.CONTROL+'/apt-data/'+n for k,n in [('release','InRelease'),('packages','Packages'),('keyring','keyring.gpg')]}
 for k,raw in [('release',release),('packages',packages),('keyring',key)]:io.put(paths[k],raw)
 import ci_archive_policy
 fixture=ci_archive_policy.Fixture(guard.sha(release),len(release),guard.sha(packages),len(packages),'Fri, 01 Jan 2010 00:00:00 UTC','fixture',frozenset(['AB'*20]))
 io.status=('[GNUPG:] VALIDSIG '+'AB'*20+' 0 0 0 0 0 0 0 0\n').encode()
 class SmallAdmission(ci_metadata.Admission):
  def run(self):return self._run_literal_policy(fixture)
 program=SimpleNamespace(native=ci_native_port,metadata=SimpleNamespace(Admission=SmallAdmission),entry=ci_entry,
  worker=ci_worker,profile=ci_profile,fixture=ci_fixture,runtime=runtime_prepare,consumer=consumer_compat,
  native_cases=SimpleNamespace(validate_result=lambda value,**keys:native_cases.validate_result(value,allow_synthetic=True,**keys)))
 codes={name:{'bytes':len(io.files[guard.SOURCE+'/native/'+source]),'sha256':guard.sha(io.files[guard.SOURCE+'/native/'+source])}
        for name,source in [('ci_protocol.py','ci_protocol.py'),('ci_profile.py','ci_profile.py'),('ci_fixture.py','ci_fixture.py'),('ci_worker_core.py','ci_worker.py')]}
 controls={'runtime':runtime,'tools':{'schema':'ocv-tools-v1','tools':tools},'imports':{'schema':'ocv-imports-v1','codeFiles':codes},
  'apt':{'schema':'ocv-apt-v1','paths':paths,'keyringSha256':guard.sha(key),'sourceProofSha256':proof}}
 hashes={}
 for name,value in controls.items():raw=guard.canonical(value);io.put(guard.CONTROL+'/'+name+'.json',raw);hashes[name]=guard.sha(raw)
 build={'schema':'ocv-build-v1','sourceManifestSha256':guard.sha(source_raw),'runtimeManifestSha256':hashes['runtime'],
 'toolManifestSha256':hashes['tools'],'importManifestSha256':hashes['imports'],'aptMetadataManifestSha256':hashes['apt'],
 'helperSha256':guard.sha(helper),'kernelVersion':'6.1-ci-fixture','systemdVersion':'252.39-1~deb12u2','fixtureOnly':True,'candidateImage':False,
 'runIdentity':{'repository':'example/public-ci','workflowRef':'example/public-ci/.github/workflows/test.yml@refs/heads/test',
   'sourceCommit':'a'*40,'runId':'1','runAttempt':'1'}}
 raw=guard.canonical(build);io.put(guard.CONTROL+'/build.json',raw)
 io.cmdline=('console=ttyS0,115200 ocv.source='+guard.sha(source_raw)+' ocv.build='+guard.sha(raw)+' ocv.session='+io.session).encode()
 return io,program


class Verification(unittest.TestCase):
 def setUp(self):self.io,self.program=setup_io()
 def prepared(self):
  plan=guard.verify(self.io);return plan,issuer.prepare(plan,self.io,self.program)
 def test_actual_source_runtime_metadata_package_elf_checks_form_non_authority_plan(self):
  plan,prepared=self.prepared();self.assertFalse(plan.native_authority)
  self.assertEqual(prepared['metadataProof']['nativeAuthenticationIssued'],False)
  self.assertTrue(any(x[0]=='command'and x[1][0]=='/usr/bin/gpgv'for x in self.io.calls))
  with self.assertRaisesRegex(guard.Refusal,'boot.native_issuer_required'):issuer.issue_native(plan,self.io,prepared)
  self.assertFalse(self.io.claimed);self.assertIsNone(ci_native_port._ISSUED_CAPABILITY);self.assertFalse(ci_worker.ARMED)
 def test_cli_and_loader_cannot_make_fake_context_native(self):
  with self.assertRaises(RuntimeError):guest_boot.main()
  with self.assertRaises(worker_entry.Refusal):worker_entry.main()
  with self.assertRaises(guard.Refusal):issuer.load_program(guard.verify(self.io),self.io)
  with self.assertRaises(guard.Refusal):native_io.NativeEvidenceIO(B/'guest_boot.py')
 def test_native_worker_identity_refusal_emits_only_bounded_facts(self):
  stream=io.StringIO()
  with patch.object(worker_entry.os,'getuid',return_value=62000),patch.object(worker_entry.os,'geteuid',return_value=62000),\
       patch.object(worker_entry.os,'getgid',return_value=62000),patch.object(worker_entry.os,'getegid',return_value=62000),\
       patch.object(worker_entry.os,'getgroups',return_value=[62000,62001]),patch.object(worker_entry.sys,'stderr',stream):
   with self.assertRaisesRegex(worker_entry.Refusal,'worker_boot.native_unit_required'):
    worker_entry.NativeWorkerFiles()
  output=stream.getvalue();self.assertLess(len(output),512)
  self.assertTrue(output.startswith('OCV_WORKER_IDENTITY_V1:'))
  fact=json.loads(output.split(':',1)[1]);self.assertEqual(fact['checks']['onlyPrimaryGroup'],False)
  self.assertEqual(fact['groupsHead'],[62000,62001]);self.assertEqual(fact['groupCount'],2)
  self.assertNotIn('report',output);self.assertNotIn('secret',output)
 def test_source_mode_owner_hash_and_extra_file_refuse(self):
  for kind in('mode','owner','hash','extra'):
   with self.subTest(kind=kind):
    io,_=setup_io();path=guard.SOURCE+'/native/ci_worker.py'
    if kind=='mode':io.modes[path]=0o644
    if kind=='owner':io.owners[path]=1
    if kind=='hash':io.files[path]+=b'changed'
    if kind=='extra':io.put(guard.SOURCE+'/native/ambient.py',b'not allowed')
    with self.assertRaises(guard.Refusal):guard.verify(io)
 def test_marker_duplicate_missing_build_and_wrong_boot_target_refuse(self):
  for kind in('duplicate','missing','build','uid','resource'):
   with self.subTest(kind=kind):
    io,_=setup_io()
    if kind=='duplicate':io.cmdline+=b' ocv.session='+io.session.encode()
    if kind=='missing':io.cmdline=b'console=ttyS0'
    if kind=='build':io.files[guard.CONTROL+'/build.json']+=b' '
    if kind=='uid':io.values['euid']=1000
    if kind=='resource':io.values['swapTotalBytes']=1
    with self.assertRaises(guard.Refusal):guard.verify(io)
 def test_bad_gpg_status_and_runtime_byte_changes_never_prepare_authority(self):
  io,program=self.io,self.program;io.status=b'[GNUPG:] BADSIG no\n'
  with self.assertRaises(Exception):issuer.prepare(guard.verify(io),io,program)
  io,program=setup_io();io.files['/usr/bin/python3.11']+=b'changed'
  with self.assertRaises(guard.Refusal):issuer.prepare(guard.verify(io),io,program)
 def test_export_paths_are_exact_and_actual_gpg_argv_is_retained(self):
  plan=guard.verify(self.io);admission=issuer.ExportAdmission(self.program,self.io,plan.controls['apt'],self.io);admission.run()
  self.assertEqual(admission.evidence['argv'][-1],guard.CONTROL+'/apt-data/InRelease')
  bad=copy.deepcopy(plan.controls['apt']);bad['paths']['release']='/unbound/InRelease'
  with self.assertRaises(guard.Refusal):issuer.ExportAdmission(self.program,self.io,bad,self.io)
 def test_worker_plan_hashes_are_no_cycle_and_fixed_fixture(self):
  plan,prep=self.prepared();manifest,context=issuer.plan_native_job(plan,prep,self.program,self.io.utc())
  self.assertEqual(context['privacySha256'],ci_fixture.REPORT_SHA);self.assertEqual(context['workerSha256'],guard.sha((B/'worker_entry.py').read_bytes()))
  self.assertEqual(context['runtimeManifestSha256'],guard.sha(guard.canonical(manifest['files'])))
  self.assertIn('code/ci_worker_core.py',{r['path']for r in manifest['files']})
 def test_fixture_loads_exact_public_layout_without_private_preparation_paths(self):
  import shutil
  with tempfile.TemporaryDirectory()as directory:
   root=Path(directory).resolve()
   groups={'bootstrap':list(B.glob('*.py')),'native':list(N.glob('*.py'))+[N/'CI-PROFILE.json'],
    'runtime':[RT/'runtime_prepare.py',RT/'test_runtime_prepare.py'],
    'consumer':[CONSUMER/name for name in ('consumer_compat.py','native_cases.py','test_native_cases.py',
     'hosted_export.py','hosted_privacy.py','public-member-comparisons-v105-workboard.json')]}
   for prefix,paths in groups.items():
    (root/prefix).mkdir()
    for source in paths:shutil.copyfile(source,root/prefix/source.name)
   shutil.copyfile(STATIC,root/'native/static_entry.c')
   spec=importlib.util.spec_from_file_location('exported_bootstrap_fixture',root/'bootstrap/test_bootstrap.py')
   module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
   self.assertEqual(module.N,root/'native');self.assertEqual(module.RT,root/'runtime')
   self.assertEqual(module.CONSUMER,root/'consumer');self.assertEqual(module.STATIC,root/'native/static_entry.c')
   io,program=module.setup_io();plan=guard.verify(io);data=issuer.prepare(plan,io,program)
   self.assertFalse(plan.native_authority)
   with self.assertRaises(guard.Refusal):issuer.issue_native(plan,io,data)
 def test_installed_status_missing_duplicate_changed_or_uninstalled_refuses(self):
  for kind in ('missing','duplicate','version','uninstalled'):
   with self.subTest(kind=kind):
    io,program=setup_io();raw=io.files['/var/lib/dpkg/status']
    if kind=='missing':raw=b''
    if kind=='duplicate':raw+=b'\nPackage: systemd\nStatus: install ok installed\nVersion: 252.39-1~deb12u2\nArchitecture: amd64\n'
    if kind=='version':raw=raw.replace(b'Version: 252.39-1~deb12u2',b'Version: wrong')
    if kind=='uninstalled':raw=raw.replace(b'Status: install ok installed',b'Status: deinstall ok config-files')
    io.files['/var/lib/dpkg/status']=raw
    with self.assertRaises(guard.Refusal):issuer.prepare(guard.verify(io),io,program)


class ConsumerJoin(unittest.TestCase):
 def test_actual_seven_tinyoci_cases_are_required_and_preserved_without_native_authority(self):
  io,program=setup_io();plan=guard.verify(io);prep=issuer.prepare(plan,io,program)
  with tempfile.TemporaryDirectory()as directory:
   completed=issuer.complete_compatibility(plan,io,prep,program,str(CONSUMER),str(Path(directory).resolve()/'scratch'))
   summary=json.loads(completed.compatibility.raw)
   self.assertEqual(summary['status'],'passed');self.assertEqual(summary['testsRun'],7);self.assertEqual(summary['failures'],[])
   self.assertEqual(completed.compatibility.raw,io.compatibility_raw);self.assertFalse(summary['nativeProof'])
   with self.assertRaises(guard.Refusal):issuer.issue_native(plan,io,completed)
   with self.assertRaisesRegex(guard.Refusal,'boot.compatibility_once'):
    issuer.complete_compatibility(plan,io,prep,program,str(CONSUMER),str(Path(directory)/'again'))
   for name,value in (('status','failed'),('testsRun',6),('elapsedMilliseconds',240001),('nativeProof',True),
                      ('sourceHashes',{}),('failures',[{'case':'x','type':'Failure'}])):
    changed=copy.deepcopy(summary);changed[name]=value
    with self.subTest(name=name),self.assertRaises(guard.Refusal):issuer.compatibility_result(changed,plan)
   changed={**summary,'unknown':True}
   with self.assertRaises(guard.Refusal):issuer.compatibility_result(changed,plan)


class Integration(unittest.TestCase):
 def setUp(self):
  self.base=old_fixtures.Integration('test_default_native_entry_has_no_context_or_effect_authority');self.base.setUp()
  self.io,self.program=setup_io();self.plan=guard.verify(self.io);self.prepared=issuer.prepare(self.plan,self.io,self.program)
  scratch=tempfile.TemporaryDirectory();self.addCleanup(scratch.cleanup)
  self.prepared=issuer.complete_compatibility(self.plan,self.io,self.prepared,self.program,str(CONSUMER),str(Path(scratch.name).resolve()/'compatibility'))
  self.manifest,self.context=issuer.plan_native_job(self.plan,self.prepared,self.program,self.io.utc())
  base=self.base;io=self.io;prepared=self.prepared;program=self.program
  self.worker_plans=[]
  outer=self
  class WrappedOps:
   def __getattr__(self,name):return getattr(base.ops,name)
   def read(self,path,cap):
    if path in prepared.aliases:
     row=prepared.aliases[path];raw=io.file(row['sourcePath'],cap)['raw']
     guard.need(len(raw)==row['bytes']and guard.sha(raw)==row['sha256'],'test.seed_changed');return raw
    if path in io.files:return io.file(path,cap)['raw']
    return base.ops.read(path,cap)
   def command(self,argv,timeout=5):
    if argv[0]=='/usr/bin/gpgv':return io.command(argv,timeout)
    if argv[0]=='/usr/bin/systemd-run':
     base.ops.calls.append(('command',argv,timeout));base.ops.unit_started=True;port=base.ops.port;ops=self
     class BootFiles:
      def file(self,path,cap):
       actual=port.root+'/root'+path
       guard.need(base.ops.modes[actual]==0o444,'test.worker_mode');return ops.read(actual,cap)
     own={'pid':base.expected['pid'],'uid':base.expected['uid'],'euid':base.expected['uid'],
      'gid':base.expected['gid'],'egid':base.expected['gid'],'groups':[base.expected['gid']]}
     process=SimpleNamespace(snapshot=lambda:dict(own))
     wp=worker_entry.verify(BootFiles(),process);outer.worker_plans.append(wp)
     class Files:
      def read_public(self,path,cap,pending=False):return ops.read(port.root+'/root'+path,cap)
      def input_released(self):
       guard.need(base.ops.modes[port.root+'/root/input']==0o555,'test.input_not_released');base.ops.events.append('input_released')
      def read_input(self,path,cap):
       guard.need('input_released'in base.ops.events,'test.early_input');base.ops.events.append('input_read')
       return ops.read(port.root+'/root'+path,cap)
     frames=[]
     timer=SimpleNamespace(call=lambda seconds,func:func())
     def after_gate(job,files):
      guard.need('input_released'in base.ops.events,'test.native_cases_before_gate')
      base.ops.events.append('native_cases')
      if getattr(outer,'force_factory_refusal',False):
       def refuse(job,files):raise native_cases.Refusal('native.worker_path')
       module=SimpleNamespace(Refusal=native_cases.Refusal,NativeIO=SimpleNamespace(for_checked_worker=refuse),
        run_cases=native_cases.run_cases,failure_summary=native_cases.failure_summary)
       return worker_entry.run_checked_native_cases(module,job,files)
      overrides={}
      if getattr(outer,'force_injected_child_failure',False):
       observation,kernel,owner=native_case_fixtures.actual_run_child_injected({
        'select':PermissionError(13,'private message never echoed'),
        'cleanup_selector':OSError(5,'private cleanup never echoed')})
       overrides['readonly-code']=observation
      outcome=native_cases.run_cases(native_case_fixtures.FakeIO(pid=own['pid'],context_sha=guard.sha(wp['contextRaw']),overrides=overrides))
      if getattr(outer,'mutate_native_summary',None):outcome=outer.mutate_native_summary(outcome)
      return outcome
     job=worker_entry.begin_with_dependencies(wp,program.worker,Files(),process,base.clock,timer,frames.append,
      after_gate=after_gate,validate_cases=lambda value,**keys:native_cases.validate_result(value,allow_synthetic=True,**keys))
     def finish(gate):
      outcome=worker_entry.finish_with_native_frame(job,gate)
      if getattr(outer,'force_timeout',False):outcome={**outcome,'timedOut':True}
      return outcome
     base.ops.worker=SimpleNamespace(finish=finish)
     base.ops.stage_file(port.root+'/evidence/worker.stderr',b''.join(frames),0o600)
     return base.ops.result()
    return base.ops.command(argv,timeout)
  self.ops=WrappedOps()
  self.port=issuer.port_successor(self.program,self.ops,self.manifest,self.context,self.plan,self.prepared,self.base.clock)
  self.base.ops.port=self.port
 def tearDown(self):self.base.tearDown()
 def run_entry(self):
  frames=[];root=self.base.root
  emitter=result_frame.Emitter(self.plan,lambda p,c:Path(p).read_bytes(),frames.append,context_raw=guard.canonical(self.context),
    compatibility_raw=self.prepared.compatibility.raw,observations=self.port.bootstrap_custody)
  entry=self.program.entry.Entry(self.port,root/'boot-custody',root/'boot-result',clock=self.base.clock,
   emit=lambda raw:emitter.emit(raw,str(root/'boot-custody')))
  return entry.run(guard.canonical(self.context)),frames,emitter
 def test_actual_bootstrap_source_port_worker_entry_probe_custody_frame_join(self):
  result,frames,emitter=self.run_entry();self.assertEqual(result['unitResult']['unitStatus'],'passed',result)
  self.assertEqual(len(self.worker_plans),1);self.assertEqual(len(frames),1)
  self.assertTrue(frames[0].startswith(b'OCV_RESULT_V1:'))
  envelope=json.loads(base64.b64decode(frames[0].split(b':',1)[1]))
  self.assertEqual(envelope['status'],'synthetic_validation');self.assertEqual(envelope['sourceManifestSha256'],self.plan.markers['ocv.source'])
  files={r['role']:r for r in envelope['custody']['files']};self.assertIn('controller-context',files)
  self.assertTrue({'host-expectation','unit-readback','consumer-compatibility','worker-stderr-raw','native-isolation-cases'}<=set(files))
  expected=json.loads(base64.b64decode(files['host-expectation']['base64']))
  unit=json.loads(base64.b64decode(files['unit-readback']['base64']))
  import ci_probe,ci_adapter
  ci_probe.validate_expected(expected)
  ci_adapter.unit_binding(unit,expected,self.context,guard.sha(guard.canonical(self.port.properties)))
  summary=json.loads(base64.b64decode(files['consumer-compatibility']['base64']))
  self.assertEqual(summary['testsRun'],7);self.assertFalse(summary['nativeProof'])
  native_summary=json.loads(base64.b64decode(files['native-isolation-cases']['base64']))
  native_cases.validate_result(native_summary,expected_pid=expected['pid'],expected_context_sha=guard.sha(guard.canonical(self.context)),allow_synthetic=True)
  self.assertEqual(native_summary['producer'],'synthetic_injected')
  with self.assertRaises(native_cases.Refusal):native_cases.validate_result(native_summary)
  raw_stderr=base64.b64decode(files['worker-stderr-raw']['base64']);normalized=base64.b64decode(files['worker-stderr']['base64'])
  self.assertEqual(len(raw_stderr.splitlines()),3);self.assertEqual(b''.join(raw_stderr.splitlines(keepends=True)[:2]),normalized)
  self.assertEqual(base64.b64decode(files['native-isolation-cases']['base64']),raw_stderr.splitlines()[2])
  self.assertLess(self.base.ops.events.index('input_released'),self.base.ops.events.index('native_cases'))
  self.assertLess(self.base.ops.events.index('native_cases'),self.base.ops.events.index('input_read'))
  raw=base64.b64decode(files['controller-context']['base64']);self.assertEqual(raw,guard.canonical(self.context))
  self.assertEqual(guard.sha(raw),files['controller-context']['sha256'])
  ready=json.loads(base64.b64decode(files['worker-stderr']['base64']).splitlines()[0])
  self.assertEqual(ready['contextSha256'],guard.sha(raw));self.assertIn('poweroff',self.port.effect_intents)
  with self.assertRaises(guard.Refusal):emitter.emit(b'{}',str(self.base.root/'boot-custody'))
 def test_changed_worker_dependency_rejected_by_actual_worker_entry_before_input(self):
  row=self.prepared.imports['ci_worker_core.py'];self.prepared.imports['ci_worker_core.py']={**row,'sha256':'0'*64}
  result,frames,_=self.run_entry();self.assertEqual(result['unitResult']['status'],'refused')
  self.assertNotIn('input_read',self.base.ops.events);self.assertIn('poweroff',self.port.effect_intents)
 def test_no_fake_success_frame_can_claim_native_capability(self):
  fake=issuer.NativeCapability(object(),self.io,self.plan,self.prepared.aliases,self.prepared.tools,900)
  with self.assertRaises(guard.Refusal):fake.check()
  with self.assertRaises(guard.Refusal):result_frame.Emitter(self.plan,lambda p,c:b'',lambda b:None,capability=fake)

 def test_admission_gate_is_published_private_then_readonly(self):
  events=[];original_stage=self.base.ops.stage_file;original_chmod=self.base.ops.chmod
  def stage(path,raw,mode):
   if path.endswith('/control/admission.json'):events.append(('stage',mode))
   return original_stage(path,raw,mode)
  def chmod(path,mode):
   if path.endswith('/control/admission.json'):events.append(('publish',mode))
   return original_chmod(path,mode)
  self.base.ops.stage_file=stage;self.base.ops.chmod=chmod
  result,_,_=self.run_entry();self.assertEqual(result['unitResult']['unitStatus'],'passed')
  self.assertEqual(events,[('stage',0o600),('publish',0o444)])

 def test_native_case_failure_prevents_fixture_and_retains_third_frame(self):
  self.mutate_native_summary=lambda value:{**value,'allChildrenReaped':False}
  result,frames,_=self.run_entry()
  self.assertEqual(result['unitResult']['status'],'refused');self.assertNotIn('input_read',self.base.ops.events)
  envelope=json.loads(base64.b64decode(frames[0].split(b':',1)[1]))
  files={r['role']:r for r in envelope['custody']['files']}
  summary=json.loads(base64.b64decode(files['native-isolation-cases']['base64']))
  self.assertIs(summary['allChildrenReaped'],False);self.assertEqual(len(base64.b64decode(files['worker-stderr-raw']['base64']).splitlines()),3)
  self.assertIn('poweroff',self.port.effect_intents)

 def test_known_factory_failure_is_fixed_third_frame_and_no_fixture_runs(self):
  self.force_factory_refusal=True
  result,frames,_=self.run_entry();self.assertEqual(result['unitResult']['status'],'refused')
  self.assertNotIn('input_read',self.base.ops.events)
  envelope=json.loads(base64.b64decode(frames[0].split(b':',1)[1]))
  rows={r['role']:r for r in envelope['custody']['files']}
  summary=json.loads(base64.b64decode(rows['native-isolation-cases']['base64']))
  self.assertEqual(summary['reason'],'native.worker_path');self.assertEqual(summary['cases'],[])
  native_cases.validate_result(summary,expected_pid=self.base.expected['pid'],expected_context_sha=guard.sha(guard.canonical(self.context)),allow_failure=True)

 def test_actual_injected_child_error_phase_errno_survive_worker_port_raw_custody(self):
  self.force_injected_child_failure=True
  result,frames,_=self.run_entry();self.assertEqual(result['unitResult']['status'],'refused')
  self.assertNotIn('input_read',self.base.ops.events)
  envelope=json.loads(base64.b64decode(frames[0].split(b':',1)[1]))
  rows={r['role']:r for r in envelope['custody']['files']}
  raw=base64.b64decode(rows['native-isolation-cases']['base64']);summary=json.loads(raw)
  errors=summary['cases'][0]['errors']
  self.assertEqual(errors['first'],{'phase':'select','type':'PermissionError','errno':13})
  self.assertIn({'phase':'cleanup_selector','type':'OSError','errno':5},errors['cleanup'])
  self.assertNotIn(b'private message',raw);self.assertNotIn(b'private cleanup',raw)
  self.assertEqual(base64.b64decode(rows['worker-stderr-raw']['base64']).splitlines()[2],raw)
  native_cases.validate_result(summary,expected_pid=self.base.expected['pid'],expected_context_sha=guard.sha(guard.canonical(self.context)),
   allow_failure=True,allow_synthetic=True)

 def test_missing_new_consumer_row_refuses_before_native_cases_and_fixture(self):
  del self.context['consumerCode']['hosted_privacy.py']
  result,_,_=self.run_entry();self.assertEqual(result['unitResult']['status'],'refused')
  self.assertNotIn('native_cases',self.base.ops.events);self.assertNotIn('input_read',self.base.ops.events)

 def test_complete_proof_with_timeout_is_refused_and_raw_three_frames_retained(self):
  self.force_timeout=True
  result,frames,_=self.run_entry();self.assertEqual(result['unitResult']['status'],'refused')
  self.assertEqual(result['unitResult']['reason'],'consumer_exit')
  envelope=json.loads(base64.b64decode(frames[0].split(b':',1)[1]))
  files={r['role']:r for r in envelope['custody']['files']}
  self.assertEqual(len(base64.b64decode(files['worker-stderr-raw']['base64']).splitlines()),3)

 def test_raw_bridge_missing_duplicate_noncanonical_or_changed_pid_refuses_before_normalization(self):
  result,_,_=self.run_entry();self.assertEqual(result['unitResult']['unitStatus'],'passed')
  original=self.port.bootstrap_custody['worker-stderr-raw'];lines=original.splitlines(keepends=True)
  changed=json.loads(lines[2]);changed['pid']+=1
  examples=[b''.join(lines[:2]),original+lines[2],b''.join(lines[:2])+b' '+lines[2],
   b''.join(lines[:2])+guard.canonical(changed)+b'\n',b''.join(lines[:2])+b'{"schema":"a","schema":"b"}\n']
  for raw in examples:
   with self.subTest(rawBytes=len(raw)):
    port=issuer.port_successor(self.program,self.ops,self.manifest,self.context,self.plan,self.prepared,self.base.clock)
    port.outputs={'stdout':b'{}','stderr':raw,'returncode':0,'timedOut':False};port.observed_pid=self.base.expected['pid']
    with self.assertRaises(ci_native_port.Refusal):port.collect_owned_outputs()
    self.assertEqual(port.bootstrap_custody['worker-stderr-raw'],raw)
    # The only later recovery is failed raw custody; no accepted two-frame proof.
    self.assertEqual(port.collect_owned_outputs()['stderr'],raw)

 def test_oversized_raw_stderr_keeps_bounded_view_full_source_count_and_hash(self):
  raw=b'first-error-'+b'x'*10000+b'-last-error'
  port=issuer.port_successor(self.program,self.ops,self.manifest,self.context,self.plan,self.prepared,self.base.clock)
  port.outputs={'stdout':b'{}','stderr':raw,'returncode':0,'timedOut':False}
  with self.assertRaises(ci_native_port.Refusal):port.collect_owned_outputs()
  def missing(path,cap):raise FileNotFoundError(path)
  custody=result_frame.custody_files('/synthetic-empty',missing,observations=port.bootstrap_custody)
  row=next(r for r in custody['files']if r['role']=='worker-stderr-raw')
  self.assertEqual(row['bytes'],8192);self.assertTrue(row['truncated']);self.assertEqual(row['sourceBytes'],len(raw))
  self.assertEqual(row['sourceSha256'],guard.sha(raw));view=base64.b64decode(row['base64'])
  self.assertTrue(view.startswith(b'first-error-'));self.assertTrue(view.endswith(b'-last-error'))


class SerialTests(unittest.TestCase):
 class Device:
  def __init__(self,fault=None):self.claimed=False;self.fault=fault;self.now_value=0;self.data=bytearray();self.closed=False;self.opened=0;self.once=False
  def identity(self):return {'char':True,'uid':0,'rdev':os.makedev(4,63 if self.fault=='identity' else 64),'canonical':True}
  def open(self):self.opened+=1;return 7
  def same(self,fd,identity):return True
  def now(self):return self.now_value
  def write(self,fd,view):
   if self.fault=='timeout':raise BlockingIOError()
   if self.fault=='write':raise OSError(5,'unpublished serial detail')
   if not self.once:self.once=True;raise BlockingIOError()
   size=min(3,len(view));self.data.extend(view[:size]);return size
  def writable(self,fd,seconds):self.now_value+=seconds
  def close(self,fd):self.closed=True
 def test_partial_nonblocking_serial_writes_complete_once_and_close(self):
  ops=self.Device();raw=b'OCV_RESULT_V1:public\n';proof=serial_io.emit_once(ops,raw)
  self.assertEqual(bytes(ops.data),raw);self.assertTrue(proof['complete']);self.assertTrue(ops.closed)
  with self.assertRaises(guard.Refusal):serial_io.emit_once(ops,raw)
  self.assertEqual(ops.opened,1)
 def test_wrong_device_and_write_deadline_refuse_without_replay(self):
  for fault in('identity','write','timeout'):
   with self.subTest(fault=fault):
    ops=self.Device(fault)
    with self.assertRaises(guard.Refusal):serial_io.emit_once(ops,b'fixed')
    if fault=='identity':self.assertEqual(ops.opened,0)
    else:self.assertTrue(ops.closed)
    with self.assertRaises(guard.Refusal):serial_io.emit_once(ops,b'fixed')

 def test_serial_limit_is_clamped_to_remaining_whole_wrapper_budget(self):
  ops=self.Device('timeout');ops.deadline=.02
  with self.assertRaises(guard.Refusal):serial_io.emit_once(ops,b'fixed')
  self.assertLessEqual(ops.now_value,.02);self.assertTrue(ops.closed);self.assertEqual(ops.opened,1)


class FailureTests(unittest.TestCase):
 def test_early_owned_failure_emits_raw_bounded_reason_and_shutdown_without_cap(self):
  io,program=setup_io();plan=guard.verify(io)
  guest_boot.handle_failure(io,plan,guard.Refusal('boot.runtime_changed'),guard,issuer,result_frame)
  self.assertEqual(len(io.sent),1);self.assertTrue(io.shutdown_intent)
  value=json.loads(base64.b64decode(io.sent[0].split(b':',1)[1]))
  self.assertEqual(value['status'],'refused');self.assertEqual(value['adapterResult']['reason'],'boot.runtime_changed')
  row=value['custody']['files'][0];self.assertIn(b'boot.runtime_changed',base64.b64decode(row['base64']))
 def test_unowned_or_duplicate_claim_failure_never_stops_another_owner(self):
  import io as stream
  io,_=setup_io()
  with patch.object(sys,'stderr',stream.StringIO()):guest_boot.handle_failure(io,None,guard.Refusal('boot.marker_missing'),guard,issuer,result_frame)
  self.assertFalse(io.shutdown_intent);self.assertEqual(io.sent,[])
  plan=guard.verify(io)
  with patch.object(sys,'stderr',stream.StringIO()):guest_boot.handle_failure(io,plan,guard.Refusal('boot.claim_exists'),guard,issuer,result_frame)
  self.assertFalse(io.shutdown_intent);self.assertEqual(io.sent,[])


class NativeSourceBoundaryTests(unittest.TestCase):
 def test_pending_outer_exit_success_still_requires_every_complete_custody_role(self):
  result={'status':'unit_passed_pending_outer_exit','unitStatus':'passed'}
  rows=[{'role':role,'truncated':False}for role in result_frame.EXTRA_CAPS]
  result_frame.require_success_roles(result,{'files':rows})
  with self.assertRaises(guard.Refusal):result_frame.require_success_roles(result,{'files':rows[:-1]})
  changed=copy.deepcopy(rows);changed[0]['truncated']=True
  with self.assertRaises(guard.Refusal):result_frame.require_success_roles(result,{'files':changed})
  result_frame.require_success_roles({'status':'refused'},{'files':[]})
 def test_actual_fixed_cleanup_boot_read_survives_expired_ordinary_read_budget(self):
  class SyntheticRead(native_io.NativeEvidenceIO):
   def __init__(self):self.started=0
  io=SyntheticRead();boot=b'aaaabbbb-1234-5678-9abc-123456789abc\n'
  with patch.object(native_io.os,'open',return_value=8),patch.object(native_io.os,'close'),\
    patch.object(native_io.time,'monotonic',return_value=2001),patch.object(native_io.os,'read',side_effect=[boot,b'']):
   with self.assertRaisesRegex(guard.Refusal,'boot.wrapper_deadline'):io.read('/fixed-synthetic',128)
   self.assertEqual(io.current_boot(cleanup=True),boot.decode().strip())
 def test_actual_wrapper_installs_exact_remaining_alarm_and_restores_with_injected_timer(self):
  class SyntheticClock(native_io.NativeEvidenceIO):
   def __init__(self):self.started=0
   def monotonic(self):return 12
  io=SyntheticClock();events=[]
  with patch.object(native_io.signal,'getitimer',return_value=(0.0,0.0)),patch.object(native_io.signal,'getsignal',return_value='previous'),\
    patch.object(native_io.signal,'signal',side_effect=lambda *a:events.append(('handler',a))),\
    patch.object(native_io.signal,'setitimer',side_effect=lambda *a:events.append(('timer',a))):
   with io.wrapper_limit():events.append(('body',))
  self.assertEqual([e[1][1] for e in events if e[0]=='timer'],[1988,0])
  self.assertEqual(events[-1][1][1],'previous')
