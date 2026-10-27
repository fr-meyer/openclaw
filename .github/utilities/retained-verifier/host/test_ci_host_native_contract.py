"""Actual NativePort contracts on public synthetic files, never Linux proof.

No NativePermit is issued, no process runs, and no system package/tool is read.
Only sealed-command execution, three fixed public-tool reads and the three
simulated root-owned output identities are substituted. The actual controller,
metadata classifier, builder bindings, serial/source replay and artifact packer
run. The sole large fixture is a disposable sparse zero image, not an OS image.
"""
import base64
import copy
import importlib.util
import io
import json
import lzma
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import ci_host as h
import command_factories as commands
import serial_receipt as serial
import source_expectation
import artifact
from test_source_validator import setup_rows
import source_validator

HERE=Path(__file__).resolve().parent
A=HERE.parent
R=A.parent
sys.path.insert(0,str(A))
# The materializer is a preparation-only tool, never an ambient export input.
if (A/'publication.py').is_file():
 import publication
else:publication=None
APT=A/'apt-r2' if (A/'apt-r2').is_dir() else A/'apt'
sys.path.insert(0,str(APT))
sys.path.insert(0,str(A/'build'))
import archive_policy as policy
import archive_guard as apt
import guard_project
import build_recipe as build

C=h.canonical
SHA=h.sha
TOOL_BYTES={
 '/usr/share/keyrings/debian-archive-keyring.gpg':b'SYNTHETIC-PUBLIC-KEYRING-NOT-A-KEY',
 '/usr/bin/gpgv':b'SYNTHETIC-PUBLIC-GPGV-NOT-AN-EXECUTABLE',
 '/usr/lib/apt/apt-helper':b'SYNTHETIC-PUBLIC-APT-HELPER-NOT-AN-EXECUTABLE'}


def outer(stdout=b'',stderr=b'',**changes):
 value={'status':'outer_exit_passed','returncode':0,'timedOut':False,'truncated':False,
  'outerExited':True,'ownedGroupGone':True,'streamsEOF':True,'streamsClosed':True,
  'ownershipRetained':False,'stdout':stdout,'stderr':stderr,'setupCause':None,
  'spawned':True,'cleanupErrors':[],'synthetic':True}
 value.update(changes);return value


def metadata():
 names=build.REQUIRED_PACKAGES|{'linux-image-6.1.0-50-amd64'}
 data=b''
 for name in sorted(names):
  version=build.SYSTEMD_VERSION if name in ('systemd','systemd-sysv','libsystemd0','libsystemd-shared') else '1.0-1'
  data+=(f'Package: {name}\nVersion: {version}\nArchitecture: amd64\n'
         f'Filename: pool/main/{name}/{name}_fixture_amd64.deb\n'
         f'SHA256: {SHA(name.encode())}\nSize: 17\n\n').encode()
 date='Sat, 11 Jul 2026 10:16:37 UTC'
 release=('-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nOrigin: Debian\n'
  'Codename: bookworm\nVersion: synthetic-public-contract\nDate: '+date+'\nSHA256:\n '
  +SHA(data)+' '+str(len(data))+' main/binary-amd64/Packages\n'
  '-----BEGIN PGP SIGNATURE-----\nSYNTHETIC-NOT-A-SIGNATURE\n-----END PGP SIGNATURE-----\n').encode()
 primary='B8B80B5B623EAB6AD8775C45B7C5D7D6350947F8'
 fixture=policy.Fixture(SHA(release),len(release),SHA(data),len(data),date,
  'synthetic-public-contract',frozenset((primary,)))
 status=('[GNUPG:] VALIDSIG '+primary+' 2026-07-11 1 0 4 0 1 10 01\n').encode()
 return release,data,status,fixture


class SyntheticCommands:
 """Factory-shaped command seam. It cannot mint a NativePermit or execute."""
 ENV={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','HOME':'/nonexistent'}
 def __init__(self,fixture):self.fixture=fixture;self.calls=[]
 def seal_command(self,permit,role,arguments,*,cwd,environment):
  assert permit is self.fixture.permit
  if role=='mkosi_build':argv=('/usr/bin/sudo','-n','--')+build.mkosi_argv(arguments['project'])
  elif role=='qemu_once':argv=build.qemu_argv(arguments['bound'],arguments['session'])
  elif role=='partition_read':argv=build.partition_argv(arguments['image'])
  else:argv=getattr(commands,role)(**arguments)
  return SimpleNamespace(role=role,arguments=copy.deepcopy(arguments),argv=argv,cwd=cwd,environment=environment)
 def run_owned(self,permit,scope,*,cwd,environment,deadline):
  assert permit is self.fixture.permit and cwd==scope.cwd and environment==scope.environment
  self.calls.append(scope)
  return self.fixture.execute(scope)


class ContractFixture:
 def __init__(self,root):
  self.root=Path(root).resolve();self.source=self.root/'source';self.mission=setup_rows()[1]['sessionId']
  if publication is not None:
   publication.write_export(publication.default_mapping(R),self.source,{})
  else:
   # Copy only the exported public allowlist; no preparation fixture is needed.
   manifest_raw=(A/'PUBLIC-SOURCE-MANIFEST.json').read_bytes();manifest=json.loads(manifest_raw)
   self.source.mkdir(mode=0o755)
   for row in manifest['files']:
    raw=(A/row['path']).read_bytes()
    assert len(raw)==row['bytes'] and SHA(raw)==row['sha256']
    target=self.source/row['path'];target.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
    target.write_bytes(raw);target.chmod(0o444)
   (self.source/'PUBLIC-SOURCE-MANIFEST.json').write_bytes(manifest_raw)
   (self.source/'PUBLIC-SOURCE-MANIFEST.json').chmod(0o444)
  self.raw,self.rows=h.bootstrap_source(self.source,SHA((self.source/'PUBLIC-SOURCE-MANIFEST.json').read_bytes()))
  self.permit=SimpleNamespace(project=str(self.root/'project'),mission=self.mission,
   expected={'source_manifest_sha':SHA(self.raw)})
  self.commands=SyntheticCommands(self)
  self.release,self.packages,self.gpg_status,self.policy_fixture=metadata()
  self.policy=SimpleNamespace(classify=lambda *args,**kw:policy.classify(*args,fixture=self.policy_fixture,**kw))
  self.modules=SimpleNamespace(context=self.commands,commands=commands,build=build,guard_project=guard_project,
   apt=apt,policy=self.policy,serial=serial,validator=source_validator,artifact=artifact,source_expectation=source_expectation)
  self.environment={'RUNNER_TEMP':str(self.root),'GITHUB_WORKFLOW_REF':
   'fr-meyer/openclaw/.github/workflows/authorized-beta-focused-validation.yml@refs/heads/retained-verifier-prerequisites',
   'GITHUB_SHA':'c'*40,'GITHUB_RUN_ID':'123'}
  self.negative_changes={};self.qemu_mode='valid';self.qemu_calls=0;self.output_paths=set()
  self.short_stream=False;self.real_read=h.read_regular;self.real_lstat=Path.lstat
  self.gpg_exit=0;self.gpg_changes={}
 def new_port(self):
  with mock.patch.dict(os.environ,self.environment):
   self.port=h.NativePort(self.permit,self.modules,self.source,self.raw,self.rows)
  return self.port
 def tool_read(self,path,cap,*,owner=None):
  if str(path) in TOOL_BYTES:
   assert owner==0 and len(TOOL_BYTES[str(path)])<=cap
   return TOOL_BYTES[str(path)]
  return self.real_read(path,cap,owner=owner)
 def root_output_stat(self,path,*args,**kw):
  actual=self.real_lstat(path,*args,**kw)
  if Path(path) not in self.output_paths:return actual
  # Sole positive-identity substitution: source-faithful synthetic root outputs.
  fields={name:getattr(actual,name) for name in dir(actual) if name.startswith('st_')}
  fields.update(st_uid=0,st_gid=0);return SimpleNamespace(**fields)
 def write(self,path,raw,mode=0o444):
  path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
  if path.exists():path.chmod(0o644)
  path.write_bytes(raw);path.chmod(mode)
 def build_outputs(self):
  out=self.port.project/'out';out.mkdir(exist_ok=True)
  image=out/'ocv-test.raw'
  with image.open('wb') as stream:stream.truncate(2*1024**3)
  image.chmod(0o444)
  for name in ('kernel.bin','initrd.img'):self.write(out/name,('SYNTHETIC-NOT-A-'+name).encode())
  self.output_paths={out/name for name in build.OUTPUT_FILES}
  helper=b'SYNTHETIC-UNCOMPILED-HELPER'
  runtime_bytes=b'SYNTHETIC-NONEXECUTED-DEBIAN-PYTHON'
  runtime={'schema':'ocv-runtime-v1','architecture':'linux-amd64',
   'files':[{'path':'usr/bin/python3.11','sourcePath':'/usr/bin/python3.11','bytes':len(runtime_bytes),
             'sha256':SHA(runtime_bytes),'mode':0o555}],
   'helper':{'path':'code/static-entry','bytes':len(helper),'sha256':SHA(helper)}}
  runtime_raw=C(runtime)
  control={'schema':'ocv-build-v1','sourceManifestSha256':SHA(self.raw),'runtimeManifestSha256':SHA(runtime_raw),
   'toolManifestSha256':SHA(b'{}'),'importManifestSha256':SHA(b'{}'),'aptMetadataManifestSha256':SHA(b'{}'),
   'helperSha256':SHA(helper),'kernelVersion':'6.1.0-50-amd64','systemdVersion':build.SYSTEMD_VERSION,
   'runIdentity':self.port.run,'fixtureOnly':True,'candidateImage':False}
  for name in artifact.CONTROLS:self.write(out/name,C({'synthetic':True,'notLinuxProof':True}))
  self.write(out/'runtime.json',runtime_raw);self.write(out/'build.json',C(control))
  self.write(out/'static-entry',helper,0o555)
  self.write(out/'runtime/usr/bin/python3.11',runtime_bytes,0o555)
  for name in artifact.APT_FILES:self.write(out/'apt-data'/name,b'SYNTHETIC-PUBLIC-APT-CONTROL:'+name.encode())
 def partition(self,image):
  return C({'partitiontable':{'label':'gpt','device':image,'unit':'sectors','sectorsize':512,
    'partitions':[{'node':image+'1','start':2048,'size':2*1024**3//512-4096,
      'type':build.ROOT_TYPE,'uuid':'11111111-2222-4333-8444-555555555555'}]}})
 def guest_frame(self):
  # Actual pure source-replay fixture, rebound to actual public source/built controls.
  # The strings below model captured evidence; they issue NO native proof.
  rows,_old=setup_rows();expected=self.port.expected
  context=json.loads(rows['controller-context']);context.update(expected['code'])
  rows['controller-context']=C(context);context_sha=SHA(rows['controller-context'])
  frames=[json.loads(line) for line in rows['worker-stderr'].splitlines()]
  frames[0].update(contextSha256=context_sha,workerSha256=expected['code']['workerSha256'])
  frames[1].update(contextSha256=context_sha)
  rows['worker-stderr']=b''.join(C(frame)+b'\n' for frame in frames)
  cases=json.loads(rows['native-isolation-cases']);cases['contextSha256']=context_sha
  rows['native-isolation-cases']=C(cases);rows['worker-stderr-raw']=rows['worker-stderr']+C(cases)+b'\n'
  # No expected/actual facts shortcut: run the actual source callback now too.
  source_validator.validate(rows,expected)
  custody=[]
  for role,raw in sorted(rows.items()):
   custody.append({'role':role,'bytes':len(raw),'sha256':SHA(raw),'base64':base64.b64encode(raw).decode(),
    'sourceBytes':len(raw),'sourceSha256':SHA(raw),'truncated':False})
  frame={'schema':'ocv.ci-result.v1',**{key:expected[key] for key in
    ('sessionId','runIdentity','sourceManifestSha256','buildControlSha256')},
   'status':'unit_passed_pending_outer_exit','adapterResult':{'status':'unit_passed_pending_outer_exit',
    'unitStatus':'passed','ownedUnitEmpty':True,'custodyComplete':True,
    'closeout':{'shutdownRequested':True,'outerExitPending':True}},
   'custody':{'schema':'ocv.custody.v1','rawBytes':sum(map(len,rows.values())),'files':custody}}
  return b'SYNTHETIC-BOOT-LOG\n'+serial.PREFIX+base64.b64encode(C(frame))+b'\n'
 def execute(self,scope):
  role,args=scope.role,scope.arguments
  if role=='dpkg_query':
   return outer(b'mkosi\t20.2-1\tamd64\n' if args['kind']=='versions' else b'mkosi: /usr/bin/mkosi\n')
  if role=='debian_metadata_curl':
   self.write(self.port.project/'metadata'/('InRelease' if args['kind']=='release' else 'Packages.xz'),
    self.release if args['kind']=='release' else lzma.compress(self.packages));return outer()
  if role=='gpgv_metadata':
   if self.gpg_exit==2:
    return outer(self.gpg_status,status='refused',returncode=2,reason='command_exit_nonzero',**self.gpg_changes)
   return outer(self.gpg_status)
  if role=='mkosi_build' and Path(args['project']).name=='negative':
   context=json.loads((Path(args['project'])/'pkgmngr/etc/apt/ocv/guard-context.json').read_bytes())
   record={'schema':'ocv-apt-refused-v1','buildId':context['buildId'],'sourceManifestSha256':SHA(self.raw),
    'contextSha256':SHA(C(context)),'phase':'update','reason':'apt.keyring_pin'}
   return outer(stderr=C(record)+b'\n',status='refused',returncode=100,**self.negative_changes)
  if role=='mkosi_build':self.build_outputs();return outer()
  if role=='partition_read':return outer(self.partition(args['image']))
  if role=='qemu_once':
   self.qemu_calls+=1
   if self.qemu_mode=='bad-frame':return outer(b'OCV_RESULT_V1:not-valid-base64\n',b'PUBLIC-DIAGNOSTIC\n')
   raw=self.guest_frame()
   if self.qemu_mode=='changed-base':
    p=self.port.project/'out/kernel.bin';p.chmod(0o644);p.write_bytes(b'CHANGED-PUBLIC-BASE');p.chmod(0o444)
   return outer(raw,b'PUBLIC-OWNED-QEMU-STDERR\n')
  return outer()
 def run(self,root_outputs=True):
  port=self.new_port()
  with mock.patch.object(h,'read_regular',side_effect=self.tool_read):
   if root_outputs:
    with mock.patch.object(Path,'lstat',new=lambda p,*a,**k:self.root_output_stat(p,*a,**k)):
     return h.Controller(port).run()
   return h.Controller(port).run()


class NativePortContract(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='ocv-public-contract-')
  self.addCleanup(self.tmp.cleanup);self.fixture=ContractFixture(self.tmp.name)
 def test_complete_gpg_exit_two_requires_policy_before_provisional_custody_clear(self):
  self.fixture.gpg_exit=2
  port=self.fixture.new_port()
  def checked(_release,_packages,**kw):
   self.assertEqual(kw['returncode'],2)
   self.assertEqual(kw['status'],self.fixture.gpg_status)
   return {'verifiedPrimaryFingerprints':['synthetic-policy-seam']}
  with mock.patch.object(h,'read_regular',side_effect=self.fixture.tool_read),\
       mock.patch.object(self.fixture.policy,'classify',side_effect=checked):
   port.install_host_tools();port.authenticate_metadata()
  self.assertIsNone(port.first_failure)
  self.assertEqual(port.commands[-1]['status'],'refused')
  self.assertFalse((port.artifacts/'host-stdout.bin').exists())
  self.assertFalse((port.artifacts/'host-stderr.bin').exists())
 def test_incomplete_gpg_exit_two_preserves_first_cause(self):
  self.fixture.gpg_exit=2;self.fixture.gpg_changes={'streamsEOF':False}
  port=self.fixture.new_port()
  with mock.patch.object(h,'read_regular',side_effect=self.fixture.tool_read):
   port.install_host_tools()
   with self.assertRaisesRegex(h.Refusal,'host.gpgv_process_boundary'):
    port.authenticate_metadata()
  self.assertEqual(port.first_failure['role'],'gpgv_metadata')
  self.assertTrue((port.artifacts/'host-stdout.bin').exists())
 def test_gpg_exit_two_with_cleanup_error_never_reaches_policy(self):
  self.fixture.gpg_exit=2;self.fixture.gpg_changes={'cleanupErrors':[{'phase':'close'}]}
  port=self.fixture.new_port()
  with mock.patch.object(h,'read_regular',side_effect=self.fixture.tool_read):
   port.install_host_tools()
   with self.assertRaisesRegex(h.Refusal,'host.gpgv_process_boundary'):
    port.authenticate_metadata()
  self.assertEqual(port.first_failure['role'],'gpgv_metadata')
 def test_public_project_stays_separate_from_private_runner_artifact_temp(self):
  runner_temp=self.fixture.root/'runner-temp';runner_temp.mkdir(mode=0o700)
  self.fixture.environment['RUNNER_TEMP']=str(runner_temp)
  port=self.fixture.new_port()
  self.assertEqual(port.project,self.fixture.root/'project')
  self.assertEqual(port.artifacts,runner_temp/'ocv-ci-artifacts')
  self.assertEqual(runner_temp.stat().st_mode&0o777,0o700)
 def test_preexisting_symlink_project_refuses_before_command(self):
  destination=self.fixture.root/'destination';destination.mkdir()
  (self.fixture.root/'project').symlink_to(destination,target_is_directory=True)
  with self.assertRaises(FileExistsError):self.fixture.new_port()
  self.assertFalse(self.fixture.commands.calls)
 def test_actual_controller_metadata_negative_build_serial_replay_and_public_artifact(self):
  result=self.fixture.run()
  self.assertEqual(result['status'],'passed',getattr(self.fixture.port,'failure',result))
  self.assertEqual(result['phase'],'complete');self.assertFalse(result['candidateQualified'])
  self.assertEqual(self.fixture.qemu_calls,1)
  commands_done=[scope.role for scope in self.fixture.commands.calls]
  self.assertEqual(commands_done.count('mkosi_build'),2);self.assertEqual(commands_done.count('qemu_once'),1)
  qemu=next(scope.argv for scope in self.fixture.commands.calls if scope.role=='qemu_once')
  self.assertIn('-snapshot',qemu);self.assertEqual(qemu[qemu.index('-nic')+1],'none')
  port=self.fixture.port
  self.assertEqual(port.metadata['nativeAuthenticationIssued'],False)
  self.assertEqual(port.negative_proof['reason'],'apt.keyring_pin')
  self.assertTrue((port.artifacts/'negative-stderr.bin').is_file())
  self.assertEqual((port.artifacts/'host-stdout.bin').read_bytes(),self.fixture.guest_frame())
  with tarfile.open(port.artifacts/'public-tooling.tar.gz','r:gz') as archive:
   names=archive.getnames()
   self.assertIn('PUBLIC-TOOLING-MANIFEST.json',names)
   self.assertIn('source/host/ci_host.py',names)
   self.assertFalse(any(Path(name).name in build.OUTPUT_FILES for name in names))
  final=json.loads((port.artifacts/'host-result.json').read_bytes())
  self.assertEqual(final['status'],'passed');self.assertIsNone(final['failure'])
  # This deliberately synthetic path result cannot establish actual Linux proof.
  self.assertTrue(all(scope.environment==SyntheticCommands.ENV or scope.role.startswith('ubuntu_apt_')
   for scope in self.fixture.commands.calls))
 def test_exported_tree_needs_only_its_manifest_not_preparation_materializer(self):
  destination=self.fixture.root/'exported-case';destination.mkdir()
  with mock.patch.dict(globals(),{'publication':None,'A':self.fixture.source}):
   cloned=ContractFixture(destination)
  self.assertEqual(cloned.raw,self.fixture.raw)
  self.assertEqual(cloned.rows,self.fixture.rows)
 def test_negative_incomplete_outer_settlement_prevents_positive_build_and_qemu(self):
  self.fixture.negative_changes={'streamsEOF':False}
  result=self.fixture.run()
  self.assertEqual((result['status'],result['phase'],result['reason']),
   ('refused','apt-negative','host.negative_not_refused'))
  self.assertEqual(sum(scope.role=='mkosi_build' for scope in self.fixture.commands.calls),1)
  self.assertEqual(self.fixture.qemu_calls,0)
  self.assertTrue((self.fixture.port.artifacts/'host-stderr.bin').is_file())
 def test_raw_guest_failure_is_kept_before_frame_parse_and_no_artifact(self):
  # Minimal real Port/Controller tail; no expensive synthetic OS-image read.
  port=self.fixture.new_port();port.bound={};port.base_records={}
  result=outer(b'OCV_RESULT_V1:not-valid-base64\n',b'PUBLIC-FAILURE-DETAIL\n')
  port.preserve_outer(result)
  with self.assertRaises(serial.Refusal):port.verify_outer(result,{})
  self.assertEqual((port.artifacts/'host-stderr.bin').read_bytes(),b'PUBLIC-FAILURE-DETAIL\n')
  self.assertFalse((port.artifacts/'public-tooling.tar.gz').exists())
 def test_post_qemu_base_change_refuses_after_raw_custody(self):
  port=self.fixture.new_port();out=port.project/'out';out.mkdir()
  p=out/'kernel.bin';p.write_bytes(b'PUBLIC-BASE');p.chmod(0o444);self.fixture.output_paths={p}
  port.base_records={'kernel.bin':{'bytes':len(b'PUBLIC-BASE'),'sha256':SHA(b'PUBLIC-BASE')}}
  value=outer(b'PUBLIC-RAW-SERIAL\n');port.preserve_outer(value)
  p.chmod(0o644);p.write_bytes(b'PUBLIC-FAKE');p.chmod(0o444)
  with mock.patch.object(Path,'lstat',new=lambda path,*a,**k:self.fixture.root_output_stat(path,*a,**k)):
   with self.assertRaisesRegex(h.Refusal,'host.base_changed'):port.verify_outer(value,{})
  self.assertEqual((port.artifacts/'host-stdout.bin').read_bytes(),value['stdout'])
 def test_actual_local_uid_output_is_rejected_not_misrepresented_as_root(self):
  if os.getuid()==0:self.skipTest('requires the actual nonroot local user')
  port=self.fixture.new_port();out=port.project/'out';out.mkdir()
  p=out/'kernel.bin';p.write_bytes(b'PUBLIC-BASE');p.chmod(0o444)
  port.base_records={'kernel.bin':{'bytes':11,'sha256':SHA(b'PUBLIC-BASE')}}
  with self.assertRaisesRegex(h.Refusal,'host.base_identity_changed'):port.verify_base_unchanged()
 def test_streamed_hash_cannot_succeed_on_short_read_with_unchanged_stat(self):
  port=self.fixture.new_port();out=port.project/'out';out.mkdir()
  p=out/'kernel.bin';p.write_bytes(b'PUBLIC-BASE');p.chmod(0o444);self.fixture.output_paths={p}
  # Even an expected digest of the prematurely ended prefix cannot waive size.
  port.base_records={'kernel.bin':{'bytes':len(b'PUBLIC-BASE'),'sha256':SHA(b'PUBLIC')}}
  real_open=Path.open
  def short_open(path,*args,**kw):
   return io.BytesIO(b'PUBLIC') if path==p else real_open(path,*args,**kw)
  with mock.patch.object(Path,'lstat',new=lambda path,*a,**k:self.fixture.root_output_stat(path,*a,**k)),\
       mock.patch.object(Path,'open',new=short_open):
   with self.assertRaisesRegex(h.Refusal,'host.base_changed'):port.verify_base_unchanged()
 def test_exact_first_owned_setup_cause_survives_command_and_failure_custody(self):
  port=self.fixture.new_port()
  cause={'phase':'before_spawn','exceptionType':'Refusal','errno':None,'reason':'host.owned_project'}
  with mock.patch.object(self.fixture.commands,'run_owned',return_value=outer(b'PUBLIC-OUT',b'PUBLIC-ERR',
      status='refused',returncode=None,spawned=False,reason='outer_Refusal',setupCause=cause)):
   try:port._run('python_tests',{'source_root':str(self.fixture.source),'suite':'host'},3)
   except h.Refusal as error:port.preserve_failure('source-tests',error)
   else:self.fail('failed command accepted')
  self.assertEqual(port.first_failure['setupCause'],cause)
  self.assertEqual(port.failure['firstCommand']['setupCause'],cause)
  self.assertFalse(port.failure['firstCommand']['spawned'])
  self.assertEqual(port.failure['firstCommand']['outerReason'],'outer_Refusal')
  self.assertEqual((port.artifacts/'host-stderr.bin').read_bytes(),b'PUBLIC-ERR')
 def test_preexisting_project_or_artifact_dir_refuses_before_command(self):
  for target in (Path(self.fixture.permit.project),self.fixture.root/'ocv-ci-artifacts'):
   with self.subTest(target=target):
    target.mkdir()
    with self.assertRaises(FileExistsError):self.fixture.new_port()
    self.assertFalse(self.fixture.commands.calls)
    # Constructor may create project before learning artifacts already exists.
    for folder in (Path(self.fixture.permit.project),self.fixture.root/'ocv-ci-artifacts'):
     if folder.exists():folder.rmdir()


if __name__=='__main__':unittest.main()
