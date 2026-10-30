"""Actual NativePort contracts on public synthetic files, never Linux proof.

No NativePermit is issued, no process runs, and no system package/tool is read.
Only sealed-command execution, three fixed public-tool reads and the three
simulated root-owned output identities are substituted. The actual controller,
metadata classifier, builder bindings, serial/source replay and artifact packer
run. The large fixtures are disposable sparse synthetic files with fixed
partition/superblock metadata; no filesystem or OS image is built.
"""
import base64
import copy
import datetime as dt
import importlib.util
import io
import json
import lzma
import os
from pathlib import Path
import stat
import struct
import sys
import tarfile
import tempfile
import time
from types import SimpleNamespace
import unittest
from uuid import UUID
from unittest import mock

import ci_host as h
import command_factories as commands
import serial_receipt as serial
import source_expectation
import artifact
import host_context as actual_host
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
import integrated_fixture
from test_archive_policy import security_fixture,extra_valid_security_signature

C=h.canonical
SHA=h.sha
# Explicit non-native payload: only the artifact hash reference is substituted.
# The unpatched production archive hash remains mandatory in actual CI.
REPAIR_RAW=(b'public synthetic offline selinux-utils package'*3000)[:126432]
REPAIR_SHA=SHA(REPAIR_RAW)
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
  if name=='selinux-utils':
   data+=('Package: selinux-utils\nVersion: 3.4-1+b6\nArchitecture: amd64\n'
     'Filename: pool/main/libs/libselinux/selinux-utils_3.4-1+b6_amd64.deb\n'
     'SHA256: '+REPAIR_SHA+'\nSize: 126432\nDepends: '+artifact.REPAIR_PACKAGE_DEPENDS+'\n\n').encode()
   continue
  version=build.SYSTEMD_VERSION if name in ('systemd','systemd-sysv','libsystemd0','libsystemd-shared') else '1.0-1'
  data+=(f'Package: {name}\nVersion: {version}\nArchitecture: amd64\n'
         f'Filename: pool/main/{name}/{name}_fixture_amd64.deb\n'
         f'SHA256: {SHA(name.encode())}\nSize: 17\n'+
         ('Depends: libc6 (>= 2.34)\n'if name=='selinux-utils'else'')+'\n').encode()
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
 def normalize_mkosi_outputs(self,permit,project):
  # This simulator writes its bounded public outputs under the final names.
  assert permit is self.fixture.permit and project==str(self.fixture.port.project)
 def initialize_integrated_test_image(self,permit,project):
  # This explicit non-native seam creates only the reviewed sparse prefill.
  assert permit is self.fixture.permit and project==str(self.fixture.port.project)
  path=Path(project)/'out/integrated-test.raw'
  with path.open('xb') as stream:
   stream.write(integrated_fixture.test_image_header())
   stream.truncate(integrated_fixture.TEST_IMAGE_BYTES)
  path.chmod(0o600)
 def seal_command(self,permit,role,arguments,*,cwd,environment,launch_deadline=None):
  assert permit is self.fixture.permit
  assert launch_deadline==(self.fixture.port.deadline-2150 if role=='qemu_once' else None)
  if role=='mkosi_build':argv=('/usr/bin/sudo','-n','--')+build.mkosi_argv(arguments['project'])
  elif role=='qemu_once':
   # Pure command model uses a relocated source-owned CI project; no command
   # is run and no NativePermit accepts this temporary fixture directory.
   original=arguments['bound']['directory'];fixed=integrated_fixture.project_path(self.fixture.mission)+'/out'
   base=build.qemu_argv(arguments['bound'],arguments['session'])
   argv=integrated_fixture.qemu_argv(tuple(a.replace(original,fixed) for a in base),
    directory=fixed,test_record=arguments['test_record'])
   argv=tuple(a.replace(fixed,original) for a in argv)
  elif role=='integrated_test_image':
   project=integrated_fixture.project_path(self.fixture.mission);fixed=project+'/integrated-seed'
   argv=integrated_fixture.image_argv(fixed,project+'/out/integrated-test.raw')
   argv=tuple(a.replace(fixed,arguments['seed_root']).replace(project+'/out/integrated-test.raw',arguments['output']) for a in argv)
  elif role=='partition_read':argv=build.partition_argv(arguments['image'])
  else:argv=getattr(commands,role)(**arguments)
  return SimpleNamespace(role=role,arguments=copy.deepcopy(arguments),argv=argv,cwd=cwd,environment=environment,
   launch_deadline=launch_deadline)
 def run_owned(self,permit,scope,*,cwd,environment,deadline):
  assert permit is self.fixture.permit and cwd==scope.cwd and environment==scope.environment
  self.calls.append(scope)
  return self.fixture.execute(scope)


class SealedSyntheticCommands(SyntheticCommands):
 """Real sealer+durable intent, explicit non-native admission/execution seam.

 No NativePermit or HostProcessOps is constructed. Tests substitute only the
 permit lookup and process execution; source factories, scope-key uniqueness,
 project/environment validation and the actual O_EXCL intent writer all run.
 """
 def __init__(self,fixture):super().__init__(fixture);self.arguments={}
 def seal_command(self,permit,role,arguments,*,cwd,environment,launch_deadline=None):
  scope=actual_host.seal_command(permit,role,arguments,cwd=cwd,environment=environment,launch_deadline=launch_deadline)
  self.arguments[scope.key]=copy.deepcopy(arguments)
  return scope
 def run_owned(self,permit,scope,*,cwd,environment,deadline):
  assert permit is self.fixture.permit and type(scope) is actual_host._Scope
  assert permit.scopes.get(scope.key) is scope and cwd==scope.cwd and environment==scope.environment
  actual_host._intent(scope)
  self.calls.append(scope)
  return self.fixture.execute(SimpleNamespace(role=scope.role,arguments=self.arguments[scope.key],
   argv=scope.argv,cwd=scope.cwd,environment=scope.environment))


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
   uid=os.getuid(),gid=os.getgid(),expected={'source_manifest_sha':SHA(self.raw)})
  self.commands=SyntheticCommands(self)
  self.release,self.packages,self.gpg_status,self.policy_fixture=metadata()
  now=dt.datetime.now(dt.timezone.utc)
  self.security_release,self.security_packages,self.security_status=security_fixture(
   date=(now-dt.timedelta(days=1)).strftime('%a, %d %b %Y %H:%M:%S UTC'),
   until=(now+dt.timedelta(days=1)).strftime('%a, %d %b %Y %H:%M:%S UTC'))
  self.policy=SimpleNamespace(classify=lambda *args,**kw:policy.classify(*args,fixture=self.policy_fixture,**kw),
   classify_security=policy.classify_security,security_signature_evidence=policy.security_signature_evidence,
   PYTHON_U9=policy.PYTHON_U9)
  self.modules=SimpleNamespace(context=self.commands,commands=commands,build=build,guard_project=guard_project,
   apt=apt,policy=self.policy,serial=serial,validator=source_validator,artifact=artifact,source_expectation=source_expectation,
   integrated_fixture=integrated_fixture,
   # Explicit non-native contract seam: this fixture has one inert runtime row
   # and only the historical generic serial packet. Real integrated replay and
   # its closed 26-role packet are tested separately and remain a Linux gate.
   integrated_capture=SimpleNamespace(expected_runtime_rows=lambda runtime,control:(),
    validate_combined=lambda rows,binding,*,generic_validator,runtime_rows:generic_validator(rows,binding)))
  self.environment={'RUNNER_TEMP':str(self.root),'GITHUB_WORKFLOW_REF':
   'fr-meyer/openclaw/.github/workflows/authorized-beta-focused-validation.yml@refs/heads/retained-verifier-prerequisites',
   'GITHUB_SHA':'c'*40,'GITHUB_RUN_ID':'123'}
  self.negative_changes={};self.qemu_mode='valid';self.qemu_calls=0;self.output_paths=set()
  self.short_stream=False;self.real_read=h.read_regular;self.real_lstat=Path.lstat
  self.gpg_exit=0;self.gpg_changes={};self.dpkg_missing=None
 def host_path_facts(self,path):
  target={'/usr/bin/bootctl':('/usr/bin/bootctl',1),
          '/usr/sbin/depmod':('/usr/bin/kmod',2),'/sbin/depmod':('/usr/bin/kmod',2),
          '/usr/sbin/mkfs.ext4':('/usr/sbin/mke2fs',3),
          '/sbin/mkfs.ext4':('/usr/sbin/mke2fs',3),
          '/usr/sbin/mke2fs':('/usr/sbin/mke2fs',3),'/sbin/mke2fs':('/usr/sbin/mke2fs',3)}[path]
  canonical,ino=target
  if self.dpkg_missing=='depmod_substitute' and path=='/sbin/depmod':ino=99
  if self.dpkg_missing=='depmod_target' and path in ('/usr/sbin/depmod','/sbin/depmod'):
   canonical='/usr/bin/other'
  return {'canonical':canonical,'dev':1,'ino':ino,'bytes':128,'mode':0o755}
 def new_port(self):
  clock=Path(self.environment['RUNNER_TEMP'])/'ocv-job-clock.json'
  if not clock.exists():self.write(clock,C({'schema':'ocv-job-clock-v1','monotonicNs':time.monotonic_ns()}),0o600)
  with mock.patch.dict(os.environ,self.environment):
   self.port=h.NativePort(self.permit,self.modules,self.source,self.raw,self.rows)
  return self.port
 def tool_read(self,path,cap,*,owner=None):
  if str(path) in TOOL_BYTES:
   assert owner==0 and len(TOOL_BYTES[str(path)])<=cap
   return TOOL_BYTES[str(path)]
  if Path(path).name=='integrated-test.raw':
   # Same explicit synthetic root-output identity seam as root_output_stat.
   assert owner==0 and cap==integrated_fixture.TEST_IMAGE_BYTES
   raw=Path(path).read_bytes();assert len(raw)==cap;return raw
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
  self.output_paths={out/name for name in (*build.OUTPUT_FILES,'integrated-test.raw')}
  helper=b'SYNTHETIC-UNCOMPILED-HELPER'
  runtime_bytes=b'SYNTHETIC-NONEXECUTED-DEBIAN-PYTHON'
  runtime={'schema':'ocv-runtime-v1','architecture':'linux-amd64',
   'files':[{'path':'usr/bin/python3.11','sourcePath':'/usr/bin/python3.11','bytes':len(runtime_bytes),
             'sha256':SHA(runtime_bytes),'mode':0o555}],
   'helper':{'path':'code/static-entry','bytes':len(helper),'sha256':SHA(helper)}}
  runtime_raw=C(runtime)
  repair_tool={'role':'selinuxenabled','path':'/usr/sbin/selinuxenabled',
   'bytes':14576,'sha256':artifact.REPAIR_TOOL_SHA256}
  tools_raw=C({'schema':'ocv-tools-v1','tools':[dict(repair_tool,package='selinux-utils',version='3.4-1+b6',debSha256=REPAIR_SHA)],
   'synthetic':True,'notLinuxProof':True})
  control={'schema':'ocv-build-v1','sourceManifestSha256':SHA(self.raw),'runtimeManifestSha256':SHA(runtime_raw),
   'toolManifestSha256':SHA(tools_raw),'importManifestSha256':SHA(b'{}'),'aptMetadataManifestSha256':SHA(b'{}'),
   'helperSha256':SHA(helper),'kernelVersion':'6.1.0-50-amd64','systemdVersion':build.SYSTEMD_VERSION,
   'runIdentity':self.port.run,'fixtureOnly':True,'candidateImage':False}
  for name in artifact.CONTROLS:self.write(out/name,C({'synthetic':True,'notLinuxProof':True}))
  self.write(out/'runtime.json',runtime_raw);self.write(out/'build.json',C(control))
  self.write(out/'tools.json',tools_raw)
  self.write(out/'static-entry',helper,0o555)
  self.write(out/'runtime/usr/bin/python3.11',runtime_bytes,0o555)
  for name in artifact.APT_FILES:self.write(out/'apt-data'/name,b'SYNTHETIC-PUBLIC-APT-CONTROL:'+name.encode())
  self.write(out/'apt-data/InRelease',self.release)
  self.write(out/'apt-data/Packages',self.packages)
  self.write(out/'apt-data/SecurityInRelease',self.security_release)
  self.write(out/'apt-data/SecurityPackages',self.security_packages)
  self.write(out/'repair/selinux-utils.deb',REPAIR_RAW)
  repair={'schema':artifact.REPAIR_SCHEMA,'fixtureOnly':True,'privateVmInstallationPerformed':False,
   'package':{'name':'selinux-utils','version':'3.4-1+b6','architecture':'amd64',
    'bytes':126432,'sha256':REPAIR_SHA,
    'filename':'pool/main/libs/libselinux/selinux-utils_3.4-1+b6_amd64.deb','origin':'main',
    'packagesSha256':SHA(self.packages),'inReleaseSha256':SHA(self.release),
    'depends':artifact.REPAIR_PACKAGE_DEPENDS},'tool':repair_tool,
   'sourceManifestSha256':SHA(self.raw),'aptMetadataManifestSha256':control['aptMetadataManifestSha256']}
  self.write(out/'repair/manifest.json',C(repair))
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
   if args['kind']=='versions':
    return outer(b'mkosi\t20.2-1\tamd64\n'+
                 (b'' if self.dpkg_missing=='version' else b'systemd-boot\t255.4-synthetic\tall\n')+
                 (b'' if self.dpkg_missing=='kmod_version' else b'kmod\t31-synthetic\tamd64\n')+
                 b'e2fsprogs\t1.47-synthetic\tamd64\n')
   if args['kind']=='owners':return outer(b'mkosi: /usr/bin/mkosi\n'+
                (b'' if self.dpkg_missing=='owner' else b'systemd-boot: /usr/bin/bootctl\n'))
   if args['kind']=='systemd_boot_files':return outer(b'/usr/bin/bootctl\n')
   if args['kind']=='kmod_files':return outer(b'/bin/kmod\n'+
                (b'' if self.dpkg_missing=='depmod_filelist' else b'/sbin/depmod\n'))
   if args['kind']=='e2fsprogs_files':return outer(b'/usr/sbin/mke2fs\n/usr/sbin/mkfs.ext4\n')
   if args['kind']=='depmod_sbin_owner':return outer(
     b'other: /sbin/depmod\n' if self.dpkg_missing=='depmod_owner' else b'kmod: /sbin/depmod\n')
   if args['kind']=='mkfs_usr_owner':return outer(
     b'other: /usr/sbin/mkfs.ext4\n' if self.dpkg_missing=='mkfs_owner' else b'e2fsprogs: /usr/sbin/mkfs.ext4\n')
   if args['kind']=='mke2fs_usr_owner':return outer(b'e2fsprogs: /usr/sbin/mke2fs\n')
   raise AssertionError('unexpected synthetic dpkg query')
  if role=='debian_metadata_curl':
   security=args.get('origin')=='security';stem='Security'if security else''
   release=self.security_release if security else self.release;packages=self.security_packages if security else self.packages
   self.write(self.port.project/'metadata'/(stem+('InRelease' if args['kind']=='release' else 'Packages.xz')),
    release if args['kind']=='release' else lzma.compress(packages));return outer()
  if role=='gpgv_metadata':
   if args.get('origin')=='security':return outer(self.security_status)
   if self.gpg_exit==2:
    return outer(self.gpg_status,status='refused',returncode=2,reason='command_exit_nonzero',**self.gpg_changes)
   return outer(self.gpg_status)
  if role=='mkosi_build' and Path(args['project']).name=='negative':
   context=json.loads((Path(args['project'])/'pkgmngr/etc/apt/ocv/guard-context.json').read_bytes())
   record={'schema':'ocv-apt-refused-v1','buildId':context['buildId'],'sourceManifestSha256':SHA(self.raw),
    'contextSha256':SHA(C(context)),'phase':'update','reason':'apt.keyring_pin'}
   return outer(stderr=C(record)+b'\n',status='refused',returncode=100,**self.negative_changes)
  if role=='mkosi_build':self.build_outputs();return outer()
  if role=='integrated_test_image':
   p=Path(args['output'])
   assert SHA(p.read_bytes())==integrated_fixture.initialized_test_image_sha256()
   # A fixed wire vector substitutes only mke2fs execution. No filesystem
   # is made; actual kernel part1/filesystem/ancestry remains a Linux gate.
   superblock=bytearray(1024)
   struct.pack_into('<I',superblock,4,16128)
   struct.pack_into('<I',superblock,0x18,2)
   struct.pack_into('<H',superblock,0x38,0xef53)
   superblock[0x68:0x78]=UUID('56b32afd-9976-4d21-9720-c4d5fcd02751').bytes
   with p.open('r+b') as stream:
    stream.seek(1048576+1024);stream.write(superblock)
   p.chmod(0o444);return outer()
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
  with mock.patch.object(h,'read_regular',side_effect=self.tool_read),\
       mock.patch.object(h,'host_path_facts',side_effect=self.host_path_facts),\
       mock.patch.object(artifact,'REPAIR_PACKAGE_SHA256',REPAIR_SHA):
   if root_outputs:
    with mock.patch.object(Path,'lstat',new=lambda p,*a,**k:self.root_output_stat(p,*a,**k)):
     return h.Controller(port).run()
   return h.Controller(port).run()


class NativePortContract(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='ocv-public-contract-')
  self.addCleanup(self.tmp.cleanup);self.fixture=ContractFixture(self.tmp.name)
 def sealed_fixture(self,root):
  Path(root).chmod(0o755)
  fixture=ContractFixture(root);permit=fixture.permit
  permit.project=Path(permit.project);permit.source=fixture.source;permit.workspace=fixture.root
  permit.rows=fixture.rows;permit.scopes={};permit.consumed=set();permit.run_id='123'
  permit.expected['expected_source']='c'*40
  fixture.commands=SealedSyntheticCommands(fixture);fixture.modules.context=fixture.commands
  return fixture
 def run_sealed_host_prefix(self,fixture):
  port=fixture.new_port()
  def no_metadata():raise h.Refusal('contract.host_tools_complete_no_linux_proof')
  port.authenticate_metadata=no_metadata
  def explicit_model(value):
   self.assertIs(value,fixture.permit);self.assertNotIsInstance(value,actual_host.NativePermit)
   return fixture.permit
  with mock.patch.object(actual_host,'_permit',side_effect=explicit_model),\
       mock.patch.object(actual_host.NativeIO,'spawn',side_effect=AssertionError('native process forbidden')),\
       mock.patch.object(actual_host,'HostProcessOps',side_effect=AssertionError('native owner forbidden')),\
       mock.patch.object(h,'read_regular',side_effect=fixture.tool_read),\
       mock.patch.object(h,'host_path_facts',side_effect=fixture.host_path_facts):
   result=h.Controller(port).run()
   return result,port,explicit_model
 def test_actual_controller_sealer_intents_share_one_settled_e2fs_listing_and_keep_all_owner_checks(self):
  with tempfile.TemporaryDirectory(prefix='ocv-public-sealed-host-',dir='/tmp') as root:
   fixture=self.sealed_fixture(root)
   result,port,model=self.run_sealed_host_prefix(fixture)
   self.assertEqual((result['phase'],result['reason']),
    ('signed-metadata','contract.host_tools_complete_no_linux_proof'),getattr(port,'failure',result))
   self.assertFalse(result['linuxIsolationProof'])
   argv=[scope.argv for scope in fixture.commands.calls]
   self.assertEqual(argv.count(commands.dpkg_query('e2fsprogs_files')),1)
   self.assertEqual(argv.count(commands.dpkg_query('mkfs_usr_owner')),1)
   self.assertEqual(argv.count(commands.dpkg_query('mke2fs_usr_owner')),1)
   self.assertEqual(len(port.host_tools['packagePathProofSha256']),64)
   intents=list((port.project/'.host-intents').glob('*.json'))
   self.assertEqual(len(intents),len(argv))
   self.assertEqual(len(fixture.permit.scopes),len(fixture.permit.consumed))
   before=len(fixture.commands.calls)
   # Reusing local immutable query evidence does not authorize resubmission:
   # both a mutation and a readonly duplicate remain refused before dispatch.
   with mock.patch.object(actual_host,'_permit',side_effect=model):
    for role,args in (('ubuntu_apt_install',{'project':str(port.project)}),
                      ('dpkg_query',{'kind':'e2fsprogs_files'})):
     with self.subTest(role=role),self.assertRaisesRegex(actual_host.Refusal,'host.scope_already_sealed'):
      port._run(role,args,2)
   self.assertEqual(len(fixture.commands.calls),before)
   self.assertEqual(len(list((port.project/'.host-intents').glob('*.json'))),len(intents))
   self.assertEqual(actual_host._ISSUED,{})
 def test_failed_readonly_listing_is_not_cached_retried_or_used_for_either_binary(self):
  with tempfile.TemporaryDirectory(prefix='ocv-public-sealed-host-fail-',dir='/tmp') as root:
   fixture=self.sealed_fixture(root);execute=fixture.execute
   def fail_listing(scope):
    if scope.role=='dpkg_query' and scope.arguments['kind']=='e2fsprogs_files':
     return outer(b'',b'PUBLIC-SYNTHETIC-FAILED-LISTING',status='refused',returncode=1)
    return execute(scope)
   fixture.execute=fail_listing
   result,port,_=self.run_sealed_host_prefix(fixture)
   self.assertEqual((result['phase'],result['reason']),('host-tools','host.command_dpkg_query'))
   argv=[scope.argv for scope in fixture.commands.calls]
   self.assertEqual(argv.count(commands.dpkg_query('e2fsprogs_files')),1)
   self.assertNotIn(commands.dpkg_query('mkfs_usr_owner'),argv)
   self.assertNotIn(commands.dpkg_query('mke2fs_usr_owner'),argv)
   self.assertFalse(hasattr(port,'host_tools'));self.assertFalse(result['linuxIsolationProof'])
   self.assertEqual(actual_host._ISSUED,{})
 def test_complete_gpg_exit_two_requires_policy_before_provisional_custody_clear(self):
  self.fixture.gpg_exit=2
  port=self.fixture.new_port()
  def checked(_release,_packages,**kw):
   self.assertEqual(kw['returncode'],2)
   self.assertEqual(kw['status'],self.fixture.gpg_status)
   return {'verifiedPrimaryFingerprints':['synthetic-policy-seam']}
  with mock.patch.object(h,'read_regular',side_effect=self.fixture.tool_read),\
       mock.patch.object(h,'host_path_facts',side_effect=self.fixture.host_path_facts),\
       mock.patch.object(self.fixture.policy,'classify',side_effect=checked):
   port.install_host_tools();port.authenticate_metadata()
  self.assertIsNone(port.first_failure)
  self.assertTrue(any(r['status']=='refused'for r in port.commands if r['role']=='gpgv_metadata'))
  self.assertFalse((port.artifacts/'host-stdout.bin').exists())
  self.assertFalse((port.artifacts/'host-stderr.bin').exists())
 def test_incomplete_gpg_exit_two_preserves_first_cause(self):
  self.fixture.gpg_exit=2;self.fixture.gpg_changes={'streamsEOF':False}
  port=self.fixture.new_port()
  with mock.patch.object(h,'read_regular',side_effect=self.fixture.tool_read),\
       mock.patch.object(h,'host_path_facts',side_effect=self.fixture.host_path_facts):
   port.install_host_tools()
   with self.assertRaisesRegex(h.Refusal,'host.gpgv_process_boundary'):
    port.authenticate_metadata()
  self.assertEqual(port.first_failure['role'],'gpgv_metadata')
  self.assertTrue((port.artifacts/'host-stdout.bin').exists())
 def test_gpg_exit_two_with_cleanup_error_never_reaches_policy(self):
  self.fixture.gpg_exit=2;self.fixture.gpg_changes={'cleanupErrors':[{'phase':'close'}]}
  port=self.fixture.new_port()
  with mock.patch.object(h,'read_regular',side_effect=self.fixture.tool_read),\
       mock.patch.object(h,'host_path_facts',side_effect=self.fixture.host_path_facts):
   port.install_host_tools()
   with self.assertRaisesRegex(h.Refusal,'host.gpgv_process_boundary'):
    port.authenticate_metadata()
  self.assertEqual(port.first_failure['role'],'gpgv_metadata')
 def test_missing_bootctl_package_or_ownership_refuses_before_build(self):
  for missing,reason in (('version','host.package_version'),('owner','host.bootctl_package')):
   with self.subTest(missing=missing):
    with tempfile.TemporaryDirectory(prefix='ocv-public-bootctl-') as root:
     fixture=ContractFixture(root);fixture.dpkg_missing=missing
     result=fixture.run()
     self.assertEqual(result['phase'],'host-tools')
     self.assertEqual(result['reason'],reason)
     self.assertFalse(any(scope.role=='mkosi_build' for scope in fixture.commands.calls))
 def test_missing_wrong_or_substituted_host_prerequisite_refuses_before_build(self):
  expected={'kmod_version':'host.package_version',
            'depmod_filelist':'host.package_filelist',
            'depmod_owner':'host.package_owner',
            'mkfs_owner':'host.package_owner',
            'depmod_substitute':'host.package_alias_identity',
            'depmod_target':'host.package_target_owner'}
  for defect,reason in expected.items():
   with self.subTest(defect=defect):
    with tempfile.TemporaryDirectory(prefix='ocv-public-host-tool-') as root:
     fixture=ContractFixture(root);fixture.dpkg_missing=defect
     result=fixture.run()
     self.assertEqual((result['phase'],result['reason']),('host-tools',reason))
     self.assertFalse(any(scope.role=='mkosi_build' for scope in fixture.commands.calls))
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
   self.assertIn('repair/manifest.json',names)
   self.assertEqual(archive.extractfile('repair/selinux-utils.deb').read(),REPAIR_RAW)
   repair=json.loads(archive.extractfile('repair/manifest.json').read())
   self.assertFalse(repair['privateVmInstallationPerformed'])
   self.assertEqual(repair['package']['sha256'],REPAIR_SHA)
   self.assertFalse(any(Path(name).name in build.OUTPUT_FILES for name in names))
  final=json.loads((port.artifacts/'host-result.json').read_bytes())
  self.assertEqual(final['status'],'passed');self.assertIsNone(final['failure'])
  # This deliberately synthetic path result cannot establish actual Linux proof.
  self.assertTrue(all(scope.environment==SyntheticCommands.ENV or scope.role.startswith('ubuntu_apt_')
   for scope in self.fixture.commands.calls))
 def test_required_security_key_with_extra_valid_signer_runs_complete_controller_and_packer(self):
  self.fixture.security_status=extra_valid_security_signature(self.fixture.security_status)
  result=self.fixture.run()
  self.assertEqual(result['status'],'passed',getattr(self.fixture.port,'failure',result))
  self.assertEqual(self.fixture.port.security_metadata['verifiedPrimaryFingerprints'],
   sorted(set(policy.SECURITY_PRIMARIES)|{'C'*40}))
  self.assertEqual(self.fixture.qemu_calls,1)
 def test_missing_required_and_bad_security_signers_refuse_before_build_with_exact_bounded_facts(self):
  original=self.fixture.security_status
  for status,parsed in ((extra_valid_security_signature(b''),True),
    (original+b'[GNUPG:] BADSIG PRIVATE_UID_NEVER_EXPORTED\n',False)):
   with self.subTest(parsed=parsed),tempfile.TemporaryDirectory(prefix='ocv-security-refusal-')as root:
    fixture=ContractFixture(root);fixture.security_status=status
    result=fixture.run();self.assertEqual(result['phase'],'signed-metadata')
    failure=fixture.port.failure;facts=failure['securitySignatures']
    self.assertEqual(facts['statusBytes'],len(status));self.assertEqual(facts['statusSha256'],SHA(status))
    self.assertIs(facts['statusParsed'],parsed);self.assertFalse(facts['requiredPrimaryPresent'])
    self.assertFalse(facts['newAuthenticationAuthority']);self.assertLessEqual(len(C(facts)),1024)
    self.assertNotIn(b'PRIVATE_UID',C(facts));self.assertEqual(fixture.qemu_calls,0)
    self.assertFalse(any(row.role=='mkosi_build'for row in fixture.commands.calls))
    saved=json.loads((fixture.port.artifacts/'host-result.json').read_bytes())
    self.assertEqual(saved['failure']['securitySignatures'],facts)
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
