"""Pure role validation and fake-owned-IO tests, never minting a native permit."""
import ast
import dataclasses
import stat
import struct
import importlib.util
import os
from pathlib import Path
import signal
import sys
import tempfile
import types
import unittest
from uuid import UUID
from unittest import mock
import host_context as h
import integrated_fixture

CANDIDATE_OUTER=(Path(__file__).resolve().parent/'outer_supervision.py',
 Path(__file__).resolve().parents[2]/'outer-supervision-r2/outer_supervision.py')
P=next((candidate for candidate in CANDIDATE_OUTER if candidate.is_file()),None)
assert P is not None, 'exact reviewed outer source must be exported or retained locally'
raw=P.read_bytes();assert h.sha(raw)==h.OUTER_SHA
name='host_context_exact_reviewed_outer';outer=types.ModuleType(name);outer.__file__=str(P);sys.modules[name]=outer
exec(compile(raw,str(P),'exec'),outer.__dict__)


def expected():return {'expected_source':'a'*40,'expected_tree':'b'*40,'workflow_sha':'c'*64,
 'source_manifest_sha':'d'*64,'source_manifest_path':'PUBLIC-SOURCE-MANIFEST.json','run_id':'42'}
def role_facts():return {'platform':'linux','machine':'x86_64','ubuntuId':'ubuntu','ubuntuVersion':'24.04','uid':1001,'gid':1001,
 'environment':{'GITHUB_ACTIONS':'true','RUNNER_OS':'Linux','RUNNER_ARCH':'X64','RUNNER_ENVIRONMENT':'github-hosted',
 'GITHUB_REPOSITORY':h.REPOSITORY,'GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_REF':h.REF,
 'GITHUB_WORKFLOW_REF':h.WORKFLOW_REF,'GITHUB_SHA':'a'*40,'GITHUB_RUN_ID':'42','GITHUB_RUN_ATTEMPT':'1'}}


class Stream:
 def __init__(self,fd):self.fd=fd;self.closed=False
 def fileno(self):return self.fd
 def close(self):self.closed=True


class Selector:
 def __init__(self,io):self.io=io;self.keys=[];self.closed=False
 def register(self,stream,event,name):
  self.keys.append(types.SimpleNamespace(fileobj=stream,data=name))
  if self.io.selector_fault:raise OSError(5,'synthetic PRIVATE selector registration failure')
 def unregister(self,stream):self.keys=[k for k in self.keys if k.fileobj is not stream]
 def select(self,duration):
  self.io.clock+=max(duration,0.01)
  if self.io.select_fault:
   self.io.select_fault=False;raise OSError('synthetic select failure')
  return [(key,1)for key in list(self.keys)]
 def close(self):
  self.closed=True
  if self.io.close_fault:raise OSError('synthetic selector close')


class Child:
 def __init__(self,io):self.io=io;self.pid=123;self.stdout=Stream(5);self.stderr=Stream(6);self.code=None
 def poll(self):
  if self.io.timeout:return None
  self.code=0;self.io.alive=False;return 0
 def wait(self,timeout):
  self.io.calls.append(('wait',self.pid))
  if self.io.wait_fault:raise TimeoutError('synthetic wait')
  return self.code if self.code is not None else -15


class FakeIO:
 synthetic=True
 def __init__(self):
  self.clock=0.;self.calls=[];self.alive=True;self.timeout=False;self.selector_fault=False
  self.selector_create_fault=False
  self.select_fault=False;self.close_fault=False;self.wait_fault=False;self.read_fault=False
  self.spawn_fault=False;self.term_fault=False;self.group_fault=False;self.reads={5:[b'public result\n',b''],6:[b'']}
 def selector(self):
  if self.selector_create_fault:raise OSError(5,'PRIVATE synthetic selector creation')
  self.sel=Selector(self);return self.sel
 def spawn(self,argv,cwd,environment):
  self.calls.append(('spawn',argv,cwd,dict(environment)))
  if self.spawn_fault:raise OSError('PRIVATE synthetic spawn')
  self.child=Child(self);return self.child
 def nonblocking(self,fd):self.calls.append(('nonblocking',fd))
 def read(self,fd,cap):
  if self.read_fault:self.read_fault=False;raise OSError('synthetic read')
  rows=self.reads[fd];return rows.pop(0)if rows else b''
 def killpg(self,pid,which):
  self.calls.append(('signal',pid,which))
  if which==0:
   if self.group_fault:self.group_fault=False;raise PermissionError('synthetic group')
   if not self.alive:raise ProcessLookupError
   return None
  if which==signal.SIGTERM and self.term_fault:self.term_fault=False;raise PermissionError('synthetic TERM')
  self.alive=False
  if hasattr(self,'child'):self.child.code=-15 if which==signal.SIGTERM else -9
 def now(self):return self.clock
 def pause(self,seconds):self.clock+=seconds


class Host(unittest.TestCase):
 def test_pure_positive_role_is_not_a_native_permit(self):
  result=h.validate_role_facts(role_facts(),expected(),'e'*32)
  self.assertIs(result['nativePermitIssued'],False);self.assertNotIsInstance(result,h.NativePermit)
  self.assertEqual(h._ISSUED,{})
  with self.assertRaisesRegex(h.Refusal,'host.permit_unissued'):h.NativePermit(None)
 def test_mac_factory_refuses_before_osrelease_source_git_or_native_io(self):
  with mock.patch.object(h.sys,'platform','darwin'),mock.patch.object(h,'_os_release',side_effect=AssertionError('osread')), \
       mock.patch.object(h,'_bootstrap_git',side_effect=AssertionError('git')),mock.patch.object(h.NativeIO,'spawn',side_effect=AssertionError('spawn')):
   with self.assertRaisesRegex(h.Refusal,'host.native_role'):h.make_native_permit('/unread',expected(),'e'*32)
 def test_each_runner_identity_environment_and_workflow_join_is_mandatory(self):
  for key in role_facts()['environment']:
   facts=role_facts();facts['environment'][key]='wrong'
   with self.subTest(key=key),self.assertRaisesRegex(h.Refusal,'host.github_role'):h.validate_role_facts(facts,expected(),'e'*32)
  facts=role_facts();facts['environment']['GITHUB_TOKEN']='never acceptable'
  with self.assertRaises(h.Refusal):h.validate_role_facts(facts,expected(),'e'*32)
 def test_linux_arch_ubuntu_version_uid_and_expected_inputs_cannot_be_spoofed_by_passed_json(self):
  for key,value in (('platform','darwin'),('machine','arm64'),('ubuntuVersion','22.04'),('uid',0),('gid',False)):
   facts=role_facts();facts[key]=value
   with self.subTest(key=key),self.assertRaises(h.Refusal):h.validate_role_facts(facts,expected(),'e'*32)
  e=expected();e['passed']=True
  with self.assertRaises(h.Refusal):h.validate_role_facts(role_facts(),e,'e'*32)
 def test_public_host_apis_reject_plain_dicts_and_cli_before_any_spawn(self):
  with mock.patch.object(h.NativeIO,'spawn',side_effect=AssertionError('native')):
   for call in (lambda:h.HostProcessOps({},{}),lambda:h.seal_command({},'git_read',{},cwd='/',environment={}),
                lambda:h.run_owned({},('/usr/bin/git',),cwd='/',environment={},deadline=1),
                lambda:h.initialize_integrated_test_image({},'/unread'),lambda:h.main([])):
    with self.assertRaises(h.Refusal):call()
  self.assertEqual(h._ISSUED,{})
 def test_closed_child_environment_has_no_github_credentials_or_extra_apt_keys(self):
  for role in h.ROLE_MAP:
   env=dict(h.ENV)
   if role.startswith('ubuntu_apt_'):env['DEBIAN_FRONTEND']='noninteractive'
   self.assertEqual(h._environment(role,env),env)
   env['GITHUB_TOKEN']='synthetic-token'
   with self.assertRaisesRegex(h.Refusal,'host.closed_environment'):h._environment(role,env)
  with self.assertRaises(h.Refusal):h._environment('git_read',{**h.ENV,'DEBIAN_FRONTEND':'noninteractive'})
 def test_manifest_guest_mode_does_not_require_git_checkout_readonly_bits(self):
  rows=[{'path':x,'bytes':1,'sha256':'a'*64,'mode':0o444}for x in
   ('host/host_context.py','host/outer_supervision.py','host/command_factories.py','build/build_recipe.py')]
  result=h._source_manifest(h.canonical({'schema':'ocv-public-source-v1','files':rows}))
  self.assertEqual(len(result),4)
  for bad in (rows+rows[:1],[{**rows[0],'path':'../outside'}]+rows[1:]):
   with self.assertRaises(h.Refusal):h._source_manifest(h.canonical({'schema':'ocv-public-source-v1','files':bad}))
 def test_scope_is_immutable_and_environment_is_copy(self):
  p=types.SimpleNamespace(consumed=set());env=tuple(sorted(h.ENV.items()))
  scope=h._Scope(p,'git_read',('/usr/bin/git',),'/synthetic',env,'a'*64)
  returned=scope.environment;returned['GITHUB_TOKEN']='never forwarded'
  self.assertEqual(scope.environment,h.ENV)
  with self.assertRaises(dataclasses.FrozenInstanceError):scope.argv=('/bin/sh','-c','bad')
  self.assertFalse(scope.consumed)
 def test_public_project_root_requires_canonical_root_owned_sticky_tmp(self):
  root=Path('/tmp')
  good=types.SimpleNamespace(st_uid=0,st_mode=stat.S_IFDIR|0o1777)
  with mock.patch.object(h.Path,'resolve',lambda p:p),mock.patch.object(h.Path,'lstat',return_value=good):
   self.assertEqual(h._public_project_root(),root)
  for uid,mode in ((1001,stat.S_IFDIR|0o1777),(0,stat.S_IFDIR|0o0777),
                   (0,stat.S_IFDIR|0o0755),(0,stat.S_IFLNK|0o1777)):
   with self.subTest(uid=uid,mode=mode),mock.patch.object(h.Path,'resolve',lambda p:p), \
        mock.patch.object(h.Path,'lstat',return_value=types.SimpleNamespace(st_uid=uid,st_mode=mode)), \
        self.assertRaisesRegex(h.Refusal,'host.public_project_root'):
    h._public_project_root()
  with mock.patch.object(h.Path,'resolve',lambda p:Path('/private/tmp')), \
       mock.patch.object(h.Path,'lstat',return_value=good), \
       self.assertRaisesRegex(h.Refusal,'host.public_project_root'):
   h._public_project_root()


class ProjectAndSources(unittest.TestCase):
 def setUp(self):
  self.project=Path('/runner/temp/ocv-'+'e'*32)
  self.permit=types.SimpleNamespace(project=self.project,uid=1001,gid=1001,mission='e'*32,
    run_id='42',expected=expected())
 def project_facts(self,path,mode=0o755,bad_ancestor=None):
  bits=0o700 if path==bad_ancestor else mode if path in(self.project,self.project/'negative') else 0o755
  return types.SimpleNamespace(st_uid=1001,st_mode=stat.S_IFDIR|bits)
 def check_project(self,path,allow=False,mode=0o755,bad_ancestor=None):
  with mock.patch.object(h.Path,'resolve',lambda p:p),mock.patch.object(h.Path,'is_dir',return_value=True), \
       mock.patch.object(h.Path,'stat',lambda p:self.project_facts(p,mode,bad_ancestor)):
   return h._project(self.permit,str(path),allow_negative=allow)
 def test_public_project_requires0755_and_traversable_ancestors(self):
  self.assertEqual(self.check_project(self.project),str(self.project))
  for mode in(0o700,0o750,0o775,0o777):
   with self.subTest(mode=mode),self.assertRaisesRegex(h.Refusal,'host.owned_project_mode'):
    self.check_project(self.project,mode=mode)
  with self.assertRaisesRegex(h.Refusal,'host.project_ancestor_traverse'):
   self.check_project(self.project,bad_ancestor=self.project.parent)
  self.assertEqual(h._ISSUED,{})
 def test_public_tmp_project_keeps_ancestor_guard_without_runner_temp_parent(self):
  self.project=Path('/tmp/ocv-'+'e'*32);self.permit.project=self.project
  self.assertEqual(self.check_project(self.project),str(self.project))
  with self.assertRaisesRegex(h.Refusal,'host.project_ancestor_traverse'):
   self.check_project(self.project,bad_ancestor=Path('/tmp'))
 def test_old_project_predicate_reproduces_public_mode_refusal(self):
  oldpath=Path(__file__).parent/'review/host-context-r1-94ab37617e79/host_context.py'
  raw=oldpath.read_bytes();self.assertEqual(h.sha(raw),'94ab37617e7951a7f0f127e4bd65437eeb8f3c7a4d12b573779ae490caa200d2')
  node=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name=='_project')
  namespace={'Path':Path,'need':h.need,'stat':stat}
  exec(compile(ast.fix_missing_locations(ast.Module(body=[node],type_ignores=[])),'frozen-old-project-check','exec'),namespace)
  with mock.patch.object(h.Path,'resolve',lambda p:p),mock.patch.object(h.Path,'is_dir',return_value=True), \
       mock.patch.object(h.Path,'stat',lambda p:self.project_facts(p)):
   with self.assertRaisesRegex(h.Refusal,'host.owned_project_mode'):namespace['_project'](self.permit,str(self.project))
   self.assertEqual(h._project(self.permit,str(self.project)),str(self.project))
 def test_negative_subproject_is_explicit_and_cannot_expand_to_other_paths(self):
  negative=self.project/'negative'
  self.assertEqual(self.check_project(negative,True),str(negative))
  for path in(negative,self.project/'other',negative/'nested',self.project.parent/'outside'):
   with self.subTest(path=str(path)),self.assertRaisesRegex(h.Refusal,'host.owned_project'):
    self.check_project(path,False)
  with self.assertRaisesRegex(h.Refusal,'host.owned_project'):self.check_project(self.project/'other',True)
 def prepare(self,relative='etc/systemd/system/multi-user.target.wants/ocv-ci-proof.service',link_target='../ocv-ci-proof.service',escape=False,missing=False):
  extra=self.project/'extra';child=extra/relative;dest=extra/'etc/systemd/system/ocv-ci-proof.service'
  def resolved(path):
   if path==child:return extra.parent/'outside' if escape else dest
   return path
  def walk(top,**kwargs):
   self.assertFalse(kwargs['followlinks'])
   return iter([(str(child.parent),[],[child.name])])if top==extra else iter([])
  with mock.patch.object(h.Path,'is_dir',return_value=True),mock.patch.object(h.Path,'resolve',resolved), \
       mock.patch.object(h.Path,'is_symlink',lambda p:p==child),mock.patch.object(h.Path,'is_file',lambda p:p==dest and not missing), \
       mock.patch.object(h.os,'walk',side_effect=walk),mock.patch.object(h.os,'readlink',return_value=link_target):
   h._prepare_tree(str(self.project))
 def test_only_exact_generated_wantedby_link_is_allowed(self):
  self.prepare()
  for options in ({'relative':'etc/systemd/system/unknown.service'}, {'link_target':'../../../../etc/shadow'},
                  {'link_target':'/etc/systemd/system/ocv-ci-proof.service'}, {'escape':True},{'missing':True}):
   with self.subTest(options=options),self.assertRaisesRegex(h.Refusal,'host.chown_tree'):self.prepare(**options)
 def test_output_chown_is_refused_before_tree_observation(self):
  with mock.patch.object(h,'_prepare_tree',side_effect=AssertionError('must not inspect tree')):
   with self.assertRaisesRegex(h.Refusal,'host.output_owner'):
    h._prepare_chown({'phase':'output','owner':'1001:1001','project':str(self.project)})
 def test_qemu_identity_is_canonical_digit_strings_only_and_positive_out(self):
  # Fixed binary metadata is not an image build or a filesystem. The actual
  # source-loaded validator must inspect it, in addition to the full hash.
  raw=bytearray(64*1024*1024);raw[:512]=integrated_fixture.test_image_header()
  start=1048576+1024
  struct.pack_into('<I',raw,start+4,16128)
  struct.pack_into('<I',raw,start+0x18,2)
  struct.pack_into('<H',raw,start+0x38,0xef53)
  raw[start+0x68:start+0x78]=UUID('56b32afd-9976-4d21-9720-c4d5fcd02751').bytes
  raw=bytes(raw)
  arguments={'session':self.permit.mission,'bound':{'directory':str(self.project/'out'),
   'sourceManifestSha256':expected()['source_manifest_sha'],'runIdentity':{'repository':h.REPOSITORY,
    'workflowRef':h.WORKFLOW_REF,'sourceCommit':expected()['expected_source'],'runId':'42','runAttempt':'1'}},
    'test_record':{'name':'integrated-test.raw','bytes':64*1024*1024,'sha256':h.sha(raw)}}
  fixture_path=Path(integrated_fixture.__file__).resolve()
  self.permit.source=fixture_path.parent.parent
  self.permit.rows={'integrated/integrated_fixture.py':{'sha256':h.sha(fixture_path.read_bytes())}}
  facts=types.SimpleNamespace(st_mode=stat.S_IFREG|0o444,st_uid=0,st_gid=0,st_nlink=1,st_size=64*1024*1024)
  with mock.patch.object(h.Path,'lstat',return_value=facts),mock.patch.object(h.Path,'resolve',lambda p:p),\
       mock.patch.object(h,'_read_regular',side_effect=lambda path,cap,**kw:
        raw if Path(path).name=='integrated-test.raw' else fixture_path.read_bytes()):
   h._qemu_arguments(self.permit,arguments)
  with self.assertRaisesRegex(h.Refusal,'host.integrated_image_record'):
   h._qemu_arguments(self.permit,{**arguments,'test_record':{**arguments['test_record'],'sha256':'0'}})
  for key,value in(('runId',42),('runAttempt',1)):
   changed={**arguments,'bound':{**arguments['bound'],'runIdentity':{**arguments['bound']['runIdentity'],key:value}}}
   with self.subTest(key=key),self.assertRaisesRegex(h.Refusal,'host.qemu_arg'):h._qemu_arguments(self.permit,changed)
  changed={**arguments,'bound':{**arguments['bound'],'directory':str(self.project/'negative/out')}}
  with self.assertRaises(h.Refusal):h._qemu_arguments(self.permit,changed)
 def test_exact_freeze_targets_require_root_regular_singlelink_immutable_ready_sources(self):
  calls=[]
  def info(path):
   calls.append(str(path));return types.SimpleNamespace(st_mode=stat.S_IFREG|0o644,st_uid=0,st_gid=0,st_nlink=1)
  with mock.patch.object(h.Path,'resolve',lambda p:p),mock.patch.object(h.Path,'is_symlink',return_value=False), \
       mock.patch.object(h.Path,'lstat',info):h._freeze_outputs(str(self.project))
  self.assertEqual(calls,[str(self.project/'out'/n)for n in('ocv-test.raw','kernel.bin','initrd.img','integrated-test.raw')])
  for field,value in(('st_uid',1001),('st_gid',1001),('st_nlink',2),('st_mode',stat.S_IFDIR|0o755),('st_mode',stat.S_IFREG|0o666)):
   bad=types.SimpleNamespace(st_mode=stat.S_IFREG|0o644,st_uid=0,st_gid=0,st_nlink=1);setattr(bad,field,value)
   with mock.patch.object(h.Path,'resolve',lambda p:p),mock.patch.object(h.Path,'is_symlink',return_value=False), \
        mock.patch.object(h.Path,'lstat',return_value=bad),self.assertRaisesRegex(h.Refusal,'host.freeze_identity'):
    h._freeze_outputs(str(self.project))
  with mock.patch.object(h.Path,'resolve',lambda p:p),mock.patch.object(h.Path,'is_symlink',return_value=True), \
       self.assertRaisesRegex(h.Refusal,'host.freeze_target'):h._freeze_outputs(str(self.project))
 def test_mkosi_output_owner_correction_is_exact_four_file_vector(self):
  import command_factories as factory
  args={'project':str(self.project),'uid':1001,'gid':1001}
  exact=factory.own_mkosi_outputs(**args)
  self.assertEqual(exact,('/usr/bin/sudo','-n','--','/usr/bin/chown','--from=1001:1001',
                          '--','0:0',*(str(self.project/'out'/name) for name in
                           ('ocv-test.raw','kernel.bin','initrd.img','integrated-test.raw'))))
  good=types.SimpleNamespace(st_mode=stat.S_IFREG|0o644,st_uid=1001,st_gid=1001,st_nlink=1,st_size=100)
  with mock.patch.object(h.Path,'resolve',lambda p:p),mock.patch.object(h.Path,'is_symlink',return_value=False), \
       mock.patch.object(h.Path,'lstat',return_value=good):h._preflight_mkosi_outputs(self.permit,args)
  for field,value in (('st_uid',0),('st_gid',0),('st_nlink',2),('st_size',0),('st_mode',stat.S_IFDIR|0o755),
                      ('st_mode',stat.S_IFREG|0o664)):
   bad=types.SimpleNamespace(**vars(good));setattr(bad,field,value)
   with self.subTest(field=field,value=value),mock.patch.object(h.Path,'resolve',lambda p:p), \
        mock.patch.object(h.Path,'is_symlink',return_value=False), \
        mock.patch.object(h.Path,'lstat',return_value=bad), \
        self.assertRaisesRegex(h.Refusal,'host.mkosi_outputs_identity'):
    h._preflight_mkosi_outputs(self.permit,args)
  with self.assertRaisesRegex(h.Refusal,'host.mkosi_outputs_owner'):
   h._preflight_mkosi_outputs(self.permit,{**args,'uid':1002})
  with mock.patch.object(h.Path,'resolve',lambda p:p),mock.patch.object(h.Path,'is_symlink',return_value=True), \
       self.assertRaisesRegex(h.Refusal,'host.mkosi_outputs_path'):
   h._preflight_mkosi_outputs(self.permit,args)
 def test_mkosi_staging_roster_normalizes_only_exact_public_sidecars(self):
  with tempfile.TemporaryDirectory() as directory:
   project=Path(directory).resolve();out=project/'out';out.mkdir(mode=0o755)
   for name in h.MKOSI_STAGE_DIRS:(out/('ocv-test-'+name)).mkdir(mode=0o755)
   for name in h.MKOSI_STAGE_FILES:(out/('ocv-test-'+name)).write_bytes(b'public')
   (out/'ocv-test.raw').write_bytes(b'untouched-image-marker')
   original=h.Path.lstat
   def staged_stat(path):
    info=original(path)
    if path.name in {*h.MKOSI_STAGE_DIRS,*(('ocv-test-'+n) for n in h.MKOSI_STAGE_DIRS)}:
     return types.SimpleNamespace(**{**{key:getattr(info,key) for key in
       ('st_dev','st_ino','st_mode','st_uid','st_gid','st_size')},'st_uid':0,'st_gid':0})
    return info
   with mock.patch.object(h.Path,'lstat',staged_stat):
    h._normalize_mkosi_roster(str(project),os.getuid(),os.getgid())
   for name in (*h.MKOSI_STAGE_DIRS,*h.MKOSI_STAGE_FILES):
    self.assertTrue((out/name).exists());self.assertFalse((out/('ocv-test-'+name)).exists())
   self.assertEqual((out/'ocv-test.raw').read_bytes(),b'untouched-image-marker')
  with tempfile.TemporaryDirectory() as directory:
   project=Path(directory).resolve();out=project/'out';out.mkdir(mode=0o755)
   with self.assertRaisesRegex(h.Refusal,'host.mkosi_stage_path'):
    h._normalize_mkosi_roster(str(project),os.getuid(),os.getgid())
   self.assertEqual(list(out.iterdir()),[])
  with tempfile.TemporaryDirectory() as directory:
   project=Path(directory).resolve();out=project/'out';out.mkdir(mode=0o755)
   for name in h.MKOSI_STAGE_DIRS:(out/('ocv-test-'+name)).mkdir(mode=0o755)
   for name in h.MKOSI_STAGE_FILES:(out/('ocv-test-'+name)).write_bytes(b'public')
   (out/'ocv-test-build.json').chmod(0o666)
   original=h.Path.lstat
   def staged_stat(path):
    info=original(path)
    if path.name in {*h.MKOSI_STAGE_DIRS,*(('ocv-test-'+n) for n in h.MKOSI_STAGE_DIRS)}:
     return types.SimpleNamespace(**{**{key:getattr(info,key) for key in
       ('st_dev','st_ino','st_mode','st_uid','st_gid','st_size')},'st_uid':0,'st_gid':0})
    return info
   with mock.patch.object(h.Path,'lstat',staged_stat),self.assertRaisesRegex(h.Refusal,'host.mkosi_stage_file'):
    h._normalize_mkosi_roster(str(project),os.getuid(),os.getgid())
   self.assertTrue((out/'ocv-test-apt-data').exists())
   self.assertFalse((out/'apt-data').exists())
 def test_repair_staging_directory_refuses_missing_alias_owner_mode_and_existing_target_before_rename(self):
  self.assertIn('repair',h.MKOSI_STAGE_DIRS)
  for defect in('missing','symlink','not_directory','owner','mode','existing_target'):
   with self.subTest(defect=defect),tempfile.TemporaryDirectory()as directory:
    project=Path(directory).resolve();out=project/'out';out.mkdir(mode=0o755)
    for name in('apt-data','runtime','repair'):(out/('ocv-test-'+name)).mkdir(mode=0o755)
    for name in h.MKOSI_STAGE_FILES:(out/('ocv-test-'+name)).write_bytes(b'public')
    repair=out/'ocv-test-repair'
    if defect=='missing':repair.rmdir()
    if defect=='symlink':
     repair.rmdir();target=project/'foreign';target.mkdir();repair.symlink_to(target,target_is_directory=True)
    if defect=='not_directory':repair.rmdir();repair.write_bytes(b'public')
    if defect=='mode':repair.chmod(0o777)
    if defect=='existing_target':(out/'repair').mkdir()
    original=h.Path.lstat
    def staged_stat(path):
     info=original(path)
     if path.name in('ocv-test-apt-data','ocv-test-runtime','ocv-test-repair'):
      return types.SimpleNamespace(**{**{key:getattr(info,key)for key in
       ('st_dev','st_ino','st_mode','st_uid','st_gid','st_size')},
       'st_uid':123456 if path==repair and defect=='owner'else 0,'st_gid':0})
     return info
    code='host.mkosi_stage_path'if defect in('missing','symlink','existing_target')else'host.mkosi_stage_directory'
    with mock.patch.object(h.Path,'lstat',staged_stat),self.assertRaisesRegex(h.Refusal,code):
     h._normalize_mkosi_roster(str(project),os.getuid(),os.getgid())
    self.assertTrue((out/'ocv-test-apt-data').exists());self.assertFalse((out/'apt-data').exists())
    self.assertTrue((out/'ocv-test-build.json').exists());self.assertFalse((out/'build.json').exists())
 def test_actual_current_factory_roles_ten_suites_and_exact_readonly_output_command(self):
  root=Path(__file__).resolve().parents[1];modules={}
  for relative,function in h.ROLE_MAP.values():
   tree=ast.parse((root/relative).read_bytes());functions={n.name for n in tree.body if isinstance(n,ast.FunctionDef)}
   self.assertIn(function,functions)
  import command_factories as factory
  self.assertEqual(len(factory.SUITES),10);self.assertIn('integrated',factory.SUITES)
  self.assertEqual(factory.freeze_public_outputs(str(self.project)),('/usr/bin/sudo','-n','--','/usr/bin/chmod','0444','--',
   *(str(self.project/'out'/n)for n in('ocv-test.raw','kernel.bin','initrd.img','integrated-test.raw'))))
  self.assertEqual(h._ISSUED,{})

 def test_only_build_and_prepare_roles_can_admit_the_single_negative_project(self):
  for role in h.ROLE_MAP:
   expected_allowed=role in('mkosi_build','own_project_chown')
   self.assertEqual(h._allow_negative(role,{'phase':'prepare'}),expected_allowed)
  self.assertFalse(h._allow_negative('own_project_chown',{'phase':'output'}))
 def test_readonly_output_vector_cannot_change_modes_targets_or_argument_count(self):
  import command_factories as factory
  exact=factory.freeze_public_outputs(str(self.project));h._freeze_vector(str(self.project),exact)
  for mutated in (exact[:4]+('0777',)+exact[5:],exact[:-1]+('/etc/shadow',),exact[:-1],exact+('/tmp/unrelated',)):
   with self.subTest(argv=mutated),self.assertRaisesRegex(h.Refusal,'host.freeze_argv'):
    h._freeze_vector(str(self.project),mutated)


class OwnedIO(unittest.TestCase):
 def setUp(self):self.io=FakeIO();self.argv=('/usr/bin/recognized-fixture','fixed');self.env=dict(h.ENV)
 def execute(self):
  ops=h.SyntheticProcessOps(outer,self.argv,'/synthetic',self.env,self.io)
  return h._supervise_owned(ops,self.argv,cwd='/synthetic',environment=self.env,deadline=ops.now()+.5,grace=.1)
 def test_actual_reviewed_supervisor_waits_drains_and_closes_exact_owned_child(self):
  result=self.execute();self.assertEqual(result['status'],'outer_exit_passed')
  self.assertEqual(result['stdout'],b'public result\n');self.assertTrue(result['synthetic'])
  self.assertTrue(result['outerExited']);self.assertTrue(result['ownedGroupGone']);self.assertTrue(result['streamsEOF'])
  self.assertTrue(self.io.child.stdout.closed);self.assertTrue(self.io.child.stderr.closed)
  self.assertEqual(sum(c[0]=='spawn'for c in self.io.calls),1)
 def test_slow_intent_cannot_spawn_after_original_absolute_deadline(self):
  def intent():self.io.clock=.5
  ops=h._OwnedOps(outer,self.argv,'/synthetic',self.env,self.io,intent)
  result=h._supervise_owned(ops,self.argv,cwd='/synthetic',environment=self.env,deadline=.5,grace=.1)
  self.assertFalse(result['spawned']);self.assertFalse(self.io.calls)
  self.assertEqual(result['setupCause'],{'phase':'before_spawn','exceptionType':'Refusal',
   'errno':None,'reason':'host.spawn_deadline'})
  self.assertEqual(ops.spawn_deadline,.5)
 def test_slow_selector_closes_without_process_after_original_deadline(self):
  original=self.io.selector
  def selector():
   result=original();self.io.clock=.5;return result
  self.io.selector=selector
  ops=h.SyntheticProcessOps(outer,self.argv,'/synthetic',self.env,self.io)
  result=h._supervise_owned(ops,self.argv,cwd='/synthetic',environment=self.env,deadline=.5,grace=.1)
  self.assertFalse(result['spawned']);self.assertTrue(self.io.sel.closed)
  self.assertFalse(any(call[0]=='spawn' for call in self.io.calls))
  self.assertEqual(result['setupCause'],{'phase':'process_spawn','exceptionType':'Refusal',
   'errno':None,'reason':'host.spawn_deadline'})
 def test_qemu_intent_or_selector_cannot_spend_preparation_reserve_before_popen(self):
  for phase in ('intent','selector'):
   self.setUp();original=self.io.selector
   def intent():
    if phase=='intent':self.io.clock=.5
   def selector():
    value=original()
    if phase=='selector':self.io.clock=.5
    return value
   self.io.selector=selector
   ops=h._OwnedOps(outer,self.argv,'/synthetic',self.env,self.io,intent,launch_deadline=.5)
   result=h._supervise_owned(ops,self.argv,cwd='/synthetic',environment=self.env,deadline=10.,grace=.1)
   self.assertFalse(result['spawned']);self.assertEqual(ops.spawn_deadline,10.)
   self.assertFalse(any(call[0]=='spawn' for call in self.io.calls))
   self.assertEqual(result['setupCause']['reason'],'host.launch_deadline')
   if phase=='selector':self.assertTrue(self.io.sel.closed)
 def test_qemu_launch_cutoff_joins_original_first_step_clock_only(self):
  permit=types.SimpleNamespace(temp=Path('/synthetic'),uid=1001)
  raw=h.canonical({'schema':'ocv-job-clock-v1','monotonicNs':1000000000})
  with mock.patch.object(h,'_read_regular',return_value=raw),\
       mock.patch.object(h.time,'monotonic_ns',return_value=100000000000),\
       mock.patch.object(h.time,'monotonic',return_value=100.):
   h._qemu_launch_deadline(permit,551.)
   for value in (True,float('nan'),float('inf'),550.,552.):
    with self.subTest(value=value),self.assertRaises(h.Refusal):h._qemu_launch_deadline(permit,value)
  with mock.patch.object(h,'_read_regular',return_value=raw),\
       mock.patch.object(h.time,'monotonic_ns',return_value=600000000000),\
       mock.patch.object(h.time,'monotonic',return_value=551.):
   with self.assertRaisesRegex(h.Refusal,'host.launch_deadline'):h._qemu_launch_deadline(permit,551.)
 def test_spawn_deadline_is_fixed_and_rejects_unbounded_or_invalid_scopes(self):
  for value in (True,0,-1,float('nan'),float('inf'),2001):
   ops=h.SyntheticProcessOps(outer,self.argv,'/synthetic',self.env,self.io)
   with self.subTest(value=value),self.assertRaisesRegex(h.Refusal,'host.spawn_deadline_scope'):
    ops.set_spawn_deadline(value)
  ops=h.SyntheticProcessOps(outer,self.argv,'/synthetic',self.env,self.io)
  ops.set_spawn_deadline(.5)
  with self.assertRaisesRegex(h.Refusal,'host.spawn_deadline_scope'):ops.set_spawn_deadline(1.)
 def test_selector_registration_failure_retains_child_and_runs_independent_cleanup(self):
  self.io.selector_fault=True;result=self.execute()
  self.assertEqual(result['status'],'refused');self.assertTrue(result['spawned']);self.assertTrue(result['outerExited'])
  self.assertTrue(result['ownedGroupGone']);self.assertIn(('wait',123),self.io.calls)
  self.assertTrue(any(c[:2]==('signal',123)and c[2]==signal.SIGTERM for c in self.io.calls))
  self.assertEqual(result['setupCause'],{'phase':'stdout_register','exceptionType':'OSError','errno':5})
  self.assertNotIn('PRIVATE',str(result['setupCause']))
 def test_owned_spawn_refusal_preserves_fixed_setup_cause_before_supervision(self):
  self.io.selector_fault=True;ops=h.SyntheticProcessOps(outer,self.argv,'/synthetic',self.env,self.io)
  with self.assertRaises(outer.SpawnedRefusal) as caught:ops.spawn(self.argv,'/synthetic',self.env)
  self.assertEqual(caught.exception.setupCause,{'phase':'stdout_register','exceptionType':'OSError','errno':5})
  self.assertEqual(len(ops.owned),1);self.assertIs(caught.exception.process.child,self.io.child)
 def test_pre_spawn_refusal_preserves_bounded_cause_without_process_or_private_text(self):
  for failure,wanted in ((h.Refusal('host.owned_project'),
        {'phase':'before_spawn','exceptionType':'Refusal','errno':None,'reason':'host.owned_project'}),
       (h.Refusal('PRIVATE'),
        {'phase':'before_spawn','exceptionType':'Refusal','errno':None,'reason':None}),
       (OSError(17,'PRIVATE synthetic path'),
        {'phase':'before_spawn','exceptionType':'FileExistsError','errno':17,'reason':None})):
   with self.subTest(kind=type(failure).__name__):
    self.setUp()
    def refuse(error=failure):raise error
    ops=h._OwnedOps(outer,self.argv,'/synthetic',self.env,self.io,refuse)
    result=h._supervise_owned(ops,self.argv,cwd='/synthetic',environment=self.env,deadline=ops.now()+.5,grace=.1)
    self.assertEqual(result['status'],'refused');self.assertFalse(result['spawned'])
    self.assertEqual(result['setupCause'],wanted)
    self.assertNotIn('PRIVATE',str(result['setupCause']))
    self.assertFalse(any(call[0]=='spawn' for call in self.io.calls))
 def test_selector_creation_and_process_spawn_failures_keep_bounded_cause(self):
  for fault,wanted in (('selector_create_fault',
      {'phase':'selector_create','exceptionType':'OSError','errno':5,'reason':None}),
      ('spawn_fault',
      {'phase':'process_spawn','exceptionType':'OSError','errno':None,'reason':None})):
   with self.subTest(fault=fault):
    self.setUp();setattr(self.io,fault,True)
    result=self.execute()
    self.assertEqual(result['status'],'refused');self.assertFalse(result['spawned'])
    self.assertEqual(result['setupCause'],wanted)
    self.assertNotIn('PRIVATE',str(result['setupCause']))
    if fault=='spawn_fault':self.assertTrue(self.io.sel.closed)
 def test_process_spawn_failure_retains_original_cause_if_selector_close_fails(self):
  self.io.spawn_fault=True;self.io.close_fault=True
  result=self.execute()
  self.assertEqual(result['reason'],'outer_OSError')
  self.assertEqual(result['setupCause'],{'phase':'process_spawn','exceptionType':'OSError','errno':None,
                                         'reason':None,'selectorCloseExceptionType':'OSError'})
  self.assertFalse(result['spawned'])
 def test_read_or_select_failure_cannot_skip_wait_or_term(self):
  for name in ('read_fault','select_fault'):
   self.setUp();setattr(self.io,name,True);result=self.execute()
   self.assertEqual(result['status'],'refused');self.assertTrue(result['outerExited'])
   self.assertIn(('wait',123),self.io.calls);self.assertTrue(self.io.sel.closed)
 def test_timeout_complete_stdout_never_passes(self):
  self.io.timeout=True;result=self.execute();self.assertTrue(result['timedOut'])
  self.assertEqual(result['status'],'refused');self.assertEqual(result['stdout'],b'public result\n')
  self.assertTrue(result['outerExited']);self.assertTrue(result['ownedGroupGone'])
 def test_wait_or_close_failure_keeps_ownership_uncertain(self):
  for name in('wait_fault','close_fault'):
   self.setUp();setattr(self.io,name,True);result=self.execute()
   self.assertEqual(result['status'],'refused');self.assertTrue(result['ownershipRetained'])
 def test_spawn_error_does_not_adopt_unrelated_process(self):
  self.io.spawn_fault=True;result=self.execute();self.assertFalse(result['spawned'])
  self.assertFalse(any(c[0]=='wait'for c in self.io.calls));self.assertTrue(self.io.sel.closed)
 def test_one_spawn_only_exact_argv_environment_and_no_native_permit_minted(self):
  ops=h.SyntheticProcessOps(outer,self.argv,'/synthetic',self.env,self.io)
  with self.assertRaises(h.Refusal):ops.spawn(('/bin/sh','-c','arbitrary'),'/synthetic',self.env)
  self.assertFalse(self.io.calls)
  ops.spawn(self.argv,'/synthetic',self.env)
  with self.assertRaisesRegex(h.Refusal,'host.spawn_consumed'):ops.spawn(self.argv,'/synthetic',self.env)
  self.assertEqual(sum(c[0]=='spawn'for c in self.io.calls),1);self.assertEqual(h._ISSUED,{})
 def test_old_unissued_scope_globals_and_constructor_are_unchanged(self):
  self.assertIsNone(outer._PUBLISHED_CI_SCOPE);self.assertEqual(outer._CONSUMED_SCOPES,set())
  with mock.patch.object(outer.subprocess,'Popen',side_effect=AssertionError('native')):
   with self.assertRaisesRegex(outer.Refusal,'unissued_ci_scope'):outer.NativeOps(None)


if __name__=='__main__':unittest.main()
