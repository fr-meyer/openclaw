"""Synthetic public representations only. No Linux/native capability is issued."""
import ast
import json
from pathlib import Path
import unittest

import ci_authority
import copied_bootstrap_probe
import integrated_entry
import integrated_fixture
import integrated_materials
import runtime_sources
from protocol import Refusal, canonical, sha

HERE=Path(__file__).resolve().parent


class FakeIO:
    evidence_kind='synthetic_contract'


class PublicContractTests(unittest.TestCase):
    def test_fixed_fixture_and_profile_are_synthetic_and_closed(self):
        root=HERE/'fixture'
        files={p.relative_to(root).as_posix():p.read_bytes() for p in root.rglob('*') if p.is_file()}
        self.assertEqual(len(integrated_fixture.fixture_layout(files)),10)
        profile=json.loads((HERE/'PROFILE.template.private.json').read_bytes())
        self.assertEqual(set(profile),{'schema','properties','fixtureOnly','candidateImage'})
        self.assertTrue(profile['fixtureOnly']);self.assertEqual(len(profile['properties']),55)
    def test_synthetic_runtime_origin_cannot_join_native_io_or_caller_json(self):
        io=FakeIO();materials={role:role.encode() for role in runtime_sources.MATERIAL_CAPS}
        row={'path':'usr/bin/fixture','archivePath':'runtime/usr/bin/fixture',
             'bytes':1,'mode':0o555,'sha256':sha(b'x')}
        source=runtime_sources.synthetic_source(io,materials,{'files':[row]})
        source.assert_for('synthetic-contract',io)
        for kind in ('private-native','ci-native-proof'):
            with self.assertRaises(Refusal):source.assert_for(kind,io)
        with self.assertRaises(Refusal):source.assert_for('synthetic-contract',FakeIO())
        with self.assertRaises(Refusal):ci_authority.current_runtime_source({}, {}, object())
        with self.assertRaises(Refusal):runtime_sources.ci_build_source({'verified':True})
    def test_packaging_is_deterministic_and_has_no_parent_path_or_symlink_type(self):
        files={'usr/bin/a':(b'a',0o555),'lib/a':(b'b',0o444)}
        self.assertEqual(integrated_materials.archive_bytes(files),
            integrated_materials.archive_bytes(dict(reversed(list(files.items())))))
        with self.assertRaises(integrated_materials.Refusal):
            integrated_materials.archive_bytes({'usr/../a':(b'x',0o444)})
    def test_absolute_budget_retains_bounded_shutdown_and_no_clock_renewal(self):
        value=integrated_fixture.timing_preflight()
        self.assertEqual((value['jobSeconds'],value['plannedSeconds']),(2700,2670))
        self.assertEqual(value['guestWrapperSeconds'],2000)
        self.assertEqual(value['workerSeconds'],300)
    def test_probe_source_measures_children_and_never_mutates_search_path(self):
        source=Path(copied_bootstrap_probe.__file__).read_bytes()
        ast.parse(source)
        self.assertIn(b'bool(children.strip())',source)
        self.assertIn(b"'/proc/self/task/'",source)
        self.assertNotIn(b'sys.path.insert',source)
# Source-owned device appearance contracts.
"""Pure actual readiness-loop contracts. No Linux device is read or created."""
import stat
from types import SimpleNamespace
import unittest
from unittest import mock

import ci_authority as target
from protocol import Refusal


class Clock:
    def __init__(self):self.clock=10.;self.checks=0;self.pauses=[];self.observed=[];self.missing=2;self.owner=0;self.kind=stat.S_IFLNK;self.target_kind=stat.S_IFBLK;self.target_group=6
    def check(self):self.checks+=1
    def now(self):return self.clock
    def pause(self,seconds):self.pauses.append(seconds);self.clock+=seconds
    def lstat(self,path):
        self.observed.append(path)
        if self.missing and path==target._device_appearance_paths()[0]:
            self.missing-=1;raise FileNotFoundError(path)
        return SimpleNamespace(st_mode=self.kind|0o777,st_uid=self.owner,st_gid=0)
    def stat(self,path):return SimpleNamespace(st_mode=self.target_kind|0o660,st_uid=0,st_gid=self.target_group)


class DeviceReadinessTests(unittest.TestCase):
    def run_loop(self,clock,*,paths=None,deadline=40.):
        return target._poll_device_appearance(target._device_appearance_paths() if paths is None else paths,
            check=clock.check,now=clock.now,lstat=clock.lstat,stat_follow=clock.stat,pause=clock.pause,
            begin=10.,deadline=deadline)
    def test_delayed_fixed_aliases_yield_only_appearance_receipt(self):
        clock=Clock();result=self.run_loop(clock)
        self.assertTrue(result['appearanceOnly']);self.assertFalse(result['identityValidated'])
        self.assertEqual(result['attempts'],3);self.assertEqual(clock.checks,4)
        self.assertTrue(set(clock.observed)<=set(target._device_appearance_paths()))
        self.assertLessEqual(sum(clock.pauses),30)
    def test_absent_devices_stop_on_original_deadline_without_renewal(self):
        clock=Clock();clock.missing=1000
        with self.assertRaises(Refusal):self.run_loop(clock)
        self.assertLessEqual(clock.clock,40.000001);self.assertLessEqual(len(clock.pauses),301)
    def test_unexpected_alias_owner_or_type_refuses_immediately(self):
        for field,value in (('owner',1000),('kind',stat.S_IFREG),('target_kind',stat.S_IFREG),('target_group',1000)):
            clock=Clock();clock.missing=0;setattr(clock,field,value)
            with self.subTest(field=field),self.assertRaises(Refusal):self.run_loop(clock)
            self.assertEqual(clock.pauses,[])
    def test_other_os_errors_are_not_retried(self):
        clock=Clock();clock.missing=0
        def denied(_):raise PermissionError(13,'unpublished metadata error')
        clock.lstat=denied
        with self.assertRaises(PermissionError):self.run_loop(clock)
        self.assertEqual(clock.pauses,[])
    def test_parent_check_failure_stops_before_device_metadata(self):
        clock=Clock()
        def refuse():raise Refusal('test.parent_expired')
        clock.check=refuse
        with self.assertRaisesRegex(Refusal,'test.parent_expired'):self.run_loop(clock)
        self.assertEqual(clock.observed,[]);self.assertEqual(clock.pauses,[])
    def test_clock_regression_or_more_than_thirty_seconds_refuses(self):
        clock=Clock();clock.clock=9.
        with self.assertRaises(Refusal):self.run_loop(clock)
        for end in (10.,40.001,float('inf')):
            with self.subTest(end=end),self.assertRaises(Refusal):self.run_loop(Clock(),deadline=end)
    def test_substituted_path_or_duplicate_fixed_alias_never_reaches_metadata(self):
        for paths in (('/dev/other',)+target._device_appearance_paths()[1:],
                      (target._device_appearance_paths()[0],)*3):
            clock=Clock()
            with self.subTest(paths=paths),self.assertRaises(Refusal):self.run_loop(clock,paths=paths)
            self.assertEqual(clock.observed,[]);self.assertEqual(clock.pauses,[])
    def test_native_wrapper_refuses_json_before_stat_or_sleep(self):
        with mock.patch.object(target.os,'lstat',side_effect=AssertionError('device read')),\
             mock.patch.object(target.time,'sleep',side_effect=AssertionError('sleep')):
            with self.assertRaises(Refusal):target.wait_for_device_appearance({'verified':True},{})



# Source-owned copied BOOT placement contracts.
"""Pure Linux metadata fixtures; no staging, chmod, mount or process occurs."""
import base64
import copy
import json
import unittest
import zlib
from unittest import mock

import copied_bootstrap_probe as probe
import copied_location as location
import integrated_capture
from protocol import Refusal,canonical,sha


def fixture():
    names=['usr/bin/python3.11','lib64/ld-linux-x86-64.so.2','code/static-entry',
        'usr/lib/python3.11/encodings/__init__.py','usr/lib/python3.11/os.py']+[
        'usr/lib/python3.11/synthetic_'+str(i)+'.py' for i in range(621)]
    rows=[{'path':name,'archivePath':'static-entry' if name=='code/static-entry' else 'runtime/'+name,
        'bytes':1,'sha256':sha(b'x'),'mode':0o555 if name in names[:3] else 0o444}for name in sorted(names)]
    session='a'*32;boot='17038b18-d0f0-4cd6-8553-46db55427b58';root=location.root_for(rows,session)
    mount={'id':1,'parent':0,'majorMinor':'8:1','root':'/','target':'/','options':['rw','relatime'],
        'fstype':'ext4','source':'/dev/vda1','superOptions':['rw']}
    final={'schema':location.META_SCHEMA,'metadataOnly':True,'executionObserved':False,
        'root':root,'bootId':boot,'rootDevice':2049,'rootMajorMinor':'8:1','ancestors':[],
        'mountInfoSha256':'b'*64,'mounts':[mount],'statvfsFlags':4096,'executables':[]}
    for index,path in enumerate(location.ancestor_paths(root)):
        final['ancestors'].append({'path':path,'device':2049,'inode':index+20,'uid':0,'gid':0,
            'mode':0o755 if index<3 else 0o700,'directory':True,'symlink':False})
    for index,name in enumerate(location.EXECUTABLES):
        final['executables'].append({'path':name,'device':2049,'inode':index+100,'uid':0,'gid':0,
            'mode':0o555,'bytes':1,'sha256':sha(b'x'),'links':1,'executeAccess':True})
    before=copy.deepcopy(final);before['ancestors']=before['ancestors'][:3];before['executables']=[]
    return rows,session,boot,root,{'beforeStage':before,'beforeSpawn':final}


def packet(rows,root,placement):
    value={'schema':'ocv.copied-controller-startup.v1','root':root,'prefix':root+'/usr',
        'basePrefix':root+'/usr','execPrefix':root+'/usr','baseExecPrefix':root+'/usr',
        'executable':root+'/usr/bin/python3.11',
        'path':[root+'/usr/lib/python3.11',root+'/usr/lib/python3.11/lib-dynload'],
        'origins':{'encodings':root+'/usr/lib/python3.11/encodings/__init__.py'},
        'maps':'1000-2000 r-xp 00000000 08:01 1 '+root+'/usr/bin/python3.11\n'+
               '2000-3000 r-xp 00000000 08:01 2 '+root+'/lib64/ld-linux-x86-64.so.2\n',
        'flags':{'isolated':1,'noSite':1,'ignoreEnvironment':1,'dontWriteBytecode':True},
        'version':[3,11,2],'childrenSpawned':False}
    raw=canonical(value);wire=canonical({'schema':'ocv.copied-controller-envelope.v1','rawBytes':len(raw),
        'rawSha256':sha(raw),'zlibBase64':base64.b64encode(zlib.compress(raw,9)).decode('ascii')})
    return canonical({'proof':probe.validate_result(wire,root,rows),'wire':json.loads(wire),
        'scriptSha256':sha(probe.probe_script(root,rows)),'placement':placement})


class CopiedLocationTests(unittest.TestCase):
    def test_versioned_roster_identity_is_order_independent_and_session_bound(self):
        rows,session,_boot,root,_placement=fixture()
        self.assertEqual(location.root_for(list(reversed(rows)),session),root)
        self.assertNotEqual(location.root_for(rows,'b'*32),root)
        changed=copy.deepcopy(rows);changed[0]['sha256']='f'*64
        self.assertNotEqual(location.root_for(changed,session),root)
        changed[0]['archivePath']='other'
        with self.assertRaises(Refusal):location.root_for(changed,session)
    def test_complete_positive_metadata_is_observation_only_and_private_argv_root_stays_generic(self):
        rows,_session,boot,root,placement=fixture()
        self.assertIs(location.validate_pair(placement,root,rows,boot),placement)
        self.assertFalse(placement['beforeSpawn']['executionObserved'])
        private='/var/lib/openclaw-retained-bootstrap/'+'f'*64+'/'+'e'*32+'/root'
        self.assertEqual(probe.build_argv(private,b'print(1)')[0],private+'/lib64/ld-linux-x86-64.so.2')
    def test_same_device_noexec_bind_and_statvfs_restrictions_refuse(self):
        rows,_session,boot,root,placement=fixture()
        for mutate in (lambda m:m['mounts'].append(dict(m['mounts'][0],id=2,target='/var/lib',options=['rw','noexec'])),
                       lambda m:m['mounts'][0]['options'].append('noexec'),
                       lambda m:m.update(statvfsFlags=8),lambda m:m.update(statvfsFlags=1)):
            changed=copy.deepcopy(placement);mutate(changed['beforeStage'])
            with self.subTest(mutate=mutate),self.assertRaises(Refusal):location.validate_pair(changed,root,rows,boot)
        raw=b'1 0 8:1 / / rw,relatime - ext4 /dev/vda1 rw\n2 1 8:1 /var/lib /var/lib rw,noexec - ext4 /dev/vda1 rw\n'
        self.assertEqual(len(location.covering_mounts(raw,root)),2)
    def test_foreign_device_owner_symlink_mode_or_existing_session_refuses(self):
        rows,_session,boot,root,placement=fixture()
        for mutate in (lambda m:m['ancestors'][1].update(device=999),
                       lambda m:m['ancestors'][1].update(uid=1000),
                       lambda m:m['ancestors'][1].update(symlink=True),
                       lambda m:m['ancestors'][1].update(mode=0o777),
                       lambda m:m['ancestors'].extend(copy.deepcopy(placement['beforeSpawn']['ancestors'][3:6]))):
            changed=copy.deepcopy(placement);mutate(changed['beforeStage'])
            with self.subTest(mutate=mutate),self.assertRaises(Refusal):location.validate_pair(changed,root,rows,boot)
        for field,value in (('mode',0o444),('executeAccess',False),('sha256','f'*64),('links',2)):
            changed=copy.deepcopy(placement);changed['beforeSpawn']['executables'][0][field]=value
            with self.subTest(field=field),self.assertRaises(Refusal):location.validate_pair(changed,root,rows,boot)
    def test_independent_host_replay_refuses_fully_rehashed_foreign_root_roster_or_session(self):
        rows,session,boot,root,placement=fixture();raw=packet(rows,root,placement)
        self.assertEqual(integrated_capture.replay_copied_controller(raw,rows,root,boot)['status'],'passed')
        for kind in ('session','roster'):
            foreign=copy.deepcopy(rows)
            if kind=='roster':foreign[0]['sha256']='f'*64
            other=location.root_for(foreign,'b'*32 if kind=='session' else session)
            moved=json.loads(canonical(placement).replace(root.encode(),other.encode()))
            for index,path in enumerate(location.ancestor_paths(other)):
                moved['beforeSpawn']['ancestors'][index]['path']=path
            location.validate_pair(moved,other,foreign,boot)
            forged=packet(foreign,other,moved)
            with self.subTest(kind=kind),self.assertRaises(ValueError):
                integrated_capture.replay_copied_controller(forged,rows,root,boot)
    def test_original_dispatch_endpoint_survives_slow_parent_check(self):
        clock=[10.];launched=[]
        def slow():clock[0]=41.
        with self.assertRaisesRegex(Refusal,'copied.dispatch_deadline'):
            probe.check_probe_dispatch(slow,lambda:clock[0],40.)
            launched.append(True)
        self.assertEqual(launched,[])
    def test_placement_not_attempted_and_real_ambiguous_spawn_stay_distinct(self):
        rows,_session,_boot,root,placement=fixture()
        for phase in ('placement_prewrite','placement_prespawn'):
            result=probe.not_attempted_capture(phase,Refusal('copied.location_test'))
            evidence=probe.capture_failure_evidence(result,root,b'print(1)',rows,0,placement,
                capture_origin='placement-not-attempted')
            self.assertEqual(evidence['capture']['spawnOutcome'],'not_attempted')
            self.assertFalse(evidence['capture']['ownershipRetained'])
        result=probe.not_attempted_capture('placement_prespawn',PermissionError(13,'not retained'))
        result.update(spawnOutcome='unknown',ownershipRetained=True)
        evidence=probe.capture_failure_evidence(result,root,b'print(1)',rows,1,placement)
        self.assertEqual(evidence['capture']['spawnOutcome'],'unknown')
        self.assertTrue(evidence['capture']['ownershipRetained'])
        with mock.patch.object(probe.os,'statvfs',side_effect=AssertionError('native metadata read')):
            with self.assertRaises(Refusal):probe.observe_location({}, {}, {}, root, rows,final=False)
    def test_complete_placement_and_full_capture_fit_original_failure_budget_with_declared_view(self):
        rows,_session,_boot,root,_placement=fixture()
        result=probe.not_attempted_capture('placement_prespawn',PermissionError(13,'not retained'))
        result.update(stdout=bytes(range(256))*64,stderr=bytes(range(256))*16,
            spawned=True,spawnOutcome='handle_returned',exitCode=1,
            errors=[{'phase':'x'*48,'type':'x'*48,'errno':4095}]*16)
        for name in ('stdout','stderr'):
            raw=result[name];result[name+'Facts']={'bytes':len(raw),'sha256':sha(raw),'truncated':False,'complete':True}
        placement={name:{'padding':'x'*8100}for name in ('beforeStage','beforeSpawn')}
        evidence=probe.capture_failure_evidence(result,root,b'print(1)',rows,0,placement)
        self.assertLessEqual(len(canonical({'phase':'bootstrap','reason':'copied.location_test',
            'exceptionType':'Refusal','facts':{'copiedChild':evidence},'errno':None})),32768)
        self.assertEqual(base64.b64decode(evidence['streams']['stderr']['viewBase64']),result['stderr'])
        self.assertEqual(evidence['placement'],placement)
        self.assertTrue(evidence['streams']['stdout']['viewTruncated'])
        self.assertEqual(evidence['streams']['stdout']['captureFacts'],result['stdoutFacts'])


if __name__=='__main__':unittest.main()
