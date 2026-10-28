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



# Source-owned bounded proc EOF contracts.
"""Execute only the actual script's reader helpers with inert fake OS reads."""
import ast
import base64
from types import SimpleNamespace
import unittest
import zlib

import copied_bootstrap_probe as probe
from protocol import Refusal,canonical,sha


class ProcIO:
    O_RDONLY=0;O_NOFOLLOW=1
    def __init__(self,chunks,*,close_error=False):
        self.chunks=list(chunks);self.calls=[];self.closed=[];self.close_error=close_error
    def open(self,path,flags):self.calls.append(('open',path,flags));return 7
    def read(self,fd,count):
        self.calls.append(('read',fd,count))
        if not self.chunks:raise AssertionError('EOF must be observed explicitly')
        value=self.chunks.pop(0)
        if isinstance(value,BaseException):raise value
        if type(value) is bytes and len(value)>count:
            self.chunks.insert(0,value[count:]);return value[:count]
        return value
    def close(self,fd):
        self.closed.append(fd)
        if self.close_error:raise OSError(5,'synthetic close error')


def readers(io):
    tree=ast.parse(probe._SCRIPT)
    names=('read_proc_complete','read_maps_complete')
    nodes=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name in names]
    assert {node.name for node in nodes}==set(names)
    namespace={'os':io}
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[])),
                 '<actual-copied-reader-functions>','exec'),namespace)
    return SimpleNamespace(read=namespace[names[0]],maps=namespace[names[1]])


class CopiedProcReadTests(unittest.TestCase):
    def test_multiple_short_reads_require_eof_and_preserve_late_loader(self):
        chunks=[b'1000-2000 r-xp 00000000 08:01 1 /copied/python\n',
                b'2000-3000 r-xp 00000000 08:01 2 /copied/',b'ld-linux.so\n',b'']
        io=ProcIO(chunks);data=readers(io).maps()
        self.assertEqual(data,b''.join(chunks));self.assertIn(b'ld-linux.so',data)
        self.assertEqual(sum(c[0]=='read' for c in io.calls),4);self.assertEqual(io.closed,[7])
    def test_exact_cap_requires_a_further_eof_read_and_overflow_never_succeeds(self):
        io=ProcIO([b'x'*65535+b'\n',b'']);self.assertEqual(len(readers(io).maps()),65536)
        self.assertEqual(io.calls[-1],('read',7,1));self.assertEqual(io.closed,[7])
        io=ProcIO([b'x'*65537,b''])
        with self.assertRaisesRegex(RuntimeError,'copied.proc_cap'):readers(io).maps()
        self.assertEqual(io.closed,[7])
    def test_nonterminating_progress_is_bounded_and_malformed_or_no_progress_reads_refuse(self):
        class Endless(ProcIO):
            def read(self,fd,count):self.calls.append(('read',fd,count));return b'x'
        io=Endless([])
        with self.assertRaisesRegex(RuntimeError,'copied.proc_cap'):readers(io).read('/proc/self/maps',16)
        self.assertLessEqual(sum(c[0]=='read'for c in io.calls),18);self.assertEqual(io.closed,[7])
        for value in (None,'text',bytearray(b'x')):
            io=ProcIO([value])
            with self.subTest(value=value),self.assertRaisesRegex(RuntimeError,'copied.proc_read_type'):
                readers(io).maps()
            self.assertEqual(io.closed,[7])
    def test_read_error_always_closes_and_close_error_is_not_success(self):
        io=ProcIO([b'first',OSError(5,'synthetic read error')])
        with self.assertRaises(OSError):readers(io).maps()
        self.assertEqual(io.closed,[7])
        io=ProcIO([b'complete\n',b''],close_error=True)
        with self.assertRaises(OSError):readers(io).maps()
        self.assertEqual(io.closed,[7])
    def test_empty_or_unterminated_maps_refuse_and_children_use_same_eof_core(self):
        for chunks in ([b''],[b'partial without newline',b'']):
            io=ProcIO(chunks)
            with self.subTest(chunks=chunks),self.assertRaisesRegex(RuntimeError,'copied.maps_malformed'):
                readers(io).maps()
            self.assertEqual(io.closed,[7])
        io=ProcIO([b'12',b'3 456',b'']);self.assertEqual(readers(io).read('/proc/self/task/1/children',4096),b'123 456')
        self.assertEqual(io.closed,[7])
    def test_foreign_late_mapping_is_still_rejected_by_original_origin_guard(self):
        names=['usr/bin/python3.11','lib64/ld-linux-x86-64.so.2','code/static-entry',
            'usr/lib/python3.11/encodings/__init__.py']+[
            'usr/lib/python3.11/synthetic_'+str(i)+'.py'for i in range(622)]
        rows=[{'path':name,'bytes':1,'sha256':sha(b'x'),
            'mode':0o555 if name in names[:3]else 0o444}for name in names]
        root='/var/lib/openclaw-retained-bootstrap/'+'1'*64+'/'+'a'*32+'/root'
        first=('1000-2000 r-xp 00000000 08:01 1 '+root+'/usr/bin/python3.11\n').encode()
        late=('2000-3000 r-xp 00000000 08:01 2 '+root+'/lib64/ld-linux-x86-64.so.2\n').encode()
        facts={'schema':'ocv.copied-controller-startup.v1','root':root,'prefix':root+'/usr',
            'basePrefix':root+'/usr','execPrefix':root+'/usr','baseExecPrefix':root+'/usr',
            'executable':root+'/usr/bin/python3.11',
            'path':[root+'/usr/lib/python3.11',root+'/usr/lib/python3.11/lib-dynload'],
            'origins':{'encodings':root+'/usr/lib/python3.11/encodings/__init__.py'},
            'maps':readers(ProcIO([first,late,b''])).maps().decode('ascii'),
            'flags':{'isolated':1,'noSite':1,'ignoreEnvironment':1,'dontWriteBytecode':True},
            'version':[3,11,2],'childrenSpawned':False}
        def envelope():
            raw=canonical(facts)
            return canonical({'schema':'ocv.copied-controller-envelope.v1','rawBytes':len(raw),
                'rawSha256':sha(raw),'zlibBase64':base64.b64encode(zlib.compress(raw,9)).decode('ascii')})
        self.assertEqual(probe.validate_result(envelope(),root,rows)['status'],'passed')
        foreign=b'3000-4000 r-xp 00000000 08:01 3 /usr/lib/foreign-host.so\n'
        facts['maps']=readers(ProcIO([first,late,foreign,b''])).maps().decode('ascii')
        with self.assertRaisesRegex(Refusal,'copied.host_mapped_object'):
            probe.validate_result(envelope(),root,rows)



# Source-owned CI failure custody and START deadline contracts.
"""Inert source/capture fixtures only; no native issuer, command or unit runs."""
import base64
import copy
import datetime as dt
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace,ModuleType
import unittest
from unittest import mock

import guest_unit as gunit
import host_admission as hadmit
import integrated_failure as diagnostic
import integrated_guest as gmod
import mac_bridge as mbridge
import native_authority as nauth
import profile as gprofile
import protocol as gprotocol
import worker as gworker


def diagnostic_context():
    session='a'*32;owner={'vmId':nauth.VM_ID,'bootId':'aaaabbbb-1234-5678-9abc-123456789abc',
        'sessionId':session,'unitName':'ocv-'+session+'.service','guestSourceSha256':'d'*64,
        'providerStopAt':'2030-01-01T00:45:00Z','executionDeadlineUtc':'2030-01-01T00:55:00Z'}
    context={'schema':gworker.CONTEXT_SCHEMA,'sessionId':session,'unitName':owner['unitName'],
        'bootId':owner['bootId'],'vmId':nauth.VM_ID,'identityName':'ocv-'+session[:24],
        'contextNonce':'2'*64,'workerDeadlineUtc':'2030-01-01T00:05:00Z','maxJobSeconds':300,
        'operation':'retained-report-only','mountPropagation':'private','sourceSha':gworker.SOURCE,
        'scannerSha':gworker.SCANNER,'indexDigest':gworker.INDEX,'privacySha256':gworker.REPORT_SHA256,
        'privacyBytes':gworker.REPORT_BYTES,'consumerCode':copy.deepcopy(gworker.CONSUMER),
        'profileSha256':gprofile.DESIGN_PROFILE_SHA,'entrySha256':gunit.HELPER_SHA256,
        'workerSha256':'b'*64,'runtimeManifestSha256':'3'*64,'inputManifestSha256':'4'*64}
    class SyntheticIO:evidence_kind='synthetic_contract'
    cap=nauth.synthetic_capability(owner,dict(context,inputManifestSha256=None,workerDeadlineUtc=None),
        pins={},ios={'unit':SyntheticIO()})
    return owner,context,cap


def diagnostic_capture():
    result={'exitCode':1,'timedOut':False,'spawned':True,'spawnOutcome':'handle_returned',
        'captureComplete':True,'streamsEOF':True,'streamsClosed':True,'ownedChildExited':True,
        'ownershipRetained':False,'refusalCode':None,'failurePhase':None,'operationId':1,
        'errors':[],'childPid':23,'stdout':b'fixed synthetic state','stderr':b'fixed synthetic failure'}
    for name in ('stdout','stderr'):
        raw=result[name];result[name+'Facts']={'bytes':len(raw),'sha256':gprotocol.sha(raw),
            'truncated':False,'complete':True}
    return result


def diagnostic_command_fixture():
    owner,context,cap=diagnostic_context();native=gunit.NativeUnitIO();native._cap=cap
    collector=object.__new__(hadmit.Collector)
    collector.ops=hadmit.HostOps(str(cap.session_root),owner['unitName'])
    collector.generic=hadmit.load_generic();collector.boot=owner['bootId']
    port=collector.generic['ci_native_port'].CommandCapture(gunit._UnitCommandIO(native,context))
    collector.ops.command_port=port;native._collector=collector
    result=diagnostic_capture();port.command_sequence=1;port.command_results[1]=result
    argv=('/usr/bin/systemctl','show','--no-pager','--property='+','.join(gunit.STATE_KEYS),owner['unitName'])
    native._last_command=('show',argv,result)
    return SimpleNamespace(io=native,cap=cap),port,result


class IntegratedFailureTests(unittest.TestCase):
    def index(self):
        return diagnostic.source_index({'protocol':gprotocol,'mac_bridge':mbridge,'guest_unit':gunit,'integrated_guest':gmod})
    def test_exact_source_codes_and_frames_survive_uncertainty_but_foreign_messages_never_serialize(self):
        try:
            try:gunit._ready(b'',{})
            except BaseException:raise mbridge.UncertainOutcome('bridge.effect_or_response_uncertain')from None
        except BaseException as error:observed=diagnostic.exception_snapshot(error,self.index())
        self.assertEqual([row['code']for row in observed['exceptions']],['bridge.effect_or_response_uncertain','unit.ready_cap'])
        self.assertTrue(any(frame['source']=='guest_unit.py'for row in observed['exceptions']for frame in row['frames']))
        class Foreign(RuntimeError):
            def __str__(self):raise AssertionError('never stringify')
        for error in (Foreign('DO_NOT_PUBLISH'),gprotocol.Refusal('unapproved.secret')):
            raw=gprotocol.canonical(diagnostic.exception_snapshot(error,self.index()))
            self.assertNotIn(b'DO_NOT_PUBLISH',raw);self.assertNotIn(b'unapproved.secret',raw)
            self.assertNotIn(b'Foreign',raw)
    def test_context_depth_cycle_and_trace_limits_are_bounded(self):
        first=gprotocol.Refusal('unit.start_failed');current=first
        for _ in range(20):current.__context__=gprotocol.Refusal('unit.start_failed');current=current.__context__
        self.assertEqual(len(diagnostic.exception_snapshot(first,self.index())['exceptions']),8)
        current.__context__=first
        self.assertTrue(diagnostic.exception_snapshot(first,self.index())['contextTruncatedOrCyclic'])
        module=ModuleType('trusted');source="def fail():\n raise RuntimeError('unit.start_failed')\n"
        exec(compile(source,'trusted.py','exec'),module.__dict__)
        other=ModuleType('other');exec(compile(source,'other.py','exec'),other.__dict__)
        self.assertEqual(module.fail.__code__,other.fail.__code__)
        self.assertIsNot(module.fail.__code__,other.fail.__code__)
        try:other.fail()
        except BaseException as error:value=diagnostic.exception_snapshot(error,diagnostic.source_index({'trusted':module}))
        self.assertEqual(value['exceptions'][0]['frames'],[])
    def test_capture_rejects_foreign_objects_extra_fields_oversize_and_hash_ownership_substitution(self):
        result=diagnostic_capture()
        self.assertEqual(diagnostic.command_snapshot(result,1,set())['capture']['exitCode'],1)
        class Foreign(dict):pass
        for mutate in (lambda r:r.update(environment={'DO_NOT_INCLUDE':'VALUE'}),
            lambda r:r.update(stderr=b'e'*4097),lambda r:r['stdoutFacts'].update(sha256='f'*64),
            lambda r:r.update(operationId=2),lambda r:r.update(ownershipRetained=True)):
            value=copy.deepcopy(result);mutate(value)
            with self.subTest(mutate=mutate),self.assertRaises(gprotocol.Refusal):diagnostic.command_snapshot(value,1,set())
        with self.assertRaises(gprotocol.Refusal):diagnostic.command_snapshot(Foreign(result),1,set())
    def test_fixed_argv_and_same_capture_identity_are_required_before_any_stream_is_exposed(self):
        unit,port,result=diagnostic_command_fixture()
        observed=gmod._diagnostic_command(unit,None)
        self.assertEqual(observed['closedCommandRole'],'unit-state');self.assertNotIn('argv',observed)
        record=unit.io._last_command
        for replacement in (('show',('/usr/bin/systemctl','show','--all',unit.cap.owner['unitName']),result),
            ('show',record[1],copy.deepcopy(result)),('environment',record[1],result)):
            unit.io._last_command=replacement
            with self.subTest(replacement=replacement[0]),self.assertRaises(gprotocol.Refusal):gmod._diagnostic_command(unit,None)
        unit.io._last_command=record;port.io=object()
        with self.assertRaises(gprotocol.Refusal):gmod._diagnostic_command(unit,None)
        unit.io._last_command=None;self.assertIsNone(gmod._diagnostic_command(unit,None))
    def test_full_stderr_counts_and_hashes_survive_declared_stdout_budget_shortening(self):
        value=diagnostic_capture();value.update(stdout=bytes(range(256))*64,stderr=bytes(range(256))*16)
        for name in ('stdout','stderr'):
            raw=value[name];value[name+'Facts']={'bytes':len(raw),'sha256':gprotocol.sha(raw),'truncated':False,'complete':True}
        command=diagnostic.command_snapshot(value,1,set())
        primary={'boundedSyntheticPadding':'x'*10000}
        evidence=diagnostic.render(primary,[],{}, {},command)
        self.assertLessEqual(len(gprotocol.canonical({'nativeChain':evidence})),diagnostic.FACTS_CAP+32)
        streams=evidence['latestSafeCommand']['streams']
        self.assertTrue(streams['stdout']['viewTruncated'])
        self.assertEqual(streams['stdout']['captureFacts'],value['stdoutFacts'])
        self.assertEqual(base64.b64decode(streams['stderr']['viewBase64']),value['stderr'])
        with self.assertRaises(gprotocol.Refusal):diagnostic.render({'padding':'x'*32768},[],{}, {},None)
        frame={'source':'s'*64+'.py','function':'f'*64,'line':999999}
        chain={'exceptions':[{'type':'t'*128,'code':'unit.start_failed','messageIncluded':False,
            'frames':[dict(frame)for _ in range(8)],'framesObserved':8,'framesSha256':'c'*64,
            'framesTruncated':False,'unlistedFrames':0}for _ in range(8)],
            'innermostObservedCode':'unit.start_failed','contextsObserved':8,
            'contextViewsOmitted':0,'contextTruncatedOrCyclic':False}
        worst=diagnostic.render(chain,[copy.deepcopy(chain)for _ in range(3)],
            {'boundedState':'x'*1000},{'boundedState':'x'*1000},diagnostic.command_snapshot(value,1,set()))
        self.assertLessEqual(len(gprotocol.canonical(worst)),diagnostic.FACTS_CAP)
        self.assertEqual(worst['primary']['innermostObservedCode'],'unit.start_failed')
        self.assertEqual(base64.b64decode(worst['latestSafeCommand']['streams']['stderr']['viewBase64']),value['stderr'])
        self.assertTrue(any(row['framesTruncated']for chain in [worst['primary'],*worst['cleanup']]for row in chain['exceptions']))
    def test_forged_or_synthetic_capability_binding_refuses_without_native_reads(self):
        _owner,_context,cap=diagnostic_context()
        with mock.patch.object(gmod.os,'open',side_effect=AssertionError('no diagnostic IO')):
            for value in ({},object(),cap):
                with self.subTest(kind=type(value)),self.assertRaises(gprotocol.Refusal):
                    gmod._diagnostic_binding(None,None,value,None,None,None,None,None,None)
    def test_original_cleanup_is_once_only_and_all_cleanup_errors_are_retained(self):
        calls=[];owner={'unitName':'synthetic.service'}
        unit=SimpleNamespace(_submit_attempted=True,_attempted=set())
        def stop(name):
            calls.append('stop');unit._attempted.add('stop');raise gprotocol.Refusal('unit.start_failed')
        unit.stop_owned_unit_normally=stop;unit.owned_cgroup_empty=lambda n:calls.append('empty')
        storage=SimpleNamespace(_mounted=True,_used=set())
        def unmount():calls.append('unmount');storage._used.add('unmount');raise OSError(5,'NOT_SERIALIZED')
        storage.unmount_test_normally=unmount
        journal=SimpleNamespace(close=lambda:(calls.append('close')or (_ for _ in ()).throw(OSError(5,'NOT_SERIALIZED'))))
        errors=gmod._cleanup_owned(unit,storage,journal,owner)
        self.assertEqual(calls,['stop','unmount','close']);self.assertEqual(len(errors),3)
        gmod._cleanup_owned(unit,storage,SimpleNamespace(close=lambda:calls.append('closed')),owner)
        self.assertEqual(calls.count('stop'),1);self.assertEqual(calls.count('unmount'),1)
        unit._submit_attempted=False;unit._attempted=set()
        gmod._cleanup_owned(unit,storage,SimpleNamespace(close=lambda:None),owner)
        self.assertEqual(calls.count('stop'),1)
    def test_unavailable_diagnostic_still_refuses_and_preserves_original_failure_cause(self):
        path=Path(gmod.__file__).resolve().parent.parent/'bootstrap/guard.py'
        if not path.exists():path=Path(gmod.__file__).resolve().parent/'proposed-public-harness/bootstrap/guard.py'
        spec=importlib.util.spec_from_file_location('guard',path);guard=importlib.util.module_from_spec(spec)
        with mock.patch.dict(sys.modules,{'guard':guard}):
            spec.loader.exec_module(guard);original=mbridge.UncertainOutcome('DO_NOT_PUBLISH')
            with self.assertRaises(guard.Refusal)as raised:
                gmod._refuse_chain(original,[OSError(5,'DO_NOT_PUBLISH')],{'unavailable':True},*[None]*9)
        self.assertIs(raised.exception.__cause__,original)
        self.assertEqual(raised.exception.code,'integrated_guest.native_chain_uncertain')
        self.assertFalse(raised.exception.facts['nativeChain']['retryPermitted'])
        self.assertEqual(raised.exception.facts['nativeChain']['diagnosticConstruction']['reason'],
            'integrated_guest.diagnostic_unavailable')
        self.assertNotIn(b'DO_NOT_PUBLISH',gprotocol.canonical(raised.exception.facts))
    def test_fallback_exposes_only_closed_source_reason_phase_and_exact_exception_type(self):
        error=gprotocol.Refusal('integrated_guest.diagnostic_guest_pending')
        self.assertEqual(diagnostic.closed_failure(error,'snapshot'),{'phase':'snapshot',
            'reason':'integrated_guest.diagnostic_guest_pending','type':'protocol.Refusal'})
        class Foreign(gprotocol.Refusal):pass
        for value in (Foreign('integrated_guest.diagnostic_guest_pending'),
            gprotocol.Refusal('secret.value'),RuntimeError('DO_NOT_PUBLISH'),PermissionError(13,'DO_NOT_PUBLISH')):
            record=diagnostic.closed_failure(value,'command');raw=gprotocol.canonical(record)
            self.assertNotIn(b'DO_NOT_PUBLISH',raw);self.assertNotIn(b'secret.value',raw)
            self.assertEqual(record['reason'],'integrated_failure.unclassified_diagnostic_failure')
        for value in ({'phase':'snapshot','reason':'secret.value','type':'protocol.Refusal'},
            {'phase':'snapshot','reason':'integrated_guest.diagnostic_guest_pending','type':'DO_NOT_PUBLISH'},
            {'phase':'snapshot','reason':'integrated_guest.diagnostic_guest_pending','type':'protocol.Refusal','extra':'DO_NOT_PUBLISH'}):
            with self.subTest(value=value),self.assertRaises(gprotocol.Refusal):diagnostic.closed_failure_record(value)


class UnitStartDeadlineTests(unittest.TestCase):
    def fixture(self):
        owner,context,cap=diagnostic_context();native=gunit.NativeUnitIO();native._cap=cap
        clock={'mono':10.,'utc':dt.datetime(2030,1,1,tzinfo=dt.timezone.utc)}
        native.monotonic=lambda:clock['mono'];native.now=lambda:clock['utc'];native._check=lambda:None
        raw=(Path(gunit.__file__).resolve().parent/'PROFILE.template.private.json').read_bytes()
        props=gunit._props(raw,cap);argv=['/usr/bin/systemd-run','--unit='+owner['unitName']]
        for value in props:
            if not value.startswith('ExecStart='):argv.extend(('--property',value))
        argv.extend(('/code/static-entry',context['identityName']))
        return native,context,clock,gunit._UnitCommandIO(native,context),tuple(argv),raw
    def test_unrelated_clocks_do_not_arm_start_and_changed_vector_or_context_refuses(self):
        native,context,clock,io,argv,raw=self.fixture();io.now();clock['mono']=100.
        self.assertIsNone(io.start_endpoint);io.arm_start(argv,raw);self.assertEqual(io.start_endpoint,115.)
        with mock.patch.object(hadmit.subprocess,'Popen')as popen:
            with self.assertRaises(gprotocol.Refusal):io.spawn(argv+('extra',))
            self.assertEqual(popen.call_count,0)
        changed=dict(context,workerSha256='f'*64)
        with self.assertRaises(gprotocol.Refusal):gunit._UnitCommandIO(native,changed)
        _native,_ctx,_clock,other,vector,profile_raw=self.fixture()
        with self.assertRaises(gprotocol.Refusal):other.arm_start(vector+('--property','Environment=BAD=1'),profile_raw)
    def test_expired_worker_or_lost_ready_reserve_launches_nothing_and_cannot_retry(self):
        for seconds in (280,301):
            native,context,clock,io,argv,raw=self.fixture();io.arm_start(argv,raw)
            clock['utc']+=dt.timedelta(seconds=seconds)
            with mock.patch.object(hadmit.subprocess,'Popen')as popen:
                with self.subTest(seconds=seconds),self.assertRaises(gprotocol.Refusal):io.spawn(argv)
                self.assertEqual(popen.call_count,0)
                with self.assertRaises(gprotocol.Refusal):io.spawn(argv)
    def test_slow_final_identity_check_cannot_renew_original_command_endpoint(self):
        native,context,clock,io,argv,raw=self.fixture();io.arm_start(argv,raw)
        def slow():clock['mono']=26.
        native._check=slow
        with mock.patch.object(hadmit.subprocess,'Popen')as popen:
            with self.assertRaisesRegex(gprotocol.Refusal,'unit.start_capture_deadline'):io.spawn(argv)
            self.assertEqual(popen.call_count,0);self.assertEqual(io.start_endpoint,25.)
    def test_positive_source_start_and_late_stop_use_same_inherited_single_popen(self):
        native,context,clock,io,argv,raw=self.fixture();io.arm_start(argv,raw)
        with mock.patch.object(hadmit.subprocess,'Popen',return_value='inert')as popen:
            self.assertEqual(io.spawn(argv),'inert');self.assertEqual(popen.call_count,1)
            with self.assertRaises(gprotocol.Refusal):io.spawn(argv)
            clock['utc']+=dt.timedelta(seconds=1000)
            self.assertEqual(io.spawn(('/usr/bin/systemctl','stop',native._cap.owner['unitName'])),'inert')
            self.assertEqual(popen.call_count,2)



# Whole checked graph and inert constructor-chain contracts.
"""Whole checked graph with actual constructors and explicitly inert native IO.

Only temporary public-source/journal files are written. No native qualification
authority is established: the boot, root and lease facts below are test seams.
"""
from contextlib import contextmanager
import datetime as dt
import json
import os
from pathlib import Path
import sys
import tempfile
import subprocess
from types import ModuleType,SimpleNamespace
import unittest
from unittest import mock

import integrated_entry as construction_entry
import integrated_guest as construction_guest


@contextmanager
def diagnostic_whole_factory():
    here=Path(construction_guest.__file__).resolve().parent
    public=here if (here/'PUBLIC-INTEGRATED-SOURCE-MANIFEST.json').exists() else here/'proposed-public-harness/integrated'
    exported=json.loads((public/'PUBLIC-INTEGRATED-SOURCE-MANIFEST.json').read_bytes())
    files={row['path']:(public/row['path']).read_bytes()for row in exported['files']}
    import hashlib
    for row in exported['files']:
        assert len(files[row['path']])==row['bytes'] and hashlib.sha256(files[row['path']]).hexdigest()==row['sha256']
    outer={};bootstrap_root=public.parent/'bootstrap'
    with tempfile.TemporaryDirectory(prefix='ocv-source-construction-')as temp,mock.patch.dict(sys.modules),\
         mock.patch.object(subprocess,'Popen',side_effect=AssertionError('native process forbidden in source construction test')):
        temp=Path(temp).resolve();physical=temp/'source';physical.mkdir(mode=0o700)
        for name in construction_entry.guest_module_names(files)|{'guard','issuer','native_io'}:sys.modules.pop(name,None)
        for name in ('guard','native_io','issuer'):
            path=bootstrap_root/(name+'.py');module=ModuleType(name);module.__file__=str(path)
            sys.modules[name]=module;exec(compile(path.read_bytes(),str(path),'exec'),module.__dict__);outer[name]=module
        # All bytes are the authenticated PUBLIC export. No private report,
        # runtime input, provider observation or native effect enters this test.
        raw_rows=[]
        for name,raw in sorted(files.items()):
            target=physical/'guest'/name;target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            target.write_bytes(raw);target.chmod(0o444)
            raw_rows.append({'path':'guest/'+name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'mode':0o444})
        for directory in physical.rglob('*'):
            if directory.is_dir():directory.chmod(0o700)
        canonical=outer['guard'].canonical;closure=hashlib.sha256(canonical(raw_rows)).hexdigest()
        manifest=canonical({'schema':'openclaw.native-guest-source-bundle.v1','files':raw_rows,'sourceClosureSha256':closure})
        (physical/'SOURCE-MANIFEST.private.json').write_bytes(manifest);(physical/'SOURCE-MANIFEST.private.json').chmod(0o444)
        root=Path('/var/lib/openclaw-retained-verifier-source')/closure
        graph=construction_entry.CheckedGuestModules(construction_entry._GRAPH_KEY,root,files,outer)
        modules=graph.load_all();m=lambda name:modules[name]
        p=m('protocol');ci=m('ci_authority');native=m('native_authority');unit_module=m('guest_unit')
        with mock.patch.object(outer['native_io'].sys,'platform','linux'),mock.patch.object(os,'geteuid',return_value=0),mock.patch.object(os,'getegid',return_value=0):
            io=outer['native_io'].NativeEvidenceIO(outer['native_io'].ENTRY)
        boot='aaaabbbb-1234-5678-9abc-123456789abc';now=dt.datetime(2030,1,1,tzinfo=dt.timezone.utc)
        io.claimed=True;io.current_boot=lambda *,cleanup=False:boot;io.monotonic=lambda:10.
        io._integrated_module_graph=graph
        aliases={};tools={}
        plan=outer['guard'].Plan({'ocv.source':'a'*64,'ocv.session':'b'*32},{'runIdentity':{}},{'files':[]},{},{},boot,now,{},True,outer['guard']._PLAN_SEAL,io)
        compatibility=outer['issuer'].Compatibility(outer['issuer']._COMPATIBILITY_SEAL,io,plan,b'{}')
        prepared=outer['issuer'].Prepared(outer['issuer']._PREPARED_SEAL,io,plan,aliases,tools,{'status':'synthetic-construction'}, {},compatibility)
        parent=outer['issuer'].NativeCapability(outer['issuer']._SEAL,io,plan,aliases,tools,2000.)
        session='c'*32;owner={'vmId':native.VM_ID,'bootId':boot,'sessionId':session,
            'unitName':'ocv-'+session+'.service','guestSourceSha256':closure,
            'providerStopAt':'2030-01-01T00:45:00Z','executionDeadlineUtc':'2030-01-01T00:55:00Z'}
        worker=m('worker');profile=m('profile')
        context={'schema':worker.CONTEXT_SCHEMA,'sessionId':session,'unitName':owner['unitName'],'bootId':boot,
            'vmId':native.VM_ID,'identityName':'ocv-'+session[:24],'contextNonce':'d'*64,
            'workerDeadlineUtc':None,'maxJobSeconds':300,'operation':'retained-report-only','mountPropagation':'private',
            'sourceSha':worker.SOURCE,'scannerSha':worker.SCANNER,'indexDigest':worker.INDEX,
            'privacySha256':worker.REPORT_SHA256,'privacyBytes':worker.REPORT_BYTES,'consumerCode':worker.CONSUMER,
            'profileSha256':profile.DESIGN_PROFILE_SHA,'entrySha256':unit_module.HELPER_SHA256,
            'workerSha256':p.sha(files['worker.py']),'runtimeManifestSha256':'e'*64,'inputManifestSha256':None}
        mac_root=temp/'mac';mac_root.mkdir(mode=0o700)
        core=graph.require_loaded_rows(root,{row['path']:row for row in raw_rows})
        pins={key:context[key]for key in ('profileSha256','workerSha256','entrySha256','runtimeManifestSha256')}
        pins.update(contextSha256=p.sha(p.canonical(context)),guestSourceSha256=closure,
            contextContractSha256=p.sha(p.canonical(sorted(worker.CONTEXT_KEYS))),transportReceiptSha256='f'*64,
            macJournalRoot=str(mac_root),sourceManifestSha256=p.sha(manifest),trustedCoreSources=core,
            unitTools={path:('1'*64 if path!='/usr/sbin/selinuxenabled'else m('host_admission').SELINUX_TOOL_SHA256)for path in unit_module.TOOL_PATHS},
            selinuxToolSha256=m('host_admission').SELINUX_TOOL_SHA256)
        storage_io=m('guest_storage').NativeStorageIO();unit_io=unit_module.NativeUnitIO()
        storage_io.now=unit_io.now=lambda:now
        transport=m('integrated_guest').LocalGuestTransport();owner_io=m('owner_guard').NativeOwnerGuardIO()
        owner_io.now=lambda:now;receipt={'syntheticNativeObjectConstruction':True}
        owner_io.verify_lease=lambda owner_raw,receipt_raw:owner_raw==p.canonical(owner) and receipt_raw==p.canonical(receipt)
        owner_guard=m('owner_guard').OwnerGuard(m('owner_guard')._KEY,owner,owner_io,receipt)
        ios={'storage':storage_io,'unit':unit_io,'mac':transport,'owner_guard':owner_io}
        runtime=ci.CIRuntimeSource(ci._KEY,parent,prepared,storage_io,{}, {})
        grant=ci.CIGrant(ci._KEY,parent,prepared,owner,context,pins,ios,runtime)
        bootstrap_cap=native._issue_bootstrap_from_verified_grant(grant,owner,context,pins,{'owner_guard':owner_io},runtime,transport)
        fd=os.open(physical,os.O_RDONLY|os.O_DIRECTORY)
        try:
            source_grant=m('guest_bootstrap').GuestSourceGrant(m('guest_bootstrap')._KEY,bootstrap_cap,
                'ci-native-proof',fd,p.sha(manifest),os.getuid(),transport,physical,dict(modules),owner_guard)
        finally:os.close(fd)
        bootstrap=m('guest_bootstrap').VerifiedBootstrap(source_grant)
        cap=native._issue_operational_from_verified_grant(grant,owner,context,pins,
            {role:ios[role]for role in ci.OPERATIONAL_ROLES},runtime,bootstrap,owner_guard,transport)
        peer=m('guest_bootstrap').issue_peer_from_outer(bootstrap,transport)
        storage=m('guest_storage').NativeStorageSession(cap,storage_io)
        unit=unit_module.NativeUnitSession(cap,storage,unit_io)
        guest_root=temp/'guest-journal';guest_root.mkdir(mode=0o700)
        with mock.patch.object(m('guest_server'),'_dir',side_effect=lambda _path,_uid:os.open(guest_root,os.O_RDONLY|os.O_DIRECTORY)):
            guest_journal=m('guest_server').GuestIntentJournal(Path(m('guest_server').CONTROL_BASE)/session/'rpc-intents',owner,uid=os.getuid())
        server=m('guest_server').GuestServer(cap,storage,unit,bootstrap,peer,guest_journal,now=lambda:now)
        transport.bind(cap,server,peer)
        journal=m('durable_intent').DurableIntent(mac_root,owner,pins['contextSha256'],p.sha(p.canonical(pins)))
        transport.bind_journal(journal);bridge=m('mac_bridge').MacBridge(cap,transport,journal,now=lambda:now)
        fixture=SimpleNamespace(modules=modules,parent=parent,prepared=prepared,cap=cap,storage=storage,unit=unit,
            transport=transport,server=server,bridge=bridge,journal=journal,bootstrap=bootstrap,
            outer=outer,temporary_root=temp,physical=physical,context=context,owner=owner,public=public)
        try:yield fixture
        finally:
            journal.close();os.close(guest_journal._fd);os.close(bootstrap._source_fd)


def settle_synthetic_preparation(f):
    """Six REAL wire/journal settlements; only storage effect ports are inert."""
    p=f.modules['protocol'];bridge_module=f.modules['mac_bridge']
    copy_manifest={'syntheticConstructionOnly':True}
    digest=p.sha(p.canonical(copy_manifest));copy_manifest['manifestSha256']=digest
    staged={'inputManifestSha256':digest,'inputManifest':copy_manifest,
        'runtimeManifestSha256':f.context['runtimeManifestSha256'],'copiesRootOwned':True,'inputMode':0,
        'propertiesSha256':'3'*64,'stagedAtUtc':'2030-01-01T00:00:00Z','workerDeadlineUtc':'2030-01-01T00:05:00Z'}
    f.storage.preflight=lambda context:{'fresh':True,'vmId':f.owner['vmId'],'testReadOnly':True,
        'bootFreeBytes':2*1024**3,'diskIds':list(bridge_module.DISK_IDS),'noOtherOwner':True,'runtimeAuthoritiesBound':True}
    f.storage.prepare=lambda context:staged
    f.storage.write_public_context_once=lambda raw:None
    f.storage.unmount_test_normally=lambda:None
    f.storage.test_is_unmounted=lambda:True
    f.bridge.prepare()
    assert f.bridge.sequence==f.server.sequence==f.journal.sequence==f.server.journal.sequence==6


def native_chain_snapshot(f,error):
    g=f.modules['integrated_guest']
    snapshot=g._failure_snapshot(error,f.parent,f.prepared,f.cap,f.storage,f.unit,f.transport,f.server,f.bridge,f.journal)
    try:g._refuse_chain(error,[],snapshot,f.parent,f.prepared,f.cap,f.storage,f.unit,f.transport,f.server,f.bridge,f.journal)
    except f.outer['guard'].Refusal as refusal:
        assert refusal.__cause__ is error
        return snapshot,refusal.facts['nativeChain']
    raise AssertionError('source failure must refuse')


def attach_inert_collector(f):
    """Actual Collector/CommandCapture; root/source reads map to public fixtures."""
    host=f.modules['host_admission'];unit_module=f.modules['guest_unit']
    physical=f.physical/'guest/attested_generic';original_source_pins=host.source_pins
    def root_source_read_seam(path):
        assert path==(f.cap.source_root/'guest/attested_generic').resolve()
        original_source_pins(physical)  # Real complete signed six-file hash checks.
    with mock.patch.object(host.os,'geteuid',return_value=0),\
         mock.patch.object(host,'_root_owned_sources',side_effect=root_source_read_seam),\
         mock.patch.object(host,'source_pins',side_effect=lambda directory=None:original_source_pins(physical)):
        collector=host.Collector(host.HostOps(str(f.cap.session_root),f.owner['unitName']),f.owner['bootId'])
    io=unit_module._UnitCommandIO(f.unit.io,f.bridge.context)
    children=[];streams={};queues={}
    def spawn(argv):
        child=SimpleNamespace(pid=23,stdout=object(),stderr=object());children.append(argv)
        # STATE output is harmless and bounded. A later direct Collector
        # busctl returns wrong typed data to exercise its real failure path.
        stdout=b'fixed synthetic state'if argv[0]=='/usr/bin/systemctl'else b'{"type":"b","data":true}'
        queues[child.stdout]=[stdout,b''];queues[child.stderr]=[b''];return child
    io.spawn=spawn;io.now=lambda:10.;io.selector=lambda:object();io.nonblocking=lambda stream:None
    io.register=lambda selector,stream,label:streams.__setitem__(stream,label)
    io.events=lambda selector,seconds:[(SimpleNamespace(fileobj=s,data=label),1)for s,label in list(streams.items())]
    io.mapped=lambda selector:bool(streams);io.read=lambda stream:queues[stream].pop(0)
    io.unregister=lambda selector,stream:streams.pop(stream);io.close_selector=lambda selector:None
    io.close_stream=lambda stream:None;io.poll=lambda child:0;io.wait=lambda child,seconds:0
    collector.ops.command_port.io=io;collector.prepared=True
    f.unit.io._collector=collector;f.unit.io._before=True;f.unit.io._check=lambda **kwargs:None
    return collector,children


@unittest.skipUnless(hasattr(sys,'stdlib_module_names'),'checked whole graph needs the Python3.11+ stdlib roster used in CI')
class WholeDiagnosticConstructionTests(unittest.TestCase):
    def test_actual_factory_pending_zero_integer_survives_snapshot_to_genuine_refusal(self):
        with diagnostic_whole_factory()as f:
            final=dict(f.context,inputManifestSha256='2'*64,workerDeadlineUtc='2030-01-01T00:05:00Z')
            f.server.staged={'inputManifestSha256':'2'*64,'stagedAtUtc':'2030-01-01T00:00:00Z','workerDeadlineUtc':final['workerDeadlineUtc']}
            f.server.finished={'write_public_context_once','test_is_unmounted'};f.server.unmounted=True
            f.server.context=final;f.bridge.context=final;f.bridge.phase='prepared'
            with self.assertRaises(f.modules['mac_bridge'].UncertainOutcome)as caught:
                f.bridge._exchange('start_worker_once',[final])
            self.assertEqual(f.server.journal.pending,0)
            self.assertEqual(f.journal.pending,(0,'start_worker_once'))
            # This one explicit shortcut seeds source-equivalent prepared state
            # at sequence0. The next test drives all six actual wire settlements.
            snapshot,evidence=native_chain_snapshot(f,caught.exception)
            self.assertEqual(snapshot['before']['guestPending'],0)
            self.assertNotIn('diagnosticUnavailable',evidence)
            self.assertEqual(evidence['primary']['innermostObservedCode'],'storage.worker_before_unmount')
    def test_six_actual_preparation_rpc_settlements_then_native_failure_preserve_primary_and_state(self):
        with diagnostic_whole_factory()as f:
            settle_synthetic_preparation(f)
            with self.assertRaises(f.modules['mac_bridge'].UncertainOutcome)as caught:f.bridge.start_and_replay()
            snapshot,evidence=native_chain_snapshot(f,caught.exception)
            self.assertEqual(snapshot['before']['macPending'],[6,'start_worker_once'])
            self.assertEqual(snapshot['before']['guestPending'],6)
            self.assertEqual(snapshot['before']['transportAttempts'],7)
            self.assertEqual(snapshot['before']['transportSettled'],6)
            self.assertFalse(snapshot['before']['unitSubmissionAttempted'])
            self.assertIsNone(snapshot['command']);self.assertIsNone(evidence['commandUnavailable'])
            self.assertFalse(evidence['retryPermitted']);self.assertNotIn('diagnosticUnavailable',evidence)
    def test_closed_guest_pending_domain_and_endpoint_specific_sequence_joins(self):
        with diagnostic_whole_factory()as f:
            g=f.modules['integrated_guest'];p=f.modules['protocol']
            state=lambda:g._diagnostic_state(f.storage,f.unit,f.transport,f.server,f.bridge,f.journal)
            self.assertIsNone(state()['guestPending'])
            f.server.attempted={'start_worker_once'}
            for value in (0,31):
                f.server.sequence=f.server.journal._seq=value;f.server.journal._pending=value
                self.assertEqual(state()['guestPending'],value)
            for value in (True,False,-1,32,'6',(6,'start_worker_once'),[] ):
                f.server.journal._pending=value
                with self.subTest(value=value),self.assertRaises(p.Refusal):state()
            f.server.journal._pending=6;f.server.sequence=6;f.server.journal._seq=5
            with self.assertRaises(p.Refusal):state()
            f.server.journal._seq=6;f.journal.pending=6
            with self.assertRaises(p.Refusal):state()
    def test_before_guest_begin_and_after_guest_settlement_lost_response_remain_uncertain(self):
        for phase in ('before-begin','after-settlement'):
            with self.subTest(phase=phase),diagnostic_whole_factory()as f:
                settle_synthetic_preparation(f);g=f.modules['integrated_guest'];p=f.modules['protocol']
                if phase=='before-begin':
                    def fail(raw):raise p.Refusal('server.blocked')
                    seam=mock.patch.object(f.server,'handle',side_effect=fail)
                else:
                    original=type(f.transport).exchange_once
                    def lost(self,raw,**kwargs):original(self,raw,**kwargs);raise p.Refusal('integrated_transport.response_cap_or_deadline')
                    seam=mock.patch.object(type(f.transport),'exchange_once',lost)
                with seam:
                    with self.assertRaises(f.modules['mac_bridge'].UncertainOutcome)as caught:f.bridge._exchange('test_is_unmounted',[])
                _snapshot,evidence=native_chain_snapshot(f,caught.exception)
                state=evidence['stateBeforeCleanup']
                self.assertIsNone(state['guestPending']);self.assertEqual(state['macPending'],[6,'test_is_unmounted'])
                self.assertEqual(state['serverSequence'],6 if phase=='before-begin'else 7)
                self.assertFalse(evidence['retryPermitted']);self.assertNotIn('diagnosticUnavailable',evidence)
    def test_direct_collector_capture_stale_command_drops_only_unknown_command_not_primary_state(self):
        with diagnostic_whole_factory()as f:
            settle_synthetic_preparation(f);collector,children=attach_inert_collector(f)
            f.unit.io._command('show');cached=f.unit.io._last_command
            self.assertEqual(cached[2]['operationId'],1)
            collector.ops.read=lambda path,cap:f.owner['bootId'].encode()
            expected=(f.cap.source_root/'guest/PROFILE.template.private.json').resolve()
            raw=(f.physical/'guest/PROFILE.template.private.json').read_bytes()
            def profile_read(path):
                if path!=expected:raise AssertionError('unlisted read in source construction fixture')
                return raw
            with mock.patch.object(Path,'read_bytes',autospec=True,side_effect=profile_read):
                with self.assertRaises(f.modules['protocol'].Refusal)as caught:collector.capture(f.bridge.context)
            self.assertGreater(collector.ops.command_port.command_sequence,1)
            self.assertIs(f.unit.io._last_command,cached)
            _snapshot,evidence=native_chain_snapshot(f,caught.exception)
            self.assertIsNone(evidence['latestSafeCommand'])
            self.assertEqual(evidence['commandUnavailable']['reason'],'integrated_guest.diagnostic_capture_source')
            self.assertEqual(evidence['primary']['innermostObservedCode'],'host.typed_schema')
            self.assertNotIn('diagnosticUnavailable',evidence);self.assertEqual(evidence['stateBeforeCleanup']['serverSequence'],6)
            self.assertTrue(all(argv[0]in ('/usr/bin/systemctl','/usr/bin/busctl')for argv in children))
    def test_whole_factory_closed_construction_refusal_survives_fallback_without_message(self):
        with diagnostic_whole_factory()as f:
            g=f.modules['integrated_guest'];p=f.modules['protocol'];diagnostic=f.modules['integrated_failure']
            original=f.modules['mac_bridge'].UncertainOutcome('bridge.effect_or_response_uncertain')
            f.server.storage=object()
            with self.assertRaisesRegex(p.Refusal,'integrated_guest.diagnostic_components')as failed:
                g._failure_snapshot(original,f.parent,f.prepared,f.cap,f.storage,f.unit,f.transport,f.server,f.bridge,f.journal)
            f.server.storage=f.storage
            snapshot={'unavailable':True,'rejection':diagnostic.closed_failure(failed.exception,'snapshot')}
            with self.assertRaises(f.outer['guard'].Refusal)as raised:
                g._refuse_chain(original,[],snapshot,f.parent,f.prepared,f.cap,f.storage,f.unit,f.transport,f.server,f.bridge,f.journal)
            evidence=raised.exception.facts['nativeChain']
            self.assertTrue(evidence['diagnosticUnavailable'])
            self.assertEqual(evidence['diagnosticConstruction'],{'phase':'snapshot',
                'reason':'integrated_guest.diagnostic_components','type':'protocol.Refusal'})
            self.assertIs(raised.exception.__cause__,original);self.assertFalse(evidence['retryPermitted'])


if __name__=='__main__':unittest.main()
