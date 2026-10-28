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
        self.assertNotIn(b'DO_NOT_PUBLISH',gprotocol.canonical(raised.exception.facts))


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


if __name__=='__main__':unittest.main()
