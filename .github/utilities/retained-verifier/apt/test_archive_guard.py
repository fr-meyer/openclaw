"""Synthetic byte/status/I/O contracts; never constructs native file/process IO."""
import copy
import contextlib
import io
import importlib.util
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import unittest

import archive_guard as g
import archive_policy as p
import guard_entry as e
import guard_project as project


def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()
def sha(b):return hashlib.sha256(b).hexdigest()


def fixture():
    packages=(b'Package: example\nVersion: 1.0\nArchitecture: amd64\nFilename: pool/main/e/example/example_1.0_amd64.deb\n'
              b'SHA256: '+b'a'*64+b'\nSize: 123\n\n')
    date='Sat, 11 Jul 2026 10:16:37 UTC'
    body=('Origin: Debian\nCodename: bookworm\nVersion: 12.15\nDate: '+date+'\nSHA256:\n '+
          sha(packages)+' '+str(len(packages))+' main/binary-amd64/Packages\n')
    release=('-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n'+body+
             '-----BEGIN PGP SIGNATURE-----\nSYNTHETIC-NOT-A-SIGNATURE\n-----END PGP SIGNATURE-----\n').encode()
    f=p.Fixture(sha(release),len(release),sha(packages),len(packages),date,'12.15',p.BOOKWORM.primaries)
    return release,packages,f


def row(name,kind='file',size=0,identity=1):
    return {'name':name,'kind':kind,'uid':0,'gid':0,'mode':0o755 if kind=='directory' else 0o644,
            'bytes':size,'identity':[1,identity,1,1,1]}


class Ops:
    def __init__(self):
        self.release,self.packages,self.fixture=fixture();self.events=[];self.calls=[];self.fault=None
        self.entry_calls=[]
        self.files={g.ETC+'/sources.list':g.SOURCE,g.ETC+'/apt.conf.d/'+g.GUARD_FILE:g.CONFIG,
          g.LISTS+'/'+g.RELEASE:self.release,g.KEYRING:b'public-synthetic-keyring',
          '/usr/bin/gpgv':b'not-executed-synthetic-gpgv','/usr/lib/apt/apt-helper':b'not-executed-synthetic-apt-helper'}
        self.directories={g.ETC:[row('sources.list'),row('sources.list.d','directory'),
          row('apt.conf.d','directory'),row('preferences.d','directory')],g.ETC+'/sources.list.d':[],
          g.ETC+'/apt.conf.d':[row(g.GUARD_FILE)],g.ETC+'/preferences.d':[],
          g.LISTS:[row(g.RELEASE,size=len(self.release)),row(g.PACKAGES+'.lz4',size=100),
                   row('lock'),dict(row('partial','directory'),mode=0o700),
                   row('auxfiles','directory')],g.LISTS+'/partial':[],g.LISTS+'/auxfiles':[]}
        self.sandbox={'name':'_apt','uid':42,'rootGroupName':'root','rootGroupGid':0}
        self.context=project.make_context(source_manifest_sha256='1'*64,build_id='2'*32,
          keyring_sha256=sha(self.files[g.KEYRING]),gpgv_sha256=sha(self.files['/usr/bin/gpgv']),
          apt_helper_sha256=sha(self.files['/usr/lib/apt/apt-helper']),run_identity={
          'repository':'fr-meyer/openclaw',
          'workflowRef':'fr-meyer/openclaw/.github/workflows/authorized-beta-focused-validation.yml@refs/heads/retained-verifier-prerequisites',
          'sourceCommit':'3'*40,'runId':'123','runAttempt':'1'})
    def entries(self,path,cap):self.entry_calls.append(path);return copy.deepcopy(self.directories[path])
    def apt_sandbox_identity(self):return copy.deepcopy(self.sandbox)
    def read_regular(self,path,cap):return self.files[path]
    def evidence(self,role,value):self.events.append((role,value))
    def now(self):return datetime(2026,10,27,tzinfo=timezone.utc)
    def run(self,argv,**bounds):
        self.calls.append((argv,bounds))
        if self.fault=='exception':raise OSError(5,'synthetic-boundary-private-message')
        raw=(b'[GNUPG:] VALIDSIG '+b'B8B80B5B623EAB6AD8775C45B7C5D7D6350947F8'+
             b' 2026-07-11 1783764997 0 4 0 1 8 01\n') if argv[0]=='/usr/bin/gpgv' else self.packages
        result={'exitCode':0,'timedOut':False,'captureComplete':True,'ownedChildExited':True,
          'ownershipRetained':False,'stdout':raw,'stderr':b''}
        if self.fault=='nonzero':result['exitCode']=1;result['stderr']=b'UNIQUE-GPG-FAILURE'
        if self.fault=='timeout':result['timedOut']=True
        if self.fault=='incomplete':result['captureComplete']=False
        if self.fault=='unknown':result['exitCode']=None
        if self.fault=='owned':result['ownershipRetained']=True
        if self.fault=='changed' and argv[0]=='/usr/lib/apt/apt-helper':
            self.directories[g.LISTS][1]['identity'][1]+=1
        return result


class GuardTests(unittest.TestCase):
    def setUp(self):self.ops=Ops()
    def run_guard(self,phase='update'):
        return g._run_guard(self.ops,self.ops.context,phase,self.ops.fixture)
    def test_only_signature_process_may_deliver_complete_exit_two_to_policy(self):
        value={'exitCode':2,'timedOut':False,'captureComplete':True,'ownedChildExited':True,
               'ownershipRetained':False,'stdout':b'bounded-status','stderr':b''}
        self.assertEqual(g._result_ok(value,16384,signature_status=True),value)
        with self.assertRaisesRegex(g.Refusal,'apt.command_failed'):g._result_ok(value,16384)
        for field in ('timedOut','captureComplete','ownedChildExited','ownershipRetained'):
            changed=dict(value,**{field:not value[field]})
            with self.subTest(field=field),self.assertRaisesRegex(g.Refusal,'apt.command_failed'):
                g._result_ok(changed,16384,signature_status=True)
    def test_actual_logic_with_small_explicit_fixture(self):
        proof,raw=self.run_guard()
        self.assertEqual(proof['releaseSha256'],sha(self.ops.release));self.assertEqual(raw['Packages'],self.ops.packages)
        self.assertFalse(proof['nativeAuthenticationIssued']);self.assertEqual(len(self.ops.events),2)
    def test_native_wrapper_is_literal_bookworm(self):
        import inspect
        self.assertIn('policy.BOOKWORM',inspect.getsource(g.run_guard))
        with self.assertRaisesRegex(g.Refusal,'security_lists_missing'):g.run_guard(self.ops,self.ops.context,'update')
        self.assertEqual(self.ops.calls,[])
    def test_altered_release_refuses_before_tools(self):
        self.ops.files[g.LISTS+'/'+g.RELEASE]+=b'\n'
        with self.assertRaisesRegex(g.Refusal,'release_pin'):self.run_guard()
        self.assertFalse(self.ops.calls)
    def test_duplicate_package_representation_refuses(self):
        self.ops.directories[g.LISTS].append(row(g.PACKAGES+'.xz'))
        with self.assertRaisesRegex(g.Refusal,'duplicate'):self.run_guard()
    def test_extra_repository_list_refuses(self):
        self.ops.directories[g.LISTS].append(row('other.example_Packages'))
        with self.assertRaisesRegex(g.Refusal,'extra_lists'):self.run_guard()
    def test_partial_and_auxiliary_contents_are_ignored_not_traversed(self):
        self.ops.directories[g.LISTS+'/partial']=[row('unfinished')]
        self.ops.directories[g.LISTS+'/auxfiles']=[row('ignored')]
        proof,_=self.run_guard()
        self.assertEqual(proof['phase'],'update')
        self.assertNotIn(g.LISTS+'/partial',self.ops.entry_calls)
        self.assertNotIn(g.LISTS+'/auxfiles',self.ops.entry_calls)
    def test_hardlink_or_oversized_index_refuses(self):
        for which in ('hardlink','oversize'):
            o=Ops()
            if which=='hardlink':o.directories[g.LISTS][1]['identity'][-1]=2
            else:o.directories[g.LISTS][1]['bytes']=64*1024*1024+1
            with self.assertRaisesRegex(g.Refusal,'identity_or_size'):
                g._run_guard(o,o.context,'update',o.fixture)
    def test_extra_source_and_fragment_refuse(self):
        for path,name in [(g.ETC+'/sources.list.d','other.sources'),(g.ETC+'/apt.conf.d','zz-clear')]:
            with self.subTest(path=path):
                o=Ops();o.directories[path].append(row(name))
                with self.assertRaises(g.Refusal):g._run_guard(o,o.context,'update',o.fixture)
    def test_main_config_or_preference_override_refuses(self):
        self.ops.directories[g.ETC].append(row('apt.conf'))
        with self.assertRaisesRegex(g.Refusal,'main_config'):self.run_guard()
    def test_source_identity_and_keyring_tool_pins(self):
        for field in ('keyringSha256','gpgvSha256','aptHelperSha256'):
            with self.subTest(field=field):
                o=Ops();o.context[field]='0'*64
                with self.assertRaises(g.Refusal):g._run_guard(o,o.context,'update',o.fixture)
    def test_failure_output_preserved_before_status(self):
        self.ops.fault='nonzero'
        with self.assertRaisesRegex(g.Refusal,'command_failed'):self.run_guard()
        self.assertEqual(self.ops.events[0][1]['stderr'],b'UNIQUE-GPG-FAILURE')
    def test_timeout_complete_data_unknown_exit_and_uncertain_owned_refuse(self):
        for fault in ('timeout','unknown','incomplete','owned'):
            with self.subTest(fault=fault):
                o=Ops();o.fault=fault
                with self.assertRaisesRegex(g.Refusal,'command_failed'):g._run_guard(o,o.context,'update',o.fixture)
                self.assertEqual(len(o.events),1)
    def test_boundary_errno_preserved_without_message(self):
        self.ops.fault='exception'
        with self.assertRaisesRegex(g.Refusal,'command_boundary'):self.run_guard()
        self.assertEqual(self.ops.events,[('gpgv',{'boundaryFailure':'OSError','errno':5})])
    def test_changed_list_identity_refuses(self):
        self.ops.fault='changed'
        with self.assertRaisesRegex(g.Refusal,'changed_during'):self.run_guard()
    def test_modified_normalized_package_hash_refuses(self):
        self.ops.packages+=b'\n'
        with self.assertRaisesRegex(g.Refusal,'packages_pin'):self.run_guard()
    def test_context_and_phase_are_closed(self):
        self.ops.context['approved']=True
        with self.assertRaisesRegex(g.Refusal,'context'):self.run_guard()
    def test_file_failure_retains_fixed_role_and_errno(self):
        del self.ops.files[g.KEYRING]
        with self.assertRaises(g.Refusal) as caught:self.run_guard()
        self.assertEqual(caught.exception.facts['role'],'keyring')
        self.assertEqual(caught.exception.facts['exceptionType'],'KeyError')
    def test_exact_config_preserves_expiry_and_no_unsigned_repo(self):
        self.assertIn(b'Check-Valid-Until "true"',g.CONFIG)
        self.assertIn(b'Error-Mode "any"',g.CONFIG)
        self.assertNotIn(b'trusted=yes',g.SOURCE);self.assertNotIn(b'Pre-Install-Pkgs',g.CONFIG)
        self.assertNotIn(b'Sandbox::User',g.CONFIG)
    def test_actual_r1_regression_standard_sandbox_owned_ignored_dirs(self):
        for item in self.ops.directories[g.LISTS]:
            if item['name'] in ('partial','auxfiles'):item['uid']=42
        path=Path(__file__).parent/'regression/archive_guard_r1.py'
        raw=path.read_bytes();self.assertEqual(sha(raw),'274acee6b686b0ccf21172024093fcf53afa891ecebb13c556d17ae0e945770d')
        spec=importlib.util.spec_from_file_location('frozen_apt_r1_regression',path)
        old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
        historical=dict(self.ops.context,sourceRosterSha256=sha(old.SOURCE))
        self.ops.files[g.ETC+'/sources.list']=old.SOURCE
        with self.assertRaisesRegex(old.Refusal,'directory_identity'):
            old._run_guard(self.ops,historical,'update',self.ops.fixture)
        self.ops.files[g.ETC+'/sources.list']=g.SOURCE
        proof,_=self.run_guard();self.assertEqual(proof['phase'],'update')
    def test_only_precise_standard_auxiliary_identity_is_allowed(self):
        for change in ({'uid':43},{'gid':42},{'mode':0o755},{'kind':'other'}):
            with self.subTest(change=change):
                o=Ops();o.directories[g.LISTS][3].update(change)
                with self.assertRaises(g.Refusal):g._run_guard(o,o.context,'update',o.fixture)
    def test_selected_metadata_cannot_use_sandbox_uid(self):
        self.ops.directories[g.LISTS][0]['uid']=42
        with self.assertRaisesRegex(g.Refusal,'directory_identity'):self.run_guard()
    def test_wrong_standard_account_and_root_group_refuse(self):
        for change in ({'name':'other'},{'uid':0},{'rootGroupGid':42}):
            with self.subTest(change=change):
                o=Ops();o.sandbox.update(change);o.directories[g.LISTS][3]['uid']=42
                with self.assertRaisesRegex(g.Refusal,'sandbox_account'):g._run_guard(o,o.context,'update',o.fixture)
    def test_root_owned_ignored_dirs_need_no_sandbox_lookup(self):
        def unexpected():raise AssertionError('root-owned ignored dirs must not query another account')
        self.ops.apt_sandbox_identity=unexpected
        proof,_=self.run_guard();self.assertEqual(proof['phase'],'update')
    def test_native_directory_role_does_not_allow_ignored_contents(self):
        for name in ('partial','auxfiles'):
            with self.assertRaisesRegex(RuntimeError,'directory_role'):e.directory_role(g.LISTS+'/'+name)
        self.assertEqual(e.directory_role(g.LISTS),g.LISTS)


class ExportTests(unittest.TestCase):
    def fixture_export(self):
        ops=Ops();records=[]
        for phase in ('update','install','postinstall'):
            proof,contents=g._run_guard(ops,ops.context,phase,ops.fixture)
            records.append(g.hook_record(proof,[]))
        contents.update({'guard-proof.json':canonical(proof),
          'first-stage-ledger.json':canonical({'schema':'ocv-apt-first-stage-ledger-v1','records':records})})
        desc=g.export_descriptor(contents,proof,ops.context)
        return ops,desc,contents
    def verify(self,ops,desc,contents):return g.verify_export(canonical(desc),contents,
      expected_keyring_sha256=ops.context['keyringSha256'],expected_source_manifest_sha256='1'*64,
      expected_build_id=ops.context['buildId'])
    def test_exact_export_join_still_requires_fresh_signature(self):
        o,d,f=self.fixture_export();self.assertTrue(self.verify(o,d,f)['freshSignatureStillRequired'])
    def test_any_missing_phase_refuses(self):
        o,d,f=self.fixture_export();ledger=json.loads(f['first-stage-ledger.json']);ledger['records'].pop()
        f['first-stage-ledger.json']=canonical(ledger);d['files']['first-stage-ledger.json'].update(bytes=len(f['first-stage-ledger.json']),sha256=sha(f['first-stage-ledger.json']))
        with self.assertRaises(g.Refusal):self.verify(o,d,f)
    def test_failed_record_and_changed_file_refuse(self):
        o,d,f=self.fixture_export();f['Packages']+=b'X'
        with self.assertRaisesRegex(g.Refusal,'export_pin'):self.verify(o,d,f)
    def test_external_source_keyring_pins_refuse(self):
        o,d,f=self.fixture_export()
        with self.assertRaisesRegex(g.Refusal,'external_pin'):g.verify_export(canonical(d),f,
          expected_keyring_sha256='0'*64,expected_source_manifest_sha256='1'*64,expected_build_id=o.context['buildId'])
    def test_old_run_export_refuses_even_with_valid_self_hashes(self):
        o,d,f=self.fixture_export()
        with self.assertRaisesRegex(g.Refusal,'external_build'):g.verify_export(canonical(d),f,
          expected_keyring_sha256=o.context['keyringSha256'],expected_source_manifest_sha256='1'*64,
          expected_build_id='3'*32)
    def test_forged_guard_proof_hash_refuses(self):
        o,d,f=self.fixture_export();ledger=json.loads(f['first-stage-ledger.json']);ledger['records'][0]['proof']['checkedAt']='2026-10-26T00:00:00+00:00'
        f['first-stage-ledger.json']=canonical(ledger);d['files']['first-stage-ledger.json'].update(bytes=len(f['first-stage-ledger.json']),sha256=sha(f['first-stage-ledger.json']))
        with self.assertRaisesRegex(g.Refusal,'proof_hash'):self.verify(o,d,f)
    def test_malformed_time_refuses_even_with_recomputed_self_hash(self):
        o,d,f=self.fixture_export();ledger=json.loads(f['first-stage-ledger.json']);p=ledger['records'][0]['proof']
        p['checkedAt']='made-up';p['proofSha256']=sha(canonical({k:v for k,v in p.items() if k!='proofSha256'}))
        f['first-stage-ledger.json']=canonical(ledger);d['files']['first-stage-ledger.json'].update(bytes=len(f['first-stage-ledger.json']),sha256=sha(f['first-stage-ledger.json']))
        with self.assertRaisesRegex(g.Refusal,'proof_time'):self.verify(o,d,f)
    def test_signed_index_and_installed_roster(self):
        o,d,f=self.fixture_export();records=g.package_records(o.packages)
        value=g.installed_roster(records,b'example\t1.0\tamd64\n',json.loads(f['guard-proof.json']))
        self.assertEqual(value['packages'][0]['debSha256'],'a'*64)
        with self.assertRaises(g.Refusal):g.installed_roster(records,b'unknown\t1.0\tamd64\n',json.loads(f['guard-proof.json']))
        self.assertEqual(g.select_roots(records,['example'],exact_versions={'example':'1.0'}),
                         [{'name':'example','version':'1.0','sha256':'a'*64}])
        with self.assertRaisesRegex(g.Refusal,'missing_or_ambiguous'):
            g.select_roots(records,['example'],exact_versions={'example':'2.0'})
    def test_package_duplicate_and_escape_refuse(self):
        _,packages,_=fixture()
        for raw in (packages+packages,packages.replace(b'pool/main/e/example/',b'pool/main/../')):
            with self.assertRaises(g.Refusal):g.package_records(raw)
    def test_source_generator_is_inert_and_pinned(self):
        o=Ops();here=Path(__file__).parent
        files=project.project_files(o.context,guard_source=(here/'archive_guard.py').read_bytes(),
          policy_source=(here/'archive_policy.py').read_bytes(),entry_source=(here/'guard_entry.py').read_bytes())
        self.assertEqual(files['etc/apt/sources.list'][0],g.SOURCE)
        self.assertIn(b'native_export',files['etc/apt/ocv/export-launcher.py'][0])
        self.assertTrue(project.outer_postinstall_script().startswith(b'#!/bin/sh\n'))
        self.assertEqual(project.project_directories(),{'etc/apt/sources.list.d':0o755,'etc/apt/preferences.d':0o755})
        for name,(raw,mode) in files.items():
            self.assertFalse(name.startswith('/'));self.assertIn(mode,(0o444,0o555))
            if name.endswith('.py'):compile(raw,name,'exec')
        with self.assertRaisesRegex(g.Refusal,'policy_changed'):project.project_files(o.context,
          guard_source=b'x',policy_source=b'not-the-reviewed-policy',entry_source=b'x')


class CaptureIO:
    def __init__(self,fault=None):self.clock=0.;self.fault=fault;self.calls=[];self.child=object();self.n=0;self.kept=False
    def now(self):self.clock+=0.01;return self.clock
    def spawn(self,argv):self.calls.append('spawn');return self.child
    def selector(self,child):
        self.calls.append('selector')
        if self.fault=='selector':raise OSError(24,'synthetic')
        return object()
    def setup(self,child,selector):
        self.calls.append('setup')
        if self.fault=='setup':raise OSError(5,'synthetic')
    def drain(self,child,selector,delay):
        self.n+=1
        if self.n==1:return [('stdout',b'PRIMARY-PARTIAL'),('stderr',b'cause')]
        if self.fault=='read':raise OSError(5,'synthetic')
        if self.fault=='overflow':return [('stdout',b'X'*100)]
        return [('stdout',b''),('stderr',b'')]
    def poll(self,child):
        if self.fault=='late' and self.n>=2:self.clock=100
        return 0 if self.n>=2 else None
    def terminate_if_running(self,child):self.calls.append('term')
    def kill_if_running(self,child):self.calls.append('kill')
    def wait(self,child,seconds):
        self.calls.append('wait')
        if self.fault=='wait':raise TimeoutError()
        return 0
    def close_selector(self,selector):self.calls.append('close_selector')
    def close_stream(self,child,name):
        self.calls.append('close_'+name)
        if self.fault=='close' and name=='stdout':raise OSError(5,'synthetic')
    def settled(self,child):return self.fault!='wait'
    def retire(self,child,settled):
        self.kept=not settled
        if self.fault=='retire':raise OSError(5,'synthetic')


class CaptureTests(unittest.TestCase):
    def run_capture(self,fault=None):
        io=CaptureIO(fault);return io,e.capture_command(io,('/fixed-not-run',),timeout=1,stdout_cap=40,stderr_cap=40)
    def test_complete_and_late_zero_exit(self):
        io,v=self.run_capture();self.assertTrue(v['captureComplete']);self.assertEqual(v['stdout'],b'PRIMARY-PARTIAL')
        io,v=self.run_capture('late');self.assertTrue(v['timedOut']);self.assertFalse(v['captureComplete'])
    def test_postspawn_faults_cleanup_all_owned_parts(self):
        for fault in ('selector','setup','read','close'):
            with self.subTest(fault=fault):
                io,v=self.run_capture(fault)
                self.assertFalse(v['captureComplete']);self.assertTrue(io.kept)
                self.assertTrue({'term','kill','wait','close_selector','close_stdout','close_stderr'}<=set(io.calls))
                if fault=='read':self.assertEqual(v['stdout'],b'PRIMARY-PARTIAL')
    def test_unknown_wait_retains_ownership_and_output(self):
        io,v=self.run_capture('wait');self.assertTrue(v['ownershipRetained']);self.assertFalse(v['ownedChildExited']);self.assertTrue(io.kept)
    def test_retirement_error_retains_primary_capture(self):
        io,v=self.run_capture('retire');self.assertTrue(v['ownershipRetained'])
        self.assertEqual(v['stdout'],b'PRIMARY-PARTIAL');self.assertFalse(v['captureComplete'])
    def test_output_cap_refuses_without_overallocation(self):
        io,v=self.run_capture('overflow');self.assertEqual(v['captureReason'],'output_limit');self.assertEqual(len(v['stdout']),40)
    def test_before_native_io_failure_has_bounded_source_role(self):
        out=io.StringIO()
        with contextlib.redirect_stderr(out):
            rc=e._failure('update',e.EntryRefusal('apt.native_source_read',
              {'role':'guard-context.json','exceptionType':'FileNotFoundError','errno':2}))
        value=json.loads(out.getvalue());self.assertEqual(rc,100)
        self.assertEqual(value['facts']['role'],'guard-context.json');self.assertLess(len(out.getvalue()),16384)
        self.assertNotIn('contextSha256',value);self.assertNotIn('buildId',value)
    def test_checked_failure_context_is_bound_without_privileged_receipt_read(self):
        o=Ops();output=io.StringIO();recorded=[]
        def recorder(*args,**kwargs):recorded.append(kwargs)
        with contextlib.redirect_stderr(output):
            rc=e._failure('update',g.Refusal('apt.keyring_pin'),g,o,record_failure=recorder)
        value=json.loads(output.getvalue());self.assertEqual(rc,100)
        self.assertEqual(value['schema'],'ocv-apt-refused-v1');self.assertEqual(value['reason'],'apt.keyring_pin')
        self.assertEqual(value['buildId'],o.context['buildId'])
        self.assertEqual(value['sourceManifestSha256'],o.context['sourceManifestSha256'])
        self.assertEqual(value['contextSha256'],sha(canonical(o.context)))
        self.assertEqual(recorded,[{'phase':'update','failure':'apt.keyring_pin','failure_facts':{}}])


class DualOps(Ops):
    def __init__(self):
        super().__init__()
        from test_archive_policy import security_fixture
        self.security_release,self.security_packages,self.security_status=security_fixture()
        self.files[g.LISTS+'/'+g.SECURITY_RELEASE]=self.security_release
        self.directories[g.LISTS]+=[row(g.SECURITY_RELEASE,size=len(self.security_release)),
                                    row(g.SECURITY_PACKAGES+'.xz',size=100)]
        self.security_fault=None
    def run(self,argv,**bounds):
        security=(argv[-1].startswith(g.LISTS+'/'+g.SECURITY_RELEASE) or
                  argv[-1].startswith(g.LISTS+'/'+g.SECURITY_PACKAGES))
        if not security:return super().run(argv,**bounds)
        self.calls.append((argv,bounds))
        raw=self.security_status if argv[0]=='/usr/bin/gpgv' else self.security_packages
        result={'exitCode':0,'timedOut':False,'captureComplete':True,'ownedChildExited':True,
                'ownershipRetained':False,'stdout':raw,'stderr':b''}
        if self.security_fault=='exit-two':result['exitCode']=2
        if self.security_fault=='incomplete':result['captureComplete']=False
        if self.security_fault=='pending':result['ownershipRetained']=True
        if self.security_fault=='changed':self.directories[g.LISTS][-1]['identity'][1]+=1
        return result


class DualOriginTests(unittest.TestCase):
    def extra_signer_export(self):
        ops=DualOps();extra='C'*40
        ops.security_status+=('[GNUPG:] VALIDSIG '+extra+' 2026-10-25 1792899000 0 4 0 1 8 01 '+extra+'\n').encode()
        records=[]
        for phase in ('update','install','postinstall'):
            proof,contents=g._run_dual_guard(ops,ops.context,phase,ops.fixture)
            records.append(g.hook_record(proof,[]))
        contents.update({'guard-proof.json':canonical(proof),'first-stage-ledger.json':canonical(
            {'schema':'ocv-apt-first-stage-ledger-v1','records':records})})
        return ops,proof,contents,sorted(set(p.SECURITY_PRIMARIES)|{extra})
    def test_required_plus_additional_valid_signer_survives_guard_ledger_and_export(self):
        ops,proof,contents,expected=self.extra_signer_export()
        self.assertEqual(proof['securityVerifiedPrimaryFingerprints'],expected)
        self.assertEqual(json.loads(contents['security-guard-proof.json'])['verifiedPrimaryFingerprints'],expected)
        descriptor=canonical(g.export_descriptor(contents,proof,ops.context))
        value=g.verify_export(descriptor,contents,expected_keyring_sha256=ops.context['keyringSha256'],
            expected_source_manifest_sha256=ops.context['sourceManifestSha256'],expected_build_id=ops.context['buildId'])
        self.assertIs(value['freshSignatureStillRequired'],True)
        self.assertIs(proof['nativeAuthenticationIssued'],False)
    def test_missing_required_duplicate_invalid_unsorted_rosters_refuse_in_consumers(self):
        ops,proof,contents,expected=self.extra_signer_export();required=next(iter(p.SECURITY_PRIMARIES))
        for roster in (['C'*40],[required,required],[required,'invalid'],list(reversed(expected)),None,tuple(expected)):
            badproof=copy.deepcopy(proof);badproof['securityVerifiedPrimaryFingerprints']=roster
            badproof['proofSha256']=g.sha(g.canonical({k:v for k,v in badproof.items()if k!='proofSha256'}))
            with self.subTest(roster=roster),self.assertRaises(g.Refusal):g._proof_checked(badproof)
            if type(roster)is tuple:continue  # JSON has lists, never tuple provenance.
            bad=dict(contents);side=json.loads(bad['security-guard-proof.json']);side['verifiedPrimaryFingerprints']=roster
            bad['security-guard-proof.json']=canonical(side)
            descriptor=canonical(g.export_descriptor(bad,proof,ops.context))
            with self.assertRaises(g.Refusal):g.validate_export(descriptor,bad)
    def test_export_full_roster_must_equal_saved_status_even_when_all_required_signers_present(self):
        ops,proof,contents,expected=self.extra_signer_export();required=next(iter(p.SECURITY_PRIMARIES))
        for roster in ([required],sorted(expected+['D'*40])):
            # Rebind both public proof hashes so only the captured status/full
            # roster join can reject dropped or invented valid primaries.
            badproof=copy.deepcopy(proof);badproof['securityVerifiedPrimaryFingerprints']=roster
            badproof['proofSha256']=g.sha(g.canonical({k:v for k,v in badproof.items()if k!='proofSha256'}))
            bad=dict(contents);bad['guard-proof.json']=canonical(badproof)
            side=json.loads(bad['security-guard-proof.json']);side['verifiedPrimaryFingerprints']=roster
            bad['security-guard-proof.json']=canonical(side)
            descriptor=canonical(g.export_descriptor(bad,badproof,ops.context))
            with self.subTest(roster=roster),self.assertRaisesRegex(g.Refusal,'security_export_join'):
                g.validate_export(descriptor,bad)
    def test_dual_phase_authentication_and_export_bind_both_origins(self):
        ops=DualOps();records=[]
        for phase in ('update','install','postinstall'):
            ops.events=[];proof,contents=g._run_dual_guard(ops,ops.context,phase,ops.fixture)
            records.append(g.hook_record(proof,[]))  # Native entry sanitizes command events separately.
            self.assertEqual(len(ops.events),4)
            self.assertEqual(proof['securityVerifiedPrimaryFingerprints'],sorted(p.SECURITY_PRIMARIES))
        ledger=canonical({'schema':'ocv-apt-first-stage-ledger-v1','records':records})
        g.validate_ledger(ledger,ops.context,proof)
        contents.update({'guard-proof.json':canonical(proof),'first-stage-ledger.json':ledger})
        descriptor=canonical(g.export_descriptor(contents,proof,ops.context))
        g.verify_export(descriptor,contents,expected_keyring_sha256=ops.context['keyringSha256'],
            expected_source_manifest_sha256=ops.context['sourceManifestSha256'],expected_build_id=ops.context['buildId'])
        for name in g.SECURITY_EXPORT_NAMES:
            bad=dict(contents);bad.pop(name)
            with self.subTest(name=name),self.assertRaises(g.Refusal):g.validate_export(descriptor,bad)
        side=json.loads(contents['security-guard-proof.json'])
        for key,value in [('extra','PUBLIC-UNLISTED'),('checkedAt','invalid'),
                          ('checkedAt','2026-10-27T00:00:01+00:00'),('validUntil','invalid')]:
            bad=dict(contents);changed=dict(side);changed[key]=value
            bad['security-guard-proof.json']=canonical(changed)
            rebound=canonical(g.export_descriptor(bad,proof,ops.context))
            with self.subTest(key=key,value=value),self.assertRaises(g.Refusal):g.validate_export(rebound,bad)
        for raw in (contents['security-guard-proof.json']+b' ',
                    contents['security-guard-proof.json'][:-1]+b',"phase":"postinstall"}'):
            bad=dict(contents,**{'security-guard-proof.json':raw})
            with self.assertRaises(g.Refusal):g.validate_export(canonical(g.export_descriptor(bad,proof,ops.context)),bad)
    def test_security_process_failure_or_metadata_churn_never_passes(self):
        for fault in ('exit-two','incomplete','pending','changed'):
            ops=DualOps();ops.security_fault=fault
            with self.subTest(fault=fault),self.assertRaises(g.Refusal):
                g._run_dual_guard(ops,ops.context,'install',ops.fixture)
    def test_missing_duplicate_extra_or_wrong_security_file_refuses(self):
        for fault in ('missing','duplicate','wrong-type','extra'):
            ops=DualOps()
            if fault=='missing':ops.directories[g.LISTS].pop()
            if fault=='duplicate':ops.directories[g.LISTS].append(row(g.SECURITY_PACKAGES+'.lz4',size=100))
            if fault=='wrong-type':ops.directories[g.LISTS][-2]['kind']='directory'
            if fault=='extra':ops.directories[g.LISTS].append(row('foreign_InRelease'))
            with self.subTest(fault=fault),self.assertRaises(g.Refusal):
                g._run_dual_guard(ops,ops.context,'update',ops.fixture)
    def test_four_security_python_roots_have_exact_hash_size_version_and_filename(self):
        ops=DualOps();records=g.package_records(ops.security_packages,origin='security')
        roots=g.security_python_roots(records);self.assertEqual(len(roots),4)
        for key in records:
            for field,value in [('bytes',0),('debSha256','0'*64),('filename',records[key]['filename'].replace('pool/updates/','pool/')),
                                ('version','3.11.2-6+deb12u8')]:
                bad=copy.deepcopy(records);bad[key][field]=value
                with self.subTest(package=key[0],field=field),self.assertRaises(g.Refusal):g.security_python_roots(bad)
            bad=copy.deepcopy(records);bad.pop(key)
            with self.assertRaises(g.Refusal):g.security_python_roots(bad)


if __name__=='__main__':unittest.main()
