"""Actual CI port→probe→gate→worker→custody joins; synthetic I/O only.

No NativeOps capability, command, kernel read, compiled entry or Linux setup.
"""
import copy
import datetime as dt
import importlib.util
import json
from pathlib import Path
import sys
import os
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import ci_adapter as adapter
import ci_entry as entry
import ci_worker as worker
import ci_fixture as fixture
import ci_native_port as native
import ci_metadata as metadata
import ci_archive_policy as archive
from ci_protocol import Refusal,canonical,sha,stamp

B=Path(__file__).resolve().parent
import ci_probe_fixtures as fixtures


class Clock:
    def __init__(self):self.seconds=0
    def utc(self):return dt.datetime(2030,1,1,tzinfo=dt.timezone.utc)+dt.timedelta(seconds=self.seconds)
    def monotonic(self):return self.seconds
    def sleep(self,value):self.seconds+=value


class Ops:
    """Filesystem/process/command facade; all data is public synthetic fixture."""
    def __init__(self,root,clock,expected):
        self.root,self.clock,self.expected=root,clock,expected
        self.kernel=fixtures.FixtureReader(expected);self.files={};self.modes={};self.calls=[];self.events=[]
        self.fail=None;self.selinux_status=1;self.host_stat_counts={};self.unit_started=False;self.worker=None;self.outcome=None;self.gate=None;self.empty=False
    def read(self,path,cap):
        self.calls.append(('read',path,cap))
        if path in self.files:
            raw=self.files[path].read_bytes();self.assert_cap(raw,cap);return raw
        if path in ('/etc/passwd','/etc/group'):return b'root:x:0:0:root:/root:/bin/sh\n'
        if path.endswith('/cgroup.events'):return b'populated 0\n' if self.empty else b'populated 1\n'
        return self.kernel.read(path,cap)
    def assert_cap(self,raw,cap):
        if len(raw)>cap:raise Refusal('fake.read_cap')
    def stage_file(self,path,raw,mode):
        p=self.root/sha(path.encode());p.write_bytes(raw);self.files[path]=p;self.modes[path]=mode
    def mkdir(self,path,mode):self.modes[path]=mode
    def chmod(self,path,mode):self.modes[path]=mode
    def unlink_file(self,path):self.files.pop(path).unlink()
    def readlink(self,path):
        if path.startswith('/proc/1/ns/'):
            n=path.rsplit('/',1)[-1];return n+':['+str(self.expected['hostNamespaces'][n]+(1 if self.fail=='manager_namespace' else 0))+']'
        if path.startswith('/proc/self/ns/'):
            n=path.rsplit('/',1)[-1];return n+':['+str(self.expected['hostNamespaces'][n])+']'
        return self.kernel.readlink(path)
    def stat(self,path):return self.kernel.stat(path)
    def lstat(self,path):
        if path=='/run/systemd/propagate' and self.fail=='first_incoming_parent' and not self.unit_started:raise FileNotFoundError(path)
        if path=='/usr/sbin/selinuxenabled':return fixtures.metadata(stat.S_IFREG,0o755)
        incoming='/run/systemd/propagate/'+self.expected['unitName']
        if path==incoming:
            if self.fail=='incoming_permission' and self.unit_started:raise PermissionError(path)
            if not self.unit_started:raise FileNotFoundError(path)
            row=next(r for r in self.expected['mounts'] if r['target']=='/run/systemd/incoming')
            return fixtures.metadata(stat.S_IFDIR,0o600,dev=row['identity']['dev'],ino=row['identity']['ino'])
        for row in self.expected['mounts']:
            source=self.port.root+'/root'+('' if row['target']=='/' else row['target'])
            if row['target'] in ('/tmp','/var/tmp'):source=row['fsroot']
            if path==source:
                ident=row['identity'];self.host_stat_counts[path]=self.host_stat_counts.get(path,0)+1
                drift=1 if self.fail=='late_host_inode' and row['target']=='/code' and self.host_stat_counts[path]>1 else 0
                return fixtures.metadata(stat.S_IFDIR,ident['mode'],dev=ident['dev'],ino=ident['ino']+drift)
        if path==self.port.root+'/root/usr/bin/python3.11':return self.kernel.stats['/proc/77/exe']
        if path==self.port.root+'/evidence/worker.stdout':return self.kernel.stats['/proc/77/fd/1']
        if path==self.port.root+'/evidence/worker.stderr':return self.kernel.stats['/proc/77/fd/2']
        if path=='/dev/null':return self.kernel.stats['/proc/77/fd/0']
        if path in ('/tmp','/var/tmp'):return fixtures.metadata(stat.S_IFDIR,0o1777)
        if '/systemd-private-' in path:return fixtures.metadata(stat.S_IFDIR,0o700)
        return fixtures.metadata(stat.S_IFDIR,0o755)
    def listdir(self,path,cap):
        if path in ('/tmp','/var/tmp'):
            if not self.unit_started:
                if self.fail=='preexisting_tmp':return ['systemd-private-'+self.expected['bootId'].replace('-','')+'-'+self.expected['unitName']+'-OLDOLD']
                return []
            prefix='systemd-private-'+self.expected['bootId'].replace('-','')+'-'+self.expected['unitName']+'-ABCDEF'
            return [prefix,prefix[:-6]+'GHIJKL'] if self.fail=='ambiguous_tmp' else [prefix]
        if path=='/run/systemd/propagate/'+self.expected['unitName']:return []
        return self.kernel.listdir(path,cap)
    def monotonic(self):return self.clock.monotonic()
    def sleep(self,value):self.clock.sleep(value)
    def result(self,raw=b'',code=0,timed=False):
        return {'stdout':raw,'stderr':b'','exitCode':code,'timedOut':timed,
          'captureComplete':not timed,'streamsEOF':True,'streamsClosed':True,'ownedChildExited':True,
          'ownershipRetained':False,'refusalCode':None,
          'stdoutFacts':{'bytes':len(raw),'sha256':sha(raw),'truncated':False},
          'stderrFacts':{'bytes':0,'sha256':sha(b''),'truncated':False}}
    def command(self,argv,timeout=5):
        self.calls.append(('command',argv,timeout))
        if argv[0]=='/usr/sbin/selinuxenabled':return self.result(code=self.selinux_status)
        if argv[0]=='/usr/bin/gpgv':return self.result(self.signature)
        if argv[0]=='/usr/bin/systemd-run':
            if self.fail=='setup':return self.result(b'UNIQUE-FIRST-SETUP-CAUSE',code=1)
            self.unit_started=True
            ops=self;port=self.port
            class Files:
                def read_public(self,path,cap):return ops.read(port.root+'/root'+path,cap)
                def input_released(self):
                    if ops.modes[port.root+'/root/input']!=0o555:raise Refusal('fake.input_not_released')
                    ops.events.append('input_released')
                def read_input(self,path,cap):
                    if 'input_released' not in ops.events:raise Refusal('fake.pre_gate_read')
                    ops.events.append('input_read');return ops.read(port.root+'/root'+path,cap)
            class Timer:
                def call(self,seconds,func):
                    ops.events.append('timer')
                    if ops.fail=='timeout':
                        func();raise worker.WorkerTimeout()
                    return func()
            own={'pid':self.expected['pid'],'uid':self.expected['uid'],'euid':self.expected['uid'],
              'gid':self.expected['gid'],'egid':self.expected['gid'],'groups':[]}
            self.worker=worker.Worker(code=port.code,files=Files(),process=SimpleNamespace(snapshot=lambda:dict(own)),
              clock=self.clock,timer=Timer())
            ready=self.worker.ready(canonical(port.context))
            self.stage_file(port.root+'/evidence/worker.stderr',ready+b'\n',0o600)
            return self.result()
        if argv[0]=='/usr/bin/busctl':
            name=argv[-1]
            if name=='ControlGroup' and argv[-2]!='org.freedesktop.systemd1.Service':
                return self.result(b'',code=1)
            values={'DynamicUser':('b',True),'User':('s',self.port.context['identityName']),
              'Group':('s',self.port.context['identityName']),'MainPID':('u',self.expected['pid']),
              'NoNewPrivileges':('b',True),'PrivateNetwork':('b',True),'PrivateIPC':('b',True),
              'CapabilityBoundingSet':('t',0),'AmbientCapabilities':('t',0),'MountFlags':('t',262144),
              'InvocationID':('ay',list(bytes.fromhex(self.expected['invocationId']))),
              'ControlGroup':('s',self.expected['cgroupPath'])}
            if name=='SubState':
                if self.outcome is None:
                    if self.fail=='changed_blob':
                        p=self.files[self.port.root+'/root/input/oci/synthetic.bin'];p.write_bytes(b'changed synthetic')
                    self.outcome=self.worker.finish(self.read(self.port.root+'/root/control/admission.json',16384))
                    self.stage_file(self.port.root+'/evidence/worker.stdout',self.outcome['stdout'],0o600)
                    self.stage_file(self.port.root+'/evidence/worker.stderr',self.outcome['stderr'],0o600)
                kind,value='s','exited' if self.outcome['returncode']==0 else 'failed'
            elif name=='ExecMainCode':kind,value='i',1
            elif name=='ExecMainStatus':kind,value='i',226 if self.outcome is None else self.outcome['returncode']
            elif name=='Result':kind,value='s','namespace' if self.outcome is None else 'timeout' if self.outcome['timedOut'] else 'success'
            else:kind,value=values[name]
            if self.fail=='wrong_unit_security' and name=='PrivateNetwork':value=False
            if self.fail=='wrong_mount_flags' and name=='MountFlags':value=1048576
            return self.result(canonical({'type':kind,'data':value}))
        if argv[:2]==('/usr/bin/systemctl','list-units'):
            return self.result((self.port.unit+' active running').encode() if self.fail=='existing_unit' else b'')
        if argv[:2]==('/usr/bin/systemctl','stop'):
            self.empty=True;return self.result()
        if argv[:2]==('/usr/bin/systemctl','poweroff'):return self.result()
        raise AssertionError('unexpected command source mapping')


def metadata_fixture(ops,clock):
    packages=b'Package: public-synthetic\nVersion: 1\n';fp='AB'*20
    body=('Origin: Debian\nCodename: bookworm\nVersion: fixture\nDate: Fri, 01 Jan 2010 00:00:00 UTC\nSHA256:\n '+
      sha(packages)+' '+str(len(packages))+' main/binary-amd64/Packages\n')
    release=('-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n'+body+
      '-----BEGIN PGP SIGNATURE-----\nsynthetic-not-a-signature\n-----END PGP SIGNATURE-----\n').encode()
    key=b'public-synthetic-test-keyring';paths={'release':'/var/lib/apt/lists/ci_InRelease',
      'packages':'/var/lib/apt/lists/ci_Packages','keyring':'/usr/share/keyrings/debian-archive-keyring.gpg'}
    for k,raw in (('release',release),('packages',packages),('keyring',key)):ops.stage_file(paths[k],raw,0o444)
    ops.signature=('[GNUPG:] VALIDSIG '+fp+' 0 0 0 0 0 0 0 0\n').encode()
    contract=archive.Fixture(sha(release),len(release),sha(packages),len(packages),
      'Fri, 01 Jan 2010 00:00:00 UTC','fixture',frozenset([fp]))
    class SyntheticAdmission(metadata.Admission):
        # Test-only private function seam. Published native run() uses BOOKWORM
        # literally; no caller JSON/manifest can replace that native policy.
        def run(self):return self._run_literal_policy(contract)
    return SyntheticAdmission(ops,paths,sha(key),clock)


class Integration(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.clock=Clock()
        self.expected=fixtures.expected_fixture();self.expected['profileSha256']=worker.DESIGN_PROFILE_SHA
        session=self.expected['sessionId'];root='/var/lib/ci-verifier/'+session
        self.expected['jailRoot']['path']=root+'/root';self.expected['executable']['path']=root+'/root/usr/bin/python3.11'
        for row in self.expected['mounts']:
            if row['target'] in ('/tmp','/var/tmp'):
                row['fsroot']=row['target']+'/systemd-private-'+self.expected['bootId'].replace('-','')+'-'+self.expected['unitName']+'-ABCDEF/tmp'
                row['identity']['mode']=0o1777
            elif row['target']=='/run/systemd/incoming':
                row['fsroot']='/systemd/propagate/'+self.expected['unitName'];row['identity']['mode']=0o600
            else:row['fsroot']=root+'/root'+('' if row['target']=='/' else row['target'])
            if row['target'] in ('/input','/control'):row['vfsOptions'].append('noexec') if 'noexec' not in row['vfsOptions'] else None
        self.ops=Ops(self.root,self.clock,self.expected);self.admission=metadata_fixture(self.ops,self.clock)
        self.session=self.expected['sessionId'];self.session_root='/var/lib/ci-verifier/'+self.session
        self.code={'entrySha256':sha(b'uncompiled-public-entry-placeholder'),
          'workerSha256':sha((B/'ci_worker.py').read_bytes()),'runtimeManifestSha256':sha(b'public-runtime-unqualified'),
          'consumerCode':{'ci_fixture.py':{'bytes':len((B/'ci_fixture.py').read_bytes()),'sha256':sha((B/'ci_fixture.py').read_bytes())}}}
        files=[]
        for path,raw in [('usr/bin/python3.11',b'not-executed-Python-placeholder'),('lib64/ld-linux-x86-64.so.2',b'not-executed-loader'),
                         ('code/static-entry',b'uncompiled-public-entry-placeholder'),('code/worker.py',(B/'ci_worker.py').read_bytes()),
                         ('code/ci_protocol.py',(B/'ci_protocol.py').read_bytes()),('code/ci_profile.py',(B/'ci_profile.py').read_bytes()),
                         ('code/ci_fixture.py',(B/'ci_fixture.py').read_bytes())]:
            seed='/seed/'+path;self.ops.stage_file(seed,raw,0o444)
            files.append({'path':path,'seedPath':seed,'bytes':len(raw),'sha256':sha(raw),'mode':0o555 if path.endswith(('python3.11','static-entry')) else 0o444})
        self.code['runtimeManifestSha256']=sha(canonical(files))
        self.ops.stage_file('/seed/CI-PROFILE.json',(B/'CI-PROFILE.json').read_bytes(),0o444)
        self.ops.stage_file('/usr/sbin/selinuxenabled',b'unexecuted-synthetic-selinux-tool',0o555)
        self.ops.stage_file('/proc/self/mountinfo',b'1 9 8:1 / / rw,nodev - ext4 /dev/sda1 rw\n2 1 0:20 / /run rw,nodev - tmpfs tmpfs rw\n',0o444)
        manifest={'files':files,'code':self.code,'tools':{'selinuxenabledSha256':sha(b'unexecuted-synthetic-selinux-tool')}}
        self.port=native.Port(self.ops,manifest,session_root=self.session_root,clock=self.clock,metadata_admission=self.admission)
        self.ops.port=self.port
        self.context={'schema':'openclaw.retained-verifier-context.v1','sessionId':self.session,'unitName':self.expected['unitName'],
          'bootId':self.expected['bootId'],'vmId':'1','identityName':self.expected['identityName'],'contextNonce':'d'*64,
          'workerDeadlineUtc':stamp(self.clock.utc()+dt.timedelta(seconds=300)),'maxJobSeconds':300,'operation':'retained-report-only','mountPropagation':'private',
          'sourceSha':worker.FIXTURE_SOURCE,'scannerSha':worker.FIXTURE_SCANNER,'indexDigest':worker.FIXTURE_INDEX,
          'privacySha256':fixture.REPORT_SHA,'privacyBytes':len(fixture.REPORT),'consumerCode':self.code['consumerCode'],
          'profileSha256':worker.DESIGN_PROFILE_SHA,**{k:self.code[k] for k in ('entrySha256','workerSha256','runtimeManifestSha256')},
          'inputManifestSha256':sha(canonical({'report':fixture.REPORT_SHA,'blob':fixture.BLOB_SHA}))}
        self.driver=adapter.Adapter(self.port,self.root/'custody',clock=self.clock)
    def tearDown(self):self.tmp.cleanup()
    def run_driver(self):return self.driver.run(canonical(self.context))
    def commands(self,program):return [r for r in self.ops.calls if r[0]=='command' and r[1][0]==program]
    def test_actual_port_metadata_probe_gate_worker_custody_and_pending_outer_exit(self):
        result=self.run_driver();self.assertEqual(result['status'],'unit_passed_pending_outer_exit',result)
        self.assertEqual(result['unitStatus'],'passed');self.assertFalse(result['nativeProof'])
        self.assertEqual(result['closeout'],{'shutdownRequested':True,'outerExitPending':True})
        self.assertGreater(len(self.ops.kernel.calls),10)
        self.assertIn(self.port.root+'/root/control/imports.json',self.ops.files)
        self.assertEqual(len(self.commands('/usr/bin/gpgv')),1);self.assertEqual(len(self.commands('/usr/bin/systemd-run')),1)
        self.assertTrue(any(call[1][-2:]==('org.freedesktop.systemd1.Service','ControlGroup')
                            for call in self.commands('/usr/bin/busctl')))
        self.assertIn('input_released',self.ops.events);self.assertIn('input_read',self.ops.events)
        self.assertTrue(result['custodyComplete']);self.assertTrue(result['ownedUnitEmpty'])
        with self.assertRaises(Refusal):self.run_driver()
        self.assertEqual(len(self.commands('/usr/bin/systemd-run')),1)
    def test_busctl_property_value_is_direct_and_strictly_typed(self):
        self.port.unit=self.context['unitName']
        for kind,value in (('b',True),('s','success'),('u',77),('t',262144),('i',-1),('ay',list(range(16)))):
            with self.subTest(kind=kind):
                self.port.command=lambda argv,kind=kind,value=value:canonical({'type':kind,'data':value})
                self.assertEqual(self.port.typed('org.freedesktop.systemd1.Service','Result',kind),value)
        for kind,value in (('b',[True]),('s',['success']),('u',[77]),('t',[262144]),
                           ('i',[0]),('ay',[list(range(16))]),('u',True),('t',-1),
                           ('i',2**31),('ay',[0]*15),('ay',[0]*15+[256])):
            with self.subTest(kind=kind,value=value):
                self.port.command=lambda argv,kind=kind,value=value:canonical({'type':kind,'data':value})
                with self.assertRaises(Refusal):
                    self.port.typed('org.freedesktop.systemd1.Service','Result',kind)
        self.port.command=lambda argv:canonical({'type':'s','data':True})
        with self.assertRaises(Refusal):self.port.typed('org.freedesktop.systemd1.Service','Result','b')
    def test_actual_probe_changed_environment_blocks_gate_and_consumer(self):
        self.ops.kernel.data['/proc/77/environ']+=b'LD_PRELOAD=bad\0'
        result=self.run_driver();self.assertEqual(result['reason'],'probe.environment_closed',result)
        self.assertNotIn('input_read',self.ops.events);self.assertNotIn('gate',self.port.effect_intents)
        self.assertTrue((self.root/'custody/host-diagnostics.private.bin').exists())
        self.assertIn('shutdown',self.port.effect_intents)
    def test_bad_metadata_stops_before_unit_and_captures_reason(self):
        self.ops.signature=b'[GNUPG:] BADSIG synthetic\n'
        result=self.run_driver();self.assertEqual(result['phase'],'metadata');self.assertEqual(result['reason'],'ci.metadata_refused')
        self.assertEqual(self.commands('/usr/bin/systemd-run'),[])
        self.assertIn('shutdown',self.port.effect_intents)
    def test_setup_failure_before_python_preserves_command_output_and_stops_owned_unit(self):
        self.ops.fail='setup';result=self.run_driver();self.assertEqual(result['reason'],'ci.native_command_failed',result)
        raw=(self.root/'custody/host-diagnostics.private.bin').read_bytes()
        self.assertIn(b'ci.fixed-command-evidence.v1',raw);self.assertIn(b'exitCode',raw)
        self.assertIn('stop',self.port.effect_intents);self.assertIn('shutdown',self.port.effect_intents)
        self.assertEqual(len(self.commands('/usr/bin/systemd-run')),1)
    def test_changed_blob_actual_worker_rejects_and_no_retry(self):
        self.ops.fail='changed_blob';result=self.run_driver();self.assertEqual(result['status'],'refused',result)
        self.assertIn(b'fixture.input_changed',(self.root/'custody/worker-stderr.private.bin').read_bytes())
        self.assertEqual(len(self.commands('/usr/bin/systemd-run')),1)
    def test_timeout_complete_json_is_preserved_but_never_accepted(self):
        self.ops.fail='timeout';result=self.run_driver();self.assertEqual(result['status'],'refused',result)
        raw=(self.root/'custody/worker-stdout.private.bin').read_bytes();self.assertIn(b'"status":"passed"',raw)
        self.assertTrue(self.ops.outcome['timedOut']);self.assertEqual(len(self.commands('/usr/bin/systemd-run')),1)
    def test_wrong_unit_readback_blocks_gate_without_downgrade(self):
        self.ops.fail='wrong_unit_security';result=self.run_driver();self.assertEqual(result['reason'],'ci.unit_security_readback')
        self.assertNotIn('input_read',self.ops.events)
    def test_all_custody_writes_fail_still_stop_and_request_normal_poweroff(self):
        with patch.object(adapter.Custody,'preserve',side_effect=OSError('synthetic custody failure')):
            result=self.run_driver()
        self.assertEqual(result['status'],'refused');self.assertIn('shutdown',self.port.effect_intents)
        self.assertNotIn('retire',self.port.effect_intents)
    def test_disarmed_entry_worker_and_native_capability_before_operations(self):
        with self.assertRaisesRegex(Refusal,'ci.adapter_disarmed'):adapter.main()
        with self.assertRaisesRegex(Refusal,'ci.worker_disarmed'):worker.main()
        with self.assertRaisesRegex(Refusal,'ci.native_capability_unissued'):native.NativeOps(None)
        self.assertEqual(self.ops.calls,[])
    def test_invalid_context_refuses_before_metadata_or_any_unit_effect(self):
        self.context['extra']='unexpected';result=self.run_driver()
        self.assertEqual(result['phase'],'context');self.assertEqual(self.commands('/usr/bin/gpgv'),[])
        self.assertEqual(self.commands('/usr/bin/systemd-run'),[])
    def test_preexisting_unit_is_never_adopted_stopped_or_dispatched(self):
        self.ops.fail='existing_unit';result=self.run_driver()
        self.assertEqual(result['reason'],'ci.unit_already_present')
        self.assertEqual(self.commands('/usr/bin/systemd-run'),[])
        stops=[x for x in self.commands('/usr/bin/systemctl') if x[1][1]=='stop']
        self.assertEqual(stops,[]);self.assertFalse(self.port.unit_issued)
    def test_source_mount_policy_mutation_rejected_by_actual_probe(self):
        self.ops.kernel.stats['/proc/77/root/code'].st_ino+=1
        result=self.run_driver();self.assertEqual(result['status'],'refused')
        self.assertTrue(result['reason'].startswith('probe.'));self.assertNotIn('input_read',self.ops.events)

    def test_manager_namespace_mismatch_refuses_before_unit(self):
        self.ops.fail='manager_namespace';result=self.run_driver()
        self.assertEqual(result['reason'],'ci.manager_namespace_changed');self.assertEqual(self.commands('/usr/bin/systemd-run'),[])
    def test_preexisting_or_ambiguous_private_tmp_never_adopted(self):
        self.ops.fail='preexisting_tmp';result=self.run_driver()
        self.assertEqual(result['reason'],'ci.anchor_preexisting_private_tmp');self.assertEqual(self.commands('/usr/bin/systemd-run'),[])
    def test_fresh_ambiguous_tmp_after_unit_refuses_before_input_release(self):
        self.ops.fail='ambiguous_tmp';result=self.run_driver()
        self.assertEqual(result['reason'],'ci.anchor_private_tmp_ambiguous');self.assertNotIn('input_read',self.ops.events)
    def test_incoming_permission_error_never_means_absent_or_safe(self):
        self.ops.fail='incoming_permission';result=self.run_driver()
        self.assertEqual(result['status'],'refused');self.assertNotIn('input_read',self.ops.events)
    def test_source_inode_drift_after_probe_blocks_gate(self):
        self.ops.fail='late_host_inode';result=self.run_driver()
        self.assertEqual(result['reason'],'ci.anchor_source_changed');self.assertNotIn('input_read',self.ops.events)
    def test_unknown_selinux_exit_refuses_without_configuration_change(self):
        self.ops.selinux_status=2;result=self.run_driver()
        self.assertEqual(result['reason'],'ci.selinux_query_unknown');self.assertEqual(self.commands('/usr/bin/systemd-run'),[])
    def test_enabled_selinux_branch_preserves_flags_without_adding_nosuid(self):
        self.ops.selinux_status=0
        for row in self.expected['mounts']:row['vfsOptions'].remove('nosuid')
        self.ops.kernel=fixtures.FixtureReader(self.expected)
        result=self.run_driver();self.assertEqual(result['unitStatus'],'passed',result)
        self.assertEqual(len(self.commands('/usr/sbin/selinuxenabled')),1)
    def test_changed_selinux_tool_refuses_before_query_or_unit(self):
        self.port.manifest['tools']['selinuxenabledSha256']='0'*64
        result=self.run_driver();self.assertEqual(result['reason'],'ci.selinux_tool_changed')
        self.assertEqual(self.commands('/usr/sbin/selinuxenabled'),[]);self.assertEqual(self.commands('/usr/bin/systemd-run'),[])
    def test_unsupported_source_propagation_never_copies_child_allowlist(self):
        self.ops.stage_file('/proc/self/mountinfo',b'1 9 8:1 / / rw,nodev future:1 - ext4 /dev/sda1 rw\n2 1 0:20 / /run rw,nodev - tmpfs tmpfs rw\n',0o444)
        result=self.run_driver();self.assertEqual(result['reason'],'probe.mount_optional')
        self.assertNotIn('input_read',self.ops.events)

    def test_worker_isolated_python_bootstrap_stays_disarmed_before_file_reads(self):
        with patch.object(worker,'_bootstrap_read',side_effect=AssertionError('must not read')) as read:
            with self.assertRaisesRegex(RuntimeError,'ci.worker_disarmed'):worker._bootstrap_imports()
        read.assert_not_called()
    def test_native_metadata_policy_is_source_literal_not_json_override(self):
        import ast
        tree=ast.parse((B/'ci_metadata.py').read_text())
        method=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='run')
        self.assertIn('policy.BOOKWORM',ast.unparse(method))
        self.assertNotIn('fixture',str(__import__('inspect').signature(metadata.Admission)))

    def test_first_use_incoming_parent_may_be_created_only_by_manager_after_start(self):
        self.ops.fail='first_incoming_parent';result=self.run_driver()
        self.assertEqual(result['unitStatus'],'passed',result)
    def test_expired_outer_budget_refuses_before_unit_but_still_requests_shutdown(self):
        self.clock.seconds=301;result=self.run_driver()
        self.assertEqual(result['status'],'refused');self.assertEqual(self.commands('/usr/bin/systemd-run'),[])
        self.assertIn('shutdown',self.port.effect_intents)

    def test_actual_entry_emits_custodied_result_before_owned_poweroff(self):
        events=[]
        def emit(raw):
            self.assertTrue((self.root/'entry-result/unit-result.json').exists())
            self.assertNotIn('poweroff',self.port.effect_intents);events.append(raw)
        controller=entry.Entry(self.port,self.root/'entry-custody',self.root/'entry-result',clock=self.clock,emit=emit)
        result=controller.run(canonical(self.context))
        self.assertTrue(result['unitResultSaved']);self.assertTrue(result['serialEmitted']);self.assertFalse(result['outerExitVerified'])
        self.assertEqual(len(events),1);self.assertIn('poweroff',self.port.effect_intents)
        with self.assertRaises(Refusal):controller.run(canonical(self.context))
    def test_entry_result_save_failure_still_requests_poweroff_exactly_once(self):
        controller=entry.Entry(self.port,self.root/'entry-custody',self.root/'entry-result',clock=self.clock,
                               emit=lambda raw:None)
        with patch.object(entry,'write_once',side_effect=OSError('synthetic final-save failure')):
            with self.assertRaises(OSError):controller.run(canonical(self.context))
        self.assertIn('poweroff',self.port.effect_intents)
        calls=[x for x in self.commands('/usr/bin/systemctl') if x[1][1]=='poweroff'];self.assertEqual(len(calls),1)
    def test_default_native_entry_has_no_context_or_effect_authority(self):
        with self.assertRaisesRegex(Refusal,'ci.entry_capability_unissued'):entry.main()
        with self.assertRaisesRegex(Refusal,'ci.worker_capability_unissued'):worker.run_bound_native(None)
        self.assertEqual(self.ops.calls,[])

    def test_explicit_private_policy_is_in_context_profile_and_actual_submit(self):
        result=self.run_driver();self.assertEqual(result['unitStatus'],'passed',result)
        args=self.commands('/usr/bin/systemd-run')[0][1]
        self.assertEqual(args.count('MountFlags=private'),1)
        self.assertEqual(self.context['mountPropagation'],'private')
        self.assertEqual(json.loads(self.ops.read(self.port.root+'/root/control/admission.json',16384))['mountPropagation'],'private')
    def test_source_shared_master_tags_clear_only_under_explicit_private_policy(self):
        self.ops.stage_file('/proc/self/mountinfo',b'1 9 8:1 / / rw,nodev shared:1 master:2 propagate_from:2 - ext4 /dev/sda1 rw\n2 1 0:20 / /run rw,nodev shared:3 - tmpfs tmpfs rw\n',0o444)
        result=self.run_driver();self.assertEqual(result['unitStatus'],'passed',result)
        self.assertTrue(any(self.port.anchors.host_propagation.values()))
        self.assertTrue(all(not row['optionalFields'] for row in self.ops.expected['mounts']))
    def test_shared_readback_cannot_be_masked_by_private_context(self):
        self.ops.fail='wrong_mount_flags';result=self.run_driver()
        self.assertEqual(result['reason'],'ci.unit_propagation_readback');self.assertNotIn('input_read',self.ops.events)
    def test_wrong_private_context_refuses_before_metadata(self):
        self.context['mountPropagation']='shared';result=self.run_driver()
        self.assertEqual(result['phase'],'context');self.assertEqual(self.commands('/usr/bin/gpgv'),[])
    def test_unbindable_or_unknown_host_source_tags_never_make_private_success(self):
        self.ops.stage_file('/proc/self/mountinfo',b'1 9 8:1 / / rw,nodev unbindable - ext4 /dev/sda1 rw\n2 1 0:20 / /run rw,nodev - tmpfs tmpfs rw\n',0o444)
        result=self.run_driver();self.assertEqual(result['reason'],'ci.anchor_unbindable_source')
    def test_actual_frozen_r1_covering_rejected_shared_host_source_new_private_model_passes(self):
        import importlib.util
        import ci_anchors
        old_path=B.parent/'native-ci-adapter-r1/ci_anchors.py'
        spec=importlib.util.spec_from_file_location('frozen_r1_anchors',old_path)
        old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
        raw=b'1 9 8:1 / / rw,nodev shared:1 - ext4 /dev/sda1 rw\n'
        rows=ci_anchors.probe.mount_table(raw.decode())
        prior=old.Sources(self.ops,self.port.root,self.expected['unitName'],self.expected['bootId'],
                         self.port.manifest['tools']['selinuxenabledSha256'])
        prior.host_mounts=rows
        with self.assertRaisesRegex(Refusal,'ci.anchor_source_propagation_unsupported'):prior.covering('/var/lib/ci-verifier/test')
        current=ci_anchors.Sources(self.ops,self.port.root,self.expected['unitName'],self.expected['bootId'],
                                  self.port.manifest['tools']['selinuxenabledSha256'],propagation_policy='private')
        current.host_mounts=rows
        self.assertEqual(current.covering('/var/lib/ci-verifier/test')[1],'/var/lib/ci-verifier/test')
        with self.assertRaisesRegex(Refusal,'ci.private_policy_required'):
            ci_anchors.Sources(self.ops,self.port.root,self.expected['unitName'],self.expected['bootId'],
                              self.port.manifest['tools']['selinuxenabledSha256'],propagation_policy='shared')
    def test_source_default_shared_regression_is_not_claimed_linux_observation(self):
        import ci_anchors
        r1=json.loads((B.parent/'native-ci-adapter-r1/CI-PROFILE.json').read_bytes())
        self.assertFalse(any(value.startswith('MountFlags=') for value in r1['properties']))
        # Source-faithful model: exact252 namespace.c2076-2077 uses MS_SHARED
        # for zero;2515-2518 applies requested flags|MS_REC to the new root.
        effective=lambda requested:requested or ci_anchors.MS_SHARED
        self.assertEqual(effective(0),ci_anchors.MS_SHARED)
        self.assertEqual(effective(ci_anchors.MS_PRIVATE),ci_anchors.MS_PRIVATE)
        # Actual existing probe still rejects shared child observations under
        # unchanged nonshared expected constraints. No gate is weakened.
        self.ops.kernel.data['/proc/77/mountinfo']=self.ops.kernel.data['/proc/77/mountinfo'].replace(b' - ext4 ',b' shared:77 - ext4 ',1)
        result=self.run_driver();self.assertEqual(result['reason'],'probe.mount_source_or_flags')
        self.assertNotIn('input_read',self.ops.events)

    def test_exact_profile_preserves_security_and_no_cloud_source(self):
        import ci_profile
        props=ci_profile.properties((B/'CI-PROFILE.json').read_bytes(),self.session,self.session_root)
        for expected in ('DynamicUser=yes','NoNewPrivileges=yes','PrivateNetwork=yes','PrivateIPC=yes',
                         'CapabilityBoundingSet=','AmbientCapabilities=','MemorySwapMax=0','Restart=no','MountFlags=private'):
            self.assertIn(expected,props)
        self.assertNotIn('BindPaths=',props)
        for name in ('ci_adapter.py','ci_native_port.py','ci_worker.py'):
            raw=(B/name).read_text();self.assertNotIn('gcloud',raw);self.assertNotIn('synthetic=True',raw)


if __name__=='__main__':unittest.main()
