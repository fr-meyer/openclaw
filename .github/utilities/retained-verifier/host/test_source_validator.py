"""Pure replay tests using actual parser/probe functions and synthetic facts."""
import copy
import base64
import datetime as dt
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
CANDIDATES=(HERE.parent/'native',HERE.parent.parent/'native-ci-adapter-r3')
NATIVE=next(path for path in CANDIDATES if path.is_dir())
sys.path.insert(0,str(NATIVE))
CONSUMER=HERE.parent/'consumer'
sys.path.insert(0,str(CONSUMER))
import ci_adapter
import ci_custody
import ci_fixture as fixture
import ci_probe as probe
import ci_probe_fixtures as fixtures
import ci_profile as profile
import ci_worker as worker
from ci_protocol import canonical,sha,stamp,Refusal
import source_validator as v
import serial_receipt as serial
import native_cases
from test_native_cases import FakeIO, actual_run_child_injected


def setup_rows():
    source=fixtures.expected_fixture();session=source['sessionId']
    root='/var/lib/ci-verifier/'+session
    source['profileSha256']=profile.DESIGN_PROFILE_SHA
    source['jailRoot']['path']=root+'/root'
    source['executable']['path']=root+'/root/usr/bin/python3.11'
    for row in source['mounts']:
        if row['target'] not in ('/tmp','/var/tmp','/run/systemd/incoming'):
            row['fsroot']=root+'/root'+('' if row['target']=='/' else row['target'])
    # Actual pure probe runs against an explicitly synthetic reader, not /proc.
    facts=probe.collect_and_validate(fixtures.FixtureReader(source),source)
    consumer_code={'ci_fixture.py':{'bytes':len((NATIVE/'ci_fixture.py').read_bytes()),
                                   'sha256':sha((NATIVE/'ci_fixture.py').read_bytes())}}
    for name in ('native_cases.py',*sorted(v.CONSUMER_FILES)):
        raw=(CONSUMER/name).read_bytes();consumer_code[name]={'bytes':len(raw),'sha256':sha(raw)}
    code={'entrySha256':sha(b'synthetic-uncompiled-entry'),
          'workerSha256':sha(b'synthetic-worker-source'),
          'runtimeManifestSha256':sha(b'synthetic-runtime-file-list'),
          'consumerCode':consumer_code}
    context={'schema':'openclaw.retained-verifier-context.v1','sessionId':session,
      'unitName':source['unitName'],'bootId':source['bootId'],'vmId':'1','identityName':source['identityName'],
      'contextNonce':'d'*64,'workerDeadlineUtc':'2020-01-01T00:05:00Z','maxJobSeconds':300,
      'operation':'retained-report-only','mountPropagation':'private','sourceSha':worker.FIXTURE_SOURCE,
      'scannerSha':worker.FIXTURE_SCANNER,'indexDigest':worker.FIXTURE_INDEX,
      'privacySha256':fixture.REPORT_SHA,'privacyBytes':len(fixture.REPORT),
      'consumerCode':code['consumerCode'],'profileSha256':profile.DESIGN_PROFILE_SHA,
      **{key:code[key] for key in ('entrySha256','workerSha256','runtimeManifestSha256')},
      'inputManifestSha256':sha(canonical({'report':fixture.REPORT_SHA,'blob':fixture.BLOB_SHA}))}
    props=sha(canonical(profile.properties((NATIVE/'CI-PROFILE.json').read_bytes(),session,root)))
    unit={'unitName':source['unitName'],'DynamicUser':True,'User':source['identityName'],'Group':source['identityName'],
          'MainPID':source['pid'],'UID':source['uid'],'GID':source['gid'],'InvocationID':source['invocationId'],
          'ControlGroup':source['cgroupPath'],'propertiesSha256':props,'staticNameAbsent':True,'MountFlags':262144}
    hashes=dict(native_cases.IMPORT_PINS)
    compat={'schema':'ocv.consumer-compat.v1','status':'passed','testsRun':7,'failures':[],
            'sourceHashes':hashes,'elapsedMilliseconds':25,'fixtureOnly':True,'nativeProof':False}
    context_raw=canonical(context)
    ready={'schema':'openclaw.retained-verifier-ready.v1','status':'ready','pid':source['pid'],
           'uid':source['uid'],'gid':source['gid'],'contextSha256':sha(context_raw),'workerSha256':code['workerSha256']}
    final={'schema':'openclaw.retained-verifier-worker-final.v1','status':'consumer_returned',
           'pid':source['pid'],'contextSha256':sha(context_raw),'readyEmitted':True,'consumerExitCode':0,
           'timedOut':False,'reasonCode':None,'elapsedMilliseconds':100}
    rows={'report':fixture.REPORT,'staging-manifest':canonical({'report':fixture.REPORT_SHA,'blob':fixture.BLOB_SHA}),
          'host-result':canonical(facts),'worker-stdout':canonical({'status':'passed',
            'privacyReceiptSha256':fixture.REPORT_SHA,'ociClosureSha256':fixture.CLOSURE_SHA}),
          'worker-stderr':canonical(ready)+b'\n'+canonical(final)+b'\n','controller-context':context_raw,
          'consumer-compatibility':canonical(compat),'host-expectation':canonical(source),'unit-readback':canonical(unit)}
    cases=native_cases.run_cases(FakeIO(pid=source['pid'],context_sha=sha(context_raw)))
    # Explicit native-shaped parser fixture, not NativeIO or issued authority.
    # A real synthetic producer is tested below and must fail host acceptance.
    cases['producer']='native_linux'
    rows['native-isolation-cases']=canonical(cases)
    rows['worker-stderr-raw']=rows['worker-stderr']+canonical(cases)+b'\n'
    expected={'sessionId':session,'sourceManifestSha256':'a'*64,'buildControlSha256':'b'*64,
      'runIdentity':{'repository':'fr-meyer/openclaw',
        'workflowRef':'fr-meyer/openclaw/.github/workflows/authorized-beta-focused-validation.yml@refs/heads/retained-verifier-prerequisites',
        'sourceCommit':'c'*40,'runId':'123','runAttempt':'1'},
      'code':code,'profileSha256':profile.DESIGN_PROFILE_SHA,'propertiesSha256':props,'consumerSourceHashes':hashes}
    return rows,expected


class ReplayTests(unittest.TestCase):
    def setUp(self):self.rows,self.expected=setup_rows()
    def edit(self,role,change,rehash=False):
        value=json.loads(self.rows[role]);change(value)
        if rehash:value['factsSha256']=sha(canonical({k:v for k,v in value.items() if k!='factsSha256'}))
        self.rows[role]=canonical(value)
    def check(self):return v.validate(self.rows,self.expected)
    def test_actual_pure_join_returns_exact_receipt_and_no_fresh_admission(self):
        result=self.check()
        self.assertEqual(result,{'schema':'ocv.source-replay.v1','status':'passed',
          'contextSha256':sha(self.rows['controller-context']),'hostResultSha256':sha(self.rows['host-result']),
          'consumerCompatibilitySha256':sha(self.rows['consumer-compatibility'])})
        self.assertNotIn('nativeProof',result)
    def test_historical_expired_context_is_replayed_without_now_or_new_expiry(self):
        self.assertLess(worker.utc(json.loads(self.rows['controller-context'])['workerDeadlineUtc']),
                        dt.datetime.now(dt.timezone.utc))
        self.assertEqual(self.check()['status'],'passed')
    def test_callback_uses_no_files_process_or_native_constructor(self):
        with patch('os.open',side_effect=AssertionError('file effect')), \
             patch('subprocess.Popen',side_effect=AssertionError('process effect')), \
             patch.object(Path,'read_bytes',side_effect=AssertionError('file effect')):
            self.assertEqual(self.check()['status'],'passed')
    def test_missing_unknown_and_oversized_custody_refuse(self):
        for mutation in ('missing','unknown','oversized'):
            rows=copy.deepcopy(self.rows)
            if mutation=='missing':rows.pop('host-expectation')
            if mutation=='unknown':rows['unknown']=b'{}'
            if mutation=='oversized':rows['worker-stdout']=b'x'*4097
            with self.assertRaises(Refusal):v.validate(rows,self.expected)
    def test_noncanonical_duplicate_and_unknown_context_refuse(self):
        for raw in (self.rows['controller-context']+b'\n',b'{"schema":1,"schema":2}',b'[]'):
            rows=dict(self.rows);rows['controller-context']=raw
            with self.assertRaises(Refusal):v.validate(rows,self.expected)
    def test_trusted_source_hash_code_profile_and_unknown_fields_refuse(self):
        for name,value in (('profileSha256','e'*64),('propertiesSha256','e'*64),('unknown',True)):
            expected=copy.deepcopy(self.expected);expected[name]=value
            with self.assertRaises(Refusal):v.validate(self.rows,expected)
        self.expected['code']['workerSha256']='e'*64
        with self.assertRaises(Refusal):self.check()
    def test_changed_context_source_session_private_policy_and_pins_refuse(self):
        for key,value in (('sessionId','e'*32),('mountPropagation','shared'),('sourceSha','e'*40),
                          ('vmId','2'),('privacySha256','e'*64),('inputManifestSha256','e'*64)):
            rows=dict(self.rows);context=json.loads(rows['controller-context']);context[key]=value
            rows['controller-context']=canonical(context)
            with self.assertRaises(Refusal):v.validate(rows,self.expected)
    def test_unit_readback_binding_cannot_be_guest_selected(self):
        self.edit('unit-readback',lambda row:row.update(propertiesSha256='e'*64))
        with self.assertRaises(Refusal):self.check()
    def test_expected_jail_cannot_point_at_an_ambient_root(self):
        self.edit('host-expectation',lambda row:row['jailRoot'].update(path='/unowned/root'))
        with self.assertRaises(Refusal):self.check()
    def test_fact_hash_and_closed_schema_are_checked(self):
        self.edit('host-result',lambda row:row.update(readCalls=row['readCalls']+1))
        with self.assertRaisesRegex(Refusal,'replay.facts_hash'):self.check()
        self.rows,self.expected=setup_rows();self.edit('host-result',lambda row:row.update(extra=True),True)
        with self.assertRaisesRegex(Refusal,'replay.facts_schema'):self.check()
    def test_critical_process_protections_refuse_even_with_recomputed_hash(self):
        changes=[lambda row:row.update(seccompMode=0),lambda row:row.update(seccompFilterCount=0),
                 lambda row:row.update(noNewPrivileges=True),lambda row:row['capabilitySets'].update(CapEff=1),
                 lambda row:row['capabilitySets'].update(CapAmb=False),lambda row:row.update(children=[99]),
                 lambda row:row.update(supplementaryGroups=[1]),
                 lambda row:row.update(supplementaryGroups=[row['gid'],1]),
                 lambda row:row.update(stableTuple=False)]
        for change in changes:
            self.rows,self.expected=setup_rows();self.edit('host-result',change,True)
            with self.assertRaises(Refusal):self.check()
    def test_namespace_separation_and_shared_namespace_identity_refuse(self):
        source=json.loads(self.rows['host-expectation'])
        for key,value in (('net',source['hostNamespaces']['net']),('pid',source['hostNamespaces']['pid']+1),('mnt',0)):
            self.rows,self.expected=setup_rows();self.edit('host-result',lambda row:row['namespaces'].update({key:value}),True)
            with self.assertRaises(Refusal):self.check()
    def test_resource_and_observation_bounds_refuse(self):
        for change in (lambda row:row['limits'].update(memorySwapMaxBytes=False),
                       lambda row:row['limits'].update(memoryMaxBytes=1),lambda row:row.update(readCalls=0),
                       lambda row:row.update(readBytes=probe.MAX_BYTES+1),lambda row:row.update(peerProcessesChecked=0)):
            self.rows,self.expected=setup_rows();self.edit('host-result',change,True)
            with self.assertRaises(Refusal):self.check()
    def test_mount_flags_roster_and_descriptor_authority_refuse(self):
        for change in (lambda row:row['mounts'][0]['vfsOptions'].append('rw'),
                       lambda row:row['mounts'][0]['optionalFields'].append('shared:1'),
                       lambda row:row['mounts'].pop(),lambda row:row['stdio']['stdout'].update(nlink=2),
                       lambda row:row['stdio']['stderr'].update(flags=0),lambda row:row['stdio'].update(extra={})):
            self.rows,self.expected=setup_rows();self.edit('host-result',change,True)
            with self.assertRaises(Refusal):self.check()
    def test_environment_raw_hash_cannot_hide_an_injected_assignment(self):
        self.edit('host-result',lambda row:row['environment'].update(sha256=sha(b'PATH=/usr/bin\0LD_PRELOAD=x\0')),True)
        with self.assertRaisesRegex(Refusal,'replay.environment_binding'):self.check()
    def test_worker_frames_and_three_key_consumer_proof_are_replayed(self):
        for field,value in (('timedOut',True),('consumerExitCode',None),('contextSha256','e'*64),('extra',1)):
            rows=dict(self.rows);frames=[json.loads(line) for line in rows['worker-stderr'].splitlines()]
            frames[1][field]=value;rows['worker-stderr']=b'\n'.join(canonical(x) for x in frames)+b'\n'
            with self.assertRaises(Refusal):v.validate(rows,self.expected)
        self.edit('worker-stdout',lambda row:row.update(ociClosureSha256='e'*64))
        with self.assertRaises(Refusal):self.check()
    def test_unrun_unknown_or_changed_compatibility_cannot_clear(self):
        for key,value in (('testsRun',0),('testsRun',True),('status','skipped'),('nativeProof',True),
                          ('fixtureOnly',False),('elapsedMilliseconds',240001),('unknown',None)):
            rows=dict(self.rows);summary=json.loads(rows['consumer-compatibility']);summary[key]=value
            rows['consumer-compatibility']=canonical(summary)
            with self.assertRaises(Refusal):v.validate(rows,self.expected)
        self.expected['consumerSourceHashes']['hosted_export.py']='e'*64
        with self.assertRaises(Refusal):self.check()

    def test_raw_stderr_is_exactly_three_lines_with_known_extra_frame(self):
        original=dict(self.rows)
        for raw in (original['worker-stderr-raw']+b'\n',original['worker-stderr'],
                    original['worker-stderr-raw'].replace(b'\n',b'\r\n'),
                    original['worker-stderr-raw']+original['native-isolation-cases']+b'\n'):
            self.rows=dict(original);self.rows['worker-stderr-raw']=raw
            with self.assertRaises(Refusal):self.check()
        self.rows=dict(original);self.rows['worker-stderr']=original['worker-stderr']+b' '
        with self.assertRaisesRegex(Refusal,'replay.raw_stderr_join'):self.check()

    def test_synthetic_unissued_missing_failed_or_changed_native_cases_refuse(self):
        original=dict(self.rows)
        for key,value in (('producer','synthetic_injected'),('producer','not_issued'),('pid',78),
                          ('contextSha256','f'*64),('status','failed'),('importsPassed',False)):
            self.rows=dict(original);case=json.loads(original['native-isolation-cases']);case[key]=value
            self.rows['native-isolation-cases']=canonical(case)
            self.rows['worker-stderr-raw']=self.rows['worker-stderr']+canonical(case)+b'\n'
            with self.assertRaises(native_cases.Refusal):self.check()
        self.rows=dict(original);case=json.loads(original['native-isolation-cases']);case['cases'][3]['reaped']=False
        self.rows['native-isolation-cases']=canonical(case)
        self.rows['worker-stderr-raw']=self.rows['worker-stderr']+canonical(case)+b'\n'
        with self.assertRaises(native_cases.Refusal):self.check()

    def test_actual_child_firstcause_survives_raw_frame_and_host_replay_refusal(self):
        import errno
        observation,_kernel,_owner=actual_run_child_injected({'select':PermissionError(errno.EACCES,'not retained'),
                                                            'cleanup_selector':OSError(errno.EIO,'not retained')})
        context_sha=sha(self.rows['controller-context'])
        pid=json.loads(self.rows['host-expectation'])['pid']
        summary=native_cases.run_cases(FakeIO(pid=pid,context_sha=context_sha,
                                            overrides={'readonly-code':observation}))
        # Native-shaped failure fixture only; this does not construct NativeIO or issue authority.
        summary['producer']='native_linux'
        raw=canonical(summary)
        self.rows['native-isolation-cases']=raw
        self.rows['worker-stderr-raw']=self.rows['worker-stderr']+raw+b'\n'
        captured=json.loads(self.rows['worker-stderr-raw'].splitlines()[2])
        self.assertEqual(captured['cases'][0]['errors'],observation['errors'])
        self.assertEqual(captured['cases'][0]['errors']['first'],
                         {'phase':'select','type':'PermissionError','errno':errno.EACCES})
        native_cases.validate_result(captured,allow_failure=True)
        with self.assertRaisesRegex(native_cases.Refusal,'native.cases_failed'):self.check()
        self.assertNotIn(b'not retained',self.rows['worker-stderr-raw'])

    def test_actual_serial_to_source_replay_accepts_only_exact_callback_receipt(self):
        files=[{'role':name,'bytes':len(raw),'sha256':sha(raw),'base64':base64.b64encode(raw).decode(),
                'sourceBytes':len(raw),'sourceSha256':sha(raw),'truncated':False} for name,raw in self.rows.items()]
        frame={key:self.expected[key] for key in ('sessionId','runIdentity','sourceManifestSha256','buildControlSha256')}
        frame.update(schema='ocv.ci-result.v1',status='unit_passed_pending_outer_exit',
          adapterResult={'status':'unit_passed_pending_outer_exit','unitStatus':'passed','ownedUnitEmpty':True,
                         'custodyComplete':True,'closeout':{'shutdownRequested':True,'outerExitPending':True}},
          custody={'schema':'ocv.custody.v1','rawBytes':sum(map(len,self.rows.values())),'files':files})
        outer={'status':'outer_exit_passed','timedOut':False,'truncated':False,'returncode':0,
          'outerExited':True,'ownedGroupGone':True,'streamsEOF':True,'streamsClosed':True,'ownershipRetained':False,
          'stdout':serial.PREFIX+base64.b64encode(canonical(frame))+b'\n','stderr':b''}
        self.assertEqual(serial.verify(outer,self.expected,source_validator=v.validate)['status'],'passed')
        self.assertFalse(serial.verify(outer,self.expected,source_validator=v.validate)['candidateQualified'])
        for value in (None,False,True,{}, {'schema':'unknown','status':'passed'}):
            with self.assertRaisesRegex(serial.Refusal,'source_replay_refused'):
                serial.verify(outer,self.expected,source_validator=lambda _r,_e:value)


if __name__=='__main__':unittest.main()
