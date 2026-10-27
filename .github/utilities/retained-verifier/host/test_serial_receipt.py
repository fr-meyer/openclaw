import base64
import copy
import json
import unittest
import serial_receipt as s


class SerialTests(unittest.TestCase):
    def setUp(self):
        self.expected={'sessionId':'a'*32,'sourceManifestSha256':'b'*64,'buildControlSha256':'c'*64,
                       'runIdentity':{'repository':'fr-meyer/openclaw','workflowRef':'workflow','sourceCommit':'d'*40,'runId':'123','runAttempt':'1'}}
        files=[]
        for role in ('report','host-result','staging-manifest','worker-stdout','worker-stderr','controller-context',
                     'consumer-compatibility','host-expectation','unit-readback','worker-stderr-raw','native-isolation-cases'):
            data=s.canonical({'role':role})
            files.append({'role':role,'bytes':len(data),'sha256':s.sha(data),'base64':base64.b64encode(data).decode(),
                          'sourceBytes':len(data),'sourceSha256':s.sha(data),'truncated':False})
        self.frame=dict(self.expected,schema='ocv.ci-result.v1',status='unit_passed_pending_outer_exit',
                        adapterResult={'status':'unit_passed_pending_outer_exit','unitStatus':'passed','ownedUnitEmpty':True,
                                       'custodyComplete':True,'closeout':{'shutdownRequested':True,'outerExitPending':True}},
                        custody={'schema':'ocv.custody.v1','rawBytes':sum(x['bytes'] for x in files),'files':files})
        self.outer={'status':'outer_exit_passed','timedOut':False,'truncated':False,'returncode':0,'outerExited':True,
                    'ownedGroupGone':True,'streamsEOF':True,'streamsClosed':True,'ownershipRetained':False,
                    'stdout':self.encode(),'stderr':b''}
        self.checked=[]
    def encode(self,frame=None):
        return b'public boot log\n'+s.PREFIX+base64.b64encode(s.canonical(self.frame if frame is None else frame))+b'\n'
    def validate(self,rows,expected):
        self.checked.append((rows,expected))
        return {'schema':'ocv.source-replay.v1','status':'passed','contextSha256':s.sha(rows['controller-context']),
                'hostResultSha256':s.sha(rows['host-result']),'consumerCompatibilitySha256':s.sha(rows['consumer-compatibility'])}
    def run_case(self):
        self.outer['stdout']=self.encode()
        return s.verify(self.outer,self.expected,source_validator=self.validate)
    def test_positive_requires_outer_and_source_consumer_join(self):
        result=self.run_case();self.assertEqual(result['status'],'passed');self.assertEqual(len(self.checked),1)
        self.assertFalse(result['candidateQualified'])
    def test_complete_json_on_timeout_still_refuses_and_preserves(self):
        self.outer['timedOut']=True
        result=self.run_case();self.assertEqual(result['reason'],'outer_not_settled');self.assertTrue(result['custody']['files']);self.assertEqual(self.checked,[])
    def test_each_unsettled_outer_fact_refuses(self):
        for field in ('outerExited','ownedGroupGone','streamsEOF','streamsClosed'):
            outer=dict(self.outer);outer[field]=False
            self.assertEqual(s.verify(outer,self.expected,source_validator=self.validate)['status'],'refused')
        self.assertEqual(self.checked,[])
    def test_owned_handle_retained_is_not_exit_proof(self):
        self.outer['ownershipRetained']=True;self.assertEqual(self.run_case()['status'],'refused')
    def test_duplicate_or_missing_frame_refuses(self):
        for raw in (b'no frame',self.encode()+self.encode()):
            with self.assertRaisesRegex(s.Refusal,'serial_single_frame'):s.extract(raw)
    def test_duplicate_json_keys_rejected(self):
        raw=s.PREFIX+base64.b64encode(b'{"status":1,"status":2}')+b'\n'
        with self.assertRaisesRegex(s.Refusal,'json_duplicate'):s.extract(raw)
    def test_noncanonical_and_malformed_base64_refuse(self):
        for raw in (s.PREFIX+b'not?base64\n',s.PREFIX+base64.b64encode(b'{ "x": 1 }')+b'\n'):
            with self.assertRaises(s.Refusal):s.extract(raw)
    def test_changed_identity_and_run_refuse(self):
        for key in self.expected:
            original=self.frame[key];self.frame[key]='wrong'
            with self.assertRaisesRegex(s.Refusal,'frame_identity'):self.run_case()
            self.frame[key]=original
    def test_guest_pass_boolean_without_custody_refuses(self):
        self.frame['custody']['files']=[]
        with self.assertRaisesRegex(s.Refusal,'custody_shape'):self.run_case()
    def test_refusal_preserves_valid_partial_custody_without_acceptance(self):
        self.frame['status']='refused';self.frame['adapterResult']['status']='refused'
        result=self.run_case();self.assertEqual(result['reason'],'guest_refused');self.assertEqual(self.checked,[])
    def test_truncated_full_hash_distinction_never_clears(self):
        row=self.frame['custody']['files'][0];row.update(sourceBytes=row['bytes']+10,sourceSha256='e'*64,truncated=True)
        result=self.run_case();self.assertEqual(result['reason'],'custody_incomplete')
    def test_duplicate_role_bad_hash_bad_raw_count_reject(self):
        original=copy.deepcopy(self.frame)
        self.frame['custody']['files'].append(copy.deepcopy(self.frame['custody']['files'][0]))
        with self.assertRaises(s.Refusal):self.run_case()
        self.frame=copy.deepcopy(original);self.frame['custody']['files'][0]['sha256']='f'*64
        with self.assertRaisesRegex(s.Refusal,'custody_hash'):self.run_case()
        self.frame=copy.deepcopy(original);self.frame['custody']['rawBytes']+=1
        with self.assertRaisesRegex(s.Refusal,'custody_total_join'):self.run_case()
    def test_source_validator_cannot_be_omitted_or_error_swallowed(self):
        with self.assertRaisesRegex(s.Refusal,'source_validator_missing'):s.verify(self.outer,self.expected)
        def wrong(_rows,_expected):raise s.Refusal('source_join_failed')
        with self.assertRaisesRegex(s.Refusal,'source_join_failed'):s.verify(self.outer,self.expected,source_validator=wrong)
        for value in (None,False,True,{}, {'status':'passed'}):
            with self.assertRaisesRegex(s.Refusal,'source_replay_refused'):
                s.verify(self.outer,self.expected,source_validator=lambda _r,_e:value)


if __name__=='__main__':unittest.main()
