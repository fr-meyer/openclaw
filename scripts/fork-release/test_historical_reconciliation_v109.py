"""Historical fact reconciliation only: synthetic replies, no Git/CI/HTTP/app."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
if (HERE/'source_validation_contract_v109.py').is_file():
    INPUT_ROOT=HERE.parents[1]
    sys.path.insert(0,str(HERE))
else:
    CI=next(parent for parent in HERE.parents if parent.name=='ci-binding-preparation-r1')
    INPUT_ROOT=CI/'baseline-r1/test-view'
    sys.path[:0]=[str(HERE),str(CI/'activation-r1/admission-correction-r1/files/scripts/fork-release'),
        str(CI/'pipeline/scripts/fork-release'),str(CI/'baseline-r1'),str(INPUT_ROOT/'scripts/fork-release')]
import source_validation_v109 as m
import composite_closed_usage_v109 as resolver


def native_model(recorded,run):
    """An explicitly synthetic provider envelope; never a historical observation."""
    value={key:'synthetic metadata' for key in m.HISTORICAL_JOB_NATIVE_FIELDS}
    value.update(run_id=run['id'],run_attempt=1,head_sha=run['head_sha'],runner_group_id=None)
    for key,item in recorded.items():
        if key!='_fieldsPresent':value[key]=deepcopy(item)
    value['steps']=[]
    for step in recorded['steps']:
        result={'started_at':'2026-01-01T00:00:00Z','completed_at':'2026-01-01T00:00:01Z'}
        result.update(deepcopy(step));value['steps'].append(result)
    return value


class ReconciliationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.baseline=resolver.resolve_baseline_258(*((INPUT_ROOT/path).read_bytes() for path in m.BASELINE_FILES))
        cls.raw=[(HERE/Path(path).relative_to('scripts/fork-release')).read_bytes() for path in m.HISTORICAL_RECONCILIATION_INPUTS]
        cls.proof=m.load_historical_reconciliation(*cls.raw,cls.baseline)
        cls.rows={str(row['id']):row for row in cls.baseline['runs']}

    def sample(self):
        rid=next(iter(self.proof['extras']));run=deepcopy(self.rows[rid]);extra=deepcopy(self.proof['extras'][rid])
        actual=[native_model(job,run) for job in run['jobs']]+deepcopy(extra)
        return run,extra,actual

    def test_pinned_original_note_and_producer_resolve_exact_booking(self):
        before=deepcopy(self.baseline)
        p=m.load_historical_reconciliation(*self.raw,self.baseline)
        self.assertEqual(len(p['allExtraIds']),25);self.assertEqual(len(p['noteIds']),5)
        artifacts=[a for group in p['artifacts'].values() for a in group]
        self.assertEqual(len(artifacts),23);self.assertEqual(sum(a['size_in_bytes'] for a in artifacts),387814)
        self.assertEqual(self.baseline,before)

    def test_any_witness_note_or_original_producer_byte_drift_refuses(self):
        for index in range(3):
            raw=list(self.raw);raw[index]=raw[index]+b' '
            with self.subTest(index=index),self.assertRaises(m.policy.Refusal):m.load_historical_reconciliation(*raw,self.baseline)

    def test_old_original_history_is_not_normalized_to_make_match(self):
        b=deepcopy(self.baseline);b['runs'][0]['jobs'][0]['name']='changed'
        with self.assertRaises(m.policy.Refusal):m.load_historical_reconciliation(*self.raw,b)

    def test_exact_witnessed25_positive_unacquired_facts(self):
        total=0;labels=set();reversed_time=False
        for rid,extra in self.proof['extras'].items():
            run=self.rows[rid];actual=[native_model(j,run) for j in run['jobs']]+deepcopy(extra)
            facts=m.reconcile_historical_jobs(actual,run['jobs'],run,extra);total+=len(facts)
            self.assertTrue(all(not f['runnerAcquired'] and f['additionalRunnerMinutes']==0 and not f['durationCalculated'] for f in facts))
            for job in extra:
                labels.add(tuple(job['labels']));reversed_time|=job['started_at']>job['completed_at']
        self.assertEqual(total,25);self.assertIn(('xcode-27',),labels);self.assertIn(('macos-15',),labels)
        self.assertTrue(reversed_time)

    def test_no_free_label_allowlist_or_timestamp_repair(self):
        run,extra,actual=self.sample();jid=extra[0]['id']
        for key,value in [('labels',['unknown']),('labels',['xcode-27']),('started_at','2026-01-01T00:00:00Z')]:
            bad=deepcopy(actual);target=next(j for j in bad if j['id']==jid);target[key]=value
            if value==extra[0][key]:continue
            with self.subTest(key=key),self.assertRaises(m.policy.Refusal):m.reconcile_historical_jobs(bad,run['jobs'],run,extra)

    def test_any_runner_acquisition_or_unknown_runner_fact_refuses(self):
        run,extra,actual=self.sample();jid=extra[0]['id']
        for key,value in [('runner_id',1),('runner_id',0),('runner_name',''),('runner_group_id',0),('runner_group_name','GitHub Actions'),('steps',[{}])]:
            bad=deepcopy(actual);target=next(j for j in bad if j['id']==jid);target[key]=value
            with self.subTest(key=key),self.assertRaises(m.policy.Refusal):m.reconcile_historical_jobs(bad,run['jobs'],run,extra)

    def test_unknown_even_unacquired_job_id_refuses(self):
        run,extra,actual=self.sample();job=deepcopy(extra[0]);job['id']=999999999999999
        with self.assertRaises(m.policy.Refusal):m.reconcile_historical_jobs(actual+[job],run['jobs'],run,extra)

    def test_missing_original_or_missing_witness_id_and_duplicate_refuse(self):
        run,extra,actual=self.sample()
        for bad in (actual[1:],actual[:-1],actual+[deepcopy(actual[-1])]):
            with self.assertRaises(m.policy.Refusal):m.reconcile_historical_jobs(bad,run['jobs'],run,extra)

    def test_recorded_original_change_and_native_context_refuse(self):
        run,extra,actual=self.sample()
        for key,value in [('name','changed'),('head_sha','f'*40),('run_id',1),('run_attempt',2)]:
            bad=deepcopy(actual);bad[0][key]=value
            with self.subTest(key=key),self.assertRaises(m.policy.Refusal):m.reconcile_historical_jobs(bad,run['jobs'],run,extra)

    def test_unrecorded_native_api_fields_are_not_new_recorded_facts(self):
        run,extra,actual=self.sample();jid=extra[0]['id'];next(j for j in actual if j['id']==jid)['new_provider_field']='unrecorded'
        self.assertEqual(len(m.reconcile_historical_jobs(actual,run['jobs'],run,extra)),len(extra))

    def test_explicit_original_absence_only_after_original_expiry(self):
        run=self.rows['40804517284'];expected=self.proof['artifacts']['40804517284'];expiry=m.provider_epoch('2026-10-30T02:09:22Z')
        with self.assertRaises(m.policy.Refusal):m.reconcile_historical_artifacts([],expected,run,expiry-1)
        facts=m.reconcile_historical_artifacts([],expected,run,expiry)
        self.assertEqual(facts[0]['payloadAvailability'],'unavailable');self.assertEqual(facts[0]['absenceCause'],'unproved')
        self.assertEqual(facts[0]['bookedBytes'],187076);self.assertFalse(facts[0]['custodyClaimed'])

    def test_absence_exception_does_not_apply_to_arbitrary_expired_artifact(self):
        run=self.rows['40804517284'];expected=deepcopy(self.proof['artifacts']['40804517284']);expected[0]['id']+=1
        with self.assertRaises(m.policy.Refusal):m.reconcile_historical_artifacts([],expected,run,m.provider_epoch('2026-11-01T00:00:00Z'))

    def test_known_note_artifact_immutable_facts_and_unknown_additions_refuse(self):
        rid=next(rid for rid,group in self.proof['artifacts'].items() if any(a['id'] in self.proof['noteIds'] for a in group))
        expected=self.proof['artifacts'][rid];run=self.rows[rid];actual=deepcopy(expected);clock=m.provider_epoch('2026-10-30T05:00:00Z')
        self.assertEqual(m.reconcile_historical_artifacts(actual,expected,run,clock),[])
        for key,value in [('name','changed'),('size_in_bytes',1),('created_at','2026-01-01T00:00:00Z')]:
            bad=deepcopy(actual);bad[0][key]=value
            with self.subTest(key=key),self.assertRaises(m.policy.Refusal):m.reconcile_historical_artifacts(bad,expected,run,clock)
        bad=deepcopy(actual);job=deepcopy(bad[0]);job['id']=999999999999999;bad.append(job)
        with self.assertRaises(m.policy.Refusal):m.reconcile_historical_artifacts(bad,expected,run,clock)

    def test_current_generation_artifact_gate_still_requires_live_unexpired(self):
        request={'phase':'validation','generation':{'runId':'123','pipelineHead':'a'*40,'artifactId':7,'artifactSha256':'b'*64}}
        run={'id':123,'head_sha':'a'*40,'run_attempt':1,'status':'completed','conclusion':'success',
            'repository':{'full_name':m.policy.REPOSITORY,'private':False},'actor':{'login':'fr-meyer'},
            'triggering_actor':{'login':'fr-meyer'}}
        native={'id':7,'name':'v109-lock-preparation-123-attempt1','digest':'sha256:'+'b'*64,'expired':False,'size_in_bytes':1024}
        for expired in (False,True):
            artifact=deepcopy(native);artifact['expired']=expired
            with patch.object(m,'jobs_for',return_value=[{'name':'lock-preparation','status':'completed','conclusion':'success'}]),\
                 patch.object(m,'artifacts_for',return_value=[artifact]),patch.object(m,'regular',return_value=b'synthetic receipt'),\
                 patch.object(m.policy,'validate_generation',return_value={'syntheticOnly':True}) as validate:
                call=lambda:m.validate_generation_provider(HERE,{},request,lambda path:run)
                if expired:
                    with self.assertRaises(m.policy.Refusal):call()
                    validate.assert_not_called()
                else:call();validate.assert_called_once()


if __name__=='__main__':unittest.main()
