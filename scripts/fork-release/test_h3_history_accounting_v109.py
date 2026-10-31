"""Pure accounting boundaries with captured public floors and synthetic native replies."""
from copy import deepcopy
from pathlib import Path
import socket,subprocess,unittest,urllib.request
from unittest.mock import patch
import bounded_run_contract_v109 as allowance
import source_validation_contract_v109 as policy
import source_validation_v109 as runtime
from test_h3_source_stage_v109 import fixture

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
NOW=policy.utc('2026-11-05T12:00:00Z').timestamp()
CURRENT='999900001'


def native_prefix():
    prefix=runtime.h3_prefix(ROOT)
    history={};jobs={};minutes={}
    for row in prefix['records']:
        rid=row['runId']
        history[rid]={'id':int(rid),'run_attempt':1,'head_sha':row['head'],'name':row['name'],
            'status':'completed','conclusion':row['conclusion'],
            'repository':{'full_name':policy.REPOSITORY,'private':False},
            'actor':{'login':'fr-meyer'},'triggering_actor':{'login':'fr-meyer'}}
        jobs[rid]=set(row['nativeJobIds']);minutes[(rid,1)]=0
    return prefix,history,minutes,jobs


def components(kind='preparation',current=1):
    prefix,history,minutes,jobs=native_prefix()
    charges=runtime.h3_prefix_floors(prefix,history,minutes,jobs)
    charges[CURRENT,1]=current
    return {'prefix':prefix,'grant':fixture()['ciRunGrant'],'run_minutes':charges,
        'run_pools':{**{r['runId']:'incidental' for r in prefix['records']},CURRENT:kind}}


def source_rows(count=1):
    """Synthetic new native rows; the pinned old legacy sequence is a separate seam."""
    b=fixture();oldraw=(HERE/'fixtures/v109-h3-anchor-request.json').read_bytes()
    oldq=policy.parse(oldraw);prior={'runId':'41154711378','pipelineHead':'9922a9505b772c407406b0275bbf74d6d2a31c54',
        'requestSha256':policy.digest(oldraw)}
    rows=[(prior['runId'],{'head_sha':prior['pipelineHead'],'status':'completed','conclusion':'failure'},oldq,oldraw)]
    bindings={};last=None
    for index in range(count):
        rid=str(int(CURRENT)+index);b=deepcopy(b)
        b['ciRunGrant']['nextExecution'].update(sequence=12+index,preparationAttempt=7+index,priorSourceRun=prior,
            reasonCode='approved_source_successor' if index==0 else 'prior_failure')
        q=policy.request_for(b,'lock-preparation',7+index);raw=policy.encode(q)
        rows.append((rid,{'head_sha':'a'*40,'status':'in_progress' if index==count-1 else 'completed',
            'conclusion':None if index==count-1 else 'failure'},q,raw))
        bindings[rid]=deepcopy(b);last=q
        prior={'runId':rid,'pipelineHead':'a'*40,'requestSha256':policy.digest(raw)}
    return b,last,rows,bindings


class H3HistoryAccountingTests(unittest.TestCase):
    def setUp(self):
        for obj,name in ((subprocess,'Popen'),(socket,'socket'),(urllib.request,'urlopen'),(urllib.request,'build_opener')):
            guard=patch.object(obj,name,side_effect=AssertionError('real host/network action forbidden'))
            guard.start();self.addCleanup(guard.stop)

    def test_real_hash_bound_prefix_contains_all_records_and_expiries(self):
        prefix=runtime.h3_prefix(ROOT)
        self.assertEqual((len(prefix['records']),len(prefix['expiryObservations']),len(prefix['artifacts'])),(293,49,26))
        self.assertEqual(sum(r['runnerMinutes'] for r in prefix['records']),2215)

    def test_all293_per_attempt_floors_apply_without_grand_total_refund(self):
        prefix,history,minutes,jobs=native_prefix()
        got=runtime.h3_prefix_floors(prefix,history,minutes,jobs)
        self.assertEqual(len(got),293);self.assertEqual(sum(got.values()),2215)
        for row in prefix['records']:self.assertEqual(got[row['runId'],1],row['runnerMinutes'])

    def test_surplus_in_one_attempt_cannot_offset_another_booked_attempt(self):
        prefix,history,minutes,jobs=native_prefix()
        row=next(r for r in prefix['records'] if r['runnerMinutes']==0)
        minutes[row['runId'],1]=2215
        got=runtime.h3_prefix_floors(prefix,history,minutes,jobs)
        self.assertEqual(sum(got.values()),4430)

    def test_missing_or_changed_record_and_native_jobs_refuse(self):
        prefix,history,minutes,jobs=native_prefix()
        for row in (prefix['records'][0],prefix['records'][145],prefix['records'][-1]):
            rid=row['runId']
            for kind in ('missing','head','conclusion','jobs'):
                h=deepcopy(history);j=deepcopy(jobs)
                if kind=='missing':del h[rid]
                elif kind=='jobs':j[rid]=set()
                else:h[rid][kind if kind!='head' else 'head_sha']='changed'
                with self.subTest(rid=rid,kind=kind),self.assertRaises(ValueError):
                    runtime.h3_prefix_floors(prefix,h,minutes,j)

    def test_all26_bookings_remain_positive_native_metadata(self):
        prefix=runtime.h3_prefix(ROOT);grant=fixture()['ciRunGrant']
        booked=runtime.h3_artifact_bookings(prefix,grant)
        self.assertEqual(sum(len(v) for v in booked.values()),26)
        self.assertEqual(sum(r['metadata']['size_in_bytes'] for v in booked.values() for r in v),395951)
        grant['sourceSuccessorAmendment']['bookedArtifacts'][0]['metadata']['size_in_bytes']+=1
        with self.assertRaises(ValueError):runtime.h3_artifact_bookings(prefix,grant)

    def test_each_expired_booked_payload_retains_bytes_without_claiming_custody(self):
        for row in runtime.h3_prefix(ROOT)['artifacts']:
            run={'id':int(row['producerRunId']),'head_sha':row['producerHead']}
            expiry=runtime.provider_epoch(row['metadata']['expires_at'])
            got=runtime.reconcile_h3_artifacts([], [row],run,expiry)
            self.assertEqual(got[0]['bookedBytes'],row['metadata']['size_in_bytes'])
            self.assertFalse(got[0]['custodyClaimed']);self.assertEqual(got[0]['absenceCause'],'unproved')
            with self.subTest(id=row['metadata']['id']),self.assertRaises(ValueError):
                runtime.reconcile_h3_artifacts([], [row],run,expiry-1)

    def test_unknown_expiry_and_wrong_producer_refuse(self):
        row=deepcopy(runtime.h3_prefix(ROOT)['artifacts'][0]);run={'id':int(row['producerRunId']),'head_sha':row['producerHead']}
        row['fieldPresence']['expires_at']=False
        with self.assertRaises(ValueError):runtime.reconcile_h3_artifacts([], [row],run,NOW)
        row=runtime.h3_prefix(ROOT)['artifacts'][0]
        with self.assertRaises(ValueError):runtime.reconcile_h3_artifacts([], [row],{**run,'head_sha':'0'*40},NOW)

    def test_present_metadata_cannot_change_and_expiry_only_advances(self):
        row=runtime.h3_prefix(ROOT)['artifacts'][0];run={'id':int(row['producerRunId']),'head_sha':row['producerHead']}
        actual=deepcopy(row['metadata']);actual['expired']=True
        self.assertEqual(runtime.reconcile_h3_artifacts([actual],[row],run,NOW),[])
        for key,value in (('size_in_bytes',0),('digest','sha256:'+'0'*64),('expires_at','2026-11-30T00:00:00Z')):
            bad=deepcopy(actual);bad[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):runtime.reconcile_h3_artifacts([bad],[row],run,NOW)

    def test_native_components_and_reserved_remainders_are_exact(self):
        facts=components('preparation',7)
        total,got=runtime.h3_minute_facts(facts,CURRENT,7)
        self.assertEqual(total,2222);self.assertEqual(got,dict(preparationObservedMinutes=7,sourceObservedMinutes=0,
            incidentalObservedMinutes=0,imageObservedMinutes=0,remainingImageFamilyReserveMinutes=180,
            remainingIncidentalReserveMinutes=160))

    def test_each_component_pool_cannot_be_exceeded(self):
        for kind,limit in allowance.H3_STAGE_POOLS.items():
            facts=components(kind,limit+1)
            with self.subTest(kind=kind),self.assertRaises(ValueError):runtime.h3_minute_facts(facts,CURRENT,limit+1)

    def test_additional_booked_floor_is_never_refunded(self):
        facts=components('source',10);old=next(r for r in facts['grant']['bookedAdditionalAttempts'] if r['runnerMinutes']>0)
        old['runnerMinutes']+=3
        total,got=runtime.h3_minute_facts(facts,CURRENT,10)
        self.assertEqual(total,2228);self.assertEqual(got['incidentalObservedMinutes'],3)
        self.assertEqual(got['remainingIncidentalReserveMinutes'],157)

    def test_missing_booked_attempt_and_prebooked_current_refuse(self):
        facts=components();row=facts['grant']['bookedAdditionalAttempts'][0]
        del facts['run_minutes'][row['runId'],1]
        with self.assertRaises(ValueError):runtime.h3_minute_facts(facts,CURRENT,1)
        facts=components();facts['grant']['bookedAdditionalAttempts'].append({'runId':CURRENT,'nativeAttempt':1,'runnerMinutes':2})
        with self.assertRaises(ValueError):runtime.h3_minute_facts(facts,CURRENT,1)

    def test_image_component_projection_books_unspent_source_and_preparation(self):
        facts=components('image',5)
        facts.update(stage=allowance.h3_stage_descriptor(),source_rows=[('999900002',{'status':'completed','conclusion':'success'}, {'synthetic':'selected'}, b'synthetic')],
            current={'id':int(CURRENT)},source_bindings={},artifact_absences=[])
        jobs=[{'id':1,'name':'image-admission','run_attempt':1,'status':'in_progress','conclusion':None,
            'runner_id':1,'runner_group_name':'GitHub Actions','labels':['ubuntu-24.04'],
            'started_at':'2026-11-05T11:55:00Z','completed_at':None},
            {'id':2,'name':'build-private-image','run_attempt':1,'status':'queued','runner_id':0,'steps':[]}]
        # An adapter unit only: native collector/floor tests above are distinct.
        with patch.object(policy,'h3_stage_contract',return_value=allowance.h3_stage_descriptor()),patch.object(runtime,'load_owner',return_value=object()),\
                patch.object(runtime,'collect_history_accounting',return_value=facts) as collect,\
                patch.object(runtime,'bounded_source_history'),patch.object(runtime,'jobs_for',return_value=jobs):
            got=runtime.image_cumulative_booking(ROOT,None,{}, {'synthetic':'selected'},CURRENT,NOW)
            self.assertEqual(got['newObservedOrBookedMinutes'],5580)
            self.assertEqual(got['currentObservedMinutes'],5)
            self.assertEqual(got['remainingIncidentalReserveMinutes'],160)
            self.assertTrue(collect.call_args.kwargs['image'])
            jobs[1].update(status='in_progress',runner_id=1)
            with self.assertRaises(ValueError):runtime.image_cumulative_booking(ROOT,None,{}, {'synthetic':'selected'},CURRENT,NOW)
            jobs[0].update(status='completed',conclusion='success',completed_at='2026-11-05T11:57:00Z')
            jobs[1].update(run_attempt=1,runner_group_name='GitHub Actions',labels=['ubuntu-24.04'],started_at='2026-11-05T11:57:00Z')
            self.assertEqual(runtime.image_cumulative_booking(ROOT,None,{}, {'synthetic':'selected'},CURRENT,NOW)['currentObservedMinutes'],5)

    def test_h3_sequence_reuses_actual_family_and_exact_anchor_pin(self):
        b,q,rows,bindings=source_rows()
        # The unchanged legacy H2 sequence has its own70 regression cases.
        with patch.object(runtime,'bounded_source_history',return_value={'sourceExecutionSequence':11}) as old:
            got=runtime.h3_source_history(ROOT,b,q,rows,CURRENT,bindings)
            self.assertEqual(got['sourceExecutionSequence'],12);self.assertEqual(got['materialSourceGenerations'],1)
            self.assertNotIn('sourceSuccessor',old.call_args.args[0])
        q['priorRunPins'][0]['requestSha256']='0'*64
        with patch.object(runtime,'bounded_source_history',return_value={'sourceExecutionSequence':11}),self.assertRaises(ValueError):
            runtime.h3_source_history(ROOT,b,q,rows,CURRENT,bindings)

    def test_five_reviewed_prechecks_do_not_fabricate_five_material_generations(self):
        b,q,rows,bindings=source_rows(5);rid=rows[-1][0]
        with patch.object(runtime,'bounded_source_history',return_value={'sourceExecutionSequence':11}):
            got=runtime.h3_source_history(ROOT,b,q,rows,rid,bindings)
            self.assertEqual(got['sourceExecutionSequence'],16);self.assertEqual(got['materialSourceGenerations'],1)
            changed=deepcopy(rows);del changed[2]
            with self.assertRaises(ValueError):runtime.h3_source_history(ROOT,b,q,changed,rid,bindings)

    def test_historical_material_generation_cannot_be_rewritten(self):
        b,q,rows,bindings=source_rows(2);rid=rows[-1][0]
        bindings[rows[1][0]]['sourceSuccessor']['generations'][0]['unchangedTreeSha256']='0'*64
        with patch.object(runtime,'bounded_source_history',return_value={'sourceExecutionSequence':11}),self.assertRaises(ValueError):
            runtime.h3_source_history(ROOT,b,q,rows,rid,bindings)


if __name__=='__main__':unittest.main()
