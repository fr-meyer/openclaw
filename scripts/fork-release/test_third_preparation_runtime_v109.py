"""Runtime bridge control tests; only in-memory approvals and fake providers."""
from copy import deepcopy
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
if not (HERE/"lockfile_policy_v109.py").is_file():
    CI=next(parent for parent in HERE.parents if parent.name=="ci-binding-preparation-r1")
    sys.path.append(str(CI/"pipeline/scripts/fork-release"))
import source_validation_v109 as m
import test_third_preparation_contract_v109 as f


def legacy_binding():
    b=f.recovery_binding(True)
    b.pop("ciRunGrant",None)  # Reconstruct only the immutable historical request context.
    b['baseline']['publicProofSha256']='dfc2cda1a2c7c5f3f4e1bc235e8a6e2aca615e62c5ce20a79102a794779770df'
    b['preparationCorrection']={'schema':m.policy.PIPELINE_RECOVERY_SCHEMA,'source':deepcopy(b['preparation']),
        'priorPhase':'lock-preparation','priorFailure':deepcopy(m.policy.FAILED_PREPARATION_PIN),
        'failedPreparationAttempt':1,'nextPreparationAttempt':2,'reasonCode':'v9.workflow_merge_parents',
        'evidenceSha256':m.policy.PREPARATION_FAILURE_EVIDENCE_SHA256}
    return b


def prior_rows():
    b=f.recovery_binding(True);old=legacy_binding();rows=[];jobs={};proofs=[]
    for index,path in enumerate((m.policy.PREPARATION_FAILURE_EVIDENCE,m.policy.ADDITIONAL_PREPARATION_FAILURE_EVIDENCE),1):
        proof=m.policy.parse((HERE/path.split('scripts/fork-release/',1)[1]).read_bytes());proofs.append(proof)
        q=m.policy.request_for(old,'lock-preparation',index);raw=m.policy.encode(q)
        assert m.policy.digest(raw)==proof['requestSha256']
        run={'id':int(proof['runId']),'head_sha':proof['pipelineHead'],'status':'completed','conclusion':'failure',
            'event':'pull_request','run_attempt':1,'head_branch':m.policy.PIPELINE_BRANCH,'path':m.policy.WORKFLOW,
            'name':m.policy.CAMPAIGN,'display_title':m.policy.CAMPAIGN,'repository':{'full_name':m.policy.REPOSITORY,'private':False},
            'actor':{'login':'fr-meyer'},'triggering_actor':{'login':'fr-meyer'}}
        names=['Set up job','Start shared deadline before checkout','Checkout reviewed pipeline closure',proof['failedStep'],
            *proof['skippedCandidateSteps'],'Post Checkout reviewed pipeline closure','Complete job']
        job={'id':proof['jobId'],'name':'lock-preparation','run_attempt':1,'status':'completed','conclusion':'failure',
            'runner_id':12,'runner_name':'synthetic runner','runner_group_name':'GitHub Actions','labels':['ubuntu-24.04'],
            'started_at':proof['nativeStartedAt'],'completed_at':proof['nativeCompletedAt'],
            'steps':[{'name':name,'status':'completed','conclusion':('failure' if name==proof['failedStep'] else
                'skipped' if name in proof['skippedCandidateSteps'] else 'success')}for name in names]}
        rows.append((proof['runId'],run,q,raw));jobs[proof['runId']]=[job]
    return b,rows,jobs,proofs


class ThirdPreparationRuntimeTests(unittest.TestCase):
    def test_disarmed_supplement_refuses_before_any_host_or_api(self):
        b=f.recovery_binding();raw=m.policy.encode(b)
        def regular(path,maximum=0):return raw if str(path).endswith('ci-bindings.json') else b'{}'
        with patch.object(m,'regular',side_effect=regular),patch.object(m,'load_owner') as loader,\
             patch.object(m,'API') as api,patch.object(subprocess,'run') as process:
            with self.assertRaises(m.policy.Refusal):m.main(['admit'],{'GITHUB_WORKSPACE':'/synthetic-only'})
            loader.assert_not_called();api.assert_not_called();process.assert_not_called()

    def test_third_parent_is_exact_second_failure_head(self):
        b=f.recovery_binding(True);q=m.policy.request_for(b,'lock-preparation',3);head='e'*40;calls=[]
        def read(*args):calls.append(args);return (m.policy.SECOND_FAILED_PREPARATION_PIN['pipelineHead']+'\n').encode()
        m.preparation_pipeline_ancestry(read,head,q,b)
        self.assertEqual(calls,[('show','-s','--format=%P',head)])
        for parents in (m.policy.FAILED_PREPARATION_PIN['pipelineHead'],'f'*40,
                        m.policy.SECOND_FAILED_PREPARATION_PIN['pipelineHead']+' '+'f'*40):
            with self.subTest(parents=parents),self.assertRaises(m.policy.Refusal):
                m.preparation_pipeline_ancestry(lambda *args:(parents+'\n').encode(),head,q,b)

    def test_later_validation_requires_generation_ancestry_not_direct_failed_parent(self):
        b=f.recovery_binding(True);q={'phase':'validation','preparationAttempt':3,'generation':{'pipelineHead':'d'*40}}
        calls=[]
        def read(*args):calls.append(args);return b''
        m.preparation_pipeline_ancestry(read,'e'*40,q,b)
        self.assertEqual(calls,[('merge-base','--is-ancestor','d'*40,'e'*40)])
        def wrong(*args):raise subprocess.CalledProcessError(1,['synthetic metadata'])
        with self.assertRaises(m.policy.Refusal):m.preparation_pipeline_ancestry(wrong,'e'*40,q,b)
        q['phase']='correction'
        with self.assertRaises(m.policy.Refusal):m.preparation_pipeline_ancestry(read,'e'*40,q,b)

    def test_both_failures_replayed_and_charged_without_generation(self):
        b,rows,jobs,proofs=prior_rows();original=m.policy.digest
        def content(api,path,sha,maximum=131072):
            if path==m.policy.WORKFLOW:return b'synthetic workflow'
            return b'synthetic runtime1'if sha==proofs[0]['pipelineHead']else b'synthetic runtime2'
        def digest(raw):
            if raw==b'synthetic workflow':return proofs[0]['producerWorkflowSha256']
            for index,proof in enumerate(proofs,1):
                if raw==('synthetic runtime'+str(index)).encode():return proof['producerRuntimeSha256']
            return original(raw)
        with patch.object(m,'content',side_effect=content),patch.object(m.policy,'digest',side_effect=digest),\
             patch.object(m,'jobs_for',side_effect=lambda api,run:jobs[str(run['id'])]),patch.object(m,'artifacts_for',return_value=[]):
            result=m.pipeline_recovery_history(HERE.parents[1],b,rows,None)
        self.assertEqual(result['priorRunnerMinutes'],16);self.assertEqual([r['observedRunnerMinutes']for r in result['priorFailures']],[9,7])
        self.assertFalse(result['generationProduced']);self.assertFalse(result['optionalCorrectionAllowed'])

    def test_missing_failure_wrong_prior_or_executed_candidate_refuses(self):
        b,base,jobs,proofs=prior_rows();original=m.policy.digest
        def digest(raw):
            if raw==b'w':return proofs[0]['producerWorkflowSha256']
            for index,proof in enumerate(proofs,1):
                if raw==('r'+str(index)).encode():return proof['producerRuntimeSha256']
            return original(raw)
        def content(api,path,sha,maximum=131072):return b'w'if path==m.policy.WORKFLOW else b'r1'if sha==proofs[0]['pipelineHead']else b'r2'
        for defect in ('missing-first','missing-second','q2-prior-empty','q1-prior-nonempty','generation','candidate','artifact','producer'):
            rows=deepcopy(base);table=deepcopy(jobs);arts=[]
            if defect=='missing-first':rows.pop(0)
            elif defect=='missing-second':rows.pop()
            elif defect=='q2-prior-empty':rows[1][2]['priorRunPins']=[]
            elif defect=='q1-prior-nonempty':rows[0][2]['priorRunPins']=[m.policy.FAILED_PREPARATION_PIN]
            elif defect=='generation':rows[1][2]['generation']={'fake':True}
            elif defect=='candidate':table[proofs[1]['runId']][0]['steps'][4]['conclusion']='success'
            elif defect=='artifact':arts=[{'id':1}]
            def selected_content(api,path,sha,maximum=131072):return b'wrong'if defect=='producer'else content(api,path,sha,maximum)
            with self.subTest(defect=defect),patch.object(m,'content',side_effect=selected_content),patch.object(m.policy,'digest',side_effect=digest),\
                 patch.object(m,'jobs_for',side_effect=lambda api,run:table[str(run['id'])]),patch.object(m,'artifacts_for',return_value=arts):
                with self.assertRaises(m.policy.Refusal):m.pipeline_recovery_history(HERE.parents[1],b,rows,None)

    def test_third_family_reserves45_inside90_and_one_validation(self):
        b,locks,jobs,proofs=prior_rows();q=m.policy.request_for(b,'lock-preparation',3);current='999999'
        now=m.policy.utc('2026-10-30T06:02:00Z').timestamp()
        run={**locks[1][1],'id':int(current),'status':'in_progress'}
        locks.append((current,run,q,b''));job=deepcopy(jobs[proofs[1]['runId']][0]);job.update(status='in_progress',conclusion=None,started_at='2026-10-30T06:00:00Z',completed_at=None);jobs[current]=[job]
        with patch.object(m,'jobs_for',side_effect=lambda api,run:jobs[str(run['id'])]):
            result=m.additional_history_booking(b,q,locks,[],current,2,28,10,None,now)
        self.assertEqual(result['preparationFamilyBookedMinutes'],61);self.assertEqual(result['maximumPreparationFamilyMinutes'],90)
        self.assertEqual(result['maximumSourceCampaigns'],1);self.assertFalse(result['optionalCorrectionAllowed'])
        self.assertLessEqual(result['bookedMinutes'],1395)

    def test_family_money_incidental_and_execution_count_bounds_refuse(self):
        b,locks,jobs,proofs=prior_rows();q=m.policy.request_for(b,'lock-preparation',3);current='999999'
        run={**locks[1][1],'id':int(current),'status':'in_progress'};locks.append((current,run,q,b''))
        for count,vals,total,incidental,family_min in ((4,[],28,10,9),(3,[('888',{},dict(q,phase='correction'),b'')],28,10,9),
                (3,[],2501,10,9),(3,[],28,51,9),(3,[],28,10,46)):
            chosen=deepcopy(locks)
            if count==4:chosen.append(deepcopy(chosen[-1]))
            with self.subTest(count=count,total=total,incidental=incidental,family=family_min),\
                 patch.object(m,'jobs_for',return_value=[]),patch.object(m,'observed_jobs',return_value=(family_min,set())):
                with self.assertRaises(m.policy.Refusal):m.additional_history_booking(b,q,chosen,vals,current,2,total,incidental,None,0)

    def test_additional_history_admits_only_three_distinct_logical_preparations(self):
        b,rows,jobs,proofs=prior_rows();b['baseline']['publicProofSha256']='dfc2cda1a2c7c5f3f4e1bc235e8a6e2aca615e62c5ce20a79102a794779770df'
        q=m.policy.request_for(b,'lock-preparation',3);raw=m.policy.encode(q);head='e'*40;rid='999999'
        current={**rows[-1][1],'id':int(rid),'head_sha':head,'status':'in_progress','conclusion':None,'created_at':'2026-10-30T06:00:00Z'}
        history={key:{**run,'created_at':'2026-10-30T03:31:00Z'if index==0 else '2026-10-30T04:34:00Z'}
            for index,(key,run,request,body)in enumerate(rows)};history[rid]=current
        currentjob=deepcopy(jobs[proofs[-1]['runId']][0]);currentjob.update(id=99999,status='in_progress',conclusion=None,
            started_at='2026-10-30T06:00:00Z',completed_at=None);jobs[rid]=[currentjob]
        old=legacy_binding();first=deepcopy(old);first['preparationCorrection']=None
        heads={proofs[0]['pipelineHead']:(first,rows[0][2],rows[0][3]),proofs[1]['pipelineHead']:(old,rows[1][2],rows[1][3]),head:(b,q,raw)}
        original=m.policy.digest
        def content(api,path,sha,maximum=131072):
            if path==m.BINDINGS:return m.policy.encode(heads[sha][0])
            if path==m.REQUEST:return heads[sha][2]
            if path==m.policy.WORKFLOW:return b'synthetic workflow'
            return b'synthetic runtime1'if sha==proofs[0]['pipelineHead']else b'synthetic runtime2'
        def digest(value):
            if value==b'synthetic workflow':return proofs[0]['producerWorkflowSha256']
            for index,proof in enumerate(proofs,1):
                if value==('synthetic runtime'+str(index)).encode():return proof['producerRuntimeSha256']
            return original(value)
        witness={path:m.policy.parse((HERE/path.split('scripts/fork-release/',1)[1]).read_bytes()) for path in
            (m.policy.PREPARATION_FAILURE_EVIDENCE,m.policy.ADDITIONAL_PREPARATION_FAILURE_EVIDENCE)}
        def regular(path,maximum=0):
            for target,value in witness.items():
                if str(path).endswith(target):return m.policy.encode(value)
            return b'synthetic baseline input'
        resolver=types.SimpleNamespace(resolve_baseline_258=lambda *args:{'runs':[]},WORKFLOW='historical source role')
        with patch.object(m,'history_rows',return_value=history),patch.object(m,'closed_baseline',side_effect=lambda *args:(set(),set(),set())),\
             patch.object(m,'regular',side_effect=regular),patch.object(m,'content',side_effect=content),patch.object(m.policy,'digest',side_effect=digest),\
             patch.object(m,'jobs_for',side_effect=lambda api,run:jobs[str(run['id'])]),patch.object(m,'artifacts_for',return_value=[]):
            result=m.history_checks(HERE.parents[1],b,q,raw,head,{}, {'GITHUB_RUN_ID':rid},None,resolver,
                m.policy.utc('2026-10-30T06:02:00Z').timestamp())
        self.assertEqual(result['lockPreparations'],3);self.assertEqual(result['sourceExecutions'],0)
        self.assertEqual(result['pipelinePreparationRecovery']['priorRunnerMinutes'],16)
        self.assertEqual(result['additionalPreparationBooking']['preparationFamilyBookedMinutes'],61)
        self.assertEqual(result['maximumNewMinutes'],2500)

    def test_attempt_three_static_source_uses_original_g_two_parents(self):
        b=f.recovery_binding(True);q=m.policy.request_for(b,'lock-preparation',3)
        manifest=m.policy.encode({'source':{'commit':b['preparation']['sourceSha'],'tree':b['preparation']['sourceTree']},'productionEligible':False})
        original=m.policy.digest
        def digest(raw):
            if raw==manifest:return q['source']['manifestSha256']
            if raw==b'synthetic inventory':return q['source']['inventorySha256']
            return original(raw)
        def regular(path,maximum=0):return manifest if str(path).endswith('manifest.json')else b'synthetic inventory'
        def read(*args):
            self.assertEqual(args,('show','-s','--format=%P',q['source']['sourceSha']))
            return (m.policy.BASELINE_SOURCE+' '+m.policy.UPSTREAM['commit']+'\n').encode()
        core=types.SimpleNamespace(preflight=types.SimpleNamespace(inventory_at=lambda *a,**k:{'syntheticOnly':True}),_v4_tree=unittest.mock.Mock())
        with patch.object(m,'source_binding',return_value=read),patch.object(m,'regular',side_effect=regular),patch.object(m.policy,'digest',side_effect=digest):
            self.assertEqual(m.static_source(HERE,Path('/synthetic-source'),b,q,core,{'deadlineEpoch':0}),{'syntheticOnly':True})
        core._v4_tree.assert_not_called()


if __name__=='__main__':unittest.main()
