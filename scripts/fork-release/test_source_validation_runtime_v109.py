"""Fake host/provider tests only; no Git, Node, application, HTTP or CI runs."""
from copy import deepcopy
from datetime import datetime, timezone
import importlib.util
import contextlib
import io
import json
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
LOCAL_LAYOUT=(HERE.name=='tests')
ROOT=HERE.parent if LOCAL_LAYOUT else HERE.parents[1]
OWNERS=ROOT/'pipeline/scripts/fork-release' if LOCAL_LAYOUT else HERE
WORKFLOWS=ROOT/'workflow' if LOCAL_LAYOUT else OWNERS/'fixtures'
BASELINE_VIEW=ROOT/'baseline-r1/test-view' if LOCAL_LAYOUT else ROOT
BASELINE_OWNER=ROOT/'baseline-r1' if LOCAL_LAYOUT else OWNERS


def workflow(name):
    return WORKFLOWS/(name+'.yml' if LOCAL_LAYOUT else 'v109-'+name+'.yml')
sys.path.insert(0,str(OWNERS))
import source_validation_contract_v109 as policy
import source_validation_v109 as owner
import test_source_validation_contract_v109 as fixture

NOW=int(datetime(2026,11,1,0,5,tzinfo=timezone.utc).timestamp())


def binding(active=True):
    b=fixture.binding()
    if active:b.update(status='APPROVED_CI',authorization=fixture.authorization())
    return b


def event_env():
    h='d'*40
    repo={'full_name':policy.REPOSITORY,'private':False}
    event={'action':'synchronize','number':28,'repository':deepcopy(repo),'pull_request':{
        'number':28,'state':'open','draft':True,'head':{'repo':deepcopy(repo),'sha':h,'ref':policy.PIPELINE_BRANCH},
        'base':{'repo':deepcopy(repo),'sha':policy.BASE,'ref':policy.BASE_BRANCH}}}
    env={'GITHUB_ACTIONS':'true','RUNNER_OS':'Linux','RUNNER_ENVIRONMENT':'github-hosted',
        'GITHUB_EVENT_NAME':'pull_request','GITHUB_RUN_ATTEMPT':'1','GITHUB_REPOSITORY':policy.REPOSITORY,
        'GITHUB_ACTOR':'fr-meyer','GITHUB_REF':'refs/pull/28/merge','GITHUB_RUN_ID':'123456789',
        'GITHUB_WORKFLOW_REF':policy.REPOSITORY+'/'+policy.WORKFLOW+'@refs/pull/28/merge',
        'GITHUB_WORKFLOW_SHA':'e'*40,owner.CLOCK:str(NOW-60)}
    return event,env


def job(name='admission',status='in_progress',jid=7):
    return {'id':jid,'name':name,'run_attempt':1,'status':status,'conclusion':None,
        'runner_id':12,'runner_name':'Hosted Agent','runner_group_name':'GitHub Actions',
        'labels':['ubuntu-24.04'],'steps':[], 'started_at':'2026-11-01T00:04:00Z','completed_at':None}


def synthetic_historical_provider_job(run, recorded):
    """Explicit synthetic native envelope for fakeAPI, never an observation.

    Historical recorded facts are copied without modifying the frozen record;
    unrecorded provider envelope fields are modeled test values. The actual
    retained774-response replay independently checks real provider data.
    """
    value={"id":recorded["id"],"run_id":run["id"],"workflow_name":"synthetic provider envelope",
        "head_branch":run["head_branch"],"run_url":"https://example.invalid/synthetic/run",
        "run_attempt":run["run_attempt"],"node_id":"synthetic provider node","head_sha":run["head_sha"],
        "url":"https://example.invalid/synthetic/job","html_url":"https://example.invalid/synthetic/html",
        "status":recorded["status"],"conclusion":recorded["conclusion"],
        "created_at":"2026-01-01T00:00:00Z","started_at":recorded["started_at"],"completed_at":recorded["completed_at"],
        "name":recorded["name"],"steps":[],"check_run_url":"https://example.invalid/synthetic/check",
        "labels":deepcopy(recorded["labels"]),"runner_id":recorded["runner_id"],
        "runner_name":recorded["runner_name"],"runner_group_id":None,"runner_group_name":recorded["runner_group_name"]}
    for key,item in recorded.items():
        if key not in ("_fieldsPresent","steps"):
            value[key]=deepcopy(item)
    for step in recorded["steps"]:
        native={"started_at":"2026-01-01T00:00:00Z","completed_at":"2026-01-01T00:00:01Z"}
        native.update(deepcopy(step));value["steps"].append(native)
    return value


def legacy_first_preparation_view(current, proof):
    """Historical test view only; never select its mode from the current PC."""
    if current["preparation"] != proof["source"]:
        raise AssertionError("historical source binding changed")
    value=deepcopy(current)
    value.pop("ciRunGrant",None)  # Historical view must not inherit a later allowance.
    value["validation"],value["correction"]=None,None
    value["preparationCorrection"]={"schema":policy.PIPELINE_RECOVERY_SCHEMA,
        "source":deepcopy(value["preparation"]),"priorPhase":"lock-preparation",
        "priorFailure":deepcopy(policy.FAILED_PREPARATION_PIN),"failedPreparationAttempt":1,
        "nextPreparationAttempt":2,"reasonCode":"v9.workflow_merge_parents",
        "evidenceSha256":policy.PREPARATION_FAILURE_EVIDENCE_SHA256}
    return value


def legacy_first_preparation_request(current, proof):
    """Replay pinned producer bytes, not a serialization of mutable input order."""
    value=legacy_first_preparation_view(current,proof)
    raw=(OWNERS/'fixtures/v109-first-preparation-source-request.json').read_bytes()
    expected=policy.FAILED_PREPARATION_PIN['requestSha256']
    if policy.digest(raw)!=expected or proof['requestSha256']!=expected:
        raise AssertionError('historical request bytes changed')
    request=policy.parse(raw)
    if request!=policy.request_for(value,'lock-preparation',1):
        raise AssertionError('historical request semantic binding changed')
    return value,request,raw


class RuntimeTests(unittest.TestCase):
    def test_exact_public_event(self):
        e,v=event_env();self.assertEqual(owner.event_binding(e,v),'d'*40)

    def test_event_host_actor_attempt_repository_and_ref(self):
        for key,value in [('GITHUB_ACTOR','other'),('GITHUB_RUN_ATTEMPT','2'),('RUNNER_ENVIRONMENT','self-hosted'),
                          ('GITHUB_REF','refs/heads/main'),('GITHUB_EVENT_NAME','workflow_dispatch')]:
            e,v=event_env();v[key]=value
            with self.subTest(key=key),self.assertRaises(policy.Refusal):owner.event_binding(e,v)

    def test_event_rejects_non_draft_or_fork(self):
        e,v=event_env();e['pull_request']['draft']=False
        with self.assertRaises(policy.Refusal):owner.event_binding(e,v)
        e,v=event_env();e['pull_request']['head']['repo']['full_name']='other/openclaw'
        with self.assertRaises(policy.Refusal):owner.event_binding(e,v)

    def test_disarmed_metadata_refuses_before_process_network_or_owner_import(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve();directory=root/'pipeline'/owner.CANDIDATE;directory.mkdir(parents=True)
            b=binding(False)
            (directory/'ci-bindings.json').write_bytes(policy.encode(b))
            (directory/'source-request.json').write_bytes(policy.encode(policy.request_for(b,'lock-preparation')))
            with patch.object(owner,'load_owner') as loader,patch.object(subprocess,'run') as process,patch.object(owner,'API') as api:
                with self.assertRaisesRegex(policy.Refusal,'disarmed'):
                    owner.main(['admit'],{'GITHUB_WORKSPACE':str(root)})
                loader.assert_not_called();process.assert_not_called();api.assert_not_called()

    def test_fixed_job_clock_counts_checkout_and_refuses_expired(self):
        b=binding();r=policy.request_for(b,'lock-preparation');_,e=event_env()
        self.assertEqual(owner.job_deadline(b,r,e,clock=NOW),NOW-60+45*60-60)
        e[owner.CLOCK]=str(NOW-45*60)
        with self.assertRaisesRegex(policy.Refusal,'job_clock'):owner.job_deadline(b,r,e,clock=NOW)

    def test_profile_cap_is_not_admission_cap(self):
        b=binding();r=policy.request_for(b,'lock-preparation');_,e=event_env()
        self.assertEqual(owner.job_deadline(b,r,e,'doctor-1',clock=NOW),NOW-60+90*60-60)

    def test_admission_output_cannot_authorize_different_run_or_source(self):
        b=binding();r=policy.request_for(b,'lock-preparation');raw=policy.encode(r);_,e=event_env()
        e.update({owner.OPERATION:policy.digest(raw),'V109_ADMISSION_PIPELINE_HEAD':'d'*40,
            'V109_ADMISSION_SOURCE_SHA':r['source']['sourceSha'],'V109_ADMISSION_RUN_ID':e['GITHUB_RUN_ID']})
        owner.check_admission_outputs(e,r,raw,'d'*40)
        for k in (owner.OPERATION,'V109_ADMISSION_PIPELINE_HEAD','V109_ADMISSION_SOURCE_SHA','V109_ADMISSION_RUN_ID'):
            bad=dict(e);bad[k]='changed'
            with self.subTest(k=k),self.assertRaises(policy.Refusal):owner.check_admission_outputs(bad,r,raw,'d'*40)

    def test_provider_timing_fractional_and_positive_zero(self):
        self.assertEqual(owner.observed_jobs([job()],NOW,limits=owner.SOURCE_JOBS)[0],1)
        j=job(status='completed');j.update(conclusion='success',completed_at='2026-11-01T00:05:00.000Z')
        self.assertEqual(owner.observed_jobs([j],NOW,terminal=True,limits=owner.SOURCE_JOBS)[0],1)
        j=job(status='completed');j.update(conclusion='skipped',runner_id=0,runner_name='',steps=[])
        self.assertEqual(owner.observed_jobs([j],NOW,terminal=True,limits=owner.SOURCE_JOBS)[0],0)
        j['steps']=[{'name':'executed'}]
        with self.assertRaises(policy.Refusal):owner.observed_jobs([j],NOW,terminal=True,limits=owner.SOURCE_JOBS)

    def test_provider_rejects_self_hosted_duplicate_or_overcap(self):
        for mutate in (lambda j:j.update(labels=['self-hosted']),lambda j:j.update(name='image-build'),
                       lambda j:j.update(started_at='2026-10-31T00:00:00Z')):
            j=job();mutate(j)
            with self.assertRaises(policy.Refusal):owner.observed_jobs([j],NOW,limits=owner.SOURCE_JOBS)
        with self.assertRaises(policy.Refusal):owner.observed_jobs([job(),job()],NOW)

    def test_api_cap_redirect_and_mutation_route_refused(self):
        class Response:
            def __init__(self,url,raw):self.url,self.raw=url,raw
            def __enter__(self):return self
            def __exit__(self,*a):pass
            def geturl(self):return self.url
            def read(self,n):return self.raw[:n]
        class Opener:
            def __init__(self,raw=b'{}',redirect=False):self.raw,self.redirect,self.requests=raw,redirect,[]
            def open(self,request,timeout):
                self.requests.append(request)
                return Response('https://untrusted.example/' if self.redirect else request.full_url,self.raw)
        o=Opener();api=owner.API('SYNTHETIC',time_future(),o)
        self.assertEqual(api('/repos/fr-meyer/openclaw/pulls/28'),{})
        self.assertEqual(o.requests[0].get_method(),'GET')
        self.assertEqual(len(o.requests),1)
        api('/repos/fr-meyer/openclaw/pulls/28');self.assertEqual(len(o.requests),1)
        with self.assertRaises(policy.Refusal):api('/repos/other/openclaw/pulls/28')
        with self.assertRaises(policy.Refusal):owner.API('x',time_future(),Opener(redirect=True))('/repos/fr-meyer/openclaw/pulls/28')
        with self.assertRaises(policy.Refusal):owner.API('x',time_future(),Opener(b'x'*(4*1024*1024+1)))('/repos/fr-meyer/openclaw/pulls/28')

    def test_complete_pagination_not_partial_or_changed(self):
        calls=[]
        def api(path):
            calls.append(path)
            return {'total_count':101,'jobs':[{'id':i} for i in range(100)] if path.endswith('&page=1') else [{'id':100}]}
        self.assertEqual(len(owner.paged(api,'/actions/runs/1/jobs?filter=all','jobs',200)),101)
        self.assertEqual(len(calls),2)
        with self.assertRaises(policy.Refusal):owner.paged(lambda p:{'total_count':2,'jobs':[{}]},'/x','jobs')

    def test_private_write_once_no_symlink_and_mode(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d).resolve()/'receipt.json';owner.private_write(path,b'{}')
            self.assertEqual(path.stat().st_mode&0o777,0o600)
            with self.assertRaises(FileExistsError):owner.private_write(path,b'changed')
            link=Path(d).resolve()/'link';link.symlink_to(path)
            with self.assertRaises(policy.Refusal):owner.regular(link)

    def test_result_success_is_not_image_or_qualification(self):
        b,_=fixture.populated();r=policy.request_for(b,'validation');e,v=event_env()
        result=owner.source_result(r,policy.encode(r),v,'d'*40,'success','success')
        self.assertEqual(result['status'],'passed')
        self.assertTrue(result['freshCoverage']);self.assertEqual(len(result['selectedProfiles']),15)
        for k in ('imageBuilt','nativeImageExecuted','productionAuthorized','historicalCoverageReused'):self.assertIs(result[k],False)
        failed=owner.source_result(r,policy.encode(r),v,'d'*40,'failure','skipped')
        self.assertEqual(failed['status'],'failed');self.assertIs(failed['freshCoverage'],False)

    def test_fixed_tag_presence_materialization_and_all_refusal_paths_fake_only(self):
        fixture_path=OWNERS/'fixtures/v2026.10.9.official.tag.raw'
        if not fixture_path.is_file():
            fixture_path=ROOT.parent/'local-integration-r1/tag-fetch-receipts-r1/v2026.10.9.official.tag.raw'
        raw=fixture_path.read_bytes()
        self.assertEqual(len(raw),owner.TAG_BYTES);self.assertEqual(policy.digest(raw),owner.TAG_SHA256)
        scenarios=('present','missing','wrong-raw','wrong-type','wrong-commit','wrong-peel','nonzero','timeout','head-change','shallow')
        for scenario in scenarios:
            with self.subTest(scenario=scenario),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary).resolve();pipeline=root/'pipeline';source=root/'source';pipeline.mkdir();source.mkdir()
                path=pipeline/owner.TAG_FIXTURE;path.parent.mkdir(parents=True)
                path.write_bytes((b'X'+raw[1:]) if scenario=='wrong-raw' else raw)
                state={'present':scenario not in ('missing','nonzero','timeout','head-change'),'written':False,'calls':0}
                def read(root,*args):
                    if args==('rev-parse','--is-shallow-repository'):return b'true\n' if scenario=='shallow' else b'false\n'
                    if args==('cat-file','-t',policy.UPSTREAM['commit']):return b'commit\n'
                    if args==('rev-parse',policy.UPSTREAM['commit']+'^{tree}'):
                        return (('f'*40 if scenario=='wrong-commit' else policy.UPSTREAM['tree'])+'\n').encode()
                    if args==('rev-parse','HEAD'):
                        return (('f'*40 if scenario=='head-change' and state['written'] else 'a'*40)+'\n').encode()
                    if args==('rev-parse','HEAD^{tree}'):return b'b'*40+b'\n'
                    if args==('status','--porcelain=v1','--untracked-files=all'):return b''
                    if args==('cat-file','-t',policy.UPSTREAM['tagObject']):
                        if not state['present']:raise subprocess.CalledProcessError(128,['fixed synthetic read'])
                        return b'blob\n' if scenario=='wrong-type' else b'tag\n'
                    if args==('cat-file','tag',policy.UPSTREAM['tagObject']):return raw
                    if args==('rev-parse',policy.UPSTREAM['tagObject']+'^{commit}'):
                        return (('e'*40 if scenario=='wrong-peel' else policy.UPSTREAM['commit'])+'\n').encode()
                    raise AssertionError('unexpected read '+repr(args))
                def writer(snapshot):
                    state['calls']+=1;self.assertEqual(snapshot.read_bytes(),raw)
                    state['written']=state['present']=True
                    return types.SimpleNamespace(returncode=1 if scenario=='nonzero' else 0,timed_out=scenario=='timeout')
                if scenario in ('present','missing'):
                    result=owner.ensure_official_tag(pipeline,source,read,writer)
                    self.assertEqual(result['status'],'present_exact' if scenario=='present' else 'materialized_exact')
                    self.assertIs(result['symbolicRefWritten'],False)
                    self.assertEqual(state['calls'],0 if scenario=='present' else 1)
                else:
                    with self.assertRaises(policy.Refusal):owner.ensure_official_tag(pipeline,source,read,writer)
                    self.assertLessEqual(state['calls'],1)
                    if scenario in ('wrong-raw','wrong-type','wrong-commit','wrong-peel','shallow'):self.assertEqual(state['calls'],0)

    def test_pipeline_intake_recovery_fresh_native_metadata_and_no_artifacts(self):
        proof=policy.parse((OWNERS/policy.PREPARATION_FAILURE_EVIDENCE.removeprefix('scripts/fork-release/')).read_bytes())
        current=policy.parse((OWNERS/'candidates/v2026.10.9-source-only/ci-bindings.json').read_bytes())
        b,q,raw=legacy_first_preparation_request(current,proof)
        self.assertEqual(policy.digest(raw),proof['requestSha256'])
        run={'id':int(proof['runId']),'head_sha':proof['pipelineHead'],'status':'completed','conclusion':'failure',
            'event':'pull_request','run_attempt':1,'head_branch':policy.PIPELINE_BRANCH,'path':policy.WORKFLOW,
            'name':policy.CAMPAIGN,'display_title':policy.CAMPAIGN,'repository':{'full_name':policy.REPOSITORY,'private':False},
            'actor':{'login':'fr-meyer'},'triggering_actor':{'login':'fr-meyer'}}
        native=job('lock-preparation',status='completed',jid=proof['jobId'])
        native.update(conclusion='failure',started_at=proof['nativeStartedAt'],completed_at=proof['nativeCompletedAt'])
        names=['Set up job','Start shared deadline before checkout','Checkout reviewed pipeline closure',proof['failedStep'],
            *proof['skippedCandidateSteps'],'Post Checkout reviewed pipeline closure','Complete job']
        native['steps']=[{'name':name,'status':'completed','conclusion':('failure' if name==proof['failedStep'] else
            'skipped' if name in proof['skippedCandidateSteps'] else 'success')} for name in names]
        original_digest=policy.digest
        def digest(value):
            if value==b'producer-workflow':return proof['producerWorkflowSha256']
            if value==b'producer-runtime':return proof['producerRuntimeSha256']
            return original_digest(value)
        for defect in (None,'candidate-ran','extra-step','artifacts','wrong-job','wrong-producer','wrong-source','prior-pass'):
            with self.subTest(defect=defect):
                table=deepcopy(native);r=deepcopy(run);request=deepcopy(q);arts=[]
                if defect=='candidate-ran':table['steps'][4]['conclusion']='success'
                if defect=='extra-step':table['steps'].append({'name':'not-approved','status':'completed','conclusion':'success'})
                if defect=='artifacts':arts=[{'id':1}]
                if defect=='wrong-job':table['id']+=1
                if defect=='wrong-source':request['source']['sourceSha']='f'*40
                if defect=='prior-pass':r['conclusion']='success'
                def content(api,path,sha,maximum=131072):
                    if defect=='wrong-producer':return b'wrong-producer'
                    return b'producer-workflow' if path==policy.WORKFLOW else b'producer-runtime'
                with patch.object(owner,'regular',return_value=policy.encode(proof)),\
                     patch.object(policy,'validate_pipeline_recovery_evidence',return_value=proof),\
                     patch.object(owner,'content',side_effect=content),patch.object(policy,'digest',side_effect=digest),\
                     patch.object(owner,'jobs_for',return_value=[table]),patch.object(owner,'artifacts_for',return_value=arts):
                    call=lambda:owner.pipeline_recovery_history(ROOT,b,[(proof['runId'],r,request,raw)],None)
                    if defect is None:
                        result=call();self.assertIs(result['sourceUnchanged'],True);self.assertIs(result['priorMinutesRemainCharged'],True)
                    else:
                        with self.assertRaises(policy.Refusal):call()

    def test_historical_request_reencoding_is_not_original_producer_bytes(self):
        proof=policy.parse((OWNERS/policy.PREPARATION_FAILURE_EVIDENCE.removeprefix('scripts/fork-release/')).read_bytes())
        current=policy.parse((OWNERS/'candidates/v2026.10.9-source-only/ci-bindings.json').read_bytes())
        before=deepcopy(current)
        _,request,raw=legacy_first_preparation_request(current,proof)
        reencoded=(json.dumps(request,sort_keys=True,indent=2)+'\n').encode()
        self.assertEqual(policy.parse(reencoded),request)
        self.assertNotEqual(reencoded,raw)
        path=OWNERS/'fixtures/v109-first-preparation-source-request.json'
        original_read=Path.read_bytes
        def read(candidate):
            return reencoded if candidate==path else original_read(candidate)
        with patch.object(Path,'read_bytes',new=read),self.assertRaisesRegex(AssertionError,'historical request bytes changed'):
            legacy_first_preparation_request(current,proof)
        self.assertEqual(current,before)

    def test_historical_request_keeps_semantic_and_proof_digest_bindings(self):
        proof=policy.parse((OWNERS/policy.PREPARATION_FAILURE_EVIDENCE.removeprefix('scripts/fork-release/')).read_bytes())
        current=policy.parse((OWNERS/'candidates/v2026.10.9-source-only/ci-bindings.json').read_bytes())
        changed=deepcopy(current);changed['baseline']['publicProofSha256']='0'*64
        with self.assertRaisesRegex(AssertionError,'historical request semantic binding changed'):
            legacy_first_preparation_request(changed,proof)
        changed_proof=deepcopy(proof);changed_proof['requestSha256']='0'*64
        with self.assertRaisesRegex(AssertionError,'historical request bytes changed'):
            legacy_first_preparation_request(current,changed_proof)

    def test_entire_historical_fixture_ignores_current_active_supplemental_variant(self):
        # This is an in-memory approval model only, never an operational file.
        path=OWNERS/'candidates/v2026.10.9-source-only/ci-bindings.json'
        current=policy.parse(path.read_bytes())
        before=deepcopy(current)
        # The historical supplemental model predates the later execution grant.
        # Never carry its current correction plan into a view with no correction.
        later_grant=deepcopy(current.pop("ciRunGrant",None))
        self.assertIsInstance(later_grant,dict)
        from test_third_preparation_contract_v109 import recovery_binding
        supplemental=recovery_binding(True)
        current["status"]="APPROVED_CI"
        current["validation"],current["correction"]=None,None
        current["preparationCorrection"]=deepcopy(supplemental["preparationCorrection"])
        current["preparationCorrection"]["source"]=deepcopy(current["preparation"])
        policy.validate_bindings(current)
        inconsistent=deepcopy(current);inconsistent["ciRunGrant"]=later_grant
        with self.assertRaisesRegex(policy.Refusal,"closed_fixture_correction_plan"):
            policy.validate_bindings(inconsistent)
        with self.assertRaises(policy.Refusal):policy.request_for(current,"lock-preparation",1)
        in_memory=policy.encode(current);original_read=Path.read_bytes
        def read(candidate):
            return in_memory if candidate==path else original_read(candidate)
        with patch.object(Path,"read_bytes",new=read):
            self.test_pipeline_intake_recovery_fresh_native_metadata_and_no_artifacts()
        self.assertEqual(policy.encode(current),in_memory)
        self.assertEqual(policy.parse(original_read(path)),before)
        self.assertEqual(current["preparationCorrection"]["schema"],policy.ADDITIONAL_PIPELINE_RECOVERY_SCHEMA)

    def test_metadata_overlay_preserves_both_sides_equal_add_delete(self):
        entry=lambda char:('100644','blob',char*40)
        base={'target-only':entry('a'),'head-only':entry('b'),'equal':entry('c'),'deleted':entry('d')}
        head={**base,'head-only':entry('e'),'equal':entry('f'),'new':entry('1')}
        target={k:v for k,v in base.items() if k!='deleted'}
        target.update({'target-only':entry('2'),'equal':entry('f')})
        before=deepcopy((base,head,target))
        expected={'target-only':entry('2'),'head-only':entry('e'),'equal':entry('f'),'new':entry('1')}
        self.assertEqual(owner.deterministic_merge_entries(base,head,target),expected)
        self.assertEqual((base,head,target),before)

    def test_metadata_overlay_refuses_content_divergence_and_path_collision(self):
        e=lambda char:('100644','blob',char*40)
        with self.assertRaisesRegex(policy.Refusal,'workflow_divergent_path'):
            owner.deterministic_merge_entries({'x':e('a')},{'x':e('b')},{'x':e('c')})
        with self.assertRaisesRegex(policy.Refusal,'workflow_path_collision'):
            owner.deterministic_merge_entries({'old':e('a')},{'old':e('a'),'x':e('b')},{'old':e('a'),'x/y':e('c')})

    def test_workflow_merge_fixed_target_graph_and_complete_tree(self):
        for defect in (None,'parents','merge-base','multi-base','target-tree','base-tree','shallow','partial','actual-tree','type'):
            with self.subTest(defect=defect):
                read,core,head,merge=fake_merge_graph(defect)
                if defect is None:
                    result=owner.workflow_merge_binding(read,core,head,merge)
                    self.assertEqual(result['target'],owner.WORKFLOW_TARGET)
                    self.assertTrue(result['completeTreeCompared']);self.assertFalse(result['gitObjectWritten'])
                else:
                    with self.assertRaises(policy.Refusal):owner.workflow_merge_binding(read,core,head,merge)

    def test_exact_merge_tree_drift_refuses_before_any_candidate_action(self):
        e,v=event_env();b=binding();r=policy.request_for(b,'lock-preparation')
        read,core,head,merge=fake_merge_graph('actual-tree')
        self.assertEqual(head,e['pull_request']['head']['sha']);self.assertEqual(merge,v['GITHUB_WORKFLOW_SHA'])
        import model_diagnostic_v109 as diagnostic
        pipeline=Path('/synthetic/pipeline')
        route_files={path:(ROOT/path).read_bytes() for path in
            (diagnostic.REQUEST_PATH,policy.WORKFLOW,diagnostic.WORKFLOW)}
        def regular(path,maximum=2*1024*1024):
            raw=route_files.get(path.relative_to(pipeline).as_posix(),b'fixed tracked bytes')
            self.assertLessEqual(len(raw),maximum)
            return raw
        def git(root,*args,**kwargs):
            if args==('rev-parse','HEAD'):return (head+'\n').encode()
            if args[:2]==('cat-file','-e'):return b''
            if args and args[0]=='show' and len(args)==2:
                return route_files.get(args[1].partition(':')[2],b'fixed tracked bytes')
            return read(*args)
        core.phase_process=unittest.mock.Mock()
        with patch.object(owner,'regular',side_effect=regular),patch.object(owner,'git_read',side_effect=git):
            with self.assertRaisesRegex(policy.Refusal,'workflow_full_merge_tree_changed'):
                owner.code_binding(pipeline,None,e,v,r,core,{'deadlineEpoch':time_future(),'gitEnv':{}})
        core.phase_process.assert_not_called()

    def test_invalid_route_refuses_before_merge_or_any_candidate_action(self):
        e,v=event_env();b=binding();r=policy.request_for(b,'lock-preparation')
        _,core,_,_=fake_merge_graph(None);core.phase_process=unittest.mock.Mock()
        with patch.object(owner,'regular',return_value=b'not JSON'),\
             patch.object(owner,'git_read') as git,patch.object(owner,'workflow_merge_binding') as merge:
            with self.assertRaisesRegex(policy.Refusal,'invalid_json'):
                owner.code_binding(Path('/synthetic/pipeline'),None,e,v,r,core,{'deadlineEpoch':time_future(),'gitEnv':{}})
        git.assert_not_called();merge.assert_not_called();core.phase_process.assert_not_called()

    def test_duplicate_incidental_display_names_not_native_identity(self):
        skipped=[]
        for ident in range(1,37):
            value=job('unexpanded (${{ matrix.platform }})',status='completed',jid=ident)
            value.update(conclusion='skipped',runner_id=None,runner_name=None,steps=[],started_at=None,completed_at=None)
            skipped.append(value)
        self.assertEqual(owner.observed_jobs(skipped,NOW,terminal=True)[0],0)
        with self.assertRaisesRegex(policy.Refusal,'unique_native_job'):
            owner.observed_jobs(skipped+[deepcopy(skipped[0])],NOW,terminal=True)
        source=[job('admission',jid=1),job('admission',jid=2)]
        with self.assertRaisesRegex(policy.Refusal,'unique_native_job'):
            owner.observed_jobs(source,NOW,limits=owner.SOURCE_JOBS)

    def test_only_incidental_standard_ubuntu_latest_addition(self):
        native=job('dispatch');native['labels']=['ubuntu-latest']
        self.assertEqual(owner.observed_jobs([native],NOW)[0],1)
        native['name']='admission'
        with self.assertRaisesRegex(policy.Refusal,'standard_free_public_runner'):
            owner.observed_jobs([native],NOW,limits=owner.SOURCE_JOBS)
        for labels,group in [(['ubuntu-latest','large'],'GitHub Actions'),(['self-hosted'],'GitHub Actions'),
                             (['ubuntu-latest'],'Custom'),(['ubuntu-22.04'],'GitHub Actions')]:
            bad=deepcopy(native);bad.update(labels=labels,runner_group_name=group)
            with self.subTest(labels=labels,group=group),self.assertRaises(policy.Refusal):owner.observed_jobs([bad],NOW)

    def test_git_metadata_ignores_replacements_and_forbids_transports(self):
        with patch.object(subprocess,'run',return_value=types.SimpleNamespace(stdout=b'fixed')) as run:
            self.assertEqual(owner.git_read(Path('/synthetic'),'show','a'*40),b'fixed')
        argv=run.call_args.args[0];env=run.call_args.kwargs['env']
        self.assertIn('protocol.allow=never',argv)
        self.assertIn('core.useReplaceRefs=false',argv)
        self.assertEqual(env['GIT_GRAFT_FILE'],'/dev/null')
        self.assertEqual(env['GIT_NO_REPLACE_OBJECTS'],'1')
        self.assertEqual(env['GIT_NO_LAZY_FETCH'],'1')
        self.assertEqual(env['GIT_CONFIG_GLOBAL'],'/dev/null')
        b=binding();r=policy.request_for(b,'lock-preparation');_,e=event_env();e['PATH']='synthetic'
        with patch('time.time',return_value=NOW):
            context=owner.prepare_context(Path('/synthetic'),r,b,e)
        self.assertEqual(context['gitEnv']['GIT_NO_REPLACE_OBJECTS'],'1')
        self.assertEqual(context['gitEnv']['GIT_CONFIG_KEY_0'],'protocol.allow')
        self.assertEqual(context['gitEnv']['GIT_CONFIG_VALUE_0'],'never')
        self.assertEqual(context['gitEnv']['GIT_GRAFT_FILE'],'/dev/null')
        self.assertEqual(context['gitEnv']['GIT_CONFIG_KEY_1'],'core.useReplaceRefs')
        self.assertEqual(context['gitEnv']['GIT_CONFIG_VALUE_1'],'false')

    def test_core_bootstrap_gets_new_identity_without_mutating_old_core_policy(self):
        class Core:
            def bootstrap_pnpm(self,*args,**kwargs):self.args,self.kwargs=args,kwargs;return 'synthetic-tool'
        c=Core();b=binding();r=policy.request_for(b,'lock-preparation')
        self.assertEqual(owner.internal_bootstrap(c,Path('/synthetic'),{},r,{'deadlineEpoch':time_future()}),'synthetic-tool')
        self.assertEqual(c.kwargs,{'operation_identity':owner.owned_identity(r)})

    def test_unsafe_command_not_in_cli_surface(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):owner.main(['build-image'],{})
            with self.assertRaises(SystemExit):owner.main(['internal-bootstrap'],{})

    def test_post_profile_refuses_staged_edits_and_head_or_tree_move(self):
        b=binding();r=policy.request_for(b,'lock-preparation')
        positive=[r['source']['sourceSha'].encode()+b'\n',r['source']['sourceTree'].encode()+b'\n',b'']
        for answers in (positive,[b'e'*40+b'\n'],[positive[0],b'f'*40+b'\n'],positive[:2]+[b'M  package.json\n']):
            with patch.object(owner,'git_read',side_effect=answers):
                if answers is positive:owner.post_profile_binding(Path('/synthetic'),r,time_future())
                else:
                    with self.assertRaisesRegex(policy.Refusal,'profile_changed_tracked_source'):
                        owner.post_profile_binding(Path('/synthetic'),r,time_future())

    def test_profile_install_gate_and_selection_order_without_process(self):
        class Core:
            def __init__(self,exit_at=None):self.calls=[];self.exit_at=exit_at
            def clean_env(self,home,env):return {'PATH':'SYNTHETIC'}
            def bootstrap_pnpm(self,*a,**k):self.calls.append('bootstrap')
            def resource_check(self,source):self.calls.append('resource')
            def phase_process(self,argv,*a):
                label='install' if 'install' in argv else 'patches';self.calls.append(label)
                return types.SimpleNamespace(returncode=1 if label==self.exit_at else 0,timed_out=False)
            def run_commands(self,planned,*a):self.calls.append('commands');return [0]
        b,_=fixture.populated();r=policy.request_for(b,'validation')
        for failed in (None,'install'):
            c=Core(failed);selector=types.SimpleNamespace(verify_mocked_units=lambda read:c.calls.append('mock-bindings'),
                commands=lambda *a:[['SYNTHETIC-ONLY']])
            with tempfile.TemporaryDirectory() as d,patch.object(owner,'static_source',return_value={}),\
                 patch.object(owner,'load_owner',return_value=selector),patch.object(owner,'git_read',return_value=b'one.test.ts\0'),\
                 patch.object(owner,'post_profile_binding'):
                invoke=lambda:owner.run_profile(Path('/synthetic/pipeline'),Path('/synthetic/source'),b,r,'dependency',
                    {'RUNNER_TEMP':str(Path(d).resolve())},c,{'deadlineEpoch':time_future()})
                if failed:
                    with self.assertRaises(policy.Refusal):invoke()
                    self.assertNotIn('commands',c.calls)
                    if failed=='install':self.assertNotIn('patches',c.calls)
                else:
                    invoke();self.assertEqual(c.calls,['bootstrap','resource','install','mock-bindings','commands'])

    def test_history_exact_once_and_current_admission_gate_fake_provider(self):
        b=binding();r=policy.request_for(b,'lock-preparation');raw=policy.encode(r)
        e,v=event_env();head='d'*40;rid=v['GITHUB_RUN_ID']
        run={'id':int(rid),'head_sha':head,'status':'in_progress','event':'pull_request','run_attempt':1,
            'head_branch':policy.PIPELINE_BRANCH,'path':policy.WORKFLOW,'name':policy.CAMPAIGN,
            'display_title':policy.CAMPAIGN,'created_at':'2026-11-01T00:04:00Z',
            'repository':{'full_name':policy.REPOSITORY,'private':False},
            'actor':{'login':'fr-meyer'},'triggering_actor':{'login':'fr-meyer'}}
        history={rid:run};native=job('lock-preparation')
        resolver=types.SimpleNamespace(resolve_baseline_258=lambda *a:{'runs':[]},WORKFLOW='historical-only')
        def fake_content(api,path,commit,maximum=0):return policy.encode(b) if path==owner.BINDINGS else raw
        with patch.object(owner,'history_rows',return_value=history),patch.object(owner,'closed_baseline',side_effect=lambda *a:(set(),set(),set())),\
             patch.object(owner,'regular',return_value=b'fixed'),patch.object(owner,'content',side_effect=fake_content),\
             patch.object(owner,'jobs_for',side_effect=lambda api,run:[native] if str(run['id'])==rid else
                 [{**native,'id':8,'status':'completed','conclusion':'failure','completed_at':'2026-11-01T00:05:00Z'}]),patch.object(owner,'artifacts_for',return_value=[]):
            facts=owner.history_checks(Path('/synthetic'),b,r,raw,head,e,v,None,resolver,NOW)
            self.assertEqual(facts['lockPreparations'],1);self.assertEqual(facts['currentBookingMinutes'],45)
            history['123456788']={**run,'id':123456788,'status':'completed','conclusion':'failure'}
            with self.assertRaisesRegex(policy.Refusal,'no_automatic_retry'):
                owner.history_checks(Path('/synthetic'),b,r,raw,head,e,v,None,resolver,NOW)
            del history['123456788'];native['name']='image-build'
            with self.assertRaisesRegex(policy.Refusal,'unexpected_source_job'):
                owner.history_checks(Path('/synthetic'),b,r,raw,head,e,v,None,resolver,NOW)

    def test_lock_phase_derives_exact_three_files_only_after_security_gate(self):
        import lockfile_policy_v109
        b=binding();r=policy.request_for(b,'lock-preparation');e,v=event_env()
        class Core:
            def clean_env(self,*a):return {'PATH':'SYNTHETIC'}
            def bootstrap_pnpm(self,*a,**k):pass
            def resource_check(self,*a):pass
            def phase_process(self,*a):
                (source/'pnpm-lock.yaml').write_bytes(b'generated synthetic lock')
                return types.SimpleNamespace(returncode=0,timed_out=False,cleanup_settled=None)
        with tempfile.TemporaryDirectory() as d:
            temp=Path(d).resolve();source=temp/'source';source.mkdir();pipeline=temp/'pipeline';pipeline.mkdir()
            (source/'pnpm-lock.yaml').write_bytes(b'original synthetic lock')
            candidate=pipeline/owner.CANDIDATE;candidate.mkdir(parents=True)
            (candidate/'registry-metadata.json').write_bytes(b'synthetic metadata')
            eventfile=temp/'event.json';eventfile.write_bytes(policy.encode(e));v.update(RUNNER_TEMP=str(temp),GITHUB_EVENT_PATH=str(eventfile))
            responses=[b'pnpm-lock.yaml\n',b'',b'closed synthetic diff']
            with patch.object(owner,'static_source',return_value={}),patch.object(policy,'recheck_registry_proof',return_value={'synthetic':True}),\
                 patch.object(owner,'git_read',side_effect=responses),patch.object(owner,'now_utc',return_value='2026-11-01T00:05:00Z'),\
                 patch.object(lockfile_policy_v109,'verify_lock_security',return_value={'synthetic':True}) as check:
                with contextlib.redirect_stdout(io.StringIO()):
                    owner.derive(pipeline,source,b,r,v,Core(),{'deadlineEpoch':time_future()})
                files=temp/'v109-lock-artifact';self.assertEqual(sorted(x.name for x in files.iterdir()),['generation.json','lock.diff','pnpm-lock.yaml'])
                receipt=policy.parse((files/'generation.json').read_bytes())
                self.assertEqual(receipt['changedPaths'],['pnpm-lock.yaml']);self.assertIs(receipt['imageBuilt'],False)
                self.assertEqual(check.call_args.args[:2],(b'original synthetic lock',b'generated synthetic lock'))
                for path in files.iterdir():self.assertEqual(path.stat().st_mode&0o777,0o600)

    def test_historical_artifact_expiry_is_monotonic_and_no_other_drift(self):
        frozen=[{'id':123,'name':'fixed','size_in_bytes':622,'expired':False,'digest':'sha256:'+'a'*64}]
        original=deepcopy(frozen)
        actual=deepcopy(frozen);actual[0]['expired']=True;actual[0]['url']='ignored-provider-extra'
        self.assertTrue(owner.historical_artifacts_match(actual,frozen));self.assertEqual(frozen,original)
        for key,value in [('id',124),('name','different'),('size_in_bytes',623),('digest','sha256:'+'b'*64),('expired',1)]:
            bad=deepcopy(actual);bad[0][key]=value
            with self.subTest(key=key):self.assertFalse(owner.historical_artifacts_match(bad,frozen))
        older=deepcopy(frozen);older[0]['expired']=True
        self.assertFalse(owner.historical_artifacts_match(frozen,older))
        self.assertFalse(owner.historical_artifacts_match([],frozen))
        self.assertFalse(owner.historical_artifacts_match(actual+actual,frozen))

    def test_actual_258_composition_with_explicit_synthetic_provider_envelopes(self):
        view=BASELINE_VIEW
        sys.path.insert(0,str(view/'scripts/fork-release'))
        sys.path.insert(0,str(BASELINE_OWNER))
        import composite_closed_usage_v109 as resolver
        raw=[(view/path).read_bytes() for path in owner.BASELINE_FILES]
        baseline=resolver.resolve_baseline_258(*raw)
        history={str(r['id']):{**{k:r[k] for k in resolver.HEADERS},
            'repository':{'full_name':policy.REPOSITORY,'private':False},
            'actor':{'login':'fr-meyer'},'triggering_actor':{'login':'fr-meyer'}} for r in baseline['runs']}
        rows={str(r['id']):r for r in baseline['runs']}
        witness=owner.policy.parse((view/owner.HISTORICAL_JOB_WITNESS).read_bytes())
        supplement={row['runId']:row['extraJobs'] for row in witness['runs']}
        note=owner.policy.parse((view/owner.HISTORICAL_ARTIFACT_NOTE).read_bytes())
        note_artifacts={}
        for item in note['artifacts']:note_artifacts.setdefault(str(item['workflow_run']['id']),[]).append(item)
        calls=[]
        def api(path):
            calls.append(path)
            match=__import__('re').search(r'/actions/runs/(\d+)/(jobs|artifacts)',path)
            rid,kind=match.groups();row=rows[rid]
            result=([synthetic_historical_provider_job(row,j) for j in row['jobs']]+deepcopy(supplement.get(rid,[])) if kind=='jobs' else deepcopy(row.get('artifactRows',[])+note_artifacts.get(rid,[])))
            # Native APIs include extra artifact metadata; the frozen projection
            # must compare exactly its own retained fields, not invent others.
            if kind=='artifacts':
                for a in result:a['url']='https://api.github.com/private-not-printed'
            return {'total_count':len(result),kind:result}
        with patch.object(owner,'regular',side_effect=lambda path,maximum=0:(view/Path(path).relative_to('/synthetic')).read_bytes()),patch.object(owner,'emit') as emitted:
            ids,jobs,arts=owner.closed_baseline(Path('/synthetic'),history,api,resolver)
            self.assertEqual(len(ids),258);self.assertEqual(len(jobs),1072);self.assertEqual(len(arts),23)
            self.assertEqual(emitted.call_args.args[0]['originalRunnerMinutes'],2944)
            self.assertEqual(len(emitted.call_args.args[0]['zeroAcquisitionJobFacts']),25)
            self.assertEqual(len(calls),516)
            self.assertEqual(resolver.resolve_baseline_258(*raw),baseline)  # no frozen record normalized
            history[next(iter(history))]['conclusion']='changed'
            with self.assertRaisesRegex(policy.Refusal,'closed_provider_header_changed'):
                owner.closed_baseline(Path('/synthetic'),history,api,resolver)

    def test_actual_workflow_clock_writes_newline_and_refuses_disarmed(self):
        import textwrap
        raw=workflow('lock-preparation').read_text()
        body=raw.split("          python3 - <<'PY'\n",1)[1].split("          PY\n",1)[0]
        code=textwrap.dedent(body)
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'env'
            env={'GITHUB_ENV':str(path),'V109_APPROVED_AT':'2026-11-01T00:00:00Z','V109_EXPIRES_AT':'2026-11-05T00:00:00Z'}
            with patch.dict(os.environ,env,clear=True),patch('time.time',return_value=NOW):
                exec(compile(code,'actual-workflow-clock','exec'),{})
            self.assertEqual(path.read_bytes(),('V109_JOB_STARTED_EPOCH='+str(NOW)+'\n').encode())
            path.unlink();env['V109_APPROVED_AT']='DISARMED'
            with patch.dict(os.environ,env,clear=True),self.assertRaises(SystemExit):
                exec(compile(code,'actual-workflow-clock','exec'),{})
            self.assertFalse(path.exists())

    def test_workflows_fixed_scoped_phase_bodies_and_no_image_trigger(self):
        prep=workflow('lock-preparation').read_text();full=workflow('source-validation').read_text()
        self.assertIn('  lock-preparation:\n',prep);self.assertNotIn('  admission:\n',prep)
        self.assertIn('timeout-minutes: 45',prep);self.assertIn('retention-days: 3',prep)
        self.assertIn('max-parallel: 3',full);self.assertEqual(full.count('          - profile:'),15)
        self.assertEqual(sum(policy.PROFILE_MINUTES.values())+30+10,1075)
        for s in (prep,full):
            self.assertIn('V109_APPROVED_AT: DISARMED',s)
            self.assertLess(s.index('Start shared deadline before checkout'),s.index('Checkout reviewed pipeline closure'))
            self.assertNotIn('workflow_dispatch',s);self.assertNotIn('workflow_run',s)
            self.assertNotIn('candidates/v2026.10.9-image-only',s);self.assertNotIn('secrets.',s);self.assertNotIn('docker',s.lower())
            self.assertNotIn('persist-credentials: true',s);self.assertNotIn('pull_request_target:',s)


def fake_merge_graph(defect=None):
    head,merge='d'*40,'e'*40
    blob=lambda c:('100644','blob',c*40)
    base={'inherited':blob('a'),'unchanged':blob('b')}
    target={**base,'inherited':blob('c')}
    h={**base,'new-controller':blob('d')}
    actual={**h,'inherited':blob('c')}
    if defect=='actual-tree':actual['unexpected']=blob('f')
    trees={owner.WORKFLOW_MERGE_BASE:base,owner.WORKFLOW_TARGET:target,head:h,merge:actual}
    treeids={owner.WORKFLOW_TARGET:owner.WORKFLOW_TARGET_TREE,
        owner.WORKFLOW_MERGE_BASE:owner.WORKFLOW_MERGE_BASE_TREE,head:'1'*40,merge:'2'*40}
    def read(*args):
        if args==('rev-parse','--is-shallow-repository'):return b'true\n' if defect=='shallow' else b'false\n'
        if args[:2]==('config','--get-regexp'):
            if defect=='partial':return b'remote.origin.promisor true\n'
            raise subprocess.CalledProcessError(1,['fixed local metadata read'])
        if args[:2]==('cat-file','-t'):return b'blob\n' if defect=='type' else b'commit\n'
        if args==('show','-s','--format=%P',merge):
            first=policy.BASE if defect=='parents' else owner.WORKFLOW_TARGET
            return (first+' '+head+'\n').encode()
        if args==('merge-base','--all',owner.WORKFLOW_TARGET,head):
            if defect=='merge-base':return b'f'*40+b'\n'
            if defect=='multi-base':return (owner.WORKFLOW_MERGE_BASE+'\n'+'f'*40+'\n').encode()
            return (owner.WORKFLOW_MERGE_BASE+'\n').encode()
        if args[0]=='rev-parse' and args[1].endswith('^{tree}'):
            commit=args[1][:-7]
            value=treeids[commit]
            if defect=='target-tree' and commit==owner.WORKFLOW_TARGET:value='f'*40
            if defect=='base-tree' and commit==owner.WORKFLOW_MERGE_BASE:value='f'*40
            return (value+'\n').encode()
        raise AssertionError('unexpected metadata read '+repr(args))
    def tree(read,commit,expected):
        if treeids[commit]!=expected:raise AssertionError('tree identity mismatch')
        return deepcopy(trees[commit])
    return read,types.SimpleNamespace(_v4_tree=tree),head,merge


def time_future():
    import time
    return time.time()+60


if __name__=='__main__':unittest.main()
