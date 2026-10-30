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

    def test_exact_merge_tree_drift_refuses_before_any_candidate_action(self):
        e,v=event_env();head=e['pull_request']['head']['sha'];merge=v['GITHUB_WORKFLOW_SHA']
        b=binding();r=policy.request_for(b,'lock-preparation')
        def read(root,*args,**kwargs):
            if args==('rev-parse','HEAD'):return (head+'\n').encode()
            if args==('show','-s','--format=%P',merge):return (policy.BASE+' '+head+'\n').encode()
            if args==('rev-parse',merge+'^{tree}'):return b'2'*40+b'\n'
            if args==('rev-parse',head+'^{tree}'):return b'1'*40+b'\n'
            if args[:2]==('cat-file','-e'):return b''
            if args and args[0]=='show':return b'fixed tracked bytes'
            raise AssertionError('unexpected Git read '+repr(args))
        core=types.SimpleNamespace(phase_process=unittest.mock.Mock())
        with patch.object(owner,'regular',return_value=b'fixed tracked bytes'),patch.object(owner,'git_read',side_effect=read):
            with self.assertRaisesRegex(policy.Refusal,'workflow_full_tree_changed'):
                owner.code_binding(Path('/synthetic/pipeline'),None,e,v,r,core,{'deadlineEpoch':time_future(),'gitEnv':{}})
        core.phase_process.assert_not_called()

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

    def test_actual_258_composition_fresh_provider_fake_and_tamper(self):
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
        calls=[]
        def api(path):
            calls.append(path)
            match=__import__('re').search(r'/actions/runs/(\d+)/(jobs|artifacts)',path)
            rid,kind=match.groups();row=rows[rid]
            result=deepcopy(row['jobs'] if kind=='jobs' else row.get('artifactRows',[]))
            # Native APIs include extra artifact metadata; the frozen projection
            # must compare exactly its own retained fields, not invent others.
            if kind=='artifacts':
                for a in result:a['url']='https://api.github.com/private-not-printed'
            return {'total_count':len(result),kind:result}
        with patch.object(owner,'regular',side_effect=lambda path,maximum=0:(view/Path(path).relative_to('/synthetic')).read_bytes()):
            ids,jobs,arts=owner.closed_baseline(Path('/synthetic'),history,api,resolver)
            self.assertEqual(len(ids),258);self.assertGreater(len(jobs),258)
            self.assertEqual(len(calls),516)
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


def time_future():
    import time
    return time.time()+60


if __name__=='__main__':unittest.main()
