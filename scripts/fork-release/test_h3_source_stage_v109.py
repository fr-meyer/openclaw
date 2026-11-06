"""Synthetic H3 authority/source boundaries; no host or package execution."""
from copy import deepcopy
from pathlib import Path
import json, socket, subprocess, unittest, urllib.request
from unittest.mock import patch
import source_validation_contract_v109 as p
import bounded_run_contract_v109 as a
import source_validation_selection_v109 as selection

HERE = Path(__file__).resolve().parent

def historical_h3_workflow(name):
    import hashlib
    pins = {
        "v109-h3-lock-preparation.yml": "c0aa0fcb733e51fcbf46a2a723d20334bd8fc32760179504ecbb46493360d428",
        "v109-h3-source-validation.yml": "4bd74d0c2ac2a94d7c2d0c96f86cc6bd068179ad78c04581f3d6581d2be4c878",
    }
    raw = (HERE / "fixtures" / name.replace(".yml", "-before-combined.yml")).read_bytes()
    if hashlib.sha256(raw).hexdigest() != pins[name]:
        raise AssertionError("historical H3 workflow pin")
    return raw


def fixture():
    b = p.parse((HERE/'fixtures/v109-h3-anchor-bindings.json').read_bytes())
    prefix = p.parse((HERE/'candidates/v2026.10.9-source-only/h3-stage-prefix.json').read_bytes())
    old = deepcopy(p.H3_ANCHOR); prep = deepcopy(old)
    prep.update(sourceSha='a'*40, sourceTree='b'*40, manifestSha256='c'*64, inventorySha256='d'*64)
    prep['fileSha256']['package.json']='e'*64; prep['fileSha256'][p.LEDGER]='f'*64
    family = {'schema':p.H3_FAMILY_SCHEMA,'publicAmendmentSha256':a.H3_AMENDMENT_SHA256,'anchor':old,
        'generations':[{'number':1,'parentSource':deepcopy(old),'preparation':prep,
            'changedPaths':sorted(('package.json',p.LEDGER)),
            'contentSha256':{'package.json':'e'*64,p.LEDGER:'f'*64},'unchangedTreeSha256':'1'*64,'validation':None}]}
    b.update(status='DISARMED', preparation=prep, validation=None, preparationCorrection=None,correction=None,
        sourceSuccessor=family,newRecoveryTests=sorted(set(selection.REQUIRED_SOURCE_TESTS)|set(selection.H3_COMPAT_EXTRA)))
    g=b['ciRunGrant'];g.update(status='DISARMED',expiresAt=a.H3_EXPIRES_AT,maximumNewRunnerMinutes=25000,moneyCeilingUSD='25.00')
    from test_budget_ceiling_amendment_v109 import amendment
    g['budgetCeilingAmendment']=amendment()
    g['bookedAdditionalAttempts']=[{'runId':r['runId'],'nativeAttempt':1,'runnerMinutes':r['runnerMinutes']} for r in prefix['records'] if r['runId'] not in a.PREFIX_RUN_IDS]
    sha=p.digest(p.canonical(family))
    g['sourceSuccessorAmendment']={**a.h3_stage_descriptor(),'sourceFamilySha256':sha,'sourceGeneration':1,'bookedArtifacts':deepcopy(prefix['artifacts'])}
    g['nextExecution'].update(status='DISARMED',sequence=12,phase='lock-preparation',preparationAttempt=7,
        source=prep,priorSourceRun={'runId':'41154711378','pipelineHead':'9922a9505b772c407406b0275bbf74d6d2a31c54','requestSha256':'0'*64},
        reasonCode='approved_source_successor',reviewSha256=None,requestSha256=None,sourceGeneration=1,
        sourceFamilySha256=sha,reservations={'current':45,'pendingValidation':1075,'conditionalImage':180,'incidental':160})
    return b

class H3SourceStageTests(unittest.TestCase):
    def setUp(self):
        for obj,name in ((subprocess,'Popen'),(socket,'socket'),(urllib.request,'urlopen'),(urllib.request,'build_opener')):
            guard=patch.object(obj,name,side_effect=AssertionError('real host/network action forbidden'));guard.start();self.addCleanup(guard.stop)
    def test_real_maintained_disarmed_constructor(self):
        b=fixture();q=p.request_for(b,'lock-preparation',7)
        self.assertIs(p.validate_request(q,b),q)
        self.assertEqual(p.h3_stage_contract(b,q),a.h3_stage_descriptor())
        self.assertEqual(p.budget(q)['maximumNewMinutes'],25000)
        self.assertEqual(p.budget(q)['phaseMaximumMinutes'],45)
        self.assertEqual(q['sourceGeneration'],1)
    def test_old_authority_bytes_unchanged(self):
        b=fixture();self.assertEqual(p.digest(p.canonical(b['authorization'])),p.ORIGINAL_AUTHORIZATION_SHA256)
        self.assertEqual(p.source_authorization_window(b),(b['authorization']['approvedAt'],a.H3_EXPIRES_AT))
    def test_disarmed_cannot_activate(self):
        b=fixture();q=p.request_for(b,'lock-preparation',7)
        with self.assertRaises(ValueError):p.validate_request(q,b,True,p.utc(a.H3_NOT_BEFORE).timestamp())
    def test_effective_clock_floor_and_end(self):
        b=fixture();g=b['ciRunGrant'];g['status']='APPROVED';b['status']='APPROVED_CI';g['nextExecution'].update(status='REVIEWED',reviewSha256='9'*64,requestSha256='8'*64)
        self.assertIs(a.validate_grant(g,b['authorization'],True,p.utc(a.H3_NOT_BEFORE).timestamp()),g)
        for stamp in ('2026-11-04T09:59:49Z',a.H3_EXPIRES_AT):
            with self.subTest(stamp=stamp),self.assertRaises(ValueError):a.validate_grant(g,b['authorization'],True,p.utc(stamp).timestamp())
    def test_wrong_or_missing_authority_is_not_source_permission(self):
        for key in a.H3_DESCRIPTOR_FIELDS:
            b=fixture();del b['ciRunGrant']['sourceSuccessorAmendment'][key]
            with self.subTest(key=key),self.assertRaises(ValueError):p.validate_bindings(b)
    def test_stale_h2_cannot_be_new_h3(self):
        b=fixture();b['sourceSuccessor']['generations'][0]['preparation']=deepcopy(p.H3_ANCHOR)
        with self.assertRaises(ValueError):p.validate_bindings(b)
    def test_wrong_generation_and_unrelated_changes_refuse(self):
        for key,value in (('number',2),('changedPaths',['Dockerfile',p.LEDGER]),('parentSource',fixture()['preparation'])):
            b=fixture();b['sourceSuccessor']['generations'][0][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):p.validate_bindings(b)
    def test_three_material_generations_is_closed(self):
        family=fixture()['sourceSuccessor']
        for number in (2,3):
            old=deepcopy(family['generations'][-1]['preparation']);new=deepcopy(old);new['sourceSha']=str(number)*40;new['sourceTree']=str(number+2)*40
            family['generations'].append({**deepcopy(family['generations'][0]),'number':number,'parentSource':old,'preparation':new})
        self.assertIs(p.validate_h3_family(family),family)
        family['generations'].append(deepcopy(family['generations'][-1]))
        with self.assertRaises(ValueError):p.validate_h3_family(family)
    def test_pending_material_successor_preserves_real_seed_without_invented_h(self):
        import source_reconciliation_v109 as r
        old = {'schema':r.SCHEMA,'lockState':'ci_derived','sourcePaths':[
            {'path':'package.json','result':{'mode':'100644','blob':'1'*40},'disposition':'MERGED_SOURCE_REVIEWED'},
            {'path':r.LOCK_PATH,'result':{'mode':'100644','blob':'2'*40},'disposition':'LOCK_CONTROLLED_DERIVATION'}],
            'lockDerivation':{'runId':41043479025,'attempt':1,'artifactSha256':'3'*64,'generatedLockSha256':'4'*64,'receiptSha256':'5'*64}}
        first=r.pending_successor_ledger(p.encode(old),{'package.json':{'mode':'100644','blob':'6'*40}},
            r.SUCCESSOR_ANCHOR['commit'],r.SUCCESSOR_ANCHOR['tree'],1,a.H3_AMENDMENT_SHA256,need=p.need)
        second=r.pending_successor_ledger(first,{'package.json':{'mode':'100644','blob':'7'*40}},
            'a'*40,'b'*40,2,a.H3_AMENDMENT_SHA256,need=p.need)
        one,two=p.parse(first),p.parse(second)
        self.assertEqual(two['sourceSuccessor']['generation'],2)
        self.assertEqual(two['sourceSuccessor']['parentSource'],'a'*40)
        for key in ('seedSource','seedTree','seedLockBlob','seedLockSha256','seedLockDerivation'):
            self.assertEqual(two['sourceSuccessor'][key],one['sourceSuccessor'][key])
        self.assertNotIn('lockDerivation',two);self.assertEqual(two['lockState'],'pending_ci_derivation')
        self.assertEqual(two['sourcePaths'][1]['result'],one['sourcePaths'][1]['result'])
        # This tests source-fact construction, not an observed G2 or fresh H.

    def test_failed_precheck_count_is_not_material_generation(self):
        b=fixture();b['ciRunGrant']['nextExecution'].update(sequence=19,preparationAttempt=14,reasonCode='reviewed_pipeline_correction')
        self.assertEqual(p.request_for(b,'lock-preparation',14)['sourceGeneration'],1)
    def test_family_hash_and_current_mirror_cannot_drift(self):
        for target in ('sourceFamilySha256','sourceGeneration'):
            b=fixture();b['ciRunGrant']['sourceSuccessorAmendment'][target]=('0'*64 if target=='sourceFamilySha256' else 2)
            with self.subTest(target=target),self.assertRaises(ValueError):p.validate_bindings(b)
    def test_prefix_bookings_cannot_be_discarded(self):
        b=fixture();b['ciRunGrant']['bookedAdditionalAttempts']=[]
        with self.assertRaises(ValueError):p.validate_bindings(b)
    def test_positive_native_pool_accounting_reserves_whole_stage(self):
        b=fixture();g=b['ciRunGrant'];facts=dict(preparationObservedMinutes=0,sourceObservedMinutes=0,incidentalObservedMinutes=0,imageObservedMinutes=0,remainingImageFamilyReserveMinutes=180,remainingIncidentalReserveMinutes=160)
        got=a.validate_h3_budget(g,g['nextExecution'],2215,0,facts);self.assertEqual(got['totalBookedMinutes'],5915)
        facts['preparationObservedMinutes']=10
        got=a.validate_h3_budget(g,g['nextExecution'],2225,10,facts);self.assertEqual(got['totalBookedMinutes'],5915)
    def test_pool_overspend_missing_and_unknown_facts_refuse(self):
        b=fixture();g=b['ciRunGrant'];facts=dict(preparationObservedMinutes=0,sourceObservedMinutes=0,incidentalObservedMinutes=0,imageObservedMinutes=0,remainingImageFamilyReserveMinutes=180,remainingIncidentalReserveMinutes=160)
        for bad in ({k:v for k,v in facts.items() if k!='sourceObservedMinutes'},{**facts,'preparationObservedMinutes':136},{**facts,'sourceObservedMinutes':True},{**facts,'remainingImageFamilyReserveMinutes':0}):
            with self.subTest(bad=bad),self.assertRaises(ValueError):a.validate_h3_budget(g,g['nextExecution'],2500,0,bad)
    def test_booked_prefix_increase_is_not_refunded(self):
        b=fixture();g=b['ciRunGrant'];facts=dict(preparationObservedMinutes=0,sourceObservedMinutes=0,incidentalObservedMinutes=0,imageObservedMinutes=0,remainingImageFamilyReserveMinutes=180,remainingIncidentalReserveMinutes=160)
        with self.assertRaises(ValueError):a.validate_h3_budget(g,g['nextExecution'],2216,0,facts)
    def test_h3_existing_minimatch_boundary_tests_selected_once(self):
        legacy=set(selection.COMPAT_EXTRA)|set(selection.legacy.V6_RUNTIME_COMPATIBILITY_TESTS)
        known=legacy|set(selection.H3_COMPAT_EXTRA)
        picked=selection.selected_tests(known,'compatibility',True)
        self.assertTrue(set(selection.H3_COMPAT_EXTRA)<=set(picked));self.assertEqual(len(picked),len(set(picked)))
        self.assertEqual(set(selection.selected_tests(known,'compatibility')),legacy)
    def test_effective_h3_job_deadline_does_not_use_expired_legacy_end(self):
        import source_validation_v109 as runtime
        b=fixture();b['status']='APPROVED_CI';g=b['ciRunGrant'];g['status']='APPROVED';g['nextExecution'].update(status='REVIEWED',reviewSha256='9'*64,requestSha256='8'*64)
        q=p.request_for(b,'lock-preparation',7);g['nextExecution']['requestSha256']=p.digest(p.encode(q))
        now=int(p.utc(a.H3_NOT_BEFORE).timestamp())
        got=runtime.job_deadline(b,q,{runtime.CLOCK:str(now)},clock=now)
        self.assertEqual(got,now+45*60-60)
        with self.assertRaises(ValueError):runtime.job_deadline(b,q,{runtime.CLOCK:str(now-1)},clock=now-1)
    def test_h3_fixed_workflow_routing_reuses_closed_source_contract(self):
        import model_diagnostic_v109 as route
        from types import SimpleNamespace
        b=fixture();q=p.request_for(b,'lock-preparation',7)
        request=(HERE/'candidates/v2026.10.9-model-diagnostic/request.json').read_bytes()
        prep=(HERE/'fixtures/v109-h3-lock-preparation.yml').read_bytes()
        diag=(HERE.parents[1]/route.WORKFLOW).read_bytes()
        values={route.REQUEST_PATH:request,p.WORKFLOW:prep,route.WORKFLOW:diag}
        runtime=SimpleNamespace(regular=lambda path,cap:values[str(path)])
        route.workflow_routing(runtime,Path('.'),False,source_request=q,source_bindings=b)
        for bad in (prep+b' ',prep.replace(b'timeout-minutes: 45',b'timeout-minutes: 46')):
            values[p.WORKFLOW]=bad
            with self.assertRaises(ValueError):route.workflow_routing(runtime,Path('.'),False,source_request=q,source_bindings=b)
        values[p.WORKFLOW]=prep
        with self.assertRaises(ValueError):route.workflow_routing(runtime,Path('.'),True,source_request=q,source_bindings=b)
        bad=deepcopy(q);bad['sourceFamilySha256']='0'*64
        with self.assertRaises(ValueError):route.workflow_routing(runtime,Path('.'),False,source_request=bad,source_bindings=b)
    def test_actual_h3_inline_clock_blocks_accept_bound_floor_and_reject_drift(self):
        import re,os,time,textwrap,io
        from unittest.mock import mock_open
        blocks=[]
        for name in ('v109-h3-lock-preparation.yml','v109-h3-source-validation.yml'):
            text=historical_h3_workflow(name).decode('utf8')
            blocks.extend(textwrap.dedent(body) for body in re.findall(r"python3 - <<'PY'\n(.*?)          PY",text,re.S) if 'def utc(v):' in body)
        self.assertEqual(len(blocks),4)
        floor=p.utc(a.H3_NOT_BEFORE).timestamp()
        env={'V109_APPROVED_AT':'2026-10-30T03:14:21Z','V109_EXPIRES_AT':a.H3_EXPIRES_AT,'GITHUB_ENV':'/synthetic/never-open'}
        for block in blocks:
            writer=mock_open()
            with patch.dict(os.environ,env,clear=True),patch.object(time,'time',return_value=floor),patch('builtins.open',writer):
                exec(compile(block,'<reviewed-h3-clock>','exec'),{})
            writer.assert_called_once_with('/synthetic/never-open','a')
            for altered,now in [({**env,'V109_EXPIRES_AT':'2026-11-07T03:14:21Z'},floor),({**env,'V109_APPROVED_AT':'2026-10-31T03:14:21Z'},floor),(env,floor-1),(env,p.utc(a.H3_EXPIRES_AT).timestamp())]:
                writer=mock_open()
                with patch.dict(os.environ,altered,clear=True),patch.object(time,'time',return_value=now),patch('builtins.open',writer),self.assertRaises(SystemExit):
                    exec(compile(block,'<reviewed-h3-clock>','exec'),{})
                writer.assert_not_called()

    def test_h3_workflow_caps_and_finite_helper_pins(self):
        import re,hashlib,model_diagnostic_v109 as route
        helper=(HERE/'finite_public_root_bootstrap_v109.py').read_bytes();sha=hashlib.sha256(helper).hexdigest()
        prep=(HERE/'fixtures/v109-h3-lock-preparation.yml').read_bytes();full=(HERE/'fixtures/v109-h3-source-validation.yml').read_bytes()
        self.assertEqual(hashlib.sha256(prep).hexdigest(),route.H3_PREPARATION_WORKFLOW_SHA256)
        self.assertEqual(hashlib.sha256(full).hexdigest(),route.H3_SOURCE_WORKFLOW_SHA256)
        self.assertEqual(prep.count(sha.encode()),1);self.assertEqual(full.count(sha.encode()),3)
        self.assertNotIn(b'fetch-depth: 0',prep);self.assertNotIn(b'fetch-depth: 0',full)
        caps=dict((name,int(value)) for name,value in re.findall(r'profile: ([a-z0-9-]+)\n\s+minutes: ([0-9]+)',full.decode()))
        self.assertEqual(caps,p.PROFILE_MINUTES);self.assertIn(b'max-parallel: 3',full)
        self.assertIn(b"V109_EXPIRES_AT: '2026-11-07T03:14:21Z'",prep)
        self.assertIn(b"V109_EXPIRES_AT: '2026-11-06T03:14:21Z'",historical_h3_workflow('v109-h3-lock-preparation.yml'))
        self.assertIn(b'timeout-minutes: 45',prep)

    def test_legacy_anchor_remains_legacy(self):
        b=p.parse((HERE/'fixtures/v109-h3-anchor-bindings.json').read_bytes());q=p.parse((HERE/'fixtures/v109-h3-anchor-request.json').read_bytes())
        self.assertIs(p.validate_request(q,b),q);self.assertIsNone(p.h3_stage_contract(b,q))

if __name__=='__main__':unittest.main()
