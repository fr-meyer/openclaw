"""Synthetic continuation-boundary checks; no package, network or CI execution."""
from copy import deepcopy
import unittest

import bounded_run_contract_v109 as run
import source_validation_contract_v109 as policy
import npm_vendor_derivation_v109 as vendor


def artifact(i):
    present = {k: k in ('id', 'name', 'size_in_bytes', 'expired') for k in run.H3_ARTIFACT_FIELDS}
    return {'producerRunId': str(100+i), 'producerHead': 'a'*40, 'nativeResponseSha256': 'b'*64,
        'metadata': {'id': i+1, 'name': 'synthetic', 'size_in_bytes': 1, 'expired': False},
        'fieldPresence': present, 'workflowRunFieldPresence': {k:False for k in run.H3_ARTIFACT_CONTEXT_FIELDS}}


def grant(continuation=False, generation=None):
    number = generation if generation is not None else (4 if continuation else 3)
    amendment = {**run.h3_stage_descriptor(continuation=continuation), 'sourceFamilySha256':'a'*64,
        'sourceGeneration':number, 'bookedArtifacts':[artifact(i) for i in range(26)]}
    if continuation: amendment['vendorRepairContinuation'] = run.vendor_repair_continuation()
    plan = {'schema':run.PLAN_SCHEMA, 'status':'DISARMED', 'sequence':17, 'phase':'lock-preparation',
        'preparationAttempt':11, 'source':{'sourceSha':'c'*40},
        'priorSourceRun':{'runId':'41959737740','pipelineHead':'c4dc691ccdd3764eb1d70997fbe483bb11517c3c','requestSha256':'d'*64},
        'reasonCode':'approved_source_successor','reviewSha256':None,'requestSha256':None,
        'reservations':{'current':45,'pendingValidation':1075,'conditionalImage':180,'incidental':160},
        'sourceGeneration':number,'sourceFamilySha256':'a'*64}
    return {'sourceSuccessorAmendment':amendment, 'nextExecution':plan,
        'authoritySha256':run.AUTHORITY_SHA256, 'originalAuthorizationSha256':run.ORIGINAL_AUTHORIZATION_SHA256,
        'expiresAt':run.H3_EXPIRES_AT, 'moneyCeilingUSD':'25.00','maximumNewRunnerMinutes':25000,
        'maximumAdditionalAttempts':1000,'maximumStageAttempts':1042,'maximumSourceParallelJobs':3,
        'diagnosticBytes':67108864, 'budgetCeilingAmendment':{
            'schema':run.BUDGET_AMENDMENT_SCHEMA, 'scope':'minute-and-spending-ceilings-only',
            'publicAmendmentSha256':run.BUDGET_AMENDMENT_SHA256,'minuteAmendmentSha256':run.MINUTE_AMENDMENT_SHA256,
            'spendingAmendmentSha256':run.SPENDING_AMENDMENT_SHA256,'isTotalNotAdditional':True}}


def components(preparation=180, source=429, incidental=71):
    return {'preparationObservedMinutes':preparation,'sourceObservedMinutes':source,
        'incidentalObservedMinutes':incidental,'imageObservedMinutes':0,
        'remainingImageFamilyReserveMinutes':180,'remainingIncidentalReserveMinutes':160-incidental}


class VendorContinuationTests(unittest.TestCase):
    def test_legacy_descriptor_remains_three(self):
        self.assertEqual(run.h3_stage_descriptor()['maximumSourceGenerations'],3)
        g=grant(); run.source_successor_amendment(g)
        self.assertEqual(run.h3_stage_pools(g),{'source':3225,'preparation':135,'incidental':160,'image':180})

    def test_g4_and_g5_require_exact_continuation(self):
        for number in (4,5):
            with self.subTest(number=number):
                g=grant(True,number); self.assertEqual(run.source_successor_amendment(g)['sourceGeneration'],number)
                del g['sourceSuccessorAmendment']['vendorRepairContinuation']
                with self.assertRaises(run.Refusal): run.source_successor_amendment(g)

    def test_generation_six_refused(self):
        with self.assertRaises(run.Refusal): run.source_successor_amendment(grant(True,6))

    def test_legacy_descriptor_cannot_carry_generation_four(self):
        with self.assertRaises(run.Refusal): run.source_successor_amendment(grant(False,4))

    def test_continuation_cannot_restart_old_material_generation(self):
        with self.assertRaises(run.Refusal):run.source_successor_amendment(grant(True,3))

    def test_material_family_requires_explicit_new_ceiling(self):
        family={'schema':policy.H3_FAMILY_SCHEMA,'publicAmendmentSha256':run.H3_AMENDMENT_SHA256,
            'anchor':deepcopy(policy.H3_ANCHOR),'generations':[]}
        parent=deepcopy(policy.H3_ANCHOR)
        for number in range(1,6):
            prep=deepcopy(parent);prep['sourceSha']=format(number,'040x');prep['sourceTree']=format(number+10,'040x')
            family['generations'].append({'number':number,'parentSource':deepcopy(parent),'preparation':prep,
                'changedPaths':sorted((policy.LEDGER,'test/v108-remediation-security.test.mjs')),
                'contentSha256':{policy.LEDGER:'a'*64,'test/v108-remediation-security.test.mjs':'b'*64},
                'unchangedTreeSha256':'c'*64,'validation':None})
            parent=prep
        with self.assertRaises(policy.Refusal):policy.validate_h3_family(family)
        self.assertEqual(len(policy.validate_h3_family(family,5)['generations']),5)
        family['generations'].append(deepcopy(family['generations'][-1]))
        with self.assertRaises(policy.Refusal):policy.validate_h3_family(family,5)

    def test_projection_exact_money_minutes_counts_and_history(self):
        p=run.vendor_repair_continuation()
        self.assertEqual(p['maximumAdditionalRunnerMinutes'],2290)
        self.assertEqual(p['vendorAggregateMaximumMinutes'],2360)
        self.assertEqual(p['vendorComponentMaximumMinutes'],{'preparation':180,'source':2150,'incidental':80})
        self.assertEqual(sum(p['stagePools'].values()),3700)
        for key in p:
            q=deepcopy(p); q[key]=None
            with self.subTest(key=key),self.assertRaises((run.Refusal,TypeError,ValueError)):
                run.validate_vendor_repair_continuation(q)

    def test_nested_limits_and_unknown_fields_refused(self):
        for key in ('preparation','source','incidental'):
            p=run.vendor_repair_continuation();p['vendorComponentMaximumMinutes'][key]+=1
            with self.assertRaises(run.Refusal):run.validate_vendor_repair_continuation(p)
        p=run.vendor_repair_continuation();p['newAccess']=True
        with self.assertRaises(run.Refusal):run.validate_vendor_repair_continuation(p)
        p=run.vendor_repair_continuation();p['conditionalSecondRevisionEvidenceRequired']=1
        with self.assertRaises(run.Refusal):run.validate_vendor_repair_continuation(p)

    def test_projection_returns_fresh_objects(self):
        p=run.vendor_repair_continuation();p['stagePools']['source']=1
        self.assertEqual(run.vendor_repair_continuation()['stagePools']['source'],3135)

    def test_rebalanced_budget_keeps_old_debits_and_3700_ceiling(self):
        g=grant(True); c=components(); charged=run.H3_PREFIX_MINUTES+180+429+71
        fact=run.validate_h3_budget(g,g['nextExecution'],charged,0,c)
        self.assertEqual(fact['newObservedOrBookedMinutes'],charged)
        self.assertEqual(fact['totalBookedMinutes'],5915)
        self.assertEqual(fact['maximumStageBookedMinutes'],5915)
        with self.assertRaises(run.Refusal):run.validate_h3_budget(grant(),grant()['nextExecution'],charged,0,c)

    def test_reduced_source_and_increased_prep_caps_both_enforced(self):
        g=grant(True)
        for c in (components(preparation=226),components(source=3136)):
            charged=run.H3_PREFIX_MINUTES+c['preparationObservedMinutes']+c['sourceObservedMinutes']+c['incidentalObservedMinutes']
            with self.assertRaises(run.Refusal):run.validate_h3_budget(g,g['nextExecution'],charged,0,c)

    def test_continuation_does_not_reset_existing_run_or_total_limits(self):
        g=grant(True);self.assertEqual(run.maximum_new_minutes(g),25000)
        self.assertEqual(g['maximumAdditionalAttempts'],1000)
        self.assertEqual(g['moneyCeilingUSD'],'25.00')
        self.assertEqual(g['diagnosticBytes'],67108864)

    def test_vendor_record_five_is_source_fact_not_execution_permission(self):
        x={'schema':vendor.SCHEMA,'sourceGeneration':5,**{k:'a'*64 for k in
            ('workspaceSha256','patchSha256','proofSha256','producerRuntimeSha256')}}
        vendor.validate_record(x,policy.need)
        x['sourceGeneration']=6
        with self.assertRaises(policy.Refusal):vendor.validate_record(x,policy.need)

    def test_request_generation_requires_bound_continuation_digest(self):
        r={'sourceSuccessorAmendmentSha256':run.H3_AMENDMENT_SHA256,
            'budgetCeilingAmendmentSha256':run.BUDGET_AMENDMENT_SHA256,'runAllowanceSha256':run.AUTHORITY_SHA256,
            'sourceGeneration':4,'sourceFamilySha256':'a'*64,'phase':'lock-preparation','executionSequence':17}
        with self.assertRaises(policy.Refusal):policy.maximum_new_minutes_for(r)
        r['vendorRepairContinuationSha256']=run.digest(run.vendor_repair_continuation())
        self.assertEqual(policy.maximum_new_minutes_for(r),25000)
        r['vendorRepairContinuationSha256']='b'*64
        with self.assertRaises(policy.Refusal):policy.maximum_new_minutes_for(r)


# Reuse the maintained real temporary-Git fixture; no candidate package runs.
import test_reviewed_material_additions_v109 as material_fixture


class ContinuationMaterialAdditionTests(unittest.TestCase):
    git = material_fixture.ReviewedMaterialAdditionTests.git
    write = material_fixture.ReviewedMaterialAdditionTests.write
    finish = material_fixture.ReviewedMaterialAdditionTests.finish

    def setUp(self):
        material_fixture.ReviewedMaterialAdditionTests.setUp(self)
        self.write('scripts/test-npm-vendor-package.mjs',b'// existing synthetic fixture\n')
        self.git('add','--','scripts/test-npm-vendor-package.mjs')
        self.git('commit','--no-gpg-sign','--quiet','-m','synthetic existing G3 payload')
        self.before_commit=self.git('rev-parse','HEAD').decode().strip()
        tree=self.git('rev-parse','HEAD^{tree}').decode().strip()
        self.before=material_fixture.core._v4_tree(self.git,self.before_commit,tree)

    def payload(self,extra=None):
        for path in policy.H3_VENDOR_CONTINUATION_PATHS:
            self.write(path,b'# synthetic Python payload\n' if path.endswith('.py') else b'// synthetic JavaScript payload\n')
        self.write('scripts/test-npm-vendor-package.mjs',b'// corrected synthetic pack fixture\n')
        self.write(policy.LEDGER,b'{"fixture":"G4-pending"}\n')
        declared=set(policy.H3_VENDOR_CONTINUATION_PATHS)|{'scripts/test-npm-vendor-package.mjs',policy.LEDGER}
        if extra is not None:self.write(extra,b'// unapproved synthetic payload\n');declared.add(extra)
        after,step=self.finish(declared);step['number']=4
        return after,step

    def verify(self,after,step,continuation=True):
        return policy._verify_reviewed_step(self.git,self.before,after,step,
            allowed_additions=set(step['changedPaths']) & policy.h3_material_paths(5),
            **({'vendor_continuation':run.vendor_repair_continuation()} if continuation else {}))

    def test_actual_four_payload_pattern_passes_exact_continuation_context(self):
        after,step=self.payload()
        self.assertEqual(len(set(after)-set(self.before)),3)
        self.assertEqual(len(set(step['changedPaths'])-{policy.LEDGER}),4)
        self.assertIsNone(self.verify(after,step))

    def test_same_payload_refuses_legacy_or_default_context(self):
        after,step=self.payload()
        with self.assertRaisesRegex(ValueError,'reviewed_addition_scope'):self.verify(after,step,False)
        with self.assertRaisesRegex(ValueError,'corrected_source_path_set'):
            policy._verify_reviewed_step(self.git,self.before,after,step)

    def test_modified_projection_cannot_expand_inner_guard(self):
        after,step=self.payload();scope=run.vendor_repair_continuation();scope['maximumMaterialSourceGenerations']=6
        with self.assertRaisesRegex(ValueError,'vendor_continuation_scope'):
            policy._verify_reviewed_step(self.git,self.before,after,step,
                allowed_additions=set(step['changedPaths']),vendor_continuation=scope)

    def test_old_generation_cannot_use_continuation_additions(self):
        after,step=self.payload();step['number']=3
        with self.assertRaisesRegex(ValueError,'reviewed_continuation_addition_generation'):self.verify(after,step)

    def test_declared_unapproved_extra_still_refuses(self):
        after,step=self.payload('scripts/unapproved-synthetic.mjs')
        with self.assertRaisesRegex(ValueError,'corrected_source_path_set'):self.verify(after,step)

    def test_new_payload_mode_drift_still_refuses(self):
        after,step=self.payload();name=sorted(policy.H3_VENDOR_CONTINUATION_PATHS)[0]
        after[name]=('100755',after[name][1],after[name][2])
        with self.assertRaisesRegex(ValueError,'exact_reviewed_correction_paths'):self.verify(after,step)


if __name__=='__main__':unittest.main()
