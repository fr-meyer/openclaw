"""Pure H3 image constraints and fixed adapter seams; never image/source proof."""
from copy import deepcopy
import io
from pathlib import Path
import socket
import subprocess
import types
import unittest
from unittest.mock import patch
import urllib.request
import zipfile

import image_build_contract_v109 as image
import image_build_runner_v109 as runner
import source_validation_v109 as source_runtime
import bounded_run_contract_v109 as allowance
import source_validation_contract_v109 as source_policy
from test_h3_source_stage_v109 import fixture as h3_bindings
from test_image_build_contract_v109 import armed, context, source_fixture


NOW = image.utc('2026-11-04T12:30:00Z').timestamp()


def stage():
    return allowance.h3_stage_descriptor()


def request(prepared=False):
    value = armed()
    value.update(sourceSha='9' * 40, sourceTree='8' * 40, builtAt='2026-11-04T12:00:00Z',
        sourceStage=stage(), sourceBudgetCeilingAmendmentSha256=image.BUDGET_AMENDMENT_SHA256)
    value['privateObject']['object'] = image.expected_object(value['sourceSha'])
    value['authorization'].update(approvedAt=image.AMENDED_APPROVED_AT,
        expiresAt=stage()['expiresAt'], maximumNewRunnerMinutes=25000,
        moneyCeilingUSDIncludingAllowance='25.00',
        budgetCeilingAmendmentSha256=image.BUDGET_AMENDMENT_SHA256,
        sourceStageSha256=image.source_stage_digest(stage()))
    if prepared:
        value.update(state='PREPARED_BUILD', authorization=None)
    return value


def passed_h3_fixture():
    """Actual maintained constructors over wholly synthetic source/producer bytes."""
    b=h3_bindings();prep=b['preparation'];here=Path(__file__).resolve().parent
    manifest=b'{"syntheticManifest":true}\n';inventory=b'{"syntheticInventory":true}\n'
    receipt=source_policy.parse((here/'fixtures/v109-h3-anchor-generation.json').read_bytes())
    receipt.update(sourceSha=prep['sourceSha'],sourceTree=prep['sourceTree'],pipelineHead='7'*40,runId='1234',
        packageSha256=prep['fileSha256']['package.json'],workspaceSha256=prep['fileSha256']['pnpm-workspace.yaml'],
        sourceLockSha256=prep['fileSha256']['pnpm-lock.yaml'],ledgerSha256=prep['fileSha256'][source_policy.LEDGER],
        generatedLockSha256='2'*64,gitDiffSha256='3'*64,changedPaths=['pnpm-lock.yaml'],
        startedAt='2026-11-04T10:00:00Z',finishedAt='2026-11-04T10:01:00Z')
    receipt['registryEvidence']['checkedAt']='2026-11-04T10:01:00Z'
    raw_generation=source_policy.encode(receipt)
    generation={'runId':'1234','runAttempt':1,'pipelineHead':'7'*40,'artifactId':44,'artifactSha256':'6'*64,
        'receiptSha256':image.sha(raw_generation),'generatedLockSha256':'2'*64,'gitDiffSha256':'3'*64}
    h=deepcopy(prep);h.update(sourceSha='9'*40,sourceTree='8'*40,
        manifestSha256=image.sha(manifest),inventorySha256=image.sha(inventory))
    h['fileSha256']['pnpm-lock.yaml']='2'*64
    v={'source':h,'generation':generation,'unchangedTreeSha256':'4'*64,'preparationAttempt':7}
    b['sourceSuccessor']['generations'][-1]['validation']=v;b['validation']=v
    family_hash=source_policy.digest(source_policy.canonical(b['sourceSuccessor']))
    b['ciRunGrant']['sourceSuccessorAmendment']['sourceFamilySha256']=family_hash
    b['ciRunGrant']['nextExecution'].update(sequence=13,phase='validation',source=h,sourceFamilySha256=family_hash,
        reasonCode='generation_ready',priorSourceRun={'runId':'1234','pipelineHead':'7'*40,'requestSha256':'6'*64},
        reservations={'current':1075,'pendingValidation':0,'conditionalImage':180,'incidental':160})
    q=source_policy.request_for(b,'validation',7);raw_request=source_policy.encode(q)
    result={'schema':'openclaw.v109.source-validation-result.v1','repository':image.REPOSITORY,
        'campaignId':image.CAMPAIGN,'phase':'validation','status':'passed','runId':'123','runAttempt':1,
        'pipelineHead':'a'*40,**{k:h[k] for k in ('sourceSha','sourceTree','manifestSha256','inventorySha256')},
        'requestSha256':image.sha(raw_request),'generationReceiptSha256':image.sha(raw_generation),
        'selectedProfiles':list(source_policy.PROFILES),'admissionResult':'success','sourceMatrixResult':'success',
        'all15Required':True,'freshCoverage':True,'historicalCoverageReused':False,'imageBuilt':False,
        'nativeImageExecuted':False,'productionAuthorized':False}
    archive=io.BytesIO()
    with zipfile.ZipFile(archive,'w') as z:z.writestr('source-validation.json',source_policy.encode(result))
    raw=archive.getvalue()
    native_request=request();run,jobs,artifacts,_,_=source_fixture(native_request)
    for job in jobs['jobs']:job.update(started_at='2026-11-04T10:02:00Z',completed_at='2026-11-04T11:00:00Z')
    artifacts['artifacts'][0].update(size_in_bytes=len(raw),digest='sha256:'+image.sha(raw))
    return [source_policy.encode(b),raw_request,raw_generation,manifest,inventory,run,jobs,artifacts,raw]


class H3ImageStageTests(unittest.TestCase):
    def setUp(self):
        for target, name in [(subprocess, 'Popen'), (socket, 'socket'),
                (urllib.request, 'urlopen'), (urllib.request, 'build_opener')]:
            blocker = patch.object(target, name, side_effect=AssertionError('real host action forbidden'))
            blocker.start(); self.addCleanup(blocker.stop)

    def test_closed_h3_prepared_and_armed_have_distinct_authority(self):
        value = request(True)
        self.assertIs(image.validate_request(value), value)
        with self.assertRaises(image.Refusal): image.validate_request(value, True, NOW)
        active = image.arm_prepared(value, request()['authorization'], NOW)
        self.assertEqual(active['sourceStage'], stage())
        self.assertIsNone(value['authorization'])

    def test_no_invented_approval_seconds_or_free_deadline_extension(self):
        value = request(); image.validate_request(value, True, NOW)
        self.assertEqual(value['authorization']['approvedAt'], '2026-10-30T03:14:21Z')
        for key, wrong in [('approvedAt', '2026-10-31T05:44:00Z'),
                ('expiresAt', '2026-11-07T03:14:21Z'), ('sourceStageSha256', '0' * 64)]:
            bad = deepcopy(value); bad['authorization'][key] = wrong
            with self.subTest(key=key), self.assertRaises(image.Refusal): image.validate_request(bad)

    def test_stage_missing_unknown_and_expanded_fields_refuse(self):
        for key in stage():
            bad = request(); del bad['sourceStage'][key]
            with self.subTest(key=key), self.assertRaises(image.Refusal): image.validate_request(bad)
        for key, wrong in [('maximumStageBookedMinutes', 5916), ('stagePrefixNewMinutes', 0),
                ('maximumSourceGenerations', 4), ('publicAmendmentSha256', '0' * 64), ('unknown', True)]:
            bad = request(); bad['sourceStage'][key] = wrong
            with self.subTest(key=key), self.assertRaises(image.Refusal): image.validate_request(bad)

    def test_h3_cannot_be_injected_into_disarmed_or_h2_request(self):
        bad = image.disarmed_request(); bad['sourceStage'] = stage()
        with self.assertRaises(image.Refusal): image.validate_request(bad)
        bad = request(); bad['sourceSha'] = image.AMENDED_SOURCE
        bad['sourceTree'] = image.AMENDED_SOURCE_TREE
        bad['privateObject']['object'] = image.expected_object(bad['sourceSha'])
        with self.assertRaises(image.Refusal): image.validate_request(bad)
        bad = request(); del bad['sourceBudgetCeilingAmendmentSha256']
        with self.assertRaises(image.Refusal): image.validate_request(bad)

    def test_package_floor_and_final_expiry_still_refuse(self):
        for stamp in ('2026-11-04T09:59:49Z', '2026-11-06T03:14:21Z'):
            with self.subTest(stamp=stamp), self.assertRaises(image.Refusal):
                image.validate_request(request(), True, image.utc(stamp).timestamp())
        bad = request(True); bad['builtAt'] = '2026-11-04T09:59:49Z'
        with self.assertRaises(image.Refusal): image.validate_request(bad)

    def test_image_access_and_physical_limits_do_not_expand(self):
        value = request()
        for key, wrong in [('maximumPhysicalBuilds', 2), ('maximumBuildMinutes', 91),
                ('maximumFamilyMinutes', 181), ('maximumNewRunnerMinutes', 25001),
                ('moneyCeilingUSDIncludingAllowance', '25.01'), ('cloudGrantFromRunnerAllowed', True),
                ('actionTimeAccessApprovalSha256', None)]:
            bad = deepcopy(value); bad['authorization'][key] = wrong
            with self.subTest(key=key), self.assertRaises(image.Refusal): image.validate_request(bad)
        self.assertEqual((value['privateObject']['maximumBytes'], value['privateObject']['putMaximumSeconds'],
            value['privateObject']['uploadGrantMaximumSeconds'], value['privateObject']['getMaximumSeconds']),
            (2147483648, 3600, 7200, 900))

    def test_whole_family_and_incidental_reservations_at_stage_boundary(self):
        value = request()
        facts = image.cumulative_stage_budget(value, 5575 + 7, 7, 0, 160)
        self.assertEqual(facts['maximumCumulativeBookedMinutes'], 5915)
        self.assertEqual(facts['currentJobReservationMinutes'], 105)
        self.assertEqual(facts['remainingImageFamilyReservationMinutes'], 180)
        self.assertEqual(facts['remainingIncidentalReserveMinutes'], 160)
        with self.assertRaises(image.Refusal): image.cumulative_stage_budget(value, 5576 + 7, 7, 0, 160)

    def test_current_actual_is_not_double_charged_and_prior_family_is_retained(self):
        value = request()
        facts = image.cumulative_stage_budget(value, 5725 + 9, 9, 75, 85)
        self.assertEqual(facts['maximumCumulativeBookedMinutes'], 5915)

    def test_missing_floor_boolean_negative_or_overfamily_observation_refuses(self):
        for args in [(2214, 0, 0, 0), (2300, 0, 76, 0), (2300, 106, 0, 0),
                (2300, 0, True, 0), (2300, 0, 0, True), (2300, 0, 0, -1), (2300, 0, 0, 161)]:
            with self.subTest(args=args), self.assertRaises(image.Refusal):
                image.cumulative_stage_budget(request(), *args)

    def test_all17_native_jobs_remain_mandatory_on_h3(self):
        value = request(); run, jobs, artifacts, raw, validator = source_fixture(value)
        for j in jobs['jobs']:
            j.update(started_at='2026-11-04T10:00:00Z', completed_at='2026-11-04T11:00:00Z')
        self.assertEqual(image.validate_source_snapshot(value, run, jobs, artifacts, raw, validator)['status'], 'passed')
        for index in range(17):
            bad = deepcopy(jobs); bad['jobs'][index]['conclusion'] = 'failure'
            with self.subTest(index=index), self.assertRaises(image.Refusal):
                image.validate_source_snapshot(value, run, bad, artifacts, raw, validator)

    def test_native_source_times_require_positive_h3_package_floor(self):
        value = request(); run, jobs, artifacts, raw, validator = source_fixture(value)
        for j in jobs['jobs']:
            j.update(started_at='2026-11-04T10:00:00Z', completed_at='2026-11-04T11:00:00Z')
        for name, stamp in [('started_at', '2026-11-04T09:59:49Z'),
                ('completed_at', '2026-11-06T03:14:22Z'), ('started_at', None)]:
            bad = deepcopy(jobs); bad['jobs'][0][name] = stamp
            with self.subTest(name=name, stamp=stamp), self.assertRaises(image.Refusal):
                image.validate_source_snapshot(value, run, bad, artifacts, raw, validator)

    def test_source_snapshot_uses_the_effective_owner_window(self):
        value = request(); run, jobs, artifacts, raw, _ = source_fixture(value)
        for j in jobs['jobs']:
            j.update(started_at='2026-11-04T10:00:00Z', completed_at='2026-11-04T11:00:00Z')
        values = {'actions/runs/123': run, 'actions/runs/123/jobs?filter=all&per_page=100': jobs,
            'actions/runs/123/artifacts?per_page=100': artifacts, 'actions/artifacts/456/zip': raw}
        api = types.SimpleNamespace(get=lambda path, **kw: values[path])
        window = unittest.mock.Mock(return_value=(image.AMENDED_APPROVED_AT, stage()['expiresAt']))
        owner = types.SimpleNamespace(validate_source_result=lambda raw, *a, **kw: image.parse(raw),
            source_authorization_window=window, utc=image.utc)
        bindings = {'authorization': {'approvedAt': image.AMENDED_APPROVED_AT,
            'expiresAt': image.AMENDED_EXPIRES_AT}}
        result = runner.source_snapshot(api, value, owner, bindings, {}, {'source-request.json': b'synthetic'})
        self.assertEqual(result['status'], 'passed'); window.assert_called_once_with(bindings)
        jobs['jobs'][0]['completed_at'] = '2026-11-06T03:14:22Z'
        with self.assertRaises(image.Refusal):
            runner.source_snapshot(api, value, owner, bindings, {}, {'source-request.json': b'synthetic'})

    def test_fixed_history_adapter_requires_positive_owner_booking(self):
        value = request(); ctx = context()
        rows = {'total_count': 1, 'workflow_runs': [{'id': 789, 'path': image.WORKFLOW,
            'event': 'push', 'head_branch': image.BRANCH, 'run_attempt': 1,
            'actor': {'login': image.ACTOR}, 'triggering_actor': {'login': image.ACTOR},
            'head_sha': ctx['sha'], 'status': 'in_progress'}]}
        seen = []
        api = types.SimpleNamespace(get=lambda path, **kw: seen.append(path) or rows)
        facts = {'newObservedOrBookedMinutes': 5500, 'currentObservedMinutes': 5,
            'perAttemptBookedMinuteFloorsApplied': True, 'remainingIncidentalReserveMinutes': 160}
        with patch.object(image, 'validate_source_budget_binding'), patch.object(source_runtime,
                'image_cumulative_booking', return_value=facts) as owner:
            result = runner.history(api, value, ctx, {'synthetic': True}, {'synthetic': True})
            self.assertEqual(result['cumulativeStageBooking']['maximumCumulativeBookedMinutes'], 5835)
            self.assertEqual(owner.call_count, 1)
            callback = owner.call_args.args[1]
            with self.assertRaises(image.Refusal): callback('/repos/other/private/actions/runs/1')
        for key in facts:
            bad = deepcopy(facts); del bad[key]
            with self.subTest(key=key), patch.object(image, 'validate_source_budget_binding'), patch.object(
                    source_runtime, 'image_cumulative_booking', return_value=bad), self.assertRaises(image.Refusal):
                runner.history(api, value, ctx, {'synthetic': True}, {'synthetic': True})

    def test_real_maintained_h3_constructor_keeps_five_controls_disarmed(self):
        args=passed_h3_fixture()
        prepared=image.prepare_from_passed_source(*args,built_at='2026-11-04T12:00:00Z')
        self.assertEqual(prepared['state'],'PREPARED_BUILD');self.assertIsNone(prepared['authorization'])
        self.assertEqual(prepared['sourceStage'],stage())
        names=['ci-bindings.json','source-request.json','generation-receipt.json','manifest.json','inventory.json']
        data=dict(zip(names,args[:5]))
        with patch.object(runner,'read',side_effect=lambda path,*a:data[path.name]):
            _,b,q,got=runner.source_inputs(prepared)
            self.assertEqual(got,data);self.assertEqual(source_policy.h3_stage_contract(b,q),stage())
        self.assertNotEqual(prepared['sourceSha'],image.AMENDED_SOURCE)
        with self.assertRaises(image.Refusal):image.validate_request(prepared,True,NOW)

    def test_actual_h3_consumer_cannot_drop_or_substitute_stage(self):
        args=passed_h3_fixture();prepared=image.prepare_from_passed_source(*args,built_at='2026-11-04T12:00:00Z')
        b,q=source_policy.parse(args[0]),source_policy.parse(args[1])
        for key in ('sourceStage','sourceBudgetCeilingAmendmentSha256'):
            bad=deepcopy(prepared);del bad[key]
            with self.subTest(key=key),self.assertRaises(image.Refusal):image.validate_source_budget_binding(bad,b,q)
        b['ciRunGrant']['sourceSuccessorAmendment']['maximumSourceGenerations']=4
        with self.assertRaises(image.Refusal):image.validate_source_budget_binding(prepared,b,q)

    def test_actual_h3_constructor_still_requires_genuine_native_artifact_envelope(self):
        args=passed_h3_fixture()
        for change in ('native_failure','wrong_artifact_digest','stale_generation'):
            bad=deepcopy(args)
            if change=='native_failure':bad[6]['jobs'][1]['conclusion']='failure'
            elif change=='wrong_artifact_digest':bad[7]['artifacts'][0]['digest']='sha256:'+'0'*64
            else:bad[2]=b'{}'
            with self.subTest(change=change),self.assertRaises(ValueError):
                image.prepare_from_passed_source(*bad,built_at='2026-11-04T12:00:00Z')


if __name__ == '__main__': unittest.main()
