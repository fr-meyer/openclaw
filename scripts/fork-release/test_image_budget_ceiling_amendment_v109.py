"""R5 integration: synthetic provider facts only, never a source/image pass."""
from copy import deepcopy
import ast
from datetime import datetime, timezone
import io
from pathlib import Path
import socket
import subprocess
import unittest
from unittest.mock import patch
import urllib.request
import zipfile

import image_build_contract_v109 as image
import image_build_runner_v109 as runner
import source_validation_contract_v109 as source
from test_image_build_contract_v109 import armed

HERE = Path(__file__).resolve().parent
NOW = datetime(2026, 10, 31, 3, tzinfo=timezone.utc).timestamp()


def amendment():
    return {'schema': 'openclaw.v109.budget-ceiling-amendment-binding.v1',
        'scope': 'minute-and-spending-ceilings-only',
        'publicAmendmentSha256': 'fabe093988e258a99b7cccc83e812d274200880cc300f78a73f795905e507f6e',
        'minuteAmendmentSha256': 'a87532d38ff05c0d5d8e253d76abac4a2ea191a603037f22f553099b3c379cf2',
        'spendingAmendmentSha256': 'c31ba60a02c44ef2525b187ea058a8de45c8e2199c60630bd4601d30d8acabc6',
        'isTotalNotAdditional': True}


def fixture(amended=True):
    """Use maintained source controls, normalize only synthetic grant selection."""
    folder = HERE / 'candidates/v2026.10.9-source-only'
    b = source.parse((folder / 'ci-bindings.json').read_bytes())
    b['status'] = b['ciRunGrant']['status'] = 'DISARMED'
    grant = b['ciRunGrant']
    grant.pop('budgetCeilingAmendment', None)
    grant.update(maximumNewRunnerMinutes=2500, moneyCeilingUSD='2.25')
    grant['nextExecution'].update(status='DISARMED', sequence=11,
                                 reviewSha256=None, requestSha256=None)
    if amended:
        grant.update(budgetCeilingAmendment=amendment(),
                     maximumNewRunnerMinutes=25000, moneyCeilingUSD='25.00')
        grant['nextExecution']['sequence'] = 12
    q = source.request_for(b, 'correction', 6)
    request_raw = source.encode(q)
    generation = (folder / 'generation-receipt.json').read_bytes()
    manifest = (folder / 'manifest.json').read_bytes()
    inventory = (folder / 'inventory.json').read_bytes()
    result = {'schema': 'openclaw.v109.source-validation-result.v1',
        'repository': source.REPOSITORY, 'campaignId': source.CAMPAIGN,
        'phase': q['phase'], 'status': 'passed', 'runId': '123', 'runAttempt': 1,
        'pipelineHead': 'a' * 40,
        **{key: q['source'][key] for key in
           ('sourceSha', 'sourceTree', 'manifestSha256', 'inventorySha256')},
        'requestSha256': image.sha(request_raw),
        'generationReceiptSha256': image.sha(generation),
        'selectedProfiles': list(source.PROFILES), 'admissionResult': 'success',
        'sourceMatrixResult': 'success', 'all15Required': True, 'freshCoverage': True,
        'historicalCoverageReused': False, 'imageBuilt': False,
        'nativeImageExecuted': False, 'productionAuthorized': False}
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, 'w') as z:
        z.writestr('source-validation.json', source.encode(result))
    zip_raw = archive.getvalue()
    run = {'id': 123, 'run_attempt': 1, 'head_sha': 'a' * 40,
        'path': image.SOURCE_WORKFLOW, 'event': 'pull_request',
        'head_branch': image.BRANCH, 'display_title': image.SOURCE_NAME,
        'status': 'completed', 'conclusion': 'success',
        'repository': {'full_name': image.REPOSITORY, 'private': False},
        'actor': {'login': image.ACTOR}, 'triggering_actor': {'login': image.ACTOR}}
    jobs = {'total_count': 17, 'jobs': [
        {'id': i + 1, 'name': name, 'status': 'completed', 'conclusion': 'success',
         'run_id': 123} for i, name in enumerate(
             ['admission', *['source (' + p + ')' for p in image.PROFILES], 'final'])]}
    artifacts = {'total_count': 1, 'artifacts': [
        {'id': 456, 'name': 'v109-source-validation-123-attempt1', 'expired': False,
         'size_in_bytes': len(zip_raw), 'digest': 'sha256:' + image.sha(zip_raw),
         'workflow_run': {'id': 123, 'head_sha': 'a' * 40}}]}
    return [source.encode(b), request_raw, generation, manifest, inventory,
            run, jobs, artifacts, zip_raw]


def prepared(amended=True):
    return image.prepare_from_passed_source(*fixture(amended), built_at='2026-10-31T03:00:00Z')


def authorization(amended=True):
    value = armed()['authorization']
    if amended:
        value.update(approvedAt=image.AMENDED_APPROVED_AT,
            expiresAt=image.AMENDED_EXPIRES_AT, maximumNewRunnerMinutes=25000,
            moneyCeilingUSDIncludingAllowance='25.00',
            budgetCeilingAmendmentSha256=image.BUDGET_AMENDMENT_SHA256)
    return value


class ImageBudgetAmendmentTests(unittest.TestCase):
    def setUp(self):
        self.blockers = []
        for target, name in [(subprocess, 'Popen'), (socket, 'socket'),
                (urllib.request, 'urlopen')]:
            guard = patch.object(target, name, side_effect=AssertionError('real host action forbidden'))
            guard.start(); self.addCleanup(guard.stop)

    def test_legacy_constructor_and_authorization_keep_original_totals(self):
        r = prepared(False)
        self.assertNotIn('sourceBudgetCeilingAmendmentSha256', r)
        r = image.arm_prepared(r, authorization(False), NOW)
        self.assertEqual((r['authorization']['maximumNewRunnerMinutes'],
                          r['authorization']['moneyCeilingUSDIncludingAllowance']), (2500, '2.25'))

    def test_amended_constructor_preserves_api_and_emits_no_authority(self):
        r = prepared()
        self.assertEqual(r['state'], 'PREPARED_BUILD')
        self.assertIsNone(r['authorization'])
        self.assertEqual(r['sourceBudgetCeilingAmendmentSha256'], image.BUDGET_AMENDMENT_SHA256)
        with self.assertRaises(image.Refusal): image.validate_request(r, True, NOW)
        active = image.arm_prepared(r, authorization(), NOW)
        self.assertEqual(active['authorization']['maximumNewRunnerMinutes'], 25000)
        self.assertEqual(active['authorization']['moneyCeilingUSDIncludingAllowance'], '25.00')

    def test_each_missing_or_failed_native_job_still_refuses(self):
        args = fixture()
        for index in range(17):
            bad = deepcopy(args); bad[6]['jobs'].pop(index); bad[6]['total_count'] = 16
            with self.subTest(index=index), self.assertRaises(image.Refusal):
                image.prepare_from_passed_source(*bad, built_at='2026-10-31T03:00:00Z')
        bad = deepcopy(args); bad[6]['jobs'][5]['conclusion'] = 'failure'
        with self.assertRaises(image.Refusal):
            image.prepare_from_passed_source(*bad, built_at='2026-10-31T03:00:00Z')

    def test_snapshot_artifact_expiry_and_control_pins_remain_mandatory(self):
        args = fixture(); args[7]['artifacts'][0]['expired'] = True
        with self.assertRaises(image.Refusal):
            image.prepare_from_passed_source(*args, built_at='2026-10-31T03:00:00Z')
        args = fixture(); args[3] = b'wrong-manifest'
        with self.assertRaises(image.Refusal):
            image.prepare_from_passed_source(*args, built_at='2026-10-31T03:00:00Z')

    def test_missing_wrong_unknown_source_amendment_refuses(self):
        for key, value in [('budgetCeilingAmendment', None),
                           ('publicAmendmentSha256', '0' * 64),
                           ('minuteAmendmentSha256', '0' * 64),
                           ('spendingAmendmentSha256', '0' * 64), ('unknown', True)]:
            args = fixture(); b = source.parse(args[0])
            if key == 'budgetCeilingAmendment': del b['ciRunGrant'][key]
            else: b['ciRunGrant']['budgetCeilingAmendment'][key] = value
            args[0] = source.encode(b)
            with self.subTest(key=key), self.assertRaises(ValueError):
                image.prepare_from_passed_source(*args, built_at='2026-10-31T03:00:00Z')

    def test_wrong_source_request_amendment_link_refuses(self):
        args = fixture(); q = source.parse(args[1]); q['budgetCeilingAmendmentSha256'] = '0' * 64
        args[1] = source.encode(q)
        with self.assertRaises(ValueError):
            image.prepare_from_passed_source(*args, built_at='2026-10-31T03:00:00Z')

    def test_source_count_deadline_and_h3_cannot_widen(self):
        for key, value in [('maximumAdditionalAttempts', 1001),
                           ('expiresAt', '2026-11-04T03:14:21Z')]:
            args = fixture(); b = source.parse(args[0]); b['ciRunGrant'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                image.source_budget_amendment(b, source.parse(args[1]))
        args = fixture(); b = source.parse(args[0]); b['ciRunGrant']['nextExecution']['source']['sourceSha'] = 'f' * 40
        with self.assertRaises(ValueError): image.source_budget_amendment(b, source.parse(args[1]))
        r = prepared(); r['sourceSha'] = 'f' * 40; r['privateObject']['object'] = image.expected_object(r['sourceSha'])
        with self.assertRaises(image.Refusal): image.validate_request(r)

    def test_sequence11_cannot_select_expanded_totals(self):
        args = fixture(); b = source.parse(args[0]); b['ciRunGrant']['nextExecution']['sequence'] = 11
        with self.assertRaises(ValueError): image.source_budget_amendment(b, source.parse(args[1]))

    def test_amended_image_requires_both_exact_links(self):
        for edit in [lambda r: r.pop('sourceBudgetCeilingAmendmentSha256'),
                     lambda r: r.update(sourceBudgetCeilingAmendmentSha256='0' * 64)]:
            r = prepared(); edit(r)
            with self.assertRaises(image.Refusal): image.arm_prepared(r, authorization(), NOW)
        for value in (None, '0' * 64):
            auth = authorization()
            if value is None: del auth['budgetCeilingAmendmentSha256']
            else: auth['budgetCeilingAmendmentSha256'] = value
            with self.assertRaises(image.Refusal): image.arm_prepared(prepared(), auth, NOW)

    def test_new_limits_are_exact_total_not_additional_or_noncanonical(self):
        for key, value in [('maximumNewRunnerMinutes', 27500), ('maximumNewRunnerMinutes', 25001),
                           ('maximumNewRunnerMinutes', True), ('moneyCeilingUSDIncludingAllowance', '27.25'),
                           ('moneyCeilingUSDIncludingAllowance', '25'), ('moneyCeilingUSDIncludingAllowance', 25)]:
            auth = authorization(); auth[key] = value
            with self.subTest(key=key), self.assertRaises(image.Refusal):
                image.arm_prepared(prepared(), auth, NOW)

    def test_deadline_cannot_shift_or_extend_with_same96hour_span(self):
        auth = authorization(); auth.update(approvedAt='2026-10-31T03:14:21Z', expiresAt='2026-11-04T03:14:21Z')
        with self.assertRaises(image.Refusal): image.arm_prepared(prepared(), auth, NOW + 90000)
        with self.assertRaises(image.Refusal):
            image.arm_prepared(prepared(), authorization(), image.utc(image.AMENDED_EXPIRES_AT).timestamp())

    def test_no_image_count_build_resource_or_access_scope_expansion(self):
        for key, value in [('maximumPhysicalBuilds', 2), ('maximumBuildMinutes', 91),
                           ('maximumFamilyMinutes', 181), ('maximumArchiveBytes', image.MAX_ARCHIVE + 1),
                           ('producedImageExecutionAllowed', True), ('cloudGrantFromRunnerAllowed', True),
                           ('publicImageExportAllowed', True), ('actionTimeAccessApprovalSha256', None)]:
            auth = authorization(); auth[key] = value
            with self.subTest(key=key), self.assertRaises(image.Refusal):
                image.arm_prepared(prepared(), auth, NOW)
        self.assertEqual(prepared()['privateObject'], image.arm_prepared(prepared(), authorization(), NOW)['privateObject'])

    def test_runner_raw_five_control_consumer_rechecks_snapshot_link(self):
        args = fixture(); r = prepared()
        data = dict(zip(['ci-bindings.json', 'source-request.json', 'generation-receipt.json',
                         'manifest.json', 'inventory.json'], args[:5]))
        def read(path, *a): return data[path.name]
        with patch.object(runner, 'read', side_effect=read):
            _, b, q, actual = runner.source_inputs(r)
            self.assertEqual(actual, data)
            self.assertEqual(image.validate_source_budget_binding(r, b, q), image.BUDGET_AMENDMENT_SHA256)
            r.pop('sourceBudgetCeilingAmendmentSha256')
            with self.assertRaises(image.Refusal): runner.source_inputs(r)

    def test_amendment_cannot_be_claimed_over_legacy_snapshot(self):
        args = fixture(False); b, q = source.parse(args[0]), source.parse(args[1])
        r = prepared(False); r['sourceBudgetCeilingAmendmentSha256'] = image.BUDGET_AMENDMENT_SHA256
        with self.assertRaises(image.Refusal): image.validate_source_budget_binding(r, b, q)

    def test_blueprint_api_stays_unchanged_and_no_capability_is_signed(self):
        import private_oci_upload_blueprint_v109 as blueprint
        r = image.arm_prepared(prepared(), authorization(), NOW)
        value = blueprint.prepare(r, 'f' * 40, 'synthetic@example.invalid', 3600, NOW)
        self.assertFalse(value['authorityCreated'])
        self.assertFalse(value['signedCapabilityCreated'])
        self.assertEqual(value['headers']['x-goog-if-generation-match'], '0')
        self.assertEqual(value['headers']['x-goog-content-length-range'], '1,2147483648')
        self.assertEqual((r['privateObject']['getMaximumSeconds'],
                          r['privateObject']['uploadGrantMaximumSeconds']), (900, 7200))

    def test_new_guard_selected_once_for_future_source_ci(self):
        tree = ast.parse((HERE / 'source_validation_selection_v109.py').read_bytes())
        entries = [node.value for node in tree.body if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == 'PIPELINE_CONTRACT_TESTS'
                           for target in node.targets)]
        self.assertEqual(len(entries), 1)
        self.assertEqual(ast.literal_eval(entries[0]).count(
            'test_image_budget_ceiling_amendment_v109.py'), 1)


if __name__ == '__main__': unittest.main()
