"""Prospective-only lower ceilings; no provider, process, or runtime access."""
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import socket
import subprocess
import sys
import unittest
from unittest import mock
import urllib.request

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
import bounded_run_contract_v109 as allowance
import source_validation_contract_v109 as policy
import source_validation_v109 as runtime
import model_diagnostic_v109 as diagnostic
import source_validation_selection_v109 as selection

LEGACY = dict(zip(policy.PROFILES, (60, 90, 90, 90, 60, 60, 60, 60, 60, 90, 75, 75, 60, 45, 60)))
LOWER = dict(zip(policy.PROFILES, (30, 35, 60, 30, 30, 30, 45, 45, 50, 70, 65, 60, 60, 30, 60)))
NEXT = dict(zip(policy.PROFILES, (25, 35, 60, 25, 30, 30, 45, 45, 50, 60, 55, 50, 60, 30, 50)))


class LowerCeilingTests(unittest.TestCase):
    def setUp(self):
        self.blockers = [mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('process forbidden')),
            mock.patch.object(socket, 'socket', side_effect=AssertionError('socket forbidden')),
            mock.patch.object(urllib.request, 'urlopen', side_effect=AssertionError('network forbidden')),
            mock.patch.object(urllib.request, 'build_opener', side_effect=AssertionError('network forbidden'))]
        for blocker in self.blockers:
            blocker.start(); self.addCleanup(blocker.stop)
        self.legacy_request = json.loads((HERE / 'candidates/v2026.10.9-source-only' / 'source-request.json').read_bytes())
        # A synthetic legacy schedule view stays stable when the active request advances.
        self.legacy_request['executionSequence'] = 9
        self.legacy_request['executionReservations']['current'] = 1075
        self.bindings = json.loads((HERE / 'candidates/v2026.10.9-source-only' / 'ci-bindings.json').read_bytes())
        self.plan = deepcopy(self.bindings['ciRunGrant']['nextExecution'])
        self.plan.update(status='DISARMED', sequence=10, reviewSha256=None, requestSha256=None)
        self.plan['reservations']['current'] = 740
        self.lower_request = deepcopy(self.legacy_request)
        self.lower_request['executionSequence'] = 10
        self.lower_request['executionReservations']['current'] = 740
        self.next_plan = deepcopy(self.plan)
        self.next_plan['sequence'] = 11
        self.next_plan['reservations'] = {'current': 690, 'pendingValidation': 0,
            'conditionalImage': 0, 'incidental': 50}
        self.next_request = deepcopy(self.lower_request)
        self.next_request['executionSequence'] = 11
        self.next_request['executionReservations'] = deepcopy(self.next_plan['reservations'])

    def test_legacy_constants_and_request_budget_are_unchanged(self):
        self.assertEqual(policy.PROFILE_MINUTES, LEGACY)
        self.assertEqual(policy.SOURCE_MINUTES, 1075)
        self.assertEqual(policy.profile_minutes_for(self.legacy_request), LEGACY)
        self.assertEqual(policy.budget(self.legacy_request)['phaseMaximumMinutes'], 1075)
        self.assertEqual(runtime.SOURCE_JOBS['source (types-production)'], 90)

    def test_lower_map_is_exact_strictly_nonincreasing_full15(self):
        self.assertEqual(policy.profile_minutes_for(self.lower_request), LOWER)
        self.assertEqual(set(LOWER), set(LEGACY))
        self.assertTrue(all(0 < LOWER[k] <= LEGACY[k] for k in LEGACY))
        self.assertEqual(sum(LOWER.values()) + 30 + 10, 740)
        self.assertEqual(policy.budget(self.lower_request)['phaseMaximumMinutes'], 740)
        self.assertEqual(policy.budget(self.lower_request)['maximumParallelSourceJobs'], 3)
        self.assertEqual(policy.budget(self.lower_request)['separateImageFamilyReserveMinutes'], 180)

    def test_lower_plan_and_full_closed_request_validate_without_activation(self):
        allowance.validate_plan(self.plan)
        b = deepcopy(self.bindings)
        b['status'] = 'DISARMED'
        b['ciRunGrant']['status'] = 'DISARMED'
        b['ciRunGrant']['nextExecution'] = deepcopy(self.plan)
        q = policy.request_for(b, 'correction', 6)
        self.assertEqual(q, self.lower_request)
        self.assertIs(policy.validate_request(q, b), q)
        with self.assertRaises(policy.Refusal):
            policy.validate_request(q, b, active=True, now=policy.utc('2026-10-31T00:00:00Z').timestamp())

    def test_legacy_plan_still_validates_exact1075(self):
        p = deepcopy(self.bindings['ciRunGrant']['nextExecution'])
        p['reservations']['current'] = 1075
        allowance.validate_plan(p)
        self.assertEqual(p['reservations']['current'], 1075)

    def test_lower_plan_wrong_phase_refuses(self):
        for phase in ('validation', 'lock-preparation'):
            p = deepcopy(self.plan); p['phase'] = phase
            with self.subTest(phase=phase), self.assertRaises(allowance.Refusal):
                allowance.validate_plan(p)

    def test_lower_plan_old_sequence_and_boolean_refuse(self):
        for sequence in (1, 9, True, 1001):
            p = deepcopy(self.plan); p['sequence'] = sequence
            with self.subTest(sequence=sequence), self.assertRaises(allowance.Refusal):
                allowance.validate_plan(p)

    def test_arbitrary_or_boolean_reservation_refuses(self):
        for minutes in (739, 741, 800, True, '740'):
            p = deepcopy(self.plan); p['reservations']['current'] = minutes
            with self.subTest(minutes=minutes), self.assertRaises(allowance.Refusal):
                allowance.validate_plan(p)

    def test_caller_selected_profile_map_is_not_a_plan_field(self):
        p = deepcopy(self.plan); p['profileMinutes'] = dict(LOWER)
        with self.assertRaises(allowance.Refusal): allowance.validate_plan(p)

    def test_lower_request_requires_exact_authority_phase_sequence_and_full15(self):
        changes = [('runAllowanceSha256', '0' * 64), ('phase', 'validation'),
            ('executionSequence', 9), ('executionSequence', True),
            ('profiles', list(policy.PROFILES)[:-1])]
        for key, value in changes:
            q = deepcopy(self.lower_request); q[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(policy.Refusal):
                policy.profile_minutes_for(q)

    def test_returned_map_is_a_copy(self):
        value = policy.profile_minutes_for(self.lower_request)
        value['dependency'] = 200
        self.assertEqual(policy.profile_minutes_for(self.lower_request), LOWER)

    def test_next_map_is_closed_full15_and_only_six_caps_are_lower(self):
        self.assertEqual(policy.NEXT_PROFILE_MINUTES, NEXT)
        self.assertEqual(policy.NEXT_SOURCE_MINUTES, 690)
        self.assertEqual(policy.profile_minutes_for(self.next_request), NEXT)
        self.assertEqual(sum(NEXT.values()) + 30 + 10, 690)
        self.assertEqual({k for k in LOWER if NEXT[k] != LOWER[k]},
            {'dependency', 'types-scripts', 'doctor-1', 'doctor-2', 'doctor-3', 'compatibility'})
        self.assertTrue(all(0 < NEXT[k] <= LOWER[k] for k in LOWER))
        for key in ('types-tests', 'sqlite', 'memory'):
            self.assertEqual(NEXT[key], LOWER[key])
        value = policy.profile_minutes_for(self.next_request)
        value['dependency'] = 200
        self.assertEqual(policy.profile_minutes_for(self.next_request), NEXT)

    def test_next_plan_and_closed_request_validate_without_activation(self):
        allowance.validate_plan(self.next_plan)
        b = deepcopy(self.bindings)
        b['status'] = b['ciRunGrant']['status'] = 'DISARMED'
        b['ciRunGrant']['nextExecution'] = deepcopy(self.next_plan)
        q = policy.request_for(b, 'correction', 6)
        self.assertEqual(q, self.next_request)
        self.assertIs(policy.validate_request(q, b), q)
        budget = policy.budget(q)
        self.assertEqual(budget['phaseMaximumMinutes'], 690)
        self.assertEqual(budget['currentPlanReservationMinutes'], 740)
        self.assertEqual(budget['maximumParallelSourceJobs'], 3)
        self.assertEqual(budget['maximumNewMinutes'], 2500)
        self.assertEqual(budget['separateImageFamilyReserveMinutes'], 180)
        with self.assertRaises(policy.Refusal):
            policy.validate_request(q, b, active=True, now=policy.utc('2026-10-31T00:00:00Z').timestamp())

    def test_next_plan_wrong_phase_sequence_and_arbitrary_fields_refuse(self):
        for key, value in (('phase', 'validation'), ('phase', 'lock-preparation'),
                ('sequence', 10), ('sequence', True), ('sequence', 1001),
                ('profileMinutes', NEXT)):
            p = deepcopy(self.next_plan); p[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(allowance.Refusal):
                allowance.validate_plan(p)
        for minutes in (689, 691, True, '690'):
            p = deepcopy(self.next_plan); p['reservations']['current'] = minutes
            with self.subTest(minutes=minutes), self.assertRaises(allowance.Refusal):
                allowance.validate_plan(p)

    def test_next_request_requires_exact_authority_phase_sequence_and_all15(self):
        for key, value in (('runAllowanceSha256', '0' * 64), ('phase', 'validation'),
                ('executionSequence', 10), ('executionSequence', True),
                ('executionSequence', 1001), ('profiles', list(policy.PROFILES)[:-1])):
            q = deepcopy(self.next_request); q[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(policy.Refusal):
                policy.profile_minutes_for(q)
        q = deepcopy(self.next_request); q['executionReservations']['current'] = 689
        with self.assertRaises(policy.Refusal): policy.profile_minutes_for(q)

    def test_next_budget_requires_closed_ledger_at_most1760_with_image_deferred(self):
        grant = self.bindings['ciRunGrant']
        result = allowance.validate_budget(grant, self.next_plan, 1760, 0)
        self.assertEqual(result['maximumNewMinutesBooked'], 2500)
        with self.assertRaises(allowance.Refusal):
            allowance.validate_budget(grant, self.next_plan, 1761, 0)
        with_image = deepcopy(self.next_plan); with_image['reservations']['conditionalImage'] = 180
        with self.assertRaises(allowance.Refusal):
            allowance.validate_budget(grant, with_image, 1760, 0)
        booked = allowance.PREFIX_MINUTES + sum(r['runnerMinutes'] for r in grant['bookedAdditionalAttempts'])
        self.assertEqual(allowance.validate_budget(grant, self.next_plan, 0, 0)['otherMinutesCharged'], booked)

    @staticmethod
    def native_run():
        return {'repository': {'full_name': 'fr-meyer/openclaw', 'private': False},
            'actor': {'login': 'fr-meyer'}, 'triggering_actor': {'login': 'fr-meyer'},
            'run_attempt': 1, 'id': 123, 'head_sha': 'a' * 40, 'event': 'pull_request',
            'head_branch': policy.PIPELINE_BRANCH, 'path': policy.WORKFLOW,
            'name': policy.CAMPAIGN, 'display_title': policy.CAMPAIGN}

    def test_historical_native_duration_above_new_cap_remains_valid(self):
        job = {'id': 12, 'name': 'source (types-production)', 'run_attempt': 1,
            'status': 'completed', 'conclusion': 'success', 'runner_id': 1,
            'runner_group_name': 'GitHub Actions', 'labels': ['ubuntu-24.04'],
            'started_at': '2026-10-30T12:00:00Z', 'completed_at': '2026-10-30T12:50:00Z'}
        old_limits = runtime.role(self.native_run(), self.legacy_request)
        new_limits = runtime.role(self.native_run(), self.lower_request)
        self.assertEqual(old_limits['source (types-production)'], 90)
        self.assertEqual(new_limits['source (types-production)'], 35)
        self.assertEqual(runtime.observed_jobs([job], 0, True, old_limits)[0], 50)
        with self.assertRaises(policy.Refusal): runtime.observed_jobs([job], 0, True, new_limits)

    def test_historical740_native_caps_are_never_reinterpreted_as690(self):
        job = {'id': 13, 'name': 'source (doctor-2)', 'run_attempt': 1,
            'status': 'completed', 'conclusion': 'success', 'runner_id': 1,
            'runner_group_name': 'GitHub Actions', 'labels': ['ubuntu-24.04'],
            'started_at': '2026-10-30T12:00:00Z', 'completed_at': '2026-10-30T13:00:00Z'}
        old_limits = runtime.role(self.native_run(), self.lower_request)
        new_limits = runtime.role(self.native_run(), self.next_request)
        self.assertEqual(old_limits['source (doctor-2)'], 65)
        self.assertEqual(new_limits['source (doctor-2)'], 55)
        self.assertEqual(runtime.observed_jobs([job], 0, True, old_limits)[0], 60)
        with self.assertRaises(policy.Refusal): runtime.observed_jobs([job], 0, True, new_limits)

    def test_job_deadline_uses_selected_map_and_keeps_absolute_expiry(self):
        start = int(datetime(2026, 10, 31, tzinfo=timezone.utc).timestamp())
        with mock.patch.object(policy, 'validate_bindings'):
            old = runtime.job_deadline(self.bindings, self.legacy_request,
                {runtime.CLOCK: str(start)}, 'types-production', start)
            new = runtime.job_deadline(self.bindings, self.lower_request,
                {runtime.CLOCK: str(start)}, 'types-production', start)
        self.assertEqual(old, start + 90 * 60 - 60)
        self.assertEqual(new, start + 35 * 60 - 60)

    def test_next_job_deadline_uses690_without_rewriting740(self):
        start = int(datetime(2026, 10, 31, tzinfo=timezone.utc).timestamp())
        with mock.patch.object(policy, 'validate_bindings'):
            old = runtime.job_deadline(self.bindings, self.lower_request,
                {runtime.CLOCK: str(start)}, 'doctor-2', start)
            new = runtime.job_deadline(self.bindings, self.next_request,
                {runtime.CLOCK: str(start)}, 'doctor-2', start)
        self.assertEqual(old, start + 65 * 60 - 60)
        self.assertEqual(new, start + 55 * 60 - 60)

    def test_exact_active_workflow_matrix_and_route_binding(self):
        raw = (ROOT / policy.WORKFLOW).read_bytes()
        restored = (HERE / 'fixtures/v109-source-validation-restored.yml').read_bytes()
        self.assertEqual(raw, restored)
        self.assertEqual(policy.digest(raw), diagnostic.SOURCE_WORKFLOW_RESTORED)
        matrix = dict((name, int(minutes)) for name, minutes in re.findall(
            rb'- profile: ([a-z0-9-]+)\n\s+minutes: ([0-9]+)', raw))
        self.assertEqual({k.decode(): v for k, v in matrix.items()}, NEXT)
        diagnostic.workflow_routing(type('R', (), {'regular': staticmethod(lambda p, cap: p.read_bytes())}), ROOT, False)

    def test_tampered_workflow_map_refuses_at_same_route_guard(self):
        target = ROOT / policy.WORKFLOW
        def read(p, cap):
            raw = p.read_bytes()
            return raw.replace(b'- profile: dependency\n            minutes: 25',
                b'- profile: dependency\n            minutes: 26') if p == target else raw
        with self.assertRaises(policy.Refusal):
            diagnostic.workflow_routing(type('R', (), {'regular': staticmethod(read)}), ROOT, False)

    def test_new_guard_module_is_positively_selected_once(self):
        self.assertEqual(selection.PIPELINE_CONTRACT_TESTS.count("test_lower_source_ceiling_v109.py"), 1)

    def test_all17_result_schema_still_requires_fresh_same_run_success(self):
        value = runtime.source_result(self.lower_request, policy.encode(self.lower_request),
            {'GITHUB_RUN_ID': '123'}, 'a' * 40, 'success', 'success')
        self.assertEqual(value['selectedProfiles'], list(policy.PROFILES))
        self.assertTrue(value['all15Required'] and value['freshCoverage'])
        self.assertFalse(value['historicalCoverageReused'])
        blocked = runtime.source_result(self.lower_request, policy.encode(self.lower_request),
            {'GITHUB_RUN_ID': '123'}, 'a' * 40, 'success', 'failure')
        self.assertEqual(blocked['status'], 'failed')
        self.assertFalse(blocked['freshCoverage'])

    def test_next_all17_results_still_require_fresh_same_caller_success(self):
        value = runtime.source_result(self.next_request, policy.encode(self.next_request),
            {'GITHUB_RUN_ID': '123'}, 'a' * 40, 'success', 'success')
        self.assertEqual(value['selectedProfiles'], list(policy.PROFILES))
        self.assertTrue(value['all15Required'] and value['freshCoverage'])
        self.assertFalse(value['historicalCoverageReused'])
        blocked = runtime.source_result(self.next_request, policy.encode(self.next_request),
            {'GITHUB_RUN_ID': '123'}, 'a' * 40, 'success', 'failure')
        self.assertEqual(blocked['status'], 'failed')
        self.assertFalse(blocked['freshCoverage'])


if __name__ == '__main__': unittest.main()
