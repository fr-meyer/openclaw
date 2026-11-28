from test_source_validation_contract_v109 import historical_control
"""Closed approved totals; synthetic only, no process/provider/runtime authority."""
from copy import deepcopy
from pathlib import Path
import socket, subprocess, sys, unittest, urllib.request
from unittest import mock
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import bounded_run_contract_v109 as a
import source_validation_contract_v109 as p
import source_validation_selection_v109 as selection
import source_validation_v109 as runtime


def amendment():
    return {'schema': 'openclaw.v109.budget-ceiling-amendment-binding.v1',
        'scope': 'minute-and-spending-ceilings-only',
        'publicAmendmentSha256': 'fabe093988e258a99b7cccc83e812d274200880cc300f78a73f795905e507f6e',
        'minuteAmendmentSha256': 'a87532d38ff05c0d5d8e253d76abac4a2ea191a603037f22f553099b3c379cf2',
        'spendingAmendmentSha256': 'c31ba60a02c44ef2525b187ea058a8de45c8e2199c60630bd4601d30d8acabc6',
        'isTotalNotAdditional': True}


class BudgetAmendmentTests(unittest.TestCase):
    def setUp(self):
        for target, name in [(subprocess, 'Popen'), (socket, 'socket'),
                (urllib.request, 'urlopen'), (urllib.request, 'build_opener')]:
            blocker = mock.patch.object(target, name, side_effect=AssertionError('real process/network forbidden'))
            blocker.start(); self.addCleanup(blocker.stop)
        self.old = p.parse(historical_control('ci-bindings.json'))
        self.b = deepcopy(self.old); self.b['status'] = self.b['ciRunGrant']['status'] = 'DISARMED'
        self.g = self.b['ciRunGrant']; self.g.update(budgetCeilingAmendment=amendment(),
            maximumNewRunnerMinutes=25000, moneyCeilingUSD='25.00')
        self.plan = self.g['nextExecution']
        self.plan.update(status='DISARMED', sequence=12, reviewSha256=None, requestSha256=None)
        self.plan['reservations'] = {'current': 690, 'pendingValidation': 0, 'conditionalImage': 0, 'incidental': 50}

    def grant_refuses(self, grant):
        with self.assertRaises(ValueError): a.validate_grant(grant, self.b['authorization'])

    def request(self): return p.request_for(self.b, 'correction', 6)

    def test_exact_amended_grant_and_closed_request_remain_disarmed(self):
        self.assertIs(a.validate_grant(self.g, self.b['authorization']), self.g)
        self.assertIs(p.validate_bindings(self.b), self.b)
        q = self.request(); self.assertIs(p.validate_request(q, self.b), q)
        self.assertEqual(q['budgetCeilingAmendmentSha256'], amendment()['publicAmendmentSha256'])
        self.assertEqual(q['runAllowanceSha256'], a.AUTHORITY_SHA256)
        self.assertEqual(p.budget(q)['maximumNewMinutes'], 25000)
        self.assertEqual(p.budget(q)['maximumBookedMinutes'], 25000)
        self.assertEqual(p.budget(q)['phaseMaximumMinutes'], 690)
        with self.assertRaises(ValueError): p.validate_request(q, self.b, active=True,
            now=p.utc('2026-10-31T03:00:00Z').timestamp())

    def test_historical_grant_authorization_request_and_three_maps_stay_original(self):
        self.assertIs(a.validate_grant(self.old['ciRunGrant'], self.old['authorization']), self.old['ciRunGrant'])
        self.assertEqual(self.old['authorization']['maximumRunnerMinutes'], 2500)
        self.assertEqual(a.maximum_new_minutes(self.old['ciRunGrant']), 2500)
        self.assertEqual((a.MONEY_USD, a.MAXIMUM_NEW_MINUTES), ('2.25', 2500))
        q = p.parse(historical_control('source-request.json'))
        self.assertIs(p.validate_request(q, self.old), q)
        self.assertNotIn('budgetCeilingAmendmentSha256', q)
        for seq, minutes, caps in [(9,1075,p.PROFILE_MINUTES),(10,740,p.LOWER_PROFILE_MINUTES),(11,690,p.NEXT_PROFILE_MINUTES)]:
            old = deepcopy(q); old['executionSequence'] = seq; old['executionReservations']['current'] = minutes
            self.assertEqual(p.profile_minutes_for(old), caps)
            self.assertEqual(p.budget(old)['maximumNewMinutes'], 2500)
        self.assertEqual(runtime.SOURCE_JOBS['source (doctor-2)'], 75)

    def test_missing_amendment_cannot_raise_either_total(self):
        del self.g['budgetCeilingAmendment']; self.grant_refuses(self.g)
        self.g['maximumNewRunnerMinutes'] = 2500; self.grant_refuses(self.g)

    def test_missing_unknown_wrong_receipt_or_scope_refuses(self):
        for key in amendment():
            bad = amendment(); del bad[key]
            with self.subTest(key=key), self.assertRaises(ValueError): a.validate_budget_amendment(bad)
        for key, value in [('publicAmendmentSha256','0'*64), ('minuteAmendmentSha256','0'*64),
                ('spendingAmendmentSha256','0'*64),('schema','unknown'),('scope','full-release'),
                ('isTotalNotAdditional',False),('isTotalNotAdditional',1),('unknown',True)]:
            bad = amendment(); bad[key] = value
            with self.subTest(key=key,value=value), self.assertRaises(ValueError): a.validate_budget_amendment(bad)

    def test_totals_are_not_additive_arbitrary_or_noncanonical(self):
        for key, value in [('maximumNewRunnerMinutes',27500),('maximumNewRunnerMinutes',25001),
                ('maximumNewRunnerMinutes',True),('moneyCeilingUSD','27.25'),('moneyCeilingUSD','25'),('moneyCeilingUSD',25.00)]:
            g = deepcopy(self.g); g[key] = value
            with self.subTest(key=key,value=value): self.grant_refuses(g)

    def test_count_authority_deadline_parallel_and_diagnostic_caps_unchanged(self):
        for key, value in [('authoritySha256','0'*64),('originalAuthorizationSha256','0'*64),
                ('maximumAdditionalAttempts',1001),('maximumStageAttempts',1043),('expiresAt','2026-11-04T03:14:21Z'),
                ('maximumSourceParallelJobs',4),('diagnosticBytes',134217728),('closedPrefixProducerSha256','0'*64)]:
            g = deepcopy(self.g); g[key] = value
            with self.subTest(key=key): self.grant_refuses(g)

    def test_original_authorization_cannot_be_rewritten(self):
        auth = deepcopy(self.b['authorization']); auth['maximumRunnerMinutes'] = 25000
        with self.assertRaises(ValueError): a.validate_grant(self.g, auth)
        with self.assertRaises(ValueError): p.validate_authorization(auth)

    def test_running_sequence_or_other_phase_cannot_use_new_totals(self):
        for key, value in [('sequence',11),('sequence',True),('sequence',1001),
                ('phase','validation'),('phase','lock-preparation'),('phase','image-build')]:
            g = deepcopy(self.g); g['nextExecution'][key] = value
            with self.subTest(key=key,value=value): self.grant_refuses(g)

    def test_h3_or_different_source_tree_not_authorized(self):
        for key in ('sourceSha','sourceTree'):
            g = deepcopy(self.g); g['nextExecution']['source'][key] = 'f'*40
            with self.subTest(key=key): self.grant_refuses(g)

    def test_age_waiver_image_access_and_security_expansion_not_authorized(self):
        for key in ('minimumDependencyAgePolicyExpanded','imageAccessOrSigningAuthorityExpanded',
                'imageBuildLimitsExpanded','materialSourceAuthorityExpanded','cloudAccessAllowedHere','paidRunnerAllowed'):
            g = deepcopy(self.g); g['budgetCeilingAmendment'][key] = True
            with self.subTest(key=key): self.grant_refuses(g)
        b = deepcopy(self.b); b['authorization']['imageExecutionAllowedHere'] = True
        with self.assertRaises(ValueError): p.validate_bindings(b)

    def test_request_hash_required_and_cannot_be_injected_into_old_binding(self):
        q = self.request()
        for value in (None,'0'*64):
            bad = deepcopy(q)
            if value is None: del bad['budgetCeilingAmendmentSha256']
            else: bad['budgetCeilingAmendmentSha256'] = value
            with self.subTest(value=value), self.assertRaises(ValueError): p.validate_request(bad,self.b)
        old = p.parse(historical_control('source-request.json'))
        old['budgetCeilingAmendmentSha256'] = amendment()['publicAmendmentSha256']
        with self.assertRaises(ValueError): p.validate_request(old,self.old)

    def test_request_budget_cannot_claim_h3_or_unknown_hash(self):
        q = self.request()
        for key, value in [('budgetCeilingAmendmentSha256','0'*64),('runAllowanceSha256','0'*64),('executionSequence',11)]:
            bad = deepcopy(q); bad[key] = value
            with self.subTest(key=key), self.assertRaises(p.Refusal): p.budget(bad)
        q['source']['sourceSha'] = 'f'*40
        with self.assertRaises(p.Refusal): p.budget(q)

    def test_exact_25000_boundary_preserves_reservations_and_never_adds_old2500(self):
        facts = a.validate_budget(self.g,self.plan,24260,0)
        self.assertEqual((facts['maximumNewMinutesBooked'],facts['reservedMinutes'],facts['maximumNewRunnerMinutes']),(25000,740,25000))
        self.assertTrue(facts['noConsumedMinuteRefund'])
        for observed in (24261,26760):
            with self.subTest(observed=observed), self.assertRaises(ValueError): a.validate_budget(self.g,self.plan,observed,0)

    def test_amended_budget_cannot_substitute_plan_or_invent790_schedule(self):
        alternate = deepcopy(self.plan); alternate['reservations']['incidental'] = 0
        with self.assertRaises(ValueError): a.validate_budget(self.g,alternate,24260,0)
        g = deepcopy(self.g); g['nextExecution']['reservations']['current'] = 790
        self.grant_refuses(g)
        with self.assertRaises(ValueError): a.validate_budget(g,g['nextExecution'],100,0)

    def test_booked_floor_never_refunded_by_smaller_observation(self):
        floor = a.PREFIX_MINUTES + sum(r['runnerMinutes'] for r in self.g['bookedAdditionalAttempts'])
        facts = a.validate_budget(self.g,self.plan,0,0)
        self.assertEqual((facts['otherMinutesCharged'],facts['maximumNewMinutesBooked']),(floor,floor+740))
        self.assertEqual(self.g['bookedAdditionalAttempts'],self.old['ciRunGrant']['bookedAdditionalAttempts'])

    def test_runtime_keeps_per_attempt_floors_and_refuses_missing_observation(self):
        rows = {(rid,1):0 for rid in a.PREFIX_RUN_IDS}; rows[(a.PREFIX_RUN_IDS[0],1)] = a.PREFIX_MINUTES
        for r in self.g['bookedAdditionalAttempts']: rows[(r['runId'],r['nativeAttempt'])] = 0
        rows[('999999999999',1)] = 10
        total,facts = runtime.bounded_minute_booking(self.g,rows,'999999999999',10)
        self.assertGreaterEqual(total,a.PREFIX_MINUTES+sum(r['runnerMinutes'] for r in self.g['bookedAdditionalAttempts'])+10)
        self.assertEqual(facts['maximumNewRunnerMinutes'],25000)
        self.assertTrue(facts['perAttemptBookedMinuteFloorsApplied'])
        r = self.g['bookedAdditionalAttempts'][0]; del rows[(r['runId'],r['nativeAttempt'])]
        with self.assertRaises(ValueError): runtime.bounded_minute_booking(self.g,rows,'999999999999',10)

    def test_attempt_count_not_refilled(self):
        old = a.count_attempts({},set(),self.old['ciRunGrant']); new = a.count_attempts({},set(),self.g)
        self.assertEqual(old,new)
        self.assertEqual(new['remainingAttemptAllowance'],1000-len(self.g['bookedAdditionalAttempts']))

    def test_new_guard_positively_selected_once(self):
        self.assertEqual(selection.PIPELINE_CONTRACT_TESTS.count('test_budget_ceiling_amendment_v109.py'),1)


if __name__ == '__main__': unittest.main()
