"""Finite grant/count/next-plan tests; approvals and requests stay in memory."""
from copy import deepcopy
from pathlib import Path
import unittest
from unittest.mock import patch

import bounded_run_contract_v109 as c
import test_third_preparation_contract_v109 as fixtures

m = fixtures.m


def grant(reviewed=False):
    value = {"schema": c.SCHEMA, "status": "APPROVED" if reviewed else "DISARMED",
        "authoritySha256": c.AUTHORITY_SHA256, "approvedAt": c.APPROVED_AT,
        "expiresAt": c.EXPIRES_AT, "originalAuthorizationSha256": c.ORIGINAL_AUTHORIZATION_SHA256,
        "closedPrefixProducerSha256": c.PREFIX_PRODUCER_SHA256,
        "maximumAdditionalAttempts": 1000, "maximumStageAttempts": 1042,
        "maximumNewRunnerMinutes": 2500, "maximumSourceParallelJobs": 3,
        "diagnosticBytes": c.DIAGNOSTIC_BYTES, "moneyCeilingUSD": "2.25",
        "bookedAdditionalAttempts": [], "nextExecution": {"schema": c.PLAN_SCHEMA,
            "status": "REVIEWED" if reviewed else "DISARMED", "sequence": 1,
            "phase": "lock-preparation", "preparationAttempt": 3,
            "source": deepcopy(fixtures.recovery_binding()["preparation"]),
            "priorSourceRun": deepcopy(c.LAST_PREFIX_SOURCE), "reasonCode": "initial_recovery",
            "reviewSha256": "a" * 64 if reviewed else None,
            "requestSha256": "b" * 64 if reviewed else None,
            "reservations": {"current": 45, "pendingValidation": 1075, "conditionalImage": 180, "incidental": 28}}}
    return value


def history(extra=0):
    result = {rid: {"id": int(rid), "run_attempt": 1} for rid in c.PREFIX_RUN_IDS}
    result.update({str(90000000000+n): {"id": 90000000000+n, "run_attempt": 1} for n in range(extra)})
    return result


class BoundedRunContractTests(unittest.TestCase):
    def test_exact_thousand_replaces_hundred_not_additive(self):
        g = grant()
        self.assertEqual(c.validate_grant(g, fixtures.original_authorization()), g)
        for wrong in (100, 1100, True):
            changed = deepcopy(g); changed["maximumAdditionalAttempts"] = wrong
            with self.subTest(wrong=wrong), self.assertRaises(ValueError): c.validate_grant(changed, fixtures.original_authorization())

    def test_disarmed_or_unreviewed_plan_cannot_activate(self):
        with self.assertRaises(ValueError): c.validate_grant(grant(), fixtures.original_authorization(), True, c.utc(c.APPROVED_AT).timestamp())
        g = grant(True)
        self.assertEqual(c.validate_grant(g, fixtures.original_authorization(), True, c.utc(c.APPROVED_AT).timestamp()), g)
        for when in ("2026-10-30T06:12:00Z", c.EXPIRES_AT):
            with self.subTest(when=when), self.assertRaises(ValueError): c.validate_grant(g, fixtures.original_authorization(), True, c.utc(when).timestamp())

    def test_all_source_incidental_and_queued_attempts_count_by_id(self):
        rows = history(2)
        for row in rows.values(): row.update(name="same display name", status="queued")
        result = c.count_attempts(rows, set(), grant())
        self.assertEqual(result["additionalAttemptCount"], 2)
        self.assertEqual(result["stageAttemptCount"], 44)
        self.assertTrue(result["supportedFreshNativeFirstAttempts"])

    def test_exact_boundary_1042_and_1001st_extra_refusal(self):
        result = c.count_attempts(history(1000), set(), grant())
        self.assertEqual(result["stageAttemptCount"], 1042)
        self.assertTrue(result["withinCountLimit"])
        self.assertFalse(c.count_attempts(history(1001), set(), grant())["withinCountLimit"])

    def test_native_rerun_is_charged_then_marked_unsupported(self):
        rows = history(); rid = c.PREFIX_RUN_IDS[0]; rows[rid]["run_attempt"] = 2
        result = c.count_attempts(rows, set(), grant())
        self.assertEqual(result["additionalAttemptCount"], 1)
        self.assertEqual(result["unsupportedNativeReruns"], [rid])
        self.assertFalse(result["supportedFreshNativeFirstAttempts"])

    def test_historical_attempt_one_excluded_but_reruns_are_charged(self):
        rows = history(); rid = "40616416909"
        rows[rid] = {"id": int(rid), "run_attempt": 1}
        first = c.count_attempts(rows, {rid}, grant())
        self.assertEqual(first["additionalAttemptCount"], 0)
        rows[rid]["run_attempt"] = 3
        result = c.count_attempts(rows, {rid}, grant())
        self.assertEqual(result["additionalAttemptCount"], 2)
        self.assertEqual(result["stageAttemptCount"], 44)
        self.assertEqual(result["unsupportedNativeReruns"], [rid])
        self.assertNotIn([rid, 1], result["attemptIdentities"])
        self.assertIn([rid, 2], result["attemptIdentities"])
        self.assertIn([rid, 3], result["attemptIdentities"])

    def test_missing_known_attempts_never_refund_count(self):
        g = grant(); g["bookedAdditionalAttempts"] = [{"runId": "90000000000", "nativeAttempt": 1, "runnerMinutes": 20}]
        rows = history(); rows.pop(c.PREFIX_RUN_IDS[0])
        result = c.count_attempts(rows, set(), g)
        self.assertEqual(result["stageAttemptCount"], 43)
        self.assertEqual(result["missingBookedAttempts"], [["90000000000", 1]])
        self.assertFalse(result["supportedFreshNativeFirstAttempts"])

    def test_booking_fields_and_prefix_identity_cannot_reset(self):
        g = grant(); row = {"runId": "90000000000", "nativeAttempt": 1, "runnerMinutes": 1}
        g["bookedAdditionalAttempts"] = [row, deepcopy(row)]
        with self.assertRaises(ValueError): c.validate_grant(g, fixtures.original_authorization())
        g = grant(); g["closedPrefixProducerSha256"] = "a" * 64
        with self.assertRaises(ValueError): c.validate_grant(g, fixtures.original_authorization())

    def test_no_aggregate_subtraction_refunds_prior_booked_minutes(self):
        g = grant(); g["bookedAdditionalAttempts"] = [{"runId": "90000000000", "nativeAttempt": 1, "runnerMinutes": 20}]
        result = c.validate_budget(g, g["nextExecution"], 55, 2)
        self.assertEqual(result["otherMinutesCharged"], 58)
        self.assertEqual(result["maximumNewMinutesBooked"], 58 + 45 + 1075 + 180 + 28)

    def test_reserve_only_next_phase_and_needed_followups_not_thousand_jobs(self):
        g = grant(); result = c.validate_budget(g, g["nextExecution"], 38, 0)
        self.assertEqual(result["maximumNewMinutesBooked"], 1366)
        with self.assertRaises(ValueError): c.validate_budget(g, g["nextExecution"], 2500, 0)
        with self.assertRaises(ValueError): c.validate_budget(g, g["nextExecution"], 100, 46)

    def test_first_needed_execution_cannot_skip_g_or_change_job_limits(self):
        for key, value in (("phase", "validation"), ("preparationAttempt", 4)):
            g = grant(); g["nextExecution"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): c.validate_grant(g, fixtures.original_authorization())
        g = grant(); g["nextExecution"]["reservations"]["current"] = 46
        with self.assertRaises(ValueError): c.validate_grant(g, fixtures.original_authorization())

    def test_policy_constructor_preserves_old_auth_and_binds_both_failures(self):
        base = fixtures.recovery_binding(); before = m.canonical(base)
        b = m.prepare_run_grant_binding(base, grant())
        self.assertEqual(m.canonical(base), before)
        self.assertEqual(b["preparationCorrection"]["priorFailures"], [m.FAILED_PREPARATION_PIN, m.SECOND_FAILED_PREPARATION_PIN])
        self.assertEqual(m.digest(m.canonical(b["authorization"])), c.ORIGINAL_AUTHORIZATION_SHA256)
        q = m.request_for(b, "lock-preparation", 3)
        self.assertEqual(q["priorRunPins"], [c.LAST_PREFIX_SOURCE])
        self.assertEqual(q["executionSequence"], 1)
        self.assertEqual(q["runAllowanceSha256"], c.AUTHORITY_SHA256)
        with self.assertRaises(m.Refusal): m.validate_request(q, b, True, c.utc(c.APPROVED_AT).timestamp())

    def test_reviewed_request_hash_no_circular_or_stale_approval_binding(self):
        g = grant(True); b = m.prepare_run_grant_binding(fixtures.recovery_binding(), g)
        q = m.request_for(b, "lock-preparation", 3)
        g["nextExecution"]["requestSha256"] = m.digest(m.encode(q))
        b = m.prepare_run_grant_binding(fixtures.recovery_binding(), g)
        self.assertEqual(m.validate_request(q, b, True, c.utc(c.APPROVED_AT).timestamp()), q)
        q["executionSequence"] = 2
        with self.assertRaises(m.Refusal): m.validate_request(q, b, True, c.utc(c.APPROVED_AT).timestamp())

    def test_later_needed_lock_retry_does_not_hit_obsolete_attempt_three_cap(self):
        g = grant(); p = g["nextExecution"]; p.update(sequence=2, preparationAttempt=4, reasonCode="prior_failure")
        p["priorSourceRun"] = {"runId": "90000000000", "pipelineHead": "a" * 40, "requestSha256": "b" * 64}
        b = m.prepare_run_grant_binding(fixtures.recovery_binding(), g)
        q = m.request_for(b, "lock-preparation", 4)
        self.assertEqual(q["preparationAttempt"], 4)
        self.assertEqual(q["source"]["sourceSha"], c.FIRST_SOURCE)
        self.assertEqual(m.budget(q)["maximumAdditionalWorkflowAttempts"], 1000)
        self.assertEqual(b["authorization"]["maximumLockPreparations"], 2)

    def test_legacy_contract_fixture_removes_live_grant_in_copy_only(self):
        current=m.prepare_run_grant_binding(fixtures.recovery_binding(),grant(True))
        current["baseline"]["publicProofSha256"]="dfc2cda1a2c7c5f3f4e1bc235e8a6e2aca615e62c5ce20a79102a794779770df"
        before=m.canonical(current)
        import test_source_validation_contract_v109 as legacy
        read=Path.read_bytes
        def current_view(path):
            return m.encode(current) if path.name=="ci-bindings.json" else read(path)
        suite=unittest.defaultTestLoader.loadTestsFromTestCase(legacy.PipelinePreparationRecoveryTests)
        result=unittest.TestResult()
        with patch.object(Path,"read_bytes",current_view): suite.run(result)
        self.assertTrue(result.wasSuccessful(),repr(result.failures+result.errors))
        self.assertEqual(m.canonical(current),before)


if __name__ == "__main__": unittest.main()
