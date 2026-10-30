"""Pure supplemental-recovery tests. Synthetic approvals are never persisted."""
from copy import deepcopy
from pathlib import Path
import unittest
from unittest.mock import patch

import test_source_validation_contract_v109 as fixtures

m = fixtures.m


def original_authorization():
    return {"schema": m.AUTH_SCHEMA, "label": "future-v109-grouped-20261030T031421Z",
        "approvedAt": "2026-10-30T03:14:21Z", "expiresAt": "2026-11-03T03:14:21Z",
        "maximumRunnerMinutes": 2500, "maximumSourceCampaigns": 2,
        "maximumParallelSourceJobs": 3, "maximumLockPreparations": 2,
        "diagnosticByteCeiling": 67108864, "lockArtifactByteCeiling": 2097152,
        "imageExecutionAllowedHere": False, "cloudAccessAllowedHere": False,
        "newSecretsAllowedHere": False}


def approval(approved=False):
    return {"schema": m.ADDITIONAL_APPROVAL_SCHEMA,
        "status": "APPROVED_RECOVERY" if approved else "DISARMED",
        "approvalEvidenceSha256": "f" * 64 if approved else None,
        "approvedAt": "2026-10-30T06:00:00Z" if approved else None,
        "expiresAt": "2026-11-03T03:14:21Z",
        "originalAuthorizationSha256": m.ORIGINAL_AUTHORIZATION_SHA256,
        "additionalPipelineCorrections": 1, "additionalLockPreparations": 1,
        "additionalSourceCampaigns": 0, "optionalCorrectionsAllowed": False}


def recovery_binding(approved=False):
    b = fixtures.binding()
    if approved:
        b["status"] = "APPROVED_CI"  # Synthetic in-memory example only.
    raw = (Path(__file__).parent / m.PREPARATION_FAILURE_EVIDENCE.split("scripts/fork-release/", 1)[1]).read_bytes()
    b["preparation"] = m.parse(raw)["source"]
    b["authorization"] = original_authorization()
    b["preparationCorrection"] = {"schema": m.ADDITIONAL_PIPELINE_RECOVERY_SCHEMA,
        "source": deepcopy(b["preparation"]), "priorPhase": "lock-preparation",
        "priorFailures": [deepcopy(m.FAILED_PREPARATION_PIN), deepcopy(m.SECOND_FAILED_PREPARATION_PIN)],
        "failedPreparationAttempts": [1, 2], "nextPreparationAttempt": 3,
        "evidenceSha256": {"1": m.PREPARATION_FAILURE_EVIDENCE_SHA256,
            "2": m.ADDITIONAL_PREPARATION_FAILURE_EVIDENCE_SHA256}, "approval": approval(approved)}
    return b


class ThirdPreparationContractTests(unittest.TestCase):
    def test_disarmed_interface_has_no_approval_or_request(self):
        b = recovery_binding()
        self.assertEqual(m.validate_bindings(b), b)
        self.assertIsNone(b["preparationCorrection"]["approval"]["approvedAt"])
        with self.assertRaisesRegex(m.Refusal, "new_approval_required"):
            m.request_for(b, "lock-preparation", 3)
        with self.assertRaises(m.Refusal):
            m.validate_bindings(b, active=True, now=m.utc("2026-10-30T06:00:00Z").timestamp())

    def test_synthetic_new_approval_selects_only_third_native_first_attempt(self):
        b = recovery_binding(True)
        before = m.canonical(b["authorization"])
        q = m.request_for(b, "lock-preparation", 3)
        self.assertEqual(q["preparationAttempt"], 3)
        self.assertEqual(q["source"], b["preparation"])
        self.assertIsNone(q["generation"])
        self.assertEqual(q["priorRunPins"], [m.FAILED_PREPARATION_PIN, m.SECOND_FAILED_PREPARATION_PIN])
        self.assertEqual(q["authorizationSha256"], m.ORIGINAL_AUTHORIZATION_SHA256)
        self.assertEqual(m.canonical(b["authorization"]), before)
        self.assertEqual(m.validate_request(q, b), q)
        # Native attempt1 is independently fixed by the unchanged hosted gate.
        self.assertNotIn("nativeRunAttempt", q)

    def test_old_approval_or_old_time_cannot_enable_extra_count(self):
        for digest in (m.ORIGINAL_AUTHORIZATION_SHA256, m.ORIGINAL_APPROVAL_PACKET_SHA256):
            b = recovery_binding(True); b["preparationCorrection"]["approval"]["approvalEvidenceSha256"] = digest
            with self.subTest(digest=digest), self.assertRaisesRegex(m.Refusal, "genuine_new_approval"):
                m.validate_bindings(b)
        b = recovery_binding(True)
        b["preparationCorrection"]["approval"]["approvedAt"] = m.ADDITIONAL_RECOVERY_NOT_BEFORE
        with self.assertRaisesRegex(m.Refusal, "after_both_failures"):
            m.validate_bindings(b)

    def test_original_clock_and_caps_cannot_be_rewritten(self):
        for key, value in (("maximumLockPreparations", 3), ("maximumRunnerMinutes", 2501),
                ("expiresAt", "2026-11-04T03:14:21Z")):
            b = recovery_binding(True); b["authorization"][key] = value
            with self.subTest(key=key), self.assertRaises(m.Refusal):
                m.validate_bindings(b)
        b = recovery_binding(True); b["preparationCorrection"]["approval"]["expiresAt"] = "2026-11-04T03:14:21Z"
        with self.assertRaises(m.Refusal): m.validate_bindings(b)

    def test_no_extra_source_campaign_correction_or_attempt_four(self):
        b = recovery_binding(True)
        for phase, attempt in (("lock-preparation", 1), ("lock-preparation", 2),
                ("lock-preparation", 4), ("correction", 3)):
            with self.subTest(phase=phase, attempt=attempt), self.assertRaises(m.Refusal):
                m.request_for(b, phase, attempt)
        for key, value in (("additionalSourceCampaigns", 1), ("optionalCorrectionsAllowed", True),
                ("additionalLockPreparations", 2)):
            changed = deepcopy(b); changed["preparationCorrection"]["approval"][key] = value
            with self.subTest(key=key), self.assertRaises(m.Refusal): m.validate_bindings(changed)

    def test_both_exact_prior_failures_are_required(self):
        b = recovery_binding(True)
        for transform in (lambda p: p.pop(), lambda p: p.reverse(),
                lambda p: p[1].update(runId="41003661032")):
            changed = deepcopy(b); transform(changed["preparationCorrection"]["priorFailures"])
            with self.assertRaises(m.Refusal): m.validate_bindings(changed)
        changed = deepcopy(b); changed["preparationCorrection"]["failedPreparationAttempts"] = [True, 2]
        with self.assertRaises(m.Refusal): m.validate_bindings(changed)

    def test_actual_failure_witnesses_are_factual_not_authority(self):
        b = recovery_binding()
        root = Path(__file__).parent
        raw = [(root / p.split("scripts/fork-release/", 1)[1]).read_bytes() for p in
            (m.PREPARATION_FAILURE_EVIDENCE, m.ADDITIONAL_PREPARATION_FAILURE_EVIDENCE)]
        proofs = m.validate_additional_pipeline_recovery_evidence(*raw, b)
        self.assertEqual([p["preparationAttempt"] for p in proofs], [1, 2])
        self.assertEqual([p["artifactCount"] for p in proofs], [0, 0])
        self.assertTrue(all(p["generationProduced"] is False for p in proofs))
        with self.assertRaisesRegex(m.Refusal, "new_approval_required"):
            m.request_for(b, "lock-preparation", 3)
        for i in range(2):
            changed = list(raw); changed[i] += b" "
            with self.subTest(witness=i), self.assertRaises(m.Refusal):
                m.validate_additional_pipeline_recovery_evidence(*changed, b)

    def test_budget_counts_only_one_future_validation_and_preserves_family90(self):
        b = recovery_binding(True); q = m.request_for(b, "lock-preparation", 3); budget = m.budget(q)
        self.assertEqual(budget["maximumLockPreparations"], 3)
        self.assertEqual(budget["maximumSourceCampaigns"], 1)
        self.assertEqual(budget["preparationFamilyMinutes"], 90)
        self.assertEqual(budget["maximumNewMinutes"], 2500)
        self.assertEqual(budget["phaseMaximumMinutes"], 45)
        self.assertLessEqual(16 + budget["phaseMaximumMinutes"], budget["preparationFamilyMinutes"])
        self.assertEqual(b["authorization"]["maximumLockPreparations"], 2)

    def test_new_approval_clock_is_bounded_without_reset(self):
        b = recovery_binding(True); b["status"] = "APPROVED_CI"
        self.assertEqual(m.validate_bindings(b, active=True,
            now=m.utc("2026-10-30T06:00:00Z").timestamp()), b)
        for when in ("2026-10-30T05:59:59Z", "2026-11-03T03:14:21Z"):
            with self.subTest(when=when), self.assertRaises(m.Refusal):
                m.validate_bindings(b, active=True, now=m.utc(when).timestamp())

    def test_source_pin_or_witness_cannot_be_substituted(self):
        b = recovery_binding(True); b["preparation"]["sourceSha"] = "a" * 40
        b["preparationCorrection"]["source"] = deepcopy(b["preparation"])
        with self.assertRaises(m.Refusal): m.validate_bindings(b)
        b = recovery_binding(True); b["preparationCorrection"]["evidenceSha256"]["2"] = "a" * 64
        with self.assertRaises(m.Refusal): m.validate_bindings(b)

    def test_third_generated_source_uses_g_directly_in_synthetic_model(self):
        # Entirely in-memory Git model: no commit, H or receipt is published.
        from test_source_derivation_v109 import repository
        factory = fixtures.source
        def synthetic_source(sha="a", tree="b"):
            value = factory(sha, tree)
            if sha == "a":
                value["sourceSha"] = m.ORIGINAL_RECOVERY_SOURCE_SHA
            return value
        with patch.object(fixtures, "source", synthetic_source):
            b, files, read, trees, gate, entries, content, parents = repository()
        b["status"] = "APPROVED_CI"; b["authorization"] = original_authorization()
        b["preparationCorrection"] = deepcopy(recovery_binding(True)["preparationCorrection"])
        b["preparationCorrection"]["source"] = deepcopy(b["preparation"])
        b["validation"]["preparationAttempt"] = 3
        proof = m.verify_derived_source(read, b, "validation", files["generation.json"],
            read_tree=trees, verify_lock=gate)
        self.assertEqual(proof["preparationAttempt"], 3)
        self.assertEqual(proof["preparationSource"], m.ORIGINAL_RECOVERY_SOURCE_SHA)
        self.assertFalse(proof["sourceCorrectionVerified"])
        q = m.request_for(b, "validation")
        self.assertEqual(q["preparationAttempt"], 3)
        self.assertEqual(m.budget(q)["maximumSourceCampaigns"], 1)
        # App change and non-G parent remain fail-closed for this new branch.
        h = b["validation"]["source"]["sourceSha"]
        parents[h] = ["a" * 40]
        with self.assertRaisesRegex(m.Refusal, "single_generated_source_parent"):
            m.verify_derived_source(read, b, "validation", files["generation.json"],
                read_tree=trees, verify_lock=gate)

    def test_third_validation_cannot_claim_an_earlier_generation(self):
        b = recovery_binding(True)
        b["validation"] = fixtures.populated()[0]["validation"]
        for attempt in (1, 2):
            b["validation"]["preparationAttempt"] = attempt
            with self.subTest(attempt=attempt), self.assertRaises(m.Refusal):
                m.validate_bindings(b)

    def test_legacy_contract_suite_is_isolated_from_current_supplemental_binding(self):
        current=recovery_binding(True)
        current["baseline"]["publicProofSha256"]="dfc2cda1a2c7c5f3f4e1bc235e8a6e2aca615e62c5ce20a79102a794779770df"
        before=m.canonical(current)
        read=Path.read_bytes
        def synthetic_current(path):
            return m.encode(current) if path.name=="ci-bindings.json" else read(path)
        suite=unittest.defaultTestLoader.loadTestsFromTestCase(fixtures.PipelinePreparationRecoveryTests)
        result=unittest.TestResult()
        with patch.object(Path,"read_bytes",synthetic_current):
            suite.run(result)
        self.assertTrue(result.wasSuccessful(),repr(result.errors+result.failures))
        self.assertGreater(result.testsRun,0)
        self.assertEqual(m.canonical(current),before)
        self.assertTrue(m.additional_pipeline_preparation_recovery(current["preparationCorrection"]))


if __name__ == "__main__":
    unittest.main()
