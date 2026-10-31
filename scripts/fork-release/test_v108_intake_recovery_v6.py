"""Exact retained public intake evidence; no future run or candidate execution."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
try:
    SPEC = importlib.util.spec_from_file_location("v108_intake_recovery_owner", HERE / "source_validation_v108.py")
    D = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(D)
finally:
    sys.path.pop(0)
FIXTURE = HERE / "fixtures/v108-npm-intake-recovery.json"
FIXTURE_SHA256 = "b6881a07d9aed97e5066c672ab4392281f6bed42c4618e517a228b4ee895a917"
JOB_FIELDS = ("id", "run_id", "run_attempt", "head_sha", "name", "status", "conclusion",
    "runner_id", "runner_name", "runner_group_id", "runner_group_name", "labels",
    "started_at", "completed_at", "steps")


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


class IntakeRecoveryV6Tests(unittest.TestCase):
    def setUp(self):
        raw = FIXTURE.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), FIXTURE_SHA256)
        self.fixture = D._v6_json(raw)
        self.prior_raw = self.fixture["priorRequestUtf8"].encode()
        self.old = D._v6_json(self.prior_raw)
        # These are the actual closed old identities, not an invented future C.
        self.pins = copy.deepcopy(D.V6_INTAKE_RECOVERY_SOURCE_PINS)
        self.pins.update(priorValidationRuns=[copy.deepcopy(D.V6_INTAKE_RECOVERY_PRIOR_PIN)],
            sourceHops=[{key: hop[key] for key in ("sourceSha", "sourceTree")}
                for hop in self.old["sourceWitness"]["hops"]], previousSourceHopCount=1)
        self.request = copy.deepcopy(self.old)
        self.request.update(profilePolicy=D.V6_RECOVERY_POLICY, stageRound=2, lifetimeOperatorRound=10,
            priorRunIds=[*self.old["priorRunIds"], D.V6_INTAKE_RECOVERY_PRIOR_PIN["runId"]])
        self.run = copy.deepcopy(self.fixture["validationRun"])
        self.table = copy.deepcopy(self.fixture["validationJobs"])
        self.pin = copy.deepcopy(D.V6_INTAKE_RECOVERY_PRIOR_PIN)

    def refusal(self, function, *args):
        with self.assertRaises((D.V6ContractRefusal, D.release.Refusal)):
            function(*args)

    def receipt(self):
        return D._h6_failed_intake_recovery(self.table, self.run, self.pin,
            D.observed_minutes_v6(self.table, self.old))

    def preparation(self, *, run=None, jobs=None, artifacts=None):
        run = self.fixture["preparationRun"] if run is None else run
        jobs = self.fixture["preparationJobs"] if jobs is None else jobs
        artifacts = self.fixture["preparationArtifacts"] if artifacts is None else artifacts
        prefix = "/repos/" + D.REPOSITORY + "/actions/runs/" + str(run["id"])
        calls = []
        def api(route):
            calls.append(route)
            if route == prefix + "/jobs?filter=all&per_page=100": return copy.deepcopy(jobs)
            if route == prefix + "/artifacts?per_page=100": return copy.deepcopy(artifacts)
            raise AssertionError("Unexpected mocked public metadata read")
        # Only the ancestry boundary is mocked. All provider facts are retained.
        with patch.object(D, "git", return_value=b"") as ancestry:
            result = D._h6_preparation(self.pins, {str(run["id"]): run}, self.run,
                self.fixture["generationWindow"], Path("unused-mocked-ancestry-root"), api)
        ancestry.assert_called_once_with(Path("unused-mocked-ancestry-root"), "merge-base", "--is-ancestor",
            self.pins["preparation"]["pipelineHead"], self.run["head_sha"])
        self.assertEqual(len(calls), 2)
        return result

    def test_public_projection_has_exact_provenance_and_no_transport_or_private_paths(self):
        self.assertEqual(set(self.fixture), {"schema", "provenance", "validationRun",
            "validationObservedInProgress", "validationJobs", "preparationRun", "preparationJobs",
            "preparationArtifacts", "generationWindow", "priorRequestUtf8"})
        self.assertEqual(self.fixture["schema"], "openclaw.v108.npm-intake-recovery-provider.v1")
        self.assertEqual(hashlib.sha256(self.prior_raw).hexdigest(), self.pin["requestSha256"])
        self.assertEqual(self.fixture["provenance"]["priorRequestSha256"], self.pin["requestSha256"])
        self.assertEqual(self.fixture["provenance"]["generationReceiptSha256"],
            self.pins["preparation"]["generationReceiptSha256"])
        for forbidden in ("https://", "http://", "/Users/", "X-Goog-", "Bearer "):
            self.assertNotIn(forbidden, FIXTURE.read_text())

    def test_actual_preparation_and_validation_roles_are_distinct(self):
        prep = self.fixture["preparationRun"]
        self.assertEqual(prep["display_title"], D.V6_PREPARATION_TITLE)
        self.assertNotEqual(prep["display_title"], D.CAMPAIGN)
        for run in (self.run, self.fixture["validationObservedInProgress"], prep):
            D._h6_expected_run_role_binding(str(run["id"]), run, self.pins)
        self.refusal(D._h6_source_run_binding, prep)
        self.refusal(D._h6_preparation_run_binding, self.run, self.pins["preparation"])

    def test_wrong_role_identity_title_pr_head_and_repository_are_refused(self):
        prep = self.fixture["preparationRun"]
        changes = (("id", prep["id"] + 1), ("display_title", D.CAMPAIGN),
            ("head_sha", "0" * 40), ("pull_requests", [{"number": 27}]),
            ("run_attempt", 2), ("repository", {"full_name": D.REPOSITORY, "private": True}))
        for key, value in changes:
            with self.subTest(role="preparation", key=key):
                run = copy.deepcopy(prep); run[key] = value
                self.refusal(D._h6_expected_run_role_binding, str(prep["id"]), run, self.pins)
        for key, value in (("display_title", D.V6_PREPARATION_TITLE),
                ("pull_requests", []), ("head_branch", "other"), ("event", "push")):
            with self.subTest(role="validation", key=key):
                run = copy.deepcopy(self.run); run[key] = value
                self.refusal(D._h6_expected_run_role_binding, str(self.run["id"]), run, self.pins)

    def test_actual_preparation_job_and_artifact_remain_derivation_only(self):
        minutes, receipt = self.preparation()
        self.assertGreater(minutes, 0)
        self.assertLessEqual(minutes, 45)
        self.assertEqual(receipt["runId"], self.pins["preparation"]["runId"])
        self.assertEqual(receipt["artifactSha256"], self.pins["preparation"]["artifactSha256"])
        self.assertEqual(receipt["status"], "derived_only")
        self.assertFalse(receipt["currentCandidateQualification"])

    def test_wrong_preparation_job_or_artifact_is_not_accepted_as_derivation(self):
        for key, value in (("runner_id", None), ("name", "source (dependency)")):
            jobs = copy.deepcopy(self.fixture["preparationJobs"])
            jobs["jobs"][0][key] = value
            with self.subTest(job=key): self.refusal(lambda: self.preparation(jobs=jobs))
        for key, value in (("digest", "sha256:" + "0" * 64), ("expired", True), ("id", 1)):
            artifacts = copy.deepcopy(self.fixture["preparationArtifacts"])
            artifacts["artifacts"][0][key] = value
            with self.subTest(artifact=key): self.refusal(lambda: self.preparation(artifacts=artifacts))

    def test_actual_failed_intake_has_three_positive_rows_and_five_minutes(self):
        self.assertEqual(D.observed_minutes_v6(self.table, self.old), 5)
        receipt = self.receipt()
        self.assertTrue(receipt["validationNeverStarted"])
        self.assertEqual(receipt["sourceJobsAcquired"], 0)
        self.assertEqual(receipt["profileResults"], {})
        self.assertEqual(receipt["unresolvedProfiles"], list(D.V6_PROFILES))
        self.assertFalse(receipt["oldF5EvidenceUsed"])
        self.assertEqual(receipt["failedIntakeJobProjectionSha256"], D.V6_INTAKE_RECOVERY_JOB_PROJECTION_SHA256)
        skipped = [job for job in self.table["jobs"] if job["name"] != "admission"]
        self.assertEqual(len(skipped), 2)
        for job in skipped:
            self.assertIsNone(job["runner_id"])
            self.assertIsNone(job["runner_name"])
            self.assertIsNone(job["runner_group_name"])
            self.assertEqual(job["steps"], [])
            self.assertEqual(job["labels"], ["ubuntu-24.04"])

    def test_exact_actual_job_projection_hash_is_reconstructed(self):
        projection = {"total_count": self.table["total_count"], "jobs": sorted(
            [{key: job[key] for key in JOB_FIELDS} for job in self.table["jobs"]], key=lambda job: job["id"])}
        self.assertEqual(hashlib.sha256(encoded(projection)).hexdigest(), D.V6_INTAKE_RECOVERY_JOB_PROJECTION_SHA256)

    def test_skipped_runner_steps_labels_or_missing_positive_fields_refuse(self):
        original = copy.deepcopy(self.table)
        mutations = (("runner_id", 1), ("runner_name", "unexpected"),
            ("runner_group_name", "GitHub Actions"), ("steps", [{"conclusion": "success"}]),
            ("labels", []), ("started_at", None))
        for key, value in mutations:
            with self.subTest(change=key):
                self.table = copy.deepcopy(original)
                self.table["jobs"][1][key] = value
                self.refusal(self.receipt)
        for key in ("runner_id", "steps", "runner_group_id", "head_sha"):
            with self.subTest(missing=key):
                self.table = copy.deepcopy(original)
                del self.table["jobs"][1][key]
                self.refusal(self.receipt)

    def test_deleted_duplicated_or_unexpanded_rows_cannot_infer_no_coverage(self):
        original = copy.deepcopy(self.table)
        for mutation in ("delete", "duplicate", "declared-count", "expanded"):
            self.table = copy.deepcopy(original)
            if mutation == "delete": self.table["jobs"].pop()
            elif mutation == "duplicate": self.table["jobs"][1] = copy.deepcopy(self.table["jobs"][2])
            elif mutation == "declared-count": self.table["total_count"] = 2
            else: self.table["jobs"][1]["name"] = "source (dependency)"
            with self.subTest(mutation=mutation): self.refusal(self.receipt)

    def test_other_prior_run_head_request_or_status_cannot_claim_recovery(self):
        for key, value in (("id", self.run["id"] + 1), ("head_sha", "0" * 40),
                ("status", "in_progress"), ("conclusion", "success")):
            with self.subTest(run=key):
                altered = copy.deepcopy(self.run); altered[key] = value
                self.refusal(D._h6_failed_intake_recovery, self.table, altered, self.pin, 5)
        for key in ("runId", "pipelineHead", "requestSha256"):
            with self.subTest(pin=key):
                pin = copy.deepcopy(self.pin); pin[key] = "1" + pin[key][1:]
                self.refusal(D._h6_failed_intake_recovery, self.table, self.run, pin, 5)

    def test_exact_same_source_full_fifteen_recovery_is_admitted(self):
        self.assertIs(D.validate_request_v6(self.request, self.pins), self.request)
        self.assertEqual(self.request["stageRound"], 2)
        self.assertEqual(self.request["lifetimeOperatorRound"], 10)
        self.assertEqual(self.request["profiles"], list(D.V6_PROFILES))
        self.assertEqual(D.validation_budget_v6(self.request)["roundMaximumMinutes"], 1015)
        old_pins = dict(self.pins, priorValidationRuns=[], previousSourceHopCount=0)
        self.assertIs(D.validate_request_v6(self.old, old_pins), self.old)

    def test_generic_target_still_has_original_two_hundred_minute_limit(self):
        generic = dict(self.request, profilePolicy=D.V6_POLICY, profiles=["types-tests"])
        self.assertIs(D.validate_request_v6(generic, self.pins), generic)
        self.assertEqual(D.validation_budget_v6(generic)["roundMaximumMinutes"], 200)
        generic["profiles"] = list(D.V6_PROFILES)
        self.refusal(D.validate_request_v6, generic, self.pins)
        self.assertEqual(D.V6_TARGETED_MINUTES, 200)

    def test_source_metadata_preparation_or_witness_change_refuses_even_when_self_consistent(self):
        for key in ("sourceSha", "sourceTree", "manifestSha256", "inventorySha256"):
            with self.subTest(key=key):
                request, pins = copy.deepcopy(self.request), copy.deepcopy(self.pins)
                changed = "0" * len(pins[key]); request[key] = pins[key] = changed
                if key in ("sourceSha", "sourceTree"):
                    pins["sourceHops"][0][key] = changed
                    request["sourceWitness"]["hops"][0][key] = changed
                self.refusal(D.validate_request_v6, request, pins)
        request, pins = copy.deepcopy(self.request), copy.deepcopy(self.pins)
        pins["preparation"]["artifactSha256"] = "0" * 64
        request["lockPreparation"] = copy.deepcopy(pins["preparation"])
        self.refusal(D.validate_request_v6, request, pins)
        request = copy.deepcopy(self.request)
        request["sourceWitness"]["hops"][0]["step"]["unchangedTreeSha256"] = "0" * 64
        self.refusal(D.validate_request_v6, request, self.pins)

    def test_prior_identity_round_lifetime_and_profile_expansion_are_closed(self):
        for key, value in (("stageRound", 1), ("stageRound", 3), ("stageRound", True),
                ("lifetimeOperatorRound", 11), ("profiles", ["types-tests"]),
                ("profiles", list(reversed(D.V6_PROFILES))),
                ("profiles", [*D.V6_PROFILES[:-1], "not-approved"]),
                ("profiles", [*D.V6_PROFILES, D.V6_PROFILES[0]])):
            with self.subTest(key=key, value=value):
                request = copy.deepcopy(self.request); request[key] = value
                self.refusal(D.validate_request_v6, request, self.pins)
        for key in ("runId", "pipelineHead", "requestSha256"):
            request, pins = copy.deepcopy(self.request), copy.deepcopy(self.pins)
            pins["priorValidationRuns"][0][key] = "1" + pins["priorValidationRuns"][0][key][1:]
            if key == "runId": request["priorRunIds"][-1] = pins["priorValidationRuns"][0][key]
            with self.subTest(prior=key): self.refusal(D.validate_request_v6, request, pins)

    def test_actual_and_worst_case_accounting_preserves_all_spent_minutes(self):
        prep_minutes, _ = self.preparation()
        actual = D.booking_v6(self.request, prep_minutes, 5, 0)
        self.assertEqual(actual["priorValidationObservedMinutes"], 5)
        self.assertEqual(actual["currentRoundBookedMinutes"], 1015)
        self.assertEqual(actual["newStageBookedMinutes"], prep_minutes + 5 + 1015 + 77)
        worst = D.booking_v6(self.request, 45, 5, 77)
        self.assertEqual(worst["newStageBookedMinutes"], 1142)
        self.assertEqual(worst["bookedRunnerMinutes"], 1237 + 1142)
        self.assertLess(worst["newStageBookedMinutes"], D.V6_NEW_MINUTES)
        self.assertFalse(worst["currentSourceCoverageReusedFromF5"])
        self.assertEqual(worst["futureTargetedReserveMinutes"], 0)

    def test_recovery_requires_actual_five_not_refunded_zero_or_generic_target_minutes(self):
        for prior in (0, 4, 6, True, 1015):
            with self.subTest(prior=prior): self.refusal(D.booking_v6, self.request, 45, prior, 0)
        for prep, ancillary in ((46, 0), (45, 78), (True, 0)):
            with self.subTest(prep=prep, ancillary=ancillary):
                self.refusal(D.booking_v6, self.request, prep, 5, ancillary)


if __name__ == "__main__":
    unittest.main()
