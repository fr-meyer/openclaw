"""V6 metadata/accounting synthetics; all API and Git calls are inert fixtures."""
import copy
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_request_contract_v6 import D, Fixture, STAGE, digest, encoded, oid

HERE = Path(__file__).resolve().parent
NOW = datetime(2026, 10, 29, 1, 5, tzinfo=timezone.utc)
REPOSITORY = {"full_name": "fr-meyer/openclaw", "private": False}


def actual_baseline_inputs():
    if (HERE / "source_validation_v108.py").exists():
        from historical_v5_test_inputs import p7_input
        return ((HERE.parents[1] / D.V6_SETTLED_USAGE_PATH).read_bytes(), p7_input("settled-usage.json"))
    return ((STAGE / "npm-activation-r1/reconciliation-r2/CLOSED-168-BASELINE.private.json").read_bytes(),
        (STAGE / "CLOSED-141-BASELINE.private.json").read_bytes())


def headers_from_actual_rows(raw):
    # These are a local counterpart of the retained header data, not fresh API
    # evidence. Actual runtime admission obtains public/run/PR fields from GitHub.
    result = {}
    for row in json.loads(raw)["runs"]:
        value = {key: row[key] for key in D.V6_PROVIDER_HEADERS}
        value.update(repository=REPOSITORY, head_repository=REPOSITORY,
            display_title=D.CAMPAIGN, pull_requests=[{"number": 28}])
        result[str(row["id"])] = value
    return result


def run(rid, head, path, status="completed", conclusion="success", branch=None):
    return {"id": int(rid), "name": "synthetic source workflow", "path": path, "event": "pull_request",
        "head_branch": D.BRANCH if branch is None else branch, "head_sha": head, "run_attempt": 1,
        "status": status, "conclusion": conclusion, "created_at": "2026-10-29T01:00:00Z",
        "updated_at": "2026-10-29T01:02:00Z", "html_url": "https://github.com/fr-meyer/openclaw/actions/runs/" + str(rid),
        "repository": REPOSITORY, "head_repository": REPOSITORY, "display_title": D.CAMPAIGN,
        "pull_requests": [{"number": 28}]}


def job(rid, head, name="lock-preparation", status="completed", conclusion="success", minutes=1):
    start = datetime(2026, 10, 29, 1, 0, tzinfo=timezone.utc)
    return {"id": int(rid) + 1000, "run_id": int(rid), "head_sha": head, "run_attempt": 1, "name": name,
        "status": status, "conclusion": conclusion, "runner_id": 42, "runner_name": "synthetic-hosted",
        "runner_group_name": "GitHub Actions", "labels": ["ubuntu-24.04"], "steps": [{"name": "synthetic"}],
        "started_at": start.isoformat().replace("+00:00", "Z"),
        "completed_at": (start + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z") if status == "completed" else None}


class HistoryFixture:
    def __init__(self, root):
        self.f = Fixture()
        self.root = root
        self.baseline, self.previous = actual_baseline_inputs()
        self.rows = headers_from_actual_rows(self.baseline)
        self.prep = run(self.f.pins["preparation"]["runId"], self.f.pins["preparation"]["pipelineHead"], D.WORKFLOW)
        self.current = run("93000000002", oid("current full pipeline"), D.WORKFLOW, "in_progress", None)
        self.current.update(created_at="2026-10-29T01:03:00Z", updated_at="2026-10-29T01:04:00Z")
        self.rows[str(self.prep["id"])] = self.prep
        self.rows[str(self.current["id"])] = self.current
        self.prep_job = job(self.prep["id"], self.prep["head_sha"])
        self.admission_job = job(self.current["id"], self.current["head_sha"], "admission", "in_progress", None)
        self.admission_job["started_at"] = "2026-10-29T01:04:50Z"
        self.artifact = {"id": self.f.pins["preparation"]["artifactId"], "name": "v108-npm-lock-preparation",
            "size_in_bytes": 1000, "expired": False, "digest": "sha256:" + self.f.pins["preparation"]["artifactSha256"]}
        self.event = {"action": "synchronize", "number": 28, "repository": REPOSITORY,
            "pull_request": {"number": 28, "state": "open", "draft": True,
                "head": {"ref": D.BRANCH, "sha": self.current["head_sha"], "repo": REPOSITORY},
                "base": {"ref": D.BASE_BRANCH, "sha": D.BASE, "repo": REPOSITORY}}}
        self.env = {"GITHUB_ACTIONS": "true", "RUNNER_OS": "Linux", "RUNNER_ENVIRONMENT": "github-hosted",
            "GITHUB_EVENT_NAME": "pull_request", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_REPOSITORY": D.REPOSITORY,
            "GITHUB_REF": "refs/pull/28/merge", "GITHUB_WORKFLOW_REF": D.REPOSITORY + "/" + D.WORKFLOW + "@refs/pull/28/merge",
            "GITHUB_WORKFLOW_SHA": oid("current merge"), "GITHUB_RUN_ID": str(self.current["id"])}
        source_workflow = (STAGE / "pipeline" / D.WORKFLOW).read_bytes() if not (HERE / "source_validation_v108.py").exists() else None
        if source_workflow is None:
            from historical_v5_test_inputs import p7_input
            source_workflow = p7_input("workflow")
        self.workflow = source_workflow.replace(D.V6_BASE_SOURCE.encode(), self.f.current.encode())
        for path, raw in ((D.V6_SETTLED_USAGE_PATH, self.baseline), (D.V6_PREPARATION_PROOF_PATH, encoded(self.f.generation)),
                (D.WORKFLOW, self.workflow)):
            file = root / path
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(raw)
        self.calls = []
        self.now = NOW
        self.prior_request = None
        self.prior_jobs = None

    def targeted(self, failed=("types-tests", "compatibility")):
        self.prior_request = encoded(self.f.request)
        self.f.targeted()
        prior = self.f.pins["priorValidationRuns"][0]
        prior["requestSha256"] = digest(self.prior_request)
        full = run(prior["runId"], prior["pipelineHead"], D.WORKFLOW, conclusion="failure" if failed else "success")
        full.update(created_at="2026-10-29T01:03:00Z", updated_at="2026-10-29T01:10:00Z")
        self.rows[prior["runId"]] = full
        self.current.update(created_at="2026-10-29T01:11:00Z", updated_at="2026-10-29T01:11:50Z")
        self.admission_job["started_at"] = "2026-10-29T01:11:50Z"
        self.now = datetime(2026, 10, 29, 1, 12, tzinfo=timezone.utc)
        jobs = []
        for index, name in enumerate(["admission", *["source (" + profile + ")" for profile in D.V6_PROFILES], "final"]):
            item = job(prior["runId"], prior["pipelineHead"], name)
            item["id"] += index
            minute = 3 if name == "admission" else 9 if name == "final" else 4 + (index - 1) // 3
            start = datetime(2026, 10, 29, 1, minute, tzinfo=timezone.utc)
            item.update(started_at=start.isoformat().replace("+00:00", "Z"),
                completed_at=(start + timedelta(minutes=1)).isoformat().replace("+00:00", "Z"))
            if name[8:-1] in failed:
                item["conclusion"] = "failure"
            jobs.append(item)
        self.prior_jobs = {"total_count": len(jobs), "jobs": jobs}

    def api(self, route):
        self.calls.append(route)
        if route.endswith("/pulls/28"): return self.event["pull_request"]
        if route.endswith("/git/ref/heads/" + D.BASE_BRANCH):
            return {"ref": "refs/heads/" + D.BASE_BRANCH, "object": {"type": "commit", "sha": D.TARGET_BRANCH_TIP}}
        if route.endswith("/git/ref/heads/" + D.V6_SOURCE_BRANCH):
            return {"ref": "refs/heads/" + D.V6_SOURCE_BRANCH, "object": {"type": "commit", "sha": self.f.current}}
        if route.endswith("/actions/runs/" + str(self.prep["id"]) + "/jobs?filter=all&per_page=100"):
            return {"total_count": 1, "jobs": [self.prep_job]}
        if route.endswith("/actions/runs/" + str(self.current["id"]) + "/jobs?filter=all&per_page=100"):
            return {"total_count": 1, "jobs": [self.admission_job]}
        if self.prior_request is not None:
            prior = self.f.pins["priorValidationRuns"][0]
            if route.endswith("/actions/runs/" + prior["runId"] + "/jobs?filter=all&per_page=100"):
                return self.prior_jobs
            if route.endswith("/contents/" + D.REQUEST + "?ref=" + prior["pipelineHead"]):
                return {"type": "file", "encoding": "base64", "size": len(self.prior_request),
                    "content": base64.b64encode(self.prior_request).decode()}
            if route.endswith("/contents/" + D.WORKFLOW + "?ref=" + prior["pipelineHead"]):
                return {"type": "file", "encoding": "base64", "size": len(self.workflow),
                    "content": base64.b64encode(self.workflow).decode()}
        if "/artifacts?per_page=100" in route:
            return {"total_count": 1, "artifacts": [self.artifact]} if "/" + str(self.prep["id"]) + "/" in route else {"total_count": 0, "artifacts": []}
        raise AssertionError("Unexpected synthetic API route")

    def git(self, pipeline, *args):
        if args == ("show", D.V6_PREVIOUS_PIPELINE + ":" + D.V5_SETTLED_USAGE_PATH): return self.previous
        if args[:2] == ("merge-base", "--is-ancestor"): return b""
        raise AssertionError("Unexpected synthetic Git route")

    def check(self):
        with patch.object(D, "_h6_branch_history", return_value=self.rows), patch.object(D, "git", side_effect=self.git), \
                patch.object(D, "datetime", wraps=datetime) as clock:
            clock.now.return_value = self.now
            with patch.object(D, "V6_PREVIOUS_PACKAGE_SHA256", digest(self.f.package_old)), \
                    patch.object(D, "V6_PREVIOUS_LOCK_SHA256", digest(self.f.lock_old)):
                return D.history_checks_v6(self.f.request, self.event, self.env, self.root, self.api, self.f.pins)


class HistoryV6Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="v6-history-no-network-")
        self.addCleanup(self.tmp.cleanup)
        self.f = HistoryFixture(Path(self.tmp.name))

    def test_actual_authenticated168_remeasures1237_and_preserves_old141(self):
        baseline, ids, _ = D.validate_closed_baseline_v6(self.f.baseline,
            lambda *args: self.f.git(self.f.root, *args), self.f.rows)
        self.assertEqual(len(ids), 168)
        self.assertEqual(baseline["runnerMinutesObserved"], 1237)
        self.assertEqual(digest(self.f.baseline), D.V6_BASELINE_SHA256)

    def test_fresh_full_admission_counts_preparation_separately_and_reuses_no_old_passes(self):
        result = self.f.check()
        self.assertEqual(len(result["profileMatrix"]), 15)
        self.assertEqual(result["currentRoundBookedMinutes"], 1015)
        self.assertEqual(result["preparationObservedMinutes"], 1)
        self.assertEqual(result["futureTargetedReserveMinutes"], 200)
        self.assertEqual(result["newStageBookedMinutes"], 1293)
        self.assertEqual(result["bookedRunnerMinutes"], 2530)
        self.assertFalse(result["preparationReceipt"]["currentCandidateQualification"])
        self.assertEqual(result["reusedProfileCount"], 0)
        self.assertFalse(result["historicalCoverageReused"])
        self.assertEqual(result["priorUnresolvedProfiles"], list(D.V6_PROFILES))

    def test_closed_provider_header_drift_refuses_without_more_calls(self):
        self.f.rows[D.V6_PRIOR_SOURCE_IDS[0]]["updated_at"] = "2026-10-29T01:01:00Z"
        with self.assertRaisesRegex(D.V6ContractRefusal, "baseline_header_changed"): self.f.check()
        self.assertFalse(any("/jobs?" in route for route in self.f.calls))

    def test_missing_preparation_unknown_source_run_and_rerun_refuse(self):
        for mutation in ("missing", "unknown", "rerun"):
            with self.subTest(mutation=mutation):
                self.f = HistoryFixture(Path(self.tmp.name))
                if mutation == "missing": self.f.rows.pop(str(self.f.prep["id"]))
                elif mutation == "unknown": self.f.rows["99999999999"] = run("99999999999", oid("unknown"), D.WORKFLOW)
                else: self.f.rows[str(self.f.prep["id"])]["run_attempt"] = 2
                with self.assertRaises(D.V6ContractRefusal): self.f.check()

    def test_preparation_is_positive_single_successful_standard_runner_job(self):
        for mutation in ("failed", "name", "runner", "over45", "private"):
            with self.subTest(mutation=mutation):
                self.f = HistoryFixture(Path(self.tmp.name))
                if mutation == "failed": self.f.prep["conclusion"] = "failure"
                elif mutation == "name": self.f.prep_job["name"] = "source (dependency)"
                elif mutation == "runner": self.f.prep_job["labels"] = ["self-hosted"]
                elif mutation == "over45": self.f.prep_job["completed_at"] = "2026-10-29T01:46:00Z"
                else: self.f.prep["repository"] = dict(REPOSITORY, private=True)
                with self.assertRaises((D.V6ContractRefusal, D.release.Refusal)): self.f.check()

    def test_artifact_identity_digest_expiry_missing_and_size_fail_closed(self):
        for field, value in (("id", True), ("name", "other"), ("digest", "sha256:" + "f" * 64),
                ("expired", True), ("size_in_bytes", 2 * 1024 * 1024 + 1)):
            with self.subTest(field=field):
                self.f = HistoryFixture(Path(self.tmp.name))
                self.f.artifact[field] = value
                with self.assertRaises(D.V6ContractRefusal): self.f.check()

    def test_current_job_context_and_positive_acquisition_required(self):
        for mutation in ("head", "queued", "runner", "unknownjob"):
            with self.subTest(mutation=mutation):
                self.f = HistoryFixture(Path(self.tmp.name))
                if mutation == "head": self.f.current["head_sha"] = oid("changed current head")
                elif mutation == "queued": self.f.admission_job["status"] = "queued"
                elif mutation == "runner": self.f.admission_job["runner_id"] = None
                else: self.f.admission_job["name"] = "unbounded-build"
                with self.assertRaises((D.V6ContractRefusal, D.release.Refusal)): self.f.check()

    def test_branch_pagination_covers_both_controlled_branches_and_refuses_duplicates(self):
        calls = []
        first = {"id": 1, **{key: None for key in D.V6_PROVIDER_HEADERS if key != "id"}}
        second = {"id": 2, **{key: None for key in D.V6_PROVIDER_HEADERS if key != "id"}}
        def api(route):
            calls.append(route)
            return {"total_count": 1, "workflow_runs": [first if "task%2F" in route else second]}
        self.assertEqual(set(D._h6_branch_history(api)), {"1", "2"})
        self.assertEqual(len(calls), 2)
        with self.assertRaises(D.V6ContractRefusal):
            D._h6_branch_history(lambda route: {"total_count": 2, "workflow_runs": [first, first]})

    def test_targeted_completion_keeps_current_candidate_passes_but_no_f5_reuse(self):
        self.f.targeted()
        result = self.f.check()
        self.assertEqual(result["priorUnresolvedProfiles"], ["compatibility", "types-tests"])
        self.assertEqual(result["priorValidationObservedMinutes"], 17)
        self.assertEqual(result["currentRoundBookedMinutes"], 190)
        self.assertEqual(result["futureTargetedReserveMinutes"], 0)
        self.assertEqual(result["priorValidationReceipts"][0]["sourceSha"], self.f.f.current)
        self.assertFalse(result["priorValidationReceipts"][0]["oldF5EvidenceUsed"])
        self.assertFalse(result["historicalCoverageReused"])

    def test_targeted_cannot_omit_failed_or_unstarted_owner(self):
        self.f.targeted()
        self.f.f.request["profiles"] = ["types-tests"]
        with self.assertRaisesRegex(D.V6ContractRefusal, "unresolved_profiles_selected"): self.f.check()
        self.f = HistoryFixture(Path(self.tmp.name))
        self.f.targeted()
        prior = self.f.f.pins["priorValidationRuns"][0]
        self.f.prior_jobs = {"total_count": 3, "jobs": []}
        for index, (name, conclusion, acquired) in enumerate([
                ("admission", "failure", True), ("final", "skipped", False),
                ("source (${{ matrix.profile }})", "skipped", False)]):
            item = job(prior["runId"], prior["pipelineHead"], name, conclusion=conclusion)
            item["id"] += index
            if not acquired:
                item.update(runner_id=None, runner_name=None, runner_group_name=None, labels=[], steps=[])
            self.f.prior_jobs["jobs"].append(item)
        with self.assertRaisesRegex(D.V6ContractRefusal, "unresolved_profiles_selected"): self.f.check()

    def test_prior_validation_request_digest_or_source_chain_drift_refuses(self):
        for mutation in ("digest", "chain"):
            with self.subTest(mutation=mutation):
                self.f = HistoryFixture(Path(self.tmp.name))
                self.f.targeted()
                if mutation == "digest":
                    self.f.prior_request += b" "
                else:
                    altered = json.loads(self.f.prior_request)
                    altered["sourceWitness"]["hops"][0]["step"]["unchangedTreeSha256"] = "f" * 64
                    self.f.prior_request = encoded(altered)
                    self.f.f.pins["priorValidationRuns"][0]["requestSha256"] = digest(self.f.prior_request)
                with self.assertRaises(D.V6ContractRefusal): self.f.check()


if __name__ == "__main__":
    unittest.main()
