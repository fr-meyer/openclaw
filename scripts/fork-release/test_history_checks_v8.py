"""Isolated Python synthetics; no Git, network, driver, application or Node runs.

Request/composition/old-history primitives are injected contract doubles. The
tests exercise the new orchestration and accounting, not qualify those owners.
"""
import ast
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
from pathlib import Path
import tempfile
import types
import unittest


HERE = Path(__file__).resolve().parent
PROFILES = ("dependency", "types-production", "types-tests", "types-scripts", "workboard-1",
    "workboard-2", "models-1", "models-2", "sqlite", "doctor-1", "doctor-2", "doctor-3",
    "memory", "pipeline-contracts", "compatibility")
LIMITS = dict(zip(PROFILES, (60, 90, 90, 90, 60, 60, 60, 60, 60, 90, 75, 75, 60, 45, 60)))
NOW = datetime(2026, 10, 29, 16, tzinfo=timezone.utc)
CLOSED = "2026-10-29T14:09:37.976704+00:00"
OLD_SOURCE_IDS = ("40616416909", "40609889437", "40607329263", "40639374411", "40647629182",
    "40681376480", "40688279536", "40706982753", "40804517284", "40808362032", "40816927196")


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class Refusal(ValueError):
    pass


def need(ok, code):
    if not ok:
        raise Refusal(code)


class Clock(datetime):
    @classmethod
    def now(cls, tz=None):
        return NOW


def minutes(table, *unused, **kwargs):
    total = 0
    for job in table["jobs"]:
        need(job["status"] == "completed", "synthetic.terminal")
        if job.get("runner_id"):
            total += math.ceil((datetime.fromisoformat(job["completed_at"].replace("Z", "+00:00")) -
                datetime.fromisoformat(job["started_at"].replace("Z", "+00:00"))).total_seconds() / 60)
    return total


class Fixture:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="r8-history-synthetic-")
        self.pipeline = Path(self.tmp.name)
        self.workflow = ".github/workflows/future-v108-source-validation.yml"
        self.head = "c" * 40
        self.source = "f" * 40
        self.current_id = "90000000001"  # Synthetic only; no future operational ID.
        self.source_ids = [*OLD_SOURCE_IDS, "40851844749", "40856125444"]
        self.request = {"schema": "synthetic-r8", "profilePolicy": "synthetic-policy",
            "stageRound": 1, "profiles": list(PROFILES), "sourceSha": self.source,
            "sourceTree": "d" * 40, "manifestSha256": "1" * 64, "inventorySha256": "2" * 64,
            "settledUsageSha256": "3" * 64, "lockPreparation": {"synthetic": "already-closed"},
            "sourceWitness": {"synthetic": "same-F"}}
        self.history, self.tables, self.artifacts, self.calls = {}, {}, {}, []
        original = []
        for index in range(213):
            rid = OLD_SOURCE_IDS[index] if index < len(OLD_SOURCE_IDS) else str(10000 + index)
            run = self.run(rid, source=index < len(OLD_SOURCE_IDS))
            jobs = [self.job(run, 0, "admission", 9 if index < 94 else 8)]
            artifact = []
            if index < 19:
                artifact = [{"id": index + 1, "name": "old", "size_in_bytes": 10000 if index < 18 else 18278,
                    "expired": False}]
            original.append(self.closed(run, jobs, artifact))
        self.original = {"runs": original, "runnerMinutesObserved": 1798}
        appended = []
        for index in range(30):
            rid = self.source_ids[11 + index] if index < 2 else str(20000 + index)
            run = self.run(rid, source=index < 2)
            if index == 0:
                jobs = [self.job(run, 0, "lock-preparation", 4)]
            elif index == 1:
                jobs = [self.job(run, 0, "admission", 5),
                    *[self.job(run, n + 1, "source (" + profile + ")", 40) for n, profile in enumerate(PROFILES)],
                    self.job(run, 16, "final", 2)]
            else:
                jobs = [self.job(run, 0, "ci", 1)]
            artifact = []
            if index < 3:
                artifact = [{"id": 1000 + index, "name": "stage", "size_in_bytes": (100000, 88913, 1)[index],
                    "expired": False}]
            appended.append(self.closed(run, jobs, artifact, actors=True))
        self.baseline = {"runs": original + appended, "runCount": 243, "runnerMinutesObserved": 2437,
            "sourceRunIds": self.source_ids, "artifactSnapshot": {"count": 22, "bytes": 387192}, "closedAt": CLOSED}
        self.proof_raw, self.original_raw, self.stage_raw = b"synthetic-public-proof", b"synthetic-original213", b"synthetic-public-stage30"
        self.pins = {"sourceSha": self.source, "sourceTree": "d" * 40,
            "manifestSha256": "1" * 64, "inventorySha256": "2" * 64,
            "sourceWitness": self.request["sourceWitness"], "priorValidationRuns": [],
            "baseline": {"sha256": digest(self.proof_raw), "resolvedSha256": digest(encoded(self.baseline)),
                "runCount": 243, "runnerMinutesObserved": 2437, "sourceRunIds": self.source_ids,
                "artifactSnapshot": {"count": 22, "bytes": 387192}, "closedAt": CLOSED}}
        for name, raw in (("proof", self.proof_raw), ("old", self.original_raw), ("stage", self.stage_raw),
                (self.workflow, b"synthetic-fixed-workflow")):
            path = self.pipeline / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        self.current = self.run(self.current_id, source=True, head=self.head, active=True)
        job = self.job(self.current, 0, "admission", 1, active=True)
        self.tables[self.current_id] = {"jobs": [job], "total_count": 1}
        self.artifacts[self.current_id] = []
        self.old_r7 = {"sourceSha": "e" * 40, "preparation": {"runId": "40851844749", "pipelineHead": "a" * 40}}
        self.old_request = {"stageRound": 1, "profiles": list(PROFILES), "sourceSha": "e" * 40}
        self.d = types.ModuleType("synthetic_r8_history")
        owner = HERE / "source_validation_v108.py"
        if owner.is_file():
            tree = ast.parse(owner.read_text())
            selected = [node for node in tree.body if isinstance(node, ast.FunctionDef) and
                (node.name.startswith("_h8_") or node.name in
                 ("booking_v8", "workflow_security_v8", "history_checks_v8"))]
            imports = ast.parse("import hashlib, json, math\nfrom datetime import datetime, timezone\n").body
            exec(compile(ast.Module(body=imports + selected, type_ignores=[]), str(owner), "exec"), self.d.__dict__)
        else:
            exec(compile((HERE / "history_contract_v8.py").read_bytes(), str(HERE / "history_contract_v8.py"), "exec"), self.d.__dict__)
        d = self.d
        d.__dict__.update(_r8_need=need, R8ContractRefusal=Refusal, R8_PROFILE_MINUTES=LIMITS,
            R8_FULL_MINUTES=1075, R8_TARGETED_MINUTES=300, R8_ADMISSION_MINUTES=30, R8_FINAL_MINUTES=10,
            R8_ANCILLARY_MINUTES=50, R8_NEW_MINUTES=1425, V6_OVERALL_MINUTES=18000,
            R8_SETTLED_USAGE_PATH="proof", R7_SETTLED_USAGE_PATH="old", R8_PRIOR_STAGE_USAGE_PATH="stage",
            R8_PRIOR_RUNS=243, R8_PRIOR_MINUTES=2437, R8_DIAGNOSTIC_BYTES=64 * 1024 * 1024,
            R8_DEADLINE="2026-10-30T08:03:19Z", R8_POLICY="synthetic-policy", R7_STAGE_PINS=self.old_r7,
            R7_PREPARATION_MINUTES=45, V6_PROFILES=PROFILES, datetime=Clock,
            V6_PROVIDER_HEADERS=("id", "name", "path", "event", "head_branch", "head_sha", "run_attempt",
                "status", "conclusion", "created_at", "updated_at", "html_url"),
            V5_TERMINAL_CONCLUSIONS={"success", "failure", "skipped", "cancelled"},
            REPOSITORY="fr-meyer/openclaw", WORKFLOW=self.workflow, REQUEST="request", BRANCH="branch",
            BASE_BRANCH="base", TARGET_BRANCH_TIP="b" * 40, V6_SOURCE_BRANCH="source", timestamp=self.timestamp,
            validate_request_v8=self.validate, validation_budget_v8=self.budget, validate_event=self.event,
            _h6_branch_history=lambda api: self.history, _h5_public=self.public, _h5_jobs=self.jobs,
            _h6_source_run_binding=self.source_binding, _h7_preparation_binding=self.preparation,
            validate_closed_baseline_v7=self.old_baseline, resolve_composite=self.resolve,
            content_at=self.content, _v6_json=json.loads, validate_request_v7=self.validate_old,
            validation_budget_v7=lambda request: {"synthetic": "historical-R7"},
            workflow_security_v7=lambda raw, source: {"profilePolicy": "historical-R7", "ownerActorRequired": True},
            observed_minutes=minutes, observed_minutes_v5=minutes, ancillary_job_snapshot=self.snapshot,
            git=lambda *args: self.calls.append(("git-adapter", args)) or "")

    @staticmethod
    def timestamp(value):
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    def run(self, rid, source=False, head="a" * 40, active=False):
        run = {"id": int(rid), "name": "synthetic", "path": self.workflow if source else ".github/workflows/ci.yml",
            "event": "pull_request", "head_branch": "branch", "head_sha": head, "run_attempt": 1,
            "status": "in_progress" if active else "completed", "conclusion": None if active else "failure",
            "created_at": "2026-10-29T15:00:00Z" if active else "2026-10-29T12:00:00Z",
            "updated_at": "2026-10-29T15:01:00Z" if active else "2026-10-29T13:45:00Z",
            "html_url": "https://github.com/fr-meyer/openclaw/actions/runs/" + rid,
            "display_title": "synthetic-campaign", "pull_requests": [{"number": 28}],
            "repository": {"full_name": "fr-meyer/openclaw", "private": False},
            "head_repository": {"full_name": "fr-meyer/openclaw", "private": False},
            "actor": {"login": "fr-meyer"}, "triggering_actor": {"login": "fr-meyer"}}
        if rid == "40851844749":
            run["conclusion"] = "success"
        self.history[rid] = run
        return run

    def job(self, run, index, name, amount, active=False):
        end = NOW if active else datetime(2026, 10, 29, 13, 40, tzinfo=timezone.utc)
        return {"id": run["id"] * 100 + index, "run_id": run["id"], "head_sha": run["head_sha"],
            "run_attempt": 1, "name": name, "status": "in_progress" if active else "completed",
            "conclusion": None if active else "success", "runner_id": 7, "runner_name": "hosted",
            "runner_group_name": "GitHub Actions", "labels": ["ubuntu-24.04"],
            "started_at": (end - timedelta(minutes=amount)).isoformat().replace("+00:00", "Z"),
            "completed_at": None if active else end.isoformat().replace("+00:00", "Z"),
            "steps": [{"name": "synthetic-safe"}]}

    def closed(self, run, jobs, artifacts, actors=False):
        headers = ("id", "name", "path", "event", "head_branch", "head_sha", "run_attempt", "status",
            "conclusion", "created_at", "updated_at", "html_url")
        row = {key: copy.deepcopy(run[key]) for key in headers}
        row.update(jobs=copy.deepcopy(jobs), observedRunnerMinutes=minutes({"jobs": jobs}), artifactRows=copy.deepcopy(artifacts))
        if actors:
            row.update(actorLogin="fr-meyer", triggeringActorLogin="fr-meyer")
        self.tables[str(run["id"])] = {"jobs": copy.deepcopy(jobs), "total_count": len(jobs)}
        self.artifacts[str(run["id"])] = copy.deepcopy(artifacts)
        return row

    def validate(self, request, pins):
        need(request["stageRound"] in (1, 2) and request["sourceSha"] == pins["sourceSha"] and
            request["sourceTree"] == pins["sourceTree"] and
            len(pins["priorValidationRuns"]) == request["stageRound"] - 1, "synthetic.request")
        need(request["stageRound"] != 1 or request["profiles"] == list(PROFILES), "synthetic.full15")
        need(40 + sum(LIMITS[p] for p in request["profiles"]) <=
            (1075 if request["stageRound"] == 1 else 300), "synthetic.booking")
        return request

    def budget(self, request):
        return {"profileMinutes": dict(LIMITS), "admissionMinutes": 30, "finalMinutes": 10,
            "roundMaximumMinutes": 1075 if request["stageRound"] == 1 else 300}

    def event(self, event, env):
        need(event.get("head", self.head) == self.head and
            event.get("pull_request", {}).get("head", {}).get("sha", self.head) == self.head, "synthetic.event")
        return self.head

    def public(self, run):
        return type(run) is dict and run.get("repository", {}).get("private") is False and \
            run.get("head_repository", {}).get("private") is False

    def source_binding(self, run):
        need(self.public(run) and run.get("event") == "pull_request" and
            type(run.get("run_attempt")) is int and run["run_attempt"] == 1 and
            run.get("head_branch") == "branch", "synthetic.source-binding")

    def preparation(self, run, pin):
        self.source_binding(run)
        need(str(run["id"]) == pin["runId"] and run["head_sha"] == pin["pipelineHead"], "synthetic.preparation")

    def jobs(self, api, run):
        table = api("/repos/fr-meyer/openclaw/actions/runs/" + str(run["id"]) + "/jobs?filter=all&per_page=100")
        need(table["total_count"] == len(table["jobs"]) <= 100 and all(j["run_id"] == run["id"] and
            j["head_sha"] == run["head_sha"] and type(j["run_attempt"]) is int and j["run_attempt"] == 1
            for j in table["jobs"]), "synthetic.fresh-jobs")
        return table

    def old_baseline(self, raw, read_git, history, api, pins):
        need(raw == self.original_raw and pins is self.old_r7, "synthetic.old-owner-unchanged")
        return self.original, {str(row["id"]) for row in self.original["runs"]}, {}

    def resolve(self, proof, original, stage):
        need((proof, original, stage) == (self.proof_raw, self.original_raw, self.stage_raw), "synthetic.composite")
        return copy.deepcopy(self.baseline)

    def validate_old(self, request, pins):
        need(pins is self.old_r7 and request == self.old_request, "synthetic.old-r7-request")

    def content(self, api, path, head):
        if path == self.workflow:
            return b"synthetic-fixed-workflow"
        return encoded(self.previous_request if head == "b" * 40 else self.old_request)

    def snapshot(self, table, now, terminal):
        acquired = 0
        pending = not terminal
        for job in table["jobs"]:
            if job.get("runner_id"):
                start = self.timestamp(job["started_at"])
                end = self.timestamp(job["completed_at"]) if job["status"] == "completed" else now
                acquired += math.ceil((end - start).total_seconds() / 60)
            if job["status"] != "completed":
                pending = True
        return {"observedAcquiredRunnerMinutes": acquired, "usageComplete": not pending}

    def api(self, path):
        self.calls.append(path)
        if path.endswith("/pulls/28"):
            return {"head": {"sha": self.head}}
        if "/git/ref/heads/" in path:
            branch = path.rsplit("/", 1)[-1]
            return {"ref": "refs/heads/" + branch,
                "object": {"type": "commit", "sha": "b" * 40 if branch == "base" else self.source}}
        rid = path.split("/actions/runs/", 1)[1].split("/", 1)[0]
        if "/jobs?" in path:
            return copy.deepcopy(self.tables[rid])
        if "/artifacts?" in path:
            rows = copy.deepcopy(self.artifacts[rid])
            return {"total_count": len(rows), "artifacts": rows}
        raise AssertionError("Unexpected synthetic metadata route")

    def targeted(self, profiles=("compatibility",)):
        self.previous_request = copy.deepcopy(self.request)
        raw = encoded(self.previous_request)
        rid = "90000000002"  # Synthetic only.
        run = self.run(rid, source=True, head="b" * 40)
        run.update(created_at="2026-10-29T14:20:00Z", updated_at="2026-10-29T14:50:00Z")
        jobs = [self.job(run, 0, "admission", 1),
            *[self.job(run, index + 1, "source (" + profile + ")", 1) for index, profile in enumerate(PROFILES)],
            self.job(run, 16, "final", 1)]
        next(j for j in jobs if j["name"] == "source (compatibility)")["conclusion"] = "failure"
        self.tables[rid] = {"jobs": jobs, "total_count": len(jobs)}
        self.artifacts[rid] = []
        self.pins["priorValidationRuns"] = [{"runId": rid, "pipelineHead": "b" * 40, "requestSha256": digest(raw)}]
        self.request.update(stageRound=2, profiles=list(profiles))

    def check(self):
        return self.d.history_checks_v8(self.request, {}, {"GITHUB_RUN_ID": self.current_id}, self.pipeline, self.api, self.pins)


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()
        self.addCleanup(self.f.tmp.cleanup)

    def refuses(self, code=None):
        with self.assertRaisesRegex(Refusal, code or ".+"):
            self.f.check()

    def test_full_booking_has_no_new_preparation_charge_or_reused_coverage(self):
        r = self.f.check()
        self.assertEqual((r["newStageBookedMinutes"], r["bookedRunnerMinutes"]), (1425, 3862))
        self.assertEqual((r["currentRoundBookedMinutes"], r["futureTargetedReserveMinutes"]), (1075, 300))
        self.assertFalse(r["preparationChargedAgain"])
        self.assertFalse(r["historicalCoverageReused"])
        self.assertEqual(len(r["profileMatrix"]), 15)
        self.assertFalse(r["productionAuthorized"])
        self.assertEqual(self.f.old_r7["sourceSha"], "e" * 40)

    def test_targeted_covers_every_unresolved_same_f_profile(self):
        self.f.targeted()
        r = self.f.check()
        self.assertEqual(r["priorUnresolvedProfiles"], ["compatibility"])
        self.assertEqual(r["priorValidationObservedMinutes"], 17)
        self.assertEqual(r["futureTargetedReserveMinutes"], 0)
        self.assertFalse(r["priorValidationReceipts"][0]["oldF5OrR7EvidenceUsedForCurrentCoverage"])

    def test_targeted_omission_or_source_repin_refuses(self):
        self.f.targeted(("types-tests",))
        self.refuses("all_unresolved")
        self.f.request["profiles"] = ["compatibility"]
        self.f.previous_request["sourceWitness"] = {"changed": True}
        self.f.pins["priorValidationRuns"][0]["requestSha256"] = digest(encoded(self.f.previous_request))
        self.refuses("same_frozen")

    def test_missing_or_extra_source_execution_refuses(self):
        self.f.run("90000000003", source=True, head=self.f.head)
        self.refuses("exact_execution_set")
        del self.f.history["90000000003"]
        del self.f.history[self.f.current_id]
        self.refuses("exact_execution_set")

    def test_actor_or_replayed_attempt_refuses(self):
        self.f.current["triggering_actor"]["login"] = "other"
        self.refuses("owner_actor")
        self.f.current["triggering_actor"]["login"] = "fr-meyer"
        self.f.current["run_attempt"] = 2
        self.refuses("source-binding")

    def test_closed_header_job_or_artifact_drift_refuses(self):
        run = self.f.history["20002"]
        run["updated_at"] = "2026-10-29T13:46:00Z"
        self.refuses("closed30_header")
        run["updated_at"] = "2026-10-29T13:45:00Z"
        self.f.tables["20002"]["jobs"][0]["steps"] = []
        self.refuses("closed30_jobs")
        self.f.tables["20002"]["jobs"][0]["steps"] = [{"name": "synthetic-safe"}]
        self.f.artifacts["20002"][0]["size_in_bytes"] = 2
        self.refuses("closed30_artifacts")

    def test_closed_actor_change_or_composite_bytes_refuses(self):
        self.f.history["20002"]["actor"]["login"] = "other"
        self.refuses("owner_actor")
        self.f.history["20002"]["actor"]["login"] = "fr-meyer"
        (self.f.pipeline / "proof").write_bytes(b"changed")
        self.refuses("proof_digest")

    def test_current_source_cannot_acquire_before_admission(self):
        job = self.f.job(self.f.current, 1, "source (compatibility)", 1, active=True)
        self.f.tables[self.f.current_id]["jobs"].append(job)
        self.f.tables[self.f.current_id]["total_count"] = 2
        self.refuses("jobs_before_admission")

    def test_unacquired_placeholder_is_positive_not_a_pass(self):
        job = self.f.job(self.f.current, 1, "source (${{ matrix.profile }})", 1)
        job.update(status="queued", conclusion=None, runner_id=None, runner_name=None, steps=[])
        self.f.tables[self.f.current_id]["jobs"].append(job)
        self.f.tables[self.f.current_id]["total_count"] = 2
        self.assertFalse(self.f.check()["historicalCoverageReused"])

    def test_current_job_or_artifact_cannot_replay_closed_identity(self):
        self.f.tables[self.f.current_id]["jobs"][0]["id"] = self.f.original["runs"][0]["jobs"][0]["id"]
        self.refuses("replayed_current_job")
        self.f.tables[self.f.current_id]["jobs"][0]["id"] = int(self.f.current_id) * 100
        self.f.artifacts[self.f.current_id] = [{"id": 1, "name": "replay", "size_in_bytes": 1, "expired": False}]
        self.refuses("artifact_duplicate")

    def test_new_ancillary_pending_usage_and_reserve(self):
        run = self.f.run("90000000004", head=self.f.head, active=True)
        job = self.f.job(run, 0, "ci", 2, active=True)
        self.f.tables[str(run["id"])] = {"jobs": [job], "total_count": 1}
        self.f.artifacts[str(run["id"])] = []
        r = self.f.check()
        self.assertFalse(r["ancillaryUsageComplete"])
        self.assertEqual(r["observedNewAncillaryRunnerMinutes"], 2)
        self.assertEqual(r["newAncillaryRemainingReserveMinutes"], 48)
        job["started_at"] = (NOW - timedelta(minutes=50)).isoformat().replace("+00:00", "Z")
        self.refuses("ancillary_limit")

    def test_stale_new_ancillary_or_wrong_head_refuses(self):
        run = self.f.run("90000000004", head=self.f.head, active=True)
        self.f.tables[str(run["id"])] = {"jobs": [self.f.job(run, 0, "ci", 1, active=True)], "total_count": 1}
        self.f.artifacts[str(run["id"])] = []
        run["created_at"] = "2026-10-29T13:00:00Z"
        self.refuses("new_ancillary_binding")
        run["created_at"] = "2026-10-29T15:00:00Z"
        run["head_sha"] = "0" * 40
        self.refuses("new_ancillary_binding")

    def test_artifact_cap_does_not_drop_closed_bytes(self):
        self.f.artifacts[self.f.current_id] = [{"id": 2000, "name": "large", "size_in_bytes": 64 * 1024 * 1024,
            "expired": False}]
        self.refuses("artifact_storage_limit")

    def test_deadline_and_current_start_refuse(self):
        self.f.d.R8_DEADLINE = "2026-10-29T15:00:00Z"
        self.refuses("history_deadline")
        self.f.d.R8_DEADLINE = "2026-10-30T08:03:19Z"
        self.f.current["created_at"] = "2026-10-29T13:00:00Z"
        self.refuses("current_validation_identity")

    def test_booking_refuses_boolean_usage_and_exhausted_ceiling(self):
        with self.assertRaisesRegex(Refusal, "actual_usage"):
            self.f.d.booking_v8(self.f.request, self.f.pins, True, 0)
        self.f.d.V6_OVERALL_MINUTES = 3000
        self.refuses("total_minute_ceiling")


if __name__ == "__main__":
    unittest.main()
