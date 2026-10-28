"""Corrective driver owners, actual public P5 fixture and synthetic API; local Git controls only."""
import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import os
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
PIPELINE = HERE.parents[1]
V4_CLOSED_PIPELINE = "2946a1678e712de90727a9e599a5f2cd47ad2151"
CURRENT = "9000000099"
HEAD = "a" * 40
NOW = datetime(2026, 10, 28, 12, tzinfo=timezone.utc)


Refusal = RuntimeError  # Rebound to the actual adjacent owner.


class Clock(datetime):
    @classmethod
    def now(cls, tz=None):
        return NOW


def load_fragment():
    global Refusal
    spec = importlib.util.spec_from_file_location(
        "published_v4_corrective_history_driver", HERE / "source_validation_v108.py")
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(HERE))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    Refusal = module.release.Refusal
    module.datetime = Clock
    return module.__dict__


def git_control(driver, commit, filename):
    """Fixed public history controls only; no lazy fetch, credentials or fallback."""
    if commit not in (driver["V4_PARENT_PIPELINE"], driver["FIRST_PIPELINE"], V4_CLOSED_PIPELINE) or filename not in (
            driver["REQUEST"], driver["WORKFLOW"]):
        raise AssertionError("Control read outside the three fixed historical owners")
    result = subprocess.run(["git", "--no-replace-objects", "-C", str(PIPELINE), "cat-file", "blob",
        commit + ":" + filename], check=True, capture_output=True, timeout=5, env={
        "PATH": os.environ["PATH"], "GIT_NO_LAZY_FETCH": "1", "GIT_OPTIONAL_LOCKS": "0",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0",
    })
    if not 0 < len(result.stdout) <= 65536:
        raise AssertionError("Historical control must be a bounded local Git blob")
    return result.stdout


def instant(value):
    return value.isoformat().replace("+00:00", "Z")


class HistoryV4Tests(unittest.TestCase):
    def setUp(self):
        self.ns = load_fragment()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.prefix_raw = (HERE / "fixtures/v108-settled-closed99.json").read_bytes()
        self.assertEqual(hashlib.sha256(self.prefix_raw).hexdigest(), self.ns["V4_CLOSED_PREFIX_SHA256"])
        self.prefix = json.loads(self.prefix_raw)
        p = self.root / self.ns["SETTLED_USAGE"]
        p.parent.mkdir(parents=True)
        p.write_bytes(self.prefix_raw)
        self.workflow = git_control(self.ns, V4_CLOSED_PIPELINE, self.ns["WORKFLOW"])
        w = self.root / self.ns["WORKFLOW"]
        w.parent.mkdir(parents=True)
        w.write_bytes(self.workflow)
        self.current_pins = copy.deepcopy(self.ns["STAGE_PINS"])
        self.current_request_raw = (HERE / "fixtures/v108-source-request-v4-2946.json").read_bytes()
        self.assertEqual(hashlib.sha256(self.current_request_raw).hexdigest(),
            "167466df439e6320f927681553ce7ad35f1b94afa5b2f81ab902a22b8a6a2d09")
        for filename, key in (("manifest.json", "manifestSha256"), ("patch-inventory.json", "inventorySha256")):
            raw = (PIPELINE / self.ns["CANDIDATE"] / filename).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), self.current_pins[key])
        self.first_request_raw = git_control(self.ns, self.ns["FIRST_PIPELINE"], self.ns["REQUEST"])
        self.first_workflow_raw = git_control(self.ns, self.ns["FIRST_PIPELINE"], self.ns["WORKFLOW"])
        self.assertEqual(hashlib.sha256(self.first_request_raw).hexdigest(), self.ns["FIRST_REQUEST_SHA256"])
        # Initial-path unit cases consume the genuine P5 request and its first-source
        # pins. The current-correction cases below use the actual tracked P6 request.
        self.request = json.loads(self.first_request_raw)
        initial_pins = copy.deepcopy(self.current_pins)
        initial_pins.update(sourceSha=initial_pins["firstSourceSha"], sourceTree=initial_pins["firstSourceTree"],
            manifestSha256=initial_pins["firstManifestSha256"], inventorySha256=initial_pins["firstInventorySha256"],
            priorRunIds=initial_pins["priorRunIds"][:5])
        self.ns["STAGE_PINS"] = initial_pins
        pins = initial_pins
        repo = {"full_name": self.ns["REPOSITORY"], "private": False}
        self.pr = {"number": 28, "state": "open", "draft": True,
            "head": {"repo": repo, "ref": self.ns["BRANCH"], "sha": HEAD},
            "base": {"repo": repo, "ref": self.ns["BASE_BRANCH"], "sha": self.ns["BASE"]}}
        self.event = {"action": "synchronize", "number": 28, "repository": repo, "pull_request": self.pr}
        self.env = {"GITHUB_ACTIONS": "true", "RUNNER_OS": "Linux", "RUNNER_ENVIRONMENT": "github-hosted",
            "GITHUB_EVENT_NAME": "pull_request", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_REPOSITORY": self.ns["REPOSITORY"],
            "GITHUB_REF": "refs/pull/28/merge", "GITHUB_WORKFLOW_REF": self.ns["REPOSITORY"] + "/" + self.ns["WORKFLOW"] + "@refs/pull/28/merge",
            "GITHUB_WORKFLOW_SHA": "b" * 40, "GITHUB_RUN_ID": CURRENT}
        self.history = {}
        for row in self.prefix["runs"]:
            run = {key: copy.deepcopy(row[key]) for key in self.ns["V4_PROVIDER_RUN_HEADERS"]}
            run.update(repository=repo, head_repository=repo, display_title=self.ns["CAMPAIGN"], pull_requests=[{"number": 28}])
            self.history[str(run["id"])] = run
        self.history[CURRENT] = self.run_record(CURRENT, self.ns["WORKFLOW"], "in_progress", HEAD)
        self.job_counter = 0
        self.tables = {CURRENT: {"total_count": 1, "jobs": [self.job(CURRENT, "admission", status="in_progress")]}}
        self.artifacts = {}
        self.contents = {}
        self.source_tip = pins["sourceSha"]
        self.calls = []
        old_request = git_control(self.ns, self.ns["V4_PARENT_PIPELINE"], self.ns["REQUEST"])
        def fake_git(root, *args):
            self.calls.append(("git", args))
            if args == ("show", self.ns["V4_PARENT_PIPELINE"] + ":" + self.ns["REQUEST"]):
                return old_request
            if args[:2] == ("merge-base", "--is-ancestor"):
                return b""
            raise AssertionError(args)
        self.ns["git"] = fake_git

    def run_record(self, rid, path, status="completed", head=HEAD):
        repo = {"full_name": self.ns["REPOSITORY"], "private": False}
        return {"id": int(rid), "path": path, "head_sha": head, "event": "pull_request", "run_attempt": 1,
            "head_branch": self.ns["BRANCH"], "display_title": self.ns["CAMPAIGN"],
            "status": status, "conclusion": "success" if status == "completed" else None,
            "repository": repo, "head_repository": repo, "pull_requests": [{"number": 28}],
            "created_at": "2026-10-28T11:00:00Z", "updated_at": "2026-10-28T11:59:00Z"}

    def job(self, rid, name, minutes=1, status="completed", acquired=True):
        self.job_counter += 1
        return {"id": int(rid) * 1000 + self.job_counter, "run_id": int(rid), "head_sha": self.history[rid]["head_sha"],
            "run_attempt": 1, "name": name, "status": status,
            "conclusion": "success" if status == "completed" else None,
            "runner_id": 12 if acquired else 0, "runner_name": "hosted" if acquired else "",
            "runner_group_name": "GitHub Actions" if acquired else None,
            "labels": ["ubuntu-24.04"], "steps": [{"name": "synthetic"}] if acquired else [],
            "started_at": instant(NOW - timedelta(minutes=minutes)) if acquired else None,
            "completed_at": instant(NOW) if status == "completed" and acquired else None}

    def api(self, route):
        self.calls.append(("api", route))
        root = "/repos/" + self.ns["REPOSITORY"]
        if route == root + "/pulls/28":
            return copy.deepcopy(self.pr)
        if route == root + "/git/ref/heads/" + self.ns["BASE_BRANCH"]:
            return {"ref": "refs/heads/" + self.ns["BASE_BRANCH"],
                    "object": {"type": "commit", "sha": self.ns["TARGET_BRANCH_TIP"]}}
        if route == root + "/git/ref/heads/" + self.ns["V4_SOURCE_BRANCH"]:
            return {"ref": "refs/heads/" + self.ns["V4_SOURCE_BRANCH"],
                    "object": {"type": "commit", "sha": self.source_tip}}
        if route.startswith(root + "/actions/runs?branch="):
            page = int(route.rsplit("=", 1)[1]);rows = list(self.history.values())
            return {"total_count": len(rows), "workflow_runs": copy.deepcopy(rows[(page-1)*100:page*100])}
        m = re.fullmatch(root + r"/actions/runs/([0-9]+)/jobs\?filter=all&per_page=100", route)
        if m:
            return copy.deepcopy(self.tables[m[1]])
        m = re.fullmatch(root + r"/actions/runs/([0-9]+)/artifacts\?per_page=100", route)
        if m:
            rows = self.artifacts.get(m[1], [])
            return {"total_count": len(rows), "artifacts": copy.deepcopy(rows)}
        if route.startswith(root + "/contents/"):
            raw = self.contents[route.split("/contents/", 1)[1]]
            return {"type": "file", "encoding": "base64", "size": len(raw),
                    "content": base64.b64encode(raw).decode()}
        raise AssertionError(route)

    def check(self):
        return self.ns["history_checks_v4"](self.request, self.event, self.env, self.root, self.api)

    def ancillary(self, status="queued", minutes=0):
        rid = "9000000100"
        path = next(row["path"] for row in self.prefix["runs"] if row["path"] != self.ns["WORKFLOW"])
        self.history[rid] = self.run_record(rid, path, status)
        self.tables[rid] = {"total_count": 1, "jobs": [self.job(rid, "fixed", minutes, status, status != "queued")]}
        return rid

    def corrective(self):
        first_id, first_head = "9000000098", "c" * 40
        raw = (json.dumps(self.request, indent=2) + "\n").encode()
        self.ns.update(FIRST_PIPELINE=first_head, FIRST_REQUEST_SHA256=hashlib.sha256(raw).hexdigest())
        self.contents[self.ns["REQUEST"] + "?ref=" + first_head] = raw
        self.contents[self.ns["WORKFLOW"] + "?ref=" + first_head] = self.workflow
        self.history[first_id] = self.run_record(first_id, self.ns["WORKFLOW"], "completed", first_head)
        self.history[first_id]["created_at"] = "2026-10-28T10:30:00Z"
        names = ["admission", "final"] + ["source (" + p + ")" for p in self.request["profiles"]]
        self.tables[first_id] = {"total_count": len(names), "jobs": [self.job(first_id, n) for n in names]}
        self.ns["STAGE_PINS"]["priorRunIds"].append(first_id)
        self.request["priorRunIds"].append(first_id)
        self.request.update(round=5, lifetimeOperatorRound=6,
            profiles=["dependency", "types-tests", "types-scripts", "compatibility", "pipeline-contracts"])
        return first_id

    def test_initial_exact99_reuses8_books475_475_45_without_prefix_api_jobs(self):
        facts = self.check()
        self.assertEqual(facts["bookedRunnerMinutes"], 1881)
        self.assertEqual((facts["selectedProfileCount"], facts["reusedProfileCount"]), (7, 8))
        self.assertEqual(facts["currentRoundBookedMinutes"], 475)
        self.assertEqual(len(facts["historicalJobTableSha256"]), 99)
        self.assertFalse(facts["artifactObservationComplete"])
        job_reads = [x[1] for x in self.calls if x[0] == "api" and "/jobs?" in x[1]]
        self.assertEqual(len(job_reads), 1)

    def test_pending_ancillary_never_zero_reservation_or_waits(self):
        self.ancillary()
        facts = self.check()
        self.assertFalse(facts["ancillaryUsageComplete"])
        self.assertEqual(facts["newAncillaryRemainingReserveMinutes"], 45)
        self.assertEqual(facts["ancillaryReservationBookedMinutes"], 45)
        self.assertFalse(facts["ancillaryWaitPerformed"])
        self.assertEqual(facts["bookedRunnerMinutes"], 1881)

    def test_completed_and_pending_acquired_usage_is_charged(self):
        self.ancillary("in_progress", 12)
        self.assertEqual(self.check()["observedNewAncillaryRunnerMinutes"], 12)
        self.tables["9000000100"]["jobs"][0]["runner_id"] = None
        with self.assertRaises(Refusal):
            self.check()

    def test_prefix_mutation_missing_header_changed_updated_or_attempt_refuses(self):
        rid = str(self.prefix["runs"][0]["id"])
        for key, value in [("updated_at", "2026-10-28T11:00:00Z"), ("run_attempt", 2), ("status", "queued")]:
            with self.subTest(key=key):
                old = self.history[rid][key];self.history[rid][key] = value
                with self.assertRaises(Refusal):self.check()
                self.history[rid][key] = old
        (self.root / self.ns["SETTLED_USAGE"]).write_bytes(self.prefix_raw + b" ")
        with self.assertRaises(Refusal):self.check()

    def test_extra_source_round_wrong_current_head_attempt_or_private_refuses(self):
        for key, value in [("head_sha", "d" * 40), ("run_attempt", 2), ("path", ".github/workflows/other.yml")]:
            with self.subTest(key=key):
                old = self.history[CURRENT][key];self.history[CURRENT][key] = value
                with self.assertRaises(Refusal):self.check()
                self.history[CURRENT][key] = old
        self.history["9000000101"] = self.run_record("9000000101", self.ns["WORKFLOW"])
        with self.assertRaises(Refusal):self.check()

    def test_private_live_repo_changed_base_source_and_unacquired_current_refuse(self):
        old = self.pr["base"]["sha"];self.pr["base"]["sha"] = "d" * 40
        with self.assertRaises(Refusal):self.check()
        self.pr["base"]["sha"] = old
        self.source_tip = "f" * 40
        with self.assertRaises(Refusal):self.check()
        self.source_tip = self.ns["STAGE_PINS"]["sourceSha"]
        self.history[CURRENT]["repository"]["private"] = True
        with self.assertRaises(Refusal):self.check()

    def test_fresh_job_attempt_run_binding_and_artifact_bytes_refuse(self):
        job = self.tables[CURRENT]["jobs"][0]
        for key, value in [("run_attempt", None), ("run_id", 99), ("labels", ["self-hosted"])]:
            old = job[key];job[key] = value
            with self.assertRaises(Refusal):self.check()
            job[key] = old
        self.artifacts[CURRENT] = [{"id": 5, "size_in_bytes": 64 * 1024 * 1024, "expired": False}]
        with self.assertRaises(Refusal):self.check()

    def test_ancillary45_bound_and_duplicate_ids_cannot_discount(self):
        rid = self.ancillary("completed", 46)
        with self.assertRaises(Refusal):self.check()
        self.tables[rid]["jobs"] = [self.job(rid, "fixed", 1)] * 2
        self.tables[rid]["total_count"] = 2
        with self.assertRaises(Refusal):self.check()

    def test_corrective_requires_genuine_first_controls_and_uses_new60_policy(self):
        rid = self.corrective()
        facts = self.check()
        self.assertEqual(facts["currentRoundBookedMinutes"], 355)
        self.assertEqual(facts["futureTargetedReserveMinutes"], 0)
        doctor = next(j for j in self.tables[rid]["jobs"] if j["name"] == "source (doctor-1)")
        doctor["started_at"] = instant(NOW - timedelta(minutes=60))
        self.assertGreater(self.check()["observedNewPriorRunnerMinutes"], facts["observedNewPriorRunnerMinutes"])
        self.ns["FIRST_PIPELINE"] = None
        with self.assertRaises(Refusal):self.check()

    def test_wrong_first_request_digest_or_unknown_current_refuses(self):
        self.corrective();self.ns["FIRST_REQUEST_SHA256"] = "0" * 64
        with self.assertRaises(Refusal):self.check()
        self.history.pop(CURRENT)
        with self.assertRaises(Refusal):self.check()

    def test_sensitive_workflow_security_refuses_without_byte_identical_requirement(self):
        path = self.root / self.ns["WORKFLOW"]
        for old, new in [(b"contents: read", b"contents: write"),
                         (b"max-parallel: 3", b"max-parallel: 4"),
                         (b"ubuntu-24.04", b"self-hosted"),
                         (b"pull_request:", b"workflow_dispatch:")]:
            path.write_bytes(self.workflow.replace(old, new, 1))
            with self.assertRaises(Refusal):self.check()
        path.write_bytes(self.workflow + b"\n# Reviewed non-security correction note.\n")
        self.assertEqual(self.check()["selectedProfileCount"], 7)

    def test_wrong_request_pins_or_duplicate_profiles_and_deadline_refuse(self):
        for key, value in [("sourceSha", "d" * 40), ("profiles", ["dependency", "dependency"])]:
            old = self.request[key];self.request[key] = value
            with self.assertRaises(ValueError):self.check()
            self.request[key] = old
        class Late(Clock):
            @classmethod
            def now(cls, tz=None):return datetime(2026, 10, 31, tzinfo=timezone.utc)
        self.ns["datetime"] = Late
        with self.assertRaises(Refusal):self.check()

    def test_duplicate_branch_record_and_missing_closed_id_refuse(self):
        self.history["duplicate-key"] = copy.deepcopy(self.history[CURRENT])
        with self.assertRaises(Refusal):self.check()
        self.history.pop("duplicate-key")
        rid = str(self.prefix["runs"][0]["id"])
        self.history.pop(rid)
        with self.assertRaises(Refusal):self.check()

    def test_corrective_full475_is_bounded_and_changed_first_source_refuses(self):
        self.corrective()
        self.request["profiles"] = list(self.ns["V4_INITIAL_PROFILES"])
        self.assertEqual(self.check()["currentRoundBookedMinutes"], 475)
        self.request["profiles"].append("doctor-2")
        with self.assertRaises(ValueError):self.check()
        self.request["profiles"] = ["dependency"]
        self.ns["STAGE_PINS"]["firstSourceSha"] = "e" * 40
        with self.assertRaises(ValueError):self.check()

    def test_queued_ancillary_missing_positive_zero_evidence_refuses(self):
        rid = self.ancillary()
        self.tables[rid]["jobs"][0].pop("runner_name")
        with self.assertRaises(Refusal):self.check()

    def test_actual_root_request_uses_current_pins_not_legacy_context(self):
        self.assertEqual(hashlib.sha256(self.current_request_raw).hexdigest(),
            "167466df439e6320f927681553ce7ad35f1b94afa5b2f81ab902a22b8a6a2d09")
        self.apply_actual_corrective()
        facts = self.check()
        self.assertEqual(facts["campaignRunnerMinuteCeiling"], 18000)
        self.assertEqual(facts["deadlineEpoch"], int(datetime(2026, 10, 30, 0, 3, 19, tzinfo=timezone.utc).timestamp()))

    def test_reviewed_extra_alphanumeric_quoted_flow_job_and_mapping_counterexamples_refuse(self):
        path = self.root / self.ns["WORKFLOW"]
        # The original exact-validator counterexample appended one extra1 job.
        extra = b"\n  extra1:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo synthetic\n"
        defaults = b"\n'defaults':\n  run:\n    shell: bash\n"
        quoted_use = b"      - 'uses': example/third-party@" + b"a" * 40 + b"\n"
        anchored_use = b"      - &extra {uses: example/third-party@" + b"a" * 40 + b"}\n"
        tagged_use = b"      - !<tag:example.test,2026:step> {uses: example/third-party@" + b"a" * 40 + b"}\n"
        candidates = [self.workflow + extra, self.workflow + defaults,
            self.workflow.replace(b"    steps:\n", b"    steps:\n" + quoted_use, 1),
            self.workflow.replace(b"    steps:\n", b"    steps:\n" + anchored_use, 1),
            self.workflow.replace(b"    steps:\n", b"    steps:\n" + tagged_use, 1),
            self.workflow + b"\n  'extra1':\n    runs-on: ubuntu-24.04\n",
            self.workflow + b"\n  extra1: {runs-on: ubuntu-24.04}\n",
            self.workflow.replace(b"      max-parallel: 3", b"      max-parallel: 3\n      'max-parallel': 4")]
        for i, candidate in enumerate(candidates):
            with self.subTest(counterexample=i):
                path.write_bytes(candidate)
                with self.assertRaises(Refusal):self.check()

    def test_corrective_cannot_omit_unresolved_or_unrun_first_profiles(self):
        rid = self.corrective()
        model = next(job for job in self.tables[rid]["jobs"] if job["name"] == "source (models-1)")
        model["conclusion"] = "failure"
        with self.assertRaises(Refusal):self.check()
        selected = self.request["profiles"]
        self.request["profiles"] = list(self.ns["V4_INITIAL_PROFILES"])
        self.assertEqual(self.check()["currentRoundBookedMinutes"], 475)
        self.assertEqual(self.check()["firstSourceReceipt"]["unresolvedProfiles"], ["models-1"])
        self.request["profiles"] = selected
        model["conclusion"] = "success"
        facts = self.check()
        self.assertEqual(facts["firstSourceReceipt"]["profileResults"]["models-1"], "success")
        self.assertEqual(facts["firstSourceReceipt"]["unresolvedProfiles"], [])
        self.tables[rid]["jobs"][0]["conclusion"] = "failure"
        self.tables[rid]["jobs"] = [j for j in self.tables[rid]["jobs"] if not j["name"].startswith("source (")]
        self.tables[rid]["total_count"] = len(self.tables[rid]["jobs"])
        with self.assertRaises(Refusal):self.check()

    def test_actual_provider_header_projection_excludes_derived_artifact_rows(self):
        self.assertEqual(sum("artifactRows" in row for row in self.prefix["runs"]), 42)
        self.assertTrue(all("artifactRows" not in row and "jobs" not in row and
                            "observedRunnerMinutes" not in row for row in self.history.values()))
        actual = next(row for row in self.prefix["runs"] if row["id"] == 40639371790)
        self.assertEqual(actual["artifactRows"], [])
        facts = self.check()
        self.assertEqual(len(facts["closedPrefixHeaderFields"]), 12)
        self.assertEqual(len(facts["historicalJobTableSha256"]), 99)
        self.assertEqual(facts["actualSettledRunnerMinutes"], 886)
        self.assertEqual(facts["closedArtifactBaselineProof"]["bytes"], 5600)

    def apply_actual_corrective(self):
        fixture_raw = (HERE / "test_history_v4_p5_failed_intake.json").read_bytes()
        self.assertEqual(hashlib.sha256(fixture_raw).hexdigest(),
            "6139e4b58edea66c7b514d89cba06522d9c72bbb96bc6f4167df5b456a18a9cd")
        fixture = json.loads(fixture_raw)
        self.assertEqual(fixture["sourceRunSha256"], "26c2108ebd9cf7880a4bc40f0ab07f66fc596e9be032423bc7f42518ba805e25")
        self.assertEqual(fixture["sourceJobTableSha256"], "d0fed2461c9b80b23bbf389433415beadb300e3445014116772a3cf3d451fde1")
        actual_run, actual_jobs = fixture["run"], fixture["jobs"]
        self.ns["STAGE_PINS"] = copy.deepcopy(self.current_pins)
        self.request = json.loads(self.current_request_raw)
        first_id = str(actual_run["id"])
        self.assertEqual(first_id, self.request["priorRunIds"][-1])
        self.assertEqual(actual_run["head_sha"], self.ns["FIRST_PIPELINE"])
        self.history[first_id] = actual_run
        self.history[CURRENT]["created_at"] = "2026-10-28T11:59:00Z"
        self.tables[first_id] = actual_jobs
        self.contents[self.ns["REQUEST"] + "?ref=" + actual_run["head_sha"]] = self.first_request_raw
        self.contents[self.ns["WORKFLOW"] + "?ref=" + actual_run["head_sha"]] = self.first_workflow_raw
        return first_id

    def test_actual_failed_p5_current_corrective_request_charges5_and_requires_all7(self):
        first_id = self.apply_actual_corrective()
        facts = self.check()
        self.assertEqual(facts["observedNewPriorRunnerMinutes"], 5)
        self.assertEqual(facts["bookedRunnerMinutes"], 1411)
        self.assertEqual((facts["currentRoundBookedMinutes"], facts["operatorRoundsRemaining"]), (475, 0))
        first = facts["firstSourceReceipt"]
        self.assertEqual(first["profileResults"], {})
        self.assertEqual(first["sourceProfilesAcquired"], 0)
        self.assertTrue(first["initialValidationNeverStarted"])
        self.assertEqual(set(first["unresolvedProfiles"]), set(self.request["profiles"]))
        self.assertEqual(len(first["unresolvedProfiles"]), 7)
        saved = copy.deepcopy(self.tables[first_id])
        literal = next(job for job in self.tables[first_id]["jobs"] if job["name"] == "source (${{ matrix.profile }})")
        literal["runner_id"] = 0
        with self.assertRaises(Refusal):self.check()
        self.tables[first_id] = copy.deepcopy(saved)
        self.tables[first_id]["jobs"] = [job for job in self.tables[first_id]["jobs"]
                                         if job["name"] != "source (${{ matrix.profile }})"]
        self.tables[first_id]["total_count"] = 2
        with self.assertRaises(Refusal):self.check()
        self.tables[first_id] = saved
        self.request["profiles"] = ["dependency", "types-tests", "types-scripts", "compatibility", "pipeline-contracts"]
        with self.assertRaises(Refusal):self.check()


if __name__ == "__main__":
    unittest.main()
