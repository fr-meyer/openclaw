"""Synthetic fourth-attempt binding checks; no network or image operations."""
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
import json
import unittest

import image_build_contract_v109 as contract


REQUEST = Path(__file__).parent / "candidates/v2026.10.9-image-only/image-request.json"
NOW = datetime(2026, 11, 7, 12, 0, tzinfo=timezone.utc).timestamp()
PRIOR = (
    (42239007307, "ccca07e2156a06ab5cd90badbf289442376d0ddf"),
    (42256250335, "f10e39a8995b4b7a8012d36757369641c6ca27c9"),
    (42325611737, "59960de8265b7bb378194d1269f035ef497f9ed6"),
)


def request():
    return json.loads(REQUEST.read_text())


def context():
    return {"repository": contract.REPOSITORY, "actor": contract.ACTOR,
        "event": "push", "ref": contract.REF, "sha": "a" * 40,
        "workflowSha": "a" * 40, "runId": "42330000000", "attempt": 1,
        "before": PRIOR[-1][1], "after": "a" * 40,
        "created": False, "deleted": False, "forced": False}


def history():
    x = context()
    rows = [{"id": int(x["runId"]), "path": contract.WORKFLOW, "event": "push",
        "head_branch": contract.BRANCH, "run_attempt": 1,
        "actor": {"login": contract.ACTOR}, "triggering_actor": {"login": contract.ACTOR},
        "head_sha": x["sha"], "status": "in_progress"}]
    jobs = {}
    for rid, sha in PRIOR:
        rows.append({"id": rid, "path": contract.WORKFLOW, "event": "push",
            "head_branch": contract.BRANCH, "run_attempt": 1,
            "actor": {"login": contract.ACTOR}, "triggering_actor": {"login": contract.ACTOR},
            "head_sha": sha, "status": "completed", "conclusion": "failure"})
        jobs[str(rid)] = {"total_count": 2, "jobs": [
            {"id": rid * 10 + 1, "name": "image-admission", "status": "completed",
                "conclusion": "failure", "run_id": rid},
            {"id": rid * 10 + 2, "name": "build-private-image", "status": "completed",
                "conclusion": "skipped", "run_id": rid, "steps": [],
                "runner_id": None, "runner_name": None}]}
    return {"total_count": 4, "workflow_runs": rows}, jobs


class FourthImageContractTests(unittest.TestCase):
    def refuse(self, fn, *args):
        with self.assertRaises(contract.Refusal):
            fn(*args)

    def test_exact_request_context_and_three_failed_admissions(self):
        req = request()
        contract.validate_request(req, active=True, now=NOW)
        contract.validate_context(context(), req, NOW)
        self.assertTrue(contract.validate_image_history(req, context(), *history()))

    def test_old_access_approval_or_missing_fourth_witness_refused(self):
        req = request()
        req["authorization"]["actionTimeAccessApprovalSha256"] = contract.THIRD_IMAGE_WORKFLOW_APPROVAL_SHA256
        self.refuse(contract.validate_request, req, True, NOW)
        req = request()
        req["retryAfterThirdFailedAdmission"]["runId"] = "42325611738"
        self.refuse(contract.validate_request, req, True, NOW)
        req = request()
        del req["retryAfterThirdFailedAdmission"]
        self.refuse(contract.validate_request, req, True, NOW)

    def test_prior_build_or_extra_or_unsettled_history_refused(self):
        for edit in ("physical", "extra", "unsettled", "wrong_head"):
            runs, jobs = history()
            if edit == "physical":
                jobs[str(PRIOR[-1][0])]["jobs"][1]["conclusion"] = "success"
            elif edit == "extra":
                runs["workflow_runs"].append(deepcopy(runs["workflow_runs"][-1]))
                runs["total_count"] = 5
            elif edit == "unsettled":
                runs["workflow_runs"][-1]["status"] = "in_progress"
            else:
                runs["workflow_runs"][-1]["head_sha"] = "b" * 40
            with self.subTest(edit=edit):
                self.refuse(contract.validate_image_history, request(), context(), runs, jobs)

    def test_previous_head_and_one_attempt_bound(self):
        x = context()
        x["before"] = PRIOR[-2][1]
        self.refuse(contract.validate_context, x, request(), NOW)
        x = context()
        x["attempt"] = 2
        self.refuse(contract.validate_context, x, request(), NOW)


if __name__ == "__main__":
    unittest.main()
