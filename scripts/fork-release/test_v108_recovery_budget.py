"""Synthetic terminal-usage accounting for the one known bootstrap repair."""

import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_source_validation_v108 as support

driver = support.driver
RECOVERY_RUN = "40609889437"
RECOVERY_HEAD = "1328661613052dfa09902e1d1d080fa8e6ccd89d"
NOW = datetime(2026, 10, 28, 2, 5, tzinfo=timezone.utc)


class RecoveryBudgetTests(unittest.TestCase):
    def refused(self, fn, *args):
        with self.assertRaises(driver.release.Refusal):
            fn(*args)

    def recovery_request(self):
        return support.request(1, list(driver.PROFILE_MINUTES), [RECOVERY_RUN])

    def fixture(self, root):
        req = self.recovery_request()
        helper = support.SourceValidationTests()
        event, env, responses, api = helper.history_fixture(root, req)
        key = "/actions/workflows/" + Path(driver.WORKFLOW).name + "/runs?event=pull_request&per_page=100"
        runs = responses[key]["workflow_runs"]
        old = next(r for r in runs if r["id"] == 101)
        old.update(id=int(RECOVERY_RUN), head_sha=RECOVERY_HEAD, conclusion="cancelled",
                   created_at="2026-10-28T00:37:00Z")
        next(r for r in runs if str(r["id"]) == driver.SKIPPED_RUN_ID)["created_at"] = "2026-10-28T00:13:04Z"
        next(r for r in runs if r["id"] == 102)["created_at"] = "2026-10-28T02:00:00Z"
        for path in (driver.REQUEST, driver.WORKFLOW):
            responses["/contents/" + path + "?ref=" + RECOVERY_HEAD] = responses.pop(
                "/contents/" + path + "?ref=" + support.OLD_HEAD)
        jobs = responses.pop("/actions/runs/101/jobs?filter=all&per_page=100")
        for i, job in enumerate(jobs["jobs"]):
            job["started_at"] = (datetime(2026, 10, 28, 0, 40, tzinfo=timezone.utc) + timedelta(minutes=i)).isoformat().replace("+00:00", "Z")
            job["completed_at"] = (datetime(2026, 10, 28, 0, 41, tzinfo=timezone.utc) + timedelta(minutes=i)).isoformat().replace("+00:00", "Z")
            if job["name"] != "admission":
                job["conclusion"] = "failure"
        for job in jobs["jobs"][-3:]:
            job.update(conclusion="cancelled", runner_id=0, runner_name="", runner_group_name=None, steps=[])
        responses["/actions/runs/" + RECOVERY_RUN + "/jobs?filter=all&per_page=100"] = jobs
        return req, event, env, responses, api, old, jobs

    def test_full_recheck_only_for_fixed_global_bootstrap_repair(self):
        req = self.recovery_request()
        self.assertEqual(driver.round_minutes(driver.validate_request(req)), 800)
        for prior, number in ((["101"], 1), ([RECOVERY_RUN, "102"], 2)):
            self.refused(driver.validate_request, support.request(number, list(driver.PROFILE_MINUTES), prior))
        self.refused(driver.validate_request, support.request(1, list(reversed(driver.PROFILE_MINUTES)), [RECOVERY_RUN]))

    def test_zero_runner_cancellation_requires_positive_explicit_fields(self):
        admitted = support.job("admission", "failure")
        cancelled = dict(support.job("final", "cancelled"), runner_id=0, runner_name="", runner_group_name=None, steps=[])
        jobs = {"total_count": 2, "jobs": [admitted, cancelled]}
        self.assertEqual(driver.observed_minutes(jobs, []), 1)
        for field in ("runner_id", "runner_name", "steps"):
            changed = copy.deepcopy(jobs)
            changed["jobs"][1].pop(field)
            self.refused(driver.observed_minutes, changed, [])
        for field, value in (("runner_id", False), ("runner_name", "a-runner"), ("steps", [{"name": "executed"}])):
            changed = copy.deepcopy(jobs)
            changed["jobs"][1][field] = value
            self.refused(driver.observed_minutes, changed, [])

    def test_measured_terminal_usage_plus_current_max_is_booked(self):
        with tempfile.TemporaryDirectory() as directory:
            req, event, env, responses, api, old, jobs = self.fixture(Path(directory))
            with patch.object(driver.subprocess, "run"), patch.object(driver, "datetime", wraps=datetime) as clock:
                clock.now.return_value = NOW
                budget = driver.history_checks(req, event, env, Path(directory), api)
            self.assertEqual(budget["observedPriorRunnerMinutes"], 11)
            self.assertEqual(budget["bookedRunnerMinutes"], 811)
            self.assertLessEqual(budget["bookedRunnerMinutes"] + driver.ANCILLARY_MINUTES + driver.RESERVE_MINUTES, 1800)
            self.assertEqual(budget["deadlineEpoch"], int(driver.timestamp(driver.APPROVAL_DEADLINE).timestamp()))

    def test_full_recovery_still_requires_known_head_and_terminal_failure(self):
        for mutation in ("head", "running", "success"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                req, event, env, responses, api, old, jobs = self.fixture(Path(directory))
                if mutation == "head":
                    old["head_sha"] = support.OLD_HEAD
                elif mutation == "running":
                    old["status"] = "in_progress"
                else:
                    old["conclusion"] = "success"
                with patch.object(driver.subprocess, "run"), patch.object(driver, "datetime", wraps=datetime) as clock:
                    clock.now.return_value = NOW
                    self.refused(driver.history_checks, req, event, env, Path(directory), api)

    def test_prior_real_usage_cannot_be_discounted_to_fit_total(self):
        with tempfile.TemporaryDirectory() as directory:
            req, event, env, responses, api, old, jobs = self.fixture(Path(directory))
            limits = {"admission": 15, "final": 5, **{"source (" + p + ")": m for p, m in driver.PROFILE_MINUTES.items()}}
            for job in jobs["jobs"]:
                start = driver.timestamp(job["started_at"])
                job.update(runner_id=42, runner_name="hosted", runner_group_name="GitHub Actions", labels=["ubuntu-24.04"], steps=[])
                job["completed_at"] = (start + timedelta(minutes=limits[job["name"]])).isoformat().replace("+00:00", "Z")
            with patch.object(driver.subprocess, "run"), patch.object(driver, "datetime", wraps=datetime) as clock:
                clock.now.return_value = NOW
                self.refused(driver.history_checks, req, event, env, Path(directory), api)

    def test_third_execution_round_and_source_repin_remain_refused(self):
        self.refused(driver.validate_request, support.request(3, ["dependency"], ["101", "102", "103"]))
        changed = self.recovery_request()
        changed["sourceSha"] = support.HEAD
        self.refused(driver.validate_request, changed)


if __name__ == "__main__":
    unittest.main()
