"""Synthetic campaign boundaries; no network, source lifecycle or application execution."""

import base64
import copy
from datetime import datetime, timezone
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("source_validation_v108", Path(__file__).with_name("source_validation_v108.py"))
driver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(driver)
NOW = datetime(2026, 10, 27, 12, tzinfo=timezone.utc)
HEAD = "a" * 40
OLD_HEAD = "b" * 40
MERGE = "c" * 40


def request(round_number=0, profiles=None, prior=None):
    return {"schema": "openclaw.fork-source-validation-request.v1", "campaignId": driver.CAMPAIGN,
            "round": round_number, "profiles": profiles or [], "sourceSha": driver.SOURCE,
            "sourceTree": driver.TREE, "manifestSha256": "d" * 64, "inventorySha256": "e" * 64,
            "priorRunIds": prior or []}


def event_env():
    repository = {"full_name": driver.REPOSITORY, "private": False}
    event = {"action": "synchronize", "number": 28, "repository": repository,
             "pull_request": {"number": 28, "state": "open", "draft": True,
                              "head": {"ref": driver.BRANCH, "sha": HEAD, "repo": repository},
                              "base": {"ref": driver.BASE_BRANCH, "sha": driver.BASE, "repo": repository}}}
    env = {"GITHUB_ACTIONS": "true", "RUNNER_OS": "Linux", "RUNNER_ENVIRONMENT": "github-hosted",
           "GITHUB_EVENT_NAME": "pull_request", "GITHUB_RUN_ATTEMPT": "1",
           "GITHUB_REPOSITORY": driver.REPOSITORY, "GITHUB_REF": "refs/pull/28/merge",
           "GITHUB_WORKFLOW_REF": driver.REPOSITORY + "/" + driver.WORKFLOW + "@refs/pull/28/merge",
           "GITHUB_WORKFLOW_SHA": MERGE, "GITHUB_RUN_ID": "102"}
    return copy.deepcopy(event), env


def run(run_id, sha, completed=False, created="2026-10-27T11:00:00Z"):
    return {"id": int(run_id), "event": "pull_request", "path": driver.WORKFLOW,
            "display_title": driver.CAMPAIGN, "run_attempt": 1,
            "repository": {"full_name": driver.REPOSITORY, "private": False},
            "head_repository": {"full_name": driver.REPOSITORY, "private": False}, "head_branch": driver.BRANCH,
            "head_sha": sha, "pull_requests": [{"number": 28}], "created_at": created,
            "status": "completed" if completed else "in_progress",
            "conclusion": "failure" if completed else None}


def job(name="admission", conclusion="success"):
    return {"name": name, "status": "completed", "conclusion": conclusion, "run_attempt": 1,
            "runner_id": 42, "runner_group_name": "GitHub Actions", "labels": ["ubuntu-24.04"],
            "started_at": "2026-10-27T11:00:00Z", "completed_at": "2026-10-27T11:01:00Z"}


def content(raw):
    return {"type": "file", "encoding": "base64", "size": len(raw),
            "content": base64.b64encode(raw).decode()}


class SourceValidationTests(unittest.TestCase):
    def refused(self, fn, *args):
        with self.assertRaises(driver.release.Refusal):
            fn(*args)

    def test_initial_and_two_targeted_requests_are_bounded(self):
        self.assertEqual(driver.round_minutes(driver.validate_request(request())), 800)
        second = request(1, ["types-production", "dependency"], ["101"])
        self.assertEqual(driver.round_minutes(driver.validate_request(second)), 170)
        third = request(2, ["workboard-1"], ["101", "102"])
        self.assertEqual(driver.round_minutes(driver.validate_request(third)), 80)
        self.assertEqual(len(driver.profiles_for(request())), 12)
        self.assertEqual(800 + 180 * 2 + driver.ANCILLARY_MINUTES + driver.RESERVE_MINUTES, 1800)

    def test_closed_request_rejects_commands_refs_urls_and_bad_types(self):
        for key, value in (("command", "docker build ."), ("ref", "main"), ("url", "https://evil.test"),
                           ("approval", True), ("secrets", [])):
            bad = request()
            bad[key] = value
            self.refused(driver.validate_request, bad)
        for field, value in (("round", True), ("round", 3), ("round", -1), ("sourceSha", HEAD),
                             ("sourceTree", OLD_HEAD), ("manifestSha256", "x" * 64),
                             ("inventorySha256", "e" * 64 + "\n"), ("campaignId", "different")):
            bad = request()
            bad[field] = value
            self.refused(driver.validate_request, bad)
        self.refused(driver.read_json, '{"round":0,"round":1}')

    def test_profile_budget_duplicate_round_and_unsafe_selection(self):
        for profiles in (["types-production", "types-tests"], ["dependency", "dependency"], [],
                         ["$(curl bad)"], ["../dependency"], ["dependency\ncommand"], ["--profile"]):
            self.refused(driver.validate_request, request(1, profiles, ["101"]))
        for prior in (["101", "101"], [101], ["../101"], ["101\n"], []):
            self.refused(driver.validate_request, request(1, ["dependency"], prior))
        self.refused(driver.validate_request, request(0, ["dependency"]))

    def test_only_exact_open_draft_public_same_repository_event(self):
        event, env = event_env()
        for action in ("opened", "reopened", "synchronize"):
            event["action"] = action
            self.assertEqual(driver.validate_event(event, env), HEAD)
        mutations = [lambda e: e.update(action="edited"), lambda e: e.update(number=29),
                     lambda e: e["pull_request"].update(draft=False),
                     lambda e: e["pull_request"].update(state="closed"),
                     lambda e: e["repository"].update(private=True),
                     lambda e: e["pull_request"]["head"]["repo"].update(full_name="other/openclaw"),
                     lambda e: e["pull_request"]["head"].update(ref="task/other"),
                     lambda e: e["pull_request"]["base"].update(sha=HEAD),
                     lambda e: e["pull_request"]["base"].update(ref="main")]
        for mutate in mutations:
            changed, _ = event_env()
            mutate(changed)
            self.refused(driver.validate_event, changed, env)

    def test_pr_snapshot_and_actual_target_are_distinct_exact_bindings(self):
        event, env = event_env()
        self.assertEqual(driver.BASE, "a65f70c5dad17b39bc3ee26ba92cde6d00bfb259")
        self.assertEqual(driver.TARGET_BRANCH_TIP, "918890b9f72b2d0372995362e8ea3088e0f87431")
        workflow = Path(__file__).resolve().parents[2] / driver.WORKFLOW
        self.assertIn("base.sha == '" + driver.BASE + "'", workflow.read_text())
        self.assertEqual(driver.validate_event(event, env), HEAD)
        event["pull_request"]["base"]["sha"] = driver.TARGET_BRANCH_TIP
        self.refused(driver.validate_event, event, env)

    def test_no_local_execution_dispatch_rerun_or_alternate_ref(self):
        event, env = event_env()
        for key, value in (("GITHUB_ACTIONS", "false"), ("RUNNER_OS", "macOS"),
                           ("RUNNER_ENVIRONMENT", "self-hosted"), ("GITHUB_EVENT_NAME", "workflow_dispatch"),
                           ("GITHUB_RUN_ATTEMPT", "2"), ("GITHUB_REF", "refs/heads/main"),
                           ("GITHUB_WORKFLOW_REF", "other/workflow"), ("GITHUB_WORKFLOW_SHA", "main")):
            self.refused(driver.validate_event, event, dict(env, **{key: value}))

    def test_workflow_and_executable_owners_bind_synthetic_merge_to_head(self):
        event, env = event_env()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = (driver.WORKFLOW, "scripts/fork-release/source_validation_v108.py",
                     "scripts/fork-release/preflight.py", "scripts/fork-release/release.py",
                     "scripts/fork-release/native_tests.mjs")
            for path in files:
                (root / path).parent.mkdir(parents=True, exist_ok=True)
                (root / path).write_bytes(b"reviewed")
            def git(_root, *args):
                if args == ("rev-parse", "HEAD"):
                    return (HEAD if _root == root else driver.SOURCE).encode()
                if args == ("rev-parse", "HEAD^{tree}"):
                    return driver.TREE.encode()
                if args == ("rev-parse", MERGE + "^1"):
                    return driver.TARGET_BRANCH_TIP.encode()
                return b"reviewed"
            with patch.object(driver, "git", side_effect=git), patch.object(driver, "acquire_workflow_commit"):
                driver.code_binding(root, root / "source", event, env)
            def drift(_root, *args):
                if args[0] == "show" and args[1].startswith(MERGE):
                    return b"synthetic merge drift"
                return git(_root, *args)
            with patch.object(driver, "git", side_effect=drift), patch.object(driver, "acquire_workflow_commit"):
                self.refused(driver.code_binding, root, root / "source", event, env)
            with patch.object(driver, "git", side_effect=lambda *a: b"wrong"):
                self.refused(driver.code_binding, root, root / "source", event, env)

    def test_absent_synthetic_merge_object_is_acquired_without_network_or_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            donor, pipeline = root / "donor", root / "pipeline"
            donor.mkdir()
            pipeline.mkdir()
            local_env = {"PATH": os.environ["PATH"], "GIT_CONFIG_NOSYSTEM": "1",
                         "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_AUTHOR_NAME": "Synthetic Fixture",
                         "GIT_AUTHOR_EMAIL": "fixture@example.invalid", "GIT_COMMITTER_NAME": "Synthetic Fixture",
                         "GIT_COMMITTER_EMAIL": "fixture@example.invalid"}
            def git_at(path, *args, input=None):
                return subprocess.check_output(["git", "-C", str(path), *args], input=input,
                                               env=local_env, stderr=subprocess.DEVNULL).decode().strip()
            git_at(donor, "init", "-q")
            tree = git_at(donor, "mktree", input=b"")
            base = git_at(donor, "commit-tree", tree, "-m", "base")
            head = git_at(donor, "commit-tree", tree, "-p", base, "-m", "head")
            side = git_at(donor, "commit-tree", tree, "-p", base, "-m", "base advance")
            merge = git_at(donor, "commit-tree", tree, "-p", side, "-p", head, "-m", "synthetic PR merge")
            git_at(donor, "update-ref", "refs/heads/head", head)
            git_at(donor, "update-ref", "refs/heads/pr-merge", merge)
            git_at(pipeline, "init", "-q")
            git_at(pipeline, "fetch", str(donor), "head")
            git_at(pipeline, "checkout", "--detach", "FETCH_HEAD")
            with self.assertRaises(subprocess.CalledProcessError):
                git_at(pipeline, "cat-file", "-t", merge)
            actual_run, fetches = subprocess.run, []
            def local_transport(argv, **kwargs):
                argv = list(argv)
                public = "https://github.com/fr-meyer/openclaw.git"
                if "fetch" in argv:
                    self.assertIn(public, argv)
                    self.assertEqual(argv[-1], merge)
                    fetches.append((list(argv), dict(kwargs["env"])))
                    argv[argv.index(public)] = str(donor)
                self.assertFalse(any("https://" in str(arg) for arg in argv))
                return actual_run(argv, **kwargs)
            with patch.object(driver.subprocess, "run", side_effect=local_transport):
                driver.acquire_workflow_commit(pipeline, head, {
                    "PATH": os.environ["PATH"], "GITHUB_WORKFLOW_SHA": merge,
                    "GH_SOURCE_READ_TOKEN": "never-forward-this", "HOME": "/operator/home"})
            self.assertEqual(git_at(pipeline, "rev-parse", "HEAD"), head)
            self.assertEqual(git_at(pipeline, "cat-file", "-t", merge), "commit")
            self.assertEqual(len(fetches), 1)
            self.assertEqual(set(fetches[0][1]), {"PATH", "GIT_TERMINAL_PROMPT", "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL"})
            with patch.object(driver.subprocess, "run") as never_fetch:
                self.refused(driver.acquire_workflow_commit, pipeline, head,
                             {"PATH": os.environ["PATH"], "GITHUB_WORKFLOW_SHA": "refs/pull/28/merge"})
                never_fetch.assert_not_called()

    def test_workflow_fetch_rejects_identity_drift(self):
        def absent_then_wrong(_root, *args):
            if args[0] == "cat-file":
                raise subprocess.CalledProcessError(1, ["git"])
            return OLD_HEAD.encode()
        with patch.object(driver, "git", side_effect=absent_then_wrong), patch.object(driver.subprocess, "run"):
            self.refused(driver.acquire_workflow_commit, Path("/synthetic"), HEAD,
                         {"PATH": "/usr/bin", "GITHUB_WORKFLOW_SHA": MERGE})

    def test_code_binding_checks_acquired_merge_first_parent_with_real_git(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            local_env = {"PATH": os.environ["PATH"], "GIT_CONFIG_NOSYSTEM": "1",
                         "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_AUTHOR_NAME": "Synthetic Fixture",
                         "GIT_AUTHOR_EMAIL": "fixture@example.invalid", "GIT_COMMITTER_NAME": "Synthetic Fixture",
                         "GIT_COMMITTER_EMAIL": "fixture@example.invalid"}
            def git_at(*args):
                return subprocess.check_output(["git", "-C", str(root), *args],
                                               env=local_env, stderr=subprocess.DEVNULL).decode().strip()
            git_at("init", "-q")
            for name in (driver.WORKFLOW, "scripts/fork-release/source_validation_v108.py",
                         "scripts/fork-release/preflight.py", "scripts/fork-release/release.py",
                         "scripts/fork-release/native_tests.mjs"):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"fixed reviewed executable")
            git_at("add", ".")
            tree = git_at("write-tree")
            target = git_at("commit-tree", tree, "-m", "target")
            head = git_at("commit-tree", tree, "-p", target, "-m", "reviewed head")
            merge = git_at("commit-tree", tree, "-p", target, "-p", head, "-m", "PR merge")
            wrong = git_at("commit-tree", tree, "-p", head, "-p", target, "-m", "wrong target parent")
            git_at("checkout", "--detach", head)
            event, env = event_env()
            event["pull_request"]["head"]["sha"] = head
            env["GITHUB_WORKFLOW_SHA"] = merge
            with patch.object(driver, "TARGET_BRANCH_TIP", target), patch.object(driver, "SOURCE", head), \
                 patch.object(driver, "TREE", tree):
                driver.code_binding(root, root, event, env)
                self.refused(driver.code_binding, root, root, event, dict(env, GITHUB_WORKFLOW_SHA=wrong))
            with patch.object(driver, "TARGET_BRANCH_TIP", head):
                self.refused(driver.code_binding, root, None, event, env)

    def history_fixture(self, root, current_request):
        event, env = event_env()
        (root / driver.WORKFLOW).parent.mkdir(parents=True)
        (root / driver.WORKFLOW).write_bytes(b"fixed workflow")
        previous = run("101", OLD_HEAD, completed=True)
        current = run("102", HEAD, created="2026-10-27T11:30:00Z")
        skipped = run(driver.SKIPPED_RUN_ID, driver.SKIPPED_HEAD, completed=True,
                      created="2026-10-27T10:30:00Z")
        skipped["conclusion"] = "skipped"
        skipped_jobs = [dict(job(name, "skipped"), runner_id=None, runner_name=None, steps=[])
                        for name in ("admission", "source (${{ matrix.profile }})", "final")]
        frozen_workflow = (Path(__file__).resolve().parents[2] / driver.WORKFLOW).read_bytes().replace(
            ("base.sha == '" + driver.BASE + "'").encode(),
            ("base.sha == '" + driver.TARGET_BRANCH_TIP + "'").encode())
        self.assertEqual(hashlib.sha256(frozen_workflow).hexdigest(), driver.SKIPPED_WORKFLOW_SHA256)
        jobs = [job(), job("final"), *[job("source (" + p + ")") for p in driver.profiles_for(request())]]
        runs = [current, *([previous] if current_request["round"] else []), skipped]
        responses = {
            "/pulls/28": event["pull_request"],
            "/git/ref/heads/" + driver.BASE_BRANCH:
                {"ref": "refs/heads/" + driver.BASE_BRANCH,
                 "object": {"type": "commit", "sha": driver.TARGET_BRANCH_TIP}},
            "/actions/workflows/" + Path(driver.WORKFLOW).name + "/runs?event=pull_request&per_page=100":
                {"total_count": len(runs), "workflow_runs": runs},
            "/contents/" + driver.REQUEST + "?ref=" + OLD_HEAD: content(json.dumps(request()).encode()),
            "/contents/" + driver.WORKFLOW + "?ref=" + OLD_HEAD: content(b"fixed workflow"),
            "/actions/runs/101/jobs?filter=all&per_page=100": {"total_count": len(jobs), "jobs": jobs},
            "/contents/" + driver.REQUEST + "?ref=" + driver.SKIPPED_HEAD: content(json.dumps(request()).encode()),
            "/contents/" + driver.WORKFLOW + "?ref=" + driver.SKIPPED_HEAD: content(frozen_workflow),
            "/actions/runs/" + driver.SKIPPED_RUN_ID + "/jobs?filter=all&per_page=100":
                {"total_count": len(skipped_jobs), "jobs": skipped_jobs},
        }
        def api(path):
            prefix = "/repos/" + driver.REPOSITORY
            self.assertTrue(path.startswith(prefix))
            return responses[path[len(prefix):]]
        return event, env, responses, api

    def test_live_history_accepts_ordered_terminal_round_and_ancestor_correction(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            req = request(1, ["dependency"], ["101"])
            event, env, responses, api = self.history_fixture(root, req)
            with patch.object(driver.subprocess, "run") as command, patch.object(driver, "datetime", wraps=datetime) as clock:
                clock.now.return_value = NOW
                budget = driver.history_checks(req, event, env, root, api)
            self.assertEqual(budget["bookedRunnerMinutes"], 94)
            self.assertEqual(budget["observedPriorRunnerMinutes"], 14)
            self.assertIn(OLD_HEAD, command.call_args.args[0])
            self.assertIn(HEAD, command.call_args.args[0])

    def test_live_history_refuses_duplicate_unlisted_rerun_unsettled_and_stale(self):
        for mutation in ("duplicate", "missing", "rerun", "running", "changed-pr", "changed-workflow",
                         "wrong-round", "incomplete-pages", "expired", "source-change", "unknown-job"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                req = request(1, ["dependency"], ["101"])
                event, env, responses, api = self.history_fixture(root, req)
                listing = responses["/actions/workflows/" + Path(driver.WORKFLOW).name + "/runs?event=pull_request&per_page=100"]
                old = listing["workflow_runs"][1]
                if mutation == "duplicate":
                    listing["workflow_runs"].append(run("103", HEAD))
                    listing["total_count"] += 1
                elif mutation == "missing":
                    listing["workflow_runs"].remove(old)
                    listing["total_count"] -= 1
                elif mutation == "rerun":
                    old["run_attempt"] = 2
                elif mutation == "running":
                    old["status"] = "in_progress"
                elif mutation == "changed-pr":
                    responses["/pulls/28"]["head"]["sha"] = MERGE
                    event = copy.deepcopy(event)
                    event["pull_request"]["head"]["sha"] = HEAD
                elif mutation == "changed-workflow":
                    responses["/contents/" + driver.WORKFLOW + "?ref=" + OLD_HEAD] = content(b"changed")
                elif mutation in ("wrong-round", "source-change"):
                    bad = request()
                    bad["round" if mutation == "wrong-round" else "sourceSha"] = 1 if mutation == "wrong-round" else HEAD
                    responses["/contents/" + driver.REQUEST + "?ref=" + OLD_HEAD] = content(json.dumps(bad).encode())
                elif mutation == "incomplete-pages":
                    listing["total_count"] = 101
                elif mutation == "expired":
                    old["created_at"] = "2026-10-25T10:00:00Z"
                else:
                    responses["/actions/runs/101/jobs?filter=all&per_page=100"]["jobs"][0]["name"] = "publish"
                with patch.object(driver.subprocess, "run"), patch.object(driver, "datetime", wraps=datetime) as clock:
                    clock.now.return_value = NOW
                    self.refused(driver.history_checks, req, event, env, root, api)

    def test_exact_skipped_admission_retained_without_consuming_initial_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            req = request()
            event, env, responses, api = self.history_fixture(root, req)
            with patch.object(driver.subprocess, "run") as ancestry, \
                 patch.object(driver, "datetime", wraps=datetime) as clock:
                clock.now.return_value = NOW
                budget = driver.history_checks(req, event, env, root, api)
            ancestry.assert_not_called()
            self.assertEqual(budget["bookedRunnerMinutes"], 800)
            self.assertEqual(budget["observedPriorRunnerMinutes"], 0)
            self.assertEqual(budget["retainedSkippedAdmissions"], [{
                "runId": driver.SKIPPED_RUN_ID, "headSha": driver.SKIPPED_HEAD, "status": "skipped",
                "bookedRunnerMinutes": 0, "observedRunnerMinutes": 0}])
            skipped_jobs = responses["/actions/runs/" + driver.SKIPPED_RUN_ID + "/jobs?filter=all&per_page=100"]
            for item in skipped_jobs["jobs"]:
                item["runner_id"] = 0
            with patch.object(driver, "datetime", wraps=datetime) as clock:
                clock.now.return_value = NOW
                self.assertEqual(driver.history_checks(req, event, env, root, api)["bookedRunnerMinutes"], 800)

    def test_skipped_admission_retains_only_exact_run_request_workflow_and_zero_work(self):
        mutations = ("missing-run", "unknown-run", "duplicate-run", "head", "status", "conclusion",
                     "attempt", "event", "path", "title", "repository", "private", "head-repository",
                     "head-private", "branch", "pr", "workflow", "missing-workflow", "manifest",
                     "inventory", "source", "tree", "round", "profiles", "prior", "extra-request",
                     "missing-request", "job-name", "duplicate-job", "missing-job", "extra-job",
                     "job-status", "job-conclusion", "job-attempt", "runner", "runner-name", "steps",
                     "missing-runner", "missing-runner-name", "missing-steps", "missing-jobs")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                req = request()
                event, env, responses, api = self.history_fixture(root, req)
                listing = responses["/actions/workflows/" + Path(driver.WORKFLOW).name + "/runs?event=pull_request&per_page=100"]
                skipped = listing["workflow_runs"][-1]
                jobs = responses["/actions/runs/" + driver.SKIPPED_RUN_ID + "/jobs?filter=all&per_page=100"]
                first = jobs["jobs"][0]
                old_request = request()
                if mutation == "missing-run":
                    listing["workflow_runs"].pop()
                    listing["total_count"] -= 1
                elif mutation == "unknown-run":
                    skipped["id"] += 1
                elif mutation == "duplicate-run":
                    listing["workflow_runs"].append(copy.deepcopy(skipped))
                    listing["total_count"] += 1
                elif mutation in ("head", "status", "conclusion", "attempt", "event", "path", "title", "branch"):
                    key, value = {"head": ("head_sha", OLD_HEAD), "status": ("status", "in_progress"),
                                  "conclusion": ("conclusion", "failure"), "attempt": ("run_attempt", 2),
                                  "event": ("event", "workflow_dispatch"), "path": ("path", "other.yml"),
                                  "title": ("display_title", "other"), "branch": ("head_branch", "other")}[mutation]
                    skipped[key] = value
                elif mutation in ("repository", "private", "head-repository", "head-private"):
                    key = "head_repository" if mutation.startswith("head-") else "repository"
                    skipped[key]["private" if mutation.endswith("private") else "full_name"] = (
                        True if mutation.endswith("private") else "other/openclaw")
                elif mutation == "pr":
                    skipped["pull_requests"][0]["number"] = 29
                elif mutation in ("workflow", "missing-workflow"):
                    responses["/contents/" + driver.WORKFLOW + "?ref=" + driver.SKIPPED_HEAD] = (
                        content(b"changed workflow") if mutation == "workflow" else {})
                elif mutation in ("manifest", "inventory", "source", "tree", "round", "profiles", "prior", "extra-request", "missing-request"):
                    if mutation == "missing-request":
                        responses["/contents/" + driver.REQUEST + "?ref=" + driver.SKIPPED_HEAD] = {}
                    else:
                        key, value = {"manifest": ("manifestSha256", "f" * 64),
                                      "inventory": ("inventorySha256", "f" * 64), "source": ("sourceSha", HEAD),
                                      "tree": ("sourceTree", HEAD), "round": ("round", 1),
                                      "profiles": ("profiles", ["dependency"]), "prior": ("priorRunIds", ["101"]),
                                      "extra-request": ("command", "anything")}[mutation]
                        old_request[key] = value
                        responses["/contents/" + driver.REQUEST + "?ref=" + driver.SKIPPED_HEAD] = content(json.dumps(old_request).encode())
                elif mutation == "job-name":
                    first["name"] = "source (dependency)"
                elif mutation == "duplicate-job":
                    jobs["jobs"][1]["name"] = first["name"]
                elif mutation in ("missing-job", "extra-job"):
                    if mutation == "missing-job":
                        jobs["jobs"].pop()
                    else:
                        jobs["jobs"].append(copy.deepcopy(first))
                    jobs["total_count"] = len(jobs["jobs"])
                elif mutation in ("job-status", "job-conclusion", "job-attempt", "runner", "runner-name", "steps"):
                    key, value = {"job-status": ("status", "queued"), "job-conclusion": ("conclusion", "success"),
                                  "job-attempt": ("run_attempt", 2), "runner": ("runner_id", 42),
                                  "runner-name": ("runner_name", "acquired"),
                                  "steps": ("steps", [{"name": "checkout", "conclusion": "skipped"}])}[mutation]
                    first[key] = value
                elif mutation == "missing-jobs":
                    jobs.pop("jobs")
                else:
                    first.pop({"missing-runner": "runner_id", "missing-runner-name": "runner_name",
                               "missing-steps": "steps"}[mutation])
                with patch.object(driver.subprocess, "run"), patch.object(driver, "datetime", wraps=datetime) as clock:
                    clock.now.return_value = NOW
                    self.refused(driver.history_checks, req, event, env, root, api)

    def test_live_target_ref_requires_exact_positive_commit_identity(self):
        for target in ({}, {"ref": "refs/heads/other", "object": {"type": "commit", "sha": driver.TARGET_BRANCH_TIP}},
                       {"ref": "refs/heads/" + driver.BASE_BRANCH, "object": {"type": "commit", "sha": driver.BASE}},
                       {"ref": "refs/heads/" + driver.BASE_BRANCH, "object": {"type": "tag", "sha": driver.TARGET_BRANCH_TIP}}):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                req = request()
                event, env, responses, api = self.history_fixture(root, req)
                responses["/git/ref/heads/" + driver.BASE_BRANCH] = target
                self.refused(driver.history_checks, req, event, env, root, api)

    def test_both_targeted_execution_rounds_remain_bounded_after_retained_skip(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            req = request(2, ["workboard-1"], ["101", "103"])
            event, env, responses, api = self.history_fixture(root, req)
            listing = responses["/actions/workflows/" + Path(driver.WORKFLOW).name + "/runs?event=pull_request&per_page=100"]
            listing["workflow_runs"].insert(1, run("103", MERGE, completed=True, created="2026-10-27T11:15:00Z"))
            listing["total_count"] += 1
            previous = request(1, ["dependency"], ["101"])
            responses["/contents/" + driver.REQUEST + "?ref=" + MERGE] = content(json.dumps(previous).encode())
            responses["/contents/" + driver.WORKFLOW + "?ref=" + MERGE] = content(b"fixed workflow")
            jobs = [job(), job("source (dependency)"), job("final")]
            responses["/actions/runs/103/jobs?filter=all&per_page=100"] = {"total_count": 3, "jobs": jobs}
            with patch.object(driver.subprocess, "run"), patch.object(driver, "datetime", wraps=datetime) as clock:
                clock.now.return_value = NOW
                budget = driver.history_checks(req, event, env, root, api)
            self.assertEqual(budget["bookedRunnerMinutes"], 97)
            self.assertEqual(budget["observedPriorRunnerMinutes"], 17)
            self.assertEqual(len(budget["retainedSkippedAdmissions"]), 1)

    def test_approval_deadline_caps_first_run_window_and_cannot_be_extended(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            req = request()
            event, env, responses, api = self.history_fixture(root, req)
            listing = responses["/actions/workflows/" + Path(driver.WORKFLOW).name + "/runs?event=pull_request&per_page=100"]
            listing["workflow_runs"][-1]["created_at"] = "2026-10-28T00:13:04Z"
            listing["workflow_runs"][0]["created_at"] = "2026-10-28T00:20:00Z"
            with patch.object(driver, "datetime", wraps=datetime) as clock:
                clock.now.return_value = datetime(2026, 10, 28, 1, tzinfo=timezone.utc)
                budget = driver.history_checks(req, event, env, root, api)
                self.assertEqual(budget["deadlineEpoch"], int(driver.timestamp(driver.APPROVAL_DEADLINE).timestamp()))
                # The run is still inside 24h here; the explicit approval has expired.
                clock.now.return_value = datetime(2026, 10, 29, 0, 3, 20, tzinfo=timezone.utc)
                self.refused(driver.history_checks, req, event, env, root, api)
                # An enlarged environment value cannot extend a source job either.
                clock.now.return_value = datetime(2026, 10, 28, 23, 30, tzinfo=timezone.utc)
                self.refused(driver.deadline_check, {"SOURCE_DEADLINE_EPOCH": "9999999999"}, "dependency")
            with patch.object(driver, "datetime", wraps=datetime) as clock:
                clock.now.return_value = NOW
                listing["workflow_runs"][-1]["created_at"] = "2026-10-27T10:30:00Z"
                listing["workflow_runs"][0]["created_at"] = "2026-10-27T11:30:00Z"
                self.assertEqual(driver.history_checks(req, event, env, root, api)["deadlineEpoch"],
                                 int(driver.timestamp("2026-10-28T10:30:00Z").timestamp()))

    def test_observed_runner_minutes_fail_closed_for_attempt_duration_platform_and_pages(self):
        base = {"total_count": 2, "jobs": [job(), job("final")]}
        self.assertEqual(driver.observed_minutes(base, []), 2)
        for mutate in (lambda j: j.update(total_count=101),
                       lambda j: j["jobs"][0].update(run_attempt=2),
                       lambda j: j["jobs"][0].update(completed_at="2026-10-27T12:00:00Z"),
                       lambda j: j["jobs"][0].update(labels=["self-hosted", "ubuntu-24.04"]),
                       lambda j: j["jobs"][0].update(runner_group_name="larger-runners")):
            bad = copy.deepcopy(base)
            mutate(bad)
            self.refused(driver.observed_minutes, bad, [])

    def test_child_environment_has_no_token_home_credentials_cloud_or_prebuilt_override(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent = {"PATH": "/usr/bin", "HOME": "/private/operator", "GITHUB_TOKEN": "secret",
                      "GH_SOURCE_READ_TOKEN": "secret", "AWS_ACCESS_KEY_ID": "secret",
                      "GOOGLE_APPLICATION_CREDENTIALS": "/private/key", "NODE_OPTIONS": "--import bad",
                      "OPENCLAW_E2E_SKIP_BUILD": "1", "OPENAI_API_KEY": "secret"}
            child = driver.clean_env(root, parent)
            self.assertEqual(child["HOME"], directory)
            self.assertEqual(child["PATH"], "/usr/bin")
            for key in parent:
                if key not in ("PATH", "HOME"):
                    self.assertNotIn(key, child)
            self.assertTrue(Path(child["OPENCLAW_STATE_DIR"]).is_dir())

    def test_admission_output_and_job_environment_bind_both_source_commands_to_deadline(self):
        event, env = event_env()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            event_path, output = root / "event.json", root / "output"
            event_path.write_text(json.dumps(event))
            env.update(GITHUB_EVENT_PATH=str(event_path), GITHUB_OUTPUT=str(output),
                       GH_SOURCE_READ_TOKEN="synthetic-read-only-token")
            deadline = int(NOW.timestamp()) + 86400
            with patch.dict(os.environ, env, clear=True), \
                 patch.object(sys, "argv", ["source_validation_v108.py", "admit", "--pipeline-dir", directory,
                                            "--source-dir", directory]), \
                 patch.object(driver, "metadata", return_value=(request(), {}, "d" * 64)), \
                 patch.object(driver, "code_binding"), patch.object(driver, "fetch_closure"), \
                 patch.object(driver, "history_checks", return_value={"deadlineEpoch": deadline}), \
                 patch.object(driver, "summarize"):
                self.assertEqual(driver.main(), 0)
            self.assertIn("deadline_epoch=" + str(deadline) + "\n", output.read_text())
        workflow = (Path(__file__).resolve().parents[2] / driver.WORKFLOW).read_text()
        self.assertIn("deadline_epoch: ${{ steps.admit.outputs.deadline_epoch }}", workflow)
        source_job = workflow.split("\n  source:\n", 1)[1].split("\n  final:\n", 1)[0]
        job_prefix = source_job.split("    strategy:\n", 1)[0]
        self.assertIn("    env:\n      SOURCE_PROFILE: ${{ matrix.profile }}\n"
                      "      SOURCE_DEADLINE_EPOCH: ${{ needs.admission.outputs.deadline_epoch }}", job_prefix)
        self.assertIn("source_validation_v108.py fetch-closure", source_job)
        self.assertIn("source_validation_v108.py run", source_job)
        with patch.object(driver, "datetime", wraps=datetime) as clock:
            clock.now.return_value = NOW
            driver.deadline_check({"SOURCE_DEADLINE_EPOCH": str(int(NOW.timestamp()) + 5400)}, "types-production")
            self.refused(driver.deadline_check, {"SOURCE_DEADLINE_EPOCH": str(int(NOW.timestamp()) + 5399)},
                         "types-production")
            self.refused(driver.deadline_check, {}, "dependency")

    def test_fixed_argv_uses_maintained_owners_and_never_pr_commands_or_docker(self):
        paths = ["extensions/workboard/src/store.test.ts", "extensions/workboard/src/cli.test.ts",
                 "src/agents/model-fallback.test.ts", "src/agents/model-fallback.live.test.ts",
                 "src/agents/utility-completion.runtime.test.ts", "extensions/workboard/../../bad.test.ts",
                 "extensions/workboard/src/command.test.ts\n--eval"]
        selected = driver.selected_tests(paths, "workboard-1") + driver.selected_tests(paths, "workboard-2")
        self.assertEqual(set(selected), set(paths[:2]))
        self.assertNotIn(paths[3], driver.selected_tests(paths, "models-1") + driver.selected_tests(paths, "models-2"))
        argv = driver.commands(Path("/pipeline"), Path("/source"), "workboard-1", paths)[0]
        self.assertEqual(argv[:4], ["node", "--import", "./scripts/tsx.mjs", "scripts/test-projects.mts"])
        self.assertEqual(driver.commands(Path("/p"), Path("/s"), "types-tests", []), [["pnpm", "tsgo:test"]])
        self.refused(driver.commands, Path("/p"), Path("/s"), "docker build", paths)
        source = Path(driver.__file__).read_text()
        self.assertNotIn("shell=True", source)
        for command in ("docker", "buildx", "gcloud", "ssh", "npm publish"):
            self.assertNotIn('["' + command + '"', source)

    def test_full_and_production_audits_preserve_all_dependency_regressions_after_failure(self):
        names = ("zod-container-bounds", "a2ui-native-zod-regression", "discord-native-zod-regression",
                 "body-parser-security", "msal-parent-compat", "undici-security",
                 "mcp-nowistay-schema-compatibility", "mcp-nowistay-sdk-regression", "http-cache-semantics-compat")
        paths = ["test/" + name + ".test.mjs" for name in names]
        planned = driver.commands(Path("/pipeline"), Path("/source"), "dependency", paths)
        self.assertEqual(planned[:2], [["pnpm", "audit"], ["pnpm", "audit", "--prod"]])
        self.assertEqual(set(planned[2][planned[2].index("--") + 1:]), set(paths))
        with patch.object(driver.subprocess, "run", side_effect=[SimpleNamespace(returncode=c) for c in (1, 2, 0)]) as runner:
            outcomes = driver.run_commands(planned, Path("/source"), {"PATH": "/synthetic"})
        self.assertEqual(outcomes, [1, 2, 0])
        self.assertTrue(any(outcomes))
        self.assertEqual([call.args[0] for call in runner.call_args_list], planned)

    def test_resource_floors_and_refusal_before_any_dependency_install(self):
        with patch.object(Path, "read_text", return_value="MemAvailable: 8388608 kB\n"), \
             patch.object(driver.shutil, "disk_usage", return_value=SimpleNamespace(free=8 * 1024 ** 3)), \
             patch.object(driver.os, "cpu_count", return_value=4):
            self.assertEqual(driver.resource_check(Path("/synthetic"))["logicalCpus"], 4)
            for memory, disk, cpus in (("8388607", 8 * 1024 ** 3, 4), ("8388608", 8 * 1024 ** 3 - 1, 4),
                                       ("8388608", 8 * 1024 ** 3, 3)):
                with patch.object(Path, "read_text", return_value="MemAvailable: " + memory + " kB\n"), \
                     patch.object(driver.shutil, "disk_usage", return_value=SimpleNamespace(free=disk)), \
                     patch.object(driver.os, "cpu_count", return_value=cpus):
                    self.refused(driver.resource_check, Path("/synthetic"))
        event, env = event_env()
        with tempfile.TemporaryDirectory() as directory:
            event_path = Path(directory) / "event.json"
            event_path.write_text(json.dumps(event))
            env.update(GITHUB_EVENT_PATH=str(event_path))
            with patch.dict(os.environ, env, clear=True), \
                 patch.object(sys, "argv", ["source_validation_v108.py", "run", "--pipeline-dir", directory,
                                            "--source-dir", directory, "--profile", "types-tests"]), \
                 patch.object(driver, "metadata", return_value=(request(), {}, "d" * 64)), \
                 patch.object(driver, "code_binding"), patch.object(driver, "deadline_check"), \
                 patch.object(driver, "source_preflight"), patch.object(driver, "git", return_value=b""), \
                 patch.object(driver, "resource_check", side_effect=driver.release.Refusal("insufficient fixture resources")), \
                 patch.object(driver.subprocess, "run") as install:
                self.refused(driver.main)
                install.assert_not_called()

    def test_new_workflow_has_only_fixed_source_surface_and_read_permissions(self):
        root = Path(__file__).resolve().parents[2]
        text = (root / driver.WORKFLOW).read_text()
        self.assertIn("types: [opened, reopened, synchronize]", text)
        self.assertIn("group: " + driver.CAMPAIGN, text)
        self.assertIn("cancel-in-progress: false", text)
        self.assertIn("max-parallel: 3", text)
        self.assertIn("timeout-minutes: ${{ matrix.minutes }}", text)
        for line in text.splitlines():
            if "runs-on:" in line:
                self.assertEqual(line.strip(), "runs-on: ubuntu-24.04")
            if "persist-credentials:" in line:
                self.assertTrue(line.endswith("false"))
            if "uses:" in line:
                self.assertTrue(any(pin in line for pin in (
                    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
                    "actions/setup-node@820762786026740c76f36085b0efc47a31fe5020")))
            if line.strip().endswith(": write"):
                self.fail("write permission")
        for forbidden in ("workflow_dispatch:", "pull_request_target:", "secrets.", "id-token:",
                          "attestations:", "upload-artifact@", "actions/cache@", "docker/", "buildx",
                          "github.event.pull_request.body", "github.event.pull_request.title",
                          "self-hosted", "OPENCLAW_E2E_SKIP_BUILD", "OPENCLAW_E2E_USE_PREBUILT_DIST"):
            self.assertNotIn(forbidden, text)
        self.assertEqual(text.count("GH_SOURCE_READ_TOKEN:"), 1)
        self.assertIn("package-manager-cache: false", text)


if __name__ == "__main__":
    unittest.main()
