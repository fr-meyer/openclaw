"""Synthetic replies and disposable local Git fixtures; never invokes Codex or GitHub."""

import argparse
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("fork_codex_review", Path(__file__).with_name("fork-codex-review.py"))
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)
BASE, HEAD, LOCAL, MERGE, TREE = (letter * 40 for letter in "abcde")


class Fixture:
    def __init__(self, root):
        root = root.resolve()
        self.root = root
        self.checkout = root / "source"
        self.checkout.mkdir()
        self.anchor = root / "anchor"
        self.helper = self.anchor / gate.HELPER
        self.helper.parent.mkdir(parents=True)
        self.helper.write_text("def tracked_sensitive_paths(paths):\n    return {p for p in paths if p == '.env'}\n")
        self.bin = root / "bin"
        self.bin.mkdir()
        for name in ("git", "gh", "codex"):
            (self.bin / name).write_text("synthetic tool, never executed\n")
        self.args = argparse.Namespace(checkout=str(self.checkout), repository=gate.FORK,
                                       host="github.com", pr=20, base_sha=BASE, head_sha=HEAD)
        self.status = {"schema_version": 1, "status": "scoped-clean", "exit_code": 0,
                       "engine": "codex", "report_produced": True, "reason": None,
                       "reviewer_exit_code": None, "timed_out": False}
        self.report = {"findings": [], "overall_correctness": "patch is correct",
                       "overall_explanation": "Synthetic complete assessment.", "review_status": "scoped-clean"}
        self.pr = {"number": 20, "state": "open", "draft": False,
                   "base": {"sha": BASE, "ref": "main", "repo": {"full_name": gate.FORK}},
                   "head": {"sha": HEAD, "ref": "task/example",
                            "repo": {"id": 123, "full_name": gate.FORK, "private": False,
                                     "html_url": f"https://github.com/{gate.FORK}"}}}
        self.after = False
        self.local = HEAD
        self.dirty = False
        self.mismatch = None
        self.on_review = lambda: None
        self.returncode = 0
        self.calls = []
        self.evidence = []
        self.changed_paths = b"example.py\0"
        self.environment = {"PATH": str(self.bin), "HOME": str(root / "home"),
                            "AUTOREVIEW_ENGINE": "claude", "AUTOREVIEW_MAX_PRIORITY": "P0",
                            "AUTOREVIEW_GIT": "/untrusted/git", "CODEX_BIN": "/untrusted/codex",
                            "GH_HOST": "wrong.example", "GH_REPO": "wrong/repository",
                            "GIT_DIR": "/wrong", "PYTHONPATH": "/wrong", "GH_TOKEN": "synthetic-auth"}

    def runner(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        name = Path(argv[0]).name
        if argv[0] == sys.executable:
            for option, value in (("--json-output", self.report), ("--status-output", self.status)):
                Path(argv[argv.index(option) + 1]).write_text(json.dumps(value))
            Path(argv[argv.index("--output") + 1]).write_text("Synthetic clean review\n")
            kwargs["stdout"].write(b"Synthetic isolated reviewer completed\n")
            self.after = True
            self.on_review()
            return subprocess.CompletedProcess(argv, self.returncode)
        if name == "gh":
            self.assert_gh(argv, kwargs)
            return subprocess.CompletedProcess(argv, 0, json.dumps(self.pr).encode())
        if name != "git":
            raise AssertionError(argv)
        command = argv[4:]
        if command == ["rev-parse", "--show-toplevel"]:
            value = str(self.checkout)
        elif command[0] == "status":
            value = " M changed.py" if self.dirty else ""
        elif command == ["rev-parse", "HEAD"]:
            value = self.local
        elif command[0] == "rev-parse":
            oid, kind = command[1].split("^{")
            value = oid if kind == "commit}" else ("f" * 40 if self.mismatch == "tree" and oid == LOCAL else TREE)
        elif command[0] == "merge-base":
            value = "f" * 40 if self.mismatch == "merge" and command[-1] == LOCAL else MERGE
        elif command[:2] == ["diff", "--name-only"]:
            return subprocess.CompletedProcess(argv, 0, self.changed_paths)
        elif command[0] == "diff":
            value = "changed" if self.mismatch == "diff" and command[-2] == LOCAL else "synthetic complete diff\n"
        else:
            raise AssertionError(command)
        return subprocess.CompletedProcess(argv, 0, value.encode())

    def assert_gh(self, argv, kwargs):
        assert argv[1:] == ["api", "--hostname", "github.com", "repos/fr-meyer/openclaw/pulls/20"]
        assert kwargs["cwd"] != self.checkout

    def run(self, times=(1000, 1001), ticks=(2000, 2001)):
        wall, mono = iter(times), iter(ticks)
        create = tempfile.mkdtemp
        def directory(**kwargs):
            value = create(dir=self.root, **kwargs)
            self.evidence.append(Path(value))
            return value
        with patch.object(gate.shutil, "which", side_effect=lambda name, path: str(self.bin / name)), \
             patch.object(gate.tempfile, "mkdtemp", side_effect=directory), contextlib.redirect_stderr(io.StringIO()):
            return gate.review(self.args, runner=self.runner, clock=lambda: next(wall),
                               monotonic=lambda: next(mono), environment=self.environment, code_root=self.anchor)


class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.f = Fixture(Path(self.temp.name))

    def rejected(self, message=None):
        with self.assertRaisesRegex(gate.Refusal, message or ".*"):
            self.f.run()

    def test_fresh_invocation_retains_bound_receipt_and_original_outputs(self):
        result = self.f.run()
        self.assertEqual(result["headSha"], HEAD)
        self.assertEqual(result["baseSha"], BASE)
        self.assertEqual(result["mergeBaseSha"], MERGE)
        self.assertEqual(result["localHeadSha"], HEAD)
        self.assertFalse(result["cryptographicAttestation"])
        self.assertEqual(result["status"], "scoped-clean")
        self.assertEqual(result["receiptSha256"], gate.file_hash(Path(result["receiptPath"])))
        self.assertEqual(set(result["files"]), {"report", "status", "summary", "log"})
        self.assertEqual(sum(argv[0] == sys.executable for argv, _ in self.f.calls), 1)
        argv, kwargs = next(call for call in self.f.calls if call[0][0] == sys.executable)
        self.assertEqual(argv[1:3], ["-I", str(self.f.helper)])
        self.assertEqual(argv[argv.index("--engine") + 1], "codex")
        self.assertEqual(argv[argv.index("--max-priority") + 1], "P2")
        self.assertEqual(kwargs["env"]["GH_TOKEN"], "synthetic-auth")
        self.assertNotIn("GH_REPO", kwargs["env"])
        self.assertNotIn("AUTOREVIEW_ENGINE", kwargs["env"])
        self.assertNotIn("CODEX_BIN", kwargs["env"])
        self.assertNotIn("GIT_DIR", kwargs["env"])
        self.assertNotIn("PYTHONPATH", kwargs["env"])

    def test_each_call_runs_new_reviewer_in_new_evidence_directory(self):
        first = self.f.run()
        second = self.f.run()
        self.assertNotEqual(first["receiptPath"], second["receiptPath"])
        self.assertEqual(sum(argv[0] == sys.executable for argv, _ in self.f.calls), 2)

    def test_local_hosted_equivalence_supported_only_with_all_bindings(self):
        self.f.local = LOCAL
        result = self.f.run()
        self.assertEqual(result["localHeadSha"], LOCAL)
        self.assertEqual(result["headSha"], HEAD)
        for mismatch in ("tree", "merge", "diff"):
            with self.subTest(mismatch=mismatch):
                self.f.mismatch = mismatch
                self.rejected()

    def test_wrong_fork_host_or_expected_sha_refused_before_invocation(self):
        for key, bad in (("repository", "openclaw/openclaw"), ("host", "example.org"), ("head_sha", "abc")):
            with self.subTest(key=key):
                original = getattr(self.f.args, key)
                setattr(self.f.args, key, bad)
                self.rejected()
                setattr(self.f.args, key, original)
        self.assertEqual(self.f.calls, [])

    def test_live_identity_and_draft_refused(self):
        original = copy.deepcopy(self.f.pr)
        for branch, key, bad in (("head", "sha", LOCAL), ("base", "sha", LOCAL),
                                 ("base", "repo", {"full_name": "wrong/repo"})):
            with self.subTest(branch=branch, key=key):
                self.f.pr = copy.deepcopy(original)
                self.f.pr[branch][key] = bad
                self.rejected()
        self.f.pr = copy.deepcopy(original)
        self.f.pr["draft"] = True
        self.rejected()

    def test_contributor_fork_head_is_bound_without_executing_or_fetching_it(self):
        self.f.pr["head"]["repo"] = {"id": 456, "full_name": "contributor/openclaw", "private": False,
                                     "html_url": "https://github.com/contributor/openclaw"}
        result = self.f.run()
        self.assertEqual(result["headRepository"], {
            "id": 456, "fullName": "contributor/openclaw", "private": False,
            "htmlUrl": "https://github.com/contributor/openclaw"})
        self.assertEqual(result["headSha"], HEAD)
        self.assertFalse(any("fetch" in argv for argv, _ in self.f.calls))

    def test_head_repository_identity_changes_during_review_are_refused(self):
        original = copy.deepcopy(self.f.pr["head"]["repo"])
        for changed in ({"id": 457}, {"full_name": "contributor/openclaw",
                                      "html_url": "https://github.com/contributor/openclaw"}):
            with self.subTest(changed=changed):
                self.f.pr["head"]["repo"] = original.copy()
                self.f.on_review = lambda: self.f.pr["head"]["repo"].update(changed)
                self.rejected("repository changed")

    def test_invalid_or_nonpublic_head_repository_refused_before_review(self):
        original = self.f.pr["head"]["repo"].copy()
        for changed in ({"id": None}, {"id": True}, {"private": True},
                        {"html_url": "https://wrong.example/fr-meyer/openclaw"},
                        {"full_name": "../openclaw"}):
            with self.subTest(changed=changed):
                self.f.pr["head"]["repo"] = {**original, **changed}
                self.rejected("public GitHub identity")
                self.assertFalse(self.f.after)
        self.f.pr["head"]["repo"] = None
        self.rejected("repository unavailable")

    def test_dirty_tracked_source_before_review_refused(self):
        self.f.dirty = True
        self.rejected("not clean")
        self.assertFalse(self.f.after)

    def test_dirty_source_or_live_head_change_during_review_refused(self):
        self.f.on_review = lambda: setattr(self.f, "dirty", True)
        self.rejected("not clean")
        self.f.dirty = False
        self.f.on_review = lambda: self.f.pr["head"].update(sha=LOCAL)
        self.rejected("live PR")

    def test_local_head_change_even_same_tree_refused_after_review(self):
        self.f.on_review = lambda: setattr(self.f, "local", LOCAL)
        self.rejected("source changed")

    def test_helper_tamper_refused_and_failure_receipt_retained(self):
        self.f.on_review = lambda: self.f.helper.write_text("tampered helper\n")
        self.rejected("code changed")
        receipt = json.loads((self.f.evidence[-1] / "receipt.json").read_text())
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(set(receipt["files"]), {"report", "status", "summary", "log"})

    def test_symlink_helper_refused(self):
        other = self.f.root / "other-helper"
        self.f.helper.rename(other)
        self.f.helper.symlink_to(other)
        self.rejected("symlink")

    def test_omitted_changed_paths_refused_before_provider_invocation(self):
        self.f.changed_paths = b"example.py\0.env\0"
        self.rejected("omit changed paths")
        self.assertFalse(self.f.after)

    def test_real_anchored_path_policy_covers_normal_source_and_refuses_credentials(self):
        self.f.helper = Path(__file__).resolve().parents[2] / gate.HELPER
        source = {"mergeBaseSha": MERGE, "headSha": HEAD}
        for paths, reject in ((b"src/auth.ts\0.env.example\0", False),
                              (b"old/.env\0new-name.py\0", True),
                              (b"credentials.json\0", True)):
            with self.subTest(paths=paths):
                self.f.changed_paths = paths
                args = (self.f.helper, self.f.checkout, source, self.f.bin / "git", {}, self.f.runner)
                if reject:
                    with self.assertRaisesRegex(gate.Refusal, "omit changed paths"):
                        gate.require_complete_path_coverage(*args)
                else:
                    self.assertEqual(gate.require_complete_path_coverage(*args)["changedPathCount"], 2)

    def test_nonzero_incomplete_filtered_or_wrong_engine_refused(self):
        self.f.returncode = 1
        self.rejected("exited 1")
        self.f.returncode = 0
        original = self.f.status.copy()
        for key, value in (("status", "incomplete"), ("status", "filtered"), ("engine", "claude"),
                           ("timed_out", True), ("report_produced", False), ("exit_code", 1)):
            with self.subTest(key=key, value=value):
                self.f.status = {**original, key: value}
                self.rejected()

    def test_bad_verdict_filtered_findings_or_partial_usage_refused(self):
        original = self.f.report.copy()
        for key, value in (("findings", [{"priority": "P2"}]), ("overall_correctness", "patch is incorrect"),
                           ("priority_filtered_findings", [{"priority": "P3"}]),
                           ("usage", {"complete": False}), ("overall_explanation", "")):
            with self.subTest(key=key):
                self.f.report = {**original, key: value}
                self.rejected()

    def test_stale_backward_or_jump_clock_refused(self):
        for times, ticks in (((1000, 50000), (2000, 51000)), ((1000, 999), (2000, 2001)),
                             ((1000, 1402), (2000, 2001))):
            with self.subTest(times=times), self.assertRaises(gate.Refusal):
                self.f.run(times, ticks)

    def test_duplicate_output_keys_refused(self):
        def duplicate():
            target = self.f.evidence[-1] / "status.json"
            target.write_text('{"status":"scoped-clean","status":"incomplete"}')
        self.f.on_review = duplicate
        self.rejected("duplicate")


class LocalGitTests(unittest.TestCase):
    def test_real_git_exact_and_tree_equivalent_commits_and_dirty_refusal(self):
        git = shutil.which("git")
        self.assertIsNotNone(git, "local Git is required for the disposable fixture")
        env = gate.clean_environment(os.environ)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            def command(*args, input=None):
                return subprocess.run([git, "-c", "user.name=Synthetic", "-c", "user.email=test@example.invalid",
                                       "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", *args],
                                      cwd=root, env=env, input=input, capture_output=True, check=True).stdout.decode().strip()
            command("init", "--quiet")
            (root / "sample.txt").write_text("before\n")
            command("add", "sample.txt")
            command("commit", "--quiet", "-m", "base")
            base = command("rev-parse", "HEAD")
            (root / "sample.txt").write_text("after\n")
            command("add", "sample.txt")
            command("commit", "--quiet", "-m", "hosted")
            head = command("rev-parse", "HEAD")
            exact = gate.source_identity(root, base, head, Path(git), env, subprocess.run)
            self.assertEqual(exact["headSha"], exact["localHeadSha"])
            local = command("commit-tree", exact["tree"], "-p", base, "-m", "local prepared equivalent")
            command("reset", "--quiet", local)
            equivalent = gate.source_identity(root, base, head, Path(git), env, subprocess.run)
            self.assertNotEqual(equivalent["headSha"], equivalent["localHeadSha"])
            self.assertEqual(exact["reviewDiffSha256"], equivalent["reviewDiffSha256"])
            (root / "sample.txt").write_text("dirty\n")
            with self.assertRaisesRegex(gate.Refusal, "not clean"):
                gate.source_identity(root, base, head, Path(git), env, subprocess.run)


if __name__ == "__main__":
    unittest.main()
