"""Focused real caller + tiny generated Git tests, never application execution."""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import ast
import importlib.util
import hashlib
import json
import tempfile
import io
import os
import signal
import subprocess
import sys
import time
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE
BASE = HERE / "source_validation_v108.py"
sys.dont_write_bytecode = True
sys.path.insert(0, str(HERE))


def load_driver():
    spec = importlib.util.spec_from_file_location("isolated_donor_driver", BASE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TinyGitClosure(unittest.TestCase):
    def setUp(self):
            self.tmp = tempfile.TemporaryDirectory(prefix="tiny-metadata-", dir=ROOT)
            self.addCleanup(self.tmp.cleanup)
            self.root = Path(self.tmp.name)
            self.origin = self.root / "origin.git"
            self.target = self.root / "checkout"
            self.env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null",
                            GIT_NO_LAZY_FETCH="1", GIT_NO_REPLACE_OBJECTS="1",
                            GIT_ALLOW_PROTOCOL="file", GIT_TERMINAL_PROMPT="0",
                            GIT_AUTHOR_NAME="Metadata fixture", GIT_AUTHOR_EMAIL="fixture@example.invalid",
                            GIT_COMMITTER_NAME="Metadata fixture", GIT_COMMITTER_EMAIL="fixture@example.invalid",
                            GIT_AUTHOR_DATE="2026-01-01T00:00:00Z", GIT_COMMITTER_DATE="2026-01-01T00:00:00Z")
            for name in list(self.env):
                if name.startswith("GIT_TRACE"):
                    self.env.pop(name)
            self.g("init", "--bare", "--initial-branch=fixture", str(self.origin))
            self.g("-C", str(self.origin), "config", "uploadpack.allowFilter", "true")
            self.g("-C", str(self.origin), "config", "uploadpack.allowAnySHA1InWant", "true")
            self.commits, self.blobs = [], []
            for index in range(8):
                blob = self.g("-C", str(self.origin), "hash-object", "-w", "--stdin",
                              data=f"generated fixture version {index}\n".encode()).stdout.strip().decode()
                tree = self.g("-C", str(self.origin), "mktree",
                              data=f"100644 blob {blob}\tfixture.txt\n".encode()).stdout.strip().decode()
                parents = ["-p", self.commits[-1]] if self.commits else []
                commit = self.g("-C", str(self.origin), "commit-tree", tree, *parents,
                                data=f"metadata {index}\n".encode()).stdout.strip().decode()
                self.blobs.append(blob)
                self.commits.append(commit)
            self.g("-C", str(self.origin), "update-ref", "refs/heads/fixture", self.commits[-1])
            self.g("-C", str(self.origin), "tag", "-a", "fixture-tag", "-m", "fixture tag", self.commits[4])
            self.tag = self.g("-C", str(self.origin), "rev-parse", "refs/tags/fixture-tag").stdout.strip().decode()
            self.g("clone", "--quiet", "--no-local", "--no-tags", "--depth=1", self.origin.as_uri(), str(self.target))

    def g(self, *args, data=None, ok=True):
            result = subprocess.run(["/usr/bin/git", "--no-replace-objects", *args],
                                    input=data, env=self.env, capture_output=True, timeout=10)
            if ok:
                self.assertEqual(result.returncode, 0, (args[0], result.returncode))
            return result

class DonorCaller(TinyGitClosure):
    def setUp(self):
        super().setUp()
        self.target.rename(self.root / "source")
        self.target = self.root / "source"
        self.pipeline = self.root / "pipeline"
        self.g("-C", str(self.origin), "tag", "-a", "v2026.10.8", "-m", "pinned metadata tag", self.commits[4])
        self.tag = self.g("-C", str(self.origin), "rev-parse", "refs/tags/v2026.10.8").stdout.strip().decode()
        self.g("clone", "--quiet", "--no-local", self.origin.as_uri(), str(self.pipeline))
        for root in (self.target, self.pipeline):
            self.g("-C", str(root), "remote", "set-url", "origin", "https://github.com/fr-meyer/openclaw.git")
        self.driver = load_driver()
        self.request = {"schema": self.driver.V6_SCHEMA, "sourceSha": self.commits[-1],
                        "sourceTree": self.g("-C", str(self.target), "rev-parse", "HEAD^{tree}").stdout.strip().decode()}
        self.event = {"trustedSyntheticHead": self.commits[-1]}
        self.runtime_env = {"PATH": os.environ["PATH"], "GITHUB_WORKSPACE": str(self.root),
                            "GITHUB_JOB": "admission", "SOURCE_ADMISSION_STARTED_EPOCH": str(int(time.time())),
                            "GH_SOURCE_READ_TOKEN": "BENIGN_PRIVATE_ENV_CANARY"}
        self.inventory = {"upstream": {"tag": "v2026.10.8", "tagObject": self.tag,
                                      "commit": self.commits[4]}}
        self.order = []
        self.acquisitions = []
        self.timeout_ordinal = None
        self.after_first = None
        self.tag_mismatch = False

    def invoke(self, *, event=True, request=None, history=None):
        driver = self.driver
        request = self.request if request is None else request
        deadline = time.time() + 1740
        guard = driver.local_closure_donor_uri
        native_check_output = subprocess.check_output

        def check_output(argv, **kwargs):
            self.assertGreater(kwargs["timeout"], 0)
            self.assertEqual(kwargs["env"]["GIT_NO_LAZY_FETCH"], "1")
            self.assertNotIn("GH_SOURCE_READ_TOKEN", kwargs["env"])
            if self.tag_mismatch and argv[-2:] == ["rev-parse", "FETCH_HEAD"]:
                return b"0" * 40
            return native_check_output(argv, **kwargs)

        def guarded(*args):
            self.order.append("guard")
            return guard(*args)

        def acquire(argv, cwd, child_env, context, phase, ordinal):
            self.order.append("fetch" + str(ordinal))
            self.acquisitions.append(list(argv))
            self.assertEqual(phase, "source-closure")
            self.assertEqual(cwd, self.target)
            self.assertIs(context["request"], request)
            self.assertEqual(context["deadlineEpoch"], deadline)
            self.assertNotIn("GH_SOURCE_READ_TOKEN", child_env)
            self.assertEqual(child_env["GIT_NO_LAZY_FETCH"], "1")
            if ordinal == self.timeout_ordinal:
                return SimpleNamespace(returncode=124, timed_out=True)
            command = list(argv)
            if ordinal == 0:
                self.assertIn(self.pipeline.as_uri(), command)
                self.assertNotIn("https://github.com/fr-meyer/openclaw.git", command)
                self.assertIn("protocol.allow=never", command)
                self.assertIn("protocol.file.allow=always", command)
            else:
                self.assertEqual(ordinal, 1)
                self.assertEqual(command[-2:], ["https://github.com/openclaw/openclaw.git", "refs/tags/v2026.10.8"])
                command[-2] = self.origin.as_uri()  # Only the test transport is redirected to generated local metadata.
                command[1:1] = ["-c", "protocol.allow=never", "-c", "protocol.file.allow=always"]
            actual = self.g(*command[1:])
            if ordinal == 0 and self.after_first is not None:
                self.after_first()
            return SimpleNamespace(returncode=actual.returncode, timed_out=False)

        with ExitStack() as stack:
            stack.enter_context(patch.object(driver, "metadata", return_value=(request, {}, "d" * 64)))
            stack.enter_context(patch.object(driver.preflight, "inventory_at", return_value=(self.inventory, None)))
            stack.enter_context(patch.object(driver.preflight, "history_commits", return_value=sorted(history or self.commits)))
            stack.enter_context(patch.object(driver, "validate_event", side_effect=lambda value, env: value["trustedSyntheticHead"]))
            stack.enter_context(patch.object(driver, "source_identity_for", side_effect=lambda value: (value["sourceSha"], value["sourceTree"])))
            stack.enter_context(patch.object(driver, "admission_deadline", side_effect=lambda env, value: deadline))
            stack.enter_context(patch.object(driver, "profile_deadline", side_effect=lambda env, profile, value: deadline))
            stack.enter_context(patch.object(driver, "local_closure_donor_uri", side_effect=guarded))
            stack.enter_context(patch.object(driver.subprocess, "check_output", side_effect=check_output))
            stack.enter_context(patch.object(driver, "phase_process", side_effect=acquire))
            stack.enter_context(patch.object(driver, "source_preflight", side_effect=lambda *args: self.order.append("preflight")))
            driver.fetch_closure(self.pipeline, self.target, request=request, env=self.runtime_env,
                                 event=self.event if event else None)

    def test_real_call_order_and_independent_full_source(self):
        before = (self.target / "fixture.txt").read_bytes()
        self.invoke()
        self.assertEqual(self.order, ["guard", "fetch0", "guard", "fetch1", "preflight"])
        self.assertEqual(self.g("-C", str(self.target), "rev-parse", "--is-shallow-repository").stdout.strip(), b"false")
        self.assertEqual(self.g("-C", str(self.target), "rev-parse", "HEAD").stdout.strip().decode(), self.request["sourceSha"])
        self.assertEqual(self.g("-C", str(self.target), "status", "--porcelain").stdout, b"")
        self.assertEqual((self.target / "fixture.txt").read_bytes(), before)
        self.assertFalse((self.target / ".git/objects/info/alternates").exists())
        for blob in self.blobs:
            self.assertEqual(self.g("-C", str(self.target), "cat-file", "-t", blob).stdout.strip(), b"blob")

    def test_v6_missing_event_refuses_before_acquisition(self):
        with self.assertRaises(self.driver.release.Refusal):
            self.invoke(event=False)
        self.assertEqual(self.order, [])

    def test_trusted_event_head_mismatch_refuses_before_acquisition(self):
        self.event["trustedSyntheticHead"] = self.commits[0]
        with self.assertRaises(self.driver.release.Refusal):
            self.invoke()
        self.assertEqual(self.acquisitions, [])

    def test_missing_donor_object_refuses_without_any_fetch(self):
        with self.assertRaises(subprocess.CalledProcessError):
            self.invoke(history=self.commits + ["f" * 40])
        self.assertEqual(self.acquisitions, [])

    def test_dirty_source_before_and_after_fetch_prevents_next_acquisition(self):
        original = (self.target / "fixture.txt").read_bytes()
        (self.target / "fixture.txt").write_bytes(b"dirty fixture\n")
        with self.assertRaises(self.driver.release.Refusal):
            self.invoke()
        self.assertEqual(self.acquisitions, [])
        (self.target / "fixture.txt").write_bytes(original)
        self.order.clear()
        self.after_first = lambda: (self.target / "fixture.txt").write_bytes(b"dirty after fetch\n")
        with self.assertRaises(self.driver.release.Refusal):
            self.invoke()
        self.assertEqual(self.order, ["guard", "fetch0", "guard"])
        self.assertEqual(len(self.acquisitions), 1)

    def test_failed_owned_fetch_never_tries_remote_or_preflight(self):
        self.timeout_ordinal = 0
        with self.assertRaises(self.driver.release.Refusal):
            self.invoke()
        self.assertEqual(self.order, ["guard", "fetch0"])
        self.assertEqual(len(self.acquisitions), 1)

    @unittest.skipUnless(sys.platform == "linux", "native session ownership requires admitted Linux; Darwin records session_identity_changed")
    def test_owned_phase_timeout_settles_benign_python_stub(self):
        # Exercise the maintained phase owner rather than substituting cleanup.
        # No application/dependency source or network endpoint is executed.
        driver = self.driver
        context = {"profile": "admission", "deadlineEpoch": time.time() + 0.2,
                   "request": self.request}
        output = io.StringIO()
        with patch.object(driver, "source_identity_for", return_value=(self.request["sourceSha"], self.request["sourceTree"])), \
                redirect_stdout(output):
            result = driver.phase_process([sys.executable, "-I", "-S", "-c", "import time; time.sleep(60)"],
                                          self.target, {"PATH": os.environ["PATH"]}, context, "source-closure", 0)
        self.assertTrue(result.timed_out)
        self.assertTrue(result.cleanup_settled)
        self.assertEqual(result.returncode, 124)
        self.assertEqual(result.actual_returncode, -signal.SIGTERM)
        facts = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual([fact["status"] for fact in facts], ["started", "timeout"])
        self.assertTrue(facts[-1]["cleanupSettled"])
        self.assertEqual(facts[-1]["signal"], signal.SIGTERM)
        self.assertNotIn("BENIGN_PRIVATE", output.getvalue())

    def test_wrong_tag_refuses_before_preflight(self):
        self.tag_mismatch = True
        with self.assertRaises(self.driver.release.Refusal):
            self.invoke()
        self.assertEqual(self.order, ["guard", "fetch0", "guard", "fetch1"])

    def test_guard_is_silent_and_child_environment_drops_private_token(self):
        (self.target / "fixture.txt").write_bytes(b"BENIGN_PRIVATE_WORKTREE_CANARY\n")
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr), self.assertRaises(self.driver.release.Refusal) as caught:
            self.invoke()
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "")
        self.assertNotIn("BENIGN_PRIVATE", str(caught.exception))
        self.assertEqual(self.acquisitions, [])

    def test_historical_helper_body_is_preserved_and_v6_never_falls_back(self):
        maintained = ast.parse(BASE.read_text())
        historical = next(n for n in maintained.body if isinstance(n, ast.FunctionDef) and n.name == "fetch_closure_historical")
        historical.name = "fetch_closure"
        # Canonical P6/3eb4 AST digest; no private adjacent baseline is needed.
        self.assertEqual(hashlib.sha256(ast.dump(historical, include_attributes=False).encode()).hexdigest(),
                         "0c434f64b0323734d327bda8562ddc965b2008a0b8d3bca6dca41e1946ef8b7a")
        old_request = {"schema": "openclaw.fork-source-validation-request.v3"}
        with patch.object(self.driver, "metadata", return_value=(old_request, {}, "d" * 64)), \
                patch.object(self.driver, "fetch_closure_historical", return_value="historical") as legacy:
            self.assertEqual(self.driver.fetch_closure(self.pipeline, self.target), "historical")
            legacy.assert_called_once()
        self.timeout_ordinal = 0
        with patch.object(self.driver, "fetch_closure_historical") as legacy:
            with self.assertRaises(self.driver.release.Refusal):
                self.invoke()
            legacy.assert_not_called()

    def test_wrong_valid_source_identity_refuses_before_acquisition(self):
        wrong = self.g("-C", str(self.target), "commit-tree", self.request["sourceTree"],
                       data=b"other valid source identity\n").stdout.strip().decode()
        self.g("-C", str(self.target), "update-ref", "HEAD", wrong)
        self.assertEqual(self.g("-C", str(self.target), "status", "--porcelain").stdout, b"")
        with self.assertRaises(self.driver.release.Refusal):
            self.invoke()
        self.assertEqual(self.acquisitions, [])

    def test_aliased_object_store_refuses_before_acquisition(self):
        objects = self.target / ".git/objects"
        objects.rename(self.target / ".git/objects-original")
        objects.symlink_to(self.pipeline / ".git/objects", target_is_directory=True)
        with self.assertRaises(self.driver.release.Refusal):
            self.invoke()
        self.assertEqual(self.acquisitions, [])

    def test_source_profile_keeps_its_request_and_owned_budget_context(self):
        self.runtime_env.update(GITHUB_JOB="source", SOURCE_PROFILE="doctor-1")
        self.invoke()
        self.assertEqual(self.order, ["guard", "fetch0", "guard", "fetch1", "preflight"])

    def test_actual_cli_rejects_legacy_request_file_before_binding_or_acquisition(self):
        driver = self.driver
        # The integrated test consumes only root-finalized current pins. It must
        # not invent a future candidate to make historical CLI inputs admissible.
        self.assertIsInstance(driver.V6_STAGE_PINS, dict)
        event_path = self.root / "synthetic-event.json"
        event_path.write_text(json.dumps(self.event))
        request_path = self.pipeline / driver.REQUEST
        request_path.parent.mkdir(parents=True, exist_ok=True)
        for version in ("v2", "v3", "v4", "v5"):
            request_path.write_text(json.dumps({"schema": "openclaw.fork-source-validation-request." + version}))
            stdout = io.StringIO()
            with patch.dict(driver.os.environ, {**self.runtime_env, "GITHUB_EVENT_PATH": str(event_path)}, clear=True), \
                    patch.object(driver, "validate_event", return_value=self.commits[-1]), \
                    patch.object(driver, "fetch_closure") as fetch, \
                    patch.object(driver, "code_binding") as binding, \
                    patch.object(driver, "phase_process") as acquire, \
                    patch.object(driver, "history_checks_v6") as history, \
                    patch.object(driver, "verify_source_equivalence_v6") as equivalence, \
                    patch.object(sys, "argv", ["source_validation_v108.py", "admit", "--pipeline-dir", str(self.pipeline),
                                               "--source-dir", str(self.target)]), redirect_stdout(stdout):
                with self.assertRaises(driver.V6ContractRefusal) as caught:
                    driver.main()
                self.assertEqual(caught.exception.args, ("v6.closed_authorized_request",))
                binding.assert_not_called()
                fetch.assert_not_called()
                acquire.assert_not_called()
                history.assert_not_called()
                equivalence.assert_not_called()
            self.assertNotIn("BENIGN_PRIVATE", stdout.getvalue())


if __name__ == "__main__":
    names = [n for n in DonorCaller.__dict__ if n.startswith("test_")]
    suite = unittest.TestSuite(DonorCaller(n) for n in sorted(names))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
