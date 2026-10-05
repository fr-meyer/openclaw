"""Pure explicit commit/run admission; no submitted runtime is executed."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("v98_admission_tests", Path(__file__).with_name("host-runtime.py"))
HOST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HOST)
COMMIT = "ab" * 20

def approved():
    return {"GITHUB_REPOSITORY": "fr-meyer/openclaw", "GITHUB_REF": "refs/heads/candidate/v2026.9.8-runtime-admission-5",
        "GITHUB_EVENT_NAME": "push", "GITHUB_SHA": COMMIT, "GITHUB_RUN_NUMBER": "2", "GITHUB_RUN_ATTEMPT": "1",
        "V98_APPROVED_COMMIT": COMMIT, "V98_APPROVED_RUN_NUMBER": "2"}

class HostedAdmissionTests(unittest.TestCase):
    def test_explicit_current_and_future_selected_runs_on_same_branch(self):
        for number in ("2", "17"):
            with patch.dict(HOST.os.environ, {**approved(), "GITHUB_RUN_NUMBER": number, "V98_APPROVED_RUN_NUMBER": number}, clear=True):
                self.assertEqual(HOST.verify_hosted_attempt(COMMIT), {"commit": COMMIT, "runNumber": int(number), "runAttempt": 1})

    def test_missing_fields_refuse(self):
        for key in approved():
            env = approved(); del env[key]
            with self.subTest(key=key), patch.dict(HOST.os.environ, env, clear=True), self.assertRaises(HOST.Refusal):
                HOST.verify_hosted_attempt(COMMIT)

    def test_malformed_or_changed_fields_refuse_before_any_source_or_host_action(self):
        cases = [("GITHUB_REPOSITORY", "elsewhere/openclaw"), ("GITHUB_REF", "refs/heads/main"),
            ("GITHUB_EVENT_NAME", "workflow_dispatch"), ("GITHUB_SHA", "cd" * 20),
            ("V98_APPROVED_COMMIT", COMMIT.upper()), ("V98_APPROVED_COMMIT", "cd" * 20),
            ("V98_APPROVED_COMMIT", "x" * 40), ("V98_APPROVED_RUN_NUMBER", ""),
            ("V98_APPROVED_RUN_NUMBER", "02"), ("V98_APPROVED_RUN_NUMBER", "2.0"),
            ("V98_APPROVED_RUN_NUMBER", "0"), ("V98_APPROVED_RUN_NUMBER", "+2"),
            ("V98_APPROVED_RUN_NUMBER", "2\n"), ("V98_APPROVED_RUN_NUMBER", "2" * 21),
            ("GITHUB_RUN_NUMBER", "1"), ("GITHUB_RUN_NUMBER", "3"), ("GITHUB_RUN_ATTEMPT", "2")]
        for key, value in cases:
            with self.subTest(key=key, value=value), patch.dict(HOST.os.environ, {**approved(), key: value}, clear=True), \
                 patch.object(HOST.os, "geteuid", return_value=0), patch.object(HOST.platform, "system", return_value="Linux"), \
                 patch.object(HOST.platform, "machine", return_value="x86_64"), \
                 patch.object(HOST, "verify_source_manifest") as manifest, patch.object(HOST, "prepare_proof") as preparation, \
                 patch.object(HOST, "compile_native") as compiler, patch.object(HOST, "command") as command:
                with self.assertRaises(HOST.Refusal):
                    HOST.execute(SimpleNamespace(tooling_commit=COMMIT))
                manifest.assert_not_called(); preparation.assert_not_called(); compiler.assert_not_called(); command.assert_not_called()

    def test_cli_commit_must_equal_approved_and_github_commit(self):
        with patch.dict(HOST.os.environ, approved(), clear=True):
            for commit in (None, COMMIT.upper(), "cd" * 20, COMMIT + "\n"):
                with self.subTest(commit=commit), self.assertRaises(HOST.Refusal):
                    HOST.verify_hosted_attempt(commit)
