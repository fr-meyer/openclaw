"""Execute the actual composite scope gate; no build, network or credentials."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest

from test_private_oci_bundle import Fixture, WORKFLOW, BUILT


ACTION = Path(__file__).resolve().parents[2] / ".github/actions/retain-private-oci/action.yml"
SOURCE = "85a9bdc1285c338f10f5ca818abc259f6d483b5b"
TREE = "3e0d6fbf5bc015063dce3e4f0f353f0eac3aed6a"


def block(marker):
    raw = ACTION.read_text().split("<<'" + marker + "'\n", 1)[1].split("\n        " + marker, 1)[0]
    return textwrap.dedent(raw)


class PrivateOciActionTests(unittest.TestCase):
    def gate(self, **changed):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            values = {"RETAIN_ENABLED": "true", "APPROVED_WORKFLOW_SHA": "a" * 40,
                      "ACTUAL_WORKFLOW_SHA": "a" * 40, "GITHUB_SHA": "a" * 40,
                      "SOURCE_SHA": SOURCE, "SOURCE_TREE": TREE,
                      "GITHUB_REPOSITORY": "fr-meyer/openclaw", "GITHUB_ACTOR": "fr-meyer",
                      "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_RUN_ATTEMPT": "1",
                      "GITHUB_RUN_ID": "123", "GITHUB_OUTPUT": str(output), **changed}
            result = subprocess.run([sys.executable, "-I", "-B", "-c", block("PY_PRIVATE_SCOPE")],
                                    env=values, capture_output=True, text=True, timeout=5)
            return result, output.read_text() if output.exists() else ""

    def test_disabled_has_no_identity_or_capability_prerequisites(self):
        result, output = self.gate(RETAIN_ENABLED="false", APPROVED_WORKFLOW_SHA="",
                                   SOURCE_SHA="", GITHUB_REPOSITORY="untrusted/fork")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(output, "enabled=false\n")

    def test_exact_independent_scope_and_first_attempt_pass(self):
        result, output = self.gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output, "enabled=true\n")
        self.assertEqual(self.gate(GITHUB_EVENT_NAME="push")[0].returncode, 0)

    def test_unapproved_pr_fork_source_revision_and_retry_fail_before_outputs(self):
        for change in ({"APPROVED_WORKFLOW_SHA": ""}, {"APPROVED_WORKFLOW_SHA": "b" * 40},
                       {"ACTUAL_WORKFLOW_SHA": "b" * 40}, {"GITHUB_SHA": "b" * 40},
                       {"GITHUB_REPOSITORY": "untrusted/fork"}, {"GITHUB_ACTOR": "someone"},
                       {"SOURCE_SHA": "b" * 40}, {"SOURCE_TREE": "b" * 40},
                       {"GITHUB_EVENT_NAME": "pull_request_target"}, {"GITHUB_EVENT_NAME": "pull_request"},
                       {"GITHUB_RUN_ATTEMPT": "2"}, {"GITHUB_RUN_ID": "0"},
                       {"RETAIN_ENABLED": "unexpected-secret-fixture-value"}):
            with self.subTest(change=change):
                result, output = self.gate(**change)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(output, "")
                self.assertNotIn("unexpected-secret-fixture-value", result.stdout + result.stderr)

    def test_composite_defaults_disabled_and_has_no_trigger_or_public_upload(self):
        action = ACTION.read_text()
        self.assertNotIn("\non:", action)
        self.assertNotIn("upload-artifact", action)
        self.assertNotIn("docker/login-action", action)
        self.assertEqual(action.count("if: steps.scope.outputs.enabled == 'true'"), 3)
        workflow = ACTION.parents[2] / "workflows/fork-release-pipeline.yml"
        self.assertIn('default: "false"', action)
        self.assertEqual(workflow.read_text().count('uses: ./tooling/.github/actions/retain-private-oci'), 1)

    def test_attestation_is_sha_pinned_and_does_not_publish_private_paths_or_registry(self):
        action = ACTION.read_text()
        attest = action.split("    - name: Attest retained private OCI archive\n", 1)[1].split("    - name:", 1)[0]
        self.assertIn("actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6", attest)
        self.assertIn("subject-name: retained-oci.tar", attest)
        self.assertIn("subject-digest: sha256:", attest)
        self.assertNotIn("subject-path:", attest)
        self.assertIn("push-to-registry: false", attest)
        self.assertIn("create-storage-record: false", attest)
        self.assertNotIn("upload-capability", action.split("    - name: Check separately", 1)[1].split("    - name: Transfer", 1)[0])

    def test_actual_prepare_action_and_receipt_paths_match_archive_owner(self):
        action = ACTION.read_text().split("    - name: Prepare exact opaque private archive\n", 1)[1]
        run = textwrap.dedent(action.split("      run: |\n", 1)[1].split("    - name: Attest", 1)[0])
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(directory)
            output = fixture.base / "action-output"
            values = {**os.environ, "GITHUB_ACTION_PATH": str(ACTION.parent),
                      "SOURCE_SHA": SOURCE, "SOURCE_TREE": TREE, "WORKFLOW_SHA": WORKFLOW,
                      "BUILT_AT": BUILT, "MANIFEST": str(fixture.manifest),
                      "INVENTORY": str(fixture.inventory), "BUILD_METADATA": str(fixture.metadata),
                      "RESOURCES": str(fixture.resources), "OCI_DIRECTORY": str(fixture.oci),
                      "OUTPUT_DIRECTORY": str(fixture.out), "RUNNER_TEMP": str(fixture.base),
                      "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_OUTPUT": str(output)}
            result = subprocess.run(["/bin/bash", "-c", run], env=values,
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue((fixture.out / "retained-oci.tar").is_file())
            self.assertTrue(Path(str(fixture.out) + "-retention.json").is_file())
            self.assertFalse((fixture.out / "retention.json").exists())
            self.assertIn("sha256=", output.read_text())


if __name__ == "__main__":
    unittest.main()
