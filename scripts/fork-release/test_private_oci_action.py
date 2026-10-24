"""Execute the actual composite scope gate; no build, network or credentials."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import shutil
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

    def prepare_boundary(self, fixture, *, action_text=None, **changed):
        action = (action_text or ACTION.read_text()).split("    - name: Prepare exact opaque private archive\n", 1)[1]
        run = textwrap.dedent(action.split("      run: |\n", 1)[1].split("    - name: Attest", 1)[0])
        output = fixture.base / "action-output"
        followup = fixture.base / "followup-actions"
        # The actual preparation Bash must abort before any following action.
        # These sentinels perform no attestation or transfer.
        run += "\npython3 - <<'PY_FOLLOWUP'\nimport os\nfrom pathlib import Path\nPath(os.environ['FOLLOWUP_TRACE']).write_text('attest transfer')\nPY_FOLLOWUP\n"
        values = {**os.environ, "GITHUB_ACTION_PATH": str(ACTION.parent),
                  "SOURCE_SHA": SOURCE, "SOURCE_TREE": TREE, "WORKFLOW_SHA": WORKFLOW,
                  "BUILT_AT": BUILT, "MANIFEST": str(fixture.manifest),
                  "INVENTORY": str(fixture.inventory), "BUILD_METADATA": str(fixture.metadata),
                  "RESOURCES": str(fixture.resources), "OCI_DIRECTORY": str(fixture.oci),
                  "OUTPUT_DIRECTORY": str(fixture.out), "RUNNER_TEMP": str(fixture.base),
                  "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_OUTPUT": str(output),
                  "FOLLOWUP_TRACE": str(followup), **changed}
        result = subprocess.run(["/bin/bash", "-c", run], env=values,
                                capture_output=True, text=True, timeout=10)
        return result, output, followup

    def fake_helper(self, fixture, body):
        root = fixture.base / "fake-action-root"
        action = root / ".github/actions/retain-private-oci"
        action.mkdir(parents=True)
        helper = root / "scripts/fork-release/private_oci_bundle.py"
        helper.parent.mkdir(parents=True)
        helper.write_text("import json,sys\n" + body)
        shutil.copyfile(Path(__file__).with_name("hosted_privacy.py"), helper.with_name("hosted_privacy.py"))
        return str(action)

    def assert_failed_preparation_is_closed(self, result, output, followup, *, code, reason):
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        records = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(records[0]["recordType"], "export_structure")
        self.assertNotIn("path", records[0])
        diagnostic = records[-1]
        self.assertEqual({key: diagnostic[key] for key in ("status", "reason", "stage")}, {
            "status": "failed", "reason": reason, "stage": "private_oci_prepare"})
        if "refusalCode" in diagnostic:
            self.assertIn(diagnostic["refusalCode"], __import__("private_oci_bundle").PUBLIC_REFUSAL_CODES)
        self.assertEqual(result.stderr, "")
        self.assertFalse(output.exists())
        self.assertFalse(followup.exists())
        action = ACTION.read_text()
        for name in ("Attest retained private OCI archive", "Transfer only the approved private object"):
            section = action.split("    - name: " + name + "\n", 1)[1].split("    - name:", 1)[0]
            self.assertIn("steps.prepare.outcome == 'success'", section)

    def test_actual_prepare_action_and_receipt_paths_match_archive_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(directory)
            result, output, followup = self.prepare_boundary(fixture)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue((fixture.out / "retained-oci.tar").is_file())
            self.assertTrue(Path(str(fixture.out) + "-retention.json").is_file())
            self.assertFalse((fixture.out / "retention.json").exists())
            self.assertIn("sha256=", output.read_text())
            records = [json.loads(line) for line in result.stdout.splitlines()]
            self.assertEqual(records[0]["recordType"], "export_structure")
            diagnostic = records[-1]
            self.assertEqual(set(diagnostic), {"status", "stage", "archiveSha256", "archiveBytes"})
            self.assertEqual(diagnostic["status"], "prepared")
            self.assertEqual(diagnostic["stage"], "private_oci_prepare")
            self.assertIn("sha256=" + diagnostic["archiveSha256"], output.read_text())
            self.assertIn("bytes=" + str(diagnostic["archiveBytes"]), output.read_text())
            self.assertNotIn(str(fixture.base), result.stdout + result.stderr)
            self.assertEqual(followup.read_text(), "attest transfer")

    def test_actual_failed_prepare_emits_closed_reason_and_stops_following_actions(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(directory)
            result, output, followup = self.prepare_boundary(fixture, SOURCE_SHA="b" * 40)
            self.assert_failed_preparation_is_closed(result, output, followup, code=1,
                reason="private_bundle_invalid_changed_or_over_limit")
            capture = Path(str(fixture.out) + "-prepare-output.json")
            self.assertEqual(capture.stat().st_mode & 0o777, 0o600)
            self.assertEqual(Path(str(fixture.out) + "-prepare-error.log").stat().st_mode & 0o777, 0o600)
            self.assertNotIn(str(fixture.base), result.stdout + result.stderr)

    def test_failed_prepare_never_logs_unknown_reason_paths_headers_or_raw_errors(self):
        secret = "private-" + "fixture-not-for-logs"
        for malformed in (False, True):
            with self.subTest(malformed=malformed), tempfile.TemporaryDirectory() as directory:
                fixture = Fixture(directory)
                value = {"status": "failed", "reason": secret, "archivePath": str(fixture.base),
                         "url": "https://quarantine.invalid/upload?synthetic=" + secret,
                         "headers": {"Authorization": secret}}
                body = ("print(" + repr(secret if malformed else json.dumps(value)) + ")\n"
                        "print(" + repr("raw-error:" + secret) + ",file=sys.stderr)\n"
                        "raise SystemExit(7)\n")
                result, output, followup = self.prepare_boundary(fixture,
                    GITHUB_ACTION_PATH=self.fake_helper(fixture, body))
                self.assert_failed_preparation_is_closed(result, output, followup, code=7,
                    reason="private_prepare_diagnostic_unavailable")
                public = result.stdout + result.stderr
                for forbidden in (secret, str(fixture.base), value["url"], "Authorization", "raw-error"):
                    self.assertNotIn(forbidden, public)
                self.assertIn(secret, Path(str(fixture.out) + "-prepare-error.log").read_text())

    def test_zero_exit_without_valid_receipt_still_blocks_attestation_and_transfer(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(directory)
            body = "print(json.dumps({'status':'prepared','archiveSha256':'a'*64,'archiveBytes':1}))\n"
            result, output, followup = self.prepare_boundary(fixture,
                GITHUB_ACTION_PATH=self.fake_helper(fixture, body))
            self.assert_failed_preparation_is_closed(result, output, followup, code=1,
                reason="private_prepare_diagnostic_unavailable")

    def test_private_capture_never_overwrites_an_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(directory)
            capture = Path(str(fixture.out) + "-prepare-output.json")
            capture.write_text("preserve-fixture")
            result, output, followup = self.prepare_boundary(fixture)
            self.assert_failed_preparation_is_closed(result, output, followup, code=1,
                reason="private_prepare_diagnostic_unavailable")
            self.assertEqual(capture.read_text(), "preserve-fixture")


if __name__ == "__main__":
    unittest.main()
