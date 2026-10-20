import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import gcp_rehearsal as gcp

HERE = Path(__file__).parent


class RehearsalContracts(unittest.TestCase):
    def setUp(self):
        self.plan = {
            "schema": "openclaw.gcp-rehearsal-plan.v1",
            "createdAt": "2026-10-20T01:00:00Z",
            "expiresAt": "2026-10-20T13:00:00Z",
            "audience": "//iam.googleapis.com/projects/123456/locations/global/"
                        "workloadIdentityPools/fork-rehearsal/providers/github",
            "environment": "openclaw-rehearsal",
            "binding": {"sourceSha": "a" * 40, "toolingSha": "b" * 40,
                        "imageDigest": "sha256:" + "c" * 64},
            "snapshot": {"id": "123456", "sizeGiB": 384, "purpose": "rehearsal_only"},
            "resources": {"machineType": "e2-standard-8", "bootDiskGiB": 32,
                          "dataDiskGiB": 384, "concurrency": 1,
                          "estimatedCostMicrousd": 5_000_000, "approvedCostMicrousd": 10_000_000},
        }
        self.now = gcp.utc("2026-10-20T02:00:00Z")

    def test_envelope_and_oidc_bind_source_tooling_ref_environment_and_audience(self):
        gcp.validate_plan(self.plan, self.now)
        condition = gcp.proposed_oidc_condition(self.plan)
        for claim, value in (
            ("repository_id", gcp.REPOSITORY_ID), ("repository_owner_id", gcp.OWNER_ID),
            ("ref", "refs/heads/main"), ("event_name", "workflow_dispatch"),
            ("environment", "openclaw-rehearsal"),
            ("workflow_ref", gcp.WORKFLOW + "@refs/heads/main"),
            ("workflow_sha", "b" * 40), ("aud", self.plan["audience"]),
        ):
            self.assertIn(f"assertion.{claim} == {json.dumps(value)}", condition)
        self.assertEqual(condition.count(" && "), 7)

    def test_template_is_deliberately_incomplete(self):
        with self.assertRaises(gcp.Refusal):
            gcp.validate_plan(json.loads((HERE / "gcp-rehearsal-plan.template.json").read_text()),
                              self.now)

    def test_resource_cost_and_snapshot_bounds(self):
        for field, value in (
            ("machineType", "e2-highmem-32"), ("bootDiskGiB", 33),
            ("dataDiskGiB", 383), ("dataDiskGiB", 1025), ("concurrency", 2),
            ("concurrency", True), ("estimatedCostMicrousd", 10_000_001),
            ("estimatedCostMicrousd", 0), ("approvedCostMicrousd", None),
        ):
            with self.subTest(field=field, value=value):
                plan = copy.deepcopy(self.plan)
                plan["resources"][field] = value
                with self.assertRaises(gcp.Refusal):
                    gcp.validate_plan(plan, self.now)

    def test_absolute_expiration_is_not_extended_on_retry(self):
        for now in ("2026-10-20T00:59:59Z", "2026-10-20T13:00:00Z", "2026-10-21T02:00:00Z"):
            with self.subTest(now=now), self.assertRaises(gcp.Refusal):
                gcp.validate_plan(self.plan, gcp.utc(now))
        self.plan["expiresAt"] = "2026-10-21T01:00:01Z"
        with self.assertRaisesRegex(gcp.Refusal, "plan.ttl"):
            gcp.validate_plan(self.plan, self.now)

    def test_rejects_mutable_identity_and_production_snapshot_use(self):
        for section, field, value in (
            ("binding", "imageDigest", "latest"), ("binding", "toolingSha", "main"),
            ("binding", "sourceSha", "$(echo injected)"),
            ("snapshot", "purpose", "promote_to_live"),
        ):
            with self.subTest(field=field):
                plan = copy.deepcopy(self.plan)
                plan[section][field] = value
                with self.assertRaises(gcp.Refusal):
                    gcp.validate_plan(plan, self.now)

    def test_public_observation_has_no_candidate_text_or_private_fields(self):
        observation = {"phase": "doctor", "state": "passed",
                       "observedAt": "2026-10-20T03:00:00Z", "elapsedSeconds": 300}
        receipt = gcp.public_receipt(self.plan["binding"], observation)
        self.assertFalse(receipt["promotionAuthorized"])
        self.assertEqual(receipt["sourceSha"], "a" * 40)
        self.assertRegex(receipt["receiptId"], r"^[0-9a-f]{32}$")
        canary = "SYNTHETIC_PRIVATE_CANARY person@example.invalid"
        for field in ("logs", "path", "environment", "snapshotId", "error"):
            with self.subTest(field=field):
                with self.assertRaisesRegex(gcp.Refusal, "^public.fields$"):
                    gcp.public_receipt(self.plan["binding"], {**observation, field: canary})
        for field in observation:
            with self.subTest(field=field), self.assertRaises(gcp.Refusal) as raised:
                gcp.public_receipt(self.plan["binding"], {**observation, field: canary})
            self.assertNotIn(canary, str(raised.exception))
        with self.assertRaisesRegex(gcp.Refusal, "binding.fields"):
            gcp.public_receipt({**self.plan["binding"], "rawLog": canary}, observation)

    def test_cli_does_not_echo_private_input_or_authorize_activation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private.json"
            path.write_text('{"SYNTHETIC_PRIVATE_CANARY": "unterminated')
            result = subprocess.run([sys.executable, str(HERE / "gcp_rehearsal.py"), str(path)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertFalse(json.loads(result.stdout)["activationAuthorized"])
            self.assertNotIn("SYNTHETIC_PRIVATE_CANARY", result.stdout + result.stderr)
            self.assertNotIn(directory, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
