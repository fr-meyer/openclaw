import copy
import importlib.util
import fcntl
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

MODULE_PATH = Path(__file__).with_name("release.py")
SPEC = importlib.util.spec_from_file_location("fork_release", MODULE_PATH)
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


def state():
    return {
        "schema": "openclaw.fork-release-progress.v2",
        "candidate": "example",
        "manifestSha256": "a" * 64,
        "inventorySha256": "e" * 64, "baselineSha256": "f" * 64, "backupPolicySha256": "1" * 64,
        "backupBindingSha256": "2" * 64,
        "receiptSha256": "d" * 64,
        "sourceSha": "b" * 40,
        "imageDigest": "sha256:" + "c" * 64,
        "phase": "backup",
        "steps": {},
        "approval": None,
    }


class ReleaseTests(unittest.TestCase):
    def test_validation_runtime_preserves_retained_lane(self):
        for upstream in (None, {"tag": "v2026.10.5"}, {"tag": "v2026.9.8"}):
            self.assertEqual(release.validation_node_version({"upstream": upstream}), "24.21.0")
        self.assertEqual(release.validation_node_version({"upstream": {"tag": "v2026.10.6"}}), "24.22.1")
        self.assertEqual(release.validation_node_version({"upstream": {"tag": "v2026.10.7"}}), "24.22.1")
        workflow = (Path(__file__).resolve().parents[2] /
                    ".github/workflows/fork-release-pipeline.yml").read_text()
        self.assertIn("node-version: ${{ steps.candidate.outputs.node_version }}", workflow)
        self.assertIn("node-version: ${{ steps.identity.outputs.node_version }}", workflow)

    def test_seed_manifest_is_exact_and_not_production_eligible(self):
        manifest, digest = release.manifest_at(Path(__file__).with_name("manifest.json"))
        self.assertEqual(len(digest), 64)
        self.assertFalse(manifest["productionEligible"])
        self.assertEqual(manifest["source"]["patches"][-1]["commit"], manifest["source"]["commit"])

    def test_manifest_rejects_unpinned_or_duplicate_gate(self):
        manifest, _ = release.manifest_at(Path(__file__).with_name("manifest.json"))
        manifest["gates"]["producerConsumer"].append(manifest["gates"]["patchLifecycle"][0])
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "manifest.json"
            candidate.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(release.Refusal, "duplicate gate"):
                release.manifest_at(candidate)
            manifest["gates"]["producerConsumer"].pop()
            manifest["productionEligible"] = True
            candidate.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(release.Refusal, "requires PR review"):
                release.manifest_at(candidate)

    def test_image_consumer_rejects_changed_source_or_producer_artifact(self):
        manifest_path = Path(__file__).with_name("manifest.json")
        manifest, manifest_hash = release.manifest_at(manifest_path)
        receipt = {
            "schema": "openclaw.fork-release-image.v2",
            "inventorySha256": "e" * 64,
            "manifestSha256": manifest_hash,
            "repository": manifest["repository"],
            "sourceSha": manifest["source"]["commit"],
            "sourceTree": manifest["source"]["tree"],
            "architecture": "amd64",
            "indexDigest": "sha256:" + "a" * 64,
            "imageDigest": "sha256:" + "b" * 64,
            "configDigest": "sha256:" + "c" * 64,
            "producer": {"workflowSha": "d" * 40, "runId": "42", "attempt": "1"},
            "artifactName": f"fork-release-{manifest['source']['commit']}-42-1",
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            path.write_text(json.dumps(receipt))
            self.assertEqual(release.receipt_at(path, manifest, manifest_hash, "e" * 64)["indexDigest"], receipt["indexDigest"])
            receipt["sourceTree"] = "e" * 40
            path.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(release.Refusal, "tree mismatch"):
                release.receipt_at(path, manifest, manifest_hash, "e" * 64)
            receipt["sourceTree"] = manifest["source"]["tree"]
            receipt["artifactName"] += "-retry"
            path.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(release.Refusal, "artifact name mismatch"):
                release.receipt_at(path, manifest, manifest_hash, "e" * 64)
            receipt["artifactName"] = f"fork-release-{manifest['source']['commit']}-42-1"
            receipt["indexDigest"] = "sha256:invalid"
            path.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(release.Refusal, "invalid indexDigest"):
                release.receipt_at(path, manifest, manifest_hash, "e" * 64)


    def test_receipt_refuses_unbound_v1_and_changed_inventory(self):
        manifest, manifest_hash = release.manifest_at(Path(__file__).with_name("manifest.json"))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            path.write_text(json.dumps({"schema": "openclaw.fork-release-image.v1"}))
            with self.assertRaisesRegex(release.Refusal, "schema"):
                release.receipt_at(path, manifest, manifest_hash, "e" * 64)
            path.write_text(json.dumps({"schema": "openclaw.fork-release-image.v2",
                                        "manifestSha256": manifest_hash, "inventorySha256": "f" * 64}))
            with self.assertRaisesRegex(release.Refusal, "inventory mismatch"):
                release.receipt_at(path, manifest, manifest_hash, "e" * 64)

    def test_gcp_producer_uses_private_execution_binding_without_github_aliases(self):
        producer = {"kind": "gcp", "toolingSha": "a" * 40, "operationId": "b" * 32,
                    "attempt": "2", "executionSha256": "c" * 64}
        release.validate_producer(producer)
        self.assertEqual(release.image_artifact_name("d" * 40, producer),
                         f"fork-release-{'d' * 40}-gcp-{'b' * 32}-2")
        for field in ("toolingSha", "operationId", "attempt", "executionSha256"):
            changed = {**producer, field: "invalid"}
            with self.subTest(field=field), self.assertRaises(release.Refusal):
                release.validate_producer(changed)
        for extra in ("workflowSha", "runId", "instanceId", "privatePath"):
            with self.subTest(extra=extra), self.assertRaisesRegex(release.Refusal, "producer fields"):
                release.validate_producer({**producer, extra: "private"})

    def test_source_only_gcp_receipt_binds_source_pr_head(self):
        manifest, manifest_hash = release.manifest_at(Path(__file__).with_name("manifest.json"))
        manifest["review"] = {"prNumber": 18, "baseSha": "1" * 40, "changedDiffSha256": "2" * 64}
        producer = {"kind": "gcp", "toolingSha": "a" * 40, "operationId": "b" * 32,
                    "attempt": "1", "executionSha256": "c" * 64}
        receipt = {"schema": "openclaw.fork-release-image.v2", "manifestSha256": manifest_hash,
                   "inventorySha256": "e" * 64, "repository": manifest["repository"],
                   "sourceSha": manifest["source"]["commit"], "sourceTree": manifest["source"]["tree"],
                   "architecture": "amd64", "indexDigest": "sha256:" + "a" * 64,
                   "imageDigest": "sha256:" + "b" * 64, "configDigest": "sha256:" + "c" * 64,
                   "producer": producer,
                   "artifactName": release.image_artifact_name(manifest["source"]["commit"], producer),
                   "review": {**manifest["review"], "headSha": manifest["source"]["commit"]}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            path.write_text(json.dumps(receipt))
            self.assertFalse(manifest["productionEligible"])
            self.assertEqual(release.receipt_at(path, manifest, manifest_hash, "e" * 64), receipt)
            receipt["review"]["headSha"] = producer["toolingSha"]
            path.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(release.Refusal, "review head differs from source"):
                release.receipt_at(path, manifest, manifest_hash, "e" * 64)

    def test_inventory_baseline_and_policy_change_operation_and_approval_identity(self):
        current = state()
        for phase in ("backup", "restore", "rehearsal"):
            current["steps"][phase] = {"state": "succeeded", "receiptId": phase + "-receipt"}
        for key in ("inventorySha256", "baselineSha256", "backupPolicySha256", "backupBindingSha256"):
            changed = copy.deepcopy(current)
            changed[key] = "9" * 64
            self.assertNotEqual(release.challenge(current), release.challenge(changed))
            if key != "backupBindingSha256":
                self.assertNotEqual(release.operation_id(current, "deploy"), release.operation_id(changed, "deploy"))

    def test_rehearsal_and_deploy_refuse_missing_admission_before_adapter_calls(self):
        for phase in ("rehearsal", "deploy"):
            current = state()
            current["phase"] = phase
            with patch.object(release, "adapter_call") as call:
                with self.assertRaisesRegex(release.Refusal, "admission interface required"):
                    release.advance(current, "adapter", "manifest", "receipt", "oci", lambda: None)
                call.assert_not_called()

    def test_adapter_rejects_missing_inventory_binding_even_for_status(self):
        current = state()
        response = {key: current[key] for key in ("manifestSha256", "baselineSha256", "backupPolicySha256", "sourceSha", "imageDigest")}
        response.update(operationId="fr-test", state="not_found")
        with patch.object(release.subprocess, "run") as runner:
            runner.return_value.returncode = 0
            runner.return_value.stdout = json.dumps(response)
            with self.assertRaisesRegex(release.Refusal, "inventorySha256"):
                release.adapter_call("adapter", "status", "backup", "fr-test", current, "manifest", "receipt", "oci")

    def test_live_admission_batches_backup_failures_and_binds_immutable_archive(self):
        import preflight
        current = state()
        current.pop("backupBindingSha256")
        current["phase"] = "rehearsal"
        current["steps"] = {phase: {"state": "succeeded", "receiptId": phase + "-receipt"}
                            for phase in ("backup", "restore")}
        now = preflight.utc("2026-10-11T01:00:00Z")
        baseline = {"sourceSha": "3" * 40, "imageDigest": "sha256:" + "4" * 64,
                    "mutableInventorySha256": "5" * 64}
        policy = {"schema": "openclaw.fork-backup-policy.v1", "maxAgeSeconds": 3600,
                  "retainSeconds": 86400}
        evidence = {"schema": "openclaw.fork-backup-evidence.v1", "baseline": baseline,
                    "archive": {"receiptId": "backup-receipt", "sha256": "6" * 64,
                                "sizeBytes": 100, "exists": True, "capturedAt": "2026-10-11T00:30:00Z",
                                "verifiedAt": "2026-10-11T00:59:00Z", "retainUntil": "2026-10-13T00:00:00Z"},
                    "restore": {"receiptId": "restore-receipt", "archiveSha256": "6" * 64,
                                "imageDigest": current["imageDigest"], "state": "passed"}}
        response = {key: current[key] for key in ("manifestSha256", "inventorySha256", "baselineSha256", "backupPolicySha256", "sourceSha", "imageDigest")}
        response.update(schema="openclaw.fork-private-admission.v1", checkedAt="2026-10-11T01:00:00Z", evidence=evidence)
        with patch.object(release.subprocess, "run") as runner:
            runner.return_value.returncode = 0
            runner.return_value.stdout = json.dumps(response)
            release.backup_admission("adapter", current, "manifest", "receipt", "oci", baseline, policy, now)
            binding = current["backupBindingSha256"]
            evidence["archive"]["verifiedAt"] = "2026-10-11T01:00:00Z"
            runner.return_value.stdout = json.dumps(response)
            release.backup_admission("adapter", current, "manifest", "receipt", "oci", baseline, policy, now)
            self.assertEqual(binding, current["backupBindingSha256"])
            evidence["archive"]["exists"] = False
            evidence["archive"]["capturedAt"] = "2026-10-10T00:00:00Z"
            evidence["archive"]["retainUntil"] = "2026-10-11T02:00:00Z"
            evidence["restore"]["state"] = "not_run"
            runner.return_value.stdout = json.dumps(response)
            with self.assertRaises(release.Refusal) as error:
                release.backup_admission("adapter", current, "manifest", "receipt", "oci", baseline, policy, now)
            for code in ("backup.archive.absent", "backup.archive.stale", "backup.archive.retention_short", "backup.restore.unproved"):
                self.assertIn(code, str(error.exception))
            evidence["archive"].update(exists=True, capturedAt="2026-10-11T00:30:00Z",
                                       retainUntil="2026-10-13T00:00:00Z", sha256="7" * 64)
            evidence["restore"].update(state="passed", archiveSha256="7" * 64)
            runner.return_value.stdout = json.dumps(response)
            with self.assertRaisesRegex(release.Refusal, "identity changed"):
                release.backup_admission("adapter", current, "manifest", "receipt", "oci", baseline, policy, now)

    def test_live_admission_refuses_unavailable_stale_and_changed_baseline(self):
        import preflight
        current = state()
        current["phase"] = "deploy"
        current["steps"] = {phase: {"state": "succeeded", "receiptId": phase + "-receipt"} for phase in ("backup", "restore")}
        with patch.object(release.subprocess, "run") as runner:
            runner.return_value.returncode = 1
            with self.assertRaisesRegex(release.Refusal, "unavailable"):
                release.backup_admission("adapter", current, "manifest", "receipt", "oci", {}, {}, preflight.utc("2026-10-11T01:00:00Z"))
            runner.return_value.returncode = 0
            response = {key: current[key] for key in ("manifestSha256", "inventorySha256", "baselineSha256", "backupPolicySha256", "sourceSha", "imageDigest")}
            response.update(schema="openclaw.fork-private-admission.v1", checkedAt="2026-10-11T00:00:00Z", evidence=None)
            runner.return_value.stdout = json.dumps(response)
            with self.assertRaises(release.Refusal) as error:
                release.backup_admission("adapter", current, "manifest", "receipt", "oci", {}, {"maxAgeSeconds": 1, "retainSeconds": 1}, preflight.utc("2026-10-11T01:00:00Z"))
            self.assertIn("admission.stale", str(error.exception))
            self.assertIn("backup.fields", str(error.exception))

    def test_rehearsal_stops_for_exact_approval_then_uses_same_digest(self):
        current = state()
        calls = []

        def adapter(_path, action, phase, operation_id, progress, *_rest):
            calls.append((action, phase, progress["imageDigest"]))
            if action == "status":
                return {"state": "not_found"}
            response = {"state": "succeeded", "operationId": operation_id, "receiptId": phase + "-receipt"}
            if phase in ("rehearsal", "deploy", "health"):
                response["imageDigest"] = progress["imageDigest"]
            return response

        with patch.object(release, "adapter_call", side_effect=adapter):
            release.advance(current, "adapter", "manifest", "receipt", "oci", lambda: None, lambda progress: None)
            self.assertEqual(current["phase"], "awaiting_approval")
            self.assertEqual({phase for _, phase, _ in calls}, {"backup", "restore", "rehearsal"})
            approval = release.challenge(current)
            current["approval"] = approval
            current["phase"] = "deploy"
            release.advance(current, "adapter", "manifest", "receipt", "oci", lambda: None, lambda progress: None)
        self.assertEqual(current["phase"], "completed")
        self.assertEqual({digest for _, _, digest in calls}, {current["imageDigest"]})
        self.assertEqual(current["steps"]["deploy"]["attempts"], 1)


    def test_resumed_accepted_deploy_reconciles_before_live_baseline_admission(self):
        current = state()
        current["phase"] = "deploy"
        current["steps"]["deploy"] = {"state": "issued", "attempts": 1,
                                     "operationId": release.operation_id(current, "deploy")}
        def adapter(_path, action, phase, op_id, progress, *_rest):
            self.assertEqual(action, "status")
            return {"state": "succeeded", "operationId": op_id, "receiptId": phase + "-receipt",
                    "imageDigest": progress["imageDigest"]}
        with patch.object(release, "adapter_call", side_effect=adapter), patch.object(release, "backup_admission") as admission:
            release.advance(current, "adapter", "manifest", "receipt", "oci", lambda: None, admission)
            self.assertEqual(current["phase"], "completed")
            admission.assert_not_called()
            self.assertEqual(current["steps"]["deploy"]["attempts"], 1)

    def test_admission_uses_time_after_adapter_observation(self):
        import preflight
        current = state()
        current["steps"] = {phase: {"state": "succeeded", "receiptId": phase + "-receipt"} for phase in ("backup", "restore")}
        response = {key: current[key] for key in ("manifestSha256", "inventorySha256", "baselineSha256", "backupPolicySha256", "sourceSha", "imageDigest")}
        response.update(schema="openclaw.fork-private-admission.v1", checkedAt="2026-10-11T01:00:10Z", evidence=None)
        order = []
        def observe(*args, **kwargs):
            order.append("adapter")
            result = type("Result", (), {})()
            result.returncode, result.stdout = 0, json.dumps(response)
            return result
        from datetime import datetime
        class Clock(datetime):
            @staticmethod
            def now(_zone):
                order.append("clock")
                return datetime(2026, 10, 11, 1, 0, 11, tzinfo=preflight.timezone.utc)
        with patch.object(release.subprocess, "run", side_effect=observe), patch.object(preflight, "datetime", Clock):
            # Archive body deliberately absent; timestamp must still be correctly assessed.
            with self.assertRaises(release.Refusal) as error:
                release.backup_admission("adapter", current, "manifest", "receipt", "oci", {}, {"maxAgeSeconds": 1, "retainSeconds": 1})
            self.assertNotIn("admission.stale", str(error.exception))
        self.assertEqual(order, ["adapter", "clock"])

    def test_uncertain_invoke_reconciles_operation_without_second_dispatch(self):
        current = state()
        invocations = []
        observed = False
        saved = []

        def adapter(_path, action, phase, operation_id, progress, *_rest):
            nonlocal observed
            if action == "invoke":
                self.assertEqual(current["steps"][phase]["state"], "issued")
                self.assertEqual(current["steps"][phase]["attempts"], 1)
                self.assertIn((phase, "issued", 1), saved)
                invocations.append((phase, operation_id))
                return {"state": "unknown"}
            if observed and phase == "backup":
                return {"state": "succeeded", "operationId": operation_id, "receiptId": "backup-1"}
            return {"state": "not_found"}

        with patch.object(release, "adapter_call", side_effect=adapter):
            def save():
                step = current["steps"].get(current["phase"])
                if step:
                    saved.append((current["phase"], step["state"], step["attempts"]))

            release.advance(current, "adapter", "manifest", "receipt", "oci", save)
            self.assertEqual(current["phase"], "backup")
            observed = True
            release.advance(current, "adapter", "manifest", "receipt", "oci", save)
        backup_invocations = [operation_id for phase, operation_id in invocations if phase == "backup"]
        self.assertEqual(len(backup_invocations), 1)
        self.assertEqual(current["steps"]["backup"]["operationId"], backup_invocations[0])
        self.assertEqual(current["phase"], "restore")

    def test_approval_challenge_requires_backup_restore_and_rehearsal(self):
        current = state()
        with self.assertRaisesRegex(release.Refusal, "not complete"):
            release.challenge(current)
        for phase in ("backup", "restore", "rehearsal"):
            current["steps"][phase] = {"state": "succeeded", "receiptId": phase + "-receipt"}
        first = release.challenge(current)
        current["steps"]["rehearsal"]["receiptId"] = "different-rehearsal"
        self.assertNotEqual(first, release.challenge(current))

    def test_adapter_rejects_changed_image_digest(self):
        current = state()
        with patch.object(release.subprocess, "run") as runner:
            runner.return_value.returncode = 0
            runner.return_value.stdout = json.dumps({**{key: current[key] for key in ("manifestSha256", "inventorySha256", "baselineSha256", "backupPolicySha256", "sourceSha")},
                "operationId": "fr-test", "state": "succeeded", "receiptId": "proof-1",
                "imageDigest": "sha256:" + "0" * 64})
            with self.assertRaisesRegex(release.Refusal, "binding changed: imageDigest"):
                release.adapter_call("adapter", "invoke", "deploy", "fr-test", current,
                                     "manifest", "receipt", "oci")

    def test_health_failure_runs_rollback_before_cleanup(self):
        current = state()
        current["phase"] = "health"
        current["steps"]["backup"] = {"state": "succeeded", "receiptId": "backup-1"}
        current["steps"]["restore"] = {"state": "succeeded", "receiptId": "restore-1"}
        current["steps"]["rehearsal"] = {"state": "succeeded", "receiptId": "rehearsal-1"}
        phases = []

        def adapter(_path, action, phase, operation_id, progress, *_rest):
            if action == "status":
                return {"state": "not_found"}
            phases.append(phase)
            if phase == "health":
                return {"state": "failed", "operationId": operation_id,
                        "rollbackSafe": True, "rollbackFenceReceiptId": "no-writes-1"}
            return {"state": "succeeded", "operationId": operation_id, "receiptId": phase + "-receipt"}

        with patch.object(release, "adapter_call", side_effect=adapter):
            release.advance(current, "adapter", "manifest", "receipt", "oci", lambda: None, lambda progress: None)
        self.assertEqual(phases, ["health", "rollback", "cleanup"])
        self.assertEqual(current["phase"], "rolled_back")

    def test_unfenced_failure_stops_without_rollback(self):
        current = state()
        current["phase"] = "deploy"
        phases = []

        def adapter(_path, action, phase, operation_id, progress, *_rest):
            if action == "status":
                return {"state": "not_found"}
            phases.append(phase)
            return {"state": "failed", "operationId": operation_id}

        with patch.object(release, "adapter_call", side_effect=adapter):
            release.advance(current, "adapter", "manifest", "receipt", "oci", lambda: None, lambda progress: None)
        self.assertEqual(phases, ["deploy"])
        self.assertEqual(current["phase"], "needs_operator")

    def test_bounded_retries_keep_same_operation_id(self):
        current = state()
        dispatched = []

        def adapter(_path, action, phase, operation_id, progress, *_rest):
            if action == "status":
                return {"state": "not_found"}
            dispatched.append(operation_id)
            return {"state": "unknown"}

        with patch.object(release, "adapter_call", side_effect=adapter):
            for _ in range(4):
                release.advance(current, "adapter", "manifest", "receipt", "oci", lambda: None, lambda progress: None)
        self.assertEqual(len(dispatched), 2)
        self.assertEqual(len(set(dispatched)), 1)
        self.assertEqual(current["steps"]["backup"]["attempts"], 2)

    def test_shared_deploy_lock_refuses_missing_symlink_and_contention(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock_path = root / "production-deploy.lock"
            with self.assertRaisesRegex(release.Refusal, "required"):
                with release.production_deploy_lock(None):
                    pass
            with self.assertRaisesRegex(release.Refusal, "unavailable"):
                with release.production_deploy_lock(lock_path):
                    pass
            lock_path.touch()
            (root / "link").symlink_to(lock_path)
            with self.assertRaisesRegex(release.Refusal, "unavailable"):
                with release.production_deploy_lock(root / "link"):
                    pass
            with lock_path.open("rb") as other:
                fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaisesRegex(release.Refusal, "another operations deployment"):
                    with release.production_deploy_lock(lock_path):
                        pass
            with release.production_deploy_lock(lock_path):
                pass


if __name__ == "__main__":
    unittest.main()
