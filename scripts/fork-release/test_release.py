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
        "schema": "openclaw.fork-release-progress.v1",
        "candidate": "example",
        "manifestSha256": "a" * 64,
        "receiptSha256": "d" * 64,
        "sourceSha": "b" * 40,
        "imageDigest": "sha256:" + "c" * 64,
        "phase": "backup",
        "steps": {},
        "approval": None,
    }


class ReleaseTests(unittest.TestCase):
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
            "schema": "openclaw.fork-release-image.v1",
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
            self.assertEqual(release.receipt_at(path, manifest, manifest_hash)["indexDigest"], receipt["indexDigest"])
            receipt["sourceTree"] = "e" * 40
            path.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(release.Refusal, "tree mismatch"):
                release.receipt_at(path, manifest, manifest_hash)
            receipt["sourceTree"] = manifest["source"]["tree"]
            receipt["artifactName"] += "-retry"
            path.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(release.Refusal, "artifact name mismatch"):
                release.receipt_at(path, manifest, manifest_hash)
            receipt["artifactName"] = f"fork-release-{manifest['source']['commit']}-42-1"
            receipt["indexDigest"] = "sha256:invalid"
            path.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(release.Refusal, "invalid indexDigest"):
                release.receipt_at(path, manifest, manifest_hash)

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
            release.advance(current, "adapter", "manifest", "receipt", "oci", lambda: None)
            self.assertEqual(current["phase"], "awaiting_approval")
            self.assertEqual({phase for _, phase, _ in calls}, {"backup", "restore", "rehearsal"})
            approval = release.challenge(current)
            current["approval"] = approval
            current["phase"] = "deploy"
            release.advance(current, "adapter", "manifest", "receipt", "oci", lambda: None)
        self.assertEqual(current["phase"], "completed")
        self.assertEqual({digest for _, _, digest in calls}, {current["imageDigest"]})
        self.assertEqual(current["steps"]["deploy"]["attempts"], 1)

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
            runner.return_value.stdout = json.dumps({
                "operationId": "fr-test", "state": "succeeded", "receiptId": "proof-1",
                "imageDigest": "sha256:" + "0" * 64})
            with self.assertRaisesRegex(release.Refusal, "image digest changed"):
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
            release.advance(current, "adapter", "manifest", "receipt", "oci", lambda: None)
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
            release.advance(current, "adapter", "manifest", "receipt", "oci", lambda: None)
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
                release.advance(current, "adapter", "manifest", "receipt", "oci", lambda: None)
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
