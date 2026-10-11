import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import preflight as pf
import release


HERE = Path(__file__).parent


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.manifest, self.manifest_hash = release.manifest_at(HERE / "manifest.json")
        self.inventory = release.read_json(HERE / "patch-inventory.json")

    def check_inventory(self, value):
        checks = pf.Checks()
        pf.inventory_checks(checks, value, self.manifest, self.manifest_hash)
        return checks.errors

    def test_seed_inventory_is_manifest_bound_and_ordered(self):
        self.assertEqual(self.check_inventory(self.inventory), [])
        self.assertFalse(self.manifest["productionEligible"])

    def test_batches_stale_binding_reordered_queue_and_unresolved_disposition(self):
        value = copy.deepcopy(self.inventory)
        value["manifestSha256"] = "0" * 64
        value["patches"].reverse()
        value["patches"][0]["disposition"] = "unknown"
        errors = self.check_inventory(value)
        self.assertIn("inventory.manifest", errors)
        self.assertIn("inventory.ordered_queue", errors)
        self.assertIn("inventory.patch.0.unresolved", errors)
        self.assertIn("inventory.patch.0.dependencies", errors)

    def test_retirement_and_upstreaming_need_evidence_and_keep_regressions(self):
        for disposition in ("upstreamed", "retire"):
            with self.subTest(disposition=disposition):
                value = copy.deepcopy(self.inventory)
                value["patches"][0].update(disposition=disposition, appliedCommit=None)
                errors = self.check_inventory(value)
                self.assertIn("inventory.patch.0.decision_evidence", errors)
                self.assertIn("inventory.ordered_queue", errors)

    def test_production_inventory_requires_verified_stable_base(self):
        self.manifest["productionEligible"] = True
        self.assertIn("inventory.upstream.required", self.check_inventory(self.inventory))
        value = copy.deepcopy(self.inventory)
        value["upstream"] = {"tag": "v2026.10.1-beta.1", "tagObject": "a" * 40,
                             "commit": "b" * 40, "verificationSha256": "c" * 64}
        errors = self.check_inventory(value)
        self.assertIn("inventory.upstream.stable_tag", errors)
        self.assertIn("inventory.upstream.base", errors)

    def test_adaptation_uses_applied_identity_and_has_regression_owner(self):
        value = copy.deepcopy(self.inventory)
        value["patches"][0].update(disposition="adapt", originCommit="f" * 40)
        self.assertEqual(self.check_inventory(value), [])
        value["patches"][0]["regressionOwner"] = None
        self.assertIn("inventory.patch.0.regression_owner", self.check_inventory(value))

    def test_completed_receipt_binds_exact_image_and_rejects_private_fields(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["productionEligible"] = True
        image = {"indexDigest": "sha256:" + "a" * 64, "imageDigest": "sha256:" + "b" * 64,
                 "configDigest": "sha256:" + "c" * 64,
                 "producer": {"workflowSha": "d" * 40, "runId": "42", "attempt": "1"}, "version": "2026.9.8"}
        receipt = release.read_json(HERE / "deployment-receipt.template.json")
        receipt.update(repository=manifest["repository"], version="v2026.9.8",
                       deploymentId="0" * 32, deployedAt="2026-10-11T01:00:00Z",
                       deploymentTag="deploy/v2026.9.8/20261011T010000Z-" + "0" * 32,
                       sourceSha=manifest["source"]["commit"], sourceTree=manifest["source"]["tree"],
                       manifestSha256=self.manifest_hash, inventorySha256="e" * 64,
                       imageReceiptSha256="f" * 64, toolingSha="1" * 40,
                       privateEvidenceSha256="2" * 64,
                       rollbackDeploymentTag="deploy/v2026.7.2-beta.7/20260901T000000Z-" + "3" * 32,
                       phaseStates={p: ("not_run" if p in ("rollback", "cleanup") else "passed") for p in release.PHASES},
                       **{key: value for key, value in image.items() if key != "version"})
        checks = pf.Checks()
        pf.deployment_checks(checks, receipt, manifest, self.manifest_hash, "e" * 64, image, "f" * 64, "v2026.9.8")
        self.assertEqual(checks.errors, [])
        receipt["indexDigest"] = "sha256:" + "4" * 64
        receipt["phaseStates"]["health"] = "not_run"
        checks = pf.Checks()
        pf.deployment_checks(checks, receipt, manifest, self.manifest_hash, "e" * 64, image, "f" * 64, "v2026.9.8")
        self.assertIn("deployment.binding.indexDigest", checks.errors)
        self.assertIn("deployment.phase.health", checks.errors)
        receipt["privateBackupPath"] = "/private/never-public"
        checks = pf.Checks()
        pf.deployment_checks(checks, receipt, manifest, self.manifest_hash, "e" * 64, image, "f" * 64, "v2026.9.8")
        self.assertEqual(checks.errors, ["deployment.fields"])

    def test_completed_receipt_rejects_wrong_version_and_nested_producer_data(self):
        image = {"indexDigest": "sha256:" + "a" * 64, "imageDigest": "sha256:" + "b" * 64,
                 "configDigest": "sha256:" + "c" * 64, "version": "2026.9.9",
                 "producer": {"workflowSha": "d" * 40, "runId": "42", "attempt": "1",
                              "opaqueMetadata": "private-fixture"}}
        receipt = release.read_json(HERE / "deployment-receipt.template.json")
        receipt.update(version="v2026.9.8", producer=image["producer"])
        checks = pf.Checks()
        pf.deployment_checks(checks, receipt, self.manifest, self.manifest_hash, "e" * 64, image, "f" * 64, "v2026.10.1")
        for error in ("deployment.version.image", "deployment.version.upstream",
                      "deployment.producer.fields", "image.producer.fields"):
            self.assertIn(error, checks.errors)

    def test_legacy_exception_cannot_be_reused_by_future_source_only_candidate(self):
        self.manifest["candidate"] = "v2026.10.1"
        self.inventory["candidate"] = self.manifest["candidate"]
        self.assertIn("inventory.upstream.required", self.check_inventory(self.inventory))

    def test_wrong_path_identity_and_missing_coverage_are_batched_in_real_git(self):
        with tempfile.TemporaryDirectory() as directory:
            def git(*args):
                return subprocess.check_output(["git", "-C", directory, *args], text=True).strip()
            git("init", "-q")
            git("config", "user.name", "Fixture")
            git("config", "user.email", "fixture@example.invalid")
            root = Path(directory)
            (root / "covered.txt").write_text("base")
            git("add", ".")
            git("commit", "-qm", "base")
            base, base_tree = git("rev-parse", "HEAD"), git("rev-parse", "HEAD^{tree}")
            (root / "covered.txt").write_text("candidate")
            (root / "missing.txt").write_text("unrecorded")
            git("add", ".")
            git("commit", "-qm", "patch")
            head, tree = git("rev-parse", "HEAD"), git("rev-parse", "HEAD^{tree}")
            manifest = {"source": {"baseCommit": base, "baseTree": base_tree,
                                   "commit": head, "tree": tree, "patches": [{"commit": head, "tree": tree}]},
                        "gates": {"patchLifecycle": [], "producerConsumer": []}}
            ledger = [{"path": "covered.txt", "sourceCommit": head, "sourceTree": tree,
                       "sourceBlob": "0" * 40, "upstreamBlob": None, "candidateBlob": "1" * 40}]
            checks = pf.Checks()
            pf.source_checks(checks, manifest, directory, [], ledger)
            self.assertIn("inventory.coverage.missing", checks.errors)
            self.assertIn("inventory.path.0.source_blob", checks.errors)
            self.assertIn("inventory.path.0.upstreamBlob", checks.errors)
            self.assertIn("inventory.path.0.candidateBlob", checks.errors)

    def test_partial_object_store_is_refused_before_any_object_probe(self):
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run(["git", "-C", directory, "init", "-q"], check=True)
            subprocess.run(["git", "-C", directory, "config", "remote.fixture.promisor", "true"], check=True)
            checks = pf.Checks()
            pf.source_checks(checks, self.manifest, directory, [], [])
            self.assertEqual(checks.errors, ["source.partial_clone.unsupported"])

    def backup(self):
        baseline = {"sourceSha": "a" * 40, "imageDigest": "sha256:" + "b" * 64,
                    "mutableInventorySha256": "c" * 64}
        image = "sha256:" + "d" * 64
        evidence = {"schema": "openclaw.fork-backup-evidence.v1", "baseline": baseline.copy(),
                    "archive": {"receiptId": "private-backup", "sha256": "e" * 64, "sizeBytes": 42,
                                "exists": True, "capturedAt": "2026-10-11T00:00:00Z",
                                "verifiedAt": "2026-10-11T00:01:00Z", "retainUntil": "2026-10-13T00:00:00Z"},
                    "restore": {"receiptId": "private-restore", "archiveSha256": "e" * 64,
                                "imageDigest": image, "state": "passed"}}
        return baseline, image, evidence

    def test_backup_uses_explicit_policy_and_exact_archive_baseline_and_image(self):
        baseline, image, evidence = self.backup()
        checks = pf.Checks()
        pf.backup_checks(checks, evidence, baseline, image, pf.utc("2026-10-11T01:00:00Z"), 3600, 86400)
        self.assertEqual(checks.errors, [])
        evidence["baseline"]["mutableInventorySha256"] = "0" * 64
        evidence["archive"].update(exists=False, sizeBytes=0, retainUntil="2026-10-11T02:00:00Z")
        evidence["restore"].update(archiveSha256="1" * 64, imageDigest="sha256:" + "2" * 64, state="not_run")
        checks = pf.Checks()
        pf.backup_checks(checks, evidence, baseline, image, pf.utc("2026-10-11T02:00:00Z"), 3600, 86400)
        for error in ("backup.baseline.changed", "backup.archive.absent", "backup.archive.empty",
                      "backup.archive.stale", "backup.archive.retention_short", "backup.restore.archive",
                      "backup.restore.image", "backup.restore.unproved"):
            self.assertIn(error, checks.errors)

    def test_backup_future_time_and_missing_policy_fail_closed(self):
        baseline, image, evidence = self.backup()
        checks = pf.Checks()
        pf.backup_checks(checks, evidence, baseline, image, pf.utc("2026-10-10T23:00:00Z"), None, None)
        self.assertIn("backup.archive.time_order", checks.errors)
        self.assertIn("backup.policy.max_age", checks.errors)
        self.assertIn("backup.policy.retention", checks.errors)

    def test_cli_null_and_malformed_inventory_always_emit_refusal_json(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory_path = Path(directory) / "inventory.json"
            for value in (None, [], dict(self.inventory, patches=[]),
                          dict(self.inventory, patches=None), dict(self.inventory, patches={})):
                with self.subTest(value=value):
                    inventory_path.write_text(json.dumps(value))
                    result = subprocess.run(["python3", str(HERE / "preflight.py"),
                                             "--manifest", str(HERE / "manifest.json"),
                                             "--inventory", str(inventory_path), "--source-dir", str(HERE)],
                                            capture_output=True, text=True)
                    self.assertEqual(result.returncode, 1)
                    report = json.loads(result.stdout)
                    self.assertFalse(report["passed"])
                    self.assertFalse(report["deploymentAuthorized"])
                    self.assertNotIn("Traceback", result.stderr)

    def test_cli_supplied_null_private_and_deployment_records_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            value = Path(directory) / "null.json"
            value.write_text("null")
            result = subprocess.run(["python3", str(HERE / "preflight.py"),
                                     "--manifest", str(HERE / "manifest.json"),
                                     "--inventory", str(HERE / "patch-inventory.json"),
                                     "--source-dir", str(HERE), "--backup-evidence", str(value),
                                     "--deployment-receipt", str(value)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            report = json.loads(result.stdout)
            self.assertIn("backup.object", report["errors"])
            self.assertIn("deployment.object", report["errors"])

    def test_cli_reports_multiple_bad_inputs_without_echoing_private_values(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = root / "private.json"
            private.write_text('{"privateToken": "DO_NOT_ECHO"}')
            result = subprocess.run(["python3", str(HERE / "preflight.py"),
                                     "--manifest", str(private), "--inventory", str(root / "absent"),
                                     "--source-dir", str(root)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            report = json.loads(result.stdout)
            self.assertEqual(report["errors"], ["inventory.unreadable", "manifest.invalid"])
            self.assertFalse(report["deploymentAuthorized"])
            self.assertNotIn("DO_NOT_ECHO", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
