"""Synthetic dd3702 cross-image startup admission tests; no remote or DB work."""

import copy
import json
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import gcp_snapshot_trial as trial
import release
import test_gcp_snapshot_trial as baseline


class Dd3702StartupOnly(unittest.TestCase):
    def setUp(self):
        # Reuse the existing small in-memory plan fixture, not its test cases.
        self.fixture = baseline.SnapshotTrialTests("test_closed_plan_and_clean_input")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.select_phase("startup")
        self.plan = self.fixture.plan
        self.clean = self.fixture.clean
        self.plan["limits"].update(memoryBytes=16 << 30, minMemoryAvailableBytes=20 << 30,
                                   readBps=320 << 20, writeBps=128 << 20,
                                   timeoutSeconds=940)
        self.image = copy.deepcopy(self.fixture.image)
        self.image.update(sourceSha="9" * 40, sourceTree="8" * 40,
                          indexDigest="sha256:" + "7" * 64)
        self.image["producer"]["toolingSha"] = "6" * 40
        self.check = {"schema": trial.DD_STARTUP_CHECK, "phase": "startup",
                      "doctorOperationId": trial.DD_DOCTOR,
                      "doctorResultSha256": trial.DD_DOCTOR_RESULT_SHA256,
                      "priorStartupResultSha256": "5" * 64,
                      "coverageReceiptSha256": "4" * 64,
                      "coverage": {}}

    def bound(self):
        return patch.multiple(trial, DD_FINAL_IMAGE={key: self.image[key] for key in
                                   trial.LEASE_PATCH_IMAGE},
                              DD_FINAL_PRODUCER=self.image["producer"]["toolingSha"],
                              DD_PRIOR_STARTUP_RESULT_SHA256="5" * 64,
                              DD_FINAL_COVERAGE_SHA256="4" * 64)

    def test_final_pins_are_deliberately_unbound(self):
        with self.assertRaisesRegex(release.Refusal, "trial.dd_final.check_identity"):
            trial.validate(self.plan, self.image, self.clean, self.check)
        with patch.object(trial, "DD_FINAL_IMAGE", None):
            with self.assertRaisesRegex(release.Refusal, "trial.dd_final.image_unbound"):
                trial.qualified_image(self.image, dd_final_startup=True)

    def test_prepared_status_discloses_disabled_pin_mismatch(self):
        self.fixture.intent["check"] = self.check
        with patch.object(trial, "load", return_value=(self.fixture.op, self.fixture.intent)):
            observed = trial.status(self.fixture.op)
        self.assertEqual(observed["state"], "prepared")
        self.assertEqual(observed["pluginPinStatus"],
                         "EXPECTED_MISMATCH_CONTROLLER_DISABLED")
        self.assertFalse(observed["promotionAuthorized"])

    def test_new_check_allows_only_new_image_and_exact_prior(self):
        with self.bound():
            trial.validate(self.plan, self.image, self.clean, self.check)
            trial.qualified_image(self.image, dd_final_startup=True)
            with self.assertRaisesRegex(release.Refusal, "trial.image.not_qualified"):
                trial.qualified_image(self.image)
            bad = copy.deepcopy(self.check)
            bad["doctorResultSha256"] = "a" * 64
            with self.assertRaisesRegex(release.Refusal, "trial.dd_final.check_identity"):
                trial.validate(self.plan, self.image, self.clean, bad)
            bad = copy.deepcopy(self.check)
            bad["priorStartupResultSha256"] = "a" * 64
            with self.assertRaisesRegex(release.Refusal, "trial.dd_final.check_identity"):
                trial.validate(self.plan, self.image, self.clean, bad)
            bad_image = copy.deepcopy(self.image)
            bad_image["indexDigest"] = "sha256:" + "a" * 64
            with self.assertRaisesRegex(release.Refusal, "trial.image.not_qualified"):
                trial.validate(self.plan, bad_image, self.clean, self.check)
            self.plan["phase"] = "doctor"
            with self.assertRaises(release.Refusal):
                trial.validate(self.plan, self.image, self.clean, self.check)

    def test_prestart_image_inspection_keeps_new_check_bound(self):
        loaded = {"Id": self.image["indexDigest"], "Os": "linux", "Architecture": "amd64",
                  "Config": {"Labels": {"org.opencontainers.image.revision": self.image["sourceSha"],
                                        "org.opencontainers.image.version": self.image["version"]},
                             "Volumes": None, "Env": []}}
        with self.bound(), patch.object(trial, "docker", return_value=json.dumps([loaded]).encode()):
            with self.assertRaisesRegex(release.Refusal, "trial.image.not_qualified"):
                trial.observe_image(self.image, "startup")
            self.assertEqual(trial.observe_image(self.image, "startup", self.check)["loadedId"],
                             self.image["indexDigest"])

    def test_original_backup_metadata_is_exact_and_read_only(self):
        root = self.fixture.dataset
        rows, files = [], []
        for number in range(11):
            item = root / (f"agent{number}.sqlite.pre-startup-migration-{trial.DD_BACKUP_ID}.bak")
            item.write_bytes(b"synthetic")
            info = item.lstat()
            allocated = info.st_blocks * 512
            rows.append({"path": str(item), "kind": "migration-backup",
                         "classification": "native-revalidation-required",
                         "disposition": "retain", "nativeDiscardOnRetry": False,
                         "device": info.st_dev, "inode": info.st_ino, "links": info.st_nlink,
                         "sizeBytes": info.st_size, "allocatedBytes": allocated})
            files.append({"path": str(item), "device": info.st_dev, "inode": info.st_ino,
                          "links": info.st_nlink, "sizeBytes": info.st_size,
                          "allocatedBytes": allocated, "modifiedNs": info.st_mtime_ns,
                          "changedNs": info.st_ctime_ns, "ownerUid": info.st_uid,
                          "mode": stat.S_IMODE(info.st_mode)})
        files.sort(key=lambda entry: entry["path"])
        prior = {"clean": {"mountRoot": str(root)},
                 "check": {"reconciliation": {"artifacts": rows}}}
        receipt = {"backupId": trial.DD_BACKUP_ID,
                   "backupManifestSha256": "a" * 64, "backupFiles": files}
        reuse = {"backupId": trial.DD_BACKUP_ID, "backupCount": 11,
                 "manifestSha256": "a" * 64,
                 "targetSourceSha": trial.LEASE_PATCH_IMAGE["sourceSha"],
                 "targetImageReceiptSha256": trial.LEASE_PATCH_RECEIPT_SHA256}
        with patch.object(trial, "backup_reuse", return_value=reuse):
            trial.validate_dd_original_backup_files(prior, receipt)
            files[0]["modifiedNs"] += 1
            with self.assertRaisesRegex(release.Refusal, "trial.dd_final.backup_changed"):
                trial.validate_dd_original_backup_files(prior, receipt)

    def test_dataset_transfer_requires_settled_startup_lease_not_older_doctor(self):
        op = self.fixture.op
        intent = self.fixture.intent
        intent["check"] = self.check
        lease = op.parent / ("dataset-" + trial.digest(self.clean["mountRoot"].encode()) + ".json")
        current = {"operationId": trial.DD_PRIOR_STARTUP, "intentSha256": "a" * 64}
        older = {"operationId": trial.DD_DOCTOR, "intentSha256": "b" * 64}
        prior = {**older, "datasetLeasePredecessor": current}
        def reserve(*_args, reserve_resource=None):
            reserve_resource()
        def attempt():
            with patch.object(trial, "load", return_value=(op, intent)), \
                 patch.object(trial.sys, "platform", "linux"), \
                 patch.object(trial, "phase_prerequisites", return_value=prior), \
                 patch.object(trial, "snapshot_paths", return_value={}), \
                 patch.object(trial, "block_devices", return_value=self.fixture.devices), \
                 patch.object(trial, "no_other_writer"), \
                 patch.object(trial, "observe_image", return_value={"loadedId": self.image["indexDigest"], "env": []}), \
                 patch.object(trial, "capacity", return_value={"dataFreeBytes": 200 << 30}), \
                 patch.object(trial.durable, "reserve_heavy_workload", side_effect=reserve), \
                 patch.object(trial.Path, "read_text", return_value="synthetic-boot"), \
                 patch.object(trial, "status", return_value={"state": "unknown"}), \
                 patch.object(trial.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as dispatch:
                result = trial.start(op)
                return result, dispatch.call_count
        with self.assertRaisesRegex(release.Refusal, "trial.dd_final.missing_predecessor_claim"):
            attempt()
        self.assertFalse((op / "start-intent.json").exists())
        reservation = {"operationId": op.name,
                       "intentSha256": trial.digest((op / "intent.json").read_bytes())}
        lease.write_bytes(trial.durable.encode(reservation))
        lease.chmod(0o600)
        with self.assertRaisesRegex(release.Refusal, "trial.dd_final.lease_changed"):
            attempt()
        self.assertFalse((op / "start-intent.json").exists())
        lease.write_bytes(trial.durable.encode(older))
        lease.chmod(0o600)
        with self.assertRaisesRegex(release.Refusal, "trial.dataset.reserved"):
            attempt()
        self.assertFalse((op / "start-intent.json").exists())
        lease.write_bytes(trial.durable.encode(current))
        self.assertEqual(attempt(), ({"state": "unknown"}, 1))
        self.assertEqual(trial.durable.read_private(lease),
                         {"operationId": op.name,
                          "intentSha256": trial.digest((op / "intent.json").read_bytes())})
        trial.verify_dd_startup_claim(op, intent, prior)
        lease.write_bytes(trial.durable.encode(older))
        with self.assertRaisesRegex(release.Refusal, "trial.dd_final.lease_changed"):
            trial.verify_dd_startup_claim(op, intent, prior)
        lease.write_bytes(trial.durable.encode({"operationId": op.name,
                             "intentSha256": trial.digest((op / "intent.json").read_bytes())}))
        (op / "dataset-previous.json").write_bytes(trial.durable.encode(older))
        with self.assertRaisesRegex(release.Refusal, "trial.dd_final.lease_changed"):
            trial.verify_dd_startup_claim(op, intent, prior)


if __name__ == "__main__":
    unittest.main()
