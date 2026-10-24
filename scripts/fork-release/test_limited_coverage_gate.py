"""The later image's startup gate discloses its limited Doctor coverage."""

import copy
import unittest
from unittest.mock import patch

import gcp_snapshot_trial as trial
import release


class LimitedCoverageGate(unittest.TestCase):
    def setUp(self):
        self.source = {
            "schema": "openclaw.dd3702.source-diff-boundary.v1",
            "status": "SOURCE_DIFF_BOUNDARY_ONLY",
            "baseSourceSha": trial.LEASE_PATCH_IMAGE["sourceSha"],
            "baseTree": trial.LEASE_PATCH_IMAGE["sourceTree"],
            "successorSourceSha": trial.DD_FINAL_IMAGE["sourceSha"],
            "successorTree": trial.DD_FINAL_IMAGE["sourceTree"],
            "changedPaths": sorted(trial.DD_FINAL_CHANGED_PATHS),
            "sourceDiffSha256": "3052fca4e90ac40db8205f8ff744b10e1abb8b42ad40aaa4c289797d0f76aec3",
            "runtimeSha256": trial.DD_FINAL_RUNTIME_SHA256,
            "noChangedGitPathsOutsideExactSet": True,
            "manifestOnlyRuntimePinChanged": True,
        }
        self.assertEqual(trial.digest(trial.durable.encode(self.source)),
                         trial.DD_FINAL_SOURCE_BOUNDARY_SHA256)
        self.image = {**trial.DD_FINAL_IMAGE,
                      "producer": {"kind": "gcp", "toolingSha": trial.DD_FINAL_PRODUCER}}
        self.plan = {"imageReceiptSha256": trial.DD_FINAL_IMAGE_RECEIPT_SHA256}
        self.clean = {"configSha256": trial.DD_CLONE_CONFIG_SHA256, "mountRoot": "/mnt/synthetic-clone",
                      "filesystemDevice": 2065}
        self.prior = {"clean": self.clean}
        self.receipt = {
            "schema": trial.DD_COVERAGE_SCHEMA,
            "doctorOperationId": trial.DD_DOCTOR,
            "doctorResultSha256": trial.DD_DOCTOR_RESULT_SHA256,
            "priorStartupOperationId": trial.DD_PRIOR_STARTUP,
            "priorStartupResultSha256": trial.DD_PRIOR_STARTUP_RESULT_SHA256,
            "doctorImageReceiptSha256": trial.LEASE_PATCH_RECEIPT_SHA256,
            "finalImageReceiptSha256": trial.DD_FINAL_IMAGE_RECEIPT_SHA256,
            "finalImageIndexDigest": trial.DD_FINAL_IMAGE["indexDigest"],
            "sourceBoundary": self.source,
            "backupId": trial.DD_BACKUP_ID,
            "backupManifestSha256": "c" * 64,
            "backupFiles": [{} for _ in range(11)],
            "configSha256": trial.DD_CLONE_CONFIG_SHA256,
            "cloneRuntimeSha256": trial.DD_CLONE_RUNTIME_SHA256,
            "finalRuntimeSha256": trial.DD_FINAL_RUNTIME_SHA256,
            "pluginPinStatus": trial.DD_PLUGIN_PIN_STATUS,
            "runtimeSha256": trial.DD_FINAL_RUNTIME_SHA256,
            "catalogPostcheck": "not_established",
            "controllerDisabled": True,
            "externalEffectsDisabled": True,
            "doctorCoverage": trial.DD_COVERAGE_STATUS,
            "imageAssetBoundary": trial.DD_IMAGE_ASSET_BOUNDARY,
            "doctorImageDifferent": True,
        }

    def assess(self, changed=None):
        receipt = copy.deepcopy(self.receipt)
        if changed:
            changed(receipt)
        pin = trial.digest(trial.durable.encode(receipt))
        check = {"coverage": receipt, "coverageReceiptSha256": pin,
                 "priorStartupResultSha256": trial.DD_PRIOR_STARTUP_RESULT_SHA256}
        with patch.object(trial, "DD_FINAL_COVERAGE_SHA256", pin), \
             patch.object(trial, "validate_dd_prior_startup",
                          return_value={"operationId": trial.DD_PRIOR_STARTUP,
                                        "intentSha256": "d" * 64}), \
             patch.object(trial, "validate_dd_original_backup_files"):
            return trial.validate_dd_final_coverage(check, self.image,
                                                    self.plan, self.clean, self.prior)

    def test_limited_receipt_admitted_as_limited_only(self):
        receipt, predecessor = self.assess()
        self.assertEqual(receipt["doctorCoverage"], "LIMITED_CROSS_IMAGE_DOCTOR_COVERAGE")
        self.assertEqual(receipt["imageAssetBoundary"], "NOT_ESTABLISHED")
        self.assertEqual(receipt["pluginPinStatus"],
                         "EXPECTED_MISMATCH_CONTROLLER_DISABLED")
        self.assertEqual(predecessor["operationId"], trial.DD_PRIOR_STARTUP)

    def test_full_equivalence_or_missing_limitation_refused(self):
        for key, value in (("doctorCoverage", "FULL_DOCTOR_COVERAGE"),
                           ("imageAssetBoundary", "ESTABLISHED"),
                           ("doctorImageDifferent", False),
                           ("catalogPostcheck", "PASS"),
                           ("controllerDisabled", False),
                           ("pluginPinStatus", "MATCHED"),
                           ("cloneRuntimeSha256", trial.DD_FINAL_RUNTIME_SHA256)):
            with self.subTest(key=key), self.assertRaisesRegex(
                    release.Refusal, "trial.dd_final.coverage_identity"):
                self.assess(lambda receipt: receipt.__setitem__(key, value))

    def test_changed_config_or_fabricated_pin_status_refused(self):
        with self.assertRaisesRegex(release.Refusal, "trial.dd_final.coverage_identity"):
            self.assess(lambda receipt: receipt.__setitem__("configSha256", "a" * 64))
        self.clean["configSha256"] = "a" * 64
        with self.assertRaisesRegex(release.Refusal, "trial.dd_final.coverage_identity"):
            self.assess()

    def test_extra_source_path_refused(self):
        with self.assertRaisesRegex(release.Refusal, "trial.dd_final.source_boundary"):
            self.assess(lambda receipt: receipt["sourceBoundary"]["changedPaths"].append(
                "src/agents/doctor-migration.ts"))

    def test_wrong_final_image_refused(self):
        self.image["indexDigest"] = "sha256:" + "e" * 64
        with self.assertRaisesRegex(release.Refusal, "trial.dd_final.coverage_identity"):
            self.assess()


if __name__ == "__main__":
    unittest.main()
