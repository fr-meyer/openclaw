"""Synthetic receipt contracts only; no image, database or provider execution."""

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import hosted_export
import hosted_privacy
import hosted_reinspection as reinspection
from test_hosted_export import runtime_fixture


def packed(value):
    raw = json.dumps(value, sort_keys=True).encode()
    return raw, reinspection.digest_document(raw)


def fixtures():
    origin = {
        "schema": "openclaw.fork-release-build-origin.v1", "repository": "fr-meyer/openclaw",
        "architecture": "amd64", "version": "2026.10.5", "sourceSha": "a" * 40, "sourceTree": "f" * 40,
        "manifestSha256": "1" * 64, "inventorySha256": "2" * 64, "builtAt": "2026-10-24T01:00:00Z",
        "indexDigest": "sha256:" + "3" * 64, "imageDigest": "sha256:" + "4" * 64,
        "configDigest": "sha256:" + "5" * 64,
        "producer": {"workflowSha": "c" * 40, "runId": "12", "attempt": "1"},
        "buildContext": {"kind": "git", "repository": "https://github.com/fr-meyer/openclaw", "sourceSha": "a" * 40},
    }
    common = {key: origin[key] for key in reinspection.IDENTITY}
    privacy = {**{key: origin[key] for key in ("sourceSha", "indexDigest", "imageDigest", "configDigest")},
               "schema": "openclaw.hosted-privacy.v2", "toolingSha": "b" * 40, "status": "passed",
               "inspectionComplete": True, "findings": [], "representativeLimit": 64,
               "representativesTruncated": False, "locationIndex": [], "locationIndexTruncated": False,
               "locationIndexLimit": 4096, "locationIndexByteLimit": 512 * 1024,
               "findingSummary": {"unit": hosted_privacy.COUNT_UNIT, "total": 0,
                                  "byRule": dict.fromkeys(hosted_privacy.FINDING_RULES, 0),
                                  "byUnit": dict.fromkeys(hosted_privacy.FINDING_UNITS, 0)}}
    static = {**common, "schema": "openclaw.fork-release-static.v1", "status": "passed", "reason": None,
              "originalBuildSha256": "0" * 64, "privacyReceiptSha256": "0" * 64,
              "inspectionToolingSha": "b" * 40, "performedAt": "2026-10-24T02:03:00Z",
              "staticOnly": True, "nativeExecuted": False, "productionAuthorized": False, "promotable": False}
    native = {**copy.deepcopy(origin), "schema": "openclaw.fork-release-image.v2", "selectedExtensions": "codex,workboard",
              "bundledCodexVersion": "0.160.0", "runtimeQualification": runtime_fixture(common),
              "pluginPayload": [
                  {"id": "codex", "package": "@openclaw/codex", "version": origin["version"],
                   "codexRuntime": {"cliVersion": "0.160.0", "packageVersion": "0.160.0",
                                    "initializeVersion": "0.160.0", "initialized": True, "shutdown": "exited"}},
                  {"id": "workboard", "workboardRuntime": {"worker": "sqlite", "roundTrip": True, "closed": True}}]}
    return {"origin": origin, "privacy": privacy, "static": static, "native": native,
            "nativeExecution": {**{key: origin[key] for key in
                                   ("sourceSha", "sourceTree", "indexDigest", "imageDigest", "configDigest")},
                                "schema": "openclaw.fork-release-native-execution.v1", "status": "passed",
                                "nativeExecuted": True, "originalBuildSha256": "0" * 64,
                                "nativeReceiptSha256": "0" * 64, "verifierToolingSha": "b" * 40,
                                "performedAt": "2026-10-24T02:05:00Z"},
            "build": {**common, "schema": "openclaw.fork-release-build-success.v1", "status": "passed",
                      "buildExitCode": 0, "toolingSha": "c" * 40, "producer": copy.deepcopy(origin["producer"])},
            "resources": {"schema": "openclaw.hosted-resources.v1", "sourceSha": origin["sourceSha"],
                          "indexDigest": origin["indexDigest"], "toolingSha": "c" * 40,
                          "status": "passed", "violations": []},
            "inspection": {"schema": "openclaw.reinspection-session.v1", "toolingSha": "b" * 40,
                           "startedAt": "2026-10-24T02:00:00Z", "completedAt": "2026-10-24T02:10:00Z",
                           "privacyReceiptCapturedAt": "2026-10-24T02:01:00Z",
                           "nativePerformedAt": "2026-10-24T02:05:00Z", "nativeToolingSha": "b" * 40}}


def documents(values):
    result = copy.deepcopy(values)
    result["static"]["originalBuildSha256"] = packed(result["origin"])[1]
    result["static"]["privacyReceiptSha256"] = packed(result["privacy"])[1]
    if "nativeExecution" in result:
        result["nativeExecution"]["originalBuildSha256"] = packed(result["origin"])[1]
        result["nativeExecution"]["nativeReceiptSha256"] = packed(result["native"])[1]
    docs = {name: packed(value) for name, value in result.items()}
    return docs, {name: value[1] for name, value in docs.items()}


class ReinspectionTests(unittest.TestCase):
    def setUp(self):
        self.values = fixtures()

    def assess(self, values=None):
        return reinspection.assess(*documents(values or self.values))

    def test_new_inspection_preserves_original_producer_and_cannot_grant_promotion(self):
        before = copy.deepcopy(self.values)
        result = self.assess()
        self.assertTrue(result["allRequiredReportsPass"])
        self.assertEqual(result["originalToolingSha"], "c" * 40)
        self.assertEqual(result["inspection"]["toolingSha"], "b" * 40)
        self.assertEqual(result["originalBuild"], self.values["origin"])
        self.assertEqual(self.values, before)
        self.assertEqual(result["status"], "diagnostic")
        self.assertFalse(result["promotable"])
        self.assertFalse(result["productionAuthorized"])
        self.assertEqual(result["export"], "none")
        self.assertIn("origin_authenticity_and_admission_not_wired", result["activationBlockers"])
        with self.assertRaises(hosted_export.Refusal):
            hosted_export.validate(result, self.values["privacy"], self.values["resources"],
                                   source="a" * 40, tooling="b" * 40,
                                   index=self.values["origin"]["indexDigest"], run="12", attempt="1")

    def test_raw_bytes_must_match_independent_pins(self):
        docs, pins = documents(self.values)
        changed = copy.deepcopy(docs)
        changed["origin"] = (docs["origin"][0] + b" ", docs["origin"][1])
        with self.assertRaisesRegex(reinspection.Refusal, "pin_mismatch"):
            reinspection.assess(changed, pins)
        with self.assertRaisesRegex(reinspection.Refusal, "pins"):
            reinspection.assess(docs, {key: value for key, value in pins.items() if key != "build"})

    def test_missing_origin_never_becomes_a_new_capture(self):
        docs, pins = documents(self.values)
        del docs["origin"]
        del pins["origin"]
        with self.assertRaisesRegex(reinspection.Refusal, "documents"):
            reinspection.assess(docs, pins)
        values = copy.deepcopy(self.values)
        del values["build"]
        result = self.assess(values)
        self.assertEqual(result["checks"]["originalBuild"], "blocked_missing_build_success_receipt")
        self.assertFalse(result["allRequiredReportsPass"])
        self.assertIsNone(result["originalReceiptSha256"]["build"])
        values["build"] = {"schema": "retained.public-job-log-summary", "status": "success"}
        self.assertEqual(self.assess(values)["checks"]["originalBuild"],
                         "blocked_unrecognized_build_success_receipt")

    def test_existing_gcp_execution_hash_and_numeric_attempt_are_preserved(self):
        values = copy.deepcopy(self.values)
        origin = values["origin"]
        del origin["buildContext"]
        execution = {key: origin[key] for key in
                     ("sourceSha", "sourceTree", "manifestSha256", "inventorySha256", "indexDigest", "builtAt")}
        execution.update({"schema": "openclaw.fork-gcp-image-execution.v1", "operationId": "7" * 32,
                          "attempt": 1, "projectNumber": "123", "instanceId": "456", "toolingSha": "c" * 40,
                          "startedAt": "2026-10-24T01:01:00Z", "completedAt": "2026-10-24T01:10:00Z",
                          "buildExitCode": 0, "buildMetadataSha256": "8" * 64, "buildLogSha256": "9" * 64})
        origin["producer"] = {"kind": "gcp", "operationId": execution["operationId"], "attempt": 1,
                              "toolingSha": "c" * 40, "executionSha256": packed(execution)[1]}
        values["build"] = execution
        values["native"]["producer"] = copy.deepcopy(origin["producer"])
        del values["native"]["buildContext"]
        result = self.assess(values)
        self.assertEqual(result["checks"]["originalBuild"], "passed")
        self.assertEqual(result["originalBuild"]["producer"], origin["producer"])
        self.assertEqual(result["status"], "diagnostic")
        execution["buildExitCode"] = 1
        with self.assertRaisesRegex(reinspection.Refusal, "producer_mismatch"):
            self.assess(values)

    def test_failed_build_or_resources_stay_failed(self):
        for name, field, value in (("build", "buildExitCode", 1), ("build", "buildExitCode", False),
                                   ("build", "status", "failed"), ("resources", "status", "failed"),
                                   ("resources", "violations", ["memory.oom"])):
            values = copy.deepcopy(self.values)
            values[name][field] = value
            with self.subTest(name=name, field=field):
                self.assertFalse(self.assess(values)["allRequiredReportsPass"])

    def test_source_image_producer_and_tooling_changes_refuse(self):
        changes = [(name, field, value) for name in ("build", "privacy", "static", "resources")
                   for field, value in (("sourceSha", "d" * 40), ("indexDigest", "sha256:" + "d" * 64))]
        changes += [("build", "sourceTree", "d" * 40), ("static", "imageDigest", "sha256:" + "d" * 64),
                    ("privacy", "configDigest", "sha256:" + "d" * 64),
                    ("build", "producer", {"workflowSha": "d" * 40, "runId": "12", "attempt": "1"}),
                    ("resources", "toolingSha", "b" * 40), ("privacy", "toolingSha", "c" * 40),
                    ("static", "inspectionToolingSha", "c" * 40)]
        for name, field, value in changes:
            values = copy.deepcopy(self.values)
            values[name][field] = value
            with self.subTest(name=name, field=field), self.assertRaises(reinspection.Refusal):
                self.assess(values)

    def test_stale_or_reordered_capture_and_execution_times_refuse(self):
        for name, key, value in (("inspection", "startedAt", "2026-10-24T00:00:00Z"),
                                  ("inspection", "privacyReceiptCapturedAt", "2026-10-24T01:59:59Z"),
                                  ("inspection", "privacyReceiptCapturedAt", "2026-10-24T02:10:01Z"),
                                  ("static", "performedAt", "2026-10-24T02:00:30Z"),
                                  ("static", "performedAt", "2026-10-24T02:11:00Z"),
                                  ("inspection", "nativePerformedAt", "2026-10-24T02:02:00Z"),
                                  ("inspection", "completedAt", "2026-02-30T02:10:00Z")):
            values = copy.deepcopy(self.values)
            values[name][key] = value
            with self.subTest(name=name, key=key, value=value), self.assertRaises(reinspection.Refusal):
                self.assess(values)

    def test_failed_or_incomplete_privacy_cannot_precede_native_execution(self):
        for field, value in (("status", "failed"), ("inspectionComplete", False),
                             ("findings", [{"rule": "service_token"}])):
            values = copy.deepcopy(self.values)
            values["privacy"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(reinspection.Refusal, "native.privacy"):
                self.assess(values)
            del values["native"]
            del values["nativeExecution"]
            del values["inspection"]["nativePerformedAt"]
            del values["inspection"]["nativeToolingSha"]
            result = self.assess(values)
            self.assertEqual(result["checks"]["privacy"], "failed")
            self.assertEqual(result["checks"]["native"], "blocked_missing_native_receipt")

    def test_static_diagnostic_cannot_substitute_native_or_be_promotable(self):
        values = copy.deepcopy(self.values)
        values["native"] = copy.deepcopy(values["static"])
        self.assertEqual(self.assess(values)["checks"]["native"], "failed")
        for field, value in (("promotable", True), ("nativeExecuted", True),
                             ("productionAuthorized", True), ("staticOnly", False)):
            values = copy.deepcopy(self.values)
            values["static"][field] = value
            with self.subTest(field=field), self.assertRaises(reinspection.Refusal):
                self.assess(values)

    def test_legacy_native_seal_cannot_be_relabelled_as_new_execution(self):
        values = copy.deepcopy(self.values)
        del values["nativeExecution"]
        result = self.assess(values)
        self.assertEqual(result["checks"]["native"], "blocked_missing_native_execution_capture")
        self.assertFalse(result["allRequiredReportsPass"])
        for field, value in (("nativeToolingSha", "d" * 40),
                             ("nativePerformedAt", "2026-10-24T02:06:00Z")):
            values = copy.deepcopy(self.values)
            values["inspection"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(reinspection.Refusal, "native.capture_mismatch"):
                self.assess(values)
        values = copy.deepcopy(self.values)
        values["nativeExecution"]["performedAt"] = "2026-10-24T01:05:00Z"
        with self.assertRaisesRegex(reinspection.Refusal, "native.capture_mismatch"):
            self.assess(values)

    def test_incomplete_native_plugin_or_runtime_evidence_stays_failed(self):
        for change in ("source", "producer", "node", "codex", "workboard"):
            values = copy.deepcopy(self.values)
            native = values["native"]
            if change == "source":
                native["sourceSha"] = "d" * 40
            elif change == "producer":
                native["producer"]["workflowSha"] = "b" * 40
            elif change == "node":
                native["runtimeQualification"]["node"]["version"] = "0.0.0"
            elif change == "codex":
                native["pluginPayload"][0]["codexRuntime"]["initialized"] = False
            else:
                native["pluginPayload"][1]["workboardRuntime"]["roundTrip"] = False
            with self.subTest(change=change):
                self.assertEqual(self.assess(values)["checks"]["native"], "failed")

    def test_cli_preserves_pins_refuses_overwrite_and_never_echoes_bad_contents(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            docs, pins = documents(self.values)
            command = [sys.executable, "-B", reinspection.__file__]
            for name, (raw, _) in docs.items():
                target = root / (name + ".json")
                target.write_bytes(raw)
                command += ["--" + ("native-execution" if name == "nativeExecution" else name),
                            str(target), "--pin", name + "=" + pins[name]]
            result_path = root / "result.json"
            command += ["--output", str(result_path)]
            first = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(first.returncode, 0, first.stderr)
            result = json.loads(first.stdout)
            self.assertEqual(result["originalReceiptSha256"]["build"], pins["build"])
            self.assertFalse(result["promotable"])
            before = result_path.read_bytes()
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            self.assertEqual(result_path.read_bytes(), before)
            (root / "privacy.json").write_text('{"private":"do-not-disclose-fixture"}')
            failure = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(failure.returncode, 0)
            self.assertNotIn("do-not-disclose-fixture", failure.stdout + failure.stderr)

    def test_receipt_reader_refuses_symlinks_and_oversized_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            regular = root / "receipt.json"
            regular.write_text("{}")
            link = root / "link.json"
            link.symlink_to(regular)
            with self.assertRaises(OSError):
                reinspection.read_document(link)
            regular.write_bytes(b" " * (reinspection.MAX_RECEIPT_BYTES + 1))
            with self.assertRaisesRegex(reinspection.Refusal, "oversized"):
                reinspection.read_document(regular)


if __name__ == "__main__":
    unittest.main()
