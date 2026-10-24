import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import hosted_export as export
import hosted_privacy as privacy


def runtime_fixture(common):
    return {
        **{key: common[key] for key in ("sourceSha", "imageDigest", "configDigest")},
        "schema": "openclaw.image-runtime.v1",
        "expected": {"nodeVersion": "24.22.1", "markdownVersion": "15.0.3", "argparseVersion": "3.0.3",
                     "dockerfileSha256": "1" * 64, "consumerManifestSha256": "2" * 64,
                     "lockfileSha256": "3" * 64},
        "node": {"version": "24.22.1", "platform": "linux", "architecture": "x64"},
        "markdown": {"version": "15.0.3", "argparseVersion": "3.0.3", "resolution": "pnpm-production-store",
                     "consumer": "dist/plugin-sdk/text-chunking.js", "consumerSha256": "4" * 64,
                     "render": True, "documentIsolation": True},
        "controlUi": {"indexSha256": "5" * 64, "manifestSha256": "6" * 64, "generation": "7" * 64,
                      "assetCount": 1, "assetBytes": 50},
    }


class HostedExportTests(unittest.TestCase):
    def setUp(self):
        self.args = dict(source="a" * 40, tooling="b" * 40, index="sha256:" + "c" * 64,
                         run="12", attempt="1")
        common = dict(sourceSha=self.args["source"], indexDigest=self.args["index"],
                      imageDigest="sha256:" + "d" * 64, configDigest="sha256:" + "e" * 64)
        self.seal = dict(common, schema="openclaw.fork-release-image.v2",
                         repository="fr-meyer/openclaw", architecture="amd64",
                         producer={"workflowSha": self.args["tooling"], "runId": "12", "attempt": "1"},
                         buildContext={"kind": "git", "repository": "https://github.com/fr-meyer/openclaw",
                                       "sourceSha": self.args["source"]},
                         artifactName=f'fork-release-{self.args["source"]}-12-1')
        self.seal["runtimeQualification"] = runtime_fixture(common)
        self.privacy = dict(common, schema="openclaw.hosted-privacy.v2", status="passed",
                            toolingSha=self.args["tooling"], findings=[], inspectionComplete=True,
                            findingSummary={"unit": privacy.COUNT_UNIT, "total": 0,
                                "byRule": dict.fromkeys(privacy.FINDING_RULES, 0),
                                "byUnit": dict.fromkeys(privacy.FINDING_UNITS, 0)},
                            representativeLimit=64, representativesTruncated=False,
                            locationIndex=[], locationIndexTruncated=False,
                            locationIndexLimit=4096, locationIndexByteLimit=512 * 1024)
        self.resources = dict(common, schema="openclaw.hosted-resources.v1", status="passed",
                              toolingSha=self.args["tooling"], violations=[])

    def test_default_is_ephemeral_and_public_export_requires_separate_storage_decision(self):
        result = export.validate(self.seal, self.privacy, self.resources, **self.args)
        self.assertEqual(result["export"], "none")
        self.assertFalse(result["productionAuthorized"])
        with self.assertRaisesRegex(export.Refusal, "storage"):
            export.validate(self.seal, self.privacy, self.resources, **self.args, public_export=True)
        self.assertEqual(export.validate(self.seal, self.privacy, self.resources, **self.args,
                                        public_export=True, storage_approved=True)["export"],
                         "public-actions-artifact")

    def test_every_receipt_is_bound_to_same_source_image_tooling_and_run(self):
        for i, key, value in ((0, "sourceSha", "d" * 40), (0, "indexDigest", "sha256:" + "d" * 64),
                              (0, "producer", {"workflowSha": "b" * 40, "runId": "13", "attempt": "1"}),
                              (0, "architecture", "arm64"), (0, "artifactName", "other"),
                              (1, "sourceSha", "d" * 40), (1, "toolingSha", "d" * 40),
                              (1, "indexDigest", "sha256:" + "d" * 64), (1, "status", "failed"),
                              (1, "inspectionComplete", False), (1, "configDigest", "sha256:" + "f" * 64),
                              (1, "findings", ["runtime-state"]), (2, "status", "running"),
                              (2, "indexDigest", "sha256:" + "d" * 64), (2, "violations", ["oom"])):
            receipts = copy.deepcopy([self.seal, self.privacy, self.resources])
            receipts[i][key] = value
            with self.subTest(receipt=i, key=key), self.assertRaises(export.Refusal):
                export.validate(*receipts, **self.args)

    def test_new_export_refuses_legacy_missing_or_changed_git_context(self):
        for value in (None, {}, {**self.seal["buildContext"], "sourceSha": "d" * 40},
                      {**self.seal["buildContext"], "repository": "https://example.invalid/fork"},
                      {**self.seal["buildContext"], "extra": True}):
            with self.subTest(value=value), self.assertRaisesRegex(export.Refusal, "Git source"):
                export.validate({**self.seal, "buildContext": value}, self.privacy,
                                self.resources, **self.args)

    def test_privacy_v2_requires_complete_consistent_zero_aggregates(self):
        changes = [
            {"schema": "openclaw.hosted-privacy.v1"}, {"findingSummary": None},
            {"representativesTruncated": True}, {"representativesTruncated": 0},
            {"representativeLimit": 65}, {"representativeLimit": False},
            {"refusal": "trailing_archive_data"},
            {"locationIndex": [{"rule": "service_token"}]}, {"locationIndexTruncated": True},
            {"locationIndexTruncated": 0}, {"locationIndexLimit": False},
            {"locationIndexByteLimit": 1024 * 1024},
        ]
        for field, value in (("total", 1), ("total", False), ("total", "0"),
                             ("total", 0.0), ("unit", "unique-secrets"), ("extra", 0)):
            summary = copy.deepcopy(self.privacy["findingSummary"])
            summary[field] = value
            changes.append({"findingSummary": summary})
        for catalog, name in (("byRule", "service_token"), ("byUnit", "archive_member")):
            for value in (1, -1, False, "0", 0.0, None):
                summary = copy.deepcopy(self.privacy["findingSummary"])
                summary[catalog][name] = value
                changes.append({"findingSummary": summary})
            for mutation in ("missing", "unknown"):
                summary = copy.deepcopy(self.privacy["findingSummary"])
                if mutation == "missing":
                    del summary[catalog][name]
                else:
                    summary[catalog]["unrecognized"] = 0
                changes.append({"findingSummary": summary})
        # A consistent nonzero aggregate cannot pass with zero retained details.
        summary = copy.deepcopy(self.privacy["findingSummary"])
        summary.update(total=100)
        summary["byRule"]["service_token"] = summary["byUnit"]["archive_member"] = 100
        changes.append({"findingSummary": summary, "representativeLimit": 0})
        for change in changes:
            with self.subTest(change=change), self.assertRaises(export.Refusal):
                export.validate(self.seal, {**self.privacy, **change}, self.resources, **self.args)
        for omitted in ("findingSummary", "representativeLimit", "representativesTruncated",
                        "locationIndex", "locationIndexTruncated", "locationIndexLimit", "locationIndexByteLimit"):
            stripped = {k: v for k, v in self.privacy.items() if k != omitted}
            with self.subTest(omitted=omitted), self.assertRaises(export.Refusal):
                export.validate(self.seal, stripped, self.resources, **self.args)

    def test_new_export_refuses_missing_stripped_stale_or_incomplete_runtime_proof(self):
        for value in (None, {}, [], "passed"):
            with self.subTest(value=value), self.assertRaises(export.Refusal):
                export.validate({**self.seal, "runtimeQualification": value}, self.privacy,
                                self.resources, **self.args)
        stripped = copy.deepcopy(self.seal)
        del stripped["runtimeQualification"]
        with self.assertRaises(export.Refusal):
            export.validate(stripped, self.privacy, self.resources, **self.args)
        for field, key, value in ((None, "sourceSha", "f" * 40), (None, "configDigest", "sha256:" + "f" * 64),
                                  ("node", "version", "24.21.0"), ("node", "platform", "darwin"),
                                  ("markdown", "version", "15.0.2"), ("markdown", "argparseVersion", "3.0.2"),
                                  ("markdown", "render", False), ("markdown", "documentIsolation", False),
                                  ("controlUi", "generation", "bad"), ("controlUi", "assetCount", 0),
                                  ("controlUi", "assetBytes", True), ("expected", "lockfileSha256", "bad")):
            seal = copy.deepcopy(self.seal)
            target = seal["runtimeQualification"]
            if field is not None:
                target = target[field]
            target[key] = value
            with self.subTest(field=field, key=key), self.assertRaises(export.Refusal):
                export.validate(seal, self.privacy, self.resources, **self.args)

    def test_cli_retains_hashes_and_refuses_overwrite_without_disclosing_bad_contents(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            command = ["python3", str(Path(export.__file__))]
            for name, value in zip(("seal", "privacy", "resources"),
                                   (self.seal, self.privacy, self.resources)):
                path = root / f"{name}.json"
                path.write_text(json.dumps(value))
                command += ["--" + name, str(path)]
            for name, value in (("source-sha", self.args["source"]), ("tooling-sha", self.args["tooling"]),
                                ("index-digest", self.args["index"]), ("run-id", "12"),
                                ("attempt", "1"), ("output", str(root / "result.json"))):
                command += ["--" + name, value]
            first = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(set(json.loads(first.stdout)["receiptSha256"]), {"seal", "privacy", "resources"})
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            (root / "privacy.json").write_text('{"private": "never-print-this"}')
            failed = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(failed.returncode, 0)
            self.assertNotIn("never-print-this", failed.stdout + failed.stderr)


if __name__ == "__main__":
    unittest.main()
