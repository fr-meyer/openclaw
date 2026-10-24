import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import hosted_export as export
import hosted_privacy as privacy
from test_hosted_privacy import Layout, SOURCE, TOOLING


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

    def test_shared_privacy_check_refuses_failed_status_and_forged_member_qualification(self):
        for change in ({"status": "failed"}, {"publicMemberQualification": {"status": "passed"}}):
            with self.subTest(change=change), self.assertRaises(export.Refusal):
                export.require_clean_privacy({**self.privacy, **change})
        source = privacy.PUBLIC_MEMBER_QUALIFICATION["sourceSha"]
        with self.assertRaisesRegex(export.Refusal, "source qualification proof missing"):
            export.require_clean_privacy({**self.privacy, "sourceSha": source})
        seal, scan, resources = copy.deepcopy((self.seal, self.privacy, self.resources))
        for value in (seal, scan, resources):
            value["sourceSha"] = source
        seal["buildContext"]["sourceSha"] = source
        seal["runtimeQualification"]["sourceSha"] = source
        seal["artifactName"] = f"fork-release-{source}-12-1"
        with self.assertRaisesRegex(export.Refusal, "source qualification proof missing"):
            export.validate(seal, scan, resources, **{**self.args, "source": source})

    def test_privacy_only_cli_binds_exact_receipt_and_redacts_refusals(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "privacy-private-marker.json"
            raw = json.dumps(self.privacy).encode()
            path.write_bytes(raw)
            command = ["python3", str(Path(export.__file__)), "check-privacy", "--privacy", str(path),
                       "--sha256", hashlib.sha256(raw).hexdigest(), "--source-sha", self.args["source"],
                       "--tooling-sha", self.args["tooling"], "--index-digest", self.args["index"]]
            passed = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(passed.returncode, 0, passed.stderr)
            self.assertEqual(json.loads(passed.stdout), {
                "status": "passed", "privacyReceiptSha256": hashlib.sha256(raw).hexdigest()})
            for flag, value in (("--sha256", "0" * 64), ("--source-sha", "f" * 40),
                                ("--tooling-sha", "f" * 40), ("--index-digest", "sha256:" + "f" * 64)):
                changed = command.copy()
                changed[changed.index(flag) + 1] = value
                failed = subprocess.run(changed, capture_output=True, text=True)
                self.assertEqual(failed.returncode, 1)
                self.assertEqual(json.loads(failed.stdout), {
                    "status": "failed", "reason": "privacy_not_clean_or_bound"})
                self.assertNotIn("privacy-private-marker", failed.stdout + failed.stderr)

    def test_receipt_reader_refuses_links_and_bounds_a_file_growing_during_read(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            path.write_bytes(b"{}")
            link = Path(directory) / "link.json"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                export.read_receipt(link)
            original = export.os.fdopen
            requests = []
            class GrowingRead:
                def __init__(self, descriptor, mode):
                    self.stream = original(descriptor, mode)
                def __enter__(self):
                    self.stream.__enter__()
                    return self
                def __exit__(self, *args):
                    return self.stream.__exit__(*args)
                def fileno(self):
                    return self.stream.fileno()
                def read(self, maximum):
                    requests.append(maximum)
                    with path.open("ab") as output:
                        output.write(b"x" * (1024 * 1024 + 10))
                    return self.stream.read(maximum)
            with patch.object(export.os, "fdopen", GrowingRead), self.assertRaisesRegex(export.Refusal, "changed"):
                export.read_receipt(path)
            self.assertEqual(requests, [1024 * 1024 + 1])

    def test_retained_closure_rehashes_blobs_and_binds_all_root_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Layout(directory)
            def closure():
                return export.RetainedClosure(directory, fixture.index["digest"], SOURCE, TOOLING).closure_digest()
            before = closure()
            self.assertEqual(closure(), before)
            root = Path(directory) / "index.json"
            value = json.loads(root.read_bytes())
            value["annotations"] = {"public-note": "changed"}
            root.write_text(json.dumps(value))
            self.assertNotEqual(closure(), before)
            value["annotations"] = {"public-note": "https://synthetic:example@invalid.test"}
            root.write_text(json.dumps(value))
            with self.assertRaisesRegex(export.Refusal, "metadata privacy"):
                closure()
            value.pop("annotations")
            root.write_text(json.dumps(value))
            blob = Path(directory) / "blobs" / "sha256" / fixture.runtime["digest"][7:]
            blob.write_bytes(blob.read_bytes().replace(b"schemaVersion", b"schemaVersioN"))
            with self.assertRaises(privacy.Refusal):
                closure()

    def test_retained_closure_rejects_orphans_and_root_extras_without_unpacking_layers(self):
        for name in ("private-extra.json", "blobs/sha256/" + "f" * 64):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                fixture = Layout(directory)
                (Path(directory) / name).write_bytes(b"uninspected")
                with patch.object(privacy.Inspector, "scan_layer", side_effect=AssertionError("must not unpack")):
                    with self.assertRaisesRegex(privacy.Refusal, "unexpected_export_entry"):
                        export.RetainedClosure(directory, fixture.index["digest"], SOURCE, TOOLING).closure_digest()

    def test_privacy_cli_revalidates_exact_oci_and_requires_source_specific_member_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Layout(Path(directory) / "oci")
            receipt = fixture.inspect()
            raw = json.dumps(receipt).encode()
            path = Path(directory) / "privacy.json"
            path.write_bytes(raw)
            command = ["python3", str(Path(export.__file__)), "check-privacy", "--privacy", str(path),
                       "--sha256", hashlib.sha256(raw).hexdigest(), "--source-sha", SOURCE,
                       "--tooling-sha", TOOLING, "--index-digest", fixture.index["digest"],
                       "--oci", str(fixture.directory)]
            passed = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(passed.returncode, 0, passed.stderr)
            self.assertRegex(json.loads(passed.stdout)["ociClosureSha256"], r"^[a-f0-9]{64}$")
            (fixture.directory / "private-extra.json").write_text("never-print-this")
            failed = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(failed.returncode, 1)
            self.assertEqual(json.loads(failed.stdout), {"status": "failed", "reason": "privacy_not_clean_or_bound"})
            self.assertNotIn("never-print-this", failed.stdout + failed.stderr)
            receipt["sourceSha"] = privacy.PUBLIC_MEMBER_QUALIFICATION["sourceSha"]
            raw = json.dumps(receipt).encode()
            path.write_bytes(raw)
            command = command[:-2]
            command[command.index("--source-sha") + 1] = receipt["sourceSha"]
            command[command.index("--sha256") + 1] = hashlib.sha256(raw).hexdigest()
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 1)


if __name__ == "__main__":
    unittest.main()
