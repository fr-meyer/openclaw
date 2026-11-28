"""Small synthetic OCI fixtures; no remote upload, application images or DBs."""
import hashlib
import dataclasses
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import hosted_bundle as bundle
import hosted_export as export
import hosted_privacy as privacy
from test_hosted_privacy import Layout, SOURCE, TOOLING
from test_hosted_export import runtime_fixture


class HostedBundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / "fork-release"
        self.layout = Layout(self.root / "oci/default")
        p = self.layout.inspect()
        self.assertEqual(p["status"], "passed")
        self.seal = {"schema": "openclaw.fork-release-image.v2", "repository": "fr-meyer/openclaw", "architecture": "amd64",
                     "producer": {"workflowSha": TOOLING, "runId": "12", "attempt": "1"},
                     "buildContext": {"kind": "git", "repository": "https://github.com/fr-meyer/openclaw", "sourceSha": SOURCE},
                     "sourceSha": SOURCE, "indexDigest": p["indexDigest"], "imageDigest": p["imageDigest"], "configDigest": p["configDigest"],
                     "artifactName": f"fork-release-{SOURCE}-12-1"}
        self.seal["runtimeQualification"] = runtime_fixture(self.seal)
        resources = {"schema": "openclaw.hosted-resources.v1", "status": "passed", "sourceSha": SOURCE,
                     "toolingSha": TOOLING, "indexDigest": p["indexDigest"], "violations": []}
        values = [self.seal, p, resources]
        hashes = []
        for name, value in zip(bundle.RECEIPTS[:3], values):
            data = json.dumps(value, sort_keys=True).encode()
            (self.root / name).write_bytes(data)
            hashes.append(hashlib.sha256(data).hexdigest())
        self.qualification = export.validate(*values, source=SOURCE, tooling=TOOLING, index=p["indexDigest"], run="12", attempt="1", public_export=True, storage_approved=True)
        self.qualification["receiptSha256"] = dict(zip(("seal", "privacy", "resources"), hashes))
        self.write_qualification()
        self.output = self.base / "fork-upload"
        self.receipt = self.base / "bundle-receipt.json"

    def tearDown(self):
        # Tests own all fixture outputs; reset read-only dirs for platform cleanup.
        for path in self.base.iterdir():
            if path.is_dir() and not path.is_symlink():
                path.chmod(0o700)

    def write_qualification(self):
        (self.root / "hosted-qualification.json").write_text(json.dumps(self.qualification, sort_keys=True))

    def prepare(self, **kwargs):
        return bundle.prepare(self.root, self.output, self.receipt, **kwargs)

    def assert_no_publishable_output(self):
        self.assertFalse(self.receipt.exists())
        if self.output.exists():
            self.assertEqual(list(self.output.iterdir()), [])

    def test_valid_zip_stored_roundtrip_exact_filename_and_identity(self):
        with patch.object(privacy.Inspector, "scan_layer", side_effect=AssertionError("must not decompress layer again")):
            result = self.prepare()
        path = Path(result["bundlePath"])
        self.assertEqual(path.name, self.qualification["artifactName"])
        self.assertEqual(path.suffix, "")
        self.assertEqual(path.read_bytes()[:4], b"PK\x03\x04")
        self.assertEqual(result["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(result["sizeBytes"], path.stat().st_size)
        self.assertEqual(result["maximumBytes"], 2_147_483_648)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o500)
        with zipfile.ZipFile(path) as archive:
            expected = {p.relative_to(self.root).as_posix() for p in self.root.rglob("*") if p.is_file()}
            self.assertEqual(set(archive.namelist()), expected)
            self.assertTrue(all(item.compress_type == zipfile.ZIP_STORED for item in archive.infolist()))
            self.assertIsNone(archive.testzip())
        self.assertEqual(bundle.verify(self.receipt, self.output), result)

    def test_actual_bundle_cli_accepts_only_empty_ingest_without_archiving_metadata_directory(self):
        (self.layout.directory / "ingest").mkdir()
        command = [sys.executable, "-B", str(Path(bundle.__file__).resolve()), "prepare",
                   "--root", str(self.root), "--output-dir", str(self.output), "--output", str(self.receipt)]
        completed = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        result = json.loads(completed.stdout)
        with zipfile.ZipFile(result["bundlePath"]) as archive:
            self.assertNotIn("oci/default/ingest", archive.namelist())
            self.assertTrue(all(not name.startswith("oci/default/ingest/") for name in archive.namelist()))
        self.assertEqual(bundle.verify(self.receipt, self.output)["sha256"], result["sha256"])

    def test_bundle_rejects_nonempty_regular_or_linked_ingest(self):
        ingest = self.layout.directory / "ingest"
        outside = self.base / "outside-ingest"
        outside.mkdir()
        for kind in ("nonempty", "regular", "symlink"):
            if kind == "nonempty":
                ingest.mkdir()
                (ingest / "writer.lock").write_text("synthetic")
            elif kind == "regular":
                ingest.write_text("synthetic")
            else:
                ingest.symlink_to(outside, target_is_directory=True)
            with self.subTest(kind=kind), self.assertRaises((bundle.Refusal, privacy.Refusal, OSError)):
                self.prepare()
            self.assert_no_publishable_output()
            if kind == "nonempty":
                (ingest / "writer.lock").unlink()
                ingest.rmdir()
            else:
                ingest.unlink()

    def test_bundle_rechecks_empty_ingest_identity_after_streaming(self):
        ingest = self.layout.directory / "ingest"
        ingest.mkdir()
        original = bundle.write_zip
        def replace_then_stream(inputs, specs, path, limit):
            ingest.rename(self.base / "old-ingest")
            ingest.mkdir()
            return original(inputs, specs, path, limit)
        with patch.object(bundle, "write_zip", side_effect=replace_then_stream), \
                self.assertRaisesRegex(privacy.Refusal, "export_transport_changed"):
            self.prepare()
        self.assert_no_publishable_output()

    def test_complete_archive_boundary_inclusive_and_one_byte_over(self):
        first = self.prepare()
        size = first["sizeBytes"]
        exact = bundle.prepare(self.root, self.base / "exact", self.base / "exact.json", limit=size)
        self.assertEqual(exact["sizeBytes"], size)
        with self.assertRaises(bundle.Refusal):
            bundle.prepare(self.root, self.base / "small", self.base / "small.json", limit=size - 1)
        self.assertFalse((self.base / "small.json").exists())
        self.assertEqual(list((self.base / "small").iterdir()), [])
        self.assertLessEqual(max(p.stat().st_size for p in (self.base / "exact").iterdir()), size)

    def test_zip_overhead_counts_and_partial_is_removed(self):
        raw_total = sum(p.stat().st_size for p in self.root.rglob("*") if p.is_file())
        with self.assertRaises(bundle.Refusal):
            self.prepare(limit=raw_total)
        self.assert_no_publishable_output()

    def test_hard_writer_bound_refuses_before_crossing_limit(self):
        import io
        raw = io.BytesIO()
        writer = bundle.BoundedWriter(raw, 5)
        writer.write(b"12345")
        with self.assertRaises(bundle.Refusal):
            writer.write(b"6")
        self.assertEqual(raw.getvalue(), b"12345")
        writer.seek(0)
        writer.write(b"ab")
        self.assertEqual(raw.getvalue(), b"ab345")

    def test_missing_storage_or_public_export_approval_is_refused(self):
        for key, value in (("export", "none"), ("storageApprovalRecorded", False), ("artifactName", "different")):
            original = self.qualification[key]
            self.qualification[key] = value
            self.write_qualification()
            with self.subTest(key=key), self.assertRaises((bundle.Refusal, export.Refusal)):
                self.prepare()
            self.assert_no_publishable_output()
            self.qualification[key] = original

    def test_receipt_metadata_is_privacy_checked_even_with_updated_hash(self):
        path = self.root / "receipt.json"
        value = json.loads(path.read_text())
        value["unexpectedMetadata"] = "https://example:synthetic-password@example.invalid"
        data = json.dumps(value).encode()
        path.write_bytes(data)
        self.qualification["receiptSha256"]["seal"] = hashlib.sha256(data).hexdigest()
        self.write_qualification()
        with self.assertRaisesRegex(bundle.Refusal, "receipt_privacy_findings"):
            self.prepare()
        self.assert_no_publishable_output()

    def test_receipt_aggregate_refuses_even_when_details_and_index_are_empty(self):
        path = self.root / "receipt.json"
        value = json.loads(path.read_text())
        value["unexpectedMetadata"] = "https://example:synthetic-password@example.invalid"
        path.write_text(json.dumps(value))
        empty_details = dataclasses.replace(privacy.Limits(), findings=0)
        with patch.object(privacy, "Limits", return_value=empty_details), \
                patch.object(privacy, "MAX_LOCATION_ROWS", 0), \
                self.assertRaisesRegex(bundle.Refusal, "receipt_privacy_findings"):
            self.prepare()
        self.assert_no_publishable_output()

    def test_stored_receipt_hashes_are_revalidated(self):
        for name in bundle.RECEIPTS[:3]:
            path = self.root / name
            original = path.read_bytes()
            path.write_bytes(original + b" ")
            with self.subTest(name=name), self.assertRaises(bundle.Refusal):
                self.prepare()
            self.assert_no_publishable_output()
            path.write_bytes(original)

    def test_blob_content_mutation_is_refused_without_decompression(self):
        path = next((self.root / "oci/default/blobs/sha256").iterdir())
        raw = path.read_bytes()
        path.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
        with self.assertRaises((bundle.Refusal, privacy.Refusal)):
            self.prepare()
        self.assert_no_publishable_output()

    def test_changed_input_between_inspection_and_streaming_is_refused(self):
        original = bundle.write_zip
        def mutate(inputs, specs, path, limit):
            receipt = self.root / "receipt.json"
            receipt.write_bytes(receipt.read_bytes() + b" ")
            return original(inputs, specs, path, limit)
        with patch.object(bundle, "write_zip", side_effect=mutate), self.assertRaises(bundle.Refusal):
            self.prepare()
        self.assert_no_publishable_output()

    def test_orphan_blobs_and_extra_files_or_directories_are_refused(self):
        for name, directory in (("extra.log", False), ("extra", True), ("oci/extra", False), ("oci/default/blobs/sha256/" + "f" * 64, False)):
            path = self.root / name
            path.mkdir() if directory else path.write_text("synthetic")
            with self.subTest(name=name), self.assertRaises((bundle.Refusal, privacy.Refusal)):
                self.prepare()
            self.assert_no_publishable_output()
            path.rmdir() if directory else path.unlink()

    def test_added_extra_during_streaming_is_refused(self):
        original = bundle.write_zip
        def extra(inputs, specs, path, limit):
            original(inputs, specs, path, limit)
            (self.root / "private-extra").write_text("fixture")
            inputs.check_tree(specs)
        with patch.object(bundle, "write_zip", side_effect=extra), self.assertRaises(bundle.Refusal):
            self.prepare()
        self.assert_no_publishable_output()

    def test_symlink_and_nonregular_inputs_are_refused(self):
        path = self.root / "receipt.json"
        original = path.read_bytes()
        path.unlink()
        outside = self.base / "outside.json"
        outside.write_bytes(original)
        path.symlink_to(outside)
        with self.assertRaises(OSError):
            self.prepare()
        path.unlink()
        os.mkfifo(path)
        with self.assertRaises(bundle.Refusal):
            self.prepare()
        self.assert_no_publishable_output()

    def test_symlink_layout_directory_is_refused(self):
        path = self.root / "oci/default"
        path.rename(self.base / "layout")
        path.symlink_to(self.base / "layout", target_is_directory=True)
        with self.assertRaises((bundle.Refusal, privacy.Refusal, OSError)):
            self.prepare()
        self.assert_no_publishable_output()

    def test_output_must_be_fresh_private_and_separate(self):
        self.output.mkdir()
        (self.output / "keep").write_text("owned elsewhere")
        with self.assertRaises(bundle.Refusal):
            self.prepare()
        self.assertEqual((self.output / "keep").read_text(), "owned elsewhere")
        with self.assertRaises(bundle.Refusal):
            bundle.prepare(self.root, self.root / "nested", self.receipt)
        with self.assertRaises(bundle.Refusal):
            bundle.prepare(self.root, self.base / "new", self.base / "new/receipt.json")

    def test_verify_refuses_changed_bytes_inode_permissions_or_extras(self):
        result = self.prepare()
        path = Path(result["bundlePath"])
        path.chmod(0o600)
        with self.assertRaises(bundle.Refusal):
            bundle.verify(self.receipt, self.output)
        path.chmod(0o400)
        with self.assertRaises(bundle.Refusal):
            bundle.verify(self.receipt, self.output)  # ctime change remains visible
        self.output.chmod(0o700)
        (self.output / "extra").write_text("fixture")
        self.output.chmod(0o500)
        with self.assertRaises(bundle.Refusal):
            bundle.verify(self.receipt, self.output)

    def test_verify_refuses_changed_bundle_bytes_and_replaced_inode(self):
        result = self.prepare()
        path = Path(result["bundlePath"])
        raw = path.read_bytes()
        path.chmod(0o600)
        path.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
        path.chmod(0o400)
        with self.assertRaises(bundle.Refusal):
            bundle.verify(self.receipt, self.output)
        self.output.chmod(0o700)
        path.unlink()
        path.write_bytes(raw)
        path.chmod(0o400)
        self.output.chmod(0o500)
        with self.assertRaises(bundle.Refusal):
            bundle.verify(self.receipt, self.output)

    def test_verify_rechecks_path_identity_after_streaming_hash(self):
        result = self.prepare()
        path = Path(result["bundlePath"])
        original = bundle.hash_file
        def replaced(*args):
            result = original(*args)
            self.output.chmod(0o700)
            path.unlink()
            path.write_bytes(b"replacement")
            path.chmod(0o400)
            self.output.chmod(0o500)
            return result
        with patch.object(bundle, "hash_file", side_effect=replaced), self.assertRaises(bundle.Refusal):
            bundle.verify(self.receipt, self.output)

    def test_non_addressed_metadata_privacy_is_checked_again(self):
        path = self.root / "oci/default/index.json"
        data = json.loads(path.read_text())
        data["annotation"] = "https://example:synthetic-password@example.invalid"
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(bundle.Refusal, "metadata_privacy_findings"):
            self.prepare()
        self.assert_no_publishable_output()

    def test_closure_aggregate_refuses_even_without_retained_details(self):
        path = self.root / "oci/default/index.json"
        data = json.loads(path.read_text())
        data["annotation"] = "https://example:synthetic-password@example.invalid"
        path.write_text(json.dumps(data))
        empty_details = dataclasses.replace(privacy.Limits(), findings=0)
        with patch.object(privacy, "Limits", return_value=empty_details), \
                self.assertRaisesRegex(bundle.Refusal, "metadata_privacy_findings"):
            self.prepare()
        self.assert_no_publishable_output()

    def test_oversized_metadata_and_cli_no_limit_override(self):
        (self.root / "receipt.json").write_bytes(b" " * (bundle.RECEIPT_BYTES + 1))
        with self.assertRaises(bundle.Refusal):
            self.prepare()
        result = subprocess.run([sys.executable, bundle.__file__, "prepare", "--root", str(self.root), "--output-dir", str(self.output), "--output", str(self.receipt), "--limit", "999999999999"], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assert_no_publishable_output()

    def test_cli_roundtrip_returns_safe_json_and_failure_is_sanitized(self):
        command = [sys.executable, bundle.__file__, "prepare", "--root", str(self.root), "--output-dir", str(self.output), "--output", str(self.receipt)]
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(set(json.loads(result.stdout)), {"status", "artifactName", "bundlePath", "sizeBytes", "sha256"})
        verified = subprocess.run([sys.executable, bundle.__file__, "verify", "--receipt", str(self.receipt), "--output-dir", str(self.output)], capture_output=True, text=True)
        self.assertEqual(verified.returncode, 0, verified.stdout)
        self.assertEqual(json.loads(verified.stdout), json.loads(result.stdout))
        failed = subprocess.run(command, capture_output=True, text=True)
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual(json.loads(failed.stdout)["reason"], "bundle_invalid_changed_or_over_limit")
        self.assertEqual(failed.stderr, "")


if __name__ == "__main__":
    unittest.main()
