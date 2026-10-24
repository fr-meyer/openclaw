"""Synthetic private archive tests; no network, real image or native execution."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import private_oci_bundle as private
import hosted_bundle
import test_hosted_privacy as layouts

WORKFLOW, BUILT = "c" * 40, "2026-10-24T00:00:00Z"


def write(path, value):
    raw = private.encoded(value)
    path.write_bytes(raw)
    return raw


class Fixture:
    def __init__(self, base):
        self.base = Path(base).resolve()
        self.inputs = self.base / "build"
        self.inputs.mkdir(mode=0o700)
        self.oci = self.inputs / "oci/default"
        with patch.object(layouts, "SOURCE", private.SOURCE):
            self.layout = layouts.Layout(self.oci)
        self.manifest, self.inventory, self.metadata, self.resources = (self.inputs / name for name in
            ("manifest.json", "patch-inventory.json", "build-metadata.json", "resources.json"))
        raw = write(self.manifest, {"schema": "openclaw.fork-release.v1", "repository": "fr-meyer/openclaw",
            "source": {"commit": private.SOURCE, "tree": private.TREE},
            "image": {"architecture": "amd64", "extensions": "codex,workboard"}})
        write(self.inventory, {"schema": "openclaw.fork-patch-inventory.v1", "repository": "fr-meyer/openclaw", "manifestSha256": private.sha(raw)})
        self.index = json.loads((self.oci / "index.json").read_bytes())["manifests"][0]["digest"]
        write(self.metadata, {"containerimage.digest": self.index, "containerimage.descriptor": {"digest": self.index}})
        write(self.resources, {"schema": "openclaw.hosted-resources.v1", "status": "passed", "sourceSha": private.SOURCE,
            "toolingSha": WORKFLOW, "indexDigest": self.index, "violations": []})
        self.out, self.receipt = self.base / "archive", self.base / "receipt.json"

    def prepare(self, **changes):
        args = dict(source_sha=private.SOURCE, source_tree=private.TREE, workflow_sha=WORKFLOW, run_id="123", attempt="1", built_at=BUILT)
        args.update(changes)
        return private.prepare_from_build(self.manifest, self.inventory, self.metadata, self.resources, self.oci, self.out, self.receipt, **args)

    def command(self):
        pairs = {"manifest": self.manifest, "inventory": self.inventory, "build-metadata": self.metadata,
            "resources": self.resources, "oci-dir": self.oci, "output-dir": self.out, "output": self.receipt,
            "source-sha": private.SOURCE, "source-tree": private.TREE, "workflow-sha": WORKFLOW, "run-id": "123", "attempt": "1", "built-at": BUILT}
        return [sys.executable, "-B", str(Path(private.__file__)), "prepare-from-build", *[
            token for key, value in pairs.items() for token in ("--" + key, str(value))]]

    def verify(self, result, digest=None):
        root = self.out / "origin"
        return private.verify_archive(result["archivePath"], digest or result["archiveSha256"], oci_dir=self.oci,
            origin_path=root / "build-origin.json", metadata_path=root / "build-metadata.json", manifest_path=root / "manifest.json",
            inventory_path=root / "patch-inventory.json", resources_path=root / "resources.json")


class PrivateOciBundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.f = Fixture(self.tmp.name)

    def test_cli_exact_private_unqualified_tar_and_no_blob_copy(self):
        original = {p.name: (p.stat().st_ino, p.read_bytes()) for p in (self.f.oci / "blobs/sha256").iterdir()}
        result = subprocess.run(self.f.command(), capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stderr, "")
        receipt = json.loads(result.stdout)
        self.assertFalse(any(receipt[k] for k in ("qualified", "productionAuthorized", "publicExportAuthorized")))
        self.assertEqual(receipt["producer"], {"workflowSha": WORKFLOW, "runId": "123", "attempt": "1"})
        self.assertEqual(receipt["builtAt"], BUILT)
        path = Path(receipt["archivePath"])
        self.assertEqual(path.name, "retained-oci.tar")
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.f.out.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.f.receipt.stat().st_mode), 0o600)
        self.assertFalse((self.f.out / "origin/oci").exists())
        with tarfile.open(path, "r:") as archive:
            expected = set(private.FILES) | {private.OCI + p.relative_to(self.f.oci).as_posix() for p in self.f.oci.rglob("*") if p.is_file()}
            self.assertEqual(archive.getnames(), sorted(expected))
            for member in archive:
                self.assertTrue(member.isreg())
                self.assertEqual((member.mtime, member.uid, member.gid), (0, 0, 0))
                src = self.f.out / "origin" / member.name if member.name in private.FILES else self.f.oci / member.name[len(private.OCI):]
                self.assertEqual(archive.extractfile(member).read(), src.read_bytes())
        self.assertEqual(self.f.verify(receipt)["ociClosureSha256"], receipt["ociClosureSha256"])
        self.assertEqual(original, {p.name: (p.stat().st_ino, p.read_bytes()) for p in (self.f.oci / "blobs/sha256").iterdir()})

    def test_deterministic_and_never_decompresses_layers(self):
        with patch.object(private.privacy.Inspector, "scan_layer", side_effect=AssertionError("no decompression")):
            first = self.f.prepare()
        self.f.out, self.f.receipt = self.f.base / "second", self.f.base / "second.json"
        for path in self.f.oci.rglob("*"):
            if path.is_file():
                os.utime(path, (123, 123))
        second = self.f.prepare()
        self.assertEqual(first["archiveSha256"], second["archiveSha256"])
        self.assertEqual(Path(first["archivePath"]).read_bytes(), Path(second["archivePath"]).read_bytes())

    def test_full_tar_budget_includes_headers_and_footer_without_large_allocation(self):
        first = self.f.prepare()
        with tarfile.open(first["archivePath"], "r:") as archive:
            raw = sum(member.size for member in archive)
        self.assertGreater(first["archiveBytes"], raw)
        self.f.out, self.f.receipt = self.f.base / "exact", self.f.base / "exact.json"
        self.assertEqual(self.f.prepare(limit=first["archiveBytes"])["archiveBytes"], first["archiveBytes"])
        self.f.out, self.f.receipt = self.f.base / "small", self.f.base / "small.json"
        with self.assertRaisesRegex(private.Refusal, "archive_size_limit"):
            self.f.prepare(limit=first["archiveBytes"] - 1)
        self.assertFalse(self.f.receipt.exists())
        self.assertFalse((self.f.out / private.NAME).exists())
        self.assertGreater(private.archive_size({"synthetic": {"size": private.MAX_BYTES}}), private.MAX_BYTES)

    def test_existing_outputs_remain_unchanged(self):
        result = self.f.prepare()
        original = Path(result["archivePath"]).read_bytes()
        with self.assertRaises((private.Refusal, hosted_bundle.Refusal)):
            self.f.prepare()
        self.assertEqual(Path(result["archivePath"]).read_bytes(), original)

    def test_cli_wrong_identity_missing_metadata_and_extra_arguments_are_redacted(self):
        for mutation in ("source", "metadata", "unexpected"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                f, command = Fixture(tmp), None
                command = f.command()
                if mutation == "source":
                    command[command.index("--source-sha") + 1] = "a" * 40
                elif mutation == "metadata":
                    write(f.metadata, {"error": "synthetic-private-value"})
                else:
                    command.extend(["--upload-url", "synthetic-private-capability"])
                result = subprocess.run(command, capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stderr, "")
                self.assertNotIn("synthetic-private", result.stdout)
                self.assertNotIn(str(f.base), result.stdout)
                self.assertFalse(f.receipt.exists())

    def test_extra_oci_symlink_hardlink_and_wrong_digest_are_refused(self):
        for mutation in ("extra", "symlink", "hardlink", "digest"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                f = Fixture(tmp)
                blob = next((f.oci / "blobs/sha256").iterdir())
                if mutation == "extra":
                    (f.oci / "unexpected.env").write_text("synthetic")
                elif mutation == "symlink":
                    saved = f.base / "saved"
                    blob.rename(saved)
                    blob.symlink_to(saved)
                elif mutation == "hardlink":
                    os.link(blob, f.base / "alias")
                else:
                    data = blob.read_bytes()
                    blob.write_bytes(bytes([data[0] ^ 1]) + data[1:])
                with self.assertRaises((private.Refusal, hosted_bundle.Refusal, private.privacy.Refusal, OSError, ValueError)):
                    f.prepare()
                self.assertFalse(f.receipt.exists())
                self.assertFalse((f.out / private.NAME).exists())

    def test_metadata_descriptor_manifest_and_resources_cannot_disagree(self):
        for target in ("manifest", "descriptor", "resources"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as tmp:
                f = Fixture(tmp)
                if target == "manifest":
                    data = json.loads(f.manifest.read_bytes()); data["source"]["tree"] = "a" * 40
                    write(f.manifest, data)
                elif target == "descriptor":
                    data = json.loads(f.metadata.read_bytes()); data["containerimage.descriptor"]["digest"] = "sha256:" + "1" * 64
                    write(f.metadata, data)
                else:
                    data = json.loads(f.resources.read_bytes()); data["toolingSha"] = "a" * 40
                    write(f.resources, data)
                with self.assertRaises(private.Refusal):
                    f.prepare()
                self.assertFalse(f.receipt.exists())

    def test_original_failed_resource_bytes_are_preserved_not_upgraded(self):
        data = json.loads(self.f.resources.read_bytes()); data.update(status="failed", violations=["synthetic-limit"])
        original = write(self.f.resources, data)
        result = self.f.prepare()
        self.assertFalse(result["qualified"])
        self.assertEqual((self.f.out / "origin/resources.json").read_bytes(), original)
        self.assertEqual(result["resourcesSha256"], private.sha(original))

    def test_control_replacement_during_archive_write_prevents_receipt(self):
        original = private.write_tar

        def replace_control(*args):
            result = original(*args)
            path = self.f.resources
            raw = path.read_bytes()
            path.unlink()
            path.write_bytes(raw)
            return result

        with patch.object(private, "write_tar", side_effect=replace_control):
            with self.assertRaisesRegex(private.Refusal, "original_control_changed"):
                self.f.prepare()
        self.assertFalse(self.f.receipt.exists())
        self.assertFalse((self.f.out / private.NAME).exists())

    def test_verifier_rejects_changed_archive_even_if_caller_updates_hash(self):
        result = self.f.prepare()
        path = Path(result["archivePath"])
        data = bytearray(path.read_bytes()); data[156] = ord("2")
        path.write_bytes(data)
        with self.assertRaisesRegex(private.Refusal, "archive_header_changed"):
            self.f.verify(result, hashlib.sha256(data).hexdigest())

    def test_verifier_rejects_extra_control_files_and_changed_original_resources(self):
        result = self.f.prepare()
        root = self.f.out / "origin"
        (root / "unapproved.log").write_text("synthetic")
        with self.assertRaisesRegex(private.Refusal, "unexpected_control_file"):
            self.f.verify(result)
        (root / "unapproved.log").unlink()
        path = root / "resources.json"; path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaisesRegex(private.Refusal, "control_hash_changed"):
            self.f.verify(result)


if __name__ == "__main__":
    unittest.main()
