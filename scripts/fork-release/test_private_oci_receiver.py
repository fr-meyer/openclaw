"""Synthetic receiver boundary proof; no network, image execution or real attestation."""
import hashlib
import io
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

import private_oci_bundle as owner
from test_private_oci_bundle import Fixture, WORKFLOW

OWNER = Path(__file__).resolve().parent


def rewrite_archive(path, mutate):
    """Construct independently hash-pinned hostile USTAR bytes, not an extract helper."""
    with tarfile.open(path, "r:") as archive:
        members = [(member.name, archive.extractfile(member).read()) for member in archive]
    members = mutate(members)
    output = path.parent / "modified.tar"
    with output.open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, payload in members:
                member = tarfile.TarInfo(name)
                member.mode, member.uid, member.gid, member.mtime = 0o600, 0, 0, 0
                if isinstance(payload, bytes):
                    member.size = len(payload)
                    archive.addfile(member, io.BytesIO(payload))
                else:
                    member.type = payload
                    member.linkname = "fixture-outside" if payload in (tarfile.SYMTYPE, tarfile.LNKTYPE) else ""
                    archive.addfile(member)
    return output


def change_inventory(members, mutate):
    result = []
    for name, payload in members:
        if name == "export-inventory.json":
            value = json.loads(payload)
            mutate(value)
            payload = owner.encoded(value)
        result.append((name, payload))
    return result


class PrivateOciReceiverTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.root.chmod(0o700)
        self.f = Fixture(self.root)
        (self.f.oci / "ingest").mkdir()
        nested = self.f.oci / "fixture-directory"
        nested.mkdir()
        (nested / "empty").mkdir()
        (nested / "payload").write_bytes(b"synthetic opaque export payload")
        self.retained = self.f.prepare()
        self.archive = Path(self.retained["archivePath"])
        self.destination = self.root / "received"
        self.receipt = self.root / "received.json"

    def invoke(self, archive=None, *, expected_hash=None, expected_size=None, nofile=None):
        archive = archive or self.archive
        command = [sys.executable, "-B", str(OWNER / "private_oci_bundle.py"), "extract",
            "--archive", str(archive), "--archive-sha256", expected_hash or hashlib.sha256(archive.read_bytes()).hexdigest(),
            "--archive-bytes", str(archive.stat().st_size if expected_size is None else expected_size),
            "--output-dir", str(self.destination), "--output", str(self.receipt)]
        if nofile is not None:
            # Set only the child's limit, then exec the actual CLI so imports
            # and argument handling use its ordinary script context.
            launch = ("import os,resource,sys;resource.setrlimit(resource.RLIMIT_NOFILE,(" +
                str(nofile) + "," + str(nofile) + "));os.execv(sys.executable,[sys.executable,'-B',*sys.argv[1:]])")
            command = [sys.executable, "-B", "-c", launch, *command[2:]]
        return subprocess.run(command,
            cwd=OWNER.parents[1], capture_output=True, text=True, timeout=15)

    def assert_refused(self, process):
        self.assertNotEqual(process.returncode, 0, process.stdout + process.stderr)
        summary = json.loads(process.stdout.splitlines()[-1])
        self.assertNotEqual(summary["status"], "extracted_unqualified")
        self.assertFalse(summary.get("qualified", False))
        self.assertFalse(summary.get("productionAuthorized", False))
        self.assertNotIn("synthetic opaque export payload", process.stdout + process.stderr)
        self.assertNotIn("fixture-outside", process.stdout + process.stderr)
        if self.receipt.exists():
            self.assertNotEqual(json.loads(self.receipt.read_bytes())["status"], "extracted_unqualified")

    def test_actual_receiver_reconstructs_full_typed_inventory_and_custody(self):
        process = self.invoke()
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        result = json.loads(process.stdout.splitlines()[-1])
        self.assertEqual(result["status"], "extracted_unqualified")
        self.assertFalse(result["qualified"])
        self.assertFalse(result["originAuthenticated"])
        self.assertFalse(result["nativeExecuted"])
        self.assertFalse(result["productionAuthorized"])
        restored = self.destination / "oci/default"
        original_entries = {path.relative_to(self.f.oci).as_posix():
            ("directory", None) if path.is_dir() else ("file", path.read_bytes()) for path in self.f.oci.rglob("*")}
        restored_entries = {path.relative_to(restored).as_posix():
            ("directory", None) if path.is_dir() else ("file", path.read_bytes()) for path in restored.rglob("*")}
        self.assertEqual(restored_entries, original_entries)
        self.assertEqual(stat.S_IMODE(self.destination.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.receipt.stat().st_mode), 0o600)
        for path in self.destination.rglob("*"):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700 if path.is_dir() else 0o600)
            self.assertFalse(path.is_symlink())
        verified = owner.verify_archive(self.archive, self.retained["archiveSha256"], oci_dir=restored,
            origin_path=self.destination / "origin/build-origin.json", metadata_path=self.destination / "origin/build-metadata.json",
            manifest_path=self.destination / "origin/manifest.json", inventory_path=self.destination / "origin/patch-inventory.json",
            resources_path=self.destination / "origin/resources.json")
        self.assertEqual(verified["ociClosureSha256"], self.retained["ociClosureSha256"])
        scan = owner.privacy.inspect_layout(restored, self.f.index, owner.SOURCE, WORKFLOW)
        self.assertFalse(scan["inspectionComplete"])
        self.assertEqual(scan["refusal"], "unexpected_export_entry")

    def test_outer_hash_size_and_existing_destination_refuse_without_overwrite(self):
        for mutation in ("hash", "size", "existing"):
            with self.subTest(mutation=mutation):
                self.destination, self.receipt = self.root / ("received-" + mutation), self.root / ("received-" + mutation + ".json")
                if mutation == "existing":
                    self.destination.mkdir(mode=0o700)
                    marker = self.destination / "preserve"
                    marker.write_bytes(b"existing owned fixture")
                    process = self.invoke()
                    self.assertEqual(marker.read_bytes(), b"existing owned fixture")
                elif mutation == "hash":
                    process = self.invoke(expected_hash="f" * 64)
                else:
                    process = self.invoke(expected_size=owner.MAX_BYTES + 1)
                self.assert_refused(process)
                self.assertEqual(hashlib.sha256(self.archive.read_bytes()).hexdigest(), self.retained["archiveSha256"])

    def test_signed_inventory_traversal_type_hash_and_bounds_refuse(self):
        def mutate(value, mode):
            files = [entry for entry in value["entries"] if entry["kind"] == "file"]
            if mode == "traversal":
                files[0]["path"] = "../fixture-outside"
            elif mode == "absolute":
                files[0]["path"] = "/fixture-outside"
            elif mode == "type":
                files[0].clear(); files[0].update(path="index.json", kind="symlink")
            elif mode == "hash":
                files[0]["sha256"] = "f" * 64
            elif mode == "size":
                files[0]["size"] = owner.MAX_BYTES + 1
            elif mode == "count":
                value["entries"] = [{"path": f"fixture-{index:04d}", "kind": "directory"} for index in range(2049)]
            else:
                files[0]["path"] = "/".join(["fixture"] * 17)
        for mode in ("traversal", "absolute", "type", "hash", "size", "count", "depth"):
            with self.subTest(mode=mode):
                changed = rewrite_archive(self.archive, lambda members: change_inventory(members, lambda value: mutate(value, mode)))
                self.destination, self.receipt = self.root / ("received-" + mode), self.root / ("received-" + mode + ".json")
                self.assert_refused(self.invoke(changed))
                self.assertFalse((self.root / "fixture-outside").exists())
                changed.unlink()  # Only the synthetic hostile archive created by this helper.

    def test_nonregular_ustar_members_and_duplicate_inventory_refuse(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE):
            with self.subTest(kind=kind):
                changed = rewrite_archive(self.archive, lambda members: [
                    (name, kind if name == "oci/default/fixture-directory/payload" else payload) for name, payload in members])
                self.destination, self.receipt = self.root / ("received-type-" + kind.decode()), self.root / ("received-type-" + kind.decode() + ".json")
                self.assert_refused(self.invoke(changed))
                changed.unlink()
        changed = rewrite_archive(self.archive, lambda members: change_inventory(members,
            lambda value: value["entries"].append(value["entries"][0])))
        self.destination, self.receipt = self.root / "received-duplicate", self.root / "received-duplicate.json"
        self.assert_refused(self.invoke(changed))

    def test_truncated_payload_and_hardlinked_archive_never_report_success(self):
        truncated = self.archive.parent / "truncated.tar"
        truncated.write_bytes(self.archive.read_bytes()[:-1]); truncated.chmod(0o600)
        self.assert_refused(self.invoke(truncated))
        self.destination, self.receipt = self.root / "received-link", self.root / "received-link.json"
        alias = self.root / "archive-alias"
        os.link(self.archive, alias)
        self.assert_refused(self.invoke())
        self.assertTrue(alias.exists())
        self.assertEqual(alias.read_bytes(), self.archive.read_bytes())

    def test_receiver_rejects_same_byte_archive_replacement_after_open(self):
        # Replace only this fixture's path after the owner's descriptor is open.
        # Hash-only verification cannot distinguish the new inode; custody must.
        original_write = owner._write_all
        saved = self.archive.parent / "original-open-archive.tar"
        changed = False

        def replace_after_open(descriptor, raw):
            nonlocal changed
            original_write(descriptor, raw)
            if not changed:
                changed = True
                self.archive.rename(saved)
                self.archive.write_bytes(saved.read_bytes())
                self.archive.chmod(0o600)

        with patch.object(owner, "_write_all", side_effect=replace_after_open):
            receipt = owner.extract_archive(self.archive, self.retained["archiveSha256"],
                self.retained["archiveBytes"], self.destination, self.receipt)
        self.assertTrue(changed)
        self.assertEqual(receipt["status"], "refused")
        # Filesystems may update the open inode's ctime on rename, which the
        # earlier fingerprint guard detects before the final path comparison.
        self.assertIn(receipt["reason"], {"archive_changed", "path_identity_changed"})
        self.assertFalse(receipt["qualified"])
        self.assertEqual(saved.read_bytes(), self.archive.read_bytes())
        self.assertNotEqual(saved.stat().st_ino, self.archive.stat().st_ino)
        self.assertNotEqual(json.loads(self.receipt.read_bytes())["status"], "extracted_unqualified")

    def test_many_empty_directories_restore_with_child_descriptor_limit(self):
        try:
            import resource
            _, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        except (ImportError, AttributeError, OSError, ValueError):
            self.skipTest("resource.RLIMIT_NOFILE is unavailable")
        if hard != resource.RLIM_INFINITY and hard < 64:
            self.skipTest("host hard descriptor limit is below the fixture's 64")
        expected = {f"empty-{index:03d}" for index in range(128)}
        for name in expected:
            (self.f.oci / name).mkdir()
        self.f.out = self.root / "many-directory-archive"
        self.f.receipt = self.root / "many-directory-retention.json"
        self.retained = self.f.prepare()
        self.archive = Path(self.retained["archivePath"])
        process = self.invoke(nofile=64)
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        receipt = json.loads(process.stdout.splitlines()[-1])
        self.assertEqual(receipt["status"], "extracted_unqualified")
        self.assertFalse(receipt["qualified"])
        restored = self.destination / "oci/default"
        self.assertEqual({path.name for path in restored.glob("empty-*")}, expected)
        self.assertTrue(all(path.is_dir() and not any(path.iterdir()) for path in restored.glob("empty-*")))
        verified = owner.verify_archive(self.archive, self.retained["archiveSha256"], oci_dir=restored,
            origin_path=self.destination / "origin/build-origin.json", metadata_path=self.destination / "origin/build-metadata.json",
            manifest_path=self.destination / "origin/manifest.json", inventory_path=self.destination / "origin/patch-inventory.json",
            resources_path=self.destination / "origin/resources.json")
        self.assertEqual(verified["ociClosureSha256"], self.retained["ociClosureSha256"])
        self.assertEqual(receipt["ociClosureSha256"], self.retained["ociClosureSha256"])


if __name__ == "__main__":
    unittest.main()
