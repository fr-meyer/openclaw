"""Artifact identity and archive-boundary tests; no OpenClaw/SQLite execution."""
import copy
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("collector", Path(__file__).with_name("collect-artifacts.py"))
COLLECTOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COLLECTOR)


class ArtifactBoundaryTests(unittest.TestCase):
    def test_archive_paths_cannot_escape(self):
        for value in ("../private", "app/../../private", "/private", "app/\x00secret"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                COLLECTOR.clean_name(value)

    def test_duplicate_archive_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "filesystem.tar"
            with tarfile.open(path, "w") as archive:
                for _ in range(2):
                    member = tarfile.TarInfo("app/file")
                    member.size = 1
                    archive.addfile(member, io.BytesIO(b"a"))
            with self.assertRaisesRegex(ValueError, "duplicate"):
                COLLECTOR.inventory_filesystem(path)

    def test_payload_is_hashed_without_host_extraction(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "filesystem.tar"
            with tarfile.open(path, "w") as archive:
                member = tarfile.TarInfo("app/file")
                member.size = 3
                archive.addfile(member, io.BytesIO(b"abc"))
            entries, special, total = COLLECTOR.inventory_filesystem(path)
            self.assertEqual(entries["app/file"]["sha256"], hashlib.sha256(b"abc").hexdigest())
            self.assertEqual(total, 3)
            self.assertEqual(special, {})
            self.assertFalse((Path(directory) / "app").exists())

    def test_cyclic_and_missing_link_targets_are_rejected(self):
        for entries in (
            {"app/a": {"type": "symlink", "target": "a"}},
            {"app/a": {"type": "symlink", "target": "missing"}},
        ):
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                COLLECTOR.resolve_file(entries, "app/a")

    def test_relative_link_keeps_image_root(self):
        entries = {"app/a": {"type": "symlink", "target": "../usr/local/bin/node"},
                   "usr/local/bin/node": {"type": "file", "sha256": "frozen"}}
        self.assertEqual(COLLECTOR.resolve_file(entries, "app/a")["sha256"], "frozen")

    def sample_image(self, directory):
        source = Path(directory)
        entries = {"usr/local/bin/node": {"type": "file", "sha256": "node"}}
        for name in COLLECTOR.CONTRACT["artifactPreparation"]["requiredCompiledEntries"]["paths"]:
            entries[name] = {"type": "file", "sha256": "compiled"}
        for name in COLLECTOR.PUBLISHER_FILES:
            path = source / "scripts/docker/runtime-plugins/mergeguez-pr-lifecycle" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(name.encode())
            entries["app/runtime-plugins/mergeguez-pr-lifecycle/" + name] = {
                "type": "file", "sha256": hashlib.sha256(name.encode()).hexdigest()}
        entry = "app/dist/openclaw-state-db-12345678.mjs"
        entries[entry] = {"type": "file", "sha256": "doctor"}
        special = {entry: b"export { prepareOpenClawStateDatabaseSchema }",
                   "app/dist/build-info.json": json.dumps({
                       "commit": COLLECTOR.CONTRACT["sourceCommit"], "version": "2026.9.8",
                       "buildId": "2026.9.8-bc8b82b2cbbb-2026-10-04"}).encode()}
        inspect = [{"Id": "sha256:" + "a" * 64, "Os": "linux", "Architecture": "amd64",
                    "Config": {"Labels": {"org.opencontainers.image.revision": COLLECTOR.CONTRACT["sourceCommit"]}}}]
        return source, entries, special, inspect

    def test_valid_image_still_does_not_claim_runtime_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            source, entries, special, inspect = self.sample_image(directory)
            result = COLLECTOR.validate_image(inspect, entries, special, source)
            self.assertFalse(result["doctorExportLoadedOrExecuted"])
            self.assertEqual(len(result["publisherFiles"]), 8)
            self.assertFalse(result["compiledEntriesLoadedOrExecuted"])

    def test_missing_registered_sqlite_worker_refuses_image_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            source, entries, special, inspect = self.sample_image(directory)
            entries.pop("app/dist/infra/sqlite-store.worker.js")
            with self.assertRaisesRegex(ValueError, "required image file missing"):
                COLLECTOR.validate_image(inspect, entries, special, source)

    def test_missing_normalization_export_refuses_image_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            source, entries, special, inspect = self.sample_image(directory)
            entries.pop("app/dist/normalization-core/agent-run-terminal-outcome.js")
            with self.assertRaisesRegex(ValueError, "required image file missing"):
                COLLECTOR.validate_image(inspect, entries, special, source)

    def test_failed_or_oversized_image_and_filesystem_are_omitted(self):
        for failed, oversized in ((True, False), (False, True)):
            with self.subTest(failed=failed, oversized=oversized), tempfile.TemporaryDirectory() as directory:
                out = Path(directory) / "out"
                stage = Path(directory) / "stage"
                out.mkdir()
                payload = b"image"
                (out / "image.tar.gz").write_bytes(payload)
                (out / "filesystem.tar").write_bytes(b"redundant")
                receipt = {"source": {"commit": COLLECTOR.CONTRACT["sourceCommit"], "tree": COLLECTOR.CONTRACT["sourceTree"]},
                           "imageArchiveSha256": hashlib.sha256(payload).hexdigest(),
                           "imageArchiveBytes": len(payload), "fixturePhases": "NEVER_RUN"}
                (out / "artifact-receipt.json").write_text(json.dumps(receipt))
                if failed:
                    (out / "collector-failure.json").write_text('{"error":"refused"}')
                COLLECTOR.stage_retention(out, stage, image_limit=4 if oversized else 8)
                self.assertFalse((stage / "image.tar.gz").exists())
                self.assertFalse((stage / "filesystem.tar").exists())
                retained = json.loads((stage / "retention-receipt.json").read_text())
                image = next(row for row in retained["files"] if row["name"] == "image.tar.gz")
                self.assertEqual(image["sha256"], hashlib.sha256(payload).hexdigest())
                self.assertFalse(image["retained"])
                self.assertFalse(retained["omittedPayloadCustodyClaimed"])

    def test_unsealed_image_and_output_symlink_are_omitted(self):
        with tempfile.TemporaryDirectory() as directory:
            out, stage = Path(directory) / "out", Path(directory) / "stage"
            out.mkdir()
            (out / "image.tar.gz").write_bytes(b"unsealed")
            (out / "build.log").symlink_to(Path(directory) / "outside")
            COLLECTOR.stage_retention(out, stage)
            self.assertEqual(sorted(path.name for path in stage.iterdir()), ["retention-receipt.json"])

    def test_evidence_budget_retains_bounded_tail_without_full_log_custody(self):
        with tempfile.TemporaryDirectory() as directory:
            out, stage = Path(directory) / "out", Path(directory) / "stage"
            out.mkdir()
            (out / "build.log").write_bytes(b"abcdefghijk")
            (out / "image-inspect.json").write_bytes(b"12345678")
            COLLECTOR.stage_retention(out, stage, evidence_limit=5, file_limit=4)
            self.assertEqual((stage / "build.log.tail").read_bytes(), b"hijk")
            self.assertFalse((stage / "build.log").exists())
            self.assertFalse((stage / "image-inspect.json").exists())
            self.assertEqual(json.loads((stage / "retention-receipt.json").read_text())["retainedEvidenceBytes"], 4)

    def test_sealed_in_budget_image_is_retained_with_exact_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            out, stage = Path(directory) / "out", Path(directory) / "stage"
            out.mkdir()
            payload = b"image"
            (out / "image.tar.gz").write_bytes(payload)
            receipt = {"source": {"commit": COLLECTOR.CONTRACT["sourceCommit"], "tree": COLLECTOR.CONTRACT["sourceTree"]},
                       "imageArchiveSha256": hashlib.sha256(payload).hexdigest(),
                       "imageArchiveBytes": len(payload), "fixturePhases": "NEVER_RUN"}
            (out / "artifact-receipt.json").write_text(json.dumps(receipt))
            COLLECTOR.stage_retention(out, stage, image_limit=len(payload))
            self.assertEqual((stage / "image.tar.gz").read_bytes(), payload)

    def test_missing_output_still_records_no_fixture_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory) / "stage"
            COLLECTOR.stage_retention(Path(directory) / "absent", stage)
            record = json.loads((stage / "retention-receipt.json").read_text())
            self.assertFalse(record["outputDirectoryPresent"])
            self.assertFalse(record["fixtureExecuted"])

    def test_failed_copy_cannot_leave_a_partial_upload_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            out, stage = Path(directory) / "out", Path(directory) / "stage"
            out.mkdir()
            (out / "build.log").write_bytes(b"admitted evidence")

            def interrupted_copy(source, destination):
                destination.write_bytes(b"partial")
                raise OSError("synthetic interrupted copy")

            with mock.patch.object(COLLECTOR.shutil, "copyfile", side_effect=interrupted_copy):
                with self.assertRaisesRegex(OSError, "interrupted copy"):
                    COLLECTOR.stage_retention(out, stage)
            self.assertFalse((stage / "build.log").exists())

    def test_old_build_cannot_borrow_final_source_label(self):
        with tempfile.TemporaryDirectory() as directory:
            source, entries, special, inspect = self.sample_image(directory)
            build = json.loads(special["app/dist/build-info.json"])
            build["commit"] = "1e197fa258704d70e17a9efd831b2e3ecbc6e6f4"
            special["app/dist/build-info.json"] = json.dumps(build).encode()
            with self.assertRaisesRegex(ValueError, "build-info"):
                COLLECTOR.validate_image(inspect, entries, special, source)

    def test_publisher_byte_change_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            source, entries, special, inspect = self.sample_image(directory)
            entries["app/runtime-plugins/mergeguez-pr-lifecycle/src/runtime.mjs"]["sha256"] = "changed"
            with self.assertRaisesRegex(ValueError, "publisher bytes"):
                COLLECTOR.validate_image(inspect, entries, special, source)

    def test_wrong_platform_or_source_label_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            source, entries, special, inspect = self.sample_image(directory)
            for field in ("architecture", "source"):
                invalid = copy.deepcopy(inspect)
                if field == "architecture":
                    invalid[0]["Architecture"] = "arm64"
                else:
                    invalid[0]["Config"]["Labels"]["org.opencontainers.image.revision"] = "0" * 40
                with self.subTest(field=field), self.assertRaises(ValueError):
                    COLLECTOR.validate_image(invalid, entries, special, source)

    def saved_image(self, directory, *, compressed=False, tamper=False):
        payload = b"synthetic layer bytes"
        diff_id = "sha256:" + hashlib.sha256(payload).hexdigest()
        config = json.dumps({"rootfs": {"diff_ids": [diff_id]}}).encode()
        image_id = "sha256:" + hashlib.sha256(config).hexdigest()
        layer = gzip.compress(payload) if compressed else payload
        if tamper:
            layer = b"different layer"
        path = Path(directory) / "image.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            for name, value in (("manifest.json", json.dumps([{"Config": "config.json", "Layers": ["layer.tar"]}]).encode()),
                                ("config.json", config), ("layer.tar", layer)):
                member = tarfile.TarInfo(name)
                member.size = len(value)
                archive.addfile(member, io.BytesIO(value))
        return path, image_id

    def test_saved_layer_and_config_closure_verified(self):
        for compressed in (False, True):
            with self.subTest(compressed=compressed), tempfile.TemporaryDirectory() as directory:
                path, image_id = self.saved_image(directory, compressed=compressed)
                self.assertEqual(len(COLLECTOR.validate_saved_image(path, image_id)), 1)

    def test_saved_image_cannot_borrow_another_config_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path, _ = self.saved_image(directory)
            with self.assertRaisesRegex(ValueError, "config identity"):
                COLLECTOR.validate_saved_image(path, "sha256:" + "b" * 64)

    def test_changed_saved_layer_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path, image_id = self.saved_image(directory, tamper=True)
            with self.assertRaisesRegex(ValueError, "layer identity"):
                COLLECTOR.validate_saved_image(path, image_id)


if __name__ == "__main__":
    unittest.main()
