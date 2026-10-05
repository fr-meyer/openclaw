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
import sys
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
        special = {entry: b"export { prepareOpenClawStateDatabaseSchema }",
                   "app/dist/build-info.json": json.dumps({
                       "commit": COLLECTOR.CONTRACT["sourceCommit"], "version": "2026.9.8",
                       "buildId": "2026.9.8-" + COLLECTOR.CONTRACT["sourceCommit"][:12] + "-synthetic-layout-test"}).encode()}
        entries[entry] = {"path": "/" + entry, "type": "file", "bytes": len(special[entry]),
                          "sha256": hashlib.sha256(special[entry]).hexdigest()}
        for name, row in entries.items():
            row.setdefault("path", "/" + name)
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

    def test_observed_implementation_and_facade_select_exact_named_export(self):
        observed = json.loads(Path(__file__).with_name("observed-layout.json").read_text())
        with tempfile.TemporaryDirectory() as directory:
            source, entries, special, inspect = self.sample_image(directory)
            entries.pop("app/dist/openclaw-state-db-12345678.mjs")
            special.pop("app/dist/openclaw-state-db-12345678.mjs")
            for chunk in observed["chunks"]:
                name = "app/dist/" + chunk["name"]
                value = (chunk["exportTable"] + "\n").encode()
                entries[name] = {"path": "/" + name, "type": "file",
                                 "bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()}
                special[name] = value
            result = COLLECTOR.validate_image(inspect, entries, special, source)
            self.assertEqual(result["doctorEntryCandidate"]["path"],
                             "/app/dist/openclaw-state-db-CgJKJRub.mjs")

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
                self.sealed_retention_outputs(out, payload)
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
            self.sealed_retention_outputs(out, payload)
            COLLECTOR.stage_retention(out, stage, image_limit=len(payload))
            self.assertEqual((stage / "image.tar.gz").read_bytes(), payload)

    def sealed_retention_outputs(self, out, payload):
        for name in ("preflight.json", "image-id.txt", "image-inspect.json", COLLECTOR.LAYOUT_NAME):
            (out / name).write_bytes(b"{}")
        (out / COLLECTOR.MANIFEST_NAME).write_bytes(gzip.compress(b"{}", mtime=0))
        receipt = {"source": {"commit": COLLECTOR.CONTRACT["sourceCommit"], "tree": COLLECTOR.CONTRACT["sourceTree"]},
                   "imageArchiveSha256": hashlib.sha256(payload).hexdigest(),
                   "imageArchiveBytes": len(payload), "fixturePhases": "NEVER_RUN",
                   "filesystemManifestPath": COLLECTOR.MANIFEST_NAME,
                   "filesystemManifestEncoding": "gzip-json",
                   "filesystemManifestSha256": COLLECTOR.digest_file(out / COLLECTOR.MANIFEST_NAME),
                   "layoutAssessmentSha256": COLLECTOR.digest_file(out / COLLECTOR.LAYOUT_NAME)}
        (out / "artifact-receipt.json").write_text(json.dumps(receipt))
        return receipt

    def replace_doctor(self, entries, special, values):
        for name in list(special):
            if name != "app/dist/build-info.json":
                entries.pop(name)
                special.pop(name)
        for suffix, value in values.items():
            name = "app/dist/openclaw-state-db-" + suffix + ".mjs"
            entries[name] = {"path": "/" + name, "type": "file", "bytes": len(value),
                             "sha256": hashlib.sha256(value).hexdigest()}
            special[name] = value

    def test_zero_multiple_and_unsupported_exports_refuse_with_diagnostics(self):
        cases = (
            ({"implementation": b"export { prepareOpenClawStateDatabaseSchema as i };"}, 0, 0),
            ({"facade": b"export { prepareOpenClawStateDatabaseSchema };",
              "second": b"export { i as prepareOpenClawStateDatabaseSchema };"}, 2, 0),
            ({"unsupported": b"export * from './other.mjs';"}, 0, 1),
            ({"unsupported": b"export { prepareOpenClawStateDatabaseSchema, prepareOpenClawStateDatabaseSchema };"}, 0, 1),
            ({"unsupported": b"export { a,,b, };"}, 0, 1),
            ({"unsupported": b"export { a as 'prepareOpenClawStateDatabaseSchema' };"}, 0, 1),
        )
        for values, count, errors in cases:
            with self.subTest(values=values), tempfile.TemporaryDirectory() as directory:
                source, entries, special, inspect = self.sample_image(directory)
                self.replace_doctor(entries, special, values)
                layout = COLLECTOR.assess_layout(entries, special)
                self.assertEqual(layout["doctor"]["candidateCount"], count)
                self.assertEqual(layout["doctor"]["parseErrorCount"], errors)
                self.assertEqual(len(layout["doctor"]["familyEntries"]), len(values))
                with self.assertRaisesRegex(ValueError, "exact named Doctor export"):
                    COLLECTOR.validate_image(inspect, entries, special, source)

    def test_export_alias_selects_public_name_and_ignores_nonexported_literal(self):
        with tempfile.TemporaryDirectory() as directory:
            source, entries, special, inspect = self.sample_image(directory)
            self.replace_doctor(entries, special, {
                "longerHashSuffix": b"export { i as prepareOpenClawStateDatabaseSchema };",
                "impl": b"const text = 'prepareOpenClawStateDatabaseSchema';\nexport { prepareOpenClawStateDatabaseSchema as i };",
            })
            result = COLLECTOR.validate_image(inspect, entries, special, source)
            self.assertEqual(result["doctorEntryCandidate"]["path"],
                             "/app/dist/openclaw-state-db-longerHashSuffix.mjs")

    def test_changed_or_uncaptured_doctor_family_bytes_refuse_admission(self):
        for change in ("hash", "capture", "type"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                source, entries, special, inspect = self.sample_image(directory)
                name = "app/dist/openclaw-state-db-12345678.mjs"
                if change == "hash":
                    entries[name]["sha256"] = "changed"
                elif change == "capture":
                    special.pop(name)
                else:
                    entries[name]["type"] = "symlink"
                with self.assertRaisesRegex(ValueError, "parseErrors=1"):
                    COLLECTOR.validate_image(inspect, entries, special, source)

    def test_each_required_selector_and_all_failures_are_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            source, entries, special, inspect = self.sample_image(directory)
            paths = COLLECTOR.CONTRACT["artifactPreparation"]["requiredCompiledEntries"]["paths"]
            for name in paths:
                with self.subTest(name=name):
                    invalid = {key: row for key, row in entries.items() if key != name}
                    layout = COLLECTOR.assess_layout(invalid, special)["requiredCompiledEntries"]
                    self.assertEqual(layout["presentCount"], 78)
                    failed = [row["requestedPath"] for row in layout["entries"] if row["status"] != "PRESENT"]
                    self.assertEqual(failed, [name])
                    with self.assertRaisesRegex(ValueError, "required compiled entry checks failed: 1"):
                        COLLECTOR.validate_image(inspect, invalid, special, source)
            for name in paths:
                entries.pop(name)
            self.replace_doctor(entries, special, {"impl": b"export { prepareOpenClawStateDatabaseSchema as i };"})
            layout = COLLECTOR.assess_layout(entries, special)
            self.assertEqual(layout["doctor"]["candidateCount"], 0)
            self.assertEqual(layout["requiredCompiledEntries"]["failureCount"], 79)
            self.assertEqual(layout["requiredCompiledEntries"]["registeredCoreEntryCount"], 53)
            self.assertEqual(layout["requiredCompiledEntries"]["normalizationExportCount"], 26)

    def test_seal_failure_retains_complete_nonadmitted_layout_without_image(self):
        for values, count in (({"impl": b"export { prepareOpenClawStateDatabaseSchema as i };"}, 0),
                              ({"one": b"export { prepareOpenClawStateDatabaseSchema };",
                                "two": b"export { prepareOpenClawStateDatabaseSchema };"}, 2)):
            with self.subTest(count=count), tempfile.TemporaryDirectory() as directory:
                source, entries, special, inspect = self.sample_image(directory)
                self.replace_doctor(entries, special, values)
                out, stage = Path(directory) / "out", Path(directory) / "stage"
                out.mkdir()
                with tarfile.open(out / "filesystem.tar", "w") as archive:
                    for name in entries:
                        value = special.get(name, name.encode())
                        member = tarfile.TarInfo(name)
                        member.size = len(value)
                        archive.addfile(member, io.BytesIO(value))
                    value = special["app/dist/build-info.json"]
                    member = tarfile.TarInfo("app/dist/build-info.json")
                    member.size = len(value)
                    archive.addfile(member, io.BytesIO(value))
                (out / "image.tar.gz").write_bytes(b"unsealed")
                (out / "image-inspect.json").write_text(json.dumps(inspect))
                with mock.patch.object(COLLECTOR, "verify_source", return_value={"commit": COLLECTOR.CONTRACT["sourceCommit"]}), \
                        mock.patch.object(sys, "argv", ["collect-artifacts.py", "seal", str(source), str(out)]):
                    with self.assertRaisesRegex(ValueError, "exact named Doctor export"):
                        COLLECTOR.main()
                COLLECTOR.stage_retention(out, stage)
                self.assertFalse((stage / "image.tar.gz").exists())
                self.assertFalse((stage / "filesystem.tar").exists())
                self.assertFalse((out / "artifact-receipt.json").exists())
                layout = json.loads((stage / COLLECTOR.LAYOUT_NAME).read_text())
                self.assertEqual(layout["doctor"]["candidateCount"], count)
                self.assertEqual(layout["requiredCompiledEntries"]["presentCount"], 79)
                manifest = json.loads(gzip.decompress((stage / COLLECTOR.MANIFEST_NAME).read_bytes()))
                self.assertEqual(len(manifest["entries"]), len(entries) + 1)
                self.assertFalse(manifest["fixtureExecuted"])
                self.assertEqual(manifest["admission"], "NOT_ADMITTED; inventory only")

    def test_required_layout_evidence_missing_changed_or_over_budget_omits_sealed_image(self):
        for change in ("missing", "changed", "file-budget", "aggregate-budget"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                out, stage = Path(directory) / "out", Path(directory) / "stage"
                out.mkdir()
                payload = b"image"
                (out / "image.tar.gz").write_bytes(payload)
                self.sealed_retention_outputs(out, payload)
                kwargs = {}
                if change == "missing":
                    (out / COLLECTOR.MANIFEST_NAME).unlink()
                elif change == "changed":
                    (out / COLLECTOR.LAYOUT_NAME).write_bytes(b"changed")
                elif change == "file-budget":
                    (out / COLLECTOR.MANIFEST_NAME).write_bytes(b"x" * 4096)
                    kwargs["file_limit"] = 2048
                else:
                    kwargs["evidence_limit"] = sum(p.stat().st_size for p in out.iterdir() if p.name != "image.tar.gz") - 1
                COLLECTOR.stage_retention(out, stage, **kwargs)
                self.assertFalse((stage / "image.tar.gz").exists())

    def test_inventory_capture_is_bounded_and_ignores_nested_doctor_family(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "filesystem.tar"
            with tarfile.open(path, "w") as archive:
                for name in ("app/dist/openclaw-state-db-LongerHash.mjs", "app/dist/native-hook-relay/openclaw-state-db-12345678.mjs"):
                    value = b"export { prepareOpenClawStateDatabaseSchema };"
                    member = tarfile.TarInfo(name)
                    member.size = len(value)
                    archive.addfile(member, io.BytesIO(value))
            entries, special, _ = COLLECTOR.inventory_filesystem(path)
            self.assertEqual(list(special), ["app/dist/openclaw-state-db-LongerHash.mjs"])
            self.assertEqual(len(entries), 2)
            with mock.patch.dict(COLLECTOR.LAYOUT_LIMITS, {"maximumDoctorFamilyEntries": 0}):
                with self.assertRaisesRegex(ValueError, "family count budget"):
                    COLLECTOR.inventory_filesystem(path)
            with mock.patch.dict(COLLECTOR.LAYOUT_LIMITS, {"capturedModuleLimitBytes": 1}):
                with self.assertRaisesRegex(ValueError, "metadata budget"):
                    COLLECTOR.inventory_filesystem(path)

    def test_over_budget_inventory_never_retains_a_partial_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            source, entries, special, _ = self.sample_image(directory)
            with mock.patch.dict(COLLECTOR.LAYOUT_LIMITS, {"expandedManifestLimitBytes": 1}):
                with self.assertRaisesRegex(ValueError, "inventory metadata budget"):
                    COLLECTOR.write_layout_evidence(source, entries, special, 0)
            self.assertFalse((source / COLLECTOR.MANIFEST_NAME).exists())
            self.assertTrue((source / COLLECTOR.LAYOUT_NAME).is_file())

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
