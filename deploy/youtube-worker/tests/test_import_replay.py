"""Exercise the existing archive import transaction with local synthetic bundles."""
import contextlib
import ctypes
import hashlib
import importlib.util
import io
import json
import os
import stat
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "runtime/scripts/youtube_ycombinator/import_chunk_bundle.py"
spec = importlib.util.spec_from_file_location("fixture_bundle_import", SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
IDS = ["fixture0001", "fixture0002"]


class ImportReplayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.project, self.archive = root / "project", root / "archive"
        self.archive.mkdir(); (self.project / "chunks").mkdir(parents=True)
        (self.project / "imports").mkdir()
        (self.project / "chunks/0001.json").write_text(json.dumps({"lease_id": "fixture-lease", "items": [{"video_id": video, "url": f"https://www.youtube.com/watch?v={video}", "state": "pending"} for video in IDS]}))
        tree = root / "bundle-source"; tree.mkdir(); (tree / "archive").mkdir()
        for video in IDS:
            folder = tree / "archive" / video; folder.mkdir()
            (folder / "report.md").write_text("fixture captions")
            (folder / "manifest.json").write_text(json.dumps({"video_id": video, "files": ["report.md", "manifest.json"]}))
        (tree / "status.json").write_text(json.dumps({"state": "complete", "lease_id": "fixture-lease", "cookies_used": False, "media_downloaded": False, "items": {video: {"state": "archived", "attempts": 1} for video in IDS}}))
        (tree / "urls.tsv").write_text("".join(f"{video}\thttps://www.youtube.com/watch?v={video}\n" for video in IDS))
        (tree / "events.jsonl").write_text("")
        self.bundle = root / "fixture.tar.gz"
        with tarfile.open(self.bundle, "w:gz") as tf:
            for path in sorted(tree.iterdir()): tf.add(path, arcname=path.name)
        self.digest = hashlib.sha256(self.bundle.read_bytes()).hexdigest()

    def invoke(self):
        argv = [str(SOURCE), "--bundle", str(self.bundle), "--expected-sha256", self.digest, "--project-root", str(self.project), "--archive-root", str(self.archive), "--chunk-id", "0001"]
        with patch.object(sys, "argv", argv), contextlib.redirect_stdout(io.StringIO()): return module.main()

    def test_interrupted_move_rolls_back_then_reuses_prior_archive(self):
        rename = module.os.rename
        calls = []
        def fail_second(source, destination):
            calls.append((source, destination))
            if len(calls) == 2: raise OSError("synthetic interrupted import")
            return rename(source, destination)
        with patch.object(module.os, "rename", fail_second):
            with self.assertRaises(OSError): self.invoke()
        self.assertTrue(all(not (self.archive / video).exists() for video in IDS))
        self.assertEqual(self.invoke(), 0)
        snapshot = {str(path): path.read_bytes() for path in self.archive.rglob("*") if path.is_file() and ".import-staging" not in path.parts}
        self.assertEqual(self.invoke(), 0)
        self.assertEqual(snapshot, {str(path): path.read_bytes() for path in self.archive.rglob("*") if path.is_file() and ".import-staging" not in path.parts})
        receipt = json.loads((self.project / "imports/chunk-0001.json").read_text())
        self.assertTrue(receipt["validated"])
        self.assertEqual(set(receipt["video_ids"]), set(IDS))

    def test_wrong_bundle_digest_does_not_touch_archive(self):
        self.digest = "0" * 64
        with self.assertRaises(SystemExit): self.invoke()
        self.assertEqual(list(self.archive.iterdir()), [])

    def test_extracted_file_sync_failure_refuses_archive_and_receipt_publication(self):
        real_sync = module.os.fsync
        def fail_file(fd):
            if stat.S_ISREG(os.fstat(fd).st_mode): raise OSError("fixture extracted file sync failure")
            return real_sync(fd)
        with patch.object(module.os, "fsync", side_effect=fail_file):
            with self.assertRaisesRegex(OSError, "extracted file sync failure"): self.invoke()
        self.assert_no_import()
        self.assertEqual(self.invoke(), 0)

    def test_extracted_directory_sync_failure_refuses_archive_and_receipt_publication(self):
        real_sync = module.fsync_directory
        def fail_archive_directory(path):
            if path.name in IDS: raise OSError("fixture extracted directory sync failure")
            return real_sync(path)
        with patch.object(module, "fsync_directory", side_effect=fail_archive_directory):
            with self.assertRaisesRegex(OSError, "extracted directory sync failure"): self.invoke()
        self.assert_no_import()
        self.assertEqual(self.invoke(), 0)

    def test_nested_archive_bytes_and_directories_are_durable_before_publication(self):
        tree = self.bundle.parent / "bundle-source"
        for video in IDS:
            folder = tree / "archive" / video
            nested = folder / "captions/en/transcript.md"
            nested.parent.mkdir(parents=True); nested.write_text("fixture nested captions")
            manifest = json.loads((folder / "manifest.json").read_text())
            manifest["files"].append("captions/en/transcript.md")
            (folder / "manifest.json").write_text(json.dumps(manifest))
        with tarfile.open(self.bundle, "w:gz") as tf:
            for entry in sorted(tree.iterdir()): tf.add(entry, arcname=entry.name)
        self.digest = hashlib.sha256(self.bundle.read_bytes()).hexdigest()
        self.archive = Path(self.temp.name) / "new-parent/archive"
        files_synced = set(); directories_synced = set(); moved = []
        real_sync, real_directory, real_rename = module.os.fsync, module.fsync_directory, module.os.rename
        def sync_file(fd):
            value = os.fstat(fd)
            if stat.S_ISREG(value.st_mode): files_synced.add((value.st_dev, value.st_ino))
            return real_sync(fd)
        def sync_directory(path):
            directories_synced.add(path)
            return real_directory(path)
        def publish(source, destination):
            self.assertIn(self.archive.parent, directories_synced)
            self.assertIn(self.archive.parent.parent, directories_synced)
            for relative in ("report.md", "manifest.json", "captions/en/transcript.md"):
                value = (source / relative).stat()
                self.assertIn((value.st_dev, value.st_ino), files_synced)
            for relative in (".", "captions", "captions/en"):
                self.assertIn(source / relative, directories_synced)
            moved.append(destination)
            return real_rename(source, destination)
        with patch.object(module.os, "fsync", side_effect=sync_file), patch.object(module, "fsync_directory", side_effect=sync_directory), patch.object(module.os, "rename", side_effect=publish):
            self.assertEqual(self.invoke(), 0)
        self.assertEqual(moved, [self.archive / video for video in IDS])

    def assert_no_import(self):
        self.assertFalse((self.project / "imports/chunk-0001.json").exists())
        self.assertTrue(all(not (self.archive / video).exists() for video in IDS))
        self.assertEqual(list((self.archive / ".import-staging").iterdir()), [])

    def test_gzip_expansion_is_bounded_before_tar_parsing(self):
        with patch.object(module, "MAX_TAR_BYTES", 1024):
            with self.assertRaisesRegex(ValueError, "decompressed tar"): self.invoke()
        self.assert_no_import()

    def test_declared_member_and_total_sizes_are_bounded(self):
        for name, limit, message in [("MAX_MEMBER_BYTES", 4, "member size"), ("MAX_EXTRACTED_BYTES", 4, "extracted size")]:
            with patch.object(module, name, limit):
                with self.assertRaisesRegex(ValueError, message): self.invoke()
            self.assert_no_import()

    def test_member_count_is_bounded(self):
        with patch.object(module, "MAX_TAR_MEMBERS", 2):
            with self.assertRaisesRegex(ValueError, "member count"): self.invoke()
        self.assert_no_import()

    def test_compressed_input_budget_precedes_archive_mutation(self):
        with patch.object(module, "MAX_BUNDLE_BYTES", self.bundle.stat().st_size - 1):
            with self.assertRaisesRegex(ValueError, "compressed bundle"): self.invoke()
        self.assertEqual(list(self.archive.iterdir()), [])

    def test_same_lease_mismatched_order_or_video_never_moves_archives(self):
        chunk_path = self.project / "chunks/0001.json"
        original = json.loads(chunk_path.read_text())
        for ids in (list(reversed(IDS)), [IDS[0], "fixture0003"]):
            chunk = dict(original)
            chunk["items"] = [{"video_id": video, "url": f"https://www.youtube.com/watch?v={video}"} for video in ids]
            chunk_path.write_text(json.dumps(chunk))
            with self.assertRaisesRegex(ValueError, "ordered video/URL bindings"): self.invoke()
            self.assert_no_import()

    def test_noncanonical_authoritative_url_is_refused_before_import(self):
        chunk_path = self.project / "chunks/0001.json"
        chunk = json.loads(chunk_path.read_text()); chunk["items"][0]["url"] = "https://example.invalid/" + IDS[0]
        chunk_path.write_text(json.dumps(chunk))
        with self.assertRaisesRegex(ValueError, "ordered video/URL bindings"): self.invoke()
        self.assert_no_import()

    def test_absent_or_invalid_authoritative_lease_is_refused_before_import(self):
        path = self.project / "chunks/0001.json"
        original = json.loads(path.read_text())
        for lease in (None, "", " ", 123):
            with self.subTest(lease=lease):
                path.write_text(json.dumps({**original, "lease_id": lease}))
                with self.assertRaisesRegex(ValueError, "chunk lease mismatch"): self.invoke()
                self.assert_no_import()

    def test_absent_or_invalid_remote_lease_is_refused_before_import(self):
        tree = self.bundle.parent / "bundle-source"
        path = tree / "status.json"
        original = json.loads(path.read_text())
        for lease in (None, "", 123):
            with self.subTest(lease=lease):
                path.write_text(json.dumps({**original, "lease_id": lease}))
                with tarfile.open(self.bundle, "w:gz") as tf:
                    for entry in sorted(tree.iterdir()): tf.add(entry, arcname=entry.name)
                self.digest = hashlib.sha256(self.bundle.read_bytes()).hexdigest()
                with self.assertRaisesRegex(ValueError, "chunk lease mismatch"): self.invoke()
                self.assert_no_import()

    def test_committed_delivery_does_not_resurrect_completed_chunk_or_queue(self):
        self.assertEqual(self.invoke(), 0)
        chunk_path = self.project / "chunks/0001.json"
        chunk = json.loads(chunk_path.read_text()); chunk["state"] = "completed"
        chunk_path.write_text(json.dumps(chunk))
        queue_path = self.project / "queue/state.json"
        queue = json.loads(queue_path.read_text()); queue.update(state="completed", current_chunk=None, catalog_rebuild_required=False)
        queue_path.write_text(json.dumps(queue))
        paths = [chunk_path, queue_path, self.project / "imports/chunk-0001.json", self.project / "imports/chunk-0001.transaction.json"]
        before = {path:path.read_bytes() for path in paths}
        self.assertEqual(self.invoke(), 0)
        self.assertEqual(before, {path:path.read_bytes() for path in paths})

    def test_committed_replay_missing_evidence_does_not_downgrade_transaction(self):
        self.assertEqual(self.invoke(), 0)
        receipt = self.project / "imports/chunk-0001.json"
        receipt.unlink()
        transaction = self.project / "imports/chunk-0001.transaction.json"
        before = transaction.read_bytes()
        with self.assertRaisesRegex(ValueError, "committed import artifacts"): self.invoke()
        self.assertEqual(transaction.read_bytes(), before)

    def test_malformed_attempt_counters_are_refused_before_any_import(self):
        tree = self.bundle.parent / "bundle-source"; path = tree / "status.json"
        original = path.read_text()
        for attempts in (None, True, "1", 1.5, -1, 4, "absent"):
            with self.subTest(attempts=attempts):
                status = json.loads(original)
                if attempts == "absent": status["items"][IDS[0]].pop("attempts")
                else: status["items"][IDS[0]]["attempts"] = attempts
                path.write_text(json.dumps(status))
                with tarfile.open(self.bundle, "w:gz") as tf:
                    for entry in sorted(tree.iterdir()): tf.add(entry, arcname=entry.name)
                self.digest = hashlib.sha256(self.bundle.read_bytes()).hexdigest()
                with self.assertRaisesRegex(ValueError, "invalid remote attempt counter"): self.invoke()
                self.assert_no_import()

    def test_zstd_expansion_budget(self):
        # Use the same system library as the importer; this fixture is tiny.
        lib = ctypes.CDLL("libzstd.so.1")
        lib.ZSTD_compressBound.argtypes = [ctypes.c_size_t]
        lib.ZSTD_compressBound.restype = ctypes.c_size_t
        lib.ZSTD_compress.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
        lib.ZSTD_compress.restype = ctypes.c_size_t
        raw = b"fixture" * 1024
        source = ctypes.create_string_buffer(raw)
        output = ctypes.create_string_buffer(lib.ZSTD_compressBound(len(raw)))
        size = lib.ZSTD_compress(output, len(output), source, len(raw), 1)
        fixture = self.bundle.with_suffix(".zst"); fixture.write_bytes(output.raw[:size])
        target = fixture.with_suffix(".tar")
        with patch.object(module, "MAX_TAR_BYTES", 1024):
            with self.assertRaisesRegex(ValueError, "decompressed tar"): module.decompress_zstd(fixture, target)
        self.assertLessEqual(target.stat().st_size, 1024)


if __name__ == "__main__": unittest.main()
