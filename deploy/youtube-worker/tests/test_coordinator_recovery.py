"""Offline GCP fencing and journal replay; no live gateway or provider calls."""
import copy
import hashlib
import importlib.util
import json
import os
import stat
import datetime as dt
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / "runtime/scripts"
sys.path.insert(0, str(SCRIPTS))
CONFIG = {
    "schema": "openclaw.youtube.windows-config.v1", "agent_id": "fixture",
    "node": {"id": "1" * 64, "label": "FIXTURE-WINDOWS", "cwd": r"C:\Users\fixture"},
    "remote": {
        "staging_root": r"C:\Users\fixture\.openclaw\youtube-transcript-staging\global",
        "adapter": r"C:\Users\fixture\.openclaw\youtube-transcript-staging\global\validation\youtube_global_windows_adapter.ps1",
        "archiver": r"C:\Users\fixture\Documents\GitHub\shared-agent-skills\skills\youtube-transcript-archive\scripts\archive_youtube_transcript.py",
        "wrapper": r"C:\Users\fixture\.openclaw\youtube-transcript-tools\yt-dlp-anonymous.cmd",
    },
    "validation_canaries": [{"id": "windows-canary-fixture-validation", "archived_count": 1}],
    "assets": {"compatibility": "windows-caption-worker-v2", "fork_revision": "2" * 40, "archiver_revision": "3" * 40, "archiver_sha256": "4" * 64, "wrapper_sha256": "5" * 64, "worker_account": "FIXTURE\\fixture"},
}
_bootstrap = tempfile.TemporaryDirectory()
_config = Path(_bootstrap.name) / "state/config/windows-worker.json"
_config.parent.mkdir(parents=True)
_config.write_text(json.dumps(CONFIG))
with patch.dict(os.environ, {"OPENCLAW_YOUTUBE_DATA_ROOT": _bootstrap.name}):
    spec = importlib.util.spec_from_file_location("fixture_windows_coordinator", SCRIPTS / "youtube_global_windows_canary.py")
    wc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(wc)
    supervisor_spec = importlib.util.spec_from_file_location("fixture_windows_supervisor", SCRIPTS / "youtube_global_windows_supervisor.py")
    sv = importlib.util.module_from_spec(supervisor_spec)
    supervisor_spec.loader.exec_module(sv)
gp, lc = wc.GP, wc.LC
_bootstrap.cleanup()
CANARY = "windows-canary-fixture-recovery"
LEASE = "00000000-0000-4000-8000-000000000001"
IDS = [f"fixture{i:04d}" for i in range(1, 5)]
DIGEST = "c" * 64


class CoordinatorRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.pool = Path(self.temp.name) / "pool"
        self.root = self.pool / "windows-canaries" / CANARY
        self.archive = Path(self.temp.name) / "archive"
        self.archive.mkdir()
        self.root.mkdir(parents=True)
        for module in (wc, lc):
            self.patch(module, "POOL_ROOT", self.pool)
            self.patch(module, "ARCHIVE_ROOT", self.archive)
        self.patch(wc, "CANARIES_ROOT", self.pool / "windows-canaries")
        self.store = gp.PoolStore(self.pool)
        self.store.ensure_dirs()
        self.node = {"node_id": CONFIG["node"]["id"], "display_name": CONFIG["node"]["label"], "platform": "windows", "connected": True}
        urls = self.root / "chunks/0001.tsv"
        urls.parent.mkdir()
        urls.write_text("".join(f"{video}\t{gp.canonical_url(video)}\n" for video in IDS))
        self.manifest = {"canary_id": CANARY, "lease_id": LEASE, "state": "blocked", "video_ids": IDS, "expected_item_count": len(IDS), "node": self.node, "urls_sha256": wc.sha256_file(urls), "worker_sha256": wc.sha256_file(wc.REMOTE_WORKER), "adapter_sha256": wc.sha256_file(wc.REMOTE_ADAPTER), "remote_adapter_path": wc.REMOTE_ADAPTER_PATH, "remote_staging_root": wc.remote_canary_root(CANARY), "assets": CONFIG["assets"]}
        self.manifest["binding_sha256"] = wc.stable_hash(wc._binding_payload(CANARY, LEASE, IDS, self.manifest["urls_sha256"], self.node))
        lease = {"lease_id": LEASE, "chunk_id": CANARY, "state": "active", "video_ids": IDS, "node": {"id": self.node["node_id"], "label": self.node["display_name"], "platform": "windows"}, "cookies_used": False, "media_allowed": False}
        self.manifest["lease_sha256"] = wc._lease_binding_hash(lease)
        self.write(self.store.leases_dir / (LEASE + ".json"), lease)
        chunk = {"lease_id": LEASE, "chunk_id": CANARY, "node_id": self.node["node_id"], "node_label": self.node["display_name"], "node_platform": "windows", "items": [{"video_id": video, "url": gp.canonical_url(video), "state": "pending"} for video in IDS], "binding_sha256": self.manifest["binding_sha256"], "cookies_used": False, "media_allowed": False}
        chunk["chunk_sha256"] = wc._chunk_binding_hash(chunk)
        self.manifest["chunk_sha256"] = chunk["chunk_sha256"]
        self.write(self.store.chunks_dir / (CANARY + ".json"), chunk)
        self.write(self.root / "chunks/0001.json", chunk)
        self.write(self.root / "manifest.json", self.manifest)
        for video in IDS:
            self.store.save_item({"video_id": video, "status": "processing", "active_lease_id": LEASE, "active_node": self.node["node_id"], "auth_allowed": False, "media_download_allowed": False, "attempt_count": 1})
        self.remote = {"chunkId": "0001", "leaseId": LEASE, "exists": True, "workerAlive": False, "workerLockFree": True, "statusSha256": DIGEST, "cookiesUsed": False, "mediaFiles": 0, "status": {"state": "blocked_interrupted", "lease_id": LEASE, "cookies_used": False, "media_downloaded": False, "items": {video: {"attempts": 1} for video in IDS}}, "staging": {"chunk_id": "0001", "lease_id": LEASE, "worker_sha256": self.manifest["worker_sha256"], "urls_sha256": self.manifest["urls_sha256"], "cookies_used": False, "media_files": 0, "assets": CONFIG["assets"]}}
        self.node_mock = self.patch(wc, "windows_node_status", return_value={"nodeId": self.node["node_id"]})
        self.calls = []
        self.adapter = self.patch(wc, "_invoke_adapter", side_effect=self.invoke_adapter)

    def patch(self, target, name, *args, **kwargs):
        p = patch.object(target, name, *args, **kwargs)
        self.addCleanup(p.stop)
        return p.start()

    def write(self, path, value):
        wc.atomic_json(path, value)

    def invoke_adapter(self, action, **kwargs):
        self.calls.append(action)
        result = copy.deepcopy(self.remote)
        if action == "Resume":
            self.assertEqual(kwargs["checkpoint_sha256"], DIGEST)
            result["workerAlive"] = True
            result["status"]["state"] = "running"
        return wc._normalise_probe(result) if action == "Probe" else result

    def resume(self, digest=DIGEST):
        return wc.resume_canary(CANARY, expected_checkpoint_sha256=digest)

    def test_fresh_same_lease_recovers_once_and_retains_all_bindings(self):
        before = {video: self.store.load_item(video) for video in IDS}
        self.assertEqual(self.resume()["state"], "running")
        self.assertEqual(self.resume()["state"], "already_requested")
        self.assertEqual(self.calls.count("Resume"), 1)
        self.assertEqual(before, {video: self.store.load_item(video) for video in IDS})

    def test_stale_checkpoint(self):
        with self.assertRaises(gp.PoolError): self.resume("d" * 64)
        self.assertNotIn("Resume", self.calls)

    def test_live_worker_or_unknown_held_lock_dispatches_nothing(self):
        for alive, lock in [(True, True), (False, False), (False, None)]:
            self.remote.update(workerAlive=alive, workerLockFree=lock)
            with self.assertRaises(gp.PoolError): self.resume()
        self.assertNotIn("Resume", self.calls)

    def test_concurrent_reconcile_or_resume_is_rejected(self):
        with gp.FileLock(self.root / "reconcile.lock", blocking=False):
            with self.assertRaises(gp.PoolLockError): self.resume()
        self.assertEqual(self.calls, [])

    def test_lost_dispatch_reply_never_replays_request(self):
        def lost(action, **kwargs):
            self.calls.append(action)
            if action == "Resume": raise wc.YC.NodeUnavailable("fixture-node", "synthetic lost connection")
            return copy.deepcopy(self.remote)
        self.adapter.side_effect = lost
        with self.assertRaisesRegex(gp.PoolError, "outcome uncertain"): self.resume()
        self.assertEqual(self.resume()["request_state"], "uncertain")
        self.assertEqual(self.calls.count("Resume"), 1)

    def test_wrong_node_lease_or_item_fails_before_dispatch(self):
        self.node_mock.return_value = {"nodeId": "9" * 64}
        with self.assertRaises(gp.PoolError): self.resume()
        self.node_mock.return_value = {"nodeId": self.node["node_id"]}
        item = self.store.load_item(IDS[0]); item["active_lease_id"] = "other"
        self.store.save_item(item)
        with self.assertRaises(gp.PoolError): self.resume()
        self.assertNotIn("Resume", self.calls)

    def test_lease_age_does_not_expire_authoritative_active_lease(self):
        path = self.store.leases_dir / (LEASE + ".json")
        lease = wc.read_json(path); lease["created_at"] = "2001-01-01T00:00:00Z"; lease["expires_at"] = "2001-01-02T00:00:00Z"
        self.write(path, lease)
        self.assertEqual(self.resume()["state"], "running")

    def test_returned_or_finalized_run_never_launches(self):
        self.remote["status"]["state"] = "complete"
        self.assertTrue(self.resume()["reconcile_required"])
        self.manifest["state"] = "completed"; self.write(self.root / "manifest.json", self.manifest)
        self.assertTrue(self.resume()["already_final"])
        self.assertNotIn("Resume", self.calls)

    def test_attention_required_supervisor_ticks_preserve_active_lease_without_resume(self):
        self.patch(sv, "LOCK_PATH", self.pool / "locks/supervisor-fixture.lock")
        self.patch(sv, "STATE_PATH", self.pool / "supervisor-fixture.json")
        self.patch(sv, "active_runs", side_effect=lambda: [(CANARY, wc.read_json(self.root / "manifest.json"))])
        self.patch(sv, "validate_cutover", return_value={})
        self.patch(sv.WC, "windows_node_status", return_value=self.node)
        self.patch(sv.WC, "validate_host", return_value={"state": "passed"})
        self.patch(sv.WC, "reconcile_canary", side_effect=wc.reconcile_canary)
        self.manifest["state"] = "attention_required"
        self.write(self.root / "manifest.json", self.manifest)
        self.remote["status"]["state"] = "unexpected_fixture_state"
        lease_path = self.store.leases_dir / (LEASE + ".json")
        lease_before = lease_path.read_bytes()
        items_before = {video: self.store.load_item(video) for video in IDS}
        for launch in (False, True):
            for _ in range(2):
                result = sv.tick(launch=launch)
                self.assertEqual(result["action"], "run_attention_required")
                self.assertTrue(result["alert"])
                self.assertEqual(result["result"]["state"], "attention_required")
                self.assertEqual(result["result"]["remote_state"], "unexpected_fixture_state")
        self.assertEqual(self.calls, ["Probe"] * 4)
        self.assertEqual(lease_path.read_bytes(), lease_before)
        self.assertEqual(items_before, {video: self.store.load_item(video) for video in IDS})

    def test_attention_required_reconciliation_observes_recovered_worker_without_resume(self):
        self.manifest["state"] = "attention_required"
        self.write(self.root / "manifest.json", self.manifest)
        self.remote["workerAlive"] = True
        self.remote["workerLockFree"] = False
        self.remote["status"]["state"] = "running"
        lease_path = self.store.leases_dir / (LEASE + ".json")
        lease_before = lease_path.read_bytes()
        self.assertEqual(wc.reconcile_canary(CANARY)["state"], "running")
        self.assertEqual(self.calls, ["Probe"])
        self.assertEqual(lease_path.read_bytes(), lease_before)

    def test_corrupt_request_fails_closed(self):
        self.write(self.root / "resume-requests" / (DIGEST + ".json"), {"state": "acknowledged"})
        with self.assertRaises(gp.PoolError): self.resume()
        self.assertNotIn("Resume", self.calls)

    def test_nonidempotent_rpc_has_no_transport_retry(self):
        run = self.patch(wc.YC, "run_node_command", side_effect=wc.YC.NodeUnavailable("fixture-node", "synthetic connection unavailable"))
        with self.assertRaises(wc.YC.NodeUnavailable): wc._run_node({}, [], timeout=1, operation="fixture", retry=False)
        self.assertEqual(run.call_count, 1)

    def import_receipt(self):
        for video in IDS:
            folder = self.archive / video; folder.mkdir()
            (folder / "report.md").write_text("fixture captions")
            (folder / "manifest.json").write_text(json.dumps({"video_id": video, "files": ["report.md", "manifest.json"]}))
        remote = wc._normalise_probe(self.remote); remote["state"] = "complete"
        bundle = self.root / "bundles/chunk-0001" / ("validated-archive-bundle-" + LEASE + ".tar.gz")
        bundle.parent.mkdir(parents=True, exist_ok=True); bundle.write_bytes(b"synthetic previously validated bundle")
        digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
        imported = {"validated": True, "bundle_sha256": digest, "video_ids": IDS, "terminal_items": [], "incomplete_items": []}
        self.write(self.root / "imports/chunk-0001.json", imported)
        self.write(bundle.parent / "receipt.json", {"sha256": digest, "size": bundle.stat().st_size, "canary_id": CANARY, "lease_id": LEASE, "cookies_used": False, "media_files": 0})
        self.write(self.root / "source-projection.json", {"canary_id": CANARY, "bundle_sha256": digest})
        return imported, remote

    def test_public_reconcile_replays_after_ordinary_lease_completion_crash(self):
        imported, remote = self.import_receipt()
        with patch.object(gp.PoolStore, "write_state", side_effect=OSError("synthetic crash after lease commit")):
            with self.assertRaises(OSError): lc.finalize_global_import(CANARY, imported, remote, root_override=self.root)
        self.assertEqual(wc.read_json(self.store.leases_dir / (LEASE + ".json"))["state"], "completed")
        self.assertTrue(wc.reconcile_canary(CANARY)["finalization_replayed"])
        self.assertEqual(self.calls, [])

    def test_public_reconcile_repairs_queue_after_final_manifest_write(self):
        imported, remote = self.import_receipt()
        atomic = lc.atomic_json
        def fail_queue(path, value):
            if path == self.root / "queue/state.json": raise OSError("synthetic queue interruption")
            return atomic(path, value)
        with patch.object(lc, "atomic_json", fail_queue):
            with self.assertRaises(OSError): lc.finalize_global_import(CANARY, imported, remote, root_override=self.root)
        self.assertEqual(wc.read_json(self.root / "manifest.json")["state"], "completed")
        self.assertTrue(wc.reconcile_canary(CANARY)["finalization_replayed"])
        self.assertEqual(wc.read_json(self.root / "queue/state.json")["state"], "completed")
        self.assertEqual(self.calls, [])

    def test_prepared_replay_rejects_lease_ownership_drift(self):
        imported, remote = self.import_receipt()
        with patch.object(gp.PoolStore, "save_item", side_effect=OSError("synthetic interruption")):
            with self.assertRaises(OSError): lc.finalize_global_import(CANARY, imported, remote, root_override=self.root)
        lease_path = self.store.leases_dir / (LEASE + ".json")
        lease = wc.read_json(lease_path); lease["node"]["id"] = "9" * 64; self.write(lease_path, lease)
        with self.assertRaisesRegex(gp.PoolError, "replay conflict"): wc.reconcile_canary(CANARY)
        self.assertEqual(wc.read_json(lease_path), lease)

    def test_finalization_replay_rejects_bundle_receipt_drift(self):
        imported, remote = self.import_receipt()
        with patch.object(gp.PoolStore, "write_state", side_effect=OSError("synthetic interruption")):
            with self.assertRaises(OSError): lc.finalize_global_import(CANARY, imported, remote, root_override=self.root)
        self.write(self.root / "bundles/chunk-0001/receipt.json", {"sha256": "0" * 64})
        with self.assertRaises(gp.PoolError): wc.reconcile_canary(CANARY)

    def test_partial_finalization_replays_without_clearing_wrong_lease(self):
        imported, remote = self.import_receipt()
        original = gp.PoolStore.save_item
        writes = []
        def interrupted(store, item):
            writes.append(item["video_id"])
            if len(writes) == 2: raise OSError("synthetic interruption")
            return original(store, item)
        with patch.object(gp.PoolStore, "save_item", interrupted):
            with self.assertRaises(OSError): lc.finalize_global_import(CANARY, imported, remote, root_override=self.root)
        self.assertEqual(wc.read_json(self.root / "finalization.json")["state"], "prepared")
        lc.finalize_global_import(CANARY, imported, remote, root_override=self.root)
        self.assertEqual(wc.read_json(self.root / "finalization.json")["state"], "committed")
        self.assertTrue(all(self.store.load_item(video)["active_lease_id"] is None for video in IDS))
        events = self.store.events_path.read_bytes()
        lc.finalize_global_import(CANARY, imported, remote, root_override=self.root)
        self.assertEqual(events, self.store.events_path.read_bytes())

    def test_committed_finalization_repairs_manifest_after_crash(self):
        imported, remote = self.import_receipt()
        with patch.object(lc, "update_canary_state", side_effect=OSError("synthetic manifest crash")):
            with self.assertRaises(OSError): lc.finalize_global_import(CANARY, imported, remote, root_override=self.root)
        lc.finalize_global_import(CANARY, imported, remote, root_override=self.root)
        self.assertEqual(wc.read_json(self.root / "manifest.json")["state"], "completed")

    def test_corrupt_journal_is_rejected_before_state_changes(self):
        imported, remote = self.import_receipt()
        self.write(self.root / "finalization.json", {"state": "prepared", "lease_id": LEASE, "bundle_sha256": imported["bundle_sha256"], "target_items": {}})
        before = {video: self.store.load_item(video) for video in IDS}
        with self.assertRaises(gp.PoolError): lc.finalize_global_import(CANARY, imported, remote, root_override=self.root)
        self.assertEqual(before, {video: self.store.load_item(video) for video in IDS})

    def test_unvalidated_import_is_rejected(self):
        imported, remote = self.import_receipt(); imported["validated"] = False
        with self.assertRaises(gp.PoolError): lc.finalize_global_import(CANARY, imported, remote, root_override=self.root)

    def projection_fixture(self):
        queue = Path(self.temp.name) / "personal-queue"; queue.mkdir()
        gp.write_jsonl(queue / "pending.jsonl", [{"video_id": video, "status": "pending", "queue_id": video} for video in IDS])
        self.patch(lc.STORAGE, "DEFAULT_QUEUE_ROOT", queue)
        catalog_root = Path(self.temp.name) / "yc"
        spec = importlib.util.spec_from_file_location("fixture_catalog_projection", SCRIPTS / "youtube_ycombinator/build_catalog.py")
        catalog = importlib.util.module_from_spec(spec); spec.loader.exec_module(catalog)
        return queue, catalog_root, catalog

    def test_terminal_source_projections_are_complete_and_replay_idempotently(self):
        imported, _ = self.import_receipt()
        imported.update(requested_video_ids=IDS, video_ids=IDS[:1], terminal_items=[
            {"video_id": video, "state": state, "attempts": 1, "failure_class": state, "error": "synthetic unavailable video"}
            for video, state in zip(IDS[1:], ("skipped_private", "skipped_age_restricted", "skipped_unavailable"))])
        queue, catalog_root, catalog = self.projection_fixture()
        lc.persist_catalog_outcomes(CANARY, imported, catalog_root)
        self.assertEqual(lc.update_personal_source_projection(CANARY, imported, "fixture-time")["changed_count"], 4)
        rows = gp.read_jsonl(queue / "pending.jsonl")
        self.assertEqual([row["status"] for row in rows], ["archived", "skipped_private", "skipped_age_restricted", "skipped_unavailable"])
        outcomes = catalog.load_terminal_outcomes(catalog_root, set(IDS))
        self.assertEqual(catalog.classify_video_ids(IDS, {video: {"complete": index == 0} for index, video in enumerate(IDS)}, outcomes), (IDS[:1], IDS[1:], []))
        before = {path: path.read_bytes() for path in queue.iterdir()}
        lc.persist_catalog_outcomes(CANARY, imported, catalog_root)
        self.assertEqual(lc.update_personal_source_projection(CANARY, imported, "later-time")["changed_count"], 0)
        self.assertEqual(before, {path: path.read_bytes() for path in queue.iterdir()})

    def test_projection_stop_before_queue_commit_preserves_events_and_replays_once(self):
        class ProcessStopped(BaseException): pass
        imported, _ = self.import_receipt(); imported["requested_video_ids"] = IDS
        queue, _, _ = self.projection_fixture()
        pending = queue / "pending.jsonl"
        original_queue = pending.read_bytes()
        events = queue / "events.jsonl"
        prefix = b'{"action":"fixture_prior_event"}\n'
        events.write_bytes(prefix)
        writer = gp.write_jsonl
        def stop_before_queue(path, rows):
            if path == pending: raise ProcessStopped("fixture stop before queue commit")
            return writer(path, rows)
        with patch.object(gp, "write_jsonl", side_effect=stop_before_queue):
            with self.assertRaises(ProcessStopped): lc.update_personal_source_projection(CANARY, imported, "first-time")
        self.assertEqual(original_queue, pending.read_bytes())
        committed_events = events.read_bytes()
        self.assertTrue(committed_events.startswith(prefix))
        outcome_events = gp.read_jsonl(events)[1:]
        self.assertEqual(len(outcome_events), 4)
        self.assertTrue(all(row["old_status"] == "pending" for row in outcome_events))
        self.assertEqual(lc.update_personal_source_projection(CANARY, imported, "later-time")["changed_count"], 4)
        self.assertEqual(committed_events, events.read_bytes())
        self.assertEqual(lc.update_personal_source_projection(CANARY, imported, "third-time")["changed_count"], 0)
        self.assertEqual(committed_events, events.read_bytes())
        self.assertTrue(all(row["status"] == "archived" for row in gp.read_jsonl(pending)))

    def test_projection_event_directory_sync_failure_preserves_queue_until_replay(self):
        imported, _ = self.import_receipt(); imported["requested_video_ids"] = IDS
        queue, _, _ = self.projection_fixture()
        pending = queue / "pending.jsonl"
        original_queue = pending.read_bytes()
        real_sync = gp.fsync_directory
        def fail_events_directory(path):
            if path == queue: raise OSError("fixture event directory sync failure")
            return real_sync(path)
        with patch.object(gp, "fsync_directory", side_effect=fail_events_directory):
            with self.assertRaises(OSError): lc.update_personal_source_projection(CANARY, imported, "first-time")
        self.assertEqual(original_queue, pending.read_bytes())
        committed_events = (queue / "events.jsonl").read_bytes()
        self.assertEqual(lc.update_personal_source_projection(CANARY, imported, "later-time")["changed_count"], 4)
        self.assertEqual(committed_events, (queue / "events.jsonl").read_bytes())

    def test_catalog_admission_remains_fail_closed_under_python_optimization(self):
        project = Path(self.temp.name) / "optimized-catalog"
        source = project / "fixture-source"; source.mkdir(parents=True)
        playlists = [f"fixture-playlist-{index}" for index in range(52)]
        entries = [{"id": f"v{index:010d}", "title": "fixture video"} for index in range(792)]
        inventory = {"playlist_count": 52, "top_level_counts": {"playlists": 52, "podcasts": 4}, "unresolved_count": 0, "unique_video_count": 792,
            "top_level_entries": {"playlists": [{"id": value} for value in playlists], "podcasts": [{"id": value} for value in playlists[:4]]},
            "playlists": {value: {"title": value, "entries": entries if index == 0 else []} for index, value in enumerate(playlists)}}
        self.write(source / "inventory.json", inventory)
        valid = {"state": "complete", "cookies_used": False, "media_downloaded": False}
        self.write(source / "status.json", valid)
        command = [sys.executable, "-O", str(SCRIPTS / "youtube_ycombinator/build_catalog.py"),
            "--project-root", str(project), "--source-dir", "fixture-source", "--archive-root", str(self.archive),
            "--state-root", str(Path(self.temp.name) / "fixture-state"), "--projection-root", str(Path(self.temp.name) / "fixture-projection")]
        completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        outputs = {path: path.read_bytes() for path in project.rglob("*") if path.is_file() and not path.is_relative_to(source)}
        self.assertTrue(outputs)
        for key, value in (("state", "incomplete"), ("cookies_used", True), ("media_downloaded", True)):
            with self.subTest(key=key):
                invalid = {**valid, key: value}; self.write(source / "status.json", invalid)
                failed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
                self.assertNotEqual(failed.returncode, 0)
                self.assertIn(b"complete anonymous caption-only inventory", failed.stderr)
                self.assertEqual(outputs, {path: path.read_bytes() for path in project.rglob("*") if path.is_file() and not path.is_relative_to(source)})

    def test_source_projection_keeps_incomplete_items_pending(self):
        imported, _ = self.import_receipt()
        imported.update(requested_video_ids=IDS, video_ids=IDS[:1], terminal_items=[{"video_id": IDS[1], "state": "skipped_private", "attempts": 1}], incomplete_items=[{"video_id": video, "state": "blocked_error", "attempts": 3} for video in IDS[2:]])
        queue, catalog_root, catalog = self.projection_fixture()
        lc.persist_catalog_outcomes(CANARY, imported, catalog_root)
        lc.update_personal_source_projection(CANARY, imported, "fixture-time")
        self.assertEqual([row["status"] for row in gp.read_jsonl(queue / "pending.jsonl")], ["archived", "skipped_private", "pending", "pending"])
        self.assertEqual(set(catalog.load_terminal_outcomes(catalog_root, set(IDS[:1]))), set())

    def test_invalid_source_partition_is_refused_before_projection_writes(self):
        imported, _ = self.import_receipt(); imported.update(requested_video_ids=IDS, terminal_items=[{"video_id": IDS[0], "state": "skipped_private"}])
        queue, catalog_root, _ = self.projection_fixture()
        before = (queue / "pending.jsonl").read_bytes()
        with self.assertRaises(gp.PoolError): lc.persist_catalog_outcomes(CANARY, imported, catalog_root)
        with self.assertRaises(gp.PoolError): lc.update_personal_source_projection(CANARY, imported, "fixture-time")
        self.assertFalse(catalog_root.exists())
        self.assertEqual(before, (queue / "pending.jsonl").read_bytes())

    def test_atomic_initial_checkpoint_is_observed_before_explicit_recovery(self):
        self.manifest["state"] = "launching"; self.write(self.root / "manifest.json", self.manifest)
        self.remote["status"]["state"] = "running"
        self.remote["status"]["items"] = {video: {"video_id": video, "state": "pending", "attempts": 0} for video in IDS}
        self.assertEqual(wc.launch_canary(CANARY)["state"], "running")
        self.assertEqual(self.calls, ["Probe"])
        self.assertEqual(self.resume()["state"], "running")
        self.assertEqual(self.calls.count("Resume"), 1)
        self.assertNotIn("StageLaunch", self.calls)

    def test_exact_lease_recovery_repairs_event_and_aggregate_after_process_stop(self):
        class ProcessStopped(BaseException): pass
        for stop_after_event in (False, True):
            with self.subTest(stop_after_event=stop_after_event):
                pool = Path(self.temp.name) / ("lease-fixture-" + str(stop_after_event))
                store = gp.PoolStore(pool); store.ensure_dirs()
                for video in IDS: store.save_item({"video_id": video, "status": "pending", "active_lease_id": None})
                store.write_state()
                node = gp.NodeTarget(self.node["node_id"], self.node["display_name"], "windows")
                boundary = "write_state" if stop_after_event else "append_event"
                with patch.object(store, boundary, side_effect=ProcessStopped("fixture process exit")):
                    with self.assertRaises(ProcessStopped): store.create_lease(node, store.load_items(), lease_id=LEASE, chunk_id=CANARY)
                journal = store.root / "runs" / f"lease-create-{LEASE}.json"
                self.assertEqual(gp.read_json(journal)["state"], "prepared")
                before = {video: store.load_item(video) for video in IDS}
                store.create_lease(node, store.load_items(), lease_id=LEASE, chunk_id=CANARY)
                self.assertEqual(gp.read_json(journal)["state"], "committed")
                self.assertEqual(gp.read_json(store.state_path)["active_leases"], [LEASE])
                self.assertEqual(before, {video: store.load_item(video) for video in IDS})
                events = store.events_path.read_bytes()
                self.assertEqual(len([row for row in gp.read_jsonl(store.events_path) if row["type"] == "lease_created"]), 1)
                store.create_lease(node, store.load_items(), lease_id=LEASE, chunk_id=CANARY)
                self.assertEqual(events, store.events_path.read_bytes())

    def test_configured_tools_and_actual_adapter_paths_must_agree(self):
        from youtube_windows_config import validate_config, WindowsConfigError
        for key in ("archiver", "wrapper"):
            configuration = copy.deepcopy(CONFIG); configuration["remote"][key] = str(wc.PureWindowsPath(CONFIG["node"]["cwd"]) / "fixture-other-tool.cmd")
            with self.assertRaises(WindowsConfigError): validate_config(configuration)
        receipt = {"readOnly": True, "eligible": True, "checks": {"platform": "Win32NT", "transportImplemented": True, "assets": CONFIG["assets"], "archiver": CONFIG["remote"]["archiver"], "ytDlpWrapper": CONFIG["remote"]["wrapper"]}}
        self.node_mock.return_value = {"nodeId": self.node["node_id"], "displayName": self.node["display_name"], "platform": "windows", "connected": True}
        self.adapter.side_effect = None; self.adapter.return_value = receipt
        self.assertEqual(wc.validate_host()["state"], "passed")
        receipt["checks"]["archiver"] = str(wc.PureWindowsPath(CONFIG["node"]["cwd"]) / "fixture-other-tool.cmd")
        with self.assertRaisesRegex(gp.PoolError, "actual tool paths"): wc.validate_host()


    def test_failed_file_sync_preserves_previous_atomic_record(self):
        path = self.pool / "durability-fixture.json"
        gp.atomic_json(path, {"state": "original"})
        original = path.read_bytes()
        with patch.object(gp.os, "fsync", side_effect=OSError("fixture storage sync failure")):
            with self.assertRaises(OSError): gp.atomic_json(path, {"state": "changed"})
        self.assertEqual(path.read_bytes(), original)

    def test_finalization_journal_sync_failure_preserves_active_lease_and_items(self):
        imported, remote = self.import_receipt()
        before = {video: self.store.load_item(video) for video in IDS}
        lease_before = (self.store.leases_dir / (LEASE + ".json")).read_bytes()
        real_sync = gp.fsync_directory
        def fail_journal_directory(path):
            if path == self.root: raise OSError("fixture finalization directory sync failure")
            return real_sync(path)
        with patch.object(gp, "fsync_directory", side_effect=fail_journal_directory):
            with self.assertRaises(OSError): lc.finalize_global_import(CANARY, imported, remote, root_override=self.root)
        self.assertEqual(before, {video: self.store.load_item(video) for video in IDS})
        self.assertEqual((self.store.leases_dir / (LEASE + ".json")).read_bytes(), lease_before)
        self.assertEqual(wc.read_json(self.root / "finalization.json")["state"], "prepared")
        lc.finalize_global_import(CANARY, imported, remote, root_override=self.root)
        self.assertEqual(wc.read_json(self.root / "finalization.json")["state"], "committed")

    def test_resume_receipt_sync_failure_dispatches_no_recovery(self):
        before = {video: self.store.load_item(video) for video in IDS}
        real_sync = gp.fsync_directory
        def fail_request_directory(path):
            if path == self.root: raise OSError("fixture resume receipt sync failure")
            return real_sync(path)
        with patch.object(gp, "fsync_directory", side_effect=fail_request_directory):
            with self.assertRaises(OSError): self.resume()
        self.assertNotIn("Resume", self.calls)
        self.assertEqual(before, {video: self.store.load_item(video) for video in IDS})

    def test_failed_catalog_file_sync_preserves_previous_projection(self):
        _, catalog_root, catalog = self.projection_fixture()
        path = catalog_root / "catalog.json"
        catalog.atomic_json(path, {"state": "original"})
        original = path.read_bytes()
        with patch.object(catalog.os, "fsync", side_effect=OSError("fixture catalog sync failure")):
            with self.assertRaises(OSError): catalog.atomic_json(path, {"state": "changed"})
        self.assertEqual(path.read_bytes(), original)

    def test_prepared_journal_sync_failure_creates_no_active_lease(self):
        pool = Path(self.temp.name) / "durability-lease-fixture"
        store = gp.PoolStore(pool); store.ensure_dirs()
        for video in IDS: store.save_item({"video_id": video, "status": "pending", "active_lease_id": None})
        real_sync = gp.os.fsync
        def fail_directory_sync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode): raise OSError("fixture directory sync failure")
            return real_sync(fd)
        node = gp.NodeTarget(self.node["node_id"], self.node["display_name"], "windows")
        with patch.object(gp.os, "fsync", side_effect=fail_directory_sync):
            with self.assertRaises(OSError): store.create_lease(node, store.load_items(), lease_id=LEASE, chunk_id=CANARY)
        self.assertEqual(list(store.leases_dir.glob("*.json")), [])
        self.assertTrue(all(item["active_lease_id"] is None for item in store.load_items()))
        journal = store.root / "runs" / f"lease-create-{LEASE}.json"
        self.assertEqual(gp.read_json(journal)["state"], "prepared")
        store.create_lease(node, store.load_items(), lease_id=LEASE, chunk_id=CANARY)
        self.assertEqual(gp.read_json(journal)["state"], "committed")
        self.assertEqual(len(list(store.leases_dir.glob("*.json"))), 1)

    def test_prelease_preparations_do_not_consume_launch_budget(self):
        paths = []
        for index in range(50):
            path = self.pool / f"fixture-unlaunched-{index}.json"
            self.write(path, {"run_kind": "windows_production", "state": "superseded_before_lease" if index % 2 else "prepared", "created_at": "2026-01-01T00:00:00Z"})
            paths.append(path)
        marker = {"max_chunk_launches_per_day": 48, "minimum_launch_interval_minutes": 15}
        with patch.object(sv, "run_manifest_paths", return_value=paths):
            result = sv.launch_metrics(marker, now=dt.datetime(2026,1,1,0,1,tzinfo=dt.timezone.utc))
        self.assertTrue(result["allowed"])
        self.assertEqual(result["launches_today"], 0)

    def test_actual_and_legacy_observed_launches_still_enforce_budget(self):
        marker = {"max_chunk_launches_per_day": 48, "minimum_launch_interval_minutes": 15}
        for evidence in ({"launched_at": "2026-01-01T00:00:00Z"}, {"worker_pid": 12345}):
            path = self.pool / "fixture-launched.json"
            self.write(path, {"run_kind": "windows_production", "state": "completed", "created_at": "2026-01-01T00:00:00Z", **evidence})
            with patch.object(sv, "run_manifest_paths", return_value=[path]):
                result = sv.launch_metrics(marker, now=dt.datetime(2026,1,1,0,1,tzinfo=dt.timezone.utc))
            self.assertFalse(result["allowed"])
            self.assertEqual(result["reason"], "minimum_launch_interval")
            self.assertEqual(result["launches_today"], 1)


if __name__ == "__main__": unittest.main()
