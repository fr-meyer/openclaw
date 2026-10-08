"""Offline incident and registered cron boundary proofs; no channel/provider calls."""
import contextlib
import copy
import datetime as dt
import io
import json
import multiprocessing
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime/scripts"))
import youtube_worker_alerts as alerts
from test_coordinator_recovery import sv

RUN = "windows-canary-prod-fixture-one"
LEASE = "00000000-0000-4000-8000-000000000001"
NOW = dt.datetime(2026, 10, 8, tzinfo=dt.timezone.utc)
SNAPSHOT = {"run_id": RUN, "lease_id": LEASE, "phase": "attention", "failure_code": "rate_limited",
            "video_id": "fixture0001", "archived_count": 3, "incomplete_count": 21, "recovery_verified": False}


def reserve_in_process(path, ready, results):
    ready.wait()
    with alerts.NotificationStore(Path(path)) as store:
        result = store.observe(SNAPSHOT, now=NOW)
        results.put(result is not None)


class NotificationOwnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.database = Path(self.temp.name) / "notifications.sqlite3"

    def observe(self, snapshot=SNAPSHOT, now=NOW):
        with alerts.NotificationStore(self.database) as store:
            return store.observe(snapshot, now=now)

    def test_unchanged_repeat_and_restart_reserve_only_once(self):
        first = self.observe()
        self.assertIn("rate limited", first.message)
        self.assertIsNone(self.observe())
        self.assertIsNone(self.observe(now=NOW + dt.timedelta(days=30)))

    def test_changed_counts_do_not_reopen_the_same_incident(self):
        self.observe()
        changed = {**SNAPSHOT, "archived_count": 4, "incomplete_count": 20}
        self.assertIsNone(self.observe(changed))

    def test_existing_maximum_batch_size_remains_supported(self):
        first = self.observe({**SNAPSHOT, "archived_count": 3, "incomplete_count": 22})
        self.assertIn("22 unfinished", first.message)

    def test_changed_failure_and_video_each_emit_once(self):
        self.observe()
        changed = {**SNAPSHOT, "failure_code": "bot_check"}
        self.assertIsNotNone(self.observe(changed))
        self.assertIsNone(self.observe(changed))
        changed = {**changed, "video_id": "fixture0002"}
        self.assertIsNotNone(self.observe(changed))
        self.assertIsNone(self.observe(changed))

    def test_unknown_failures_remain_visible_without_raw_errors(self):
        first = self.observe({**SNAPSHOT, "failure_code": "unknown:" + "a" * 64})
        self.assertIn("recognized", first.message)
        second = self.observe({**SNAPSHOT, "failure_code": "unknown:" + "b" * 64})
        self.assertIsNotNone(second)
        self.assertNotIn("a" * 16, first.message)

    def test_new_run_is_a_new_incident(self):
        self.observe()
        self.assertIsNotNone(self.observe({**SNAPSHOT, "run_id": "windows-canary-prod-fixture-two", "lease_id": "00000000-0000-4000-8000-000000000002"}))

    def test_live_lease_reassignment_is_not_silently_suppressed(self):
        self.observe()
        with self.assertRaises(alerts.NotificationError):
            self.observe({**SNAPSHOT, "lease_id": "00000000-0000-4000-8000-000000000002"})

    def test_running_is_progress_and_never_successful_recovery(self):
        self.observe()
        message = self.observe({**SNAPSHOT, "phase": "watching"}).message
        self.assertIn("resumed", message)
        self.assertNotIn("recovered", message)
        self.assertIsNone(self.observe({**SNAPSHOT, "phase": "watching"}))

    def test_verified_recovery_once_and_healthy_runs_stay_silent(self):
        resolved = {**SNAPSHOT, "phase": "resolved", "recovery_verified": True, "archived_count": 24, "incomplete_count": 0}
        self.assertIsNone(self.observe(resolved))
        self.observe()
        self.assertIn("recovered", self.observe(resolved).message)
        self.assertIsNone(self.observe(resolved))
        with self.assertRaises(alerts.NotificationError):
            self.observe()

    def test_unverified_recovery_refused(self):
        self.observe()
        with self.assertRaises(alerts.NotificationError):
            self.observe({**SNAPSHOT, "phase": "resolved"})

    def test_crash_after_reservation_before_stdout_does_not_replay(self):
        first = self.observe()  # Deliberately omit mark_emission, as a crashed process would.
        self.assertIsNone(self.observe())
        with alerts.NotificationStore(self.database, read_only=True) as store:
            status = json.dumps(store.status())
        self.assertIn(first.event_id, status)
        self.assertIn("reserved", status)
        self.assertNotIn('"delivered"', status)

    def test_failed_or_partial_emission_is_uncertain_and_not_retried(self):
        first = self.observe()
        with alerts.NotificationStore(self.database) as store:
            store.mark_emission(first.event_id, successful=False)
        self.assertIsNone(self.observe())
        with alerts.NotificationStore(self.database, read_only=True) as store:
            self.assertIn("uncertain", json.dumps(store.status()))

    def test_print_success_does_not_claim_whatsapp_delivery(self):
        first = self.observe()
        with alerts.NotificationStore(self.database) as store:
            store.mark_emission(first.event_id, successful=True)
        with alerts.NotificationStore(self.database, read_only=True) as store:
            status = json.dumps(store.status())
        self.assertIn("emitted", status)
        self.assertNotIn('"delivery_state": "delivered"', status)
        self.assertIsNone(self.observe())

    def test_concurrent_processes_reserve_one_event(self):
        # One process composition protects SQLite's cross-process reservation contract.
        context = multiprocessing.get_context("fork")
        ready = context.Barrier(4)
        results = context.Queue()
        processes = [context.Process(target=reserve_in_process, args=(str(self.database), ready, results)) for _ in range(4)]
        for process in processes:
            process.start()
        for process in processes:
            process.join(5)
            self.assertEqual(process.exitcode, 0)
        self.assertEqual(sum(results.get(timeout=1) for _ in processes), 1)
        results.close()

    def test_read_only_status_missing_database_creates_nothing(self):
        with alerts.NotificationStore(self.database, read_only=True) as store:
            store.status()
        self.assertFalse(self.database.exists())

    def test_unsafe_database_and_invalid_snapshot_fail_visibly(self):
        target = Path(self.temp.name) / "target"
        target.write_text("preserve")
        self.database.symlink_to(target)
        with self.assertRaises((alerts.NotificationError, OSError)):
            self.observe()
        self.assertEqual(target.read_text(), "preserve")


class ScheduledNotificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.pool = Path(self.temp.name) / "pool"
        self.root = self.pool / "windows-canaries" / RUN
        self.root.mkdir(parents=True)
        self.manifest = {"canary_id": RUN, "lease_id": LEASE, "state": "blocked", "expected_item_count": 24,
                         "worker_alive": False, "reason": "rate_limited", "remote_summary": {
                             "state": "waiting_network_cooldown", "current_video_id": "fixture0001",
                             "circuit_reason": "rate_limited", "counts": {"archived": 3, "pending": 20, "waiting_network_cooldown": 1}}}
        self.write(self.root / "manifest.json", self.manifest)
        for name, value in [("POOL_ROOT", self.pool), ("RUNS_ROOT", self.pool / "windows-canaries"), ("LOCK_PATH", self.pool / "locks/supervisor.lock"),
                            ("ALERT_DATABASE", self.pool / "notifications.sqlite3")]:
            p = patch.object(sv, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.tick = patch.object(sv, "tick", return_value={"run_id": RUN, "alert": True})
        self.tick.start()
        self.addCleanup(self.tick.stop)

    def write(self, path, record):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(record))

    def invoke(self, entry):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(entry(), 0)
        return stdout.getvalue().strip()

    def test_actual_cron_and_reconcile_share_suppression(self):
        before = (self.root / "manifest.json").read_bytes()
        self.assertIn("needs attention", self.invoke(sv.cron_main))
        self.assertEqual(self.invoke(sv.cron_reconcile_main), "NO_REPLY")
        self.assertEqual(self.invoke(sv.cron_main), "NO_REPLY")
        self.assertEqual((self.root / "manifest.json").read_bytes(), before)

    def test_polling_timestamps_and_pid_changes_do_not_alert(self):
        self.invoke(sv.cron_reconcile_main)
        changed = copy.deepcopy(self.manifest)
        changed.update(updated_at="2030-01-01T00:00:00Z", worker_pid=12345)
        changed["remote_summary"].update(updated_at="2030-01-01T00:00:00Z")
        self.write(self.root / "manifest.json", changed)
        self.assertEqual(self.invoke(sv.cron_main), "NO_REPLY")

    def test_restarts_and_returns_to_seen_incidents_do_not_replay_notices(self):
        self.assertIn("needs attention", self.invoke(sv.cron_main))

        def running():
            record = copy.deepcopy(self.manifest)
            record.update(state="running", worker_alive=True)
            record["remote_summary"].update(state="running", circuit_open=False,
                                          counts={"archived": 3, "running": 1, "pending": 20})
            self.write(self.root / "manifest.json", record)

        running()
        self.assertIn("resumed", self.invoke(sv.cron_reconcile_main))
        for _ in range(2):
            self.write(self.root / "manifest.json", self.manifest)
            self.assertEqual(self.invoke(sv.cron_main), "NO_REPLY")
            running()
            self.assertEqual(self.invoke(sv.cron_reconcile_main), "NO_REPLY")

        changed = copy.deepcopy(self.manifest)
        changed["remote_summary"]["circuit_reason"] = "bot_check"
        self.write(self.root / "manifest.json", changed)
        self.assertIn("needs attention", self.invoke(sv.cron_reconcile_main))
        running()
        self.assertIn("resumed", self.invoke(sv.cron_main))
        self.write(self.root / "manifest.json", self.manifest)
        self.assertEqual(self.invoke(sv.cron_reconcile_main), "NO_REPLY")
        # Suppressed transitions still update lifecycle facts and retain a
        # valid reference to the last reserved emission across process opens.
        with alerts.NotificationStore(sv.ALERT_DATABASE, read_only=True) as store:
            status = store.status()[0]
        self.assertEqual(status["phase"], "attention")
        self.assertEqual(status["failure_code"], "rate_limited")
        self.assertEqual(status["latest_event"]["kind"], "resumed")

    def test_new_unknown_failure_changes_are_visible_and_sanitized(self):
        self.invoke(sv.cron_main)
        changed = copy.deepcopy(self.manifest)
        changed["reason"] = "unexpected_reply"
        changed["remote_summary"].update(circuit_reason="unexpected_reply", state="unknown_provider_reply")
        changed["remote_summary"]["error"] = "sensitive arbitrary fixture output must not be copied"
        self.write(self.root / "manifest.json", changed)
        output = self.invoke(sv.cron_reconcile_main)
        self.assertIn("needs attention", output)
        self.assertNotIn("sensitive arbitrary", output)
        self.assertEqual(self.invoke(sv.cron_main), "NO_REPLY")

    def test_partial_import_reports_changed_validated_outcomes_not_old_reason(self):
        self.invoke(sv.cron_main)
        ids = [f"fixture{i:04d}" for i in range(1, 25)]
        digest = "a" * 64
        partial = {**self.manifest, "state": "partial", "video_ids": ids,
                   "bundle_sha256": digest, "remote_summary": {
                       "state": "complete", "current_video_id": ids[0],
                       "counts": {"archived": 3, "failed_provisional": 1, "pending": 20}}}
        imported = {"validated": True, "requested_video_ids": ids, "video_ids": ids[1:4],
                    "terminal_items": [], "incomplete_count": 21, "bundle_sha256": digest,
                    "cookies_used": False, "media_files": 0,
                    "incomplete_items": [{"video_id": ids[0], "state": "failed_provisional",
                                          "failure_class": "bot_check", "error": "private fixture output"}]
                    + [{"video_id": video, "state": "pending", "failure_class": None} for video in ids[4:]]}
        self.write(self.root / "manifest.json", partial)
        self.write(self.root / "imports/chunk-0001.json", imported)
        output = self.invoke(sv.cron_reconcile_main)
        self.assertIn("needs attention", output)
        self.assertNotIn("rate limited", output)
        self.assertNotIn("private fixture output", output)
        self.assertEqual(self.invoke(sv.cron_main), "NO_REPLY")
        # A newly failed second item is meaningful even if the primary failure
        # remains unchanged; receipt ordering alone is not meaningful.
        imported["incomplete_items"][1].update(state="failed_provisional", failure_class="auth_required")
        self.write(self.root / "imports/chunk-0001.json", imported)
        self.assertIn("needs attention", self.invoke(sv.cron_main))
        imported["incomplete_items"].reverse()
        self.write(self.root / "imports/chunk-0001.json", imported)
        self.assertEqual(self.invoke(sv.cron_reconcile_main), "NO_REPLY")
        imported["bundle_sha256"] = "b" * 64
        self.write(self.root / "imports/chunk-0001.json", imported)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(sv.cron_main(), 1)

    def test_unknown_codes_with_digits_and_punctuation_remain_distinct(self):
        changed = copy.deepcopy(self.manifest)
        changed["state"] = "attention_required"
        previous = None
        for code, remote_state in [("http_429", "stopped_v1"), ("http_403", "stopped_v1"), ("http_403", "stopped-v2")]:
            changed["remote_summary"].update(circuit_reason=code, state=remote_state)
            self.write(self.root / "manifest.json", changed)
            output = self.invoke(sv.cron_reconcile_main)
            self.assertIn("needs attention", output)
            self.assertNotIn(code, output)
            self.assertNotEqual(output, previous)
            self.assertEqual(self.invoke(sv.cron_main), "NO_REPLY")
            previous = output

    def test_unexpected_stopped_state_does_not_inherit_previous_rate_limit(self):
        first = self.invoke(sv.cron_main)
        changed = copy.deepcopy(self.manifest)
        changed["state"] = "attention_required"
        changed["remote_summary"].update(state="unexpected_stopped")
        del changed["remote_summary"]["circuit_reason"]
        self.write(self.root / "manifest.json", changed)
        output = self.invoke(sv.cron_reconcile_main)
        self.assertIn("needs attention", output)
        self.assertNotIn("rate limited", output)
        self.assertNotEqual(output, first)
        self.assertEqual(self.invoke(sv.cron_main), "NO_REPLY")

    def test_valid_terminal_skips_are_not_unfinished_items(self):
        changed = copy.deepcopy(self.manifest)
        changed["remote_summary"]["counts"]["skipped_private"] = 2
        changed["remote_summary"]["counts"]["pending"] = 18
        self.write(self.root / "manifest.json", changed)
        output = self.invoke(sv.cron_main)
        self.assertIn("3 archived; 19 unfinished", output)

    def test_print_failure_persists_uncertainty_without_duplicate(self):
        with patch("builtins.print", side_effect=BrokenPipeError):
            with self.assertRaises(BrokenPipeError):
                sv.emit_notifications({"run_id": RUN, "alert": True})
        self.assertEqual(self.invoke(sv.cron_main), "NO_REPLY")
        with alerts.NotificationStore(sv.ALERT_DATABASE, read_only=True) as store:
            self.assertIn("uncertain", json.dumps(store.status()))

    def test_missing_run_and_genuine_supervisor_errors_remain_visible(self):
        (self.root / "manifest.json").unlink()
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.assertEqual(sv.cron_main(), 1)
        self.assertIn("failed closed", stderr.getvalue())

    def test_recovery_requires_matching_committed_finalization_and_cleared_bindings(self):
        self.invoke(sv.cron_main)
        ids = [f"fixture{i:04d}" for i in range(1, 25)]
        digest = "a" * 64
        complete = {**self.manifest, "state": "completed", "bundle_sha256": digest, "video_ids": ids,
                    "archived_count": 24, "incomplete_count": 0, "remote_summary": {"counts": {"archived": 24}}}
        self.write(self.root / "manifest.json", complete)
        imported = {"validated": True, "requested_video_ids": ids, "video_ids": ids, "terminal_items": [],
                    "incomplete_items": [], "incomplete_count": 0, "bundle_sha256": digest, "cookies_used": False, "media_files": 0}
        self.write(self.root / "imports/chunk-0001.json", imported)
        journal = {"schema": "openclaw.youtube.windows-finalization.v2", "canary_id": RUN, "lease_id": LEASE, "bundle_sha256": digest,
                   "target_items": {video: {"video_id": video} for video in ids}, "preimages": {video: {"video_id": video} for video in ids},
                   "target_lease": {"lease_id": LEASE, "chunk_id": RUN, "video_ids": ids, "state": "completed"},
                   "target_chunk": {"lease_id": LEASE, "state": "completed"}}
        journal["journal_sha256"] = sv.stable_hash(journal)
        journal["state"] = "prepared"
        self.write(self.root / "finalization.json", journal)
        self.write(self.pool / "leases" / (LEASE + ".json"), {"state": "completed", "lease_id": LEASE, "chunk_id": RUN, "video_ids": ids})
        self.write(self.pool / "chunks" / (RUN + ".json"), {"state": "completed", "lease_id": LEASE})
        for video in ids:
            self.write(self.pool / "items" / (video + ".json"), {"status": "archived", "active_lease_id": None, "active_node": None})
        self.assertEqual(self.invoke(sv.cron_reconcile_main), "NO_REPLY")
        journal["state"] = "committed"
        self.write(self.root / "finalization.json", journal)
        self.write(self.pool / "items" / (ids[0] + ".json"), {"status": "archived", "active_lease_id": LEASE, "active_node": None})
        self.assertEqual(self.invoke(sv.cron_main), "NO_REPLY")
        self.write(self.pool / "items" / (ids[0] + ".json"), {"status": "archived", "active_lease_id": None, "active_node": None})
        # A committed journal can precede the manifest and its separate queue
        # write. Missing/stale queue state must not advertise finished recovery.
        self.assertEqual(self.invoke(sv.cron_reconcile_main), "NO_REPLY")
        queue = {"state": "completed", "bundle_sha256": digest, "worker_alive": False}
        for drift in [{"state": "blocked"}, {"bundle_sha256": "b" * 64}, {"worker_alive": True}]:
            self.write(self.root / "queue/state.json", {**queue, **drift})
            self.assertEqual(self.invoke(sv.cron_main), "NO_REPLY")
        self.write(self.root / "queue/state.json", queue)
        self.assertIn("recovered", self.invoke(sv.cron_reconcile_main))
        self.assertEqual(self.invoke(sv.cron_main), "NO_REPLY")


if __name__ == "__main__":
    unittest.main()
