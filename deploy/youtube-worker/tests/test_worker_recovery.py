"""Offline recovery regressions; every extractor/process boundary is mocked."""

import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.parse import urlunsplit


WORKER_PATH = Path(__file__).resolve().parents[1] / "runtime" / "scripts" / "youtube_global_chunk_worker.py"
SPEC = importlib.util.spec_from_file_location("youtube_recovery_worker", WORKER_PATH)
worker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(worker)

VIDEO_IDS = [f"fixture{index:04d}" for index in range(1, 9)]
LEASE = "synthetic-worker-lease"
WARNING = "WARNING: [youtube] No supported JavaScript runtime could be found."
VERSIONS = "\nnode v24.18.0\n2026.08.19\n"


class WorkerRecoveryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name) / "synthetic-chunk"
        self.base.mkdir()
        self.archive = self.base / "archive"
        self.archive.mkdir()
        self.urls = self.base / "urls.tsv"
        self.urls.write_text("".join(f"{video}\thttps://www.youtube.com/watch?v={video}\n" for video in VIDEO_IDS), encoding="utf-8")
        self.status = self.base / "status.json"
        self.pid = self.base / "worker.pid"
        self.pid.write_text("synthetic-prior-pid\n", encoding="utf-8")
        self.args = argparse.Namespace(
            base=str(self.base), urls=str(self.urls), archive_root=str(self.archive),
            python="synthetic-python", archiver="synthetic-archiver.py",
            yt_dlp="synthetic-wrapper.cmd", max_attempts=3, inter_item_sleep=5,
            lease_id=LEASE, resume_blocked=True, wrapper_preflight=False,
        )
        self.original_archive_factory = worker.start_archive_process
        self.spawn = self.start_patch(worker, "start_archive_process", side_effect=AssertionError("unexpected process launch"))
        self.original_guarded_runner = worker.run_guarded_command
        self.run = self.start_patch(worker, "run_guarded_command", side_effect=AssertionError("unexpected tool launch"))
        self.sleep = self.start_patch(worker.time, "sleep")

    def start_patch(self, target, name, **options):
        patcher = patch.object(target, name, **options)
        self.addCleanup(patcher.stop)
        return patcher.start()

    def write_archive(self, video):
        folder = self.archive / video
        folder.mkdir(exist_ok=True)
        (folder / "report.md").write_text("synthetic complete caption archive", encoding="utf-8")
        (folder / "manifest.json").write_text(json.dumps({"video_id": video, "status": "archived", "files": ["report.md", "manifest.json"]}), encoding="utf-8")

    def checkpoint(self, *, state="blocked_interrupted", circuit_open=True):
        items = {}
        for index, video in enumerate(VIDEO_IDS):
            archived = index < 3
            if archived:
                self.write_archive(video)
            items[video] = {
                "video_id": video, "url": f"https://www.youtube.com/watch?v={video}",
                "state": "archived" if archived else "blocked_interrupted" if index == 3 else "pending",
                "attempts": 1 if index <= 3 else 0,
                "failure_class": None if index != 3 else "worker_session_interrupted",
                "error": None if index != 3 else "synthetic previous interruption",
                "completed_at": "synthetic-completion" if archived else None,
            }
        record = {
            "schema": "franck.youtube-catalog-chunk-worker.v1", "state": state,
            "lease_id": LEASE, "cookies_used": False, "media_downloaded": False,
            "circuit_open": circuit_open, "items": items,
            "urls_sha256": hashlib.sha256(self.urls.read_bytes()).hexdigest(),
        }
        self.save(record)
        return record

    def save(self, record):
        self.status.write_text(json.dumps(record), encoding="utf-8")

    def invoke(self):
        if self.args.resume_blocked and self.status.is_file():
            self.args.checkpoint_sha256 = hashlib.sha256(self.status.read_bytes()).hexdigest()
        with contextlib.redirect_stdout(io.StringIO()):
            return worker.run_worker(self.args)

    def archive_snapshot(self):
        return {path: path.read_bytes() for path in self.archive.rglob("*") if path.is_file()}

    def successful_launches(self):
        launched = []

        def launch(command):
            video = command[2].rsplit("=", 1)[1]
            launched.append(video)
            self.write_archive(video)
            process = Mock(returncode=0)
            process.communicate.return_value = ("", "")
            return process

        self.spawn.side_effect = launch
        return launched

    def preflight_result(self, code=0, stdout=VERSIONS, stderr=""):
        self.run.side_effect = None
        self.run.return_value = subprocess.CompletedProcess(["synthetic-wrapper.cmd"], code, stdout, stderr)

    def test_windows_launch_assigns_job_before_releasing_private_fence(self):
        process = Mock(returncode=None)
        job = Mock()
        order = Mock()
        order.attach_mock(job.assign, "assign")
        order.attach_mock(process.stdin.write, "release")
        # Call the real factory; the ordinary fixture mock protects all other tests.
        factory = self.original_archive_factory
        with patch.object(worker.os, "name", "nt"), patch.object(worker, "WindowsArchiveJob", return_value=job), patch.object(worker.subprocess, "Popen", return_value=process) as popen:
            self.assertIs(factory(["fixture-python", "fixture-archiver.py", "fixture-url"]), process)
        self.assertEqual([call[0] for call in order.mock_calls], ["assign", "release"])
        self.assertEqual(popen.call_args.args[0][1:3], ["-c", worker.WINDOWS_ARCHIVE_BOOTSTRAP])
        self.assertIs(process._archive_job, job)
        self.assertIsNone(process.stdin)

    def test_windows_job_assignment_failure_never_releases_archiver(self):
        process = Mock(); process.communicate.return_value = ("", "")
        stdin = process.stdin
        job = Mock(); job.assign.side_effect = OSError("synthetic assignment refused")
        with patch.object(worker.os, "name", "nt"), patch.object(worker, "WindowsArchiveJob", return_value=job), patch.object(worker.subprocess, "Popen", return_value=process):
            with self.assertRaisesRegex(OSError, "assignment refused"):
                self.original_archive_factory(["fixture-python", "fixture-archiver.py"])
        stdin.write.assert_not_called()
        process.kill.assert_called_once()
        process.communicate.assert_called_once_with(timeout=5)
        job.close.assert_called_once()

    def test_unconfirmed_timeout_cleanup_blocks_without_retry_or_source_probe(self):
        self.checkpoint()
        process = Mock(returncode=None)
        process.communicate.side_effect = [subprocess.TimeoutExpired("fixture", value) for value in (1200,20,5)]
        self.spawn.side_effect = None; self.spawn.return_value = process
        with patch.object(worker, "terminate_archive_process") as terminate, patch.object(worker, "close_archive_process") as close:
            self.assertEqual(self.invoke(), 4)
        self.assertEqual([call.kwargs["timeout"] for call in process.communicate.call_args_list], [1200,20,5])
        self.assertEqual(terminate.call_count, 2)
        close.assert_called_once_with(process)
        self.spawn.assert_called_once()
        status = json.loads(self.status.read_text())
        self.assertEqual(status["state"], "blocked_configuration")
        self.assertIn("cleanup could not be confirmed", status["items"][VIDEO_IDS[3]]["error"])
        self.assertTrue(all(status["items"][video]["attempts"] == 0 for video in VIDEO_IDS[4:]))
        self.run.assert_not_called()

    def test_timeout_captured_bytes_are_preserved_and_cleanup_is_bounded(self):
        process = Mock(returncode=1)
        process.communicate.side_effect = [subprocess.TimeoutExpired("fixture",1200,output=b"partial output",stderr=b"root diagnostic"), (None,None)]
        with patch.object(worker, "terminate_archive_process"), patch.object(worker, "close_archive_process") as close:
            stdout, stderr, code = worker.communicate_archive_process(process)
        self.assertEqual(stdout, "partial output")
        self.assertIn("root diagnostic", stderr)
        self.assertIsNone(code)
        close.assert_called_once_with(process)

    def test_guarded_probe_timeout_reports_only_after_process_tree_cleanup(self):
        process = Mock(returncode=1)
        process.communicate.side_effect = [subprocess.TimeoutExpired("fixture",45,stderr=b"primary error"), ("", "primary error")]
        self.spawn.side_effect = None; self.spawn.return_value = process
        with patch.object(worker, "terminate_archive_process") as terminate, patch.object(worker, "close_archive_process") as close:
            with self.assertRaises(subprocess.TimeoutExpired) as error:
                self.original_guarded_runner(["fixture-wrapper.cmd", "fixture-probe"], timeout=45)
        self.assertIn("primary error", error.exception.stderr)
        self.assertEqual([call.kwargs["timeout"] for call in process.communicate.call_args_list], [45,20])
        terminate.assert_called_once_with(process)
        close.assert_called_once_with(process)

    def test_preflight_containment_failure_stops_before_spending_an_attempt(self):
        original = self.checkpoint()
        self.args.wrapper_preflight = True
        self.run.side_effect = worker.ArchiveProcessCleanupError("synthetic unconfirmed descendant cleanup")
        self.assertEqual(self.invoke(), 4)
        status = json.loads(self.status.read_text())
        self.assertEqual(status["state"], "blocked_configuration")
        self.assertEqual(status["items"], original["items"])
        self.spawn.assert_not_called()

    def test_probe_circuit_stops_retry_and_next_item(self):
        for primary, state in [("ERROR: Sign in to confirm you're not a bot", "blocked_bot_check"), ("ERROR: HTTP Error 429", "waiting_network_cooldown"), ("ERROR: authentication required", "blocked_auth_required")]:
            with self.subTest(state=state):
                self.checkpoint()
                process = Mock(returncode=1); process.communicate.return_value = ("", "ERROR: caption extraction failed")
                self.spawn.reset_mock(); self.spawn.side_effect = None; self.spawn.return_value = process
                self.run.side_effect = None; self.run.return_value = subprocess.CompletedProcess(["fixture"],1,"",primary)
                self.assertEqual(self.invoke(), 4)
                status = json.loads(self.status.read_text())
                self.assertEqual(status["state"], state)
                self.assertTrue(status["circuit_open"])
                self.assertIn(primary, status["items"][VIDEO_IDS[3]]["error"])
                self.assertTrue(all(status["items"][video]["attempts"] == 0 for video in VIDEO_IDS[4:]))
                self.spawn.assert_called_once()

    def test_normal_windows_scope_close_waits_for_all_descendants(self):
        process = Mock()
        job = Mock(); process._archive_job = job
        worker.close_archive_process(process)
        self.assertEqual([call[0] for call in job.mock_calls], ["terminate", "wait_empty", "close"])

    def assert_refused_without_mutation(self):
        before_status, before_pid = self.status.read_bytes(), self.pid.read_bytes()
        self.assertEqual(self.invoke(), 9)
        self.assertEqual(self.status.read_bytes(), before_status)
        self.assertEqual(self.pid.read_bytes(), before_pid)
        self.spawn.assert_not_called()
        self.run.assert_not_called()

    def test_same_lease_resume_reuses_archives_and_keeps_attempt_history(self):
        original = self.checkpoint()
        archives = self.archive_snapshot()
        launched = self.successful_launches()
        self.assertEqual(self.invoke(), 0)
        self.assertEqual(launched, VIDEO_IDS[3:])
        status = json.loads(self.status.read_text())
        self.assertEqual(status["state"], "complete")
        self.assertEqual(status["lease_id"], LEASE)
        self.assertEqual(status["items"][VIDEO_IDS[3]]["attempts"], 2)
        for video in VIDEO_IDS[:3]:
            self.assertEqual(status["items"][video], original["items"][video])
        for video in VIDEO_IDS[4:]:
            self.assertEqual(status["items"][video]["attempts"], 1)
        for path, content in archives.items():
            self.assertEqual(path.read_bytes(), content)
        self.args.wrapper_preflight = True
        self.assertEqual(self.invoke(), 0)
        self.assertEqual(launched, VIDEO_IDS[3:])
        self.run.assert_not_called()

    def test_published_initial_checkpoint_recovers_without_spending_prior_attempts(self):
        record = {"schema": "franck.youtube-catalog-chunk-worker.v1", "state": "running", "stage_checkpoint": True,
                  "lease_id": LEASE, "cookies_used": False, "media_downloaded": False, "circuit_open": False,
                  "urls_sha256": hashlib.sha256(self.urls.read_bytes()).hexdigest(),
                  "items": {video: {"video_id": video, "url": f"https://www.youtube.com/watch?v={video}",
                                    "state": "pending", "attempts": 0} for video in VIDEO_IDS}}
        self.save(record)
        launched = self.successful_launches()
        self.assertEqual(self.invoke(), 0)
        self.assertEqual(launched, VIDEO_IDS)
        self.assertTrue(all(row["attempts"] == 1 for row in json.loads(self.status.read_text())["items"].values()))

    def test_completed_archive_before_checkpoint_is_adopted_without_replay(self):
        record = self.checkpoint(state="running", circuit_open=False)
        record["items"][VIDEO_IDS[3]]["state"] = "running"
        self.save(record)
        self.write_archive(VIDEO_IDS[3])
        archives = self.archive_snapshot()
        launched = self.successful_launches()
        self.assertEqual(self.invoke(), 0)
        self.assertEqual(launched, VIDEO_IDS[4:])
        self.assertEqual(json.loads(self.status.read_text())["items"][VIDEO_IDS[3]]["attempts"], 1)
        for path, content in archives.items():
            self.assertEqual(path.read_bytes(), content)

    def test_terminal_skip_and_exhausted_attempt_are_not_replayed(self):
        record = self.checkpoint()
        record["items"][VIDEO_IDS[3]].update(state="skipped_private", failure_class="private_video")
        record["items"][VIDEO_IDS[4]].update(state="blocked_error", attempts=3, error="synthetic exhausted attempt")
        self.save(record)
        launched = self.successful_launches()
        self.assertEqual(self.invoke(), 6)
        self.assertEqual(launched, VIDEO_IDS[5:])
        status = json.loads(self.status.read_text())
        for video in VIDEO_IDS[3:5]:
            self.assertEqual(status["items"][video], record["items"][video])

    def test_damaged_completed_archive_refuses_without_pid_or_status_mutation(self):
        self.checkpoint()
        (self.archive / VIDEO_IDS[0] / "report.md").unlink()
        self.assert_refused_without_mutation()

    def test_blocked_resume_requires_explicit_authority_and_same_nonempty_lease(self):
        for kind in ("no_resume", "wrong_lease", "missing_requested_lease", "missing_prior_lease", "item_only_circuit"):
            with self.subTest(kind=kind):
                record = self.checkpoint()
                self.args.lease_id, self.args.resume_blocked = LEASE, True
                if kind == "no_resume":
                    self.args.resume_blocked = False
                elif kind == "wrong_lease":
                    self.args.lease_id = "synthetic-other-lease"
                elif kind == "missing_requested_lease":
                    self.args.lease_id = None
                elif kind == "missing_prior_lease":
                    record["lease_id"] = None
                    self.args.lease_id = None
                else:
                    record.update(state="running", circuit_open=False)
                    self.args.resume_blocked = False
                self.save(record)
                self.assert_refused_without_mutation()

    def test_invalid_checkpoint_binding_and_budget_fail_closed(self):
        kinds = ("json", "schema", "top_state", "unhashable_state", "circuit", "cookies", "media", "empty_items", "item_set", "identity", "url", "url_hash", "item_state", "item_record", "negative", "over_budget", "boolean", "string", "fraction", "exit_code")
        for kind in kinds:
            with self.subTest(kind=kind):
                record = self.checkpoint()
                item = record["items"][VIDEO_IDS[3]]
                if kind == "schema": record["schema"] = "synthetic-other-schema"
                elif kind == "top_state": record["state"] = "unknown"
                elif kind == "unhashable_state": record["state"] = []
                elif kind == "circuit": record["circuit_open"] = "true"
                elif kind == "cookies": record["cookies_used"] = True
                elif kind == "media": record["media_downloaded"] = True
                elif kind == "empty_items": record["items"] = {}
                elif kind == "item_set": del record["items"][VIDEO_IDS[-1]]
                elif kind == "identity": item["video_id"] = VIDEO_IDS[4]
                elif kind == "url": item["url"] = "https://example.invalid/synthetic"
                elif kind == "url_hash": record["urls_sha256"] = "0" * 64
                elif kind == "item_state": item["state"] = {}
                elif kind == "item_record": record["items"][VIDEO_IDS[3]] = []
                elif kind == "negative": item["attempts"] = -1
                elif kind == "over_budget": item["attempts"] = 4
                elif kind == "boolean": item["attempts"] = True
                elif kind == "string": item["attempts"] = "1"
                elif kind == "fraction": item["attempts"] = 1.5
                elif kind == "exit_code": item["process_exit_code"] = "synthetic invalid code"
                self.save(record)
                if kind == "json": self.status.write_text("{synthetic invalid JSON", encoding="utf-8")
                self.assert_refused_without_mutation()

    def test_checkpoint_is_revalidated_after_lock_acquisition(self):
        real_acquire = worker.acquire_worker_lock
        for kind in ("lease", "attempts", "circuit"):
            with self.subTest(kind=kind):
                record = self.checkpoint(state="running", circuit_open=False)
                record["items"][VIDEO_IDS[3]]["state"] = "pending"
                self.save(record)
                self.args.resume_blocked = False
                observed = {}

                def acquire(base, **options):
                    self.assertEqual(options, {"persist_pid": False})
                    handle = real_acquire(base, **options)
                    self.assertIsNotNone(handle)
                    changed = json.loads(self.status.read_text())
                    if kind == "lease": changed["lease_id"] = "synthetic-changed-lease"
                    elif kind == "attempts": changed["items"][VIDEO_IDS[3]]["attempts"] = -1
                    else: changed.update(state="blocked_interrupted", circuit_open=True)
                    self.save(changed)
                    observed["status"] = self.status.read_bytes()
                    return handle

                before_pid = self.pid.read_bytes()
                with patch.object(worker, "acquire_worker_lock", side_effect=acquire):
                    self.assertEqual(self.invoke(), 9)
                self.assertEqual(self.status.read_bytes(), observed["status"])
                self.assertEqual(self.pid.read_bytes(), before_pid)
                self.spawn.assert_not_called()
                self.run.assert_not_called()

    def test_authorized_checkpoint_replacement_under_lock_requires_fresh_proof(self):
        self.checkpoint()
        real_acquire = worker.acquire_worker_lock

        def acquire(base, **options):
            handle = real_acquire(base, **options)
            record = json.loads(self.status.read_text())
            record["items"][VIDEO_IDS[3]]["attempts"] = 2
            self.save(record)
            return handle

        launched = self.successful_launches()
        with patch.object(worker, "acquire_worker_lock", side_effect=acquire):
            self.assertEqual(self.invoke(), 9)
        self.assertEqual(launched, [])
        self.assertEqual(json.loads(self.status.read_text())["items"][VIDEO_IDS[3]]["attempts"], 2)

    def test_lock_contention_preserves_pid_checkpoint_and_archives(self):
        self.checkpoint()
        before_status, before_pid = self.status.read_bytes(), self.pid.read_bytes()
        archives = self.archive_snapshot()
        handle = worker.acquire_worker_lock(self.base, persist_pid=False)
        self.assertIsNotNone(handle)
        try:
            self.assertEqual(self.invoke(), 7)
        finally:
            handle.close()
        self.assertEqual(self.status.read_bytes(), before_status)
        self.assertEqual(self.pid.read_bytes(), before_pid)
        self.assertEqual(self.archive_snapshot(), archives)
        self.spawn.assert_not_called()
        self.run.assert_not_called()

    def test_wrapper_preflight_is_offline_once_and_confirms_pinned_versions(self):
        self.checkpoint()
        self.args.wrapper_preflight = True
        self.preflight_result()
        launched = self.successful_launches()
        self.assertEqual(self.invoke(), 0)
        self.assertEqual(launched, VIDEO_IDS[3:])
        self.run.assert_called_once_with(["synthetic-wrapper.cmd", "--worker-preflight"], timeout=15)
        events = (self.base / "events.jsonl").read_text()
        self.assertIn("node v24.18.0; yt-dlp 2026.08.19", events)
        self.assertEqual(self.invoke(), 0)
        self.assertEqual(self.run.call_count, 1)

    def test_invalid_preflight_success_receipts_preserve_attempt_and_archive_state(self):
        outputs = ("", "2026.08.19\n", "node v20.0.0\n2026.08.19\n", "node v24.18.0\n", "node v24.18.0\n2026.08.20\n", VERSIONS + "node v22.0.0\n", VERSIONS + "2026.08.20\n")
        self.args.wrapper_preflight = True
        for output in outputs:
            with self.subTest(output=output):
                record = self.checkpoint()
                record["items"][VIDEO_IDS[3]]["process_exit_code"] = 1
                self.save(record)
                archives = self.archive_snapshot()
                self.preflight_result(stdout=output)
                self.assertEqual(self.invoke(), 4)
                status = json.loads(self.status.read_text())
                self.assertEqual(status["state"], "blocked_configuration")
                self.assertEqual(status["items"], record["items"])
                self.assertEqual(self.archive_snapshot(), archives)
                self.spawn.assert_not_called()

    def test_preflight_shutdown_has_priority_without_spending_attempts(self):
        self.args.wrapper_preflight = True
        cases = ((3221226091, WARNING), (-1073741205, ""), (1, "ERROR: 0xC000026B\n" + "noise " * 15000), (0, "Windows window station is shutting down"))
        for code, detail in cases:
            with self.subTest(code=code):
                record = self.checkpoint()
                self.preflight_result(code=code, stdout=VERSIONS, stderr=detail)
                self.assertEqual(self.invoke(), 4)
                status = json.loads(self.status.read_text())
                self.assertEqual(status["state"], "blocked_interrupted")
                self.assertEqual(status["circuit_reason"], "worker_session_interrupted")
                self.assertEqual(status["items"], record["items"])
                self.assertIn("0xC000026B", status["preflight_error"])
                self.assertLessEqual(len(status["preflight_error"]), 2000)
                self.spawn.assert_not_called()

    def test_unavailable_or_timed_out_preflight_spends_no_attempt(self):
        self.args.wrapper_preflight = True
        for exception in (FileNotFoundError("synthetic unavailable wrapper"), subprocess.TimeoutExpired(["synthetic-wrapper.cmd"], 15)):
            with self.subTest(exception=type(exception).__name__):
                record = self.checkpoint()
                self.run.side_effect = exception
                self.assertEqual(self.invoke(), 4)
                status = json.loads(self.status.read_text())
                self.assertEqual(status["state"], "blocked_configuration")
                self.assertEqual(status["items"], record["items"])
                self.spawn.assert_not_called()

    def test_no_preflight_or_launch_when_all_items_are_terminal_or_exhausted(self):
        record = self.checkpoint()
        record["items"][VIDEO_IDS[3]]["state"] = "skipped_private"
        for video in VIDEO_IDS[4:]:
            record["items"][video].update(state="blocked_error", attempts=3)
        self.save(record)
        self.args.wrapper_preflight = True
        self.assertEqual(self.invoke(), 6)
        self.assertEqual(json.loads(self.status.read_text())["items"], record["items"])
        self.run.assert_not_called()
        self.spawn.assert_not_called()

    def test_preflight_timeout_preserves_captured_shutdown_diagnostic(self):
        record = self.checkpoint()
        self.args.wrapper_preflight = True
        self.run.side_effect = subprocess.TimeoutExpired(["synthetic-wrapper.cmd"], 15, output=b"", stderr=b"ERROR: 0xC000026B\n" + b"noise " * 15000)
        self.assertEqual(self.invoke(), 4)
        status = json.loads(self.status.read_text())
        self.assertEqual(status["state"], "blocked_interrupted")
        self.assertEqual(status["items"], record["items"])
        self.assertIn("0xC000026B", status["preflight_error"])
        self.assertLessEqual(len(status["preflight_error"]), 2000)
        self.spawn.assert_not_called()

    def test_child_shutdown_stops_before_probe_retry_and_next_item_and_redacts_logs(self):
        record = self.checkpoint()
        stdout = "https://example.invalid/caption?sig=synthetic-query-secret\nCookie: session=synthetic-cookie-secret\neyJmaXh0dXJl.c3ludGhldGlj.c2lnbmF0dXJl\n"
        stderr = WARNING + "\nERROR: 0xC000026B\n--password synthetic-cli-secret\n" + "noise " * 15000
        process = Mock(returncode=1)
        process.communicate.return_value = (stdout, stderr)
        self.spawn.side_effect = None
        self.spawn.return_value = process
        with patch.object(worker, "source_diagnostic", side_effect=AssertionError("unexpected source probe")):
            self.assertEqual(self.invoke(), 4)
        self.spawn.assert_called_once()
        self.sleep.assert_not_called()
        status = json.loads(self.status.read_text())
        self.assertEqual(status["state"], "blocked_interrupted")
        item = status["items"][VIDEO_IDS[3]]
        self.assertEqual(item["attempts"], 2)
        self.assertEqual(item["process_exit_code"], 1)
        self.assertIn("0xC000026B", item["error"])
        self.assertLessEqual(len(item["error"]), 2000)
        for video in VIDEO_IDS[4:]:
            self.assertEqual(status["items"][video], record["items"][video])
        for path in (self.status, self.base / "events.jsonl", *self.base.glob("logs/*")):
            content = path.read_text()
            for secret in ("synthetic-query-secret", "synthetic-cookie-secret", "synthetic-cli-secret", "eyJmaXh0dXJl.c3ludGhldGlj.c2lnbmF0dXJl"):
                self.assertNotIn(secret, content)
        for path in self.base.glob("logs/*"):
            self.assertLessEqual(len(path.read_text()), 65536)

    def test_probe_shutdown_stops_without_retry_or_advancing(self):
        for code, detail in ((3221226091, "ERROR: private video"), (-1073741205, ""), (1, "ERROR: 0xC000026B\n" + "noise " * 15000)):
            with self.subTest(code=code):
                self.checkpoint()
                process = Mock(returncode=1)
                process.communicate.return_value = ("", WARNING + "\nERROR: subtitle unavailable")
                self.spawn.side_effect = None
                self.spawn.return_value = process
                self.preflight_result(code=code, stdout="", stderr=detail)
                before_calls = self.spawn.call_count
                self.assertEqual(self.invoke(), 4)
                self.assertEqual(self.spawn.call_count, before_calls + 1)
                status = json.loads(self.status.read_text())
                self.assertEqual(status["state"], "blocked_interrupted")
                self.assertIn("0xC000026B", status["items"][VIDEO_IDS[3]]["error"])
                self.assertEqual(status["items"][VIDEO_IDS[3]]["attempts"], 2)
                self.assertTrue(all(status["items"][video]["attempts"] == 0 for video in VIDEO_IDS[4:]))
                self.sleep.assert_not_called()

    def test_paired_adapter_flags_remain_accepted_by_cli(self):
        arguments = ["synthetic-worker", "--base", str(self.base), "--urls", str(self.urls), "--archive-root", str(self.archive), "--python", "synthetic-python", "--archiver", "synthetic-archiver.py", "--yt-dlp", "synthetic-wrapper.cmd", "--lease-id", LEASE, "--resume-blocked", "--wrapper-preflight"]
        with patch.object(sys, "argv", arguments), patch.object(worker, "run_worker", return_value=0) as invoke:
            self.assertEqual(worker.main(), 0)
        options = invoke.call_args.args[0]
        self.assertTrue(options.resume_blocked)
        self.assertTrue(options.wrapper_preflight)
        self.assertEqual(options.lease_id, LEASE)


class DiagnosticTests(unittest.TestCase):
    def test_probe_fatal_circuits_keep_their_primary_classification(self):
        for detail, expected in [("ERROR: Sign in to confirm you're not a bot", "bot_check"), ("ERROR: HTTP Error 429", "rate_limited"), ("ERROR: authentication required", "auth_required")]:
            result = subprocess.CompletedProcess(["fixture"], 1, "", detail)
            with patch.object(worker, "run_guarded_command", return_value=result):
                actual, primary = worker.source_diagnostic("https://www.youtube.com/watch?v=fixture0001", "fixture-wrapper.cmd")
            self.assertEqual(actual, expected)
            self.assertIn(detail, primary)

    def test_probe_timeout_preserves_primary_shutdown_evidence(self):
        error = subprocess.TimeoutExpired("fixture",45,stderr=b"ERROR: 0xC000026B")
        with patch.object(worker, "run_guarded_command", side_effect=error):
            actual, primary = worker.source_diagnostic("https://www.youtube.com/watch?v=fixture0001", "fixture-wrapper.cmd")
        self.assertEqual(actual, "worker_session_interrupted")
        self.assertIn("0xC000026B", primary)

    def test_probe_redacts_complete_fields_before_bounding(self):
        secret = "synthetic-cookie-secret" * 200
        result = subprocess.CompletedProcess(["synthetic-wrapper.cmd"], 1, "", "ERROR: private video\nCookie: " + secret)
        with patch.object(worker, "run_guarded_command", return_value=result):
            failure_class, detail = worker.source_diagnostic("https://www.youtube.com/watch?v=fixture0001", "synthetic-wrapper.cmd")
        self.assertEqual(failure_class, "private_video")
        self.assertNotIn("synthetic-cookie-secret", detail)
        self.assertLessEqual(len(detail), 2000)

    def test_runtime_warning_does_not_become_fatal_configuration(self):
        self.assertEqual(worker.classify(WARNING), "error")
        self.assertEqual(worker.classify(WARNING + "\nERROR: subtitle request failed"), "error")
        self.assertEqual(worker.classify(WARNING + "\nERROR: HTTP Error 429"), "rate_limited")
        self.assertEqual(worker.classify("ERROR: JavaScript runtime unavailable"), "configuration")
        for code in (3221226091, -1073741205):
            self.assertEqual(worker.classify(WARNING, code), "worker_session_interrupted")

    def test_redaction_precedes_bounding_and_preserves_shutdown_prefix(self):
        secrets = ("synthetic-header-secret", "synthetic-cookie-secret", "synthetic-cli-secret", "synthetic-json-secret", "synthetic-url-secret", "synthetic-query-secret", "synthetic-fragment-secret")
        jwt = "eyJmaXh0dXJl.c3ludGhldGlj.c2lnbmF0dXJl"
        # Build the reserved-host dummy URI from fixture parts, never a usable credential.
        dummy_uri = urlunsplit((
            "https", "{}:{}@{}".format("fixture", "synthetic-url-secret", "example.invalid"),
            "/caption", "sig=synthetic-query-secret", "synthetic-fragment-secret",
        ))
        detail = "ERROR: 0xC000026B\n" + "noise " * 15000 + (
            '\nAuthorization: Bearer synthetic-header-secret\nSet-Cookie: session=synthetic-cookie-secret\n'
            '--password synthetic-cli-secret\n{"token":"synthetic-json-secret"}\n'
        ) + dummy_uri + "\n" + jwt
        sanitized = worker.sanitized_error_detail(detail)
        self.assertTrue(sanitized.startswith("worker_session_interrupted (0xC000026B): "))
        self.assertLessEqual(len(sanitized), 2000)
        for secret in (*secrets, jwt):
            self.assertNotIn(secret, sanitized)


if __name__ == "__main__":
    unittest.main()
