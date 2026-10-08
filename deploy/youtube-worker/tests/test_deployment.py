"""Managed deployment proof gates, active-lease fences and rollback preimages."""
import importlib.util
from pathlib import Path
import tempfile
import os
import copy
import datetime as dt
import json
import shutil
import subprocess
import sys
import time
import unittest
from unittest.mock import patch
import test_coordinator_recovery as fixtures

SOURCE = Path(__file__).resolve().parents[1] / "deployment.py"
spec = importlib.util.spec_from_file_location("fixture_windows_deployment", SOURCE)
deploy = importlib.util.module_from_spec(spec); spec.loader.exec_module(deploy)


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name) / "workspace"; self.workspace.mkdir()
        self.data = Path(self.temp.name) / "data"; self.data.mkdir()
        self.config = fixtures.copy.deepcopy(fixtures.CONFIG)
        self.config["assets"]["wrapper_sha256"] = deploy.digest((deploy.BUNDLE / "windows/yt-dlp-anonymous.cmd").read_bytes())
        self.release = {"schema": "openclaw.youtube.windows-release.v1", "repository": deploy.REPOSITORY, "compatibility": deploy.COMPATIBILITY, "revision": self.config["assets"]["fork_revision"], "files": {key: deploy.digest(raw) for key, raw in deploy.source_files().items()}, "archiver": {"repository": "fr-meyer/agent-toolkit", "revision": self.config["assets"]["archiver_revision"], "path": "skills/youtube-transcript-archive/scripts/archive_youtube_transcript.py", "sha256": self.config["assets"]["archiver_sha256"]}, "wrapper_sha256": self.config["assets"]["wrapper_sha256"]}
        self.marker = self.data / "state/automation/global/gates/windows-worker-cutover.json"
        deploy.atomic(self.marker, deploy.json_bytes({"enabled": True, "node_id": self.config["node"]["id"], "scheduler_job_id": "synthetic-existing-scheduler", "cookies_allowed": False, "media_allowed": False}))
        self.identity = deploy.release_identity(self.release, deploy.source_files())
        self.proofs = {"revision": self.release["revision"], "release_sha256": self.identity, **{key: {"state": "passed", "evidence_sha256": "c" * 64} for key in ("autoreview", "offline_tests", "native_windows")}}
        self.proofs["windows_installation"] = {"assets": self.config["assets"], "worker_alive": False, "worker_lock_free": True, "adapter_sha256": self.release["files"]["scripts/youtube_global_windows_adapter.ps1"], "archiver_sha256": self.release["archiver"]["sha256"], "wrapper_sha256": self.release["wrapper_sha256"]}
        self.proposed = deploy.targets(self.workspace, self.data, self.release, self.config, deploy.source_files())
        self.expected = {str(path): deploy.digest(path.read_bytes()) if path.is_file() else None for path in self.proposed}
        self.journal = Path(self.temp.name) / "transaction.json"
        p = patch.object(deploy, "verify_source_revision")
        self.verify_revision = p.start(); self.addCleanup(p.stop)

    def activate(self, **options):
        return deploy.activate(self.workspace, self.data, self.release, self.config, self.proofs, self.expected, self.journal, **options)

    def test_exact_proof_activation_and_byte_identical_rollback(self):
        before = self.marker.read_bytes()
        self.assertEqual(self.activate()["state"], "committed")
        self.assertEqual(deploy.read(self.marker)["scheduler_job_id"], "synthetic-existing-scheduler")
        self.assertEqual(deploy.rollback(self.journal)["state"], "rolled_back")
        self.assertEqual(self.marker.read_bytes(), before)
        self.assertFalse((self.data / "state/config/windows-worker.json").exists())
        self.assertTrue(all(not path.exists() for path in self.proposed if path.is_relative_to(self.workspace)))

    def test_incomplete_review_or_native_proof_prevents_all_writes(self):
        self.proofs["autoreview"]["state"] = "unavailable"
        with self.assertRaises(deploy.DeploymentError): self.activate()
        self.assertFalse(self.journal.exists())

    def test_nonexecutable_existing_helper_refuses_before_boundary_or_windows_handoff(self):
        helper = self.workspace / "scripts/youtube_worker/openclaw-node-run"
        helper.parent.mkdir(parents=True)
        helper.write_bytes(b"synthetic existing helper")
        helper.chmod(0o644)
        before = helper.read_bytes(), helper.stat().st_mode, self.marker.read_bytes()
        with self.assertRaisesRegex(deploy.DeploymentError, "not executable"):
            deploy.targets(self.workspace, self.data, self.release, self.config, deploy.source_files())
        with patch.object(deploy, "boundary_locks", side_effect=AssertionError("boundary must remain untouched")), patch.object(deploy, "read_windows_receipt", side_effect=AssertionError("Windows handoff must remain untouched")):
            with self.assertRaisesRegex(deploy.DeploymentError, "not executable"):
                self.activate(await_windows=True)
        self.assertEqual(before, (helper.read_bytes(), helper.stat().st_mode, self.marker.read_bytes()))
        self.assertFalse(self.journal.exists())

    def test_existing_executable_helper_mode_is_preserved_through_activation_and_rollback(self):
        helper = self.workspace / "scripts/youtube_worker/openclaw-node-run"
        helper.parent.mkdir(parents=True)
        helper.write_bytes(b"synthetic existing helper")
        helper.chmod(0o750)
        original = helper.read_bytes()
        self.expected[str(helper)] = deploy.digest(original)
        self.assertEqual(self.activate()["state"], "committed")
        self.assertEqual(helper.stat().st_mode & 0o777, 0o750)
        self.assertEqual(deploy.rollback(self.journal)["state"], "rolled_back")
        self.assertEqual(helper.read_bytes(), original)
        self.assertEqual(helper.stat().st_mode & 0o777, 0o750)

    def test_active_same_node_lease_is_not_ttl_expired(self):
        lease = self.data / "state/automation/global/leases/fixture.json"
        deploy.atomic(lease, deploy.json_bytes({"state": "active", "node": {"id": self.config["node"]["id"]}, "expires_at": "2001-01-01T00:00:00Z"}))
        with self.assertRaises(deploy.DeploymentError): self.activate()
        self.assertFalse(self.journal.exists())

    def test_mismatched_windows_install_receipt_prevents_all_writes(self):
        self.proofs["windows_installation"]["adapter_sha256"] = "0" * 64
        with self.assertRaises(deploy.DeploymentError): self.activate()
        self.assertFalse(self.journal.exists())

    def test_malformed_same_node_configuration_prevents_all_writes(self):
        self.config.pop("remote")
        with self.assertRaises(deploy.DeploymentError): self.activate()
        self.assertFalse(self.journal.exists())
        self.assertFalse((self.data / "state/config/windows-worker.json").exists())

    def test_partial_windows_receipt_times_out_and_releases_boundary_locks(self):
        reader, writer = os.pipe()
        self.addCleanup(os.close, writer)
        stream = os.fdopen(reader, "rb", buffering=0); self.addCleanup(stream.close)
        os.write(writer, b'{"assets":')
        read = deploy.read_windows_receipt
        start = time.monotonic()
        with patch.object(deploy.sys, "stdin", stream), patch.object(deploy, "read_windows_receipt", side_effect=lambda source: read(source, timeout_seconds=0.03)):
            with self.assertRaisesRegex(deploy.DeploymentError, "deadline reached"): self.activate(await_windows=True)
        self.assertLess(time.monotonic() - start, 0.5)
        with deploy.boundary_locks(self.data): pass
        self.assertFalse(self.journal.exists())

    def test_preimage_drift_blocks_source_replacement(self):
        deploy.atomic(self.marker, deploy.json_bytes({"enabled": True, "node_id": self.config["node"]["id"], "scheduler_job_id": "changed"}))
        with self.assertRaises(deploy.DeploymentError): self.activate()
        self.assertFalse(self.journal.exists())

    def test_concurrent_coordinator_blocks_activation(self):
        with deploy.boundary_locks(self.data):
            with self.assertRaises(deploy.DeploymentError): self.activate()
        self.assertFalse(self.journal.exists())

    def test_rollback_preserves_unexpected_later_drift(self):
        self.activate()
        path = self.workspace / "scripts/youtube_global_chunk_worker.py"
        path.write_text("synthetic subsequent drift")
        with self.assertRaises(deploy.DeploymentError): deploy.rollback(self.journal)
        self.assertEqual(path.read_text(), "synthetic subsequent drift")

    def test_interrupted_atomic_replace_can_rollback_with_orphan_evidence(self):
        target = self.workspace / next(iter(deploy.source_files()))
        replace = deploy.os.replace
        def interrupted(source, destination):
            if destination == target: raise OSError("synthetic crash before source replace")
            return replace(source, destination)
        with patch.object(deploy.os, "replace", interrupted):
            with self.assertRaises(OSError): self.activate()
        orphans = list(target.parent.glob(target.name + ".deployment-tmp-*"))
        self.assertEqual(len(orphans), 1)
        self.assertEqual(deploy.rollback(self.journal)["state"], "rolled_back")
        self.assertTrue(orphans[0].is_file())

    def test_source_identity_drift_is_rejected(self):
        self.release["files"]["scripts/youtube_global_chunk_worker.py"] = "0" * 64
        with self.assertRaises(deploy.DeploymentError): self.activate()
        self.assertFalse(self.journal.exists())

    def test_symlink_destination_is_rejected(self):
        (self.workspace / "scripts").symlink_to(self.data, target_is_directory=True)
        with self.assertRaises(deploy.DeploymentError): deploy.targets(self.workspace, self.data, self.release, self.config, deploy.source_files())


    def test_tracked_revision_refusal_precedes_all_transaction_writes(self):
        before = self.marker.read_bytes()
        self.verify_revision.side_effect = deploy.DeploymentError("synthetic tracked-tree drift")
        with patch.object(deploy, "boundary_locks", side_effect=AssertionError("boundary must remain untouched")):
            with self.assertRaises(deploy.DeploymentError): self.activate()
        self.assertFalse(self.journal.exists())
        self.assertEqual(self.marker.read_bytes(), before)
        self.assertEqual(list(self.workspace.iterdir()), [])
        self.assertFalse((self.data / "state/config/windows-worker.json").exists())

    def test_each_state_target_symlink_is_refused_before_marker_read(self):
        outside = Path(self.temp.name) / "synthetic-outside.json"
        outside.write_bytes(b"synthetic unrelated state")
        for relative in ("state/config/windows-worker.json", "state/automation/global/gates/windows-worker-cutover.json", "state/config/windows-deployment.json"):
            with self.subTest(relative=relative):
                target = self.data / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                before = target.read_bytes() if target.is_file() else None
                target.unlink(missing_ok=True)
                target.symlink_to(outside)
                try:
                    with patch.object(deploy, "read", side_effect=AssertionError("redirected state must not be read")):
                        with self.assertRaises(deploy.DeploymentError):
                            deploy.targets(self.workspace, self.data, self.release, self.config, deploy.source_files())
                    self.assertEqual(outside.read_bytes(), b"synthetic unrelated state")
                    self.assertFalse(self.journal.exists())
                finally:
                    target.unlink()
                    if before is not None: target.write_bytes(before)

    def test_state_ancestor_symlinks_are_refused_before_boundary_or_windows_handoff(self):
        outside = Path(self.temp.name) / "synthetic-outside-directory"
        outside.mkdir()
        sentinel = outside / "untouched.txt"
        sentinel.write_bytes(b"synthetic private state")
        for index, relative in enumerate(("state/config", "state/automation/global/gates", "state")):
            with self.subTest(relative=relative):
                ancestor = self.data / relative
                ancestor.mkdir(parents=True, exist_ok=True)
                saved = Path(self.temp.name) / f"synthetic-original-state-{index}"
                ancestor.rename(saved)
                ancestor.symlink_to(outside, target_is_directory=True)
                try:
                    with patch.object(deploy, "boundary_locks", side_effect=AssertionError("redirected lock ancestors must not be used")), patch.object(deploy, "read_windows_receipt", side_effect=AssertionError("Windows must not be handed off")):
                        with self.assertRaises(deploy.DeploymentError): self.activate(await_windows=True)
                    self.assertFalse(self.journal.exists())
                    self.assertEqual(list(self.workspace.iterdir()), [])
                    self.assertEqual(list(outside.iterdir()), [sentinel])
                    self.assertEqual(sentinel.read_bytes(), b"synthetic private state")
                finally:
                    ancestor.unlink()
                    saved.rename(ancestor)


class NotificationDeploymentTests(unittest.TestCase):
    """Actual five-target transaction against a bound blocked lifecycle fixture."""

    def setUp(self):
        case = fixtures.CoordinatorRecoveryTests()
        case.setUp(); self.addCleanup(case.doCleanups)
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name) / "workspace"; self.workspace.mkdir()
        self.data = Path(self.temp.name) / "data"
        self.pool = self.data / "state/automation/global"
        shutil.copytree(case.pool, self.pool)
        self.config = copy.deepcopy(fixtures.CONFIG)
        self.source = deploy.source_files()
        wrapper = deploy.digest((deploy.BUNDLE / "windows/yt-dlp-anonymous.cmd").read_bytes())
        self.config["assets"]["wrapper_sha256"] = wrapper
        # A full admitted baseline has no alert helper. Native/protected bytes
        # are real; old notification owners are deliberately distinct bytes.
        previous = {key: raw for key, raw in self.source.items() if key != "scripts/youtube_worker_alerts.py"}
        previous[deploy.SUPERVISOR] = b"# synthetic prior notification owner\n"
        for key, raw in previous.items():
            path = self.workspace / key
            deploy.atomic(path, raw, mode=0o750 if path.name == "openclaw-node-run" else 0o640)
        self.baseline = {"schema": "openclaw.youtube.windows-release.v1", "repository": deploy.REPOSITORY,
            "compatibility": deploy.COMPATIBILITY, "revision": self.config["assets"]["fork_revision"],
            "files": {key: deploy.digest(raw) for key, raw in previous.items()},
            "archiver": {"repository": "fr-meyer/agent-toolkit", "revision": self.config["assets"]["archiver_revision"],
                "path": "skills/youtube-transcript-archive/scripts/archive_youtube_transcript.py", "sha256": self.config["assets"]["archiver_sha256"]},
            "wrapper_sha256": wrapper}
        self.release = {**self.baseline, "revision": "a" * 40, "files": {key: deploy.digest(raw) for key, raw in self.source.items()}}
        self.identity = deploy.release_identity(self.release, self.source)
        deploy.atomic(self.data / "state/config/windows-worker.json", deploy.json_bytes(self.config), mode=0o600)
        deploy.atomic(self.pool / "gates/windows-worker-cutover.json", deploy.json_bytes({"enabled": True,
            "node_id": self.config["node"]["id"], "worker_sha256": self.baseline["files"]["scripts/youtube_global_chunk_worker.py"],
            "adapter_sha256": self.baseline["files"]["scripts/youtube_global_windows_adapter.ps1"], "scheduler_identity_sha256": "d" * 64}), mode=0o600)
        deploy.atomic(self.data / "state/config/windows-deployment.json", deploy.json_bytes({
            "schema": "openclaw.youtube.windows-deployment.v1", "revision": self.baseline["revision"],
            "release_sha256": deploy.digest(deploy.json_bytes(self.baseline)), "files": self.baseline["files"],
            "assets": self.config["assets"], "configuration_sha256": deploy.digest(deploy.json_bytes(self.config))}), mode=0o600)
        root = self.pool / "windows-canaries" / fixtures.CANARY
        manifest = deploy.read(root / "manifest.json")
        self.ids = [f"fixture{i:04d}" for i in range(1, 25)]
        urls = root / "chunks/0001.tsv"
        urls.write_text("".join(f"{video}\t{fixtures.gp.canonical_url(video)}\n" for video in self.ids))
        manifest.update(assets=self.config["assets"], worker_alive=False, video_ids=self.ids,
            expected_item_count=24, urls_sha256=deploy.digest(urls.read_bytes()))
        manifest["binding_sha256"] = fixtures.wc.stable_hash(fixtures.wc._binding_payload(fixtures.CANARY,
            fixtures.LEASE, self.ids, manifest["urls_sha256"], manifest["node"]))
        lease_path = self.pool / "leases" / (fixtures.LEASE + ".json")
        lease = deploy.read(lease_path); lease["video_ids"] = self.ids
        deploy.atomic(lease_path, deploy.json_bytes(lease)); manifest["lease_sha256"] = fixtures.wc._lease_binding_hash(lease)
        chunk_paths = [self.pool / "chunks" / (fixtures.CANARY + ".json"), root / "chunks/0001.json"]
        for path in chunk_paths:
            chunk = deploy.read(path); chunk["binding_sha256"] = manifest["binding_sha256"]
            chunk["items"] = [{"video_id": video, "url": fixtures.gp.canonical_url(video), "state": "pending"} for video in self.ids]
            chunk["chunk_sha256"] = fixtures.wc._chunk_binding_hash(chunk)
            deploy.atomic(path, deploy.json_bytes(chunk))
            manifest["chunk_sha256"] = chunk["chunk_sha256"]
        template = deploy.read(self.pool / "items" / (fixtures.IDS[0] + ".json"))
        for video in self.ids:
            deploy.atomic(self.pool / "items" / (video + ".json"), deploy.json_bytes({**template, "video_id": video}))
        for video in self.ids[:3]:
            deploy.atomic(root / "original-archives" / (video + ".txt"), ("synthetic validated original " + video).encode())
        deploy.atomic(root / "manifest.json", deploy.json_bytes(manifest))
        remote = fixtures.wc._normalise_probe(copy.deepcopy(case.remote))
        remote["assets"] = self.config["assets"]
        remote["staging"]["assets"] = self.config["assets"]
        remote["staging"]["urls_sha256"] = manifest["urls_sha256"]
        remote["items"] = {video: {"attempts": 1} for video in self.ids}
        self.readiness = {"schema": "openclaw.youtube.windows-notification-readiness.v1",
            "checked_at": dt.datetime.now(dt.timezone.utc).isoformat(), "canary_id": fixtures.CANARY,
            "lease_id": fixtures.LEASE, "checkpoint_sha256": fixtures.DIGEST, "node_id": self.config["node"]["id"],
            "node_connected": True, "assets": self.config["assets"], "remote": remote,
            "worker_account": self.config["assets"]["worker_account"],
            "adapter_sha256": manifest["adapter_sha256"], "archiver_sha256": self.config["assets"]["archiver_sha256"],
            "wrapper_sha256": wrapper, "configuration_sha256": deploy.digest((self.data / "state/config/windows-worker.json").read_bytes()),
            "cutover_sha256": deploy.digest((self.pool / "gates/windows-worker-cutover.json").read_bytes())}
        self.proofs = {"revision": self.release["revision"], "release_sha256": self.identity,
            **{key: {"state": "passed", "evidence_sha256": "c" * 64} for key in ("autoreview", "offline_tests")},
            "native_windows": {"state": "inherited", "evidence_sha256": "e" * 64,
                "baseline_release_sha256": deploy.digest(deploy.json_bytes(self.baseline)), "assets": self.config["assets"],
                "worker_sha256": self.baseline["files"]["scripts/youtube_global_chunk_worker.py"],
                "adapter_sha256": self.baseline["files"]["scripts/youtube_global_windows_adapter.ps1"]}}
        self.journal = self.workspace / ".openclaw/tmp/notification-deploy/transaction.json"
        self.proposed = deploy.notification_targets(self.workspace, self.data, self.release, self.config, self.source, self.baseline)
        self.expected = {str(path): deploy.digest(path.read_bytes()) if path.is_file() else None for path in self.proposed}
        p = patch.object(deploy, "verify_source_revision"); p.start(); self.addCleanup(p.stop)
        self.sentinel = self.pool / "windows-canaries/windows-canary-fixture-closed/archives/original.txt"
        deploy.atomic(self.sentinel, b"synthetic original validated output\n")
        deploy.atomic(self.sentinel.parent.parent / "imports/receipt.json", b'{"synthetic":"closed validated import"}\n')
        self.ledger = self.pool / "windows-notifications.sqlite3"
        # A real durable reservation, outside the deployment write set, must
        # survive rollback so an already noticed incident stays quiet.
        self.notice_snapshot = {"run_id": "windows-canary-prod-fixture-notification", "lease_id": fixtures.LEASE, "phase": "attention",
            "failure_code": "rate_limited", "video_id": self.ids[3], "archived_count": 3,
            "incomplete_count": 21, "recovery_verified": False}
        with fixtures.sv.ALERTS.NotificationStore(self.ledger) as store:
            self.assertIsNotNone(store.observe(self.notice_snapshot, now=dt.datetime.now(dt.timezone.utc)))

    def activate(self):
        return deploy.activate_notifications(self.workspace, self.data, self.release, self.config, self.proofs,
            self.expected, self.journal, self.baseline, self.readiness)

    def tree(self):
        return {str(path): (path.read_bytes(), path.stat().st_mode & 0o777) for root in (self.workspace, self.data)
            for path in root.rglob("*") if path.is_file() and path != self.journal and path.name not in {"windows-supervisor.lock", "coordinator.lock", "reconcile.lock"} and "__pycache__" not in path.parts}

    def test_blocked_same_lease_changes_only_five_targets_and_restores_all_preimages(self):
        before = self.tree()
        self.assertEqual(self.activate()["state"], "committed")
        changed = {key for key, value in self.tree().items() if before.get(key) != value}
        self.assertLessEqual(changed, set(self.expected))
        self.assertIn(str(self.workspace / "scripts/youtube_worker_alerts.py"), changed)
        self.assertEqual(deploy.read(self.data / "state/config/windows-deployment.json")["assets"], self.config["assets"])
        self.assertEqual(deploy.rollback(self.journal, readiness=self.readiness)["state"], "rolled_back")
        self.assertEqual(self.tree(), before)
        with fixtures.sv.ALERTS.NotificationStore(self.ledger) as store:
            self.assertIsNone(store.observe(self.notice_snapshot, now=dt.datetime.now(dt.timezone.utc)))

    def test_full_installer_still_refuses_the_same_active_lease(self):
        proofs = copy.deepcopy(self.proofs)
        proofs["native_windows"] = {"state": "passed", "evidence_sha256": "e" * 64}
        with self.assertRaisesRegex(deploy.DeploymentError, "active authoritative lease"):
            deploy.activate(self.workspace, self.data, self.release, self.config, proofs, self.expected, self.journal)
        self.assertFalse(self.journal.exists())

    def test_journal_cannot_replace_runtime_ledger_or_run_state(self):
        before = self.tree()
        original = self.journal
        for path in (self.workspace / "scripts/youtube_worker_alerts.py", self.pool / "new-run-artifact.json", self.ledger):
            with self.subTest(path=path):
                self.journal = path
                with self.assertRaisesRegex(deploy.DeploymentError, "private deployment artifact"): self.activate()
        self.journal = original
        self.assertEqual(self.tree(), before)

    def test_unknown_running_stale_or_mismatched_readiness_refuses_before_journal(self):
        original = copy.deepcopy(self.readiness)
        cases = [("checked_at", "2001-01-01T00:00:00Z"), ("node_connected", False), ("lease_id", "other"),
            ("checkpoint_sha256", "0" * 64)]
        for key, value in cases:
            with self.subTest(key=key):
                self.readiness = copy.deepcopy(original); self.readiness[key] = value
                with self.assertRaises(deploy.DeploymentError): self.activate()
                self.assertFalse(self.journal.exists())
        for key, value in (("worker_alive", True), ("worker_alive", None), ("worker_lock_free", None)):
            with self.subTest(key=key, value=value):
                self.readiness = copy.deepcopy(original); self.readiness["remote"][key] = value
                with self.assertRaises(deploy.DeploymentError): self.activate()
                self.assertFalse(self.journal.exists())

    def test_each_current_item_binding_and_unknown_recovery_intent_is_fenced(self):
        for video in self.ids:
            path = self.pool / "items" / (video + ".json"); raw = path.read_bytes()
            row = deploy.read(path); row["active_node"] = "9" * 64
            deploy.atomic(path, deploy.json_bytes(row))
            with self.assertRaises(deploy.DeploymentError): self.activate()
            self.assertFalse(self.journal.exists()); path.write_bytes(raw)
        request = self.pool / "windows-canaries" / fixtures.CANARY / "resume-requests/fixture.json"
        for state in ("intent", "uncertain", "unexpected", "acknowledged"):
            deploy.atomic(request, deploy.json_bytes({"state": state}))
            with self.assertRaisesRegex(deploy.DeploymentError, "unresolved"): self.activate()
            self.assertFalse(self.journal.exists())

    def test_protected_source_config_and_pin_drift_are_not_notification_changes(self):
        before = self.tree()
        for path in (self.workspace / "scripts/youtube_global_chunk_worker.py", self.data / "state/config/windows-worker.json",
                     self.pool / "gates/windows-worker-cutover.json"):
            raw = path.read_bytes(); path.write_bytes(raw + b"\n")
            with self.subTest(path=path):
                with self.assertRaises(deploy.DeploymentError): self.activate()
                self.assertFalse(self.journal.exists())
            path.write_bytes(raw)
        self.assertEqual(self.tree(), before)

    def test_candidate_cannot_change_protected_worker_even_with_recomputed_release(self):
        source = {**self.source, "scripts/youtube_global_chunk_worker.py": b"synthetic changed worker"}
        self.release["files"] = {key: deploy.digest(raw) for key, raw in source.items()}
        self.proofs["release_sha256"] = deploy.digest(deploy.json_bytes(self.release))
        with patch.object(deploy, "source_files", return_value=source):
            with self.assertRaisesRegex(deploy.DeploymentError, "changes protected source"): self.activate()
        self.assertFalse(self.journal.exists())

    def test_unrelated_process_cwd_is_not_read_but_relevant_unknown_cwd_refuses(self):
        process = Path(self.temp.name) / "synthetic-proc-123"; process.mkdir()
        cmdline = process / "cmdline"
        cmdline.write_bytes(b"/usr/bin/sleep\x00300\x00")
        with patch.object(deploy, "bounded_children", return_value=[process]):
            deploy.commands_drained(self.workspace)
            cmdline.write_bytes(b"python3\x00scripts/youtube_global_windows_supervisor.py\x00cron\x00")
            with self.assertRaisesRegex(deploy.DeploymentError, "outcome unknown"):
                deploy.commands_drained(self.workspace)

    def test_direct_reconcile_and_both_owner_lock_contentions_refuse_without_writes(self):
        for relative in ("locks/windows-supervisor.lock", "locks/coordinator.lock", "windows-canaries/" + fixtures.CANARY + "/reconcile.lock"):
            with self.subTest(relative=relative), fixtures.gp.FileLock(self.pool / relative, blocking=False):
                with self.assertRaises(deploy.DeploymentError): self.activate()
                self.assertFalse(self.journal.exists())

    def test_real_existing_command_is_drained_before_writes_and_new_cron_fences_imports(self):
        process = subprocess.Popen([sys.executable, "-c", "import sys;print('ready',flush=True);sys.stdin.read()", str(self.workspace / deploy.SUPERVISOR)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(process.stdout.readline().strip(), "ready")
            with self.assertRaisesRegex(deploy.DeploymentError, "still active"): self.activate()
            self.assertFalse(self.journal.exists())
        finally:
            process.communicate(input="", timeout=2)
        atomic = deploy.atomic
        observed = []
        def during(path, raw, **options):
            atomic(path, raw, **options)
            if path == self.workspace / deploy.SUPERVISOR:
                for command in ("cron", "cron-reconcile"):
                    result = subprocess.run([sys.executable, str(path), command], text=True, capture_output=True, timeout=2,
                        env={**os.environ, "OPENCLAW_YOUTUBE_DATA_ROOT": str(self.data)})
                    observed.append((result.returncode, result.stdout.strip(), result.stderr))
        with patch.object(deploy, "atomic", side_effect=during): self.activate()
        self.assertEqual(observed, [(0, "NO_REPLY", ""), (0, "NO_REPLY", "")])

    def test_rollback_keeps_startup_fence_through_source_and_receipt_restoration(self):
        before = self.tree(); self.activate(); atomic = deploy.atomic
        observed = []
        def during(path, raw, **options):
            atomic(path, raw, **options)
            if path in self.proposed and path != self.workspace / deploy.SUPERVISOR:
                for command in ("cron", "cron-reconcile"):
                    result = subprocess.run([sys.executable, str(self.workspace / deploy.SUPERVISOR), command],
                        text=True, capture_output=True, timeout=2,
                        env={**os.environ, "OPENCLAW_YOUTUBE_DATA_ROOT": str(self.data)})
                    observed.append((result.returncode, result.stdout.strip(), result.stderr))
        with patch.object(deploy, "atomic", side_effect=during):
            self.assertEqual(deploy.rollback(self.journal, readiness=self.readiness)["state"], "rolled_back")
        self.assertTrue(observed)
        self.assertTrue(all(result == (0, "NO_REPLY", "") for result in observed), observed)
        self.assertEqual(self.tree(), before)

    def test_loaded_old_owner_cannot_accept_new_receipt(self):
        self.activate()
        path = self.workspace / "scripts/youtube_windows_deployment.py"
        spec = importlib.util.spec_from_file_location("fixture_notification_reader", path)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        with patch.dict(os.environ, {"OPENCLAW_YOUTUBE_DATA_ROOT": str(self.data)}):
            for loaded in (None, "0" * 64):
                with self.assertRaisesRegex(RuntimeError, "loaded-owner"):
                    module.verify_managed_sources(self.workspace, self.config, loaded_supervisor_sha256=loaded)
            module.verify_managed_sources(self.workspace, self.config,
                loaded_supervisor_sha256=self.release["files"][deploy.SUPERVISOR])

    def test_interrupted_replacement_or_lost_commit_response_is_inspected_never_replayed(self):
        # Every durable replacement, including the committed journal write,
        # can finish before the caller loses its acknowledgement.
        for destination in [*self.proposed, self.journal]:
            with self.subTest(destination=destination):
                before = self.tree(); atomic = deploy.atomic; fired = False
                def lose_response(path, raw, **options):
                    nonlocal fired
                    atomic(path, raw, **options)
                    committed = path == self.journal and json.loads(raw).get("state") == "committed"
                    if not fired and (path == destination and path != self.journal or committed and destination == self.journal):
                        fired = True; raise OSError("synthetic lost durable write response")
                with patch.object(deploy, "atomic", side_effect=lose_response):
                    with self.assertRaises(OSError): self.activate()
                self.assertTrue(fired)
                self.assertIn(deploy.read(self.journal)["state"], {"prepared", "committed"})
                with self.assertRaisesRegex(deploy.DeploymentError, "already exists"): self.activate()
                deploy.rollback(self.journal, readiness=self.readiness)
                self.assertEqual(self.tree(), before); self.journal.unlink()

    def test_total_deadline_includes_admission_and_write_then_preserves_intent(self):
        clock = [0.0]; atomic = deploy.atomic
        def expire(path, raw, **options):
            atomic(path, raw, **options)
            if path == self.workspace / "scripts/youtube_worker_alerts.py": clock[0] = 31.0
        with patch.object(deploy.time, "monotonic", side_effect=lambda: clock[0]), patch.object(deploy, "atomic", side_effect=expire):
            with self.assertRaisesRegex(deploy.DeploymentError, "deadline reached"): self.activate()
        self.assertEqual(deploy.read(self.journal)["state"], "prepared")
        with deploy.boundary_locks(self.data, canary_id=fixtures.CANARY): pass
        deploy.rollback(self.journal, readiness=self.readiness)
        self.assertFalse((self.workspace / "scripts/youtube_worker_alerts.py").exists())

    def test_rollback_lost_final_write_response_and_later_drift_are_preserved(self):
        before = self.tree(); self.activate(); atomic = deploy.atomic
        def interrupt(path, raw, **options):
            atomic(path, raw, **options)
            if path == self.workspace / deploy.SUPERVISOR: raise OSError("synthetic interrupted rollback")
        with patch.object(deploy, "atomic", side_effect=interrupt):
            with self.assertRaises(OSError): deploy.rollback(self.journal, readiness=self.readiness)
        self.assertEqual(deploy.read(self.journal)["state"], "committed")
        path = self.workspace / "scripts/youtube_safe_diagnostics.py"; installed = path.read_bytes()
        path.write_bytes(b"synthetic later source drift")
        with self.assertRaisesRegex(deploy.DeploymentError, "unknown or drifted"):
            deploy.rollback(self.journal, readiness=self.readiness)
        self.assertEqual(path.read_bytes(), b"synthetic later source drift")
        path.write_bytes(installed)
        mode = path.stat().st_mode & 0o777; path.chmod(mode ^ 0o004)
        with self.assertRaisesRegex(deploy.DeploymentError, "unknown or drifted"):
            deploy.rollback(self.journal, readiness=self.readiness)
        self.assertEqual(path.stat().st_mode & 0o777, mode ^ 0o004)
        path.chmod(mode); deploy.rollback(self.journal, readiness=self.readiness)
        self.assertEqual(self.tree(), before)

    def test_partial_rollback_retains_startup_fence_and_can_restore_known_preimages(self):
        before = self.tree(); self.activate(); atomic = deploy.atomic
        def interrupt(path, raw, **options):
            atomic(path, raw, **options)
            if path == self.workspace / "scripts/youtube_safe_diagnostics.py":
                raise OSError("synthetic interrupted intermediate rollback")
        with patch.object(deploy, "atomic", side_effect=interrupt):
            with self.assertRaises(OSError): deploy.rollback(self.journal, readiness=self.readiness)
        self.assertEqual(deploy.read(self.journal)["state"], "committed")
        self.assertEqual((self.workspace / deploy.SUPERVISOR).read_bytes(), self.source[deploy.SUPERVISOR])
        deploy.rollback(self.journal, readiness=self.readiness)
        self.assertEqual(self.tree(), before)


class TrackedSourceRevisionTests(unittest.TestCase):
    """Real fixture files with mocked, immutable Git tree/blob responses."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.repository = Path(self.temp.name) / "synthetic-repository"
        self.bundle = self.repository / "deploy/youtube-worker"
        self.revision = "a" * 40
        self.head = self.revision
        self.committed = {
            "deployment.py": b"synthetic committed deployment\n",
            "runtime/scripts/worker.py": b"synthetic committed runtime\n",
            "windows/yt-dlp-anonymous.cmd": b"synthetic committed wrapper\n",
            "tests/test_fixture.py": b"synthetic committed tests\n",
        }
        for relative, raw in self.committed.items():
            path = self.bundle / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        p = patch.object(deploy, "BUNDLE", self.bundle)
        p.start(); self.addCleanup(p.stop)
        p = patch.object(deploy.subprocess, "check_output", side_effect=self.git_response)
        self.git = p.start(); self.addCleanup(p.stop)

    def git_response(self, argv, **options):
        self.assertEqual(argv[:3], ["git", "-C", str(self.repository)])
        operation = argv[3:]
        if operation == ["rev-parse", "HEAD"]:
            self.assertTrue(options.get("text"))
            return self.head + "\n"
        if operation == ["ls-tree", "-r", "-z", "--full-tree", self.revision, "--", "deploy/youtube-worker"]:
            return b"".join(b"100644 blob " + b"b" * 40 + b"\tdeploy/youtube-worker/" + relative.encode() + b"\0" for relative in self.committed)
        if operation[0] == "show":
            self.assertTrue(operation[1].startswith(self.revision + ":deploy/youtube-worker/"))
            return self.committed[operation[1].split(":deploy/youtube-worker/", 1)[1]]
        self.fail("unexpected Git source verification operation")

    def verify(self, source=None):
        deploy.verify_source_revision(self.revision, deploy.source_files() if source is None else source)

    def test_exact_tracked_tree_allows_only_generated_caches_and_private_inputs_outside_bundle(self):
        cache = self.bundle / "runtime/scripts/__pycache__/worker.cpython-313.pyc"
        cache.parent.mkdir()
        cache.write_bytes(b"synthetic generated cache")
        private = self.repository / "private-operational-input.json"
        private.write_bytes(b"synthetic external operational input")
        self.verify()
        self.assertEqual(deploy.source_files(), {"scripts/worker.py": self.committed["runtime/scripts/worker.py"]})
        self.assertEqual(private.read_bytes(), b"synthetic external operational input")

    def test_non_head_revision_is_refused(self):
        self.head = "d" * 40
        with self.assertRaises(deploy.DeploymentError): self.verify()
        self.assertEqual(self.git.call_count, 1)

    def test_modified_tracked_deployment_runtime_wrapper_and_tests_are_refused(self):
        for relative, raw in self.committed.items():
            with self.subTest(relative=relative):
                path = self.bundle / relative
                path.write_bytes(b"synthetic changed source with a freshly computed release hash")
                try:
                    with self.assertRaises(deploy.DeploymentError): self.verify()
                finally:
                    path.write_bytes(raw)

    def test_missing_tracked_source_is_refused(self):
        (self.bundle / "runtime/scripts/worker.py").unlink()
        with self.assertRaises(deploy.DeploymentError): self.verify()

    def test_untracked_and_ignored_bundle_files_cannot_be_admitted_by_recomputed_inventory(self):
        (self.repository / ".gitignore").write_text("*ignored.py\n", encoding="utf-8")
        for relative in ("runtime/scripts/extra.py", "runtime/scripts/ignored.py", "runtime/scripts/__pycache__/injected.py", "windows/untracked.cmd", "private-input-inside-bundle.json"):
            with self.subTest(relative=relative):
                path = self.bundle / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"synthetic untracked deployment source")
                try:
                    source = deploy.source_files()
                    if relative.startswith("runtime/"):
                        self.assertIn(relative.removeprefix("runtime/"), source)
                    with self.assertRaises(deploy.DeploymentError): self.verify(source)
                finally:
                    path.unlink()

    def test_captured_runtime_bytes_must_match_the_verified_tracked_blobs(self):
        with self.assertRaises(deploy.DeploymentError):
            self.verify({"scripts/worker.py": b"synthetic stale or substituted payload"})

    def test_managed_source_symlink_is_refused(self):
        outside = self.repository / "synthetic-unrelated-wrapper.cmd"
        outside.write_bytes(self.committed["windows/yt-dlp-anonymous.cmd"])
        wrapper = self.bundle / "windows/yt-dlp-anonymous.cmd"
        wrapper.unlink()
        wrapper.symlink_to(outside)
        with self.assertRaises(deploy.DeploymentError): self.verify()


if __name__ == "__main__": unittest.main()
