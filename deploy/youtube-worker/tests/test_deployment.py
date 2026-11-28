"""Managed deployment proof gates, active-lease fences and rollback preimages."""
import importlib.util
from pathlib import Path
import tempfile
import os
import copy
import contextlib
import datetime as dt
import json
import io
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

    def history(self, leases=1206, runs=710):
        # Real metadata files at the observed failing production cardinality;
        # original archives, receipt, ledger and all 24 bindings stay present.
        for index in range(leases - 1):
            path = self.pool / "leases" / f"history-{index:04d}.json"
            path.write_bytes(deploy.json_bytes({"lease_id": path.stem, "state": "completed", "node": {"id": self.config["node"]["id"]}, "history_note": "x" * 900}))
        for index in range(runs - 1):
            root = self.pool / "windows-canaries" / f"windows-canary-history-{index:04d}"
            root.mkdir()
            (root / "manifest.json").write_bytes(deploy.json_bytes({"canary_id": root.name,
                "state": "completed", "node": {"node_id": self.config["node"]["id"]}, "history_note": "x" * 4500}))

    def plan(self):
        root = Path(self.temp.name) / "plan-inputs"; root.mkdir(exist_ok=True)
        arguments = []
        for name, value in (("release", self.release), ("configuration", self.config),
                            ("baseline-release", self.baseline), ("readiness", self.readiness)):
            path = root / (name + ".json"); path.write_bytes(deploy.json_bytes(value))
            arguments += ["--" + name, str(path)]
        output = io.StringIO()
        with patch.object(sys, "argv", [str(SOURCE), "plan", "--notification-only", "--workspace", str(self.workspace),
                "--data-root", str(self.data), *arguments]), contextlib.redirect_stdout(output):
            self.assertEqual(deploy.main(), 0)
        return json.loads(output.getvalue())

    def test_production_sized_history_real_plan_activation_and_rollback_preserve_graph(self):
        self.history()
        before = self.tree()
        with patch.object(deploy, "boundary_locks", side_effect=AssertionError("read-only plan acquired boundary")):
            self.assertEqual(self.plan(), self.expected)
        self.assertEqual(self.tree(), before)
        self.assertEqual(self.activate()["state"], "committed")
        self.assertEqual(deploy.rollback(self.journal, readiness=self.readiness)["state"], "rolled_back")
        self.assertEqual(self.tree(), before)

    def test_malformed_historical_records_refuse_plan_and_activation_before_boundary(self):
        path = self.pool / "leases/history-malformed.json"
        for raw in (b"{", b"[]", b"\xff", b"\xef\xbb\xbf{}", b'{"state":"completed","node":"invalid"}', b'{"state":[]}'):
            with self.subTest(raw=raw):
                path.write_bytes(raw); before = self.tree()
                with patch.object(deploy, "boundary_locks", side_effect=AssertionError("unsafe scan acquired boundary")):
                    with self.assertRaises(deploy.DeploymentError): self.plan()
                    with self.assertRaises(deploy.DeploymentError): self.activate()
                self.assertFalse(self.journal.exists()); self.assertEqual(self.tree(), before)

    def historical_record_path(self, kind):
        if kind == "leases": return self.pool / "leases/history-node.json"
        root = self.pool / "windows-canaries/windows-canary-history-node"
        root.mkdir(exist_ok=True)
        return root / "manifest.json"

    def test_explicit_nonobject_nodes_refuse_both_histories_before_boundary(self):
        for kind in ("leases", "windows-canaries"):
            path = self.historical_record_path(kind)
            for state in ("completed", "active" if kind == "leases" else "blocked"):
                for node in (None, False, True, 0, 0.0, "", [], [None], "invalid"):
                    with self.subTest(kind=kind, state=state, node=node):
                        path.write_bytes(deploy.json_bytes({"state": state, "node": node})); before = self.tree()
                        with patch.object(deploy, "boundary_locks", side_effect=AssertionError("malformed node acquired boundary")):
                            with self.assertRaisesRegex(deploy.DeploymentError, "node/state record is malformed"): self.plan()
                            with self.assertRaisesRegex(deploy.DeploymentError, "node/state record is malformed"): self.activate()
                        self.assertFalse(self.journal.exists()); self.assertEqual(self.tree(), before)
            path.unlink()

    def test_missing_or_empty_live_node_identity_refuses_before_boundary(self):
        for kind in ("leases", "windows-canaries"):
            path = self.historical_record_path(kind)
            key = "id" if kind == "leases" else "node_id"
            for state in (("active",) if kind == "leases" else ("preparing", "prepared", "blocked", "running")):
                rows = [{"state": state}, {"state": state, "node": {}}]
                rows += [{"state": state, "node": {key: value}} for value in (None, False, 0, "", [])]
                for row in rows:
                    with self.subTest(kind=kind, row=row):
                        path.write_bytes(deploy.json_bytes(row)); before = self.tree()
                        with patch.object(deploy, "boundary_locks", side_effect=AssertionError("unknown owner acquired boundary")):
                            with self.assertRaisesRegex(deploy.DeploymentError, "node identity is incomplete"): self.plan()
                            with self.assertRaisesRegex(deploy.DeploymentError, "node identity is incomplete"): self.activate()
                        self.assertFalse(self.journal.exists()); self.assertEqual(self.tree(), before)
            path.unlink()

    def test_terminal_missing_or_object_nodes_preserve_history_and_same_run(self):
        paths = [self.historical_record_path(kind) for kind in ("leases", "windows-canaries")]
        for path in paths: path.write_bytes(deploy.json_bytes({"state": "completed"}))
        for kind, path in zip(("leases", "windows-canaries"), paths):
            states = ("completed", "partial") if kind == "leases" else ("completed", "partial", "superseded_before_lease")
            for state in states:
                rows = [{"state": state}, {"state": state, "node": {}},
                        {"state": state, "node": {"id": "9" * 64, "node_id": "9" * 64, "platform": "linux"}}]
                for row in rows:
                    with self.subTest(kind=kind, row=row):
                        path.write_bytes(deploy.json_bytes(row)); before = self.tree()
                        with patch.object(deploy, "boundary_locks", side_effect=AssertionError("plan acquired boundary")):
                            self.assertEqual(self.plan(), self.expected)
                        self.assertEqual(self.tree(), before)
            path.write_bytes(deploy.json_bytes({"state": "completed"}))
        before = self.tree()
        self.assertEqual(self.activate()["state"], "committed")
        self.assertEqual(deploy.rollback(self.journal, readiness=self.readiness)["state"], "rolled_back")
        self.assertEqual(self.tree(), before)

    def test_valid_other_node_objects_keep_existing_ownership_rules(self):
        lease = self.historical_record_path("leases")
        run = self.historical_record_path("windows-canaries")
        lease.write_bytes(deploy.json_bytes({"state": "active", "node": {"id": "9" * 64, "platform": "linux"}}))
        run.write_bytes(deploy.json_bytes({"state": "blocked", "node": {"node_id": "9" * 64, "platform": "windows"}}))
        before = self.tree()
        with patch.object(deploy, "boundary_locks", side_effect=AssertionError("plan acquired boundary")):
            self.assertEqual(self.plan(), self.expected)
        self.assertEqual(self.tree(), before)

    def test_misplaced_node_namespace_does_not_hide_an_additional_owner(self):
        path = self.pool / "leases/history-misplaced.json"
        path.write_bytes(deploy.json_bytes({"state": "blocked", "node": {"node_id": self.config["node"]["id"]}}))
        with patch.object(deploy, "boundary_locks", side_effect=AssertionError("ambiguous scan acquired boundary")):
            with self.assertRaisesRegex(deploy.DeploymentError, "ownership differs"): self.activate()
        self.assertFalse(self.journal.exists())

    @contextlib.contextmanager
    def inventory_view(self, kind, count, *, ignored=False):
        # Fixed synthetic enumeration tests the capacity boundary cheaply.
        # The production-sized test above exercises actual unique files.
        root = self.pool / kind
        if kind == "windows-canaries" and not ignored:
            directory = root / "windows-canary-history-capacity"; directory.mkdir(exist_ok=True)
            path = directory / "manifest.json"
        else: path = root / ("ignored.txt" if ignored else "history-capacity.json")
        path.write_bytes(b'{"state":"completed"}\n')
        scandir = deploy.os.scandir
        with scandir(root) as entries: existing = list(entries)
        active_name = fixtures.LEASE + ".json" if kind == "leases" else fixtures.CANARY
        active = next(entry for entry in existing if entry.name == active_name)
        historical_name = path.parent.name if kind == "windows-canaries" and not ignored else path.name
        historical = next(entry for entry in existing if entry.name == historical_name)
        @contextlib.contextmanager
        def enumerated(directory):
            if Path(directory) == root:
                yield iter([active] + [historical] * (count - 1))
            else:
                with scandir(directory) as entries: yield entries
        with patch.object(deploy.os, "scandir", side_effect=enumerated): yield

    def test_entry_capacity_boundary_is_finite_and_counts_ignored_names(self):
        # Synthetic enumeration proves the entry limit independently of host
        # CPU quota. The separate scan-deadline regression proves time expiry.
        with patch.object(deploy.time, "monotonic", return_value=0.0):
            for kind in ("leases", "windows-canaries"):
                with self.subTest(kind=kind), self.inventory_view(kind, deploy.NotificationInventory.ENTRY_LIMIT):
                    self.assertEqual(self.plan(), self.expected)
                for ignored in (False, True):
                    with self.subTest(kind=kind, ignored=ignored), self.inventory_view(kind, deploy.NotificationInventory.ENTRY_LIMIT + 1, ignored=ignored):
                        with patch.object(deploy, "boundary_locks", side_effect=AssertionError("over-bound scan acquired boundary")):
                            with self.assertRaisesRegex(deploy.DeploymentError, "entries exceed bound"): self.plan()
                            with self.assertRaisesRegex(deploy.DeploymentError, "entries exceed bound"): self.activate()
                        self.assertFalse(self.journal.exists())

    def test_special_or_symlinked_record_refuses_before_boundary(self):
        path = self.pool / "leases/history-unsafe.json"
        for kind in ("symlink", "fifo"):
            if kind == "fifo" and not hasattr(os, "mkfifo"): continue
            if kind == "symlink": path.symlink_to(self.pool / "leases" / (fixtures.LEASE + ".json"))
            else: os.mkfifo(path)
            try:
                with patch.object(deploy, "boundary_locks", side_effect=AssertionError("unsafe scan acquired boundary")):
                    with self.assertRaises(deploy.DeploymentError): self.plan()
                self.assertFalse(self.journal.exists())
            finally: path.unlink()

    def test_record_and_aggregate_byte_capacity_stop_before_boundary(self):
        path = self.pool / "leases/history-bytes.json"
        path.write_bytes(b" " * (deploy.NotificationInventory.RECORD_LIMIT + 1))
        with patch.object(deploy, "boundary_locks", side_effect=AssertionError("over-byte scan acquired boundary")):
            with self.assertRaisesRegex(deploy.DeploymentError, "bytes exceed bound"): self.activate()
        path.write_bytes(b'{"state":"completed"}\n')
        with patch.object(deploy.NotificationInventory, "BYTE_LIMIT", 1):
            with patch.object(deploy, "boundary_locks", side_effect=AssertionError("over-byte scan acquired boundary")):
                with self.assertRaisesRegex(deploy.DeploymentError, "bytes exceed bound"): self.plan()
        self.assertFalse(self.journal.exists())
        inventory = deploy.NotificationInventory(self.workspace, self.data)
        with patch.object(inventory, "BYTE_LIMIT", path.stat().st_size):
            self.assertEqual(inventory.read_json(path)["state"], "completed")
            with self.assertRaisesRegex(deploy.DeploymentError, "bytes exceed bound"): inventory.read_json(path)

    def test_growing_inventory_is_not_retried_or_admitted(self):
        read = deploy.NotificationInventory.read_json
        grown = False
        def grow(inventory, path, default=None):
            nonlocal grown
            row = read(inventory, path, default)
            if not grown and Path(path).parent == self.pool / "leases":
                grown = True
                (self.pool / "leases/concurrent-history.json").write_bytes(b'{"state":"completed"}\n')
            return row
        with patch.object(deploy.NotificationInventory, "read_json", new=grow), patch.object(deploy, "boundary_locks", side_effect=AssertionError("growing scan acquired boundary")):
            with self.assertRaisesRegex(deploy.DeploymentError, "changed during scan"): self.activate()
        self.assertTrue(grown); self.assertFalse(self.journal.exists())

    def test_scan_time_budget_expires_before_boundary_without_real_waits(self):
        clock = [0.0]; read = deploy.NotificationInventory.read_json
        def expire(inventory, path, default=None):
            result = read(inventory, path, default); clock[0] = 6.0
            return result
        with patch.object(deploy.time, "monotonic", side_effect=lambda: clock[0]), patch.object(deploy.NotificationInventory, "read_json", new=expire), patch.object(deploy, "boundary_locks", side_effect=AssertionError("expired scan acquired boundary")):
            with self.assertRaisesRegex(deploy.DeploymentError, "scan deadline"): self.activate()
        self.assertFalse(self.journal.exists())

    def test_installed_repeated_reads_share_budget_and_restore_reader_on_interruption(self):
        raw = deploy.NotificationInventory.raw
        lease_path = self.pool / "leases" / (fixtures.LEASE + ".json")
        for failure in (deploy.DeploymentError("synthetic read budget exhausted"), KeyboardInterrupt()):
            reads = 0
            original_path, original_data = sys.path[:], os.environ.get("OPENCLAW_YOUTUBE_DATA_ROOT")
            original_reader = sys.modules["youtube_global_pool"].read_json
            original_store = sys.modules["youtube_global_pool"].PoolStore
            def interrupt(inventory, path):
                nonlocal reads
                result = raw(inventory, path)
                if Path(path) == lease_path:
                    reads += 1
                    if reads == 2: raise failure
                return result
            with self.subTest(failure=type(failure)), patch.object(deploy.NotificationInventory, "raw", new=interrupt), patch.object(deploy, "boundary_locks", side_effect=AssertionError("interrupted scan acquired boundary")):
                with self.assertRaises(type(failure)): self.activate()
            self.assertEqual(reads, 2)
            self.assertIs(sys.modules["youtube_global_pool"].read_json, original_reader)
            self.assertIs(sys.modules["youtube_global_pool"].PoolStore, original_store)
            self.assertEqual(sys.path, original_path)
            self.assertEqual(os.environ.get("OPENCLAW_YOUTUBE_DATA_ROOT"), original_data)
            self.assertFalse(self.journal.exists())

    def test_locked_scan_repeats_live_ownership_instead_of_reusing_preflight(self):
        locks = deploy.boundary_locks
        @contextlib.contextmanager
        def raced(data, *, canary_id=None):
            with locks(data, canary_id=canary_id):
                (self.pool / "leases/concurrent-active.json").write_bytes(deploy.json_bytes({
                    "state": "active", "lease_id": "other", "node": {"id": self.config["node"]["id"]}}))
                yield
        with patch.object(deploy, "boundary_locks", side_effect=raced):
            with self.assertRaisesRegex(deploy.DeploymentError, "ownership differs"): self.activate()
        self.assertFalse(self.journal.exists())
        self.assertFalse((self.workspace / "scripts/youtube_worker_alerts.py").exists())

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


class CoordinatorDeploymentTests(unittest.TestCase):
    """Four-target extension of an installed notification repair, unarmed."""

    def setUp(self):
        notification = NotificationDeploymentTests()
        notification.setUp(); self.addCleanup(notification.doCleanups)
        notification.activate()
        self.fixture = notification
        for name in ("workspace", "data", "pool", "config", "source", "release", "identity", "readiness", "proofs", "ids"):
            setattr(self, name, copy.deepcopy(getattr(notification, name)))
        self.receipt_path = self.data / "state/config/windows-deployment.json"
        self.baseline = deploy.read(self.receipt_path)
        self.baseline["revision"] = deploy.NOTIFICATION_REVISION
        self.baseline["release_sha256"] = deploy.digest(deploy.json_bytes({**notification.release,
            "revision": deploy.NOTIFICATION_REVISION}))
        # Distinct candidate bytes exercise all three replacements without
        # rewriting any inherited native or installed notification provenance.
        for key in deploy.COORDINATOR_FILES:
            self.source[key] += b"\n# synthetic distinct coordinator candidate\n"
        self.release["files"] = {key: deploy.digest(raw) for key, raw in self.source.items()}
        self.identity = deploy.release_identity(self.release, self.source)
        self.proofs["release_sha256"] = self.identity
        p = patch.object(deploy, "source_files", return_value=self.source)
        p.start(); self.addCleanup(p.stop)
        deploy.atomic(self.receipt_path, deploy.json_bytes(self.baseline), mode=0o600)
        self.proofs["native_windows"].update(
            baseline_release_sha256=self.baseline["baseline"]["release_sha256"],
            baseline_deployment_sha256=deploy.digest(self.receipt_path.read_bytes()))
        self.journal = self.workspace / ".openclaw/tmp/coordinator-deploy/transaction.json"
        notification.journal = self.journal
        self.proposed = deploy.coordinator_targets(self.workspace, self.data, self.release, self.config, self.source, self.baseline)
        self.expected = {str(path): deploy.digest(path.read_bytes()) for path in self.proposed}
        self.root = self.pool / "windows-canaries" / fixtures.CANARY
        self.requests = self.root / "resume-requests"

    def tree(self): return self.fixture.tree()

    def activate(self):
        return deploy.activate_coordinator(self.workspace, self.data, self.release, self.config, self.proofs,
            self.expected, self.journal, self.baseline, self.readiness)

    def request(self, *, state="acknowledged", checkpoint=None):
        manifest = deploy.read(self.root / "manifest.json")
        checkpoint = checkpoint or fixtures.DIGEST
        row = {"schema": "openclaw.youtube.windows-resume.v1", "state": state,
            "checkpoint_sha256": checkpoint, "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "binding": {key: manifest.get(key) for key in ("canary_id", "lease_id", "binding_sha256", "worker_sha256", "adapter_sha256", "urls_sha256")}}
        path = self.requests / (checkpoint + ".json")
        deploy.atomic(path, deploy.json_bytes(row))
        return path

    def bounded_request(self, state, *, checkpoint=None):
        path = self.request(state="acknowledged", checkpoint=checkpoint)
        row = deploy.read(path)
        approved = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=5)
        occurrence = approved - dt.timedelta(hours=5)
        row.update(schema="openclaw.youtube.windows-resume.v2", state=state,
            policy_version="gcp-rate-recovery-v1", recovery_ordinal=1,
            occurrence_checkpoint_sha256=row["checkpoint_sha256"],
            occurrence_at=occurrence.isoformat(), failed_video_id=self.ids[3], failed_video_attempt=1,
            due_at=(occurrence + dt.timedelta(hours=4)).isoformat(), approval_reference="synthetic-review-approval",
            approved_at=approved.isoformat(), created_at=approved.isoformat(),
            grant_expires_at=(approved + dt.timedelta(hours=24)).isoformat())
        if state in {"intent", "uncertain", "acknowledged"}:
            row["dispatched_at"] = (approved + dt.timedelta(minutes=1)).isoformat()
        deploy.atomic(path, deploy.json_bytes(row))
        return path

    def plan(self, *, extra=()):
        root = self.workspace / ".openclaw/tmp/coordinator-inputs"; root.mkdir(parents=True, exist_ok=True)
        arguments = []
        for name, value in (("release", self.release), ("configuration", self.config),
                            ("baseline-deployment", self.baseline), ("readiness", self.readiness)):
            path = root / (name + ".json"); path.write_bytes(deploy.json_bytes(value))
            arguments += ["--" + name, str(path)]
        output = io.StringIO()
        with patch.object(sys, "argv", [str(SOURCE), "plan", "--coordinator-only", "--workspace", str(self.workspace),
                "--data-root", str(self.data), *arguments, *extra]), contextlib.redirect_stdout(output):
            self.assertEqual(deploy.main(), 0)
        return json.loads(output.getvalue())

    def test_real_coordinator_plan_four_target_activation_and_exact_rollback_preserve_notifications(self):
        with patch.object(deploy, "boundary_locks", side_effect=AssertionError("read-only plan acquired boundary")):
            self.assertEqual(self.plan(), self.expected)
        before = self.tree()
        self.assertEqual(set(self.expected), {str(self.workspace / key) for key in deploy.COORDINATOR_FILES} | {str(self.receipt_path)})
        self.assertEqual(self.activate()["kind"], "coordinator-only")
        self.assertEqual({key for key, value in self.tree().items() if before.get(key) != value}, set(self.expected))
        receipt = deploy.read(self.receipt_path)
        self.assertEqual(receipt["baseline"], self.baseline["baseline"])
        self.assertEqual(receipt["notification_baseline"]["revision"], deploy.NOTIFICATION_REVISION)
        self.assertEqual(receipt["previous"]["receipt_sha256"], deploy.digest(before[str(self.receipt_path)][0]))
        journal = deploy.read(self.journal)
        self.assertEqual(journal["protected"][str(self.requests)], {"exists": False})
        self.assertEqual(deploy.rollback(self.journal, readiness=self.readiness)["kind"], "coordinator-only")
        self.assertEqual(self.tree(), before)
        with fixtures.sv.ALERTS.NotificationStore(self.fixture.ledger) as store:
            self.assertIsNone(store.observe(self.fixture.notice_snapshot, now=dt.datetime.now(dt.timezone.utc)))

    def test_unknown_baseline_kind_revision_or_provided_receipt_refuses_before_boundary(self):
        before = self.tree()
        for key, value in (("kind", None), ("revision", "0" * 40), ("release_sha256", "0" * 64)):
            with self.subTest(key=key):
                baseline = copy.deepcopy(self.baseline); baseline[key] = value
                with patch.object(deploy, "boundary_locks", side_effect=AssertionError("invalid baseline acquired boundary")):
                    with self.assertRaises(deploy.DeploymentError):
                        deploy.activate_coordinator(self.workspace, self.data, self.release, self.config, self.proofs,
                            self.expected, self.journal, baseline, self.readiness)
                self.assertFalse(self.journal.exists()); self.assertEqual(self.tree(), before)

    def test_candidate_cannot_change_notification_or_native_protected_source(self):
        before = self.tree()
        for key in ("scripts/youtube_worker_alerts.py", "scripts/youtube_safe_diagnostics.py",
                    "scripts/youtube_global_chunk_worker.py", "scripts/youtube_global_windows_adapter.ps1"):
            with self.subTest(key=key):
                source = {**self.source, key: b"synthetic disallowed change"}
                release = {**self.release, "files": {name: deploy.digest(raw) for name, raw in source.items()}}
                proofs = copy.deepcopy(self.proofs); proofs["release_sha256"] = deploy.digest(deploy.json_bytes(release))
                with patch.object(deploy, "source_files", return_value=source), patch.object(deploy, "boundary_locks", side_effect=AssertionError("protected source acquired boundary")):
                    with self.assertRaisesRegex(deploy.DeploymentError, "changes protected source"):
                        deploy.activate_coordinator(self.workspace, self.data, release, self.config, proofs,
                            self.expected, self.journal, self.baseline, self.readiness)
                self.assertFalse(self.journal.exists()); self.assertEqual(self.tree(), before)

    def test_native_proof_binds_original_native_release_and_immediate_deployment(self):
        for key in ("baseline_release_sha256", "baseline_deployment_sha256", "worker_sha256", "adapter_sha256"):
            with self.subTest(key=key):
                proofs = copy.deepcopy(self.proofs); proofs["native_windows"][key] = "0" * 64
                with patch.object(deploy, "boundary_locks", side_effect=AssertionError("invalid native proof acquired boundary")):
                    with self.assertRaises(deploy.DeploymentError):
                        deploy.activate_coordinator(self.workspace, self.data, self.release, self.config, proofs,
                            self.expected, self.journal, self.baseline, self.readiness)
                self.assertFalse(self.journal.exists())

    def test_unknown_or_unresolved_recovery_requests_refuse_before_boundary(self):
        for state in ("intent", "uncertain", "unexpected"):
            path = self.request(state=state)
            with self.subTest(state=state), patch.object(deploy, "boundary_locks", side_effect=AssertionError("unresolved request acquired boundary")):
                with self.assertRaises(deploy.DeploymentError): self.activate()
            self.assertFalse(self.journal.exists()); path.unlink()
        path = self.requests / "unknown.txt"; path.write_bytes(b"synthetic unexpected recovery artifact")
        with patch.object(deploy, "boundary_locks", side_effect=AssertionError("unknown artifact acquired boundary")):
            with self.assertRaises(deploy.DeploymentError): self.activate()
        self.assertFalse(self.journal.exists())

    def test_v2_armed_or_unresolved_receipt_refuses_and_nonarmed_receipts_are_preserved(self):
        for state in ("armed", "intent", "uncertain"):
            path = self.bounded_request(state)
            with self.subTest(state=state), patch.object(deploy, "boundary_locks", side_effect=AssertionError("armed request acquired boundary")):
                with self.assertRaisesRegex(deploy.DeploymentError, "armed or outcome unresolved"):
                    self.activate()
            self.assertFalse(self.journal.exists()); path.unlink()
        for state in ("held", "expired", "acknowledged"):
            path = self.bounded_request(state); before = self.tree()
            with self.subTest(state=state):
                self.activate()
                self.assertEqual(deploy.read(self.journal)["protected"][str(path)]["sha256"], deploy.digest(path.read_bytes()))
                deploy.rollback(self.journal, readiness=self.readiness)
                self.assertEqual(self.tree(), before)
            self.journal.unlink(); path.unlink()

    def test_rollback_never_erases_an_armed_grant(self):
        self.activate()
        path = self.bounded_request("armed"); armed = path.read_bytes()
        with self.assertRaisesRegex(deploy.DeploymentError, "armed or outcome unresolved"):
            deploy.rollback(self.journal, readiness=self.readiness)
        self.assertEqual(path.read_bytes(), armed)
        self.assertEqual(deploy.read(self.journal)["state"], "committed")

    def test_recovery_directory_absence_empty_set_content_and_modes_prevent_rollback_after_drift(self):
        self.activate()
        self.requests.mkdir()
        with self.assertRaisesRegex(deploy.DeploymentError, "protected state drifted"):
            deploy.rollback(self.journal, readiness=self.readiness)
        self.requests.rmdir()
        deploy.rollback(self.journal, readiness=self.readiness); self.journal.unlink()
        path = self.request(); original = path.read_bytes(), path.stat().st_mode & 0o777
        self.activate()
        row = deploy.read(path); row["updated_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
        path.write_bytes(deploy.json_bytes(row))
        with self.assertRaisesRegex(deploy.DeploymentError, "protected state drifted"):
            deploy.rollback(self.journal, readiness=self.readiness)
        path.write_bytes(original[0]); path.chmod(original[1] ^ 0o004)
        with self.assertRaisesRegex(deploy.DeploymentError, "protected state drifted"):
            deploy.rollback(self.journal, readiness=self.readiness)
        path.chmod(original[1]); deploy.rollback(self.journal, readiness=self.readiness)

    def test_recovery_request_arriving_between_preflight_and_boundary_refuses_without_journal(self):
        locks = deploy.boundary_locks
        @contextlib.contextmanager
        def raced(data, *, canary_id=None):
            with locks(data, canary_id=canary_id):
                self.request()
                yield
        with patch.object(deploy, "boundary_locks", side_effect=raced):
            with self.assertRaisesRegex(deploy.DeploymentError, "protected state changed"):
                self.activate()
        self.assertFalse(self.journal.exists())

    def test_receipt_file_and_aggregate_limits_bound_actual_reads_before_boundary(self):
        read = deploy.NotificationInventory.raw
        actual = []
        def measured(inventory, path, **options):
            before = inventory.bytes_read
            try: return read(inventory, path, **options)
            finally:
                if Path(path).parent == self.requests:
                    actual.append(inventory.bytes_read - before)
        path = self.request(); row = deploy.read(path)
        row["synthetic_padding"] = "x" * 65536
        path.write_bytes(deploy.json_bytes(row))
        with patch.object(deploy.NotificationInventory, "raw", new=measured), patch.object(deploy, "boundary_locks", side_effect=AssertionError("over-byte request acquired boundary")):
            with self.assertRaisesRegex(deploy.DeploymentError, "lifecycle binding/probe proof differs") as refused:
                self.activate()
        self.assertIsInstance(refused.exception.__context__, fixtures.gp.PoolError)
        self.assertRegex(str(refused.exception.__context__), "recovery receipt exceeds its byte contract")
        # The receipt owner rejects oversized metadata before the bounded raw
        # reader is invoked; no content read or deployment boundary is needed.
        self.assertEqual(actual, []); self.assertFalse(self.journal.exists()); path.unlink()
        for ordinal in range(20):
            path = self.bounded_request("held", checkpoint=f"{ordinal:064x}"); row = deploy.read(path)
            row["synthetic_padding"] = "x" * 58000
            path.write_bytes(deploy.json_bytes(row))
        actual.clear()
        with patch.object(deploy.NotificationInventory, "raw", new=measured), patch.object(deploy, "boundary_locks", side_effect=AssertionError("over-byte inventory acquired boundary")):
            with self.assertRaisesRegex(deploy.DeploymentError, "lifecycle binding/probe proof differs") as refused:
                self.activate()
        self.assertIsInstance(refused.exception.__context__, fixtures.gp.PoolError)
        self.assertRegex(str(refused.exception.__context__), "recovery receipt exceeds its byte contract")
        self.assertGreater(sum(actual), 0); self.assertLessEqual(sum(actual), 1048576)
        self.assertFalse(self.journal.exists())

    def test_runtime_requires_current_loaded_canary_and_supervisor(self):
        self.activate()
        path = self.workspace / "scripts/youtube_windows_deployment.py"
        spec = importlib.util.spec_from_file_location("fixture_coordinator_reader", path)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        with patch.dict(os.environ, {"OPENCLAW_YOUTUBE_DATA_ROOT": str(self.data)}):
            for canary, supervisor in ((None, self.release["files"][deploy.SUPERVISOR]),
                    ("0" * 64, self.release["files"][deploy.SUPERVISOR]),
                    (self.release["files"][deploy.COORDINATOR_FILES[0]], "0" * 64)):
                with self.assertRaisesRegex(RuntimeError, "loaded-owner"):
                    module.verify_managed_sources(self.workspace, self.config,
                        loaded_supervisor_sha256=supervisor, loaded_canary_sha256=canary)
            module.verify_managed_sources(self.workspace, self.config,
                loaded_supervisor_sha256=self.release["files"][deploy.SUPERVISOR],
                loaded_canary_sha256=self.release["files"][deploy.COORDINATOR_FILES[0]])
            module.verify_managed_sources(self.workspace, self.config,
                loaded_canary_sha256=self.release["files"][deploy.COORDINATOR_FILES[0]])

    def test_compatible_coordinator_baseline_uses_constant_ancestry(self):
        self.activate()
        first = deploy.read(self.receipt_path)
        self.baseline = first
        self.proofs["native_windows"]["baseline_deployment_sha256"] = deploy.digest(self.receipt_path.read_bytes())
        self.journal = self.workspace / ".openclaw/tmp/coordinator-second/transaction.json"
        self.proposed = deploy.coordinator_targets(self.workspace, self.data, self.release, self.config, self.source, self.baseline)
        self.expected = {str(path): deploy.digest(path.read_bytes()) for path in self.proposed}
        self.activate()
        second = deploy.read(self.receipt_path)
        self.assertEqual(second["baseline"], first["baseline"])
        self.assertEqual(second["notification_baseline"], first["notification_baseline"])
        self.assertEqual(set(second["previous"]), {"kind", "revision", "release_sha256", "receipt_sha256", "files"})
        self.assertLess(self.receipt_path.stat().st_size, 16384)
        deploy.rollback(self.journal, readiness=self.readiness)
        self.assertEqual(deploy.read(self.receipt_path), first)

    def test_coordinator_cli_refuses_windows_handoff_or_mixed_variant(self):
        with contextlib.redirect_stderr(io.StringIO()):
            for extra in (("--await-windows",), ("--notification-only",)):
                with self.subTest(extra=extra), self.assertRaises(SystemExit): self.plan(extra=extra)


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
