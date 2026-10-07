"""Managed deployment proof gates, active-lease fences and rollback preimages."""
import importlib.util
from pathlib import Path
import tempfile
import os
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
