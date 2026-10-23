"""Synthetic acquisition tests; the canonical HTTPS fetch is never executed."""

import copy
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import preflight
import release
import source_ancestry as ancestry
from test_merge_source import MergeFixture, encoded, git


class SourceAncestryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name) / "origin"
        self.root.mkdir()
        self.fixture = MergeFixture(self.root)
        self.inventory = self.fixture.save_metadata()
        self.inventory_path = self.fixture.path.with_name("patch-inventory.json")

    def acquire(self, checkout=None):
        return ancestry.acquire(self.fixture.path, self.inventory_path, checkout or self.root)

    def shallow_clone(self):
        checkout = Path(self.directory.name) / "shallow"
        subprocess.run(["git", "clone", "--quiet", "--no-tags", "--depth=1",
                        self.root.as_uri(), str(checkout)], check=True, capture_output=True)
        return checkout

    def test_fetch_argv_is_one_fixed_bounded_noninteractive_call(self):
        with patch.object(ancestry.subprocess, "run") as run:
            ancestry.fetch_source(self.root, self.fixture.source)
        run.assert_called_once()
        args, kwargs = run.call_args
        self.assertEqual(args[0], [
            "git", "--no-replace-objects", "-C", str(self.root), "fetch", "--no-tags",
            "--depth=512", "--no-recurse-submodules", "--no-auto-maintenance",
            "https://github.com/fr-meyer/openclaw.git", self.fixture.source,
        ])
        self.assertEqual(kwargs["timeout"], 180)
        self.assertEqual(kwargs["env"]["GIT_NO_LAZY_FETCH"], "1")
        self.assertEqual(kwargs["env"]["GIT_TERMINAL_PROMPT"], "0")
        self.assertTrue(kwargs["check"])

    def test_sufficient_existing_graph_is_verified_without_moving_head(self):
        f = self.fixture
        before = git(self.root, "rev-parse", "HEAD")
        with patch.object(ancestry, "fetch_source") as fetch:
            result = self.acquire()
        fetch.assert_called_once_with(self.root, f.source)
        self.assertEqual(result["status"], "verified")
        self.assertTrue(result["fetched"])
        self.assertEqual(result["fetchDepth"], 512)
        self.assertEqual(result["headSha"], before)
        self.assertEqual(git(self.root, "rev-parse", "HEAD"), before)

    def test_metadata_seal_head_is_preserved_for_existing_pr_owner(self):
        seal = self.fixture.commit("metadata seal")
        with patch.object(ancestry, "fetch_source"):
            result = self.acquire()
        self.assertEqual(result["headSha"], seal)
        self.assertEqual(result["sourceSha"], self.fixture.source)
        self.assertEqual(git(self.root, "rev-parse", "HEAD"), seal)

    def test_missing_ancestry_remains_refused_after_ineffective_fetch(self):
        checkout = self.shallow_clone()
        before = git(checkout, "rev-parse", "HEAD")
        with patch.object(ancestry, "fetch_source") as fetch:
            with self.assertRaises(release.Refusal):
                self.acquire(checkout)
        fetch.assert_called_once()
        self.assertEqual(git(checkout, "rev-parse", "HEAD"), before)

    def test_local_transport_proves_bounded_fetch_restores_ancestry(self):
        checkout = self.shallow_clone()
        before = git(checkout, "rev-parse", "HEAD")

        def local_fetch(directory, source_sha):
            self.assertEqual(directory, checkout)
            self.assertEqual(source_sha, self.fixture.source)
            # Only the network seam is substituted; real Git supplies bounded
            # ancestry and the production shared graph verifier runs unchanged.
            git(directory, "fetch", "--quiet", "--no-tags", "--depth=512",
                "--no-recurse-submodules", "--no-auto-maintenance", self.root.as_uri(), source_sha)

        with patch.object(ancestry, "fetch_source", side_effect=local_fetch) as fetch:
            result = self.acquire(checkout)
        fetch.assert_called_once()
        self.assertEqual(result["status"], "verified")
        self.assertEqual(git(checkout, "rev-parse", "HEAD"), before)

    def test_promisor_configuration_refuses_before_fetch_or_graph(self):
        git(self.root, "config", "remote.fixture.promisor", "true")
        with patch.object(ancestry, "fetch_source") as fetch:
            with patch.object(release, "check_source_graph") as graph:
                with self.assertRaisesRegex(release.Refusal, "partial_clone.unsupported"):
                    self.acquire()
        fetch.assert_not_called()
        graph.assert_not_called()

    def test_invalid_metadata_is_refused_before_fetch(self):
        self.inventory["manifestSha256"] = "0" * 64
        self.inventory_path.write_bytes(encoded(self.inventory))
        with patch.object(ancestry, "fetch_source") as fetch:
            with self.assertRaisesRegex(release.Refusal, "inventory.manifest"):
                self.acquire()
        fetch.assert_not_called()

    def test_linear_candidate_performs_no_fetch(self):
        f = self.fixture
        manifest = copy.deepcopy(f.manifest)
        manifest["source"] = {
            "baseCommit": f.common, "baseTree": f.tree(f.common),
            "patches": [{"commit": f.fork, "tree": f.tree(f.fork)}],
            "commit": f.fork, "tree": f.tree(f.fork),
        }
        f.path.write_bytes(encoded(manifest))
        inventory = copy.deepcopy(self.inventory)
        inventory["manifestSha256"] = preflight.digest(f.path)
        inventory["upstream"]["commit"] = f.common
        inventory["patches"][0]["appliedCommit"] = f.fork
        self.inventory_path.write_bytes(encoded(inventory))
        with patch.object(ancestry, "fetch_source") as fetch:
            with patch.object(release, "check_source_graph") as graph:
                result = self.acquire()
        fetch.assert_not_called()
        graph.assert_not_called()
        self.assertEqual(result["status"], "not_required_linear")
        self.assertFalse(result["fetched"])

    def test_failed_or_timed_out_fetch_has_no_retry_or_fallback(self):
        failures = [subprocess.CalledProcessError(1, ["git"], stderr="do not expose transport output"),
                    subprocess.TimeoutExpired(["git"], timeout=180)]
        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                before = git(self.root, "rev-parse", "HEAD")
                with patch.object(ancestry, "fetch_source", side_effect=failure) as fetch:
                    with self.assertRaisesRegex(release.Refusal, "ancestry.fetch.(failed|timeout)"):
                        self.acquire()
                fetch.assert_called_once()
                self.assertEqual(git(self.root, "rev-parse", "HEAD"), before)

    def test_head_movement_during_fetch_is_reported_without_reset(self):
        def moved_head(directory, _):
            git(directory, "update-ref", "HEAD", self.fixture.fork)

        with patch.object(ancestry, "fetch_source", side_effect=moved_head) as fetch:
            with self.assertRaisesRegex(release.Refusal, "ancestry.checkout.head_changed"):
                self.acquire()
        fetch.assert_called_once()
        self.assertEqual(git(self.root, "rev-parse", "HEAD"), self.fixture.fork)

    def test_metadata_movement_during_fetch_is_refused(self):
        def changed_metadata(_directory, _sha):
            value = copy.deepcopy(self.fixture.manifest)
            value["candidate"] = "changed-after-admission"
            self.fixture.path.write_bytes(encoded(value))

        with patch.object(ancestry, "fetch_source", side_effect=changed_metadata) as fetch:
            with self.assertRaisesRegex(release.Refusal, "ancestry.metadata.changed"):
                self.acquire()
        fetch.assert_called_once()

    def test_four_workflow_calls_follow_last_fetch_and_precede_verification(self):
        workflow = (Path(__file__).resolve().parents[2] /
                    ".github/workflows/fork-release-pipeline.yml").read_text()
        self.assertEqual(workflow.count("/source_ancestry.py"), 4)
        expected = (
            ("Seal exact PR head, base and changed product diff", "candidate", "trusted", "pr.py seal"),
            ("Verify source, manifest and offline PR regressions", "source", "trusted", "preflight.py"),
            ("Verify metadata PR seal before a manual candidate build", "metadata", "tooling", "pr.py seal-offline"),
            ("Verify source and run offline pipeline regressions", "source", "tooling", "preflight.py"),
        )
        for title, checkout, owner, verification in expected:
            with self.subTest(step=title):
                block = workflow.split("- name: " + title, 1)[1].split("\n      - name:", 1)[0]
                acquisition = block.index(owner + "/scripts/fork-release/source_ancestry.py")
                self.assertLess(block.rindex(" fetch "), acquisition)
                self.assertLess(acquisition, block.index(owner + "/scripts/fork-release/" + verification))
                self.assertIn("--source-dir " + checkout, block[acquisition:])


if __name__ == "__main__":
    unittest.main()
