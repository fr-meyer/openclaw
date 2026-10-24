"""Offline merge-source contracts proved with tiny, real Git object graphs."""

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import preflight
import pr
import release


RECONCILIATION = "custom-patches/reconciliation-2026.10.6.json"
METHOD = (
    "Complete exact-tree inventory of every changed path between upstream10.5 and fork10.5. "
    "Result blobs bind the source preparation tree; dispositions are source review, never "
    "runtime qualification. No retired paths or claimed semantic upstream equivalents without evidence."
)


def git(root, *args, data=None):
    return subprocess.run(
        ["git", "-C", str(root), "-c", "commit.gpgsign=false", *args],
        input=data, capture_output=True, text=True, check=True,
    ).stdout.strip()


def encoded(value):
    return (json.dumps(value, indent=2) + "\n").encode()


class MergeFixture:
    def __init__(self, root):
        self.root = root
        git(root, "init", "-q")
        git(root, "config", "user.email", "merge-test@example.invalid")
        git(root, "config", "user.name", "Merge Test")
        self.write("src/a.test.ts", "test('a', () => {});\n")
        self.write("src/b.test.ts", "test('b', () => {});\n")
        self.write("shared.txt", "common\n")
        self.write("retained.txt", "common\n")
        self.common = self.commit("common upstream")
        self.write("shared.txt", "fork\n")
        self.write("retained.txt", "downstream behavior\n")
        self.write("fork-only.txt", "downstream addition\n")
        self.fork = self.commit("retained fork changes")
        git(root, "checkout", "-q", "--detach", self.common)
        self.write("shared.txt", "new upstream\n")
        self.write("upstream-only.txt", "new upstream addition\n")
        self.upstream = self.commit("target upstream")
        git(root, "checkout", "-q", "--detach", self.fork)
        self.write("shared.txt", "new upstream plus downstream behavior\n")
        self.write("upstream-only.txt", "new upstream addition\n")
        git(root, "add", ".")
        result_tree = git(root, "write-tree")
        rows = []
        for path in ("fork-only.txt", "retained.txt", "shared.txt"):
            overlap = path == "shared.txt"
            rows.append({
                "path": path,
                "upstream105Blob": self.blob(self.common, path),
                "fork105Blob": self.blob(self.fork, path),
                "upstream106Blob": self.blob(self.upstream, path),
                "resultBlob": self.blob(result_tree, path),
                "upstreamChanged": overlap,
                "disposition": "MERGED_SOURCE_REVIEWED" if overlap else "CARRIED_EXACT",
                "reason": "Synthetic source reconciliation; no runtime qualification.",
            })
        self.ledger = {
            "schema": "openclaw-v106-fork-patch-reconciliation-v1", "method": METHOD,
            "upstream105": self.common, "fork105": self.fork, "upstream106": self.upstream,
            "qualificationTransferred": False,
            "summary": {"paths": 3, "upstreamOverlap": 1, "textualConflictsResolved": 1,
                        "dispositions": {"CARRIED_EXACT": 2, "MERGED_SOURCE_REVIEWED": 1},
                        "upstreamedExact": 0, "retired": 0},
            "carryForwardCommits": [self.fork], "conflictPaths": ["shared.txt"], "paths": rows,
        }
        self.write(RECONCILIATION, encoded(self.ledger))
        git(root, "add", ".")
        tree = git(root, "write-tree")
        self.source = self.commit_tree(tree, [self.fork, self.upstream])
        git(root, "checkout", "-q", "--detach", self.source)
        self.manifest = {
            "schema": "openclaw.fork-release.v1", "repository": "fr-meyer/openclaw",
            "candidate": "v2026.10.6-fixture", "productionEligible": False,
            "source": {
                "baseCommit": self.upstream, "baseTree": self.tree(self.upstream),
                "patches": [{"commit": self.source, "tree": tree}],
                "commit": self.source, "tree": tree,
                "merge": {
                    "commonCommit": self.common, "commonTree": self.tree(self.common),
                    "forkCommit": self.fork, "forkTree": self.tree(self.fork),
                    "reconciliation": {"path": RECONCILIATION,
                                       "blob": self.blob(self.source, RECONCILIATION),
                                       "sha256": hashlib.sha256(encoded(self.ledger)).hexdigest()},
                },
            },
            "gates": {"patchLifecycle": ["src/a.test.ts"], "producerConsumer": ["src/b.test.ts"]},
            "image": {"architecture": "amd64", "extensions": "codex,workboard"},
            "review": {"prNumber": 19, "baseSha": self.fork,
                       "changedDiffSha256": self.diff_hash(self.fork, self.source)},
        }
        # A real annotated tag object, without publishing or creating any tag ref.
        self.tag = git(root, "hash-object", "-w", "-t", "tag", "--stdin", data=(
            f"object {self.upstream}\ntype commit\ntag v2026.10.6\n"
            "tagger Merge Test <merge-test@example.invalid> 1700000000 +0000\n\nFixture release\n"))
        self.path = root / "scripts/fork-release/manifest.json"

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value if isinstance(value, bytes) else value.encode())

    def commit(self, message):
        git(self.root, "add", ".")
        git(self.root, "commit", "-qm", message)
        return git(self.root, "rev-parse", "HEAD")

    def commit_tree(self, tree, parents):
        args = ["commit-tree", tree]
        for parent in parents:
            args.extend(["-p", parent])
        return git(self.root, *args, data="Synthetic candidate\n")

    def tree(self, commit):
        return git(self.root, "rev-parse", f"{commit}^{{tree}}")

    def blob(self, commit, path):
        item = git(self.root, "ls-tree", commit, "--", path)
        return item.split()[2] if item else None

    def diff_hash(self, base, head):
        raw = subprocess.run(["git", "-C", str(self.root), "diff", "--binary", "--full-index",
                              "--no-ext-diff", base, head], check=True, capture_output=True).stdout
        return hashlib.sha256(raw).hexdigest()

    def replaced_source(self, parents=None, ledger=None):
        """Bind modified bytes honestly, so refusals must validate their semantics."""
        tree = self.manifest["source"]["tree"]
        if ledger is not None:
            self.write(RECONCILIATION, encoded(ledger))
            git(self.root, "add", RECONCILIATION)
            tree = git(self.root, "write-tree")
        commit = self.commit_tree(tree, parents if parents is not None else [self.fork, self.upstream])
        source = copy.deepcopy(self.manifest["source"])
        source.update(commit=commit, tree=tree, patches=[{"commit": commit, "tree": tree}])
        if ledger is not None:
            source["merge"]["reconciliation"].update(
                blob=self.blob(commit, RECONCILIATION), sha256=hashlib.sha256(encoded(ledger)).hexdigest())
        return source

    def save_metadata(self):
        self.write("scripts/fork-release/manifest.json", encoded(self.manifest))
        paths = git(self.root, "diff", "--name-only", "--no-renames", self.upstream, self.source).splitlines()
        ledger = []
        for path in paths:
            origin = self.fork if self.blob(self.fork, path) is not None else self.source
            ledger.append({"path": path, "boundary": "container", "sourceCommit": origin,
                           "sourceTree": self.tree(origin), "sourceBlob": self.blob(origin, path),
                           "upstreamBlob": self.blob(self.upstream, path),
                           "candidateBlob": self.blob(self.source, path)})
        inventory = {
            "schema": "openclaw.fork-patch-inventory.v1", "repository": self.manifest["repository"],
            "candidate": self.manifest["candidate"], "manifestSha256": preflight.digest(self.path),
            "upstream": {"tag": "v2026.10.6", "tagObject": self.tag, "commit": self.upstream,
                         "verificationSha256": "a" * 64},
            "patches": [{"id": "reconciled-fork", "originCommit": self.fork, "disposition": "adapt",
                         "appliedCommit": self.source, "rationale": "Preserve the reconciled fork changes.",
                         "evidenceSha256": self.manifest["source"]["merge"]["reconciliation"]["sha256"],
                         "regressionTests": ["src/a.test.ts"], "dependsOn": [],
                         "regressionOwner": "fixture", "paths": ledger}],
        }
        self.write("scripts/fork-release/patch-inventory.json", encoded(inventory))
        return inventory


class MergeSourceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.fixture = MergeFixture(Path(self.directory.name))

    def assert_graph_refused(self, source):
        with self.assertRaises(release.Refusal):
            release.check_source_graph(source, self.fixture.root)

    def test_real_merge_passes_all_source_and_pr_consumers(self):
        f = self.fixture
        inventory = f.save_metadata()
        manifest, digest = release.manifest_at(f.path)
        release.check_source_graph(manifest["source"], f.root)
        release.check_source(manifest, f.root)
        preflight.inventory_at(f.path.with_name("patch-inventory.json"), manifest, digest, f.root)
        derived = pr.derived_binding(manifest, f.root, f.source, f.fork)
        self.assertEqual(derived["source"], manifest["source"])
        self.assertEqual(derived["changedDiffSha256"], f.diff_hash(f.fork, f.source))
        self.assertNotEqual(derived["changedDiffSha256"], f.diff_hash(f.upstream, f.source))
        self.assertEqual(pr.generate_binding(f.path, f.root, manifest["candidate"], 19, f.fork), manifest)
        self.assertEqual(pr.validate_binding(f.path, f.root)["sourceSha"], f.source)
        self.assertEqual(inventory["upstream"]["commit"], f.upstream)

    def test_merge_metadata_seal_keeps_qualified_product_identity(self):
        f = self.fixture
        f.save_metadata()
        seal = f.commit("metadata seal")
        evidence = pr.offline_release_seal(f.path, f.root)
        self.assertEqual(evidence["headSha"], seal)
        self.assertEqual(evidence["sourceSha"], f.source)
        self.assertEqual(evidence["sourceTree"], f.manifest["source"]["tree"])
        self.assertEqual(evidence["changedDiffSha256"], f.diff_hash(f.fork, f.source))
        self.assertFalse(f.manifest["productionEligible"])

    def test_wrong_reversed_extra_and_descendant_parents_are_refused(self):
        f = self.fixture
        for parents in ([f.upstream, f.fork], [f.common, f.upstream],
                        [f.fork, f.upstream, f.common], [f.source]):
            with self.subTest(parents=parents):
                self.assert_graph_refused(f.replaced_source(parents=parents))

    def test_replace_object_cannot_hide_wrong_merge_parents(self):
        f = self.fixture
        bad = f.replaced_source(parents=[f.upstream, f.fork])
        git(f.root, "replace", bad["commit"], f.source)
        # Ordinary Git observes the replacement; both contract owners must
        # inspect the pinned object's real parents instead.
        self.assertEqual(git(f.root, "show", "-s", "--format=%P", bad["commit"]),
                         f.fork + " " + f.upstream)
        self.assertEqual(release.git(f.root, "show", "-s", "--format=%P", bad["commit"]),
                         f.upstream + " " + f.fork)
        self.assertEqual(pr.git(f.root, "show", "-s", "--format=%P", bad["commit"]),
                         f.upstream + " " + f.fork)
        self.assert_graph_refused(bad)
        manifest = copy.deepcopy(f.manifest)
        manifest["source"] = bad
        with self.assertRaises(release.Refusal):
            pr.derived_binding(manifest, f.root, bad["commit"], f.fork)

    def test_every_pinned_tree_and_common_identity_is_checked(self):
        f = self.fixture
        for owner, key in (("source", "baseTree"), ("source", "tree"),
                           ("merge", "commonTree"), ("merge", "forkTree"),
                           ("merge", "commonCommit"), ("merge", "forkCommit")):
            with self.subTest(field=key):
                value = copy.deepcopy(f.manifest["source"])
                target = value if owner == "source" else value["merge"]
                target[key] = f.upstream if key.endswith("Commit") else f.tree(f.upstream)
                if key == "baseTree":
                    target[key] = f.tree(f.common)
                if key == "tree":
                    value["patches"][0]["tree"] = target[key]
                self.assert_graph_refused(value)

    def test_merge_requires_exactly_one_declared_source_patch(self):
        value = copy.deepcopy(self.fixture.manifest["source"])
        value["patches"].insert(0, {"commit": self.fixture.fork, "tree": self.fixture.tree(self.fixture.fork)})
        self.assert_graph_refused(value)

    def test_reconciliation_file_blob_and_digest_are_bound(self):
        for key, replacement in (("path", "shared.txt"), ("blob", "0" * 40), ("sha256", "0" * 64)):
            with self.subTest(field=key):
                value = copy.deepcopy(self.fixture.manifest["source"])
                value["merge"]["reconciliation"][key] = replacement
                self.assert_graph_refused(value)

    def test_reconciliation_cannot_omit_a_carried_path_or_commit(self):
        f = self.fixture
        for field in ("paths", "carryForwardCommits"):
            with self.subTest(field=field):
                ledger = copy.deepcopy(f.ledger)
                ledger[field].pop(0)
                if field == "paths":
                    ledger["summary"]["paths"] -= 1
                    ledger["summary"]["dispositions"]["CARRIED_EXACT"] -= 1
                self.assert_graph_refused(f.replaced_source(ledger=ledger))

    def test_all_four_reconciliation_blobs_are_verified(self):
        for key in ("upstream105Blob", "fork105Blob", "upstream106Blob", "resultBlob"):
            with self.subTest(field=key):
                ledger = copy.deepcopy(self.fixture.ledger)
                ledger["paths"][-1][key] = "0" * 40
                self.assert_graph_refused(self.fixture.replaced_source(ledger=ledger))

    def test_reconciliation_summary_overlap_and_qualification_are_not_assertions(self):
        f = self.fixture
        mutations = [
            lambda x: x.update(qualificationTransferred=True),
            lambda x: x["paths"][-1].update(upstreamChanged=False),
            lambda x: x["summary"].update(paths=4),
            lambda x: x["summary"].update(upstreamOverlap=0),
            lambda x: x["summary"].update(textualConflictsResolved=0),
            lambda x: x["summary"].update(retired=1),
            lambda x: x["summary"].update(upstreamedExact=1),
            lambda x: x["summary"]["dispositions"].update(CARRIED_EXACT=3),
            lambda x: x.update(conflictPaths=["not-a-carried-path.txt"]),
            lambda x: x.update(carryForwardCommits=[f.upstream]),
            lambda x: x["paths"][0].update(disposition="CARRIED_EXACT", resultBlob=f.blob(f.source, "shared.txt")),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                ledger = copy.deepcopy(f.ledger)
                mutate(ledger)
                self.assert_graph_refused(f.replaced_source(ledger=ledger))

    def test_exact_carry_checks_file_mode_as_well_as_blob(self):
        f = self.fixture
        git(f.root, "update-index", "--chmod=+x", "fork-only.txt")
        # Executable-bit mutation leaves all four recorded blob IDs unchanged.
        changed = f.replaced_source(ledger=copy.deepcopy(f.ledger))
        self.assertEqual(f.blob(changed["commit"], "fork-only.txt"), f.blob(f.fork, "fork-only.txt"))
        self.assert_graph_refused(changed)

    def test_preflight_rejects_tag_bound_to_fork_instead_of_target(self):
        f = self.fixture
        inventory = f.save_metadata()
        inventory["upstream"]["tagObject"] = git(f.root, "hash-object", "-w", "-t", "tag", "--stdin", data=(
            f"object {f.fork}\ntype commit\ntag v2026.10.6\n"
            "tagger Merge Test <merge-test@example.invalid> 1700000000 +0000\n\nWrong target\n"))
        f.write("scripts/fork-release/patch-inventory.json", encoded(inventory))
        manifest, digest = release.manifest_at(f.path)
        with self.assertRaisesRegex(release.Refusal, "upstream.tag.binding"):
            preflight.inventory_at(f.path.with_name("patch-inventory.json"), manifest, digest, f.root)

    def test_pr_refuses_stale_diff_and_metadata_with_product_changes(self):
        f = self.fixture
        f.save_metadata()
        f.manifest["review"]["changedDiffSha256"] = f.diff_hash(f.upstream, f.source)
        f.write("scripts/fork-release/manifest.json", encoded(f.manifest))
        with self.assertRaises(release.Refusal):
            pr.validate_binding(f.path, f.root)
        f.manifest["review"]["changedDiffSha256"] = f.diff_hash(f.fork, f.source)
        f.save_metadata()
        f.write("unreviewed-product.txt", "not metadata\n")
        f.commit("bad seal")
        with self.assertRaisesRegex(release.Refusal, "seal commit must change exactly"):
            pr.offline_release_seal(f.path, f.root)

    def test_linear_source_remains_valid_and_cannot_hide_a_merge(self):
        f = self.fixture
        source = {"baseCommit": f.common, "baseTree": f.tree(f.common),
                  "patches": [{"commit": f.fork, "tree": f.tree(f.fork)}],
                  "commit": f.fork, "tree": f.tree(f.fork)}
        release.check_source_graph(source, f.root)
        derived = pr.derived_binding({"source": source}, f.root, f.fork, f.common)
        self.assertEqual(derived["source"], source)
        unmarked = copy.deepcopy(f.manifest["source"])
        del unmarked["merge"]
        self.assert_graph_refused(unmarked)

    def test_preflight_routes_merge_parent_refusal_through_shared_graph(self):
        f = self.fixture
        manifest = copy.deepcopy(f.manifest)
        manifest["source"] = f.replaced_source(parents=[f.upstream, f.fork])
        checks = preflight.Checks()
        preflight.source_checks(checks, manifest, f.root, [], None, check_head=False)
        self.assertIn("source.graph.refused", checks.errors)

    def test_partial_clone_is_refused_before_any_graph_or_object_probe(self):
        f = self.fixture
        git(f.root, "config", "remote.fixture.promisor", "true")
        checks = preflight.Checks()
        with patch.object(release, "git", side_effect=AssertionError("unexpected object probe")):
            preflight.source_checks(checks, f.manifest, f.root, [], None)
        self.assertEqual(checks.errors, ["source.partial_clone.unsupported"])

    def test_missing_merge_history_needs_ancestry_not_only_tip_objects(self):
        f = self.fixture
        inventory = f.save_metadata()
        required = preflight.history_commits(inventory, f.manifest)
        self.assertEqual(set(required), {f.common, f.fork, f.upstream, f.source})
        with tempfile.TemporaryDirectory() as directory:
            checkout = Path(directory) / "shallow"
            subprocess.run(["git", "clone", "--quiet", "--no-tags", "--depth=1",
                            f.root.as_uri(), str(checkout)], check=True, capture_output=True)
            checks = preflight.Checks()
            preflight.source_checks(checks, f.manifest, checkout, [], None)
            self.assertIn("source.graph.refused", checks.errors)
            # All exact objects can exist while shallow boundaries still hide
            # the merge ancestry. Tip acquisition must not be mistaken for proof.
            for commit in required:
                git(checkout, "fetch", "--quiet", "--no-tags", "--depth=1", "origin", commit)
            for commit in required:
                self.assertEqual(git(checkout, "cat-file", "-t", commit), "commit")
            checks = preflight.Checks()
            preflight.source_checks(checks, f.manifest, checkout, [], None)
            self.assertIn("source.graph.refused", checks.errors)
            # Bounded local transport supplies this tiny fixture's complete
            # ancestry. No network or real repository history is accessed.
            git(checkout, "fetch", "--quiet", "--no-tags", "--depth=3", "origin", f.source)
            checks = preflight.Checks()
            preflight.source_checks(checks, f.manifest, checkout, [], None)
            self.assertEqual(checks.errors, [])

    def test_image_receipt_cannot_transfer_across_changed_merge_metadata(self):
        f = self.fixture
        f.save_metadata()
        manifest, manifest_hash = release.manifest_at(f.path)
        inventory_hash = preflight.digest(f.path.with_name("patch-inventory.json"))
        producer = {"kind": "gcp", "toolingSha": "1" * 40, "operationId": "2" * 32,
                    "attempt": "1", "executionSha256": "3" * 64}
        receipt = {
            "schema": "openclaw.fork-release-image.v2", "repository": manifest["repository"],
            "manifestSha256": manifest_hash, "inventorySha256": inventory_hash,
            "sourceSha": f.source, "sourceTree": manifest["source"]["tree"],
            "architecture": "amd64", "indexDigest": "sha256:" + "4" * 64,
            "imageDigest": "sha256:" + "5" * 64, "configDigest": "sha256:" + "6" * 64,
            "producer": producer, "artifactName": release.image_artifact_name(f.source, producer),
            "review": {**manifest["review"], "headSha": f.source},
        }
        path = f.root / "synthetic-image-receipt.json"
        path.write_bytes(encoded(receipt))
        self.assertEqual(release.receipt_at(path, manifest, manifest_hash, inventory_hash), receipt)
        changed = copy.deepcopy(manifest)
        changed["source"]["merge"]["reconciliation"]["sha256"] = "0" * 64
        changed_hash = hashlib.sha256(encoded(changed)).hexdigest()
        with self.assertRaisesRegex(release.Refusal, "another manifest"):
            release.receipt_at(path, changed, changed_hash, inventory_hash)
        with self.assertRaisesRegex(release.Refusal, "inventory mismatch"):
            release.receipt_at(path, manifest, manifest_hash, "0" * 64)
        changed = copy.deepcopy(manifest)
        changed["source"]["commit"] = f.upstream
        with self.assertRaisesRegex(release.Refusal, "source mismatch"):
            release.receipt_at(path, changed, manifest_hash, inventory_hash)


if __name__ == "__main__":
    unittest.main()
