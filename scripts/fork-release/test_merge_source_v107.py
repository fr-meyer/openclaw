"""10.7 integration and successor proof using tiny real Git object graphs."""

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import release
from test_merge_source import MergeFixture, encoded, git


LEDGER = "custom-patches/reconciliation-2026.10.7.json"
NOTE = "custom-patches/NEXT-RELEASE-2026.10.7.md"


class FutureFixture(MergeFixture):
    def __init__(self, root):
        super().__init__(root)
        self.previous_fork = self.source
        self.common107 = self.upstream
        self.write("retained.txt", "reviewed parent security repair\n")
        self.fork107 = self.commit("parent dependency repair")
        git(root, "checkout", "-q", "--detach", self.common107)
        self.write("security-only.txt", "approved security fixture\n")
        self.security = self.commit("separate approved security source")
        git(root, "checkout", "-q", "--detach", self.common107)
        self.write("upstream-only.txt", "new stable release\n")
        self.upstream107 = self.commit("new stable upstream")
        git(root, "checkout", "-q", "--detach", self.fork107)
        self.write("upstream-only.txt", "new stable release\n")
        self.write("security-only.txt", "approved security fixture\n")
        self.write(NOTE, "source-only preparation\n")
        self.write(LEDGER, "{}\n")
        git(root, "add", ".")
        tree = git(root, "write-tree")
        self.integration107 = self.commit_tree(tree, [self.fork107, self.upstream107])
        git(root, "checkout", "-q", "--detach", self.integration107)
        self.write(NOTE, "source-only dependency fixture qualification\n")
        self.first_successor = self.commit("dependency fixture successor")
        result_paths = set(git(root, "diff", "--name-only", "--no-renames",
                               self.upstream107, self.first_successor).splitlines()) - {LEDGER, NOTE}
        fork_paths = set(git(root, "diff", "--name-only", "--no-renames",
                             self.common107, self.fork107).splitlines())
        rows = []
        for path in sorted(result_paths):
            security = path == "security-only.txt"
            rows.append({
                "path": path,
                "upstream106Blob": self.blob(self.common107, path),
                "fork106SecurityBlob": self.blob(self.fork107, path),
                "upstream107Blob": self.blob(self.upstream107, path),
                "approvedSecuritySourceBlob": self.blob(self.security, path) if security else None,
                "resultBlob": self.blob(self.first_successor, path),
                "upstream107Changed": False,
                "disposition": "SECURITY_CARRIED_EXACT" if security else "CARRIED_EXACT",
                "reason": "Synthetic exact source carry, no runtime qualification.",
            })
        self.ledger107 = {
            "schema": "openclaw-v107-fork-patch-reconciliation-v1",
            "method": "Synthetic complete fork/security union.",
            "upstream106": self.common107, "fork106": self.previous_fork,
            "fork106Security": self.fork107, "upstream107": self.upstream107,
            "approvedSecuritySource": self.security,
            "previousInventory": "custom-patches/reconciliation-2026.10.6.json",
            "qualificationTransferred": False,
            "summary": {"paths": len(rows), "previousForkPaths": len(fork_paths),
                        "newUpstreamOverlapPaths": [], "securityCarryPaths": 1,
                        "textualConflicts": 0,
                        "dispositions": {"CARRIED_EXACT": len(rows) - 1, "SECURITY_CARRIED_EXACT": 1},
                        "upstreamedClaimed": 0, "retired": 0},
            "paths": rows, "devDependencyRefresh": {},
            "focusedTestSuccessor": {"base": self.first_successor,
                                     "runtimeChanged": False, "dependenciesChanged": False},
        }
        self.write(LEDGER, encoded(self.ledger107))
        self.final107 = self.commit("focused test metadata successor")
        self.source107 = {
            "baseCommit": self.upstream107, "baseTree": self.tree(self.upstream107),
            "patches": [self.identity(self.final107)],
            "commit": self.final107, "tree": self.tree(self.final107),
            "merge": {
                "schema": "openclaw.fork-source-merge.v2",
                "commonCommit": self.common107, "commonTree": self.tree(self.common107),
                "forkCommit": self.fork107, "forkTree": self.tree(self.fork107),
                "integration": self.identity(self.integration107),
                "successors": [self.identity(self.first_successor), self.identity(self.final107)],
                "securitySource": self.identity(self.security),
                "reconciliation": {"path": LEDGER, "blob": self.blob(self.final107, LEDGER),
                                   "sha256": hashlib.sha256(encoded(self.ledger107)).hexdigest()},
            },
        }

    def identity(self, commit):
        return {"commit": commit, "tree": self.tree(commit)}

    def replaced_final(self, ledger=None, changed_file=None, executable_file=None):
        git(self.root, "checkout", "-q", "--detach", self.final107)
        if ledger is not None:
            self.write(LEDGER, encoded(ledger))
        if changed_file is not None:
            self.write(changed_file, "unreviewed replacement\n")
        if executable_file is not None:
            (self.root / executable_file).chmod(0o755)
        git(self.root, "add", ".")
        tree = git(self.root, "write-tree")
        head = self.commit_tree(tree, [self.first_successor])
        source = copy.deepcopy(self.source107)
        source.update(commit=head, tree=tree, patches=[self.identity(head)])
        source["merge"]["successors"][-1] = self.identity(head)
        source["merge"]["reconciliation"].update(
            blob=self.blob(head, LEDGER),
            sha256=hashlib.sha256(git(self.root, "show", head + ":" + LEDGER).encode() + b"\n").hexdigest())
        return source


class FutureMergeSourceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.fixture = FutureFixture(Path(self.directory.name))

    def refused(self, source, reason=None):
        with self.assertRaisesRegex(release.Refusal, reason or ".*"):
            release.check_source_graph(source, self.fixture.root)

    def test_exact_integration_successors_and_security_union_pass(self):
        release.check_source_graph(self.fixture.source107, self.fixture.root)
        self.assertEqual(release.validation_node_version({"upstream": {"tag": "v2026.10.7"}}),
                         "24.22.1")

    def test_reversed_integration_parents_refused(self):
        f = self.fixture
        value = copy.deepcopy(f.source107)
        commit = f.commit_tree(f.tree(f.integration107), [f.upstream107, f.fork107])
        value["merge"]["integration"] = f.identity(commit)
        self.refused(value, "ordered parents")

    def test_missing_moved_or_reordered_successors_refused(self):
        f = self.fixture
        values = []
        value = copy.deepcopy(f.source107)
        value["merge"]["successors"].pop(0)
        values.append(value)
        value = copy.deepcopy(f.source107)
        value["merge"]["successors"][0] = f.identity(f.upstream107)
        values.append(value)
        value = copy.deepcopy(f.source107)
        value["merge"]["successors"].reverse()
        values.append(value)
        for value in values:
            self.refused(value)

    def test_missing_required_parent_object_is_refused(self):
        value = copy.deepcopy(self.fixture.source107)
        value["merge"]["forkCommit"] = "0" * 40
        with self.assertRaises((release.Refusal, subprocess.CalledProcessError)):
            release.check_source_graph(value, self.fixture.root)

    def test_wrong_tree_security_identity_and_unsupported_schema_refused(self):
        for field in ("tree", "securitySource", "schema"):
            value = copy.deepcopy(self.fixture.source107)
            if field == "tree":
                value["merge"]["integration"]["tree"] = self.fixture.tree(self.fixture.common107)
            elif field == "securitySource":
                value["merge"]["securitySource"] = self.fixture.identity(self.fixture.fork107)
            else:
                value["merge"]["schema"] = "openclaw.fork-source-merge.v3"
            self.refused(value)

    def test_ledger_and_source_file_changes_are_refused(self):
        f = self.fixture
        value = copy.deepcopy(f.source107)
        value["merge"]["reconciliation"]["sha256"] = "0" * 64
        self.refused(value, "digest changed")
        self.refused(f.replaced_final(changed_file="retained.txt"), "ledger blob changed")

    def test_every_origin_and_result_blob_is_checked(self):
        f = self.fixture
        for field in ("upstream106Blob", "fork106SecurityBlob", "upstream107Blob", "resultBlob"):
            value = copy.deepcopy(f.ledger107)
            value["paths"][0][field] = "0" * 40
            self.refused(f.replaced_final(ledger=value), "ledger blob changed")
        value = copy.deepcopy(f.ledger107)
        row = next(row for row in value["paths"] if row["path"] == "security-only.txt")
        row["approvedSecuritySourceBlob"] = "0" * 40
        self.refused(f.replaced_final(ledger=value), "ledger blob changed")

    def test_coverage_security_source_and_qualification_are_not_assertions(self):
        f = self.fixture
        mutations = [lambda ledger: ledger["paths"].pop(),
                     lambda ledger: ledger.update(qualificationTransferred=True),
                     lambda ledger: ledger["summary"].update(securityCarryPaths=0),
                     lambda ledger: ledger["focusedTestSuccessor"].update(runtimeChanged=True)]
        for mutate in mutations:
            ledger = copy.deepcopy(f.ledger107)
            mutate(ledger)
            self.refused(f.replaced_final(ledger=ledger))

    def test_exact_security_carry_checks_mode_not_only_blob(self):
        f = self.fixture
        self.refused(f.replaced_final(ledger=copy.deepcopy(f.ledger107),
                                      executable_file="security-only.txt"), "exact security carry changed")

    def test_focused_successor_cannot_claim_runtime_equivalence_after_product_change(self):
        f = self.fixture
        source = f.replaced_final(changed_file="retained.txt")
        ledger = copy.deepcopy(f.ledger107)
        row = next(row for row in ledger["paths"] if row["path"] == "retained.txt")
        row.update(resultBlob=f.blob(source["commit"], "retained.txt"),
                   disposition="ADAPTED_RELEASE_BINDING")
        ledger["summary"]["dispositions"]["CARRIED_EXACT"] -= 1
        ledger["summary"]["dispositions"]["ADAPTED_RELEASE_BINDING"] = 1
        self.refused(f.replaced_final(ledger=ledger, changed_file="retained.txt"),
                     "focused successor changed runtime")

    def test_stale_106_ledger_and_source_receipts_do_not_transfer(self):
        f = self.fixture
        self.refused(f.replaced_final(ledger=f.ledger), "10.7 merge ledger")
        old_manifest = copy.deepcopy(f.manifest)
        new_manifest = copy.deepcopy(f.manifest)
        new_manifest["source"] = f.source107
        receipt = {"schema": "openclaw.fork-release-image.v2", "inventorySha256": "a" * 64,
                   "manifestSha256": "b" * 64, "repository": old_manifest["repository"],
                   "sourceSha": old_manifest["source"]["commit"],
                   "sourceTree": old_manifest["source"]["tree"], "architecture": "amd64",
                   "indexDigest": "sha256:" + "c" * 64, "imageDigest": "sha256:" + "d" * 64,
                   "configDigest": "sha256:" + "e" * 64,
                   "producer": {"workflowSha": "f" * 40, "runId": "42", "attempt": "1"},
                   "artifactName": "fork-release-" + old_manifest["source"]["commit"] + "-42-1"}
        path = f.root / "receipt.json"
        path.write_bytes(encoded(receipt))
        with self.assertRaises(release.Refusal):
            release.receipt_at(path, new_manifest, "b" * 64, "a" * 64)


if __name__ == "__main__":
    unittest.main()
