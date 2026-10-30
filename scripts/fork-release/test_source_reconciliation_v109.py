"""Pure-control cases; only disposable Git objects are created, never shared refs."""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import source_reconciliation_v109 as checker


def load_release():
    spec = importlib.util.spec_from_file_location("v109_release_under_test", HERE / "release.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


release = load_release()


def original_release_text():
    text = (HERE / "release.py").read_text()
    text = text.replace('("v2026.10.6", "v2026.10.7", "v2026.10.8", "v2026.10.9")',
                        '("v2026.10.6", "v2026.10.7", "v2026.10.8")', 1)
    text = text.replace(
        'need(merge["schema"] in ("openclaw.fork-source-merge.v2", "openclaw.fork-source-merge.v3",\n'
        '                                 "openclaw.fork-source-merge.v4"),',
        'need(merge["schema"] in ("openclaw.fork-source-merge.v2", "openclaw.fork-source-merge.v3"),', 1)
    text = text.replace(
        '        if merge["schema"] == "openclaw.fork-source-merge.v4":\n'
        '            minimum = 0\n'
        '            need(type(successors) is list and len(successors) <= 3, "invalid 10.9 merge successor count")\n',
        '', 1)
    return text.replace(
        '    if merge.get("schema") == "openclaw.fork-source-merge.v4":\n'
        '        from source_reconciliation_v109 import check_v109_reconciliation\n'
        '        check_v109_reconciliation(source, source_dir, git=git, need=need)\n'
        '        return\n', '', 1)


def baseline_release():
    module = types.ModuleType("historical_release_under_test")
    module.__file__ = str(HERE / "release.py")
    exec(compile(original_release_text(), module.__file__, "exec"), module.__dict__)
    return module


class GitObjects:
    def __init__(self, directory):
        self.repo = Path(directory) / "synthetic.git"
        self.env = {**os.environ, "GIT_NO_LAZY_FETCH": "1", "GIT_OPTIONAL_LOCKS": "0",
                    "GIT_NO_REPLACE_OBJECTS": "1", "GIT_AUTHOR_NAME": "Synthetic",
                    "GIT_AUTHOR_EMAIL": "synthetic@example.invalid", "GIT_COMMITTER_NAME": "Synthetic",
                    "GIT_COMMITTER_EMAIL": "synthetic@example.invalid",
                    "GIT_AUTHOR_DATE": "1700000000 +0000", "GIT_COMMITTER_DATE": "1700000000 +0000"}
        self.run("init", "--bare", "--quiet", str(self.repo), outside=True)
        self.base_entries = self.entries({"app.txt": b"base\n", "upstream.txt": b"base\n",
                                          checker.LOCK_PATH: b"old-lock\n", "retired.patch": b"retire\n"})
        self.base = self.commit(self.base_entries, [], "base")
        self.fork_entries = {**self.base_entries, **self.entries({
            "app.txt": b"fork\n", checker.LOCK_PATH: b"retained-fork-lock\n",
            checker.HISTORICAL_PROOF_PATH: b"historical-proof\n"})}
        del self.fork_entries["retired.patch"]
        self.fork = self.commit(self.fork_entries, [self.base[0]], "fork")
        self.upstream_entries = {**self.base_entries, **self.entries({
            "app.txt": b"upstream\n", "upstream.txt": b"new upstream\n",
            "test/new-security.test.ts": b"old API\n"})}
        self.upstream = self.commit(self.upstream_entries, [self.base[0]], "upstream")
        self.result_entries = {**self.upstream_entries, "app.txt": self.fork_entries["app.txt"],
                               checker.LOCK_PATH: self.fork_entries[checker.LOCK_PATH],
                               checker.HISTORICAL_PROOF_PATH: self.fork_entries[checker.HISTORICAL_PROOF_PATH],
                               **self.entries({"test/new-security.test.ts": b"adapted API\n"})}
        del self.result_entries["retired.patch"]
        self.initial = self.make_result()

    def run(self, *args, data=None, outside=False):
        prefix = ["git", "--no-replace-objects", "-c", "protocol.allow=never"]
        if not outside:
            prefix += ["-C", str(self.repo)]
        return subprocess.run(prefix + list(args), env=self.env, input=data,
                              capture_output=True, check=True, timeout=20).stdout

    def entries(self, contents, mode="100644"):
        return {path: {"mode": mode, "blob": self.run("hash-object", "-w", "--stdin", data=raw).decode().strip()}
                for path, raw in contents.items()}

    def tree(self, entries):
        def write(items):
            direct = {}
            directories = {}
            for path, entry in items.items():
                if "/" in path:
                    name, rest = path.split("/", 1)
                    directories.setdefault(name, {})[rest] = entry
                else:
                    direct[path] = entry
            lines = [entry["mode"] + " blob " + entry["blob"] + "\t" + name
                     for name, entry in direct.items()]
            lines.extend("040000 tree " + write(children) + "\t" + name
                         for name, children in directories.items())
            return self.run("mktree", data=("\n".join(sorted(lines)) + "\n").encode()).decode().strip()
        return write(entries)

    def commit(self, entries, parents, message):
        tree = self.tree(entries)
        args = ["commit-tree", tree]
        for parent in parents:
            args += ["-p", parent]
        commit = self.run(*args, data=(message + "\n").encode()).decode().strip()
        return commit, tree

    @staticmethod
    def changed(before, after):
        return {name for name in before.keys() | after.keys() if before.get(name) != after.get(name)}

    def ledger(self, entries, state="pending_ci_derivation"):
        fork_changed = self.changed(self.base_entries, self.fork_entries)
        up_changed = self.changed(self.base_entries, self.upstream_entries)
        names = fork_changed | self.changed(self.upstream_entries, entries)
        names.discard(checker.PROOF_PATH)
        rows = []
        for name in sorted(names):
            if name == checker.LOCK_PATH:
                disposition = "LOCK_CONTROLLED_DERIVATION"
            elif entries.get(name) == self.fork_entries.get(name):
                disposition = "CARRIED_EXACT"
            elif name.endswith(".test.ts"):
                disposition = "ADAPTED_SECURITY_TEST"
            else:
                disposition = "MERGED_SOURCE_REVIEWED"
            rows.append({"path": name, "base108": self.base_entries.get(name),
                         "fork108": self.fork_entries.get(name), "upstream109": self.upstream_entries.get(name),
                         "result": entries.get(name), "disposition": disposition})
        result = {"schema": checker.SCHEMA, "upstream108": self.base[0], "fork108": self.fork[0],
                  "upstream109": self.upstream[0], "qualificationTransferred": False,
                  "selfExclusion": {"path": checker.PROOF_PATH, "reason": "result-blob self-reference excluded"},
                  "forkDeltaPathCount": len(fork_changed), "upstreamChangedPathCount": len(up_changed),
                  "overlapPathCount": len(fork_changed & up_changed), "lockState": state, "sourcePaths": rows}
        if state == "ci_derived":
            result["lockDerivation"] = {"runId": 123, "attempt": 1, "artifactSha256": "a" * 64,
                                        "generatedLockSha256": hashlib.sha256(self.run(
                                            "cat-file", "blob", entries[checker.LOCK_PATH]["blob"])).hexdigest(),
                                        "receiptSha256": "b" * 64}
        return copy.deepcopy(result)

    def make_result(self, *, entries=None, edit=None, state="pending_ci_derivation", parents=None,
                    integration=None, prior_successors=None, raw_edit=None):
        entries = dict(self.result_entries if entries is None else entries)
        entries.pop(checker.PROOF_PATH, None)
        # The lock must be described even while its retained input equals upstream.
        ledger = self.ledger(entries, state)
        if checker.LOCK_PATH not in [row["path"] for row in ledger["sourcePaths"]]:
            ledger["sourcePaths"].append({"path": checker.LOCK_PATH, "base108": self.base_entries[checker.LOCK_PATH],
                                         "fork108": self.fork_entries[checker.LOCK_PATH],
                                         "upstream109": self.upstream_entries[checker.LOCK_PATH],
                                         "result": entries[checker.LOCK_PATH], "disposition": "LOCK_CONTROLLED_DERIVATION"})
        if edit:
            edit(ledger)
        raw = (json.dumps(ledger, sort_keys=True) + "\n").encode()
        if raw_edit:
            raw = raw_edit(raw)
        proof_blob = self.entries({checker.PROOF_PATH: raw})[checker.PROOF_PATH]
        committed_entries = {**entries, checker.PROOF_PATH: proof_blob}
        point = self.commit(committed_entries, parents or [self.fork[0], self.upstream[0]], "result")
        integration = integration or point
        successors = list(prior_successors or [])
        if point != integration:
            successors.append({"commit": point[0], "tree": point[1]})
        source = {"baseCommit": self.upstream[0], "baseTree": self.upstream[1],
                  "patches": [{"commit": point[0], "tree": point[1]}], "commit": point[0], "tree": point[1],
                  "merge": {"schema": checker.MERGE_SCHEMA, "commonCommit": self.base[0], "commonTree": self.base[1],
                            "forkCommit": self.fork[0], "forkTree": self.fork[1],
                            "integration": {"commit": integration[0], "tree": integration[1]},
                            "successors": successors, "securitySource": {"commit": self.fork[0], "tree": self.fork[1]},
                            "reconciliation": {"path": checker.PROOF_PATH, "blob": proof_blob["blob"],
                                               "sha256": hashlib.sha256(raw).hexdigest()}}}
        return source, ledger, entries


class ReconciliationCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.fixture = GitObjects(cls.temp.name)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def check(self, record):
        source, ledger, _entries = record
        checker.check_v109_reconciliation(source, self.fixture.repo, ledger, git=release.git, need=release.need)

    def refused(self, record):
        with self.assertRaises(release.Refusal):
            self.check(record)

    def test_initial_zero_successor_proof_and_legacy_retirement(self):
        self.check(self.fixture.initial)
        self.assertEqual(release.check_source_graph(self.fixture.initial[0], self.fixture.repo)[-1],
                         (self.fixture.initial[0]["commit"], self.fixture.initial[0]["tree"]))
        self.assertEqual(self.fixture.run("for-each-ref", "--format=%(refname)").strip(), b"")

    def test_actual_ci_lock_successor_preserves_raw_trailing_newline(self):
        f = self.fixture
        entries = {**f.result_entries, **f.entries({checker.LOCK_PATH: b"new-lock\n\n"})}
        integration = (f.initial[0]["commit"], f.initial[0]["tree"])
        record = f.make_result(entries=entries, state="ci_derived", parents=[integration[0]], integration=integration)
        self.check(record)
        release.check_source_graph(record[0], f.repo)

    def test_up_to_three_generic_single_parent_successors(self):
        f = self.fixture
        integration = (f.initial[0]["commit"], f.initial[0]["tree"])
        previous = integration
        prior = []
        for number in range(3):
            entries = {**f.result_entries, **f.entries({checker.LOCK_PATH: ("lock%d\n" % number).encode()})}
            record = f.make_result(entries=entries, state="ci_derived", parents=[previous[0]],
                                   integration=integration, prior_successors=prior)
            self.check(record)
            previous = (record[0]["commit"], record[0]["tree"])
            prior = record[0]["merge"]["successors"]

    def test_wrong_origin_or_result_tree(self):
        for field in ("tree", "baseTree"):
            with self.subTest(field=field):
                record = copy.deepcopy(self.fixture.initial)
                record[0][field] = "f" * 40
                if field == "tree":
                    record[0]["patches"][0]["tree"] = "f" * 40
                    record[0]["merge"]["integration"]["tree"] = "f" * 40
                self.refused(record)

    def test_wrong_common_or_fork_tree(self):
        for field in ("commonTree", "forkTree"):
            with self.subTest(field=field):
                record = copy.deepcopy(self.fixture.initial)
                record[0]["merge"][field] = "f" * 40
                self.refused(record)

    def test_wrong_ordered_integration_parents(self):
        self.refused(self.fixture.make_result(parents=[self.fixture.upstream[0], self.fixture.fork[0]]))

    def test_security_source_is_exact_fork(self):
        record = copy.deepcopy(self.fixture.initial)
        record[0]["merge"]["securitySource"] = {"commit": self.fixture.upstream[0], "tree": self.fixture.upstream[1]}
        self.refused(record)

    def test_unique_common_ancestor_is_not_inferred(self):
        record = copy.deepcopy(self.fixture.initial)
        record[0]["merge"]["commonCommit"] = self.fixture.fork[0]
        record[0]["merge"]["commonTree"] = self.fixture.fork[1]
        self.refused(record)

    def test_qualification_cannot_transfer(self):
        self.refused(self.fixture.make_result(edit=lambda d: d.update(qualificationTransferred=True)))

    def test_origin_names_are_closed_and_bound(self):
        self.refused(self.fixture.make_result(edit=lambda d: d.update(fork108=self.fixture.upstream[0])))
        self.refused(self.fixture.make_result(edit=lambda d: d.update(extra=True)))

    def test_self_exclusion_is_only_fixed_new_proof(self):
        self.refused(self.fixture.make_result(edit=lambda d: d["selfExclusion"].update(path="other.json")))

    def test_missing_duplicate_or_spurious_path(self):
        for action in (lambda d: d["sourcePaths"].pop(),
                       lambda d: d["sourcePaths"].append(copy.deepcopy(d["sourcePaths"][0])),
                       lambda d: d["sourcePaths"].append({**d["sourcePaths"][0], "path": "extra.txt"})):
            with self.subTest(action=action):
                self.refused(self.fixture.make_result(edit=action))

    def test_new_result_path_not_in_ledger_is_refused(self):
        entries = {**self.fixture.result_entries, **self.fixture.entries({"outside.txt": b"unreviewed\n"})}
        self.refused(self.fixture.make_result(entries=entries, edit=lambda d: d.update(
            sourcePaths=[x for x in d["sourcePaths"] if x["path"] != "outside.txt"])))

    def test_derived_counts_are_exact_integers(self):
        for field in ("forkDeltaPathCount", "upstreamChangedPathCount", "overlapPathCount"):
            for value in (True, -1, 999):
                with self.subTest(field=field, value=value):
                    self.refused(self.fixture.make_result(edit=lambda d, f=field, v=value: d.update({f: v})))

    def test_wrong_actual_blob_mode_or_typed_mode(self):
        def edit(d, field, value):
            row = next(x for x in d["sourcePaths"] if x["path"] == "app.txt")
            row["result"][field] = value
        for field, value in (("mode", "100755"), ("mode", []), ("blob", "f" * 40)):
            with self.subTest(field=field, value=value):
                self.refused(self.fixture.make_result(edit=lambda d, f=field, v=value: edit(d, f, v)))

    def test_exact_carry_cannot_change_or_silently_retire(self):
        def edit(d):
            row = next(x for x in d["sourcePaths"] if x["path"] == "test/new-security.test.ts")
            row["disposition"] = "CARRIED_EXACT"
        self.refused(self.fixture.make_result(edit=edit))

    def test_historical_eight_ledger_is_exact_fork(self):
        entries = {**self.fixture.result_entries, **self.fixture.entries({checker.HISTORICAL_PROOF_PATH: b"rewritten\n"})}
        self.refused(self.fixture.make_result(entries=entries))

    def test_disposition_is_closed_and_test_means_test(self):
        def edit(d, disposition):
            next(x for x in d["sourcePaths"] if x["path"] == "app.txt")["disposition"] = disposition
        for disposition in ("UNKNOWN", "ADAPTED_SECURITY_TEST"):
            with self.subTest(disposition=disposition):
                self.refused(self.fixture.make_result(edit=lambda d, x=disposition: edit(d, x)))

    def test_path_traversal_and_pathspec_injection_refuse(self):
        for value in ("../private", ":(top)*", "/etc/passwd", "safe/../other"):
            with self.subTest(value=value):
                self.refused(self.fixture.make_result(edit=lambda d, v=value: d["sourcePaths"][0].update(path=v)))

    def test_pending_lock_requires_retained_fork_and_no_receipt(self):
        entries = {**self.fixture.result_entries, **self.fixture.entries({checker.LOCK_PATH: b"changed\n"})}
        self.refused(self.fixture.make_result(entries=entries))
        self.refused(self.fixture.make_result(edit=lambda d: d.update(lockDerivation={})))

    def test_lock_is_only_controlled_derivation_disposition(self):
        self.refused(self.fixture.make_result(edit=lambda d: next(
            x for x in d["sourcePaths"] if x["path"] == checker.LOCK_PATH).update(disposition="CARRIED_EXACT")))
        self.refused(self.fixture.make_result(edit=lambda d: next(
            x for x in d["sourcePaths"] if x["path"] == "app.txt").update(disposition="LOCK_CONTROLLED_DERIVATION")))

    def test_ci_receipt_shape_and_exact_lock_hash(self):
        for field, value in (("runId", True), ("attempt", 2), ("attempt", True),
                             ("generatedLockSha256", "c" * 64), ("artifactSha256", "bad")):
            with self.subTest(field=field, value=value):
                self.refused(self.fixture.make_result(state="ci_derived", edit=lambda d, f=field, v=value:
                                                     d["lockDerivation"].update({f: v})))

    def test_duplicate_json_key_and_nonfinite_constant_refuse(self):
        for change in (lambda raw: raw.replace(b'"qualificationTransferred": false',
                                              b'"qualificationTransferred": true, "qualificationTransferred": false'),
                       lambda raw: raw.replace(b'"qualificationTransferred": false', b'"qualificationTransferred": NaN')):
            with self.subTest(change=change):
                self.refused(self.fixture.make_result(raw_edit=change))

    def test_manifest_proof_digest_and_supplied_ledger_cannot_diverge(self):
        record = copy.deepcopy(self.fixture.initial)
        record[0]["merge"]["reconciliation"]["sha256"] = "f" * 64
        self.refused(record)
        record = copy.deepcopy(self.fixture.initial)
        record[1]["schema"] = "forged"
        self.refused(record)

    def test_source_oid_or_proof_path_cannot_choose_host_input(self):
        for field, value in (("commit", "--help"), ("proof", "../../private.json")):
            record = copy.deepcopy(self.fixture.initial)
            if field == "commit":
                record[0][field] = value
            else:
                record[0]["merge"]["reconciliation"]["path"] = value
            self.refused(record)

    def test_raw_read_size_refuses_before_body_read(self):
        for size in (b"4194305\n", b"-1\n", b"not-size\n"):
            with self.subTest(size=size), mock.patch.object(
                    checker.subprocess, "run", return_value=types.SimpleNamespace(stdout=size)) as command:
                with self.assertRaises(release.Refusal):
                    checker._raw_blob(self.fixture.repo, "a" * 40, release.need)
                self.assertEqual(command.call_count, 1)
                self.assertEqual(command.call_args.args[0][-3:], ["cat-file", "-s", "a" * 40])


class HistoricalDispatchCases(unittest.TestCase):
    def test_inverse_patch_is_exact_original_p13_bytes(self):
        self.assertEqual(hashlib.sha256(original_release_text().encode()).hexdigest(),
                         "d809c07015cd86e717c750ae87fa7849baf7e27a86209d0ca55b068c236246ac")

    @staticmethod
    def shape(schema, count):
        integration = {"commit": "1" * 40, "tree": "a" * 40}
        successors = [{"commit": format(i + 16, "040x"), "tree": format(i + 128, "040x")}
                      for i in range(count)]
        tip = successors[-1] if successors else integration
        merge = {"commonCommit": "2" * 40, "commonTree": "b" * 40, "forkCommit": "3" * 40,
                 "forkTree": "c" * 40, "reconciliation": {"path": "custom-patches/proof.json",
                     "blob": "4" * 40, "sha256": "d" * 64}}
        if schema:
            merge.update(schema=schema, integration=integration, successors=successors,
                         securitySource={"commit": "3" * 40, "tree": "c" * 40})
        return {"commit": tip["commit"], "tree": tip["tree"], "patches": [tip], "merge": merge}

    def test_v2_v3_and_default_shape_outcomes_are_unchanged(self):
        old = baseline_release()
        for schema, count in ((None, 0), ("openclaw.fork-source-merge.v2", 0),
                              ("openclaw.fork-source-merge.v2", 1), ("openclaw.fork-source-merge.v2", 16),
                              ("openclaw.fork-source-merge.v3", 0), ("openclaw.fork-source-merge.v3", 16)):
            outcomes = []
            for module in (old, release):
                try:
                    module.validate_merge_shape(self.shape(schema, count))
                    outcomes.append("passed")
                except module.Refusal as error:
                    outcomes.append(str(error))
            with self.subTest(schema=schema, count=count):
                self.assertEqual(outcomes[0], outcomes[1])

    def test_v4_zero_three_and_four_successor_shapes(self):
        release.validate_merge_shape(self.shape(checker.MERGE_SCHEMA, 0))
        release.validate_merge_shape(self.shape(checker.MERGE_SCHEMA, 3))
        with self.assertRaises(release.Refusal):
            release.validate_merge_shape(self.shape(checker.MERGE_SCHEMA, 4))

    def test_v3_and_v2_dispatch_still_reach_original_owners(self):
        old = baseline_release()
        for module in (old, release):
            for schema, expected in (("openclaw.fork-source-merge.v3", "108"),
                                     ("openclaw.fork-source-merge.v2", "107")):
                calls = []
                source = self.shape(schema, 1)
                proof = source["merge"]["reconciliation"]
                with mock.patch.object(module, "git", return_value="100644 blob " + proof["blob"] + "\t" + proof["path"]), \
                     mock.patch.object(module.subprocess, "run", return_value=types.SimpleNamespace(stdout=b"{}")), \
                     mock.patch.object(module, "sha256", return_value=proof["sha256"]), \
                     mock.patch.object(module, "check_v108_reconciliation", side_effect=lambda *a: calls.append("108")), \
                     mock.patch.object(module, "check_v107_reconciliation", side_effect=lambda *a: calls.append("107")):
                    module.check_merge_reconciliation(source, Path("unused"))
                self.assertEqual(calls, [expected])


if __name__ == "__main__":
    unittest.main()
