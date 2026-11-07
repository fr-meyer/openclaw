"""Synthetic local file/Git-response tests only; no Git/app/client is executed."""
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location("source_profile_diagnostic_v109",
    HERE / "source_profile_diagnostic_v109.py")
diag = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diag)
import sys
sys.modules[spec.name] = diag
SOURCE, TREE = "1" * 40, "2" * 40
CTX = {"runId": "123456", "runAttempt": 1, "profile": "models-1"}
REQUEST = {"source": {"sourceSha": SOURCE, "sourceTree": TREE}}


def oid(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


class Reader:
    def __init__(self, files=None, status=b" M src/file.ts\0", textual=b" M src/file.ts\n"):
        self.files = files if files is not None else {"src/file.ts": ("100644", b"before")}
        self.status, self.textual, self.calls = status, textual, []
        self.head, self.tree = SOURCE, TREE
        self.index_override, self.tree_override = None, None
        self.blobs = {oid(raw): raw for mode, raw in self.files.values() if mode != "160000"}

    def __call__(self, *args):
        self.calls.append(args)
        if args == ("rev-parse", "HEAD"):
            return self.head.encode() + b"\n"
        if args == ("rev-parse", "HEAD^{tree}"):
            return self.tree.encode() + b"\n"
        if args == ("rev-parse", SOURCE + "^{tree}"):
            return TREE.encode() + b"\n"
        if args == ("status", "--porcelain=v1", "--untracked-files=no"):
            return self.textual
        if args == ("status", "--porcelain=v1", "-z", "--untracked-files=no"):
            return self.status
        if args == ("ls-tree", "-rz", "--full-tree", SOURCE):
            return self.tree_override if self.tree_override is not None else b"".join(
                (mode + " " + ("commit" if mode == "160000" else "blob") + " " +
                 ("3" * 40 if mode == "160000" else oid(raw)) + "\t" + name).encode() + b"\0"
                for name, (mode, raw) in self.files.items())
        if args == ("ls-files", "--stage", "-z"):
            return self.index_override if self.index_override is not None else b"".join(
                (mode + " " + ("3" * 40 if mode == "160000" else oid(raw)) + " 0\t" + name).encode() + b"\0"
                for name, (mode, raw) in self.files.items())
        if len(args) == 3 and args[:2] == ("cat-file", "-s"):
            return str(len(self.blobs[args[2]])).encode() + b"\n"
        if len(args) == 3 and args[:2] == ("cat-file", "blob"):
            return self.blobs[args[2]]
        raise AssertionError("unexpected fixed Git operation")

    def observations(self):
        return {"head": self.head.encode() + b"\n", "tree": self.tree.encode() + b"\n", "status": self.textual}


class Refusal(RuntimeError):
    pass


def need(value, code):
    if not value:
        raise Refusal(code)


def post_gate(reader, emitted):
    path = HERE / "source_validation_v109.py"
    tree = ast.parse(path.read_text())
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "post_profile_binding")
    namespace = {"policy": types.SimpleNamespace(need=need), "emit": emitted.append,
        "git_read": lambda source, *args, deadline: reader(*args)}
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(path), "exec"), namespace)
    return namespace["post_profile_binding"]


class Diagnostic(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="v109-diagnostic-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        (self.root / "src").mkdir()
        (self.root / "src/file.ts").write_bytes(b"after")

    def report(self, reader=None, **kwargs):
        reader = Reader() if reader is None else reader
        return diag.report(self.root, REQUEST, reader.observations(), reader, CTX, 100, clock=lambda: 1, **kwargs)

    def test_dirty_file_before_index_after_are_separate_and_content_not_returned(self):
        value = self.report()
        row = value["paths"][0]
        self.assertEqual(row["path"], "src/file.ts")
        self.assertEqual(row["before"]["gitOid"], oid(b"before"))
        self.assertEqual(row["before"]["sha256"], hashlib.sha256(b"before").hexdigest())
        self.assertEqual(row["after"]["sha256"], hashlib.sha256(b"after").hexdigest())
        self.assertEqual(row["index"][0]["stage"], 0)
        self.assertFalse(value["rawContentReturned"])
        self.assertFalse(value["acceptanceGranted"])
        self.assertNotIn(b'"before"\n', diag.encoded(value))

    def test_head_tree_status_failures_are_distinguished_and_before_uses_bound_source(self):
        for field in ("head", "tree"):
            reader = Reader()
            setattr(reader, field, "4" * 40)
            value = self.report(reader)
            self.assertFalse(value["checks"][field]["matches"])
            self.assertFalse(value["checks"]["trackedStatus"]["clean"])
            self.assertIn(("ls-tree", "-rz", "--full-tree", SOURCE), reader.calls)
            self.assertFalse(any("4" * 40 in call for call in reader.calls))

    def test_original_status_and_nul_observation_have_independent_evidence(self):
        value = self.report(Reader(status=b"", textual=b" M src/file.ts\n"))
        self.assertFalse(value["checks"]["trackedStatus"]["clean"])
        self.assertGreater(value["rawEvidence"]["gateStatus"]["observedBytes"], 0)
        self.assertEqual(value["rawEvidence"]["nulStatus"]["observedBytes"], 0)
        self.assertEqual(value["paths"], [])

    def test_deleted_path_has_bound_before_and_explicit_absent_after(self):
        (self.root / "src/file.ts").unlink()
        value = self.report(Reader(status=b" D src/file.ts\0"))
        self.assertEqual(value["paths"][0]["after"]["kind"], "absent")

    def test_mode_change_reports_fixed_git_modes(self):
        (self.root / "src/file.ts").chmod(0o755)
        row = self.report()["paths"][0]
        self.assertEqual(row["before"]["mode"], "100644")
        self.assertEqual(row["after"]["mode"], "100755")

    def test_final_symlink_hashes_only_target_without_following(self):
        path = self.root / "src/file.ts"
        path.unlink()
        path.symlink_to("/DO-NOT-FOLLOW/private-marker")
        row = self.report()["paths"][0]
        self.assertEqual(row["after"]["kind"], "symlink")
        self.assertEqual(row["after"]["sha256"], hashlib.sha256(b"/DO-NOT-FOLLOW/private-marker").hexdigest())
        self.assertNotIn("DO-NOT-FOLLOW", json.dumps(row))

    def test_parent_symlink_is_not_traversed(self):
        (self.root / "src/file.ts").unlink()
        (self.root / "src").rmdir()
        (self.root / "outside").mkdir()
        (self.root / "outside/file.ts").write_bytes(b"private-must-not-hash")
        (self.root / "src").symlink_to(self.root / "outside")
        row = self.report()["paths"][0]
        self.assertEqual(row["unavailableCode"], "path_unavailable")
        self.assertIsNone(row["after"])

    def test_rename_unknown_destination_is_not_returned_but_known_origin_is(self):
        value = self.report(Reader(status=b"R  DO-NOT-EMIT-UNKNOWN\0src/file.ts\0"))
        self.assertEqual(value["unknownPathCount"], 1)
        self.assertEqual(value["paths"][0]["pathRole"], "origin")
        self.assertNotIn("DO-NOT-EMIT", json.dumps(value))

    def test_known_rename_both_paths_are_bound(self):
        reader = Reader({"src/file.ts": ("100644", b"before"), "src/second.ts": ("100644", b"old")},
            status=b"R  src/second.ts\0src/file.ts\0")
        self.assertEqual({p["pathRole"] for p in self.report(reader)["paths"]}, {"origin", "destination"})

    def test_malformed_nul_status_preserves_prefix_hash_not_raw(self):
        for raw in (b" M src/file.ts", b" M src/file.ts\0\0", b"R  src/file.ts\0", b"ZZ src/file.ts\0"):
            value = self.report(Reader(status=raw))
            self.assertEqual(value["paths"], [])
            self.assertTrue(value["issueCodes"])
            self.assertEqual(value["rawEvidence"]["nulStatus"]["prefixSha256"], hashlib.sha256(raw).hexdigest())

    def test_duplicate_and_traversal_paths_are_not_returned(self):
        for raw in (b" M src/file.ts\0 M src/file.ts\0", b" M ../private\0", b" M /absolute\0",
                    b" M src/secret\nvalue\0"):
            value = self.report(Reader(status=raw))
            self.assertTrue(value["issueCodes"])
            self.assertEqual(value["paths"], [])

    def test_changed_index_identity_and_unmerged_stages_are_not_hidden(self):
        reader = Reader(status=b"UU src/file.ts\0")
        reader.index_override = b"".join((f"100644 {str(i) * 40} {i}\tsrc/file.ts\0").encode() for i in (1, 2, 3))
        row = self.report(reader)["paths"][0]
        self.assertEqual([r["stage"] for r in row["index"]], [1, 2, 3])

    def test_bad_tree_and_index_are_explicit_unavailable_with_raw_hash(self):
        for field in ("tree_override", "index_override"):
            reader = Reader()
            setattr(reader, field, b"not-a-typed-metadata-stream\0")
            value = self.report(reader)
            self.assertTrue(value["issueCodes"])
            self.assertIn("boundTree" if field == "tree_override" else "index", value["rawEvidence"])

    def test_git_failure_has_no_stderr_or_exception_text(self):
        def read(*args):
            raise OSError("DO-NOT-EMIT-PRIVATE-ERROR")
        reader = Reader()
        value = diag.report(self.root, REQUEST, reader.observations(), read, CTX, 100, clock=lambda: 1)
        self.assertEqual(value["issueCodes"], ["diagnostic_unavailable"])
        self.assertNotIn("DO-NOT-EMIT", json.dumps(value))

    def test_path_cap_is_explicit_and_sorted(self):
        files = {f"src/f{i:02}.ts": ("100644", b"before") for i in range(40)}
        status = b"".join((" D " + name).encode() + b"\0" for name in files)
        value = self.report(Reader(files, status=status))
        self.assertLessEqual(len(value["paths"]), 32)
        self.assertEqual(value["omittedKnownPaths"] + len(value["paths"]), 40)
        self.assertIn("path_cap", value["issueCodes"])
        self.assertLessEqual(len(diag.encoded(value)), diag.MAX_REPORT)

    def test_metadata_cap_preserves_bounded_prefix_digest(self):
        with patch.object(diag, "MAX_METADATA", 64):
            value = self.report(Reader(status=b"M" * 100))
        fact = value["rawEvidence"]["nulStatus"]
        self.assertEqual(fact["observedBytes"], 100)
        self.assertEqual(fact["hashedPrefixBytes"], 64)
        self.assertFalse(fact["completeHash"])
        self.assertEqual(fact["prefixSha256"], hashlib.sha256(b"M" * 64).hexdigest())
        self.assertIn("metadata_cap", value["issueCodes"])

    def test_blob_and_worktree_caps_are_explicit_not_partial_full_hashes(self):
        with patch.object(diag, "MAX_FILE", 2):
            row = self.report()["paths"][0]
        self.assertEqual(row["before"]["availability"], "content_cap")
        self.assertEqual(row["after"]["availability"], "content_cap")
        self.assertIsNone(row["before"]["sha256"])
        self.assertIsNone(row["after"]["sha256"])

    def test_total_hash_budget_and_deadline_never_overrun_or_accept(self):
        with patch.object(diag, "MAX_HASH_BYTES", 128):
            value = self.report()
        self.assertLessEqual(value["hashedBytes"], 128)
        self.assertFalse(value["acceptanceGranted"])
        reader = Reader()
        value = diag.report(self.root, REQUEST, reader.observations(), reader, CTX, 1, clock=lambda: 1)
        self.assertEqual(value["issueCodes"], ["deadline"])
        self.assertEqual(reader.calls, [])

    def test_unsafe_context_values_are_not_echoed(self):
        reader = Reader()
        context = {**CTX, "profile": "DO-NOT-EMIT", "runId": "private"}
        value = diag.report(self.root, REQUEST, reader.observations(), reader, context, 100, clock=lambda: 1)
        self.assertEqual(value["issueCodes"], ["run_context"])
        self.assertIsNone(value["runId"])
        self.assertNotIn("DO-NOT-EMIT", json.dumps(value))

    def test_unchanged_source_succeeds_without_diagnostic_or_extra_git_reads(self):
        reader, emitted = Reader(status=b"", textual=b""), []
        post_gate(reader, emitted)(self.root, REQUEST, 100, CTX)
        self.assertEqual(emitted, [])
        self.assertEqual(len(reader.calls), 3)

    def test_runtime_evaluates_all_three_subchecks_and_preserves_exact_refusal(self):
        reader, emitted = Reader(), []
        reader.head, reader.tree = "4" * 40, "5" * 40
        with self.assertRaisesRegex(Refusal, "^v9.profile_changed_tracked_source$"):
            post_gate(reader, emitted)(self.root, REQUEST, 99999999999, CTX)
        self.assertEqual(reader.calls[:3], [("rev-parse", "HEAD"), ("rev-parse", "HEAD^{tree}"),
            ("status", "--porcelain=v1", "--untracked-files=no")])
        self.assertEqual(len(emitted), 1)
        self.assertFalse(emitted[0]["checks"]["head"]["matches"])
        self.assertFalse(emitted[0]["checks"]["tree"]["matches"])

    def test_failed_gate_read_retains_other_observations_without_private_error(self):
        reader, emitted = Reader(), []
        def failed(*args):
            if args == ("rev-parse", "HEAD"):
                raise OSError("DO-NOT-EMIT-PRIVATE-ERROR")
            return reader(*args)
        with self.assertRaisesRegex(Refusal, "^v9.profile_changed_tracked_source$"):
            post_gate(failed, emitted)(self.root, REQUEST, 99999999999, CTX)
        value = emitted[0]
        self.assertFalse(value["checks"]["head"]["available"])
        self.assertTrue(value["checks"]["tree"]["matches"])
        self.assertFalse(value["checks"]["trackedStatus"]["clean"])
        self.assertNotIn("DO-NOT-EMIT", json.dumps(value))

    def test_wrong_bound_tree_or_blob_identity_is_not_asserted_as_before(self):
        for kind in ("tree", "blob"):
            reader = Reader()
            def read(*args):
                if kind == "tree" and args == ("rev-parse", SOURCE + "^{tree}"):
                    return b"4" * 40 + b"\n"
                if kind == "blob" and len(args) == 3 and args[:2] == ("cat-file", "blob"):
                    return b"spoof!"
                return reader(*args)
            value = diag.report(self.root, REQUEST, reader.observations(), read, CTX, 100, clock=lambda: 1)
            if kind == "tree":
                self.assertEqual(value["issueCodes"], ["bound_tree_identity"])
            else:
                self.assertEqual(value["paths"][0]["unavailableCode"], "blob_response")
                self.assertIsNone(value["paths"][0]["before"]["sha256"])

    def test_report_cap_is_honest_and_unknown_issue_strings_never_escape(self):
        files = {"src/" + ("a" * 200) + str(i) + ".ts": ("100644", b"before") for i in range(32)}
        value = self.report(Reader(files, status=b"".join((" D " + n).encode() + b"\0" for n in files)))
        self.assertLessEqual(len(diag.encoded(value)), 32 * 1024)
        self.assertEqual(len(value["paths"]) + value["omittedKnownPaths"], 32)
        self.assertIn("report_cap", value["issueCodes"])
        self.assertEqual(diag.issue(diag.Unavailable("PRIVATE-NOT-A-CODE")), "diagnostic_unavailable")

    def test_report_and_output_failures_never_turn_refusal_into_success(self):
        for mode in ("report", "output"):
            reader, emitted = Reader(), []
            gate = post_gate(reader, emitted)
            if mode == "output":
                gate.__globals__["emit"] = lambda value: (_ for _ in ()).throw(OSError("PRIVATE"))
                context = patch.object(diag, "report", wraps=diag.report)
            else:
                context = patch.object(diag, "report", side_effect=ValueError("PRIVATE"))
            with context, self.assertRaisesRegex(Refusal, "^v9.profile_changed_tracked_source$"):
                gate(self.root, REQUEST, 99999999999, CTX)
            self.assertNotIn("PRIVATE", json.dumps(emitted))

    def test_registration_actual_module_and_presence_ast_gate(self):
        path = HERE / "source_validation_selection_v109.py"
        tree = ast.parse(path.read_text())
        names = ast.literal_eval(next(n.value for n in tree.body if isinstance(n, ast.Assign) and
            any(isinstance(t, ast.Name) and t.id == "PIPELINE_CONTRACT_TESTS" for t in n.targets)))
        name = Path(__file__).name
        self.assertEqual(names.count(name), 1)
        nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in
            ("_need", "verify_pipeline_contract_files")]
        ns = {"ast": ast, "contract": types.SimpleNamespace(need=need, Refusal=Refusal),
            "PIPELINE_CONTRACT_TESTS": (name,)}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec"), ns)
        gate = ns["verify_pipeline_contract_files"]
        self.assertEqual(gate(lambda p: Path(__file__).read_bytes())["fixedTestModules"], [name])
        for raw in (b"", b"def invalid(:", b"# no tests\n"):
            with self.assertRaises(Refusal):
                gate(lambda p: raw)
        with self.assertRaises(FileNotFoundError):
            gate(lambda p: (_ for _ in ()).throw(FileNotFoundError()))
        runtime = ast.parse((HERE / "source_validation_v109.py").read_text())
        paths = next(n.value for n in runtime.body if isinstance(n, ast.Assign) and
            any(isinstance(t, ast.Name) and t.id == "CODE_PATHS" for t in n.targets))
        self.assertIn("scripts/fork-release/source_profile_diagnostic_v109.py",
            [n.value for n in ast.walk(paths) if isinstance(n, ast.Constant)])


if __name__ == "__main__":
    unittest.main()
