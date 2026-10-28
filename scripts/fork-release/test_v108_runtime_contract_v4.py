"""Operational v4 Python synthetics: no application/Node/API execution."""
import contextlib
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent


def load_driver():
    published = HERE / "source_validation_v108.py"
    if published.exists():
        spec = importlib.util.spec_from_file_location("runtime_v4_owner_under_test", published)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module, HERE.parents[1]
    from install_runtime_v4 import apply_runtime_v4
    q = HERE.parent
    base = (HERE / "BASE-DRIVER.py.private").read_text()
    current = apply_runtime_v4(base, (HERE / "runtime_contract_v4.py").read_text())
    request = (q / "request-contract/request_contract_v4.py").read_text()
    pins = json.loads((q / "V4-TRUSTED-PINS.private.json").read_text())
    marker = '\nif __name__ == "__main__":'
    current = current.replace(marker, "\n" + request + "\nSTAGE_PINS = " + repr(pins) + '''
def history_checks_v4(*args):
    raise AssertionError("SYNTHETIC_HISTORY_MUST_BE_INJECTED")
''' + marker, 1)
    module = types.ModuleType("runtime_v4_owner_under_test")
    module.__file__ = str(q / "pipeline-controls/scripts/fork-release/source_validation_v108.py")
    release = types.ModuleType("release")
    class Refusal(ValueError):
        pass
    release.Refusal = Refusal
    def require(condition, reason):
        if not condition:
            raise Refusal(reason)
    release.need = require
    release.matches = lambda pattern, value: type(value) is str and __import__("re").fullmatch(pattern, value) is not None
    release.SHA = __import__("re").compile(r"[a-f0-9]{40}\Z")
    release.manifest_at = lambda p: (json.loads(p.read_bytes()), hashlib.sha256(p.read_bytes()).hexdigest())
    preflight = types.ModuleType("preflight")
    preflight.digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    with patch.dict(sys.modules, {"release": release, "preflight": preflight}):
        exec(compile(current, module.__file__, "exec"), module.__dict__)
    return module, q / "pipeline"


D, INPUT_PIPELINE = load_driver()
FIXED_NOW = datetime(2026, 10, 29, 0, 10, tzinfo=timezone.utc)
EPOCH = int(FIXED_NOW.timestamp())


class RuntimeContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="v4-runtime-synthetic-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pipeline, self.source = self.root / "pipeline", self.root / "source"
        self.source.mkdir()
        for name in ["source-request.json", "manifest.json", "patch-inventory.json", "settled-usage.json"]:
            dest = self.pipeline / D.CANDIDATE / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(INPUT_PIPELINE / D.CANDIDATE / name, dest)
        self.request = json.loads((self.pipeline / D.REQUEST).read_bytes())
        self.env = {"GITHUB_EVENT_PATH": str(self.root / "event.json"),
            "GITHUB_OUTPUT": str(self.root / "output"), "GITHUB_JOB": "admission",
            "GITHUB_RUN_ID": "999999", "SOURCE_ADMISSION_STARTED_EPOCH": str(EPOCH - 30),
            "SOURCE_JOB_STARTED_EPOCH": str(EPOCH - 30), "SOURCE_PROFILE": "compatibility",
            "SOURCE_DEADLINE_EPOCH": str(int(D.timestamp(D.V4_DEADLINE).timestamp())),
            "GH_SOURCE_READ_TOKEN": "synthetic-no-api", "PATH": "/synthetic"}
        (self.root / "event.json").write_text("{}")

    def args(self, command="admit", profile=None):
        return types.SimpleNamespace(command=command, pipeline_dir=self.pipeline,
                                     source_dir=self.source, profile=profile)

    def budget(self):
        return {"deadlineEpoch": int(D.timestamp(D.V4_DEADLINE).timestamp()),
            "profileMatrix": [{"profile": p, "minutes": D.profile_minutes_for(self.request)[p]}
                              for p in D.profiles_for(self.request)],
            "reusedProfileEvidence": {"profiles": list(D.V4_REUSED_PROFILES)}}

    def clock(self, stack):
        clock = stack.enter_context(patch.object(D, "datetime", wraps=datetime))
        clock.now.return_value = FIXED_NOW
        stack.enter_context(patch.object(D.time, "time", return_value=EPOCH))

    def cli(self, command="admit", request_change=None, equivalence_error=None):
        if request_change:
            value = copy.deepcopy(self.request)
            request_change(value)
            (self.pipeline / D.REQUEST).write_text(json.dumps(value))
        records, order = [], []
        with contextlib.ExitStack() as stack:
            self.clock(stack)
            stack.enter_context(patch.object(D.os, "environ", self.env))
            stack.enter_context(patch.object(sys, "argv", ["driver", command,
                "--pipeline-dir", str(self.pipeline), "--source-dir", str(self.source)]))
            stack.enter_context(patch.object(D, "validate_event", return_value="a" * 40))
            binding = stack.enter_context(patch.object(D, "code_binding", side_effect=lambda *a, **k: order.append("binding")))
            history = stack.enter_context(patch.object(D, "history_checks_v4", side_effect=lambda *a: (order.append("history"), self.budget())[1]))
            closure = stack.enter_context(patch.object(D, "fetch_closure", side_effect=lambda *a, **k: order.append("closure")))
            def equivalence(*args):
                order.append("equivalence")
                if equivalence_error:
                    raise equivalence_error
                return {"verified": True, "reusedReceiptSourceSha": D.V4_PARENT_SOURCE}
            eq = stack.enter_context(patch.object(D, "verify_source_equivalence_v4", side_effect=equivalence))
            stack.enter_context(patch.object(D, "summarize", side_effect=lambda value, env: records.append(value)))
            errors = stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
            result = D.entrypoint()
        return result, records, order, binding, history, closure, eq

    def test_real_v4_metadata_file_hashes_and_pins(self):
        request, manifest, digest = D.metadata(self.pipeline)
        self.assertEqual(request, self.request)
        self.assertEqual(digest, D.STAGE_PINS["manifestSha256"])
        self.assertEqual(manifest["source"]["commit"], D.STAGE_PINS["sourceSha"])

    def test_actual_cli_admits_v4_after_history_closure_equivalence(self):
        code, records, order, binding, _, _, _ = self.cli()
        self.assertEqual(code, 0)
        self.assertEqual(order, ["binding", "history", "closure", "equivalence"])
        output = Path(self.env["GITHUB_OUTPUT"]).read_text()
        matrix = json.loads(output.splitlines()[0].split("=", 1)[1])
        self.assertEqual([v["profile"] for v in matrix["include"]], D.profiles_for(self.request))
        if "doctor-1" in D.profiles_for(self.request):
            self.assertEqual(next(v["minutes"] for v in matrix["include"] if v["profile"] == "doctor-1"), 60)
        self.assertEqual(records[-1]["sourceSha"], D.STAGE_PINS["sourceSha"])
        self.assertEqual(binding.call_args.kwargs["request"], self.request)

    def test_v2_and_v3_cli_files_refused_before_matrix_or_binding(self):
        for version in [2, 3]:
            with self.subTest(version=version):
                code, records, order, *_ = self.cli(request_change=lambda r: r.update(
                    schema=f"openclaw.fork-source-validation-request.v{version}"))
                self.assertEqual(code, 2)
                self.assertEqual(order, [])
                self.assertFalse(Path(self.env["GITHUB_OUTPUT"]).exists())
                self.assertEqual(records[-1]["sourceSha"], D.STAGE_PINS["sourceSha"])
                self.assertTrue(records[-1]["failedNeedCode"].startswith("v4."))

    def test_manifest_hash_change_refused_before_binding(self):
        path = self.pipeline / D.CANDIDATE / "manifest.json"
        path.write_bytes(path.read_bytes() + b" ")
        code, records, order, *_ = self.cli()
        self.assertEqual((code, order), (2, []))
        self.assertEqual(records[-1]["failedNeedCode"], "v4.runtime_metadata_digest")

    def test_old_source_pin_in_v4_file_refused_before_binding(self):
        code, records, order, *_ = self.cli(request_change=lambda r: r.update(sourceSha=D.SOURCE))
        self.assertEqual((code, order), (2, []))
        self.assertEqual(records[-1]["failedNeedCode"], "v4.exact_reviewed_pins")

    def test_settled_prefix_file_hash_change_refused(self):
        p = self.pipeline / D.SETTLED_USAGE
        p.write_bytes(p.read_bytes() + b" ")
        code, records, order, *_ = self.cli()
        self.assertEqual((code, order), (2, []))
        self.assertEqual(records[-1]["failedNeedCode"], "v4.runtime_settled_usage_digest")

    def test_source_equivalence_failure_blocks_matrix(self):
        code, records, order, *_ = self.cli(equivalence_error=D.V4ContractRefusal("v4.exact_git_tree"))
        self.assertEqual(code, 2)
        self.assertEqual(order[-1], "equivalence")
        self.assertFalse(Path(self.env["GITHUB_OUTPUT"]).exists())
        self.assertEqual(records[-1]["failedNeedCode"], "v4.exact_git_tree")

    def test_mocked_legacy_metadata_cannot_bypass_operational_validation(self):
        legacy = dict(self.request, schema="openclaw.fork-source-validation-request.v3")
        with patch.object(D, "metadata", return_value=(legacy, {}, "d" * 64)):
            self.assertEqual(self.cli()[0], 2)

    def test_source_and_deadline_defaults_keep_legacy_but_v4_is_current(self):
        self.assertEqual(D.source_identity_for(), (D.SOURCE, D.TREE))
        self.assertEqual(D.approval_deadline_for(), "2026-10-29T00:03:19Z")
        self.assertEqual(D.source_identity_for(self.request), (D.STAGE_PINS["sourceSha"], D.STAGE_PINS["sourceTree"]))
        self.assertEqual(D.approval_deadline_for(self.request), "2026-10-30T00:03:19Z")
        self.assertEqual(set(D.profile_minutes_for(self.request)), set(D.V4_INITIAL_PROFILES))
        self.assertEqual(D.profile_minutes_for()["doctor-1"], 45)

    def test_deadline_after_old_approval_uses_new_bound_and_profile_clock(self):
        with contextlib.ExitStack() as stack:
            self.clock(stack)
            D.deadline_check(self.env, "doctor-1", self.request)
            self.assertEqual(D.profile_deadline(self.env, "doctor-1", self.request), EPOCH - 30 + 3600 - 60)
            with self.assertRaises(D.release.Refusal):
                D.deadline_check(self.env, "doctor-1")

    def test_checkout_budget_uses_same_early_clock_and_current_request(self):
        self.env["SOURCE_ADMISSION_STARTED_EPOCH"] = str(EPOCH - 420)
        code, _, _, binding, history, *_ = self.cli("checkout-budget")
        self.assertEqual(code, 0)
        self.assertEqual(Path(self.env["GITHUB_OUTPUT"]).read_text(), "checkout_minutes=7\n")
        self.assertEqual(binding.call_args.kwargs["request"], self.request)
        history.assert_not_called()

    def test_compatibility_has_both_changed_test_owners_and_current_npm_head(self):
        paths = [*D.V4_RUNTIME_COMPATIBILITY_TESTS, "test/v108-remediation-security.test.mjs"]
        commands = D.commands(self.pipeline, self.source, "compatibility", paths, self.request)
        self.assertEqual(commands[0][-1], "test/v108-remediation-security.test.mjs")
        self.assertEqual(commands[1][4:], list(D.V4_RUNTIME_COMPATIBILITY_TESTS))
        self.assertEqual(len(commands[1][4:]), 18)
        self.assertEqual(commands[2][-1], D.STAGE_PINS["sourceSha"])
        for missing in D.V4_RUNTIME_COMPATIBILITY_TESTS[-2:]:
            with self.assertRaises(D.release.Refusal):
                D.commands(self.pipeline, self.source, "compatibility", [p for p in paths if p != missing], self.request)

    def test_phase_summary_uses_request_not_legacy_source(self):
        child = Mock(returncode=0)
        child.communicate.return_value = (None, None)
        rows = []
        with patch.object(D.subprocess, "Popen", return_value=child), patch.object(D.time, "time", return_value=EPOCH), \
             patch.object(D, "summarize", side_effect=lambda row, env: rows.append(row)):
            result = D.phase_process(["benign-stub"], self.source, {},
                {"profile": "types-tests", "deadlineEpoch": EPOCH + 20, "request": self.request}, "command", 0)
        self.assertEqual(result.returncode, 0)
        self.assertTrue(all(row["sourceSha"] == D.STAGE_PINS["sourceSha"] for row in rows))
        self.assertNotEqual(rows[-1]["sourceSha"], D.SOURCE)

    def test_actual_binding_requires_current_source_tree_and_all_five_bytes(self):
        head, workflow = "a" * 40, "b" * 40
        files = [D.WORKFLOW, "scripts/fork-release/source_validation_v108.py",
                 "scripts/fork-release/preflight.py", "scripts/fork-release/release.py",
                 "scripts/fork-release/native_tests.mjs"]
        for name in files:
            p = self.pipeline / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(("synthetic-owner:" + name).encode())
        seen = []
        def read(root, *args):
            if root == self.source:
                return ((D.STAGE_PINS["sourceSha"] if args[-1] == "HEAD" else D.STAGE_PINS["sourceTree"]) + "\n").encode()
            if args == ("rev-parse", "HEAD"):
                return (head + "\n").encode()
            if args == ("rev-parse", workflow + "^1"):
                return (D.TARGET_BRANCH_TIP + "\n").encode()
            if args[0] == "show":
                name = args[1].split(":", 1)[1]
                seen.append(name)
                return (self.pipeline / name).read_bytes()
            raise AssertionError("UNEXPECTED_SYNTHETIC_GIT")
        with patch.object(D, "validate_event", return_value=head), patch.object(D, "acquire_workflow_commit"), \
             patch.object(D, "git", side_effect=read):
            D.code_binding(self.pipeline, self.source, {}, {"GITHUB_WORKFLOW_SHA": workflow}, request=self.request)
        self.assertEqual(set(seen), set(files))
        def old(root, *args):
            return (D.SOURCE + "\n").encode() if root == self.source and args[-1] == "HEAD" else read(root, *args)
        with patch.object(D, "validate_event", return_value=head), patch.object(D, "acquire_workflow_commit"), \
             patch.object(D, "git", side_effect=old), self.assertRaises(D.release.Refusal):
            D.code_binding(self.pipeline, self.source, {}, {"GITHUB_WORKFLOW_SHA": workflow}, request=self.request)

    def test_run_orders_preflight_equivalence_before_bootstrap_and_uses_current_context(self):
        order, rows = [], []
        paths = [*D.V4_RUNTIME_COMPATIBILITY_TESTS, "test/v108-remediation-security.test.mjs"]
        contexts = []
        def install(*args):
            order.append("install")
            contexts.append(args[3])
            return types.SimpleNamespace(returncode=0, timed_out=False)
        def commands(*args, **kwargs):
            order.append("commands")
            contexts.append(kwargs["context"])
            self.assertNotIn("GH_SOURCE_READ_TOKEN", args[2])
            return [0, 0, 0]
        with contextlib.ExitStack() as stack:
            self.clock(stack)
            stack.enter_context(patch.object(D, "validate_event", return_value="a" * 40))
            stack.enter_context(patch.object(D, "code_binding", side_effect=lambda *a, **k: order.append("binding")))
            stack.enter_context(patch.object(D, "source_preflight", side_effect=lambda *a: order.append("preflight")))
            stack.enter_context(patch.object(D, "verify_source_equivalence_v4", side_effect=lambda *a: (order.append("equivalence"), {})[1]))
            stack.enter_context(patch.object(D, "git", return_value=("\n".join(paths) + "\n").encode()))
            stack.enter_context(patch.object(D, "resource_check", return_value={"logicalCpus": 4}))
            bootstrap = stack.enter_context(patch.object(D, "bootstrap_pnpm", side_effect=lambda *a, **k: (order.append("bootstrap"), Path("/owned/pnpm"))[1]))
            stack.enter_context(patch.object(D, "phase_process", side_effect=install))
            stack.enter_context(patch.object(D, "run_commands", side_effect=commands))
            stack.enter_context(patch.object(D, "summarize", side_effect=lambda row, env: rows.append(row)))
            result = D.command(self.args("run", "compatibility"), self.env)
        self.assertEqual(result, 0)
        self.assertEqual(order, ["binding", "preflight", "equivalence", "bootstrap", "install", "commands"])
        self.assertEqual(bootstrap.call_args.kwargs["request"], self.request)
        self.assertTrue(all(c["request"] == self.request for c in contexts))
        self.assertTrue(all(row["sourceSha"] == D.STAGE_PINS["sourceSha"] for row in rows))

    def test_bootstrap_refusal_uses_current_source_without_starting_runtime(self):
        rows = []
        with tempfile.TemporaryDirectory(prefix="v4-no-runtime-") as directory, \
             patch.object(D.shutil, "which", return_value=None), \
             patch.object(D.subprocess, "run") as child, \
             patch.object(D, "summarize", side_effect=lambda row, env: rows.append(row)), \
             self.assertRaises(D.release.Refusal):
            D.bootstrap_pnpm(Path(directory), {"PATH": "/synthetic"}, request=self.request)
        child.assert_not_called()
        self.assertEqual(rows[-1]["sourceSha"], D.STAGE_PINS["sourceSha"])
        self.assertEqual(rows[-1]["bootstrapPhase"], "resolve-runtimes")

    def test_final_historical_eight_are_not_current_source_passes(self):
        self.env.update(SOURCE_ADMISSION_RESULT="success", SOURCE_MATRIX_RESULT="failure")
        code, records, _, *_ = self.cli("finalize")
        self.assertEqual(code, 1)
        row = records[-1]
        self.assertEqual(row["sourceSha"], D.STAGE_PINS["sourceSha"])
        self.assertEqual(row["historicalReuse"]["sourceSha"], D.V4_PARENT_SOURCE)
        self.assertEqual(row["historicalReuse"]["profiles"], list(D.V4_REUSED_PROFILES))
        self.assertFalse(row["historicalReuse"]["relabeledAsCurrentSourcePass"])

    def test_refusal_projection_never_emits_arbitrary_exception_data(self):
        secret = "SYNTHETIC_PRIVATE_ERROR_VALUE"
        code, records, *_ = self.cli(equivalence_error=D.V4ContractRefusal(secret))
        self.assertEqual(code, 2)
        self.assertEqual(records[-1]["failedNeedCode"], "v4.unprojected")
        self.assertNotIn(secret, json.dumps(records))


if __name__ == "__main__":
    unittest.main()
