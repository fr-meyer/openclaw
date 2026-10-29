"""Current V6 entrypoint synthetics; no candidate, command or remote execution."""
import contextlib
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

from test_request_contract_v6 import Fixture, STAGE, digest, encoded

HERE = Path(__file__).resolve().parent


def load_runtime():
    integrated = HERE / "source_validation_v108.py"
    path = integrated if integrated.exists() else HERE / "runtime/source_validation_v108.py"
    adjacent = HERE if integrated.exists() else STAGE / "pipeline/scripts/fork-release"
    sys.path.insert(0, str(adjacent))
    try:
        spec = importlib.util.spec_from_file_location("actual_v6_runtime_test_owner", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


D = load_runtime()
NOW = datetime(2026, 10, 29, 1, 30, tzinfo=timezone.utc)
EPOCH = int(NOW.timestamp())


class RuntimeV6Tests(unittest.TestCase):
    CANARY = "SYNTHETIC_PRIVATE_API_TOKEN_BODY_STDERR"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="v6-current-runtime-synthetic-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.pipeline, self.source = self.root / "pipeline", self.root / "source"
        self.source.mkdir()
        self.f = Fixture()
        self.manifest = {"source": {"commit": self.f.current, "tree": self.f.current_tree}, "productionEligible": False}
        self.inventory = {"synthetic": "no runtime payload"}
        self.f.pins.update(manifestSha256=digest(encoded(self.manifest)), inventorySha256=digest(encoded(self.inventory)))
        self.f.request.update(manifestSha256=self.f.pins["manifestSha256"], inventorySha256=self.f.pins["inventorySha256"])
        baseline = (STAGE / "npm-activation-r1/reconciliation-r2/CLOSED-168-BASELINE.private.json").read_bytes() if not (HERE / "source_validation_v108.py").exists() else (HERE.parents[1] / D.V6_SETTLED_USAGE_PATH).read_bytes()
        for path, raw in ((D.REQUEST, encoded(self.f.request)), (D.CANDIDATE + "/manifest.json", encoded(self.manifest)),
                (D.CANDIDATE + "/patch-inventory.json", encoded(self.inventory)), (D.V6_SETTLED_USAGE_PATH, baseline),
                (D.V6_PREPARATION_PROOF_PATH, encoded(self.f.generation))):
            p = self.pipeline / path
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(raw)
        self.env = {"GITHUB_EVENT_PATH": str(self.root / "event.json"), "GITHUB_OUTPUT": str(self.root / "output"),
            "GITHUB_RUN_ID": "94000000000", "GITHUB_JOB": "admission", "PATH": "/synthetic-no-command",
            "SOURCE_ADMISSION_STARTED_EPOCH": str(EPOCH - 30), "SOURCE_JOB_STARTED_EPOCH": str(EPOCH - 30),
            "SOURCE_PROFILE": "compatibility", "SOURCE_DEADLINE_EPOCH": str(int(D.timestamp(D.V6_DEADLINE).timestamp())),
            "GH_SOURCE_READ_TOKEN": self.CANARY, "SOURCE_ADMISSION_RESULT": "success", "SOURCE_MATRIX_RESULT": "success"}
        (self.root / "event.json").write_bytes(b"{}")
        self.pins = patch.object(D, "V6_STAGE_PINS", self.f.pins)
        self.pins.start()
        self.addCleanup(self.pins.stop)

    def budget(self):
        return {"deadlineEpoch": int(D.timestamp(D.V6_DEADLINE).timestamp()),
            "profileMatrix": [{"profile": profile, "minutes": D.V6_PROFILE_MINUTES[profile]}
                for profile in self.f.request["profiles"]], "historicalCoverageReused": False, "reusedProfileCount": 0}

    def cli(self, command="admit", failure=None, owner="history_checks_v6", profile=None):
        records, order = [], []
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.dict(D.os.environ, self.env, clear=True))
            argv = ["source_validation_v108.py", command, "--pipeline-dir", str(self.pipeline), "--source-dir", str(self.source)]
            if profile is not None: argv += ["--profile", profile]
            stack.enter_context(patch.object(sys, "argv", argv))
            stack.enter_context(patch.object(D, "validate_event", return_value="e" * 40))
            stack.enter_context(patch.object(D.release, "manifest_at", side_effect=lambda p: (json.loads(p.read_bytes()), digest(p.read_bytes()))))
            stack.enter_context(patch.object(D, "V6_PREVIOUS_PACKAGE_SHA256", digest(self.f.package_old)))
            stack.enter_context(patch.object(D, "V6_PREVIOUS_LOCK_SHA256", digest(self.f.lock_old)))
            clock = stack.enter_context(patch.object(D, "datetime", wraps=datetime))
            clock.now.return_value = NOW
            stack.enter_context(patch.object(D.time, "time", return_value=EPOCH))
            mocks = {}
            for name, label, result in (("code_binding", "binding", None),
                    ("history_checks_v6", "history", self.budget()), ("fetch_closure", "closure", None),
                    ("verify_source_equivalence_v6", "equivalence", {"synthetic": "verified"})):
                def run(*args, _name=name, _label=label, _result=result, **kwargs):
                    order.append(_label)
                    if failure is not None and _name == owner: raise failure
                    return _result
                mocks[name] = stack.enter_context(patch.object(D, name, side_effect=run))
            stack.enter_context(patch.object(D, "admission_deadline", return_value=EPOCH + 1200))
            stack.enter_context(patch.object(D, "source_preflight"))
            stack.enter_context(patch.object(D, "profile_signals", side_effect=contextlib.nullcontext))
            stack.enter_context(patch.object(D, "git", return_value=b"src/synthetic.test.ts\n"))
            stack.enter_context(patch.object(D, "resource_check", return_value={"synthetic": "resources"}))
            stack.enter_context(patch.object(D, "bootstrap_pnpm", return_value=Path("/synthetic/pnpm")))
            stack.enter_context(patch.object(D, "phase_process", return_value=types.SimpleNamespace(returncode=0, timed_out=False)))
            stack.enter_context(patch.object(D, "run_commands", return_value=[0]))
            if command == "run": stack.enter_context(patch.object(D, "commands", return_value=[["pnpm", "synthetic-no-execution"]]))
            stdout, stderr = io.StringIO(), io.StringIO()
            stack.enter_context(contextlib.redirect_stdout(stdout))
            stack.enter_context(contextlib.redirect_stderr(stderr))
            code = D.entrypoint()
        text = stdout.getvalue() + stderr.getvalue()
        self.assertNotIn(self.CANARY, text)
        for line in stdout.getvalue().splitlines():
            records.append(json.loads(line))
        return code, records, order, mocks, stderr.getvalue()

    def test_actual_current_metadata_and_admission_choose_v6_and_all15_once(self):
        code, records, order, mocks, stderr = self.cli()
        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        self.assertEqual(order, ["binding", "history", "closure", "equivalence"])
        matrix = (self.root / "output").read_text()
        self.assertEqual(matrix.count("matrix="), 1)
        self.assertEqual(len(records[-1]["profileMatrix"]), 15)
        self.assertFalse(records[-1]["historicalCoverageReused"])
        self.assertEqual(mocks["history_checks_v6"].call_args.args[-1], self.f.pins)
        self.assertEqual(mocks["verify_source_equivalence_v6"].call_args.args[3], encoded(self.f.generation))

    def test_known_v6_refusal_is_fixed_private_and_before_closure_or_matrix(self):
        code, rows, order, mocks, stderr = self.cli(failure=D.V6ContractRefusal("v6.history.preparation_artifact_identity"))
        self.assertEqual(code, 2)
        self.assertEqual(order, ["binding", "history"])
        failure = rows[-1]
        self.assertEqual(failure["failedNeedCode"], "v6.history.preparation_artifact_identity")
        self.assertEqual(failure["exceptionClass"], "V6ContractRefusal")
        self.assertEqual(failure["sourceSha"], self.f.current)
        self.assertFalse((self.root / "output").exists())
        mocks["fetch_closure"].assert_not_called()
        self.assertEqual(stderr, "source-validation: refused; inspect bounded structured admission/step diagnostics\n")

    def test_unknown_private_refusal_never_exports_error_text(self):
        code, rows, _, _, _ = self.cli(failure=D.V6ContractRefusal(self.CANARY))
        self.assertEqual(code, 2)
        self.assertEqual(rows[-1]["failedNeedCode"], "v6.unprojected")

    def test_shared_strict_history_guard_preserves_only_its_fixed_code(self):
        error = D.release.Refusal("source-validation: v5.history.fresh_jobs_complete")
        code, rows, _, _, _ = self.cli(failure=error)
        self.assertEqual(code, 2)
        self.assertEqual(rows[-1]["failedNeedCode"], "v6.shared.fresh_jobs_complete")

    def test_current_cli_refuses_old_v5_before_binding_api_or_source(self):
        value = copy.deepcopy(self.f.request)
        value["schema"] = D.V5_SCHEMA
        (self.pipeline / D.REQUEST).write_bytes(encoded(value))
        code, rows, order, mocks, _ = self.cli()
        self.assertEqual(code, 2)
        self.assertEqual(order, [])
        self.assertEqual(rows[-1]["failedNeedCode"], "v6.closed_authorized_request")
        mocks["history_checks_v6"].assert_not_called()

    def test_unbound_source_pins_project_null_without_exception_or_fallback(self):
        with patch.object(D, "V6_STAGE_PINS", None):
            code, rows, order, _, _ = self.cli()
        self.assertEqual(code, 2)
        self.assertEqual(order, [])
        self.assertIsNone(rows[-1]["sourceSha"])
        self.assertIsNone(rows[-1]["sourceTree"])

    def test_actual_metadata_refuses_missing_tampered_generation_or_inventory(self):
        original = (self.pipeline / D.V6_PREPARATION_PROOF_PATH).read_bytes()
        for mutation in ("proof", "inventory"):
            with self.subTest(mutation=mutation):
                if mutation == "proof": (self.pipeline / D.V6_PREPARATION_PROOF_PATH).write_bytes(original + b" ")
                else:
                    (self.pipeline / D.V6_PREPARATION_PROOF_PATH).write_bytes(original)
                    (self.pipeline / D.CANDIDATE / "patch-inventory.json").write_bytes(b"{}")
                code, _, order, _, _ = self.cli()
                self.assertEqual(code, 2)
                self.assertEqual(order, [])

    def test_profile_entrypoint_accepts_new_production_type_profile_without_app_calls(self):
        self.env["GITHUB_JOB"] = "source"
        code, rows, order, mocks, _ = self.cli("run", profile="types-production")
        self.assertEqual(code, 0)
        self.assertEqual(order, ["binding", "equivalence"])
        self.assertEqual(rows[-1]["profile"], "types-production")
        self.assertFalse(rows[-1]["productionAuthorized"])
        mocks["history_checks_v6"].assert_not_called()

    def test_fetch_closure_failure_reports_actual_acquisition_owner(self):
        self.env["GITHUB_JOB"] = "source"
        code, rows, order, _, _ = self.cli("fetch-closure", failure=D.release.Refusal(self.CANARY), owner="fetch_closure")
        self.assertEqual(code, 2)
        self.assertEqual(order, ["binding", "closure"])
        self.assertEqual((rows[-1]["phase"], rows[-1]["subcheck"]), ("closure", "closure.acquire"))

    def test_finalize_full_has_fresh_all15_coverage_and_truthful_failure(self):
        code, rows, order, mocks, _ = self.cli("finalize")
        self.assertEqual(code, 0)
        self.assertEqual(order, ["binding"])
        self.assertEqual(rows[-1]["coverage"], "fresh_current_candidate_all15")
        self.assertEqual(rows[-1]["requiredFullProfileCount"], 15)
        self.assertFalse(rows[-1]["historicalF5CoverageReused"])
        self.assertTrue(mocks["code_binding"].call_args.kwargs["minimal"])
        self.assertEqual(mocks["code_binding"].call_args.kwargs["request"], self.f.request)
        mocks["history_checks_v6"].assert_not_called()
        self.env["SOURCE_MATRIX_RESULT"] = "failure"
        code, rows, _, _, _ = self.cli("finalize")
        self.assertEqual(code, 1)
        self.assertEqual(rows[-1]["status"], "failed")

    def test_targeted_finalize_keeps_selected_scope_and_admission_owned_completion(self):
        self.f.targeted()
        (self.pipeline / D.REQUEST).write_bytes(encoded(self.f.request))
        code, rows, order, _, _ = self.cli("finalize")
        self.assertEqual(code, 0)
        self.assertEqual(order, ["binding"])
        self.assertEqual(rows[-1]["coverage"], "current_candidate_with_admission_verified_targeted_completion")
        self.assertEqual(rows[-1]["selectedProfiles"], ["types-tests", "compatibility"])
        self.assertEqual(rows[-1]["sourceWitness"], self.f.request["sourceWitness"])
        self.assertEqual(rows[-1]["targetedPriorCoverageVerificationOwner"], "native_admission")
        self.assertFalse(rows[-1]["historicalF5CoverageReused"])
        self.assertFalse(rows[-1]["productionAuthorized"])

    def test_current_clocks_use_new_caps_and_historical_clocks_keep_original_limits(self):
        with patch.object(D.time, "time", return_value=EPOCH):
            env = dict(self.env, SOURCE_ADMISSION_STARTED_EPOCH=str(EPOCH - 20 * 60))
            self.assertGreater(D.admission_deadline(env, self.f.request), EPOCH)
            historical = {"schema": D.V5_SCHEMA, "profilePolicy": "donor-repair-v1"}
            self.assertEqual(D.profile_minutes_for(historical)["pipeline-contracts"], 30)
            self.assertEqual(D.profile_minutes_for(self.f.request)["pipeline-contracts"], 45)
            self.assertEqual(D.profile_minutes_for(self.f.request)["doctor-1"], 90)

    def test_registry_keeps_old_python_owners_and_adds_current_contract_and_prep_owners(self):
        rows = D.commands(Path("pipeline"), Path("source"), "pipeline-contracts", [], self.f.request)
        owners = [row[-1] for row in rows]
        self.assertEqual(len(owners), len(set(owners)))
        self.assertIn("test_v108_runtime_contract_v5.py", owners)
        self.assertIn("test_historical_v5_test_inputs.py", owners)
        self.assertIn("test_npm_lock_preparation_v108.py", owners)
        for name in ("test_request_contract_v6.py", "test_history_checks_v6.py", "test_v108_runtime_contract_v6.py"):
            self.assertIn(name, owners)
        self.assertNotIn("test_v108_runtime_contract_v4.py", owners)

    def test_compatibility_keeps_all_old_owners_and_requires_npm_consumers_and_real_bundle_probe(self):
        paths = [*D.V6_RUNTIME_COMPATIBILITY_TESTS, "test/v108-remediation-security.test.mjs"]
        commands = D.commands(Path("pipeline"), Path("source"), "compatibility", paths, self.f.request)
        self.assertEqual(commands[1][4:22], list(D.V4_RUNTIME_COMPATIBILITY_TESTS))
        self.assertEqual(len(commands[1][4:]), 24)
        self.assertEqual(commands[1][-4:], ["src/infra/npm-command.test.ts", "src/infra/safe-package-install.test.ts",
            "src/plugins/install.npm-spec.test.ts", "test/scripts/npm-runner.test.ts"])
        self.assertEqual(commands[2], ["pnpm", "deps:npm-lock:check:changed", "--base", D.ORIGINAL_SOURCE, "--head", self.f.current])
        self.assertEqual(commands[3], ["node", "--input-type=module", "-e", D.V6_BUNDLED_NPM_VERSION_CHECK])
        for missing in D.V6_RUNTIME_COMPATIBILITY_TESTS:
            with self.subTest(missing=missing), self.assertRaises(D.release.Refusal):
                D.commands(Path("pipeline"), Path("source"), "compatibility", [p for p in paths if p != missing], self.f.request)


if __name__ == "__main__":
    unittest.main()
