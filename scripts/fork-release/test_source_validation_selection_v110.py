"""Synthetic selection and pre-checkout gate tests; never run candidate code."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
import source_contract_v110 as contract
import source_validation_selection_v110 as selection

FIXTURES = Path(__file__).parent / "fixtures"


def inventory():
    # Context for the fixed full-family checks; expected behavior below names
    # independent external contracts rather than comparing generated inventories.
    return sorted(set(selection.REQUIRED_SOURCE_TESTS + selection.REQUIRED_HELPERS +
        tuple(selection.legacy.V6_RUNTIME_COMPATIBILITY_TESTS) +
        tuple("test/" + name for name in selection.NATIVE_DEPENDENCY_NAMES) + (
            "test/v108-remediation-security.test.mjs",
            "extensions/workboard/src/exact-dispatch.test.ts",
            "extensions/workboard/src/claim-generation.test.ts",
            "extensions/memory-core/src/memory-owner.test.ts",
            "src/agents/model-contract.test.ts",
            "src/agents/model-private.live.test.ts",
            "src/commands/doctor-state.test.ts",
            "src/commands/doctor-session.process.test.ts",
        )))


def binding():
    return {"newRecoveryTests": list(selection.MIGRATION_REQUIRED)}


def early_script(template):
    lines = template.splitlines()
    start = lines.index("          python3 -I - <<'PY'") + 1
    end = lines.index("          PY", start)
    return "\n".join(line[10:] for line in lines[start:end]) + "\n"


def frontloaders(template):
    lines = template.splitlines()
    result = []
    for i, line in enumerate(lines):
        if (line.startswith("          python3 -I - ") and line.endswith(" <<'PY'") and
                line != "          python3 -I - <<'PY'"):
            end = lines.index("          PY", i + 1)
            result.append((line, "\n".join(value[10:] for value in lines[i + 1:end]) + "\n"))
    return result


class SelectionTests(unittest.TestCase):
    def test_new_migration_owners_selected_exactly_once_and_not_old_paths(self):
        paths = inventory()
        selection.coverage(paths)
        selected = [p for profile in contract.PROFILES for p in selection.selected_tests(paths, profile)]
        for name in (
            "src/state/openclaw-state-h3-v20-upgrade.test.ts",
            "src/state/openclaw-agent-json-predicate-schema.test.ts",
            "src/commands/backup-sqlite.test.ts",
            "src/commands/doctor-migration-backup.scoped.test.ts",
        ):
            self.assertEqual(selected.count(name), 1)
        self.assertNotIn("src/state/agent-database-startup-fts.test.ts", selected)
        self.assertNotIn("src/agents/tool-search.live-diagnostics.test.ts", selected)

    def test_shards_are_disjoint_and_input_order_cannot_move_their_membership(self):
        for group in (("workboard-1", "workboard-2"), ("models-1", "models-2"),
                      ("doctor-1", "doctor-2", "doctor-3")):
            actual = [selection.selected_tests(inventory(), name) for name in group]
            self.assertEqual(len([p for part in actual for p in part]),
                len({p for part in actual for p in part}))
            self.assertEqual(actual, [selection.selected_tests(list(reversed(inventory())), name)
                for name in group])

    def test_general_live_exclusion_and_only_reviewed_synthetic_exception(self):
        selected = {p for name in contract.PROFILES for p in selection.selected_tests(inventory(), name)}
        self.assertNotIn("src/agents/model-private.live.test.ts", selected)
        self.assertIn("src/agents/tool-search.agent-loop.test.ts", selected)
        self.assertIn("test/scripts/ci-hydrate-live-auth.test.ts", selected)
        forbidden = "src/agents/synthetic-provider.live.test.ts"
        with patch.object(selection, "MODEL_EXTRA", selection.MODEL_EXTRA + (forbidden,)):
            with self.assertRaisesRegex(contract.Refusal, "no_unreviewed_live"):
                selection.coverage(inventory() + [forbidden])

    def test_missing_authentic_migration_fixture_owner_or_helper_refuses(self):
        for missing in ("src/state/openclaw-state-h3-v20-upgrade.test.ts",
                        "test/scripts/a2ui-zod-bounds.regression.mjs"):
            with self.subTest(missing=missing), self.assertRaisesRegex(contract.Refusal, "complete_changed"):
                selection.coverage([p for p in inventory() if p != missing])

    def test_unsafe_or_duplicate_inventory_is_refused_before_commands(self):
        for path in ("../outside.test.ts", "/tmp/outside.test.ts", "-option.test.ts",
                     "src/../outside.test.ts", "src\\outside.test.ts", "src/a\ntest.ts",
                     inventory()[0]):
            with self.subTest(path=path), self.assertRaises(contract.Refusal):
                selection.commands("/pipeline", "/source", "sqlite", inventory() + [path],
                    {"phase": "validation"}, binding())

    def test_dependency_order_keeps_patch_check_both_audits_then_fixed_native_owner(self):
        commands = selection.commands("/pipeline", "/source", "dependency", inventory(),
            {"phase": "validation"}, binding())
        self.assertEqual(commands[:3], [["pnpm", "deps:patches:check"],
            ["pnpm", "audit"], ["pnpm", "audit", "--prod"]])
        self.assertEqual(commands[3][:5], ["node", "/pipeline/scripts/fork-release/native_tests.mjs",
            "--source-root", "/source", "--"])
        self.assertIn("test/body-parser-security.test.mjs", commands[3])
        self.assertIn("test/mcp-nowistay-sdk-regression.test.mjs", commands[3])

    def test_missing_or_duplicate_native_name_does_not_shrink_suite(self):
        for paths in ([p for p in inventory() if p != "test/body-parser-security.test.mjs"],
                      inventory() + ["test/other/body-parser-security.test.mjs"]):
            with self.assertRaisesRegex(contract.Refusal, "complete_native"):
                selection.commands("/p", "/s", "dependency", paths, {"phase": "validation"}, binding())

    def test_compatibility_uses_current_source_tree_and_maintained_wrappers(self):
        commands = selection.commands("/pipeline", "/source", "compatibility", inventory(),
            {"phase": "validation", "source": {"sourceSha": "a" * 40}}, binding())
        self.assertIn("test/v108-remediation-security.test.mjs", commands[0])
        self.assertEqual(commands[1][:4], ["node", "--import", "./scripts/tsx.mjs",
            "scripts/test-projects.mts"])
        self.assertEqual(commands[2], ["pnpm", "deps:npm-lock:check:changed", "--base",
            "7dc3350cb9f08fcf9a0af5c4845a20d5b2f1a8be", "--head", "a" * 40])
        self.assertIn("12.2.1", commands[3][-1])

    def test_types_and_test_commands_are_closed_not_caller_selected(self):
        self.assertEqual(selection.commands("/p", "/s", "types-tests", inventory(),
            {"phase": "validation"}, binding()), [["pnpm", "tsgo:test"]])
        for profile, request, supplied in (("image", {"phase": "validation"}, binding()),
                ("sqlite", {"phase": "lock-preparation"}, binding()),
                ("sqlite", {"phase": "validation"}, {"newRecoveryTests": []})):
            with self.assertRaises(contract.Refusal):
                selection.commands("/p", "/s", profile, inventory(), request, supplied)

    def test_function_only_or_nested_tests_cannot_count_as_unittest_discovery(self):
        for raw in (b"def test_contract(): pass\n",
                    b"class NotATestCase:\n    def test_contract(self): pass\n",
                    b"import unittest\ndef factory():\n    class Nested(unittest.TestCase):\n        def test_contract(self): pass\n",
                    b"import unittest\nclass Empty(unittest.TestCase):\n    def helper(self):\n        def test_nested(): pass\n"):
            with self.subTest(raw=raw), self.assertRaisesRegex(contract.Refusal, "positive_pipeline"):
                selection.verify_pipeline_contract_files(lambda p: raw)
        # Inspect the actual five fixed operator test modules without executing them.
        actual = selection.verify_pipeline_contract_files(
            lambda p: (Path(__file__).parent.parent.parent / p).read_bytes())
        self.assertEqual(len(actual["fixedTestModules"]), 5)

    def test_positive_synthetic_helper_hash_not_live_name_alone(self):
        unit = "test/scripts/ci-hydrate-live-auth.test.ts"
        helper = "scripts/ci-hydrate-live-auth.sh"
        contents = {unit: b"public synthetic unit", helper: b"public synthetic helper"}
        with patch.object(selection, "MOCKED_UNITS", {unit: hashlib.sha256(contents[unit]).hexdigest()}), \
             patch.object(selection, "MOCKED_HELPERS", {helper: hashlib.sha256(contents[helper]).hexdigest()}):
            result = selection.verify_mocked_units(contents.__getitem__)
            self.assertFalse(result["liveProviderCredentialsAllowed"])
            with self.assertRaisesRegex(contract.Refusal, "exact_mocked"):
                selection.verify_mocked_units(lambda p: contents[p] + b"changed")
        with patch.object(selection, "MOCKED_HELPERS", {}), self.assertRaisesRegex(
                contract.Refusal, "preparation_complete"):
            selection.verify_mocked_units(lambda p: b"not a positive helper proof")

    def test_unittest_discovery_cannot_accept_absent_or_empty_test_modules(self):
        for raw in (b"", b"# no tests", b"broken Python???", "not bytes"):
            with self.subTest(raw=raw), self.assertRaises(contract.Refusal):
                selection.verify_pipeline_contract_files(lambda p: raw)
        result = selection.verify_pipeline_contract_files(lambda p: b"import unittest\nclass Positive(unittest.TestCase):\n    def test_contract(self): pass\n")
        self.assertFalse(result["missingModuleAccepted"])
        commands = selection.commands("/p", "/s", "pipeline-contracts", inventory(),
            {"phase": "validation"}, binding())
        self.assertTrue(all(command[:4] == ["python3", "-m", "unittest", "discover"]
            for command in commands))
        self.assertEqual(len({tuple(command) for command in commands}), len(commands))


class PreCheckoutTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="v110-caller-test-")
        self.addCleanup(self.directory.cleanup)
        self.output = Path(self.directory.name) / "github-env"
        self.script = early_script((FIXTURES / "v110-lock-preparation.yml").read_text())
        self.environment = {
            "V110_ARMED": "true", "V110_BOUND_PR": "31", "V110_SOURCE_SHA": "a" * 40,
            "V110_ENTRY_SHA256": "b" * 64, "V110_CODE_MANIFEST_SHA256": "c" * 64, "V110_EFFECTIVE_AT": "2026-11-03T09:12:23Z",
            "V110_EXPIRES_AT": "2026-11-06T03:14:21Z", "V110_JOB_MINUTES": "45",
            "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux",
            "GITHUB_REPOSITORY": "fr-meyer/openclaw", "GITHUB_ACTOR": "fr-meyer",
            "GITHUB_EVENT_NAME": "pull_request", "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_REF": "refs/pull/31/merge", "GITHUB_ENV": str(self.output),
        }
        self.now = int(datetime(2026, 11, 4, 10, tzinfo=timezone.utc).timestamp())

    def run_gate(self, changes=None, now=None):
        environment = {**self.environment, **(changes or {})}
        with patch.dict(os.environ, environment, clear=True), patch("time.time", return_value=self.now if now is None else now):
            exec(compile(self.script, "fixed-precheckout-gate", "exec"), {})

    def test_valid_synthetic_clock_writes_only_started_epoch(self):
        self.run_gate()
        self.assertEqual(self.output.read_text(), f"V110_JOB_STARTED_EPOCH={self.now}\n")

    def test_disarmed_or_missing_binding_refuses_before_any_checkout_environment(self):
        for changes in ({"V110_ARMED": "false"}, {"V110_BOUND_PR": "0"},
                        {"V110_SOURCE_SHA": "0" * 40}, {"V110_ENTRY_SHA256": "0" * 64},
                        {"V110_ENTRY_SHA256": "url-or-command"},
                        {"V110_CODE_MANIFEST_SHA256": "0" * 64},
                        {"V110_CODE_MANIFEST_SHA256": "not-a-digest"}):
            with self.subTest(changes=changes), self.assertRaisesRegex(SystemExit, "disarmed_binding"):
                self.run_gate(changes)
            self.assertFalse(self.output.exists())

    def test_wrong_host_actor_ref_or_attempt_refuses_before_checkout(self):
        for changes in ({"GITHUB_ACTOR": "another-user"}, {"RUNNER_ENVIRONMENT": "self-hosted"},
                        {"GITHUB_REF": "refs/pull/28/merge"}, {"GITHUB_RUN_ATTEMPT": "2"},
                        {"GITHUB_EVENT_NAME": "pull_request_target"}):
            with self.subTest(changes=changes), self.assertRaisesRegex(SystemExit, "hosted_identity"):
                self.run_gate(changes)
            self.assertFalse(self.output.exists())

    def test_quarantine_floor_and_full_job_plus_cleanup_window_are_enforced(self):
        floor = int(datetime(2026, 11, 4, 9, 59, 50, tzinfo=timezone.utc).timestamp())
        deadline = int(datetime(2026, 11, 6, 3, 14, 21, tzinfo=timezone.utc).timestamp())
        for now in (floor - 1, deadline - 45 * 60 - 59, deadline):
            with self.subTest(now=now), self.assertRaisesRegex(SystemExit, "authorization_clock"):
                self.run_gate(now=now)
            self.assertFalse(self.output.exists())

    def test_invalid_clock_and_limits_do_not_write_started_epoch(self):
        for changes in ({"V110_EFFECTIVE_AT": "DISARMED"},
                        {"V110_EFFECTIVE_AT": "2026-11-03T09:11:00Z"},
                        {"V110_EXPIRES_AT": "2026-11-07T03:14:21Z"},
                        {"V110_JOB_MINUTES": "0"}, {"V110_JOB_MINUTES": "91"},
                        {"V110_JOB_MINUTES": "1.5"}):
            with self.subTest(changes=changes), self.assertRaises(SystemExit):
                self.run_gate(changes)
            self.assertFalse(self.output.exists())

    def test_each_template_job_refuses_disarmed_and_early_clock_before_writing(self):
        for name in ("v110-lock-preparation.yml", "v110-source-validation.yml"):
            remaining = (FIXTURES / name).read_text()
            count = 0
            while "          python3 -I - <<'PY'\n" in remaining:
                start = remaining.index("          python3 -I - <<'PY'\n")
                end = remaining.index("          PY\n", start) + len("          PY\n")
                self.script = early_script(remaining[start:end])
                count += 1
                for changes, now in (({"V110_ARMED": "false"}, self.now),
                                     ({}, self.now - 60)):
                    with self.subTest(template=name, gate=count, changes=changes), self.assertRaises(SystemExit):
                        self.run_gate(changes, now)
                    self.assertFalse(self.output.exists())
                remaining = remaining[end:]
            self.assertEqual(count, 1 if name == "v110-lock-preparation.yml" else 3)


class ManifestFrontloaderTests(unittest.TestCase):
    MANIFEST = "scripts/fork-release/candidates/v2026.10.10-source-only/code-manifest.json"
    ENTRY = "scripts/fork-release/source_validation_v110.py"
    HELPER = "scripts/fork-release/public_helper.py"
    IMPORTS = "scripts/fork-release/verified_imports_v110.py"

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="v110-closure-test-")
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)
        self.pipeline = self.base / "pipeline"
        self.guard = frontloaders((FIXTURES / "v110-lock-preparation.yml").read_text())[0][1]
        self.entry = b"from pathlib import Path\nimport sys\nPath('launched').write_text(__name__ + '|' + __file__ + '|' + '|'.join(sys.argv[1:]))\n"
        self.write(self.ENTRY, self.entry)
        self.write(self.HELPER, b"public_operator_value = 1\n")
        self.write(self.IMPORTS, (Path(__file__).parent / "verified_imports_v110.py").read_bytes())
        self.manifest = {"schema": "openclaw.v110.code-manifest.v1", "codeFiles": {
            name: {"sha256": hashlib.sha256((self.pipeline / name).read_bytes()).hexdigest(),
                "bytes": (self.pipeline / name).stat().st_size}
            for name in (self.ENTRY, self.HELPER, self.IMPORTS)}}
        self.environment = {"PATH": "/usr/bin:/bin", "HOME": self.directory.name,
            "V110_ENTRY_SHA256": hashlib.sha256(self.entry).hexdigest()}
        self.bind()

    def write(self, relative, raw):
        path = self.pipeline / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)

    def bind(self, raw=None):
        raw = json.dumps(self.manifest, sort_keys=True).encode() if raw is None else raw
        self.write(self.MANIFEST, raw)
        self.environment["V110_CODE_MANIFEST_SHA256"] = hashlib.sha256(raw).hexdigest()

    def execute(self, reason=None):
        result = subprocess.run([sys.executable, "-I", "-", "admit"], input=self.guard,
            cwd=self.base, env=self.environment, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=5, check=False)
        if reason is None:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(reason, result.stderr)
            self.assertFalse((self.base / "launched").exists())
        return result

    def test_valid_full_closure_executes_captured_entry_with_correct_identity_argv(self):
        # -I prevents a cwd module from replacing stdlib before verification.
        (self.base / "json.py").write_text("raise RuntimeError('untrusted cwd module')\n")
        self.execute()
        self.assertEqual((self.base / "launched").read_text(),
            "__main__|" + str(self.pipeline.resolve() / self.ENTRY) + "|admit")
        self.assertFalse(list(self.pipeline.rglob("__pycache__")))

    def set_entry(self, raw):
        self.write(self.ENTRY, raw)
        self.manifest["codeFiles"][self.ENTRY] = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
        self.environment["V110_ENTRY_SHA256"] = hashlib.sha256(raw).hexdigest()
        self.bind()

    def test_unlisted_sibling_argparse_cannot_shadow_stdlib_with_unchanged_pins(self):
        self.set_entry(b"import argparse\nfrom pathlib import Path\nPath('launched').write_text(argparse.__file__)\n")
        manifest_hash = self.environment["V110_CODE_MANIFEST_SHA256"]
        entry_hash = self.environment["V110_ENTRY_SHA256"]
        self.write("scripts/fork-release/argparse.py",
            b"from pathlib import Path\nPath('unlisted-executed').write_text('unsafe')\n")
        self.execute()
        self.assertFalse((self.base / "unlisted-executed").exists())
        self.assertNotIn(str(self.pipeline.resolve()), (self.base / "launched").read_text())
        self.assertEqual(self.environment["V110_CODE_MANIFEST_SHA256"], manifest_hash)
        self.assertEqual(self.environment["V110_ENTRY_SHA256"], entry_hash)

    def test_captured_plain_helper_import_has_real_file_identity_and_is_cached(self):
        self.set_entry(b"import public_helper\nfrom public_helper import public_operator_value\n"
            b"import public_helper as again\nfrom pathlib import Path\n"
            b"assert public_helper is again\n"
            b"Path('launched').write_text(str(public_operator_value) + '|' + public_helper.__file__)\n")
        self.execute()
        self.assertEqual((self.base / "launched").read_text(),
            "1|" + str(self.pipeline.resolve() / self.HELPER))

    def test_helper_import_uses_captured_bytes_after_verified_file_is_replaced(self):
        self.set_entry(b"from pathlib import Path\n"
            b"Path('pipeline/scripts/fork-release/public_helper.py').write_text(\"raise RuntimeError('changed after capture')\\n\")\n"
            b"import public_helper\nPath('launched').write_text(str(public_helper.public_operator_value))\n")
        self.execute()
        self.assertEqual((self.base / "launched").read_text(), "1")

    def test_local_relative_or_package_shaped_imports_refuse(self):
        for raw in (b"import public_helper.child\n", b"from . import public_helper\n",
                    b"__import__('scripts/fork-release/public_helper')\n"):
            with self.subTest(raw=raw):
                self.set_entry(raw)
                self.execute("closed_import_package_target")

    def test_fixed_import_helper_is_required_and_hash_bound_before_execution(self):
        pin = self.manifest["codeFiles"].pop(self.IMPORTS)
        self.bind()
        self.execute("code_manifest_schema")
        self.manifest["codeFiles"][self.IMPORTS] = pin
        self.bind()
        self.write(self.IMPORTS, b"raise RuntimeError('unverified loader')\n")
        self.execute("code_manifest_content")

    def test_all_cli_guards_are_byte_identical(self):
        for name in ("v110-lock-preparation.yml", "v110-source-validation.yml"):
            for header, guard in frontloaders((FIXTURES / name).read_text()):
                with self.subTest(template=name, header=header):
                    self.assertEqual(guard, self.guard)

    def test_changed_helper_refuses_before_entry(self):
        self.write(self.HELPER, b"public_operator_value = 2\n")
        self.execute("code_manifest_content")

    def test_missing_helper_refuses_before_entry(self):
        (self.pipeline / self.HELPER).unlink()
        self.execute("code_manifest_file_unavailable")

    def test_path_traversal_outside_scope_and_noncanonical_paths_refuse(self):
        pin = self.manifest["codeFiles"].pop(self.HELPER)
        for path in ("scripts/fork-release/../outside.py", "/tmp/outside.py", "src/foreign.py",
                     "scripts/fork-release//helper.py", "scripts/fork-release/-option.py"):
            with self.subTest(path=path):
                self.manifest["codeFiles"][path] = pin
                self.bind()
                self.execute("code_manifest_path")
                del self.manifest["codeFiles"][path]

    def test_manifest_self_reference_and_operational_workflow_are_excluded(self):
        for path in (self.MANIFEST, ".github/workflows/future-v110-source-validation.yml"):
            with self.subTest(path=path):
                self.manifest["codeFiles"][path] = {"sha256": "a" * 64, "bytes": 1}
                self.bind()
                self.execute("code_manifest_self_or_workflow")
                del self.manifest["codeFiles"][path]

    def test_symlink_file_or_parent_is_not_a_regular_closure_input(self):
        helper = self.pipeline / self.HELPER
        helper.unlink()
        outside = self.base / "outside.py"
        outside.write_bytes(b"public_operator_value = 1\n")
        helper.symlink_to(outside)
        self.execute("code_manifest_regular_file")
        helper.unlink()
        directory = helper.parent
        relocated = self.pipeline / "relocated"
        directory.rename(relocated)
        directory.symlink_to(relocated, target_is_directory=True)
        self.execute("code_manifest_directory")

    def test_missing_manifest_and_wrong_manifest_hash_refuse(self):
        manifest = self.pipeline / self.MANIFEST
        raw = manifest.read_bytes()
        manifest.unlink()
        self.execute("code_manifest_file_unavailable")
        manifest.write_bytes(raw + b" ")
        self.execute("code_manifest_digest")

    def test_duplicate_json_keys_constants_unknown_schema_and_extra_fields_refuse(self):
        for raw, reason in ((b'{"schema":"x","schema":"y","codeFiles":{}}', "duplicate_key"),
                            (b'{"schema":NaN,"codeFiles":{}}', "json_constant"),
                            (b'{"schema":"other","codeFiles":{}}', "schema"),
                            (b'{"schema":"openclaw.v110.code-manifest.v1","codeFiles":{},"extra":0}', "schema")):
            with self.subTest(raw=raw):
                self.bind(raw)
                self.execute("code_manifest_" + reason)

    def test_missing_entry_wrong_size_wrong_entry_hash_and_unbound_pin_refuse(self):
        pin = self.manifest["codeFiles"].pop(self.ENTRY)
        self.bind()
        self.execute("code_manifest_schema")
        self.manifest["codeFiles"][self.ENTRY] = pin
        self.manifest["codeFiles"][self.HELPER]["bytes"] += 1
        self.bind()
        self.execute("code_manifest_content")
        self.manifest["codeFiles"].pop(self.HELPER)
        self.bind()
        self.environment["V110_ENTRY_SHA256"] = "b" * 64
        self.execute("code_manifest_entry_digest")
        self.environment["V110_CODE_MANIFEST_SHA256"] = "0" * 64
        self.execute("code_manifest_unbound")


class WorkflowTemplateTests(unittest.TestCase):
    def test_role_rendering_changes_only_explicit_disarmed_bindings(self):
        arguments = {"pr_number": 31, "source_sha": "a" * 40, "entry_sha256": "b" * 64,
            "code_manifest_sha256": "c" * 64, "effective_at": "2026-11-03T09:12:23Z"}
        for path in (selection.LOCK_PREPARATION_TEMPLATE, selection.SOURCE_VALIDATION_TEMPLATE):
            raw = (Path(__file__).parent.parent.parent / path).read_bytes()
            actual = selection.render_workflow(raw, **arguments)
            expected = raw.replace(b"  V110_ARMED: 'false'", b"  V110_ARMED: 'true'")
            expected = expected.replace(b"  V110_BOUND_PR: '0'", b"  V110_BOUND_PR: '31'")
            for key, old, value in (("SOURCE_SHA", "0" * 40, "a" * 40),
                    ("ENTRY_SHA256", "0" * 64, "b" * 64),
                    ("CODE_MANIFEST_SHA256", "0" * 64, "c" * 64),
                    ("EFFECTIVE_AT", "DISARMED", "2026-11-03T09:12:23Z")):
                expected = expected.replace(("  V110_" + key + ": '" + old + "'").encode(),
                    ("  V110_" + key + ": '" + value + "'").encode())
            expected = expected.replace(b"github.event.pull_request.number == 0 &&",
                b"github.event.pull_request.number == 31 &&")
            self.assertEqual(actual, expected)
            self.assertNotEqual(actual, raw)
            for changes in ({"pr_number": 0}, {"pr_number": True}, {"source_sha": "0" * 40},
                    {"entry_sha256": "not-a-pin"}, {"code_manifest_sha256": "0" * 64},
                    {"effective_at": "2026-11-03T09:11:00Z"}):
                with self.subTest(changes=changes), self.assertRaises(contract.Refusal):
                    selection.render_workflow(raw, **{**arguments, **changes})
            with self.assertRaisesRegex(contract.Refusal, "fixed_disarmed_field"):
                selection.render_workflow(actual, **arguments)

    def test_fifteen_profile_caps_include_migration_time_and_admission_final(self):
        template = (FIXTURES / "v110-source-validation.yml").read_text()
        profiles = re.findall(r"          - profile: ([a-z0-9-]+)\n            minutes: ([0-9]+)\n", template)
        self.assertEqual(len(profiles), 15)
        self.assertEqual(len({name for name, _ in profiles}), 15)
        caps = {name: int(minutes) for name, minutes in profiles}
        self.assertEqual(caps["sqlite"], 90)
        self.assertEqual(caps["doctor-1"], 90)
        self.assertEqual(caps["doctor-2"], 75)
        self.assertEqual(caps["doctor-3"], 75)
        self.assertEqual(sum(caps.values()) + 30 + 10, 1105)
        self.assertIn("      max-parallel: 3\n", template)

    def test_fixed_read_permissions_and_public_synthetic_caller_without_secret_cache_or_build(self):
        for name in ("v110-lock-preparation.yml", "v110-source-validation.yml"):
            text = (FIXTURES / name).read_text()
            self.assertEqual(text.split("permissions:\n", 1)[1].split("concurrency:\n", 1)[0],
                "  contents: read\n  actions: read\n  pull-requests: read\n")
            for forbidden in ("pull_request_target:", "workflow_dispatch:", "secrets.",
                              "id-token:", "actions/cache", "docker build", "gcloud "):
                self.assertNotIn(forbidden, text)
            self.assertIn("  cancel-in-progress: false\n", text)
            self.assertIn("github.event.pull_request.number == 0", text)
            self.assertIn("  V110_ARMED: 'false'\n", text)
            self.assertIn("task/v110-source-validation", text)
            self.assertNotIn("refs/pull/28/merge", text)
            self.assertIn("          persist-credentials: false\n", text)
            self.assertIn("          check-latest: false\n", text)
            self.assertIn("          node-version: 24.22.1\n", text)
            # The metadata token is only a trusted-step input, not a top/job env.
            self.assertTrue(all(line.startswith("          GH_TOKEN:")
                for line in text.splitlines() if "GH_TOKEN:" in line))

    def test_entry_hash_check_precedes_every_controller_invocation_and_caps_retention(self):
        for name in ("v110-lock-preparation.yml", "v110-source-validation.yml"):
            text = (FIXTURES / name).read_text()
            lines = text.splitlines()
            guards = frontloaders(text)
            self.assertEqual(len(guards), 3 if name == "v110-lock-preparation.yml" else 4)
            self.assertNotIn("python3 pipeline/scripts/fork-release/source_validation_v110.py", text)
            for header, guard in guards:
                self.assertIn("python3 -I - ", header)
                self.assertNotIn("sys.path.insert", guard)
                self.assertLess(guard.index("captured = verify_code_manifest()"),
                    guard.index("exec(compile(captured[IMPORTS]"))
                self.assertLess(guard.index("captured = verify_code_manifest()"),
                    guard.index("exec(compile(captured[ENTRY]"))
                self.assertIn("'__builtins__': closed_builtins", guard)
                self.assertIn("sys.dont_write_bytecode = True", guard)
                self.assertIn("V110_CODE_MANIFEST_SHA256", guard)
            self.assertIn("  V110_CODE_MANIFEST_SHA256: '" + "0" * 64 + "'", text)
            uploads = [i for i, line in enumerate(lines) if "uses: actions/upload-artifact@" in line]
            self.assertEqual(len(uploads), 2 if name == "v110-lock-preparation.yml" else 1)
            self.assertEqual(text.count("          retention-days: 3\n"), len(uploads))
            self.assertEqual(text.count("          include-hidden-files: false\n"), len(uploads))


if __name__ == "__main__":
    unittest.main()
