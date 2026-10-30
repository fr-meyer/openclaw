"""10.9 additions to the maintained source-only test-family owner.

Selection is pure; commands are returned to the secretless CI executor. No test,
provider, package manager, image builder or cloud client is invoked on import.
"""
from pathlib import Path
import ast
import hashlib
import re

import source_validation_contract_v109 as contract
import source_validation_v108 as legacy

SQLITE_EXTRA = (
    "src/infra/sqlite-fts-integrity.test.ts",
    "src/infra/sqlite-startup-integrity.test.ts",
    "src/infra/state-migrations.transcript-archive-stream.test.ts",
    "src/infra/update-fts-snapshot.test.ts",
    "src/state/agent-database-startup-fts.test.ts",
    "src/state/openclaw-database-preflight.startup-fts.test.ts",
    "src/infra/state-migrations.media-persistence.canonical-archives.test.ts",
    "src/infra/state-migrations.transcript-directives-archives.batching.test.ts",
    "src/infra/state-migrations.transcript-directives-archives.progress.test.ts",
    "src/state/openclaw-agent-execution.close-wedge.test.ts",
    "src/state/openclaw-state-worker-lease.test.ts",
)
DOCTOR_EXTRA = (
    "src/commands/doctor-session-sqlite.fts-recovery.test.ts",
    "src/cli/daemon-cli/update-executor-recovery.test.ts",
    "src/cli/update-cli/update-command-current-core-recovery.test.ts",
    "src/cli/update-cli/update-command-current-core-restoration.test.ts",
    "src/cli/update-cli/update-command-service-command-risk.test.ts",
    "src/process/exec-buffered-cleanup.test.ts",
    "src/infra/update-runner-git.test.ts",
)
MODEL_EXTRA = (
    "src/agents/prepared-model-runtime.generation-custody.test.ts",
    "src/agents/prepared-model-runtime.auth-recovery.test.ts",
    "src/agents/tool-search.live-diagnostics.test.ts",
    "src/agents/tool-fs-policy.test.ts",
    "extensions/codex/src/app-server/run-attempt.steering-media.test.ts",
)
COMPAT_EXTRA = (
    "extensions/msteams/src/sdk.msal-compat.test.ts",
    "src/infra/npm-managed-root.overrides.test.ts",
    "test/scripts/a2ui-zod-bounds.test.ts",
    "test/scripts/clawhub-cli-security-pin.test.ts",
    "test/scripts/discord-sdk-zod.test.ts",
    "src/gateway/server.acp-session-cwd.test.ts",
    "src/gateway/tool-resolution.test.ts",
    "src/cli/mcp-cli.test.ts",
    "src/auto-reply/reply/commands-mcp.test.ts",
    "src/logging/log-tail-redaction.test.ts",
    "src/logging/redact.test.ts",
    "src/gateway/server-methods/nodes.test.ts",
    "test/scripts/ci-hydrate-live-auth.test.ts",
)
REQUIRED_SOURCE_TESTS = tuple(sorted(set(SQLITE_EXTRA + DOCTOR_EXTRA + MODEL_EXTRA + COMPAT_EXTRA)))
REQUIRED_HELPERS = ("test/scripts/a2ui-zod-bounds.regression.mjs",)
NATIVE_DEPENDENCY_NAMES = frozenset((
    "zod-container-bounds.test.mjs", "a2ui-native-zod-regression.test.mjs",
    "discord-native-zod-regression.test.mjs", "body-parser-security.test.mjs",
    "msal-parent-compat.test.mjs", "undici-security.test.mjs",
    "mcp-nowistay-schema-compatibility.test.mjs", "mcp-nowistay-sdk-regression.test.mjs",
    "http-cache-semantics-compat.test.mjs",
))
# These exact tests exercise synthetic callbacks/temporary HOME only. Their
# imported helpers are separately pinned before selection; the general live-name
# exclusion remains in the maintained owner.
MOCKED_UNITS = {
    "src/agents/tool-search.live-diagnostics.test.ts": "d152d06ac98de46e17b7f26dfce6271e71e0f59d54716e9485e2eea4af1a8ac1",
    "test/scripts/ci-hydrate-live-auth.test.ts": "600f7908525aa7b321c91f7d42ed7ec9ac0d55ad1d5d751fb8a0fed42f2b60c0",
}
# Filled only from the exact reviewed public helpers, never from an artifact or
# caller-selected path. A missing preparation pin remains a refusal.
MOCKED_HELPERS = {
    "scripts/ci-hydrate-live-auth.sh": "b4c1c81471d05484a953fbdbd5a4fe06eedfcc245dc237a95c5f4da96ce818b6",
    "src/agents/tool-search.live-diagnostics.ts": "9fdb79fd8af10453aac556e2f2393aeed60100486821851a1643f2681fb52bbb",
}
PIPELINE_CONTRACT_TESTS = (
    "test_release.py", "test_preflight.py", "test_source_tests.py",
    "test_merge_source.py", "test_merge_source_v107.py", "test_merge_source_v108.py",
    "test_source_reconciliation_v109.py", "test_validation_node_v109.py",
    "test_security_regression_name_v109.py",
    "test_source_validation_contract_v109.py", "test_lockfile_policy_v109.py",
    "test_source_derivation_v109.py", "test_source_correction_artifact_v109.py",
    "test_source_validation_selection_v109.py",
    "test_source_validation_runtime_v109.py",
    "test_composite_closed_usage.py", "test_composite_closed_usage_v109.py",
    "test_shared_owner_hook_v109.py",
)


def _need(value, code):
    contract.need(value, "v9.selection." + code)


def _paths(paths):
    _need(type(paths) in (list, tuple, set, frozenset) and all(type(p) is str and
        p and not p.startswith("/") and all(x not in ("", ".", "..") for x in p.split("/"))
        for p in paths), "tracked_paths")
    _need(len(paths) == len(set(paths)), "unique_tracked_paths")
    return set(paths)


def verify_mocked_units(read_file):
    _need(set(MOCKED_HELPERS) == {"scripts/ci-hydrate-live-auth.sh",
        "src/agents/tool-search.live-diagnostics.ts"}, "mocked_helper_preparation_complete")
    for path, expected in {**MOCKED_UNITS, **MOCKED_HELPERS}.items():
        raw = read_file(path)
        _need(type(raw) is bytes and len(raw) <= 64 * 1024 and
            hashlib.sha256(raw).hexdigest() == expected, "exact_mocked_unit_and_helper")
    return {"syntheticLiveNamedUnitFiles": sorted(MOCKED_UNITS),
        "helperFiles": sorted(MOCKED_HELPERS), "liveProviderCredentialsAllowed": False}


def verify_pipeline_contract_files(read_file):
    # unittest discover exits zero when a -p filename does not exist. The closed
    # caller must positively bind each reviewed module before starting that job.
    for name in PIPELINE_CONTRACT_TESTS:
        raw = read_file("scripts/fork-release/" + name)
        _need(type(raw) is bytes and 0 < len(raw) <= 512 * 1024, "pipeline_test_file")
        try:
            tree = ast.parse(raw)
        except (SyntaxError, ValueError, UnicodeError):
            raise contract.Refusal("v9.selection.pipeline_test_syntax")
        _need(any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and
            node.name.startswith("test_") for node in ast.walk(tree)), "positive_pipeline_test_definitions")
    return {"fixedTestModules": list(PIPELINE_CONTRACT_TESTS), "missingModuleAccepted": False}


def selected_tests(paths, profile):
    known = _paths(paths)
    _need(profile in contract.PROFILES, "fixed_profile")
    legacy_request = {"schema": legacy.R8_SCHEMA}
    if profile.startswith("models-"):
        family = set(legacy.selected_tests(paths, "models-1", legacy_request)) | set(
            legacy.selected_tests(paths, "models-2", legacy_request)) | set(MODEL_EXTRA)
        return sorted(family)[int(profile[-1]) - 1::2]
    if profile.startswith("doctor-"):
        family = set(DOCTOR_EXTRA)
        for name in ("doctor-1", "doctor-2", "doctor-3"):
            family.update(legacy.selected_tests(paths, name, legacy_request))
        ordered = sorted(family)
        priority = [p for p in ordered if re.search(r"(?:process|session)", p.rsplit("/", 1)[-1])]
        rest = [p for p in ordered if p not in set(priority)]
        return sorted((priority + rest)[int(profile[-1]) - 1::3])
    if profile == "sqlite":
        return sorted(set(legacy.selected_tests(paths, profile, legacy_request)) | set(SQLITE_EXTRA))
    if profile == "compatibility":
        return sorted(set(legacy.V6_RUNTIME_COMPATIBILITY_TESTS) | set(COMPAT_EXTRA))
    result = legacy.selected_tests(paths, profile, legacy_request)
    _need(set(result) <= known, "maintained_selection_tracked")
    return result


def coverage(paths):
    known = _paths(paths)
    _need(set(REQUIRED_SOURCE_TESTS + REQUIRED_HELPERS) <= known, "complete_changed_recovery_security_paths")
    _need(all(contract.TEST_PATH.fullmatch(p) for p in REQUIRED_SOURCE_TESTS), "fixed_test_paths")
    families = {p: selected_tests(paths, p) for p in contract.PROFILES
        if p.startswith(("models-", "doctor-", "workboard-")) or p in ("sqlite", "memory", "compatibility")}
    _need(all(set(v) <= known for v in families.values()), "no_missing_selection")
    for prefixes in (("models-1", "models-2"), ("doctor-1", "doctor-2", "doctor-3"),
                     ("workboard-1", "workboard-2")):
        all_paths = [p for group in prefixes for p in families[group]]
        _need(len(all_paths) == len(set(all_paths)), "disjoint_family_shards")
    selected = set(p for group in families.values() for p in group)
    _need(set(REQUIRED_SOURCE_TESTS) <= selected, "complete_new_owner_coverage")
    allowed = set(MOCKED_UNITS)
    _need(not any(re.search(r"(?:^|[./-])live(?:[./-]|$)", p) and p not in allowed for p in selected),
        "no_unreviewed_live_tests")
    return {"requiredNewOrChangedTests": list(REQUIRED_SOURCE_TESTS),
        "requiredNativeHelperFiles": list(REQUIRED_HELPERS),
        "familyCounts": {k: len(v) for k, v in families.items()},
        "freshSourceCoverageRequired": True, "priorGenerationCoverageReused": False}


def commands(pipeline, source, profile, tracked_paths, request, bindings):
    _need(profile in contract.PROFILES and request["phase"] in ("validation", "correction"), "execution_profile")
    _need(bindings["newRecoveryTests"] == list(REQUIRED_SOURCE_TESTS), "binding_complete_changed_roots")
    coverage(tracked_paths)
    pipeline, source = Path(pipeline), Path(source)
    if profile.startswith("types-"):
        return [["pnpm", {"types-production": "tsgo:prod", "types-tests": "tsgo:test",
            "types-scripts": "tsgo:scripts"}[profile]]]
    native_owner = str(pipeline / "scripts/fork-release/native_tests.mjs")
    if profile == "dependency":
        native = sorted(p for p in tracked_paths if p.startswith("test/") and
            p.endswith(".test.mjs") and p.rsplit("/", 1)[-1] in NATIVE_DEPENDENCY_NAMES)
        _need(len(native) == len(NATIVE_DEPENDENCY_NAMES) and
            len({p.rsplit("/", 1)[-1] for p in native}) == len(NATIVE_DEPENDENCY_NAMES), "complete_native_dependency_suite")
        return [["pnpm", "deps:patches:check"], ["pnpm", "audit"], ["pnpm", "audit", "--prod"],
            ["node", native_owner, "--source-root", str(source), "--", *native]]
    if profile == "pipeline-contracts":
        return [["python3", "-m", "unittest", "discover", "-s", str(pipeline / "scripts/fork-release"),
            "-p", name] for name in PIPELINE_CONTRACT_TESTS]
    if profile == "compatibility":
        _need("test/v108-remediation-security.test.mjs" in tracked_paths, "native_fork_security_suite")
        return [["node", native_owner, "--source-root", str(source), "--", "test/v108-remediation-security.test.mjs"],
            ["node", "--import", "./scripts/tsx.mjs", "scripts/test-projects.mts", *selected_tests(tracked_paths, profile)],
            ["pnpm", "deps:npm-lock:check:changed", "--base", contract.BASELINE_SOURCE,
                "--head", request["source"]["sourceSha"]],
            ["node", "--input-type=module", "-e", legacy.V6_BUNDLED_NPM_VERSION_CHECK]]
    selected = selected_tests(tracked_paths, profile)
    _need(bool(selected), "nonempty_owner_family")
    return [["node", "--import", "./scripts/tsx.mjs", "scripts/test-projects.mts", *selected]]
