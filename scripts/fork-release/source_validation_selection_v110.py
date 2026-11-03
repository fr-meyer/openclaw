"""Fixed 10.10 source selection; returns commands without executing them.

The current maintained family router owns discovery. This module adds only the
reviewed 10.10 owner paths and synthetic exemptions; retired modules stay retired.
"""
from pathlib import Path
import ast
import hashlib
import re

import source_contract_v110 as contract
import source_validation_v108 as legacy

SQLITE_EXTRA = (
    'src/commands/backup-restore.test.ts',
    'src/commands/backup-sqlite.test.ts',
    'src/infra/sqlite-fts-integrity.test.ts',
    'src/infra/sqlite-integrity.test.ts',
    'src/infra/state-migrations.media-persistence.canonical-archives.test.ts',
    'src/infra/state-migrations.transcript-archive-stream.test.ts',
    'src/infra/state-migrations.transcript-directives-archives.batching.test.ts',
    'src/infra/state-migrations.transcript-directives-archives.progress.test.ts',
    'src/infra/update-candidate-state.test.ts',
    'src/infra/update-database-backup.test.ts',
    'src/state/openclaw-agent-execution.close-wedge.test.ts',
    'src/state/openclaw-agent-json-predicate-schema.test.ts',
    'src/state/openclaw-database-preflight.startup-fts.test.ts',
    'src/state/openclaw-database-preflight.startup-integrity.test.ts',
    'src/state/openclaw-state-db-schema-v21-columns.test.ts',
    'src/state/openclaw-state-db-schema-v22-columns.test.ts',
    'src/state/openclaw-state-h3-v20-upgrade.test.ts',
    'src/state/openclaw-state-worker-lease.test.ts',
)

DOCTOR_EXTRA = (
    'src/cli/daemon-cli/install.wrapper.integration.test.ts',
    'src/cli/update-cli/update-command-database-rollback.test.ts',
    'src/cli/update-cli/update-command-fresh-doctor.test.ts',
    'src/cli/update-cli/update-command-native-recovery.test.ts',
    'src/cli/update-cli/update-command-post-update-repair.test.ts',
    'src/cli/update-cli/update-command-post-update.test.ts',
    'src/cli/update-cli/update-command-service-command.process.test.ts',
    'src/cli/update-cli/update-command-service-command.test.ts',
    'src/cli/update-cli/update-command-service-custody.test.ts',
    'src/commands/doctor-migration-backup.scoped.test.ts',
    'src/commands/doctor-migration-backup.test.ts',
    'src/commands/doctor-session-sqlite.fts-recovery.test.ts',
    'src/infra/update-runner-git.test.ts',
    'src/process/exec-buffered-cleanup.test.ts',
)

MODEL_EXTRA = (
    'extensions/codex/src/app-server/run-attempt.steering-media.test.ts',
    'src/agents/prepared-model-catalog-worker.custody.integration.test.ts',
    'src/agents/prepared-model-runtime.auth-recovery.test.ts',
    'src/agents/prepared-model-runtime.test.ts',
    'src/agents/tool-fs-policy.test.ts',
    'src/agents/tool-search-runtime.output-variants.test.ts',
    'src/agents/tool-search-runtime.test.ts',
    'src/agents/tool-search.agent-loop.test.ts',
    'src/plugins/prepared-model-generation.lifecycle.test.ts',
)

COMPAT_EXTRA = (
    'extensions/msteams/src/sdk.msal-compat.test.ts',
    'src/acp/translator.lifecycle.test.ts',
    'src/acp/translator.session-setup.test.ts',
    'src/auto-reply/reply/commands-mcp.test.ts',
    'src/cli/mcp-cli.test.ts',
    'src/gateway/server-methods/nodes.test.ts',
    'src/gateway/server.sessions.create.workspace-policy.test.ts',
    'src/gateway/server.sessions.create.worktrees.test.ts',
    'src/gateway/tool-resolution.test.ts',
    'src/infra/npm-managed-root.overrides.test.ts',
    'src/logging/log-tail-redaction.test.ts',
    'src/logging/redact.test.ts',
    'test/scripts/a2ui-zod-bounds.test.ts',
    'test/scripts/ci-hydrate-live-auth.test.ts',
    'test/scripts/clawhub-cli-security-pin.test.ts',
    'test/scripts/discord-sdk-zod.test.ts',
)

H3_COMPAT_EXTRA = (
    'extensions/file-transfer/src/shared/policy.test.ts',
    'src/agents/workspace-bootstrap-policy.platform.test.ts',
    'src/agents/workspace-bootstrap-policy.test.ts',
    'src/daemon/systemd-scalar-paths.test.ts',
)

MIGRATION_REQUIRED = (
    'src/commands/backup-restore.test.ts',
    'src/commands/backup-sqlite.test.ts',
    'src/commands/doctor-migration-backup.scoped.test.ts',
    'src/commands/doctor-migration-backup.test.ts',
    'src/state/openclaw-agent-json-predicate-schema.test.ts',
    'src/state/openclaw-state-db-schema-v21-columns.test.ts',
    'src/state/openclaw-state-db-schema-v22-columns.test.ts',
    'src/state/openclaw-state-h3-v20-upgrade.test.ts',
)

REQUIRED_HELPERS = (
    'test/scripts/a2ui-zod-bounds.regression.mjs',
)

NATIVE_DEPENDENCY_NAMES = frozenset((
    'a2ui-native-zod-regression.test.mjs',
    'body-parser-security.test.mjs',
    'discord-native-zod-regression.test.mjs',
    'http-cache-semantics-compat.test.mjs',
    'mcp-nowistay-schema-compatibility.test.mjs',
    'mcp-nowistay-sdk-regression.test.mjs',
    'msal-parent-compat.test.mjs',
    'undici-security.test.mjs',
    'zod-container-bounds.test.mjs',
))

REQUIRED_SOURCE_TESTS = tuple(sorted(set(
    SQLITE_EXTRA + DOCTOR_EXTRA + MODEL_EXTRA + COMPAT_EXTRA + H3_COMPAT_EXTRA
)))

# Only this unchanged test and helper have a positive synthetic-only review.
MOCKED_UNITS = {
    "test/scripts/ci-hydrate-live-auth.test.ts": "600f7908525aa7b321c91f7d42ed7ec9ac0d55ad1d5d751fb8a0fed42f2b60c0",
}
MOCKED_HELPERS = {
    "scripts/ci-hydrate-live-auth.sh": "b4c1c81471d05484a953fbdbd5a4fe06eedfcc245dc237a95c5f4da96ce818b6",
}

PIPELINE_CONTRACT_TESTS = (
    "test_source_contract_v110.py",
    "test_lockfile_policy_v110.py",
    "test_source_validation_selection_v110.py",
    "test_source_validation_v110.py",
    "test_bounded_run_contract_v109.py",
)


def _need(value, code):
    contract.need(value, "v110.selection." + code)


def _paths(paths):
    _need(type(paths) in (list, tuple, set, frozenset) and all(
        type(p) is str and p and not p.startswith(("/", "-")) and "\\" not in p and
        not any(ord(c) < 32 or ord(c) == 127 for c in p) and
        all(part not in ("", ".", "..") for part in p.split("/")) for p in paths),
        "tracked_paths")
    _need(len(paths) == len(set(paths)), "unique_tracked_paths")
    return set(paths)


def verify_mocked_units(read_file):
    _need(set(MOCKED_UNITS) == {"test/scripts/ci-hydrate-live-auth.test.ts"} and
        set(MOCKED_HELPERS) == {"scripts/ci-hydrate-live-auth.sh"},
        "mocked_helper_preparation_complete")
    for path, expected in {**MOCKED_UNITS, **MOCKED_HELPERS}.items():
        raw = read_file(path)
        _need(type(raw) is bytes and 0 < len(raw) <= 64 * 1024 and
            hashlib.sha256(raw).hexdigest() == expected, "exact_mocked_unit_and_helper")
    return {"syntheticLiveNamedUnitFiles": sorted(MOCKED_UNITS),
        "helperFiles": sorted(MOCKED_HELPERS), "liveProviderCredentialsAllowed": False}


def verify_pipeline_contract_files(read_file):
    # unittest discovery accepts a missing -p filename as zero tests. Positively
    # bind the fixed test modules before asking the maintained executor to run them.
    for name in PIPELINE_CONTRACT_TESTS:
        raw = read_file("scripts/fork-release/" + name)
        _need(type(raw) is bytes and 0 < len(raw) <= 512 * 1024, "pipeline_test_file")
        try:
            tree = ast.parse(raw)
        except (SyntaxError, ValueError, UnicodeError):
            raise contract.Refusal("v110.selection.pipeline_test_syntax")
        unittest_names = {alias.asname or alias.name for node in tree.body
            if isinstance(node, ast.Import) for alias in node.names if alias.name == "unittest"}
        testcase_names = {alias.asname or alias.name for node in tree.body
            if isinstance(node, ast.ImportFrom) and node.module == "unittest" and node.level == 0
            for alias in node.names if alias.name == "TestCase"}
        _need(any(isinstance(node, ast.ClassDef) and any(
            (isinstance(base, ast.Attribute) and base.attr == "TestCase" and
                isinstance(base.value, ast.Name) and base.value.id in unittest_names) or
            (isinstance(base, ast.Name) and base.id in testcase_names) for base in node.bases) and
            any(isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)) and
                method.name.startswith("test_") for method in node.body) for node in tree.body),
            "positive_pipeline_test_definitions")
    return {"fixedTestModules": list(PIPELINE_CONTRACT_TESTS), "missingModuleAccepted": False}


LOCK_PREPARATION_TEMPLATE = "scripts/fork-release/fixtures/v110-lock-preparation.yml"
SOURCE_VALIDATION_TEMPLATE = "scripts/fork-release/fixtures/v110-source-validation.yml"


def render_workflow(template_raw, *, pr_number, source_sha, entry_sha256,
                    code_manifest_sha256, effective_at):
    """Render only fixed disarmed fields in an already code-bound role fixture.

    The runtime reads one of the two fixed fixture paths from its verified code
    closure, then compares the complete returned bytes with the operational W.
    No runtime head/request hash is embedded here, avoiding a code/W hash cycle.
    """
    _need(type(template_raw) is bytes and 0 < len(template_raw) <= 256 * 1024,
        "workflow_fixture_bytes")
    _need(type(pr_number) is int and 1 <= pr_number <= 9999999999 and
        type(source_sha) is str and re.fullmatch(r"[0-9a-f]{40}", source_sha) is not None and
        source_sha != "0" * 40 and
        all(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None and
            value != "0" * 64 for value in (entry_sha256, code_manifest_sha256)) and
        effective_at == "2026-11-03T09:12:23Z", "workflow_render_bindings")
    try:
        text = template_raw.decode("utf-8")
    except UnicodeError:
        raise contract.Refusal("v110.selection.workflow_fixture_encoding")
    for key, old, new in (("ARMED", "false", "true"), ("BOUND_PR", "0", str(pr_number)),
            ("SOURCE_SHA", "0" * 40, source_sha), ("ENTRY_SHA256", "0" * 64, entry_sha256),
            ("CODE_MANIFEST_SHA256", "0" * 64, code_manifest_sha256),
            ("EFFECTIVE_AT", "DISARMED", effective_at)):
        marker = "  V110_" + key + ": '" + old + "'\n"
        _need(text.count(marker) == 1, "workflow_fixed_disarmed_field")
        text = text.replace(marker, "  V110_" + key + ": '" + new + "'\n")
    marker = "github.event.pull_request.number == 0 &&"
    _need(text.count(marker) in (1, 3), "workflow_fixed_pr_conditions")
    return text.replace(marker, "github.event.pull_request.number == " + str(pr_number) + " &&").encode("utf-8")


def selected_tests(paths, profile):
    known = _paths(paths)
    _need(profile in contract.PROFILES, "fixed_profile")
    legacy_request = {"schema": legacy.R8_SCHEMA}
    if profile.startswith("models-"):
        family = set(MODEL_EXTRA)
        for name in ("models-1", "models-2"):
            family.update(legacy.selected_tests(paths, name, legacy_request))
        result = sorted(family)[int(profile[-1]) - 1::2]
    elif profile.startswith("doctor-"):
        family = set(DOCTOR_EXTRA)
        for name in ("doctor-1", "doctor-2", "doctor-3"):
            family.update(legacy.selected_tests(paths, name, legacy_request))
        ordered = sorted(family)
        priority = [p for p in ordered if re.search(r"(?:process|session)", p.rsplit("/", 1)[-1])]
        rest = [p for p in ordered if p not in set(priority)]
        result = sorted((priority + rest)[int(profile[-1]) - 1::3])
    elif profile == "sqlite":
        result = sorted(set(legacy.selected_tests(paths, profile, legacy_request)) | set(SQLITE_EXTRA))
    elif profile == "compatibility":
        result = sorted(set(legacy.V6_RUNTIME_COMPATIBILITY_TESTS) | set(COMPAT_EXTRA) | set(H3_COMPAT_EXTRA))
    else:
        result = legacy.selected_tests(paths, profile, legacy_request)
    _need(set(result) <= known, "maintained_selection_tracked")
    _need(all(contract.TEST_PATH.fullmatch(p) for p in result), "fixed_test_paths")
    _need(not any(re.search(r"(?:^|[./-])live(?:[./-]|$)", p) and p not in MOCKED_UNITS
        for p in result), "no_unreviewed_live_tests")
    return result


def coverage(paths):
    known = _paths(paths)
    _need(set(REQUIRED_SOURCE_TESTS + REQUIRED_HELPERS) <= known,
        "complete_changed_recovery_security_paths")
    families = {p: selected_tests(paths, p) for p in contract.PROFILES
        if p.startswith(("models-", "doctor-", "workboard-")) or
        p in ("sqlite", "memory", "compatibility")}
    for group in (("models-1", "models-2"), ("doctor-1", "doctor-2", "doctor-3"),
                  ("workboard-1", "workboard-2")):
        all_paths = [p for name in group for p in families[name]]
        _need(len(all_paths) == len(set(all_paths)), "disjoint_family_shards")
    selected = {p for group in families.values() for p in group}
    _need(set(REQUIRED_SOURCE_TESTS) <= selected, "complete_new_owner_coverage")
    _need(all(sum(path in family for family in families.values()) == 1
        for path in MIGRATION_REQUIRED), "migration_owner_selected_once")
    return {"requiredNewOrChangedTests": list(REQUIRED_SOURCE_TESTS),
        "requiredMigrationTests": list(MIGRATION_REQUIRED),
        "requiredNativeHelperFiles": list(REQUIRED_HELPERS),
        "familyCounts": {k: len(v) for k, v in families.items()},
        "freshSourceCoverageRequired": True, "priorGenerationCoverageReused": False,
        "retiredToolSearchDiagnosticsRestored": False}


def commands(pipeline, source, profile, tracked_paths, request, bindings):
    _need(profile in contract.PROFILES and request.get("phase") in ("validation", "correction"),
        "execution_profile")
    _need(bindings.get("newRecoveryTests") == list(MIGRATION_REQUIRED),
        "binding_complete_migration_roots")
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
            len({p.rsplit("/", 1)[-1] for p in native}) == len(NATIVE_DEPENDENCY_NAMES),
            "complete_native_dependency_suite")
        return [["pnpm", "deps:patches:check"], ["pnpm", "audit"], ["pnpm", "audit", "--prod"],
            ["node", native_owner, "--source-root", str(source), "--", *native]]
    if profile == "pipeline-contracts":
        return [["python3", "-m", "unittest", "discover", "-s", str(pipeline / "scripts/fork-release"),
            "-p", name] for name in PIPELINE_CONTRACT_TESTS]
    if profile == "compatibility":
        _need("test/v108-remediation-security.test.mjs" in tracked_paths, "native_fork_security_suite")
        _need(type(request.get("source")) is dict and
            type(request["source"].get("sourceSha")) is str and
            re.fullmatch(r"[0-9a-f]{40}", request["source"]["sourceSha"]) is not None,
            "source_identity")
        return [["node", native_owner, "--source-root", str(source), "--", "test/v108-remediation-security.test.mjs"],
            ["node", "--import", "./scripts/tsx.mjs", "scripts/test-projects.mts", *selected_tests(tracked_paths, profile)],
            ["pnpm", "deps:npm-lock:check:changed", "--base", contract.UPSTREAM["commit"],
                "--head", request["source"]["sourceSha"]],
            ["node", "--input-type=module", "-e", legacy.V6_BUNDLED_NPM_VERSION_CHECK]]
    selected = selected_tests(tracked_paths, profile)
    _need(bool(selected), "nonempty_owner_family")
    return [["node", "--import", "./scripts/tsx.mjs", "scripts/test-projects.mts", *selected]]
