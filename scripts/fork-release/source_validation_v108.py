#!/usr/bin/env python3
"""Bounded, public GitHub source-validation campaign; never an execution approval.

Only the reviewed fixed request selects a round and named profiles. PR text,
dispatch inputs, arbitrary commands, refs and URLs are not an input surface.
"""

import argparse
from contextlib import contextmanager
import base64
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import time
import subprocess
import sys
import tempfile
import urllib.request
import urllib.error

import preflight
import release

REPOSITORY = "fr-meyer/openclaw"
CAMPAIGN = "future-v108-source-validation-20261027"
# Historical F5 helper defaults. Operational admission uses literal STAGE_PINS below.
SOURCE = "f5c198efedd78625e5a1b4a133d58ebfb3dae1c5"
TREE = "c4b245211ceaab98b397945bb0177770f1052c90"
FIRST_SOURCE = "f5c198efedd78625e5a1b4a133d58ebfb3dae1c5"
FIRST_TREE = "c4b245211ceaab98b397945bb0177770f1052c90"
ORIGINAL_SOURCE = "61f924bdb7ed4f837096c87120087919ff0a6bdf"
SOURCE_AUTHORIZATION = "future-v108-remediation-20261028T0433Z"
BASE = "a65f70c5dad17b39bc3ee26ba92cde6d00bfb259"
TARGET_BRANCH_TIP = "918890b9f72b2d0372995362e8ea3088e0f87431"
APPROVAL_DEADLINE = "2026-10-29T00:03:19Z"
RETAINED_SOURCE_RUN_IDS = ("40607329263", "40609889437", "40616416909")
SETTLED_MINUTES = 425
BRANCH = "task/v107-source-binding"
BASE_BRANCH = "release-pipeline/v105-image-only-20261024"
WORKFLOW = ".github/workflows/future-v108-source-validation.yml"
CANDIDATE = "scripts/fork-release/candidates/v2026.10.8-source-only"
REQUEST = CANDIDATE + "/source-request.json"
SETTLED_USAGE = CANDIDATE + "/settled-usage.json"
LEGACY_PROFILE_MINUTES = {
    "dependency": 60, "types-production": 90, "types-tests": 90,
    "types-scripts": 90, "workboard-1": 60, "workboard-2": 60,
    "models-1": 60, "models-2": 60, "sqlite": 60, "doctor": 60,
    "memory": 60, "pipeline-contracts": 30,
}
PROFILE_MINUTES = {
    "dependency": 60, "types-production": 90, "types-tests": 90,
    "types-scripts": 90, "workboard-1": 60, "workboard-2": 60,
    "models-1": 60, "models-2": 60, "sqlite": 60,
    "doctor-1": 45, "doctor-2": 45, "doctor-3": 45,
    "memory": 60, "pipeline-contracts": 30, "compatibility": 60,
}
# New-stage source/request/control pins are root-owned and remain UNFINAL here.
# The exported historical policy must never inherit the repaired Doctor cap.
REPAIR_PROFILE_POLICY = "five-gate-repair-v1"
REPAIR_PROFILE_MINUTES = {**PROFILE_MINUTES, "doctor-1": 60}
INITIAL_MINUTES = 940
CAMPAIGN_MINUTES = 1800
ANCILLARY_MINUTES = 135
MAX_CORRECTION_MINUTES = 300
INITIAL_RESUME_RUN_ID = "40639374411"
INITIAL_RESUME_PIPELINE = "95df4eb49204150c8aaaa9da8e2abd3112fa5972"
INITIAL_RESUME_REQUEST_SHA256 = "c7d63de47231fc368477635cc0f28e7b8e015129ebed8987b76ce01a636b83d1"
INITIAL_RESUME_WITNESS = {
    "schema": "openclaw.v108.initial-resume.v1", "priorRunId": INITIAL_RESUME_RUN_ID,
    "priorPipelineHead": INITIAL_RESUME_PIPELINE,
    "sourceSha": "f5c198efedd78625e5a1b4a133d58ebfb3dae1c5",
    "sourceTree": "c4b245211ceaab98b397945bb0177770f1052c90",
    "manifestSha256": "802abd7c85ee123621d7cc96796ffcd0cf40d58c0d4db60f5f32304802a11f0b",
    "inventorySha256": "876afa1cf8c6398b1fe3f5cdaa031bf1796d96b3e3307352e5a5571b8e3a296e",
    "priorRequestSha256": INITIAL_RESUME_REQUEST_SHA256,
}
JOB_OVERHEAD_MINUTES = 25  # admission15 + final10
DERIVED_LEDGER_PATH = "custom-patches/reconciliation-2026.10.8.json"
TEST_ONLY_PATHS = frozenset((
    "src/gateway/server-managed-task-flow-runtime.mergeguez-parity.test.ts",
    "src/gateway/server-managed-task-flow-runtime.mergeguez-recovery.test.ts",
    "src/commands/doctor-config-preflight.process.test.ts",
    "test/body-parser-security.test.mjs", "test/v108-remediation-security.test.mjs",
))
COMPATIBILITY_TESTS = (
    "ui/src/components/markdown-mermaid.test.ts",
    "ui/src/components/markdown-mermaid-native.browser.test.ts",
    "ui/src/components/markdown-mermaid.runtime.browser.test.ts",
    "ui/src/e2e/chat-mermaid-load-errors.e2e.test.ts",
    "test/scripts/vitest-mock-resolution.test.ts",
    "test/scripts/vitest-forks-pool.test.ts",
    "test/scripts/vitest-fork-shutdown.test.ts",
    "test/scripts/vitest-isolated.test.ts",
    "test/scripts/vitest-isolated-build.test.ts",
    "extensions/imap/src/sender-gate.test.ts", "extensions/imap/src/watcher.test.ts",
    "src/agents/agent-bundle-mcp-requester-connect.import-boundary.test.ts",
    "src/agents/agent-bundle-mcp-retirement-boundaries.test.ts",
    "src/agents/agent-bundle-mcp-tools.request-boundary.test.ts",
    "src/agents/mcp-ui-resource.import-boundary.test.ts",
    "src/cli/mcp-cli.import-boundary.test.ts",
)
HEX256 = re.compile(r"[0-9a-f]{64}\Z")
RUN_ID = re.compile(r"[1-9][0-9]{0,19}\Z")
# Exact public pnpm@12.15.0 tarball files, inspected against registry SHA-512.
# Only this initializer and its one local import run during bootstrap.
PNPM_BOOTSTRAP_FILES = {
    "package.json": "f3e2afee436a7793338c6837ee58f73d97db0de874e9f2a8acd1bf6d83eae0be",
    "install.js": "f176986d8aad7d17c3328178928b9ba72d30b1a1c9edc94d2a279a51d8d6da6e",
    "native-binary.mjs": "27c6039ef59196ad19cca8915c391b0ec34df2f9a91519717f87c28984787565",
}
TEST_PATH = re.compile(r"[A-Za-z0-9_./@+-]+\.(?:test|e2e)\.[cm]?[jt]s\Z")


# Admission diagnostics project only these reviewed source literals. Never use
# exception text, API bodies, child output or arbitrary labels as public codes.
ADMISSION_NEED_CODES = {'API timestamp': 'need.api_timestamp', 'Linux memory metadata': 'need.linux_memory_metadata', 'PR event and first attempt required': 'need.pr_event_and_first_attempt_required', 'actual prior425 proof': 'need.actual_prior425_proof', 'admitted campaign deadline/profile required': 'need.admitted_campaign_deadline_profile_required', 'all affected test-only owner profiles': 'need.all_affected_test_only_owner_profiles', 'all other tracked bytes equivalence': 'need.all_other_tracked_bytes_equivalence', 'ancillary alarm already owned': 'need.ancillary_alarm_already_owned', 'ancillary observation owned admission identity': 'need.ancillary_observation_owned_admission_identity', 'ancillary observation source/prefix metadata changed': 'need.ancillary_observation_source_prefix_metadata_changed', 'ancillary still unsettled after bounded60-second observation': 'need.ancillary_still_unsettled_after_bounded60_second_observation', 'authorized successor request': 'need.authorized_successor_request', 'bootstrap runtimes required': 'need.bootstrap_runtimes_required', 'bound first-source receipt': 'need.bound_first_source_receipt', 'bounded API response': 'need.bounded_api_response', 'bounded Git-backed content': 'need.bounded_git_backed_content', 'bounded complete branch history': 'need.bounded_complete_branch_history', 'bounded derived ledger': 'need.bounded_derived_ledger', 'bounded exact source closure commits': 'need.bounded_exact_source_closure_commits', 'bounded summary': 'need.bounded_summary', 'closed exact initial-resume witness': 'need.closed_exact_initial_resume_witness', 'closed test-only witness': 'need.closed_test_only_witness', 'complete compatibility acceptance paths': 'need.complete_compatibility_acceptance_paths', 'complete current admission job table': 'need.complete_current_admission_job_table', 'complete dependency regression set': 'need.complete_dependency_regression_set', 'complete new ancillary job table': 'need.complete_new_ancillary_job_table', 'complete ordered prior source runs': 'need.complete_ordered_prior_source_runs', 'complete settled 57-record prefix': 'need.complete_settled_57_record_prefix', 'complete terminal job table': 'need.complete_terminal_job_table', 'complete test-only plus derived-ledger changed set': 'need.complete_test_only_plus_derived_ledger_changed_set', 'complete unique history pages': 'need.complete_unique_history_pages', 'content size': 'need.content_size', 'current admission acquisition': 'need.current_admission_acquisition', 'current admission runner': 'need.current_admission_runner', 'current source round identity': 'need.current_source_round_identity', 'derived ledger row schema': 'need.derived_ledger_row_schema', 'duplicate JSON key': 'need.duplicate_json_key', 'early admission clock freshness': 'need.early_admission_clock_freshness', 'early admission clock required': 'need.early_admission_clock_required', 'empty owner family': 'need.empty_owner_family', 'event action': 'need.event_action', 'exact annotated upstream tag binding': 'need.exact_annotated_upstream_tag_binding', 'exact campaign source run identity': 'need.exact_campaign_source_run_identity', 'exact published v2 prior request': 'need.exact_published_v2_prior_request', 'exact reviewed successor source': 'need.exact_reviewed_successor_source', 'exact source closure fetch failed': 'need.exact_source_closure_fetch_failed', 'exact test-only paths': 'need.exact_test_only_paths', 'exact two witnessed source checkout refs': 'need.exact_two_witnessed_source_checkout_refs', 'exact unstarted initial job set': 'need.exact_unstarted_initial_job_set', 'fetched workflow commit changed': 'need.fetched_workflow_commit_changed', 'first-source complete job booking exceeded': 'need.first_source_complete_job_booking_exceeded', 'fixed API route': 'need.fixed_api_route', 'fixed Node version': 'need.fixed_node_version', 'fixed base': 'need.fixed_base', 'fixed content identity': 'need.fixed_content_identity', 'fixed five-gate profile policy': 'need.fixed_five_gate_profile_policy', 'fixed live target branch tip': 'need.fixed_live_target_branch_tip', 'fixed pnpm package/version/bin': 'need.fixed_pnpm_package_version_bin', 'fixed pnpm version': 'need.fixed_pnpm_version', 'fixed settled run fields': 'need.fixed_settled_run_fields', 'fixed settled usage envelope': 'need.fixed_settled_usage_envelope', 'fixed unique profiles': 'need.fixed_unique_profiles', 'four lifetime operator rounds': 'need.four_lifetime_operator_rounds', 'frozen install failed': 'need.frozen_install_failed', 'initial admission failed acquired within15 rounded minutes': 'need.initial_admission_failed_acquired_within15_rounded_minutes', 'initial source/final explicitly skipped unacquired': 'need.initial_source_final_explicitly_skipped_unacquired', 'initial-resume exact failed prior source/controls': 'need.initial_resume_exact_failed_prior_source_controls', 'initial-resume provider run/head binding': 'need.initial_resume_provider_run_head_binding', 'insufficient admission/deadline observation time': 'need.insufficient_admission_deadline_observation_time', 'insufficient shared product checkout budget': 'need.insufficient_shared_product_checkout_budget', 'insufficient time in approved campaign': 'need.insufficient_time_in_approved_campaign', 'internal120 ancillary-record alarm': 'need.internal120_ancillary_record_alarm', 'known historical profile policy': 'need.known_historical_profile_policy', 'ledger changed beyond exact derived test result blobs': 'need.ledger_changed_beyond_exact_derived_test_result_blobs', 'lifetime1800 runner-minute ceiling': 'need.lifetime1800_runner_minute_ceiling', 'literal workflow commit required': 'need.literal_workflow_commit_required', 'live head changed': 'need.live_head_changed', 'missing admitted profile jobs': 'need.missing_admitted_profile_jobs', 'missing campaign boundary job': 'need.missing_campaign_boundary_job', 'named profile required': 'need.named_profile_required', 'native pnpm executable': 'need.native_pnpm_executable', 'new ancillary elapsed time': 'need.new_ancillary_elapsed_time', 'new ancillary job identity/attempt': 'need.new_ancillary_job_identity_attempt', 'new ancillary public identity/path/head': 'need.new_ancillary_public_identity_path_head', 'new ancillary run state': 'need.new_ancillary_run_state', 'new ancillary terminal conclusion': 'need.new_ancillary_terminal_conclusion', 'new ancillary terminal time evidence': 'need.new_ancillary_terminal_time_evidence', 'new ancillary135-minute bucket exceeded': 'need.new_ancillary135_minute_bucket_exceeded', 'new source authorization time': 'need.new_source_authorization_time', 'no ancillary usage headroom for observation': 'need.no_ancillary_usage_headroom_for_observation', 'no owned job budget remains': 'need.no_owned_job_budget_remains', 'observed ancillary identity changed': 'need.observed_ancillary_identity_changed', 'observed ancillary run disappeared': 'need.observed_ancillary_run_disappeared', 'old ledger result matches exact parent test blob': 'need.old_ledger_result_matches_exact_parent_test_blob', 'one full successor round': 'need.one_full_successor_round', 'open draft PR28': 'need.open_draft_pr28', 'ordered new source rounds': 'need.ordered_new_source_rounds', 'original approval deadline': 'need.original_approval_deadline', 'owned pnpm command link': 'need.owned_pnpm_command_link', 'owned regular pnpm bootstrap file': 'need.owned_regular_pnpm_bootstrap_file', 'pinned annotated upstream tag': 'need.pinned_annotated_upstream_tag', 'pinned pnpm bootstrap file digest': 'need.pinned_pnpm_bootstrap_file_digest', 'pipeline checkout head': 'need.pipeline_checkout_head', 'positive in-progress ancillary acquisition': 'need.positive_in_progress_ancillary_acquisition', 'positive queued ancillary unacquired evidence': 'need.positive_queued_ancillary_unacquired_evidence', 'positive unacquired terminal evidence': 'need.positive_unacquired_terminal_evidence', 'prior new round terminal': 'need.prior_new_round_terminal', 'profile not in admitted request': 'need.profile_not_in_admitted_request', 'profile policy record required': 'need.profile_policy_record_required', 'public hosted Linux only': 'need.public_hosted_linux_only', 'public repository': 'need.public_repository', 'read-only API token required': 'need.read_only_api_token_required', 'repository/ref': 'need.repository_ref', 'request digest': 'need.request_digest', 'request fields': 'need.request_fields', 'request metadata hashes': 'need.request_metadata_hashes', 'reviewed source pins required': 'need.reviewed_source_pins_required', 'reviewed workflow/code bytes': 'need.reviewed_workflow_code_bytes', 'run identity': 'need.run_identity', 'same-repository reviewed head': 'need.same_repository_reviewed_head', 'settled new ancillary state changed': 'need.settled_new_ancillary_state_changed', 'settled provider usage changed': 'need.settled_provider_usage_changed', 'settled run identity/state': 'need.settled_run_identity_state', 'settled usage digest': 'need.settled_usage_digest', 'settled425 source/ancillary coverage': 'need.settled425_source_ancillary_coverage', 'source checkout required': 'need.source_checkout_required', 'source checkout/tree': 'need.source_checkout_tree', 'source closure commit type': 'need.source_closure_commit_type', 'source closure remains shallow': 'need.source_closure_remains_shallow', 'source closure shared deadline exhausted': 'need.source_closure_shared_deadline_exhausted', 'source job clock freshness': 'need.source_job_clock_freshness', 'source job clock required': 'need.source_job_clock_required', 'source shallow state': 'need.source_shallow_state', 'source-only manifest': 'need.source_only_manifest', 'stable branch history pagination': 'need.stable_branch_history_pagination', 'standard public Ubuntu acquired runner': 'need.standard_public_ubuntu_acquired_runner', 'standard runner below engineering resource floors': 'need.standard_runner_below_engineering_resource_floors', 'targeted correction minute cap': 'need.targeted_correction_minute_cap', 'terminal ancillary run has pending jobs': 'need.terminal_ancillary_run_has_pending_jobs', 'terminal first-attempt unique job': 'need.terminal_first_attempt_unique_job', 'terminal job duration': 'need.terminal_job_duration', 'terminal unique positive job ID': 'need.terminal_unique_positive_job_id', 'test-only parent tree': 'need.test_only_parent_tree', 'test-only successor added/deleted path': 'need.test_only_successor_added_deleted_path', 'test-only successor must be direct single-parent': 'need.test_only_successor_must_be_direct_single_parent', 'test/ledger mode or type changed': 'need.test_ledger_mode_or_type_changed', 'unique derived ledger rows': 'need.unique_derived_ledger_rows', 'unknown new ancillary job state': 'need.unknown_new_ancillary_job_state', 'unlisted/duplicate source round': 'need.unlisted_duplicate_source_round', 'unwitnessed source repin': 'need.unwitnessed_source_repin', 'witness parent/digest': 'need.witness_parent_digest', 'workflow acquisition changed checkout': 'need.workflow_acquisition_changed_checkout', 'workflow identity': 'need.workflow_identity', 'workflow merge target parent': 'need.workflow_merge_target_parent', 'workflow/security caps changed between new rounds': 'need.workflow_security_caps_changed_between_new_rounds', 'v4.history.ancillary45_exceeded': 'need.v4_history_ancillary45_exceeded', 'v4.history.ancillary_record_bound': 'need.v4_history_ancillary_record_bound', 'v4.history.artifact_duplicate': 'need.v4_history_artifact_duplicate', 'v4.history.artifact_identity_size': 'need.v4_history_artifact_identity_size', 'v4.history.artifact_storage_bound': 'need.v4_history_artifact_storage_bound', 'v4.history.artifacts_complete': 'need.v4_history_artifacts_complete', 'v4.history.branch_page': 'need.v4_history_branch_page', 'v4.history.branch_page_size': 'need.v4_history_branch_page_size', 'v4.history.branch_pagination': 'need.v4_history_branch_pagination', 'v4.history.branch_unique_ids': 'need.v4_history_branch_unique_ids', 'v4.history.current_jobs_before_admission': 'need.v4_history_current_jobs_before_admission', 'v4.history.current_public_admission': 'need.v4_history_current_public_admission', 'v4.history.current_source_identity': 'need.v4_history_current_source_identity', 'v4.history.deadline': 'need.v4_history_deadline', 'v4.history.first_booking_exceeded': 'need.v4_history_first_booking_exceeded', 'v4.history.first_job_conclusion': 'need.v4_history_first_job_conclusion', 'v4.history.first_request_digest': 'need.v4_history_first_request_digest', 'v4.history.first_request_round': 'need.v4_history_first_request_round', 'v4.history.first_source_terminal': 'need.v4_history_first_source_terminal', 'v4.history.fresh_job_binding': 'need.v4_history_fresh_job_binding', 'v4.history.fresh_jobs_complete': 'need.v4_history_fresh_jobs_complete', 'v4.history.genuine_first_controls_required': 'need.v4_history_genuine_first_controls_required', 'v4.history.lifetime18000_exceeded': 'need.v4_history_lifetime18000_exceeded', 'v4.history.live_pr_changed': 'need.v4_history_live_pr_changed', 'v4.history.new_ancillary_conclusion': 'need.v4_history_new_ancillary_conclusion', 'v4.history.new_ancillary_identity': 'need.v4_history_new_ancillary_identity', 'v4.history.prefix_actual886': 'need.v4_history_prefix_actual886', 'v4.history.prefix_digest': 'need.v4_history_prefix_digest', 'v4.history.prefix_envelope': 'need.v4_history_prefix_envelope', 'v4.history.prefix_header_changed': 'need.v4_history_prefix_header_changed', 'v4.history.prefix_job_attempt': 'need.v4_history_prefix_job_attempt', 'v4.history.prefix_job_minutes': 'need.v4_history_prefix_job_minutes', 'v4.history.prefix_run_identity': 'need.v4_history_prefix_run_identity', 'v4.history.source_branch_tip': 'need.v4_history_source_branch_tip', 'v4.history.source_round_set': 'need.v4_history_source_round_set', 'v4.history.source_run_binding': 'need.v4_history_source_run_binding', 'v4.history.target_tip': 'need.v4_history_target_tip', 'v4.history.unresolved_first_profiles_selected': 'need.v4_history_unresolved_first_profiles_selected', 'v4.history.workflow_block': 'need.v4_history_workflow_block', 'v4.history.workflow_concurrency': 'need.v4_history_workflow_concurrency', 'v4.history.workflow_credentials': 'need.v4_history_workflow_credentials', 'v4.history.workflow_fixed_actions': 'need.v4_history_workflow_fixed_actions', 'v4.history.workflow_job_caps': 'need.v4_history_workflow_job_caps', 'v4.history.workflow_job_permissions': 'need.v4_history_workflow_job_permissions', 'v4.history.workflow_jobs': 'need.v4_history_workflow_jobs', 'v4.history.workflow_literal_mapping': 'need.v4_history_workflow_literal_mapping', 'v4.history.workflow_matrix_policy': 'need.v4_history_workflow_matrix_policy', 'v4.history.workflow_permissions': 'need.v4_history_workflow_permissions', 'v4.history.workflow_runner_job_keys': 'need.v4_history_workflow_runner_job_keys', 'v4.history.workflow_size': 'need.v4_history_workflow_size', 'v4.history.workflow_source_refs': 'need.v4_history_workflow_source_refs', 'v4.history.workflow_token_surface': 'need.v4_history_workflow_token_surface', 'v4.history.workflow_top_level': 'need.v4_history_workflow_top_level', 'v4.history.workflow_trigger': 'need.v4_history_workflow_trigger', 'v4.history.workflow_yaml_shape': 'need.v4_history_workflow_yaml_shape', 'v4.history.first_unexpanded_positive_evidence': 'need.v4_history_first_unexpanded_positive_evidence', 'v4.history.prefix_projection_schema': 'need.v4_history_prefix_projection_schema'}
ADMISSION_PHASES = frozenset(("input", "metadata", "binding", "history", "closure", "equivalence", "matrix"))
ADMISSION_SUBCHECKS = frozenset(("event.read", "event.validate", "manifest.request", "code.bind",
    "current-pr", "target-ref", "branch-history", "settled-prefix", "source-rounds", "prior-round",
    "new-ancillary", "closure.acquire", "equivalence.verify", "matrix.publish", "api.read"))
_ADMISSION_DIAGNOSTIC = None


def diagnostic_run_id(value):
    return int(value) if type(value) is str and re.fullmatch(r"[1-9][0-9]{0,19}", value) else None


def admission_stage(phase, subcheck, run_id=None):
    if _ADMISSION_DIAGNOSTIC is not None:
        _ADMISSION_DIAGNOSTIC.update(
            phase=phase if phase in ADMISSION_PHASES else "unprojected",
            subcheck=subcheck if subcheck in ADMISSION_SUBCHECKS else "unprojected",
            relatedRunId=diagnostic_run_id(run_id))


@contextmanager
def admission_api_read(path):
    if _ADMISSION_DIAGNOSTIC is None:
        yield
        return
    previous = (_ADMISSION_DIAGNOSTIC["subcheck"], _ADMISSION_DIAGNOSTIC["relatedRunId"])
    match = re.fullmatch(r"/repos/fr-meyer/openclaw/actions/runs/([1-9][0-9]{0,19})/jobs\?filter=all&per_page=100", path)
    _ADMISSION_DIAGNOSTIC.update(subcheck="api.read", relatedRunId=diagnostic_run_id(match[1]) if match else previous[1])
    try:
        yield
    except BaseException:
        # Preserve only the fixed failing location; no response/error data.
        raise
    else:
        _ADMISSION_DIAGNOSTIC.update(subcheck=previous[0], relatedRunId=previous[1])


@contextmanager
def admission_diagnostics(env, enabled, operational=False):
    global _ADMISSION_DIAGNOSTIC
    previous = _ADMISSION_DIAGNOSTIC
    if not enabled:
        yield
        return
    _ADMISSION_DIAGNOSTIC = {"phase": "input", "subcheck": "event.read",
        "runId": diagnostic_run_id(env.get("GITHUB_RUN_ID")), "relatedRunId": None}
    try:
        yield
    except (release.Refusal, OSError, ValueError, KeyError, TypeError,
            subprocess.CalledProcessError, ProfileInterrupted) as error:
        classes = ((R8ContractRefusal, "R8ContractRefusal"),
                   (R7ContractRefusal, "R7ContractRefusal"),
                   (V6ContractRefusal, "V6ContractRefusal"),
                   (V5ContractRefusal, "V5ContractRefusal"),
                   (V4ContractRefusal, "V4ContractRefusal"),
                   (urllib.error.HTTPError, "HTTPError"),
                   (subprocess.CalledProcessError, "CalledProcessError"),
                   (release.Refusal, "Refusal"), (ProfileInterrupted, "ProfileInterrupted"),
                   (OSError, "OSError"), (ValueError, "ValueError"),
                   (KeyError, "KeyError"), (TypeError, "TypeError"))
        error_class = next((name for cls, name in classes if isinstance(error, cls)), "UnprojectedError")
        status = error.code if isinstance(error, urllib.error.HTTPError) else None
        child_exit = error.returncode if isinstance(error, subprocess.CalledProcessError) else None
        # HTTPError may delegate unknown attributes to an absent file handle.
        # Read only our own annotation; never inspect/format exception payloads.
        code = runtime_refusal_code_v7(error) if operational else vars(error).get("admission_need_code")
        if operational:
            trusted = (R8_STAGE_PINS if type(R8_STAGE_PINS) is dict else
                       R7_STAGE_PINS if type(R7_STAGE_PINS) is dict else
                       V6_STAGE_PINS if type(V6_STAGE_PINS) is dict else {})
            source_sha = trusted.get("sourceSha")
            source_tree = trusted.get("sourceTree")
            source_sha = source_sha if _v6_matches(r"[0-9a-f]{40}\Z", source_sha) else None
            source_tree = source_tree if _v6_matches(r"[0-9a-f]{40}\Z", source_tree) else None
        else:
            source_sha, source_tree = SOURCE, TREE
        summarize({"schema": "openclaw.v108.admission-failure.v1", "campaignId": CAMPAIGN,
            "status": "refused", **_ADMISSION_DIAGNOSTIC,
            "failedNeedCode": code if operational or code in ADMISSION_NEED_CODES.values() else "need.unprojected",
            "exceptionClass": error_class,
            "httpStatus": status if type(status) is int and 100 <= status <= 599 else None,
            "childExitCode": child_exit if type(child_exit) is int and -255 <= child_exit <= 255 else None,
            "sourceSha": source_sha, "sourceTree": source_tree, "productionAuthorized": False, "imageBuilt": False}, {})
        raise
    finally:
        _ADMISSION_DIAGNOSTIC = previous




def need(value, code):
    try:
        release.need(value, "source-validation: " + code)
    except release.Refusal as error:
        if _ADMISSION_DIAGNOSTIC is not None:
            error.admission_need_code = ADMISSION_NEED_CODES.get(code, "need.unprojected")
        raise


def read_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def validate_request(value, bind_source=True):
    fields = {"schema", "campaignId", "round", "profiles", "sourceSha", "sourceTree",
              "manifestSha256", "inventorySha256", "priorRunIds", "sourceAuthorization",
              "settledUsageSha256", "firstSourceSha", "firstSourceTree", "sourceWitness", "initialResume"}
    need(type(value) is dict and set(value) == fields, "request fields")
    need(value["schema"] == "openclaw.fork-source-validation-request.v3" and
         value["campaignId"] == CAMPAIGN and value["sourceAuthorization"] == SOURCE_AUTHORIZATION,
         "authorized successor request")
    for key in ("sourceSha", "sourceTree", "firstSourceSha", "firstSourceTree"):
        need(release.matches(release.SHA, value[key]), "reviewed source pins required")
    if bind_source:
        need(value["sourceSha"] == SOURCE and value["sourceTree"] == TREE and
             value["firstSourceSha"] == FIRST_SOURCE and value["firstSourceTree"] == FIRST_TREE,
             "exact reviewed successor source")
    for key in ("manifestSha256", "inventorySha256", "settledUsageSha256"):
        need(release.matches(HEX256, value[key]), "request digest")
    need(type(value["round"]) is int and value["round"] in (2, 3), "four lifetime operator rounds")
    prior = value["priorRunIds"]
    need(type(prior) is list and prior[:3] == list(RETAINED_SOURCE_RUN_IDS) and
         len(prior) == (3 if value["round"] == 2 else 4) and
         all(release.matches(RUN_ID, item) for item in prior) and len(prior) == len(set(prior)),
         "complete ordered prior source runs")
    profiles = value["profiles"]
    need(type(profiles) is list and all(type(p) is str and p in PROFILE_MINUTES for p in profiles)
         and len(profiles) == len(set(profiles)), "fixed unique profiles")
    witness = value["sourceWitness"]
    resume = value["initialResume"]
    if resume is not None:
        need(type(resume) is dict and resume == INITIAL_RESUME_WITNESS and
             value["round"] == 3 and prior[-1] == INITIAL_RESUME_RUN_ID and witness is None and
             profiles == list(PROFILE_MINUTES) and
             value["sourceSha"] == value["firstSourceSha"] == resume["sourceSha"] and
             value["sourceTree"] == value["firstSourceTree"] == resume["sourceTree"] and
             value["manifestSha256"] == resume["manifestSha256"] and
             value["inventorySha256"] == resume["inventorySha256"], "closed exact initial-resume witness")
    if value["round"] == 2:
        need(profiles == [] and witness is None and resume is None and value["sourceSha"] == value["firstSourceSha"]
             and value["sourceTree"] == value["firstSourceTree"], "one full successor round")
    elif resume is None:
        need(bool(profiles) and sum(PROFILE_MINUTES[p] for p in profiles) + JOB_OVERHEAD_MINUTES
             <= MAX_CORRECTION_MINUTES, "targeted correction minute cap")
        if witness is None:
            need(value["sourceSha"] == value["firstSourceSha"] and
                 value["sourceTree"] == value["firstSourceTree"], "unwitnessed source repin")
        else:
            need(type(witness) is dict and set(witness) ==
                 {"schema", "parentSha", "parentTree", "changedPaths", "unchangedTreeSha256"},
                 "closed test-only witness")
            need(witness["schema"] == "openclaw.v108.test-only-successor.v1" and
                 witness["parentSha"] == value["firstSourceSha"] and
                 witness["parentTree"] == value["firstSourceTree"] and
                 release.matches(HEX256, witness["unchangedTreeSha256"]), "witness parent/digest")
            paths = witness["changedPaths"]
            need(type(paths) is list and paths == sorted(set(paths)) and bool(paths) and
                 all(type(p) is str and p in TEST_ONLY_PATHS for p in paths), "exact test-only paths")
            required = required_correction_profiles(paths)
            need(required <= set(profiles), "all affected test-only owner profiles")
    return value


def prior_request(raw, pipeline_head):
    value = read_json(raw)
    if type(value) is dict and value.get("schema") == "openclaw.fork-source-validation-request.v2":
        # v2 is historical evidence only: accept exactly the published95df blob,
        # never a newly supplied operational request or a differently pinned v2.
        need(pipeline_head == INITIAL_RESUME_PIPELINE and
             hashlib.sha256(raw).hexdigest() == INITIAL_RESUME_REQUEST_SHA256,
             "exact published v2 prior request")
        validated = dict(value, schema="openclaw.fork-source-validation-request.v3", initialResume=None)
        validate_request(validated, bind_source=False)
        return value
    return validate_request(value, bind_source=False)


def initial_resume_jobs(table):
    measured = observed_minutes(table, list(PROFILE_MINUTES))
    names = {job["name"] for job in table["jobs"]}
    need(len(table["jobs"]) == 3 and names ==
         {"admission", "final", "source (${{ matrix.profile }})"}, "exact unstarted initial job set")
    for job in table["jobs"]:
        need(job.get("run_id") == int(INITIAL_RESUME_RUN_ID) and
             job.get("head_sha") == INITIAL_RESUME_PIPELINE,
             "initial-resume provider run/head binding")
        if job["name"] == "admission":
            need(job.get("conclusion") == "failure" and type(job.get("runner_id")) is int and
                 job["runner_id"] > 0 and type(job.get("runner_name")) is str and bool(job["runner_name"]) and
                 0 < measured <= 15, "initial admission failed acquired within15 rounded minutes")
        else:
            need(job.get("conclusion") == "skipped" and "runner_id" in job and
                 (job["runner_id"] is None or type(job["runner_id"]) is int and job["runner_id"] == 0) and
                 job.get("runner_name") in (None, "") and type(job.get("steps")) is list and not job["steps"],
                 "initial source/final explicitly skipped unacquired")
    return measured


def profile_minutes_for(request=None):
    """Choose accounting limits from the record's policy, never today's defaults."""
    if request is None:
        return PROFILE_MINUTES
    need(type(request) is dict, "profile policy record required")
    if request.get("schema") == R7_SCHEMA:
        return validation_budget_v7(request)["profileMinutes"]
    if request.get("schema") == V6_SCHEMA:
        return validation_budget_v6(request)["profileMinutes"]
    if request.get("schema") == V5_SCHEMA:
        return validation_budget_for_record_v5(request)["profileMinutes"]
    if request.get("schema") == "openclaw.fork-source-validation-request.v4":
        need(request.get("profilePolicy") == REPAIR_PROFILE_POLICY,
             "fixed five-gate profile policy")
        return V4_PROFILE_MINUTES
    need(request.get("schema") in ("openclaw.fork-source-validation-request.v2",
         "openclaw.fork-source-validation-request.v3") and "profilePolicy" not in request,
         "known historical profile policy")
    return PROFILE_MINUTES




def profiles_for(request):
    if request.get("schema") == R7_SCHEMA:
        validate_request_v7(request, R7_STAGE_PINS)
        return list(request["profiles"])
    if request.get("schema") == V6_SCHEMA:
        validate_request_v6(request, V6_STAGE_PINS)
        return list(request["profiles"])
    if request.get("schema") == V5_SCHEMA:
        validate_request_v5(request, V5_STAGE_PINS)
        return list(request["profiles"])
    if request.get("schema") == V4_SCHEMA:
        validate_request_v4(request, STAGE_PINS)
        return list(request["profiles"])
    return list(PROFILE_MINUTES) if request["round"] == 2 or request["initialResume"] is not None else request["profiles"]



def round_minutes(request):
    if request.get("schema") == V5_SCHEMA:
        budget = validation_budget_for_record_v5(request)
        return budget["admissionMinutes"] + budget["finalMinutes"] + sum(
            budget["profileMinutes"][p] for p in profiles_for(request))
    return JOB_OVERHEAD_MINUTES + sum(profile_minutes_for(request)[p] for p in profiles_for(request))



def required_correction_profiles(paths):
    required = {"types-tests"}
    for path in paths:
        if path.startswith("src/commands/"):
            required.update(("doctor-1", "doctor-2", "doctor-3"))
        elif path.startswith("src/gateway/"):
            required.add("sqlite")
        else:
            required.update(("dependency", "compatibility"))
    return required


def verify_test_only_successor(source, request):
    witness = request["sourceWitness"]
    if witness is None:
        return None
    parent, current = request["firstSourceSha"], request["sourceSha"]
    need(git(source, "show", "-s", "--format=%P", current).decode().strip() == parent,
         "test-only successor must be direct single-parent")
    need(git(source, "rev-parse", parent + "^{tree}").decode().strip() == request["firstSourceTree"],
         "test-only parent tree")
    def entries(commit):
        result = {}
        for row in git(source, "ls-tree", "-r", "-z", commit).split(b"\0"):
            if not row:
                continue
            metadata, path = row.split(b"\t", 1)
            result[path.decode()] = metadata
        return result
    before, after = entries(parent), entries(current)
    need(set(before) == set(after), "test-only successor added/deleted path")
    changed = sorted(path for path in before if before[path] != after[path])
    tests = witness["changedPaths"]
    need(changed == sorted([*tests, DERIVED_LEDGER_PATH]) and set(tests) <= TEST_ONLY_PATHS,
         "complete test-only plus derived-ledger changed set")
    for path in changed:
        left, right = before[path].split(), after[path].split()
        need(left[:2] == right[:2] == [b"100644", b"blob"], "test/ledger mode or type changed")
    old_raw = git(source, "show", parent + ":" + DERIVED_LEDGER_PATH)
    new_raw = git(source, "show", current + ":" + DERIVED_LEDGER_PATH)
    need(len(old_raw) <= 2 * 1024 * 1024 and len(new_raw) <= 2 * 1024 * 1024,
         "bounded derived ledger")
    old_ledger, new_ledger = read_json(old_raw), read_json(new_raw)
    need(type(old_ledger) is dict and type(new_ledger) is dict and
         type(old_ledger.get("paths")) is list and type(new_ledger.get("paths")) is list,
         "derived ledger row schema")
    expected = read_json(old_raw)
    rows = expected["paths"]
    need(all(type(row) is dict and type(row.get("path")) is str for row in rows) and
         len({row["path"] for row in rows}) == len(rows), "unique derived ledger rows")
    by_path = {row["path"]: row for row in rows}
    for path in tests:
        row = by_path.get(path, {})
        need(type(row.get("result")) is dict and set(row["result"]) == {"mode", "blob"} and
             row["result"]["mode"] == "100644" and
             row["result"]["blob"] == before[path].split()[2].decode(),
             "old ledger result matches exact parent test blob")
        row["result"]["blob"] = after[path].split()[2].decode()
    need(expected == new_ledger, "ledger changed beyond exact derived test result blobs")
    def unchanged_digest(rows):
        raw = b"".join(rows[path] + b"\t" + path.encode() + b"\0"
                       for path in sorted(rows) if path not in changed)
        return hashlib.sha256(raw).hexdigest()
    digest = unchanged_digest(before)
    need(digest == unchanged_digest(after) == witness["unchangedTreeSha256"],
         "all other tracked bytes equivalence")
    return {"status": "verified_test_only_successor", "parentSourceSha": parent,
            "currentSourceSha": current, "changedPaths": tests, "unchangedTreeSha256": digest,
            "derivedLedger": {"path": DERIVED_LEDGER_PATH,
                "previousBlob": before[DERIVED_LEDGER_PATH].split()[2].decode(),
                "currentBlob": after[DERIVED_LEDGER_PATH].split()[2].decode(),
                "changedResultPaths": tests},
            "reusedReceiptSourceSha": parent, "sameSourceReceiptRelabeled": False}

def validate_event(event, env):
    need(env.get("GITHUB_ACTIONS") == "true" and env.get("RUNNER_OS") == "Linux" and
         env.get("RUNNER_ENVIRONMENT") == "github-hosted", "public hosted Linux only")
    need(env.get("GITHUB_EVENT_NAME") == "pull_request" and env.get("GITHUB_RUN_ATTEMPT") == "1",
         "PR event and first attempt required")
    need(env.get("GITHUB_REPOSITORY") == REPOSITORY and
         env.get("GITHUB_REF") == "refs/pull/28/merge", "repository/ref")
    need(event.get("action") in ("opened", "reopened", "synchronize"), "event action")
    pr = event.get("pull_request", {})
    repo = event.get("repository", {})
    need(event.get("number") == 28 and pr.get("number") == 28 and
         pr.get("state") == "open" and pr.get("draft") is True, "open draft PR28")
    need(repo.get("full_name") == REPOSITORY and repo.get("private") is False,
         "public repository")
    head, base = pr.get("head", {}), pr.get("base", {})
    need(head.get("repo", {}).get("full_name") == REPOSITORY and
         head.get("repo", {}).get("private") is False and head.get("ref") == BRANCH and
         release.matches(release.SHA, head.get("sha")), "same-repository reviewed head")
    need(base.get("repo", {}).get("full_name") == REPOSITORY and
         base.get("ref") == BASE_BRANCH and base.get("sha") == BASE, "fixed base")
    need(env.get("GITHUB_WORKFLOW_REF") == REPOSITORY + "/" + WORKFLOW + "@refs/pull/28/merge"
         and release.matches(release.SHA, env.get("GITHUB_WORKFLOW_SHA")), "workflow identity")
    need(release.matches(RUN_ID, env.get("GITHUB_RUN_ID")), "run identity")
    return head["sha"]


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.DEVNULL)


def code_binding(pipeline, source, event, env, minimal=False, request=None):
    source_sha, source_tree = source_identity_for(request)
    head = validate_event(event, env)
    need(git(pipeline, "rev-parse", "HEAD").decode().strip() == head, "pipeline checkout head")
    if source is not None:
        need(git(source, "rev-parse", "HEAD").decode().strip() == source_sha and
             git(source, "rev-parse", "HEAD^{tree}").decode().strip() == source_tree, "source checkout/tree")
    acquire_workflow_commit(pipeline, head, env, minimal=minimal)
    need(git(pipeline, "rev-parse", env["GITHUB_WORKFLOW_SHA"] + "^1").decode().strip() ==
         TARGET_BRANCH_TIP, "workflow merge target parent")
    # pull_request workflow code can be a synthetic merge. Bind every executable
    # owner used by this driver to reviewed head bytes before source code runs.
    bound_paths = (WORKFLOW, "scripts/fork-release/source_validation_v108.py",
                   "scripts/fork-release/preflight.py", "scripts/fork-release/release.py",
                   "scripts/fork-release/native_tests.mjs")
    if not minimal and request is not None and ((request.get("schema") == R7_SCHEMA and request.get("stageRound") == 2) or request.get("schema") == R8_SCHEMA):
        bound_paths += (R7_TAG_FIXTURE,)
    if request is not None and request.get("schema") == R8_SCHEMA:
        bound_paths += ("scripts/fork-release/composite_closed_usage.py",)
    for path in bound_paths:
        actual = (pipeline / path).read_bytes()
        need(actual == git(pipeline, "show", head + ":" + path) ==
             git(pipeline, "show", env["GITHUB_WORKFLOW_SHA"] + ":" + path),
             "reviewed workflow/code bytes")




def acquire_workflow_commit(pipeline, head, env, minimal=False):
    """The PR merge workflow object need not belong to the checked-out head DAG."""
    commit = env.get("GITHUB_WORKFLOW_SHA")
    need(release.matches(release.SHA, commit), "literal workflow commit required")
    try:
        present = git(pipeline, "cat-file", "-t", commit).strip() == b"commit"
    except subprocess.CalledProcessError:
        present = False
    if present and minimal:
        try:
            git(pipeline, "cat-file", "-e", commit + "^1^{commit}")
        except subprocess.CalledProcessError:
            present = False
    if not present:
        child_env = {"PATH": env["PATH"], "GIT_TERMINAL_PROMPT": "0",
                     "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}
        subprocess.run(["git", "-C", str(pipeline), "-c", "credential.helper=",
                        "-c", "maintenance.auto=0", "-c", "gc.auto=0", "fetch", "--no-tags",
                        *(["--depth=2"] if minimal else []),
                        "https://github.com/fr-meyer/openclaw.git", commit],
                       check=True, env=child_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        need(git(pipeline, "rev-parse", "FETCH_HEAD^{commit}").decode().strip() == commit,
             "fetched workflow commit changed")
    need(git(pipeline, "cat-file", "-t", commit).strip() == b"commit" and
         git(pipeline, "rev-parse", "HEAD").decode().strip() == head,
         "workflow acquisition changed checkout")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise release.Refusal("source-validation: API redirect refused")


def api_json(path, token):
    with admission_api_read(path):
        need(path.startswith("/repos/" + REPOSITORY + "/") and "\n" not in path,
             "fixed API route")
        request = urllib.request.Request("https://api.github.com" + path, headers={
            "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": CAMPAIGN, "Authorization": "Bearer " + token,
        })
        with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
            raw = response.read(4 * 1024 * 1024 + 1)
        need(len(raw) <= 4 * 1024 * 1024, "bounded API response")
        return read_json(raw)


def content_at(api, path, commit):
    need(release.matches(release.SHA, commit) and path in (REQUEST, WORKFLOW), "fixed content identity")
    obj = api("/repos/" + REPOSITORY + "/contents/" + path + "?ref=" + commit)
    need(obj.get("type") == "file" and obj.get("encoding") == "base64" and
         type(obj.get("size")) is int and 0 < obj["size"] <= 65536, "bounded Git-backed content")
    raw = base64.b64decode(obj["content"], validate=False)
    need(len(raw) == obj["size"], "content size")
    return raw


def timestamp(value):
    need(type(value) is str and value.endswith("Z"), "API timestamp")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def observed_minutes(jobs, expected=None, legacy=False, profile_request=None):
    need(type(jobs) is dict and type(jobs.get("total_count")) is int and
         type(jobs.get("jobs")) is list and jobs["total_count"] <= 100 and
         jobs["total_count"] == len(jobs["jobs"]), "complete terminal job table")
    caps = LEGACY_PROFILE_MINUTES if legacy else profile_minutes_for(profile_request)
    limits = None if expected is None else {"admission": 15, "final": 5 if legacy else 10,
        "source": 0, "source (${{ matrix.profile }})": 0,
        **{"source (" + p + ")": caps[p] for p in expected}}
    ids, names, minutes, admitted = set(), set(), 0, False
    for job in jobs["jobs"]:
        need(type(job.get("id")) is int and job["id"] > 0 and job["id"] not in ids,
             "terminal unique positive job ID")
        ids.add(job["id"])
        name = job.get("name")
        need(type(name) is str and 0 < len(name) <= 200 and (limits is None or name not in names) and
             job.get("status") == "completed" and job.get("run_attempt") == 1 and
             (limits is None or name in limits), "terminal first-attempt unique job")
        names.add(name)
        if name == "admission":
            admitted = job.get("conclusion") == "success"
        zero = "runner_id" in job and (job["runner_id"] is None or
               type(job["runner_id"]) is int and job["runner_id"] == 0)
        if job.get("conclusion") in ("skipped", "cancelled") and zero:
            need("runner_name" in job and job["runner_name"] in (None, "") and
                 "steps" in job and type(job["steps"]) is list and not job["steps"],
                 "positive unacquired terminal evidence")
            continue
        need(type(job.get("runner_id")) is int and job["runner_id"] > 0 and
             job.get("runner_group_name") == "GitHub Actions" and
             job.get("labels") in (["ubuntu-24.04"], ["ubuntu-latest"] if legacy else ["ubuntu-24.04"]),
             "standard public Ubuntu acquired runner")
        seconds = (timestamp(job["completed_at"]) - timestamp(job["started_at"])).total_seconds()
        need(seconds >= 0 and (limits is None or seconds <= (limits[name] + 1) * 60),
             "terminal job duration")
        minutes += math.ceil(seconds / 60)
    if limits is not None:
        need({"admission", "final"} <= names, "missing campaign boundary job")
        if admitted:
            need(names == {"admission", "final", *["source (" + p + ")" for p in expected]},
                 "missing admitted profile jobs")
    return minutes


def settled_usage(pipeline, request):
    raw = (pipeline / SETTLED_USAGE).read_bytes()
    need(hashlib.sha256(raw).hexdigest() == request["settledUsageSha256"], "settled usage digest")
    value = read_json(raw)
    need(type(value) is dict and set(value) == {"schema", "observedAt", "spentRunnerMinutes", "runs"}
         and value["schema"] == "openclaw.v108.settled-usage.v1" and
         value["spentRunnerMinutes"] == SETTLED_MINUTES and type(value["spentRunnerMinutes"]) is int,
         "fixed settled usage envelope")
    rows = value["runs"]
    need(type(rows) is list and len(rows) == 57 and len({row["id"] for row in rows}) == 57,
         "complete settled 57-record prefix")
    fields = {"id", "headSha", "path", "event", "conclusion", "roundedMinutes"}
    for row in rows:
        need(type(row) is dict and set(row) == fields and release.matches(RUN_ID, row["id"]) and
             release.matches(release.SHA, row["headSha"]) and type(row["roundedMinutes"]) is int and
             row["roundedMinutes"] >= 0 and row["event"] in ("pull_request", "pull_request_target") and
             type(row["path"]) is str and row["path"].startswith(".github/workflows/"),
             "fixed settled run fields")
    need(sum(row["roundedMinutes"] for row in rows) == SETTLED_MINUTES and
         {row["id"] for row in rows if row["path"] == WORKFLOW} == set(RETAINED_SOURCE_RUN_IDS),
         "settled425 source/ancillary coverage")
    return value


def branch_history(api):
    route = "/repos/" + REPOSITORY + "/actions/runs?branch=task%2Fv107-source-binding&created=%3E%3D2026-10-28T00%3A03%3A19Z&per_page=100&page="
    first = api(route + "1")
    total = first.get("total_count")
    need(type(total) is int and 0 <= total <= 128 and type(first.get("workflow_runs")) is list,
         "bounded complete branch history")
    runs = first["workflow_runs"]
    if total > 100:
        second = api(route + "2")
        need(second.get("total_count") == total and type(second.get("workflow_runs")) is list,
             "stable branch history pagination")
        runs += second["workflow_runs"]
    need(len(runs) == total and len({r["id"] for r in runs}) == total, "complete unique history pages")
    return {str(run["id"]): run for run in runs}


def ancillary_job_snapshot(table, now, terminal_run):
    need(type(table) is dict and type(table.get("total_count")) is int and
         type(table.get("jobs")) is list and table["total_count"] <= 100 and
         table["total_count"] == len(table["jobs"]) and
         (bool(table["jobs"]) or terminal_run), "complete new ancillary job table")
    acquired_minutes, acquired, unacquired, pending = 0, 0, 0, False
    ids = set()
    for job in table["jobs"]:
        need(type(job) is dict and type(job.get("id")) is int and job["id"] > 0 and job["id"] not in ids and
             type(job.get("name")) is str and
             job.get("run_attempt") == 1, "new ancillary job identity/attempt")
        ids.add(job["id"])
        status = job.get("status")
        if status == "completed":
            runner = job.get("runner_id")
            if type(runner) is int and runner > 0:
                need(type(job.get("started_at")) is str and type(job.get("completed_at")) is str and
                     timestamp(job["completed_at"]) <= now, "new ancillary terminal time evidence")
                acquired += 1
            else:
                unacquired += 1
            acquired_minutes += observed_minutes({"total_count": 1, "jobs": [job]}, legacy=True)
        elif status == "in_progress":
            need(type(job.get("runner_id")) is int and job["runner_id"] > 0 and
                 type(job.get("runner_name")) is str and bool(job["runner_name"]) and
                 job.get("runner_group_name") == "GitHub Actions" and
                 job.get("labels") in (["ubuntu-24.04"], ["ubuntu-latest"]) and
                 type(job.get("started_at")) is str and "completed_at" in job and
                 job["completed_at"] is None and type(job.get("steps")) is list,
                 "positive in-progress ancillary acquisition")
            seconds = (now - timestamp(job["started_at"])).total_seconds()
            need(seconds >= 0, "new ancillary elapsed time")
            acquired_minutes += math.ceil(seconds / 60)
            acquired += 1
            pending = True
        elif status in ("queued", "waiting", "pending"):
            need("runner_id" in job and (job["runner_id"] is None or
                 type(job["runner_id"]) is int and job["runner_id"] == 0) and
                 "runner_name" in job and job["runner_name"] in (None, "") and
                 type(job.get("steps")) is list and not job["steps"] and
                 job.get("labels") in (["ubuntu-24.04"], ["ubuntu-latest"]),
                 "positive queued ancillary unacquired evidence")
            unacquired += 1
            pending = True
        else:
            need(False, "unknown new ancillary job state")
    need(not terminal_run or not pending, "terminal ancillary run has pending jobs")
    return {"observedAcquiredRunnerMinutes": acquired_minutes, "acquiredJobs": acquired,
            "explicitlyUnacquiredJobs": unacquired, "usageComplete": terminal_run and not pending}


class AncillaryObservationExpired(Exception):
    pass


@contextmanager
def ancillary_observation_window():
    # Bound even a stalled read-only API call, without changing the API surface
    # or ever retrying a dispatch. This admission process owns no other alarm.
    need(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), "ancillary alarm already owned")
    def expired(signum, frame):
        raise AncillaryObservationExpired()
    old = signal.signal(signal.SIGALRM, expired)
    try:
        signal.setitimer(signal.ITIMER_REAL, 60)
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


def ancillary_admission_clock(env, api):
    need(env.get("GITHUB_JOB") == "admission" and release.matches(RUN_ID, env.get("GITHUB_RUN_ID")),
         "ancillary observation owned admission identity")
    table = api("/repos/" + REPOSITORY + "/actions/runs/" + env["GITHUB_RUN_ID"] +
                "/jobs?filter=all&per_page=100")
    need(type(table) is dict and type(table.get("total_count")) is int and
         type(table.get("jobs")) is list and table["total_count"] <= 100 and
         table["total_count"] == len(table["jobs"]), "complete current admission job table")
    jobs = [job for job in table["jobs"] if job.get("name") == "admission"]
    need(len(jobs) == 1 and jobs[0].get("status") == "in_progress" and
         str(jobs[0].get("run_id")) == env["GITHUB_RUN_ID"], "current admission acquisition")
    now = datetime.now(timezone.utc)
    facts = ancillary_job_snapshot({"total_count": 1, "jobs": jobs}, now, False)
    need(facts["acquiredJobs"] == 1 and facts["explicitlyUnacquiredJobs"] == 0 and
         jobs[0].get("labels") == ["ubuntu-24.04"], "current admission runner")
    deadline = min(timestamp(jobs[0]["started_at"]).timestamp() + 15 * 60,
                   timestamp(APPROVAL_DEADLINE).timestamp())
    need(now.timestamp() + 60 <= deadline, "insufficient admission/deadline observation time")
    return deadline


def new_ancillary_usage(history, usage, request, event, env, api):
    prefix = {row["id"] for row in usage["runs"]}
    known_paths = {row["path"] for row in usage["runs"] if row["path"] != WORKFLOW}
    known_heads = {row["headSha"] for row in usage["runs"]}
    known_heads.add(event["pull_request"]["head"]["sha"])
    known_heads.update(history[rid]["head_sha"] for rid in request["priorRunIds"] if rid in history)
    # Frozen prefix/source metadata is checked across observation, while their
    # already verified job tables are never fetched again by this phase.
    def identity(run, state=False):
        fields = ("id", "head_sha", "path", "event", "run_attempt", "head_branch",
                  "repository", "head_repository", "created_at")
        if state:
            fields += ("status", "conclusion")
        return json.dumps({key: run.get(key) for key in fields}, sort_keys=True)
    anchors = {rid: identity(run, True) for rid, run in history.items()
               if rid in prefix or run.get("path") == WORKFLOW}
    source_ids = {rid for rid, run in history.items() if run.get("path") == WORKFLOW}
    cache, identities = {}, {}
    def measure(current):
        need(set(anchors) <= set(current) and
             {rid for rid, run in current.items() if run.get("path") == WORKFLOW} ==
             source_ids and all(identity(current[rid], True) == value for rid, value in anchors.items()),
             "ancillary observation source/prefix metadata changed")
        need(sum(run.get("path") != WORKFLOW for run in current.values()) <= 120,
             "internal120 ancillary-record alarm")
        need(set(identities) <= set(current), "observed ancillary run disappeared")
        total, records, pending = 0, [], []
        for run_id, run in sorted(current.items()):
            if run_id in prefix or run.get("path") == WORKFLOW:
                continue
            admission_stage("history", "new-ancillary", run_id)
            need(run.get("event") in ("pull_request", "pull_request_target") and
                 run.get("path") in known_paths and run.get("head_sha") in known_heads and
                 run.get("run_attempt") == 1 and run.get("head_branch") == BRANCH and
                 run.get("repository", {}).get("full_name") == REPOSITORY and
                 run.get("repository", {}).get("private") is False and
                 run.get("head_repository", {}).get("full_name") == REPOSITORY and
                 run.get("head_repository", {}).get("private") is False,
                 "new ancillary public identity/path/head")
            run_identity = identity(run)
            need(run_id not in identities or identities[run_id] == run_identity,
                 "observed ancillary identity changed")
            identities[run_id] = run_identity
            status = run.get("status")
            need(status in ("completed", "in_progress", "queued", "waiting", "pending"),
                 "new ancillary run state")
            terminal = status == "completed"
            if terminal:
                need(run.get("conclusion") in ("success", "failure", "cancelled", "timed_out",
                     "action_required", "neutral", "skipped", "startup_failure", "stale"),
                     "new ancillary terminal conclusion")
            if run_id in cache:
                record, conclusion = cache[run_id]
                need(terminal and run.get("conclusion") == conclusion,
                     "settled new ancillary state changed")
            else:
                table = api("/repos/" + REPOSITORY + "/actions/runs/" + run_id +
                            "/jobs?filter=all&per_page=100")
                facts = ancillary_job_snapshot(table, datetime.now(timezone.utc), terminal)
                record = {"campaignId": CAMPAIGN, "phase": "new_ancillary", "runId": run_id,
                          "status": "terminal" if facts["usageComplete"] else "unsettled",
                          **facts, "remainingReservationMinutes": 0 if facts["usageComplete"] else None}
                summarize(record, {})
                if facts["usageComplete"]:
                    cache[run_id] = (record, run.get("conclusion"))
            total += record["observedAcquiredRunnerMinutes"]
            records.append(record)
            if not record["usageComplete"]:
                pending.append(run_id)
        need(total <= ANCILLARY_MINUTES, "new ancillary135-minute bucket exceeded")
        need(not pending or total < ANCILLARY_MINUTES, "no ancillary usage headroom for observation")
        return total, records, pending

    total, records, pending = measure(history)
    if pending:
        ancillary_admission_clock(env, api)
        end = time.monotonic() + 60
        try:
            with ancillary_observation_window():
                while pending:
                    remaining = end - time.monotonic()
                    if remaining <= 0:
                        raise AncillaryObservationExpired()
                    time.sleep(min(5, remaining))
                    if time.monotonic() >= end:
                        raise AncillaryObservationExpired()
                    # Only pending/new ancillary tables are re-read by measure;
                    # completed new runs and the old57 retain their exact facts.
                    total, records, pending = measure(branch_history(api))
        except AncillaryObservationExpired:
            summarize({"campaignId": CAMPAIGN, "phase": "ancillary_status_observation",
                       "status": "refused_pending", "pendingRunIds": pending,
                       "observedAcquiredRunnerMinutes": total, "remainingReservationMinutes": None,
                       "usageComplete": False, "observationLimitSeconds": 60}, {})
            need(False, "ancillary still unsettled after bounded60-second observation")
    return {"observedNewAncillaryRunnerMinutes": total,
            "newAncillaryRemainingReserveMinutes": ANCILLARY_MINUTES - total,
            "newAncillaryRecords": records}


def history_checks(request, event, env, pipeline, api):
    request = validate_request(request)
    admission_stage("history", "current-pr")
    live = api("/repos/" + REPOSITORY + "/pulls/28")
    need(validate_event(dict(event, pull_request=live), env) == event["pull_request"]["head"]["sha"],
         "live head changed")
    admission_stage("history", "target-ref")
    target = api("/repos/" + REPOSITORY + "/git/ref/heads/" + BASE_BRANCH)
    need(target.get("ref") == "refs/heads/" + BASE_BRANCH and
         target.get("object", {}).get("type") == "commit" and
         target["object"].get("sha") == TARGET_BRANCH_TIP, "fixed live target branch tip")
    admission_stage("history", "branch-history")
    history = branch_history(api)
    need(sum(run.get("path") != WORKFLOW for run in history.values()) <= 120,
         "internal120 ancillary-record alarm")
    usage = settled_usage(pipeline, request)
    measured_prefix = 0
    for row in usage["runs"]:
        admission_stage("history", "settled-prefix", row["id"])
        run = history.get(row["id"], {})
        need(run.get("head_sha") == row["headSha"] and run.get("path") == row["path"] and
             run.get("event") == row["event"] and run.get("status") == "completed" and
             run.get("conclusion") == row["conclusion"] and run.get("run_attempt") == 1 and
             run.get("repository", {}).get("full_name") == REPOSITORY and
             run.get("repository", {}).get("private") is False and
             run.get("head_repository", {}).get("full_name") == REPOSITORY and
             run.get("head_repository", {}).get("private") is False, "settled run identity/state")
        table = api("/repos/" + REPOSITORY + "/actions/runs/" + row["id"] + "/jobs?filter=all&per_page=100")
        measured = observed_minutes(table, list(LEGACY_PROFILE_MINUTES) if row["path"] == WORKFLOW else None, legacy=True)
        need(measured == row["roundedMinutes"], "settled provider usage changed")
        measured_prefix += measured
        if row["path"] == WORKFLOW:
            subprocess.run(["git", "-C", str(pipeline), "merge-base", "--is-ancestor",
                            row["headSha"], event["pull_request"]["head"]["sha"]],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    need(measured_prefix == SETTLED_MINUTES, "actual prior425 proof")
    admission_stage("history", "source-rounds")
    expected = [*request["priorRunIds"], env["GITHUB_RUN_ID"]]
    actual = {rid for rid, run in history.items() if run.get("path") == WORKFLOW}
    need(actual == set(expected) and len(expected) == len(set(expected)), "unlisted/duplicate source round")
    for run_id in actual:
        run = history[run_id]
        need(run.get("event") == "pull_request" and run.get("run_attempt") == 1 and
             run.get("head_branch") == BRANCH and run.get("display_title") == CAMPAIGN and
             run.get("repository", {}).get("full_name") == REPOSITORY and
             run.get("repository", {}).get("private") is False and
             run.get("head_repository", {}).get("full_name") == REPOSITORY and
             run.get("head_repository", {}).get("private") is False and
             [pr.get("number") for pr in run.get("pull_requests", [])] == [28],
             "exact campaign source run identity")
    current = history[env["GITHUB_RUN_ID"]]
    need(current.get("head_sha") == event["pull_request"]["head"]["sha"] and
         current.get("event") == "pull_request" and current.get("path") == WORKFLOW and
         current.get("run_attempt") == 1 and current.get("status") == "in_progress",
         "current source round identity")
    prior_new_minutes = 0
    first_receipt = None
    if request["round"] == 3:
        run_id = request["priorRunIds"][-1]
        admission_stage("history", "prior-round", run_id)
        previous = history[run_id]
        need(previous.get("status") == "completed" and previous.get("run_attempt") == 1,
             "prior new round terminal")
        old_request = prior_request(content_at(api, REQUEST, previous["head_sha"]), previous["head_sha"])
        need(old_request["round"] == 2 and old_request["sourceSha"] == request["firstSourceSha"] and
             old_request["sourceTree"] == request["firstSourceTree"] and
             old_request["settledUsageSha256"] == request["settledUsageSha256"], "bound first-source receipt")
        old_workflow = content_at(api, WORKFLOW, previous["head_sha"])
        new_workflow = (pipeline / WORKFLOW).read_bytes()
        if request["sourceWitness"] is not None:
            old_ref = ("ref: " + request["firstSourceSha"]).encode()
            new_ref = ("ref: " + request["sourceSha"]).encode()
            need(old_workflow.count(old_ref) == 2 and new_workflow.count(new_ref) == 2,
                 "exact two witnessed source checkout refs")
            old_workflow = old_workflow.replace(old_ref, new_ref)
        need(old_workflow == new_workflow, "workflow/security caps changed between new rounds")
        subprocess.run(["git", "-C", str(pipeline), "merge-base", "--is-ancestor",
                        previous["head_sha"], event["pull_request"]["head"]["sha"]],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        prior_jobs = api("/repos/" + REPOSITORY + "/actions/runs/" + run_id +
                         "/jobs?filter=all&per_page=100")
        if request["initialResume"] is not None:
            need(run_id == INITIAL_RESUME_RUN_ID and previous.get("head_sha") == INITIAL_RESUME_PIPELINE and
                 previous.get("conclusion") == "failure" and
                 old_request["sourceSha"] == request["sourceSha"] and
                 old_request["sourceTree"] == request["sourceTree"] and
                 old_request["manifestSha256"] == request["manifestSha256"] and
                 old_request["inventorySha256"] == request["inventorySha256"],
                 "initial-resume exact failed prior source/controls")
            prior_new_minutes = initial_resume_jobs(prior_jobs)
        else:
            prior_new_minutes = observed_minutes(prior_jobs, list(PROFILE_MINUTES), profile_request=old_request)
            need(prior_new_minutes <= INITIAL_MINUTES, "first-source complete job booking exceeded")
        first_receipt = {"runId": run_id, "pipelineHead": previous["head_sha"],
                         "sourceSha": request["firstSourceSha"],
                         "sourceTree": request["firstSourceTree"], "conclusion": previous.get("conclusion"),
                         "profileResults": {job["name"][8:-1]: job["conclusion"]
                            for job in prior_jobs["jobs"] if job["name"].startswith("source (")},
                         "relabeledAsCurrentSourcePass": False}
        if request["initialResume"] is not None:
            first_receipt.update(profileResults={}, sourceProfilesAcquired=0,
                                 initialValidationNeverStarted=True, status="admission_failed")
    admission_stage("history", "new-ancillary")
    ancillary = new_ancillary_usage(history, usage, request, event, env, api)
    initial_resume = request["initialResume"] is not None
    reserve = (MAX_CORRECTION_MINUTES if request["round"] == 2 else
               MAX_CORRECTION_MINUTES - prior_new_minutes if initial_resume else 0)
    # The failed14 is rebooked within the already approved300 bucket. Its286
    # remainder is a reservation only; this final operator round creates no
    # later-round authority. The full940 initial source suite never started.
    # The135 bucket includes observed new spend plus its remaining reserve.
    # The prior425 already includes its old33 ancillary minutes exactly once.
    booked = (SETTLED_MINUTES + prior_new_minutes + round_minutes(request) + reserve +
              ancillary["observedNewAncillaryRunnerMinutes"] +
              ancillary["newAncillaryRemainingReserveMinutes"])
    need(booked <= CAMPAIGN_MINUTES, "lifetime1800 runner-minute ceiling")
    now = datetime.now(timezone.utc).timestamp()
    need(timestamp(current["created_at"]) >= timestamp("2026-10-28T04:33:00Z") and
         timestamp(current["created_at"]).timestamp() <= now, "new source authorization time")
    if request["round"] == 3:
        need(timestamp(previous["created_at"]) <= timestamp(current["created_at"]),
             "ordered new source rounds")
    deadline = int(timestamp(APPROVAL_DEADLINE).timestamp())
    need(now < deadline, "original approval deadline")
    return {"bookedRunnerMinutes": booked, "actualSettledRunnerMinutes": SETTLED_MINUTES,
            "observedNewPriorRunnerMinutes": prior_new_minutes,
            "futureTargetedReserveMinutes": reserve if request["round"] == 2 else 0,
            "reservedCorrectionBalanceMinutes": reserve if initial_resume else 0,
            "initialValidationResume": initial_resume,
            "operatorRoundsRemaining": 0 if request["round"] == 3 else 1,
            "ancillaryRunnerMinutes": ANCILLARY_MINUTES, "campaignRunnerMinuteCeiling": CAMPAIGN_MINUTES,
            "deadlineEpoch": deadline, "firstSourceReceipt": first_receipt,
            "historicalConclusionsRetained": True, **ancillary}


def metadata(pipeline):
    """Current operations accept only reviewed V6 or the explicit RE2JS successor."""
    request = validate_operational_request(_v6_json((pipeline / REQUEST).read_bytes()))
    directory = pipeline / CANDIDATE
    manifest, manifest_hash = release.manifest_at(directory / "manifest.json")
    _v6_need(request["manifestSha256"] == manifest_hash and
        request["inventorySha256"] == preflight.digest(directory / "patch-inventory.json"),
        "v6.runtime_metadata_digest")
    _v6_need(manifest["source"]["commit"] == request["sourceSha"] and
        manifest["source"]["tree"] == request["sourceTree"] and manifest["productionEligible"] is False,
        "v6.runtime_manifest_source")
    path, proof = operational_input_paths(request)
    _v6_need(preflight.digest(pipeline / path) == request["settledUsageSha256"],
        "v6.runtime_baseline_digest")
    validate_operational_generation(request, (pipeline / proof).read_bytes())
    return request, manifest, manifest_hash




def source_preflight(pipeline, source, manifest, manifest_hash):
    return preflight.inventory_at(pipeline / CANDIDATE / "patch-inventory.json", manifest,
                                  manifest_hash, source_dir=source)


def admission_deadline(env, request=None):
    """One early shared clock covers both checkouts, metadata and acquisition."""
    start = env.get("SOURCE_ADMISSION_STARTED_EPOCH", "")
    need(env.get("GITHUB_JOB") == "admission" and
         re.fullmatch(r"[0-9]{10}", start) is not None,
         "early admission clock required")
    # Historical helpers retain their original15-minute record policy. They do
    # not provide an operational CLI route to V3/V4.
    minutes = (validation_budget_v7(request)["admissionMinutes"]
        if request is not None and request.get("schema") == R7_SCHEMA else
        validation_budget_v6(request)["admissionMinutes"]
        if request is not None and request.get("schema") == V6_SCHEMA else
        validation_budget_for_record_v5(request)["admissionMinutes"]
        if request is not None and request.get("schema") == V5_SCHEMA else 15)
    now = time.time()
    need(int(start) <= now and now - int(start) < minutes * 60,
         "early admission clock freshness")
    return min(int(start) + minutes * 60 - 60,
               int(timestamp(approval_deadline_for(request)).timestamp()) - 60)




def closure_remaining(deadline):
    remaining = deadline - time.time()
    need(remaining >= 1, "source closure shared deadline exhausted")
    return remaining


def product_checkout_minutes(env, request=None):
    # Both checkouts consume the same admission clock; this is no new lease.
    minutes = min(10, math.floor(closure_remaining(admission_deadline(env, request)) / 60))
    need(minutes >= 1, "insufficient shared product checkout budget")
    return minutes







def selected_tests(paths, profile, request=None):
    """Complete fixed-source owner families; maintained test-projects owns routing."""
    tests = sorted(path for path in paths if TEST_PATH.fullmatch(path) and
                   not any(part in ("", ".", "..") for part in path.split("/")) and
                   not re.search(r"(?:^|[./-])live(?:[./-]|$)", path))
    if profile.startswith("workboard-"):
        family = [p for p in tests if p.startswith("extensions/workboard/")]
        return family[int(profile[-1]) - 1::2]
    if profile.startswith("models-"):
        family = [p for p in tests if (
            p.startswith("src/agents/") and re.search(
                r"(?:^|/)(?:model|models|configured-model|configured-provider|utility-completion|"
                r"result-fallback-classifier|subagent-spawn-child-plan\.sandbox-cli)", p)
            or p.startswith("extensions/codex/src/app-server/") and re.search(
                r"(?:model|provider-capabilities|inference-routing)", p))]
        return family[int(profile[-1]) - 1::2]
    if profile == "sqlite":
        return [p for p in tests if (
            p.startswith(("src/state/", "src/tasks/")) or
            p.startswith(("src/infra/", "src/plugins/", "src/gateway/")) and re.search(
                r"(?:sqlite|managed-task-flow|loader\.(?:gateway-bindings|native-module-loader))", p))]
    if profile == "doctor" or profile.startswith("doctor-"):
        family = [p for p in tests if (
            p.startswith("src/commands/doctor") or p.startswith("src/flows/doctor") or
            p.startswith("extensions/codex/src/migration/"))]
        if profile == "doctor":
            return family
        priority = [p for p in family if re.search(r"(?:process|session)", p.rsplit("/", 1)[-1])]
        rest = [p for p in family if p not in set(priority)]
        return sorted((priority + rest)[int(profile[-1]) - 1::3])
    if profile == "compatibility":
        if request is not None and request.get("schema") in (V6_SCHEMA, R7_SCHEMA, R8_SCHEMA):
            return list(V6_RUNTIME_COMPATIBILITY_TESTS)
        if request is not None and request.get("schema") == V5_SCHEMA:
            return list(V5_RUNTIME_COMPATIBILITY_TESTS)
        return list(V4_RUNTIME_COMPATIBILITY_TESTS if request is not None and
                    request.get("schema") == V4_SCHEMA else COMPATIBILITY_TESTS)
    if profile == "memory":
        return [p for p in tests if p.startswith(("extensions/memory-wiki/", "extensions/memory-core/"))]
    return []




def clean_env(home, parent):
    # An allowlist, not secret-name redaction. Candidate lifecycle/tests never
    # inherit the Actions token, credential files, production HOME or cloud env.
    env = {key: parent[key] for key in ("PATH", "LANG", "LC_ALL", "TZ") if key in parent}
    env.update({"HOME": str(home), "TMPDIR": str(home / "tmp"), "CI": "true",
                "XDG_CONFIG_HOME": str(home / "config"), "XDG_CACHE_HOME": str(home / "cache"),
                "OPENCLAW_STATE_DIR": str(home / "state"), "OPENCLAW_CONFIG_PATH": str(home / "config.json"),
                "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_TERMINAL_PROMPT": "0", "npm_config_userconfig": "/dev/null",
                "npm_config_registry": "https://registry.npmjs.org/"})
    for child in ("tmp", "config", "cache", "state"):
        (home / child).mkdir(mode=0o700, exist_ok=True)
    return env


def commands(pipeline, source, profile, paths, request=None):
    need(profile in profile_minutes_for(request), "named profile required")
    source_sha, _ = source_identity_for(request)
    if profile.startswith("types-"):
        return [["pnpm", {"types-production": "tsgo:prod", "types-tests": "tsgo:test",
                          "types-scripts": "tsgo:scripts"}[profile]]]
    if profile == "dependency":
        native = sorted(p for p in paths if p.startswith("test/") and p.endswith(".test.mjs") and
                        p.rsplit("/", 1)[-1] in {
                            "zod-container-bounds.test.mjs", "a2ui-native-zod-regression.test.mjs",
                            "discord-native-zod-regression.test.mjs", "body-parser-security.test.mjs",
                            "msal-parent-compat.test.mjs", "undici-security.test.mjs",
                            "mcp-nowistay-schema-compatibility.test.mjs", "mcp-nowistay-sdk-regression.test.mjs",
                            "http-cache-semantics-compat.test.mjs"})
        need(len(native) == 9, "complete dependency regression set")
        return [["pnpm", "audit"], ["pnpm", "audit", "--prod"],
                ["node", str(pipeline / "scripts/fork-release/native_tests.mjs"),
                 "--source-root", str(source), "--", *native]]
    if profile == "compatibility":
        compatibility = selected_tests(paths, profile, request)
        required = set(compatibility) | {"test/v108-remediation-security.test.mjs"}
        need(required <= set(paths), "complete compatibility acceptance paths")
        result = [["node", str(pipeline / "scripts/fork-release/native_tests.mjs"),
                 "--source-root", str(source), "--", "test/v108-remediation-security.test.mjs"],
                ["node", "--import", "./scripts/tsx.mjs", "scripts/test-projects.mts", *compatibility],
                ["pnpm", "deps:npm-lock:check:changed", "--base", ORIGINAL_SOURCE, "--head", source_sha]]
        if request is not None and request.get("schema") in (V6_SCHEMA, R7_SCHEMA, R8_SCHEMA):
            result.append(["node", "--input-type=module", "-e", V6_BUNDLED_NPM_VERSION_CHECK])
        return result
    if profile == "pipeline-contracts":
        names = ("test_release.py", "test_preflight.py", "test_merge_source.py",
                                          "test_merge_source_v107.py", "test_merge_source_v108.py",
                                          "test_source_tests.py", "test_source_validation_v108.py",
                                          "test_v108_pnpm_bootstrap.py", "test_v108_recovery_budget.py",
                                          "test_v108_successor_witness.py")
        if request is not None and request.get("schema") in (V4_SCHEMA, V5_SCHEMA, V6_SCHEMA, R7_SCHEMA, R8_SCHEMA):
            names += ("test_v108_runtime_contract_v4.py", "test_request_contract_v4.py",
                      "test_history_checks_v4.py")
        if request is not None and request.get("schema") in (V5_SCHEMA, V6_SCHEMA, R7_SCHEMA, R8_SCHEMA):
            names = tuple(name for name in names if name != "test_v108_runtime_contract_v4.py")
            names += ("test_request_contract_v5.py", "test_history_checks_v5.py",
                      "test_v108_runtime_contract_v5.py", "test_v108_source_donor.py")
        if request is not None and request.get("schema") in (V6_SCHEMA, R7_SCHEMA, R8_SCHEMA):
            names += ("test_historical_v5_test_inputs.py", "test_npm_lock_preparation_v108.py",
                "test_request_contract_v6.py", "test_history_checks_v6.py", "test_v108_runtime_contract_v6.py", "test_v108_intake_recovery_v6.py")
        if request is not None and request.get("schema") in (R7_SCHEMA, R8_SCHEMA):
            names += ("test_request_contract_v7.py", "test_re2js_lock_preparation_v108.py")
            if request.get("stageRound") == 2 or request.get("schema") == R8_SCHEMA:
                names += ("test_targeted_tag_reuse_v108.py",)
        if request is not None and request.get("schema") == R8_SCHEMA:
            names += ("test_request_contract_v8.py", "test_history_checks_v8.py",
                      "test_runtime_contract_v8.py", "test_composite_closed_usage.py")
        return [["python3", "-m", "unittest", "discover", "-s", str(pipeline / "scripts/fork-release"),
                 "-p", name] for name in names]
    tests = selected_tests(paths, profile, request)
    need(bool(tests), "empty owner family")
    return [["node", "--import", "./scripts/tsx.mjs", "scripts/test-projects.mts", *tests]]




def summarize(data, env):
    raw = json.dumps(data, sort_keys=True)
    need(len(raw.encode()) <= 65536, "bounded summary")
    print(raw, flush=True)
    if env.get("GITHUB_STEP_SUMMARY"):
        with open(env["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as out:
            out.write("```json\n" + raw + "\n```\n")


def deadline_check(env, profile, request=None):
    need(profile in profile_minutes_for(request) and re.fullmatch(r"[0-9]{10}", env.get("SOURCE_DEADLINE_EPOCH", "")),
         "admitted campaign deadline/profile required")
    need(datetime.now(timezone.utc).timestamp() + profile_minutes_for(request)[profile] * 60 <=
         min(int(env["SOURCE_DEADLINE_EPOCH"]), int(timestamp(approval_deadline_for(request)).timestamp())),
         "insufficient time in approved campaign")




def resource_check(source):
    """Engineering admission floors, not a measured workload capacity claim."""
    memory = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, value = line.split(":", 1)
        if key == "MemAvailable":
            parts = value.split()
            need(len(parts) == 2 and parts[1] == "kB" and parts[0].isdigit(), "Linux memory metadata")
            memory[key] = int(parts[0]) * 1024
    facts = {"availableMemoryBytes": memory.get("MemAvailable", 0),
             "availableSourceDiskBytes": shutil.disk_usage(source).free,
             "logicalCpus": os.cpu_count() or 0}
    need(facts["availableMemoryBytes"] >= 8 * 1024 ** 3 and
         facts["availableSourceDiskBytes"] >= 8 * 1024 ** 3 and facts["logicalCpus"] >= 4,
         "standard runner below engineering resource floors")
    return facts


def owned_pnpm_file(toolchain, relative):
    path = toolchain / "node_modules/pnpm" / relative
    need(path.resolve(strict=True) == path and path.is_file(), "owned regular pnpm bootstrap file")
    return path


def operation_identity_for(request=None, operation_identity=None):
    """Logging identity only; the caller must separately admit every operation."""
    if operation_identity is None:
        source_sha, source_tree = source_identity_for(request)
        return source_sha, source_tree, CAMPAIGN
    need(type(operation_identity) is dict and set(operation_identity) ==
        {"campaignId", "sourceSha", "sourceTree"} and
        operation_identity["campaignId"] == "future-v109-grouped-validation-20261030" and
        all(type(operation_identity[k]) is str and
            re.fullmatch(r"[0-9a-f]{40}", operation_identity[k]) is not None
            for k in ("sourceSha", "sourceTree")), "fixed explicit operation identity")
    return (operation_identity["sourceSha"], operation_identity["sourceTree"],
            operation_identity["campaignId"])


def bootstrap_pnpm(home, env, request=None, *, operation_identity=None):
    """Initialize only pinned pnpm, then return its owned native executable."""
    source_sha, source_tree, operation_campaign = operation_identity_for(request, operation_identity)
    phase, owned = "resolve-runtimes", False
    try:
        toolchain = home.resolve(strict=True) / "toolchain"
        toolchain.mkdir(mode=0o700)
        node, npm = (shutil.which(name, path=env["PATH"]) for name in ("node", "npm"))
        need(node and npm, "bootstrap runtimes required")
        node, npm = str(Path(node).resolve(strict=True)), str(Path(npm).resolve(strict=True))
        phase = "download-pnpm"
        subprocess.run([npm, "install", "--prefix", str(toolchain), "--ignore-scripts",
                        "--no-audit", "--no-fund", "pnpm@12.15.0"], cwd=toolchain, env=env,
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        phase = "verify-package"
        files = {name: owned_pnpm_file(toolchain, name) for name in PNPM_BOOTSTRAP_FILES}
        for name, path in files.items():
            need(path.stat().st_size <= 65536 and preflight.digest(path) == PNPM_BOOTSTRAP_FILES[name],
                 "pinned pnpm bootstrap file digest")
        package = read_json(files["package.json"].read_bytes())
        need(package.get("name") == "pnpm" and package.get("version") == "12.15.0" and
             package.get("bin") == {"pnpm": "pnpm", "pn": "pn", "pnpx": "pnpx", "pnx": "pnx"} and
             package.get("optionalDependencies", {}).get("@pnpm/exe.linux-x64") == "12.15.0",
             "fixed pnpm package/version/bin")
        phase = "initialize-native"
        # The reviewed Linux initializer only places the already-installed optional
        # native binary. A direct Python exec cannot launch the shebang-less bin.
        subprocess.run([node, str(files["install.js"])], cwd=toolchain, env=env,
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        phase = "verify-native"
        pnpm = owned_pnpm_file(toolchain, "pnpm")
        owned = True
        with pnpm.open("rb") as executable:
            need(executable.read(4) == b"\x7fELF" and os.access(pnpm, os.X_OK), "native pnpm executable")
        need((toolchain / "node_modules/.bin/pnpm").resolve(strict=True) == pnpm,
             "owned pnpm command link")
        phase = "pnpm-version"
        need(subprocess.check_output([str(pnpm), "--version"], cwd=toolchain, env=env,
                                     text=True, stderr=subprocess.DEVNULL).strip() == "12.15.0",
             "fixed pnpm version")
        phase = "node-version"
        need(subprocess.check_output([node, "--version"], cwd=toolchain, env=env,
                                     text=True, stderr=subprocess.DEVNULL).strip() == "v24.22.1",
             "fixed Node version")
        env["PATH"] = str(toolchain / "node_modules/.bin") + os.pathsep + env["PATH"]
        return pnpm
    except (release.Refusal, OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError,
            ProfileInterrupted) as error:
        error_class = ("Interrupted" if isinstance(error, ProfileInterrupted) else
                       "Refusal" if isinstance(error, release.Refusal) else
                       "ProcessError" if isinstance(error, subprocess.CalledProcessError) else
                       "OSError" if isinstance(error, OSError) else "MetadataError")
        code = getattr(error, "errno", None)
        returncode = getattr(error, "returncode", None)
        summarize({"campaignId": operation_campaign, "bootstrapPhase": phase,
                   "sourceSha": source_sha, "sourceTree": source_tree,
                   "status": "interrupted" if isinstance(error, ProfileInterrupted) else "refused",
                   "errorClass": error_class, "errno": code if type(code) is int else None,
                   "exitCode": returncode if type(returncode) is int and returncode >= 0 else None,
                   "signal": -returncode if type(returncode) is int and returncode < 0 else
                             signal.SIGTERM if isinstance(error, ProfileInterrupted) else None,
                   "resolvedWithinOwnedToolchain": owned}, {})
        raise




class ProfileInterrupted(Exception):
    pass


@contextmanager
def profile_signals():
    def interrupted(signum, frame):
        raise ProfileInterrupted()
    old = signal.signal(signal.SIGTERM, interrupted)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, old)


def profile_deadline(env, profile, request=None):
    start = env.get("SOURCE_JOB_STARTED_EPOCH", "")
    need(re.fullmatch(r"[0-9]{10}", start) is not None, "source job clock required")
    now = time.time()
    need(int(start) <= now and now - int(start) < profile_minutes_for(request)[profile] * 60,
         "source job clock freshness")
    return min(int(start) + profile_minutes_for(request)[profile] * 60 - 60,
               int(timestamp(approval_deadline_for(request)).timestamp()) - 60)




def wait_owned_group_absent(pgid, seconds):
    deadline = time.monotonic() + seconds
    while True:
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            return False
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.05, remaining))


def settle_owned_timeout_group(child):
    """Signal only while the unreaped leader pins its verified PID/PGID/SID.

    Inherited stdio lets communicate() reap a TERM-handling leader before its
    descendant exits. Keep that leader unreaped throughout the grace period,
    then signal the same verified group before reaping. After reaping, only
    non-destructive signal0 probes are allowed; never signal a reused identity.
    """
    pid = child.pid
    if type(pid) is not int or pid <= 1 or child.returncode is not None:
        return None, False, "leader_not_owned_unreaped"
    def owned():
        try:
            return child.returncode is None and os.getpgid(pid) == pid and os.getsid(pid) == pid
        except ProcessLookupError:
            return False
        except PermissionError:
            return False
    if not owned():
        return None, False, "session_identity_unverified"
    try:
        os.killpg(pid, signal.SIGTERM)
        deadline = time.monotonic() + 10
        # Do not call poll/wait/communicate here: any of them can reap the
        # leader, losing the stable identity needed for group escalation.
        while time.monotonic() < deadline:
            time.sleep(min(0.05, max(0, deadline - time.monotonic())))
        if not owned():
            return None, False, "session_identity_changed"
        os.killpg(pid, signal.SIGKILL)
        try:
            output, _ = child.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            return None, False, "leader_unsettled_after_kill"
        settled = wait_owned_group_absent(pid, 5)
        return output, settled, "settled" if settled else "group_still_present"
    except (ProcessLookupError, PermissionError):
        return None, False, "group_signal_refused_or_unverified"


def phase_process(argv, cwd, env, context, phase, ordinal):
    """One owned process session; emit bounded facts before every terminal path."""
    source_sha, source_tree, operation_campaign = operation_identity_for(
        context.get("request"), context.get("operationIdentity"))
    remaining = context["deadlineEpoch"] - time.time()
    fact = {"campaignId": operation_campaign, "profile": context["profile"], "phase": phase,
            "commandIndex": ordinal, "sourceSha": source_sha, "sourceTree": source_tree}
    if remaining <= 0:
        summarize(dict(fact, status="budget_refused", exitCode=None, signal=None, timedOut=True), {})
        need(False, "no owned job budget remains")
    summarize(dict(fact, status="started", timeoutSeconds=max(1, math.floor(remaining))), {})
    child = None
    timed_out, interrupted = False, False
    output, cleanup_settled, cleanup_reason = None, None, "not_requested"
    try:
        child = subprocess.Popen(argv, cwd=cwd, env=env, start_new_session=True)
        try:
            output, _ = child.communicate(timeout=remaining)
        except (subprocess.TimeoutExpired, ProfileInterrupted) as error:
            timed_out = isinstance(error, subprocess.TimeoutExpired)
            interrupted = not timed_out
            output, cleanup_settled, cleanup_reason = settle_owned_timeout_group(child)
        actual = child.returncode
        effective = 124 if timed_out else actual if type(actual) is int else 125
        result = subprocess.CompletedProcess(argv, effective, stdout=output)
        result.actual_returncode = actual
        result.timed_out = timed_out
        result.cleanup_settled = cleanup_settled
        summarize(dict(fact, status="timeout" if timed_out else "interrupted" if interrupted else "completed",
                       exitCode=actual if type(actual) is int and actual >= 0 else None,
                       signal=-actual if type(actual) is int and actual < 0 else None,
                       timedOut=timed_out, interrupted=interrupted,
                       cleanupSettled=cleanup_settled, cleanupReason=cleanup_reason), {})
        if interrupted:
            raise ProfileInterrupted()
        return result
    except OSError as error:
        summarize(dict(fact, status="launch_refused", errno=error.errno,
                       exitCode=None, signal=None, timedOut=False), {})
        raise




def run_commands(planned, cwd, env, context=None):
    # Preserve both audits and regressions after ordinary nonzero exits.
    outcomes = []
    for ordinal, argv in enumerate(planned):
        if context is None:
            result = subprocess.run(argv, cwd=cwd, env=env, check=False)
        else:
            result = phase_process(argv, cwd, env, context, "command", ordinal)
        outcomes.append(result.returncode)
        if getattr(result, "timed_out", False):
            break
    return outcomes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("admit", "checkout-budget", "fetch-closure", "run", "finalize"))
    parser.add_argument("--pipeline-dir", type=Path, required=True)
    parser.add_argument("--source-dir", type=Path)
    parser.add_argument("--profile", choices=V6_PROFILE_MINUTES)
    args = parser.parse_args()
    env = os.environ
    with admission_diagnostics(env, True, operational=True):
        return command(args, env)




def command(args, env):
    admission_stage("input", "event.read")
    event = read_json(Path(env["GITHUB_EVENT_PATH"]).read_bytes())
    admission_stage("input", "event.validate")
    validate_event(event, env)
    admission_stage("metadata", "manifest.request")
    request, manifest, manifest_hash = metadata(args.pipeline_dir)
    validate_operational_request(request)
    source_sha, source_tree = source_identity_for(request)
    if args.command == "finalize":
        code_binding(args.pipeline_dir, None, event, env, minimal=True, request=request)
        admission_passed = env.get("SOURCE_ADMISSION_RESULT") == "success"
        passed = env.get("SOURCE_MATRIX_RESULT") == "success" and admission_passed
        summarize({"campaignId": CAMPAIGN, "stageRound": request["stageRound"],
            "lifetimeOperatorRound": request["lifetimeOperatorRound"], "sourceSha": source_sha,
            "sourceTree": source_tree, "status": "passed" if passed else "failed",
            "coverage": "fresh_current_candidate_all15" if request["stageRound"] == 1 else
                "current_candidate_with_admission_verified_targeted_completion",
            "selectedProfiles": profiles_for(request), "requiredFullProfileCount": 15,
            "sourceWitness": request["sourceWitness"], "lockPreparation": request["lockPreparation"],
            "historicalF5CoverageReused": False, "historicalConclusionsRetained": True,
            "targetedPriorCoverageVerificationOwner": "native_admission" if request["stageRound"] == 2 else None,
            "productionAuthorized": False, "imageBuilt": False}, env)
        return 0 if passed else 1
    if args.command == "checkout-budget":
        product_checkout_minutes(env, request)
        admission_stage("binding", "code.bind")
        code_binding(args.pipeline_dir, None, event, env, request=request)
        minutes = product_checkout_minutes(env, request)
        with open(env["GITHUB_OUTPUT"], "a", encoding="utf-8") as out:
            out.write("checkout_minutes=" + str(minutes) + "\n")
        return 0
    need(args.source_dir is not None, "source checkout required")
    admission_stage("binding", "code.bind")
    code_binding(args.pipeline_dir, args.source_dir, event, env, request=request)
    if args.command in ("fetch-closure", "run"):
        profile = args.profile if args.command == "run" else env.get("SOURCE_PROFILE")
        need(profile in profiles_for(request), "profile not in admitted request")
        deadline_check(env, profile, request)
    if args.command == "fetch-closure":
        admission_stage("closure", "closure.acquire")
        fetch_closure(args.pipeline_dir, args.source_dir, request=request, env=env, event=event)
        return 0
    if args.command == "admit":
        admission_deadline(env, request)
        admission_stage("history", "current-pr")
        token = env.get("GH_SOURCE_READ_TOKEN", "")
        need(bool(token), "read-only API token required")
        budget = history_checks_for_operational_request(request, event, env, args.pipeline_dir, lambda p: api_json(p, token))
        admission_stage("closure", "closure.acquire")
        fetch_closure(args.pipeline_dir, args.source_dir, request=request, env=env, event=event)
        admission_stage("equivalence", "equivalence.verify")
        equivalence = verify_operational_source(request, args.pipeline_dir, runtime_read_git(args.source_dir))
        budget["sourceEquivalence"] = equivalence
        matrix = {"include": [{"profile": p, "minutes": profile_minutes_for(request)[p]}
                              for p in profiles_for(request)]}
        _v6_need(budget["profileMatrix"] == matrix["include"] and
            budget["historicalCoverageReused"] is False and budget["reusedProfileCount"] == 0,
            "v6.runtime_verified_budget_and_fresh_coverage")
        _v6_need(type(budget["deadlineEpoch"]) is int and
                 budget["deadlineEpoch"] <= int(timestamp(approval_deadline_for(request)).timestamp()),
                 "v6.runtime_approval_deadline")
        closure_remaining(admission_deadline(env, request))
        admission_stage("matrix", "matrix.publish")
        with open(env["GITHUB_OUTPUT"], "a", encoding="utf-8") as out:
            out.write("matrix=" + json.dumps(matrix, separators=(",", ":")) + "\n")
            out.write("deadline_epoch=" + str(budget["deadlineEpoch"]) + "\n")
        summarize({**budget, "campaignId": CAMPAIGN, "stageRound": request["stageRound"], "lifetimeOperatorRound": request["lifetimeOperatorRound"], "sourceSha": source_sha,
            "sourceTree": source_tree, "manifestSha256": manifest_hash,
            "authorization": "source-validation-only", "productionAuthorized": False,
            "imageBuilt": False}, env)
        return 0
    need(args.profile in profiles_for(request), "profile not in admitted request")
    summarize({"campaignId": CAMPAIGN, "profile": args.profile, "phase": "profile",
        "status": "started", "sourceSha": source_sha, "sourceTree": source_tree}, {})
    with profile_signals():
        try:
            source_preflight(args.pipeline_dir, args.source_dir, manifest, manifest_hash)
            admission_stage("equivalence", "equivalence.verify")
            witness = verify_operational_source(request, args.pipeline_dir, runtime_read_git(args.source_dir))
            paths = git(args.source_dir, "ls-tree", "-r", "--name-only", source_sha).decode().splitlines()
            planned = commands(args.pipeline_dir, args.source_dir, args.profile, paths, request=request)
            resources = resource_check(args.source_dir)
            summarize({**resources, "campaignId": CAMPAIGN, "profile": args.profile, "sourceSha": source_sha,
                "sourceTree": source_tree, "engineeringFloorsPassed": True}, env)
            with tempfile.TemporaryDirectory(prefix="v108-source-") as directory:
                home = Path(directory)
                child_env = clean_env(home, env)
                context = {"profile": args.profile,
                    "deadlineEpoch": profile_deadline(env, args.profile, request), "request": request}
                summarize({"campaignId": CAMPAIGN, "profile": args.profile, "phase": "bootstrap",
                    "status": "started", "sourceSha": source_sha, "sourceTree": source_tree}, {})
                pnpm = bootstrap_pnpm(home, child_env, request=request)
                summarize({"campaignId": CAMPAIGN, "profile": args.profile, "phase": "bootstrap",
                    "status": "completed", "sourceSha": source_sha, "sourceTree": source_tree}, {})
                planned = [[str(pnpm), *argv[1:]] if argv[0] == "pnpm" else argv for argv in planned]
                installation = phase_process([str(pnpm), "install", "--frozen-lockfile"],
                    args.source_dir, child_env, context, "install", 0)
                need(installation.returncode == 0 and not installation.timed_out, "frozen install failed")
                cwd = args.pipeline_dir if args.profile == "pipeline-contracts" else args.source_dir
                outcomes = run_commands(planned, cwd, child_env, context=context)
                summarize({"campaignId": CAMPAIGN, "stageRound": request["stageRound"], "lifetimeOperatorRound": request["lifetimeOperatorRound"], "profile": args.profile,
                    "sourceSha": source_sha, "sourceTree": source_tree, "phase": "profile",
                    "status": "failed" if any(outcomes) else "passed", "exitCodes": outcomes,
                    "completedCommandCount": len(outcomes), "plannedCommandCount": len(planned),
                    "selectedTestCount": len(selected_tests(paths, args.profile, request)),
                    "sourceEquivalence": witness, "productionAuthorized": False, "imageBuilt": False}, env)
                return int(any(outcomes))
        except (release.Refusal, OSError, ValueError, KeyError, TypeError,
                subprocess.CalledProcessError, ProfileInterrupted) as error:
            summarize({"campaignId": CAMPAIGN, "profile": args.profile, "phase": "profile",
                "status": "interrupted" if isinstance(error, ProfileInterrupted) else "refused",
                "errorClass": type(error).__name__ if type(error).__name__ in (
                    "R7ContractRefusal", "V6ContractRefusal", "V5ContractRefusal", "V4ContractRefusal", "Refusal", "OSError", "ValueError", "KeyError", "TypeError",
                    "CalledProcessError", "ProfileInterrupted") else "UnprojectedError",
                "failedNeedCode": runtime_refusal_code_v7(error), "sourceSha": source_sha,
                "sourceTree": source_tree, "signal": signal.SIGTERM if isinstance(error, ProfileInterrupted) else None,
                "productionAuthorized": False, "imageBuilt": False}, {})
            raise




def entrypoint():
    try:
        return main()
    except (release.Refusal, OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError, ProfileInterrupted):
        # Do not print exception data from API/credential-bearing child contexts.
        print("source-validation: refused; inspect bounded structured admission/step diagnostics", file=sys.stderr)
        return 2




V4_RUNTIME_REFUSAL_CODES = frozenset(('v4.affected_source_profiles', 'v4.approved_changed_paths', 'v4.authorized_schema_policy', 'v4.bounded_git_read', 'v4.bounded_ledger', 'v4.closed_prefix_envelope', 'v4.closed_source_equivalence', 'v4.complete_changed_set', 'v4.corrective_booking', 'v4.direct_single_parent', 'v4.duplicate_json_key', 'v4.duplicate_parent_profile', 'v4.exact_closed_prefix', 'v4.exact_derived_ledger', 'v4.exact_derived_row_count', 'v4.exact_git_tree', 'v4.exact_initial_profiles', 'v4.exact_parent_run', 'v4.exact_reviewed_pins', 'v4.exact_ten_passed_parent_profiles', 'v4.fixed_unique_profiles', 'v4.generator_ledger_membership', 'v4.git_entry_encoding', 'v4.git_entry_schema', 'v4.initial_booking', 'v4.initial_source_binding', 'v4.invalid_json', 'v4.invalid_json_constant', 'v4.ledger_origin_path', 'v4.ledger_origin_ref', 'v4.ledger_schema', 'v4.only_generator_ledger_addition', 'v4.other_tracked_bytes_unchanged', 'v4.parent_control_source_binding', 'v4.parent_job_schema', 'v4.parent_ledger_result', 'v4.parent_run_identity', 'v4.positive_reused_job_acquisition', 'v4.regular_source_mode', 'v4.request_fields', 'v4.round_limit', 'v4.runtime_approval_deadline', 'v4.runtime_closure_request', 'v4.runtime_manifest_source', 'v4.runtime_metadata_digest', 'v4.runtime_request_type', 'v4.runtime_settled_usage_digest', 'v4.runtime_verified_budget_and_reuse', 'v4.same_stage_source', 'v4.tracked_path_set_unchanged', 'v4.trusted_metadata_pin', 'v4.trusted_pin_fields', 'v4.trusted_prior_run_pins', 'v4.trusted_source_pin', 'v4.unique_ledger_rows', 'v4.unprojected', 'v4.witness_fields', 'v4.witness_parent'))


V4_RUNTIME_COMPATIBILITY_TESTS = (*COMPATIBILITY_TESTS,
    "src/agents/subagents/registry/subagent-control.accepted-stop.test.ts",
    "test/scripts/generate-npm-package-lock.test.ts")


def source_identity_for(request=None):
    # None/explicit historical records serve old helper tests only. Operational
    # metadata and command both validate the closed v4 request before calling.
    if request is None:
        return SOURCE, TREE
    _v4_need(type(request) is dict, "v4.runtime_request_type")
    if request.get("schema") == R7_PREPARATION_CONTEXT_SCHEMA:
        validate_preparation_context_v7(request, R7_PREPARATION_PINS)
        return request["sourceSha"], request["sourceTree"]
    if request.get("schema") == R7_SCHEMA:
        validate_request_v7(request, R7_STAGE_PINS)
        return request["sourceSha"], request["sourceTree"]
    if request.get("schema") == V6_SCHEMA:
        validate_request_v6(request, V6_STAGE_PINS)
        return request["sourceSha"], request["sourceTree"]
    if request.get("schema") == V5_SCHEMA:
        validate_request_v5(request, V5_STAGE_PINS)
        return request["sourceSha"], request["sourceTree"]
    if request.get("schema") in ("openclaw.fork-source-validation-request.v2",
                                  "openclaw.fork-source-validation-request.v3"):
        return SOURCE, TREE
    validate_request_v4(request, STAGE_PINS)
    return request["sourceSha"], request["sourceTree"]



def approval_deadline_for(request=None):
    if request is None:
        return APPROVAL_DEADLINE
    _v4_need(type(request) is dict, "v4.runtime_request_type")
    if request.get("schema") == R7_SCHEMA:
        validate_request_v7(request, R7_STAGE_PINS)
        return R7_DEADLINE
    if request.get("schema") == V6_SCHEMA:
        validate_request_v6(request, V6_STAGE_PINS)
        return V6_DEADLINE
    if request.get("schema") == V5_SCHEMA:
        validate_request_v5(request, V5_STAGE_PINS)
        return V5_DEADLINE
    if request.get("schema") in ("openclaw.fork-source-validation-request.v2",
                                  "openclaw.fork-source-validation-request.v3"):
        return APPROVAL_DEADLINE
    validate_request_v4(request, STAGE_PINS)
    return V4_DEADLINE



def runtime_refusal_code_v4(error):
    if isinstance(error, V4ContractRefusal):
        code = error.args[0] if len(error.args) == 1 else None
        return code if type(code) is str and code in V4_RUNTIME_REFUSAL_CODES else "v4.unprojected"
    code = vars(error).get("admission_need_code")
    return code if code in ADMISSION_NEED_CODES.values() else "v4.unprojected"


def runtime_read_git(root):
    return lambda *args: git(root, *args)

# Reviewed current-stage literal bindings; historical defaults above are read-only.
STAGE_PINS = {'sourceSha': '84d9bd1c618708e9d5798a730d473ddecf99297a', 'sourceTree': 'ca3ce016d7429e7ef42f6fed99b58f6c6ec623f4', 'firstSourceSha': '84d9bd1c618708e9d5798a730d473ddecf99297a', 'firstSourceTree': 'ca3ce016d7429e7ef42f6fed99b58f6c6ec623f4', 'manifestSha256': '39436d06465c651f63ded013530f91aaf549932dd32390d31b809f8982f527f0', 'inventorySha256': '5f9f2f96f3303487daccb5a59177b7ee7ffa6457a0d5bac98187683b353d8ec7', 'firstManifestSha256': '39436d06465c651f63ded013530f91aaf549932dd32390d31b809f8982f527f0', 'firstInventorySha256': '5f9f2f96f3303487daccb5a59177b7ee7ffa6457a0d5bac98187683b353d8ec7', 'settledUsageSha256': '69a4ab1b30f00b95312ee217fd87dbf32249abd0686bcb941e704d34c9855047', 'priorRunIds': ['40607329263', '40609889437', '40616416909', '40639374411', '40647629182', '40681376480']}

V4_SCHEMA = "openclaw.fork-source-validation-request.v4"
V4_POLICY = "five-gate-repair-v1"
V4_AUTHORIZATION = "future-v108-five-gate-repair-20261028T1007Z"
V4_CAMPAIGN = "future-v108-source-validation-20261027"
V4_DEADLINE = "2026-10-30T00:03:19Z"
V4_CLOSED_PREFIX_SHA256 = "69a4ab1b30f00b95312ee217fd87dbf32249abd0686bcb941e704d34c9855047"
V4_PARENT_SOURCE = "f5c198efedd78625e5a1b4a133d58ebfb3dae1c5"
V4_PARENT_TREE = "c4b245211ceaab98b397945bb0177770f1052c90"
V4_PARENT_PIPELINE = "0dd3c9ef205939350f41ab2187232268c7c44ab8"
V4_PARENT_RUN = "40647629182"
V4_PARENT_MANIFEST = "802abd7c85ee123621d7cc96796ffcd0cf40d58c0d4db60f5f32304802a11f0b"
V4_PARENT_INVENTORY = "876afa1cf8c6398b1fe3f5cdaa031bf1796d96b3e3307352e5a5571b8e3a296e"
V4_REQUEST_PATH = "scripts/fork-release/candidates/v2026.10.8-source-only/source-request.json"
V4_LEDGER_PATH = "custom-patches/reconciliation-2026.10.8.json"
V4_GENERATOR_PATH = "scripts/generate-npm-package-lock.mts"
V4_SOURCE_PATHS = frozenset((
    "src/agents/subagents/registry/subagent-control.accepted-stop.test.ts",
    "test/v108-remediation-security.test.mjs",
    V4_GENERATOR_PATH,
    "test/scripts/generate-npm-package-lock.test.ts",
))
V4_INITIAL_PROFILES = (
    "dependency", "types-tests", "types-scripts", "models-1", "doctor-1",
    "compatibility", "pipeline-contracts",
)
V4_PROFILE_MINUTES = dict(zip(V4_INITIAL_PROFILES, (60, 90, 90, 60, 60, 60, 30)))
V4_REUSED_PROFILES = (
    "types-production", "workboard-1", "workboard-2", "models-2", "sqlite",
    "doctor-2", "doctor-3", "memory",
)
V4_PARENT_PASSED_PROFILES = frozenset((*V4_REUSED_PROFILES, "dependency", "types-scripts"))
V4_BOUNDARY_MINUTES = 25
V4_INITIAL_MINUTES = 475
V4_CORRECTION_MINUTES = 475
V4_OVERALL_MINUTES = 18000
V4_MAX_SOURCE_JOBS = 3
V4_DIAGNOSTIC_BYTES = 64 * 1024 * 1024
V4_MONEY_CEILING_USD = "0.30"
V4_SCOPE = "approved-fixture-and-generator-source-remediation"
V4_DISPOSITION = "REVIEWED_V108_SOURCE_REMEDIATION"
V4_SHA = re.compile(r"[0-9a-f]{40}\Z")
V4_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
V4_RUN_ID = re.compile(r"[1-9][0-9]{0,19}\Z")


class V4ContractRefusal(ValueError):
    """A bounded literal refusal; never contains caller data or child output."""


def _v4_need(condition, code):
    if not condition:
        raise V4ContractRefusal(code)


def _v4_matches(pattern, value):
    return type(value) is str and pattern.fullmatch(value) is not None


def _v4_json(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            _v4_need(key not in value, "v4.duplicate_json_key")
            value[key] = item
        return value
    def invalid_constant(_value):
        raise V4ContractRefusal("v4.invalid_json_constant")
    try:
        return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_constant)
    except (UnicodeError, json.JSONDecodeError):
        raise V4ContractRefusal("v4.invalid_json") from None


def _v4_pins(pins):
    """Pins come only from reviewed driver literals, never request/PR input."""
    fields = {
        "sourceSha", "sourceTree", "firstSourceSha", "firstSourceTree",
        "manifestSha256", "inventorySha256", "firstManifestSha256",
        "firstInventorySha256", "settledUsageSha256", "priorRunIds",
    }
    _v4_need(type(pins) is dict and set(pins) == fields, "v4.trusted_pin_fields")
    for key in ("sourceSha", "sourceTree", "firstSourceSha", "firstSourceTree"):
        _v4_need(_v4_matches(V4_SHA, pins[key]), "v4.trusted_source_pin")
    for key in fields - {"sourceSha", "sourceTree", "firstSourceSha", "firstSourceTree", "priorRunIds"}:
        _v4_need(_v4_matches(V4_SHA256, pins[key]), "v4.trusted_metadata_pin")
    prior = pins["priorRunIds"]
    _v4_need(type(prior) is list and len(prior) in (5, 6) and
             all(_v4_matches(V4_RUN_ID, item) for item in prior) and
             len(prior) == len(set(prior)) and prior[:5] == [
                 "40607329263", "40609889437", "40616416909", "40639374411", V4_PARENT_RUN,
             ], "v4.trusted_prior_run_pins")
    return pins


def _v4_witness(value, parent_sha, parent_tree, initial):
    _v4_need(type(value) is dict and set(value) == {
        "parentSha", "parentTree", "changedPaths", "unchangedTreeSha256",
    }, "v4.witness_fields")
    _v4_need(value["parentSha"] == parent_sha and value["parentTree"] == parent_tree and
             _v4_matches(V4_SHA256, value["unchangedTreeSha256"]), "v4.witness_parent")
    paths = value["changedPaths"]
    _v4_need(type(paths) is list and all(type(path) is str for path in paths) and
             paths == sorted(set(paths)) and bool(paths) and set(paths) <= V4_SOURCE_PATHS and
             (not initial or set(paths) == V4_SOURCE_PATHS), "v4.approved_changed_paths")


def v4_required_correction_profiles(paths):
    _v4_need(type(paths) in (list, tuple, set, frozenset) and bool(paths) and
             all(type(path) is str and path in V4_SOURCE_PATHS for path in paths),
             "v4.approved_changed_paths")
    required = {"dependency", "types-tests", "pipeline-contracts", "compatibility"}
    if V4_GENERATOR_PATH in paths:
        required.add("types-scripts")
    return required


def validate_request_v4(value, pins):
    """Validate only the new closed request. v2/v3 are never operational input."""
    pins = _v4_pins(pins)
    fields = {
        "schema", "campaignId", "profilePolicy", "round", "lifetimeOperatorRound",
        "profiles", "sourceSha", "sourceTree", "firstSourceSha", "firstSourceTree",
        "sourceAuthorization", "manifestSha256", "inventorySha256", "settledUsageSha256",
        "priorRunIds", "sourceWitness",
    }
    _v4_need(type(value) is dict and set(value) == fields, "v4.request_fields")
    _v4_need(value["schema"] == V4_SCHEMA and value["campaignId"] == V4_CAMPAIGN and
             value["profilePolicy"] == V4_POLICY and value["sourceAuthorization"] == V4_AUTHORIZATION,
             "v4.authorized_schema_policy")
    for key in ("sourceSha", "sourceTree", "firstSourceSha", "firstSourceTree",
                "manifestSha256", "inventorySha256", "settledUsageSha256", "priorRunIds"):
        _v4_need(value[key] == pins[key], "v4.exact_reviewed_pins")
    round_number = value["round"]
    _v4_need(type(round_number) is int and round_number in (4, 5) and
             type(value["lifetimeOperatorRound"]) is int and
             value["lifetimeOperatorRound"] == round_number + 1 and
             len(pins["priorRunIds"]) == round_number + 1, "v4.round_limit")
    profiles = value["profiles"]
    _v4_need(type(profiles) is list and bool(profiles) and
             all(type(profile) is str and profile in V4_PROFILE_MINUTES for profile in profiles) and
             len(profiles) == len(set(profiles)), "v4.fixed_unique_profiles")
    witness = value["sourceWitness"]
    _v4_need(type(witness) is dict and set(witness) == {
        "schema", "scope", "closedPrefixSha256", "stageBase", "corrective",
    } and witness["schema"] == "openclaw.v108.fixture-generator-equivalence.v1" and
        witness["scope"] == V4_SCOPE and witness["closedPrefixSha256"] == V4_CLOSED_PREFIX_SHA256,
        "v4.closed_source_equivalence")
    _v4_witness(witness["stageBase"], V4_PARENT_SOURCE, V4_PARENT_TREE, initial=True)
    same_source = (value["sourceSha"], value["sourceTree"]) == (
        value["firstSourceSha"], value["firstSourceTree"])
    if same_source:
        _v4_need(witness["corrective"] is None and
                 value["manifestSha256"] == pins["firstManifestSha256"] and
                 value["inventorySha256"] == pins["firstInventorySha256"], "v4.same_stage_source")
    else:
        _v4_need(round_number == 5, "v4.initial_source_binding")
        _v4_witness(witness["corrective"], pins["firstSourceSha"], pins["firstSourceTree"], initial=False)
        _v4_need(v4_required_correction_profiles(witness["corrective"]["changedPaths"]) <= set(profiles),
                 "v4.affected_source_profiles")
    if round_number == 4:
        _v4_need(same_source and profiles == list(V4_INITIAL_PROFILES), "v4.exact_initial_profiles")
        _v4_need(V4_BOUNDARY_MINUTES + sum(V4_PROFILE_MINUTES[p] for p in profiles) == V4_INITIAL_MINUTES,
                 "v4.initial_booking")
    else:
        _v4_need(V4_BOUNDARY_MINUTES + sum(V4_PROFILE_MINUTES[p] for p in profiles) <= V4_CORRECTION_MINUTES,
                 "v4.corrective_booking")
    return value


def _v4_git(read_git, *args):
    raw = read_git(*args)
    _v4_need(type(raw) is bytes and len(raw) <= V4_DIAGNOSTIC_BYTES, "v4.bounded_git_read")
    return raw


def _v4_entries(raw):
    result = {}
    for row in raw.split(b"\0"):
        if not row:
            continue
        try:
            metadata, encoded_path = row.split(b"\t", 1)
            mode, kind, blob = metadata.decode("ascii").split()
            path = encoded_path.decode("utf-8")
        except (ValueError, UnicodeError):
            raise V4ContractRefusal("v4.git_entry_encoding") from None
        _v4_need(path and not path.startswith("/") and
                 all(part not in ("", ".", "..") for part in path.split("/")) and
                 path not in result and re.fullmatch(r"[0-7]{6}", mode) is not None and
                 kind in ("blob", "commit") and _v4_matches(V4_SHA, blob), "v4.git_entry_schema")
        result[path] = (mode, kind, blob)
    return result


def _v4_tree(read_git, commit, tree):
    actual = _v4_git(read_git, "rev-parse", commit + "^{tree}")
    _v4_need(actual == (tree + "\n").encode(), "v4.exact_git_tree")
    return _v4_entries(_v4_git(read_git, "ls-tree", "-r", "-z", commit))


def _v4_result(entry):
    _v4_need(entry[:2] == ("100644", "blob"), "v4.regular_source_mode")
    return {"mode": entry[0], "blob": entry[2]}


def _v4_origin(read_git, ref, path):
    _v4_need(_v4_matches(V4_SHA, ref), "v4.ledger_origin_ref")
    found = _v4_entries(_v4_git(read_git, "ls-tree", "-z", ref, "--", path))
    _v4_need(set(found) <= {path}, "v4.ledger_origin_path")
    return _v4_result(found[path]) if path in found else None


def _v4_expected_ledger(read_git, old_raw, before, after, changed, initial):
    _v4_need(len(old_raw) <= 2 * 1024 * 1024, "v4.bounded_ledger")
    expected = _v4_json(old_raw)
    _v4_need(type(expected) is dict and type(expected.get("paths")) is list,
             "v4.ledger_schema")
    rows = expected["paths"]
    _v4_need(all(type(row) is dict and type(row.get("path")) is str for row in rows) and
             len({row["path"] for row in rows}) == len(rows) and
             len(rows) == (248 if initial else 249), "v4.unique_ledger_rows")
    by_path = {row["path"]: row for row in rows}
    _v4_need((V4_GENERATOR_PATH not in by_path) if initial else (V4_GENERATOR_PATH in by_path),
             "v4.generator_ledger_membership")
    row_fields = {"path", "upstream107", "fork107", "upstream108", "result", "disposition"}
    for path in changed:
        row = by_path.get(path)
        if row is None:
            _v4_need(initial and path == V4_GENERATOR_PATH, "v4.only_generator_ledger_addition")
            row = {
                "path": path,
                "upstream107": _v4_origin(read_git, expected.get("upstream107"), path),
                "fork107": _v4_origin(read_git, expected.get("fork107Source"), path),
                "upstream108": _v4_origin(read_git, expected.get("upstream108"), path),
                "result": _v4_result(after[path]),
                "disposition": V4_DISPOSITION,
            }
            rows.append(row)
            rows.sort(key=lambda item: item["path"])
            by_path[path] = row
            continue
        _v4_need(set(row) == row_fields and row["result"] == _v4_result(before[path]) and
                 row["disposition"] in ("CARRIED_EXACT", V4_DISPOSITION), "v4.parent_ledger_result")
        row["result"] = _v4_result(after[path])
        row["disposition"] = V4_DISPOSITION
    _v4_need(len(rows) == 249, "v4.exact_derived_row_count")
    return expected


def _v4_verify_step(read_git, current, current_tree, witness, initial):
    parent, parent_tree = witness["parentSha"], witness["parentTree"]
    _v4_need(_v4_git(read_git, "show", "-s", "--format=%P", current) == (parent + "\n").encode(),
             "v4.direct_single_parent")
    before = _v4_tree(read_git, parent, parent_tree)
    after = _v4_tree(read_git, current, current_tree)
    _v4_need(set(before) == set(after), "v4.tracked_path_set_unchanged")
    changed = sorted(path for path in before if before[path] != after[path])
    source_paths = witness["changedPaths"]
    _v4_need(changed == sorted([*source_paths, V4_LEDGER_PATH]), "v4.complete_changed_set")
    for path in changed:
        _v4_result(before[path])
        _v4_result(after[path])
    old_raw = _v4_git(read_git, "show", parent + ":" + V4_LEDGER_PATH)
    new_raw = _v4_git(read_git, "show", current + ":" + V4_LEDGER_PATH)
    _v4_need(len(new_raw) <= 2 * 1024 * 1024, "v4.bounded_ledger")
    expected = _v4_expected_ledger(read_git, old_raw, before, after, source_paths, initial)
    # Python value equality conflates false/0 and 1/1.0. Preserve JSON types as
    # well as every non-derived field; whitespace/key order are not semantics.
    _v4_need(json.dumps(expected, sort_keys=True, separators=(",", ":"), allow_nan=False) ==
             json.dumps(_v4_json(new_raw), sort_keys=True, separators=(",", ":"), allow_nan=False),
             "v4.exact_derived_ledger")
    def digest(entries):
        payload = b"".join((" ".join(entries[path]) + "\t" + path).encode() + b"\0"
                           for path in sorted(entries) if path not in changed)
        return hashlib.sha256(payload).hexdigest()
    unchanged = digest(before)
    _v4_need(unchanged == digest(after) == witness["unchangedTreeSha256"], "v4.other_tracked_bytes_unchanged")
    return {
        "parentSha": parent, "parentTree": parent_tree, "sourceSha": current,
        "sourceTree": current_tree, "changedPaths": source_paths,
        "unchangedTreeSha256": unchanged,
        "derivedLedger": {"path": V4_LEDGER_PATH, "previousBlob": before[V4_LEDGER_PATH][2],
                          "currentBlob": after[V4_LEDGER_PATH][2]},
    }


def verify_source_equivalence_v4(request, pins, read_git):
    """Prove actual Git object entries; the witness alone grants no reuse."""
    validate_request_v4(request, pins)
    witness = request["sourceWitness"]
    base = _v4_verify_step(read_git, pins["firstSourceSha"], pins["firstSourceTree"],
                           witness["stageBase"], initial=True)
    correction = None
    if witness["corrective"] is not None:
        correction = _v4_verify_step(read_git, pins["sourceSha"], pins["sourceTree"],
                                     witness["corrective"], initial=False)
    return {
        "schema": "openclaw.v108.verified-fixture-generator-equivalence.v1",
        "scope": V4_SCOPE, "stageBase": base, "corrective": correction,
        "reusedReceiptSourceSha": V4_PARENT_SOURCE,
        "reusedReceiptPipelineHead": V4_PARENT_PIPELINE, "reusedReceiptRunId": V4_PARENT_RUN,
        "sameSourceReceiptRelabeled": False, "unchangedOutsideApprovedSourceAndLedger": True,
        "generatorOwnerChanged": V4_GENERATOR_PATH in witness["stageBase"]["changedPaths"],
        "testOnly": False,
    }


def validate_reused_profile_evidence_v4(prefix_raw, read_git):
    """Read-only historical proof; it never converts v3 into a v4 request."""
    _v4_need(type(prefix_raw) is bytes and len(prefix_raw) <= V4_DIAGNOSTIC_BYTES and
             hashlib.sha256(prefix_raw).hexdigest() == V4_CLOSED_PREFIX_SHA256, "v4.exact_closed_prefix")
    prefix = _v4_json(prefix_raw)
    _v4_need(type(prefix) is dict and type(prefix.get("runs")) is list and
             len(prefix["runs"]) == 99 and prefix.get("runnerMinutesObserved") == 886,
             "v4.closed_prefix_envelope")
    selected = [run for run in prefix["runs"] if type(run) is dict and run.get("id") == int(V4_PARENT_RUN)]
    _v4_need(len(selected) == 1, "v4.exact_parent_run")
    run = selected[0]
    _v4_need(run.get("head_sha") == V4_PARENT_PIPELINE and run.get("run_attempt") == 1 and
             run.get("event") == "pull_request" and run.get("status") == "completed" and
             run.get("path") == ".github/workflows/future-v108-source-validation.yml" and
             run.get("head_branch") == "task/v107-source-binding" and type(run.get("jobs")) is list,
             "v4.parent_run_identity")
    historical = _v4_json(_v4_git(read_git, "show", V4_PARENT_PIPELINE + ":" + V4_REQUEST_PATH))
    _v4_need(type(historical) is dict and historical.get("schema") == "openclaw.fork-source-validation-request.v3" and
             historical.get("sourceSha") == V4_PARENT_SOURCE and historical.get("sourceTree") == V4_PARENT_TREE and
             historical.get("manifestSha256") == V4_PARENT_MANIFEST and
             historical.get("inventorySha256") == V4_PARENT_INVENTORY, "v4.parent_control_source_binding")
    profile_jobs = {}
    for job in run["jobs"]:
        _v4_need(type(job) is dict and type(job.get("name")) is str, "v4.parent_job_schema")
        name = job["name"]
        if name.startswith("source (") and name.endswith(")"):
            profile = name[8:-1]
            _v4_need(profile not in profile_jobs, "v4.duplicate_parent_profile")
            profile_jobs[profile] = job
    passed = {profile for profile, job in profile_jobs.items()
              if job.get("status") == "completed" and job.get("conclusion") == "success"}
    _v4_need(passed == V4_PARENT_PASSED_PROFILES, "v4.exact_ten_passed_parent_profiles")
    for profile in V4_REUSED_PROFILES:
        job = profile_jobs[profile]
        _v4_need(type(job.get("runner_id")) is int and job["runner_id"] > 0 and
                 type(job.get("runner_name")) is str and bool(job["runner_name"]) and
                 type(job.get("steps")) is list and bool(job["steps"]), "v4.positive_reused_job_acquisition")
    return {
        "schema": "openclaw.v108.reused-parent-profiles.v1", "sourceSha": V4_PARENT_SOURCE,
        "sourceTree": V4_PARENT_TREE, "pipelineHead": V4_PARENT_PIPELINE,
        "runId": V4_PARENT_RUN, "runAttempt": 1, "manifestSha256": V4_PARENT_MANIFEST,
        "inventorySha256": V4_PARENT_INVENTORY, "closedPrefixSha256": V4_CLOSED_PREFIX_SHA256,
        "profiles": list(V4_REUSED_PROFILES), "passedParentProfiles": sorted(passed),
        "relabeledAsCurrentSourcePass": False,
    }

V4_HISTORY_ORIGIN = "2026-10-28T00:03:19Z"
V4_STAGE_ORIGIN = "2026-10-28T10:07:00Z"
V4_HISTORY_MAX_RUNS = 200
V4_HISTORY_MAX_ANCILLARY = 160
V4_NEW_ANCILLARY_MINUTES = 45
V4_CLOSED_ARTIFACT_BYTES = 5600
V4_CLOSED_ARTIFACT_COUNT = 9
V4_CLOSED_ARTIFACT_PROOF_SHA256 = "cf741734a6dcda5a6282e043fa8211dedf2670becb7b88ad195aaf6cf1ee9d51"
V4_SOURCE_BRANCH = "prep/v2026.10.8-remediation"
V4_PROVIDER_RUN_HEADERS = ("id", "name", "path", "event", "head_branch", "head_sha", "run_attempt",
                           "status", "conclusion", "created_at", "updated_at", "html_url")
V4_PREFIX_DERIVED_FIELDS = {"jobs", "observedRunnerMinutes", "artifactRows"}
FIRST_PIPELINE = "de4cdb8aae20719ae95808d3cf725a4b503d6d01"
FIRST_REQUEST_SHA256 = "1e30932e9ae9ef55777d169a14e350d3e95aaf01bbafd0237ed2b553ce4ec667"


def _h4_need(value, code):
    need(value, "v4.history." + code)


def _h4_public(run):
    return all(type(run.get(key)) is dict and
               run[key].get("full_name") == REPOSITORY and
               run[key].get("private") is False
               for key in ("repository", "head_repository"))


def _h4_branch_history(api):
    route = ("/repos/" + REPOSITORY + "/actions/runs?branch=task%2Fv107-source-binding"
             "&created=%3E%3D2026-10-28T00%3A03%3A19Z&per_page=100&page=")
    first = api(route + "1")
    _h4_need(type(first) is dict and type(first.get("total_count")) is int and
             0 <= first["total_count"] <= V4_HISTORY_MAX_RUNS and
             type(first.get("workflow_runs")) is list, "branch_page")
    total, rows = first["total_count"], list(first["workflow_runs"])
    _h4_need(len(rows) == min(total, 100), "branch_page_size")
    if total > 100:
        second = api(route + "2")
        _h4_need(type(second) is dict and second.get("total_count") == total and
                 type(second.get("workflow_runs")) is list and
                 len(second["workflow_runs"]) == total - 100, "branch_pagination")
        rows += second["workflow_runs"]
    ids = [row.get("id") for row in rows if type(row) is dict]
    _h4_need(len(ids) == total and all(type(i) is int and i > 0 for i in ids) and
             len(set(ids)) == total, "branch_unique_ids")
    return {str(row["id"]): row for row in rows}


def _h4_jobs(api, run):
    rid = str(run["id"])
    table = api("/repos/" + REPOSITORY + "/actions/runs/" + rid +
                "/jobs?filter=all&per_page=100")
    _h4_need(type(table) is dict and type(table.get("total_count")) is int and
             type(table.get("jobs")) is list and
             table["total_count"] == len(table["jobs"]) <= 100, "fresh_jobs_complete")
    for job in table["jobs"]:
        _h4_need(type(job) is dict and job.get("run_id") == run["id"] and
                 job.get("head_sha") == run["head_sha"] and
                 job.get("run_attempt") == 1, "fresh_job_binding")
    return table


def _h4_artifacts(api, run):
    table = api("/repos/" + REPOSITORY + "/actions/runs/" + str(run["id"]) +
                "/artifacts?per_page=100")
    _h4_need(type(table) is dict and type(table.get("total_count")) is int and
             type(table.get("artifacts")) is list and
             table["total_count"] == len(table["artifacts"]) <= 100, "artifacts_complete")
    ids, size = set(), 0
    for artifact in table["artifacts"]:
        _h4_need(type(artifact) is dict and type(artifact.get("id")) is int and
                 artifact["id"] > 0 and artifact["id"] not in ids and
                 type(artifact.get("size_in_bytes")) is int and
                 artifact["size_in_bytes"] >= 0 and type(artifact.get("expired")) is bool,
                 "artifact_identity_size")
        ids.add(artifact["id"])
        size += artifact["size_in_bytes"]
    return {"count": len(ids), "bytes": size, "ids": sorted(ids),
            "observationComplete": run["status"] == "completed"}


def _h4_unexpanded_failed_initial(jobs):
    """Positive immutable P5 shape, not an inference from absent profile rows."""
    names = {job["name"]: job for job in jobs}
    if len(jobs) != 3 or set(names) != {"admission", "final", "source (${{ matrix.profile }})"}:
        return False
    admission = names["admission"]
    if not (admission["status"] == "completed" and admission["conclusion"] == "failure" and
            type(admission.get("runner_id")) is int and admission["runner_id"] > 0):
        return False
    return all(job["status"] == "completed" and job["conclusion"] == "skipped" and
               "runner_id" in job and job["runner_id"] is None and
               "runner_name" in job and job["runner_name"] is None and
               "runner_group_name" in job and job["runner_group_name"] is None and
               type(job.get("steps")) is list and not job["steps"]
               for job in (names["final"], names["source (${{ matrix.profile }})"]))


def _h4_block(text, header, indent=0):
    lines = text.splitlines()
    matches = [i for i, line in enumerate(lines) if line == " " * indent + header + ":"]
    _h4_need(len(matches) == 1, "workflow_block")
    start = matches[0] + 1
    end = start
    while end < len(lines):
        line = lines[end]
        if line.strip() and not line.lstrip().startswith("#") and len(line) - len(line.lstrip()) <= indent:
            break
        end += 1
    return [line for line in lines[start:end] if line.strip() and not line.lstrip().startswith("#")]


def workflow_security_v4(raw, source_sha):
    """Closed sensitive YAML projection; non-security selection/code may change."""
    _h4_need(type(raw) is bytes and 0 < len(raw) <= 65536, "workflow_size")
    text = raw.decode("utf-8")
    _h4_need("\t" not in text and "\r" not in text and
             not re.search(r"(?m)^\s*(?:-\s*)?(?:[A-Za-z_][A-Za-z0-9_-]*:\s*)?[&*!]", text),
             "workflow_yaml_shape")
    # This owner accepts the reviewed literal mapping style, not general YAML.
    # Otherwise quoted/flow keys could be effective while invisible to checks.
    _h4_need(not re.search(r'''(?m)^\s*(?:-\s*)?["'][^"'\n]+["']\s*:''', text) and
             not re.search(r"(?m)^\s*(?:-\s*)?\{", text) and
             not re.search(r":\s*\{(?!\{)", text), "workflow_literal_mapping")
    top_lines = [line for line in text.splitlines() if line and
                 not line.startswith((" ", "#"))]
    top_matches = [re.fullmatch(r"([A-Za-z][A-Za-z0-9_-]*):(?: .*)?", line) for line in top_lines]
    _h4_need(all(top_matches), "workflow_literal_mapping")
    top = [match[1] for match in top_matches]
    _h4_need(len(top) == len(set(top)) and set(top) ==
             {"name", "run-name", "on", "permissions", "concurrency", "env", "jobs"},
             "workflow_top_level")
    _h4_need(_h4_block(text, "on") == ["  pull_request:",
             "    types: [opened, reopened, synchronize]"], "workflow_trigger")
    _h4_need(_h4_block(text, "permissions") == ["  contents: read"], "workflow_permissions")
    _h4_need(_h4_block(text, "concurrency") == [
             "  group: future-v108-source-validation-20261027", "  cancel-in-progress: false"],
             "workflow_concurrency")
    jobs = _h4_block(text, "jobs")
    _h4_need([line for line in jobs if len(line) - len(line.lstrip()) == 2] ==
             ["  admission:", "  source:", "  final:"], "workflow_jobs")
    for name in ("admission", "source", "final"):
        block = "\n".join(_h4_block(text, name, 2))
        direct = [line for line in block.splitlines() if len(line) - len(line.lstrip()) == 4]
        matches = [re.fullmatch(r"    ([A-Za-z][A-Za-z0-9_-]*):(?: .*)?", line) for line in direct]
        _h4_need(all(matches), "workflow_literal_mapping")
        keys = [match[1] for match in matches]
        allowed = {"if", "needs", "name", "runs-on", "timeout-minutes", "permissions",
                   "outputs", "steps", "env", "strategy"}
        _h4_need(len(keys) == len(set(keys)) and set(keys) <= allowed and
                 "    runs-on: ubuntu-24.04" in block.splitlines(), "workflow_runner_job_keys")
        expected = {"admission": "15", "source": "${{ matrix.minutes }}", "final": "10"}[name]
        _h4_need("    timeout-minutes: " + expected in block.splitlines(), "workflow_job_caps")
        expected_permissions = (["      contents: read", "      actions: read", "      pull-requests: read"]
                                if name == "admission" else ["      contents: read"])
        permissions = _h4_block("  " + name + ":\n" + block, "permissions", 4)
        _h4_need(permissions == expected_permissions, "workflow_job_permissions")
    _h4_need(text.count("      max-parallel: 3") == 1 and
             text.count("      fail-fast: false") == 1, "workflow_matrix_policy")
    _h4_need(_h4_block("  source:\n" + "\n".join(_h4_block(text, "source", 2)),
                      "strategy", 4) == ["      fail-fast: false", "      max-parallel: 3",
                      "      matrix: ${{ fromJSON(needs.admission.outputs.matrix) }}"],
             "workflow_matrix_policy")
    refs = re.findall(r"(?m)^          ref: ([0-9a-f]{40})$", text)
    _h4_need(refs == [source_sha, source_sha], "workflow_source_refs")
    _h4_need(re.findall(r"(?m)^\s*persist-credentials:\s*([^\n]+)$", text) ==
             ["false"] * 5, "workflow_credentials")
    uses = re.findall(r"(?m)^\s*-?\s*uses: ([^\n#]+)", text)
    _h4_need(len(uses) == 6 and all(value.strip() in (
             "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
             "actions/setup-node@820762786026740c76f36085b0efc47a31fe5020") for value in uses),
             "workflow_fixed_actions")
    _h4_need("secrets." not in text and text.count("${{ github.token }}") == 1 and
             text.count("          GH_SOURCE_READ_TOKEN: ${{ github.token }}") == 1,
             "workflow_token_surface")
    return {"runner": "ubuntu-24.04", "permissions": "read-only",
            "trigger": "same-repository-draft-pr28", "parallel": 3,
            "caps": {"admission": 15, "final": 10, "profileMaximum": 90},
            "sourceRefs": 2, "fixedActions": 6}


def _h4_prefix(pipeline, request, history):
    raw = (pipeline / SETTLED_USAGE).read_bytes()
    _h4_need(hashlib.sha256(raw).hexdigest() == request["settledUsageSha256"] ==
             V4_CLOSED_PREFIX_SHA256, "prefix_digest")
    prefix = read_json(raw)
    _h4_need(type(prefix) is dict and type(prefix.get("runs")) is list and
             len(prefix["runs"]) == 99 and prefix.get("runnerMinutesObserved") == 886,
             "prefix_envelope")
    ids, total, table_hashes = set(), 0, {}
    for row in prefix["runs"]:
        rid = str(row.get("id"))
        _h4_need(type(row.get("id")) is int and row["id"] > 0 and rid not in ids and
                 row.get("status") == "completed" and row.get("run_attempt") == 1 and
                 type(row.get("jobs")) is list, "prefix_run_identity")
        ids.add(rid)
        live = history.get(rid, {})
        _h4_need(set(V4_PROVIDER_RUN_HEADERS) <= set(row) and
                 set(row) <= set(V4_PROVIDER_RUN_HEADERS) | V4_PREFIX_DERIVED_FIELDS and
                 ("artifactRows" not in row or type(row["artifactRows"]) is list),
                 "prefix_projection_schema")
        headers = V4_PROVIDER_RUN_HEADERS
        _h4_need(_h4_public(live) and all(live.get(key) == row[key] for key in headers),
                 "prefix_header_changed")
        # This exact hashed projection omitted per-job attempt. Its positive
        # authenticated run header supplies the field; fresh API tables never do.
        jobs = []
        for item in row["jobs"]:
            _h4_need(type(item) is dict and ("run_attempt" not in item or item["run_attempt"] == row["run_attempt"]),
                     "prefix_job_attempt")
            jobs.append(dict(item, run_attempt=row["run_attempt"]))
        old = rid in STAGE_PINS["priorRunIds"][:3]
        expected = (list(LEGACY_PROFILE_MINUTES) if old else list(PROFILE_MINUTES)) if row["path"] == WORKFLOW else None
        measured = observed_minutes({"total_count": len(jobs), "jobs": jobs}, expected,
                                    legacy=old or row["path"] != WORKFLOW,
                                    profile_request=None if old else {"schema": "openclaw.fork-source-validation-request.v3"})
        _h4_need(type(row.get("observedRunnerMinutes")) is int and measured == row["observedRunnerMinutes"],
                 "prefix_job_minutes")
        total += measured
        table_hashes[rid] = hashlib.sha256(json.dumps(row["jobs"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    _h4_need(len(ids) == 99 and total == 886, "prefix_actual886")
    return raw, prefix, ids, table_hashes


def history_checks_v4(request, event, env, pipeline, api):
    request = validate_request_v4(request, STAGE_PINS)
    head = validate_event(event, env)
    now = datetime.now(timezone.utc)
    _h4_need(now < timestamp(V4_DEADLINE), "deadline")
    live = api("/repos/" + REPOSITORY + "/pulls/28")
    _h4_need(validate_event(dict(event, pull_request=live), env) == head, "live_pr_changed")
    target = api("/repos/" + REPOSITORY + "/git/ref/heads/" + BASE_BRANCH)
    _h4_need(target.get("ref") == "refs/heads/" + BASE_BRANCH and
             target.get("object", {}).get("type") == "commit" and
             target["object"].get("sha") == TARGET_BRANCH_TIP, "target_tip")
    source_ref = api("/repos/" + REPOSITORY + "/git/ref/heads/" + V4_SOURCE_BRANCH)
    _h4_need(source_ref.get("ref") == "refs/heads/" + V4_SOURCE_BRANCH and
             source_ref.get("object", {}).get("type") == "commit" and
             source_ref["object"].get("sha") == request["sourceSha"], "source_branch_tip")
    history = _h4_branch_history(api)
    _h4_need(sum(r.get("path") != WORKFLOW for r in history.values()) <= V4_HISTORY_MAX_ANCILLARY,
             "ancillary_record_bound")
    raw, prefix, prefix_ids, hashes = _h4_prefix(pipeline, request, history)
    reused = validate_reused_profile_evidence_v4(raw, lambda *args: git(pipeline, *args))
    expected = [*request["priorRunIds"], env["GITHUB_RUN_ID"]]
    actual = {rid for rid, run in history.items() if run.get("path") == WORKFLOW}
    _h4_need(actual == set(expected) and len(expected) == len(set(expected)), "source_round_set")
    for rid in actual:
        run = history[rid]
        _h4_need(_h4_public(run) and run.get("event") == "pull_request" and
                 run.get("run_attempt") == 1 and run.get("head_branch") == BRANCH and
                 run.get("display_title") == CAMPAIGN and
                 [pr.get("number") for pr in run.get("pull_requests", [])] == [28], "source_run_binding")
    current = history[env["GITHUB_RUN_ID"]]
    _h4_need(current.get("head_sha") == head and current.get("status") == "in_progress" and
             timestamp(V4_STAGE_ORIGIN) <= timestamp(current["created_at"]) <= now,
             "current_source_identity")
    for rid in request["priorRunIds"][:5]:
        git(pipeline, "merge-base", "--is-ancestor", history[rid]["head_sha"], head)
    workflow = workflow_security_v4((pipeline / WORKFLOW).read_bytes(), request["sourceSha"])
    previous_minutes, first = 0, None
    new_source_runs = [current]
    if request["round"] == 5:
        _h4_need(type(FIRST_PIPELINE) is str and release.matches(release.SHA, FIRST_PIPELINE) and
                 type(FIRST_REQUEST_SHA256) is str and release.matches(HEX256, FIRST_REQUEST_SHA256),
                 "genuine_first_controls_required")
        rid = request["priorRunIds"][-1]
        previous = history[rid]
        _h4_need(previous.get("status") == "completed" and previous.get("head_sha") == FIRST_PIPELINE and
                 previous.get("conclusion") in ("success", "failure", "cancelled", "timed_out",
                     "action_required", "neutral", "skipped", "startup_failure", "stale") and
                 timestamp(V4_STAGE_ORIGIN) <= timestamp(previous["created_at"]) <=
                 timestamp(current["created_at"]), "first_source_terminal")
        prior_raw = content_at(api, REQUEST, FIRST_PIPELINE)
        _h4_need(hashlib.sha256(prior_raw).hexdigest() == FIRST_REQUEST_SHA256, "first_request_digest")
        pins = dict(STAGE_PINS, sourceSha=STAGE_PINS["firstSourceSha"], sourceTree=STAGE_PINS["firstSourceTree"],
                    manifestSha256=STAGE_PINS["firstManifestSha256"], inventorySha256=STAGE_PINS["firstInventorySha256"],
                    priorRunIds=STAGE_PINS["priorRunIds"][:5])
        old_request = validate_request_v4(read_json(prior_raw), pins)
        _h4_need(old_request["round"] == 4, "first_request_round")
        workflow_security_v4(content_at(api, WORKFLOW, FIRST_PIPELINE), old_request["sourceSha"])
        git(pipeline, "merge-base", "--is-ancestor", FIRST_PIPELINE, head)
        prior_jobs = _h4_jobs(api, previous)
        previous_minutes = observed_minutes(prior_jobs, old_request["profiles"], profile_request=old_request)
        _h4_need(previous_minutes <= V4_INITIAL_MINUTES, "first_booking_exceeded")
        _h4_need(all(job.get("conclusion") in ("success", "failure", "cancelled", "timed_out",
                     "action_required", "neutral", "skipped", "startup_failure", "stale")
                     for job in prior_jobs["jobs"]), "first_job_conclusion")
        prior_results = {job["name"][8:-1]: job["conclusion"] for job in prior_jobs["jobs"]
                         if job["name"].startswith("source (") and job["name"].endswith(")") and
                         job["name"][8:-1] in old_request["profiles"]}
        source_acquired = sum(type(job.get("runner_id")) is int and job["runner_id"] > 0
                              for job in prior_jobs["jobs"] if job["name"][8:-1] in prior_results)
        unexpanded_failed_initial = _h4_unexpanded_failed_initial(prior_jobs["jobs"])
        _h4_need(bool(prior_results) or unexpanded_failed_initial, "first_unexpanded_positive_evidence")
        unresolved = {profile for profile in old_request["profiles"]
                      if prior_results.get(profile) != "success"}
        _h4_need(unresolved <= set(request["profiles"]), "unresolved_first_profiles_selected")
        first = {"runId": rid, "pipelineHead": FIRST_PIPELINE, "sourceSha": old_request["sourceSha"],
                 "sourceTree": old_request["sourceTree"], "requestSha256": FIRST_REQUEST_SHA256,
                 "observedRunnerMinutes": previous_minutes, "profileResults": prior_results,
                 "conclusion": previous["conclusion"], "unresolvedProfiles": sorted(unresolved),
                 "sourceProfilesAcquired": source_acquired,
                 "initialValidationNeverStarted": unexpanded_failed_initial,
                 "relabeledAsCurrentSourcePass": False}
        new_source_runs.append(previous)
    current_jobs = _h4_jobs(api, current)
    admission = [j for j in current_jobs["jobs"] if j.get("name") == "admission"]
    _h4_need(len(admission) == 1 and admission[0].get("status") == "in_progress" and
             type(admission[0].get("runner_id")) is int and admission[0]["runner_id"] > 0 and
             admission[0].get("runner_group_name") == "GitHub Actions" and
             admission[0].get("labels") == ["ubuntu-24.04"] and
             type(admission[0].get("runner_name")) is str and bool(admission[0]["runner_name"]),
             "current_public_admission")
    current_facts = ancillary_job_snapshot(current_jobs, now, False)
    allowed_current = {"admission", "final", "source (${{ matrix.profile }})",
                       *["source (" + p + ")" for p in request["profiles"]]}
    _h4_need(all(j.get("name") in allowed_current and
                 (j is admission[0] or j.get("runner_id") in (None, 0))
                 for j in current_jobs["jobs"]), "current_jobs_before_admission")
    known_paths = {r["path"] for r in prefix["runs"] if r["path"] != WORKFLOW}
    known_heads = {r["head_sha"] for r in prefix["runs"]} | {head}
    if FIRST_PIPELINE is not None:
        known_heads.add(FIRST_PIPELINE)
    ancillary, observed, pending = [], 0, []
    artifact_records, artifact_ids, artifact_bytes = [], set(), V4_CLOSED_ARTIFACT_BYTES
    for rid, run in sorted(history.items()):
        if rid in prefix_ids:
            continue
        if run.get("path") != WORKFLOW:
            _h4_need(_h4_public(run) and run.get("event") in ("pull_request", "pull_request_target") and
                     run.get("run_attempt") == 1 and run.get("head_branch") == BRANCH and
                     run.get("path") in known_paths and run.get("head_sha") in known_heads and
                     run.get("status") in ("completed", "in_progress", "queued", "waiting", "pending"),
                     "new_ancillary_identity")
            _h4_need(run["status"] != "completed" or run.get("conclusion") in (
                     "success", "failure", "cancelled", "timed_out", "action_required", "neutral",
                     "skipped", "startup_failure", "stale"), "new_ancillary_conclusion")
            facts = ancillary_job_snapshot(_h4_jobs(api, run), now, run["status"] == "completed")
            observed += facts["observedAcquiredRunnerMinutes"]
            ancillary.append({"runId": rid, **facts})
            if not facts["usageComplete"]:
                pending.append(rid)
        artifacts = _h4_artifacts(api, run)
        _h4_need(not artifact_ids.intersection(artifacts["ids"]), "artifact_duplicate")
        artifact_ids.update(artifacts["ids"])
        artifact_bytes += artifacts["bytes"]
        artifact_records.append({"runId": rid, **artifacts})
    _h4_need(observed <= V4_NEW_ANCILLARY_MINUTES and
             (not pending or observed < V4_NEW_ANCILLARY_MINUTES), "ancillary45_exceeded")
    _h4_need(artifact_bytes <= V4_DIAGNOSTIC_BYTES, "artifact_storage_bound")
    planned = V4_BOUNDARY_MINUTES + sum(V4_PROFILE_MINUTES[p] for p in request["profiles"])
    reserve = V4_CORRECTION_MINUTES if request["round"] == 4 else 0
    booked = 886 + previous_minutes + planned + reserve + V4_NEW_ANCILLARY_MINUTES
    _h4_need(booked <= V4_OVERALL_MINUTES, "lifetime18000_exceeded")
    return {"bookedRunnerMinutes": booked, "actualSettledRunnerMinutes": 886,
            "observedNewPriorRunnerMinutes": previous_minutes, "currentRoundBookedMinutes": planned,
            "futureTargetedReserveMinutes": reserve, "operatorRoundsRemaining": 1 if request["round"] == 4 else 0,
            "observedNewAncillaryRunnerMinutes": observed,
            "newAncillaryRemainingReserveMinutes": V4_NEW_ANCILLARY_MINUTES - observed,
            "newAncillaryRecords": ancillary, "pendingAncillaryRunIds": pending,
            "ancillaryUsageComplete": not pending, "ancillaryReservationBookedMinutes": V4_NEW_ANCILLARY_MINUTES,
            "ancillaryWaitPerformed": False, "artifactRecords": artifact_records,
            "observedRetainedWorkflowArtifactBytes": artifact_bytes,
            "closedArtifactBaselineProof": {"bytes": V4_CLOSED_ARTIFACT_BYTES,
                "count": V4_CLOSED_ARTIFACT_COUNT, "finalCloseoutSha256": V4_CLOSED_ARTIFACT_PROOF_SHA256},
            "closedPrefixHeaderFields": list(V4_PROVIDER_RUN_HEADERS),
            "artifactObservationComplete": all(a["observationComplete"] for a in artifact_records),
            "artifactBudgetIsNotWholeDiagnosticCustodyProof": True,
            "campaignRunnerMinuteCeiling": V4_OVERALL_MINUTES,
            "deadlineEpoch": int(timestamp(V4_DEADLINE).timestamp()), "firstSourceReceipt": first,
            "reusedProfileEvidence": reused, "historicalJobTableSha256": hashes,
            "profileMatrix": [{"profile": p, "minutes": V4_PROFILE_MINUTES[p]} for p in request["profiles"]],
            "selectedProfileCount": len(request["profiles"]), "reusedProfileCount": len(V4_REUSED_PROFILES),
            "currentAdmissionObservation": current_facts,
            "workflowSecurity": workflow, "historicalConclusionsRetained": True,
            "productionAuthorized": False, "imageBuilt": False}




V5_RUNTIME_REFUSAL_CODES = frozenset(('v5.affected_source_profiles', 'v5.approved_changed_paths', 'v5.baseline_unbound', 'v5.baseline_unique_runs', 'v5.budget_policy', 'v5.budget_record', 'v5.closed_authorized_request', 'v5.closed_baseline_envelope', 'v5.closed_source_equivalence', 'v5.current_source_chain', 'v5.duplicate_json_key', 'v5.exact_closed_baseline', 'v5.exact_initial_profiles', 'v5.exact_reviewed_pins', 'v5.first_source_baseline', 'v5.fixed_unique_profiles', 'v5.invalid_json', 'v5.invalid_json_constant', 'v5.original_prefix_git_binding', 'v5.previous_source_hop_count', 'v5.round_booking', 'v5.round_limit', 'v5.runtime_approval_deadline', 'v5.runtime_manifest_source', 'v5.runtime_metadata_digest', 'v5.runtime_settled_usage_digest', 'v5.runtime_verified_budget_and_reuse', 'v5.source_hop_duplicate', 'v5.trusted_metadata_pin', 'v5.trusted_pin_fields', 'v5.trusted_prior_run_pins', 'v5.trusted_source_hops', 'v5.trusted_source_pin', 'v5.unchanged_source_metadata', 'v5.unprojected', 'v5.witness_hop_binding', 'v5.witness_hop_count', 'v5.witness_parent_fields'))


V5_RUNTIME_COMPATIBILITY_TESTS = V4_RUNTIME_COMPATIBILITY_TESTS


def runtime_refusal_code_v5(error):
    if isinstance(error, V5ContractRefusal):
        code = error.args[0] if len(error.args) == 1 else None
        return code if type(code) is str and code in V5_RUNTIME_REFUSAL_CODES else "v5.unprojected"
    if isinstance(error, V4ContractRefusal):
        # V5's actual Git proof delegates unchanged closed V4 object owners.
        return runtime_refusal_code_v4(error)
    code = vars(error).get("admission_need_code")
    return code if code in ADMISSION_NEED_CODES.values() else "v5.unprojected"


V5_STAGE_PINS = {'firstInventorySha256': '5f9f2f96f3303487daccb5a59177b7ee7ffa6457a0d5bac98187683b353d8ec7',
 'firstManifestSha256': '39436d06465c651f63ded013530f91aaf549932dd32390d31b809f8982f527f0',
 'firstSourceSha': '84d9bd1c618708e9d5798a730d473ddecf99297a',
 'firstSourceTree': 'ca3ce016d7429e7ef42f6fed99b58f6c6ec623f4',
 'inventorySha256': '5f9f2f96f3303487daccb5a59177b7ee7ffa6457a0d5bac98187683b353d8ec7',
 'manifestSha256': '39436d06465c651f63ded013530f91aaf549932dd32390d31b809f8982f527f0',
 'previousSourceHopCount': 0,
 'priorRunIds': ['40607329263',
                 '40609889437',
                 '40616416909',
                 '40639374411',
                 '40647629182',
                 '40681376480',
                 '40688279536'],
 'settledUsageSha256': 'b02f46b6c5404f33bf04a519190bc724843f901f3bd045ac47a82edaa845eb0d',
 'sourceHops': [],
 'sourceSha': '84d9bd1c618708e9d5798a730d473ddecf99297a',
 'sourceTree': 'ca3ce016d7429e7ef42f6fed99b58f6c6ec623f4'}
V5_STAGE_RUN_PINS = []

V5_SCHEMA = "openclaw.fork-source-validation-request.v5"
V5_POLICY = "donor-repair-v1"
V5_AUTHORIZATION = "future-v108-donor-repair-20261028T1339Z"
V5_CAMPAIGN = "future-v108-source-validation-20261027"
V5_DEADLINE = "2026-10-30T00:03:19Z"
# Genuine closed141 receipt produced by the coordinating owner, not a new run.
V5_BASELINE_SHA256 = "b02f46b6c5404f33bf04a519190bc724843f901f3bd045ac47a82edaa845eb0d"
V5_CLOSED_SOURCE_RUN_IDS = ("40607329263", "40609889437", "40616416909", "40639374411",
                            "40647629182", "40681376480", "40688279536")
V5_PRIOR_RUNS = 141
V5_PRIOR_MINUTES = 928
V5_FIRST_SOURCE = "84d9bd1c618708e9d5798a730d473ddecf99297a"
V5_FIRST_TREE = "ca3ce016d7429e7ef42f6fed99b58f6c6ec623f4"
V5_ORIGINAL_PREFIX_SHA256 = "69a4ab1b30f00b95312ee217fd87dbf32249abd0686bcb941e704d34c9855047"
V5_ORIGINAL_PREFIX_RUNS = 99
V5_ORIGINAL_PREFIX_MINUTES = 886
V5_ORIGINAL_PREFIX_PIPELINE = "2946a1678e712de90727a9e599a5f2cd47ad2151"
V5_SETTLED_USAGE_PATH = "scripts/fork-release/candidates/v2026.10.8-source-only/settled-usage.json"
V5_PROFILES = ("dependency", "types-tests", "types-scripts", "models-1", "doctor-1",
               "compatibility", "pipeline-contracts")
V5_PROFILE_MINUTES = dict(zip(V5_PROFILES, (60, 90, 90, 60, 90, 60, 30)))
V5_ADMISSION_MINUTES = 30
V5_FINAL_MINUTES = 10
V5_ROUND_MINUTES = 520
V5_ANCILLARY_MINUTES = 90
V5_STAGE_MINUTES = 1650
V5_OVERALL_MINUTES = 18000
V5_MAX_CORRECTIONS = 2
V5_MAX_SOURCE_JOBS = 3
V5_DIAGNOSTIC_BYTES = 64 * 1024 * 1024
V5_MONEY_CEILING_USD = "0.30"
V5_SOURCE_PATHS = frozenset((
    "scripts/generate-npm-package-lock.mts",
    "src/agents/subagents/registry/subagent-control.accepted-stop.test.ts",
    "test/scripts/generate-npm-package-lock.test.ts",
    "test/v108-remediation-security.test.mjs",
))
V5_SCOPE = "approved-fixture-and-generator-source-remediation"
V5_SHA = re.compile(r"[0-9a-f]{40}\Z")
V5_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
V5_RUN_ID = re.compile(r"[1-9][0-9]{0,19}\Z")


class V5ContractRefusal(ValueError):
    """Fixed literal reason only; no caller-controlled detail."""


def _v5_need(condition, code):
    if not condition:
        raise V5ContractRefusal(code)


def _v5_matches(pattern, value):
    return type(value) is str and pattern.fullmatch(value) is not None


def _v5_json(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            _v5_need(key not in value, "v5.duplicate_json_key")
            value[key] = item
        return value
    def invalid_constant(_value):
        raise V5ContractRefusal("v5.invalid_json_constant")
    try:
        return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_constant)
    except (UnicodeError, json.JSONDecodeError):
        raise V5ContractRefusal("v5.invalid_json") from None


def validation_budget_for_record_v5(record):
    """Versioned measurement policy, never permission to operate legacy input."""
    _v5_need(type(record) is dict, "v5.budget_record")
    schema = record.get("schema")
    if schema == V5_SCHEMA:
        _v5_need(record.get("profilePolicy") == V5_POLICY, "v5.budget_policy")
        return {"admissionMinutes": V5_ADMISSION_MINUTES, "finalMinutes": V5_FINAL_MINUTES,
                "profileMinutes": dict(V5_PROFILE_MINUTES), "roundMaximumMinutes": V5_ROUND_MINUTES,
                "ancillaryMinutes": V5_ANCILLARY_MINUTES, "stageMaximumMinutes": V5_STAGE_MINUTES}
    if schema == "openclaw.fork-source-validation-request.v4":
        _v5_need(record.get("profilePolicy") == "five-gate-repair-v1", "v5.budget_policy")
        return {"admissionMinutes": 15, "finalMinutes": 10,
                "profileMinutes": dict(zip(V5_PROFILES, (60, 90, 90, 60, 60, 60, 30))),
                "roundMaximumMinutes": 475, "ancillaryMinutes": 45, "stageMaximumMinutes": 995}
    _v5_need(schema in ("openclaw.fork-source-validation-request.v2",
                        "openclaw.fork-source-validation-request.v3") and "profilePolicy" not in record,
             "v5.budget_policy")
    # The old pre-V4 policy has15 profiles and Doctor1/2/3=45. Keep the exact
    # prior table for historical accounting instead of today's seven defaults.
    profiles = {"dependency":60, "types-production":90, "types-tests":90, "types-scripts":90,
                "workboard-1":60, "workboard-2":60, "models-1":60, "models-2":60,
                "sqlite":60, "doctor-1":45, "doctor-2":45, "doctor-3":45,
                "memory":60, "pipeline-contracts":30, "compatibility":60}
    return {"admissionMinutes":15, "finalMinutes":10, "profileMinutes":profiles,
            "roundMaximumMinutes":940, "ancillaryMinutes":135, "stageMaximumMinutes":1375}


def v5_required_correction_profiles(paths):
    _v5_need(type(paths) in (list, tuple, set, frozenset) and bool(paths) and
             all(type(path) is str and path in V5_SOURCE_PATHS for path in paths), "v5.approved_changed_paths")
    required = {"dependency", "types-tests", "compatibility", "pipeline-contracts"}
    if "scripts/generate-npm-package-lock.mts" in paths:
        required.add("types-scripts")
    return required


def _v5_pins(pins):
    fields = {"sourceSha", "sourceTree", "firstSourceSha", "firstSourceTree", "manifestSha256",
              "inventorySha256", "firstManifestSha256", "firstInventorySha256", "settledUsageSha256",
              "priorRunIds", "sourceHops", "previousSourceHopCount"}
    _v5_need(type(pins) is dict and set(pins) == fields, "v5.trusted_pin_fields")
    _v5_need(_v5_matches(V5_SHA256, V5_BASELINE_SHA256) and
             type(V5_CLOSED_SOURCE_RUN_IDS) is tuple and len(V5_CLOSED_SOURCE_RUN_IDS) == 7 and
             all(_v5_matches(V5_RUN_ID, run) for run in V5_CLOSED_SOURCE_RUN_IDS) and
             len(set(V5_CLOSED_SOURCE_RUN_IDS)) == 7, "v5.baseline_unbound")
    for key in ("sourceSha", "sourceTree", "firstSourceSha", "firstSourceTree"):
        _v5_need(_v5_matches(V5_SHA, pins[key]), "v5.trusted_source_pin")
    for key in ("manifestSha256", "inventorySha256", "firstManifestSha256", "firstInventorySha256",
                "settledUsageSha256"):
        _v5_need(_v5_matches(V5_SHA256, pins[key]), "v5.trusted_metadata_pin")
    _v5_need(pins["firstSourceSha"] == V5_FIRST_SOURCE and pins["firstSourceTree"] == V5_FIRST_TREE and
             pins["settledUsageSha256"] == V5_BASELINE_SHA256, "v5.first_source_baseline")
    prior = pins["priorRunIds"]
    _v5_need(type(prior) is list and 7 <= len(prior) <= 9 and
             all(_v5_matches(V5_RUN_ID, run) for run in prior) and len(set(prior)) == len(prior) and
             prior[:7] == list(V5_CLOSED_SOURCE_RUN_IDS), "v5.trusted_prior_run_pins")
    hops = pins["sourceHops"]
    _v5_need(type(hops) is list and len(hops) <= V5_MAX_CORRECTIONS and
             all(type(hop) is dict and set(hop) == {"sourceSha", "sourceTree"} and
                 _v5_matches(V5_SHA, hop["sourceSha"]) and _v5_matches(V5_SHA, hop["sourceTree"])
                 for hop in hops), "v5.trusted_source_hops")
    _v5_need(type(pins["previousSourceHopCount"]) is int and
             0 <= pins["previousSourceHopCount"] <= len(hops) and
             len(hops) - pins["previousSourceHopCount"] <= 1, "v5.previous_source_hop_count")
    commits = [V5_FIRST_SOURCE, *(hop["sourceSha"] for hop in hops)]
    _v5_need(len(set(commits)) == len(commits), "v5.source_hop_duplicate")
    current = hops[-1] if hops else {"sourceSha": V5_FIRST_SOURCE, "sourceTree": V5_FIRST_TREE}
    _v5_need(pins["sourceSha"] == current["sourceSha"] and pins["sourceTree"] == current["sourceTree"],
             "v5.current_source_chain")
    if not hops:
        _v5_need(pins["manifestSha256"] == pins["firstManifestSha256"] and
                 pins["inventorySha256"] == pins["firstInventorySha256"], "v5.unchanged_source_metadata")
    return pins


def _v5_step(witness, parent_sha, parent_tree, initial):
    fields = {"parentSha", "parentTree", "changedPaths", "unchangedTreeSha256"}
    _v5_need(type(witness) is dict and set(witness) == fields and
             witness["parentSha"] == parent_sha and witness["parentTree"] == parent_tree and
             _v5_matches(V5_SHA256, witness["unchangedTreeSha256"]), "v5.witness_parent_fields")
    paths = witness["changedPaths"]
    _v5_need(type(paths) is list and all(type(path) is str for path in paths) and
             paths == sorted(set(paths)) and bool(paths) and set(paths) <= V5_SOURCE_PATHS and
             (not initial or set(paths) == V5_SOURCE_PATHS), "v5.approved_changed_paths")


def validate_request_v5(value, pins):
    pins = _v5_pins(pins)
    fields = {"schema", "campaignId", "profilePolicy", "stageRound", "lifetimeOperatorRound", "profiles",
              "sourceSha", "sourceTree", "firstSourceSha", "firstSourceTree", "sourceAuthorization",
              "manifestSha256", "inventorySha256", "settledUsageSha256", "priorRunIds", "sourceWitness"}
    _v5_need(type(value) is dict and set(value) == fields and value["schema"] == V5_SCHEMA and
             value["campaignId"] == V5_CAMPAIGN and value["profilePolicy"] == V5_POLICY and
             value["sourceAuthorization"] == V5_AUTHORIZATION, "v5.closed_authorized_request")
    for key in ("sourceSha", "sourceTree", "firstSourceSha", "firstSourceTree", "manifestSha256",
                "inventorySha256", "settledUsageSha256", "priorRunIds"):
        _v5_need(value[key] == pins[key], "v5.exact_reviewed_pins")
    number = value["stageRound"]
    _v5_need(type(number) is int and 0 <= number <= V5_MAX_CORRECTIONS and
             type(value["lifetimeOperatorRound"]) is int and value["lifetimeOperatorRound"] == number + 7 and
             len(pins["priorRunIds"]) == number + 7 and len(pins["sourceHops"]) <= number, "v5.round_limit")
    profiles = value["profiles"]
    _v5_need(type(profiles) is list and bool(profiles) and
             all(type(profile) is str and profile in V5_PROFILE_MINUTES for profile in profiles) and
             len(profiles) == len(set(profiles)), "v5.fixed_unique_profiles")
    _v5_need(V5_ADMISSION_MINUTES + V5_FINAL_MINUTES + sum(V5_PROFILE_MINUTES[p] for p in profiles)
             <= V5_ROUND_MINUTES, "v5.round_booking")
    if number == 0:
        _v5_need(profiles == list(V5_PROFILES) and not pins["sourceHops"] and
                 pins["previousSourceHopCount"] == 0, "v5.exact_initial_profiles")
    else:
        _v5_need(pins["previousSourceHopCount"] <= number - 1, "v5.previous_source_hop_count")
    witness = value["sourceWitness"]
    _v5_need(type(witness) is dict and set(witness) == {"schema", "scope", "originalClosedPrefixSha256",
        "closedBaselineSha256", "stageBase", "correctionHops"} and
        witness["schema"] == "openclaw.v108.fixture-generator-equivalence.v2" and witness["scope"] == V5_SCOPE and
        witness["originalClosedPrefixSha256"] == V5_ORIGINAL_PREFIX_SHA256 and
        witness["closedBaselineSha256"] == V5_BASELINE_SHA256, "v5.closed_source_equivalence")
    _v5_step(witness["stageBase"], "f5c198efedd78625e5a1b4a133d58ebfb3dae1c5",
             "c4b245211ceaab98b397945bb0177770f1052c90", initial=True)
    hops = witness["correctionHops"]
    _v5_need(type(hops) is list and len(hops) == len(pins["sourceHops"]), "v5.witness_hop_count")
    parent_sha, parent_tree = V5_FIRST_SOURCE, V5_FIRST_TREE
    for witnessed, pinned in zip(hops, pins["sourceHops"]):
        _v5_need(type(witnessed) is dict and set(witnessed) == {"sourceSha", "sourceTree", "step"} and
                 witnessed["sourceSha"] == pinned["sourceSha"] and witnessed["sourceTree"] == pinned["sourceTree"],
                 "v5.witness_hop_binding")
        _v5_step(witnessed["step"], parent_sha, parent_tree, initial=False)
        parent_sha, parent_tree = pinned["sourceSha"], pinned["sourceTree"]
    # History binds this trusted count to the actual previous stage request.
    # Old hops remain in the Git proof, but only new deltas require owner reruns.
    affected = set()
    for hop in hops[pins["previousSourceHopCount"]:]:
        affected.update(v5_required_correction_profiles(hop["step"]["changedPaths"]))
    _v5_need(affected <= set(profiles), "v5.affected_source_profiles")
    return value


def verify_source_equivalence_v5(request, pins, read_git):
    """Reuse immutable V4 Git/ledger mechanics, never its operational validator."""
    validate_request_v5(request, pins)
    witness = request["sourceWitness"]
    stage_base = _v4_verify_step(read_git, V5_FIRST_SOURCE, V5_FIRST_TREE, witness["stageBase"], initial=True)
    hops = [_v4_verify_step(read_git, hop["sourceSha"], hop["sourceTree"], hop["step"], initial=False)
            for hop in witness["correctionHops"]]
    return {"schema":"openclaw.v108.verified-fixture-generator-equivalence.v2", "scope":V5_SCOPE,
            "stageBase":stage_base, "correctionHops":hops, "sourceSha":request["sourceSha"],
            "sourceTree":request["sourceTree"], "originalClosedPrefixSha256":V5_ORIGINAL_PREFIX_SHA256,
            "closedBaselineSha256":V5_BASELINE_SHA256, "reusedReceiptSourceSha":"f5c198efedd78625e5a1b4a133d58ebfb3dae1c5",
            "reusedReceiptPipelineHead":"0dd3c9ef205939350f41ab2187232268c7c44ab8", "reusedReceiptRunId":"40647629182",
            "sameSourceReceiptRelabeled":False, "unchangedOutsideApprovedSourceAndLedger":True, "testOnly":False}


def validate_reused_profile_evidence_v5(baseline_raw, read_git):
    """Bind new141, reverify original69a bytes, and retain original F5 provenance."""
    _v5_need(type(baseline_raw) is bytes and len(baseline_raw) <= V5_DIAGNOSTIC_BYTES and
             _v5_matches(V5_SHA256, V5_BASELINE_SHA256) and
             hashlib.sha256(baseline_raw).hexdigest() == V5_BASELINE_SHA256, "v5.exact_closed_baseline")
    baseline = _v5_json(baseline_raw)
    _v5_need(type(baseline) is dict and baseline.get("schema") == "openclaw.v108.closed-source-usage.v3" and
             baseline.get("repository") == "fr-meyer/openclaw" and baseline.get("campaignId") == V5_CAMPAIGN and
             type(baseline.get("runs")) is list and len(baseline["runs"]) == V5_PRIOR_RUNS and
             type(baseline.get("runCount")) is int and baseline["runCount"] == V5_PRIOR_RUNS and
             type(baseline.get("runnerMinutesObserved")) is int and
             baseline["runnerMinutesObserved"] == V5_PRIOR_MINUTES and
             baseline.get("previousPrefixSha256") == V5_ORIGINAL_PREFIX_SHA256 and
             type(baseline.get("previousPrefixRunCount")) is int and
             baseline["previousPrefixRunCount"] == V5_ORIGINAL_PREFIX_RUNS and
             type(baseline.get("previousPrefixMinutes")) is int and
             baseline["previousPrefixMinutes"] == V5_ORIGINAL_PREFIX_MINUTES and
             baseline.get("previousPrefixPipeline") == V5_ORIGINAL_PREFIX_PIPELINE,
             "v5.closed_baseline_envelope")
    original_raw = read_git("show", V5_ORIGINAL_PREFIX_PIPELINE + ":" + V5_SETTLED_USAGE_PATH)
    _v5_need(type(original_raw) is bytes and len(original_raw) <= V5_DIAGNOSTIC_BYTES and
             hashlib.sha256(original_raw).hexdigest() == V5_ORIGINAL_PREFIX_SHA256,
             "v5.original_prefix_git_binding")
    original = _v5_json(original_raw)
    ids = [run.get("id") for run in baseline["runs"] if type(run) is dict]
    _v5_need(len(ids) == V5_PRIOR_RUNS and all(type(run) is int and run > 0 for run in ids) and
             len(set(ids)) == len(ids), "v5.baseline_unique_runs")
    original_by_id = {run["id"]: run for run in original["runs"]}
    current_by_id = {run["id"]: run for run in baseline["runs"]}
    _v5_need(len(original_by_id) == V5_ORIGINAL_PREFIX_RUNS and set(original_by_id) <= set(current_by_id) and
             json.dumps(original_by_id, sort_keys=True, separators=(",", ":"), allow_nan=False) ==
             json.dumps({run:current_by_id[run] for run in original_by_id},
                        sort_keys=True, separators=(",", ":"), allow_nan=False), "v5.original99_subset_unchanged")
    # The existing reviewed helper proves the original fixed raw69a/F5/control
    # identities and positive ten-pass/eight-reuse acquisition. No global mutates.
    reused = validate_reused_profile_evidence_v4(original_raw, read_git)
    return {**reused, "schema":"openclaw.v108.reused-parent-profiles.v2",
            "closedBaselineSha256":V5_BASELINE_SHA256, "closedBaselineRuns":V5_PRIOR_RUNS,
            "closedBaselineMinutes":V5_PRIOR_MINUTES, "originalClosedPrefixSha256":V5_ORIGINAL_PREFIX_SHA256,
            "originalPrefixRawGitReverified":True, "original99SubsetUnchanged":True,
            "relabeledAsCurrentSourcePass":False}


V5_STAGE_ORIGIN = "2026-10-28T13:39:00Z"
V5_HISTORY_MAX_RUNS = 300  # internal complete-pagination alarm, not spending authority
V5_PROVIDER_RUN_HEADERS = ("id", "name", "path", "event", "head_branch", "head_sha", "run_attempt",
                           "status", "conclusion", "created_at", "updated_at", "html_url")
V5_PREFIX_DERIVED_FIELDS = {"jobs", "observedRunnerMinutes", "artifactRows"}
V5_SOURCE_BRANCH = "prep/v2026.10.8-remediation"
# Stage run identities are the root-owned literal above.
V5_TERMINAL_CONCLUSIONS = frozenset(("success", "failure", "cancelled", "timed_out", "action_required",
                                    "neutral", "skipped", "startup_failure", "stale"))


def _h5_need(value, code):
    need(value, "v5.history." + code)


def _h5_public(run):
    return all(type(run.get(key)) is dict and
               run[key].get("full_name") == REPOSITORY and
               run[key].get("private") is False
               for key in ("repository", "head_repository"))


def _h5_jobs(api, run):
    rid = str(run["id"])
    table = api("/repos/" + REPOSITORY + "/actions/runs/" + rid +
                "/jobs?filter=all&per_page=100")
    _h5_need(type(table) is dict and type(table.get("total_count")) is int and
             type(table.get("jobs")) is list and
             table["total_count"] == len(table["jobs"]) <= 100, "fresh_jobs_complete")
    for job in table["jobs"]:
        _h5_need(type(job) is dict and job.get("run_id") == run["id"] and
                 job.get("head_sha") == run["head_sha"] and
                 type(job.get("run_attempt")) is int and job["run_attempt"] == 1, "fresh_job_binding")
    return table


def _h5_artifacts(api, run):
    table = api("/repos/" + REPOSITORY + "/actions/runs/" + str(run["id"]) +
                "/artifacts?per_page=100")
    _h5_need(type(table) is dict and type(table.get("total_count")) is int and
             type(table.get("artifacts")) is list and
             table["total_count"] == len(table["artifacts"]) <= 100, "artifacts_complete")
    ids, size = set(), 0
    for artifact in table["artifacts"]:
        _h5_need(type(artifact) is dict and type(artifact.get("id")) is int and
                 artifact["id"] > 0 and artifact["id"] not in ids and
                 type(artifact.get("size_in_bytes")) is int and
                 artifact["size_in_bytes"] >= 0 and type(artifact.get("expired")) is bool,
                 "artifact_identity_size")
        ids.add(artifact["id"])
        size += artifact["size_in_bytes"]
    return {"count": len(ids), "bytes": size, "ids": sorted(ids),
            "observationComplete": run["status"] == "completed"}


def _h5_unexpanded_failed_initial(jobs):
    """Positive immutable P5 shape, not an inference from absent profile rows."""
    names = {job["name"]: job for job in jobs}
    if len(jobs) != 3 or set(names) != {"admission", "final", "source (${{ matrix.profile }})"}:
        return False
    admission = names["admission"]
    if not (admission["status"] == "completed" and admission["conclusion"] == "failure" and
            type(admission.get("runner_id")) is int and admission["runner_id"] > 0):
        return False
    return all(job["status"] == "completed" and job["conclusion"] == "skipped" and
               "runner_id" in job and job["runner_id"] is None and
               "runner_name" in job and job["runner_name"] is None and
               "runner_group_name" in job and job["runner_group_name"] is None and
               type(job.get("steps")) is list and not job["steps"]
               for job in (names["final"], names["source (${{ matrix.profile }})"]))


def _h5_block(text, header, indent=0):
    lines = text.splitlines()
    matches = [i for i, line in enumerate(lines) if line == " " * indent + header + ":"]
    _h5_need(len(matches) == 1, "workflow_block")
    start = matches[0] + 1
    end = start
    while end < len(lines):
        line = lines[end]
        if line.strip() and not line.lstrip().startswith("#") and len(line) - len(line.lstrip()) <= indent:
            break
        end += 1
    return [line for line in lines[start:end] if line.strip() and not line.lstrip().startswith("#")]


def workflow_security_v5(raw, source_sha):
    """Closed sensitive YAML projection; non-security selection/code may change."""
    _h5_need(type(raw) is bytes and 0 < len(raw) <= 65536, "workflow_size")
    text = raw.decode("utf-8")
    _h5_need("\t" not in text and "\r" not in text and
             not re.search(r"(?m)^\s*(?:-\s*)?(?:[A-Za-z_][A-Za-z0-9_-]*:\s*)?[&*!]", text),
             "workflow_yaml_shape")
    # This owner accepts the reviewed literal mapping style, not general YAML.
    # Otherwise quoted/flow keys could be effective while invisible to checks.
    _h5_need(not re.search(r'''(?m)^\s*(?:-\s*)?["'][^"'\n]+["']\s*:''', text) and
             not re.search(r"(?m)^\s*(?:-\s*)?\{", text) and
             not re.search(r":\s*\{(?!\{)", text), "workflow_literal_mapping")
    top_lines = [line for line in text.splitlines() if line and
                 not line.startswith((" ", "#"))]
    top_matches = [re.fullmatch(r"([A-Za-z][A-Za-z0-9_-]*):(?: .*)?", line) for line in top_lines]
    _h5_need(all(top_matches), "workflow_literal_mapping")
    top = [match[1] for match in top_matches]
    _h5_need(len(top) == len(set(top)) and set(top) ==
             {"name", "run-name", "on", "permissions", "concurrency", "env", "jobs"},
             "workflow_top_level")
    _h5_need(_h5_block(text, "on") == ["  pull_request:",
             "    types: [opened, reopened, synchronize]"], "workflow_trigger")
    _h5_need(_h5_block(text, "permissions") == ["  contents: read"], "workflow_permissions")
    _h5_need(_h5_block(text, "concurrency") == [
             "  group: future-v108-source-validation-20261027", "  cancel-in-progress: false"],
             "workflow_concurrency")
    jobs = _h5_block(text, "jobs")
    _h5_need([line for line in jobs if len(line) - len(line.lstrip()) == 2] ==
             ["  admission:", "  source:", "  final:"], "workflow_jobs")
    for name in ("admission", "source", "final"):
        block = "\n".join(_h5_block(text, name, 2))
        direct = [line for line in block.splitlines() if len(line) - len(line.lstrip()) == 4]
        matches = [re.fullmatch(r"    ([A-Za-z][A-Za-z0-9_-]*):(?: .*)?", line) for line in direct]
        _h5_need(all(matches), "workflow_literal_mapping")
        keys = [match[1] for match in matches]
        allowed = {"if", "needs", "name", "runs-on", "timeout-minutes", "permissions",
                   "outputs", "steps", "env", "strategy"}
        _h5_need(len(keys) == len(set(keys)) and set(keys) <= allowed and
                 "    runs-on: ubuntu-24.04" in block.splitlines(), "workflow_runner_job_keys")
        expected = {"admission": "30", "source": "${{ matrix.minutes }}", "final": "10"}[name]
        _h5_need("    timeout-minutes: " + expected in block.splitlines(), "workflow_job_caps")
        expected_permissions = (["      contents: read", "      actions: read", "      pull-requests: read"]
                                if name == "admission" else ["      contents: read"])
        permissions = _h5_block("  " + name + ":\n" + block, "permissions", 4)
        _h5_need(permissions == expected_permissions, "workflow_job_permissions")
    _h5_need(text.count("      max-parallel: 3") == 1 and
             text.count("      fail-fast: false") == 1, "workflow_matrix_policy")
    _h5_need(_h5_block("  source:\n" + "\n".join(_h5_block(text, "source", 2)),
                      "strategy", 4) == ["      fail-fast: false", "      max-parallel: 3",
                      "      matrix: ${{ fromJSON(needs.admission.outputs.matrix) }}"],
             "workflow_matrix_policy")
    refs = re.findall(r"(?m)^          ref: ([0-9a-f]{40})$", text)
    _h5_need(refs == [source_sha, source_sha], "workflow_source_refs")
    _h5_need(re.findall(r"(?m)^\s*persist-credentials:\s*([^\n]+)$", text) ==
             ["false"] * 5, "workflow_credentials")
    uses = re.findall(r"(?m)^\s*-?\s*uses: ([^\n#]+)", text)
    _h5_need(len(uses) == 6 and all(value.strip() in (
             "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
             "actions/setup-node@820762786026740c76f36085b0efc47a31fe5020") for value in uses),
             "workflow_fixed_actions")
    _h5_need("secrets." not in text and text.count("${{ github.token }}") == 1 and
             text.count("          GH_SOURCE_READ_TOKEN: ${{ github.token }}") == 1,
             "workflow_token_surface")
    return {"runner": "ubuntu-24.04", "permissions": "read-only",
            "trigger": "same-repository-draft-pr28", "parallel": 3,
            "caps": {"admission": 30, "final": 10, "profileMaximum": 90},
            "sourceRefs": 2, "fixedActions": 6}


def _h5_branch_history(api):
    route = ("/repos/" + REPOSITORY + "/actions/runs?branch=task%2Fv107-source-binding"
             "&created=%3E%3D2026-10-28T00%3A03%3A19Z&per_page=100&page=")
    first = api(route + "1")
    _h5_need(type(first) is dict and type(first.get("total_count")) is int and
             0 <= first["total_count"] <= V5_HISTORY_MAX_RUNS, "branch_page")
    total, rows = first["total_count"], []
    for page in range(1, max(1, math.ceil(total / 100)) + 1):
        response = first if page == 1 else api(route + str(page))
        _h5_need(type(response) is dict and type(response.get("total_count")) is int and
                 response["total_count"] == total and type(response.get("workflow_runs")) is list and
                 len(response["workflow_runs"]) == min(100, max(0, total - (page - 1) * 100)),
                 "branch_pagination")
        rows.extend(response["workflow_runs"])
    ids = [row.get("id") for row in rows if type(row) is dict]
    _h5_need(len(ids) == total and all(type(i) is int and i > 0 for i in ids) and
             len(set(ids)) == total, "branch_unique_ids")
    return {str(row["id"]): row for row in rows}


def observed_minutes_v5(table, expected, budget):
    """Measure terminal source jobs using the original request's exact clock policy."""
    _h5_need(type(table) is dict and type(table.get("total_count")) is int and
             type(table.get("jobs")) is list and table["total_count"] == len(table["jobs"]) <= 100,
             "terminal_jobs_complete")
    _h5_need(type(expected) is list and bool(expected) and len(set(expected)) == len(expected) and
             all(p in budget["profileMinutes"] for p in expected), "terminal_profiles")
    limits = {"admission": budget["admissionMinutes"], "final": budget["finalMinutes"],
              "source": 0, "source (${{ matrix.profile }})": 0,
              **{"source (" + p + ")": budget["profileMinutes"][p] for p in expected}}
    ids, names, minutes, admitted = set(), set(), 0, False
    for job in table["jobs"]:
        _h5_need(type(job) is dict and type(job.get("id")) is int and job["id"] > 0 and
                 job["id"] not in ids and type(job.get("name")) is str and job["name"] in limits and
                 job["name"] not in names and job.get("status") == "completed" and
                 type(job.get("run_attempt")) is int and job["run_attempt"] == 1 and
                 job.get("conclusion") in V5_TERMINAL_CONCLUSIONS, "terminal_job_identity")
        ids.add(job["id"]);names.add(job["name"])
        if job["name"] == "admission":
            admitted = job["conclusion"] == "success"
        unacquired = "runner_id" in job and (job["runner_id"] is None or
                         type(job["runner_id"]) is int and job["runner_id"] == 0)
        if job["conclusion"] in ("skipped", "cancelled") and unacquired:
            _h5_need("runner_name" in job and job["runner_name"] in (None, "") and
                     type(job.get("steps")) is list and not job["steps"], "terminal_unacquired_evidence")
            continue
        _h5_need(type(job.get("runner_id")) is int and job["runner_id"] > 0 and
                 type(job.get("runner_name")) is str and bool(job["runner_name"]) and
                 job.get("runner_group_name") == "GitHub Actions" and job.get("labels") == ["ubuntu-24.04"],
                 "terminal_public_runner")
        seconds = (timestamp(job["completed_at"]) - timestamp(job["started_at"])).total_seconds()
        _h5_need(0 <= seconds <= (limits[job["name"]] + 1) * 60, "terminal_job_duration")
        minutes += math.ceil(seconds / 60)
    _h5_need({"admission", "final"} <= names, "terminal_boundary_jobs")
    if admitted:
        _h5_need(names == {"admission", "final", *["source (" + p + ")" for p in expected]},
                 "terminal_admitted_profiles")
    _h5_need(minutes <= budget["roundMaximumMinutes"], "terminal_round_booking")
    return minutes


def _h5_prefix(pipeline, request, history):
    raw = (pipeline / V5_SETTLED_USAGE_PATH).read_bytes()
    _h5_need(hashlib.sha256(raw).hexdigest() == request["settledUsageSha256"] == V5_BASELINE_SHA256,
             "prefix_digest")
    prefix = read_json(raw)
    fields = {"schema", "repository", "campaignId", "closedAt", "runnerMinutesObserved", "runCount",
              "previousPrefixSha256", "previousPrefixRunCount", "previousPrefixMinutes",
              "previousPrefixPipeline", "previousArtifactSnapshot", "currentArtifactSnapshot", "sourceRunIds", "runs"}
    _h5_need(type(prefix) is dict and set(prefix) == fields and
             prefix["schema"] == "openclaw.v108.closed-source-usage.v3" and
             prefix["repository"] == REPOSITORY and prefix["campaignId"] == V5_CAMPAIGN and
             type(prefix["runs"]) is list and len(prefix["runs"]) == V5_PRIOR_RUNS and
             type(prefix["runCount"]) is int and prefix["runCount"] == V5_PRIOR_RUNS and
             type(prefix["runnerMinutesObserved"]) is int and prefix["runnerMinutesObserved"] == V5_PRIOR_MINUTES and
             prefix["sourceRunIds"] == list(V5_CLOSED_SOURCE_RUN_IDS) and
             prefix["previousPrefixSha256"] == V5_ORIGINAL_PREFIX_SHA256 and
             prefix["previousPrefixRunCount"] == 99 and prefix["previousPrefixMinutes"] == 886 and
             prefix["previousPrefixPipeline"] == V5_ORIGINAL_PREFIX_PIPELINE and
             prefix["previousArtifactSnapshot"] == {"count":9, "bytes":5600,
                 "proofSha256":"cf741734a6dcda5a6282e043fa8211dedf2670becb7b88ad195aaf6cf1ee9d51"} and
             prefix["currentArtifactSnapshot"] == {"count":13, "bytes":8090}, "prefix_envelope")
    _h5_need(type(prefix["closedAt"]) is str and
             re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}\+00:00", prefix["closedAt"]) is not None,
             "prefix_capture_timestamp")
    datetime.fromisoformat(prefix["closedAt"])
    ids, total, hashes = set(), 0, {}
    source_ids = set()
    for row in prefix["runs"]:
        _h5_need(type(row) is dict and set(V5_PROVIDER_RUN_HEADERS) <= set(row) and
                 set(row) <= set(V5_PROVIDER_RUN_HEADERS) | V5_PREFIX_DERIVED_FIELDS and
                 type(row.get("id")) is int and row["id"] > 0 and str(row["id"]) not in ids and
                 row["status"] == "completed" and row["conclusion"] in V5_TERMINAL_CONCLUSIONS and
                 type(row["run_attempt"]) is int and row["run_attempt"] == 1 and
                 type(row.get("jobs")) is list and
                 ("artifactRows" not in row or type(row["artifactRows"]) is list), "prefix_run_projection")
        rid = str(row["id"]);ids.add(rid)
        live = history.get(rid, {})
        _h5_need(_h5_public(live) and all(type(live.get(key)) is type(row[key]) and
                 live.get(key) == row[key] for key in V5_PROVIDER_RUN_HEADERS), "prefix_header_changed")
        # Only immutable historical projections omit per-job attempt. The hashed
        # parent run positively binds attempt1; live tables never get a default.
        jobs = []
        for item in row["jobs"]:
            _h5_need(type(item) is dict and ("run_attempt" not in item or
                     type(item["run_attempt"]) is int and item["run_attempt"] == 1), "prefix_job_attempt")
            jobs.append(dict(item, run_attempt=1))
        table = {"total_count":len(jobs), "jobs":jobs}
        if row["path"] != WORKFLOW or rid in V5_CLOSED_SOURCE_RUN_IDS[:3]:
            measured = observed_minutes(table, list(LEGACY_PROFILE_MINUTES) if row["path"] == WORKFLOW else None,
                                        legacy=True)
        else:
            source_ids.add(rid)
            version = ("openclaw.fork-source-validation-request.v4" if rid in V5_CLOSED_SOURCE_RUN_IDS[-2:]
                       else "openclaw.fork-source-validation-request.v3")
            record = {"schema":version}
            if version.endswith("v4"):
                record["profilePolicy"] = "five-gate-repair-v1"
            budget = validation_budget_for_record_v5(record)
            measured = observed_minutes_v5(table, list(budget["profileMinutes"]), budget)
        if row["path"] == WORKFLOW:
            source_ids.add(rid)
        _h5_need(type(row.get("observedRunnerMinutes")) is int and
                 measured == row["observedRunnerMinutes"], "prefix_job_minutes")
        total += measured
        hashes[rid] = hashlib.sha256(json.dumps(row["jobs"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    _h5_need(len(ids) == V5_PRIOR_RUNS and total == V5_PRIOR_MINUTES and
             source_ids == set(V5_CLOSED_SOURCE_RUN_IDS), "prefix_actual141_928")
    return raw, prefix, ids, hashes


def _h5_previous_stage(request, history, current, head, pipeline, api):
    pins = V5_STAGE_RUN_PINS
    _h5_need(type(pins) is list and len(pins) == request["stageRound"] and all(type(p) is dict and
             set(p) == {"runId", "pipelineHead", "requestSha256"} and
             type(p["runId"]) is str and V5_RUN_ID.fullmatch(p["runId"]) and
             type(p["pipelineHead"]) is str and V5_SHA.fullmatch(p["pipelineHead"]) and
             type(p["requestSha256"]) is str and V5_SHA256.fullmatch(p["requestSha256"]) for p in pins),
             "genuine_stage_controls_required")
    _h5_need([p["runId"] for p in pins] == request["priorRunIds"][7:] and
             len({p["pipelineHead"] for p in pins}) == len(pins), "stage_control_ids")
    latest, receipts, total, previous_hops = {}, [], 0, []
    for number, pin in enumerate(pins):
        run = history[pin["runId"]]
        _h5_need(run["status"] == "completed" and run["conclusion"] in V5_TERMINAL_CONCLUSIONS and
                 run["head_sha"] == pin["pipelineHead"] and
                 timestamp(V5_STAGE_ORIGIN) <= timestamp(run["created_at"]) <= timestamp(current["created_at"]),
                 "prior_stage_terminal")
        raw = content_at(api, REQUEST, pin["pipelineHead"])
        _h5_need(hashlib.sha256(raw).hexdigest() == pin["requestSha256"], "prior_stage_request_digest")
        old = read_json(raw)
        # The reviewed publication/run/request pin authenticates these historical
        # source controls. The current source chain may extend, never retcon them.
        _h5_need(type(old) is dict and type(old.get("sourceWitness")) is dict and
                 type(old["sourceWitness"].get("correctionHops")) is list, "prior_stage_request_shape")
        hops = old["sourceWitness"]["correctionHops"]
        prior_pins = dict(V5_STAGE_PINS, sourceSha=old.get("sourceSha"), sourceTree=old.get("sourceTree"),
            manifestSha256=old.get("manifestSha256"), inventorySha256=old.get("inventorySha256"),
            priorRunIds=request["priorRunIds"][:7+number],
            sourceHops=[{"sourceSha":h.get("sourceSha"), "sourceTree":h.get("sourceTree")} for h in hops
                        if type(h) is dict], previousSourceHopCount=len(previous_hops))
        old = validate_request_v5(old, prior_pins)
        _h5_need(old["stageRound"] == number and hops[:len(previous_hops)] == previous_hops and
                 request["sourceWitness"]["correctionHops"][:len(hops)] == hops,
                 "prior_stage_source_chain")
        # A source change invalidates affected prior-source evidence even when
        # this run fails before expansion. Only genuine new results restore it.
        invalidated = set()
        for hop in hops[len(previous_hops):]:
            invalidated.update(v5_required_correction_profiles(hop["step"]["changedPaths"]))
        for profile in invalidated:
            latest.pop(profile, None)
        unresolved_before = {p for p in V5_PROFILES if latest.get(p) != "success"}
        _h5_need(unresolved_before <= set(old["profiles"]), "prior_stage_unresolved_selected")
        workflow_security_v5(content_at(api, WORKFLOW, pin["pipelineHead"]), old["sourceSha"])
        git(pipeline, "merge-base", "--is-ancestor", pin["pipelineHead"], head)
        table = _h5_jobs(api, run)
        minutes = observed_minutes_v5(table, old["profiles"], validation_budget_for_record_v5(old))
        results = {j["name"][8:-1]:j["conclusion"] for j in table["jobs"]
                   if j["name"].startswith("source (") and j["name"].endswith(")") and
                   j["name"][8:-1] in old["profiles"]}
        unexpanded = _h5_unexpanded_failed_initial(table["jobs"])
        _h5_need(bool(results) or unexpanded, "prior_stage_unexpanded_positive_evidence")
        latest.update(results);total += minutes;previous_hops = hops
        receipts.append({"runId":pin["runId"], "pipelineHead":pin["pipelineHead"],
            "requestSha256":pin["requestSha256"], "sourceSha":old["sourceSha"], "sourceTree":old["sourceTree"],
            "observedRunnerMinutes":minutes, "profileResults":results, "conclusion":run["conclusion"],
            "unresolvedProfiles":sorted(p for p in V5_PROFILES if latest.get(p) != "success"),
            "initialValidationNeverStarted":unexpanded, "invalidatedPriorProfiles":sorted(invalidated),
            "relabeledAsCurrentSourcePass":False})
    _h5_need(V5_STAGE_PINS["previousSourceHopCount"] == len(previous_hops), "previous_source_hop_count")
    unresolved = {p for p in V5_PROFILES if latest.get(p) != "success"}
    _h5_need(unresolved <= set(request["profiles"]), "unresolved_prior_profiles_selected")
    return total, receipts, latest, sorted(unresolved)


def history_checks_v5(request, event, env, pipeline, api):
    request = validate_request_v5(request, V5_STAGE_PINS)
    head = validate_event(event, env)
    now = datetime.now(timezone.utc)
    _h5_need(now < timestamp(V5_DEADLINE), "deadline")
    live = api("/repos/" + REPOSITORY + "/pulls/28")
    _h5_need(validate_event(dict(event, pull_request=live), env) == head, "live_pr_changed")
    target = api("/repos/" + REPOSITORY + "/git/ref/heads/" + BASE_BRANCH)
    _h5_need(target.get("ref") == "refs/heads/" + BASE_BRANCH and
             target.get("object", {}).get("type") == "commit" and
             target["object"].get("sha") == TARGET_BRANCH_TIP, "target_tip")
    source_ref = api("/repos/" + REPOSITORY + "/git/ref/heads/" + V5_SOURCE_BRANCH)
    _h5_need(source_ref.get("ref") == "refs/heads/" + V5_SOURCE_BRANCH and
             source_ref.get("object", {}).get("type") == "commit" and
             source_ref["object"].get("sha") == request["sourceSha"], "source_branch_tip")
    history = _h5_branch_history(api)
    raw, prefix, prefix_ids, hashes = _h5_prefix(pipeline, request, history)
    reused = validate_reused_profile_evidence_v5(raw, lambda *args: git(pipeline, *args))
    expected = [*request["priorRunIds"], env["GITHUB_RUN_ID"]]
    actual = {rid for rid, run in history.items() if run.get("path") == WORKFLOW}
    _h5_need(actual == set(expected) and len(expected) == len(set(expected)), "source_round_set")
    for rid in actual:
        run = history[rid]
        _h5_need(_h5_public(run) and run.get("event") == "pull_request" and
                 type(run.get("run_attempt")) is int and run["run_attempt"] == 1 and
                 run.get("head_branch") == BRANCH and run.get("display_title") == CAMPAIGN and
                 [pr.get("number") for pr in run.get("pull_requests", [])] == [28], "source_run_binding")
    current = history[env["GITHUB_RUN_ID"]]
    _h5_need(current.get("head_sha") == head and current.get("status") == "in_progress" and
             timestamp(V5_STAGE_ORIGIN) <= timestamp(current["created_at"]) <= now, "current_source_identity")
    for rid in V5_CLOSED_SOURCE_RUN_IDS:
        git(pipeline, "merge-base", "--is-ancestor", history[rid]["head_sha"], head)
    workflow = workflow_security_v5((pipeline / WORKFLOW).read_bytes(), request["sourceSha"])
    previous_minutes, receipts, results, unresolved = _h5_previous_stage(request, history, current, head, pipeline, api)
    current_jobs = _h5_jobs(api, current)
    admission = [j for j in current_jobs["jobs"] if j.get("name") == "admission"]
    _h5_need(len(admission) == 1 and admission[0].get("status") == "in_progress" and
             type(admission[0].get("runner_id")) is int and admission[0]["runner_id"] > 0 and
             admission[0].get("runner_group_name") == "GitHub Actions" and
             admission[0].get("labels") == ["ubuntu-24.04"] and
             type(admission[0].get("runner_name")) is str and bool(admission[0]["runner_name"]),
             "current_public_admission")
    current_facts = ancillary_job_snapshot(current_jobs, now, False)
    allowed_current = {"admission", "final", "source (${{ matrix.profile }})",
                       *["source (" + p + ")" for p in request["profiles"]]}
    _h5_need(all(j.get("name") in allowed_current for j in current_jobs["jobs"]) and
             current_facts["observedAcquiredRunnerMinutes"] <= V5_ADMISSION_MINUTES,
             "current_job_booking")
    paths = {row["path"] for row in prefix["runs"] if row["path"] != WORKFLOW}
    heads = {row["head_sha"] for row in prefix["runs"]} | {head}
    heads.update(pin["pipelineHead"] for pin in V5_STAGE_RUN_PINS)
    observed, ancillary, pending = 0, [], []
    artifact_bytes, artifact_records, artifact_ids = 8090, [], set()
    for rid, run in sorted(history.items()):
        if rid in prefix_ids:
            continue
        if run.get("path") != WORKFLOW:
            _h5_need(_h5_public(run) and run.get("event") in ("pull_request", "pull_request_target") and
                     run.get("path") in paths and run.get("head_sha") in heads and
                     type(run.get("run_attempt")) is int and run["run_attempt"] == 1 and
                     run.get("head_branch") == BRANCH and
                     run.get("status") in ("completed", "in_progress", "queued", "waiting", "pending") and
                     (run["status"] != "completed" or run.get("conclusion") in V5_TERMINAL_CONCLUSIONS),
                     "new_ancillary_binding")
            facts = ancillary_job_snapshot(_h5_jobs(api, run), now, run["status"] == "completed")
            observed += facts["observedAcquiredRunnerMinutes"]
            ancillary.append({"runId":rid, **facts})
            if not facts["usageComplete"]:
                pending.append(rid)
        artifacts = _h5_artifacts(api, run)
        _h5_need(not artifact_ids.intersection(artifacts["ids"]), "artifact_duplicate")
        artifact_ids.update(artifacts["ids"]);artifact_bytes += artifacts["bytes"]
        artifact_records.append({"runId":rid, **artifacts})
    _h5_need(observed <= V5_ANCILLARY_MINUTES and
             (not pending or observed < V5_ANCILLARY_MINUTES), "ancillary90_exceeded")
    _h5_need(artifact_bytes <= V5_DIAGNOSTIC_BYTES, "artifact_storage_bound")
    policy = validation_budget_for_record_v5(request)
    planned = policy["admissionMinutes"] + policy["finalMinutes"] + sum(policy["profileMinutes"][p] for p in request["profiles"])
    reserve = (V5_MAX_CORRECTIONS - request["stageRound"]) * V5_ROUND_MINUTES
    stage_booked = previous_minutes + planned + reserve + V5_ANCILLARY_MINUTES
    booked = V5_PRIOR_MINUTES + stage_booked
    _h5_need(stage_booked <= V5_STAGE_MINUTES and booked <= V5_OVERALL_MINUTES, "stage1650_lifetime18000_exceeded")
    return {"bookedRunnerMinutes":booked, "actualSettledRunnerMinutes":V5_PRIOR_MINUTES,
        "observedNewPriorRunnerMinutes":previous_minutes, "currentRoundBookedMinutes":planned,
        "futureTargetedReserveMinutes":reserve, "operatorRoundsRemaining":V5_MAX_CORRECTIONS-request["stageRound"],
        "stageBookedAdditionalRunnerMinutes":stage_booked, "observedNewAncillaryRunnerMinutes":observed,
        "newAncillaryRemainingReserveMinutes":V5_ANCILLARY_MINUTES-observed,
        "newAncillaryRecords":ancillary, "pendingAncillaryRunIds":pending,
        "ancillaryUsageComplete":not pending, "ancillaryReservationBookedMinutes":V5_ANCILLARY_MINUTES,
        "ancillaryWaitPerformed":False, "artifactRecords":artifact_records,
        "observedRetainedWorkflowArtifactBytes":artifact_bytes,
        "closedArtifactBaselineProof":prefix["currentArtifactSnapshot"],
        "closedPrefixHeaderFields":list(V5_PROVIDER_RUN_HEADERS),
        "artifactObservationComplete":all(a["observationComplete"] for a in artifact_records),
        "artifactBudgetIsNotWholeDiagnosticCustodyProof":True, "campaignRunnerMinuteCeiling":V5_OVERALL_MINUTES,
        "deadlineEpoch":int(timestamp(V5_DEADLINE).timestamp()), "firstSourceReceipts":receipts,
        "firstSourceReceipt":receipts[0] if receipts else None, "priorStageProfileResults":results,
        "priorUnresolvedProfiles":unresolved, "reusedProfileEvidence":reused, "historicalJobTableSha256":hashes,
        "profileMatrix":[{"profile":p,"minutes":V5_PROFILE_MINUTES[p]} for p in request["profiles"]],
        "selectedProfileCount":len(request["profiles"]), "reusedProfileCount":len(reused["profiles"]),
        "currentAdmissionObservation":current_facts, "workflowSecurity":workflow,
        "historicalConclusionsRetained":True, "productionAuthorized":False, "imageBuilt":False}


"""Inline donor caller fragment; root owns integration and V5 runtime contracts.

Requires existing driver imports/helpers, V5_SCHEMA, and the runtime owner's
version-aware optional-request identity/deadline APIs. Has no standalone CLI.
"""

DONOR_NEED_CODES = {'donor.alternates_forbidden': 'need.source_donor_alternates_forbidden', 'donor.canonical_directory': 'need.source_donor_canonical_directory', 'donor.commit_set': 'need.source_donor_commit_set', 'donor.commit_type': 'need.source_donor_commit_type', 'donor.common_directory': 'need.source_donor_common_directory', 'donor.config_unavailable': 'need.source_donor_config_unavailable', 'donor.current_schema': 'need.source_donor_current_schema', 'donor.directory_owner': 'need.source_donor_directory_owner', 'donor.fixed_roots': 'need.source_donor_fixed_roots', 'donor.git_root': 'need.source_donor_git_root', 'donor.identity_shape': 'need.source_donor_identity_shape', 'donor.independent_git_directory': 'need.source_donor_independent_git_directory', 'donor.object_directory': 'need.source_donor_object_directory', 'donor.object_file': 'need.source_donor_object_file', 'donor.object_symlink': 'need.source_donor_object_symlink', 'donor.origin': 'need.source_donor_origin', 'donor.owned_directory': 'need.source_donor_owned_directory', 'donor.partial_clone': 'need.source_donor_partial_clone', 'donor.pipeline_head': 'need.source_donor_pipeline_head', 'donor.promisor_pack': 'need.source_donor_promisor_pack', 'donor.request_binding': 'need.source_donor_request_binding', 'donor.service_workspace': 'need.source_donor_service_workspace', 'donor.shallow': 'need.source_donor_shallow', 'donor.shared_object_inode': 'need.source_donor_shared_object_inode', 'donor.source_clean': 'need.source_donor_source_clean', 'donor.source_identity': 'need.source_donor_source_identity', 'donor.tree_type': 'need.source_donor_tree_type', 'donor.uri_stability': 'need.source_donor_uri_stability', 'donor.validated_event': 'need.source_donor_validated_event', 'donor.worktree_root': 'need.source_donor_worktree_root'}
ADMISSION_NEED_CODES.update(DONOR_NEED_CODES)

def local_closure_donor_uri(workspace, pipeline, source, pipeline_head, source_sha, source_tree, commits, read_git):
    """Call before AND after the owned fetch with trusted request identities.

    read_git must retain the caller's shared deadline and minimal no-lazy Git
    environment. Expected identities must not be inferred from the checkouts.
    """
    def require(condition, code):
        if not condition:
            need(False, code)

    workspace, pipeline, source = map(Path, (workspace, pipeline, source))
    for path in (workspace, pipeline, source):
        require(path.is_dir() and not path.is_symlink(), "donor.owned_directory")
        require(path.resolve() == path.absolute(), "donor.canonical_directory")
        require(path.stat().st_uid == os.geteuid(), "donor.directory_owner")
    require(pipeline == workspace / "pipeline" and source == workspace / "source" and
            pipeline != source, "donor.fixed_roots")
    require(all(type(value) is str and re.fullmatch(r"[0-9a-f]{40}", value) is not None
                for value in (pipeline_head, source_sha, source_tree)), "donor.identity_shape")
    require(type(commits) is list and 0 < len(commits) <= 16 and commits == sorted(set(commits)) and
            all(re.fullmatch(r"[0-9a-f]{40}", c) is not None for c in commits), "donor.commit_set")
    object_inodes = set()
    for root in (pipeline, source):
        git_dir = root / ".git"
        require(git_dir.is_dir() and not git_dir.is_symlink() and git_dir.resolve() == git_dir,
                "donor.independent_git_directory")
        require(not (git_dir / "commondir").exists() and not (git_dir / "commondir").is_symlink(),
                "donor.common_directory")
        require(read_git(root, "rev-parse", "--show-toplevel").strip() == str(root).encode(), "donor.worktree_root")
        require(read_git(root, "rev-parse", "--absolute-git-dir").strip() == str(git_dir).encode(), "donor.git_root")
        require(read_git(root, "rev-parse", "--path-format=absolute", "--git-common-dir").strip() ==
                str(git_dir).encode(), "donor.common_directory")
        objects = git_dir / "objects"
        require(objects.is_dir() and not objects.is_symlink() and objects.resolve() == objects,
                "donor.object_directory")
        require(read_git(root, "rev-parse", "--path-format=absolute", "--git-path", "objects").strip() ==
                str(objects).encode(), "donor.object_directory")
        for name in ("alternates", "http-alternates"):
            alternate = objects / "info" / name
            require(not alternate.exists() and not alternate.is_symlink(), "donor.alternates_forbidden")
        for directory, names, files in os.walk(objects, followlinks=False):
            for name in names + files:
                path = Path(directory) / name
                require(not path.is_symlink() and path.resolve() == path, "donor.object_symlink")
                if name in files:
                    require(path.is_file(), "donor.object_file")
                    stat = path.stat()
                    inode = (stat.st_dev, stat.st_ino)
                    require(stat.st_nlink == 1 and inode not in object_inodes, "donor.shared_object_inode")
                    object_inodes.add(inode)
        try:
            read_git(root, "config", "--get-regexp", r"^(extensions\.partialclone|remote\..*\.promisor)$")
        except subprocess.CalledProcessError as error:
            require(error.returncode == 1, "donor.config_unavailable")
        else:
            need(False, "donor.partial_clone")
        require(not list((objects / "pack").glob("*.promisor")), "donor.promisor_pack")
        require(read_git(root, "remote", "get-url", "origin").strip() in
                (b"https://github.com/fr-meyer/openclaw", b"https://github.com/fr-meyer/openclaw.git"), "donor.origin")
    require(read_git(pipeline, "rev-parse", "HEAD").strip() == pipeline_head.encode(), "donor.pipeline_head")
    require(read_git(source, "rev-parse", "HEAD").strip() == source_sha.encode() and
            read_git(source, "rev-parse", "HEAD^{tree}").strip() == source_tree.encode(), "donor.source_identity")
    require(read_git(source, "status", "--porcelain=v1", "--untracked-files=all").strip() == b"",
            "donor.source_clean")
    require(read_git(pipeline, "rev-parse", "--is-shallow-repository").strip() == b"false", "donor.shallow")
    for commit in commits:
        require(read_git(pipeline, "cat-file", "-t", commit).strip() == b"commit", "donor.commit_type")
        require(read_git(pipeline, "cat-file", "-t", commit + "^{tree}").strip() == b"tree", "donor.tree_type")
    return pipeline.as_uri()

def fetch_closure_historical(pipeline, source, request=None, env=None):
    """CI only: one explicit product ancestry fetch plus one pinned annotated tag."""
    found, manifest, manifest_hash = metadata(pipeline)
    if request is None:
        request = found
    else:
        _v4_need(found == request, "v4.runtime_closure_request")
    source_sha, _ = source_identity_for(request)
    env = os.environ if env is None else env
    profile = "admission" if env.get("GITHUB_JOB") == "admission" else env.get("SOURCE_PROFILE")
    deadline = (admission_deadline(env, request) if profile == "admission" else
                profile_deadline(env, profile, request))
    closure_remaining(deadline)
    inventory, _ = preflight.inventory_at(pipeline / CANDIDATE / "patch-inventory.json",
                                         manifest, manifest_hash)
    safe_env = {"PATH": env["PATH"], "GIT_TERMINAL_PROMPT": "0", "GIT_NO_LAZY_FETCH": "1",
                "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}
    def inspect(*args):
        return subprocess.check_output(["git", "-C", str(source), *args], env=safe_env,
            timeout=closure_remaining(deadline), stderr=subprocess.DEVNULL).strip()
    commits = preflight.history_commits(inventory, manifest)
    need(type(commits) is list and 0 < len(commits) <= 16 and commits == sorted(set(commits)) and
         source_sha in commits and all(release.matches(release.SHA, commit) for commit in commits),
         "bounded exact source closure commits")
    shallow = inspect("rev-parse", "--is-shallow-repository")
    need(shallow in (b"true", b"false"), "source shallow state")
    need(inventory["upstream"]["tag"] == "v2026.10.8" and
         release.matches(release.SHA, inventory["upstream"]["tagObject"]) and
         release.matches(release.SHA, inventory["upstream"]["commit"]), "pinned annotated upstream tag")
    context = {"profile": profile, "deadlineEpoch": deadline, "request": request}
    def acquire(url, refs, ordinal, unshallow=False):
        closure_remaining(deadline)
        argv = ["git", "-C", str(source), "-c", "credential.helper=", "-c", "maintenance.auto=0",
                "-c", "gc.auto=0", "fetch", "--quiet", "--no-tags",
                *(["--unshallow"] if unshallow else []), url, *refs]
        result = phase_process(argv, source, safe_env, context, "source-closure", ordinal)
        need(result.returncode == 0 and not result.timed_out, "exact source closure fetch failed")
    with profile_signals():
        # Fetch even present objects: a checkout's existingF5 shallow boundary is
        # not proof that any required parent ancestry has been acquired.
        acquire("https://github.com/fr-meyer/openclaw.git", commits, 0, shallow == b"true")
        need(inspect("rev-parse", "--is-shallow-repository") == b"false",
             "source closure remains shallow")
        for commit in commits:
            need(inspect("cat-file", "-t", commit) == b"commit", "source closure commit type")
        acquire("https://github.com/openclaw/openclaw.git", ["refs/tags/v2026.10.8"], 1)
        tag = inventory["upstream"]["tagObject"]
        need(inspect("rev-parse", "FETCH_HEAD") == tag.encode() and
             inspect("cat-file", "-t", tag) == b"tag" and
             inspect("rev-parse", tag + "^{commit}") == inventory["upstream"]["commit"].encode(),
             "exact annotated upstream tag binding")
        closure_remaining(deadline)
        source_preflight(pipeline, source, manifest, manifest_hash)
        closure_remaining(deadline)

def fetch_closure(pipeline, source, request=None, env=None, event=None):
    """One owned donor fetch, then official tag fetch or exact V7 target fixture.

    Historical helper routing is reachable only from metadata explicitly supplying
    a historical request. Operational metadata/command reject those versions.
    """
    found, manifest, manifest_hash = metadata(pipeline)
    if request is None:
        request = found
    else:
        need(found == request, "donor.request_binding")
    need(type(request) is dict, "donor.current_schema")
    if request.get("schema") in ("openclaw.fork-source-validation-request.v3",
                                  "openclaw.fork-source-validation-request.v4"):
        return fetch_closure_historical(pipeline, source, request=request, env=env)
    need(request.get("schema") in (V5_SCHEMA, V6_SCHEMA, R7_SCHEMA, R8_SCHEMA), "donor.current_schema")
    env = os.environ if env is None else env
    need(type(event) is dict, "donor.validated_event")
    pipeline_head = validate_event(event, env)
    source_sha, source_tree = source_identity_for(request)
    profile = "admission" if env.get("GITHUB_JOB") == "admission" else env.get("SOURCE_PROFILE")
    deadline = (admission_deadline(env, request) if profile == "admission" else
                profile_deadline(env, profile, request))
    closure_remaining(deadline)
    inventory, _ = preflight.inventory_at(pipeline / CANDIDATE / "patch-inventory.json",
                                         manifest, manifest_hash)
    safe_env = {"PATH": env["PATH"], "GIT_TERMINAL_PROMPT": "0", "GIT_NO_LAZY_FETCH": "1",
                "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}
    def inspect(root, *args):
        return subprocess.check_output(["git", "--no-replace-objects", "-C", str(root), *args],
            env=safe_env, timeout=closure_remaining(deadline), stderr=subprocess.DEVNULL).strip()
    commits = preflight.history_commits(inventory, manifest)
    need(type(commits) is list and 0 < len(commits) <= 16 and commits == sorted(set(commits)) and
         source_sha in commits and all(release.matches(release.SHA, commit) for commit in commits),
         "bounded exact source closure commits")
    if request.get("schema") == R8_SCHEMA:
        validate_request_v8(request, R8_STAGE_PINS)
        _r8_need(len(commits) == 12 and R8_SOURCE in commits and R8_BASE_SOURCE in commits,
            "r8.complete_twelve_commit_closure")
    shallow = inspect(source, "rev-parse", "--is-shallow-repository")
    need(shallow in (b"true", b"false"), "source shallow state")
    need(inventory["upstream"]["tag"] == "v2026.10.8" and
         release.matches(release.SHA, inventory["upstream"]["tagObject"]) and
         release.matches(release.SHA, inventory["upstream"]["commit"]), "pinned annotated upstream tag")
    workspace_value = env.get("GITHUB_WORKSPACE")
    need(type(workspace_value) is str and Path(workspace_value).is_absolute(), "donor.service_workspace")
    workspace = Path(workspace_value)
    context = {"profile": profile, "deadlineEpoch": deadline, "request": request}
    def acquire(url, refs, ordinal, unshallow=False, donor=False):
        closure_remaining(deadline)
        argv = ["git", "--no-replace-objects", "-C", str(source), "-c", "credential.helper=",
                "-c", "maintenance.auto=0", "-c", "gc.auto=0",
                *(["-c", "protocol.allow=never", "-c", "protocol.file.allow=always"] if donor else []),
                "fetch", "--quiet", "--no-tags", *( ["--unshallow"] if unshallow else []), url, *refs]
        result = phase_process(argv, source, safe_env, context, "source-closure", ordinal)
        need(result.returncode == 0 and not result.timed_out, "exact source closure fetch failed")
    with profile_signals():
        donor_uri = local_closure_donor_uri(workspace, pipeline, source, pipeline_head,
                                           source_sha, source_tree, commits, inspect)
        acquire(donor_uri, commits, 0, shallow == b"true", donor=True)
        need(inspect(source, "rev-parse", "--is-shallow-repository") == b"false",
             "source closure remains shallow")
        need(local_closure_donor_uri(workspace, pipeline, source, pipeline_head,
                                     source_sha, source_tree, commits, inspect) == donor_uri,
             "donor.uri_stability")
        for commit in commits:
            need(inspect(source, "cat-file", "-t", commit) == b"commit", "source closure commit type")
        if request.get("schema") == R8_SCHEMA:
            reuse_upstream_tag_v8(pipeline, source, request, inventory, inspect, safe_env, context)
        elif request.get("schema") == R7_SCHEMA and request.get("stageRound") == 2:
            reuse_upstream_tag_v7(pipeline, source, request, inventory, inspect, safe_env, context)
        else:
            acquire("https://github.com/openclaw/openclaw.git", ["refs/tags/v2026.10.8"], 1)
            tag = inventory["upstream"]["tagObject"]
            need(inspect(source, "rev-parse", "FETCH_HEAD") == tag.encode() and
                 inspect(source, "cat-file", "-t", tag) == b"tag" and
                 inspect(source, "rev-parse", tag + "^{commit}") == inventory["upstream"]["commit"].encode(),
                 "exact annotated upstream tag binding")
        closure_remaining(deadline)
        source_preflight(pipeline, source, manifest, manifest_hash)
        closure_remaining(deadline)


# Fixed reviewed history reasons; no provider or exception text becomes a public code.
ADMISSION_NEED_CODES.update({'v5.history.ancillary90_exceeded': 'v5.history.ancillary90_exceeded',
 'v5.history.artifact_duplicate': 'v5.history.artifact_duplicate',
 'v5.history.artifact_identity_size': 'v5.history.artifact_identity_size',
 'v5.history.artifact_storage_bound': 'v5.history.artifact_storage_bound',
 'v5.history.artifacts_complete': 'v5.history.artifacts_complete',
 'v5.history.branch_page': 'v5.history.branch_page',
 'v5.history.branch_pagination': 'v5.history.branch_pagination',
 'v5.history.branch_unique_ids': 'v5.history.branch_unique_ids',
 'v5.history.current_job_booking': 'v5.history.current_job_booking',
 'v5.history.current_public_admission': 'v5.history.current_public_admission',
 'v5.history.current_source_identity': 'v5.history.current_source_identity',
 'v5.history.deadline': 'v5.history.deadline',
 'v5.history.fresh_job_binding': 'v5.history.fresh_job_binding',
 'v5.history.fresh_jobs_complete': 'v5.history.fresh_jobs_complete',
 'v5.history.genuine_stage_controls_required': 'v5.history.genuine_stage_controls_required',
 'v5.history.live_pr_changed': 'v5.history.live_pr_changed',
 'v5.history.new_ancillary_binding': 'v5.history.new_ancillary_binding',
 'v5.history.prefix_actual141_928': 'v5.history.prefix_actual141_928',
 'v5.history.prefix_capture_timestamp': 'v5.history.prefix_capture_timestamp',
 'v5.history.prefix_digest': 'v5.history.prefix_digest',
 'v5.history.prefix_envelope': 'v5.history.prefix_envelope',
 'v5.history.prefix_header_changed': 'v5.history.prefix_header_changed',
 'v5.history.prefix_job_attempt': 'v5.history.prefix_job_attempt',
 'v5.history.prefix_job_minutes': 'v5.history.prefix_job_minutes',
 'v5.history.prefix_run_projection': 'v5.history.prefix_run_projection',
 'v5.history.previous_source_hop_count': 'v5.history.previous_source_hop_count',
 'v5.history.prior_stage_request_digest': 'v5.history.prior_stage_request_digest',
 'v5.history.prior_stage_request_shape': 'v5.history.prior_stage_request_shape',
 'v5.history.prior_stage_source_chain': 'v5.history.prior_stage_source_chain',
 'v5.history.prior_stage_terminal': 'v5.history.prior_stage_terminal',
 'v5.history.prior_stage_unexpanded_positive_evidence': 'v5.history.prior_stage_unexpanded_positive_evidence',
 'v5.history.prior_stage_unresolved_selected': 'v5.history.prior_stage_unresolved_selected',
 'v5.history.source_branch_tip': 'v5.history.source_branch_tip',
 'v5.history.source_round_set': 'v5.history.source_round_set',
 'v5.history.source_run_binding': 'v5.history.source_run_binding',
 'v5.history.stage1650_lifetime18000_exceeded': 'v5.history.stage1650_lifetime18000_exceeded',
 'v5.history.stage_control_ids': 'v5.history.stage_control_ids',
 'v5.history.target_tip': 'v5.history.target_tip',
 'v5.history.terminal_admitted_profiles': 'v5.history.terminal_admitted_profiles',
 'v5.history.terminal_boundary_jobs': 'v5.history.terminal_boundary_jobs',
 'v5.history.terminal_job_duration': 'v5.history.terminal_job_duration',
 'v5.history.terminal_job_identity': 'v5.history.terminal_job_identity',
 'v5.history.terminal_jobs_complete': 'v5.history.terminal_jobs_complete',
 'v5.history.terminal_profiles': 'v5.history.terminal_profiles',
 'v5.history.terminal_public_runner': 'v5.history.terminal_public_runner',
 'v5.history.terminal_round_booking': 'v5.history.terminal_round_booking',
 'v5.history.terminal_unacquired_evidence': 'v5.history.terminal_unacquired_evidence',
 'v5.history.unresolved_prior_profiles_selected': 'v5.history.unresolved_prior_profiles_selected',
 'v5.history.workflow_block': 'v5.history.workflow_block',
 'v5.history.workflow_concurrency': 'v5.history.workflow_concurrency',
 'v5.history.workflow_credentials': 'v5.history.workflow_credentials',
 'v5.history.workflow_fixed_actions': 'v5.history.workflow_fixed_actions',
 'v5.history.workflow_job_caps': 'v5.history.workflow_job_caps',
 'v5.history.workflow_job_permissions': 'v5.history.workflow_job_permissions',
 'v5.history.workflow_jobs': 'v5.history.workflow_jobs',
 'v5.history.workflow_literal_mapping': 'v5.history.workflow_literal_mapping',
 'v5.history.workflow_matrix_policy': 'v5.history.workflow_matrix_policy',
 'v5.history.workflow_permissions': 'v5.history.workflow_permissions',
 'v5.history.workflow_runner_job_keys': 'v5.history.workflow_runner_job_keys',
 'v5.history.workflow_size': 'v5.history.workflow_size',
 'v5.history.workflow_source_refs': 'v5.history.workflow_source_refs',
 'v5.history.workflow_token_surface': 'v5.history.workflow_token_surface',
 'v5.history.workflow_top_level': 'v5.history.workflow_top_level',
 'v5.history.workflow_trigger': 'v5.history.workflow_trigger',
 'v5.history.workflow_yaml_shape': 'v5.history.workflow_yaml_shape'})


"""Closed npm-repair contract fragment for the maintained validation owner.

The coordinating owner supplies actual reviewed pins after CI derivation. This
file has no CLI, network, process, publication, or candidate-execution entrypoint.
It reuses the existing strict Git/ledger and workflow/job measurement owners.
"""

V6_SCHEMA = "openclaw.fork-source-validation-request.v6"
V6_POLICY = "npm-remediation-v1"
V6_AUTHORIZATION = "future-v108-npm-repair-20261029"
V6_CAMPAIGN = "future-v108-source-validation-20261027"
V6_DEADLINE = "2026-10-30T00:03:19Z"
V6_BASE_SOURCE = "84d9bd1c618708e9d5798a730d473ddecf99297a"
V6_BASE_TREE = "ca3ce016d7429e7ef42f6fed99b58f6c6ec623f4"
V6_PREVIOUS_PIPELINE = "d213bb593b3e618d459dde6767bc93f716ac8493"
V6_PREVIOUS_PREFIX_SHA256 = "b02f46b6c5404f33bf04a519190bc724843f901f3bd045ac47a82edaa845eb0d"
V6_BASELINE_SHA256 = "6f6043f0a6e733fd00ffb3dedc8d14d5c21c5da8ce1db96303b70d3d403c7382"
V6_PREVIOUS_PACKAGE_SHA256 = "289d42988293d8afd6a7ca133b0ffbbde7c0a466592dfe7b08565371bbcd60a4"
V6_PREVIOUS_LOCK_SHA256 = "bfaafb73d19b61f0b5124791c05ae8c65a7436f0d6c9ef1dd6f79358e9c35334"
V6_NPM_VERSION = "12.2.1"
V6_NPM_INTEGRITY = "sha512-bKCmFRVT/BB+YPEYbZwQ1XUI3N5t4xKSpU1MxOjo7z3iWzKBJ0ZXRC1xFdEN+TC7N5TdywaBzf2dMXGJq/e2PQ=="
V6_PROFILES = ("dependency", "types-production", "types-tests", "types-scripts",
    "workboard-1", "workboard-2", "models-1", "models-2", "sqlite", "doctor-1",
    "doctor-2", "doctor-3", "memory", "pipeline-contracts", "compatibility")
V6_PROFILE_MINUTES = dict(zip(V6_PROFILES,
    (60, 90, 90, 90, 60, 60, 60, 60, 60, 90, 45, 45, 60, 45, 60)))
V6_ADMISSION_MINUTES = 30
V6_FINAL_MINUTES = 10
V6_FULL_MINUTES = 1015
V6_TARGETED_MINUTES = 200
V6_PREPARATION_MINUTES = 45
V6_ANCILLARY_MINUTES = 77
V6_NEW_MINUTES = 1337
V6_PRIOR_MINUTES = 1237
V6_PRIOR_RUNS = 168
V6_PRIOR_SOURCE_IDS = ("40607329263", "40609889437", "40616416909", "40639374411",
    "40647629182", "40681376480", "40688279536", "40706982753")
V6_PREVIOUS_STAGE_MINUTES = 309
V6_EXISTING_STAGE_LIMIT = 1650
V6_OVERALL_MINUTES = 18000
V6_DIAGNOSTIC_BYTES = 64 * 1024 * 1024
V6_PREPARATION_ARTIFACT_BYTES = 2 * 1024 * 1024
V6_ARTIFACT_BASELINE = {"count": 15, "bytes": 9335}
V6_SETTLED_USAGE_PATH = "scripts/fork-release/candidates/v2026.10.8-source-only/npm-settled-usage.json"
V6_PREPARATION_PROOF_PATH = "scripts/fork-release/candidates/v2026.10.8-source-only/lock-preparation-proof.json"
V6_SOURCE_BRANCH = "prep/v2026.10.8-remediation"
V6_SCOPE = "approved-npm-patch-and-fixture-remediation"
V6_SOURCE_PATHS = frozenset(("package.json", "pnpm-lock.yaml",
    "scripts/generate-npm-package-lock.mts", "test/scripts/generate-npm-package-lock.test.ts",
    "src/agents/subagents/registry/subagent-control.accepted-stop.test.ts",
    "test/v108-remediation-security.test.mjs", "scripts/fork-release/native_tests.mjs",
    "test/scripts/native-security-ownership.test.ts"))
# This is deliberately unbound. Only the root's reviewed actual derivation and
# source identities can replace it; it cannot admit an invented future source.
V6_STAGE_PINS = {'sourceSha': '9b0a696bf62f045889d76044f84a0c372c8dddcc', 'sourceTree': 'b5905b54f4b70f45ea58ace4feccd30031200864', 'manifestSha256': '1694932d3eca8357161671a0d62e319c48f2a3ea9b047ae447db2068ab56b997', 'inventorySha256': '830baa2cc1ce989d1da4208a059a7704fd72fa0176305d9afb56785e25bdf893', 'settledUsageSha256': '6f6043f0a6e733fd00ffb3dedc8d14d5c21c5da8ce1db96303b70d3d403c7382', 'preparation': {'runId': '40804517284', 'pipelineHead': 'e96941f0c8c05a45d7df32ca7e45758e12609be7', 'artifactId': 12867024791, 'artifactSha256': 'f433194ae0b6927a21c8ba8a5be7bebb000a533a39a979905855d5cbb8b691e3', 'generationReceiptSha256': '662cb33cb91ab073b05f3cdf14ed1d0a8221e9d77c892f3668fac350c98324c6', 'packageSha256': 'd5cb6bde3b3d5f032b09add3adcb16fb2ae6dab85ba375051376533c1ddbf8a1', 'lockSha256': '5e631697caa53422d40dde5ae04a7ee0d84321921891062a4f580ca11b55fc50'}, 'priorValidationRuns': [{'runId': '40808362032', 'pipelineHead': '774c81d7ff22f962dcdef67a7a08f565846a4986', 'requestSha256': '2fed151bd3038f9ed80758dd23d3e655dbe281ee76ecb7a03987643903021740'}], 'sourceHops': [{'sourceSha': '9b0a696bf62f045889d76044f84a0c372c8dddcc', 'sourceTree': 'b5905b54f4b70f45ea58ace4feccd30031200864'}], 'previousSourceHopCount': 1}

# One exact recovery of the unused first validation booking; never a generic
# larger targeted allowance or permission for another correction.
V6_RECOVERY_POLICY = "npm-intake-recovery-v1"
V6_INTAKE_RECOVERY_PRIOR_PIN = {'runId': '40808362032', 'pipelineHead': '774c81d7ff22f962dcdef67a7a08f565846a4986', 'requestSha256': '2fed151bd3038f9ed80758dd23d3e655dbe281ee76ecb7a03987643903021740'}
V6_INTAKE_RECOVERY_SOURCE_PINS = {'sourceSha': '9b0a696bf62f045889d76044f84a0c372c8dddcc', 'sourceTree': 'b5905b54f4b70f45ea58ace4feccd30031200864', 'manifestSha256': '1694932d3eca8357161671a0d62e319c48f2a3ea9b047ae447db2068ab56b997', 'inventorySha256': '830baa2cc1ce989d1da4208a059a7704fd72fa0176305d9afb56785e25bdf893', 'settledUsageSha256': '6f6043f0a6e733fd00ffb3dedc8d14d5c21c5da8ce1db96303b70d3d403c7382', 'preparation': {'runId': '40804517284', 'pipelineHead': 'e96941f0c8c05a45d7df32ca7e45758e12609be7', 'artifactId': 12867024791, 'artifactSha256': 'f433194ae0b6927a21c8ba8a5be7bebb000a533a39a979905855d5cbb8b691e3', 'generationReceiptSha256': '662cb33cb91ab073b05f3cdf14ed1d0a8221e9d77c892f3668fac350c98324c6', 'packageSha256': 'd5cb6bde3b3d5f032b09add3adcb16fb2ae6dab85ba375051376533c1ddbf8a1', 'lockSha256': '5e631697caa53422d40dde5ae04a7ee0d84321921891062a4f580ca11b55fc50'}}
V6_INTAKE_RECOVERY_WITNESS_SHA256 = "89a1cbc90052e7d297c9b0c3e3efe8db7d3f14306caf69bc810a3438315ba1c3"
V6_INTAKE_RECOVERY_MINUTES = 5
V6_INTAKE_RECOVERY_JOB_PROJECTION_SHA256 = "1ecb68032249e5b5d42f029c63cd078fdca54d02d4e9238a994a95362f706fcb"
V6_PREPARATION_TITLE = "future-v108-npm-lock-preparation-20261029"


class V6ContractRefusal(ValueError):
    pass


def _v6_need(condition, code):
    if not condition:
        raise V6ContractRefusal(code)


def _v6_matches(pattern, value):
    return type(value) is str and re.fullmatch(pattern, value) is not None


def _v6_json(raw):
    _v6_need(type(raw) is bytes and 0 < len(raw) <= V6_DIAGNOSTIC_BYTES, "v6.bounded_json")
    def pairs(values):
        result = {}
        for key, value in values:
            _v6_need(key not in result, "v6.duplicate_json_key")
            result[key] = value
        return result
    def constant(value):
        raise V6ContractRefusal("v6.invalid_json_constant")
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise V6ContractRefusal("v6.invalid_json") from None


def _v6_equal(left, right):
    return json.dumps(left, sort_keys=True, separators=(",", ":"), allow_nan=False) == \
        json.dumps(right, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _v6_preparation_pin(value):
    fields = {"runId", "pipelineHead", "artifactId", "artifactSha256",
        "generationReceiptSha256", "packageSha256", "lockSha256"}
    _v6_need(type(value) is dict and set(value) == fields, "v6.preparation_pin_fields")
    _v6_need(_v6_matches(r"[1-9][0-9]{0,19}\Z", value["runId"]) and
        _v6_matches(r"[0-9a-f]{40}\Z", value["pipelineHead"]) and
        type(value["artifactId"]) is int and value["artifactId"] > 0,
        "v6.preparation_pin_identity")
    _v6_need(all(_v6_matches(r"[0-9a-f]{64}\Z", value[key]) for key in
        ("artifactSha256", "generationReceiptSha256", "packageSha256", "lockSha256")),
        "v6.preparation_pin_digest")
    return value


def _v6_pins(value):
    fields = {"sourceSha", "sourceTree", "manifestSha256", "inventorySha256",
        "settledUsageSha256", "preparation", "priorValidationRuns", "sourceHops",
        "previousSourceHopCount"}
    _v6_need(type(value) is dict and set(value) == fields, "v6.trusted_pin_fields")
    _v6_need(all(_v6_matches(r"[0-9a-f]{40}\Z", value[key]) for key in
        ("sourceSha", "sourceTree")) and all(_v6_matches(r"[0-9a-f]{64}\Z", value[key])
        for key in ("manifestSha256", "inventorySha256", "settledUsageSha256")),
        "v6.trusted_source_pins")
    _v6_need(value["settledUsageSha256"] == V6_BASELINE_SHA256, "v6.trusted_baseline_pin")
    _v6_preparation_pin(value["preparation"])
    runs = value["priorValidationRuns"]
    _v6_need(type(runs) is list and len(runs) <= 1 and all(type(pin) is dict and
        set(pin) == {"runId", "pipelineHead", "requestSha256"} and
        _v6_matches(r"[1-9][0-9]{0,19}\Z", pin["runId"]) and
        _v6_matches(r"[0-9a-f]{40}\Z", pin["pipelineHead"]) and
        _v6_matches(r"[0-9a-f]{64}\Z", pin["requestSha256"]) for pin in runs),
        "v6.trusted_validation_runs")
    _v6_need(len({value["preparation"]["runId"], *[pin["runId"] for pin in runs]}) == 1 + len(runs)
        and not ({value["preparation"]["runId"], *[pin["runId"] for pin in runs]} & set(V6_PRIOR_SOURCE_IDS)),
        "v6.trusted_run_unique")
    hops = value["sourceHops"]
    _v6_need(type(hops) is list and 1 <= len(hops) <= 2 and all(type(hop) is dict and
        set(hop) == {"sourceSha", "sourceTree"} and all(_v6_matches(r"[0-9a-f]{40}\Z", hop[key])
        for key in ("sourceSha", "sourceTree")) for hop in hops), "v6.trusted_source_hops")
    _v6_need(len({V6_BASE_SOURCE, *[hop["sourceSha"] for hop in hops]}) == 1 + len(hops) and
        hops[-1] == {"sourceSha": value["sourceSha"], "sourceTree": value["sourceTree"]},
        "v6.trusted_source_chain")
    _v6_need(type(value["previousSourceHopCount"]) is int and
        0 <= value["previousSourceHopCount"] <= len(hops), "v6.trusted_previous_hop_count")
    return value


def v6_required_correction_profiles(paths):
    _v6_need(type(paths) is list and paths == sorted(set(paths)) and bool(paths) and
        all(type(path) is str and path in V6_SOURCE_PATHS for path in paths), "v6.approved_changed_paths")
    # Preserve the existing conservative affected-owner rule. The small targeted
    # allowance never authorizes dropping a required owner merely to fit it.
    if set(paths) & {"package.json", "pnpm-lock.yaml"}:
        return set(V6_PROFILES)
    result = {"dependency", "types-tests", "compatibility", "pipeline-contracts"}
    if set(paths) & {"scripts/generate-npm-package-lock.mts", "scripts/fork-release/native_tests.mjs"}:
        result.add("types-scripts")
    return result


def validation_budget_v6(request):
    _v6_need(type(request) is dict and request.get("schema") == V6_SCHEMA and
        request.get("profilePolicy") in (V6_POLICY, V6_RECOVERY_POLICY) and type(request.get("stageRound")) is int and
        request["stageRound"] in (1, 2), "v6.budget_policy")
    recovery = request["profilePolicy"] == V6_RECOVERY_POLICY
    _v6_need(not recovery or request["stageRound"] == 2, "v6.recovery_round_only")
    return {"admissionMinutes": V6_ADMISSION_MINUTES, "finalMinutes": V6_FINAL_MINUTES,
        "profileMinutes": dict(V6_PROFILE_MINUTES),
        "roundMaximumMinutes": V6_FULL_MINUTES if request["stageRound"] == 1 or recovery else V6_TARGETED_MINUTES,
        "ancillaryMinutes": V6_ANCILLARY_MINUTES, "stageMaximumMinutes": V6_NEW_MINUTES}


def _v6_step(value, parent_sha, parent_tree):
    _v6_need(type(value) is dict and set(value) == {"parentSha", "parentTree", "changedPaths",
        "unchangedTreeSha256"} and value["parentSha"] == parent_sha and value["parentTree"] == parent_tree and
        _v6_matches(r"[0-9a-f]{64}\Z", value["unchangedTreeSha256"]), "v6.witness_parent_fields")
    v6_required_correction_profiles(value["changedPaths"])


def validate_request_v6(value, pins):
    pins = _v6_pins(pins)
    fields = {"schema", "campaignId", "profilePolicy", "sourceAuthorization", "stageRound",
        "lifetimeOperatorRound", "profiles", "sourceSha", "sourceTree", "manifestSha256",
        "inventorySha256", "settledUsageSha256", "priorRunIds", "lockPreparation", "sourceWitness"}
    _v6_need(type(value) is dict and set(value) == fields and value["schema"] == V6_SCHEMA and
        value["campaignId"] == V6_CAMPAIGN and value["profilePolicy"] in (V6_POLICY, V6_RECOVERY_POLICY) and
        value["sourceAuthorization"] == V6_AUTHORIZATION, "v6.closed_authorized_request")
    for key in ("sourceSha", "sourceTree", "manifestSha256", "inventorySha256", "settledUsageSha256"):
        _v6_need(type(value[key]) is str and value[key] == pins[key], "v6.exact_reviewed_pins")
    _v6_need(_v6_equal(value["lockPreparation"], pins["preparation"]), "v6.exact_preparation_pin")
    number = value["stageRound"]
    _v6_need(type(number) is int and number in (1, 2) and type(value["lifetimeOperatorRound"]) is int and
        value["lifetimeOperatorRound"] == number + 8 and len(pins["priorValidationRuns"]) == number - 1,
        "v6.round_limit")
    prior = [*V6_PRIOR_SOURCE_IDS, pins["preparation"]["runId"],
        *[pin["runId"] for pin in pins["priorValidationRuns"]]]
    _v6_need(type(value["priorRunIds"]) is list and value["priorRunIds"] == prior, "v6.exact_prior_runs")
    profiles = value["profiles"]
    _v6_need(type(profiles) is list and bool(profiles) and len(profiles) == len(set(profiles)) and
        all(type(profile) is str and profile in V6_PROFILE_MINUTES for profile in profiles),
        "v6.fixed_unique_profiles")
    budget = validation_budget_v6(value)
    _v6_need(V6_ADMISSION_MINUTES + V6_FINAL_MINUTES + sum(V6_PROFILE_MINUTES[p] for p in profiles)
        <= budget["roundMaximumMinutes"], "v6.round_booking")
    if number == 1:
        _v6_need(profiles == list(V6_PROFILES) and len(pins["sourceHops"]) == 1 and
            pins["previousSourceHopCount"] == 0, "v6.exact_fresh_full_validation")
    else:
        _v6_need(pins["previousSourceHopCount"] == 1, "v6.previous_source_hop_count")
    witness = value["sourceWitness"]
    _v6_need(type(witness) is dict and set(witness) == {"schema", "scope", "closedBaselineSha256", "hops"} and
        witness["schema"] == "openclaw.v108.npm-source-equivalence.v1" and witness["scope"] == V6_SCOPE and
        witness["closedBaselineSha256"] == pins["settledUsageSha256"], "v6.closed_source_witness")
    hops = witness["hops"]
    _v6_need(type(hops) is list and len(hops) == len(pins["sourceHops"]), "v6.witness_hop_count")
    parent_sha, parent_tree = V6_BASE_SOURCE, V6_BASE_TREE
    for index, (hop, trusted) in enumerate(zip(hops, pins["sourceHops"])):
        _v6_need(type(hop) is dict and set(hop) == {"sourceSha", "sourceTree", "step"} and
            hop["sourceSha"] == trusted["sourceSha"] and hop["sourceTree"] == trusted["sourceTree"],
            "v6.witness_hop_binding")
        _v6_step(hop["step"], parent_sha, parent_tree)
        if index == 0:
            _v6_need({"package.json", "pnpm-lock.yaml"} <= set(hop["step"]["changedPaths"]),
                "v6.initial_dependency_change_required")
        parent_sha, parent_tree = trusted["sourceSha"], trusted["sourceTree"]
    if value["profilePolicy"] == V6_RECOVERY_POLICY:
        _v6_need(number == 2 and profiles == list(V6_PROFILES) and
            pins["priorValidationRuns"] == [V6_INTAKE_RECOVERY_PRIOR_PIN] and
            len(pins["sourceHops"]) == 1 and pins["previousSourceHopCount"] == 1 and
            all(_v6_equal(pins[key], expected) for key, expected in V6_INTAKE_RECOVERY_SOURCE_PINS.items()) and
            hashlib.sha256(json.dumps(witness, sort_keys=True, separators=(",", ":"),
                allow_nan=False).encode()).hexdigest() == V6_INTAKE_RECOVERY_WITNESS_SHA256,
            "v6.closed_failed_intake_recovery")
    affected = set()
    for hop in hops[pins["previousSourceHopCount"]:]:
        affected.update(v6_required_correction_profiles(hop["step"]["changedPaths"]))
    _v6_need(affected <= set(profiles), "v6.affected_source_profiles")
    return value


def validate_generation_receipt_v6(raw, pins):
    pins = _v6_pins(pins)
    _v6_need(type(raw) is bytes and len(raw) <= 65536 and
        hashlib.sha256(raw).hexdigest() == pins["preparation"]["generationReceiptSha256"],
        "v6.generation_receipt_digest")
    value = _v6_json(raw)
    fields = {"schema", "status", "sourceSha", "sourceTree", "pipelineHead", "runId", "runAttempt",
        "sourcePackageSha256", "sourceLockSha256", "packageSha256", "lockSha256", "npmVersion",
        "npmIntegrity", "nodeVersion", "pnpmVersion", "workspaceSha256", "changedPaths",
        "gitDiffSha256", "allOtherTrackedEntriesUnchanged", "startedAt", "finishedAt", "commandSeconds",
        "exitCode", "timedOut", "cleanupSettled", "qualified", "imageBuilt", "productionAuthorized"}
    _v6_need(type(value) is dict and set(value) == fields and
        value["schema"] == "openclaw.v108.npm-lock-derivation.v1" and value["status"] == "derived_only" and
        value["sourceSha"] == V6_BASE_SOURCE and value["sourceTree"] == V6_BASE_TREE and
        value["pipelineHead"] == pins["preparation"]["pipelineHead"] and
        value["runId"] == pins["preparation"]["runId"] and type(value["runAttempt"]) is int and
        value["runAttempt"] == 1, "v6.generation_identity")
    _v6_need(value["sourcePackageSha256"] == V6_PREVIOUS_PACKAGE_SHA256 and
        value["sourceLockSha256"] == V6_PREVIOUS_LOCK_SHA256 and
        all(value[key] == pins["preparation"][key] for key in ("packageSha256", "lockSha256")) and
        all(_v6_matches(r"[0-9a-f]{64}\Z", value[key]) for key in ("workspaceSha256", "gitDiffSha256")),
        "v6.generation_source_digests")
    _v6_need(value["npmVersion"] == V6_NPM_VERSION and value["npmIntegrity"] == V6_NPM_INTEGRITY and
        value["nodeVersion"] == "24.22.1" and value["pnpmVersion"] == "12.15.0" and
        value["changedPaths"] == ["package.json", "pnpm-lock.yaml"] and
        value["allOtherTrackedEntriesUnchanged"] is True and type(value["exitCode"]) is int and
        value["exitCode"] == 0 and value["timedOut"] is False and value["cleanupSettled"] is None and
        all(value[key] is False for key in ("qualified", "imageBuilt", "productionAuthorized")),
        "v6.generation_outcome")
    _v6_need(type(value["commandSeconds"]) in (int, float) and math.isfinite(value["commandSeconds"]) and
        0 <= value["commandSeconds"] <= V6_PREPARATION_MINUTES * 60 and
        _v6_matches(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z\Z", value["startedAt"]) and
        _v6_matches(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z\Z", value["finishedAt"]),
        "v6.generation_clock_shape")
    start, end = timestamp(value["startedAt"]), timestamp(value["finishedAt"])
    _v6_need(0 <= (end - start).total_seconds() <= V6_PREPARATION_MINUTES * 60 and
        end < timestamp(V6_DEADLINE), "v6.generation_clock_bound")
    return value


def verify_source_equivalence_v6(request, pins, read_git, generation_raw):
    validate_request_v6(request, pins)
    generation = validate_generation_receipt_v6(generation_raw, pins)
    hops = [_v4_verify_step(read_git, hop["sourceSha"], hop["sourceTree"], hop["step"], initial=False)
        for hop in request["sourceWitness"]["hops"]]
    old_package_raw = _v4_git(read_git, "show", V6_BASE_SOURCE + ":package.json")
    old_lock_raw = _v4_git(read_git, "show", V6_BASE_SOURCE + ":pnpm-lock.yaml")
    _v6_need(hashlib.sha256(old_package_raw).hexdigest() == V6_PREVIOUS_PACKAGE_SHA256 and
        hashlib.sha256(old_lock_raw).hexdigest() == V6_PREVIOUS_LOCK_SHA256, "v6.base_dependency_digests")
    old_package = _v6_json(old_package_raw)
    _v6_need(type(old_package) is dict and type(old_package.get("dependencies")) is dict and
        old_package["dependencies"].get("npm") == "12.2.0", "v6.base_npm_pin")
    expected_package = json.loads(json.dumps(old_package))
    expected_package["dependencies"]["npm"] = V6_NPM_VERSION
    for hop in request["sourceWitness"]["hops"]:
        package_raw = _v4_git(read_git, "show", hop["sourceSha"] + ":package.json")
        lock_raw = _v4_git(read_git, "show", hop["sourceSha"] + ":pnpm-lock.yaml")
        _v6_need(hashlib.sha256(package_raw).hexdigest() == generation["packageSha256"] and
            hashlib.sha256(lock_raw).hexdigest() == generation["lockSha256"] and
            _v6_equal(_v6_json(package_raw), expected_package), "v6.only_exact_npm_dependency_change")
        workspace_old = _v4_git(read_git, "show", V6_BASE_SOURCE + ":pnpm-workspace.yaml")
        workspace_new = _v4_git(read_git, "show", hop["sourceSha"] + ":pnpm-workspace.yaml")
        _v6_need(workspace_new == workspace_old and
            hashlib.sha256(workspace_old).hexdigest() == generation["workspaceSha256"], "v6.workspace_policy_unchanged")
        dependency_diff = _v4_git(read_git, "-c", "diff.algorithm=myers", "-c", "core.quotePath=true",
            "diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--full-index", "--binary",
            V6_BASE_SOURCE, hop["sourceSha"], "--", "package.json", "pnpm-lock.yaml")
        _v6_need(hashlib.sha256(dependency_diff).hexdigest() == generation["gitDiffSha256"],
            "v6.exact_generated_dependency_diff")
    return {"schema": "openclaw.v108.verified-npm-source-equivalence.v1", "scope": V6_SCOPE,
        "sourceSha": request["sourceSha"], "sourceTree": request["sourceTree"], "hops": hops,
        "baseSourceSha": V6_BASE_SOURCE, "baseSourceTree": V6_BASE_TREE,
        "closedBaselineSha256": request["settledUsageSha256"],
        "generationReceiptSha256": pins["preparation"]["generationReceiptSha256"],
        "npmVersion": V6_NPM_VERSION, "lockSha256": generation["lockSha256"],
        "unchangedOutsideApprovedSourceAndLedger": True, "historicalCoverageReused": False,
        "sameSourceReceiptRelabeled": False, "productionAuthorized": False, "imageBuilt": False}


def workflow_security_v6(raw, source_sha):
    # The three validation jobs, token surface and closed read-only workflow
    # structure are unchanged. Only their dynamic source-profile table expands.
    return workflow_security_v5(raw, source_sha)


def observed_minutes_v6(table, request):
    return observed_minutes_v5(table, request["profiles"], validation_budget_v6(request))


def booking_v6(request, preparation_minutes, prior_validation_minutes, ancillary_minutes):
    _v6_need(all(type(value) is int and value >= 0 for value in
        (preparation_minutes, prior_validation_minutes, ancillary_minutes)) and
        preparation_minutes <= V6_PREPARATION_MINUTES and ancillary_minutes <= V6_ANCILLARY_MINUTES,
        "v6.actual_usage_bounds")
    budget = validation_budget_v6(request)
    planned = V6_ADMISSION_MINUTES + V6_FINAL_MINUTES + sum(V6_PROFILE_MINUTES[p] for p in request["profiles"])
    _v6_need(planned <= budget["roundMaximumMinutes"] and
        ((request["stageRound"] == 1 and prior_validation_minutes == 0) or
         (request["stageRound"] == 2 and prior_validation_minutes <= V6_FULL_MINUTES)), "v6.round_booking")
    if request["profilePolicy"] == V6_RECOVERY_POLICY:
        _v6_need(prior_validation_minutes == V6_INTAKE_RECOVERY_MINUTES and
            request["profiles"] == list(V6_PROFILES), "v6.recovery_actual_intake_minutes")
    reserve = V6_TARGETED_MINUTES if request["stageRound"] == 1 else 0
    additional = preparation_minutes + prior_validation_minutes + planned + reserve + V6_ANCILLARY_MINUTES
    cumulative = V6_PRIOR_MINUTES + additional
    _v6_need(additional <= V6_NEW_MINUTES and V6_PREVIOUS_STAGE_MINUTES + additional <=
        V6_EXISTING_STAGE_LIMIT and cumulative <= V6_OVERALL_MINUTES, "v6.total_minute_ceiling")
    return {"bookedRunnerMinutes": cumulative, "actualSettledRunnerMinutes": V6_PRIOR_MINUTES,
        "newStageBookedMinutes": additional, "preparationObservedMinutes": preparation_minutes,
        "priorValidationObservedMinutes": prior_validation_minutes, "currentRoundBookedMinutes": planned,
        "futureTargetedReserveMinutes": reserve, "ancillaryReservationBookedMinutes": V6_ANCILLARY_MINUTES,
        "observedNewAncillaryRunnerMinutes": ancillary_minutes,
        "newAncillaryRemainingReserveMinutes": V6_ANCILLARY_MINUTES - ancillary_minutes,
        "sourceFetchStageBookedMinutes": V6_PREVIOUS_STAGE_MINUTES + additional,
        "overallMinuteCeiling": V6_OVERALL_MINUTES, "newScopeMinuteCeiling": V6_NEW_MINUTES,
        "currentSourceCoverageReusedFromF5": False}


"""V6 history/accounting fragment: fixed derivation plus fresh current-source CI.

Shared historical measurement and API readers remain owned by the maintained
driver. No source result from the closed prefix is current-candidate coverage.
"""

V6_HISTORY_MAX_RUNS = 300
V6_PROVIDER_HEADERS = ("id", "name", "path", "event", "head_branch", "head_sha", "run_attempt",
    "status", "conclusion", "created_at", "updated_at", "html_url")
V6_PREFIX_DERIVED_FIELDS = {"jobs", "observedRunnerMinutes", "artifactRows"}


def _h6_branch_history(api):
    result = {}
    for branch in ("task%2Fv107-source-binding", "prep%2Fv2026.10.8-remediation"):
        route = ("/repos/" + REPOSITORY + "/actions/runs?branch=" + branch +
            "&created=%3E%3D2026-10-28T00%3A03%3A19Z&per_page=100&page=")
        first = api(route + "1")
        _v6_need(type(first) is dict and type(first.get("total_count")) is int and
            0 <= first["total_count"] <= V6_HISTORY_MAX_RUNS, "v6.history.branch_page")
        total, rows = first["total_count"], []
        for page in range(1, max(1, math.ceil(total / 100)) + 1):
            table = first if page == 1 else api(route + str(page))
            _v6_need(type(table) is dict and type(table.get("total_count")) is int and
                table["total_count"] == total and type(table.get("workflow_runs")) is list and
                len(table["workflow_runs"]) == min(100, max(0, total - (page - 1) * 100)),
                "v6.history.complete_branch_pagination")
            rows.extend(table["workflow_runs"])
        ids = [row.get("id") for row in rows if type(row) is dict]
        _v6_need(len(ids) == total and all(type(rid) is int and rid > 0 for rid in ids) and
            len(set(ids)) == total, "v6.history.unique_branch_ids")
        for row in rows:
            rid = str(row["id"])
            _v6_need(rid not in result or all(type(row.get(key)) is type(result[rid].get(key)) and
                row.get(key) == result[rid].get(key) for key in V6_PROVIDER_HEADERS),
                "v6.history.duplicate_branch_header_changed")
            result[rid] = row
    return result


def validate_closed_baseline_v6(raw, read_git, history):
    _v6_need(type(raw) is bytes and hashlib.sha256(raw).hexdigest() == V6_BASELINE_SHA256,
        "v6.history.exact_baseline_digest")
    baseline = _v6_json(raw)
    fields = {"schema", "repository", "campaignId", "closedAt", "runnerMinutesObserved", "runCount",
        "previousPrefixSha256", "previousPrefixRunCount", "previousPrefixMinutes", "previousPrefixPipeline",
        "previousArtifactSnapshot", "currentArtifactSnapshot", "sourceRunIds", "runs"}
    _v6_need(type(baseline) is dict and set(baseline) == fields and
        baseline["schema"] == "openclaw.v108.closed-source-usage.v4" and baseline["repository"] == REPOSITORY and
        baseline["campaignId"] == V6_CAMPAIGN and type(baseline["runCount"]) is int and
        baseline["runCount"] == V6_PRIOR_RUNS and type(baseline["runnerMinutesObserved"]) is int and
        baseline["runnerMinutesObserved"] == V6_PRIOR_MINUTES and type(baseline["runs"]) is list and
        len(baseline["runs"]) == V6_PRIOR_RUNS and
        baseline["previousPrefixSha256"] == V6_PREVIOUS_PREFIX_SHA256 and
        type(baseline["previousPrefixRunCount"]) is int and baseline["previousPrefixRunCount"] == 141 and
        type(baseline["previousPrefixMinutes"]) is int and baseline["previousPrefixMinutes"] == 928 and
        baseline["previousPrefixPipeline"] == V6_PREVIOUS_PIPELINE and
        _v6_equal(baseline["previousArtifactSnapshot"], {"count": 13, "bytes": 8090}) and
        _v6_equal(baseline["currentArtifactSnapshot"], V6_ARTIFACT_BASELINE), "v6.history.baseline_envelope")
    source_ids = baseline["sourceRunIds"]
    _v6_need(type(source_ids) is list and len(source_ids) == len(V6_PRIOR_SOURCE_IDS) and
        all(type(rid) is str for rid in source_ids) and len(set(source_ids)) == len(source_ids) and
        set(source_ids) == set(V6_PRIOR_SOURCE_IDS), "v6.history.baseline_source_ids")
    _v6_need(_v6_matches(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}\+00:00\Z",
        baseline["closedAt"]), "v6.history.baseline_capture_time")
    datetime.fromisoformat(baseline["closedAt"])
    previous_raw = _v4_git(read_git, "show", V6_PREVIOUS_PIPELINE + ":" + V5_SETTLED_USAGE_PATH)
    _v6_need(hashlib.sha256(previous_raw).hexdigest() == V6_PREVIOUS_PREFIX_SHA256,
        "v6.history.original141_git_digest")
    previous = _v6_json(previous_raw)
    _v6_need(type(previous) is dict and type(previous.get("runs")) is list and
        len(previous["runs"]) == 141 and previous.get("runnerMinutesObserved") == 928,
        "v6.history.original141_envelope")
    old_by_id = {str(row["id"]): row for row in previous["runs"]}
    new_by_id = {str(row["id"]): row for row in baseline["runs"] if type(row) is dict and "id" in row}
    _v6_need(len(old_by_id) == 141 and len(new_by_id) == V6_PRIOR_RUNS and set(old_by_id) <= set(new_by_id) and
        all(_v6_equal(row, new_by_id[rid]) for rid, row in old_by_id.items()),
        "v6.history.original141_subset_unchanged")
    ids, measured_total, measured_source, hashes = set(), 0, set(), {}
    for row in baseline["runs"]:
        _v6_need(type(row) is dict and set(V6_PROVIDER_HEADERS) <= set(row) and
            set(row) <= set(V6_PROVIDER_HEADERS) | V6_PREFIX_DERIVED_FIELDS and
            type(row.get("id")) is int and row["id"] > 0 and str(row["id"]) not in ids and
            row["status"] == "completed" and row["conclusion"] in V5_TERMINAL_CONCLUSIONS and
            type(row["run_attempt"]) is int and row["run_attempt"] == 1 and type(row.get("jobs")) is list and
            ("artifactRows" not in row or type(row["artifactRows"]) is list),
            "v6.history.baseline_run_projection")
        rid = str(row["id"])
        ids.add(rid)
        live = history.get(rid, {})
        _v6_need(_h5_public(live) and all(type(live.get(key)) is type(row[key]) and
            live.get(key) == row[key] for key in V6_PROVIDER_HEADERS), "v6.history.baseline_header_changed")
        jobs = []
        for item in row["jobs"]:
            _v6_need(type(item) is dict and
                ((rid in old_by_id and ("run_attempt" not in item or
                    type(item["run_attempt"]) is int and item["run_attempt"] == 1)) or
                 (rid not in old_by_id and type(item.get("run_attempt")) is int and item["run_attempt"] == 1)),
                "v6.history.baseline_job_attempt")
            # Only exact inherited historical bytes omit job attempt. Their
            # authenticated parent run positively bound the original attempt1.
            jobs.append(dict(item, run_attempt=1))
        table = {"total_count": len(jobs), "jobs": jobs}
        if row["path"] != WORKFLOW or rid in V6_PRIOR_SOURCE_IDS[:3]:
            measured = observed_minutes(table,
                list(LEGACY_PROFILE_MINUTES) if row["path"] == WORKFLOW else None, legacy=True)
        else:
            if rid == V6_PRIOR_SOURCE_IDS[-1]:
                policy = validation_budget_for_record_v5({"schema": V5_SCHEMA, "profilePolicy": "donor-repair-v1"})
            elif rid in V6_PRIOR_SOURCE_IDS[-3:-1]:
                policy = validation_budget_for_record_v5({"schema": "openclaw.fork-source-validation-request.v4",
                    "profilePolicy": "five-gate-repair-v1"})
            else:
                policy = validation_budget_for_record_v5({"schema": "openclaw.fork-source-validation-request.v3"})
            measured = observed_minutes_v5(table, list(policy["profileMinutes"]), policy)
        if row["path"] == WORKFLOW:
            measured_source.add(rid)
        _v6_need(type(row.get("observedRunnerMinutes")) is int and
            row["observedRunnerMinutes"] == measured, "v6.history.baseline_actual_minutes")
        measured_total += measured
        hashes[rid] = hashlib.sha256(json.dumps(row["jobs"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    _v6_need(len(ids) == V6_PRIOR_RUNS and measured_total == V6_PRIOR_MINUTES and
        measured_source == set(V6_PRIOR_SOURCE_IDS), "v6.history.actual168_1237")
    return baseline, ids, hashes


def _h6_source_run_binding(run):
    _v6_need(_h5_public(run) and run.get("event") == "pull_request" and
        type(run.get("run_attempt")) is int and run["run_attempt"] == 1 and
        run.get("head_branch") == BRANCH and run.get("display_title") == CAMPAIGN and
        [pr.get("number") for pr in run.get("pull_requests", [])] == [28],
        "v6.history.source_run_binding")


def _h6_preparation_run_binding(run, pin):
    _v6_preparation_pin(pin)
    _v6_need(_h5_public(run) and type(run.get("id")) is int and str(run["id"]) == pin["runId"] and
        run.get("event") == "pull_request" and type(run.get("run_attempt")) is int and run["run_attempt"] == 1 and
        run.get("head_branch") == BRANCH and run.get("display_title") == V6_PREPARATION_TITLE and
        run.get("path") == WORKFLOW and run.get("head_sha") == pin["pipelineHead"] and
        [pr.get("number") for pr in run.get("pull_requests", [])] == [28],
        "v6.history.preparation_run_binding")


def _h6_expected_run_role_binding(rid, run, pins):
    _v6_need(type(rid) is str and type(run) is dict and type(run.get("id")) is int and
        str(run["id"]) == rid, "v6.history.run_role_identity")
    if rid == pins["preparation"]["runId"]:
        _h6_preparation_run_binding(run, pins["preparation"])
    else:
        _h6_source_run_binding(run)


def _h6_preparation(pins, history, current, generation, pipeline, api):
    pin = pins["preparation"]
    _v6_need(pin["runId"] in history, "v6.history.preparation_run_present")
    run = history[pin["runId"]]
    _h6_preparation_run_binding(run, pin)
    _v6_need(run.get("path") == WORKFLOW and run.get("head_sha") == pin["pipelineHead"] and
        run.get("status") == "completed" and run.get("conclusion") == "success" and
        timestamp(run["updated_at"]) <= timestamp(current["created_at"]), "v6.history.preparation_terminal")
    git(pipeline, "merge-base", "--is-ancestor", pin["pipelineHead"], current["head_sha"])
    table = _h5_jobs(api, run)
    _v6_need(table["total_count"] == 1, "v6.history.preparation_single_job")
    job = table["jobs"][0]
    _v6_need(job.get("name") == "lock-preparation" and job.get("status") == "completed" and
        job.get("conclusion") == "success" and type(job.get("runner_id")) is int and job["runner_id"] > 0 and
        type(job.get("runner_name")) is str and bool(job["runner_name"]) and
        job.get("runner_group_name") == "GitHub Actions" and job.get("labels") == ["ubuntu-24.04"],
        "v6.history.preparation_public_job")
    start, end = timestamp(job["started_at"]), timestamp(job["completed_at"])
    seconds = (end - start).total_seconds()
    _v6_need(0 <= seconds and math.ceil(seconds / 60) <= V6_PREPARATION_MINUTES and
        start <= timestamp(generation["startedAt"]) <= timestamp(generation["finishedAt"]) <= end,
        "v6.history.preparation_clock_bound")
    artifacts = api("/repos/" + REPOSITORY + "/actions/runs/" + pin["runId"] + "/artifacts?per_page=100")
    _v6_need(type(artifacts) is dict and type(artifacts.get("total_count")) is int and
        artifacts["total_count"] == 1 and type(artifacts.get("artifacts")) is list and len(artifacts["artifacts"]) == 1,
        "v6.history.preparation_single_artifact")
    artifact = artifacts["artifacts"][0]
    _v6_need(type(artifact) is dict and type(artifact.get("id")) is int and artifact["id"] == pin["artifactId"] and
        artifact.get("name") == "v108-npm-lock-preparation" and type(artifact.get("size_in_bytes")) is int and
        0 < artifact["size_in_bytes"] <= V6_PREPARATION_ARTIFACT_BYTES and artifact.get("expired") is False and
        artifact.get("digest") == "sha256:" + pin["artifactSha256"], "v6.history.preparation_artifact_identity")
    return math.ceil(seconds / 60), {"runId": pin["runId"], "pipelineHead": pin["pipelineHead"],
        "jobId": job["id"], "observedRunnerMinutes": math.ceil(seconds / 60), "artifactId": pin["artifactId"],
        "artifactSha256": pin["artifactSha256"], "artifactBytes": artifact["size_in_bytes"],
        "generationReceiptSha256": pin["generationReceiptSha256"], "status": "derived_only",
        "currentCandidateQualification": False}


def _h6_failed_intake_recovery(table, run, pin, minutes):
    """Positive exact terminal job evidence, never absent-row coverage inference."""
    _v6_need(pin == V6_INTAKE_RECOVERY_PRIOR_PIN and type(run.get("id")) is int and
        str(run["id"]) == pin["runId"] and run.get("head_sha") == pin["pipelineHead"] and
        run.get("status") == "completed" and run.get("conclusion") == "failure" and
        type(minutes) is int and minutes == V6_INTAKE_RECOVERY_MINUTES and
        type(table) is dict and type(table.get("total_count")) is int and table["total_count"] == 3 and
        type(table.get("jobs")) is list and len(table["jobs"]) == 3 and
        _h5_unexpanded_failed_initial(table["jobs"]), "v6.history.recovery_failed_intake_shape")
    fields = ("id", "run_id", "run_attempt", "head_sha", "name", "status", "conclusion",
        "runner_id", "runner_name", "runner_group_id", "runner_group_name", "labels",
        "started_at", "completed_at", "steps")
    _v6_need(all(type(job) is dict and set(fields) <= set(job) and type(job["id"]) is int and
        job["id"] > 0 for job in table["jobs"]) and
        len({job["id"] for job in table["jobs"]}) == 3, "v6.history.recovery_complete_job_fields")
    projection = {"total_count": table["total_count"], "jobs": sorted(
        [{key: job[key] for key in fields} for job in table["jobs"]], key=lambda job: job["id"])}
    digest = hashlib.sha256(json.dumps(projection, sort_keys=True, separators=(",", ":"),
        allow_nan=False).encode()).hexdigest()
    _v6_need(digest == V6_INTAKE_RECOVERY_JOB_PROJECTION_SHA256,
        "v6.history.recovery_actual_job_projection")
    return {"runId": pin["runId"], "pipelineHead": pin["pipelineHead"],
        "requestSha256": pin["requestSha256"], "sourceSha": V6_INTAKE_RECOVERY_SOURCE_PINS["sourceSha"],
        "sourceTree": V6_INTAKE_RECOVERY_SOURCE_PINS["sourceTree"],
        "observedRunnerMinutes": minutes, "conclusion": "failure", "profileResults": {},
        "invalidatedPriorProfiles": [], "unresolvedProfiles": list(V6_PROFILES),
        "validationNeverStarted": True, "sourceJobsAcquired": 0,
        "failedIntakeJobProjectionSha256": digest, "oldF5EvidenceUsed": False}


def _h6_previous_validation(request, pins, history, current, pipeline, api):
    if request["stageRound"] == 1:
        _v6_need(not pins["priorValidationRuns"] and pins["previousSourceHopCount"] == 0,
            "v6.history.initial_validation_identity")
        return 0, [], {}, list(V6_PROFILES)
    pin = pins["priorValidationRuns"][0]
    _v6_need(pin["runId"] in history, "v6.history.prior_validation_present")
    run = history[pin["runId"]]
    _h6_source_run_binding(run)
    _v6_need(run.get("path") == WORKFLOW and run.get("head_sha") == pin["pipelineHead"] and
        run.get("status") == "completed" and run.get("conclusion") in V5_TERMINAL_CONCLUSIONS and
        timestamp(run["updated_at"]) <= timestamp(current["created_at"]), "v6.history.prior_validation_terminal")
    old_raw = content_at(api, REQUEST, pin["pipelineHead"])
    _v6_need(hashlib.sha256(old_raw).hexdigest() == pin["requestSha256"],
        "v6.history.prior_request_digest")
    old = _v6_json(old_raw)
    _v6_need(type(old) is dict and type(old.get("sourceWitness")) is dict and
        type(old["sourceWitness"].get("hops")) is list, "v6.history.prior_request_shape")
    old_hops = old["sourceWitness"]["hops"]
    old_pins = dict(pins, sourceSha=old.get("sourceSha"), sourceTree=old.get("sourceTree"),
        manifestSha256=old.get("manifestSha256"), inventorySha256=old.get("inventorySha256"),
        sourceHops=[{"sourceSha": hop.get("sourceSha"), "sourceTree": hop.get("sourceTree")}
            for hop in old_hops if type(hop) is dict], previousSourceHopCount=0, priorValidationRuns=[])
    validate_request_v6(old, old_pins)
    _v6_need(old["stageRound"] == 1 and pins["previousSourceHopCount"] == len(old_hops) and
        _v6_equal(request["sourceWitness"]["hops"][:len(old_hops)], old_hops),
        "v6.history.prior_source_chain")
    git(pipeline, "merge-base", "--is-ancestor", pin["pipelineHead"], current["head_sha"])
    workflow_security_v6(content_at(api, WORKFLOW, pin["pipelineHead"]), old["sourceSha"])
    table = _h5_jobs(api, run)
    minutes = observed_minutes_v6(table, old)
    if request["profilePolicy"] == V6_RECOVERY_POLICY:
        receipt = _h6_failed_intake_recovery(table, run, pin, minutes)
        return minutes, [receipt], {}, list(V6_PROFILES)
    results = {job["name"][8:-1]: job["conclusion"] for job in table["jobs"] if
        job["name"].startswith("source (") and job["name"].endswith(")") and job["name"][8:-1] in old["profiles"]}
    unexpanded = _h5_unexpanded_failed_initial(table["jobs"])
    _v6_need(bool(results) or unexpanded, "v6.history.prior_positive_unexpanded_evidence")
    invalidated = set()
    for hop in request["sourceWitness"]["hops"][len(old_hops):]:
        invalidated.update(v6_required_correction_profiles(hop["step"]["changedPaths"]))
    for profile in invalidated:
        results.pop(profile, None)
    unresolved = sorted(profile for profile in V6_PROFILES if results.get(profile) != "success")
    _v6_need(set(unresolved) <= set(request["profiles"]), "v6.history.unresolved_profiles_selected")
    receipt = {"runId": pin["runId"], "pipelineHead": pin["pipelineHead"],
        "requestSha256": pin["requestSha256"], "sourceSha": old["sourceSha"], "sourceTree": old["sourceTree"],
        "observedRunnerMinutes": minutes, "profileResults": results, "conclusion": run["conclusion"],
        "invalidatedPriorProfiles": sorted(invalidated), "unresolvedProfiles": unresolved,
        "validationNeverStarted": unexpanded, "oldF5EvidenceUsed": False}
    return minutes, [receipt], results, unresolved


def history_checks_v6(request, event, env, pipeline, api, pins):
    request = validate_request_v6(request, pins)
    head = validate_event(event, env)
    now = datetime.now(timezone.utc)
    _v6_need(now < timestamp(V6_DEADLINE), "v6.history.deadline")
    live = api("/repos/" + REPOSITORY + "/pulls/28")
    _v6_need(validate_event(dict(event, pull_request=live), env) == head, "v6.history.live_pr_changed")
    target = api("/repos/" + REPOSITORY + "/git/ref/heads/" + BASE_BRANCH)
    _v6_need(target.get("ref") == "refs/heads/" + BASE_BRANCH and
        target.get("object", {}).get("type") == "commit" and
        target["object"].get("sha") == TARGET_BRANCH_TIP, "v6.history.target_tip")
    source_ref = api("/repos/" + REPOSITORY + "/git/ref/heads/" + V6_SOURCE_BRANCH)
    _v6_need(source_ref.get("ref") == "refs/heads/" + V6_SOURCE_BRANCH and
        source_ref.get("object", {}).get("type") == "commit" and
        source_ref["object"].get("sha") == request["sourceSha"], "v6.history.source_branch_tip")
    history = _h6_branch_history(api)
    raw = (pipeline / V6_SETTLED_USAGE_PATH).read_bytes()
    baseline, prefix_ids, hashes = validate_closed_baseline_v6(raw, lambda *args: git(pipeline, *args), history)
    expected = [*V6_PRIOR_SOURCE_IDS, pins["preparation"]["runId"],
        *[pin["runId"] for pin in pins["priorValidationRuns"]], env["GITHUB_RUN_ID"]]
    actual = {rid for rid, run in history.items() if run.get("path") == WORKFLOW}
    _v6_need(actual == set(expected) and len(expected) == len(set(expected)), "v6.history.exact_execution_set")
    for rid in actual:
        _h6_expected_run_role_binding(rid, history[rid], pins)
    current = history[env["GITHUB_RUN_ID"]]
    _v6_need(current.get("head_sha") == head and current.get("status") == "in_progress" and
        datetime.fromisoformat(baseline["closedAt"]) <= timestamp(current["created_at"]) <= now,
        "v6.history.current_source_identity")
    for rid in V6_PRIOR_SOURCE_IDS:
        git(pipeline, "merge-base", "--is-ancestor", history[rid]["head_sha"], head)
    workflow = workflow_security_v6((pipeline / WORKFLOW).read_bytes(), request["sourceSha"])
    generation = validate_generation_receipt_v6((pipeline / V6_PREPARATION_PROOF_PATH).read_bytes(), pins)
    preparation_minutes, preparation = _h6_preparation(pins, history, current, generation, pipeline, api)
    previous_minutes, previous_receipts, results, unresolved = _h6_previous_validation(
        request, pins, history, current, pipeline, api)
    current_jobs = _h5_jobs(api, current)
    admission = [job for job in current_jobs["jobs"] if job.get("name") == "admission"]
    _v6_need(len(admission) == 1 and admission[0].get("status") == "in_progress" and
        type(admission[0].get("runner_id")) is int and admission[0]["runner_id"] > 0 and
        type(admission[0].get("runner_name")) is str and bool(admission[0]["runner_name"]) and
        admission[0].get("runner_group_name") == "GitHub Actions" and admission[0].get("labels") == ["ubuntu-24.04"],
        "v6.history.current_public_admission")
    current_facts = ancillary_job_snapshot(current_jobs, now, False)
    allowed_current = {"admission", "final", "source (${{ matrix.profile }})",
        *["source (" + profile + ")" for profile in request["profiles"]]}
    _v6_need(all(job.get("name") in allowed_current for job in current_jobs["jobs"]) and
        current_facts["observedAcquiredRunnerMinutes"] <= V6_ADMISSION_MINUTES,
        "v6.history.current_job_booking")
    paths = {row["path"] for row in baseline["runs"] if row["path"] != WORKFLOW}
    pipeline_heads = {row["head_sha"] for row in baseline["runs"] if row["head_branch"] == BRANCH} | \
        {head, pins["preparation"]["pipelineHead"], *[pin["pipelineHead"] for pin in pins["priorValidationRuns"]]}
    source_heads = {V6_BASE_SOURCE, *[hop["sourceSha"] for hop in pins["sourceHops"]]}
    observed, ancillary, pending = 0, [], []
    artifact_bytes, artifact_records, artifact_ids = V6_ARTIFACT_BASELINE["bytes"], [], set()
    for rid, run in sorted(history.items()):
        if rid in prefix_ids:
            continue
        if run.get("path") != WORKFLOW:
            branch = run.get("head_branch")
            correct_branch = (branch == BRANCH and run.get("head_sha") in pipeline_heads) or \
                (branch == V6_SOURCE_BRANCH and run.get("head_sha") in source_heads)
            events = ("pull_request", "pull_request_target") if branch == BRANCH else ("push",)
            _v6_need(_h5_public(run) and correct_branch and run.get("event") in events and
                run.get("path") in paths and type(run.get("run_attempt")) is int and run["run_attempt"] == 1 and
                run.get("status") in ("completed", "in_progress", "queued", "waiting", "pending") and
                (run["status"] != "completed" or run.get("conclusion") in V5_TERMINAL_CONCLUSIONS),
                "v6.history.new_ancillary_binding")
            facts = ancillary_job_snapshot(_h5_jobs(api, run), now, run["status"] == "completed")
            observed += facts["observedAcquiredRunnerMinutes"]
            ancillary.append({"runId": rid, **facts})
            if not facts["usageComplete"]:
                pending.append(rid)
        artifacts = _h5_artifacts(api, run)
        _v6_need(not artifact_ids.intersection(artifacts["ids"]), "v6.history.artifact_duplicate")
        artifact_ids.update(artifacts["ids"])
        artifact_bytes += artifacts["bytes"]
        artifact_records.append({"runId": rid, **artifacts})
    _v6_need(observed <= V6_ANCILLARY_MINUTES and (not pending or observed < V6_ANCILLARY_MINUTES),
        "v6.history.ancillary77_exceeded")
    _v6_need(artifact_bytes <= V6_DIAGNOSTIC_BYTES, "v6.history.artifact_storage_bound")
    booking = booking_v6(request, preparation_minutes, previous_minutes, observed)
    return {**booking, "deadlineEpoch": int(timestamp(V6_DEADLINE).timestamp()),
        "profileMatrix": [{"profile": profile, "minutes": V6_PROFILE_MINUTES[profile]} for profile in request["profiles"]],
        "selectedProfileCount": len(request["profiles"]), "preparationReceipt": preparation,
        "priorValidationReceipts": previous_receipts, "priorValidationProfileResults": results,
        "priorUnresolvedProfiles": unresolved, "historicalCoverageReused": False,
        "reusedProfileCount": 0, "closedBaselineRuns": V6_PRIOR_RUNS,
        "closedBaselineMinutes": V6_PRIOR_MINUTES, "closedBaselineSha256": V6_BASELINE_SHA256,
        "historicalJobTableSha256": hashes, "newAncillaryRecords": ancillary,
        "pendingAncillaryRunIds": pending, "ancillaryUsageComplete": not pending,
        "artifactRecords": artifact_records, "observedRetainedWorkflowArtifactBytes": artifact_bytes,
        "artifactObservationComplete": all(row["observationComplete"] for row in artifact_records),
        "artifactBudgetIsNotWholeDiagnosticCustodyProof": True, "workflowSecurity": workflow,
        "currentAdmissionObservation": current_facts, "historicalConclusionsRetained": True,
        "productionAuthorized": False, "imageBuilt": False}



V6_RUNTIME_COMPATIBILITY_TESTS = (*V4_RUNTIME_COMPATIBILITY_TESTS,
    "test/scripts/native-runner.test.ts", "test/scripts/native-security-ownership.test.ts",
    "src/infra/npm-command.test.ts", "src/infra/safe-package-install.test.ts",
    "src/plugins/install.npm-spec.test.ts", "test/scripts/npm-runner.test.ts")


def runtime_refusal_code_v6(error):
    if isinstance(error, V6ContractRefusal):
        code = error.args[0] if len(error.args) == 1 else None
        return code if type(code) is str and code in V6_RUNTIME_REFUSAL_CODES else "v6.unprojected"
    if isinstance(error, V4ContractRefusal):
        return runtime_refusal_code_v4(error)
    if isinstance(error, V5ContractRefusal):
        # Retained V5 readers measure historical records only. Their controlled
        # refusal enum remains useful evidence, not an operational fallback.
        return runtime_refusal_code_v5(error)
    if type(error) is release.Refusal and len(error.args) == 1 and type(error.args[0]) is str:
        shared = V6_SHARED_HISTORY_REFUSALS.get(error.args[0])
        if shared is not None:
            return shared
    code = vars(error).get("admission_need_code")
    return code if code in ADMISSION_NEED_CODES.values() else "v6.unprojected"

V6_BUNDLED_NPM_VERSION_CHECK = 'import { createRequire } from "node:module";\nimport { realpathSync, readFileSync, statSync } from "node:fs";\nimport { dirname, join, sep } from "node:path";\nimport { spawnSync } from "node:child_process";\nconst allowed = new Set(["node_version", "source_npm_scope", "npm_package_version", "npm_cli_scope", "npm_cli_exit", "npm_cli_version"]);\nconst requireCondition = (ok, code) => { if (!ok) throw { controlledCode: code }; };\nlet subcheck = "source_npm_scope";\ntry {\n  requireCondition(process.versions.node === "24.22.1", "node_version");\n  const source = realpathSync(process.cwd());\n  const modules = realpathSync(join(source, "node_modules"));\n  requireCondition(modules === join(source, "node_modules"), "source_npm_scope");\n  const requireSource = createRequire(join(source, "package.json"));\n  const manifest = realpathSync(requireSource.resolve("npm/package.json"));\n  requireCondition(manifest.startsWith(modules + sep), "source_npm_scope");\n  subcheck = "npm_package_version";\n  requireCondition(statSync(manifest).isFile() && statSync(manifest).size <= 65536, "npm_package_version");\n  const pkg = JSON.parse(readFileSync(manifest, "utf8"));\n  requireCondition(pkg.name === "npm" && pkg.version === "12.2.1", "npm_package_version");\n  const packageRoot = dirname(manifest);\n  subcheck = "npm_cli_scope";\n  const cli = realpathSync(join(packageRoot, "bin", "npm-cli.js"));\n  requireCondition(cli.startsWith(packageRoot + sep), "npm_cli_scope");\n  subcheck = "npm_cli_exit";\n  const child = spawnSync(process.execPath, [cli, "--version"], {\n    cwd: source, timeout: 10000, maxBuffer: 4096, encoding: "utf8",\n    env: { ...process.env, npm_config_offline: "true", npm_config_ignore_scripts: "true",\n      npm_config_audit: "false", npm_config_fund: "false", npm_config_update_notifier: "false" }\n  });\n  requireCondition(!child.error && !child.signal && child.status === 0, "npm_cli_exit");\n  subcheck = "npm_cli_version";\n  requireCondition(typeof child.stdout === "string" && child.stdout.trim() === "12.2.1", "npm_cli_version");\n  console.log(JSON.stringify({schema:"openclaw.v108.bundled-npm-version.v1", status:"verified", npmVersion:"12.2.1", nodeVersion:process.versions.node, sourceInstalledPackage:true, productionAuthorized:false, imageBuilt:false}));\n} catch (error) {\n  const code = allowed.has(error?.controlledCode) ? error.controlledCode : subcheck;\n  console.log(JSON.stringify({schema:"openclaw.v108.bundled-npm-version.v1", status:"refused", code, productionAuthorized:false, imageBuilt:false}));\n  process.exitCode = 1;\n}\n'

V6_SHARED_HISTORY_REFUSALS = {'source-validation: v5.history.artifact_identity_size': 'v6.shared.artifact_identity_size', 'source-validation: v5.history.artifacts_complete': 'v6.shared.artifacts_complete', 'source-validation: v5.history.fresh_job_binding': 'v6.shared.fresh_job_binding', 'source-validation: v5.history.fresh_jobs_complete': 'v6.shared.fresh_jobs_complete', 'source-validation: v5.history.terminal_admitted_profiles': 'v6.shared.terminal_admitted_profiles', 'source-validation: v5.history.terminal_boundary_jobs': 'v6.shared.terminal_boundary_jobs', 'source-validation: v5.history.terminal_job_duration': 'v6.shared.terminal_job_duration', 'source-validation: v5.history.terminal_job_identity': 'v6.shared.terminal_job_identity', 'source-validation: v5.history.terminal_jobs_complete': 'v6.shared.terminal_jobs_complete', 'source-validation: v5.history.terminal_profiles': 'v6.shared.terminal_profiles', 'source-validation: v5.history.terminal_public_runner': 'v6.shared.terminal_public_runner', 'source-validation: v5.history.terminal_round_booking': 'v6.shared.terminal_round_booking', 'source-validation: v5.history.terminal_unacquired_evidence': 'v6.shared.terminal_unacquired_evidence', 'source-validation: v5.history.workflow_concurrency': 'v6.shared.workflow_concurrency', 'source-validation: v5.history.workflow_credentials': 'v6.shared.workflow_credentials', 'source-validation: v5.history.workflow_fixed_actions': 'v6.shared.workflow_fixed_actions', 'source-validation: v5.history.workflow_job_caps': 'v6.shared.workflow_job_caps', 'source-validation: v5.history.workflow_job_permissions': 'v6.shared.workflow_job_permissions', 'source-validation: v5.history.workflow_jobs': 'v6.shared.workflow_jobs', 'source-validation: v5.history.workflow_literal_mapping': 'v6.shared.workflow_literal_mapping', 'source-validation: v5.history.workflow_matrix_policy': 'v6.shared.workflow_matrix_policy', 'source-validation: v5.history.workflow_permissions': 'v6.shared.workflow_permissions', 'source-validation: v5.history.workflow_runner_job_keys': 'v6.shared.workflow_runner_job_keys', 'source-validation: v5.history.workflow_size': 'v6.shared.workflow_size', 'source-validation: v5.history.workflow_source_refs': 'v6.shared.workflow_source_refs', 'source-validation: v5.history.workflow_token_surface': 'v6.shared.workflow_token_surface', 'source-validation: v5.history.workflow_top_level': 'v6.shared.workflow_top_level', 'source-validation: v5.history.workflow_trigger': 'v6.shared.workflow_trigger', 'source-validation: v5.history.workflow_yaml_shape': 'v6.shared.workflow_yaml_shape'}

V6_RUNTIME_REFUSAL_CODES = frozenset(('v6.actual_usage_bounds', 'v6.affected_source_profiles', 'v6.approved_changed_paths', 'v6.base_dependency_digests', 'v6.base_npm_pin', 'v6.bounded_json', 'v6.budget_policy', 'v6.closed_authorized_request', 'v6.closed_failed_intake_recovery', 'v6.closed_source_witness', 'v6.duplicate_json_key', 'v6.exact_fresh_full_validation', 'v6.exact_generated_dependency_diff', 'v6.exact_preparation_pin', 'v6.exact_prior_runs', 'v6.exact_reviewed_pins', 'v6.fixed_unique_profiles', 'v6.generation_clock_bound', 'v6.generation_clock_shape', 'v6.generation_identity', 'v6.generation_outcome', 'v6.generation_receipt_digest', 'v6.generation_source_digests', 'v6.history.actual168_1237', 'v6.history.ancillary77_exceeded', 'v6.history.artifact_duplicate', 'v6.history.artifact_storage_bound', 'v6.history.baseline_actual_minutes', 'v6.history.baseline_capture_time', 'v6.history.baseline_envelope', 'v6.history.baseline_header_changed', 'v6.history.baseline_job_attempt', 'v6.history.baseline_run_projection', 'v6.history.baseline_source_ids', 'v6.history.branch_page', 'v6.history.complete_branch_pagination', 'v6.history.current_job_booking', 'v6.history.current_public_admission', 'v6.history.current_source_identity', 'v6.history.deadline', 'v6.history.duplicate_branch_header_changed', 'v6.history.exact_baseline_digest', 'v6.history.exact_execution_set', 'v6.history.initial_validation_identity', 'v6.history.live_pr_changed', 'v6.history.new_ancillary_binding', 'v6.history.original141_envelope', 'v6.history.original141_git_digest', 'v6.history.original141_subset_unchanged', 'v6.history.preparation_artifact_identity', 'v6.history.preparation_clock_bound', 'v6.history.preparation_public_job', 'v6.history.preparation_run_binding', 'v6.history.preparation_run_present', 'v6.history.preparation_single_artifact', 'v6.history.preparation_single_job', 'v6.history.preparation_terminal', 'v6.history.prior_positive_unexpanded_evidence', 'v6.history.prior_request_digest', 'v6.history.prior_request_shape', 'v6.history.prior_source_chain', 'v6.history.prior_validation_present', 'v6.history.prior_validation_terminal', 'v6.history.recovery_actual_job_projection', 'v6.history.recovery_complete_job_fields', 'v6.history.recovery_failed_intake_shape', 'v6.history.run_role_identity', 'v6.history.source_branch_tip', 'v6.history.source_run_binding', 'v6.history.target_tip', 'v6.history.unique_branch_ids', 'v6.history.unresolved_profiles_selected', 'v6.initial_dependency_change_required', 'v6.invalid_json', 'v6.invalid_json_constant', 'v6.only_exact_npm_dependency_change', 'v6.preparation_pin_digest', 'v6.preparation_pin_fields', 'v6.preparation_pin_identity', 'v6.previous_source_hop_count', 'v6.recovery_actual_intake_minutes', 'v6.recovery_round_only', 'v6.round_booking', 'v6.round_limit', 'v6.runtime_approval_deadline', 'v6.runtime_baseline_digest', 'v6.runtime_manifest_source', 'v6.runtime_metadata_digest', 'v6.runtime_verified_budget_and_fresh_coverage', 'v6.shared.artifact_identity_size', 'v6.shared.artifacts_complete', 'v6.shared.fresh_job_binding', 'v6.shared.fresh_jobs_complete', 'v6.shared.terminal_admitted_profiles', 'v6.shared.terminal_boundary_jobs', 'v6.shared.terminal_job_duration', 'v6.shared.terminal_job_identity', 'v6.shared.terminal_jobs_complete', 'v6.shared.terminal_profiles', 'v6.shared.terminal_public_runner', 'v6.shared.terminal_round_booking', 'v6.shared.terminal_unacquired_evidence', 'v6.shared.workflow_concurrency', 'v6.shared.workflow_credentials', 'v6.shared.workflow_fixed_actions', 'v6.shared.workflow_job_caps', 'v6.shared.workflow_job_permissions', 'v6.shared.workflow_jobs', 'v6.shared.workflow_literal_mapping', 'v6.shared.workflow_matrix_policy', 'v6.shared.workflow_permissions', 'v6.shared.workflow_runner_job_keys', 'v6.shared.workflow_size', 'v6.shared.workflow_source_refs', 'v6.shared.workflow_token_surface', 'v6.shared.workflow_top_level', 'v6.shared.workflow_trigger', 'v6.shared.workflow_yaml_shape', 'v6.total_minute_ceiling', 'v6.trusted_baseline_pin', 'v6.trusted_pin_fields', 'v6.trusted_previous_hop_count', 'v6.trusted_run_unique', 'v6.trusted_source_chain', 'v6.trusted_source_hops', 'v6.trusted_source_pins', 'v6.trusted_validation_runs', 'v6.unprojected', 'v6.witness_hop_binding', 'v6.witness_hop_count', 'v6.witness_parent_fields', 'v6.workspace_policy_unchanged'))

"""Closed RE2JS followup fragment for the maintained source-validation owner.

No CLI, transport, package manager, or source writer lives in this fragment.
Actual source/provider pins are deliberately absent until the coordinating owner
has genuine resolver and source evidence. Historical V6 policy is unchanged.
"""

R7_SCHEMA = "openclaw.fork-source-validation-request.v7"
R7_POLICY = "re2js-security-followup-v1"
R7_AUTHORIZATION = "future-v108-re2js-followup-20261029"
R7_DEADLINE = "2026-10-30T00:03:19Z"
R7_BASE_SOURCE = "9b0a696bf62f045889d76044f84a0c372c8dddcc"
R7_BASE_TREE = "b5905b54f4b70f45ea58ace4feccd30031200864"
R7_BASE_PACKAGE_SHA256 = "d5cb6bde3b3d5f032b09add3adcb16fb2ae6dab85ba375051376533c1ddbf8a1"
R7_BASE_LOCK_SHA256 = "5e631697caa53422d40dde5ae04a7ee0d84321921891062a4f580ca11b55fc50"
R7_METADATA_PROOF_SHA256 = "2511fc1bc645e400b31ba6a7e98abb7198c812d392237ae2afcdef2e90c43eea"
R7_RE2JS_VERSION = "2.8.7"
R7_RE2JS_INTEGRITY = "sha512-bRSL/vn3KAmlGfGNoVpcsBXLaVvl6AbuvMMWbz0m3vBj60nj+p2/biozfBUOSBP+5XTduF6mr6IO/ZVjmqqkVQ=="
R7_RE2JS_PUBLISHED_AT = "2026-10-17T19:21:18.170Z"
R7_RE2JS_GIT_HEAD = "6ba840014b192668365271d7b1c4d2d24a4b5f83"
R7_RE2JS_ENGINE = ">=20.0.0"
R7_PARENT_VERSION = "0.1.29"
R7_PARENT_DECLARED_CHILD = "2.8.6"
R7_PARENT_ENGINE = ">=22"
R7_PARENT_INTEGRITY = "sha512-x7kkvSsAkjUSoeFjvtaBDg6W7gYNIIIo2iOVrI6JG6LjbOHXuGQjHRECKh46iJdZKyc67BUUVRA8HF961yRMxg=="
R7_MINIMUM_AGE_MINUTES = 10080
R7_PREPARATION_CONTEXT_SCHEMA = "openclaw.v108.re2js-lock-preparation.v1"
R7_PREPARATION_TITLE = "future-v108-re2js-lock-preparation-20261029"
R7_PREPARATION_ARTIFACT = "v108-re2js-lock-preparation"
R7_SETTLED_USAGE_PATH = "scripts/fork-release/candidates/v2026.10.8-source-only/re2js-settled-usage.json"
R7_PREPARATION_PROOF_PATH = "scripts/fork-release/candidates/v2026.10.8-source-only/re2js-lock-preparation-proof.json"
R7_SECURITY_TEST_PATH = "test/v108-remediation-security.test.mjs"
R7_PREPARED_PATHS = ["pnpm-workspace.yaml", R7_SECURITY_TEST_PATH]
R7_DERIVED_PATHS = ["pnpm-lock.yaml"]
R7_SOURCE_SCOPE = "approved-re2js-child-override-only"
R7_PROFILE_MINUTES = dict(V6_PROFILE_MINUTES, **{"doctor-2": 75, "doctor-3": 75})
R7_ADMISSION_MINUTES = 30
R7_FINAL_MINUTES = 10
R7_PREPARATION_MINUTES = 45
R7_FULL_MINUTES = 1075
R7_TARGETED_MINUTES = 300
R7_ANCILLARY_MINUTES = 50
R7_NEW_MINUTES = 1470
R7_BASELINE_SHA256 = "c2438e2b10555f396f662c6fb8e142bafd61f7b32b172fd8a5cb982ccac567ec"
R7_PRIOR_RUNS = 213
R7_PRIOR_MINUTES = 1798
R7_ARTIFACT_BASELINE = {"count": 19, "bytes": 198278}
R7_BASELINE_SOURCE_IDS = ("40616416909", "40609889437", "40607329263", "40639374411",
    "40647629182", "40681376480", "40688279536", "40706982753", "40804517284", "40808362032", "40816927196")
R7_PREPARATION_PINS = {'ledgerSha256': 'ceddaa033f8440d96aed322f823946553194de9f3f3744286596e81dac7220bd', 'metadataProofSha256': '2511fc1bc645e400b31ba6a7e98abb7198c812d392237ae2afcdef2e90c43eea', 'packageSha256': 'd5cb6bde3b3d5f032b09add3adcb16fb2ae6dab85ba375051376533c1ddbf8a1', 'securityTestSha256': '913bdc0443a86dcfab4d4917a25b545830377af716db0c69e026f8ec2ad6a595', 'sourceLockSha256': '5e631697caa53422d40dde5ae04a7ee0d84321921891062a4f580ca11b55fc50', 'sourceSha': '5ee477cf16b11325bca69423392a455859cd7862', 'sourceTree': 'cdd806366c79cffa5cad995af021bed54d5d80ed', 'workspaceSha256': '70cbac6461cb180e8e5c3799a17c3e37becaa7b476929730e9c1b1ae79654e26'}
R7_STAGE_PINS = {'baseline': {'artifactSnapshot': {'bytes': 198278, 'count': 19}, 'runCount': 213, 'runnerMinutesObserved': 1798, 'sha256': 'c2438e2b10555f396f662c6fb8e142bafd61f7b32b172fd8a5cb982ccac567ec', 'sourceRunIds': ['40616416909', '40609889437', '40607329263', '40639374411', '40647629182', '40681376480', '40688279536', '40706982753', '40804517284', '40808362032', '40816927196']}, 'inventorySha256': 'cfcf6c1f97e9adc0d428186c63426c83afe3dbb94d9194f2b9389ebded75de57', 'manifestSha256': 'a4daac2453b3212d41fc7f2a910a5349dd066fde7abde344c911cbff3e96c257', 'preparation': {'artifactId': 12887657070, 'artifactSha256': 'e446f3c0e775362ebe622c88a88f3feec72f588394edf382756a0a7eb0603f0c', 'generationReceiptSha256': 'aab54ccb07d2c0bb2dc55e3cf86929d73eae50adfe81f9f25fce3ea4c6bed1d1', 'lockSha256': '07cbdb13cc0fc5c6dd25b4acdfe927eabe4ec566e6cfab9fb63d224c25765002', 'packageSha256': 'd5cb6bde3b3d5f032b09add3adcb16fb2ae6dab85ba375051376533c1ddbf8a1', 'pipelineHead': '1b26975c3c38b264632a1bc26577a71039cc23ae', 'runId': '40851844749'}, 'priorValidationRuns': [], 'sourceHops': [{'sourceSha': '5ee477cf16b11325bca69423392a455859cd7862', 'sourceTree': 'cdd806366c79cffa5cad995af021bed54d5d80ed'}, {'sourceSha': '76522eaa2dd93a4933b5c87f7451eab1d458f8be', 'sourceTree': '28adf129927ab5f4589f90f599fe6b76d790a015'}], 'sourceSha': '76522eaa2dd93a4933b5c87f7451eab1d458f8be', 'sourceTree': '28adf129927ab5f4589f90f599fe6b76d790a015'}


class R7ContractRefusal(ValueError):
    pass


def _r7_need(value, code):
    if not value:
        raise R7ContractRefusal(code)


def _r7_digest(value):
    return _v6_matches(r"[0-9a-f]{64}\Z", value)


def _r7_preparation_pins(pins):
    fields = {"sourceSha", "sourceTree", "packageSha256", "sourceLockSha256",
        "workspaceSha256", "securityTestSha256", "ledgerSha256", "metadataProofSha256"}
    _r7_need(type(pins) is dict and set(pins) == fields and
        all(_v6_matches(r"[0-9a-f]{40}\Z", pins[k]) for k in ("sourceSha", "sourceTree")) and
        all(_r7_digest(pins[k]) for k in fields - {"sourceSha", "sourceTree"}) and
        pins["sourceSha"] != R7_BASE_SOURCE and pins["packageSha256"] == R7_BASE_PACKAGE_SHA256 and
        pins["sourceLockSha256"] == R7_BASE_LOCK_SHA256 and
        pins["metadataProofSha256"] == R7_METADATA_PROOF_SHA256, "r7.preparation_pins")
    return pins


def validate_preparation_context_v7(value, pins):
    pins = _r7_preparation_pins(pins)
    _r7_need(type(value) is dict and set(value) == {"schema", "sourceSha", "sourceTree"} and
        value["schema"] == R7_PREPARATION_CONTEXT_SCHEMA and
        all(value[k] == pins[k] for k in ("sourceSha", "sourceTree")), "r7.preparation_context")
    return value


def _r7_pins(pins):
    prep = _r7_preparation_pins(R7_PREPARATION_PINS)
    fields = {"sourceSha", "sourceTree", "manifestSha256", "inventorySha256", "baseline",
        "preparation", "priorValidationRuns", "sourceHops"}
    _r7_need(type(pins) is dict and set(pins) == fields and
        all(_v6_matches(r"[0-9a-f]{40}\Z", pins[k]) for k in ("sourceSha", "sourceTree")) and
        all(_r7_digest(pins[k]) for k in ("manifestSha256", "inventorySha256")), "r7.stage_pins")
    _v6_preparation_pin(pins["preparation"])
    _r7_need(pins["preparation"]["packageSha256"] == R7_BASE_PACKAGE_SHA256,
        "r7.preparation_package_unchanged")
    baseline = pins["baseline"]
    _r7_need(type(baseline) is dict and set(baseline) ==
        {"sha256", "runCount", "runnerMinutesObserved", "artifactSnapshot", "sourceRunIds"} and
        baseline["sha256"] == R7_BASELINE_SHA256 and type(baseline["runCount"]) is int and
        baseline["runCount"] == R7_PRIOR_RUNS and
        type(baseline["runnerMinutesObserved"]) is int and
        baseline["runnerMinutesObserved"] == R7_PRIOR_MINUTES and
        type(baseline["artifactSnapshot"]) is dict and set(baseline["artifactSnapshot"]) == {"count", "bytes"} and
        all(type(baseline["artifactSnapshot"][k]) is int and baseline["artifactSnapshot"][k] >= 0
            for k in ("count", "bytes")) and _v6_equal(baseline["artifactSnapshot"], R7_ARTIFACT_BASELINE),
        "r7.closed_baseline_pins")
    known = list(R7_BASELINE_SOURCE_IDS)
    _r7_need(baseline["sourceRunIds"] == known, "r7.baseline_source_runs")
    prior = pins["priorValidationRuns"]
    _r7_need(type(prior) is list and len(prior) <= 1 and all(type(p) is dict and
        set(p) == {"runId", "pipelineHead", "requestSha256"} and
        _v6_matches(r"[1-9][0-9]{0,19}\Z", p["runId"]) and
        _v6_matches(r"[0-9a-f]{40}\Z", p["pipelineHead"]) and _r7_digest(p["requestSha256"])
        for p in prior), "r7.prior_validation_pins")
    ids = [*known, pins["preparation"]["runId"], *[p["runId"] for p in prior]]
    _r7_need(len(ids) == len(set(ids)), "r7.unique_executions")
    hops = pins["sourceHops"]
    _r7_need(type(hops) is list and hops == [
        {"sourceSha": prep["sourceSha"], "sourceTree": prep["sourceTree"]},
        {"sourceSha": pins["sourceSha"], "sourceTree": pins["sourceTree"]}] and
        len({R7_BASE_SOURCE, *[p["sourceSha"] for p in hops]}) == 3, "r7.exact_two_source_hops")
    return pins


def validation_budget_v7(value):
    _r7_need(type(value) is dict and value.get("schema") == R7_SCHEMA and
        value.get("profilePolicy") == R7_POLICY and type(value.get("stageRound")) is int and
        value["stageRound"] in (1, 2), "r7.budget_policy")
    return {"admissionMinutes": R7_ADMISSION_MINUTES, "finalMinutes": R7_FINAL_MINUTES,
        "profileMinutes": dict(R7_PROFILE_MINUTES),
        "roundMaximumMinutes": R7_FULL_MINUTES if value["stageRound"] == 1 else R7_TARGETED_MINUTES,
        "ancillaryMinutes": R7_ANCILLARY_MINUTES, "stageMaximumMinutes": R7_NEW_MINUTES}


def validate_request_v7(value, pins):
    pins = _r7_pins(pins)
    fields = {"schema", "campaignId", "profilePolicy", "sourceAuthorization", "stageRound",
        "lifetimeOperatorRound", "profiles", "sourceSha", "sourceTree", "manifestSha256",
        "inventorySha256", "settledUsageSha256", "priorRunIds", "lockPreparation", "sourceWitness"}
    _r7_need(type(value) is dict and set(value) == fields and value["schema"] == R7_SCHEMA and
        value["campaignId"] == V6_CAMPAIGN and value["profilePolicy"] == R7_POLICY and
        value["sourceAuthorization"] == R7_AUTHORIZATION, "r7.closed_request")
    _r7_need(all(value[k] == pins[k] for k in ("sourceSha", "sourceTree", "manifestSha256", "inventorySha256")) and
        value["settledUsageSha256"] == pins["baseline"]["sha256"] and
        _v6_equal(value["lockPreparation"], pins["preparation"]), "r7.exact_reviewed_pins")
    number = value["stageRound"]
    _r7_need(type(number) is int and number in (1, 2) and
        type(value["lifetimeOperatorRound"]) is int and value["lifetimeOperatorRound"] == number + 10 and
        len(pins["priorValidationRuns"]) == number - 1, "r7.once_full_once_targeted")
    _r7_need(value["priorRunIds"] == [*pins["baseline"]["sourceRunIds"], pins["preparation"]["runId"],
        *[p["runId"] for p in pins["priorValidationRuns"]]], "r7.exact_prior_runs")
    profiles = value["profiles"]
    _r7_need(type(profiles) is list and bool(profiles) and len(profiles) == len(set(profiles)) and
        all(type(p) is str and p in R7_PROFILE_MINUTES for p in profiles), "r7.fixed_profiles")
    budget = validation_budget_v7(value)
    _r7_need(R7_ADMISSION_MINUTES + R7_FINAL_MINUTES + sum(R7_PROFILE_MINUTES[p] for p in profiles)
        <= budget["roundMaximumMinutes"], "r7.round_booking")
    _r7_need(number != 1 or profiles == list(V6_PROFILES), "r7.all15_fresh")
    witness = value["sourceWitness"]
    _r7_need(type(witness) is dict and set(witness) == {"schema", "scope", "closedBaselineSha256", "hops"} and
        witness["schema"] == "openclaw.v108.re2js-source-equivalence.v1" and
        witness["scope"] == R7_SOURCE_SCOPE and witness["closedBaselineSha256"] == pins["baseline"]["sha256"] and
        type(witness["hops"]) is list and len(witness["hops"]) == 2, "r7.source_witness")
    parent, tree = R7_BASE_SOURCE, R7_BASE_TREE
    for hop, trusted, paths in zip(witness["hops"], pins["sourceHops"], (R7_PREPARED_PATHS, R7_DERIVED_PATHS)):
        _r7_need(type(hop) is dict and set(hop) == {"sourceSha", "sourceTree", "step"} and
            all(hop[k] == trusted[k] for k in ("sourceSha", "sourceTree")), "r7.hop_identity")
        step = hop["step"]
        _r7_need(type(step) is dict and set(step) ==
            {"parentSha", "parentTree", "changedPaths", "unchangedTreeSha256"} and
            step["parentSha"] == parent and step["parentTree"] == tree and
            step["changedPaths"] == paths and _r7_digest(step["unchangedTreeSha256"]), "r7.hop_scope")
        parent, tree = trusted["sourceSha"], trusted["sourceTree"]
    return value


def booking_v7(request, pins, preparation_minutes, prior_minutes, ancillary_minutes):
    validate_request_v7(request, pins)
    _r7_need(all(type(v) is int and v >= 0 for v in
        (preparation_minutes, prior_minutes, ancillary_minutes)) and
        preparation_minutes <= R7_PREPARATION_MINUTES and ancillary_minutes <= R7_ANCILLARY_MINUTES and
        ((request["stageRound"] == 1 and prior_minutes == 0) or
         (request["stageRound"] == 2 and prior_minutes <= R7_FULL_MINUTES)), "r7.actual_usage")
    current = R7_ADMISSION_MINUTES + R7_FINAL_MINUTES + sum(R7_PROFILE_MINUTES[p] for p in request["profiles"])
    reserve = R7_TARGETED_MINUTES if request["stageRound"] == 1 else 0
    total = preparation_minutes + prior_minutes + current + reserve + R7_ANCILLARY_MINUTES
    cumulative = pins["baseline"]["runnerMinutesObserved"] + total
    _r7_need(total <= R7_NEW_MINUTES and cumulative <= V6_OVERALL_MINUTES, "r7.total_minute_ceiling")
    return {"bookedRunnerMinutes": cumulative, "actualSettledRunnerMinutes": pins["baseline"]["runnerMinutesObserved"],
        "newStageBookedMinutes": total, "preparationObservedMinutes": preparation_minutes,
        "priorValidationObservedMinutes": prior_minutes, "currentRoundBookedMinutes": current,
        "futureTargetedReserveMinutes": reserve, "ancillaryReservationBookedMinutes": R7_ANCILLARY_MINUTES,
        "observedNewAncillaryRunnerMinutes": ancillary_minutes,
        "newAncillaryRemainingReserveMinutes": R7_ANCILLARY_MINUTES - ancillary_minutes,
        "overallMinuteCeiling": V6_OVERALL_MINUTES, "newScopeMinuteCeiling": R7_NEW_MINUTES,
        "maximumStageExecutionsIncludingPreparation": 3, "currentSourceCoverageReusedFromF5": False}


def validate_re2js_registry_checks_v7(value):
    fields = {"checkedAt", "minimumAgeMinutes", "ageMinutes", "publishedAt", "targetName", "targetVersion",
        "targetIntegrity", "targetGitHead", "targetNodeEngine", "parentName", "parentVersion",
        "parentDeclaredRe2js", "parentNodeEngine", "parentIntegrity", "targetManifestSha256",
        "packumentSha256", "parentManifestSha256", "manifestPackumentAgreement"}
    expected = {"minimumAgeMinutes": R7_MINIMUM_AGE_MINUTES, "publishedAt": R7_RE2JS_PUBLISHED_AT,
        "targetName": "re2js", "targetVersion": R7_RE2JS_VERSION, "targetIntegrity": R7_RE2JS_INTEGRITY,
        "targetGitHead": R7_RE2JS_GIT_HEAD, "targetNodeEngine": R7_RE2JS_ENGINE,
        "parentName": "@openclaw/crabline", "parentVersion": R7_PARENT_VERSION,
        "parentDeclaredRe2js": R7_PARENT_DECLARED_CHILD, "parentNodeEngine": R7_PARENT_ENGINE,
        "parentIntegrity": R7_PARENT_INTEGRITY, "manifestPackumentAgreement": True}
    _r7_need(type(value) is dict and set(value) == fields and
        all(type(value[k]) is type(v) and value[k] == v for k, v in expected.items()) and
        all(_r7_digest(value[k]) for k in ("targetManifestSha256", "packumentSha256", "parentManifestSha256")),
        "r7.authentic_registry_binding")
    _r7_need(_v6_matches(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z\Z", value["checkedAt"]) and
        type(value["ageMinutes"]) in (int, float) and math.isfinite(value["ageMinutes"]), "r7.registry_clock_shape")
    age = (timestamp(value["checkedAt"]) - timestamp(value["publishedAt"])).total_seconds() / 60
    _r7_need(age >= R7_MINIMUM_AGE_MINUTES and abs(age - value["ageMinutes"]) <= 0.000001 and
        timestamp(value["checkedAt"]) < timestamp(R7_DEADLINE), "r7.registry_minimum_age")
    return value


def validate_re2js_lock_delta_v7(before, generated, workspace, registry):
    validate_re2js_registry_checks_v7(registry)
    prep = _r7_preparation_pins(R7_PREPARATION_PINS)
    _r7_need(type(before) is bytes and hashlib.sha256(before).hexdigest() == R7_BASE_LOCK_SHA256 and
        type(generated) is bytes and 0 < len(generated) <= V6_PREPARATION_ARTIFACT_BYTES and
        type(workspace) is bytes and hashlib.sha256(workspace).hexdigest() == prep["workspaceSha256"] and
        workspace.count(b'  "@openclaw/crabline@0.1.29>re2js": 2.8.7\n') == 1,
        "r7.lock_base_and_workspace")
    old_package = ("  re2js@2.8.6:\n    resolution: {integrity: "
        "sha512-xLgQil4kIUCrAzVk9fRSkxkFNwmygLFjVxXrLc65aE1F0+Zsb8rxumFBy4XKyvgMCTL6kilDq3EZ0piE2dP/Dg=="
        "}\n    engines: {node: '>=18.0.0'}\n").encode()
    new_package = ("  re2js@2.8.7:\n    resolution: {integrity: " + R7_RE2JS_INTEGRITY +
        "}\n    engines: {node: '>=20.0.0'}\n").encode()
    expected = before
    for old, new in ((b"overrides:\n", b"overrides:\n  '@openclaw/crabline@0.1.29>re2js': 2.8.7\n"),
                     (old_package, new_package), (b"  re2js@2.8.6: {}\n", b"  re2js@2.8.7: {}\n")):
        _r7_need(expected.count(old) == 1, "r7.exact_original_lock_shape")
        expected = expected.replace(old, new)
    prefix = b"  '@openclaw/crabline@0.1.29':\n    dependencies:\n"
    _r7_need(expected.count(prefix) == 1, "r7.exact_parent_snapshot")
    left, tail = expected.split(prefix)
    block, separator, rest = tail.partition(b"\n\n")
    _r7_need(bool(separator) and block.count(b"      re2js: 2.8.6\n") == 1 and
        expected.count(b"      re2js: 2.8.6\n") == 1, "r7.exact_parent_child_edge")
    expected = left + prefix + block.replace(b"      re2js: 2.8.6\n", b"      re2js: 2.8.7\n") + separator + rest
    # This is a comparison only. Resolver bytes are never synthesized/substituted.
    _r7_need(generated == expected, "r7.unrelated_resolution_or_format_change")
    return {"changedLockKind": "qualified-parent-override-and-authentic-leaf-only", "resolverBytesAccepted": True}


def validate_re2js_generation_receipt_v7(raw, pins):
    pins = _r7_pins(pins)
    prep = _r7_preparation_pins(R7_PREPARATION_PINS)
    _r7_need(type(raw) is bytes and 0 < len(raw) <= 65536 and
        hashlib.sha256(raw).hexdigest() == pins["preparation"]["generationReceiptSha256"], "r7.generation_digest")
    value = _v6_json(raw)
    fields = {"schema", "status", "sourceSha", "sourceTree", "baseSourceSha", "baseSourceTree", "pipelineHead",
        "runId", "runAttempt", "packageSha256", "sourceLockSha256", "lockSha256", "workspaceSha256",
        "securityTestSha256", "ledgerSha256", "metadataProofSha256", "re2jsVersion", "re2jsIntegrity", "parentName",
        "parentVersion", "parentDeclaredRe2js", "nodeVersion", "pnpmVersion", "registryChecks", "changedPaths",
        "gitDiffSha256", "allOtherTrackedEntriesUnchanged", "startedAt", "finishedAt", "commandSeconds",
        "exitCode", "timedOut", "cleanupSettled", "qualified", "imageBuilt", "productionAuthorized"}
    _r7_need(type(value) is dict and set(value) == fields and
        value["schema"] == "openclaw.v108.re2js-lock-derivation.v1" and value["status"] == "derived_only" and
        all(value[k] == prep[k] for k in prep) and value["baseSourceSha"] == R7_BASE_SOURCE and
        value["baseSourceTree"] == R7_BASE_TREE and
        all(value[k] == pins["preparation"][k] for k in ("pipelineHead", "runId", "packageSha256", "lockSha256")) and
        type(value["runAttempt"]) is int and value["runAttempt"] == 1 and _r7_digest(value["gitDiffSha256"]),
        "r7.generation_identity")
    _r7_need(value["re2jsVersion"] == R7_RE2JS_VERSION and value["re2jsIntegrity"] == R7_RE2JS_INTEGRITY and
        value["parentName"] == "@openclaw/crabline" and value["parentVersion"] == R7_PARENT_VERSION and
        value["parentDeclaredRe2js"] == R7_PARENT_DECLARED_CHILD and value["nodeVersion"] == "24.22.1" and
        value["pnpmVersion"] == "12.15.0" and value["changedPaths"] == R7_DERIVED_PATHS and
        value["allOtherTrackedEntriesUnchanged"] is True and type(value["exitCode"]) is int and value["exitCode"] == 0 and
        value["timedOut"] is False and value["cleanupSettled"] is None and
        all(value[k] is False for k in ("qualified", "imageBuilt", "productionAuthorized")), "r7.generation_outcome")
    _r7_need(type(value["commandSeconds"]) in (int, float) and math.isfinite(value["commandSeconds"]) and
        0 <= value["commandSeconds"] <= R7_PREPARATION_MINUTES * 60 and
        all(_v6_matches(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z\Z", value[k])
            for k in ("startedAt", "finishedAt")), "r7.generation_clock_shape")
    registry = validate_re2js_registry_checks_v7(value["registryChecks"])
    start, end = timestamp(value["startedAt"]), timestamp(value["finishedAt"])
    _r7_need(start <= timestamp(registry["checkedAt"]) <= end and
        0 <= (end - start).total_seconds() <= R7_PREPARATION_MINUTES * 60 and end < timestamp(R7_DEADLINE),
        "r7.generation_clock_bound")
    return value


def verify_source_equivalence_v7(request, pins, read_git, generation_raw):
    validate_request_v7(request, pins)
    generation = validate_re2js_generation_receipt_v7(generation_raw, pins)
    hops = [_v4_verify_step(read_git, hop["sourceSha"], hop["sourceTree"], hop["step"], initial=False)
        for hop in request["sourceWitness"]["hops"]]
    prep = _r7_preparation_pins(R7_PREPARATION_PINS)
    base_package = _v4_git(read_git, "show", R7_BASE_SOURCE + ":package.json")
    before = _v4_git(read_git, "show", R7_BASE_SOURCE + ":pnpm-lock.yaml")
    _r7_need(hashlib.sha256(base_package).hexdigest() == R7_BASE_PACKAGE_SHA256 and
        hashlib.sha256(before).hexdigest() == R7_BASE_LOCK_SHA256, "r7.exact_base_dependencies")
    for hop in request["sourceWitness"]["hops"]:
        source = hop["sourceSha"]
        _r7_need(_v4_git(read_git, "show", source + ":package.json") == base_package and
            hashlib.sha256(_v4_git(read_git, "show", source + ":pnpm-workspace.yaml")).hexdigest() == prep["workspaceSha256"] and
            hashlib.sha256(_v4_git(read_git, "show", source + ":" + R7_SECURITY_TEST_PATH)).hexdigest() == prep["securityTestSha256"],
            "r7.preserved_package_and_prepared_controls")
    _r7_need(_v4_git(read_git, "show", prep["sourceSha"] + ":pnpm-lock.yaml") == before and
        hashlib.sha256(_v4_git(read_git, "show", prep["sourceSha"] + ":" + V4_LEDGER_PATH)).hexdigest() == prep["ledgerSha256"],
        "r7.preparation_source_original_lock")
    lock = _v4_git(read_git, "show", request["sourceSha"] + ":pnpm-lock.yaml")
    workspace = _v4_git(read_git, "show", request["sourceSha"] + ":pnpm-workspace.yaml")
    validate_re2js_lock_delta_v7(before, lock, workspace, generation["registryChecks"])
    _r7_need(hashlib.sha256(lock).hexdigest() == pins["preparation"]["lockSha256"], "r7.generated_lock_source_binding")
    return {"schema": "openclaw.v108.verified-re2js-source-equivalence.v1", "scope": R7_SOURCE_SCOPE,
        "baseSourceSha": R7_BASE_SOURCE, "baseSourceTree": R7_BASE_TREE, "sourceSha": request["sourceSha"],
        "sourceTree": request["sourceTree"], "hops": hops, "unchangedOutsideApprovedSourceAndLedger": True,
        "generationReceiptSha256": pins["preparation"]["generationReceiptSha256"],
        "lockSha256": pins["preparation"]["lockSha256"], "historicalCoverageReused": False,
        "sameSourceReceiptRelabeled": False, "productionAuthorized": False, "imageBuilt": False}


def validate_closed_baseline_v7(raw, read_git, history, api, pins):
    pins = _r7_pins(pins)
    trusted = pins["baseline"]
    _r7_need(type(raw) is bytes and hashlib.sha256(raw).hexdigest() == trusted["sha256"],
        "r7.baseline_digest")
    value = _v6_json(raw)
    fields = {"schema", "repository", "campaignId", "closedAt", "runnerMinutesObserved", "runCount",
        "previousPrefixSha256", "previousPrefixRunCount", "previousPrefixMinutes", "previousPrefixPipeline",
        "previousArtifactSnapshot", "currentArtifactSnapshot", "sourceRunIds", "runs"}
    _r7_need(type(value) is dict and set(value) == fields and
        value["schema"] == "openclaw.v108.closed-source-usage.v5" and value["repository"] == REPOSITORY and
        value["campaignId"] == V6_CAMPAIGN and value["runCount"] == trusted["runCount"] and
        type(value["runCount"]) is int and value["runnerMinutesObserved"] == trusted["runnerMinutesObserved"] and
        type(value["runnerMinutesObserved"]) is int and type(value["runs"]) is list and
        len(value["runs"]) == trusted["runCount"] and value["sourceRunIds"] == trusted["sourceRunIds"] and
        value["previousPrefixSha256"] == V6_BASELINE_SHA256 and value["previousPrefixRunCount"] == V6_PRIOR_RUNS and
        type(value["previousPrefixRunCount"]) is int and value["previousPrefixMinutes"] == V6_PRIOR_MINUTES and
        type(value["previousPrefixMinutes"]) is int and
        value["previousPrefixPipeline"] == "5eb54e3c43ebf44de915574c1575c36df660847b" and
        _v6_equal(value["previousArtifactSnapshot"], V6_ARTIFACT_BASELINE) and
        _v6_equal(value["currentArtifactSnapshot"], trusted["artifactSnapshot"]), "r7.baseline_envelope")
    _r7_need(_v6_matches(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}\+00:00\Z",
        value["closedAt"]), "r7.baseline_capture_time")
    datetime.fromisoformat(value["closedAt"])
    old_raw = _v4_git(read_git, "show", value["previousPrefixPipeline"] + ":" + V6_SETTLED_USAGE_PATH)
    old, old_ids, hashes = validate_closed_baseline_v6(old_raw, read_git, history)
    old_rows = {str(row["id"]): row for row in old["runs"]}
    rows = {str(row["id"]): row for row in value["runs"] if type(row) is dict and type(row.get("id")) is int}
    _r7_need(len(rows) == trusted["runCount"] and set(old_rows) <= set(rows) and
        all(_v6_equal(row, rows[rid]) for rid, row in old_rows.items()), "r7.original168_unchanged")
    measured, sources = V6_PRIOR_MINUTES, set(V6_PRIOR_SOURCE_IDS)
    historical_full = {
        "40808362032": ("774c81d7ff22f962dcdef67a7a08f565846a4986",
            "2fed151bd3038f9ed80758dd23d3e655dbe281ee76ecb7a03987643903021740"),
        "40816927196": ("5eb54e3c43ebf44de915574c1575c36df660847b",
            "e343bc68535cdb9a82106b3d876efcd660bea10576f9edcb991b2c2ac271fc7f")}
    for rid, row in rows.items():
        if rid in old_ids:
            continue
        _r7_need(set(V6_PROVIDER_HEADERS) <= set(row) and
            set(row) <= set(V6_PROVIDER_HEADERS) | V6_PREFIX_DERIVED_FIELDS and
            row["status"] == "completed" and row["conclusion"] in V5_TERMINAL_CONCLUSIONS and
            type(row["run_attempt"]) is int and row["run_attempt"] == 1 and type(row.get("jobs")) is list,
            "r7.baseline_row")
        live = history.get(rid)
        _r7_need(_h5_public(live) and all(type(live.get(k)) is type(row[k]) and live.get(k) == row[k]
            for k in V6_PROVIDER_HEADERS), "r7.baseline_header_changed")
        table = {"total_count": len(row["jobs"]), "jobs": row["jobs"]}
        if rid == "40804517284":
            _h6_preparation_run_binding(live, V6_INTAKE_RECOVERY_SOURCE_PINS["preparation"])
            _r7_need(table["total_count"] == 1 and row["conclusion"] == "success", "r7.historical_preparation")
            job = row["jobs"][0]
            _r7_need(job.get("name") == "lock-preparation" and job.get("status") == "completed" and
                job.get("conclusion") == "success" and type(job.get("run_attempt")) is int and job["run_attempt"] == 1 and
                type(job.get("runner_id")) is int and job["runner_id"] > 0 and
                type(job.get("runner_name")) is str and bool(job["runner_name"]) and
                job.get("runner_group_name") == "GitHub Actions" and job.get("labels") == ["ubuntu-24.04"],
                "r7.historical_preparation_job")
            seconds = (timestamp(job["completed_at"]) - timestamp(job["started_at"])).total_seconds()
            _r7_need(0 <= seconds <= V6_PREPARATION_MINUTES * 60, "r7.historical_preparation_clock")
            minutes = math.ceil(seconds / 60)
            sources.add(rid)
        elif rid in historical_full:
            head, digest = historical_full[rid]
            _h6_source_run_binding(live)
            _r7_need(row["head_sha"] == head, "r7.historical_full_head")
            historical_raw = content_at(api, REQUEST, head)
            _r7_need(hashlib.sha256(historical_raw).hexdigest() == digest, "r7.historical_request_digest")
            historical = _v6_json(historical_raw)
            hpins = V6_STAGE_PINS if rid == "40816927196" else dict(V6_STAGE_PINS,
                priorValidationRuns=[], previousSourceHopCount=0)
            validate_request_v6(historical, hpins)
            minutes = observed_minutes_v6(table, historical)
            sources.add(rid)
        else:
            _r7_need(row["path"] != WORKFLOW, "r7.unreviewed_historical_execution")
            minutes = observed_minutes(table, None, legacy=True)
        _r7_need(type(row.get("observedRunnerMinutes")) is int and row["observedRunnerMinutes"] == minutes,
            "r7.baseline_actual_minutes")
        measured += minutes
        hashes[rid] = hashlib.sha256(json.dumps(row["jobs"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    _r7_need(measured == trusted["runnerMinutesObserved"] and sources == set(trusted["sourceRunIds"]),
        "r7.baseline_measured_total")
    return value, set(rows), hashes


def _h7_preparation_binding(run, pin):
    _v6_preparation_pin(pin)
    _r7_need(_h5_public(run) and type(run.get("id")) is int and str(run["id"]) == pin["runId"] and
        run.get("event") == "pull_request" and type(run.get("run_attempt")) is int and run["run_attempt"] == 1 and
        run.get("head_branch") == BRANCH and run.get("display_title") == R7_PREPARATION_TITLE and
        run.get("path") == WORKFLOW and run.get("head_sha") == pin["pipelineHead"] and
        [pr.get("number") for pr in run.get("pull_requests", [])] == [28], "r7.preparation_role")


def _h7_preparation(pins, history, current, generation, pipeline, api):
    pin = pins["preparation"]
    run = history.get(pin["runId"])
    _h7_preparation_binding(run, pin)
    _r7_need(run["status"] == "completed" and run["conclusion"] == "success" and
        timestamp(run["updated_at"]) <= timestamp(current["created_at"]), "r7.preparation_terminal")
    git(pipeline, "merge-base", "--is-ancestor", pin["pipelineHead"], current["head_sha"])
    table = _h5_jobs(api, run)
    _r7_need(table["total_count"] == 1, "r7.preparation_single_job")
    job = table["jobs"][0]
    _r7_need(job.get("name") == "lock-preparation" and job.get("status") == "completed" and
        job.get("conclusion") == "success" and type(job.get("runner_id")) is int and job["runner_id"] > 0 and
        type(job.get("runner_name")) is str and bool(job["runner_name"]) and
        job.get("runner_group_name") == "GitHub Actions" and job.get("labels") == ["ubuntu-24.04"],
        "r7.preparation_public_job")
    start, end = timestamp(job["started_at"]), timestamp(job["completed_at"])
    seconds = (end - start).total_seconds()
    _r7_need(0 <= seconds <= R7_PREPARATION_MINUTES * 60 and
        start <= timestamp(generation["startedAt"]) <= timestamp(generation["finishedAt"]) <= end,
        "r7.preparation_clock")
    table = api("/repos/" + REPOSITORY + "/actions/runs/" + pin["runId"] + "/artifacts?per_page=100")
    _r7_need(type(table) is dict and type(table.get("total_count")) is int and table["total_count"] == 1 and
        type(table.get("artifacts")) is list and len(table["artifacts"]) == 1, "r7.preparation_single_artifact")
    artifact = table["artifacts"][0]
    _r7_need(type(artifact) is dict and type(artifact.get("id")) is int and artifact["id"] == pin["artifactId"] and
        artifact.get("name") == R7_PREPARATION_ARTIFACT and type(artifact.get("size_in_bytes")) is int and
        0 < artifact["size_in_bytes"] <= V6_PREPARATION_ARTIFACT_BYTES and artifact.get("expired") is False and
        artifact.get("digest") == "sha256:" + pin["artifactSha256"], "r7.preparation_artifact")
    return math.ceil(seconds / 60), {"runId": pin["runId"], "pipelineHead": pin["pipelineHead"],
        "jobId": job["id"], "observedRunnerMinutes": math.ceil(seconds / 60), "artifactId": pin["artifactId"],
        "artifactSha256": pin["artifactSha256"], "artifactBytes": artifact["size_in_bytes"],
        "generationReceiptSha256": pin["generationReceiptSha256"], "status": "derived_only",
        "currentCandidateQualification": False}


def _h7_previous(request, pins, history, current, pipeline, api):
    if request["stageRound"] == 1:
        return 0, [], {}, list(V6_PROFILES)
    pin = pins["priorValidationRuns"][0]
    run = history.get(pin["runId"])
    _h6_source_run_binding(run)
    _r7_need(run.get("head_sha") == pin["pipelineHead"] and run.get("path") == WORKFLOW and
        run.get("status") == "completed" and run.get("conclusion") in V5_TERMINAL_CONCLUSIONS and
        timestamp(run["updated_at"]) <= timestamp(current["created_at"]), "r7.prior_validation_terminal")
    raw = content_at(api, REQUEST, pin["pipelineHead"])
    _r7_need(hashlib.sha256(raw).hexdigest() == pin["requestSha256"], "r7.prior_request_digest")
    prior = _v6_json(raw)
    validate_request_v7(prior, dict(pins, priorValidationRuns=[]))
    _r7_need(prior["stageRound"] == 1 and prior["profiles"] == list(V6_PROFILES) and
        all(_v6_equal(prior[k], request[k]) for k in ("sourceSha", "sourceTree", "manifestSha256",
            "inventorySha256", "settledUsageSha256", "lockPreparation", "sourceWitness")),
        "r7.same_frozen_source_only")
    git(pipeline, "merge-base", "--is-ancestor", pin["pipelineHead"], current["head_sha"])
    workflow_security_v7(content_at(api, WORKFLOW, pin["pipelineHead"]), request["sourceSha"])
    table = _h5_jobs(api, run)
    minutes = observed_minutes_v5(table, prior["profiles"], validation_budget_v7(prior))
    results = {job["name"][8:-1]: job["conclusion"] for job in table["jobs"]
        if job["name"].startswith("source (") and job["name"].endswith(")") and
        job["name"][8:-1] in V6_PROFILES}
    unresolved = [p for p in V6_PROFILES if results.get(p) != "success"]
    _r7_need(bool(unresolved) and set(unresolved) <= set(request["profiles"]), "r7.all_unresolved_selected")
    return minutes, [{"runId": pin["runId"], "pipelineHead": pin["pipelineHead"],
        "requestSha256": pin["requestSha256"], "observedRunnerMinutes": minutes,
        "sourceSha": request["sourceSha"], "profileResults": results,
        "unresolvedProfiles": unresolved, "sourceUnchanged": True, "oldF5EvidenceUsed": False}], results, unresolved


def workflow_security_v7(raw, source_sha):
    result = workflow_security_v5(raw, source_sha)
    text = raw.decode("utf-8")
    source_if = "    if: ${{ github.actor == 'fr-meyer' && needs.admission.result == 'success' }}"
    final_if = "    if: ${{ always() && github.actor == 'fr-meyer' && needs.admission.result == 'success' }}"
    admission = _h5_block(text, "admission", 2)
    admission_if = ["    if: >-",
        "      ${{ github.actor == 'fr-meyer' && github.repository == 'fr-meyer/openclaw' && github.event.repository.private == false &&",
        "          github.event.pull_request.number == 28 && github.event.pull_request.draft == true &&",
        "          github.event.pull_request.head.repo.full_name == 'fr-meyer/openclaw' &&",
        "          github.event.pull_request.head.ref == 'task/v107-source-binding' &&",
        "          github.event.pull_request.base.ref == 'release-pipeline/v105-image-only-20261024' &&",
        "          github.event.pull_request.base.sha == 'a65f70c5dad17b39bc3ee26ba92cde6d00bfb259' &&",
        "          github.run_attempt == 1 }}"]
    _r7_need(source_if in _h5_block(text, "source", 2) and final_if in _h5_block(text, "final", 2) and
        admission[:len(admission_if)] == admission_if and
        text.count("github.actor == 'fr-meyer'") == 3 and "||" not in text,
        "r7.workflow_owner_actor")
    return {**result, "profilePolicy": R7_POLICY, "maximumParallel": 3, "ownerActorRequired": True}


def history_checks_v7(request, event, env, pipeline, api, pins):
    request = validate_request_v7(request, pins)
    head = validate_event(event, env)
    now = datetime.now(timezone.utc)
    _r7_need(now < timestamp(R7_DEADLINE), "r7.history_deadline")
    live = api("/repos/" + REPOSITORY + "/pulls/28")
    _r7_need(validate_event(dict(event, pull_request=live), env) == head, "r7.live_pr_changed")
    for branch, expected in ((BASE_BRANCH, TARGET_BRANCH_TIP), (V6_SOURCE_BRANCH, request["sourceSha"])):
        ref = api("/repos/" + REPOSITORY + "/git/ref/heads/" + branch)
        _r7_need(ref.get("ref") == "refs/heads/" + branch and ref.get("object", {}).get("type") == "commit" and
            ref["object"].get("sha") == expected, "r7.live_branch_tip")
    history = _h6_branch_history(api)
    baseline, prefix_ids, hashes = validate_closed_baseline_v7((pipeline / R7_SETTLED_USAGE_PATH).read_bytes(),
        lambda *args: git(pipeline, *args), history, api, pins)
    expected = [*pins["baseline"]["sourceRunIds"], pins["preparation"]["runId"],
        *[p["runId"] for p in pins["priorValidationRuns"]], env["GITHUB_RUN_ID"]]
    actual = {rid for rid, run in history.items() if run.get("path") == WORKFLOW}
    _r7_need(actual == set(expected) and len(expected) == len(set(expected)), "r7.exact_execution_set")
    for rid in actual:
        run = history[rid]
        if rid == pins["preparation"]["runId"]:
            _h7_preparation_binding(run, pins["preparation"])
        elif rid == "40804517284":
            _h6_preparation_run_binding(run, V6_INTAKE_RECOVERY_SOURCE_PINS["preparation"])
        else:
            _h6_source_run_binding(run)
    current = history[env["GITHUB_RUN_ID"]]
    _r7_need(current.get("head_sha") == head and current.get("status") == "in_progress" and
        datetime.fromisoformat(baseline["closedAt"]) <= timestamp(current["created_at"]) <= now,
        "r7.current_validation_identity")
    for rid in pins["baseline"]["sourceRunIds"]:
        git(pipeline, "merge-base", "--is-ancestor", history[rid]["head_sha"], head)
    workflow = workflow_security_v7((pipeline / WORKFLOW).read_bytes(), request["sourceSha"])
    generation = validate_re2js_generation_receipt_v7((pipeline / R7_PREPARATION_PROOF_PATH).read_bytes(), pins)
    prep_minutes, preparation = _h7_preparation(pins, history, current, generation, pipeline, api)
    previous_minutes, previous, results, unresolved = _h7_previous(request, pins, history, current, pipeline, api)
    table = _h5_jobs(api, current)
    admission = [j for j in table["jobs"] if j.get("name") == "admission"]
    _r7_need(len(admission) == 1 and admission[0].get("status") == "in_progress" and
        type(admission[0].get("runner_id")) is int and admission[0]["runner_id"] > 0 and
        type(admission[0].get("runner_name")) is str and bool(admission[0]["runner_name"]) and
        admission[0].get("runner_group_name") == "GitHub Actions" and admission[0].get("labels") == ["ubuntu-24.04"],
        "r7.current_public_admission")
    current_facts = ancillary_job_snapshot(table, now, False)
    names = {"admission", "final", "source (${{ matrix.profile }})", *["source (" + p + ")" for p in request["profiles"]]}
    _r7_need(all(j.get("name") in names for j in table["jobs"]) and
        current_facts["observedAcquiredRunnerMinutes"] <= R7_ADMISSION_MINUTES, "r7.current_job_booking")
    paths = {row["path"] for row in baseline["runs"] if row["path"] != WORKFLOW}
    pipeline_heads = {row["head_sha"] for row in baseline["runs"] if row["head_branch"] == BRANCH} | \
        {head, pins["preparation"]["pipelineHead"], *[p["pipelineHead"] for p in pins["priorValidationRuns"]]}
    source_heads = {R7_BASE_SOURCE, *[p["sourceSha"] for p in pins["sourceHops"]]}
    observed, ancillary, pending, artifacts, artifact_ids = 0, [], [], [], set()
    artifact_bytes = pins["baseline"]["artifactSnapshot"]["bytes"]
    for rid, run in sorted(history.items()):
        if rid in prefix_ids:
            continue
        if run.get("path") != WORKFLOW:
            branch = run.get("head_branch")
            correct = (branch == BRANCH and run.get("head_sha") in pipeline_heads) or \
                (branch == V6_SOURCE_BRANCH and run.get("head_sha") in source_heads)
            events = ("pull_request", "pull_request_target") if branch == BRANCH else ("push",)
            _r7_need(_h5_public(run) and correct and run.get("event") in events and run.get("path") in paths and
                type(run.get("run_attempt")) is int and run["run_attempt"] == 1 and
                run.get("status") in ("completed", "in_progress", "queued", "waiting", "pending") and
                (run["status"] != "completed" or run.get("conclusion") in V5_TERMINAL_CONCLUSIONS),
                "r7.new_ancillary_binding")
            facts = ancillary_job_snapshot(_h5_jobs(api, run), now, run["status"] == "completed")
            observed += facts["observedAcquiredRunnerMinutes"]
            ancillary.append({"runId": rid, **facts})
            if not facts["usageComplete"]:
                pending.append(rid)
        row = _h5_artifacts(api, run)
        _r7_need(not artifact_ids.intersection(row["ids"]), "r7.artifact_duplicate")
        artifact_ids.update(row["ids"])
        artifact_bytes += row["bytes"]
        artifacts.append({"runId": rid, **row})
    _r7_need(observed <= R7_ANCILLARY_MINUTES and (not pending or observed < R7_ANCILLARY_MINUTES),
        "r7.ancillary_limit")
    _r7_need(artifact_bytes <= V6_DIAGNOSTIC_BYTES, "r7.artifact_storage_limit")
    return {**booking_v7(request, pins, prep_minutes, previous_minutes, observed),
        "deadlineEpoch": int(timestamp(R7_DEADLINE).timestamp()),
        "profileMatrix": [{"profile": p, "minutes": R7_PROFILE_MINUTES[p]} for p in request["profiles"]],
        "selectedProfileCount": len(request["profiles"]), "preparationReceipt": preparation,
        "priorValidationReceipts": previous, "priorValidationProfileResults": results,
        "priorUnresolvedProfiles": unresolved, "historicalCoverageReused": False, "reusedProfileCount": 0,
        "closedBaselineRuns": R7_PRIOR_RUNS, "closedBaselineMinutes": R7_PRIOR_MINUTES,
        "closedBaselineSha256": R7_BASELINE_SHA256, "historicalJobTableSha256": hashes,
        "newAncillaryRecords": ancillary, "pendingAncillaryRunIds": pending,
        "ancillaryUsageComplete": not pending, "artifactRecords": artifacts,
        "observedRetainedWorkflowArtifactBytes": artifact_bytes,
        "artifactObservationComplete": all(row["observationComplete"] for row in artifacts),
        "artifactBudgetIsNotWholeDiagnosticCustodyProof": True, "workflowSecurity": workflow,
        "currentAdmissionObservation": current_facts, "historicalConclusionsRetained": True,
        "productionAuthorized": False, "imageBuilt": False}


def validate_operational_request(request):
    if type(request) is dict and request.get("schema") == R7_SCHEMA:
        return validate_request_v7(request, R7_STAGE_PINS)
    return validate_request_v6(request, V6_STAGE_PINS)


def operational_input_paths(request):
    validate_operational_request(request)
    return ((R7_SETTLED_USAGE_PATH, R7_PREPARATION_PROOF_PATH) if request["schema"] == R7_SCHEMA else
        (V6_SETTLED_USAGE_PATH, V6_PREPARATION_PROOF_PATH))


def validate_operational_generation(request, raw):
    if request["schema"] == R7_SCHEMA:
        return validate_re2js_generation_receipt_v7(raw, R7_STAGE_PINS)
    return validate_generation_receipt_v6(raw, V6_STAGE_PINS)


def history_checks_for_operational_request(request, event, env, pipeline, api):
    if request["schema"] == R7_SCHEMA:
        return history_checks_v7(request, event, env, pipeline, api, R7_STAGE_PINS)
    return history_checks_v6(request, event, env, pipeline, api, V6_STAGE_PINS)


def verify_operational_source(request, pipeline, read_git):
    _, path = operational_input_paths(request)
    raw = (pipeline / path).read_bytes()
    if request["schema"] == R7_SCHEMA:
        return verify_source_equivalence_v7(request, R7_STAGE_PINS, read_git, raw)
    return verify_source_equivalence_v6(request, V6_STAGE_PINS, read_git, raw)


def runtime_refusal_code_v7(error):
    if isinstance(error, R7ContractRefusal):
        code = error.args[0] if len(error.args) == 1 else None
        return code if type(code) is str and code in R7_RUNTIME_REFUSAL_CODES else "r7.unprojected"
    return runtime_refusal_code_v6(error)

R7_RUNTIME_REFUSAL_CODES = frozenset(('r7.actual_usage', 'r7.all15_fresh', 'r7.all_unresolved_selected', 'r7.ancillary_limit', 'r7.artifact_duplicate', 'r7.artifact_storage_limit', 'r7.authentic_registry_binding', 'r7.baseline_actual_minutes', 'r7.baseline_capture_time', 'r7.baseline_digest', 'r7.baseline_envelope', 'r7.baseline_header_changed', 'r7.baseline_measured_total', 'r7.baseline_row', 'r7.baseline_source_runs', 'r7.budget_policy', 'r7.closed_baseline_pins', 'r7.closed_request', 'r7.current_job_booking', 'r7.current_public_admission', 'r7.current_validation_identity', 'r7.exact_base_dependencies', 'r7.exact_execution_set', 'r7.exact_original_lock_shape', 'r7.exact_parent_child_edge', 'r7.exact_parent_snapshot', 'r7.exact_prior_runs', 'r7.exact_reviewed_pins', 'r7.exact_two_source_hops', 'r7.fixed_profiles', 'r7.generated_lock_source_binding', 'r7.generation_clock_bound', 'r7.generation_clock_shape', 'r7.generation_digest', 'r7.generation_identity', 'r7.generation_outcome', 'r7.historical_full_head', 'r7.historical_preparation', 'r7.historical_preparation_clock', 'r7.historical_preparation_job', 'r7.historical_request_digest', 'r7.history_deadline', 'r7.hop_identity', 'r7.hop_scope', 'r7.live_branch_tip', 'r7.live_pr_changed', 'r7.lock_base_and_workspace', 'r7.new_ancillary_binding', 'r7.once_full_once_targeted', 'r7.original168_unchanged', 'r7.preparation_artifact', 'r7.preparation_clock', 'r7.preparation_context', 'r7.preparation_package_unchanged', 'r7.preparation_pins', 'r7.preparation_public_job', 'r7.preparation_role', 'r7.preparation_single_artifact', 'r7.preparation_single_job', 'r7.preparation_source_original_lock', 'r7.preparation_terminal', 'r7.preserved_package_and_prepared_controls', 'r7.prior_request_digest', 'r7.prior_validation_pins', 'r7.prior_validation_terminal', 'r7.registry_clock_shape', 'r7.registry_minimum_age', 'r7.round_booking', 'r7.same_frozen_source_only', 'r7.source_witness', 'r7.stage_pins', 'r7.total_minute_ceiling', 'r7.unique_executions', 'r7.unrelated_resolution_or_format_change', 'r7.unreviewed_historical_execution', 'r7.workflow_owner_actor'))


# The official annotated tag is public, immutable review input. Its fixed bytes
# were matched to the official GitHub ref/tag, verified payload and signature.
# This is not a new local GPG-verification or full-source qualification claim.
R7_TAG_FIXTURE = "scripts/fork-release/fixtures/v2026.10.8.official.tag.raw"
R7_TAG_BYTES = 1028
R7_TAG_SHA256 = "e675eff97e84b1a79c64a2e2b83d23bf03498ccdcf5bf41eede0af92ed1bad3c"
R7_TAG_OBJECT = "e07a2f67d11717ed39aa2fa07bbe9342376ebfbf"
R7_TAG_COMMIT = "dc2523e5a5c7a309517fd7fa834add938231d526"
R7_TAG_NAME = "v2026.10.8"
R7_TAG_REF = "refs/tags/v2026.10.8"


def reuse_upstream_tag_v7(pipeline, source, request, inventory, inspect, env, context):
    """Replace only the round-2 official-tag fetch after ordinary donor closure.

    No caller-supplied path/ref/URL, alternate transport, object fallback or source
    mutation is accepted. Only the fixed tag object and its exact tag ref may be
    written; the already-complete required commit closure is still the donor's.
    """
    _r7_need(type(request) is dict and request.get("schema") == R7_SCHEMA and
        request.get("profilePolicy") == R7_POLICY and type(request.get("stageRound")) is int and
        request["stageRound"] == 2 and context.get("request") == request,
        "r7.tag_reuse_context")
    validate_request_v7(request, R7_STAGE_PINS)
    _r7_need(inventory.get("upstream", {}).get("tag") == R7_TAG_NAME and
        inventory["upstream"].get("tagObject") == R7_TAG_OBJECT and
        inventory["upstream"].get("commit") == R7_TAG_COMMIT,
        "r7.tag_reuse_inventory")
    fixture = Path(pipeline) / R7_TAG_FIXTURE
    _r7_need(fixture.is_file() and not fixture.is_symlink() and
        fixture.resolve(strict=True) == fixture.absolute() and
        fixture.stat().st_uid == os.geteuid() and fixture.stat().st_nlink == 1 and
        fixture.stat().st_size == R7_TAG_BYTES, "r7.tag_reuse_fixture_file")
    before = fixture.stat()
    with fixture.open("rb") as handle:
        raw = handle.read(R7_TAG_BYTES + 1)
        after = os.fstat(handle.fileno())
    def fixture_identity(info):
        # stat_result sequence equality omits subsecond fields on some hosts.
        # Reading may change atime; content/identity/ownership changes must refuse.
        return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
                info.st_mode, info.st_uid, info.st_gid, info.st_nlink)
    _r7_need(fixture_identity(before) == fixture_identity(after) and
        fixture_identity(fixture.stat()) == fixture_identity(after) and len(raw) == R7_TAG_BYTES and
        hashlib.sha256(raw).hexdigest() == R7_TAG_SHA256 and
        hashlib.sha1(b"tag " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == R7_TAG_OBJECT and
        raw.startswith(("object " + R7_TAG_COMMIT + "\ntype commit\ntag " + R7_TAG_NAME + "\n").encode()),
        "r7.tag_reuse_fixture_identity")
    try:
        base_present = (inspect(source, "rev-parse", "--is-shallow-repository") == b"false" and
            inspect(source, "cat-file", "-t", R7_TAG_COMMIT) == b"commit")
    except subprocess.CalledProcessError:
        base_present = False
    _r7_need(base_present, "r7.tag_reuse_base_object")
    expected = (request["sourceSha"].encode(), request["sourceTree"].encode(), b"")
    def source_state():
        return (inspect(source, "rev-parse", "HEAD"), inspect(source, "rev-parse", "HEAD^{tree}"),
                inspect(source, "status", "--porcelain=v1", "--untracked-files=all"))
    _r7_need(source_state() == expected, "r7.tag_reuse_source_identity")
    # A symbolic tag ref, including a dangling one, is never treated as absence.
    try:
        inspect(source, "symbolic-ref", "--quiet", R7_TAG_REF)
    except subprocess.CalledProcessError as error:
        _r7_need(error.returncode == 1, "r7.tag_reuse_ref_read")
    else:
        _r7_need(False, "r7.tag_reuse_ref_conflict")
    refs = inspect(source, "for-each-ref", "--format=%(refname) %(objectname)", R7_TAG_REF)
    _r7_need(refs in (b"", (R7_TAG_REF + " " + R7_TAG_OBJECT).encode()),
        "r7.tag_reuse_ref_conflict")
    # Reuse the existing owned phase/session/deadline owner. Public fixed object
    # hashes may appear in its ordinary Git output; no credential is provided.
    with tempfile.TemporaryDirectory(prefix="v108-official-tag-", dir=Path(pipeline).parent) as private:
        snapshot = Path(private) / "verified.tag"
        fd = os.open(snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            _r7_need(handle.write(raw) == len(raw), "r7.tag_reuse_snapshot_write")
            handle.flush()
            os.fsync(handle.fileno())
        for ordinal, args in enumerate((
                ("hash-object", "-t", "tag", "-w", "--no-filters", "--", str(snapshot)),
                ("update-ref", "--no-deref", R7_TAG_REF, R7_TAG_OBJECT,
                 R7_TAG_OBJECT if refs else "0" * 40)), 1):
            argv = ["git", "--no-replace-objects", "-C", str(source), "-c", "credential.helper=",
                    "-c", "core.hooksPath=/dev/null", "-c", "maintenance.auto=0", "-c", "gc.auto=0",
                    "-c", "protocol.allow=never", *args]
            result = phase_process(argv, source, env, context, "source-tag-reuse", ordinal)
            _r7_need(result.returncode == 0 and not result.timed_out, "r7.tag_reuse_write_failed")
    _r7_need(inspect(source, "cat-file", "-t", R7_TAG_OBJECT) == b"tag" and
        inspect(source, "cat-file", "-s", R7_TAG_OBJECT) == str(R7_TAG_BYTES).encode() and
        inspect(source, "rev-parse", "--verify", R7_TAG_REF) == R7_TAG_OBJECT.encode() and
        inspect(source, "rev-parse", "--verify", R7_TAG_REF + "^{commit}") == R7_TAG_COMMIT.encode() and
        source_state() == expected and fixture_identity(fixture.stat()) == fixture_identity(after),
        "r7.tag_reuse_final_binding")


R7_RUNTIME_REFUSAL_CODES = R7_RUNTIME_REFUSAL_CODES | frozenset((
    "r7.tag_reuse_context", "r7.tag_reuse_inventory", "r7.tag_reuse_fixture_file",
    "r7.tag_reuse_fixture_identity", "r7.tag_reuse_base_object", "r7.tag_reuse_source_identity",
    "r7.tag_reuse_ref_read", "r7.tag_reuse_ref_conflict", "r7.tag_reuse_write_failed",
    "r7.tag_reuse_snapshot_write", "r7.tag_reuse_final_binding"))



from composite_closed_usage import resolve_composite

# Closed approved fixture-only successor. Historical R7/R6 contracts stay unchanged.
R8_SCHEMA = "openclaw.fork-source-validation-request.v8"
R8_POLICY = "crabline-fixture-successor-v1"
R8_AUTHORIZATION = "future-v108-crabline-successor-20261029T1432Z"
R8_DEADLINE = "2026-10-30T08:03:19Z"
R8_SOURCE_SCOPE = "approved-crabline-locator-and-age-hygiene-only"
R8_BASE_SOURCE = "76522eaa2dd93a4933b5c87f7451eab1d458f8be"
R8_BASE_TREE = "28adf129927ab5f4589f90f599fe6b76d790a015"
R8_SOURCE = "e6c4786dafbc8308661ea8fa14a81e06873d1630"
R8_TREE = "318a14351a7049d9d613a928edb0cfe69311d201"
R8_SOURCE_PATHS = ["pnpm-workspace.yaml", R7_SECURITY_TEST_PATH]
R8_SOURCE_BLOBS = {
    "pnpm-workspace.yaml": "ee9200c50d6bd8edd5ae522e3ab4033b85627227d6df8b7d1cf40140e114e934",
    R7_SECURITY_TEST_PATH: "161df59dfaf3f8f3ed5cc48142e1c1b2cc051cd1698b4b8fdbfe881c99e9709e",
    V4_LEDGER_PATH: "3fc1c483e77b36fef60b939fa9a797008cab3644d53b0fb3a22f70bd4337a71e",
}
R8_PROFILE_MINUTES = dict(R7_PROFILE_MINUTES)
R8_ADMISSION_MINUTES = 30
R8_FINAL_MINUTES = 10
R8_FULL_MINUTES = 1075
R8_TARGETED_MINUTES = 300
R8_ANCILLARY_MINUTES = 50
R8_NEW_MINUTES = 1425
R8_DIAGNOSTIC_BYTES = V6_DIAGNOSTIC_BYTES
R8_PRIOR_RUNS = 243
R8_PRIOR_MINUTES = 2437
R8_BASELINE_SHA256 = "2188800522988ac5837c554db7d4be01186f1031a86bd782deab839765919fd8"
R8_RESOLVED_SHA256 = "de4bede2d3c1bece03aa7093097c1fd89f9f8014f307507583a7a953dfeea9c3"
R8_ARTIFACT_BASELINE = {"count": 22, "bytes": 387192}
R8_BASELINE_SOURCE_IDS = (*R7_BASELINE_SOURCE_IDS, "40851844749", "40856125444")
R8_BASELINE_CLOSED_AT = "2026-10-29T14:09:37.976704+00:00"
R8_SETTLED_USAGE_PATH = "scripts/fork-release/candidates/v2026.10.8-source-only/crabline-settled-usage.json"
R8_PRIOR_STAGE_USAGE_PATH = "scripts/fork-release/candidates/v2026.10.8-source-only/re2js-closed-provider-usage.json"
R8_STAGE_PINS = {'sourceSha': 'e6c4786dafbc8308661ea8fa14a81e06873d1630', 'sourceTree': '318a14351a7049d9d613a928edb0cfe69311d201', 'manifestSha256': '8f4bbce1f53bbe8d81462a14fe7c7118433844c506a8286062e01985040bb4a1', 'inventorySha256': '2f6f23348b029b1de52bef8a40fcfaee67a1fef8c2bd8cb6a4bcf9ff481d6a5d', 'baseline': {'sha256': '2188800522988ac5837c554db7d4be01186f1031a86bd782deab839765919fd8', 'resolvedSha256': 'de4bede2d3c1bece03aa7093097c1fd89f9f8014f307507583a7a953dfeea9c3', 'runCount': 243, 'runnerMinutesObserved': 2437, 'sourceRunIds': ['40616416909', '40609889437', '40607329263', '40639374411', '40647629182', '40681376480', '40688279536', '40706982753', '40804517284', '40808362032', '40816927196', '40851844749', '40856125444'], 'artifactSnapshot': {'count': 22, 'bytes': 387192}, 'closedAt': '2026-10-29T14:09:37.976704+00:00'}, 'priorValidationRuns': [], 'sourceWitness': {'schema': 'openclaw.v108.crabline-source-equivalence.v1', 'scope': 'approved-crabline-locator-and-age-hygiene-only', 'closedBaselineSha256': '2188800522988ac5837c554db7d4be01186f1031a86bd782deab839765919fd8', 'hops': [{'sourceSha': 'e6c4786dafbc8308661ea8fa14a81e06873d1630', 'sourceTree': '318a14351a7049d9d613a928edb0cfe69311d201', 'step': {'parentSha': '76522eaa2dd93a4933b5c87f7451eab1d458f8be', 'parentTree': '28adf129927ab5f4589f90f599fe6b76d790a015', 'changedPaths': ['pnpm-workspace.yaml', 'test/v108-remediation-security.test.mjs'], 'unchangedTreeSha256': 'c2e70ede5490be963a54e6aea479149fff222bd7611003337d43807d2c0decd4'}}]}}


class R8ContractRefusal(ValueError):
    pass


def _r8_need(value, code):
    if not value:
        raise R8ContractRefusal(code)


def _r8_pins(pins):
    fields = {"sourceSha", "sourceTree", "manifestSha256", "inventorySha256", "baseline",
              "priorValidationRuns", "sourceWitness"}
    _r8_need(type(pins) is dict and set(pins) == fields and
        pins["sourceSha"] == R8_SOURCE and pins["sourceTree"] == R8_TREE and
        all(_r7_digest(pins[k]) for k in ("manifestSha256", "inventorySha256")), "r8.stage_pins")
    b = pins["baseline"]
    _r8_need(type(b) is dict and set(b) == {"sha256", "resolvedSha256", "runCount",
        "runnerMinutesObserved", "sourceRunIds", "artifactSnapshot", "closedAt"} and
        b["sha256"] == R8_BASELINE_SHA256 and b["resolvedSha256"] == R8_RESOLVED_SHA256 and
        type(b["runCount"]) is int and b["runCount"] == R8_PRIOR_RUNS and
        type(b["runnerMinutesObserved"]) is int and b["runnerMinutesObserved"] == R8_PRIOR_MINUTES and
        _v6_equal(b["artifactSnapshot"], R8_ARTIFACT_BASELINE) and
        b["sourceRunIds"] == list(R8_BASELINE_SOURCE_IDS) and b["closedAt"] == R8_BASELINE_CLOSED_AT,
        "r8.closed_baseline_pins")
    prior = pins["priorValidationRuns"]
    _r8_need(type(prior) is list and len(prior) <= 1 and all(type(p) is dict and
        set(p) == {"runId", "pipelineHead", "requestSha256"} and
        _v6_matches(r"[1-9][0-9]{0,19}\Z", p["runId"]) and
        _v6_matches(r"[0-9a-f]{40}\Z", p["pipelineHead"]) and _r7_digest(p["requestSha256"])
        for p in prior), "r8.prior_validation_pins")
    ids = [*R8_BASELINE_SOURCE_IDS, *[p["runId"] for p in prior]]
    _r8_need(len(ids) == len(set(ids)), "r8.unique_executions")
    w = pins["sourceWitness"]
    _r8_need(type(w) is dict and set(w) == {"schema", "scope", "closedBaselineSha256", "hops"} and
        w["schema"] == "openclaw.v108.crabline-source-equivalence.v1" and w["scope"] == R8_SOURCE_SCOPE and
        w["closedBaselineSha256"] == R8_BASELINE_SHA256 and type(w["hops"]) is list and len(w["hops"]) == 1,
        "r8.source_witness")
    h = w["hops"][0]
    _r8_need(type(h) is dict and set(h) == {"sourceSha", "sourceTree", "step"} and
        h["sourceSha"] == R8_SOURCE and h["sourceTree"] == R8_TREE, "r8.hop_identity")
    step = h["step"]
    _r8_need(type(step) is dict and set(step) ==
        {"parentSha", "parentTree", "changedPaths", "unchangedTreeSha256"} and
        step["parentSha"] == R8_BASE_SOURCE and step["parentTree"] == R8_BASE_TREE and
        step["changedPaths"] == R8_SOURCE_PATHS and _r7_digest(step["unchangedTreeSha256"]), "r8.hop_scope")
    return pins


def validation_budget_v8(value):
    _r8_need(type(value) is dict and value.get("schema") == R8_SCHEMA and
        value.get("profilePolicy") == R8_POLICY and type(value.get("stageRound")) is int and
        value["stageRound"] in (1, 2), "r8.budget_policy")
    return {"admissionMinutes": R8_ADMISSION_MINUTES, "finalMinutes": R8_FINAL_MINUTES,
        "profileMinutes": dict(R8_PROFILE_MINUTES),
        "roundMaximumMinutes": R8_FULL_MINUTES if value["stageRound"] == 1 else R8_TARGETED_MINUTES,
        "ancillaryMinutes": R8_ANCILLARY_MINUTES, "stageMaximumMinutes": R8_NEW_MINUTES}


def validate_request_v8(value, pins):
    pins = _r8_pins(pins)
    fields = {"schema", "campaignId", "profilePolicy", "sourceAuthorization", "stageRound",
        "lifetimeOperatorRound", "profiles", "sourceSha", "sourceTree", "manifestSha256",
        "inventorySha256", "settledUsageSha256", "priorRunIds", "lockPreparation", "sourceWitness"}
    _r8_need(type(value) is dict and set(value) == fields and value["schema"] == R8_SCHEMA and
        value["campaignId"] == V6_CAMPAIGN and value["profilePolicy"] == R8_POLICY and
        value["sourceAuthorization"] == R8_AUTHORIZATION, "r8.closed_request")
    _r8_need(all(value[k] == pins[k] for k in ("sourceSha", "sourceTree", "manifestSha256", "inventorySha256")) and
        value["settledUsageSha256"] == R8_BASELINE_SHA256 and
        _v6_equal(value["sourceWitness"], pins["sourceWitness"]) and
        _v6_equal(value["lockPreparation"], R7_STAGE_PINS["preparation"]), "r8.exact_reviewed_pins")
    number = value["stageRound"]
    _r8_need(type(number) is int and number in (1, 2) and
        type(value["lifetimeOperatorRound"]) is int and value["lifetimeOperatorRound"] == number + 11 and
        len(pins["priorValidationRuns"]) == number - 1, "r8.once_full_once_targeted")
    _r8_need(value["priorRunIds"] == [*R8_BASELINE_SOURCE_IDS,
        *[p["runId"] for p in pins["priorValidationRuns"]]], "r8.exact_prior_runs")
    p = value["profiles"]
    _r8_need(type(p) is list and bool(p) and all(type(x) is str and x in R8_PROFILE_MINUTES for x in p) and
        len(p) == len(set(p)), "r8.fixed_profiles")
    budget = validation_budget_v8(value)
    _r8_need(R8_ADMISSION_MINUTES + R8_FINAL_MINUTES + sum(R8_PROFILE_MINUTES[x] for x in p)
        <= budget["roundMaximumMinutes"], "r8.round_booking")
    _r8_need(number != 1 or p == list(V6_PROFILES), "r8.all15_fresh")
    return value


def verify_source_equivalence_v8(request, pins, read_git, generation_raw):
    validate_request_v8(request, pins)
    # This generation is immutable historical D evidence, already in the243-run
    # baseline. It authorizes no new preparation or transferred qualification.
    generation = validate_re2js_generation_receipt_v7(generation_raw, R7_STAGE_PINS)
    h = request["sourceWitness"]["hops"][0]
    proof = _v4_verify_step(read_git, h["sourceSha"], h["sourceTree"], h["step"], initial=False)
    for path in ("package.json", "pnpm-lock.yaml"):
        before = _v4_git(read_git, "show", R8_BASE_SOURCE + ":" + path)
        after = _v4_git(read_git, "show", R8_SOURCE + ":" + path)
        expected = R7_STAGE_PINS["preparation"]["packageSha256" if path == "package.json" else "lockSha256"]
        _r8_need(before == after and hashlib.sha256(after).hexdigest() == expected,
            "r8.dependencies_unchanged")
    for path, expected in R8_SOURCE_BLOBS.items():
        _r8_need(hashlib.sha256(_v4_git(read_git, "show", R8_SOURCE + ":" + path)).hexdigest() == expected,
            "r8.exact_source_fixture_bytes")
    return {"schema": "openclaw.v108.verified-crabline-source-equivalence.v1", "scope": R8_SOURCE_SCOPE,
        "baseSourceSha": R8_BASE_SOURCE, "baseSourceTree": R8_BASE_TREE,
        "sourceSha": R8_SOURCE, "sourceTree": R8_TREE, "hops": [proof],
        "unchangedOutsideApprovedSourceAndLedger": True, "packageAndLockUnchanged": True,
        "historicalGenerationReceiptSha256": R7_STAGE_PINS["preparation"]["generationReceiptSha256"],
        "historicalCoverageReused": False, "sameSourceReceiptRelabeled": False,
        "productionAuthorized": False, "imageBuilt": False}

def reuse_upstream_tag_v8(pipeline, source, request, inventory, inspect, env, context):
    """Use the fixed official tag in either approved R8 round after ordinary donor closure.

    No caller-supplied path/ref/URL, alternate transport, object fallback or source
    mutation is accepted. Only the fixed tag object and its exact tag ref may be
    written; the already-complete required commit closure is still the donor's.
    """
    _r8_need(type(request) is dict and request.get("schema") == R8_SCHEMA and
        context.get("request") == request, "r8.tag_reuse_context")
    validate_request_v8(request, R8_STAGE_PINS)
    _r7_need(inventory.get("upstream", {}).get("tag") == R7_TAG_NAME and
        inventory["upstream"].get("tagObject") == R7_TAG_OBJECT and
        inventory["upstream"].get("commit") == R7_TAG_COMMIT,
        "r7.tag_reuse_inventory")
    fixture = Path(pipeline) / R7_TAG_FIXTURE
    _r7_need(fixture.is_file() and not fixture.is_symlink() and
        fixture.resolve(strict=True) == fixture.absolute() and
        fixture.stat().st_uid == os.geteuid() and fixture.stat().st_nlink == 1 and
        fixture.stat().st_size == R7_TAG_BYTES, "r7.tag_reuse_fixture_file")
    before = fixture.stat()
    with fixture.open("rb") as handle:
        raw = handle.read(R7_TAG_BYTES + 1)
        after = os.fstat(handle.fileno())
    def fixture_identity(info):
        # stat_result sequence equality omits subsecond fields on some hosts.
        # Reading may change atime; content/identity/ownership changes must refuse.
        return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
                info.st_mode, info.st_uid, info.st_gid, info.st_nlink)
    _r7_need(fixture_identity(before) == fixture_identity(after) and
        fixture_identity(fixture.stat()) == fixture_identity(after) and len(raw) == R7_TAG_BYTES and
        hashlib.sha256(raw).hexdigest() == R7_TAG_SHA256 and
        hashlib.sha1(b"tag " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == R7_TAG_OBJECT and
        raw.startswith(("object " + R7_TAG_COMMIT + "\ntype commit\ntag " + R7_TAG_NAME + "\n").encode()),
        "r7.tag_reuse_fixture_identity")
    try:
        base_present = (inspect(source, "rev-parse", "--is-shallow-repository") == b"false" and
            inspect(source, "cat-file", "-t", R7_TAG_COMMIT) == b"commit")
    except subprocess.CalledProcessError:
        base_present = False
    _r7_need(base_present, "r7.tag_reuse_base_object")
    expected = (request["sourceSha"].encode(), request["sourceTree"].encode(), b"")
    def source_state():
        return (inspect(source, "rev-parse", "HEAD"), inspect(source, "rev-parse", "HEAD^{tree}"),
                inspect(source, "status", "--porcelain=v1", "--untracked-files=all"))
    _r7_need(source_state() == expected, "r7.tag_reuse_source_identity")
    # A symbolic tag ref, including a dangling one, is never treated as absence.
    try:
        inspect(source, "symbolic-ref", "--quiet", R7_TAG_REF)
    except subprocess.CalledProcessError as error:
        _r7_need(error.returncode == 1, "r7.tag_reuse_ref_read")
    else:
        _r7_need(False, "r7.tag_reuse_ref_conflict")
    refs = inspect(source, "for-each-ref", "--format=%(refname) %(objectname)", R7_TAG_REF)
    _r7_need(refs in (b"", (R7_TAG_REF + " " + R7_TAG_OBJECT).encode()),
        "r7.tag_reuse_ref_conflict")
    # Reuse the existing owned phase/session/deadline owner. Public fixed object
    # hashes may appear in its ordinary Git output; no credential is provided.
    with tempfile.TemporaryDirectory(prefix="v108-official-tag-", dir=Path(pipeline).parent) as private:
        snapshot = Path(private) / "verified.tag"
        fd = os.open(snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            _r7_need(handle.write(raw) == len(raw), "r7.tag_reuse_snapshot_write")
            handle.flush()
            os.fsync(handle.fileno())
        for ordinal, args in enumerate((
                ("hash-object", "-t", "tag", "-w", "--no-filters", "--", str(snapshot)),
                ("update-ref", "--no-deref", R7_TAG_REF, R7_TAG_OBJECT,
                 R7_TAG_OBJECT if refs else "0" * 40)), 1):
            argv = ["git", "--no-replace-objects", "-C", str(source), "-c", "credential.helper=",
                    "-c", "core.hooksPath=/dev/null", "-c", "maintenance.auto=0", "-c", "gc.auto=0",
                    "-c", "protocol.allow=never", *args]
            result = phase_process(argv, source, env, context, "source-tag-reuse", ordinal)
            _r7_need(result.returncode == 0 and not result.timed_out, "r7.tag_reuse_write_failed")
    _r7_need(inspect(source, "cat-file", "-t", R7_TAG_OBJECT) == b"tag" and
        inspect(source, "cat-file", "-s", R7_TAG_OBJECT) == str(R7_TAG_BYTES).encode() and
        inspect(source, "rev-parse", "--verify", R7_TAG_REF) == R7_TAG_OBJECT.encode() and
        inspect(source, "rev-parse", "--verify", R7_TAG_REF + "^{commit}") == R7_TAG_COMMIT.encode() and
        source_state() == expected and fixture_identity(fixture.stat()) == fixture_identity(after),
        "r7.tag_reuse_final_binding")
"""R8 insertion fragment: pure validation plus caller-injected read-only transport.

The maintained owner supplies the reviewed R8 request/pins/constants, the unchanged
R7/shared history helpers, and the separately reviewed resolve_composite function.
This file neither imports a driver nor changes any historical policy or literal.
"""

import hashlib
import json
import math
from datetime import datetime, timezone


def booking_v8(request, pins, prior_minutes, ancillary_minutes):
    validate_request_v8(request, pins)
    _r8_need(all(type(v) is int and v >= 0 for v in (prior_minutes, ancillary_minutes)) and
        ancillary_minutes <= R8_ANCILLARY_MINUTES and
        ((request["stageRound"] == 1 and prior_minutes == 0) or
         (request["stageRound"] == 2 and prior_minutes <= R8_FULL_MINUTES)), "r8.actual_usage")
    current = R8_ADMISSION_MINUTES + R8_FINAL_MINUTES + sum(
        R8_PROFILE_MINUTES[p] for p in request["profiles"])
    reserve = R8_TARGETED_MINUTES if request["stageRound"] == 1 else 0
    total = prior_minutes + current + reserve + R8_ANCILLARY_MINUTES
    cumulative = pins["baseline"]["runnerMinutesObserved"] + total
    _r8_need(total <= R8_NEW_MINUTES and cumulative <= V6_OVERALL_MINUTES,
        "r8.total_minute_ceiling")
    return {"bookedRunnerMinutes": cumulative,
        "actualSettledRunnerMinutes": pins["baseline"]["runnerMinutesObserved"],
        "newStageBookedMinutes": total, "priorValidationObservedMinutes": prior_minutes,
        "currentRoundBookedMinutes": current, "futureTargetedReserveMinutes": reserve,
        "ancillaryReservationBookedMinutes": R8_ANCILLARY_MINUTES,
        "observedNewAncillaryRunnerMinutes": ancillary_minutes,
        "newAncillaryRemainingReserveMinutes": R8_ANCILLARY_MINUTES - ancillary_minutes,
        "overallMinuteCeiling": V6_OVERALL_MINUTES, "newScopeMinuteCeiling": R8_NEW_MINUTES,
        "maximumStageExecutionsIncludingPreparation": 2,
        "newPreparationExecutionAuthorized": False, "preparationChargedAgain": False,
        "currentSourceCoverageReusedFromF5": False}


def _h8_equal(left, right):
    return json.dumps(left, sort_keys=True, separators=(",", ":"), allow_nan=False) == \
        json.dumps(right, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _h8_actor(run):
    _r8_need(type(run) is dict and all(type(run.get(k)) is dict and
        run[k].get("login") == "fr-meyer" for k in ("actor", "triggering_actor")),
        "r8.owner_actor")


def _h8_source_binding(run):
    _r8_need(type(run) is dict, "r8.source_role")
    _h6_source_run_binding(run)
    _h8_actor(run)
    _r8_need(run.get("path") == WORKFLOW, "r8.source_role")


def _h8_job_ids(table):
    jobs = table["jobs"]
    ids = [job.get("id") for job in jobs]
    _r8_need(all(type(i) is int and i > 0 for i in ids) and len(set(ids)) == len(ids),
        "r8.unique_job_ids")
    return set(ids)


def _h8_artifacts(api, run):
    table = api("/repos/" + REPOSITORY + "/actions/runs/" + str(run["id"]) +
        "/artifacts?per_page=100")
    _r8_need(type(table) is dict and type(table.get("total_count")) is int and
        type(table.get("artifacts")) is list and table["total_count"] == len(table["artifacts"]) <= 100,
        "r8.artifacts_complete")
    projected, ids, size = [], set(), 0
    for artifact in table["artifacts"]:
        _r8_need(type(artifact) is dict and type(artifact.get("id")) is int and
            artifact["id"] > 0 and artifact["id"] not in ids and
            type(artifact.get("name")) is str and bool(artifact["name"]) and
            type(artifact.get("size_in_bytes")) is int and artifact["size_in_bytes"] >= 0 and
            type(artifact.get("expired")) is bool, "r8.artifact_identity")
        ids.add(artifact["id"]); size += artifact["size_in_bytes"]
        projected.append({k: artifact[k] for k in ("id", "name", "size_in_bytes", "expired")})
    return {"ids": sorted(ids), "count": len(ids), "bytes": size,
        "rows": sorted(projected, key=lambda item: item["id"]),
        "observationComplete": run["status"] == "completed"}


def _h8_closed_baseline(pipeline, history, api, pins):
    trusted = pins["baseline"]
    proof_raw = (pipeline / R8_SETTLED_USAGE_PATH).read_bytes()
    original_raw = (pipeline / R7_SETTLED_USAGE_PATH).read_bytes()
    stage_raw = (pipeline / R8_PRIOR_STAGE_USAGE_PATH).read_bytes()
    _r8_need(len(proof_raw) <= 16384 and len(original_raw) <= 2 * 1024 * 1024 and
        len(stage_raw) <= 2 * 1024 * 1024 and
        hashlib.sha256(proof_raw).hexdigest() == trusted["sha256"], "r8.baseline_proof_digest")
    baseline = resolve_composite(proof_raw, original_raw, stage_raw)
    _r8_need(hashlib.sha256(json.dumps(baseline, sort_keys=True, separators=(",", ":"),
        allow_nan=False).encode()).hexdigest() == trusted["resolvedSha256"] and
        baseline["runCount"] == trusted["runCount"] == R8_PRIOR_RUNS and
        baseline["runnerMinutesObserved"] == trusted["runnerMinutesObserved"] == R8_PRIOR_MINUTES and
        baseline["sourceRunIds"] == trusted["sourceRunIds"] and
        _h8_equal(baseline["artifactSnapshot"], trusted["artifactSnapshot"]) and
        baseline["closedAt"] == trusted["closedAt"], "r8.baseline_resolved_binding")
    # Historical policy/objects are deliberately passed unchanged, not repinned
    # to the current source and not charged as new preparation or validation.
    original, original_ids, hashes = validate_closed_baseline_v7(original_raw,
        lambda *args: git(pipeline, *args), history, api, R7_STAGE_PINS)
    rows = {str(row["id"]): row for row in baseline["runs"]}
    _r8_need(len(rows) == R8_PRIOR_RUNS and original_ids <= set(rows) and
        all(_h8_equal(row, rows[str(row["id"])]) for row in original["runs"]),
        "r8.original213_preserved")
    measured = original["runnerMinutesObserved"]
    known_jobs = {job["id"] for row in original["runs"] for job in row["jobs"]}
    known_artifacts = {item["id"] for row in original["runs"] for item in row.get("artifactRows", [])}
    for rid, row in rows.items():
        if rid in original_ids:
            continue
        run = history.get(rid)
        _r8_need(type(run) is dict and _h5_public(run) and
            all(type(run.get(k)) is type(row[k]) and run.get(k) == row[k] for k in V6_PROVIDER_HEADERS) and
            run.get("status") == "completed" and run.get("conclusion") in V5_TERMINAL_CONCLUSIONS and
            row.get("actorLogin") == row.get("triggeringActorLogin") == "fr-meyer",
            "r8.closed30_header_changed")
        _h8_actor(run)
        table = _h5_jobs(api, run)
        ids = _h8_job_ids(table)
        _r8_need(not known_jobs.intersection(ids) and
            _h8_equal(sorted(table["jobs"], key=lambda j: j["id"]),
                sorted(row["jobs"], key=lambda j: j["id"])), "r8.closed30_jobs_changed")
        known_jobs.update(ids)
        if rid == R7_STAGE_PINS["preparation"]["runId"]:
            _h7_preparation_binding(run, R7_STAGE_PINS["preparation"])
            _r8_need(table["total_count"] == 1 and table["jobs"][0].get("name") == "lock-preparation" and
                run["conclusion"] == "success", "r8.closed_preparation_role")
            minutes = observed_minutes(table, None, legacy=True)
            _r8_need(minutes <= R7_PREPARATION_MINUTES, "r8.closed_preparation_clock")
        elif run["path"] == WORKFLOW:
            _r8_need(rid == "40856125444", "r8.closed_source_role")
            _h8_source_binding(run)
            prior = _v6_json(content_at(api, REQUEST, run["head_sha"]))
            validate_request_v7(prior, R7_STAGE_PINS)
            _r8_need(prior["stageRound"] == 1 and prior["profiles"] == list(V6_PROFILES),
                "r8.closed_r7_full_request")
            workflow_security_v7(content_at(api, WORKFLOW, run["head_sha"]), prior["sourceSha"])
            minutes = observed_minutes_v5(table, prior["profiles"], validation_budget_v7(prior))
        else:
            minutes = observed_minutes(table, None, legacy=True)
        _r8_need(type(row.get("observedRunnerMinutes")) is int and
            row["observedRunnerMinutes"] == minutes, "r8.closed30_actual_minutes")
        measured += minutes
        artifacts = _h8_artifacts(api, run)
        _r8_need(not known_artifacts.intersection(artifacts["ids"]) and
            _h8_equal(artifacts["rows"], sorted(row["artifactRows"], key=lambda a: a["id"])),
            "r8.closed30_artifacts_changed")
        known_artifacts.update(artifacts["ids"])
        hashes[rid] = hashlib.sha256(json.dumps(row["jobs"], sort_keys=True,
            separators=(",", ":")).encode()).hexdigest()
    _r8_need(measured == trusted["runnerMinutesObserved"], "r8.closed243_actual_minutes")
    return baseline, set(rows), hashes, known_jobs, known_artifacts


def workflow_security_v8(raw, source_sha):
    return {**workflow_security_v7(raw, source_sha), "profilePolicy": R8_POLICY}


def _h8_previous(request, pins, history, current, pipeline, api):
    if request["stageRound"] == 1:
        return 0, [], {}, list(V6_PROFILES), set()
    pin = pins["priorValidationRuns"][0]
    run = history.get(pin["runId"])
    _h8_source_binding(run)
    _r8_need(run.get("head_sha") == pin["pipelineHead"] and run.get("status") == "completed" and
        run.get("conclusion") in V5_TERMINAL_CONCLUSIONS and
        timestamp(run["updated_at"]) <= timestamp(current["created_at"]), "r8.prior_validation_terminal")
    raw = content_at(api, REQUEST, pin["pipelineHead"])
    _r8_need(hashlib.sha256(raw).hexdigest() == pin["requestSha256"], "r8.prior_request_digest")
    prior = _v6_json(raw)
    validate_request_v8(prior, dict(pins, priorValidationRuns=[]))
    _r8_need(prior["stageRound"] == 1 and prior["profiles"] == list(V6_PROFILES) and
        all(_h8_equal(prior[k], request[k]) for k in ("sourceSha", "sourceTree", "manifestSha256",
            "inventorySha256", "settledUsageSha256", "lockPreparation", "sourceWitness")),
        "r8.same_frozen_source_only")
    git(pipeline, "merge-base", "--is-ancestor", pin["pipelineHead"], current["head_sha"])
    workflow_security_v8(content_at(api, WORKFLOW, pin["pipelineHead"]), request["sourceSha"])
    table = _h5_jobs(api, run)
    minutes = observed_minutes_v5(table, prior["profiles"], validation_budget_v8(prior))
    results = {job["name"][8:-1]: job["conclusion"] for job in table["jobs"]
        if job["name"].startswith("source (") and job["name"].endswith(")") and
        job["name"][8:-1] in V6_PROFILES}
    unresolved = [p for p in V6_PROFILES if results.get(p) != "success"]
    _r8_need(bool(unresolved) and set(unresolved) <= set(request["profiles"]),
        "r8.all_unresolved_selected")
    return minutes, [{"runId": pin["runId"], "pipelineHead": pin["pipelineHead"],
        "requestSha256": pin["requestSha256"], "observedRunnerMinutes": minutes,
        "sourceSha": request["sourceSha"], "profileResults": results,
        "unresolvedProfiles": unresolved, "sourceUnchanged": True,
        "oldF5OrR7EvidenceUsedForCurrentCoverage": False}], results, unresolved, _h8_job_ids(table)


def history_checks_v8(request, event, env, pipeline, api, pins):
    request = validate_request_v8(request, pins)
    head = validate_event(event, env)
    now = datetime.now(timezone.utc)
    _r8_need(now < timestamp(R8_DEADLINE), "r8.history_deadline")
    live = api("/repos/" + REPOSITORY + "/pulls/28")
    _r8_need(validate_event(dict(event, pull_request=live), env) == head, "r8.live_pr_changed")
    for branch, expected in ((BASE_BRANCH, TARGET_BRANCH_TIP), (V6_SOURCE_BRANCH, request["sourceSha"])):
        ref = api("/repos/" + REPOSITORY + "/git/ref/heads/" + branch)
        _r8_need(ref.get("ref") == "refs/heads/" + branch and
            ref.get("object", {}).get("type") == "commit" and ref["object"].get("sha") == expected,
            "r8.live_branch_tip")
    history = _h6_branch_history(api)
    baseline, prefix_ids, hashes, job_ids, artifact_ids = _h8_closed_baseline(pipeline, history, api, pins)
    expected = [*pins["baseline"]["sourceRunIds"],
        *[p["runId"] for p in pins["priorValidationRuns"]], env["GITHUB_RUN_ID"]]
    actual = {rid for rid, run in history.items() if run.get("path") == WORKFLOW}
    _r8_need(actual == set(expected) and len(expected) == len(set(expected)), "r8.exact_execution_set")
    current = history[env["GITHUB_RUN_ID"]]
    _h8_source_binding(current)
    _r8_need(current.get("head_sha") == head and current.get("status") == "in_progress" and
        datetime.fromisoformat(baseline["closedAt"]) <= timestamp(current["created_at"]) <= now,
        "r8.current_validation_identity")
    for rid in pins["baseline"]["sourceRunIds"]:
        git(pipeline, "merge-base", "--is-ancestor", history[rid]["head_sha"], head)
    workflow = workflow_security_v8((pipeline / WORKFLOW).read_bytes(), request["sourceSha"])
    prior_minutes, previous, results, unresolved, prior_ids = _h8_previous(
        request, pins, history, current, pipeline, api)
    _r8_need(not job_ids.intersection(prior_ids), "r8.replayed_prior_job")
    job_ids.update(prior_ids)
    table = _h5_jobs(api, current)
    current_ids = _h8_job_ids(table)
    _r8_need(not job_ids.intersection(current_ids), "r8.replayed_current_job")
    job_ids.update(current_ids)
    admission = [j for j in table["jobs"] if j.get("name") == "admission"]
    _r8_need(len(admission) == 1 and admission[0].get("status") == "in_progress" and
        type(admission[0].get("runner_id")) is int and admission[0]["runner_id"] > 0 and
        type(admission[0].get("runner_name")) is str and bool(admission[0]["runner_name"]) and
        admission[0].get("runner_group_name") == "GitHub Actions" and
        admission[0].get("labels") == ["ubuntu-24.04"], "r8.current_public_admission")
    for job in table["jobs"]:
        if job is admission[0]:
            continue
        _r8_need(job.get("name") in {"final", "source (${{ matrix.profile }})",
            *["source (" + p + ")" for p in request["profiles"]]} and
            (job.get("runner_id") is None or type(job.get("runner_id")) is int and job["runner_id"] == 0) and
            job.get("runner_name") in (None, "") and type(job.get("steps")) is list and not job["steps"] and
            (job.get("status") in ("queued", "waiting", "pending") or
             job.get("status") == "completed" and job.get("conclusion") in ("skipped", "cancelled")),
            "r8.jobs_before_admission")
    current_facts = ancillary_job_snapshot(table, now, False)
    _r8_need(current_facts["observedAcquiredRunnerMinutes"] <= R8_ADMISSION_MINUTES,
        "r8.current_job_booking")
    paths = {row["path"] for row in baseline["runs"] if row["path"] != WORKFLOW}
    pipeline_heads = {head, *[p["pipelineHead"] for p in pins["priorValidationRuns"]]}
    observed, ancillary, pending, artifacts = 0, [], [], []
    artifact_bytes = pins["baseline"]["artifactSnapshot"]["bytes"]
    for rid, run in sorted(history.items()):
        if rid in prefix_ids:
            continue
        if run.get("path") != WORKFLOW:
            _h8_actor(run)
            branch = run.get("head_branch")
            correct = (branch == BRANCH and run.get("head_sha") in pipeline_heads) or \
                (branch == V6_SOURCE_BRANCH and run.get("head_sha") == request["sourceSha"])
            events = ("pull_request", "pull_request_target") if branch == BRANCH else ("push",)
            _r8_need(_h5_public(run) and correct and run.get("event") in events and run.get("path") in paths and
                type(run.get("run_attempt")) is int and run["run_attempt"] == 1 and
                run.get("status") in ("completed", "in_progress", "queued", "waiting", "pending") and
                datetime.fromisoformat(baseline["closedAt"]) <= timestamp(run["created_at"]) <= now and
                (run["status"] != "completed" or run.get("conclusion") in V5_TERMINAL_CONCLUSIONS),
                "r8.new_ancillary_binding")
            table = _h5_jobs(api, run)
            ids = _h8_job_ids(table)
            _r8_need(not job_ids.intersection(ids), "r8.replayed_new_job")
            job_ids.update(ids)
            facts = ancillary_job_snapshot(table, now, run["status"] == "completed")
            observed += facts["observedAcquiredRunnerMinutes"]
            ancillary.append({"runId": rid, **facts})
            if not facts["usageComplete"]:
                pending.append(rid)
        row = _h8_artifacts(api, run)
        _r8_need(not artifact_ids.intersection(row["ids"]), "r8.artifact_duplicate")
        artifact_ids.update(row["ids"])
        artifact_bytes += row["bytes"]
        artifacts.append({"runId": rid, **row})
    _r8_need(observed <= R8_ANCILLARY_MINUTES and (not pending or observed < R8_ANCILLARY_MINUTES),
        "r8.ancillary_limit")
    _r8_need(artifact_bytes <= R8_DIAGNOSTIC_BYTES, "r8.artifact_storage_limit")
    return {**booking_v8(request, pins, prior_minutes, observed),
        "deadlineEpoch": int(timestamp(R8_DEADLINE).timestamp()),
        "profileMatrix": [{"profile": p, "minutes": R8_PROFILE_MINUTES[p]} for p in request["profiles"]],
        "selectedProfileCount": len(request["profiles"]), "priorValidationReceipts": previous,
        "priorValidationProfileResults": results, "priorUnresolvedProfiles": unresolved,
        "historicalCoverageReused": False, "reusedProfileCount": 0,
        "closedBaselineRuns": R8_PRIOR_RUNS, "closedBaselineMinutes": R8_PRIOR_MINUTES,
        "closedBaselineProofSha256": pins["baseline"]["sha256"],
        "closedBaselineResolvedSha256": pins["baseline"]["resolvedSha256"],
        "historicalJobTableSha256": hashes, "newAncillaryRecords": ancillary,
        "pendingAncillaryRunIds": pending, "ancillaryUsageComplete": not pending,
        "artifactRecords": artifacts, "observedRetainedWorkflowArtifactBytes": artifact_bytes,
        "artifactObservationComplete": all(row["observationComplete"] for row in artifacts),
        "artifactBudgetIsNotWholeDiagnosticCustodyProof": True, "workflowSecurity": workflow,
        "currentAdmissionObservation": current_facts, "historicalConclusionsRetained": True,
        "productionAuthorized": False, "imageBuilt": False}

# Explicit version dispatch adds R8 without mutating historical policy globals.
_r8_historical_profile_minutes_for = profile_minutes_for
_r8_historical_profiles_for = profiles_for
_r8_historical_source_identity_for = source_identity_for
_r8_historical_approval_deadline_for = approval_deadline_for
_r8_historical_admission_deadline = admission_deadline
_r8_historical_validate_operational_request = validate_operational_request
_r8_historical_operational_input_paths = operational_input_paths
_r8_historical_validate_operational_generation = validate_operational_generation
_r8_historical_history_checks_for_operational_request = history_checks_for_operational_request
_r8_historical_verify_operational_source = verify_operational_source
_r8_historical_runtime_refusal_code_v7 = runtime_refusal_code_v7


def _is_r8(value):
    return type(value) is dict and value.get("schema") == R8_SCHEMA


def profile_minutes_for(request=None):
    if _is_r8(request):
        return validation_budget_v8(request)["profileMinutes"]
    return _r8_historical_profile_minutes_for(request)


def profiles_for(request):
    if _is_r8(request):
        validate_request_v8(request, R8_STAGE_PINS)
        return list(request["profiles"])
    return _r8_historical_profiles_for(request)


def source_identity_for(request=None):
    if _is_r8(request):
        validate_request_v8(request, R8_STAGE_PINS)
        return request["sourceSha"], request["sourceTree"]
    return _r8_historical_source_identity_for(request)


def approval_deadline_for(request=None):
    if _is_r8(request):
        validate_request_v8(request, R8_STAGE_PINS)
        return R8_DEADLINE
    return _r8_historical_approval_deadline_for(request)


def admission_deadline(env, request=None):
    if not _is_r8(request):
        return _r8_historical_admission_deadline(env, request)
    validate_request_v8(request, R8_STAGE_PINS)
    start = env.get("SOURCE_ADMISSION_STARTED_EPOCH", "")
    _r8_need(env.get("GITHUB_JOB") == "admission" and
        re.fullmatch(r"[0-9]{10}", start) is not None, "r8.admission_clock")
    now = time.time()
    _r8_need(int(start) <= now and now - int(start) < R8_ADMISSION_MINUTES * 60,
        "r8.admission_clock_freshness")
    return min(int(start) + R8_ADMISSION_MINUTES * 60 - 60,
               int(timestamp(R8_DEADLINE).timestamp()) - 60)


def validate_operational_request(request):
    if _is_r8(request):
        return validate_request_v8(request, R8_STAGE_PINS)
    return _r8_historical_validate_operational_request(request)


def operational_input_paths(request):
    if _is_r8(request):
        validate_request_v8(request, R8_STAGE_PINS)
        return R8_SETTLED_USAGE_PATH, R7_PREPARATION_PROOF_PATH
    return _r8_historical_operational_input_paths(request)


def validate_operational_generation(request, raw):
    if _is_r8(request):
        validate_request_v8(request, R8_STAGE_PINS)
        return validate_re2js_generation_receipt_v7(raw, R7_STAGE_PINS)
    return _r8_historical_validate_operational_generation(request, raw)


def history_checks_for_operational_request(request, event, env, pipeline, api):
    if _is_r8(request):
        return history_checks_v8(request, event, env, pipeline, api, R8_STAGE_PINS)
    return _r8_historical_history_checks_for_operational_request(request, event, env, pipeline, api)


def verify_operational_source(request, pipeline, read_git):
    if _is_r8(request):
        return verify_source_equivalence_v8(request, R8_STAGE_PINS, read_git,
            (pipeline / R7_PREPARATION_PROOF_PATH).read_bytes())
    return _r8_historical_verify_operational_source(request, pipeline, read_git)


def runtime_refusal_code_v7(error):
    if isinstance(error, R8ContractRefusal):
        code = error.args[0] if len(error.args) == 1 else None
        return code if type(code) is str and code in R8_RUNTIME_REFUSAL_CODES else "r8.unprojected"
    return _r8_historical_runtime_refusal_code_v7(error)

R8_RUNTIME_REFUSAL_CODES = frozenset(('r8.actual_usage', 'r8.admission_clock', 'r8.admission_clock_freshness', 'r8.all15_fresh', 'r8.all_unresolved_selected', 'r8.ancillary_limit', 'r8.artifact_duplicate', 'r8.artifact_identity', 'r8.artifact_storage_limit', 'r8.artifacts_complete', 'r8.baseline_proof_digest', 'r8.baseline_resolved_binding', 'r8.budget_policy', 'r8.closed243_actual_minutes', 'r8.closed30_actual_minutes', 'r8.closed30_artifacts_changed', 'r8.closed30_header_changed', 'r8.closed30_jobs_changed', 'r8.closed_baseline_pins', 'r8.closed_preparation_clock', 'r8.closed_preparation_role', 'r8.closed_r7_full_request', 'r8.closed_request', 'r8.closed_source_role', 'r8.current_job_booking', 'r8.current_public_admission', 'r8.current_validation_identity', 'r8.dependencies_unchanged', 'r8.exact_execution_set', 'r8.exact_prior_runs', 'r8.exact_reviewed_pins', 'r8.exact_source_fixture_bytes', 'r8.fixed_profiles', 'r8.history_deadline', 'r8.hop_identity', 'r8.hop_scope', 'r8.jobs_before_admission', 'r8.live_branch_tip', 'r8.live_pr_changed', 'r8.new_ancillary_binding', 'r8.once_full_once_targeted', 'r8.original213_preserved', 'r8.owner_actor', 'r8.prior_request_digest', 'r8.prior_validation_pins', 'r8.prior_validation_terminal', 'r8.replayed_current_job', 'r8.replayed_new_job', 'r8.replayed_prior_job', 'r8.round_booking', 'r8.same_frozen_source_only', 'r8.source_role', 'r8.source_witness', 'r8.stage_pins', 'r8.tag_reuse_context', 'r8.total_minute_ceiling', 'r8.unique_executions', 'r8.unique_job_ids'))

if __name__ == "__main__":
    raise SystemExit(entrypoint())
