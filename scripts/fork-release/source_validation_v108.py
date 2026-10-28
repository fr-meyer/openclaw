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
        classes = ((V4ContractRefusal, "V4ContractRefusal"),
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
        code = runtime_refusal_code_v4(error) if operational else vars(error).get("admission_need_code")
        source_sha, source_tree = ((STAGE_PINS["sourceSha"], STAGE_PINS["sourceTree"])
                                   if operational else (SOURCE, TREE))
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
    if request.get("schema") == "openclaw.fork-source-validation-request.v4":
        need(request.get("profilePolicy") == REPAIR_PROFILE_POLICY,
             "fixed five-gate profile policy")
        return V4_PROFILE_MINUTES
    need(request.get("schema") in ("openclaw.fork-source-validation-request.v2",
         "openclaw.fork-source-validation-request.v3") and "profilePolicy" not in request,
         "known historical profile policy")
    return PROFILE_MINUTES



def profiles_for(request):
    if request.get("schema") == V4_SCHEMA:
        validate_request_v4(request, STAGE_PINS)
        return list(request["profiles"])
    return list(PROFILE_MINUTES) if request["round"] == 2 or request["initialResume"] is not None else request["profiles"]


def round_minutes(request):
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
    for path in (WORKFLOW, "scripts/fork-release/source_validation_v108.py",
                 "scripts/fork-release/preflight.py", "scripts/fork-release/release.py",
                 "scripts/fork-release/native_tests.mjs"):
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
    """Operational metadata is exclusively the reviewed closed v4 request."""
    request = validate_request_v4(_v4_json((pipeline / REQUEST).read_bytes()), STAGE_PINS)
    directory = pipeline / CANDIDATE
    manifest, manifest_hash = release.manifest_at(directory / "manifest.json")
    _v4_need(request["manifestSha256"] == manifest_hash and
             request["inventorySha256"] == preflight.digest(directory / "patch-inventory.json"),
             "v4.runtime_metadata_digest")
    source_sha, source_tree = source_identity_for(request)
    _v4_need(manifest["source"]["commit"] == source_sha and
             manifest["source"]["tree"] == source_tree and manifest["productionEligible"] is False,
             "v4.runtime_manifest_source")
    _v4_need(preflight.digest(pipeline / SETTLED_USAGE) == request["settledUsageSha256"],
             "v4.runtime_settled_usage_digest")
    return request, manifest, manifest_hash



def source_preflight(pipeline, source, manifest, manifest_hash):
    return preflight.inventory_at(pipeline / CANDIDATE / "patch-inventory.json", manifest,
                                  manifest_hash, source_dir=source)


def admission_deadline(env, request=None):
    """The early job clock precedes both checkouts; retain one minute to close."""
    start = env.get("SOURCE_ADMISSION_STARTED_EPOCH", "")
    need(env.get("GITHUB_JOB") == "admission" and
         re.fullmatch(r"[0-9]{10}", start) is not None,
         "early admission clock required")
    now = time.time()
    need(int(start) <= now and now - int(start) < 15 * 60,
         "early admission clock freshness")
    return min(int(start) + 15 * 60 - 60,
               int(timestamp(approval_deadline_for(request)).timestamp()) - 60)



def closure_remaining(deadline):
    remaining = deadline - time.time()
    need(remaining >= 1, "source closure shared deadline exhausted")
    return remaining


def product_checkout_minutes(env, request=None):
    # This is part of the same15-minute admission, not a new10-minute lease.
    minutes = min(10, math.floor(closure_remaining(admission_deadline(env, request)) / 60))
    need(minutes >= 1, "insufficient shared product checkout budget")
    return minutes



def fetch_closure(pipeline, source, request=None, env=None):
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
        return [["node", str(pipeline / "scripts/fork-release/native_tests.mjs"),
                 "--source-root", str(source), "--", "test/v108-remediation-security.test.mjs"],
                ["node", "--import", "./scripts/tsx.mjs", "scripts/test-projects.mts", *compatibility],
                ["pnpm", "deps:npm-lock:check:changed", "--base", ORIGINAL_SOURCE, "--head", source_sha]]
    if profile == "pipeline-contracts":
        names = ("test_release.py", "test_preflight.py", "test_merge_source.py",
                                          "test_merge_source_v107.py", "test_merge_source_v108.py",
                                          "test_source_tests.py", "test_source_validation_v108.py",
                                          "test_v108_pnpm_bootstrap.py", "test_v108_recovery_budget.py",
                                          "test_v108_successor_witness.py")
        if request is not None and request.get("schema") == V4_SCHEMA:
            names += ("test_v108_runtime_contract_v4.py", "test_request_contract_v4.py",
                      "test_history_checks_v4.py")
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


def bootstrap_pnpm(home, env, request=None):
    """Initialize only pinned pnpm, then return its owned native executable."""
    source_sha, source_tree = source_identity_for(request)
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
        summarize({"campaignId": CAMPAIGN, "bootstrapPhase": phase,
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
    source_sha, source_tree = source_identity_for(context.get("request"))
    remaining = context["deadlineEpoch"] - time.time()
    fact = {"campaignId": CAMPAIGN, "profile": context["profile"], "phase": phase,
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
    parser.add_argument("--profile", choices=V4_PROFILE_MINUTES)
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
    validate_request_v4(request, STAGE_PINS)
    source_sha, source_tree = source_identity_for(request)
    if args.command == "finalize":
        code_binding(args.pipeline_dir, None, event, env, minimal=True, request=request)
        admission_passed = env.get("SOURCE_ADMISSION_RESULT") == "success"
        passed = env.get("SOURCE_MATRIX_RESULT") == "success" and admission_passed
        summarize({"campaignId": CAMPAIGN, "round": request["round"], "sourceSha": source_sha,
            "sourceTree": source_tree, "status": "passed" if passed else "failed",
            "coverage": "affected_profiles_with_admission_verified_historical_reuse",
            "affectedProfiles": profiles_for(request), "sourceWitness": request["sourceWitness"],
            "historicalReuse": {"verificationOwner": "native_admission", "verified": admission_passed,
                "profiles": list(V4_REUSED_PROFILES), "sourceSha": V4_PARENT_SOURCE,
                "sourceTree": V4_PARENT_TREE, "pipelineHead": V4_PARENT_PIPELINE,
                "runId": V4_PARENT_RUN, "closedPrefixSha256": V4_CLOSED_PREFIX_SHA256,
                "relabeledAsCurrentSourcePass": False},
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
        fetch_closure(args.pipeline_dir, args.source_dir, request=request, env=env)
        return 0
    if args.command == "admit":
        admission_deadline(env, request)
        admission_stage("history", "current-pr")
        token = env.get("GH_SOURCE_READ_TOKEN", "")
        need(bool(token), "read-only API token required")
        budget = history_checks_v4(request, event, env, args.pipeline_dir, lambda p: api_json(p, token))
        admission_stage("closure", "closure.acquire")
        fetch_closure(args.pipeline_dir, args.source_dir, request=request, env=env)
        admission_stage("equivalence", "equivalence.verify")
        equivalence = verify_source_equivalence_v4(request, STAGE_PINS, runtime_read_git(args.source_dir))
        budget["sourceEquivalence"] = equivalence
        matrix = {"include": [{"profile": p, "minutes": profile_minutes_for(request)[p]}
                              for p in profiles_for(request)]}
        _v4_need(budget["profileMatrix"] == matrix["include"] and
                 budget["reusedProfileEvidence"]["profiles"] == list(V4_REUSED_PROFILES),
                 "v4.runtime_verified_budget_and_reuse")
        _v4_need(type(budget["deadlineEpoch"]) is int and
                 budget["deadlineEpoch"] <= int(timestamp(approval_deadline_for(request)).timestamp()),
                 "v4.runtime_approval_deadline")
        admission_stage("matrix", "matrix.publish")
        with open(env["GITHUB_OUTPUT"], "a", encoding="utf-8") as out:
            out.write("matrix=" + json.dumps(matrix, separators=(",", ":")) + "\n")
            out.write("deadline_epoch=" + str(budget["deadlineEpoch"]) + "\n")
        summarize({**budget, "campaignId": CAMPAIGN, "round": request["round"], "sourceSha": source_sha,
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
            witness = verify_source_equivalence_v4(request, STAGE_PINS, runtime_read_git(args.source_dir))
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
                summarize({"campaignId": CAMPAIGN, "round": request["round"], "profile": args.profile,
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
                    "V4ContractRefusal", "Refusal", "OSError", "ValueError", "KeyError", "TypeError",
                    "CalledProcessError", "ProfileInterrupted") else "UnprojectedError",
                "failedNeedCode": runtime_refusal_code_v4(error), "sourceSha": source_sha,
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
    if request.get("schema") in ("openclaw.fork-source-validation-request.v2",
                                  "openclaw.fork-source-validation-request.v3"):
        return SOURCE, TREE
    validate_request_v4(request, STAGE_PINS)
    return request["sourceSha"], request["sourceTree"]


def approval_deadline_for(request=None):
    if request is None:
        return APPROVAL_DEADLINE
    _v4_need(type(request) is dict, "v4.runtime_request_type")
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



if __name__ == "__main__":
    raise SystemExit(entrypoint())
