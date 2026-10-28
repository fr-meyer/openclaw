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
# Deliberately disarmed until the reviewed successor is supplied by the source owner.
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
ADMISSION_NEED_CODES = {
    'API timestamp': 'need.api_timestamp',
    'Linux memory metadata': 'need.linux_memory_metadata',
    'PR event and first attempt required': 'need.pr_event_and_first_attempt_required',
    'actual prior425 proof': 'need.actual_prior425_proof',
    'admitted campaign deadline/profile required': 'need.admitted_campaign_deadline_profile_required',
    'all affected test-only owner profiles': 'need.all_affected_test_only_owner_profiles',
    'all other tracked bytes equivalence': 'need.all_other_tracked_bytes_equivalence',
    'ancillary alarm already owned': 'need.ancillary_alarm_already_owned',
    'ancillary observation owned admission identity': 'need.ancillary_observation_owned_admission_identity',
    'ancillary observation source/prefix metadata changed': 'need.ancillary_observation_source_prefix_metadata_changed',
    'ancillary still unsettled after bounded60-second observation': 'need.ancillary_still_unsettled_after_bounded60_second_observation',
    'authorized successor request': 'need.authorized_successor_request',
    'bootstrap runtimes required': 'need.bootstrap_runtimes_required',
    'bound first-source receipt': 'need.bound_first_source_receipt',
    'bounded API response': 'need.bounded_api_response',
    'bounded Git-backed content': 'need.bounded_git_backed_content',
    'bounded complete branch history': 'need.bounded_complete_branch_history',
    'bounded derived ledger': 'need.bounded_derived_ledger',
    'bounded summary': 'need.bounded_summary',
    'closed exact initial-resume witness': 'need.closed_exact_initial_resume_witness',
    'closed test-only witness': 'need.closed_test_only_witness',
    'closure commit': 'need.closure_commit',
    'complete compatibility acceptance paths': 'need.complete_compatibility_acceptance_paths',
    'complete current admission job table': 'need.complete_current_admission_job_table',
    'complete dependency regression set': 'need.complete_dependency_regression_set',
    'complete new ancillary job table': 'need.complete_new_ancillary_job_table',
    'complete ordered prior source runs': 'need.complete_ordered_prior_source_runs',
    'complete settled 57-record prefix': 'need.complete_settled_57_record_prefix',
    'complete terminal job table': 'need.complete_terminal_job_table',
    'complete test-only plus derived-ledger changed set': 'need.complete_test_only_plus_derived_ledger_changed_set',
    'complete unique history pages': 'need.complete_unique_history_pages',
    'content size': 'need.content_size',
    'current admission acquisition': 'need.current_admission_acquisition',
    'current admission runner': 'need.current_admission_runner',
    'current source round identity': 'need.current_source_round_identity',
    'derived ledger row schema': 'need.derived_ledger_row_schema',
    'duplicate JSON key': 'need.duplicate_json_key',
    'empty owner family': 'need.empty_owner_family',
    'event action': 'need.event_action',
    'exact campaign source run identity': 'need.exact_campaign_source_run_identity',
    'exact published v2 prior request': 'need.exact_published_v2_prior_request',
    'exact reviewed successor source': 'need.exact_reviewed_successor_source',
    'exact test-only paths': 'need.exact_test_only_paths',
    'exact two witnessed source checkout refs': 'need.exact_two_witnessed_source_checkout_refs',
    'exact unstarted initial job set': 'need.exact_unstarted_initial_job_set',
    'fetched workflow commit changed': 'need.fetched_workflow_commit_changed',
    'first-source complete job booking exceeded': 'need.first_source_complete_job_booking_exceeded',
    'fixed API route': 'need.fixed_api_route',
    'fixed Node version': 'need.fixed_node_version',
    'fixed base': 'need.fixed_base',
    'fixed content identity': 'need.fixed_content_identity',
    'fixed live target branch tip': 'need.fixed_live_target_branch_tip',
    'fixed pnpm package/version/bin': 'need.fixed_pnpm_package_version_bin',
    'fixed pnpm version': 'need.fixed_pnpm_version',
    'fixed settled run fields': 'need.fixed_settled_run_fields',
    'fixed settled usage envelope': 'need.fixed_settled_usage_envelope',
    'fixed unique profiles': 'need.fixed_unique_profiles',
    'fixed upstream tag': 'need.fixed_upstream_tag',
    'four lifetime operator rounds': 'need.four_lifetime_operator_rounds',
    'frozen install failed': 'need.frozen_install_failed',
    'initial admission failed acquired within15 rounded minutes': 'need.initial_admission_failed_acquired_within15_rounded_minutes',
    'initial source/final explicitly skipped unacquired': 'need.initial_source_final_explicitly_skipped_unacquired',
    'initial-resume exact failed prior source/controls': 'need.initial_resume_exact_failed_prior_source_controls',
    'initial-resume provider run/head binding': 'need.initial_resume_provider_run_head_binding',
    'insufficient admission/deadline observation time': 'need.insufficient_admission_deadline_observation_time',
    'insufficient time in approved campaign': 'need.insufficient_time_in_approved_campaign',
    'internal120 ancillary-record alarm': 'need.internal120_ancillary_record_alarm',
    'ledger changed beyond exact derived test result blobs': 'need.ledger_changed_beyond_exact_derived_test_result_blobs',
    'lifetime1800 runner-minute ceiling': 'need.lifetime1800_runner_minute_ceiling',
    'literal workflow commit required': 'need.literal_workflow_commit_required',
    'live head changed': 'need.live_head_changed',
    'missing admitted profile jobs': 'need.missing_admitted_profile_jobs',
    'missing campaign boundary job': 'need.missing_campaign_boundary_job',
    'named profile required': 'need.named_profile_required',
    'native pnpm executable': 'need.native_pnpm_executable',
    'new ancillary elapsed time': 'need.new_ancillary_elapsed_time',
    'new ancillary job identity/attempt': 'need.new_ancillary_job_identity_attempt',
    'new ancillary public identity/path/head': 'need.new_ancillary_public_identity_path_head',
    'new ancillary run state': 'need.new_ancillary_run_state',
    'new ancillary terminal conclusion': 'need.new_ancillary_terminal_conclusion',
    'new ancillary terminal time evidence': 'need.new_ancillary_terminal_time_evidence',
    'new ancillary135-minute bucket exceeded': 'need.new_ancillary135_minute_bucket_exceeded',
    'new source authorization time': 'need.new_source_authorization_time',
    'no ancillary usage headroom for observation': 'need.no_ancillary_usage_headroom_for_observation',
    'no owned job budget remains': 'need.no_owned_job_budget_remains',
    'observed ancillary identity changed': 'need.observed_ancillary_identity_changed',
    'observed ancillary run disappeared': 'need.observed_ancillary_run_disappeared',
    'old ledger result matches exact parent test blob': 'need.old_ledger_result_matches_exact_parent_test_blob',
    'one full successor round': 'need.one_full_successor_round',
    'open draft PR28': 'need.open_draft_pr28',
    'ordered new source rounds': 'need.ordered_new_source_rounds',
    'original approval deadline': 'need.original_approval_deadline',
    'owned pnpm command link': 'need.owned_pnpm_command_link',
    'owned regular pnpm bootstrap file': 'need.owned_regular_pnpm_bootstrap_file',
    'pinned pnpm bootstrap file digest': 'need.pinned_pnpm_bootstrap_file_digest',
    'pipeline checkout head': 'need.pipeline_checkout_head',
    'positive in-progress ancillary acquisition': 'need.positive_in_progress_ancillary_acquisition',
    'positive queued ancillary unacquired evidence': 'need.positive_queued_ancillary_unacquired_evidence',
    'positive unacquired terminal evidence': 'need.positive_unacquired_terminal_evidence',
    'prior new round terminal': 'need.prior_new_round_terminal',
    'profile not in admitted request': 'need.profile_not_in_admitted_request',
    'public hosted Linux only': 'need.public_hosted_linux_only',
    'public repository': 'need.public_repository',
    'read-only API token required': 'need.read_only_api_token_required',
    'repository/ref': 'need.repository_ref',
    'request digest': 'need.request_digest',
    'request fields': 'need.request_fields',
    'request metadata hashes': 'need.request_metadata_hashes',
    'reviewed source pins required': 'need.reviewed_source_pins_required',
    'reviewed workflow/code bytes': 'need.reviewed_workflow_code_bytes',
    'run identity': 'need.run_identity',
    'same-repository reviewed head': 'need.same_repository_reviewed_head',
    'settled new ancillary state changed': 'need.settled_new_ancillary_state_changed',
    'settled provider usage changed': 'need.settled_provider_usage_changed',
    'settled run identity/state': 'need.settled_run_identity_state',
    'settled usage digest': 'need.settled_usage_digest',
    'settled425 source/ancillary coverage': 'need.settled425_source_ancillary_coverage',
    'source checkout required': 'need.source_checkout_required',
    'source checkout/tree': 'need.source_checkout_tree',
    'source job clock freshness': 'need.source_job_clock_freshness',
    'source job clock required': 'need.source_job_clock_required',
    'source-only manifest': 'need.source_only_manifest',
    'stable branch history pagination': 'need.stable_branch_history_pagination',
    'standard public Ubuntu acquired runner': 'need.standard_public_ubuntu_acquired_runner',
    'standard runner below engineering resource floors': 'need.standard_runner_below_engineering_resource_floors',
    'targeted correction minute cap': 'need.targeted_correction_minute_cap',
    'terminal ancillary run has pending jobs': 'need.terminal_ancillary_run_has_pending_jobs',
    'terminal first-attempt unique job': 'need.terminal_first_attempt_unique_job',
    'terminal job duration': 'need.terminal_job_duration',
    'terminal unique positive job ID': 'need.terminal_unique_positive_job_id',
    'test-only parent tree': 'need.test_only_parent_tree',
    'test-only successor added/deleted path': 'need.test_only_successor_added_deleted_path',
    'test-only successor must be direct single-parent': 'need.test_only_successor_must_be_direct_single_parent',
    'test/ledger mode or type changed': 'need.test_ledger_mode_or_type_changed',
    'unique derived ledger rows': 'need.unique_derived_ledger_rows',
    'unknown new ancillary job state': 'need.unknown_new_ancillary_job_state',
    'unlisted/duplicate source round': 'need.unlisted_duplicate_source_round',
    'unwitnessed source repin': 'need.unwitnessed_source_repin',
    'witness parent/digest': 'need.witness_parent_digest',
    'workflow acquisition changed checkout': 'need.workflow_acquisition_changed_checkout',
    'workflow identity': 'need.workflow_identity',
    'workflow merge target parent': 'need.workflow_merge_target_parent',
    'workflow/security caps changed between new rounds': 'need.workflow_security_caps_changed_between_new_rounds',
}
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
def admission_diagnostics(env, enabled):
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
        classes = ((urllib.error.HTTPError, "HTTPError"),
                   (subprocess.CalledProcessError, "CalledProcessError"),
                   (release.Refusal, "Refusal"), (ProfileInterrupted, "ProfileInterrupted"),
                   (OSError, "OSError"), (ValueError, "ValueError"),
                   (KeyError, "KeyError"), (TypeError, "TypeError"))
        error_class = next((name for cls, name in classes if isinstance(error, cls)), "UnprojectedError")
        status = error.code if isinstance(error, urllib.error.HTTPError) else None
        child_exit = error.returncode if isinstance(error, subprocess.CalledProcessError) else None
        # HTTPError may delegate unknown attributes to an absent file handle.
        # Read only our own annotation; never inspect/format exception payloads.
        code = vars(error).get("admission_need_code")
        summarize({"schema": "openclaw.v108.admission-failure.v1", "campaignId": CAMPAIGN,
            "status": "refused", **_ADMISSION_DIAGNOSTIC,
            "failedNeedCode": code if code in ADMISSION_NEED_CODES.values() else "need.unprojected",
            "exceptionClass": error_class,
            "httpStatus": status if type(status) is int and 100 <= status <= 599 else None,
            "childExitCode": child_exit if type(child_exit) is int and -255 <= child_exit <= 255 else None,
            "sourceSha": SOURCE, "sourceTree": TREE, "productionAuthorized": False, "imageBuilt": False}, {})
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


def profiles_for(request):
    return list(PROFILE_MINUTES) if request["round"] == 2 or request["initialResume"] is not None else request["profiles"]

def round_minutes(request):
    return JOB_OVERHEAD_MINUTES + sum(PROFILE_MINUTES[p] for p in profiles_for(request))


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


def code_binding(pipeline, source, event, env, minimal=False):
    head = validate_event(event, env)
    need(git(pipeline, "rev-parse", "HEAD").decode().strip() == head, "pipeline checkout head")
    if source is not None:
        need(git(source, "rev-parse", "HEAD").decode().strip() == SOURCE and
             git(source, "rev-parse", "HEAD^{tree}").decode().strip() == TREE, "source checkout/tree")
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


def observed_minutes(jobs, expected=None, legacy=False):
    need(type(jobs) is dict and type(jobs.get("total_count")) is int and
         type(jobs.get("jobs")) is list and jobs["total_count"] <= 100 and
         jobs["total_count"] == len(jobs["jobs"]), "complete terminal job table")
    caps = LEGACY_PROFILE_MINUTES if legacy else PROFILE_MINUTES
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
            prior_new_minutes = observed_minutes(prior_jobs, list(PROFILE_MINUTES))
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
    directory = pipeline / CANDIDATE
    request = validate_request(read_json((pipeline / REQUEST).read_bytes()))
    manifest, manifest_hash = release.manifest_at(directory / "manifest.json")
    need(request["manifestSha256"] == manifest_hash and
         request["inventorySha256"] == preflight.digest(directory / "patch-inventory.json"),
         "request metadata hashes")
    need(manifest["source"]["commit"] == SOURCE and manifest["source"]["tree"] == TREE and
         manifest["productionEligible"] is False, "source-only manifest")
    settled_usage(pipeline, request)
    return request, manifest, manifest_hash


def source_preflight(pipeline, source, manifest, manifest_hash):
    return preflight.inventory_at(pipeline / CANDIDATE / "patch-inventory.json", manifest,
                                  manifest_hash, source_dir=source)


def fetch_closure(pipeline, source):
    """CI only: acquire exact public objects declared by the maintained inventory owner."""
    request, manifest, manifest_hash = metadata(pipeline)
    inventory, _ = preflight.inventory_at(pipeline / CANDIDATE / "patch-inventory.json",
                                         manifest, manifest_hash)
    safe_env = {"PATH": os.environ["PATH"], "GIT_TERMINAL_PROMPT": "0",
                "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}
    commits = preflight.history_commits(inventory, manifest)
    for commit in commits:
        need(release.matches(release.SHA, commit), "closure commit")
        if subprocess.run(["git", "-C", str(source), "cat-file", "-e", commit + "^{commit}"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
            subprocess.run(["git", "-C", str(source), "-c", "credential.helper=", "fetch", "--no-tags",
                            "https://github.com/fr-meyer/openclaw.git", commit], check=True, env=safe_env)
    need(inventory["upstream"]["tag"] == "v2026.10.8", "fixed upstream tag")
    subprocess.run(["git", "-C", str(source), "-c", "credential.helper=", "fetch", "--no-tags",
                    "https://github.com/openclaw/openclaw.git", "refs/tags/v2026.10.8"],
                   check=True, env=safe_env)
    source_preflight(pipeline, source, manifest, manifest_hash)


def selected_tests(paths, profile):
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
        return list(COMPATIBILITY_TESTS)
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


def commands(pipeline, source, profile, paths):
    need(profile in PROFILE_MINUTES, "named profile required")
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
        required = set(COMPATIBILITY_TESTS) | {"test/v108-remediation-security.test.mjs"}
        need(required <= set(paths), "complete compatibility acceptance paths")
        return [["node", str(pipeline / "scripts/fork-release/native_tests.mjs"),
                 "--source-root", str(source), "--", "test/v108-remediation-security.test.mjs"],
                ["node", "--import", "./scripts/tsx.mjs", "scripts/test-projects.mts", *COMPATIBILITY_TESTS],
                ["pnpm", "deps:npm-lock:check:changed", "--base", ORIGINAL_SOURCE, "--head", SOURCE]]
    if profile == "pipeline-contracts":
        return [["python3", "-m", "unittest", "discover", "-s", str(pipeline / "scripts/fork-release"),
                 "-p", name] for name in ("test_release.py", "test_preflight.py", "test_merge_source.py",
                                          "test_merge_source_v107.py", "test_merge_source_v108.py",
                                          "test_source_tests.py", "test_source_validation_v108.py",
                                          "test_v108_pnpm_bootstrap.py", "test_v108_recovery_budget.py",
                                          "test_v108_successor_witness.py")]
    tests = selected_tests(paths, profile)
    need(bool(tests), "empty owner family")
    return [["node", "--import", "./scripts/tsx.mjs", "scripts/test-projects.mts", *tests]]


def summarize(data, env):
    raw = json.dumps(data, sort_keys=True)
    need(len(raw.encode()) <= 65536, "bounded summary")
    print(raw, flush=True)
    if env.get("GITHUB_STEP_SUMMARY"):
        with open(env["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as out:
            out.write("```json\n" + raw + "\n```\n")


def deadline_check(env, profile):
    need(profile in PROFILE_MINUTES and re.fullmatch(r"[0-9]{10}", env.get("SOURCE_DEADLINE_EPOCH", "")),
         "admitted campaign deadline/profile required")
    need(datetime.now(timezone.utc).timestamp() + PROFILE_MINUTES[profile] * 60 <=
         min(int(env["SOURCE_DEADLINE_EPOCH"]), int(timestamp(APPROVAL_DEADLINE).timestamp())),
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


def bootstrap_pnpm(home, env):
    """Initialize only pinned pnpm, then return its owned native executable."""
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


def profile_deadline(env, profile):
    start = env.get("SOURCE_JOB_STARTED_EPOCH", "")
    need(re.fullmatch(r"[0-9]{10}", start) is not None, "source job clock required")
    now = time.time()
    need(int(start) <= now and now - int(start) < PROFILE_MINUTES[profile] * 60,
         "source job clock freshness")
    return min(int(start) + PROFILE_MINUTES[profile] * 60 - 60,
               int(timestamp(APPROVAL_DEADLINE).timestamp()) - 60)


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
    remaining = context["deadlineEpoch"] - time.time()
    fact = {"campaignId": CAMPAIGN, "profile": context["profile"], "phase": phase,
            "commandIndex": ordinal, "sourceSha": SOURCE, "sourceTree": TREE}
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
    parser.add_argument("command", choices=("admit", "fetch-closure", "run", "finalize"))
    parser.add_argument("--pipeline-dir", type=Path, required=True)
    parser.add_argument("--source-dir", type=Path)
    parser.add_argument("--profile", choices=PROFILE_MINUTES)
    args = parser.parse_args()
    env = os.environ
    with admission_diagnostics(env, args.command == "admit"):
        return command(args, env)


def command(args, env):
    admission_stage("input", "event.read")
    event = read_json(Path(env["GITHUB_EVENT_PATH"]).read_bytes())
    admission_stage("input", "event.validate")
    validate_event(event, env)
    admission_stage("metadata", "manifest.request")
    request, manifest, manifest_hash = metadata(args.pipeline_dir)
    if args.command == "finalize":
        code_binding(args.pipeline_dir, None, event, env, minimal=True)
        passed = env.get("SOURCE_MATRIX_RESULT") == "success" and env.get("SOURCE_ADMISSION_RESULT") == "success"
        summarize({"campaignId": CAMPAIGN, "round": request["round"], "sourceSha": SOURCE,
                   "sourceTree": TREE, "status": "passed" if passed else "failed",
                   "coverage": "combined_successor" if request["round"] == 2 or request["initialResume"] is not None else "targeted_correction_only",
                   "sourceWitness": request["sourceWitness"],
                   "productionAuthorized": False, "imageBuilt": False}, env)
        return 0 if passed else 1
    need(args.source_dir is not None, "source checkout required")
    admission_stage("binding", "code.bind")
    code_binding(args.pipeline_dir, args.source_dir, event, env)
    if args.command in ("fetch-closure", "run"):
        profile = args.profile if args.command == "run" else env.get("SOURCE_PROFILE")
        need(profile in profiles_for(request), "profile not in admitted request")
        deadline_check(env, profile)
    if args.command == "fetch-closure":
        fetch_closure(args.pipeline_dir, args.source_dir)
        return 0
    if args.command == "admit":
        admission_stage("history", "current-pr")
        token = env.get("GH_SOURCE_READ_TOKEN", "")
        need(bool(token), "read-only API token required")
        budget = history_checks(request, event, env, args.pipeline_dir, lambda p: api_json(p, token))
        admission_stage("closure", "closure.acquire")
        fetch_closure(args.pipeline_dir, args.source_dir)
        admission_stage("equivalence", "equivalence.verify")
        equivalence = verify_test_only_successor(args.source_dir, request)
        budget["testOnlyEquivalence"] = equivalence
        admission_stage("matrix", "matrix.publish")
        matrix = {"include": [{"profile": p, "minutes": PROFILE_MINUTES[p]} for p in profiles_for(request)]}
        with open(env["GITHUB_OUTPUT"], "a", encoding="utf-8") as out:
            out.write("matrix=" + json.dumps(matrix, separators=(",", ":")) + "\n")
            out.write("deadline_epoch=" + str(budget["deadlineEpoch"]) + "\n")
        summarize({"campaignId": CAMPAIGN, "round": request["round"], "sourceSha": SOURCE,
                   "sourceTree": TREE, "manifestSha256": manifest_hash, **budget,
                   "authorization": "source-validation-only", "productionAuthorized": False}, env)
        return 0
    need(args.profile in profiles_for(request), "profile not in admitted request")
    summarize({"campaignId": CAMPAIGN, "profile": args.profile, "phase": "profile",
               "status": "started", "sourceSha": SOURCE, "sourceTree": TREE}, {})
    with profile_signals():
        try:
            source_preflight(args.pipeline_dir, args.source_dir, manifest, manifest_hash)
            witness = verify_test_only_successor(args.source_dir, request)
            paths = git(args.source_dir, "ls-tree", "-r", "--name-only", SOURCE).decode().splitlines()
            planned = commands(args.pipeline_dir, args.source_dir, args.profile, paths)
            resources = resource_check(args.source_dir)
            summarize({"campaignId": CAMPAIGN, "profile": args.profile, "engineeringFloorsPassed": True,
                       **resources}, env)
            # Each job owns a synthetic HOME, state and toolchain. No cross-run cache or
            # dependency/source/database/config artifact is exported.
            with tempfile.TemporaryDirectory(prefix="v108-source-") as directory:
                home = Path(directory)
                child_env = clean_env(home, env)
                context = {"profile": args.profile, "deadlineEpoch": profile_deadline(env, args.profile)}
                summarize({"campaignId": CAMPAIGN, "profile": args.profile, "phase": "bootstrap",
                           "status": "started"}, {})
                pnpm = bootstrap_pnpm(home, child_env)
                summarize({"campaignId": CAMPAIGN, "profile": args.profile, "phase": "bootstrap",
                           "status": "completed"}, {})
                planned = [[str(pnpm), *argv[1:]] if argv[0] == "pnpm" else argv for argv in planned]
                installation = phase_process([str(pnpm), "install", "--frozen-lockfile"],
                                             args.source_dir, child_env, context, "install", 0)
                need(installation.returncode == 0 and not installation.timed_out, "frozen install failed")
                cwd = args.pipeline_dir if args.profile == "pipeline-contracts" else args.source_dir
                outcomes = run_commands(planned, cwd, child_env, context=context)
                summarize({"campaignId": CAMPAIGN, "round": request["round"], "profile": args.profile,
                           "sourceSha": SOURCE, "sourceTree": TREE, "phase": "profile",
                       "status": "failed" if any(outcomes) else "passed", "exitCodes": outcomes,
                       "completedCommandCount": len(outcomes), "plannedCommandCount": len(planned),
                           "selectedTestCount": len(selected_tests(paths, args.profile)),
                           "testOnlyEquivalence": witness,
                           "productionAuthorized": False, "imageBuilt": False}, env)
                return int(any(outcomes))
        except (release.Refusal, OSError, ValueError, KeyError, TypeError,
                subprocess.CalledProcessError, ProfileInterrupted) as error:
            summarize({"campaignId": CAMPAIGN, "profile": args.profile, "phase": "profile",
                       "status": "interrupted" if isinstance(error, ProfileInterrupted) else "refused",
                       "errorClass": type(error).__name__, "sourceSha": SOURCE, "sourceTree": TREE,
                       "signal": signal.SIGTERM if isinstance(error, ProfileInterrupted) else None,
                       "productionAuthorized": False, "imageBuilt": False}, {})
            raise


def entrypoint():
    try:
        return main()
    except (release.Refusal, OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError, ProfileInterrupted):
        # Do not print exception data from API/credential-bearing child contexts.
        print("source-validation: refused; inspect bounded structured admission/step diagnostics", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(entrypoint())
