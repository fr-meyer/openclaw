"""Closed 10.9 CI policy and source-derivation contract.

Pure functions only. These records constrain an approved operator; neither a
matching record nor a timestamp grants publication, execution or cloud authority.
The current prepared binding is disarmed until the coordinating owner receives
and records actual approval. There is no image, cloud or native runtime command.
"""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import bounded_run_contract_v109 as run_allowance
import re


SCHEMA = "openclaw.fork-source-validation-request.v9"
BINDINGS_SCHEMA = "openclaw.v109.ci-bindings.v1"
AUTH_SCHEMA = "openclaw.v109.public-ci-authorization.v1"
GENERATION_SCHEMA = "openclaw.v109.lock-derivation.v1"
CAMPAIGN = "future-v109-grouped-validation-20261030"
REPOSITORY = "fr-meyer/openclaw"
WORKFLOW = ".github/workflows/future-v109-source-validation.yml"
PIPELINE_BRANCH = "task/v107-source-binding"
SOURCE_BRANCH = "prep/v2026.10.9-remediation"
BASE_BRANCH = "release-pipeline/v105-image-only-20261024"
BASE = "a65f70c5dad17b39bc3ee26ba92cde6d00bfb259"
PIPELINE_RECOVERY_SCHEMA = "openclaw.v109.pipeline-preparation-recovery.v1"
PREPARATION_FAILURE_EVIDENCE = "scripts/fork-release/candidates/v2026.10.9-source-only/preparation-failure-40997868140.json"
PREPARATION_FAILURE_EVIDENCE_SHA256 = "af64a6728b88d0e520f24722871ef760c5181e1492b9142b1f9af0944c060856"
FAILED_PREPARATION_PIN = {"runId": "40997868140", "pipelineHead": "84b825aca15a58191e718a958a356dcc305d4e47",
    "requestSha256": "cf52903c8a20e94684e3a6fcb5e947b8336eca62e66f0744efcda4d4d054a9ef"}
ADDITIONAL_PIPELINE_RECOVERY_SCHEMA = "openclaw.v109.additional-pipeline-preparation-recovery.v1"
ADDITIONAL_APPROVAL_SCHEMA = "openclaw.v109.additional-preparation-approval.v1"
ADDITIONAL_PREPARATION_FAILURE_EVIDENCE = "scripts/fork-release/candidates/v2026.10.9-source-only/preparation-failure-41003661031.json"
ADDITIONAL_PREPARATION_FAILURE_EVIDENCE_SHA256 = "15efc4c98e7caccc8f532ec58f676ed642a9aa8670cf0d7a9a7d42f62a87897d"
SECOND_FAILED_PREPARATION_PIN = {"runId": "41003661031", "pipelineHead": "409704dd078c83d2f41ed709660633c619b172be",
    "requestSha256": "5c4f7d4a56d959ba21d77dd00ca6868a49eb18519ada393e639d002fe68ae5ff"}
ORIGINAL_AUTHORIZATION_SHA256 = "af503856db977750026d77e0e53d63ad2ec0f617254c346ca55ef2a8e110f3d8"
ORIGINAL_APPROVAL_PACKET_SHA256 = "204817fab9a8f6fc8c9f670e728e7e349e1376a46740efb504ab4c957c87da76"
ORIGINAL_RECOVERY_SOURCE_SHA = "ba04217f6642091b94f396669318d068e6007ed7"
ADDITIONAL_RECOVERY_NOT_BEFORE = "2026-10-30T04:40:43Z"
PREPARATION_FAMILY_MINUTES = 90
BASELINE_SOURCE = "e6c4786dafbc8308661ea8fa14a81e06873d1630"
BASELINE_PIPELINE = "37400d942839bee0b92852037d6f8bf99e60358c"
BASELINE_RUN = "40901336241"
UPSTREAM = {"tag": "v2026.10.9", "tagObject": "88a19e0d8677804d8ec98e30a3a3a3a9308ebee0",
            "commit": "8b18b5578f66eab1501cba4cef2310d88bfb9a41",
            "tree": "3ccfb9632d8f30196d0f9d94f92f8cc7f07b2be7"}
LEDGER = "custom-patches/reconciliation-2026.10.9.json"
INPUTS = ("package.json", "pnpm-workspace.yaml", "pnpm-lock.yaml", LEDGER)
FIXTURE_CORRECTION_PATH = "src/state/openclaw-agent-db-lease.exited-owner.test.ts"
FIXTURE_CORRECTION_PARENT = "edd010829dcb622d7dc60dc90f7097048cb78819"
FIXTURE_CORRECTION_SOURCE_PIN_SHA256 = "3c9f36ea1d45f9787cf08198a4de869e57f689311521acfe4f10295962eb0a63"
FIXTURE_CORRECTION_GENERATION_SHA256 = "83dfb391140b1f575cc9cdc012422125a263b58fce516b80b1852045be4f5262"
FIXTURE_CORRECTION_BEFORE_SHA256 = "ebb1325d8c877db46fe005093bfa29bff7e27069bcd9a3915ccb7ed90e80ac72"
FIXTURE_CORRECTION_AFTER_SHA256 = "5cbe5159cb2b7b4f38cf123b881f59a69ea4103ded371d06845ba5589703bffa"
FIXTURE_CORRECTION_BEFORE_BLOB = "fca5a1d4f0d1778310f27b2ddb2877148a1cb7ed"
FIXTURE_CORRECTION_AFTER_BLOB = "ddbfc567415e9d6fbc01648f1e4e620b7c9fca0d"
FIXTURE_CORRECTION_PRIOR_VALIDATION = {"runId": "41052090949",
    "pipelineHead": "3722c8935ded3b3e249054fe6db2f3a50def8b8c",
    "requestSha256": "139ef96602ea6920715a9802a829e60424e0ddc3187e1d6a8196e7e9d2470cb9"}
PROFILES = ("dependency", "types-production", "types-tests", "types-scripts",
            "workboard-1", "workboard-2", "models-1", "models-2", "sqlite",
            "doctor-1", "doctor-2", "doctor-3", "memory", "pipeline-contracts", "compatibility")
PROFILE_MINUTES = dict(zip(PROFILES, (60, 90, 90, 90, 60, 60, 60, 60, 60, 90, 75, 75, 60, 45, 60)))
PREPARATION_MINUTES = 45
MAXIMUM_PREPARATIONS = 2  # The second job belongs to the one reviewed source correction.
ADMISSION_MINUTES = 30
FINAL_MINUTES = 10
SOURCE_MINUTES = 1075
IMAGE_FAMILY_MINUTES = 180  # Reserved to a separate image owner; never executable here.
INCIDENTAL_MINUTES = 50
MAXIMUM_NEW_MINUTES = 2500
DIAGNOSTIC_BYTES = 64 * 1024 * 1024
ARTIFACT_BYTES = 2 * 1024 * 1024
AUTH_HOURS = 96
REGISTRY_PROOF_SHA256 = "05bcbaf5a7bf3fb19046534d239ac25db140f34054c7f2cc38c6c1f2d09f9b97"
REGISTRY_PINS = (
    {"package": "@azure/msal-node", "version": "7.1.1", "publishedAt": "2026-10-21T19:21:33.186Z",
     "distIntegrity": "sha512-zHXTJB38XVrsNaXrPBCMqEUjeyQysFfgmKtUHRDsEKTRjNIPckJ/w6fE5wBXrmJXBim1D3C7O7LOag0msPTrgw=="},
    {"package": "@azure/msal-common", "version": "16.14.3", "publishedAt": "2026-10-21T19:12:59.113Z",
     "distIntegrity": "sha512-tz3GvMrR9V/plb2lDdW8qaO8CPpfZevdExBKjltzzbAtyhK0eB2UIvji1aU+gkyHj3fxQ2ie+LNHyMXdmo8wOg=="},
)
PHASES = ("lock-preparation", "validation", "correction")
SYNTHETIC_LIVE_UNIT_PATHS = frozenset((
    "src/agents/tool-search.live-diagnostics.test.ts",
    "test/scripts/ci-hydrate-live-auth.test.ts",
))
SHA = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
RUN_ID = re.compile(r"[1-9][0-9]{0,19}\Z")
TEST_PATH = re.compile(r"[A-Za-z0-9_./@+-]+\.(?:test|e2e)\.[cm]?[jt]s\Z")


class Refusal(ValueError):
    pass


def need(value, code):
    if not value:
        raise Refusal(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (json.dumps(value, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def parse(raw, maximum=ARTIFACT_BYTES):
    need(type(raw) is bytes and len(raw) <= maximum, "v9.bounded_json")
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "v9.duplicate_json_key")
            result[key] = value
        return result
    def constant(_):
        raise Refusal("v9.json_constant")
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except Refusal:
        raise
    except (ValueError, UnicodeError):
        raise Refusal("v9.invalid_json")


def fields(value, expected, code):
    need(type(value) is dict and set(value) == set(expected), code)
    return value


def pin(value, bits=256):
    return type(value) is str and (SHA256 if bits == 256 else SHA).fullmatch(value) is not None


def utc(value):
    need(type(value) is str and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value),
         "v9.canonical_utc")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise Refusal("v9.canonical_utc")
    need(parsed.strftime("%Y-%m-%dT%H:%M:%SZ") == value, "v9.canonical_utc")
    return parsed


def validate_authorization(value, now=None):
    fields(value, ("schema", "label", "approvedAt", "expiresAt", "maximumRunnerMinutes",
        "maximumSourceCampaigns", "maximumParallelSourceJobs", "maximumLockPreparations",
        "diagnosticByteCeiling", "lockArtifactByteCeiling", "imageExecutionAllowedHere",
        "cloudAccessAllowedHere", "newSecretsAllowedHere"), "v9.authorization_fields")
    need(value["schema"] == AUTH_SCHEMA and type(value["label"]) is str and
        re.fullmatch(r"future-v109-grouped-\d{8}T\d{6}Z", value["label"]), "v9.authorization_label")
    start, end = utc(value["approvedAt"]), utc(value["expiresAt"])
    need(end - start == timedelta(hours=AUTH_HOURS), "v9.exact_96_hour_window")
    need(value["maximumRunnerMinutes"] == MAXIMUM_NEW_MINUTES and
        type(value["maximumRunnerMinutes"]) is int and value["maximumSourceCampaigns"] == 2 and
        type(value["maximumSourceCampaigns"]) is int and value["maximumParallelSourceJobs"] == 3 and
        type(value["maximumParallelSourceJobs"]) is int and value["maximumLockPreparations"] == MAXIMUM_PREPARATIONS and
        type(value["maximumLockPreparations"]) is int and value["diagnosticByteCeiling"] == DIAGNOSTIC_BYTES and
        type(value["diagnosticByteCeiling"]) is int and value["lockArtifactByteCeiling"] == ARTIFACT_BYTES and
        type(value["lockArtifactByteCeiling"]) is int and value["imageExecutionAllowedHere"] is False and
        value["cloudAccessAllowedHere"] is False and value["newSecretsAllowedHere"] is False,
        "v9.exact_source_only_limits")
    if now is not None:
        need(type(now) in (int, float) and start.timestamp() <= now < end.timestamp(), "v9.authorization_clock")
    return value


def source_pin(value):
    fields(value, ("sourceSha", "sourceTree", "manifestSha256", "inventorySha256", "fileSha256"),
           "v9.source_pin_fields")
    need(pin(value["sourceSha"], 160) and pin(value["sourceTree"], 160) and
        pin(value["manifestSha256"]) and pin(value["inventorySha256"]), "v9.source_pin_digests")
    fields(value["fileSha256"], INPUTS, "v9.source_input_fields")
    need(all(pin(v) for v in value["fileSha256"].values()), "v9.source_input_digests")
    return value


def generation_pin(value):
    fields(value, ("runId", "runAttempt", "pipelineHead", "artifactId", "artifactSha256",
        "receiptSha256", "generatedLockSha256", "gitDiffSha256"), "v9.generation_pin_fields")
    need(type(value["runId"]) is str and RUN_ID.fullmatch(value["runId"]) and
        type(value["runAttempt"]) is int and value["runAttempt"] == 1 and
        pin(value["pipelineHead"], 160) and type(value["artifactId"]) is int and value["artifactId"] > 0 and
        all(pin(value[k]) for k in ("artifactSha256", "receiptSha256", "generatedLockSha256", "gitDiffSha256")),
        "v9.generation_pin_values")
    return value


def run_grant(bindings):
    return bindings.get("ciRunGrant")


def prepare_run_grant_binding(bindings, grant):
    """Pure binding proposal; never writes or invents a review/approval/request."""
    validate_bindings(bindings)
    result = deepcopy(bindings)
    result["preparationCorrection"] = {"schema": ADDITIONAL_PIPELINE_RECOVERY_SCHEMA,
        "source": deepcopy(result["preparation"]), "priorPhase": "lock-preparation",
        "priorFailures": [deepcopy(FAILED_PREPARATION_PIN), deepcopy(SECOND_FAILED_PREPARATION_PIN)],
        "failedPreparationAttempts": [1, 2], "nextPreparationAttempt": 3,
        "evidenceSha256": {"1": PREPARATION_FAILURE_EVIDENCE_SHA256,
            "2": ADDITIONAL_PREPARATION_FAILURE_EVIDENCE_SHA256},
        "approval": {"schema": ADDITIONAL_APPROVAL_SCHEMA, "status": "DISARMED",
            "approvalEvidenceSha256": None, "approvedAt": None,
            "expiresAt": result["authorization"]["expiresAt"],
            "originalAuthorizationSha256": ORIGINAL_AUTHORIZATION_SHA256,
            "additionalPipelineCorrections": 1, "additionalLockPreparations": 1,
            "additionalSourceCampaigns": 0, "optionalCorrectionsAllowed": False}}
    result["correction"] = None
    result["ciRunGrant"] = deepcopy(grant)
    result["status"] = "APPROVED_CI" if grant["status"] == "APPROVED" else "DISARMED"
    validate_bindings(result)
    return result


def validate_run_grant(bindings, active=False, now=None):
    value = run_grant(bindings)
    if value is None:
        return None
    try:
        run_allowance.validate_grant(value, bindings["authorization"], active, now)
    except ValueError as exc:
        raise Refusal(str(exc))
    source_pin(value["nextExecution"]["source"])
    return value


def additional_pipeline_preparation_recovery(value):
    """Closed discriminator only; it never supplies approval or a request."""
    return type(value) is dict and value.get("schema") == ADDITIONAL_PIPELINE_RECOVERY_SCHEMA


def validate_additional_approval(value, original, active=False, now=None):
    fields(value, ("schema", "status", "approvalEvidenceSha256", "approvedAt", "expiresAt",
        "originalAuthorizationSha256", "additionalPipelineCorrections", "additionalLockPreparations",
        "additionalSourceCampaigns", "optionalCorrectionsAllowed"), "v9.additional_approval_fields")
    need(type(original) is dict and digest(canonical(original)) == ORIGINAL_AUTHORIZATION_SHA256 and
        value["schema"] == ADDITIONAL_APPROVAL_SCHEMA and value["status"] in ("DISARMED", "APPROVED_RECOVERY") and
        value["originalAuthorizationSha256"] == ORIGINAL_AUTHORIZATION_SHA256 and
        value["expiresAt"] == original["expiresAt"] and
        type(value["additionalPipelineCorrections"]) is int and value["additionalPipelineCorrections"] == 1 and
        type(value["additionalLockPreparations"]) is int and value["additionalLockPreparations"] == 1 and
        type(value["additionalSourceCampaigns"]) is int and value["additionalSourceCampaigns"] == 0 and
        value["optionalCorrectionsAllowed"] is False, "v9.additional_approval_scope")
    if value["status"] == "DISARMED":
        need(value["approvalEvidenceSha256"] is None and value["approvedAt"] is None and not active,
            "v9.additional_approval_disarmed")
        return value
    need(pin(value["approvalEvidenceSha256"]) and value["approvalEvidenceSha256"] not in
        (ORIGINAL_AUTHORIZATION_SHA256, ORIGINAL_APPROVAL_PACKET_SHA256), "v9.genuine_new_approval_required")
    approved, expires = utc(value["approvedAt"]), utc(value["expiresAt"])
    need(utc(ADDITIONAL_RECOVERY_NOT_BEFORE) < approved < expires,
        "v9.additional_approval_after_both_failures")
    if now is not None:
        need(type(now) in (int, float) and approved.timestamp() <= now < expires.timestamp(),
            "v9.additional_approval_clock")
    return value


def same_generation_fixture_correction(bindings):
    """Closed branch discriminator; validate_bindings still proves every field."""
    c, v = bindings.get("correction"), bindings.get("validation")
    return (run_grant(bindings) is not None and type(c) is dict and type(v) is dict and
        type(c.get("preparationAttempt")) is int and c["preparationAttempt"] == 6 and
        type(v.get("preparationAttempt")) is int and v["preparationAttempt"] == 6 and
        type(v.get("source")) is dict and v["source"].get("sourceSha") == FIXTURE_CORRECTION_PARENT and
        c.get("parentSource") == FIXTURE_CORRECTION_PARENT and c.get("generation") == v.get("generation"))


def validate_same_generation_fixture_correction(bindings):
    c, v = bindings["correction"], bindings["validation"]
    need(same_generation_fixture_correction(bindings), "v9.fixture_correction_not_bound")
    need(digest(canonical(v["source"])) == FIXTURE_CORRECTION_SOURCE_PIN_SHA256 and
        digest(canonical(v["generation"])) == FIXTURE_CORRECTION_GENERATION_SHA256 and
        c["priorValidation"] == FIXTURE_CORRECTION_PRIOR_VALIDATION and
        c["source"]["sourceSha"] not in (FIXTURE_CORRECTION_PARENT, ORIGINAL_RECOVERY_SOURCE_SHA) and
        c["changedPaths"] == sorted((FIXTURE_CORRECTION_PATH, LEDGER)) and
        c["contentSha256"][FIXTURE_CORRECTION_PATH] == FIXTURE_CORRECTION_AFTER_SHA256 and
        c["source"]["fileSha256"][LEDGER] == c["contentSha256"][LEDGER] and
        all(c["source"]["fileSha256"][p] == v["source"]["fileSha256"][p]
            for p in ("package.json", "pnpm-workspace.yaml", "pnpm-lock.yaml")),
        "v9.exact_same_generation_fixture_correction")
    return c


def expected_fixture_correction_ledger(before, fixture_blob):
    """One existing row only; lock derivation and every other JSON fact survive."""
    need(fixture_blob == FIXTURE_CORRECTION_AFTER_BLOB, "v9.fixture_correction_blob")
    value = parse(before)
    need(type(value) is dict and value.get("schema") == "openclaw.v109.fork-carry-reconciliation.v1" and
        value.get("lockState") == "ci_derived" and type(value.get("sourcePaths")) is list and
        all(type(row) is dict and type(row.get("path")) is str for row in value["sourcePaths"]) and
        len({row["path"] for row in value["sourcePaths"]}) == len(value["sourcePaths"]),
        "v9.fixture_correction_ledger_state")
    rows = [row for row in value["sourcePaths"] if type(row) is dict and row.get("path") == FIXTURE_CORRECTION_PATH]
    need(len(rows) == 1 and rows[0].get("disposition") == "CARRIED_EXACT" and
        rows[0].get("result") == {"mode": "100644", "blob": FIXTURE_CORRECTION_BEFORE_BLOB},
        "v9.fixture_correction_original_row")
    result = deepcopy(value)
    row = next(row for row in result["sourcePaths"] if row["path"] == FIXTURE_CORRECTION_PATH)
    row["result"] = {"mode": "100644", "blob": fixture_blob}
    row["disposition"] = "ADAPTED_SECURITY_TEST"
    return encode(result)


def validate_additional_recovery(value, bindings, active=False, now=None):
    fields(value, ("schema", "source", "priorPhase", "priorFailures", "failedPreparationAttempts",
        "nextPreparationAttempt", "evidenceSha256", "approval"), "v9.additional_recovery_fields")
    source_pin(value["source"])
    need(value["source"] == bindings["preparation"] and value["source"]["sourceSha"] == ORIGINAL_RECOVERY_SOURCE_SHA and
        value["priorPhase"] == "lock-preparation" and
        value["priorFailures"] == [FAILED_PREPARATION_PIN, SECOND_FAILED_PREPARATION_PIN] and
        value["failedPreparationAttempts"] == [1, 2] and all(type(n) is int for n in value["failedPreparationAttempts"]) and
        type(value["nextPreparationAttempt"]) is int and value["nextPreparationAttempt"] == 3 and
        value["evidenceSha256"] == {"1": PREPARATION_FAILURE_EVIDENCE_SHA256,
            "2": ADDITIONAL_PREPARATION_FAILURE_EVIDENCE_SHA256} and
        (bindings["correction"] is None or same_generation_fixture_correction(bindings)),
        "v9.exact_additional_pipeline_recovery")
    for prior in value["priorFailures"]:
        run_pin(prior)
    validate_additional_approval(value["approval"], bindings["authorization"],
        active and run_grant(bindings) is None, now if run_grant(bindings) is None else None)
    return value


def validate_bindings(value, active=False, now=None):
    fields(value, ("schema", "status", "campaignId", "repository", "workflow", "pipelineBranch",
        "sourceBranch", "baseBranch", "baseSha", "upstream", "baseline", "preparation", "preparationCorrection",
        "validation", "correction", "authorization", "newRecoveryTests") +
        (("ciRunGrant",) if type(value) is dict and "ciRunGrant" in value else ()), "v9.bindings_fields")
    need(value["schema"] == BINDINGS_SCHEMA and value["status"] in ("DISARMED", "APPROVED_CI") and
        value["campaignId"] == CAMPAIGN and value["repository"] == REPOSITORY and
        value["workflow"] == WORKFLOW and value["pipelineBranch"] == PIPELINE_BRANCH and
        value["sourceBranch"] == SOURCE_BRANCH and value["baseBranch"] == BASE_BRANCH and
        value["baseSha"] == BASE and value["upstream"] == UPSTREAM, "v9.fixed_binding_scope")
    b = fields(value["baseline"], ("sourceSha", "pipelineHead", "sourceRunId", "runCount",
        "runnerMinutes", "publicProofSha256"), "v9.baseline_fields")
    need(b["sourceSha"] == BASELINE_SOURCE and b["pipelineHead"] == BASELINE_PIPELINE and
        b["sourceRunId"] == BASELINE_RUN and type(b["runCount"]) is int and b["runCount"] == 258 and
        type(b["runnerMinutes"]) is int and b["runnerMinutes"] == 2944 and pin(b["publicProofSha256"]),
        "v9.baseline_binding")
    source_pin(value["preparation"])
    grant = validate_run_grant(value, active, now)
    pc = value["preparationCorrection"]
    if pc is not None:
        if additional_pipeline_preparation_recovery(pc):
            validate_additional_recovery(pc, value, active, now)
        elif pipeline_preparation_recovery(pc):
            fields(pc, ("schema", "source", "priorPhase", "priorFailure", "failedPreparationAttempt",
                "nextPreparationAttempt", "reasonCode", "evidenceSha256"), "v9.pipeline_recovery_fields")
            source_pin(pc["source"]); run_pin(pc["priorFailure"])
            need(pc["source"] == value["preparation"] and pc["priorPhase"] == "lock-preparation" and
                pc["priorFailure"] == FAILED_PREPARATION_PIN and
                type(pc["failedPreparationAttempt"]) is int and pc["failedPreparationAttempt"] == 1 and
                type(pc["nextPreparationAttempt"]) is int and pc["nextPreparationAttempt"] == 2 and
                pc["reasonCode"] == "v9.workflow_merge_parents" and
                pc["evidenceSha256"] == PREPARATION_FAILURE_EVIDENCE_SHA256,
                "v9.exact_pipeline_only_preparation_recovery")
            need(value["correction"] is None, "v9.pipeline_correction_already_consumed")
        else:
            fields(pc, ("source", "parentSource", "changedPaths", "contentSha256", "unchangedTreeSha256",
                "priorFailure", "priorPhase"), "v9.preparation_correction_fields")
            source_pin(pc["source"]); run_pin(pc["priorFailure"])
            need(pc["priorPhase"] in ("lock-preparation", "validation"), "v9.preparation_correction_phase")
            parent = value["preparation"] if pc["priorPhase"] == "lock-preparation" else (
                value["validation"]["source"] if type(value["validation"]) is dict else None)
            need(parent is not None and pc["parentSource"] == parent["sourceSha"] and
                pin(pc["unchangedTreeSha256"]) and pc["source"]["fileSha256"]["package.json"] ==
                value["preparation"]["fileSha256"]["package.json"], "v9.preparation_correction_parent")
            correction_paths(pc)
    tests = value["newRecoveryTests"]
    need(type(tests) is list and tests == sorted(set(tests)) and bool(tests) and all(
        type(p) is str and TEST_PATH.fullmatch(p) and not p.startswith("/") and
        not any(x in ("", ".", "..") for x in p.split("/")) and
        (not re.search(r"(?:^|[./-])live(?:[./-]|$)", p) or p in SYNTHETIC_LIVE_UNIT_PATHS) for p in tests), "v9.reviewed_new_recovery_tests")
    if value["validation"] is not None:
        v = fields(value["validation"], ("source", "generation", "unchangedTreeSha256", "preparationAttempt"), "v9.validation_binding_fields")
        source_pin(v["source"]); generation_pin(v["generation"])
        need(pin(v["unchangedTreeSha256"]), "v9.validation_tree_witness")
        prep = preparation_for(value, v["preparationAttempt"])
        if additional_pipeline_preparation_recovery(pc) and grant is None:
            need(v["preparationAttempt"] == 3, "v9.additional_single_validation_from_third")
        need(v["preparationAttempt"] == 1 or pc["priorPhase"] == "lock-preparation", "v9.initial_validation_preparation")
        need(v["source"]["sourceSha"] != prep["sourceSha"] and
            all(v["source"]["fileSha256"][p] == prep["fileSha256"][p]
                for p in ("package.json", "pnpm-workspace.yaml")) and
            v["source"]["fileSha256"]["pnpm-lock.yaml"] == v["generation"]["generatedLockSha256"],
            "v9.lock_only_dependency_derivation")
    if value["correction"] is not None:
        need(value["validation"] is not None, "v9.correction_requires_validation")
        c = fields(value["correction"], ("source", "parentSource", "changedPaths", "contentSha256",
            "unchangedTreeSha256", "priorValidation", "preparationAttempt", "generation"), "v9.correction_binding_fields")
        source_pin(c["source"])
        run_pin(c["priorValidation"])
        correction_paths(c)
        fixture_only = same_generation_fixture_correction(value)
        need(fixture_only or value["validation"]["preparationAttempt"] == 1, "v9.only_one_source_correction")
        if fixture_only:
            validate_same_generation_fixture_correction(value)
        elif c["preparationAttempt"] == 1:
            need(pc is None and c["parentSource"] == value["validation"]["source"]["sourceSha"] and
                c["generation"] == value["validation"]["generation"] and
                all(c["source"]["fileSha256"][p] == value["validation"]["source"]["fileSha256"][p]
                    for p in ("package.json", "pnpm-workspace.yaml", "pnpm-lock.yaml")),
                "v9.correction_no_dependency_scope_expansion")
        else:
            need(type(c["preparationAttempt"]) is int and c["preparationAttempt"] == 2 and
                pc is not None and pc["priorPhase"] == "validation" and
                pc["priorFailure"] == c["priorValidation"] and c["parentSource"] == pc["source"]["sourceSha"] and
                c["changedPaths"] == sorted(("pnpm-lock.yaml", LEDGER)) and
                all(c["source"]["fileSha256"][p] == pc["source"]["fileSha256"][p]
                    for p in ("package.json", "pnpm-workspace.yaml")), "v9.corrected_lock_derivation_only")
            generation_pin(c["generation"])
            need(c["source"]["fileSha256"]["pnpm-lock.yaml"] == c["generation"]["generatedLockSha256"],
                "v9.corrected_generation_lock")
    if grant is not None and grant["nextExecution"]["phase"] == "correction":
        need(same_generation_fixture_correction(value) and
            grant["nextExecution"]["source"] == value["correction"]["source"] and
            grant["nextExecution"]["preparationAttempt"] == 6 and
            grant["nextExecution"]["reasonCode"] in ("prior_failure", "reviewed_pipeline_correction"),
            "v9.closed_fixture_correction_plan")
    if value["status"] == "DISARMED":
        preserved_only = (((additional_pipeline_preparation_recovery(pc) and
            pc["approval"]["status"] == "DISARMED") or grant is not None) and
            digest(canonical(value["authorization"])) == ORIGINAL_AUTHORIZATION_SHA256)
        need(not active and (value["authorization"] is None or preserved_only), "v9.disarmed")
    else:
        validate_authorization(value["authorization"], now)
    if active:
        need(value["status"] == "APPROVED_CI", "v9.disarmed")
    return value



def pipeline_preparation_recovery(value):
    """Closed discriminator, not proof: validation still checks exact fields/facts."""
    return type(value) is dict and value.get("schema") == PIPELINE_RECOVERY_SCHEMA


def validate_pipeline_recovery_evidence(raw, bindings):
    validate_bindings(bindings)
    pc = bindings["preparationCorrection"]
    need(pipeline_preparation_recovery(pc) and digest(raw) == pc["evidenceSha256"] ==
        PREPARATION_FAILURE_EVIDENCE_SHA256, "v9.pipeline_failure_evidence_digest")
    value = parse(raw, 65536)
    fields(value, ("schema", "repository", "runId", "runAttempt", "pipelineHead", "requestSha256",
        "workflow", "runName", "headBranch", "event", "runConclusion", "source", "preparationAttempt",
        "jobId", "jobName", "jobConclusion", "nativeStartedAt", "nativeCompletedAt", "failedStep", "failureCode",
        "skippedCandidateSteps", "artifactCount", "sourceCheckoutPerformed", "lockGenerationExecuted",
        "generationProduced", "nativeImageExecuted", "productionAuthorized", "producerRuntimeSha256",
        "producerWorkflowSha256", "nativeEvidenceSha256"), "v9.pipeline_failure_evidence_fields")
    need(value["schema"] == "openclaw.v109.preparation-intake-failure.v1" and
        value["repository"] == REPOSITORY and all(value[k] == v for k,v in FAILED_PREPARATION_PIN.items()) and
        type(value["runAttempt"]) is int and value["runAttempt"] == 1 and value["workflow"] == WORKFLOW and
        value["runName"] == CAMPAIGN and value["headBranch"] == PIPELINE_BRANCH and
        value["event"] == "pull_request" and value["runConclusion"] == "failure" and
        value["source"] == bindings["preparation"] == pc["source"] and
        type(value["preparationAttempt"]) is int and value["preparationAttempt"] == 1 and
        value["jobId"] == 123875131632 and type(value["jobId"]) is int and
        value["jobName"] == "lock-preparation" and value["jobConclusion"] == "failure" and
        value["failedStep"] == "Exact public admission and cumulative accounting" and
        value["failureCode"] == pc["reasonCode"] == "v9.workflow_merge_parents" and
        value["skippedCandidateSteps"] == ["Checkout exact admitted source", "Pinned public Node runtime",
            "Verify and acquire local public closure", "Derive lock only with secretless pinned pnpm",
            "Retain exact lock derivation for review"] and type(value["artifactCount"]) is int and
        value["artifactCount"] == 0 and all(value[k] is False for k in ("sourceCheckoutPerformed",
            "lockGenerationExecuted", "generationProduced", "nativeImageExecuted", "productionAuthorized")) and
        value["producerRuntimeSha256"] == "96be043eae4bd47dcda2d51784ef95562cb3b568bf29231c19a95276ae824807" and
        value["producerWorkflowSha256"] == "8741d7bb20253276ed13967ab61147d4b61a4520268c1fd41440005d020878c6",
        "v9.exact_failed_intake_without_generation")
    start, end = utc(value["nativeStartedAt"]), utc(value["nativeCompletedAt"])
    need(start <= end and (end-start).total_seconds() <= PREPARATION_MINUTES*60,
        "v9.failed_intake_native_clock")
    fields(value["nativeEvidenceSha256"], ("run", "jobs", "artifacts", "log", "canonicalMergeGraph",
        "executableClosure"), "v9.pipeline_failure_native_evidence_fields")
    need(all(pin(v) for v in value["nativeEvidenceSha256"].values()), "v9.pipeline_failure_native_evidence_hashes")
    return value


def validate_additional_pipeline_recovery_evidence(first_raw, second_raw, bindings):
    """Authenticate both immutable failed intakes; no generation is invented."""
    validate_bindings(bindings)
    pc = bindings["preparationCorrection"]
    need(additional_pipeline_preparation_recovery(pc), "v9.additional_recovery_not_bound")
    legacy = deepcopy(bindings)
    legacy["preparationCorrection"] = {"schema": PIPELINE_RECOVERY_SCHEMA,
        "source": deepcopy(bindings["preparation"]), "priorPhase": "lock-preparation",
        "priorFailure": deepcopy(FAILED_PREPARATION_PIN), "failedPreparationAttempt": 1,
        "nextPreparationAttempt": 2, "reasonCode": "v9.workflow_merge_parents",
        "evidenceSha256": PREPARATION_FAILURE_EVIDENCE_SHA256}
    legacy["validation"], legacy["correction"] = None, None
    legacy.pop("ciRunGrant", None)
    # This in-memory view describes the already approved first recovery. It
    # carries no supplemental approval or third request.
    legacy["status"] = "APPROVED_CI"
    first = validate_pipeline_recovery_evidence(first_raw, legacy)
    need(digest(second_raw) == ADDITIONAL_PREPARATION_FAILURE_EVIDENCE_SHA256,
        "v9.second_failure_evidence_digest")
    second = parse(second_raw, 65536)
    fields(second, tuple(first), "v9.second_failure_evidence_fields")
    same = ("schema", "repository", "runAttempt", "workflow", "runName", "headBranch", "event",
        "runConclusion", "source", "jobName", "jobConclusion", "failedStep", "skippedCandidateSteps",
        "artifactCount", "sourceCheckoutPerformed", "lockGenerationExecuted", "generationProduced",
        "nativeImageExecuted", "productionAuthorized", "producerWorkflowSha256")
    need(all(type(second[k]) is type(first[k]) and second[k] == first[k] for k in same) and
        all(second[k] == v for k,v in SECOND_FAILED_PREPARATION_PIN.items()) and
        type(second["preparationAttempt"]) is int and second["preparationAttempt"] == 2 and
        type(second["jobId"]) is int and second["jobId"] == 123893555647 and
        second["failureCode"] == "v9.closed_provider_jobs_changed" and
        second["nativeStartedAt"] == "2026-10-30T04:34:39Z" and
        second["nativeCompletedAt"] == ADDITIONAL_RECOVERY_NOT_BEFORE and
        second["producerRuntimeSha256"] == "8d734768690be68e8b02f49096631bf37d68619a7ed46edb5512a675bd1cf0a7",
        "v9.exact_second_failed_intake_without_generation")
    # The producer runtime pin is independently checked against the actual
    # hosted commit by the caller, along with native jobs and zero artifacts.
    fields(second["nativeEvidenceSha256"], ("run", "jobs", "artifacts", "log"),
        "v9.second_failure_native_evidence_fields")
    need(all(pin(v) for v in second["nativeEvidenceSha256"].values()) and
        utc(first["nativeCompletedAt"]) < utc(second["nativeStartedAt"]) < utc(second["nativeCompletedAt"]) and
        (utc(second["nativeCompletedAt"]) - utc(second["nativeStartedAt"])).total_seconds() <= PREPARATION_MINUTES * 60,
        "v9.second_failed_intake_native_clock")
    return [first, second]


def correction_paths(value):
    changed = value["changedPaths"]
    need(type(changed) is list and changed == sorted(set(changed)) and bool(changed) and
        len(changed) <= 64 and all(type(p) is str and re.fullmatch(r"[A-Za-z0-9_./@+-]+", p) and
            not p.startswith("/") and not any(x in ("", ".", "..") for x in p.split("/")) for p in changed),
        "v9.correction_changed_paths")
    fields(value["contentSha256"], changed, "v9.correction_content_paths")
    need(all(pin(v) for v in value["contentSha256"].values()) and pin(value["unchangedTreeSha256"]),
         "v9.correction_content_digests")


def preparation_for(bindings, attempt):
    grant = run_grant(bindings)
    if grant is not None and type(attempt) is int and 3 <= attempt <= 1002:
        return bindings["preparation"]
    need(type(attempt) is int and attempt in (1, 2, 3), "v9.preparation_attempt")
    if attempt == 1:
        return bindings["preparation"]
    if additional_pipeline_preparation_recovery(bindings["preparationCorrection"]):
        need(attempt == 3 and bindings["preparationCorrection"]["approval"]["status"] == "APPROVED_RECOVERY",
            "v9.third_preparation_new_approval_required")
        return bindings["preparation"]
    need(attempt == 2, "v9.third_preparation_not_bound")
    need(type(bindings["preparationCorrection"]) is dict, "v9.second_preparation_not_bound")
    return bindings["preparationCorrection"]["source"]


def run_pin(value):
    fields(value, ("runId", "pipelineHead", "requestSha256"), "v9.prior_run_fields")
    need(type(value["runId"]) is str and RUN_ID.fullmatch(value["runId"]) and
        pin(value["pipelineHead"], 160) and pin(value["requestSha256"]), "v9.prior_run_values")
    return value


def request_for(bindings, phase, preparation_attempt=1):
    validate_bindings(bindings)
    need(phase in PHASES, "v9.phase")
    additional = additional_pipeline_preparation_recovery(bindings["preparationCorrection"])
    grant = run_grant(bindings)
    if additional and grant is None:
        need(phase != "correction" and (phase != "lock-preparation" or preparation_attempt == 3),
            "v9.additional_only_third_and_single_validation")
    if phase == "lock-preparation":
        source, generation = preparation_for(bindings, preparation_attempt), None
        prior = (deepcopy(bindings["preparationCorrection"]["priorFailures"]) if additional else
            ([] if preparation_attempt == 1 else [bindings["preparationCorrection"]["priorFailure"]]))
    elif phase == "validation":
        need(bindings["validation"] is not None, "v9.validation_not_bound")
        v = bindings["validation"]
        source, generation, prior = v["source"], v["generation"], []
        preparation_attempt = v["preparationAttempt"]
    else:
        need(bindings["correction"] is not None, "v9.correction_not_bound")
        c = bindings["correction"]
        source, generation, prior = c["source"], c["generation"], [c["priorValidation"]]
        preparation_attempt = c["preparationAttempt"]
    result = {"schema": SCHEMA, "campaignId": CAMPAIGN, "phase": phase,
        "source": deepcopy(source), "settledUsageSha256": bindings["baseline"]["publicProofSha256"],
        "generation": deepcopy(generation), "priorRunPins": deepcopy(prior), "preparationAttempt": preparation_attempt,
        "profiles": [] if phase == "lock-preparation" else list(PROFILES),
        "authorizationSha256": digest(canonical(bindings["authorization"])) if bindings["authorization"] else None}
    if additional and grant is None:
        need(bindings["preparationCorrection"]["approval"]["status"] == "APPROVED_RECOVERY",
            "v9.third_preparation_new_approval_required")
        result["additionalApprovalSha256"] = digest(canonical(bindings["preparationCorrection"]["approval"]))
    if grant is not None:
        plan = grant["nextExecution"]
        need(phase == plan["phase"] and (phase != "correction" or same_generation_fixture_correction(bindings)) and
            preparation_attempt == plan["preparationAttempt"] and source == plan["source"], "v9.run_grant.plan_request")
        result["priorRunPins"] = [deepcopy(plan["priorSourceRun"])]
        result["executionSequence"] = plan["sequence"]
        result["runAllowanceSha256"] = run_allowance.AUTHORITY_SHA256
        result["executionReservations"] = deepcopy(plan["reservations"])
    return result


def validate_request(value, bindings, active=False, now=None):
    validate_bindings(bindings, active, now)
    need(type(value) is dict and value.get("phase") in PHASES and
        value == request_for(bindings, value["phase"], value.get("preparationAttempt")), "v9.closed_request")
    grant = run_grant(bindings)
    if grant is not None and (active or grant["nextExecution"]["requestSha256"] is not None):
        need(digest(encode(value)) == grant["nextExecution"]["requestSha256"], "v9.run_grant.reviewed_request_hash")
    return value


def budget(request):
    need(type(request) is dict and request.get("schema") == SCHEMA and request.get("phase") in PHASES,
         "v9.budget_request")
    if "runAllowanceSha256" in request:
        need(request["runAllowanceSha256"] == run_allowance.AUTHORITY_SHA256 and
            request["phase"] in ("lock-preparation", "validation", "correction"), "v9.run_grant.budget_scope")
        return {"phase": request["phase"], "phaseMaximumMinutes": PREPARATION_MINUTES if
            request["phase"] == "lock-preparation" else SOURCE_MINUTES,
            "preparationMinutesPerJob": PREPARATION_MINUTES, "maximumLockPreparations": 1002,
            "admissionMinutes": ADMISSION_MINUTES, "profileMinutes": dict(PROFILE_MINUTES),
            "finalMinutes": FINAL_MINUTES, "maximumSourceCampaigns": 1000, "maximumParallelSourceJobs": 3,
            "separateImageFamilyReserveMinutes": IMAGE_FAMILY_MINUTES, "maximumNewMinutes": MAXIMUM_NEW_MINUTES,
            "incidentalMinutes": request["executionReservations"]["incidental"],
            "currentPlanReservationMinutes": sum(request["executionReservations"].values()),
            "maximumBookedMinutes": MAXIMUM_NEW_MINUTES,
            "maximumAdditionalWorkflowAttempts": 1000, "maximumStageWorkflowAttempts": 1042}
    additional = "additionalApprovalSha256" in request
    if additional:
        need(pin(request["additionalApprovalSha256"]) and request.get("preparationAttempt") == 3 and
            type(request["preparationAttempt"]) is int and request["phase"] != "correction",
            "v9.additional_budget_scope")
    result = {"phase": request["phase"], "phaseMaximumMinutes": PREPARATION_MINUTES if
        request["phase"] == "lock-preparation" else SOURCE_MINUTES,
        "preparationMinutesPerJob": PREPARATION_MINUTES, "maximumLockPreparations": 3 if additional else MAXIMUM_PREPARATIONS,
        "admissionMinutes": ADMISSION_MINUTES,
        "profileMinutes": dict(PROFILE_MINUTES), "finalMinutes": FINAL_MINUTES,
        "maximumSourceCampaigns": 1 if additional else 2, "maximumParallelSourceJobs": 3,
        "separateImageFamilyReserveMinutes": IMAGE_FAMILY_MINUTES,
        "incidentalMinutes": INCIDENTAL_MINUTES, "maximumNewMinutes": MAXIMUM_NEW_MINUTES,
        "maximumBookedMinutes": MAXIMUM_PREPARATIONS * PREPARATION_MINUTES + (1 if additional else 2) * SOURCE_MINUTES + IMAGE_FAMILY_MINUTES + INCIDENTAL_MINUTES}
    if additional:
        result["preparationFamilyMinutes"] = PREPARATION_FAMILY_MINUTES
    return result


def remaining_deadline(bindings, started_epoch, phase, now):
    validate_bindings(bindings, active=True, now=now)
    need(type(started_epoch) is int and type(now) in (int, float) and started_epoch <= now,
         "v9.phase_clock")
    minutes = PREPARATION_MINUTES if phase == "lock-preparation" else ADMISSION_MINUTES
    need(phase in PHASES and now - started_epoch < minutes * 60, "v9.phase_clock")
    return min(started_epoch + minutes * 60 - 60, int(utc(bindings["authorization"]["expiresAt"]).timestamp()) - 60)


def validate_generation(raw, bindings, phase="validation"):
    validate_bindings(bindings)
    need(phase in ("validation", "correction") and bindings[phase] is not None, "v9.validation_not_bound")
    pinset = bindings[phase]["generation"]
    need(digest(raw) == pinset["receiptSha256"], "v9.generation_receipt_pin")
    value = parse(raw, 65536)
    expected = {"schema", "status", "sourceSha", "sourceTree", "pipelineHead", "runId", "runAttempt",
        "packageSha256", "workspaceSha256", "sourceLockSha256", "generatedLockSha256", "ledgerSha256",
        "nodeVersion", "pnpmVersion", "changedPaths", "gitDiffSha256", "allOtherTrackedEntriesUnchanged",
        "startedAt", "finishedAt", "exitCode", "timedOut", "cleanupSettled", "imageBuilt", "qualified",
        "productionAuthorized", "registryEvidence", "lockSecuritySha256"}
    fields(value, expected, "v9.generation_receipt_fields")
    p = preparation_for(bindings, bindings[phase]["preparationAttempt"])
    need(value["schema"] == GENERATION_SCHEMA and value["status"] == "derived_only" and
        value["sourceSha"] == p["sourceSha"] and value["sourceTree"] == p["sourceTree"] and
        value["pipelineHead"] == pinset["pipelineHead"] and value["runId"] == pinset["runId"] and
        value["runAttempt"] == 1 and type(value["runAttempt"]) is int and
        value["packageSha256"] == p["fileSha256"]["package.json"] and
        value["workspaceSha256"] == p["fileSha256"]["pnpm-workspace.yaml"] and
        value["sourceLockSha256"] == p["fileSha256"]["pnpm-lock.yaml"] and
        value["ledgerSha256"] == p["fileSha256"][LEDGER] and
        value["generatedLockSha256"] == pinset["generatedLockSha256"] and
        value["gitDiffSha256"] == pinset["gitDiffSha256"] and
        value["nodeVersion"] == "24.22.1" and value["pnpmVersion"] == "12.15.0" and
        value["changedPaths"] == ["pnpm-lock.yaml"] and value["allOtherTrackedEntriesUnchanged"] is True and
        type(value["exitCode"]) is int and value["exitCode"] == 0 and value["timedOut"] is False and
        (value["cleanupSettled"] is None or value["cleanupSettled"] is True) and value["imageBuilt"] is False and
        value["qualified"] is False and value["productionAuthorized"] is False and
        pin(value["lockSecuritySha256"]), "v9.generation_receipt_values")
    start, finish = utc(value["startedAt"]), utc(value["finishedAt"])
    need(start <= finish and (finish - start).total_seconds() <= PREPARATION_MINUTES * 60,
         "v9.generation_clock")
    if bindings["authorization"] is not None:
        need(utc(bindings["authorization"]["approvedAt"]) <= start <= finish <=
            utc(bindings["authorization"]["expiresAt"]), "v9.generation_authorization_clock")
    validate_registry_evidence(value["registryEvidence"], finish.timestamp())
    return value


def validate_registry_evidence(value, now):
    # These public metadata/integrity pins were independently retrieved and
    # registry-signature verified. A CI check of this pinned proof is not labeled
    # a new HTTP observation or a tarball signature/content verification.
    fields(value, ("proofSha256", "packages", "registry", "checkedAt", "minimumAgeMinutes",
        "checkKind", "parentDependency"), "v9.registry_fields")
    need(value["proofSha256"] == REGISTRY_PROOF_SHA256 and value["packages"] == list(REGISTRY_PINS) and
        value["registry"] == "https://registry.npmjs.org/" and value["minimumAgeMinutes"] == 10080 and
        type(value["minimumAgeMinutes"]) is int and
        value["checkKind"] == "recheck_pinned_registry_metadata_age_and_integrity" and
        value["parentDependency"] == {"package": "@azure/msal-node", "version": "7.1.1",
            "dependency": "@azure/msal-common", "dependencyVersion": "16.14.3"}, "v9.registry_identity")
    checked = utc(value["checkedAt"])
    need(0 <= now - checked.timestamp() <= PREPARATION_MINUTES * 60, "v9.registry_check_clock")
    for package in REGISTRY_PINS:
        stamp = datetime.fromisoformat(package["publishedAt"][:-1] + "+00:00")
        need(checked.timestamp() - stamp.timestamp() >= 10080 * 60, "v9.registry_seven_day_age")
    return value


def recheck_registry_proof(raw, checked_at):
    need(digest(raw) == REGISTRY_PROOF_SHA256, "v9.registry_proof_pin")
    proof = parse(raw, 65536)
    need(proof.get("schema") == "openclaw.public-npm-metadata-proof.v1" and
        proof.get("status") == "metadata_only" and type(proof.get("packages")) is list,
        "v9.registry_producer_proof")
    rows = {row.get("name"): row for row in proof["packages"] if type(row) is dict}
    need(len(rows) == len(proof["packages"]) == 4, "v9.registry_proof_unique_packages")
    for expected in REGISTRY_PINS:
        row = rows.get(expected["package"])
        need(type(row) is dict and row.get("version") == expected["version"] and
            row.get("publicationTime") == expected["publishedAt"] and
            row.get("dist", {}).get("integrity") == expected["distIntegrity"] and
            row.get("versionAndPackumentDistMatch") is True and
            type(row.get("registrySignatureResults")) is list and bool(row["registrySignatureResults"]) and
            all(type(sig) is dict and sig.get("returncode") == 0 and
                type(sig.get("returncode")) is int and sig.get("signatureVerified") is True and
                sig.get("keyIdMatchedRegistryEndpoint") is True for sig in row["registrySignatureResults"]),
            "v9.registry_proof_package_binding")
    need(rows["@azure/msal-node"]["dependencies"] ==
        {"@azure/msal-common": "16.14.3", "jsonwebtoken": "^9.0.0"}, "v9.registry_parent_child_binding")
    value = {"proofSha256": REGISTRY_PROOF_SHA256, "packages": deepcopy(list(REGISTRY_PINS)),
        "registry": "https://registry.npmjs.org/", "checkedAt": checked_at, "minimumAgeMinutes": 10080,
        "checkKind": "recheck_pinned_registry_metadata_age_and_integrity",
        "parentDependency": {"package": "@azure/msal-node", "version": "7.1.1",
            "dependency": "@azure/msal-common", "dependencyVersion": "16.14.3"}}
    return validate_registry_evidence(value, utc(checked_at).timestamp())


def expected_derived_ledger(before, generated_lock_blob, generation):
    ledger = parse(before)
    need(type(ledger) is dict and ledger.get("schema") == "openclaw.v109.fork-carry-reconciliation.v1" and
        ledger.get("lockState") == "pending_ci_derivation" and "lockDerivation" not in ledger and
        type(ledger.get("sourcePaths")) is list and pin(generated_lock_blob, 160), "v9.initial_ledger")
    generation_pin(generation)
    result = deepcopy(ledger)
    rows = [r for r in result["sourcePaths"] if type(r) is dict and r.get("path") == "pnpm-lock.yaml"]
    need(len(rows) == 1 and type(rows[0].get("result")) is dict and
        rows[0]["result"].get("mode") == "100644", "v9.unique_lock_ledger_row")
    rows[0]["result"] = {"mode": "100644", "blob": generated_lock_blob}
    result["lockState"] = "ci_derived"
    result["lockDerivation"] = {"runId": int(generation["runId"]), "attempt": 1,
        "artifactSha256": generation["artifactSha256"], "generatedLockSha256": generation["generatedLockSha256"],
        "receiptSha256": generation["receiptSha256"]}
    return encode(result)


def verify_generated_artifact(files, bindings, phase="validation"):
    """The caller first authenticates provider artifact/run/head before these bytes."""
    fields(files, ("pnpm-lock.yaml", "lock.diff", "generation.json"), "v9.artifact_exact_members")
    need(all(type(v) is bytes for v in files.values()) and sum(map(len, files.values())) <= ARTIFACT_BYTES - 65536,
         "v9.artifact_total_cap")
    receipt = validate_generation(files["generation.json"], bindings, phase)
    need(digest(files["pnpm-lock.yaml"]) == receipt["generatedLockSha256"] and
        digest(files["lock.diff"]) == receipt["gitDiffSha256"], "v9.generated_artifact_hashes")
    return receipt


def tree_digest(entries, ignored=()):
    """Canonical tree witness; parsing stays at the maintained Git-entry owner."""
    need(type(entries) is dict and bool(entries), "v9.positive_source_tree")
    return digest(canonical([[p, *entries[p]] for p in sorted(entries) if p not in set(ignored)]))


def verify_derived_source(read_git, bindings, phase, generation_raw, *, read_tree, verify_lock,
                          initial_generation_raw=None):
    """Read-only G/H proof using the maintained prebound Git-tree parser.

    Callers bind read_tree to the reviewed historical `_v4_tree` owner, not to a
    function/path selected by an artifact. Provider run/artifact authentication
    is independently required before consuming the generation bytes.
    """
    validate_bindings(bindings)
    need(phase in ("validation", "correction") and bindings[phase] is not None,
         "v9.derived_source_phase")
    def read(*args):
        value = read_git(*args)
        need(type(value) is bytes and len(value) <= DIAGNOSTIC_BYTES, "v9.bounded_source_git_read")
        return value
    def parents(sha):
        raw = read("show", "-s", "--format=%P", sha)
        try:
            value = raw.decode("ascii").strip().split()
        except UnicodeError:
            raise Refusal("v9.source_parent_encoding")
        need(all(pin(p, 160) for p in value), "v9.source_parent_shape")
        return value
    def tree(source):
        need(read("rev-parse", source["sourceSha"] + "^{tree}") == (source["sourceTree"] + "\n").encode(),
             "v9.source_tree_identity")
        value = read_tree(source["sourceSha"], source["sourceTree"])
        need(type(value) is dict and bool(value), "v9.positive_source_tree")
        return value
    def inputs(source):
        for path, expected in source["fileSha256"].items():
            need(digest(read("show", source["sourceSha"] + ":" + path)) == expected,
                 "v9.source_input_byte_pin")
    initial = bindings["preparation"]
    need(parents(initial["sourceSha"]) == [BASELINE_SOURCE, UPSTREAM["commit"]],
         "v9.initial_integration_parents")
    initial_tree = tree(initial); inputs(initial)
    step = bindings[phase]
    fixture_only = same_generation_fixture_correction(bindings)
    if phase == "correction" and (step["preparationAttempt"] == 1 or fixture_only):
        # A test/control-only source correction reuses the same already derived
        # dependency bytes, while requiring fresh all15 coverage for its new head.
        verified = verify_derived_source(read_git, bindings, "validation", generation_raw,
            read_tree=read_tree, verify_lock=verify_lock)
        before = tree(bindings["validation"]["source"])
        after = tree(step["source"])
        need(parents(step["source"]["sourceSha"]) == [step["parentSource"]], "v9.single_correction_parent")
        _verify_reviewed_step(read, before, after, step)
        if fixture_only:
            need(digest(read("show", step["parentSource"] + ":" + FIXTURE_CORRECTION_PATH)) ==
                FIXTURE_CORRECTION_BEFORE_SHA256, "v9.fixture_correction_parent_bytes")
            fixture = read("show", step["source"]["sourceSha"] + ":" + FIXTURE_CORRECTION_PATH)
            fixture_blob = hashlib.sha1(b"blob " + str(len(fixture)).encode() + b"\0" + fixture).hexdigest()
            need(fixture_blob == FIXTURE_CORRECTION_AFTER_BLOB and
                read("show", step["source"]["sourceSha"] + ":" + LEDGER) ==
                expected_fixture_correction_ledger(read("show", step["parentSource"] + ":" + LEDGER), fixture_blob),
                "v9.exact_fixture_correction_ledger")
        inputs(step["source"])
        result = {**verified, "sourceSha": step["source"]["sourceSha"], "sourceTree": step["source"]["sourceTree"],
            "sourceCorrectionVerified": True, "freshSourceCoverageRequired": True}
        if fixture_only:
            result.update(generatedSourceSha=verified["sourceSha"], generatedChangedPaths=verified["changedPaths"],
                changedPaths=deepcopy(step["changedPaths"]), correctionParentSource=step["parentSource"],
                unchangedTreeBase=step["parentSource"], fixtureOnlyCorrectionVerified=True)
        return result
    attempt = step["preparationAttempt"]
    prep = preparation_for(bindings, attempt)
    before = initial_tree
    if attempt >= 3:
        pc = bindings["preparationCorrection"]
        need(additional_pipeline_preparation_recovery(pc) and prep == initial and
            pc["priorPhase"] == "lock-preparation" and (bindings["correction"] is None or fixture_only),
            "v9.additional_recovery_original_source")
    if attempt == 2:
        pc = bindings["preparationCorrection"]
        if pipeline_preparation_recovery(pc):
            # No invented G2: only the pipeline changed after an authenticated
            # failed intake. Its native failure is independently replayed by
            # admission; this owner proves the unchanged G/H source relation.
            need(prep == initial and pc["priorPhase"] == "lock-preparation",
                "v9.pipeline_recovery_original_source")
        else:
            if pc["priorPhase"] == "validation":
                need(type(initial_generation_raw) is bytes, "v9.initial_generation_receipt_required")
                verify_derived_source(read_git, bindings, "validation", initial_generation_raw,
                    read_tree=read_tree, verify_lock=verify_lock)
                before = tree(bindings["validation"]["source"])
            need(parents(prep["sourceSha"]) == [pc["parentSource"]], "v9.single_preparation_correction_parent")
            after = tree(prep)
            _verify_reviewed_step(read, before, after, {**pc, "source": prep})
            before = after
            inputs(prep)
    generation = validate_generation(generation_raw, bindings, phase)
    target = step["source"]
    need(parents(target["sourceSha"]) == [prep["sourceSha"]], "v9.single_generated_source_parent")
    after = tree(target)
    need(set(before) == set(after), "v9.generated_path_set_unchanged")
    changed = sorted(p for p in before if before[p] != after[p])
    need(changed == sorted(("pnpm-lock.yaml", LEDGER)) and
        all(before[p][:2] == after[p][:2] == ("100644", "blob") for p in changed),
        "v9.only_generated_lock_and_ledger")
    unchanged = tree_digest(before, changed)
    need(unchanged == tree_digest(after, changed) == step["unchangedTreeSha256"],
         "v9.generated_unchanged_tree_witness")
    lock = read("show", target["sourceSha"] + ":pnpm-lock.yaml")
    before_lock = read("show", prep["sourceSha"] + ":pnpm-lock.yaml")
    lock_security = verify_lock(before_lock, lock, REGISTRY_PINS[0]["distIntegrity"], REGISTRY_PINS[1]["distIntegrity"])
    need(digest(canonical(lock_security)) == generation["lockSecuritySha256"], "v9.generated_lock_security_binding")
    blob = hashlib.sha1(b"blob " + str(len(lock)).encode() + b"\0" + lock).hexdigest()
    need(blob == after["pnpm-lock.yaml"][2] and digest(lock) == generation["generatedLockSha256"],
         "v9.generated_lock_git_and_receipt_binding")
    old_ledger = read("show", prep["sourceSha"] + ":" + LEDGER)
    need(read("show", target["sourceSha"] + ":" + LEDGER) ==
        expected_derived_ledger(old_ledger, blob, step["generation"]), "v9.exact_derived_ledger")
    inputs(target)
    return {"schema": "openclaw.v109.verified-generated-source.v1", "sourceSha": target["sourceSha"],
        "sourceTree": target["sourceTree"], "preparationSource": prep["sourceSha"], "preparationAttempt": attempt,
        "generationReceiptSha256": digest(generation_raw), "changedPaths": changed,
        "lockSecuritySha256": generation["lockSecuritySha256"],
        "allOtherTrackedBytesUnchanged": True, "sourceCorrectionVerified": attempt == 2 and
            not pipeline_preparation_recovery(bindings["preparationCorrection"]),
        "freshSourceCoverageRequired": True, "imageBuilt": False, "productionAuthorized": False}


def _verify_reviewed_step(read, before, after, step):
    need(set(before) == set(after), "v9.corrected_source_path_set")
    changed = sorted(p for p in before if before[p] != after[p])
    need(changed == step["changedPaths"] and all(before[p][:2] == after[p][:2] == ("100644", "blob")
        for p in changed), "v9.exact_reviewed_correction_paths")
    need(tree_digest(before, changed) == tree_digest(after, changed) == step["unchangedTreeSha256"],
         "v9.corrected_unchanged_tree_witness")
    for path, expected in step["contentSha256"].items():
        need(digest(read("show", step["source"]["sourceSha"] + ":" + path)) == expected,
             "v9.exact_reviewed_correction_bytes")


def validate_source_result(raw, bindings, request_raw, expected_run_pin, *, expected_result_sha256):
    """Validate safe result bytes after independent provider/artifact acquisition.

    This function does not query GitHub or infer a passed provider job from a
    caller flag. The image owner must independently verify all17 native jobs and
    the authenticated artifact identity before invoking this byte contract.
    """
    need(pin(expected_result_sha256) and digest(raw) == expected_result_sha256, "v9.source_result_hash")
    request = validate_request(parse(request_raw, 65536), bindings)
    need(request["phase"] in ("validation", "correction"), "v9.source_result_phase")
    fields(expected_run_pin, ("runId", "runAttempt", "pipelineHead", "requestSha256"),
           "v9.source_result_expected_run_fields")
    need(type(expected_run_pin["runId"]) is str and RUN_ID.fullmatch(expected_run_pin["runId"]) and
        type(expected_run_pin["runAttempt"]) is int and expected_run_pin["runAttempt"] == 1 and
        pin(expected_run_pin["pipelineHead"], 160) and expected_run_pin["requestSha256"] == digest(request_raw),
        "v9.source_result_expected_run_values")
    value = parse(raw, 16384)
    fields(value, ("schema", "repository", "campaignId", "phase", "status", "runId", "runAttempt",
        "pipelineHead", "sourceSha", "sourceTree", "manifestSha256", "inventorySha256", "requestSha256",
        "generationReceiptSha256", "selectedProfiles", "admissionResult", "sourceMatrixResult",
        "all15Required", "freshCoverage", "historicalCoverageReused", "imageBuilt", "nativeImageExecuted",
        "productionAuthorized"), "v9.source_result_fields")
    need(value["schema"] == "openclaw.v109.source-validation-result.v1" and value["repository"] == REPOSITORY and
        value["campaignId"] == CAMPAIGN and value["phase"] == request["phase"] and value["status"] == "passed" and
        all(type(value[k]) is type(v) and value[k] == v for k,v in expected_run_pin.items()) and
        all(value[k] == request["source"][k] for k in ("sourceSha", "sourceTree", "manifestSha256", "inventorySha256")) and
        value["generationReceiptSha256"] == request["generation"]["receiptSha256"] and
        value["selectedProfiles"] == list(PROFILES) and value["admissionResult"] == value["sourceMatrixResult"] == "success" and
        value["all15Required"] is True and value["freshCoverage"] is True and
        value["historicalCoverageReused"] is False and value["imageBuilt"] is False and
        value["nativeImageExecuted"] is False and value["productionAuthorized"] is False,
        "v9.source_result_binding")
    return value
