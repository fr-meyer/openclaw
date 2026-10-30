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
BASELINE_SOURCE = "e6c4786dafbc8308661ea8fa14a81e06873d1630"
BASELINE_PIPELINE = "37400d942839bee0b92852037d6f8bf99e60358c"
BASELINE_RUN = "40901336241"
UPSTREAM = {"tag": "v2026.10.9", "tagObject": "88a19e0d8677804d8ec98e30a3a3a3a9308ebee0",
            "commit": "8b18b5578f66eab1501cba4cef2310d88bfb9a41",
            "tree": "3ccfb9632d8f30196d0f9d94f92f8cc7f07b2be7"}
LEDGER = "custom-patches/reconciliation-2026.10.9.json"
INPUTS = ("package.json", "pnpm-workspace.yaml", "pnpm-lock.yaml", LEDGER)
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
AUTH_HOURS = 72
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
    need(end - start == timedelta(hours=AUTH_HOURS), "v9.exact_72_hour_window")
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


def validate_bindings(value, active=False, now=None):
    fields(value, ("schema", "status", "campaignId", "repository", "workflow", "pipelineBranch",
        "sourceBranch", "baseBranch", "baseSha", "upstream", "baseline", "preparation", "preparationCorrection",
        "validation", "correction", "authorization", "newRecoveryTests"), "v9.bindings_fields")
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
    pc = value["preparationCorrection"]
    if pc is not None:
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
        need(value["validation"]["preparationAttempt"] == 1, "v9.only_one_source_correction")
        if c["preparationAttempt"] == 1:
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
    if value["status"] == "DISARMED":
        need(value["authorization"] is None and not active, "v9.disarmed")
    else:
        validate_authorization(value["authorization"], now)
    if active:
        need(value["status"] == "APPROVED_CI", "v9.disarmed")
    return value


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
    need(type(attempt) is int and attempt in (1, 2), "v9.preparation_attempt")
    if attempt == 1:
        return bindings["preparation"]
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
    if phase == "lock-preparation":
        source, generation = preparation_for(bindings, preparation_attempt), None
        prior = [] if preparation_attempt == 1 else [bindings["preparationCorrection"]["priorFailure"]]
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
    return {"schema": SCHEMA, "campaignId": CAMPAIGN, "phase": phase,
        "source": deepcopy(source), "settledUsageSha256": bindings["baseline"]["publicProofSha256"],
        "generation": deepcopy(generation), "priorRunPins": deepcopy(prior), "preparationAttempt": preparation_attempt,
        "profiles": [] if phase == "lock-preparation" else list(PROFILES),
        "authorizationSha256": digest(canonical(bindings["authorization"])) if bindings["authorization"] else None}


def validate_request(value, bindings, active=False, now=None):
    validate_bindings(bindings, active, now)
    need(type(value) is dict and value.get("phase") in PHASES and
        value == request_for(bindings, value["phase"], value.get("preparationAttempt")), "v9.closed_request")
    return value


def budget(request):
    need(type(request) is dict and request.get("schema") == SCHEMA and request.get("phase") in PHASES,
         "v9.budget_request")
    return {"phase": request["phase"], "phaseMaximumMinutes": PREPARATION_MINUTES if
        request["phase"] == "lock-preparation" else SOURCE_MINUTES,
        "preparationMinutesPerJob": PREPARATION_MINUTES, "maximumLockPreparations": MAXIMUM_PREPARATIONS,
        "admissionMinutes": ADMISSION_MINUTES,
        "profileMinutes": dict(PROFILE_MINUTES), "finalMinutes": FINAL_MINUTES,
        "maximumSourceCampaigns": 2, "maximumParallelSourceJobs": 3,
        "separateImageFamilyReserveMinutes": IMAGE_FAMILY_MINUTES,
        "incidentalMinutes": INCIDENTAL_MINUTES, "maximumNewMinutes": MAXIMUM_NEW_MINUTES,
        "maximumBookedMinutes": MAXIMUM_PREPARATIONS * PREPARATION_MINUTES + 2 * SOURCE_MINUTES + IMAGE_FAMILY_MINUTES + INCIDENTAL_MINUTES}


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
    result["lockDerivation"] = {"runId": generation["runId"], "attempt": 1,
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
    if phase == "correction" and step["preparationAttempt"] == 1:
        # A test/control-only source correction reuses the same already derived
        # dependency bytes, while requiring fresh all15 coverage for its new head.
        verified = verify_derived_source(read_git, bindings, "validation", generation_raw,
            read_tree=read_tree, verify_lock=verify_lock)
        before = tree(bindings["validation"]["source"])
        after = tree(step["source"])
        need(parents(step["source"]["sourceSha"]) == [step["parentSource"]], "v9.single_correction_parent")
        _verify_reviewed_step(read, before, after, step)
        inputs(step["source"])
        return {**verified, "sourceSha": step["source"]["sourceSha"], "sourceTree": step["source"]["sourceTree"],
            "sourceCorrectionVerified": True, "freshSourceCoverageRequired": True}
    attempt = step["preparationAttempt"]
    prep = preparation_for(bindings, attempt)
    before = initial_tree
    if attempt == 2:
        pc = bindings["preparationCorrection"]
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
        "allOtherTrackedBytesUnchanged": True, "sourceCorrectionVerified": attempt == 2,
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
