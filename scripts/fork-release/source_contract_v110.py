"""Pure, fixed 10.10 source/lock contract. Records constrain authority, not grant it.

The hosted caller owns current GitHub identity, released capacity and process
settlement. This module performs no I/O, subprocess, import of candidate code or
network operation. Git readers are prebound by that caller to the maintained
native tree owner; no path or function is selected by an artifact.
"""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import math
import re

SCHEMA = "openclaw.v110.source-request.v1"
BINDINGS_SCHEMA = "openclaw.v110.ci-bindings.v1"
AUTH_SCHEMA = "openclaw.v110.source-authorization.v1"
GENERATION_SCHEMA = "openclaw.v110.lock-derivation.v1"
CAMPAIGN = "future-v110-grouped-validation-20261103"
REPOSITORY = "fr-meyer/openclaw"
WORKFLOW = ".github/workflows/future-v110-source-validation.yml"
CANDIDATE = "scripts/fork-release/candidates/v2026.10.10-source-only"
PIPELINE_BRANCH = "task/v110-source-validation"
SOURCE_BRANCH = "prep/v2026.10.10-remediation"
BASE_BRANCH = "release-pipeline/v105-image-only-20261024"
BASE = "918890b9f72b2d0372995362e8ea3088e0f87431"
UPSTREAM = {"tag": "v2026.10.10", "tagObject": "6eef4472c85436c7deb8563248827d7f6d29df67",
            "commit": "7dc3350cb9f08fcf9a0af5c4845a20d5b2f1a8be",
            "tree": "38c6000594d8935685b54febd7c4c5cb47a428b0"}
FORK_BASE = "8b18b5578f66eab1501cba4cef2310d88bfb9a41"
FROZEN_FORK = "83b022d934ea0908031bb4fa50c9ea7b4aada8a5"
FORK_BASE_TREE = "3ccfb9632d8f30196d0f9d94f92f8cc7f07b2be7"
FROZEN_FORK_TREE = "4bc0d3ab657c289f09edc4e0e690b31646e31a2a"
INITIAL_TREE = "8ad99415b29a89cfede24980e7440de7fbb5cead"
LEDGER = "custom-patches/reconciliation-2026.10.10.json"
MANIFEST = "custom-patches/manifest.json"
INPUTS = ("package.json", "pnpm-workspace.yaml", "pnpm-lock.yaml", LEDGER, MANIFEST)
INITIAL_INPUT_HASHES = {
    "package.json": "81cf7c38037ceba6791afeb736f74f099ffce29107e1801ccab20194ec78e741",
    "pnpm-workspace.yaml": "8b475a29d068c2d1aa1d89694230594bb434ce57b1025bf0151da26261c51838",
    "pnpm-lock.yaml": "cac4e3810242167d941d14b6befd63959ca76bd10289437c33caa5366eeb383c",
    LEDGER: "08f7938ca407b413bfe790a6f8b5933a895e74dbc5074714e498250f1ab12a84",
    MANIFEST: "db5c7b6dacd75af8138937d0704b663b9b7e6eb2d7f6032235133bb3462e3b11",
}
PROPOSAL_SHA256 = "721662912807288539c324acd281d9e5b86526aa3ed70f8afd49564d93e7fb33"
APPROVAL_RECEIPT_SHA256 = "97931a883800bfa1c19df32054989c6fc3d9ff688ec181631ad8a333c058cc2d"
# Ceiling of the actual operator receipt's 09:12:22.233578Z observation. This is
# not a fabricated second within the user's minute-precision 09:11 message.
APPROVAL_RECORDED_AT = "2026-11-03T09:12:23Z"
PACKAGE_NOT_BEFORE = "2026-11-04T09:59:50Z"
EXPIRES_AT = "2026-11-06T03:14:21Z"
PROFILES = ("dependency", "types-production", "types-tests", "types-scripts",
            "workboard-1", "workboard-2", "models-1", "models-2", "sqlite",
            "doctor-1", "doctor-2", "doctor-3", "memory", "pipeline-contracts", "compatibility")
PROFILE_MINUTES = dict(zip(PROFILES, (60, 90, 90, 90, 60, 60, 60, 60, 90, 90, 75, 75, 60, 45, 60)))
PREPARATION_MINUTES = 45
ADMISSION_MINUTES = 30
FINAL_MINUTES = 10
# Three source slots give a 375-minute capped critical path. Admission30,
# final10, queue60 and cleanup5 make an eight-hour released validation window;
# lock derivation and its separate review are not part of this phase.
VALIDATION_WINDOW_MINUTES = 375 + ADMISSION_MINUTES + FINAL_MINUTES + 60 + 5
SOURCE_MINUTES = 1105
STAGE_MINUTES = 2400
GLOBAL_MINUTES = 25000
SETTLED_MINUTES = 2215
OTHER_RESERVED_MINUTES = 3700
ARTIFACT_BYTES = 2 * 1024 * 1024
DIAGNOSTIC_BYTES = 64 * 1024 * 1024
OTHER_BOOKED_ARTIFACT_BYTES_FLOOR = 783765
RECOVERY_TESTS = tuple(sorted((
    "src/state/openclaw-state-h3-v20-upgrade.test.ts",
    "src/state/openclaw-state-db-schema-v21-columns.test.ts",
    "src/state/openclaw-state-db-schema-v22-columns.test.ts",
    "src/state/openclaw-agent-json-predicate-schema.test.ts",
    "src/commands/backup-sqlite.test.ts", "src/commands/backup-restore.test.ts",
    "src/commands/doctor-migration-backup.test.ts",
    "src/commands/doctor-migration-backup.scoped.test.ts",
)))
REQUIRED_CODE = frozenset(("scripts/fork-release/source_contract_v110.py",
    "scripts/fork-release/source_validation_v110.py", "scripts/fork-release/lockfile_policy_v110.py",
    "scripts/fork-release/source_validation_selection_v110.py",
    "scripts/fork-release/source_validation_v108.py", "scripts/fork-release/source_validation_v109.py",
    "scripts/fork-release/bounded_run_contract_v109.py"))
SHA = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
TEST_PATH = re.compile(r"[A-Za-z0-9_./@+-]+\.(?:test|e2e)\.[cm]?[jt]s\Z")
SAFE_PATH = re.compile(r"[A-Za-z0-9_./@+\-]+\Z")


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
    need(type(raw) is bytes and len(raw) <= maximum, "v110.bounded_json")
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value, "v110.duplicate_json_key")
            value[key] = item
        return value
    def constant(_):
        raise Refusal("v110.json_constant")
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except Refusal:
        raise
    except (ValueError, UnicodeError):
        raise Refusal("v110.invalid_json")


def fields(value, names, code):
    need(type(value) is dict and set(value) == set(names), code)
    return value


def pin(value, bits=256):
    return type(value) is str and (SHA if bits == 160 else SHA256).fullmatch(value) is not None


def path(value):
    return (type(value) is str and bool(SAFE_PATH.fullmatch(value)) and
            not value.startswith("/") and all(p not in ("", ".", "..", ".git") for p in value.split("/")))


def utc(value):
    need(type(value) is str and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value), "v110.canonical_utc")
    try:
        stamp = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise Refusal("v110.canonical_utc")
    need(stamp.strftime("%Y-%m-%dT%H:%M:%SZ") == value, "v110.canonical_utc")
    return stamp


def epoch(now):
    if type(now) is str:
        return utc(now).timestamp()
    need(type(now) in (int, float) and math.isfinite(now), "v110.clock")
    return now


def validate_authorization(value, active=False, now=None):
    if value is None:
        need(not active, "v110.authorization_disarmed")
        return None
    expected = {"schema": AUTH_SCHEMA, "recordedAt": APPROVAL_RECORDED_AT,
        "approvalReceiptSha256": APPROVAL_RECEIPT_SHA256, "proposalSha256": PROPOSAL_SHA256,
        "expiresAt": EXPIRES_AT, "packageNotBefore": PACKAGE_NOT_BEFORE,
        "stageRunnerMinutes": 2400, "totalRunnerMinutes": 25000,
        "totalTaxInclusiveUSD": "25.00", "maxMaterialGenerations": 2,
        "maxSubstantiveExecutions": 4, "maxConcurrentSourceJobs": 3,
        "imageBuildAllowed": False, "newAccessAllowed": False, "cloudAllowed": False,
        "productionAllowed": False}
    fields(value, expected, "v110.authorization_fields")
    need(value == expected and all(type(value[k]) is type(v) for k, v in expected.items()), "v110.authorization_values")
    if active:
        need(now is not None and utc(PACKAGE_NOT_BEFORE).timestamp() <= epoch(now) < utc(EXPIRES_AT).timestamp(), "v110.authorization_clock")
    return value


def source_pin(value, armed=False):
    fields(value, ("sourceSha", "sourceTree", "fileSha256"), "v110.source_pin_fields")
    need((pin(value["sourceSha"], 160) or (not armed and value["sourceSha"] is None)) and
         pin(value["sourceTree"], 160), "v110.source_pin")
    fields(value["fileSha256"], INPUTS, "v110.source_input_fields")
    need(all(pin(v) for v in value["fileSha256"].values()), "v110.source_input_pins")
    return value


def validate_window(value, active=False, now=None, phase="lock-preparation"):
    need(phase in ("lock-preparation", "validation"), "v110.phase")
    if value is None:
        need(not active, "v110.owner_window_disarmed")
        return None
    fields(value, ("referenceSha256", "checkedAt", "expiresAt", "source109Released",
        "source109NeededAttemptsUsed", "source109BookedArtifactBytes", "source109LatestLedgerSha256",
        "maximumSourceJobs"), "v110.owner_window_fields")
    need(pin(value["referenceSha256"]) and value["source109Released"] is True and
        type(value["maximumSourceJobs"]) is int and value["maximumSourceJobs"] == 3 and
        type(value["source109NeededAttemptsUsed"]) is int and
        251 <= value["source109NeededAttemptsUsed"] < 1000 and
        type(value["source109BookedArtifactBytes"]) is int and
        OTHER_BOOKED_ARTIFACT_BYTES_FLOOR <= value["source109BookedArtifactBytes"] <= DIAGNOSTIC_BYTES and
        pin(value["source109LatestLedgerSha256"]), "v110.owner_window_values")
    checked, end = utc(value["checkedAt"]), utc(value["expiresAt"])
    need(utc(APPROVAL_RECORDED_AT) <= checked < end <= utc(EXPIRES_AT), "v110.owner_window_bounds")
    if active:
        current = epoch(now)
        need(checked.timestamp() <= current, "v110.owner_window_future_check")
        seconds = (PREPARATION_MINUTES * 60 + 60) if phase == "lock-preparation" else VALIDATION_WINDOW_MINUTES * 60
        need(current + seconds <= end.timestamp(), "v110.owner_window_full_phase")
    return value


def validate_admitted_window(value, admitted_at, now, phase="lock-preparation"):
    """Workers retain the already-admitted window; they cannot renew its scope."""
    admitted, current = epoch(admitted_at), epoch(now)
    validate_window(value, active=True, now=admitted, phase=phase)
    need(admitted <= current < utc(value["expiresAt"]).timestamp(), "v110.admitted_window_expired")
    return value


def validate_bindings(value, active=False, now=None, phase="lock-preparation"):
    fields(value, ("schema", "repository", "draftPr", "pipeline", "authorization", "ownerWindow",
        "generations", "activeGeneration", "newRecoveryTests"), "v110.bindings_fields")
    need(value["schema"] == BINDINGS_SCHEMA and value["repository"] == REPOSITORY, "v110.bindings_identity")
    pr = fields(value["draftPr"], ("number", "headBranch", "baseBranch", "baseSha"), "v110.pr_fields")
    need(pr["headBranch"] == PIPELINE_BRANCH and pr["baseBranch"] == BASE_BRANCH and pr["baseSha"] == BASE and
        ((type(pr["number"]) is int and pr["number"] > 0) or (not active and pr["number"] is None)), "v110.pr_identity")
    pipeline = fields(value["pipeline"], ("codeCommit", "codeTree", "codeFiles"), "v110.pipeline_fields")
    need(all(pin(pipeline[k], 160) or (not active and pipeline[k] is None) for k in ("codeCommit", "codeTree")), "v110.pipeline_identity")
    fileset = pipeline["codeFiles"]
    # The actual workflow later pins the code-only manifest. Including itself
    # in that manifest would create a hash cycle; native event checks bind it.
    need(type(fileset) is dict and len(fileset) <= 256 and WORKFLOW not in fileset and
         all(path(p) for p in fileset), "v110.code_map")
    need(not active or REQUIRED_CODE <= set(fileset), "v110.required_code_map")
    for item in fileset.values():
        fields(item, ("sha256", "bytes"), "v110.code_file_fields")
        need(pin(item["sha256"]) and type(item["bytes"]) is int and 0 < item["bytes"] <= DIAGNOSTIC_BYTES, "v110.code_file_pin")
    validate_authorization(value["authorization"], active, now)
    validate_window(value["ownerWindow"], active, now, phase)
    generations = value["generations"]
    need(type(generations) is list and 1 <= len(generations) <= 2 and
        type(value["activeGeneration"]) is int and 1 <= value["activeGeneration"] <= len(generations), "v110.generations")
    for i, item in enumerate(generations, 1):
        fields(item, ("number", "material", "correction", "validation"), "v110.generation_fields")
        need(type(item["number"]) is int and item["number"] == i, "v110.generation_order")
        material = source_pin(item["material"], active)
        if i == 1:
            need(material["sourceTree"] == INITIAL_TREE and material["fileSha256"] == INITIAL_INPUT_HASHES and item["correction"] is None, "v110.initial_reviewed_source")
        else:
            correction = fields(item["correction"], ("parentSource", "reviewSha256", "changedPaths", "beforeTreeSha256", "afterTreeSha256"), "v110.correction_fields")
            need(generations[0]["validation"] is not None and correction["parentSource"] == generations[0]["validation"]["source"]["sourceSha"] and
                pin(correction["reviewSha256"]) and all(pin(correction[k]) for k in ("beforeTreeSha256", "afterTreeSha256")), "v110.correction_parent")
            changes = correction["changedPaths"]
            need(type(changes) is list and 1 <= len(changes) <= 256 and changes == sorted(set(changes)) and
                all(path(p) for p in changes) and LEDGER in changes, "v110.correction_delta")
        if item["validation"] is not None:
            validation = fields(item["validation"], ("source", "generation", "unchangedTreeSha256"), "v110.validation_fields")
            source_pin(validation["source"], active)
            generation_pin(validation["generation"])
            need(pin(validation["unchangedTreeSha256"]), "v110.unchanged_tree_pin")
    need(value["newRecoveryTests"] == list(RECOVERY_TESTS), "v110.required_recovery_selection")
    return value


def generation_pin(value):
    fields(value, ("runId", "pipelineHead", "artifactId", "artifactSha256", "receiptSha256",
        "generatedLockSha256", "gitDiffSha256"), "v110.generation_pin_fields")
    need(type(value["runId"]) is str and re.fullmatch(r"[1-9][0-9]{0,19}", value["runId"]) and
         type(value["artifactId"]) is int and value["artifactId"] > 0 and pin(value["pipelineHead"], 160) and
         all(pin(value[k]) for k in ("artifactSha256", "receiptSha256", "generatedLockSha256", "gitDiffSha256")), "v110.generation_pin")
    return value


def active_material(bindings):
    return bindings["generations"][bindings["activeGeneration"] - 1]


def request_for(bindings, phase):
    validate_bindings(bindings)
    need(phase in ("lock-preparation", "validation"), "v110.phase")
    item = active_material(bindings)
    selected = item["material"]
    if phase == "validation":
        need(item["validation"] is not None, "v110.validation_disarmed")
        selected = item["validation"]["source"]
    return {"schema": SCHEMA, "campaign": CAMPAIGN, "phase": phase,
        "generation": bindings["activeGeneration"], "bindingsSha256": digest(encode(bindings)),
        "source": deepcopy(selected), "codeCommit": bindings["pipeline"]["codeCommit"],
        "codeFilesSha256": digest(canonical(bindings["pipeline"]["codeFiles"])),
        "imageBuilt": False, "productionAuthorized": False}


def validate_request(value, bindings, active=False, now=None):
    need(type(value) is dict, "v110.request")
    phase = value.get("phase")
    validate_bindings(bindings, active, now, phase)
    need(canonical(value) == canonical(request_for(bindings, phase)), "v110.exact_request")
    return value


def tree_digest(entries, ignored=()):
    need(type(entries) is dict and bool(entries), "v110.positive_tree")
    return digest(canonical([[p, *entries[p]] for p in sorted(entries) if p not in set(ignored)]))


def _read_reader(read_git):
    def read(*args):
        raw = read_git(*args)
        need(type(raw) is bytes and len(raw) <= DIAGNOSTIC_BYTES, "v110.bounded_git_read")
        return raw
    return read


def _source(read, read_tree, value):
    need(read("rev-parse", value["sourceSha"] + "^{tree}") == (value["sourceTree"] + "\n").encode(), "v110.source_tree")
    entries = read_tree(value["sourceSha"], value["sourceTree"])
    need(type(entries) is dict and entries, "v110.positive_tree")
    for name, expected in value["fileSha256"].items():
        need(digest(read("show", value["sourceSha"] + ":" + name)) == expected, "v110.source_input_bytes")
    return entries


def _parents(read, sha):
    try:
        result = read("show", "-s", "--format=%P", sha).decode("ascii").strip().split()
    except UnicodeError:
        raise Refusal("v110.parent_encoding")
    need(all(pin(p, 160) for p in result), "v110.parent_shape")
    return result


def _entry(entry):
    return None if entry is None else {"mode": entry[0], "blob": entry[2], "type": entry[1]}


def verify_material_source(read_git, bindings, *, read_tree):
    """Authenticate the explicit transplant; never pretend it was a DAG merge."""
    validate_bindings(bindings)
    read = _read_reader(read_git)
    initial = bindings["generations"][0]["material"]
    need(pin(initial["sourceSha"], 160), "v110.source_disarmed")
    first = _source(read, read_tree, initial)
    need(_parents(read, initial["sourceSha"]) == [UPSTREAM["commit"]], "v110.initial_single_real_parent")
    roots = {}
    for label, sha, tid in (("upstream109", FORK_BASE, FORK_BASE_TREE),
                            ("frozenH3", FROZEN_FORK, FROZEN_FORK_TREE),
                            ("upstream110", UPSTREAM["commit"], UPSTREAM["tree"])):
        need(read("rev-parse", sha + "^{tree}") == (tid + "\n").encode(), "v110.origin_tree")
        roots[label] = read_tree(sha, tid)
    raw = read("show", initial["sourceSha"] + ":" + LEDGER)
    ledger = parse(raw)
    need(ledger.get("schema") == "openclaw.v110.fork-carry-reconciliation.v1" and ledger.get("target") == UPSTREAM and
        ledger.get("forkDeltaBase") == FORK_BASE and ledger.get("frozenFork") == FROZEN_FORK and
        ledger.get("provedGitAncestryMerge") is False and ledger.get("qualificationTransferred") is False and
        ledger.get("productionAuthorized") is False and ledger.get("nativeImageExecuted") is False and
        ledger.get("lockState") == "pending_secretless_ci_derivation", "v110.transplant_identity")
    rows, extra = ledger.get("sourcePaths"), ledger.get("additionalAdaptationPaths")
    need(type(rows) is list and len(rows) == 256 and type(extra) is list and len(extra) == 4, "v110.transplant_inventory_count")
    seen = set()
    for row in rows + extra:
        need(type(row) is dict and path(row.get("path")) and row["path"] not in seen, "v110.transplant_unique_paths")
        name = row["path"]; seen.add(name)
        if row in rows:
            for label in roots:
                need(row.get(label) == _entry(roots[label].get(name)), "v110.transplant_origin_entry")
        actual, result = first.get(name), row.get("result")
        if actual is None:
            need(result is None, "v110.transplant_absent_result")
        else:
            need(type(result) is dict and actual[0] == result.get("mode") and actual[1] == "blob" and
                actual[2] == result.get("blob") and digest(read("show", initial["sourceSha"] + ":" + name)) == result.get("sha256"), "v110.transplant_result")
    changed = {p for p in set(first) | set(roots["upstream110"]) if first.get(p) != roots["upstream110"].get(p)}
    need(len(changed) == 252 and changed <= seen | {LEDGER}, "v110.complete_transplant_delta")
    manifest = parse(read("show", initial["sourceSha"] + ":" + MANIFEST))
    need(manifest.get("upstream") == UPSTREAM and manifest.get("productionEligible") is False and
        manifest.get("integrationBasis", {}).get("provedGitAncestryMerge") is False, "v110.manifest_not_qualification")
    current = initial
    for item in bindings["generations"][1:]:
        correction = item["correction"]
        previous = bindings["generations"][0]
        parent = previous["validation"]["source"]
        before = _verify_h_delta(read, read_tree, previous["material"], previous["validation"])
        after = _source(read, read_tree, item["material"])
        need(_parents(read, item["material"]["sourceSha"]) == [parent["sourceSha"]], "v110.correction_single_parent")
        delta = sorted(p for p in set(before) | set(after) if before.get(p) != after.get(p))
        need(delta == correction["changedPaths"] and tree_digest(before) == correction["beforeTreeSha256"] and
            tree_digest(after) == correction["afterTreeSha256"], "v110.reviewed_exact_correction")
        current = item["material"]
    return current


def validate_generation(raw, bindings, *, generation=None):
    validate_bindings(bindings)
    item = active_material(bindings)
    if generation is None:
        need(item["validation"] is not None, "v110.validation_disarmed")
        generation = item["validation"]["generation"]
    pinset = generation_pin(generation)
    need(digest(raw) == pinset["receiptSha256"], "v110.generation_receipt_pin")
    value = parse(raw, 262144)
    names = ("schema", "status", "sourceSha", "sourceTree", "pipelineHead", "runId", "runAttempt",
        "packageSha256", "workspaceSha256", "sourceLockSha256", "generatedLockSha256", "ledgerSha256",
        "nodeVersion", "pnpmVersion", "changedPaths", "gitDiffSha256", "allOtherTrackedEntriesUnchanged",
        "startedAt", "finishedAt", "exitCode", "timedOut", "cleanupSettled", "imageBuilt", "qualified",
        "productionAuthorized", "lockSecurity")
    fields(value, names, "v110.generation_receipt_fields")
    material = item["material"]
    expected = {"schema": GENERATION_SCHEMA, "status": "derived_only", "sourceSha": material["sourceSha"],
        "sourceTree": material["sourceTree"], "pipelineHead": pinset["pipelineHead"], "runId": pinset["runId"],
        "runAttempt": 1, "packageSha256": material["fileSha256"]["package.json"],
        "workspaceSha256": material["fileSha256"]["pnpm-workspace.yaml"],
        "sourceLockSha256": material["fileSha256"]["pnpm-lock.yaml"],
        "ledgerSha256": material["fileSha256"][LEDGER], "nodeVersion": "24.22.1", "pnpmVersion": "12.15.0",
        "generatedLockSha256": pinset["generatedLockSha256"], "gitDiffSha256": pinset["gitDiffSha256"],
        "changedPaths": [] if material["fileSha256"]["pnpm-lock.yaml"] == pinset["generatedLockSha256"] else ["pnpm-lock.yaml"],
        "allOtherTrackedEntriesUnchanged": True, "exitCode": 0, "timedOut": False, "cleanupSettled": True,
        "imageBuilt": False, "qualified": False, "productionAuthorized": False}
    need(all(value[k] == v and type(value[k]) is type(v) for k, v in expected.items()), "v110.generation_values")
    start, finish = utc(value["startedAt"]), utc(value["finishedAt"])
    need(utc(PACKAGE_NOT_BEFORE) <= start <= finish <= utc(EXPIRES_AT) and
         (finish - start).total_seconds() <= PREPARATION_MINUTES * 60, "v110.generation_clock")
    # The lock owner validates its own complete summary; do not invent a second
    # weaker interpretation of that owner's age/security field names here.
    from lockfile_policy_v110 import validate_generated_summary
    validate_generated_summary(value["lockSecurity"], value["sourceLockSha256"],
                               value["generatedLockSha256"], value["finishedAt"])
    return value


def validate_producer(raw_run, raw_artifact, pinset, draft_pr, archive_sha256, now):
    """Check fixed-route native API observations and the actual downloaded ZIP.

    The caller's immutable API/download owner authenticates transport. These
    response objects are not supplied by the archive or its manifest. The
    normalized record below is the only meaning of ``authenticated`` accepted
    by the file consumer; it is not separate authority to make an HTTP request.
    """
    generation_pin(pinset)
    need(type(raw_run) is dict and type(raw_artifact) is dict and type(draft_pr) is dict,
         "v110.native_producer_objects")
    repo, head_repo = raw_run.get("repository"), raw_run.get("head_repository")
    need(type(repo) is dict and repo.get("full_name") == REPOSITORY and repo.get("private") is False and
         type(repo.get("id")) is int and repo["id"] > 0 and
         type(head_repo) is dict and head_repo.get("full_name") == REPOSITORY and
         head_repo.get("id") == repo["id"], "v110.native_producer_repository")
    actor, trigger = raw_run.get("actor"), raw_run.get("triggering_actor")
    need(type(actor) is dict and type(trigger) is dict and actor.get("login") == "fr-meyer" and
         trigger.get("login") == "fr-meyer" and
         type(raw_run.get("id")) is int and str(raw_run["id"]) == pinset["runId"] and
         raw_run.get("head_sha") == pinset["pipelineHead"] and raw_run.get("head_branch") == PIPELINE_BRANCH and
         raw_run.get("path") == WORKFLOW and raw_run.get("event") == "pull_request" and
         type(raw_run.get("run_attempt")) is int and raw_run["run_attempt"] == 1 and
         raw_run.get("status") == "completed" and raw_run.get("conclusion") == "success",
         "v110.native_producer_run")
    pulls = raw_run.get("pull_requests")
    need(type(pulls) is list and sum(type(p) is dict and type(p.get("number")) is int and p["number"] == draft_pr.get("number") for p in pulls) == 1 and
         draft_pr.get("headBranch") == PIPELINE_BRANCH and draft_pr.get("baseBranch") == BASE_BRANCH and
         draft_pr.get("baseSha") == BASE and type(draft_pr.get("number")) is int and draft_pr["number"] > 0,
         "v110.native_producer_pr")
    bound_pr = next(p for p in pulls if type(p) is dict and type(p.get("number")) is int and p["number"] == draft_pr["number"])
    head, base = bound_pr.get("head"), bound_pr.get("base")
    # The immutable run.head_sha above binds the producer. A PR head projection
    # can advance after this run when genuine H is published; it is not a second
    # immutable producer identity.
    need(type(head) is dict and type(base) is dict and
         head.get("ref") == PIPELINE_BRANCH and base.get("sha") == BASE and
         base.get("ref") == BASE_BRANCH, "v110.native_producer_pr_binding")
    need(type(raw_artifact.get("id")) is int and raw_artifact["id"] == pinset["artifactId"] and
         raw_artifact.get("name") == "v110-lock-preparation-" + pinset["runId"] + "-attempt1" and
         type(raw_artifact.get("size_in_bytes")) is int and
         0 < raw_artifact["size_in_bytes"] <= ARTIFACT_BYTES + 65536 and
         raw_artifact.get("expired") is False and raw_artifact.get("digest") == "sha256:" + archive_sha256 and
         archive_sha256 == pinset["artifactSha256"], "v110.native_producer_artifact")
    workflow_run = raw_artifact.get("workflow_run")
    need(type(workflow_run) is dict and workflow_run.get("id") == raw_run["id"] and
         workflow_run.get("head_sha") == pinset["pipelineHead"] and
         workflow_run.get("head_branch") == PIPELINE_BRANCH and
         workflow_run.get("repository_id") == repo["id"] and
         workflow_run.get("head_repository_id") == repo["id"], "v110.native_artifact_run_binding")
    created, artifact_created, expires = (utc(raw_run.get("created_at")),
        utc(raw_artifact.get("created_at")), utc(raw_artifact.get("expires_at")))
    current = epoch(now)
    need(utc(PACKAGE_NOT_BEFORE) <= created <= artifact_created < expires and
         artifact_created.timestamp() <= current < expires.timestamp() and current < utc(EXPIRES_AT).timestamp() and
         (expires - artifact_created).total_seconds() <= 3 * 86400 + 60,
         "v110.native_producer_clock")
    return {"authenticated": True, "runId": pinset["runId"], "pipelineHead": pinset["pipelineHead"],
            "artifactId": pinset["artifactId"], "artifactSha256": archive_sha256,
            "runAttempt": 1, "conclusion": "success"}


def verify_generated_artifact(files, bindings, *, producer):
    """Consume only ``validate_producer``'s normalized fixed-route result."""
    validate_bindings(bindings)
    fields(files, ("pnpm-lock.yaml", "lock.diff", "generation.json"), "v110.artifact_exact_members")
    need(all(type(v) is bytes for v in files.values()) and sum(map(len, files.values())) <= ARTIFACT_BYTES - 65536, "v110.artifact_total_cap")
    fields(producer, ("authenticated", "runId", "pipelineHead", "artifactId", "artifactSha256", "runAttempt", "conclusion"), "v110.producer_fields")
    need(producer["authenticated"] is True and producer["conclusion"] == "success" and
         type(producer["runAttempt"]) is int and producer["runAttempt"] == 1,
         "v110.authentic_generation_producer")
    p = {k: producer[k] for k in ("runId", "pipelineHead", "artifactId", "artifactSha256")}
    p.update(receiptSha256=digest(files["generation.json"]),
             generatedLockSha256=digest(files["pnpm-lock.yaml"]), gitDiffSha256=digest(files["lock.diff"]))
    generation_pin(p)
    existing = active_material(bindings)["validation"]
    need(existing is None or existing["generation"] == p, "v110.existing_generation_pin")
    value = validate_generation(files["generation.json"], bindings, generation=p)
    need(digest(files["pnpm-lock.yaml"]) == value["generatedLockSha256"] and
        digest(files["lock.diff"]) == value["gitDiffSha256"], "v110.generated_artifact_hashes")
    return value


def expected_derived_ledger(before_raw, generated_lock_blob, generation):
    before = parse(before_raw)
    need(type(before) is dict and before.get("schema") == "openclaw.v110.fork-carry-reconciliation.v1" and
         before.get("lockState") == "pending_secretless_ci_derivation" and "lockDerivation" not in before,
         "v110.pending_ledger")
    generation_pin(generation)
    need(pin(generated_lock_blob, 160), "v110.generated_lock_blob")
    rows = [r for r in before.get("sourcePaths", []) if type(r) is dict and r.get("path") == "pnpm-lock.yaml"]
    need(len(rows) == 1 and type(rows[0].get("result")) is dict and rows[0]["result"].get("mode") == "100644", "v110.unique_lock_row")
    result = deepcopy(before)
    row = next(r for r in result["sourcePaths"] if r["path"] == "pnpm-lock.yaml")
    row["result"] = {"mode": "100644", "blob": generated_lock_blob, "sha256": generation["generatedLockSha256"]}
    row["disposition"] = "AUTHENTIC_CI_DERIVED_LOCK_ONLY"
    result["lockState"] = "ci_derived"
    result["lockDerivation"] = {"runId": generation["runId"], "attempt": 1,
        "artifactId": generation["artifactId"], "artifactSha256": generation["artifactSha256"],
        "receiptSha256": generation["receiptSha256"], "generatedLockSha256": generation["generatedLockSha256"]}
    return encode(result)


def _verify_h_delta(read, read_tree, material, validation):
    """The same exact G→H tree rule also protects a correction's prior H."""
    target, pinset = validation["source"], validation["generation"]
    a, b = _source(read, read_tree, material), _source(read, read_tree, target)
    need(_parents(read, target["sourceSha"]) == [material["sourceSha"]], "v110.derived_single_parent")
    changed = sorted(p for p in set(a) | set(b) if a.get(p) != b.get(p))
    expected = [LEDGER] if material["fileSha256"]["pnpm-lock.yaml"] == pinset["generatedLockSha256"] else sorted((LEDGER, "pnpm-lock.yaml"))
    need(set(a) == set(b) and changed == expected and tree_digest(a, changed) == tree_digest(b, changed) == validation["unchangedTreeSha256"], "v110.derived_exact_delta")
    need(all(b[name][:2] == ("100644", "blob") for name in ("pnpm-lock.yaml", LEDGER)),
         "v110.derived_regular_inputs")
    lock = read("show", target["sourceSha"] + ":pnpm-lock.yaml")
    need(digest(lock) == pinset["generatedLockSha256"], "v110.derived_lock_bytes")
    ledger = expected_derived_ledger(read("show", material["sourceSha"] + ":" + LEDGER), b["pnpm-lock.yaml"][2], pinset)
    need(read("show", target["sourceSha"] + ":" + LEDGER) == ledger, "v110.derived_exact_ledger")
    return b


def verify_derived_source(read_git, bindings, generation_raw, *, read_tree):
    validate_bindings(bindings)
    item = active_material(bindings)
    need(item["validation"] is not None, "v110.validation_disarmed")
    verify_material_source(read_git, bindings, read_tree=read_tree)
    read = _read_reader(read_git)
    value = validate_generation(generation_raw, bindings)
    _verify_h_delta(read, read_tree, item["material"], item["validation"])
    return value
