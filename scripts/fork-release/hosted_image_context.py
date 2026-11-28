#!/usr/bin/env python3
"""Prepare/capture a hosted producer; never qualify, execute or upload its image.

Only explicit capture calls the installed native GitHub attestation verifier and
canonical GitHub API owner. Historical reuse requires an independently pinned
custody handoff and the exact evidence authenticated by its original capture.
Reuse is limited to one code-pinned source85 capture and plan; it is not a
generic saved-receipt authenticator and never refreshes historical evidence.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

import hosted_reinspection as documents
import hosted_export
import pr
import private_oci_bundle

REPOSITORY = "fr-meyer/openclaw"
SOURCE = "30786562e236aab6a924981c62aa61b920132c76"
TREE = "2c7d245a5abe5b4ecfd4477f7890f00aaa3deeff"
WORKFLOW = ".github/workflows/fork-release-pipeline.yml"
BUILD_STEP = "Build exact candidate once into OCI"
ATTEST_STEP = "Retain private OCI archive"
GH = "/opt/homebrew/bin/gh" if sys.platform == "darwin" else "/usr/bin/gh"
TOOLING = Path(__file__).resolve().parents[2]
LINUX_GH_RELATIVE = Path(".local/qualification-tools/gh-2.98.0/bin/gh")
LINUX_GH_BYTES = 41377954
LINUX_GH_SHA256 = "62885b97de6a0cd85e616cdd94bcda908bf5cf1018094385892b05cea3537163"
VERIFICATION_FILTER = ('[.[] | {verificationResult: {signature: {certificate: .verificationResult.signature.certificate}, '
                       'verifiedTimestamps: .verificationResult.verifiedTimestamps, statement: '
                       '{predicateType: .verificationResult.statement.predicateType, subject: .verificationResult.statement.subject}}}]')
SHA = re.compile(r"[0-9a-f]{40}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
POSITIVE = re.compile(r"[1-9][0-9]*\Z")
FIELDS = set("""schema sourceDir ociDir manifestPath inventoryPath metadataPath originPath archivePath resourcesPath
workflowSha workflowRef inspectionToolingSha runId attempt jobId archiveSha256 originSha256
manifestSha256 inventorySha256 buildMetadataSha256 resourcesSha256 indexDigest builtAt""".split())
BUNDLE_FIELDS = {"attestationBundlePath", "attestationBundleSha256"}
# Frozen authentication authority for this retained source85 image only. A
# caller-provided handoff/hash cannot add another trusted historical capture.
ORIGINAL_CAPTURE_SHA256 = "770c256fc291c4311e61141965f4421f1388c7cd8203e6bd2e4a3d2efffb637f"
ORIGINAL_PLAN_SHA256 = "7a4b86a599282dae1d979d3ce5eab12aabd4c5eaa78d65b7a4b572ea318aac81"


class Refusal(ValueError):
    pass


def need(value):
    if not value:
        raise Refusal("hosted.origin_refused")


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def private(path, directory=False):
    path = Path(path)
    info = path.lstat()
    need(path.is_absolute() and path.resolve() == path and info.st_uid == os.getuid() and
         info.st_mode & 0o077 == 0 and
         (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)))


def data(path):
    raw, hashed = documents.read_document(path)
    return json.loads(raw, object_pairs_hook=documents._pairs), hashed


def stamp():
    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_plan(value, canonical_paths=True):
    optional = set(value) & BUNDLE_FIELDS
    need(optional in (set(), BUNDLE_FIELDS) and set(value) == FIELDS | optional and
         value["schema"] == "openclaw.retained-hosted-origin-input.v1")
    for key in FIELDS | optional:
        if key.endswith("Path") or key.endswith("Dir"):
            location = Path(value[key])
            need(location.is_absolute() and (not canonical_paths or location.resolve() == location))
        if key.endswith("Sha256"):
            need(isinstance(value[key], str) and HEX.fullmatch(value[key]))
    need(all(isinstance(value[key], str) and SHA.fullmatch(value[key]) for key in
             ("workflowSha", "inspectionToolingSha")) and
         all(isinstance(value[key], str) and POSITIVE.fullmatch(value[key]) for key in ("runId", "attempt", "jobId")) and
         isinstance(value["workflowRef"], str) and
         re.fullmatch(r"refs/heads/[A-Za-z0-9._/-]{1,128}", value["workflowRef"]) and
         ".." not in value["workflowRef"].split("/"))
    documents.timestamp(value["builtAt"])
    need(documents.DIGEST.fullmatch(value["indexDigest"]))
    return value


def plan_at(path, expected):
    private(path)
    value, hashed = data(path)
    need(isinstance(expected, str) and HEX.fullmatch(expected) and hashed == expected)
    return validate_plan(value), hashed


def bundle_bytes(plan):
    if "attestationBundlePath" not in plan:
        return None
    private(plan["attestationBundlePath"])
    raw, hashed = documents.read_document(plan["attestationBundlePath"])
    need(hashed == plan["attestationBundleSha256"])
    # An input Sigstore bundle is untrusted bytes for the native verifier. It is
    # never parsed as a successful verification result or authentication flag.
    return raw


def prepare(plan, plan_hash):
    source = Path(plan["sourceDir"])
    need(pr.git(source, "rev-parse", "HEAD") == SOURCE and
         pr.git(source, "rev-parse", "HEAD^{tree}") == TREE and
         pr.git(source, "status", "--porcelain", "--untracked-files=all") == "")
    tooling = Path(__file__).resolve().parents[2]
    need(pr.git(tooling, "rev-parse", "HEAD") == plan["inspectionToolingSha"] and
         pr.git(tooling, "status", "--porcelain", "--untracked-files=all") == "")
    for key in ("originPath", "metadataPath", "archivePath", "resourcesPath"):
        private(plan[key])
    origin, origin_hash = data(plan["originPath"])
    manifest, manifest_hash = data(plan["manifestPath"])
    inventory, inventory_hash = data(plan["inventoryPath"])
    metadata, metadata_hash = data(plan["metadataPath"])
    resources, resources_hash = data(plan["resourcesPath"])
    producer = {"workflowSha": plan["workflowSha"], "runId": plan["runId"], "attempt": plan["attempt"]}
    expected = {"schema": "openclaw.hosted-build-custody.v1", "repository": REPOSITORY,
                "producer": producer, "sourceSha": SOURCE, "sourceTree": TREE,
                **{key: plan[key] for key in ("manifestSha256", "inventorySha256", "indexDigest",
                                              "builtAt", "buildMetadataSha256", "resourcesSha256")}}
    need(origin == expected and origin_hash == plan["originSha256"] and
         manifest_hash == plan["manifestSha256"] and inventory_hash == plan["inventorySha256"] and
         metadata_hash == plan["buildMetadataSha256"] and metadata.get("containerimage.digest") == plan["indexDigest"] and
         resources_hash == plan["resourcesSha256"] and
         manifest.get("repository") == REPOSITORY and manifest.get("source", {}).get("commit") == SOURCE and
         manifest.get("source", {}).get("tree") == TREE and
         manifest.get("image") == {"architecture": "amd64", "extensions": "codex,workboard"} and
         inventory.get("manifestSha256") == manifest_hash and inventory.get("repository") == REPOSITORY)
    resource_passed = hosted_export.require_resources(resources, source=SOURCE, tooling=plan["workflowSha"],
                                                       index=plan["indexDigest"], require_pass=False)
    bundle_bytes(plan)
    archive = private_oci_bundle.verify_archive(plan["archivePath"], plan["archiveSha256"],
        oci_dir=plan["ociDir"], manifest_path=plan["manifestPath"], inventory_path=plan["inventoryPath"],
        metadata_path=plan["metadataPath"], origin_path=plan["originPath"], resources_path=plan["resourcesPath"])
    need(archive["archiveSha256"] == plan["archiveSha256"] and HEX.fullmatch(archive["ociClosureSha256"]))
    return {"schema": "openclaw.retained-hosted-build-context.v1", "status": "prepared",
            "originAuthenticated": False, "qualified": False, "nativeExecuted": False,
            "productionAuthorized": False, "repository": REPOSITORY, "sourceSha": SOURCE, "sourceTree": TREE,
            "producer": producer, "manifestSha256": manifest_hash, "inventorySha256": inventory_hash,
            "indexDigest": plan["indexDigest"], "builtAt": plan["builtAt"],
            "buildMetadataSha256": metadata_hash, "custodySha256": origin_hash,
            "resourcesSha256": resources_hash, "resourceAssessment": "passed" if resource_passed else "failed",
            "archiveSha256": archive["archiveSha256"], "ociClosureSha256": archive["ociClosureSha256"],
            "planSha256": plan_hash, "inspectionToolingSha": plan["inspectionToolingSha"],
            **({"attestationBundleSha256": plan["attestationBundleSha256"]} if "attestationBundlePath" in plan else {}),
            "blockers": ["native_attestation_and_canonical_api_capture_required",
                         "privacy_static_and_native_image_qualification_not_performed"]}


def verifier_executable():
    if sys.platform != "linux":
        return GH
    path = TOOLING / LINUX_GH_RELATIVE
    need(path.resolve() == path)
    # This is one fixed, separately approved tool location, not a PATH search,
    # installation, fallback or executable supplied by the capture caller.
    for directory in (TOOLING, *list(path.parents)[:4]):
        info = directory.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.getuid()) and info.st_mode & 0o022 == 0)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid in (0, os.getuid()) and
             before.st_mode & (0o022 | stat.S_ISUID | stat.S_ISGID) == 0 and
             before.st_mode & 0o111 != 0 and before.st_size == LINUX_GH_BYTES)
        hashed, count = hashlib.sha256(), 0
        while chunk := stream.read(1024 * 1024):
            count += len(chunk)
            need(count <= LINUX_GH_BYTES)
            hashed.update(chunk)
        after = os.fstat(stream.fileno())
        need(count == LINUX_GH_BYTES and hashed.hexdigest() == LINUX_GH_SHA256 and
             all(getattr(before, key) == getattr(after, key) for key in
                 ("st_dev", "st_ino", "st_uid", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")))
    return str(path)


def command(plan, bundle_snapshot=None):
    argv = [verifier_executable(), "attestation", "verify", plan["archivePath"], "--hostname", "github.com", "--repo", REPOSITORY,
            "--signer-workflow", f"{REPOSITORY}/{WORKFLOW}", "--signer-digest", plan["workflowSha"],
            "--source-digest", plan["workflowSha"], "--source-ref", plan["workflowRef"],
            "--cert-oidc-issuer", "https://token.actions.githubusercontent.com", "--deny-self-hosted-runners",
            "--predicate-type", "https://slsa.dev/provenance/v1", "--format", "json", "--limit", "1",
            "--jq", VERIFICATION_FILTER]
    if "attestationBundlePath" in plan:
        argv.extend(["--bundle", str(bundle_snapshot or plan["attestationBundlePath"])])
    return argv


def validate_attestation(plan, raw):
    verified = json.loads(raw, object_pairs_hook=documents._pairs)
    need(isinstance(verified, list) and len(verified) == 1)
    proof = verified[0]["verificationResult"]
    certificate = proof["signature"]["certificate"]
    signer = f"https://github.com/{REPOSITORY}/{WORKFLOW}@{plan['workflowRef']}"
    invocation = f"https://github.com/{REPOSITORY}/actions/runs/{plan['runId']}/attempts/{plan['attempt']}"
    # Pinned GH 2.98.0 emits the URI SAN as a JSON string.
    need(certificate.get("issuer") == "https://token.actions.githubusercontent.com" and
         certificate.get("sourceRepositoryURI") == f"https://github.com/{REPOSITORY}" and
         certificate.get("sourceRepositoryDigest") == certificate.get("buildSignerDigest") == plan["workflowSha"] and
         certificate.get("buildSignerURI") == signer and
         certificate.get("subjectAlternativeName") == signer and
         certificate.get("sourceRepositoryRef") == plan["workflowRef"] and
         certificate.get("runnerEnvironment") == "github-hosted" and certificate.get("runInvocationURI") == invocation and
         isinstance(proof.get("verifiedTimestamps"), list) and bool(proof["verifiedTimestamps"]))
    statement = proof["statement"]
    need(statement.get("predicateType") == "https://slsa.dev/provenance/v1" and
         isinstance(statement.get("subject"), list) and len(statement["subject"]) == 1 and
         statement["subject"][0].get("name") == "retained-oci.tar" and
         statement["subject"][0].get("digest") == {"sha256": plan["archiveSha256"]})


def canonical_outcomes(plan, run, job, captured_at):
    need(run.get("id") == int(plan["runId"]) and run.get("run_attempt") == int(plan["attempt"]) and
         run.get("head_sha") == plan["workflowSha"] and run.get("path") == WORKFLOW and
         run.get("repository", {}).get("full_name") == REPOSITORY and
         run.get("head_repository", {}).get("full_name") == REPOSITORY and
         run.get("head_branch") == plan["workflowRef"].removeprefix("refs/heads/") and
         run.get("event") in ("push", "workflow_dispatch") and run.get("status") == "completed" and
         run.get("conclusion") in ("success", "failure", "cancelled") and
         job.get("id") == int(plan["jobId"]) and job.get("run_id") == int(plan["runId"]) and
         job.get("run_attempt") == int(plan["attempt"]) and job.get("head_sha") == plan["workflowSha"] and
         job.get("name") == "qualify-and-prepare" and job.get("status") == "completed" and
         job.get("conclusion") in ("success", "failure", "cancelled") and isinstance(job.get("steps"), list))
    selected = []
    for name in (BUILD_STEP, ATTEST_STEP):
        matches = [step for step in job["steps"] if step.get("name") == name]
        need(len(matches) == 1 and matches[0].get("status") == "completed" and
             matches[0].get("conclusion") in (("success",) if name == BUILD_STEP else
                                               ("success", "failure", "cancelled")))
        selected.append(matches[0])
    need(documents.timestamp(selected[0]["started_at"]) <= documents.timestamp(selected[0]["completed_at"]) <=
         documents.timestamp(selected[1]["started_at"]) <= documents.timestamp(selected[1]["completed_at"]) <=
         documents.timestamp(job["completed_at"]) <= documents.timestamp(captured_at))
    return {"buildStepOutcome": "success", "retentionStepOutcome": selected[1]["conclusion"],
            "workflowOutcome": run["conclusion"], "jobOutcome": job["conclusion"]}


def capture(plan, prepared):
    # A separately pinned signed bundle may select native no-login verification;
    # never accept a saved verification result, custom trust root, executable or
    # auth-failure fallback. Snapshot the exact private input before native use.
    raw_bundle = bundle_bytes(plan)
    with tempfile.TemporaryDirectory(prefix="openclaw-attestation-input-") as directory:
        snapshot = Path(directory) / "bundle.jsonl"
        if raw_bundle is not None:
            with snapshot.open("xb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(raw_bundle); stream.flush(); os.fsync(stream.fileno())
        argv = command(plan, snapshot if raw_bundle is not None else None)
        result = subprocess.run(argv, capture_output=True, timeout=90, check=False)
    need(result.returncode == 0 and len(result.stdout) <= 1024 * 1024)
    validate_attestation(plan, result.stdout)
    prefix = f"repos/{REPOSITORY}"
    run = pr.fetch_public_json(f"{prefix}/actions/runs/{plan['runId']}/attempts/{plan['attempt']}")
    job = pr.fetch_public_json(f"{prefix}/actions/jobs/{plan['jobId']}")
    outcomes = canonical_outcomes(plan, run, job, stamp())
    # Recheck retained bytes after native verification/API work, preserving a
    # separate later-inspector record without changing the original producer.
    need(prepare(plan, prepared["planSha256"]) == prepared)
    recorded = argv[:3] + ["<private-archive>"] + argv[4:]
    if "--bundle" in recorded:
        recorded[recorded.index("--bundle") + 1] = "<private-attestation-bundle>"
    return {**prepared, "status": "captured", "originAuthenticated": True,
            "capturedAt": stamp(), "attestationVerificationSha256": digest(result.stdout),
            "apiCanonicalSha256": digest(encoded({"run": run, "job": job})),
            **outcomes,
            "verificationCommand": recorded,
            "blockers": (["original_resource_assessment_failed"] if prepared["resourceAssessment"] != "passed" else []) +
                ["privacy_static_and_native_image_qualification_not_performed"]}


def reuse(plan, prepared, custody_path, custody_hash):
    private(custody_path)
    custody, actual = data(custody_path)
    fields = {"schema", "currentPlanSha256", "originalPlanPath", "originalPlanSha256", "originalCapturePath",
              "originalCaptureSha256", "nativeVerificationPath", "canonicalApiPath"}
    need(isinstance(custody_hash, str) and HEX.fullmatch(custody_hash) and actual == custody_hash and
         set(custody) == fields and custody["schema"] == "openclaw.retained-hosted-authentication-custody.v1" and
         custody["currentPlanSha256"] == prepared["planSha256"] and
         custody["originalCaptureSha256"] == ORIGINAL_CAPTURE_SHA256 and
         custody["originalPlanSha256"] == ORIGINAL_PLAN_SHA256)
    raw = {}
    for key in fields:
        if not key.endswith("Path"):
            continue
        private(custody[key])
        raw[key], _ = documents.read_document(custody[key])
    for name in ("originalPlan", "originalCapture"):
        need(isinstance(custody[name + "Sha256"], str) and HEX.fullmatch(custody[name + "Sha256"]) and
             digest(raw[name + "Path"]) == custody[name + "Sha256"])
    original_plan = validate_plan(json.loads(raw["originalPlanPath"], object_pairs_hook=documents._pairs),
                                  canonical_paths=False)
    original = json.loads(raw["originalCapturePath"], object_pairs_hook=documents._pairs)
    # Only explicitly local paths and the later inspector may differ. Original
    # producer, bundle digest, source, archive, controls, run/job and time do not.
    need(set(original_plan) == set(plan) and all(original_plan[key] == plan[key] for key in plan
         if not key.endswith(("Path", "Dir")) and key != "inspectionToolingSha"))
    capture_fields = {"capturedAt", "attestationVerificationSha256", "apiCanonicalSha256", "buildStepOutcome",
                      "retentionStepOutcome", "workflowOutcome", "jobOutcome", "verificationCommand"}
    need(set(original) == set(prepared) | capture_fields and original["status"] == "captured" and
         original["originAuthenticated"] is True and original["planSha256"] == custody["originalPlanSha256"] and
         original["inspectionToolingSha"] == original_plan["inspectionToolingSha"] and
         all(original[key] == prepared[key] for key in prepared
             if key not in {"status", "originAuthenticated", "planSha256", "inspectionToolingSha", "blockers"}) and
         documents.timestamp(original["builtAt"]) <= documents.timestamp(original["capturedAt"]) <=
         documents.timestamp(stamp()) and
         digest(raw["nativeVerificationPath"]) == original["attestationVerificationSha256"])
    validate_attestation(original_plan, raw["nativeVerificationPath"])
    api = json.loads(raw["canonicalApiPath"], object_pairs_hook=documents._pairs)
    need(set(api) == {"run", "job"} and digest(encoded(api)) == original["apiCanonicalSha256"])
    outcomes = canonical_outcomes(original_plan, api["run"], api["job"], original["capturedAt"])
    need(all(original[key] == value for key, value in outcomes.items()))
    blockers = (["original_resource_assessment_failed"] if prepared["resourceAssessment"] != "passed" else []) + [
        "privacy_static_and_native_image_qualification_not_performed"]
    need(original["blockers"] == blockers and prepare(plan, prepared["planSha256"]) == prepared)
    # This is a local check of historical authenticated evidence, not a new
    # signature verification/API observation. Never rewrite the original file.
    return {**prepared, "status": "captured", "originAuthenticated": True,
            **{key: original[key] for key in capture_fields}, "blockers": blockers,
            "authenticationMethod": "historical_verified_capture_reuse",
            "authenticationCustodySha256": custody_hash,
            "originalCaptureSha256": custody["originalCaptureSha256"],
            "originalPlanSha256": custody["originalPlanSha256"],
            "originalCapturedAt": original["capturedAt"],
            "originalInspectionToolingSha": original["inspectionToolingSha"],
            "nativeAttestationVerificationPerformed": False, "canonicalApiFetched": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "capture", "reuse"))
    for field in ("plan", "plan-sha256", "output"):
        parser.add_argument("--" + field, required=True)
    parser.add_argument("--custody")
    parser.add_argument("--custody-sha256")
    args = parser.parse_args(argv)
    try:
        need((args.mode == "reuse") == (args.custody is not None and args.custody_sha256 is not None) and
             (args.mode == "reuse" or args.custody is args.custody_sha256 is None))
        plan, plan_hash = plan_at(args.plan, args.plan_sha256)
        value = prepare(plan, plan_hash)
        if args.mode == "capture":
            value = capture(plan, value)
        elif args.mode == "reuse":
            value = reuse(plan, value, args.custody, args.custody_sha256)
        need(plan_at(args.plan, args.plan_sha256) == (plan, plan_hash))
        parent = Path(args.output).parent
        private(parent, directory=True)
        output = Path(args.output)
        need(output.is_absolute() and output.resolve() == output and
             not any(output == Path(plan[key]) for key in FIELDS if key.endswith("Path")) and
             all(parent != Path(plan[key]) and Path(plan[key]) not in parent.parents and
                 parent not in Path(plan[key]).parents for key in ("sourceDir", "ociDir")))
        with output.open("xb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(encoded(value)); stream.flush(); os.fsync(stream.fileno())
        print(json.dumps(value, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError, AttributeError, subprocess.SubprocessError):
        print('{"schema":"openclaw.retained-hosted-build-context.v1","status":"refused","originAuthenticated":false,"qualified":false,"nativeExecuted":false,"productionAuthorized":false}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
