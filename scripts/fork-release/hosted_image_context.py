#!/usr/bin/env python3
"""Prepare/capture a hosted producer; never qualify, execute or upload its image.

Only explicit capture calls the installed native GitHub attestation verifier and
canonical GitHub API owner. Saved caller-supplied JSON is never signature proof.
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

import hosted_reinspection as documents
import hosted_export
import pr
import private_oci_bundle

REPOSITORY = "fr-meyer/openclaw"
SOURCE = "85a9bdc1285c338f10f5ca818abc259f6d483b5b"
TREE = "3e0d6fbf5bc015063dce3e4f0f353f0eac3aed6a"
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


def plan_at(path, expected):
    private(path)
    value, hashed = data(path)
    need(HEX.fullmatch(expected) and hashed == expected and set(value) == FIELDS and
         value["schema"] == "openclaw.retained-hosted-origin-input.v1")
    for key in FIELDS:
        if key.endswith("Path") or key.endswith("Dir"):
            location = Path(value[key])
            need(location.is_absolute() and location.resolve() == location)
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
    return value, hashed


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


def command(plan):
    return [verifier_executable(), "attestation", "verify", plan["archivePath"], "--hostname", "github.com", "--repo", REPOSITORY,
            "--signer-workflow", f"{REPOSITORY}/{WORKFLOW}", "--signer-digest", plan["workflowSha"],
            "--source-digest", plan["workflowSha"], "--source-ref", plan["workflowRef"],
            "--cert-oidc-issuer", "https://token.actions.githubusercontent.com", "--deny-self-hosted-runners",
            "--predicate-type", "https://slsa.dev/provenance/v1", "--format", "json", "--limit", "1",
            "--jq", VERIFICATION_FILTER]


def capture(plan, prepared):
    # Never load a saved verification JSON file or accept a caller-controlled
    # verifier executable, bundle root, command hook or authenticated flag.
    argv = command(plan)
    result = subprocess.run(argv, capture_output=True, timeout=90, check=False)
    need(result.returncode == 0 and len(result.stdout) <= 1024 * 1024)
    verified = json.loads(result.stdout, object_pairs_hook=documents._pairs)
    need(isinstance(verified, list) and len(verified) == 1)
    proof = verified[0]["verificationResult"]
    certificate = proof["signature"]["certificate"]
    signer = f"https://github.com/{REPOSITORY}/{WORKFLOW}@{plan['workflowRef']}"
    invocation = f"https://github.com/{REPOSITORY}/actions/runs/{plan['runId']}/attempts/{plan['attempt']}"
    need(certificate.get("issuer") == "https://token.actions.githubusercontent.com" and
         certificate.get("sourceRepositoryURI") == f"https://github.com/{REPOSITORY}" and
         certificate.get("sourceRepositoryDigest") == certificate.get("buildSignerDigest") == plan["workflowSha"] and
         certificate.get("buildSignerURI") == signer and
         certificate.get("subjectAlternativeName") == {"type": "URI", "value": signer} and
         certificate.get("sourceRepositoryRef") == plan["workflowRef"] and
         certificate.get("runnerEnvironment") == "github-hosted" and certificate.get("runInvocationURI") == invocation and
         isinstance(proof.get("verifiedTimestamps"), list) and bool(proof["verifiedTimestamps"]))
    statement = proof["statement"]
    need(statement.get("predicateType") == "https://slsa.dev/provenance/v1" and
         isinstance(statement.get("subject"), list) and len(statement["subject"]) == 1 and
         statement["subject"][0].get("name") == "retained-oci.tar" and
         statement["subject"][0].get("digest") == {"sha256": plan["archiveSha256"]})
    prefix = f"repos/{REPOSITORY}"
    run = pr.fetch_public_json(f"{prefix}/actions/runs/{plan['runId']}/attempts/{plan['attempt']}")
    job = pr.fetch_public_json(f"{prefix}/actions/jobs/{plan['jobId']}")
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
         documents.timestamp(job["completed_at"]) <= documents.timestamp(stamp()))
    # Recheck retained bytes after native verification/API work, preserving a
    # separate later-inspector record without changing the original producer.
    need(prepare(plan, prepared["planSha256"]) == prepared)
    return {**prepared, "status": "captured", "originAuthenticated": True,
            "capturedAt": stamp(), "attestationVerificationSha256": digest(result.stdout),
            "apiCanonicalSha256": digest(encoded({"run": run, "job": job})),
            "buildStepOutcome": "success", "retentionStepOutcome": selected[1]["conclusion"],
            "workflowOutcome": run["conclusion"], "jobOutcome": job["conclusion"],
            "verificationCommand": argv[:3] + ["<private-archive>"] + argv[4:],
            "blockers": (["original_resource_assessment_failed"] if prepared["resourceAssessment"] != "passed" else []) +
                ["privacy_static_and_native_image_qualification_not_performed"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "capture"))
    for field in ("plan", "plan-sha256", "output"):
        parser.add_argument("--" + field, required=True)
    args = parser.parse_args(argv)
    try:
        plan, plan_hash = plan_at(args.plan, args.plan_sha256)
        value = prepare(plan, plan_hash)
        if args.mode == "capture":
            value = capture(plan, value)
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
