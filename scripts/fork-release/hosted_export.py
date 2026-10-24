#!/usr/bin/env python3
"""Bind hosted seal/privacy/resource evidence before optional public export.

This gate does not upload anything, grant storage approval or replace OCI/native
verification. With export disabled, outputs expire with the runner and cannot be
promoted later. Legacy image receipts remain readable elsewhere, but are not
accepted as newly qualified hosted Git-context evidence here.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re

import hosted_privacy as privacy_contract


class Refusal(ValueError):
    pass


def need(condition, reason):
    if not condition:
        raise Refusal(reason)


def require_clean_privacy(receipt):
    """V2 aggregates are authoritative; representatives may be empty/truncated."""
    summary = receipt.get("findingSummary")
    need(isinstance(summary, dict) and set(summary) == {"unit", "total", "byRule", "byUnit"} and
         summary.get("unit") == privacy_contract.COUNT_UNIT, "privacy aggregate contract missing")
    for key, catalog in (("byRule", privacy_contract.FINDING_RULES),
                         ("byUnit", privacy_contract.FINDING_UNITS)):
        counts = summary.get(key)
        need(isinstance(counts, dict) and set(counts) == set(catalog) and
             all(type(value) is int and value >= 0 for value in counts.values()),
             "privacy aggregate catalog or count invalid")
    total = summary.get("total")
    need(type(total) is int and total == sum(summary["byRule"].values()) ==
         sum(summary["byUnit"].values()) and total == 0, "privacy aggregate findings remain or disagree")
    need(receipt.get("inspectionComplete") is True and receipt.get("findings") == [] and
         receipt.get("representativesTruncated") is False and "refusal" not in receipt and
         type(receipt.get("representativeLimit")) is int and
         0 <= receipt["representativeLimit"] <= privacy_contract.MAX_REPRESENTATIVES,
         "privacy inspection is incomplete or findings remain")
    need(receipt.get("locationIndex") == [] and receipt.get("locationIndexTruncated") is False and
         type(receipt.get("locationIndexLimit")) is int and
         receipt["locationIndexLimit"] == privacy_contract.MAX_LOCATION_ROWS and
         type(receipt.get("locationIndexByteLimit")) is int and
         receipt["locationIndexByteLimit"] == privacy_contract.MAX_LOCATION_BYTES,
         "privacy location index is missing, truncated or nonempty")


def runtime_proof(seal):
    """New hosted exports require measured image facts, not source test results."""
    proof = seal.get("runtimeQualification")
    need(isinstance(proof, dict), "actual image runtime proof missing")
    expected = proof.get("expected")
    need(isinstance(expected, dict) and set(expected) == {
        "nodeVersion", "markdownVersion", "argparseVersion", "dockerfileSha256",
        "consumerManifestSha256", "lockfileSha256"}, "invalid runtime expectations")
    need(all(isinstance(expected[key], str) and re.fullmatch(r"\d+\.\d+\.\d+", expected[key])
             for key in ("nodeVersion", "markdownVersion", "argparseVersion")), "invalid runtime version")
    need(all(isinstance(expected[key], str) and re.fullmatch(r"[a-f0-9]{64}", expected[key])
             for key in ("dockerfileSha256", "consumerManifestSha256", "lockfileSha256")), "invalid runtime source hash")
    node, markdown, ui = (proof.get(key) for key in ("node", "markdown", "controlUi"))
    need(all(isinstance(value, dict) for value in (node, markdown, ui)), "incomplete runtime proof")
    need(proof.get("schema") == "openclaw.image-runtime.v1" and
         all(proof.get(key) == seal.get(key) for key in ("sourceSha", "imageDigest", "configDigest")) and
         node == {"version": expected["nodeVersion"], "platform": "linux", "architecture": "x64"} and
         markdown.get("version") == expected["markdownVersion"] and
         markdown.get("argparseVersion") == expected["argparseVersion"] and
         markdown.get("resolution") == "pnpm-production-store" and
         markdown.get("consumer") == "dist/plugin-sdk/text-chunking.js" and
         markdown.get("render") is True and markdown.get("documentIsolation") is True,
         "actual image runtime proof changed")
    need(all(isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) for value in
             (markdown.get("consumerSha256"), ui.get("indexSha256"), ui.get("manifestSha256"), ui.get("generation"))) and
         type(ui.get("assetCount")) is int and 0 < ui["assetCount"] <= 4096 and
         type(ui.get("assetBytes")) is int and 0 < ui["assetBytes"] <= 96 * 1024 * 1024,
         "incomplete built UI or consumer proof")


def validate(seal, privacy, resources, *, source, tooling, index, run, attempt,
             public_export=False, storage_approved=False):
    need(re.fullmatch(r"[0-9a-f]{40}", source or "") is not None, "invalid source identity")
    need(re.fullmatch(r"[0-9a-f]{40}", tooling or "") is not None, "invalid tooling identity")
    need(re.fullmatch(r"sha256:[0-9a-f]{64}", index or "") is not None, "invalid image identity")
    need(all(re.fullmatch(r"[1-9][0-9]*", v or "") for v in (run, attempt)),
         "invalid execution identity")
    need(not public_export or storage_approved, "public artifact storage is not approved")
    need(isinstance(seal, dict) and seal.get("schema") == "openclaw.fork-release-image.v2",
         "missing native image seal")
    need(seal.get("repository") == "fr-meyer/openclaw" and
         seal.get("architecture") == "amd64", "wrong repository or architecture")
    need(seal.get("producer") == {"workflowSha": tooling, "runId": run, "attempt": attempt},
         "image seal belongs to another execution")
    need(seal.get("buildContext") == {"kind": "git", "repository": "https://github.com/fr-meyer/openclaw",
                                      "sourceSha": source}, "hosted Git source proof missing or changed")
    runtime_proof(seal)
    for receipt, schema in ((privacy, "openclaw.hosted-privacy.v2"),
                            (resources, "openclaw.hosted-resources.v1")):
        need(isinstance(receipt, dict) and receipt.get("schema") == schema and
             receipt.get("status") == "passed", "incomplete privacy or resource assessment")
        need(receipt.get("toolingSha") == tooling, "assessment tooling changed")
    for receipt in (seal, privacy, resources):
        need(receipt.get("sourceSha") == source and receipt.get("indexDigest") == index,
             "assessment source or image changed")
    need(resources.get("violations") == [], "resource violations remain")
    require_clean_privacy(privacy)
    for field in ("imageDigest", "configDigest"):
        need(re.fullmatch(r"sha256:[0-9a-f]{64}", seal.get(field, "")) is not None and
             privacy.get(field) == seal[field], "privacy selected another image")
    name = f"fork-release-{source}-{run}-{attempt}"
    need(seal.get("artifactName") == name, "artifact name changed")
    return {"schema": "openclaw.hosted-export.v1", "status": "passed",
            "sourceSha": source, "toolingSha": tooling, "indexDigest": index,
            "producer": seal["producer"], "artifactName": name,
            "export": "public-actions-artifact" if public_export else "none",
            "storageApprovalRecorded": storage_approved if public_export else False,
            "productionAuthorized": False}


def read_receipt(path):
    # These are fresh owned runner outputs, never a runtime/home/database path.
    p = Path(path)
    need(p.is_file() and not p.is_symlink() and p.stat().st_size <= 1024 * 1024,
         "invalid or oversized receipt")
    data = p.read_bytes()
    return json.loads(data), hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("seal", "privacy", "resources", "source-sha", "tooling-sha", "index-digest",
                 "run-id", "attempt", "output"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--public-export", choices=("true", "false"), default="false")
    parser.add_argument("--storage-approved", choices=("true", "false"), default="false")
    args = parser.parse_args()
    try:
        values = [read_receipt(getattr(args, name)) for name in ("seal", "privacy", "resources")]
        result = validate(*(v[0] for v in values), source=args.source_sha, tooling=args.tooling_sha,
                          index=args.index_digest, run=args.run_id, attempt=args.attempt,
                          public_export=args.public_export == "true",
                          storage_approved=args.storage_approved == "true")
        result["receiptSha256"] = dict(zip(("seal", "privacy", "resources"), (v[1] for v in values)))
        with Path(args.output).open("x") as output:
            output.write(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, sort_keys=True))
    except (OSError, ValueError, TypeError):
        # Do not echo untrusted receipt values or secret matches into public logs.
        raise SystemExit("Hosted export refused: incomplete, changed or unauthorized evidence") from None


if __name__ == "__main__":
    main()
