#!/usr/bin/env python3
"""Derive the frozen 10.6 merge proposal from local objects and retained observations."""

import argparse
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

sys.dont_write_bytecode = True
ENV = {**os.environ, "GIT_NO_LAZY_FETCH": "1", "GIT_NO_REPLACE_OBJECTS": "1",
       "GIT_TERMINAL_PROMPT": "0"}
HEAD = "a39cad2d97efae7d0c832af3d71e6ccc86f60e50"
TREE = "47a3c1321ce39b50d22ec092054e54fd0afaa03a"
COMMON = "1b58cb9a1b4f4353e1add63c8506db4d890962e8"
COMMON_TREE = "a138559698570e238395121723a773106ac33f8c"
FORK = "7f3ac1fbfd3691546c5b1fd247680a3d00851c76"
FORK_TREE = "ebd66baae19b34b604e166dff5075beec79592de"
UPSTREAM = "fe06181dc5ecc01cf8904abbfc26925925efefbc"
UPSTREAM_TREE = "de35137f62064ebdfd93c7d146b78b05a0332ff1"
TAG = "v2026.10.6"
TAG_OBJECT = "3494baecba2366a89fa703158a2c2b5c9edcd6ba"
LEDGER_PATH = "custom-patches/reconciliation-2026.10.6.json"
LEDGER_BLOB = "186abc747081b09b8f7af58a37513b170af1f4b4"
LEDGER_SHA256 = "c323daa5425d329578a392313de7677618d4fe5150ee8af399b75bd229bcf516"
SUPPORT_PATHS = {LEDGER_PATH, "custom-patches/NEXT-RELEASE-2026.10.6.md"}
TEST = re.compile(r".*\.test\.[cm]?[jt]s\Z")
GATES = {
    "patchLifecycle": [
        "src/agents/worktrees/run-lease.test.ts",
        "src/secrets/egress-proxy/proxy-forward.test.ts",
    ],
    "producerConsumer": [
        "src/tasks/managed-task-flow.worker.integration.test.ts",
        "src/agents/mcp-http-transport.test.ts",
    ],
}
NATIVE_NOWISTAY_TEST = "test/mcp-nowistay-sdk-regression.test.mjs"
REGRESSION_REFERENCES = [
    "src/commands/doctor-migration-backup.test.ts",
    "src/commands/doctor-agent-deletion-journal-restore.test.ts",
    "src/commands/doctor-original-capture.test.ts",
    "src/cli/gateway-cli/register.option-collisions.test.ts",
    "src/gateway/server-managed-task-flow-runtime.mergeguez-parity.test.ts",
    "src/gateway/server-managed-task-flow-runtime.mergeguez-recovery.test.ts",
    "src/agents/worktrees/run-lease.test.ts",
    "src/secrets/egress-proxy/proxy-forward.test.ts",
    "src/secrets/egress-proxy/response-headers.test.ts",
    "extensions/workboard/src/store.test.ts",
    "packages/memory-host-sdk/src/host/memory-schema-storage-migration.test.ts",
    NATIVE_NOWISTAY_TEST,
]


def require(value, message):
    if not value:
        raise ValueError(message)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()


def boundary(path):
    """Packaging classification; the original semantic decisions remain separate."""
    if path.startswith("apps/"):
        return "host"
    if TEST.fullmatch(path) or path.startswith(("test/", "custom-patches/")):
        return "tooling"
    if path.startswith("scripts/docker/runtime-plugins/") and "/test/" not in path:
        return "container"
    return "tooling" if path.startswith("scripts/") else "container"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--tooling", type=Path, required=True)
    parser.add_argument("--head", default=HEAD)
    parser.add_argument("--pr-json", type=Path, required=True)
    parser.add_argument("--pr-observation-kind",
                        choices=("full-api-response", "public-identity-projection", "connector-pr-info"),
                        default="public-identity-projection")
    parser.add_argument("--upstream-verification-json", type=Path, required=True)
    parser.add_argument("--upstream-observation-kind",
                        choices=("tag-observation", "github-api-response"), default="tag-observation")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require(args.head == HEAD, "This proposal is frozen to the reviewed a39 merge")
    allowed_root = Path("/tmp/openclaw-v106-seal-prep").resolve()
    output = args.output.resolve()
    require(output == allowed_root or allowed_root in output.parents,
            "Outputs must remain under /tmp/openclaw-v106-seal-prep")
    require(not output.exists(), "Use a new output directory; preserve prior proposal bytes")

    def git(*argv, raw=False, root=args.source):
        result = subprocess.run(
            ["git", "--no-replace-objects", "-C", str(root), *argv], env=ENV,
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ).stdout
        return result if raw else result.decode().strip()

    require(git("rev-parse", "HEAD") == HEAD, "Source checkout moved")
    for name, root in (("Source", args.source), ("Tooling", args.tooling)):
        require(not git("status", "--porcelain", "--untracked-files=all", root=root),
                f"{name} checkout is not clean")
    tooling_sha = git("rev-parse", "HEAD", root=args.tooling)
    ledger_raw = git("show", f"{HEAD}:{LEDGER_PATH}", raw=True)
    require(git("rev-parse", f"{HEAD}:{LEDGER_PATH}") == LEDGER_BLOB and
            sha256(ledger_raw) == LEDGER_SHA256, "Committed reconciliation changed")
    ledger = json.loads(ledger_raw)
    require(ledger["upstream105"] == COMMON and ledger["fork105"] == FORK and
            ledger["upstream106"] == UPSTREAM and ledger["qualificationTransferred"] is False,
            "Reconciliation source identities changed")
    decisions = {entry["path"]: entry for entry in ledger["paths"]}
    require(len(decisions) == len(ledger["paths"]) == ledger["summary"]["paths"] == 142,
            "Expected the complete 142-path fork reconciliation")

    pr_raw = args.pr_json.read_bytes()
    observed = json.loads(pr_raw)
    if args.pr_observation_kind == "connector-pr-info":
        require(observed["url"] == "https://github.com/fr-meyer/openclaw/pull/19" and
                observed["head_repo_full_name"] == "fr-meyer/openclaw",
                "Connector observation is not fork PR19")
        # The connector names the base branch of the PR repository in its URL;
        # this is a local identity adapter, not an invented raw API observation.
        pr_identity = {
            "number": observed["number"], "html_url": observed["url"],
            "state": observed["state"], "draft": observed["draft"],
            "updated_at": observed["updated_at"], "user": observed["user"],
            "head": {"ref": observed["head"], "sha": observed["head_sha"],
                     "repo": {"full_name": observed["head_repo_full_name"]}},
            "base": {"ref": observed["base"], "sha": observed["base_sha"],
                     "repo": {"full_name": "fr-meyer/openclaw"}},
        }
    else:
        pr_identity = observed
    observed = pr_identity
    require(observed["number"] == 19 and
            observed["html_url"] == "https://github.com/fr-meyer/openclaw/pull/19" and
            observed["head"]["repo"]["full_name"] == "fr-meyer/openclaw" and
            observed["base"]["repo"]["full_name"] == "fr-meyer/openclaw",
            "Observation is not fork PR19")
    require(observed["head"]["ref"] == "prep/v2026.10.6-next-group" and
            observed["base"]["ref"] == "prep/v2026.10.5-source-only" and
            observed["head"]["sha"] == HEAD and observed["base"]["sha"] == FORK and
            observed["state"] == "open", "PR observation differs from the frozen source/base")
    require(observed["user"]["login"] == "fr-meyer", "Unexpected regression owner")

    tag_raw = git("cat-file", "tag", TAG_OBJECT, raw=True)
    tag_headers = dict(line.split(" ", 1) for line in tag_raw.decode().split("\n\n", 1)[0].splitlines()
                       if " " in line)
    require(tag_headers.get("object") == UPSTREAM and tag_headers.get("type") == "commit" and
            tag_headers.get("tag") == TAG, "Annotated upstream tag differs")
    verification_raw = args.upstream_verification_json.read_bytes()
    verification = json.loads(verification_raw)
    if args.upstream_observation_kind == "github-api-response":
        require(verification["url"] ==
                f"https://api.github.com/repos/openclaw/openclaw/git/tags/{TAG_OBJECT}" and
                verification["sha"] == TAG_OBJECT, "Raw tag API observation has a different identity")
        signature = verification["verification"]
    else:
        require(verification["schema"] == "openclaw.upstream-tag-observation.v1" and
                verification["repository"] == "openclaw/openclaw" and
                verification["tagObject"] == TAG_OBJECT,
                "Wrapped upstream observation has a different identity")
        signature = verification["githubVerification"]
    require(verification["tag"] == TAG and
            verification["object"]["type"] == "commit" and
            verification["object"]["sha"] == UPSTREAM,
            "Upstream observation has a different tag identity")
    require(signature["verified"] is True and signature["reason"] == "valid" and
            signature["verified_at"], "Upstream observation lacks verified signature evidence")
    require((signature["payload"] + signature["signature"]).encode() == tag_raw,
            "Observed signed tag bytes differ from the local annotated tag")

    source = {
        "baseCommit": UPSTREAM, "baseTree": UPSTREAM_TREE,
        "patches": [{"commit": HEAD, "tree": TREE}], "commit": HEAD, "tree": TREE,
        "merge": {
            "commonCommit": COMMON, "commonTree": COMMON_TREE,
            "forkCommit": FORK, "forkTree": FORK_TREE,
            "reconciliation": {"path": LEDGER_PATH, "blob": LEDGER_BLOB, "sha256": LEDGER_SHA256},
        },
    }
    # The shared owner verifies ordered parents, ancestry and the full ledger.
    # Derivation does not bypass the full preflight's promisor-checkout refusal.
    os.environ.update({key: ENV[key] for key in (
        "GIT_NO_LAZY_FETCH", "GIT_NO_REPLACE_OBJECTS", "GIT_TERMINAL_PROMPT")})
    sys.path.insert(0, str(args.tooling / "scripts/fork-release"))
    pr_owner = importlib.import_module("pr")
    release = importlib.import_module("release")
    preflight = importlib.import_module("preflight")
    derived = pr_owner.derived_binding({"source": source}, args.source, HEAD, FORK)
    require(derived["source"] == source, "Shared source derivation changed the frozen merge")
    manifest = {
        "schema": "openclaw.fork-release.v1", "repository": "fr-meyer/openclaw",
        "candidate": "v2026.10.6-source-only", "productionEligible": False,
        "source": source, "gates": GATES,
        "image": {"architecture": "amd64", "extensions": "codex,workboard"},
        "review": {"prNumber": 19, "baseSha": FORK,
                   "changedDiffSha256": derived["changedDiffSha256"]},
    }
    trees = {}

    def tree(commit):
        if commit not in trees:
            trees[commit] = {}
            for record in git("ls-tree", "-r", "-z", commit, raw=True).split(b"\0"):
                if record:
                    meta, path = record.split(b"\t", 1)
                    mode, kind, oid = meta.decode().split()
                    require(kind == "blob", "Candidate inventory does not support gitlink entries")
                    trees[commit][path.decode()] = {"mode": mode, "type": kind, "blob": oid}
        return trees[commit]

    def blob(commit, path):
        record = tree(commit).get(path)
        return record["blob"] if record else None

    all_changed = set(git("diff", "--name-only", "--no-renames", UPSTREAM, HEAD).splitlines())
    require(len(all_changed) == 144 and all_changed == set(decisions) | SUPPORT_PATHS,
            "Expected 142 fork paths plus the two explicit release evidence paths")
    records = []
    for path in sorted(all_changed):
        # Historical fork bytes remain the source where present; deleted paths
        # bind their common original, and new release metadata binds the merge.
        origin = FORK if path in decisions and blob(FORK, path) else COMMON
        if path in SUPPORT_PATHS:
            origin = HEAD
        require(blob(origin, path), f"Historical source blob is unavailable: {path}")
        records.append({
            "path": path, "boundary": boundary(path), "sourceCommit": origin,
            "sourceTree": git("rev-parse", f"{origin}^{{tree}}"), "sourceBlob": blob(origin, path),
            "upstreamBlob": blob(UPSTREAM, path), "candidateBlob": blob(HEAD, path),
        })
    references = set(REGRESSION_REFERENCES) | {path for lane in GATES.values() for path in lane}
    for path in sorted(references):
        require(path in tree(HEAD), f"Regression reference absent from candidate: {path}")
    merge_evidence = {
        "schema": "openclaw.local-merge-source-evidence.v1",
        "source": source, "orderedParents": [FORK, UPSTREAM],
        "commitObjectSha256": sha256(git("cat-file", "commit", HEAD, raw=True)),
        "reconciliationSha256": LEDGER_SHA256,
        "originalForkPathCount": len(decisions), "candidateChangedPaths": sorted(all_changed),
        "additionalReleaseEvidencePaths": sorted(SUPPORT_PATHS),
        "carryForwardCommits": ledger["carryForwardCommits"],
        "prChangedDiffSha256": derived["changedDiffSha256"],
        "regressionReferences": REGRESSION_REFERENCES,
        "qualification": "Source binding and references only; no tests or image qualification transferred.",
    }
    evidence_raw = encoded(merge_evidence)
    manifest_raw = encoded(manifest)
    inventory = {
        "schema": "openclaw.fork-patch-inventory.v1", "repository": manifest["repository"],
        "candidate": manifest["candidate"], "manifestSha256": sha256(manifest_raw),
        "upstream": {"tag": TAG, "tagObject": TAG_OBJECT, "commit": UPSTREAM,
                     "verificationSha256": sha256(verification_raw)},
        "patches": [{
            "id": "merge-2026.10.6-a39cad2d97ef", "originCommit": FORK,
            "disposition": "adapt", "appliedCommit": HEAD,
            "rationale": "One reviewed two-parent integration. The adapt value identifies the merge, "
                         "not a replacement classification for the 142 original per-path decisions; "
                         "those remain unchanged in semantic-reconciliation.json.",
            "evidenceSha256": sha256(evidence_raw), "regressionTests": REGRESSION_REFERENCES,
            "dependsOn": [], "regressionOwner": observed["user"]["login"], "paths": records,
        }],
    }
    context = {
        "schema": "openclaw.local-source-seal-preparation.v1",
        "sourceSha": HEAD, "sourceTree": TREE, "toolingSha": tooling_sha,
        "review": manifest["review"], "productionEligible": False,
        "cachedPrObservation": {
            "sha256": sha256(pr_raw), "kind": args.pr_observation_kind,
            "updatedAt": observed["updated_at"], "headSha": HEAD, "baseSha": FORK,
            "state": observed["state"], "draft": observed["draft"],
        },
        "upstreamVerification": {
            "sha256": sha256(verification_raw), "kind": args.upstream_observation_kind,
            "verified": signature["verified"],
            "reason": signature["reason"], "verifiedAt": signature["verified_at"],
            "payloadAndSignatureMatchLocalTag": True,
        },
        "observationProvenance": "Supplied observations retained unchanged. PR updatedAt is not "
                                 "a fetch timestamp. No fresh API or signature-verification call.",
        "originalForkPaths": 142, "candidateChangedPaths": 144, "appliedIntegrationCount": 1,
        "execution": "No candidate code or tests executed; no fetch, GCP operation or database access.",
        "remaining": [
            "Recheck live PR19 exact head/base and upstream identity at admission.",
            "Run full source preflight on an ordinary non-promisor checkout; this is construction only.",
            "Bind existing exact-source fixture receipts; references alone are not passing evidence.",
            "Qualify the 10.6 Dockerfile/build profile and immutable image/native plugin checks.",
            "Qualify the image-bound rehearsal executor; retain future 320/128 MiB/s I/O profile.",
            "No cross-version backup reuse is qualified; do not widen the reviewed 10.5 reuse allowlist.",
            "Native Doctor, lost-journal process fixture requiring dist/entry.js, and startup remain pending.",
        ],
    }
    outputs = {
        "manifest.json": manifest_raw, "patch-inventory.json": encoded(inventory),
        "semantic-reconciliation.json": ledger_raw, "merge-source-evidence.json": evidence_raw,
        "pr19-observation.json": pr_raw, "upstream-verification.json": verification_raw,
        "upstream-tag.txt": tag_raw, "preparation-context.json": encoded(context),
        "native-nowistay-prerequisite.json": encoded({
            "schema": "openclaw.local-native-test-prerequisite.v1", "sourceSha": HEAD,
            "sourceTree": TREE, "required": True, "testPath": NATIVE_NOWISTAY_TEST,
            "testBlob": blob(HEAD, NATIVE_NOWISTAY_TEST),
            "command": ["node", "--test", NATIVE_NOWISTAY_TEST],
            "sdk": {"package": "@modelcontextprotocol/sdk", "version": "1.32.0"},
            "executionEvidenceAttached": False,
            "qualification": "Bind the separate native-node receipt; Vitest does not run node:test.",
        }),
    }
    # Validate with the existing metadata owner; no full source-preflight claim.
    checks = preflight.Checks()
    preflight.inventory_checks(checks, inventory, manifest, sha256(manifest_raw))
    require(not checks.errors, "Metadata refusal: " + ", ".join(checks.errors))
    output.mkdir(parents=True, exist_ok=False)
    for name, raw in outputs.items():
        target = output / name
        target.write_bytes(raw)
        target.chmod(0o600)
    release.manifest_at(output / "manifest.json")
    hash_path = output / "sha256.json"
    hash_path.write_bytes(encoded({name: sha256(raw) for name, raw in sorted(outputs.items())}))
    hash_path.chmod(0o600)
    print(json.dumps({"sourceSha": HEAD, "sourceTree": TREE, "toolingSha": tooling_sha,
                      "forkPaths": 142, "coveredPaths": 144, "output": str(output),
                      "productionEligible": False}, indent=2))


if __name__ == "__main__":
    main()
