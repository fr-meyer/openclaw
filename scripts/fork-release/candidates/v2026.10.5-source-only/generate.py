#!/usr/bin/env python3
"""Derive proposed source-only seal inputs from committed evidence, without fetching."""

import argparse
import collections
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

sys.dont_write_bytecode = True
ENV = {**os.environ, "GIT_NO_LAZY_FETCH": "1", "GIT_TERMINAL_PROMPT": "0"}
SHA = re.compile(r"[0-9a-f]{40}\Z")
TEST = re.compile(r".*\.test\.[cm]?[jt]s\Z")
NON_APPLIED = {
    "RETIRED_REVIEWED": "retire",
    "UPSTREAM_EQUIVALENT_REVIEWED": "upstreamed",
}
DECISION_TESTS = {
    "apps/android/app/src/main/java/ai/openclaw/app/gateway/GatewayProtocol.kt":
        ["test/scripts/native-protocol-artifact.test.ts"],
    "apps/shared/OpenClawKit/Sources/OpenClawProtocol/GatewayModels.swift":
        ["test/scripts/native-protocol-artifact.test.ts"],
    "scripts/check-codex-app-server-protocol.ts":
        ["test/scripts/codex-app-server-protocol-source.test.ts"],
    "src/plugins/loader.runtime-metadata.test.ts":
        ["src/plugins/loader.gateway-bindings.test.ts"],
    "src/plugins/loader.runtime-registry.test.ts":
        ["src/plugins/loader.gateway-bindings.test.ts"],
    "test/scripts/full-release-validation-state.test.ts":
        ["test/scripts/full-release-validation-state.test.ts"],
    "ui/src/test-helpers/app-sidebar-cases/session-delegated-activity.ts":
        ["ui/src/components/app-sidebar.sessions.test.ts"],
}
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


def require(value, message):
    if not value:
        raise ValueError(message)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()


def boundary(path):
    """Packaging classification, not a new semantic disposition or runtime claim."""
    if path.startswith("apps/"):
        return "host"
    if TEST.fullmatch(path) or path.startswith(("test/", "custom-patches/")):
        return "tooling"
    if path.startswith("scripts/docker/runtime-plugins/") and "/test/" not in path:
        return "container"
    if path.startswith("scripts/"):
        return "tooling"
    return "container"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--tooling", type=Path, required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--pr-json", type=Path, required=True)
    parser.add_argument("--pr-observation-kind",
                        choices=("full-api-response", "public-identity-projection"),
                        default="full-api-response")
    parser.add_argument("--upstream-verification-json", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require(SHA.fullmatch(args.head), "Expected an exact source SHA")
    allowed_root = Path("/tmp/openclaw-v105-seal-prep").resolve()
    output = args.output.resolve()
    require(output == allowed_root or allowed_root in output.parents,
            "Outputs must remain under /tmp/openclaw-v105-seal-prep")
    output.mkdir(parents=True, exist_ok=True)

    def git(*argv, raw=False, root=args.source):
        result = subprocess.run(
            ["git", "-C", str(root), *argv], env=ENV, check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ).stdout
        return result if raw else result.decode().strip()

    require(git("rev-parse", "HEAD") == args.head, "Source checkout moved")
    require(not git("status", "--porcelain", "--untracked-files=all"),
            "Source checkout is not clean")
    require(not git("status", "--porcelain", "--untracked-files=all", root=args.tooling),
            "Tooling checkout is not clean")
    tooling_sha = git("rev-parse", "HEAD", root=args.tooling)
    source_manifest_raw = git("show", f"{args.head}:custom-patches/manifest.json", raw=True)
    ledger_raw = git("show", f"{args.head}:custom-patches/reconciliation-2026.10.5.json", raw=True)
    source_manifest = json.loads(source_manifest_raw)
    ledger = json.loads(ledger_raw)
    require(source_manifest["status"] == "SOURCE_ONLY_UNQUALIFIED" and
            source_manifest["productionEligible"] is False and
            source_manifest["carryForward"]["reconciliation"] == "COMPLETE_SOURCE",
            "Source preparation is not the completed source-only contract")
    base = source_manifest["upstream"]["commit"]
    prior = source_manifest["carryForward"]["v99ForkSource"]
    prior_tree = git("rev-parse", f"{prior}^{{tree}}")
    require(base == ledger["v105UpstreamCommit"] and prior == ledger["v99ForkSource"],
            "Source manifest and semantic ledger disagree")
    require(len(ledger["paths"]) == ledger["summary"]["paths"] == 92,
            "Expected the existing 92-path semantic ledger")
    decisions = {entry["path"]: entry for entry in ledger["paths"]}
    require(len(decisions) == 92, "Duplicate semantic ledger path")
    actual_dispositions = collections.Counter(entry["disposition"] for entry in ledger["paths"])
    require(dict(actual_dispositions) == ledger["summary"]["dispositions"],
            "Semantic disposition counts changed")
    require(set(actual_dispositions) <= {
        "ADAPTED_SOURCE_ONLY", "CARRIED_SOURCE_ONLY", "CARRIED_INERT_SOURCE_ONLY",
        *NON_APPLIED,
    }, "Unreviewed semantic disposition")

    pr_raw = args.pr_json.read_bytes()
    observed = json.loads(pr_raw)
    require(observed["number"] == 18 and
            observed["html_url"] == "https://github.com/fr-meyer/openclaw/pull/18" and
            observed["head"]["repo"]["full_name"] == "fr-meyer/openclaw" and
            observed["base"]["repo"]["full_name"] == "fr-meyer/openclaw",
            "Cached observation is not fork PR18")
    require(observed["head"]["ref"] == "prep/v2026.10.5-source-only",
            "Cached source branch changed")
    require(observed["head"]["sha"] == args.head and observed["state"] == "open",
            "Provided PR observation does not identify the open exact-head candidate")
    review_base = observed["base"]["sha"]
    require(review_base == base, "Provided PR base differs from the upstream source base")
    require(observed["user"]["login"] == "fr-meyer", "Unexpected regression owner")
    regression_owner = observed["user"]["login"]

    # Reuse the pipeline's canonical derivation. This is binding construction,
    # not its full preflight, whose partial-clone refusal remains intact.
    os.environ.update({"GIT_NO_LAZY_FETCH": "1", "GIT_TERMINAL_PROMPT": "0"})
    sys.path.insert(0, str(args.tooling / "scripts/fork-release"))
    pr_owner = importlib.import_module("pr")
    release = importlib.import_module("release")
    preflight = importlib.import_module("preflight")
    derived = pr_owner.derived_binding({"source": {"baseCommit": base}},
                                       args.source, args.head, review_base)
    manifest = {
        "schema": "openclaw.fork-release.v1",
        "repository": "fr-meyer/openclaw",
        "candidate": "v2026.10.5-source-only",
        "productionEligible": False,
        "source": derived["source"],
        "gates": GATES,
        "image": {"architecture": "amd64", "extensions": "codex,workboard"},
        "review": {"prNumber": 18, "baseSha": review_base,
                   "changedDiffSha256": derived["changedDiffSha256"]},
    }
    trees = {}

    def tree(commit):
        if commit not in trees:
            records = git("ls-tree", "-r", "-z", commit, raw=True).split(b"\0")
            trees[commit] = {}
            for record in records:
                if not record:
                    continue
                meta, path = record.split(b"\t", 1)
                mode, kind, oid = meta.decode().split()
                if kind == "blob":
                    trees[commit][path.decode()] = oid
        return trees[commit]

    base_paths, final_paths, prior_paths = tree(base), tree(args.head), tree(prior)
    for path, entry in decisions.items():
        require(prior_paths.get(path) == entry["v99ForkBlob"], f"Prior source differs: {path}")
        require(base_paths.get(path) == entry["v105UpstreamBlob"], f"Upstream differs: {path}")
        if entry["disposition"] in NON_APPLIED:
            require(final_paths.get(path) == base_paths.get(path),
                    f"Non-applied decision has a candidate delta: {path}")

    def path_record(path, commit):
        blob = tree(commit).get(path)
        require(blob is not None, f"Path source is unavailable: {commit}:{path}")
        return {
            "path": path, "boundary": boundary(path), "sourceCommit": commit,
            "sourceTree": git("rev-parse", f"{commit}^{{tree}}"), "sourceBlob": blob,
            "upstreamBlob": base_paths.get(path), "candidateBlob": final_paths.get(path),
        }

    all_outputs = {
        "source-preparation-manifest.json": source_manifest_raw,
        "semantic-reconciliation.json": ledger_raw,
        "pr18-observation.json": pr_raw,
    }
    upstream = source_manifest["upstream"]
    tag_raw = git("cat-file", "tag", upstream["tagObject"], raw=True)
    tag_headers = dict(line.split(" ", 1) for line in tag_raw.decode().split("\n\n", 1)[0].splitlines()
                       if " " in line)
    require(tag_headers["object"] == base and tag_headers["type"] == "commit" and
            tag_headers["tag"] == upstream["tag"], "Annotated upstream tag differs")
    require(git("rev-parse", f"{base}^{{tree}}") == upstream["tree"],
            "Upstream tree differs")
    all_outputs["upstream-tag.txt"] = tag_raw
    local_binding = {
        "schema": "openclaw.local-upstream-object-binding.v1",
        "upstream": upstream,
        "tagBytesSha256": sha256(tag_raw),
        "sourceManifestSha256": sha256(source_manifest_raw),
        "scope": "Existing local Git object binding; no fresh network or signature-verification claim.",
    }
    all_outputs["upstream-local-object-binding.json"] = encoded(local_binding)
    verification_raw = args.upstream_verification_json.read_bytes()
    verification = json.loads(verification_raw)
    require(verification["schema"] == "openclaw.upstream-tag-observation.v1" and
            verification["repository"] == "openclaw/openclaw" and
            verification["tag"] == upstream["tag"] and
            verification["tagObject"] == upstream["tagObject"] and
            verification["object"]["type"] == "commit" and
            verification["object"]["sha"] == base,
            "Provided upstream verification receipt has a different tag identity")
    signature = verification["githubVerification"]
    require(signature["verified"] is True and signature["reason"] == "valid" and
            signature["verified_at"], "Provided upstream verification receipt is not verified")
    require((signature["payload"] + signature["signature"]).encode() == tag_raw,
            "Provided verified tag payload and signature differ from the local tag object")
    all_outputs["upstream-verification.json"] = verification_raw
    patches = []
    covered_legacy = set()
    previous_id = None
    chain = derived["source"]["patches"]
    all_changed = set(git("diff", "--name-only", "--no-renames", base, args.head).splitlines())
    introduced = all_changed - set(decisions)
    for index, item in enumerate(chain):
        commit = item["commit"]
        parent = base if index == 0 else chain[index - 1]["commit"]
        changed = git("diff", "--name-only", "--no-renames", parent, commit).splitlines()
        paths = set(changed)
        # Some reviewed source intentions are retained unchanged by upstream.
        # Keep their exact decisions visible without inventing a new applied hunk.
        if index == 0:
            paths.update(path for path, decision in decisions.items()
                         if decision["disposition"] not in NON_APPLIED)
        records, retained_decisions, support = [], [], []
        for path in sorted(paths):
            decision = decisions.get(path)
            if decision and decision["disposition"] in NON_APPLIED:
                continue
            if decision:
                records.append(path_record(path, prior))
                retained_decisions.append(decision)
                covered_legacy.add(path)
            else:
                # Newly introduced paths use the exact introducing/modifying
                # commit's blob, never a fabricated historical source identity.
                source_commit = commit if path in tree(commit) else parent
                records.append(path_record(path, source_commit))
                support.append({"path": path, "sourceCommit": source_commit,
                                "basis": "Exact committed support change; no legacy disposition asserted."})
        require(records, f"Applied commit has no bound paths: {commit}")
        changed_tests = sorted(path for path in changed
                               if TEST.fullmatch(path) and path in final_paths)
        tests = changed_tests
        # This source commit changes 25 tests. The inventory schema permits 24
        # references; the CI routing owner is already represented by its dedicated
        # test. Preserve the full list in evidence without inventing another gate.
        if len(tests) > 24 and "test/vitest-projects-config.test.ts" in tests:
            tests = [path for path in tests if path != "test/vitest-projects-config.test.ts"]
        require(1 <= len(tests) <= 24, f"Focused existing test references need review: {commit}")
        evidence = {
            "schema": "openclaw.local-source-commit-evidence.v1",
            "commit": commit, "tree": item["tree"], "parent": parent,
            "commitObjectSha256": sha256(git("cat-file", "commit", commit, raw=True)),
            "subject": git("show", "-s", "--format=%s", commit),
            "changedPaths": changed,
            "semanticLedgerSha256": sha256(ledger_raw),
            "verbatimSemanticDecisions": retained_decisions,
            "introducedOrUpdatedSupport": support,
            "allChangedTestReferences": changed_tests,
            "inventoryTestReferences": tests,
            "qualification": "References only; this generator executes no tests and transfers no qualification.",
        }
        evidence_raw = encoded(evidence)
        evidence_name = f"commit-{commit[:12]}-evidence.json"
        all_outputs[evidence_name] = evidence_raw
        patch_id = f"source-{index + 1:02d}-{commit[:12]}"
        rationales = [
            f"Exact committed source adaptation: {evidence['subject']}.",
            "The commit-level adapt value records the linear applied commit; original per-path "
            "carry/adapt decisions remain verbatim below and in the evidence.",
        ]
        for decision in retained_decisions:
            rationales.append(f"{decision['path']} [{decision['disposition']}]: {decision['reason']}")
        for entry in support:
            rationales.append(f"{entry['path']}: {entry['basis']}")
        patches.append({
            "id": patch_id, "originCommit": commit, "disposition": "adapt",
            "appliedCommit": commit, "rationale": "\n".join(rationales),
            "evidenceSha256": sha256(evidence_raw),
            "regressionTests": tests, "dependsOn": [previous_id] if previous_id else [],
            "regressionOwner": regression_owner, "paths": records,
        })
        previous_id = patch_id

    for path in sorted(decisions):
        decision = decisions[path]
        if decision["disposition"] not in NON_APPLIED:
            continue
        tests = DECISION_TESTS[path]
        evidence = {
            "schema": "openclaw.local-semantic-decision-evidence.v1",
            "semanticLedgerSha256": sha256(ledger_raw),
            "verbatimSemanticDecision": decision,
            "candidateCommit": args.head,
            "pathBinding": path_record(path, prior),
            "scope": "Retained reviewed semantic decision, not an exact-upstreamed patch claim.",
            "regressionReferences": tests,
            "qualification": "References only; no tests executed by this generator.",
        }
        raw = encoded(evidence)
        decision_id = f"decision-{sha256(path.encode())[:16]}"
        all_outputs[decision_id + ".json"] = raw
        patches.append({
            "id": decision_id, "originCommit": prior,
            "disposition": NON_APPLIED[decision["disposition"]], "appliedCommit": None,
            "rationale": (f"{path} [{decision['disposition']}]: {decision['reason']} "
                          "The upstreamed enum, where used, means the ledger's reviewed semantic "
                          "equivalence; it does not claim exact patch identity."),
            "evidenceSha256": sha256(raw), "regressionTests": tests, "dependsOn": [],
            "regressionOwner": decision.get("semanticOwner", regression_owner),
            "paths": [path_record(path, prior)],
        })
        covered_legacy.add(path)

    require(covered_legacy == set(decisions), "Original semantic decisions are missing")
    covered = {record["path"] for patch in patches for record in patch["paths"]}
    require(all_changed <= covered, "Changed candidate paths are missing")
    references = {path for patch in patches for path in patch["regressionTests"]}
    require(NATIVE_NOWISTAY_TEST in references,
            "Native Nowistay SDK regression reference must remain in the inventory")
    references.update(path for lane in GATES.values() for path in lane)
    for path in sorted(references):
        require(path in final_paths, f"Regression reference absent from candidate: {path}")
    manifest_raw = encoded(manifest)
    inventory = {
        "schema": "openclaw.fork-patch-inventory.v1",
        "repository": manifest["repository"], "candidate": manifest["candidate"],
        "manifestSha256": sha256(manifest_raw),
        "upstream": {
            "tag": upstream["tag"], "tagObject": upstream["tagObject"], "commit": base,
            "verificationSha256": sha256(verification_raw),
        },
        "patches": patches,
    }
    all_outputs["manifest.json"] = manifest_raw
    all_outputs["patch-inventory.json"] = encoded(inventory)
    native_nowistay = {
        "schema": "openclaw.local-native-test-prerequisite.v1",
        "name": "Nowistay native Node SDK 1.32 compatibility",
        "required": True,
        "sourceSha": args.head,
        "sourceTree": derived["source"]["tree"],
        "testPath": NATIVE_NOWISTAY_TEST,
        "testBlob": final_paths[NATIVE_NOWISTAY_TEST],
        "command": ["node", "--test", NATIVE_NOWISTAY_TEST],
        "cwd": "Exact candidate source checkout",
        "sdk": {
            "package": "@modelcontextprotocol/sdk",
            "version": "1.32.0",
            "assertedByTest": True,
            "optionalRootOverride": "NOWISTAY_COMPAT_SDK_ROOT",
        },
        "runnerRouting": {
            "toolingSha": tooling_sha,
            "workflowPath": ".github/workflows/fork-release-pipeline.yml",
            "workflowBlob": git("rev-parse", f"{tooling_sha}:.github/workflows/fork-release-pipeline.yml",
                                root=args.tooling),
            "gateOwnerPath": "scripts/fork-release/release.py",
            "gateOwnerBlob": git("rev-parse", f"{tooling_sha}:scripts/fork-release/release.py",
                                 root=args.tooling),
            "candidateVitestEntryBlob": final_paths["scripts/run-vitest.mjs"],
            "candidateVitestImplementationBlob": final_paths["scripts/run-vitest.mts"],
            "finding": (
                "Both hosted gate steps pass release.py gates output to node scripts/run-vitest.mjs. "
                "The source entry delegates to run-vitest.mts and Vitest; it does not dispatch node:test. "
                "The Nowistay file imports node:test and must run separately with node --test."
            ),
            "vitestProducerGate": "src/agents/mcp-http-transport.test.ts",
        },
        "executionEvidenceAttached": False,
        "qualification": (
            "Required separate native-node check, retained as an inventory regression reference. "
            "No execution or passing result is asserted by this preparation; bind actual qualification "
            "evidence before treating this prerequisite as satisfied."
        ),
    }
    all_outputs["native-nowistay-prerequisite.json"] = encoded(native_nowistay)
    context = {
        "schema": "openclaw.local-source-seal-preparation.v1",
        "sourceSha": args.head, "sourceTree": derived["source"]["tree"],
        "toolingSha": tooling_sha,
        "review": manifest["review"],
        "cachedPrObservation": {
            "sha256": sha256(pr_raw), "updatedAt": observed["updated_at"],
            "kind": args.pr_observation_kind,
            "headSha": observed["head"]["sha"], "headRef": observed["head"]["ref"],
            "baseSha": review_base, "baseRef": observed["base"]["ref"],
            "state": observed["state"], "draft": observed["draft"],
        },
        "cachedHeadMatchesCandidate": observed["head"]["sha"] == args.head,
        "prObservationExactHeadVerified": True,
        "observationProvenance": (
            f"Provided native GitHub CLI API {args.pr_observation_kind}; the generator validates "
            "its exact identity and retains the provided bytes unchanged. A public identity "
            "projection is selected API fields, not the full raw response. updatedAt is "
            "the PR update time, not a fetch time. "
            "This generator makes no fresh API or signature-verification call."
        ),
        "upstreamVerification": {
            "sha256": sha256(verification_raw),
            "verified": signature["verified"], "reason": signature["reason"],
            "verifiedAt": signature["verified_at"],
            "payloadAndSignatureMatchLocalTag": True,
        },
        "originalSemanticPaths": len(decisions),
        "originalDispositionCounts": dict(actual_dispositions),
        "candidateChangedPaths": len(all_changed),
        "introducedPaths": sorted(introduced),
        "coveredDistinctPaths": len(covered),
        "appliedCommitCount": len(chain),
        "nonAppliedDecisionCount": sum(x["appliedCommit"] is None for x in patches),
        "referencedTestCount": len(references),
        "separateNativePrerequisites": [{
            "file": "native-nowistay-prerequisite.json",
            "sha256": sha256(all_outputs["native-nowistay-prerequisite.json"]),
            "required": True,
        }],
        "execution": "No candidate code or tests executed; no fetch or cloud operation.",
        "remaining": [
            "Recheck PR18 exact head/base at the later release admission boundary.",
            "Full existing source preflight must run on an ordinary non-promisor checkout.",
            "Bind separate node --test Nowistay SDK 1.32 qualification evidence; Vitest gates do not satisfy it.",
            "Image build, native Doctor, readiness, and rollback remain separate qualification.",
        ],
    }
    all_outputs["preparation-context.json"] = encoded(context)
    for name, raw in all_outputs.items():
        target = output / name
        target.write_bytes(raw)
        target.chmod(0o600)
    # Validate construction using the established metadata owner only.
    loaded, manifest_hash = release.manifest_at(output / "manifest.json")
    checks = preflight.Checks()
    preflight.inventory_checks(checks, inventory, loaded, manifest_hash)
    require(not checks.errors, "Metadata refusal: " + ", ".join(checks.errors))
    hash_manifest = {name: sha256(raw) for name, raw in sorted(all_outputs.items())}
    hash_path = output / "sha256.json"
    hash_path.write_bytes(encoded(hash_manifest))
    hash_path.chmod(0o600)
    print(json.dumps({key: context[key] for key in [
        "sourceSha", "sourceTree", "appliedCommitCount", "originalSemanticPaths",
        "candidateChangedPaths", "coveredDistinctPaths", "nonAppliedDecisionCount",
        "cachedHeadMatchesCandidate",
    ]}, indent=2))


if __name__ == "__main__":
    main()
