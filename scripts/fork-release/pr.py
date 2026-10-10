#!/usr/bin/env python3
"""Read-only PR intent, exact-head evidence, and changed-diff reuse checks."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from urllib.request import Request, urlopen

from release import Refusal, SHA, manifest_at, matches, need, sha256

LOGIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\Z")
BRANCH = re.compile(r"[A-Za-z0-9._/-]{1,128}\Z")
MARKER = re.compile(r"<!-- fork-task-intent-v1\s*(\{[^<>]*\})\s*-->", re.DOTALL)
EVENTS = {"opened", "reopened", "synchronize", "ready_for_review", "converted_to_draft",
          "edited", "assigned", "unassigned"}
WORKFLOW = ".github/workflows/fork-release-pipeline.yml"
FORK_DRAFT_GUARD = re.compile(
    r"github\.repository != 'fr-meyer/openclaw'\s*\|\|\s*"
    r"github\.event_name != 'pull_request_target'\s*\|\|\s*"
    r"github\.event\.pull_request\.draft == false"
)


def git(root, *args, binary=False):
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, check=True)
    return result.stdout if binary else result.stdout.decode().strip()


def intent_from_body(body):
    need(isinstance(body, str), "missing PR body")
    found = MARKER.findall(body)
    need(len(found) == 1, "PR body needs one fork-task-intent-v1 declaration")
    try:
        intent = json.loads(found[0])
    except json.JSONDecodeError as error:
        raise Refusal("invalid PR intent JSON") from error
    need(type(intent) is dict and set(intent) == {"kind", "owner", "target", "scope", "dependsOn"}, "invalid PR intent fields")
    need(intent["kind"] in ("task", "release"), "invalid PR kind")
    need(matches(LOGIN, intent["owner"]), "invalid PR owner")
    need(matches(BRANCH, intent["target"]) and ".." not in intent["target"].split("/"), "invalid PR target")
    need(intent["kind"] != "release" or intent["target"] == "main", "release PR must target fork main")
    need(type(intent["scope"]) is str and 1 <= len(intent["scope"]) <= 240 and all(character not in intent["scope"] for character in "\n<>"), "invalid PR scope")
    dependencies = intent["dependsOn"]
    need(type(dependencies) is list and len(dependencies) <= 8, "too many PR dependencies")
    numbers = set()
    for dependency in dependencies:
        need(type(dependency) is dict and set(dependency) == {"number", "headSha"}, "invalid dependency declaration")
        need(type(dependency["number"]) is int and dependency["number"] > 0 and matches(SHA, dependency["headSha"]), "invalid dependency identity")
        need(dependency["number"] not in numbers, "duplicate PR dependency")
        numbers.add(dependency["number"])
    return intent


def event_identity(event, intent):
    pr = event.get("pull_request")
    need(type(pr) is dict and event.get("action") in EVENTS, "unsupported PR event")
    need(event.get("repository", {}).get("full_name") == "fr-meyer/openclaw", "wrong PR repository")
    head, base = pr.get("head", {}), pr.get("base", {})
    need(head.get("repo", {}).get("full_name") == "fr-meyer/openclaw", "external PR head is not admitted")
    need(base.get("repo", {}).get("full_name") == "fr-meyer/openclaw", "wrong PR base repository")
    need(matches(SHA, head.get("sha")) and matches(SHA, base.get("sha")), "invalid PR head/base")
    need(type(pr.get("number")) is int and pr["number"] > 0, "invalid PR number")
    need(type(pr.get("draft")) is bool, "missing PR draft state")
    need(base.get("ref") == intent["target"], "PR target differs from declared target")
    need(pr.get("user", {}).get("login") == intent["owner"] or intent["owner"] in
         {item.get("login") for item in pr.get("assignees", [])}, "declared owner is not PR author or assignee")
    prefix = "candidate/" if intent["kind"] == "release" else "task/"
    need(isinstance(head.get("ref"), str) and head["ref"].startswith(prefix), "PR branch has wrong task kind")
    need(pr["number"] not in {item["number"] for item in intent["dependsOn"]}, "PR depends on itself")
    return pr, head, base


def intake(event, run):
    intent = intent_from_body(event.get("pull_request", {}).get("body"))
    pr, head, base = event_identity(event, intent)
    need(matches(SHA, run.get("workflowSha")), "invalid workflow identity")
    need(all(type(run.get(key)) is int and run[key] > 0 for key in ("runId", "attempt", "checkRunId")), "invalid check identity")
    return {
        "schema": "openclaw.fork-task-pr-evidence.v1",
        "repository": "fr-meyer/openclaw",
        "prNumber": pr["number"],
        "kind": intent["kind"],
        "owner": intent["owner"],
        "scope": intent["scope"],
        "target": intent["target"],
        "dependsOn": intent["dependsOn"],
        "draft": pr["draft"],
        "headRef": head["ref"],
        "headSha": head["sha"],
        "baseSha": base["sha"],
        "run": run,
    }


def release_seal(evidence, manifest_path, checkout):
    need(evidence["kind"] == "release", "only candidate PRs have release seals")
    manifest, manifest_hash = manifest_at(manifest_path)
    validate_binding(manifest_path, checkout)
    review = manifest.get("review")
    need(review is not None and review["prNumber"] == evidence["prNumber"] and review["baseSha"] == evidence["baseSha"], "manifest PR/base differs from event")
    need(git(checkout, "rev-parse", "HEAD") == evidence["headSha"], "checkout is not the PR head")
    need(git(checkout, "show", "-s", "--format=%P", "HEAD") == manifest["source"]["commit"], "PR head must be a single manifest seal commit")
    changed = git(checkout, "diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD").splitlines()
    need(changed == ["scripts/fork-release/manifest.json"], "seal commit changes more than the manifest")
    need(git(checkout, "cat-file", "-t", evidence["baseSha"]) == "commit", "PR base commit is unavailable")
    product_diff = git(checkout, "diff", "--binary", "--full-index", "--no-ext-diff",
                       evidence["baseSha"], manifest["source"]["commit"], binary=True)
    changed_digest = sha256(product_diff)
    need(changed_digest == review["changedDiffSha256"], "changed product diff differs from manifest")
    return {**evidence, "sourceSha": manifest["source"]["commit"],
            "sourceTree": manifest["source"]["tree"], "manifestSha256": manifest_hash,
            "changedDiffSha256": changed_digest}


def offline_release_seal(manifest_path, checkout):
    manifest, _ = manifest_at(manifest_path)
    review = manifest.get("review")
    need(review is not None, "candidate manifest has no PR review binding")
    head_sha = git(checkout, "rev-parse", "HEAD")
    return release_seal({"kind": "release", "prNumber": review["prNumber"],
                         "baseSha": review["baseSha"], "headSha": head_sha},
                        manifest_path, checkout)


def derived_binding(manifest, checkout, source_sha, base_sha):
    """Derive the complete linear source chain and PR diff from local Git objects."""
    need(matches(SHA, source_sha) and matches(SHA, base_sha), "invalid source or PR base")
    source_base = manifest["source"]["baseCommit"]
    for commit in (source_base, source_sha, base_sha):
        need(git(checkout, "cat-file", "-t", commit) == "commit", "binding commit is unavailable")
    chain = git(checkout, "rev-list", "--reverse", f"{source_base}..{source_sha}").splitlines()
    need(1 <= len(chain) <= 64, "binding patch chain is empty or exceeds 64 commits")
    parent = source_base
    patches = []
    for commit in chain:
        need(git(checkout, "show", "-s", "--format=%P", commit) == parent,
             "binding patch chain is not linear from source base")
        patches.append({"commit": commit, "tree": git(checkout, "rev-parse", f"{commit}^{{tree}}")})
        parent = commit
    need(parent == source_sha, "binding source is outside patch chain")
    product_diff = git(checkout, "diff", "--binary", "--full-index", "--no-ext-diff",
                       base_sha, source_sha, binary=True)
    return {"source": {"baseCommit": source_base,
                       "baseTree": git(checkout, "rev-parse", f"{source_base}^{{tree}}"),
                       "patches": patches, "commit": source_sha,
                       "tree": patches[-1]["tree"]},
            "changedDiffSha256": sha256(product_diff)}


def generate_binding(manifest_path, checkout, candidate, pr_number, base_sha):
    """Generate a proposed manifest; never silently rebind another candidate or PR."""
    manifest = json.loads(Path(manifest_path).read_text())
    need(type(manifest) is dict and manifest.get("candidate") == candidate,
         "candidate identity differs from requested binding")
    need(type(pr_number) is int and pr_number > 0 and matches(SHA, base_sha),
         "invalid PR binding identity")
    old = manifest.get("review")
    need(old is None or (old.get("prNumber") == pr_number and old.get("baseSha") == base_sha),
         "existing PR/base binding cannot be silently changed")
    source_sha = git(checkout, "rev-parse", "HEAD")
    derived = derived_binding(manifest, checkout, source_sha, base_sha)
    manifest["source"] = derived["source"]
    manifest["review"] = {"prNumber": pr_number, "baseSha": base_sha,
                          "changedDiffSha256": derived["changedDiffSha256"]}
    return manifest


def validate_binding(manifest_path, checkout):
    manifest, manifest_hash = manifest_at(manifest_path)
    review = manifest.get("review")
    need(review is not None, "candidate manifest has no PR review binding")
    derived = derived_binding(manifest, checkout, manifest["source"]["commit"], review["baseSha"])
    need(manifest["source"] == derived["source"], "source binding is stale")
    need(review["changedDiffSha256"] == derived["changedDiffSha256"], "changed diff binding is stale")
    return {"candidate": manifest["candidate"], "prNumber": review["prNumber"],
            "baseSha": review["baseSha"], "sourceSha": manifest["source"]["commit"],
            "sourceTree": manifest["source"]["tree"],
            "changedDiffSha256": derived["changedDiffSha256"], "manifestSha256": manifest_hash}


def opening_preflight(base_checkout, base_sha):
    """Refuse a draft-opening plan until the exact base has the fork guard."""
    need(matches(SHA, base_sha) and git(base_checkout, "rev-parse", "HEAD") == base_sha,
         "opening preflight checkout differs from declared PR base")
    try:
        dispatcher = git(base_checkout, "show", "HEAD:.github/workflows/clawsweeper-dispatch.yml")
        security = git(base_checkout, "show", "HEAD:.github/workflows/security-review.yml")
    except subprocess.CalledProcessError as error:
        raise Refusal("opening preflight lacks base workflows") from error
    section = dispatcher.partition("jobs:\n  dispatch:")[2].partition("    steps:")[0]
    admission = re.search(r"(?m)^    if: >-\n((?:      .*\n)+)", section)
    need(admission is not None and FORK_DRAFT_GUARD.search(admission.group(1)) and
         "ready_for_review" in dispatcher.partition("jobs:")[0],
         "base ClawSweeper workflow can dispatch a fork draft PR")
    need("pull_request_target:" in security.partition("jobs:")[0] and
         "statuses: write" in security and "pull-requests: write" in security,
         "base security review gate is missing")
    return {"repository": "fr-meyer/openclaw", "baseSha": base_sha,
            "forkDraftExternalDispatch": "blocked_by_base_guard",
            "readyForReviewDispatch": "retained", "securityReview": "retained"}


def reusable_changed_diff(previous, current):
    for evidence in (previous, current):
        need(evidence.get("schema") == "openclaw.fork-task-pr-evidence.v1" and evidence.get("kind") == "release", "invalid release review evidence")
    return all(previous.get(key) == current.get(key) for key in
               ("repository", "prNumber", "baseSha", "sourceTree", "changedDiffSha256"))


def template(kind, owner, target, scope, dependencies):
    declared = []
    for item in dependencies:
        number, separator, head_sha = item.partition(":")
        need(separator == ":" and number.isdecimal(), "dependency must be NUMBER:HEAD_SHA")
        declared.append({"number": int(number), "headSha": head_sha})
    intent = {"kind": kind, "owner": owner, "target": target,
              "scope": scope, "dependsOn": declared}
    marker = f"<!-- fork-task-intent-v1\n{json.dumps(intent, sort_keys=True)}\n-->"
    intent_from_body(marker)
    return (f"## Scope\n\n{scope}\n\n## Owner and dependencies\n\n"
            f"Owner: @{owner}\n\nDependencies: "
            + (", ".join(f"#{item['number']} at `{item['headSha']}`" for item in declared) if declared else "None")
            + "\n\n## Review\n\nTrack this work in one draft PR. Record the exact head/base check run, "
              "review the changed diff, and resolve dependencies before merge. "
              "Main or master merge always needs an explicit user decision.\n\n" + marker + "\n")


def assess_current(evidence, pr, reviews, run, jobs, dependencies=()):
    need(evidence.get("schema") == "openclaw.fork-task-pr-evidence.v1", "invalid PR evidence")
    need(pr.get("number") == evidence["prNumber"] and pr.get("state") == "open", "PR is no longer open")
    current_intent = intent_from_body(pr.get("body"))
    need(all(current_intent[key] == evidence.get(key) for key in
             ("kind", "owner", "target", "scope", "dependsOn")),
         "PR intent changed after the exact check")
    need(pr.get("head", {}).get("sha") == evidence["headSha"] and pr.get("base", {}).get("sha") == evidence["baseSha"], "PR head/base advanced")
    need(pr.get("head", {}).get("ref") == evidence["headRef"] and pr.get("base", {}).get("ref") == evidence["target"], "PR branch or target changed")
    need(pr.get("head", {}).get("repo", {}).get("full_name") == evidence["repository"] and pr.get("base", {}).get("repo", {}).get("full_name") == evidence["repository"], "PR repository changed")
    owner = evidence["owner"]
    need(pr.get("user", {}).get("login") == owner or owner in {item.get("login") for item in pr.get("assignees", [])}, "declared owner is not PR author or assignee")
    need(run.get("id") == evidence["run"]["runId"] and run.get("run_attempt") == evidence["run"]["attempt"], "check run identity changed")
    need(run.get("event") == "pull_request" and run.get("conclusion") == "success", "PR check run is not successful")
    need(run.get("repository", {}).get("full_name") == evidence["repository"], "check run repository changed")
    need(run.get("head_branch") == evidence["headRef"], "check run branch changed")
    need(WORKFLOW in run.get("path", ""), "wrong PR check workflow")
    expected_url = f"https://api.github.com/repos/{evidence['repository']}/check-runs/{evidence['run']['checkRunId']}"
    matching = [job for job in jobs if job.get("check_run_url") == expected_url]
    need(len(matching) == 1 and matching[0].get("conclusion") == "success", "exact PR check is not successful")
    latest = {}
    for review in sorted(reviews, key=lambda item: (item.get("submitted_at") or "", item.get("id") or 0)):
        user = review.get("user", {}).get("login")
        if user:
            latest[user] = review
    need(not any(review.get("state") == "CHANGES_REQUESTED" for review in latest.values()), "outstanding change request")
    need(any(review.get("state") == "APPROVED" and review.get("commit_id") == evidence["headSha"] for review in latest.values()), "no current-head approval")
    dependency_map = {item.get("number"): item for item in dependencies}
    for declared in evidence["dependsOn"]:
        dependency = dependency_map.get(declared["number"])
        need(dependency is not None and dependency.get("head", {}).get("sha") == declared["headSha"], "dependency head changed or is unverified")
        need(dependency.get("base", {}).get("ref") == evidence["target"] and dependency.get("base", {}).get("repo", {}).get("full_name") == evidence["repository"], "dependency merged toward another target")
        need(dependency.get("merged_at") is not None and dependency.get("state") == "closed", "dependency is not merged")
    return {"schema": "openclaw.fork-task-pr-assessment.v1",
            "repository": evidence["repository"], "prNumber": evidence["prNumber"],
            "headSha": evidence["headSha"], "baseSha": evidence["baseSha"],
            "sourceSha": evidence.get("sourceSha"), "sourceTree": evidence.get("sourceTree"),
            "changedDiffSha256": evidence.get("changedDiffSha256"),
            "runId": evidence["run"]["runId"], "attempt": evidence["run"]["attempt"],
            "checkRunId": evidence["run"]["checkRunId"], "reviewState": "approved_exact_head",
            "diffReviewReusable": evidence.get("changedDiffSha256") is not None,
            "mergeAuthorized": False}


def fetch_public_json(path):
    need(path.startswith("repos/fr-meyer/openclaw/"), "API path escaped fork")
    request = Request("https://api.github.com/" + path,
                      headers={"Accept": "application/vnd.github+json",
                               "User-Agent": "openclaw-fork-release-readonly",
                               "X-GitHub-Api-Version": "2022-11-28"})
    with urlopen(request, timeout=8) as response:
        raw = response.read(2_000_001)
    need(len(raw) <= 2_000_000, "GitHub response exceeds bound")
    return json.loads(raw)


def pages(fetch, path, key=None):
    collected = []
    for page in range(1, 11):
        result = fetch(f"{path}?per_page=100&page={page}")
        entries = result.get(key) if key else result
        need(type(entries) is list, "invalid GitHub page")
        collected.extend(entries)
        if len(entries) < 100:
            return collected
    raise Refusal("GitHub result exceeds ten-page bound")


def assess_live(evidence, fetch=fetch_public_json):
    need(evidence.get("repository") == "fr-meyer/openclaw", "wrong evidence repository")
    deadline = time.monotonic() + 45

    def bounded_fetch(path):
        need(time.monotonic() < deadline, "GitHub assessment exceeded time bound")
        return fetch(path)

    prefix = "repos/fr-meyer/openclaw"
    number = evidence["prNumber"]
    run_id, attempt = evidence["run"]["runId"], evidence["run"]["attempt"]
    pr = bounded_fetch(f"{prefix}/pulls/{number}")
    run = bounded_fetch(f"{prefix}/actions/runs/{run_id}")
    reviews = pages(bounded_fetch, f"{prefix}/pulls/{number}/reviews")
    jobs = pages(bounded_fetch, f"{prefix}/actions/runs/{run_id}/attempts/{attempt}/jobs", "jobs")
    dependencies = [bounded_fetch(f"{prefix}/pulls/{item['number']}") for item in evidence["dependsOn"]]
    assessment = assess_current(evidence, pr, reviews, run, jobs, dependencies)
    seen = {number}
    active = {number}
    cache = {item["number"]: item for item in dependencies}

    def visit(declared):
        for item in declared:
            child_number = item["number"]
            need(child_number not in active, "PR dependency cycle")
            child = cache.get(child_number)
            if child is None:
                need(len(cache) < 32, "PR dependency closure exceeds 32 PRs")
                child = cache[child_number] = bounded_fetch(f"{prefix}/pulls/{child_number}")
            need(child.get("number") == child_number and child.get("head", {}).get("sha") == item["headSha"],
                 "transitive dependency head changed")
            need(child.get("base", {}).get("ref") == evidence["target"] and
                 child.get("base", {}).get("repo", {}).get("full_name") == evidence["repository"],
                 "transitive dependency target changed")
            need(child.get("state") == "closed" and child.get("merged_at") is not None,
                 "transitive dependency is not merged")
            if child_number in seen:
                continue
            seen.add(child_number)
            active.add(child_number)
            child_intent = intent_from_body(child.get("body"))
            need(child_intent["target"] == evidence["target"], "transitive dependency declared another target")
            visit(child_intent["dependsOn"])
            active.remove(child_number)

    visit(evidence["dependsOn"])
    return assessment


def cli():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("template", "intake", "seal", "seal-offline", "bind", "binding-check", "opening-preflight", "compare", "assess", "assess-live"))
    parser.add_argument("--kind", choices=("task", "release"))
    parser.add_argument("--owner")
    parser.add_argument("--target")
    parser.add_argument("--scope")
    parser.add_argument("--candidate")
    parser.add_argument("--pr-number", type=int)
    parser.add_argument("--base-sha")
    parser.add_argument("--dependency", action="append", default=[])
    parser.add_argument("--event", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--checkout", type=Path)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--previous", type=Path)
    parser.add_argument("--pr", type=Path)
    parser.add_argument("--reviews", type=Path)
    parser.add_argument("--run", type=Path)
    parser.add_argument("--jobs", type=Path)
    parser.add_argument("--dependencies", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.command == "template":
        value = template(args.kind, args.owner, args.target, args.scope, args.dependency)
        if args.output:
            args.output.write_text(value)
        else:
            print(value, end="")
        return
    if args.command == "seal-offline":
        value = offline_release_seal(args.manifest, args.checkout)
    elif args.command == "bind":
        need(args.output is not None, "binding proposal requires output path")
        need(args.output.resolve() != args.manifest.resolve(), "binding proposal must use a separate output path")
        value = generate_binding(args.manifest, args.checkout, args.candidate,
                                 args.pr_number, args.base_sha)
    elif args.command == "binding-check":
        value = validate_binding(args.manifest, args.checkout)
    elif args.command == "opening-preflight":
        value = opening_preflight(args.checkout, args.base_sha)
    elif args.command in ("intake", "seal"):
        event = json.loads(args.event.read_text())
        run = {"runId": int(os.environ["GITHUB_RUN_ID"]), "attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
               "checkRunId": int(os.environ["CHECK_RUN_ID"]), "workflowSha": os.environ["GITHUB_WORKFLOW_SHA"]}
        value = intake(event, run)
        if args.command == "seal":
            value = release_seal(value, args.manifest, args.checkout)
    elif args.command == "compare":
        value = {"changedDiffReusable": reusable_changed_diff(json.loads(args.previous.read_text()), json.loads(args.evidence.read_text()))}
    elif args.command == "assess-live":
        value = assess_live(json.loads(args.evidence.read_text()))
    else:
        jobs = json.loads(args.jobs.read_text())
        value = assess_current(json.loads(args.evidence.read_text()), json.loads(args.pr.read_text()),
                               json.loads(args.reviews.read_text()), json.loads(args.run.read_text()),
                               jobs.get("jobs", jobs) if isinstance(jobs, dict) else jobs,
                               json.loads(args.dependencies.read_text()) if args.dependencies else ())
    output = json.dumps(value, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(output)
    else:
        print(output, end="")


if __name__ == "__main__":
    try:
        cli()
    except (Refusal, OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f"Fork PR refused: {error}", file=sys.stderr)
        sys.exit(1)
