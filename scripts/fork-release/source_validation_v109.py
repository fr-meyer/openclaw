#!/usr/bin/env python3
"""Closed, secretless 10.9 source-validation caller. No image/cloud entrypoint.

Operational commands are available only on the fixed public hosted PR event,
with a genuine future clock, reviewed code and exact closed source bindings.
Importing this module performs no process, API, filesystem or runtime action.
"""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

import source_validation_contract_v109 as policy

CANDIDATE = "scripts/fork-release/candidates/v2026.10.9-source-only"
REQUEST = CANDIDATE + "/source-request.json"
BINDINGS = CANDIDATE + "/ci-bindings.json"
RESULT_SCHEMA = "openclaw.v109.source-validation-result.v1"
CORE = "scripts/fork-release/source_validation_v108.py"
CORE_HASH = "d2e014f20f5227b183ea217d9874ef7159c90a894debe5a6581bd4696145f965"
TAG_FIXTURE = "scripts/fork-release/fixtures/v2026.10.9.official.tag.raw"
TAG_BYTES = 1028
TAG_SHA256 = "3574aa376a8372d0305a4040e0ea027fead4fed15d5587654d0af755a1fb3f5e"
CLOCK = "V109_JOB_STARTED_EPOCH"
OPERATION = "V109_ADMISSION_REQUEST_SHA256"
BASELINE_FILES = (
    CANDIDATE + "/closed-258-proof.json",
    "scripts/fork-release/candidates/v2026.10.8-source-only/crabline-settled-usage.json",
    "scripts/fork-release/candidates/v2026.10.8-source-only/re2js-settled-usage.json",
    "scripts/fork-release/candidates/v2026.10.8-source-only/re2js-closed-provider-usage.json",
    CANDIDATE + "/closed-15-provider-usage.json",
)
# A closed reviewed import/execution closure; every byte must also match the PR
# workflow merge, before candidate install/preflight/test code can execute.
CODE_PATHS = (
    policy.WORKFLOW, CORE, "scripts/fork-release/source_validation_v109.py",
    "scripts/fork-release/source_validation_contract_v109.py",
    "scripts/fork-release/lockfile_policy_v109.py",
    "scripts/fork-release/source_validation_selection_v109.py",
    "scripts/fork-release/composite_closed_usage.py",
    "scripts/fork-release/composite_closed_usage_v109.py",
    "scripts/fork-release/preflight.py", "scripts/fork-release/release.py",
    "scripts/fork-release/source_reconciliation_v109.py",
    "scripts/fork-release/native_tests.mjs",
    "scripts/fork-release/fixtures/v2026.10.9.official.tag.raw",
    "scripts/fork-release/fixtures/v109-lock-preparation.yml",
    "scripts/fork-release/fixtures/v109-source-validation.yml",
    BINDINGS, REQUEST, CANDIDATE + "/manifest.json", CANDIDATE + "/inventory.json",
    CANDIDATE + "/registry-metadata.json", *BASELINE_FILES,
)
TERMINAL = frozenset(("success", "failure", "neutral", "cancelled", "skipped", "timed_out",
    "action_required", "stale", "startup_failure"))
SOURCE_JOBS = {"admission": 30, "final": 10,
    "source (${{ matrix.profile }})": 0,
    **{"source (" + p + ")": n for p, n in policy.PROFILE_MINUTES.items()}}
OLD_SOURCE_BRANCH = "prep/v2026.10.8-remediation"


def now_utc(epoch=None):
    return datetime.fromtimestamp(time.time() if epoch is None else epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def regular(path, maximum=2 * 1024 * 1024):
    path = Path(path)
    info = path.lstat()
    policy.need(stat.S_ISREG(info.st_mode) and not path.is_symlink() and
        path.resolve(strict=True) == path.absolute() and 0 < info.st_size <= maximum,
        "v9.regular_bounded_input")
    raw = path.read_bytes()
    policy.need(len(raw) == info.st_size, "v9.input_size_changed")
    return raw


def private_write(path, raw):
    policy.need(type(raw) is bytes, "v9.output_bytes")
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    policy.need(path.parent.resolve(strict=True) == path.parent.absolute(), "v9.output_parent")
    with os.fdopen(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb") as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def emit(value):
    # Only fixed structured facts; never subprocess output, tokens or URL data.
    print(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False), flush=True)


def load_metadata(pipeline, active=True, now=None):
    braw, rraw = regular(pipeline / BINDINGS, 131072), regular(pipeline / REQUEST, 65536)
    bindings = policy.validate_bindings(policy.parse(braw), active=active, now=now)
    request = policy.validate_request(policy.parse(rraw), bindings, active=active, now=now)
    return bindings, request, rraw


def event_binding(event, env):
    policy.need(env.get("GITHUB_ACTIONS") == "true" and env.get("RUNNER_OS") == "Linux" and
        env.get("RUNNER_ENVIRONMENT") == "github-hosted" and env.get("GITHUB_EVENT_NAME") == "pull_request" and
        env.get("GITHUB_RUN_ATTEMPT") == "1" and env.get("GITHUB_REPOSITORY") == policy.REPOSITORY and
        env.get("GITHUB_ACTOR") == "fr-meyer" and env.get("GITHUB_REF") == "refs/pull/28/merge" and
        env.get("GITHUB_WORKFLOW_REF") == policy.REPOSITORY + "/" + policy.WORKFLOW + "@refs/pull/28/merge" and
        policy.pin(env.get("GITHUB_WORKFLOW_SHA"), 160) and
        type(env.get("GITHUB_RUN_ID")) is str and policy.RUN_ID.fullmatch(env["GITHUB_RUN_ID"]),
        "v9.public_hosted_first_attempt")
    pr, repo = event.get("pull_request", {}), event.get("repository", {})
    head, base = pr.get("head", {}), pr.get("base", {})
    policy.need(event.get("action") in ("opened", "reopened", "synchronize") and event.get("number") == 28 and
        pr.get("number") == 28 and pr.get("state") == "open" and pr.get("draft") is True and
        repo.get("full_name") == policy.REPOSITORY and repo.get("private") is False and
        head.get("repo", {}).get("full_name") == policy.REPOSITORY and head.get("repo", {}).get("private") is False and
        head.get("ref") == policy.PIPELINE_BRANCH and policy.pin(head.get("sha"), 160) and
        base.get("repo", {}).get("full_name") == policy.REPOSITORY and base.get("ref") == policy.BASE_BRANCH and
        base.get("sha") == policy.BASE, "v9.fixed_draft_pr")
    return head["sha"]


def load_owner(pipeline, name, relative, expected=None):
    path = pipeline / relative
    raw = regular(path, 512 * 1024)
    if expected:
        policy.need(policy.digest(raw) == expected, "v9.reviewed_core_hash")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def git_read(root, *args, deadline=None):
    # Local metadata only: lazy fetch, credentials, hooks and maintenance off.
    remaining = min(60, (deadline or time.time() + 60) - time.time())
    policy.need(remaining > 0, "v9.git_read_deadline")
    env = {"PATH": os.environ["PATH"], "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_LAZY_FETCH": "1", "GIT_NO_REPLACE_OBJECTS": "1", "GIT_GRAFT_FILE": "/dev/null", "GIT_OPTIONAL_LOCKS": "0"}
    child = subprocess.run(["git", "-C", str(root), "-c", "credential.helper=", "-c", "core.hooksPath=/dev/null",
        "-c", "maintenance.auto=0", "-c", "gc.auto=0", "-c", "protocol.allow=never", "-c", "core.useReplaceRefs=false", *args], env=env, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, timeout=remaining, check=True)
    policy.need(len(child.stdout) <= policy.DIAGNOSTIC_BYTES, "v9.git_output_cap")
    return child.stdout


def owned_identity(request):
    return {"campaignId": policy.CAMPAIGN, "sourceSha": request["source"]["sourceSha"],
        "sourceTree": request["source"]["sourceTree"]}


def job_deadline(bindings, request, env, profile=None, clock=None):
    clock = time.time() if clock is None else clock
    value = env.get(CLOCK)
    policy.need(type(value) is str and value.isdigit(), "v9.explicit_job_clock")
    start = int(value)
    policy.validate_bindings(bindings, active=True, now=clock)
    cap = policy.PROFILE_MINUTES[profile] if profile is not None else (
        45 if request["phase"] == "lock-preparation" else 30)
    policy.need(start <= clock < start + cap * 60 - 60 and clock - start < cap * 60,
        "v9.job_clock_expired")
    expiry = policy.utc(bindings["authorization"]["expiresAt"]).timestamp()
    return min(start + cap * 60 - 60, expiry - 60)


def code_binding(pipeline, source, event, env, request, core, context):
    head = event_binding(event, env)
    read = lambda *args: git_read(pipeline, *args, deadline=context["deadlineEpoch"])
    policy.need(read("rev-parse", "HEAD").strip() == head.encode(), "v9.pipeline_head")
    # Verify current head closure before the reviewed fetch helper is used.
    paths = list(CODE_PATHS)
    for optional in ("generation-receipt.json", "generation-receipt-initial.json"):
        path = pipeline / CANDIDATE / optional
        if path.exists():
            paths.append(CANDIDATE + "/" + optional)
    for path in paths:
        policy.need(regular(pipeline / path, 2 * 1024 * 1024) == read("show", head + ":" + path),
            "v9.head_code_bytes")
    merge = env["GITHUB_WORKFLOW_SHA"]
    try:
        read("cat-file", "-e", merge + "^{commit}")
    except subprocess.CalledProcessError:
        result = core.phase_process(["git", "-C", str(pipeline), "-c", "credential.helper=",
            "-c", "maintenance.auto=0", "-c", "gc.auto=0", "-c", "protocol.https.allow=always", "fetch", "--no-tags", "--depth=2",
            "https://github.com/fr-meyer/openclaw.git", merge], pipeline, context["gitEnv"],
            context, "workflow-object", 0)
        policy.need(result.returncode == 0 and not getattr(result, "timed_out", False), "v9.workflow_fetch_refused")
    policy.need(read("show", "-s", "--format=%P", merge).strip().split() ==
        [policy.BASE.encode(), head.encode()], "v9.workflow_merge_parents")
    policy.need(read("rev-parse", merge + "^{tree}") == read("rev-parse", head + "^{tree}"),
        "v9.workflow_full_tree_changed")
    for path in paths:
        policy.need(read("show", head + ":" + path) == read("show", merge + ":" + path),
            "v9.workflow_reviewed_code")
    policy.need(read("status", "--porcelain=v1", "--untracked-files=no").strip() == b"", "v9.pipeline_tracked_clean")
    if source is not None:
        source_binding(source, request, context["deadlineEpoch"])
    return head


def source_binding(source, request, deadline):
    read = lambda *args: git_read(source, *args, deadline=deadline)
    expected = request["source"]
    policy.need(read("rev-parse", "HEAD").strip() == expected["sourceSha"].encode() and
        read("rev-parse", "HEAD^{tree}").strip() == expected["sourceTree"].encode() and
        read("status", "--porcelain=v1", "--untracked-files=all").strip() == b"", "v9.source_checkout_identity")
    for path, digest in expected["fileSha256"].items():
        policy.need(policy.digest(regular(source / path, 16 * 1024 * 1024)) == digest,
            "v9.source_tracked_input_pin")
    return read


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class API:
    """Fixed GitHub read-only API, no credential forwarding across redirects."""
    def __init__(self, token, deadline, opener=None):
        policy.need(type(token) is str and 0 < len(token) <= 4096, "v9.api_token_required")
        self.token, self.deadline = token, deadline
        self.opener = opener or urllib.request.build_opener(NoRedirect)
        self.cache = {}

    def __call__(self, path):
        policy.need(type(path) is str and path.startswith("/repos/" + policy.REPOSITORY + "/") and
            len(path) <= 1024 and not any(c in path for c in "\r\n#") and ".." not in path,
            "v9.fixed_api_route")
        if path not in self.cache:
            seconds = min(30, self.deadline - time.time())
            policy.need(seconds > 0, "v9.api_deadline")
            req = urllib.request.Request("https://api.github.com" + path, headers={
                "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": policy.CAMPAIGN, "Authorization": "Bearer " + self.token})
            with self.opener.open(req, timeout=seconds) as response:
                policy.need(response.geturl() == "https://api.github.com" + path, "v9.api_redirect")
                raw = response.read(4 * 1024 * 1024 + 1)
            self.cache[path] = policy.parse(raw, 4 * 1024 * 1024)
        return self.cache[path]


def paged(api, suffix, collection, maximum=1000):
    rows, total = [], None
    for page in range(1, math.ceil(maximum / 100) + 1):
        obj = api("/repos/" + policy.REPOSITORY + suffix + ("&" if "?" in suffix else "?") +
            "per_page=100&page=" + str(page))
        policy.need(type(obj) is dict and type(obj.get("total_count")) is int and
            type(obj.get(collection)) is list, "v9.complete_provider_collection")
        if total is None:
            total = obj["total_count"]
            policy.need(0 <= total <= maximum, "v9.provider_collection_cap")
        policy.need(total == obj["total_count"] and len(obj[collection]) <= 100,
            "v9.provider_collection_changed")
        rows += obj[collection]
        if len(rows) >= total:
            policy.need(len(rows) == total, "v9.provider_collection_duplicate")
            return rows
        policy.need(len(obj[collection]) == 100, "v9.provider_collection_incomplete")
    raise policy.Refusal("v9.provider_collection_incomplete")


def history_rows(api):
    rows = {}
    for branch in (policy.PIPELINE_BRANCH, OLD_SOURCE_BRANCH, policy.SOURCE_BRANCH):
        for row in paged(api, "/actions/runs?branch=" + urllib.parse.quote(branch, safe=""), "workflow_runs"):
            rid = str(row.get("id"))
            policy.need(policy.RUN_ID.fullmatch(rid), "v9.provider_run_id")
            if rid in rows:
                policy.need(rows[rid] == row, "v9.provider_branch_overlap_changed")
            rows[rid] = row
    return rows


def public_run(run):
    repo = run.get("repository", {})
    return (repo.get("full_name") == policy.REPOSITORY and repo.get("private") is False and
        run.get("actor", {}).get("login") == "fr-meyer" and
        run.get("triggering_actor", {}).get("login") == "fr-meyer" and run.get("run_attempt") == 1 and
        type(run.get("id")) is int and run["id"] > 0 and policy.pin(run.get("head_sha"), 160))


def jobs_for(api, run):
    return paged(api, "/actions/runs/" + str(run["id"]) + "/jobs?filter=all", "jobs", 100)


def artifacts_for(api, run):
    return paged(api, "/actions/runs/" + str(run["id"]) + "/artifacts", "artifacts", 100)


def provider_epoch(value):
    policy.need(type(value) is str and value.endswith("Z"), "v9.provider_timestamp")
    return datetime.fromisoformat(value[:-1] + "+00:00").timestamp()


def observed_jobs(jobs, clock, terminal=False, limits=None):
    ids, names, minutes = set(), set(), 0
    for job in jobs:
        jid, name = job.get("id"), job.get("name")
        policy.need(type(jid) is int and jid > 0 and jid not in ids and type(name) is str and
            name not in names and job.get("run_attempt") == 1, "v9.unique_native_job")
        ids.add(jid); names.add(name)
        if limits is not None:
            policy.need(name in limits, "v9.unexpected_source_job")
        status, conclusion = job.get("status"), job.get("conclusion")
        if terminal:
            policy.need(status == "completed" and conclusion in TERMINAL, "v9.terminal_job_required")
        if status in ("queued", "waiting", "pending"):
            policy.need(not terminal and job.get("started_at") is None, "v9.queued_job_identity")
            continue
        zero = type(job.get("runner_id")) is int and job["runner_id"] == 0 or job.get("runner_id") is None
        if status == "completed" and conclusion in ("skipped", "cancelled") and zero:
            policy.need(job.get("runner_name") in (None, "") and job.get("steps") == [], "v9.positive_unacquired_job")
            continue
        policy.need(type(job.get("runner_id")) is int and job["runner_id"] > 0 and
            job.get("runner_group_name") == "GitHub Actions" and job.get("labels") == ["ubuntu-24.04"],
            "v9.standard_free_public_runner")
        start = provider_epoch(job["started_at"])
        finish = provider_epoch(job["completed_at"]) if status == "completed" else clock
        policy.need(0 <= finish - start and (limits is None or finish - start <= (limits[name] + 1) * 60),
            "v9.native_job_clock")
        minutes += math.ceil((finish - start) / 60)
    return minutes, ids


def historical_artifacts_match(actual, frozen):
    """Keep the frozen usage rows; permit provider expiry only to advance.

    This observes metadata, never claims payload custody or transfers coverage.
    Historical bytes remain conservatively booked even after an expiry change.
    """
    if type(actual) is not list or type(frozen) is not list or len(actual) != len(frozen):
        return False
    by_id = {a.get("id"):a for a in actual if type(a) is dict}
    if len(by_id) != len(actual):
        return False
    for old in frozen:
        if type(old) is not dict or type(old.get("id")) is not int or old["id"] <= 0:
            return False
        current = by_id.get(old["id"])
        if type(current) is not dict or type(current.get("expired")) is not bool or type(old.get("expired")) is not bool:
            return False
        if old["expired"] and not current["expired"]:
            return False
        if any(type(current.get(k)) is not type(v) or current.get(k) != v for k,v in old.items() if k != "expired"):
            return False
    return True


def closed_baseline(pipeline, history, api, resolver):
    baseline = resolver.resolve_baseline_258(*(regular(pipeline / path) for path in BASELINE_FILES))
    ids, alljobs, allartifacts = set(), set(), set()
    for row in baseline["runs"]:
        rid = str(row["id"]); run = history.get(rid)
        policy.need(type(run) is dict and public_run(run) and run.get("status") == "completed" and
            run.get("conclusion") in TERMINAL and all(type(run.get(k)) is type(row[k]) and
            run.get(k) == row[k] for k in resolver.HEADERS), "v9.closed_provider_header_changed")
        table = jobs_for(api, run)
        policy.need(sorted(table, key=lambda j:j["id"]) == sorted(row["jobs"], key=lambda j:j["id"]),
            "v9.closed_provider_jobs_changed")
        jobids = {j["id"] for j in table}
        policy.need(not alljobs.intersection(jobids), "v9.historical_duplicate_job")
        alljobs.update(jobids)
        # Historical provider timestamps may have fractional UTC; they are kept
        # byte-exact above and measured by the maintained historical owner.
        arts = artifacts_for(api, run)
        expected = row.get("artifactRows", [])
        policy.need(historical_artifacts_match(arts, expected),
            "v9.closed_provider_artifacts_changed")
        a_ids = {a["id"] for a in arts}
        policy.need(not allartifacts.intersection(a_ids), "v9.historical_duplicate_artifact")
        allartifacts.update(a_ids); ids.add(rid)
    policy.need(len(ids) == 258 and baseline["runnerMinutesObserved"] == 2944, "v9.closed_usage_count")
    return ids, alljobs, allartifacts


def content(api, path, commit, maximum=131072):
    policy.need(path in (BINDINGS, REQUEST, policy.WORKFLOW) and policy.pin(commit, 160), "v9.fixed_content_read")
    obj = api("/repos/" + policy.REPOSITORY + "/contents/" + path + "?ref=" + commit)
    policy.need(obj.get("type") == "file" and obj.get("encoding") == "base64" and
        type(obj.get("size")) is int and 0 < obj["size"] <= maximum, "v9.public_content_metadata")
    try:
        raw = base64.b64decode("".join(obj["content"].split()), validate=True)
    except (ValueError, TypeError):
        raise policy.Refusal("v9.public_content_encoding")
    policy.need(len(raw) == obj["size"], "v9.public_content_size")
    return raw


def live_identity(api, head, request, event):
    pr = api("/repos/" + policy.REPOSITORY + "/pulls/28")
    policy.need(pr.get("number") == 28 and pr.get("state") == "open" and pr.get("draft") is True and
        pr.get("head", {}).get("sha") == head and pr.get("head", {}).get("ref") == policy.PIPELINE_BRANCH and
        pr.get("head", {}).get("repo", {}).get("full_name") == policy.REPOSITORY and
        pr.get("base", {}).get("sha") == policy.BASE and pr.get("base", {}).get("ref") == policy.BASE_BRANCH,
        "v9.live_pr_changed")
    for branch, sha in ((policy.PIPELINE_BRANCH, head), (policy.SOURCE_BRANCH, request["source"]["sourceSha"])):
        ref = api("/repos/" + policy.REPOSITORY + "/git/ref/heads/" + urllib.parse.quote(branch,safe="/"))
        policy.need(ref.get("object", {}).get("sha") == sha, "v9.live_branch_tip")


def role(run, request):
    policy.need(public_run(run) and run.get("event") == "pull_request" and
        run.get("head_branch") == policy.PIPELINE_BRANCH and run.get("path") == policy.WORKFLOW and
        run.get("name") == policy.CAMPAIGN and run.get("display_title") == policy.CAMPAIGN,
        "v9.source_run_role")
    return {"lock-preparation":45} if request["phase"] == "lock-preparation" else SOURCE_JOBS


def history_checks(pipeline, bindings, request, rraw, head, event, env, api, resolver, clock):
    history = history_rows(api)
    baseline_ids, alljobs, allartifacts = closed_baseline(pipeline, history, api, resolver)
    current = history.get(env["GITHUB_RUN_ID"])
    policy.need(type(current) is dict and current["head_sha"] == head and current.get("status") in
        ("queued", "in_progress", "waiting", "pending") and public_run(current), "v9.current_provider_run")
    role(current, request)
    # Same publication can cause unrelated fixed public workflows. Count every
    # post-baseline record, even failed intake, without inventing retry rights.
    total, incidental, source_rows, seen_artifacts = 0, 0, [], set(allartifacts)
    artifact_bytes = 387814
    baseline = resolver.resolve_baseline_258(*(regular(pipeline / path) for path in BASELINE_FILES))
    incidental_paths = {r["path"] for r in baseline["runs"] if r["path"] != resolver.WORKFLOW}
    auth_start = policy.utc(bindings["authorization"]["approvedAt"]).timestamp()
    for rid, run in history.items():
        if rid in baseline_ids:
            continue
        created = provider_epoch(run["created_at"])
        policy.need(created >= auth_start and public_run(run), "v9.unaccounted_postbaseline_run")
        is_source = run.get("path") == policy.WORKFLOW
        if is_source:
            b = policy.validate_bindings(policy.parse(content(api, BINDINGS, run["head_sha"])))
            rr = content(api, REQUEST, run["head_sha"], 65536)
            q = policy.validate_request(policy.parse(rr), b)
            policy.need(b["authorization"] == bindings["authorization"], "v9.source_campaign_clock_changed")
            limits = role(run, q)
            source_rows.append((rid, run, q, rr))
        else:
            # No other executable role is selected or authorized here. Existing
            # incidental runs must remain public read-only policy/intake jobs.
            policy.need(run.get("path") in incidental_paths and run.get("head_branch") in
                (policy.PIPELINE_BRANCH, policy.SOURCE_BRANCH) and run.get("event") in
                (("pull_request", "pull_request_target") if run.get("head_branch") == policy.PIPELINE_BRANCH else ("push",)),
                "v9.unknown_incidental_workflow")
            limits = None
        jobs = jobs_for(api, run)
        minutes, jobids = observed_jobs(jobs, clock, run.get("status") == "completed", limits)
        if is_source:
            names = {j["name"] for j in jobs}
            if q["phase"] == "lock-preparation":
                policy.need(names == {"lock-preparation"}, "v9.one_preparation_job")
            elif run.get("status") == "completed" and any(j["name"] == "admission" and
                    j.get("conclusion") == "success" for j in jobs):
                policy.need(names == set(SOURCE_JOBS) - {"source (${{ matrix.profile }})"}, "v9.all15_job_shape")
        policy.need(not alljobs.intersection(jobids), "v9.duplicate_new_job")
        alljobs.update(jobids); total += minutes
        if not is_source:
            # Reserve a whole bounded50-minute incidental family while it runs.
            incidental += minutes
        else:
            policy.need(run.get("status") == "completed" or rid == env["GITHUB_RUN_ID"], "v9.concurrent_source_execution")
        arts = artifacts_for(api, run)
        for artifact in arts:
            aid = artifact.get("id")
            policy.need(type(aid) is int and aid > 0 and aid not in seen_artifacts and
                type(artifact.get("size_in_bytes")) is int and artifact["size_in_bytes"] >= 0,
                "v9.new_artifact_identity")
            seen_artifacts.add(aid)
        artifact_bytes += sum(a["size_in_bytes"] for a in arts)
        policy.need(artifact_bytes <= policy.DIAGNOSTIC_BYTES, "v9.cumulative_artifact_limit")
    locks = [row for row in source_rows if row[2]["phase"] == "lock-preparation"]
    validations = [row for row in source_rows if row[2]["phase"] in ("validation", "correction")]
    policy.need(len(locks) <= 2 and len(validations) <= 2 and len(source_rows) <= 4,
        "v9.once_bounded_executions")
    identities = [(q["phase"],q["preparationAttempt"]) for _,_,q,_ in source_rows]
    policy.need(len(identities) == len(set(identities)), "v9.no_automatic_retry")
    for pin in request["priorRunPins"]:
        found = [row for row in source_rows if row[0] == pin["runId"]]
        policy.need(len(found) == 1 and found[0][1]["status"] == "completed" and
            found[0][1]["conclusion"] in ("failure", "cancelled", "timed_out") and
            found[0][1]["head_sha"] == pin["pipelineHead"] and policy.digest(found[0][3]) == pin["requestSha256"],
            "v9.genuine_failed_prior_required")
    if request["phase"] != "lock-preparation":
        gen = request["generation"]
        rows = [row for row in locks if row[0] == gen["runId"]]
        policy.need(len(rows) == 1 and rows[0][1]["status"] == "completed" and rows[0][1]["conclusion"] == "success" and
            rows[0][1]["head_sha"] == gen["pipelineHead"] and rows[0][2]["preparationAttempt"] == request["preparationAttempt"],
            "v9.genuine_generation_run_required")
    booking = 45 if request["phase"] == "lock-preparation" else 1075
    current_jobs = jobs_for(api,current)
    allowed_active = "lock-preparation" if request["phase"] == "lock-preparation" else "admission"
    active = [j for j in current_jobs if j.get("name") == allowed_active]
    policy.need(len(active) == 1 and active[0].get("status") == "in_progress" and
        type(active[0].get("runner_id")) is int and active[0]["runner_id"] > 0, "v9.current_admission_job")
    for job in current_jobs:
        if job is active[0]:
            continue
        policy.need(job.get("status") in ("queued", "waiting", "pending") and
            job.get("runner_id") in (None, 0) and job.get("steps") == [], "v9.no_candidate_before_admission")
    current_minutes = observed_jobs(current_jobs, clock, False, role(current,request))[0]
    other_total = total - current_minutes
    # Future source and image slots remain reserved even if the current run is
    # cheaper; failures and incidental jobs are never refunded or forgotten.
    used_locks = len(locks)
    used_campaigns = len(validations)
    remaining_booking = (2-used_locks)*45 + (2-used_campaigns)*1075 + 180
    policy.need(incidental <= 50 and other_total + booking + remaining_booking + max(0,50-incidental) <= 2500,
        "v9.cumulative_booking_ceiling")
    return {"historicalRecords":258, "historicalMinutes":2944, "newObservedMinutes":total,
        "incidentalMinutes":incidental,"currentBookingMinutes":booking,"maximumNewMinutes":2500,
        "sourceExecutions":len(validations),"lockPreparations":len(locks),"observedArtifactBytes":artifact_bytes}


def validate_generation_provider(pipeline, bindings, request, api):
    generation = request["generation"]
    if generation is None:
        return
    run = api("/repos/" + policy.REPOSITORY + "/actions/runs/" + generation["runId"])
    policy.need(public_run(run) and run.get("status") == "completed" and run.get("conclusion") == "success" and
        run.get("head_sha") == generation["pipelineHead"], "v9.generation_provider_identity")
    jobs = jobs_for(api,run)
    policy.need(len(jobs) == 1 and jobs[0].get("name") == "lock-preparation" and
        jobs[0].get("status") == "completed" and jobs[0].get("conclusion") == "success", "v9.generation_provider_job")
    matches = [a for a in artifacts_for(api,run) if a.get("id") == generation["artifactId"]]
    policy.need(len(matches) == 1 and matches[0].get("name") == "v109-lock-preparation-" + generation["runId"] + "-attempt1" and
        matches[0].get("digest") == "sha256:" + generation["artifactSha256"] and matches[0].get("expired") is False and
        0 < matches[0].get("size_in_bytes",0) <= policy.ARTIFACT_BYTES, "v9.generation_provider_artifact")
    policy.validate_generation(regular(pipeline / CANDIDATE / "generation-receipt.json",65536), bindings, request["phase"])


def write_outputs(env, value):
    path = env.get("GITHUB_OUTPUT")
    if path:
        with open(path,"a",encoding="utf-8") as stream:
            for key,item in value.items():
                policy.need(re.fullmatch(r"[a-z_]+",key) and type(item) in (str,int) and "\n" not in str(item),
                    "v9.fixed_output")
                stream.write(key + "=" + str(item) + "\n")


def prepare_context(pipeline, request, bindings, env, profile=None):
    deadline = job_deadline(bindings,request,env,profile)
    return {"deadlineEpoch":deadline,"profile":profile or request["phase"],
        "operationIdentity":owned_identity(request),"gitEnv":{"PATH":env["PATH"],"GIT_TERMINAL_PROMPT":"0",
            "GIT_CONFIG_NOSYSTEM":"1","GIT_CONFIG_GLOBAL":"/dev/null","GIT_NO_LAZY_FETCH":"1",
            "GIT_NO_REPLACE_OBJECTS":"1","GIT_GRAFT_FILE":"/dev/null",
            "GIT_CONFIG_COUNT":"2","GIT_CONFIG_KEY_0":"protocol.allow","GIT_CONFIG_VALUE_0":"never",
            "GIT_CONFIG_KEY_1":"core.useReplaceRefs","GIT_CONFIG_VALUE_1":"false",
            "GIT_OPTIONAL_LOCKS":"0"}}


def check_admission_outputs(env, request, rraw, head):
    policy.need(env.get(OPERATION) == policy.digest(rraw) and env.get("V109_ADMISSION_PIPELINE_HEAD") == head and
        env.get("V109_ADMISSION_SOURCE_SHA") == request["source"]["sourceSha"] and
        env.get("V109_ADMISSION_RUN_ID") == env.get("GITHUB_RUN_ID"), "v9.same_run_admission_required")


def ensure_official_tag(pipeline, source, inspect, write_tag):
    """Materialize only the authenticated public annotated tag, never a ref.

    Caller first binds its reviewed source/workflow and full local donor closure.
    inspect(root,*args) is the prebound no-lazy/no-replacement metadata owner;
    write_tag(snapshotPath) is prebound ONLY to the owned fixed hash-object call.
    Neither a command, URL, object identity nor fixture path comes from a request.
    """
    fixture = Path(pipeline) / TAG_FIXTURE
    before = fixture.lstat()
    def identity(info):
        return (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns,
            info.st_mode,info.st_uid,info.st_gid,info.st_nlink)
    policy.need(stat.S_ISREG(before.st_mode) and not fixture.is_symlink() and
        fixture.resolve(strict=True) == fixture.absolute() and before.st_uid == os.geteuid() and
        before.st_nlink == 1 and before.st_size == TAG_BYTES, "v9.tag_fixture_file")
    with fixture.open("rb") as handle:
        raw = handle.read(TAG_BYTES + 1)
        after = os.fstat(handle.fileno())
    policy.need(identity(before) == identity(after) == identity(fixture.lstat()) and
        len(raw) == TAG_BYTES and policy.digest(raw) == TAG_SHA256 and
        hashlib.sha1(b"tag " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == policy.UPSTREAM["tagObject"] and
        raw.startswith(("object " + policy.UPSTREAM["commit"] + "\ntype commit\ntag " +
            policy.UPSTREAM["tag"] + "\n").encode()), "v9.authentic_tag_fixture")
    def read(*args):
        value = inspect(source,*args)
        policy.need(type(value) is bytes and len(value) <= 2 * 1024 * 1024,"v9.tag_metadata_bytes")
        return value.strip()
    policy.need(read("rev-parse","--is-shallow-repository") == b"false" and
        read("cat-file","-t",policy.UPSTREAM["commit"]) == b"commit" and
        read("rev-parse",policy.UPSTREAM["commit"]+"^{tree}") == policy.UPSTREAM["tree"].encode(),
        "v9.tag_requires_full_commit_closure")
    def state():
        value=(read("rev-parse","HEAD"),read("rev-parse","HEAD^{tree}"),
            read("status","--porcelain=v1","--untracked-files=all"))
        policy.need(all(re.fullmatch(rb"[0-9a-f]{40}",v) for v in value[:2]) and value[2] == b"",
            "v9.tag_source_clean_identity")
        return value
    previous = state()
    def exact():
        policy.need(read("cat-file","-t",policy.UPSTREAM["tagObject"]) == b"tag" and
            inspect(source,"cat-file","tag",policy.UPSTREAM["tagObject"]) == raw and
            read("rev-parse",policy.UPSTREAM["tagObject"]+"^{commit}") == policy.UPSTREAM["commit"].encode(),
            "v9.authentic_official_tag_closure")
    present = False
    try:
        kind = read("cat-file","-t",policy.UPSTREAM["tagObject"])
    except subprocess.CalledProcessError:
        # This does not classify the read's cause. The only permitted write is
        # deterministic content-addressed insertion of the already verified tag.
        kind = None
    if kind is not None:
        policy.need(kind == b"tag","v9.existing_tag_wrong_type")
        exact();present = True
    else:
        with tempfile.TemporaryDirectory(prefix="v109-official-tag-",dir=Path(pipeline).parent) as temporary:
            snapshot=Path(temporary)/"verified.tag"
            private_write(snapshot,raw)
            result=write_tag(snapshot)
            policy.need(type(getattr(result,"returncode",None)) is int and result.returncode == 0 and
                getattr(result,"timed_out",False) is False,"v9.tag_materialization_refused")
        exact()
    policy.need(state() == previous and identity(fixture.lstat()) == identity(after),
        "v9.tag_materialization_changed_source")
    return {"schema":"openclaw.v109.official-tag-closure.v1","status":"present_exact" if present else "materialized_exact",
        "tagObject":policy.UPSTREAM["tagObject"],"commit":policy.UPSTREAM["commit"],"fixtureSha256":TAG_SHA256,
        "symbolicRefWritten":False,"remoteFetchUsed":False,"sourceChanged":False}


def fetch_closure(pipeline, source, bindings, request, event, env, core, context):
    head = code_binding(pipeline,source,event,env,request,core,context)
    check_admission_outputs(env,request,regular(pipeline/REQUEST,65536),head)
    commits = sorted(set((policy.BASELINE_SOURCE,policy.UPSTREAM["commit"],bindings["preparation"]["sourceSha"],
        request["source"]["sourceSha"], *([bindings["validation"]["source"]["sourceSha"]] if bindings["validation"] else []),
        *([bindings["preparationCorrection"]["source"]["sourceSha"]] if bindings["preparationCorrection"] else []))))
    read = lambda root,*args: git_read(root,*args,deadline=context["deadlineEpoch"])
    donor = core.local_closure_donor_uri(Path(env["GITHUB_WORKSPACE"]),pipeline,source,head,
        request["source"]["sourceSha"],request["source"]["sourceTree"],commits,read)
    shallow = read(source,"rev-parse","--is-shallow-repository").strip() == b"true"
    result = core.phase_process(["git","-C",str(source),"-c","protocol.file.allow=always","-c","credential.helper=",
        "-c","maintenance.auto=0","-c","gc.auto=0","fetch","--no-tags",*(["--unshallow"] if shallow else []),donor,*commits],source,context["gitEnv"],context,"local-source-closure",0)
    policy.need(result.returncode == 0 and not getattr(result,"timed_out",False),"v9.local_closure_refused")
    core.local_closure_donor_uri(Path(env["GITHUB_WORKSPACE"]),pipeline,source,head,
        request["source"]["sourceSha"],request["source"]["sourceTree"],commits,read)
    def write_tag(snapshot):
        return core.phase_process(["git","--no-replace-objects","-C",str(source),"-c","credential.helper=",
            "-c","core.hooksPath=/dev/null","-c","maintenance.auto=0","-c","gc.auto=0",
            "-c","protocol.allow=never","hash-object","-t","tag","-w","--no-filters","--",str(snapshot)],
            source,context["gitEnv"],context,"fixed-official-tag",1)
    ensure_official_tag(pipeline,source,read,write_tag)
    return source_binding(source,request,context["deadlineEpoch"])


def static_source(pipeline,source,bindings,request,core,context):
    from lockfile_policy_v109 import verify_lock_security
    read = source_binding(source,request,context["deadlineEpoch"])
    if request["phase"] == "lock-preparation":
        prep = policy.preparation_for(bindings,request["preparationAttempt"])
        parents = read("show","-s","--format=%P",prep["sourceSha"]).strip().split()
        if request["preparationAttempt"] == 1:
            policy.need(parents == [policy.BASELINE_SOURCE.encode(),policy.UPSTREAM["commit"].encode()],
                "v9.initial_source_parents")
        else:
            pc = bindings["preparationCorrection"]
            policy.need(parents == [pc["parentSource"].encode()],"v9.preparation_correction_parent")
            before = core._v4_tree(read,pc["parentSource"],read("rev-parse",pc["parentSource"]+"^{tree}").decode().strip())
            after = core._v4_tree(read,prep["sourceSha"],prep["sourceTree"])
            policy._verify_reviewed_step(read,before,after,pc)
    else:
        initial = pipeline/CANDIDATE/"generation-receipt-initial.json"
        policy.verify_derived_source(read,bindings,request["phase"],
            regular(pipeline/CANDIDATE/"generation-receipt.json",65536),
            read_tree=lambda commit,tree:core._v4_tree(read,commit,tree),verify_lock=verify_lock_security,
            initial_generation_raw=regular(initial,65536) if initial.exists() else None)
    mraw,iraw = regular(pipeline/CANDIDATE/"manifest.json",131072),regular(pipeline/CANDIDATE/"inventory.json")
    policy.need(policy.digest(mraw)==request["source"]["manifestSha256"] and
        policy.digest(iraw)==request["source"]["inventorySha256"],"v9.producer_control_hashes")
    manifest = policy.parse(mraw)
    policy.need(manifest.get("source",{}).get("commit")==request["source"]["sourceSha"] and
        manifest.get("source",{}).get("tree")==request["source"]["sourceTree"] and
        manifest.get("productionEligible") is False,"v9.manifest_source_not_release")
    return core.preflight.inventory_at(pipeline/CANDIDATE/"inventory.json",manifest,policy.digest(mraw),source_dir=source)


def internal_bootstrap(core, home, env, request, context):
    # This seam is internal only; no standalone unadmitted bootstrap CLI exists.
    policy.need(time.time()<context["deadlineEpoch"],"v9.bootstrap_deadline")
    return core.bootstrap_pnpm(home,env,operation_identity=owned_identity(request))


def derive(pipeline,source,bindings,request,env,core,context):
    policy.need(request["phase"]=="lock-preparation","v9.lock_phase_only")
    static_source(pipeline,source,bindings,request,core,context)
    from lockfile_policy_v109 import verify_lock_security
    started = now_utc()
    registry = policy.recheck_registry_proof(regular(pipeline/CANDIDATE/"registry-metadata.json",65536),started)
    before = regular(source/"pnpm-lock.yaml",16*1024*1024)
    with tempfile.TemporaryDirectory(prefix="v109-lock-",dir=env["RUNNER_TEMP"]) as temporary:
        home=Path(temporary); child_env=core.clean_env(home,env)
        internal_bootstrap(core,home,child_env,request,context)
        core.resource_check(source)
        result=core.phase_process(["pnpm","install","--lockfile-only","--ignore-scripts","--no-frozen-lockfile"],
            source,child_env,context,"lock-derivation",0)
        policy.need(result.returncode==0 and not getattr(result,"timed_out",False),"v9.lock_derivation_failed")
        read=lambda *a:git_read(source,*a,deadline=context["deadlineEpoch"])
        policy.need(read("diff","--name-only").decode().splitlines()==["pnpm-lock.yaml"] and
            read("ls-files","--others","--exclude-standard").strip()==b"","v9.lock_only_worktree_delta")
        generated=regular(source/"pnpm-lock.yaml",16*1024*1024)
        security=verify_lock_security(before,generated,policy.REGISTRY_PINS[0]["distIntegrity"],policy.REGISTRY_PINS[1]["distIntegrity"])
        diff=read("diff","--no-ext-diff","--no-textconv","--binary","--","pnpm-lock.yaml")
        receipt={"schema":policy.GENERATION_SCHEMA,"status":"derived_only",**{
            k:request["source"][k] for k in ("sourceSha","sourceTree")},"pipelineHead":event_binding(policy.parse(
            regular(Path(env["GITHUB_EVENT_PATH"]),1024*1024)),env),"runId":env["GITHUB_RUN_ID"],"runAttempt":1,
            "packageSha256":request["source"]["fileSha256"]["package.json"],
            "workspaceSha256":request["source"]["fileSha256"]["pnpm-workspace.yaml"],
            "sourceLockSha256":request["source"]["fileSha256"]["pnpm-lock.yaml"],
            "generatedLockSha256":policy.digest(generated),"ledgerSha256":request["source"]["fileSha256"][policy.LEDGER],
            "nodeVersion":"24.22.1","pnpmVersion":"12.15.0","changedPaths":["pnpm-lock.yaml"],
            "gitDiffSha256":policy.digest(diff),"allOtherTrackedEntriesUnchanged":True,"startedAt":started,
            "finishedAt":now_utc(),"exitCode":0,"timedOut":False,"cleanupSettled":getattr(result,"cleanup_settled",None),
            "imageBuilt":False,"qualified":False,"productionAuthorized":False,"registryEvidence":registry,
            "lockSecuritySha256":policy.digest(policy.canonical(security))}
        files={"pnpm-lock.yaml":generated,"lock.diff":diff,"generation.json":policy.encode(receipt)}
        policy.need(sum(map(len,files.values()))<=policy.ARTIFACT_BYTES-65536,"v9.lock_artifact_size")
        out=Path(env["RUNNER_TEMP"])/"v109-lock-artifact"
        policy.need(not out.exists(),"v9.artifact_output_fresh")
        for name,raw in files.items():private_write(out/name,raw)
        emit({"schema":policy.GENERATION_SCHEMA,"status":"derived_only","runId":env["GITHUB_RUN_ID"],
            "receiptSha256":policy.digest(files["generation.json"]),"artifactBytes":sum(map(len,files.values())),
            "imageBuilt":False,"productionAuthorized":False})


def post_profile_binding(source, request, deadline):
    read = lambda *args: git_read(source, *args, deadline=deadline)
    policy.need(read("rev-parse", "HEAD").strip() == request["source"]["sourceSha"].encode() and
        read("rev-parse", "HEAD^{tree}").strip() == request["source"]["sourceTree"].encode() and
        read("status", "--porcelain=v1", "--untracked-files=no").strip() == b"",
        "v9.profile_changed_tracked_source")


def run_profile(pipeline,source,bindings,request,profile,env,core,context):
    policy.need(request["phase"] in ("validation","correction") and profile in policy.PROFILES,"v9.source_profile")
    static_source(pipeline,source,bindings,request,core,context)
    selector=load_owner(pipeline,"source_validation_selection_v109","scripts/fork-release/source_validation_selection_v109.py")
    with tempfile.TemporaryDirectory(prefix="v109-source-",dir=env["RUNNER_TEMP"]) as temporary:
        home=Path(temporary); child_env=core.clean_env(home,env)
        internal_bootstrap(core,home,child_env,request,context)
        core.resource_check(source)
        child=core.phase_process(["pnpm","install","--frozen-lockfile"],source,child_env,context,"frozen-install",0)
        policy.need(child.returncode==0 and not getattr(child,"timed_out",False),"v9.frozen_install_failed")
        paths=git_read(source,"ls-files","-z",deadline=context["deadlineEpoch"]).decode().rstrip("\0").split("\0")
        selector.verify_mocked_units(lambda relative: regular(source / relative, 2 * 1024 * 1024))
        if profile == "pipeline-contracts":
            selector.verify_pipeline_contract_files(lambda relative: regular(pipeline / relative, 512 * 1024))
        planned=selector.commands(pipeline,source,profile,paths,request,bindings)
        outcomes=core.run_commands(planned,source,child_env,context)
        policy.need(bool(outcomes) and all(type(x)is int and x==0 for x in outcomes),"v9.profile_failed")
        post_profile_binding(source,request,context["deadlineEpoch"])


def source_result(request,rraw,env,head,admission,matrix):
    policy.need(request["phase"] in ("validation","correction") and admission in ("success","failure","cancelled","skipped") and
        matrix in ("success","failure","cancelled","skipped"),"v9.final_job_results")
    return {"schema":RESULT_SCHEMA,"repository":policy.REPOSITORY,"campaignId":policy.CAMPAIGN,
        "phase":request["phase"],"status":"passed" if admission==matrix=="success" else "failed",
        "runId":env["GITHUB_RUN_ID"],"runAttempt":1,"pipelineHead":head,
        **{k:request["source"][k] for k in ("sourceSha","sourceTree","manifestSha256","inventorySha256")},
        "requestSha256":policy.digest(rraw),"generationReceiptSha256":request["generation"]["receiptSha256"],
        "selectedProfiles":list(policy.PROFILES),"admissionResult":admission,"sourceMatrixResult":matrix,
        "all15Required":True,"freshCoverage":admission==matrix=="success","historicalCoverageReused":False,
        "imageBuilt":False,"nativeImageExecuted":False,"productionAuthorized":False}


def main(argv=None,environment=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command",choices=("admit","fetch-closure","derive","run","finalize"))
    parser.add_argument("--profile",choices=policy.PROFILES)
    args=parser.parse_args(argv)
    env=dict(os.environ if environment is None else environment)
    workspace=Path(env["GITHUB_WORKSPACE"]); pipeline=workspace/"pipeline"; source=workspace/"source"
    bindings,request,rraw=load_metadata(pipeline,active=True,now=time.time())
    policy.need(env.get("V109_APPROVED_AT") == bindings["authorization"]["approvedAt"] and
        env.get("V109_EXPIRES_AT") == bindings["authorization"]["expiresAt"], "v9.workflow_authorization_clock_binding")
    event=policy.parse(regular(Path(env["GITHUB_EVENT_PATH"]),1024*1024))
    head=event_binding(event,env)
    core=load_owner(pipeline,"v109_shared_execution_owner",CORE,CORE_HASH)
    context=prepare_context(pipeline,request,bindings,env,args.profile if args.command in ("run","fetch-closure") else None)
    if args.command == "finalize":
        context["deadlineEpoch"] = min(context["deadlineEpoch"], int(env[CLOCK]) + 10 * 60 - 60)
    core.profile_signals()
    if args.command=="admit":
        code_binding(pipeline,None,event,env,request,core,context)
        api=API(env.get("GH_TOKEN"),context["deadlineEpoch"])
        live_identity(api,head,request,event)
        resolver=load_owner(pipeline,"v109_closed_usage","scripts/fork-release/composite_closed_usage_v109.py")
        facts=history_checks(pipeline,bindings,request,rraw,head,event,env,api,resolver,time.time())
        validate_generation_provider(pipeline,bindings,request,api)
        # Fresh uncached exact head reads immediately before exporting selection.
        api.cache.clear(); live_identity(api,head,request,event)
        write_outputs(env,{"source_sha":request["source"]["sourceSha"],"request_sha":policy.digest(rraw),
            "pipeline_head":head,"run_id":env["GITHUB_RUN_ID"],"phase":request["phase"]})
        emit({"schema":"openclaw.v109.admission.v1","status":"admitted",**facts,"imageBuilt":False})
        return 0
    code_binding(pipeline,None,event,env,request,core,context)
    if args.command=="finalize":
        value=source_result(request,rraw,env,head,env.get("V109_ADMISSION_RESULT"),env.get("V109_SOURCE_RESULT"))
        raw=policy.encode(value);policy.need(len(raw)<=16384,"v9.result_artifact_size")
        private_write(Path(env["RUNNER_TEMP"])/"v109-source-result"/"source-validation.json",raw)
        emit(value);return 0 if value["status"]=="passed" else 1
    check_admission_outputs(env,request,rraw,head)
    if args.command=="fetch-closure":
        fetch_closure(pipeline,source,bindings,request,event,env,core,context);return 0
    # Every candidate-facing entry revalidates source/static identity; the fixed
    # prior fetch step is not treated as authority for a changed checkout.
    if args.command=="derive":derive(pipeline,source,bindings,request,env,core,context)
    else:run_profile(pipeline,source,bindings,request,args.profile,env,core,context)
    return 0


if __name__=="__main__":
    try:
        raise SystemExit(main())
    except (policy.Refusal,ValueError,KeyError,TypeError,OSError,subprocess.SubprocessError) as error:
        code=str(error) if isinstance(error,policy.Refusal) and re.fullmatch(r"v9\.[a-z0-9_]+",str(error)) else "v9.runtime_refused"
        emit({"schema":"openclaw.v109.runtime-refusal.v1","status":"refused","code":code,
            "imageBuilt":False,"productionAuthorized":False})
        raise SystemExit(1)
