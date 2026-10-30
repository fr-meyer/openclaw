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
from bounded_run_contract_v109 import Refusal as RunGrantRefusal

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
WORKFLOW_TARGET = "918890b9f72b2d0372995362e8ea3088e0f87431"
WORKFLOW_TARGET_TREE = "d8ce67a5b48c1f5e2ccf56e7f47dabccb4511df1"
WORKFLOW_MERGE_BASE = "c5f6ea725b69740582e8051c974a798feda792ba"
WORKFLOW_MERGE_BASE_TREE = "38a532f0cf67e887db788f98dd90aed0f8d8d572"
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
    "scripts/fork-release/bounded_run_contract_v109.py",
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
    CANDIDATE + "/registry-metadata.json", policy.PREPARATION_FAILURE_EVIDENCE,
    policy.ADDITIONAL_PREPARATION_FAILURE_EVIDENCE,
    CANDIDATE + "/historical-unacquired-jobs-20261030.json",
    CANDIDATE + "/historical-artifact-snapshot-20261028.json",
    CANDIDATE + "/historical-artifact-closeout-20261028.json", *BASELINE_FILES,
)
HISTORICAL_JOB_WITNESS = CANDIDATE + "/historical-unacquired-jobs-20261030.json"
HISTORICAL_JOB_WITNESS_SHA256 = "a3d1cdeddc6af9bd469c069cd52a4c80b3e8565d175944b8b1bef1d3a07bdc23"
HISTORICAL_ARTIFACT_NOTE = CANDIDATE + "/historical-artifact-snapshot-20261028.json"
HISTORICAL_ARTIFACT_NOTE_SHA256 = "8c5b538f300b95ea0c447aa9821472e87deb5dac261faa20d170de0ea45a0a87"
HISTORICAL_ARTIFACT_PRODUCER = CANDIDATE + "/historical-artifact-closeout-20261028.json"
HISTORICAL_ARTIFACT_PRODUCER_SHA256 = "38962ed7beed7c875e2fbad72ae82668898f6776c92903675bc202d5b994665d"
HISTORICAL_RECONCILIATION_INPUTS = (HISTORICAL_JOB_WITNESS,HISTORICAL_ARTIFACT_NOTE,HISTORICAL_ARTIFACT_PRODUCER)
HISTORICAL_ABSENCE_ARTIFACT = 12867024791

TERMINAL = frozenset(("success", "failure", "neutral", "cancelled", "skipped", "timed_out",
    "action_required", "stale", "startup_failure"))
SOURCE_JOBS = {"admission": 30, "final": 10,
    "source (${{ matrix.profile }})": 0,
    **{"source (" + p + ")": n for p, n in policy.PROFILE_MINUTES.items()}}
OLD_SOURCE_BRANCH = "prep/v2026.10.8-remediation"
HISTORY_START = "2026-10-28T00:12:07Z"  # Earliest created_at in the pinned258 baseline.
HISTORY_MAXIMUM = 2000
HISTORY_QUERY_MAXIMUM = 256
HISTORY_SEARCH_CAP = 1000


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


def deterministic_merge_entries(base, head, target):
    """Metadata-only3way overlay; divergent paths refuse, never content-merge.

    Entries come from the maintained strict recursive Git tree parser. This
    deliberately covers only the reviewed conflict-free per-path merge graph;
    it is not a replacement implementation of Git's general merge strategy.
    """
    policy.need(all(type(tree) is dict and bool(tree) for tree in (base,head,target)),
        "v9.workflow_complete_trees")
    result={}
    for path in sorted(set(base)|set(head)|set(target)):
        b,h,t=base.get(path),head.get(path),target.get(path)
        if h==b:
            chosen=t
        elif t==b or h==t:
            chosen=h
        else:
            raise policy.Refusal("v9.workflow_divergent_path")
        if chosen is not None:
            result[path]=chosen
    # A directory/file collision cannot be represented by a valid Git tree.
    # Refuse it directly rather than relying on comparison to omit one side.
    paths=set(result)
    policy.need(all(not any('/'.join(path.split('/')[:i]) in paths for i in range(1,len(path.split('/'))))
        for path in paths),"v9.workflow_path_collision")
    return result


def workflow_merge_binding(read, core, head, merge):
    """Prove the fixed physical graph and complete conflict-free merge entries.

    PR's advertisedbasea65 and the current merge-target918 are separate pinned
    identities. No Git object/ref writer, formatter heuristic or fetched ref is
    accepted as the expected merge; only complete typed metadata is compared.
    """
    policy.need(read("rev-parse","--is-shallow-repository").strip()==b"false",
        "v9.workflow_shallow_graph")
    try:
        read("config","--get-regexp",r"^(extensions\.partialclone|remote\..*\.promisor)$")
    except subprocess.CalledProcessError as error:
        policy.need(error.returncode==1,"v9.workflow_graph_config")
    else:
        raise policy.Refusal("v9.workflow_partial_graph")
    for commit in (head,merge,WORKFLOW_TARGET,WORKFLOW_MERGE_BASE):
        policy.need(policy.pin(commit,160) and read("cat-file","-t",commit).strip()==b"commit",
            "v9.workflow_typed_commit_graph")
    policy.need(read("show","-s","--format=%P",merge).strip().split()==
        [WORKFLOW_TARGET.encode(),head.encode()],"v9.workflow_merge_parents")
    policy.need(read("merge-base","--all",WORKFLOW_TARGET,head).strip().split()==
        [WORKFLOW_MERGE_BASE.encode()],"v9.workflow_unique_fixed_merge_base")
    def tree_id(commit):
        value=read("rev-parse",commit+"^{tree}").strip().decode("ascii")
        policy.need(policy.pin(value,160),"v9.workflow_tree_identity")
        return value
    policy.need(tree_id(WORKFLOW_TARGET)==WORKFLOW_TARGET_TREE and
        tree_id(WORKFLOW_MERGE_BASE)==WORKFLOW_MERGE_BASE_TREE,"v9.workflow_fixed_graph_trees")
    base=core._v4_tree(read,WORKFLOW_MERGE_BASE,WORKFLOW_MERGE_BASE_TREE)
    head_entries=core._v4_tree(read,head,tree_id(head))
    target=core._v4_tree(read,WORKFLOW_TARGET,WORKFLOW_TARGET_TREE)
    actual=core._v4_tree(read,merge,tree_id(merge))
    expected=deterministic_merge_entries(base,head_entries,target)
    policy.need(actual==expected,"v9.workflow_full_merge_tree_changed")
    return {"target":WORKFLOW_TARGET,"mergeBase":WORKFLOW_MERGE_BASE,
        "entryCount":len(expected),"completeTreeCompared":True,"gitObjectWritten":False}


def preparation_pipeline_ancestry(read, head, request, bindings):
    grant=policy.run_grant(bindings)
    if grant is not None:
        plan=grant["nextExecution"]
        policy.need(request["executionSequence"]==plan["sequence"] and
            request["phase"]==plan["phase"] and request["preparationAttempt"]==plan["preparationAttempt"],
            "v9.run_grant_reviewed_plan")
        try:
            read("merge-base","--is-ancestor",plan["priorSourceRun"]["pipelineHead"],head)
            if request["phase"]=="validation":
                read("merge-base","--is-ancestor",request["generation"]["pipelineHead"],head)
        except subprocess.CalledProcessError:
            raise policy.Refusal("v9.run_grant_pipeline_ancestry")
        return
    pc=bindings["preparationCorrection"]
    if policy.additional_pipeline_preparation_recovery(pc):
        policy.need(request["preparationAttempt"]==3 and request["phase"] in ("lock-preparation","validation"),
            "v9.additional_only_third_and_single_validation")
        if request["phase"]=="lock-preparation":
            policy.need(read("show","-s","--format=%P",head).strip().split()==
                [pc["priorFailures"][-1]["pipelineHead"].encode()],"v9.additional_direct_second_parent")
        else:
            try:
                read("merge-base","--is-ancestor",request["generation"]["pipelineHead"],head)
            except subprocess.CalledProcessError:
                raise policy.Refusal("v9.additional_generation_pipeline_ancestry")
    elif request["phase"]=="lock-preparation" and request["preparationAttempt"]==2 and policy.pipeline_preparation_recovery(pc):
        policy.need(read("show","-s","--format=%P",head).strip().split()==
            [pc["priorFailure"]["pipelineHead"].encode()],"v9.pipeline_recovery_direct_parent")


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
            "-c", "maintenance.auto=0", "-c", "gc.auto=0", "-c", "protocol.https.allow=always", "fetch", "--no-tags",
            "https://github.com/fr-meyer/openclaw.git", merge], pipeline, context["gitEnv"],
            context, "workflow-object", 0)
        policy.need(result.returncode == 0 and not getattr(result, "timed_out", False), "v9.workflow_fetch_refused")
    workflow_merge_binding(read,core,head,merge)
    bindings=context.get("bindings") or policy.parse(regular(pipeline/BINDINGS,131072))
    preparation_pipeline_ancestry(read,head,request,bindings)
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


def history_created_range(first, last):
    """Fixed UTC-second query only; no caller URL or route relaxation."""
    policy.need(type(first) is int and type(last) is int and first <= last,
        "v9.history_created_bounds")
    # GitHub's documented range operator is query data, encoded canonically so
    # the existing fixed-route prohibition on literal '..' remains unchanged.
    return (urllib.parse.quote(now_utc(first), safe="") + "%2E%2E" +
        urllib.parse.quote(now_utc(last), safe=""))


def history_rows(api, clock=None):
    """Complete bounded history despite GitHub's1000-result filtered-search cap.

    A total_count of1000 is ambiguous, so bisect disjoint inclusive UTC-second
    windows until each positive collection is strictly below that threshold.
    Never accept an incomplete singleton-second search or normalize duplicate
    IDs. All three maintained branches and the original earliest run survive.
    """
    clock = time.time() if clock is None else clock
    policy.need(type(clock) in (int, float) and math.isfinite(clock), "v9.history_clock")
    first = int(provider_epoch(HISTORY_START))
    last = math.floor(clock)
    policy.need(first <= last, "v9.history_clock")
    branches = (policy.PIPELINE_BRANCH, OLD_SOURCE_BRANCH, policy.SOURCE_BRANCH)
    rows, queries = {}, 0

    def request(branch, lo, hi, page):
        nonlocal queries
        queries += 1
        policy.need(queries <= HISTORY_QUERY_MAXIMUM, "v9.history_query_cap")
        suffix = ("/actions/runs?branch=" + urllib.parse.quote(branch, safe="") +
            "&created=" + history_created_range(lo, hi) + "&per_page=100&page=" + str(page))
        obj = api("/repos/" + policy.REPOSITORY + suffix)
        policy.need(type(obj) is dict and type(obj.get("total_count")) is int and
            obj["total_count"] >= 0 and type(obj.get("workflow_runs")) is list and
            len(obj["workflow_runs"]) <= 100, "v9.complete_provider_collection")
        for row in obj["workflow_runs"]:
            policy.need(type(row) is dict and type(row.get("id")) is int and row["id"] > 0 and
                policy.RUN_ID.fullmatch(str(row["id"])) and row.get("head_branch") == branch,
                "v9.provider_run_id")
            created = provider_epoch(row.get("created_at"))
            policy.need(lo <= created <= hi, "v9.history_created_membership")
        return obj

    def window(branch, lo, hi):
        first_page = request(branch, lo, hi, 1)
        total = first_page["total_count"]
        if total >= HISTORY_SEARCH_CAP:
            policy.need(lo < hi, "v9.history_single_second_overflow")
            middle = (lo + hi) // 2
            window(branch, lo, middle)
            window(branch, middle + 1, hi)
            return
        policy.need(len(rows) + total <= HISTORY_MAXIMUM, "v9.history_total_cap")
        count = 0
        for page in range(1, max(1, math.ceil(total / 100)) + 1):
            obj = first_page if page == 1 else request(branch, lo, hi, page)
            policy.need(obj["total_count"] == total and
                len(obj["workflow_runs"]) == min(100, total - count),
                "v9.provider_collection_changed")
            for row in obj["workflow_runs"]:
                rid = str(row["id"])
                policy.need(rid not in rows, "v9.provider_collection_duplicate")
                rows[rid] = row
            count += len(obj["workflow_runs"])
        policy.need(count == total, "v9.provider_collection_incomplete")

    for branch in branches:
        window(branch, first, last)
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
            0 < len(name) <= 300 and (limits is None or name not in names) and
            job.get("run_attempt") == 1, "v9.unique_native_job")
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
            job.get("runner_group_name") == "GitHub Actions" and (job.get("labels") == ["ubuntu-24.04"] or
                limits is None and job.get("labels") == ["ubuntu-latest"]),
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


HISTORICAL_JOB_PROJECTED_FIELDS = frozenset(("id","name","status","conclusion","started_at","completed_at",
    "runner_id","runner_name","runner_group_name","labels","steps"))
HISTORICAL_JOB_NATIVE_FIELDS = frozenset(("id","run_id","workflow_name","head_branch","run_url","run_attempt",
    "node_id","head_sha","url","html_url","status","conclusion","created_at","started_at","completed_at",
    "name","steps","check_run_url","labels","runner_id","runner_name","runner_group_id","runner_group_name"))
HISTORICAL_PRESENCE_ORDER = ("id","run_id","workflow_name","head_branch","run_url","run_attempt","node_id",
    "head_sha","url","html_url","status","conclusion","created_at","started_at","completed_at","name","steps",
    "check_run_url","labels","runner_id","runner_name","runner_group_id","runner_group_name")
HISTORICAL_STEP_PROJECTED_FIELDS = frozenset(("name","status","conclusion","number"))
HISTORICAL_STEP_NATIVE_FIELDS = HISTORICAL_STEP_PROJECTED_FIELDS | {"started_at","completed_at"}


def _historical_fact_equal(actual, recorded):
    """Type-exact JSON equality; absent keys are never replaced by null."""
    if type(actual) is not type(recorded):
        return False
    if type(recorded) is dict:
        return set(actual)==set(recorded) and all(_historical_fact_equal(actual[key],recorded[key]) for key in recorded)
    if type(recorded) is list:
        return len(actual)==len(recorded) and all(_historical_fact_equal(a,b) for a,b in zip(actual,recorded))
    return type(recorded) in (str,int,float,bool,type(None)) and actual==recorded


def _historical_steps_match(actual, recorded):
    if type(actual) is not list or type(recorded) is not list or len(actual)!=len(recorded):
        return False
    for current,old in zip(actual,recorded):
        if type(current) is not dict or type(old) is not dict or set(old) not in (
                HISTORICAL_STEP_PROJECTED_FIELDS,HISTORICAL_STEP_NATIVE_FIELDS):
            return False
        # Terminal native steps carry the complete six-field envelope. More
        # provider metadata is not an additional historical recorded fact.
        if not HISTORICAL_STEP_NATIVE_FIELDS<=set(current):
            return False
        if any(key not in current or not _historical_fact_equal(current[key],value) for key,value in old.items()):
            return False
    return True


def historical_jobs_match(actual, recorded, authenticated_run):
    """Compare the three exact frozen producer schemas to complete native jobs.

    The immutable213+30+15 inputs retain their bytes/counters unchanged. The
    original presence list is provenance of its producer's read, not a field
    expected from GitHub. Native fields not recorded by that producer are not
    falsely reported as changed historical facts. Native run identity is still
    positively required; a projection cannot be substituted for a fresh reply.
    """
    if type(actual) is not list or type(recorded) is not list or len(actual)!=len(recorded) or type(authenticated_run) is not dict:
        return False
    if (type(authenticated_run.get("id")) is not int or authenticated_run["id"]<=0 or
            type(authenticated_run.get("run_attempt")) is not int or authenticated_run["run_attempt"]!=1 or
            not policy.pin(authenticated_run.get("head_sha"),160)):
        return False
    current_by_id={}
    for current in actual:
        if type(current) is not dict or not HISTORICAL_JOB_NATIVE_FIELDS<=set(current) or "_fieldsPresent" in current:
            return False
        jid=current["id"]
        if (type(jid) is not int or jid<=0 or jid in current_by_id or
                type(current["run_id"]) is not int or current["run_id"]!=authenticated_run["id"] or
                type(current["run_attempt"]) is not int or current["run_attempt"]!=1 or
                type(current["head_sha"]) is not str or current["head_sha"]!=authenticated_run["head_sha"]):
            return False
        current_by_id[jid]=current
    seen=set()
    for old in recorded:
        if type(old) is not dict or set(old) not in (HISTORICAL_JOB_PROJECTED_FIELDS,
                HISTORICAL_JOB_PROJECTED_FIELDS|{"_fieldsPresent"},HISTORICAL_JOB_NATIVE_FIELDS):
            return False
        jid=old["id"]
        if type(jid) is not int or jid<=0 or jid in seen or jid not in current_by_id:
            return False
        seen.add(jid);current=current_by_id[jid]
        if "_fieldsPresent" in old:
            presence=old["_fieldsPresent"]
            if (type(presence) is not list or tuple(presence)!=HISTORICAL_PRESENCE_ORDER or
                    any(type(key) is not str for key in presence) or not set(presence)<=set(current)):
                return False
        for key,value in old.items():
            if key=="_fieldsPresent":
                continue
            if key=="steps":
                if not _historical_steps_match(current[key],value):
                    return False
            elif key not in current or not _historical_fact_equal(current[key],value):
                return False
    return len(seen)==len(current_by_id)


def _historical_positive_unacquired(job, run):
    """Positive native absence of acquisition, not elapsed-time arithmetic."""
    return (type(job) is dict and HISTORICAL_JOB_NATIVE_FIELDS<=set(job) and "_fieldsPresent" not in job and
        type(run.get("id")) is int and run["id"]>0 and type(run.get("run_attempt")) is int and
        policy.pin(run.get("head_sha"),160) and
        type(job["id"]) is int and job["id"]>0 and
        type(job["run_id"]) is int and job["run_id"]==run["id"] and
        type(job["run_attempt"]) is int and job["run_attempt"]==1 and run["run_attempt"]==1 and
        job["head_sha"]==run["head_sha"] and type(job["head_sha"]) is str and
        job["status"]=="completed" and job["conclusion"] in ("skipped","cancelled") and
        all(job[key] is None for key in ("runner_id","runner_name","runner_group_id","runner_group_name")) and
        type(job["steps"]) is list and job["steps"]==[] and type(job["labels"]) is list and
        all(type(label) is str for label in job["labels"]) and
        all(type(job[key]) is str for key in ("created_at","started_at","completed_at")))


def load_historical_reconciliation(job_raw, note_raw, producer_raw, baseline):
    """Resolve only exact old proofs and the captured25-ID fact supplement."""
    policy.need(policy.digest(job_raw)==HISTORICAL_JOB_WITNESS_SHA256 and
        policy.digest(note_raw)==HISTORICAL_ARTIFACT_NOTE_SHA256 and
        policy.digest(producer_raw)==HISTORICAL_ARTIFACT_PRODUCER_SHA256,"v9.historical_reconciliation_input_pin")
    witness,note,producer=(policy.parse(raw,65536) for raw in (job_raw,note_raw,producer_raw))
    policy.need(baseline["runCount"]==258 and baseline["runnerMinutesObserved"]==2944 and
        baseline["artifactSnapshot"]=={"count":23,"bytes":387814} and
        policy.digest(policy.canonical(baseline))=="e811ce042eaf2b5b111f785ed5c5aecfab079f19b1a35116a5d23aa216dfff87",
        "v9.historical_original_booking")
    rows={str(row["id"]):row for row in baseline["runs"]}
    frozen_ids={j["id"] for row in baseline["runs"] for j in row["jobs"]}
    policy.need(len(rows)==258 and witness["schema"]=="openclaw.v109.historical-unacquired-job-supplement.v1" and
        witness["repository"]==policy.REPOSITORY and witness["originalBaselineProofSha256"]==
        "dfc2cda1a2c7c5f3f4e1bc235e8a6e2aca615e62c5ce20a79102a794779770df" and
        witness["originalResolvedCanonicalSha256"]=="e811ce042eaf2b5b111f785ed5c5aecfab079f19b1a35116a5d23aa216dfff87" and
        witness["sourceCapture"]["sha256"]=="e9bc1af83343f2ed58b8f8780e1808dd89d4b601cc87c686f5dd6dcd00ea87a0" and
        witness["sourceCapture"]["responseCount"]==774 and witness["extraJobCount"]==25 and
        witness["additionalHistoricalRunnerMinutes"]==0 and witness["coverageTransferred"] is False and
        witness["originalHistoryRewritten"] is False and witness["executionAuthorized"] is False,
        "v9.closed_historical_job_witness")
    extras={};all_extra=set()
    for item in witness["runs"]:
        rid=item["runId"];row=rows.get(rid)
        policy.need(row is not None and rid not in extras and item["headSha"]==row["head_sha"] and
            type(item["runAttempt"]) is int and item["runAttempt"]==1 and
            policy.pin(item["nativeRunSha256"]) and policy.pin(item["nativeJobsSha256"]),"v9.historical_witness_run")
        for job in item["extraJobs"]:
            policy.need(set(job)==HISTORICAL_JOB_NATIVE_FIELDS and _historical_positive_unacquired(job,row) and job["id"] not in frozen_ids|all_extra,
                "v9.historical_witness_unacquired")
            # These provider timestamps can be reversed for an unacquired skip.
            # Validate syntax but never repair them or calculate a paid duration.
            for key in ("created_at","started_at","completed_at"):provider_epoch(job[key])
            all_extra.add(job["id"])
        extras[rid]=item["extraJobs"]
    policy.need(len(extras)==5 and len(all_extra)==25,"v9.historical_exact_supplement")
    policy.need(producer["schema"]=="openclaw.v108.final-campaign-closeout.v1" and
        producer["artifactInventory"]=="FINAL-ARTIFACT-INVENTORY-COMPLETE.private.json" and
        producer["artifactInventorySha256"]==HISTORICAL_ARTIFACT_NOTE_SHA256 and
        producer["artifactCount"]==5 and producer["artifactBytes"]==3111 and
        producer["artifactPaginationComplete"] is True and producer["qualified"] is False and
        producer["productionAuthorized"] is False,"v9.historical_note_producer")
    policy.need(note["schema"]=="openclaw.v108.complete-artifact-inventory.v2" and
        note["completePagination"] is True and note["artifactCount"]==5 and note["totalBytes"]==3111 and
        note["sourceWorkflowArtifacts"]==0 and len(note["artifacts"])==5,"v9.historical_artifact_note")
    artifacts={rid:list(row.get("artifactRows",[])) for rid,row in rows.items()}
    artifact_ids={a["id"] for expected in artifacts.values() for a in expected}
    policy.need(len(artifact_ids)==sum(map(len,artifacts.values())),"v9.historical_original_artifact_ids")
    note_ids=set()
    for artifact in note["artifacts"]:
        context=artifact["workflow_run"];rid=str(context["id"]);row=rows.get(rid)
        policy.need(set(artifact)=={"id","name","size_in_bytes","expired","created_at","expires_at","workflow_run"} and
            type(artifact["id"]) is int and artifact["id"]>0 and artifact["id"] not in artifact_ids|note_ids and
            type(artifact["name"]) is str and type(artifact["size_in_bytes"]) is int and artifact["size_in_bytes"]>0 and
            artifact["expired"] is False and row is not None and context["head_sha"]==row["head_sha"] and
            context["head_branch"]==row["head_branch"] and
            context["repository_id"]==context["head_repository_id"]==1309456040,"v9.historical_note_artifact_identity")
        provider_epoch(artifact["created_at"]);provider_epoch(artifact["expires_at"])
        note_ids.add(artifact["id"]);artifacts[rid].append(artifact)
    policy.need(len(artifact_ids|note_ids)==23 and sum(a["size_in_bytes"] for expected in artifacts.values() for a in expected)==387814,
        "v9.historical_artifact_booking_preserved")
    return {"extras":extras,"artifacts":artifacts,"noteIds":note_ids,"allExtraIds":all_extra}


def reconcile_historical_jobs(actual, recorded, run, expected_extras):
    """Keep every frozen job; only the25 exact witnessed no-runner IDs may append."""
    policy.need(type(actual) is list and type(expected_extras) is list,"v9.historical_reconciliation_jobs")
    known={job["id"] for job in recorded};extra={job["id"]:job for job in expected_extras}
    native={job["id"]:job for job in actual if type(job) is dict and type(job.get("id")) is int}
    policy.need(len(native)==len(actual) and set(native)==known|set(extra),"v9.historical_job_set_changed")
    policy.need(historical_jobs_match([native[job["id"]] for job in recorded],recorded,run),
        "v9.historical_original_job_changed")
    facts=[]
    for jid,old in extra.items():
        job=native[jid]
        policy.need(_historical_positive_unacquired(job,run) and all(key in job and
            _historical_fact_equal(job[key],value) for key,value in old.items()),"v9.historical_extra_job_changed")
        facts.append({"runId":str(run["id"]),"jobId":jid,"status":job["status"],"conclusion":job["conclusion"],
            "labels":list(job["labels"]),"runnerAcquired":False,"additionalRunnerMinutes":0,
            "durationCalculated":False,"timestampsRepaired":False,"coverageTransferred":False})
    return facts


def reconcile_historical_artifacts(actual, expected, run, observed_epoch):
    """Conservative historical booking, with one explicit dated payload absence."""
    policy.need(type(observed_epoch) in (int,float) and math.isfinite(observed_epoch) and
        type(actual) is list,"v9.historical_artifact_observation_clock")
    native={a["id"]:a for a in actual if type(a) is dict and type(a.get("id")) is int}
    wanted={a["id"]:a for a in expected}
    policy.need(len(native)==len(actual) and len(wanted)==len(expected) and set(native)<=set(wanted),
        "v9.historical_unknown_artifact")
    missing=[]
    for aid,old in wanted.items():
        if aid not in native:
            policy.need(aid==HISTORICAL_ABSENCE_ARTIFACT and run["id"]==40804517284 and
                old["name"]=="v108-npm-lock-preparation" and old["size_in_bytes"]==187076 and
                old["digest"]=="sha256:f433194ae0b6927a21c8ba8a5be7bebb000a533a39a979905855d5cbb8b691e3" and
                old["expires_at"]=="2026-10-30T02:09:22Z" and
                observed_epoch>=provider_epoch(old["expires_at"]),"v9.historical_artifact_missing_before_or_without_expiry")
            missing.append({"runId":str(run["id"]),"artifactId":aid,"bookedBytes":old["size_in_bytes"],
                "recordedExpiresAt":old["expires_at"],"payloadAvailability":"unavailable",
                "absenceCause":"unproved","originalBookingPreserved":True,"custodyClaimed":False})
        else:
            policy.need(historical_artifacts_match([native[aid]],[old]),"v9.historical_artifact_recorded_fact_changed")
    return missing


def closed_baseline(pipeline, history, api, resolver, observed_epoch=None):
    baseline=resolver.resolve_baseline_258(*(regular(pipeline/path) for path in BASELINE_FILES))
    proof=load_historical_reconciliation(*(regular(pipeline/path,65536) for path in HISTORICAL_RECONCILIATION_INPUTS),baseline)
    observed_epoch=time.time() if observed_epoch is None else observed_epoch
    ids,alljobs,allartifacts=set(),set(),set();job_facts=[];missing_artifacts=[]
    for row in baseline["runs"]:
        rid=str(row["id"]);run=history.get(rid)
        policy.need(type(run) is dict and public_run(run) and run.get("status")=="completed" and
            run.get("conclusion") in TERMINAL and all(type(run.get(key)) is type(row[key]) and
                run.get(key)==row[key] for key in resolver.HEADERS),"v9.closed_provider_header_changed")
        table=jobs_for(api,run)
        job_facts+=reconcile_historical_jobs(table,row["jobs"],run,proof["extras"].get(rid,[]))
        jobids={job["id"] for job in table}
        policy.need(not alljobs.intersection(jobids),"v9.historical_duplicate_job")
        alljobs.update(jobids)
        expected=proof["artifacts"][rid]
        missing_artifacts+=reconcile_historical_artifacts(artifacts_for(api,run),expected,run,observed_epoch)
        artifact_ids={a["id"] for a in expected}
        policy.need(not allartifacts.intersection(artifact_ids),"v9.historical_duplicate_artifact")
        allartifacts.update(artifact_ids);ids.add(rid)
    policy.need(len(ids)==258 and len(alljobs)==1072 and len(job_facts)==25 and len(allartifacts)==23,
        "v9.historical_reconciliation_cardinality")
    emit({"schema":"openclaw.v109.historical-reconciliation-facts.v1","status":"historical_metadata_reconciled_only",
        "originalRunCount":258,"originalRunnerMinutes":2944,"originalArtifactBooking":{"count":23,"bytes":387814},
        "jobWitnessSha256":HISTORICAL_JOB_WITNESS_SHA256,"artifactNoteSha256":HISTORICAL_ARTIFACT_NOTE_SHA256,
        "artifactProducerSha256":HISTORICAL_ARTIFACT_PRODUCER_SHA256,"zeroAcquisitionJobFacts":job_facts,
        "historicalPayloadAbsences":missing_artifacts,"additionalHistoricalRunnerMinutes":0,
        "rawHistoryRewritten":False,"coverageTransferred":False,"qualified":False,"productionAuthorized":False})
    return ids,alljobs,allartifacts


def content(api, path, commit, maximum=131072):
    policy.need(path in (BINDINGS, REQUEST, policy.WORKFLOW, "scripts/fork-release/source_validation_v109.py") and policy.pin(commit, 160), "v9.fixed_content_read")
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
    for branch, sha in ((policy.PIPELINE_BRANCH, head), (policy.SOURCE_BRANCH, request["source"]["sourceSha"]),
                        (policy.BASE_BRANCH, WORKFLOW_TARGET)):
        ref = api("/repos/" + policy.REPOSITORY + "/git/ref/heads/" + urllib.parse.quote(branch,safe="/"))
        policy.need(ref.get("ref") == "refs/heads/" + branch and ref.get("object", {}).get("type") == "commit" and
            ref.get("object", {}).get("sha") == sha, "v9.live_branch_tip")


def role(run, request):
    policy.need(public_run(run) and run.get("event") == "pull_request" and
        run.get("head_branch") == policy.PIPELINE_BRANCH and run.get("path") == policy.WORKFLOW and
        run.get("name") == policy.CAMPAIGN and run.get("display_title") == policy.CAMPAIGN,
        "v9.source_run_role")
    return {"lock-preparation":45} if request["phase"] == "lock-preparation" else SOURCE_JOBS


def replay_failed_preparation(proof, bindings, source_rows, api, expected_attempt, expected_prior):
    rows=[row for row in source_rows if row[0]==proof["runId"]]
    policy.need(len(rows)==1,"v9.pipeline_recovery_prior_missing")
    _,run,q,raw=rows[0]
    policy.need(public_run(run) and run.get("status")=="completed" and run.get("conclusion")=="failure" and
        run.get("head_sha")==proof["pipelineHead"] and policy.digest(raw)==proof["requestSha256"] and
        q["phase"]=="lock-preparation" and q["preparationAttempt"]==expected_attempt and q["source"]==bindings["preparation"] and
        q["generation"] is None and q["priorRunPins"]==expected_prior,"v9.pipeline_recovery_prior_identity")
    role(run,q)
    policy.need(policy.digest(content(api,policy.WORKFLOW,run["head_sha"]))==proof["producerWorkflowSha256"] and
        policy.digest(content(api,"scripts/fork-release/source_validation_v109.py",run["head_sha"]))==
            proof["producerRuntimeSha256"],"v9.pipeline_recovery_producer_identity")
    jobs=jobs_for(api,run)
    policy.need(len(jobs)==1 and jobs[0].get("id")==proof["jobId"] and jobs[0].get("name")=="lock-preparation" and
        jobs[0].get("status")=="completed" and jobs[0].get("conclusion")=="failure" and
        jobs[0].get("run_attempt")==1 and jobs[0].get("started_at")==proof["nativeStartedAt"] and
        jobs[0].get("completed_at")==proof["nativeCompletedAt"],"v9.pipeline_recovery_native_job")
    steps=jobs[0].get("steps")
    policy.need(type(steps) is list and all(type(step) is dict and type(step.get("name")) is str for step in steps),
        "v9.pipeline_recovery_native_steps")
    by_name={step["name"]:step for step in steps}
    skipped=proof["skippedCandidateSteps"]
    allowed={"Set up job","Start shared deadline before checkout","Checkout reviewed pipeline closure",
        proof["failedStep"],*skipped,"Post Checkout reviewed pipeline closure","Complete job"}
    policy.need(len(by_name)==len(steps) and set(by_name)==allowed and all(
        step.get("status")=="completed" for step in steps) and
        by_name[proof["failedStep"]].get("conclusion")=="failure" and all(
        by_name[name].get("conclusion")=="skipped" for name in skipped) and all(
        by_name[name].get("conclusion")=="success" for name in allowed-set(skipped)-{proof["failedStep"]}),
        "v9.pipeline_recovery_no_candidate_execution")
    policy.need(artifacts_for(api,run)==[],"v9.pipeline_recovery_zero_artifacts")
    minutes=observed_jobs(jobs,provider_epoch(jobs[0]["completed_at"]),True,{"lock-preparation":45})[0]
    return {"runId":proof["runId"],"jobId":proof["jobId"],"sourceUnchanged":True,"observedRunnerMinutes":minutes,
        "sourceCheckoutPerformed":False,"generationProduced":False,"priorMinutesRemainCharged":True}



def pipeline_recovery_history(pipeline, bindings, source_rows, api):
    pc=bindings["preparationCorrection"]
    if policy.additional_pipeline_preparation_recovery(pc):
        proofs=policy.validate_additional_pipeline_recovery_evidence(
            regular(pipeline/policy.PREPARATION_FAILURE_EVIDENCE,16384),
            regular(pipeline/policy.ADDITIONAL_PREPARATION_FAILURE_EVIDENCE,16384),bindings)
        facts=[replay_failed_preparation(proof,bindings,source_rows,api,index+1,pc["priorFailures"][:index])
            for index,proof in enumerate(proofs)]
        policy.need(len(facts)==2 and sum(f["observedRunnerMinutes"] for f in facts)==16,
            "v9.additional_both_failures_charged")
        return {"additionalPipelineRecovery":True,"priorFailures":facts,"priorRunnerMinutes":16,
            "sourceUnchanged":True,"generationProduced":False,"optionalCorrectionAllowed":False}
    if not policy.pipeline_preparation_recovery(pc):
        return None
    proof=policy.validate_pipeline_recovery_evidence(regular(pipeline/policy.PREPARATION_FAILURE_EVIDENCE,16384),bindings)
    return replay_failed_preparation(proof,bindings,source_rows,api,1,[])


def additional_history_booking(bindings,request,locks,validations,current_id,current_minutes,total,incidental,api,clock):
    """One expressly approved third intake, then one existing full validation."""
    pc=bindings["preparationCorrection"]
    policy.need(policy.additional_pipeline_preparation_recovery(pc) and request["preparationAttempt"]==3 and
        request["phase"] in ("lock-preparation","validation") and len(locks)==3 and
        {row[2]["preparationAttempt"] for row in locks}=={1,2,3} and
        len(validations)==(0 if request["phase"]=="lock-preparation" else 1) and
        all(row[2]["phase"]=="validation" and row[2]["preparationAttempt"]==3 and row[0]==current_id
            for row in validations),"v9.additional_exact_execution_set")
    family=0
    for rid,run,q,raw in locks:
        minutes=observed_jobs(jobs_for(api,run),clock,run.get("status")=="completed",{"lock-preparation":45})[0]
        family+=45 if rid==current_id else minutes
    policy.need(family<=policy.PREPARATION_FAMILY_MINUTES==90,"v9.additional_preparation_family_ceiling")
    booking=45 if request["phase"]=="lock-preparation" else 1075
    remaining_validation=1075 if request["phase"]=="lock-preparation" else 0
    booked=total-current_minutes+booking+remaining_validation+180+max(0,50-incidental)
    policy.need(total<=2500 and incidental<=50 and booked<=policy.budget(request)["maximumBookedMinutes"]<=2500,
        "v9.additional_cumulative_booking_ceiling")
    return {"preparationFamilyBookedMinutes":family,"maximumPreparationFamilyMinutes":90,
        "maximumSourceCampaigns":1,"optionalCorrectionAllowed":False,"bookedMinutes":booked}


def bounded_source_history(bindings,request,source_rows,current_id):
    """Reviewed logical source sequence; never a generic retry scheduler."""
    grant=policy.run_grant(bindings)
    policy.need(grant is not None,"v9.run_grant_required")
    plan=grant["nextExecution"]
    legacy={policy.FAILED_PREPARATION_PIN["runId"],policy.SECOND_FAILED_PREPARATION_PIN["runId"]}
    sequence_rows={}
    for rid,run,q,raw in source_rows:
        if "executionSequence" not in q:
            policy.need(rid in legacy,"v9.run_grant_unsequenced_source")
            continue
        sequence=q["executionSequence"]
        policy.need(type(sequence) is int and sequence>0 and sequence not in sequence_rows and
            q.get("runAllowanceSha256")==grant["authoritySha256"] and
            q["phase"] in ("lock-preparation","validation"),"v9.run_grant_source_sequence")
        if q["phase"]=="lock-preparation":
            policy.need(q["source"]==bindings["preparation"] and q["generation"] is None,
                "v9.run_grant_unchanged_preparation_source")
        else:
            validation=bindings["validation"]
            policy.need(type(validation) is dict and q["source"]==validation["source"] and
                q["generation"]==validation["generation"],"v9.run_grant_same_derived_source")
        policy.need(rid==current_id or run.get("status")=="completed" and run.get("conclusion") in TERMINAL,
            "v9.run_grant_prior_source_terminal")
        sequence_rows[sequence]=(rid,run,q,raw)
    policy.need(type(plan["sequence"]) is int and
        set(sequence_rows)==set(range(1,plan["sequence"]+1)) and
        sequence_rows[plan["sequence"]][0]==current_id and
        sequence_rows[plan["sequence"]][2]==request,"v9.run_grant_contiguous_source_sequence")
    prior=policy.SECOND_FAILED_PREPARATION_PIN
    for sequence in range(1,plan["sequence"]+1):
        rid,run,q,raw=sequence_rows[sequence]
        policy.need(q["priorRunPins"]==[prior],"v9.run_grant_exact_prior_source")
        prior={"runId":rid,"pipelineHead":run["head_sha"],"requestSha256":policy.digest(raw)}
    previous_pin=plan["priorSourceRun"]
    candidates=[row for row in source_rows if row[0]==previous_pin["runId"]]
    policy.need(len(candidates)==1,"v9.run_grant_prior_source_missing")
    rid,run,q,raw=candidates[0]
    policy.need(run.get("status")=="completed" and run.get("conclusion") in TERMINAL and
        run.get("head_sha")==previous_pin["pipelineHead"] and policy.digest(raw)==previous_pin["requestSha256"] and
        request["priorRunPins"]==[previous_pin],"v9.run_grant_prior_source_identity")
    if plan["reasonCode"]=="prior_failure":
        policy.need(run["conclusion"] in ("failure","cancelled","timed_out"),"v9.run_grant_prior_failure")
    elif plan["reasonCode"]=="generation_ready":
        policy.need(request["phase"]=="validation" and q["phase"]=="lock-preparation" and
            run["conclusion"]=="success" and request["generation"]["runId"]==rid,
            "v9.run_grant_generation_ready")
    return {"sourceExecutionSequence":plan["sequence"],"reviewedLogicalExecutions":len(sequence_rows),
        "freshNativeFirstAttemptOnly":True,"unchangedPreparationSource":True}


def bounded_minute_booking(grant,run_minutes,current_id,current_minutes):
    from bounded_run_contract_v109 import PREFIX_RUN_IDS,PREFIX_MINUTES,validate_budget
    policy.need(all((rid,1) in run_minutes for rid in PREFIX_RUN_IDS),"v9.run_grant_prefix_minutes_missing")
    prefix_minutes=sum(run_minutes[(rid,1)] for rid in PREFIX_RUN_IDS)
    policy.need(prefix_minutes>=PREFIX_MINUTES==38,"v9.run_grant_prefix_minute_floor")
    charges=dict(run_minutes)
    for booked in grant["bookedAdditionalAttempts"]:
        key=(booked["runId"],booked["nativeAttempt"])
        policy.need(key in charges,"v9.run_grant_booked_minutes_missing")
        charges[key]=max(charges[key],booked["runnerMinutes"])
    policy.need((current_id,1) in run_minutes and run_minutes[(current_id,1)]==current_minutes,
        "v9.run_grant_current_minute_identity")
    charged_total=sum(charges.values())
    facts=validate_budget(grant,grant["nextExecution"],charged_total,current_minutes)
    facts.update({"prefixMinutesObserved":prefix_minutes,"perAttemptBookedMinuteFloorsApplied":True})
    return charged_total,facts


def history_checks(pipeline, bindings, request, rraw, head, event, env, api, resolver, clock):
    history = history_rows(api, clock)
    grant=policy.run_grant(bindings)
    attempt_facts=None
    if grant is not None:
        from bounded_run_contract_v109 import count_attempts
        # Read only the pinned original ID set before full live validation.
        # A native rerun must be accounted for even when its changed header
        # will subsequently refuse. The complete validation remains below.
        frozen=resolver.resolve_baseline_258(*(regular(pipeline/path) for path in BASELINE_FILES))
        frozen_ids={str(row["id"]) for row in frozen["runs"]}
        attempt_facts=count_attempts(history,frozen_ids,grant)
        # Unsupported native reruns are counted before the fresh-native1 gate;
        # refusal must not silently forget attempts or return their allowance.
        emit({"schema":"openclaw.v109.workflow-attempt-accounting.v1",**attempt_facts,
            "imageBuilt":False,"productionAuthorized":False})
        policy.need(attempt_facts["withinCountLimit"] is True and
            attempt_facts["unsupportedNativeReruns"]==[] and attempt_facts["missingPrefixIds"]==[] and
            attempt_facts["missingBookedAttempts"]==[],"v9.run_grant_attempt_observation")
    baseline_ids, alljobs, allartifacts = closed_baseline(pipeline, history, api, resolver)
    current = history.get(env["GITHUB_RUN_ID"])
    policy.need(type(current) is dict and current["head_sha"] == head and current.get("status") in
        ("queued", "in_progress", "waiting", "pending") and public_run(current), "v9.current_provider_run")
    role(current, request)
    # Same publication can cause unrelated fixed public workflows. Count every
    # post-baseline record, even failed intake, without inventing retry rights.
    total, incidental, source_rows, seen_artifacts = 0, 0, [], set(allartifacts)
    run_minutes={}
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
            if grant is not None and "executionSequence" in q:
                from bounded_run_contract_v109 import validate_grant
                prior_grant=policy.run_grant(b)
                policy.need(prior_grant is not None,"v9.run_grant_historical_authority_missing")
                validate_grant(prior_grant,b["authorization"],active=True,now=created)
                policy.need(policy.digest(rr)==prior_grant["nextExecution"]["requestSha256"],
                    "v9.run_grant_historical_reviewed_request")
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
        run_minutes[(rid,run["run_attempt"])]=minutes
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
    recovery=pipeline_recovery_history(pipeline,bindings,source_rows,api)
    locks = [row for row in source_rows if row[2]["phase"] == "lock-preparation"]
    validations = [row for row in source_rows if row[2]["phase"] in ("validation", "correction")]
    additional=policy.additional_pipeline_preparation_recovery(bindings["preparationCorrection"])
    if grant is not None:
        bounded_source_facts=bounded_source_history(bindings,request,source_rows,env["GITHUB_RUN_ID"])
    else:
        bounded_source_facts=None
        policy.need(len(locks) <= (3 if additional else 2) and len(validations) <= (1 if additional else 2) and len(source_rows) <= 4,
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
    charged_total=total
    if grant is not None:
        charged_total,additional_booking=bounded_minute_booking(grant,run_minutes,env["GITHUB_RUN_ID"],current_minutes)
    elif additional:
        additional_booking=additional_history_booking(bindings,request,locks,validations,env["GITHUB_RUN_ID"],
            current_minutes,total,incidental,api,clock)
    else:
        used_locks = len(locks)
        used_campaigns = len(validations)
        remaining_booking = (2-used_locks)*45 + (2-used_campaigns)*1075 + 180
        policy.need(incidental <= 50 and other_total + booking + remaining_booking + max(0,50-incidental) <= 2500,
            "v9.cumulative_booking_ceiling")
        additional_booking=None
    return {"historicalRecords":258, "historicalMinutes":2944, "newObservedMinutes":total,
        "newChargedMinutes":charged_total,"workflowAttemptAccounting":attempt_facts,
        "boundedSourceExecution":bounded_source_facts,
        "incidentalMinutes":incidental,"currentBookingMinutes":booking,"maximumNewMinutes":2500,
        "sourceExecutions":len(validations),"lockPreparations":len(locks),"observedArtifactBytes":artifact_bytes,
        "pipelinePreparationRecovery":recovery,"additionalPreparationBooking":additional_booking}


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
    return {"deadlineEpoch":deadline,"profile":profile or request["phase"],"bindings":bindings,
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
        if (request["preparationAttempt"] == 1 or policy.pipeline_preparation_recovery(bindings["preparationCorrection"]) or
                policy.additional_pipeline_preparation_recovery(bindings["preparationCorrection"])):
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


def safe_refusal_code(error):
    """Expose only fixed, owned controller refusals under the existing grammar."""
    return (str(error) if isinstance(error,(policy.Refusal,RunGrantRefusal)) and
        re.fullmatch(r"v9\.[a-z0-9_]+",str(error)) else "v9.runtime_refused")


if __name__=="__main__":
    try:
        raise SystemExit(main())
    except (policy.Refusal,ValueError,KeyError,TypeError,OSError,subprocess.SubprocessError) as error:
        code=safe_refusal_code(error)
        emit({"schema":"openclaw.v109.runtime-refusal.v1","status":"refused","code":code,
            "imageBuilt":False,"productionAuthorized":False})
        raise SystemExit(1)
