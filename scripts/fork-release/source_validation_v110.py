#!/usr/bin/env python3
"""Fixed 10.10 hosted source caller. No image, cloud, credential or deployment API.

The pure contract owns this target. Existing owners provide GitHub measurement,
booking and bounded processes; importing this module performs no operation.
"""
import argparse
from datetime import datetime, timezone
import hashlib
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

import bounded_run_contract_v109 as booking
import source_contract_v110 as policy
import source_validation_v108 as process_owner
import source_validation_v109 as native

REQUEST = policy.CANDIDATE + "/source-request.json"
BINDINGS = policy.CANDIDATE + "/ci-bindings.json"
RECEIPT = policy.CANDIDATE + "/generation-receipt.json"
CODE_MANIFEST = policy.CANDIDATE + "/code-manifest.json"
ACTOR = "fr-meyer"
HISTORY_START = policy.APPROVAL_RECORDED_AT
HISTORY_MAXIMUM = 749
CURRENT_JOBS = {"lock-preparation": {"lock-preparation": 45}, "validation": {
    "admission": 30, "final": 10,
    **{"source (" + name + ")": minutes for name, minutes in policy.PROFILE_MINUTES.items()}}}


def now_utc(clock=None):
    return datetime.fromtimestamp(time.time() if clock is None else clock, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def emit(value):
    raw = policy.encode(value)
    policy.need(len(raw) <= 65536, "v110.summary_cap")
    print(raw.decode().rstrip(), flush=True)


def regular(path, maximum=policy.ARTIFACT_BYTES):
    """No links at any existing component of the fixed private/public input path."""
    path = Path(path).absolute()
    for item in (path, *path.parents):
        policy.need(not stat.S_ISLNK(item.lstat().st_mode), "v110.input_symlink")
    info = path.stat()
    policy.need(stat.S_ISREG(info.st_mode) and info.st_size <= maximum, "v110.input_regular_cap")
    raw = path.read_bytes()
    policy.need(len(raw) == info.st_size and len(raw) <= maximum, "v110.input_changed")
    return raw


def private_write(path, raw):
    policy.need(type(raw) is bytes, "v110.output_bytes")
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    policy.need(path.parent.resolve(strict=True) == path.parent.absolute(), "v110.output_parent")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def hosted_environment(env):
    policy.need(env.get("GITHUB_ACTIONS") == "true" and env.get("GITHUB_REPOSITORY") == policy.REPOSITORY and
        env.get("GITHUB_EVENT_NAME") == "pull_request" and env.get("GITHUB_ACTOR") == ACTOR and
        env.get("GITHUB_TRIGGERING_ACTOR", ACTOR) == ACTOR and env.get("GITHUB_RUN_ATTEMPT") == "1" and
        re.fullmatch(r"[1-9][0-9]{0,19}", env.get("GITHUB_RUN_ID", "")), "v110.fixed_hosted_event")
    policy.need(env.get("RUNNER_OS") == "Linux" and env.get("RUNNER_ARCH") == "X64" and
        env.get("RUNNER_ENVIRONMENT") == "github-hosted", "v110.standard_hosted_runner")


def event_binding(event, env, bindings):
    hosted_environment(env)
    number = bindings["draftPr"]["number"]
    policy.need(type(number) is int and number > 0 and type(event) is dict and event.get("number") == number,
        "v110.event_pr")
    pr = event.get("pull_request", {})
    head, base = pr.get("head", {}), pr.get("base", {})
    policy.need(pr.get("number") == number and pr.get("draft") is True and pr.get("state") == "open" and
        head.get("repo", {}).get("full_name") == policy.REPOSITORY and
        head.get("repo", {}).get("private") is False and head.get("ref") == policy.PIPELINE_BRANCH and
        base.get("repo", {}).get("full_name") == policy.REPOSITORY and
        base.get("ref") == policy.BASE_BRANCH and base.get("sha") == policy.BASE and
        policy.pin(head.get("sha"), 160), "v110.event_identity")
    ref = "refs/pull/" + str(number) + "/merge"
    policy.need(env.get("GITHUB_REF") == ref and env.get("GITHUB_WORKFLOW_REF") ==
        policy.REPOSITORY + "/" + policy.WORKFLOW + "@" + ref and
        policy.pin(env.get("GITHUB_SHA"), 160), "v110.workflow_identity")
    return head["sha"]


def live_pr(api, event, env, bindings):
    head = event_binding(event, env, bindings)
    current = api("/repos/" + policy.REPOSITORY + "/pulls/" + str(bindings["draftPr"]["number"]))
    head_meta, base = current.get("head", {}), current.get("base", {})
    policy.need(current.get("state") == "open" and current.get("draft") is True and
        current.get("number") == bindings["draftPr"]["number"] and head_meta.get("sha") == head and
        head_meta.get("ref") == policy.PIPELINE_BRANCH and
        head_meta.get("repo", {}).get("full_name") == policy.REPOSITORY and
        head_meta.get("repo", {}).get("private") is False and
        base.get("ref") == policy.BASE_BRANCH and base.get("sha") == policy.BASE and
        base.get("repo", {}).get("full_name") == policy.REPOSITORY, "v110.live_pr_changed")
    repository = api("/repos/" + policy.REPOSITORY)
    policy.need(repository.get("full_name") == policy.REPOSITORY and repository.get("private") is False and
        repository.get("archived") is False, "v110.public_repository")
    return head


def live_source(api, request):
    current = api("/repos/" + policy.REPOSITORY + "/branches/" + urllib.parse.quote(policy.SOURCE_BRANCH, safe=""))
    policy.need(current.get("name") == policy.SOURCE_BRANCH and
        current.get("commit", {}).get("sha") == request["source"]["sourceSha"], "v110.live_source_ref_changed")


def read_inputs(pipeline, env, *, admission=False):
    hosted_environment(env)  # No file or subprocess action on a non-hosted invocation.
    braw, rraw = regular(pipeline / BINDINGS), regular(pipeline / REQUEST, 262144)
    bindings, request = policy.parse(braw), policy.parse(rraw, 262144)
    current = time.time()
    policy.validate_request(request, bindings, active=admission, now=current)
    if not admission:
        policy.validate_authorization(bindings["authorization"], active=True, now=current)
        policy.validate_window(bindings["ownerWindow"], active=False, phase=request["phase"])
        policy.need(current < policy.utc(bindings["ownerWindow"]["expiresAt"]).timestamp(), "v110.window_expired")
    event = policy.parse(regular(Path(env["GITHUB_EVENT_PATH"]), 1024 * 1024), 1024 * 1024)
    event_binding(event, env, bindings)
    return bindings, request, braw, rraw, event


def deadline(env, bindings, request, profile=None, *, final=False):
    start = env.get("V110_JOB_STARTED_EPOCH", "")
    policy.need(re.fullmatch(r"[0-9]{10}", start), "v110.job_clock")
    minutes = policy.PREPARATION_MINUTES if request["phase"] == "lock-preparation" else (
        policy.PROFILE_MINUTES[profile] if profile is not None else
        policy.FINAL_MINUTES if final else policy.ADMISSION_MINUTES)
    current = time.time()
    policy.need(int(start) <= current < int(start) + minutes * 60, "v110.job_clock_freshness")
    policy.need(int(start) + minutes * 60 <= min(policy.utc(policy.EXPIRES_AT).timestamp(),
        policy.utc(bindings["ownerWindow"]["expiresAt"]).timestamp()), "v110.full_job_window_required")
    end = min(int(start) + minutes * 60, policy.utc(policy.EXPIRES_AT).timestamp(),
        policy.utc(bindings["ownerWindow"]["expiresAt"]).timestamp()) - 60
    policy.need(current < end, "v110.job_budget_exhausted")
    return end


def git_read(root, *args, deadline_epoch):
    return native.git_read(root, *args, deadline=deadline_epoch)


def code_binding(pipeline, bindings, head, end):
    read = lambda *a: git_read(pipeline, *a, deadline_epoch=end)
    policy.need(read("rev-parse", "HEAD").strip() == head.encode() and
        read("status", "--porcelain=v1", "--untracked-files=no").strip() == b"", "v110.pipeline_checkout_changed")
    code = bindings["pipeline"]
    policy.need(read("rev-parse", code["codeCommit"] + "^{tree}").strip() == code["codeTree"].encode(), "v110.code_commit_tree")
    # The caller receives a code-only ancestor, never a self-referential embedded head.
    policy.need(read("merge-base", code["codeCommit"], head).strip() == code["codeCommit"].encode(), "v110.code_ancestor")
    for path, expected in code["codeFiles"].items():
        raw = regular(pipeline / path, policy.DIAGNOSTIC_BYTES)
        policy.need(len(raw) == expected["bytes"] and policy.digest(raw) == expected["sha256"] and
            read("show", code["codeCommit"] + ":" + path) == raw and read("show", head + ":" + path) == raw,
            "v110.closed_code_bytes")
    return read("rev-parse", "HEAD^{tree}").decode().strip()


def workflow_merge_binding(pipeline, env, head, tree, end):
    read = lambda *a: git_read(pipeline, *a, deadline_epoch=end)
    merge = env["GITHUB_SHA"]
    policy.need(read("show", "-s", "--format=%P", merge).decode().strip().split() == [policy.BASE, head] and
        read("rev-parse", merge + "^{tree}").decode().strip() == tree, "v110.exact_workflow_merge")


def workflow_role_binding(pipeline, bindings, request, env):
    """Compare every operational workflow byte with the reviewed role fixture.

    The workflow's stdlib front loader verifies this same closed map before
    importing us. The map excludes itself and W, avoiding a self-hash cycle.
    """
    import source_validation_selection_v110 as selection
    raw = regular(pipeline / CODE_MANIFEST, policy.ARTIFACT_BYTES)
    code = policy.parse(raw)
    policy.need(type(code) is dict and set(code) == {"schema", "codeFiles"} and
        code["schema"] == "openclaw.v110.code-manifest.v1" and
        code["codeFiles"] == bindings["pipeline"]["codeFiles"] and
        env.get("V110_CODE_MANIFEST_SHA256") == policy.digest(raw), "v110.same_preimport_code_map")
    entry = "scripts/fork-release/source_validation_v110.py"
    expected_env = {"V110_ARMED": "true", "V110_BOUND_PR": str(bindings["draftPr"]["number"]),
        "V110_SOURCE_SHA": request["source"]["sourceSha"],
        "V110_ENTRY_SHA256": code["codeFiles"][entry]["sha256"],
        "V110_EFFECTIVE_AT": policy.APPROVAL_RECORDED_AT, "V110_EXPIRES_AT": policy.EXPIRES_AT}
    policy.need(all(env.get(k) == v for k, v in expected_env.items()), "v110.same_workflow_env")
    template = selection.LOCK_PREPARATION_TEMPLATE if request["phase"] == "lock-preparation" else selection.SOURCE_VALIDATION_TEMPLATE
    policy.need(template in code["codeFiles"], "v110.closed_role_fixture")
    rendered = selection.render_workflow(regular(pipeline / template, 262144),
        pr_number=bindings["draftPr"]["number"], source_sha=request["source"]["sourceSha"],
        entry_sha256=code["codeFiles"][entry]["sha256"], code_manifest_sha256=policy.digest(raw),
        effective_at=policy.APPROVAL_RECORDED_AT)
    policy.need(regular(pipeline / policy.WORKFLOW, 262144) == rendered, "v110.reviewed_role_workflow")


def finite_fetch(pipeline, source, bindings, request, env, context, head):
    """Acquire only the bound public objects, never all refs or private endpoints."""
    roots = [policy.BASE, bindings["pipeline"]["codeCommit"],
        policy.UPSTREAM["tagObject"], policy.UPSTREAM["commit"], policy.FORK_BASE, policy.FROZEN_FORK]
    for generation in bindings["generations"]:
        roots.append(generation["material"]["sourceSha"])
        if generation["validation"] is not None:
            roots.append(generation["validation"]["source"]["sourceSha"])
    roots = list(dict.fromkeys(roots))
    policy.need(len(roots) <= 10 and all(policy.pin(x, 160) for x in roots), "v110.finite_public_roots")
    groups = [(pipeline, list(dict.fromkeys([head, env["GITHUB_SHA"], *roots[:2]])))]
    if source is not None:
        groups.append((source, roots[2:]))
    for root, refs in groups:
        # One planned acquisition per root group, not a retry selected by an
        # ambiguous cat-file failure. There is no alternate endpoint or backend.
        argv = ["git", "-c", "credential.helper=", "-c", "core.hooksPath=/dev/null", "-c",
            "gc.auto=0", "-c", "maintenance.auto=false", "-c", "fetch.writeCommitGraph=false",
            "fetch", "--no-tags", "--no-write-fetch-head", "--depth=" + ("64" if root == pipeline else "8"),
            "https://github.com/" + policy.REPOSITORY + ".git", *refs]
        with tempfile.TemporaryDirectory(prefix="v110-fetch-", dir=env["RUNNER_TEMP"]) as temp:
            child_env = process_owner.clean_env(Path(temp), env)
            outcome = process_owner.phase_process(argv, root, child_env, context, "finite-public-fetch", 0)
            settled(outcome)
        for ref in refs:
            expected = b"tag" if ref == policy.UPSTREAM["tagObject"] else b"commit"
            policy.need(git_read(root, "cat-file", "-t", ref,
                deadline_epoch=context["deadlineEpoch"]).strip() == expected, "v110.fetched_root_identity")
        if root == source:
            tag = policy.UPSTREAM["tagObject"]
            policy.need(git_read(root, "rev-parse", tag + "^{commit}",
                deadline_epoch=context["deadlineEpoch"]).strip() == policy.UPSTREAM["commit"].encode(),
                "v110.upstream_annotated_target")


def source_binding(pipeline, source, bindings, request, end):
    read = lambda *a: git_read(source, *a, deadline_epoch=end)
    selected = request["source"]
    policy.need(read("rev-parse", "HEAD").strip() == selected["sourceSha"].encode() and
        read("rev-parse", "HEAD^{tree}").strip() == selected["sourceTree"].encode() and
        not read("status", "--porcelain=v1", "--untracked-files=no").strip() and
        not read("ls-files", "--others", "--exclude-standard").strip(), "v110.source_checkout_changed")
    tree = lambda sha, tid: process_owner._v4_tree(read, sha, tid)
    policy.verify_material_source(read, bindings, read_tree=tree)
    if request["phase"] == "validation":
        policy.verify_derived_source(read, bindings, regular(pipeline / RECEIPT, 262144), read_tree=tree)
    return read, tree


def _runs(api, branch, maximum=HISTORY_MAXIMUM):
    suffix = "/actions/runs?branch=" + urllib.parse.quote(branch, safe="") + "&created=" + urllib.parse.quote(
        ">=" + HISTORY_START, safe="")
    rows = native.paged(api, suffix, "workflow_runs", maximum)
    seen = set()
    for run in rows:
        policy.need(native.public_run(run) and run.get("head_branch") == branch and run["id"] not in seen and
            native.provider_epoch(run.get("created_at")) >= policy.utc(HISTORY_START).timestamp(), "v110.native_run_identity")
        seen.add(run["id"])
    return rows


def collect_stage(api, bindings, request, env, clock):
    """Measure new fixed branches, retaining other-stage booking separately."""
    # A released window is a positive owner promise, not inferred from this read.
    policy.need(bindings["ownerWindow"]["source109Released"] is True, "v110.source_window_required")
    old = []
    for branch in ("task/v107-source-binding", "prep/v2026.10.9-remediation", "prep/v2026.10.8-remediation"):
        old += _runs(api, branch, maximum=1000)
    policy.need(len({r["id"] for r in old}) == len(old), "v110.unique_other_stage_runs")
    other_artifact_floor = 783765
    for run in old:
        policy.need(run.get("status") == "completed" and run.get("conclusion") in native.TERMINAL,
            "v110.source109_still_active")
        for artifact in native.artifacts_for(api, run):
            policy.need(type(artifact.get("size_in_bytes")) is int and artifact["size_in_bytes"] >= 0,
                "v110.other_stage_artifact_fields")
            other_artifact_floor += artifact["size_in_bytes"]
    window = bindings["ownerWindow"]
    policy.need(window["source109NeededAttemptsUsed"] >= 251 + len(old) and
        window["source109BookedArtifactBytes"] >= other_artifact_floor and
        policy.pin(window["source109LatestLedgerSha256"]), "v110.other_stage_booking_understated")
    rows = _runs(api, policy.PIPELINE_BRANCH) + _runs(api, policy.SOURCE_BRANCH)
    policy.need(len(rows) <= HISTORY_MAXIMUM and len({r["id"] for r in rows}) == len(rows), "v110.unique_stage_runs")
    current_id = int(env["GITHUB_RUN_ID"])
    observed = {"minutes": {"preparation": 0, "validation": 0, "incidental": 0},
        "executions": {"preparation": 0, "validation": 0}, "currentRunMinutes": 0, "currentRunArtifactBytes": 0,
        "currentRunIncluded": False, "stageRunRecords": len(rows),
        "source109NeededAttemptsUsed": window["source109NeededAttemptsUsed"],
        "artifactBytes": window["source109BookedArtifactBytes"]}
    for run in rows:
        jobs = native.jobs_for(api, run)
        named = run.get("path") == policy.WORKFLOW and run.get("name") == policy.CAMPAIGN
        names = {j.get("name") for j in jobs}
        if named:
            policy.need(bool(names) and ((names == {"lock-preparation"}) or
                names <= set(CURRENT_JOBS["validation"]) and "admission" in names), "v110.native_role_jobs")
        role = ("preparation" if "lock-preparation" in names else "validation") if named else "incidental"
        limits = CURRENT_JOBS["lock-preparation" if role == "preparation" else "validation"] if named else None
        minutes, _ = native.observed_jobs(jobs, clock, terminal=run["id"] != current_id, limits=limits)
        if run["id"] != current_id:
            policy.need(run.get("status") == "completed" and run.get("conclusion") in native.TERMINAL,
                "v110.other_stage_run_active")
        else:
            policy.need(run.get("head_sha") == env.get("V110_ADMISSION_PIPELINE_HEAD", run.get("head_sha")),
                "v110.current_head_changed")
            expected_role = "preparation" if request["phase"] == "lock-preparation" else "validation"
            policy.need(named and role == expected_role and
                sum(j.get("status") == "in_progress" and str(j.get("name", "")).startswith("source (")
                    for j in jobs) <= 3, "v110.current_role_or_parallelism")
            observed["currentRunIncluded"], observed["currentRunMinutes"] = True, minutes
        observed["minutes"][role] += minutes
        if named:
            observed["executions"][role] += 1
        for artifact in native.artifacts_for(api, run):
            policy.need(type(artifact.get("size_in_bytes")) is int and artifact["size_in_bytes"] >= 0 and
                type(artifact.get("expired")) is bool, "v110.native_artifact_fields")
            observed["artifactBytes"] += artifact["size_in_bytes"]
            if run["id"] == current_id:
                observed["currentRunArtifactBytes"] += artifact["size_in_bytes"]
    role = "preparation" if request["phase"] == "lock-preparation" else "validation"
    policy.need(observed["currentRunIncluded"], "v110.current_native_run_missing")
    return booking.book_stage_v110(observed, {"role": role, "maximumMinutes": 45 if role == "preparation" else 1105})


def settled(result):
    policy.need(type(result.returncode) is int and result.returncode == 0 and
        getattr(result, "timed_out", None) is False and getattr(result, "cleanup_settled", None) is True,
        "v110.owned_process_not_successfully_settled")


_BOOTSTRAP_CHILD = r"""import hashlib, json, os, re, stat, sys
from pathlib import Path
ROOT = Path(sys.argv[1])
MANIFEST = 'scripts/fork-release/candidates/v2026.10.10-source-only/code-manifest.json'
HELPER = 'scripts/fork-release/verified_imports_v110.py'
CORE = 'scripts/fork-release/source_validation_v108.py'
MAXIMUM = 64 * 1024 * 1024
if ROOT.absolute() != ROOT or ROOT.resolve(strict=True) != ROOT:
    raise SystemExit('v110.bootstrap_root')
def strict_object(pairs):
    if type(pairs) is not list:
        raise SystemExit('v110.bootstrap_json_constant')
    result = {}
    for key, value in pairs:
        if key in result:
            raise SystemExit('v110.bootstrap_duplicate_key')
        result[key] = value
    return result
def read_regular(relative, maximum):
    if (type(relative) is not str or
            re.fullmatch(r'scripts/fork-release/[A-Za-z0-9_./-]+', relative) is None or
            any(part in ('', '.', '..') or part.startswith('-') for part in relative.split('/'))):
        raise SystemExit('v110.bootstrap_code_path')
    parent = ROOT
    for part in relative.split('/')[:-1]:
        parent = parent / part
        if not stat.S_ISDIR(parent.lstat().st_mode):
            raise SystemExit('v110.bootstrap_code_parent')
    path = ROOT / relative
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
        raise SystemExit('v110.bootstrap_code_regular')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    if (identity(before) != identity(opened) or identity(before) != identity(after) or
            identity(before) != identity(path.lstat()) or len(raw) > maximum):
        raise SystemExit('v110.bootstrap_code_changed')
    return raw
expected = sys.argv[4]
if re.fullmatch(r'[0-9a-f]{64}', expected) is None or expected == '0' * 64:
    raise SystemExit('v110.bootstrap_code_manifest_pin')
raw = read_regular(MANIFEST, MAXIMUM)
if hashlib.sha256(raw).hexdigest() != expected:
    raise SystemExit('v110.bootstrap_code_manifest_digest')
manifest = json.loads(raw, object_pairs_hook=strict_object, parse_constant=strict_object)
if (type(manifest) is not dict or set(manifest) != {'schema', 'codeFiles'} or
        manifest['schema'] != 'openclaw.v110.code-manifest.v1' or
        type(manifest['codeFiles']) is not dict or not 1 <= len(manifest['codeFiles']) <= 256 or
        not {HELPER, CORE} <= set(manifest['codeFiles'])):
    raise SystemExit('v110.bootstrap_code_manifest_schema')
captured, total = {}, 0
for relative, pin in manifest['codeFiles'].items():
    if (relative == MANIFEST or type(pin) is not dict or set(pin) != {'sha256', 'bytes'} or
            type(pin['sha256']) is not str or re.fullmatch(r'[0-9a-f]{64}', pin['sha256']) is None or
            type(pin['bytes']) is not int or not 1 <= pin['bytes'] <= MAXIMUM):
        raise SystemExit('v110.bootstrap_code_file_pin')
    total += pin['bytes']
    if total > MAXIMUM:
        raise SystemExit('v110.bootstrap_code_total_cap')
    content = read_regular(relative, pin['bytes'])
    if len(content) != pin['bytes'] or hashlib.sha256(content).hexdigest() != pin['sha256']:
        raise SystemExit('v110.bootstrap_code_file_digest')
    captured[relative] = content
helper = {'__name__': '_v110_verified_imports', '__file__': str(ROOT / HELPER)}
exec(compile(captured[HELPER], str(ROOT / HELPER), 'exec'), helper)
closed = helper['install_verified_imports'](str(ROOT), captured)
exec('import source_validation_v108 as core\ncore.bootstrap_pnpm(home, env, operation_identity=identity)',
    {'__builtins__': closed, 'home': Path(sys.argv[2]), 'env': dict(os.environ),
     'identity': json.loads(sys.argv[3])})
"""


def bootstrap(home, env, pipeline, context, manifest_sha256):
    # The maintained bootstrap's nested npm calls run inside this single owned
    # session, so a hung bootstrap is bounded and joined by the same process owner.
    policy.need(policy.pin(manifest_sha256), "v110.bootstrap_manifest_pin")
    argv = [sys.executable, "-I", "-c", _BOOTSTRAP_CHILD, str(pipeline),
        str(home), json.dumps(context["operationIdentity"], sort_keys=True), manifest_sha256]
    outcome = process_owner.phase_process(argv, pipeline, env, context, "pinned-bootstrap", 0)
    settled(outcome)
    binary = process_owner.owned_pnpm_file(home / "toolchain", "pnpm")
    env["PATH"] = str(binary.parent.parent / ".bin") + os.pathsep + env["PATH"]
    policy.need((home / "toolchain/node_modules/.bin/pnpm").resolve(strict=True) == binary,
        "v110.owned_pnpm_command_link")
    return binary


def source_inputs(source, read):
    paths = read("ls-files", "-z").decode().split("\0")
    selected = {p for p in paths if p == "pnpm-workspace.yaml" or p == "package.json" or
        p == "ui/package.json" or p == "tools/solid-lint/package.json" or p.startswith("patches/") and p.endswith(".patch") or
        re.fullmatch(r"(?:packages|extensions|examples)/[^/]+/package\.json", p)}
    return {p: regular(source / p, 4 * 1024 * 1024) for p in sorted(selected)}


def context_for(request, profile, end):
    return {"deadlineEpoch": end, "profile": profile, "operationIdentity": {
        "campaignId": policy.CAMPAIGN, "sourceSha": request["source"]["sourceSha"],
        "sourceTree": request["source"]["sourceTree"]}}


def verify_code_files(pipeline, bindings):
    for path, expected in bindings["pipeline"]["codeFiles"].items():
        raw = regular(pipeline / path, policy.DIAGNOSTIC_BYTES)
        policy.need(len(raw) == expected["bytes"] and policy.digest(raw) == expected["sha256"], "v110.closed_code_changed")


def check_outputs(env, request, rraw, head):
    policy.need(env.get("V110_ADMISSION_REQUEST_SHA256") == policy.digest(rraw) and
        env.get("V110_ADMISSION_PIPELINE_HEAD") == head and
        env.get("V110_ADMISSION_SOURCE_SHA") == request["source"]["sourceSha"] and
        env.get("V110_ADMISSION_RUN_ID") == env.get("GITHUB_RUN_ID"), "v110.same_run_admission")


def outputs(env, values):
    policy.need(type(env.get("GITHUB_OUTPUT")) is str, "v110.output_channel")
    with open(env["GITHUB_OUTPUT"], "a", encoding="utf8") as stream:
        for name, value in values.items():
            policy.need(re.fullmatch(r"[a-z_]+", name) and type(value) in (str, int) and
                "\n" not in str(value) and "\r" not in str(value), "v110.safe_output")
            stream.write(name + "=" + str(value) + "\n")


def tracked_changes(read, *, changed_lock=False):
    # HEAD comparison covers the complete working state. Inspect the index
    # separately too: an unstaged reversion must not conceal a staged payload.
    changes = read("diff", "--name-only", "HEAD", "--").decode().splitlines()
    staged = read("diff", "--cached", "--name-only", "HEAD", "--").decode().splitlines()
    policy.need(not staged, "v110.source_index_delta")
    policy.need(changes in ([], ["pnpm-lock.yaml"]) if changed_lock else changes == [],
        "v110.source_tracked_delta")
    return changes


def fresh_guard(pipeline, source, bindings, request, rraw, event, env, end, head, *, changed_lock=False):
    policy.validate_authorization(bindings["authorization"], active=True, now=time.time())
    policy.validate_window(bindings["ownerWindow"], active=False, phase=request["phase"])
    policy.need(time.time() < end and time.time() < policy.utc(bindings["ownerWindow"]["expiresAt"]).timestamp(), "v110.effect_deadline")
    policy.need(policy.digest(regular(pipeline / REQUEST, 262144)) == policy.digest(rraw) and
        policy.digest(regular(pipeline / BINDINGS)) == request["bindingsSha256"], "v110.operation_inputs_changed")
    verify_code_files(pipeline, bindings)
    workflow_role_binding(pipeline, bindings, request, env)
    policy.need(git_read(pipeline, "rev-parse", "HEAD", deadline_epoch=end).strip() == head.encode(), "v110.pipeline_checkout_changed")
    api = native.API(env.get("GH_TOKEN", ""), end)
    policy.need(live_pr(api, event, env, bindings) == head, "v110.pipeline_head_changed")
    live_source(api, request)
    collect_stage(api, bindings, request, env, time.time())
    if source is not None:
        read = lambda *a: git_read(source, *a, deadline_epoch=end)
        policy.need(read("rev-parse", "HEAD").strip() == request["source"]["sourceSha"].encode() and
            read("rev-parse", "HEAD^{tree}").strip() == request["source"]["sourceTree"].encode(), "v110.source_identity_changed")
        try:
            tracked_changes(read, changed_lock=changed_lock)
        except policy.Refusal:
            native.post_profile_binding(source, request, end, {
                "runId": env.get("GITHUB_RUN_ID"), "runAttempt": 1, "profile": env.get("V110_CURRENT_PROFILE")})
            raise
        policy.need(not read("ls-files", "--others", "--exclude-standard").strip(), "v110.source_untracked_delta")


def validate_generation_provider(pipeline, bindings, request, api, clock):
    if request["phase"] != "validation":
        return
    generation = policy.active_material(bindings)["validation"]["generation"]
    run = api("/repos/" + policy.REPOSITORY + "/actions/runs/" + generation["runId"])
    policy.need(native.public_run(run) and run.get("path") == policy.WORKFLOW and run.get("event") == "pull_request" and
        run.get("head_branch") == policy.PIPELINE_BRANCH and run.get("head_sha") == generation["pipelineHead"] and
        run.get("status") == "completed" and run.get("conclusion") == "success", "v110.native_generation_run")
    prs = run.get("pull_requests")
    policy.need(type(prs) is list and any(p.get("number") == bindings["draftPr"]["number"] for p in prs), "v110.native_generation_pr")
    jobs = native.jobs_for(api, run)
    policy.need(len(jobs) == 1 and jobs[0].get("name") == "lock-preparation" and jobs[0].get("status") == "completed" and
        jobs[0].get("conclusion") == "success", "v110.native_generation_job")
    native.observed_jobs(jobs, clock, terminal=True, limits=CURRENT_JOBS["lock-preparation"])
    artifacts = [a for a in native.artifacts_for(api, run) if a.get("id") == generation["artifactId"]]
    policy.need(len(artifacts) == 1, "v110.native_generation_unique_artifact")
    item = artifacts[0]
    policy.need(item.get("name") == "v110-lock-preparation-" + generation["runId"] + "-attempt1" and
        item.get("digest") == "sha256:" + generation["artifactSha256"] and item.get("expired") is False and
        type(item.get("size_in_bytes")) is int and 0 < item["size_in_bytes"] <= policy.ARTIFACT_BYTES and
        native.provider_epoch(item.get("expires_at")) > clock, "v110.native_generation_artifact")
    policy.validate_generation(regular(pipeline / RECEIPT, 262144), bindings)


def retain_unvalidated_lock(generated, diff, request, env, started):
    record = {"schema": "openclaw.v110.unvalidated-lock.v1", "status": "unvalidated", "acceptedAsGeneration": False,
        "sourceSha": request["source"]["sourceSha"], "sourceTree": request["source"]["sourceTree"],
        "runId": env["GITHUB_RUN_ID"], "runAttempt": 1, "generatedLockSha256": policy.digest(generated),
        "generatedLockBytes": len(generated), "gitDiffSha256": policy.digest(diff), "gitDiffBytes": len(diff),
        "startedAt": started, "capturedAt": now_utc(), "imageBuilt": False, "productionAuthorized": False}
    files = {"pnpm-lock.yaml": generated, "lock.diff": diff, "lock-diagnostic.json": policy.encode(record)}
    policy.need(sum(map(len, files.values())) <= policy.ARTIFACT_BYTES - 65536, "v110.unvalidated_lock_cap")
    out = Path(env["RUNNER_TEMP"]) / "v110-lock-diagnostic"
    policy.need(not out.exists(), "v110.diagnostic_fresh")
    for name, raw in files.items():
        private_write(out / name, raw)


def derive(pipeline, source, bindings, request, rraw, event, env, context, head):
    import lockfile_policy_v110 as lock_policy
    policy.need(request["phase"] == "lock-preparation", "v110.lock_phase")
    read, _ = source_binding(pipeline, source, bindings, request, context["deadlineEpoch"])
    inputs, before = source_inputs(source, read), regular(source / "pnpm-lock.yaml", 16 * 1024 * 1024)
    started = now_utc()
    lock_policy.validate_source_inputs(inputs, started)
    lock_policy.verify_bootstrap_age(before, lock_policy.PublicRegistry(context["deadlineEpoch"]), started)
    guard = lambda **kw: fresh_guard(pipeline, source, bindings, request, rraw, event, env,
        context["deadlineEpoch"], head, **kw)
    with tempfile.TemporaryDirectory(prefix="v110-lock-", dir=env["RUNNER_TEMP"]) as temporary:
        home = Path(temporary); child_env = process_owner.clean_env(home, env)
        guard(); process_owner.resource_check(source)
        bootstrap(home, child_env, pipeline, context, env["V110_CODE_MANIFEST_SHA256"])
        guard()
        # Ignore both lifecycle scripts and a potential project pnpmfile hook:
        # no candidate code may precede the complete selected-closure check.
        result = process_owner.phase_process(["pnpm", "install", "--lockfile-only", "--ignore-scripts",
            "--ignore-pnpmfile", "--no-frozen-lockfile"], source, child_env, context, "lock-derivation", 0)
        settled(result)
    changed = tracked_changes(read, changed_lock=True)
    policy.need(not read("ls-files", "--others", "--exclude-standard").strip(), "v110.lock_only_delta")
    generated = regular(source / "pnpm-lock.yaml", 16 * 1024 * 1024)
    diff = read("diff", "--no-ext-diff", "--no-textconv", "--binary", "HEAD", "--", "pnpm-lock.yaml")
    retain_unvalidated_lock(generated, diff, request, env, started)
    security = lock_policy.verify_generated_lock(before, generated, inputs,
        lock_policy.PublicRegistry(context["deadlineEpoch"]), now_utc())
    guard(changed_lock=True)
    receipt = {"schema": policy.GENERATION_SCHEMA, "status": "derived_only", "sourceSha": request["source"]["sourceSha"],
        "sourceTree": request["source"]["sourceTree"], "pipelineHead": head, "runId": env["GITHUB_RUN_ID"], "runAttempt": 1,
        "packageSha256": policy.digest(inputs["package.json"]), "workspaceSha256": policy.digest(inputs["pnpm-workspace.yaml"]),
        "sourceLockSha256": policy.digest(before), "generatedLockSha256": policy.digest(generated),
        "ledgerSha256": request["source"]["fileSha256"][policy.LEDGER], "nodeVersion": "24.22.1", "pnpmVersion": "12.15.0",
        "changedPaths": changed, "gitDiffSha256": policy.digest(diff), "allOtherTrackedEntriesUnchanged": True,
        "startedAt": started, "finishedAt": now_utc(), "exitCode": 0, "timedOut": False, "cleanupSettled": True,
        "imageBuilt": False, "qualified": False, "productionAuthorized": False, "lockSecurity": security}
    files = {"pnpm-lock.yaml": generated, "lock.diff": diff, "generation.json": policy.encode(receipt)}
    policy.need(sum(map(len, files.values())) <= policy.ARTIFACT_BYTES - 65536, "v110.lock_artifact_cap")
    out = Path(env["RUNNER_TEMP"]) / "v110-lock-artifact"
    policy.need(not out.exists(), "v110.lock_artifact_fresh")
    for name, raw in files.items():
        private_write(out / name, raw)
    emit({"schema": policy.GENERATION_SCHEMA, "status": "derived_only", "runId": env["GITHUB_RUN_ID"],
        "receiptSha256": policy.digest(files["generation.json"]), "artifactBytes": sum(map(len, files.values())),
        "imageBuilt": False, "productionAuthorized": False})


def run_profile(pipeline, source, bindings, request, profile, rraw, event, env, context, head):
    import lockfile_policy_v110 as lock_policy
    import source_validation_selection_v110 as selection
    policy.need(request["phase"] == "validation" and profile in policy.PROFILES, "v110.profile")
    read, _ = source_binding(pipeline, source, bindings, request, context["deadlineEpoch"])
    paths = read("ls-files", "-z").decode().rstrip("\0").split("\0")
    selection.coverage(paths)
    selection.verify_mocked_units(lambda p: regular(source / p, 2 * 1024 * 1024))
    if profile == "pipeline-contracts":
        selection.verify_pipeline_contract_files(lambda p: regular(pipeline / p, 512 * 1024))
    inputs = source_inputs(source, read)
    lock_policy.validate_source_inputs(inputs, now_utc())
    lock_policy.verify_bootstrap_age(regular(source / "pnpm-lock.yaml", 16 * 1024 * 1024),
        lock_policy.PublicRegistry(context["deadlineEpoch"]), now_utc())
    planned = selection.commands(pipeline, source, profile, paths, request, bindings)
    policy.need(type(planned) is list and bool(planned) and all(type(a) is list and a and
        all(type(v) is str and "\0" not in v for v in a) for a in planned), "v110.fixed_profile_commands")
    guard = lambda: fresh_guard(pipeline, source, bindings, request, rraw, event, env, context["deadlineEpoch"], head)
    with tempfile.TemporaryDirectory(prefix="v110-profile-", dir=env["RUNNER_TEMP"]) as temporary:
        home = Path(temporary); child_env = process_owner.clean_env(home, env)
        if profile == "pipeline-contracts":
            child_env["V110_TEST_SOURCE"] = str(source.resolve(strict=True))
        guard(); process_owner.resource_check(source)
        bootstrap(home, child_env, pipeline, context, env["V110_CODE_MANIFEST_SHA256"])
        guard()
        result = process_owner.phase_process(["pnpm", "install", "--frozen-lockfile"], source, child_env, context, "frozen-install", 0)
        settled(result)
        outcomes = []
        for ordinal, argv in enumerate(planned):
            guard()
            result = process_owner.phase_process(argv, source, child_env, context, "source-command", ordinal)
            policy.need(getattr(result, "cleanup_settled", None) is True and
                getattr(result, "timed_out", None) is False, "v110.source_process_unsettled")
            outcomes.append(result.returncode)
        policy.need(outcomes and all(type(code) is int and code == 0 for code in outcomes), "v110.source_profile_failed")
        guard()
    emit({"schema": "openclaw.v110.profile-result.v1", "profile": profile, "status": "passed",
        "sourceSha": request["source"]["sourceSha"], "sourceTree": request["source"]["sourceTree"],
        "imageBuilt": False, "qualified": False, "productionAuthorized": False})


def result_record(request, rraw, env, head, admission, matrix, jobs=None):
    policy.need(request["phase"] == "validation" and admission in ("success", "failure", "cancelled", "skipped") and
        matrix in ("success", "failure", "cancelled", "skipped"), "v110.final_results")
    passed = admission == matrix == "success"
    if passed:
        policy.need(type(jobs) is list, "v110.native_final_jobs")
        by_name = {job.get("name"): job for job in jobs}
        expected = set(CURRENT_JOBS["validation"])
        policy.need(len(jobs) == len(expected) and set(by_name) == expected and
            all(by_name[name].get("status") == "completed" and by_name[name].get("conclusion") == "success"
                for name in expected - {"final"}), "v110.all_fresh_profiles_required")
    return {"schema": "openclaw.v110.source-validation-result.v1", "repository": policy.REPOSITORY,
        "campaignId": policy.CAMPAIGN, "runId": env["GITHUB_RUN_ID"], "runAttempt": 1,
        "pipelineHead": head, "requestSha256": policy.digest(rraw),
        "sourceSha": request["source"]["sourceSha"], "sourceTree": request["source"]["sourceTree"],
        "generation": request["generation"], "status": "passed" if passed else "failed",
        "selectedProfiles": list(policy.PROFILES), "all15FreshProfilesRequired": True,
        "oldCoverageTransferred": False, "sourceQualificationOnly": True,
        "imageBuilt": False, "nativeImageExecuted": False, "qualified": False, "productionAuthorized": False}


def command(args, env):
    admission = args.command == "admit"
    bindings, request, _braw, rraw, event = read_inputs(args.pipeline_dir, env, admission=admission)
    policy.need(args.command != "run" or args.profile in policy.PROFILES, "v110.named_profile")
    end = deadline(env, bindings, request, args.profile, final=args.command == "finalize")
    context = context_for(request, args.profile or request["phase"], end)
    verify_code_files(args.pipeline_dir, bindings)
    workflow_role_binding(args.pipeline_dir, bindings, request, env)
    api = native.API(env.get("GH_TOKEN", ""), end)
    head = live_pr(api, event, env, bindings)
    live_source(api, request)
    current = api("/repos/" + policy.REPOSITORY + "/actions/runs/" + env["GITHUB_RUN_ID"])
    policy.need(native.public_run(current) and current.get("head_sha") == head and
        current.get("head_branch") == policy.PIPELINE_BRANCH and current.get("event") == "pull_request" and
        current.get("path") == policy.WORKFLOW and current.get("name") == policy.CAMPAIGN,
        "v110.current_native_run_identity")
    collect_stage(api, bindings, request, env, time.time())
    finite_fetch(args.pipeline_dir, args.source_dir if args.command == "fetch-closure" else None,
        bindings, request, env, context, head)
    tree = code_binding(args.pipeline_dir, bindings, head, end)
    workflow_merge_binding(args.pipeline_dir, env, head, tree, end)
    if args.command not in ("admit", "finalize"):
        check_outputs(env, request, rraw, head)
    fresh_guard(args.pipeline_dir, None, bindings, request, rraw, event, env, end, head)
    if request["phase"] == "validation":
        validate_generation_provider(args.pipeline_dir, bindings, request, api, time.time())
    if args.command == "admit":
        outputs(env, {"source_sha": request["source"]["sourceSha"], "request_sha": policy.digest(rraw),
            "pipeline_head": head, "run_id": env["GITHUB_RUN_ID"], "phase": request["phase"]})
        emit({"schema": "openclaw.v110.admission.v1", "status": "admitted", "pipelineHead": head,
            "pipelineTree": tree, "sourceSha": request["source"]["sourceSha"], "requestSha256": policy.digest(rraw),
            "runId": env["GITHUB_RUN_ID"], "imageBuilt": False, "productionAuthorized": False})
        return 0
    if args.command == "fetch-closure":
        policy.need(args.source_dir is not None, "v110.source_directory_required")
        source_binding(args.pipeline_dir, args.source_dir, bindings, request, end)
        fresh_guard(args.pipeline_dir, args.source_dir, bindings, request, rraw, event, env, end, head)
        emit({"schema": "openclaw.v110.closed-local-inputs.v1", "status": "verified", "imageBuilt": False})
        return 0
    if args.command == "derive":
        policy.need(args.source_dir is not None, "v110.source_directory_required")
        derive(args.pipeline_dir, args.source_dir, bindings, request, rraw, event, env, context, head)
        return 0
    if args.command == "run":
        policy.need(args.source_dir is not None, "v110.source_directory_required")
        env = dict(env, V110_CURRENT_PROFILE=args.profile)
        run_profile(args.pipeline_dir, args.source_dir, bindings, request, args.profile, rraw, event, env, context, head)
        return 0
    record = result_record(request, rraw, env, head, env.get("V110_ADMISSION_RESULT"),
        env.get("V110_SOURCE_RESULT"), native.jobs_for(api, current))
    private_write(Path(env["RUNNER_TEMP"]) / "v110-source-result/source-validation.json", policy.encode(record))
    emit(record)
    return 0 if record["status"] == "passed" else 1


def main(argv=None, env=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("admit", "fetch-closure", "derive", "run", "finalize"))
    parser.add_argument("--pipeline-dir", type=Path)
    parser.add_argument("--source-dir", type=Path)
    parser.add_argument("--profile", choices=policy.PROFILES)
    args = parser.parse_args(argv)
    env = os.environ if env is None else env
    try:
        hosted_environment(env)
        workspace = Path(env["GITHUB_WORKSPACE"]).absolute()
        args.pipeline_dir = args.pipeline_dir or workspace / "pipeline"
        args.source_dir = args.source_dir or (workspace / "source" if args.command in ("fetch-closure", "derive", "run") else None)
        policy.need(args.pipeline_dir.absolute() == workspace / "pipeline" and
            (args.source_dir is None or args.source_dir.absolute() == workspace / "source") and
            workspace.resolve(strict=True) == workspace and args.pipeline_dir.resolve(strict=True) == args.pipeline_dir.absolute(),
            "v110.fixed_workspace_paths")
        with process_owner.profile_signals():
            return command(args, env)
    except (policy.Refusal, booking.Refusal, native.policy.Refusal, process_owner.release.Refusal,
            OSError, ValueError, TypeError, KeyError, subprocess.CalledProcessError, subprocess.TimeoutExpired,
            process_owner.ProfileInterrupted) as error:
        code = str(error)
        if not re.fullmatch(r"v(?:[0-9]+|110)\.[A-Za-z0-9_.]+", code):
            code = "v110.runtime_refused"
        failure = {"schema": "openclaw.v110.source-refusal.v1", "status": "refused", "phase": args.command,
            "code": code, "errorClass": type(error).__name__, "imageBuilt": False, "productionAuthorized": False}
        emit(failure)
        # An always-run finalizer must retain a truthful bounded failure even
        # when its provider read fails. It can never emit a qualified/pass result.
        if args.command == "finalize" and env.get("GITHUB_ACTIONS") == "true" and env.get("RUNNER_TEMP"):
            try:
                private_write(Path(env["RUNNER_TEMP"]) / "v110-source-result/source-validation.json", policy.encode(failure))
            except OSError:
                pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
