#!/usr/bin/env python3
"""Bounded, public GitHub source-validation campaign; never an execution approval.

Only the reviewed fixed request selects a round and named profiles. PR text,
dispatch inputs, arbitrary commands, refs and URLs are not an input surface.
"""

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request

import preflight
import release

REPOSITORY = "fr-meyer/openclaw"
CAMPAIGN = "future-v108-source-validation-20261027"
SOURCE = "61f924bdb7ed4f837096c87120087919ff0a6bdf"
TREE = "416a77f6b89110883c41652f64c602ab989662d7"
# The PR snapshot and actual target branch tip are distinct retained identities.
BASE = "a65f70c5dad17b39bc3ee26ba92cde6d00bfb259"
TARGET_BRANCH_TIP = "918890b9f72b2d0372995362e8ea3088e0f87431"
APPROVAL_DEADLINE = "2026-10-29T00:03:19Z"
SKIPPED_RUN_ID = "40607329263"
SKIPPED_HEAD = "fb136445c313fdd94b2e3a615acb2a16ea9bf1e3"
SKIPPED_WORKFLOW_SHA256 = "717834ccb7a9ba27622d0981fc61875a109219b906350a825ea0ee2d04e8d13f"
BRANCH = "task/v107-source-binding"
BASE_BRANCH = "release-pipeline/v105-image-only-20261024"
WORKFLOW = ".github/workflows/future-v108-source-validation.yml"
CANDIDATE = "scripts/fork-release/candidates/v2026.10.8-source-only"
REQUEST = CANDIDATE + "/source-request.json"
PROFILE_MINUTES = {
    "dependency": 60, "types-production": 90, "types-tests": 90,
    "types-scripts": 90, "workboard-1": 60, "workboard-2": 60,
    "models-1": 60, "models-2": 60, "sqlite": 60, "doctor": 60,
    "memory": 60, "pipeline-contracts": 30,
}
INITIAL_MINUTES = 800  # 780 matrix + admission 15 + final 5.
CAMPAIGN_MINUTES = 1800
ANCILLARY_MINUTES = 500
RESERVE_MINUTES = 140
MAX_CORRECTION_MINUTES = 180
HEX256 = re.compile(r"[0-9a-f]{64}\Z")
RUN_ID = re.compile(r"[1-9][0-9]{0,19}\Z")
TEST_PATH = re.compile(r"[A-Za-z0-9_./@+-]+\.(?:test|e2e)\.[cm]?[jt]s\Z")


def need(value, code):
    release.need(value, "source-validation: " + code)


def read_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def validate_request(value):
    fields = {"schema", "campaignId", "round", "profiles", "sourceSha", "sourceTree",
              "manifestSha256", "inventorySha256", "priorRunIds"}
    need(type(value) is dict and set(value) == fields, "request fields")
    need(value["schema"] == "openclaw.fork-source-validation-request.v1", "request schema")
    need(value["campaignId"] == CAMPAIGN, "campaign identity")
    need(value["sourceSha"] == SOURCE and value["sourceTree"] == TREE, "frozen source")
    need(type(value["round"]) is int and 0 <= value["round"] <= 2, "round limit")
    for key in ("manifestSha256", "inventorySha256"):
        need(release.matches(HEX256, value[key]), "request digest")
    profiles = value["profiles"]
    need(type(profiles) is list and all(type(item) is str and item in PROFILE_MINUTES
                                      for item in profiles), "named profiles only")
    need(len(profiles) == len(set(profiles)), "duplicate profile")
    if value["round"] == 0:
        need(profiles == [], "initial round is complete suite")
    else:
        need(bool(profiles) and sum(PROFILE_MINUTES[p] for p in profiles) + 20 <=
             MAX_CORRECTION_MINUTES, "targeted correction minute cap")
    prior = value["priorRunIds"]
    need(type(prior) is list and len(prior) == value["round"] and
         all(release.matches(RUN_ID, item) for item in prior) and
         len(prior) == len(set(prior)), "prior rounds")
    return value


def profiles_for(request):
    return list(PROFILE_MINUTES) if request["round"] == 0 else request["profiles"]


def round_minutes(request):
    return 20 + sum(PROFILE_MINUTES[p] for p in profiles_for(request))


def validate_event(event, env):
    need(env.get("GITHUB_ACTIONS") == "true" and env.get("RUNNER_OS") == "Linux" and
         env.get("RUNNER_ENVIRONMENT") == "github-hosted", "public hosted Linux only")
    need(env.get("GITHUB_EVENT_NAME") == "pull_request" and env.get("GITHUB_RUN_ATTEMPT") == "1",
         "PR event and first attempt required")
    need(env.get("GITHUB_REPOSITORY") == REPOSITORY and
         env.get("GITHUB_REF") == "refs/pull/28/merge", "repository/ref")
    need(event.get("action") in ("opened", "reopened", "synchronize"), "event action")
    pr = event.get("pull_request", {})
    repo = event.get("repository", {})
    need(event.get("number") == 28 and pr.get("number") == 28 and
         pr.get("state") == "open" and pr.get("draft") is True, "open draft PR28")
    need(repo.get("full_name") == REPOSITORY and repo.get("private") is False,
         "public repository")
    head, base = pr.get("head", {}), pr.get("base", {})
    need(head.get("repo", {}).get("full_name") == REPOSITORY and
         head.get("repo", {}).get("private") is False and head.get("ref") == BRANCH and
         release.matches(release.SHA, head.get("sha")), "same-repository reviewed head")
    need(base.get("repo", {}).get("full_name") == REPOSITORY and
         base.get("ref") == BASE_BRANCH and base.get("sha") == BASE, "fixed base")
    need(env.get("GITHUB_WORKFLOW_REF") == REPOSITORY + "/" + WORKFLOW + "@refs/pull/28/merge"
         and release.matches(release.SHA, env.get("GITHUB_WORKFLOW_SHA")), "workflow identity")
    need(release.matches(RUN_ID, env.get("GITHUB_RUN_ID")), "run identity")
    return head["sha"]


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.DEVNULL)


def code_binding(pipeline, source, event, env):
    head = validate_event(event, env)
    need(git(pipeline, "rev-parse", "HEAD").decode().strip() == head, "pipeline checkout head")
    if source is not None:
        need(git(source, "rev-parse", "HEAD").decode().strip() == SOURCE and
             git(source, "rev-parse", "HEAD^{tree}").decode().strip() == TREE, "source checkout/tree")
    acquire_workflow_commit(pipeline, head, env)
    need(git(pipeline, "rev-parse", env["GITHUB_WORKFLOW_SHA"] + "^1").decode().strip() ==
         TARGET_BRANCH_TIP, "workflow merge target parent")
    # pull_request workflow code can be a synthetic merge. Bind every executable
    # owner used by this driver to reviewed head bytes before source code runs.
    for path in (WORKFLOW, "scripts/fork-release/source_validation_v108.py",
                 "scripts/fork-release/preflight.py", "scripts/fork-release/release.py",
                 "scripts/fork-release/native_tests.mjs"):
        actual = (pipeline / path).read_bytes()
        need(actual == git(pipeline, "show", head + ":" + path) ==
             git(pipeline, "show", env["GITHUB_WORKFLOW_SHA"] + ":" + path),
             "reviewed workflow/code bytes")


def acquire_workflow_commit(pipeline, head, env):
    """The PR merge workflow object need not belong to the checked-out head DAG."""
    commit = env.get("GITHUB_WORKFLOW_SHA")
    need(release.matches(release.SHA, commit), "literal workflow commit required")
    try:
        present = git(pipeline, "cat-file", "-t", commit).strip() == b"commit"
    except subprocess.CalledProcessError:
        present = False
    if not present:
        child_env = {"PATH": env["PATH"], "GIT_TERMINAL_PROMPT": "0",
                     "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}
        subprocess.run(["git", "-C", str(pipeline), "-c", "credential.helper=",
                        "-c", "maintenance.auto=0", "-c", "gc.auto=0", "fetch", "--no-tags",
                        "https://github.com/fr-meyer/openclaw.git", commit],
                       check=True, env=child_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        need(git(pipeline, "rev-parse", "FETCH_HEAD^{commit}").decode().strip() == commit,
             "fetched workflow commit changed")
    need(git(pipeline, "cat-file", "-t", commit).strip() == b"commit" and
         git(pipeline, "rev-parse", "HEAD").decode().strip() == head,
         "workflow acquisition changed checkout")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise release.Refusal("source-validation: API redirect refused")


def api_json(path, token):
    need(path.startswith("/repos/" + REPOSITORY + "/") and "\n" not in path,
         "fixed API route")
    request = urllib.request.Request("https://api.github.com" + path, headers={
        "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": CAMPAIGN, "Authorization": "Bearer " + token,
    })
    with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
        raw = response.read(4 * 1024 * 1024 + 1)
    need(len(raw) <= 4 * 1024 * 1024, "bounded API response")
    return read_json(raw)


def content_at(api, path, commit):
    need(release.matches(release.SHA, commit) and path in (REQUEST, WORKFLOW), "fixed content identity")
    obj = api("/repos/" + REPOSITORY + "/contents/" + path + "?ref=" + commit)
    need(obj.get("type") == "file" and obj.get("encoding") == "base64" and
         type(obj.get("size")) is int and 0 < obj["size"] <= 65536, "bounded Git-backed content")
    raw = base64.b64decode(obj["content"], validate=False)
    need(len(raw) == obj["size"], "content size")
    return raw


def timestamp(value):
    need(type(value) is str and value.endswith("Z"), "API timestamp")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def observed_minutes(jobs, expected):
    need(type(jobs) is dict and type(jobs.get("total_count")) is int and
         jobs["total_count"] <= 100 and jobs["total_count"] == len(jobs.get("jobs", [])),
         "complete job history")
    limits = {"admission": 15, "final": 5, "source": 0, **{
        "source (" + p + ")": PROFILE_MINUTES[p] for p in expected}}
    seen, minutes, admitted = set(), 0, False
    for job in jobs["jobs"]:
        name = job.get("name")
        need(name in limits and name not in seen and job.get("status") == "completed" and
             job.get("run_attempt") == 1, "unexpected/duplicate/incomplete job")
        seen.add(name)
        if name == "admission":
            admitted = job.get("conclusion") == "success"
        # Skipped jobs have no runner. Acquired jobs must be standard public Ubuntu.
        if job.get("conclusion") == "skipped" and not job.get("runner_id"):
            continue
        need(name != "source" and job.get("started_at") is not None, "missing job time")
        labels = job.get("labels", [])
        need("ubuntu-24.04" in labels and "self-hosted" not in labels and
             job.get("runner_group_name") == "GitHub Actions", "standard Ubuntu runner")
        seconds = (timestamp(job["completed_at"]) - timestamp(job["started_at"])).total_seconds()
        need(0 <= seconds <= (limits[name] + 1) * 60, "job minute ceiling")
        minutes += math.ceil(seconds / 60)
    need("admission" in seen and "final" in seen, "missing campaign jobs")
    if admitted:
        need(seen == set(limits) - {"source"}, "missing admitted profile jobs")
    return minutes


def skipped_admission(run, request, api):
    """Retain only the positively observed, fixed whole-skipped admission."""
    need(str(run.get("id")) == SKIPPED_RUN_ID and run.get("head_sha") == SKIPPED_HEAD and
         run.get("status") == "completed" and run.get("conclusion") == "skipped" and
         run.get("repository", {}).get("full_name") == REPOSITORY and
         run.get("repository", {}).get("private") is False and
         run.get("head_repository", {}).get("private") is False,
         "fixed skipped admission identity")
    previous = validate_request(read_json(content_at(api, REQUEST, SKIPPED_HEAD)))
    need(previous == dict(request, round=0, profiles=[], priorRunIds=[]),
         "fixed skipped initial request")
    need(hashlib.sha256(content_at(api, WORKFLOW, SKIPPED_HEAD)).hexdigest() ==
         SKIPPED_WORKFLOW_SHA256, "fixed skipped workflow digest")
    jobs = api("/repos/" + REPOSITORY + "/actions/runs/" + SKIPPED_RUN_ID +
               "/jobs?filter=all&per_page=100")
    need(type(jobs.get("total_count")) is int and jobs["total_count"] == 3 and
         type(jobs.get("jobs")) is list and len(jobs["jobs"]) == 3,
         "complete skipped admission jobs")
    names = {"admission", "source (${{ matrix.profile }})", "final"}
    seen = set()
    for job in jobs["jobs"]:
        name = job.get("name")
        need(name in names and name not in seen and job.get("status") == "completed" and
             job.get("conclusion") == "skipped" and job.get("run_attempt") == 1 and
             "runner_id" in job and (job["runner_id"] is None or
                                     type(job["runner_id"]) is int and job["runner_id"] == 0) and
             "runner_name" in job and job["runner_name"] is None and
             "steps" in job and type(job["steps"]) is list and job["steps"] == [],
             "skipped admission acquired runner or steps")
        seen.add(name)
    need(seen == names, "missing skipped admission job")
    return {"runId": SKIPPED_RUN_ID, "headSha": SKIPPED_HEAD, "status": "skipped",
            "bookedRunnerMinutes": 0, "observedRunnerMinutes": 0}


def history_checks(request, event, env, pipeline, api):
    live = api("/repos/" + REPOSITORY + "/pulls/28")
    # Ignore PR prose entirely and revalidate only the same structured fields.
    current = dict(event, pull_request=live)
    need(validate_event(current, env) == event["pull_request"]["head"]["sha"], "live head changed")
    target = api("/repos/" + REPOSITORY + "/git/ref/heads/" + BASE_BRANCH)
    need(target.get("ref") == "refs/heads/" + BASE_BRANCH and
         target.get("object", {}).get("type") == "commit" and
         target["object"].get("sha") == TARGET_BRANCH_TIP, "fixed live target branch tip")
    listing = api("/repos/" + REPOSITORY + "/actions/workflows/" + Path(WORKFLOW).name +
                  "/runs?event=pull_request&per_page=100")
    need(type(listing.get("total_count")) is int and listing["total_count"] <= 100 and
         listing["total_count"] == len(listing.get("workflow_runs", [])), "complete run history")
    runs = listing["workflow_runs"]
    known = [SKIPPED_RUN_ID, *request["priorRunIds"], env["GITHUB_RUN_ID"]]
    need(len(known) == len(set(known)) and len(runs) == len(known) and {str(run.get("id")) for run in runs} == set(known),
         "unlisted/duplicate campaign round")
    by_id = {str(run["id"]): run for run in runs}
    booked, observed, starts, retained_skipped = 0, 0, [], []
    workflow = (pipeline / WORKFLOW).read_bytes()
    for index, run_id in enumerate(known, start=-1):
        run = by_id[run_id]
        need(run.get("event") == "pull_request" and run.get("path") == WORKFLOW and
             run.get("display_title") == CAMPAIGN and run.get("run_attempt") == 1 and
             run.get("head_repository", {}).get("full_name") == REPOSITORY and
             run.get("head_branch") == BRANCH and
             [pr.get("number") for pr in run.get("pull_requests", [])] == [28], "run identity/attempt")
        starts.append(timestamp(run["created_at"]))
        if run_id == SKIPPED_RUN_ID:
            retained_skipped.append(skipped_admission(run, request, api))
            continue
        if run_id == env["GITHUB_RUN_ID"]:
            need(run.get("head_sha") == event["pull_request"]["head"]["sha"] and
                 run.get("status") == "in_progress", "current run identity")
            previous = request
        else:
            need(run.get("status") == "completed" and run.get("conclusion") in
                 ("success", "failure", "cancelled", "timed_out", "action_required", "neutral", "skipped"),
                 "previous run must be terminal")
            previous = validate_request(read_json(content_at(api, REQUEST, run["head_sha"])))
            need(previous["round"] == index and previous["priorRunIds"] == request["priorRunIds"][:index],
                 "ordered prior round request")
            need(content_at(api, WORKFLOW, run["head_sha"]) == workflow, "campaign workflow changed")
            subprocess.run(["git", "-C", str(pipeline), "merge-base", "--is-ancestor",
                            run["head_sha"], event["pull_request"]["head"]["sha"]],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            jobs = api("/repos/" + REPOSITORY + "/actions/runs/" + run_id +
                       "/jobs?filter=all&per_page=100")
            measured = observed_minutes(jobs, profiles_for(previous))
            need(measured <= round_minutes(previous), "prior run budget")
            observed += measured
        booked += round_minutes(previous)
    need(starts == sorted(starts) and (starts[-1] - starts[0]).total_seconds() <= 86400 and
         0 <= (datetime.now(timezone.utc) - starts[0]).total_seconds() <= 86400, "24 hour campaign window")
    deadline = min(int(starts[0].timestamp()) + 86400,
                   int(timestamp(APPROVAL_DEADLINE).timestamp()))
    need(datetime.now(timezone.utc).timestamp() <= deadline, "approval campaign deadline")
    need(booked + ANCILLARY_MINUTES + RESERVE_MINUTES <= CAMPAIGN_MINUTES,
         "campaign runner-minute ceiling")
    return {"bookedRunnerMinutes": booked, "observedPriorRunnerMinutes": observed,
            "ancillaryRunnerMinutes": ANCILLARY_MINUTES, "reserveRunnerMinutes": RESERVE_MINUTES,
            "campaignRunnerMinuteCeiling": CAMPAIGN_MINUTES,
            "deadlineEpoch": deadline, "retainedSkippedAdmissions": retained_skipped}


def metadata(pipeline):
    directory = pipeline / CANDIDATE
    request = validate_request(read_json((pipeline / REQUEST).read_bytes()))
    manifest, manifest_hash = release.manifest_at(directory / "manifest.json")
    need(request["manifestSha256"] == manifest_hash and
         request["inventorySha256"] == preflight.digest(directory / "patch-inventory.json"),
         "request metadata hashes")
    need(manifest["source"]["commit"] == SOURCE and manifest["source"]["tree"] == TREE and
         manifest["productionEligible"] is False, "source-only manifest")
    return request, manifest, manifest_hash


def source_preflight(pipeline, source, manifest, manifest_hash):
    return preflight.inventory_at(pipeline / CANDIDATE / "patch-inventory.json", manifest,
                                  manifest_hash, source_dir=source)


def fetch_closure(pipeline, source):
    """CI only: acquire exact public objects declared by the maintained inventory owner."""
    request, manifest, manifest_hash = metadata(pipeline)
    inventory, _ = preflight.inventory_at(pipeline / CANDIDATE / "patch-inventory.json",
                                         manifest, manifest_hash)
    safe_env = {"PATH": os.environ["PATH"], "GIT_TERMINAL_PROMPT": "0",
                "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}
    commits = preflight.history_commits(inventory, manifest)
    for commit in commits:
        need(release.matches(release.SHA, commit), "closure commit")
        if subprocess.run(["git", "-C", str(source), "cat-file", "-e", commit + "^{commit}"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
            subprocess.run(["git", "-C", str(source), "-c", "credential.helper=", "fetch", "--no-tags",
                            "https://github.com/fr-meyer/openclaw.git", commit], check=True, env=safe_env)
    need(inventory["upstream"]["tag"] == "v2026.10.8", "fixed upstream tag")
    subprocess.run(["git", "-C", str(source), "-c", "credential.helper=", "fetch", "--no-tags",
                    "https://github.com/openclaw/openclaw.git", "refs/tags/v2026.10.8"],
                   check=True, env=safe_env)
    source_preflight(pipeline, source, manifest, manifest_hash)


def selected_tests(paths, profile):
    """Complete fixed-source owner families; maintained test-projects owns routing."""
    tests = sorted(path for path in paths if TEST_PATH.fullmatch(path) and
                   not any(part in ("", ".", "..") for part in path.split("/")) and
                   not re.search(r"(?:^|[./-])live(?:[./-]|$)", path))
    if profile.startswith("workboard-"):
        family = [p for p in tests if p.startswith("extensions/workboard/")]
        return family[int(profile[-1]) - 1::2]
    if profile.startswith("models-"):
        family = [p for p in tests if (
            p.startswith("src/agents/") and re.search(
                r"(?:^|/)(?:model|models|configured-model|configured-provider|utility-completion|"
                r"result-fallback-classifier|subagent-spawn-child-plan\.sandbox-cli)", p)
            or p.startswith("extensions/codex/src/app-server/") and re.search(
                r"(?:model|provider-capabilities|inference-routing)", p))]
        return family[int(profile[-1]) - 1::2]
    if profile == "sqlite":
        return [p for p in tests if (
            p.startswith(("src/state/", "src/tasks/")) or
            p.startswith(("src/infra/", "src/plugins/", "src/gateway/")) and re.search(
                r"(?:sqlite|managed-task-flow|loader\.(?:gateway-bindings|native-module-loader))", p))]
    if profile == "doctor":
        return [p for p in tests if (
            p.startswith("src/commands/doctor") or p.startswith("src/flows/doctor") or
            p.startswith("extensions/codex/src/migration/"))]
    if profile == "memory":
        return [p for p in tests if p.startswith(("extensions/memory-wiki/", "extensions/memory-core/"))]
    return []


def clean_env(home, parent):
    # An allowlist, not secret-name redaction. Candidate lifecycle/tests never
    # inherit the Actions token, credential files, production HOME or cloud env.
    env = {key: parent[key] for key in ("PATH", "LANG", "LC_ALL", "TZ") if key in parent}
    env.update({"HOME": str(home), "TMPDIR": str(home / "tmp"), "CI": "true",
                "XDG_CONFIG_HOME": str(home / "config"), "XDG_CACHE_HOME": str(home / "cache"),
                "OPENCLAW_STATE_DIR": str(home / "state"), "OPENCLAW_CONFIG_PATH": str(home / "config.json"),
                "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_TERMINAL_PROMPT": "0", "npm_config_userconfig": "/dev/null",
                "npm_config_registry": "https://registry.npmjs.org/"})
    for child in ("tmp", "config", "cache", "state"):
        (home / child).mkdir(mode=0o700, exist_ok=True)
    return env


def commands(pipeline, source, profile, paths):
    need(profile in PROFILE_MINUTES, "named profile required")
    if profile.startswith("types-"):
        return [["pnpm", {"types-production": "tsgo:prod", "types-tests": "tsgo:test",
                          "types-scripts": "tsgo:scripts"}[profile]]]
    if profile == "dependency":
        native = sorted(p for p in paths if p.startswith("test/") and p.endswith(".test.mjs") and
                        p.rsplit("/", 1)[-1] in {
                            "zod-container-bounds.test.mjs", "a2ui-native-zod-regression.test.mjs",
                            "discord-native-zod-regression.test.mjs", "body-parser-security.test.mjs",
                            "msal-parent-compat.test.mjs", "undici-security.test.mjs",
                            "mcp-nowistay-schema-compatibility.test.mjs", "mcp-nowistay-sdk-regression.test.mjs",
                            "http-cache-semantics-compat.test.mjs"})
        need(len(native) == 9, "complete dependency regression set")
        return [["pnpm", "audit"], ["pnpm", "audit", "--prod"],
                ["node", str(pipeline / "scripts/fork-release/native_tests.mjs"),
                 "--source-root", str(source), "--", *native]]
    if profile == "pipeline-contracts":
        return [["python3", "-m", "unittest", "discover", "-s", str(pipeline / "scripts/fork-release"),
                 "-p", name] for name in ("test_release.py", "test_preflight.py", "test_merge_source.py",
                                          "test_merge_source_v107.py", "test_merge_source_v108.py",
                                          "test_source_tests.py", "test_source_validation_v108.py")]
    tests = selected_tests(paths, profile)
    need(bool(tests), "empty owner family")
    return [["node", "--import", "./scripts/tsx.mjs", "scripts/test-projects.mts", *tests]]


def summarize(data, env):
    raw = json.dumps(data, sort_keys=True)
    need(len(raw.encode()) <= 65536, "bounded summary")
    print(raw)
    if env.get("GITHUB_STEP_SUMMARY"):
        with open(env["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as out:
            out.write("```json\n" + raw + "\n```\n")


def deadline_check(env, profile):
    need(profile in PROFILE_MINUTES and re.fullmatch(r"[0-9]{10}", env.get("SOURCE_DEADLINE_EPOCH", "")),
         "admitted campaign deadline/profile required")
    need(datetime.now(timezone.utc).timestamp() + PROFILE_MINUTES[profile] * 60 <=
         min(int(env["SOURCE_DEADLINE_EPOCH"]), int(timestamp(APPROVAL_DEADLINE).timestamp())),
         "insufficient time in approved campaign")


def resource_check(source):
    """Engineering admission floors, not a measured workload capacity claim."""
    memory = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, value = line.split(":", 1)
        if key == "MemAvailable":
            parts = value.split()
            need(len(parts) == 2 and parts[1] == "kB" and parts[0].isdigit(), "Linux memory metadata")
            memory[key] = int(parts[0]) * 1024
    facts = {"availableMemoryBytes": memory.get("MemAvailable", 0),
             "availableSourceDiskBytes": shutil.disk_usage(source).free,
             "logicalCpus": os.cpu_count() or 0}
    need(facts["availableMemoryBytes"] >= 8 * 1024 ** 3 and
         facts["availableSourceDiskBytes"] >= 8 * 1024 ** 3 and facts["logicalCpus"] >= 4,
         "standard runner below engineering resource floors")
    return facts


def run_commands(planned, cwd, env):
    # Audit failure must retain the production audit and native regressions.
    return [subprocess.run(argv, cwd=cwd, env=env, check=False).returncode for argv in planned]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("admit", "fetch-closure", "run", "finalize"))
    parser.add_argument("--pipeline-dir", type=Path, required=True)
    parser.add_argument("--source-dir", type=Path)
    parser.add_argument("--profile", choices=PROFILE_MINUTES)
    args = parser.parse_args()
    env = os.environ
    event = read_json(Path(env["GITHUB_EVENT_PATH"]).read_bytes())
    validate_event(event, env)
    request, manifest, manifest_hash = metadata(args.pipeline_dir)
    if args.command == "finalize":
        code_binding(args.pipeline_dir, None, event, env)
        passed = env.get("SOURCE_MATRIX_RESULT") == "success" and env.get("SOURCE_ADMISSION_RESULT") == "success"
        summarize({"campaignId": CAMPAIGN, "round": request["round"], "sourceSha": SOURCE,
                   "sourceTree": TREE, "status": "passed" if passed else "failed",
                   "productionAuthorized": False, "imageBuilt": False}, env)
        return 0 if passed else 1
    need(args.source_dir is not None, "source checkout required")
    code_binding(args.pipeline_dir, args.source_dir, event, env)
    if args.command in ("fetch-closure", "run"):
        profile = args.profile if args.command == "run" else env.get("SOURCE_PROFILE")
        need(profile in profiles_for(request), "profile not in admitted request")
        deadline_check(env, profile)
    if args.command == "fetch-closure":
        fetch_closure(args.pipeline_dir, args.source_dir)
        return 0
    if args.command == "admit":
        token = env.get("GH_SOURCE_READ_TOKEN", "")
        need(bool(token), "read-only API token required")
        budget = history_checks(request, event, env, args.pipeline_dir, lambda p: api_json(p, token))
        fetch_closure(args.pipeline_dir, args.source_dir)
        matrix = {"include": [{"profile": p, "minutes": PROFILE_MINUTES[p]} for p in profiles_for(request)]}
        with open(env["GITHUB_OUTPUT"], "a", encoding="utf-8") as out:
            out.write("matrix=" + json.dumps(matrix, separators=(",", ":")) + "\n")
            out.write("deadline_epoch=" + str(budget["deadlineEpoch"]) + "\n")
        summarize({"campaignId": CAMPAIGN, "round": request["round"], "sourceSha": SOURCE,
                   "sourceTree": TREE, "manifestSha256": manifest_hash, **budget,
                   "authorization": "source-validation-only", "productionAuthorized": False}, env)
        return 0
    need(args.profile in profiles_for(request), "profile not in admitted request")
    source_preflight(args.pipeline_dir, args.source_dir, manifest, manifest_hash)
    paths = git(args.source_dir, "ls-tree", "-r", "--name-only", SOURCE).decode().splitlines()
    planned = commands(args.pipeline_dir, args.source_dir, args.profile, paths)
    resources = resource_check(args.source_dir)
    summarize({"campaignId": CAMPAIGN, "profile": args.profile, "engineeringFloorsPassed": True,
               **resources}, env)
    # Each job owns a synthetic HOME, state and toolchain. No cross-run cache or
    # dependency/source/database/config artifact is exported.
    with tempfile.TemporaryDirectory(prefix="v108-source-") as directory:
        home = Path(directory)
        child_env = clean_env(home, env)
        subprocess.run(["npm", "install", "--prefix", str(home / "toolchain"), "--ignore-scripts",
                        "--no-audit", "--no-fund", "pnpm@12.15.0"], env=child_env, check=True)
        child_env["PATH"] = str(home / "toolchain/node_modules/.bin") + os.pathsep + child_env["PATH"]
        version = subprocess.check_output(["pnpm", "--version"], env=child_env, text=True).strip()
        need(version == "12.15.0", "fixed pnpm version")
        need(subprocess.check_output(["node", "--version"], env=child_env, text=True).strip() == "v24.22.1",
             "fixed Node version")
        subprocess.run(["pnpm", "install", "--frozen-lockfile"], cwd=args.source_dir, env=child_env, check=True)
        cwd = args.pipeline_dir if args.profile == "pipeline-contracts" else args.source_dir
        outcomes = run_commands(planned, cwd, child_env)
        summarize({"campaignId": CAMPAIGN, "round": request["round"], "profile": args.profile,
                   "sourceSha": SOURCE, "sourceTree": TREE, "exitCodes": outcomes,
                   "selectedTestCount": len(selected_tests(paths, args.profile)),
                   "productionAuthorized": False, "imageBuilt": False}, env)
        return int(any(outcomes))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (release.Refusal, OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError):
        # Do not print exception data from API/credential-bearing child contexts.
        print("source-validation: refused; inspect bounded structured admission/step diagnostics", file=sys.stderr)
        raise SystemExit(2)
