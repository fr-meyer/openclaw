#!/usr/bin/env python3
"""One secretless RE2JS lock derivation; no source qualification or publication."""
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
import time
import types
import urllib.error
import urllib.parse
import urllib.request

sys.dont_write_bytecode = True
CONFIG = {'pipelineParentSha': '5eb54e3c43ebf44de915574c1575c36df660847b', 'driverSha256': '16b6dbf36f4f5799f2b9cd2102831a8913571c8582b6d4891808760015154519', 'preflightSha256': '89b6ba41fc89131f33754104fdd0d3ebc08c20f252288651bc7d95038639103a', 'releaseSha256': '7d890adb43a03a44add07e8e66539bfc8319a688c8da6cef095f768a5877cb62', 'baselineSha256': 'c2438e2b10555f396f662c6fb8e142bafd61f7b32b172fd8a5cb982ccac567ec', 'knownPriorRuns': {'40616416909': 'de5b35be1531ca14394f5457ae934ad268ddb941', '40609889437': '1328661613052dfa09902e1d1d080fa8e6ccd89d', '40607329263': 'fb136445c313fdd94b2e3a615acb2a16ea9bf1e3', '40639374411': '95df4eb49204150c8aaaa9da8e2abd3112fa5972', '40647629182': '0dd3c9ef205939350f41ab2187232268c7c44ab8', '40681376480': 'de4cdb8aae20719ae95808d3cf725a4b503d6d01', '40688279536': '2946a1678e712de90727a9e599a5f2cd47ad2151', '40706982753': 'd213bb593b3e618d459dde6767bc93f716ac8493', '40804517284': 'e96941f0c8c05a45d7df32ca7e45758e12609be7', '40808362032': '774c81d7ff22f962dcdef67a7a08f565846a4986', '40816927196': '5eb54e3c43ebf44de915574c1575c36df660847b'}, 'changedPipelinePaths': ['.github/workflows/future-v108-source-validation.yml', 'scripts/fork-release/candidates/v2026.10.8-source-only/manifest.json', 'scripts/fork-release/candidates/v2026.10.8-source-only/patch-inventory.json', 'scripts/fork-release/candidates/v2026.10.8-source-only/re2js-primary-metadata.json', 'scripts/fork-release/candidates/v2026.10.8-source-only/re2js-settled-usage.json', 'scripts/fork-release/candidates/v2026.10.8-source-only/source-request.json', 'scripts/fork-release/historical_v5_test_inputs.py', 'scripts/fork-release/re2js_lock_prepare_v108.py', 'scripts/fork-release/release.py', 'scripts/fork-release/source_validation_v108.py', 'scripts/fork-release/test_historical_v5_test_inputs.py', 'scripts/fork-release/test_history_checks_v4.py', 'scripts/fork-release/test_re2js_lock_preparation_v108.py', 'scripts/fork-release/test_request_contract_v7.py', 'scripts/fork-release/test_v108_source_donor.py']}
REPOSITORY = "fr-meyer/openclaw"
WORKFLOW = ".github/workflows/future-v108-source-validation.yml"
BRANCH = "task/v107-source-binding"
SOURCE_BRANCH = "prep/v2026.10.8-remediation"
BASE_BRANCH = "release-pipeline/v105-image-only-20261024"
BASE = "a65f70c5dad17b39bc3ee26ba92cde6d00bfb259"
BASE_SOURCE = "9b0a696bf62f045889d76044f84a0c372c8dddcc"
BASE_TREE = "b5905b54f4b70f45ea58ace4feccd30031200864"
PACKAGE_SHA = "d5cb6bde3b3d5f032b09add3adcb16fb2ae6dab85ba375051376533c1ddbf8a1"
LOCK_SHA = "5e631697caa53422d40dde5ae04a7ee0d84321921891062a4f580ca11b55fc50"
BASELINE_SHA = "c2438e2b10555f396f662c6fb8e142bafd61f7b32b172fd8a5cb982ccac567ec"
DEADLINE = "2026-10-30T00:03:19Z"
CANDIDATE = "scripts/fork-release/candidates/v2026.10.8-source-only"
HELPER = "scripts/fork-release/re2js_lock_prepare_v108.py"
TEST = "scripts/fork-release/test_re2js_lock_preparation_v108.py"
TITLE = "future-v108-re2js-lock-preparation-20261029"
CLOCK = "RE2JS_LOCK_STARTED_EPOCH"
PREFIX = "v108-re2js-lock-"
CONTEXT_SCHEMA = "openclaw.v108.re2js-lock-preparation.v1"
SCHEMA = "openclaw.v108.re2js-lock-derivation.v1"
VERSION = "2.8.7"
PUBLISHED = "2026-10-17T19:21:18.170Z"
INTEGRITY = "sha512-bRSL/vn3KAmlGfGNoVpcsBXLaVvl6AbuvMMWbz0m3vBj60nj+p2/biozfBUOSBP+5XTduF6mr6IO/ZVjmqqkVQ=="
GIT_HEAD = "6ba840014b192668365271d7b1c4d2d24a4b5f83"
PARENT_INTEGRITY = "sha512-x7kkvSsAkjUSoeFjvtaBDg6W7gYNIIIo2iOVrI6JG6LjbOHXuGQjHRECKh46iJdZKyc67BUUVRA8HF961yRMxg=="
CAP = 2 * 1024 * 1024
PREP_KEYS = frozenset(("sourceSha", "sourceTree", "packageSha256", "sourceLockSha256",
    "workspaceSha256", "securityTestSha256", "ledgerSha256", "metadataProofSha256"))
CONFIG_KEYS = frozenset(("pipelineParentSha", "driverSha256", "preflightSha256",
    "releaseSha256", "baselineSha256", "knownPriorRuns", "changedPipelinePaths"))
SOURCE_FILES = {"package.json": "packageSha256", "pnpm-lock.yaml": "sourceLockSha256",
    "pnpm-workspace.yaml": "workspaceSha256", "test/v108-remediation-security.test.mjs": "securityTestSha256",
    "custom-patches/reconciliation-2026.10.8.json": "ledgerSha256"}
REGISTRY_URLS = {
    "target": "https://registry.npmjs.org/re2js/2.8.7",
    "packument": "https://registry.npmjs.org/re2js",
    "parent": "https://registry.npmjs.org/@openclaw%2fcrabline/0.1.29",
}


DONOR_SHA = "526557a4d72d10a601ba906420499421bd491818f4027201008e1a786da4a7de"


def utility_owner():
    """Only the adjacent immutable reviewed utility donor; never its operations."""
    path = Path(__file__).resolve().with_name("npm_lock_prepare_v108.py")
    observed = path.lstat()
    if not stat.S_ISREG(observed.st_mode) or path.resolve(strict=True) != path or observed.st_size > 65536:
        raise ValueError("utility.regular")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != DONOR_SHA:
        raise ValueError("utility.hash")
    owner = types.ModuleType("immutable_re2js_utility_donor")
    owner.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), owner.__dict__)
    return owner


_UTILITIES = utility_owner()
Refusal = _UTILITIES.Refusal
need, digest, encode, parse = (_UTILITIES.need, _UTILITIES.digest, _UTILITIES.encode, _UTILITIES.parse)
regular, private_write, git, public_lock_material = (_UTILITIES.regular, _UTILITIES.private_write,
    _UTILITIES.git, _UTILITIES.public_lock_material)

def utc_now(epoch=None):
    return datetime.fromtimestamp(time.time() if epoch is None else epoch, timezone.utc).isoformat(
        timespec="microseconds").replace("+00:00", "Z")


def configuration():
    value = CONFIG
    need(type(value) is dict and set(value) == CONFIG_KEYS, "config.unbound")
    need(all(type(value[k]) is str and re.fullmatch(r"[0-9a-f]{40}" if k == "pipelineParentSha"
        else r"[0-9a-f]{64}", value[k]) for k in CONFIG_KEYS -
        {"knownPriorRuns", "changedPipelinePaths"}), "config.digests")
    need(value["baselineSha256"] == BASELINE_SHA, "config.baseline")
    prior = value["knownPriorRuns"]
    need(type(prior) is dict and 0 < len(prior) < 100 and all(type(k) is str and
        re.fullmatch(r"[1-9][0-9]{0,19}", k) and type(v) is str and
        re.fullmatch(r"[0-9a-f]{40}", v) for k, v in prior.items()), "config.prior")
    paths = value["changedPipelinePaths"]
    need(type(paths) is list and paths == sorted(set(paths)) and
        {WORKFLOW, HELPER, TEST, "scripts/fork-release/source_validation_v108.py"} <= set(paths) and
        all(type(p) is str and not any(x in ("", ".", "..", ".git") for x in p.split("/")) and
            ".private" not in p and (p == WORKFLOW or p.startswith("scripts/fork-release/"))
            for p in paths), "config.paths")
    return value


def exact_paths(env):
    need(sys.platform == "linux" and env.get("GITHUB_ACTIONS") == "true" and
        env.get("RUNNER_OS") == "Linux" and env.get("RUNNER_ENVIRONMENT") == "github-hosted",
        "host.ci_only")
    workspace, temporary = Path(env["GITHUB_WORKSPACE"]), Path(env["RUNNER_TEMP"])
    need(all(p.is_absolute() and p.resolve(strict=True) == p and p.is_dir()
        for p in (workspace, temporary)), "host.paths")
    rid = env.get("GITHUB_RUN_ID", "")
    need(re.fullmatch(r"[1-9][0-9]{0,19}", rid) and env.get("GITHUB_RUN_ATTEMPT") == "1" and
        env.get("GITHUB_REPOSITORY") == REPOSITORY and env.get("GITHUB_EVENT_NAME") == "pull_request" and
        env.get("GITHUB_ACTOR") == "fr-meyer", "event.environment")
    return workspace / "pipeline", workspace / "source", temporary, rid


def clock_deadline(env, now=None):
    now = time.time() if now is None else now
    start = env.get(CLOCK, "")
    need(type(now) in (int, float) and math.isfinite(now) and
        re.fullmatch(r"[0-9]{10}", start) and int(start) <= now and now - int(start) < 2640,
        "budget.clock")
    absolute = datetime.fromisoformat(DEADLINE.replace("Z", "+00:00")).timestamp()
    need(int(start) + 2700 <= absolute, "budget.deadline")
    return int(start) + 2640


def event_binding(event):
    pr = event.get("pull_request") if type(event) is dict else None
    need(type(pr) is dict and event.get("action") in ("opened", "reopened", "synchronize") and
        event.get("number") == 28 and pr.get("number") == 28 and pr.get("draft") is True and
        pr.get("state") == "open", "event.pr")
    for key in ("head", "base"):
        repo = pr.get(key, {}).get("repo", {})
        need(repo.get("full_name") == REPOSITORY and repo.get("private") is False, "event.repo")
    need(pr["head"].get("ref") == BRANCH and pr["base"].get("ref") == BASE_BRANCH and
        pr["base"].get("sha") == BASE and
        re.fullmatch(r"[0-9a-f]{40}", pr["head"].get("sha", "")), "event.refs")
    return pr["head"]["sha"]


def load_driver(pipeline, config):
    directory = pipeline / "scripts/fork-release"
    rows = (("release", "releaseSha256"), ("preflight", "preflightSha256"),
        ("source_validation_v108", "driverSha256"))
    raw = {name: regular(directory / (name + ".py"), expected=config[key]) for name, key in rows}
    owners = {name: types.ModuleType(name) for name, _ in rows}
    missing = object()
    previous = {name: sys.modules.get(name, missing) for name in owners}
    try:
        for name, _ in rows:
            owner = owners[name]
            owner.__file__ = str(directory / (name + ".py"))
            sys.modules[name] = owner
            exec(compile(raw[name], owner.__file__, "exec"), owner.__dict__)
        return owners["source_validation_v108"]
    finally:
        for name, old in previous.items():
            if old is missing:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = old


def preparation(driver):
    pins = driver.R7_PREPARATION_PINS
    need(type(pins) is dict and set(pins) == PREP_KEYS and
        all(type(pins[k]) is str and re.fullmatch(r"[0-9a-f]{40}" if k in
            ("sourceSha", "sourceTree") else r"[0-9a-f]{64}", pins[k]) for k in pins) and
        pins["packageSha256"] == PACKAGE_SHA and pins["sourceLockSha256"] == LOCK_SHA,
        "source.preparation_pins")
    context = {"schema": CONTEXT_SCHEMA, "sourceSha": pins["sourceSha"], "sourceTree": pins["sourceTree"]}
    driver.validate_preparation_context_v7(context, pins)
    return pins, context


def code_binding(pipeline, source, head, config, pins):
    need(pipeline.resolve(strict=True) == pipeline and source.resolve(strict=True) == source and
        git(pipeline, "rev-parse", "HEAD").strip().decode() == head and
        git(pipeline, "show", "-s", "--format=%P", "HEAD").strip().decode() == config["pipelineParentSha"],
        "checkout.parent")
    changed = git(pipeline, "diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--name-only",
        config["pipelineParentSha"], "HEAD").decode().splitlines()
    need(changed == config["changedPipelinePaths"] and
        not git(pipeline, "status", "--porcelain=v1", "--untracked-files=all"), "checkout.scope")
    regular(pipeline / "scripts/fork-release/npm_lock_prepare_v108.py", expected=DONOR_SHA)
    regular(pipeline / CANDIDATE / "re2js-settled-usage.json", expected=config["baselineSha256"])
    regular(pipeline / CANDIDATE / "re2js-primary-metadata.json", expected=pins["metadataProofSha256"])
    need(git(source, "rev-parse", "HEAD").strip().decode() == pins["sourceSha"] and
        git(source, "rev-parse", "HEAD^{tree}").strip().decode() == pins["sourceTree"], "source.identity")


def source_inputs(source, pins, after=False):
    if not after:
        need(not git(source, "status", "--porcelain=v1", "--untracked-files=all"), "source.clean")
    for path, key in SOURCE_FILES.items():
        if not (after and path == "pnpm-lock.yaml"):
            regular(source / path, expected=pins[key])
    need(not any((source / name).exists() or (source / name).is_symlink()
        for name in (".pnpmfile.cjs", ".pnpmfile.mjs", ".pnpmfile.js", "pnpmfile.cjs")), "source.hook")
    for name in ("package.json", "pnpm-workspace.yaml", ".npmrc"):
        path = source / name
        if path.exists():
            raw = regular(path)
            need(not re.search(rb"(?i)pnpmfile|globalPnpmfile", raw), "source.hook")
    workspace = regular(source / "pnpm-workspace.yaml", expected=pins["workspaceSha256"])
    need(re.search(rb"(?m)^minimumReleaseAge:\s*10080\s*$", workspace) is not None,
        "source.minimum_age")
    if after:
        need(git(source, "diff", "--name-only", "--no-renames").decode().splitlines() ==
            ["pnpm-lock.yaml"] and not git(source, "diff", "--cached", "--name-only") and
            not git(source, "ls-files", "--others", "--exclude-standard"), "source.only_lock")


def _public(run):
    return all(run.get(key, {}).get("full_name") == REPOSITORY and
        run.get(key, {}).get("private") is False for key in ("repository", "head_repository"))


def checked_run(run, rid, head):
    need(type(run) is dict and type(run.get("id")) is int and str(run["id"]) == rid and
        type(run.get("run_attempt")) is int and run["run_attempt"] == 1 and _public(run) and
        run.get("event") == "pull_request" and run.get("path") == WORKFLOW and
        run.get("head_branch") == BRANCH and run.get("head_sha") == head and
        run.get("display_title") == TITLE and run.get("status") == "in_progress" and
        run.get("actor", {}).get("login") == "fr-meyer", "admission.current")


def checked_history(table, rid, head, config):
    rows = table.get("workflow_runs") if type(table) is dict else None
    need(type(rows) is list and type(table.get("total_count")) is int and
        table["total_count"] == len(rows) == len(config["knownPriorRuns"]) + 1 and
        all(type(r) is dict and type(r.get("id")) is int for r in rows) and
        len({r["id"] for r in rows}) == len(rows), "admission.history_complete")
    prior = {str(r["id"]): r for r in rows if str(r["id"]) != rid}
    need(set(prior) == set(config["knownPriorRuns"]), "admission.history_once")
    for old, expected in config["knownPriorRuns"].items():
        row = prior[old]
        need(row.get("head_sha") == expected and type(row.get("run_attempt")) is int and
            row["run_attempt"] == 1 and row.get("status") == "completed" and _public(row) and
            row.get("event") == "pull_request" and row.get("path") == WORKFLOW and
            row.get("head_branch") == BRANCH, "admission.history_binding")
    current = [r for r in rows if str(r["id"]) == rid]
    need(len(current) == 1, "admission.current_once")
    checked_run(current[0], rid, head)


def checked_job(table, rid, head):
    rows = table.get("jobs") if type(table) is dict else None
    need(type(rows) is list and len(rows) == 1 and type(table.get("total_count")) is int and
        table["total_count"] == 1, "admission.one_job")
    job = rows[0]
    need(job.get("name") == "lock-preparation" and type(job.get("id")) is int and job["id"] > 0 and
        str(job.get("run_id")) == rid and job.get("head_sha") == head and
        type(job.get("run_attempt")) is int and job["run_attempt"] == 1 and
        job.get("status") == "in_progress" and type(job.get("runner_id")) is int and job["runner_id"] > 0 and
        job.get("runner_group_name") == "GitHub Actions" and job.get("labels") == ["ubuntu-24.04"],
        "admission.standard_job")
    return job["id"]


def api_location(route):
    prefix = "/repos/" + REPOSITORY
    if route == prefix + "/pulls/28": return "pr28", 1
    if route == prefix + "/git/ref/heads/" + SOURCE_BRANCH: return "source_ref", 2
    if re.fullmatch(re.escape(prefix) + r"/actions/runs/[1-9][0-9]{0,19}", route):
        return "current_run", 0
    if re.fullmatch(re.escape(prefix) + r"/actions/runs/[1-9][0-9]{0,19}/jobs\?filter=all&per_page=100", route):
        return "current_jobs", 4
    query = urllib.parse.urlencode({"branch": BRANCH, "event": "pull_request",
        "created": ">=2026-10-28T00:03:19Z", "per_page": 100})
    if route == prefix + "/actions/workflows/future-v108-source-validation.yml/runs?" + query:
        return "source_history", 3
    raise Refusal("api.fixed_route")


def public_api(route, token, deadline):
    kind, ordinal = api_location(route)
    need(type(token) is str and bool(token) and deadline > time.time(), "api.token_deadline")
    request = urllib.request.Request("https://api.github.com" + route, headers={
        "Accept": "application/vnd.github+json", "Authorization": "Bearer " + token,
        "Cache-Control": "max-age=0", "X-GitHub-Api-Version": "2022-11-28"})
    return fetch_json(request, deadline, "api", kind, ordinal)


def fetch_json(request, deadline, phase, kind, ordinal):
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args):
            return None
    need((phase, kind, ordinal) in (("api", "current_run", 0), ("api", "pr28", 1),
        ("api", "source_ref", 2), ("api", "source_history", 3), ("api", "current_jobs", 4),
        ("registry", "target", 0), ("registry", "packument", 1), ("registry", "parent", 2)),
        "metadata.location")
    raw, status, complete = None, None, False
    try:
        remaining = deadline - time.time()
        need(remaining > 0, phase + ".deadline")
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=min(20, remaining)) as response:
            status = response.status
            need(type(status) is int and status == 200, phase + ".status")
            raw = response.read(CAP + 1)
        complete = len(raw) <= CAP
        need(complete, phase + ".cap")
        value = parse(raw)
        need(type(value) is dict, phase + ".object")
    except Exception as error:
        if isinstance(error, urllib.error.HTTPError):
            status = error.code
            try:
                raw = error.read(65537)
                complete = len(raw) <= 65536
            except Exception:
                complete = False
        elif raw is None and isinstance(getattr(error, "partial", None), bytes):
            raw = error.partial[:CAP + 1]
        codes = {p + "." + suffix for p in ("api", "registry") for suffix in
            ("deadline", "status", "cap", "object")} | {"json.duplicate_key", "json.nonfinite"}
        code = phase + ".http_refused" if isinstance(error, urllib.error.HTTPError) else (
            str(error) if isinstance(error, Refusal) and str(error) in codes else phase + ".transport_or_json")
        print(json.dumps({"schema": "openclaw.v108.re2js-metadata-observation.v1", "phase": phase,
            "kind": kind, "ordinal": ordinal, "status": "refused", "refusalCode": code,
            "httpStatus": status if type(status) is int and 100 <= status <= 599 else None,
            "errorClass": type(error).__name__, "bodyBytes": len(raw) if raw is not None else None,
            "bodySha256": digest(raw) if raw is not None else None,
            "bodyComplete": complete, "rawReturned": False}), flush=True)
        raise Refusal(phase + ".read_failed") from None
    return value, raw


def registry_request(kind, deadline):
    need(kind in REGISTRY_URLS, "registry.kind")
    return fetch_json(urllib.request.Request(REGISTRY_URLS[kind],
        headers={"Accept": "application/json", "Cache-Control": "max-age=0"}), deadline,
        "registry", kind, ("target", "packument", "parent").index(kind))


def same_json(left, right):
    return json.dumps(left, sort_keys=True, separators=(",", ":"), allow_nan=False) == json.dumps(
        right, sort_keys=True, separators=(",", ":"), allow_nan=False)


def metadata_checks(documents, now=None):
    now = time.time() if now is None else now
    need(type(now) in (int, float) and math.isfinite(now), "registry.clock")
    need(type(documents) is dict and set(documents) == set(REGISTRY_URLS), "registry.complete")
    values = {}
    hashes = {}
    for name in REGISTRY_URLS:
        value, raw = documents[name]
        need(type(raw) is bytes and len(raw) <= CAP and same_json(parse(raw), value), "registry.raw_binding")
        values[name], hashes[name] = value, digest(raw)
    target, pack, parent = (values[k] for k in ("target", "packument", "parent"))
    need(same_json(pack.get("versions", {}).get(VERSION), target) and
        target.get("name") == "re2js" and target.get("version") == VERSION and
        target.get("gitHead") == GIT_HEAD and target.get("engines") == {"node": ">=20.0.0"} and
        target.get("dist", {}).get("integrity") == INTEGRITY and
        target["dist"].get("shasum") == "7c16e45ba6842b7078c739a6d2046c07eae93e21" and
        target["dist"].get("tarball") == "https://registry.npmjs.org/re2js/-/re2js-2.8.7.tgz" and
        all(key not in target or target[key] == {} for key in
            ("dependencies", "optionalDependencies", "peerDependencies")), "registry.target")
    need(parent.get("name") == "@openclaw/crabline" and parent.get("version") == "0.1.29" and
        parent.get("dependencies", {}).get("re2js") == "2.8.6" and
        parent.get("engines") == {"node": ">=22"} and
        parent.get("dist", {}).get("integrity") == PARENT_INTEGRITY and
        parent["dist"].get("tarball") == "https://registry.npmjs.org/@openclaw/crabline/-/crabline-0.1.29.tgz",
        "registry.parent")
    published = pack.get("time", {}).get(VERSION)
    need(published == PUBLISHED, "registry.publication")
    epoch = datetime.fromisoformat(published.replace("Z", "+00:00")).timestamp()
    age = (now - epoch) / 60
    need(age >= 10080 and now < datetime.fromisoformat(DEADLINE.replace("Z", "+00:00")).timestamp(),
        "registry.minimum_age")
    return {"checkedAt": utc_now(now), "minimumAgeMinutes": 10080, "ageMinutes": age,
        "publishedAt": published, "targetName": "re2js", "targetVersion": VERSION,
        "targetIntegrity": INTEGRITY, "targetGitHead": GIT_HEAD, "targetNodeEngine": ">=20.0.0",
        "parentName": "@openclaw/crabline", "parentVersion": "0.1.29", "parentDeclaredRe2js": "2.8.6",
        "parentNodeEngine": ">=22", "parentIntegrity": PARENT_INTEGRITY,
        "targetManifestSha256": hashes["target"], "packumentSha256": hashes["packument"],
        "parentManifestSha256": hashes["parent"], "manifestPackumentAgreement": True}


def admit(env, api=public_api):
    config = configuration()
    pipeline, source, temporary, rid = exact_paths(env)
    deadline = clock_deadline(env)
    head = event_binding(parse(regular(Path(env["GITHUB_EVENT_PATH"]), 4 * CAP)))
    driver = load_driver(pipeline, config)
    pins, prep = preparation(driver)
    code_binding(pipeline, source, head, config, pins)
    source_inputs(source, pins)
    def read(route):
        return api(route, env.get("GH_SOURCE_READ_TOKEN"), deadline)[0]
    prefix = "/repos/" + REPOSITORY
    checked_run(read(prefix + "/actions/runs/" + rid), rid, head)
    need(event_binding({"pull_request": read(prefix + "/pulls/28"), "action": "synchronize", "number": 28}) == head,
        "admission.pr_changed")
    ref = read(prefix + "/git/ref/heads/" + SOURCE_BRANCH)
    need(ref.get("ref") == "refs/heads/" + SOURCE_BRANCH and
        ref.get("object", {}).get("type") == "commit" and
        ref["object"].get("sha") == pins["sourceSha"], "admission.source_changed")
    query = urllib.parse.urlencode({"branch": BRANCH, "event": "pull_request",
        "created": ">=2026-10-28T00:03:19Z", "per_page": 100})
    checked_history(read(prefix + "/actions/workflows/future-v108-source-validation.yml/runs?" + query), rid, head, config)
    job = checked_job(read(prefix + "/actions/runs/" + rid + "/jobs?filter=all&per_page=100"), rid, head)
    now = time.time()
    context = {"schema": "openclaw.v108.re2js-lock-admission.v1", **prep, "pipelineHead": head,
        "runId": rid, "runAttempt": 1, "jobId": job, "checkedAtEpoch": int(now),
        "expiresAtEpoch": min(int(now) + 600, int(deadline)), "deadlineEpoch": deadline,
        "startedEpoch": int(env[CLOCK])}
    context["schema"] = "openclaw.v108.re2js-lock-admission.v1"
    raw = encode(context)
    private_write(temporary / (PREFIX + "admission-" + rid + ".json"), raw)
    with Path(env["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as out:
        out.write("admission_sha256=" + digest(raw) + "\n")
    print(json.dumps({"status": "admitted_derivation_only", "runId": rid,
        "admissionSha256": digest(raw), "qualified": False, "productionAuthorized": False}), flush=True)


def read_admission(temporary, rid, expected, deadline, pins):
    need(type(expected) is str and re.fullmatch(r"[0-9a-f]{64}", expected), "admission.hash_required")
    path = temporary / (PREFIX + "admission-" + rid + ".json")
    observed = path.lstat()
    need(observed.st_uid == os.getuid() and stat.S_IMODE(observed.st_mode) == 0o600, "admission.private")
    value = parse(regular(path, 16384, expected))
    fields = {"schema", "sourceSha", "sourceTree", "pipelineHead", "runId", "runAttempt", "jobId",
        "checkedAtEpoch", "expiresAtEpoch", "deadlineEpoch", "startedEpoch"}
    need(type(value) is dict and set(value) == fields and
        value["schema"] == "openclaw.v108.re2js-lock-admission.v1" and
        all(value[k] == pins[k] for k in ("sourceSha", "sourceTree")) and value["runId"] == rid and
        type(value["runAttempt"]) is int and value["runAttempt"] == 1 and
        type(value["jobId"]) is int and value["jobId"] > 0 and
        re.fullmatch(r"[0-9a-f]{40}", value["pipelineHead"]), "admission.closed")
    now = time.time()
    need(all(type(value[k]) is int for k in ("checkedAtEpoch", "expiresAtEpoch", "startedEpoch")) and
        value["checkedAtEpoch"] <= now <= value["expiresAtEpoch"] <= value["checkedAtEpoch"] + 600 and
        value["deadlineEpoch"] == deadline == value["startedEpoch"] + 2640, "admission.fresh")
    return value


def successful_phase(result):
    need(type(result.returncode) is int and result.returncode == 0 and
        getattr(result, "timed_out", None) is False, "process.nonzero_or_timeout")


def internal_bootstrap(path):
    config = configuration()
    pipeline, source, temporary, rid = exact_paths(os.environ)
    driver = load_driver(pipeline, config)
    pins, prep = preparation(driver)
    deadline = clock_deadline(os.environ)
    home = temporary / (PREFIX + "home-" + rid)
    value = parse(regular(path, 16384))
    need(type(value) is dict and set(value) == {"schema", "runId", "admissionSha256"} and
        value["schema"] == "openclaw.v108.re2js-lock-bootstrap.v1" and value["runId"] == rid and
        path == home / "bootstrap-context.json" and home.resolve(strict=True) == home and
        home.stat().st_uid == os.getuid() and stat.S_IMODE(home.stat().st_mode) == 0o700 and
        path.stat().st_uid == os.getuid() and stat.S_IMODE(path.stat().st_mode) == 0o600,
        "bootstrap.context")
    admission = read_admission(temporary, rid, value["admissionSha256"], deadline, pins)
    code_binding(pipeline, source, admission["pipelineHead"], config, pins)
    source_inputs(source, pins)
    driver.bootstrap_pnpm(home, driver.clean_env(home, os.environ), request=prep)


def artifact_ready(env, output):
    entries = list(output.iterdir())
    need({p.name for p in entries} <= {"pnpm-lock.yaml", "re2js-lock.diff", "generation.json"} and
        any(p.name == "generation.json" for p in entries) and
        all(stat.S_ISREG(p.lstat().st_mode) and p.resolve(strict=True) == p for p in entries) and
        sum(p.stat().st_size for p in entries) <= CAP - 65536, "artifact.cap_or_members")
    directory = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    with Path(env["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as out:
        out.write("artifact_ready=true\n")


def safe_refusal(error, driver=None):
    if isinstance(error, Refusal) and re.fullmatch(r"[a-z0-9_.]+", str(error)):
        return str(error)
    cls = getattr(driver, "R7ContractRefusal", None)
    if isinstance(cls, type) and isinstance(error, cls):
        project = getattr(driver, "runtime_refusal_code_v7", None)
        allowed = getattr(driver, "R7_RUNTIME_REFUSAL_CODES", None)
        code = project(error) if callable(project) and type(allowed) is frozenset else None
        if type(code) is str and code in allowed:
            return code
    return "preparation.unavailable"


def preserve_failure(state, error, env):
    if not state or state["output"].exists():
        return
    facts, reasons, material = {}, {}, {}
    result = state.get("result")
    unsettled = bool(state.get("generated") and (result is None or
        getattr(result, "timed_out", False) and getattr(result, "cleanup_settled", None) is not True))
    if state.get("bound") and state.get("generated") and not unsettled:
        try:
            lock = regular(state["source"] / "pnpm-lock.yaml")
            facts["pnpm-lock.yaml"] = {"bytes": len(lock), "sha256": digest(lock)}
            if digest(lock) != LOCK_SHA:
                diff = git(state["source"], "-c", "diff.algorithm=myers", "-c", "core.quotePath=true",
                    "diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--full-index", "--binary",
                    state["pins"]["sourceSha"], "--", "pnpm-lock.yaml")
                facts["re2js-lock.diff"] = {"bytes": len(diff), "sha256": digest(diff)}
                if public_lock_material(lock) and public_lock_material(diff) and len(lock) + len(diff) <= CAP - 81920:
                    material = {"pnpm-lock.yaml": lock, "re2js-lock.diff": diff}
                else:
                    reasons.update({"pnpm-lock.yaml": "unsafe_or_oversize", "re2js-lock.diff": "unsafe_or_oversize"})
            else:
                reasons.update({"pnpm-lock.yaml": "unchanged", "re2js-lock.diff": "unchanged"})
        except Exception:
            reasons.update({"pnpm-lock.yaml": "capture_unavailable", "re2js-lock.diff": "capture_unavailable"})
    else:
        reasons.update({"pnpm-lock.yaml": "writer_unsettled" if unsettled else "not_generated",
            "re2js-lock.diff": "writer_unsettled" if unsettled else "not_generated"})
    value = {"schema": SCHEMA, "status": "refused", "phase": state.get("phase", "input"),
        "refusalCode": safe_refusal(error, state.get("driver")), "sourceSha": state["pins"]["sourceSha"] if "pins" in state else None,
        "sourceTree": state["pins"]["sourceTree"] if "pins" in state else None, "runId": state["rid"],
        "runAttempt": 1, "fileFacts": facts, "missingFileReasons": reasons, "finishedAt": utc_now(),
        "exitCode": getattr(result, "actual_returncode", None), "timedOut": getattr(result, "timed_out", None),
        "cleanupSettled": getattr(result, "cleanup_settled", None),
        "qualified": False, "imageBuilt": False, "productionAuthorized": False}
    raw = encode(value)
    need(len(raw) <= 16384 and sum(map(len, material.values())) + len(raw) <= CAP - 65536, "artifact.failure_cap")
    state["output"].mkdir(mode=0o700)
    for name, value in (*material.items(), ("generation.json", raw)):
        private_write(state["output"] / name, value)
    artifact_ready(env, state["output"])


def derive(env, expected):
    state = {}
    try:
        _derive(env, expected, state)
    except Exception as error:
        preserve_failure(state, error, env)
        raise


def _derive(env, expected, state):
    config = configuration()
    pipeline, source, temporary, rid = exact_paths(env)
    state.update(source=source, output=temporary / (PREFIX + "output-" + rid), rid=rid, phase="admission")
    need(not env.get("GH_SOURCE_READ_TOKEN") and not env.get("GITHUB_TOKEN"), "derive.no_token")
    deadline = clock_deadline(env)
    driver = load_driver(pipeline, config)
    state["driver"] = driver
    pins, prep = preparation(driver)
    state["pins"] = pins
    admission = read_admission(temporary, rid, expected, deadline, pins)
    head = event_binding(parse(regular(Path(env["GITHUB_EVENT_PATH"]), 4 * CAP)))
    need(head == admission["pipelineHead"], "admission.head")
    code_binding(pipeline, source, head, config, pins)
    source_inputs(source, pins)
    state["bound"] = True
    started, command_start = utc_now(), time.monotonic()
    state["phase"] = "registry"
    registry = metadata_checks({kind: registry_request(kind, deadline) for kind in REGISTRY_URLS})
    driver.validate_re2js_registry_checks_v7(registry)
    output, home = state["output"], temporary / (PREFIX + "home-" + rid)
    need(not output.exists() and not home.exists(), "derive.once_only")
    home.mkdir(mode=0o700)
    phase = {"deadlineEpoch": deadline, "profile": "lock-preparation", "request": prep}
    child_env = driver.clean_env(home, env)
    context = home / "bootstrap-context.json"
    private_write(context, encode({"schema": "openclaw.v108.re2js-lock-bootstrap.v1", "runId": rid,
        "admissionSha256": expected}))
    boot_env = dict(child_env)
    for key in ("GITHUB_ACTIONS", "RUNNER_OS", "RUNNER_ENVIRONMENT", "GITHUB_WORKSPACE", "RUNNER_TEMP",
        "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_REPOSITORY", "GITHUB_EVENT_NAME", "GITHUB_ACTOR", CLOCK):
        boot_env[key] = env[key]
    with driver.profile_signals():
        state["phase"] = "bootstrap"
        result = driver.phase_process([sys.executable, "-I", "-B", str(Path(__file__).resolve()),
            "internal-bootstrap", "--context", str(context)], pipeline, boot_env, phase, "bootstrap", 0)
        state["result"] = result
        successful_phase(result)
        pnpm = driver.owned_pnpm_file(home / "toolchain", "pnpm")
        with pnpm.open("rb") as stream:
            need(stream.read(4) == b"\x7fELF" and os.access(pnpm, os.X_OK), "bootstrap.native")
        child_env["PATH"] = str(home / "toolchain/node_modules/.bin") + os.pathsep + child_env["PATH"]
        before = regular(source / "pnpm-lock.yaml", expected=LOCK_SHA)
        state.update(phase="lock_generation", generated=True, result=None)
        result = driver.phase_process([str(pnpm), "install", "--lockfile-only", "--ignore-scripts",
            "--no-frozen-lockfile"], source, child_env, phase, "lock-generation", 1)
        state["result"] = result
        successful_phase(result)
    state["phase"] = "lock_validation"
    generated = regular(source / "pnpm-lock.yaml")
    workspace = regular(source / "pnpm-workspace.yaml", expected=pins["workspaceSha256"])
    driver.validate_re2js_lock_delta_v7(before, generated, workspace, registry)
    source_inputs(source, pins, after=True)
    need(git(source, "rev-parse", "HEAD").strip().decode() == pins["sourceSha"] and
        git(source, "rev-parse", "HEAD^{tree}").strip().decode() == pins["sourceTree"] and
        not git(pipeline, "status", "--porcelain=v1", "--untracked-files=all"), "source.head_pipeline_unchanged")
    diff = git(source, "-c", "diff.algorithm=myers", "-c", "core.quotePath=true", "diff",
        "--no-ext-diff", "--no-textconv", "--no-renames", "--full-index", "--binary",
        pins["sourceSha"], "--", "pnpm-lock.yaml")
    need(time.time() < deadline, "budget.before_artifact")
    receipt = generation_receipt(pins, head, rid, generated, diff, registry, started, command_start, result)
    raw = encode(receipt)
    need(len(generated) + len(diff) + len(raw) <= CAP - 65536, "artifact.total_cap")
    output.mkdir(mode=0o700)
    for name, value in (("pnpm-lock.yaml", generated), ("re2js-lock.diff", diff), ("generation.json", raw)):
        private_write(output / name, value)
    artifact_ready(env, output)
    print(json.dumps({"status": "derived_only", "runId": rid, "generationReceiptSha256": digest(raw),
        "lockSha256": digest(generated), "qualified": False, "imageBuilt": False,
        "productionAuthorized": False}), flush=True)


def generation_receipt(pins, head, rid, generated, diff, registry, started, command_start, result):
    return {"schema": SCHEMA, "status": "derived_only", "sourceSha": pins["sourceSha"],
        "sourceTree": pins["sourceTree"], "baseSourceSha": BASE_SOURCE, "baseSourceTree": BASE_TREE,
        "pipelineHead": head, "runId": rid, "runAttempt": 1, "packageSha256": pins["packageSha256"],
        "sourceLockSha256": LOCK_SHA, "lockSha256": digest(generated),
        **{k: pins[k] for k in ("workspaceSha256", "securityTestSha256", "ledgerSha256", "metadataProofSha256")},
        "re2jsVersion": VERSION, "re2jsIntegrity": INTEGRITY, "parentName": "@openclaw/crabline",
        "parentVersion": "0.1.29", "parentDeclaredRe2js": "2.8.6", "nodeVersion": "24.22.1",
        "pnpmVersion": "12.15.0", "registryChecks": registry, "changedPaths": ["pnpm-lock.yaml"],
        "gitDiffSha256": digest(diff), "allOtherTrackedEntriesUnchanged": True,
        "startedAt": started, "finishedAt": utc_now(), "commandSeconds": time.monotonic() - command_start,
        "exitCode": result.returncode, "timedOut": result.timed_out, "cleanupSettled": result.cleanup_settled,
        "qualified": False, "imageBuilt": False, "productionAuthorized": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("admit", "derive", "internal-bootstrap"))
    parser.add_argument("--admission-sha256")
    parser.add_argument("--context", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        configuration()
        if args.command == "admit":
            admit(os.environ)
        elif args.command == "derive":
            derive(os.environ, args.admission_sha256)
        else:
            need(args.context is not None and args.context.is_absolute(), "bootstrap.path")
            internal_bootstrap(args.context)
    except Exception as error:
        print(json.dumps({"status": "refused", "errorClass": type(error).__name__,
            "code": str(error) if isinstance(error, Refusal) else "preparation.unavailable",
            "qualified": False, "imageBuilt": False, "productionAuthorized": False}), flush=True)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
