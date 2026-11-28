#!/usr/bin/env python3
"""One CI-only npm lock derivation; it never qualifies or publishes a candidate.

The early admission step alone receives the read-only Actions token. The later
derivation step uses a fresh HOME and the existing reviewed process/bootstrap
owners. There is no generic command, ref, package version or artifact selector.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import urllib.error

sys.dont_write_bytecode = True

REPOSITORY = "fr-meyer/openclaw"
WORKFLOW = ".github/workflows/future-v108-source-validation.yml"
PARENT = "d213bb593b3e618d459dde6767bc93f716ac8493"
SOURCE = "84d9bd1c618708e9d5798a730d473ddecf99297a"
TREE = "ca3ce016d7429e7ef42f6fed99b58f6c6ec623f4"
BASE = "a65f70c5dad17b39bc3ee26ba92cde6d00bfb259"
DEADLINE = "2026-10-30T00:03:19Z"
BRANCH = "task/v107-source-binding"
BASE_BRANCH = "release-pipeline/v105-image-only-20261024"
CANDIDATE = "scripts/fork-release/candidates/v2026.10.8-source-only"
HELPER = "scripts/fork-release/npm_lock_prepare_v108.py"
BASELINE_SHA = "6f6043f0a6e733fd00ffb3dedc8d14d5c21c5da8ce1db96303b70d3d403c7382"
PACKAGE_SHA = "289d42988293d8afd6a7ca133b0ffbbde7c0a466592dfe7b08565371bbcd60a4"
NEW_PACKAGE_SHA = "d5cb6bde3b3d5f032b09add3adcb16fb2ae6dab85ba375051376533c1ddbf8a1"
LOCK_SHA = "bfaafb73d19b61f0b5124791c05ae8c65a7436f0d6c9ef1dd6f79358e9c35334"
WORKSPACE_SHA = "6e00354044a5c9c05c87217e1fc0fad1efaebdb0606bcf040d79664e5fca8c17"
OLD_NPM_SRI = "sha512-ZsJjKpTnlmSXOLLXiU1xDCzC4Wlok4IwZmh/aw2KUuXytU7q6qMv/cUT7MoeSf95Slwuw/lRXYefGzGCspHPNQ=="
NPM_SRI = "sha512-bKCmFRVT/BB+YPEYbZwQ1XUI3N5t4xKSpU1MxOjo7z3iWzKBJ0ZXRC1xFdEN+TC7N5TdywaBzf2dMXGJq/e2PQ=="
REQUEST_SHA = "381c9752fc73f8fe094054b633b587e4e6f20494e98f0d47587518bfd88dcc03"
DRIVER_PINS = {
    "source_validation_v108.py": "ff04088cd2026aea3c06d1109b4741aa55b6919879acda2f3f75e93f26291cc5",
    "preflight.py": "89b6ba41fc89131f33754104fdd0d3ebc08c20f252288651bc7d95038639103a",
    "release.py": "6a183cbde1f2257b30440b34b781688e873ee2e2ed938a129e921d72ac667da3",
}
CHANGED_PIPELINE_PATHS = frozenset((WORKFLOW, HELPER,
    "scripts/fork-release/test_npm_lock_preparation_v108.py",
    CANDIDATE + "/npm-settled-usage.json", CANDIDATE + "/README.md"))
PRIOR_SOURCE_RUNS = {
    40607329263: "fb136445c313fdd94b2e3a615acb2a16ea9bf1e3",
    40609889437: "1328661613052dfa09902e1d1d080fa8e6ccd89d",
    40616416909: "de5b35be1531ca14394f5457ae934ad268ddb941",
    40639374411: "95df4eb49204150c8aaaa9da8e2abd3112fa5972",
    40647629182: "0dd3c9ef205939350f41ab2187232268c7c44ab8",
    40681376480: "de4cdb8aae20719ae95808d3cf725a4b503d6d01",
    40688279536: "2946a1678e712de90727a9e599a5f2cd47ad2151",
    40706982753: PARENT,
}
CAP = 2 * 1024 * 1024
SHA = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class Refusal(ValueError):
    pass


def need(value, code):
    if not value:
        raise Refusal(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (json.dumps(value, indent=2, allow_nan=False) + "\n").encode()


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def parse(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, "json.duplicate_key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, "json.nonfinite"))


def regular(path, maximum=CAP, expected=None):
    st = path.lstat()
    need(stat.S_ISREG(st.st_mode) and st.st_size <= maximum and path.resolve(strict=True) == path,
         "input.regular_bounded")
    raw = path.read_bytes()
    need(len(raw) <= maximum and (expected is None or digest(raw) == expected), "input.hash")
    return raw


def private_write(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(raw)
        out.flush()
        os.fsync(out.fileno())


def git(directory, *args):
    env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_NO_LAZY_FETCH": "1",
           "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0"}
    child = subprocess.run(["/usr/bin/git", "--no-replace-objects", "-C", str(directory), *args],
                           env=env, capture_output=True, timeout=20)
    need(child.returncode == 0 and len(child.stdout) <= 8 * CAP and len(child.stderr) <= 65536,
         "git.read_failed")
    return child.stdout


def exact_paths(env):
    need(sys.platform == "linux" and env.get("GITHUB_ACTIONS") == "true" and
         env.get("RUNNER_OS") == "Linux", "host.ci_only")
    workspace = Path(env["GITHUB_WORKSPACE"])
    temporary = Path(env["RUNNER_TEMP"])
    need(workspace.is_absolute() and workspace.resolve(strict=True) == workspace and
         temporary.is_absolute() and temporary.resolve(strict=True) == temporary and
         temporary.is_dir() and workspace.is_dir(), "host.paths")
    rid = env.get("GITHUB_RUN_ID", "")
    need(re.fullmatch(r"[1-9][0-9]{0,19}", rid) and env.get("GITHUB_RUN_ATTEMPT") == "1" and
         env.get("GITHUB_REPOSITORY") == REPOSITORY and env.get("GITHUB_EVENT_NAME") == "pull_request" and
         env.get("GITHUB_ACTOR") == "fr-meyer", "event.environment")
    return workspace / "pipeline", workspace / "source", temporary, rid


def clock_deadline(env, now=None):
    now = time.time() if now is None else now
    start = env.get("NPM_LOCK_STARTED_EPOCH", "")
    need(re.fullmatch(r"[0-9]{10}", start) and int(start) <= now and now - int(start) < 45 * 60 - 60,
         "budget.clock")
    absolute = datetime.fromisoformat(DEADLINE.replace("Z", "+00:00")).timestamp()
    need(int(start) + 45 * 60 <= absolute, "budget.approval_deadline")
    return min(int(start) + 45 * 60 - 60, absolute - 60)


def event_binding(event, env):
    pr = event.get("pull_request")
    need(type(pr) is dict and event.get("action") in ("opened", "reopened", "synchronize") and
         event.get("number") == 28 and pr.get("number") == 28 and pr.get("draft") is True and
         pr.get("state") == "open", "event.pull_request")
    for key in ("head", "base"):
        repo = pr.get(key, {}).get("repo", {})
        need(repo.get("full_name") == REPOSITORY and repo.get("private") is False,
             "event.repository")
    need(pr["head"].get("ref") == BRANCH and pr["base"].get("ref") == BASE_BRANCH and
         pr["base"].get("sha") == BASE and SHA.fullmatch(pr["head"].get("sha", "")), "event.refs")
    return pr["head"]["sha"]


def code_binding(pipeline, source, head):
    need(pipeline.resolve(strict=True) == pipeline and source.resolve(strict=True) == source,
         "checkout.paths")
    need(git(pipeline, "rev-parse", "HEAD").strip().decode() == head and
         git(pipeline, "show", "-s", "--format=%P", "HEAD").strip().decode() == PARENT,
         "checkout.pipeline_parent")
    changed = set(git(pipeline, "diff", "--no-ext-diff", "--no-textconv", "--no-renames",
                      "--name-only", PARENT, "HEAD").decode().splitlines())
    need(changed == CHANGED_PIPELINE_PATHS and
         not git(pipeline, "status", "--porcelain=v1", "--untracked-files=all"), "checkout.pipeline_scope")
    for name, expected in DRIVER_PINS.items():
        regular(pipeline / "scripts/fork-release" / name, expected=expected)
    regular(pipeline / CANDIDATE / "source-request.json", expected=REQUEST_SHA)
    baseline = parse(regular(pipeline / CANDIDATE / "npm-settled-usage.json", expected=BASELINE_SHA))
    need(baseline.get("runCount") == 168 and baseline.get("runnerMinutesObserved") == 1237 and
         baseline.get("currentArtifactSnapshot") == {"count": 15, "bytes": 9335}, "budget.closed_baseline")
    need(git(source, "rev-parse", "HEAD").strip().decode() == SOURCE and
         git(source, "rev-parse", "HEAD^{tree}").strip().decode() == TREE,
         "checkout.source_identity")


def clean_source(source):
    need(not git(source, "status", "--porcelain=v1", "--untracked-files=all"), "source.clean")
    regular(source / "package.json", expected=PACKAGE_SHA)
    regular(source / "pnpm-lock.yaml", expected=LOCK_SHA)
    regular(source / "pnpm-workspace.yaml", expected=WORKSPACE_SHA)


def checked_public_run(run, rid, head):
    need(type(run) is dict and str(run.get("id")) == rid and run.get("run_attempt") == 1 and
         run.get("event") == "pull_request" and run.get("path") == WORKFLOW and
         run.get("head_branch") == BRANCH and run.get("head_sha") == head and
         run.get("status") == "in_progress" and run.get("actor", {}).get("login") == "fr-meyer",
         "admission.current_run")
    for key in ("repository", "head_repository"):
        need(run.get(key, {}).get("full_name") == REPOSITORY and
             run.get(key, {}).get("private") is False, "admission.public_run")


def checked_history(table, rid, head):
    need(type(table) is dict and table.get("total_count") == len(PRIOR_SOURCE_RUNS) + 1 and
         type(table.get("workflow_runs")) is list and
         len(table["workflow_runs"]) == table["total_count"], "admission.complete_history")
    rows = table["workflow_runs"]
    need(len({r.get("id") for r in rows}) == len(rows), "admission.unique_history")
    prior = {r["id"]: r for r in rows if str(r.get("id")) != rid}
    need(set(prior) == set(PRIOR_SOURCE_RUNS), "admission.no_duplicate_preparation")
    for old_id, old_head in PRIOR_SOURCE_RUNS.items():
        row = prior[old_id]
        need(row.get("head_sha") == old_head and row.get("run_attempt") == 1 and
             row.get("status") == "completed" and row.get("path") == WORKFLOW,
             "admission.closed_source_history")
    matches = [r for r in rows if str(r.get("id")) == rid]
    need(len(matches) == 1 and matches[0].get("head_sha") == head and
         matches[0].get("run_attempt") == 1 and matches[0].get("status") == "in_progress",
         "admission.single_current_preparation")


def checked_jobs(table, rid, head):
    need(type(table) is dict and table.get("total_count") == 1 and
         type(table.get("jobs")) is list and len(table["jobs"]) == 1, "admission.one_job")
    job = table["jobs"][0]
    need(job.get("name") == "lock-preparation" and str(job.get("run_id")) == rid and
         job.get("head_sha") == head and job.get("run_attempt") == 1 and
         job.get("status") == "in_progress" and type(job.get("runner_id")) is int and
         job["runner_id"] > 0 and type(job.get("labels")) is list and
         "ubuntu-24.04" in job["labels"] and "self-hosted" not in job["labels"], "admission.standard_job")
    return job["id"]


def api_route_kind(route):
    prefix = "/repos/" + REPOSITORY
    fixed = {prefix + "/pulls/28": ("pr28", 1),
             prefix + "/git/ref/heads/prep/v2026.10.8-remediation": ("source_ref", 2)}
    if route in fixed:
        return fixed[route]
    if re.fullmatch(re.escape(prefix) + r"/actions/runs/[1-9][0-9]{0,19}", route):
        return "current_run", 0
    if re.fullmatch(re.escape(prefix) + r"/actions/runs/[1-9][0-9]{0,19}/jobs\?filter=all&per_page=100", route):
        return "current_jobs", 4
    if route.startswith(prefix + "/actions/workflows/future-v108-source-validation.yml/runs?"):
        return "source_history", 3
    raise Refusal("admission.fixed_api")


def api_observation(route, status, http_status=None, headers=None, raw=None, complete=False, error=None):
    kind, ordinal = api_route_kind(route)
    headers = headers or {}
    def numeric(name):
        value = headers.get(name)
        return int(value) if type(value) is str and re.fullmatch(r"[0-9]{1,12}", value) else None
    print(json.dumps({"schema": "openclaw.v108.npm-lock-api-observation.v1", "phase": kind,
        "ordinal": ordinal, "status": status, "httpStatus": http_status,
        "rateLimitRemaining": numeric("X-RateLimit-Remaining"),
        "rateLimitResetEpoch": numeric("X-RateLimit-Reset"), "retryAfterSeconds": numeric("Retry-After"),
        "responseBodyBytes": len(raw) if raw is not None else None,
        "responseBodySha256": digest(raw) if raw is not None else None,
        "responseBodyComplete": bool(complete),
        "errorClass": type(error).__name__ if error is not None else None,
        "errorCode": str(error) if isinstance(error, Refusal) and re.fullmatch(r"[a-z0-9_.]+", str(error)) else None,
        "rawBodyReturned": False}), flush=True)


def public_api(route, token, deadline):
    api_route_kind(route)
    need(route.startswith("/repos/" + REPOSITORY + "/"), "admission.fixed_api")
    remaining = deadline - time.time()
    need(remaining > 0 and type(token) is str and bool(token), "admission.token_deadline")
    request = urllib.request.Request("https://api.github.com" + route, method="GET", headers={
        "Accept": "application/vnd.github+json", "Authorization": "Bearer " + token,
        "Cache-Control": "max-age=0", "X-GitHub-Api-Version": "2022-11-28"})
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, stream, code, message, headers, new_url):
            return None
    # A repository move is a refusal, never a token-bearing alternate endpoint.
    opener = urllib.request.build_opener(NoRedirect())
    try:
        with opener.open(request, timeout=min(20, remaining)) as response:
            status, headers = response.status, response.headers
            raw = response.read(CAP + 1)
    except urllib.error.HTTPError as error:
        try:
            raw = error.read(65537)
        except Exception:
            raw = None
        api_observation(route, "http_refused", error.code, error.headers, raw,
                        raw is not None and len(raw) <= 65536, error)
        raise Refusal("admission.http_refused") from None
    except Exception as error:
        partial = getattr(error, "partial", None)
        raw = partial[:CAP + 1] if isinstance(partial, bytes) else None
        api_observation(route, "transport_or_read_refused", raw=raw, complete=False, error=error)
        raise Refusal("admission.transport_or_read_refused") from None
    if len(raw) > CAP:
        api_observation(route, "response_cap_refused", status, headers, raw, False)
        raise Refusal("admission.response_cap")
    try:
        value = parse(raw)
        need(type(value) is dict, "admission.response_object")
    except Exception as error:
        api_observation(route, "response_json_refused", status, headers, raw, True, error)
        raise Refusal("admission.response_json") from None
    api_observation(route, "completed", status, headers, raw, True)
    return value


def admit(env, api=public_api):
    pipeline, source, temporary, rid = exact_paths(env)
    deadline = clock_deadline(env)
    head = event_binding(parse(regular(Path(env["GITHUB_EVENT_PATH"]), 4 * CAP)), env)
    code_binding(pipeline, source, head)
    clean_source(source)
    token = env.get("GH_SOURCE_READ_TOKEN")
    current = api("/repos/" + REPOSITORY + "/actions/runs/" + rid, token, deadline)
    checked_public_run(current, rid, head)
    pr = api("/repos/" + REPOSITORY + "/pulls/28", token, deadline)
    need(event_binding({"pull_request": pr, "action": "synchronize", "number": 28}, env) == head,
         "admission.current_pr")
    source_ref = api("/repos/" + REPOSITORY + "/git/ref/heads/prep/v2026.10.8-remediation", token, deadline)
    need(source_ref.get("object", {}).get("sha") == SOURCE, "admission.current_source_branch")
    query = urllib.parse.urlencode({"branch": BRANCH, "event": "pull_request",
                                   "created": ">=2026-10-28T00:03:19Z", "per_page": 100})
    table = api("/repos/" + REPOSITORY + "/actions/workflows/future-v108-source-validation.yml/runs?" + query,
                token, deadline)
    checked_history(table, rid, head)
    jobs = api("/repos/" + REPOSITORY + "/actions/runs/" + rid + "/jobs?filter=all&per_page=100", token, deadline)
    job_id = checked_jobs(jobs, rid, head)
    now = time.time()
    context = {"schema": "openclaw.v108.npm-lock-admission.v1", "sourceSha": SOURCE,
               "sourceTree": TREE, "pipelineHead": head, "runId": rid, "runAttempt": 1,
               "jobId": job_id, "checkedAtEpoch": int(now),
               "expiresAtEpoch": min(int(now) + 600, int(deadline)),
               "deadlineEpoch": deadline, "startedEpoch": int(env["NPM_LOCK_STARTED_EPOCH"])}
    path = temporary / ("v108-npm-lock-admission-" + rid + ".json")
    raw = encode(context)
    private_write(path, raw)
    output = Path(env["GITHUB_OUTPUT"])
    with output.open("a", encoding="utf-8") as out:
        out.write("admission_sha256=" + digest(raw) + "\n")
    print(json.dumps({"status": "admitted_derivation_only", "runId": rid,
                      "pipelineHead": head, "admissionSha256": digest(raw),
                      "qualified": False, "productionAuthorized": False}))


ADMISSION_FIELDS = frozenset(("schema", "sourceSha", "sourceTree", "pipelineHead", "runId", "runAttempt",
    "jobId", "checkedAtEpoch", "expiresAtEpoch", "deadlineEpoch", "startedEpoch"))


def read_admission(path, expected, rid, now, deadline):
    need(SHA256.fullmatch(expected or ""), "admission.required_hash")
    st = path.lstat()
    need(st.st_uid == os.getuid() and stat.S_IMODE(st.st_mode) == 0o600, "admission.private_file")
    value = parse(regular(path, 16384, expected))
    need(type(value) is dict and set(value) == ADMISSION_FIELDS and
         value["schema"] == "openclaw.v108.npm-lock-admission.v1" and
         value["sourceSha"] == SOURCE and value["sourceTree"] == TREE and
         value["runId"] == rid and type(value["runAttempt"]) is int and value["runAttempt"] == 1 and
         SHA.fullmatch(value["pipelineHead"]) and type(value["jobId"]) is int and value["jobId"] > 0,
         "admission.closed_context")
    need(all(type(value[k]) is int for k in ("checkedAtEpoch", "expiresAtEpoch", "startedEpoch")) and
         type(value["deadlineEpoch"]) in (int, float) and
         value["checkedAtEpoch"] <= now <= value["expiresAtEpoch"] <= value["checkedAtEpoch"] + 600 and
         value["deadlineEpoch"] == deadline and value["startedEpoch"] + 45 * 60 - 60 == deadline,
         "admission.fresh_context")
    return value


def load_driver(pipeline):
    directory = pipeline / "scripts/fork-release"
    for name, expected in DRIVER_PINS.items():
        regular(directory / name, expected=expected)
    sys.path.insert(0, str(directory))
    spec = importlib.util.spec_from_file_location("reviewed_v108_derivation_process_owner", directory / "source_validation_v108.py")
    driver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(driver)
    return driver


def patched_package(raw):
    need(digest(raw) == PACKAGE_SHA and raw.count(b'"npm": "12.2.0"') == 1, "package.original")
    changed = raw.replace(b'"npm": "12.2.0"', b'"npm": "12.2.1"')
    need(digest(changed) == NEW_PACKAGE_SHA, "package.exact_patch")
    return changed


def validate_generated_lock(before, generated):
    """Accept pnpm's bytes only when its complete diff is the reviewed npm delta.

    This expected representation is a comparison guard; it is never written or
    substituted for the maintained resolver's actual output.
    """
    need(digest(before) == LOCK_SHA and generated != before and 0 < len(generated) <= CAP,
         "lock.original_or_output")
    replacements = (
        (b"      npm:\n        specifier: 12.2.0\n        version: 12.2.0\n",
         b"      npm:\n        specifier: 12.2.1\n        version: 12.2.1\n"),
        (("  npm@12.2.0:\n    resolution: {integrity: " + OLD_NPM_SRI + "}\n").encode(),
         ("  npm@12.2.1:\n    resolution: {integrity: " + NPM_SRI + "}\n").encode()),
        (b"  npm@12.2.0: {}\n", b"  npm@12.2.1: {}\n"),
    )
    expected = before
    for old, new in replacements:
        need(expected.count(old) == 1, "lock.original_shape")
        expected = expected.replace(old, new)
    need(generated == expected, "lock.unrelated_resolution_or_format_change")


def successful_phase(result):
    need(result.returncode == 0 and getattr(result, "timed_out", None) is False,
         "process.nonzero_or_timeout")


def internal_bootstrap(path):
    pipeline, source, temporary, rid = exact_paths(os.environ)
    deadline = clock_deadline(os.environ)
    context = parse(regular(path, 16384))
    need(set(context) == {"schema", "home", "pipeline", "runId", "admissionSha256"} and
         context["schema"] == "openclaw.v108.npm-lock-bootstrap.v1" and
         re.fullmatch(r"[1-9][0-9]{0,19}", context["runId"]), "bootstrap.closed_context")
    home = Path(context["home"])
    need(context["runId"] == rid and Path(context["pipeline"]) == pipeline and
         home == temporary / ("v108-npm-lock-home-" + rid), "bootstrap.admitted_paths")
    need(path.name == "bootstrap-context.json" and path.parent == home and
         home.name == "v108-npm-lock-home-" + context["runId"] and
         home.resolve(strict=True) == home and stat.S_IMODE(home.stat().st_mode) == 0o700,
         "bootstrap.owned_home")
    need(path.stat().st_uid == os.getuid() and stat.S_IMODE(path.stat().st_mode) == 0o600,
         "bootstrap.private_context")
    admission = read_admission(temporary / ("v108-npm-lock-admission-" + rid + ".json"),
                               context["admissionSha256"], rid, time.time(), deadline)
    code_binding(pipeline, source, admission["pipelineHead"])
    clean_source(source)
    driver = load_driver(pipeline)
    request = parse(regular(pipeline / CANDIDATE / "source-request.json", expected=REQUEST_SHA))
    child_env = driver.clean_env(home, os.environ)
    driver.bootstrap_pnpm(home, child_env, request=request)


def artifact_ready(env, output):
    entries = list(output.iterdir())
    need({p.name for p in entries} <= {"pnpm-lock.yaml", "npm-lock.diff", "generation.json"} and
         any(p.name == "generation.json" for p in entries), "artifact.closed_subset")
    need(all(stat.S_ISREG(p.lstat().st_mode) and p.resolve(strict=True) == p for p in entries) and
         sum(p.stat().st_size for p in entries) <= CAP - 65536, "artifact.total_cap")
    directory = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    with Path(env["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as out:
        out.write("artifact_ready=true\n")


def public_lock_material(raw):
    """Only resolver output from public inputs is eligible for a public failure artifact."""
    if len(raw) > CAP - 81920:
        return False
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        return False
    if re.search(r"(?i)(?:_authToken|_password|authorization:|BEGIN [A-Z ]*PRIVATE KEY|/Users/|://[^/\s]+@)", text):
        return False
    # Public registries may occur in the pinned source. Newly credentialed or
    # capability-bearing URLs are never made public as debugging evidence.
    return not re.search(r"https?://[^\s\"'<>]*[?#]", text)


def preserve_failure(state, error, env):
    if not state:
        return
    output = state["output"]
    if output.exists():
        # Existing success/partial evidence is never overwritten to repair a failure.
        return
    facts, reasons, material = {}, {}, {}
    result = state.get("result")
    writer_uncertain = bool(state.get("generated_attempt") and (result is None or
                            (getattr(result, "timed_out", False) and
                             getattr(result, "cleanup_settled", None) is not True)))
    if state.get("source_bound") and state.get("generated_attempt") and not writer_uncertain:
        try:
            path = state["source"] / "pnpm-lock.yaml"
            observed = path.lstat()
            facts["pnpm-lock.yaml"] = {"bytes": observed.st_size,
                "entryType": "regular" if stat.S_ISREG(observed.st_mode) else
                             "symlink" if stat.S_ISLNK(observed.st_mode) else "other",
                "sha256": None, "hashComplete": False}
            lock = regular(path)
            facts["pnpm-lock.yaml"].update(bytes=len(lock), sha256=digest(lock), hashComplete=True)
            if digest(lock) == LOCK_SHA:
                reasons["pnpm-lock.yaml"] = "source_lock_unchanged"
            else:
                diff = git(state["source"], "-c", "diff.algorithm=myers", "-c", "core.quotePath=true",
                    "diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--full-index", "--binary",
                    SOURCE, "--", "package.json", "pnpm-lock.yaml")
                facts["npm-lock.diff"] = {"bytes": len(diff), "sha256": digest(diff)}
                if public_lock_material(lock) and public_lock_material(diff) and len(lock) + len(diff) <= CAP - 81920:
                    material = {"pnpm-lock.yaml": lock, "npm-lock.diff": diff}
                else:
                    reasons.update({"pnpm-lock.yaml": "unknown_or_oversize_public_material",
                                    "npm-lock.diff": "unknown_or_oversize_public_material"})
        except Exception as capture_error:
            reasons.update({"pnpm-lock.yaml": "bounded_capture_" + type(capture_error).__name__,
                            "npm-lock.diff": "bounded_capture_unavailable"})
    else:
        reason = "writer_unsettled" if writer_uncertain else "not_generated"
        reasons.update({"pnpm-lock.yaml": reason, "npm-lock.diff": reason})
    for name in ("pnpm-lock.yaml", "npm-lock.diff"):
        if name not in material and name not in reasons:
            reasons[name] = "unavailable"
    safe_code = str(error) if isinstance(error, Refusal) and re.fullmatch(r"[a-z0-9_.]+", str(error)) else "preparation.unavailable"
    receipt = {"schema": "openclaw.v108.npm-lock-derivation.v1", "status": "refused",
        "phase": state.get("phase", "input"), "refusalCode": safe_code,
        "sourceSha": SOURCE, "sourceTree": TREE, "pipelineHead": state.get("head"),
        "runId": state["rid"], "runAttempt": 1, "fileFacts": facts,
        "missingFileReasons": reasons, "finishedAt": utc_now(),
        "exitCode": getattr(result, "actual_returncode", None),
        "timedOut": getattr(result, "timed_out", None),
        "cleanupSettled": getattr(result, "cleanup_settled", None),
        "qualified": False, "imageBuilt": False, "productionAuthorized": False}
    raw = encode(receipt)
    need(len(raw) <= 16384 and sum(len(v) for v in material.values()) + len(raw) <= CAP - 65536,
         "artifact.failure_cap")
    output.mkdir(mode=0o700)
    for name, value in material.items():
        private_write(output / name, value)
    private_write(output / "generation.json", raw)
    artifact_ready(env, output)


def derive(env, expected_admission):
    state = {}
    try:
        _derive(env, expected_admission, state)
    except Exception as error:
        preserve_failure(state, error, env)
        raise


def _derive(env, expected_admission, state):
    pipeline, source, temporary, rid = exact_paths(env)
    state.update(source=source, output=temporary / ("v108-npm-lock-output-" + rid), rid=rid,
                 phase="admission_context")
    need(not env.get("GH_SOURCE_READ_TOKEN") and not env.get("GITHUB_TOKEN"), "derive.no_token")
    deadline = clock_deadline(env)
    context = read_admission(temporary / ("v108-npm-lock-admission-" + rid + ".json"),
                             expected_admission, rid, time.time(), deadline)
    head = event_binding(parse(regular(Path(env["GITHUB_EVENT_PATH"]), 4 * CAP)), env)
    state["head"] = head
    need(head == context["pipelineHead"], "admission.head")
    code_binding(pipeline, source, head)
    clean_source(source)
    state["source_bound"] = True
    driver = load_driver(pipeline)
    request = parse(regular(pipeline / CANDIDATE / "source-request.json", expected=REQUEST_SHA))
    output = temporary / ("v108-npm-lock-output-" + rid)
    home = temporary / ("v108-npm-lock-home-" + rid)
    need(not output.exists() and not home.exists(), "derive.once_only_directories")
    home.mkdir(mode=0o700)
    start = utc_now()
    command_start = time.monotonic()
    phase = {"deadlineEpoch": deadline, "profile": "lock-preparation", "request": request}
    child_env = driver.clean_env(home, env)
    bootstrap_context = home / "bootstrap-context.json"
    private_write(bootstrap_context, encode({"schema": "openclaw.v108.npm-lock-bootstrap.v1",
        "home": str(home), "pipeline": str(pipeline), "runId": rid,
        "admissionSha256": expected_admission}))
    bootstrap_env = dict(child_env)
    # Only public identity/clock facts reach the Python child. The child calls
    # clean_env again before npm/Node; no API token or Actions output path is copied.
    for key in ("GITHUB_ACTIONS", "RUNNER_OS", "GITHUB_WORKSPACE", "RUNNER_TEMP", "GITHUB_RUN_ID",
                "GITHUB_RUN_ATTEMPT", "GITHUB_REPOSITORY", "GITHUB_EVENT_NAME", "GITHUB_ACTOR",
                "NPM_LOCK_STARTED_EPOCH"):
        bootstrap_env[key] = env[key]
    with driver.profile_signals():
        state["phase"] = "bootstrap"
        result = driver.phase_process([sys.executable, "-I", "-B", str(Path(__file__).resolve()),
            "internal-bootstrap", "--context", str(bootstrap_context)], pipeline, bootstrap_env,
            phase, "bootstrap", 0)
        state["result"] = result
        successful_phase(result)
        pnpm = driver.owned_pnpm_file(home / "toolchain", "pnpm")
        with pnpm.open("rb") as stream:
            need(stream.read(4) == b"\x7fELF" and os.access(pnpm, os.X_OK), "bootstrap.native_identity")
        child_env["PATH"] = str(home / "toolchain/node_modules/.bin") + os.pathsep + child_env["PATH"]
        before_package = regular(source / "package.json", expected=PACKAGE_SHA)
        before_lock = regular(source / "pnpm-lock.yaml", expected=LOCK_SHA)
        (source / "package.json").write_bytes(patched_package(before_package))
        state.update(phase="lock_generation", generated_attempt=True, result=None)
        result = driver.phase_process([str(pnpm), "install", "--lockfile-only", "--ignore-scripts",
            "--no-frozen-lockfile"], source, child_env, phase, "lock-generation", 1)
        state["result"] = result
        successful_phase(result)
    state["phase"] = "validate_lock"
    package = regular(source / "package.json", expected=NEW_PACKAGE_SHA)
    lock = regular(source / "pnpm-lock.yaml")
    validate_generated_lock(before_lock, lock)
    state["phase"] = "source_delta"
    regular(source / "pnpm-workspace.yaml", expected=WORKSPACE_SHA)
    need(git(source, "rev-parse", "HEAD").strip().decode() == SOURCE and
         git(source, "rev-parse", "HEAD^{tree}").strip().decode() == TREE and
         not git(source, "diff", "--cached", "--name-only"), "source.original_head_index")
    changed = git(source, "diff", "--name-only", "--no-renames").decode().splitlines()
    need(changed == ["package.json", "pnpm-lock.yaml"] and
         git(source, "ls-files", "--others", "--exclude-standard") == b"", "source.only_npm_delta")
    need(not git(pipeline, "status", "--porcelain=v1", "--untracked-files=all"), "pipeline.unchanged")
    diff = git(source, "-c", "diff.algorithm=myers", "-c", "core.quotePath=true", "diff",
               "--no-ext-diff", "--no-textconv", "--no-renames", "--full-index", "--binary", SOURCE,
               "--", "package.json", "pnpm-lock.yaml")
    need(time.time() < deadline, "budget.before_artifact")
    state["phase"] = "artifact"
    receipt = {"schema": "openclaw.v108.npm-lock-derivation.v1", "status": "derived_only",
        "sourceSha": SOURCE, "sourceTree": TREE, "pipelineHead": head, "runId": rid, "runAttempt": 1,
        "sourcePackageSha256": PACKAGE_SHA, "sourceLockSha256": LOCK_SHA,
        "packageSha256": digest(package), "lockSha256": digest(lock), "npmVersion": "12.2.1",
        "npmIntegrity": NPM_SRI, "nodeVersion": "24.22.1", "pnpmVersion": "12.15.0",
        "workspaceSha256": WORKSPACE_SHA, "changedPaths": ["package.json", "pnpm-lock.yaml"],
        "gitDiffSha256": digest(diff), "allOtherTrackedEntriesUnchanged": True,
        "startedAt": start, "finishedAt": utc_now(), "commandSeconds": time.monotonic() - command_start,
        "exitCode": result.returncode, "timedOut": result.timed_out,
        "cleanupSettled": result.cleanup_settled, "qualified": False, "imageBuilt": False,
        "productionAuthorized": False}
    receipt_raw = encode(receipt)
    # Three provider ZIP entries need framing. Reserve64KiB beyond plain payload.
    need(len(lock) + len(diff) + len(receipt_raw) <= CAP - 65536, "artifact.total_cap")
    output.mkdir(mode=0o700)
    for name, raw in (("pnpm-lock.yaml", lock), ("npm-lock.diff", diff), ("generation.json", receipt_raw)):
        private_write(output / name, raw)
    artifact_ready(env, output)
    print(json.dumps({"status": "derived_only", "runId": rid, "generationReceiptSha256": digest(receipt_raw),
                      "lockSha256": digest(lock), "artifactBytes": len(lock) + len(diff) + len(receipt_raw),
                      "qualified": False, "imageBuilt": False, "productionAuthorized": False}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("admit", "derive", "internal-bootstrap"))
    parser.add_argument("--admission-sha256")
    parser.add_argument("--context", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.command == "admit":
            admit(os.environ)
        elif args.command == "derive":
            derive(os.environ, args.admission_sha256)
        else:
            need(args.context is not None and args.context.is_absolute(), "bootstrap.required_context")
            internal_bootstrap(args.context)
    except Exception as error:
        # Never print HTTP bodies, tokens, environments or candidate-controlled errors.
        print(json.dumps({"status": "refused", "errorClass": type(error).__name__,
                          "code": str(error) if isinstance(error, Refusal) else "preparation.unavailable",
                          "qualified": False, "imageBuilt": False, "productionAuthorized": False}))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
