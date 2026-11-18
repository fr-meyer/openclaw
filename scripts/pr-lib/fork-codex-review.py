#!/usr/bin/env python3
"""Fresh fork-only Codex review. Local receipts attest invocation, not signatures."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import stat
import subprocess
import sys
import tempfile
import time

FORK = "fr-meyer/openclaw"
SHA = re.compile(r"[0-9a-f]{40}\Z")
MAX_AGE = 12 * 60 * 60
HELPER = ".agents/skills/autoreview/scripts/autoreview"


class Refusal(Exception):
    pass


def need(condition, message):
    if not condition:
        raise Refusal(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_hash(path):
    need(stat.S_ISREG(path.lstat().st_mode), f"not a regular evidence/code file: {path.name}")
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def clean_environment(environment):
    # Keep approved ordinary authentication; never inherit review/checkout overrides.
    removed = {"CODEX_BIN", "GH_HOST", "GH_REPO", "PYTHONPATH", "PYTHONHOME"}
    env = {k: v for k, v in environment.items()
           if k not in removed and not k.startswith(("AUTOREVIEW_", "GIT_"))}
    env.update(GIT_NO_LAZY_FETCH="1", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    return env


def invoke(argv, cwd, env, runner, log=None):
    result = runner(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                    stdout=log if log is not None else subprocess.PIPE,
                    stderr=subprocess.STDOUT if log is not None else subprocess.PIPE,
                    **({} if log is not None else {"timeout": 30}))
    need(result.returncode == 0, f"{Path(argv[0]).name} exited {result.returncode}")
    return result.stdout if log is None else b""


def source_identity(checkout, base, head, git, env, runner):
    def read(*args):
        return invoke([str(git), "--no-replace-objects", "-C", str(checkout), *args],
                      checkout, env, runner)
    need(read("rev-parse", "--show-toplevel").decode().strip() == str(checkout), "checkout root differs")
    need(not read("status", "--porcelain=v1", "--untracked-files=no", "--ignore-submodules=none").strip(),
         "tracked source is not clean")
    local = read("rev-parse", "HEAD").decode().strip()
    need(SHA.fullmatch(local), "invalid local head")
    for commit in (base, head, local):
        need(read("rev-parse", f"{commit}^{{commit}}").decode().strip() == commit, "commit unavailable")
    tree = read("rev-parse", f"{head}^{{tree}}").decode().strip()
    need(read("rev-parse", f"{local}^{{tree}}").decode().strip() == tree, "local/hosted trees differ")
    merge_base = read("merge-base", "--all", base, head).decode().strip()
    need(SHA.fullmatch(merge_base), "missing or ambiguous merge base")
    need(read("merge-base", "--all", base, local).decode().strip() == merge_base, "merge bases differ")
    hashes = {}
    for key, origin in (("diffSha256", base), ("reviewDiffSha256", merge_base)):
        args = ("diff", "--binary", "--full-index", "--no-ext-diff", "--no-textconv", origin)
        data = read(*args, head, "--")
        need(data == read(*args, local, "--"), "local/hosted diffs differ")
        hashes[key] = digest(data)
    return {"baseSha": base, "headSha": head, "localHeadSha": local, "tree": tree,
            "mergeBaseSha": merge_base, **hashes}


def current_pr(pr, base, head, gh, cwd, env, runner):
    raw = invoke([str(gh), "api", "--hostname", "github.com", f"repos/{FORK}/pulls/{pr}"],
                 cwd, env, runner)
    value = json.loads(raw)
    need(value.get("number") == pr and value.get("state") == "open" and value.get("draft") is False,
         "PR is not open and ready")
    need(value["base"]["repo"]["full_name"] == FORK, "PR target repository differs")
    repository = value["head"].get("repo")
    need(type(repository) is dict, "PR head repository unavailable")
    full_name = repository.get("full_name")
    need(isinstance(full_name, str) and re.fullmatch(r"[A-Za-z0-9-]+/[A-Za-z0-9_.-]+", full_name)
         and full_name.split("/")[1] not in (".", "..")
         and type(repository.get("id")) is int and repository["id"] > 0
         and repository.get("private") is False
         and repository.get("html_url") == f"https://github.com/{full_name}",
         "PR head repository is not a valid public GitHub identity")
    need(value["base"]["sha"] == base and value["head"]["sha"] == head, "live PR base/head differs")
    return {"baseRef": value["base"]["ref"], "headRef": value["head"]["ref"],
            "headRepository": {"id": repository["id"], "fullName": full_name,
                               "htmlUrl": repository["html_url"], "private": False}}


def require_complete_path_coverage(helper, checkout, source, git, env, runner):
    # Import the trusted anchored policy without running its CLI or any PR helper.
    policy = runpy.run_path(str(helper), run_name="_fork_codex_path_policy")
    predicate = policy.get("tracked_sensitive_paths")
    need(callable(predicate), "anchored reviewer path policy unavailable")
    raw = invoke([str(git), "--no-replace-objects", "-C", str(checkout), "diff", "--name-only",
                  "-z", "--no-renames", source["mergeBaseSha"], source["headSha"], "--"],
                 checkout, env, runner)
    paths = [os.fsdecode(value) for value in raw.split(b"\0") if value]
    need(not predicate(paths), "review would omit changed paths; complete review required")
    return {"changedPathCount": len(paths), "changedPathsSha256": digest(raw)}


def validate_result(report, status):
    need(status.get("schema_version") == 1 and status.get("engine") == "codex", "wrong review producer")
    need(status.get("status") == "scoped-clean" and status.get("exit_code") == 0
         and status.get("report_produced") is True and status.get("timed_out") is False
         and status.get("reason") is None and status.get("reviewer_exit_code") in (None, 0),
         "review did not complete cleanly")
    need(report.get("review_status") == "scoped-clean" and report.get("findings") == []
         and report.get("overall_correctness") == "patch is correct"
         and isinstance(report.get("overall_explanation"), str) and report["overall_explanation"].strip(),
         "review verdict is incomplete or has findings")
    for key in ("scope_rejected_findings", "priority_filtered_findings", "attribution_rejected_findings",
                "missing_required_findings"):
        need(not report.get(key), "review omitted or filtered findings")
    for value in (report, status):
        if "usage" in value:
            need(value["usage"].get("complete") is True, "review usage records incomplete attempts")


def validate_times(start, end, elapsed):
    need(0 <= elapsed < MAX_AGE and 0 <= end - start < MAX_AGE, "review expired or clock moved backwards")
    need(abs((end - start) - elapsed) <= 300, "review clock drift exceeds five minutes")


def read_json(path):
    file_hash(path)
    need(path.stat().st_size <= 8 * 1024 * 1024, "review output exceeds bound")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, "duplicate review JSON key")
            result[key] = value
        return result
    value = json.loads(path.read_bytes(), object_pairs_hook=unique)
    need(type(value) is dict, "invalid review JSON object")
    return value


def review(args, runner=subprocess.run, clock=time.time, monotonic=time.monotonic,
           environment=None, code_root=None):
    need(args.repository == FORK and args.host == "github.com", "review route is fork-only")
    need(type(args.pr) is int and args.pr > 0 and SHA.fullmatch(args.base_sha) and SHA.fullmatch(args.head_sha),
         "invalid expected PR identity")
    checkout = Path(args.checkout).resolve(strict=True)
    anchor = (code_root or Path(__file__).resolve().parents[2]).resolve(strict=True)
    helper = anchor / HELPER
    for path in (helper, *helper.parents):
        if path == anchor:
            break
        need(not path.is_symlink(), "anchored helper path is a symlink")
    env = clean_environment(os.environ if environment is None else environment)
    tools = {}
    for name in ("git", "gh", "codex"):
        found = shutil.which(name, path=env.get("PATH"))
        need(found, f"required trusted tool unavailable: {name}")
        tool = Path(found).resolve(strict=True)
        need(not tool.is_relative_to(checkout), "tool resolves inside reviewed checkout")
        tools[name] = tool
    env["AUTOREVIEW_GIT"] = str(tools["git"])
    env["PYTHONNOUSERSITE"] = "1"
    code = {"gate": Path(__file__).resolve(), "autoreview": helper, **tools}
    pinned = {key: {"path": str(path), "sha256": file_hash(path)} for key, path in code.items()}
    # Autoreview refuses outputs anywhere inside its source checkout, including .local.
    directory = Path(tempfile.mkdtemp(prefix="openclaw-fork-codex-")).resolve()
    need(not directory.is_relative_to(checkout), "evidence directory is inside reviewed source")
    os.chmod(directory, 0o700)
    receipt_path = directory / "receipt.json"
    paths = {key: directory / name for key, name in
             (("report", "report.json"), ("status", "status.json"), ("summary", "review.txt"), ("log", "invocation.log"))}
    start, tick = clock(), monotonic()
    receipt = {"schema": "openclaw.fork-codex-review.v1", "repository": FORK, "host": args.host,
               "prNumber": args.pr, "startedAt": start, "invocation": directory.name,
               "producer": "trusted-local-invocation", "cryptographicAttestation": False,
               "code": pinned, "status": "failed", "maxPriority": "P2"}
    try:
        source = source_identity(checkout, args.base_sha, args.head_sha, tools["git"], env, runner)
        live = current_pr(args.pr, args.base_sha, args.head_sha, tools["gh"], directory, env, runner)
        receipt.update(source)
        receipt.update(live)
        receipt.update(require_complete_path_coverage(helper, checkout, source, tools["git"], env, runner))
        argv = [sys.executable, "-I", str(helper), "--mode", "branch", "--base", args.base_sha,
                "--engine", "codex", "--codex-bin", str(tools["codex"]), "--max-priority", "P2",
                "--engine-timeout-seconds", "1200", "--json-output", str(paths["report"]),
                "--status-output", str(paths["status"]), "--output", str(paths["summary"])]
        receipt["command"] = argv
        with paths["log"].open("xb") as log:
            invoke(argv, checkout, env, runner, log)
        validate_result(read_json(paths["report"]), read_json(paths["status"]))
        need(source_identity(checkout, args.base_sha, args.head_sha, tools["git"], env, runner) == source,
             "source changed during review")
        need(current_pr(args.pr, args.base_sha, args.head_sha, tools["gh"], directory, env, runner) == live,
             "PR branches or repository changed during review")
        need({key: {"path": str(path), "sha256": file_hash(path)} for key, path in code.items()} == pinned,
             "review code changed during invocation")
        end, elapsed = clock(), monotonic() - tick
        validate_times(start, end, elapsed)
        receipt.update(status="scoped-clean", completedAt=end, elapsedSeconds=elapsed)
    finally:
        receipt["files"] = {key: {"path": str(path), "sha256": file_hash(path)}
                            for key, path in paths.items() if path.exists()}
        receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        print(f"Fork Codex evidence retained: {receipt_path}", file=sys.stderr)
    return {**receipt, "receiptPath": str(receipt_path), "receiptSha256": file_hash(receipt_path)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--pr", required=True, type=int)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--head-sha", required=True)
    try:
        print(json.dumps(review(parser.parse_args()), sort_keys=True))
    except (Refusal, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(f"Fork Codex review refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
