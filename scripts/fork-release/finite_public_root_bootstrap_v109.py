"""One finite public Git fetch before unchanged source qualification gates.

No alternate origin, lazy/deepening loop, cache, SDK or application command.
The exact shallow P checkout is bootstrap only. Qualification requires full
M/S connectivity, unchanged HEAD=P and the maintained physical merge proof.
"""
import argparse
import base64
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

ORIGIN = "https://github.com/fr-meyer/openclaw"
GIT = "/usr/bin/git"
HELPER_SECONDS = 600
CLEANUP_RESERVE_SECONDS = 20
PREFIX_BYTES = 16384
FETCH_OUTPUT_BYTES = 2097152
METADATA_BYTES = 67108864
OWNER_PINS = {
    "bounded_run_contract_v109.py": "381781d940f04af764a68e8967f0794e3ecb2cc12c17128a5310fb6af921bfe2",
    "composite_closed_usage.py": "b5c923e0205a4d49ae81dced385398199725185249a81711ac371d07e624bdb4",
    "manifest_capture.py": "d5fd42317bf538720b48949a9503dc3c58df6a0035f200ac30a20400c1ed3eac",
    "preflight.py": "89b6ba41fc89131f33754104fdd0d3ebc08c20f252288651bc7d95038639103a",
    "release.py": "5026178bb85a9ff51a36f7512a899c8cd4beab2f5b3ed146e1e0d87c0dc3a639",
    "source_validation_contract_v109.py": "2e8fd0741ad3e0830974c10ff50bd1a34f4cbf8f9a36e871854191e67d05c102",
    "source_validation_v108.py": "d2e014f20f5227b183ea217d9874ef7159c90a894debe5a6581bd4696145f965",
    "source_validation_v109.py": "a74b9bb90955ac4e87c7c3c9cafe5a926d4ef3516b07aff076c17f187a350f00",
}


class Refusal(ValueError):
    pass


def need(value, code):
    if not value:
        raise Refusal("bootstrap." + code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def regular(path, maximum):
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
         before.st_uid == os.geteuid() and before.st_size <= maximum, "regular_input")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        raw = stream.read(maximum + 1); after = os.fstat(stream.fileno())
    keys = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    need(keys(before) == keys(after) == keys(path.lstat()) and len(raw) == before.st_size,
         "input_changed")
    return raw


def owners(folder):
    for name, expected in OWNER_PINS.items():
        need(sha(regular(folder / name, 524288)) == expected, "owner_pin")
    runtime = importlib.import_module("source_validation_v109")
    core = importlib.import_module("source_validation_v108")
    for module in (runtime, core):
        need(Path(module.__file__).resolve().parent == folder, "owner_import_path")
    return runtime, core


def git_environment(env):
    return {"PATH": env["PATH"], "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0", "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1", "GIT_GRAFT_FILE": "/dev/null",
        "GIT_OPTIONAL_LOCKS": "0"}


def fetch_environment(base, token):
    need(type(token) is str and 20 <= len(token) <= 4096 and
         all(32 < ord(c) < 127 for c in token), "job_token")
    header = "AUTHORIZATION: basic " + base64.b64encode(("x-access-token:" + token).encode()).decode()
    settings = {"protocol.allow": "never", "protocol.https.allow": "always",
        "credential.helper": "", "core.hooksPath": "/dev/null", "maintenance.auto": "0",
        "gc.auto": "0", "core.useReplaceRefs": "false",
        "http.https://github.com/.extraheader": header}
    result = dict(base, GIT_CONFIG_COUNT=str(len(settings)))
    for i, (key, value) in enumerate(settings.items()):
        result["GIT_CONFIG_KEY_" + str(i)] = key
        result["GIT_CONFIG_VALUE_" + str(i)] = value
    return result, (token.encode(), header.encode(), header.split()[-1].encode())


def redacted_prefix(raw, secrets):
    # Redact before truncation, including whole lines containing partial token
    # prefixes or authentication fields. Never persist raw child auth output.
    result = []
    for line in raw.splitlines(keepends=True):
        low = line.lower()
        sensitive = any(secret and (secret in line or secret[:8] in line) for secret in secrets)
        if sensitive or re.search(rb"authorization|extraheader|git_config_value|(?:https?://)[^/\s]+@", low):
            result.append(b"[redacted authentication line]\n")
        else:
            result.append(line)
    return b"".join(result)[:PREFIX_BYTES]


def identity_output(mode, code, raw, head):
    """Only these five repository queries may enter closed identity custody."""
    need(mode in ("origin", "head", "shallow", "config", "replacement_refs"), "identity_mode")
    if mode == "origin":
        return (type(code) is int and code == 0 and raw in
                (ORIGIN.encode() + b"\n", (ORIGIN + ".git").encode() + b"\n")), "fixed_origin"
    if mode == "head":
        return (type(code) is int and code == 0 and raw == head.encode() + b"\n"), "head_must_remain_P"
    if mode == "shallow":
        return (type(code) is int and code == 0 and raw in (b"true\n", b"false\n")), "full_nonshallow"
    if mode == "replacement_refs":
        return (type(code) is int and code == 0 and raw == b""), "replacement_or_graft"
    return (type(code) is int and code == 1 and raw == b""), (
        "partial_or_redirect_config" if code == 0 else "config_unavailable")


class CapturedChild:
    """Keep stderr while reusing the existing verified owned-group cleanup."""
    def __init__(self, child):
        self.child = child; self.stdout = b""; self.stderr = b""

    def __getattr__(self, name):
        return getattr(self.child, name)

    def communicate(self, timeout):
        try:
            self.stdout, self.stderr = self.child.communicate(timeout=timeout)
            return self.stdout, self.stderr
        except subprocess.TimeoutExpired as error:
            self.stdout, self.stderr = error.stdout or b"", error.stderr or b""
            raise


class OwnedGit:
    def __init__(self, root, env, deadline, output, core, secrets=()):
        self.root, self.env, self.deadline = root, env, deadline
        self.output, self.core, self.secrets = output, core, secrets
        self.ordinal = 0

    def run(self, argv, *, env=None, fetch=False, suppress_output=False, identity_mode=None, expected_head=None):
        remaining = min(self.deadline - time.time(), HELPER_SECONDS if fetch else 60)
        need(remaining > 0, "shared_deadline")
        self.ordinal += 1
        stem = self.output / ("%03d" % self.ordinal)
        timed_out = interrupted = False
        settled, reason = None, "not_requested"
        try:
            child = CapturedChild(subprocess.Popen(argv, cwd=self.root,
                env=self.env if env is None else env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                start_new_session=True))
        except OSError as error:
            fact = {"schema": "openclaw.v109.finite-root-child.v1", "ordinal": self.ordinal,
                "kind": "finite_fetch" if fetch else "local_metadata", "exitCode": None,
                "launchErrno": error.errno, "timedOut": False, "interrupted": False,
                "childStarted": False, "outputSuppressed": suppress_output, "stdout": {"bytes": 0, "sha256": sha(b"")},
                "stderr": {"bytes": 0, "sha256": sha(b"")}}
            save(Path(str(stem) + ".stdout.redacted.private"), b"")
            save(Path(str(stem) + ".stderr.redacted.private"), b"")
            save(Path(str(stem) + ".status.private.json"), (json.dumps(fact, sort_keys=True) + "\n").encode())
            raise Refusal("bootstrap.child_launch_refused") from None
        try:
            child.communicate(timeout=remaining)
        except (subprocess.TimeoutExpired, self.core.ProfileInterrupted, KeyboardInterrupt) as error:
            timed_out = isinstance(error, subprocess.TimeoutExpired)
            interrupted = not timed_out
            _, settled, reason = self.core.settle_owned_timeout_group(child)
        identity_ok, identity_code = (True, "identity_mode") if identity_mode is None else identity_output(
            identity_mode, child.returncode, child.stdout, expected_head)
        hide_stdout = suppress_output or not identity_ok
        hide_stderr = suppress_output or identity_mode is not None
        fact = {"schema": "openclaw.v109.finite-root-child.v1", "ordinal": self.ordinal,
            "kind": "finite_fetch" if fetch else "local_metadata", "exitCode": child.returncode,
            "timedOut": timed_out, "interrupted": interrupted,
            "cleanupSettled": settled, "cleanupReason": reason, "outputSuppressed": hide_stdout,
            "repositoryIdentityMode": identity_mode, "identityAccepted": identity_ok if identity_mode else None}
        for key, raw in (("stdout", child.stdout), ("stderr", child.stderr)):
            prefix = b"" if (hide_stdout if key == "stdout" else hide_stderr) else redacted_prefix(raw, self.secrets)
            save(Path(str(stem) + "." + key + ".redacted.private"), prefix)
            fact[key] = {"bytes": len(raw), "sha256": sha(raw), "redactedPrefixBytes": len(prefix)}
        save(Path(str(stem) + ".status.private.json"), (json.dumps(fact, sort_keys=True) + "\n").encode())
        # Only sanitized prefixes and fixed metadata may reach public CI logs.
        if timed_out or interrupted or child.returncode not in (0, 1) or (fetch and child.returncode != 0) or not identity_ok:
            print(json.dumps({**fact,
                "stdoutRedactedPrefix": "" if hide_stdout else redacted_prefix(child.stdout, self.secrets).decode("utf-8", "replace"),
                "stderrRedactedPrefix": "" if hide_stderr else redacted_prefix(child.stderr, self.secrets).decode("utf-8", "replace")}), flush=True)
        need(not timed_out and not interrupted, "owned_child_incomplete")
        need(len(child.stdout) <= (FETCH_OUTPUT_BYTES if fetch else METADATA_BYTES) and
             len(child.stderr) <= FETCH_OUTPUT_BYTES, "child_output_cap")
        need(identity_ok, identity_code)
        return subprocess.CompletedProcess(argv, child.returncode,
            b"" if hide_stdout else child.stdout, b"" if hide_stderr else child.stderr)

    def read(self, *args, repository_identity=None, expected_head=None):
        argv = [GIT, "--no-replace-objects", "-C", str(self.root),
            "-c", "protocol.allow=never", "-c", "credential.helper=",
            "-c", "core.hooksPath=/dev/null", "-c", "maintenance.auto=0", "-c", "gc.auto=0", *args]
        result = self.run(argv, suppress_output=bool(args and args[0] == "config"),
            identity_mode=repository_identity, expected_head=expected_head)
        if result.returncode != 0:
            raise subprocess.CalledProcessError(result.returncode, argv, output=result.stdout)
        return result.stdout


    def read_identity(self, mode, head=None):
        queries = {
            "origin": ("remote", "get-url", "origin"),
            "head": ("rev-parse", "HEAD"),
            "shallow": ("rev-parse", "--is-shallow-repository"),
            "config": ("config", "--local", "--get-regexp", r"^(extensions\.partialclone|remote\..*\.promisor|url\.|include\.|includeif\.|http\.|credential\.|core\.sshcommand|remote\..*\.(proxy|vcs|uploadpack)|protocol\.)"),
            "replacement_refs": ("for-each-ref", "--format=%(refname)", "refs/replace"),
        }
        need(mode in queries, "identity_mode")
        need(mode != "head" or type(head) is str and re.fullmatch(r"[0-9a-f]{40}", head), "identity_expected_head")
        return self.read(*queries[mode], repository_identity=mode, expected_head=head)


def repository_state(owner, head, allow_shallow):
    root = owner.root
    need(root.is_dir() and not root.is_symlink() and root.resolve() == root.absolute() and
         root.stat().st_uid == os.geteuid(), "owned_pipeline")
    gd = root / ".git"
    need(gd.is_dir() and not gd.is_symlink() and gd.resolve() == gd and
         not (gd / "commondir").exists(), "independent_pipeline_git")
    need(owner.read_identity("origin").strip() in (ORIGIN.encode(), (ORIGIN + ".git").encode()), "fixed_origin")
    need(owner.read_identity("head", head).strip() == head.encode(), "head_must_remain_P")
    shallow = owner.read_identity("shallow").strip()
    need(shallow in (b"true", b"false") and (allow_shallow or shallow == b"false"), "full_nonshallow")
    try:
        owner.read_identity("config")
    except subprocess.CalledProcessError as error:
        need(error.returncode == 1, "config_unavailable")
    else:
        raise Refusal("bootstrap.partial_or_redirect_config")
    objects = gd / "objects"
    need(objects.is_dir() and not objects.is_symlink() and objects.resolve() == objects and
         objects.stat().st_uid == os.geteuid(), "owned_objects")
    for directory, directories, files in os.walk(objects, followlinks=False):
        for name in directories + files:
            item = Path(directory) / name
            need(not item.is_symlink() and item.resolve() == item, "object_symlink")
            if name in files:
                info = item.stat()
                need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                     info.st_uid == os.geteuid(), "independent_object_file")
    for name in ("config", "HEAD", "FETCH_HEAD", "shallow"):
        item = gd / name
        if item.exists() or item.is_symlink():
            info = item.lstat()
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                 info.st_uid == os.geteuid(), "git_control_file")
    need(not (gd / "info/grafts").exists() and not (gd / "info/grafts").is_symlink() and
         owner.read_identity("replacement_refs").strip() == b"",
         "replacement_or_graft")
    for name in ("alternates", "http-alternates"):
        need(not (gd / "objects/info" / name).exists() and not (gd / "objects/info" / name).is_symlink(), "alternate_objects")
    need(not list((gd / "objects/pack").glob("*.promisor")), "promisor_pack")
    return shallow == b"true"


def fetch_argv(root, merge, source, shallow):
    return [GIT, "--no-replace-objects", "-C", str(root), "fetch", "--no-tags",
        "--no-recurse-submodules", *(["--unshallow"] if shallow else []), ORIGIN, merge, source]


def acquire(owner, runtime, core, head, merge, selected, fetch_env):
    need(all(type(x) is str and re.fullmatch(r"[0-9a-f]{40}", x) for x in
             (head, merge, selected["source"]["sourceSha"], selected["source"]["sourceTree"])) and
         merge != head, "exact_roots")
    shallow = repository_state(owner, head, True)
    result = owner.run(fetch_argv(owner.root, merge, selected["source"]["sourceSha"], shallow),
                       env=fetch_env, fetch=True)
    need(result.returncode == 0, "one_finite_fetch_refused")
    repository_state(owner, head, False)
    owner.read("fsck", "--connectivity-only", "--strict", "--no-reflogs", "--no-dangling",
               merge, selected["source"]["sourceSha"])
    need(owner.read("cat-file", "-t", selected["source"]["sourceSha"]).strip() == b"commit" and
         owner.read("rev-parse", selected["source"]["sourceSha"] + "^{tree}").strip() ==
         selected["source"]["sourceTree"].encode(), "source_object_tree")
    observed = {}
    def graph_read(*args):
        raw = owner.read(*args)
        if args == ("show", "-s", "--format=%P", merge):
            observed["parents"] = raw.strip().split()
            observed["sha256"] = sha(raw)
        return raw
    proof = runtime.workflow_merge_binding(graph_read, core, head, merge)
    need(observed.get("parents") == [runtime.WORKFLOW_TARGET.encode(), head.encode()], "actual_parent_evidence")
    need(owner.read_identity("head", head).strip() == head.encode(), "head_changed")
    return {"schema": "openclaw.v109.finite-root-bootstrap.v1", "status": "full_closure_only",
        "pipelineHead": head, "workflowMerge": merge, "sourceSha": selected["source"]["sourceSha"],
        "sourceTree": selected["source"]["sourceTree"], "mergeProof": proof,
        "actualWorkflowParents": [value.decode("ascii") for value in observed["parents"]],
        "workflowParentsRawSha256": observed["sha256"], "declaredPRBase": runtime.policy.BASE,
        "fetchAttempts": 1, "sourceQualified": False, "applicationExecuted": False}


def main(argv=None, environment=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print('{"status":"DISARMED","networkCalls":0}')
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--job", choices=("admission", "source", "final"), required=True)
    parser.add_argument("--profile")
    args = parser.parse_args(argv)
    env = dict(os.environ if environment is None else environment)
    workspace = Path(env["GITHUB_WORKSPACE"]).absolute()
    pipeline = workspace / "pipeline"
    folder = pipeline / "scripts/fork-release"
    need(Path(__file__).resolve().parent == folder and workspace.resolve() == workspace, "fixed_workspace")
    runtime, core = owners(folder)
    bindings, selected, request_raw = runtime.load_metadata(pipeline, active=True, now=time.time())
    need(env.get("V109_APPROVED_AT") == bindings["authorization"]["approvedAt"] and
         env.get("V109_EXPIRES_AT") == runtime.policy.source_authorization_window(bindings)[1], "workflow_clock_binding")
    need((args.job == "source") == (args.profile in runtime.policy.PROFILES) and
         (args.job == "source" or args.profile is None), "fixed_job_profile")
    event = runtime.policy.parse(regular(Path(env["GITHUB_EVENT_PATH"]), 1048576))
    head = runtime.event_binding(event, env)
    merge = env.get("GITHUB_WORKFLOW_SHA")
    if args.job == "source":
        runtime.check_admission_outputs(env, selected, request_raw, head)
    deadline = runtime.job_deadline(bindings, selected, env, args.profile)
    if args.job == "final":
        deadline = min(deadline, int(env[runtime.CLOCK]) + 10 * 60 - 60)
    deadline = min(deadline, time.time() + HELPER_SECONDS) - CLEANUP_RESERVE_SECONDS
    need(deadline > time.time(), "shared_deadline")
    temp = Path(env["RUNNER_TEMP"]).absolute()
    need(temp.is_dir() and temp.resolve() == temp and not temp.is_symlink() and
         temp.stat().st_uid == os.geteuid(), "owned_temporary_root")
    out = temp / ("v109-finite-roots-" + args.job + ("-" + args.profile if args.profile else ""))
    out.mkdir(mode=0o700)  # No reuse/retry of an uncertain acquisition.
    base_env = git_environment(env)
    authenticated, secrets = fetch_environment(base_env, env.get("GH_TOKEN"))
    owner = OwnedGit(pipeline, base_env, deadline, out, core, secrets)
    with core.profile_signals():
        proof = acquire(owner, runtime, core, head, merge, selected, authenticated)
    save(out / "RESULT.private.json", (json.dumps(proof, sort_keys=True) + "\n").encode())
    print(json.dumps(proof, sort_keys=True), flush=True)
    return 0


def safe_refusal_code(error):
    value = str(error)
    return value if isinstance(error, ValueError) and re.fullmatch(
        r"(?:bootstrap|v9|need)\.[a-z0-9_]+", value) else "bootstrap.runtime_refused"


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, KeyError, TypeError, OSError, ImportError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "refused", "code": safe_refusal_code(error),
                          "sourceQualified": False, "applicationExecuted": False}), flush=True)
        raise SystemExit("bootstrap refused; bounded redacted child custody retained where created")
