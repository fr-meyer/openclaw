#!/usr/bin/env python3
"""Validation-branch payload. No GitHub writes, review calls, or application build."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import time
import urllib.request

BASE = "57034eb5e70b33bcf1e11ba782693d0d0889bb83"
PATCH_SHA = "a5b28834b24c28dab8f9667c2e6a6629193d49747abc36e7f5b83d0ba233c6a2"
REPOSITORY = "fr-meyer/openclaw"
BRANCH = "refs/heads/validation/pr114287-a5b288"
WORKSPACES = [
  {
    "directory": ".",
    "name": "openclaw"
  },
  {
    "directory": "extensions/acpx",
    "name": "@openclaw/acpx"
  },
  {
    "directory": "extensions/admin-http-rpc",
    "name": "@openclaw/admin-http-rpc"
  },
  {
    "directory": "extensions/amazon-bedrock",
    "name": "@openclaw/amazon-bedrock-provider"
  },
  {
    "directory": "extensions/anthropic",
    "name": "@openclaw/anthropic-provider"
  },
  {
    "directory": "extensions/beam",
    "name": "@openclaw/beam"
  },
  {
    "directory": "extensions/buzz",
    "name": "@openclaw/buzz"
  },
  {
    "directory": "extensions/canvas",
    "name": "@openclaw/canvas-plugin"
  },
  {
    "directory": "extensions/chutes",
    "name": "@openclaw/chutes-provider"
  },
  {
    "directory": "extensions/clawrouter",
    "name": "@openclaw/clawrouter"
  },
  {
    "directory": "extensions/codex",
    "name": "@openclaw/codex"
  },
  {
    "directory": "extensions/copilot",
    "name": "@openclaw/copilot"
  },
  {
    "directory": "extensions/crabbox",
    "name": "@openclaw/crabbox-provider"
  },
  {
    "directory": "extensions/diagnostics-otel",
    "name": "@openclaw/diagnostics-otel"
  },
  {
    "directory": "extensions/diagnostics-prometheus",
    "name": "@openclaw/diagnostics-prometheus"
  },
  {
    "directory": "extensions/diffs",
    "name": "@openclaw/diffs"
  },
  {
    "directory": "extensions/discord",
    "name": "@openclaw/discord"
  },
  {
    "directory": "extensions/document-extract",
    "name": "@openclaw/document-extract-plugin"
  },
  {
    "directory": "extensions/feishu",
    "name": "@openclaw/feishu"
  },
  {
    "directory": "extensions/file-transfer",
    "name": "@openclaw/file-transfer"
  },
  {
    "directory": "extensions/firecrawl",
    "name": "@openclaw/firecrawl-plugin"
  },
  {
    "directory": "extensions/google",
    "name": "@openclaw/google-plugin"
  },
  {
    "directory": "extensions/googlechat",
    "name": "@openclaw/googlechat"
  },
  {
    "directory": "extensions/imessage",
    "name": "@openclaw/imessage"
  },
  {
    "directory": "extensions/irc",
    "name": "@openclaw/irc"
  },
  {
    "directory": "extensions/line",
    "name": "@openclaw/line"
  },
  {
    "directory": "extensions/logbook",
    "name": "@openclaw/logbook"
  },
  {
    "directory": "extensions/matrix",
    "name": "@openclaw/matrix"
  },
  {
    "directory": "extensions/mattermost",
    "name": "@openclaw/mattermost"
  },
  {
    "directory": "extensions/memory-core",
    "name": "@openclaw/memory-core"
  },
  {
    "directory": "extensions/msteams",
    "name": "@openclaw/msteams"
  },
  {
    "directory": "extensions/openai",
    "name": "@openclaw/openai-provider"
  },
  {
    "directory": "extensions/qa-channel",
    "name": "@openclaw/qa-channel"
  },
  {
    "directory": "extensions/qa-lab",
    "name": "@openclaw/qa-lab"
  },
  {
    "directory": "extensions/radius",
    "name": "@openclaw/radius-provider"
  },
  {
    "directory": "extensions/session-share",
    "name": "@openclaw/session-share"
  },
  {
    "directory": "extensions/slack",
    "name": "@openclaw/slack"
  },
  {
    "directory": "extensions/team-reports",
    "name": "@openclaw/team-reports"
  },
  {
    "directory": "extensions/telegram",
    "name": "@openclaw/telegram"
  },
  {
    "directory": "extensions/twitch",
    "name": "@openclaw/twitch"
  },
  {
    "directory": "extensions/webhooks",
    "name": "@openclaw/webhooks"
  },
  {
    "directory": "extensions/whatsapp",
    "name": "@openclaw/whatsapp"
  },
  {
    "directory": "extensions/workboard",
    "name": "@openclaw/workboard"
  },
  {
    "directory": "extensions/xai",
    "name": "@openclaw/xai-plugin"
  },
  {
    "directory": "packages/acp-core",
    "name": "@openclaw/acp-core"
  },
  {
    "directory": "packages/agent-core",
    "name": "@openclaw/agent-core"
  },
  {
    "directory": "packages/ai",
    "name": "@openclaw/ai"
  },
  {
    "directory": "packages/gateway-client",
    "name": "@openclaw/gateway-client"
  },
  {
    "directory": "packages/gateway-protocol",
    "name": "@openclaw/gateway-protocol"
  },
  {
    "directory": "packages/llm-core",
    "name": "@openclaw/llm-core"
  },
  {
    "directory": "packages/markdown-core",
    "name": "@openclaw/markdown-core"
  },
  {
    "directory": "packages/media-core",
    "name": "@openclaw/media-core"
  },
  {
    "directory": "packages/media-generation-core",
    "name": "@openclaw/media-generation-core"
  },
  {
    "directory": "packages/media-understanding-common",
    "name": "@openclaw/media-understanding-common"
  },
  {
    "directory": "packages/memory-host-sdk",
    "name": "@openclaw/memory-host-sdk"
  },
  {
    "directory": "packages/mermaid-renderer",
    "name": "@openclaw/mermaid-renderer"
  },
  {
    "directory": "packages/model-catalog-core",
    "name": "@openclaw/model-catalog-core"
  },
  {
    "directory": "packages/net-policy",
    "name": "@openclaw/net-policy"
  },
  {
    "directory": "packages/normalization-core",
    "name": "@openclaw/normalization-core"
  },
  {
    "directory": "packages/plugin-package-contract",
    "name": "@openclaw/plugin-package-contract"
  },
  {
    "directory": "packages/plugin-sdk",
    "name": "@openclaw/plugin-sdk"
  },
  {
    "directory": "packages/retry",
    "name": "@openclaw/retry"
  },
  {
    "directory": "packages/session-url-contract",
    "name": "@openclaw/session-url-contract"
  },
  {
    "directory": "packages/terminal-core",
    "name": "@openclaw/terminal-core"
  },
  {
    "directory": "packages/tool-call-repair",
    "name": "@openclaw/tool-call-repair"
  },
  {
    "directory": "packages/workboard-contract",
    "name": "@openclaw/workboard-contract"
  },
  {
    "directory": "ui",
    "name": "openclaw-control-ui"
  }
]
FILES = sorted([
    "CONTRIBUTING.md",
    "git-hooks/pre-push",
    "scripts/prepare-git-hooks.mjs",
    "scripts/publication-preflight.d.mts",
    "scripts/publication-preflight.mjs",
    "test/scripts/prepare-git-hooks.test.ts",
    "test/scripts/publication-preflight.test.ts",
])
ROOT = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
PROOF = Path(os.environ["RUNNER_TEMP"]) / "pr114287-proof"
PROOF.mkdir(exist_ok=True)


def child_env(offline=True):
    """Explicit safe child inputs; do not inherit Actions service or provider credentials."""
    task_temp = Path(os.environ["RUNNER_TEMP"]).resolve()
    child_home = task_temp / "pr114287-child-home"
    child_tmp = task_temp / "pr114287-child-tmp"
    child_config = child_home / ".config"
    child_cache = child_home / ".cache"
    store = ROOT / ".cache/pr114287-pnpm-store"
    cache = ROOT / ".cache/pr114287-pnpm-cache"
    for directory in [child_home, child_tmp, child_config, child_cache, store, cache]:
        directory.mkdir(parents=True, exist_ok=True)
    npmrc = child_config / "npmrc"
    npmrc.write_text("")
    env = {
        "PATH": os.environ["PATH"], "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC",
        "HOME": str(child_home), "TMPDIR": str(child_tmp), "TMP": str(child_tmp), "TEMP": str(child_tmp),
        "XDG_CONFIG_HOME": str(child_config), "XDG_CACHE_HOME": str(child_cache),
        "NPM_CONFIG_USERCONFIG": str(npmrc), "PNPM_CONFIG_STORE_DIR": str(store), "PNPM_CONFIG_CACHE_DIR": str(cache),
        "PNPM_HOME": str(task_temp / "pr114287-pnpm-home"),
        "COREPACK_ENABLE_DOWNLOAD_PROMPT": "0", "COREPACK_DEFAULT_TO_LATEST": "0",
        "COREPACK_ENABLE_NETWORK": "0" if offline else "1",
        "CI": "true", "GITHUB_ACTIONS": "true", "GITHUB_WORKSPACE": str(ROOT),
        "GIT_NO_LAZY_FETCH": "1", "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
        "OPENCLAW_TSGO_TIMEOUT_MS": "600000", "OPENCLAW_VITEST_MAX_WORKERS": "1",
        "OPENCLAW_VITEST_NO_OUTPUT_TIMEOUT_MS": "300000",
    }
    if os.environ.get("COREPACK_HOME"):
        corepack_home = Path(os.environ["COREPACK_HOME"]).resolve(strict=True)
        assert corepack_home.is_relative_to(task_temp), "toolchain cache is outside this job's temporary owner"
        env["COREPACK_HOME"] = str(corepack_home)
    if offline:
        env.update({"NPM_CONFIG_OFFLINE": "true", "PNPM_CONFIG_OFFLINE": "true", "GIT_ALLOW_PROTOCOL": "file"})
    assert not any(k.startswith("ACTIONS_") or "TOKEN" in k or "SECRET" in k or "API_KEY" in k for k in env)
    return env


def capture(argv):
    return subprocess.check_output(argv, cwd=ROOT, env=child_env())


def save(name, value):
    (PROOF / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def sha(value):
    return hashlib.sha256(value).hexdigest()


def assert_frozen(lane):
    assert capture(["git", "rev-parse", "HEAD"]).decode().strip() == BASE
    paths = capture(["git", "diff", "--name-only", "-z", "HEAD"]).split(b"\0")
    actual_paths = sorted(p.decode() for p in paths if p)
    expected_paths = FILES if lane == "candidate" else []
    assert actual_paths == expected_paths, ("unexpected tracked diff", actual_paths)
    patch = capture(["git", "diff", "--binary", "--full-index", "HEAD", "--", *FILES])
    if lane == "candidate":
        assert sha(patch) == PATCH_SHA, ("selected patch changed", sha(patch))
    else:
        assert patch == b""
    # A staged candidate is deliberately left uncommitted in this ephemeral checkout.
    assert capture(["git", "diff", "--binary", "--full-index"]) == b"", "unstaged tracked mutation"
    return {"head": BASE, "lane": lane, "patch_sha256": sha(patch), "changed_paths": actual_paths}


def verify_complete_baseline():
    tree = capture(["git", "ls-tree", "-r", "-z", "HEAD"])
    records = [r for r in tree.split(b"\0") if r]
    assert len(records) == 44782, ("unexpected pinned tree count", len(records))
    total_bytes = 0
    for record in records:
        metadata, raw_path = record.split(b"\t", 1)
        mode, kind, oid = metadata.decode().split(" ")
        assert kind == "blob", "submodule inputs need a separately reviewed route"
        path = ROOT / os.fsdecode(raw_path)
        file_stat = path.lstat()
        if mode == "120000":
            assert stat.S_ISLNK(file_stat.st_mode)
            data = os.fsencode(os.readlink(path))
        else:
            assert stat.S_ISREG(file_stat.st_mode), os.fsdecode(raw_path)
            assert bool(file_stat.st_mode & 0o111) == (mode == "100755"), os.fsdecode(raw_path)
            data = path.read_bytes()
        actual_oid = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        assert actual_oid == oid, ("pinned blob mismatch", os.fsdecode(raw_path))
        total_bytes += len(data)
    return {"verified_blobs": len(records), "verified_bytes": total_bytes, "tree_listing_sha256": sha(tree)}


def prepare(lane):
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    assert os.environ["GITHUB_REPOSITORY"] == REPOSITORY
    assert os.environ["GITHUB_EVENT_NAME"] == "push"
    assert os.environ["GITHUB_REF"] == BRANCH
    assert event["repository"]["fork"] is True and event["repository"]["private"] is False
    assert not os.environ.get("OPENCLAW_TSGO_SPARSE_SKIP"), "sparse-skip is forbidden for this proof"
    initial = assert_frozen("baseline")
    complete = verify_complete_baseline()
    workflow_sha = os.environ["GITHUB_SHA"]
    assert len(workflow_sha) == 40 and all(c in "0123456789abcdef" for c in workflow_sha)
    url = f"https://raw.githubusercontent.com/{REPOSITORY}/{workflow_sha}/.validation/pr114287-current-main.patch"
    with urllib.request.urlopen(url, timeout=60) as response:
        patch = response.read(2_000_001)
    assert len(patch) <= 2_000_000
    assert sha(patch) == PATCH_SHA, "validation payload patch checksum mismatch"
    patch_path = PROOF / "pr114287-current-main.patch"
    patch_path.write_bytes(patch)
    if lane == "candidate":
        subprocess.run(["git", "apply", "--check", "--index", str(patch_path)], cwd=ROOT, env=child_env(), check=True)
        subprocess.run(["git", "apply", "--index", str(patch_path)], cwd=ROOT, env=child_env(), check=True)
    save("inputs.json", {
        "schema": 1,
        "baseline": BASE,
        "patch_sha256": PATCH_SHA,
        "workflow_commit": workflow_sha,
        "workflow_repository": REPOSITORY,
        "patch_url": url,
        "source": complete,
        "before": initial,
        "after": assert_frozen(lane),
        "runtime_image": {k: os.environ.get(k) for k in ["ImageOS", "ImageVersion", "RUNNER_OS", "RUNNER_ARCH"]},
        "review_gates": "autoreview and final Mergeguez remain separate, unexecuted gates",
    })


def run_logged(name, argv):
    started = time.monotonic()
    with (PROOF / f"{name}.txt").open("wb") as log:
        child = subprocess.Popen(argv, cwd=ROOT, env=child_env(offline=name != "install"),
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for line in iter(child.stdout.readline, b""):
            log.write(line)
            log.flush()
            sys.stdout.buffer.write(line)
            sys.stdout.buffer.flush()
        exit_code = child.wait()
    return {"command": argv, "exit_code": exit_code, "seconds": round(time.monotonic() - started, 3),
            "log_sha256": sha((PROOF / f"{name}.txt").read_bytes())}


def install(lane):
    assert_frozen(lane)
    disk = shutil.disk_usage(ROOT)
    save("disk-reserve.json", {"available_bytes_before_install": disk.free,
                               "minimum_required_bytes": 10 * 1024**3, "passed": disk.free >= 10 * 1024**3})
    assert disk.free >= 10 * 1024**3, "less than 10 GiB free; no cleanup or larger-runner fallback is permitted"
    assert capture(["pnpm", "--version"]).decode().strip() == "12.4.0"
    assert capture(["node", "-p", "process.versions.node"]).decode().strip() == "24.19.0"
    assert len(WORKSPACES) == 67 and len({w["name"] for w in WORKSPACES}) == 67
    filters = [arg for w in WORKSPACES for arg in ["--filter", w["name"]]]
    argv = ["pnpm", "list", "-r", "--depth", "-1", "--json", *filters]
    selection = subprocess.run(argv, cwd=ROOT, env=child_env(), capture_output=True)
    (PROOF / "workspace-selection.json").write_bytes(selection.stdout)
    (PROOF / "workspace-selection-stderr.txt").write_bytes(selection.stderr)
    assert selection.returncode == 0, "pnpm workspace selection failed"
    projects = json.loads(selection.stdout)
    actual = sorted((p["name"], str(Path(p["path"]).resolve().relative_to(ROOT))) for p in projects)
    expected = sorted((w["name"], w["directory"]) for w in WORKSPACES)
    assert actual == expected, ("selected workspace set differs", actual)
    save("install-policy.json", {"selectors": WORKSPACES, "selection_command": argv,
                                 "selected_count": len(projects), "scripts_disabled": True,
                                 "pnpm": "12.4.0", "node": "24.19.0",
                                 "dependencies": "normal frozen selected-importer graph, including dev and optional"})
    result = run_logged("install", ["pnpm", "install", "--frozen-lockfile", "--ignore-scripts",
                                   "--config.enable-pre-post-scripts=false", *filters])
    save("install-result.json", result)
    assert result["exit_code"] == 0, "frozen install failed; no lifecycle-script fallback is permitted"
    assert_frozen(lane)


def network_probe(lane):
    expected_uid = int(os.environ["VALIDATION_EXPECT_UID"])
    expected_gid = int(os.environ["VALIDATION_EXPECT_GID"])
    assert os.geteuid() == expected_uid != 0 and os.getegid() == expected_gid
    namespace = os.readlink("/proc/self/ns/net")
    assert namespace != os.environ["VALIDATION_HOST_NET_NS"], "host network namespace retained"
    interfaces = sorted(line.split(":", 1)[0].strip() for line in Path("/proc/net/dev").read_text().splitlines()[2:])
    assert interfaces == ["lo"], ("unexpected network interface", interfaces)
    routes = Path("/proc/net/route").read_text().splitlines()[1:]
    assert not routes, "isolated network namespace has IPv4 routes"
    save("network-isolation.json", {"lane": lane, "namespace": namespace,
                                     "host_namespace": os.environ["VALIDATION_HOST_NET_NS"],
                                     "uid": expected_uid, "gid": expected_gid, "interfaces": interfaces,
                                     "ipv4_routes": [], "privilege_or_policy_changes": False})


def membership(name, config):
    result = run_logged(name, ["node", "scripts/run-tsgo.mjs", "-p", config, "--listFilesOnly"])
    lines = (PROOF / f"{name}.txt").read_text().splitlines()
    paths = sorted(set(line for line in lines if line.startswith("/")))
    unowned = [p for p in paths if not Path(p).resolve(strict=True).is_relative_to(ROOT)]
    result["members"] = len(paths)
    result["unowned"] = unowned
    result["accepted"] = result["exit_code"] == 0 and bool(paths) and not unowned
    return result


def run(lane):
    network_probe(lane)
    receipt = json.loads((PROOF / "inputs.json").read_text())
    assert receipt["after"]["lane"] == lane
    assert_frozen(lane)
    assert not os.environ.get("OPENCLAW_TSGO_SPARSE_SKIP")
    # Normal frozen install creates physical package roots under the checkout's node_modules.
    packages = {}
    for package, version in [("typescript-native", "7.0.2"), ("vitest", "5.0.0")]:
        package_file = (ROOT / "node_modules" / package / "package.json").resolve(strict=True)
        assert package_file.is_relative_to(ROOT / "node_modules"), ("foreign package root", package_file)
        metadata = json.loads(package_file.read_text())
        assert metadata["version"] == version, (package, metadata["version"])
        packages[package] = {"version": version, "physical_package_file": str(package_file),
                             "package_json_sha256": sha(package_file.read_bytes())}
    results = {"lane": lane, "baseline": BASE, "patch_sha256": PATCH_SHA,
               "packages": packages, "commands": {}, "review_gates_executed": False}
    results["child_environment_keys"] = sorted(child_env())
    save("results.json", results)
    for name, argv in [("scripts-types", ["pnpm", "tsgo:scripts"]),
                       ("test-root-types", ["pnpm", "tsgo:test:root"])]:
        results["commands"][name] = run_logged(name, argv)
        save("results.json", results)
        assert_frozen(lane)
    results["membership"] = {
        "scripts": membership("scripts-membership", "tsconfig.scripts.json"),
        "test-root": membership("test-root-membership", "test/tsconfig/tsconfig.test.root.json"),
    }
    save("results.json", results)
    tests = ["test/scripts/prepare-git-hooks.test.ts"]
    if lane == "candidate":
        tests.append("test/scripts/publication-preflight.test.ts")
    report_path = PROOF / "vitest.json"
    argv = ["node", "scripts/run-vitest.mjs", "run", "--config", "test/vitest/vitest.tooling.config.ts",
            *tests, "--maxWorkers=1", "--reporter=default", "--reporter=json", "--outputFile.json", str(report_path)]
    results["commands"]["targeted-tests"] = run_logged("targeted-tests", argv)
    try:
        report = json.loads(report_path.read_text())
        expected = {str(ROOT / t) for t in tests}
        actual = {t["name"] for t in report["testResults"]}
        assert actual == expected, ("unexpected selected suites", actual)
        assert report["success"] is True
        assert report["numFailedTests"] == 0 and report["numPendingTests"] == 0
        assert all(t["status"] == "passed" for t in report["testResults"])
        assert report["numPassedTests"] == report["numTotalTests"]
        assert report["numTotalTests"] == 54 if lane == "candidate" else report["numTotalTests"] > 0
        results["test_receipt"] = {"accepted": True, "files": sorted(actual), "tests": report["numTotalTests"],
                                   "report_sha256": sha(report_path.read_bytes())}
    except (AssertionError, KeyError, ValueError, OSError) as error:
        results["test_receipt"] = {"accepted": False, "error": str(error)}
    results["final_source"] = assert_frozen(lane)
    results["all_requested_checks_passed"] = (
        all(r["exit_code"] == 0 for r in results["commands"].values())
        and all(r["accepted"] for r in results["membership"].values())
        and results["test_receipt"]["accepted"]
    )
    save("results.json", results)
    hashes = {p.name: sha(p.read_bytes()) for p in PROOF.iterdir() if p.is_file() and p.name != "manifest.json"}
    save("manifest.json", hashes)
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as summary:
        summary.write(f"### PR114287 {lane}\n\nBaseline `{BASE}`, frozen patch `{PATCH_SHA}`.\n\n")
        for name, result in results["commands"].items():
            summary.write(f"- {name}: exit {result['exit_code']}\n")
        summary.write("\nThis is validation evidence. Autoreview, final Mergeguez, and upstream acceptance gates remain separate.\n")
    return 0 if results["all_requested_checks_passed"] else 1


if __name__ == "__main__":
    assert len(sys.argv) == 3 and sys.argv[1] in {"prepare", "probe", "install", "run"} and sys.argv[2] in {"baseline", "candidate"}
    try:
        if sys.argv[1] == "prepare":
            prepare(sys.argv[2])
            exit_code = 0
        elif sys.argv[1] == "install":
            install(sys.argv[2])
            exit_code = 0
        elif sys.argv[1] == "probe":
            network_probe(sys.argv[2])
            exit_code = 0
        else:
            exit_code = run(sys.argv[2])
    except Exception as error:
        save("proof-error.json", {"phase": sys.argv[1], "lane": sys.argv[2], "type": type(error).__name__, "error": str(error)})
        raise
    sys.exit(exit_code)
