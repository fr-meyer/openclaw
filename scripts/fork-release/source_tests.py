#!/usr/bin/env python3
"""Bounded source tests using prepared frozen dependencies in secretless Docker.

This adapter never installs dependencies, builds an image, or changes the source
checkout. Missing/stale dependencies are a preparation error. The source export
and installed packages are read-only; only private tmpfs scratch is writable.
It is a synchronous test step, not another release or rehearsal coordinator.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shutil
import subprocess
import sys
import tarfile
import time

DOCKER = ("/usr/bin/sudo", "-n", "/usr/bin/docker")
ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8"}
SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
TEST = re.compile(r"[A-Za-z0-9_./-]+\.(?:test|e2e)\.[cm]?[jt]sx?\Z")
PRIVATE = re.compile(r"(?:\.git|\.local|\.openclaw|\.env(?:\..*)?|node_modules)\Z")

# This small preflight runs inside the same isolation as the tests. YAML order
# and serialization are immaterial; all semantic lock fields must match.
ENTRY = r'''
import fs from "node:fs";
import { createRequire } from "node:module";
import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { spawnSync } from "node:child_process";
const require = createRequire("/workspace/package.json");
const { parseAllDocuments } = require("yaml");
const source = JSON.parse(fs.readFileSync("/workspace/package.json", "utf8"));
const expected = JSON.parse(fs.readFileSync("/control/expected.json", "utf8"));
const fail = (code) => { console.error(code); process.exit(78); };
const documents = (file) => {
  const docs = parseAllDocuments(fs.readFileSync(file, "utf8"));
  if (docs.some((doc) => doc.errors.length)) fail("tests.preparation_required.lock_parse");
  return docs.map((doc) => doc.toJSON());
};
const sourceLocks = documents("/workspace/pnpm-lock.yaml");
const installedLocks = documents("/workspace/node_modules/.pnpm/lock.yaml");
// pnpm 12's first document pins its own package manager/config dependencies;
// node_modules/.pnpm/lock.yaml stores only the project dependency document.
if (sourceLocks.length !== 2 || installedLocks.length !== 1 ||
    !isDeepStrictEqual(Object.keys(sourceLocks[0].importers ?? {}), ["."]) ||
    !isDeepStrictEqual(sourceLocks[0].importers["."].configDependencies, {}) ||
    !isDeepStrictEqual(sourceLocks[0].importers["."].packageManagerDependencies,
      { pnpm: { specifier: expected.pnpmVersion, version: expected.pnpmVersion } }) ||
    !isDeepStrictEqual(sourceLocks[1], installedLocks[0]))
  fail("tests.preparation_required.lock");
const versions = {};
for (const name of ["vitest", "@modelcontextprotocol/sdk"]) {
  const actual = JSON.parse(fs.readFileSync(`/workspace/node_modules/${name}/package.json`, "utf8")).version;
  const pinned = source.dependencies?.[name] ?? source.devDependencies?.[name];
  if (actual !== pinned || actual !== expected.dependencies[name])
    fail("tests.preparation_required.version");
  versions[name] = actual;
}
for (const [name, hash] of Object.entries(expected.pnpmFileSha256)) {
  const actual = createHash("sha256").update(fs.readFileSync(`/toolchain/pnpm/${name}`)).digest("hex");
  if (actual !== hash) fail("tests.preparation_required.pnpm_bytes");
}
const pnpmPath = `/toolchain/pnpm/${expected.pnpmEntrypoint}`;
process.env.npm_execpath = pnpmPath;
// Observe the selected executable's version outside the project. pnpm 12 can
// resolve package-manager/config dependencies before --version when cwd contains
// a workspace; that would turn an identity probe into dependency preparation.
const pnpm = spawnSync(pnpmPath, ["--version"], {
  cwd: "/tmp", encoding: "utf8", timeout: 30000, maxBuffer: 65536,
});
if (pnpm.status !== 0 || pnpm.stdout?.trim() !== expected.pnpmVersion) {
  // Private native log only; preserve the first probe's evidence, never retry it.
  console.error(JSON.stringify({ phase: "pnpm-version", status: pnpm.status,
    signal: pnpm.signal, errorCode: pnpm.error?.code,
    stdout: pnpm.stdout, stderr: pnpm.stderr }));
  fail("tests.preparation_required.pnpm");
}
console.log(JSON.stringify({ phase: "dependency-preflight", pnpm: pnpm.stdout.trim(), versions }));
const child = spawnSync("node", ["scripts/run-vitest.mjs", "run", "--configLoader", "runner",
  `--maxWorkers=${expected.workers}`, ...expected.tests], { stdio: "inherit" });
process.exit(child.status ?? 1);
'''


class Refusal(ValueError):
    pass


def need(value, message):
    if not value:
        raise Refusal(message)


def stamp():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def native(argv, timeout=30):
    return subprocess.run([str(arg) for arg in argv], capture_output=True, text=True,
                          timeout=timeout, env=ENV, check=True)


def git(source, *args):
    return native(["git", "-C", source, *args]).stdout.strip()


def safe_relative(value):
    return (type(value) is str and value != "" and not value.startswith("/")
            and not any(part in ("", ".", "..") or PRIVATE.fullmatch(part)
                        for part in value.split("/")) and not re.search(r"[\\\x00\r\n]", value))


def bind_path(path):
    path = Path(path).resolve(strict=True)
    need(not re.search(r"[,\x00\r\n]", str(path)), "tests.bind_path")
    return path


def export_archive(stream, exported):
    """Extract Git's finite entry types into a new, private, empty directory.

    Older GCP Python has no tarfile data filter. Do not delegate extraction to
    tarfile: files are exclusive/no-follow writes; links are created only after
    every ordinary entry, and no archive entry may traverse a link or file.
    """
    need(exported.is_dir() and not any(exported.iterdir()) and
         exported.resolve() == exported, "tests.export_directory_not_new")
    members = {}
    for member in stream.getmembers():
        name = member.name.rstrip("/")
        need(name and not name.startswith("/") and
             not any(part in ("", ".", "..") for part in name.split("/")) and
             not re.search(r"[\\\x00\r\n]", name), "tests.source_archive_entry")
        if any(PRIVATE.fullmatch(part) for part in name.split("/")):
            continue
        need(safe_relative(name) and name not in members and
             member.type in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE, tarfile.SYMTYPE),
             "tests.source_archive_entry")
        if member.issym():
            link = member.linkname
            need(link and not link.startswith("/") and not re.search(r"[\\\x00\r\n]", link),
                 "tests.source_archive_link")
            target = posixpath.normpath(posixpath.join(posixpath.dirname(name), link))
            need(safe_relative(target), "tests.source_archive_link")
        members[name] = member
    for name in members:
        for parent in PurePosixPath(name).parents:
            if str(parent) in members:
                need(members[str(parent)].isdir(), "tests.source_archive_link_ancestor")
    for name, member in members.items():
        target = exported / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if member.isdir():
            target.mkdir(exist_ok=True)
        elif member.isfile():
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o755 if member.mode & 0o111 else 0o644)
            with os.fdopen(descriptor, "wb") as destination, stream.extractfile(member) as source:
                shutil.copyfileobj(source, destination)
    for name, member in members.items():
        if member.issym():
            (exported / name).symlink_to(member.linkname)
    for name, member in members.items():
        if member.issym():
            try:
                target = (exported / name).resolve(strict=True)
            except (OSError, RuntimeError):
                raise Refusal("tests.source_archive_link") from None
            need(target.is_relative_to(exported), "tests.source_archive_link")


def prepare(source, dependencies, pnpm_dir, output, sha, image, tests, workers=1, memory_mib=2048,
            timeout=300):
    source, dependencies = bind_path(source), bind_path(dependencies)
    pnpm_dir = bind_path(pnpm_dir)
    need(SHA.fullmatch(sha) and DIGEST.fullmatch(image), "tests.immutable_identity")
    need(type(workers) is int and 1 <= workers <= 4, "tests.workers")
    need(type(memory_mib) is int and 512 <= memory_mib <= 4096, "tests.memory")
    need(type(timeout) is int and 1 <= timeout <= 900, "tests.timeout")
    need(type(tests) is list and 1 <= len(tests) <= 32 and len(set(tests)) == len(tests),
         "tests.explicit_files")
    need(git(source, "rev-parse", "HEAD") == sha, "tests.source_head")
    need(git(source, "status", "--porcelain", "--untracked-files=all") == "", "tests.dirty_source")
    tracked = git(source, "ls-files", "-z").split("\0")
    need(all(safe_relative(test) and TEST.fullmatch(test) and test in tracked
             for test in tests), "tests.explicit_tracked_files")
    metadata = ["package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml"]
    metadata += [file for file in tracked if file.endswith("/package.json")]
    need(all((dependencies / file).is_file() and
             (source / file).read_bytes() == (dependencies / file).read_bytes()
             for file in metadata), "tests.preparation_required.manifests")
    package = json.loads((source / "package.json").read_text())
    pin = re.fullmatch(r"pnpm@([0-9]+\.[0-9]+\.[0-9]+)(?:\+sha512\.[0-9a-f]+)?",
                       package.get("packageManager", ""))
    need(pin is not None, "tests.package_manager_pin")
    pnpm_package = json.loads((pnpm_dir / "package.json").read_text())
    pnpm_entry = pnpm_package.get("bin", {}).get("pnpm")
    need(pnpm_package.get("name") == "pnpm" and pnpm_package.get("version") == pin[1] and
         safe_relative(pnpm_entry), "tests.preparation_required.pnpm_package")
    pnpm_files = ["package.json", pnpm_entry, "bin/pnpm.mjs"]
    need(all((pnpm_dir / name).is_file() and
             (pnpm_dir / name).resolve().is_relative_to(pnpm_dir) for name in pnpm_files) and
         os.access(pnpm_dir / pnpm_entry, os.X_OK), "tests.preparation_required.pnpm_files")
    pnpm_hashes = {name: digest(pnpm_dir / name) for name in pnpm_files}
    versions = {name: package.get("dependencies", {}).get(name,
                 package.get("devDependencies", {}).get(name))
                for name in ("vitest", "@modelcontextprotocol/sdk")}
    need(all(type(version) is str and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version)
             for version in versions.values()), "tests.exact_dependency_pins")
    modules = ["node_modules"] + [str(PurePosixPath(file).parent / "node_modules")
                                   for file in metadata if file.endswith("/package.json")]
    modules = sorted(set(file for file in modules if (dependencies / file).is_dir()))
    need("node_modules" in modules and
         (dependencies / "node_modules/.pnpm/lock.yaml").is_file(),
         "tests.preparation_required.install")
    for module in modules:
        need((dependencies / module).resolve() == dependencies / module,
             "tests.dependency_directory_symlink")
    output = Path(output).absolute()
    need(all(output != root and root not in output.parents and output not in root.parents
             for root in (source, dependencies, pnpm_dir)), "tests.output_overlaps_input")
    need(not output.exists() and output.parent.resolve() == output.parent,
         "tests.output_must_be_new_physical_directory")
    output.mkdir(mode=0o700)
    exported = output / "source"
    exported.mkdir(mode=0o755)
    archive = output / "source.tar"
    native(["git", "-C", source, "archive", "--format=tar", f"--output={archive}", sha], timeout=120)
    with tarfile.open(archive) as stream:
        export_archive(stream, exported)
    archive.unlink()
    for module in modules:
        (exported / module).mkdir(parents=True, exist_ok=True)
    for path in (".cache", ".artifacts", ".openclaw"):
        (exported / path).mkdir(exist_ok=True)
    metadata_hash = hashlib.sha256()
    for name in sorted(metadata):
        metadata_hash.update(name.encode() + b"\0" + (dependencies / name).read_bytes() + b"\0")
    expected = {"sourceSha": sha, "sourceTree": git(source, "rev-parse", f"{sha}^{{tree}}"),
                "lockSha256": digest(exported / "pnpm-lock.yaml"), "imageDigest": image,
                "installedLockSha256": digest(dependencies / "node_modules/.pnpm/lock.yaml"),
                "dependencyMetadataSha256": metadata_hash.hexdigest(),
                "dependencyProof": "matched manifests, full project-lock semantics and named runtime versions; not a package-byte audit",
                "sourceExportExcludes": [".git", ".local", ".openclaw", ".env and .env.*", "node_modules"],
                "pnpmVersion": pin[1], "pnpmEntrypoint": pnpm_entry,
                "pnpmFileSha256": pnpm_hashes, "dependencies": versions, "tests": tests,
                "workers": workers, "memoryMiB": memory_mib, "timeoutSeconds": timeout}
    need(git(source, "rev-parse", "HEAD") == sha and
         git(source, "status", "--porcelain", "--untracked-files=all") == "",
         "tests.source_changed_during_preparation")
    need(all((exported / file).read_bytes() == (dependencies / file).read_bytes()
             for file in metadata), "tests.dependency_metadata_changed")
    (output / "entry.mjs").write_text(ENTRY)
    (output / "expected.json").write_text(json.dumps(expected))
    # The parent stays 0700. Individual readonly bind files must be readable by
    # the explicit non-root container identity, independent of inherited umask.
    for name in ("entry.mjs", "expected.json"):
        (output / name).chmod(0o444)
    return output, expected, modules


def create_argv(output, dependencies, pnpm_dir, expected, modules):
    need(os.getuid() != 0, "tests.non_root_operator_required")
    argv = [*DOCKER, "create", "--pull", "never", "--platform", "linux/amd64", "--no-healthcheck",
            "--network", "none", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--user", f"{os.getuid()}:{os.getgid()}",
            "--init", "--log-driver", "local", "--log-opt", "max-size=10m",
            "--log-opt", "max-file=1", "--log-opt", "compress=false",
            "--pids-limit", "256", "--cpus", str(expected["workers"]),
            "--memory", f"{expected['memoryMiB']}m", "--memory-swap", f"{expected['memoryMiB']}m",
            "--tmpfs", "/tmp:rw,nosuid,nodev,exec,size=512m,mode=1777",
            "--workdir", "/workspace"]
    for path in (".cache", ".artifacts", ".openclaw"):
        argv += ["--tmpfs", f"/workspace/{path}:rw,nosuid,nodev,size=256m,mode=1777"]
    for key, value in {"HOME": "/tmp", "TMPDIR": "/tmp", "CI": "1",
                       "COREPACK_ENABLE_NETWORK": "0", "TSX_DISABLE_CACHE": "1",
                       "npm_config_manage_package_manager_versions": "false",
                       "NODE_COMPILE_CACHE": "/tmp/node-compile",
                       "OPENCLAW_VITEST_FS_MODULE_CACHE_PATH": "/tmp/vitest-cache",
                       "OPENCLAW_TEST_PROJECTS_PARALLEL": "1",
                       "RAYON_NUM_THREADS": str(expected["workers"]),
                       "TOKIO_WORKER_THREADS": str(expected["workers"]),
                       "ROLLDOWN_WORKER_THREADS": str(expected["workers"])}.items():
        argv += ["--env", f"{key}={value}"]
    bindings = [(output / "source", "/workspace"), (output / "entry.mjs", "/control/entry.mjs"),
                (output / "expected.json", "/control/expected.json"),
                (pnpm_dir, "/toolchain/pnpm")]
    bindings += [(dependencies / module, "/workspace/" + module) for module in modules]
    for source, target in bindings:
        argv += ["--mount", f"type=bind,source={source},target={target},readonly"]
    return [*argv, "--entrypoint", "/usr/bin/env", expected["imageDigest"], "-i",
            *[arg for index, arg in enumerate(argv) if index > 0 and argv[index - 1] == "--env"],
            "PATH=/toolchain/pnpm:/usr/local/bin:/usr/bin:/bin", "timeout", "--signal=TERM", "--kill-after=5s",
            f"{expected['timeoutSeconds']}s", "node", "/control/entry.mjs"]


def run(output, dependencies, pnpm_dir, expected, modules):
    need(sys.platform == "linux", "tests.execution_requires_linux")
    container = native(create_argv(output, dependencies, pnpm_dir, expected, modules)).stdout.strip()
    need(re.fullmatch(r"[0-9a-f]{64}", container), "tests.owned_container_identity")
    started, monotonic = stamp(), time.monotonic()
    observation, failure = None, None
    native_failure, log_failure, cleanup_failure = None, None, None
    try:
        native([*DOCKER, "start", container])
        try:
            native([*DOCKER, "wait", container], timeout=expected["timeoutSeconds"] + 10)
        except subprocess.TimeoutExpired:
            failure = "tests.timeout"
            native([*DOCKER, "stop", "--time", "5", container], timeout=15)
        observation = json.loads(native([*DOCKER, "inspect", "--format", "{{json .State}}", container]).stdout)
        need(observation.get("Running") is False, "tests.container_still_running")
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        failure = failure or type(error).__name__
        native_failure = {"type": type(error).__name__, "message": str(error)}
        if isinstance(error, subprocess.CalledProcessError):
            native_failure.update(returnCode=error.returncode, stdout=error.stdout, stderr=error.stderr)
    finally:
        try:
            with (output / "native.log").open("xb") as log:
                captured = subprocess.run([*DOCKER, "logs", "--timestamps", container], stdout=log,
                                          stderr=subprocess.STDOUT, timeout=30, env=ENV)
                if captured.returncode:
                    log_failure = "tests.logs_unavailable"
                    failure = failure or log_failure
        except (OSError, subprocess.SubprocessError):
            log_failure = "tests.logs_unavailable"
            failure = failure or log_failure
        finally:
            # Exact create-returned ID only; interrupted children cannot keep running
            # after cleanup. A cleanup failure remains a failed/unknown outcome.
            try:
                native([*DOCKER, "rm", "--force", container])
            except (OSError, subprocess.SubprocessError):
                cleanup_failure = "tests.cleanup_unconfirmed"
                failure = failure or cleanup_failure
    passed = (failure is None and observation is not None and
              observation.get("ExitCode") == 0 and observation.get("OOMKilled") is False)
    receipt = {"schema": "openclaw.source-tests.v1", **expected, "startedAt": started,
               "completedAt": stamp(), "elapsedSeconds": round(time.monotonic() - monotonic, 3),
               "containerId": container, "state": "passed" if passed else "failed",
               "nativeState": observation, "failure": failure, "nativeFailure": native_failure,
               "logFailure": log_failure, "cleanupFailure": cleanup_failure,
               "logSha256": digest(output / "native.log"), "logRetention": {
                   "driver": "local", "maxSize": "10m", "maxFiles": 1, "compress": False,
                   "truncationPossible": True}, "productionEligible": False}
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print((output / "native.log").read_text(errors="replace"), end="")
    print(json.dumps(receipt))
    return 0 if passed else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--dependencies", required=True, type=Path)
    parser.add_argument("--pnpm-dir", required=True, type=Path,
                        help="Existing source-pinned pnpm package directory; no Corepack download")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--memory-mib", type=int, default=2048)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("tests", nargs="+")
    args = parser.parse_args()
    try:
        need(sys.platform == "linux", "tests.execution_requires_linux")
        output, expected, modules = prepare(args.source, args.dependencies, args.pnpm_dir, args.output,
            args.source_sha, args.image, args.tests, args.workers, args.memory_mib, args.timeout)
        return run(output, bind_path(args.dependencies), bind_path(args.pnpm_dir), expected, modules)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
