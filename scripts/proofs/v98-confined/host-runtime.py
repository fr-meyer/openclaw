#!/usr/bin/env python3
"""One hosted, exact-image confined runtime attempt. Never run on a local host.

The workflow owns authorization and acquisition. This program refuses execution
until the reviewed source manifest, retained image validator, Docker container,
actual PID 1 and host cgroup all agree. Unit tests import only its pure checks.
"""
import argparse
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import selectors
import shutil
import stat
import subprocess
import sys
import tarfile
import time

_accounting_spec = importlib.util.spec_from_file_location(
    "v98_accounting_owner", Path(__file__).with_name("accounting_owner.py"))
_accounting = importlib.util.module_from_spec(_accounting_spec)
_accounting_spec.loader.exec_module(_accounting)
SliceOwner = _accounting.SliceOwner

SOURCE = "bc8b82b2cbbbb81f5abe6093e1bb3af4f1f70cdf"
TREE = "ba825f670dc5ba943f7893cb267225d1f68d3110"
IMAGE_SHA = "0a3418e393313dbe7e20f4ef140fea81e3a7e6d8a24f9ee1bf5e0bd87d86ffcf"
IMAGE_ID = "sha256:1b2669dcea79d48e6c9f1e86a81495746e62f6d4b9a7837eaccca5ce0a266c39"
ARTIFACT_ID = 11299504641
ARTIFACT_RUN = 37192724704
ARTIFACT_ATTEMPT = 1
ZIP_SHA = "73662d185f6e308c29ae365af540f451a0e4672644bcb861f692424d5fbb46c3"
GATE = b"V98_HOST_ADMITTED\n"
MAX_STDOUT = 128 * 1024
MAX_STDERR = 256 * 1024
MAX_SCRATCH = 16 * 1024 * 1024
MAX_PROBE_SCRATCH = 1024 * 1024
MAX_ARCHIVE_ENTRIES = 4096
MAX_ARCHIVE_PATH_BYTES = 256 * 1024
MAX_UPLOAD = 20 * 1024 * 1024
MODE_LIMITS = {
    "--capability-probe": (15.0, 5_000_000),
    "--deadline-probe": (2.0, 1_000_000),
    "--run-frozen-six-phases": (60.0, 30_000_000),
}
PROOF_INPUTS = (
    "fixture.mjs", "predecessor-state.sql", "predecessor-workboard.ts",
    "predecessor-publisher-controller.mjs",
)
PROOF_READS = tuple(sorted(
    ["/proof/inputs/" + name for name in PROOF_INPUTS] +
    ["/proof/runner/v98-supervisor", "/proof/runner/v98-confine.so",
     "/proof/runner/capability-probe.mjs", "/proof/policy/parent-read-paths.txt",
     "/proof/policy/helper-read-paths.txt"]
))
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


Refusal = _accounting.Refusal
ObservationFailure = _accounting.ObservationFailure


class SettlementFailure(Refusal):
    def __init__(self, stop_failure, final_error):
        self.details = {"stopFailure": stop_failure,
                        "finalObservationFailure": failure_detail(final_error, "exact Docker final inspection")}
        super().__init__("exact Docker final inspection: " + self.details["finalObservationFailure"]["reason"])


def failure_detail(error, operation):
    observed = isinstance(error, ObservationFailure)
    cause = error.cause if observed else error
    return {"operation": error.operation if observed else operation,
            "type": type(cause).__name__, "errno": getattr(cause, "errno", None),
            "reason": bounded_text(cause, 2000)}


def bounded_text(value, limit):
    return str(value).encode("utf-8", "replace")[:limit].decode("utf-8", "replace")


def require(ok, reason):
    if not ok:
        raise Refusal(reason)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_json(path, limit=2 * 1024 * 1024):
    path = Path(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_size <= limit, "JSON is not bounded regular input")
    def unique(pairs):
        out = {}
        for key, value in pairs:
            require(key not in out, "duplicate JSON key")
            out[key] = value
        return out
    return json.loads(path.read_bytes(), object_pairs_hook=unique)


def command(argv, *, timeout=15, stdout_limit=65536):
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, check=False)
    require(len(result.stdout) <= stdout_limit and len(result.stderr) <= 65536,
            "host command output budget exceeded")
    require(result.returncode == 0, "host command failed: " + argv[0] + " " +
            result.stderr[:300].decode("utf-8", "replace"))
    return result.stdout


def git(root, *args):
    # Actions checkout is runner-owned, while admission runs as root to write
    # the gate. Trust only these exact checkout paths, never global safe.directory.
    return command(["git", "-c", "safe.directory=" + str(Path(root).resolve()),
                    "-C", str(root), *args]).decode().strip()


def verify_source_manifest(tooling, expected_commit):
    tooling = Path(tooling).resolve()
    require(HEX40.fullmatch(expected_commit or ""), "tooling SHA must be exact")
    require(git(tooling, "rev-parse", "HEAD") == expected_commit, "tooling checkout head changed")
    require(not git(tooling, "status", "--porcelain=v1", "--untracked-files=normal"),
            "tooling checkout is dirty")
    manifest = read_json(tooling / "scripts/proofs/v98-confined/source-manifest.json")
    require(manifest.get("schema") == "openclaw-v98-confined-source-manifest/v1", "source manifest schema")
    rows = manifest.get("files")
    require(isinstance(rows, list) and len(rows) >= 15, "source manifest files absent")
    names = []
    for row in rows:
        name = row.get("path")
        require(isinstance(name, str) and
                (name.startswith("scripts/proofs/") or name.startswith(".github/workflows/")),
                "source manifest path outside owner scope")
        require(name not in names and not name.startswith("/") and ".." not in Path(name).parts
                and "\\" not in name and "\x00" not in name, "source manifest path invalid")
        names.append(name)
        path = tooling / name
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and type(row.get("bytes")) is int
                and info.st_size == row["bytes"] and row.get("mode") == oct(stat.S_IMODE(info.st_mode))
                and HEX64.fullmatch(row.get("sha256", "")) and sha256(path) == row["sha256"],
                "reviewed source input changed: " + name)
    require(names == sorted(names), "source manifest must be sorted")
    required = {
        "scripts/proofs/v98-confined/" + name for name in
        ("v98-supervisor.c", "v98-confine.c", "native-policy.c", "native-policy.h",
         "native-filter.h", "native-boundary.h", "native-sha256.h", "capability-probe.mjs",
         "host-runtime.py", "test_host_runtime.py", "derive_read_policy.py", "packet.json",
         "startup-prerequisites.json", "accounting_owner.py", "test_accounting_owner.py", "test_scratch_usage.py",
         "test_hosted_admission.py", "test_fixture_read_boundary.mjs",
         "proposal/openssl-read-proposal.json", "proposal/image-openssl.cnf",
         "proposal/render_delta.py", "test_openssl_proposal.py",
         "read-policy/runtime-read-binding.json", "read-policy/parent-read-paths.txt",
         "read-policy/helper-read-paths.txt")
    } | {"scripts/proofs/v98-confined/inputs/" + name for name in PROOF_INPUTS} | {
        ".github/workflows/v98-confined-runtime-3.yml",
        ".github/workflows/v98-confined-runtime-4.yml",
        ".github/workflows/v98-confined-runtime-5.yml",
        "scripts/proofs/v98-parity/verify-artifact.py",
        "scripts/proofs/v98-parity/collect-artifacts.py",
        "scripts/proofs/v98-parity/contract.json",
    }
    require(required <= set(names), "source manifest omits a host or native owner file")
    return manifest


def verify_prepared(validation, binding, packet, image):
    v = read_json(validation)
    b = read_json(binding, 1024 * 1024)
    p = read_json(packet)
    selected_source = v.get("source") or {}
    require(v.get("status") == "PREPARED_IMAGE_IDENTITY_VERIFIED; RUNTIME_UNQUALIFIED"
            and v.get("selectedReadFilesVerifiedAgainstSavedLayers") == 1548
            and selected_source.get("commit") == SOURCE and selected_source.get("tree") == TREE
            and v.get("imageArchiveSha256") == IMAGE_SHA
            and v.get("imageConfigId") == IMAGE_ID
            and v.get("artifactId") == ARTIFACT_ID
            and v.get("runId") == ARTIFACT_RUN and v.get("runAttempt") == ARTIFACT_ATTEMPT
            and v.get("zipSha256") == ZIP_SHA and v.get("githubZipDigestVerified") is True,
            "selected image validation is not exact")
    require(p.get("sourceCommit") == SOURCE and p.get("sourceTree") == TREE
            and p.get("schema") == "openclaw-v98-confined-execution-packet/v1"
            and p.get("sourceManifestPath") == "scripts/proofs/v98-confined/source-manifest.json"
            and p.get("boundary", {}).get("readBindingSha256") == sha256(binding)
            and p.get("artifact", {}).get("imageSha256") == IMAGE_SHA
            and p.get("artifact", {}).get("configId") == IMAGE_ID
            and p.get("artifact", {}).get("zipSha256") == ZIP_SHA,
            "frozen packet identity changed")
    require(b.get("sourceCommit") == SOURCE and b.get("sourceTree") == TREE
            and b.get("imageSha256") == IMAGE_SHA and b.get("imageConfigId") == IMAGE_ID
            and b.get("status") == "STATIC_READ_POLICY_PREPARED; RUNTIME_NOT_ADMITTED"
            and len(b.get("imageEntries", [])) == 1548 and len(b.get("namespaceEntries", [])) == 360,
            "selected read binding changed")
    require(Path(image).is_file() and not Path(image).is_symlink() and sha256(image) == IMAGE_SHA,
            "retained image bytes changed after validation")
    return v, b


def validate_read_list(path, binding):
    text = Path(path).read_text()
    lines = text.splitlines()
    expected = sorted(row["path"] for row in binding["imageEntries"])
    require(lines == expected and text.endswith("\n") and len(text.encode()) < 1024 * 1024,
            "source read list differs from selected image binding")
    return text


def startup_preflight(base, binding, output):
    """Static requirements only: never grant a read or invoke image code."""
    base, output = Path(base), Path(output)
    asset = base / "startup-prerequisites.json"
    receipt = {"status": "STARTUP_PREREQUISITES_UNPROVED", "executionAdmission": False,
               "imageConfigId": IMAGE_ID, "missingFileReads": [], "identityMismatches": [],
               "missingNamespaceMetadata": [], "completeRuntimeClosure": False}
    try:
        required = read_json(asset, 64 * 1024)
        packet = read_json(base / "packet.json")
        require(packet.get("startupPrerequisitesSha256") == sha256(asset),
                "startup prerequisite asset differs from packet")
        require(required.get("schema") == "openclaw-v98-node-startup-prerequisites/v1"
                and required.get("sourceCommit") == SOURCE and required.get("sourceTree") == TREE
                and required.get("imageSha256") == IMAGE_SHA
                and required.get("imageConfigId") == IMAGE_ID,
                "startup prerequisite source/image identity changed")
        files = required.get("requiredCanonicalRegularFiles")
        namespace = required.get("requiredNamespaceMetadata")
        require(isinstance(files, list) and len(files) == 10 and isinstance(namespace, list)
                and 1 <= len(namespace) <= 32, "startup prerequisite inventory invalid")
        for rows in (files, namespace):
            names = [row.get("path") for row in rows]
            require(all(isinstance(name, str) and name.startswith("/") for name in names)
                    and len(set(names)) == len(names), "startup prerequisite paths invalid")
        reads = {scope: set(validate_read_list(base / "read-policy" / (scope + "-read-paths.txt"),
                                              binding).splitlines()) for scope in ("parent", "helper")}
        selected = {row["path"]: row for row in binding["imageEntries"]}
        selected_namespace = {row["path"]: row for row in binding["namespaceEntries"]}
        for row in files:
            path = row["path"]
            scopes = [scope for scope in reads if path not in reads[scope]]
            if scopes:
                receipt["missingFileReads"].append({"path": path, "scopes": scopes})
            elif any(selected[path].get(key) != row.get(key)
                     for key in ("path", "type", "mode", "bytes", "sha256")):
                receipt["identityMismatches"].append(path)
        for row in namespace:
            path = row["path"]
            if path not in selected_namespace:
                receipt["missingNamespaceMetadata"].append(path)
            elif any(selected_namespace[path].get(key) != row.get(key)
                     for key in ("path", "type", "mode", "target")):
                receipt["identityMismatches"].append(path)
        require(not receipt["missingFileReads"] and not receipt["identityMismatches"]
                and not receipt["missingNamespaceMetadata"],
                "static startup prerequisites are absent from the reviewed read binding; permission approval remains required")
        receipt["status"] = "STATIC_STARTUP_PREREQUISITES_JOINED; RUNTIME_NOT_ADMITTED"
    except Exception as issue:
        receipt["reason"] = bounded_text(issue, 2000)
        raise
    finally:
        encoded = (json.dumps(receipt, indent=2) + "\n").encode()
        require(len(encoded) <= 32 * 1024, "startup preflight receipt exceeds budget")
        (output / "startup-preflight.json").write_bytes(encoded)
    return receipt


def prepare_proof(tooling, binding, destination):
    base = Path(tooling) / "scripts/proofs/v98-confined"
    destination = Path(destination)
    destination.mkdir(mode=0o755)
    for child in ("inputs", "runner", "policy"):
        (destination / child).mkdir(mode=0o755)
    for name in PROOF_INPUTS:
        source = base / "inputs" / name
        require(sha256(source) == binding["frozenInputHashes"]["/proof/inputs/" + name],
                "frozen input changed: " + name)
        shutil.copyfile(source, destination / "inputs" / name)
    shutil.copyfile(base / "capability-probe.mjs", destination / "runner/capability-probe.mjs")
    for scope in ("parent", "helper"):
        original = validate_read_list(base / "read-policy" / (scope + "-read-paths.txt"), binding)
        path = destination / "policy" / (scope + "-read-paths.txt")
        path.write_text(original + "".join(item + "\n" for item in PROOF_READS))
    for path in destination.rglob("*"):
        if path.is_file():
            os.chown(path, 0, 0)
            path.chmod(0o444)
    return {str(path.relative_to(destination)): sha256(path) for path in destination.rglob("*") if path.is_file()}


def elf_identity(path, *, static):
    data = Path(path).read_bytes()[:20]
    require(data[:6] == b"\x7fELF\x02\x01" and data[18:20] == b"\x3e\x00", "native ELF is not Linux x86-64")
    dynamic = command(["readelf", "-d", str(path)]).decode()
    program = command(["readelf", "-l", str(path)]).decode()
    require("(NEEDED)" not in dynamic, "native binary has a DT_NEEDED dependency")
    if static:
        require("INTERP" not in program, "supervisor has an ELF interpreter")
    else:
        symbols = command(["readelf", "-Ws", str(path)]).decode()
        require(not any(re.search(r"\bUND\s+\S", line) for line in symbols.splitlines()),
                "preload has undefined external symbols")
    return {"bytes": Path(path).stat().st_size, "sha256": sha256(path),
            "needed": [], "interpreter": None if static else "host-image-loader"}


def compile_native(tooling, proof):
    base = Path(tooling) / "scripts/proofs/v98-confined"
    runner = Path(proof) / "runner"
    cc = shutil.which("cc")
    require(cc and Path(cc).is_file(), "installed C compiler unavailable")
    flags_supervisor = ["-std=c11", "-O2", "-static", "-no-pie", "-fno-omit-frame-pointer",
                        "-fno-strict-aliasing"]
    flags_preload = ["-std=c11", "-O2", "-shared", "-fPIC", "-nostdlib", "-nodefaultlibs",
                     "-fno-builtin", "-fno-stack-protector", "-fno-strict-aliasing",
                     "-Wl,-z,defs", "-Wl,-z,now"]
    command([cc, *flags_supervisor, "-o", str(runner / "v98-supervisor"),
             str(base / "v98-supervisor.c"), str(base / "native-policy.c")], timeout=90)
    command([cc, *flags_preload, "-o", str(runner / "v98-confine.so"),
             str(base / "v98-confine.c")], timeout=90)
    binaries = {name: elf_identity(runner / name, static=name == "v98-supervisor")
                for name in ("v98-supervisor", "v98-confine.so")}
    for path in runner.iterdir():
        os.chown(path, 0, 0)
        path.chmod(0o555 if path.name == "v98-supervisor" else 0o444)
    return {"compilerPath": str(Path(cc).resolve()), "compilerSha256": sha256(cc),
            "compilerVersion": command([cc, "--version"]).decode().splitlines()[0],
            "supervisorFlags": flags_supervisor, "preloadFlags": flags_preload, "binaries": binaries}


def parse_cgroup(pid, container_id, proc_text, root=Path("/sys/fs/cgroup")):
    rows = proc_text.strip().splitlines()
    require(len(rows) == 1 and rows[0].startswith("0::/"), "PID is not in a single v2 cgroup")
    relative = rows[0][3:]
    parts = Path(relative).parts
    require(relative.startswith("/") and ".." not in parts and
            any(part == container_id or part == "docker-" + container_id + ".scope" for part in parts),
            "cgroup is not owned by exact container")
    path = root.joinpath(*parts[1:])
    require(path.is_dir() and not path.is_symlink(), "container cgroup path absent or alias")
    return path


def validate_cgroup_values(values):
    quota = values.get("cpu.max", "").split()
    require(len(quota) == 2 and all(item.isdecimal() for item in quota)
            and int(quota[0]) == int(quota[1]) and int(quota[1]) > 0,
            "cgroup CPU quota is not exactly one core")
    require(values.get("memory.max") == str(1024 ** 3)
            and values.get("memory.swap.max") == "0"
            and values.get("pids.max") == "128", "cgroup memory/swap/pid limits changed")


def inspect_container_configuration(inspect, container_id, image_id, proof, scratch):
    require(isinstance(inspect, dict) and inspect.get("Id") == container_id
            and inspect.get("Image") == image_id, "container identity changed")
    host = inspect.get("HostConfig", {})
    config = inspect.get("Config", {})
    require(config.get("User") == "1000:1000"
            and config.get("Entrypoint") == ["/proof/runner/v98-supervisor"]
            and (config.get("Healthcheck") or {}).get("Test") in (None, ["NONE"]),
            "container user, entrypoint or healthcheck changed")
    require(host.get("ReadonlyRootfs") is True and host.get("Privileged") is False
            and host.get("NetworkMode") == "none" and host.get("CapDrop") == ["ALL"]
            and host.get("CgroupnsMode") == "private" and host.get("PidMode") == ""
            and host.get("IpcMode") == "private" and host.get("Memory") == 1024 ** 3
            and host.get("MemorySwap") == 1024 ** 3 and host.get("NanoCpus") == 10 ** 9
            and host.get("PidsLimit") == 128 and host.get("ShmSize") == 1024 ** 2,
            "container isolation or resource settings changed")
    security = host.get("SecurityOpt") or []
    require(security in (["no-new-privileges:true"], ["no-new-privileges"]),
            "default seccomp/AppArmor or no-new-privileges changed")
    require(host.get("LogConfig") == {"Type": "local", "Config": {
                "max-size": "1m", "max-file": "1", "compress": "false"}}
            and host.get("Ulimits") == [{"Name": "core", "Soft": 0, "Hard": 0}],
            "container log budget or core dump limit changed")
    # Moby assigns its default profile during start, not create. A created
    # container may have no stored profile yet; running admission is strict.
    require(inspect.get("AppArmorProfile") in ("", "docker-default"),
            "created container AppArmor configuration changed")
    mounts = {row.get("Destination"): row for row in inspect.get("Mounts", [])}
    require(set(mounts) == {"/proof", "/scratch"}
            and mounts["/proof"].get("Type") == "bind" and mounts["/proof"].get("RW") is False
            and mounts["/scratch"].get("Type") == "bind" and mounts["/scratch"].get("RW") is True
            and Path(mounts["/proof"].get("Source", "")).resolve() == Path(proof).resolve()
            and Path(mounts["/scratch"].get("Source", "")).resolve() == Path(scratch).resolve(),
            "container mount scope changed")


def inspect_container(inspect, container_id, image_id, proof, scratch):
    inspect_container_configuration(inspect, container_id, image_id, proof, scratch)
    require(inspect.get("AppArmorProfile") == "docker-default",
            "Docker default AppArmor is not enforced")
    pid = inspect.get("State", {}).get("Pid")
    require(type(pid) is int and pid > 1 and inspect["State"].get("Running") is True,
            "container has no running host PID")
    return pid


def inspect_owned_container(inspect, container_id, name, image_id, proof, scratch, mode):
    """Establish cleanup authority, independently of runtime policy admission."""
    require(inspect.get("Id") == container_id and inspect.get("Image") == image_id
            and inspect.get("Name") == "/" + name, "created container ownership changed")
    config = inspect.get("Config") or {}
    require(config.get("Entrypoint") == ["/proof/runner/v98-supervisor"]
            and config.get("Cmd") == [mode], "created container command changed")
    require(inspect.get("HostConfig", {}).get("CgroupParent") == accounting_name(name),
            "created container accounting parent changed")
    mounts = {row.get("Destination"): row for row in inspect.get("Mounts", [])}
    require(set(mounts) == {"/proof", "/scratch"}
            and mounts["/proof"].get("Type") == "bind"
            and mounts["/scratch"].get("Type") == "bind"
            and Path(mounts["/proof"].get("Source", "")).resolve() == Path(proof).resolve()
            and Path(mounts["/scratch"].get("Source", "")).resolve() == Path(scratch).resolve(),
            "created container mount ownership changed")
    return inspect.get("State", {}).get("Pid")


def observe_owned_process(container_id, name, image_id, proof, scratch, mode):
    """Bind exact Docker ID to a live host PID and cgroup for cleanup."""
    inspected = docker_inspect(container_id)
    pid = inspect_owned_container(inspected, container_id, name, image_id, proof, scratch, mode)
    require(type(pid) is int and pid > 1 and inspected["State"].get("Running") is True,
            "owned container has no running PID to bind")
    starttime = proc_starttime(pid)
    pidfd = os.pidfd_open(pid)
    group_fd = None
    try:
        cgroup = parse_cgroup(pid, container_id, Path(f"/proc/{pid}/cgroup").read_text())
        group_fd = os.open(cgroup, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(group_fd)
        identity = (info.st_dev, info.st_ino)
        require(str(pid) in (cgroup / "cgroup.procs").read_text().split(),
                "owned PID is not in its exact cgroup")
        require(proc_starttime(pid) == starttime
                and docker_inspect(container_id)["State"]["Pid"] == pid,
                "owned PID changed during cleanup binding")
        return pid, starttime, pidfd, group_fd, cgroup, identity
    except Exception:
        os.close(pidfd)
        if group_fd is not None:
            os.close(group_fd)
        raise


def parse_events(stdout, stderr):
    def rows(data, trusted):
        events = []
        for raw in data.splitlines():
            if not raw.startswith(b"{"):
                require(not trusted, "non-JSON trusted native stdout")
                continue
            try:
                row = json.loads(raw)
            except (UnicodeError, ValueError):
                require(not trusted, "malformed trusted native JSONL")
                continue
            if isinstance(row, dict) and isinstance(row.get("event"), str):
                events.append(row)
            elif trusted:
                raise Refusal("trusted native JSONL event missing")
        return events
    return rows(stdout, True), rows(stderr, False)


def assess_native(mode, native, product, exit_code, deadline_killed):
    names = [row["event"] for row in native]
    require(names.count("host_gate_ready") == 1 and native[0] ==
            {"event": "host_gate_ready", "mode": mode}, "trusted host gate event absent")
    require(not any(name.endswith("_refused") or name.endswith("_failed") for name in names),
            "native boundary reported a refusal")
    if mode == "--deadline-probe":
        require(deadline_killed and any(row.get("event") == "deadline_worker_ready" for row in product)
                and "phase_started" in names and "base_boundary_installed" in names
                and "thread_owned" in names and "native_attempt_joined" not in names,
                "deadline probe did not prove a deliberate whole-cgroup kill")
        return
    require(not deadline_killed and exit_code == 0 and
            sum(row.get("event") == "native_attempt_joined" and row.get("value") == 0
                for row in native) == 1,
            "native attempt did not exit and join cleanly")
    require(names.count("thread_owned") > 0 and names.count("thread_owned") == names.count("thread_reaped"),
            "owned native threads were not fully reaped")
    if mode == "--capability-probe":
        joined = [row for row in product if row.get("event") == "capability_controls_joined"]
        require(len(joined) == 1 and all(joined[0].get(role, {}).get(key) is True
                for role in ("main", "worker") for key in
                ("fsync", "sqliteWalBackupClose", "deniedOutsideScratch", "deniedSockets")),
                "capability product observations incomplete")
        require(sum(row.get("event") == "syscall_denied" and row.get("value") == 41
                    for row in native) >= 4
                and any(row.get("event") == "syscall_denied" and row.get("value") in (56, 57)
                        for row in native), "native socket/process denials absent")
        require(sum(row.get("event") == "fsync_completed" for row in native) >= 4,
                "trusted native fsync completions absent")
        require(any(row.get("event") == "phase_joined" and row.get("phase") == 0
                    and row.get("value") == 0 for row in native)
                and any(row.get("event") == "base_boundary_installed" and row.get("phase") == 0
                        for row in native), "capability native phase exit or boundary missing")
    else:
        for phase in range(1, 7):
            require(sum(row.get("event") == "phase_started" and row.get("phase") == phase
                        for row in native) == 1
                    and sum(row.get("event") == "phase_joined" and row.get("phase") == phase
                            and row.get("value") == 0 for row in native) == 1
                    and sum(row.get("event") == "base_boundary_installed" and row.get("phase") == phase
                            for row in native) == 1,
                    "frozen phase start/exit observation missing")
        require(any(row.get("event") == "fsync_completed" for row in native)
                and any(row.get("event") == "helper_fork_owned" and row.get("phase") == 3
                        for row in native)
                and any(row.get("event") == "helper_exec_verified" and row.get("phase") == 3
                        for row in native)
                and any(row.get("event") == "helper_landlock_tightened" and row.get("phase") == 3
                        for row in native)
                and any(row.get("event") == "helper_reaped" and
                                                   row.get("phase") == 3 and row.get("value") == 0
                                                   for row in native), "owned Doctor helper join absent")


def docker_inspect(container):
    rows = json.loads(command(["docker", "container", "inspect", container], timeout=5))
    require(isinstance(rows, list) and len(rows) == 1, "ambiguous Docker inspection")
    return rows[0]


def accounting_name(name):
    require(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", name),
            "invalid task container name")
    # Deterministic, flat slice name; StartTransientUnit refuses an existing unit.
    token = int(hashlib.sha256(name.encode()).hexdigest()[:16], 16)
    mode_index = name.rsplit("-", 1)[-1]
    return "v98proof" + str(token) + "m" + (mode_index if mode_index in ("1", "2", "3") else "1") + ".slice"


def create_command(name, image, proof, scratch, mode):
    return ["docker", "create", "--pull", "never", "--name", name, "--user", "1000:1000", "--read-only",
            "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
            "--pids-limit", "128", "--memory", "1g", "--memory-swap", "1g", "--cpus", "1",
            "--shm-size", "1m", "--cgroupns", "private", "--cgroup-parent", accounting_name(name), "--ipc", "private",
            "--no-healthcheck", "--ulimit", "core=0:0", "--log-driver", "local",
            "--log-opt", "max-size=1m", "--log-opt", "max-file=1",
            "--log-opt", "compress=false",
            "--mount", f"type=bind,src={proof},dst=/proof,readonly",
            "--mount", f"type=bind,src={scratch},dst=/scratch",
            "--entrypoint", "/proof/runner/v98-supervisor", image, mode]


def validate_docker_prerequisites(version, info, endpoint, controllers, yama):
    """Pure checks of supported host requirements, never execution admission."""
    server = version.get("Server") or {}
    api = server.get("ApiVersion", "").split(".")
    require(len(api) == 2 and all(part.isdecimal() for part in api)
            and tuple(map(int, api)) >= (1, 41), "Docker API lacks private cgroup namespace support")
    require(endpoint == "unix:///var/run/docker.sock"
            and server.get("Os") == "linux" and server.get("Arch") == "amd64"
            and info.get("OSType") == "linux" and info.get("Architecture") in ("amd64", "x86_64"),
            "Docker must use the local Linux amd64 daemon")
    security = info.get("SecurityOptions") or []
    require("name=apparmor" in security and "name=seccomp,profile=builtin" in security
            and not any(item in security for item in ("name=rootless", "name=userns")),
            "rootful Docker default AppArmor/seccomp without user remapping required")
    require(info.get("CgroupVersion") == "2" and info.get("CgroupDriver") == "systemd"
            and {"cpu", "memory", "pids"} <= set(controllers)
            and info.get("MemoryLimit") is True and info.get("SwapLimit") is True
            and info.get("CpuCfsQuota") is True and info.get("PidsLimit") is True,
            "Docker cgroup v2 resource controllers unavailable")
    require("local" in (info.get("Plugins") or {}).get("Log", []), "Docker local logger unavailable")
    require(info.get("DefaultRuntime") == "runc" and "runc" in (info.get("Runtimes") or {}),
            "reviewed Docker default runc runtime absent")
    require(yama in ("0", "1"), "Yama disallows unprivileged own-child tracing")


def proof_mount_options(path, mountinfo):
    """Find the effective existing proof mount without mounting or executing."""
    def decode(value):
        return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), value)
    candidates = []
    for row in mountinfo.splitlines():
        fields = row.split()
        require(len(fields) >= 10 and "-" in fields, "invalid host mountinfo")
        mount = Path(decode(fields[4]))
        if Path(path).is_relative_to(mount):
            candidates.append((len(mount.parts), set(fields[5].split(","))))
    require(candidates, "proof mount was not observed")
    return max(candidates, key=lambda row: row[0])[1]


def host_preflight(proof, output):
    """Record bounded host facts and refuse predictable startup incompatibilities."""
    observations = {"status": "HOST_PREREQUISITES_UNPROVED", "executionAdmission": False}
    try:
        require(not any(os.environ.get(key) for key in
                ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH")),
                "Docker endpoint environment override is forbidden")
        paths = {name: shutil.which(name) for name in ("git", "docker", "cc", "readelf", "mount", "umount", "systemctl", "busctl")}
        observations["installedTools"] = paths
        require(all(paths.values()) and hasattr(os, "pidfd_open"), "required installed host tooling absent")
        endpoint = json.loads(command(["docker", "context", "inspect", "--format", "{{json .Endpoints.docker.Host}}"], timeout=5))
        version = json.loads(command(["docker", "version", "--format", "{{json .}}"], timeout=5))
        info = json.loads(command(["docker", "info", "--format", "{{json .}}"], timeout=5))
        controllers = Path("/sys/fs/cgroup/cgroup.controllers").read_text().split()
        yama = Path("/proc/sys/kernel/yama/ptrace_scope").read_text().strip()
        mountinfo = Path("/proc/self/mountinfo").read_text()
        require(len(mountinfo.encode()) <= 1024 * 1024, "host mountinfo exceeds budget")
        mount_options = proof_mount_options(proof, mountinfo)
        observations.update({"daemonEndpoint": endpoint, "server": version.get("Server"),
            "docker": {key: info.get(key) for key in ("OSType", "Architecture", "CgroupVersion",
                "CgroupDriver", "MemoryLimit", "SwapLimit", "CpuCfsQuota", "PidsLimit",
                "DefaultRuntime", "SecurityOptions")}, "controllers": controllers, "yama": yama,
            "proofMountOptions": sorted(mount_options),
            "runnerFreeBytes": shutil.disk_usage(output).free,
            "dockerRootFreeBytes": shutil.disk_usage(info["DockerRootDir"]).free})
        validate_docker_prerequisites(version, info, endpoint, controllers, yama)
        require("noexec" not in mount_options, "proof supervisor mount disallows execution")
        for directory in (Path(proof), *(Path(proof) / name for name in ("inputs", "runner", "policy"))):
            inode = directory.lstat()
            require(stat.S_ISDIR(inode.st_mode) and inode.st_uid == 0 and inode.st_gid == 0
                    and stat.S_IMODE(inode.st_mode) == 0o755, "proof directory search permissions changed")
        supervisor = Path(proof) / "runner/v98-supervisor"
        inode = supervisor.lstat()
        require(stat.S_ISREG(inode.st_mode) and inode.st_uid == 0 and inode.st_gid == 0
                and stat.S_IMODE(inode.st_mode) == 0o555 and inode.st_nlink == 1,
                "proof supervisor executable identity changed")
        observations["status"] = "HOST_PREREQUISITES_OBSERVED; RUNTIME_NOT_ADMITTED"
    except Exception as issue:
        observations["reason"] = str(issue)[:2000]
        raise
    finally:
        encoded = (json.dumps(observations, indent=2) + "\n").encode()
        require(len(encoded) <= 32 * 1024, "host preflight receipt exceeds budget")
        (Path(output) / "host-preflight.json").write_bytes(encoded)
    return observations


def mount_scratch(path):
    Path(path).mkdir(mode=0o700)
    command(["mount", "-t", "tmpfs", "-o", "size=16m,mode=0700,uid=1000,gid=1000,nosuid,nodev,noexec",
             "tmpfs", str(path)])
    require(os.path.ismount(path), "task-owned scratch is not mounted")
    info = os.stat(path)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 1000 and info.st_gid == 1000
            and stat.S_IMODE(info.st_mode) == 0o700, "scratch tmpfs identity changed")
    for name in ("home", "tmp", "cache"):
        directory = Path(path) / name
        directory.mkdir(mode=0o700)
        os.chown(directory, 1000, 1000)
        require(stat.S_IMODE(directory.stat().st_mode) == 0o700, "scratch child mode changed")
    return info


def proc_starttime(pid):
    text = Path(f"/proc/{pid}/stat").read_text()
    tail = text.rsplit(") ", 1)
    require(len(tail) == 2 and len(tail[1].split()) > 19, "PID start identity absent")
    value = tail[1].split()[19]  # stat field 22, after pid and comm.
    require(value.isdecimal(), "PID start identity invalid")
    return int(value)


def host_pid_gate(container_id, image_id, proof, scratch, owned):
    inspected = docker_inspect(container_id)
    pid = inspect_container(inspected, container_id, image_id, proof, scratch)
    owned_pid, first_starttime, _, group_fd, cgroup, identity = owned
    require(pid == owned_pid, "admission PID differs from cleanup-bound PID")
    status = Path(f"/proc/{pid}/status").read_text()
    match = re.search(r"^NSpid:\s+(.+)$", status, re.M)
    def field(name):
        row = re.search(r"^" + re.escape(name) + r":\s*(\S+)", status, re.M)
        return row.group(1) if row else None
    require(match and match.group(1).split()[-1] == "1"
            and re.search(r"^Uid:\s+1000\s+1000\s+1000\s+1000$", status, re.M)
            and re.search(r"^Gid:\s+1000\s+1000\s+1000\s+1000$", status, re.M)
            and field("Seccomp") == "2" and int(field("Seccomp_filters") or "0") >= 1
            and field("NoNewPrivs") == "1"
            and all(field(name) == "0000000000000000" for name in
                    ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")),
            "actual Docker PID1 identity changed")
    require(Path(f"/proc/{pid}/attr/current").read_text().strip() == "docker-default (enforce)",
            "actual PID1 AppArmor profile changed")
    require(Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")[:2] ==
            [b"/proof/runner/v98-supervisor", inspected["Config"]["Cmd"][0].encode()],
            "actual PID1 command changed")
    require(parse_cgroup(pid, container_id, Path(f"/proc/{pid}/cgroup").read_text()) == cgroup
            and (os.stat(cgroup).st_dev, os.stat(cgroup).st_ino) == identity,
            "admission cgroup differs from cleanup-bound cgroup")
    values = {name: (cgroup / name).read_text().strip() for name in
              ("cpu.max", "memory.max", "memory.swap.max", "pids.max")}
    validate_cgroup_values(values)
    require(str(pid) in (cgroup / "cgroup.procs").read_text().split(), "PID1 is not in owned cgroup")
    root_scratch = os.stat(f"/proc/{pid}/root/scratch")
    host_scratch = os.stat(scratch)
    require((root_scratch.st_dev, root_scratch.st_ino) == (host_scratch.st_dev, host_scratch.st_ino),
            "container scratch is not the task-owned tmpfs")
    require(proc_starttime(pid) == first_starttime and docker_inspect(container_id)["State"]["Pid"] == pid,
            "Docker PID1 changed during host admission")
    # CPU accounting belongs to the persistent parent before Docker starts;
    # the native host gate must never reset its lifetime baseline.
    return None


def release_gate(scratch):
    fd = os.open(scratch, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        temporary = ".host-admitted-prepared"
        gate = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                       0o600, dir_fd=fd)
        try:
            os.write(gate, GATE)
            os.fchown(gate, 0, 1000)
            os.fchmod(gate, 0o440)
            os.fsync(gate)
        finally:
            os.close(gate)
        os.rename(temporary, "host-admitted", src_dir_fd=fd, dst_dir_fd=fd)
        info = os.stat("host-admitted", dir_fd=fd, follow_symlinks=False)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_gid == 1000
                and stat.S_IMODE(info.st_mode) == 0o440 and info.st_size == len(GATE)
                and info.st_nlink == 1, "host gate file identity changed")
    finally:
        os.close(fd)


def settle_created_container(container_id, name, image_id, proof, scratch, mode):
    """Settle the exact created ID independently of cgroup proof availability."""
    inspected = docker_inspect(container_id)
    inspect_owned_container(inspected, container_id, name, image_id, proof, scratch, mode)
    stop_requested = inspected.get("State", {}).get("Running") is True
    stop_failure = None
    if stop_requested:
        try:
            command(["docker", "kill", "--signal=KILL", container_id], timeout=5)
        except Exception as issue:
            stop_failure = failure_detail(issue, "exact Docker stop")
    # A daemon timeout/error can race with exit. Observe final ownership/state
    # independently; a failed command never erases an available stopped witness.
    try:
        final = docker_inspect(container_id)
        inspect_owned_container(final, container_id, name, image_id, proof, scratch, mode)
        state = final.get("State") or {}
        require(type(state.get("Running")) is bool and type(state.get("Pid")) is int
                and state["Pid"] >= 0 and (state.get("ExitCode") is None
                or type(state["ExitCode"]) is int), "exact container final state malformed")
    except Exception as issue:
        raise SettlementFailure(stop_failure, issue) from issue
    return stopped_state(state, stop_requested, stop_failure)


def stopped_state(state, stop_requested=False, stop_failure=None):
    require(type(state.get("Running")) is bool and type(state.get("Pid")) is int
            and state["Pid"] >= 0 and (state.get("ExitCode") is None
            or type(state["ExitCode"]) is int), "exact container final state malformed")
    return {"Status": bounded_text(state.get("Status", ""), 64),
            "Running": state["Running"], "Pid": state["Pid"],
            "ExitCode": state.get("ExitCode"), "Error": bounded_text(state.get("Error", ""), 2000),
            "stoppedVerified": state["Running"] is False and state["Pid"] == 0,
            "stopRequested": stop_requested,
            "stopCommandSucceeded": stop_requested and stop_failure is None,
            "stopFailure": stop_failure}


def seal_parent_checkpoint(target, container_id, name, image_id, proof, scratch,
                           mode, final, state, observed_wall):
    """Save final proof while its parent is still active, before cleanup."""
    require(state and state.get("stoppedVerified") is True
            and state.get("Running") is False and state.get("Pid") == 0
            and final and final.get("extinctionObserved") is True
            and final.get("populated") is False and final.get("finalCpuVerified") is True,
            "checkpoint requires complete parent proof and exact stopped Docker state")
    row = {"schema": "openclaw-v98-parent-accounting-checkpoint/v1",
           "containerId": container_id, "containerName": name, "imageConfigId": image_id,
           "mode": mode, "cgroupParent": accounting_name(name),
           "proofMount": str(proof), "scratchMount": str(scratch),
           "sourceCommit": SOURCE, "sourceTree": TREE,
           "parentAccountingFinal": final, "stoppedContainerState": state,
           "aggregateCpuObservedWallSeconds": observed_wall}
    data = (json.dumps(row, indent=2) + "\n").encode()
    require(len(data) <= 32 * 1024, "parent checkpoint exceeds evidence budget")
    target = Path(target)
    partial = target.with_name("." + target.name + ".partial")
    with partial.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    partial.replace(target)
    directory = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return {"path": target.name, "bytes": len(data), "sha256": sha256(target)}


def scratch_bytes(scratch):
    total = 0
    for path in Path(scratch).rglob("*"):
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode) or
                stat.S_ISLNK(info.st_mode), "unsupported scratch artifact type")
        if stat.S_ISREG(info.st_mode):
            total += info.st_size
    return total


class BoundedWriter:
    def __init__(self, stream, limit):
        self.stream = stream
        self.limit = limit
        self.count = 0

    def write(self, data):
        require(self.count + len(data) <= self.limit,
                "compressed scratch archive exceeds its byte budget")
        written = self.stream.write(data)
        require(written == len(data), "short scratch archive write")
        self.count += written
        return written

    def flush(self):
        self.stream.flush()

    def tell(self):
        return self.count


def retain_scratch(scratch, target):
    target = Path(target)
    temporary = target.with_name("." + target.name + ".partial")
    require(not os.path.lexists(target) and not os.path.lexists(temporary),
            "scratch archive destination already exists")
    total = 0
    entries = path_bytes = 0
    admitted = []
    for path in Path(scratch).rglob("*"):
        entries += 1
        name = str(path.relative_to(scratch))
        encoded = name.encode("utf-8")
        path_bytes += len(encoded)
        require(entries <= MAX_ARCHIVE_ENTRIES and len(encoded) <= 512
                and path_bytes <= MAX_ARCHIVE_PATH_BYTES,
                "scratch namespace exceeds archive metadata budget")
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode) or
                stat.S_ISLNK(info.st_mode), "unsupported scratch artifact type")
        if stat.S_ISLNK(info.st_mode):
            require(len(os.readlink(path).encode("utf-8")) <= 512,
                    "scratch symlink metadata exceeds budget")
        if stat.S_ISREG(info.st_mode):
            total += info.st_size
            require(total <= MAX_SCRATCH and info.st_nlink == 1,
                    "scratch regular bytes or link count exceed budget")
        admitted.append((name, path))
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb", buffering=0) as stream:
            bounded = BoundedWriter(stream, MAX_SCRATCH)
            with tarfile.open(fileobj=bounded, mode="w:gz", dereference=False) as archive:
                for name, path in sorted(admitted):
                    archive.add(path, arcname=name, recursive=False)
            stream.flush()
            os.fsync(stream.fileno())
        require(temporary.stat().st_size <= MAX_SCRATCH,
                "compressed scratch evidence over budget")
        os.rename(temporary, target)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)
    return total


def observe_scratch_usage(path, identity):
    """Host-only allocation counters from the exact mounted scratch inode."""
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        require((info.st_dev, info.st_ino) == identity and stat.S_ISDIR(info.st_mode)
                and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == 1000 and info.st_gid == 1000,
                "scratch usage mount identity changed")
        usage = os.fstatvfs(fd)
        unit = usage.f_frsize or usage.f_bsize
        require(unit > 0 and usage.f_blocks * unit == MAX_SCRATCH
                and 0 <= usage.f_bavail <= usage.f_bfree <= usage.f_blocks
                and 0 <= usage.f_ffree <= usage.f_files, "scratch allocation counters invalid or cap changed")
        return {"capacityBytes": usage.f_blocks * unit,
                "allocatedBytes": (usage.f_blocks - usage.f_bfree) * unit,
                "availableBytes": usage.f_bavail * unit,
                "usedInodes": usage.f_files - usage.f_ffree,
                "freeInodes": usage.f_ffree}
    finally:
        os.close(fd)


class ScratchUsage:
    """Bounded sampled allocation evidence; never a cleanup authority."""
    def __init__(self, path, identity):
        self.path, self.identity = path, identity
        self.started = time.monotonic()
        self.last = None
        self.offset = 0
        self.phase = None
        self.samples = 0
        self.max_allocated = 0
        self.max_gap = 0.0
        self.minimum_available = MAX_SCRATCH
        self.minimum_free_inodes = None
        self.windows = {}
        self.boundaries = []

    def sample(self, reason, force=False):
        now = time.monotonic()
        if not force and self.last is not None and now - self.last < 0.05:
            return
        counters = observe_scratch_usage(self.path, self.identity)
        row = {"elapsedSeconds": round(now - self.started, 6), "lastNativePhaseSeen": self.phase, **counters}
        self.samples += 1
        if self.last is not None:
            self.max_gap = max(self.max_gap, now - self.last)
        self.last = now
        self.max_allocated = max(self.max_allocated, counters["allocatedBytes"])
        self.minimum_available = min(self.minimum_available, counters["availableBytes"])
        free = counters["freeInodes"]
        self.minimum_free_inodes = free if self.minimum_free_inodes is None else min(self.minimum_free_inodes, free)
        key = str(self.phase) if self.phase is not None else "before-phase"
        window = self.windows.setdefault(key, {"samples": 0, "maximumSampledAllocatedBytes": 0})
        window["samples"] += 1
        window["maximumSampledAllocatedBytes"] = max(window["maximumSampledAllocatedBytes"], counters["allocatedBytes"])
        if reason != "periodic":
            require(len(self.boundaries) < 20, "scratch usage boundary budget exceeded")
            self.boundaries.append({"reason": reason, **row})

    def observe(self, stdout, force=False):
        # Native output is already bounded by its existing stream owner. Read
        # only complete new lines; receipt times may lag actual phase changes.
        while True:
            end = stdout.find(b"\n", self.offset)
            if end < 0:
                break
            native, _ = parse_events(bytes(stdout[self.offset:end + 1]), b"")
            self.offset = end + 1
            for row in native:
                if row["event"] in ("phase_started", "phase_joined"):
                    phase = row.get("phase")
                    require(type(phase) is int and 0 <= phase <= 6, "scratch usage native phase invalid")
                    self.phase = phase
                    self.sample(row["event"], force=True)
        self.sample("periodic", force=force)

    def seal(self, target):
        require(self.samples > 0, "scratch allocation never observed")
        summary = {"schema": "openclaw-v98-scratch-allocation-observations/v1",
            "status": "OBSERVED_SAMPLED_LOWER_BOUND; EXACT_PEAK_NOT_CLAIMED",
            "mountDevInode": self.identity, "hardScratchCapacityBytes": MAX_SCRATCH,
            "samples": self.samples, "nominalPollSeconds": 0.05,
            "maximumObservedGapSeconds": round(self.max_gap, 6),
            "maximumSampledAllocatedBytes": self.max_allocated,
            "minimumSampledAvailableBytes": self.minimum_available,
            "minimumSampledFreeInodes": self.minimum_free_inodes,
            "nativeEventCorrelatedWindows": self.windows, "nativeEventReceiptObservations": self.boundaries,
            "limitations": "Samples can miss brief peaks; phase labels use received native events and may lag execution. fstatvfs includes allocated live-unlinked files but does not identify their names. Only actual full-six success under the verified hard cap proves that flow fits; no storage sample grants extinction or cleanup."}
        encoded = (json.dumps(summary, indent=2) + "\n").encode()
        require(len(encoded) <= 32 * 1024, "scratch usage receipt exceeds budget")
        Path(target).write_bytes(encoded)
        return {"path": "scratch-usage.json", "bytes": len(encoded), "sha256": hashlib.sha256(encoded).hexdigest(),
                "maximumSampledAllocatedBytes": self.max_allocated, "exactPeakClaimed": False}


def run_mode(image_id, proof, out, name, mode):
    out = Path(out)
    out.mkdir(mode=0o755)
    scratch = out / "scratch-tmpfs"
    container_id = None
    group_fd = pidfd = child_group_fd = None
    cgroup = identity = None
    accounting = None
    accounting_final = None
    accounting_release = None
    accounting_settlement_failure = None
    checkpoint = None
    scratch_usage = None
    scratch_usage_receipt = None
    scratch_usage_failure = None
    extinct = False
    stdout = bytearray()
    stderr = bytearray()
    deadline_killed = False
    deadline_kill_requested_wall = None
    deadline_signal_completed_wall = None
    attach = None
    sel = None
    cpu = None
    cpu_observed_wall = None
    lifetime_end_observed_wall = None
    final_cpu_verified = False
    final_cpu_status = "NOT_ATTEMPTED"
    exit_code = None
    operation = "scratch preparation"
    mode_started = None
    owned = None
    receipt = None
    error = None
    cleanup_errors = []
    stopped_without_group = False
    stopped_container_state = None
    settlement_failure = None
    creation_attempted = False
    try:
        operation = "persistent accounting parent creation"
        accounting = SliceOwner(command, accounting_name(name))
        accounting.create()
        group_fd, cgroup, identity = accounting.directory_fd, accounting.path, accounting.identity
        cpu = 0
        scratch_identity = mount_scratch(scratch)
        scratch_usage = ScratchUsage(scratch, (scratch_identity.st_dev, scratch_identity.st_ino))
        operation = "scratch allocation observation"
        scratch_usage.observe(stdout, force=True)
        creation_attempted = True
        operation = "container create"
        container_id = command(create_command(name, image_id, proof, scratch, mode)).decode().strip()
        require(HEX64.fullmatch(container_id), "Docker did not create an exact owned container")
        accounting.expect_container(container_id)
        created = docker_inspect(container_id)
        inspect_owned_container(created, container_id, name, image_id, proof, scratch, mode)
        inspect_container_configuration(created, container_id, image_id, proof, scratch)
        require(created.get("State", {}).get("Running") is False
                and created["State"].get("Pid") == 0, "created container already has a live PID")
        operation = "container start and bounded streams"
        mode_started = time.monotonic()
        attach = subprocess.Popen(["docker", "start", "--attach", container_id],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        sel = selectors.DefaultSelector()
        for stream, label in ((attach.stdout, "stdout"), (attach.stderr, "stderr")):
            os.set_blocking(stream.fileno(), False)
            sel.register(stream, selectors.EVENT_READ, label)
        gate_seen = False
        while sel.get_map() or attach.poll() is None:
            for key, _ in sel.select(0.05):
                data = os.read(key.fileobj.fileno(), 65536)
                if not data:
                    sel.unregister(key.fileobj)
                    continue
                target = stdout if key.data == "stdout" else stderr
                limit = MAX_STDOUT if key.data == "stdout" else MAX_STDERR
                overflow = len(target) + len(data) > limit
                target.extend(data[:max(0, limit - len(target))])
                require(not overflow,
                        "native/product log budget exceeded")
            if not gate_seen and b"\n" in stdout:
                first = bytes(stdout).split(b"\n", 1)[0] + b"\n"
                native, _ = parse_events(first, b"")
                require(native and native[0] == {"event": "host_gate_ready", "mode": mode},
                        "first trusted stdout was not host gate")
                operation = "actual PID1 and cgroup admission"
                owned = observe_owned_process(container_id, name, image_id, proof, scratch, mode)
                owned_pid, starttime, pidfd, child_group_fd, child_cgroup, child_identity = owned
                accounting.bind_child(child_cgroup, child_identity, pid=owned_pid)
                host_pid_gate(container_id, image_id, proof, scratch, owned)
                require(proc_starttime(docker_inspect(container_id)["State"]["Pid"]) == starttime,
                        "Docker PID1 changed before host gate")
                accounting.bind_child(child_cgroup, child_identity, pid=owned_pid)
                cpu = accounting.cpu_delta()
                cpu_observed_wall = time.monotonic() - mode_started
                require(0 <= cpu <= MODE_LIMITS[mode][1],
                        "whole-cgroup aggregate CPU budget exceeded before gate")
                require(cpu_observed_wall < MODE_LIMITS[mode][0],
                        "native wall deadline exceeded before gate")
                gate_seen = True
                release_gate(scratch)
            operation = "scratch allocation observation"
            scratch_usage.observe(stdout)
            if not gate_seen and time.monotonic() - mode_started > 5:
                raise Refusal("trusted host gate not observed within five seconds")
            if attach.poll() is not None and not sel.get_map():
                break
            operation = "live cgroup observation"
            if accounting.populated():
                observed = accounting.cpu_delta()
                require(observed >= cpu, "aggregate CPU counter decreased")
                cpu = observed
                cpu_observed_wall = time.monotonic() - mode_started
                wall_limit, cpu_limit = MODE_LIMITS[mode]
                require(cpu >= 0, "aggregate CPU counter decreased")
                if cpu > cpu_limit:
                    raise Refusal("whole-cgroup aggregate CPU budget exceeded")
                if time.monotonic() - mode_started >= wall_limit and attach.poll() is None:
                    deadline_kill_requested_wall = time.monotonic() - mode_started
                    signalled_at = accounting.kill()
                    deadline_killed = True
                    deadline_signal_completed_wall = (signalled_at - mode_started
                                                      if signalled_at is not None else None)
                    if mode != "--deadline-probe":
                        raise Refusal("native wall deadline exceeded")
                    require(deadline_kill_requested_wall <= wall_limit + 0.1
                            and deadline_signal_completed_wall is not None
                            and deadline_signal_completed_wall <= wall_limit + 0.1,
                            "deadline control was requested or signalled too late")
        operation = "exact container exit and native outcome"
        attach.wait(timeout=2)
        lifetime_end_observed_wall = time.monotonic() - mode_started
        if mode != "--deadline-probe":
            require(lifetime_end_observed_wall <= MODE_LIMITS[mode][0] + 0.1,
                    "complete native lifetime exceeded wall budget")
        inspected = docker_inspect(container_id)
        inspect_owned_container(inspected, container_id, name, image_id, proof, scratch, mode)
        require(inspected.get("State", {}).get("Running") is False
                and inspected["State"].get("Pid") == 0, "exact container final stop was not observed")
        stopped_container_state = stopped_state(inspected["State"])
        exit_code = inspected["State"]["ExitCode"]
        require(gate_seen and group_fd is not None, "host gate was never admitted")
        native, product = parse_events(bytes(stdout), bytes(stderr))
        operation = "scratch allocation observation"
        scratch_usage.observe(stdout, force=True)
        operation = "exact container exit and native outcome"
        assess_native(mode, native, product, exit_code, deadline_killed)
        operation = "final aggregate CPU accounting"
        final_cpu_status = "ATTEMPTED_UNVERIFIED"
        accounting_final = accounting.final_observation(cpu)
        extinct = accounting_final["extinctionObserved"]
        observed = accounting_final["aggregateCpuUsec"]
        require(observed >= cpu, "final aggregate CPU counter decreased")
        cpu = observed
        cpu_observed_wall = time.monotonic() - mode_started
        require(0 <= cpu <= MODE_LIMITS[mode][1],
                "final whole-cgroup aggregate CPU budget was not verified")
        final_cpu_verified = True
        final_cpu_status = "VERIFIED"
        require(extinct, "whole task parent still populated after native exit")
        if mode != "--run-frozen-six-phases":
            require(scratch_bytes(scratch) <= MAX_PROBE_SCRATCH,
                    "probe scratch exceeds retained evidence budget")
        receipt = {"mode": mode, "containerId": container_id, "imageConfigId": image_id,
                   "cgroupDevInode": identity, "aggregateCpuUsecLastObserved": cpu,
                   "aggregateCpuObservedWallSeconds": cpu_observed_wall,
                   "finalCpuVerified": final_cpu_verified,
                   "finalCpuStatus": final_cpu_status,
                   "parentAccountingFinal": accounting_final,
                   "lifetimeEndObservedWallSeconds": lifetime_end_observed_wall,
                   "wallSeconds": time.monotonic() - mode_started,
                   "exitCode": exit_code, "deadlineKilled": deadline_killed,
                   "deadlineKillRequestedWallSeconds": deadline_kill_requested_wall,
                   "deadlineSignalCompletedWallSeconds": deadline_signal_completed_wall,
                   "extinctionObserved": extinct, "nativeEvents": native, "productEvents": product}
    except Exception as caught:
        error = caught
        # A policy refusal must still settle the container. Cleanup authority
        # has narrower checks and never admits the tracee or releases the gate.
        if container_id and group_fd is not None and not extinct:
            try:
                accounting.kill()
            except Exception as kill_error:
                cleanup_errors.append("owned parent kill: " + str(kill_error)[:300])
        # Exact-ID settlement and its stopped-state witness are independent of
        # cgroup accounting/extinction. A vanished scope must not skip them.
        if container_id:
            try:
                stopped_container_state = settle_created_container(container_id, name, image_id, proof, scratch, mode)
                stopped_without_group = stopped_container_state["stoppedVerified"] and not extinct
                if stopped_container_state["stopFailure"] is not None:
                    cleanup_errors.append("exact ID kill: " + stopped_container_state["stopFailure"]["reason"])
                if not stopped_container_state["stoppedVerified"]:
                    cleanup_errors.append("exact container stop was not verified by final Running=false/Pid=0")
            except Exception as kill_error:
                if isinstance(kill_error, SettlementFailure):
                    settlement_failure = kill_error.details
                cleanup_errors.append("exact ID kill: " + str(kill_error)[:300])
        if accounting is not None and group_fd is not None:
            try:
                final_cpu_status = "ATTEMPTED_UNVERIFIED"
                accounting_final = accounting.final_observation(cpu or 0)
                extinct = accounting_final["extinctionObserved"]
                cpu = accounting_final["aggregateCpuUsec"]
                cpu_observed_wall = time.monotonic() - mode_started if mode_started is not None else None
                final_cpu_verified = 0 <= cpu <= MODE_LIMITS[mode][1]
                final_cpu_status = "VERIFIED" if final_cpu_verified else "OBSERVED_OVER_BUDGET"
                stopped_without_group = bool(stopped_container_state and
                                              stopped_container_state["stoppedVerified"] and not extinct)
            except Exception as accounting_error:
                accounting_settlement_failure = failure_detail(accounting_error, "final parent accounting/extinction")
                cleanup_errors.append("final parent proof: " + str(accounting_error)[:300])
    finally:
        if attach is not None and attach.poll() is None:
            try:
                attach.terminate()
                attach.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    attach.kill()
                    attach.wait(timeout=2)
                except Exception as attach_error:
                    cleanup_errors.append("Docker attach stop: " + str(attach_error)[:300])
            except Exception as attach_error:
                cleanup_errors.append("Docker attach stop: " + str(attach_error)[:300])
        if sel is not None:
            sel.close()
        if attach is not None:
            attach.stdout.close()
            attach.stderr.close()
        if scratch_usage is not None:
            try:
                scratch_usage.observe(stdout, force=True)
                scratch_usage_receipt = scratch_usage.seal(out / "scratch-usage.json")
                if receipt is not None:
                    receipt["scratchUsage"] = scratch_usage_receipt
            except Exception as usage_error:
                scratch_usage_failure = failure_detail(usage_error, "scratch allocation observation/retention")
                cleanup_errors.append("scratch usage retention: " + str(usage_error)[:300])
        try:
            (out / "native-stdout.jsonl").write_bytes(bytes(stdout))
            (out / "product-stderr.log").write_bytes(bytes(stderr))
        except Exception as log_error:
            cleanup_errors.append("bounded log retention: " + str(log_error)[:300])
        if extinct and accounting_final is not None and stopped_container_state and not cleanup_errors:
            try:
                checkpoint = seal_parent_checkpoint(out / "parent-accounting-checkpoint.json",
                    container_id, name, image_id, proof, scratch, mode, accounting_final,
                    stopped_container_state, cpu_observed_wall)
                if receipt is not None:
                    receipt["parentAccountingCheckpoint"] = checkpoint
            except Exception as checkpoint_error:
                cleanup_errors.append("parent proof checkpoint: " + str(checkpoint_error)[:300])
        if checkpoint is not None and not cleanup_errors:
            try:
                retain_scratch(scratch, out / "scratch.tar.gz")
            except Exception as archive_error:
                cleanup_errors.append("scratch retention: " + str(archive_error)[:300])
            if container_id and not cleanup_errors:
                try:
                    # Archive work may take time. Rejoin exact stopped ownership
                    # and unchanged complete parent proof immediately before rm.
                    final_container = docker_inspect(container_id)
                    inspect_owned_container(final_container, container_id, name, image_id, proof, scratch, mode)
                    require(stopped_state(final_container["State"])["stoppedVerified"],
                            "container changed before removal")
                    refreshed = accounting.final_observation(cpu)
                    require(refreshed == accounting_final, "parent proof changed before removal")
                    command(["docker", "rm", container_id], timeout=5)
                except Exception as remove_error:
                    cleanup_errors.append("owned container removal: " + str(remove_error)[:300])
            if not cleanup_errors:
                try:
                    command(["umount", str(scratch)], timeout=5)
                except Exception as unmount_error:
                    cleanup_errors.append("task scratch unmount: " + str(unmount_error)[:300])
        if pidfd is not None:
            try:
                os.close(pidfd)
            except OSError as close_error:
                cleanup_errors.append("PID handle close: " + str(close_error)[:300])
        if child_group_fd is not None:
            try:
                os.close(child_group_fd)
            except OSError as close_error:
                cleanup_errors.append("child cgroup handle close: " + str(close_error)[:300])
        if accounting is not None:
            try:
                if checkpoint is not None and not cleanup_errors:
                    accounting_release = accounting.release()
                    if receipt is not None:
                        receipt["parentAccountingRelease"] = accounting_release
            except OSError as close_error:
                cleanup_errors.append("accounting handle close: " + str(close_error)[:300])
            except Exception as release_error:
                cleanup_errors.append("owned parent release: " + str(release_error)[:300])
            finally:
                try:
                    accounting.close()
                except Exception as close_error:
                    cleanup_errors.append("accounting handle close: " + str(close_error)[:300])
        if not extinct and os.path.ismount(scratch):
            cleanup_errors.append("task scratch retained because cgroup extinction was not proved")
    if error is None and cleanup_errors:
        error = Refusal("cleanup or evidence retention incomplete")
    if error is not None:
        host_failure = failure_detail(error, operation)
        native_exits = []
        try:
            native, _ = parse_events(bytes(stdout), bytes(stderr))
            phases = range(1, 7) if mode == "--run-frozen-six-phases" else (0,)
            native_exits = [{"phase": row["phase"], "exitCode": row["value"]} for row in native
                            if row.get("event") == "phase_joined" and type(row.get("phase")) is int
                            and row["phase"] in phases
                            and type(row.get("value")) is int and 0 <= row["value"] <= 255]
            require(len(native_exits) <= len(phases)
                    and len({row["phase"] for row in native_exits}) == len(native_exits),
                    "native exit observations are duplicated or unbounded")
        except Exception as parse_error:
            native_exits = []
            cleanup_errors.append("native failure observation: " + str(parse_error)[:300])
        failed_phase = next((row for row in native_exits if row["exitCode"]), None)
        primary_failure = ({"authority": "TRUSTED_NATIVE_PHASE_EXIT",
                            "reason": "native phase " + str(failed_phase["phase"]) +
                                      " exited " + str(failed_phase["exitCode"])}
                           if failed_phase else {"authority": "HOST_OPERATION", **host_failure})
        encoded = (json.dumps({
            "status": "FAILED; NO_RUNTIME_QUALIFICATION", "mode": mode,
            "reason": primary_failure["reason"], "primaryFailure": primary_failure,
            "hostFailure": host_failure, "nativePhaseExits": native_exits,
            "containerExitCode": exit_code, "containerId": container_id,
            "cgroupDevInode": identity, "extinctionObserved": extinct,
            "aggregateCpuUsecLastObserved": cpu,
            "aggregateCpuObservedWallSeconds": cpu_observed_wall,
            "lifetimeEndObservedWallSeconds": lifetime_end_observed_wall,
            "finalCpuVerified": final_cpu_verified,
            "finalCpuStatus": final_cpu_status,
            "parentAccounting": accounting.receipt() if accounting is not None else None,
            "parentAccountingFinal": accounting_final,
            "parentAccountingRelease": accounting_release,
            "parentAccountingCheckpoint": checkpoint,
            "scratchUsage": scratch_usage_receipt,
            "scratchUsageFailure": scratch_usage_failure,
            "accountingSettlementFailure": accounting_settlement_failure,
            "stoppedWithoutCgroupProof": stopped_without_group,
            "stoppedContainerState": stopped_container_state,
            "containerSettlementFailure": settlement_failure,
            "containerCreationAttempted": creation_attempted,
            "creationOutcome": "EXACT_ID_OBSERVED" if container_id else (
                "UNKNOWN" if creation_attempted else "NOT_ATTEMPTED"),
            "attachReturnCode": attach.poll() if attach is not None else None,
            "cleanupErrors": cleanup_errors, "scratchMounted": os.path.ismount(scratch),
            "deadlineKilled": deadline_killed,
            "deadlineKillRequestedWallSeconds": deadline_kill_requested_wall,
            "deadlineSignalCompletedWallSeconds": deadline_signal_completed_wall}, indent=2,
            ensure_ascii=False) + "\n").encode("utf-8")
        require(len(encoded) <= 32 * 1024, "failure receipt exceeds evidence budget")
        (out / "failure.json").write_bytes(encoded)
        if failed_phase:
            raise Refusal(primary_failure["reason"]) from error
        raise error
    (out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt


def collect_evidence(validation, host_output, destination):
    """Stage only bounded, sealed attempt evidence for unconditional retention."""
    destination = Path(destination)
    destination.mkdir(mode=0o755)
    host_output = Path(host_output)
    files = [(Path(validation), Path("validation.json"), 1024 * 1024),
             (host_output / "host-preflight.json", Path("host-preflight.json"), 32 * 1024),
             (host_output / "startup-preflight.json", Path("startup-preflight.json"), 32 * 1024),
             (host_output / "preparation.json", Path("preparation.json"), 1024 * 1024),
             (host_output / "qualification.json", Path("qualification.json"), 2 * 1024 * 1024)]
    for number in (1, 2, 3):
        attempt = host_output / f"attempt-{number}"
        for name, cap in (("failure.json", 32 * 1024), ("receipt.json", 2 * 1024 * 1024),
                          ("parent-accounting-checkpoint.json", 32 * 1024),
                          ("scratch-usage.json", 32 * 1024),
                          ("native-stdout.jsonl", MAX_STDOUT),
                          ("product-stderr.log", MAX_STDERR)):
            files.append((attempt / name, Path(f"attempt-{number}") / name, cap))
    # Scratch archives are last so receipts and bounded logs have priority.
    for number in (1, 2, 3):
        name = f"attempt-{number}"
        files.append((host_output / name / "scratch.tar.gz", Path(name) / "scratch.tar.gz",
                      MAX_SCRATCH))
    copied = []
    omitted = []
    used = 0
    reserve = 64 * 1024
    for source, relative, cap in files:
        if not os.path.lexists(source):
            continue
        try:
            info = source.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                    "unsealed or aliased evidence file")
            require(info.st_size <= cap and used + info.st_size <= MAX_UPLOAD - reserve,
                    "evidence file or aggregate byte budget exceeded")
            target = destination / relative
            target.parent.mkdir(mode=0o755, exist_ok=True)
            input_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                current = os.fstat(input_fd)
                require((current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns)
                        == (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns),
                        "evidence source changed before copy")
                output_fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                                    0o644)
                try:
                    remaining = info.st_size
                    digest = hashlib.sha256()
                    while remaining:
                        chunk = os.read(input_fd, min(1024 * 1024, remaining))
                        require(chunk, "evidence source shortened during copy")
                        digest.update(chunk)
                        require(os.write(output_fd, chunk) == len(chunk), "short evidence write")
                        remaining -= len(chunk)
                    final = os.fstat(input_fd)
                    require((final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns)
                            == (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns),
                            "evidence source changed during copy")
                finally:
                    os.close(output_fd)
            finally:
                os.close(input_fd)
            used += info.st_size
            copied.append({"path": str(relative), "bytes": info.st_size,
                           "sha256": digest.hexdigest()})
        except (OSError, Refusal) as issue:
            target = destination / relative
            if os.path.lexists(target):
                os.unlink(target)
            omitted.append({"path": str(relative), "reason": str(issue)[:160]})
    for number in (1, 2, 3):
        attempt = host_output / f"attempt-{number}"
        if not attempt.is_dir():
            continue
        if not any(row["path"] == f"attempt-{number}/scratch.tar.gz" for row in copied):
            omitted.append({"path": f"attempt-{number}/scratch.tar.gz",
                            "reason": "scratch archive was not sealed within budget; host scratch custody is retained when mounted"})
    manifest = {"status": "BOUNDED_EVIDENCE_STAGED", "byteLimit": MAX_UPLOAD,
                "copiedBytes": used, "copied": copied, "omitted": omitted}
    encoded = (json.dumps(manifest, indent=2) + "\n").encode()
    require(len(encoded) <= reserve, "evidence omission manifest budget exceeded")
    (destination / "evidence-custody.json").write_bytes(encoded)
    require(sum(path.stat().st_size for path in destination.rglob("*") if path.is_file()) <= MAX_UPLOAD,
            "staged evidence exceeded aggregate budget")
    return manifest


def verify_hosted_attempt(commit):
    approved = os.environ.get("V98_APPROVED_COMMIT", "")
    number = os.environ.get("V98_APPROVED_RUN_NUMBER", "")
    require(isinstance(commit, str) and re.fullmatch(r"[0-9a-f]{40}", commit)
            and re.fullmatch(r"[0-9a-f]{40}", approved)
            and re.fullmatch(r"[1-9][0-9]{0,19}", number)
            and approved == commit == os.environ.get("GITHUB_SHA")
            and os.environ.get("GITHUB_REPOSITORY") == "fr-meyer/openclaw"
            and os.environ.get("GITHUB_REF") == "refs/heads/candidate/v2026.9.8-runtime-admission-5"
            and os.environ.get("GITHUB_EVENT_NAME") == "push"
            and os.environ.get("GITHUB_RUN_NUMBER") == number
            and os.environ.get("GITHUB_RUN_ATTEMPT") == "1",
            "wrong hosted workflow identity or explicit commit/run approval")
    return {"commit": commit, "runNumber": int(number), "runAttempt": 1}


def execute(args):
    require(os.geteuid() == 0 and platform.system() == "Linux" and platform.machine() == "x86_64",
            "hosted root Linux x86-64 runner required")
    verify_hosted_attempt(args.tooling_commit)
    tooling = Path(args.tooling).resolve()
    source = Path(args.source).resolve()
    commit = args.tooling_commit
    verify_source_manifest(tooling, commit)
    require(git(source, "rev-parse", "HEAD") == SOURCE
            and git(source, "rev-parse", "HEAD^{tree}") == TREE
            and not git(source, "status", "--porcelain=v1", "--untracked-files=normal"),
            "qualified product checkout changed")
    base = tooling / "scripts/proofs/v98-confined"
    validation, binding = verify_prepared(args.validation, base / "read-policy/runtime-read-binding.json",
                                          base / "packet.json", args.image)
    require(validation.get("toolingCommit") == "711da57d4e7576fb911f917cd83ead95dfd17602",
            "retained artifact producer changed")
    out = Path(args.output).resolve()
    out.mkdir(mode=0o755)
    startup_preflight(base, binding, out)
    proof = out / "proof"
    proof_files = prepare_proof(tooling, binding, proof)
    compiler = compile_native(tooling, proof)
    (out / "preparation.json").write_text(json.dumps({"toolingCommit": commit,
        "retainedImageSha256": IMAGE_SHA, "imageConfigId": IMAGE_ID,
        "proofFiles": proof_files, "compiler": compiler, "runtimeExecuted": False}, indent=2) + "\n")
    host_preflight(proof, out)
    # Source verification precedes all Docker operations. The saved image is
    # loaded only once, after exact archive and selected read joins pass.
    prior = subprocess.run(["docker", "image", "inspect", IMAGE_ID], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=5)
    require(prior.returncode != 0, "retained image already exists; ownership ambiguous")
    command(["docker", "load", "--input", str(args.image)], timeout=180, stdout_limit=65536)
    loaded = json.loads(command(["docker", "image", "inspect", IMAGE_ID], timeout=5))
    require(len(loaded) == 1 and loaded[0].get("Id") == IMAGE_ID
            and loaded[0].get("Os") == "linux" and loaded[0].get("Architecture") == "amd64",
            "loaded image config or target architecture differs from selected retained bytes")
    completed = []
    try:
        for index, mode in enumerate(MODE_LIMITS, start=1):
            completed.append(run_mode(IMAGE_ID, proof, out / f"attempt-{index}",
                                      f"v98-confined-{os.environ['GITHUB_RUN_ID']}-1-{index}", mode))
    finally:
        if len(completed) == len(MODE_LIMITS):
            command(["docker", "image", "rm", IMAGE_ID], timeout=15)
    (out / "qualification.json").write_text(json.dumps({"status": "SYNTHETIC_HOST_OBSERVATIONS_COMPLETE",
        "imageConfigId": IMAGE_ID, "modes": completed,
        "productionAdmitted": False, "productionStateRead": False}, indent=2) + "\n")


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--retain-evidence":
        parser = argparse.ArgumentParser(description="Stage bounded exact-attempt evidence")
        parser.add_argument("--retain-evidence", action="store_true")
        parser.add_argument("--validation", type=Path, required=True)
        parser.add_argument("--host-output", type=Path, required=True)
        parser.add_argument("--destination", type=Path, required=True)
        selected = parser.parse_args()
        collect_evidence(selected.validation, selected.host_output, selected.destination)
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tooling", type=Path, required=True)
    parser.add_argument("--tooling-commit", required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--validation", type=Path, required=True)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    execute(args)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("Confined host admission refused: " + str(error), file=sys.stderr)
        sys.exit(125)
