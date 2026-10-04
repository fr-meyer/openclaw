#!/usr/bin/env python3
"""One hosted, exact-image confined runtime attempt. Never run on a local host.

The workflow owns authorization and acquisition. This program refuses execution
until the reviewed source manifest, retained image validator, Docker container,
actual PID 1 and host cgroup all agree. Unit tests import only its pure checks.
"""
import argparse
import hashlib
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


class Refusal(ValueError):
    pass


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
         "read-policy/runtime-read-binding.json", "read-policy/parent-read-paths.txt",
         "read-policy/helper-read-paths.txt")
    } | {"scripts/proofs/v98-confined/inputs/" + name for name in PROOF_INPUTS} | {
        ".github/workflows/v98-confined-runtime.yml",
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
            and v.get("selectedReadFilesVerifiedAgainstSavedLayers") == 1547
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
            and len(b.get("imageEntries", [])) == 1547 and len(b.get("namespaceEntries", [])) == 358,
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


def cgroup_cpu(stats):
    rows = dict(line.split() for line in stats.splitlines())
    value = rows.get("usage_usec", "")
    require(value.isdecimal(), "missing aggregate cgroup CPU usage")
    return int(value)


def read_cgroup_cpu_fd(fd):
    os.lseek(fd, 0, os.SEEK_SET)
    data = os.read(fd, 4096)
    require(len(data) < 4096, "aggregate cgroup CPU counter is unbounded")
    return cgroup_cpu(data.decode("ascii"))


def inspect_container(inspect, container_id, image_id, proof, scratch):
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
    require(inspect.get("AppArmorProfile") == "docker-default",
            "Docker default AppArmor is not enforced")
    mounts = {row.get("Destination"): row for row in inspect.get("Mounts", [])}
    require(set(mounts) == {"/proof", "/scratch"}
            and mounts["/proof"].get("Type") == "bind" and mounts["/proof"].get("RW") is False
            and mounts["/scratch"].get("Type") == "bind" and mounts["/scratch"].get("RW") is True
            and Path(mounts["/proof"].get("Source", "")).resolve() == Path(proof).resolve()
            and Path(mounts["/scratch"].get("Source", "")).resolve() == Path(scratch).resolve(),
            "container mount scope changed")
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


def create_command(name, image, proof, scratch, mode):
    return ["docker", "create", "--name", name, "--user", "1000:1000", "--read-only",
            "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
            "--pids-limit", "128", "--memory", "1g", "--memory-swap", "1g", "--cpus", "1",
            "--shm-size", "1m", "--cgroupns", "private", "--ipc", "private",
            "--no-healthcheck", "--ulimit", "core=0:0", "--log-driver", "local",
            "--log-opt", "max-size=1m", "--log-opt", "max-file=1",
            "--mount", f"type=bind,src={proof},dst=/proof,readonly",
            "--mount", f"type=bind,src={scratch},dst=/scratch",
            "--entrypoint", "/proof/runner/v98-supervisor", image, mode]


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
    cpu_fd = os.open("cpu.stat", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=group_fd)
    try:
        baseline = read_cgroup_cpu_fd(cpu_fd)
    except Exception:
        os.close(cpu_fd)
        raise
    return baseline, cpu_fd


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


def extinction(cgroup, identity, fd):
    try:
        current = os.stat(cgroup)
    except FileNotFoundError:
        return os.fstat(fd).st_nlink == 0
    require((current.st_dev, current.st_ino) == identity, "owned cgroup path was reused")
    rows = dict(line.split() for line in (cgroup / "cgroup.events").read_text().splitlines())
    return rows.get("populated") == "0"


def wait_extinction(cgroup, identity, fd, seconds=5):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        if extinction(cgroup, identity, fd):
            return True
        time.sleep(0.05)
    return False


def kill_owned(container_id, cgroup, identity, fd):
    if extinction(cgroup, identity, fd):
        return None
    require((os.stat(cgroup).st_dev, os.stat(cgroup).st_ino) == identity,
            "refusing to kill reused cgroup path")
    try:
        with open(cgroup / "cgroup.kill", "w") as stream:
            stream.write("1\n")
        signalled_at = time.monotonic()
    except OSError:
        command(["docker", "kill", "--signal=KILL", container_id], timeout=5)
        signalled_at = time.monotonic()
    require(wait_extinction(cgroup, identity, fd), "owned cgroup extinction not observed")
    return signalled_at


def kill_created_without_group(container_id, name, image_id, proof, scratch, mode):
    """Stop the exact created ID if cgroup binding failed; do not claim extinction."""
    inspected = docker_inspect(container_id)
    inspect_owned_container(inspected, container_id, name, image_id, proof, scratch, mode)
    if inspected.get("State", {}).get("Running") is True:
        command(["docker", "kill", "--signal=KILL", container_id], timeout=5)
    require(docker_inspect(container_id).get("State", {}).get("Running") is False,
            "exact created container remains running")


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


def run_mode(image_id, proof, out, name, mode):
    out = Path(out)
    out.mkdir(mode=0o755)
    scratch = out / "scratch-tmpfs"
    container_id = None
    group_fd = pidfd = cpu_fd = None
    cgroup = identity = baseline = None
    extinct = False
    stdout = bytearray()
    stderr = bytearray()
    deadline_killed = False
    deadline_kill_requested_wall = None
    deadline_signal_completed_wall = None
    attach = None
    sel = None
    cpu = None
    started = time.monotonic()
    owned = None
    receipt = None
    error = None
    cleanup_errors = []
    stopped_without_group = False
    try:
        mount_scratch(scratch)
        container_id = command(create_command(name, image_id, proof, scratch, mode)).decode().strip()
        require(HEX64.fullmatch(container_id), "Docker did not create an exact owned container")
        attach = subprocess.Popen(["docker", "start", "--attach", container_id],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        sel = selectors.DefaultSelector()
        for stream, label in ((attach.stdout, "stdout"), (attach.stderr, "stderr")):
            os.set_blocking(stream.fileno(), False)
            sel.register(stream, selectors.EVENT_READ, label)
        gate_seen = False
        mode_started = None
        while sel.get_map() or attach.poll() is None:
            for key, _ in sel.select(0.05):
                data = os.read(key.fileobj.fileno(), 65536)
                if not data:
                    sel.unregister(key.fileobj)
                    continue
                target = stdout if key.data == "stdout" else stderr
                target.extend(data)
                require(len(target) <= (MAX_STDOUT if key.data == "stdout" else MAX_STDERR),
                        "native/product log budget exceeded")
            if not gate_seen and b"\n" in stdout:
                first = bytes(stdout).split(b"\n", 1)[0] + b"\n"
                native, _ = parse_events(first, b"")
                require(native and native[0] == {"event": "host_gate_ready", "mode": mode},
                        "first trusted stdout was not host gate")
                owned = observe_owned_process(container_id, name, image_id, proof, scratch, mode)
                _, starttime, pidfd, group_fd, cgroup, identity = owned
                baseline, cpu_fd = host_pid_gate(container_id, image_id, proof, scratch, owned)
                require(proc_starttime(docker_inspect(container_id)["State"]["Pid"]) == starttime,
                        "Docker PID1 changed before host gate")
                gate_seen = True
                mode_started = time.monotonic()
                cpu = 0
                release_gate(scratch)
            if not gate_seen and time.monotonic() - started > 5:
                raise Refusal("trusted host gate not observed within five seconds")
            if gate_seen and not extinction(cgroup, identity, group_fd):
                cpu = read_cgroup_cpu_fd(cpu_fd) - baseline
                wall_limit, cpu_limit = MODE_LIMITS[mode]
                require(cpu >= 0, "aggregate CPU counter decreased")
                if cpu > cpu_limit:
                    raise Refusal("whole-cgroup aggregate CPU budget exceeded")
                if time.monotonic() - mode_started >= wall_limit and attach.poll() is None:
                    deadline_kill_requested_wall = time.monotonic() - mode_started
                    signalled_at = kill_owned(container_id, cgroup, identity, group_fd)
                    deadline_killed = True
                    deadline_signal_completed_wall = (signalled_at - mode_started
                                                      if signalled_at is not None else None)
                    if mode != "--deadline-probe":
                        raise Refusal("native wall deadline exceeded")
                    require(deadline_kill_requested_wall <= wall_limit + 0.1
                            and deadline_signal_completed_wall is not None
                            and deadline_signal_completed_wall <= wall_limit + 0.1,
                            "deadline control was requested or signalled too late")
            if attach.poll() is not None and not sel.get_map():
                break
        attach.wait(timeout=2)
        inspected = docker_inspect(container_id)
        exit_code = inspected["State"]["ExitCode"]
        require(gate_seen and group_fd is not None, "host gate was never admitted")
        cpu = read_cgroup_cpu_fd(cpu_fd) - baseline
        require(0 <= cpu <= MODE_LIMITS[mode][1],
                "final whole-cgroup aggregate CPU budget was not verified")
        extinct = wait_extinction(cgroup, identity, group_fd)
        require(extinct, "whole cgroup still populated after native exit")
        if mode != "--run-frozen-six-phases":
            require(scratch_bytes(scratch) <= MAX_PROBE_SCRATCH,
                    "probe scratch exceeds retained evidence budget")
        native, product = parse_events(bytes(stdout), bytes(stderr))
        assess_native(mode, native, product, exit_code, deadline_killed)
        receipt = {"mode": mode, "containerId": container_id, "imageConfigId": image_id,
                   "cgroupDevInode": identity, "aggregateCpuUsecLastObserved": cpu,
                   "wallSeconds": time.monotonic() - mode_started,
                   "exitCode": exit_code, "deadlineKilled": deadline_killed,
                   "deadlineKillRequestedWallSeconds": deadline_kill_requested_wall,
                   "deadlineSignalCompletedWallSeconds": deadline_signal_completed_wall,
                   "extinctionObserved": extinct, "nativeEvents": native, "productEvents": product}
    except Exception as caught:
        error = caught
        # A policy refusal must still settle the container. Cleanup authority
        # has narrower checks and never admits the tracee or releases the gate.
        if container_id and group_fd is None and attach is not None:
            try:
                owned = observe_owned_process(container_id, name, image_id, proof, scratch, mode)
                _, _, pidfd, group_fd, cgroup, identity = owned
            except Exception as binding_error:
                cleanup_errors.append("cleanup binding: " + str(binding_error)[:300])
        if container_id and group_fd is not None and not extinct:
            try:
                kill_owned(container_id, cgroup, identity, group_fd)
                extinct = extinction(cgroup, identity, group_fd)
            except Exception as kill_error:
                cleanup_errors.append("owned cgroup kill: " + str(kill_error)[:300])
        elif container_id and group_fd is None:
            try:
                kill_created_without_group(container_id, name, image_id, proof, scratch, mode)
                stopped_without_group = True
            except Exception as kill_error:
                cleanup_errors.append("exact ID kill: " + str(kill_error)[:300])
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
        try:
            (out / "native-stdout.jsonl").write_bytes(bytes(stdout))
            (out / "product-stderr.log").write_bytes(bytes(stderr))
        except Exception as log_error:
            cleanup_errors.append("bounded log retention: " + str(log_error)[:300])
        if extinct:
            try:
                retain_scratch(scratch, out / "scratch.tar.gz")
            except Exception as archive_error:
                cleanup_errors.append("scratch retention: " + str(archive_error)[:300])
            if container_id:
                try:
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
        if cpu_fd is not None:
            try:
                os.close(cpu_fd)
            except OSError as close_error:
                cleanup_errors.append("CPU handle close: " + str(close_error)[:300])
        if group_fd is not None:
            try:
                os.close(group_fd)
            except OSError as close_error:
                cleanup_errors.append("cgroup handle close: " + str(close_error)[:300])
        if not extinct and os.path.ismount(scratch):
            cleanup_errors.append("task scratch retained because cgroup extinction was not proved")
    if error is None and cleanup_errors:
        error = Refusal("cleanup or evidence retention incomplete")
    if error is not None:
        (out / "failure.json").write_text(json.dumps({
            "status": "FAILED; NO_RUNTIME_QUALIFICATION", "mode": mode,
            "reason": str(error)[:2000], "containerId": container_id,
            "cgroupDevInode": identity, "extinctionObserved": extinct,
            "stoppedWithoutCgroupProof": stopped_without_group,
            "cleanupErrors": cleanup_errors, "scratchMounted": os.path.ismount(scratch),
            "deadlineKilled": deadline_killed,
            "deadlineKillRequestedWallSeconds": deadline_kill_requested_wall,
            "deadlineSignalCompletedWallSeconds": deadline_signal_completed_wall}, indent=2) + "\n")
        raise error
    (out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt


def collect_evidence(validation, host_output, destination):
    """Stage only bounded, sealed attempt evidence for unconditional retention."""
    destination = Path(destination)
    destination.mkdir(mode=0o755)
    host_output = Path(host_output)
    files = [(Path(validation), Path("validation.json"), 1024 * 1024),
             (host_output / "preparation.json", Path("preparation.json"), 1024 * 1024),
             (host_output / "qualification.json", Path("qualification.json"), 2 * 1024 * 1024)]
    for number in (1, 2, 3):
        attempt = host_output / f"attempt-{number}"
        for name, cap in (("failure.json", 32 * 1024), ("receipt.json", 2 * 1024 * 1024),
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


def execute(args):
    require(os.geteuid() == 0 and platform.system() == "Linux" and platform.machine() == "x86_64",
            "hosted root Linux x86-64 runner required")
    require(os.environ.get("GITHUB_REPOSITORY") == "fr-meyer/openclaw"
            and os.environ.get("GITHUB_REF") == "refs/heads/candidate/v2026.9.8-runtime-admission"
            and os.environ.get("GITHUB_RUN_ATTEMPT") == "1"
            and os.environ.get("GITHUB_RUN_NUMBER") == "1", "wrong hosted workflow identity")
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
    proof = out / "proof"
    proof_files = prepare_proof(tooling, binding, proof)
    compiler = compile_native(tooling, proof)
    (out / "preparation.json").write_text(json.dumps({"toolingCommit": commit,
        "retainedImageSha256": IMAGE_SHA, "imageConfigId": IMAGE_ID,
        "proofFiles": proof_files, "compiler": compiler, "runtimeExecuted": False}, indent=2) + "\n")
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
