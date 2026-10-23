#!/usr/bin/env python3
"""Bounded metadata evidence for one GitHub-hosted BuildKit qualification.

Docker limits and the workflow timeout are the live enforcement. This recorder
never kills a worker: observed violations refuse artifact publication at finish.
Disk floors are estimated export/load margins, not a proven cold-build capacity.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import time
import uuid

GIB = 1024**3
INTERVAL = 5
DURATION = 90 * 60
COMMAND_TIMEOUT = 10
PROFILE = {
    "builderMemoryBytes": 8 * GIB,
    "builderMemoryPlusSwapBytes": 8 * GIB,
    "builderCpuQuota": 400000,
    "builderCpuPeriod": 100000,
    "compilerOldSpaceMiB": 6144,
    "startAvailableMemoryBytes": 10 * GIB,
    "runtimeAvailableMemoryBytes": 2 * GIB,
    "startFreeDiskBytes": 8 * GIB,
    "runtimeFreeDiskBytes": 2 * GIB,
    "sampleIntervalSeconds": INTERVAL,
    "durationLimitSeconds": DURATION,
    "enforcement": "docker-cgroup-cap-and-job-timeout; telemetry-refuses-export-at-finish",
    "budgetBasis": "engineering margins; 8 GiB disk rounds prior OCI/load/image plus 2 GiB reserve; cold peak unknown",
}
SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}\Z")


class Refusal(Exception):
    """Only fixed metadata codes may reach logs; subprocess stderr stays private."""


def require(condition, code):
    if not condition:
        raise Refusal(code)


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def read(path):
    try:
        return Path(path).read_text()
    except (OSError, UnicodeError):
        raise Refusal("metadata.unreadable") from None


def command_json(args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=COMMAND_TIMEOUT, check=False)
        require(result.returncode == 0, "docker.metadata_command_failed")
        return json.loads(result.stdout)
    except (OSError, subprocess.TimeoutExpired, ValueError):
        raise Refusal("docker.metadata_unavailable") from None


def private_state(path):
    path = Path(path).absolute()
    require(not path.is_symlink() and path.is_dir(), "state.not_private_directory")
    info = path.stat()
    require(info.st_uid == os.getuid() and info.st_mode & 0o077 == 0, "state.not_private_directory")
    return path


def load(path):
    path = Path(path)
    require(not path.is_symlink() and path.is_file(), "state.file_missing_or_symlink")
    try:
        return json.loads(read(path))
    except ValueError:
        raise Refusal("state.invalid_json") from None


def save(path, value):
    path = Path(path)
    require(not path.is_symlink(), "state.symlink")
    temp = path.with_name(path.name + ".new")
    descriptor = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as out:
        json.dump(value, out, sort_keys=True)
        out.write("\n")
    os.replace(temp, path)


def key_values(value):
    result = {}
    for line in value.splitlines():
        fields = line.split()
        require(len(fields) == 2 and fields[0] not in result, "metadata.invalid_counters")
        result[fields[0]] = int(fields[1])
        require(result[fields[0]] >= 0, "metadata.invalid_counters")
    return result


def pressure(value):
    result = {}
    for line in value.splitlines():
        fields = line.split()
        require(fields and fields[0] in ("some", "full"), "metadata.invalid_pressure")
        row = dict(item.split("=", 1) for item in fields[1:])
        require(set(row) == {"avg10", "avg60", "avg300", "total"}, "metadata.invalid_pressure")
        result[fields[0]] = {key: float(val) for key, val in row.items()}
        require(all(math.isfinite(v) and v >= 0 for v in result[fields[0]].values()), "metadata.invalid_pressure")
    require("some" in result, "metadata.invalid_pressure")
    return result


def io_totals(value):
    totals = {key: 0 for key in ("rbytes", "wbytes", "rios", "wios", "dbytes", "dios")}
    for line in value.splitlines():
        fields = line.split()
        require(bool(re.fullmatch(r"\d+:\d+", fields[0])), "metadata.invalid_io")
        for field in fields[1:]:
            key, val = field.split("=", 1)
            if key in totals:
                require(int(val) >= 0, "metadata.invalid_io")
                totals[key] += int(val)
    return totals


def local_node(builder, nodes):
    require(bool(NAME.fullmatch(builder)), "builder.invalid_name")
    require(isinstance(nodes, list) and len(nodes) == 1, "builder.requires_one_node")
    node = nodes[0]
    require(isinstance(node, dict) and bool(NAME.fullmatch(node.get("name", ""))), "builder.invalid_node")
    require(node.get("status") == "running", "builder.node_not_running")
    require(node.get("endpoint") in ("unix:///var/run/docker.sock", "default"), "builder.nonlocal_endpoint")
    # Node metadata comes directly from this exact setup-buildx action output.
    return "buildx_buildkit_" + node["name"]


def inspect_worker(container, expected=None):
    value = command_json(["docker", "--host", "unix:///var/run/docker.sock", "inspect", "--type", "container", container])
    require(isinstance(value, list) and len(value) == 1, "worker.inspect_shape")
    value = value[0]
    identity = value.get("Id", "")
    require(bool(re.fullmatch(r"[0-9a-f]{64}", identity)), "worker.invalid_id")
    require(value.get("Name") == "/" + container, "worker.name_changed")
    require(expected is None or identity == expected, "worker.identity_changed")
    state = value.get("State", {})
    require(state.get("Running") is True and isinstance(state.get("Pid"), int) and state["Pid"] > 0, "worker.not_running")
    require(not state.get("OOMKilled", False), "worker.oom_killed")
    config = value.get("HostConfig", {})
    for key, required in (("Memory", 8 * GIB), ("MemorySwap", 8 * GIB), ("CpuPeriod", 100000), ("CpuQuota", 400000)):
        require(config.get(key) == required, "worker.hostconfig_" + key.lower())
    require(config.get("NanoCpus", 0) == 0, "worker.conflicting_cpu_limit")
    require(config.get("CgroupnsMode") == "private", "worker.cgroup_namespace_not_private")
    return {"id": identity, "pid": state["Pid"]}


def cgroup_path(pid, proc=Path("/proc")):
    require(isinstance(pid, int) and pid > 0, "worker.invalid_pid")
    rows = read(proc / str(pid) / "cgroup").splitlines()
    unified = [row[3:] for row in rows if row.startswith("0::")]
    require(len(unified) == 1 and unified[0].startswith("/") and ".." not in Path(unified[0]).parts, "cgroup.unified_path_unavailable")
    mounts = []
    for row in read(proc / "self/mountinfo").splitlines():
        before, separator, after = row.partition(" - ")
        if separator and after.split()[0] == "cgroup2":
            fields = before.split()
            require(fields[3] == "/" and "\\" not in fields[4], "cgroup.hidden_ancestors")
            mounts.append(Path(fields[4]))
    require(len(mounts) == 1, "cgroup.requires_complete_v2_mount")
    root = mounts[0]
    path = root / unified[0].lstrip("/")
    require(path != root and path.resolve() == path, "cgroup.invalid_worker_path")
    return root, path


def finite_limit(value):
    value = value.strip()
    if value == "max":
        return None
    limit = int(value)
    require(limit >= 0, "cgroup.invalid_limit")
    return limit


def cgroup_bounds(root, path):
    rows = []
    current = path
    while current != root:
        require(root in current.parents, "cgroup.invalid_ancestry")
        memory = finite_limit(read(current / "memory.max"))
        swap = finite_limit(read(current / "memory.swap.max"))
        cpu = read(current / "cpu.max").split()
        require(len(cpu) == 2 and int(cpu[1]) > 0, "cgroup.invalid_cpu_limit")
        quota = finite_limit(cpu[0])
        rows.append({"memoryMaxBytes": memory, "swapMaxBytes": swap, "cpuCores": None if quota is None else quota / int(cpu[1])})
        current = current.parent
    # The cgroup v2 root has no resource limits; all visible ancestors above the
    # worker have been considered. Child 'max' cannot erase a parent's limit.
    effective = {}
    for key in ("memoryMaxBytes", "swapMaxBytes", "cpuCores"):
        finite = [row[key] for row in rows if row[key] is not None]
        effective[key] = min(finite) if finite else None
    require(effective == {"memoryMaxBytes": 8 * GIB, "swapMaxBytes": 0, "cpuCores": 4.0}, "cgroup.effective_profile_mismatch")
    return {"effective": effective, "ancestors": rows}


def sample(contract, initial=False):
    worker = inspect_worker(contract["containerName"], contract.get("builderId"))
    root, path = cgroup_path(worker["pid"])
    if "cgroupPath" in contract:
        require(str(path) == contract["cgroupPath"] and worker["pid"] == contract["workerPid"], "worker.execution_changed")
    bounds = cgroup_bounds(root, path)
    meminfo = {}
    for line in read("/proc/meminfo").splitlines():
        key, _, value = line.partition(":")
        if key in ("MemTotal", "MemAvailable"):
            fields = value.split()
            require(len(fields) == 2 and fields[1] == "kB", "host.invalid_meminfo")
            meminfo[key] = int(fields[0]) * 1024
    require(set(meminfo) == {"MemTotal", "MemAvailable"}, "host.missing_meminfo")
    filesystems = {}
    for label, location in (("root", "/"), ("tmp", "/tmp")):
        stat = os.statvfs(location)
        filesystems[label] = {"totalBytes": stat.f_blocks * stat.f_frsize, "freeBytes": stat.f_bavail * stat.f_frsize}
    events = key_values(read(path / "memory.events"))
    require({"oom", "oom_kill", "max", "high"}.issubset(events), "cgroup.missing_memory_events")
    stats = key_values(read(path / "memory.stat"))
    require({"anon", "file"}.issubset(stats), "cgroup.missing_memory_stat")
    row = {
        "observedAt": utc(), "availableMemoryBytes": meminfo["MemAvailable"], "totalMemoryBytes": meminfo["MemTotal"],
        "filesystems": filesystems, "memoryPressure": pressure(read("/proc/pressure/memory")),
        "cpuPressure": pressure(read("/proc/pressure/cpu")), "ioPressure": pressure(read("/proc/pressure/io")),
        "memoryCurrentBytes": int(read(path / "memory.current")), "cgroupLifetimeMemoryPeakBytes": int(read(path / "memory.peak")),
        "memoryStat": {key: stats[key] for key in ("anon", "file")}, "memoryEvents": events,
        "cpuStat": key_values(read(path / "cpu.stat")), "ioStat": io_totals(read(path / "io.stat")), "bounds": bounds,
    }
    require(all(row[key] >= 0 for key in ("memoryCurrentBytes", "cgroupLifetimeMemoryPeakBytes")), "cgroup.invalid_usage")
    if initial:
        contract.update(builderId=worker["id"], workerPid=worker["pid"], cgroupPath=str(path))
    return row


def violations(row, first, initial=False):
    problems = []
    memory_floor = PROFILE["startAvailableMemoryBytes" if initial else "runtimeAvailableMemoryBytes"]
    disk_floor = PROFILE["startFreeDiskBytes" if initial else "runtimeFreeDiskBytes"]
    if row["availableMemoryBytes"] < memory_floor:
        problems.append("host.available_memory_below_floor")
    for label, fs in row["filesystems"].items():
        if fs["freeBytes"] < disk_floor:
            problems.append("host." + label + "_disk_below_floor")
    for key in ("oom", "oom_kill", "oom_group_kill"):
        current = row["memoryEvents"].get(key, 0)
        baseline = first["memoryEvents"].get(key, 0)
        if current < baseline:
            problems.append("worker.event_counters_reset")
        elif current > baseline:
            problems.append("worker." + key + "_increased")
    return problems


def process_identity(pid):
    value = read(Path("/proc") / str(pid) / "stat")
    # comm may contain spaces or parentheses; fields after its last ')' start at 3.
    fields = value.rsplit(")", 1)[1].split()
    return {"pid": pid, "startTicks": int(fields[19])}


def settled_collector(identity):
    path = Path("/proc") / str(identity["pid"]) / "stat"
    try:
        value = path.read_text()
    except FileNotFoundError:
        return True
    except (OSError, UnicodeError):
        raise Refusal("collector.settlement_unreadable") from None
    fields = value.rsplit(")", 1)[1].split()
    require(int(fields[19]) == identity["startTicks"], "collector.process_replaced")
    return fields[0] == "Z"


def aggregate(rows):
    first, last = rows[0], rows[-1]
    return {
        "sampleCount": len(rows), "first": first, "last": last,
        "sampledMemoryCurrentMaxBytes": max(row["memoryCurrentBytes"] for row in rows),
        "cgroupLifetimeMemoryPeakBytes": max(row["cgroupLifetimeMemoryPeakBytes"] for row in rows),
        "cgroupLifetimeMemoryPeakAtStartBytes": first["cgroupLifetimeMemoryPeakBytes"],
        "minimumAvailableMemoryBytes": min(row["availableMemoryBytes"] for row in rows),
        "minimumFreeDiskBytes": {label: min(row["filesystems"][label]["freeBytes"] for row in rows) for label in first["filesystems"]},
        "memoryEventDeltas": {key: last["memoryEvents"].get(key, 0) - val for key, val in first["memoryEvents"].items()},
        "cpuStatDeltas": {key: last["cpuStat"].get(key, 0) - val for key, val in first["cpuStat"].items()},
        "ioStatDeltas": {key: last["ioStat"].get(key, 0) - val for key, val in first["ioStat"].items()},
        "memoryPressureSomeAvg10Max": max(row["memoryPressure"]["some"]["avg10"] for row in rows),
    }


def collect(state, sampler=sample, clock=time.monotonic, sleep=time.sleep):
    state = private_state(state)
    contract = load(state / "contract.json")
    identity = process_identity(os.getpid())
    save(state / "collector.json", {**identity, "token": contract["token"]})
    rows = [contract["firstSample"]]
    problems = []
    began = clock()
    reason = "deadline"
    try:
        while clock() - began < DURATION:
            stopping = (state / "stop.json").exists()
            if stopping:
                require(load(state / "stop.json") == {"token": contract["token"]}, "collector.stop_identity_changed")
            row = sampler(contract)
            rows.append(row)
            problems.extend(violations(row, rows[0]))
            with (state / "samples.jsonl").open("a") as out:
                out.write(json.dumps(row, sort_keys=True) + "\n")
            if stopping:
                reason = "finished"
                break
            sleep(INTERVAL)
        if reason != "finished":
            problems.append("collector.deadline_reached")
    except (Refusal, OSError, ValueError, KeyError, IndexError, TypeError) as exc:
        problems.append(str(exc) if isinstance(exc, Refusal) else "collector.metadata_failed")
        reason = "failed"
    save(state / "completed.json", {
        "token": contract["token"], "collector": identity, "endedAt": utc(), "reason": reason,
        "measurements": aggregate(rows), "violations": sorted(set(problems)),
    })


def start(args):
    require(bool(SHA.fullmatch(args.source_sha)) and bool(SHA.fullmatch(args.tooling_sha)), "identity.requires_full_commit")
    require(platform.system() == "Linux" and platform.machine() == "x86_64", "host.requires_linux_amd64")
    os_release = dict(line.split("=", 1) for line in read("/etc/os-release").splitlines() if "=" in line)
    require(os_release.get("ID", "").strip('"') == "ubuntu" and os_release.get("VERSION_ID", "").strip('"') == "24.04", "host.requires_ubuntu_24_04")
    require(args.driver == "docker-container", "builder.requires_docker_container_driver")
    contract = {"token": uuid.uuid4().hex, "sourceSha": args.source_sha, "toolingSha": args.tooling_sha,
                "builderName": args.builder, "containerName": local_node(args.builder, load(args.nodes_json)), "startedAt": utc()}
    first = sample(contract, initial=True)
    problems = violations(first, first, initial=True)
    require(not problems, ";".join(problems))
    state = Path(args.state_dir).absolute()
    require(not state.exists() and not state.is_symlink(), "state.already_exists")
    state.mkdir(mode=0o700)
    contract["firstSample"] = first
    save(state / "contract.json", contract)
    child = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "_collect", "--state-dir", str(state)],
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    deadline = time.monotonic() + COMMAND_TIMEOUT
    while not (state / "collector.json").exists() and child.poll() is None and time.monotonic() < deadline:
        time.sleep(0.1)
    require((state / "collector.json").exists(), "collector.start_unconfirmed")
    identity = load(state / "collector.json")
    require(identity["pid"] == child.pid and identity["token"] == contract["token"] and process_identity(child.pid) == {key: identity[key] for key in ("pid", "startTicks")}, "collector.start_identity_mismatch")
    return {"status": "collecting", "builderId": contract["builderId"], "sourceSha": args.source_sha, "toolingSha": args.tooling_sha, "startedAt": contract["startedAt"], "profile": PROFILE}


def finish(args):
    state = private_state(args.state_dir)
    contract = load(state / "contract.json")
    collector = load(state / "collector.json")
    require(collector["token"] == contract["token"], "collector.identity_mismatch")
    completed_path = state / "completed.json"
    if not completed_path.exists():
        require(process_identity(collector["pid"]) == {key: collector[key] for key in ("pid", "startTicks")}, "collector.process_replaced")
        if not (state / "stop.json").exists():
            save(state / "stop.json", {"token": contract["token"]})
        deadline = time.monotonic() + COMMAND_TIMEOUT * 3 + INTERVAL
        while not completed_path.exists() and time.monotonic() < deadline:
            time.sleep(0.1)
    require(completed_path.exists(), "collector.finish_unconfirmed")
    done = load(completed_path)
    require(done["token"] == contract["token"] and done["collector"] == {key: collector[key] for key in ("pid", "startTicks")}, "collector.completed_identity_mismatch")
    identity = {key: collector[key] for key in ("pid", "startTicks")}
    deadline = time.monotonic() + INTERVAL
    while not settled_collector(identity):
        require(time.monotonic() < deadline, "collector.exit_unconfirmed")
        time.sleep(0.1)
    problems = list(done["violations"])
    if done["reason"] != "finished":
        problems.append("collector.not_finished")
    if not DIGEST.fullmatch(args.index_digest or ""):
        problems.append("image.missing_or_invalid_index_digest")
    result = {
        "schema": "openclaw.hosted-resources.v1", "status": "failed" if problems else "passed",
        "sourceSha": contract["sourceSha"], "toolingSha": contract["toolingSha"], "builderId": contract["builderId"],
        "startedAt": contract["startedAt"], "endedAt": done["endedAt"], "profile": PROFILE,
        "indexDigest": args.index_digest if DIGEST.fullmatch(args.index_digest or "") else None,
        "measurements": done["measurements"], "violations": sorted(set(problems)),
    }
    output = Path(args.output).absolute()
    require(state != output and state not in output.parents, "output.must_be_outside_private_state")
    final_path = state / "final.json"
    if final_path.exists():
        require(load(final_path) == result, "collector.final_binding_changed")
    else:
        save(final_path, result)
    if output.exists():
        require(load(output) == result, "output.already_exists_with_different_result")
    else:
        save(output, result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    begin = sub.add_parser("start")
    for argument in ("builder", "driver", "nodes-json", "state-dir", "source-sha", "tooling-sha"):
        begin.add_argument("--" + argument, required=True)
    end = sub.add_parser("finish")
    end.add_argument("--state-dir", required=True)
    end.add_argument("--output", required=True)
    end.add_argument("--index-digest", default="")
    worker = sub.add_parser("_collect", help=argparse.SUPPRESS)
    worker.add_argument("--state-dir", required=True)
    args = parser.parse_args()
    try:
        if args.command == "_collect":
            collect(args.state_dir)
            return 0
        result = start(args) if args.command == "start" else finish(args)
        print(json.dumps(result, sort_keys=True))
        return 1 if result["status"] == "failed" else 0
    except (Refusal, OSError, ValueError, KeyError, IndexError, TypeError) as exc:
        print(json.dumps({"status": "failed", "violations": [str(exc) if isinstance(exc, Refusal) else "metadata.unavailable_or_invalid"]}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
