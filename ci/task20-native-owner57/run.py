"""Run once on the dedicated public GitHub VM, never on a live Gateway host."""
import argparse
import datetime
import json
from pathlib import Path
import shutil
import signal
import subprocess
import time

HERE = Path(__file__).resolve().parent
M = json.loads((HERE / "manifest.json").read_text())
IMAGE = "node@" + M["officialNodeImage"]["linuxAmd64Manifest"]["digest"]
RUN_DEADLINE = None
PAYLOAD_DEADLINE = None


def command(argv, timeout=10):
    now = time.monotonic()
    remaining = [deadline - now for deadline in [RUN_DEADLINE, PAYLOAD_DEADLINE] if deadline is not None]
    if remaining:
        timeout = min(timeout, min(remaining))
    if timeout <= 0:
        raise RuntimeError("owned job command deadline reached")
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError("command failed: " + argv[0] + ": " + result.stderr[-2000:])
    # Docker preserves container stderr separately; retain both diagnostic streams.
    return result.stdout + result.stderr if argv[:2] == ["docker", "logs"] else result.stdout


def admission():
    mem = dict(line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
    vm = dict(line.split() for line in Path("/proc/vmstat").read_text().splitlines())
    pressure = {}
    for line in Path("/proc/pressure/memory").read_text().splitlines():
        words = line.split()
        pressure[words[0]] = float(dict(word.split("=") for word in words[1:])["avg10"])
    return {"utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "availableBytes": int(mem["MemAvailable"].split()[0]) * 1024,
            "swapFreeBytes": int(mem["SwapFree"].split()[0]) * 1024,
            "oomKills": int(vm["oom_kill"]), "memoryPsiAvg10": pressure}


def require_admission(samples):
    if any(x["availableBytes"] < M["budgets"]["minimumHostAvailableBytes"] or
           max(x["memoryPsiAvg10"].values()) >= 2 for x in samples):
        raise RuntimeError("host memory/PSI admission refused")
    if len({x["oomKills"] for x in samples}) != 1 or samples[-1]["swapFreeBytes"] < samples[0]["swapFreeBytes"]:
        raise RuntimeError("host OOM/swap admission refused")


def cgroup(pid):
    rows = Path(f"/proc/{pid}/cgroup").read_text().splitlines()
    if len(rows) != 1 or not rows[0].startswith("0::/"):
        raise RuntimeError("unified job cgroup unavailable")
    path = Path("/sys/fs/cgroup") / rows[0][3:].lstrip("/")
    path = path.resolve(strict=True)
    if path == Path("/sys/fs/cgroup") or not path.is_relative_to("/sys/fs/cgroup"):
        raise RuntimeError("invalid job cgroup")
    return path


def counters(group):
    cpu = dict(line.split() for line in (group / "cpu.stat").read_text().splitlines())
    events = dict(line.split() for line in (group / "memory.events").read_text().splitlines())
    rss = 0
    group_name = str(group).removeprefix("/sys/fs/cgroup")
    for pid in (group / "cgroup.procs").read_text().splitlines():
        try:
            member = Path(f"/proc/{pid}/cgroup").read_text().strip()
            if member != "0::" + group_name:
                continue
            values = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines() if ":" in line)
            if Path(f"/proc/{pid}/cgroup").read_text().strip() == member:
                rss += int(values.get("VmRSS", "0 kB").split()[0]) * 1024
        except FileNotFoundError:
            pass
    return {"cpuSeconds": int(cpu["usage_usec"]) / 1e6,
            "peakMemoryBytes": int((group / "memory.peak").read_text()),
            "aggregateRssBytes": rss,
            "oom": int(events["oom"]), "oomKill": int(events["oom_kill"])}


def run(work, output, run_id):
    global RUN_DEADLINE, PAYLOAD_DEADLINE
    RUN_DEADLINE = time.monotonic() + 280
    if output.exists():
        raise RuntimeError("output must be new")
    output.mkdir()
    receipt = {"status": "NOT_ACCEPTED", "sourceCommit": M["nativeCommit"],
               "sourceTree": M["nativeTree"], "sourceMapRevision": M["sourceMapRevision"], "image": IMAGE, "runId": run_id,
               "nativeWorkerHeapOverride": None, "fullT06Accepted": False,
               "all13CompleteGatesOpen": True, "fixtureStarted": False}
    container = None
    attachment = None
    last = None
    component_validated = False
    try:
        # This is the standard Docker daemon of the disposable GitHub VM only.
        command(["docker", "pull", "--platform=linux/amd64", IMAGE], timeout=120)
        image = json.loads(command(["docker", "image", "inspect", IMAGE]))[0]
        if image["Architecture"] != "amd64" or image["Os"] != "linux" or image["Size"] > 512 * 1024**2:
            raise RuntimeError("runtime image footprint/platform refused")
        receipt["runtimeImage"] = {"id": image["Id"], "repoDigests": image["RepoDigests"], "size": image["Size"]}
        samples = []
        for _ in range(3):
            samples.append(admission())
            if len(samples) < 3:
                time.sleep(1)
        receipt["admission"] = samples
        require_admission(samples)
        tsx = "/work/" + M["tsxPackageRoot"] + "/dist/loader.mjs"
        argv = ["docker", "create", "--interactive", "--platform=linux/amd64", "--network=none", "--read-only",
                "--user=1000:1000", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                "--memory=1g", "--memory-swap=1g", "--cpus=1", "--pids-limit=128",
                "--ulimit=core=0", "--log-driver=local", "--log-opt=max-size=1m", "--log-opt=max-file=1",
                "--log-opt=compress=false",
                "--label=task20.native-owner57=" + run_id,
                "--mount=type=bind,src=" + str(work) + ",dst=/work,readonly",
                "--mount=type=bind,src=" + str(HERE / "entry.mjs") + ",dst=/entry.mjs,readonly",
                "--mount=type=bind,src=" + str(HERE / "watchdog.mjs") + ",dst=/watchdog.mjs,readonly",
                "--mount=type=bind,src=" + str(work / "control/sealed-empty") + ",dst=/dev/shm,readonly",
                "--mount=type=bind,src=" + str(work / "control/sealed-empty") + ",dst=/dev/mqueue,readonly",
                "--tmpfs=/fixture:rw,nosuid,nodev,noexec,size=16m,uid=1000,gid=1000,mode=0700",
                "--env=HOME=/fixture", "--env=TMPDIR=/fixture", "--env=LANG=C.UTF-8",
                "--env=TSX_TSCONFIG_PATH=/work/source/tsconfig.json",
                "--env=TSX_DISABLE_CACHE=1", "--env=OPENCLAW_STATE_DIR=/fixture",
                "--env=OPENCLAW_CONFIG_PATH=/fixture/openclaw.json",
                "--workdir=/work/source", "--entrypoint=/usr/bin/timeout", IMAGE,
                "--signal=TERM", "--kill-after=1s", "119s", "/usr/local/bin/node", "/watchdog.mjs",
                "--import", tsx, "/entry.mjs"]
        receipt["argv"] = argv
        container = command(argv).strip()
        if len(container) != 64 or any(c not in "0123456789abcdef" for c in container):
            raise RuntimeError("invalid owned container identity")
        before = json.loads(command(["docker", "inspect", container]))[0]
        config = before["HostConfig"]
        if (config["NetworkMode"] != "none" or config["Memory"] != 1024**3 or
            config["MemorySwap"] != 1024**3 or config["PidsLimit"] != 128 or
            not config["ReadonlyRootfs"] or config["Privileged"] or config["CapAdd"] or
            config["CapDrop"] != ["ALL"] or config["NanoCpus"] != 1000000000 or
            not any(x.startswith("no-new-privileges") for x in config["SecurityOpt"])):
            raise RuntimeError("container resource/confinement binding changed")
        if config["LogConfig"] != {"Type": "local", "Config": {
                "max-size": "1m", "max-file": "1", "compress": "false"}}:
            raise RuntimeError("container bounded logging configuration changed")
        mounts = {x["Destination"]: x for x in before["Mounts"] if x["Type"] == "bind"}
        expected_mounts = {"/work": str(work), "/entry.mjs": str(HERE / "entry.mjs"),
                           "/watchdog.mjs": str(HERE / "watchdog.mjs"),
                           "/dev/shm": str(work / "control/sealed-empty"),
                           "/dev/mqueue": str(work / "control/sealed-empty")}
        if set(mounts) != set(expected_mounts) or any(mounts[target]["RW"] or
                mounts[target]["Source"] != source for target, source in expected_mounts.items()):
            raise RuntimeError("container sealed mount binding changed")
        if set(config["Tmpfs"]) != {"/fixture"} or any(x["Type"] != "bind" and
                (x["Type"] != "tmpfs" or x["Destination"] != "/fixture") for x in before["Mounts"]):
            raise RuntimeError("unexpected writable container mount")
        if before["Config"]["User"] != "1000:1000" or any("NODE_OPTIONS=" in x for x in before["Config"]["Env"]):
            raise RuntimeError("container runtime binding changed")
        actual_env = dict(item.split("=",1) for item in before["Config"]["Env"])
        if any(actual_env.get(key) != value for key,value in M["runtimeEnvironment"].items()):
            raise RuntimeError("exact fixture environment binding changed")
        receipt["preGoHostConfig"] = {key: config[key] for key in ["NetworkMode","Memory","MemorySwap","PidsLimit","ReadonlyRootfs","Privileged","CapAdd","CapDrop","NanoCpus","SecurityOpt","LogConfig","Tmpfs"]}
        started = time.monotonic()
        PAYLOAD_DEADLINE = started + 120
        attachment = subprocess.Popen(["docker", "start", "--attach", "--interactive", container],
                                      stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # PID1 is waiting for GO; no migration import or database open has happened.
        for _ in range(30):
            running = json.loads(command(["docker", "inspect", container]))[0]
            if running["State"]["Running"]:
                break
            time.sleep(0.05)
        else:
            raise RuntimeError("container did not reach pre-GO entry")
        running = json.loads(command(["docker", "inspect", container]))[0]
        group = cgroup(running["State"]["Pid"])
        if int((group / "memory.max").read_text()) != 1024**3 or int((group / "memory.swap.max").read_text()) != 0:
            raise RuntimeError("kernel memory/swap confinement not installed")
        receipt["ownedCgroup"] = str(group)
        receipt["preGoKernelLimits"] = {name:(group/name).read_text().strip() for name in ["memory.max","memory.swap.max","pids.max","cpu.max"]}
        for _ in range(50):
            prego_logs = command(["docker", "logs", container])
            if any(x.startswith("TASK20_READY ") for x in prego_logs.splitlines()):
                break
            time.sleep(0.05)
        else:
            raise RuntimeError("kernel confinement attestation missing before GO")
        ready = [json.loads(x.removeprefix("TASK20_READY ")) for x in prego_logs.splitlines() if x.startswith("TASK20_READY ")]
        runtime = [json.loads(x.removeprefix("TASK20_RUNTIME ")) for x in prego_logs.splitlines() if x.startswith("TASK20_RUNTIME ")]
        confinement = [json.loads(x.removeprefix("TASK20_CONFINEMENT ")) for x in prego_logs.splitlines() if x.startswith("TASK20_CONFINEMENT ")]
        if len(ready) != 1 or ready[0]["phase"] != "ADMISSION_WAIT_NATIVE_OWNER_NOT_IMPORTED" or len(runtime) != 1 or len(confinement) != 1:
            raise RuntimeError("exact trusted runtime/confinement READY missing")
        if runtime[0]["version"] != "v24.19.0" or runtime[0]["uid"] != 1000 or runtime[0]["gid"] != 1000 or runtime[0]["nodeOptions"] is not None:
            raise RuntimeError("runtime READY binding mismatch")
        receipt["preGoRuntime"] = runtime[0]
        receipt["preGoConfinement"] = confinement[0]
        receipt["preGoReady"] = ready[0]
        require_admission([samples[0], admission()])
        # A failed write/flush cannot prove that GO was not delivered.
        receipt["sourceImportsStarted"] = True
        receipt["goDelivery"] = "ATTEMPTED_UNCONFIRMED"
        attachment.stdin.write(b"TASK20_GO\n")
        attachment.stdin.flush()
        receipt["goDelivery"] = "WRITE_AND_FLUSH_COMPLETED"
        close_sent = False
        actor_sent = False
        rss_peak = 0
        while True:
            try:
                last = counters(group)
                rss_peak = max(rss_peak, last["aggregateRssBytes"])
            except FileNotFoundError:
                pass  # Docker may remove the stopped container's cgroup; final state is required below.
            state = json.loads(command(["docker", "inspect", container]))[0]["State"]
            if not state["Running"]:
                break
            elapsed = time.monotonic() - started
            if elapsed >= M["budgets"]["fixtureWallSeconds"] or (last and last["cpuSeconds"] >= 30) or rss_peak > 1024**3:
                raise RuntimeError("fixture wall/aggregate CPU budget exceeded")
            current = admission()
            require_admission([samples[0], current])
            if not close_sent:
                logs = command(["docker", "logs", container])
                if len(logs.encode()) > 1024**2:
                    raise RuntimeError("fixture log bound exceeded")
                binding_ready = [json.loads(x.removeprefix("TASK20_BINDINGS_READY ")) for x in logs.splitlines() if x.startswith("TASK20_BINDINGS_READY ")]
                if binding_ready and not actor_sent:
                    if len(binding_ready) != 1 or binding_ready[0] != {"sourceMapRevision": M["sourceMapRevision"], "phase": "OPERATION_BINDINGS_VERIFIED_DATABASE_FIXTURE_NOT_INVOKED"}:
                        raise RuntimeError("exact operation binding READY mismatch")
                    fresh = []
                    for _ in range(3):
                        fresh.append(admission())
                        require_admission([samples[0], *fresh])
                        active = counters(group)
                        if time.monotonic() - started >= 120 or active["cpuSeconds"] >= 30 or active["oom"] or active["oomKill"]:
                            raise RuntimeError("binding phase resource boundary refused")
                        if len(fresh) < 3:
                            time.sleep(1)
                    receipt["actorAdmission"] = fresh
                    receipt["actorGoDelivery"] = "ATTEMPTED_UNCONFIRMED"
                    receipt["fixtureStarted"] = True
                    attachment.stdin.write(b"TASK20_ACTOR_GO\n")
                    attachment.stdin.flush()
                    receipt["actorGoDelivery"] = "WRITE_AND_FLUSH_COMPLETED"
                    actor_sent = True
                if any(x.startswith("TASK20_FINAL_COUNTERS ") for x in logs.splitlines()):
                    if not actor_sent:
                        raise RuntimeError("fixture completion without fresh actor admission")
                    attachment.stdin.write(b"TASK20_CLOSE\n")
                    attachment.stdin.flush()
                    close_sent = True
            time.sleep(0.1)
        receipt["wallSeconds"] = time.monotonic() - started
        receipt["lastKernelCounters"] = last
        receipt["peakObservedAggregateRssBytes"] = rss_peak
        receipt["finalState"] = state
        if state["ExitCode"] != 0 or state["OOMKilled"] or last is None or last["oom"] or last["oomKill"]:
            raise RuntimeError("fixture did not exit normally within admitted resources")
        if last["cpuSeconds"] > 30 or last["peakMemoryBytes"] > 1024**3 or receipt["wallSeconds"] > 120:
            raise RuntimeError("fixture resource budget exceeded")
        logs = command(["docker", "logs", container])
        if len(logs.encode()) > 1024**2:
            raise RuntimeError("fixture log bound exceeded")
        (output / "fixture.stdout").write_text(logs)
        results = [json.loads(x.removeprefix("TASK20_COMPONENT ")) for x in logs.splitlines() if x.startswith("TASK20_COMPONENT ")]
        runtimes = [json.loads(x.removeprefix("TASK20_RUNTIME ")) for x in logs.splitlines() if x.startswith("TASK20_RUNTIME ")]
        completed = [json.loads(x.removeprefix("TASK20_FINAL_COUNTERS ")) for x in logs.splitlines() if x.startswith("TASK20_FINAL_COUNTERS ")]
        if len(results) != 1 or len(runtimes) != 1 or len(completed) != 1 or not close_sent or not actor_sent:
            raise RuntimeError("missing or duplicate exact component/runtime result")
        if completed[0]["cpuSeconds"] > 30 or completed[0]["peakMemoryBytes"] > 1024**3 or completed[0]["oom"] or completed[0]["oomKill"] or completed[0]["fixtureUsedBytes"] > 16 * 1024**2:
            raise RuntimeError("terminal native component resource budget exceeded")
        receipt["nativeComponentCompletionCounters"] = completed[0]
        result = results[0]
        if result["status"] != "ACTUAL_NATIVE_RECEIPT_CONSUMER_COMPONENT_ONLY":
            raise RuntimeError("component status mismatch")
        if result["checks"] != M["expectedScope"]["orderedCheckNames"]:
            raise RuntimeError("exact original actor receipt assertion mismatch")
        if any(result.get(key) != value for key, value in M["expectedScope"]["acceptanceFlags"].items()):
            raise RuntimeError("component scope flags mismatch")
        bindings = [json.loads(x.removeprefix("TASK20_SOURCE_BINDINGS ")) for x in logs.splitlines() if x.startswith("TASK20_SOURCE_BINDINGS ")]
        if len(bindings) != 1 or bindings[0]["sourceMapRevision"] != M["sourceMapRevision"] or bindings[0]["ownerPostimages"] != 57 or bindings[0]["eagerSourceFiles"] != len(M["sourceGraphFiles"]) or bindings[0]["originalEntryExports"] != 10:
            raise RuntimeError("exact original source/export binding evidence missing")
        if len(bindings[0]["packageExportBindings"]) != len(M["sourceBareBindings"]) or bindings[0]["publishedOrCompiledGraphQualified"] is not False or bindings[0]["privateIssuerQualified"] is not False:
            raise RuntimeError("source export scope mismatch")
        if bindings[0].get("operationClosureBound") is not True or bindings[0].get("requiredOperationClosure") != M["requiredOperationClosure"] or len(bindings[0].get("sourceAliasBindings", [])) != len(M["sourceAliases"]) or bindings[0].get("resolverProbeDirectoriesVerified") != len(M["resolverProbeDirectories"]):
            raise RuntimeError("required native source/alias/worker operation binding incomplete")
        for actual, expected in zip(bindings[0]["packageExportBindings"], M["sourceBareBindings"]):
            target = expected["expected"]
            if actual != {"specifier": expected["specifier"], "parent": expected["parent"], "target": target["target"], "sha256": target["sha256"], "snapshot": target["snapshot"], "integrity": target["integrity"], "packageJsonSha256": target["packageJsonSha256"], "peerLinksVerified": len(target["peerLinks"])}:
                raise RuntimeError("exact package/export/peer runtime binding mismatch")
        receipt["sourceBindings"] = bindings[0]
        receipt["runtime"] = runtimes[0]
        receipt["componentResult"] = result
        component_validated = True
    except Exception as error:
        receipt["status"] = "NOT_ACCEPTED"
        component_validated = False
        receipt["error"] = type(error).__name__ + ": " + str(error)
    finally:
        PAYLOAD_DEADLINE = None
        RUN_DEADLINE = time.monotonic() + 30
        if container:
            try:
                final = json.loads(command(["docker", "inspect", container]))[0]
                if final["Config"]["Labels"].get("task20.native-owner57") != run_id:
                    raise RuntimeError("cleanup owner mismatch")
                if final["State"]["Running"]:
                    receipt["status"] = "NOT_ACCEPTED"
                    component_validated = False
                    receipt["budgetFailureStop"] = True
                    receipt["normalDrainAccepted"] = False
                    if attachment:
                        attachment.stdin.close()  # Refuse pending GO/CLOSE and allow normal handle cleanup first.
                    command(["docker", "stop", "--time=1", container])
                    final = json.loads(command(["docker", "inspect", container]))[0]
                if final["State"]["Running"] or final["State"]["ExitCode"] != 0 or final["State"]["OOMKilled"]:
                    receipt["status"] = "NOT_ACCEPTED"
                    component_validated = False
                    receipt["cleanupExitError"] = "cleanup did not confirm normal exited state"
                logs = command(["docker", "logs", container])
                if len(logs.encode()) <= 1024**2:
                    (output / "fixture.stdout").write_text(logs)
                else:
                    raise RuntimeError("cleanup log bound exceeded")
                receipt["cleanupFinalState"] = final["State"]
                command(["docker", "rm", container])
                receipt["ownedContainerRemoved"] = True
            except Exception as error:
                receipt["cleanupError"] = str(error)
                receipt["status"] = "NOT_ACCEPTED"
        if attachment:
            try:
                attachment.stdin.close()
                attachment.wait(timeout=10)
                receipt["attachmentReturncode"] = attachment.returncode
                if attachment.returncode != 0:
                    raise RuntimeError("attachment did not exit normally")
            except Exception as error:
                receipt["attachmentCleanupError"] = str(error)
                receipt["status"] = "NOT_ACCEPTED"
        if (component_validated and receipt.get("ownedContainerRemoved") and
                not any(key in receipt for key in ["error", "cleanupError", "cleanupExitError", "attachmentCleanupError", "budgetFailureStop"])):
            receipt["normalDrainAccepted"] = True
            receipt["status"] = "EXACT57_ORIGINAL_NATIVE_ACTOR_RECEIPT_COMPONENT_PASS"
        (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        shutil.copyfile(work / "control/materialization-receipt.json", output / "materialization-receipt.json")
    if receipt["status"] != "EXACT57_ORIGINAL_NATIVE_ACTOR_RECEIPT_COMPONENT_PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    if not args.run_id.isdigit():
        raise SystemExit("numeric GitHub run ID required")
    def interrupted(signum, frame):
        raise RuntimeError("host observer interrupted by signal " + str(signum))
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    run(args.work.resolve(), args.output.resolve(), args.run_id)
