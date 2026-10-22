#!/usr/bin/env python3
"""One durable GCP build client. No deployment, builder creation, or builder stop.

prepare takes a closed private config plus the existing manifest/inventory/source
bindings. start records an fsynced intent before systemd dispatch. Repeating start
only observes that operation, including after a lost dispatch reply. status prints
native output first and finalizes the existing GCP execution contract only after
systemd and the private child receipt agree on terminal success.

The existing Docker builder owns its solve. Cancelling this service/client does
not prove the daemon-side solve stopped. Operations retain their builder reservation
for owner reconciliation; this module never resets it. The fixed private root
serializes users of this adapter, not other native Docker callers. Those still
require ownership coordination and fresh builder inspection.
"""

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time

import preflight
import pr
import release

DOCKER = ("/usr/bin/sudo", "-n", "/usr/bin/docker")
SYSTEMD_RUN = ("/usr/bin/sudo", "-n", "/usr/bin/systemd-run")
SYSTEMCTL = ("/usr/bin/sudo", "-n", "/usr/bin/systemctl")
CHOWN = ("/usr/bin/sudo", "-n", "/usr/bin/chown")
ENDPOINT = "unix:///var/run/docker.sock"
PRIVATE_ROOT = Path("/var/tmp/openclaw-fork-gcp-build")
CGROUP_SLICE = Path("/sys/fs/cgroup/system.slice")
HEAVY_ROOT = Path("/var/tmp/openclaw-fork-heavy-workload")
TRIAL_ROOT = Path("/var/tmp/openclaw-fork-snapshot-trial")
CLIENT_TERM_GRACE_SECONDS = 5
CLIENT_JOIN_SECONDS = 2
CLIENT_PIPE_DRAIN_SECONDS = 1
HELPERS = ("gcp_build.py", "release.py", "preflight.py", "pr.py")
SAFE_ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"}
# This complete reviewed Dockerfile gives every RUN an explicit network mode:
# only three pre-payload acquisition steps use default; all others use none.
# Review the whole file, including stage/COPY/ENV/SHELL policy, before changing
# this pin. A partial Dockerfile parser cannot establish that boundary.
REVIEWED_DOCKERFILE_SHA256 = "ad0d820a72747bd48c528ea5cad3df03bf213049afc5fc31f83904d98b7b917e"
CONFIG_FIELDS = """schema operationId attempt projectNumber instanceId toolingSha
sourceSha sourceTree manifestSha256 inventorySha256 builtAt builder limits dockerExport"""
BUILD_TUNING_FIELDS = "tsdownMaxOldSpaceMb"
BUILDER_FIELDS = """name node endpoint containerId imageId memoryBytes memorySwapBytes
cpuPeriod cpuQuota cpuShares nanoCpus pidsLimit readBps writeBps"""
LIMIT_FIELDS = """timeoutSeconds clientMemoryBytes clientCpuQuotaPercent clientTasksMax
minFreeBytes minMemoryAvailableBytes"""
CACHE_FIELDS = "volumeName backingPath filesystemDevice minFreeBytes"
INTENT_FIELDS = """schema config sourceDir toolingDir uid gid version preparedAt
supervisorSha256 buildArgv serviceArgv unitName"""
SHOW_FIELDS = ("LoadState", "ActiveState", "SubState", "Result", "ExecMainCode",
               "ExecMainStatus", "MainPID", "InvocationID")
# Buildx v0.33 inspect has no --format. Its ls formatter emits a flat builder
# row followed by node rows; select the exact builder from this narrow JSONL.
BUILDER_FORMAT = ('{"Builder":{{json .Builder.Name}},"Name":{{json .Name}},'
                  '"DriverEndpoint":{{json .DriverEndpoint}},"Status":{{json .Status}}}')
CONTAINER_FORMAT = (
    '{"Id":{{json .Id}},"Image":{{json .Image}},'
    '"State":{"Running":{{json .State.Running}}},"HostConfig":{'
    '"Memory":{{json .HostConfig.Memory}},"MemorySwap":{{json .HostConfig.MemorySwap}},'
    '"CpuPeriod":{{json .HostConfig.CpuPeriod}},"CpuQuota":{{json .HostConfig.CpuQuota}},'
    '"CpuShares":{{json .HostConfig.CpuShares}},"NanoCpus":{{json .HostConfig.NanoCpus}},'
    '"PidsLimit":{{json .HostConfig.PidsLimit}},'
    '"BlkioDeviceReadBps":{{json .HostConfig.BlkioDeviceReadBps}},'
    '"BlkioDeviceWriteBps":{{json .HostConfig.BlkioDeviceWriteBps}}}}')
CACHE_VOLUME_FORMAT = (
    '{"Name":{{json .Name}},"Driver":{{json .Driver}},'
    '"Mountpoint":{{json .Mountpoint}},"Options":{{json .Options}}}')
CACHE_MOUNT_FORMAT = (
    '{{range .Mounts}}{{if eq .Destination "/var/lib/buildkit"}}'
    '{"Type":{{json .Type}},"Name":{{json .Name}},"Source":{{json .Source}},'
    '"Destination":{{json .Destination}},"Driver":{{json .Driver}},"RW":{{json .RW}}}'
    '{{println}}{{end}}{{end}}')
need = release.need


def fields(value, names, code):
    need(type(value) is dict and set(value) == set(names.split()), code)


def integer(value, low, high, code):
    need(type(value) is int and low <= value <= high, code)


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def private_bytes(path):
    path = Path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        need(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.getuid()
             and metadata.st_mode & 0o077 == 0, "build.evidence.not_private")
        return stream.read()


def read_private(path):
    return json.loads(private_bytes(path))


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_once(path, data):
    """Exclusive creation plus directory fsync; interrupted writes stay fenced."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    sync_directory(Path(path).parent)


def outside(left, right):
    left, right = Path(left).resolve(), Path(right).resolve()
    need(left != right and left not in right.parents and right not in left.parents,
         "build.evidence.overlaps_source")


def validate_config(config):
    # Older retained operations omit cache and keep their root-backed contract.
    optional = " cache" if type(config) is dict and "cache" in config else ""
    optional += " buildTuning" if type(config) is dict and "buildTuning" in config else ""
    fields(config, CONFIG_FIELDS + optional, "build.config.fields")
    need(config["schema"] == "openclaw.fork-gcp-build-config.v1", "build.config.schema")
    need(release.matches(re.compile(r"[0-9a-f]{32}\Z"), config["operationId"]),
         "build.operation_id")
    integer(config["attempt"], 1, 1000, "build.attempt")
    for key in ("projectNumber", "instanceId"):
        need(release.matches(re.compile(r"[1-9][0-9]*\Z"), config[key]), "build.cloud_identity")
    for key in ("toolingSha", "sourceSha", "sourceTree"):
        need(release.matches(release.SHA, config[key]), "build.source_identity")
    for key in ("manifestSha256", "inventorySha256"):
        need(release.matches(preflight.HEX256, config[key]), "build.metadata_identity")
    preflight.utc(config["builtAt"])
    need(config["builtAt"] <= now(), "build.future_timestamp")
    # The native Docker exporter rejects the attested manifest list. Keep OCI
    # attestations intact; another transport needs its own native qualification.
    need(config["dockerExport"] is False, "build.export.unqualified_transport")
    builder = config["builder"]
    fields(builder, BUILDER_FIELDS, "build.builder.fields")
    for key in ("name", "node"):
        need(release.matches(re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}\Z"), builder[key]),
             "build.builder.name")
    need(builder["endpoint"] == ENDPOINT, "build.builder.endpoint")
    need(release.matches(preflight.HEX256, builder["containerId"])
         and release.matches(release.DIGEST, builder["imageId"]), "build.builder.identity")
    for key in ("memoryBytes", "memorySwapBytes", "cpuPeriod", "cpuQuota", "cpuShares"):
        integer(builder[key], 1, 1 << 50, "build.builder.resources")
    integer(builder["nanoCpus"], 0, 1 << 50, "build.builder.nano_cpus")
    need(builder["memorySwapBytes"] >= builder["memoryBytes"], "build.builder.swap")
    # Record absent limits honestly. This adapter never changes the builder.
    need(builder["pidsLimit"] is None or
         (type(builder["pidsLimit"]) is int and builder["pidsLimit"] > 0), "build.builder.pids")
    need(builder["readBps"] is None and builder["writeBps"] is None, "build.builder.io_contract")
    limits = config["limits"]
    start_field = " minStartMemoryAvailableBytes" if type(limits) is dict and \
        "minStartMemoryAvailableBytes" in limits else ""
    pressure_field = " maxFullMemoryPressureAvg10" if type(limits) is dict and \
        "maxFullMemoryPressureAvg10" in limits else ""
    fields(limits, LIMIT_FIELDS + start_field + pressure_field, "build.limits.fields")
    integer(limits["timeoutSeconds"], 60, 86400, "build.timeout")
    integer(limits["clientMemoryBytes"], 64 << 20, 2 << 30, "build.client_memory")
    integer(limits["clientCpuQuotaPercent"], 1, 100, "build.client_cpu")
    integer(limits["clientTasksMax"], 8, 128, "build.client_tasks")
    for key in ("minFreeBytes", "minMemoryAvailableBytes"):
        integer(limits[key], 1, 1 << 50, "build.reserve")
    if start_field:
        integer(limits["minStartMemoryAvailableBytes"],
                limits["minMemoryAvailableBytes"], 1 << 50, "build.start_reserve")
    if pressure_field:
        value = limits["maxFullMemoryPressureAvg10"]
        need(type(value) in (int, float) and 0.1 <= value <= 100,
             "build.pressure_limit")
    if "buildTuning" in config:
        tuning = config["buildTuning"]
        fields(tuning, BUILD_TUNING_FIELDS, "build.tuning.fields")
        # The reviewed source measures a 4,352 MiB minimum heap and defaults to
        # 12 GiB. A lower unproven cap and an unbounded override are both refused.
        integer(tuning["tsdownMaxOldSpaceMb"], 4352, 12288,
                "build.tuning.tsdown_heap")
        need((tuning["tsdownMaxOldSpaceMb"] + 768) << 20 < builder["memoryBytes"],
             "build.tuning.builder_memory")
    cache = config.get("cache")
    if cache is not None:
        fields(cache, CACHE_FIELDS, "build.cache.fields")
        need(cache["volumeName"] == f"buildx_buildkit_{builder['node']}_state",
             "build.cache.volume_name")
        value = cache["backingPath"]
        need(type(value) is str and Path(value).is_absolute()
             and str(Path(value)) == value and ".." not in Path(value).parts and value != "/",
             "build.cache.path")
        integer(cache["filesystemDevice"], 1, (1 << 64) - 1, "build.cache.device")
        integer(cache["minFreeBytes"], 1, 1 << 50, "build.cache.reserve")


def clean_checkout(root, sha):
    need(release.git(root, "rev-parse", "HEAD") == sha, "build.checkout.head")
    need(release.git(root, "status", "--porcelain", "--untracked-files=all") == "",
         "build.checkout.dirty")


def source_binding(config, manifest_path, inventory_path, source):
    manifest, manifest_hash = release.manifest_at(manifest_path)
    need(manifest_hash == config["manifestSha256"]
         and preflight.digest(inventory_path) == config["inventorySha256"],
         "build.metadata.binding")
    need(manifest["source"]["commit"] == config["sourceSha"]
         and manifest["source"]["tree"] == config["sourceTree"], "build.source.binding")
    need(manifest["image"] == {"architecture": "amd64", "extensions": "codex,workboard"},
         "build.image.selection")
    clean_checkout(source, config["sourceSha"])
    release.check_source(manifest, source)
    inventory, _ = preflight.inventory_at(inventory_path, manifest, manifest_hash, source)
    pr.validate_binding(manifest_path, source)
    dockerfile = pr.git(source, "show", f"{config['sourceSha']}:Dockerfile", binary=True)
    need(release.sha256(dockerfile) == REVIEWED_DOCKERFILE_SHA256,
         "build.dockerfile.network_policy_unreviewed")
    version = json.loads(pr.git(source, "show", f"{config['sourceSha']}:package.json"))["version"]
    need(release.matches(re.compile(r"2026\.[1-9][0-9]*\.(?:0|[1-9][0-9]*)\Z"), version),
         "build.version.not_stable")
    need(type(inventory["upstream"]) is dict
         and inventory["upstream"]["tag"] == f"v{version}", "build.version.upstream_mismatch")
    return version


def tooling_bytes(root, sha):
    clean_checkout(root, sha)
    result = {}
    for name in HELPERS:
        path = Path(root) / "scripts/fork-release" / name
        committed = pr.git(root, "show", f"{sha}:scripts/fork-release/{name}", binary=True)
        need(path.read_bytes() == committed, "build.tooling.changed")
        result[name] = committed
    need(Path(__file__).read_bytes() == result["gcp_build.py"], "build.tooling.executor")
    return result


def build_argv(op, config, version):
    need(config["dockerExport"] is False, "build.export.unqualified_transport")
    sha = config["sourceSha"]
    command = [*DOCKER, "--host", ENDPOINT, "buildx", "build",
               "--builder", config["builder"]["name"], "--platform", "linux/amd64",
               "--network", "default", "--progress", "plain",
               "--build-arg", "GITHUB_ACTIONS=true",
               "--build-arg", f"GIT_COMMIT={sha}",
               "--build-arg", "OPENCLAW_PARITY_IMAGE=1",
               "--build-arg", f"OPENCLAW_BUILD_TIMESTAMP={config['builtAt']}",
               "--build-arg", f"OPENCLAW_DOCKER_BUILD_VERSION={version}",
               "--build-arg", "OPENCLAW_EXTENSIONS=codex,workboard",
               "--label", f"org.opencontainers.image.revision={sha}",
               "--label", "org.opencontainers.image.source=https://github.com/fr-meyer/openclaw",
               "--label", f"org.opencontainers.image.version={version}",
               "--label", f"org.opencontainers.image.created={config['builtAt']}",
               "--metadata-file", str(op / "build-metadata.json"),
               "--provenance", "mode=max", "--sbom", "true",
               "--output", f"type=oci,dest={op / 'oci'},tar=false,compression=gzip,compression-level=1",
               "--tag", f"openclaw-v105-prep:{sha[:12]}"]
    if "buildTuning" in config:
        command.extend(["--build-arg", "OPENCLAW_DOCKER_BUILD_TSDOWN_MAX_OLD_SPACE_MB="
                        f"{config['buildTuning']['tsdownMaxOldSpaceMb']}"])
    # BuildKit's default raw-SHA route fetches tags and can unshallow history.
    # The native commit-fetch route is shallow, while checksum still verifies
    # the exact requested commit. Keep the full ref for provenance capture.
    return [*command, "https://github.com/fr-meyer/openclaw.git"
            f"?fetch-by-commit=true&checksum={sha}#{sha}"]


def service_argv(op, intent):
    limits = intent["config"]["limits"]
    return [*SYSTEMD_RUN, "--unit", intent["unitName"], "--service-type=exec",
            "--uid", str(intent["uid"]), "--gid", str(intent["gid"]),
            "--property=Restart=no", "--property=RemainAfterExit=yes",
            "--property=KillMode=control-group", "--property=TimeoutStopSec=15",
            f"--property=RuntimeMaxSec={limits['timeoutSeconds']}",
            f"--property=MemoryMax={limits['clientMemoryBytes']}",
            f"--property=CPUQuota={limits['clientCpuQuotaPercent']}%",
            f"--property=TasksMax={limits['clientTasksMax']}",
            "--property=UMask=0077", "--property=StandardOutput=journal",
            "--property=StandardError=journal", "--working-directory", str(op),
            "--", sys.executable, "-B", str(op / "supervisor/gcp_build.py"), "_serve", str(op)]


def prepare(private_root, config, manifest, inventory, source, tooling):
    validate_config(config)
    source, tooling = Path(source).resolve(), Path(tooling).resolve()
    root = Path(private_root).absolute()
    need(root == PRIVATE_ROOT and root.resolve() == PRIVATE_ROOT.resolve()
         and not root.is_symlink(), "build.private_root.not_canonical")
    outside(root, source)
    outside(root, tooling)
    version = source_binding(config, manifest, inventory, source)
    helpers = tooling_bytes(tooling, config["toolingSha"])
    root = release.private_root(root)
    op = root / config["operationId"]
    op.mkdir(mode=0o700)  # Existing or partially prepared operations are never replaced.
    (op / "supervisor").mkdir(mode=0o700)
    for name, data in helpers.items():
        write_once(op / "supervisor" / name, data)
    write_once(op / "manifest.json", Path(manifest).read_bytes())
    write_once(op / "patch-inventory.json", Path(inventory).read_bytes())
    intent = {"schema": "openclaw.fork-gcp-build-intent.v1", "config": config,
              "sourceDir": str(source), "toolingDir": str(tooling), "uid": os.getuid(),
              "gid": os.getgid(), "version": version, "preparedAt": now(),
              "supervisorSha256": {name: release.sha256(data) for name, data in helpers.items()},
              "buildArgv": build_argv(op, config, version),
              "serviceArgv": [], "unitName": f"openclaw-image-build-{config['operationId']}.service"}
    intent["serviceArgv"] = service_argv(op, intent)
    write_once(op / "intent.json", encode(intent))
    return op


def load_intent(op):
    op = Path(op).resolve()
    need(op.parent == PRIVATE_ROOT.resolve() and not PRIVATE_ROOT.is_symlink(),
         "build.private_root.not_canonical")
    need(op.is_dir() and op.parent.is_dir(), "build.operation.missing")
    release.private_root(op.parent)
    release.private_root(op)
    intent = read_private(op / "intent.json")
    fields(intent, INTENT_FIELDS, "build.intent.fields")
    need(intent["schema"] == "openclaw.fork-gcp-build-intent.v1", "build.intent.schema")
    config = intent["config"]
    validate_config(config)
    need(op.name == config["operationId"] and intent["uid"] == os.getuid()
         and intent["gid"] == os.getgid(), "build.intent.owner")
    for key in ("sourceDir", "toolingDir"):
        outside(op.parent, intent[key])
    need(intent["unitName"] == f"openclaw-image-build-{config['operationId']}.service",
         "build.intent.unit")
    fields(intent["supervisorSha256"], " ".join(HELPERS), "build.supervisor.fields")
    for name, digest in intent["supervisorSha256"].items():
        need(release.sha256(private_bytes(op / "supervisor" / name)) == digest,
             "build.supervisor.changed")
    need(preflight.digest(op / "manifest.json") == config["manifestSha256"]
         and preflight.digest(op / "patch-inventory.json") == config["inventorySha256"],
         "build.intent.metadata_changed")
    need(intent["buildArgv"] == build_argv(op, config, intent["version"])
         and intent["serviceArgv"] == service_argv(op, intent), "build.intent.argv_changed")
    if (op / "start-intent.json").exists():
        need(read_private(op / "start-intent.json")["intentSha256"] ==
             preflight.digest(op / "intent.json"), "build.start_intent.changed")
    return op, intent


@contextmanager
def operation_lock(op):
    descriptor = os.open(op / "operation.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "r+b") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield


def prove_trial_no_create_failure(op, intent_sha256):
    """Prove a native supervisor failed before it could dispatch Docker create.

    A missing container reply is never sufficient: the durable create intent
    precedes that dispatch and excludes this recovery path. Re-read the private
    records and exact terminal service here so callers cannot supply a weaker
    assertion to release the shared slot or admit rollback.
    """
    op = Path(op)
    need(op.is_dir() and op.parent == TRIAL_ROOT and op.resolve() == op and
         release.matches(re.compile(r"[0-9a-f]{32}\Z"), op.name), "workload.no_create.path")
    release.private_root(op)
    need(release.matches(preflight.HEX256, intent_sha256) and
         preflight.digest(op / "intent.json") == intent_sha256, "workload.no_create.intent")
    intent = read_private(op / "intent.json")
    requested = read_private(op / "start-intent.json")
    started = read_private(op / "started.json")
    completed = read_private(op / "result.json")
    plan = intent["plan"]
    invocation = started["invocationId"]
    need(plan["operationId"] == op.name and requested["intentSha256"] == intent_sha256 and
         release.matches(re.compile(r"[0-9a-f]{32}\Z"), invocation) and
         completed.get("operationId") == op.name and completed.get("invocationId") == invocation and
         all(completed.get(key) == plan[key] for key in ("imageReceiptSha256", "cleanInputSha256")),
         "workload.no_create.binding")
    if "checkInputSha256" in plan:
        need(completed.get("checkInputSha256") == plan["checkInputSha256"] and
             completed.get("phase") == plan["phase"], "workload.no_create.phase")
    need(completed.get("state") == "failed" and completed.get("cleanup") == "not_started" and
         "containerId" in completed and completed["containerId"] is None and
         "nativeState" in completed and completed["nativeState"] is None and
         "nativeExitCode" in completed and completed["nativeExitCode"] is None and
         completed.get("cgroupSettlementObserved") is False and completed.get("doctorComplete") is False and
         type(completed.get("oomKillDelta")) is int and completed["oomKillDelta"] == 0,
         "workload.no_create.result")
    markers = ("create-intent.json", "container.json", "container-start-intent.json")
    need(not any(os.path.lexists(op / name) for name in markers), "workload.no_create.dispatch_uncertain")
    observed = native([*SYSTEMCTL, "show", "openclaw-snapshot-doctor-" + op.name + ".service",
                       "--property=" + ",".join(SHOW_FIELDS)])
    service = dict(line.split("=", 1) for line in observed.stdout.splitlines() if "=" in line)
    need(observed.returncode == 0 and service.get("LoadState") == "loaded" and
         service.get("InvocationID") == invocation and service.get("MainPID") == "0" and
         service.get("ExecMainCode") == "1" and service.get("ExecMainStatus") == "1" and
         service.get("Result") == "exit-code" and service.get("ActiveState") == "failed" and
         service.get("SubState") == "failed", "workload.no_create.service_unsettled")
    # Recheck after observing terminal service; never release a slot if a
    # create intent appeared while the native service observation was pending.
    need(not any(os.path.lexists(op / name) for name in markers), "workload.no_create.dispatch_uncertain")
    return completed


def heavy_workload_settled(owner, successor=None):
    """Release a cooperative reservation only from retained native terminal proof.

    Build client cancellation is deliberately insufficient: its BuildKit solve
    may outlive it. Legacy/native callers still need operator coordination.
    """
    fields(owner, "kind operationPath intentSha256", "workload.owner.fields")
    kind = owner["kind"]
    need(kind in ("build", "doctor"), "workload.owner.kind")
    op = Path(owner["operationPath"])
    root = PRIVATE_ROOT if kind == "build" else TRIAL_ROOT
    need(op.is_dir() and op.parent == root and op.resolve() == op and
         release.matches(re.compile(r"[0-9a-f]{32}\Z"), op.name), "workload.owner.path")
    release.private_root(op)
    need(preflight.digest(op / "intent.json") == owner["intentSha256"], "workload.owner.changed")
    started = read_private(op / "started.json")
    completed = read_private(op / ("completed.json" if kind == "build" else "result.json"))
    invocation = started["invocationId"]
    need(release.matches(re.compile(r"[0-9a-f]{32}\Z"), invocation) and
         completed["invocationId"] == invocation, "workload.invocation.changed")
    prefix = "openclaw-image-build-" if kind == "build" else "openclaw-snapshot-doctor-"
    result = native([*SYSTEMCTL, "show", prefix + op.name + ".service",
                     "--property=" + ",".join(SHOW_FIELDS)])
    service = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    need(result.returncode == 0 and service.get("LoadState") == "loaded" and
         service.get("InvocationID") == invocation and service.get("MainPID") == "0" and
         service.get("SubState") in ("exited", "dead", "failed") and
         service.get("ExecMainCode") == "1", "workload.service.unsettled")
    if kind == "build":
        if completed.get("exitCode") == 0 and completed.get("nativeExitCode") == 0:
            need(service.get("Result") == "success" and service.get("ExecMainStatus") == "0",
                 "workload.build.solve_unsettled")
        else:
            # A failed client alone cannot release its BuildKit solve. A
            # successor may claim the slot only through the recorded stopped
            # worker and exact lease recovery for this same failed operation.
            need(successor is not None and successor.parent == PRIVATE_ROOT and
                 service.get("Result") == "exit-code" and
                 service.get("ExecMainStatus") != "0" and
                 completed.get("remoteSolveTerminationObserved") is False and
                 not (op / "execution.json").exists(),
                 "workload.build.solve_unsettled")
            proposed = read_private(successor / "builder-handoff-intent.json")
            need(proposed.get("schema") == "openclaw.gcp-builder-recovery.v1" and
                 proposed.get("originOperationId") == op.name and
                 proposed.get("originIntentSha256") == owner["intentSha256"] and
                 proposed.get("originCompletedSha256") ==
                 preflight.digest(op / "completed.json"),
                 "workload.build.recovery_changed")
            successor_intent = read_private(successor / "intent.json")
            verify_builder_handoff(successor, successor_intent)
    else:
        if completed.get("cleanup") == "not_started":
            need(prove_trial_no_create_failure(op, owner["intentSha256"]) == completed,
                 "workload.no_create.result_changed")
            return
        state = completed.get("nativeState") or {}
        need(completed.get("state") in ("succeeded", "failed") and
             completed.get("cleanup") == "owned_container_stopped_retained" and
             state.get("Running") is False and state.get("Pid") == 0 and
             service.get("Result") in ("success", "exit-code") and
             service.get("ExecMainStatus") == ("0" if completed["state"] == "succeeded" else "1"),
             "workload.doctor.unsettled")
        cid = completed.get("containerId")
        need(release.matches(preflight.HEX256, cid), "workload.doctor.container")
        observed = native([*DOCKER, "--host", ENDPOINT, "inspect", "--format", "{{json .State}}", cid])
        need(observed.returncode == 0, "workload.doctor.observation_failed")
        current = json.loads(observed.stdout)
        need(current.get("Running") is False and current.get("Pid") == 0 and
             current.get("StartedAt") == state.get("StartedAt") and
             current.get("FinishedAt") == state.get("FinishedAt"), "workload.doctor.container_changed")


def reserve_heavy_workload(op, kind, intent_sha256, *, reserve_resource=None):
    """Claim a resource and the shared slot under one admission lock.

    The idempotent resource claim runs after checking other workload ownership
    and before publishing this owner. A conflict on either side cannot strand
    a newly claimed slot on the other. Elapsed time never releases ownership.
    """
    op = Path(op)
    need(kind in ("build", "doctor") and
         release.matches(preflight.HEX256, intent_sha256), "workload.reservation.identity")
    expected_root = PRIVATE_ROOT if kind == "build" else TRIAL_ROOT
    need(op.parent == expected_root and op.resolve() == op and
         release.matches(re.compile(r"[0-9a-f]{32}\Z"), op.name) and
         preflight.digest(op / "intent.json") == intent_sha256, "workload.reservation.path")
    need(HEAVY_ROOT.resolve() == HEAVY_ROOT and not HEAVY_ROOT.is_symlink(), "workload.root.changed")
    root = release.private_root(HEAVY_ROOT)
    requested = {"kind": kind, "operationPath": str(op), "intentSha256": intent_sha256}
    with operation_lock(root):
        path = root / "owner.json"
        previous = None
        if path.exists():
            previous = read_private(path)
            if previous != requested:
                try:
                    heavy_workload_settled(previous, successor=op)
                except (OSError, ValueError, KeyError, subprocess.SubprocessError, release.Refusal) as error:
                    raise release.Refusal("workload.owned_or_uncertain; inspect retained owner before continuing") from error
        if reserve_resource is not None:
            reserve_resource()
        if previous == requested:
            return
        if previous is not None:
            # Keep prior ownership facts even when the live slot advances.
            history = root / ("settled-" + release.sha256(encode(previous)) + ".json")
            if not history.exists():
                write_once(history, encode(previous))
        release.atomic_json(path, requested)


def native(argv):
    return subprocess.run(argv, capture_output=True, text=True, timeout=30, env=SAFE_ENV)


def observe_builder(builder, cache=None):
    inspected = native([*DOCKER, "--host", ENDPOINT, "buildx", "ls",
                        "--no-trunc", "--timeout", "10s",
                        "--format", BUILDER_FORMAT])
    need(inspected.returncode == 0, "build.builder.inspect")
    rows = [json.loads(line) for line in inspected.stdout.splitlines() if line.strip()]
    for row in rows:
        fields(row, "Builder Name DriverEndpoint Status", "build.builder.list_fields")
        need(all(type(value) is str for value in row.values()), "build.builder.list_values")
    selected = [row for row in rows if row["Builder"] == builder["name"]]
    drivers = [row for row in selected if row["Name"] == builder["name"]]
    nodes = [row for row in selected if row["Name"] != builder["name"]]
    need(len(drivers) == 1 and len(nodes) == 1, "build.builder.row_count")
    driver, node = drivers[0], nodes[0]
    need(driver["DriverEndpoint"] == "docker-container" and driver["Status"] == "",
         "build.builder.driver")
    need(node["Name"] == builder["node"] and node["DriverEndpoint"] == ENDPOINT
         and node["Status"] == "running", "build.builder.node")
    inspected = native([*DOCKER, "--host", ENDPOINT, "inspect",
                        "--format", CONTAINER_FORMAT, f"buildx_buildkit_{builder['node']}"])
    need(inspected.returncode == 0, "build.builder.container_inspect")
    row = json.loads(inspected.stdout)
    host = row["HostConfig"]
    observed = {"name": driver["Name"], "node": node["Name"], "endpoint": node["DriverEndpoint"],
                "containerId": row["Id"], "imageId": row["Image"],
                **{key: host[native_key] for key, native_key in {
                    "memoryBytes": "Memory", "memorySwapBytes": "MemorySwap",
                    "cpuPeriod": "CpuPeriod", "cpuQuota": "CpuQuota", "cpuShares": "CpuShares",
                    "nanoCpus": "NanoCpus", "pidsLimit": "PidsLimit",
                    "readBps": "BlkioDeviceReadBps", "writeBps": "BlkioDeviceWriteBps"}.items()}}
    need(row["State"]["Running"] is True and observed == builder, "build.builder.changed")
    if cache is not None:
        observe_cache(builder, cache)
    return observed


def cache_path(cache):
    """Verify the mounted filesystem without traversing BuildKit-owned contents."""
    path = Path(cache["backingPath"])
    need(path.resolve(strict=True) == path, "build.cache.path_not_canonical")
    metadata = path.lstat()
    parent = path.parent.stat()
    need(stat.S_ISDIR(metadata.st_mode) and stat.S_ISDIR(parent.st_mode),
         "build.cache.not_directory")
    need(metadata.st_dev == parent.st_dev == cache["filesystemDevice"],
         "build.cache.filesystem_changed")
    return path, metadata


def observe_cache(builder, cache):
    inspected = native([*DOCKER, "--host", ENDPOINT, "volume", "inspect",
                        "--format", CACHE_VOLUME_FORMAT, cache["volumeName"]])
    need(inspected.returncode == 0, "build.cache.volume_inspect")
    volume = json.loads(inspected.stdout)
    fields(volume, "Name Driver Mountpoint Options", "build.cache.volume_fields")
    need(volume["Name"] == cache["volumeName"] and volume["Driver"] == "local"
         and volume["Options"] == {"type": "none", "o": "bind", "device": cache["backingPath"]}
         and type(volume["Mountpoint"]) is str and Path(volume["Mountpoint"]).is_absolute(),
         "build.cache.volume_changed")
    # Inspect the already bound container ID, not a reusable builder name.
    inspected = native([*DOCKER, "--host", ENDPOINT, "inspect", "--format",
                        CACHE_MOUNT_FORMAT, builder["containerId"]])
    need(inspected.returncode == 0, "build.cache.mount_inspect")
    mounts = [json.loads(line) for line in inspected.stdout.splitlines() if line.strip()]
    need(mounts == [{"Type": "volume", "Name": cache["volumeName"],
                    "Source": volume["Mountpoint"], "Destination": "/var/lib/buildkit",
                    "Driver": "local", "RW": True}], "build.cache.mount_changed")
    cache_path(cache)


def cache_sample(cache):
    path, before = cache_path(cache)
    sample_path = path
    try:
        free = shutil.disk_usage(path).free
    except PermissionError:
        # BuildKit can own cache/ as root0700. The verified parent is on exactly
        # the same pinned device, so statvfs there measures the same free space.
        sample_path = path.parent
        free = shutil.disk_usage(sample_path).free
    _, after = cache_path(cache)
    need((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino),
         "build.cache.path_changed")
    return {"cacheFreeBytes": free, "cacheSamplePath": str(sample_path),
            "cacheFilesystemDevice": after.st_dev}


def memory_pressure_sample():
    pressure = {}
    for line in Path("/proc/pressure/memory").read_text().splitlines():
        name, _, rest = line.partition(" ")
        if name in ("some", "full"):
            values = dict(part.split("=", 1) for part in rest.split())
            pressure[name] = {key: float(values[key]) for key in ("avg10", "avg60")}
    need(set(pressure) == {"some", "full"}, "build.capacity.pressure_unavailable")
    return pressure


def resource_sample(op, cache=None):
    memory = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, _, value = line.partition(":")
        if key == "MemAvailable":
            memory[key] = int(value.split()[0]) * 1024
    need("MemAvailable" in memory, "build.capacity.memory_unavailable")
    free = shutil.disk_usage(op).free
    pressure = {}
    try:
        pressure["memoryPressure"] = memory_pressure_sample()
    except (OSError, ValueError, KeyError, release.Refusal) as error:
        # Retained configurations without a PSI limit keep their original
        # admission contract. The configured pressure gate below still refuses.
        pressure["memoryPressureObservationError"] = str(error)
    return {"observedAt": now(), "freeBytes": free,
            "memoryAvailableBytes": memory["MemAvailable"],
            **pressure,
            **(cache_sample(cache) if cache is not None else {})}


def capacity(op, limits, cache=None, *, starting=False):
    observed = resource_sample(op, cache)
    need(observed["freeBytes"] >= limits["minFreeBytes"], "build.capacity.disk_reserve")
    need(observed["memoryAvailableBytes"] >= limits["minMemoryAvailableBytes"],
         "build.capacity.memory_reserve")
    if starting and "minStartMemoryAvailableBytes" in limits:
        need(observed["memoryAvailableBytes"] >= limits["minStartMemoryAvailableBytes"],
             "build.capacity.start_memory_reserve")
    if "maxFullMemoryPressureAvg10" in limits:
        need("memoryPressure" in observed, "build.capacity.pressure_unavailable")
        need(observed["memoryPressure"]["full"]["avg10"] <=
             limits["maxFullMemoryPressureAvg10"], "build.capacity.memory_pressure")
    if cache is not None:
        need(observed["cacheFreeBytes"] >= cache["minFreeBytes"], "build.capacity.cache_reserve")
    return observed


def cgroup_text(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor) as stream:
        need(stat.S_ISREG(os.fstat(stream.fileno()).st_mode),
             "build.telemetry.not_regular")
        return stream.read(16384)


def builder_sample(builder):
    """Read the exact pinned worker cgroup, including its persistent memory peak."""
    path = CGROUP_SLICE / f"docker-{builder['containerId']}.scope"
    need(path.is_dir() and not path.is_symlink(), "build.telemetry.cgroup_unavailable")
    memory = dict(line.split(None, 1) for line in
                  cgroup_text(path / "memory.stat").splitlines())
    cpu = dict(line.split(None, 1) for line in cgroup_text(path / "cpu.stat").splitlines())
    events = dict(line.split(None, 1) for line in
                  cgroup_text(path / "memory.events").splitlines())
    return {"containerId": builder["containerId"],
            "memoryCurrentBytes": int(cgroup_text(path / "memory.current")),
            "memoryPeakBytes": int(cgroup_text(path / "memory.peak")),
            "anonBytes": int(memory["anon"]), "fileBytes": int(memory["file"]),
            "slabBytes": int(memory["slab"]),
            "cpuUsageUsec": int(cpu["usage_usec"]),
            "cpuThrottledUsec": int(cpu["throttled_usec"]),
            "cpuPeriods": int(cpu["nr_periods"]),
            "cpuThrottledPeriods": int(cpu["nr_throttled"]),
            "oom": int(events["oom"]), "oomKill": int(events["oom_kill"])}


def record_resources(op, phase, observed=None, cache=None, builder=None):
    """Small host and pinned-builder samples; neither proves phase progress."""
    record = {"observedAt": now(), "scope": "host", "phase": phase}
    try:
        record["resources"] = observed if observed is not None else resource_sample(op, cache)
    except (OSError, ValueError, release.Refusal) as error:
        record["observationError"] = str(error)
    if builder is not None:
        try:
            record["builder"] = builder_sample(builder)
        except (OSError, ValueError, KeyError, release.Refusal) as error:
            record["builderObservationError"] = str(error)
    try:
        descriptor = os.open(op / "resources.jsonl", os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "ab", buffering=0) as stream:
            stream.write((json.dumps(record, sort_keys=True) + "\n").encode())
            os.fsync(stream.fileno())
    except OSError as error:
        # Diagnostic persistence must not replace the already observed child
        # result or prevent its durable exit/completion records.
        try:
            os.write(2, f"{now()} host resource evidence unavailable: {error}\n".encode())
        except OSError:
            pass
        return False
    return True


def reserve_builder(op, intent):
    """A retained intent fences other operations even if systemd dispatch is uncertain."""
    lease = op.parent / f"builder-{intent['config']['builder']['containerId']}.json"
    value = {"operationId": op.name, "intentSha256": preflight.digest(op / "intent.json")}
    try:
        write_once(lease, encode(value))
    except FileExistsError:
        need(read_private(lease) == value, "build.builder.reserved_by_other_operation")


def verify_builder_handoff(op, intent):
    """Fence start until a successor lease transfer is durably complete."""
    path = op / "builder-handoff-intent.json"
    if not path.exists():
        return
    proposed = read_private(path)
    need(type(proposed) is dict, "build.handoff.intent.fields")
    if proposed.get("schema") == "openclaw.gcp-builder-handoff.v1":
        fields(proposed, """schema originOperationId targetOperationId originIntentSha256
               targetIntentSha256 originExecutionSha256 originLeaseSha256""",
               "build.handoff.intent.fields")
    elif proposed.get("schema") == "openclaw.gcp-builder-recovery.v1":
        fields(proposed, """schema originOperationId targetOperationId originIntentSha256
               targetIntentSha256 originCompletedSha256 builderStoppedSha256 originLeaseSha256""",
               "build.handoff.intent.fields")
        need(preflight.digest(op / "builder-stopped.json") == proposed["builderStoppedSha256"],
             "build.handoff.stop_proof.changed")
    else:
        need(False, "build.handoff.intent.schema")
    need(proposed["targetOperationId"] == op.name and
         proposed["targetIntentSha256"] == preflight.digest(op / "intent.json"),
         "build.handoff.intent.changed")
    receipt = read_private(op / "builder-handoff.json")
    need(type(receipt) is dict and set(receipt) == set(proposed) | {"targetLeaseSha256"},
         "build.handoff.receipt.fields")
    value = {"operationId": op.name,
             "intentSha256": preflight.digest(op / "intent.json")}
    lease = op.parent / f"builder-{intent['config']['builder']['containerId']}.json"
    need(receipt == {**proposed, "targetLeaseSha256": release.sha256(encode(value))} and
         private_bytes(lease) == encode(value), "build.handoff.incomplete")
    evidence = [path, op / "builder-handoff.json", lease]
    if proposed["schema"] == "openclaw.gcp-builder-recovery.v1":
        evidence.append(op / "builder-stopped.json")
    for item in evidence:
        fd = os.open(item, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        sync_directory(item.parent)


def metadata_handoff_capability(op, intent):
    result = native(["/usr/bin/sudo", "-n", "-l", "/usr/bin/chown",
                     f"{intent['uid']}:{intent['gid']}", str(op / "build-metadata.json")])
    need(result.returncode == 0, "build.metadata.handoff_unavailable")


def take_metadata(op, intent):
    """Transfer only the exact native output, after the Buildx client has joined."""
    path = op / "build-metadata.json"
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
         and before.st_uid in (0, intent["uid"]), "build.metadata.unsafe_output")
    if before.st_uid != intent["uid"]:
        metadata_handoff_capability(op, intent)
        result = native([*CHOWN, f"{intent['uid']}:{intent['gid']}", str(path)])
        need(result.returncode == 0, "build.metadata.handoff_failed")
    after = path.lstat()
    need((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)
         and stat.S_ISREG(after.st_mode) and after.st_uid == intent["uid"]
         and after.st_gid == intent["gid"] and after.st_nlink == 1,
         "build.metadata.handoff_changed")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        current = os.fstat(descriptor)
        need((current.st_dev, current.st_ino) == (after.st_dev, after.st_ino),
             "build.metadata.handoff_changed")
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def start(op):
    need(sys.platform == "linux", "build.start.requires_gcp_linux")
    op, intent = load_intent(op)
    with operation_lock(op):
        if (op / "start-intent.json").exists():
            return status(op)
        config = intent["config"]
        verify_builder_handoff(op, intent)
        source_binding(config, op / "manifest.json", op / "patch-inventory.json",
                       intent["sourceDir"])
        need(tooling_bytes(intent["toolingDir"], config["toolingSha"]) ==
             {name: private_bytes(op / "supervisor" / name) for name in HELPERS},
             "build.tooling.changed")
        observe_builder(config["builder"], config.get("cache"))
        reserve = capacity(op, config["limits"], config.get("cache"), starting=True)
        metadata_handoff_capability(op, intent)
        reserve_heavy_workload(op, "build", preflight.digest(op / "intent.json"),
                               reserve_resource=lambda: reserve_builder(op, intent))
        write_once(op / "start-intent.json", encode({
            "intentSha256": preflight.digest(op / "intent.json"), "requestedAt": now(),
            "unitName": intent["unitName"], "capacity": reserve}))
        # Any exception after the fsynced start intent is an uncertain dispatch.
        try:
            result = native(intent["serviceArgv"])
            record = {"observedAt": now(), "returnCode": result.returncode,
                      "stdout": result.stdout, "stderr": result.stderr}
        except (OSError, subprocess.TimeoutExpired):
            record = {"observedAt": now(), "returnCode": None,
                      "stdout": "", "stderr": "dispatch outcome uncertain; status only"}
        write_once(op / "dispatch.json", encode(record))
    return status(op)


def run_child(op, intent):
    """Called by the retained service, never an SSH-attached build process."""
    invocation = os.environ.get("INVOCATION_ID", "")
    need(release.matches(re.compile(r"[0-9a-f]{32}\Z"), invocation), "build.service.invocation")
    start_intent = read_private(op / "start-intent.json")
    need(start_intent["intentSha256"] == preflight.digest(op / "intent.json"),
         "build.start_intent.changed")
    started = {"startedAt": now(), "invocationId": invocation}
    write_once(op / "started.json", encode(started))
    write_once(op / "resources.jsonl", b"")
    previous_umask = os.umask(0o077)
    signal_received = []
    child = None
    stop_at = None
    join_attempted = False
    previous = {}

    def cancel(signum, _frame):
        signal_received.append(signum)
        if child is not None and child.poll() is None:
            child.terminate()

    for signum in (signal.SIGTERM, signal.SIGINT):
        previous[signum] = signal.signal(signum, cancel)
    native_exit, exit_code, reason = None, 1, "client failed before launch"
    cache = intent["config"].get("cache")
    try:
        reserve_heavy_workload(op, "build", preflight.digest(op / "intent.json"))
        observe_builder(intent["config"]["builder"], cache)
        record_resources(op, "start", capacity(op, intent["config"]["limits"], cache,
                                                starting=True),
                         builder=intent["config"]["builder"])
        need(not signal_received, "build.cancelled_before_launch")
        with open(op / "build.log", "xb", buffering=0) as log:
            child = subprocess.Popen(intent["buildArgv"], cwd=op, env=SAFE_ENV,
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     umask=0o022)
            selector = selectors.DefaultSelector()
            selector.register(child.stdout, selectors.EVENT_READ)
            drain_at = None
            pipe_incomplete = False
            next_capacity = time.monotonic()
            next_sample = next_capacity + 30
            deadline = next_capacity + intent["config"]["limits"]["timeoutSeconds"]
            try:
                while selector.get_map() or child.poll() is None:
                    if time.monotonic() >= deadline and stop_at is None:
                        reason = "client deadline; remote solve termination unobserved"
                        child.terminate()
                        stop_at = time.monotonic() + CLIENT_TERM_GRACE_SECONDS
                    if time.monotonic() >= next_capacity and stop_at is None:
                        next_capacity = time.monotonic() + 2
                        try:
                            observed = capacity(op, intent["config"]["limits"], cache)
                            if time.monotonic() >= next_sample:
                                record_resources(op, "periodic", observed,
                                                 builder=intent["config"]["builder"])
                                next_sample = time.monotonic() + 30
                        except (OSError, ValueError, release.Refusal) as error:
                            reason = str(error)
                            record_resources(op, "reserve-failed", cache=cache,
                                             builder=intent["config"]["builder"])
                            child.terminate()
                            stop_at = time.monotonic() + CLIENT_TERM_GRACE_SECONDS
                    if signal_received and stop_at is None:
                        reason = "service cancellation; remote solve termination unobserved"
                        stop_at = time.monotonic() + CLIENT_TERM_GRACE_SECONDS
                    if stop_at is not None and time.monotonic() >= stop_at:
                        if child.poll() is None:
                            child.kill()  # Only this client's PID; never a daemon/container.
                        break  # Descendants may still hold the inherited output pipe.
                    if child.poll() is not None:
                        if drain_at is None:
                            drain_at = time.monotonic() + CLIENT_PIPE_DRAIN_SECONDS
                        if time.monotonic() >= drain_at:
                            pipe_incomplete = bool(selector.get_map())
                            break
                    for key, _ in selector.select(timeout=0.25):
                        data = os.read(key.fd, 65536)
                        if not data:
                            selector.unregister(key.fileobj)
                            continue
                        # Prefix each received native output chunk; preserve its bytes.
                        stamped = now().encode() + b" " + data
                        log.write(stamped)
                        sys.stdout.buffer.write(stamped)
                        sys.stdout.buffer.flush()
            finally:
                selector.close()
                child.stdout.close()
            join_attempted = True
            try:
                result = child.wait(timeout=CLIENT_JOIN_SECONDS)
                native_exit = result if result >= 0 else 128 - result
            except subprocess.TimeoutExpired:
                native_exit = None
            exit_code = native_exit if native_exit is not None else 75
            if stop_at is not None:
                exit_code = exit_code or 75
            elif pipe_incomplete:
                exit_code = exit_code or 75
                reason = "client exited with output pipe still open; remote solve termination unobserved"
            else:
                reason = "client exited; remote solve termination unobserved" if exit_code else "client succeeded"
            os.fsync(log.fileno())
        if exit_code == 0:
            # Sudo Buildx may atomically replace a precreated file; do not assume
            # in-place writes retain the invoking user's ownership.
            take_metadata(op, intent)
    except BaseException:
        exit_code = 1
        if stop_at is None:
            reason = "supervisor failed; retain native output and reconcile"
        raise
    finally:
        try:
            if child is not None:
                if child.poll() is None and not join_attempted:
                    child.terminate()
                    try:
                        child.wait(timeout=CLIENT_TERM_GRACE_SECONDS)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        try:
                            child.wait(timeout=CLIENT_JOIN_SECONDS)
                        except subprocess.TimeoutExpired:
                            pass  # No observed exit means no native success evidence.
                if child.returncode is not None:
                    native_exit = child.returncode if child.returncode >= 0 else 128 - child.returncode
            if native_exit is not None:
                write_once(op / "build.exit", f"{native_exit}\n".encode())
            write_once(op / "completed.json", encode({
                **started, "completedAt": now(), "exitCode": exit_code,
                "nativeExitCode": native_exit, "reason": reason,
                "remoteSolveTerminationObserved": False}))
            record_resources(op, "end", cache=cache,
                             builder=intent["config"]["builder"])
        finally:
            try:
                for signum, handler in previous.items():
                    signal.signal(signum, handler)
            finally:
                os.umask(previous_umask)
    return exit_code


def readable_outputs(op):
    """Check access without copying/hashing layers; seal-gcp owns OCI validation.

    The parent remains private0700. Only the native Buildx child uses umask0022,
    so root-owned export directories/files can be traversed/read by this UID.
    Native sudo/exporter behavior must be probed before candidate execution; an
    unexpected mode here leaves the operation incomplete, without a receipt.
    """
    pending = [op / "oci"]
    files = []
    while pending:
        directory = pending.pop()
        need(stat.S_ISDIR(directory.lstat().st_mode), "build.output.unsafe_directory")
        with os.scandir(directory) as entries:
            for entry in entries:
                if entry.is_dir(follow_symlinks=False):
                    pending.append(Path(entry.path))
                else:
                    files.append(Path(entry.path))
    for path in files:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            need(stat.S_ISREG(os.fstat(descriptor).st_mode), "build.output.unsafe_file")
        finally:
            os.close(descriptor)


def finalize(op, intent, service):
    completed = read_private(op / "completed.json")
    fields(completed, """startedAt invocationId completedAt exitCode nativeExitCode reason
           remoteSolveTerminationObserved""", "build.completion.fields")
    started = read_private(op / "started.json")
    fields(started, "startedAt invocationId", "build.started.fields")
    need(all(completed[key] == started[key] for key in started), "build.started.changed")
    need(service["InvocationID"] == completed["invocationId"], "build.service.identity_changed")
    need(completed["exitCode"] == 0 and completed["nativeExitCode"] == 0
         and private_bytes(op / "build.exit").strip() == b"0",
         "build.client.failed")
    config = intent["config"]
    for key in ("startedAt", "completedAt"):
        preflight.utc(completed[key])
    need(config["builtAt"] <= completed["startedAt"] <= completed["completedAt"] <= now(),
         "build.time.order")
    metadata = private_bytes(op / "build-metadata.json")
    digest = json.loads(metadata)["containerimage.digest"]
    need(release.matches(release.DIGEST, digest), "build.metadata.digest")
    readable_outputs(op)
    # Full OCI/SBOM/provenance verification remains with image.mjs seal-gcp.
    index = json.loads((op / "oci/index.json").read_bytes())
    need(len(index["manifests"]) == 1 and index["manifests"][0]["digest"] == digest,
         "build.oci.index_binding")
    execution = {"schema": "openclaw.fork-gcp-image-execution.v1",
                 **{key: config[key] for key in (
                     "operationId", "attempt", "projectNumber", "instanceId", "toolingSha",
                     "sourceSha", "sourceTree", "manifestSha256", "inventorySha256", "builtAt")},
                 "indexDigest": digest, "startedAt": completed["startedAt"],
                 "completedAt": completed["completedAt"], "buildExitCode": 0,
                 "buildMetadataSha256": release.sha256(metadata),
                 "buildLogSha256": release.sha256(private_bytes(op / "build.log"))}
    path = op / "execution.json"
    try:
        write_once(path, encode(execution))
    except FileExistsError:
        need(read_private(path) == execution, "build.execution.changed")
    return execution


def service_observation(intent):
    result = native([*SYSTEMCTL, "show", intent["unitName"], "--no-pager",
                     "--property=" + ",".join(SHOW_FIELDS)])
    service = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    return result, service


def status(op):
    op, intent = load_intent(op)
    result, service = service_observation(intent)
    state = "unknown"
    if result.returncode == 0 and service.get("LoadState") == "loaded":
        if service.get("SubState") == "running" and service.get("ActiveState") == "active":
            state = "running"
        elif service.get("ActiveState") == "failed":
            state = "failed"
        elif (service.get("SubState") in ("exited", "dead")
              and service.get("Result") == "success" and service.get("ExecMainCode") == "1"
              and service.get("ExecMainStatus") == "0" and service.get("MainPID") == "0"):
            try:
                finalize(op, intent, service)
                state = "succeeded"
            except (OSError, ValueError, KeyError, release.Refusal):
                state = "incomplete"
    log = op / "build.log"
    return {"operationId": op.name, "unitName": intent["unitName"], "state": state,
            "dispatchRecorded": (op / "start-intent.json").exists(),
            "logBytes": log.stat().st_size if log.is_file() else 0,
            "buildPhaseProgress": "unproven", "remoteSolveTerminationObserved": False,
            "service": service}


def cancel(op):
    op, intent = load_intent(op)
    need((op / "start-intent.json").exists(), "build.cancel.not_started")
    with operation_lock(op):
        if not (op / "cancel-intent.json").exists():
            need((op / "started.json").exists(), "build.cancel.service_owner_unproven")
            started = read_private(op / "started.json")
            fields(started, "startedAt invocationId", "build.started.fields")
            result, service = service_observation(intent)
            need(result.returncode == 0 and service.get("LoadState") == "loaded"
                 and service.get("ActiveState") == "active"
                 and service.get("SubState") == "running"
                 and release.matches(re.compile(r"[0-9a-f]{32}\Z"), started["invocationId"])
                 and service.get("InvocationID") == started["invocationId"],
                 "build.cancel.service_owner_unproven")
            write_once(op / "cancel-intent.json", encode({"requestedAt": now(),
                                                        "unitName": intent["unitName"],
                                                        "invocationId": started["invocationId"]}))
            try:
                native([*SYSTEMCTL, "stop", intent["unitName"]])
            except (OSError, subprocess.TimeoutExpired):
                pass  # An uncertain cancellation is observation-only on retry.
    return status(op)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prep = sub.add_parser("prepare")
    for name in ("config", "private-root", "manifest", "inventory", "source-dir", "tooling-dir"):
        prep.add_argument("--" + name, required=True, type=Path)
    for name in ("start", "status", "cancel", "_serve"):
        sub.add_parser(name).add_argument("operation", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            print(prepare(args.private_root, release.read_json(args.config), args.manifest,
                          args.inventory, args.source_dir, args.tooling_dir))
            return 0
        if args.command == "_serve":
            need(sys.platform == "linux", "build.service.requires_gcp_linux")
            op, intent = load_intent(args.operation)
            return run_child(op, intent)
        if args.command == "status":
            op, _ = load_intent(args.operation)
            log = op / "build.log"
            if log.is_file():
                descriptor = os.open(log, os.O_RDONLY | os.O_NOFOLLOW)
                with os.fdopen(descriptor, "rb") as stream:
                    stream.seek(max(0, log.stat().st_size - 16384))
                    sys.stdout.buffer.write(stream.read())
                    sys.stdout.buffer.flush()
        print(json.dumps({"start": start, "status": status, "cancel": cancel}[args.command](args.operation)))
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, release.Refusal) as error:
        print(f"GCP image build refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
