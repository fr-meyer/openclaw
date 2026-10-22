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

from __future__ import annotations

import argparse
import copy
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import fcntl
from fractions import Fraction
import json
from math import isfinite
import os
from pathlib import Path
import queue
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time

import preflight
import pr
import release

DOCKER = ("/usr/bin/sudo", "-n", "/usr/bin/docker")
PRODUCTION_GATEWAY_NAME = "openclaw-openclaw-gateway-1"
# This profile is a single controlled qualification of the reviewed 10.5
# source, not a general lower-memory promise for future Dockerfiles.
QUALIFICATION_SOURCE_SHA = "84d65b446d66cd5db5b9c533bd158e9062968692"
RETAINED_QUALIFICATION_SOURCE_SHA = "1d5ab20bea4cccce0b80b60a9ba5d5020cf08038"
QUALIFICATION_PROFILE_ID = "qualification-8g"
QUALIFICATION_START_BYTES = 10 << 30
QUALIFICATION_RUNNING_FLOOR_BYTES = 2 << 30
QUALIFICATION_PRESSURE_RISK_BYTES = 4 << 30
SYSTEMD_RUN = ("/usr/bin/sudo", "-n", "/usr/bin/systemd-run")
SYSTEMCTL = ("/usr/bin/sudo", "-n", "/usr/bin/systemctl")
CHOWN = ("/usr/bin/sudo", "-n", "/usr/bin/chown")
ENDPOINT = "unix:///var/run/docker.sock"
PRIVATE_ROOT = Path("/var/tmp/openclaw-fork-gcp-build")
CGROUP_ROOT = Path("/sys/fs/cgroup")
CGROUP_SLICE = CGROUP_ROOT / "system.slice"
HEAVY_ROOT = Path("/var/tmp/openclaw-fork-heavy-workload")
TRIAL_ROOT = Path("/var/tmp/openclaw-fork-snapshot-trial")
CLIENT_TERM_GRACE_SECONDS = 5
CLIENT_JOIN_SECONDS = 2
CLIENT_PIPE_DRAIN_SECONDS = 1
CLIENT_DEADLINE_REASON = "client deadline; remote solve termination unobserved"
PRESSURE_ENTER = 5.0
PRESSURE_CLEAR = 3.0
PRESSURE_CLEAR_SECONDS = 30.0
PRESSURE_MAX_SAMPLE_GAP_SECONDS = 30.0
PRESSURE_HEADROOM_RISK_BYTES = 12 << 30
PRESSURE_HEADROOM_RISK_SECONDS = 30.0
PRESSURE_HEALTH_LATENCY_MS = 4000.0
PRESSURE_HEALTH_MAX_AGE_SECONDS = 30.0
PRESSURE_LATENCY_RISK_SECONDS = 60.0
PRESSURE_STOP_SECONDS = 120.0
PRESSURE_WATCH_MAX_SECONDS = 180.0
PRESSURE_PROBE_MAX_SECONDS = 10.0
HELPERS = ("gcp_build.py", "release.py", "preflight.py", "pr.py")
SAFE_ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"}
# This complete reviewed Dockerfile gives every RUN an explicit network mode:
# only three pre-payload acquisition steps use default; all others use none.
# Review the whole file, including stage/COPY/ENV/SHELL policy, before changing
# this pin. A partial Dockerfile parser cannot establish that boundary.
REVIEWED_DOCKERFILE_SHA256 = "10e784c10a826ac74457f5bc50a76861057671871735aa96ad176d9285b984c3"
CONFIG_FIELDS = """schema operationId attempt projectNumber instanceId toolingSha
sourceSha sourceTree manifestSha256 inventorySha256 builtAt builder limits dockerExport"""
BUILD_TUNING_FIELDS = "tsdownMaxOldSpaceMb"
BUILDER_FIELDS = """name node endpoint containerId imageId memoryBytes memorySwapBytes
cpuPeriod cpuQuota cpuShares nanoCpus pidsLimit readBps writeBps"""
LIMIT_FIELDS = """timeoutSeconds clientMemoryBytes clientCpuQuotaPercent clientTasksMax
minFreeBytes minMemoryAvailableBytes"""
CACHE_FIELDS = "volumeName backingPath filesystemDevice minFreeBytes"
PROFILE_FIELDS = """id qualification sourceSha sourceTree builderContainerId builderSha256
 tsdownMaxOldSpaceMb minStartMemoryAvailableBytes minMemoryAvailableBytes
 maxFullMemoryPressureAvg10 minFreeBytes minCacheFreeBytes"""
ADAPTIVE_FIELDS = "schema profile profileSha256 gatewayContainerId samples selectedAt"
ADAPTIVE_SAMPLE_FIELDS = """observedAt memoryAvailableBytes freeBytes cacheFreeBytes
 fullMemoryPressureAvg10 gatewayContainerId gatewayHealthy gatewayOomKilled"""
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


@dataclass(frozen=True)
class PressureSample:
    at_seconds: float
    host_full_avg10_pct: float
    available_bytes: int
    gateway_healthy: bool
    gateway_oom: bool
    worker_oom: bool
    last_health_check_ms: float | None = None
    last_health_check_age_seconds: float | None = None


@dataclass(frozen=True)
class PressureState:
    active: bool = False
    high_since: float | None = None
    clear_since: float | None = None
    last_at: float | None = None
    watch_since: float | None = None


@dataclass(frozen=True)
class PressureDecision:
    action: str
    reason: str


def finite_number(value):
    if type(value) not in (int, float):
        return False
    try:
        return isfinite(value)
    except OverflowError:
        return False


def valid_pressure_state(state):
    if type(state) is not PressureState or type(state.active) is not bool:
        return False
    if any(value is not None and not finite_number(value) for value in
           (state.high_since, state.clear_since, state.last_at, state.watch_since)):
        return False
    if state.high_since is not None and state.clear_since is not None:
        return False
    if state.last_at is None and (state.active or state.high_since is not None or
                                  state.clear_since is not None or state.watch_since is not None):
        return False
    if state.active != (state.watch_since is not None):
        return False
    if state.last_at is not None and any(value is not None and value > state.last_at
                                         for value in (state.high_since, state.clear_since,
                                                       state.watch_since)):
        return False
    if not state.active and (state.high_since is not None or state.clear_since is not None):
        return False
    return True


def valid_pressure_sample(sample, state):
    if type(sample) is not PressureSample or not valid_pressure_state(state):
        return False
    if (not finite_number(sample.at_seconds) or
            not finite_number(sample.host_full_avg10_pct) or
            not 0 <= sample.host_full_avg10_pct <= 100 or
            type(sample.available_bytes) is not int or sample.available_bytes < 0 or
            any(type(value) is not bool for value in
                (sample.gateway_healthy, sample.gateway_oom, sample.worker_oom))):
        return False
    if state.last_at is not None and not (
        state.last_at < sample.at_seconds <= state.last_at + PRESSURE_MAX_SAMPLE_GAP_SECONDS
    ):
        return False
    duration = sample.last_health_check_ms
    age = sample.last_health_check_age_seconds
    if (duration is None) != (age is None):
        return False
    if duration is not None and not (
        finite_number(duration) and finite_number(age) and duration >= 0 and age >= 0
    ):
        return False
    return True


def pressure_guard_evaluate(sample, state, *, hard_floor_bytes=10 << 30,
                            risk_floor_bytes=PRESSURE_HEADROOM_RISK_BYTES):
    """Bound runtime PSI by time and independent health/headroom signals.

    A single host full-PSI avg10 crossing is an observation, not proof of build
    causality. All current hard capacity/health/OOM gates remain separate.
    """
    if (type(hard_floor_bytes) is not int or type(risk_floor_bytes) is not int or
            not 0 < hard_floor_bytes < risk_floor_bytes or
            not valid_pressure_sample(sample, state)):
        return PressureDecision("stop", "build.pressure.telemetry_invalid"), state
    if not sample.gateway_healthy or sample.gateway_oom or sample.worker_oom:
        return PressureDecision("stop", "build.pressure.critical_health_or_oom"), state
    if sample.available_bytes < hard_floor_bytes:
        return PressureDecision("stop", "build.pressure.critical_headroom"), state

    timestamp = sample.at_seconds
    if (state.active and state.watch_since is not None and
            timestamp - state.watch_since >= PRESSURE_WATCH_MAX_SECONDS):
        return PressureDecision("stop", "build.pressure.watch_timeout"), state
    if sample.host_full_avg10_pct > PRESSURE_ENTER:
        high_since = state.high_since if state.high_since is not None else timestamp
        elapsed = timestamp - high_since
        watch_since = state.watch_since if state.watch_since is not None else timestamp
        updated = PressureState(True, high_since, None, timestamp, watch_since)
        if elapsed >= PRESSURE_STOP_SECONDS:
            return PressureDecision("stop", "build.pressure.sustained"), updated
        if (elapsed >= PRESSURE_HEADROOM_RISK_SECONDS and
                sample.available_bytes < risk_floor_bytes):
            return PressureDecision("stop", "build.pressure.headroom"), updated
        if (elapsed >= PRESSURE_LATENCY_RISK_SECONDS and
                sample.last_health_check_ms is not None and
                sample.last_health_check_age_seconds <= PRESSURE_HEALTH_MAX_AGE_SECONDS and
                sample.last_health_check_ms >= PRESSURE_HEALTH_LATENCY_MS):
            return PressureDecision("stop", "build.pressure.gateway_latency"), updated
        return PressureDecision("watch", "build.pressure.observed"), updated

    if not state.active:
        return PressureDecision("clear", "build.pressure.clear"), PressureState(last_at=timestamp)
    if sample.host_full_avg10_pct < PRESSURE_CLEAR:
        clear_since = state.clear_since if state.clear_since is not None else timestamp
        if timestamp - clear_since >= PRESSURE_CLEAR_SECONDS:
            return PressureDecision("clear", "build.pressure.cleared"), PressureState(
                last_at=timestamp)
        return PressureDecision("watch", "build.pressure.clearing"), PressureState(
            True, None, clear_since, timestamp, state.watch_since)
    return PressureDecision("watch", "build.pressure.below_entry"), PressureState(
        True, None, None, timestamp, state.watch_since)


def pressure_watchdog(now_seconds, state):
    """An independent timed caller detects silence and enforces the stop clock."""
    if (not valid_pressure_state(state) or not finite_number(now_seconds) or
            state.last_at is None or now_seconds < state.last_at or
            now_seconds - state.last_at > PRESSURE_MAX_SAMPLE_GAP_SECONDS):
        return PressureDecision("stop", "build.pressure.telemetry_silent")
    if state.high_since is not None and now_seconds - state.high_since >= PRESSURE_STOP_SECONDS:
        return PressureDecision("stop", "build.pressure.sustained")
    if state.watch_since is not None and now_seconds - state.watch_since >= PRESSURE_WATCH_MAX_SECONDS:
        return PressureDecision("stop", "build.pressure.watch_timeout")
    return PressureDecision("watch" if state.active else "clear", "build.pressure.current")


def probe_timed_out(now_seconds, started_at, completed_at):
    """Judge the probe's work time, not when a busy supervisor reads its result."""
    return (started_at is not None and now_seconds - started_at > PRESSURE_PROBE_MAX_SECONDS
            and (completed_at is None or
                 completed_at - started_at > PRESSURE_PROBE_MAX_SECONDS))


def prefer_published_stop(current_reason, candidate_reason, candidate_at, deadline):
    """An earlier measured guard stop outranks a later client deadline."""
    if candidate_reason is None:
        return current_reason
    if (current_reason.startswith("client deadline") and finite_number(candidate_at) and
            candidate_at <= deadline):
        return candidate_reason
    return current_reason


def stop_cause_at_deadline(candidate_reason, published_at, deadline, checked_at):
    """Resolve a deadline crossed between the loop check and a stop branch."""
    if (checked_at >= deadline and
            (not finite_number(published_at) or published_at > deadline)):
        return CLIENT_DEADLINE_REASON
    return candidate_reason


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
    optional += " adaptiveSelection" if type(config) is dict and "adaptiveSelection" in config else ""
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
    if "adaptiveSelection" in config:
        selection = config["adaptiveSelection"]
        fields(selection, ADAPTIVE_FIELDS, "build.adaptive.fields")
        need(selection["schema"] == "openclaw.gcp-build-adaptive-selection.v1",
             "build.adaptive.schema")
        profile = selection["profile"]
        validate_profile(profile, config)
        need(profile in adaptive_profiles(config), "build.adaptive.profile_unreviewed")
        validate_adaptive_samples(selection["samples"], selection["selectedAt"])
        need(selection["profileSha256"] == release.sha256(encode(profile)) and
             all(sample["gatewayContainerId"] == selection["gatewayContainerId"]
                 for sample in selection["samples"]), "build.adaptive.binding")
        need(profile_fits(profile, selection["samples"]), "build.adaptive.selection_unfit")
        need(config["limits"]["minMemoryAvailableBytes"] ==
             profile["minMemoryAvailableBytes"] and
             config["limits"].get("minStartMemoryAvailableBytes") ==
             profile["minStartMemoryAvailableBytes"] and
             config["limits"].get("maxFullMemoryPressureAvg10") ==
             profile["maxFullMemoryPressureAvg10"] and
             config["limits"]["minFreeBytes"] == profile["minFreeBytes"] and
             config.get("buildTuning") ==
             {"tsdownMaxOldSpaceMb": profile["tsdownMaxOldSpaceMb"]} and
             cache is not None and cache["minFreeBytes"] == profile["minCacheFreeBytes"],
             "build.adaptive.config_changed")


def utc_time(value):
    preflight.utc(value)
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def validate_adaptive_samples(samples, selected_at):
    need(type(samples) is list and len(samples) == 3, "build.adaptive.sample_count")
    times = []
    for sample in samples:
        fields(sample, ADAPTIVE_SAMPLE_FIELDS, "build.adaptive.sample_fields")
        times.append(utc_time(sample["observedAt"]))
        for key in ("memoryAvailableBytes", "freeBytes", "cacheFreeBytes"):
            integer(sample[key], 0, 1 << 60, "build.adaptive.sample_resource")
        need(type(sample["fullMemoryPressureAvg10"]) in (int, float) and
             0 <= sample["fullMemoryPressureAvg10"] <= 100,
             "build.adaptive.sample_pressure")
        need(release.matches(preflight.HEX256, sample["gatewayContainerId"])
             and type(sample["gatewayHealthy"]) is bool
             and type(sample["gatewayOomKilled"]) is bool,
             "build.adaptive.gateway_state")
    selected = utc_time(selected_at)
    need(times == sorted(set(times)) and timedelta(seconds=10) <= times[-1] - times[0]
         <= timedelta(seconds=60) and timedelta(0) <= selected - times[-1]
         <= timedelta(seconds=30), "build.adaptive.sample_window")


def validate_profile(profile, config):
    fields(profile, PROFILE_FIELDS, "build.adaptive.profile_fields")
    need(release.matches(re.compile(r"[a-z][a-z0-9-]{2,40}\Z"), profile["id"])
         and profile["qualification"] == "candidate-unqualified",
         "build.adaptive.profile_status")
    need(profile["sourceSha"] == config["sourceSha"] and
         profile["sourceTree"] == config["sourceTree"] and
         profile["builderContainerId"] == config["builder"]["containerId"] and
         profile["builderSha256"] == release.sha256(encode(config["builder"])),
         "build.adaptive.profile_identity")
    integer(profile["tsdownMaxOldSpaceMb"], 4352, 12288,
            "build.adaptive.profile_heap")
    need((profile["tsdownMaxOldSpaceMb"] + 768) << 20 <
         config["builder"]["memoryBytes"], "build.adaptive.profile_worker_memory")
    for key in ("minStartMemoryAvailableBytes", "minMemoryAvailableBytes",
                "minFreeBytes", "minCacheFreeBytes"):
        integer(profile[key], 1, 1 << 50, "build.adaptive.profile_floor")
    qualification = profile["id"] == QUALIFICATION_PROFILE_ID
    minimum_start = QUALIFICATION_START_BYTES if qualification else 21 << 30
    minimum_running = QUALIFICATION_RUNNING_FLOOR_BYTES if qualification else 10 << 30
    need(profile["minStartMemoryAvailableBytes"] >= profile["minMemoryAvailableBytes"]
         >= minimum_running and profile["minStartMemoryAvailableBytes"] >= minimum_start,
         "build.adaptive.profile_reserve")
    if qualification:
        builder = config["builder"]
        current_floor = (profile["minMemoryAvailableBytes"] ==
                         QUALIFICATION_RUNNING_FLOOR_BYTES)
        retained_floor = (profile["minMemoryAvailableBytes"] == 10 << 30 and
                          profile["minStartMemoryAvailableBytes"] >= 18 << 30)
        need(profile["sourceSha"] in (QUALIFICATION_SOURCE_SHA,
                                      RETAINED_QUALIFICATION_SOURCE_SHA) and
             builder["memoryBytes"] == builder["memorySwapBytes"] == 8 << 30 and
             builder["cpuPeriod"] == 100000 and builder["cpuQuota"] == 400000 and
             profile["tsdownMaxOldSpaceMb"] == 6144 and
             (current_floor or retained_floor) and
             profile["maxFullMemoryPressureAvg10"] <= 5.0,
             "build.adaptive.qualification_identity")
    need(profile["minFreeBytes"] >= 16 << 30 and
         profile["minCacheFreeBytes"] >= 44 << 30,
         "build.adaptive.profile_disk_reserve")
    need(type(profile["maxFullMemoryPressureAvg10"]) in (int, float) and
         0.1 <= profile["maxFullMemoryPressureAvg10"] <= 5.0,
         "build.adaptive.profile_pressure")


def profile_fits(profile, samples):
    return all(sample["memoryAvailableBytes"] >=
               profile["minStartMemoryAvailableBytes"] and
               sample["freeBytes"] >= profile["minFreeBytes"] and
               sample["cacheFreeBytes"] >= profile["minCacheFreeBytes"] and
               sample["fullMemoryPressureAvg10"] <=
               profile["maxFullMemoryPressureAvg10"] and
               sample["gatewayHealthy"] and not sample["gatewayOomKilled"]
               for sample in samples)


def is_qualification_worker(config):
    builder = config["builder"]
    return (config["sourceSha"] in (QUALIFICATION_SOURCE_SHA,
                                    RETAINED_QUALIFICATION_SOURCE_SHA) and
            builder["memoryBytes"] == builder["memorySwapBytes"] == 8 << 30 and
            builder["cpuPeriod"] == 100000 and builder["cpuQuota"] == 400000)


def has_current_qualification_profile(config):
    profile = config.get("adaptiveSelection", {}).get("profile", {})
    return (profile.get("id") == QUALIFICATION_PROFILE_ID and
            type(profile.get("minStartMemoryAvailableBytes")) is int and
            profile["minStartMemoryAvailableBytes"] >= QUALIFICATION_START_BYTES and
            profile.get("minMemoryAvailableBytes") == QUALIFICATION_RUNNING_FLOOR_BYTES)


def adaptive_profiles(config):
    """Two unqualified, source-bound candidates; no inferred Doctor/build minimum."""
    need("cache" in config, "build.adaptive.cache_required")
    qualification = is_qualification_worker(config)
    common = {"qualification": "candidate-unqualified",
              "sourceSha": config["sourceSha"], "sourceTree": config["sourceTree"],
              "builderContainerId": config["builder"]["containerId"],
              "builderSha256": release.sha256(encode(config["builder"])),
              "minMemoryAvailableBytes": max(
                  QUALIFICATION_RUNNING_FLOOR_BYTES if qualification else 10 << 30,
                  config["limits"]["minMemoryAvailableBytes"]),
              "maxFullMemoryPressureAvg10": min(
                  5.0, config["limits"].get("maxFullMemoryPressureAvg10", 5.0)),
              "minFreeBytes": max(16 << 30, config["limits"]["minFreeBytes"]),
              "minCacheFreeBytes": max(44 << 30, config["cache"]["minFreeBytes"])}
    if qualification:
        # User-selected 10 GiB start = 8 GiB hard worker cap plus 2 GiB
        # nominal residual. Stopped-builder availability moved 5.15 GiB in
        # 15 seconds, so this is a risky qualification, not a safe minimum.
        profile = {**common, "id": QUALIFICATION_PROFILE_ID,
                   "tsdownMaxOldSpaceMb": 6144,
                   "minStartMemoryAvailableBytes": max(
                       QUALIFICATION_START_BYTES,
                       config["limits"].get("minStartMemoryAvailableBytes", 0),
                       common["minMemoryAvailableBytes"])}
        validate_profile(profile, config)
        return [profile]
    # 21 GiB is a qualification candidate: a prior complete image build started
    # at 20.53 GiB, while the failed solve lost 8.19 GiB of host availability.
    # Neither measurement establishes a whole-build minimum or peak.
    prior_start = config["limits"].get("minStartMemoryAvailableBytes", 0)
    profiles = [{**common, "id": "constrained-21g", "tsdownMaxOldSpaceMb": 6144,
                 "minStartMemoryAvailableBytes": max(
                     21 << 30, prior_start, common["minMemoryAvailableBytes"])},
                {**common, "id": "roomy-26g", "tsdownMaxOldSpaceMb": 12288,
                 "minStartMemoryAvailableBytes": max(
                     26 << 30, prior_start, common["minMemoryAvailableBytes"])}]
    eligible = []
    for profile in profiles:
        if (profile["tsdownMaxOldSpaceMb"] + 768) << 20 >= config["builder"]["memoryBytes"]:
            continue
        validate_profile(profile, config)
        eligible.append(profile)
    return eligible


def select_profile(config, samples):
    validate_adaptive_samples(samples, now())
    if (is_qualification_worker(config) and
            config["sourceSha"] != QUALIFICATION_SOURCE_SHA):
        return None  # Retained source is readable for recovery, not newly selectable.
    fitting = [profile for profile in adaptive_profiles(config)
               if profile_fits(profile, samples)]
    if not fitting:
        return None
    # Spend spare headroom on the larger heap only when every fresh sample fits.
    return max(fitting, key=lambda profile: profile["minStartMemoryAvailableBytes"])


def bind_adaptive_selection(config, samples):
    """Return a new immutable config, or None without reserving/creating a job."""
    need("adaptiveSelection" not in config, "build.adaptive.already_selected")
    profile = select_profile(config, samples)
    if profile is None:
        return None
    bound = json.loads(json.dumps(config))
    bound["limits"].update({key: profile[key] for key in (
        "minStartMemoryAvailableBytes", "minMemoryAvailableBytes",
        "maxFullMemoryPressureAvg10", "minFreeBytes")})
    bound["cache"]["minFreeBytes"] = profile["minCacheFreeBytes"]
    bound["buildTuning"] = {"tsdownMaxOldSpaceMb": profile["tsdownMaxOldSpaceMb"]}
    bound["adaptiveSelection"] = {
        "schema": "openclaw.gcp-build-adaptive-selection.v1", "profile": profile,
        "profileSha256": release.sha256(encode(profile)),
        "gatewayContainerId": samples[0]["gatewayContainerId"],
        "samples": samples, "selectedAt": now()}
    validate_config(bound)
    return bound


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
    need(not is_qualification_worker(config) or
         config["sourceSha"] == QUALIFICATION_SOURCE_SHA,
         "build.qualification.retained_source_only")
    need(not is_qualification_worker(config) or has_current_qualification_profile(config),
         "build.qualification.current_profile_required")
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
            need(type(proposed) is dict, "workload.build.recovery_fields")
            successor_intent = read_private(successor / "intent.json")
            if proposed.get("schema") == "openclaw.gcp-builder-prepared-handoff.v1":
                proposed = prepared_recovery_proposal(successor, proposed,
                                                     successor_intent)
            need(proposed.get("schema") == "openclaw.gcp-builder-recovery.v1" and
                 proposed.get("originOperationId") == op.name and
                 proposed.get("originIntentSha256") == owner["intentSha256"] and
                 proposed.get("originCompletedSha256") ==
                 preflight.digest(op / "completed.json"),
                 "workload.build.recovery_changed")
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


def gateway_sample(container_id):
    need(release.matches(preflight.HEX256, container_id),
         "build.adaptive.gateway_identity")
    result = native([*DOCKER, "inspect", "--format",
                     '{"Id":{{json .Id}},"Name":{{json .Name}},'
                     '"State":{{json .State}}}', PRODUCTION_GATEWAY_NAME])
    need(result.returncode == 0, "build.adaptive.gateway_inspect")
    observed = json.loads(result.stdout)
    need(type(observed) is dict and observed.get("Id") == container_id and
         observed.get("Name") == "/" + PRODUCTION_GATEWAY_NAME,
         "build.adaptive.gateway_identity_changed")
    state = observed.get("State")
    need(type(state) is dict and type(state.get("Running")) is bool and
         type(state.get("OOMKilled")) is bool and
         type(state.get("Health")) is dict and
         type(state["Health"].get("Status")) is str,
         "build.adaptive.gateway_observation")
    health = state["Health"]
    duration_ms = None
    age_seconds = None
    age_measured_at = None
    logs = health.get("Log", [])
    if type(logs) is list and logs and type(logs[-1]) is dict:
        try:
            start = datetime.fromisoformat(logs[-1]["Start"].replace("Z", "+00:00"))
            end = datetime.fromisoformat(logs[-1]["End"].replace("Z", "+00:00"))
            need(end >= start, "build.gateway.health_time")
            duration_ms = round((end - start).total_seconds() * 1000, 1)
            age_seconds = (datetime.now(timezone.utc) - end).total_seconds()
            age_measured_at = time.monotonic()
            need(0 <= age_seconds <= 86400, "build.gateway.health_time")
        except (KeyError, TypeError, ValueError):
            need(False, "build.gateway.health_time")
    return {"gatewayContainerId": container_id,
            "gatewayHealthy": state["Running"] and
            state["Health"]["Status"] == "healthy",
            "gatewayOomKilled": state["OOMKilled"],
            "lastHealthCheckDurationMs": duration_ms,
            "lastHealthCheckAgeSeconds": age_seconds,
            "lastHealthCheckAgeMeasuredAtMonotonicSeconds": age_measured_at}


def gateway_runtime_sample(container_id):
    """Only counters and health timing; never persist health output or secrets."""
    state = gateway_sample(container_id)
    path = CGROUP_SLICE / f"docker-{container_id}.scope"
    need(path.is_dir() and not path.is_symlink(), "build.gateway.cgroup_unavailable")
    memory = dict(line.split(None, 1) for line in
                  cgroup_text(path / "memory.stat").splitlines())
    events = dict(line.split(None, 1) for line in
                  cgroup_text(path / "memory.events").splitlines())
    pressure = {}
    for line in cgroup_text(path / "memory.pressure").splitlines():
        name, _, rest = line.partition(" ")
        if name in ("some", "full"):
            values = dict(part.split("=", 1) for part in rest.split())
            pressure[name] = float(values["avg10"])
    need("full" in pressure, "build.gateway.pressure_unavailable")
    return {**state, "memoryCurrentBytes": int(cgroup_text(path / "memory.current")),
            "anonBytes": int(memory["anon"]), "fileBytes": int(memory["file"]),
            "oom": int(events["oom"]), "oomKill": int(events["oom_kill"]),
            "fullMemoryPressureAvg10": pressure["full"]}


def collect_adaptive_samples(op, cache, gateway_container_id):
    need(cache is not None, "build.adaptive.cache_required")
    samples = []
    for index in range(3):
        if index:
            time.sleep(5)
        observed = resource_sample(op, cache)
        need("memoryPressure" in observed and "cacheFreeBytes" in observed,
             "build.adaptive.metrics_unavailable")
        samples.append({"observedAt": observed["observedAt"],
                        "memoryAvailableBytes": observed["memoryAvailableBytes"],
                        "freeBytes": observed["freeBytes"],
                        "cacheFreeBytes": observed["cacheFreeBytes"],
                        "fullMemoryPressureAvg10":
                        observed["memoryPressure"]["full"]["avg10"],
                        **{key: value for key, value in
                           gateway_sample(gateway_container_id).items()
                           if key not in ("lastHealthCheckDurationMs",
                                          "lastHealthCheckAgeSeconds",
                                          "lastHealthCheckAgeMeasuredAtMonotonicSeconds")}})
    validate_adaptive_samples(samples, now())
    return samples


def capacity(op, limits, cache=None, *, starting=False,
             gateway_container_id=None, builder=None, defer_pressure=False):
    need(defer_pressure is False or
         (defer_pressure is True and gateway_container_id is not None and builder is not None),
         "build.pressure.defer_unscoped")
    observed = resource_sample(op, cache)
    need(observed["freeBytes"] >= limits["minFreeBytes"], "build.capacity.disk_reserve")
    need(observed["memoryAvailableBytes"] >= limits["minMemoryAvailableBytes"],
         "build.capacity.memory_reserve")
    if starting and "minStartMemoryAvailableBytes" in limits:
        need(observed["memoryAvailableBytes"] >= limits["minStartMemoryAvailableBytes"],
             "build.capacity.start_memory_reserve")
    if "maxFullMemoryPressureAvg10" in limits:
        need("memoryPressure" in observed, "build.capacity.pressure_unavailable")
        if not defer_pressure:
            need(observed["memoryPressure"]["full"]["avg10"] <=
                 limits["maxFullMemoryPressureAvg10"], "build.capacity.memory_pressure")
    if cache is not None:
        need(observed["cacheFreeBytes"] >= cache["minFreeBytes"], "build.capacity.cache_reserve")
    if gateway_container_id is not None:
        gateway = gateway_runtime_sample(gateway_container_id)
        need(gateway["gatewayHealthy"] and not gateway["gatewayOomKilled"] and
             gateway["oom"] == 0 and gateway["oomKill"] == 0,
             "build.capacity.gateway_health")
        observed["gateway"] = gateway
    if builder is not None:
        worker = builder_sample(builder)
        need(worker["oom"] == worker["oomKill"] == 0,
             "build.capacity.worker_oom")
        observed["builder"] = worker
    return observed


def running_pressure_sample(observed, at_seconds, completed_at_seconds):
    """Translate the already checked pinned Gateway/worker observation."""
    gateway, worker = observed["gateway"], observed["builder"]
    age = gateway["lastHealthCheckAgeSeconds"]
    if age is not None:
        measured_at = gateway["lastHealthCheckAgeMeasuredAtMonotonicSeconds"]
        need(finite_number(measured_at) and
             at_seconds <= measured_at <= completed_at_seconds,
             "build.pressure.health_clock_invalid")
        age += completed_at_seconds - measured_at
    return PressureSample(
        at_seconds, observed["memoryPressure"]["full"]["avg10"],
        observed["memoryAvailableBytes"], gateway["gatewayHealthy"],
        gateway["gatewayOomKilled"] or gateway["oom"] != 0 or gateway["oomKill"] != 0,
        worker["oom"] != 0 or worker["oomKill"] != 0,
        gateway["lastHealthCheckDurationMs"], age)


def evaluate_pressure_observation(observed, started_at, completed_at, state, *,
                                  hard_floor_bytes=10 << 30,
                                  risk_floor_bytes=PRESSURE_HEADROOM_RISK_BYTES):
    """Evaluate one completed probe before the output-forwarding loop can block."""
    try:
        sample = running_pressure_sample(observed, started_at, completed_at)
        return pressure_guard_evaluate(sample, state,
                                       hard_floor_bytes=hard_floor_bytes,
                                       risk_floor_bytes=risk_floor_bytes)
    except Exception as error:
        if type(observed) is dict:
            observed["pressureError"] = type(error).__name__
        return PressureDecision("stop", "build.pressure.telemetry_invalid"), state


def running_capacity_probe(op, config, gateway_id, output, lock, shared):
    """One read-only sample in a daemon thread; the supervisor owns the clock."""
    try:
        observed = capacity(op, config["limits"], config.get("cache"),
                            gateway_container_id=gateway_id, builder=config["builder"],
                            defer_pressure=True)
        result = (True, observed)
    except Exception as error:
        result = (False, str(error))
    with lock:
        sampled_at = time.monotonic()
        old_state = shared["state"]
        decision = None
        if result[0]:
            qualification = (config.get("adaptiveSelection", {}).get("profile", {}).get("id") ==
                             QUALIFICATION_PROFILE_ID)
            decision, shared["state"] = evaluate_pressure_observation(
                result[1], shared["probe_started"], sampled_at, old_state,
                hard_floor_bytes=(QUALIFICATION_RUNNING_FLOOR_BYTES if qualification
                                  else 10 << 30),
                risk_floor_bytes=(QUALIFICATION_PRESSURE_RISK_BYTES if qualification
                                  else PRESSURE_HEADROOM_RISK_BYTES))
            shared["last_observation"] = copy.deepcopy(result[1])
            if decision.action == "stop":
                result[1]["pressureDecision"] = {
                    "action": decision.action, "reason": decision.reason}
                publish_pressure_stop(shared, decision.reason, result[1])
        else:
            publish_pressure_stop(shared, result[1] or "build.capacity.probe_failed")
        # Completion means the full result is available in shared state.
        # Include evaluation/copy work, but exclude later queue-read delay.
        shared["probe_completed_at"] = time.monotonic()
        completed_at = shared["probe_completed_at"]
    output.put((*result, completed_at, decision, old_state))


def publish_pressure_stop(shared, reason, observation=None, *, published_at=None):
    """Keep the first guard cause, its time, and its evidence together."""
    if shared.get("published_stop_reason") is None:
        if observation is None:
            basis = shared.get("stop_observation")
            if (basis is not None and
                    basis.get("pressureDecision", {}).get("reason") != reason):
                basis = None
            if basis is None and reason.startswith("build.pressure."):
                basis = shared.get("last_observation")
            evidence = copy.deepcopy(basis) if basis is not None else {"observedAt": now()}
        else:
            evidence = copy.deepcopy(observation)
        evidence["pressureDecision"] = {"action": "stop", "reason": reason}
        # No potentially slow evidence work follows the publication clock.
        if published_at is None:
            published_at = time.monotonic()
        evidence["pressureDecision"]["publishedAtMonotonicSeconds"] = published_at
        shared["stop_observation"] = evidence
        shared["stop_at_monotonic"] = published_at
        shared["published_stop_reason"] = reason
    return shared["published_stop_reason"]


def publish_stale_probe_if_needed(shared, started_at, checked_at):
    """Caller holds the pressure lock across completion check and publication."""
    if not probe_timed_out(checked_at, started_at, shared["probe_completed_at"]):
        return False
    publish_pressure_stop(shared, "build.pressure.telemetry_stale")
    return True


def stop_resource_evidence(first_reason, first_at, first_observation,
                           receipt_cause, event_reason):
    """Keep first-stop provenance distinct from a later event or deadline."""
    evidence = (copy.deepcopy(first_observation) if first_observation is not None
                else {"observedAt": now()})
    evidence["firstPublishedStop"] = {
        "reason": first_reason, "publishedAtMonotonicSeconds": first_at}
    evidence["eventReason"] = event_reason
    evidence["receiptCause"] = receipt_cause
    return evidence


def running_pressure_watchdog(stop_event, lock, shared, child):
    """Cancel only the owned client if samples or the probe clock outlive bounds."""
    while not stop_event.wait(0.25):
        if child.poll() is not None:
            return
        with lock:
            now_seconds = time.monotonic()
            decision = pressure_watchdog(now_seconds, shared["state"])
            probe_started = shared["probe_started"]
            if shared.get("published_stop_reason") is not None:
                decision = PressureDecision("stop", shared["published_stop_reason"])
            elif probe_timed_out(now_seconds, probe_started, shared["probe_completed_at"]):
                decision = PressureDecision("stop", "build.pressure.telemetry_stale")
            if decision.action == "stop":
                if child.poll() is None:
                    child.terminate()
                if shared["reason"] is None:
                    shared["reason"] = publish_pressure_stop(
                        shared, decision.reason)
        if decision.action == "stop":
            # Output forwarding may block the main loop. Own escalation here
            # too, and target only this client PID after its normal grace.
            if (not stop_event.wait(CLIENT_TERM_GRACE_SECONDS) and
                    child.poll() is None):
                child.kill()
            return


def cgroup_text(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor) as stream:
        need(stat.S_ISREG(os.fstat(stream.fileno()).st_mode),
             "build.telemetry.not_regular")
        return stream.read(16384)


def verify_builder_cgroup_limits(builder):
    """Verify the effective v2 ancestors before the experimental 8 GiB solve."""
    result = native([*DOCKER, "inspect", "--format",
                     '{"Id":{{json .Id}},"State":{"Running":{{json .State.Running}},'
                     '"Pid":{{json .State.Pid}}}}', builder["containerId"]])
    need(result.returncode == 0, "build.qualification.builder_inspect")
    row = json.loads(result.stdout)
    need(row["Id"] == builder["containerId"] and
         row["State"]["Running"] is True and
         type(row["State"]["Pid"]) is int and row["State"]["Pid"] > 0,
         "build.qualification.builder_identity")
    relative = cgroup_text(Path("/proc") / str(row["State"]["Pid"]) / "cgroup")
    lines = [line.split("::", 1)[1] for line in relative.splitlines()
             if line.startswith("0::/")]
    need(len(lines) == 1, "build.qualification.cgroup_path")
    root = CGROUP_ROOT
    path = (root / lines[0].lstrip("/")).resolve(strict=True)
    need(root in path.parents and f"docker-{builder['containerId']}.scope" in path.parts,
         "build.qualification.cgroup_identity")
    hierarchy = []
    for ancestor in (path, *path.parents):
        # The cgroup v2 root has no resource-control files of its own.
        if ancestor == root:
            break
        memory = cgroup_text(ancestor / "memory.max").strip()
        swap = cgroup_text(ancestor / "memory.swap.max").strip()
        cpu = cgroup_text(ancestor / "cpu.max").split()
        need(len(cpu) == 2, "build.qualification.cpu_limit")
        hierarchy.append({"path": str(ancestor), "memoryMax": memory,
                          "memorySwapMax": swap, "cpuMax": " ".join(cpu)})
    finite_memory = [int(item["memoryMax"]) for item in hierarchy
                     if item["memoryMax"] != "max"]
    finite_swap = [int(item["memorySwapMax"]) for item in hierarchy
                   if item["memorySwapMax"] != "max"]
    finite_cpu = [Fraction(int(item["cpuMax"].split()[0]),
                           int(item["cpuMax"].split()[1])) for item in hierarchy
                  if not item["cpuMax"].startswith("max ")]
    scope = next((item for item in hierarchy if Path(item["path"]).name ==
                  f"docker-{builder['containerId']}.scope"), None)
    need(scope is not None and
         scope["memoryMax"] == str(builder["memoryBytes"]) and
         scope["memorySwapMax"] == "0" and
         scope["cpuMax"].split()[0] != "max" and
         Fraction(*map(int, scope["cpuMax"].split())) == Fraction(4, 1),
         "build.qualification.worker_scope_limits")
    need(finite_memory and min(finite_memory) == builder["memoryBytes"] and
         finite_swap and min(finite_swap) == 0 and
         finite_cpu and min(finite_cpu) == Fraction(4, 1),
         "build.qualification.effective_limits")
    return {"containerId": builder["containerId"], "pid": row["State"]["Pid"],
            "effectiveMemoryBytes": min(finite_memory),
            "effectiveSwapBytes": min(finite_swap),
            "effectiveCpuQuota": "4/1", "hierarchy": hierarchy}


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


def prepared_binding_compatible(origin, target):
    """Permit one exact retained-source cutover on an already bound 8 GiB worker.

    Each operation keeps its own immutable intent, manifest and inventory. This
    exception changes neither the builder lease nor the cache ownership.
    """
    old, new = origin["config"], target["config"]
    if old.get("builder") != new.get("builder") or old.get("cache") != new.get("cache"):
        return False
    bindings = ("sourceSha", "sourceTree", "manifestSha256", "inventorySha256")
    if all(old.get(key) == new.get(key) for key in bindings):
        return True
    return (old.get("sourceSha") == RETAINED_QUALIFICATION_SOURCE_SHA and
            new.get("sourceSha") == QUALIFICATION_SOURCE_SHA and
            is_qualification_worker(new) and
            has_current_qualification_profile(new) and
            release.matches(release.SHA, old.get("sourceTree", "")) and
            release.matches(release.SHA, new.get("sourceTree", "")) and
            all(release.matches(preflight.HEX256, old.get(key, "")) and
                release.matches(preflight.HEX256, new.get(key, ""))
                for key in ("manifestSha256", "inventorySha256")))


def prepared_recovery_proposal(op, proposed, intent, *, max_handoffs=4):
    """Verify at most four never-dispatched handoffs back to one failed recovery."""
    need(type(max_handoffs) is int and 1 <= max_handoffs <= 4,
         "build.handoff.prepared_depth_limit")
    seen = {op.name}
    for _ in range(max_handoffs):
        fields(proposed, """schema originOperationId targetOperationId
               originIntentSha256 targetIntentSha256 originHandoffSha256
               originLeaseSha256""", "build.handoff.prepared_fields")
        old_id = proposed["originOperationId"]
        need(release.matches(re.compile(r"[0-9a-f]{32}\Z"), old_id) and
             old_id not in seen, "build.handoff.prepared_cycle")
        seen.add(old_id)
        old = op.parent / old_id
        need(old.is_dir() and old.resolve() == old and
             all(not (old / name).exists() for name in
                 ("start-intent.json", "started.json", "execution.json", "completed.json")),
             "build.handoff.prepared_dispatched")
        origin = read_private(old / "intent.json")
        old_proposal = read_private(old / "builder-handoff-intent.json")
        old_receipt = read_private(old / "builder-handoff.json")
        need(all(type(item) is dict for item in (origin, old_proposal, old_receipt)),
             "build.handoff.prepared_origin_fields")
        old_lease = {"operationId": old.name,
                     "intentSha256": preflight.digest(old / "intent.json")}
        need(proposed["targetOperationId"] == op.name and
             proposed["originIntentSha256"] == old_lease["intentSha256"] and
             proposed["originHandoffSha256"] ==
             preflight.digest(old / "builder-handoff.json") and
             proposed["originLeaseSha256"] == release.sha256(encode(old_lease)) and
             old_proposal.get("targetOperationId") == old.name and
             old_receipt == {**old_proposal,
                             "targetLeaseSha256": release.sha256(encode(old_lease))} and
             prepared_binding_compatible(origin, intent),
             "build.handoff.prepared_origin_changed")
        if old_proposal.get("schema") == "openclaw.gcp-builder-recovery.v1":
            failed_id = old_proposal["originOperationId"]
            need(release.matches(re.compile(r"[0-9a-f]{32}\Z"), failed_id),
                 "build.handoff.recovery_origin_id")
            failed = op.parent / failed_id
            failed_intent = read_private(failed / "intent.json")
            need(type(failed_intent) is dict,
                 "build.handoff.recovery_origin_fields")
            failed_lease = {"operationId": failed.name,
                            "intentSha256": preflight.digest(failed / "intent.json")}
            need(old_proposal.get("originIntentSha256") == failed_lease["intentSha256"] and
                 old_proposal.get("originLeaseSha256") ==
                 release.sha256(encode(failed_lease)) and
                 old_proposal.get("originCompletedSha256") ==
                 preflight.digest(failed / "completed.json") and
                 old_proposal.get("builderStoppedSha256") ==
                 preflight.digest(old / "builder-stopped.json"),
                 "build.handoff.prepared_recovery_changed")
            transition_path = old / "resource-transition.json"
            repair_path = old / "resource-transition-repair-intent.json"
            if "resourceTransitionSha256" in old_proposal:
                transition = read_private(transition_path)
                need(type(transition) is dict and
                     old_proposal["resourceTransitionSha256"] ==
                     preflight.digest(transition_path) and
                     transition.get("originOperationId") == failed.name and
                     transition.get("targetOperationId") == old.name and
                     transition.get("originIntentSha256") == failed_lease["intentSha256"] and
                     transition.get("targetIntentSha256") == old_lease["intentSha256"] and
                     transition.get("builderStoppedSha256") ==
                     old_proposal["builderStoppedSha256"] and
                     transition.get("originBuilderSha256") ==
                     release.sha256(encode(failed_intent["config"]["builder"])) and
                     transition.get("targetBuilderSha256") ==
                     transition.get("observedBuilderSha256") ==
                     release.sha256(encode(intent["config"]["builder"])) and
                     repair_path.exists() == ("repairIntentSha256" in transition) and
                     (not repair_path.exists() or
                      preflight.digest(repair_path) == transition["repairIntentSha256"]) and
                     preflight.digest(old / "resource-transition-intent.json") ==
                     release.sha256(encode({key: value for key, value in transition.items()
                                            if key not in ("observedBuilderSha256",
                                                           "repairIntentSha256")})),
                     "build.handoff.prepared_recovery_changed")
            else:
                need(failed_intent["config"]["builder"] == intent["config"]["builder"] and
                     not any((old / name).exists() for name in
                             ("resource-transition-intent.json", "resource-transition.json",
                              "resource-transition-repair-intent.json")),
                     "build.handoff.prepared_recovery_changed")
            return old_proposal
        need(old_proposal.get("schema") == "openclaw.gcp-builder-prepared-handoff.v1",
             "build.handoff.prepared_origin_schema")
        op, proposed = old, old_proposal
    need(False, "build.handoff.prepared_depth")


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
        optional = (" resourceTransitionSha256" if
                    "resourceTransitionSha256" in proposed else "")
        fields(proposed, """schema originOperationId targetOperationId originIntentSha256
               targetIntentSha256 originCompletedSha256 builderStoppedSha256 originLeaseSha256"""
               + optional,
               "build.handoff.intent.fields")
        need(preflight.digest(op / "builder-stopped.json") == proposed["builderStoppedSha256"],
             "build.handoff.stop_proof.changed")
        old = op.parent / proposed["originOperationId"]
        origin = read_private(old / "intent.json")
        need((origin["config"]["builder"] != intent["config"]["builder"]) ==
             bool(optional), "build.handoff.resource_transition_required")
        if optional:
            transition = read_private(op / "resource-transition.json")
            repair = (" repairIntentSha256" if "repairIntentSha256" in transition else "")
            fields(transition, """schema originOperationId targetOperationId
                   originIntentSha256 targetIntentSha256 builderStoppedSha256
                   originBuilderSha256 targetBuilderSha256 observedBuilderSha256"""
                   + repair,
                   "build.handoff.resource_transition_fields")
            need(transition["schema"] == "openclaw.gcp-builder-resource-transition.v1" and
                 transition["originOperationId"] == old.name and
                 transition["targetOperationId"] == op.name and
                 transition["originIntentSha256"] == preflight.digest(old / "intent.json") and
                 transition["targetIntentSha256"] == preflight.digest(op / "intent.json") and
                 transition["builderStoppedSha256"] == proposed["builderStoppedSha256"] and
                 transition["originBuilderSha256"] ==
                 release.sha256(encode(origin["config"]["builder"])) and
                 transition["targetBuilderSha256"] ==
                 transition["observedBuilderSha256"] ==
                 release.sha256(encode(intent["config"]["builder"])) and
                 ((op / "resource-transition-repair-intent.json").exists() == bool(repair)) and
                 (not repair or preflight.digest(op / "resource-transition-repair-intent.json") ==
                  transition["repairIntentSha256"]) and
                 preflight.digest(op / "resource-transition-intent.json") ==
                 release.sha256(encode({key: value for key, value in transition.items()
                                        if key not in ("observedBuilderSha256",
                                                       "repairIntentSha256")})) and
                 preflight.digest(op / "resource-transition.json") ==
                 proposed["resourceTransitionSha256"],
                 "build.handoff.resource_transition_changed")
    elif proposed.get("schema") == "openclaw.gcp-builder-prepared-handoff.v1":
        prepared_recovery_proposal(op, proposed, intent)
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
        if "resourceTransitionSha256" in proposed:
            evidence.extend((op / "resource-transition-intent.json",
                             op / "resource-transition.json"))
            if (op / "resource-transition-repair-intent.json").exists():
                evidence.append(op / "resource-transition-repair-intent.json")
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
        need(not is_qualification_worker(config) or
             config["sourceSha"] == QUALIFICATION_SOURCE_SHA,
             "build.qualification.retained_source_only")
        need(not is_qualification_worker(config) or has_current_qualification_profile(config),
             "build.qualification.current_profile_required")
        verify_builder_handoff(op, intent)
        source_binding(config, op / "manifest.json", op / "patch-inventory.json",
                       intent["sourceDir"])
        need(tooling_bytes(intent["toolingDir"], config["toolingSha"]) ==
             {name: private_bytes(op / "supervisor" / name) for name in HELPERS},
             "build.tooling.changed")
        observe_builder(config["builder"], config.get("cache"))
        adaptive_samples = None
        qualification = (config.get("adaptiveSelection", {}).get("profile", {}).get("id") ==
                         QUALIFICATION_PROFILE_ID)
        cgroup_proof = (verify_builder_cgroup_limits(config["builder"])
                        if qualification else None)
        if "adaptiveSelection" in config:
            adaptive_samples = collect_adaptive_samples(
                op, config["cache"],
                config["adaptiveSelection"]["gatewayContainerId"])
            need(profile_fits(config["adaptiveSelection"]["profile"], adaptive_samples),
                 "build.adaptive.start_no_fit")
        reserve = capacity(op, config["limits"], config.get("cache"), starting=True,
                           gateway_container_id=(
                               config["adaptiveSelection"]["gatewayContainerId"]
                               if qualification else None),
                           builder=config["builder"] if qualification else None)
        metadata_handoff_capability(op, intent)
        reserve_heavy_workload(op, "build", preflight.digest(op / "intent.json"),
                               reserve_resource=lambda: reserve_builder(op, intent))
        write_once(op / "start-intent.json", encode({
            "intentSha256": preflight.digest(op / "intent.json"), "requestedAt": now(),
            "unitName": intent["unitName"], "capacity": reserve,
            **({"adaptiveSamples": adaptive_samples} if adaptive_samples is not None else {}),
            **({"builderCgroupLimits": cgroup_proof} if cgroup_proof is not None else {})}))
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
    pressure_stop = threading.Event()
    pressure_lock = threading.Lock()
    pressure_shared = {"state": None, "reason": None, "probe_started": None,
                       "probe_completed_at": None, "published_stop_reason": None,
                       "stop_observation": None, "last_observation": None,
                       "stop_at_monotonic": None}
    pressure_thread = None
    pressure_reported = False
    probe_thread = None
    probe_output = None
    probe_started = None

    def cancel(signum, _frame):
        signal_received.append(signum)
        if child is not None and child.poll() is None:
            child.terminate()

    for signum in (signal.SIGTERM, signal.SIGINT):
        previous[signum] = signal.signal(signum, cancel)
    native_exit, exit_code, reason = None, 1, "client failed before launch"
    cache = intent["config"].get("cache")
    config = intent["config"]
    qualification = (config.get("adaptiveSelection", {}).get("profile", {}).get("id") ==
                     QUALIFICATION_PROFILE_ID)
    need(not is_qualification_worker(config) or has_current_qualification_profile(config),
         "build.qualification.current_profile_required")
    gateway_id = (config["adaptiveSelection"]["gatewayContainerId"]
                  if qualification else None)
    try:
        reserve_heavy_workload(op, "build", preflight.digest(op / "intent.json"))
        observe_builder(intent["config"]["builder"], cache)
        if qualification:
            need(verify_builder_cgroup_limits(config["builder"]) ==
                 start_intent.get("builderCgroupLimits"),
                 "build.qualification.cgroup_changed")
        if "adaptiveSelection" in intent["config"]:
            selection = intent["config"]["adaptiveSelection"]
            samples = collect_adaptive_samples(
                op, cache, selection["gatewayContainerId"])
            need(profile_fits(selection["profile"], samples),
                 "build.adaptive.service_no_fit")
        record_resources(op, "start", capacity(op, config["limits"], cache,
                                                starting=True, gateway_container_id=gateway_id,
                                                builder=config["builder"] if qualification else None),
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
            if qualification:
                pressure_shared["state"] = PressureState(last_at=next_capacity)
                pressure_thread = threading.Thread(
                    target=running_pressure_watchdog,
                    args=(pressure_stop, pressure_lock, pressure_shared, child),
                    name="build-pressure-watchdog", daemon=True)
                pressure_thread.start()
            try:
                while (selector.get_map() or child.poll() is None or
                       (qualification and probe_thread is not None and stop_at is None)):
                    if time.monotonic() >= deadline and stop_at is None:
                        reason = CLIENT_DEADLINE_REASON
                        child.terminate()
                        stop_at = time.monotonic() + CLIENT_TERM_GRACE_SECONDS
                    if qualification and not pressure_reported:
                        with pressure_lock:
                            watchdog_reason = pressure_shared["published_stop_reason"]
                            stop_observation = pressure_shared["stop_observation"]
                            published_at = pressure_shared["stop_at_monotonic"]
                        if watchdog_reason is not None:
                            if stop_at is None:
                                reason = stop_cause_at_deadline(
                                    watchdog_reason, published_at, deadline,
                                    time.monotonic())
                                if child.poll() is None:
                                    child.terminate()
                                stop_at = time.monotonic() + CLIENT_TERM_GRACE_SECONDS
                            else:
                                reason = prefer_published_stop(
                                    reason, watchdog_reason, published_at, deadline)
                            record_resources(op, "pressure-watchdog-stop",
                                             stop_resource_evidence(
                                                 watchdog_reason, published_at,
                                                 stop_observation, reason, watchdog_reason),
                                             builder=config["builder"])
                            pressure_reported = True
                    if qualification and stop_at is None:
                        if stop_at is None and probe_thread is None and time.monotonic() >= next_capacity:
                            probe_output = queue.SimpleQueue()
                            probe_thread = threading.Thread(
                                target=running_capacity_probe,
                                args=(op, config, gateway_id, probe_output,
                                      pressure_lock, pressure_shared),
                                name="build-capacity-probe", daemon=True)
                            probe_started = time.monotonic()
                            with pressure_lock:
                                pressure_shared["probe_started"] = probe_started
                                pressure_shared["probe_completed_at"] = None
                            probe_thread.start()
                            next_capacity = probe_started + 2
                        stale_stop = False
                        if stop_at is None and probe_thread is not None:
                            with pressure_lock:
                                stale_at = time.monotonic()
                                stale_stop = publish_stale_probe_if_needed(
                                    pressure_shared, probe_started, stale_at)
                                if stale_stop:
                                    published_reason = pressure_shared["published_stop_reason"]
                                    published_at = pressure_shared["stop_at_monotonic"]
                                    stop_observation = pressure_shared["stop_observation"]
                        if stale_stop:
                            reason = stop_cause_at_deadline(
                                published_reason, published_at,
                                deadline, time.monotonic())
                            if child.poll() is None:
                                child.terminate()
                            stop_at = time.monotonic() + CLIENT_TERM_GRACE_SECONDS
                            record_resources(op, "probe-stale",
                                             stop_resource_evidence(
                                                 published_reason, published_at,
                                                 stop_observation, reason,
                                                 "build.pressure.telemetry_stale"),
                                             builder=config["builder"])
                        if stop_at is None and probe_thread is not None:
                            try:
                                succeeded, result, completed_at, decision, old_state = (
                                    probe_output.get_nowait())
                            except queue.Empty:
                                pass
                            else:
                                probe_thread = None
                                with pressure_lock:
                                    pressure_shared["probe_started"] = None
                                    pressure_shared["probe_completed_at"] = None
                                if not (finite_number(completed_at) and
                                        probe_started <= completed_at <= time.monotonic()):
                                    succeeded, result = False, "build.pressure.probe_clock_invalid"
                                if succeeded and (type(decision) is not PressureDecision or
                                                  type(old_state) is not PressureState):
                                    succeeded, result = False, "build.pressure.probe_decision_invalid"
                                if not succeeded:
                                    with pressure_lock:
                                        published_reason = pressure_shared["published_stop_reason"]
                                        published_at = pressure_shared["stop_at_monotonic"]
                                        if published_reason is None:
                                            published_reason = publish_pressure_stop(
                                                pressure_shared,
                                                result or "build.capacity.probe_failed")
                                            published_at = pressure_shared["stop_at_monotonic"]
                                        stop_observation = pressure_shared["stop_observation"]
                                    reason = stop_cause_at_deadline(
                                        published_reason or result or "build.capacity.probe_failed",
                                        published_at, deadline, time.monotonic())
                                    if child.poll() is None:
                                        child.terminate()
                                    stop_at = time.monotonic() + CLIENT_TERM_GRACE_SECONDS
                                    record_resources(op, "reserve-failed",
                                                     stop_resource_evidence(
                                                         published_reason, published_at,
                                                         stop_observation, reason,
                                                         result or "build.capacity.probe_failed"),
                                                     builder=config["builder"])
                                else:
                                    observed = result
                                    sampled_at = time.monotonic()
                                    observed["pressureDecision"] = {
                                        "action": decision.action, "reason": decision.reason}
                                    if decision.action == "stop":
                                        with pressure_lock:
                                            published_reason = pressure_shared["published_stop_reason"]
                                            published_at = pressure_shared["stop_at_monotonic"]
                                            stop_observation = pressure_shared["stop_observation"]
                                        reason = stop_cause_at_deadline(
                                            published_reason or decision.reason, published_at,
                                            deadline, time.monotonic())
                                        if child.poll() is None:
                                            child.terminate()
                                        stop_at = time.monotonic() + CLIENT_TERM_GRACE_SECONDS
                                        record_resources(op, "pressure-stop",
                                                         stop_resource_evidence(
                                                             published_reason, published_at,
                                                             stop_observation, reason,
                                                             decision.reason),
                                                         builder=config["builder"])
                                    else:
                                        if (not old_state.active and decision.action == "watch") or (
                                            old_state.active and decision.action == "clear"
                                        ):
                                            record_resources(op, "pressure-transition", observed,
                                                             builder=config["builder"])
                                        if sampled_at >= next_sample:
                                            record_resources(op, "periodic", observed,
                                                             builder=config["builder"])
                                            next_sample = sampled_at + 30
                                probe_started = None
                    elif time.monotonic() >= next_capacity and stop_at is None:
                        next_capacity = time.monotonic() + 2
                        try:
                            observed = capacity(op, config["limits"], cache,
                                                gateway_container_id=gateway_id,
                                                builder=config["builder"] if qualification else None)
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
                # The outer fallback also owns this PID. Finish the same
                # termination here before stopping its independent watchdog,
                # including when output forwarding raises.
                try:
                    if child.poll() is None:
                        child.terminate()
                        try:
                            child.wait(timeout=CLIENT_TERM_GRACE_SECONDS)
                        except subprocess.TimeoutExpired:
                            child.kill()
                finally:
                    pressure_stop.set()
                    if pressure_thread is not None:
                        pressure_thread.join(timeout=1)
                    selector.close()
                    child.stdout.close()
            if qualification:
                with pressure_lock:
                    watchdog_reason = pressure_shared["published_stop_reason"]
                    stop_observation = pressure_shared["stop_observation"]
                    published_at = pressure_shared["stop_at_monotonic"]
                    final_decision = pressure_watchdog(time.monotonic(),
                                                       pressure_shared["state"])
                    if watchdog_reason is None and final_decision.action == "stop":
                        watchdog_reason = publish_pressure_stop(
                            pressure_shared, final_decision.reason)
                        published_at = pressure_shared["stop_at_monotonic"]
                        stop_observation = pressure_shared["stop_observation"]
                final_reason = watchdog_reason or (
                    final_decision.reason if final_decision.action == "stop" else None)
                if final_reason is not None and not pressure_reported:
                    if stop_at is None:
                        reason = stop_cause_at_deadline(
                            final_reason, published_at, deadline, time.monotonic())
                        stop_at = time.monotonic() + CLIENT_TERM_GRACE_SECONDS
                    else:
                        reason = prefer_published_stop(
                            reason, final_reason, published_at, deadline)
                    record_resources(op, "pressure-final-stop",
                                     stop_resource_evidence(
                                         watchdog_reason, published_at,
                                         stop_observation, reason, final_reason),
                                     builder=config["builder"])
                    pressure_reported = True
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
    prep.add_argument("--adaptive-gateway-id")
    for name in ("start", "status", "cancel", "_serve"):
        sub.add_parser(name).add_argument("operation", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            config = release.read_json(args.config)
            if args.adaptive_gateway_id is not None:
                validate_config(config)
                samples = collect_adaptive_samples(
                    args.private_root.parent, config.get("cache"),
                    args.adaptive_gateway_id)
                config = bind_adaptive_selection(config, samples)
                if config is None:
                    print(json.dumps({"status": "no_fit", "operationCreated": False,
                                      "reason": "profile_capacity_or_health"}, sort_keys=True))
                    return 2
            print(prepare(args.private_root, config, args.manifest,
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
