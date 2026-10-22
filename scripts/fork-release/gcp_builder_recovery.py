#!/usr/bin/env python3
"""Transfer a failed build's builder lease or a never-dispatched preparation.

Stopping the exact retained BuildKit container settles a solve whose client
exited without proof of remote termination. This never stops a container,
starts a build, or changes the cache. The operator owns the stop and its cost.
The --prepared path only advances a lease from an operation with no start
intent, preserving its exact stopped-worker transition evidence.
"""

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

import gcp_build as build
import gcp_builder_handoff as handoff
import release


STOP_FORMAT = ('{"Id":{{json .Id}},"Image":{{json .Image}},"State":{'
               '"Running":{{json .State.Running}},'
               '"Restarting":{{json .State.Restarting}},'
               '"Pid":{{json .State.Pid}},'
               '"FinishedAt":{{json .State.FinishedAt}}}}')
RESOURCE_FIELDS = ("memoryBytes", "memorySwapBytes", "cpuPeriod", "cpuQuota")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def docker_time(value):
    match = re.fullmatch(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?Z", value)
    release.need(match is not None, "recovery.builder.stop_time_invalid")
    fractional = (match.group(2) or "")[:6]
    return datetime.fromisoformat(match.group(1) +
                                  ("." + fractional if fractional else "") + "+00:00")


def stopped_proof(builder, cache, completed_at, origin):
    inspected = build.native([*build.DOCKER, "--host", build.ENDPOINT, "inspect",
                              "--format", STOP_FORMAT, builder["containerId"]])
    release.need(inspected.returncode == 0, "recovery.builder.inspect")
    row = json.loads(inspected.stdout)
    build.fields(row, "Id Image State", "recovery.builder.fields")
    build.fields(row["State"], "Running Restarting Pid FinishedAt",
                 "recovery.builder.state_fields")
    state = row["State"]
    release.need(row["Id"] == builder["containerId"] and
                 row["Image"] == builder["imageId"] and
                 state["Running"] is False and state["Restarting"] is False and
                 state["Pid"] == 0, "recovery.builder.not_stopped")
    finished = docker_time(state["FinishedAt"])
    completed = docker_time(completed_at)
    release.need(finished >= completed, "recovery.builder.stop_precedes_failure")
    if cache is not None:
        build.observe_cache(builder, cache)
    return {"schema": "openclaw.gcp-builder-stopped.v1",
            "originOperationId": origin, "builderId": row["Id"],
            "builderImageId": row["Image"], "finishedAt": state["FinishedAt"],
            "originCompletedAt": completed_at}


def qualification_transition(origin, target):
    """Only the approved stopped-worker 16/18 GiB, 7 CPU -> 8/8 GiB, 4 CPU."""
    old, new = origin["config"], target["config"]
    before, after = old["builder"], new["builder"]
    release.need(old["sourceSha"] == new["sourceSha"] ==
                 build.QUALIFICATION_SOURCE_SHA and
                 {k: v for k, v in before.items() if k not in RESOURCE_FIELDS} ==
                 {k: v for k, v in after.items() if k not in RESOURCE_FIELDS} and
                 {k: before[k] for k in RESOURCE_FIELDS} == {
                     "memoryBytes": 16 << 30, "memorySwapBytes": 18 << 30,
                     "cpuPeriod": 100000, "cpuQuota": 700000} and
                 {k: after[k] for k in RESOURCE_FIELDS} == {
                     "memoryBytes": 8 << 30, "memorySwapBytes": 8 << 30,
                     "cpuPeriod": 100000, "cpuQuota": 400000} and
                 new.get("adaptiveSelection", {}).get("profile", {}).get("id") ==
                 build.QUALIFICATION_PROFILE_ID and
                 old.get("cache") == new.get("cache"),
                 "recovery.resource_transition.unreviewed")


def stopped_resources(builder):
    result = build.native([*build.DOCKER, "--host", build.ENDPOINT, "inspect",
                           "--format", build.CONTAINER_FORMAT, builder["containerId"]])
    release.need(result.returncode == 0, "recovery.resource_transition.inspect")
    row = json.loads(result.stdout)
    release.need(row["Id"] == builder["containerId"] and
                 row["Image"] == builder["imageId"] and
                 row["State"]["Running"] is False,
                 "recovery.resource_transition.not_stopped")
    observed = {"name": builder["name"], "node": builder["node"],
                "endpoint": builder["endpoint"], "containerId": row["Id"],
                "imageId": row["Image"],
                **{key: row["HostConfig"][native_key] for key, native_key in {
                    "memoryBytes": "Memory", "memorySwapBytes": "MemorySwap",
                    "cpuPeriod": "CpuPeriod", "cpuQuota": "CpuQuota",
                    "cpuShares": "CpuShares", "nanoCpus": "NanoCpus",
                    "pidsLimit": "PidsLimit", "readBps": "BlkioDeviceReadBps",
                    "writeBps": "BlkioDeviceWriteBps"}.items()}}
    return observed


def transition_resources(old, new, origin, target, stopped):
    """Intent-before-Docker-update; reconcile exact target if reply was lost."""
    qualification_transition(origin, target)
    before, after = origin["config"]["builder"], target["config"]["builder"]
    proposal = {"schema": "openclaw.gcp-builder-resource-transition.v1",
                "originOperationId": old.name, "targetOperationId": new.name,
                "originIntentSha256": build.preflight.digest(old / "intent.json"),
                "targetIntentSha256": build.preflight.digest(new / "intent.json"),
                "builderStoppedSha256": digest(build.encode(stopped)),
                "originBuilderSha256": digest(build.encode(before)),
                "targetBuilderSha256": digest(build.encode(after))}
    intent_path = new / "resource-transition-intent.json"
    try:
        build.write_once(intent_path, build.encode(proposal))
    except FileExistsError:
        release.need(build.read_private(intent_path) == proposal,
                     "recovery.resource_transition.intent_changed")
        handoff.sync_existing(intent_path)
    observed = stopped_resources(before)
    command = [*build.DOCKER, "--host", build.ENDPOINT, "update",
               "--memory", str(8 << 30), "--memory-swap", str(8 << 30),
               "--cpu-period", "100000", "--cpu-quota", "400000",
               before["containerId"]]
    if observed == before:
        # Even a nonzero or lost CLI reply must be reconciled by exact native
        # readback. Do not repeat Docker update if the target is already set.
        try:
            build.native(command)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            pass
        observed = stopped_resources(before)
    repair_path = new / "resource-transition-repair-intent.json"
    if observed != before and observed != after:
        # Docker can apply only part of an update. Repair exactly once, only
        # while stopped and only when every changed field is an intended value.
        release.need(all(observed[key] == before[key] for key in before
                         if key not in RESOURCE_FIELDS) and
                     all(observed[key] in (before[key], after[key])
                         for key in RESOURCE_FIELDS),
                     "recovery.resource_transition.unrecognized_partial")
        repair = {**proposal, "partialBuilderSha256": digest(build.encode(observed))}
        try:
            build.write_once(repair_path, build.encode(repair))
        except FileExistsError:
            release.need(False, "recovery.resource_transition.repair_exhausted")
        try:
            build.native(command)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            pass
        observed = stopped_resources(before)
    release.need(observed == after, "recovery.resource_transition.readback")
    receipt = {**proposal, "observedBuilderSha256": digest(build.encode(observed)),
               **({"repairIntentSha256": build.preflight.digest(repair_path)}
                  if repair_path.exists() else {})}
    receipt_path = new / "resource-transition.json"
    try:
        build.write_once(receipt_path, build.encode(receipt))
    except FileExistsError:
        release.need(build.read_private(receipt_path) == receipt,
                     "recovery.resource_transition.receipt_changed")
        handoff.sync_existing(receipt_path)
    return receipt


def recover(old_path, new_path):
    old, origin = build.load_intent(old_path)
    new, target = build.load_intent(new_path)
    release.need(old != new and old.parent == new.parent == build.PRIVATE_ROOT.resolve(),
                 "recovery.operations.invalid")
    root = old.parent
    with handoff.handoff_lock(root), build.operation_lock(new):
        release.need(not (new / "start-intent.json").exists(), "recovery.target.started")
        release.need(build.private_bytes(new / "supervisor/gcp_build.py") ==
                     Path(build.__file__).read_bytes(), "recovery.target.tooling_changed")
        resource_transition = origin["config"]["builder"] != target["config"]["builder"]
        if resource_transition:
            qualification_transition(origin, target)
        # A failed solve may retry the exact same source under a new operation.
        observed = build.status(old)
        completed_bytes = build.private_bytes(old / "completed.json")
        completed = build.read_private(old / "completed.json")
        service = observed["service"]
        release.need(observed["state"] == "failed" and observed["dispatchRecorded"] and
                     not (old / "execution.json").exists() and
                     type(completed["exitCode"]) is int and completed["exitCode"] != 0 and
                     type(completed["nativeExitCode"]) is int and
                     completed["nativeExitCode"] != 0 and
                     build.private_bytes(old / "build.exit").strip() ==
                     str(completed["nativeExitCode"]).encode() and
                     completed["remoteSolveTerminationObserved"] is False and
                     service.get("InvocationID") == completed["invocationId"] and
                     service.get("MainPID") == "0" and
                     service.get("ActiveState") == "failed" and
                     service.get("SubState") == "failed" and
                     service.get("Result") == "exit-code", "recovery.origin.not_terminal_failed")
        origin_sha = build.preflight.digest(old / "intent.json")
        target_sha = build.preflight.digest(new / "intent.json")
        old_value = {"operationId": old.name, "intentSha256": origin_sha}
        new_value = {"operationId": new.name, "intentSha256": target_sha}
        lease = root / f"builder-{target['config']['builder']['containerId']}.json"
        current = build.private_bytes(lease)
        release.need(current in (build.encode(old_value), build.encode(new_value)),
                     "recovery.lease.other_owner")
        proof_path = new / "builder-stopped.json"
        if current == build.encode(old_value):
            proof = stopped_proof(target["config"]["builder"],
                                  target["config"].get("cache"),
                                  completed["completedAt"], old.name)
            proof_bytes = build.encode(proof)
            try:
                build.write_once(proof_path, proof_bytes)
            except FileExistsError:
                release.need(build.private_bytes(proof_path) == proof_bytes,
                             "recovery.stop_proof.changed")
                handoff.sync_existing(proof_path)
        else:
            proof_bytes = build.private_bytes(proof_path)
        transition = None
        if resource_transition:
            transition = transition_resources(old, new, origin, target,
                                             json.loads(proof_bytes))
        intent = {"schema": "openclaw.gcp-builder-recovery.v1",
                  "originOperationId": old.name, "targetOperationId": new.name,
                  "originIntentSha256": origin_sha, "targetIntentSha256": target_sha,
                  "originCompletedSha256": digest(completed_bytes),
                  "builderStoppedSha256": digest(proof_bytes),
                  "originLeaseSha256": digest(build.encode(old_value)),
                  **({"resourceTransitionSha256": digest(build.encode(transition))}
                     if transition is not None else {})}
        intent_path = new / "builder-handoff-intent.json"
        try:
            build.write_once(intent_path, build.encode(intent))
        except FileExistsError:
            release.need(build.read_private(intent_path) == intent,
                         "recovery.intent.changed")
            handoff.sync_existing(intent_path)
        if current == build.encode(old_value):
            handoff.replace_lease(lease, build.encode(new_value))
        else:
            handoff.sync_existing(lease)
        release.need(build.private_bytes(lease) == build.encode(new_value),
                     "recovery.lease.changed")
        receipt = {**intent, "targetLeaseSha256": digest(build.encode(new_value))}
        receipt_path = new / "builder-handoff.json"
        try:
            build.write_once(receipt_path, build.encode(receipt))
        except FileExistsError:
            release.need(build.read_private(receipt_path) == receipt,
                         "recovery.receipt.changed")
            handoff.sync_existing(receipt_path)
        build.verify_builder_handoff(new, target)
        return receipt


def transfer_prepared(old_path, new_path):
    """Move a lease from a never-dispatched preparation to corrected tooling."""
    old, origin = build.load_intent(old_path)
    new, target = build.load_intent(new_path)
    release.need(old != new and old.parent == new.parent == build.PRIVATE_ROOT.resolve(),
                 "prepared.operations.invalid")
    with handoff.handoff_lock(old.parent), build.operation_lock(old), build.operation_lock(new):
        release.need(all(not (operation / name).exists()
                         for operation in (old, new)
                         for name in ("start-intent.json", "started.json",
                                      "execution.json", "completed.json")),
                     "prepared.origin_or_target_dispatched")
        release.need(build.private_bytes(new / "supervisor/gcp_build.py") ==
                     Path(build.__file__).read_bytes(), "prepared.target.tooling_changed")
        for key in ("sourceSha", "sourceTree", "manifestSha256", "inventorySha256",
                    "builder", "cache"):
            release.need(origin["config"].get(key) == target["config"].get(key),
                         "prepared.binding_changed")
        origin_sha = build.preflight.digest(old / "intent.json")
        target_sha = build.preflight.digest(new / "intent.json")
        old_value = {"operationId": old.name, "intentSha256": origin_sha}
        new_value = {"operationId": new.name, "intentSha256": target_sha}
        lease = old.parent / f"builder-{target['config']['builder']['containerId']}.json"
        current = build.private_bytes(lease)
        release.need(current in (build.encode(old_value), build.encode(new_value)),
                     "prepared.lease.other_owner")
        if current == build.encode(old_value):
            build.verify_builder_handoff(old, origin)
        old_handoff = build.read_private(old / "builder-handoff.json")
        release.need(old_handoff["schema"] in
                     ("openclaw.gcp-builder-recovery.v1",
                      "openclaw.gcp-builder-prepared-handoff.v1") and
                     old_handoff["targetOperationId"] == old.name,
                     "prepared.origin.transition_unproven")
        if old_handoff["schema"] == "openclaw.gcp-builder-prepared-handoff.v1":
            # The successor adds one hop; refuse before touching the lease if
            # that would exceed the verifier's four-handoff limit.
            build.prepared_recovery_proposal(
                old, build.read_private(old / "builder-handoff-intent.json"),
                origin, max_handoffs=3)
        intent = {"schema": "openclaw.gcp-builder-prepared-handoff.v1",
                  "originOperationId": old.name, "targetOperationId": new.name,
                  "originIntentSha256": origin_sha, "targetIntentSha256": target_sha,
                  "originHandoffSha256": build.preflight.digest(old / "builder-handoff.json"),
                  "originLeaseSha256": digest(build.encode(old_value))}
        receipt = {**intent, "targetLeaseSha256": digest(build.encode(new_value))}
        receipt_path = new / "builder-handoff.json"
        if receipt_path.exists():
            release.need(build.private_bytes(receipt_path) == build.encode(receipt),
                         "prepared.receipt.changed")
            handoff.sync_existing(receipt_path)
        path = new / "builder-handoff-intent.json"
        try:
            build.write_once(path, build.encode(intent))
        except FileExistsError:
            release.need(build.read_private(path) == intent, "prepared.intent.changed")
            handoff.sync_existing(path)
        if current == build.encode(old_value):
            handoff.replace_lease(lease, build.encode(new_value))
        else:
            handoff.sync_existing(lease)
        release.need(build.private_bytes(lease) == build.encode(new_value),
                     "prepared.lease.changed")
        try:
            build.write_once(receipt_path, build.encode(receipt))
        except FileExistsError:
            release.need(build.read_private(receipt_path) == receipt,
                         "prepared.receipt.changed")
            handoff.sync_existing(receipt_path)
        build.verify_builder_handoff(new, target)
        return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepared", action="store_true",
                        help="transfer an exact never-dispatched build preparation")
    parser.add_argument("origin", type=Path)
    parser.add_argument("target", type=Path)
    args = parser.parse_args()
    try:
        action = transfer_prepared if args.prepared else recover
        print(json.dumps(action(args.origin, args.target), sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, release.Refusal) as error:
        print(f"GCP builder recovery refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
