#!/usr/bin/env python3
"""Transfer a failed build's builder lease only after its worker is stopped.

Stopping the exact retained BuildKit container settles a solve whose client
exited without proof of remote termination. This never stops a container,
starts a build, or changes the cache. The operator owns the stop and its cost.
"""

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import sys

import gcp_build as build
import gcp_builder_handoff as handoff
import release


STOP_FORMAT = ('{"Id":{{json .Id}},"Image":{{json .Image}},"State":{'
               '"Running":{{json .State.Running}},'
               '"Restarting":{{json .State.Restarting}},'
               '"Pid":{{json .State.Pid}},'
               '"FinishedAt":{{json .State.FinishedAt}}}}')


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
        release.need(origin["config"]["builder"] == target["config"]["builder"],
                     "recovery.builder.changed")
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
        intent = {"schema": "openclaw.gcp-builder-recovery.v1",
                  "originOperationId": old.name, "targetOperationId": new.name,
                  "originIntentSha256": origin_sha, "targetIntentSha256": target_sha,
                  "originCompletedSha256": digest(completed_bytes),
                  "builderStoppedSha256": digest(proof_bytes),
                  "originLeaseSha256": digest(build.encode(old_value))}
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("origin", type=Path)
    parser.add_argument("target", type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(recover(args.origin, args.target), sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, release.Refusal) as error:
        print(f"GCP builder recovery refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
