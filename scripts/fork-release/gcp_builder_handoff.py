#!/usr/bin/env python3
"""Advance a retained BuildKit reservation after a proven successful build.

This changes only the cooperative reservation for one existing builder. It
neither creates a builder nor dispatches the successor. An interrupted handoff
is reconciled using its durable intent and the exact current lease bytes.
"""

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile

import gcp_build as build
import release

CAPABLE_BUILD_SHA256 = "961fd6b542b52828146c1169830d9fddcf9939e294cf23a682b21d3e8862b8a3"


def digest(data):
    return hashlib.sha256(data).hexdigest()


@contextmanager
def handoff_lock(root):
    path = root / "builder-handoff.lock"
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        release.need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                     and stat.S_IMODE(info.st_mode) == 0o600,
                     "handoff.lock.unsafe")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def replace_lease(path, value):
    fd, temporary = tempfile.mkstemp(prefix=".builder-handoff-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        build.sync_directory(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def sync_existing(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        release.need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                     and stat.S_IMODE(info.st_mode) == 0o600,
                     "handoff.evidence.unsafe")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    build.sync_directory(path.parent)


def handoff(old_path, new_path):
    old, origin = build.load_intent(old_path)
    new, target = build.load_intent(new_path)
    release.need(old != new and old.parent == new.parent == build.PRIVATE_ROOT.resolve(),
                 "handoff.operations.invalid")
    root = old.parent
    with handoff_lock(root), build.operation_lock(new):
        release.need(not (new / "start-intent.json").exists(), "handoff.target.started")
        release.need(digest(Path(build.__file__).read_bytes()) == CAPABLE_BUILD_SHA256 and
                     digest(build.private_bytes(new / "supervisor/gcp_build.py")) ==
                     CAPABLE_BUILD_SHA256, "handoff.target.tooling_lacks_start_fence")
        release.need(origin["config"]["builder"] == target["config"]["builder"],
                     "handoff.builder.changed")
        release.need(origin["config"]["sourceSha"] != target["config"]["sourceSha"],
                     "handoff.source.unchanged")
        observed = build.status(old)
        release.need(observed["state"] == "succeeded" and observed["dispatchRecorded"],
                     "handoff.origin.not_succeeded")
        execution = build.private_bytes(old / "execution.json")
        completed = build.read_private(old / "completed.json")
        release.need(completed["exitCode"] == completed["nativeExitCode"] == 0 and
                     completed["reason"] == "client succeeded" and
                     observed["service"].get("InvocationID") == completed["invocationId"] and
                     observed["service"].get("MainPID") == "0",
                     "handoff.origin.not_terminal")
        origin_sha = build.preflight.digest(old / "intent.json")
        target_sha = build.preflight.digest(new / "intent.json")
        old_value = {"operationId": old.name, "intentSha256": origin_sha}
        new_value = {"operationId": new.name, "intentSha256": target_sha}
        lease = root / f"builder-{target['config']['builder']['containerId']}.json"
        current = build.private_bytes(lease)
        intent = {"schema": "openclaw.gcp-builder-handoff.v1",
                  "originOperationId": old.name, "targetOperationId": new.name,
                  "originIntentSha256": origin_sha, "targetIntentSha256": target_sha,
                  "originExecutionSha256": digest(execution),
                  "originLeaseSha256": digest(build.encode(old_value))}
        path = new / "builder-handoff-intent.json"
        try:
            build.write_once(path, build.encode(intent))
        except FileExistsError:
            release.need(build.read_private(path) == intent, "handoff.intent.changed")
            sync_existing(path)
        if current == build.encode(old_value):
            replace_lease(lease, build.encode(new_value))
        else:
            release.need(current == build.encode(new_value), "handoff.lease.other_owner")
            sync_existing(lease)
        release.need(build.private_bytes(lease) == build.encode(new_value),
                     "handoff.lease.changed")
        receipt = {**intent, "targetLeaseSha256": digest(build.encode(new_value))}
        try:
            build.write_once(new / "builder-handoff.json", build.encode(receipt))
        except FileExistsError:
            release.need(build.read_private(new / "builder-handoff.json") == receipt,
                         "handoff.receipt.changed")
            sync_existing(new / "builder-handoff.json")
        return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("origin", type=Path)
    parser.add_argument("target", type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(handoff(args.origin, args.target), sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, release.Refusal) as error:
        print(f"GCP builder handoff refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
