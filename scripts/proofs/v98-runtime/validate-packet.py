#!/usr/bin/env python3
"""Validate the frozen argument/binding manifest; never admit or execute runtime."""
import argparse
import hashlib
import json
from pathlib import Path

SOURCE = "bc8b82b2cbbbb81f5abe6093e1bb3af4f1f70cdf"
TREE = "ba825f670dc5ba943f7893cb267225d1f68d3110"
DOCTOR = "/app/dist/openclaw-state-db-CgJKJRub.mjs"
DOCTOR_SHA = "adfe8f5551b6904d46ce157c20defff6e8f991a2ea67a6c1d32ddd66b93e6c13"
PACKET_RAW_SHA = "fe04c964622a86b817c95320c89fa783af1ffdcfbf7a790fafee34c724d072a7"
PACKET_CANONICAL_SHA = "7f386eda7f7d9dfedeade0b2673cd97b8dae8d0975e67968ff30a26b8992fda0"
INPUTS = {
    "fixture.mjs": "777936fa311d3b6fb141dff1fc67f46e2cfddf0651bf75b30ae62f74368f674e",
    "predecessor-state.sql": "32a9ec60e38f1511e6f5fcd532f4c631d680d537a8325601f5bdf8221cf20fa3",
    "predecessor-workboard.ts": "aa15bf48dbe292993a47c7286d5f7e12fe2ffbd74442c92b37ad98018bd2e810",
    "predecessor-publisher-controller.mjs": "c3d63b3c567541f72fb33c6982b41d4d5e4efa7fdd2d43ba5d7d14e624ebdbfc",
}


def validate(packet, inputs=None):
    def require(condition, message):
        if not condition:
            raise ValueError(message)
    require(packet["sourceCommit"] == SOURCE and packet["sourceTree"] == TREE, "qualified source changed")
    require(packet["status"] == "BLOCKED_UNCHANGED_DOCTOR_REQUIRES_DENIED_CHILD_PROCESS", "runtime admission forbidden")
    require(packet["doctor"] == {"path": DOCTOR, "sha256": DOCTOR_SHA,
                                "export": "prepareOpenClawStateDatabaseSchema", "mode": "doctor"}, "Doctor binding changed")
    require(packet["inputs"] == {"/proof/inputs/" + n: h for n, h in INPUTS.items()}, "frozen inputs changed")
    context = packet["commandContext"]
    require(context["nodePath"] == "/usr/local/bin/node" and context["fixtureScriptPath"] == "/proof/inputs/fixture.mjs", "command context changed")
    require(context["requiredGlobalEnvironment"] == {"PARITY_FIXTURE_SCRATCH_ROOT": "/scratch", "XDG_CACHE_HOME": "/scratch/cache"}, "scratch environment changed")
    root = "/scratch/synthetic-parity-fixture"
    args = [["prepare", root, "/proof/inputs/predecessor-state.sql", "/proof/inputs/predecessor-workboard.ts", "/proof/inputs/predecessor-publisher-controller.mjs"],
            ["assert", root, "predecessor"], ["migrate", root, DOCTOR, DOCTOR_SHA],
            ["assert", root, "candidate"], ["restore", root], ["assert", root, "rollback"]]
    require(packet["phases"] == [{"number": i + 1, "argv": a, "execution": "NEVER_RUN"} for i, a in enumerate(args)], "phase manifest changed")
    blocker = packet["blockedRequirement"]
    require(blocker["childCreation"] == blocker["childExecution"] == "DENIED", "child boundary changed")
    require(blocker["runtimeApprovalRequested"] is False and packet["noNewExecutionWorkflow"] is True, "execution request forbidden")
    require(packet["limits"] == {"scratchBytes": 16777216, "wallSeconds": 60, "aggregateCpuSeconds": 30,
                                "cpuCores": 1, "memoryBytes": 1073741824, "swapBytes": 0,
                                "pidsAndThreads": 128, "parentOldSpaceMiB": 128, "workerOldGenerationMiB": 512}, "resource limits changed")
    canonical = json.dumps(packet, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    require(hashlib.sha256(canonical).hexdigest() == PACKET_CANONICAL_SHA, "frozen manifest identity changed")
    if inputs is not None:
        for name, expected in INPUTS.items():
            p = inputs / name
            require(p.is_file() and not p.is_symlink() and hashlib.sha256(p.read_bytes()).hexdigest() == expected, "input bytes changed:" + name)
    return {"status": "BLOCKED_PACKET_IDENTITY_VERIFIED; NO_RUNTIME_ADMISSION", "fixturePhases": ["NEVER_RUN"] * 6}


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--packet", type=Path, required=True)
    p.add_argument("--inputs", type=Path, required=True)
    a = p.parse_args()
    if a.packet.stat().st_size > 256 * 1024:
        raise ValueError("packet over budget")
    raw = a.packet.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PACKET_RAW_SHA:
        raise ValueError("frozen manifest bytes changed")
    print(json.dumps(validate(json.loads(raw), a.inputs)))
