#!/usr/bin/env python3
"""One bounded native rehearsal phase on an already restored, isolated disk.

The deployment owner supplies a private clean-input receipt and owns restore,
phase sequencing and production. This executor never provisions, copies,
deletes, repairs a dataset in prepare, or retries a migration. prepare is inert;
start is a separately authorized mutation. An uncertain start is status-only.
The receipt is a private, caller-owned restore-owner attestation, not a database
integrity scan. That owner must establish coherent unmigrated input and disabled
integrations before prepare. A checksum alone does not establish those facts.
The current resource envelope is deliberately specific to the reviewed 10.5 run.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time

import gcp_build as durable
import gcp_rehearsal_checks as checks
import release

PRIVATE_ROOT = Path("/var/tmp/openclaw-fork-snapshot-trial")
HELPERS = ("gcp_snapshot_trial.py", "gcp_rehearsal_checks.py", *durable.HELPERS)
DOCTOR = ["node", "/app/openclaw.mjs", "doctor", "--fix", "--non-interactive",
          "--no-workspace-suggestions"]
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")
OP = re.compile(r"[0-9a-f]{32}\Z")
STATE_TARGET = "/home/node/.openclaw"
ADMISSION = "/run/openclaw-trial-admission"
CAP = 4 * 1024 * 1024
QUALIFIED_IMAGE = {
    "repository": "fr-meyer/openclaw", "version": "2026.10.5", "architecture": "amd64",
    "sourceSha": "4bcf8902e1eeb2fa5e84d0c4bf55572382ca61e4",
    "sourceTree": "bd6a3b130536a5bfcbdb2b97a7319db5d389dc33",
    "manifestSha256": "ec8c26e1480a7236667520ba3b32bd39413a466db3eba5a3091411a2e1bfeec1",
    "inventorySha256": "bc3f130cea66991ffc33c060b0de906cf2bddaca65b8480a57b0b4519d6facf7",
    "indexDigest": "sha256:0829e7490ce910da86fc374a627d1282fd0586d9f4abf61f9492899c0964ad5e",
    "imageDigest": "sha256:a5a97b480d1d813755a26c1a858c28261cba55e685d8813b6b57919ab3edb5ec",
    "configDigest": "sha256:8e7c58d98fea62abc2e97d2cde96a4549cbdd4c9b7488d6bcaf277341781e960",
    "selectedExtensions": "codex,workboard", "bundledCodexVersion": "0.160.0",
}
HISTORICAL_IMAGE = {
    **QUALIFIED_IMAGE,
    "sourceSha": "ae85778296da373dfe7d80101931bafac1acc9dd",
    "sourceTree": "3efb0b6fdb4491462591e2f534161c2b8bab65ab",
    "manifestSha256": "4dfce05ac50a38c7667aeaa3b88f8f60e9c6046bb48a1d361785e77ee5d4ccd2",
    "inventorySha256": "cc4298057d4c61b6e1a488f06fdac93a0ea9263f87811700c0179a470cc495a8",
    "indexDigest": "sha256:f41c7a7762f7a051636b899dac54110c482fb91352431ba6957343b9828f2e9c",
    "imageDigest": "sha256:e4901df74f92d4abeebae37982ff2ef631943446c0cfe37394f86e5351cc6280",
    "configDigest": "sha256:b6eaa3f6594c677f7795b68cda3adc4a34236af242d1a5257642e57574c6527d",
}
QUALIFIED_PRODUCER = "672f8a182cea6219d680bacd400923bf84ec9876"
HISTORICAL_PRODUCER = "1507a29361d335283f1f4a55d8c037505892f94c"
HISTORICAL_IMAGE_RECEIPT_SHA256 = "98ba31371e306b4e8878161ebf2dce0d021f1be2a3ae5e10384e238fdc9e6178"
BACKUP_REUSE = "openclaw.doctor-backup-reuse.v1"
IO_PROFILES = {(128 << 20, 32 << 20): "read128-write32",
               (256 << 20, 64 << 20): "read256-write64"}
LOW_MEMORY_BYTES = 16 << 30
LOW_MEMORY_ADMISSION_BYTES = 20 << 30
CONTINUATION = "openclaw.snapshot-doctor-continuation.v1"
LEGACY_DEVICE_SHA = "a9b6526bbde15c2f9eeb3385e2fa00aa4cadfa39"
LEGACY_CONTINUATION_SHA = "4c57b5269dc882c4c15f4b26fbdbb05a89b2df2d"
# Read-only compatibility for these reviewed or qualified historical supervisors.
# Digest of the sorted compact JSON helper-hash map; never execute old helpers.
RETAINED_HELPERS = {
    LEGACY_DEVICE_SHA: "872b6966330c2bb127ae007cf936bffc6e6d7704d9d0ed1a0b7be5de57e8da0d",
    "ad0c1a62300f77e616b1a373c92c967c3cba95b8": "af5caa6316e15bec85b501ff2f8839835546b1e1e5313810a314741479343156",
    LEGACY_CONTINUATION_SHA: "0de004053ed692ae2dc0cbf2d70f336dda72c02c21ba65a893ccac37a4719f97",
}
need = release.need


def digest(data):
    return hashlib.sha256(data).hexdigest()


RUNNING_HELPERS = {
    "gcp_snapshot_trial.py": Path(__file__).resolve(), "gcp_build.py": Path(durable.__file__).resolve(),
    "gcp_rehearsal_checks.py": Path(checks.__file__).resolve(),
    "release.py": Path(release.__file__).resolve(), "preflight.py": Path(durable.preflight.__file__).resolve(),
    "pr.py": Path(durable.pr.__file__).resolve(),
}
LOADED_HELPER_HASHES = {name: digest(file.read_bytes()) for name, file in RUNNING_HELPERS.items()}


def verify_running_helpers(expected):
    need(set(expected) == set(HELPERS) == set(RUNNING_HELPERS), "trial.running_helper.fields")
    for name, hashed in expected.items():
        need(LOADED_HELPER_HASHES[name] == hashed and digest(RUNNING_HELPERS[name].read_bytes()) == hashed,
             "trial.running_helper.changed")


def qualified_image(image, *, retained=False):
    candidates = ((QUALIFIED_IMAGE, QUALIFIED_PRODUCER),)
    if retained:
        candidates += ((HISTORICAL_IMAGE, HISTORICAL_PRODUCER),)
    need(image.get("producer", {}).get("kind") == "gcp" and any(
         all(image.get(key) == value for key, value in candidate.items()) and
         image["producer"].get("toolingSha") == producer for candidate, producer in candidates),
         "trial.image.not_qualified")


def private_json(path):
    raw = durable.private_bytes(path)
    need(len(raw) <= 1024 * 1024, "trial.input.too_large")
    return json.loads(raw), digest(raw)


def exact(value, keys, code):
    durable.fields(value, keys, code)


def path(value, canonical=True):
    need(type(value) is str and value.startswith("/") and value != "/"
         and not any(c in value for c in ",\n\r\0"), "trial.path.invalid")
    p = Path(value)
    need(str(p) == value and ".." not in p.parts and len(p.parts) <= 128 and
         (not canonical or p.resolve() == p), "trial.path.noncanonical")
    return p


def overlaps(a, b):
    return a == b or a in b.parents or b in a.parents


def project_target(target):
    text = str(target)
    if text.startswith(("/home/node/workspace/", "/data/")):
        return True
    state = Path(STATE_TARGET)
    if target == state / "repos":
        return True
    if state in target.parents:
        parts = target.relative_to(state).parts
        return len(parts) >= 2 and re.fullmatch(r"workspace(?:-[A-Za-z0-9_.-]+)?", parts[0]) is not None
    return False


def direct_source_overlay(parent, child):
    """A clone subtree may only cover its own path with a read-only bind."""
    parent_source, child_source = Path(parent["source"]), Path(child["source"])
    parent_target, child_target = Path(parent["target"]), Path(child["target"])
    return (parent["readOnly"] is False and child["readOnly"] is True and
            parent_source in child_source.parents and parent_target in child_target.parents and
            project_target(child_target) and
            (str(parent_target) == STATE_TARGET or project_target(parent_target)) and
            child_source.relative_to(parent_source) == child_target.relative_to(parent_target))


def phase(plan):
    return plan["phase"] if plan["schema"] == "openclaw.snapshot-trial-plan.v2" else "doctor"


def native_phase(plan):
    return {"startup": "candidate-startup", "rollback": "rollback-startup"}[phase(plan)]


def continuing(check):
    return isinstance(check, dict) and check.get("schema") == CONTINUATION


def backup_reuse(check):
    return check.get("backupReuse") if continuing(check) else None


def timestamp(value):
    need(type(value) is str, "trial.continuation.timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    need(parsed.tzinfo is not None, "trial.continuation.timestamp")
    return parsed


def validate_continuation(check, *, legacy=False):
    reuse = backup_reuse(check)
    exact(check, "schema phase doctorOperationId doctorIntentSha256 doctorResultSha256 reconciliation" +
          (" backupReuse" if reuse is not None else ""),
          "trial.continuation.fields")
    need(check["phase"] == "doctor" and HEX.fullmatch(check["doctorIntentSha256"]),
         "trial.continuation.identity")
    record = check["reconciliation"]
    if legacy:
        need(reuse is None, "trial.continuation.legacy_reuse")
        # Read-only interpretation of the already qualified 4c57 receipt dialect.
        exact(record, "observedAt artifactDisposition artifactReceiptSha256 preservedBytes recaptureBytes additionalReserveBytes",
              "trial.continuation.legacy_fields")
        timestamp(record["observedAt"])
        need(HEX.fullmatch(record["artifactReceiptSha256"]) and
             record["artifactDisposition"] in ("completed-group-retained", "incomplete-survivors-preserved") and
             all(type(record[k]) is int and record[k] >= 0 for k in ("preservedBytes", "recaptureBytes")) and
             type(record["additionalReserveBytes"]) is int and record["additionalReserveBytes"] > 0 and
             (record["recaptureBytes"] > 0) == (record["artifactDisposition"] == "incomplete-survivors-preserved"),
             "trial.continuation.legacy_reconciliation")
        return
    exact(record, "observedAt artifactDisposition artifactReceiptSha256 artifacts recaptureBytes originalCaptureBytes additionalReserveBytes",
          "trial.continuation.reconciliation_fields")
    timestamp(record["observedAt"])
    need(HEX.fullmatch(record["artifactReceiptSha256"]) and
         record["artifactDisposition"] in ("completed-group-retained", "incomplete-group-reconciled") and
         all(type(record[k]) is int and record[k] >= 0 for k in ("recaptureBytes", "originalCaptureBytes")) and
         type(record["additionalReserveBytes"]) is int and record["additionalReserveBytes"] > 0,
         "trial.continuation.reconciliation")
    need((record["recaptureBytes"] > 0) == (record["artifactDisposition"] == "incomplete-group-reconciled"),
         "trial.continuation.recapture")
    artifact_accounting(check)
    if reuse is not None:
        exact(reuse, "schema originSourceSha originImageDigest originImageReceiptSha256 targetSourceSha "
              "targetImageReceiptSha256 backupId manifestSha256 backupCount", "trial.reuse.fields")
        need(reuse["schema"] == BACKUP_REUSE and
             reuse["originSourceSha"] == HISTORICAL_IMAGE["sourceSha"] and
             reuse["originImageDigest"] == HISTORICAL_IMAGE["indexDigest"] and
             reuse["originImageReceiptSha256"] == HISTORICAL_IMAGE_RECEIPT_SHA256 and
             SHA.fullmatch(reuse["targetSourceSha"]) and
             HEX.fullmatch(reuse["targetImageReceiptSha256"]) and
             re.fullmatch(r"[a-f0-9]{8}-[a-f0-9]{4}-8[a-f0-9]{3}-8[a-f0-9]{3}-[a-f0-9]{12}",
                          reuse["backupId"]) and HEX.fullmatch(reuse["manifestSha256"]) and
             type(reuse["backupCount"]) is int and 1 <= reuse["backupCount"] <= 1024 and
             record["artifactDisposition"] == "completed-group-retained" and
             record["recaptureBytes"] == 0 and
             len(record["artifacts"]) == reuse["backupCount"] and
             all(item["kind"] == "migration-backup" and
                 item["classification"] == "native-revalidation-required" and
                 item["disposition"] == "retain" and item["nativeDiscardOnRetry"] is False and
                 item["path"].endswith(".pre-startup-migration-" + reuse["backupId"] + ".bak")
                 for item in record["artifacts"]), "trial.reuse.group")


def artifact_accounting(check, clean=None):
    """Bounded owner attestations, never a filesystem scan or cleanup authority."""
    rows = check["reconciliation"]["artifacts"]
    need(type(rows) is list and len(rows) <= 1024, "trial.artifacts.bound")
    totals = {key: 0 for key in ("retainedBytes", "preservedBytes", "pendingDeletionBytes", "removedBytes")}
    keys = {"retain": "retainedBytes", "preserve-outside-mounts": "preservedBytes",
            "deletion-pending": "pendingDeletionBytes", "removed": "removedBytes"}
    paths, identities = set(), set()
    pending, unreconciled = [], []
    for item in rows:
        exact(item, "path kind classification disposition reason ownerOperationId device inode links sizeBytes "
              "allocatedBytes evidenceSha256 nativeDiscardOnRetry removal", "trial.artifacts.fields")
        pathname = path(item["path"], canonical=False)
        need(item["path"] not in paths and not any(overlaps(pathname, Path(p)) for p in paths),
             "trial.artifacts.overlap")
        paths.add(item["path"])
        need(item["kind"] in ("migration-backup", "snapshot-staging", "standalone-capture", "protected") and
             item["classification"] in ("native-revalidation-required", "not-reusable", "protected", "unknown") and
             item["disposition"] in keys and type(item["reason"]) is str and 0 < len(item["reason"]) <= 500 and
             HEX.fullmatch(item["evidenceSha256"]) and
             all(type(item[k]) is int and item[k] >= 0 for k in ("sizeBytes", "allocatedBytes")) and
             all(type(item[k]) is int and item[k] > 0 for k in ("device", "inode", "links")),
             "trial.artifacts.metadata")
        identity = (item["device"], item["inode"])
        need(identity not in identities, "trial.artifacts.duplicate_identity")
        identities.add(identity)
        if clean is not None:
            need(Path(clean["mountRoot"]) in pathname.parents and item["device"] == clean["filesystemDevice"],
                 "trial.artifacts.dataset")
        disposition = item["disposition"]
        discard = item["nativeDiscardOnRetry"]
        need(discard is None or type(discard) is bool, "trial.artifacts.native_discard")
        if discard is True:
            need(item["kind"] == "migration-backup" and
                 check["reconciliation"]["artifactDisposition"] == "incomplete-group-reconciled",
                 "trial.artifacts.native_discard_scope")
        if discard is None or (discard is True and disposition == "retain"):
            unreconciled.append(item["path"])
        if item["classification"] == "native-revalidation-required":
            need(item["kind"] == "migration-backup" and disposition == "retain", "trial.artifacts.reuse")
        if item["kind"] == "protected" or item["classification"] in ("protected", "unknown"):
            need(disposition == "retain", "trial.artifacts.protected")
        if disposition != "retain":
            need(item["classification"] == "not-reusable" and
                 item["ownerOperationId"] == check["doctorOperationId"] and item["links"] == 1,
                 "trial.artifacts.disposable_owner")
        else:
            need(item["ownerOperationId"] is None or OP.fullmatch(item["ownerOperationId"]),
                 "trial.artifacts.owner")
        removal = item["removal"]
        if disposition == "removed":
            exact(removal, "manifestSha256 approvalSha256 resultSha256", "trial.artifacts.removal_fields")
            need(all(type(v) is str and HEX.fullmatch(v) for v in removal.values()),
                 "trial.artifacts.removal_proof")
        else:
            need(removal is None, "trial.artifacts.unsettled_removal")
        totals[keys[disposition]] += item["allocatedBytes"]
        if disposition == "deletion-pending":
            pending.append(item["path"])
        if (check["reconciliation"]["artifactDisposition"] == "incomplete-group-reconciled" and
                item["kind"] in ("migration-backup", "snapshot-staging") and
                item["classification"] == "not-reusable"):
            need(disposition != "retain", "trial.artifacts.incomplete_survivor")
    return {**totals, "pendingDeletionPaths": pending, "unreconciledNativeDiscardPaths": unreconciled,
            "inventorySha256": digest(durable.encode(rows))}


def continuation_capacity(resources, plan, check):
    if continuing(check):
        record = check["reconciliation"]
        accounting = artifact_accounting(check)
        need(not accounting["pendingDeletionPaths"], "trial.artifacts.deletion_pending")
        need(not accounting["unreconciledNativeDiscardPaths"], "trial.artifacts.native_discard_unreconciled")
        required = (plan["limits"]["minDataFreeBytes"] + record["recaptureBytes"] +
                    record["originalCaptureBytes"] + record["additionalReserveBytes"])
        need(resources["dataFreeBytes"] >= required, "trial.continuation.capacity")
        resources["continuationAdmission"] = {"requiredFreeBytes": required,
            "recaptureBytes": record["recaptureBytes"], "originalCaptureBytes": record["originalCaptureBytes"],
            "additionalReserveBytes": record["additionalReserveBytes"], "artifacts": accounting,
            "basis": "owner-estimate-plus-runtime-floor; not an all-stage upper bound"}


def resource_profile(limits):
    """One explicit fixed profile per operation; no implicit escalation."""
    need(all(type(limits.get(k)) is int for k in ("memoryBytes", "cpus", "readBps", "writeBps")) and
         limits["cpus"] == 4 and
         ((limits["memoryBytes"] == 24 << 30 and
           (limits["readBps"], limits["writeBps"]) in IO_PROFILES) or
          (limits["memoryBytes"] == LOW_MEMORY_BYTES and
           (limits["readBps"], limits["writeBps"]) == (256 << 20, 64 << 20))),
         "trial.limits.unreviewed_envelope")
    profile = IO_PROFILES[(limits["readBps"], limits["writeBps"])]
    if limits["memoryBytes"] == LOW_MEMORY_BYTES:
        profile = "memory16-" + profile
    return {"id": profile, "mode": "fixed",
            **{k: limits[k] for k in ("memoryBytes", "cpus", "readBps", "writeBps")}, "swapBytes": 0}


def memory_admission(limits):
    """Keep the daily lifecycle and direct trial on the same admission contract."""
    return (limits["minMemoryAvailableBytes"] == LOW_MEMORY_ADMISSION_BYTES
            if limits["memoryBytes"] == LOW_MEMORY_BYTES else
            limits["minMemoryAvailableBytes"] >= limits["memoryBytes"])


def validate(plan, image, clean, check=None, *, retained=False):
    v2 = plan.get("schema") == "openclaw.snapshot-trial-plan.v2"
    exact(plan, "schema operationId toolingSha imageReceiptSha256 cleanInputSha256 limits" +
          (" phase checkInputSha256" if v2 else ""),
          "trial.plan.fields")
    need(plan["schema"] in ("openclaw.snapshot-trial-plan.v1", "openclaw.snapshot-trial-plan.v2") and
         OP.fullmatch(plan["operationId"]) and SHA.fullmatch(plan["toolingSha"]),
         "trial.plan.identity")
    selected = phase(plan)
    legacy_continuation = retained and plan["toolingSha"] == LEGACY_CONTINUATION_SHA
    need(selected in ("doctor", "startup", "rollback"), "trial.plan.phase")
    if v2:
        need(HEX.fullmatch(plan["checkInputSha256"]), "trial.check.hash")
        if continuing(check):
            validate_continuation(check, legacy=legacy_continuation)
            need(selected == "doctor", "trial.continuation.phase")
        else:
            exact(check, "schema phase" + (" doctorOperationId doctorResultSha256" if selected != "doctor" else ""),
                  "trial.check.fields")
            need(check["schema"] == "openclaw.snapshot-trial-check.v1" and check["phase"] == selected,
                 "trial.check.phase")
        if selected != "doctor" or continuing(check):
            need(OP.fullmatch(check["doctorOperationId"]) and check["doctorOperationId"] != plan["operationId"] and
                 HEX.fullmatch(check["doctorResultSha256"]), "trial.check.doctor_reference")
    else:
        need(check is None, "trial.check.unexpected")
    need(all(HEX.fullmatch(plan[k]) for k in ("imageReceiptSha256", "cleanInputSha256")),
         "trial.plan.hash")
    limits = plan["limits"]
    exact(limits, "memoryBytes cpus readBps writeBps minMemoryAvailableBytes minRootFreeBytes "
          "minDataFreeBytes timeoutSeconds", "trial.limits.fields")
    need(all(type(v) is int and v > 0 for v in limits.values()), "trial.limits.integer")
    resource_profile(limits)
    need(memory_admission(limits) and 600 <= limits["timeoutSeconds"] <= 86400,
         "trial.limits.admission")
    need(image.get("schema") == ("openclaw.rehearsal-baseline-image.v1" if selected == "rollback" else
                                 "openclaw.fork-release-image.v2") and
         image.get("architecture") == "amd64" and SHA.fullmatch(image.get("sourceSha", "")),
         "trial.image.receipt")
    if selected != "rollback":
        qualified_image(image, retained=retained)
    need(all(DIGEST.fullmatch(image.get(k, "")) for k in
             ("indexDigest", "imageDigest", "configDigest")), "trial.image.digests")
    if selected != "rollback":
        need(image.get("producer", {}).get("kind") == "gcp" and
             SHA.fullmatch(image["producer"].get("toolingSha", "")), "trial.image.producer")
        payload = {item["id"]: item for item in image.get("pluginPayload", [])}
        codex = payload.get("codex", {}).get("codexRuntime", {})
        board = payload.get("workboard", {}).get("workboardRuntime", {})
        need(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", image.get("bundledCodexVersion", "")) and
             all(codex.get(key) == image.get("bundledCodexVersion") for key in
                 ("packageVersion", "cliVersion", "initializeVersion")) and
             codex.get("initialized") is True and codex.get("shutdown") == "exited" and
             board == {"worker": "sqlite", "roundTrip": True, "closed": True},
             "trial.image.native_proof")
    exact(clean, "schema receiptId restorationState restoreReceiptSha256 baselineSourceSha "
          "baselineImageDigest snapshotIdentity mountRoot filesystemDevice devicePath "
          "deviceMajorMinor mounts configSha256 integrationsDisabled", "trial.clean.fields")
    expected_state = "doctor-interrupted" if continuing(check) else ("doctor-complete" if selected == "startup" else "unmigrated")
    need(clean["schema"] == "openclaw.snapshot-clean-input.v1" and
         clean["restorationState"] == expected_state and
         release.IDENT.fullmatch(clean["receiptId"]) and
         release.IDENT.fullmatch(clean["snapshotIdentity"]) and
         HEX.fullmatch(clean["restoreReceiptSha256"]) and
         SHA.fullmatch(clean["baselineSourceSha"]) and DIGEST.fullmatch(clean["baselineImageDigest"]) and
         HEX.fullmatch(clean["configSha256"]) and clean["integrationsDisabled"] is True,
         "trial.clean.identity")
    root = path(clean["mountRoot"])
    need(type(clean["filesystemDevice"]) is int and clean["filesystemDevice"] > 0 and
         re.fullmatch(r"[0-9]+:[0-9]+", clean["deviceMajorMinor"]), "trial.clean.device")
    if continuing(check) and not legacy_continuation:
        artifact_accounting(check, clean)
    reuse = backup_reuse(check)
    if reuse is not None:
        need(reuse["targetSourceSha"] == image["sourceSha"] and
             reuse["targetImageReceiptSha256"] == plan["imageReceiptSha256"] and
             image["sourceSha"] != reuse["originSourceSha"], "trial.reuse.target")
    device = path(clean["devicePath"], canonical=False)
    need(str(device).startswith("/dev/"), "trial.clean.device_path")
    mounts = clean["mounts"]
    need(type(mounts) is list and 3 <= len(mounts) <= 16, "trial.mounts.count")
    targets, sources = {}, []
    for mount in mounts:
        exact(mount, "source target readOnly", "trial.mount.fields")
        need(type(mount["readOnly"]) is bool, "trial.mount.read_only")
        # UID1000 owns private snapshot state. The fixed owner probe validates
        # physical canonical paths before admission; parsing cannot stat them.
        source, target = path(mount["source"], canonical=False), Path(mount["target"])
        need(root in source.parents, "trial.mount.outside_dataset")
        need(str(target) == mount["target"] and str(target).startswith("/") and
             not any(c in str(target) for c in ",\n\r\0") and ".." not in target.parts,
             "trial.mount.target")
        need(str(target) in (STATE_TARGET, "/tmp", "/rehearsal/cache", "/srv/openkb") or
             str(target).startswith(("/home/node/workspace/", "/data/")) or
             (mount["readOnly"] and project_target(target)), "trial.mount.target_scope")
        need(target not in targets, "trial.mount.duplicate_target")
        for previous in sources:
            if overlaps(source, Path(previous["source"])):
                need(direct_source_overlay(previous, mount) or direct_source_overlay(mount, previous),
                     "trial.mount.source_overlap")
        targets[target] = mount
        sources.append(mount)
    need({Path(STATE_TARGET), Path("/tmp"), Path("/rehearsal/cache")}.issubset(targets),
         "trial.mount.required")
    need(all(not targets[Path(target)]["readOnly"] for target in (STATE_TARGET, "/tmp", "/rehearsal/cache")),
         "trial.mount.required_writable")
    for target, child in targets.items():
        for ancestor in target.parents:
            if ancestor in targets:
                parent = targets[ancestor]
                need(child["readOnly"] and not parent["readOnly"] and project_target(target) and
                     (str(ancestor) == STATE_TARGET or project_target(ancestor)), "trial.mount.nested_scope")
    if selected != "doctor":
        contract = None
        if selected == "rollback":
            contract = checks.validate_phase(native_phase(plan), image, clean,
                {key: plan[key] for key in ("imageReceiptSha256", "cleanInputSha256")})
        checks.command(native_phase(plan), limits["timeoutSeconds"], contract)


DATA_OWNER_PROBE = r'''
import hashlib, json, os, stat, sys
from pathlib import Path
def require(value):
    if not value:
        raise ValueError("data-owner-probe refused")
try:
    require(os.geteuid() == 1000)
    raw = sys.stdin.buffer.read(65537)
    require(len(raw) <= 65536)
    request = json.loads(raw)
    require(type(request) is dict and set(request) == {"root", "sources", "config"})
    def canonical(value):
        require(type(value) is str and value.startswith("/") and value != "/")
        p = Path(value)
        require(str(p) == value and ".." not in p.parts and len(p.parts) <= 128 and p.resolve(strict=True) == p)
        return p
    root = canonical(request["root"])
    sources = request["sources"]
    require(type(sources) is list and 3 <= len(sources) <= 16 and len(set(sources)) == len(sources))
    directories = {}
    for value in sources:
        source = canonical(value)
        require(root in source.parents)
        for current in (source, *source.parents):
            info = current.lstat()
            require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode))
            directories[str(current)] = {"device": info.st_dev, "inode": info.st_ino,
                                         "mode": info.st_mode, "uid": info.st_uid}
            if current == root:
                break
    config = canonical(request["config"])
    require(config.name == "openclaw.json" and str(config.parent) in sources)
    descriptor = os.open(config, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 1000 and before.st_size <= 1048576)
        content = stream.read(1048577)
        after = os.fstat(stream.fileno())
        require(len(content) <= 1048576 and len(content) == before.st_size and
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns))
    print(json.dumps({"schema": "openclaw.snapshot-owner-metadata.v1", "uid": os.geteuid(),
                      "directories": directories, "configSha256": hashlib.sha256(content).hexdigest()},
                     sort_keys=True, separators=(",", ":")))
except Exception:
    sys.exit("data-owner-probe refused")
'''


def data_owner_metadata(clean):
    """Read only listed metadata/config hash using the established UID1000 route."""
    root = path(clean["mountRoot"])
    sources = [path(m["source"], canonical=False) for m in clean["mounts"]]
    state = next(Path(m["source"]) for m in clean["mounts"] if m["target"] == STATE_TARGET)
    request = durable.encode({"root": str(root), "sources": [str(p) for p in sources],
                              "config": str(state / "openclaw.json")})
    need(len(request) <= 65536, "trial.owner_probe.input_limit")
    args = ["/usr/bin/python3", "-I", "-c", DATA_OWNER_PROBE]
    if os.geteuid() != 1000:
        args = ["/usr/bin/sudo", "-n", "-u", "frmeyer", "--", *args]
    result = subprocess.run(args, input=request, capture_output=True, timeout=30, env=durable.SAFE_ENV)
    need(result.returncode == 0 and len(result.stdout) <= 1024 * 1024 and len(result.stderr) <= 65536,
         "trial.owner_probe.failed")
    metadata = json.loads(result.stdout)
    exact(metadata, "schema uid directories configSha256", "trial.owner_probe.fields")
    need(metadata["schema"] == "openclaw.snapshot-owner-metadata.v1" and metadata["uid"] == 1000 and
         metadata["configSha256"] == clean["configSha256"], "trial.owner_probe.binding")
    expected = {str(root)}
    for source in sources:
        need(root in source.parents, "trial.mount.outside_dataset")
        current = source
        while current != root:
            expected.add(str(current))
            current = current.parent
    need(type(metadata["directories"]) is dict and set(metadata["directories"]) == expected,
         "trial.owner_probe.paths")
    for info in metadata["directories"].values():
        exact(info, "device inode mode uid", "trial.owner_probe.stat_fields")
        need(all(type(v) is int for v in info.values()) and info["device"] > 0 and info["inode"] > 0 and
             info["uid"] >= 0 and stat.S_ISDIR(info["mode"]), "trial.owner_probe.stat")
    observed = root.stat()
    need(metadata["directories"][str(root)]["device"] == observed.st_dev == clean["filesystemDevice"] and
         metadata["directories"][str(root)]["inode"] == observed.st_ino, "trial.owner_probe.root_changed")
    return metadata["directories"]


def source_identities(clean, metadata=None):
    """Stat only listed roots and their ancestors, never directory contents."""
    root, result, lineages = path(clean["mountRoot"]), {}, []
    for mount in clean["mounts"]:
        source = path(mount["source"], canonical=metadata is None)
        need(root in source.parents, "trial.mount.outside_dataset")
        lineage, current = {}, source
        while current != root:
            if metadata is None:
                info = current.stat()
                entry = {"mode": info.st_mode, "device": info.st_dev, "inode": info.st_ino}
            else:
                entry = metadata[str(current)]
            need(stat.S_ISDIR(entry["mode"]) and entry["device"] == clean["filesystemDevice"], "trial.dataset.bind")
            lineage[current] = (entry["device"], entry["inode"])
            if current == source:
                identity = lineage[current]
                result[str(source)] = {"device": entry["device"], "inode": entry["inode"]}
            current = current.parent
        for previous, previous_lineage, previous_mount in lineages:
            if direct_source_overlay(previous_mount, mount):
                parent, parent_id, parent_lineage = previous_mount, previous, previous_lineage
                child_id, child_lineage = identity, lineage
            elif direct_source_overlay(mount, previous_mount):
                parent, parent_id, parent_lineage = mount, identity, lineage
                child_id, child_lineage = previous, previous_lineage
            else:
                need(not overlaps(source, Path(previous_mount["source"])) and
                     identity not in previous_lineage.values() and previous not in lineage.values(),
                     "trial.mount.physical_alias")
                continue
            # The allowed textual nesting must also be the observed physical
            # ancestry, with no duplicate root or alternate ancestor alias.
            need(parent_id != child_id and child_lineage.get(Path(parent["source"])) == parent_id and
                 list(child_lineage.values()).count(parent_id) == 1 and child_id not in parent_lineage.values(),
                 "trial.mount.physical_alias")
        lineages.append((identity, lineage, mount))
    return result


def block_devices(clean):
    """Bind the exact mounted filesystem and its whole-disk throttle target."""
    root = path(clean["mountRoot"])
    need(root.is_mount() and root.stat().st_dev == clean["filesystemDevice"] and
         root.stat().st_dev != Path("/").stat().st_dev, "trial.dataset.mount")
    device = path(clean["devicePath"], canonical=False)
    resolved = device.resolve(strict=True)
    need(str(resolved).startswith("/dev/"), "trial.dataset.device_target")
    info = resolved.stat()
    need(stat.S_ISBLK(info.st_mode) and
         f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}" == clean["deviceMajorMinor"],
         "trial.dataset.device")
    mounted = root.stat().st_dev
    filesystem_major_minor = f"{os.major(mounted)}:{os.minor(mounted)}"

    def sysfs(major_minor):
        location = (Path("/sys/dev/block") / major_minor).resolve(strict=True)
        need(Path("/sys/devices") in location.parents and location.is_dir() and
             (location / "dev").read_text().strip() == major_minor, "trial.dataset.sysfs_device")
        return location

    def node(location, major_minor):
        need(re.fullmatch(r"[A-Za-z0-9_.!-]+", location.name), "trial.dataset.device_name")
        result = Path("/dev") / location.name
        need(result.resolve(strict=True) == result, "trial.dataset.device_node_alias")
        native = result.stat()
        need(stat.S_ISBLK(native.st_mode) and
             f"{os.major(native.st_rdev)}:{os.minor(native.st_rdev)}" == major_minor,
             "trial.dataset.device_node")
        return result

    filesystem_sys = sysfs(filesystem_major_minor)
    filesystem_path = node(filesystem_sys, filesystem_major_minor)
    marker = filesystem_sys / "partition"
    if marker.exists():
        need(re.fullmatch(r"[1-9][0-9]*", marker.read_text().strip()), "trial.dataset.partition")
        io_sys = filesystem_sys.parent
        io_major_minor = (io_sys / "dev").read_text().strip()
        need(re.fullmatch(r"[0-9]+:[0-9]+", io_major_minor) and
             io_major_minor != filesystem_major_minor and sysfs(io_major_minor) == io_sys,
             "trial.dataset.io_parent")
    else:
        io_sys, io_major_minor = filesystem_sys, filesystem_major_minor
    need(not (io_sys / "partition").exists(), "trial.dataset.io_not_whole_disk")
    io_path = node(io_sys, io_major_minor)
    device_sys = sysfs(clean["deviceMajorMinor"])
    need((device_sys == filesystem_sys and resolved == filesystem_path) or
         (device_sys == io_sys and resolved == io_path), "trial.dataset.device_parent")
    return {"filesystemPath": str(filesystem_path), "filesystemMajorMinor": filesystem_major_minor,
            "devicePath": str(resolved), "deviceMajorMinor": clean["deviceMajorMinor"],
            "ioPath": str(io_path), "ioMajorMinor": io_major_minor,
            "filesystemSysfs": str(filesystem_sys), "ioSysfs": str(io_sys)}


def snapshot_paths(clean):
    block_devices(clean)
    return source_identities(clean, data_owner_metadata(clean))


def native(args, timeout=30):
    result = subprocess.run(args, capture_output=True, timeout=timeout, env=durable.SAFE_ENV)
    need(len(result.stdout) <= 1024 * 1024 and len(result.stderr) <= 64 * 1024,
         "trial.native.output_limit")
    need(result.returncode == 0, "trial.native.failed")
    return result.stdout


def docker(args, timeout=30):
    return native([*durable.DOCKER, "--host", durable.ENDPOINT, *args], timeout)


def inspect_container(cid):
    need(HEX.fullmatch(cid), "trial.container.id")
    return json.loads(docker(["inspect", cid]))[0]


def capacity(plan, clean, admission=False):
    mem = dict(line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
    result = {"at": durable.now(), "memoryAvailableBytes": int(mem["MemAvailable"].split()[0]) * 1024}
    for key, location in (("rootFreeBytes", "/"), ("dataFreeBytes", clean["mountRoot"])):
        fs = os.statvfs(location)
        result[key] = fs.f_bavail * fs.f_frsize
    limits = plan["limits"]
    need(result["rootFreeBytes"] >= limits["minRootFreeBytes"] and
         result["dataFreeBytes"] >= limits["minDataFreeBytes"], "trial.capacity.disk")
    if admission:
        need(result["memoryAvailableBytes"] >= limits["minMemoryAvailableBytes"],
             "trial.capacity.memory")
    return result


def observe_image(image, selected="doctor"):
    if selected != "rollback":
        qualified_image(image)
    value = json.loads(docker(["image", "inspect", image["indexDigest"]]))[0]
    ids = {image[k] for k in ("indexDigest", "imageDigest", "configDigest")}
    cfg = value["Config"]
    need(value["Id"] in ids and value["Os"] == "linux" and value["Architecture"] == "amd64"
         and cfg.get("Labels", {}).get("org.opencontainers.image.revision") == image["sourceSha"]
         and cfg.get("Labels", {}).get("org.opencontainers.image.version") == image["version"]
         and not cfg.get("Volumes"), "trial.image.loaded_binding")
    return {"loadedId": value["Id"], "env": cfg.get("Env", [])}


def no_other_writer(clean):
    ids = docker(["ps", "--quiet", "--no-trunc"]).decode().split()
    need(len(ids) <= 64 and all(HEX.fullmatch(cid) for cid in ids), "trial.active_container_count")
    if ids:
        rows = docker(["inspect", "--format", "{{json .Mounts}}", *ids]).decode().splitlines()
        sources = [path(m["source"], canonical=False) for m in clean["mounts"]]
        for row in rows:
            for mount in json.loads(row):
                if mount.get("RW") and mount.get("Source"):
                    need(not any(overlaps(source, Path(mount["Source"]).resolve()) for source in sources),
                         "trial.dataset.active_writer")


def gate_script(op):
    # Node timers keep a stable process set; shell sleep would add transient PIDs
    # and make native-descendant quiescence indistinguishable from gate polling.
    return ("const directory = " + json.dumps(ADMISSION) + ";\n" +
            "const prefix = " + json.dumps("OPENCLAW_TRIAL_" + op.name + "_") + ";\n" + r"""
const fs = require('node:fs');
const {spawn} = require('node:child_process');
const {constants} = require('node:os');
async function waitFor(name, exitCode) {
  const deadline = Date.now() + 60000;
  while (!fs.existsSync(directory + '/' + name)) {
    if (Date.now() >= deadline) throw Object.assign(new Error('gate timeout: ' + name), {exitCode});
    await new Promise(resolve => setTimeout(resolve, 100));
  }
}
function emit(text) {
  return new Promise((resolve, reject) => process.stdout.write(text, error => error ? reject(error) : resolve()));
}
(async () => {
  await emit(prefix + 'READY\n');
  await waitFor('go', 70);
  const args = process.argv.slice(1);
  const code = await new Promise(resolve => {
    const child = spawn(args[0], args.slice(1), {stdio: 'inherit'});
    child.once('error', () => resolve(127));
    child.once('exit', (code, signal) => resolve(code === null ? 128 + (constants.signals[signal] || 1) : code));
  });
  await emit('\n' + prefix + 'EXIT=' + code + '\n');
  await waitFor('settled', 71);
  process.exitCode = code;
})().catch(error => {
  process.stderr.write(String(error.message) + '\n');
  process.exitCode = error.exitCode || 70;
});
""")


def create_argv(op, intent, devices):
    plan, clean, image = intent["plan"], intent["clean"], intent["image"]
    limits = plan["limits"]
    args = ["create", "--pull=never", "--platform", "linux/amd64", "--name", "openclaw-doctor-" + op.name,
            "--label", "openclaw.snapshot-trial.operation=" + op.name,
            "--network", "none", "--ipc", "none", "--user", "1000:1000", "--init",
            "--cpus", str(limits["cpus"]), "--memory", str(limits["memoryBytes"]),
            "--memory-swap", str(limits["memoryBytes"]), "--pids-limit", "512", "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--restart", "no",
            "--no-healthcheck", "--log-driver", "none", "--stop-timeout", "30",
            "--device-read-bps", f"{devices['ioPath']}:{limits['readBps']}",
            "--device-write-bps", f"{devices['ioPath']}:{limits['writeBps']}"]
    for mount in sorted(clean["mounts"], key=lambda item: (len(Path(item["target"]).parts), item["target"])):
        args += ["--mount", f"type=bind,src={mount['source']},dst={mount['target']}" +
                 (",readonly" if mount["readOnly"] else "")]
    args += ["--mount", f"type=bind,src={op / 'gate'},dst={ADMISSION},readonly"]
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/home/node", "TMPDIR": "/tmp",
           "SQLITE_TMPDIR": "/tmp", "XDG_CACHE_HOME": "/rehearsal/cache", "OPENCLAW_STATE_DIR": STATE_TARGET,
           "OPENCLAW_CONFIG_PATH": STATE_TARGET + "/openclaw.json", "OPENCLAW_SERVICE_REPAIR_POLICY": "external",
           "OPENCLAW_NO_AUTO_UPDATE": "1", "NODE_DISABLE_COMPILE_CACHE": "1"}
    for name in ("CHANNELS", "PROVIDERS", "CRON", "GMAIL_WATCHER", "CANVAS_HOST",
                 "BROWSER_CONTROL_SERVER", "STARTUP_MODEL_PREWARM"):
        env["OPENCLAW_SKIP_" + name] = "1"
    reuse = backup_reuse(intent.get("check"))
    if reuse is not None:
        native = {key: reuse[key] for key in ("schema", "originSourceSha", "originImageDigest",
                  "originImageReceiptSha256", "targetSourceSha", "backupId", "manifestSha256")}
        env["OPENCLAW_DOCTOR_BACKUP_REUSE_PROOF"] = json.dumps(native, sort_keys=True, separators=(",", ":"))
    command = DOCTOR if phase(plan) == "doctor" else checks.command(
        native_phase(plan), limits["timeoutSeconds"], image.get("gatewayProbeContract"))
    return [*args, "--entrypoint", "/usr/bin/env", image["indexDigest"], "-i",
            *(f"{k}={v}" for k, v in env.items()), "node", "-e", gate_script(op), "--",
            "/usr/bin/timeout", "--signal=TERM", "--kill-after=30",
            str(limits["timeoutSeconds"]) + "s", *command]


def service_argv(op):
    return [*durable.SYSTEMD_RUN, "--unit=openclaw-snapshot-doctor-" + op.name, "--service-type=exec",
            "--uid=" + str(os.getuid()), "--gid=" + str(os.getgid()), "--property=Restart=no",
            "--property=RemainAfterExit=yes", "--property=UMask=0077", "--property=MemoryMax=512M",
            "--property=CPUQuota=50%", "--property=KillMode=control-group", "--property=TimeoutStopSec=90",
            "--property=StandardOutput=journal", "--property=StandardError=journal",
            "--", sys.executable, "-B", str(op / "supervisor/gcp_snapshot_trial.py"), "_serve", str(op)]


def prepare(plan_path, image_path, clean_path, tooling, check_path=None):
    plan, _ = private_json(plan_path)
    image, image_hash = private_json(image_path)
    clean, clean_hash = private_json(clean_path)
    check, check_hash = private_json(check_path) if check_path is not None else (None, None)
    validate(plan, image, clean, check)
    need(check_hash == plan.get("checkInputSha256"), "trial.check.input_hash")
    need(image_hash == plan["imageReceiptSha256"] and clean_hash == plan["cleanInputSha256"], "trial.input.hash")
    tooling = Path(tooling).resolve()
    durable.clean_checkout(tooling, plan["toolingSha"])
    files = {name: subprocess.check_output(["git", "-C", str(tooling), "show",
             f"{plan['toolingSha']}:scripts/fork-release/{name}"]) for name in HELPERS}
    verify_running_helpers({name: digest(data) for name, data in files.items()})
    root = release.private_root(PRIVATE_ROOT)
    need(not overlaps(root.resolve(), path(clean["mountRoot"])), "trial.control.overlap")
    op = root / plan["operationId"]
    op.mkdir(mode=0o700)
    (op / "supervisor").mkdir(mode=0o700)
    for name, data in files.items():
        durable.write_once(op / "supervisor" / name, data)
    for name, source in (("image-receipt.json", image_path), ("clean-input.json", clean_path)):
        durable.write_once(op / name, durable.private_bytes(source))
    if check_path is not None:
        durable.write_once(op / "check-input.json", durable.private_bytes(check_path))
    intent = {"schema": "openclaw.snapshot-trial-intent.v1", "plan": plan, "image": image, "clean": clean,
              "ownerUid": os.getuid(), "ownerGid": os.getgid(), "preparedAt": durable.now(),
              "helpers": {name: digest(data) for name, data in files.items()}}
    if check is not None:
        intent["check"] = check
    durable.write_once(op / "intent.json", durable.encode(intent))
    return op


def read_operation(op, *, retained=False):
    op = Path(op).absolute()
    need(op.resolve() == op and op.parent == PRIVATE_ROOT.resolve(), "trial.operation.path")
    info = op.stat()
    need(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, "trial.operation.owner")
    intent, _ = private_json(op / "intent.json")
    need(intent["ownerUid"] == os.getuid() and intent["ownerGid"] == os.getgid() and
         intent["plan"]["operationId"] == op.name, "trial.intent.owner")
    validate(intent["plan"], intent["image"], intent["clean"], intent.get("check"), retained=retained)
    if "checkInputSha256" in intent["plan"]:
        value, hashed = private_json(op / "check-input.json")
        need(hashed == intent["plan"]["checkInputSha256"] and value == intent["check"], "trial.check.changed")
    for name, key in (("image-receipt.json", "imageReceiptSha256"), ("clean-input.json", "cleanInputSha256")):
        value, hashed = private_json(op / name)
        need(hashed == intent["plan"][key] and value == intent["image" if key.startswith("image") else "clean"],
             "trial.input.changed")
    need(set(intent["helpers"]) == set(HELPERS), "trial.helpers.fields")
    for name, hashed in intent["helpers"].items():
        need(digest(durable.private_bytes(op / "supervisor" / name)) == hashed, "trial.helper.changed")
    return op, intent


def load(op):
    op, intent = read_operation(op)
    verify_running_helpers(intent["helpers"])
    return op, intent


def read_retained(op):
    op, intent = read_operation(op, retained=True)
    manifest = digest(json.dumps(intent["helpers"], sort_keys=True, separators=(",", ":")).encode())
    need(intent["helpers"] == LOADED_HELPER_HASHES or
         RETAINED_HELPERS.get(intent["plan"]["toolingSha"]) == manifest,
         "trial.prior.unreviewed_helpers")
    return op, intent


def retained_devices(prior, start_record):
    if prior["plan"]["toolingSha"] == LEGACY_DEVICE_SHA:
        need("devices" not in start_record, "trial.prior.legacy_devices")
        return {"ioPath": prior["clean"]["devicePath"]}
    need("devices" in start_record, "trial.prior.devices_missing")
    return start_record["devices"]


def phase_prerequisites(op, intent):
    """Resolve private prior authority; caller-embedded result JSON is not proof."""
    selected = phase(intent["plan"])
    continuation = continuing(intent.get("check"))
    if selected == "doctor" and not continuation:
        return None
    check = intent["check"]
    previous, prior = read_retained(PRIVATE_ROOT / check["doctorOperationId"])
    need(phase(prior["plan"]) == "doctor", "trial.prior.not_doctor")
    result, hashed = private_json(previous / "result.json")
    need(hashed == check["doctorResultSha256"], "trial.prior.result_hash")
    observed = status(previous, retained=True)
    accepted = ("failed",) if continuation else (("succeeded",) if selected == "startup" else ("succeeded", "failed"))
    need(observed["state"] in accepted and observed.get("result") == result, "trial.prior.not_settled")
    start_record = durable.read_private(previous / "start-intent.json")
    prior_hash = digest(durable.private_bytes(previous / "intent.json"))
    need(start_record["intentSha256"] == prior_hash, "trial.prior.intent_hash")
    if continuation:
        need(check["doctorIntentSha256"] == prior_hash, "trial.continuation.intent_hash")
        need(timestamp(result["at"]) <= timestamp(check["reconciliation"]["observedAt"]) <= datetime.now(timezone.utc),
             "trial.continuation.reconciliation_time")
    if selected == "rollback" and result.get("cleanup") == "not_started":
        need(durable.prove_trial_no_create_failure(previous, prior_hash) == result,
             "trial.prior.no_create_changed")
        state = {"StartedAt": None, "FinishedAt": None}
    else:
        need(result["cleanup"] == "owned_container_stopped_retained", "trial.prior.not_settled")
        retained = durable.read_private(previous / "container.json")
        need(retained["id"] == result["containerId"], "trial.prior.container_receipt")
        actual = inspect_container(result["containerId"])
        validate_owned_container(actual, result["containerId"], previous)
        before = result["nativeState"]
        state = actual["State"]
        need(state["Running"] is False and state["Pid"] == 0 and
             all(state[key] == before[key] for key in ("StartedAt", "FinishedAt", "ExitCode", "OOMKilled")),
             "trial.prior.container_changed")
        validate_container(actual, previous, prior, start_record["image"]["env"], retained_devices(prior, start_record))
    clean, old = intent["clean"], prior["clean"]
    reuse = backup_reuse(check)
    common = ("snapshotIdentity", "baselineSourceSha", "baselineImageDigest")
    need(all(clean[key] == old[key] for key in common), "trial.prior.snapshot_binding")
    if selected == "startup" or continuation:
        same = ("restoreReceiptSha256", "mountRoot", "filesystemDevice", "devicePath", "deviceMajorMinor", "mounts")
        image_same = intent["plan"]["imageReceiptSha256"] == prior["plan"]["imageReceiptSha256"]
        prior_reuse = backup_reuse(prior.get("check"))
        # A later Doctor continuation must keep the original group's proof.
        # Dropping it would recapture from the already modified test copy.
        same_build = image_same and (not continuation or reuse == prior_reuse)
        cross_build = (continuation and reuse is not None and not image_same and
                       prior_reuse is None and
                       prior["plan"]["imageReceiptSha256"] == reuse["originImageReceiptSha256"] and
                       all(prior["image"].get(key) == value for key, value in HISTORICAL_IMAGE.items()) and
                       prior["image"].get("producer", {}).get("toolingSha") == HISTORICAL_PRODUCER and
                       intent["image"]["sourceSha"] == reuse["targetSourceSha"] and
                       intent["plan"]["imageReceiptSha256"] == reuse["targetImageReceiptSha256"])
        need(all(clean[key] == old[key] for key in same) and
             (same_build or cross_build),
             "trial.prior.startup_binding")
        need(snapshot_paths(clean) == start_record["mounts"], "trial.prior.startup_mount_changed")
        current_devices = block_devices(clean)
        if prior["plan"]["toolingSha"] == LEGACY_DEVICE_SHA:
            need(current_devices["deviceMajorMinor"] == old["deviceMajorMinor"] and
                 current_devices["ioMajorMinor"] == old["deviceMajorMinor"], "trial.prior.legacy_parent_changed")
        else:
            need(current_devices == start_record["devices"], "trial.prior.startup_device_changed")
        helper_check = {"imageReceiptSha256": prior["plan"]["imageReceiptSha256"],
                        "cleanInputSha256": prior["plan"]["cleanInputSha256"], "doctorResult": result}
    else:
        need(clean["restoreReceiptSha256"] != old["restoreReceiptSha256"] and
             not overlaps(path(clean["mountRoot"]), path(old["mountRoot"])) and
             all(not overlaps(path(a["source"], canonical=False), path(b["source"], canonical=False))
                 for a in clean["mounts"] for b in old["mounts"]), "trial.prior.rollback_not_fresh")
        # A sequential detach/delete/restore may reuse the same device numbers.
        # The restore owner binds the distinct receipt to the new cloud disk ID.
        helper_check = {key: intent["plan"][key] for key in ("imageReceiptSha256", "cleanInputSha256")}
    contract = None if continuation else checks.validate_phase(native_phase(intent["plan"]), intent["image"], clean, helper_check)
    proof = {"operationId": previous.name, "intentSha256": prior_hash, "resultSha256": hashed,
            "containerId": result["containerId"], "startedAt": state["StartedAt"],
            "finishedAt": state["FinishedAt"], "probeContract": contract}
    if continuation:
        proof.update(invocationId=result["invocationId"], priorResourceProfile=resource_profile(prior["plan"]["limits"]),
                     priorLimits=prior["plan"]["limits"],
                     reconciliationSha256=digest(durable.encode(check["reconciliation"])))
        if reuse is not None:
            proof.update(priorImageReceiptSha256=prior["plan"]["imageReceiptSha256"],
                         successorImageReceiptSha256=intent["plan"]["imageReceiptSha256"],
                         backupReuseSha256=digest(durable.encode(reuse)))
    if "continuedFrom" in result:
        proof["continuedFrom"] = result["continuedFrom"]
    return proof


def sync_private_claim(claim, expected):
    """Make an exact, already validated private claim durable on retry."""
    descriptor = os.open(claim, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        need(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.getuid() and
             metadata.st_mode & 0o077 == 0, "trial.continuation.claim_not_private")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            need(stream.read(CAP + 1) == expected, "trial.continuation.claim_changed")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    durable.sync_directory(claim.parent)


def verify_continuation_claim(op, intent, prior):
    lease = op.parent / ("dataset-" + digest(intent["clean"]["mountRoot"].encode()) + ".json")
    requested = {"operationId": op.name, "intentSha256": digest(durable.private_bytes(op / "intent.json"))}
    lease_raw = durable.private_bytes(lease)
    need(json.loads(lease_raw) == requested, "trial.continuation.claim_changed")
    raw = durable.private_bytes(op / "dataset-previous.json")
    need(json.loads(raw) == {"operationId": prior["operationId"], "intentSha256": prior["intentSha256"]},
         "trial.continuation.previous_claim")
    transfer_raw = durable.private_bytes(op / "dataset-transfer.json")
    need(json.loads(transfer_raw) == {
        "previousLeaseSha256": digest(raw), "successor": requested, "priorDoctor": prior,
        "checkInputSha256": intent["plan"]["checkInputSha256"]}, "trial.continuation.transfer_changed")
    # A previous attempt may have renamed the lease and then failed to sync
    # its parent. Re-durable all three exact claims before dispatching.
    for claim, value in ((op / "dataset-previous.json", raw),
                         (op / "dataset-transfer.json", transfer_raw), (lease, lease_raw)):
        sync_private_claim(claim, value)


def start(op):
    need(sys.platform == "linux", "trial.requires_linux")
    op, intent = load(op)
    with durable.operation_lock(op):
        if (op / "start-intent.json").exists():
            return status(op)
        clean = intent["clean"]
        prior = phase_prerequisites(op, intent)
        mounts = snapshot_paths(clean)
        devices = block_devices(clean)
        no_other_writer(clean)
        image = observe_image(intent["image"], phase(intent["plan"]))
        resources = capacity(intent["plan"], clean, True)
        continuation_capacity(resources, intent["plan"], intent.get("check"))
        intent_hash = digest(durable.private_bytes(op / "intent.json"))
        lease = op.parent / ("dataset-" + digest(clean["mountRoot"].encode()) + ".json")
        reservation = {"operationId": op.name, "intentSha256": intent_hash}
        def reserve_dataset():
            continuation = continuing(intent.get("check"))
            if continuation:
                # This callback runs inside the global workload lock. Repeat
                # live prior proof at the actual ownership transition boundary.
                need(phase_prerequisites(op, intent) == prior, "trial.prior.changed")
                need(lease.exists(), "trial.continuation.missing_claim")
            try:
                if continuation:
                    raise FileExistsError()
                durable.write_once(lease, durable.encode(reservation))
            except FileExistsError:
                original = durable.private_bytes(lease)
                current = json.loads(original)
                if current == reservation:
                    if continuation:
                        verify_continuation_claim(op, intent, prior)
                    else:
                        sync_private_claim(lease, original)
                    return
                need((phase(intent["plan"]) == "startup" or continuation) and current == {
                    "operationId": prior["operationId"], "intentSha256": prior["intentSha256"]},
                    "trial.dataset.reserved")
                previous_lease = op / "dataset-previous.json"
                if previous_lease.exists():
                    need(durable.private_bytes(previous_lease) == original, "trial.dataset.previous_changed")
                    sync_private_claim(previous_lease, original)
                else:
                    durable.write_once(previous_lease, original)
                if continuation:
                    transfer = {"previousLeaseSha256": digest(original), "successor": reservation,
                                "priorDoctor": prior, "checkInputSha256": intent["plan"]["checkInputSha256"]}
                    if (op / "dataset-transfer.json").exists():
                        need(durable.read_private(op / "dataset-transfer.json") == transfer,
                             "trial.continuation.transfer_changed")
                        sync_private_claim(op / "dataset-transfer.json", durable.encode(transfer))
                    else:
                        durable.write_once(op / "dataset-transfer.json", durable.encode(transfer))
                release.atomic_json(lease, reservation)
        # The common lock checks its current owner, then reserves the dataset,
        # then publishes this global owner. Exact pre-dispatch claims can resume.
        durable.reserve_heavy_workload(op, "doctor", intent_hash, reserve_resource=reserve_dataset)
        durable.write_once(op / "start-intent.json", durable.encode({"intentSha256": intent_hash,
            "requestedAt": durable.now(), "bootId": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "mounts": mounts, "devices": devices, "image": image, "resources": resources, "serviceArgv": service_argv(op),
            "priorDoctor": prior}))
        try:
            result = subprocess.run(service_argv(op), capture_output=True, timeout=30, env=durable.SAFE_ENV)
            record = {"returnCode": result.returncode, "observedAt": durable.now()}
        except (OSError, subprocess.TimeoutExpired):
            record = {"returnCode": None, "observedAt": durable.now()}
        durable.write_once(op / "dispatch.json", durable.encode(record))
    return status(op)


def validate_container(value, op, intent, expected_env, devices):
    h, cfg = value["HostConfig"], value["Config"]
    image, clean, limits = intent["image"], intent["clean"], intent["plan"]["limits"]
    args = create_argv(op, intent, devices)
    entry = args.index("--entrypoint")
    need(value["Image"] in {image[k] for k in ("indexDigest", "imageDigest", "configDigest")} and
         cfg["Image"] == image["indexDigest"] and cfg["User"] == "1000:1000" and
         cfg["Entrypoint"] == [args[entry + 1]] and cfg["Cmd"] == args[entry + 3:] and
         cfg.get("Env", []) == expected_env and value["RestartCount"] == 0 and
         cfg.get("Labels", {}).get("openclaw.snapshot-trial.operation") == op.name, "trial.container.binding")
    need(h["NetworkMode"] == "none" and h["IpcMode"] == "none" and h["ReadonlyRootfs"] and
         h.get("Init") is True and not h["Privileged"] and h["CapDrop"] == ["ALL"] and not h.get("CapAdd") and
         h["SecurityOpt"] in (["no-new-privileges"], ["no-new-privileges=true"]) and
         h["Memory"] == limits["memoryBytes"] and h["MemorySwap"] == limits["memoryBytes"] and
         h["NanoCpus"] == limits["cpus"] * 10**9 and h["PidsLimit"] == 512 and
         h["RestartPolicy"]["Name"] == "no" and h["LogConfig"]["Type"] == "none" and
         cfg["Healthcheck"]["Test"] == ["NONE"], "trial.container.isolation")
    need(not any(h.get(k) for k in ("Devices", "DeviceRequests", "PortBindings", "PublishAllPorts",
         "VolumesFrom", "Binds", "Tmpfs", "Links", "PidMode", "UTSMode")), "trial.container.extra_access")
    expected = {(m["source"], m["target"], not m["readOnly"]) for m in clean["mounts"]}
    expected.add((str(op / "gate"), ADMISSION, False))
    need(len(value["Mounts"]) == len(expected) and
         {(m["Source"], m["Destination"], m["RW"]) for m in value["Mounts"] if m["Type"] == "bind"} == expected,
         "trial.container.mounts")
    for field, limit in (("BlkioDeviceReadBps", "readBps"), ("BlkioDeviceWriteBps", "writeBps")):
        need(h[field] == [{"Path": devices["ioPath"], "Rate": limits[limit]}], "trial.container.io")


def cgroup_path(value):
    pid = value["State"]["Pid"]
    need(type(pid) is int and pid > 0, "trial.cgroup.pid")
    entry = Path(f"/proc/{pid}/cgroup").read_text().strip()
    need(entry.startswith("0::/") and "\n" not in entry and ".." not in entry.split("/"), "trial.cgroup.v2")
    root = Path("/sys/fs/cgroup")
    resolved = (root / entry[4:]).resolve()
    need(root in resolved.parents, "trial.cgroup.path")
    return resolved


def cgroup_sample(root):
    def values(name):
        return {k: int(v) for k, v in (line.split() for line in (root / name).read_text().splitlines())}
    memory = values("memory.stat")
    events = values("memory.events")
    need("oom_kill" in events, "trial.cgroup.events_unavailable")
    return {"at": durable.now(), "current": int((root / "memory.current").read_text()),
            "peak": int((root / "memory.peak").read_text()), "events": events,
            "swap": int((root / "memory.swap.current").read_text()),
            "anon": memory.get("anon"), "file": memory.get("file"), "kernel": memory.get("kernel")}


def cgroup_processes(root):
    with (root / "cgroup.procs").open("rb") as stream:
        raw = stream.read(8193)
    need(len(raw) <= 8192, "trial.cgroup.process_limit")
    pids = sorted({int(pid) for pid in raw.split()})
    need(0 < len(pids) <= 512 and all(pid > 0 for pid in pids), "trial.cgroup.processes_unavailable")
    return pids


def admit_cgroup(root, intent, devices):
    limits = intent["plan"]["limits"]
    need(int((root / "memory.max").read_text()) == limits["memoryBytes"] and
         (root / "memory.swap.max").read_text().strip() == "0" and
         (root / "pids.max").read_text().strip() == "512", "trial.cgroup.memory")
    cpu = (root / "cpu.max").read_text().split()
    need(len(cpu) == 2 and int(cpu[0]) == limits["cpus"] * int(cpu[1]), "trial.cgroup.cpu")
    io = io_rows(root / "io.max")
    need(io.get(devices["ioMajorMinor"], {}).get("rbps") == str(limits["readBps"]) and
         io[devices["ioMajorMinor"]].get("wbps") == str(limits["writeBps"]) and
         all(io[devices["ioMajorMinor"]].get(key, "max") == "max" for key in ("riops", "wiops")),
         "trial.cgroup.io")


def io_rows(file, *, allow_counterless=False):
    raw = file.read_text()
    need(len(raw) <= 65536, "trial.cgroup.io_size")
    rows = {}
    for line in raw.splitlines():
        row = line.split()
        need(row and (allow_counterless or len(row) > 1) and
             re.fullmatch(r"[0-9]+:[0-9]+", row[0]) and row[0] not in rows,
             "trial.cgroup.io_rows")
        values = {}
        for pair in row[1:]:
            need(pair.count("=") == 1, "trial.cgroup.io_fields")
            key, value = pair.split("=")
            need(key not in values and (value == "max" or re.fullmatch(r"[0-9]+", value)),
                 "trial.cgroup.io_fields")
            values[key] = value
        rows[row[0]] = values
    return rows


def io_sample(root, intent, devices, previous=None):
    """Bounded cgroup counters, not a database scan or a migration progress claim."""
    admit_cgroup(root, intent, devices)
    # cgroup v2 may list idle devices as a bare major:minor row. An idle
    # target has no counters yet; other idle devices must not fail admission.
    counters = io_rows(root / "io.stat", allow_counterless=True).get(devices["ioMajorMinor"])
    present = bool(counters)
    need(present or previous is None or not previous["deviceObserved"], "trial.cgroup.io_counter_lost")
    if present:
        need(all(k in counters and counters[k].isdigit() for k in ("rbytes", "wbytes")),
             "trial.cgroup.io_counters")
    counts = {k: int(counters[k]) if present else 0 for k in ("rbytes", "wbytes")}
    stamp = time.monotonic_ns()
    limits = intent["plan"]["limits"]
    sample = {"device": devices["ioMajorMinor"], "deviceObserved": present,
              "monotonicNs": stamp, **counts, "readCapBps": limits["readBps"], "writeCapBps": limits["writeBps"],
              "intervalSeconds": None, "readBps": None, "writeBps": None,
              "readCapRatio": None, "writeCapRatio": None}
    if previous is not None:
        need(previous["device"] == sample["device"] and stamp > previous["monotonicNs"] and
             all(counts[k] >= previous[k] for k in counts), "trial.cgroup.io_counter_changed")
        elapsed = (stamp - previous["monotonicNs"]) / 10**9
        sample["intervalSeconds"] = elapsed
        for prefix, key, cap in (("read", "rbytes", "readBps"), ("write", "wbytes", "writeBps")):
            rate = (counts[key] - previous[key]) / elapsed
            sample[prefix + "Bps"] = rate
            sample[prefix + "CapRatio"] = rate / limits[cap]
    return sample


def successful(state, attach_exit, complete, oom_kills):
    return (state.get("Running") is False and state.get("Pid") == 0 and
            state.get("ExitCode") == 0 and state.get("OOMKilled") is False and
            attach_exit == 0 and complete and oom_kills == 0)


def validate_owned_container(value, cid, op):
    # Policy drift is a reason to stop, never a reason to leave an owned writer
    # running. Stop authority is the exact create ID plus its operation identity.
    need(value["Id"] == cid and value["Name"] == "/openclaw-doctor-" + op.name and
         value["Config"].get("Labels", {}).get("openclaw.snapshot-trial.operation") == op.name,
         "trial.container.stop_ownership")


class RollingLog:
    """Retain the latest two bounded segments; counters/markers are independent."""
    def __init__(self, path):
        self.path, self.size, self.total = path, 0, 0
        self.stream = self._open()

    def _open(self):
        return os.fdopen(os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb", buffering=0)

    def append(self, data):
        if self.size + len(data) > CAP:
            self.stream.close()
            os.replace(self.path, self.path.with_suffix(self.path.suffix + ".previous"))
            self.stream = self._open()
            self.size = 0
        self.stream.write(data)
        self.size += len(data)
        self.total += len(data)

    def close(self):
        os.fsync(self.stream.fileno())
        self.stream.close()


def serve(op):
    op, intent = load(op)
    started = durable.read_private(op / "start-intent.json")
    need(started["intentSha256"] == digest(durable.private_bytes(op / "intent.json")), "trial.intent.changed")
    invocation = os.environ.get("INVOCATION_ID", "")
    need(OP.fullmatch(invocation), "trial.service.invocation")
    durable.write_once(op / "started.json", durable.encode({"invocationId": invocation, "at": durable.now()}))
    cid, child, cg, initial, final, reason = None, None, None, None, None, None
    first_io, last_io, io_samples = None, None, 0
    complete, oom_kills, child_exit, settled = False, 0, None, False
    selected = phase(intent["plan"])
    native_check, check_buffer, check_count = None, b"", 0
    gate_ready, baseline_processes = False, None
    tails = {"stdout.log": b"", "stderr.log": b""}
    logs = {}
    end = time.monotonic() + intent["plan"]["limits"]["timeoutSeconds"]
    interrupted = []
    def stop(signum, _frame):
        interrupted.append(signum)
    old = {sig: signal.signal(sig, stop) for sig in (signal.SIGTERM, signal.SIGINT)}
    selector = selectors.DefaultSelector()
    try:
        need(started["bootId"] == Path("/proc/sys/kernel/random/boot_id").read_text().strip(), "trial.boot.changed")
        need(phase_prerequisites(op, intent) == started.get("priorDoctor"), "trial.prior.changed")
        need(snapshot_paths(intent["clean"]) == started["mounts"], "trial.mount.changed")
        devices = block_devices(intent["clean"])
        need(devices == started["devices"], "trial.devices.changed")
        no_other_writer(intent["clean"])
        need(observe_image(intent["image"], selected) == started["image"], "trial.image.changed")
        admission = capacity(intent["plan"], intent["clean"], True)
        continuation_capacity(admission, intent["plan"], intent.get("check"))
        durable.reserve_heavy_workload(op, "doctor", started["intentSha256"])
        if continuing(intent.get("check")):
            verify_continuation_claim(op, intent, started["priorDoctor"])
        (op / "gate").mkdir(mode=0o755)
        os.chmod(op / "gate", 0o755)
        args = create_argv(op, intent, devices)
        need(block_devices(intent["clean"]) == devices, "trial.devices.changed")
        durable.write_once(op / "create-intent.json", durable.encode({"at": durable.now(), "argv": args}))
        cid = docker(args).decode().strip()
        need(HEX.fullmatch(cid), "trial.create.uncertain")
        durable.write_once(op / "container.json", durable.encode({"id": cid, "at": durable.now()}))
        value = inspect_container(cid)
        validate_container(value, op, intent, started["image"]["env"], devices)
        need(value["State"]["Status"] == "created", "trial.container.not_fresh")
        durable.write_once(op / "container-start-intent.json", durable.encode({"id": cid, "at": durable.now()}))
        logs = {name: RollingLog(op / name) for name in ("stdout.log", "stderr.log", "resources.jsonl")}
        child = subprocess.Popen([*durable.DOCKER, "--host", durable.ENDPOINT, "start", "--attach", cid],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=durable.SAFE_ENV)
        for name, stream in (("stdout.log", child.stdout), ("stderr.log", child.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        next_check = 0
        container_start = None
        while selector.get_map() or child.poll() is None:
            need(not interrupted and time.monotonic() < end, "trial.deadline_or_signal")
            if time.monotonic() >= next_check:
                value = inspect_container(cid)
                validate_container(value, op, intent, started["image"]["env"], devices)
                need(not value["State"]["OOMKilled"], "trial.container.oom")
                if value["State"]["Running"]:
                    if container_start is None:
                        container_start = value["State"]["StartedAt"]
                    need(value["State"]["StartedAt"] == container_start, "trial.container.restarted")
                    if cg is None and gate_ready:
                        cg = cgroup_path(value)
                        need(block_devices(intent["clean"]) == devices, "trial.devices.changed")
                        admit_cgroup(cg, intent, devices)
                        baseline_processes = cgroup_processes(cg)
                        need(len(baseline_processes) == 2 and value["State"]["Pid"] in baseline_processes,
                             "trial.cgroup.gate_processes")
                        initial = cgroup_sample(cg)
                        first_io = last_io = io_sample(cg, intent, devices)
                        io_samples += 1
                        initial["io"] = first_io
                        durable.write_once(op / "cgroup-admission.json", durable.encode({"path": str(cg),
                            "containerStart": container_start, "sample": initial, "processes": baseline_processes}))
                        durable.reserve_heavy_workload(op, "doctor", started["intentSha256"])
                        if continuing(intent.get("check")):
                            need(phase_prerequisites(op, intent) == started["priorDoctor"], "trial.prior.changed")
                            verify_continuation_claim(op, intent, started["priorDoctor"])
                            continuation_capacity(capacity(intent["plan"], intent["clean"]), intent["plan"], intent["check"])
                        durable.write_once(op / "gate/go", b"admitted\n")
                        os.chmod(op / "gate/go", 0o444)
                    if cg is not None:
                        sample = cgroup_sample(cg)
                        last_io = io_sample(cg, intent, devices, last_io)
                        io_samples += 1
                        sample["io"] = last_io
                        oom_kills = sample["events"]["oom_kill"] - initial["events"]["oom_kill"]
                        logs["resources.jsonl"].append(json.dumps(sample).encode() + b"\n")
                        need(oom_kills == 0, "trial.cgroup.oom_kill")
                        if child_exit is not None and not settled:
                            processes = cgroup_processes(cg)
                            durable.write_once(op / "native-quiescence.json", durable.encode({
                                "at": durable.now(), "baselineProcesses": baseline_processes, "processes": processes}))
                            need(processes == baseline_processes, "trial.native.descendants_remain")
                            # Only the trusted gate and init remain. Neither forks
                            # after this point, so no native descendant can OOM
                            # between this final sample and normal cgroup removal.
                            sample = cgroup_sample(cg)
                            last_io = io_sample(cg, intent, devices, last_io)
                            io_samples += 1
                            sample["io"] = last_io
                            oom_kills = sample["events"]["oom_kill"] - initial["events"]["oom_kill"]
                            logs["resources.jsonl"].append(json.dumps(sample).encode() + b"\n")
                            need(oom_kills == 0, "trial.cgroup.oom_kill")
                            durable.write_once(op / "native-settlement.json", durable.encode({
                                "at": durable.now(), "nativeExitCode": child_exit, "processes": processes, "cgroup": sample}))
                            durable.write_once(op / "gate/settled", b"observed\n")
                            os.chmod(op / "gate/settled", 0o444)
                            settled = True
                capacity(intent["plan"], intent["clean"])
                next_check = time.monotonic() + 1
            for key, _ in selector.select(.1):
                data = os.read(key.fd, 65536)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                logs[key.data].append(durable.now().encode() + b" " + data)
                window = tails[key.data] + data
                if selected == "doctor":
                    complete |= b"Doctor complete." in window
                elif key.data == "stdout.log":
                    # Only the trusted checker's stdout carries receipts; native
                    # gateway output is inherited stderr. Parse complete bounded
                    # lines once, including markers split across attach chunks.
                    lines = (check_buffer + data).split(b"\n")
                    check_buffer = lines.pop()
                    need(len(check_buffer) <= 4096 and all(len(line) <= 4096 for line in lines),
                         "trial.check.output_limit")
                    for line in lines:
                        if line.startswith(checks.RESULT_PREFIX.encode()):
                            check_count += 1
                            need(check_count == 1, "trial.check.duplicate_result")
                            native_check = checks.parse_result(line.decode("utf-8"))
                gate_ready |= b"OPENCLAW_TRIAL_" + op.name.encode() + b"_READY\n" in window
                match = re.search(rb"OPENCLAW_TRIAL_" + op.name.encode() + rb"_EXIT=([0-9]{1,3})\n", window)
                if match:
                    child_exit = int(match[1])
                need(b"Startup migration refused" not in window, "trial.doctor.refused")
                tails[key.data] = window[-256:]
        final = inspect_container(cid)
        validate_container(final, op, intent, started["image"]["env"], devices)
        need(final["State"]["StartedAt"] == container_start, "trial.container.final_start_changed")
        need(cg is not None and settled, "trial.exit.before_settlement")
        need(child_exit == 0, "trial.doctor.native_exit")
        if selected != "doctor":
            need(check_count == 1 and not check_buffer, "trial.check.missing_result")
            checks.validate_result(native_check, native_phase(intent["plan"]),
                                   intent["image"].get("gatewayProbeContract"))
            complete = True
        # Docker normally removes this cgroup on exit. Success may use the
        # retained quiescent settlement proof; a surviving cgroup adds evidence.
        if cg.exists():
            last = cgroup_sample(cg)
            last_io = io_sample(cg, intent, devices, last_io)
            io_samples += 1
            last["io"] = last_io
            oom_kills = max(oom_kills, last["events"].get("oom_kill", 0) - initial["events"].get("oom_kill", 0))
            logs["resources.jsonl"].append(json.dumps(last).encode() + b"\n")
        need(successful(final["State"], child.returncode, complete, oom_kills), "trial.doctor.not_successful")
    except Exception as error:
        reason = str(error) if isinstance(error, release.Refusal) else type(error).__name__
    finally:
        cleanup = "not_started"
        if cid and HEX.fullmatch(cid):
            try:
                value = inspect_container(cid)
                validate_owned_container(value, cid, op)
                if value["State"]["Running"]:
                    docker(["stop", "--time", "30", cid], timeout=45)
                final = inspect_container(cid)
                validate_owned_container(final, cid, op)
                need(not final["State"]["Running"] and final["State"]["Pid"] == 0, "trial.stop.unsettled")
                cleanup = "owned_container_stopped_retained"
            except Exception:
                cleanup = "unknown_reconcile_required"
                reason = reason or "trial.stop.unknown"
        if child is not None:
            if child.poll() is None:
                child.kill()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                reason = reason or "trial.attach.unsettled"
            child.stdout.close()
            child.stderr.close()
        selector.close()
        for log in logs.values():
            log.close()
        for sig, handler in old.items():
            signal.signal(sig, handler)
        result = {"operationId": op.name, "at": durable.now(), "invocationId": invocation,
                  "state": "failed" if reason else "succeeded", "reason": reason,
                  "containerId": cid, "nativeState": final["State"] if final else None,
                  "phase": selected, "doctorComplete": complete if selected == "doctor" else False,
                  "nativeCheck": native_check, "oomKillDelta": oom_kills, "cleanup": cleanup,
                  "nativeExitCode": child_exit, "cgroupSettlementObserved": settled,
                  "imageReceiptSha256": intent["plan"]["imageReceiptSha256"],
                  "cleanInputSha256": intent["plan"]["cleanInputSha256"],
                  "resourceProfile": resource_profile(intent["plan"]["limits"]),
                  "ioObservation": {"samples": io_samples, "first": first_io, "last": last_io},
                  "promotionAuthorized": False}
        if "checkInputSha256" in intent["plan"]:
            result["checkInputSha256"] = intent["plan"]["checkInputSha256"]
        if continuing(intent.get("check")):
            result["continuedFrom"] = started["priorDoctor"]
        durable.write_once(op / "result.json", durable.encode(result))
    return 0 if reason is None else 1


def status(op, *, retained=False):
    op, intent = read_retained(op) if retained else load(op)
    output = {"nativeOutput": {}, "operationId": op.name, "phase": phase(intent["plan"]),
              "state": "prepared", "promotionAuthorized": False,
              "resourceProfile": resource_profile(intent["plan"]["limits"])}
    if continuing(intent.get("check")) and "artifacts" in intent["check"]["reconciliation"]:
        output["artifactAccounting"] = artifact_accounting(intent["check"], intent["clean"])
    newest = None
    for name in ("stdout.log", "stderr.log"):
        file = op / name
        if file.is_file():
            info = file.stat()
            with file.open("rb") as stream:
                stream.seek(max(0, info.st_size - 4096))
                tail = stream.read(4096).decode(errors="replace")
            output["nativeOutput"][name] = {"path": str(file), "bytes": info.st_size,
                "modifiedAt": datetime.fromtimestamp(info.st_mtime, timezone.utc).isoformat(), "tail": tail}
            if info.st_size:
                newest = max(newest or 0, info.st_mtime)
    output["nativeQuietSeconds"] = max(0, round(time.time() - newest, 1)) if newest else None
    output["stageProgress"] = "unproven"
    resources = op / "resources.jsonl"
    if resources.is_file():
        with resources.open("rb") as stream:
            stream.seek(max(0, resources.stat().st_size - 4096))
            lines = stream.read(4096).split(b"\n")
        # Ignore an in-flight partial write. A resource sample proves liveness,
        # not that a migration stage has made progress.
        if len(lines) > 1 and lines[-2]:
            try:
                output["lastResourceSample"] = json.loads(lines[-2])
            except ValueError:
                pass
    if not (op / "start-intent.json").exists():
        return output
    output["state"] = "unknown"
    unit = "openclaw-snapshot-doctor-" + op.name + ".service"
    try:
        raw = native([*durable.SYSTEMCTL, "show", unit, "--property=" + ",".join(durable.SHOW_FIELDS)])
        service = dict(line.split("=", 1) for line in raw.decode().splitlines() if "=" in line)
        output["service"] = service
        if (op / "started.json").exists():
            started = durable.read_private(op / "started.json")
            need(service.get("InvocationID") == started["invocationId"],
                 "trial.service.changed")
            output["elapsedSeconds"] = max(0, round(time.time() - datetime.fromisoformat(started["at"].replace("Z", "+00:00")).timestamp(), 1))
        if (op / "native-settlement.json").exists():
            output["lastNativeStage"] = durable.read_private(op / "native-settlement.json")
            output["stageProgress"] = "native-exit-observed"
        if service.get("ActiveState") == "active" and service.get("SubState") == "running":
            output["state"] = "running"
        if (op / "result.json").exists():
            result = durable.read_private(op / "result.json")
            output["result"] = result
            need((op / "started.json").exists() and result["operationId"] == op.name and
                 result["invocationId"] == started["invocationId"] == service.get("InvocationID") and
                 result["imageReceiptSha256"] == intent["plan"]["imageReceiptSha256"] and
                 result["cleanInputSha256"] == intent["plan"]["cleanInputSha256"], "trial.result.binding")
            # Older frozen supervisors have no additive profile receipt. Their
            # original intent remains authority; never rewrite their evidence.
            if "resourceProfile" in result:
                need(result["resourceProfile"] == output["resourceProfile"], "trial.result.profile")
            if continuing(intent.get("check")):
                prior = durable.read_private(op / "start-intent.json")["priorDoctor"]
                need(result.get("continuedFrom") == prior and
                     prior["operationId"] == intent["check"]["doctorOperationId"] and
                     prior["intentSha256"] == intent["check"]["doctorIntentSha256"] and
                     prior["resultSha256"] == intent["check"]["doctorResultSha256"], "trial.result.continuation")
            if "checkInputSha256" in intent["plan"]:
                need(result.get("phase") == phase(intent["plan"]) and
                     result.get("checkInputSha256") == intent["plan"]["checkInputSha256"], "trial.result.phase_binding")
                if result["state"] == "succeeded" and phase(intent["plan"]) != "doctor":
                    checks.validate_result(result.get("nativeCheck"), native_phase(intent["plan"]),
                                           intent["image"].get("gatewayProbeContract"))
                    need(result.get("cgroupSettlementObserved") is True and result.get("nativeExitCode") == 0 and
                         result.get("cleanup") == "owned_container_stopped_retained" and
                         successful(result.get("nativeState") or {}, 0, True, result.get("oomKillDelta")),
                         "trial.result.native_proof")
            need(service.get("LoadState") == "loaded" and service.get("MainPID") == "0" and
                 service.get("ExecMainCode") == "1", "trial.service.not_settled")
            succeeded = result["state"] == "succeeded"
            need(result["state"] in ("succeeded", "failed") and
                 service.get("ExecMainStatus") == ("0" if succeeded else "1") and
                 service.get("Result") == ("success" if succeeded else "exit-code") and
                 (service.get("ActiveState"), service.get("SubState")) ==
                 (("active", "exited") if succeeded else ("failed", "failed")), "trial.service.result_conflict")
            output["state"] = result["state"]
            if output["state"] == "succeeded":
                output["stageProgress"] = phase(intent["plan"]) + "-completed"
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired, release.Refusal):
        output["state"] = "unknown"
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prep = commands.add_parser("prepare")
    for name in ("plan", "image-receipt", "clean-input", "tooling"):
        prep.add_argument("--" + name, type=Path, required=True)
    prep.add_argument("--check-input", type=Path, help="Required private phase evidence reference for v2 plans")
    for name in ("start", "status", "_serve"):
        command = commands.add_parser(name)
        command.add_argument("operation", type=Path)
        if name == "status":
            command.add_argument("--json", action="store_true", help="Structured adapter output; default shows native tails first")
    args = parser.parse_args()
    if args.command == "prepare":
        print(prepare(args.plan, args.image_receipt, args.clean_input, args.tooling, args.check_input))
    elif args.command == "_serve":
        return serve(args.operation)
    else:
        result = {"start": start, "status": status}[args.command](args.operation)
        if args.command == "status" and not args.json:
            for name, observation in result["nativeOutput"].items():
                print(f"{observation['modifiedAt']} {name}\n{observation['tail']}")
        print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
