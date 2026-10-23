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
    "sourceSha": "cc69ab4e786706c0f835427ba5fe884528f302ff",
    "sourceTree": "67b692219f51cb243efbbdf3bd907d3d77a454fd",
    "manifestSha256": "096105a899102e4ebb0d990c9761d80bd14690c97c0cee25b29ef88c2f588cec",
    "inventorySha256": "95a0b9cc23844320daae0fc852fff0e862e6c862f90df77c4182b5d049a18037",
    "indexDigest": "sha256:74e412b6602117b59ce7ea3b000275eacda606df83b3171105fd19f7bd43e5a3",
    "imageDigest": "sha256:aa4006612a6f35503247286066138108108008d3d8d16136cc750ec47e5701a3",
    "configDigest": "sha256:4e84c302e0c075e12b5a4f9b47c4ec32374b7212c3a32ba5eadadf6e16dd2ca3",
    "selectedExtensions": "codex,workboard", "bundledCodexVersion": "0.160.0",
}
LEASE_PATCH_IMAGE = {
    "repository": "fr-meyer/openclaw", "version": "2026.10.5", "architecture": "amd64",
    "sourceSha": "84d65b446d66cd5db5b9c533bd158e9062968692",
    "sourceTree": "f52ccc16baa27b0b83cd79b03c55a5faa273d9d9",
    "manifestSha256": "99829ec0d78f42bbb28f34a94b30f46a68124c2851cb478c379da38bd60369be",
    "inventorySha256": "cc70ef6eaad30e47e02859923c89b76743df6a6983b1e7056ae91d72d20caa39",
    "indexDigest": "sha256:52a587bcf2e793dcff4ca70e3fe5ca2315fa41dcda6d4840a46c64d324d56ca1",
    "imageDigest": "sha256:334dadd8e12ef60339cee139c07dd557d30dc9f082e98e23ace517c0e2c5a423",
    "configDigest": "sha256:68f6400206d53ce43e299d2ffc4ff11fb6ae4d312879c1e2623db848d1780d3b",
    "selectedExtensions": "codex,workboard", "bundledCodexVersion": "0.160.0",
}
LEASE_PATCH_PRODUCER = "d74c72bf32a55f73b0f8d395604892b39d6073c9"
LEASE_PATCH_RECEIPT_SHA256 = "2004c0f3d6100a5677e565d1fbb8f8c2760de70e75717340f8c82d80281f03cc"
LEASE_PATCH_PRIOR = "25102903106f3d34082d5f703a7e758c"
LEASE_PATCH_PRIOR_PIPELINE_SHA = "e18ff4483ddb5a6c2b07332723112ff97b6d630f"
LEASE_PATCH_PRIOR_IMAGE_RECEIPT_SHA256 = "7c71d34de8e2f7f7bae6ad131fcc913b3160f66016e79edb6a900ecea13e2164"
# Distinct final-image startup on the already migrated clone. The prior
# Doctor ran in the older image; compiled image asset parity is unestablished.
DD_DOCTOR = "dd3702b5bc99e4da5fd0062910f935f3"
DD_DOCTOR_PIPELINE_SHA = "719ce41e29f8e0e16d346bc6fcd439c7fed67f88"
DD_DOCTOR_RESULT_SHA256 = "f544f12bf791a822bf20ec413aef481996f5cf172a43d53c2ad6d7b02a922619"
DD_PRIOR_STARTUP = "f2e0c37b2d0544af9220ad23fd277383"
DD_PRIOR_STARTUP_RESULT_SHA256 = "099435c9bbea92c482e1a0d015549923d1d59a618c338c7167de8d1a5b7e556f"
DD_BACKUP_ID = "f8c55592-a39a-8e8c-87cd-40cb5ad53f22"
DD_STARTUP_CHECK = "openclaw.snapshot-trial-check.dd3702-unchanged-config-startup.v1"
DD_COVERAGE_SCHEMA = "openclaw.dd3702-unchanged-config-startup-coverage.v1"
DD_COVERAGE_STATUS = "LIMITED_CROSS_IMAGE_DOCTOR_COVERAGE"
DD_IMAGE_ASSET_BOUNDARY = "NOT_ESTABLISHED"
DD_CLONE_CONFIG_SHA256 = "00310df6ae5dcd4c5a1b53eec93102521b4612198697607f939b1cfadca047b2"
DD_CLONE_RUNTIME_SHA256 = "c96ee2ee390ea1f5366c6e0c8eb184e4cf30f76bfb50121c1623f1172ef01c54"
DD_PLUGIN_PIN_STATUS = "EXPECTED_MISMATCH_CONTROLLER_DISABLED"
DD_FINAL_IMAGE = {
    "repository": "fr-meyer/openclaw",
    "version": "2026.10.5",
    "architecture": "amd64",
    "sourceSha": "7f3ac1fbfd3691546c5b1fd247680a3d00851c76",
    "sourceTree": "ebd66baae19b34b604e166dff5075beec79592de",
    "manifestSha256": "7c2fb3242aac99b123c8baad517915f8d16aa06936dd35613ad30b3075ded0f7",
    "inventorySha256": "4d6860807c32f3b17e353e74b78032d0e3d06556091e8e282fa8f72c4edf788a",
    "indexDigest": "sha256:01471666e50f49747f2eba7d906ba42defef429f652382ccd5a06758d1b710d0",
    "imageDigest": "sha256:f18cc573086482a3aeadd441ea119bfe53e28f6475adc1cf09b626be3aeb6586",
    "configDigest": "sha256:dbd5cac9fe459d649aebf2a8b4ec40c3e14ad86c4063540ba9a3a0579be48a4e",
    "selectedExtensions": "codex,workboard",
    "bundledCodexVersion": "0.160.0",
}
DD_FINAL_PRODUCER = 'a1ea8b7d1758f47a127531c8adcf32fcebb429a1'
DD_FINAL_IMAGE_RECEIPT_SHA256 = 'ff59c90259f0271a4bcb6f443b87576a05da907318026a7f64cbf3994a10a7f4'
DD_FINAL_RUNTIME_SHA256 = "31377ee1c1873d1496e75973e25fc3b0f85c1ff4a83943da23955fada02ecaf9"
DD_FINAL_SOURCE_BOUNDARY_SHA256 = "b922f91354cbc99d815cd466f5c202d0f2e6752cd85a33e57d1c22fd8a9e98d7"
DD_FINAL_COVERAGE_SHA256 = "760a35941f14ca6510a43733680e754908f1acc5ff77e193cbaf1a7558b4e73e"
# Historical final-image timeline attempt. These pins are separate from the
# current DD_FINAL_* candidate so a new sealed image cannot reinterpret its
# retained check, image or dataset lease as current-image evidence.
DD_RETAINED_TIMELINE = "92cfb12dcb504c65a6e84738219c4b69"
DD_RETAINED_TIMELINE_RESULT_SHA256 = "ef88d874a86f7f3c6c67e0bba52eef7e841bbadc5f62cc394bb2a1fe8f92c534"
DD_RETAINED_TIMELINE_TOOLING = "b1541530720a37b64a9726ad8b041c6cc588dd14"
DD_RETAINED_TIMELINE_CHECKS_SHA256 = "3fa06dcf52d8cb91548867a46afac2e611074287338fb9e4252278482dfb1168"
# The exact JS emitted by that helper for the pinned 92cf timeline check.
# This preserves the historical command binding without executing old helpers.
DD_RETAINED_TIMELINE_SCRIPT_SHA256 = "c5b9369a11369d49770136a001e3bf90556505285df0f945a5298fae342e6e80"
DD_RETAINED_TIMELINE_CHECK_SHA256 = "a09288dd697ddacbafe04de5cab183ec39d9378b060ff6ac0903e97efa39e1c8"
DD_RETAINED_TIMELINE_IMAGE_RECEIPT_SHA256 = "61fe55011a7a8bb0a845da0a640b20000ba61db05fcae35c5f0819336d705d01"
DD_RETAINED_TIMELINE_COVERAGE_SHA256 = "b6f996dcbcc825a244a90c0eb22da464f5df33ca5fc2fb2e417ab19afc213568"
DD_RETAINED_TIMELINE_IMAGE = {
    "repository": "fr-meyer/openclaw", "version": "2026.10.5", "architecture": "amd64",
    "sourceSha": "4cf5cb7e256c67a5c98097774cad2d05cd781c01",
    "sourceTree": "e63f5bf2762a58bda6b2d8436830a03914f8704e",
    "manifestSha256": "588ca44c39101e818c59ff3e88f64e19a28db47f819b2bd4f147c5c5869b9d1a",
    "inventorySha256": "85202a5bb8ab3959a9af4669eda7b771e73bbc4f879873f1c517ea9b745dccd5",
    "indexDigest": "sha256:09e12109fb283a0c9740b92c5fa618d69784c9cc6adf76d03d889553618c3ec2",
    "imageDigest": "sha256:77b42d79c8b42502e873b2a3eb1d14a2591eca62b7848b52c622ef1063c21ac0",
    "configDigest": "sha256:8f5f71efc2dbac3159eaba899ba2d0a686035ae0779362f6b6178c8657968946",
    "selectedExtensions": "codex,workboard", "bundledCodexVersion": "0.160.0",
}
DD_RETAINED_TIMELINE_PRODUCER = "b2c3034a0e3f1fdb44f72a6d300e814af74c8f90"
DD_FINAL_CHANGED_PATHS = (
    "Dockerfile",
    "custom-patches/manifest.json",
    "extensions/memory-core/src/dreaming.test.ts",
    "extensions/memory-core/src/dreaming.ts",
    "scripts/docker/runtime-plugins/mergeguez-pr-lifecycle/src/runtime-pin-transition.mjs",
    "scripts/docker/runtime-plugins/mergeguez-pr-lifecycle/src/runtime.mjs",
    "scripts/docker/runtime-plugins/mergeguez-pr-lifecycle/test/capture-integrity.test.mjs",
    "scripts/docker/runtime-plugins/mergeguez-pr-lifecycle/test/current-parity.test.mjs",
    "src/gateway/server-managed-task-flow-runtime.mergeguez-parity.test.ts",
    "src/gateway/server-managed-task-flow-runtime.mergeguez-recovery.test.ts",
    "src/gateway/server-managed-task-flow-runtime.ts",
    "src/plugins/registry-runtime-task-flow.ts",
    "src/plugins/registry-runtime.ts",
    "src/tasks/managed-task-flow-contract.ts",
    "src/tasks/managed-task-flow-host.ts",
    "test/vitest/vitest.gateway-server-paths.mjs",
)
PREVIOUS_IMAGE = {
    **QUALIFIED_IMAGE,
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
    **PREVIOUS_IMAGE,
    "sourceSha": "ae85778296da373dfe7d80101931bafac1acc9dd",
    "sourceTree": "3efb0b6fdb4491462591e2f534161c2b8bab65ab",
    "manifestSha256": "4dfce05ac50a38c7667aeaa3b88f8f60e9c6046bb48a1d361785e77ee5d4ccd2",
    "inventorySha256": "cc4298057d4c61b6e1a488f06fdac93a0ea9263f87811700c0179a470cc495a8",
    "indexDigest": "sha256:f41c7a7762f7a051636b899dac54110c482fb91352431ba6957343b9828f2e9c",
    "imageDigest": "sha256:e4901df74f92d4abeebae37982ff2ef631943446c0cfe37394f86e5351cc6280",
    "configDigest": "sha256:b6eaa3f6594c677f7795b68cda3adc4a34236af242d1a5257642e57574c6527d",
}
QUALIFIED_PRODUCER = "672f8a182cea6219d680bacd400923bf84ec9876"
PREVIOUS_IMAGE_RECEIPT_SHA256 = "b2dbfc302ebeb0cb2ee1fc31d35977905d662a5c1fe5b46e7faeec4c3191af71"
PREVIOUS_PIPELINE_SHA = "ba225c30515c6b4dd8d0c96c67c066b7f8f1d1dc"
CORRECTED_REBUILD_PRIOR = "bc97e00e81908f609cb55d61b109cefe"
HISTORICAL_PRODUCER = "1507a29361d335283f1f4a55d8c037505892f94c"
HISTORICAL_IMAGE_RECEIPT_SHA256 = "98ba31371e306b4e8878161ebf2dce0d021f1be2a3ae5e10384e238fdc9e6178"
BACKUP_REUSE = "openclaw.doctor-backup-reuse.v1"
IO_PROFILES = {(128 << 20, 32 << 20): "read128-write32",
               (256 << 20, 64 << 20): "read256-write64",
               (320 << 20, 128 << 20): "read320-write128"}
LOW_MEMORY_BYTES = 16 << 30
LOW_MEMORY_ADMISSION_BYTES = 20 << 30
LEASE_PATCH_ADMISSION_BYTES = 12 << 30
LEASE_PATCH_HOST_RESERVE_BYTES = 8 << 30
LEASE_PATCH_FULL_PSI_LIMIT = 5.0
LEASE_PATCH_FULL_PSI_SECONDS = 5
CONTINUATION = "openclaw.snapshot-doctor-continuation.v1"
LEGACY_DEVICE_SHA = "a9b6526bbde15c2f9eeb3385e2fa00aa4cadfa39"
LEGACY_CONTINUATION_SHA = "4c57b5269dc882c4c15f4b26fbdbb05a89b2df2d"
# Read-only compatibility for these reviewed or qualified historical supervisors.
# Digest of the sorted compact JSON helper-hash map; never execute old helpers.
RETAINED_HELPERS = {
    LEASE_PATCH_PRIOR_PIPELINE_SHA: "bedac832d1ab2f95b9c813e95db9e41d548c2c25f381f723699dce470281a47d",
    # The settled dd3702 Doctor and f2e0 startup share this exact helper map.
    DD_DOCTOR_PIPELINE_SHA: "2483e1d4a5686553f3bf142bc1fb971abded41c27c09d7f8b72f9af5c441dd7d",
    # The failed first final-image startup is a retained, read-only lease predecessor.
    "f959359ee23744f5db55aace5609d77cd52c0609": "dc3b3951f13484b52ea26fb79c868acc5fd030e7cf969b4c58be7613e5b6a77d",
    DD_RETAINED_TIMELINE_TOOLING: "5832de863cbb8c85173fa7add1d43555696952537c0b70d3a81a44fdb18f2711",
    LEGACY_DEVICE_SHA: "872b6966330c2bb127ae007cf936bffc6e6d7704d9d0ed1a0b7be5de57e8da0d",
    "ad0c1a62300f77e616b1a373c92c967c3cba95b8": "af5caa6316e15bec85b501ff2f8839835546b1e1e5313810a314741479343156",
    LEGACY_CONTINUATION_SHA: "0de004053ed692ae2dc0cbf2d70f336dda72c02c21ba65a893ccac37a4719f97",
    # Actual stopped 16 GiB predecessor; read-only interpretation only.
    "4ad784b4c78d7109c719c22d80c0e927a3299e11": "d36a0a552c5db304b92f915e43f78997bcb58132fc9364eb9afcc0bc8596f556",
    # Exact stopped 4bcf890 Doctor; retain only its reviewed helper manifest.
    PREVIOUS_PIPELINE_SHA: "969db0156d9dfc0480288a913f637a8252dc7ed93988873b7399ae02922a5fb0",
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


def qualified_image(image, *, retained=False, dd_final_startup=False):
    candidates = ((QUALIFIED_IMAGE, QUALIFIED_PRODUCER),
                  (LEASE_PATCH_IMAGE, LEASE_PATCH_PRODUCER))
    if dd_final_startup:
        need(DD_FINAL_IMAGE is not None and DD_FINAL_PRODUCER is not None,
             "trial.dd_final.image_unbound")
        candidates += ((DD_FINAL_IMAGE, DD_FINAL_PRODUCER),)
    if retained:
        candidates += ((PREVIOUS_IMAGE, QUALIFIED_PRODUCER),
                       (HISTORICAL_IMAGE, HISTORICAL_PRODUCER),
                       (DD_RETAINED_TIMELINE_IMAGE, DD_RETAINED_TIMELINE_PRODUCER))
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


def dd_final_startup_check(check):
    return type(check) is dict and check.get("schema") == DD_STARTUP_CHECK


def dd_diagnostic_trace(check):
    """Opt in only on an explicitly pinned cross-image startup check."""
    return dd_final_startup_check(check) and check.get("diagnosticPluginServiceTrace") is True


def dd_diagnostic_timeline(check):
    """Confine the sealed-image timeline to one pinned diagnostic startup."""
    return dd_final_startup_check(check) and check.get("diagnosticPluginServiceTimeline") is True


_BACKUP_OWNER_STAT_SCRIPT = r'''
import json, os, stat, sys
from pathlib import Path
if os.getuid() != 1000 or os.geteuid() != 1000:
    raise SystemExit(2)
raw = sys.stdin.buffer.read(16385)
if len(raw) > 16384:
    raise SystemExit(2)
request = json.loads(raw)
if set(request) != {"schema", "paths"} or request["schema"] != "openclaw.backup-owner-stat.v1":
    raise SystemExit(2)
paths = request["paths"]
if type(paths) is not list or len(paths) != 11 or len(set(paths)) != 11:
    raise SystemExit(2)
result = []
for value in paths:
    if type(value) is not str or not value.startswith("/") or ".." in Path(value).parts:
        raise SystemExit(2)
    file = Path(value)
    if file.resolve(strict=True) != file:
        raise SystemExit(2)
    info = file.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise SystemExit(2)
    result.append({"device": info.st_dev, "inode": info.st_ino,
                   "links": info.st_nlink, "sizeBytes": info.st_size,
                   "allocatedBytes": info.st_blocks * 512,
                   "modifiedNs": info.st_mtime_ns, "changedNs": info.st_ctime_ns,
                   "ownerUid": info.st_uid, "mode": stat.S_IMODE(info.st_mode)})
sys.stdout.write(json.dumps(result, separators=(",", ":")))
'''


def backup_owner_stats(paths):
    """Stat exact backups as their existing owner; never read their contents."""
    need(type(paths) is list and len(paths) == 11 and len(set(paths)) == 11,
         "trial.dd_final.backup_owner_paths")
    request = durable.encode({"schema": "openclaw.backup-owner-stat.v1", "paths": paths})
    need(len(request) <= 16384, "trial.dd_final.backup_owner_input_cap")
    command = ["/usr/bin/sudo", "-n", "-u", "frmeyer", "--", "/usr/bin/env", "-i",
               "PATH=/usr/bin:/bin", "HOME=/nonexistent", "/usr/bin/python3", "-I", "-B", "-S",
               "-c", _BACKUP_OWNER_STAT_SCRIPT]
    try:
        output = subprocess.run(command, input=request, capture_output=True, timeout=15,
                                env=durable.SAFE_ENV)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise release.Refusal("trial.dd_final.backup_owner_stat_unavailable") from error
    need(output.returncode == 0 and len(output.stdout) <= 16384 and not output.stderr,
         "trial.dd_final.backup_owner_stat_failed")
    try:
        rows = json.loads(output.stdout)
    except (UnicodeError, ValueError) as error:
        raise release.Refusal("trial.dd_final.backup_owner_stat_malformed") from error
    keys = {"device", "inode", "links", "sizeBytes", "allocatedBytes",
            "modifiedNs", "changedNs", "ownerUid", "mode"}
    need(type(rows) is list and len(rows) == 11 and all(
         type(row) is dict and set(row) == keys and all(type(v) is int and v >= 0 for v in row.values())
         for row in rows), "trial.dd_final.backup_owner_stat_shape")
    return rows


_TIMELINE_OWNER_CLEANUP = r'''
import hashlib,json,os,stat,sys
from pathlib import Path
if os.getuid()!=1000 or os.geteuid()!=1000: raise SystemExit(2)
raw=sys.stdin.buffer.read(2049)
if len(raw)>2048: raise SystemExit(2)
req=json.loads(raw)
if set(req)!={'schema','cacheSource','operationId','timeline'} or req['schema']!='openclaw.timeline-owned-cleanup.v1': raise SystemExit(2)
op=req['operationId'];t=req['timeline'];cache=req['cacheSource']
if type(op) is not str or len(op)!=32 or any(c not in '0123456789abcdef' for c in op): raise SystemExit(2)
if type(cache) is not str or not cache.startswith('/') or '..' in Path(cache).parts or os.path.realpath(cache)!=cache: raise SystemExit(2)
required={'directoryDevice','directoryInode','fileDevice','fileInode','observedBytes','sha256'}
if type(t) is not dict or set(t)!=required or any(type(t[k]) is not str or not t[k].isdigit() for k in ('directoryDevice','directoryInode','fileDevice','fileInode')): raise SystemExit(2)
count=t['observedBytes']
if type(count) is not int or count<0 or count>8388608 or type(t['sha256']) is not str or len(t['sha256'])!=64 or any(c not in '0123456789abcdef' for c in t['sha256']): raise SystemExit(2)
flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
root=os.open(cache,flags)
try:
 directory=os.open('startup-timeline-'+op,flags,dir_fd=root)
 try:
  d=os.fstat(directory)
  if not stat.S_ISDIR(d.st_mode) or d.st_uid!=1000 or stat.S_IMODE(d.st_mode)!=0o700 or d.st_dev!=int(t['directoryDevice']) or d.st_ino!=int(t['directoryInode']): raise SystemExit(2)
  if os.listdir(directory)!=['events.jsonl']: raise SystemExit(2)
  file=os.open('events.jsonl',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=directory)
  try:
   first=os.fstat(file)
   if not stat.S_ISREG(first.st_mode) or first.st_uid!=1000 or stat.S_IMODE(first.st_mode)!=0o600 or first.st_nlink!=1 or first.st_dev!=int(t['fileDevice']) or first.st_ino!=int(t['fileInode']) or first.st_size<count or first.st_size>16777216: raise SystemExit(2)
   h=hashlib.sha256();remaining=count
   while remaining:
    piece=os.read(file,min(65536,remaining))
    if not piece: raise SystemExit(2)
    h.update(piece);remaining-=len(piece)
   if h.hexdigest()!=t['sha256']: raise SystemExit(2)
   second=os.fstat(file)
   if (second.st_dev,second.st_ino,second.st_size,second.st_mtime_ns,second.st_ctime_ns)!=(first.st_dev,first.st_ino,first.st_size,first.st_mtime_ns,first.st_ctime_ns): raise SystemExit(2)
   named=os.stat('events.jsonl',dir_fd=directory,follow_symlinks=False)
   if (named.st_dev,named.st_ino,named.st_size,named.st_mtime_ns,named.st_ctime_ns)!=(first.st_dev,first.st_ino,first.st_size,first.st_mtime_ns,first.st_ctime_ns): raise SystemExit(2)
   os.unlink('events.jsonl',dir_fd=directory);os.fsync(directory)
  finally: os.close(file)
  os.rmdir('startup-timeline-'+op,dir_fd=root);os.fsync(root)
 finally: os.close(directory)
finally: os.close(root)
sys.stdout.write('{"status":"REMOVED"}')
'''


def cleanup_dd_timeline_raw(op, clean, projection, *, stopped, settled):
    """Delete only this operation's private diagnostic JSONL after native settlement."""
    if not stopped or not settled or projection is None:
        return {"status": "RETAINED_UNSETTLED", "at": durable.now()}
    mounts = [row for row in clean["mounts"] if row["target"] == "/rehearsal/cache"]
    if len(mounts) != 1 or mounts[0]["readOnly"] is not False:
        return {"status": "RETAINED_MOUNT_CHANGED", "at": durable.now()}
    timeline = {key: projection[key] for key in
                ("directoryDevice", "directoryInode", "fileDevice", "fileInode", "observedBytes", "sha256")}
    request = durable.encode({"schema": "openclaw.timeline-owned-cleanup.v1",
                              "cacheSource": mounts[0]["source"], "operationId": op.name,
                              "timeline": timeline})
    need(len(request) <= 2048, "trial.timeline.cleanup_request_cap")
    command = ["/usr/bin/sudo", "-n", "-u", "frmeyer", "--", "/usr/bin/env", "-i",
               "PATH=/usr/bin:/bin", "HOME=/nonexistent", "/usr/bin/python3", "-I", "-B", "-S",
               "-c", _TIMELINE_OWNER_CLEANUP]
    try:
        output = subprocess.run(command, input=request, capture_output=True, timeout=15,
                                env=durable.SAFE_ENV)
    except (OSError, subprocess.TimeoutExpired):
        return {"status": "RETAINED_CLEANUP_UNKNOWN", "at": durable.now()}
    if output.returncode != 0 or output.stdout != b'{"status":"REMOVED"}' or output.stderr:
        return {"status": "RETAINED_CLEANUP_UNKNOWN", "at": durable.now()}
    return {"status": "REMOVED", "at": durable.now()}


def validate_dd_original_backup_files(prior, receipt):
    """Stat only the eleven pinned originals; never scan database contents."""
    reuse = backup_reuse(prior.get("check"))
    need(reuse is not None and reuse["backupId"] == receipt["backupId"] == DD_BACKUP_ID and
         reuse["backupCount"] == 11 and reuse["manifestSha256"] == receipt["backupManifestSha256"] and
         reuse["targetSourceSha"] == LEASE_PATCH_IMAGE["sourceSha"] and
         reuse["targetImageReceiptSha256"] == LEASE_PATCH_RECEIPT_SHA256,
         "trial.dd_final.backup_group")
    rows = prior["check"]["reconciliation"]["artifacts"]
    files = receipt["backupFiles"]
    need(type(rows) is list and len(rows) == 11 and type(files) is list and len(files) == 11 and
         [entry.get("path") for entry in files] == sorted(row["path"] for row in rows),
         "trial.dd_final.backup_inventory")
    by_path = {entry["path"]: entry for entry in files}
    need(len(by_path) == 11, "trial.dd_final.backup_duplicate")
    root = path(prior["clean"]["mountRoot"])
    paths = []
    for row in rows:
        pinned = by_path[row["path"]]
        exact(pinned, "path device inode links sizeBytes allocatedBytes modifiedNs "
              "changedNs ownerUid mode", "trial.dd_final.backup_file_fields")
        # The supervisor owns private trial receipts but cannot traverse the
        # data owner's backup directories. Check syntax here and canonical
        # identity in the narrowly scoped data-owner stat helper.
        file = path(row["path"], canonical=False)
        need(root in file.parents and row["kind"] == "migration-backup" and
             row["classification"] == "native-revalidation-required" and
             row["disposition"] == "retain" and row["nativeDiscardOnRetry"] is False and
             file.name.endswith(".pre-startup-migration-" + DD_BACKUP_ID + ".bak") and
             all(type(pinned[key]) is int and pinned[key] >= 0 for key in
                 ("device", "inode", "links", "sizeBytes", "allocatedBytes", "modifiedNs",
                  "changedNs", "ownerUid", "mode")) and
             all(pinned[key] == row[key] for key in
                 ("device", "inode", "links", "sizeBytes", "allocatedBytes")),
             "trial.dd_final.backup_file_scope")
        paths.append(str(file))
    observed = backup_owner_stats(paths)
    for row, info in zip(rows, observed):
        pinned = by_path[row["path"]]
        need(info["links"] == pinned["links"] == 1 and
             all(info[key] == pinned[key] for key in
                 ("device", "inode", "sizeBytes", "allocatedBytes", "modifiedNs",
                  "changedNs", "ownerUid", "mode")),
             "trial.dd_final.backup_changed")


def validate_dd_prior_startup(receipt, prior):
    """Use the genuine private f2e0 result and settled native container."""
    need(DD_PRIOR_STARTUP_RESULT_SHA256 is not None, "trial.dd_final.prior_startup_unbound")
    previous, intent = read_retained(PRIVATE_ROOT / DD_PRIOR_STARTUP)
    result, hashed = private_json(previous / "result.json")
    observed = status(previous, retained=True)
    need(phase(intent["plan"]) == "startup" and
         hashed == receipt["priorStartupResultSha256"] == DD_PRIOR_STARTUP_RESULT_SHA256 and
         observed["state"] == "succeeded" and observed.get("result") == result and
         intent["check"]["doctorOperationId"] == DD_DOCTOR and
         intent["check"]["doctorResultSha256"] == DD_DOCTOR_RESULT_SHA256 and
         intent["plan"]["imageReceiptSha256"] == LEASE_PATCH_RECEIPT_SHA256 and
         all(intent["image"].get(key) == value for key, value in LEASE_PATCH_IMAGE.items()) and
         all(intent["clean"][key] == prior["clean"][key] for key in
             ("snapshotIdentity", "restoreReceiptSha256", "mountRoot", "filesystemDevice",
              "devicePath", "deviceMajorMinor", "mounts")) and
         intent["clean"]["configSha256"] == receipt["configSha256"] and
         result.get("state") == "succeeded" and result.get("nativeExitCode") == 0 and
         result.get("oomKillDelta") == 0 and result.get("cgroupSettlementObserved") is True and
         result.get("cleanup") == "owned_container_stopped_retained",
         "trial.dd_final.prior_startup")
    native_check = result.get("nativeCheck")
    need(type(native_check) is dict and native_check.get("ready") is True and
         native_check.get("nativeExitCode") == 0 and native_check.get("shutdown") == "exited" and
         native_check.get("healthz", {}).get("status") == 200 and
         native_check.get("startupz", {}).get("status") == 200 and
         native_check.get("readyz", {}).get("status") == 200,
         "trial.dd_final.prior_startup_probe")
    retained = durable.read_private(previous / "container.json")
    need(retained["id"] == result["containerId"], "trial.dd_final.prior_container_receipt")
    actual = inspect_container(result["containerId"])
    validate_owned_container(actual, result["containerId"], previous)
    state = actual["State"]
    old_state = result["nativeState"]
    need(state["Running"] is False and state["Pid"] == 0 and
         all(state[key] == old_state[key] for key in
             ("StartedAt", "FinishedAt", "ExitCode", "OOMKilled")),
         "trial.dd_final.prior_container_changed")
    started = durable.read_private(previous / "start-intent.json")
    intent_hash = digest(durable.private_bytes(previous / "intent.json"))
    need(started["intentSha256"] == intent_hash, "trial.dd_final.prior_intent_hash")
    validate_container(actual, previous, intent, started["image"]["env"],
                       retained_devices(intent, started))
    return {"operationId": DD_PRIOR_STARTUP, "intentSha256": intent_hash}


def validate_dd_final_coverage(check, image, plan, clean, prior):
    """Bind unchanged disabled config and disclose unverified compiled assets."""
    need(all(value is not None for value in
             (DD_FINAL_IMAGE, DD_FINAL_PRODUCER, DD_FINAL_IMAGE_RECEIPT_SHA256,
              DD_FINAL_RUNTIME_SHA256, DD_FINAL_SOURCE_BOUNDARY_SHA256,
              DD_FINAL_COVERAGE_SHA256, DD_FINAL_CHANGED_PATHS,
              DD_PRIOR_STARTUP_RESULT_SHA256)), "trial.dd_final.unbound")
    receipt = check["coverage"]
    exact(receipt, "schema doctorOperationId doctorResultSha256 priorStartupOperationId "
          "priorStartupResultSha256 doctorImageReceiptSha256 finalImageReceiptSha256 "
          "finalImageIndexDigest sourceBoundary backupId backupManifestSha256 backupFiles "
          "configSha256 cloneRuntimeSha256 finalRuntimeSha256 pluginPinStatus "
          "runtimeSha256 catalogPostcheck controllerDisabled externalEffectsDisabled "
          "doctorCoverage imageAssetBoundary doctorImageDifferent", "trial.dd_final.coverage_fields")
    need(receipt["schema"] == DD_COVERAGE_SCHEMA and
         digest(durable.encode(receipt)) == DD_FINAL_COVERAGE_SHA256 and
         check["coverageReceiptSha256"] == DD_FINAL_COVERAGE_SHA256 and
         receipt["doctorOperationId"] == DD_DOCTOR and
         receipt["doctorResultSha256"] == DD_DOCTOR_RESULT_SHA256 and
         receipt["priorStartupOperationId"] == DD_PRIOR_STARTUP and
         receipt["priorStartupResultSha256"] == check["priorStartupResultSha256"] ==
             DD_PRIOR_STARTUP_RESULT_SHA256 and
         receipt["doctorImageReceiptSha256"] == LEASE_PATCH_RECEIPT_SHA256 and
         receipt["finalImageReceiptSha256"] == plan["imageReceiptSha256"] ==
             DD_FINAL_IMAGE_RECEIPT_SHA256 and
         receipt["finalImageIndexDigest"] == image.get("indexDigest") ==
             DD_FINAL_IMAGE["indexDigest"] and
         all(image.get(key) == value for key, value in DD_FINAL_IMAGE.items()) and
         image.get("producer", {}).get("toolingSha") == DD_FINAL_PRODUCER and
         receipt["runtimeSha256"] == DD_FINAL_RUNTIME_SHA256 and
         receipt["catalogPostcheck"] == "not_established" and
         receipt["doctorCoverage"] == DD_COVERAGE_STATUS and
         receipt["imageAssetBoundary"] == DD_IMAGE_ASSET_BOUNDARY and
         receipt["doctorImageDifferent"] is True and
         receipt["controllerDisabled"] is True and
         receipt["externalEffectsDisabled"] is True and
         receipt["configSha256"] == DD_CLONE_CONFIG_SHA256 ==
             clean["configSha256"] == prior["clean"]["configSha256"] and
         receipt["cloneRuntimeSha256"] == DD_CLONE_RUNTIME_SHA256 and
         receipt["finalRuntimeSha256"] == DD_FINAL_RUNTIME_SHA256 and
         receipt["pluginPinStatus"] == DD_PLUGIN_PIN_STATUS and
         type(receipt["backupManifestSha256"]) is str and
         HEX.fullmatch(receipt["backupManifestSha256"]),
         "trial.dd_final.coverage_identity")
    source = receipt["sourceBoundary"]
    exact(source, "schema status baseSourceSha baseTree successorSourceSha successorTree "
          "changedPaths sourceDiffSha256 runtimeSha256 noChangedGitPathsOutsideExactSet "
          "manifestOnlyRuntimePinChanged", "trial.dd_final.source_fields")
    need(source["schema"] == "openclaw.dd3702.source-diff-boundary.v1" and
         source["status"] == "SOURCE_DIFF_BOUNDARY_ONLY" and
         digest(durable.encode(source)) == DD_FINAL_SOURCE_BOUNDARY_SHA256 and
         source["baseSourceSha"] == LEASE_PATCH_IMAGE["sourceSha"] and
         source["baseTree"] == LEASE_PATCH_IMAGE["sourceTree"] and
         source["successorSourceSha"] == image["sourceSha"] and
         source["successorTree"] == image["sourceTree"] and
         source["changedPaths"] == sorted(DD_FINAL_CHANGED_PATHS) and
         source["runtimeSha256"] == DD_FINAL_RUNTIME_SHA256 and
         source["noChangedGitPathsOutsideExactSet"] is True and
         source["manifestOnlyRuntimePinChanged"] is True and
         HEX.fullmatch(source["sourceDiffSha256"]),
         "trial.dd_final.source_boundary")
    lease_predecessor = validate_dd_prior_startup(receipt, prior)
    validate_dd_original_backup_files(prior, receipt)
    return receipt, lease_predecessor


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
           (limits["readBps"], limits["writeBps"]) in
           ((128 << 20, 32 << 20), (256 << 20, 64 << 20))) or
          (limits["memoryBytes"] == LOW_MEMORY_BYTES and
           (limits["readBps"], limits["writeBps"]) in
           ((256 << 20, 64 << 20), (320 << 20, 128 << 20)))),
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


def lease_patch_pressure_profile(plan, image, check=None):
    """The lower host admission is specific to the sealed lease-fix image."""
    limits = plan["limits"]
    if limits["minMemoryAvailableBytes"] != LEASE_PATCH_ADMISSION_BYTES:
        return False
    selected = phase(plan)
    need(((selected == "doctor" and continuing(check) and
           check.get("doctorOperationId") == LEASE_PATCH_PRIOR) or
          (selected == "startup" and not continuing(check))) and
         limits["memoryBytes"] == LOW_MEMORY_BYTES and limits["cpus"] == 4 and
         limits["readBps"] == 320 << 20 and limits["writeBps"] == 128 << 20 and
         plan["imageReceiptSha256"] == LEASE_PATCH_RECEIPT_SHA256 and
         all(image.get(key) == value for key, value in LEASE_PATCH_IMAGE.items()) and
         image.get("producer", {}).get("kind") == "gcp" and
         image["producer"].get("toolingSha") == LEASE_PATCH_PRODUCER,
         "trial.host_pressure.scope")
    return True


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
        elif dd_final_startup_check(check):
            historical_timeline = retained and plan["operationId"] == DD_RETAINED_TIMELINE
            if historical_timeline:
                need(plan["toolingSha"] == DD_RETAINED_TIMELINE_TOOLING and
                     plan["checkInputSha256"] == DD_RETAINED_TIMELINE_CHECK_SHA256 and
                     plan["imageReceiptSha256"] == DD_RETAINED_TIMELINE_IMAGE_RECEIPT_SHA256 and
                     dd_diagnostic_timeline(check) and
                     check["diagnosticPredecessorOperationId"] == "6c95c85497d64eaf97e2a7f0be4ea916" and
                     check["diagnosticPredecessorResultSha256"] ==
                         "9e5152f455cd025fa40706008e45812cc7828f36ba33caf15b94d406780240fc",
                     "trial.dd_final.retained_timeline_identity")
            need(not (dd_diagnostic_trace(check) and dd_diagnostic_timeline(check)),
                 "trial.dd_final.diagnostic_exclusive")
            exact(check, "schema phase doctorOperationId doctorResultSha256 "
                  "priorStartupResultSha256 coverageReceiptSha256 coverage" +
                  (" diagnosticPluginServiceTrace" if dd_diagnostic_trace(check) else "") +
                  (" diagnosticPluginServiceTimeline diagnosticPredecessorOperationId "
                   "diagnosticPredecessorResultSha256" if dd_diagnostic_timeline(check) else ""),
                  "trial.dd_final.check_fields")
            if dd_diagnostic_timeline(check):
                need(OP.fullmatch(check["diagnosticPredecessorOperationId"]) and
                     HEX.fullmatch(check["diagnosticPredecessorResultSha256"]) and
                     check["diagnosticPredecessorOperationId"] not in
                         (plan["operationId"], DD_DOCTOR, DD_PRIOR_STARTUP),
                     "trial.dd_final.diagnostic_predecessor_fields")
            need(selected == check["phase"] == "startup" and
                 check["doctorOperationId"] == DD_DOCTOR and
                 check["doctorResultSha256"] == DD_DOCTOR_RESULT_SHA256 and
                 DD_PRIOR_STARTUP_RESULT_SHA256 is not None and
                 check["priorStartupResultSha256"] == DD_PRIOR_STARTUP_RESULT_SHA256 and
                 DD_FINAL_COVERAGE_SHA256 is not None and
                 check["coverageReceiptSha256"] ==
                     (DD_RETAINED_TIMELINE_COVERAGE_SHA256 if historical_timeline else
                      DD_FINAL_COVERAGE_SHA256),
                 "trial.dd_final.check_identity")
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
    pressure_profile = lease_patch_pressure_profile(plan, image, check)
    need((memory_admission(limits) or pressure_profile) and
         600 <= limits["timeoutSeconds"] <= 86400,
         "trial.limits.admission")
    need(image.get("schema") == ("openclaw.rehearsal-baseline-image.v1" if selected == "rollback" else
                                 "openclaw.fork-release-image.v2") and
         image.get("architecture") == "amd64" and SHA.fullmatch(image.get("sourceSha", "")),
         "trial.image.receipt")
    if selected != "rollback":
        qualified_image(image, retained=retained,
                        dd_final_startup=dd_final_startup_check(check))
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
        checks.command(native_phase(plan), limits["timeoutSeconds"], contract,
                       diagnostic_trace=dd_diagnostic_trace(check),
                       diagnostic_timeline_op=plan["operationId"] if dd_diagnostic_timeline(check) else None)


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


def host_pressure_sample():
    """Bounded host-wide observations for the lower-admission lease-patch trial."""
    try:
        mem_raw = Path("/proc/meminfo").read_text()
        psi_raw = Path("/proc/pressure/memory").read_text()
    except (OSError, UnicodeError) as error:
        raise release.Refusal("trial.host_pressure.unavailable") from error
    need(len(mem_raw) <= 4096 and len(psi_raw) <= 4096,
         "trial.host_pressure.unavailable")
    memory = re.findall(r"^MemAvailable:\s+([0-9]+) kB$", mem_raw, re.MULTILINE)
    full = [line.split() for line in psi_raw.splitlines() if line.startswith("full ")]
    need(len(memory) == 1 and len(full) == 1 and len(full[0]) == 5,
         "trial.host_pressure.unavailable")
    fields = {}
    for pair in full[0][1:]:
        need(pair.count("=") == 1, "trial.host_pressure.unavailable")
        key, value = pair.split("=", 1)
        need(key not in fields and re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", value),
             "trial.host_pressure.unavailable")
        fields[key] = value
    need(set(fields) == {"avg10", "avg60", "avg300", "total"} and
         0 <= float(fields["avg10"]) <= 100 and int(memory[0]) > 0,
         "trial.host_pressure.unavailable")
    return {"at": durable.now(), "availableBytes": int(memory[0]) * 1024,
            "fullAvg10": float(fields["avg10"])}


def host_pressure_gate(state, *, admission=False, now=None):
    """Stop the owned test on material host pressure; never change production."""
    observed = host_pressure_sample()
    need(type(observed.get("availableBytes")) is int and
         type(observed.get("fullAvg10")) is float and
         observed["availableBytes"] >= 0 and 0 <= observed["fullAvg10"] <= 100,
         "trial.host_pressure.unavailable")
    now = time.monotonic() if now is None else now
    state["samples"] += 1
    state["last"] = observed
    state["minimumAvailableBytes"] = min(state["minimumAvailableBytes"], observed["availableBytes"])
    state["maximumFullAvg10"] = max(state["maximumFullAvg10"], observed["fullAvg10"])
    if observed["fullAvg10"] > LEASE_PATCH_FULL_PSI_LIMIT:
        if state["highPsiSince"] is None:
            state["highPsiSince"] = now
    else:
        state["highPsiSince"] = None
    need(observed["availableBytes"] >=
         (LEASE_PATCH_ADMISSION_BYTES if admission else LEASE_PATCH_HOST_RESERVE_BYTES),
         "trial.host_pressure.admission" if admission else "trial.host_pressure.memory")
    if admission:
        need(observed["fullAvg10"] <= LEASE_PATCH_FULL_PSI_LIMIT,
             "trial.host_pressure.admission_psi")
    else:
        need(state["highPsiSince"] is None or
             now - state["highPsiSince"] < LEASE_PATCH_FULL_PSI_SECONDS,
             "trial.host_pressure.psi")
    return observed


def observe_image(image, selected="doctor", check=None):
    if selected != "rollback":
        qualified_image(image, dd_final_startup=selected == "startup" and
                        dd_final_startup_check(check))
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
        native_phase(plan), limits["timeoutSeconds"], image.get("gatewayProbeContract"),
        diagnostic_trace=dd_diagnostic_trace(intent.get("check")),
        diagnostic_timeline_op=op.name if dd_diagnostic_timeline(intent.get("check")) else None)
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


def validate_dd_diagnostic_predecessor(check, intent):
    """Prove a stopped, exact earlier final-image startup owns the next lease."""
    previous, prior = read_retained(PRIVATE_ROOT / check["diagnosticPredecessorOperationId"])
    result, hashed = private_json(previous / "result.json")
    observed = status(previous, retained=True)
    prior_intent_sha = digest(durable.private_bytes(previous / "intent.json"))
    started = durable.read_private(previous / "start-intent.json")
    same_image = (prior["plan"]["imageReceiptSha256"] ==
                  intent["plan"]["imageReceiptSha256"] and
                  prior["check"]["coverageReceiptSha256"] == check["coverageReceiptSha256"])
    # The old sealed image cannot emit the new fixed cron marks. Admit exactly
    # its settled diagnostic result as a lease predecessor for a different,
    # freshly qualified candidate image; never reinterpret old coverage as new.
    cross_image = (previous.name == DD_RETAINED_TIMELINE and
                   hashed == DD_RETAINED_TIMELINE_RESULT_SHA256 and
                   prior["plan"]["toolingSha"] == DD_RETAINED_TIMELINE_TOOLING and
                   prior["plan"]["checkInputSha256"] == DD_RETAINED_TIMELINE_CHECK_SHA256 and
                   prior["plan"]["imageReceiptSha256"] ==
                       DD_RETAINED_TIMELINE_IMAGE_RECEIPT_SHA256 and
                   prior["check"]["coverageReceiptSha256"] ==
                       DD_RETAINED_TIMELINE_COVERAGE_SHA256 and
                   dd_diagnostic_timeline(prior["check"]) and
                   prior["check"]["diagnosticPredecessorOperationId"] ==
                       "6c95c85497d64eaf97e2a7f0be4ea916" and
                   prior["check"]["diagnosticPredecessorResultSha256"] ==
                       "9e5152f455cd025fa40706008e45812cc7828f36ba33caf15b94d406780240fc" and
                   all(prior["image"].get(key) == value for key, value in
                       DD_RETAINED_TIMELINE_IMAGE.items()) and
                   prior["image"].get("producer", {}).get("toolingSha") ==
                       DD_RETAINED_TIMELINE_PRODUCER and
                   intent["plan"]["imageReceiptSha256"] == DD_FINAL_IMAGE_RECEIPT_SHA256 and
                   check["coverageReceiptSha256"] == DD_FINAL_COVERAGE_SHA256 and
                   intent["plan"]["imageReceiptSha256"] !=
                       DD_RETAINED_TIMELINE_IMAGE_RECEIPT_SHA256)
    need(previous.name != intent["plan"]["operationId"] and
         hashed == check["diagnosticPredecessorResultSha256"] and
         prior["plan"]["operationId"] == result.get("operationId") == previous.name and
         observed["state"] == result["state"] == "failed" and
         observed.get("result") == result and
         result.get("cleanup") == "owned_container_stopped_retained" and
         result.get("promotionAuthorized") is False and
         result.get("checkInputSha256") == prior["plan"].get("checkInputSha256") and
         result.get("imageReceiptSha256") == prior["plan"]["imageReceiptSha256"] and
         result.get("cleanInputSha256") == prior["plan"]["cleanInputSha256"] and
         started["intentSha256"] == prior_intent_sha and
         phase(prior["plan"]) == "startup" and
         prior["plan"]["cleanInputSha256"] == intent["plan"]["cleanInputSha256"] and
         prior["clean"] == intent["clean"] and
         dd_final_startup_check(prior.get("check")) and
         prior["check"]["doctorOperationId"] == DD_DOCTOR and
         prior["check"]["doctorResultSha256"] == DD_DOCTOR_RESULT_SHA256 and
         prior["check"]["priorStartupResultSha256"] == DD_PRIOR_STARTUP_RESULT_SHA256 and
         (same_image or cross_image),
         "trial.dd_final.diagnostic_predecessor_changed")
    cid = result.get("containerId")
    need(type(cid) is str and HEX.fullmatch(cid), "trial.dd_final.diagnostic_predecessor_container")
    actual = inspect_container(cid)
    validate_owned_container(actual, cid, previous)
    state = actual["State"]
    need(state["Running"] is False and state["Pid"] == 0 and
         all(state[key] == result["nativeState"][key] for key in
             ("StartedAt", "FinishedAt", "ExitCode", "OOMKilled")),
         "trial.dd_final.diagnostic_predecessor_active")
    validate_container(actual, previous, prior, started["image"]["env"],
                       retained_devices(prior, started))
    durable.heavy_workload_settled({"kind": "doctor", "operationPath": str(previous),
                                    "intentSha256": prior_intent_sha})
    return {"operationId": previous.name, "intentSha256": prior_intent_sha}


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
        dd_final_startup = dd_final_startup_check(check)
        if dd_final_startup:
            need(selected == "startup" and not continuation and not image_same,
                 "trial.dd_final.not_cross_image_startup")
        prior_reuse = backup_reuse(prior.get("check"))
        # A later Doctor continuation must keep the original group's proof.
        # Dropping it would recapture from the already modified test copy.
        same_build = image_same and (not continuation or reuse == prior_reuse)
        # The original ae85778 -> 4bcf890 transition is retained history, not
        # a new direct ae85778 -> cc69ab4 route. Admit only the exact failed
        # 4bcf890 Doctor with its original group still intact.
        same_group = (reuse is not None and prior_reuse is not None and
                      all(reuse[key] == prior_reuse[key] for key in
                          ("schema", "originSourceSha", "originImageDigest",
                           "originImageReceiptSha256", "backupId", "manifestSha256", "backupCount")))
        corrected_rebuild = (continuation and not image_same and same_group and
                             check["doctorOperationId"] == CORRECTED_REBUILD_PRIOR and
                             prior["plan"]["toolingSha"] == PREVIOUS_PIPELINE_SHA and
                             prior["plan"]["imageReceiptSha256"] == PREVIOUS_IMAGE_RECEIPT_SHA256 and
                             all(prior["image"].get(key) == value for key, value in PREVIOUS_IMAGE.items()) and
                             prior["image"].get("producer", {}).get("toolingSha") == QUALIFIED_PRODUCER and
                             prior_reuse["targetSourceSha"] == PREVIOUS_IMAGE["sourceSha"] and
                             prior_reuse["targetImageReceiptSha256"] == PREVIOUS_IMAGE_RECEIPT_SHA256 and
                             intent["image"]["sourceSha"] == QUALIFIED_IMAGE["sourceSha"] and
                             reuse["targetSourceSha"] == QUALIFIED_IMAGE["sourceSha"] and
                             intent["plan"]["imageReceiptSha256"] == reuse["targetImageReceiptSha256"])
        lease_patch_rebuild = (continuation and not image_same and same_group and
                               check["doctorOperationId"] == LEASE_PATCH_PRIOR and
                               prior["plan"]["toolingSha"] == LEASE_PATCH_PRIOR_PIPELINE_SHA and
                               prior["plan"]["imageReceiptSha256"] == LEASE_PATCH_PRIOR_IMAGE_RECEIPT_SHA256 and
                               resource_profile(prior["plan"]["limits"])["id"] == "memory16-read256-write64" and
                               all(prior["image"].get(key) == value for key, value in QUALIFIED_IMAGE.items()) and
                               prior["image"].get("producer", {}).get("toolingSha") == QUALIFIED_PRODUCER and
                               prior_reuse["targetSourceSha"] == QUALIFIED_IMAGE["sourceSha"] and
                               prior_reuse["targetImageReceiptSha256"] == LEASE_PATCH_PRIOR_IMAGE_RECEIPT_SHA256 and
                               all(intent["image"].get(key) == value for key, value in LEASE_PATCH_IMAGE.items()) and
                               intent["image"].get("producer", {}).get("toolingSha") == LEASE_PATCH_PRODUCER and
                               intent["plan"]["imageReceiptSha256"] == LEASE_PATCH_RECEIPT_SHA256 and
                               reuse["targetSourceSha"] == LEASE_PATCH_IMAGE["sourceSha"] and
                               reuse["targetImageReceiptSha256"] == LEASE_PATCH_RECEIPT_SHA256 and
                               resource_profile(intent["plan"]["limits"])["id"] == "memory16-read320-write128")
        dd_final, lease_predecessor = False, None
        if dd_final_startup:
            receipt, lease_predecessor = validate_dd_final_coverage(
                check, intent["image"], intent["plan"], clean, prior)
            if dd_diagnostic_timeline(check):
                lease_predecessor = validate_dd_diagnostic_predecessor(check, intent)
            need(check["doctorOperationId"] == DD_DOCTOR and
                 prior["plan"]["toolingSha"] == DD_DOCTOR_PIPELINE_SHA and
                 prior["plan"]["imageReceiptSha256"] == LEASE_PATCH_RECEIPT_SHA256 and
                 all(prior["image"].get(key) == value for key, value in LEASE_PATCH_IMAGE.items()) and
                 prior["image"].get("producer", {}).get("toolingSha") == LEASE_PATCH_PRODUCER and
                 result.get("operationId") == DD_DOCTOR and
                 hashed == DD_DOCTOR_RESULT_SHA256 and result.get("state") == "succeeded" and
                 result.get("doctorComplete") is True and result.get("nativeExitCode") == 0 and
                 result.get("oomKillDelta") == 0 and result.get("cgroupSettlementObserved") is True and
                 clean["configSha256"] == receipt["configSha256"] and reuse is None,
                 "trial.dd_final.prior_and_config")
            dd_final = True
        need(all(clean[key] == old[key] for key in same) and
             (same_build or corrected_rebuild or lease_patch_rebuild or dd_final),
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
    contract = None if continuation else checks.validate_phase(
        native_phase(intent["plan"]), intent["image"], clean, helper_check,
        dd_final_startup=dd_final if selected == "startup" else False)
    proof = {"operationId": previous.name, "intentSha256": prior_hash, "resultSha256": hashed,
            "containerId": result["containerId"], "startedAt": state["StartedAt"],
            "finishedAt": state["FinishedAt"], "probeContract": contract}
    if selected == "startup" and dd_final:
        proof["datasetLeasePredecessor"] = lease_predecessor
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


def verify_dd_startup_claim(op, intent, prior):
    """Require the proven current startup owner -> successor lease transfer."""
    check = intent.get("check")
    expected = (check["diagnosticPredecessorOperationId"] if dd_diagnostic_timeline(check)
                else DD_PRIOR_STARTUP)
    need(dd_final_startup_check(intent.get("check")) and
         prior.get("datasetLeasePredecessor", {}).get("operationId") == expected,
         "trial.dd_final.lease_predecessor")
    lease = op.parent / ("dataset-" + digest(intent["clean"]["mountRoot"].encode()) + ".json")
    previous = op / "dataset-previous.json"
    need(lease.exists() and previous.exists(), "trial.dd_final.lease_changed")
    requested = {"operationId": op.name,
                 "intentSha256": digest(durable.private_bytes(op / "intent.json"))}
    need(durable.read_private(lease) == requested and
         durable.read_private(previous) == prior["datasetLeasePredecessor"],
         "trial.dd_final.lease_changed")


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
        image = observe_image(intent["image"], phase(intent["plan"]), intent.get("check"))
        resources = capacity(intent["plan"], clean, True)
        continuation_capacity(resources, intent["plan"], intent.get("check"))
        intent_hash = digest(durable.private_bytes(op / "intent.json"))
        lease = op.parent / ("dataset-" + digest(clean["mountRoot"].encode()) + ".json")
        reservation = {"operationId": op.name, "intentSha256": intent_hash}
        def reserve_dataset():
            continuation = continuing(intent.get("check"))
            dd_startup = dd_final_startup_check(intent.get("check"))
            if continuation or dd_startup:
                # This callback runs inside the global workload lock. Repeat
                # live prior proof at the actual ownership transition boundary.
                need(phase_prerequisites(op, intent) == prior, "trial.prior.changed")
            if continuation:
                need(lease.exists(), "trial.continuation.missing_claim")
            if dd_startup:
                need(lease.exists(), "trial.dd_final.missing_predecessor_claim")
            try:
                if continuation or dd_startup:
                    raise FileExistsError()
                durable.write_once(lease, durable.encode(reservation))
            except FileExistsError:
                original = durable.private_bytes(lease)
                current = json.loads(original)
                if current == reservation:
                    if continuation:
                        verify_continuation_claim(op, intent, prior)
                    elif dd_startup:
                        verify_dd_startup_claim(op, intent, prior)
                    else:
                        sync_private_claim(lease, original)
                    return
                need(phase(intent["plan"]) == "startup" or continuation,
                     "trial.dataset.reserved")
                predecessor = prior.get("datasetLeasePredecessor", {
                    "operationId": prior["operationId"], "intentSha256": prior["intentSha256"]})
                need(current == predecessor, "trial.dataset.reserved")
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


def expected_container_cmd(op, intent, args):
    entry = args.index("--entrypoint")
    current = args[entry + 3:]
    if op.name != DD_RETAINED_TIMELINE:
        return current
    plan = intent["plan"]
    need(plan.get("operationId") == DD_RETAINED_TIMELINE and
         plan.get("toolingSha") == DD_RETAINED_TIMELINE_TOOLING and
         plan.get("checkInputSha256") == DD_RETAINED_TIMELINE_CHECK_SHA256 and
         plan.get("imageReceiptSha256") == DD_RETAINED_TIMELINE_IMAGE_RECEIPT_SHA256 and
         intent.get("helpers", {}).get("gcp_rehearsal_checks.py") == DD_RETAINED_TIMELINE_CHECKS_SHA256 and
         dd_diagnostic_timeline(intent.get("check")),
         "trial.container.historical_command_identity")
    # The old create intent is owner-protected and was written before Docker
    # creation. Its argv is accepted only where it equals a fresh argv in every
    # element except the final JS, whose bytes are pinned to the b154 helper.
    recorded, _ = private_json(op / "create-intent.json")
    old = recorded.get("argv") if type(recorded) is dict else None
    need(type(recorded) is dict and set(recorded) == {"at", "argv"} and
         type(old) is list and len(old) == len(args) and old[:-1] == args[:-1] and
         type(old[-1]) is str and len(old[-1].encode()) == 14103 and
         digest(old[-1].encode()) == DD_RETAINED_TIMELINE_SCRIPT_SHA256,
         "trial.container.historical_command")
    return old[entry + 3:]


def validate_container(value, op, intent, expected_env, devices):
    h, cfg = value["HostConfig"], value["Config"]
    image, clean, limits = intent["image"], intent["clean"], intent["plan"]["limits"]
    args = create_argv(op, intent, devices)
    entry = args.index("--entrypoint")
    expected_cmd = expected_container_cmd(op, intent, args)
    need(value["Image"] in {image[k] for k in ("indexDigest", "imageDigest", "configDigest")} and
         cfg["Image"] == image["indexDigest"] and cfg["User"] == "1000:1000" and
         cfg["Entrypoint"] == [args[entry + 1]] and cfg["Cmd"] == expected_cmd and
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
    native_check, timeline_projection, check_buffer, check_count = None, None, b"", 0
    gate_ready, baseline_processes = False, None
    pressure, pressure_trip = None, False
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
        need(observe_image(intent["image"], selected, intent.get("check")) == started["image"],
             "trial.image.changed")
        admission = capacity(intent["plan"], intent["clean"], True)
        continuation_capacity(admission, intent["plan"], intent.get("check"))
        if lease_patch_pressure_profile(intent["plan"], intent["image"], intent.get("check")):
            pressure = {"samples": 0, "last": None,
                        "minimumAvailableBytes": admission["memoryAvailableBytes"],
                        "maximumFullAvg10": 0.0, "highPsiSince": None}
            host_pressure_gate(pressure, admission=True)
        durable.reserve_heavy_workload(op, "doctor", started["intentSha256"])
        if continuing(intent.get("check")):
            verify_continuation_claim(op, intent, started["priorDoctor"])
        elif dd_final_startup_check(intent.get("check")):
            verify_dd_startup_claim(op, intent, started["priorDoctor"])
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
                if pressure is not None:
                    host_pressure_gate(pressure)
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
                        elif dd_final_startup_check(intent.get("check")):
                            need(phase_prerequisites(op, intent) == started["priorDoctor"],
                                 "trial.prior.changed")
                            verify_dd_startup_claim(op, intent, started["priorDoctor"])
                        if pressure is not None:
                            host_pressure_gate(pressure, admission=True)
                            durable.write_once(op / "host-pressure-admission.json",
                                               durable.encode(pressure))
                        durable.write_once(op / "gate/go", b"admitted\n")
                        os.chmod(op / "gate/go", 0o444)
                    if cg is not None:
                        sample = cgroup_sample(cg)
                        if pressure is not None:
                            sample["hostPressure"] = pressure["last"]
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
                            if pressure is not None:
                                sample["hostPressure"] = pressure["last"]
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
                            candidate = checks.parse_result(line.decode("utf-8"))
                            if dd_diagnostic_timeline(intent.get("check")):
                                if candidate.get("failure") is None:
                                    checks.validate_result(candidate, native_phase(intent["plan"]),
                                                           intent["image"].get("gatewayProbeContract"),
                                                           diagnostic_timeline=True)
                                    timeline_projection = candidate["timeline"]
                                else:
                                    timeline_projection = checks.validate_diagnostic_timeline_failure(
                                        candidate, native_phase(intent["plan"]),
                                        intent["image"].get("gatewayProbeContract"))
                            native_check = candidate
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
                                   intent["image"].get("gatewayProbeContract"),
                                   diagnostic_timeline=dd_diagnostic_timeline(intent.get("check")))
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
        if dd_final_startup_check(intent.get("check")):
            need(phase_prerequisites(op, intent) == started["priorDoctor"],
                 "trial.dd_final.postrun_provenance")
    except Exception as error:
        reason = str(error) if isinstance(error, release.Refusal) else type(error).__name__
        pressure_trip = reason.startswith("trial.host_pressure.")
    finally:
        cleanup = "not_started"
        if cid and HEX.fullmatch(cid):
            try:
                value = inspect_container(cid)
                validate_owned_container(value, cid, op)
                if value["State"]["Running"]:
                    docker(["stop", "--time", "1" if pressure_trip else "30", cid],
                           timeout=10 if pressure_trip else 45)
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
        if pressure is not None:
            result["hostPressure"] = pressure
        if "checkInputSha256" in intent["plan"]:
            result["checkInputSha256"] = intent["plan"]["checkInputSha256"]
        if dd_final_startup_check(intent.get("check")):
            result["doctorCoverage"] = DD_COVERAGE_STATUS
            result["imageAssetBoundary"] = DD_IMAGE_ASSET_BOUNDARY
            result["doctorImageDifferent"] = True
            result["catalogPostcheck"] = "not_established"
            result["pluginPinStatus"] = DD_PLUGIN_PIN_STATUS
            if dd_diagnostic_timeline(intent.get("check")):
                result["diagnosticOnly"] = True
                result["timelineProjection"] = timeline_projection
        if continuing(intent.get("check")):
            result["continuedFrom"] = started["priorDoctor"]
        durable.write_once(op / "result.json", durable.encode(result))
        if dd_diagnostic_timeline(intent.get("check")):
            stopped = (cleanup == "owned_container_stopped_retained" and
                       child is not None and child.poll() is not None)
            cgroup_gone = cg is not None and not cg.exists()
            receipt = cleanup_dd_timeline_raw(op, intent["clean"], timeline_projection,
                                              stopped=stopped, settled=settled or cgroup_gone)
            durable.write_once(op / "timeline-cleanup.json", durable.encode(receipt))
    return 0 if reason is None else 1


def status(op, *, retained=False):
    op, intent = read_retained(op) if retained else load(op)
    output = {"nativeOutput": {}, "operationId": op.name, "phase": phase(intent["plan"]),
              "state": "prepared", "promotionAuthorized": False,
              "resourceProfile": resource_profile(intent["plan"]["limits"])}
    if dd_final_startup_check(intent.get("check")):
        output["doctorCoverage"] = DD_COVERAGE_STATUS
        output["imageAssetBoundary"] = DD_IMAGE_ASSET_BOUNDARY
        output["doctorImageDifferent"] = True
        output["catalogPostcheck"] = "not_established"
        output["pluginPinStatus"] = DD_PLUGIN_PIN_STATUS
        if dd_diagnostic_timeline(intent.get("check")):
            output["diagnosticOnly"] = True
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
            if dd_final_startup_check(intent.get("check")):
                need(result.get("doctorCoverage") == DD_COVERAGE_STATUS and
                     result.get("imageAssetBoundary") == DD_IMAGE_ASSET_BOUNDARY and
                     result.get("doctorImageDifferent") is True and
                     result.get("catalogPostcheck") == "not_established" and
                     result.get("pluginPinStatus") == DD_PLUGIN_PIN_STATUS and
                     result.get("promotionAuthorized") is False,
                     "trial.result.limited_coverage")
                if dd_diagnostic_timeline(intent.get("check")):
                    need(result.get("diagnosticOnly") is True,
                         "trial.result.diagnostic_binding")
                    marker = result.get("nativeCheck")
                    projection = result.get("timelineProjection")
                    if marker is None:
                        need(projection is None, "trial.result.diagnostic_projection_missing")
                    elif marker.get("failure") is None:
                        checks.validate_result(marker, native_phase(intent["plan"]),
                                               intent["image"].get("gatewayProbeContract"),
                                               diagnostic_timeline=True)
                        need(projection == marker["timeline"],
                             "trial.result.diagnostic_projection_changed")
                    else:
                        expected = checks.validate_diagnostic_timeline_failure(
                            marker, native_phase(intent["plan"]),
                            intent["image"].get("gatewayProbeContract"))
                        need(projection == expected,
                             "trial.result.diagnostic_projection_changed")
                    cleanup_file = op / "timeline-cleanup.json"
                    if cleanup_file.exists():
                        timeline_cleanup = durable.read_private(cleanup_file)
                        exact(timeline_cleanup, "status at", "trial.result.timeline_cleanup_fields")
                        need(timeline_cleanup["status"] in
                             ("REMOVED", "RETAINED_UNSETTLED", "RETAINED_MOUNT_CHANGED",
                              "RETAINED_CLEANUP_UNKNOWN"),
                             "trial.result.timeline_cleanup_status")
                        output["timelineRawCleanup"] = timeline_cleanup["status"]
                    else:
                        output["timelineRawCleanup"] = "UNKNOWN_NOT_RECORDED"
            if "checkInputSha256" in intent["plan"]:
                need(result.get("phase") == phase(intent["plan"]) and
                     result.get("checkInputSha256") == intent["plan"]["checkInputSha256"], "trial.result.phase_binding")
                if result["state"] == "succeeded" and phase(intent["plan"]) != "doctor":
                    checks.validate_result(result.get("nativeCheck"), native_phase(intent["plan"]),
                                           intent["image"].get("gatewayProbeContract"),
                                           diagnostic_timeline=dd_diagnostic_timeline(intent.get("check")))
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
