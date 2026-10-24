#!/usr/bin/env python3
"""Inspect one retained private OCI without building, transferring or deploying.

The image owner authenticates the original GCP execution and owns all native
verification. This driver only sequences fixed trusted commands, retains their
bounded receipts and reconciles completion. A started uncertain native operation
is never retried. Fresh resource checks are supplied by the existing host owner;
this module does not query the host or define capacity thresholds.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

import gcp_build
import hosted_export
import hosted_reinspection


HERE = Path(__file__).resolve().parent
TOOLING = HERE.parents[1]
SHA = re.compile(r"[0-9a-f]{40}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
OP = re.compile(r"[0-9a-f]{32}\Z")
BASE_FIELDS = {"schema", "manifestPath", "inventoryPath", "sourceDir", "ociDir", "executionPath",
               "originalToolingSha", "executionSha256", "inspectionToolingSha"}
OUTPUTS = ("origin.json", "static.json", "diagnostics.json", "receipt.json", "native.json",
           "native-attempt.json", "native-execution.json", "admission.json")
TIMEOUT = 900


class Refusal(ValueError):
    """Only fixed codes may enter public output."""


def need(condition, code):
    if not condition:
        raise Refusal(code)


def now():
    return datetime.now(timezone.utc).replace(microsecond=0)


def utc(value):
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def private_data(path):
    before = Path(path).lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and before.st_mode & 0o077 == 0,
         "input.not_private")
    raw, hashed = hosted_reinspection.read_document(path)
    after = Path(path).lstat()
    need((before.st_dev, before.st_ino, before.st_ctime_ns, before.st_uid, before.st_mode) ==
         (after.st_dev, after.st_ino, after.st_ctime_ns, after.st_uid, after.st_mode), "input.changed")
    return raw, hashed


def document(path):
    raw, hashed = private_data(path)
    value = json.loads(raw, object_pairs_hook=hosted_reinspection._pairs)
    need(isinstance(value, dict), "input.object_required")
    return value, hashed


def pinned(path, expected):
    need(isinstance(expected, str) and HEX.fullmatch(expected), "input.pin_invalid")
    raw, hashed = private_data(path)
    need(hashed == expected, "input.pin_changed")
    return raw


def write_once(path, raw, claim=False):
    path = Path(path)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        if claim:
            return False
        need(private_data(path)[0] == raw, "state.output_changed")
        return False
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return True


def canonical(path):
    path = Path(path).absolute()
    need(path.resolve() == path, "input.path_not_canonical")
    return path


def outside(left, right):
    need(left != right and left not in right.parents and right not in left.parents,
         "state.overlaps_input")


def prepare(plan_path, plan_pin, state, original_resources, resources_pin):
    raw = pinned(plan_path, plan_pin)
    plan = json.loads(raw, object_pairs_hook=hosted_reinspection._pairs)
    need(isinstance(plan, dict) and set(plan) == BASE_FIELDS and
         plan.get("schema") == "openclaw.retained-gcp-input.v1", "plan.invalid")
    need(all(isinstance(plan[k], str) and SHA.fullmatch(plan[k]) for k in
             ("originalToolingSha", "inspectionToolingSha")) and
         isinstance(plan.get("executionSha256"), str) and HEX.fullmatch(plan["executionSha256"]),
         "plan.identity_invalid")
    for key in ("manifestPath", "inventoryPath", "sourceDir", "ociDir", "executionPath"):
        need(isinstance(plan[key], str), "plan.path_invalid")
        canonical(plan[key])
    gcp_build.clean_checkout(TOOLING, plan["inspectionToolingSha"])
    state = canonical(state)
    need(OP.fullmatch(state.name), "state.operation_invalid")
    for path in (Path(plan["sourceDir"]), Path(plan["ociDir"]), Path(plan["executionPath"]).parent):
        outside(state, path)
    parent = state.parent.lstat()
    need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.getuid() and parent.st_mode & 0o077 == 0,
         "state.parent_not_private")
    resources = pinned(original_resources, resources_pin)
    if state.exists():
        info = state.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and info.st_mode & 0o077 == 0 and
             (state / "intent.json").exists(), "state.not_owned_operation")
    else:
        state.mkdir(mode=0o700)
    intent = {"schema": "openclaw.gcp-image-reinspection-intent.v1", "operationId": state.name,
              "planSha256": plan_pin, "inspectionToolingSha": plan["inspectionToolingSha"],
              "executionSha256": plan["executionSha256"], "originalResourcesSha256": resources_pin}
    write_once(state / "intent.json", encoded(intent))
    write_once(state / "base-plan.json", raw)
    write_once(state / "original-resources.json", resources)
    return plan, state, intent


def command(args, timeout=TIMEOUT):
    # Trusted owners retain their bounded structured files. Never echo raw child
    # output, exception text, private paths or unexpected suspect contents.
    return subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                          timeout=timeout, check=False).returncode


def verify_owner(args, execute):
    try:
        return execute(args) == 0
    except (OSError, subprocess.SubprocessError):
        return False


def snapshots(directory, names):
    return {name: private_data(directory / name)[1] for name in names if (directory / name).exists()}


def stage(state, name, args, output_dir, names, execute, clock, inputs=()):
    started, completed = state / (name + ".started.json"), state / (name + ".completed.json")
    argv_hash = digest(encoded(args))
    input_pins = {str(path): private_data(path)[1] for path in inputs}
    if started.exists():
        marker, _ = document(started)
        need(marker.get("argvSha256") == argv_hash and marker.get("inputSha256") == input_pins,
             "state.stage_inputs_changed")
    if completed.exists():
        result, _ = document(completed)
        need(started.exists() and result.get("argvSha256") == argv_hash and result.get("inputSha256") == input_pins and
             result.get("outputs") == snapshots(output_dir, names), "state.stage_changed")
        return result
    if started.exists():
        return {"stage": name, "status": "uncertain", "exitCode": None, "outputs": {}}
    if not write_once(started, encoded({"schema": "openclaw.gcp-image-reinspection-stage.v1",
                                       "stage": name, "argvSha256": argv_hash, "inputSha256": input_pins,
                                       "startedAt": utc(clock())}), claim=True):
        return {"stage": name, "status": "uncertain", "exitCode": None, "outputs": {}}
    try:
        exit_code = execute(args)
        need(type(exit_code) is int, "stage.invalid_exit")
        status = "completed"
    except (OSError, subprocess.SubprocessError):
        exit_code, status = None, "uncertain"
    result = {"schema": "openclaw.gcp-image-reinspection-stage-result.v1", "stage": name,
              "argvSha256": argv_hash, "inputSha256": input_pins, "status": status, "exitCode": exit_code,
              "completedAt": utc(clock()), "outputs": snapshots(output_dir, names)}
    write_once(completed, encoded(result))
    return result


def resource_admission(path, pin, captured, state, clock):
    raw = pinned(path, pin)
    admission = json.loads(raw, object_pairs_hook=hosted_reinspection._pairs)
    need(isinstance(admission, dict) and set(admission) == {
        "schema", "sourceSha", "indexDigest", "inspectionToolingSha", "checkedAt", "expiresAt", "status", "checks"} and
        admission.get("schema") == "openclaw.fork-release-reinspection-resource-admission.v1" and
        all(admission.get(key) == captured[key] for key in ("sourceSha", "indexDigest", "inspectionToolingSha")),
        "resource.identity_invalid")
    checked, expires = (hosted_reinspection.timestamp(admission[key]) for key in ("checkedAt", "expiresAt"))
    need(0 < (expires - checked).total_seconds() <= 300 and checked <= clock() <= expires,
         "resource.stale")
    need(admission.get("status") == "passed" and admission.get("checks") ==
         {"capacity": "passed", "ownership": "passed", "heavyWorkload": "clear"}, "resource.not_passed")
    target = state / ("resource-admission-" + pin + ".json")
    write_once(target, raw)
    return target


def summary(state, captured, checks, status, reason=None, handoff=None):
    result = {"schema": "openclaw.gcp-image-reinspection-summary.v1", "operationId": state.name,
              "status": status, "checks": checks, "reason": reason, "productionAuthorized": False,
              "buildExecuted": False, "transferExecuted": False, "hostChecksPerformed": False,
              "qualified": status == "qualified"}
    if captured:
        result.update({key: captured[key] for key in ("sourceSha", "indexDigest", "inspectionToolingSha")})
    if handoff:
        result["handoffSha256"] = digest(encoded(handoff))
    # Historical summaries are immutable; a later verification failure must not
    # overwrite or silently upgrade them.
    target = state / ("summary.json" if not (state / "summary.json").exists() else
                      "summary-" + digest(encoded(result)) + ".json")
    write_once(target, encoded(result))
    return result


def inspect(plan_path, plan_pin, state, *, admission_path=None, admission_pin=None,
            original_resources, resources_pin, node=None, execute=command, clock=now):
    plan, state, _ = prepare(plan_path, plan_pin, state, original_resources, resources_pin)
    node = node or shutil.which("node")
    need(node is not None, "tool.node_missing")
    node = str(Path(node).resolve())
    need(Path(node).is_file() and os.access(node, os.X_OK), "tool.node_missing")
    for candidate in (Path(plan["sourceDir"]), Path(plan["ociDir"])):
        need(candidate not in Path(node).parents, "tool.candidate_executable")
    owner = [node, str(HERE / "image.mjs")]
    checks = {key: "blocked" for key in ("metadata", "resources", "privacy", "static", "native")}
    capture_path = state / "capture.json"
    capture = stage(state, "capture", [*owner, "capture-retained-gcp-origin", str(state / "base-plan.json"),
                                      str(capture_path)], state, ("capture.json",), execute, clock)
    if capture["status"] != "completed" or capture["exitCode"] != 0 or not capture_path.exists():
        return summary(state, None, checks, "blocked", "metadata.unconfirmed")
    captured, _ = document(capture_path)
    need(captured.get("schema") == "openclaw.retained-gcp-build-context.v1" and
         captured.get("status") == "captured" and captured.get("qualified") is False and
         captured.get("productionAuthorized") is False and
         captured.get("executionSha256") == plan["executionSha256"] and
         captured.get("inspectionToolingSha") == plan["inspectionToolingSha"] and
         isinstance(captured.get("sourceSha"), str) and SHA.fullmatch(captured["sourceSha"]) and
         isinstance(captured.get("indexDigest"), str) and DIGEST.fullmatch(captured["indexDigest"]),
         "metadata.identity_invalid")
    checks["metadata"] = "passed"
    output_dir = state / "qualification"
    privacy_path = state / "privacy.json"
    qualify_plan_path = state / "qualification-plan.json"
    receipt_path = output_dir / "receipt.json"
    privacy_args = [sys.executable, str(HERE / "hosted_privacy.py"), "--oci-dir", plan["ociDir"],
                    "--expected-index-digest", captured["indexDigest"], "--source-sha", captured["sourceSha"],
                    "--tooling-sha", plan["inspectionToolingSha"], "--output", str(privacy_path),
                    "--public-comparisons", str(HERE / "public-member-comparisons-v105.json"),
                    "--qualify-public-members"]

    # Once native qualification may have started, the only permitted resume is
    # a read-only owner verification of already complete outputs.
    started = state / "qualify.started.json"
    if started.exists():
        need(qualify_plan_path.exists() and (state / "privacy.completed.json").exists(),
             "state.qualification_inputs_missing")
        saved_privacy = stage(state, "privacy", privacy_args, state, ("privacy.json",), execute, clock)
        need(saved_privacy["status"] == "completed", "state.privacy_unconfirmed")
        saved_result = stage(state, "qualify", [*owner, "qualify-retained-gcp",
                             str(qualify_plan_path), str(output_dir)], output_dir, OUTPUTS, execute, clock,
                             inputs=(qualify_plan_path,))
        if (saved_result["status"] == "completed" and
                saved_result["exitCode"] != 0 and not (output_dir / "native-attempt.json").exists()):
            saved_scan, _ = document(privacy_path)
            checks["privacy"] = "passed" if saved_scan.get("status") == "passed" else "failed"
            checks["resources"] = "passed"  # Historical admission, not a new capacity check.
            if (output_dir / "static.json").exists():
                saved_static, _ = document(output_dir / "static.json")
                checks["static"] = saved_static.get("status") if saved_static.get("status") in (
                    "passed", "failed", "blocked") else "failed"
            return summary(state, captured, checks, "failed", "qualification.not_passed")
        if not receipt_path.exists() or not (output_dir / "admission.json").exists():
            checks["native"] = "uncertain"
            return summary(state, captured, checks, "blocked", "native.outcome_uncertain")
        verify_args = [*owner, "verify-retained-gcp", str(qualify_plan_path), str(receipt_path)]
        if not verify_owner(verify_args, execute):
            checks["native"] = "uncertain"
            return summary(state, captured, checks, "blocked", "native.verification_failed")
        receipt, receipt_hash = document(receipt_path)
        checks = {key: "passed" for key in checks}
        return finish_handoff(state, captured, checks, receipt, receipt_hash, output_dir)

    try:
        admitted_path = resource_admission(admission_path, admission_pin, captured, state, clock)
        checks["resources"] = "passed"
    except (OSError, ValueError, TypeError):
        checks["resources"] = "failed"
        return summary(state, captured, checks, "blocked", "resource.admission_refused")
    privacy_result = stage(state, "privacy", privacy_args, state, ("privacy.json",), execute, clock)
    if privacy_result["status"] != "completed" or not privacy_path.exists():
        return summary(state, captured, checks, "blocked", "privacy.outcome_uncertain")
    privacy_report, privacy_hash = document(privacy_path)
    need(privacy_report.get("schema") == "openclaw.hosted-privacy.v2" and
         all(privacy_report.get(key) == captured[key] for key in ("sourceSha", "indexDigest")) and
         privacy_report.get("toolingSha") == plan["inspectionToolingSha"], "privacy.identity_invalid")
    try:
        hosted_export.require_clean_privacy(privacy_report)
        clean = privacy_report.get("status") == "passed" and privacy_result["exitCode"] == 0
    except ValueError:
        clean = False
    checks["privacy"] = "passed" if clean else "failed"
    if privacy_report.get("inspectionComplete") is not True or "refusal" in privacy_report:
        return summary(state, captured, checks, "failed", "privacy.structure_incomplete")
    if privacy_result["exitCode"] not in (0, 1) or (
            privacy_report.get("status") == "passed" and privacy_result["exitCode"] != 0):
        return summary(state, captured, checks, "blocked", "privacy.exit_inconsistent")
    try:
        admitted_path = resource_admission(admission_path, admission_pin, captured, state, clock)
    except (OSError, ValueError, TypeError):
        checks["resources"] = "failed"
        return summary(state, captured, checks, "blocked", "resource.admission_refused")
    qualify_plan = {**plan, "schema": "openclaw.retained-gcp-qualification.v1",
                    "privacyPath": str(privacy_path), "privacySha256": privacy_hash,
                    "resourceAdmissionPath": str(admitted_path), "resourceAdmissionSha256": admission_pin,
                    "originalResourcesPath": str(state / "original-resources.json"),
                    "originalResourcesSha256": resources_pin}
    write_once(qualify_plan_path, encoded(qualify_plan))
    if not output_dir.exists():
        output_dir.mkdir(mode=0o700)
    info = output_dir.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and info.st_mode & 0o077 == 0 and
         not any(output_dir.iterdir()), "state.qualification_output_not_empty")
    result = stage(state, "qualify", [*owner, "qualify-retained-gcp", str(qualify_plan_path), str(output_dir)],
                   output_dir, OUTPUTS, execute, clock, inputs=(qualify_plan_path,))
    if (output_dir / "static.json").exists():
        static, _ = document(output_dir / "static.json")
        need(all(static.get(key) == captured[key] for key in ("sourceSha", "indexDigest")) and
             static.get("inspectionToolingSha") == plan["inspectionToolingSha"], "static.identity_invalid")
        checks["static"] = static.get("status") if static.get("status") in ("passed", "failed", "blocked") else "failed"
    if result["status"] != "completed":
        checks["native"] = "uncertain"
        return summary(state, captured, checks, "blocked", "native.outcome_uncertain")
    if result["exitCode"] != 0:
        if (output_dir / "native-attempt.json").exists() and not receipt_path.exists():
            checks["native"] = "uncertain"
        return summary(state, captured, checks, "failed", "qualification.not_passed")
    need(clean and checks["static"] == "passed" and receipt_path.exists(), "qualification.inconsistent")
    if not verify_owner([*owner, "verify-retained-gcp", str(qualify_plan_path), str(receipt_path)], execute):
        checks["native"] = "uncertain"
        return summary(state, captured, checks, "blocked", "native.verification_failed")
    receipt, receipt_hash = document(receipt_path)
    checks["native"] = "passed"
    return finish_handoff(state, captured, checks, receipt, receipt_hash, output_dir)


def finish_handoff(state, captured, checks, receipt, receipt_hash, output_dir):
    need(receipt.get("schema") == "openclaw.fork-release-image.v2" and
         all(receipt.get(key) == captured[key] for key in ("sourceSha", "indexDigest")) and
         all(isinstance(receipt.get(key), str) and DIGEST.fullmatch(receipt[key]) for key in
             ("imageDigest", "configDigest")), "handoff.identity_invalid")
    handoff = {"schema": "openclaw.fork-retained-image-handoff.v1", "status": "qualified",
               "sourceSha": captured["sourceSha"], "indexDigest": captured["indexDigest"],
               "imageDigest": receipt["imageDigest"], "configDigest": receipt["configDigest"],
               "inspectionToolingSha": captured["inspectionToolingSha"], "originalProducer": receipt.get("producer"),
               "imageReceiptPath": str(output_dir / "receipt.json"), "imageReceiptSha256": receipt_hash,
               "ociDir": str(document(state / "base-plan.json")[0]["ociDir"]),
               "admissionPath": str(output_dir / "admission.json"), "productionAuthorized": False,
               "rebuildRequired": False}
    write_once(state / "handoff.json", encoded(handoff))
    return summary(state, captured, checks, "qualified", handoff=handoff)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ("plan", "plan-sha256", "state-dir", "original-resources", "original-resources-sha256"):
        parser.add_argument("--" + field, required=True)
    parser.add_argument("--resource-admission")
    parser.add_argument("--resource-admission-sha256")
    parser.add_argument("--node")
    args = parser.parse_args()
    try:
        result = inspect(args.plan, args.plan_sha256, args.state_dir,
                         admission_path=args.resource_admission, admission_pin=args.resource_admission_sha256,
                         original_resources=args.original_resources, resources_pin=args.original_resources_sha256,
                         node=args.node)
        print(json.dumps(result, sort_keys=True))
        return 0 if result["qualified"] else 1
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        print('{"schema":"openclaw.gcp-image-reinspection-summary.v1","status":"refused","qualified":false,"buildExecuted":false,"transferExecuted":false,"productionAuthorized":false,"checks":{"metadata":"failed","resources":"blocked","privacy":"blocked","static":"blocked","native":"blocked"}}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
