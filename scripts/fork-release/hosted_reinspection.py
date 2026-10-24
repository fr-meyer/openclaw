#!/usr/bin/env python3
"""Record reinspection evidence without relabeling its original build.

This is a diagnostic contract, not an origin authenticator, native executor,
image seal, export admission or private-storage transport. Expected receipt
hashes come from a separately trusted handoff; matching hashes alone cannot
authenticate a producer. Existing seal/export contracts remain unchanged.
"""

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat

import hosted_export


SHA = re.compile(r"[0-9a-f]{40}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
POSITIVE = re.compile(r"[1-9][0-9]*\Z")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?\Z")
UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
MAX_RECEIPT_BYTES = 1024 * 1024
IDENTITY = ("sourceSha", "sourceTree", "manifestSha256", "inventorySha256",
            "indexDigest", "imageDigest", "configDigest", "builtAt")


class Refusal(ValueError):
    """Fixed codes only; receipt contents never become diagnostics."""


def need(value, code):
    if not value:
        raise Refusal(code)


def timestamp(value):
    need(isinstance(value, str) and UTC.fullmatch(value), "timestamp.invalid")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise Refusal("timestamp.invalid") from None


def positive(value):
    return (type(value) is int and value > 0) or (isinstance(value, str) and POSITIVE.fullmatch(value))


def producer_tooling(producer):
    need(isinstance(producer, dict), "origin.producer_invalid")
    if producer.get("kind") == "gcp":
        need(set(producer) == {"kind", "toolingSha", "operationId", "attempt", "executionSha256"} and
             isinstance(producer.get("operationId"), str) and
             re.fullmatch(r"[0-9a-f]{32}", producer["operationId"]) and
             isinstance(producer.get("executionSha256"), str) and
             HEX.fullmatch(producer["executionSha256"]), "origin.producer_invalid")
        tooling = producer.get("toolingSha")
    else:
        need(set(producer) == {"workflowSha", "runId", "attempt"} and positive(producer.get("runId")),
             "origin.producer_invalid")
        tooling = producer.get("workflowSha")
    need(isinstance(tooling, str) and SHA.fullmatch(tooling) and positive(producer.get("attempt")),
         "origin.producer_invalid")
    return tooling


def validate_origin(origin):
    need(isinstance(origin, dict), "origin.missing")
    expected = {"schema", "repository", "architecture", "version", "producer", *IDENTITY}
    hosted = origin.get("producer", {}).get("kind") != "gcp" if isinstance(origin.get("producer"), dict) else True
    if hosted:
        expected.add("buildContext")
    need(set(origin) == expected and origin.get("schema") == "openclaw.fork-release-build-origin.v1" and
         origin.get("repository") == "fr-meyer/openclaw" and origin.get("architecture") == "amd64" and
         isinstance(origin.get("version"), str) and len(origin["version"]) <= 64 and
         VERSION.fullmatch(origin["version"]), "origin.invalid")
    for key in ("sourceSha", "sourceTree"):
        need(isinstance(origin.get(key), str) and SHA.fullmatch(origin[key]), "origin.identity_invalid")
    for key in ("manifestSha256", "inventorySha256"):
        need(isinstance(origin.get(key), str) and HEX.fullmatch(origin[key]), "origin.identity_invalid")
    for key in ("indexDigest", "imageDigest", "configDigest"):
        need(isinstance(origin.get(key), str) and DIGEST.fullmatch(origin[key]), "origin.identity_invalid")
    timestamp(origin.get("builtAt"))
    tooling = producer_tooling(origin["producer"])
    if hosted:
        need(origin.get("buildContext") == {"kind": "git", "repository": "https://github.com/fr-meyer/openclaw",
                                             "sourceSha": origin["sourceSha"]}, "origin.context_invalid")
    return tooling


def digest_document(raw):
    return hashlib.sha256(raw).hexdigest()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "document.duplicate_key")
        result[key] = value
    return result


def read_document(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= MAX_RECEIPT_BYTES,
             "document.invalid_or_oversized")
        raw = stream.read(MAX_RECEIPT_BYTES + 1)
        after = os.fstat(stream.fileno())
        need(len(raw) == before.st_size and
             (before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
             (after.st_size, after.st_mtime_ns, after.st_ctime_ns), "document.changed")
    return raw, digest_document(raw)


def _same(receipt, origin, fields, code):
    need(isinstance(receipt, dict) and all(receipt.get(key) == origin[key] for key in fields), code)


def _native_passes(receipt, origin):
    _same(receipt, origin, IDENTITY, "native.identity_mismatch")
    need(receipt.get("schema") == "openclaw.fork-release-image.v2" and
         receipt.get("repository") == origin["repository"] and
         receipt.get("architecture") == origin["architecture"] and
         receipt.get("version") == origin["version"] and receipt.get("producer") == origin["producer"],
         "native.producer_mismatch")
    hosted_export.runtime_proof(receipt)
    plugins = receipt.get("pluginPayload")
    need(receipt.get("selectedExtensions") == "codex,workboard" and isinstance(plugins, list) and
         len(plugins) == 2 and all(isinstance(item, dict) for item in plugins) and
         [item.get("id") for item in plugins] == ["codex", "workboard"],
         "native.plugins_missing")
    codex, workboard = plugins
    runtime = codex.get("codexRuntime", {})
    version = receipt.get("bundledCodexVersion")
    need(isinstance(version, str) and VERSION.fullmatch(version) and isinstance(runtime, dict) and
         codex.get("package") == "@openclaw/codex" and codex.get("version") == origin["version"] and
         all(runtime.get(key) == version for key in ("cliVersion", "packageVersion", "initializeVersion")) and
         runtime.get("initialized") is True and runtime.get("shutdown") == "exited" and
         workboard.get("workboardRuntime") == {"worker": "sqlite", "roundTrip": True, "closed": True},
         "native.runtime_incomplete")


def assess(documents, pins):
    """Bind supplied, independently pinned documents; never grant promotion."""
    required = {"origin", "resources", "privacy", "static", "inspection"}
    need(isinstance(documents, dict) and required <= set(documents) <= required | {"build", "native", "nativeExecution"},
         "documents.missing_or_unknown")
    need("nativeExecution" not in documents or "native" in documents, "native.capture_without_receipt")
    need(isinstance(pins, dict) and set(pins) == set(documents), "pins.missing_or_unknown")
    values = {}
    for name, document in documents.items():
        need(isinstance(document, tuple) and len(document) == 2 and isinstance(document[0], bytes) and
             len(document[0]) <= MAX_RECEIPT_BYTES and isinstance(pins.get(name), str) and
             HEX.fullmatch(pins[name]) and digest_document(document[0]) == document[1] == pins[name],
             "document.pin_mismatch")
        values[name] = json.loads(document[0], object_pairs_hook=_pairs,
                                  parse_constant=lambda _: (_ for _ in ()).throw(Refusal("document.invalid_number")))
        need(isinstance(values[name], dict), "document.object_required")
    origin, inspection = values["origin"], values["inspection"]
    original_tooling = validate_origin(origin)
    fields = {"schema", "toolingSha", "startedAt", "completedAt", "privacyReceiptCapturedAt"}
    if "native" in values:
        fields.update(("nativePerformedAt", "nativeToolingSha"))
    need(set(inspection) == fields and inspection.get("schema") == "openclaw.reinspection-session.v1" and
         isinstance(inspection.get("toolingSha"), str) and SHA.fullmatch(inspection["toolingSha"]),
         "inspection.invalid")
    if "native" in values:
        need(isinstance(inspection["nativeToolingSha"], str) and SHA.fullmatch(inspection["nativeToolingSha"]),
             "native.tooling_invalid")
        native_time = timestamp(inspection["nativePerformedAt"])
    start, end = timestamp(inspection["startedAt"]), timestamp(inspection["completedAt"])
    privacy_time = timestamp(inspection["privacyReceiptCapturedAt"])
    need(timestamp(origin["builtAt"]) <= start <= privacy_time <= end, "inspection.time_order")
    tooling = inspection["toolingSha"]
    checks = {}
    build = values.get("build")
    if build is None:
        checks["originalBuild"] = "blocked_missing_build_success_receipt"
    elif build.get("schema") == "openclaw.fork-gcp-image-execution.v1" and origin["producer"].get("kind") == "gcp":
        need(set(build) == {"schema", "operationId", "attempt", "projectNumber", "instanceId", "toolingSha",
                            "sourceSha", "sourceTree", "manifestSha256", "inventorySha256", "indexDigest", "builtAt",
                            "startedAt", "completedAt", "buildExitCode", "buildMetadataSha256", "buildLogSha256"} and
             all(isinstance(build.get(key), str) and POSITIVE.fullmatch(build[key]) for key in ("projectNumber", "instanceId")) and
             all(isinstance(build.get(key), str) and HEX.fullmatch(build[key]) for key in ("buildMetadataSha256", "buildLogSha256")),
             "build.capture_fields_invalid")
        _same(build, origin, ("sourceSha", "sourceTree", "manifestSha256", "inventorySha256", "indexDigest", "builtAt"),
              "build.identity_mismatch")
        need(build.get("toolingSha") == original_tooling and
             build.get("operationId") == origin["producer"]["operationId"] and
             build.get("attempt") == origin["producer"]["attempt"] and
             pins["build"] == origin["producer"]["executionSha256"], "build.producer_mismatch")
        # Preserve the existing GCP adapter's reproducible input timestamp,
        # not an inferred image-completion time (gcp-image-context.mjs).
        need(timestamp(origin["builtAt"]) <= timestamp(build.get("startedAt")) <=
             timestamp(build.get("completedAt")) <= start, "build.time_order")
        checks["originalBuild"] = "passed" if type(build.get("buildExitCode")) is int and build["buildExitCode"] == 0 else "failed"
    elif build.get("schema") == "openclaw.fork-release-build-success.v1":
        # Future owned capture, not a schema emitted by a historical failed job.
        need(set(build) == {"schema", "status", "buildExitCode", "toolingSha", "producer", *IDENTITY},
             "build.capture_fields_invalid")
        _same(build, origin, IDENTITY, "build.identity_mismatch")
        need(build.get("producer") == origin["producer"] and build.get("toolingSha") == original_tooling,
             "build.producer_mismatch")
        checks["originalBuild"] = "passed" if build.get("status") == "passed" and type(build.get("buildExitCode")) is int and build["buildExitCode"] == 0 else "failed"
    else:
        checks["originalBuild"] = "blocked_unrecognized_build_success_receipt"
    resources = values["resources"]
    _same(resources, origin, ("sourceSha", "indexDigest"), "resources.identity_mismatch")
    need(resources.get("toolingSha") == original_tooling, "resources.tooling_mismatch")
    checks["originalResources"] = "passed" if resources.get("schema") == "openclaw.hosted-resources.v1" and resources.get("status") == "passed" and resources.get("violations") == [] else "failed"
    privacy = values["privacy"]
    _same(privacy, origin, ("sourceSha", "indexDigest", "imageDigest", "configDigest"), "privacy.identity_mismatch")
    need(privacy.get("toolingSha") == tooling, "privacy.tooling_mismatch")
    try:
        need(privacy.get("schema") == "openclaw.hosted-privacy.v2" and privacy.get("status") == "passed",
             "privacy.not_passed")
        hosted_export.require_clean_privacy(privacy)
        checks["privacy"] = "passed"
    except ValueError:
        checks["privacy"] = "failed"
    static_report = values["static"]
    _same(static_report, origin, IDENTITY, "static.identity_mismatch")
    need(static_report.get("schema") == "openclaw.fork-release-static.v1" and
         static_report.get("originalBuildSha256") == pins["origin"] and
         static_report.get("privacyReceiptSha256") == pins["privacy"] and
         static_report.get("inspectionToolingSha") == tooling and static_report.get("staticOnly") is True and
         static_report.get("nativeExecuted") is False and static_report.get("promotable") is False and
         static_report.get("productionAuthorized") is False, "static.contract_mismatch")
    static_time = timestamp(static_report.get("performedAt"))
    need(privacy_time <= static_time <= end, "static.stale_or_future")
    checks["static"] = "passed" if static_report.get("status") == "passed" and static_report.get("reason") is None else "failed"
    native = values.get("native")
    if native is None:
        checks["native"] = "blocked_missing_native_receipt"
    elif "nativeExecution" not in values:
        # A historical image seal has no verifier execution time/revision. A
        # session assertion must never relabel it as a new native execution.
        checks["native"] = "blocked_missing_native_execution_capture"
    else:
        need(static_time <= native_time <= end, "native.stale_or_future")
        need(checks["privacy"] == checks["static"] == "passed", "native.privacy_or_static_not_passed")
        capture = values["nativeExecution"]
        need(set(capture) == {"schema", "status", "nativeExecuted", "sourceSha", "sourceTree", "indexDigest",
                              "imageDigest", "configDigest", "originalBuildSha256", "nativeReceiptSha256",
                              "verifierToolingSha", "performedAt"} and
             capture.get("schema") == "openclaw.fork-release-native-execution.v1" and
             capture.get("originalBuildSha256") == pins["origin"] and
             capture.get("nativeReceiptSha256") == pins["native"] and
             capture.get("verifierToolingSha") == inspection["nativeToolingSha"] and
             capture.get("performedAt") == inspection["nativePerformedAt"], "native.capture_mismatch")
        _same(capture, origin, ("sourceSha", "sourceTree", "indexDigest", "imageDigest", "configDigest"),
              "native.capture_identity_mismatch")
        try:
            need(capture.get("status") == "passed" and capture.get("nativeExecuted") is True,
                 "native.capture_not_passed")
            _native_passes(native, origin)
            checks["native"] = "passed"
        except ValueError:
            checks["native"] = "failed"
    return {"schema": "openclaw.fork-release-reinspection.v1", "status": "diagnostic",
            "originalBuild": copy.deepcopy(origin), "originalToolingSha": original_tooling,
            "originalReceiptSha256": {name: pins.get(name) for name in ("origin", "build", "resources")},
            "inspection": copy.deepcopy(inspection),
            "reportSha256": {name: pins.get(name) for name in ("privacy", "static", "native", "nativeExecution")},
            "checks": checks, "allRequiredReportsPass": all(value == "passed" for value in checks.values()),
            "originAuthority": "trusted-handoff-required", "activationBlockers": ["origin_authenticity_and_admission_not_wired"],
            "limitations": ["Original build resources are preserved; future execution still requires fresh resource admission.",
                            "privacyReceiptCapturedAt is an observation time, not a claim that the scanner executed again.",
                            "Historical logs are not an owned build-success capture; no existing failed receipt is upgraded."],
            "promotable": False, "export": "none", "productionAuthorized": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("origin", "resources", "privacy", "static", "inspection"):
        parser.add_argument("--" + name, required=True)
    for name in ("build", "native"):
        parser.add_argument("--" + name)
    parser.add_argument("--native-execution", dest="nativeExecution")
    parser.add_argument("--pin", action="append", required=True, help="Independently pinned NAME=SHA256")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        pins = {}
        for item in args.pin:
            name, separator, value = item.partition("=")
            need(separator and name not in pins, "pins.invalid")
            pins[name] = value
        documents = {name: read_document(getattr(args, name)) for name in
                     ("origin", "build", "resources", "privacy", "static", "native", "nativeExecution", "inspection") if getattr(args, name)}
        result = assess(documents, pins)
        with open(args.output, "x", encoding="utf-8") as output:
            output.write(json.dumps(result, sort_keys=True, indent=2) + "\n")
        print(json.dumps(result, sort_keys=True))
        # Complete evidence still remains diagnostic; a missing/failed report
        # also returns nonzero while retaining the bounded result.
        return 0 if result["allRequiredReportsPass"] else 1
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        # A rejected report must not echo untrusted receipt values or paths.
        print('{"schema":"openclaw.fork-release-reinspection.v1","status":"refused","promotable":false,"export":"none","productionAuthorized":false}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
