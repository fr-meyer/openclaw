#!/usr/bin/env python3
"""Bind hosted seal/privacy/resource evidence before optional public export.

This gate does not upload anything, grant storage approval or replace OCI/native
verification. With export disabled, outputs expire with the runner and cannot be
promoted later. Legacy image receipts remain readable elsewhere, but are not
accepted as newly qualified hosted Git-context evidence here.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

import hosted_privacy as privacy_contract


class Refusal(ValueError):
    pass


def need(condition, reason):
    if not condition:
        raise Refusal(reason)


# Fixed diagnostic vocabulary. Never add receipt values, paths, exception text
# or arbitrary validator strings to a public failure record.
PRIVACY_CHECKS = frozenset({
    ('arguments', 'syntax'), ('receipt', 'read'), ('receipt', 'binding'),
    ('aggregate', 'receipt_status'), ('aggregate', 'summary'),
    ('aggregate', 'catalog_by_rule'), ('aggregate', 'catalog_by_unit'),
    ('aggregate', 'finding_total'), ('aggregate', 'inspection_complete'),
    ('aggregate', 'location_index'), ('qualification', 'presence'),
    ('qualification', 'plan_read'), ('qualification', 'plan_validate'),
    ('closure', 'initialize'), ('closure', 'digest'), ('closure', 'selected_image'),
})
PRIVACY_REASON_CODES = {
    'invalid binding': 'binding_invalid',
    'privacy binding changed': 'privacy_binding_changed',
    'invalid or oversized receipt': 'receipt_invalid',
    'receipt changed': 'receipt_changed',
    'privacy receipt did not pass': 'privacy_receipt_not_passed',
    'privacy aggregate contract missing': 'aggregate_contract_missing',
    'privacy aggregate catalog or count invalid': 'aggregate_catalog_invalid',
    'privacy aggregate findings remain or disagree': 'aggregate_findings_or_disagreement',
    'privacy inspection is incomplete or findings remain': 'inspection_incomplete_or_findings',
    'privacy location index is missing, truncated or nonempty': 'location_index_invalid',
    'source qualification proof missing': 'qualification_proof_missing',
    'public member qualification is incomplete or changed': 'qualification_incomplete_or_changed',
    'invalid_public_member_qualification': 'public_member_qualification_invalid',
    'unsupported_layer_format': 'closure_layer_format_unsupported',
    'layer_limit': 'closure_layer_limit',
    'retained metadata privacy findings': 'closure_metadata_findings',
    'retained root metadata changed': 'closure_root_changed',
    'retained image changed': 'closure_selected_image_changed',
}
PRIVACY_EXCEPTION_TYPES = frozenset({
    'Refusal', 'OSError', 'FileNotFoundError', 'PermissionError', 'IsADirectoryError',
    'NotADirectoryError', 'ValueError', 'JSONDecodeError', 'TypeError', 'KeyError',
    'AttributeError', 'RecursionError',
})


def _privacy_stage(state, phase, subcheck):
    if state is not None:
        state.clear()
        state.update(phase=phase, subcheck=subcheck)


def _privacy_failure_fields(error):
    code = 'unclassified_failure'
    if type(error) in (Refusal, privacy_contract.Refusal) and len(error.args) == 1:
        reason = error.args[0]
        if type(reason) is str and len(reason) <= 128:
            code = PRIVACY_REASON_CODES.get(reason, code)
    kind = type(error).__name__
    number = error.errno if isinstance(error, OSError) else None
    return {'code': code, 'exceptionType': kind if kind in PRIVACY_EXCEPTION_TYPES else 'other',
            'errno': number if type(number) is int and 0 < number <= 4095 else None}


def _privacy_diagnostic(error, state):
    phase, subcheck = state.get('phase'), state.get('subcheck')
    if (phase, subcheck) not in PRIVACY_CHECKS:
        phase = subcheck = 'unknown'
    fields = state.get('failure') or _privacy_failure_fields(error)
    if type(fields) is not dict:
        fields = _privacy_failure_fields(error)
    code, kind, number = (fields.get(key) for key in ('code', 'exceptionType', 'errno'))
    code = code if type(code) is str and code in PRIVACY_REASON_CODES.values() else 'unclassified_failure'
    kind = kind if type(kind) is str and kind in PRIVACY_EXCEPTION_TYPES else 'other'
    number = number if type(number) is int and 0 < number <= 4095 else None
    return {'schema': 'openclaw.hosted-privacy-check-diagnostic.v1',
            'phase': phase, 'subcheck': subcheck, 'code': code, 'exceptionType': kind, 'errno': number}


def require_clean_privacy(receipt, *, failure_state=None):
    """V2 aggregates are authoritative; representatives may be empty/truncated."""
    _privacy_stage(failure_state, 'aggregate', 'receipt_status')
    need(isinstance(receipt, dict) and receipt.get("schema") == "openclaw.hosted-privacy.v2" and
         receipt.get("status") == "passed", "privacy receipt did not pass")
    _privacy_stage(failure_state, 'aggregate', 'summary')
    summary = receipt.get("findingSummary")
    need(isinstance(summary, dict) and set(summary) == {"unit", "total", "byRule", "byUnit"} and
         summary.get("unit") == privacy_contract.COUNT_UNIT, "privacy aggregate contract missing")
    for key, catalog in (("byRule", privacy_contract.FINDING_RULES),
                         ("byUnit", privacy_contract.FINDING_UNITS)):
        _privacy_stage(failure_state, 'aggregate', 'catalog_by_rule' if key == 'byRule' else 'catalog_by_unit')
        counts = summary.get(key)
        need(isinstance(counts, dict) and set(counts) == set(catalog) and
             all(type(value) is int and value >= 0 for value in counts.values()),
             "privacy aggregate catalog or count invalid")
    _privacy_stage(failure_state, 'aggregate', 'finding_total')
    total = summary.get("total")
    need(type(total) is int and total == sum(summary["byRule"].values()) ==
         sum(summary["byUnit"].values()) and total == 0, "privacy aggregate findings remain or disagree")
    _privacy_stage(failure_state, 'aggregate', 'inspection_complete')
    need(receipt.get("inspectionComplete") is True and receipt.get("findings") == [] and
         receipt.get("representativesTruncated") is False and "refusal" not in receipt and
         type(receipt.get("representativeLimit")) is int and
         0 <= receipt["representativeLimit"] <= privacy_contract.MAX_REPRESENTATIVES,
         "privacy inspection is incomplete or findings remain")
    _privacy_stage(failure_state, 'aggregate', 'location_index')
    need(receipt.get("locationIndex") == [] and receipt.get("locationIndexTruncated") is False and
         type(receipt.get("locationIndexLimit")) is int and
         receipt["locationIndexLimit"] == privacy_contract.MAX_LOCATION_ROWS and
         type(receipt.get("locationIndexByteLimit")) is int and
         receipt["locationIndexByteLimit"] == privacy_contract.MAX_LOCATION_BYTES,
         "privacy location index is missing, truncated or nonempty")
    _privacy_stage(failure_state, 'qualification', 'presence')
    if receipt.get("sourceSha") == privacy_contract.PUBLIC_MEMBER_QUALIFICATION["sourceSha"]:
        need("publicMemberQualification" in receipt, "source qualification proof missing")
    if "publicMemberQualification" in receipt:
        try:
            _privacy_stage(failure_state, 'qualification', 'plan_read')
            plan = read_bounded_bytes(Path(__file__).with_name("public-member-comparisons-v105-workboard.json"),
                                      privacy_contract.MAX_COMPARISON_PLAN_BYTES)
            _privacy_stage(failure_state, 'qualification', 'plan_validate')
            privacy_contract.require_public_member_qualification(receipt, plan)
        except (privacy_contract.Refusal, OSError, ValueError, TypeError, KeyError, AttributeError) as error:
            # Preserve only closed type/code/errno before the historical fixed
            # outer refusal intentionally suppresses the underlying exception.
            if failure_state is not None:
                failure_state['failure'] = _privacy_failure_fields(error)
            raise Refusal("public member qualification is incomplete or changed") from None


def runtime_proof(seal):
    """New hosted exports require measured image facts, not source test results."""
    proof = seal.get("runtimeQualification")
    need(isinstance(proof, dict), "actual image runtime proof missing")
    expected = proof.get("expected")
    need(isinstance(expected, dict) and set(expected) == {
        "nodeVersion", "markdownVersion", "argparseVersion", "dockerfileSha256",
        "consumerManifestSha256", "lockfileSha256"}, "invalid runtime expectations")
    need(all(isinstance(expected[key], str) and re.fullmatch(r"\d+\.\d+\.\d+", expected[key])
             for key in ("nodeVersion", "markdownVersion", "argparseVersion")), "invalid runtime version")
    need(all(isinstance(expected[key], str) and re.fullmatch(r"[a-f0-9]{64}", expected[key])
             for key in ("dockerfileSha256", "consumerManifestSha256", "lockfileSha256")), "invalid runtime source hash")
    node, markdown, ui = (proof.get(key) for key in ("node", "markdown", "controlUi"))
    need(all(isinstance(value, dict) for value in (node, markdown, ui)), "incomplete runtime proof")
    need(proof.get("schema") == "openclaw.image-runtime.v1" and
         all(proof.get(key) == seal.get(key) for key in ("sourceSha", "imageDigest", "configDigest")) and
         node == {"version": expected["nodeVersion"], "platform": "linux", "architecture": "x64"} and
         markdown.get("version") == expected["markdownVersion"] and
         markdown.get("argparseVersion") == expected["argparseVersion"] and
         markdown.get("resolution") == "pnpm-production-store" and
         markdown.get("consumer") == "dist/plugin-sdk/text-chunking.js" and
         markdown.get("render") is True and markdown.get("documentIsolation") is True,
         "actual image runtime proof changed")
    need(all(isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) for value in
             (markdown.get("consumerSha256"), ui.get("indexSha256"), ui.get("manifestSha256"), ui.get("generation"))) and
         type(ui.get("assetCount")) is int and 0 < ui["assetCount"] <= 4096 and
         type(ui.get("assetBytes")) is int and 0 < ui["assetBytes"] <= 96 * 1024 * 1024,
         "incomplete built UI or consumer proof")


def require_resources(resources, *, source, tooling, index, require_pass=True):
    """Share resource identity checks without promoting failed private evidence."""
    need(type(require_pass) is bool, "invalid resource admission mode")
    need(isinstance(resources, dict) and
         resources.get("schema") == "openclaw.hosted-resources.v1" and
         resources.get("status") in ("passed", "failed") and
         isinstance(resources.get("violations"), list),
         "incomplete privacy or resource assessment")
    need(resources.get("toolingSha") == tooling, "assessment tooling changed")
    need(resources.get("sourceSha") == source and resources.get("indexDigest") == index,
         "assessment source or image changed")
    if require_pass:
        need(resources["status"] == "passed", "incomplete privacy or resource assessment")
        need(resources["violations"] == [], "resource violations remain")
    return resources["status"] == "passed" and resources["violations"] == []


def validate(seal, privacy, resources, *, source, tooling, index, run, attempt,
             public_export=False, storage_approved=False):
    need(re.fullmatch(r"[0-9a-f]{40}", source or "") is not None, "invalid source identity")
    need(re.fullmatch(r"[0-9a-f]{40}", tooling or "") is not None, "invalid tooling identity")
    need(re.fullmatch(r"sha256:[0-9a-f]{64}", index or "") is not None, "invalid image identity")
    need(all(re.fullmatch(r"[1-9][0-9]*", v or "") for v in (run, attempt)),
         "invalid execution identity")
    need(not public_export or storage_approved, "public artifact storage is not approved")
    need(isinstance(seal, dict) and seal.get("schema") == "openclaw.fork-release-image.v2",
         "missing native image seal")
    need(seal.get("repository") == "fr-meyer/openclaw" and
         seal.get("architecture") == "amd64", "wrong repository or architecture")
    need(seal.get("producer") == {"workflowSha": tooling, "runId": run, "attempt": attempt},
         "image seal belongs to another execution")
    need(seal.get("buildContext") == {"kind": "git", "repository": "https://github.com/fr-meyer/openclaw",
                                      "sourceSha": source}, "hosted Git source proof missing or changed")
    runtime_proof(seal)
    need(isinstance(privacy, dict) and privacy.get("schema") == "openclaw.hosted-privacy.v2" and
         privacy.get("status") == "passed", "incomplete privacy or resource assessment")
    need(privacy.get("toolingSha") == tooling, "assessment tooling changed")
    for receipt in (seal, privacy):
        need(receipt.get("sourceSha") == source and receipt.get("indexDigest") == index,
             "assessment source or image changed")
    require_resources(resources, source=source, tooling=tooling, index=index)
    require_clean_privacy(privacy)
    for field in ("imageDigest", "configDigest"):
        need(re.fullmatch(r"sha256:[0-9a-f]{64}", seal.get(field, "")) is not None and
             privacy.get(field) == seal[field], "privacy selected another image")
    name = f"fork-release-{source}-{run}-{attempt}"
    need(seal.get("artifactName") == name, "artifact name changed")
    return {"schema": "openclaw.hosted-export.v1", "status": "passed",
            "sourceSha": source, "toolingSha": tooling, "indexDigest": index,
            "producer": seal["producer"], "artifactName": name,
            "export": "public-actions-artifact" if public_export else "none",
            "storageApprovalRecorded": storage_approved if public_export else False,
            "productionAuthorized": False}


def read_bounded_bytes(path, limit):
    # These are owned reports/trusted plans, never a runtime/home/database path.
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= limit,
             "invalid or oversized receipt")
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        need(len(data) <= limit and len(data) == before.st_size and
             (before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
             (after.st_size, after.st_mtime_ns, after.st_ctime_ns), "receipt changed")
    return data


def read_receipt(path):
    data = read_bounded_bytes(path, 1024 * 1024)
    return json.loads(data), hashlib.sha256(data).hexdigest()


class RetainedClosure(privacy_contract.Inspector):
    """Rehash the exact previously inspected OCI graph without unpacking layers."""
    def __init__(self, directory, index, source, tooling):
        super().__init__(directory, index, source, tooling, privacy_contract.Limits())
        self.root_hashes = {}

    def local_json(self, name):
        data = read_bounded_bytes(self.directory / name, self.limits.json_bytes)
        self.root_hashes[name] = hashlib.sha256(data).hexdigest()
        value = self.parse_json(data)
        self.scan_json(value, name)
        return value

    def scan_layer(self, descriptor):
        privacy_contract.require(descriptor.get("mediaType") in
                                 (privacy_contract.TAR, privacy_contract.GZIP), "unsupported_layer_format")
        self.counts["layers"] += 1
        privacy_contract.require(self.counts["layers"] <= self.limits.layers, "layer_limit")
        stream, _ = self.blob(descriptor)
        stream.close()

    def closure_digest(self):
        self.run()
        need(self.finding_total == 0, "retained metadata privacy findings")
        # Root metadata is outside the content-addressed graph. Pin its complete
        # bytes as well, including harmless changes, and reject a moving input.
        for name, digest in self.root_hashes.items():
            need(hashlib.sha256(read_bounded_bytes(self.directory / name, self.limits.json_bytes)).hexdigest()
                 == digest, "retained root metadata changed")
        value = {"schema": "openclaw.oci-closure.v1", "sourceSha": self.source_sha,
                 "indexDigest": self.index_digest, "roots": self.root_hashes,
                 "blobs": sorted(self.blobs.items())}
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def check_privacy(argv):
    """One shared native-admission check; never print untrusted receipt fields."""
    parser = argparse.ArgumentParser(description="Check an exact clean privacy receipt")
    for name in ("privacy", "sha256", "source-sha", "tooling-sha", "index-digest"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--oci")
    args = parser.parse_args(argv)
    failure_state = {'phase': 'arguments', 'subcheck': 'syntax'}
    try:
        need(re.fullmatch(r"[0-9a-f]{64}", args.sha256 or "") and
             re.fullmatch(r"[0-9a-f]{40}", args.source_sha or "") and
             re.fullmatch(r"[0-9a-f]{40}", args.tooling_sha or "") and
             re.fullmatch(r"sha256:[0-9a-f]{64}", args.index_digest or ""), "invalid binding")
        _privacy_stage(failure_state, 'receipt', 'read')
        receipt, digest = read_receipt(args.privacy)
        _privacy_stage(failure_state, 'receipt', 'binding')
        need(digest == args.sha256 and receipt.get("sourceSha") == args.source_sha and
             receipt.get("toolingSha") == args.tooling_sha and
             receipt.get("indexDigest") == args.index_digest, "privacy binding changed")
        require_clean_privacy(receipt, failure_state=failure_state)
        result = {"status": "passed", "privacyReceiptSha256": digest}
        if args.oci:
            _privacy_stage(failure_state, 'closure', 'initialize')
            closure = RetainedClosure(args.oci, args.index_digest, args.source_sha, args.tooling_sha)
            _privacy_stage(failure_state, 'closure', 'digest')
            result["ociClosureSha256"] = closure.closure_digest()
            _privacy_stage(failure_state, 'closure', 'selected_image')
            need(closure.image_digest == receipt.get("imageDigest") and
                 closure.config_digest == receipt.get("configDigest"), "retained image changed")
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError, privacy_contract.Refusal) as error:
        print(json.dumps({'status': 'failed', 'reason': 'privacy_not_clean_or_bound',
                          'diagnostic': _privacy_diagnostic(error, failure_state)}, sort_keys=True))
        return 1


def main():
    if sys.argv[1:2] == ["check-privacy"]:
        raise SystemExit(check_privacy(sys.argv[2:]))
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("seal", "privacy", "resources", "source-sha", "tooling-sha", "index-digest",
                 "run-id", "attempt", "output"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--public-export", choices=("true", "false"), default="false")
    parser.add_argument("--storage-approved", choices=("true", "false"), default="false")
    args = parser.parse_args()
    try:
        values = [read_receipt(getattr(args, name)) for name in ("seal", "privacy", "resources")]
        result = validate(*(v[0] for v in values), source=args.source_sha, tooling=args.tooling_sha,
                          index=args.index_digest, run=args.run_id, attempt=args.attempt,
                          public_export=args.public_export == "true",
                          storage_approved=args.storage_approved == "true")
        result["receiptSha256"] = dict(zip(("seal", "privacy", "resources"), (v[1] for v in values)))
        with Path(args.output).open("x") as output:
            output.write(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, sort_keys=True))
    except (OSError, ValueError, TypeError):
        # Do not echo untrusted receipt values or secret matches into public logs.
        raise SystemExit("Hosted export refused: incomplete, changed or unauthorized evidence") from None


if __name__ == '__main__':
    raise SystemExit('ci_import_only')
