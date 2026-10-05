#!/usr/bin/env python3
"""Render an unapplied exact OpenSSL read proposal; never apply a policy.

Only pinned Python declarations/functions and retained JSON metadata are used.
No image, ELF, native program, Docker, or host-control operation is invoked.
The CLI can write a patch and receipt to a new separate proposal directory.
It never writes the projected source/read-policy files.
"""
import argparse
import difflib
import gzip
import hashlib
import json
import stat
from pathlib import Path


PREFIX = "scripts/proofs/v98-confined/"
DERIVE = PREFIX + "derive_read_policy.py"
BINDING = PREFIX + "read-policy/runtime-read-binding.json"
PARENT = PREFIX + "read-policy/parent-read-paths.txt"
HELPER = PREFIX + "read-policy/helper-read-paths.txt"
DERIVE_SHA = "1df6fd10ae0c3e91e128f94c2b93ab38816d8c080aabdd5836bbc87b2edd43f1"
BINDING_SHA = "f4697e6eb2868dc1d44e5074eadb385e1963d23d54e8ed12c81c2dbf82b00667"
LIST_SHA = "0df305867ff2cbf6675198f0545a8dc18d8dbe53e99849e732abac02313c8f03"
ASSESSMENT_PATH = "openclaw-v98-runtime-local-successor-review-20261005/node-openssl-startup-assessment.json"
ASSESSMENT_SHA = "35f83029500191d238f68505b781836adab51bcdd3ad02bf95c0d7ff6fa72015"
CONFIG = {"path": "/etc/ssl/openssl.cnf", "mode": "0o644", "type": "file",
          "bytes": 12332, "sha256": "7ae8cae2e64856b34c80276deb1dcf60f76da27bc1e00382201ba7bb7dc33311"}
NODE = {"path": "/usr/local/bin/node", "mode": "0o755", "type": "file",
        "bytes": 126595440, "sha256": "7fde7b8afa198da66257f42ee2001d874c7355631e6d1579a5fb5ef1f246df4c"}
LAYER = "7cceb600eafaa47b3ccccf5a66c0034e9113f827a092d85a9a535317dd79ee7a"
NAMESPACE = [
    {"path": "/etc/ssl", "mode": "0o755", "type": "directory"},
    {"path": "/usr/lib/ssl/openssl.cnf", "mode": "0o777", "type": "symlink",
     "target": "/etc/ssl/openssl.cnf"},
]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def decode_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique)


def _inert_deriver(source):
    # The exact reviewed original or our two textual edits are the only inputs.
    original = digest(source) == DERIVE_SHA
    if not original:
        raise ValueError("active derivation source pin changed")
    scope = {"__name__": "v98_unapplied_read_proposal"}
    exec(compile(source, "<pinned-inert-read-derivation>", "exec"), scope)
    return scope


def proposed_derive_bytes(source):
    """Return exactly two source replacements, never write the active source."""
    _inert_deriver(source)
    text = source.decode("utf-8")
    old_selection = '    "/etc/ld.so.cache",\n)'
    new_selection = '    "/etc/ld.so.cache",\n    "/etc/ssl/openssl.cnf",\n)'
    old_elf = '    for path in (GNU_FS_SAFE, GNU_KOFFI) + SYSTEM_FILES[:-1]:'
    new_elf = ('    elf_files = tuple(path for path in SYSTEM_FILES\n'
               '                      if path not in ("/etc/ld.so.cache", "/etc/ssl/openssl.cnf"))\n'
               '    for path in (GNU_FS_SAFE, GNU_KOFFI) + elf_files:')
    if text.count(old_selection) != 1 or text.count(old_elf) != 1:
        raise ValueError("exact derivation replacement anchors changed")
    return text.replace(old_selection, new_selection).replace(old_elf, new_elf).encode("utf-8")


def _future_deriver(original):
    future = proposed_derive_bytes(original)
    scope = {"__name__": "v98_unapplied_read_proposal"}
    exec(compile(future, "<proposed-inert-read-derivation>", "exec"), scope)
    return future, scope


def _decode_inputs(raw_inputs, deriver):
    if set(raw_inputs) != set(deriver["PINNED_INPUTS"]):
        raise ValueError("all five pinned derivation inputs are required")
    decoded = {}
    for key, (_, expected) in deriver["PINNED_INPUTS"].items():
        data = raw_inputs[key]
        if digest(data) != expected:
            raise ValueError("pinned derivation input changed: " + key)
        decoded[key] = decode_json(gzip.decompress(data) if key == "inventory" else data)
    return decoded


def _validate_proposal(proposal, payload, deriver):
    if (proposal.get("schema") != "openclaw-v98-unapplied-openssl-read-proposal/v1"
            or proposal.get("status") != "UNAPPLIED; EXPLICIT_PERMISSION_APPROVAL_REQUIRED"
            or proposal.get("canonicalRead") != CONFIG or proposal.get("nodeIdentity") != NODE
            or proposal.get("sourceCommit") != deriver["SOURCE_COMMIT"]
            or proposal.get("sourceTree") != deriver["SOURCE_TREE"]
            or proposal.get("imageSha256") != deriver["IMAGE_SHA256"]
            or proposal.get("imageConfigId") != deriver["IMAGE_CONFIG"]
            or proposal.get("permission") != "READ_FILE"
            or proposal.get("scopes") != ["parent", "fresh Node helper"]
            or proposal.get("currentReadBindingSha256") != BINDING_SHA
            or proposal.get("currentParentAndHelperListSha256") != LIST_SHA
            or proposal.get("sourceAssessmentSha256") != ASSESSMENT_SHA
            or proposal.get("countsAfterApproval") != {"regularReadFiles": 1548, "namespaceMetadata": 360}
            or proposal.get("noDirectoryReadGrant") is not True
            or proposal.get("payloadIsNotCopiedIntoRuntimeProof") is not True
            or proposal.get("proposalPayloadPath") != PREFIX + "proposal/image-openssl.cnf"
            or proposal.get("activeConfigIncludes") != []
            or proposal.get("configDrivenProviderEngineDsos") != []
            or proposal.get("completeDynamicClosureClaimed") is not False):
        raise ValueError("exact unapplied permission proposal changed")
    if proposal.get("savedLayerCustody") != {
            "layerArchivePath": "blobs/sha256/" + LAYER,
            "layerDiffId": "sha256:" + LAYER, "selectedPayloadBytesJoined": True}:
        raise ValueError("config saved-layer custody changed")
    namespace = proposal.get("namespaceMetadataOnly")
    if not isinstance(namespace, list) or len(namespace) != 2:
        raise ValueError("proposal namespace metadata changed")
    for actual, expected in zip(namespace, NAMESPACE):
        if ({k: actual.get(k) for k in expected} != expected
                or actual.get("metadataOnly") is not True
                or actual.get("directoryReadGrant") is not False
                or actual.get("alreadyInReviewedBinding") is not False):
            raise ValueError("proposal namespace metadata changed")
    if len(payload) != CONFIG["bytes"] or digest(payload) != CONFIG["sha256"]:
        raise ValueError("proposal config payload changed")


def _validate_capture(assessment_bytes, payload, proposal, inputs):
    if digest(assessment_bytes) != ASSESSMENT_SHA:
        raise ValueError("independent saved-image assessment pin changed")
    assessment = decode_json(assessment_bytes)
    capture = assessment["capturedSmallFiles"][CONFIG["path"]]
    if (capture["identity"] != CONFIG or capture["text"].encode("utf-8") != payload
            or {k: capture[k] for k in ("layerArchivePath", "layerDiffId", "selectedPayloadBytesJoined")}
            != proposal["savedLayerCustody"]):
        raise ValueError("payload differs from the pinned saved-layer capture")
    entries = {row["path"]: row for row in inputs["inventory"]["entries"]}
    if entries.get(CONFIG["path"]) != CONFIG or entries.get(NODE["path"]) != NODE:
        raise ValueError("config or Node differs from pinned image inventory")


def _derive_projection(source, inputs, current_files):
    """Pure derivation helper; render_projection additionally proves input custody."""
    active = _inert_deriver(source)
    future_source, future = _future_deriver(source)
    before = active["derive_binding"](**inputs)
    if (json_bytes(before) != current_files[BINDING]
            or active["read_list_bytes"](active["image_read_paths"](before)) != current_files[PARENT]
            or current_files[PARENT] != current_files[HELPER]):
        raise ValueError("baseline derivation does not reproduce active binding/read bytes")
    after = future["derive_binding"](**inputs)
    if set(before) != set(after):
        raise ValueError("proposed binding changed non-selection metadata keys")
    for key in before:
        if key not in ("imageEntries", "namespaceEntries") and before[key] != after[key]:
            raise ValueError("proposed binding changed non-selection metadata")
    for key, additions in (("imageEntries", [{**CONFIG, "reasons": ["named-node-and-gnu-loader-runtime"]}]),
                           ("namespaceEntries", NAMESPACE)):
        old = {row["path"]: row for row in before[key]}
        new = {row["path"]: row for row in after[key]}
        if (not all(new.get(path) == row for path, row in old.items())
                or [new[path] for path in sorted(set(new) - set(old))] != additions
                or len(new) != len(old) + len(additions)):
            raise ValueError("proposal changed more than the exact one-file/two-metadata delta")
    reads = future["read_list_bytes"](future["image_read_paths"](after))
    files = {DERIVE: future_source, BINDING: json_bytes(after), PARENT: reads, HELPER: reads}
    return files, before, after


def render_projection(*, derive_bytes, pinned_inputs, current_files, proposal_bytes,
                      config_payload_bytes, assessment_bytes):
    """Return (relative source path -> future bytes, metadata); never write files."""
    active = _inert_deriver(derive_bytes)
    if (set(current_files) != {BINDING, PARENT, HELPER}
            or digest(current_files[BINDING]) != BINDING_SHA
            or any(digest(current_files[path]) != LIST_SHA for path in (PARENT, HELPER))):
        raise ValueError("active read-policy byte pins changed")
    proposal = decode_json(proposal_bytes)
    _validate_proposal(proposal, config_payload_bytes, active)
    inputs = _decode_inputs(pinned_inputs, active)
    _validate_capture(assessment_bytes, config_payload_bytes, proposal, inputs)
    files, before, after = _derive_projection(derive_bytes, inputs, current_files)
    if ((len(before["imageEntries"]), len(before["namespaceEntries"])) != (1547, 358)
            or (len(after["imageEntries"]), len(after["namespaceEntries"])) != (1548, 360)):
        raise ValueError("exact original/projected selection counts changed")
    originals = {DERIVE: derive_bytes, **current_files}
    metadata = {
        "schema": "openclaw-v98-inert-openssl-read-projection/v1",
        "status": "UNAPPLIED; EXPLICIT_PERMISSION_APPROVAL_AND_FRESH_INTEGRATION_REVIEW_REQUIRED",
        "policyApplied": False, "executionAdmission": False, "runtimeExecuted": False,
        "completeDynamicClosureClaimed": False,
        "sourceCommit": active["SOURCE_COMMIT"], "sourceTree": active["SOURCE_TREE"],
        "imageSha256": active["IMAGE_SHA256"], "imageConfigId": active["IMAGE_CONFIG"],
        "assessmentSha256": ASSESSMENT_SHA, "proposalSha256": digest(proposal_bytes),
        "configPayloadSha256": digest(config_payload_bytes), "configSavedLayerDiffId": "sha256:" + LAYER,
        "countsBefore": {"regularReadFiles": 1547, "namespaceMetadata": 358},
        "countsAfterApproval": {"regularReadFiles": 1548, "namespaceMetadata": 360},
        "addedRegularRead": {**CONFIG, "scopes": ["parent", "fresh Node helper"], "permission": "READ_FILE"},
        "addedNamespaceMetadata": NAMESPACE, "directoryReadGrant": False,
        "allOtherBindingRowsAndMetadataUnchanged": True,
        "pinnedInputs": {key: {"path": name, "sha256": pin} for key, (name, pin) in active["PINNED_INPUTS"].items()},
        "files": [{"path": path, "mode": "0o644",
                   "before": {"bytes": len(originals[path]), "sha256": digest(originals[path])},
                   "after": {"bytes": len(files[path]), "sha256": digest(files[path])}}
                  for path in sorted(files)],
        "remainingIntegration": "Host/packet/verifier count and hash joins, projected manifest and external approval packet require separate reviewed changes. This renderer does not apply them or solve runtime accounting/behavior gates.",
    }
    return files, metadata


def _regular_bytes(path, mode=None):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or (mode is not None and stat.S_IMODE(info.st_mode) != mode):
        raise ValueError("projection input must be a regular file")
    return path.read_bytes()


def load_render_inputs(checkout, evidence_root):
    """Read retained metadata/payloads only; no image archive traversal or imports."""
    checkout, evidence_root = Path(checkout), Path(evidence_root)
    source = _regular_bytes(checkout / DERIVE, mode=0o644)
    active = _inert_deriver(source)
    return {"derive_bytes": source,
            "pinned_inputs": {key: _regular_bytes(evidence_root / name)
                              for key, (name, _) in active["PINNED_INPUTS"].items()},
            "current_files": {path: _regular_bytes(checkout / path, mode=0o644)
                              for path in (BINDING, PARENT, HELPER)},
            "proposal_bytes": _regular_bytes(checkout / (PREFIX + "proposal/openssl-read-proposal.json")),
            "config_payload_bytes": _regular_bytes(checkout / (PREFIX + "proposal/image-openssl.cnf")),
            "assessment_bytes": _regular_bytes(evidence_root / ASSESSMENT_PATH)}


def standalone_patch(originals, projected):
    chunks = []
    for path in sorted(projected):
        chunks.append("diff --git a/" + path + " b/" + path + "\n")
        chunks.extend(difflib.unified_diff(originals[path].decode("utf-8").splitlines(True),
                                           projected[path].decode("utf-8").splitlines(True),
                                           fromfile="a/" + path, tofile="b/" + path))
    return "".join(chunks).encode("utf-8")


def write_proposal_output(destination, checkout, patch, metadata):
    """Write only patch/receipt in a new explicit directory outside the checkout."""
    destination, checkout = Path(destination).resolve(), Path(checkout).resolve()
    if destination == checkout or checkout in destination.parents:
        raise ValueError("proposal destination must be outside the active checkout")
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    with (destination / "openssl-read-proposal.patch").open("xb") as stream:
        stream.write(patch)
    with (destination / "projection.json").open("xb") as stream:
        stream.write(json_bytes({**metadata, "patchSha256": digest(patch), "patchBytes": len(patch)}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--proposal-destination", type=Path)
    args = parser.parse_args()
    values = load_render_inputs(args.checkout, args.evidence_root)
    files, metadata = render_projection(**values)
    if args.proposal_destination is not None:
        patch = standalone_patch({DERIVE: values["derive_bytes"], **values["current_files"]}, files)
        write_proposal_output(args.proposal_destination, args.checkout, patch, metadata)
    print(json.dumps(metadata, sort_keys=True))


if __name__ == "__main__":
    main()
