"""Pure binding for the single approved npm12.2.1 cancellation backport.

The JavaScript producer owns archive/compiler verification. This contract binds
its closed generated source files to the existing CI/Git proof without granting
package, process, network, or publication authority.
"""
import hashlib
import json
import math
import re

SCHEMA = "openclaw.v109.npm-vendor-derivation.v1"
PROOF_SCHEMA = "openclaw.npm-glob-vendor-backport.v1"
PATCH = "patches/npm@12.2.1.patch"
PROOF = "patches/npm-12.2.1.glob-cancellation.proof.json"
WORKSPACE = "pnpm-workspace.yaml"
GENERATED = (WORKSPACE, PATCH, PROOF)
PRODUCER = "scripts/build-npm-glob-vendor-backport.mjs"
QUALIFIER = "scripts/qualify-npm-glob-vendor-backport.mjs"
CONTROL_TESTS = (("scripts/test-npm-glob-vendor-controls.mjs", 30),
    ("scripts/test-npm-glob-vendor-qualification.mjs", 22))
QUALIFICATION_CASE_COUNT = 52
JS_MEMBERS = tuple("node_modules/glob/dist/" + kind + "/" + name
    for kind in ("commonjs", "esm") for name in ("index.min.js", "walker.js"))
ORIGINAL_SHA256 = "228bd64aaef23270dbdbd2cf3d5ef5c467602ef38c4066246cef1984adab9a67"
ORIGINAL_SRI = "sha512-bKCmFRVT/BB+YPEYbZwQ1XUI3N5t4xKSpU1MxOjo7z3iWzKBJ0ZXRC1xFdEN+TC7N5TdywaBzf2dMXGJq/e2PQ=="
ORIGINAL_INVENTORY_SHA256 = "c9a016c3ef9993a88d8dad15ecb5d508a59f5f958c3ff6352d8b4ccfe5362fa3"
SOURCE_COMMIT = "e80cb38ae60d6cbff9e75f39032a994858994d35"
FIX_COMMIT = "4682e8c9babee1b385202ede36389634e12076d7"
ESBUILD_SRI = "sha512-HKVLS8dvII+xoKW9kmqxbRKrnWEXfJJr/FZhhJmiqIB0e053QNYFqOBouTMO/k5sID4MvCiUCvv8b9M4h32wIA=="
HEX = re.compile(r"[0-9a-f]{64}\Z")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def pin(value):
    return type(value) is str and HEX.fullmatch(value) is not None


def strict_json(raw, need, maximum=2 * 1024 * 1024):
    need(type(raw) is bytes and 0 < len(raw) <= maximum, "v9.vendor_bounded_json")
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, "v9.vendor_duplicate_json")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs,
            parse_constant=lambda _: need(False, "v9.vendor_nonfinite_json"))
    except (UnicodeError, ValueError, TypeError):
        need(False, "v9.vendor_json")


def validate_record(value, need, *, generation=None):
    keys = {"schema", "sourceGeneration", "workspaceSha256", "patchSha256", "proofSha256", "producerRuntimeSha256"}
    need(type(value) is dict and set(value) == keys and value["schema"] == SCHEMA and
        type(value["sourceGeneration"]) is int and 2 <= value["sourceGeneration"] <= 3 and
        (generation is None or value["sourceGeneration"] == generation) and
        all(pin(value[k]) for k in keys - {"schema", "sourceGeneration"}), "v9.vendor_record")
    return value


def expected_workspace(before, need):
    need(type(before) is bytes and 0 < len(before) <= 2 * 1024 * 1024 and b"\r" not in before,
        "v9.vendor_workspace_bytes")
    try:
        text = before.decode("utf8")
    except UnicodeError:
        need(False, "v9.vendor_workspace_utf8")
    marker = "patchedDependencies:\n"
    matches = list(re.finditer(r"^patchedDependencies:\n", text, re.M))
    need(len(matches) == 1, "v9.vendor_workspace_patch_section")
    boundary = matches[0].end()
    head, tail = text[:boundary - len(marker)], text[boundary:]
    end = re.search(r"^[^ #\n]", tail, re.M)
    body = tail[:end.start()] if end else tail
    existing = re.findall(r"^  [\"']?npm@12\.2\.1[\"']?:[^\n]*$", body, re.M)
    line = "  npm@12.2.1: " + PATCH
    need(len(existing) <= 1 and (not existing or existing == [line]), "v9.vendor_workspace_existing_npm_patch")
    return before if existing else (head + marker + line + "\n" + tail).encode()


def validate_patch(raw, need):
    need(type(raw) is bytes and 0 < len(raw) <= 2 * 1024 * 1024 and b"\0" not in raw,
        "v9.vendor_patch_bounded")
    try:
        text = raw.decode("utf8")
    except UnicodeError:
        need(False, "v9.vendor_patch_utf8")
    names = re.findall(r"^diff --git a/([^\n ]+) b/([^\n ]+)$", text, re.M)
    need(len(names) == len(JS_MEMBERS) and all(a == b for a, b in names) and
        sorted(a for a, _ in names) == list(JS_MEMBERS), "v9.vendor_patch_exact_members")
    need(sorted(re.findall(r"^--- a/([^\n]+)$", text, re.M)) == list(JS_MEMBERS) and
        sorted(re.findall(r"^\+\+\+ b/([^\n]+)$", text, re.M)) == list(JS_MEMBERS) and
        len(re.findall(r"^@@ ", text, re.M)) >= 4 and
        not re.search(r"^(?:new file mode|deleted file mode|old mode|new mode|rename|copy|GIT binary patch|Binary files)", text, re.M),
        "v9.vendor_patch_regular_replacements")
    return raw


def validate_proof(raw, patch, need):
    value = strict_json(raw, need)
    need((json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode() == raw, "v9.vendor_canonical_proof")
    need(type(value) is dict and set(value) == {"schema", "npmVersion", "original", "repair", "compiler", "derived", "patch", "maps"} and
        value["schema"] == PROOF_SCHEMA and value["npmVersion"] == "12.2.1", "v9.vendor_proof_fields")
    original, repair, compiler, derived, bound_patch = (value[k] for k in ("original", "repair", "compiler", "derived", "patch"))
    need(type(original) is dict and set(original) == {"integrity", "sha256", "inventorySha256", "mapsAbsent", "files"} and
        original["mapsAbsent"] is True and original["integrity"] == ORIGINAL_SRI and original["sha256"] == ORIGINAL_SHA256 and
        original["inventorySha256"] == ORIGINAL_INVENTORY_SHA256 and type(original["files"]) is list and
        len(original["files"]) == 1942, "v9.vendor_original_identity")
    paths = []
    for row in original["files"]:
        need(type(row) is dict and set(row) == {"path", "mode", "size", "sha256"} and
            type(row["path"]) is str and not row["path"].startswith("/") and
            not re.search(r"[\x00-\x1f\x7f\\]", row["path"]) and
            all(part not in ("", ".", "..") for part in row["path"].split("/")) and
            type(row["mode"]) is int and row["mode"] in (0o644, 0o755) and
            type(row["size"]) is int and 0 <= row["size"] <= 8 * 1024 * 1024 and pin(row["sha256"]), "v9.vendor_original_file")
        paths.append(row["path"])
    need(paths == sorted(set(paths)), "v9.vendor_original_inventory_order")
    inventory = json.dumps(original["files"], separators=(",", ":"), ensure_ascii=True).encode() + b"\n"
    need(digest(inventory) == ORIGINAL_INVENTORY_SHA256, "v9.vendor_original_inventory_hash")
    need(type(repair) is dict and set(repair) == {"globVersion", "fixCommit", "sourceCommit", "sourceSha256", "upstreamFixSha256", "changedFiles"} and
        repair["globVersion"] == "13.0.6" and repair["fixCommit"] == FIX_COMMIT and
        repair["sourceCommit"] == SOURCE_COMMIT and
        repair["sourceSha256"] == "ae534f35edd3837a2969ecdd4ea90853cc1b9a9c8e4d10108e5e0994fb5e001e" and
        repair["upstreamFixSha256"] == "22adee340137e4f0636701c99bb5f75fb572d38c91ff5de0b77b80f453c18e4a" and
        type(repair["changedFiles"]) is list and len(repair["changedFiles"]) == 4, "v9.vendor_repair_identity")
    originals = {row["path"]: row for row in original["files"]}
    changed = []
    for row in repair["changedFiles"]:
        need(type(row) is dict and set(row) == {"path", "oldSha256", "newSha256", "size", "mode"} and
            row["path"] in JS_MEMBERS and row["oldSha256"] == originals[row["path"]]["sha256"] and
            pin(row["newSha256"]) and row["newSha256"] != row["oldSha256"] and
            type(row["size"]) is int and row["size"] > 0 and row["mode"] == originals[row["path"]]["mode"],
            "v9.vendor_changed_file")
        changed.append(row["path"])
    need(changed == list(JS_MEMBERS), "v9.vendor_exact_changed_inventory")
    need(compiler == {"name": "esbuild", "version": "0.28.2", "integrity": ESBUILD_SRI}, "v9.vendor_existing_compiler")
    need(type(derived) is dict and set(derived) == {"integrity", "sha256", "inventorySha256"} and
        all(type(derived[k]) is str for k in derived) and pin(derived["sha256"]) and pin(derived["inventorySha256"]) and
        re.fullmatch(r"sha512-[A-Za-z0-9+/]{86}==", derived["integrity"]) is not None and
        derived["sha256"] != ORIGINAL_SHA256, "v9.vendor_derived_identity")
    transformed = [dict(row) for row in original["files"]]
    changes = {row["path"]: row for row in repair["changedFiles"]}
    for row in transformed:
        if row["path"] in changes:
            row["sha256"] = changes[row["path"]]["newSha256"]
            row["size"] = changes[row["path"]]["size"]
    need(digest(json.dumps(transformed, separators=(",", ":")).encode() + b"\n") == derived["inventorySha256"],
        "v9.vendor_derived_inventory_hash")
    validate_patch(patch, need)
    need(bound_patch == {"filename": PATCH.rsplit("/", 1)[1], "sha256": digest(patch), "size": len(patch)}, "v9.vendor_patch_proof")
    need(type(value["maps"]) is list and len(value["maps"]) == 4 and
        [r.get("path") for r in value["maps"] if type(r) is dict] == [p + ".map" for p in JS_MEMBERS] and
        all(set(row) == {"path", "size", "sha256"} and type(row["size"]) is int and row["size"] > 0 and
            pin(row["sha256"]) for row in value["maps"]), "v9.vendor_external_map_evidence")
    return value


def make_record(generation, workspace, patch, proof, producer, need):
    validate_proof(proof, patch, need)
    return validate_record({"schema": SCHEMA, "sourceGeneration": generation,
        "workspaceSha256": digest(workspace), "patchSha256": digest(patch), "proofSha256": digest(proof),
        "producerRuntimeSha256": digest(producer)}, need, generation=generation)


def verify_files(record, before_workspace, workspace, patch, proof, producer, need):
    validate_record(record, need)
    need(workspace == expected_workspace(before_workspace, need), "v9.vendor_deterministic_workspace")
    actual = make_record(record["sourceGeneration"], workspace, patch, proof, producer, need)
    need(actual == record, "v9.vendor_generated_file_binding")
    return actual


def unpatched_lock(before, generated, patch_sha256, need):
    """Remove only pnpm's fixed npm patch registration/reference transformation.

    The caller runs all original graph, integrity, override, and age checks on
    the result. No bundled-version override is granted by this operation.
    """
    need(pin(patch_sha256), "v9.vendor_lock_patch_hash")
    try:
        old, new = before.decode("utf8"), generated.decode("utf8")
    except (AttributeError, UnicodeError):
        need(False, "v9.vendor_lock_utf8")
    def patch_section(text):
        markers = list(re.finditer(r"^patchedDependencies:\n", text, re.M))
        need(len(markers) == 1, "v9.vendor_lock_patch_section")
        tail = text[markers[0].end():]
        following = re.search(r"^[A-Za-z][A-Za-z0-9]*:", tail, re.M)
        return tail[:following.start()] if following else tail
    old_hash = re.findall(r"^  npm@12\.2\.1: ([0-9a-f]{64})$", patch_section(old), re.M)
    need(len(old_hash) <= 1, "v9.vendor_seed_patch_unique")
    new_line = "  npm@12.2.1: " + patch_sha256
    need(re.findall(r"^  npm@12\.2\.1: [0-9a-f]{64}$", patch_section(new), re.M) == [new_line] and
        re.findall(r"^  npm@12\.2\.1: [0-9a-f]{64}$", new, re.M) == [new_line], "v9.vendor_lock_patch_registration")
    suffix = "(patch_hash=" + patch_sha256 + ")"
    old_suffix = "(patch_hash=" + old_hash[0] + ")" if old_hash else ""
    snapshot = "  npm@12.2.1" + suffix + ": {}"
    need(new.count(snapshot + "\n") == 1 and new.count(suffix) == 2,
        "v9.vendor_lock_exact_npm_references")
    importer = "      npm:\n        specifier: 12.2.1\n        version: 12.2.1" + suffix + "\n"
    need(new.count(importer) == 1, "v9.vendor_lock_root_npm_reference")
    new = new.replace(importer, importer.replace(suffix, old_suffix), 1)
    new = new.replace(snapshot, snapshot.replace(suffix, old_suffix), 1)
    if old_hash:
        new = new.replace(new_line + "\n", "  npm@12.2.1: " + old_hash[0] + "\n", 1)
    else:
        new = new.replace(new_line + "\n", "", 1)
    return new.encode()


def validate_qualification(value, record, need):
    """Validate the safe actual-package projection; never infer an image pass."""
    validate_record(record, need)
    need(type(value) is dict and set(value) == {"schema", "qualifierRuntimeSha256", "receiptSha256", "receipt", "controls"} and
        value["schema"] == "openclaw.v109.npm-vendor-qualification-evidence.v1" and
        pin(value["qualifierRuntimeSha256"]) and pin(value["receiptSha256"]), "v9.vendor_qualification_fields")
    receipt = value["receipt"]
    need(type(receipt) is dict and set(receipt) == {"schema", "status", "phase", "reason", "packageExecuted", "imageTested", "actualBunRuntimeTested", "proofSha256", "patchSha256", "originalSha256", "derivedSha256", "packageExecutionAttempted", "tests", "testResultEvidence"} and
        receipt["schema"] == "openclaw.npm-glob-vendor-qualification.v1" and receipt["status"] == "passed" and
        receipt["phase"] == "complete" and receipt["reason"] == "all_52_cases_passed" and
        receipt["packageExecuted"] is True and receipt["packageExecutionAttempted"] is True and
        receipt["imageTested"] is False and receipt["actualBunRuntimeTested"] is False and
        receipt["proofSha256"] == record["proofSha256"] and receipt["patchSha256"] == record["patchSha256"] and
        receipt["originalSha256"] == ORIGINAL_SHA256 and pin(receipt["derivedSha256"]), "v9.vendor_actual_qualification")
    need(digest((json.dumps(receipt, indent=2, ensure_ascii=False) + "\n").encode()) == value["receiptSha256"],
        "v9.vendor_qualification_receipt_hash")
    metadata = receipt["testResultEvidence"]
    need(type(metadata) is dict and set(metadata) == {"file", "bytes", "sha256", "storedBytes", "storedSha256", "truncated", "limitBytes"} and
        metadata["file"] == "npm-vendor-actual-test-result.private.json" and
        type(metadata["bytes"]) is int and 0 < metadata["bytes"] <= 131072 and
        type(metadata["storedBytes"]) is int and metadata["storedBytes"] == metadata["bytes"] and
        pin(metadata["sha256"]) and metadata["storedSha256"] == metadata["sha256"] and
        metadata["truncated"] is False and metadata["limitBytes"] == 131072, "v9.vendor_private_result_metadata")
    tests = receipt["tests"]
    need(type(tests) is dict and set(tests) == {"schema", "passed", "caseCount", "passedCount", "cases", "packageExecutionHost", "imageTested", "publicPackTested", "actualBunRuntimeTested"} and
        tests["schema"] == "openclaw.npm-vendor-actual-package-tests.v1" and tests["passed"] is True and
        type(tests["caseCount"]) is int and tests["caseCount"] == QUALIFICATION_CASE_COUNT and
        type(tests["passedCount"]) is int and tests["passedCount"] == QUALIFICATION_CASE_COUNT and
        tests["packageExecutionHost"] == "ci-only" and tests["imageTested"] is False and
        tests["publicPackTested"] is True and tests["actualBunRuntimeTested"] is False and
        type(tests["cases"]) is list and len(tests["cases"]) == QUALIFICATION_CASE_COUNT,
        "v9.vendor_actual_case_set")
    names = []
    for row in tests["cases"]:
        need(type(row) is dict and set(row) == {"name", "passed"} and type(row["name"]) is str and
            re.fullmatch(r"[A-Za-z0-9._:/ -]{1,180}", row["name"]) is not None and row["passed"] is True,
            "v9.vendor_actual_case")
        names.append(row["name"])
    need(len(set(names)) == QUALIFICATION_CASE_COUNT, "v9.vendor_unique_actual_cases")
    controls = value["controls"]
    need(type(controls) is list and len(controls) == len(CONTROL_TESTS), "v9.vendor_control_set")
    for row, (source, count) in zip(controls, CONTROL_TESTS):
        need(type(row) is dict and set(row) == {"path", "runtimeSha256", "receiptSha256", "caseCount", "passedCount", "exitCode", "timedOut", "cleanupSettled"} and
            row["path"] == source and pin(row["runtimeSha256"]) and pin(row["receiptSha256"]) and
            type(row["caseCount"]) is int and row["caseCount"] == count and type(row["passedCount"]) is int and
            row["passedCount"] == count and type(row["exitCode"]) is int and row["exitCode"] == 0 and
            row["timedOut"] is False and (row["cleanupSettled"] is None or row["cleanupSettled"] is True),
            "v9.vendor_control_result")
    return value


EXCEPTION_NAMES = frozenset(('Error', 'TypeError', 'SyntaxError', 'RangeError', 'ReferenceError', 'EvalError', 'URIError', 'AggregateError', 'AssertionError'))
EXCEPTION_CODES = frozenset(('ERR_MODULE_NOT_FOUND', 'ERR_PACKAGE_PATH_NOT_EXPORTED', 'ERR_REQUIRE_ESM', 'ERR_UNKNOWN_FILE_EXTENSION', 'ERR_INVALID_PACKAGE_CONFIG', 'ERR_INVALID_PACKAGE_TARGET', 'ERR_PACKAGE_IMPORT_NOT_DEFINED', 'ERR_UNSUPPORTED_DIR_IMPORT', 'ERR_INVALID_ARG_TYPE', 'ERR_INVALID_ARG_VALUE', 'ERR_INVALID_RETURN_VALUE', 'ERR_ASSERTION', 'ERR_BUFFER_TOO_LARGE', 'ERR_OUT_OF_RANGE', 'ERR_INVALID_URL', 'ERR_INVALID_FILE_URL_PATH', 'ERR_INVALID_FILE_URL_HOST', 'ERR_UNKNOWN_BUILTIN_MODULE', 'ABORT_ERR', 'ENOENT', 'EACCES', 'EPERM', 'EEXIST', 'ENOTDIR', 'EISDIR', 'ENOSPC', 'EROFS', 'EMFILE', 'ENFILE', 'EIO', 'ENAMETOOLONG', 'ELOOP', 'ETIMEDOUT'))
QUALIFIER_PHASES = frozenset(('proof', 'archive_authentication', 'owned_staging', 'actual_package_tests', 'complete'))
QUALIFIER_FAILURE_REASONS = frozenset(('npm-vendor.archive_bound', 'npm-vendor.archive_expansion', 'npm-vendor.archive_member', 'npm-vendor.archive_member_bound', 'npm-vendor.archive_member_size', 'npm-vendor.archive_unsettled', 'npm-vendor.change_binding', 'npm-vendor.change_count', 'npm-vendor.compiler_binding', 'npm-vendor.derived_archive_identity', 'npm-vendor.derived_archive_inventory', 'npm-vendor.derived_binding', 'npm-vendor.installed_inventory', 'npm-vendor.installed_link', 'npm-vendor.installed_type', 'npm-vendor.inventory_count', 'npm-vendor.inventory_mode', 'npm-vendor.inventory_row', 'npm-vendor.map_binding', 'npm-vendor.map_count', 'npm-vendor.original_archive_identity', 'npm-vendor.original_archive_inventory', 'npm-vendor.original_binding', 'npm-vendor.pack_bound', 'npm-vendor.pack_bytes', 'npm-vendor.package_assertion_shape', 'npm-vendor.package_case_shape', 'npm-vendor.package_test_conclusion', 'npm-vendor.package_test_shape', 'npm-vendor.patch_binding', 'npm-vendor.patch_bytes', 'npm-vendor.path', 'npm-vendor.proof_bytes', 'npm-vendor.proof_identity', 'npm-vendor.proof_json', 'npm-vendor.proof_noncanonical', 'npm-vendor.qualification_arguments', 'npm-vendor.qualification_ci_only', 'npm-vendor.qualification_evidence_input', 'npm-vendor.qualification_evidence_short_write', 'npm-vendor.qualification_input_bound', 'npm-vendor.qualification_package_tests_failed', 'npm-vendor.qualification_patch', 'npm-vendor.qualification_path', 'npm-vendor.qualification_receipt_bound', 'npm-vendor.qualification_receipt_path', 'npm-vendor.qualification_repo', 'npm-vendor.qualification_result_truncated', 'npm-vendor.qualification_test_interface', 'npm-vendor.repair_binding', 'npm-vendor.root', 'qualification_failed'))


def exception_cause(value, need):
    """A fixed tagged envelope; unknown exception properties are never echoed."""
    need(type(value) is dict and set(value) == {"name", "code"}, "v9.vendor_exception_cause_fields")
    result = {}
    for field, allowed in (("name", EXCEPTION_NAMES), ("code", EXCEPTION_CODES)):
        tag = value[field]
        need(type(tag) is dict and type(tag.get("state")) is str, "v9.vendor_exception_cause_tag")
        if tag["state"] == "recognized":
            need(set(tag) == {"state", "value"} and type(tag["value"]) is str and tag["value"] in allowed,
                "v9.vendor_exception_cause_value")
        else:
            need(set(tag) == {"state"} and tag["state"] in ("absent", "unrecognized"),
                "v9.vendor_exception_cause_state")
        result[field] = dict(tag)
    return result


def failed_qualification_projection(raw, need):
    """Project only finite observed cause codes; this never admits a result."""
    value = strict_json(raw, need, 65536)
    required = {"schema", "status", "phase", "reason", "packageExecuted", "imageTested", "actualBunRuntimeTested"}
    allowed = required | {"proofSha256", "patchSha256", "originalSha256", "derivedSha256", "packageExecutionAttempted",
        "tests", "testResultEvidence", "errorEvidence", "exceptionEvidence", "exceptionCause"}
    need(type(value) is dict and required <= set(value) <= allowed and
        value["schema"] == "openclaw.npm-glob-vendor-qualification.v1" and value["status"] == "failed" and
        type(value["phase"]) is str and value["phase"] in QUALIFIER_PHASES and
        type(value["reason"]) is str and
        (type(value["packageExecuted"]) is bool or value["packageExecuted"] == "unknown") and
        value["imageTested"] is False and value["actualBunRuntimeTested"] is False,
        "v9.vendor_failure_envelope")
    reason = ({"state": "recognized", "value": value["reason"]} if value["reason"] in QUALIFIER_FAILURE_REASONS
        else {"state": "unrecognized"})
    present = "exceptionCause" in value
    cause = exception_cause(value["exceptionCause"], need) if present else None
    return {"schema": "openclaw.v109.npm-vendor-failure-diagnostic.v1", "status": "refused",
        "diagnosticState": "observed", "phase": value["phase"], "reason": reason,
        "exceptionCausePresent": present, **({"exceptionCause": cause} if present else {}),
        "rawReceiptBytes": len(raw), "rawReceiptSha256": digest(raw),
        "packageTests": failed_package_test_details(value),
        "qualificationAccepted": False, "imageBuilt": False, "productionAuthorized": False}


ASSERTION_OPERATORS = frozenset(("strictEqual", "notStrictEqual", "deepStrictEqual", "notDeepStrictEqual", "equal", "notEqual", "deepEqual", "notDeepEqual", "ok", "match", "doesNotMatch", "throws", "doesNotThrow", "rejects", "doesNotReject", "fail", "ifError", "==", "!=", "===", "!==", ">", "<", ">=", "<=", "unavailable"))
PACKAGE_CASE_NAMES = tuple(name + suffix for name in ("cjs-normal", "cjs-raw", "esm-normal", "esm-raw")
    for suffix in (".positive", ".original-positive-parity", ".async.pre-abort", ".async.mid-abort", ".sync.pre-abort", ".sync.mid-abort", ".stream.pre-abort", ".stream.mid-abort", ".stream-sync.pre-abort", ".stream-sync.mid-abort", ".pause.async", ".pause.sync")) + (
    "original-regression-positive-control", "actual-npm-consumers", "actual-public-pack-delivery", "actual-offline-global-delivery")


def failed_package_test_details(receipt):
    """Only fixed source case identities and finite assertion numbers survive."""
    if "tests" not in receipt:
        return {"state": "missing"}
    tests = receipt["tests"]
    if type(tests) is not dict:
        return {"state": "invalid", "reason": "tests_type"}
    fields = {"schema", "passed", "caseCount", "passedCount", "cases", "packageExecutionHost", "imageTested", "publicPackTested", "actualBunRuntimeTested"}
    if set(tests) != fields or tests.get("schema") != "openclaw.npm-vendor-actual-package-tests.v1" or type(tests.get("passed")) is not bool or tests.get("packageExecutionHost") != "ci-only" or tests.get("imageTested") is not False or tests.get("actualBunRuntimeTested") is not False or tests.get("publicPackTested") is not tests.get("passed"):
        return {"state": "invalid", "reason": "tests_shape"}
    count, passed = tests.get("caseCount"), tests.get("passedCount")
    if type(count) is not int or count != QUALIFICATION_CASE_COUNT or type(passed) is not int or not 0 <= passed <= count:
        return {"state": "invalid", "reason": "counter_shape"}
    counters = {"caseCount": count, "passedCount": passed, "failedCount": count - passed}
    def invalid(reason, index=None):
        return {"state": "invalid", "reason": reason, "reportedCounters": counters,
            **({"invalidCaseIndex": index} if index is not None else {})}
    cases = tests.get("cases")
    if type(cases) is not list or len(cases) != count:
        return invalid("case_count")
    failures, observed_passed = [], 0
    for index, (row, name) in enumerate(zip(cases, PACKAGE_CASE_NAMES), 1):
        if type(row) is not dict or row.get("name") != name or type(row.get("passed")) is not bool:
            return invalid("case_identity", index)
        if row["passed"]:
            if set(row) != {"name", "passed"}: return invalid("passed_case_shape", index)
            observed_passed += 1
            continue
        if set(row) != {"name", "passed", "code", "assertion"}:
            return invalid("failed_case_shape", index)
        assertion = row["assertion"]
        if type(assertion) is not dict or not {"operator"} <= set(assertion) <= {"operator", "actual", "expected"} or type(assertion.get("operator")) is not str or assertion["operator"] not in ASSERTION_OPERATORS:
            return invalid("assertion_shape", index)
        safe_assertion = {"operator": assertion["operator"]}
        for field in ("actual", "expected"):
            if field not in assertion: continue
            number = assertion[field]
            try: finite = type(number) in (int, float) and math.isfinite(number)
            except (OverflowError, ValueError, TypeError): finite = False
            if not finite: return invalid("assertion_number", index)
            safe_assertion[field] = number
        code = row["code"]
        safe_code = ({"state": "recognized", "value": code} if type(code) is str and code in EXCEPTION_CODES | {"assertion_failed", "case_failed"} else {"state": "unrecognized"})
        failures.append({"index": index, "name": name, "code": safe_code, "assertion": safe_assertion})
    if observed_passed != passed or tests["passed"] is not (passed == count):
        return invalid("case_counter_mismatch")
    return {"state": "available", "counters": counters, "failedCases": failures}


def control_footer_projection(index, returncode, timed_out, raw=None, capture_state="missing"):
    """Footer counters/indices only: never raw TAP, test names or messages."""
    if type(index) is not int or not 0 <= index < len(CONTROL_TESTS):
        raise ValueError("v9.vendor_control_diagnostic_index")
    script, expected = CONTROL_TESTS[index]
    exit_code = returncode if type(returncode) is int and -255 <= returncode <= 255 else None
    timeout = timed_out if type(timed_out) is bool else None
    base = {"schema": "openclaw.v109.npm-vendor-control-footer.v1", "controlIndex": index, "script": script,
        "exitCode": exit_code, "timedOut": timeout, "expectedCaseCount": expected,
        "qualificationAccepted": False, "imageBuilt": False, "productionAuthorized": False}
    def result(state, reason=None, **details):
        return {**base, "footer": {"state": state, **({"reason": reason} if reason else {}), **details}}
    if capture_state != "available" or type(raw) is not bytes:
        reason = capture_state if capture_state in ("missing", "incomplete", "unavailable") else "unavailable"
        return result("unavailable", reason)
    try: text = raw.decode("utf8")
    except UnicodeError: return result("invalid", "tap_utf8")
    if not text.startswith("TAP version 13\n"):
        return result("invalid", "tap_header")
    counts = {}
    for key in ("tests", "pass", "fail", "cancelled", "skipped", "todo"):
        values = re.findall(r"^# " + key + r" ([0-9]+)$", text, re.M)
        if len(values) != 1 or len(values[0]) > 5 or int(values[0]) > 10000:
            return result("invalid", "counter_fields")
        counts[key] = int(values[0])
    if counts["tests"] != sum(counts[key] for key in ("pass", "fail", "cancelled", "skipped", "todo")):
        return result("invalid", "counter_sum")
    indices = [int(value) for value in re.findall(r"^not ok ([1-9][0-9]{0,4})(?=\s|$)", text, re.M)]
    if len(indices) != len(set(indices)) or any(value > counts["tests"] for value in indices):
        return result("invalid", "case_indices")
    return result("available", counters=counts, notOkIndices=indices)
