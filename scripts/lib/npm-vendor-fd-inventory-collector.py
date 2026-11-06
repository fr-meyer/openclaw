"""Private data-only successor; JS proof owner supplies already validated facts.

No proof/SRI policy lives here. No package, shell, network or child execution.
The operational stdin client is Linux-only and has no fallback transport.
"""
import hashlib
import base64
import ctypes
import errno
import json
import os
import resource
import stat
import sys
import time

LIMITS = {"entries": 5000, "readBytes": 32 * 1024 * 1024,
          "fileBytes": 8 * 1024 * 1024, "directories": 512,
          "depth": 64, "relativeNameBytes": 4096, "differences": 128, "outputBytes": 64 * 1024, "elapsedMs": 30000}
MAX_INPUT = 1024 * 1024
PROOF_PARTS = ("patches", "npm-12.2.1.glob-cancellation.proof.json")
SELECTOR_CAP = 4096


class Refused(Exception):
    pass


def _identity(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def _parts(value, absolute=False):
    if not isinstance(value, str) or len(value) > 4096 or "\0" in value or "\\" in value:
        raise Refused("path_refused")
    if absolute:
        if not value.startswith("/") or value == "/":
            raise Refused("path_refused")
        value = value[1:]
    elif value.startswith("/"):
        raise Refused("path_refused")
    parts = value.split("/")
    if any(not p or p in (".", "..") for p in parts):
        raise Refused("path_refused")
    return parts


def _require_client(linux=True):
    if (linux and sys.platform != "linux") or sys.version_info < (3, 9):
        raise Refused("unsupported_client")
    required = ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK")
    if any(not hasattr(os, name) for name in required):
        raise Refused("unsupported_fd_api")
    if os.open not in os.supports_dir_fd or os.stat not in os.supports_dir_fd or os.scandir not in os.supports_fd:
        raise Refused("unsupported_fd_api")
    soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    if linux and soft != resource.RLIM_INFINITY and soft < 1024:
        raise Refused("unsupported_fd_budget")


DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
FILE_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)


def _open_child_directory(parent, name):
    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if not stat.S_ISDIR(before.st_mode):
        raise Refused("directory_type_refused")
    fd = os.open(name, DIR_FLAGS, dir_fd=parent)
    if _identity(before) != _identity(os.fstat(fd)):
        os.close(fd)
        raise Refused("unstable_input")
    return fd


def _open_absolute_directory(value):
    parts = _parts(value, absolute=True)
    fd = os.open("/", DIR_FLAGS)
    try:
        for name in parts:
            child = _open_child_directory(fd, name)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _open_relative_directory(parent, value):
    parts = _parts(value)
    if parts[0] != "node_modules" or parts[-1] != "npm":
        raise Refused("package_scope_refused")
    fd = os.dup(parent)
    try:
        for name in parts:
            child = _open_child_directory(fd, name)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _binding(fd, expected):
    if not isinstance(expected, dict) or set(expected) != {"device", "inode"}:
        raise Refused("identity_binding_refused")
    s = os.fstat(fd)
    if str(s.st_dev) != expected["device"] or str(s.st_ino) != expected["inode"]:
        raise Refused("identity_binding_refused")


def _name_hash(name):
    return hashlib.sha256(name.encode("utf-8", "surrogateescape")).hexdigest()


def compare(facts, observations, complete, limits):
    expected = {r["path"]: r for r in facts["files"]}
    counts = dict.fromkeys(("missing", "extra", "type", "mode", "size", "content", "links"), 0)
    rows, seen = [], set()
    for actual in observations:
        name = actual["path"]
        seen.add(name)
        before = expected.get(name)
        if before is None:
            counts["extra"] += 1
            counts["links"] += actual["kind"] == "link"
            rows.append({"kind": "extra", "pathSha256": _name_hash(name), "actual": {
                "kind": actual["kind"], "mode": actual["mode"], "size": actual["size"], "contentRead": False}})
            continue
        changes = []
        if actual["kind"] != "file":
            counts["type"] += 1
            changes.append("type")
            if actual["kind"] == "link":
                counts["links"] += 1
                changes.append("link")
        if actual["mode"] != before["mode"]:
            counts["mode"] += 1
            changes.append("mode")
        if actual["kind"] == "file":
            for key, category in (("size", "size"), ("sha256", "content")):
                if actual[key] != before[key]:
                    counts[category] += 1
                    changes.append(category)
        if changes:
            safe_actual = {k: actual[k] for k in ("kind", "mode", "size")}
            if actual["kind"] == "file":
                safe_actual["sha256"] = actual["sha256"]
            rows.append({"kind": "changed", "path": before["path"], "changes": changes,
                         "expected": {"kind": "file", **{k: before[k] for k in ("mode", "size", "sha256")}}, "actual": safe_actual})
    if complete:
        for before in facts["files"]:
            if before["path"] not in seen:
                counts["missing"] += 1
                rows.append({"kind": "missing", "path": before["path"], "expected": {
                    "kind": "file", **{k: before[k] for k in ("mode", "size", "sha256")}}})
    rows.sort(key=lambda r: r.get("path", r.get("pathSha256", "")))
    return {"counts": counts, "countsComplete": complete, "differenceCount": len(rows),
            "differences": rows[:limits["differences"]], "differencesTruncated": len(rows) > limits["differences"]}


def collect_fd_inventory(payload, limits=None, held=None, metadata_bytes=0, proof_bytes=0, selector_bytes=0, selector_link=False):
    """Core accepts prebound facts, not proof authority. Private tests use small limits."""
    limits = LIMITS if limits is None else limits
    started = time.monotonic()
    facts = payload["facts"]
    expected = {r["path"]: r for r in facts["files"]}
    prefixes = {"/".join(name.split("/")[:i]) for name in expected for i in range(1, len(name.split("/")))}
    report = {"schema": "openclaw.npm-vendor-fd-inventory-diagnostic.v2", "status": "refused", "reason": "not_completed",
              "qualificationAccepted": False, "imageBuilt": False, "complete": False,
              "proofSha256": facts["proofSha256"], "expectedInventorySha256": facts["expectedInventorySha256"],
              "observed": {"entries": 0, "expectedFilesRead": 0, "bytes": metadata_bytes, "verificationEntries": 0, "proofMetadataBytes": proof_bytes, "selectorMetadataBytes": selector_bytes},
              "privacy": {"unknownNamesHashed": True, "unknownContentsRead": False, "unknownLinkTargetsRead": False, "declaredNpmSelectorTargetMetadataRead": selector_link},
              "limits": limits, "deadlineKind": "cooperative_30s_requires_outer_whole_call_deadline"}
    progress = report["observed"]
    fds, directories, nodes, observations = [], [], [], []

    def budget():
        if (time.monotonic() - started) * 1000 >= limits["elapsedMs"]:
            raise Refused("elapsed_cap")

    def hold(fd):
        if len(fds) >= limits["directories"]:
            os.close(fd)
            raise Refused("fd_cap")
        fds.append(fd)
        return fd

    def walk(fd, prefix):
        budget()
        if prefix.count("/") + bool(prefix) > limits["depth"]:
            raise Refused("depth_cap")
        before = os.fstat(fd)
        names = set()
        directories.append((fd, _identity(before), names))
        with os.scandir(fd) as iterator:
            while True:
                budget()
                # Refuse before asking for an additional name; never materialize a directory.
                if progress["entries"] >= limits["entries"]:
                    raise Refused("entry_cap")
                try:
                    entry = next(iterator)
                except StopIteration:
                    break
                progress["entries"] += 1
                name = entry.name
                names.add(name)
                relative = prefix + "/" + name if prefix else name
                if len(relative.encode("utf-8", "surrogateescape")) > limits["relativeNameBytes"]:
                    raise Refused("relative_name_cap")
                s = os.stat(name, dir_fd=fd, follow_symlinks=False)
                nodes.append((fd, name, _identity(s)))
                actual = {"path": relative, "mode": stat.S_IMODE(s.st_mode), "size": s.st_size}
                if stat.S_ISDIR(s.st_mode):
                    if relative not in prefixes:
                        observations.append({**actual, "kind": "directory"})
                    walk(hold(_open_child_directory(fd, name)), relative)
                    continue
                kind = "link" if stat.S_ISLNK(s.st_mode) else "file" if stat.S_ISREG(s.st_mode) else "other"
                if kind != "file" or relative not in expected:
                    observations.append({**actual, "kind": kind})
                    continue  # Never open unknown contents or link targets.
                if s.st_size < 0 or s.st_size > limits["fileBytes"]:
                    raise Refused("file_cap")
                if s.st_size > limits["readBytes"] - progress["bytes"]:
                    raise Refused("read_cap")
                opened = os.open(name, FILE_FLAGS, dir_fd=fd)
                try:
                    if _identity(s) != _identity(os.fstat(opened)):
                        raise Refused("unstable_input")
                    remaining, digest = s.st_size, hashlib.sha256()
                    while remaining:
                        budget()
                        allowed = min(65536, remaining, limits["fileBytes"], limits["readBytes"] - progress["bytes"])
                        if allowed <= 0:
                            raise Refused("read_cap")
                        chunk = os.read(opened, allowed)
                        if not chunk:
                            raise Refused("unstable_input")
                        progress["bytes"] += len(chunk)
                        remaining -= len(chunk)
                        digest.update(chunk)
                    # No EOF probe after the initial bound length is consumed.
                    if _identity(s) != _identity(os.fstat(opened)):
                        raise Refused("unstable_input")
                    progress["expectedFilesRead"] += 1
                    observations.append({**actual, "kind": "file", "sha256": digest.hexdigest()})
                finally:
                    os.close(opened)

    try:
        _require_client(linux=False)
        source = hold(os.dup(held[0]) if held else _open_absolute_directory(payload["sourceRoot"]))
        _binding(source, payload["sourceIdentity"])
        root = hold(os.dup(held[1]) if held else _open_relative_directory(source, payload["npmRelativeRoot"]))
        _binding(root, payload["npmIdentity"])
        walk(root, "")
        for fd, name, before in nodes:
            budget()
            if before != _identity(os.stat(name, dir_fd=fd, follow_symlinks=False)):
                raise Refused("unstable_input")
        for fd, before, names in directories:
            budget()
            if before != _identity(os.fstat(fd)):
                raise Refused("unstable_input")
            seen = set()
            with os.scandir(fd) as iterator:
                while True:
                    budget()
                    if progress["verificationEntries"] >= limits["entries"]:
                        raise Refused("verification_entry_cap")
                    try:
                        entry = next(iterator)
                    except StopIteration:
                        break
                    progress["verificationEntries"] += 1
                    if entry.name not in names:
                        raise Refused("unstable_input")
                    seen.add(entry.name)
            if seen != names:
                raise Refused("unstable_input")
        report.update(compare(facts, observations, True, limits))
        report["complete"] = not report["differencesTruncated"]
        report["status"] = "refused" if report["differencesTruncated"] else "observed"
        report["reason"] = "difference_cap" if report["differencesTruncated"] else "differences_observed" if report["differenceCount"] else "no_difference_observed"
    except (Refused, OSError) as error:
        report["reason"] = str(error) if isinstance(error, Refused) else "io_or_nofollow_refused"
        report["countsComplete"] = False
        report["complete"] = False
    finally:
        for fd in reversed(fds):
            os.close(fd)
    if (time.monotonic() - started) * 1000 >= limits["elapsedMs"]:
        report.update(status="refused", reason="elapsed_cap", complete=False, countsComplete=False)
    encoded = json.dumps(report, separators=(",", ":"), allow_nan=False).encode()
    if len(encoded) > limits["outputBytes"]:
        report.update(status="refused", reason="output_cap", complete=False, countsComplete=False, differences=[])
    return report


def _binding_value(fd):
    s = os.fstat(fd)
    return {"device": str(s.st_dev), "inode": str(s.st_ino)}


def _wire_identity(s):
    return [str(v) for v in _identity(s)]


def _read_source_proof(source):
    directory = _open_child_directory(source, PROOF_PARTS[0])
    opened = None
    try:
        before = os.stat(PROOF_PARTS[1], dir_fd=directory, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_INPUT:
            raise Refused("proof_file_refused")
        opened = os.open(PROOF_PARTS[1], FILE_FLAGS, dir_fd=directory)
        if _identity(before) != _identity(os.fstat(opened)):
            raise Refused("proof_unstable")
        left, chunks = before.st_size, []
        while left:
            chunk = os.read(opened, min(65536, left))
            if not chunk:
                raise Refused("proof_unstable")
            left -= len(chunk)
            chunks.append(chunk)
        if _identity(before) != _identity(os.fstat(opened)) or _identity(before) != _identity(os.stat(PROOF_PARTS[1], dir_fd=directory, follow_symlinks=False)):
            raise Refused("proof_unstable")
        data = b"".join(chunks)
        return data, {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "identity": _wire_identity(before)}
    finally:
        if opened is not None:
            os.close(opened)
        os.close(directory)


def _bounded_declared_npm_readlink(directory):
    # The only native call is fixed Linux readlinkat(fd, "npm", buffer, 4096).
    # No caller-selected library/symbol/path, no fallback and no target-file read.
    if type(directory) is not int or directory < 0:
        raise Refused("selector_fd_refused")
    try:
        function = ctypes.CDLL(None, use_errno=True).readlinkat
        function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.POINTER(ctypes.c_char), ctypes.c_size_t]
        function.restype = ctypes.c_ssize_t
    except (AttributeError, OSError):
        raise Refused("unsupported_readlinkat")
    buffer = ctypes.create_string_buffer(SELECTOR_CAP)
    try:
        length = function(directory, b"npm", buffer, SELECTOR_CAP)
    except (ctypes.ArgumentError, TypeError, ValueError):
        raise Refused("unsupported_readlinkat")
    if type(length) is not int:
        raise Refused("unsupported_readlinkat")
    if length < 0:
        code = {errno.ENOENT: "selector_enoent", errno.EACCES: "selector_eacces", errno.EPERM: "selector_eperm", errno.EINVAL: "selector_einval", errno.ENOTDIR: "selector_enotdir", errno.ELOOP: "selector_eloop"}.get(ctypes.get_errno(), "selector_read_refused")
        raise Refused(code)
    if length >= SELECTOR_CAP:
        raise Refused("selector_target_cap")
    return bytes(buffer.raw[:length])


def _select_declared_npm(source):
    directory = _open_child_directory(source, "node_modules")
    opened = None
    try:
        before = os.stat("npm", dir_fd=directory, follow_symlinks=False)
        target_bytes, link = 0, stat.S_ISLNK(before.st_mode)
        if link:
            if not 0 < before.st_size < SELECTOR_CAP:
                raise Refused("selector_target_cap")
            raw = _bounded_declared_npm_readlink(directory)
            target_bytes = len(raw)
            if _identity(before) != _identity(os.stat("npm", dir_fd=directory, follow_symlinks=False)):
                raise Refused("selector_unstable")
            parts = _parts(os.fsdecode(raw))
            if parts[-1] != "npm":
                raise Refused("selector_target_refused")
            opened = os.dup(directory)
            for name in parts:
                child = _open_child_directory(opened, name)
                os.close(opened)
                opened = child
        elif stat.S_ISDIR(before.st_mode):
            opened = _open_child_directory(directory, "npm")
        else:
            raise Refused("declared_npm_type_refused")
        return directory, opened, _identity(before), target_bytes, link
    except BaseException:
        if opened is not None:
            os.close(opened)
        os.close(directory)
        raise


def read_proof_mode(payload):
    if not isinstance(payload, dict) or set(payload) != {"sourceRoot"}:
        raise Refused("input_shape")
    source = _open_absolute_directory(payload["sourceRoot"])
    try:
        data, proof = _read_source_proof(source)
        return {"schema": "openclaw.npm-vendor-proof-read.v1", "status": "observed", "sourceIdentity": _binding_value(source), "sourceSnapshot": _wire_identity(os.fstat(source)), "proof": proof, "proofBase64": base64.b64encode(data).decode("ascii")}
    finally:
        os.close(source)


def scan_selected_mode(payload):
    if not isinstance(payload, dict) or set(payload) != {"schema", "sourceRoot", "sourceIdentity", "sourceSnapshot", "proof", "facts"} or payload["schema"] != "openclaw.npm-vendor-selected-input.v1":
        raise Refused("input_shape")
    # Structural wire bounds only; proof semantics stay exclusively in the JS owner.
    _validate_payload({"schema": "openclaw.npm-vendor-fd-input.v1", "sourceRoot": payload["sourceRoot"], "npmRelativeRoot": "node_modules/npm", "sourceIdentity": payload["sourceIdentity"], "npmIdentity": payload["sourceIdentity"], "facts": payload["facts"]})
    source = _open_absolute_directory(payload["sourceRoot"])
    directory = opened = None
    try:
        _binding(source, payload["sourceIdentity"])
        if _wire_identity(os.fstat(source)) != payload["sourceSnapshot"]:
            raise Refused("source_unstable")
        data, proof = _read_source_proof(source)
        if proof != payload["proof"] or proof["sha256"] != payload["facts"]["proofSha256"]:
            raise Refused("proof_binding_refused")
        directory, opened, declared, target_bytes, link = _select_declared_npm(source)
        private_payload = {"sourceRoot": payload["sourceRoot"], "npmRelativeRoot": "node_modules/npm", "sourceIdentity": _binding_value(source), "npmIdentity": _binding_value(opened), "facts": payload["facts"]}
        report = collect_fd_inventory(private_payload, held=(source, opened), metadata_bytes=2 * len(data) + target_bytes, proof_bytes=2 * len(data), selector_bytes=target_bytes, selector_link=link)
        if declared != _identity(os.stat("npm", dir_fd=directory, follow_symlinks=False)) or _wire_identity(os.fstat(source)) != payload["sourceSnapshot"]:
            raise Refused("selector_unstable")
        proof_directory = _open_child_directory(source, PROOF_PARTS[0])
        try:
            if proof["identity"] != _wire_identity(os.stat(PROOF_PARTS[1], dir_fd=proof_directory, follow_symlinks=False)):
                raise Refused("proof_unstable")
        finally:
            os.close(proof_directory)
        return report
    finally:
        if opened is not None:
            os.close(opened)
        if directory is not None:
            os.close(directory)
        os.close(source)


def _json_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise Refused("duplicate_json_key")
        value[key] = item
    return value


def _validate_payload(p):
    if not isinstance(p, dict) or set(p) != {"schema", "sourceRoot", "npmRelativeRoot", "sourceIdentity", "npmIdentity", "facts"} or p["schema"] != "openclaw.npm-vendor-fd-input.v1":
        raise Refused("input_shape")
    _parts(p["sourceRoot"], absolute=True)
    _parts(p["npmRelativeRoot"])
    facts = p["facts"]
    if not isinstance(facts, dict) or set(facts) != {"proofSha256", "expectedInventorySha256", "files"} or not isinstance(facts["files"], list) or len(facts["files"]) != 1942:
        raise Refused("facts_shape")
    for digest in (facts["proofSha256"], facts["expectedInventorySha256"]):
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise Refused("facts_shape")
    seen = set()
    for row in facts["files"]:
        if not isinstance(row, dict) or set(row) != {"path", "mode", "size", "sha256"}:
            raise Refused("facts_shape")
        _parts(row["path"])
        if row["path"] in seen or row["mode"] not in (0o644, 0o755) or type(row["size"]) is not int or not 0 <= row["size"] <= LIMITS["fileBytes"] or not isinstance(row["sha256"], str) or len(row["sha256"]) != 64 or any(c not in "0123456789abcdef" for c in row["sha256"]):
            raise Refused("facts_shape")
        seen.add(row["path"])


def main():
    mode = sys.argv[1:]
    try:
        if mode not in (["--read-proof-v1"], ["--selected-facts-v1"]):
            raise Refused("arguments")
        _require_client(linux=True)
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            raise Refused("input_cap")
        payload = json.loads(raw, object_pairs_hook=_json_object, parse_constant=lambda _: (_ for _ in ()).throw(Refused("json_constant")))
        report = read_proof_mode(payload) if mode == ["--read-proof-v1"] else scan_selected_mode(payload)
    except BaseException as error:
        reason = str(error) if isinstance(error, Refused) else "client_refused"
        report = {"schema": "openclaw.npm-vendor-fd-inventory-diagnostic.v2", "status": "refused", "reason": reason, "qualificationAccepted": False, "imageBuilt": False, "complete": False}
    encoded = json.dumps(report, separators=(",", ":"), allow_nan=False)
    limit = 2 * MAX_INPUT if mode == ["--read-proof-v1"] else LIMITS["outputBytes"]
    if len(encoded.encode()) > limit:
        report = {"schema": "openclaw.npm-vendor-fd-inventory-diagnostic.v2", "status": "refused", "reason": "output_cap", "qualificationAccepted": False, "imageBuilt": False, "complete": False}
        encoded = json.dumps(report, separators=(",", ":"))
    print(encoded)
    return 0 if report["status"] == "observed" else 2


if __name__ == "__main__":
    sys.exit(main())
