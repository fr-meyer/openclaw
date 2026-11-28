"""Bounded metadata-only explanation of an already-refused source-cleanliness gate.

No subprocess, network, source write or acceptance decision lives here. The caller
supplies its fixed local Git reader, actual observations and existing deadline.
Only paths in the bound commit's tree can be returned. Contents and raw Git
streams are never returned, even when parsing fails.
"""
import hashlib
import json
import os
import re
import stat
import time

SCHEMA = "openclaw.v109.profile-cleanliness-diagnostic.v1"
MAX_PATHS = 32
MAX_REPORT = 32 * 1024
MAX_HASH_BYTES = 64 * 1024 * 1024
MAX_METADATA = 8 * 1024 * 1024
MAX_FILE = 8 * 1024 * 1024
MODES = frozenset(("100644", "100755", "120000", "160000"))
OID = re.compile(r"[0-9a-f]{40}")
PROFILES = frozenset(("dependency", "types-production", "types-tests", "types-scripts",
    "workboard-1", "workboard-2", "models-1", "models-2", "sqlite", "doctor-1",
    "doctor-2", "doctor-3", "memory", "pipeline-contracts", "compatibility"))
# Fixed two-character porcelain codes only. Unsupported combinations still do
# not authorize anything: this diagnostic is emitted only after a refused gate.
STATUS_CODES = frozenset(a + b for a in " MADRCUT" for b in " MADRCUT" if a + b != "  ")
ISSUE_CODES = frozenset(("path_encoding", "deadline", "hash_cap", "response_type", "metadata_cap",
    "nul_termination", "nul_empty_record", "tree_format", "tree_identity", "status_format", "status_code",
    "rename_record", "duplicate_status_path", "index_format", "index_identity", "duplicate_index_stage",
    "blob_size", "blob_response", "worktree_race", "source_context", "run_context", "observed_identity",
    "gate_read_unavailable", "bound_tree_identity", "path_cap", "report_cap", "path_unavailable",
    "diagnostic_unavailable"))


class Unavailable(Exception):
    """Only fixed internal codes cross the diagnostic boundary."""


def require(value, code):
    if not value:
        raise Unavailable(code)


def issue(error):
    return str(error) if str(error) in ISSUE_CODES else "diagnostic_unavailable"


def safe_path(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 512, "path_encoding")
    require(re.fullmatch(rb"[A-Za-z0-9_.@+ /,\[\]-]+", raw) is not None and
        all(p not in (b"", b".", b"..") for p in raw.split(b"/")), "path_encoding")
    return raw.decode("ascii")


class Budget:
    def __init__(self, deadline, clock):
        self.deadline, self.clock, self.hashed = deadline, clock, 0

    def check(self):
        require(self.clock() < self.deadline, "deadline")

    def hash(self, raw):
        self.check()
        require(type(raw) is bytes and len(raw) <= MAX_HASH_BYTES - self.hashed, "hash_cap")
        self.hashed += len(raw)
        return hashlib.sha256(raw).hexdigest()


def raw_fact(raw, budget):
    """Hash a bounded prefix BEFORE parsing/cap adjudication; never return bytes."""
    require(type(raw) is bytes, "response_type")
    count = min(len(raw), MAX_METADATA, MAX_HASH_BYTES - budget.hashed)
    digest = budget.hash(raw[:count])
    return {"observedBytes": len(raw), "hashedPrefixBytes": count,
        "prefixSha256": digest, "completeHash": count == len(raw), "payloadRetained": False}


def metadata(raw, budget, evidence, name):
    evidence[name] = raw_fact(raw, budget)
    require(len(raw) <= MAX_METADATA and evidence[name]["completeHash"], "metadata_cap")
    return raw


def nul_rows(raw):
    require(raw == b"" or raw.endswith(b"\0"), "nul_termination")
    rows = raw.split(b"\0")[:-1] if raw else []
    require(all(rows), "nul_empty_record")
    return rows


def tree_entries(raw):
    result = {}
    for row in nul_rows(raw):
        prefix, sep, path = row.partition(b"\t")
        fields = prefix.split(b" ")
        require(sep and len(fields) == 3, "tree_format")
        mode, kind, oid = (v.decode("ascii") for v in fields)
        # Unsafe path spellings are never emitted, even if tracked. Refuse this
        # diagnostic rather than silently accepting an ambiguous path set.
        name = safe_path(path)
        require(mode in MODES and kind == ("commit" if mode == "160000" else "blob") and
            OID.fullmatch(oid) and name not in result, "tree_identity")
        result[name] = {"mode": mode, "gitOid": oid, "objectType": kind}
    return result


def status_entries(raw, known):
    rows, result, unknown = nul_rows(raw), {}, 0
    position = 0
    while position < len(rows):
        row = rows[position]
        position += 1
        require(len(row) >= 4 and row[2:3] == b" ", "status_format")
        code = row[:2].decode("ascii")
        require(code in STATUS_CODES, "status_code")
        paths = [(row[3:], "path")]
        if "R" in code or "C" in code:
            require(position < len(rows), "rename_record")
            paths[0] = (paths[0][0], "destination")
            paths.append((rows[position], "origin"))
            position += 1
        for raw_path, role in paths:
            name = safe_path(raw_path)
            if name not in known:
                unknown += 1
                continue
            require(name not in result, "duplicate_status_path")
            result[name] = {"statusCode": code, "pathRole": role}
    return result, unknown


def index_entries(raw):
    result = {}
    for row in nul_rows(raw):
        prefix, sep, raw_path = row.partition(b"\t")
        fields = prefix.split(b" ")
        require(sep and len(fields) == 3, "index_format")
        mode, oid, stage = (v.decode("ascii") for v in fields)
        name = safe_path(raw_path)
        require(mode in MODES and OID.fullmatch(oid) and stage in ("0", "1", "2", "3"), "index_identity")
        entries = result.setdefault(name, [])
        require(not any(e["stage"] == int(stage) for e in entries), "duplicate_index_stage")
        entries.append({"mode": mode, "gitOid": oid, "stage": int(stage)})
    return result


def before_identity(entry, read, budget, evidence, name):
    value = dict(entry, sha256=None, availability="git_identity_only")
    if entry["objectType"] != "blob":
        return value
    size_raw = metadata(read("cat-file", "-s", entry["gitOid"]), budget, evidence, name + ".size")
    require(re.fullmatch(rb"(?:0|[1-9][0-9]*)\n?", size_raw) is not None, "blob_size")
    size = int(size_raw)
    value["bytes"] = size
    if size > min(MAX_FILE, MAX_HASH_BYTES - budget.hashed):
        value["availability"] = "content_cap"
        return value
    raw = read("cat-file", "blob", entry["gitOid"])
    # Hash the bounded response before checking actual-vs-announced size.
    fact = raw_fact(raw, budget)
    evidence[name + ".blob"] = fact
    require(fact["completeHash"] and len(raw) == size, "blob_response")
    git_raw = b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw
    budget.check()
    require(len(git_raw) <= MAX_HASH_BYTES - budget.hashed, "hash_cap")
    budget.hashed += len(git_raw)
    require(hashlib.sha1(git_raw).hexdigest() == entry["gitOid"], "blob_response")
    value.update(sha256=fact["prefixSha256"], availability="hashed")
    return value


def file_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def after_identity(root_fd, path, budget):
    """Walk directories by fd with O_NOFOLLOW; never traverse a source symlink."""
    descriptors, parent = [], root_fd
    try:
        for part in path.split("/")[:-1]:
            budget.check()
            parent = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            descriptors.append(parent)
        leaf = path.split("/")[-1]
        try:
            initial = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return {"kind": "absent", "mode": None, "sha256": None, "availability": "absent"}
        if stat.S_ISLNK(initial.st_mode):
            target = os.readlink(os.fsencode(leaf), dir_fd=parent)
            require(len(target) <= 4096 and file_identity(initial) == file_identity(
                os.stat(leaf, dir_fd=parent, follow_symlinks=False)), "worktree_race")
            return {"kind": "symlink", "mode": "120000", "bytes": len(target),
                "sha256": budget.hash(target), "availability": "link_target_hashed_without_following"}
        if not stat.S_ISREG(initial.st_mode):
            return {"kind": "directory" if stat.S_ISDIR(initial.st_mode) else "other",
                "mode": None, "sha256": None, "availability": "not_traversed"}
        result = {"kind": "regular", "mode": "100755" if initial.st_mode & 0o111 else "100644",
            "bytes": initial.st_size, "sha256": None, "availability": "content_cap"}
        if initial.st_size > min(MAX_FILE, MAX_HASH_BYTES - budget.hashed):
            return result
        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            opened = os.fstat(fd)
            require(stat.S_ISREG(opened.st_mode) and file_identity(initial) == file_identity(opened), "worktree_race")
            digest, count = hashlib.sha256(), 0
            while True:
                budget.check()
                block = os.read(fd, min(65536, initial.st_size - count + 1))
                if not block:
                    break
                require(count + len(block) <= initial.st_size and len(block) <= MAX_HASH_BYTES - budget.hashed,
                    "worktree_race")
                digest.update(block)
                count += len(block)
                budget.hashed += len(block)
            require(count == initial.st_size and file_identity(opened) == file_identity(os.fstat(fd)) ==
                file_identity(os.stat(leaf, dir_fd=parent, follow_symlinks=False)), "worktree_race")
            result.update(sha256=digest.hexdigest(), availability="hashed")
            return result
        finally:
            os.close(fd)
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def encoded(report):
    return json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def report(source, request, observations, read, context, deadline, clock=time.time):
    """Best effort only. Fixed issue codes, hashes and bound paths; never acceptance."""
    expected = request["source"]
    value = {"schema": SCHEMA, "status": "diagnostic_only", "gate": "v9.profile_changed_tracked_source",
        "sourceSha": None, "sourceTree": None, "runId": None, "runAttempt": None, "profile": None,
        "checks": {}, "rawEvidence": {}, "paths": [], "unknownPathCount": 0,
        "omittedKnownPaths": 0, "issueCodes": [], "hashedBytes": 0,
        "maxPaths": MAX_PATHS, "maxReportBytes": MAX_REPORT, "maxHashBytes": MAX_HASH_BYTES,
        "rawContentReturned": False, "acceptanceGranted": False}
    budget = Budget(deadline, clock)
    try:
        require(all(type(expected.get(k)) is str and OID.fullmatch(expected[k]) for k in
            ("sourceSha", "sourceTree")), "source_context")
        value.update(sourceSha=expected["sourceSha"], sourceTree=expected["sourceTree"])
        require(type(context) is dict and type(context.get("runId")) is str and
            re.fullmatch(r"[1-9][0-9]{0,19}", context["runId"]) and context.get("runAttempt") == 1 and
            type(context.get("runAttempt")) is int and context.get("profile") in PROFILES, "run_context")
        value.update({k: context[k] for k in ("runId", "runAttempt", "profile")})
        for name, key in (("head", "sourceSha"), ("tree", "sourceTree")):
            value["checks"][name] = {"available": False, "matches": None, "observedGitOid": None}
            if type(observations.get(name)) is not bytes:
                value["issueCodes"].append("gate_read_unavailable")
                continue
            raw = metadata(observations[name], budget, value["rawEvidence"], name)
            if re.fullmatch(rb"[0-9a-f]{40}", raw.strip()) is None:
                value["issueCodes"].append("observed_identity")
                continue
            actual = raw.strip().decode("ascii")
            value["checks"][name] = {"available": True, "matches": actual == expected[key], "observedGitOid": actual}
        value["checks"]["trackedStatus"] = {"available": False, "clean": None}
        if type(observations.get("status")) is bytes:
            original = metadata(observations["status"], budget, value["rawEvidence"], "gateStatus")
            value["checks"]["trackedStatus"] = {"available": True, "clean": original.strip() == b""}
        else:
            value["issueCodes"].append("gate_read_unavailable")
        # The original, non-NUL predicate is preserved. This second observation
        # is explicitly separate and never represented as the original stream.
        raw = metadata(read("status", "--porcelain=v1", "-z", "--untracked-files=no"), budget,
            value["rawEvidence"], "nulStatus")
        bound_tree = metadata(read("rev-parse", expected["sourceSha"] + "^{tree}"), budget,
            value["rawEvidence"], "boundTreeIdentity")
        require(bound_tree.strip() == expected["sourceTree"].encode("ascii"), "bound_tree_identity")
        tree_raw = metadata(read("ls-tree", "-rz", "--full-tree", expected["sourceSha"]), budget,
            value["rawEvidence"], "boundTree")
        known = tree_entries(tree_raw)
        changes, value["unknownPathCount"] = status_entries(raw, known)
        index_raw = metadata(read("ls-files", "--stage", "-z"), budget, value["rawEvidence"], "index")
        index = index_entries(index_raw)
        ordered = sorted(changes)
        value["omittedKnownPaths"] = max(0, len(ordered) - MAX_PATHS)
        if value["omittedKnownPaths"]:
            value["issueCodes"].append("path_cap")
        root_fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for name in ordered[:MAX_PATHS]:
                budget.check()
                row = {"path": name, **changes[name], "before": dict(known[name], sha256=None,
                    availability="git_identity_only"), "index": index.get(name, []), "after": None}
                value["paths"].append(row)
                try:
                    row["before"] = before_identity(known[name], read, budget, value["rawEvidence"],
                        "before" + str(len(value["paths"])))
                    row["after"] = after_identity(root_fd, name, budget)
                except Unavailable as error:
                    row["unavailableCode"] = issue(error)
                except (OSError, ValueError, UnicodeError, TypeError):
                    row["unavailableCode"] = "path_unavailable"
                # Keep already-produced metadata without ever exceeding cap.
                if len(encoded(value)) > MAX_REPORT - 1024:
                    value["paths"].pop()
                    value["omittedKnownPaths"] += len(ordered[:MAX_PATHS]) - len(value["paths"])
                    value["issueCodes"].append("report_cap")
                    break
        finally:
            os.close(root_fd)
    except Unavailable as error:
        value["issueCodes"].append(issue(error))
    except Exception:
        # No exception text, Git stderr or arbitrary exception class is exposed.
        value["issueCodes"].append("diagnostic_unavailable")
    value["hashedBytes"] = budget.hashed
    if len(encoded(value)) > MAX_REPORT:
        # Fixed minimal fallback, never a truncated JSON document or acceptance.
        value["paths"], value["rawEvidence"] = [], {}
        value["issueCodes"] = ["report_cap"]
    return value
