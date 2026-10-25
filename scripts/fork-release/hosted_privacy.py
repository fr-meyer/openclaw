#!/usr/bin/env python3
"""Bounded, non-executing privacy heuristic for the hosted OCI export boundary.

Inspect the exact digest-addressed layout before loading or publishing it. All
referenced image layers are inspected, including overwritten and whiteouted
files. Nothing is extracted. Unsupported/incomplete inspection fails closed.
The existing image.mjs sealer still owns release provenance/qualification; this
receipt only binds this inspection to its inputs. toolingSha is caller-supplied
pipeline identity, not an assertion derived from the application image.

This is NOT a proof of absence of secrets: patterns can miss arbitrary passwords,
encoded/encrypted data and nested archives, and can flag public test credentials.
It does not audit source history, dependency trust, logs or registry visibility.
Only fixed rule codes, hashed locations and bounded syntax diagnostics are
emitted, never matched contents or fingerprints of arbitrary matched values.
"""

import argparse
from contextlib import contextmanager
import dataclasses
import gzip
import hashlib
import json
import os
import re
import stat
import tarfile
import zlib
from pathlib import Path
from urllib.parse import urlsplit


INDEX = "application/vnd.oci.image.index.v1+json"
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
CONFIG = "application/vnd.oci.image.config.v1+json"
EMPTY_CONFIG = "application/vnd.oci.empty.v1+json"
EMPTY_CONFIG_DIGEST = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
ATTESTATION_ARTIFACT = "application/vnd.docker.attestation.manifest.v1+json"
TAR = "application/vnd.oci.image.layer.v1.tar"
GZIP = TAR + "+gzip"
ATTESTATION = "application/vnd.in-toto+json"
PROVENANCE = "https://slsa.dev/provenance/v1"
REPOSITORY = "fr-meyer/openclaw"
DIGEST = re.compile(r"sha256:[a-f0-9]{64}\Z")
SHA = re.compile(r"[a-f0-9]{40}\Z")
CHUNK = 64 * 1024
OVERLAP = 512
SENSITIVE_KEY = re.compile(
    r"(?:^|[:_./-])(?:password|passwd|token|secret|api[_-]?key|private[_-]?key|"
    r"access[_-]?key|credentials)(?:$|[_-](?:id|value|secret)$)", re.I
)
OPENSSH_SK_ALGORITHM = b"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com"
PATTERNS = (
    # A header literal is common in public crypto parsers/documentation. Require
    # a plausible body, including the optional legacy encrypted-PEM headers.
    ("private_key", re.compile(
        rb"-----BEGIN (?:[A-Z0-9 ]{0,40} )?PRIVATE KEY-----\r?\n"
        rb"(?:Proc-Type: [^\r\n]{1,80}\r?\nDEK-Info: [^\r\n]{1,160}\r?\n\r?\n)?"
        rb"[A-Za-z0-9+/]{64}")),
    ("github_token", re.compile(rb"(?:gh[pousr]_[A-Za-z0-9]{30,255}|github_pat_[A-Za-z0-9_]{30,255})")),
    # Exclude only the complete public OpenSSH algorithm at a string/name-list
    # delimiter on both sides. Changed names and namespace continuations remain
    # candidates under the ordinary service-token start boundary.
    ("service_token", re.compile(
        rb"(?:(?<![A-Za-z0-9_])"
        rb"(?!(?<![^\x00\t\r\n ,\"'])" + re.escape(OPENSSH_SK_ALGORITHM) +
        rb"(?=\Z|[\x00\t\r\n ,\"']))"
        rb"sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{24,255}|xox[baprs]-[A-Za-z0-9-]{20,255})")),
    ("aws_access_key", re.compile(rb"(?<![A-Za-z0-9_])(?:AKIA|ASIA)[A-Z0-9]{16}")),
    ("credential_url", re.compile(rb"https?://[^\s/:@?#\"']{1,100}:[^\s/@?#\"']{1,150}@")),
)
FINDING_RULES = tuple(rule for rule, _ in PATTERNS) + (
    "private_runtime_path", "sqlite_database_payload", "sensitive_metadata_value", "sensitive_environment_value")
FINDING_UNITS = ("archive_member", "json_key", "json_string", "metadata_value", "byte_input")
COUNT_UNIT = "rule-per-scan-unit.v1"
MAX_REPRESENTATIVES = 64
MAX_LOCATION_ROWS = 4096
MAX_LOCATION_BYTES = 512 * 1024
MAX_RECEIPT_BYTES = 1024 * 1024
MAX_COMPARISON_ENTRIES = 128
MAX_COMPARISON_PLAN_BYTES = 128 * 1024
MAX_PROVENANCE_SUBJECT_DETAILS = 4
_MISSING = object()
PUBLIC_MEMBER_QUALIFICATION = {
    "sourceSha": "30786562e236aab6a924981c62aa61b920132c76",
    "planSha256": "4243432f63377a19a75746f5f41d345f24db3d7176aa2e446ccee3aa3a4bff11",
    "rules": ("service_token", "credential_url", "github_token", "aws_access_key", "private_key",
              "private_runtime_path"),
}
# All six complete PEMs in this exact public binary match GnuTLS 3.7.9's
# lib/crypto-selftests-pk.c. This qualifies only private_key after reading and
# hashing the complete member; it is not a path, dependency or layer allowlist.
PUBLIC_GNUTLS_SELF_TEST = {
    "rule": "private_key",
    "blobDigest": "sha256:11422d7ca1a44390a32bd8d8d9dc5946b4d053b3bbd9507d682e35584ba84a26",
    "path": "usr/lib/x86_64-linux-gnu/libgnutls.so.30.34.3",
    "memberSha256": "779b25d20249988bea2c1aa6bbeb218f5ae7ea8a9d30ce4f54ea37372965cc4b",
    "memberBytes": 2209528,
    "publicSourceSha256": "c3d79122e072177f55dc30a98f68b949c0f36f6159a363aae9512a22a9280ed0",
}
LIMITATIONS = [
    "Heuristic detection is not proof that an image contains no secrets.",
    "Arbitrary, encoded/encrypted credentials and nested archives may evade detection.",
    "GnuTLS qualification is exact and hash-bound. Explicit public-member qualification additionally requires the code-pinned source/manifest and complete exact regular-member bytes for each permitted rule; unplanned rules, paths and changed fixtures still cause refusals.",
    "Match lengths and syntax flags describe the first retained scan-window match, which may be a bounded prefix.",
    "Counts are rule/scan-unit pairs, not unique credentials: each TAR member occurrence, JSON key/string occurrence, explicit metadata value or standalone byte input is a unit.",
    "Overlapping chunks and path/link checks share their member unit; repeated members or layers count separately. PAX JSON has its own key/string units.",
    "Representatives use fixed per-rule quotas within 64 total; omitted representatives do not stop inspection. Counts are partial when inspectionComplete is false.",
    "The separate hashed-location index is capped at 4096 rows and 512 KiB of compact JSON; truncation does not count unique omitted locations or stop inspection.",
    "Optional caller-reviewed public-member comparisons never remove findings or prove final overlay presence. Public provenance is caller-attested; missing records are inconclusive when inspectionComplete is false, and any differing/incomplete occurrence prevents a matched result.",
    "Source history, build logs, dependencies and publication visibility are outside this inspection.",
    "Release qualification and complete provenance validation remain the image sealer's responsibility.",
]


@dataclasses.dataclass(frozen=True)
class Limits:
    blob_bytes: int = 8 * 1024**3
    total_blob_bytes: int = 16 * 1024**3
    json_bytes: int = 32 * 1024**2
    expanded_layer_bytes: int = 12 * 1024**3
    total_expanded_bytes: int = 32 * 1024**3
    member_bytes: int = 4 * 1024**3
    members: int = 500000
    layers: int = 256
    manifests: int = 16
    blobs: int = 1024
    path_bytes: int = 4096
    tar_metadata_bytes: int = 64 * 1024
    json_nodes: int = 1000000
    findings: int = 64
    export_entries: int = 2048
    export_depth: int = 16


class Refusal(Exception):
    """Fixed, safe rule identifier; never carry untrusted exception messages."""


def require(condition, code):
    if not condition:
        raise Refusal(code)


def _directory_fingerprint(info):
    return tuple(getattr(info, key) for key in
                 ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_size", "st_mtime_ns", "st_ctime_ns"))


def _entry_type(info):
    if stat.S_ISLNK(info.st_mode):
        return "symlink"
    if stat.S_ISDIR(info.st_mode):
        return "directory"
    if stat.S_ISREG(info.st_mode):
        return "regular"
    return "special"


def capture_empty_ingest(directory):
    """Snapshot only an absent or genuinely empty, nonlink root ingest store.

    This is transport metadata, not a namespace or content allowlist. The token
    stays private in the caller; no path, entry name or inode enters diagnostics.
    """
    root = Path(directory)
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISDIR(before.st_mode), "unsafe_export_root")
        try:
            entry = os.stat("ingest", dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            entry = None
        if entry is not None:
            require(stat.S_ISDIR(entry.st_mode) and not stat.S_ISLNK(entry.st_mode), "unsafe_export_ingest")
            child = os.open("ingest", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK,
                            dir_fd=descriptor)
            try:
                current = os.fstat(child)
                require(_directory_fingerprint(current) == _directory_fingerprint(entry), "export_transport_changed")
                with os.scandir(child) as entries:
                    require(next(entries, None) is None, "nonempty_export_ingest")
                require(_directory_fingerprint(current) == _directory_fingerprint(os.fstat(child)) and
                        _directory_fingerprint(current) == _directory_fingerprint(
                            os.stat("ingest", dir_fd=descriptor, follow_symlinks=False)), "export_transport_changed")
                token = _directory_fingerprint(current)
            finally:
                os.close(child)
        else:
            token = None
        after = os.fstat(descriptor)
        require(_directory_fingerprint(before) == _directory_fingerprint(after) and
                _directory_fingerprint(after) == _directory_fingerprint(root.lstat()), "export_transport_changed")
        return _directory_fingerprint(after), token
    finally:
        os.close(descriptor)


def require_unchanged_empty_ingest(directory, snapshot):
    require(capture_empty_ingest(directory) == snapshot, "export_transport_changed")


def inspect_export_structure(directory, limits=None):
    """Bounded metadata-only inventory; never follow links or expose names.

    Complete traversal does not admit OCI graph/content semantics. Unsafe entry
    types are counted without following them, and still refuse the structure.
    Limits stop traversal with explicitly incomplete aggregate coverage.
    """
    selected = limits or Limits()
    counts = dict.fromkeys(("entries", "directories", "regularFiles", "symlinks", "hardlinkedFiles",
                            "specialFiles", "regularFileBytes", "allocatedFileBytes", "blobFiles", "blobBytes"), 0)
    roots = {name: {"present": False, "type": "absent"}
             for name in ("ociLayout", "indexJson", "blobs")}
    roots["ingest"] = {"present": False, "type": "absent", "genuinelyEmpty": False}
    known = {"oci-layout": "ociLayout", "index.json": "indexJson", "blobs": "blobs", "ingest": "ingest"}
    result = {"schema": "openclaw.oci-export-structure.v1", "status": "refused", "reason": None,
              "counts": counts,
              "coverage": {"traversalComplete": False, "byteCountsComplete": False,
                           "metadataOnly": True, "linksFollowed": False},
              "limits": {"entries": 2048, "depth": 16, "blobs": Limits().blobs}, "knownRoot": roots}
    reason, complete, root_fd = None, False, None

    class StopTraversal(Exception):
        pass

    def note(code):
        nonlocal reason
        if reason is None:
            reason = code

    def visit(descriptor, depth, scope=None):
        nonlocal reason
        before = os.fstat(descriptor)
        children = 0
        with os.scandir(descriptor) as entries:
            for entry in entries:
                if counts["entries"] >= selected.export_entries:
                    reason = "export_entry_limit"
                    raise StopTraversal()
                info = entry.stat(follow_symlinks=False)
                kind = _entry_type(info)
                counts["entries"] += 1
                children += 1
                if depth == 0 and entry.name in known:
                    roots[known[entry.name]].update(present=True, type=kind)
                if kind == "symlink":
                    counts["symlinks"] += 1
                    note("export_symlink")
                    continue
                if kind == "special":
                    counts["specialFiles"] += 1
                    note("export_special_type")
                    continue
                if kind == "regular":
                    counts["regularFiles"] += 1
                    counts["regularFileBytes"] += info.st_size
                    counts["allocatedFileBytes"] += getattr(info, "st_blocks", 0) * 512
                    if info.st_nlink != 1:
                        counts["hardlinkedFiles"] += 1
                        note("export_hardlink")
                    if scope == "blobStore":
                        counts["blobFiles"] += 1
                        counts["blobBytes"] += info.st_size
                    continue
                counts["directories"] += 1
                if depth >= selected.export_depth:
                    reason = "export_depth_limit"
                    raise StopTraversal()
                child_scope = ("blobs" if depth == 0 and entry.name == "blobs" else
                               "blobStore" if scope == "blobs" and entry.name == "sha256" else None)
                child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                dir_fd=descriptor)
                try:
                    require(_directory_fingerprint(info) == _directory_fingerprint(os.fstat(child)),
                            "export_structure_changed")
                    child_count = visit(child, depth + 1, child_scope)
                    require(_directory_fingerprint(info) == _directory_fingerprint(
                        os.stat(entry.name, dir_fd=descriptor, follow_symlinks=False)), "export_structure_changed")
                    if depth == 0 and entry.name == "ingest":
                        roots["ingest"]["genuinelyEmpty"] = child_count == 0
                finally:
                    os.close(child)
        require(_directory_fingerprint(before) == _directory_fingerprint(os.fstat(descriptor)),
                "export_structure_changed")
        return children

    try:
        require(type(selected.export_entries) is int and 0 < selected.export_entries <= 2048 and
                type(selected.export_depth) is int and 0 < selected.export_depth <= 16 and
                type(selected.blobs) is int and 0 <= selected.blobs <= Limits().blobs,
                "invalid_export_structure_limits")
        result["limits"] = {"entries": selected.export_entries, "depth": selected.export_depth, "blobs": selected.blobs}
        root = Path(directory)
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK)
        initial = os.fstat(root_fd)
        require(stat.S_ISDIR(initial.st_mode), "unsafe_export_root")
        visit(root_fd, 0)
        require(_directory_fingerprint(initial) == _directory_fingerprint(root.lstat()), "export_structure_changed")
        complete = True
    except StopTraversal:
        pass
    except Refusal as error:
        reason = str(error)
    except (OSError, ValueError, TypeError, AttributeError, OverflowError):
        reason = "export_structure_unreadable"
    finally:
        if root_fd is not None:
            os.close(root_fd)
    if not complete:
        roots["ingest"]["genuinelyEmpty"] = False
    result["status"] = "complete" if complete and reason is None else "refused"
    result["reason"] = reason
    result["coverage"]["traversalComplete"] = complete
    result["coverage"]["byteCountsComplete"] = complete and not any(
        counts[key] for key in ("symlinks", "specialFiles", "hardlinkedFiles"))
    return result


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def provenance_subject_summary(subject, image_digest, observed):
    """Fixed shapes only; never disclose subject names, algorithm keys or values."""
    def kind(value):
        if value is _MISSING:
            return "missing"
        if value is None:
            return "null"
        return {dict: "object", list: "array", str: "string", bool: "boolean",
                int: "number", float: "number"}.get(type(value), "other")

    expected = image_digest[7:] if isinstance(image_digest, str) and DIGEST.fullmatch(image_digest) else None
    records = []
    values = subject if isinstance(subject, list) else []
    for item in values[:MAX_PROVENANCE_SUBJECT_DETAILS]:
        digest = item.get("digest", _MISSING) if isinstance(item, dict) else _MISSING
        algorithms = ("sha256", "sha512", "sha1")
        known = sum(key in digest for key in algorithms) if isinstance(digest, dict) else 0
        shapes = {}
        for algorithm in algorithms:
            value = digest.get(algorithm, _MISSING) if isinstance(digest, dict) else _MISSING
            shapes[algorithm] = {
                "present": value is not _MISSING, "type": kind(value),
                "length": len(value) if isinstance(value, str) else None,
                "hex": isinstance(value, str) and bool(re.fullmatch(r"[0-9a-fA-F]+", value)),
                "matchesExpectedPlatform": algorithm == "sha256" and expected is not None and value == expected,
            }
        records.append({"subjectType": kind(item), "digestType": kind(digest),
                        "digestAlgorithmCount": len(digest) if isinstance(digest, dict) else None,
                        "knownAlgorithmCount": known,
                        "unknownAlgorithmCount": len(digest) - known if isinstance(digest, dict) else None,
                        "digests": shapes})
    return {"schema": "openclaw.provenance-subject-diagnostics.v1", "statementSelection": "last_observed",
            "statementsObserved": observed, "subjectType": kind(subject),
            "subjectCount": len(subject) if isinstance(subject, list) else None,
            "retainedSubjects": len(records), "subjectsTruncated": len(values) > len(records),
            "subjects": records}


def object_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def require_public_member_qualification(receipt, plan_bytes):
    """Validate exact qualification evidence; this does not rescan image bytes."""
    code = "invalid_public_member_qualification"
    try:
        trusted = PUBLIC_MEMBER_QUALIFICATION
        require(type(plan_bytes) is bytes and len(plan_bytes) <= MAX_COMPARISON_PLAN_BYTES and
                sha256(plan_bytes) == trusted["planSha256"], code)
        plan = json.loads(plan_bytes, object_pairs_hook=object_pairs)
        require(plan["schema"] == "openclaw.public-member-comparisons.v1" and
                plan["sourceSha"] == trusted["sourceSha"] and receipt["sourceSha"] == trusted["sourceSha"] and
                receipt["inspectionComplete"] is True, code)
        expected = {entry["id"]: entry for entry in plan["entries"]}
        expected_pairs = {(entry["id"], rule) for entry in plan["entries"] for rule in entry["rules"]}
        require(len(expected) == len(plan["entries"]) <= MAX_COMPARISON_ENTRIES and
                all(rule in trusted["rules"] for _, rule in expected_pairs), code)
        comparison, qualification = receipt["publicMemberComparisons"], receipt["publicMemberQualification"]
        require(set(comparison) == {"schema", "sourceSha", "planSha256", "diagnosticOnly", "records", "inspectionComplete"}
                and comparison["schema"] == "openclaw.public-member-comparison-results.v1" and
                comparison["diagnosticOnly"] is True and
                set(qualification) == {"schema", "sourceSha", "planSha256", "records", "inspectionComplete", "status"} and
                qualification["schema"] == "openclaw.public-member-qualification.v1" and
                qualification["status"] == "satisfied", code)
        for report in (comparison, qualification):
            require(report["sourceSha"] == trusted["sourceSha"] and report["planSha256"] == trusted["planSha256"] and
                    report["inspectionComplete"] is True and isinstance(report["records"], list), code)
        require(len(comparison["records"]) == len(expected) and
                len(qualification["records"]) == len(expected_pairs), code)
        compared = {}
        for record in comparison["records"]:
            require(set(record) == {"id", "locationSha256", "memberSha256", "memberBytes", "rules", "status",
                                    "observedMembers", "matchedMembers", "mismatchedMembers"}, code)
            entry = expected[record["id"]]
            require(record["id"] not in compared and record["status"] == "matched" and
                    record["locationSha256"] == sha256(entry["path"].encode("utf-8", "surrogatepass")) and
                    type(record["memberBytes"]) is int and
                    all(record[key] == entry[key] for key in ("memberSha256", "memberBytes", "rules")) and
                    all(type(record[key]) is int for key in ("observedMembers", "matchedMembers", "mismatchedMembers")) and
                    record["observedMembers"] == record["matchedMembers"] > 0 and record["mismatchedMembers"] == 0, code)
            compared[record["id"]] = record
        seen = set()
        for record in qualification["records"]:
            require(set(record) == {"id", "locationSha256", "memberSha256", "memberBytes", "sourceSha",
                                    "planSha256", "rule", "memberOccurrences"}, code)
            pair = (record["id"], record["rule"])
            require(pair in expected_pairs and pair not in seen, code)
            observed = compared[record["id"]]
            require(record["sourceSha"] == trusted["sourceSha"] and record["planSha256"] == trusted["planSha256"] and
                    type(record["memberBytes"]) is int and type(record["memberOccurrences"]) is int and
                    all(record[key] == observed[key] for key in ("locationSha256", "memberSha256", "memberBytes")) and
                    record["memberOccurrences"] == observed["matchedMembers"], code)
            seen.add(pair)
    except (Refusal, ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError):
        raise Refusal(code) from None


class ExpandedReader:
    """Budget decompression before tarfile can allocate a member/PAX payload."""

    def __init__(self, stream, inspector):
        self.stream, self.inspector, self.count = stream, inspector, 0
        self.tail = b""

    def read(self, size=-1):
        require(0 <= size <= CHUNK, "unbounded_archive_read")
        data = self.stream.read(size)
        self.count += len(data)
        self.tail = (self.tail + data)[-1024:]
        self.inspector.counts["expandedBytes"] += len(data)
        require(self.count <= self.inspector.limits.expanded_layer_bytes, "expanded_layer_limit")
        require(self.inspector.counts["expandedBytes"] <= self.inspector.limits.total_expanded_bytes,
                "expanded_total_limit")
        return data


class Inspector:
    def __init__(self, directory, expected_index_digest, source_sha, tooling_sha, limits):
        self.directory = Path(directory)
        self.index_digest, self.source_sha, self.tooling_sha = expected_index_digest, source_sha, tooling_sha
        self.limits = limits
        self.findings = []
        self.qualified_public_fixtures = []
        self.finding_counts = dict.fromkeys(FINDING_RULES, 0)
        self.finding_unit_counts = dict.fromkeys(FINDING_UNITS, 0)
        self.representative_counts = dict.fromkeys(FINDING_RULES, 0)
        self.location_index, self.location_identities = [], set()
        self.location_index_bytes, self.location_index_truncated = 2, False
        self.unit_kind, self.unit_rules = None, set()
        self.blobs = {}
        self.counts = {"blobBytes": 0, "expandedBytes": 0, "layers": 0, "members": 0,
                       "files": 0, "fileBytes": 0, "jsonNodes": 0}
        self.image_digest = self.config_digest = None
        self.public_comparisons = None
        self.comparisons_by_path = {}
        self.qualify_public_members = False
        self.qualified_public_members = {}
        self.provenance_subjects_observed = 0
        self.provenance_subject_diagnostics = None
        self.export_transport_snapshot = _MISSING

    def enable_public_member_qualification(self):
        plan, trusted = self.public_comparisons, PUBLIC_MEMBER_QUALIFICATION
        require(plan is not None, "public_member_qualification_plan_required")
        require(plan["sourceSha"] == trusted["sourceSha"] and plan["planSha256"] == trusted["planSha256"] and
                all(rule in trusted["rules"] for record in plan["records"] for rule in record["rules"]),
                "untrusted_public_member_qualification_plan")
        self.qualify_public_members = True

    def qualify_member_findings(self, candidates, pending, digest):
        for rule, finding in pending.items():
            record = candidates[rule]
            if finding is not None and digest is not None and digest == record["memberSha256"]:
                key = (record["id"], rule)
                if key not in self.qualified_public_members:
                    self.qualified_public_members[key] = {
                        **{field: record[field] for field in ("id", "locationSha256", "memberSha256", "memberBytes")},
                        "sourceSha": self.source_sha, "planSha256": self.public_comparisons["planSha256"],
                        "rule": rule, "memberOccurrences": 0}
                self.qualified_public_members[key]["memberOccurrences"] += 1
                pending[rule] = None

    def load_public_comparisons(self, path):
        """Read a caller-reviewed public manifest, never image-controlled data."""
        try:
            with self.open_regular(path, MAX_COMPARISON_PLAN_BYTES)[0] as stream:
                before = os.fstat(stream.fileno())
                data = stream.read(MAX_COMPARISON_PLAN_BYTES + 1)
                after = os.fstat(stream.fileno())
            require(len(data) <= MAX_COMPARISON_PLAN_BYTES and len(data) == before.st_size and
                    (before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                    (after.st_size, after.st_mtime_ns, after.st_ctime_ns), "invalid_public_comparison_plan")
            plan = self.parse_json(data)
            require(set(plan) == {"schema", "sourceSha", "entries"} and
                    plan["schema"] == "openclaw.public-member-comparisons.v1" and
                    isinstance(plan["sourceSha"], str) and SHA.fullmatch(plan["sourceSha"]) and
                    plan["sourceSha"] == self.source_sha and isinstance(plan["entries"], list) and
                    len(plan["entries"]) <= MAX_COMPARISON_ENTRIES, "invalid_public_comparison_plan")
            identities, pairs, records, by_path = set(), set(), [], {}
            for entry in plan["entries"]:
                require(isinstance(entry, dict) and set(entry) ==
                        {"id", "path", "memberSha256", "memberBytes", "rules", "evidence"},
                        "invalid_public_comparison_plan")
                identity, name, rules = entry["id"], entry["path"], entry["rules"]
                require(isinstance(identity, str) and re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", identity) and
                        identity not in identities and isinstance(name, str) and name and
                        self.safe_name(name) == name and not any(ord(char) < 32 or ord(char) == 127 for char in name) and
                        isinstance(entry["memberSha256"], str) and re.fullmatch(r"[a-f0-9]{64}", entry["memberSha256"]) and
                        type(entry["memberBytes"]) is int and 0 <= entry["memberBytes"] <= self.limits.member_bytes and
                        isinstance(rules, list) and 1 <= len(rules) <= len(FINDING_RULES) and
                        all(isinstance(rule, str) and rule in FINDING_RULES for rule in rules) and
                        len(set(rules)) == len(rules) and all((name, rule) not in pairs for rule in rules),
                        "invalid_public_comparison_plan")
                evidence = entry["evidence"]
                require(isinstance(evidence, dict) and set(evidence) == {"reference", "sha256"} and
                        isinstance(evidence["reference"], str) and len(evidence["reference"]) <= 2048 and
                        isinstance(evidence["sha256"], str) and re.fullmatch(r"[a-f0-9]{64}", evidence["sha256"]),
                        "invalid_public_comparison_plan")
                reference = urlsplit(evidence["reference"])
                require(reference.scheme == "https" and reference.hostname and
                        re.fullmatch(r"[A-Za-z0-9.-]+", reference.hostname) and reference.port in (None, 443) and
                        reference.username is None and reference.password is None and not reference.query and
                        not reference.fragment and not any(ord(char) < 33 or ord(char) == 127 for char in evidence["reference"]),
                        "invalid_public_comparison_plan")
                identities.add(identity)
                pairs.update((name, rule) for rule in rules)
                record = {"id": identity, "locationSha256": sha256(name.encode("utf-8", "surrogatepass")),
                          "memberSha256": entry["memberSha256"], "memberBytes": entry["memberBytes"],
                          "rules": rules, "status": "missing", "observedMembers": 0,
                          "matchedMembers": 0, "mismatchedMembers": 0}
                records.append(record)
                by_path.setdefault(name, []).append(record)
            self.public_comparisons = {"schema": "openclaw.public-member-comparison-results.v1",
                                       "sourceSha": self.source_sha, "planSha256": sha256(data),
                                       "diagnosticOnly": True, "records": records}
            self.comparisons_by_path = by_path
        except (Refusal, OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError):
            raise Refusal("invalid_public_comparison_plan") from None

    def begin_public_comparisons(self, name, member):
        pending = []
        for record in self.comparisons_by_path.get(name, ()):
            record["observedMembers"] += 1
            # Provisional mismatch stays in place if a read cannot complete.
            record["mismatchedMembers"] += 1
            record["status"] = "mismatch"
            if member.isfile() and member.size == record["memberBytes"]:
                pending.append(record)
        return pending

    def finish_public_comparisons(self, pending, digest):
        for record in pending:
            matched = digest is not None and digest == record["memberSha256"]
            if matched:
                record["matchedMembers"] += 1
                record["mismatchedMembers"] -= 1
            record["status"] = "mismatch" if record["mismatchedMembers"] else "matched"

    @property
    def finding_total(self):
        return sum(self.finding_counts.values())

    @contextmanager
    def scan_unit(self, kind):
        require(kind in FINDING_UNITS, "invalid_finding_unit")
        previous = self.unit_kind, self.unit_rules
        self.unit_kind, self.unit_rules = kind, set()
        try:
            yield
        finally:
            self.unit_kind, self.unit_rules = previous

    def finding_summary(self):
        return {"unit": COUNT_UNIT, "total": self.finding_total,
                "byRule": dict(self.finding_counts), "byUnit": dict(self.finding_unit_counts)}

    def finding(self, rule, location, blob_digest=None, diagnostics=None):
        if self.unit_kind is None:
            with self.scan_unit("metadata_value"):
                self.finding(rule, location, blob_digest, diagnostics)
            return
        require(rule in FINDING_RULES, "invalid_finding_rule")
        # Location identity is independent of count identity: a symlink name
        # and target can both match one rule within the same member unit.
        location_hash = sha256(location.encode("utf-8", "surrogatepass"))
        identity = (rule, location_hash, blob_digest)
        if identity not in self.location_identities:
            row = {"rule": rule, "locationSha256": location_hash}
            if blob_digest:
                row["blobDigest"] = blob_digest
            size = len(json.dumps(row, sort_keys=True, separators=(",", ":")).encode())
            size += int(bool(self.location_index))
            if (len(self.location_index) < MAX_LOCATION_ROWS and
                    self.location_index_bytes + size <= MAX_LOCATION_BYTES):
                self.location_index.append(row)
                self.location_identities.add(identity)
                self.location_index_bytes += size
            else:
                self.location_index_truncated = True
        if rule in self.unit_rules:
            return
        self.unit_rules.add(rule)
        self.finding_counts[rule] += 1
        self.finding_unit_counts[self.unit_kind] += 1
        require(type(self.limits.findings) is int and 0 <= self.limits.findings <= MAX_REPRESENTATIVES,
                "invalid_representative_limit")
        quota, remainder = divmod(self.limits.findings, len(FINDING_RULES))
        quota += int(FINDING_RULES.index(rule) < remainder)
        if self.representative_counts[rule] >= quota:
            return
        self.representative_counts[rule] += 1
        finding = {"rule": rule, "unit": self.unit_kind, "locationSha256": location_hash}
        if blob_digest:
            finding["blobDigest"] = blob_digest
        if diagnostics:
            finding.update(diagnostics)
        self.findings.append(finding)

    def scan_bytes(self, data, location, blob_digest=None, *, previous_byte=b"", pending_private_key=None,
                   pending_public_members=None, final_chunk=True):
        if self.unit_kind is None:
            with self.scan_unit("byte_input"):
                self.scan_bytes(data, location, blob_digest, previous_byte=previous_byte,
                                pending_private_key=pending_private_key, pending_public_members=pending_public_members,
                                final_chunk=final_chunk)
            return
        # Preserve the real predecessor for both sk- and AWS lookbehind. Search
        # after that byte so the context itself never becomes a new match start.
        window = previous_byte + data
        def context(byte, empty):
            if not byte:
                return empty
            if re.fullmatch(rb"[A-Za-z0-9_]", byte):
                return "ascii_identifier"
            return "ascii_delimiter" if byte[0] < 128 else "non_ascii"
        for rule, pattern in PATTERNS:
            found = pattern.search(window, len(previous_byte))
            # Defer only an unresolved prefix of the excluded name; it fits in
            # the retained overlap. Other credentials remain immediate findings,
            # including when a later member read fails. EOF flags truncated names.
            if found and rule == "service_token" and not final_chunk:
                predecessor = window[max(0, found.start() - 1):found.start()]
                if ((not predecessor or re.fullmatch(rb"[\x00\t\r\n ,\"']", predecessor)) and
                        OPENSSH_SK_ALGORITHM.startswith(window[found.start():])):
                    continue
            if found:
                diagnostics = {"matchLength": found.end() - found.start(), "syntaxFlags": {
                    "leftContext": context(window[max(0, found.start() - 1):found.start()], "input_start"),
                    "rightContext": context(window[found.end():found.end() + 1], "window_end"),
                    "percentEncoded": bool(re.search(rb"%[A-Fa-f0-9]{2}", found.group())),
                }}
                if rule == "private_key" and pending_private_key is not None:
                    if not pending_private_key:
                        pending_private_key.append((rule, location, blob_digest, diagnostics))
                elif pending_public_members is not None and rule in pending_public_members:
                    if pending_public_members[rule] is None:
                        pending_public_members[rule] = (rule, location, blob_digest, diagnostics)
                else:
                    self.finding(rule, location, blob_digest, diagnostics)

    def scan_json(self, value, location, blob_digest=None):
        pending = [(value, location)]
        while pending:
            item, where = pending.pop()
            self.counts["jsonNodes"] += 1
            require(self.counts["jsonNodes"] <= self.limits.json_nodes, "json_node_limit")
            if isinstance(item, str):
                with self.scan_unit("json_string"):
                    self.scan_bytes(item.encode("utf-8", "surrogatepass"), where, blob_digest)
            elif isinstance(item, dict):
                for key, child in item.items():
                    with self.scan_unit("json_key"):
                        self.scan_bytes(key.encode("utf-8", "surrogatepass"), where, blob_digest)
                    # BuildKit's externalParameters.args includes build-arg:NAME.
                    # Arbitrary SBOM properties named token/secret are not envs.
                    if ("/externalParameters" in where and key.startswith("build-arg:") and
                            SENSITIVE_KEY.search(key) and isinstance(child, str) and child):
                        with self.scan_unit("metadata_value"):
                            self.finding("sensitive_metadata_value", where + "/" + key, blob_digest)
                    pending.append((child, where + "/" + key))
            elif isinstance(item, list):
                pending.extend((child, where + "/" + str(i)) for i, child in enumerate(item))

    def open_regular(self, path, limit):
        # O_NOFOLLOW also rejects a blob substituted by a symlink after lstat.
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(descriptor)
            require(stat.S_ISREG(info.st_mode), "nonregular_input")
            require(0 <= info.st_size <= limit, "input_size_limit")
            return os.fdopen(descriptor, "rb"), info
        except BaseException:
            os.close(descriptor)
            raise

    def parse_json(self, data):
        try:
            result = json.loads(data, object_pairs_hook=object_pairs,
                                parse_constant=lambda _: (_ for _ in ()).throw(Refusal("invalid_json_number")))
        except (ValueError, UnicodeError, RecursionError):
            raise Refusal("malformed_json") from None
        require(isinstance(result, dict), "json_object_required")
        return result

    def local_json(self, name):
        with self.open_regular(self.directory / name, self.limits.json_bytes)[0] as stream:
            data = stream.read(self.limits.json_bytes + 1)
        require(len(data) <= self.limits.json_bytes, "json_size_limit")
        parsed = self.parse_json(data)
        self.scan_json(parsed, name)
        return parsed

    def descriptor(self, descriptor):
        require(isinstance(descriptor, dict), "descriptor_required")
        digest, size = descriptor.get("digest"), descriptor.get("size")
        require(isinstance(digest, str) and DIGEST.fullmatch(digest), "invalid_blob_digest")
        require(type(size) is int and 0 <= size <= self.limits.blob_bytes, "invalid_blob_size")
        require(not descriptor.get("urls") and "data" not in descriptor, "external_or_inline_blob")
        self.scan_json(descriptor, "descriptor/" + digest, digest)
        if digest in self.blobs:
            require(self.blobs[digest] == size, "conflicting_blob_size")
        else:
            require(len(self.blobs) < self.limits.blobs, "blob_count_limit")
            self.counts["blobBytes"] += size
            require(self.counts["blobBytes"] <= self.limits.total_blob_bytes, "blob_total_limit")
            self.blobs[digest] = size
        return digest, size

    def blob(self, descriptor, as_json=False):
        digest, size = self.descriptor(descriptor)
        require(not as_json or size <= self.limits.json_bytes, "json_size_limit")
        stream, before = self.open_regular(self.directory / "blobs" / "sha256" / digest[7:], self.limits.blob_bytes)
        try:
            require(before.st_size == size, "blob_size_mismatch")
            content, hashed, count = [], hashlib.sha256(), 0
            while True:
                chunk = stream.read(CHUNK)
                if not chunk:
                    break
                count += len(chunk)
                require(count <= size, "blob_changed")
                hashed.update(chunk)
                if as_json:
                    content.append(chunk)
            after = os.fstat(stream.fileno())
            require(count == size and (before.st_mtime_ns, before.st_ctime_ns) ==
                    (after.st_mtime_ns, after.st_ctime_ns), "blob_changed")
            require("sha256:" + hashed.hexdigest() == digest, "blob_digest_mismatch")
            if as_json:
                value = self.parse_json(b"".join(content))
                self.scan_json(value, digest, digest)
                return value
            stream.seek(0)
            return stream, before
        except BaseException:
            stream.close()
            raise
        finally:
            if as_json:
                stream.close()

    def safe_name(self, name, link=False, parent=""):
        require(isinstance(name, str) and len(name.encode("utf-8", "surrogatepass")) <= self.limits.path_bytes,
                "archive_path_limit")
        require("\0" not in name and "\\" not in name, "unsafe_archive_path")
        require(link or not name.startswith("/"), "absolute_archive_path")
        parts = [] if name.startswith("/") else [p for p in parent.split("/") if p] if link else []
        for part in name.split("/"):
            if part in ("", "."):
                continue
            if part == "..":
                require(link and parts, "archive_path_escape")
                parts.pop()
            else:
                parts.append(part)
        return "/".join(parts)

    def scan_path(self, path, digest, *, pending_public_members=None):
        parts = path.lower().split("/")
        leaf = parts[-1]
        # Empty runtime directories are normal; this applies to files/links only.
        if (leaf == ".env" or leaf.startswith(".env.") or ".openclaw" in parts or
                ".ssh" in parts or ".aws" in parts or
                leaf in ("id_rsa", "id_ed25519", "cookies", "cookies.txt", "cookies.sqlite",
                         "auth-profiles.json", "application_default_credentials.json",
                         "openclaw.sqlite", "openclaw-agent.sqlite") or
                any(leaf.startswith(db + "-") for db in ("openclaw.sqlite", "openclaw-agent.sqlite")) or
                ("gcloud" in parts and "credential" in leaf)):
            if pending_public_members is not None and "private_runtime_path" in pending_public_members:
                pending_public_members["private_runtime_path"] = ("private_runtime_path", path, digest)
            else:
                self.finding("private_runtime_path", path, digest)

    def scan_layer(self, descriptor):
        media_type = descriptor.get("mediaType")
        require(media_type in (TAR, GZIP), "unsupported_layer_format")
        self.counts["layers"] += 1
        require(self.counts["layers"] <= self.limits.layers, "layer_limit")
        raw, before = self.blob(descriptor)
        digest = descriptor["digest"]
        limits = self.limits
        class BoundedTarInfo(tarfile.TarInfo):
            # tarfile consumes these pseudo-members internally before yielding a
            # normal member. Bound them before its whole-header allocation.
            def _proc_pax(self, archive):
                require(0 <= self.size <= limits.tar_metadata_bytes, "tar_metadata_limit")
                return super()._proc_pax(archive)

            def _proc_gnulong(self, archive):
                require(0 <= self.size <= limits.path_bytes + 1, "archive_path_limit")
                return super()._proc_gnulong(archive)

            def _proc_sparse(self, archive):
                raise Refusal("unsupported_sparse_member")

            def _proc_gnusparse_00(self, *args):
                raise Refusal("unsupported_sparse_member")

            def _proc_gnusparse_01(self, *args):
                raise Refusal("unsupported_sparse_member")

            def _proc_gnusparse_10(self, *args):
                raise Refusal("unsupported_sparse_member")
        try:
            decoded = gzip.GzipFile(fileobj=raw, mode="rb") if media_type == GZIP else raw
            bounded = ExpandedReader(decoded, self)
            # Refuse non-padding data after the tar end marker (including a hidden
            # second archive). Drain through tarfile's buffer, then the decompressor
            # to check all padding, compressed EOF and CRC without losing read-ahead.
            with tarfile.open(fileobj=bounded, mode="r|", bufsize=10240, tarinfo=BoundedTarInfo) as archive:
                for member in archive:
                    with self.scan_unit("archive_member"):
                        self.counts["members"] += 1
                        require(self.counts["members"] <= self.limits.members, "member_count_limit")
                        require(0 <= member.size <= self.limits.member_bytes, "member_size_limit")
                        require(not member.sparse, "unsupported_sparse_member")
                        name = self.safe_name(member.name)
                        require(member.isfile() or member.isdir() or member.issym() or member.islnk(),
                                "unsupported_member_type")
                        self.scan_json(member.pax_headers, digest + "/pax/" + name, digest)
                        comparisons = self.begin_public_comparisons(name, member)
                        if member.isdir():
                            continue
                        if member.issym() or member.islnk():
                            self.scan_path(name, digest)
                            target = self.safe_name(member.linkname, link=True,
                                                    parent=name.rpartition("/")[0] if member.issym() else "")
                            self.scan_path(target, digest)
                            self.scan_bytes(member.linkname.encode("utf-8", "surrogatepass"), name, digest)
                            continue
                        self.counts["files"] += 1
                        total, tail, previous_byte = 0, b"", b""
                        public = PUBLIC_GNUTLS_SELF_TEST
                        candidate = (public["rule"] == "private_key" and public["blobDigest"] == digest and
                                     public["path"] == name and public["memberBytes"] == member.size)
                        member_hash = hashlib.sha256() if candidate or comparisons else None
                        complete_member_digest = None
                        public_candidates = {rule: record for record in comparisons for rule in record["rules"]}
                        public_pending = dict.fromkeys(public_candidates) if self.qualify_public_members else {}
                        pending = []
                        try:
                            # Only an exact planned regular member can defer a path
                            # finding. The full hash below qualifies it; every failed
                            # or incomplete read flushes the finding in finally.
                            self.scan_path(name, digest, pending_public_members=public_pending)
                            file = archive.extractfile(member)  # A stream only: never extract to disk.
                            require(file is not None, "missing_member_stream")
                            while True:
                                chunk = file.read(CHUNK)
                                if not chunk:
                                    break
                                if total == 0 and chunk.startswith(b"SQLite format 3\0"):
                                    self.finding("sqlite_database_payload", name, digest)
                                total += len(chunk)
                                self.counts["fileBytes"] += len(chunk)
                                if member_hash is not None:
                                    member_hash.update(chunk)
                                window = tail + chunk
                                self.scan_bytes(window, name, digest, previous_byte=previous_byte,
                                                pending_private_key=pending if candidate else None,
                                                pending_public_members=public_pending,
                                                final_chunk=total == member.size)
                                # Preserve lookbehind at a clipped overlap boundary;
                                # short reads retain file-start semantics until clipping.
                                previous_byte = window[-OVERLAP - 1:-OVERLAP]
                                tail = window[-OVERLAP:]
                            require(total == member.size, "truncated_member")
                            complete_member_digest = member_hash.hexdigest() if member_hash is not None else None
                            self.qualify_member_findings(public_candidates, public_pending, complete_member_digest)
                            if pending and complete_member_digest == public["memberSha256"]:
                                qualification = {key: public[key] for key in
                                    ("rule", "blobDigest", "memberSha256", "memberBytes", "publicSourceSha256")}
                                qualification["locationSha256"] = sha256(name.encode("utf-8", "surrogatepass"))
                                if qualification not in self.qualified_public_fixtures:
                                    self.qualified_public_fixtures.append(qualification)
                                pending.clear()
                        finally:
                            self.finish_public_comparisons(comparisons, complete_member_digest)
                            # An incomplete read or different byte hash never qualifies.
                            for finding in pending:
                                self.finding(*finding)
                            for finding in public_pending.values():
                                if finding is not None:
                                    self.finding(*finding)
                while True:
                    padding = archive.fileobj.read(CHUNK)
                    if not padding:
                        break
                    require(not any(padding), "trailing_archive_data")
            while bounded.read(CHUNK):
                pass
            require(bounded.count >= 1024 and bounded.tail == bytes(1024), "missing_tar_end_marker")
            after = os.fstat(raw.fileno())
            require((before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                    (after.st_size, after.st_mtime_ns, after.st_ctime_ns), "blob_changed")
        finally:
            raw.close()

    def verify_export_closure(self):
        # The workflow exports the entire layout. Reject extras instead of
        # silently approving uninspected files or orphaned blobs in that folder.
        if self.export_transport_snapshot is _MISSING:
            self.export_transport_snapshot = capture_empty_ingest(self.directory)
        require_unchanged_empty_ingest(self.directory, self.export_transport_snapshot)
        expected_root = {"oci-layout", "index.json", "blobs"}
        if self.export_transport_snapshot[1] is not None:
            expected_root.add("ingest")
        for directory, expected in (
                (self.directory, expected_root),
                (self.directory / "blobs", {"sha256"}),
                (self.directory / "blobs" / "sha256", {digest[7:] for digest in self.blobs})):
            seen = set()
            with os.scandir(directory) as entries:
                for entry in entries:
                    require(entry.name in expected and not entry.is_symlink(), "unexpected_export_entry")
                    seen.add(entry.name)
                    require(len(seen) <= self.limits.blobs + 3, "export_entry_limit")
            require(seen == expected, "missing_export_entry")
        require_unchanged_empty_ingest(self.directory, self.export_transport_snapshot)

    def attestation_config(self, manifest, image):
        config = manifest.get("config")
        require(isinstance(config, dict), "unsupported_config")
        media = config.get("mediaType")
        if "artifactType" in manifest or media == EMPTY_CONFIG:
            require(manifest.get("artifactType") == ATTESTATION_ARTIFACT, "unsupported_attestation_artifact")
            subject = manifest.get("subject")
            require(isinstance(subject, dict) and type(subject.get("size")) is int and
                    all(subject.get(key) == image.get(key) for key in ("mediaType", "digest", "size")),
                    "attestation_subject_mismatch")
            self.descriptor(subject)
        if media == CONFIG:
            return self.blob(config, as_json=True)
        # BuildKit's OCI artifact config is exactly {}. Inline data is only a
        # redundant canonical encoding here: the local blob is still mandatory,
        # hashed, budgeted and included in the verified export closure.
        require(media == EMPTY_CONFIG and set(config) <= {"mediaType", "digest", "size", "data"} and
                config.get("digest") == EMPTY_CONFIG_DIGEST and type(config.get("size")) is int and
                config["size"] == 2 and ("data" not in config or config["data"] == "e30="),
                "unsupported_empty_attestation_config")
        value = self.blob({key: value for key, value in config.items() if key != "data"}, as_json=True)
        require(value == {}, "nonempty_attestation_config")
        return value

    def run(self):
        self.export_transport_snapshot = capture_empty_ingest(self.directory)
        require(type(self.limits.findings) is int and 0 <= self.limits.findings <= MAX_REPRESENTATIVES,
                "invalid_representative_limit")
        require(isinstance(self.index_digest, str) and DIGEST.fullmatch(self.index_digest), "invalid_index_digest")
        require(isinstance(self.source_sha, str) and SHA.fullmatch(self.source_sha), "invalid_source_sha")
        require(isinstance(self.tooling_sha, str) and SHA.fullmatch(self.tooling_sha), "invalid_tooling_sha")
        for directory in (self.directory, self.directory / "blobs", self.directory / "blobs" / "sha256"):
            require(stat.S_ISDIR(directory.lstat().st_mode), "unsafe_layout_directory")
        require(self.local_json("oci-layout").get("imageLayoutVersion") == "1.0.0", "unsupported_layout")
        root = self.local_json("index.json")
        require(isinstance(root.get("manifests"), list) and len(root["manifests"]) == 1, "ambiguous_root_index")
        descriptor = root["manifests"][0]
        require(descriptor.get("digest") == self.index_digest, "index_binding_mismatch")
        index = self.blob(descriptor, as_json=True)
        require(index.get("mediaType") == INDEX and isinstance(index.get("manifests"), list), "unsupported_index")
        entries = index["manifests"]
        require(1 <= len(entries) <= self.limits.manifests, "manifest_count_limit")
        images = [item for item in entries if item.get("platform") == {"os": "linux", "architecture": "amd64"}]
        require(len(images) == 1, "ambiguous_image_platform")
        self.image_digest = images[0].get("digest")
        provenance_count = 0
        for entry in entries:
            require(entry.get("mediaType") == MANIFEST, "unsupported_manifest_format")
            manifest = self.blob(entry, as_json=True)
            require(manifest.get("mediaType") == MANIFEST and manifest.get("schemaVersion") == 2,
                    "unsupported_manifest")
            require(isinstance(manifest.get("layers"), list), "missing_layers")
            config_descriptor = manifest.get("config")
            if entry == images[0]:
                require(isinstance(config_descriptor, dict) and config_descriptor.get("mediaType") == CONFIG,
                        "unsupported_config")
                config = self.blob(config_descriptor, as_json=True)
                self.config_digest = config_descriptor["digest"]
                require(config.get("os") == "linux" and config.get("architecture") == "amd64", "config_platform_mismatch")
                runtime = config.get("config", {})
                require(runtime.get("Labels", {}).get("org.opencontainers.image.revision") == self.source_sha,
                        "config_source_mismatch")
                environment = runtime.get("Env", [])
                require(isinstance(environment, list) and all(isinstance(item, str) for item in environment), "invalid_environment")
                for value in environment:
                    key, separator, content = value.partition("=")
                    require(separator, "invalid_environment")
                    if content and SENSITIVE_KEY.search(key):
                        with self.scan_unit("metadata_value"):
                            self.finding("sensitive_environment_value", "environment/" + key, self.config_digest)
                require(manifest["layers"], "empty_image_layers")
                for layer in manifest["layers"]:
                    self.scan_layer(layer)
            else:
                annotations = entry.get("annotations", {})
                require(annotations.get("vnd.docker.reference.type") == "attestation-manifest" and
                        annotations.get("vnd.docker.reference.digest") == self.image_digest,
                        "unsupported_extra_manifest")
                self.attestation_config(manifest, images[0])
                for layer in manifest["layers"]:
                    require(layer.get("mediaType") == ATTESTATION, "unsupported_attestation_format")
                    statement = self.blob(layer, as_json=True)
                    if statement.get("predicateType") == PROVENANCE:
                        self.provenance_subjects_observed += 1
                        self.provenance_subject_diagnostics = provenance_subject_summary(
                            statement.get("subject", _MISSING), self.image_digest, self.provenance_subjects_observed)
                        require(statement.get("subject") and len(statement["subject"]) == 1 and
                                statement["subject"][0].get("digest", {}).get("sha256") == self.image_digest[7:],
                                "provenance_subject_mismatch")
                        definition = statement.get("predicate", {}).get("buildDefinition", {})
                        expected = {"uri": "https://github.com/" + REPOSITORY + ".git#" + self.source_sha,
                                    "digest": {"sha1": self.source_sha}}
                        def matches(source):
                            return isinstance(source, dict) and source.get("uri") == expected["uri"] and source.get("digest", {}).get("sha1") == self.source_sha
                        require(matches(definition.get("externalParameters", {}).get("configSource")) and
                                any(matches(source) for source in definition.get("resolvedDependencies", [])),
                                "provenance_source_mismatch")
                        provenance_count += 1
        require(provenance_count > 0, "missing_source_provenance")
        self.verify_export_closure()


def inspect_layout(oci_dir, expected_index_digest, source_sha, tooling_sha, limits=None, public_comparisons=None,
                   qualify_public_members=False):
    """Return sanitized receipt; callers must require passed AND inspectionComplete."""
    inspector = Inspector(oci_dir, expected_index_digest, source_sha, tooling_sha, limits or Limits())
    structure = inspect_export_structure(oci_dir, inspector.limits)
    complete, error = False, None
    try:
        require(structure["status"] == "complete", structure["reason"] or "export_structure_refused")
        require(type(qualify_public_members) is bool, "invalid_public_member_qualification_mode")
        if public_comparisons is not None:
            inspector.load_public_comparisons(public_comparisons)
        if qualify_public_members:
            inspector.enable_public_member_qualification()
        inspector.run()
        complete = True
    except Refusal as exc:
        error = str(exc)
    except (OSError, EOFError, tarfile.TarError, zlib.error, ValueError, TypeError, KeyError,
            AttributeError, RecursionError, OverflowError):
        error = "malformed_or_unreadable_layout"
    qualification_satisfied = (not inspector.qualify_public_members or
        all(record["status"] == "matched" and
            all(inspector.qualified_public_members.get((record["id"], rule), {}).get("memberOccurrences") ==
                record["matchedMembers"] for rule in record["rules"])
            for record in inspector.public_comparisons["records"]))
    receipt = {
        "schema": "openclaw.hosted-privacy.v2",
        "status": "passed" if complete and inspector.finding_total == 0 and qualification_satisfied else "failed",
        "inspectionComplete": complete,
        "exportStructure": structure,
        "indexDigest": expected_index_digest if isinstance(expected_index_digest, str) and DIGEST.fullmatch(expected_index_digest) else None,
        "sourceSha": source_sha if isinstance(source_sha, str) and SHA.fullmatch(source_sha) else None,
        "toolingSha": tooling_sha if isinstance(tooling_sha, str) and SHA.fullmatch(tooling_sha) else None,
        "imageDigest": inspector.image_digest if isinstance(inspector.image_digest, str) and DIGEST.fullmatch(inspector.image_digest) else None,
        "configDigest": inspector.config_digest,
        "counts": inspector.counts,
        "findings": inspector.findings,
        "findingSummary": inspector.finding_summary(),
        "representativeLimit": inspector.limits.findings,
        "representativesTruncated": inspector.finding_total > len(inspector.findings),
        "locationIndex": inspector.location_index,
        "locationIndexLimit": MAX_LOCATION_ROWS,
        "locationIndexByteLimit": MAX_LOCATION_BYTES,
        "locationIndexTruncated": inspector.location_index_truncated,
        "qualifiedPublicFixtures": inspector.qualified_public_fixtures,
        "limits": dataclasses.asdict(inspector.limits),
        "limitations": LIMITATIONS,
        "heuristicOnly": True,
    }
    if error:
        receipt["refusal"] = error
    if inspector.provenance_subject_diagnostics is not None:
        receipt["provenanceSubjectDiagnostics"] = inspector.provenance_subject_diagnostics
    if inspector.public_comparisons is not None:
        receipt["publicMemberComparisons"] = {**inspector.public_comparisons, "inspectionComplete": complete}
    if inspector.qualify_public_members:
        receipt["publicMemberQualification"] = {"schema": "openclaw.public-member-qualification.v1",
            "sourceSha": inspector.source_sha, "planSha256": inspector.public_comparisons["planSha256"],
            "inspectionComplete": complete, "status": "satisfied" if complete and qualification_satisfied else "failed",
            "records": list(inspector.qualified_public_members.values())}
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oci-dir", required=True)
    parser.add_argument("--expected-index-digest", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--tooling-sha", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--public-comparisons", help="Optional reviewed public-member comparison manifest; diagnostic only")
    parser.add_argument("--qualify-public-members", action="store_true",
                        help="Qualify only the code-pinned public manifest/source and exact regular-member rules")
    args = parser.parse_args()
    # Persist a bounded safe namespace observation before any expensive parsing
    # or decompression. The data-only owner independently binds a fresh view.
    print(json.dumps({"recordType": "export_structure",
                      **inspect_export_structure(args.oci_dir)}), flush=True)
    result = inspect_layout(args.oci_dir, args.expected_index_digest, args.source_sha, args.tooling_sha,
                            public_comparisons=args.public_comparisons, qualify_public_members=args.qualify_public_members)
    encoded = json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n"
    if len(encoded.encode("utf-8")) > MAX_RECEIPT_BYTES:
        print('{"status":"failed","refusal":"receipt_size_limit"}')
        return 1
    # Exclusive creation avoids silently replacing prior inspection evidence.
    persisted = False
    try:
        with open(args.output, "x", encoding="utf-8") as output:
            output.write(encoded)
        persisted = True
    except OSError:
        # Preserve the newly computed sanitized evidence in logs even if its
        # exclusive receipt cannot be written. Never overwrite prior evidence.
        pass
    # Aggregate counts continue after the bounded per-rule representatives fill.
    # A structural refusal still makes all aggregates explicitly incomplete.
    print(json.dumps({"recordType": "summary", "schema": result["schema"],
                      "status": result["status"] if persisted else "failed",
                      **{key: result[key] for key in ("sourceSha", "toolingSha", "indexDigest",
                                                     "imageDigest", "configDigest")},
                      "receiptPersisted": persisted,
                      "persistenceRefusal": None if persisted else "receipt_write_failed",
                      "inspectionComplete": result["inspectionComplete"],
                      "findings": result["findingSummary"]["total"],
                      "findingCounts": result["findingSummary"]["byRule"],
                      "findingSummary": result["findingSummary"],
                      "retainedFindings": len(result["findings"]),
                      "representativeLimit": result["representativeLimit"],
                      "representativesTruncated": result["representativesTruncated"],
                      "indexedLocations": len(result["locationIndex"]),
                      "locationIndexLimit": result["locationIndexLimit"],
                      "locationIndexByteLimit": result["locationIndexByteLimit"],
                      "locationIndexTruncated": result["locationIndexTruncated"],
                      "qualifiedPublicFixtures": result["qualifiedPublicFixtures"],
                      "refusal": result.get("refusal")}))
    if "provenanceSubjectDiagnostics" in result:
        print(json.dumps({"recordType": "provenance_subject_diagnostics",
                          **result["provenanceSubjectDiagnostics"]}))
    # Bounded NDJSON batches avoid a single oversized Actions log line. These
    # contain only the same sanitized fields already bound in the receipt.
    for kind, values, batch_size in (("finding_details", result["findings"], 16),
                                     ("location_index", result["locationIndex"], 32)):
        for offset in range(0, len(values), batch_size):
            print(json.dumps({"recordType": kind, "offset": offset, "items": values[offset:offset + batch_size]}))
    comparison = result.get("publicMemberComparisons")
    if comparison is not None:
        print(json.dumps({"recordType": "public_member_comparison_summary",
                          **{key: value for key, value in comparison.items() if key != "records"},
                          "recordCount": len(comparison["records"])}))
        for offset in range(0, len(comparison["records"]), 16):
            print(json.dumps({"recordType": "public_member_comparisons", "planSha256": comparison["planSha256"],
                              "sourceSha": comparison["sourceSha"], "offset": offset,
                              "items": comparison["records"][offset:offset + 16]}))
    qualification = result.get("publicMemberQualification")
    if qualification is not None:
        print(json.dumps({"recordType": "public_member_qualification_summary",
                          **{key: value for key, value in qualification.items() if key != "records"},
                          "recordCount": len(qualification["records"])}))
        for offset in range(0, len(qualification["records"]), 16):
            print(json.dumps({"recordType": "qualified_public_members", "planSha256": qualification["planSha256"],
                              "sourceSha": qualification["sourceSha"], "offset": offset,
                              "items": qualification["records"][offset:offset + 16]}))
    return 0 if persisted and result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
