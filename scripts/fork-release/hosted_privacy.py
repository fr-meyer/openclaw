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
PATTERNS = (
    # A header literal is common in public crypto parsers/documentation. Require
    # a plausible body, including the optional legacy encrypted-PEM headers.
    ("private_key", re.compile(
        rb"-----BEGIN (?:[A-Z0-9 ]{0,40} )?PRIVATE KEY-----\r?\n"
        rb"(?:Proc-Type: [^\r\n]{1,80}\r?\nDEK-Info: [^\r\n]{1,160}\r?\n\r?\n)?"
        rb"[A-Za-z0-9+/]{64}")),
    ("github_token", re.compile(rb"(?:gh[pousr]_[A-Za-z0-9]{30,255}|github_pat_[A-Za-z0-9_]{30,255})")),
    ("service_token", re.compile(rb"(?:(?<![A-Za-z0-9_])sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{24,255}|xox[baprs]-[A-Za-z0-9-]{20,255})")),
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
    "Only the exact hash-bound public GnuTLS self-test is qualified; other public fixtures can cause refusals.",
    "Match lengths and syntax flags describe the first retained scan-window match, which may be a bounded prefix.",
    "Counts are rule/scan-unit pairs, not unique credentials: each TAR member occurrence, JSON key/string occurrence, explicit metadata value or standalone byte input is a unit.",
    "Overlapping chunks and path/link checks share their member unit; repeated members or layers count separately. PAX JSON has its own key/string units.",
    "Representatives use fixed per-rule quotas within 64 total; omitted representatives do not stop inspection. Counts are partial when inspectionComplete is false.",
    "The separate hashed-location index is capped at 4096 rows and 512 KiB of compact JSON; truncation does not count unique omitted locations or stop inspection.",
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


class Refusal(Exception):
    """Fixed, safe rule identifier; never carry untrusted exception messages."""


def require(condition, code):
    if not condition:
        raise Refusal(code)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def object_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


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

    def scan_bytes(self, data, location, blob_digest=None, *, previous_byte=b"", pending_private_key=None):
        if self.unit_kind is None:
            with self.scan_unit("byte_input"):
                self.scan_bytes(data, location, blob_digest, previous_byte=previous_byte,
                                pending_private_key=pending_private_key)
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
            if found:
                diagnostics = {"matchLength": found.end() - found.start(), "syntaxFlags": {
                    "leftContext": context(window[max(0, found.start() - 1):found.start()], "input_start"),
                    "rightContext": context(window[found.end():found.end() + 1], "window_end"),
                    "percentEncoded": bool(re.search(rb"%[A-Fa-f0-9]{2}", found.group())),
                }}
                if rule == "private_key" and pending_private_key is not None:
                    if not pending_private_key:
                        pending_private_key.append((rule, location, blob_digest, diagnostics))
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

    def scan_path(self, path, digest):
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
                        if member.isdir():
                            continue
                        self.scan_path(name, digest)
                        if member.issym() or member.islnk():
                            target = self.safe_name(member.linkname, link=True,
                                                    parent=name.rpartition("/")[0] if member.issym() else "")
                            self.scan_path(target, digest)
                            self.scan_bytes(member.linkname.encode("utf-8", "surrogatepass"), name, digest)
                            continue
                        self.counts["files"] += 1
                        file = archive.extractfile(member)  # A stream only: never extract to disk.
                        require(file is not None, "missing_member_stream")
                        total, tail, previous_byte = 0, b"", b""
                        public = PUBLIC_GNUTLS_SELF_TEST
                        candidate = (public["rule"] == "private_key" and public["blobDigest"] == digest and
                                     public["path"] == name and public["memberBytes"] == member.size)
                        member_hash = hashlib.sha256() if candidate else None
                        pending = []
                        try:
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
                                                pending_private_key=pending if candidate else None)
                                # Preserve lookbehind at a clipped overlap boundary;
                                # short reads retain file-start semantics until clipping.
                                previous_byte = window[-OVERLAP - 1:-OVERLAP]
                                tail = window[-OVERLAP:]
                            require(total == member.size, "truncated_member")
                            if pending and member_hash.hexdigest() == public["memberSha256"]:
                                qualification = {key: public[key] for key in
                                    ("rule", "blobDigest", "memberSha256", "memberBytes", "publicSourceSha256")}
                                qualification["locationSha256"] = sha256(name.encode("utf-8", "surrogatepass"))
                                if qualification not in self.qualified_public_fixtures:
                                    self.qualified_public_fixtures.append(qualification)
                                pending.clear()
                        finally:
                            # An incomplete read or different byte hash never qualifies.
                            for finding in pending:
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
        for directory, expected in (
                (self.directory, {"oci-layout", "index.json", "blobs"}),
                (self.directory / "blobs", {"sha256"}),
                (self.directory / "blobs" / "sha256", {digest[7:] for digest in self.blobs})):
            seen = set()
            with os.scandir(directory) as entries:
                for entry in entries:
                    require(entry.name in expected and not entry.is_symlink(), "unexpected_export_entry")
                    seen.add(entry.name)
                    require(len(seen) <= self.limits.blobs + 3, "export_entry_limit")
            require(seen == expected, "missing_export_entry")

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


def inspect_layout(oci_dir, expected_index_digest, source_sha, tooling_sha, limits=None):
    """Return sanitized receipt; callers must require passed AND inspectionComplete."""
    inspector = Inspector(oci_dir, expected_index_digest, source_sha, tooling_sha, limits or Limits())
    complete, error = False, None
    try:
        inspector.run()
        complete = True
    except Refusal as exc:
        error = str(exc)
    except (OSError, EOFError, tarfile.TarError, zlib.error, ValueError, TypeError, KeyError,
            AttributeError, RecursionError, OverflowError):
        error = "malformed_or_unreadable_layout"
    receipt = {
        "schema": "openclaw.hosted-privacy.v2",
        "status": "passed" if complete and inspector.finding_total == 0 else "failed",
        "inspectionComplete": complete,
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
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oci-dir", required=True)
    parser.add_argument("--expected-index-digest", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--tooling-sha", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = inspect_layout(args.oci_dir, args.expected_index_digest, args.source_sha, args.tooling_sha)
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
    # Bounded NDJSON batches avoid a single oversized Actions log line. These
    # contain only the same sanitized fields already bound in the receipt.
    for kind, values, batch_size in (("finding_details", result["findings"], 16),
                                     ("location_index", result["locationIndex"], 32)):
        for offset in range(0, len(values), batch_size):
            print(json.dumps({"recordType": kind, "offset": offset, "items": values[offset:offset + batch_size]}))
    return 0 if persisted and result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
