#!/usr/bin/env python3
"""Prepare one opaque private OCI archive with an explicit byte identity.

The reviewed 918890b9 producer algorithm is retained; source identity is supplied
explicitly by the separately authenticated v109 caller. This module neither
authenticates a producer nor authorizes source, access or execution.

Prepare a private unqualified OCI tar; never upload, execute or grant custody.

GitHub attestation and canonical run/step verification remain the receiver's
responsibility. A matching producer document alone is not build authority.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tarfile

import hosted_bundle as bundle
import hosted_privacy as privacy
import hosted_reinspection as inspection

MAX_BYTES = bundle.MAX_BYTES
CHUNK = bundle.CHUNK
ORIGINAL_FILES = ("build-origin.json", "build-metadata.json", "manifest.json", "patch-inventory.json", "resources.json")
INVENTORY_FILE = "export-inventory.json"
FILES = ORIGINAL_FILES + (INVENTORY_FILE,)
MAX_ENTRIES, MAX_DEPTH, MAX_PATH_BYTES = 2048, 16, 88
INVENTORY_SCHEMA = "openclaw.private-export-inventory.v1"
OCI = "oci/default/"
NAME = "retained-oci.tar"
SHA = re.compile(r"[0-9a-f]{40}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
DECIMAL = re.compile(r"[1-9][0-9]{0,19}\Z")
ORIGIN_FIELDS = {"schema", "repository", "producer", "sourceSha", "sourceTree", "manifestSha256",
                 "inventorySha256", "indexDigest", "builtAt", "buildMetadataSha256", "resourcesSha256"}


class Refusal(ValueError):
    pass


def need(value, code):
    if not value:
        raise Refusal(code)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(path):
    path = Path(path).absolute()
    need(path.resolve() == path, "path_not_canonical")
    return path


def distinct(left, right):
    need(left != right and left not in right.parents and right not in left.parents, "paths_overlap")


def private_json(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(encoded(value))
        stream.flush()
        os.fsync(stream.fileno())


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def safe_relative(name):
    need(isinstance(name, str) and 0 < len(name) <= MAX_PATH_BYTES and name.isascii() and
         all(32 <= ord(char) <= 126 and char != "\\" for char in name) and
         len(name.split("/")) <= MAX_DEPTH and all(part not in ("", ".", "..") for part in name.split("/")),
         "export_path_refused")
    return name


def validate_inventory(value):
    need(isinstance(value, dict) and set(value) == {"schema", "entries"} and
         value["schema"] == INVENTORY_SCHEMA and isinstance(value["entries"], list) and
         0 < len(value["entries"]) <= MAX_ENTRIES, "export_inventory_invalid")
    seen, previous, total, blobs = {}, "", 0, 0
    for entry in value["entries"]:
        need(isinstance(entry, dict), "export_inventory_invalid")
        name, kind = safe_relative(entry.get("path")), entry.get("kind")
        need(name > previous and kind in ("file", "directory") and
             set(entry) == ({"path", "kind"} if kind == "directory" else {"path", "kind", "size", "sha256"}),
             "export_inventory_invalid")
        previous = name
        parent = name.rpartition("/")[0]
        need(not parent or seen.get(parent) == "directory", "export_inventory_parent")
        if kind == "file":
            need(type(entry["size"]) is int and 0 <= entry["size"] <= MAX_BYTES and
                 isinstance(entry["sha256"], str) and HEX.fullmatch(entry["sha256"]), "export_inventory_invalid")
            total += entry["size"]
            need(total <= MAX_BYTES, "archive_size_limit")
            if name.startswith("blobs/sha256/"):
                blobs += 1
                need(blobs <= privacy.Limits().blobs, "blob_count_limit")
        seen[name] = kind
    need(seen.get("index.json") == seen.get("oci-layout") == "file" and
         seen.get("blobs") == seen.get("blobs/sha256") == "directory" and blobs > 0, "missing_oci_entry")
    return value


class Inputs:
    """Fixed archive namespace over small control files and the original OCI.

    Existing Inputs owns safe descriptor-relative reads and fingerprint checks;
    no blob copy, symlink or hardlink is needed to assemble the namespace.
    """
    def __init__(self, controls, oci_dir):
        self.root, self.oci_root = canonical(controls), canonical(oci_dir)
        distinct(self.root, self.oci_root)
        self.control = bundle.Inputs(self.root)
        try:
            self.oci = bundle.Inputs(self.oci_root)
        except BaseException:
            self.control.close()
            raise
        self.snapshots, self.hashes = {}, {}

    def close(self):
        self.control.close()
        self.oci.close()

    def open(self, name, limit):
        if name in FILES:
            reader, relative = self.control, name
        else:
            need(isinstance(name, str) and name.startswith(OCI), "member_not_allowed")
            reader, relative = self.oci, name[len(OCI):]
        stream, info = reader.open(relative, limit)
        try:
            need(info.st_nlink == 1, "input_hardlink")
            need(self.snapshots.setdefault(name, bundle.fingerprint(info)) == bundle.fingerprint(info), "input_changed")
            return stream, info
        except BaseException:
            stream.close()
            raise

    data = bundle.Inputs.data

    def oci_inventory(self):
        """Snapshot every safe regular file and directory; never qualify OCI."""
        entries, directories, total, blobs = [], {}, 0, 0

        def walk(descriptor, relative):
            nonlocal total, blobs
            before = os.fstat(descriptor)
            names = []
            with os.scandir(descriptor) as children:
                for child in children:
                    name = (relative + "/" if relative else "") + child.name
                    safe_relative(name)
                    need(len(entries) < MAX_ENTRIES, "export_entry_limit")
                    info = os.stat(child.name, dir_fd=descriptor, follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        entry = {"path": name, "kind": "directory"}
                    else:
                        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "export_type_or_link")
                        total += info.st_size
                        need(total <= MAX_BYTES, "archive_size_limit")
                        if name.startswith("blobs/sha256/"):
                            blobs += 1
                            need(blobs <= privacy.Limits().blobs, "blob_count_limit")
                        stream, opened = self.open(OCI + name, MAX_BYTES)
                        hashed, count = hashlib.sha256(), 0
                        with stream:
                            while chunk := stream.read(CHUNK):
                                count += len(chunk)
                                need(count <= opened.st_size, "input_changed")
                                hashed.update(chunk)
                            need(count == opened.st_size and bundle.fingerprint(opened) ==
                                 bundle.fingerprint(os.fstat(stream.fileno())), "input_changed")
                        digest = hashed.hexdigest()
                        if re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", name):
                            need(digest == name.rsplit("/", 1)[1], "input_digest_changed")
                        need(self.hashes.setdefault(OCI + name, digest) == digest, "input_changed")
                        entry = {"path": name, "kind": "file", "size": count, "sha256": digest}
                    names.append((child.name, entry["kind"]))
                    entries.append(entry)
                    if entry["kind"] == "directory":
                        fd = os.open(child.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                        try:
                            need(bundle.fingerprint(info) == bundle.fingerprint(os.fstat(fd)), "input_changed")
                            walk(fd, name)
                        finally:
                            os.close(fd)
            need(bundle.fingerprint(before) == bundle.fingerprint(os.fstat(descriptor)), "input_changed")
            snapshot = (bundle.fingerprint(before), tuple(sorted(names)))
            need(self.directories.setdefault(relative, snapshot) == snapshot, "oci_inventory_changed")
            directories[relative] = snapshot

        if not hasattr(self, "directories"):
            self.directories = {}
        walk(self.oci.fd, "")
        value = {"schema": INVENTORY_SCHEMA, "entries": sorted(entries, key=lambda entry: entry["path"])}
        validate_inventory(value)
        need(set(directories) == set(self.directories), "oci_inventory_changed")
        return value

    def oci_specs(self):
        inventory = self.oci_inventory()
        specs = {}
        for entry in inventory["entries"]:
            specs[OCI + entry["path"]] = ({"kind": "directory", "size": 0, "sha256": sha(b"")}
                if entry["kind"] == "directory" else
                {"kind": "file", "size": entry["size"], "sha256": entry["sha256"]})
        return inventory, specs

    def check_tree(self, specs):
        # Reopen all inputs with no-follow and compare the complete directory
        # identities/names/types after streaming. Never silently omit extras.
        expected = {name[len(OCI):]: spec for name, spec in specs.items() if name.startswith(OCI)}
        seen_directories, seen_files = set(), set()

        def walk(descriptor, relative):
            before = os.fstat(descriptor)
            names = []
            with os.scandir(descriptor) as children:
                for child in children:
                    name = (relative + "/" if relative else "") + child.name
                    safe_relative(name)
                    info = os.stat(child.name, dir_fd=descriptor, follow_symlinks=False)
                    kind = "directory" if stat.S_ISDIR(info.st_mode) else "file"
                    need(name in expected and kind == expected[name]["kind"] and
                         (stat.S_ISDIR(info.st_mode) if kind == "directory" else stat.S_ISREG(info.st_mode)),
                         "oci_inventory_changed")
                    names.append((child.name, kind))
                    if kind == "directory":
                        seen_directories.add(name)
                        fd = os.open(child.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                        try:
                            walk(fd, name)
                        finally:
                            os.close(fd)
                    else:
                        seen_files.add(name)
                        stream, _ = self.open(OCI + name, MAX_BYTES)
                        stream.close()
            need(bundle.fingerprint(before) == bundle.fingerprint(os.fstat(descriptor)) and
                 self.directories.get(relative) == (bundle.fingerprint(before), tuple(sorted(names))),
                 "oci_inventory_changed")
        walk(self.oci.fd, "")
        need(seen_files | seen_directories == set(expected), "oci_inventory_changed")
        seen = set()
        with os.scandir(self.root) as entries:
            for entry in entries:
                need(entry.name in FILES and not entry.is_symlink(), "unexpected_control_file")
                seen.add(entry.name)
        need(seen == set(FILES), "unexpected_control_file")
        for reader in (self.control, self.oci):
            current = reader.root.lstat()
            need((current.st_dev, current.st_ino) == (reader.root_identity.st_dev, reader.root_identity.st_ino), "input_root_changed")
        for name, spec in specs.items():
            if spec["kind"] == "file":
                stream, _ = self.open(name, MAX_BYTES)
                stream.close()


def inspect_inputs(inputs, expected=None, *, source_sha, source_tree):
    need(isinstance(source_sha, str) and SHA.fullmatch(source_sha) and
         isinstance(source_tree, str) and SHA.fullmatch(source_tree), "expected_identity")
    parser = privacy.Inspector(inputs.root, None, None, None, privacy.Limits())
    values = {name: parser.parse_json(inputs.data(name, bundle.RECEIPT_BYTES)) for name in FILES}
    origin, metadata, manifest, inventory, resources = (values[name] for name in ORIGINAL_FILES)
    export_inventory = validate_inventory(values[INVENTORY_FILE])
    need(isinstance(origin, dict) and set(origin) == ORIGIN_FIELDS and
         origin.get("schema") == "openclaw.hosted-build-custody.v1" and origin.get("repository") == "fr-meyer/openclaw" and
         origin.get("sourceSha") == source_sha and origin.get("sourceTree") == source_tree, "origin_binding")
    producer = origin.get("producer")
    need(isinstance(producer, dict) and set(producer) == {"workflowSha", "runId", "attempt"} and
         isinstance(producer.get("workflowSha"), str) and SHA.fullmatch(producer["workflowSha"]) and
         all(isinstance(producer.get(key), str) and DECIMAL.fullmatch(producer[key]) for key in ("runId", "attempt")), "producer_binding")
    if expected is not None:
        need(producer == expected, "expected_producer_changed")
    need(inspection.timestamp(origin.get("builtAt")) <= datetime.now(timezone.utc), "build_time")
    need(all(isinstance(origin.get(key), str) and HEX.fullmatch(origin[key]) for key in
             ("manifestSha256", "inventorySha256", "buildMetadataSha256", "resourcesSha256")) and
         isinstance(origin.get("indexDigest"), str) and privacy.DIGEST.fullmatch(origin["indexDigest"]), "origin_hashes")
    need(origin["manifestSha256"] == inputs.hashes["manifest.json"] and
         origin["inventorySha256"] == inputs.hashes["patch-inventory.json"] and
         origin["buildMetadataSha256"] == inputs.hashes["build-metadata.json"] and
         origin["resourcesSha256"] == inputs.hashes["resources.json"], "control_hash_changed")
    need(isinstance(metadata, dict) and metadata.get("containerimage.digest") == origin["indexDigest"], "docker_metadata_binding")
    if "containerimage.descriptor" in metadata:
        need(isinstance(metadata["containerimage.descriptor"], dict) and
             metadata["containerimage.descriptor"].get("digest") == origin["indexDigest"], "docker_descriptor_binding")
    need(isinstance(manifest, dict) and manifest.get("schema") == "openclaw.fork-release.v1" and
         manifest.get("repository") == "fr-meyer/openclaw" and manifest.get("source", {}).get("commit") == source_sha and
         manifest.get("source", {}).get("tree") == source_tree and manifest.get("image") ==
         {"architecture": "amd64", "extensions": "codex,workboard"}, "manifest_binding")
    need(isinstance(inventory, dict) and inventory.get("schema") == "openclaw.fork-patch-inventory.v1" and
         inventory.get("repository") == "fr-meyer/openclaw" and
         inventory.get("manifestSha256") == origin["manifestSha256"], "inventory_binding")
    need(isinstance(resources, dict) and resources.get("schema") == "openclaw.hosted-resources.v1" and
         resources.get("sourceSha") == source_sha and resources.get("toolingSha") == producer["workflowSha"] and
         resources.get("indexDigest") == origin["indexDigest"], "resources_binding")
    specs = {name: {"kind": "file", "size": info["size"], "sha256": inputs.hashes[name]} for name, info in inputs.snapshots.items()
             if name in FILES}
    # Retention authenticates an opaque byte inventory. Image structure,
    # provenance subjects and privacy remain the unchanged qualifier's job.
    actual_inventory, oci_specs = inputs.oci_specs()
    need(actual_inventory == export_inventory, "export_inventory_changed")
    specs.update(oci_specs)
    inputs.check_tree(specs)
    return origin, specs


def closure_hash(specs):
    """Bind every retained OCI file; this is not image graph qualification."""
    return sha(encoded([{ "path": name, **specs[name]} for name in sorted(specs) if name.startswith(OCI)]))


def archive_size(specs):
    payload = sum(512 + ((spec["size"] + 511) // 512) * 512 for spec in specs.values() if spec.get("kind", "file") == "file") + 1024
    return ((payload + tarfile.RECORDSIZE - 1) // tarfile.RECORDSIZE) * tarfile.RECORDSIZE


def header(name, size):
    value = tarfile.TarInfo(name)
    value.size, value.mode, value.uid, value.gid, value.mtime = size, 0o600, 0, 0, 0
    value.uname = value.gname = ""
    return value.tobuf(format=tarfile.USTAR_FORMAT, encoding="utf-8", errors="strict")


def write_tar(inputs, specs, path, limit):
    need(archive_size(specs) <= limit, "archive_size_limit")
    with open(path, "xb") as raw:
        os.fchmod(raw.fileno(), 0o600)
        writer = bundle.BoundedWriter(raw, limit)
        for name, spec in sorted(specs.items()):
            if spec["kind"] == "directory":
                continue
            writer.write(header(name, spec["size"]))
            stream, before = inputs.open(name, MAX_BYTES)
            hashed, count = hashlib.sha256(), 0
            with stream:
                while True:
                    chunk = stream.read(CHUNK)
                    if not chunk:
                        break
                    count += len(chunk)
                    need(count <= spec["size"], "input_changed")
                    hashed.update(chunk)
                    writer.write(chunk)
                need(count == spec["size"] and hashed.hexdigest() == spec["sha256"], "input_digest_changed")
                need(bundle.fingerprint(before) == bundle.fingerprint(os.fstat(stream.fileno())), "input_changed")
            writer.write(bytes((-count) % 512))
        writer.write(bytes(archive_size(specs) - writer.tell()))
        raw.flush()
        os.fsync(raw.fileno())
    inputs.check_tree(specs)


def read_control(path):
    path = canonical(path)
    reader = bundle.Inputs(path.parent)
    try:
        raw = reader.data(path.name, bundle.RECEIPT_BYTES)
        need(reader.snapshots[path.name]["nlink"] == 1, "input_hardlink")
        return raw, reader.snapshots[path.name]
    finally:
        reader.close()


def prepare_from_build(manifest_path, inventory_path, metadata_path, resources_path, oci_dir, output_dir, output,
                       *, source_sha, source_tree, workflow_sha, run_id, attempt, built_at, limit=MAX_BYTES):
    need(type(limit) is int and 0 < limit <= MAX_BYTES, "archive_size_limit")
    need(isinstance(source_sha, str) and SHA.fullmatch(source_sha) and
         isinstance(source_tree, str) and SHA.fullmatch(source_tree) and
         isinstance(workflow_sha, str) and SHA.fullmatch(workflow_sha) and
         all(isinstance(value, str) and DECIMAL.fullmatch(value) for value in (run_id, attempt)), "expected_identity")
    inspection.timestamp(built_at)
    original_paths = (manifest_path, inventory_path, metadata_path, resources_path)
    original_inputs = [read_control(path) for path in original_paths]
    manifest, inventory, metadata, resources = (item[0] for item in original_inputs)
    parsed = json.loads(metadata, object_pairs_hook=privacy.object_pairs)
    need(isinstance(parsed, dict) and isinstance(parsed.get("containerimage.digest"), str) and
         privacy.DIGEST.fullmatch(parsed["containerimage.digest"]), "docker_metadata_binding")
    output_dir, output, oci_dir = (canonical(path) for path in (output_dir, output, oci_dir))
    distinct(output_dir, oci_dir)
    distinct(output, output_dir)
    distinct(output, oci_dir)
    for path in (manifest_path, inventory_path, metadata_path, resources_path):
        distinct(output_dir, canonical(path))
        distinct(output, canonical(path))
    need(not output.exists() and not output.is_symlink(), "receipt_exists")
    directory = bundle.output_directory(output_dir)
    controls = directory / "origin"
    controls.mkdir(mode=0o700)
    origin = {"schema": "openclaw.hosted-build-custody.v1", "repository": "fr-meyer/openclaw",
              "producer": {"workflowSha": workflow_sha, "runId": run_id, "attempt": attempt},
              "sourceSha": source_sha, "sourceTree": source_tree, "manifestSha256": sha(manifest),
              "inventorySha256": sha(inventory), "indexDigest": parsed["containerimage.digest"],
              "builtAt": built_at, "buildMetadataSha256": sha(metadata), "resourcesSha256": sha(resources)}
    private_json(controls / "build-origin.json", origin)
    for name, raw in zip(ORIGINAL_FILES[1:], (metadata, manifest, inventory, resources)):
        descriptor = os.open(controls / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    sync_directory(controls)
    inputs = Inputs(controls, oci_dir)
    partial, final = directory / ".partial", directory / NAME
    try:
        private_json(controls / INVENTORY_FILE, inputs.oci_inventory())
        sync_directory(controls)
        origin, specs = inspect_inputs(inputs, origin["producer"], source_sha=source_sha, source_tree=source_tree)
        write_tar(inputs, specs, partial, limit)
        need(all(read_control(path) == saved for path, saved in zip(original_paths, original_inputs)), "original_control_changed")
        archive_hash, info = bundle.hash_file(partial, limit)
        need(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1, "archive_permissions")
        inputs.check_tree(specs)
        os.link(partial, final, follow_symlinks=False)
        partial.unlink()
        sync_directory(directory)
        result = {"schema": "openclaw.private-oci-bundle.v2", "status": "prepared", "qualified": False,
                  "productionAuthorized": False, "publicExportAuthorized": False,
                  "retentionValidation": "opaque_byte_inventory",
                  "originAuthority": "native_github_attestation_and_run_verification_required",
                  "format": "USTAR", "archivePath": str(final), "archiveSha256": archive_hash,
                  "archiveBytes": info.st_size, "maximumBytes": MAX_BYTES, "sourceSha": source_sha,
                  "sourceTree": source_tree, "producer": origin["producer"], "builtAt": built_at,
                  "manifestSha256": origin["manifestSha256"], "inventorySha256": origin["inventorySha256"],
                  "buildMetadataSha256": origin["buildMetadataSha256"], "originSha256": inputs.hashes["build-origin.json"],
                  "resourcesSha256": origin["resourcesSha256"],
                  "indexDigest": origin["indexDigest"], "indexSha256": inputs.hashes[OCI + "index.json"],
                  "ociClosureSha256": closure_hash(specs), "exportInventorySha256": inputs.hashes[INVENTORY_FILE],
                  "memberCount": sum(spec["kind"] == "file" for spec in specs.values()),
                  "exportEntryCount": len(specs) - len(FILES)}
        private_json(output, result)
        sync_directory(output.parent)
        return result
    except BaseException:
        if partial.exists():
            partial.unlink()
        # Only this fresh operation owns its partial/final archive. Control
        # evidence remains private; no original OCI or input file is removed.
        if final.exists():
            final.unlink()
        raise
    finally:
        inputs.close()

