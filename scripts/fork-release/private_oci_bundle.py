#!/usr/bin/env python3
"""Prepare a private unqualified OCI tar; never upload, execute or grant custody.

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
SOURCE = "30786562e236aab6a924981c62aa61b920132c76"
TREE = "2c7d245a5abe5b4ecfd4477f7890f00aaa3deeff"
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


def inspect_inputs(inputs, expected=None):
    parser = privacy.Inspector(inputs.root, None, None, None, privacy.Limits())
    values = {name: parser.parse_json(inputs.data(name, bundle.RECEIPT_BYTES)) for name in FILES}
    origin, metadata, manifest, inventory, resources = (values[name] for name in ORIGINAL_FILES)
    export_inventory = validate_inventory(values[INVENTORY_FILE])
    need(isinstance(origin, dict) and set(origin) == ORIGIN_FIELDS and
         origin.get("schema") == "openclaw.hosted-build-custody.v1" and origin.get("repository") == "fr-meyer/openclaw" and
         origin.get("sourceSha") == SOURCE and origin.get("sourceTree") == TREE, "origin_binding")
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
         manifest.get("repository") == "fr-meyer/openclaw" and manifest.get("source", {}).get("commit") == SOURCE and
         manifest.get("source", {}).get("tree") == TREE and manifest.get("image") ==
         {"architecture": "amd64", "extensions": "codex,workboard"}, "manifest_binding")
    need(isinstance(inventory, dict) and inventory.get("schema") == "openclaw.fork-patch-inventory.v1" and
         inventory.get("repository") == "fr-meyer/openclaw" and
         inventory.get("manifestSha256") == origin["manifestSha256"], "inventory_binding")
    need(isinstance(resources, dict) and resources.get("schema") == "openclaw.hosted-resources.v1" and
         resources.get("sourceSha") == SOURCE and resources.get("toolingSha") == producer["workflowSha"] and
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
    need(source_sha == SOURCE and source_tree == TREE and isinstance(workflow_sha, str) and SHA.fullmatch(workflow_sha) and
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
              "sourceSha": SOURCE, "sourceTree": TREE, "manifestSha256": sha(manifest),
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
        origin, specs = inspect_inputs(inputs, origin["producer"])
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
                  "archiveBytes": info.st_size, "maximumBytes": MAX_BYTES, "sourceSha": SOURCE,
                  "sourceTree": TREE, "producer": origin["producer"], "builtAt": built_at,
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


def verify_archive(archive_path, archive_sha256, *, oci_dir, manifest_path, inventory_path, metadata_path, resources_path, origin_path):
    """Read-only exact member comparison; no extraction, native or trust grant."""
    need(isinstance(archive_sha256, str) and HEX.fullmatch(archive_sha256), "archive_hash")
    controls = canonical(origin_path).parent
    need(all(canonical(path) == controls / name for path, name in (
        (origin_path, "build-origin.json"), (metadata_path, "build-metadata.json"),
        (manifest_path, "manifest.json"), (inventory_path, "patch-inventory.json"), (resources_path, "resources.json"))), "control_paths")
    inputs = Inputs(controls, oci_dir)
    try:
        _, specs = inspect_inputs(inputs)
        stream, before = bundle.regular(canonical(archive_path), MAX_BYTES)
        hashed, count = hashlib.sha256(), 0
        with stream:
            need(before.st_nlink == 1 and before.st_uid == os.getuid() and stat.S_IMODE(before.st_mode) == 0o600 and
                 before.st_size == archive_size(specs), "archive_type_or_size")
            def read(size):
                nonlocal count
                data = stream.read(size)
                need(len(data) == size, "archive_truncated")
                count += len(data)
                hashed.update(data)
                return data
            for name, spec in sorted(specs.items()):
                if spec["kind"] == "directory":
                    continue
                need(read(512) == header(name, spec["size"]), "archive_header_changed")
                original, info = inputs.open(name, MAX_BYTES)
                member_hash, remaining = hashlib.sha256(), spec["size"]
                with original:
                    while remaining:
                        data = read(min(CHUNK, remaining))
                        need(original.read(len(data)) == data, "archive_member_changed")
                        member_hash.update(data)
                        remaining -= len(data)
                    need(member_hash.hexdigest() == spec["sha256"] and
                         bundle.fingerprint(info) == bundle.fingerprint(os.fstat(original.fileno())), "input_digest_changed")
                need(not any(read((-spec["size"]) % 512)), "archive_padding_changed")
            need(not any(read(before.st_size - count)) and not stream.read(1), "archive_tail_changed")
            need(bundle.fingerprint(before) == bundle.fingerprint(os.fstat(stream.fileno())), "archive_changed")
        need(hashed.hexdigest() == archive_sha256, "archive_hash_changed")
        inputs.check_tree(specs)
        return {"archiveSha256": archive_sha256, "archiveBytes": count, "ociClosureSha256": closure_hash(specs),
                "memberCount": sum(spec["kind"] == "file" for spec in specs.values()),
                "exportInventorySha256": inputs.hashes[INVENTORY_FILE], "retentionValidation": "opaque_byte_inventory",
                "qualified": False, "productionAuthorized": False}
    finally:
        inputs.close()


def _private_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
             stat.S_IMODE(info.st_mode) == 0o700, "parent_not_private_owned")
        return descriptor, info
    except BaseException:
        os.close(descriptor)
        raise


def _same_inode(left, right):
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _write_all(descriptor, raw):
    offset = 0
    while offset < len(raw):
        count = os.write(descriptor, raw[offset:])
        need(count > 0, "receipt_short_write")
        offset += count


def extract_archive(archive_path, archive_sha256, archive_bytes, output_dir, receipt):
    """Reconstruct the signed opaque inventory as private data, never execute it.

    The caller authenticates the signed archive before extraction; this owner
    verifies its exact byte hash, safe canonical headers and typed inventory.
    Failure preserves the original archive, partial output and an honest receipt.
    """
    archive, output, receipt = (canonical(value) for value in (archive_path, output_dir, receipt))
    need(isinstance(archive_sha256, str) and HEX.fullmatch(archive_sha256), "expected_hash")
    need(type(archive_bytes) is int and 0 < archive_bytes <= MAX_BYTES, "expected_size")
    need(output.parent == receipt.parent and receipt not in (archive, output) and
         output not in archive.parents and output not in receipt.parents, "output_overlap")
    source_parent, source_parent_info = _private_directory(archive.parent)
    destination_parent = source_fd = receipt_fd = root_fd = None
    directories = {}
    result = {"schema": "openclaw.private-oci-unpack.v2", "status": "started",
              "archiveSha256": archive_sha256, "archiveBytes": archive_bytes,
              "dataOnly": True, "originAuthenticated": False, "qualified": False,
              "nativeExecuted": False, "productionAuthorized": False,
              "partialOutputPreserved": False}
    try:
        destination_parent, destination_parent_info = _private_directory(output.parent)
        try:
            os.stat(output.name, dir_fd=destination_parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise Refusal("output_exists")
        source_fd = os.open(archive.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=source_parent)
        before = os.fstat(source_fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and
             before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600 and
             before.st_size == archive_bytes, "archive_not_private_regular_or_size")
        receipt_fd = os.open(receipt.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=destination_parent)
        os.fchmod(receipt_fd, 0o600)
        _write_all(receipt_fd, encoded(result))
        os.fsync(receipt_fd)
        os.fsync(destination_parent)
        os.mkdir(output.name, 0o700, dir_fd=destination_parent)
        result["partialOutputPreserved"] = True
        root_fd = os.open(output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                          dir_fd=destination_parent)
        os.fchmod(root_fd, 0o700)
        output_info = os.fstat(root_fd)
        directories[""] = output_info
        os.fsync(destination_parent)

        def directory_fd(relative):
            # Keep only the output root open. Reopening each verified chain
            # bounds descriptors independently of the inventory's entry count.
            descriptor, prefix = os.dup(root_fd), ""
            try:
                need(_same_inode(os.fstat(descriptor), directories[""]), "output_identity_changed")
                for component in relative.split("/") if relative else ():
                    prefix = (prefix + "/" if prefix else "") + component
                    next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                      dir_fd=descriptor)
                    os.close(descriptor)
                    descriptor = next_fd
                    info = os.fstat(descriptor)
                    need(prefix in directories and _same_inode(info, directories[prefix]) and
                         stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
                         stat.S_IMODE(info.st_mode) == 0o700, "output_identity_changed")
                return descriptor
            except BaseException:
                os.close(descriptor)
                raise

        def create_directory(relative):
            parent, _, component = relative.rpartition("/")
            need(parent in directories, "inventory_parent_missing")
            parent_fd = directory_fd(parent)
            child_fd = None
            try:
                os.mkdir(component, 0o700, dir_fd=parent_fd)
                child_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                   dir_fd=parent_fd)
                os.fchmod(child_fd, 0o700)
                directories[relative] = os.fstat(child_fd)
                os.fsync(child_fd)
                os.fsync(parent_fd)
            finally:
                if child_fd is not None:
                    os.close(child_fd)
                os.close(parent_fd)

        for name in ("origin", "oci", "oci/default"):
            create_directory(name)
        hashed, consumed, specs, previous, inventory = hashlib.sha256(), 0, {}, "", None
        expected_files = {}
        with os.fdopen(source_fd, "rb") as stream:
            source_fd = None

            def read(size):
                nonlocal consumed
                need(type(size) is int and 0 < size <= CHUNK and consumed + size <= archive_bytes,
                     "read_bound_or_truncated")
                value = stream.read(size)
                need(len(value) == size, "archive_truncated")
                consumed += size
                hashed.update(value)
                return value

            while True:
                raw = read(512)
                if not any(raw):
                    while consumed < archive_bytes:
                        need(not any(read(min(CHUNK, archive_bytes - consumed))), "nonzero_archive_tail")
                    break
                try:
                    name = raw[:100].split(b"\0", 1)[0].decode("ascii")
                    size = int(raw[124:136].split(b"\0", 1)[0].strip(), 8)
                except (UnicodeError, ValueError):
                    raise Refusal("invalid_header") from None
                need(name in FILES or name.startswith(OCI), "member_namespace_refused")
                need(name > previous, "member_order_or_duplicate")
                need(0 <= size <= MAX_BYTES and size <= archive_bytes - consumed, "member_size")
                need(raw == header(name, size), "noncanonical_or_nonregular_header")
                if name in FILES:
                    need(size <= bundle.RECEIPT_BYTES, "control_size")
                else:
                    safe_relative(name[len(OCI):])
                    need(inventory is not None and name in expected_files and
                         expected_files[name]["size"] == size, "inventory_member_mismatch")
                previous = name
                parent, _, filename = name.rpartition("/")
                if name in FILES:
                    parent = "origin"
                need(parent in directories, "inventory_parent_missing")
                parent_fd = directory_fd(parent)
                try:
                    descriptor = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                         0o600, dir_fd=parent_fd)
                finally:
                    os.close(parent_fd)
                member_hash, remaining, control = hashlib.sha256(), size, bytearray()
                with os.fdopen(descriptor, "wb") as destination:
                    os.fchmod(destination.fileno(), 0o600)
                    while remaining:
                        value = read(min(CHUNK, remaining))
                        destination.write(value)
                        member_hash.update(value)
                        if name == INVENTORY_FILE:
                            control.extend(value)
                        remaining -= len(value)
                    destination.flush()
                    os.fsync(destination.fileno())
                digest = member_hash.hexdigest()
                if name.startswith(OCI):
                    need(digest == expected_files[name]["sha256"], "inventory_member_hash")
                    if re.fullmatch(r"oci/default/blobs/sha256/[0-9a-f]{64}", name):
                        need(digest == name.rsplit("/", 1)[1], "blob_digest_mismatch")
                padding = (-size) % 512
                if padding:
                    need(not any(read(padding)), "nonzero_member_padding")
                specs[name] = {"kind": "file", "size": size, "sha256": digest}
                if name == INVENTORY_FILE:
                    inventory = validate_inventory(json.loads(control, object_pairs_hook=privacy.object_pairs))
                    for entry in inventory["entries"]:
                        location = OCI + entry["path"]
                        if entry["kind"] == "file":
                            expected_files[location] = entry
                            continue
                        create_directory(location)
                        specs[location] = {"kind": "directory", "size": 0, "sha256": sha(b"")}
            need(set(FILES) <= set(specs) and inventory is not None and
                 {name for name, spec in specs.items() if name.startswith(OCI) and spec["kind"] == "file"} ==
                 set(expected_files), "incomplete_namespace")
            need(archive_bytes == archive_size(specs), "noncanonical_archive_size")
            need(not stream.read(1) and bundle.fingerprint(before) == bundle.fingerprint(os.fstat(stream.fileno())),
                 "archive_changed")
        need(hashed.hexdigest() == archive_sha256, "archive_hash_mismatch")
        need(_same_inode(before, os.stat(archive.name, dir_fd=source_parent, follow_symlinks=False)) and
             _same_inode(source_parent_info, archive.parent.lstat()) and
             _same_inode(destination_parent_info, output.parent.lstat()) and
             _same_inode(output_info, os.stat(output.name, dir_fd=destination_parent, follow_symlinks=False)),
             "path_identity_changed")
        result.update(status="extracted_unqualified", memberCount=sum(spec["kind"] == "file" for spec in specs.values()),
                      memberBytes=sum(spec["size"] for spec in specs.values()),
                      exportEntryCount=len(inventory["entries"]), ociClosureSha256=closure_hash(specs),
                      exportInventorySha256=specs[INVENTORY_FILE]["sha256"],
                      controlSha256={name: specs[name]["sha256"] for name in FILES})
    except (Refusal, OSError, ValueError, TypeError, RecursionError, OverflowError) as error:
        result.update(status="refused", reason=str(error) if isinstance(error, Refusal) else "unpack_io_refused")
    finally:
        if root_fd is not None:
            for relative in reversed(list(directories)):
                descriptor = None
                try:
                    descriptor = directory_fd(relative)
                    os.fsync(descriptor)
                except (OSError, Refusal):
                    result.update(status="refused", reason="output_identity_changed")
                finally:
                    if descriptor is not None:
                        os.close(descriptor)
            os.close(root_fd)
        if receipt_fd is not None:
            os.lseek(receipt_fd, 0, os.SEEK_SET)
            os.ftruncate(receipt_fd, 0)
            _write_all(receipt_fd, encoded(result))
            os.fsync(receipt_fd)
            os.close(receipt_fd)
        if destination_parent is not None:
            os.fsync(destination_parent)
        for descriptor in (source_fd, destination_parent, source_parent):
            if descriptor is not None:
                os.close(descriptor)
    return result


PUBLIC_REFUSAL_CODES = frozenset(('output_identity_changed', 'archive_changed', 'archive_hash', 'archive_hash_changed', 'archive_hash_mismatch', 'archive_header_changed', 'archive_member_changed', 'archive_not_private_regular_or_size', 'archive_padding_changed', 'archive_permissions', 'archive_size_limit', 'archive_tail_changed', 'archive_truncated', 'archive_type_or_size', 'artifact_name', 'blob_count_limit', 'blob_digest_mismatch', 'blob_size_changed', 'build_time', 'bundle_changed', 'bundle_directory_permissions', 'bundle_directory_type', 'bundle_identity', 'bundle_permissions', 'bundle_receipt_changed', 'bundle_receipt_permissions', 'bundle_receipt_schema', 'bundle_size_limit', 'control_hash_changed', 'control_paths', 'control_size', 'docker_descriptor_binding', 'docker_metadata_binding', 'expected_hash', 'expected_identity', 'expected_producer_changed', 'expected_size', 'export_entry_limit', 'export_inventory_changed', 'export_inventory_invalid', 'export_inventory_parent', 'export_path_refused', 'export_qualification_changed_or_not_approved', 'export_type_or_link', 'incomplete_namespace', 'input_changed', 'input_count_limit', 'input_digest_changed', 'input_directory_type', 'input_hardlink', 'input_invalid', 'input_path', 'input_root_changed', 'input_root_symlink', 'input_type_or_size', 'invalid_arguments', 'invalid_header', 'invalid_size_limit', 'inventory_binding', 'inventory_member_hash', 'inventory_member_mismatch', 'inventory_parent_missing', 'io_refused', 'manifest_binding', 'member_namespace_refused', 'member_not_allowed', 'member_order_or_duplicate', 'member_size', 'metadata_privacy_findings', 'missing_input', 'missing_oci_entry', 'noncanonical_archive_size', 'noncanonical_or_nonregular_header', 'nonzero_archive_tail', 'nonzero_member_padding', 'oci_image_binding_changed', 'oci_inventory_changed', 'origin_binding', 'origin_hashes', 'original_control_changed', 'output_directory_not_fresh', 'output_exists', 'output_overlap', 'output_overlaps_input', 'output_owner', 'parent_not_private_owned', 'path_identity_changed', 'path_not_canonical', 'paths_overlap', 'producer_binding', 'read_bound_or_truncated', 'receipt_exists', 'receipt_overlaps_bundle_or_input', 'receipt_privacy_findings', 'receipt_short_write', 'resources_binding', 'unexpected_bundle_file', 'unexpected_control_file', 'unexpected_input'))

def diagnostic_refusal(error):
    code = error.args[0] if isinstance(error, (Refusal, bundle.Refusal)) and error.args else None
    return code if isinstance(code, str) and code in PUBLIC_REFUSAL_CODES else "io_refused" if isinstance(error, OSError) else "input_invalid"


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Refusal("invalid_arguments")


def main():
    structure = None
    try:
        parser = Parser(description=__doc__)
        commands = parser.add_subparsers(dest="command", required=True)
        prepare = commands.add_parser("prepare-from-build")
        for name in ("manifest", "inventory", "build-metadata", "resources", "oci-dir", "output-dir", "output",
                     "source-sha", "source-tree", "workflow-sha", "run-id", "attempt", "built-at"):
            prepare.add_argument("--" + name, required=True)
        extract = commands.add_parser("extract")
        for name in ("archive", "archive-sha256", "output-dir", "output"):
            extract.add_argument("--" + name, required=True)
        extract.add_argument("--archive-bytes", type=int, required=True)
        args = parser.parse_args()
        if args.command == "extract":
            result = extract_archive(args.archive, args.archive_sha256, args.archive_bytes, args.output_dir, args.output)
            print(json.dumps(result, sort_keys=True))
            return 0 if result["status"] == "extracted_unqualified" else 1
        structure = privacy.inspect_export_structure(args.oci_dir)
        result = prepare_from_build(args.manifest, args.inventory, args.build_metadata, args.resources, args.oci_dir, args.output_dir, args.output,
                                    source_sha=args.source_sha, source_tree=args.source_tree, workflow_sha=args.workflow_sha,
                                    run_id=args.run_id, attempt=args.attempt, built_at=args.built_at)
        result["exportStructure"] = structure
        print(json.dumps(result, sort_keys=True))
        return 0
    except (Refusal, bundle.Refusal, privacy.Refusal, inspection.Refusal, OSError, ValueError, TypeError,
            KeyError, AttributeError, RecursionError, OverflowError, tarfile.TarError) as error:
        print(json.dumps({"status": "failed", "reason": "private_bundle_invalid_changed_or_over_limit",
                          "refusalCode": diagnostic_refusal(error), "exportStructure": structure,
                          "qualified": False, "productionAuthorized": False}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
