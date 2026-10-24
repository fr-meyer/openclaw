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
SOURCE = "85a9bdc1285c338f10f5ca818abc259f6d483b5b"
TREE = "3e0d6fbf5bc015063dce3e4f0f353f0eac3aed6a"
FILES = ("build-origin.json", "build-metadata.json", "manifest.json", "patch-inventory.json", "resources.json")
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

    def oci_names(self):
        """Closed file namespace, without admitting the image's graph or claims."""
        def children(descriptor, expected):
            seen = set()
            with os.scandir(descriptor) as entries:
                for entry in entries:
                    directory = entry.name in ("blobs", "sha256")
                    need(entry.name in expected and not entry.is_symlink() and
                         (entry.is_dir(follow_symlinks=False) if directory else
                          entry.is_file(follow_symlinks=False)), "unexpected_oci_entry")
                    seen.add(entry.name)
            need(seen == expected, "missing_oci_entry")

        children(self.oci.fd, {"index.json", "oci-layout", "blobs"})
        blobs = os.open("blobs", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.oci.fd)
        try:
            children(blobs, {"sha256"})
            digests = os.open("sha256", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=blobs)
            try:
                names, maximum = [], privacy.Limits().blobs
                with os.scandir(digests) as entries:
                    for entry in entries:
                        need(len(names) < maximum, "blob_count_limit")
                        need(HEX.fullmatch(entry.name) and not entry.is_symlink() and
                             entry.is_file(follow_symlinks=False), "unexpected_oci_entry")
                        names.append("blobs/sha256/" + entry.name)
            finally:
                os.close(digests)
        finally:
            os.close(blobs)
        return ["index.json", "oci-layout", *sorted(names)]

    def oci_specs(self):
        specs, total = {}, 0
        for relative in self.oci_names():
            name = OCI + relative
            stream, before = self.open(name, MAX_BYTES)
            with stream:
                total += before.st_size
                need(total <= MAX_BYTES, "archive_size_limit")
                if relative.startswith("blobs/sha256/"):
                    # Check the named digest while streaming these opaque bytes
                    # into the archive (or comparing them during verification).
                    digest = relative.rsplit("/", 1)[1]
                else:
                    hashed, count = hashlib.sha256(), 0
                    while chunk := stream.read(CHUNK):
                        count += len(chunk)
                        need(count <= before.st_size, "input_changed")
                        hashed.update(chunk)
                    need(count == before.st_size and
                         bundle.fingerprint(before) == bundle.fingerprint(os.fstat(stream.fileno())), "input_changed")
                    digest = hashed.hexdigest()
                    need(self.hashes.setdefault(name, digest) == digest, "input_changed")
                specs[name] = {"size": before.st_size, "sha256": digest}
        return specs

    def check_tree(self, specs):
        need(set(self.oci_names()) == {name[len(OCI):] for name in specs if name.startswith(OCI)},
             "oci_inventory_changed")
        seen = set()
        with os.scandir(self.root) as entries:
            for entry in entries:
                need(entry.name in FILES and not entry.is_symlink(), "unexpected_control_file")
                seen.add(entry.name)
        need(seen == set(FILES), "unexpected_control_file")
        for reader in (self.control, self.oci):
            current = reader.root.lstat()
            need((current.st_dev, current.st_ino) == (reader.root_identity.st_dev, reader.root_identity.st_ino), "input_root_changed")
        for name in specs:
            stream, _ = self.open(name, MAX_BYTES)
            stream.close()


def inspect_inputs(inputs, expected=None):
    parser = privacy.Inspector(inputs.root, None, None, None, privacy.Limits())
    values = {name: parser.parse_json(inputs.data(name, bundle.RECEIPT_BYTES)) for name in FILES}
    origin, metadata, manifest, inventory, resources = (values[name] for name in FILES)
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
    specs = {name: {"size": info["size"], "sha256": inputs.hashes[name]} for name, info in inputs.snapshots.items()
             if name in FILES}
    # Retention authenticates an opaque byte inventory. Image structure,
    # provenance subjects and privacy remain the unchanged qualifier's job.
    specs.update(inputs.oci_specs())
    inputs.check_tree(specs)
    return origin, specs


def closure_hash(specs):
    """Bind every retained OCI file; this is not image graph qualification."""
    return sha(encoded([{ "path": name, **specs[name]} for name in sorted(specs) if name.startswith(OCI)]))


def archive_size(specs):
    payload = sum(512 + ((spec["size"] + 511) // 512) * 512 for spec in specs.values()) + 1024
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
    for name, raw in zip(FILES[1:], (metadata, manifest, inventory, resources)):
        descriptor = os.open(controls / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    sync_directory(controls)
    inputs = Inputs(controls, oci_dir)
    partial, final = directory / ".partial", directory / NAME
    try:
        origin, specs = inspect_inputs(inputs, origin["producer"])
        write_tar(inputs, specs, partial, limit)
        need(all(read_control(path) == saved for path, saved in zip(original_paths, original_inputs)), "original_control_changed")
        archive_hash, info = bundle.hash_file(partial, limit)
        need(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1, "archive_permissions")
        inputs.check_tree(specs)
        os.link(partial, final, follow_symlinks=False)
        partial.unlink()
        sync_directory(directory)
        result = {"schema": "openclaw.private-oci-bundle.v1", "status": "prepared", "qualified": False,
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
                  "ociClosureSha256": closure_hash(specs), "memberCount": len(specs)}
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
                "memberCount": len(specs), "retentionValidation": "opaque_byte_inventory",
                "qualified": False, "productionAuthorized": False}
    finally:
        inputs.close()


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Refusal("invalid_arguments")


def main():
    try:
        parser = Parser(description=__doc__)
        commands = parser.add_subparsers(dest="command", required=True)
        prepare = commands.add_parser("prepare-from-build")
        for name in ("manifest", "inventory", "build-metadata", "resources", "oci-dir", "output-dir", "output",
                     "source-sha", "source-tree", "workflow-sha", "run-id", "attempt", "built-at"):
            prepare.add_argument("--" + name, required=True)
        args = parser.parse_args()
        result = prepare_from_build(args.manifest, args.inventory, args.build_metadata, args.resources, args.oci_dir, args.output_dir, args.output,
                                    source_sha=args.source_sha, source_tree=args.source_tree, workflow_sha=args.workflow_sha,
                                    run_id=args.run_id, attempt=args.attempt, built_at=args.built_at)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (Refusal, bundle.Refusal, privacy.Refusal, inspection.Refusal, OSError, ValueError, TypeError,
            KeyError, AttributeError, RecursionError, OverflowError, tarfile.TarError):
        print('{"status":"failed","reason":"private_bundle_invalid_changed_or_over_limit","qualified":false,"productionAuthorized":false}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
