#!/usr/bin/env python3
"""Freeze one bounded ZIP_STORED file for direct, explicitly approved upload.

The maximum applies to the complete archive, including ZIP metadata. This helper
never uploads, decompresses image layers, changes billing, or grants approval.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import zipfile

import hosted_export as export
import hosted_privacy as privacy

MAX_BYTES = 2_147_483_648
CHUNK = 1024 * 1024
RECEIPT_BYTES = 1024 * 1024
RECEIPTS = ("receipt.json", "privacy.json", "resources.json", "hosted-qualification.json")
OCI = "oci/default/"
NAME = re.compile(r"fork-release-[0-9a-f]{40}-[1-9][0-9]*-[1-9][0-9]*\Z")


class Refusal(ValueError):
    pass


def need(condition, code):
    if not condition:
        raise Refusal(code)


def fingerprint(info):
    return {key: getattr(info, "st_" + key) for key in
            ("dev", "ino", "size", "mtime_ns", "ctime_ns", "mode", "uid", "nlink")}


def regular(path, limit):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        need(stat.S_ISREG(info.st_mode) and 0 <= info.st_size <= limit, "input_type_or_size")
        return os.fdopen(descriptor, "rb"), info
    except BaseException:
        os.close(descriptor)
        raise


class Inputs:
    """Open allowlisted files beneath a fixed root without following symlinks."""
    def __init__(self, path):
        self.root = Path(path).absolute()
        need(self.root.resolve() == self.root, "input_root_symlink")
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.root_identity = os.fstat(self.fd)
        self.snapshots = {}
        self.hashes = {}

    def close(self):
        os.close(self.fd)

    def open(self, name, limit):
        parts = Path(name).parts
        need(parts and all(part not in ("", ".", "..", "/") for part in parts), "input_path")
        current = os.dup(self.fd)
        try:
            for part in parts[:-1]:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
                os.close(current)
                current = next_fd
            descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=current)
        finally:
            os.close(current)
        try:
            info = os.fstat(descriptor)
            need(stat.S_ISREG(info.st_mode) and 0 <= info.st_size <= limit, "input_type_or_size")
            old = self.snapshots.setdefault(name, fingerprint(info))
            need(old == fingerprint(info), "input_changed")
            return os.fdopen(descriptor, "rb"), info
        except BaseException:
            os.close(descriptor)
            raise

    def data(self, name, limit):
        stream, before = self.open(name, limit)
        with stream:
            data = stream.read(limit + 1)
            need(len(data) == before.st_size and fingerprint(os.fstat(stream.fileno())) == fingerprint(before), "input_changed")
        digest = hashlib.sha256(data).hexdigest()
        need(self.hashes.setdefault(name, digest) == digest, "input_changed")
        return data

    def check_tree(self, files):
        expected = set(files)
        directories = {"", "oci", "oci/default", "oci/default/blobs", "oci/default/blobs/sha256"}
        need(len(expected) <= privacy.Limits().blobs + len(RECEIPTS) + 2, "input_count_limit")
        for name in directories:
            location = self.root / name
            need(stat.S_ISDIR(location.lstat().st_mode), "input_directory_type")
            prefix = name + "/" if name else ""
            children = {item[len(prefix):].split("/", 1)[0] for item in expected | (directories - {""}) if item.startswith(prefix) and item != name}
            seen = set()
            with os.scandir(location) as entries:
                for entry in entries:
                    need(entry.name in children and not entry.is_symlink(), "unexpected_input")
                    seen.add(entry.name)
                    relative = prefix + entry.name
                    need(entry.is_dir(follow_symlinks=False) if relative in directories else entry.is_file(follow_symlinks=False), "input_type_or_size")
            need(seen == children, "missing_input")
        root_now = self.root.lstat()
        need((root_now.st_dev, root_now.st_ino) == (self.root_identity.st_dev, self.root_identity.st_ino), "input_root_changed")
        for name in expected:
            stream, _ = self.open(name, MAX_BYTES)
            stream.close()


class Closure(privacy.Inspector):
    """Reuse the validated OCI graph, checking layers by hash during ZIP writing."""
    def __init__(self, inputs, qualification):
        super().__init__(inputs.root / "oci/default", qualification["indexDigest"],
                         qualification["sourceSha"], qualification["toolingSha"], privacy.Limits())
        self.inputs = inputs

    def open_regular(self, path, limit):
        return self.inputs.open(Path(path).relative_to(self.inputs.root).as_posix(), limit)

    def local_json(self, name):
        data = self.inputs.data(OCI + name, self.limits.json_bytes)
        parsed = self.parse_json(data)
        self.scan_json(parsed, name)
        return parsed

    def scan_layer(self, descriptor):
        privacy.require(descriptor.get("mediaType") in (privacy.TAR, privacy.GZIP), "unsupported_layer_format")
        self.counts["layers"] += 1
        privacy.require(self.counts["layers"] <= self.limits.layers, "layer_limit")
        self.descriptor(descriptor)
        # Its prior privacy inspection is bound by the complete index digest.
        # The exact stored bytes are hashed while writing; no decompression here.


def inspect_inputs(inputs):
    parser = privacy.Inspector(inputs.root, None, None, None, privacy.Limits())
    values = {name: parser.parse_json(inputs.data(name, RECEIPT_BYTES)) for name in RECEIPTS}
    for name, value in values.items():
        parser.scan_json(value, name)
    need(parser.finding_total == 0, "receipt_privacy_findings")
    qualification = values["hosted-qualification.json"]
    producer = qualification.get("producer", {})
    expected = export.validate(values["receipt.json"], values["privacy.json"], values["resources.json"],
                               source=qualification.get("sourceSha"), tooling=qualification.get("toolingSha"),
                               index=qualification.get("indexDigest"), run=producer.get("runId"),
                               attempt=producer.get("attempt"), public_export=True, storage_approved=True)
    expected["receiptSha256"] = dict(zip(("seal", "privacy", "resources"),
                                         (inputs.hashes[name] for name in RECEIPTS[:3])))
    need(qualification == expected, "export_qualification_changed_or_not_approved")
    need(NAME.fullmatch(qualification["artifactName"]) is not None, "artifact_name")
    closure = Closure(inputs, qualification)
    closure.run()
    need(closure.finding_total == 0, "metadata_privacy_findings")
    seal = values["receipt.json"]
    need(closure.image_digest == seal["imageDigest"] and closure.config_digest == seal["configDigest"], "oci_image_binding_changed")
    specs = {name: {"size": info["size"], "sha256": inputs.hashes[name]} for name, info in inputs.snapshots.items()
             if name in RECEIPTS or name in (OCI + "index.json", OCI + "oci-layout")}
    for digest, size in closure.blobs.items():
        name = OCI + "blobs/sha256/" + digest[7:]
        stream, info = inputs.open(name, MAX_BYTES)
        stream.close()
        need(info.st_size == size, "blob_size_changed")
        specs[name] = {"size": size, "sha256": digest[7:]}
    inputs.check_tree(specs)
    return qualification, specs


class BoundedWriter:
    """Bound highest written extent, including final central-directory records."""
    def __init__(self, stream, limit):
        self.stream, self.limit = stream, limit

    def write(self, data):
        need(self.stream.tell() + len(data) <= self.limit, "bundle_size_limit")
        return self.stream.write(data)

    def tell(self):
        return self.stream.tell()

    def seek(self, *args):
        return self.stream.seek(*args)

    def flush(self):
        return self.stream.flush()


def write_zip(inputs, specs, path, limit):
    with open(path, "xb") as raw:
        os.fchmod(raw.fileno(), 0o600)
        bounded = BoundedWriter(raw, limit)
        with zipfile.ZipFile(bounded, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
            for name, spec in sorted(specs.items()):
                entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                entry.compress_type = zipfile.ZIP_STORED
                entry.file_size = spec["size"]
                entry.external_attr = (stat.S_IFREG | 0o400) << 16
                stream, before = inputs.open(name, MAX_BYTES)
                digest, count = hashlib.sha256(), 0
                with stream, archive.open(entry, "w") as member:
                    while True:
                        chunk = stream.read(CHUNK)
                        if not chunk:
                            break
                        count += len(chunk)
                        need(count <= spec["size"], "input_changed")
                        digest.update(chunk)
                        member.write(chunk)
                    need(count == spec["size"] and digest.hexdigest() == spec["sha256"], "input_digest_changed")
                    need(fingerprint(before) == fingerprint(os.fstat(stream.fileno())), "input_changed")
        raw.flush()
        os.fsync(raw.fileno())
    inputs.check_tree(specs)


def hash_file(path, limit):
    stream, before = regular(path, limit)
    digest, count = hashlib.sha256(), 0
    with stream:
        while True:
            chunk = stream.read(CHUNK)
            if not chunk:
                break
            count += len(chunk)
            need(count <= limit, "bundle_size_limit")
            digest.update(chunk)
        need(count == before.st_size and fingerprint(before) == fingerprint(os.fstat(stream.fileno())), "bundle_changed")
    return digest.hexdigest(), before


def output_directory(path):
    path = Path(path).absolute()
    need(path.resolve() == path and not path.exists(), "output_directory_not_fresh")
    path.mkdir(mode=0o700)
    need(path.stat().st_uid == os.getuid(), "output_owner")
    return path


def prepare(root, output_dir, output, *, limit=MAX_BYTES):
    # limit is an internal test injection only; the CLI has no override.
    need(type(limit) is int and 0 < limit <= MAX_BYTES, "invalid_size_limit")
    root, output_dir, output = (Path(value).absolute() for value in (root, output_dir, output))
    need(output_dir != root and root not in output_dir.parents and output_dir not in root.parents, "output_overlaps_input")
    need(output != output_dir and output_dir not in output.parents and output != root and root not in output.parents, "receipt_overlaps_bundle_or_input")
    need(not output.exists() and not output.is_symlink(), "receipt_exists")
    inputs = Inputs(root)
    directory = partial = final = None
    receipt_created = False
    try:
        qualification, specs = inspect_inputs(inputs)
        directory = output_directory(output_dir)
        partial = directory / ".partial"
        final = directory / qualification["artifactName"]
        write_zip(inputs, specs, partial, limit)
        os.chmod(partial, 0o400)
        digest, info = hash_file(partial, limit)
        need(0 < info.st_size <= limit, "bundle_size_limit")
        os.rename(partial, final)
        os.chmod(directory, 0o500)
        # ctime can change on rename; bind the final file metadata.
        info = final.lstat()
        result = {"schema": "openclaw.hosted-bundle.v1", "status": "passed", "format": "ZIP_STORED",
                  "artifactName": qualification["artifactName"], "sizeBytes": info.st_size, "sha256": digest,
                  "maximumBytes": MAX_BYTES, "sourceSha": qualification["sourceSha"],
                  "toolingSha": qualification["toolingSha"], "indexDigest": qualification["indexDigest"],
                  "producer": qualification["producer"], "qualificationSha256": inputs.hashes["hosted-qualification.json"],
                  "fileIdentity": fingerprint(info)}
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        receipt_created = True
        with os.fdopen(descriptor, "w") as receipt:
            json.dump(result, receipt, sort_keys=True)
            receipt.write("\n")
        return {**result, "bundlePath": str(final)}
    except BaseException:
        # Only this fresh directory and this attempt's receipt are owned here.
        if directory is not None:
            os.chmod(directory, 0o700)
            for path in (partial, final):
                if path is not None and path.exists():
                    path.unlink()
        if receipt_created:
            output.unlink()
        raise
    finally:
        inputs.close()


def verify(receipt, output_dir):
    receipt = Path(receipt).absolute()
    directory = Path(output_dir).absolute()
    need(directory.resolve() == directory and stat.S_ISDIR(directory.lstat().st_mode), "bundle_directory_type")
    folder = directory.stat()
    need(folder.st_uid == os.getuid() and stat.S_IMODE(folder.st_mode) == 0o500, "bundle_directory_permissions")
    stream, receipt_info = regular(receipt, RECEIPT_BYTES)
    with stream:
        data = stream.read(RECEIPT_BYTES + 1)
        need(fingerprint(receipt_info) == fingerprint(os.fstat(stream.fileno())), "bundle_receipt_changed")
    need(receipt_info.st_uid == os.getuid() and stat.S_IMODE(receipt_info.st_mode) == 0o400, "bundle_receipt_permissions")
    result = json.loads(data, object_pairs_hook=privacy.object_pairs)
    need(result.get("schema") == "openclaw.hosted-bundle.v1" and result.get("status") == "passed" and
         result.get("format") == "ZIP_STORED" and result.get("maximumBytes") == MAX_BYTES, "bundle_receipt_schema")
    name = result.get("artifactName", "")
    need(isinstance(name, str) and NAME.fullmatch(name), "artifact_name")
    need(name == f'fork-release-{result.get("sourceSha")}-{result.get("producer", {}).get("runId")}-{result.get("producer", {}).get("attempt")}', "bundle_identity")
    found = set()
    with os.scandir(directory) as entries:
        for entry in entries:
            need(entry.name == name and not found, "unexpected_bundle_file")
            found.add(entry.name)
    need(found == {name}, "unexpected_bundle_file")
    digest, info = hash_file(directory / name, MAX_BYTES)
    need(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o400 and info.st_nlink == 1, "bundle_permissions")
    need(fingerprint((directory / name).lstat()) == fingerprint(info), "bundle_changed")
    need(fingerprint(info) == result.get("fileIdentity") and info.st_size == result.get("sizeBytes") and digest == result.get("sha256"), "bundle_changed")
    return {**result, "bundlePath": str(directory / name)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    begin = commands.add_parser("prepare")
    for name in ("root", "output-dir", "output"):
        begin.add_argument("--" + name, required=True)
    check = commands.add_parser("verify")
    check.add_argument("--receipt", required=True)
    check.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    try:
        result = prepare(args.root, args.output_dir, args.output) if args.command == "prepare" else verify(args.receipt, args.output_dir)
        print(json.dumps({key: result[key] for key in ("status", "artifactName", "bundlePath", "sizeBytes", "sha256")}, sort_keys=True))
        return 0
    except (Refusal, privacy.Refusal, export.Refusal, OSError, ValueError, TypeError, KeyError, AttributeError,
            RecursionError, zipfile.LargeZipFile, zipfile.BadZipFile):
        print('{"status":"failed","reason":"bundle_invalid_changed_or_over_limit"}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
