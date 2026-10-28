"""Descriptor-anchored raw copy of the fixed report and complete OCI prefix.

The caller must positively establish the original disk is read-only first.
Only synthetic temporary files are used by current tests. No parsing/extraction.
"""
from __future__ import annotations

import hashlib
import os
import re
import stat
from pathlib import Path, PurePosixPath

from protocol import (MAX_FILES, PRIVATE_MAX, Refusal, canonical, require,
                      regular_identity, sha, write_once)


def relative_parts(value):
    require(isinstance(value, str) and value and "\\" not in value and "\x00" not in value,
            "source_relative_path")
    p = PurePosixPath(value)
    require(not p.is_absolute() and str(p) == value and all(x not in (".", "..") for x in p.parts),
            "source_relative_path")
    return p.parts


def open_dir_at(base_fd, parts):
    current = os.dup(base_fd)
    try:
        for part in parts:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK,
                              dir_fd=current)
            os.close(current); current = next_fd
        return current
    except BaseException:
        os.close(current)
        raise


def dir_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_mtime_ns, info.st_ctime_ns)


def names_bounded(fd, limit, role):
    """Stop at cap+1 entries, before sorting/allocating an attacker-sized list."""
    names = []
    with os.scandir(fd) as entries:
        for entry in entries:
            require(len(names) < limit, "copy_directory_entry_cap",
                    {"role": role, "entryCap": limit, "entriesObserved": len(names) + 1})
            names.append(entry.name)
    return sorted(names)


class Copier:
    def __init__(self, destination, *, max_bytes=PRIVATE_MAX, max_files=MAX_FILES):
        require(type(max_bytes) is int and 0 < max_bytes <= PRIVATE_MAX, "copy_byte_bound")
        require(type(max_files) is int and 0 < max_files <= MAX_FILES, "copy_count_bound")
        self.destination = Path(destination)
        require(not os.path.lexists(self.destination), "copy_destination_exists")
        self.destination.mkdir(mode=0o700)
        self.max_bytes, self.max_files = max_bytes, max_files
        self.total, self.rows = 0, []
        self.created = []

    def _copy(self, directory, name, relative, *, expected_sha=None, expected_size=None):
        require(len(self.rows) < self.max_files, "copy_file_count")
        before = os.stat(name, dir_fd=directory, follow_symlinks=False)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, "copy_regular_single_link")
        require(0 <= before.st_size <= self.max_bytes - self.total, "copy_total_bytes")
        if expected_size is not None:
            require(before.st_size == expected_size, "copy_size_pin")
        target = self.destination / relative
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        output = None
        try:
            require(regular_identity(os.fstat(source)) == regular_identity(before), "copy_source_changed")
            output = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
            self.created.append(str(relative))
            h, copied = hashlib.sha256(), 0
            while True:
                chunk = os.read(source, min(65536, before.st_size + 1 - copied))
                if not chunk:
                    break
                copied += len(chunk)
                require(copied <= before.st_size, "copy_source_grew")
                h.update(chunk)
                view = memoryview(chunk)
                while view:
                    n = os.write(output, view)
                    require(n > 0, "copy_short_write")
                    view = view[n:]
            require(copied == before.st_size, "copy_source_short")
            require(regular_identity(os.fstat(source)) == regular_identity(before), "copy_source_changed")
            require(regular_identity(os.stat(name, dir_fd=directory, follow_symlinks=False)) ==
                    regular_identity(before), "copy_source_replaced")
            digest = h.hexdigest()
            if expected_sha is not None:
                require(digest == expected_sha, "copy_hash_pin",
                        {"role": "privacy" if relative.name == "privacy.json" else "oci_blob",
                         "copiedBytes": copied, "expectedSha256": expected_sha, "observedSha256": digest})
            os.fchmod(output, 0o444); os.fsync(output)
            result = os.fstat(output)
            require(stat.S_ISREG(result.st_mode) and result.st_nlink == 1 and
                    result.st_size == copied, "copy_destination_identity")
            # Root ownership is a mandatory operational host check; no chown on Mac.
            self.total += copied
            self.rows.append({"path": str(relative), "bytes": copied, "sha256": digest,
                              "dev": result.st_dev, "ino": result.st_ino,
                              "uid": result.st_uid, "gid": result.st_gid})
        finally:
            os.close(source)
            if output is not None:
                os.close(output)

    def _directory(self, fd, relative, allowed):
        before = os.fstat(fd)
        names = names_bounded(fd, len(allowed), "oci_root")
        require(set(names) <= set(allowed), "copy_unexpected_entry")
        for name in names:
            item = os.stat(name, dir_fd=fd, follow_symlinks=False)
            expected = allowed[name]
            if expected is None:
                require(stat.S_ISREG(item.st_mode), "copy_root_file_type")
                self._copy(fd, name, relative / name)
            else:
                require(stat.S_ISDIR(item.st_mode), "copy_directory_type")
                child = open_dir_at(fd, (name,))
                try:
                    child_before = os.fstat(child)
                    if expected == "blobs":
                        require(names_bounded(child, 1, "blob_algorithm") == ["sha256"], "copy_blob_algorithm")
                        algorithm = open_dir_at(child, ("sha256",))
                        try:
                            old = os.fstat(algorithm)
                            blobs = names_bounded(algorithm, max(0, self.max_files - 3), "oci_blobs")
                            (self.destination / relative / name / "sha256").mkdir(parents=True, mode=0o700)
                            for blob in blobs:
                                require(re.fullmatch(r"[0-9a-f]{64}", blob) is not None, "copy_blob_name")
                                self._copy(algorithm, blob, relative / name / "sha256" / blob,
                                           expected_sha=blob)
                            require(dir_identity(old) == dir_identity(os.fstat(algorithm)), "copy_tree_changed")
                        finally:
                            os.close(algorithm)
                    else:
                        require(not names_bounded(child, 0, "ingest"), "copy_ingest_nonempty")
                        (self.destination / relative / name).mkdir(parents=True, mode=0o700)
                    require(dir_identity(child_before) == dir_identity(os.fstat(child)), "copy_tree_changed")
                    require(dir_identity(os.fstat(child)) == dir_identity(os.stat(name, dir_fd=fd, follow_symlinks=False)),
                            "copy_directory_replaced")
                finally:
                    os.close(child)
        require(set(names) >= {"oci-layout", "index.json", "blobs"}, "copy_root_missing")
        require(dir_identity(before) == dir_identity(os.fstat(fd)) and
                names == names_bounded(fd, len(allowed), "oci_root_recheck"),
                "copy_tree_changed")

    def copy(self, source_root, report_relative, oci_relative, report_pin):
        """Source paths are caller's fixed reviewed layout, never worker input."""
        require(set(report_pin) == {"bytes", "sha256"}, "copy_report_pin")
        root = os.open(source_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        report_parent = oci = None
        try:
            report = relative_parts(report_relative)
            oci_path = relative_parts(oci_relative)
            report_parent = open_dir_at(root, report[:-1])
            self._copy(report_parent, report[-1], Path("privacy.json"),
                       expected_sha=report_pin["sha256"], expected_size=report_pin["bytes"])
            oci = open_dir_at(root, oci_path)
            (self.destination / "oci").mkdir(mode=0o700)
            self._directory(oci, Path("oci"), {"oci-layout": None, "index.json": None,
                                             "blobs": "blobs", "ingest": "empty"})
            # All writes happen outside source and without original mode changes.
            for base, dirs, _ in os.walk(self.destination, followlinks=False):
                for name in dirs:
                    os.chmod(Path(base) / name, 0o555)
            os.chmod(self.destination, 0o000)  # Host only; gate releases copies later.
            result = {"schema": "openclaw.nonroot-input-copy.v1", "bytes": self.total,
                      "files": len(self.rows), "entries": self.rows}
            return {**result, "manifestSha256": sha(canonical(result))}
        finally:
            if report_parent is not None:
                os.close(report_parent)
            if oci is not None:
                os.close(oci)
            os.close(root)


def closure_sha(manifest, source_sha, index_digest):
    """Independent raw-copy join to the maintained consumer's closure recipe.

The maintained consumer still proves graph reachability, descriptor semantics
and privacy. This computes no accepted verdict and never parses private JSON.
"""
    rows = manifest["entries"]
    roots, blobs = {}, []
    for row in rows:
        name = row["path"]
        if name in ("oci/oci-layout", "oci/index.json"):
            roots[name[4:]] = row["sha256"]
        elif name.startswith("oci/blobs/sha256/"):
            blobs.append(("sha256:" + name.rsplit("/", 1)[1], row["bytes"]))
        else:
            require(name == "privacy.json", "closure_copy_extra")
    require(set(roots) == {"oci-layout", "index.json"} and blobs, "closure_copy_missing")
    value = {"schema": "openclaw.oci-closure.v1", "sourceSha": source_sha,
             "indexDigest": index_digest, "roots": roots, "blobs": sorted(blobs)}
    return sha(canonical(value))


if __name__ == "__main__":
    raise SystemExit("disarmed_local_source_only")
