"""POSIX descriptor-based bounded I/O for private, isolated publisher packets.

No network, runtime startup or capture occurs at import. Directory components
are opened without following links and checked again at each use boundary.
"""
from __future__ import annotations

import errno
import hashlib
import io
import os
from pathlib import Path
import stat
import uuid
import sys


class IOFailure(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def identity(value):
    return value.st_dev, value.st_ino


def version(value):
    return (*identity(value), value.st_size, value.st_mode,
            value.st_mtime_ns, value.st_ctime_ns)


def io_error(error, default="READ_FAILED"):
    return IOFailure("SYMLINK_REJECTED" if error.errno in (errno.ELOOP, errno.ENOTDIR) else default)


class Directory:
    """Anchor every absolute component, including parents of the admitted root."""
    def __init__(self, path: Path, *, create=False):
        self.path = path.absolute()
        self.fds = []
        self.edges = []
        if ".." in self.path.parts or not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
            raise IOFailure("PATH_INVALID")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        try:
            fd = os.open("/", flags)
            self.fds.append(fd)
            for part in self.path.parts[1:]:
                if create:
                    try:
                        os.mkdir(part, mode=0o700, dir_fd=fd)
                    except FileExistsError:
                        pass
                child = os.open(part, flags, dir_fd=fd)
                self.fds.append(child)
                self.edges.append((fd, part, child))
                fd = child
            self.fd = fd
            self.root_identity = identity(os.fstat(fd))
            self.verify()
        except OSError as error:
            self.close()
            raise io_error(error) from None
        except Exception:
            self.close()
            raise

    def verify(self):
        try:
            for parent, name, child in self.edges:
                current = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if not stat.S_ISDIR(current.st_mode) or identity(current) != identity(os.fstat(child)):
                    raise IOFailure("SOURCE_CHANGED")
        except OSError:
            raise IOFailure("SOURCE_CHANGED") from None

    def close(self):
        # Detach ownership first; never retry close on a possibly reused FD.
        owned, self.fds = self.fds, []
        errors = []
        for fd in reversed(owned):
            try:
                os.close(fd)
            except OSError:
                errors.append("DESCRIPTOR_CLOSE_FAILED")
        self.cleanup_errors = getattr(self, "cleanup_errors", []) + errors
        return errors

    def __enter__(self):
        return self

    def __exit__(self, kind, error, traceback):
        finish_cleanup(error, self.close())


def record_cleanup(error, failures):
    if error is not None and failures:
        error.cleanup_codes = list(getattr(error, "cleanup_codes", [])) + failures


def finish_cleanup(primary, failures):
    if not failures:
        return
    if primary is not None:
        record_cleanup(primary, failures)
    else:
        error = IOFailure("CLEANUP_FAILED")
        record_cleanup(error, failures)
        raise error


def root_identity(root):
    with Directory(root) as directory:
        return directory.root_identity


def parent(root, rel, *, create=False, expected_root=None):
    # A separate anchor for the admitted root prevents root replacement between
    # plan and copy, even if the replacement is another ordinary directory.
    anchor = Directory(root)
    directory = None
    try:
        if expected_root is not None and anchor.root_identity != tuple(expected_root):
            raise IOFailure("SOURCE_CHANGED")
        directory = Directory(root / rel.parent, create=create)
        anchor.verify()
        return anchor, directory
    except BaseException as error:
        failures = directory.close() if directory is not None else []
        failures += anchor.close()
        record_cleanup(error, failures)
        raise


def read_file(root, rel, *, sink=None, limit, pattern=None, expected_root=None):
    anchor, directory = parent(root, rel, expected_root=expected_root)
    try:
        directory.verify()
        fd = os.open(rel.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory.fd)
        with os.fdopen(fd, "rb") as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise IOFailure("FILE_TYPE_INVALID")
            if before.st_size > limit:
                raise IOFailure("SIZE_LIMIT")
            h, total, tail = hashlib.sha256(), 0, b""
            while block := source.read(min(64 * 1024, limit - total + 1)):
                total += len(block)
                if total > limit:
                    raise IOFailure("SIZE_LIMIT")
                if pattern is not None and pattern.search(tail + block):
                    raise IOFailure("PRIVACY_REJECTED")
                tail = (tail + block)[-128:]
                h.update(block)
                if sink is not None:
                    sink.write(block)
            after = os.fstat(source.fileno())
        current = os.stat(rel.name, dir_fd=directory.fd, follow_symlinks=False)
        directory.verify(); anchor.verify()
        if version(before) != version(after) or version(after) != version(current) or total != before.st_size:
            raise IOFailure("SOURCE_CHANGED")
        return {"sha256": h.hexdigest(), "bytes": total,
                "mode": 0o755 if before.st_mode & 0o111 else 0o644}
    except OSError as error:
        raise io_error(error) from None
    finally:
        failures = directory.close() + anchor.close()
        finish_cleanup(sys.exc_info()[1], failures)


def read_bytes(path, *, limit, expected_root=None):
    data = io.BytesIO()
    read_file(path.parent, Path(path.name), sink=data, limit=limit, expected_root=expected_root)
    return data.getvalue()


def atomic_write(root, rel, writer, *, mode=0o600, exclusive=False, expected_root=None):
    anchor, directory = parent(root, rel, create=True, expected_root=expected_root)
    temporary = rel.name if exclusive else ".family-" + uuid.uuid4().hex
    made = False
    try:
        directory.verify(); anchor.verify()
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory.fd)
        made = True
        with os.fdopen(fd, "wb") as target:
            writer(target)
            target.flush(); os.fsync(target.fileno()); os.fchmod(target.fileno(), mode)
        directory.verify(); anchor.verify()
        if not exclusive:
            try:
                leaf = os.stat(rel.name, dir_fd=directory.fd, follow_symlinks=False)
                if not stat.S_ISREG(leaf.st_mode):
                    raise IOFailure("FILE_TYPE_INVALID")
            except FileNotFoundError:
                pass
            os.replace(temporary, rel.name, src_dir_fd=directory.fd, dst_dir_fd=directory.fd)
        made = False
        directory.verify(); anchor.verify()
    except OSError as error:
        raise io_error(error, "WRITE_FAILED") from None
    finally:
        primary = sys.exc_info()[1]
        failures = []
        if made:
            try:
                os.unlink(temporary, dir_fd=directory.fd)
            except FileNotFoundError:
                pass
            except OSError:
                failures.append("TEMPORARY_UNLINK_FAILED")
        failures += directory.close() + anchor.close()
        finish_cleanup(primary, failures)
