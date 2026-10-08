"""Isolated descriptor-anchored private byte custody; no SQLite or runtime I/O."""
from __future__ import annotations

from contextlib import contextmanager
import errno
import fcntl
import hashlib
import os
from pathlib import Path
import re
import stat
import threading
import time
from types import MappingProxyType
import uuid

import family_publish_io as _vendor

VENDOR_SOURCE_SHA256 = "ef1f6341e8fbc29c13b3acb873fbc9181f0075f6869c37bc6fa87fba52d6b967"
# Narrow isolated Directory reuse only; this does not accept the whole publisher.
DEPENDENCY_ACCEPTANCE = True
DEPENDENCY_ACCEPTANCE_SCOPE = "Directory anchoring and cleanup; isolated synthetic byte custody"
LIVE_CUSTODY_ACCEPTANCE = False
if getattr(_vendor, "__source_sha256__", None) != VENDOR_SOURCE_SHA256:
    raise RuntimeError("CUSTODY_VENDOR_BINDING_REQUIRED")

ROLES = frozenset({"capture", "quarantine", "ledger", "operational-fixture"})
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_LOCK_NAME = ".custody-owner.lock"
_NOFOLLOW = os.O_NOFOLLOW
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | _NOFOLLOW
_READ_FLAGS = os.O_RDONLY | _NOFOLLOW | os.O_NONBLOCK


class CustodyError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _fail(code):
    raise CustodyError(code)


@contextmanager
def _errors(default="CUSTODY_IO_FAILED"):
    try:
        yield
    except CustodyError:
        raise
    except _vendor.IOFailure as exc:
        raise CustodyError(exc.code) from None
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            code = "SYMLINK_REJECTED"
        elif exc.errno == errno.EEXIST:
            code = "DESTINATION_EXISTS"
        elif exc.errno == errno.ENOENT:
            code = "NOT_FOUND"
        else:
            code = default
        raise CustodyError(code) from None


def _identity(value):
    return value.st_dev, value.st_ino


def _version(value):
    return (*_identity(value), value.st_uid, value.st_nlink, value.st_mode,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _uuid(value):
    if not isinstance(value, str):
        _fail("OPERATION_ID_INVALID")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        _fail("OPERATION_ID_INVALID")
    if str(parsed) != value or parsed.version != 4:
        _fail("OPERATION_ID_INVALID")
    return value


def _name(value, *, internal=False):
    if isinstance(value, str) and _NAME.fullmatch(value):
        return value
    if internal and isinstance(value, str):
        if value == _LOCK_NAME:
            return value
        if value.startswith(".custody-stage-") and value.endswith(".tmp"):
            _uuid(value[len(".custody-stage-"):-4])
            return value
    _fail("NAME_INVALID")


def _metadata(value):
    return MappingProxyType({"identity": _identity(value), "uid": value.st_uid,
                             "mode": stat.S_IMODE(value.st_mode),
                             "bytes": value.st_size, "nlink": value.st_nlink,
                             "mtimeNs": value.st_mtime_ns,
                             "ctimeNs": value.st_ctime_ns,
                             "type": "directory" if stat.S_ISDIR(value.st_mode) else "file"})


def _close_fd(fd):
    try:
        os.close(fd)
    except OSError as exc:
        if exc.errno != errno.EBADF:
            raise


class PrivateCustody:
    """One admitted existing root; all descendants are opened through its fd."""
    def __init__(self, root, uid, sizeLimit):
        self._anchor = None
        self._handles = []
        self._closed = False
        self._lock_fd = None
        self._lock_identity = None
        self._lock_depth = 0
        self._lock_thread = None
        self._thread_lock = threading.RLock()
        self.cleanup_errors = []
        if type(uid) is not int or uid < 0 or type(sizeLimit) is not int or not 0 < sizeLimit <= 64 * 1024 * 1024:
            _fail("CUSTODY_POLICY_INVALID")
        if not isinstance(root, (str, Path)):
            _fail("PATH_INVALID")
        original_root = str(root)
        root = Path(root)
        if not root.is_absolute() or original_root != str(root) or original_root.startswith("//") or str(root) != os.path.normpath(str(root)) or ".." in root.parts:
            _fail("PATH_INVALID")
        self._uid, self._size_limit = uid, sizeLimit
        try:
            with _errors():
                self._anchor = _vendor.Directory(root)
                self._private_directory(os.fstat(self._anchor.fd))
                self._identity = _identity(os.fstat(self._anchor.fd))
                self.verify()
        except Exception:
            self._close_after_primary()
            raise

    uid = property(lambda self: self._uid)
    sizeLimit = property(lambda self: self._size_limit)
    identity = property(lambda self: self._identity)

    def _private_directory(self, value):
        if not stat.S_ISDIR(value.st_mode) or value.st_uid != self.uid or value.st_mode & 0o077:
            _fail("PRIVATE_DIRECTORY_REQUIRED")

    def _private_file(self, value):
        if not stat.S_ISREG(value.st_mode) or value.st_uid != self.uid or value.st_nlink != 1 or value.st_mode & 0o077:
            _fail("PRIVATE_REGULAR_FILE_REQUIRED")
        if value.st_size > self.sizeLimit:
            _fail("SIZE_LIMIT")

    def verify(self):
        with _errors():
            if self._closed or self._anchor is None:
                _fail("CUSTODY_CLOSED")
            self._anchor.verify()
            current = os.fstat(self._anchor.fd)
            self._private_directory(current)
            if _identity(current) != self.identity:
                _fail("ROOT_IDENTITY_CHANGED")

    def _open_chain(self, names, *, create_role=False, fresh=False, expected_identity=None):
        self.verify()
        fds, edges = [], []
        fd = self._anchor.fd
        try:
            with _errors():
                for i, name in enumerate(names):
                    if i == 0 and create_role:
                        try:
                            os.mkdir(name, 0o700, dir_fd=fd)
                            os.fsync(fd)
                        except FileExistsError:
                            pass
                    if fresh and i == len(names) - 1:
                        os.mkdir(name, 0o700, dir_fd=fd)
                        os.fsync(fd)
                    child = os.open(name, _DIR_FLAGS, dir_fd=fd)
                    fds.append(child)
                    self._private_directory(os.fstat(child))
                    edges.append((fd, name, child))
                    fd = child
                handle = CustodyDirectory(self, tuple(names), fds, edges)
                handle.verify()
                if expected_identity is not None and tuple(expected_identity) != handle.identity:
                    _fail("DIRECTORY_IDENTITY_CHANGED")
                self._handles.append(handle)
                return handle
        except Exception:
            for child in reversed(fds):
                try:
                    _close_fd(child)
                except OSError:
                    self.cleanup_errors.append("FD_CLOSE_FAILED")
            raise

    def role(self, role, *, create=False, expected_identity=None):
        if not isinstance(role, str) or role not in ROLES:
            _fail("ROLE_INVALID")
        return self._open_chain((role,), create_role=create, expected_identity=expected_identity)

    def allocate(self, role, operation_id):
        if not isinstance(role, str) or role not in ROLES or role == "operational-fixture":
            _fail("ROLE_INVALID")
        return self._open_chain((role, _uuid(operation_id)), create_role=True, fresh=True)

    def open_operation(self, role, operation_id, *, expected_identity=None):
        if not isinstance(role, str) or role not in ROLES or role == "operational-fixture":
            _fail("ROLE_INVALID")
        return self._open_chain((role, _uuid(operation_id)), expected_identity=expected_identity)

    def _verify_lock(self):
        self.verify()
        before = os.fstat(self._lock_fd)
        self._private_file(before)
        current = os.stat(_LOCK_NAME, dir_fd=self._anchor.fd, follow_symlinks=False)
        self._private_file(current)
        if before.st_size != 0 or current.st_size != 0:
            _fail("LOCK_CONTENT_INVALID")
        if _identity(before) != self._lock_identity or _identity(current) != self._lock_identity:
            _fail("LOCK_IDENTITY_CHANGED")

    def _open_lock(self):
        self.verify()
        if self._lock_fd is not None:
            self._verify_lock()
            return
        created = False
        try:
            fd = os.open(_LOCK_NAME, os.O_RDWR | os.O_CREAT | os.O_EXCL | _NOFOLLOW | os.O_NONBLOCK,
                         0o600, dir_fd=self._anchor.fd)
            created = True
        except FileExistsError:
            fd = os.open(_LOCK_NAME, os.O_RDWR | _NOFOLLOW | os.O_NONBLOCK, dir_fd=self._anchor.fd)
        self._lock_fd = fd
        self._private_file(os.fstat(fd))
        self._lock_identity = _identity(os.fstat(fd))
        self._verify_lock()
        if created:
            os.fsync(fd)
            os.fsync(self._anchor.fd)

    @contextmanager
    def owner_lock(self, *, timeout=5):
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0 <= timeout <= 60:
            _fail("LOCK_TIMEOUT_INVALID")
        deadline = time.monotonic() + timeout
        if not self._thread_lock.acquire(timeout=timeout):
            _fail("LOCK_BUSY")
        outer = self._lock_depth == 0
        acquired = False
        primary = False
        try:
            with _errors():
                self._open_lock()
                if outer:
                    while True:
                        try:
                            fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            acquired = True
                            break
                        except BlockingIOError:
                            if time.monotonic() >= deadline:
                                _fail("LOCK_BUSY")
                            time.sleep(min(0.01, max(0, deadline - time.monotonic())))
                    self._lock_thread = threading.get_ident()
                self._verify_lock()
                self._lock_depth += 1
                try:
                    yield MappingProxyType({"identity": self._lock_identity,
                                            "rootIdentity": self.identity, "uid": self.uid})
                except BaseException:
                    primary = True
                    raise
                finally:
                    self._lock_depth -= 1
                    try:
                        self._verify_lock()
                    except Exception:
                        if not primary:
                            raise
                        self.cleanup_errors.append("LOCK_EXIT_CHECK_FAILED")
        except BaseException:
            primary = True
            raise
        finally:
            try:
                if outer and acquired:
                    try:
                        fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
                    except OSError:
                        if not primary:
                            _fail("LOCK_RELEASE_FAILED")
                        self.cleanup_errors.append("LOCK_RELEASE_FAILED")
                    finally:
                        self._lock_thread = None
            finally:
                self._thread_lock.release()

    def _require_lock(self):
        if self._lock_depth <= 0 or self._lock_thread != threading.get_ident():
            _fail("OWNER_LOCK_REQUIRED")
        self._verify_lock()

    def _close_after_primary(self):
        try:
            self.close()
        except Exception:
            self.cleanup_errors.append("CUSTODY_CLOSE_FAILED")

    def close(self):
        if self._closed:
            return
        if self._lock_depth:
            _fail("CUSTODY_LOCK_ACTIVE")
        self._closed = True
        failures = []
        for handle in reversed(self._handles):
            try:
                handle.close()
            except Exception:
                failures.append("HANDLE_CLOSE_FAILED")
        if self._lock_fd is not None:
            try:
                _close_fd(self._lock_fd)
            except OSError:
                failures.append("LOCK_CLOSE_FAILED")
            self._lock_fd = None
        if self._anchor is not None:
            try:
                anchor_failures = self._anchor.close()
                if anchor_failures:
                    self.cleanup_errors.extend(anchor_failures)
                    failures.append("ANCHOR_CLOSE_FAILED")
            except Exception:
                failures.append("ANCHOR_CLOSE_FAILED")
        self.cleanup_errors.extend(failures)
        if failures:
            _fail("CUSTODY_CLOSE_FAILED")

    def __enter__(self):
        self.verify()
        return self

    def __exit__(self, exc_type, exc, traceback):
        if exc is not None:
            self._close_after_primary()
        else:
            self.close()


class PrivateReader:
    __slots__ = ("_directory", "_name", "_fd", "_before", "_identity", "_metadata", "_sha256")

    def __init__(self, directory, name, fd, before):
        self._directory, self._name, self._fd, self._before = directory, name, fd, before
        self._identity = _identity(before)
        self._metadata = _metadata(before)
        self._sha256 = self._stream(None)

    fd = property(lambda self: self._fd)
    identity = property(lambda self: self._identity)
    metadata = property(lambda self: self._metadata)
    sha256 = property(lambda self: self._sha256)
    size = property(lambda self: self._metadata["bytes"])

    def _check(self):
        directory = self._directory
        directory.verify()
        after = os.fstat(self.fd)
        current = os.stat(self._name, dir_fd=directory.fd, follow_symlinks=False)
        directory._owner._private_file(after)
        directory._owner._private_file(current)
        if _version(after) != _version(self._before) or _version(current) != _version(self._before):
            _fail("FILE_CHANGED")

    def _stream(self, sink):
        self._check()
        os.lseek(self.fd, 0, os.SEEK_SET)
        total, digest = 0, hashlib.sha256()
        while True:
            chunk = os.read(self.fd, min(64 * 1024, self._directory._owner.sizeLimit - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > self._directory._owner.sizeLimit:
                _fail("SIZE_LIMIT")
            digest.update(chunk)
            if sink is not None:
                sink.append(chunk)
        self._check()
        if total != self._before.st_size:
            _fail("FILE_CHANGED")
        os.lseek(self.fd, 0, os.SEEK_SET)
        return digest.hexdigest()

    def read_bytes(self):
        with _errors():
            chunks = []
            digest = self._stream(chunks)
            if digest != self.sha256:
                _fail("FILE_CHANGED")
            return b"".join(chunks)


class CustodyDirectory:
    __slots__ = ("_owner", "_names", "_fds", "_edges", "_closed", "_fd", "_identity", "_role", "_operation_id")

    def __init__(self, owner, names, fds, edges):
        self._owner, self._names = owner, names
        self._fds, self._edges = fds, edges
        self._closed = False
        self._fd = fds[-1]
        self._identity = _identity(os.fstat(self.fd))
        self._role = names[0]
        self._operation_id = names[1] if len(names) == 2 else None

    fd = property(lambda self: self._fd)
    identity = property(lambda self: self._identity)
    role = property(lambda self: self._role)
    operation_id = property(lambda self: self._operation_id)

    def verify(self):
        with _errors():
            if self._closed:
                _fail("DIRECTORY_CLOSED")
            self._owner.verify()
            for parent, name, fd in self._edges:
                current = os.stat(name, dir_fd=parent, follow_symlinks=False)
                held = os.fstat(fd)
                self._owner._private_directory(current)
                self._owner._private_directory(held)
                if _identity(current) != _identity(held):
                    _fail("DIRECTORY_IDENTITY_CHANGED")
            if _identity(os.fstat(self.fd)) != self.identity:
                _fail("DIRECTORY_IDENTITY_CHANGED")

    def _leaf(self, name, *, internal=False):
        name = _name(name, internal=internal)
        if self.role == "operational-fixture" and name != "source.sqlite":
            _fail("FIXTURE_NAME_INVALID")
        return name

    @contextmanager
    def open_reader(self, name):
        name = self._leaf(name)
        fd = None
        primary = False
        try:
            with _errors():
                self.verify()
                fd = os.open(name, _READ_FLAGS, dir_fd=self.fd)
                before = os.fstat(fd)
                self._owner._private_file(before)
                reader = PrivateReader(self, name, fd, before)
                try:
                    yield reader
                except BaseException:
                    primary = True
                    raise
                finally:
                    try:
                        reader._check()
                    except Exception:
                        if not primary:
                            raise
                        self._owner.cleanup_errors.append("READER_EXIT_CHECK_FAILED")
        except BaseException:
            primary = True
            raise
        finally:
            if fd is not None:
                try:
                    _close_fd(fd)
                except OSError:
                    if not primary:
                        _fail("READER_CLOSE_FAILED")
                    self._owner.cleanup_errors.append("READER_CLOSE_FAILED")

    def read_bytes(self, name):
        with self.open_reader(name) as reader:
            return reader.read_bytes()

    def _write(self, name, data, *, internal=False):
        name = self._leaf(name, internal=internal)
        if not isinstance(data, bytes):
            _fail("BYTES_REQUIRED")
        if len(data) > self._owner.sizeLimit:
            _fail("SIZE_LIMIT")
        fd = None
        primary = False
        try:
            with _errors():
                self.verify()
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
                             0o600, dir_fd=self.fd)
                before = os.fstat(fd)
                self._owner._private_file(before)
                view = memoryview(data)
                while view:
                    count = os.write(fd, view[:64 * 1024])
                    if count <= 0:
                        _fail("WRITE_INCOMPLETE")
                    view = view[count:]
                os.fsync(fd)
                after = os.fstat(fd)
                current = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
                self._owner._private_file(after)
                self._owner._private_file(current)
                if _identity(before) != _identity(after) or _version(after) != _version(current) or after.st_size != len(data):
                    _fail("FILE_CHANGED")
                self.verify()
                os.fsync(self.fd)
                self.verify()
                return MappingProxyType({"identity": _identity(after), "bytes": len(data),
                                         "sha256": hashlib.sha256(data).hexdigest()})
        except BaseException:
            primary = True
            raise
        finally:
            # Never unlink a failed stage, especially after pathname exchange.
            if fd is not None:
                try:
                    _close_fd(fd)
                except OSError:
                    if not primary:
                        _fail("WRITE_CLOSE_FAILED")
                    self._owner.cleanup_errors.append("WRITE_CLOSE_FAILED")

    def write_bytes(self, name, data):
        if self.role == "ledger":
            self._owner._require_lock()
        return self._write(name, data)

    def replace_bytes(self, name, data, *, expected_sha256):
        name = self._leaf(name)
        if self.role != "ledger":
            _fail("LEDGER_REPLACEMENT_ONLY")
        if expected_sha256 is not None and (not isinstance(expected_sha256, str) or not _HEX.fullmatch(expected_sha256)):
            _fail("EXPECTED_DIGEST_INVALID")
        with _errors():
            self._owner._require_lock()
            stage = ".custody-stage-" + str(uuid.uuid4()) + ".tmp"
            receipt = self._write(stage, data, internal=True)
            try:
                current = self.read_bytes(name)
                current_digest = hashlib.sha256(current).hexdigest()
            except CustodyError as exc:
                if exc.code != "NOT_FOUND":
                    raise
                current_digest = None
            if current_digest != expected_sha256:
                _fail("LEDGER_CONFLICT")
            self.verify()
            self._owner._require_lock()
            staged = os.stat(stage, dir_fd=self.fd, follow_symlinks=False)
            self._owner._private_file(staged)
            if _identity(staged) != receipt["identity"]:
                _fail("FILE_CHANGED")
            os.replace(stage, name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
            os.fsync(self.fd)
            self.verify()
            if hashlib.sha256(self.read_bytes(name)).hexdigest() != receipt["sha256"]:
                _fail("FILE_CHANGED")
            self._owner._require_lock()
            return receipt

    def stat(self, name):
        name = self._leaf(name, internal=True)
        with _errors():
            self.verify()
            value = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            if stat.S_ISDIR(value.st_mode):
                self._owner._private_directory(value)
            else:
                self._owner._private_file(value)
            self.verify()
            return _metadata(value)

    def list_names(self):
        with _errors():
            self.verify()
            names = sorted(os.listdir(self.fd))
            for name in names:
                self.stat(name)
            self.verify()
            return tuple(names)

    def reopen(self):
        self.verify()
        return self._owner._open_chain(self._names, expected_identity=self.identity)

    def close(self):
        if self._closed:
            return
        self._closed = True
        failures = []
        for fd in reversed(self._fds):
            try:
                _close_fd(fd)
            except OSError:
                failures.append("FD_CLOSE_FAILED")
        self._fds.clear()
        if failures:
            self._owner.cleanup_errors.extend(failures)
            _fail("DIRECTORY_CLOSE_FAILED")

    def __enter__(self):
        self.verify()
        return self

    def __exit__(self, exc_type, exc, traceback):
        if exc is None:
            self.close()
        else:
            try:
                self.close()
            except Exception:
                self._owner.cleanup_errors.append("DIRECTORY_CLOSE_FAILED")
