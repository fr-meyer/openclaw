#!/usr/bin/env python3
"""Storage contract and lossless Markdown projection for YouTube archives.

Canonical raw artifacts and all mutable pipeline state live outside the
OpenClaw memory tree.  Every canonical raw Markdown document is projected
byte-for-byte into a shallow, collision-safe memory tree for indexing.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
import stat
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterator


SCHEMA = "openclaw.youtube-markdown-projection"
SCHEMA_VERSION = 1
DEFAULT_WORKSPACE = Path(__file__).resolve().parents[1]
DEFAULT_DATA_ROOT = Path(os.environ.get("OPENCLAW_YOUTUBE_DATA_ROOT", "~/.openclaw/data/youtube-transcripts")).expanduser()
DEFAULT_ARCHIVE_ROOT = DEFAULT_DATA_ROOT / "archive"
DEFAULT_STATE_ROOT = DEFAULT_DATA_ROOT / "state"
DEFAULT_QUEUE_ROOT = DEFAULT_STATE_ROOT / "queue"
DEFAULT_POOL_ROOT = DEFAULT_STATE_ROOT / "automation/global"
DEFAULT_YC_ROOT = DEFAULT_STATE_ROOT / "channels/ycombinator"
DEFAULT_PROJECTION_ROOT = DEFAULT_WORKSPACE / "memory/youtube-transcripts"
DEFAULT_MANIFEST_PATH = DEFAULT_STATE_ROOT / "projection/manifest.json"
DEFAULT_LOCK_PATH = DEFAULT_STATE_ROOT / "locks/projection.lock"
ROOT_IDS = {"archive": "youtube-archive", "state": "youtube-state", "projection": "openclaw-memory"}
MAX_MARKDOWN_BYTES = int(os.environ.get("OPENCLAW_YOUTUBE_MAX_MARKDOWN_BYTES", str(256 * 1024 * 1024)))


class StorageError(RuntimeError):
    """Raised when a storage or projection safety invariant is violated."""


@dataclass(frozen=True)
class StorageRoots:
    archive: Path = DEFAULT_ARCHIVE_ROOT
    state: Path = DEFAULT_STATE_ROOT
    projection: Path = DEFAULT_PROJECTION_ROOT

    @property
    def queue(self) -> Path:
        return self.state / "queue"

    @property
    def pool(self) -> Path:
        return self.state / "automation/global"

    @property
    def ycombinator(self) -> Path:
        return self.state / "channels/ycombinator"

    @property
    def manifest(self) -> Path:
        return self.state / "projection/manifest.json"

    @property
    def lock(self) -> Path:
        return self.state / "locks/projection.lock"


def utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _resolved(path: Path) -> Path:
    return path.expanduser().resolve(strict=False)


def _reject_symlink_root(path: Path, label: str) -> None:
    """Reject an explicitly supplied symlink root before canonicalization.

    Existing host aliases above the supplied root (for example macOS `/var`)
    are outside the caller-controlled boundary and are canonicalized normally.
    Descendants are still checked component-by-component on every access.
    """
    expanded = path.expanduser().absolute()
    try:
        metadata = expanded.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(metadata.st_mode):
        raise StorageError(f"{label} root must not be a symlink: {expanded}")


def validate_roots(archive_root: Path, state_root: Path, projection_root: Path) -> tuple[Path, Path, Path]:
    _reject_symlink_root(archive_root, "archive")
    _reject_symlink_root(state_root, "state")
    _reject_symlink_root(projection_root, "projection")
    archive = _resolved(archive_root)
    state_root = _resolved(state_root)
    projection = _resolved(projection_root)
    if len({archive, state_root, projection}) != 3:
        raise StorageError("archive, state, and projection roots must be distinct")
    roots = (("archive", archive), ("state", state_root), ("projection", projection))
    for left_name, left in roots:
        for right_name, right in roots:
            if left_name != right_name and _is_within(left, right):
                raise StorageError(f"{left_name} root must not be inside {right_name} root")
    return archive, state_root, projection


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_relative_path(source: Path, archive_root: Path) -> str:
    archive = _resolved(archive_root)
    original = source.expanduser().absolute()
    if original.is_symlink():
        raise StorageError(f"symlink source is not allowed: {source}")
    absolute = _resolved(original)
    try:
        relative = absolute.relative_to(archive)
    except ValueError as exc:
        raise StorageError(f"source is outside the canonical archive: {source}") from exc
    posix = PurePosixPath(relative.as_posix())
    if posix.is_absolute() or not posix.parts or any(part in {"", ".", ".."} for part in posix.parts):
        raise StorageError(f"unsafe canonical relative path: {relative}")
    return posix.as_posix()


def document_id(relative_source: str) -> str:
    normalized = PurePosixPath(relative_source).as_posix()
    return sha256_bytes(normalized.encode("utf-8"))


def projection_relative_path(relative_source: str) -> str:
    identifier = document_id(relative_source)
    return f"{identifier[:2]}/{identifier}.md"


def projection_path_for(source: Path, archive_root: Path, projection_root: Path) -> Path:
    relative = canonical_relative_path(source, archive_root)
    return _resolved(projection_root) / projection_relative_path(f"archive/{relative}")


def source_identity(namespace: str, source: Path, root: Path) -> str:
    if namespace not in {"archive", "state"}:
        raise StorageError(f"unsupported source namespace: {namespace}")
    return f"{namespace}/{canonical_relative_path(source, root)}"


def _reject_symlink_chain(path: Path, stop: Path) -> None:
    stop = stop.expanduser().absolute()
    cursor = path.expanduser().absolute()
    while True:
        try:
            metadata = cursor.lstat()
        except FileNotFoundError:
            cursor = cursor.parent
            continue
        if stat.S_ISLNK(metadata.st_mode):
            raise StorageError(f"symlink path component is not allowed: {cursor}")
        if cursor == stop:
            break
        cursor = cursor.parent
        if not _is_within(cursor, stop) and cursor != stop:
            raise StorageError(f"path escaped guarded root: {path}")


def read_regular_bytes(path: Path, root: Path) -> bytes:
    root = _resolved(root)
    original = path.expanduser().absolute()
    if original.is_symlink():
        raise StorageError(f"symlink source is not allowed: {path}")
    path = _resolved(original)
    if not _is_within(path, root):
        raise StorageError(f"path is outside guarded root: {path}")
    _reject_symlink_chain(Path(path), root)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise StorageError(f"source is not a regular file: {path}")
        if metadata.st_nlink != 1:
            raise StorageError(f"hard-linked source is not allowed: {path}")
        if metadata.st_size > MAX_MARKDOWN_BYTES:
            raise StorageError(f"source exceeds the bounded Markdown size limit: {path}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, data: bytes) -> None:
    """Write an entire buffer even when the OS reports a short write."""
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        written = os.write(descriptor, view[offset:])
        if written <= 0:
            raise OSError("write returned no progress")
        offset += written


def atomic_write_bytes(path: Path, data: bytes, *, mode: int = 0o600) -> bool:
    """Durably replace a regular destination and return whether bytes changed."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _reject_symlink_chain(path, path.parent)
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        metadata = None
    if metadata is not None:
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise StorageError(f"projection target must be one regular, unlinked file: {path}")
        if path.read_bytes() == data:
            return False
        mode = stat.S_IMODE(metadata.st_mode)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, mode)
    committed = False
    try:
        _write_all(descriptor, data)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        committed = True
        _fsync_directory(path.parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if not committed:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
    return True


def atomic_json(path: Path, payload: Any) -> bool:
    encoded = (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    return atomic_write_bytes(path, encoded)


def hash_regular_file(path: Path, root: Path) -> tuple[str, int]:
    root = _resolved(root)
    original = path.expanduser().absolute()
    if original.is_symlink():
        raise StorageError(f"symlink file is not allowed: {path}")
    resolved = _resolved(original)
    if not _is_within(resolved, root):
        raise StorageError(f"path is outside guarded root: {path}")
    _reject_symlink_chain(original, root)
    descriptor = os.open(original, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    digest = hashlib.sha256()
    size = 0
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise StorageError(f"file must be one regular, unlinked file: {path}")
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            size += len(block)
            digest.update(block)
    finally:
        os.close(descriptor)
    return digest.hexdigest(), size


def regular_target_matches(path: Path, root: Path, expected_digest: str, expected_size: int) -> bool:
    root = _resolved(root)
    path = Path(path)
    if not _is_within(_resolved(path), root):
        raise StorageError(f"projection target escaped its root: {path}")
    _reject_symlink_chain(path, root)
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise StorageError(f"projection target must be one regular, unlinked file: {path}")
    digest, size = hash_regular_file(path, root)
    return size == expected_size and digest == expected_digest


def _source_signature(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)


def project_regular_file(
    source: Path,
    source_root: Path,
    target: Path,
    projection_root: Path,
    expected_signature: tuple[int, int, int, int],
) -> tuple[bool, str, int]:
    """Stream one source to a same-directory temp, then atomically publish it."""
    source_root = _resolved(source_root)
    original_source = source.expanduser().absolute()
    if original_source.is_symlink():
        raise StorageError(f"symlink source is not allowed: {source}")
    resolved_source = _resolved(original_source)
    if not _is_within(resolved_source, source_root):
        raise StorageError(f"source escaped its guarded root: {source}")
    _reject_symlink_chain(resolved_source, source_root)
    descriptor = os.open(resolved_source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _reject_symlink_chain(target, _resolved(projection_root))
    temporary = target.with_name(f".{target.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    output = os.open(
        temporary,
        os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    digest = hashlib.sha256()
    size = 0
    committed = False
    try:
        before = os.fstat(descriptor)
        if _source_signature(before) != expected_signature:
            raise StorageError(f"source changed after projection preflight: {source}")
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise StorageError(f"source must be one regular, unlinked file: {source}")
        if before.st_size > MAX_MARKDOWN_BYTES:
            raise StorageError(f"source exceeds the bounded Markdown size limit: {source}")
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            _write_all(output, block)
            size += len(block)
            digest.update(block)
        after = os.fstat(descriptor)
        if _source_signature(after) != expected_signature or size != before.st_size:
            raise StorageError(f"source changed during projection: {source}")
        os.fsync(output)
        hexdigest = digest.hexdigest()
        if regular_target_matches(target, projection_root, hexdigest, size):
            os.close(output)
            output = -1
            temporary.unlink()
            return False, hexdigest, size
        os.close(output)
        output = -1
        os.replace(temporary, target)
        committed = True
        _fsync_directory(target.parent)
        return True, hexdigest, size
    finally:
        os.close(descriptor)
        if output >= 0:
            os.close(output)
        if not committed:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


@contextlib.contextmanager
def exclusive_lock(path: Path) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise StorageError(f"lock path must not be a symlink: {path}")
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


@contextlib.contextmanager
def writer_lock(state_root: Path = DEFAULT_STATE_ROOT) -> Iterator[None]:
    """Serialize canonical writers with projection sync and one-file publish."""
    state = _resolved(state_root)
    with exclusive_lock(state / "locks/source-writers.lock"):
        yield


def discover_markdown(archive_root: Path) -> list[tuple[Path, tuple[int, int, int, int]]]:
    archive = _resolved(archive_root)
    if not archive.exists():
        return []
    if archive.is_symlink() or not archive.is_dir():
        raise StorageError("canonical archive root must be a real directory")
    found: list[tuple[Path, tuple[int, int, int, int]]] = []
    for directory, dirnames, filenames in os.walk(archive, followlinks=False):
        base = Path(directory)
        safe_dirs: list[str] = []
        for name in sorted(dirnames):
            candidate = base / name
            if candidate.is_symlink():
                raise StorageError(f"symlink directory in canonical archive: {candidate}")
            safe_dirs.append(name)
        dirnames[:] = safe_dirs
        for name in sorted(filenames):
            if not name.lower().endswith(".md"):
                continue
            candidate = base / name
            metadata = candidate.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise StorageError(f"Markdown source must be one regular, unlinked file: {candidate}")
            if metadata.st_size > MAX_MARKDOWN_BYTES:
                raise StorageError(f"Markdown source exceeds size limit: {candidate}")
            found.append((candidate, _source_signature(metadata)))
    found.sort(key=lambda row: canonical_relative_path(row[0], archive))
    return found


def discover_all_markdown(
    archive_root: Path,
    state_root: Path,
) -> list[tuple[str, Path, Path, str, tuple[int, int, int, int]]]:
    """Enumerate both authoritative trees before any stale output is pruned."""
    discovered: list[tuple[str, Path, Path, str, tuple[int, int, int, int]]] = []
    for namespace, root in (("archive", _resolved(archive_root)), ("state", _resolved(state_root))):
        for source, signature in discover_markdown(root):
            identity = source_identity(namespace, source, root)
            discovered.append((namespace, root, source, identity, signature))
    discovered.sort(key=lambda row: row[3])
    return discovered


def _document_entry(identity: str, digest: str, size: int) -> dict[str, Any]:
    return {
        "document_id": document_id(identity),
        "source_path": identity,
        "projection_path": projection_relative_path(identity),
        "source_sha256": digest,
        "projection_sha256": digest,
        "size": size,
    }


def publish_markdown(
    source: Path,
    archive_root: Path = DEFAULT_ARCHIVE_ROOT,
    state_root: Path = DEFAULT_STATE_ROOT,
    projection_root: Path = DEFAULT_PROJECTION_ROOT,
    manifest_path: Path = DEFAULT_MANIFEST_PATH,
    lock_path: Path = DEFAULT_LOCK_PATH,
) -> str | None:
    """Publish one changed Markdown source without pruning any other output."""
    if source.suffix.lower() != ".md":
        return None
    archive, state, projection = validate_roots(archive_root, state_root, projection_root)
    manifest_path = _resolved(manifest_path)
    lock_path = _resolved(lock_path)
    with writer_lock(state):
        return _publish_markdown_locked(source, archive, state, projection, manifest_path, lock_path)


def _publish_markdown_locked(
    source: Path,
    archive: Path,
    state: Path,
    projection: Path,
    manifest_path: Path,
    lock_path: Path,
) -> str:
    original = source.expanduser().absolute()
    if original.is_symlink():
        raise StorageError(f"symlink source is not allowed: {source}")
    absolute = _resolved(original)
    if _is_within(absolute, archive):
        namespace, guarded_root = "archive", archive
    elif _is_within(absolute, state):
        namespace, guarded_root = "state", state
    else:
        raise StorageError(f"Markdown source is outside canonical roots: {source}")
    metadata = original.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise StorageError(f"Markdown source must be one regular, unlinked file: {source}")
    identity = source_identity(namespace, original, guarded_root)
    with exclusive_lock(lock_path):
        manifest = read_manifest(manifest_path)
        target = projection / projection_relative_path(identity)
        _changed, digest, size = project_regular_file(
            original, guarded_root, target, projection, _source_signature(metadata)
        )
        entry = _document_entry(identity, digest, size)
        documents = dict(manifest["documents"])
        documents[identity] = entry
        next_manifest = {
            **manifest,
            "schema": SCHEMA,
            "version": SCHEMA_VERSION,
            "roots": ROOT_IDS,
            "document_count": len(documents),
            "documents": documents,
        }
        comparable_previous = {key: value for key, value in manifest.items() if key != "generated_at"}
        comparable_next = {key: value for key, value in next_manifest.items() if key != "generated_at"}
        if comparable_previous != comparable_next:
            next_manifest["generated_at"] = utcnow()
            atomic_json(manifest_path, next_manifest)
        return str(target)


def publish_markdown_locked(
    source: Path,
    archive_root: Path,
    state_root: Path,
    projection_root: Path,
    manifest_path: Path,
    lock_path: Path,
) -> str | None:
    """Publish one source while the caller already holds ``writer_lock``."""
    if source.suffix.lower() != ".md":
        return None
    archive, state, projection = validate_roots(archive_root, state_root, projection_root)
    manifest = _resolved(manifest_path)
    lock = _resolved(lock_path)
    if not _is_within(manifest, state) or not _is_within(lock, state):
        raise StorageError("manifest and lock must remain inside the state root")
    return _publish_markdown_locked(source, archive, state, projection, manifest, lock)


def write_canonical_bytes(
    path: Path,
    data: bytes,
    *,
    archive_root: Path = DEFAULT_ARCHIVE_ROOT,
    state_root: Path = DEFAULT_STATE_ROOT,
    projection_root: Path = DEFAULT_PROJECTION_ROOT,
    manifest_path: Path = DEFAULT_MANIFEST_PATH,
    lock_path: Path = DEFAULT_LOCK_PATH,
    mode: int = 0o600,
    _writer_lock_held: bool = False,
) -> dict[str, Any]:
    """Durably write one canonical artifact and immediately publish Markdown.

    This is the common writer boundary for direct helpers and state producers.
    Callers that already hold :func:`writer_lock` must pass the internal flag
    so a child/helper cannot deadlock trying to acquire the same process-wide
    file lock again.
    """
    archive, state, projection = validate_roots(archive_root, state_root, projection_root)
    manifest_path = _resolved(manifest_path)
    lock_path = _resolved(lock_path)
    if not _is_within(manifest_path, state) or not _is_within(lock_path, state):
        raise StorageError("manifest and lock must remain inside the state root")
    original = path.expanduser().absolute()
    absolute = _resolved(original)
    if _is_within(absolute, archive):
        guarded_root = archive
    elif _is_within(absolute, state):
        guarded_root = state
    else:
        raise StorageError(f"canonical write is outside archive/state roots: {path}")
    _reject_symlink_chain(absolute, guarded_root)
    guard = contextlib.nullcontext() if _writer_lock_held else writer_lock(state)
    with guard:
        changed = atomic_write_bytes(original, data, mode=mode)
        memory_path: str | None = None
        if original.suffix.lower() == ".md":
            memory_path = _publish_markdown_locked(
                original,
                archive,
                state,
                projection,
                manifest_path,
                lock_path,
            )
        return {"changed": changed, "memory_path": memory_path, "path": str(original)}


def write_canonical_text(
    path: Path,
    text: str,
    **kwargs: Any,
) -> dict[str, Any]:
    """UTF-8 text form of :func:`write_canonical_bytes`."""
    return write_canonical_bytes(path, text.encode("utf-8"), **kwargs)


def read_manifest(path: Path) -> dict[str, Any]:
    try:
        root = _resolved(path.parent.parent)
        payload = json.loads(read_regular_bytes(path, root).decode("utf-8"))
    except FileNotFoundError:
        return {"schema": SCHEMA, "version": SCHEMA_VERSION, "documents": {}}
    except (OSError, json.JSONDecodeError) as exc:
        raise StorageError(f"projection manifest is unreadable: {path}") from exc
    if payload.get("schema") != SCHEMA or payload.get("version") != SCHEMA_VERSION:
        raise StorageError("projection manifest schema/version is not recognized")
    if not isinstance(payload.get("documents"), dict):
        raise StorageError("projection manifest documents map is malformed")
    for identity, entry in payload["documents"].items():
        if not isinstance(identity, str) or not isinstance(entry, dict):
            raise StorageError("projection manifest entry is malformed")
        expected = projection_relative_path(identity)
        relative = entry.get("projection_path")
        posix = PurePosixPath(str(relative or ""))
        if relative != expected or posix.is_absolute() or any(part in {"", ".", ".."} for part in posix.parts):
            raise StorageError(f"projection manifest path is not deterministic for {identity}")
    return payload


def sync_projection(
    archive_root: Path = DEFAULT_ARCHIVE_ROOT,
    projection_root: Path = DEFAULT_PROJECTION_ROOT,
    manifest_path: Path = DEFAULT_MANIFEST_PATH,
    lock_path: Path = DEFAULT_LOCK_PATH,
    *,
    prune: bool = True,
    _writer_lock_held: bool = False,
) -> dict[str, Any]:
    archive, state_root, projection = validate_roots(archive_root, manifest_path.parent.parent, projection_root)
    manifest_path = _resolved(manifest_path)
    lock_path = _resolved(lock_path)
    if not _is_within(manifest_path, state_root) or not _is_within(lock_path, state_root):
        raise StorageError("manifest and lock must remain inside the state root")
    guard = contextlib.nullcontext() if _writer_lock_held else writer_lock(state_root)
    # The first pass enumerates and validates both authoritative roots. The
    # second pass streams each bounded source; no collection of file bodies is
    # held in RAM. Pruning and manifest publication happen only after all
    # sources have been read and atomically published successfully.
    with guard, exclusive_lock(lock_path):
        previous = read_manifest(manifest_path)
        sources = discover_all_markdown(archive, state_root)
        documents: dict[str, Any] = {}
        created = updated = unchanged = 0
        for _namespace, guarded_root, source, identity, signature in sources:
            relative_projection = projection_relative_path(identity)
            target = projection / relative_projection
            prior = previous["documents"].get(identity)
            changed, digest, size = project_regular_file(
                source, guarded_root, target, projection, signature
            )
            if not changed:
                unchanged += 1
            else:
                if prior is None:
                    created += 1
                else:
                    updated += 1
            documents[identity] = _document_entry(identity, digest, size)
        removed = 0
        if prune:
            active_outputs = {entry["projection_path"] for entry in documents.values()}
            for relative_source, entry in previous["documents"].items():
                relative_output = entry.get("projection_path")
                if not isinstance(relative_output, str) or relative_output in active_outputs:
                    continue
                if relative_output != projection_relative_path(relative_source):
                    raise StorageError(f"non-deterministic stale projection path for {relative_source}")
                expected = projection / relative_output
                if not _is_within(_resolved(expected), projection):
                    raise StorageError(f"unsafe stale projection path in manifest: {relative_output}")
                try:
                    metadata = expected.lstat()
                except FileNotFoundError:
                    continue
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise StorageError(f"refusing to prune unsafe projection target: {expected}")
                expected.unlink()
                _fsync_directory(expected.parent)
                removed += 1
        else:
            # Retain stale mappings as tombstones so a later authoritative
            # pruning run can still identify and safely remove their outputs.
            for identity, entry in previous["documents"].items():
                if identity not in documents:
                    documents[identity] = {**entry, "tombstone": True}
        next_manifest = {
            "schema": SCHEMA,
            "version": SCHEMA_VERSION,
            "roots": ROOT_IDS,
            "generated_at": utcnow(),
            "document_count": len(documents),
            "documents": documents,
        }
        # generated_at must not turn an idempotent sync into a manifest write.
        comparable_previous = {key: value for key, value in previous.items() if key != "generated_at"}
        comparable_next = {key: value for key, value in next_manifest.items() if key != "generated_at"}
        manifest_changed = comparable_previous != comparable_next
        if manifest_changed:
            atomic_json(manifest_path, next_manifest)
        return {
            "created": created,
            "updated": updated,
            "unchanged": unchanged,
            "removed": removed,
            "document_count": len(documents),
            "manifest_changed": manifest_changed,
            "manifest_path": str(manifest_path),
            "projection_root": str(projection),
        }


def sync_projection_locked(
    archive_root: Path,
    projection_root: Path,
    manifest_path: Path,
    lock_path: Path,
    *,
    prune: bool,
) -> dict[str, Any]:
    """Sync while the caller already holds ``writer_lock(state_root)``."""
    return sync_projection(
        archive_root,
        projection_root,
        manifest_path,
        lock_path,
        prune=prune,
        _writer_lock_held=True,
    )


def memory_path_for(source: Path, archive_root: Path, projection_root: Path) -> str:
    return str(projection_path_for(source, archive_root, projection_root))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sync = sub.add_parser("sync", help="atomically reconcile all canonical Markdown into memory")
    sync.add_argument("--archive-root", type=Path, default=DEFAULT_ARCHIVE_ROOT)
    sync.add_argument("--state-root", type=Path, default=DEFAULT_STATE_ROOT)
    sync.add_argument("--projection-root", type=Path, default=DEFAULT_PROJECTION_ROOT)
    sync.add_argument("--no-prune", action="store_true", help="do not remove outputs missing from this complete scan")
    path = sub.add_parser("path", help="resolve the stable memory path for one canonical Markdown source")
    path.add_argument("source", type=Path)
    path.add_argument("--archive-root", type=Path, default=DEFAULT_ARCHIVE_ROOT)
    path.add_argument("--projection-root", type=Path, default=DEFAULT_PROJECTION_ROOT)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "path":
            payload: Any = {"memory_path": memory_path_for(args.source, args.archive_root, args.projection_root)}
        else:
            state_root = _resolved(args.state_root)
            payload = sync_projection(
                args.archive_root,
                args.projection_root,
                state_root / "projection/manifest.json",
                state_root / "locks/projection.lock",
                prune=not args.no_prune,
            )
    except (StorageError, OSError, ValueError) as exc:
        print(json.dumps({"error": str(exc), "error_type": type(exc).__name__}), file=sys.stderr)
        return 2
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
