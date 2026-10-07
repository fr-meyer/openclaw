#!/usr/bin/env python3
"""Source-neutral YouTube transcript processing pool foundation.

Phase 1 intentionally implements only inert, file-backed planning primitives:
state schemas, atomic writes/events, deterministic selection, coordinator/import
locks, exclusive leases, and read-only migration previews.  It does not launch
node workers, touch cron jobs, configure OAuth, mutate YouTube, or import
archives.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import importlib.util
import json
import os
import re
import shutil
import sys
import tempfile
import uuid
from collections import Counter
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Iterator
from urllib.parse import parse_qs, urlparse


SCHEMA_PREFIX = "franck.youtube-global-pool"
try:
    import youtube_storage as STORAGE
except ModuleNotFoundError:
    _storage_path = Path(__file__).resolve().with_name("youtube_storage.py")
    _storage_spec = importlib.util.spec_from_file_location("youtube_storage", _storage_path)
    if _storage_spec is None or _storage_spec.loader is None:
        raise RuntimeError("could not load YouTube storage contract")
    STORAGE = importlib.util.module_from_spec(_storage_spec)
    sys.modules[_storage_spec.name] = STORAGE
    _storage_spec.loader.exec_module(STORAGE)

DEFAULT_POOL_ROOT = STORAGE.DEFAULT_POOL_ROOT
DEFAULT_ARCHIVE_ROOT = STORAGE.DEFAULT_ARCHIVE_ROOT
DEFAULT_PERSONAL_QUEUE_ROOT = STORAGE.DEFAULT_QUEUE_ROOT
DEFAULT_YC_ROOT = STORAGE.DEFAULT_YC_ROOT

VIDEO_ID_RE = re.compile(r"^[A-Za-z0-9_-]{11}$")
STORAGE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
MEDIA_EXTENSIONS = {".mp4", ".m4a", ".webm", ".mp3", ".wav", ".mov", ".mkv", ".opus"}

LANE_ORDER = {
    "urgent_personal": 0,
    "personal": 1,
    "fresh_monitored": 2,
    "bulk_archive": 3,
    "approved_takeout": 4,
}
PRIORITY_ORDER = {"urgent": 0, "high": 1, "normal": 2, "low": 3}
TERMINAL_STATUSES = {
    "archived",
    "done",
    "metadata_only_no_captions",
    "skipped_existing",
    "blocked_bot_check",
    "blocked_auth_required",
    "blocked_configuration",
    "blocked_error",
    "skipped_private",
    "skipped_age_restricted",
    "skipped_unavailable",
    "cancelled",
}
ACTIVE_ITEM_STATUSES = {"leased", "processing", "returned", "importing"}
YC_ACTIVE_CHUNK_STATES = {
    "planned",
    "launching",
    "running",
    "launched",
    "waiting_for_worker",
    "returned",
    "importing",
}


class PoolError(RuntimeError):
    """Base pool exception."""


class PoolLockError(PoolError):
    """Raised when a lock cannot be acquired."""


class LeaseConflictError(PoolError):
    """Raised when attempting to lease an already leased video."""


@dataclass(frozen=True)
class SelectionPolicy:
    """Deterministic scheduler reservation policy."""

    chunk_size: int = 25
    personal_reserved: int = 5
    fresh_reserved: int = 5
    aging_promote_after_days: int = 3
    guarantee_after_days: int = 7

    def __post_init__(self) -> None:
        if not 1 <= self.chunk_size <= 25:
            raise ValueError("chunk_size must be 1..25")
        if self.personal_reserved < 0 or self.fresh_reserved < 0:
            raise ValueError("reservations must be non-negative")


@dataclass(frozen=True)
class NodeTarget:
    """A node selected by preflight outside this Phase 1 module."""

    node_id: str
    label: str
    platform: str
    adapter_version: str = "unknown"
    max_chunk_size: int = 25


class FileLock:
    """Small fcntl lock wrapper for coordinator/import critical sections."""

    def __init__(self, path: Path, *, blocking: bool = True) -> None:
        self.path = path
        self.blocking = blocking
        self._fd: int | None = None

    def __enter__(self) -> "FileLock":
        ensure_directory_durable(self.path.parent)
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        flags = fcntl.LOCK_EX | (0 if self.blocking else fcntl.LOCK_NB)
        try:
            fcntl.flock(fd, flags)
        except BlockingIOError as exc:
            os.close(fd)
            raise PoolLockError(f"lock already held: {self.path}") from exc
        self._fd = fd
        os.ftruncate(fd, 0)
        os.write(fd, str(os.getpid()).encode("ascii"))
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        if self._fd is not None:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
            os.close(self._fd)
            self._fd = None


def utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def parse_time(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def ensure_z(value: dt.datetime | str | None) -> str:
    if value is None:
        return utcnow()
    if isinstance(value, str):
        parsed = parse_time(value)
        if parsed is None:
            raise ValueError(f"invalid ISO-8601 timestamp: {value!r}")
        return parsed.isoformat().replace("+00:00", "Z")
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def fsync_directory(path: Path) -> None:
    directory_fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def ensure_directory_durable(path: Path) -> None:
    missing = []
    current = path
    while not current.exists():
        missing.append(current)
        current = current.parent
    path.mkdir(parents=True, exist_ok=True)
    # Persist each newly created name before a journal can depend on it.
    for directory in reversed(missing):
        fsync_directory(directory.parent)


def atomic_write(path: Path, text: str) -> None:
    ensure_directory_durable(path.parent)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)
    fsync_directory(path.parent)


def atomic_json(path: Path, payload: Any) -> None:
    atomic_write(path, json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def write_canonical_markdown_if_authoritative(path: Path, text: str) -> None:
    """Publish production archive/state Markdown; keep test/export paths local."""
    resolved = path.expanduser().resolve(strict=False)
    archive = STORAGE.DEFAULT_ARCHIVE_ROOT.expanduser().resolve(strict=False)
    state = STORAGE.DEFAULT_STATE_ROOT.expanduser().resolve(strict=False)
    if resolved.is_relative_to(archive) or resolved.is_relative_to(state):
        STORAGE.write_canonical_text(
            path,
            text,
            archive_root=archive,
            state_root=state,
            projection_root=STORAGE.DEFAULT_PROJECTION_ROOT,
            manifest_path=STORAGE.DEFAULT_MANIFEST_PATH,
            lock_path=STORAGE.DEFAULT_LOCK_PATH,
        )
    else:
        atomic_write(path, text)


def publish_existing_markdown_if_authoritative(path: Path) -> None:
    """Publish an already committed production Markdown artifact."""
    resolved = path.expanduser().resolve(strict=False)
    archive = STORAGE.DEFAULT_ARCHIVE_ROOT.expanduser().resolve(strict=False)
    state = STORAGE.DEFAULT_STATE_ROOT.expanduser().resolve(strict=False)
    if resolved.is_relative_to(archive) or resolved.is_relative_to(state):
        STORAGE.publish_markdown(
            path,
            archive,
            state,
            STORAGE.DEFAULT_PROJECTION_ROOT,
            STORAGE.DEFAULT_MANIFEST_PATH,
            STORAGE.DEFAULT_LOCK_PATH,
        )


def read_json(path: Path, default: Any = None) -> Any:
    if not path.is_file():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    atomic_write(path, "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows))


def canonical_url(video_id: str) -> str:
    return f"https://www.youtube.com/watch?v={video_id}"


def allowed_youtube_host(host: str) -> bool:
    host = host.lower().strip().rstrip(".")
    return host == "youtu.be" or host == "youtube.com" or host.endswith(".youtube.com")


def extract_video_id(value: str) -> str:
    """Extract a YouTube video ID from a strict, allowlisted URL or bare ID."""
    raw = str(value).strip()
    if VIDEO_ID_RE.match(raw):
        return raw
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"not a YouTube URL or bare video ID: {value!r}")
    host = parsed.hostname or ""
    if not allowed_youtube_host(host):
        raise ValueError(f"unsupported YouTube host: {host!r}")
    path_parts = [part for part in parsed.path.split("/") if part]
    candidate: str | None = None
    if host.lower().strip().rstrip(".") == "youtu.be":
        candidate = path_parts[0] if path_parts else None
    elif path_parts[:1] == ["watch"]:
        candidate = (parse_qs(parsed.query).get("v") or [None])[0]
    elif path_parts and path_parts[0] in {"shorts", "embed", "live"}:
        candidate = path_parts[1] if len(path_parts) >= 2 else None
    if candidate and VIDEO_ID_RE.match(candidate):
        return candidate
    raise ValueError(f"could not extract a valid YouTube video ID from {value!r}")


def validate_video_id(video_id: str) -> str:
    video_id = str(video_id).strip()
    if not VIDEO_ID_RE.match(video_id):
        raise ValueError(f"invalid YouTube video id: {video_id!r}")
    return video_id


def validate_storage_id(value: str, label: str) -> str:
    value = str(value).strip()
    if not STORAGE_ID_RE.match(value):
        raise ValueError(f"invalid {label}: {value!r}")
    return value


def path_has_media(path: Path) -> bool:
    if not path.exists():
        return False
    return any(child.is_file() and child.suffix.lower() in MEDIA_EXTENSIONS for child in path.rglob("*"))


def validate_archive_folder(archive_root: Path, video_id: str) -> dict[str, Any]:
    video_id = validate_video_id(video_id)
    root = archive_root.resolve()
    folder = archive_root / video_id
    if not folder.is_dir() or folder.is_symlink():
        raise ValueError(f"{video_id}: archive folder missing or unsafe")
    resolved_folder = folder.resolve()
    if not resolved_folder.is_relative_to(root):
        raise ValueError(f"{video_id}: archive folder escaped the canonical root")
    manifest_path = folder / "manifest.json"
    report_path = folder / "report.md"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise ValueError(f"{video_id}: manifest.json missing or unsafe")
    if not report_path.is_file() or report_path.is_symlink():
        raise ValueError(f"{video_id}: report.md missing or unsafe")
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    if payload.get("video_id") != video_id:
        raise ValueError(f"{video_id}: manifest identity mismatch")
    files = payload.get("files")
    if not isinstance(files, list) or not files:
        raise ValueError(f"{video_id}: manifest files list missing or empty")
    transcript_path: str | None = None
    for raw in files:
        raw_value = str(raw)
        posix = PurePosixPath(raw_value.replace("\\", "/"))
        windows = PureWindowsPath(raw_value)
        if (
            not raw_value
            or posix.is_absolute()
            or windows.is_absolute()
            or bool(windows.drive)
            or ".." in posix.parts
            or ".." in windows.parts
        ):
            raise ValueError(f"{video_id}: unsafe manifest path {raw!r}")
        relative = Path(*posix.parts)
        candidate = folder / relative
        if not candidate.is_file() or candidate.is_symlink() or not candidate.resolve().is_relative_to(resolved_folder):
            raise ValueError(f"{video_id}: missing or unsafe listed file {raw!r}")
        if candidate.suffix.lower() in MEDIA_EXTENSIONS:
            raise ValueError(f"{video_id}: media file listed in archive")
        if raw_value.endswith("clean-deduped.txt"):
            transcript_path = str(candidate)
    for candidate in folder.rglob("*"):
        if candidate.is_symlink():
            raise ValueError(f"{video_id}: archive contains a symlink")
        if candidate.is_file() and candidate.suffix.lower() in MEDIA_EXTENSIONS:
            raise ValueError(f"{video_id}: archive contains media")
    return {
        "manifest": payload,
        "report_path": str(report_path),
        "transcript_path": transcript_path,
    }


def archive_complete(archive_root: Path, video_id: str) -> tuple[bool, str | None, str | None]:
    try:
        validated = validate_archive_folder(archive_root, video_id)
    except Exception:
        return False, None, None
    return True, validated["report_path"], validated["transcript_path"]


def source_lane(source: dict[str, Any]) -> str:
    explicit = source.get("lane")
    if explicit in LANE_ORDER:
        return str(explicit)
    source_type = str(source.get("type") or "")
    priority = str(source.get("priority") or "normal")
    if priority == "urgent":
        return "urgent_personal"
    if source_type in {"chat_share", "playlist_read", "manual_personal"}:
        return "personal"
    if source_type == "fresh_channel":
        return "fresh_monitored"
    if source_type == "takeout_candidate":
        return "approved_takeout" if source.get("approved") else "approved_takeout"
    return "bulk_archive"


def strongest_priority(left: str | None, right: str | None) -> str:
    left = left if left in PRIORITY_ORDER else "normal"
    right = right if right in PRIORITY_ORDER else "normal"
    return left if PRIORITY_ORDER[left] <= PRIORITY_ORDER[right] else right


def strongest_lane(left: str | None, right: str | None) -> str:
    left = left if left in LANE_ORDER else "bulk_archive"
    right = right if right in LANE_ORDER else "bulk_archive"
    return left if LANE_ORDER[left] <= LANE_ORDER[right] else right


def source_key(source: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(source.get("type") or "unknown"),
        str(source.get("ref") or source.get("source_ref") or ""),
        str(source.get("requested_action") or "archive_transcript"),
    )


def normalize_source(source: dict[str, Any], *, now: str | None = None) -> dict[str, Any]:
    requested_at = ensure_z(source.get("requested_at") or source.get("received_at") or now)
    lane = source.get("lane")
    priority = source.get("priority") or "normal"
    if lane is not None and lane not in LANE_ORDER:
        raise ValueError(f"unknown processing lane: {lane!r}")
    if priority not in PRIORITY_ORDER:
        raise ValueError(f"unknown priority: {priority!r}")
    normalized = {
        "type": str(source.get("type") or source.get("source_type") or "manual_import"),
        "ref": source.get("ref") or source.get("source_ref"),
        "requested_at": requested_at,
        "requested_action": source.get("requested_action") or "archive_transcript",
        "priority": priority,
        "lane": lane,
        "title_hint": source.get("title_hint") or source.get("title"),
        "memberships": list(source.get("memberships") or []),
        "approved": bool(source.get("approved", False)),
    }
    return {k: v for k, v in normalized.items() if v is not None}


def make_item(
    video_id: str,
    url: str | None,
    source: dict[str, Any],
    *,
    status: str | None = None,
    report_path: str | None = None,
    transcript_path: str | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    video_id = validate_video_id(video_id)
    if url and extract_video_id(str(url)) != video_id:
        raise ValueError(f"YouTube URL does not match video id {video_id}")
    source = normalize_source(source, now=now)
    lane = source_lane(source)
    if status is None:
        status = "review_required" if source.get("type") == "takeout_candidate" and not source.get("approved") else "pending"
    requested_at = source["requested_at"]
    return {
        "schema": f"{SCHEMA_PREFIX}.work-item.v1",
        "video_id": video_id,
        "url": canonical_url(video_id),
        "sources": [source],
        "lane": lane,
        "priority": source.get("priority") if source.get("priority") in PRIORITY_ORDER else "normal",
        "status": status,
        "requested_at": requested_at,
        "process_after": requested_at,
        "retry_after": None,
        "attempt_count": 0,
        "active_lease_id": None,
        "active_node": None,
        "report_path": report_path,
        "transcript_path": transcript_path,
        "summary_status": "not_requested",
        "auth_allowed": False,
        "media_download_allowed": False,
        "updated_at": ensure_z(now),
    }


def merge_item(
    existing: dict[str, Any] | None,
    video_id: str,
    url: str | None,
    source: dict[str, Any],
    *,
    status: str | None = None,
    report_path: str | None = None,
    transcript_path: str | None = None,
    now: str | None = None,
) -> tuple[dict[str, Any], bool]:
    video_id = validate_video_id(video_id)
    if url and extract_video_id(str(url)) != video_id:
        raise ValueError(f"YouTube URL does not match video id {video_id}")
    if existing is None:
        return make_item(
            video_id,
            url,
            source,
            status=status,
            report_path=report_path,
            transcript_path=transcript_path,
            now=now,
        ), True

    normalized = normalize_source(source, now=now)
    existing["url"] = canonical_url(video_id)
    seen = {source_key(src) for src in existing.get("sources") or []}
    if source_key(normalized) not in seen:
        existing.setdefault("sources", []).append(normalized)
    existing["lane"] = strongest_lane(existing.get("lane"), source_lane(normalized))
    existing["priority"] = strongest_priority(existing.get("priority"), normalized.get("priority"))
    requested_times = [parse_time(src.get("requested_at")) for src in existing.get("sources") or []]
    requested_times = [value for value in requested_times if value is not None]
    if requested_times:
        existing["requested_at"] = min(requested_times).isoformat().replace("+00:00", "Z")
    if not existing.get("process_after"):
        existing["process_after"] = existing.get("requested_at") or ensure_z(now)
    if report_path and not existing.get("report_path"):
        existing["report_path"] = report_path
    if transcript_path and not existing.get("transcript_path"):
        existing["transcript_path"] = transcript_path
    if status == "skipped_existing" and existing.get("status") not in ACTIVE_ITEM_STATUSES:
        existing["status"] = "skipped_existing"
    elif status == "external_active" and existing.get("status") not in TERMINAL_STATUSES:
        existing["status"] = "external_active"
    elif existing.get("status") == "review_required" and normalized.get("approved"):
        existing["status"] = "pending"
    existing["auth_allowed"] = bool(existing.get("auth_allowed", False)) and bool(normalized.get("auth_allowed", False))
    existing["media_download_allowed"] = False
    existing["updated_at"] = ensure_z(now)
    return existing, False


class PoolStore:
    """File-backed global pool state store."""

    def __init__(self, root: Path | str = DEFAULT_POOL_ROOT) -> None:
        self.root = Path(root)

    @property
    def items_dir(self) -> Path:
        return self.root / "items"

    @property
    def leases_dir(self) -> Path:
        return self.root / "leases"

    @property
    def chunks_dir(self) -> Path:
        return self.root / "chunks"

    @property
    def locks_dir(self) -> Path:
        return self.root / "locks"

    @property
    def events_path(self) -> Path:
        return self.root / "events.jsonl"

    @property
    def state_path(self) -> Path:
        return self.root / "state.json"

    @property
    def status_path(self) -> Path:
        return self.root / "status.md"

    def ensure_dirs(self) -> None:
        for directory in [self.items_dir, self.leases_dir, self.chunks_dir, self.locks_dir, self.root / "bundles", self.root / "imports", self.root / "runs"]:
            ensure_directory_durable(directory)

    @contextlib.contextmanager
    def coordinator_lock(self, *, blocking: bool = True) -> Iterator[None]:
        with FileLock(self.locks_dir / "coordinator.lock", blocking=blocking):
            yield

    @contextlib.contextmanager
    def import_lock(self, *, blocking: bool = True) -> Iterator[None]:
        with FileLock(self.locks_dir / "import.lock", blocking=blocking):
            yield

    def item_path(self, video_id: str) -> Path:
        return self.items_dir / f"{validate_video_id(video_id)}.json"

    def load_item(self, video_id: str) -> dict[str, Any] | None:
        return read_json(self.item_path(video_id))

    def save_item(self, item: dict[str, Any]) -> None:
        validate_video_id(str(item["video_id"]))
        item.setdefault("schema", f"{SCHEMA_PREFIX}.work-item.v1")
        item["updated_at"] = ensure_z(item.get("updated_at"))
        atomic_json(self.item_path(str(item["video_id"])), item)

    def load_items(self) -> list[dict[str, Any]]:
        if not self.items_dir.exists():
            return []
        return [json.loads(path.read_text(encoding="utf-8")) for path in sorted(self.items_dir.glob("*.json"))]

    def retry_blocked_items(
        self,
        video_ids: list[str],
        *,
        allowed_reason: str,
        now: str | None = None,
        dry_run: bool = False,
    ) -> list[dict[str, Any]]:
        """Requeue an exact, validated set of blocked items, or change nothing."""
        ids = [validate_video_id(value) for value in video_ids]
        if not ids or len(ids) != len(set(ids)):
            raise PoolError("retry requires a non-empty set of unique video IDs")
        reason = str(allowed_reason)
        if not reason:
            raise PoolError("retry requires an explicit non-empty allowed reason")
        timestamp = ensure_z(now)
        with self.coordinator_lock():
            active_leases = [
                read_json(path, {}) or {}
                for path in sorted(self.leases_dir.glob("*.json"))
                if (read_json(path, {}) or {}).get("state") == "active"
            ]
            if active_leases:
                raise PoolError("cannot retry while global pool has active lease(s)")
            originals: dict[str, dict[str, Any]] = {}
            for video_id in ids:
                item = self.load_item(video_id)
                if item is None:
                    raise PoolError(f"cannot retry unknown item {video_id}")
                if item.get("status") != "blocked_error":
                    raise PoolError(f"item {video_id} is not blocked_error")
                if item.get("active_lease_id") is not None or item.get("active_node") is not None:
                    raise PoolError(f"item {video_id} has an active lease binding")
                if item.get("last_error") != reason:
                    raise PoolError(f"item {video_id} error does not match allowed reason")
                originals[video_id] = json.loads(json.dumps(item))
            if dry_run:
                return list(originals.values())
            changed: list[dict[str, Any]] = []
            try:
                for video_id, original in originals.items():
                    item = json.loads(json.dumps(original))
                    item.setdefault("retry_history", []).append({
                        "status": original.get("status"),
                        "last_error": original.get("last_error"),
                        "attempt_count": original.get("attempt_count", 0),
                        "recorded_at": timestamp,
                    })
                    item["status"] = "pending"
                    item["retry_after"] = None
                    item["active_lease_id"] = None
                    item["active_node"] = None
                    item["attempt_count"] = int(original.get("attempt_count", 0)) + 1
                    item["last_error"] = None
                    item["updated_at"] = timestamp
                    self.save_item(item)
                    changed.append(item)
                self.append_event(
                    "blocked_items_requeued",
                    video_ids=ids,
                    allowed_reason=reason,
                    prior_items=originals,
                )
                self.write_state()
            except Exception:
                for video_id, original in originals.items():
                    self.save_item(original)
                raise
            return changed

    def append_event(self, event_type: str, *, event_id: str | None = None, **payload: Any) -> None:
        self.ensure_dirs()
        if event_id and any(row.get("event_id") == event_id for row in read_jsonl(self.events_path)):
            return
        event = {
            "schema": f"{SCHEMA_PREFIX}.event.v1",
            "event_id": event_id or str(uuid.uuid4()),
            "created_at": utcnow(),
            "type": event_type,
            **payload,
        }
        with (self.events_path).open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        fsync_directory(self.events_path.parent)

    def merge_source(self, video_id: str, url: str | None, source: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        with self.coordinator_lock():
            existing = self.load_item(video_id)
            item, created = merge_item(existing, video_id, url, source, **kwargs)
            self.save_item(item)
            self.append_event("item_created" if created else "item_source_merged", video_id=video_id, source=source_key(normalize_source(source)))
            self.write_state()
            return item

    def write_state(self) -> dict[str, Any]:
        self.ensure_dirs()
        items = self.load_items()
        status_counts = Counter(str(item.get("status") or "unknown") for item in items)
        lane_counts = Counter(str(item.get("lane") or "unknown") for item in items)
        active_leases = [path.stem for path in sorted(self.leases_dir.glob("*.json")) if (read_json(path, {}) or {}).get("state") == "active"]
        payload = {
            "schema": f"{SCHEMA_PREFIX}.state.v1",
            "updated_at": utcnow(),
            "item_count": len(items),
            "status_counts": dict(sorted(status_counts.items())),
            "lane_counts": dict(sorted(lane_counts.items())),
            "active_lease_count": len(active_leases),
            "active_leases": active_leases,
            "cookies_used": False,
            "media_files": 0,
        }
        previous = read_json(self.state_path, {}) or {}
        if previous.get("materialization"):
            payload["materialization"] = previous["materialization"]
        atomic_json(self.state_path, payload)
        return payload

    def write_status(self) -> str:
        state = self.write_state()
        lines = [
            "# YouTube global processing pool status",
            "",
            f"Updated: {state['updated_at']}",
            f"Items: {state['item_count']}",
            f"Active leases: {state['active_lease_count']}",
            "Cookies used: no",
            "Media files: 0",
            "",
            "## Status counts",
        ]
        for key, value in state["status_counts"].items():
            lines.append(f"- {key}: {value}")
        lines.append("")
        lines.append("## Lane counts")
        for key, value in state["lane_counts"].items():
            lines.append(f"- {key}: {value}")
        text = "\n".join(lines) + "\n"
        write_canonical_markdown_if_authoritative(self.status_path, text)
        return text

    def validate_active_lease_graph(self) -> dict[str, dict[str, Any]]:
        """Return a coordinator-consistent, fully validated active lease graph.

        This validates storage identity, node uniqueness, chunk bindings, item
        bindings, and the anonymous caption-only safety flags for *every* active
        lease.  Callers still decide which node-scoped leases are authorized.
        """
        self.ensure_dirs()
        with self.coordinator_lock():
            leases: dict[str, dict[str, Any]] = {}
            for path in sorted(self.leases_dir.glob("*.json")):
                lease = read_json(path, {}) or {}
                if lease.get("state") != "active":
                    continue
                lease_id = str(lease.get("lease_id") or "")
                if not lease_id or lease_id != path.stem:
                    raise PoolError(f"active lease storage identity differs: {path.name}")
                if lease_id in leases:
                    raise PoolError(f"duplicate active lease identity: {lease_id}")
                leases[lease_id] = lease

            items = self.load_items()
            item_by_id = {str(item.get("video_id") or ""): item for item in items}
            active_items = {
                str(item.get("video_id") or ""): item
                for item in items
                if item.get("status") in ACTIVE_ITEM_STATUSES
                or item.get("active_lease_id") is not None
                or item.get("active_node") is not None
            }
            seen_video_ids: set[str] = set()
            seen_node_ids: set[str] = set()
            graph: dict[str, dict[str, Any]] = {}
            for lease_id, lease in leases.items():
                if lease.get("cookies_used") is not False or lease.get("media_allowed") is not False:
                    raise PoolError(f"active lease violates anonymous caption-only policy: {lease_id}")
                node = lease.get("node") if isinstance(lease.get("node"), dict) else {}
                node_id = str(node.get("id") or "")
                node_platform = str(node.get("platform") or "")
                chunk_id = str(lease.get("chunk_id") or "")
                video_ids = [validate_video_id(str(value)) for value in lease.get("video_ids") or []]
                if (
                    not node_id
                    or not node_platform
                    or not chunk_id
                    or not video_ids
                    or len(video_ids) != len(set(video_ids))
                ):
                    raise PoolError(f"active lease binding is incomplete: {lease_id}")
                if node_id in seen_node_ids:
                    raise PoolError(f"node has multiple active leases: {node_id}")
                seen_node_ids.add(node_id)
                overlap = seen_video_ids.intersection(video_ids)
                if overlap:
                    raise PoolError(f"active leases overlap on items: {sorted(overlap)}")
                seen_video_ids.update(video_ids)

                chunk = read_json(self.chunks_dir / f"{chunk_id}.json", {}) or {}
                chunk_video_ids = [str(item.get("video_id") or "") for item in chunk.get("items") or []]
                if (
                    chunk.get("lease_id") != lease_id
                    or chunk.get("chunk_id") != chunk_id
                    or chunk.get("node_id") != node_id
                    or chunk_video_ids != video_ids
                    or chunk.get("cookies_used") is not False
                    or chunk.get("media_allowed") is not False
                ):
                    raise PoolError(f"active chunk/lease binding differs: {lease_id}")
                for video_id in video_ids:
                    item = item_by_id.get(video_id)
                    if (
                        not item
                        or item.get("status") not in ACTIVE_ITEM_STATUSES
                        or item.get("active_lease_id") != lease_id
                        or item.get("active_node") != node_id
                    ):
                        raise PoolError(f"active item lease binding differs: {video_id}")
                graph[lease_id] = {
                    "lease": lease,
                    "chunk": chunk,
                    "video_ids": video_ids,
                    "node_id": node_id,
                    "node_platform": node_platform,
                }

            if set(active_items) != seen_video_ids:
                orphaned = sorted(set(active_items) - seen_video_ids)
                missing = sorted(seen_video_ids - set(active_items))
                raise PoolError(
                    "active item/lease graph differs: "
                    f"orphaned={orphaned}, missing={missing}"
                )
            return graph

    def create_lease(
        self,
        node: NodeTarget,
        items: list[dict[str, Any]],
        *,
        lease_id: str | None = None,
        chunk_id: str | None = None,
        now: str | None = None,
    ) -> dict[str, Any]:
        if not items:
            raise ValueError("cannot create an empty lease")
        if len(items) > node.max_chunk_size:
            raise ValueError(f"node chunk cap exceeded: {len(items)} > {node.max_chunk_size}")
        timestamp = ensure_z(now)
        lease_id = validate_storage_id(lease_id or str(uuid.uuid4()), "lease id")
        chunk_id = validate_storage_id(chunk_id or f"chunk-{timestamp.replace(':', '').replace('-', '').replace('.', '')}-{lease_id[:8]}", "chunk id")
        video_ids = [validate_video_id(str(item["video_id"])) for item in items]
        if len(video_ids) != len(set(video_ids)):
            raise LeaseConflictError("chunk contains duplicate video IDs")

        with self.coordinator_lock():
            current_items = {str(item["video_id"]): item for item in self.load_items()}
            lease_path = self.leases_dir / f"{lease_id}.json"
            chunk_path = self.chunks_dir / f"{chunk_id}.json"
            journal_path = self.root / "runs" / f"lease-create-{lease_id}.json"
            existing_lease = read_json(lease_path, {}) or {}
            existing_chunk = read_json(chunk_path, {}) or {}
            if existing_lease or existing_chunk:
                exact_replay = (
                    existing_lease.get("lease_id") == lease_id
                    and existing_lease.get("chunk_id") == chunk_id
                    and existing_lease.get("node", {}).get("id") == node.node_id
                    and existing_lease.get("video_ids") == video_ids
                    and existing_chunk.get("lease_id") == lease_id
                    and existing_chunk.get("chunk_id") == chunk_id
                    and all(
                        (current_items.get(video_id) or {}).get("active_lease_id") == lease_id
                        and (current_items.get(video_id) or {}).get("active_node") == node.node_id
                        for video_id in video_ids
                    )
                )
                if exact_replay:
                    journal = read_json(journal_path, {}) or {}
                    # A process can stop after the last item write but before
                    # these side effects. Their deterministic event ID and
                    # aggregate rebuild make exact recovery idempotent.
                    event_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"youtube-lease-created:{lease_id}:{chunk_id}"))
                    self.append_event("lease_created", event_id=event_id, lease_id=lease_id, chunk_id=chunk_id, node_id=node.node_id, video_ids=video_ids)
                    self.write_state()
                    if journal.get("state") == "prepared":
                        journal["state"] = "committed"
                        journal["committed_at"] = utcnow()
                        atomic_json(journal_path, journal)
                    return existing_lease
                journal = read_json(journal_path, {}) or {}
                if (
                    journal.get("state") == "prepared"
                    and journal.get("lease_id") == lease_id
                    and journal.get("chunk_id") == chunk_id
                ):
                    for video_id, preimage in (journal.get("preimages") or {}).items():
                        self.save_item(preimage)
                    for path in (lease_path, chunk_path):
                        if path.exists():
                            path.unlink()
                    journal["state"] = "recovered_rollback"
                    journal["recovered_at"] = utcnow()
                    atomic_json(journal_path, journal)
                    self.write_state()
                    raise LeaseConflictError("recovered an interrupted lease creation; retry with fresh item state")
                raise LeaseConflictError(f"lease or chunk identifier collision: {lease_id} / {chunk_id}")
            for path in self.leases_dir.glob("*.json"):
                active = read_json(path, {}) or {}
                if active.get("state") == "active" and active.get("node", {}).get("id") == node.node_id:
                    raise LeaseConflictError(f"node {node.node_id} already has active lease {active.get('lease_id')}")
            for video_id in video_ids:
                item = current_items.get(video_id)
                if item is None:
                    raise LeaseConflictError(f"cannot lease unknown item {video_id}")
                if item.get("active_lease_id") or item.get("status") in ACTIVE_ITEM_STATUSES:
                    raise LeaseConflictError(f"video {video_id} already has active lease {item.get('active_lease_id')}")
                if item.get("status") != "pending":
                    raise LeaseConflictError(f"video {video_id} is not pending: {item.get('status')}")

            lease = {
                "schema": f"{SCHEMA_PREFIX}.lease.v1",
                "lease_id": lease_id,
                "chunk_id": chunk_id,
                "state": "active",
                "created_at": timestamp,
                "node": {
                    "id": node.node_id,
                    "label": node.label,
                    "platform": node.platform,
                    "adapter_version": node.adapter_version,
                },
                "video_ids": video_ids,
                "cookies_used": False,
                "media_allowed": False,
            }
            chunk = {
                "schema": f"{SCHEMA_PREFIX}.chunk.v1",
                "chunk_id": chunk_id,
                "lease_id": lease_id,
                "created_at": timestamp,
                "state": "leased",
                "node_id": node.node_id,
                "node_label": node.label,
                "node_platform": node.platform,
                "items": [
                    {
                        "video_id": video_id,
                        "url": canonical_url(video_id),
                        "lane": current_items[video_id].get("lane"),
                        "priority": current_items[video_id].get("priority"),
                    }
                    for video_id in video_ids
                ],
                "cookies_used": False,
                "media_allowed": False,
            }
            journal = {
                "schema": f"{SCHEMA_PREFIX}.lease-create-journal.v1",
                "state": "prepared",
                "prepared_at": timestamp,
                "lease_id": lease_id,
                "chunk_id": chunk_id,
                "preimages": {video_id: current_items[video_id] for video_id in video_ids},
                "lease": lease,
                "chunk": chunk,
            }
            atomic_json(journal_path, journal)
            try:
                atomic_json(lease_path, lease)
                atomic_json(chunk_path, chunk)
                for video_id in video_ids:
                    item = json.loads(json.dumps(current_items[video_id]))
                    item["status"] = "leased"
                    item["active_lease_id"] = lease_id
                    item["active_node"] = node.node_id
                    item["updated_at"] = timestamp
                    self.save_item(item)
                event_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"youtube-lease-created:{lease_id}:{chunk_id}"))
                self.append_event("lease_created", event_id=event_id, lease_id=lease_id, chunk_id=chunk_id, node_id=node.node_id, video_ids=video_ids)
                self.write_state()
                journal["state"] = "committed"
                journal["committed_at"] = utcnow()
                atomic_json(journal_path, journal)
                return lease
            except Exception:
                for video_id, preimage in journal["preimages"].items():
                    self.save_item(preimage)
                for path in (lease_path, chunk_path):
                    if path.exists():
                        path.unlink()
                journal["state"] = "rolled_back"
                journal["rolled_back_at"] = utcnow()
                atomic_json(journal_path, journal)
                self.write_state()
                raise


def item_age_days(item: dict[str, Any], now_dt: dt.datetime) -> float:
    requested = parse_time(item.get("requested_at")) or parse_time(item.get("process_after")) or now_dt
    return max(0.0, (now_dt - requested).total_seconds() / 86400.0)


def effective_priority_rank(item: dict[str, Any], now_dt: dt.datetime, policy: SelectionPolicy) -> int:
    priority = str(item.get("priority") or "normal")
    rank = PRIORITY_ORDER.get(priority, PRIORITY_ORDER["normal"])
    if item_age_days(item, now_dt) >= policy.aging_promote_after_days:
        rank = max(0, rank - 1)
    return rank


def eligible(item: dict[str, Any], now_dt: dt.datetime) -> bool:
    if item.get("status") != "pending":
        return False
    if item.get("active_lease_id"):
        return False
    process_after = parse_time(item.get("process_after"))
    if process_after and process_after > now_dt:
        return False
    retry_after = parse_time(item.get("retry_after"))
    if retry_after and retry_after > now_dt:
        return False
    if item.get("auth_allowed") or item.get("media_download_allowed"):
        return False
    return True


def sort_key(item: dict[str, Any], now_dt: dt.datetime, policy: SelectionPolicy) -> tuple[Any, ...]:
    process_after = parse_time(item.get("process_after")) or dt.datetime.min.replace(tzinfo=dt.timezone.utc)
    requested_at = parse_time(item.get("requested_at")) or process_after
    return (
        LANE_ORDER.get(str(item.get("lane") or ""), 99),
        effective_priority_rank(item, now_dt, policy),
        process_after,
        requested_at,
        str(item.get("video_id") or ""),
    )


def select_items(items: list[dict[str, Any]], *, now: str | dt.datetime | None = None, policy: SelectionPolicy | None = None) -> list[dict[str, Any]]:
    policy = policy or SelectionPolicy()
    now_dt = parse_time(now if isinstance(now, str) else None) if isinstance(now, str) else now
    now_dt = now_dt or dt.datetime.now(dt.timezone.utc)
    candidates = [item for item in items if eligible(item, now_dt)]
    candidates.sort(key=lambda item: sort_key(item, now_dt, policy))

    selected_ids: set[str] = set()
    selected: list[dict[str, Any]] = []

    def take(pool: list[dict[str, Any]], count: int) -> None:
        nonlocal selected
        if count <= 0:
            return
        for item in pool:
            if len(selected) >= policy.chunk_size or count <= 0:
                return
            video_id = str(item["video_id"])
            if video_id in selected_ids:
                continue
            selected.append(item)
            selected_ids.add(video_id)
            count -= 1

    personal = [item for item in candidates if item.get("lane") in {"urgent_personal", "personal"}]
    fresh = [item for item in candidates if item.get("lane") == "fresh_monitored"]
    take(personal, min(policy.personal_reserved, policy.chunk_size))
    take(fresh, min(policy.fresh_reserved, policy.chunk_size - len(selected)))

    # Starvation guard: when capacity remains, guarantee one very old item per
    # otherwise-unrepresented lane before normal spillover.
    represented_lanes = {str(item.get("lane")) for item in selected}
    for lane in sorted(LANE_ORDER, key=LANE_ORDER.get):
        if len(selected) >= policy.chunk_size:
            break
        if lane in represented_lanes:
            continue
        guaranteed = [
            item for item in candidates
            if item.get("lane") == lane
            and str(item.get("video_id")) not in selected_ids
            and item_age_days(item, now_dt) >= policy.guarantee_after_days
        ]
        if guaranteed:
            take(guaranteed, 1)
            represented_lanes.add(lane)

    remaining_by_lane: list[dict[str, Any]] = []
    for lane in sorted(LANE_ORDER, key=LANE_ORDER.get):
        remaining_by_lane.extend(item for item in candidates if item.get("lane") == lane)
    take(remaining_by_lane, policy.chunk_size - len(selected))
    return selected


def partition_for_nodes(selected: list[dict[str, Any]], nodes: list[NodeTarget]) -> list[dict[str, Any]]:
    """Partition a preselected global disjoint item list into stable node chunks."""
    sorted_nodes = sorted(nodes, key=lambda node: node.node_id)
    plans: list[dict[str, Any]] = []
    offset = 0
    seen: set[str] = set()
    for node in sorted_nodes:
        if offset >= len(selected):
            break
        cap = max(0, min(25, node.max_chunk_size))
        chunk = selected[offset: offset + cap]
        offset += cap
        if not chunk:
            continue
        video_ids = [str(item["video_id"]) for item in chunk]
        if seen.intersection(video_ids):
            raise LeaseConflictError("node partition produced duplicate video IDs")
        seen.update(video_ids)
        plans.append({
            "node_id": node.node_id,
            "node_label": node.label,
            "node_platform": node.platform,
            "video_ids": video_ids,
            "items": chunk,
        })
    return plans


def active_yc_video_ids(chunks_dir: Path) -> set[str]:
    active: set[str] = set()
    if not chunks_dir.is_dir():
        return active
    for path in sorted(chunks_dir.glob("*.json")):
        try:
            chunk = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise PoolError(f"malformed YC chunk state {path}: {exc}") from exc
        if str(chunk.get("state") or "") not in YC_ACTIVE_CHUNK_STATES:
            continue
        for row in chunk.get("items") or []:
            state = str(row.get("state") or "pending")
            if state != "imported":
                video_id = row.get("video_id")
                if video_id and VIDEO_ID_RE.match(str(video_id)):
                    active.add(str(video_id))
    return active


def build_migration_preview(
    *,
    personal_queue_root: Path | str | None = None,
    yc_root: Path | str | None = None,
    archive_root: Path | str = DEFAULT_ARCHIVE_ROOT,
    archive_inventory: dict[str, dict[str, Any]] | None = None,
    now: str | None = None,
    max_items: int = 25,
    include_items: bool = False,
) -> dict[str, Any]:
    """Read existing source states and preview global-pool materialization.

    This function is deliberately read-only. It returns a materialized in-memory
    projection and counts; it does not create a pool root or modify source files.
    """
    generated_at = ensure_z(now)
    archive_root = Path(archive_root)
    items: dict[str, dict[str, Any]] = {}
    counts: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    merged_duplicates = 0

    def add(video_id: str, url: str | None, source: dict[str, Any], *, status: str | None = None, report_path: str | None = None, transcript_path: str | None = None) -> None:
        nonlocal merged_duplicates
        existing = items.get(video_id)
        item, created = merge_item(existing, video_id, url, source, status=status, report_path=report_path, transcript_path=transcript_path, now=generated_at)
        items[video_id] = item
        if not created:
            merged_duplicates += 1

    if personal_queue_root:
        pending_path = Path(personal_queue_root) / "pending.jsonl"
        for row in read_jsonl(pending_path):
            if str(row.get("status") or "pending") not in {"pending", "waiting_network_cooldown"}:
                continue
            video_id = validate_video_id(str(row.get("video_id") or extract_video_id(str(row.get("url") or row.get("original_url") or ""))))
            inventory_row = (archive_inventory or {}).get(video_id)
            if inventory_row is None:
                ok, report_path, transcript_path = archive_complete(archive_root, video_id)
            else:
                ok = bool(inventory_row.get("complete"))
                report_path = inventory_row.get("report_path")
                transcript_path = inventory_row.get("transcript_path")
            status = "skipped_existing" if ok else "pending"
            add(
                video_id,
                row.get("url") or canonical_url(video_id),
                {
                    "type": row.get("source_type") or "chat_share",
                    "ref": row.get("queue_id"),
                    "requested_at": row.get("received_at") or row.get("process_after") or generated_at,
                    "requested_action": row.get("requested_action") or "archive_transcript_and_summarize",
                    "priority": row.get("priority") or "normal",
                    "lane": "personal",
                    "title_hint": row.get("title_hint"),
                },
                status=status,
                report_path=report_path,
                transcript_path=transcript_path,
            )
            counts["personal_rows"] += 1
            source_counts["chat_share"] += 1

    if yc_root:
        yc_root = Path(yc_root)
        catalog_path = yc_root / "catalog.json"
        active_ids = active_yc_video_ids(yc_root / "chunks")
        catalog = read_json(catalog_path, {}) or {}
        for video in catalog.get("videos") or []:
            video_id = video.get("video_id")
            if not video_id or not VIDEO_ID_RE.match(str(video_id)):
                continue
            video_id = str(video_id)
            archive = video.get("archive") or {}
            memberships = video.get("memberships") or []
            source = {
                "type": "channel_catalog",
                "ref": "ycombinator",
                "requested_at": catalog.get("generated_at") or generated_at,
                "requested_action": "archive_transcript",
                "priority": "normal",
                "lane": "bulk_archive",
                "title_hint": video.get("title"),
                "memberships": memberships,
            }
            if video_id in active_ids:
                status = "external_active"
                counts["yc_active_shadowed"] += 1
                report_path = None
                transcript_path = None
            else:
                inventory_row = (archive_inventory or {}).get(video_id)
                if inventory_row is None and bool(archive.get("complete")):
                    ok = True
                    report_path = archive.get("report_path")
                    transcript_path = archive.get("transcript_path")
                elif inventory_row is None:
                    ok, report_path, transcript_path = archive_complete(archive_root, video_id)
                else:
                    ok = bool(inventory_row.get("complete"))
                    report_path = inventory_row.get("report_path")
                    transcript_path = inventory_row.get("transcript_path")
                status = "skipped_existing" if ok else "pending"
                counts["yc_missing_or_incomplete"] += 0 if ok else 1
                counts["yc_existing_complete"] += 1 if ok else 0
            add(video_id, video.get("canonical_url") or canonical_url(video_id), source, status=status, report_path=report_path, transcript_path=transcript_path)
            counts["yc_catalog_videos"] += 1
            source_counts["channel_catalog"] += 1

    status_counts = Counter(str(item.get("status") or "unknown") for item in items.values())
    lane_counts = Counter(str(item.get("lane") or "unknown") for item in items.values())
    sorted_items = sorted(items.values(), key=lambda item: (LANE_ORDER.get(str(item.get("lane")), 99), str(item.get("video_id"))))
    payload = {
        "schema": f"{SCHEMA_PREFIX}.migration-preview.v1",
        "generated_at": generated_at,
        "read_only": True,
        "counts": dict(sorted(counts.items())),
        "source_counts": dict(sorted(source_counts.items())),
        "status_counts": dict(sorted(status_counts.items())),
        "lane_counts": dict(sorted(lane_counts.items())),
        "unique_video_count": len(items),
        "merged_duplicates": merged_duplicates,
        "sample_items": sorted_items[:max(0, max_items)],
        "cookies_used": False,
        "media_files": 0,
    }
    if include_items:
        payload["items"] = sorted_items
    return payload


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fingerprint_file(path: Path, logical_path: str) -> dict[str, Any]:
    stat = path.stat()
    return {
        "logical_path": logical_path,
        "source_path": str(path),
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        "sha256": sha256_file(path),
    }


def migration_source_paths(personal_queue_root: Path, yc_root: Path) -> list[tuple[str, Path, Path]]:
    """Return deterministic source inputs plus useful rollback context files."""
    paths: list[tuple[str, Path, Path]] = []

    for name in ("pending.jsonl", "events.jsonl"):
        source = personal_queue_root / name
        if source.is_file():
            paths.append((f"personal/{name}", source, Path("personal") / name))

    root_files = ("automation.json", "catalog.json", "events.jsonl")
    for name in root_files:
        source = yc_root / name
        if source.is_file():
            paths.append((f"ycombinator/{name}", source, Path("ycombinator") / name))

    for name in ("pending.jsonl", "state.json"):
        source = yc_root / "queue" / name
        if source.is_file():
            paths.append((f"ycombinator/queue/{name}", source, Path("ycombinator") / "queue" / name))

    for source in sorted((yc_root / "chunks").glob("*.json")):
        paths.append((f"ycombinator/chunks/{source.name}", source, Path("ycombinator") / "chunks" / source.name))
    return paths


def fingerprint_sources(paths: list[tuple[str, Path, Path]]) -> dict[str, dict[str, Any]]:
    return {logical: fingerprint_file(source, logical) for logical, source, _ in paths}


def source_video_ids(personal_queue_root: Path, yc_root: Path) -> list[str]:
    video_ids: set[str] = set()
    for row in read_jsonl(personal_queue_root / "pending.jsonl"):
        value = row.get("video_id") or row.get("url") or row.get("original_url")
        if value:
            video_ids.add(extract_video_id(str(value)))
    catalog = read_json(yc_root / "catalog.json", {}) or {}
    for row in catalog.get("videos") or []:
        value = row.get("video_id") or row.get("canonical_url")
        if value:
            video_ids.add(extract_video_id(str(value)))
    return sorted(video_ids)


def build_archive_inventory(archive_root: Path, video_ids: list[str]) -> dict[str, dict[str, Any]]:
    inventory: dict[str, dict[str, Any]] = {}
    for video_id in video_ids:
        complete, report_path, transcript_path = archive_complete(archive_root, video_id)
        manifest = archive_root / video_id / "manifest.json"
        inventory[video_id] = {
            "video_id": video_id,
            "complete": complete,
            "report_path": report_path,
            "transcript_path": transcript_path,
            "manifest_sha256": sha256_file(manifest) if manifest.is_file() else None,
        }
    return inventory


def tree_fingerprint(path: Path) -> dict[str, str]:
    if not path.is_dir():
        return {}
    return {
        str(child.relative_to(path)): sha256_file(child)
        for child in sorted(path.rglob("*"))
        if child.is_file()
    }


def write_rehearsal_report(
    path: Path,
    *,
    run_id: str,
    generated_at: str,
    preview: dict[str, Any],
    projection: dict[str, Any],
    selection: dict[str, Any],
    runtime_context: dict[str, Any] | None,
) -> None:
    nodes = (runtime_context or {}).get("nodes") or []
    connected_nodes = [node.get("displayName") for node in nodes if node.get("connected")]
    disconnected_nodes = [node.get("displayName") for node in nodes if not node.get("connected")]
    checks = projection["checks"]
    lines = [
        f"# YouTube global pool migration rehearsal — {run_id}",
        "",
        f"Generated: {generated_at}",
        f"Overall result: {'PASS' if projection['ok'] else 'FAIL'}",
        "Mode: read-only source rehearsal; no leases, workers, imports, OAuth, or YouTube writes",
        "",
        "## Source projection",
        "",
        f"- Unique proposed items: {preview['unique_video_count']}",
        f"- Personal source rows: {preview['counts'].get('personal_rows', 0)}",
        f"- Y Combinator catalog videos: {preview['counts'].get('yc_catalog_videos', 0)}",
        f"- Existing complete archives reused: {preview['status_counts'].get('skipped_existing', 0)}",
        f"- Active YC items shadowed: {preview['status_counts'].get('external_active', 0)}",
        f"- Pending proposed items: {preview['status_counts'].get('pending', 0)}",
        f"- Cookies used: {str(preview['cookies_used']).lower()}",
        f"- Media files: {preview['media_files']}",
        "",
        "## Rehearsed first dispatch",
        "",
        f"- Selected items: {selection['selected_count']}",
        f"- Lane counts: {json.dumps(selection['lane_counts'], ensure_ascii=False, sort_keys=True)}",
        f"- Active YC overlap: {selection['active_yc_overlap_count']}",
        "- This is a selection preview only; no lease or node assignment was created.",
        "",
        "## Runtime context",
        "",
        f"- Connected nodes: {', '.join(str(value) for value in connected_nodes) or 'none recorded'}",
        f"- Disconnected nodes: {', '.join(str(value) for value in disconnected_nodes) or 'none recorded'}",
        f"- YC supervisor enabled: {str(bool((runtime_context or {}).get('yc_supervisor', {}).get('enabled'))).lower()}",
        "",
        "## Invariant checks",
        "",
    ]
    for check in checks:
        lines.append(f"- [{'x' if check['ok'] else ' '}] {check['name']}: {check['detail']}")
    lines.extend([
        "",
        "## Review decision",
        "",
        "- The rehearsal artifacts are durable and checksum-verified.",
        "- `proposed-items.jsonl` is a proposal outside the live global `items/` directory.",
        "- Source snapshots are copies; source hashes were unchanged before/after the rehearsal.",
        "- Phase 3 materialization or any worker canary remains a separate gate.",
        "",
    ])
    atomic_write(path, "\n".join(lines))


def run_migration_rehearsal(
    *,
    personal_queue_root: Path,
    yc_root: Path,
    archive_root: Path,
    output_root: Path,
    runtime_context_path: Path | None = None,
    run_id: str | None = None,
    max_attempts: int = 3,
) -> dict[str, Any]:
    """Create a durable, checksum-verified rehearsal without materializing items."""
    if not 1 <= max_attempts <= 5:
        raise ValueError("max_attempts must be 1..5")
    generated_at = utcnow()
    run_id = run_id or f"rehearsal-{generated_at.replace('-', '').replace(':', '').replace('.', '')}"
    output_root.mkdir(parents=True, exist_ok=True)
    final_dir = output_root / run_id
    if final_dir.exists():
        raise PoolError(f"rehearsal already exists: {final_dir}")

    runtime_context = read_json(runtime_context_path, {}) if runtime_context_path else {}
    live_items_dir = output_root.parent / "items"
    live_items_before = tree_fingerprint(live_items_dir)
    last_error = "source changed during rehearsal"

    for attempt in range(1, max_attempts + 1):
        staging = Path(tempfile.mkdtemp(prefix=f".{run_id}-", dir=output_root))
        try:
            source_paths_before = migration_source_paths(personal_queue_root, yc_root)
            source_names_before = [logical for logical, _, _ in source_paths_before]
            fingerprints_before = fingerprint_sources(source_paths_before)

            snapshots = staging / "snapshots"
            for logical, source, relative in source_paths_before:
                destination = snapshots / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
                if sha256_file(destination) != fingerprints_before[logical]["sha256"]:
                    raise PoolError(f"snapshot checksum mismatch: {logical}")

            snapshot_personal = snapshots / "personal"
            snapshot_yc = snapshots / "ycombinator"
            video_ids = source_video_ids(snapshot_personal, snapshot_yc)
            archive_before = build_archive_inventory(archive_root, video_ids)

            preview = build_migration_preview(
                personal_queue_root=snapshot_personal,
                yc_root=snapshot_yc,
                archive_root=archive_root,
                archive_inventory=archive_before,
                now=generated_at,
                max_items=25,
                include_items=True,
            )
            proposed_items = preview.pop("items")
            proposed_ids = [str(item["video_id"]) for item in proposed_items]
            active_ids = active_yc_video_ids(snapshot_yc / "chunks")
            selected = select_items(proposed_items, now=generated_at, policy=SelectionPolicy())
            selected_ids = [str(item["video_id"]) for item in selected]
            selected_lanes = Counter(str(item.get("lane") or "unknown") for item in selected)

            source_paths_after = migration_source_paths(personal_queue_root, yc_root)
            source_names_after = [logical for logical, _, _ in source_paths_after]
            fingerprints_after = fingerprint_sources(source_paths_after)
            archive_after = build_archive_inventory(archive_root, video_ids)
            if source_names_before != source_names_after or fingerprints_before != fingerprints_after:
                last_error = "source file set or checksum changed during rehearsal"
                continue
            if archive_before != archive_after:
                last_error = "canonical archive inventory changed during rehearsal"
                continue

            checks = [
                {
                    "name": "source_files_stable",
                    "ok": True,
                    "detail": f"{len(fingerprints_before)} source files unchanged by path, size, mtime, and SHA-256",
                },
                {
                    "name": "archive_inventory_stable",
                    "ok": True,
                    "detail": f"{len(archive_before)} video archive records unchanged during the rehearsal",
                },
                {
                    "name": "unique_video_ids",
                    "ok": len(proposed_ids) == len(set(proposed_ids)) == preview["unique_video_count"],
                    "detail": f"{len(proposed_ids)} proposed IDs, {len(set(proposed_ids))} unique",
                },
                {
                    "name": "active_yc_items_shadowed",
                    "ok": all(
                        next(item for item in proposed_items if item["video_id"] == video_id)["status"] == "external_active"
                        for video_id in active_ids
                        if video_id in set(proposed_ids)
                    ),
                    "detail": f"{len(active_ids)} active YC IDs excluded from pending materialization",
                },
                {
                    "name": "selection_excludes_active_yc",
                    "ok": not set(selected_ids).intersection(active_ids),
                    "detail": f"overlap={len(set(selected_ids).intersection(active_ids))}",
                },
                {
                    "name": "existing_archives_not_pending",
                    "ok": all(
                        item["status"] != "pending"
                        for item in proposed_items
                        if archive_before.get(str(item["video_id"]), {}).get("complete")
                    ),
                    "detail": f"{sum(1 for row in archive_before.values() if row['complete'])} complete archive records checked",
                },
                {
                    "name": "anonymous_caption_only_policy",
                    "ok": all(not item.get("auth_allowed") and not item.get("media_download_allowed") for item in proposed_items),
                    "detail": "every proposed item has auth_allowed=false and media_download_allowed=false",
                },
                {
                    "name": "no_live_item_materialization",
                    "ok": tree_fingerprint(live_items_dir) == live_items_before,
                    "detail": f"live items directory unchanged ({len(live_items_before)} pre-existing files)",
                },
            ]
            projection = {
                "schema": f"{SCHEMA_PREFIX}.projection-diff.v1",
                "generated_at": generated_at,
                "ok": all(check["ok"] for check in checks),
                "checks": checks,
                "source_counts": preview["source_counts"],
                "status_counts": preview["status_counts"],
                "lane_counts": preview["lane_counts"],
                "active_yc_ids": sorted(active_ids),
                "proposed_unique_video_count": preview["unique_video_count"],
            }
            selection = {
                "schema": f"{SCHEMA_PREFIX}.selection-preview.v1",
                "generated_at": generated_at,
                "selected_count": len(selected),
                "video_ids": selected_ids,
                "lane_counts": dict(sorted(selected_lanes.items())),
                "active_yc_overlap_count": len(set(selected_ids).intersection(active_ids)),
                "items": selected,
                "lease_created": False,
            }
            source_manifest = {
                "schema": f"{SCHEMA_PREFIX}.source-snapshot-manifest.v1",
                "generated_at": generated_at,
                "source_file_count": len(fingerprints_before),
                "sources_unchanged": True,
                "files": [
                    {
                        **fingerprints_before[logical],
                        "snapshot_path": str(Path("snapshots") / relative),
                    }
                    for logical, _, relative in source_paths_before
                ],
            }

            write_jsonl(staging / "proposed-items.jsonl", proposed_items)
            atomic_json(staging / "preview-summary.json", preview)
            atomic_json(staging / "projection-diff.json", projection)
            atomic_json(staging / "selection-preview.json", selection)
            atomic_json(staging / "source-manifest.json", source_manifest)
            atomic_json(staging / "archive-inventory.json", {
                "schema": f"{SCHEMA_PREFIX}.archive-inventory.v1",
                "generated_at": generated_at,
                "items": archive_before,
            })
            atomic_json(staging / "runtime-context.json", runtime_context)
            write_rehearsal_report(
                staging / "report.md",
                run_id=run_id,
                generated_at=generated_at,
                preview=preview,
                projection=projection,
                selection=selection,
                runtime_context=runtime_context,
            )

            artifacts = {
                str(path.relative_to(staging)): {
                    "size": path.stat().st_size,
                    "sha256": sha256_file(path),
                }
                for path in sorted(staging.rglob("*"))
                if path.is_file()
            }
            atomic_json(staging / "artifact-manifest.json", {
                "schema": f"{SCHEMA_PREFIX}.rehearsal-artifacts.v1",
                "generated_at": generated_at,
                "artifacts": artifacts,
            })
            for relative, expected in artifacts.items():
                candidate = staging / relative
                if candidate.stat().st_size != expected["size"] or sha256_file(candidate) != expected["sha256"]:
                    raise PoolError(f"artifact readback mismatch: {relative}")
            for json_path in sorted(staging.glob("*.json")):
                json.loads(json_path.read_text(encoding="utf-8"))
            read_jsonl(staging / "proposed-items.jsonl")

            if not projection["ok"]:
                raise PoolError("migration rehearsal invariant failure")
            if tree_fingerprint(live_items_dir) != live_items_before:
                raise PoolError("live global items directory changed during rehearsal")
            os.replace(staging, final_dir)
            publish_existing_markdown_if_authoritative(final_dir / "report.md")
            return {
                "schema": f"{SCHEMA_PREFIX}.rehearsal-result.v1",
                "run_id": run_id,
                "generated_at": generated_at,
                "state": "passed",
                "attempt": attempt,
                "path": str(final_dir),
                "unique_video_count": preview["unique_video_count"],
                "status_counts": preview["status_counts"],
                "selection_count": len(selected),
                "cookies_used": False,
                "media_files": 0,
                "live_items_materialized": False,
            }
        finally:
            if staging.exists():
                shutil.rmtree(staging)
    raise PoolError(f"could not capture a stable rehearsal after {max_attempts} attempts: {last_error}")


def verify_rehearsal_artifacts(rehearsal_dir: Path) -> dict[str, Any]:
    """Verify every hash-bound rehearsal artifact and return parsed inputs."""
    required = {
        "archive-inventory.json",
        "artifact-manifest.json",
        "preview-summary.json",
        "projection-diff.json",
        "proposed-items.jsonl",
        "selection-preview.json",
        "source-manifest.json",
    }
    missing = sorted(name for name in required if not (rehearsal_dir / name).is_file())
    if missing:
        raise PoolError(f"rehearsal artifacts missing: {', '.join(missing)}")

    artifact_manifest_path = rehearsal_dir / "artifact-manifest.json"
    artifact_manifest = read_json(artifact_manifest_path, {}) or {}
    if artifact_manifest.get("schema") != f"{SCHEMA_PREFIX}.rehearsal-artifacts.v1":
        raise PoolError("unexpected rehearsal artifact manifest schema")
    artifacts = artifact_manifest.get("artifacts") or {}
    if not isinstance(artifacts, dict) or not artifacts:
        raise PoolError("empty rehearsal artifact manifest")
    for relative, expected in sorted(artifacts.items()):
        relative_path = Path(str(relative))
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise PoolError(f"unsafe rehearsal artifact path: {relative}")
        candidate = rehearsal_dir / relative_path
        if not candidate.is_file():
            raise PoolError(f"rehearsal artifact missing: {relative}")
        if candidate.stat().st_size != int(expected.get("size", -1)):
            raise PoolError(f"rehearsal artifact size mismatch: {relative}")
        if sha256_file(candidate) != str(expected.get("sha256") or ""):
            raise PoolError(f"rehearsal artifact hash mismatch: {relative}")

    proposal = read_jsonl(rehearsal_dir / "proposed-items.jsonl")
    preview = read_json(rehearsal_dir / "preview-summary.json", {}) or {}
    projection = read_json(rehearsal_dir / "projection-diff.json", {}) or {}
    selection = read_json(rehearsal_dir / "selection-preview.json", {}) or {}
    source_manifest = read_json(rehearsal_dir / "source-manifest.json", {}) or {}
    archive_inventory = read_json(rehearsal_dir / "archive-inventory.json", {}) or {}

    if not projection.get("ok"):
        raise PoolError("rehearsal projection did not pass")
    if not preview.get("read_only") or preview.get("cookies_used") or preview.get("media_files") != 0:
        raise PoolError("rehearsal violates read-only anonymous caption-only policy")
    if selection.get("lease_created") or selection.get("active_yc_overlap_count") != 0:
        raise PoolError("rehearsal selection created a lease or overlaps active YC work")
    if source_manifest.get("schema") != f"{SCHEMA_PREFIX}.source-snapshot-manifest.v1":
        raise PoolError("unexpected rehearsal source manifest schema")
    if not source_manifest.get("sources_unchanged"):
        raise PoolError("rehearsal source manifest is not stable")
    if archive_inventory.get("schema") != f"{SCHEMA_PREFIX}.archive-inventory.v1":
        raise PoolError("unexpected rehearsal archive inventory schema")

    video_ids: list[str] = []
    for item in proposal:
        video_id = validate_video_id(str(item.get("video_id") or ""))
        video_ids.append(video_id)
        if item.get("auth_allowed") or item.get("media_download_allowed"):
            raise PoolError(f"unsafe proposal policy for {video_id}")
        if item.get("active_lease_id") or item.get("active_node"):
            raise PoolError(f"proposal unexpectedly contains an active assignment for {video_id}")
    if len(video_ids) != len(set(video_ids)):
        raise PoolError("proposal contains duplicate video IDs")

    status_counts = dict(sorted(Counter(str(item.get("status") or "unknown") for item in proposal).items()))
    lane_counts = dict(sorted(Counter(str(item.get("lane") or "unknown") for item in proposal).items()))
    if len(proposal) != int(preview.get("unique_video_count", -1)):
        raise PoolError("proposal item count does not match preview")
    if status_counts != (preview.get("status_counts") or {}):
        raise PoolError("proposal status counts do not match preview")
    if lane_counts != (preview.get("lane_counts") or {}):
        raise PoolError("proposal lane counts do not match preview")

    return {
        "artifact_manifest": artifact_manifest,
        "artifact_manifest_sha256": sha256_file(artifact_manifest_path),
        "proposal": proposal,
        "preview": preview,
        "projection": projection,
        "selection": selection,
        "source_manifest": source_manifest,
        "archive_inventory": archive_inventory,
        "status_counts": status_counts,
        "lane_counts": lane_counts,
    }


def verify_live_sources_match_manifest(
    source_manifest: dict[str, Any],
    *,
    personal_queue_root: Path,
    yc_root: Path,
) -> None:
    expected_rows = source_manifest.get("files") or []
    expected = {str(row.get("logical_path")): row for row in expected_rows}
    current_paths = migration_source_paths(personal_queue_root, yc_root)
    current = fingerprint_sources(current_paths)
    if set(current) != set(expected):
        added = sorted(set(current) - set(expected))
        removed = sorted(set(expected) - set(current))
        raise PoolError(f"migration source set drifted: added={added}, removed={removed}")
    for logical, actual in current.items():
        wanted = expected[logical]
        for key in ("source_path", "size", "mtime_ns", "sha256"):
            if actual.get(key) != wanted.get(key):
                raise PoolError(f"migration source drifted: {logical} ({key})")


def verify_live_archive_inventory(
    archive_inventory: dict[str, Any],
    *,
    archive_root: Path,
    video_ids: list[str],
) -> None:
    expected = archive_inventory.get("items") or {}
    current = build_archive_inventory(archive_root, video_ids)
    if current != expected:
        changed = sorted(video_id for video_id in set(current) | set(expected) if current.get(video_id) != expected.get(video_id))
        raise PoolError(f"canonical archive inventory drifted: {changed[:20]}")


def verify_materialized_items(items_dir: Path, proposal: list[dict[str, Any]]) -> None:
    expected = {str(item["video_id"]): item for item in proposal}
    actual_paths = sorted(items_dir.glob("*.json")) if items_dir.is_dir() else []
    if {path.stem for path in actual_paths} != set(expected):
        raise PoolError("materialized item ID set does not match proposal")
    for path in actual_paths:
        if read_json(path, {}) != expected[path.stem]:
            raise PoolError(f"materialized item content mismatch: {path.stem}")
    if path_has_media(items_dir):
        raise PoolError("media file detected in materialized item tree")


def materialize_rehearsal(
    *,
    rehearsal_dir: Path,
    pool_root: Path,
    personal_queue_root: Path,
    yc_root: Path,
    archive_root: Path,
    now: str | None = None,
) -> dict[str, Any]:
    """Hash-bind and materialize a stable rehearsal without creating leases."""
    verified = verify_rehearsal_artifacts(rehearsal_dir)
    proposal = verified["proposal"]
    video_ids = [str(item["video_id"]) for item in proposal]
    verify_live_sources_match_manifest(
        verified["source_manifest"],
        personal_queue_root=personal_queue_root,
        yc_root=yc_root,
    )
    verify_live_archive_inventory(
        verified["archive_inventory"],
        archive_root=archive_root,
        video_ids=video_ids,
    )

    materialized_at = ensure_z(now)
    artifact_hash = str(verified["artifact_manifest_sha256"])
    artifact_entries = verified["artifact_manifest"].get("artifacts") or {}
    binding = {
        "schema": f"{SCHEMA_PREFIX}.materialization-binding.v1",
        "rehearsal_path": str(rehearsal_dir),
        "rehearsal_generated_at": verified["preview"].get("generated_at"),
        "materialized_at": materialized_at,
        "artifact_manifest_sha256": artifact_hash,
        "proposed_items_sha256": artifact_entries["proposed-items.jsonl"]["sha256"],
        "source_manifest_sha256": artifact_entries["source-manifest.json"]["sha256"],
        "archive_inventory_sha256": artifact_entries["archive-inventory.json"]["sha256"],
    }
    state = {
        "schema": f"{SCHEMA_PREFIX}.state.v1",
        "updated_at": materialized_at,
        "item_count": len(proposal),
        "status_counts": verified["status_counts"],
        "lane_counts": verified["lane_counts"],
        "active_lease_count": 0,
        "active_leases": [],
        "cookies_used": False,
        "media_files": 0,
        "materialization": binding,
    }
    event = {
        "schema": f"{SCHEMA_PREFIX}.event.v1",
        "event_id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"{SCHEMA_PREFIX}:materialized:{artifact_hash}")),
        "created_at": materialized_at,
        "type": "migration_materialized",
        "item_count": len(proposal),
        "status_counts": verified["status_counts"],
        "lane_counts": verified["lane_counts"],
        "active_yc_overlap_count": 0,
        "cookies_used": False,
        "media_files": 0,
        "binding": binding,
    }

    store = PoolStore(pool_root)
    with store.coordinator_lock():
        transaction_path = pool_root / "materialization-commit.json"
        transaction = read_json(transaction_path, {}) or {}
        if transaction.get("state") == "prepared":
            if transaction.get("artifact_manifest_sha256") != artifact_hash:
                raise PoolError("an interrupted materialization for a different rehearsal requires review")
            target_paths = [store.items_dir, store.state_path, store.events_path]
            complete_targets = all(path.exists() for path in target_paths)
            if complete_targets:
                try:
                    verify_materialized_items(store.items_dir, proposal)
                    committed_state = read_json(store.state_path, {}) or {}
                    committed_events = read_jsonl(store.events_path)
                    if (committed_state.get("materialization") or {}).get("artifact_manifest_sha256") == artifact_hash and any(
                        (row.get("binding") or {}).get("artifact_manifest_sha256") == artifact_hash for row in committed_events
                    ):
                        transaction["state"] = "committed"
                        transaction["recovered_at"] = utcnow()
                        atomic_json(transaction_path, transaction)
                except Exception:
                    complete_targets = False
            if transaction.get("state") != "committed":
                for path in reversed(target_paths):
                    if path.is_dir():
                        shutil.rmtree(path)
                    elif path.exists():
                        path.unlink()
                transaction["state"] = "recovered_rollback"
                transaction["recovered_at"] = utcnow()
                atomic_json(transaction_path, transaction)
        existing_state = read_json(store.state_path, {}) or {}
        existing_hash = (existing_state.get("materialization") or {}).get("artifact_manifest_sha256")
        if existing_hash == artifact_hash:
            verify_materialized_items(store.items_dir, proposal)
            return {
                "schema": f"{SCHEMA_PREFIX}.materialization-result.v1",
                "state": "already_materialized",
                "item_count": len(proposal),
                "status_counts": verified["status_counts"],
                "lane_counts": verified["lane_counts"],
                "artifact_manifest_sha256": artifact_hash,
                "cookies_used": False,
                "media_files": 0,
                "leases_created": 0,
                "workers_launched": 0,
            }
        if store.items_dir.exists() or store.state_path.exists() or store.events_path.exists():
            raise PoolError("live global pool already contains a different materialization")

        pool_root.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix=".materialize-", dir=str(pool_root)))
        committed: list[Path] = []
        try:
            staged_items = staging / "items"
            staged_items.mkdir()
            for item in proposal:
                atomic_json(staged_items / f"{item['video_id']}.json", item)
            atomic_json(staging / "state.json", state)
            write_jsonl(staging / "events.jsonl", [event])
            verify_materialized_items(staged_items, proposal)
            if read_json(staging / "state.json", {}) != state:
                raise PoolError("staged state readback mismatch")
            if read_jsonl(staging / "events.jsonl") != [event]:
                raise PoolError("staged event readback mismatch")

            # Recheck every mutable input immediately before committing.
            verify_live_sources_match_manifest(
                verified["source_manifest"],
                personal_queue_root=personal_queue_root,
                yc_root=yc_root,
            )
            verify_live_archive_inventory(
                verified["archive_inventory"],
                archive_root=archive_root,
                video_ids=video_ids,
            )

            transaction = {
                "schema": f"{SCHEMA_PREFIX}.materialization-commit.v1",
                "state": "prepared",
                "prepared_at": utcnow(),
                "artifact_manifest_sha256": artifact_hash,
                "targets": ["items", "state.json", "events.jsonl"],
                "committed_targets": [],
            }
            atomic_json(transaction_path, transaction)

            for source, target in (
                (staged_items, store.items_dir),
                (staging / "state.json", store.state_path),
                (staging / "events.jsonl", store.events_path),
            ):
                os.replace(source, target)
                committed.append(target)
                transaction["committed_targets"].append(str(target.relative_to(pool_root)))
                atomic_json(transaction_path, transaction)
            verify_materialized_items(store.items_dir, proposal)
            if read_json(store.state_path, {}) != state or read_jsonl(store.events_path) != [event]:
                raise PoolError("committed materialization readback mismatch")
            transaction["state"] = "committed"
            transaction["committed_at"] = utcnow()
            atomic_json(transaction_path, transaction)
        except Exception:
            for target in reversed(committed):
                if target.is_dir():
                    shutil.rmtree(target)
                elif target.exists():
                    target.unlink()
            if transaction:
                transaction["state"] = "rolled_back"
                transaction["rolled_back_at"] = utcnow()
                atomic_json(transaction_path, transaction)
            raise
        finally:
            if staging.exists():
                shutil.rmtree(staging)

    return {
        "schema": f"{SCHEMA_PREFIX}.materialization-result.v1",
        "state": "materialized",
        "item_count": len(proposal),
        "status_counts": verified["status_counts"],
        "lane_counts": verified["lane_counts"],
        "artifact_manifest_sha256": artifact_hash,
        "cookies_used": False,
        "media_files": 0,
        "leases_created": 0,
        "workers_launched": 0,
    }


def reconcile_external_active_items(
    *,
    pool_root: Path,
    yc_root: Path,
    archive_root: Path,
    now: str | None = None,
) -> dict[str, Any]:
    """Resolve stale YC-shadowed items after a verified clean chunk boundary."""
    timestamp = ensure_z(now)
    store = PoolStore(pool_root)
    with store.coordinator_lock():
        if any((read_json(path, {}) or {}).get("state") == "active" for path in store.leases_dir.glob("*.json")):
            raise PoolError("cannot reconcile external-active items while a global lease is active")
        active_ids = active_yc_video_ids(yc_root / "chunks")
        changed: list[dict[str, str]] = []
        still_active = 0
        for item in store.load_items():
            if item.get("status") != "external_active":
                continue
            video_id = str(item["video_id"])
            if video_id in active_ids:
                still_active += 1
                continue
            complete, report_path, transcript_path = archive_complete(archive_root, video_id)
            previous = str(item.get("status"))
            item["status"] = "skipped_existing" if complete else "pending"
            item["report_path"] = report_path
            item["transcript_path"] = transcript_path
            item["active_lease_id"] = None
            item["active_node"] = None
            item["updated_at"] = timestamp
            store.save_item(item)
            changed.append({"video_id": video_id, "from": previous, "to": str(item["status"])})
        if changed:
            store.append_event(
                "external_active_reconciled",
                changed_count=len(changed),
                still_active_count=still_active,
                status_counts=dict(sorted(Counter(row["to"] for row in changed).items())),
                video_ids=[row["video_id"] for row in changed],
                cookies_used=False,
                media_files=0,
            )
        state = store.write_state() if changed else (read_json(store.state_path, {}) or {})
    return {
        "schema": f"{SCHEMA_PREFIX}.external-active-reconciliation.v1",
        "state": "reconciled" if changed else "unchanged",
        "changed_count": len(changed),
        "still_active_count": still_active,
        "changed_status_counts": dict(sorted(Counter(row["to"] for row in changed).items())),
        "item_count": state["item_count"],
        "status_counts": state["status_counts"],
        "active_lease_count": state["active_lease_count"],
        "cookies_used": False,
        "media_files": 0,
    }


def command_init(args: argparse.Namespace) -> int:
    store = PoolStore(args.pool_root)
    store.ensure_dirs()
    state = store.write_state()
    store.write_status()
    print(json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def command_migration_preview(args: argparse.Namespace) -> int:
    preview = build_migration_preview(
        personal_queue_root=args.personal_queue_root,
        yc_root=args.yc_root,
        archive_root=args.archive_root,
        max_items=args.max_items,
    )
    print(json.dumps(preview, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def command_migration_rehearsal(args: argparse.Namespace) -> int:
    result = run_migration_rehearsal(
        personal_queue_root=args.personal_queue_root,
        yc_root=args.yc_root,
        archive_root=args.archive_root,
        output_root=args.output_root,
        runtime_context_path=args.runtime_context,
        run_id=args.run_id,
        max_attempts=args.max_attempts,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def command_migration_materialize(args: argparse.Namespace) -> int:
    result = materialize_rehearsal(
        rehearsal_dir=args.rehearsal_dir,
        pool_root=args.pool_root,
        personal_queue_root=args.personal_queue_root,
        yc_root=args.yc_root,
        archive_root=args.archive_root,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def command_reconcile_external_active(args: argparse.Namespace) -> int:
    result = reconcile_external_active_items(
        pool_root=args.pool_root,
        yc_root=args.yc_root,
        archive_root=args.archive_root,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def command_select_preview(args: argparse.Namespace) -> int:
    store = PoolStore(args.pool_root)
    policy = SelectionPolicy(chunk_size=args.chunk_size, personal_reserved=args.personal_reserved, fresh_reserved=args.fresh_reserved)
    selected = select_items(store.load_items(), policy=policy)
    print(json.dumps({"selected_count": len(selected), "video_ids": [item["video_id"] for item in selected], "items": selected}, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def command_retry_blocked(args: argparse.Namespace) -> int:
    store = PoolStore(args.pool_root)
    result = store.retry_blocked_items(
        args.video_ids,
        allowed_reason=args.allowed_reason,
        dry_run=args.dry_run,
    )
    print(json.dumps({"dry_run": args.dry_run, "video_ids": [row["video_id"] for row in result]}, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="YouTube global transcript processing pool foundation")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="create empty global-pool directories/state only")
    init.add_argument("--pool-root", type=Path, default=DEFAULT_POOL_ROOT)
    init.set_defaults(func=command_init)

    preview = sub.add_parser("migration-preview", help="read existing source states and print a read-only migration preview")
    preview.add_argument("--personal-queue-root", type=Path, default=DEFAULT_PERSONAL_QUEUE_ROOT)
    preview.add_argument("--yc-root", type=Path, default=DEFAULT_YC_ROOT)
    preview.add_argument("--archive-root", type=Path, default=DEFAULT_ARCHIVE_ROOT)
    preview.add_argument("--max-items", type=int, default=25)
    preview.set_defaults(func=command_migration_preview)

    rehearsal = sub.add_parser(
        "migration-rehearsal",
        help="write a durable source snapshot/projection review without materializing live pool items",
    )
    rehearsal.add_argument("--personal-queue-root", type=Path, default=DEFAULT_PERSONAL_QUEUE_ROOT)
    rehearsal.add_argument("--yc-root", type=Path, default=DEFAULT_YC_ROOT)
    rehearsal.add_argument("--archive-root", type=Path, default=DEFAULT_ARCHIVE_ROOT)
    rehearsal.add_argument(
        "--output-root",
        type=Path,
        default=DEFAULT_POOL_ROOT / "rehearsals",
    )
    rehearsal.add_argument("--runtime-context", type=Path)
    rehearsal.add_argument("--run-id")
    rehearsal.add_argument("--max-attempts", type=int, default=3)
    rehearsal.set_defaults(func=command_migration_rehearsal)

    materialize = sub.add_parser(
        "migration-materialize",
        help="materialize one exact hash-bound rehearsal without creating leases or workers",
    )
    materialize.add_argument("--rehearsal-dir", type=Path, required=True)
    materialize.add_argument("--pool-root", type=Path, default=DEFAULT_POOL_ROOT)
    materialize.add_argument("--personal-queue-root", type=Path, default=DEFAULT_PERSONAL_QUEUE_ROOT)
    materialize.add_argument("--yc-root", type=Path, default=DEFAULT_YC_ROOT)
    materialize.add_argument("--archive-root", type=Path, default=DEFAULT_ARCHIVE_ROOT)
    materialize.set_defaults(func=command_migration_materialize)

    reconcile = sub.add_parser(
        "reconcile-external-active",
        help="resolve YC-shadowed items after a clean external chunk boundary",
    )
    reconcile.add_argument("--pool-root", type=Path, default=DEFAULT_POOL_ROOT)
    reconcile.add_argument("--yc-root", type=Path, default=DEFAULT_YC_ROOT)
    reconcile.add_argument("--archive-root", type=Path, default=DEFAULT_ARCHIVE_ROOT)
    reconcile.set_defaults(func=command_reconcile_external_active)

    select = sub.add_parser("select-preview", help="select pending pool items without creating leases")
    select.add_argument("--pool-root", type=Path, default=DEFAULT_POOL_ROOT)
    select.add_argument("--chunk-size", type=int, default=25)
    select.add_argument("--personal-reserved", type=int, default=5)
    select.add_argument("--fresh-reserved", type=int, default=5)
    select.set_defaults(func=command_select_preview)

    retry = sub.add_parser("retry-blocked", help="fail-closed retry of exact blocked_error items")
    retry.add_argument("video_ids", nargs="+", help="exact YouTube video IDs")
    retry.add_argument("--allowed-reason", required=True)
    retry.add_argument("--pool-root", type=Path, default=DEFAULT_POOL_ROOT)
    retry.add_argument("--dry-run", action="store_true")
    retry.set_defaults(func=command_retry_blocked)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
