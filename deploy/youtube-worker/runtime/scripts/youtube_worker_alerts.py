"""Durable supervisor notification reservations, never delivery receipts.

This external Python worker owns its notification database, not OpenClaw's
control-plane database. Reservation commits before stdout: process restarts and
concurrent cron jobs cannot replay it. A crash in that gap can lose the notice.
Neither a reservation nor successful stdout proves external message delivery.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import sqlite3
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, NamedTuple

from youtube_safe_diagnostics import REASONS, VIDEO_ID

APPLICATION_ID = 0x5954414C  # YTAL: this standalone notification owner.
SCHEMA_VERSION = 1
MAX_ITEMS = 25  # Existing coordinator's supported batch maximum.
RUN_ID = re.compile(r"^windows-canary-prod-[a-z0-9-]{1,64}$")
LEASE_ID = re.compile(r"^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$")
UNKNOWN_CODE = re.compile(r"^unknown:[a-f0-9]{64}$")
EVENT_ID = re.compile(r"^[a-f0-9]{32}$")
DIGEST = re.compile(r"^[a-f0-9]{64}$")

_SCHEMA = (
    """CREATE TABLE metadata (
        id INTEGER PRIMARY KEY CHECK (id = 1), scan_after TEXT NOT NULL
    )""",
    """CREATE TABLE runs (
        run_id TEXT PRIMARY KEY, lease_id TEXT NOT NULL,
        phase TEXT NOT NULL CHECK (phase IN ('attention', 'watching', 'resolved')),
        signature TEXT NOT NULL, failure_code TEXT NOT NULL, video_id TEXT,
        archived_count INTEGER NOT NULL CHECK (archived_count BETWEEN 0 AND 25),
        incomplete_count INTEGER NOT NULL CHECK (incomplete_count BETWEEN 0 AND 25),
        observed_at TEXT NOT NULL, sequence INTEGER NOT NULL CHECK (sequence >= 1)
    )""",
    """CREATE TABLE events (
        event_id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(run_id),
        sequence INTEGER NOT NULL, kind TEXT NOT NULL
            CHECK (kind IN ('attention', 'resumed', 'recovered')),
        signature TEXT NOT NULL,
        state TEXT NOT NULL CHECK (state IN ('reserved', 'emitted', 'uncertain')),
        reserved_at TEXT NOT NULL, emission_finished_at TEXT,
        UNIQUE (run_id, sequence), UNIQUE (run_id, kind, signature)
    )""",
)


class NotificationError(ValueError):
    """A notification-state refusal that contains no captured diagnostics."""


class Reservation(NamedTuple):
    event_id: str
    message: str


def _stamp(now: dt.datetime) -> str:
    if not isinstance(now, dt.datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise NotificationError("Notification clock must have a timezone")
    return now.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _reason_code(code: Any) -> str:
    if isinstance(code, str):
        if code in REASONS:
            return code
        if UNKNOWN_CODE.fullmatch(code):
            return "unknown"
        parts = code.split(":")
        if len(parts) == 3 and parts[0] == "partial" and parts[1] in REASONS and DIGEST.fullmatch(parts[2]):
            return parts[1]
    raise NotificationError("Invalid notification failure classification")


def _snapshot(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise NotificationError("Invalid notification snapshot")
    run_id, lease_id, phase = (value.get(key) for key in ("run_id", "lease_id", "phase"))
    if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
        raise NotificationError("Invalid notification run identity")
    if not isinstance(lease_id, str) or not LEASE_ID.fullmatch(lease_id):
        raise NotificationError("Invalid notification lease identity")
    if not isinstance(phase, str) or phase not in {"attention", "watching", "resolved"}:
        raise NotificationError("Invalid notification phase")
    recovery = value.get("recovery_verified", False)
    if type(recovery) is not bool or (phase == "resolved" and not recovery):
        raise NotificationError("Notification recovery requires validated finalization")
    counts = [value.get(key) for key in ("archived_count", "incomplete_count")]
    if any(type(count) is not int or not 0 <= count <= MAX_ITEMS for count in counts) or sum(counts) > MAX_ITEMS:
        raise NotificationError("Invalid notification outcome counts")
    if phase == "resolved" and counts[1] != 0:
        raise NotificationError("Notification recovery still has unfinished items")
    code = value.get("failure_code")
    if phase == "attention":
        _reason_code(code)
    video = value.get("video_id")
    if video is not None and (not isinstance(video, str) or not VIDEO_ID.fullmatch(video)):
        raise NotificationError("Invalid notification video identity")
    return {"run_id": run_id, "lease_id": lease_id, "phase": phase,
            "failure_code": code if phase == "attention" else None, "video_id": video,
            "archived_count": counts[0], "incomplete_count": counts[1]}


def _timestamp(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 40:
        raise NotificationError("Invalid stored notification timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise NotificationError("Invalid stored notification timestamp") from None
    return _stamp(parsed)


def _signature(snapshot: dict[str, Any]) -> str:
    identity = [snapshot[key] for key in ("run_id", "lease_id", "failure_code", "video_id")]
    return hashlib.sha256(json.dumps(identity, separators=(",", ":")).encode()).hexdigest()


def _message(snapshot: dict[str, Any], kind: str, signature: str) -> str:
    run_id = snapshot["run_id"]
    counts = f"{snapshot['archived_count']} archived; {snapshot['incomplete_count']} unfinished."
    if kind == "attention":
        code = snapshot["failure_code"]
        reason, next_step = REASONS[_reason_code(code)]
        video = f" Video {snapshot['video_id']}." if snapshot["video_id"] else ""
        text = f"Windows YouTube worker needs attention. Run {run_id}. {reason}.{video} {counts} {next_step}."
    elif kind == "resumed":
        text = f"Windows YouTube worker resumed. Run {run_id}. Completion is not yet validated. {counts}"
    else:
        text = f"Windows YouTube run recovered. Run {run_id}. Archive import and finalization validated. {counts}"
    return f"{text} Incident {signature[:12]}."


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _check_parent(path: Path) -> None:
    for ancestor in (path, *path.parents):
        if ancestor.is_symlink() or (ancestor.exists() and not ancestor.is_dir()):
            raise NotificationError("Notification database parent must contain only regular directories")


def _prepare_directory(path: Path) -> None:
    _check_parent(path)
    path.mkdir(parents=True, exist_ok=True)
    # Another initializer can have just created an ancestor before syncing its
    # name. Persist the entire initial directory chain before opening SQLite.
    for ancestor in reversed((path, *path.parents)):
        _fsync_directory(ancestor)


class NotificationStore:
    def __init__(self, path: Path, *, read_only: bool = False):
        self.path = Path(path).absolute()
        self.read_only = read_only
        self._db: sqlite3.Connection | None = None
        self._entered = False

    def __enter__(self) -> "NotificationStore":
        if self._entered:
            raise NotificationError("Notification store is already open")
        self._entered = True
        try:
            if self.path.is_symlink() or (self.path.exists() and not self.path.is_file()):
                raise NotificationError("Notification database must be a regular file")
            _check_parent(self.path.parent)
            if self.read_only and not self.path.exists():
                return self
            if not self.read_only:
                if not self.path.exists():
                    _prepare_directory(self.path.parent)
            target = self.path.as_uri() + "?mode=ro" if self.read_only else str(self.path)
            self._db = sqlite3.connect(target, uri=self.read_only, timeout=10, isolation_level=None)
            self._db.row_factory = sqlite3.Row
            self._db.execute("PRAGMA foreign_keys=ON")
            self._db.execute("PRAGMA synchronous=EXTRA")
            if self.read_only:
                self._db.execute("PRAGMA query_only=ON")
            with self._transaction(write=not self.read_only) as db:
                self._admit(db)
            if not self.read_only:
                _fsync_directory(self.path.parent)
            return self
        except (OSError, sqlite3.Error):
            self._close()
            raise NotificationError("Notification database could not be opened; diagnostics withheld") from None
        except BaseException:
            self._close()
            raise

    def __exit__(self, *_args: Any) -> None:
        self._close()

    def _close(self) -> None:
        self._entered = False
        if self._db is not None:
            self._db.close()
            self._db = None

    @contextmanager
    def _transaction(self, *, write: bool = True):
        if self._db is None or (write and self.read_only):
            raise NotificationError("Notification store is not open for this operation")
        try:
            self._db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield self._db
            self._db.execute("COMMIT")
        except BaseException as exc:
            if self._db.in_transaction:
                self._db.execute("ROLLBACK")
            if isinstance(exc, sqlite3.Error):
                raise NotificationError("Notification state could not be committed; diagnostics withheld") from None
            raise

    def _admit(self, db: sqlite3.Connection) -> None:
        if db.execute("PRAGMA journal_mode").fetchone()[0] != "delete":
            raise NotificationError("Notification database journal mode differs")
        application_id = db.execute("PRAGMA application_id").fetchone()[0]
        version = db.execute("PRAGMA user_version").fetchone()[0]
        objects = db.execute("SELECT name, sql FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'").fetchall()
        if not self.read_only and application_id == version == 0 and not objects:
            for sql in _SCHEMA:
                db.execute(sql)
            db.execute("INSERT INTO metadata VALUES (1, '')")
            db.execute(f"PRAGMA application_id={APPLICATION_ID}")
            db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        else:
            expected = {sql.split()[2]: " ".join(sql.split()) for sql in _SCHEMA}
            actual = {row["name"]: " ".join((row["sql"] or "").split()) for row in objects}
            if application_id != APPLICATION_ID or version != SCHEMA_VERSION or actual != expected:
                raise NotificationError("Notification database identity or schema differs")
        cursor = db.execute("SELECT id, scan_after FROM metadata").fetchall()
        if len(cursor) != 1 or cursor[0]["id"] != 1 or not isinstance(cursor[0]["scan_after"], str) or (cursor[0]["scan_after"] and not RUN_ID.fullmatch(cursor[0]["scan_after"])):
            raise NotificationError("Invalid notification scan cursor")

    @staticmethod
    def _run(row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        snapshot = _snapshot({**data, "recovery_verified": True})
        _reason_code(data["failure_code"])
        if not isinstance(data["signature"], str) or not DIGEST.fullmatch(data["signature"]) or type(data["sequence"]) is not int or data["sequence"] < 1:
            raise NotificationError("Invalid stored notification identity")
        snapshot["failure_code"] = data["failure_code"]
        if _signature(snapshot) != data["signature"]:
            raise NotificationError("Stored notification signature differs")
        _timestamp(data["observed_at"])
        return data

    def observe(self, snapshot: dict[str, Any], now: dt.datetime) -> Reservation | None:
        snapshot = _snapshot(snapshot)
        stamp = _stamp(now)
        with self._transaction() as db:
            row = db.execute("SELECT * FROM runs WHERE run_id=?", (snapshot["run_id"],)).fetchone()
            previous = self._run(row) if row is not None else None
            phase = snapshot["phase"]
            if previous is None and phase != "attention":
                return None
            if previous is not None:
                if previous["lease_id"] != snapshot["lease_id"]:
                    raise NotificationError("Notification run lease changed; inspect authoritative bindings")
                if previous["phase"] == "resolved" and phase != "resolved":
                    raise NotificationError("A finalized notification run returned to an unfinished state")
            signature = _signature(snapshot) if phase == "attention" else previous["signature"]
            kind = {"attention": "attention", "watching": "resumed", "resolved": "recovered"}[phase]
            event_signature = (_signature({**snapshot, "failure_code": None, "video_id": None})
                               if kind == "recovered" else signature)
            # Phase observations are mutable; the reserved incident identity is
            # permanent, including uncertain emissions and a return after resume.
            seen = db.execute("SELECT 1 FROM events WHERE run_id=? AND kind=? AND signature=?",
                              (snapshot["run_id"], kind, event_signature)).fetchone()
            sequence = (previous["sequence"] if previous else 0) + int(seen is None)
            code = snapshot["failure_code"] if phase == "attention" else previous["failure_code"]
            video = snapshot["video_id"] if phase == "attention" else previous["video_id"]
            db.execute("""INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET phase=excluded.phase,
                signature=excluded.signature, failure_code=excluded.failure_code,
                video_id=excluded.video_id, archived_count=excluded.archived_count,
                incomplete_count=excluded.incomplete_count, observed_at=excluded.observed_at,
                sequence=excluded.sequence""",
                (snapshot["run_id"], snapshot["lease_id"], phase, signature, code, video,
                 snapshot["archived_count"], snapshot["incomplete_count"], stamp, sequence))
            if seen is not None:
                return None
            event_id = uuid.uuid4().hex
            db.execute("INSERT INTO events VALUES (?, ?, ?, ?, ?, 'reserved', ?, NULL)",
                       (event_id, snapshot["run_id"], sequence, kind, event_signature, stamp))
            return Reservation(event_id, _message(snapshot, kind, signature))

    def unfinished_runs(self, limit: int = 8, exclude_run_id: str | None = None) -> list[str]:
        self._limit(limit)
        if exclude_run_id is not None and (not isinstance(exclude_run_id, str) or not RUN_ID.fullmatch(exclude_run_id)):
            raise NotificationError("Invalid excluded notification run identity")
        with self._transaction() as db:
            cursor = db.execute("SELECT scan_after FROM metadata WHERE id=1").fetchone()[0]
            query = "SELECT run_id FROM runs WHERE phase != 'resolved' AND (? IS NULL OR run_id != ?) AND run_id"
            rows = db.execute(query + " > ? ORDER BY run_id LIMIT ?", (exclude_run_id, exclude_run_id, cursor, limit)).fetchall()
            if len(rows) < limit:
                rows += db.execute(query + " <= ? ORDER BY run_id LIMIT ?", (exclude_run_id, exclude_run_id, cursor, limit - len(rows))).fetchall()
            run_ids = [row["run_id"] for row in rows]
            if any(not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id) for run_id in run_ids):
                raise NotificationError("Invalid stored notification run identity")
            if run_ids:
                db.execute("UPDATE metadata SET scan_after=? WHERE id=1", (run_ids[-1],))
            return run_ids

    def mark_emission(self, event_id: str, successful: bool) -> None:
        if not isinstance(event_id, str) or not EVENT_ID.fullmatch(event_id) or type(successful) is not bool:
            raise NotificationError("Invalid notification emission result")
        desired = "emitted" if successful else "uncertain"
        with self._transaction() as db:
            row = db.execute("SELECT state FROM events WHERE event_id=?", (event_id,)).fetchone()
            if row is None or row["state"] not in {"reserved", desired}:
                raise NotificationError("Notification emission reservation differs")
            if row["state"] == "reserved":
                db.execute("UPDATE events SET state=?, emission_finished_at=? WHERE event_id=?",
                           (desired, _stamp(dt.datetime.now(dt.timezone.utc)), event_id))

    @staticmethod
    def _limit(limit: int) -> None:
        if type(limit) is not int or not 1 <= limit <= 64:
            raise NotificationError("Notification result limit must be 1..64")

    def status(self, limit: int = 20) -> list[dict[str, Any]]:
        """SELECT-only summaries; 'emitted' means stdout, never recipient receipt."""
        self._limit(limit)
        if not self._entered:
            raise NotificationError("Notification store is not open for this operation")
        if self._db is None and self.read_only:
            return []
        with self._transaction(write=False) as db:
            rows = db.execute("SELECT * FROM runs ORDER BY run_id DESC LIMIT ?", (limit,)).fetchall()
            summaries = []
            for row in rows:
                run = self._run(row)
                event = db.execute("SELECT event_id, kind, signature, state, reserved_at, emission_finished_at FROM events WHERE run_id=? AND sequence=?",
                                   (run["run_id"], run["sequence"])).fetchone()
                if event is None or not isinstance(event["event_id"], str) or not EVENT_ID.fullmatch(event["event_id"]) or event["kind"] not in {"attention", "resumed", "recovered"} or event["state"] not in {"reserved", "emitted", "uncertain"} or not isinstance(event["signature"], str) or not DIGEST.fullmatch(event["signature"]):
                    raise NotificationError("Invalid stored notification emission")
                _timestamp(event["reserved_at"])
                if event["emission_finished_at"] is not None:
                    _timestamp(event["emission_finished_at"])
                summaries.append({key: run[key] for key in ("run_id", "lease_id", "phase", "failure_code", "video_id", "archived_count", "incomplete_count", "observed_at")})
                summaries[-1]["latest_event"] = dict(event)
            return summaries
