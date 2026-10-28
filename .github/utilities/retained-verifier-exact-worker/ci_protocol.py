"""Closed contracts for the disarmed retained-report successor.

No cloud, privilege, namespace or service operations occur on import or CLI.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
import os
import re
import stat
import time
from pathlib import Path

ARMED = False
REPORT_BYTES = 66  # SYNTHETIC ONLY; no retained-image authority.
REPORT_SHA = '00d915549e747dd40556a277b428b07e2113cdc2e5c404e85bf339c7851bdf5b'  # SYNTHETIC ONLY; no retained-image authority.
INDEX = 'sha256:dabb6734aef65473bd1c9d1f5f2971cd9c724020ceed4492928db07383e8ad48'  # SYNTHETIC ONLY; no retained-image authority.
SOURCE = 'b7a0f3d51dbe8b262b900d12c49637c650f0e9c7'  # SYNTHETIC ONLY; no retained-image authority.
SCANNER = 'c168bb9df139d3b690db370df660d13e902905e8'  # SYNTHETIC ONLY; no retained-image authority.
PRIVATE_MAX = 768 * 1024 * 1024
PUBLIC_MAX = 256 * 1024 * 1024
MIN_BOOT_FREE = 2 * 1024 * 1024 * 1024
MAX_FILES = 128
RAW_CUSTODY_MAX = 131072
CONSUMER = {}  # SYNTHETIC ONLY; no retained-image authority.


class Refusal(RuntimeError):
    def __init__(self, code, facts=None):
        if not isinstance(code, str) or not re.fullmatch(r"[a-z][a-z0-9_.]{0,95}", code):
            code = "invalid_reason_code"
        super().__init__(code)
        self.code = code
        self.reason = code
        self.facts = {} if facts is None else facts


def require(condition, code, facts=None):
    if not condition:
        raise Refusal(code, facts)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def _pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def decode(raw, cap=16384):
    require(isinstance(raw, bytes) and len(raw) <= cap, "json_size")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                          parse_constant=lambda _: require(False, "nonfinite_json"))
    except Refusal:
        raise
    except (ValueError, UnicodeError):
        raise Refusal("malformed_json") from None


def closed(value, keys, code="closed_schema"):
    require(isinstance(value, dict) and set(value) == set(keys), code)
    return value


def integer(value, low=0, high=(1 << 63) - 1):
    return type(value) is int and low <= value <= high


def utc(value):
    require(isinstance(value, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value), "utc_format")
    try:
        result = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    except ValueError:
        raise Refusal("utc_value") from None
    return result


def stamp(value):
    return value.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def identity(session):
    require(isinstance(session, str) and re.fullmatch(r"[0-9a-f]{32}", session), "session_identity")
    return "ocv-" + session[:24], "ocv-" + session + ".service"


def regular_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read_regular(path, cap, *, expected_sha=None, expected_size=None):
    """No-follow, bounded single-inode read; parent must already be trusted."""
    before = os.lstat(path)
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, "file_identity")
    require(before.st_size <= cap, "file_size")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        require(regular_identity(before) == regular_identity(opened), "file_changed")
        parts, total = [], 0
        while True:
            chunk = os.read(fd, min(65536, cap + 1 - total))
            if not chunk:
                break
            parts.append(chunk); total += len(chunk)
            require(total <= cap, "file_grew")
        after = os.fstat(fd)
        require(regular_identity(opened) == regular_identity(after), "file_changed")
        require(regular_identity(after) == regular_identity(os.lstat(path)), "file_replaced")
    finally:
        os.close(fd)
    raw = b"".join(parts)
    require(len(raw) == before.st_size, "file_short_read")
    if expected_size is not None:
        require(len(raw) == expected_size, "file_size_pin")
    if expected_sha is not None:
        require(sha(raw) == expected_sha, "file_hash_pin")
    return raw


def write_once(path, raw, mode=0o600):
    require(isinstance(raw, bytes), "write_type")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode)
        view = memoryview(raw)
        while view:
            n = os.write(fd, view)
            require(n > 0, "write_short")
            view = view[n:]
        os.fsync(fd)
    finally:
        os.close(fd)
    return {"bytes": len(raw), "sha256": sha(raw)}


class Budget:
    """One monotonic deadline; no per-phase resets or retry allowance."""
    def __init__(self, seconds, clock=time.monotonic):
        require(isinstance(seconds, (int, float)) and not isinstance(seconds, bool)
                and math.isfinite(seconds) and 0 < seconds <= 300, "budget_bound")
        self.clock = clock
        self.deadline = clock() + seconds

    def remaining(self):
        value = self.deadline - self.clock()
        require(value > 0, "budget_expired")
        return value


if __name__ == "__main__":
    raise SystemExit("disarmed_local_source_only")
