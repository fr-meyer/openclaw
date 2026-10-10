#!/usr/bin/env python3
"""Fail-closed Windows canary lifecycle for the global YouTube pool.

Windows is deliberately an opt-in validation lane only.  This module never
changes scheduler state, enables Windows, deletes remote staging, uses cookies,
or downloads media.  Control operations go through the audited
``scripts/openclaw-node-run`` path and the staged PowerShell adapter.  Finished
bundles return through OpenClaw's identity-bound ``file.fetch`` node command so
binary data never depends on the bounded ``system.run`` stdout envelope.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import gzip
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
import time
import uuid

from youtube_windows_config import load_config
from collections.abc import Callable
from pathlib import Path, PureWindowsPath
from typing import Any, TypeVar

WORKSPACE = Path(__file__).resolve().parents[1]
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
POOL_ROOT = STORAGE.DEFAULT_POOL_ROOT
ARCHIVE_ROOT = STORAGE.DEFAULT_ARCHIVE_ROOT
YC_ROOT = STORAGE.DEFAULT_YC_ROOT
YC_CODE_ROOT = WORKSPACE / "scripts/youtube_ycombinator"
CANARIES_ROOT = POOL_ROOT / "windows-canaries"
WINDOWS_CONFIG = load_config()
WINDOWS_NODE_LABEL = WINDOWS_CONFIG["node"]["label"]
WINDOWS_PLATFORM = "windows"
WINDOWS_POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
REMOTE_PARENT = WINDOWS_CONFIG["remote"]["staging_root"]
REMOTE_ADAPTER_PATH = WINDOWS_CONFIG["remote"]["adapter"]
REMOTE_ARCHIVER_PATH = WINDOWS_CONFIG["remote"]["archiver"]
REMOTE_YT_DLP_WRAPPER_PATH = WINDOWS_CONFIG["remote"]["wrapper"]
REMOTE_CHUNK_ID = "0001"
REMOTE_ADAPTER = WORKSPACE / "scripts/youtube_global_windows_adapter.ps1"
REMOTE_WORKER = WORKSPACE / "scripts/youtube_global_chunk_worker.py"
CANARY_ID_RE = re.compile(r"^windows-canary-[a-z0-9-]{1,64}$")
REMOTE_IMPORTABLE = {"complete", "complete_with_blocked"}
REMOTE_BLOCKED = {
    "blocked_bot_check",
    "blocked_auth_required",
    "blocked_configuration",
    "blocked_interrupted",
    "waiting_network_cooldown",
}
MAX_CANARY_ITEMS = 25
# The bundled file-transfer node command has a hard 16 MiB per-file limit.  A
# production Windows lot is eight transcript archives and is expected to stay
# comfortably below this bound.  Oversized bundles fail closed with their lease
# retained rather than falling back to the truncated command-output path.
FILE_FETCH_MAX_BYTES = 16 * 1024 * 1024
FILE_FETCH_TIMEOUT_SECONDS = 300
NODE_RETRY_ATTEMPTS = 5
NODE_RETRY_SLEEP_SECONDS = 2.0
T = TypeVar("T")
_LOADED_CANARY_SHA256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
RESUME_SCHEMA = "openclaw.youtube.windows-resume.v2"
RECOVERY_POLICY = "gcp-rate-recovery-v1"
RECOVERY_WAITS = (4 * 3600, 8 * 3600)
RECOVERY_HORIZON = 24 * 3600
RECOVERY_DISPATCHED = {"intent", "uncertain", "acknowledged"}
RECOVERY_STATES = RECOVERY_DISPATCHED | {"armed", "expired", "held"}
RECOVERY_MAX_RECEIPTS = 64
RECOVERY_MAX_RECEIPT_BYTES = 64 * 1024
RECOVERY_MAX_TOTAL_BYTES = 1024 * 1024


def load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load module {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


LC = load_module("youtube_global_windows_lifecycle", WORKSPACE / "scripts/youtube_windows_import.py")
GP = LC.GP
YC = LC.YC


class SelectionConflictError(GP.PoolError):
    """Selected items were claimed by another node before lease creation."""


class RecoveryNotReady(GP.PoolError):
    """The same approved checkpoint is temporarily busy, without a dispatch."""


def _transient_node_errors() -> tuple[type[BaseException], ...]:
    return (YC.SafeCommandFailure, YC.NodeRequestTimedOut, YC.NodeUnavailable)


def _retry_transient_node_call(fn: Callable[[], T]) -> T:
    """Retry brief Windows node/gateway flaps without launching extra workers."""
    last: BaseException | None = None
    for attempt in range(1, NODE_RETRY_ATTEMPTS + 1):
        try:
            return fn()
        except _transient_node_errors() as exc:
            last = exc
            if attempt >= NODE_RETRY_ATTEMPTS:
                break
            time.sleep(NODE_RETRY_SLEEP_SECONDS * attempt)
    assert last is not None
    raise last


def utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def read_json(path: Path, default: Any = None) -> Any:
    if not path.is_file():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def atomic_json(path: Path, payload: Any) -> None:
    GP.atomic_json(path, payload)


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def stable_hash(payload: Any) -> str:
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256_bytes(raw)


def workspace_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(WORKSPACE.resolve()))
    except ValueError:
        return str(path.resolve())


def state_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(POOL_ROOT.resolve()))
    except ValueError:
        return str(path.resolve())


def validate_canary_id(value: str) -> str:
    value = str(value).strip().lower()
    if not CANARY_ID_RE.fullmatch(value):
        raise ValueError(f"invalid Windows canary id: {value!r}")
    return value


def canary_root(canary_id: str) -> Path:
    return CANARIES_ROOT / validate_canary_id(canary_id)


def remote_canary_root(canary_id: str) -> str:
    return REMOTE_PARENT + "\\canaries\\" + validate_canary_id(canary_id)


def windows_config() -> dict[str, Any]:
    """Static Windows lane configuration; no scheduler configuration is read or changed."""
    return {
        "node": WINDOWS_CONFIG["node"]["id"],
        "agent_id": WINDOWS_CONFIG["agent_id"],
        "platform": WINDOWS_PLATFORM,
        "node_cwd": WINDOWS_CONFIG["node"]["cwd"],
        "remote_root": REMOTE_PARENT,
        "remote_adapter": REMOTE_ADAPTER_PATH,
        "remote_archiver": REMOTE_ARCHIVER_PATH,
        "remote_yt_dlp_wrapper": REMOTE_YT_DLP_WRAPPER_PATH,
        "max_attempts": 3,
        "inter_item_sleep_seconds": 10,
        "safety": {"cookies_allowed": False, "media_allowed": False, "max_concurrent_workers": 1},
        "windows_enabled": False,
    }


def remote_summary(remote: dict[str, Any]) -> dict[str, Any]:
    return {
        "state": str(remote.get("state") or "unknown"),
        "counts": remote.get("counts") if isinstance(remote.get("counts"), dict) else {},
        "current_index": remote.get("current_index"),
        "current_video_id": remote.get("current_video_id"),
        "updated_at": remote.get("updated_at"),
        "worker_alive": remote.get("worker_alive") is True,
        "lease_id": remote.get("lease_id"),
        "cookies_used": remote.get("cookies_used"),
        "media_downloaded": remote.get("media_downloaded"),
        "circuit_open": bool(remote.get("circuit_open")),
        "circuit_reason": remote.get("circuit_reason"),
    }


def _require_bool_false(payload: dict[str, Any], key: str) -> None:
    if payload.get(key) is not False:
        raise GP.PoolError(f"Windows adapter safety flag {key} is not false")


def _require_safe_payload(payload: dict[str, Any], action: str) -> None:
    cookie_key = "cookies_used" if action == "Package" else "cookiesUsed"
    media_key = "media_files" if action == "Package" else "mediaFiles"
    _require_bool_false(payload, cookie_key)
    if payload.get(media_key) != 0:
        raise GP.PoolError("Windows adapter reported media files")


def windows_node_status(config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Require the exact configured display label, platform, connection, and RPC capability."""
    config = config or windows_config()
    node = _retry_transient_node_call(lambda: YC.require_connected_node(config))
    if node.get("displayName") != WINDOWS_NODE_LABEL:
        raise GP.PoolError("Windows node display label mismatch")
    if node.get("platform") != WINDOWS_PLATFORM:
        raise GP.PoolError("Windows node platform mismatch")
    if node.get("connected") is not True:
        raise GP.PoolError("Windows node is not connected")
    if not isinstance(node.get("nodeId"), str) or not node["nodeId"]:
        raise GP.PoolError("Windows node id is missing")
    if node["nodeId"] != WINDOWS_CONFIG["node"]["id"]:
        raise GP.PoolError("Windows node identity mismatch")
    if not isinstance(node.get("commands"), list) or "system.run" not in node["commands"]:
        raise GP.PoolError("Windows node does not advertise system.run")
    return node


def _ps_quote(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _powershell_encoded_command(script: str) -> list[str]:
    """Return deterministic Windows PowerShell argv without inline ``-Command`` text."""
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    return [
        "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
        "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded,
    ]


def _remote_adapter_stage_command(adapter_bytes: bytes, digest: str) -> list[str]:
    encoded = base64.b64encode(gzip.compress(adapter_bytes, compresslevel=9, mtime=0)).decode("ascii")
    # This is intentionally a write-only, idempotent staging operation.  It
    # never removes old remote data and verifies the exact staged adapter hash.
    script = (
        "$ErrorActionPreference='Stop'; "
        f"$path={_ps_quote(REMOTE_ADAPTER_PATH)}; "
        "$profile=[IO.Path]::GetFullPath($env:USERPROFILE).TrimEnd('\\'); $full=[IO.Path]::GetFullPath($path).TrimEnd('\\'); "
        "if(-not ($full.StartsWith($profile+'\\',[StringComparison]::OrdinalIgnoreCase))){throw 'adapter path is outside USERPROFILE'}; "
        "$root=[IO.Path]::GetPathRoot($full); $relative=$full.Substring($root.Length).TrimStart('\\'); $current=$root; "
        "foreach($part in $relative.Split('\\')){if($part){$current=Join-Path $current $part}; if(Test-Path -LiteralPath $current){$item=Get-Item -LiteralPath $current -Force; if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'adapter path reparse point refused'}}}; "
        "if(Test-Path -LiteralPath $path -PathType Leaf){$actual=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant(); if($actual -ne "
        f"{_ps_quote(digest)}){{throw 'existing staged adapter hash mismatch'}}; [ordered]@{{path=$path;sha256=$actual;size=(Get-Item -LiteralPath $path).Length}}|ConvertTo-Json -Compress; exit 0}}; "
        "$parent=Split-Path -Parent $path; New-Item -ItemType Directory -Force -Path $parent | Out-Null; "
        f"$compressed=[Convert]::FromBase64String({_ps_quote(encoded)}); "
        "$source=[IO.MemoryStream]::new($compressed); $gzip=[IO.Compression.GzipStream]::new($source,[IO.Compression.CompressionMode]::Decompress); "
        "$decoded=[IO.MemoryStream]::new(); try{$gzip.CopyTo($decoded);$bytes=$decoded.ToArray()}finally{$decoded.Dispose();$gzip.Dispose();$source.Dispose()}; "
        "$tmp=$path+'.tmp-'+[guid]::NewGuid().ToString('N'); "
        "[IO.File]::WriteAllBytes($tmp,$bytes); Move-Item -LiteralPath $tmp -Destination $path -Force; "
        "$actual=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant(); "
        f"if($actual -ne {_ps_quote(digest)}){{throw 'staged adapter hash mismatch'}}; "
        "[ordered]@{path=$path;sha256=$actual;size=(Get-Item -LiteralPath $path).Length}|ConvertTo-Json -Compress"
    )
    return _powershell_encoded_command(script)


def _remote_adapter_verify_command(digest: str) -> list[str]:
    script = (
        "$ErrorActionPreference='Stop'; "
        f"$path={_ps_quote(REMOTE_ADAPTER_PATH)}; "
        "if(-not (Test-Path -LiteralPath $path -PathType Leaf)){[ordered]@{exists=$false}|ConvertTo-Json -Compress; exit 0}; "
        "$actual=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant(); "
        f"[ordered]@{{exists=$true;path=$path;sha256=$actual;expected={_ps_quote(digest)};size=(Get-Item -LiteralPath $path).Length}}|ConvertTo-Json -Compress"
    )
    return _powershell_encoded_command(script)


def _run_node(config: dict[str, Any], command: list[str], *, timeout: int, operation: str, retry: bool = True) -> Any:
    invoke = lambda: YC.run_node_command(config, command, timeout=timeout, operation=operation, preflight=False)
    # Lost RPC replies cannot prove whether a worker started. Observe before
    # another explicit recovery; never repeat a launch/resume RPC automatically.
    result = _retry_transient_node_call(invoke) if retry else invoke()
    try:
        return YC.parse_json_output(result.stdout)
    except Exception as exc:
        raise GP.PoolError(f"{operation} returned invalid JSON") from None


def _remote_adapter_hash_command() -> list[str]:
    return ["certutil.exe", "-hashfile", REMOTE_ADAPTER_PATH, "SHA256"]


def _parse_certutil_sha256(output: str) -> str:
    matches = re.findall(r"(?im)^\s*([0-9a-f]{64})\s*$", str(output))
    if len(matches) != 1:
        raise GP.PoolError("Windows adapter hash probe returned an invalid digest")
    return matches[0].lower()


def _stage_remote_adapter(config: dict[str, Any]) -> dict[str, Any]:
    """Verify the pre-staged adapter with a native binary; never self-update it."""
    raw = REMOTE_ADAPTER.read_bytes()
    digest = sha256_bytes(raw)
    result = _retry_transient_node_call(
        lambda: YC.run_node_command(
            config,
            _remote_adapter_hash_command(),
            timeout=60,
            operation="verify staged Windows canary adapter",
            preflight=False,
        )
    )
    actual = _parse_certutil_sha256(result.stdout)
    if actual != digest:
        raise GP.PoolError("staged Windows adapter hash mismatch; controlled restaging is required")
    return {"path": REMOTE_ADAPTER_PATH, "sha256": digest, "size": len(raw)}


def _adapter_command(
    config: dict[str, Any],
    action: str,
    *,
    staging_root: str = REMOTE_PARENT,
    lease_id: str | None = None,
    worker_b64: str | None = None,
    worker_gzip_b64: str | None = None,
    urls_b64: str | None = None,
    offset: int | None = None,
    count: int | None = None,
    checkpoint_sha256: str | None = None,
) -> list[str]:
    # Use PowerShell's positional script-file form.  The connected Windows
    # node (2026.7.1) misclassifies ``-File`` allowlist targets as directly
    # executable .ps1 files and fails with ``spawn EFTYPE``.  Positional form
    # remains argv-bound to the pinned PowerShell binary and exact adapter path.
    #
    # Keep this interpreter invocation bindable by OpenClaw's approval flow:
    # passing the existing archiver and wrapper as explicit argv makes three
    # concrete local file operands, while approval-backed runtime commands may
    # bind exactly one.  The audited adapter already pins these same defaults.
    if (
        config.get("remote_archiver") != REMOTE_ARCHIVER_PATH
        or config.get("remote_yt_dlp_wrapper") != REMOTE_YT_DLP_WRAPPER_PATH
    ):
        raise GP.PoolError("Windows adapter tool path configuration differs from its pinned defaults")
    command = [
        WINDOWS_POWERSHELL, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        REMOTE_ADAPTER_PATH,
        "-Action", action,
        "-StagingRoot", staging_root,
        "-MaxAttempts", str(config["max_attempts"]),
        "-InterItemSleepSeconds", str(config["inter_item_sleep_seconds"]),
    ]
    if lease_id is not None:
        command += ["-ChunkId", REMOTE_CHUNK_ID, "-LeaseId", lease_id]
    if worker_b64 is not None:
        command += ["-WorkerBase64", worker_b64]
    if worker_gzip_b64 is not None:
        command += ["-WorkerGzipBase64", worker_gzip_b64]
    if urls_b64 is not None:
        command += ["-UrlsBase64", urls_b64]
    if offset is not None:
        command += ["-Offset", str(offset)]
    if count is not None:
        command += ["-Count", str(count)]
    if checkpoint_sha256 is not None:
        if not re.fullmatch(r"[0-9a-f]{64}", checkpoint_sha256):
            raise GP.PoolError("Windows recovery checkpoint digest invalid")
        command += ["-CheckpointSha256", checkpoint_sha256]
    return command


def _normalise_probe(payload: dict[str, Any]) -> dict[str, Any]:
    status = payload.get("status") if isinstance(payload.get("status"), dict) else {}
    staging = payload.get("staging") if isinstance(payload.get("staging"), dict) else {}
    merged = {**status, **payload}
    merged["chunk_id"] = merged.get("chunk_id") or payload.get("chunkId") or staging.get("chunk_id")
    merged["lease_id"] = merged.get("lease_id") or payload.get("leaseId") or staging.get("lease_id")
    merged["worker_alive"] = payload.get("workerAlive") if isinstance(payload.get("workerAlive"), bool) else None
    merged["worker_lock_free"] = payload.get("workerLockFree")
    merged["status_sha256"] = payload.get("statusSha256")
    merged["cookies_used"] = status.get("cookies_used", payload.get("cookiesUsed"))
    merged["media_downloaded"] = status.get("media_downloaded", False)
    merged["media_files"] = payload.get("mediaFiles", 0)
    merged["staging"] = staging
    merged["exists"] = payload.get("exists") is True
    return merged


def _invoke_adapter(
    action: str,
    *,
    staging_root: str = REMOTE_PARENT,
    lease_id: str | None = None,
    worker_b64: str | None = None,
    worker_gzip_b64: str | None = None,
    urls_b64: str | None = None,
    offset: int | None = None,
    count: int | None = None,
    checkpoint_sha256: str | None = None,
    timeout: int = 300,
    verify_host: bool = True,
) -> dict[str, Any]:
    config = windows_config()
    if verify_host:
        windows_node_status(config)
        _stage_remote_adapter(config)
    payload = _run_node(
        config,
        _adapter_command(
            config,
            action,
            staging_root=staging_root,
            lease_id=lease_id,
            worker_b64=worker_b64,
            worker_gzip_b64=worker_gzip_b64,
            urls_b64=urls_b64,
            offset=offset,
            count=count,
            checkpoint_sha256=checkpoint_sha256,
        ),
        timeout=timeout,
        operation=f"Windows adapter {action}",
        retry=action not in {"Resume", "StageLaunch"},
    )
    if not isinstance(payload, dict):
        raise GP.PoolError(f"Windows adapter {action} returned a non-object")
    _require_safe_payload(payload, action)
    if action != "Validate":
        chunk_key = "chunk_id" if action == "Package" else "chunkId"
        lease_key = "lease_id" if action == "Package" else "leaseId"
        if payload.get(chunk_key) != REMOTE_CHUNK_ID or payload.get(lease_key) != lease_id:
            raise GP.PoolError(f"Windows adapter {action} lease/chunk binding mismatch")
    if action == "Probe":
        return _normalise_probe(payload)
    return payload


def validate_host() -> dict[str, Any]:
    config = windows_config()
    node = windows_node_status(config)
    result = _invoke_adapter("Validate")
    if result.get("readOnly") is not True or result.get("eligible") is not True:
        raise GP.PoolError(f"Windows host validation failed: {result.get('reasons')}")
    checks = result.get("checks") if isinstance(result.get("checks"), dict) else {}
    if checks.get("transportImplemented") is not True or str(checks.get("platform")) != "Win32NT":
        raise GP.PoolError("Windows host validation did not prove the expected platform or transport")
    if checks.get("assets") != WINDOWS_CONFIG["assets"]:
        raise GP.PoolError("Windows installed component provenance differs from GCP pins")
    for actual, expected in ((checks.get("archiver"), REMOTE_ARCHIVER_PATH), (checks.get("ytDlpWrapper"), REMOTE_YT_DLP_WRAPPER_PATH)):
        if not isinstance(actual, str) or PureWindowsPath(actual) != PureWindowsPath(expected):
            raise GP.PoolError("Windows actual tool paths differ from configured component bindings")
    return {
        "schema": "franck.youtube-global-pool.windows-canary-preflight.v1",
        "state": "passed",
        "checked_at": utcnow(),
        "node": {
            "node_id": node["nodeId"],
            "display_name": node["displayName"],
            "platform": node["platform"],
            "connected": node["connected"] is True,
        },
        "adapter": result,
        "adapter_path": REMOTE_ADAPTER_PATH,
        "windows_enabled": False,
        "cookies_used": False,
        "media_files": 0,
    }


def select_canary_items(items: list[dict[str, Any]], *, item_count: int = 1, now: str | None = None) -> list[dict[str, Any]]:
    if not 1 <= int(item_count) <= MAX_CANARY_ITEMS:
        raise GP.PoolError("Windows canary item count must be 1..25")
    policy = GP.SelectionPolicy(
        chunk_size=int(item_count),
        personal_reserved=min(2, int(item_count)),
        fresh_reserved=0,
    )
    selected = GP.select_items(items, now=now, policy=policy)
    if len(selected) != int(item_count):
        raise GP.PoolError(f"Windows canary requires {item_count} eligible disjoint items; found {len(selected)}")
    ids = [GP.validate_video_id(str(item.get("video_id") or "")) for item in selected]
    if len(ids) != len(set(ids)):
        raise GP.PoolError("Windows canary selection contains duplicate IDs")
    return selected


def _assert_selection_disjoint(store: Any, selected: list[dict[str, Any]]) -> None:
    ids = {str(item["video_id"]) for item in selected}
    active_leases = [read_json(path, {}) or {} for path in store.leases_dir.glob("*.json")]
    active_ids = {
        str(value)
        for lease in active_leases
        if lease.get("state") == "active"
        for value in lease.get("video_ids") or []
    }
    overlap = sorted(ids & active_ids)
    if overlap:
        raise SelectionConflictError(
            f"Windows canary selection overlaps active global items: {overlap}"
        )
    for item in selected:
        current = store.load_item(str(item["video_id"]))
        if not current or current.get("status") != "pending" or current.get("active_lease_id") is not None:
            raise SelectionConflictError(
                f"Windows canary selected item is not disjoint and pending: {item.get('video_id')}"
            )
        if current.get("auth_allowed") is not False or current.get("media_download_allowed") is not False:
            raise GP.PoolError(
                f"Windows canary item violates anonymous caption-only policy: {item.get('video_id')}"
            )


def _binding_payload(canary_id: str, lease_id: str, video_ids: list[str], urls_sha256: str, node: dict[str, Any]) -> dict[str, Any]:
    return {
        "canary_id": canary_id,
        "chunk_id": REMOTE_CHUNK_ID,
        "lease_id": lease_id,
        "video_ids": video_ids,
        "urls_sha256": urls_sha256,
        "node_id": node.get("node_id"),
        "node_label": node.get("display_name"),
        "node_platform": node.get("platform"),
    }


def _lease_binding_hash(lease: dict[str, Any]) -> str:
    node = lease.get("node") if isinstance(lease.get("node"), dict) else {}
    return stable_hash({
        "lease_id": lease.get("lease_id"),
        "chunk_id": lease.get("chunk_id"),
        "node": {"id": node.get("id"), "label": node.get("label"), "platform": node.get("platform")},
        "video_ids": lease.get("video_ids"),
        "cookies_used": lease.get("cookies_used"),
        "media_allowed": lease.get("media_allowed"),
    })


def _chunk_binding_hash(chunk: dict[str, Any]) -> str:
    # Import updates state/attempt/error fields in-place.  Bind only immutable
    # dispatch identity so those journaled transitions do not invalidate the
    # lease while any ID, URL, lane, priority, node, or safety drift still does.
    immutable_items = [
        {
            "video_id": row.get("video_id"),
            "url": row.get("url"),
            "lane": row.get("lane"),
            "priority": row.get("priority"),
        }
        for row in (chunk.get("items") or [])
    ]
    return stable_hash({
        "chunk_id": chunk.get("chunk_id"),
        "lease_id": chunk.get("lease_id"),
        "node_id": chunk.get("node_id"),
        "node_label": chunk.get("node_label"),
        "node_platform": chunk.get("node_platform"),
        "items": immutable_items,
        "cookies_used": chunk.get("cookies_used"),
        "media_allowed": chunk.get("media_allowed"),
    })


def _manifest_and_files_valid(canary_id: str, manifest: dict[str, Any], *, allow_adapter_hotfix: bool = False) -> tuple[Path, dict[str, Any], list[str]]:
    root = canary_root(canary_id)
    if manifest.get("canary_id") != canary_id:
        raise GP.PoolError("Windows canary manifest identity mismatch")
    ids = [GP.validate_video_id(str(value)) for value in manifest.get("video_ids") or []]
    count = int(manifest.get("expected_item_count") or 0)
    if count not in range(1, MAX_CANARY_ITEMS + 1) or len(ids) != count or len(ids) != len(set(ids)):
        raise GP.PoolError("Windows canary manifest item binding is invalid")
    tsv = root / "chunks" / f"{REMOTE_CHUNK_ID}.tsv"
    if not tsv.is_file() or sha256_file(tsv) != manifest.get("urls_sha256"):
        raise GP.PoolError("Windows canary URL file is missing or hash-drifted")
    rows = [line.split("\t", 1) for line in tsv.read_text(encoding="utf-8").splitlines() if line]
    if len(rows) != count or [row[0] for row in rows] != ids or any(len(row) != 2 or row[1] != GP.canonical_url(row[0]) for row in rows):
        raise GP.PoolError("Windows canary URL rows are not canonical or disjoint")
    worker_hash = sha256_file(REMOTE_WORKER)
    adapter_hash = sha256_file(REMOTE_ADAPTER)
    if manifest.get("worker_sha256") != worker_hash:
        raise GP.PoolError("Windows canary worker hash drifted")
    if manifest.get("adapter_sha256") != adapter_hash and not allow_adapter_hotfix:
        raise GP.PoolError("Windows canary adapter hash drifted")
    if manifest.get("assets") != WINDOWS_CONFIG["assets"]:
        raise GP.PoolError("Windows canary installed component pins drifted")
    binding = _binding_payload(canary_id, str(manifest.get("lease_id") or ""), ids, str(manifest.get("urls_sha256") or ""), manifest.get("node") or {})
    if manifest.get("binding_sha256") != stable_hash(binding):
        raise GP.PoolError("Windows canary binding hash drifted")
    return root, manifest, ids


def validate_prelaunch_bindings(canary_id: str, manifest: dict[str, Any], *, allow_adapter_hotfix: bool = False) -> None:
    root, manifest, ids = _manifest_and_files_valid(canary_id, manifest, allow_adapter_hotfix=allow_adapter_hotfix)
    if (
        manifest.get("remote_adapter_path") != REMOTE_ADAPTER_PATH
        or manifest.get("remote_staging_root") != remote_canary_root(canary_id)
    ):
        raise GP.PoolError("Windows canary remote path binding differs")
    store = GP.PoolStore(POOL_ROOT)
    lease_id = str(manifest.get("lease_id") or "")
    lease = read_json(store.leases_dir / f"{lease_id}.json", {}) or {}
    if lease.get("state") != "active" or lease.get("chunk_id") != canary_id or lease.get("video_ids") != ids:
        raise GP.PoolError("Windows canary lease binding differs")
    node = manifest.get("node") or {}
    if lease.get("node", {}).get("id") != node.get("node_id") or lease.get("node", {}).get("platform") != WINDOWS_PLATFORM:
        raise GP.PoolError("Windows canary lease node binding differs")
    if manifest.get("lease_sha256") != _lease_binding_hash(lease):
        raise GP.PoolError("Windows canary lease binding hash differs")
    active = [
        read_json(path, {}) or {}
        for path in store.leases_dir.glob("*.json")
        if (read_json(path, {}) or {}).get("state") == "active"
    ]
    active_ids = {str(row.get("lease_id")) for row in active}
    if lease_id not in active_ids:
        raise GP.PoolError("Windows canary active lease disappeared")
    same_node = [row for row in active if (row.get("node") or {}).get("id") == node.get("node_id")]
    if [str(row.get("lease_id")) for row in same_node] != [lease_id]:
        raise GP.PoolError("Windows node has another active global lease")
    chunk = read_json(store.chunks_dir / f"{canary_id}.json", {}) or {}
    local_chunk = read_json(root / "chunks" / f"{REMOTE_CHUNK_ID}.json", {}) or {}
    for candidate in (chunk, local_chunk):
        candidate_ids = [str(row.get("video_id")) for row in candidate.get("items") or []]
        if candidate.get("lease_id") != lease_id or candidate_ids != ids:
            raise GP.PoolError("Windows canary chunk item binding differs")
        if candidate.get("binding_sha256") != manifest.get("binding_sha256"):
            raise GP.PoolError("Windows canary chunk binding hash differs")
        if candidate.get("chunk_sha256") != _chunk_binding_hash(candidate):
            raise GP.PoolError("Windows canary chunk hash differs")
    if manifest.get("chunk_sha256") != local_chunk.get("chunk_sha256"):
        raise GP.PoolError("Windows canary manifest chunk hash differs")
    for video_id in ids:
        item = store.load_item(video_id)
        if (
            not item
            or item.get("status") not in {"leased", "processing"}
            or item.get("active_lease_id") != lease_id
            or item.get("active_node") != node.get("node_id")
        ):
            raise GP.PoolError(f"Windows canary item lease binding lost for {video_id}")
        if item.get("auth_allowed") is not False or item.get("media_download_allowed") is not False:
            raise GP.PoolError(f"Windows canary item safety binding changed for {video_id}")


def _write_preparation_files(root: Path, canary_id: str, selected: list[dict[str, Any]], manifest: dict[str, Any], created_at: str) -> None:
    GP.ensure_directory_durable(root / "chunks")
    GP.ensure_directory_durable(root / "queue")
    GP.ensure_directory_durable(root / "bundles" / f"chunk-{REMOTE_CHUNK_ID}")
    GP.ensure_directory_durable(root / "imports")
    ids = [str(item["video_id"]) for item in selected]
    tsv = root / "chunks" / f"{REMOTE_CHUNK_ID}.tsv"
    if not tsv.exists():
        GP.atomic_write(tsv, "".join(f"{video_id}\t{GP.canonical_url(video_id)}\n" for video_id in ids))
    node = manifest["node"]
    local_chunk = {
        "schema": "franck.youtube-global-pool.windows-canary-chunk.v1",
        "chunk_id": REMOTE_CHUNK_ID,
        "global_chunk_id": canary_id,
        "canary_id": canary_id,
        "lease_id": manifest["lease_id"],
        "state": "planned",
        "created_at": created_at,
        "node_id": node["node_id"],
        "node_label": node["display_name"],
        "node_platform": WINDOWS_PLATFORM,
        "remote_staging_root": manifest["remote_staging_root"],
        "items": [{"video_id": str(item["video_id"]), "url": GP.canonical_url(str(item["video_id"])), "lane": item.get("lane"), "priority": item.get("priority"), "state": "pending"} for item in selected],
        "binding_sha256": manifest["binding_sha256"],
        "cookies_used": False,
        "media_allowed": False,
    }
    atomic_json(root / "chunks" / f"{REMOTE_CHUNK_ID}.json", local_chunk)
    atomic_json(root / "queue" / "state.json", {"schema": "franck.youtube-global-pool.windows-canary-queue.v1", "state": "planned", "current_chunk": REMOTE_CHUNK_ID, "updated_at": created_at, "windows_enabled": manifest.get("windows_enabled") is True, "cookies_used": False, "media_files": 0})
    atomic_json(root / "selected-item-preimages.json", {"schema": "franck.youtube-global-pool.windows-canary-item-preimages.v1", "canary_id": canary_id, "created_at": created_at, "items": selected})


def resume_canary_preparation(canary_id: str, manifest: dict[str, Any] | None = None) -> dict[str, Any]:
    canary_id = validate_canary_id(canary_id)
    root = canary_root(canary_id)
    manifest = manifest or (read_json(root / "manifest.json", {}) or {})
    if manifest.get("state") not in {"preparing", "prepare_failed_before_lease", "prepared"}:
        raise GP.PoolError(f"Windows canary preparation is not replayable: {manifest.get('state')}")
    root, manifest, ids = _manifest_and_files_valid(canary_id, manifest)
    preimages = read_json(root / "selected-item-preimages.json", {}) or {}
    selected = preimages.get("items") if isinstance(preimages.get("items"), list) else []
    if [str(item.get("video_id")) for item in selected] != ids:
        raise GP.PoolError("Windows canary selection preimages differ")
    node_info = manifest.get("node") if isinstance(manifest.get("node"), dict) else {}
    if node_info.get("platform") != WINDOWS_PLATFORM or node_info.get("display_name") != WINDOWS_NODE_LABEL or node_info.get("connected") is not True or node_info.get("node_id") != WINDOWS_CONFIG["node"]["id"]:
        raise GP.PoolError("Windows canary node preflight binding is not exact")
    store = GP.PoolStore(POOL_ROOT)
    store.ensure_dirs()
    lease_id = str(manifest["lease_id"])
    lease_path = store.leases_dir / f"{lease_id}.json"
    lease = read_json(lease_path, {}) or {}
    exact = lease.get("state") == "active" and lease.get("chunk_id") == canary_id and lease.get("video_ids") == ids and lease.get("node", {}).get("id") == node_info.get("node_id")
    if not exact:
        _assert_selection_disjoint(store, selected)
        node = GP.NodeTarget(node_id=str(node_info["node_id"]), label=WINDOWS_NODE_LABEL, platform=WINDOWS_PLATFORM, adapter_version="windows-powershell-v1", max_chunk_size=len(ids))
        try:
            lease = store.create_lease(node, selected, lease_id=lease_id, chunk_id=canary_id, now=str(manifest.get("created_at") or utcnow()))
        except GP.LeaseConflictError as exc:
            message = str(exc)
            if "recovered an interrupted lease creation" in message:
                lease = store.create_lease(node, selected, lease_id=lease_id, chunk_id=canary_id, now=str(manifest.get("created_at") or utcnow()))
            elif "already has active lease" in message or "is not pending" in message:
                raise SelectionConflictError(f"Windows lease preparation raced with another node: {exc}") from exc
            else:
                raise GP.PoolError(f"Windows lease preparation failed closed: {exc}") from exc
    if lease.get("state") != "active" or lease.get("video_ids") != ids:
        raise GP.PoolError("Windows preparation did not produce the exact active lease")
    global_chunk_path = store.chunks_dir / f"{canary_id}.json"
    global_chunk = read_json(global_chunk_path, {}) or {}
    binding_hash = manifest["binding_sha256"]
    lease_sha256 = _lease_binding_hash(lease)
    local_chunk_path = root / "chunks" / f"{REMOTE_CHUNK_ID}.json"
    local_chunk = read_json(local_chunk_path, {}) or {}
    target_local = {**local_chunk, "state": "leased", "binding_sha256": binding_hash, "lease_sha256": lease_sha256}
    target_local["chunk_sha256"] = _chunk_binding_hash(target_local)
    target_global = {**global_chunk, "canary_id": canary_id, "canary_project_root": state_path(root), "remote_staging_root": manifest["remote_staging_root"], "remote_adapter_path": REMOTE_ADAPTER_PATH, "binding_sha256": binding_hash, "lease_sha256": lease_sha256, "cookies_used": False, "media_allowed": False}
    target_global["chunk_sha256"] = _chunk_binding_hash(target_global)
    target_manifest = {**manifest, "state": "prepared", "lease_sha256": lease_sha256, "chunk_sha256": target_local["chunk_sha256"], "prepared_at": manifest.get("prepared_at") or utcnow()}
    journal_path = root / "preparation.json"
    journal = read_json(journal_path, {}) or {}
    if journal and (journal.get("canary_id") != canary_id or journal.get("lease_id") != lease_id or journal.get("binding_sha256") != binding_hash):
        raise GP.PoolError("Windows preparation journal binding mismatch")
    if journal.get("state") == "committed":
        current = {
            "target_global_chunk": read_json(global_chunk_path, {}) or {},
            "target_local_chunk": read_json(local_chunk_path, {}) or {},
            "target_manifest": read_json(root / "manifest.json", {}) or {},
        }
        expected = {key: journal.get(key) for key in current}
        if current != expected:
            raise GP.PoolError("committed Windows preparation journal drifted")
        validate_prelaunch_bindings(canary_id, journal["target_manifest"])
        return {"schema": "franck.youtube-global-pool.windows-canary-prepare-result.v1", "state": "prepared", "canary_id": canary_id, "lease_id": lease_id, "video_ids": ids, "item_count": len(ids), "windows_enabled": manifest.get("windows_enabled") is True, "cookies_used": False, "media_files": 0}
    if not journal:
        journal = {"schema": "franck.youtube-global-pool.windows-canary-preparation-journal.v1", "state": "prepared", "prepared_at": utcnow(), "canary_id": canary_id, "lease_id": lease_id, "binding_sha256": binding_hash, "target_global_chunk": target_global, "target_local_chunk": target_local, "target_manifest": target_manifest}
        atomic_json(journal_path, journal)
    atomic_json(global_chunk_path, journal["target_global_chunk"])
    atomic_json(local_chunk_path, journal["target_local_chunk"])
    atomic_json(root / "manifest.json", journal["target_manifest"])
    if read_json(global_chunk_path, {}) != journal["target_global_chunk"] or read_json(local_chunk_path, {}) != journal["target_local_chunk"] or read_json(root / "manifest.json", {}) != journal["target_manifest"]:
        raise GP.PoolError("Windows preparation commit readback mismatch")
    journal["state"] = "committed"
    journal["committed_at"] = journal.get("committed_at") or utcnow()
    atomic_json(journal_path, journal)
    validate_prelaunch_bindings(canary_id, journal["target_manifest"])
    return {"schema": "franck.youtube-global-pool.windows-canary-prepare-result.v1", "state": "prepared", "canary_id": canary_id, "lease_id": lease_id, "video_ids": ids, "item_count": len(ids), "windows_enabled": manifest.get("windows_enabled") is True, "cookies_used": False, "media_files": 0}


def prepare_canary(
    canary_id: str,
    *,
    item_count: int = 1,
    selected_items: list[dict[str, Any]] | None = None,
    preflight: dict[str, Any] | None = None,
    run_kind: str = "windows_canary",
    windows_enabled: bool = False,
) -> dict[str, Any]:
    canary_id = validate_canary_id(canary_id)
    if not 1 <= int(item_count) <= MAX_CANARY_ITEMS:
        raise GP.PoolError("Windows canary item count must be 1..25")
    if run_kind not in {"windows_canary", "windows_production"}:
        raise GP.PoolError(f"unsupported Windows run kind: {run_kind}")
    if windows_enabled is not (run_kind == "windows_production"):
        raise GP.PoolError("Windows production enablement and run kind differ")
    root = canary_root(canary_id)
    existing = read_json(root / "manifest.json", {}) or {}
    if existing.get("state") in {"preparing", "prepare_failed_before_lease", "prepared"}:
        return resume_canary_preparation(canary_id, existing)
    if existing.get("state") in {"launching", "running", "returned", "importing", "completed", "partial", "blocked", "superseded_before_lease", "attention_required"}:
        return {"state": "already_prepared", "canary_id": canary_id, "manifest": existing}
    if root.exists():
        raise GP.PoolError("Windows canary directory exists without a replayable manifest")
    preflight = preflight or validate_host()
    node = preflight.get("node") if isinstance(preflight.get("node"), dict) else {}
    adapter = preflight.get("adapter") if isinstance(preflight.get("adapter"), dict) else {}
    if (
        preflight.get("state") != "passed"
        or node.get("display_name") != WINDOWS_NODE_LABEL
        or node.get("platform") != WINDOWS_PLATFORM
        or node.get("connected") is not True
        or node.get("node_id") != WINDOWS_CONFIG["node"]["id"]
        or preflight.get("cookies_used") is not False
        or preflight.get("media_files") != 0
        or adapter.get("readOnly") is not True
        or adapter.get("eligible") is not True
        or adapter.get("cookiesUsed") is not False
        or adapter.get("mediaFiles") != 0
    ):
        raise GP.PoolError("Windows canary preparation requires an exact passed host preflight")
    store = GP.PoolStore(POOL_ROOT)
    store.ensure_dirs()
    selected = selected_items or select_canary_items(store.load_items(), item_count=item_count)
    if len(selected) != int(item_count):
        raise GP.PoolError("Windows canary selection count differs from requested bound")
    ids = [GP.validate_video_id(str(item.get("video_id") or "")) for item in selected]
    if len(ids) != len(set(ids)):
        raise GP.PoolError("Windows canary selection contains duplicate IDs")
    lease_id = str(uuid.uuid4())
    created_at = utcnow()
    GP.ensure_directory_durable(root.parent)
    root.mkdir(exist_ok=False)
    GP.fsync_directory(root.parent)
    tsv = root / "chunks" / f"{REMOTE_CHUNK_ID}.tsv"
    GP.ensure_directory_durable(tsv.parent)
    GP.atomic_write(tsv, "".join(f"{video_id}\t{GP.canonical_url(video_id)}\n" for video_id in ids))
    urls_hash = sha256_file(tsv)
    binding = _binding_payload(canary_id, lease_id, ids, urls_hash, node)
    remote_root = remote_canary_root(canary_id)
    manifest = {
        "schema": "franck.youtube-global-pool.windows-canary-manifest.v1",
        "canary_id": canary_id,
        "run_kind": run_kind,
        "state": "preparing",
        "created_at": created_at,
        "global_chunk_id": canary_id,
        "local_chunk_id": REMOTE_CHUNK_ID,
        "remote_chunk_id": REMOTE_CHUNK_ID,
        "lease_id": lease_id,
        "remote_staging_root": remote_root,
        "remote_adapter_path": REMOTE_ADAPTER_PATH,
        "node": node,
        "video_ids": ids,
        "expected_item_count": len(ids),
        "worker_sha256": sha256_file(REMOTE_WORKER),
        "adapter_sha256": sha256_file(REMOTE_ADAPTER),
        "assets": WINDOWS_CONFIG["assets"],
        "urls_sha256": urls_hash,
        "binding_sha256": stable_hash(binding),
        "lane_counts": dict(sorted(__import__("collections").Counter(str(item.get("lane")) for item in selected).items())),
        "cookies_used": False,
        "media_files": 0,
        "automatic_remote_cleanup": False,
        "windows_enabled": windows_enabled,
        "preflight": preflight,
    }
    _write_preparation_files(root, canary_id, selected, manifest, created_at)
    atomic_json(root / "manifest.json", manifest)
    try:
        # Re-check after the durable preparing record exists so selection races
        # leave an explicit superseded marker instead of an invisible failure.
        _assert_selection_disjoint(store, selected)
        return resume_canary_preparation(canary_id, manifest)
    except SelectionConflictError:
        current = read_json(root / "manifest.json", {}) or {}
        if current.get("state") in {"preparing", "prepare_failed_before_lease"}:
            _set_state(root, "superseded_before_lease", reason="selection raced with another active lease")
        raise


def _set_state(root: Path, state: str, **changes: Any) -> None:
    now = utcnow()
    manifest = read_json(root / "manifest.json", {}) or {}
    enabled = manifest.get("windows_enabled") is True
    manifest.update({"state": state, "updated_at": now, **changes, "windows_enabled": enabled, "cookies_used": False, "media_files": 0})
    atomic_json(root / "manifest.json", manifest)
    queue = read_json(root / "queue" / "state.json", {}) or {}
    queue.update({"state": state, "updated_at": now, **changes, "windows_enabled": enabled, "cookies_used": False, "media_files": 0})
    atomic_json(root / "queue" / "state.json", queue)


def _strict_remote_binding(manifest: dict[str, Any], remote: dict[str, Any]) -> None:
    if remote.get("lease_id") != manifest.get("lease_id") or remote.get("chunk_id") != REMOTE_CHUNK_ID:
        raise GP.PoolError("Windows remote lease/chunk binding differs")
    staging = remote.get("staging") if isinstance(remote.get("staging"), dict) else {}
    expected = {"lease_id": manifest.get("lease_id"), "chunk_id": REMOTE_CHUNK_ID, "worker_sha256": manifest.get("worker_sha256"), "urls_sha256": manifest.get("urls_sha256"), "cookies_used": False, "media_files": 0}
    expected["assets"] = manifest.get("assets")
    for key, value in expected.items():
        if staging.get(key) != value:
            raise GP.PoolError(f"Windows remote staging binding differs for {key}")
    if remote.get("cookies_used") is not False or remote.get("media_downloaded") is not False:
        raise GP.PoolError("Windows remote worker violated anonymous caption-only policy")
    if not isinstance(remote.get("worker_alive"), bool):
        raise GP.PoolError("Windows remote worker liveness is unknown")


def _mark_global_running(canary_id: str, state: str, remote: dict[str, Any]) -> None:
    store = GP.PoolStore(POOL_ROOT)
    with store.coordinator_lock():
        manifest = read_json(canary_root(canary_id) / "manifest.json", {}) or {}
        lease_id = str(manifest.get("lease_id") or "")
        for video_id in manifest.get("video_ids") or []:
            item = store.load_item(str(video_id))
            if not item or item.get("active_lease_id") != lease_id:
                raise GP.PoolError(f"Windows global lease binding lost for {video_id}")
            item["status"] = "processing"
            item["updated_at"] = utcnow()
            store.save_item(item)
        chunk_path = store.chunks_dir / f"{canary_id}.json"
        chunk = read_json(chunk_path, {}) or {}
        chunk.update({"state": state, "remote_state": remote.get("state"), "worker_alive": remote.get("worker_alive"), "remote_counts": remote.get("counts") or {}, "cookies_used": False, "media_files": 0})
        atomic_json(chunk_path, chunk)
        store.append_event("windows_canary_launched", canary_id=canary_id, lease_id=lease_id, video_ids=manifest.get("video_ids"), cookies_used=False, media_files=0)
        store.write_state()


def launch_canary(canary_id: str) -> dict[str, Any]:
    canary_id = validate_canary_id(canary_id)
    root = canary_root(canary_id)
    manifest = read_json(root / "manifest.json", {}) or {}
    if manifest.get("state") in {"running", "returned", "completed", "partial", "blocked"}:
        return {"state": "already_launched", "canary_id": canary_id, "manifest": manifest}
    if manifest.get("state") not in {"prepared", "launching"}:
        raise GP.PoolError(f"Windows canary is not launchable: {manifest.get('state')}")
    validate_prelaunch_bindings(canary_id, manifest)
    staging_root = str(manifest["remote_staging_root"])
    _set_state(root, "launching", launch_intent_at=utcnow())
    probe = _invoke_adapter("Probe", staging_root=staging_root, lease_id=str(manifest["lease_id"]), timeout=300)
    if probe.get("exists"):
        _strict_remote_binding(manifest, probe)
        remote = probe
        # Existing staging is authoritative after an uncertain dispatch. An
        # unattended launch must never grant blocked/stopped-run recovery.
    else:
        worker = REMOTE_WORKER.read_bytes()
        urls = (root / "chunks" / f"{REMOTE_CHUNK_ID}.tsv").read_bytes()
        if sha256_bytes(worker) != manifest.get("worker_sha256") or sha256_bytes(urls) != manifest.get("urls_sha256"):
            raise GP.PoolError("Windows launch worker or URL hash drifted")
        # Keep the Windows process command line well below its platform limit.
        # The raw worker crossed that limit after terminal-state diagnostics
        # grew, while deterministic gzip remains small and is hash-checked
        # after decompression by the existing staging contract.
        worker_gzip = gzip.compress(worker, compresslevel=9, mtime=0)
        remote = _normalise_probe(_invoke_adapter(
            "StageLaunch",
            staging_root=staging_root,
            lease_id=str(manifest["lease_id"]),
            worker_gzip_b64=base64.b64encode(worker_gzip).decode("ascii"),
            urls_b64=base64.b64encode(urls).decode("ascii"),
            timeout=600,
        ))
    _strict_remote_binding(manifest, remote)
    state = "running" if remote.get("worker_alive") or remote.get("state") in {"running", "retry_wait"} else ("returned" if remote.get("state") in REMOTE_IMPORTABLE else "blocked" if remote.get("state") in REMOTE_BLOCKED else "attention_required")
    _set_state(
        root,
        state,
        launched_at=utcnow(),
        worker_pid=remote.get("pid"),
        remote_state=remote.get("state"),
        adapter_sha256=sha256_file(REMOTE_ADAPTER),
        remote_summary={"state": remote.get("state"), "worker_alive": remote.get("worker_alive"), "counts": remote.get("counts") or {}, "cookies_used": False, "media_files": 0},
    )
    if state in {"running", "returned", "blocked"}:
        _mark_global_running(canary_id, state, remote)
    return {"state": state, "canary_id": canary_id, "lease_id": manifest["lease_id"], "worker_pid": remote.get("pid"), "windows_enabled": manifest.get("windows_enabled") is True, "cookies_used": False, "media_files": 0}


def probe_canary(canary_id: str) -> dict[str, Any]:
    canary_id = validate_canary_id(canary_id)
    manifest = read_json(canary_root(canary_id) / "manifest.json", {}) or {}
    if manifest.get("canary_id") != canary_id:
        raise GP.PoolError("Windows canary manifest is missing")
    remote = _normalise_probe(_invoke_adapter("Probe", staging_root=str(manifest["remote_staging_root"]), lease_id=str(manifest.get("lease_id") or ""), timeout=300))
    if remote.get("exists"):
        _strict_remote_binding(manifest, remote)
    remote["windows_enabled"] = manifest.get("windows_enabled") is True
    remote["checkpoint_sha256"] = checkpoint_sha256(remote)
    return remote


def checkpoint_sha256(remote: dict[str, Any]) -> str:
    """Bind explicit recovery to persisted bytes; staging is fenced separately."""
    digest = remote.get("status_sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise GP.PoolError("Windows persisted checkpoint digest unavailable")
    return digest


def _recovery_time(value: str) -> dt.datetime:
    try:
        if not isinstance(value, str) or len(value) > 64:
            raise ValueError()
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() != dt.timedelta(0):
            raise ValueError()
        return parsed
    except (ValueError, OverflowError):
        raise GP.PoolError("Windows recovery timestamp is invalid") from None


def _recovery_now(now: dt.datetime | None) -> dt.datetime:
    value = now if now is not None else dt.datetime.now(dt.timezone.utc)
    if not isinstance(value, dt.datetime) or value.tzinfo is None:
        raise GP.PoolError("Windows recovery clock is invalid")
    return value.astimezone(dt.timezone.utc)


def _recovery_stamp(value: dt.datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _resume_binding(manifest: dict[str, Any]) -> dict[str, Any]:
    return {key: manifest.get(key) for key in ("canary_id", "lease_id", "binding_sha256", "worker_sha256", "adapter_sha256", "urls_sha256")}


def _existing_recovery_root(canary_id: str) -> Path:
    root = canary_root(canary_id)
    manifest = root / "manifest.json"
    if root.is_symlink() or not root.is_dir() or manifest.is_symlink() or not manifest.is_file():
        raise GP.PoolError("Windows recovery requires an existing canary manifest")
    return root


def _recovery_receipt_reader() -> Callable[[Path], bytes]:
    """Share the actual receipt-byte ceiling across one operation's rereads."""
    remaining = RECOVERY_MAX_TOTAL_BYTES
    def read(path: Path) -> bytes:
        nonlocal remaining
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= RECOVERY_MAX_RECEIPT_BYTES
            or info.st_size > remaining):
            raise GP.PoolError("Windows recovery receipt operation exceeds its byte contract")
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError:
            raise GP.PoolError("Windows recovery receipt cannot be opened safely") from None
        with os.fdopen(fd, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns):
                raise GP.PoolError("Windows recovery receipt changed during admission")
            raw = handle.read(info.st_size)
            after = os.fstat(handle.fileno())
            remaining -= len(raw)
            if len(raw) != info.st_size or (after.st_size, after.st_mtime_ns) != (info.st_size, info.st_mtime_ns):
                raise GP.PoolError("Windows recovery receipt changed during read")
        return raw
    return read


def resume_request_inventory(root: Path, manifest: dict[str, Any], *,
                             read_raw: Callable[[Path], bytes] | None = None) -> dict[str, dict]:
    """One bounded external-tool receipt owner; never probes or changes state."""
    read_raw = read_raw or _recovery_receipt_reader()
    directory = root / "resume-requests"
    if any(path.is_symlink() for path in (root, directory)):
        raise GP.PoolError("Windows recovery receipt path is redirected")
    if not directory.exists():
        return {}
    if not directory.is_dir():
        raise GP.PoolError("Windows recovery receipt directory is invalid")
    result = {}
    total = 0
    consumed_ordinals = set()
    with os.scandir(directory) as entries:
        for entry in entries:
            if len(result) >= RECOVERY_MAX_RECEIPTS or not re.fullmatch(r"[0-9a-f]{64}\.json", entry.name):
                raise GP.PoolError("Windows recovery receipt inventory exceeds its contract")
            info = entry.stat(follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= RECOVERY_MAX_RECEIPT_BYTES
                or info.st_size > RECOVERY_MAX_TOTAL_BYTES - total):
                raise GP.PoolError("Windows recovery receipt exceeds its byte contract")
            raw = read_raw(Path(entry.path))
            total += len(raw)
            if not isinstance(raw, bytes) or len(raw) != info.st_size or len(raw) > RECOVERY_MAX_RECEIPT_BYTES or total > RECOVERY_MAX_TOTAL_BYTES:
                raise GP.PoolError("Windows recovery receipt inventory changed or exceeds its byte contract")
            try:
                row = json.loads(raw)
            except (ValueError, UnicodeError):
                raise GP.PoolError("Windows recovery request receipt is corrupt or mismatched") from None
            digest = entry.name[:-5]
            if (not isinstance(row, dict) or row.get("binding") != _resume_binding(manifest)
                or row.get("checkpoint_sha256") != digest
                or row.get("schema") not in {"openclaw.youtube.windows-resume.v1", RESUME_SCHEMA}):
                raise GP.PoolError("Windows recovery request receipt is corrupt or mismatched")
            created = _recovery_time(row.get("created_at"))
            if row["schema"].endswith(".v1"):
                if row.get("state") not in RECOVERY_DISPATCHED:
                    raise GP.PoolError("Windows legacy recovery receipt state is invalid")
            else:
                approved = _recovery_time(row.get("approved_at"))
                occurrence = _recovery_time(row.get("occurrence_at"))
                due = _recovery_time(row.get("due_at"))
                expires = _recovery_time(row.get("grant_expires_at"))
                ordinal = row.get("recovery_ordinal")
                if (row.get("policy_version") != RECOVERY_POLICY or row.get("state") not in RECOVERY_STATES
                    or type(ordinal) is not int or ordinal not in {1, 2}
                    or row.get("occurrence_checkpoint_sha256") != digest
                    or not re.fullmatch(r"[A-Za-z0-9_-]{11}", str(row.get("failed_video_id")))
                    or type(row.get("failed_video_attempt")) is not int or not 1 <= row["failed_video_attempt"] < 3
                    or not isinstance(row.get("approval_reference"), str)
                    or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}", row["approval_reference"])
                    or created != approved or occurrence > approved
                    or expires != approved + dt.timedelta(seconds=RECOVERY_HORIZON)
                    or not occurrence + dt.timedelta(seconds=RECOVERY_WAITS[ordinal - 1]) <= due <= occurrence + dt.timedelta(seconds=RECOVERY_HORIZON)
                    or due >= expires):
                    raise GP.PoolError("Windows bounded recovery receipt is corrupt or mismatched")
                if row["state"] in RECOVERY_DISPATCHED:
                    if ordinal in consumed_ordinals:
                        raise GP.PoolError("Windows recovery ordinal was consumed more than once")
                    consumed_ordinals.add(ordinal)
                    dispatched = _recovery_time(row.get("dispatched_at"))
                    if not max(approved, due) <= dispatched < expires:
                        raise GP.PoolError("Windows recovery dispatch chronology is invalid")
            result[digest] = row
    if sum(row["state"] == "armed" for row in result.values()) > 1:
        raise GP.PoolError("Windows run has competing recovery grants")
    return result


def _rate_occurrence(manifest: dict, remote: dict, now: dt.datetime) -> tuple[str, int, dt.datetime]:
    if (remote.get("state") != "waiting_network_cooldown" or remote.get("circuit_open") is not True
        or remote.get("circuit_reason") != "rate_limited"):
        raise GP.PoolError("Windows checkpoint is not an eligible rate-limit circuit")
    items = remote.get("items")
    ids = manifest.get("video_ids")
    if not isinstance(items, dict) or not isinstance(ids, list) or set(items) != set(ids):
        raise GP.PoolError("Windows recovery attempt map differs from the requested items")
    allowed_states = {"archived", "pending", "running", "retry_wait", "blocked_error", "blocked_configuration",
        "blocked_interrupted", "blocked_bot_check", "blocked_auth_required", "waiting_network_cooldown",
        "skipped_private", "skipped_age_restricted", "skipped_unavailable"}
    for video, item in items.items():
        if (not isinstance(item, dict) or item.get("video_id") != video or item.get("url") != GP.canonical_url(video)
            or type(item.get("attempts")) is not int or not 0 <= item["attempts"] <= 3
            or item.get("state") not in allowed_states
            or (item.get("process_exit_code") is not None and type(item["process_exit_code"]) is not int)):
            raise GP.PoolError("Windows recovery attempt map is invalid")
        if item.get("failure_class") == "rate_limited" and item["attempts"] >= 3:
            raise GP.PoolError("Windows rate-limited item exhausted its attempt budget; manual hold")
    video = remote.get("current_video_id")
    item = items.get(video)
    if (not isinstance(item, dict) or item.get("state") != "waiting_network_cooldown"
        or item.get("failure_class") != "rate_limited" or not 1 <= item["attempts"] < 3):
        raise GP.PoolError("Windows recovery failed-video occurrence is invalid")
    occurrence = _recovery_time(remote.get("updated_at"))
    if occurrence > now:
        raise GP.PoolError("Windows rate-limit occurrence is in the future")
    return video, item["attempts"], occurrence


def _verify_recovery_sources() -> None:
    from youtube_windows_deployment import verify_managed_sources
    verify_managed_sources(WORKSPACE, WINDOWS_CONFIG, loaded_canary_sha256=_LOADED_CANARY_SHA256)


def _recovery_probe(canary_id: str, manifest: dict, digest: str) -> dict:
    validate_prelaunch_bindings(canary_id, manifest)
    node = windows_node_status()
    if node["nodeId"] != (manifest.get("node") or {}).get("node_id"):
        raise GP.PoolError("Windows recovery node differs from active lease")
    remote = probe_canary(canary_id)
    if remote.get("exists") is not True:
        raise GP.PoolError("Windows recovery requires existing staging")
    _strict_remote_binding(manifest, remote)
    if checkpoint_sha256(remote) != digest:
        raise GP.PoolError("Windows recovery checkpoint changed; obtain fresh proof")
    if remote.get("worker_alive") is not False or remote.get("worker_lock_free") is not True:
        raise RecoveryNotReady("Windows recovery requires a stopped worker and a proven free OS lock")
    return remote


def _arm_rate_locked(canary_id: str, manifest: dict, digest: str, approval_reference: str,
                     retry_after_at: str | None, now: dt.datetime | None, inventory: dict, remote: dict) -> dict:
    current = _recovery_now(now)
    if not isinstance(approval_reference, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}", approval_reference):
        raise GP.PoolError("Windows rate recovery requires a bounded explicit approval reference")
    previous = inventory.get(digest)
    if previous:
        if previous.get("approval_reference") != approval_reference:
            raise GP.PoolError("Windows checkpoint already has a recovery request; observe it")
        return previous
    if any(row.get("approval_reference") == approval_reference or row["state"] == "armed" for row in inventory.values()):
        raise GP.PoolError("Windows recovery needs a separate approval and no competing grant")
    consumed = [row for row in inventory.values() if row["state"] in RECOVERY_DISPATCHED]
    if len(consumed) >= len(RECOVERY_WAITS):
        raise GP.PoolError("Windows run exhausted its recovery dispatch budget; manual hold")
    video, attempt, occurrence = _rate_occurrence(manifest, remote, current)
    if consumed:
        last = max(consumed, key=lambda row: _recovery_time(row.get("dispatched_at", row["created_at"])))
        last_dispatch = _recovery_time(last.get("dispatched_at", last["created_at"]))
        if (last["checkpoint_sha256"] == digest or occurrence <= last_dispatch
            or (last.get("failed_video_id") == video and attempt <= last["failed_video_attempt"])):
            raise GP.PoolError("Windows second recovery requires a proven new rate-limit occurrence")
    ordinal = len(consumed) + 1
    due = occurrence + dt.timedelta(seconds=RECOVERY_WAITS[ordinal - 1])
    if retry_after_at is not None:
        due = max(due, _recovery_time(retry_after_at))
    expires = current + dt.timedelta(seconds=RECOVERY_HORIZON)
    if due > occurrence + dt.timedelta(seconds=RECOVERY_HORIZON) or due >= expires:
        raise GP.PoolError("Windows recovery wait exceeds the finite planning horizon; manual hold")
    request = {"schema": RESUME_SCHEMA, "policy_version": RECOVERY_POLICY, "binding": _resume_binding(manifest),
        "checkpoint_sha256": digest, "occurrence_checkpoint_sha256": digest, "occurrence_at": _recovery_stamp(occurrence),
        "failed_video_id": video, "failed_video_attempt": attempt, "recovery_ordinal": ordinal,
        "due_at": _recovery_stamp(due), "approved_at": _recovery_stamp(current), "created_at": _recovery_stamp(current),
        "grant_expires_at": _recovery_stamp(expires), "approval_reference": approval_reference, "state": "armed"}
    # Readiness is awaited before this write. Recheck authoritative ownership now.
    validate_prelaunch_bindings(canary_id, manifest)
    atomic_json(canary_root(canary_id) / "resume-requests" / (digest + ".json"), request)
    return request


def arm_rate_recovery(canary_id: str, *, expected_checkpoint_sha256: str, approval_reference: str,
                      retry_after_at: str | None = None, now: dt.datetime | None = None) -> dict[str, Any]:
    canary_id = validate_canary_id(canary_id)
    root = _existing_recovery_root(canary_id)
    if not isinstance(expected_checkpoint_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_checkpoint_sha256):
        raise GP.PoolError("explicit recovery requires a fresh checkpoint digest")
    with GP.FileLock(root / "reconcile.lock", blocking=False), GP.PoolStore(POOL_ROOT).coordinator_lock(blocking=False):
        manifest = read_json(root / "manifest.json", {}) or {}
        if manifest.get("state") != "blocked":
            raise GP.PoolError("Windows rate recovery requires an existing blocked run")
        inventory = resume_request_inventory(root, manifest)
        _verify_recovery_sources()
        remote = _recovery_probe(canary_id, manifest, expected_checkpoint_sha256)
        request = _arm_rate_locked(canary_id, manifest, expected_checkpoint_sha256, approval_reference, retry_after_at, now, inventory, remote)
        return {"state": "recovery_armed" if request["state"] == "armed" else "already_requested", "canary_id": canary_id,
                "request_state": request["state"], "due_at": request.get("due_at"), "grant_expires_at": request.get("grant_expires_at")}


def _resume_canary_locked(canary_id: str, manifest: dict, digest: str, *,
                          approval_reference: str | None = None, retry_after_at: str | None = None,
                          now: dt.datetime | None = None, read_raw: Callable[[Path], bytes] | None = None) -> dict[str, Any]:
    read_raw = read_raw or _recovery_receipt_reader()
    root = canary_root(canary_id)
    if manifest.get("state") in {"completed", "partial"}:
        return {"state": manifest["state"], "canary_id": canary_id, "already_final": True}
    if manifest.get("state") not in {"launching", "running", "returned", "blocked", "attention_required"}:
        raise GP.PoolError("Windows canary is not resumable")
    validate_prelaunch_bindings(canary_id, manifest)
    inventory = resume_request_inventory(root, manifest, read_raw=read_raw)
    previous = inventory.get(digest)
    if previous and previous["state"] in RECOVERY_DISPATCHED:
        return {"state": "already_requested", "canary_id": canary_id, "request_state": previous["state"], "observe_before_recovery": True}
    request_path = root / "resume-requests" / (digest + ".json")
    if previous:
        if previous["state"] != "armed":
            return {"state": "recovery_held", "canary_id": canary_id, "request_state": previous["state"]}
        current = _recovery_now(now)
        if current >= _recovery_time(previous["grant_expires_at"]):
            atomic_json(request_path, {**previous, "state": "expired", "updated_at": _recovery_stamp(current)})
            return {"state": "recovery_expired", "canary_id": canary_id}
        if current < _recovery_time(previous["due_at"]):
            return {"state": "recovery_waiting", "canary_id": canary_id, "due_at": previous["due_at"]}
    remote = _recovery_probe(canary_id, manifest, digest)
    if remote.get("state") in REMOTE_IMPORTABLE:
        return {"state": "returned", "canary_id": canary_id, "reconcile_required": True}
    if remote.get("state") not in REMOTE_BLOCKED | {"running", "retry_wait"}:
        raise GP.PoolError("Windows recovery checkpoint state is not recoverable")
    if remote.get("state") == "waiting_network_cooldown" or remote.get("circuit_reason") == "rate_limited" or previous:
        _verify_recovery_sources()
        if previous is None:
            if approval_reference is None:
                raise GP.PoolError("Windows rate recovery requires an explicit approved grant")
            previous = _arm_rate_locked(canary_id, manifest, digest, approval_reference, retry_after_at, now, inventory, remote)
        video, attempt, occurrence = _rate_occurrence(manifest, remote, _recovery_now(now))
        if (video, attempt, _recovery_stamp(occurrence)) != (previous["failed_video_id"], previous["failed_video_attempt"], previous["occurrence_at"]):
            raise GP.PoolError("Windows recovery occurrence changed")
        current = _recovery_now(now)
        if current >= _recovery_time(previous["grant_expires_at"]):
            atomic_json(request_path, {**previous, "state": "expired", "updated_at": _recovery_stamp(current)})
            return {"state": "recovery_expired", "canary_id": canary_id}
        if current < _recovery_time(previous["due_at"]):
            return {"state": "recovery_waiting", "canary_id": canary_id, "due_at": previous["due_at"]}
        request = {**previous, "state": "intent", "dispatched_at": _recovery_stamp(current)}
    else:
        request = {"schema": "openclaw.youtube.windows-resume.v1", "binding": _resume_binding(manifest), "checkpoint_sha256": digest, "state": "intent", "created_at": utcnow()}
    # The held locks serialize all receipt writers. Re-read the live authority and
    # run budget after awaited readiness, immediately before intent/RPC.
    validate_prelaunch_bindings(canary_id, manifest)
    windows_node_status()
    refreshed = resume_request_inventory(root, manifest, read_raw=read_raw)
    if sum(row["state"] in RECOVERY_DISPATCHED for row in refreshed.values()) >= len(RECOVERY_WAITS):
        raise GP.PoolError("Windows run exhausted its recovery dispatch budget; manual hold")
    if previous:
        if refreshed.get(digest) != previous:
            raise GP.PoolError("Windows recovery grant changed before dispatch")
        _verify_recovery_sources()
    validate_prelaunch_bindings(canary_id, manifest)
    if previous:
        current = _recovery_now(now)
        if current >= _recovery_time(previous["grant_expires_at"]):
            atomic_json(request_path, {**previous, "state": "expired", "updated_at": _recovery_stamp(current)})
            return {"state": "recovery_expired", "canary_id": canary_id}
        if current < _recovery_time(previous["due_at"]):
            return {"state": "recovery_waiting", "canary_id": canary_id, "reason": "grant_not_current"}
        request["dispatched_at"] = _recovery_stamp(current)
    atomic_json(request_path, request)
    try:
        reply = _normalise_probe(_invoke_adapter("Resume", staging_root=str(manifest["remote_staging_root"]), lease_id=str(manifest["lease_id"]), checkpoint_sha256=digest, timeout=300, verify_host=False))
        _strict_remote_binding(manifest, reply)
    except Exception:
        atomic_json(request_path, {**request, "state": "uncertain", "updated_at": utcnow()})
        raise GP.PoolError("Windows recovery dispatch outcome uncertain; observe/reconcile before another explicit request") from None
    state = "running" if reply.get("worker_alive") else ("returned" if reply.get("state") in REMOTE_IMPORTABLE else "blocked" if reply.get("state") in REMOTE_BLOCKED else "attention_required")
    atomic_json(request_path, {**request, "state": "acknowledged", "updated_at": utcnow(), "remote_summary": remote_summary(reply)})
    _set_state(root, state, resumed_at=utcnow(), worker_pid=reply.get("pid"), remote_state=reply.get("state"))
    return {"state": state, "canary_id": canary_id, "lease_id": manifest["lease_id"], "cookies_used": False, "media_files": 0}


def resume_canary(canary_id: str, *, expected_checkpoint_sha256: str, approval_reference: str | None = None,
                  retry_after_at: str | None = None) -> dict[str, Any]:
    canary_id = validate_canary_id(canary_id)
    if not isinstance(expected_checkpoint_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_checkpoint_sha256):
        raise GP.PoolError("explicit recovery requires a fresh checkpoint digest")
    root = _existing_recovery_root(canary_id)
    with GP.FileLock(root / "reconcile.lock", blocking=False), GP.PoolStore(POOL_ROOT).coordinator_lock(blocking=False):
        manifest = read_json(root / "manifest.json", {}) or {}
        return _resume_canary_locked(canary_id, manifest, expected_checkpoint_sha256,
                                    approval_reference=approval_reference, retry_after_at=retry_after_at)


def continue_rate_recovery(canary_id: str, *, now: dt.datetime | None = None) -> dict[str, Any]:
    """Scheduled observation can consume only an explicitly armed one-RPC grant."""
    canary_id = validate_canary_id(canary_id)
    root = _existing_recovery_root(canary_id)
    read_raw = _recovery_receipt_reader()
    with GP.FileLock(root / "reconcile.lock", blocking=False), GP.PoolStore(POOL_ROOT).coordinator_lock(blocking=False):
        manifest = read_json(root / "manifest.json", {}) or {}
        inventory = resume_request_inventory(root, manifest, read_raw=read_raw)
        armed = [(digest, row) for digest, row in inventory.items() if row["state"] == "armed"]
        if not armed:
            return {"state": "recovery_unarmed", "canary_id": canary_id}
        digest, request = armed[0]
        try:
            return _resume_canary_locked(canary_id, manifest, digest, now=now, read_raw=read_raw)
        except _transient_node_errors():
            return {"state": "recovery_waiting", "canary_id": canary_id, "reason": "node_unavailable"}
        except RecoveryNotReady:
            return {"state": "recovery_waiting", "canary_id": canary_id, "reason": "worker_or_lock_busy"}
        except GP.PoolError:
            # An adapter exception can happen after durable intent. Never turn
            # that consumed slot back into an undispatched grant or hold.
            current = resume_request_inventory(root, manifest, read_raw=read_raw).get(digest)
            if current and current["state"] in RECOVERY_DISPATCHED:
                raise
            atomic_json(root / "resume-requests" / (digest + ".json"), {**request, "state": "held", "updated_at": _recovery_stamp(_recovery_now(now)), "hold_reason": "readiness_or_occurrence_refused"})
            return {"state": "recovery_held", "canary_id": canary_id, "reason": "readiness_or_occurrence_refused"}



def cancel_rate_recovery(canary_id: str, *, expected_checkpoint_sha256: str) -> dict[str, Any]:
    """Revoke only an undispatched grant; retain every receipt and run binding."""
    canary_id = validate_canary_id(canary_id)
    root = _existing_recovery_root(canary_id)
    with GP.FileLock(root / "reconcile.lock", blocking=False), GP.PoolStore(POOL_ROOT).coordinator_lock(blocking=False):
        manifest = read_json(root / "manifest.json", {}) or {}
        request = resume_request_inventory(root, manifest).get(expected_checkpoint_sha256)
        if not request:
            return {"state": "recovery_unarmed", "canary_id": canary_id}
        if request["state"] in RECOVERY_DISPATCHED:
            return {"state": "already_requested", "canary_id": canary_id, "observe_before_recovery": True}
        if request["state"] == "armed":
            atomic_json(root / "resume-requests" / (expected_checkpoint_sha256 + ".json"),
                        {**request, "state": "held", "hold_reason": "operator_cancelled", "updated_at": utcnow()})
        return {"state": "recovery_held", "canary_id": canary_id}


def package_canary(canary_id: str) -> dict[str, Any]:
    canary_id = validate_canary_id(canary_id)
    manifest = read_json(canary_root(canary_id) / "manifest.json", {}) or {}
    validate_prelaunch_bindings(canary_id, manifest)
    staging_root = str(manifest["remote_staging_root"])
    probe = _normalise_probe(_invoke_adapter("Probe", staging_root=staging_root, lease_id=str(manifest["lease_id"]), timeout=300))
    if not probe.get("exists"):
        raise GP.PoolError("Windows package requires existing remote staging")
    _strict_remote_binding(manifest, probe)
    package = _invoke_adapter("Package", staging_root=staging_root, lease_id=str(manifest["lease_id"]), timeout=900)
    if package.get("chunk_id") != REMOTE_CHUNK_ID or package.get("lease_id") != manifest.get("lease_id"):
        raise GP.PoolError("Windows package lease/chunk binding differs")
    if package.get("cookies_used") is not False or package.get("media_files") != 0:
        raise GP.PoolError("Windows package violates anonymous caption-only policy")
    path = _normalise_remote_path(str(package.get("path") or ""))
    expected = _expected_remote_bundle_path(str(manifest["lease_id"]), staging_root)
    if path.casefold() != expected.casefold():
        raise GP.PoolError("Windows package path escaped the expected exports directory")
    digest = str(package.get("sha256") or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", digest) or int(package.get("size") or 0) <= 0 or int(package.get("size")) > FILE_FETCH_MAX_BYTES:
        raise GP.PoolError("Windows package receipt has an invalid hash or bounded size")
    package["windows_enabled"] = manifest.get("windows_enabled") is True
    current_adapter_hash = sha256_file(REMOTE_ADAPTER)
    if manifest.get("adapter_sha256") != current_adapter_hash:
        package["adapter_hotfix"] = {
            "previous_adapter_sha256": manifest.get("adapter_sha256"),
            "package_adapter_sha256": current_adapter_hash,
            "recorded_at": utcnow(),
        }
    return package


def _normalise_remote_path(value: str) -> str:
    return str(PureWindowsPath(value.replace("/", "\\")))


def _expected_remote_bundle_path(lease_id: str, staging_root: str = REMOTE_PARENT) -> str:
    return _normalise_remote_path(staging_root + rf"\chunk-{REMOTE_CHUNK_ID}\exports\validated-archive-bundle-{lease_id}.tar.gz")


def _remote_bundle_binding(remote_path: str) -> tuple[str, str]:
    path = PureWindowsPath(_normalise_remote_path(remote_path))
    match = re.fullmatch(r"validated-archive-bundle-([0-9a-fA-F-]{36})\.tar\.gz", path.name)
    if not match or path.parent.name.casefold() != "exports" or path.parents[1].name.casefold() != f"chunk-{REMOTE_CHUNK_ID}".casefold():
        raise GP.PoolError("Windows transfer path is not a validated bundle")
    try:
        lease_id = str(uuid.UUID(match.group(1)))
    except ValueError as exc:
        raise GP.PoolError("Windows transfer bundle lease id is invalid") from exc
    staging_root = str(path.parents[2])
    if str(path.parents[3]).casefold() != str(PureWindowsPath(REMOTE_PARENT) / "canaries").casefold():
        raise GP.PoolError("Windows transfer staging root escaped the canary directory")
    validate_canary_id(path.parents[2].name)
    return staging_root, lease_id


def _durable_transfer_paths(local: Path) -> tuple[Path, Path]:
    return local.with_name(local.name + ".part"), local.with_name(local.name + ".part.json")


def _fetch_remote_file(remote_path: str, expected_size: int) -> tuple[bytes, dict[str, Any]]:
    """Fetch one verified bundle through the native file-transfer node command."""
    if expected_size < 1 or expected_size > FILE_FETCH_MAX_BYTES:
        raise GP.PoolError("Windows bundle exceeds the native file-transfer size bound")
    config = windows_config()
    node = windows_node_status(config)
    commands = node.get("commands") if isinstance(node.get("commands"), list) else []
    if "file.fetch" not in commands:
        raise GP.PoolError("Windows node does not advertise the native file.fetch command")
    request_id = f"youtube-windows-file-fetch-{uuid.uuid4()}"
    params = {
        "nodeId": node["nodeId"],
        "command": "file.fetch",
        "params": {"path": remote_path, "maxBytes": FILE_FETCH_MAX_BYTES},
        "idempotencyKey": request_id,
    }

    completed = _retry_transient_node_call(
        lambda: YC.run_command(
            [
                "openclaw", "gateway", "call", "node.invoke", "--json",
                "--timeout", str(FILE_FETCH_TIMEOUT_SECONDS * 1000),
                "--params", json.dumps(params, ensure_ascii=False, separators=(",", ":")),
            ],
            timeout=FILE_FETCH_TIMEOUT_SECONDS + 30,
            operation="fetch verified Windows archive bundle",
        )
    )
    try:
        response = json.loads(completed.stdout)
    except Exception as exc:
        raise GP.PoolError("Windows native file transfer returned invalid JSON") from exc
    payload = response.get("payload") if isinstance(response, dict) else None
    if not isinstance(payload, dict) or payload.get("ok") is not True:
        code = payload.get("code") if isinstance(payload, dict) else None
        suffix = f" ({code})" if isinstance(code, str) and code else ""
        raise GP.PoolError(f"Windows native file transfer failed{suffix}")
    canonical_path = str(payload.get("path") or "")
    if _normalise_remote_path(canonical_path).casefold() != _normalise_remote_path(remote_path).casefold():
        raise GP.PoolError("Windows native file transfer canonical path differs")
    if int(payload.get("size") or -1) != expected_size:
        raise GP.PoolError("Windows native file transfer size differs")
    encoded = payload.get("base64")
    if not isinstance(encoded, str):
        raise GP.PoolError("Windows native file transfer omitted bundle bytes")
    try:
        data = base64.b64decode(encoded, validate=True)
    except Exception as exc:
        raise GP.PoolError("Windows native file transfer returned invalid base64") from exc
    if len(data) != expected_size:
        raise GP.PoolError("Windows native file transfer decoded size differs")
    actual_sha = hashlib.sha256(data).hexdigest()
    remote_sha = str(payload.get("sha256") or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", remote_sha) or remote_sha != actual_sha:
        raise GP.PoolError("Windows native file transfer integrity check failed")
    return data, {
        "node_id": node["nodeId"],
        "canonical_path": canonical_path,
        "sha256": remote_sha,
        "size": expected_size,
        "filesystem_identity_bound": True,
    }


def _transfer_bundle(canary_id: str, package: dict[str, Any]) -> tuple[Path, dict[str, Any]]:
    root = canary_root(canary_id)
    manifest = read_json(root / "manifest.json", {}) or {}
    remote_path = _normalise_remote_path(str(package["path"]))
    expected_path = _expected_remote_bundle_path(str(manifest["lease_id"]), str(manifest["remote_staging_root"]))
    if remote_path.casefold() != expected_path.casefold():
        raise GP.PoolError("Windows transfer path binding differs")
    expected_sha = str(package.get("sha256") or "").lower()
    expected_size = int(package.get("size") or -1)
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
        raise GP.PoolError("Windows package receipt has an invalid bundle hash")
    if expected_size < 1 or expected_size > FILE_FETCH_MAX_BYTES:
        raise GP.PoolError("Windows bundle exceeds the native file-transfer size bound")
    destination = root / "bundles" / f"chunk-{REMOTE_CHUNK_ID}"
    GP.ensure_directory_durable(destination)
    if destination.is_symlink() or not destination.resolve().is_relative_to(root.resolve()):
        raise GP.PoolError("Windows bundle destination escaped the canary root")
    receipt_path = destination / "receipt.json"
    receipt = read_json(receipt_path, {}) or {}
    local = root / str(receipt.get("local_bundle") or "")
    if not (receipt.get("lease_id") == manifest["lease_id"] and receipt.get("sha256") == expected_sha and receipt.get("size") == expected_size and local.is_file() and local.resolve().is_relative_to(destination.resolve()) and local.stat().st_size == expected_size and sha256_file(local) == expected_sha):
        local = destination / f"validated-archive-bundle-{manifest['lease_id']}.tar.gz"
        transfer_started_at = utcnow()
        data, remote_receipt = _fetch_remote_file(remote_path, expected_size)
        actual_sha = hashlib.sha256(data).hexdigest()
        if len(data) != expected_size or actual_sha != expected_sha or remote_receipt["sha256"] != expected_sha:
            part, meta_path = _durable_transfer_paths(local)
            part.unlink(missing_ok=True)
            meta_path.unlink(missing_ok=True)
            raise GP.PoolError("local Windows bundle hash or size verification failed")
        part, meta_path = _durable_transfer_paths(local)
        if part.is_symlink() or meta_path.is_symlink():
            raise GP.PoolError("Windows bundle transfer part path is unsafe")
        meta_path.unlink(missing_ok=True)
        with part.open("wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(part, local)
        with local.open("rb") as handle:
            os.fsync(handle.fileno())
        directory_fd = os.open(destination, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        receipt = {
            "schema": "franck.youtube-global-pool.windows-canary-bundle-receipt.v1",
            "recorded_at": utcnow(),
            "canary_id": canary_id,
            "lease_id": manifest["lease_id"],
            "remote_bundle": remote_path,
            "local_bundle": str(local.relative_to(root)),
            "sha256": expected_sha,
            "size": expected_size,
            "cookies_used": False,
            "media_files": 0,
            "transfer": "native_file_fetch_v1",
            "transfer_command": "file.fetch",
            "transfer_chunks": 1,
            "transfer_bytes": len(data),
            "transfer_max_bytes": FILE_FETCH_MAX_BYTES,
            "rpc_count": 1,
            "resumed_from_offset": 0,
            "host_verified_once": True,
            "filesystem_identity_bound": remote_receipt["filesystem_identity_bound"],
            "node_id": remote_receipt["node_id"],
            "transfer_started_at": transfer_started_at,
            "transfer_finished_at": utcnow(),
        }
        atomic_json(receipt_path, receipt)
    return local, receipt


def transfer_and_import(canary_id: str, remote: dict[str, Any] | None = None) -> dict[str, Any]:
    canary_id = validate_canary_id(canary_id)
    root = canary_root(canary_id)
    manifest = read_json(root / "manifest.json", {}) or {}
    package = package_canary(canary_id)
    local_bundle, receipt = _transfer_bundle(canary_id, package)
    _set_state(root, "importing", bundle_receipt=str((root / "bundles" / f"chunk-{REMOTE_CHUNK_ID}" / "receipt.json").relative_to(root)))
    store = GP.PoolStore(POOL_ROOT)
    remote = remote or probe_canary(canary_id)
    if remote.get("items") is None and isinstance(remote.get("status"), dict):
        remote = _normalise_probe(remote)
    with store.import_lock(blocking=False):
        evidence = read_json(root / "imports" / f"chunk-{REMOTE_CHUNK_ID}.json", {}) or {}
        if evidence.get("bundle_sha256") == package.get("sha256") and evidence.get("validated") is True:
            imported = {"state": "already_imported", "bundle_sha256": package["sha256"]}
        else:
            completed = YC.run_command([
                sys.executable, str(YC_CODE_ROOT / "import_chunk_bundle.py"),
                "--bundle", str(local_bundle), "--expected-sha256", str(package["sha256"]),
                "--project-root", str(root), "--archive-root", str(ARCHIVE_ROOT), "--chunk-id", REMOTE_CHUNK_ID,
            ], timeout=900, operation=f"import Windows canary {canary_id}")
            imported = YC.parse_json_output(completed.stdout)
            evidence = read_json(root / "imports" / f"chunk-{REMOTE_CHUNK_ID}.json", {}) or {}
        if evidence.get("bundle_sha256") != package.get("sha256") or evidence.get("validated") is not True:
            raise GP.PoolError("Windows canary import evidence is absent or not bundle-bound")
    with STORAGE.writer_lock(STORAGE.DEFAULT_STATE_ROOT):
        LC.persist_catalog_outcomes(canary_id, evidence, YC_ROOT)
        catalog = YC.run_command([
            sys.executable, str(YC_CODE_ROOT / "build_catalog.py"),
            "--project-root", str(YC_ROOT),
            "--archive-root", str(ARCHIVE_ROOT),
            "--state-root", str(STORAGE.DEFAULT_STATE_ROOT),
            "--projection-root", str(STORAGE.DEFAULT_PROJECTION_ROOT),
            "--writer-lock-held",
            "--chunk-size", "25",
        ], timeout=300, operation=f"refresh central projection after Windows canary {canary_id}")
        catalog_payload = YC.parse_json_output(catalog.stdout)
        STORAGE.sync_projection_locked(
            ARCHIVE_ROOT,
            STORAGE.DEFAULT_PROJECTION_ROOT,
            STORAGE.DEFAULT_MANIFEST_PATH,
            STORAGE.DEFAULT_LOCK_PATH,
            prune=False,
        )
        personal = LC.update_personal_source_projection(canary_id, evidence, utcnow())
        projection = {"schema": "franck.youtube-global-pool.windows-canary-source-projection.v1", "canary_id": canary_id, "bundle_sha256": package["sha256"], "updated_at": utcnow(), "yc_catalog": catalog_payload, "personal_queue": personal}
        atomic_json(root / "source-projection.json", projection)
        LC.finalize_global_import(canary_id, evidence, remote, root_override=root)
    return {"bundle": package, "receipt": receipt, "import": imported, "import_evidence": evidence, "source_projection": projection}


copy_and_import = transfer_and_import


def reconcile_canary(canary_id: str) -> dict[str, Any]:
    canary_id = validate_canary_id(canary_id)
    root = canary_root(canary_id)
    with GP.FileLock(root / "reconcile.lock", blocking=False):
        manifest = read_json(root / "manifest.json", {}) or {}
        if manifest.get("state") in {"completed", "partial"}:
            queue = read_json(root / "queue/state.json", {}) or {}
            if queue.get("state") == manifest.get("state") and queue.get("bundle_sha256") == manifest.get("bundle_sha256") and queue.get("worker_alive") is False:
                return {"state": manifest["state"], "canary_id": canary_id, "already_final": True}
        journal = read_json(root / "finalization.json")
        if journal is not None:
            # A crash can happen after the ordinary lease completion write but
            # before journal/manifest closeout. Replay already-validated local
            # receipts without demanding an active lease or re-packaging.
            _manifest_and_files_valid(canary_id, manifest)
            evidence = read_json(root / "imports" / f"chunk-{REMOTE_CHUNK_ID}.json", {}) or {}
            receipt = read_json(root / "bundles" / f"chunk-{REMOTE_CHUNK_ID}" / "receipt.json", {}) or {}
            digest = str(evidence.get("bundle_sha256") or "")
            bundle = root / "bundles" / f"chunk-{REMOTE_CHUNK_ID}" / f"validated-archive-bundle-{manifest['lease_id']}.tar.gz"
            projection = read_json(root / "source-projection.json", {}) or {}
            if (evidence.get("validated") is not True or receipt.get("sha256") != digest
                or receipt.get("canary_id") != canary_id or receipt.get("lease_id") != manifest.get("lease_id")
                or receipt.get("cookies_used") is not False or receipt.get("media_files") != 0
                or projection.get("canary_id") != canary_id or projection.get("bundle_sha256") != digest
                or bundle.is_symlink() or not bundle.is_file() or bundle.stat().st_size != receipt.get("size") or sha256_file(bundle) != digest):
                raise GP.PoolError("Windows finalization replay requires matching validated import and bundle receipts")
            LC.validate_journal(journal, canary_id, str(manifest["lease_id"]), digest, set(manifest["video_ids"]))
            summary = (journal.get("target_manifest_fields") or {}).get("remote_summary") or {}
            if summary.get("worker_alive") is not False or summary.get("cookies_used") is not False or summary.get("media_downloaded") is not False:
                raise GP.PoolError("Windows finalization replay safety proof invalid")
            LC.finalize_global_import(canary_id, evidence, summary, root_override=root)
            return {"state": read_json(root / "manifest.json", {}).get("state"), "canary_id": canary_id, "finalization_replayed": True, "bundle_sha256": digest}
        if manifest.get("state") not in {"launching", "running", "returned", "blocked", "importing", "attention_required"}:
            raise GP.PoolError(f"Windows canary is not reconcilable: {manifest.get('state')}")
        remote = probe_canary(canary_id)
        state = str(remote.get("state") or "unknown")
        summary = remote_summary(remote)
        if remote.get("worker_alive"):
            _set_state(
                root,
                "running",
                remote_state=state,
                remote_summary=summary,
                remote_counts=summary.get("counts") or {},
                worker_alive=True,
            )
            return {"state": "running", "canary_id": canary_id, "remote_state": state, "counts": summary.get("counts") or {}}
        if state in REMOTE_IMPORTABLE:
            _set_state(
                root,
                "returned",
                remote_state=state,
                remote_summary=summary,
                remote_counts=summary.get("counts") or {},
                worker_alive=False,
            )
            # Fail closed unless the import path sees an exact terminated worker.
            if remote.get("worker_alive") is not False:
                raise GP.PoolError("Windows import refused while remote worker is still alive")
            result = transfer_and_import(canary_id, remote)
            final = read_json(root / "manifest.json", {}) or {}
            return {"state": final.get("state"), "canary_id": canary_id, "remote_state": state, **result}
        if state in REMOTE_BLOCKED:
            _set_state(
                root,
                "blocked",
                remote_state=state,
                reason=remote.get("circuit_reason"),
                remote_summary=summary,
                remote_counts=summary.get("counts") or {},
                worker_alive=False,
            )
            return {"state": "blocked", "canary_id": canary_id, "remote_state": state, "reason": remote.get("circuit_reason"), "counts": summary.get("counts") or {}}
        _set_state(
            root,
            "attention_required",
            remote_state=state,
            remote_summary=summary,
            remote_counts=summary.get("counts") or {},
            worker_alive=False,
        )
        return {"state": "attention_required", "canary_id": canary_id, "remote_state": state, "worker_alive": False}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Fail-closed Windows canary orchestrator; Windows remains disabled")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("preflight")
    prepare = sub.add_parser("prepare")
    prepare.add_argument("--canary-id", required=True)
    prepare.add_argument("--item-count", type=int, default=1)
    for name in ("launch", "probe", "resume", "arm-rate", "cancel-rate", "recovery-status", "package", "reconcile"):
        command = sub.add_parser(name)
        command.add_argument("--canary-id", required=True)
        if name in {"resume", "arm-rate", "cancel-rate"}:
            command.add_argument("--checkpoint-sha256", required=True)
        if name in {"resume", "arm-rate"}:
            command.add_argument("--approval-reference", required=name == "arm-rate")
            command.add_argument("--retry-after-at", help="Validated UTC deadline; only extends the policy wait")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "preflight":
        result = validate_host()
    elif args.command == "prepare":
        result = prepare_canary(args.canary_id, item_count=args.item_count)
    elif args.command == "launch":
        result = launch_canary(args.canary_id)
    elif args.command == "probe":
        result = probe_canary(args.canary_id)
    elif args.command == "resume":
        result = resume_canary(args.canary_id, expected_checkpoint_sha256=args.checkpoint_sha256,
                               approval_reference=args.approval_reference, retry_after_at=args.retry_after_at)
    elif args.command == "arm-rate":
        result = arm_rate_recovery(args.canary_id, expected_checkpoint_sha256=args.checkpoint_sha256,
                                  approval_reference=args.approval_reference, retry_after_at=args.retry_after_at)
    elif args.command == "cancel-rate":
        result = cancel_rate_recovery(args.canary_id, expected_checkpoint_sha256=args.checkpoint_sha256)
    elif args.command == "recovery-status":
        root = _existing_recovery_root(args.canary_id)
        manifest = read_json(root / "manifest.json", {}) or {}
        result = {"canary_id": args.canary_id, "requests": resume_request_inventory(root, manifest)}
    elif args.command == "package":
        result = package_canary(args.canary_id)
    else:
        result = reconcile_canary(args.canary_id)
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
