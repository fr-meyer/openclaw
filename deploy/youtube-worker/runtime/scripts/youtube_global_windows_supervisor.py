#!/usr/bin/env python3
"""Health-gated production supervisor for the Windows YouTube pool worker."""
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
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

# Scheduled commands fence imports as well as tick/output. Imported callers
# retain the existing operation locks; deployment never edits scheduler argv.
_COMMAND_LOCK_FD = None
if __name__ == "__main__" and len(sys.argv) > 1 and sys.argv[1] in {"cron", "cron-reconcile", "tick"}:
    _command_data = Path(os.environ.get("OPENCLAW_YOUTUBE_DATA_ROOT", "~/.openclaw/data/youtube-transcripts")).expanduser()
    _command_lock = _command_data / "state/automation/global/locks/windows-supervisor.lock"
    if any(part.is_symlink() for part in [_command_lock, *_command_lock.parents]):
        raise RuntimeError("Windows supervisor lock path is redirected")
    _command_lock.parent.mkdir(parents=True, exist_ok=True)
    _COMMAND_LOCK_FD = os.open(_command_lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(_COMMAND_LOCK_FD, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(_COMMAND_LOCK_FD)
        print("NO_REPLY")
        raise SystemExit(0)
_LOADED_SUPERVISOR_SHA256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

from youtube_windows_deployment import verify_managed_sources
import youtube_worker_alerts as ALERTS
from youtube_safe_diagnostics import REASONS, VIDEO_ID

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
RUNS_ROOT = POOL_ROOT / "windows-canaries"
MARKER_PATH = POOL_ROOT / "gates/windows-worker-cutover.json"
STATE_PATH = POOL_ROOT / "windows-supervisor-state.json"
LOCK_PATH = POOL_ROOT / "locks/windows-supervisor.lock"
ALERT_DATABASE = POOL_ROOT / "windows-notifications.sqlite3"
SCRIPT_PATH = WORKSPACE / "scripts/youtube_global_windows_supervisor.py"
DECLARATION_KEY = "youtube-global-windows-supervisor-v1"
EXPECTED_ARGV = ["python3", str(SCRIPT_PATH), "cron"]

FINAL_STATES = {"completed", "partial", "superseded_before_lease"}
RECONCILABLE_STATES = {"running", "returned", "importing", "complete", "complete_with_blocked", "blocked", "attention_required"}


def load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load module {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


GP = load_module("youtube_global_pool_windows_supervisor", WORKSPACE / "scripts/youtube_global_pool.py")
WC = load_module("youtube_global_windows_lifecycle_supervisor", WORKSPACE / "scripts/youtube_global_windows_canary.py")
NODE_ID = WC.WINDOWS_CONFIG["node"]["id"]
CANARY_IDS = [row["id"] for row in WC.WINDOWS_CONFIG["validation_canaries"]]


def utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def read_json(path: Path, default: Any = None) -> Any:
    if not path.is_file():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def atomic_json(path: Path, payload: Any) -> None:
    GP.atomic_json(path, payload)


def stable_hash(payload: Any) -> str:
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def cron_identity(job: dict[str, Any]) -> dict[str, Any]:
    return {key: job.get(key) for key in (
        "id", "declarationKey", "name", "description", "agentId", "schedule",
        "sessionTarget", "wakeMode", "payload", "delivery", "failureAlert",
    )}


def read_cron_job(job_id: str) -> dict[str, Any]:
    completed = subprocess.run(
        ["openclaw", "automations", "get", job_id, "--json"], cwd=WORKSPACE, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45, check=False,
    )
    if completed.returncode != 0:
        raise GP.PoolError(f"Windows scheduler inspection failed for {job_id}")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise GP.PoolError("Windows scheduler inspection returned invalid JSON") from exc
    if not isinstance(payload, dict) or payload.get("id") != job_id:
        raise GP.PoolError("Windows scheduler inspection returned the wrong job")
    return payload


def validate_cron_job(job: dict[str, Any], *, enabled: bool) -> None:
    if job.get("declarationKey") != DECLARATION_KEY or job.get("enabled") is not enabled:
        raise GP.PoolError("Windows scheduler identity or enabled state differs")
    payload = job.get("payload") if isinstance(job.get("payload"), dict) else {}
    if payload.get("kind") != "command" or payload.get("argv") != EXPECTED_ARGV:
        raise GP.PoolError("Windows scheduler command payload differs")
    if Path(str(payload.get("cwd") or "")).resolve() != WORKSPACE.resolve():
        raise GP.PoolError("Windows scheduler working directory differs")


def completed_canary_evidence() -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    expected_counts = {row["id"]: row["archived_count"] for row in WC.WINDOWS_CONFIG["validation_canaries"]}
    for canary_id in CANARY_IDS:
        root = RUNS_ROOT / canary_id
        manifest = read_json(root / "manifest.json", {}) or {}
        summary = manifest.get("remote_summary") if isinstance(manifest.get("remote_summary"), dict) else {}
        chunk = read_json(POOL_ROOT / "chunks" / f"{canary_id}.json", {}) or {}
        finalization = read_json(root / "finalization.json", {}) or {}
        import_evidence = read_json(root / "imports" / "chunk-0001.json", {}) or {}
        bundle_sha = (
            manifest.get("bundle_sha256")
            or import_evidence.get("bundle_sha256")
            or finalization.get("bundle_sha256")
        )
        if (
            manifest.get("canary_id") != canary_id
            or manifest.get("run_kind") != "windows_canary"
            or manifest.get("state") != "completed"
            or int(manifest.get("archived_count") or 0) != expected_counts[canary_id]
            or int(manifest.get("incomplete_count") or 0) != 0
            or manifest.get("cookies_used") is not False
            or int(manifest.get("media_files") or 0) != 0
            or (manifest.get("node") or {}).get("node_id") != NODE_ID
            or not bundle_sha
            or manifest.get("worker_alive") is not False
            or summary.get("worker_alive") is not False
            or str(manifest.get("remote_state") or "") not in {"complete", "complete_with_blocked"}
            or str(summary.get("state") or "") not in {"complete", "complete_with_blocked"}
            or chunk.get("state") != "completed"
            or chunk.get("worker_alive") is not False
            or str(chunk.get("remote_state") or "") not in {"complete", "complete_with_blocked"}
            or finalization.get("state") != "committed"
            or finalization.get("bundle_sha256") != bundle_sha
            or import_evidence.get("validated") is not True
            or import_evidence.get("bundle_sha256") != bundle_sha
        ):
            raise GP.PoolError(f"Windows canary evidence is incomplete: {canary_id}")
        evidence.append({
            "canary_id": canary_id,
            "item_count": expected_counts[canary_id],
            "lease_id": manifest.get("lease_id"),
            "bundle_sha256": bundle_sha,
            "manifest_sha256": stable_hash(manifest),
            "worker_alive": False,
            "remote_state": manifest.get("remote_state"),
        })
    return evidence


def record_cutover(job_id: str, *, chunk_size: int = 8) -> dict[str, Any]:
    if not 1 <= chunk_size <= 25:
        raise GP.PoolError("Windows production chunk size must be 1..25")
    job = read_cron_job(job_id)
    validate_cron_job(job, enabled=False)
    preflight = WC.validate_host()
    if (preflight.get("node") or {}).get("node_id") != NODE_ID:
        raise GP.PoolError("Windows cutover preflight node identity differs")
    if active_runs():
        raise GP.PoolError("Windows cutover requires no active Windows production run")
    marker = {
        "schema": "franck.youtube-global-pool.windows-worker-cutover.v1",
        "recorded_at": utcnow(),
        "enabled": True,
        "node_id": NODE_ID,
        "node_label": WC.WINDOWS_NODE_LABEL,
        "scheduler_job_id": job_id,
        "scheduler_identity_sha256": stable_hash(cron_identity(job)),
        "chunk_size": chunk_size,
        "minimum_launch_interval_minutes": 15,
        "max_chunk_launches_per_day": 48,
        "adapter_sha256": WC.sha256_file(WC.REMOTE_ADAPTER),
        "worker_sha256": WC.sha256_file(WC.REMOTE_WORKER),
        "canaries": completed_canary_evidence(),
        "dual_node_canary": "deferred_mac_offline_not_scheduler_gate",
        "cookies_allowed": False,
        "media_allowed": False,
        "automatic_remote_cleanup": False,
        "rollback": {"first": f"disable scheduler {job_id}", "then": "set enabled=false in this marker"},
    }
    atomic_json(MARKER_PATH, marker)
    return marker


def validate_cutover() -> dict[str, Any]:
    verify_managed_sources(WORKSPACE, WC.WINDOWS_CONFIG, loaded_supervisor_sha256=_LOADED_SUPERVISOR_SHA256)
    marker = read_json(MARKER_PATH, {}) or {}
    if marker.get("schema") != "franck.youtube-global-pool.windows-worker-cutover.v1" or marker.get("enabled") is not True:
        raise GP.PoolError("Windows worker cutover marker is absent or disabled")
    if marker.get("node_id") != NODE_ID or marker.get("node_label") != WC.WINDOWS_NODE_LABEL:
        raise GP.PoolError("Windows worker cutover node identity differs")
    if marker.get("cookies_allowed") is not False or marker.get("media_allowed") is not False:
        raise GP.PoolError("Windows worker cutover violates anonymous caption-only policy")
    if marker.get("automatic_remote_cleanup") is not False:
        raise GP.PoolError("Windows worker cutover unexpectedly permits remote cleanup")
    if marker.get("adapter_sha256") != WC.sha256_file(WC.REMOTE_ADAPTER) or marker.get("worker_sha256") != WC.sha256_file(WC.REMOTE_WORKER):
        raise GP.PoolError("Windows worker cutover code hash drifted")
    if marker.get("canaries") != completed_canary_evidence():
        raise GP.PoolError("Windows worker cutover canary evidence drifted")
    job_id = str(marker.get("scheduler_job_id") or "")
    job = read_cron_job(job_id)
    validate_cron_job(job, enabled=True)
    if stable_hash(cron_identity(job)) != marker.get("scheduler_identity_sha256"):
        raise GP.PoolError("Windows worker scheduler identity drifted after cutover")
    return marker


def run_manifest_paths() -> list[Path]:
    return sorted(RUNS_ROOT.glob("windows-canary-prod-*/manifest.json"))


def active_runs() -> list[tuple[str, dict[str, Any]]]:
    rows = []
    for path in run_manifest_paths():
        manifest = read_json(path, {}) or {}
        if manifest.get("run_kind") == "windows_production" and manifest.get("state") not in FINAL_STATES:
            rows.append((str(manifest.get("canary_id") or path.parent.name), manifest))
    return rows


def new_run_id() -> str:
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dt%H%M%Sz")
    return f"windows-canary-prod-{stamp}-{uuid.uuid4().hex[:8]}"


def launch_metrics(marker: dict[str, Any], *, now: dt.datetime | None = None) -> dict[str, Any]:
    now = now or dt.datetime.now(dt.timezone.utc)
    timezone = ZoneInfo("Asia/Seoul")
    today = now.astimezone(timezone).date()
    launches: list[dt.datetime] = []
    for path in run_manifest_paths():
        manifest = read_json(path, {}) or {}
        if manifest.get("run_kind") != "windows_production":
            continue
        launched = GP.parse_time(manifest.get("launched_at"))
        if launched is None and manifest.get("state") != "superseded_before_lease":
            # Legacy manifests may predate launched_at. Creation alone is a
            # preparation, so require an observed worker PID before counting.
            if manifest.get("worker_pid"):
                launched = GP.parse_time(manifest.get("created_at"))
        if launched:
            launches.append(launched)
    today_count = sum(value.astimezone(timezone).date() == today for value in launches)
    maximum = int(marker.get("max_chunk_launches_per_day") or 0)
    if today_count >= maximum:
        return {"allowed": False, "reason": "daily_budget_exhausted", "launches_today": today_count, "max_launches_per_day": maximum}
    if launches:
        elapsed = (now - max(launches)).total_seconds() / 60
        minimum = int(marker.get("minimum_launch_interval_minutes") or 0)
        if elapsed < minimum:
            return {"allowed": False, "reason": "minimum_launch_interval", "minutes_remaining": round(minimum - elapsed, 1), "launches_today": today_count, "max_launches_per_day": maximum}
    return {"allowed": True, "reason": "eligible", "launches_today": today_count, "max_launches_per_day": maximum}


def write_state(state: str, **fields: Any) -> None:
    store = GP.PoolStore(POOL_ROOT)
    pool = store.write_state()
    atomic_json(STATE_PATH, {
        "schema": "franck.youtube-global-pool.windows-supervisor-state.v1",
        "state": state,
        "updated_at": utcnow(),
        "node_id": NODE_ID,
        "windows_enabled": True,
        "pool": {
            "item_count": pool.get("item_count"),
            "status_counts": pool.get("status_counts"),
            "active_lease_count": pool.get("active_lease_count"),
            "cookies_used": False,
            "media_files": 0,
        },
        **fields,
    })


NODE_UNAVAILABLE_MARKERS = (
    "node unavailable",
    "node disconnected",
    "node is not connected",
    "is disconnected; no remote command was started",
    "is not paired or visible; no remote command was started",
    "is not available for remote execution; no remote command was started",
    "timed out; the supervisor will re-check the node",
)


def exception_chain(exc: BaseException):
    """Yield a bounded exception/cause chain without looping."""
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen and len(seen) < 8:
        seen.add(id(current))
        yield current
        current = current.__cause__ or current.__context__


def is_node_unavailable(exc: BaseException) -> bool:
    """Recognise only expected node absence, including wrapped transport errors."""
    for current in exception_chain(exc):
        if isinstance(current, (WC.YC.NodeUnavailable, WC.YC.NodeRequestTimedOut)):
            return True
        if type(current).__name__ in {"NodeUnavailable", "NodeRequestTimedOut"}:
            return True
        message = str(current).lower()
        if any(marker in message for marker in NODE_UNAVAILABLE_MARKERS):
            return True
    return False


def defer_node_unavailable(current: list[tuple[str, dict[str, Any]]]) -> dict[str, Any]:
    """Persist expected offline state while leaving any run and lease untouched."""
    run_id = current[0][0] if current else None
    manifest = current[0][1] if current else {}
    state = str(manifest.get("state") or "") if manifest else ""
    if not run_id:
        write_state("waiting_node", reason="node unavailable; deferred until the next supervisor tick")
        return {"action": "waiting_node", "alert": False}
    unavailable_count = int(manifest.get("node_unavailable_count") or 0) + 1
    WC._set_state(
        WC.canary_root(run_id),
        state or "running",
        node_unavailable_count=unavailable_count,
        last_node_unavailable_at=utcnow(),
        reason="node unavailable; deferred until the next supervisor tick",
    )
    write_state(
        "waiting_node_active_run",
        run_id=run_id,
        run_state=state,
        node_unavailable_count=unavailable_count,
        reason="node unavailable; deferred until the next supervisor tick",
    )
    return {
        "action": "waiting_node_active_run",
        "run_id": run_id,
        "result": {"state": state, "node_unavailable_count": unavailable_count},
        "alert": False,
    }


def tick(*, launch: bool = True) -> dict[str, Any]:
    with supervisor_lock():
        current = active_runs()
        if len(current) > 1:
            raise GP.PoolError("multiple non-final Windows production runs")
        if not launch:
            if not current:
                return {"action": "no_active_run", "alert": False}
            run_id, manifest = current[0]
            state = str(manifest.get("state") or "")
            if state not in RECONCILABLE_STATES:
                return {"action": "deferred_to_launcher", "run_id": run_id, "run_state": state, "alert": False}
            try:
                WC.windows_node_status()
            except Exception as exc:
                if is_node_unavailable(exc):
                    return defer_node_unavailable(current)
                raise
            validate_cutover()
            try:
                result = WC.reconcile_canary(run_id)
            except Exception as exc:
                if is_node_unavailable(exc):
                    return defer_node_unavailable(current)
                raise
            result_state = str(result.get("state") or "")
            if result_state in {"blocked", "attention_required", "partial"}:
                action = "run_attention_required" if result_state != "partial" else "run_partial"
            else:
                action = "run_reconciled"
            write_state(action, run_id=run_id, run_state=result.get("state"))
            return {
                "action": action,
                "run_id": run_id,
                "result": result,
                "alert": action in {"run_attention_required", "run_partial"},
            }
        # An offline residential node is an expected scheduling condition.  Probe
        # connectivity before validating launch-only code/canary bindings so a
        # dormant worker does not generate repeated integrity alerts.  The full
        # fail-closed cutover validation still runs immediately once it is online.
        try:
            WC.windows_node_status()
        except Exception as exc:
            if is_node_unavailable(exc):
                return defer_node_unavailable(current)
            raise
        marker = validate_cutover()
        try:
            preflight = WC.validate_host()
            node_available = True
        except Exception as exc:
            if not is_node_unavailable(exc):
                raise
            node_available = False
            preflight = None
            if not current:
                return defer_node_unavailable(current)
        if current:
            run_id, manifest = current[0]
            state = str(manifest.get("state") or "")
            if not node_available:
                return defer_node_unavailable(current)
            try:
                if state in {"preparing", "prepare_failed_before_lease", "prepared"}:
                    try:
                        result = WC.resume_canary_preparation(run_id, manifest) if state != "prepared" else WC.launch_canary(run_id)
                    except WC.SelectionConflictError as exc:
                        write_state("selection_conflict", run_id=run_id, reason=str(exc))
                        return {"action": "selection_conflict", "run_id": run_id, "alert": False, "reason": str(exc)}
                    action = "run_prepared_recovered" if state != "prepared" else "run_launched"
                elif state == "launching":
                    result = WC.launch_canary(run_id)
                    action = "run_launch_reconciled"
                elif state in RECONCILABLE_STATES:
                    result = WC.reconcile_canary(run_id)
                    result_state = str(result.get("state") or "")
                    if result_state in {"blocked", "attention_required", "partial"}:
                        action = "run_attention_required" if result_state != "partial" else "run_partial"
                    else:
                        action = "run_reconciled"
                else:
                    raise GP.PoolError(f"unsupported Windows production state: {state}")
            except Exception as exc:
                if is_node_unavailable(exc):
                    return defer_node_unavailable(current)
                raise
            write_state(action, run_id=run_id, run_state=result.get("state"))
            return {
                "action": action,
                "run_id": run_id,
                "result": result,
                "alert": action in {"run_attention_required", "run_partial"},
            }

        metrics = launch_metrics(marker)
        if not metrics["allowed"]:
            write_state("waiting_policy", launch_policy=metrics)
            return {"action": "waiting_policy", "metrics": metrics, "alert": False}
        chunk_size = int(marker["chunk_size"])
        store = GP.PoolStore(POOL_ROOT)
        selected = []
        last_conflict = None
        for attempt in range(3):
            selected = GP.select_items(store.load_items(), policy=GP.SelectionPolicy(chunk_size=chunk_size))
            if len(selected) != chunk_size:
                write_state("no_pending_work", selected_count=len(selected), attempt=attempt)
                return {"action": "no_pending_work", "alert": False}
            run_id = new_run_id()
            try:
                prepared = WC.prepare_canary(
                    run_id,
                    item_count=chunk_size,
                    selected_items=selected,
                    preflight=preflight,
                    run_kind="windows_production",
                    windows_enabled=True,
                )
                break
            except WC.SelectionConflictError as exc:
                last_conflict = exc
                continue
            except Exception as exc:
                if is_node_unavailable(exc):
                    refreshed = active_runs()
                    if len(refreshed) > 1:
                        raise GP.PoolError("multiple non-final Windows production runs appeared during node deferral") from exc
                    return defer_node_unavailable(refreshed)
                raise
        else:
            write_state("selection_conflict", reason=str(last_conflict) if last_conflict else "selection raced")
            return {"action": "selection_conflict", "alert": False, "reason": str(last_conflict) if last_conflict else "selection raced"}
        try:
            launched = WC.launch_canary(run_id)
        except Exception as exc:
            if is_node_unavailable(exc):
                refreshed = active_runs()
                if len(refreshed) > 1:
                    raise GP.PoolError("multiple non-final Windows production runs appeared during node deferral") from exc
                return defer_node_unavailable(refreshed)
            raise
        write_state(
            "run_started",
            run_id=run_id,
            run_state=launched.get("state"),
            item_count=chunk_size,
            lane_counts=prepared.get("lane_counts"),
        )
        return {
            "action": "run_started",
            "run_id": run_id,
            "lease_id": prepared.get("lease_id"),
            "item_count": chunk_size,
            "alert": False,
        }


def notification_record(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise GP.PoolError("Windows notification evidence is unavailable or unsafe")
    record = read_json(path)
    if not isinstance(record, dict):
        raise GP.PoolError("Windows notification evidence is not an object")
    return record


def notification_recovery_verified(root: Path, manifest: dict[str, Any]) -> bool:
    """Consume the coordinator's committed receipts, never perform recovery."""
    if manifest.get("state") != "completed" or manifest.get("worker_alive") is not False:
        return False
    run_id, lease_id = manifest.get("canary_id"), manifest.get("lease_id")
    bundle = manifest.get("bundle_sha256")
    if not isinstance(bundle, str) or not re.fullmatch(r"[0-9a-f]{64}", bundle):
        return False
    imported = notification_record(root / "imports/chunk-0001.json")
    journal = notification_record(root / "finalization.json")
    queue = notification_record(root / "queue/state.json")
    lease = notification_record(POOL_ROOT / "leases" / (lease_id + ".json"))
    chunk = notification_record(POOL_ROOT / "chunks" / (run_id + ".json"))
    ids = manifest.get("video_ids")
    archived = imported.get("video_ids") or []
    terminal = imported.get("terminal_items") or []
    if not isinstance(ids, list) or not 1 <= len(ids) <= WC.MAX_CANARY_ITEMS or any(not isinstance(v, str) or not VIDEO_ID.fullmatch(v) for v in ids):
        return False
    if not isinstance(archived, list) or not isinstance(terminal, list) or any(not isinstance(row, dict) for row in terminal):
        return False
    terminal_states = {"skipped_private", "skipped_age_restricted", "skipped_unavailable"}
    expected = {v: "archived" for v in archived if isinstance(v, str)}
    expected.update({row.get("video_id"): row.get("state") for row in terminal if isinstance(row.get("video_id"), str)})
    partition = archived + [row.get("video_id") for row in terminal]
    if (imported.get("validated") is not True or imported.get("requested_video_ids") != ids
        or imported.get("incomplete_items") or imported.get("incomplete_count") != 0
        or len(partition) != len(ids) or len(expected) != len(ids) or set(expected) != set(ids)
        or any(row.get("state") not in terminal_states for row in terminal)
        or imported.get("cookies_used") is not False or imported.get("media_files") != 0
        or journal.get("state") != "committed" or journal.get("canary_id") != run_id
        or journal.get("lease_id") != lease_id
        or not all(record.get("bundle_sha256") == bundle for record in (imported, journal))
        or lease.get("state") != "completed" or lease.get("lease_id") != lease_id
        or lease.get("chunk_id") != run_id or lease.get("video_ids") != ids
        or chunk.get("state") != "completed" or chunk.get("lease_id") != lease_id):
        return False
    if queue.get("state") != "completed" or queue.get("bundle_sha256") != bundle or queue.get("worker_alive") is not False:
        return False
    try:
        WC.LC.validate_journal(journal, run_id, lease_id, bundle, set(ids))
    except WC.LC.GP.PoolError:
        return False
    for video in ids:
        item = notification_record(POOL_ROOT / "items" / (video + ".json"))
        if item.get("status") != expected[video] or item.get("active_lease_id") is not None or item.get("active_node") is not None:
            return False
    return True


def notification_partial_outcome(root: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    """Use validated import outcomes; finalization can retain an old reason."""
    imported = notification_record(root / "imports/chunk-0001.json")
    ids = manifest.get("video_ids")
    bundle = manifest.get("bundle_sha256")
    if (not isinstance(ids, list) or not 1 <= len(ids) <= WC.MAX_CANARY_ITEMS
        or any(not isinstance(video, str) or not VIDEO_ID.fullmatch(video) for video in ids)
        or not isinstance(bundle, str) or not re.fullmatch(r"[0-9a-f]{64}", bundle)
        or imported.get("requested_video_ids") != ids or imported.get("bundle_sha256") != bundle
        or imported.get("cookies_used") is not False or imported.get("media_files") != 0):
        raise GP.PoolError("Windows partial notification import evidence differs")
    archived, _terminal, incomplete = WC.LC.import_outcomes(imported)
    if not incomplete or imported.get("incomplete_count") != len(incomplete):
        raise GP.PoolError("Windows partial notification outcome counts differ")
    outcomes = []
    for video, row in sorted(incomplete.items()):
        state, code = row.get("state"), row.get("failure_class")
        if any(value is not None and (not isinstance(value, str) or len(value) > 256) for value in (state, code)):
            raise GP.PoolError("Windows partial notification classification is invalid")
        outcomes.append({"video_id": video, "state": state, "failure_class": code})
    primary = next((row for row in outcomes if row["failure_class"]), outcomes[0])
    reason = primary["failure_class"] if primary["failure_class"] in REASONS else "unknown"
    return {"failure_code": "partial:" + reason + ":" + stable_hash(outcomes),
            "video_id": primary["video_id"], "archived_count": len(archived),
            "incomplete_count": len(incomplete)}


def notification_snapshot(run_id: str) -> dict[str, Any] | None:
    if not isinstance(run_id, str) or not re.fullmatch(r"windows-canary-prod-[a-z0-9-]{1,64}", run_id):
        raise GP.PoolError("Windows notification run identity is invalid")
    root = RUNS_ROOT / run_id
    manifest = notification_record(root / "manifest.json")
    lease_id = manifest.get("lease_id")
    if manifest.get("canary_id") != run_id or not isinstance(lease_id, str) or not re.fullmatch(r"[0-9a-f-]{36}", lease_id):
        raise GP.PoolError("Windows notification run/lease evidence differs")
    state = manifest.get("state")
    summary = manifest.get("remote_summary") or {}
    if not isinstance(summary, dict):
        raise GP.PoolError("Windows notification summary is invalid")
    recovery = notification_recovery_verified(root, manifest)
    if recovery:
        phase = "resolved"
    elif state in {"blocked", "attention_required", "partial"}:
        phase = "attention"
    elif state == "running" and manifest.get("worker_alive") is True:
        phase = "watching"
    else:
        return None
    if state == "partial":
        return {"run_id": run_id, "lease_id": lease_id, "phase": "attention",
                "recovery_verified": False, **notification_partial_outcome(root, manifest)}
    # Free-form errors and polling timestamps never become fingerprints or text.
    remote_state = summary.get("state")
    # Reconciliation retains old manifest fields. An unexpected remote state
    # must not inherit a previous, recognized circuit and disappear as a repeat.
    raw_code = summary.get("circuit_reason") or (manifest.get("reason") if state != "attention_required" else None) or "unknown"
    if any(value is not None and (not isinstance(value, str) or len(value) > 256) for value in (raw_code, remote_state)):
        raise GP.PoolError("Windows notification classification is invalid")
    recognized = state != "attention_required" and raw_code in REASONS and raw_code != "unknown"
    code = raw_code if recognized else "unknown:" + stable_hash({
        "state": state,
        # Hash the complete bounded structured classification; only the digest
        # enters incident state/text. Digits and punctuation retain identity.
        "remote_state": remote_state,
        "code": raw_code,
    })
    video = summary.get("current_video_id")
    video = video if isinstance(video, str) and VIDEO_ID.fullmatch(video) else None
    counts = summary.get("counts") or {}
    if not isinstance(counts, dict):
        raise GP.PoolError("Windows notification counts are invalid")
    archived = counts.get("archived", manifest.get("archived_count", 0))
    archived = archived if type(archived) is int and 0 <= archived <= WC.MAX_CANARY_ITEMS else 0
    total = manifest.get("expected_item_count")
    total = total if type(total) is int and 1 <= total <= WC.MAX_CANARY_ITEMS else 24
    terminal = sum(value for key, value in counts.items() if key in {"skipped_private", "skipped_age_restricted", "skipped_unavailable"}
                   and type(value) is int and 0 <= value <= total)
    if archived + terminal > total:
        raise GP.PoolError("Windows notification outcome counts differ")
    return {"run_id": run_id, "lease_id": lease_id, "phase": phase, "failure_code": code,
            "video_id": video, "archived_count": archived, "incomplete_count": 0 if recovery else total - archived - terminal,
            "recovery_verified": recovery}


def emit_notifications(result: dict[str, Any]) -> None:
    """Both scheduled callers reserve through the same durable incident owner."""
    with supervisor_lock(), GP.FileLock(POOL_ROOT / "locks/coordinator.lock", blocking=False):
        emit_notifications_locked(result)


def supervisor_lock():
    return contextlib.nullcontext() if _COMMAND_LOCK_FD is not None else GP.FileLock(LOCK_PATH, blocking=False)


def emit_notifications_locked(result: dict[str, Any]) -> None:
    current = result.get("run_id")
    if result.get("alert") and not isinstance(current, str):
        raise GP.PoolError("Windows attention result has no run identity")
    with ALERTS.NotificationStore(ALERT_DATABASE) as store:
        candidates = ([current] if isinstance(current, str) else []) + store.unfinished_runs(limit=8, exclude_run_id=current)
        for run_id in candidates:
            snapshot = notification_snapshot(run_id)
            if snapshot is None:
                continue
            reservation = store.observe(snapshot, now=dt.datetime.now(dt.timezone.utc))
            if reservation is None:
                continue
            try:
                print(reservation.message, flush=True)
            except BaseException:
                store.mark_emission(reservation.event_id, successful=False)
                raise
            store.mark_emission(reservation.event_id, successful=True)
            return
    print("NO_REPLY")


def scheduled_main(*, launch: bool) -> int:
    try:
        result = tick(launch=launch)
        emit_notifications(result)
    except GP.PoolLockError:
        print("NO_REPLY")
        return 0
    except Exception as exc:
        if is_node_unavailable(exc):
            current = active_runs()
            if len(current) <= 1:
                defer_node_unavailable(current)
                print("NO_REPLY")
                return 0
        print(f"Windows YouTube supervisor failed closed: {type(exc).__name__}. No new worker was authorized.", file=sys.stderr)
        return 1
    return 0


def cron_reconcile_main() -> int:
    return scheduled_main(launch=False)


def cron_main() -> int:
    return scheduled_main(launch=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Production supervisor for the Windows YouTube pool worker")
    sub = parser.add_subparsers(dest="command", required=True)
    marker = sub.add_parser("record-cutover")
    marker.add_argument("--job-id", required=True)
    marker.add_argument("--chunk-size", type=int, default=5)
    sub.add_parser("preflight")
    sub.add_parser("tick")
    sub.add_parser("cron")
    sub.add_parser("cron-reconcile")
    sub.add_parser("status")
    sub.add_parser("notification-status")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "record-cutover":
        result = record_cutover(args.job_id, chunk_size=args.chunk_size)
    elif args.command == "preflight":
        result = {"canaries": completed_canary_evidence(), "host": WC.validate_host(), "windows_enabled": False}
    elif args.command == "tick":
        result = tick()
    elif args.command == "cron":
        return cron_main()
    elif args.command == "cron-reconcile":
        return cron_reconcile_main()
    elif args.command == "notification-status":
        with ALERTS.NotificationStore(ALERT_DATABASE, read_only=True) as store:
            result = store.status()
    else:
        result = read_json(STATE_PATH, {}) or {"state": "not_started", "windows_enabled": False}
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    finally:
        if _COMMAND_LOCK_FD is not None:
            os.close(_COMMAND_LOCK_FD)
