"""Existing journaled global import finalization, owned by the Windows lane."""
from __future__ import annotations
import datetime as dt
import hashlib
import json
import os
import uuid
from pathlib import Path
from typing import Any
import youtube_storage as STORAGE
import youtube_global_pool as GP
import youtube_windows_transport as YC
POOL_ROOT = STORAGE.DEFAULT_POOL_ROOT
ARCHIVE_ROOT = STORAGE.DEFAULT_ARCHIVE_ROOT
REMOTE_IMPORTABLE = {"complete", "complete_with_blocked"}
TERMINAL_STATES = {"skipped_private", "skipped_age_restricted", "skipped_unavailable"}


def utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def atomic_json(path: Path, payload: Any) -> None:
    GP.atomic_json(path, payload)


def read_json(path: Path, default: Any = None) -> Any:
    if not path.is_file():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def remote_summary(remote: dict[str, Any]) -> dict[str, Any]:
    return {
        "state": str(remote.get("state") or "unknown"),
        "counts": remote.get("counts") if isinstance(remote.get("counts"), dict) else {},
        "current_index": remote.get("current_index"),
        "current_video_id": remote.get("current_video_id"),
        "updated_at": remote.get("updated_at"),
        "worker_alive": bool(remote.get("worker_alive")),
        "lease_id": remote.get("lease_id"),
        "cookies_used": remote.get("cookies_used"),
        "media_downloaded": remote.get("media_downloaded"),
        "circuit_open": bool(remote.get("circuit_open")),
        "circuit_reason": remote.get("circuit_reason"),
    }


def update_canary_state(root: Path, state: str, **changes: Any) -> None:
    now = utcnow()
    raw_remote = changes.pop("remote", None)
    if raw_remote is not None:
        changes["remote_summary"] = remote_summary(raw_remote)
    manifest = read_json(root / "manifest.json", {}) or {}
    manifest.update({"state": state, "updated_at": now, **changes})
    atomic_json(root / "manifest.json", manifest)
    queue = read_json(root / "queue/state.json", {}) or {}
    queue.update({"state": state, "updated_at": now, **changes})
    atomic_json(root / "queue/state.json", queue)


def append_global_event_once(store: Any, event_id: str, event_type: str, **payload: Any) -> None:
    for row in GP.read_jsonl(store.events_path):
        if row.get("event_id") == event_id:
            return
    event = {
        "schema": f"{GP.SCHEMA_PREFIX}.event.v1",
        "event_id": event_id,
        "created_at": utcnow(),
        "type": event_type,
        **payload,
    }
    with store.events_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def journal_digest(journal: dict[str, Any]) -> str:
    bound = {key: value for key, value in journal.items() if key not in {"state", "committed_at", "journal_sha256"}}
    return hashlib.sha256(json.dumps(bound, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def validate_journal(journal: dict[str, Any], canary_id: str, lease_id: str, bundle_hash: str, expected_ids: set[str]) -> None:
    if (journal.get("schema") != "openclaw.youtube.windows-finalization.v2"
        or journal.get("state") not in {"prepared", "committed"}
        or journal.get("canary_id") != canary_id or journal.get("lease_id") != lease_id
        or journal.get("bundle_sha256") != bundle_hash or journal.get("journal_sha256") != journal_digest(journal)):
        raise GP.PoolError("Windows finalization journal integrity/binding mismatch")
    for key in ("target_items", "preimages"):
        rows = journal.get(key)
        if not isinstance(rows, dict) or set(rows) != expected_ids or any(not isinstance(row, dict) or row.get("video_id") != video for video, row in rows.items()):
            raise GP.PoolError("Windows finalization journal item partition mismatch")
    target = journal.get("target_lease") or {}
    if target.get("lease_id") != lease_id or target.get("chunk_id") != canary_id or set(target.get("video_ids") or []) != expected_ids or target.get("state") not in {"completed", "partial"}:
        raise GP.PoolError("Windows finalization journal lease target mismatch")
    chunk = journal.get("target_chunk") or {}
    if chunk.get("lease_id") != lease_id or chunk.get("state") != target.get("state"):
        raise GP.PoolError("Windows finalization journal chunk target mismatch")


def import_outcomes(imported: dict[str, Any]) -> tuple[set[str], dict[str, Any], dict[str, Any]]:
    if imported.get("validated") is not True or not imported.get("bundle_sha256"):
        raise GP.PoolError("source projection requires a validated bundle-bound import")
    requested = imported.get("requested_video_ids") or []
    archived = imported.get("video_ids") or []
    terminal_rows = imported.get("terminal_items") or []
    incomplete_rows = imported.get("incomplete_items") or []
    terminal = {str(row["video_id"]): row for row in terminal_rows}
    incomplete = {str(row["video_id"]): row for row in incomplete_rows}
    archived_ids = set(str(value) for value in archived)
    if (not requested or len(requested) != len(set(requested)) or len(archived) != len(archived_ids)
        or len(terminal_rows) != len(terminal) or len(incomplete_rows) != len(incomplete)
        or set(requested) != archived_ids | set(terminal) | set(incomplete)
        or archived_ids & set(terminal) or archived_ids & set(incomplete) or set(terminal) & set(incomplete)
        or any(row.get("state") not in TERMINAL_STATES for row in terminal.values())):
        raise GP.PoolError("source projection import partition invalid")
    return archived_ids, terminal, incomplete


def persist_catalog_outcomes(canary_id: str, imported: dict[str, Any], project_root: Path) -> None:
    import_outcomes(imported)
    record = {"schema": "openclaw.youtube.windows-source-outcomes.v1", "canary_id": canary_id,
              **{key: imported.get(key) for key in ("bundle_sha256", "requested_video_ids", "video_ids", "terminal_items", "incomplete_items", "validated")}}
    path = project_root / "imports/windows-canaries" / f"{canary_id}.json"
    previous = read_json(path)
    if previous is not None and previous != record:
        raise GP.PoolError("catalog outcome projection conflicts with prior import")
    if previous is None:
        atomic_json(path, record)


def update_personal_source_projection(canary_id: str, imported: dict[str, Any], timestamp: str) -> dict[str, Any]:
    archived_ids, terminal, _ = import_outcomes(imported)
    queue_root = STORAGE.DEFAULT_QUEUE_ROOT
    pending_path = queue_root / "pending.jsonl"
    events_path = queue_root / "events.jsonl"
    rows = GP.read_jsonl(pending_path)
    changed: list[dict[str, Any]] = []
    for row in rows:
        video_id = str(row.get("video_id") or "")
        if video_id not in archived_ids | set(terminal):
            continue
        old_status = row.get("status")
        if video_id in archived_ids:
            complete, report_path, transcript_path = GP.archive_complete(ARCHIVE_ROOT, video_id)
            if not complete:
                raise GP.PoolError(f"personal source projection archive validation failed: {video_id}")
            target = {"status": "archived", "report_path": report_path, "transcript_path": transcript_path,
                      "last_error": None, "failure_class": None, "summary_status": "pending_deferred"}
        else:
            outcome = terminal[video_id]
            target = {"status": outcome["state"], "report_path": None, "transcript_path": None,
                      "last_error": outcome.get("error"), "failure_class": outcome.get("failure_class"),
                      "summary_status": "not_applicable", "attempt_count": int(outcome.get("attempts") or 0)}
        if all(row.get(key) == value for key, value in target.items()) and row.get("last_run_id") == canary_id:
            continue
        row.update({**target, "last_attempt_at": timestamp, "last_run_id": canary_id})
        changed.append({"queue_id": row.get("queue_id"), "video_id": video_id, "old_status": old_status, "new_status": row["status"], "summary_status": row["summary_status"]})
    if changed:
        # The validated outcome event is durable before its queue projection.
        # A stopped queue write can replay using the existing event identity.
        existing_events = GP.read_jsonl(events_path)
        keys = {
            (event.get("action"), (event.get("detail") or {}).get("canary_id"), (event.get("detail") or {}).get("video_id"))
            for event in existing_events
        }
        with events_path.open("a", encoding="utf-8") as handle:
            for row in changed:
                action = "global_pool_archive" if row["new_status"] == "archived" else "global_pool_terminal"
                key = (action, canary_id, row["video_id"])
                if key in keys:
                    continue
                handle.write(json.dumps({
                    "action": action,
                    "detail": {"canary_id": canary_id, "video_id": row["video_id"], "summary_status": row["summary_status"]},
                    "new_status": row["new_status"],
                    "old_status": row["old_status"],
                    "queue_id": row["queue_id"],
                    "run_id": canary_id,
                    "ts": timestamp,
                }, ensure_ascii=False, sort_keys=True) + "\n")
                keys.add(key)
            handle.flush()
            os.fsync(handle.fileno())
        GP.fsync_directory(events_path.parent)
        GP.write_jsonl(pending_path, rows)
    return {"changed_count": len(changed), "video_ids": sorted(row["video_id"] for row in changed)}


def finalize_global_import(
    canary_id: str,
    imported: dict[str, Any],
    remote: dict[str, Any],
    *,
    root_override: Path,
) -> None:
    root = root_override
    manifest = read_json(root / "manifest.json", {}) or {}
    if imported.get("validated") is not True:
        raise GP.PoolError("global finalization requires a validated import receipt")
    lease_id = str(manifest["lease_id"])
    store = GP.PoolStore(POOL_ROOT)
    archived_ids = set(str(value) for value in imported.get("video_ids") or [])
    terminal = {str(row["video_id"]): row for row in imported.get("terminal_items") or []}
    incomplete = {str(row["video_id"]): row for row in imported.get("incomplete_items") or []}
    timestamp = utcnow()
    journal_path = root / "finalization.json"
    bundle_hash = str(imported.get("bundle_sha256") or "")
    if not bundle_hash:
        raise GP.PoolError("canary import evidence is missing its bundle hash")
    with store.coordinator_lock():
        lease_path = store.leases_dir / f"{lease_id}.json"
        global_chunk_path = store.chunks_dir / f"{canary_id}.json"
        lease = read_json(lease_path, {}) or {}
        expected_ids = set(str(value) for value in lease.get("video_ids") or manifest.get("video_ids") or [])
        if expected_ids != set(manifest.get("video_ids") or []):
            raise GP.PoolError("global canary manifest and lease item sets differ")
        outcome_sets = (archived_ids, set(terminal), set(incomplete))
        if (
            set().union(*outcome_sets) != expected_ids
            or archived_ids & set(terminal)
            or archived_ids & set(incomplete)
            or set(terminal) & set(incomplete)
        ):
            raise GP.PoolError("global canary import result does not partition the lease item set")
        journal = read_json(journal_path, {}) or {}
        if journal:
            validate_journal(journal, canary_id, lease_id, bundle_hash, expected_ids)
            if journal.get("lease_id") != lease_id or journal.get("bundle_sha256") != bundle_hash:
                raise GP.PoolError("canary finalization journal binding mismatch")
            if journal.get("state") == "committed":
                for video_id, target in (journal.get("target_items") or {}).items():
                    if store.load_item(video_id) != target:
                        raise GP.PoolError(f"committed canary finalization drifted: {video_id}")
                if read_json(lease_path, {}) != journal.get("target_lease"):
                    raise GP.PoolError("committed canary finalization lease drifted")
                if read_json(global_chunk_path, {}) != journal.get("target_chunk"):
                    raise GP.PoolError("committed canary finalization chunk drifted")
                final_state = str((journal.get("target_lease") or {}).get("state") or "completed")
                target_manifest_fields = journal.get("target_manifest_fields") or {
                    "archived_count": len(archived_ids),
                    "terminal_count": len(terminal),
                    "incomplete_count": len(incomplete),
                    "completed_at": journal.get("committed_at"),
                    "bundle_sha256": bundle_hash,
                    "remote_state": (journal.get("target_chunk") or {}).get("remote_state"),
                    "remote_summary": remote_summary({
                        "state": (journal.get("target_chunk") or {}).get("remote_state"),
                        "counts": (journal.get("target_chunk") or {}).get("remote_counts") or {},
                        "worker_alive": False,
                        "lease_id": lease_id,
                        "cookies_used": False,
                        "media_downloaded": False,
                    }),
                    "remote_counts": (journal.get("target_chunk") or {}).get("remote_counts") or {},
                    "worker_alive": False,
                }
                current_manifest = read_json(root / "manifest.json", {}) or {}
                current_queue = read_json(root / "queue/state.json", {}) or {}
                needs_manifest = (
                    current_manifest.get("state") != final_state
                    or current_manifest.get("worker_alive") is not False
                    or current_manifest.get("remote_state") != target_manifest_fields.get("remote_state")
                    or current_manifest.get("bundle_sha256") != bundle_hash
                    or current_queue.get("state") != final_state
                    or current_queue.get("bundle_sha256") != bundle_hash
                    or current_queue.get("worker_alive") is not False
                )
                if needs_manifest:
                    update_canary_state(root, final_state, **target_manifest_fields)
                return
        else:
            if lease.get("state") != "active" or lease.get("chunk_id") != canary_id:
                raise GP.PoolError("global canary lease is not active or bound to this canary")
            target_items: dict[str, dict[str, Any]] = {}
            preimages: dict[str, dict[str, Any]] = {}
            for video_id in sorted(expected_ids):
                item = store.load_item(video_id)
                if not item or item.get("active_lease_id") != lease_id:
                    raise GP.PoolError(f"global canary item lease mismatch: {video_id}")
                preimages[video_id] = item
                target = json.loads(json.dumps(item))
                attempt_source = (remote.get("items") or {}).get(video_id, {})
                target["attempt_count"] = int(attempt_source.get("attempts") or incomplete.get(video_id, {}).get("attempts") or target.get("attempt_count") or 0)
                if video_id in archived_ids:
                    complete, report_path, transcript_path = GP.archive_complete(ARCHIVE_ROOT, video_id)
                    if not complete:
                        raise GP.PoolError(f"imported canonical archive failed validation: {video_id}")
                    needs_summary = any("summarize" in str(source.get("requested_action") or "") for source in target.get("sources") or [])
                    target["status"] = "archived"
                    target["summary_status"] = "pending_deferred" if needs_summary else "not_requested"
                    target["report_path"] = report_path
                    target["transcript_path"] = transcript_path
                    target["retry_after"] = None
                    target.pop("last_error", None)
                    target.pop("last_error_class", None)
                else:
                    failure = terminal.get(video_id) or incomplete[video_id]
                    failure_state = str(failure.get("state") or "blocked_error")
                    target["status"] = failure_state if failure_state in {"skipped_private", "skipped_age_restricted", "skipped_unavailable"} or failure_state.startswith("blocked_") else "blocked_error"
                    target["retry_after"] = None
                    target["last_error_class"] = failure.get("failure_class") or "error"
                    target["last_error"] = str(failure.get("error") or "")[-2000:] or None
                target["active_lease_id"] = None
                target["active_node"] = None
                target["updated_at"] = timestamp
                target_items[video_id] = target
            final_state = "completed" if not incomplete else "partial"
            if remote.get("worker_alive") is not False:
                raise GP.PoolError("final import requires a terminated remote worker")
            remote_state = str(remote.get("state") or "")
            if remote_state not in REMOTE_IMPORTABLE:
                raise GP.PoolError(f"final import remote state is not importable: {remote_state}")
            final_summary = remote_summary(remote)
            if final_summary.get("worker_alive") is not False:
                raise GP.PoolError("final remote summary still reports a live worker")
            if final_summary.get("cookies_used") is not False or final_summary.get("media_downloaded") is not False:
                raise GP.PoolError("final remote summary violates anonymous caption-only policy")
            target_lease = {
                **lease,
                "state": final_state,
                "completed_at": timestamp,
                "archived_count": len(archived_ids),
                "terminal_count": len(terminal),
                "incomplete_count": len(incomplete),
                "cookies_used": False,
                "media_files": 0,
            }
            target_chunk = {
                **(read_json(global_chunk_path, {}) or {}),
                "state": final_state,
                "completed_at": timestamp,
                "archived_count": len(archived_ids),
                "terminal_count": len(terminal),
                "incomplete_count": len(incomplete),
                "remote_state": remote_state,
                "worker_alive": False,
                "remote_counts": final_summary.get("counts") or {},
                "remote_updated_at": final_summary.get("updated_at"),
                "cookies_used": False,
                "media_files": 0,
            }
            target_manifest_fields = {
                "remote_state": remote_state,
                "remote_summary": final_summary,
                "remote_counts": final_summary.get("counts") or {},
                "worker_alive": False,
                "bundle_sha256": bundle_hash,
                "archived_count": len(archived_ids),
                "terminal_count": len(terminal),
                "incomplete_count": len(incomplete),
                "completed_at": timestamp,
            }
            journal = {
                "schema": "openclaw.youtube.windows-finalization.v2",
                "state": "prepared",
                "prepared_at": timestamp,
                "canary_id": canary_id,
                "lease_id": lease_id,
                "bundle_sha256": bundle_hash,
                "event_id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"youtube-canary-import:{lease_id}:{bundle_hash}")),
                "preimages": preimages,
                "lease_preimage": lease,
                "chunk_preimage": read_json(global_chunk_path, {}) or {},
                "target_items": target_items,
                "target_lease": target_lease,
                "target_chunk": target_chunk,
                "target_manifest_fields": target_manifest_fields,
            }
            journal["journal_sha256"] = journal_digest(journal)
            atomic_json(journal_path, journal)

        for path, preimage_key, target_key in ((lease_path, "lease_preimage", "target_lease"), (global_chunk_path, "chunk_preimage", "target_chunk")):
            current = read_json(path, {}) or {}
            if current != journal.get(preimage_key) and current != journal.get(target_key):
                raise GP.PoolError("Windows finalization lease/chunk replay conflict")
        for video_id, target in sorted((journal.get("target_items") or {}).items()):
            current = store.load_item(video_id)
            preimage = (journal.get("preimages") or {}).get(video_id)
            if current != target and current != preimage:
                raise GP.PoolError(f"canary finalization replay conflict: {video_id}")
            if current != target:
                store.save_item(target)
        atomic_json(global_chunk_path, journal["target_chunk"])
        append_global_event_once(
            store,
            str(journal["event_id"]),
            "canary_imported",
            canary_id=canary_id,
            lease_id=lease_id,
            archived_count=len(archived_ids),
            terminal_count=len(terminal),
            incomplete_count=len(incomplete),
            video_ids=sorted(archived_ids),
            cookies_used=False,
            media_files=0,
        )
        atomic_json(lease_path, journal["target_lease"])
        store.write_state()
        journal["state"] = "committed"
        journal["committed_at"] = utcnow()
        atomic_json(journal_path, journal)
    final_state = "completed" if not incomplete else "partial"
    target_manifest_fields = journal.get("target_manifest_fields") or {
        "archived_count": len(archived_ids),
        "terminal_count": len(terminal),
        "incomplete_count": len(incomplete),
        "completed_at": timestamp,
        "bundle_sha256": bundle_hash,
        "remote_state": str(remote.get("state") or ""),
        "remote_summary": remote_summary(remote),
        "remote_counts": remote.get("counts") if isinstance(remote.get("counts"), dict) else {},
        "worker_alive": False,
    }
    update_canary_state(root, final_state, **target_manifest_fields)
