#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

CODE_ROOT = Path(__file__).resolve().parent
WORKSPACE = CODE_ROOT.parents[1]
sys.path.insert(0, str(WORKSPACE / "scripts"))
import youtube_storage as STORAGE

_CANONICAL_WRITE_CONTEXT: dict[str, Any] | None = None

MEDIA_EXTENSIONS = {
    ".mp4", ".mkv", ".webm", ".mov", ".avi", ".m4v",
    ".mp3", ".m4a", ".aac", ".wav", ".flac", ".ogg", ".opus",
}
KNOWN_COMPLETE_STATUSES = {
    "created", "refreshed", "reused", "transcript-archived",
    "metadata-only-no-captions", "archived", "complete",
}
TERMINAL_NON_ARCHIVE_STATES = {"skipped_private", "skipped_age_restricted", "skipped_unavailable"}
TERMINAL_CHUNK_STATES = {
    "imported_pending_catalog_rebuild", "partial_imported_pending_catalog_rebuild",
    "imported", "partial_imported",
}


def load_terminal_outcomes(project_root: Path, inventory_ids: set[str] | None = None) -> dict[str, dict[str, Any]]:
    """Load only outcomes that reached the durable central import boundary."""
    outcomes: dict[str, dict[str, Any]] = {}
    for path in sorted((project_root / "chunks").glob("[0-9][0-9][0-9][0-9].json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        if str(payload.get("state") or "") not in TERMINAL_CHUNK_STATES:
            continue
        for item in payload.get("items") or []:
            state = str(item.get("state") or "")
            if state not in TERMINAL_NON_ARCHIVE_STATES:
                continue
            video_id = str(item.get("video_id") or "")
            if not video_id:
                raise ValueError(f"terminal item without video_id in {path.name}")
            outcome = {
                "state": state,
                "chunk_id": path.stem,
                "attempt_count": int(item.get("attempt_count") or item.get("attempts") or 0),
                "failure_class": item.get("failure_class"),
                "error": item.get("error"),
            }
            prior = outcomes.get(video_id)
            if prior and prior["state"] != state:
                raise ValueError(f"conflicting terminal outcomes for {video_id}: {prior['state']} vs {state}")
            outcomes[video_id] = outcome
    # Windows global imports live outside the YC chunk tree. Consume their
    # durable validated partition, projected before the catalog rebuild.
    for path in sorted((project_root / "imports/windows-canaries").glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        requested = payload.get("requested_video_ids") or []
        archived = payload.get("video_ids") or []
        terminal = payload.get("terminal_items") or []
        incomplete = payload.get("incomplete_items") or []
        terminal_ids = [str(row.get("video_id") or "") for row in terminal]
        incomplete_ids = [str(row.get("video_id") or "") for row in incomplete]
        partitions = (set(archived), set(terminal_ids), set(incomplete_ids))
        if (payload.get("schema") != "openclaw.youtube.windows-source-outcomes.v1"
            or payload.get("validated") is not True or not payload.get("bundle_sha256")
            or payload.get("canary_id") != path.stem or not requested
            or len(requested) != len(set(requested)) or len(archived) != len(set(archived))
            or len(terminal_ids) != len(set(terminal_ids)) or len(incomplete_ids) != len(set(incomplete_ids))
            or set(requested) != set().union(*partitions)
            or partitions[0] & partitions[1] or partitions[0] & partitions[2] or partitions[1] & partitions[2]
            or any(row.get("state") not in TERMINAL_NON_ARCHIVE_STATES for row in terminal)):
            raise ValueError("Windows catalog outcome partition invalid")
        for row in terminal:
            video_id = str(row["video_id"])
            if inventory_ids is not None and video_id not in inventory_ids:
                continue
            outcome = {"state": row["state"], "chunk_id": payload["canary_id"], "attempt_count": int(row.get("attempts") or 0),
                       "failure_class": row.get("failure_class"), "error": row.get("error")}
            prior = outcomes.get(video_id)
            if prior and prior["state"] != outcome["state"]:
                raise ValueError("conflicting imported terminal outcomes")
            outcomes[video_id] = outcome
    return outcomes


def classify_video_ids(
    unique_ids: list[str],
    validations: dict[str, dict[str, Any]],
    terminal_outcomes: dict[str, dict[str, Any]],
) -> tuple[list[str], list[str], list[str]]:
    """Return archived, terminal-no-archive, and genuinely pending IDs."""
    complete_ids = [video_id for video_id in unique_ids if validations[video_id]["complete"]]
    terminal_ids = [
        video_id for video_id in unique_ids
        if not validations[video_id]["complete"] and video_id in terminal_outcomes
    ]
    pending_ids = [
        video_id for video_id in unique_ids
        if not validations[video_id]["complete"] and video_id not in terminal_outcomes
    ]
    return complete_ids, terminal_ids, pending_ids


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def ensure_directory_durable(path: Path) -> None:
    missing = []
    current = path
    while not current.exists():
        missing.append(current)
        current = current.parent
    path.mkdir(parents=True, exist_ok=True)
    for directory in reversed(missing):
        fsync_directory(directory.parent)


def atomic_write(path: Path, text: str) -> None:
    if path.suffix.lower() == ".md" and _CANONICAL_WRITE_CONTEXT is not None:
        STORAGE.write_canonical_text(path, text, **_CANONICAL_WRITE_CONTEXT)
        return
    ensure_directory_durable(path.parent)
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)
    fsync_directory(path.parent)


def atomic_json(path: Path, payload: Any) -> None:
    atomic_write(path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")


def validate_archive(archive_root: Path, video_id: str) -> dict[str, Any]:
    folder = archive_root / video_id
    manifest_path = folder / "manifest.json"
    report_path = folder / "report.md"
    result: dict[str, Any] = {
        "video_id": video_id,
        "complete": False,
        "report_path": None,
        "transcript_path": None,
        "language": None,
        "transcript_source": None,
        "status": "absent",
        "errors": [],
    }
    if not folder.is_dir():
        return result
    result["status"] = "incomplete"
    if not manifest_path.is_file():
        result["errors"].append("missing manifest.json")
        return result
    if not report_path.is_file():
        result["errors"].append("missing report.md")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        result["errors"].append(f"invalid manifest.json: {exc}")
        return result
    if manifest.get("video_id") != video_id:
        result["errors"].append(f"manifest video_id mismatch: {manifest.get('video_id')!r}")
    status = str(manifest.get("status") or "")
    if status and status not in KNOWN_COMPLETE_STATUSES:
        # Preserve forward compatibility: file validation is authoritative, but expose the unknown status.
        result["unknown_helper_status"] = status
    rel_files = manifest.get("files") or []
    if not isinstance(rel_files, list) or not rel_files:
        result["errors"].append("manifest files list missing or empty")
        rel_files = []
    safe_files: list[str] = []
    for raw in rel_files:
        rel = Path(str(raw))
        if rel.is_absolute() or ".." in rel.parts:
            result["errors"].append(f"unsafe manifest path: {raw}")
            continue
        target = folder / rel
        if not target.is_file():
            result["errors"].append(f"missing listed file: {raw}")
        else:
            safe_files.append(str(rel))
    media = [str(p.relative_to(folder)) for p in folder.rglob("*") if p.is_file() and p.suffix.lower() in MEDIA_EXTENSIONS]
    if media:
        result["errors"].append(f"unexpected media files: {media[:10]}")
    source = manifest.get("transcript_source")
    if source != "none":
        transcript_candidates = [
            rel for rel in safe_files
            if rel.startswith("transcript/") and rel.endswith(("clean-deduped.txt", "timestamped-deduped.txt", "clean.txt", "timestamped.txt"))
        ]
        if not transcript_candidates:
            result["errors"].append("caption-backed manifest has no listed transcript artifact")
        else:
            preference = ("clean-deduped.txt", "timestamped-deduped.txt", "clean.txt", "timestamped.txt")
            for suffix in preference:
                match = next((rel for rel in transcript_candidates if rel.endswith(suffix)), None)
                if match:
                    result["transcript_path"] = str(folder / match)
                    break
    result["language"] = manifest.get("language")
    result["transcript_source"] = source
    result["helper_status"] = status or None
    if not result["errors"]:
        result["complete"] = True
        result["status"] = "metadata_only_no_captions" if source == "none" else "caption_backed_complete"
        result["report_path"] = str(report_path)
    return result


def build(args: argparse.Namespace) -> dict[str, Any]:
    project_root = Path(args.project_root).resolve()
    source_root = project_root / args.source_dir
    archive_root = Path(args.archive_root).resolve()
    inventory = json.loads((source_root / "inventory.json").read_text(encoding="utf-8"))
    status = json.loads((source_root / "status.json").read_text(encoding="utf-8"))
    if (status.get("state") != "complete" or status.get("cookies_used") is not False
        or status.get("media_downloaded") is not False):
        raise ValueError("catalog requires a complete anonymous caption-only inventory")
    if (inventory.get("playlist_count") != 52 or inventory.get("top_level_counts") != {"playlists": 52, "podcasts": 4}
        or inventory.get("unresolved_count") != 0):
        raise ValueError("catalog inventory cardinality or resolution differs")

    playlist_order = [row["id"] for row in inventory["top_level_entries"]["playlists"]]
    podcast_order = [row["id"] for row in inventory["top_level_entries"]["podcasts"]]
    playlist_set = set(playlist_order)
    if (len(playlist_order) != 52 or len(playlist_set) != 52
        or len(podcast_order) != 4 or len(set(podcast_order)) != 4
        or not set(podcast_order).issubset(playlist_set)):
        raise ValueError("catalog playlist or podcast identity partition differs")

    memberships: list[dict[str, Any]] = []
    by_video: dict[str, list[dict[str, Any]]] = defaultdict(list)
    playlist_rows: list[dict[str, Any]] = []
    first_seen: dict[str, int] = {}
    occurrence_counter = 0

    for surface_position, playlist_id in enumerate(playlist_order, 1):
        playlist = inventory["playlists"][playlist_id]
        roles = ["playlist"] + (["podcast"] if playlist_id in set(podcast_order) else [])
        members: list[dict[str, Any]] = []
        for occurrence_position, entry in enumerate(playlist.get("entries") or [], 1):
            occurrence_counter += 1
            video_id = entry.get("id")
            occurrence_id = f"{playlist_id}:{occurrence_position}"
            membership = {
                "occurrence_id": occurrence_id,
                "playlist_id": playlist_id,
                "playlist_title": playlist.get("title"),
                "surface_roles": roles,
                "surface_position": surface_position,
                "occurrence_position": occurrence_position,
                "video_id": video_id,
                "title": entry.get("title"),
                "url": entry.get("url"),
                "duration": entry.get("duration"),
                "availability": "resolvable" if video_id else "unresolved",
            }
            memberships.append(membership)
            members.append(membership)
            if video_id:
                by_video[str(video_id)].append(membership)
                first_seen.setdefault(str(video_id), occurrence_counter)
        playlist_rows.append({
            "playlist_id": playlist_id,
            "title": playlist.get("title"),
            "url": playlist.get("url"),
            "surface_position": surface_position,
            "surface_roles": roles,
            "is_podcast_feed": playlist_id in set(podcast_order),
            "entry_count": len(members),
            "memberships": members,
        })

    unique_ids = sorted(by_video, key=lambda vid: (first_seen[vid], vid))
    if len(unique_ids) != 792 or inventory.get("unique_video_count") != 792:
        raise ValueError("catalog unique-video inventory differs")
    unresolved = [row for row in memberships if not row.get("video_id")]
    if len(unresolved) != 0 or inventory.get("unresolved_count") != 0:
        raise ValueError("catalog contains unresolved source entries")

    validations = {video_id: validate_archive(archive_root, video_id) for video_id in unique_ids}
    terminal_outcomes = load_terminal_outcomes(project_root, set(unique_ids))
    unknown_terminal_ids = sorted(set(terminal_outcomes) - set(unique_ids))
    if unknown_terminal_ids:
        raise ValueError(f"terminal outcomes reference unknown inventory IDs: {unknown_terminal_ids[:10]}")
    complete_ids, terminal_ids, missing_ids = classify_video_ids(
        unique_ids, validations, terminal_outcomes
    )
    partial_ids = [video_id for video_id in missing_ids if validations[video_id]["status"] == "incomplete"]
    absent_ids = [video_id for video_id in missing_ids if validations[video_id]["status"] == "absent"]
    overlaps = [
        {
            "video_id": video_id,
            "occurrence_count": len(by_video[video_id]),
            "playlist_count": len({row["playlist_id"] for row in by_video[video_id]}),
            "memberships": [row["occurrence_id"] for row in by_video[video_id]],
        }
        for video_id in unique_ids if len(by_video[video_id]) > 1
    ]
    cross_playlist = [row for row in overlaps if row["playlist_count"] > 1]

    video_rows = []
    for video_id in unique_ids:
        validation = validations[video_id]
        first = by_video[video_id][0]
        video_rows.append({
            "video_id": video_id,
            "canonical_url": f"https://www.youtube.com/watch?v={video_id}",
            "title": first.get("title"),
            "archive": validation,
            "terminal_outcome": terminal_outcomes.get(video_id),
            "membership_count": len(by_video[video_id]),
            "playlist_count": len({row["playlist_id"] for row in by_video[video_id]}),
            "memberships": [row["occurrence_id"] for row in by_video[video_id]],
        })

    generated_at = utc_now()
    summary = {
        "playlist_count": len(playlist_rows),
        "podcast_feed_count": len(podcast_order),
        "membership_occurrence_count": len(memberships),
        "unique_video_count": len(unique_ids),
        "cross_source_duplicate_video_count": inventory.get("cross_source_duplicate_video_count"),
        "duplicate_occurrence_video_count": len(overlaps),
        "cross_playlist_overlap_video_count": len(cross_playlist),
        "complete_existing_count": len(complete_ids),
        "terminal_without_archive_count": len(terminal_ids),
        "terminal_private_count": sum(
            terminal_outcomes[video_id]["state"] == "skipped_private" for video_id in terminal_ids
        ),
        "terminal_unavailable_count": sum(
            terminal_outcomes[video_id]["state"] == "skipped_unavailable" for video_id in terminal_ids
        ),
        "terminal_age_restricted_count": sum(
            terminal_outcomes[video_id]["state"] == "skipped_age_restricted" for video_id in terminal_ids
        ),
        "missing_or_incomplete_count": len(missing_ids),
        "partial_count": len(partial_ids),
        "absent_count": len(absent_ids),
        "unresolved_count": len(unresolved),
        "cookies_used": False,
        "media_files": 0,
    }
    catalog = {
        "schema": "franck.youtube-catalog-transcript-archive.v1",
        "generated_at": generated_at,
        "channel_handle": inventory.get("channel_handle"),
        "source_urls": inventory.get("source_urls"),
        "source_inventory": str((source_root / "inventory.json").relative_to(project_root)),
        "policy": "anonymous trusted residential inventory; caption-only archives; no cookies; no media",
        "summary": summary,
        "podcast_feed_ids": podcast_order,
        "playlists": playlist_rows,
        "memberships": memberships,
        "videos": video_rows,
        "cross_playlist_overlaps": cross_playlist,
        "unresolved": unresolved,
    }
    atomic_json(project_root / "catalog.json", catalog)

    queue_root = project_root / "queue"
    ensure_directory_durable(queue_root)
    queue_rows = []
    for position, video_id in enumerate(missing_ids, 1):
        first = by_video[video_id][0]
        queue_rows.append({
            "schema": "franck.youtube-catalog-pending-item.v1",
            "queue_position": position,
            "video_id": video_id,
            "url": f"https://www.youtube.com/watch?v={video_id}",
            "title": first.get("title"),
            "state": "pending",
            "attempt_count": 0,
            "archive_class": validations[video_id]["status"],
            "memberships": [row["occurrence_id"] for row in by_video[video_id]],
        })
    atomic_write(queue_root / "pending.jsonl", "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in queue_rows))
    prior_queue_state: dict[str, Any] = {}
    queue_state_path = queue_root / "state.json"
    if queue_state_path.is_file():
        try:
            loaded = json.loads(queue_state_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                prior_queue_state = loaded
        except Exception:
            prior_queue_state = {}
    queue_state = dict(prior_queue_state)
    queue_state.update({
        "schema": "franck.youtube-catalog-queue-state.v1",
        "updated_at": generated_at,
        "state": "complete" if not queue_rows else prior_queue_state.get("state", "planned"),
        "total": len(queue_rows),
        "complete_existing": len(complete_ids),
        # pending.jsonl is rewritten to contain only currently missing/incomplete IDs.
        "next_pending_offset": 0,
        "launched_chunks": prior_queue_state.get("launched_chunks", []),
        "cookies_used": False,
        "media_files": 0,
    })
    atomic_json(queue_state_path, queue_state)

    chunks_root = project_root / "chunks"
    ensure_directory_durable(chunks_root)
    existing_chunk_files = sorted(chunks_root.glob("[0-9][0-9][0-9][0-9].json"))
    if not existing_chunk_files:
        first_chunk_rows = queue_rows[: min(25, int(args.chunk_size))]
        chunk = {
            "schema": "franck.youtube-catalog-chunk.v1",
            "chunk_id": "0001",
            "created_at": generated_at,
            "state": "planned",
            "max_items": min(25, int(args.chunk_size)),
            "execution_lane": "trusted-residential-anonymous",
            "cookies_used": False,
            "media_allowed": False,
            "items": first_chunk_rows,
        }
        atomic_json(chunks_root / "0001.json", chunk)
        atomic_write(chunks_root / "0001.tsv", "".join(f"{row['video_id']}\t{row['url']}\n" for row in first_chunk_rows))
        existing_chunk_files = [chunks_root / "0001.json"]
    known_chunk_count = len(existing_chunk_files)

    indexes_root = project_root / "indexes"
    for playlist in playlist_rows:
        playlist_id = playlist["playlist_id"]
        members = []
        complete_count = 0
        for membership in playlist["memberships"]:
            video_id = membership.get("video_id")
            validation = validations.get(video_id) if video_id else None
            complete = bool(validation and validation["complete"])
            complete_count += int(complete)
            members.append({**membership, "archive": validation})
        payload = {
            "schema": "franck.youtube-playlist-transcript-index.v1",
            "generated_at": generated_at,
            "playlist_id": playlist_id,
            "title": playlist["title"],
            "surface_roles": playlist["surface_roles"],
            "is_podcast_feed": playlist["is_podcast_feed"],
            "entry_count": len(members),
            "complete_occurrence_count": complete_count,
            "members": members,
        }
        atomic_json(indexes_root / "playlists" / f"{playlist_id}.json", payload)
        lines = [
            f"# {playlist['title']}", "",
            f"- Playlist ID: `{playlist_id}`",
            f"- Roles: {', '.join(playlist['surface_roles'])}",
            f"- Podcast feed: {'yes' if playlist['is_podcast_feed'] else 'no'}",
            f"- Membership occurrences: {len(members)}",
            f"- Centrally complete occurrences: {complete_count}", "",
            "## Ordered membership", "",
        ]
        for member in members:
            marker = "complete" if member.get("archive", {}).get("complete") else "pending"
            lines.append(f"{member['occurrence_position']}. `{member.get('video_id') or 'unresolved'}` — {member.get('title') or '(untitled)'} [{marker}]")
        atomic_write(indexes_root / "playlists" / f"{playlist_id}.md", "\n".join(lines) + "\n")
        if playlist["is_podcast_feed"]:
            atomic_json(indexes_root / "podcasts" / f"{playlist_id}.json", payload)
            atomic_write(indexes_root / "podcasts" / f"{playlist_id}.md", "\n".join(lines) + "\n")

    report_lines = [
        "# Y Combinator Playlists and Podcasts Transcript Catalog", "",
        f"Generated: {generated_at}", "",
        "## Inventory", "",
        f"- Playlists: **{summary['playlist_count']}**",
        f"- Podcast feeds: **{summary['podcast_feed_count']}** (also present in Playlists)",
        f"- Membership occurrences: **{summary['membership_occurrence_count']}**",
        f"- Unique video IDs: **{summary['unique_video_count']}**",
        f"- Cross-playlist overlap video IDs: **{summary['cross_playlist_overlap_video_count']}**",
        f"- Unresolved entries: **{summary['unresolved_count']}**", "",
        "## Archive state", "",
        f"- Complete existing archives: **{summary['complete_existing_count']}**",
        f"- Missing or incomplete: **{summary['missing_or_incomplete_count']}**",
        f"- Partial: **{summary['partial_count']}**",
        f"- Absent: **{summary['absent_count']}**",
        f"- Pending queue rows: **{len(queue_rows)}**",
        f"- Known bounded chunks: **{known_chunk_count}**", "",
        "## Safety", "",
        "- Inventory ran anonymously on the configured caption worker.",
        "- Cookies used: **no**.",
        "- Audio/video media files: **0**.",
        "- Extraction remains caption/metadata only, serial, paced, and stop-on-bot-check.", "",
        "## Files", "",
        "- Machine-readable catalog: `catalog.json`",
        "- Pending queue: `queue/pending.jsonl`",
        "- Queue state: `queue/state.json`",
        "- First chunk: `chunks/0001.json` and `chunks/0001.tsv`",
        "- Per-playlist indexes: `indexes/playlists/`",
        "- Podcast aliases: `indexes/podcasts/`",
        "- Immutable source snapshot: `source-inventory-20260717/`",
    ]
    atomic_write(project_root / "report.md", "\n".join(report_lines) + "\n")
    return {"summary": summary, "known_chunk_count": known_chunk_count, "pending_queue_count": len(queue_rows), "project_root": str(project_root)}


def main() -> int:
    global _CANONICAL_WRITE_CONTEXT
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", required=True)
    parser.add_argument("--source-dir", default="source-inventory-20260717")
    parser.add_argument("--archive-root", required=True)
    parser.add_argument("--state-root", default=str(STORAGE.DEFAULT_STATE_ROOT))
    parser.add_argument("--projection-root", default=str(STORAGE.DEFAULT_PROJECTION_ROOT))
    parser.add_argument("--writer-lock-held", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--chunk-size", type=int, default=25)
    args = parser.parse_args()
    if not 1 <= args.chunk_size <= 25:
        parser.error("--chunk-size must be between 1 and 25")
    project_root = Path(args.project_root).expanduser().resolve()
    state_root = Path(args.state_root).expanduser().resolve()
    if project_root.is_relative_to(state_root):
        _CANONICAL_WRITE_CONTEXT = {
            "archive_root": Path(args.archive_root).expanduser(),
            "state_root": state_root,
            "projection_root": Path(args.projection_root).expanduser(),
            "manifest_path": state_root / "projection/manifest.json",
            "lock_path": state_root / "locks/projection.lock",
            "_writer_lock_held": bool(args.writer_lock_held),
        }
    print(json.dumps(build(args), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
