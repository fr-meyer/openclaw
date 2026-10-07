#!/usr/bin/env python3
from __future__ import annotations

import argparse
import bz2
import ctypes
import datetime as dt
import gzip
import hashlib
import json
import lzma
import os
import re
import tarfile
import tempfile
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

MEDIA_EXTENSIONS = {
    ".mp4", ".mkv", ".webm", ".mov", ".avi", ".m4v",
    ".mp3", ".m4a", ".aac", ".wav", ".flac", ".ogg", ".opus",
}
TERMINAL_NON_ARCHIVE_STATES = {"skipped_private", "skipped_age_restricted", "skipped_unavailable"}
# Bounded caption-only imports, including tar headers, padding and metadata.
MAX_BUNDLE_BYTES = 16 * 1024 * 1024
MAX_TAR_BYTES = 128 * 1024 * 1024
MAX_EXTRACTED_BYTES = 96 * 1024 * 1024
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_TAR_MEMBERS = 4096


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def ensure_directory_durable(path: Path, *, mode: int = 0o777) -> None:
    missing = []
    current = path
    while not current.exists():
        missing.append(current)
        current = current.parent
    path.mkdir(parents=True, exist_ok=True, mode=mode)
    for directory in reversed(missing):
        fsync_directory(directory.parent)


def atomic_json(path: Path, payload: Any) -> None:
    ensure_directory_durable(path.parent)
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)
    directory_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def decompress_zstd(source: Path, target: Path) -> None:
    if source.stat().st_size > MAX_BUNDLE_BYTES:
        raise ValueError("compressed bundle exceeds import budget")
    candidates = (
        "/lib/x86_64-linux-gnu/libzstd.so.1",
        "/usr/lib/x86_64-linux-gnu/libzstd.so.1",
        "libzstd.so.1",
    )
    lib = None
    for candidate in candidates:
        try:
            lib = ctypes.CDLL(candidate)
            break
        except OSError:
            continue
    if lib is None:
        raise RuntimeError("libzstd.so.1 is unavailable")

    class InBuffer(ctypes.Structure):
        _fields_ = [("src", ctypes.c_void_p), ("size", ctypes.c_size_t), ("pos", ctypes.c_size_t)]

    class OutBuffer(ctypes.Structure):
        _fields_ = [("dst", ctypes.c_void_p), ("size", ctypes.c_size_t), ("pos", ctypes.c_size_t)]

    lib.ZSTD_createDStream.restype = ctypes.c_void_p
    lib.ZSTD_freeDStream.argtypes = [ctypes.c_void_p]
    lib.ZSTD_freeDStream.restype = ctypes.c_size_t
    lib.ZSTD_initDStream.argtypes = [ctypes.c_void_p]
    lib.ZSTD_initDStream.restype = ctypes.c_size_t
    lib.ZSTD_DStreamOutSize.restype = ctypes.c_size_t
    lib.ZSTD_decompressStream.argtypes = [ctypes.c_void_p, ctypes.POINTER(OutBuffer), ctypes.POINTER(InBuffer)]
    lib.ZSTD_decompressStream.restype = ctypes.c_size_t
    lib.ZSTD_isError.argtypes = [ctypes.c_size_t]
    lib.ZSTD_isError.restype = ctypes.c_uint

    with source.open("rb") as handle:
        compressed = handle.read(MAX_BUNDLE_BYTES + 1)
    if len(compressed) > MAX_BUNDLE_BYTES:
        raise ValueError("compressed bundle exceeds import budget")
    source_buffer = ctypes.create_string_buffer(compressed)
    in_buffer = InBuffer(ctypes.cast(source_buffer, ctypes.c_void_p), len(compressed), 0)
    stream = lib.ZSTD_createDStream()
    if not stream:
        raise RuntimeError("ZSTD_createDStream failed")
    try:
        result = lib.ZSTD_initDStream(stream)
        if lib.ZSTD_isError(result):
            raise RuntimeError(f"ZSTD_initDStream failed: {result}")
        chunk_size = max(131072, int(lib.ZSTD_DStreamOutSize()))
        expanded = 0
        with target.open("wb") as output:
            while True:
                output_buffer_raw = ctypes.create_string_buffer(chunk_size)
                output_buffer = OutBuffer(ctypes.cast(output_buffer_raw, ctypes.c_void_p), chunk_size, 0)
                result = lib.ZSTD_decompressStream(stream, ctypes.byref(output_buffer), ctypes.byref(in_buffer))
                if lib.ZSTD_isError(result):
                    raise RuntimeError(f"ZSTD_decompressStream failed: {result}")
                if output_buffer.pos:
                    expanded += int(output_buffer.pos)
                    if expanded > MAX_TAR_BYTES:
                        raise ValueError("decompressed tar exceeds import budget")
                    output.write(output_buffer_raw.raw[: output_buffer.pos])
                if result == 0 and in_buffer.pos == in_buffer.size:
                    break
                if output_buffer.pos == 0 and in_buffer.pos == in_buffer.size:
                    raise RuntimeError("truncated zstd frame")
    finally:
        lib.ZSTD_freeDStream(stream)


def bounded_tar(source: Path, target: Path) -> None:
    """Materialize only a bounded plain tar, before parsing any tar metadata."""
    if source.stat().st_size > MAX_BUNDLE_BYTES:
        raise ValueError("compressed bundle exceeds import budget")
    if source.name.endswith(".tar.zst"):
        decompress_zstd(source, target)
        return
    with source.open("rb") as handle:
        magic = handle.read(6)
    opener = (gzip.open if magic.startswith(b"\x1f\x8b") else
              bz2.open if magic.startswith(b"BZh") else
              lzma.open if magic.startswith(b"\xfd7zXZ\x00") else open)
    expanded = 0
    with opener(source, "rb") as compressed, target.open("wb") as output:
        while block := compressed.read(65536):
            expanded += len(block)
            if expanded > MAX_TAR_BYTES:
                raise ValueError("decompressed tar exceeds import budget")
            output.write(block)


def extract_bounded_tar(tar_path: Path, staging: Path) -> None:
    # The plain-tar budget already bounds PAX/GNU metadata and padding. Iterate
    # members instead of building an unbounded getmembers() inventory.
    normalized: set[str] = set()
    total = 0
    count = 0
    with tarfile.open(tar_path, "r|") as tf:
        for member in tf:
            count += 1
            if count > MAX_TAR_MEMBERS:
                raise ValueError("tar member count exceeds import budget")
            text = member.name.replace("\\", "/")
            path = PurePosixPath(text)
            windows = PureWindowsPath(member.name)
            name = path.as_posix().rstrip("/")
            if not name or name in normalized:
                raise ValueError("empty or duplicate tar member")
            normalized.add(name)
            if path.is_absolute() or windows.is_absolute() or windows.drive or ".." in path.parts:
                raise ValueError("unsafe tar path")
            if not member.isdir() and not member.isreg():
                raise ValueError("unsupported tar member type")
            if not path.parts or path.parts[0] not in {"archive", "status.json", "events.jsonl", "urls.tsv"}:
                raise ValueError("unexpected tar root")
            if path.parts[0] != "archive" and (len(path.parts) != 1 or not member.isreg()):
                raise ValueError("unexpected tar metadata path")
            if member.size < 0 or member.size > MAX_MEMBER_BYTES or (member.isdir() and member.size):
                raise ValueError("tar member size exceeds import budget")
            total += member.size
            if total > MAX_EXTRACTED_BYTES:
                raise ValueError("tar extracted size exceeds import budget")
            destination = staging.joinpath(*path.parts)
            if member.isdir():
                ensure_directory_durable(destination)
                fsync_directory(destination)
                continue
            ensure_directory_durable(destination.parent)
            with tf.extractfile(member) as source, destination.open("xb") as output:
                copied = 0
                while block := source.read(65536):
                    copied += len(block)
                    if copied > member.size:
                        raise ValueError("tar member expanded beyond declared size")
                    output.write(block)
                if copied != member.size:
                    raise ValueError("truncated tar member")
                output.flush()
                os.fsync(output.fileno())
            fsync_directory(destination.parent)


def validate_archive(folder: Path, video_id: str) -> dict[str, Any]:
    manifest_path = folder / "manifest.json"
    report_path = folder / "report.md"
    if not manifest_path.is_file() or not report_path.is_file():
        raise ValueError(f"{video_id}: missing manifest.json or report.md")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("video_id") != video_id:
        raise ValueError(f"{video_id}: manifest identity mismatch")
    files = manifest.get("files") or []
    if not isinstance(files, list) or not files:
        raise ValueError(f"{video_id}: manifest files list missing or empty")
    for raw in files:
        raw_text = str(raw)
        posix = PurePosixPath(raw_text.replace("\\", "/"))
        windows = PureWindowsPath(raw_text)
        if (
            posix.is_absolute()
            or windows.is_absolute()
            or bool(windows.drive)
            or ".." in posix.parts
            or ".." in windows.parts
        ):
            raise ValueError(f"{video_id}: unsafe manifest path {raw}")
        rel = Path(*posix.parts)
        if not (folder / rel).is_file():
            raise ValueError(f"{video_id}: missing listed file {raw}")
    media = [str(p.relative_to(folder)) for p in folder.rglob("*") if p.is_file() and p.suffix.lower() in MEDIA_EXTENSIONS]
    if media:
        raise ValueError(f"{video_id}: media files found {media[:10]}")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--project-root", required=True)
    parser.add_argument("--archive-root", required=True)
    parser.add_argument("--chunk-id", required=True)
    args = parser.parse_args()

    bundle = Path(args.bundle).resolve()
    project_root = Path(args.project_root).resolve()
    archive_root = Path(args.archive_root).resolve()
    if bundle.stat().st_size > MAX_BUNDLE_BYTES:
        raise ValueError("compressed bundle exceeds import budget")
    actual_sha = sha256_file(bundle)
    if actual_sha != args.expected_sha256:
        raise SystemExit(f"bundle SHA-256 mismatch: {actual_sha} != {args.expected_sha256}")

    ensure_directory_durable(archive_root, mode=0o700)
    staging_parent = archive_root / ".import-staging"
    ensure_directory_durable(staging_parent, mode=0o700)
    if staging_parent.stat().st_dev != archive_root.stat().st_dev:
        raise ValueError("import staging and archive destination are on different filesystems")
    with tempfile.TemporaryDirectory(prefix=f"yc-chunk-{args.chunk_id}-", dir=str(staging_parent)) as work_raw:
        work = Path(work_raw)
        tar_path = work / "bundle.tar"
        bounded_tar(bundle, tar_path)
        staging = work / "staging"
        ensure_directory_durable(staging)
        extract_bounded_tar(tar_path, staging)

        status = json.loads((staging / "status.json").read_text(encoding="utf-8"))
        remote_state = status.get("state")
        if remote_state not in {"complete", "complete_with_blocked"}:
            raise ValueError(f"chunk state is not importable: {remote_state}")
        if status.get("cookies_used") is not False or status.get("media_downloaded") is not False:
            raise ValueError("chunk safety flags are not false")
        requested_video_ids = []
        for line in (staging / "urls.tsv").read_text(encoding="utf-8").splitlines():
            video_id, url = line.split("\t", 1)
            if not re.fullmatch(r"[A-Za-z0-9_-]{11}", video_id) or url != f"https://www.youtube.com/watch?v={video_id}":
                raise ValueError(f"URL does not match video ID: {video_id}")
            requested_video_ids.append(video_id)
        if not requested_video_ids or len(requested_video_ids) > 25 or len(requested_video_ids) != len(set(requested_video_ids)):
            raise ValueError(f"invalid chunk ID count: {len(requested_video_ids)}")
        status_items = status.get("items") or {}
        if not isinstance(status_items, dict) or set(status_items) != set(requested_video_ids):
            raise ValueError("status item set does not match urls.tsv")
        for video_id in requested_video_ids:
            item = status_items[video_id]
            attempts = item.get("attempts") if isinstance(item, dict) else None
            # The paired Windows worker has a three-attempt lifetime budget;
            # adoption of an already valid archive may legitimately use zero.
            if type(attempts) is not int or not 0 <= attempts <= 3:
                raise ValueError(f"{video_id}: invalid remote attempt counter")
        chunk_path = project_root / "chunks" / f"{args.chunk_id}.json"
        chunk = json.loads(chunk_path.read_text(encoding="utf-8"))
        leased_items = chunk.get("items")
        if (not isinstance(leased_items, list) or any(not isinstance(row, dict) for row in leased_items)
            or [row.get("video_id") for row in leased_items] != requested_video_ids
            or any(row.get("url") != f"https://www.youtube.com/watch?v={row.get('video_id')}" for row in leased_items)):
            raise ValueError("bundle ordered video/URL bindings differ from the authoritative chunk")
        expected_lease_id = chunk.get("lease_id")
        remote_lease_id = status.get("lease_id")
        if not isinstance(expected_lease_id, str) or not expected_lease_id or expected_lease_id.strip() != expected_lease_id or not isinstance(remote_lease_id, str) or remote_lease_id != expected_lease_id:
            raise ValueError(
                f"chunk lease mismatch: remote={remote_lease_id!r} expected={expected_lease_id!r}"
            )
        archived_video_ids = [
            video_id for video_id in requested_video_ids
            if (status_items.get(video_id) or {}).get("state") == "archived"
        ]
        terminal_video_ids = [
            video_id for video_id in requested_video_ids
            if (status_items.get(video_id) or {}).get("state") in TERMINAL_NON_ARCHIVE_STATES
        ]
        if remote_state == "complete":
            # A private video is a successful terminal anonymous outcome: the
            # worker deliberately records skipped_private and produces no
            # archive directory.  Complete chunks may therefore contain a mix
            # of archived and skipped_private items, but no retryable or
            # blocked state.
            nonterminal = {
                video_id: (status_items.get(video_id) or {}).get("state")
                for video_id in requested_video_ids
                if (status_items.get(video_id) or {}).get("state")
                not in {"archived", *TERMINAL_NON_ARCHIVE_STATES}
            }
            if nonterminal:
                raise ValueError(f"complete chunk contains nonterminal items: {nonterminal}")
        # A complete_with_blocked worker checkpoint may legitimately contain
        # no archives (for example, when an older worker stopped after each of
        # its first exhausted items).  Import the status-only bundle so the
        # active chunk can be closed transactionally and all incomplete rows
        # become eligible for a later bounded retry.
        incomplete_items = [
            {
                "video_id": video_id,
                "state": (status_items.get(video_id) or {}).get("state"),
                "attempts": status_items[video_id]["attempts"],
                "failure_class": (status_items.get(video_id) or {}).get("failure_class"),
                "error": (status_items.get(video_id) or {}).get("error"),
            }
            for video_id in requested_video_ids
            if video_id not in set(archived_video_ids) | set(terminal_video_ids)
        ]
        terminal_items = [
            {
                "video_id": video_id,
                "state": (status_items.get(video_id) or {}).get("state"),
                "attempts": status_items[video_id]["attempts"],
                "failure_class": (status_items.get(video_id) or {}).get("failure_class"),
                "error": (status_items.get(video_id) or {}).get("error"),
            }
            for video_id in terminal_video_ids
        ]

        source_archive = staging / "archive"
        source_dirs = {p.name for p in source_archive.iterdir() if p.is_dir()}
        if source_dirs != set(archived_video_ids):
            raise ValueError("archive directory set does not match archived status items")
        for video_id in archived_video_ids:
            validate_archive(source_archive / video_id, video_id)

        conflicts = []
        reused = []
        for video_id in archived_video_ids:
            destination = archive_root / video_id
            if destination.exists():
                try:
                    validate_archive(destination, video_id)
                    reused.append(video_id)
                except Exception as exc:
                    conflicts.append({"video_id": video_id, "error": str(exc)})
        if conflicts:
            raise ValueError(f"conflicting destination archives: {conflicts}")

        transaction_path = project_root / "imports" / f"chunk-{args.chunk_id}.transaction.json"
        prior_transaction = (
            json.loads(transaction_path.read_text(encoding="utf-8"))
            if transaction_path.is_file()
            else None
        )
        if prior_transaction is not None and (
            prior_transaction.get("schema") != "franck.youtube-catalog-chunk-import-transaction.v1"
            or prior_transaction.get("chunk_id") != args.chunk_id
            or prior_transaction.get("bundle_sha256") != actual_sha
        ):
            raise ValueError("existing import transaction does not match this chunk bundle")
        if prior_transaction is not None and prior_transaction.get("phase") == "committed":
            evidence_path = project_root / "imports" / f"chunk-{args.chunk_id}.json"
            evidence = json.loads(evidence_path.read_text()) if evidence_path.is_file() else {}
            expected = {
                "schema": "franck.youtube-catalog-chunk-import.v1", "chunk_id": args.chunk_id,
                "bundle_sha256": actual_sha, "remote_state": remote_state,
                "requested_count": len(requested_video_ids), "video_count": len(archived_video_ids),
                "requested_video_ids": requested_video_ids, "video_ids": archived_video_ids,
                "terminal_video_ids": terminal_video_ids, "terminal_items": terminal_items,
                "terminal_count": len(terminal_items), "incomplete_count": len(incomplete_items),
                "incomplete_items": incomplete_items, "cookies_used": False,
                "media_files": 0, "validated": True,
            }
            actual = {key: evidence.get(key) for key in expected}
            if json.dumps(actual, sort_keys=True) != json.dumps(expected, sort_keys=True) or prior_transaction.get("planned_video_ids") != archived_video_ids or set(reused) != set(archived_video_ids):
                raise ValueError("committed import artifacts differ from the validated bundle")
            # A delayed delivery must not resurrect a chunk/queue after catalog
            # completion. Keep the original receipt, transaction and states.
            print(json.dumps({"state": chunk.get("state"), **{key: evidence[key] for key in (
                "chunk_id", "requested_count", "video_count", "imported_count", "reused_count",
                "terminal_count", "incomplete_count", "bundle_sha256",
            )}}, ensure_ascii=False, indent=2))
            return 0
        transaction = {
            "schema": "franck.youtube-catalog-chunk-import-transaction.v1",
            "chunk_id": args.chunk_id,
            "bundle_sha256": actual_sha,
            "phase": "prepared",
            "updated_at": now(),
            "planned_video_ids": archived_video_ids,
            "moved_video_ids": list((prior_transaction or {}).get("moved_video_ids") or []),
            "same_filesystem": True,
        }
        atomic_json(transaction_path, transaction)

        imported = []
        moved_this_run: list[str] = []
        try:
            for video_id in archived_video_ids:
                source = source_archive / video_id
                destination = archive_root / video_id
                if destination.exists():
                    continue
                if source.stat().st_dev != archive_root.stat().st_dev:
                    raise ValueError(f"{video_id}: staging crossed the archive filesystem boundary")
                os.rename(source, destination)
                fsync_directory(archive_root)
                imported.append(video_id)
                moved_this_run.append(video_id)
                transaction["phase"] = "moving"
                transaction["updated_at"] = now()
                transaction["moved_video_ids"] = sorted(
                    set(transaction["moved_video_ids"]) | {video_id}
                )
                atomic_json(transaction_path, transaction)
        except BaseException:
            rolled_back: list[str] = []
            for video_id in reversed(moved_this_run):
                source = source_archive / video_id
                destination = archive_root / video_id
                if destination.is_dir() and not source.exists():
                    os.rename(destination, source)
                    fsync_directory(archive_root)
                    rolled_back.append(video_id)
            transaction.update({
                "phase": "failed_rolled_back",
                "updated_at": now(),
                "rolled_back_video_ids": sorted(rolled_back),
                "moved_video_ids": sorted(
                    set(transaction["moved_video_ids"]) - set(rolled_back)
                ),
            })
            atomic_json(transaction_path, transaction)
            raise
        for video_id in archived_video_ids:
            validate_archive(archive_root / video_id, video_id)

        evidence = {
            "schema": "franck.youtube-catalog-chunk-import.v1",
            "chunk_id": args.chunk_id,
            "imported_at": now(),
            "bundle_path": str(bundle),
            "bundle_sha256": actual_sha,
            "remote_state": remote_state,
            "requested_count": len(requested_video_ids),
            "video_count": len(archived_video_ids),
            "imported_count": len(imported),
            "reused_count": len(reused),
            "terminal_count": len(terminal_items),
            "incomplete_count": len(incomplete_items),
            "requested_video_ids": requested_video_ids,
            "video_ids": archived_video_ids,
            "imported_video_ids": imported,
            "reused_video_ids": reused,
            "terminal_video_ids": terminal_video_ids,
            "terminal_items": terminal_items,
            "incomplete_items": incomplete_items,
            "cookies_used": False,
            "media_files": 0,
            "validated": True,
        }
        atomic_json(project_root / "imports" / f"chunk-{args.chunk_id}.json", evidence)

        # Importing files and rebuilding the central catalog are one logical
        # transaction.  Do not clear the active chunk yet: an interruption
        # after moving artifacts but before the catalog rebuild must retry
        # idempotently from this durable bundle, not launch a new chunk.
        pending_chunk_state = (
            "imported_pending_catalog_rebuild"
            if not incomplete_items
            else "partial_imported_pending_catalog_rebuild"
        )
        chunk.update({
            "state": pending_chunk_state,
            "remote_state": remote_state,
            "imported_at": evidence["imported_at"],
            "bundle_sha256": actual_sha,
            "imported_count": len(imported),
            "reused_count": len(reused),
            "terminal_count": len(terminal_items),
            "incomplete_count": len(incomplete_items),
            "cookies_used": False,
            "media_files": 0,
        })
        archived_set = set(archived_video_ids)
        for item in chunk.get("items") or []:
            video_id = str(item.get("video_id"))
            remote_item = status_items.get(video_id) or {}
            item["attempt_count"] = remote_item["attempts"]
            if video_id in archived_set:
                item["state"] = "imported"
                item["failure_class"] = None
                item["error"] = None
            else:
                item["state"] = remote_item.get("state") or "pending"
                item["failure_class"] = remote_item.get("failure_class")
                item["error"] = remote_item.get("error")
        atomic_json(chunk_path, chunk)

        queue_state_path = project_root / "queue" / "state.json"
        queue_state = json.loads(queue_state_path.read_text(encoding="utf-8")) if queue_state_path.is_file() else {}
        queue_state.update({
            "state": pending_chunk_state,
            "updated_at": evidence["imported_at"],
            "current_chunk": args.chunk_id,
            "last_imported_chunk": args.chunk_id,
            "last_imported_count": len(archived_video_ids),
            "last_incomplete_count": len(incomplete_items),
            "catalog_rebuild_required": True,
            "blocker": None,
            "last_error": None,
            "cookies_used": False,
            "media_files": 0,
        })
        atomic_json(queue_state_path, queue_state)
        transaction.update({
            "phase": "committed",
            "updated_at": now(),
            "evidence_path": str(project_root / "imports" / f"chunk-{args.chunk_id}.json"),
        })
        atomic_json(transaction_path, transaction)

    print(json.dumps({
        "state": pending_chunk_state,
        "chunk_id": args.chunk_id,
        "requested_count": len(requested_video_ids),
        "video_count": len(archived_video_ids),
        "imported_count": len(imported),
        "reused_count": len(reused),
        "terminal_count": len(terminal_items),
        "incomplete_count": len(incomplete_items),
        "bundle_sha256": actual_sha,
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
