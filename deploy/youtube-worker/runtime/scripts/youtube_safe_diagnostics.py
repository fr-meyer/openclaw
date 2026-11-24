"""Closed, bounded diagnostics: never put captured output into exceptions/notices."""
from __future__ import annotations

import json
import re
from typing import Any


class DiagnosticParseError(ValueError):
    pass


def parse_json_record(text: str, *, allow_prefix: bool = False) -> dict[str, Any]:
    """Accept a JSON object, optionally after complete CLI log lines.

    Raise outside the decoder's exception handler so neither its message nor
    its document is attached to the public exception's traceback/context.
    This function is for JSON records, never for singleValue secret files.
    """
    parsed: Any = None
    valid = isinstance(text, str) and len(text) <= 4 * 1024 * 1024
    if valid:
        candidate = text.lstrip("\ufeff \t\r\n")
        if allow_prefix and not candidate.startswith("{"):
            match = re.search(r"(?m)^[ \t]*\{", candidate)
            candidate = candidate[match.start():] if match else ""
        try:
            parsed = json.loads(candidate)
        except (ValueError, TypeError, RecursionError):
            valid = False
    if not valid or not isinstance(parsed, dict):
        raise DiagnosticParseError("Invalid JSON record; captured output withheld")
    return parsed


VIDEO_ID = re.compile(r"^[A-Za-z0-9_-]{11}$")
REASONS = {
    "configuration": ("Worker configuration circuit opened", "Inspect this video's stored extraction error before changing configuration"),
    "javascript_runtime_missing": ("No supported JavaScript runtime was reported", "Verify the explicit runtime path/version in the worker launch account"),
    "windows_session_logoff": ("Extractor launch was interrupted by Windows session shutdown", "Verify a stable worker session and the stopped worker before same-lease recovery"),
    "worker_session_interrupted": ("Worker extraction was interrupted by Windows session shutdown", "Verify a stable worker session and the stopped worker before same-lease recovery"),
    "bot_check": ("Anonymous extraction hit a bot check", "Review the stored failure without adding cookies or replaying the batch"),
    "auth_required": ("Anonymous extraction requires authentication", "Review this video's eligibility under the existing anonymous policy"),
    "rate_limited": ("Anonymous extraction was rate limited", "Respect the existing cooldown before coordinated recovery"),
    "unsafe_archive_boundary": ("Archive boundary validation failed", "Inspect the exact archive path before any retry"),
    "transient_timeout": ("Extraction timed out", "Verify termination and the current lease before any retry"),
    "error": ("Worker needs investigation", "Inspect this video's stored extraction error"),
    "unknown": ("Worker stopped without a recognized sanitized reason", "Inspect this video's stored extraction error"),
}


def diagnostic_from_remote(remote: dict[str, Any]) -> dict[str, Any]:
    video = remote.get("current_video_id")
    video = video if isinstance(video, str) and VIDEO_ID.fullmatch(video) else None
    items = remote.get("items") if isinstance(remote.get("items"), dict) else {}
    item = items.get(video) if isinstance(items.get(video), dict) else {}
    code = item.get("failure_class") or remote.get("circuit_reason") or "unknown"
    code = code if isinstance(code, str) and code in REASONS else "unknown"
    # Inspect bounded text to select a closed template; never copy it out.
    detail = item.get("diagnostic") or item.get("root_error") or item.get("error") or ""
    detail = detail[:4096].casefold() if isinstance(detail, str) else ""
    returncode = item.get("returncode", item.get("process_exit_code"))
    logoff = isinstance(returncode, int) and not isinstance(returncode, bool) and returncode & 0xFFFFFFFF == 0xC000026B
    if logoff or any(s in detail for s in ("0xc000026b", "3221226091", "status_dll_init_failed_logoff")):
        code = "windows_session_logoff"
    elif "no supported javascript runtime" in detail or "no supported js runtime" in detail:
        code = "javascript_runtime_missing"
    reason, action = REASONS[code]
    return {"video_id": video, "reason_code": code, "reason": reason, "next_step": action}
