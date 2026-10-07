"""Windows lane configuration snapshot; deployment owns the external record."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path, PureWindowsPath


class WindowsConfigError(ValueError):
    pass


def validate_config(value: object) -> dict:
    if not isinstance(value, dict) or value.get("schema") != "openclaw.youtube.windows-config.v1":
        raise WindowsConfigError("Windows configuration schema invalid")
    if not isinstance(value.get("agent_id"), str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", value["agent_id"]):
        raise WindowsConfigError("Windows configuration audit agent invalid")
    node, remote = value.get("node"), value.get("remote")
    if not isinstance(node, dict) or not isinstance(remote, dict):
        raise WindowsConfigError("Windows configuration bindings missing")
    if not isinstance(node.get("id"), str) or not re.fullmatch(r"[0-9a-f]{64}", node["id"]):
        raise WindowsConfigError("Windows configuration node identity invalid")
    label = node.get("label")
    if not isinstance(label, str) or not 1 <= len(label) <= 120 or any(ord(c) < 32 for c in label):
        raise WindowsConfigError("Windows configuration node label invalid")
    paths = {"cwd": node.get("cwd"), **{key: remote.get(key) for key in ("staging_root", "adapter", "archiver", "wrapper")}}
    for key, path in paths.items():
        if not isinstance(path, str) or len(path) > 1024 or any(ord(c) < 32 for c in path):
            raise WindowsConfigError("Windows configuration path invalid")
        parsed = PureWindowsPath(path)
        if not parsed.is_absolute() or ".." in parsed.parts or str(parsed) != path:
            raise WindowsConfigError("Windows configuration path must be absolute and normalized")
        if key != "cwd" and not parsed.is_relative_to(PureWindowsPath(paths["cwd"])):
            raise WindowsConfigError("Windows configuration path escapes worker profile")
    expected_adapter = PureWindowsPath(paths["staging_root"]) / "validation" / "youtube_global_windows_adapter.ps1"
    if PureWindowsPath(paths["adapter"]) != expected_adapter:
        raise WindowsConfigError("Windows configuration adapter binding invalid")
    profile = PureWindowsPath(paths["cwd"])
    defaults = {
        "archiver": profile / "Documents/GitHub/shared-agent-skills/skills/youtube-transcript-archive/scripts/archive_youtube_transcript.py",
        "wrapper": profile / ".openclaw/youtube-transcript-tools/yt-dlp-anonymous.cmd",
    }
    if any(PureWindowsPath(paths[key]) != expected for key, expected in defaults.items()):
        raise WindowsConfigError("Windows configured tools differ from the paired adapter defaults")
    canaries = value.get("validation_canaries")
    if not isinstance(canaries, list) or not 1 <= len(canaries) <= 8:
        raise WindowsConfigError("Windows configuration validation evidence missing")
    ids = []
    for entry in canaries:
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str) or not re.fullmatch(r"windows-canary-[a-z0-9-]{1,64}", entry["id"]):
            raise WindowsConfigError("Windows configuration validation identity invalid")
        if type(entry.get("archived_count")) is not int or not 1 <= entry["archived_count"] <= 25:
            raise WindowsConfigError("Windows configuration validation count invalid")
        ids.append(entry["id"])
    if len(set(ids)) != len(ids):
        raise WindowsConfigError("Windows configuration validation identities duplicated")
    assets = value.get("assets")
    if not isinstance(assets, dict) or assets.get("compatibility") != "windows-caption-worker-v2":
        raise WindowsConfigError("Windows configuration component contract missing")
    for key in ("archiver_sha256", "wrapper_sha256"):
        if not isinstance(assets.get(key), str) or not re.fullmatch(r"[0-9a-f]{64}", assets[key]):
            raise WindowsConfigError("Windows configuration component hash invalid")
    for key in ("fork_revision", "archiver_revision"):
        if not isinstance(assets.get(key), str) or not re.fullmatch(r"[0-9a-f]{40}", assets[key]):
            raise WindowsConfigError("Windows configuration source revision invalid")
    if not isinstance(assets.get("worker_account"), str) or not 1 <= len(assets["worker_account"]) <= 128 or any(ord(c) < 32 for c in assets["worker_account"]):
        raise WindowsConfigError("Windows configuration worker account invalid")
    return value


def load_config() -> dict:
    data = Path(os.environ.get("OPENCLAW_YOUTUBE_DATA_ROOT", "~/.openclaw/data/youtube-transcripts")).expanduser()
    path = data / "state/config/windows-worker.json"
    value = None
    try:
        if not path.is_symlink() and path.is_file() and path.stat().st_size <= 16384:
            value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    # Captured JSON and decoder context must never reach coordinator errors.
    if value is None:
        raise WindowsConfigError("Windows configuration unavailable; deployment validation required")
    return validate_config(value)
