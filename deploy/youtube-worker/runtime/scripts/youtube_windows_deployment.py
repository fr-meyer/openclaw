"""Read-only drift gate for the fork-owned Windows lane deployment."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re

EXPECTED_FILES = {
    "scripts/youtube_global_chunk_worker.py", "scripts/youtube_global_windows_adapter.ps1",
    "scripts/youtube_global_windows_canary.py", "scripts/youtube_global_windows_supervisor.py",
    "scripts/youtube_global_pool.py", "scripts/youtube_storage.py",
    "scripts/youtube_safe_diagnostics.py", "scripts/youtube_windows_config.py",
    "scripts/youtube_windows_import.py", "scripts/youtube_windows_transport.py",
    "scripts/youtube_windows_deployment.py", "scripts/youtube_worker/openclaw-node-run",
    "scripts/youtube_worker_alerts.py",
    "scripts/youtube_ycombinator/import_chunk_bundle.py", "scripts/youtube_ycombinator/build_catalog.py",
}
NOTIFICATION_FILES = {
    "scripts/youtube_global_windows_supervisor.py", "scripts/youtube_worker_alerts.py",
    "scripts/youtube_safe_diagnostics.py", "scripts/youtube_windows_deployment.py",
}


def verify_managed_sources(workspace: Path, configuration: dict, *, loaded_supervisor_sha256: str | None = None) -> None:
    data = Path(os.environ.get("OPENCLAW_YOUTUBE_DATA_ROOT", "~/.openclaw/data/youtube-transcripts")).expanduser()
    path = data / "state/config/windows-deployment.json"
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16384: raise RuntimeError("managed Windows deployment receipt unavailable")
    try: receipt = json.loads(path.read_text())
    except (ValueError, OSError): raise RuntimeError("managed Windows deployment receipt invalid") from None
    if not isinstance(receipt, dict) or receipt.get("schema") != "openclaw.youtube.windows-deployment.v1" or receipt.get("assets") != configuration.get("assets"):
        raise RuntimeError("managed Windows source/config provenance differs")
    files = receipt.get("files")
    if not isinstance(files, dict) or set(files) != EXPECTED_FILES: raise RuntimeError("managed Windows source inventory differs")
    if receipt.get("kind") == "notification-only":
        baseline = receipt.get("baseline") or {}
        previous = baseline.get("files") or {}
        if (not re.fullmatch(r"[0-9a-f]{40}", str(receipt.get("revision")))
            or baseline.get("revision") != configuration["assets"]["fork_revision"]
            or not re.fullmatch(r"[0-9a-f]{64}", str(baseline.get("release_sha256")))
            or set(previous) != EXPECTED_FILES - {"scripts/youtube_worker_alerts.py"}
            or any(previous.get(key) != files[key] for key in EXPECTED_FILES - NOTIFICATION_FILES)
            or loaded_supervisor_sha256 != files["scripts/youtube_global_windows_supervisor.py"]):
            raise RuntimeError("notification-only source/loaded-owner compatibility differs")
    elif receipt.get("kind") is not None or receipt.get("revision") != configuration["assets"]["fork_revision"]:
        raise RuntimeError("managed Windows source/config provenance differs")
    config_path = data / "state/config/windows-worker.json"
    if hashlib.sha256(config_path.read_bytes()).hexdigest() != receipt.get("configuration_sha256"): raise RuntimeError("managed Windows configuration bytes drifted")
    for relative, expected in files.items():
        parts = PurePosixPath(relative)
        target = workspace / relative
        if target.is_symlink() or not target.is_file() or not target.resolve().is_relative_to(workspace.resolve()) or not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected) or hashlib.sha256(target.read_bytes()).hexdigest() != expected:
            raise RuntimeError("managed Windows source bytes drifted: " + str(parts))
