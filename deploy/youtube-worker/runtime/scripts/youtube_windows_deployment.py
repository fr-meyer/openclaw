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
COORDINATOR_FILES = {
    "scripts/youtube_global_windows_canary.py", "scripts/youtube_global_windows_supervisor.py",
    "scripts/youtube_windows_deployment.py",
}
NOTIFICATION_REVISION = "e9fb664681efc09856acb5ac32d3925d210a905c"


def _hashes(files: object, expected: set[str]) -> bool:
    return (isinstance(files, dict) and set(files) == expected
        and all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) for value in files.values()))


def validate_receipt_provenance(receipt: dict, configuration: dict) -> None:
    """Validate bounded deployment ancestry without executing a coordinator."""
    if (receipt.get("schema") != "openclaw.youtube.windows-deployment.v1"
        or receipt.get("assets") != configuration.get("assets")):
        raise RuntimeError("managed Windows source/config provenance differs")
    files = receipt.get("files")
    if not _hashes(files, EXPECTED_FILES): raise RuntimeError("managed Windows source inventory differs")
    kind = receipt.get("kind")
    if kind == "notification-only":
        baseline = receipt.get("baseline") or {}
        previous = baseline.get("files") or {}
        if (not re.fullmatch(r"[0-9a-f]{40}", str(receipt.get("revision")))
            or baseline.get("revision") != configuration["assets"]["fork_revision"]
            or not re.fullmatch(r"[0-9a-f]{64}", str(baseline.get("release_sha256")))
            or set(previous) != EXPECTED_FILES - {"scripts/youtube_worker_alerts.py"}
            or any(previous.get(key) != files[key] for key in EXPECTED_FILES - NOTIFICATION_FILES)):
            raise RuntimeError("notification-only source/loaded-owner compatibility differs")
    elif kind == "coordinator-only":
        native, notification, previous = (receipt.get(key) for key in ("baseline", "notification_baseline", "previous"))
        if (not all(isinstance(row, dict) for row in (native, notification, previous))
            or not re.fullmatch(r"[0-9a-f]{40}", str(receipt.get("revision")))
            or not re.fullmatch(r"[0-9a-f]{64}", str(receipt.get("release_sha256")))
            or native.get("revision") != configuration["assets"]["fork_revision"]
            or not re.fullmatch(r"[0-9a-f]{64}", str(native.get("release_sha256")))
            or not _hashes(native.get("files"), EXPECTED_FILES - {"scripts/youtube_worker_alerts.py"})
            or notification.get("revision") != NOTIFICATION_REVISION
            or previous.get("kind") not in {"notification-only", "coordinator-only"}
            or previous.get("kind") == "notification-only" and previous.get("revision") != NOTIFICATION_REVISION
            or not re.fullmatch(r"[0-9a-f]{40}", str(previous.get("revision")))
            or any(not re.fullmatch(r"[0-9a-f]{64}", str(row.get(key)))
                for row in (notification, previous) for key in ("release_sha256", "receipt_sha256"))
            or not _hashes(notification.get("files"), EXPECTED_FILES)
            or not _hashes(previous.get("files"), EXPECTED_FILES)
            or any(native["files"][key] != files[key] for key in EXPECTED_FILES - NOTIFICATION_FILES - COORDINATOR_FILES)
            or any(notification["files"][key] != files[key] or previous["files"][key] != files[key]
                for key in EXPECTED_FILES - COORDINATOR_FILES)):
            raise RuntimeError("coordinator-only source/native/notification compatibility differs")
    elif kind is not None or receipt.get("revision") != configuration["assets"]["fork_revision"]:
        raise RuntimeError("managed Windows source/config provenance differs")


def verify_managed_sources(workspace: Path, configuration: dict, *, loaded_supervisor_sha256: str | None = None,
                           loaded_canary_sha256: str | None = None) -> None:
    data = Path(os.environ.get("OPENCLAW_YOUTUBE_DATA_ROOT", "~/.openclaw/data/youtube-transcripts")).expanduser()
    path = data / "state/config/windows-deployment.json"
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16384: raise RuntimeError("managed Windows deployment receipt unavailable")
    try: receipt = json.loads(path.read_text())
    except (ValueError, OSError): raise RuntimeError("managed Windows deployment receipt invalid") from None
    if not isinstance(receipt, dict):
        raise RuntimeError("managed Windows source/config provenance differs")
    validate_receipt_provenance(receipt, configuration)
    files = receipt.get("files")
    if (receipt.get("kind") == "notification-only"
        and loaded_supervisor_sha256 != files["scripts/youtube_global_windows_supervisor.py"]
        or receipt.get("kind") == "coordinator-only" and (
            loaded_canary_sha256 != files["scripts/youtube_global_windows_canary.py"]
            or loaded_supervisor_sha256 is not None and loaded_supervisor_sha256 != files["scripts/youtube_global_windows_supervisor.py"])):
        raise RuntimeError("managed Windows source/loaded-owner compatibility differs")
    config_path = data / "state/config/windows-worker.json"
    if hashlib.sha256(config_path.read_bytes()).hexdigest() != receipt.get("configuration_sha256"): raise RuntimeError("managed Windows configuration bytes drifted")
    for relative, expected in files.items():
        parts = PurePosixPath(relative)
        target = workspace / relative
        if target.is_symlink() or not target.is_file() or not target.resolve().is_relative_to(workspace.resolve()) or not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected) or hashlib.sha256(target.read_bytes()).hexdigest() != expected:
            raise RuntimeError("managed Windows source bytes drifted: " + str(parts))
