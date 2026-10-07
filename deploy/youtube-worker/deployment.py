#!/usr/bin/env python3
"""Journaled, between-run source deployment; never dispatches a worker."""
from __future__ import annotations
import argparse
import base64
import contextlib
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import stat
import select
import sys
import uuid
import time

BUNDLE = Path(__file__).resolve().parent
REPOSITORY = "fr-meyer/openclaw"
COMPATIBILITY = "windows-caption-worker-v2"


class DeploymentError(RuntimeError):
    pass


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def ensure_directory_durable(path: Path) -> None:
    missing = []
    current = path
    while not current.exists():
        missing.append(current)
        current = current.parent
    path.mkdir(parents=True, exist_ok=True)
    for directory in reversed(missing):
        fd = os.open(directory.parent, os.O_RDONLY)
        try: os.fsync(fd)
        finally: os.close(fd)


def atomic(path: Path, raw: bytes, *, mode: int | None = None) -> None:
    ensure_directory_durable(path.parent)
    temporary = path.with_name(path.name + ".deployment-tmp-" + uuid.uuid4().hex)
    with temporary.open("xb") as handle:
        os.fchmod(handle.fileno(), mode if mode is not None else stat.S_IMODE(path.stat().st_mode) if path.is_file() else 0o600)
        handle.write(raw); handle.flush(); os.fsync(handle.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY)
    try: os.fsync(fd)
    finally: os.close(fd)


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def read(path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
        raise DeploymentError("deployment evidence unavailable or unsafe")
    value = json.loads(path.read_text())
    if not isinstance(value, dict): raise DeploymentError("deployment evidence is not an object")
    return value


def safe_target(root: Path, relative: str) -> Path:
    parts = PurePosixPath(relative)
    if parts.is_absolute() or not parts.parts or any(part in {".", ".."} for part in parts.parts) or "\\" in relative:
        raise DeploymentError("managed destination invalid")
    path = root / relative
    cursor = path
    while cursor != root.parent:
        if cursor.is_symlink(): raise DeploymentError("managed destination has symlink ancestor")
        cursor = cursor.parent
    return path


def source_files() -> dict[str, bytes]:
    runtime = BUNDLE / "runtime"
    result = {}
    for path in sorted(runtime.rglob("*")):
        if path.is_symlink(): raise DeploymentError("managed source symlink refused")
        if path.is_file() and not generated_cache(path, runtime): result[path.relative_to(runtime).as_posix()] = path.read_bytes()
    return result


def generated_cache(path: Path, root: Path) -> bool:
    return "__pycache__" in path.relative_to(root).parts and path.suffix == ".pyc"


def verify_source_revision(revision: str, source: dict[str, bytes]) -> None:
    """Bind all bundle source and the captured runtime bytes to HEAD's tracked tree."""
    repository = BUNDLE.parents[1]
    relative_bundle = BUNDLE.relative_to(repository).as_posix()
    try:
        head = subprocess.check_output(["git", "-C", str(repository), "rev-parse", "HEAD"], text=True).strip()
        if head != revision:
            raise DeploymentError("activation requires the exact canonical source commit")
        tree = subprocess.check_output(["git", "-C", str(repository), "ls-tree", "-r", "-z", "--full-tree", revision, "--", relative_bundle])
        tracked = {}
        for record in tree.split(b"\0"):
            if not record: continue
            metadata, raw_path = record.split(b"\t", 1)
            mode, kind, _object_id = metadata.split()
            if kind != b"blob" or mode not in {b"100644", b"100755"}:
                raise DeploymentError("canonical deployment tree contains unsupported source types")
            repository_path = raw_path.decode("utf-8")
            relative = PurePosixPath(repository_path).relative_to(PurePosixPath(relative_bundle)).as_posix()
            tracked[relative] = repository_path
        actual = {}
        for path in sorted(BUNDLE.rglob("*")):
            if path.is_symlink(): raise DeploymentError("managed deployment source symlink refused")
            if not path.is_file(): continue
            relative = path.relative_to(BUNDLE).as_posix()
            # Generated Python caches are never deployed. Every other ignored
            # or untracked file in this bundle must fail closed.
            if generated_cache(path, BUNDLE) and relative not in tracked: continue
            actual[relative] = path
        if not tracked or set(actual) != set(tracked):
            raise DeploymentError("deployment source inventory differs from the exact tracked revision")
        committed_runtime = {}
        for relative, repository_path in tracked.items():
            committed = subprocess.check_output(["git", "-C", str(repository), "show", revision + ":" + repository_path])
            if actual[relative].read_bytes() != committed:
                raise DeploymentError("tracked deployment source bytes differ from the exact revision")
            if relative.startswith("runtime/"):
                committed_runtime[relative.removeprefix("runtime/")] = committed
        if source != committed_runtime:
            raise DeploymentError("captured runtime source differs from the exact tracked revision")
    except (subprocess.CalledProcessError, OSError, ValueError, UnicodeError):
        raise DeploymentError("canonical deployment source revision could not be verified") from None


def release_identity(release: dict, source: dict[str, bytes]) -> str:
    if release.get("schema") != "openclaw.youtube.windows-release.v1" or release.get("repository") != REPOSITORY or release.get("compatibility") != COMPATIBILITY:
        raise DeploymentError("release ownership/compatibility invalid")
    revision = release.get("revision")
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise DeploymentError("release revision invalid")
    if release.get("files") != {key: digest(raw) for key, raw in source.items()}:
        raise DeploymentError("release source bytes drifted")
    archiver = release.get("archiver") or {}
    if archiver.get("repository") != "fr-meyer/agent-toolkit" or archiver.get("path") != "skills/youtube-transcript-archive/scripts/archive_youtube_transcript.py" or not re.fullmatch(r"[0-9a-f]{40}", str(archiver.get("revision") or "")) or not re.fullmatch(r"[0-9a-f]{64}", str(archiver.get("sha256") or "")):
        raise DeploymentError("external archiver source pin invalid")
    if release.get("wrapper_sha256") != digest((BUNDLE / "windows/yt-dlp-anonymous.cmd").read_bytes()):
        raise DeploymentError("Windows wrapper source bytes drifted")
    return digest(json_bytes(release))


def check_proofs(release: dict, identity: str, proofs: dict) -> None:
    if proofs.get("release_sha256") != identity or proofs.get("revision") != release["revision"]:
        raise DeploymentError("deployment proof is not exact-revision bound")
    for key in ("autoreview", "offline_tests", "native_windows"):
        proof = proofs.get(key)
        if not isinstance(proof, dict) or proof.get("state") != "passed" or not isinstance(proof.get("evidence_sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", proof["evidence_sha256"]):
            raise DeploymentError("required release proof incomplete: " + key)


def ensure_between_runs(data: Path, node_id: str) -> None:
    pool = data / "state/automation/global"
    for path in (pool / "leases").glob("*.json"):
        row = read(path)
        if row.get("state") == "active" and (row.get("node") or {}).get("id") == node_id:
            raise DeploymentError("Windows node still has an active authoritative lease")
    for path in (pool / "windows-canaries").glob("*/manifest.json"):
        row = read(path)
        if (row.get("node") or {}).get("node_id") == node_id and row.get("state") not in {"completed", "partial", "superseded_before_lease"}:
            raise DeploymentError("Windows run remains nonfinal; preserve its component pins")


@contextlib.contextmanager
def boundary_locks(data: Path):
    held = []
    try:
        for name in ("windows-supervisor.lock", "coordinator.lock"):
            path = data / "state/automation/global/locks" / name
            ensure_directory_durable(path.parent)
            fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
            held.append(fd)
            try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError: raise DeploymentError("coordinator is busy; wait for the next between-run boundary") from None
        yield
    finally:
        for fd in reversed(held): os.close(fd)


def managed_state_paths(data: Path) -> tuple[Path, Path, Path]:
    return (
        safe_target(data, "state/config/windows-worker.json"),
        safe_target(data, "state/automation/global/gates/windows-worker-cutover.json"),
        safe_target(data, "state/config/windows-deployment.json"),
    )


def validate_transport_helper(workspace: Path) -> None:
    helper = safe_target(workspace, "scripts/youtube_worker/openclaw-node-run")
    if helper.exists() and (not helper.is_file() or not os.access(helper, os.X_OK)):
        raise DeploymentError("existing transport helper is not executable; preserve its permissions and resolve before activation")


def targets(workspace: Path, data: Path, release: dict, configuration: dict, source: dict[str, bytes]) -> dict[Path, bytes]:
    validate_transport_helper(workspace)
    validate_configuration(configuration)
    configuration_path, marker_path, deployment_path = managed_state_paths(data)
    marker = read(marker_path)
    if marker.get("enabled") is not True or marker.get("node_id") != configuration["node"]["id"]:
        raise DeploymentError("existing coordinator cutover identity differs")
    assets = configuration.get("assets") or {}
    if assets.get("fork_revision") != release["revision"] or assets.get("compatibility") != COMPATIBILITY or assets.get("archiver_revision") != release.get("archiver", {}).get("revision") or assets.get("archiver_sha256") != release.get("archiver", {}).get("sha256") or assets.get("wrapper_sha256") != release.get("wrapper_sha256"):
        raise DeploymentError("external component pins differ from release")
    marker.update(worker_sha256=release["files"]["scripts/youtube_global_chunk_worker.py"], adapter_sha256=release["files"]["scripts/youtube_global_windows_adapter.ps1"])
    result = {safe_target(workspace, key): raw for key, raw in source.items()}
    result[configuration_path] = json_bytes(configuration)
    result[marker_path] = json_bytes(marker)
    result[deployment_path] = json_bytes({"schema": "openclaw.youtube.windows-deployment.v1", "revision": release["revision"], "release_sha256": digest(json_bytes(release)), "files": release["files"], "assets": assets, "configuration_sha256": digest(json_bytes(configuration))})
    return result


def validate_configuration(configuration: dict) -> None:
    path = BUNDLE / "runtime/scripts/youtube_windows_config.py"
    spec = importlib.util.spec_from_file_location("windows_deployment_config_validator", path)
    if spec is None or spec.loader is None: raise DeploymentError("configuration validator unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try: module.validate_config(configuration)
    except ValueError: raise DeploymentError("external Windows configuration contract invalid") from None


def read_windows_receipt(stream, *, timeout_seconds: float = 60) -> dict:
    deadline = time.monotonic() + timeout_seconds
    record = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([stream], [], [], remaining)[0]:
            raise DeploymentError("Windows installation receipt deadline reached; restore local assets if installation occurred")
        chunk = os.read(stream.fileno(), min(4096, 16385 - len(record)))
        if not chunk: break
        record.extend(chunk)
        if len(record) > 16384: raise DeploymentError("Windows installation receipt exceeds bound")
        if b"\n" in record:
            line, rest = bytes(record).split(b"\n", 1)
            if rest.strip(): raise DeploymentError("Windows installation receipt has trailing records")
            record = bytearray(line); break
    try: value = json.loads(record.decode("utf-8"))
    except (ValueError, UnicodeError): raise DeploymentError("Windows installation receipt invalid") from None
    if not isinstance(value, dict): raise DeploymentError("Windows installation receipt is not an object")
    return value


def validate_windows_ready(receipt: dict, release: dict, configuration: dict) -> None:
    if (not isinstance(receipt, dict) or receipt.get("assets") != configuration.get("assets") or receipt.get("worker_alive") is not False or receipt.get("worker_lock_free") is not True
        or receipt.get("adapter_sha256") != release["files"]["scripts/youtube_global_windows_adapter.ps1"]
        or receipt.get("archiver_sha256") != release["archiver"]["sha256"] or receipt.get("wrapper_sha256") != release["wrapper_sha256"]):
        raise DeploymentError("Windows installation/readback receipt is not exact-release bound")


def activate(workspace: Path, data: Path, release: dict, configuration: dict, proofs: dict, expected: dict, journal_path: Path, *, await_windows: bool = False) -> dict:
    source = source_files(); identity = release_identity(release, source)
    check_proofs(release, identity, proofs)
    verify_source_revision(release["revision"], source)
    validate_configuration(configuration)
    revision = release["revision"]
    # Refuse redirected state before creating locks or handing off Windows work.
    managed_state_paths(data)
    validate_transport_helper(workspace)
    if journal_path.exists(): raise DeploymentError("deployment journal already exists; inspect or roll back its recorded transaction")
    with boundary_locks(data):
        ensure_between_runs(data, configuration["node"]["id"])
        validate_transport_helper(workspace)
        if await_windows:
            print(json.dumps({"state": "boundary_locked", "release_sha256": identity, "native_install_receipt_deadline_seconds": 60}), flush=True)
            ready = read_windows_receipt(sys.stdin)
        else:
            ready = proofs.get("windows_installation") or {}
        validate_windows_ready(ready, release, configuration)
        proposed = targets(workspace, data, release, configuration, source)
        actual = {str(path): digest(path.read_bytes()) if path.is_file() else None for path in proposed}
        if actual != expected: raise DeploymentError("deployment preimage hashes changed")
        journal = {"schema": "openclaw.youtube.windows-deploy-journal.v1", "state": "prepared", "release_sha256": identity, "revision": revision, "node_id": configuration["node"]["id"], "workspace": str(workspace), "data_root": str(data), "files": [{"path": str(path), "before": base64.b64encode(path.read_bytes()).decode() if path.is_file() else None, "before_mode": stat.S_IMODE(path.stat().st_mode) if path.is_file() else None, "after": base64.b64encode(raw).decode(), "after_sha256": digest(raw)} for path, raw in proposed.items()]}
        atomic(journal_path, json_bytes(journal))
        try:
            for path, raw in proposed.items():
                mode = stat.S_IMODE(path.stat().st_mode) if path.is_file() else 0o755 if path.name == "openclaw-node-run" else 0o644 if path.is_relative_to(workspace) else 0o600
                if not path.is_file() or path.read_bytes() != raw: atomic(path, raw, mode=mode)
            if any(digest(path.read_bytes()) != digest(raw) for path, raw in proposed.items()): raise DeploymentError("deployment readback mismatch")
            journal["state"] = "committed"; atomic(journal_path, json_bytes(journal))
        except BaseException:
            # Leave recoverable intent/preimages. No automatic worker retry or
            # rollback while the coordinator boundary is uncertain.
            raise
    return {"state": "committed", "revision": revision, "release_sha256": identity, "journal": str(journal_path)}


def rollback(journal_path: Path) -> dict:
    journal = read(journal_path)
    if journal.get("schema") != "openclaw.youtube.windows-deploy-journal.v1" or journal.get("state") not in {"prepared", "committed"}:
        raise DeploymentError("rollback journal invalid or already consumed")
    workspace, data = Path(journal["workspace"]), Path(journal["data_root"])
    rows = journal.get("files")
    if not isinstance(rows, list) or not rows: raise DeploymentError("rollback preimages missing")
    with boundary_locks(data):
        ensure_between_runs(data, journal["node_id"])
        for row in rows:
            path = Path(row["path"])
            root = workspace if path.is_relative_to(workspace) else data
            if not path.is_relative_to(root) or (root == data and path not in {data / "state/config/windows-worker.json", data / "state/config/windows-deployment.json", data / "state/automation/global/gates/windows-worker-cutover.json"}):
                raise DeploymentError("rollback destination outside managed contract")
            safe_target(root, path.relative_to(root).as_posix())
            before = base64.b64decode(row["before"], validate=True) if row["before"] is not None else None
            current = path.read_bytes() if path.is_file() else None
            if current != before and (current is None or digest(current) != row["after_sha256"]):
                raise DeploymentError("rollback refused after source/state drift")
        for row in reversed(rows):
            path = Path(row["path"])
            if row["before"] is None: path.unlink(missing_ok=True)
            else: atomic(path, base64.b64decode(row["before"], validate=True), mode=row["before_mode"])
        journal["state"] = "rolled_back"; atomic(journal_path, json_bytes(journal))
    return {"state": "rolled_back", "journal": str(journal_path)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("inventory", "plan", "activate", "rollback"))
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--data-root", type=Path)
    parser.add_argument("--release", type=Path)
    parser.add_argument("--configuration", type=Path)
    parser.add_argument("--proofs", type=Path)
    parser.add_argument("--expected-current", type=Path)
    parser.add_argument("--journal", type=Path)
    parser.add_argument("--await-windows", action="store_true", help="Hold the verified coordinator boundary up to 60s for the local Windows installation receipt on stdin")
    args = parser.parse_args()
    if args.action == "rollback":
        if not args.journal: parser.error("journal required for rollback")
        print(json.dumps(rollback(args.journal), indent=2)); return 0
    source = source_files()
    if args.action == "inventory":
        print(json.dumps({"repository": REPOSITORY, "compatibility": COMPATIBILITY, "files": {key: digest(raw) for key, raw in source.items()}, "wrapper_sha256": digest((BUNDLE / "windows/yt-dlp-anonymous.cmd").read_bytes())}, indent=2)); return 0
    if not all((args.workspace, args.data_root, args.release, args.configuration)): parser.error("workspace, data-root, release and configuration are required")
    workspace, data = args.workspace.absolute(), args.data_root.absolute()
    if workspace.is_symlink() or data.is_symlink(): raise DeploymentError("deployment roots must be real directories")
    release, configuration = read(args.release), read(args.configuration)
    release_identity(release, source)
    if args.action == "plan":
        proposed = targets(workspace, data, release, configuration, source)
        print(json.dumps({str(path): digest(path.read_bytes()) if path.is_file() else None for path in proposed}, indent=2)); return 0
    if not all((args.proofs, args.expected_current, args.journal)): parser.error("proofs, expected-current and journal are required for activation")
    result = activate(workspace, data, release, configuration, read(args.proofs), read(args.expected_current), args.journal, await_windows=args.await_windows)
    print(json.dumps(result, indent=2)); return 0


if __name__ == "__main__": raise SystemExit(main())
