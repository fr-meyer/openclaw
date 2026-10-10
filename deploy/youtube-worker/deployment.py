#!/usr/bin/env python3
"""Journaled, between-run source deployment; never dispatches a worker."""
from __future__ import annotations
import argparse
import base64
import contextlib
import datetime as dt
import fcntl
import fnmatch
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import stat
import select
import signal
import sys
import uuid
import time

BUNDLE = Path(__file__).resolve().parent
REPOSITORY = "fr-meyer/openclaw"
COMPATIBILITY = "windows-caption-worker-v2"
NOTIFICATION_FILES = (
    "scripts/youtube_worker_alerts.py", "scripts/youtube_global_windows_supervisor.py",
    "scripts/youtube_safe_diagnostics.py", "scripts/youtube_windows_deployment.py",
)
COORDINATOR_FILES = (
    "scripts/youtube_global_windows_canary.py", "scripts/youtube_global_windows_supervisor.py",
    "scripts/youtube_windows_deployment.py",
)
NOTIFICATION_REVISION = "e9fb664681efc09856acb5ac32d3925d210a905c"
SUPERVISOR = "scripts/youtube_global_windows_supervisor.py"


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


def check_proofs(release: dict, identity: str, proofs: dict, *, required: tuple[str, ...] = ("autoreview", "offline_tests", "native_windows")) -> None:
    if proofs.get("release_sha256") != identity or proofs.get("revision") != release["revision"]:
        raise DeploymentError("deployment proof is not exact-revision bound")
    for key in required:
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
def boundary_locks(data: Path, *, canary_id: str | None = None):
    held = []
    try:
        pool = data / "state/automation/global"
        paths = [pool / "locks/windows-supervisor.lock"]
        if canary_id is not None:
            paths.append(pool / "windows-canaries" / canary_id / "reconcile.lock")
        paths.append(pool / "locks/coordinator.lock")
        for path in paths:
            safe_target(data, path.relative_to(data).as_posix())
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


@contextlib.contextmanager
def notification_deadline(seconds: float = 30):
    """One command budget; expiry preserves journaled intent, never replays it."""
    if not 0 < seconds <= 30 or signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
        raise DeploymentError("notification transaction deadline unavailable")
    started = time.monotonic()
    def check(*args):
        if args or time.monotonic() - started >= seconds:
            raise DeploymentError("notification transaction deadline reached; inspect journal before any recovery")
    previous = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, check)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield check
        check()
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def bounded_children(root: Path, pattern: str, *, limit: int = 512) -> list[Path]:
    result = []
    if not root.exists(): return result
    with os.scandir(root) as entries:
        for count, entry in enumerate(entries, 1):
            if count > 4096: raise DeploymentError("notification directory entries exceed bound")
            if not fnmatch.fnmatchcase(entry.name, pattern): continue
            if len(result) == limit: raise DeploymentError("notification admission inventory exceeds bound")
            result.append(Path(entry.path))
    return result


class NotificationInventory:
    """Stream history; bound actual reads, including the installed graph reader.

    Production sizing: 1207 leases + 710 manifests occupy 4.29 MB. A 16 MiB
    aggregate read budget also covers the lifecycle's repeated lease reads and
    its at-most-25-item graph. No historical row is skipped or retained whole.
    Metadata watches detect growth/replacement; they are never authority caches.
    """
    ENTRY_LIMIT = 4096
    BYTE_LIMIT = 16 * 1024 * 1024
    RECORD_LIMIT = 2 * 1024 * 1024
    SECONDS = 5

    def __init__(self, workspace: Path, data: Path):
        self.workspace, self.data = workspace, data
        self.started = time.monotonic()
        self.bytes_read = 0
        self.watches = {}

    def check(self):
        if time.monotonic() - self.started >= self.SECONDS:
            raise DeploymentError("notification admission scan deadline reached before writes")

    def watch(self, path: Path, info=None):
        self.check()
        info = path.lstat() if info is None else info
        value = (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if path in self.watches and self.watches[path] != value:
            raise DeploymentError("notification admission inventory changed during scan")
        self.watches[path] = value

    def raw(self, path: Path, *, byte_limit: int | None = None) -> bytes:
        path = Path(path)
        root = self.data if path.is_relative_to(self.data) else self.workspace
        safe_target(root, path.relative_to(root).as_posix())
        self.check()
        limit = min(self.RECORD_LIMIT, self.BYTE_LIMIT - self.bytes_read)
        if byte_limit is not None: limit = min(limit, byte_limit)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode): raise DeploymentError("notification admission record is not a regular file")
            if info.st_size > limit:
                raise DeploymentError("notification admission record or aggregate bytes exceed bound")
            self.watch(path, info)
            raw = handle.read(limit + 1)
            if len(raw) > limit:
                raise DeploymentError("notification admission record or aggregate bytes exceed bound")
            self.bytes_read += len(raw)
            self.watch(path, os.fstat(handle.fileno()))
        self.check()
        return raw

    def read_json(self, path: Path, default=None):
        try: raw = self.raw(path)
        except FileNotFoundError: return default
        try: row = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeError, RecursionError):
            raise DeploymentError("notification admission record is malformed") from None
        self.check()
        if not isinstance(row, dict): raise DeploymentError("notification admission record is not an object")
        return row

    def rows(self, pool: Path, kind: str):
        root = safe_target(self.data, (pool / kind).relative_to(self.data).as_posix())
        self.watch(root)
        with os.scandir(root) as entries:
            for count, entry in enumerate(entries, 1):
                self.check()
                if count > self.ENTRY_LIMIT: raise DeploymentError("notification directory entries exceed bound")
                path = Path(entry.path)
                if kind == "leases":
                    if not entry.name.endswith(".json"): continue
                else:
                    if entry.is_symlink(): raise DeploymentError("notification run inventory has symlink")
                    if not entry.is_dir(follow_symlinks=False): continue
                    self.watch(path)
                    path /= "manifest.json"
                    if not path.exists() and not path.is_symlink(): continue
                row = self.read_json(path)
                if row is None: raise DeploymentError("notification admission record disappeared")
                yield row

    def verify(self):
        for path in tuple(self.watches): self.watch(path)
        self.check()


def commands_drained(workspace: Path) -> None:
    """Refuse existing commands; the installed startup lock fences new cron."""
    proc = Path("/proc")
    if not proc.is_dir(): raise DeploymentError("notification command admission requires Linux proc evidence")
    started = time.monotonic()
    candidates = bounded_children(proc, "[0-9]*", limit=4096)
    scripts = {str(workspace / key) for key in (SUPERVISOR, "scripts/youtube_global_windows_canary.py")}
    for directory in candidates:
        if time.monotonic() - started >= 5: raise DeploymentError("notification command scan deadline reached")
        if directory.name == str(os.getpid()): continue
        try:
            with (directory / "cmdline").open("rb") as handle: raw = handle.read(16385)
            if len(raw) > 16384: raise DeploymentError("command admission argv exceeds bound")
            argv = [part.decode("utf-8", errors="strict") for part in raw.split(b"\0") if part]
            if not argv: continue
            if any(value in scripts for value in argv[1:]):
                raise DeploymentError("Windows command is still active; wait for its ordinary completion")
            relative = [value for value in argv[1:] if not value.startswith(("/", "-")) and Path(value).name in {Path(key).name for key in scripts}]
            if not relative: continue
            cwd = (directory / "cwd").resolve(strict=True)
        except FileNotFoundError:
            if (directory / "cmdline").exists():
                raise DeploymentError("notification command admission outcome unknown") from None
            continue
        except (PermissionError, UnicodeError, OSError):
            raise DeploymentError("notification command admission outcome unknown") from None
        if any(os.path.normpath(str(cwd / value)) in scripts for value in relative):
            raise DeploymentError("Windows command is still active; wait for its ordinary completion")
    if time.monotonic() - started >= 5: raise DeploymentError("notification command scan deadline reached")


def notification_targets(workspace: Path, data: Path, release: dict, configuration: dict, source: dict[str, bytes], baseline: dict) -> dict[Path, bytes]:
    """One typed variant of the same inventory owner; native provenance stays."""
    validate_configuration(configuration)
    configuration_path, marker_path, deployment_path = managed_state_paths(data)
    config_raw = configuration_path.read_bytes()
    receipt = read(deployment_path)
    previous = baseline.get("files") or {}
    expected_previous = set(source) - {"scripts/youtube_worker_alerts.py"}
    if (receipt.get("schema") != "openclaw.youtube.windows-deployment.v1" or receipt.get("kind") is not None
        or baseline.get("schema") != "openclaw.youtube.windows-release.v1" or baseline.get("repository") != REPOSITORY
        or baseline.get("compatibility") != COMPATIBILITY or receipt.get("revision") != configuration["assets"]["fork_revision"]
        or baseline.get("revision") != receipt.get("revision") or receipt.get("release_sha256") != digest(json_bytes(baseline))
        or receipt.get("assets") != configuration["assets"] or receipt.get("files") != previous
        or read(configuration_path) != configuration or receipt.get("configuration_sha256") != digest(config_raw)
        or set(previous) != expected_previous or baseline.get("archiver") != release.get("archiver")
        or baseline.get("wrapper_sha256") != release.get("wrapper_sha256")):
        raise DeploymentError("notification baseline/configuration provenance differs")
    for key, expected in previous.items():
        path = safe_target(workspace, key)
        if not path.is_file() or digest(path.read_bytes()) != expected:
            raise DeploymentError("notification baseline source drifted")
        if key not in NOTIFICATION_FILES and digest(source[key]) != expected:
            raise DeploymentError("notification candidate changes protected source")
    helper = safe_target(workspace, "scripts/youtube_worker_alerts.py")
    if helper.exists(): raise DeploymentError("notification helper already exists outside baseline")
    marker = read(marker_path)
    if (marker.get("enabled") is not True or marker.get("node_id") != configuration["node"]["id"]
        or marker.get("worker_sha256") != previous["scripts/youtube_global_chunk_worker.py"]
        or marker.get("adapter_sha256") != previous["scripts/youtube_global_windows_adapter.ps1"]):
        raise DeploymentError("notification protected cutover differs")
    validate_transport_helper(workspace)
    proposed = {safe_target(workspace, key): source[key] for key in NOTIFICATION_FILES}
    proposed[deployment_path] = json_bytes({"schema": receipt["schema"], "kind": "notification-only",
        "revision": release["revision"], "release_sha256": digest(json_bytes(release)), "files": release["files"],
        "assets": configuration["assets"], "configuration_sha256": digest(config_raw),
        "baseline": {"revision": baseline["revision"], "release_sha256": receipt["release_sha256"], "files": previous}})
    return proposed


def coordinator_targets(workspace: Path, data: Path, release: dict, configuration: dict, source: dict[str, bytes], baseline: dict) -> dict[Path, bytes]:
    """Extend the installed receipt while retaining bounded native ancestry."""
    validate_configuration(configuration)
    configuration_path, marker_path, deployment_path = managed_state_paths(data)
    config_raw, receipt_raw = configuration_path.read_bytes(), deployment_path.read_bytes()
    receipt = read(deployment_path)
    spec = importlib.util.spec_from_file_location("coordinator_deployment_provenance", BUNDLE / "runtime/scripts/youtube_windows_deployment.py")
    if spec is None or spec.loader is None: raise DeploymentError("managed deployment provenance owner unavailable")
    owner = importlib.util.module_from_spec(spec); spec.loader.exec_module(owner)
    try: owner.validate_receipt_provenance(receipt, configuration)
    except (RuntimeError, KeyError, TypeError, AttributeError):
        raise DeploymentError("coordinator baseline/native/notification provenance differs") from None
    if (baseline != receipt or receipt.get("kind") not in {"notification-only", "coordinator-only"}
        or receipt.get("kind") == "notification-only" and receipt.get("revision") != NOTIFICATION_REVISION
        or read(configuration_path) != configuration or receipt.get("configuration_sha256") != digest(config_raw)
        or set(source) != set(receipt["files"])
        or release.get("archiver", {}).get("revision") != configuration["assets"]["archiver_revision"]
        or release.get("archiver", {}).get("sha256") != configuration["assets"]["archiver_sha256"]
        or release.get("wrapper_sha256") != configuration["assets"]["wrapper_sha256"]):
        raise DeploymentError("coordinator baseline/configuration provenance differs")
    for key, expected in receipt["files"].items():
        path = safe_target(workspace, key)
        if not path.is_file() or digest(path.read_bytes()) != expected:
            raise DeploymentError("coordinator baseline source drifted")
        if key not in COORDINATOR_FILES and digest(source[key]) != expected:
            raise DeploymentError("coordinator candidate changes protected source")
    marker = read(marker_path)
    if (marker.get("enabled") is not True or marker.get("node_id") != configuration["node"]["id"]
        or marker.get("worker_sha256") != receipt["files"]["scripts/youtube_global_chunk_worker.py"]
        or marker.get("adapter_sha256") != receipt["files"]["scripts/youtube_global_windows_adapter.ps1"]):
        raise DeploymentError("coordinator protected cutover differs")
    validate_transport_helper(workspace)
    notification = receipt.get("notification_baseline") if receipt["kind"] == "coordinator-only" else {
        "revision": receipt["revision"], "release_sha256": receipt["release_sha256"],
        "receipt_sha256": digest(receipt_raw), "files": receipt["files"]}
    proposed = {safe_target(workspace, key): source[key] for key in COORDINATOR_FILES}
    proposed[deployment_path] = json_bytes({"schema": receipt["schema"], "kind": "coordinator-only",
        "revision": release["revision"], "release_sha256": digest(json_bytes(release)), "files": release["files"],
        "assets": configuration["assets"], "configuration_sha256": digest(config_raw), "baseline": receipt["baseline"],
        "notification_baseline": notification, "previous": {"kind": receipt["kind"], "revision": receipt["revision"],
            "release_sha256": receipt["release_sha256"], "receipt_sha256": digest(receipt_raw), "files": receipt["files"]}})
    if len(proposed[deployment_path]) > 16384: raise DeploymentError("coordinator deployment receipt exceeds bound")
    try: owner.validate_receipt_provenance(json.loads(proposed[deployment_path]), configuration)
    except (RuntimeError, KeyError, TypeError, AttributeError):
        raise DeploymentError("coordinator candidate/native/notification provenance differs") from None
    return proposed


def recovery_snapshot(root: Path, inventory: NotificationInventory, validated: dict[str, dict], captured: dict[Path, bytes]) -> dict[str, dict]:
    """Protect request set/content, including absence; never create a grant."""
    path = safe_target(inventory.data, (root / "resume-requests").relative_to(inventory.data).as_posix())
    if not path.exists():
        if validated: raise DeploymentError("coordinator recovery receipt inventory changed during scan")
        inventory.watch(root)
        return {str(path): {"exists": False}}
    inventory.watch(path)
    if not path.is_dir(): raise DeploymentError("coordinator recovery receipt inventory is not a directory")
    requests = bounded_children(path, "*", limit=64)
    if any(not re.fullmatch(r"[0-9a-f]{64}\.json", request.name) for request in requests):
        raise DeploymentError("coordinator recovery receipt inventory differs")
    if {request.stem for request in requests} != set(validated):
        raise DeploymentError("coordinator recovery receipt inventory changed during scan")
    result = {str(path): {"exists": True, "mode": stat.S_IMODE(path.stat().st_mode),
        "entries": sorted(request.name for request in requests)}}
    for request in requests:
        # The owner already validated these bounded bytes. Revalidate metadata
        # and the directory set rather than spend a second receipt read budget.
        inventory.watch(request)
        raw = captured[request]
        if json.loads(raw) != validated[request.stem]:
            raise DeploymentError("coordinator recovery receipt changed during scan")
        result[str(request)] = {"sha256": digest(raw), "mode": stat.S_IMODE(request.stat().st_mode)}
    return result


def notification_admission(workspace: Path, data: Path, configuration: dict, readiness: dict, *, coordinator_only: bool = False) -> dict[str, dict]:
    try:
        checked = dt.datetime.fromisoformat(readiness["checked_at"].replace("Z", "+00:00"))
        age = (dt.datetime.now(dt.timezone.utc) - checked).total_seconds()
        canary_id, lease_id = readiness["canary_id"], readiness["lease_id"]
        if (readiness.get("schema") != "openclaw.youtube.windows-notification-readiness.v1"
            or not 0 <= age <= 60 or not re.fullmatch(r"windows-canary-[A-Za-z0-9_-]{1,100}", canary_id)
            or not re.fullmatch(r"[a-zA-Z0-9-]{1,80}", lease_id)
            or readiness.get("node_connected") is not True or readiness.get("node_id") != configuration["node"]["id"]
            or readiness.get("assets") != configuration["assets"]
            or readiness.get("worker_account") != configuration["assets"]["worker_account"]
            or readiness.get("archiver_sha256") != configuration["assets"]["archiver_sha256"]
            or readiness.get("wrapper_sha256") != configuration["assets"]["wrapper_sha256"]): raise ValueError
    except (KeyError, TypeError, ValueError):
        raise DeploymentError("notification readiness is stale, incomplete or mismatched") from None
    pool = data / "state/automation/global"
    inventory = NotificationInventory(workspace, data)
    if (readiness.get("configuration_sha256") != digest(safe_target(data, "state/config/windows-worker.json").read_bytes())
        or readiness.get("cutover_sha256") != digest(safe_target(data, "state/automation/global/gates/windows-worker-cutover.json").read_bytes())):
        raise DeploymentError("notification protected configuration/cutover preimage differs")
    for relative in ("leases", "windows-canaries"):
        selected = []
        for row in inventory.rows(pool, relative):
            node = row.get("node", {})
            state = row.get("state")
            if not isinstance(node, dict) or state is not None and not isinstance(state, str):
                raise DeploymentError("notification admission node/state record is malformed")
            # Inactive leases and terminal runs may omit historical node data.
            # An active lease or nonterminal run must identify its owner; an
            # absent/empty object cannot prove that it belongs to another node.
            needs_owner = state == "active" if relative == "leases" else state not in {"completed", "partial", "superseded_before_lease"}
            owner_key = "id" if relative == "leases" else "node_id"
            if needs_owner and (not isinstance(node.get(owner_key), str) or not node[owner_key]):
                raise DeploymentError("notification admission node identity is incomplete")
            owned = ((node.get("id") == configuration["node"]["id"] and row.get("state") == "active")
                or (node.get("node_id") == configuration["node"]["id"] and row.get("state") not in {"completed", "partial", "superseded_before_lease"}))
            if owned:
                if selected: raise DeploymentError("notification same-run authoritative ownership differs")
                selected.append(row)
        if len(selected) != 1 or selected[0].get("lease_id") != lease_id or (relative == "windows-canaries" and selected[0].get("canary_id") != canary_id):
            raise DeploymentError("notification same-run authoritative ownership differs")
    root = pool / "windows-canaries" / canary_id
    manifest = inventory.read_json(safe_target(data, (root / "manifest.json").relative_to(data).as_posix()))
    if manifest.get("state") != "blocked" or manifest.get("worker_alive") is not False:
        raise DeploymentError("notification admission requires a known stopped blocked run")
    if (root / "finalization.json").exists() or bounded_children(root / "imports", "*.json", limit=25):
        raise DeploymentError("notification run has import/finalization activity")
    for request in ([] if coordinator_only else bounded_children(root / "resume-requests", "*.json", limit=25)):
        row = inventory.read_json(safe_target(data, request.relative_to(data).as_posix()))
        binding = {key: manifest.get(key) for key in ("canary_id", "lease_id", "binding_sha256", "worker_sha256", "adapter_sha256", "urls_sha256")}
        if (row.get("state") != "acknowledged" or row.get("schema") != "openclaw.youtube.windows-resume.v1"
            or row.get("binding") != binding or not re.fullmatch(r"[0-9a-f]{64}", str(row.get("checkpoint_sha256")))
            or request.stem != row["checkpoint_sha256"]):
            raise DeploymentError("notification recovery outcome is unresolved")
    # Reuse the installed, protected lifecycle's complete graph/staging checks.
    scripts = workspace / "scripts"
    old_path, old_data = sys.path[:], os.environ.get("OPENCLAW_YOUTUBE_DATA_ROOT")
    pool_module, old_pool_read, old_pool_store = None, None, None
    validated_requests = {}
    captured_requests = {}
    try:
        sys.path.insert(0, str(scripts)); os.environ["OPENCLAW_YOUTUBE_DATA_ROOT"] = str(data)
        spec = importlib.util.spec_from_file_location("notification_deployment_lifecycle", scripts / "youtube_global_windows_canary.py")
        if spec is None or spec.loader is None: raise DeploymentError("installed lifecycle unavailable")
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        module.POOL_ROOT = pool
        # Keep every installed graph decision; adapt only its read primitives.
        # In particular, its second history scan cannot escape this byte/time
        # budget. Restore the shared pool reader even after interruption.
        class BudgetPath(type(Path())):
            def read_text(self, encoding=None, errors=None):
                return inventory.raw(self).decode(encoding or "utf-8", errors or "strict")
            def glob(self, pattern):
                inventory.watch(Path(self))
                for path in bounded_children(Path(self), pattern, limit=inventory.ENTRY_LIMIT):
                    inventory.check()
                    yield BudgetPath(path)
        module.CANARIES_ROOT = BudgetPath(pool / "windows-canaries")
        module.read_json = inventory.read_json
        pool_module, old_pool_read, old_pool_store = module.GP, module.GP.read_json, module.GP.PoolStore
        class BudgetPoolStore(old_pool_store):
            @property
            def leases_dir(self): return BudgetPath(super().leases_dir)
        pool_module.read_json = inventory.read_json
        pool_module.PoolStore = BudgetPoolStore
        module.sha256_file = lambda path: digest(inventory.raw(path))
        module.validate_prelaunch_bindings(canary_id, manifest)
        remote = readiness.get("remote") or {}
        module._strict_remote_binding(manifest, remote)
        if (remote.get("exists") is not True or remote.get("worker_alive") is not False or remote.get("worker_lock_free") is not True
            or remote.get("state") not in module.REMOTE_BLOCKED or module.checkpoint_sha256(remote) != readiness.get("checkpoint_sha256")
            or readiness.get("adapter_sha256") != manifest.get("adapter_sha256")):
            raise DeploymentError("notification checkpoint/worker proof differs")
        if coordinator_only:
            # The installed e9 lifecycle has no v2 reader. Use the qualified
            # candidate's pure receipt owner, never a second schema validator.
            spec = importlib.util.spec_from_file_location("coordinator_deployment_recovery", BUNDLE / "runtime/scripts/youtube_global_windows_canary.py")
            if spec is None or spec.loader is None: raise DeploymentError("candidate recovery receipt owner unavailable")
            candidate = importlib.util.module_from_spec(spec); spec.loader.exec_module(candidate)
            receipt_bytes = 0
            def recovery_raw(path):
                nonlocal receipt_bytes
                raw = inventory.raw(path, byte_limit=min(65536, 1048576 - receipt_bytes))
                receipt_bytes += len(raw)
                captured_requests[Path(path)] = raw
                return raw
            validated_requests = candidate.resume_request_inventory(root, manifest, read_raw=recovery_raw)
            if any(row["state"] in {"armed", "intent", "uncertain"} for row in validated_requests.values()):
                raise DeploymentError("coordinator recovery grant is armed or outcome unresolved")
    except DeploymentError: raise
    except Exception:
        raise DeploymentError("notification lifecycle binding/probe proof differs") from None
    finally:
        if pool_module is not None:
            pool_module.read_json, pool_module.PoolStore = old_pool_read, old_pool_store
        sys.path[:] = old_path
        if old_data is None: os.environ.pop("OPENCLAW_YOUTUBE_DATA_ROOT", None)
        else: os.environ["OPENCLAW_YOUTUBE_DATA_ROOT"] = old_data
    paths = [root / "manifest.json", root / "chunks/0001.tsv", root / "chunks/0001.json", pool / "chunks" / (canary_id + ".json"), pool / "leases" / (lease_id + ".json")]
    paths += [pool / "items" / (video + ".json") for video in manifest["video_ids"]]
    paths += list(managed_state_paths(data)[:2])
    result = {str(path): {"sha256": digest(inventory.raw(path)), "mode": stat.S_IMODE(path.stat().st_mode)} for path in paths}
    if coordinator_only: result.update(recovery_snapshot(root, inventory, validated_requests, captured_requests))
    inventory.verify()
    return result


def file_fingerprint(path: Path) -> dict:
    return {"sha256": digest(path.read_bytes()), "mode": stat.S_IMODE(path.stat().st_mode)}


def notification_snapshot(workspace: Path, data: Path, configuration: dict, readiness: dict, *, coordinator_only: bool = False) -> dict[str, dict]:
    result = notification_admission(workspace, data, configuration, readiness, coordinator_only=coordinator_only)
    for key in set(source_files()) - set(COORDINATOR_FILES if coordinator_only else NOTIFICATION_FILES):
        path = safe_target(workspace, key)
        result[str(path)] = file_fingerprint(path)
    return result


def activate_notifications(workspace: Path, data: Path, release: dict, configuration: dict, proofs: dict, expected: dict, journal_path: Path, baseline: dict, readiness: dict, *, deadline_seconds: float = 30) -> dict:
    return _activate_compatible(workspace, data, release, configuration, proofs, expected, journal_path,
        baseline, readiness, kind="notification-only", deadline_seconds=deadline_seconds)


def activate_coordinator(workspace: Path, data: Path, release: dict, configuration: dict, proofs: dict, expected: dict, journal_path: Path, baseline: dict, readiness: dict, *, deadline_seconds: float = 30) -> dict:
    return _activate_compatible(workspace, data, release, configuration, proofs, expected, journal_path,
        baseline, readiness, kind="coordinator-only", deadline_seconds=deadline_seconds)


def _activate_compatible(workspace: Path, data: Path, release: dict, configuration: dict, proofs: dict, expected: dict, journal_path: Path, baseline: dict, readiness: dict, *, kind: str, deadline_seconds: float) -> dict:
    coordinator_only = kind == "coordinator-only"
    target_owner = coordinator_targets if coordinator_only else notification_targets
    snapshot = lambda: notification_snapshot(workspace, data, configuration, readiness, coordinator_only=coordinator_only)
    with notification_deadline(deadline_seconds) as check:
        source = source_files(); identity = release_identity(release, source)
        check_proofs(release, identity, proofs, required=("autoreview", "offline_tests"))
        native = proofs.get("native_windows") or {}
        native_baseline = baseline.get("baseline") if coordinator_only else None
        if coordinator_only and not isinstance(native_baseline, dict):
            raise DeploymentError("coordinator native baseline provenance unavailable")
        if (native.get("state") != "inherited" or native.get("baseline_release_sha256") != (native_baseline.get("release_sha256") if coordinator_only else digest(json_bytes(baseline)))
            or native.get("assets") != configuration.get("assets")
            or native.get("worker_sha256") != baseline.get("files", {}).get("scripts/youtube_global_chunk_worker.py")
            or native.get("adapter_sha256") != baseline.get("files", {}).get("scripts/youtube_global_windows_adapter.ps1")
            or not re.fullmatch(r"[0-9a-f]{64}", str(native.get("evidence_sha256")))):
            raise DeploymentError("notification unchanged-byte native proof incomplete")
        if coordinator_only and native.get("baseline_deployment_sha256") != digest(safe_target(data, "state/config/windows-deployment.json").read_bytes()):
            raise DeploymentError("coordinator unchanged-byte native proof baseline differs")
        verify_source_revision(release["revision"], source)
        validate_notification_journal(workspace, journal_path)
        if journal_path.exists(): raise DeploymentError("deployment journal already exists; inspect its outcome")
        proposed = target_owner(workspace, data, release, configuration, source, baseline)
        canary_id = readiness.get("canary_id")
        if not isinstance(canary_id, str) or not re.fullmatch(r"windows-canary-[A-Za-z0-9_-]{1,100}", canary_id): raise DeploymentError("notification run identity invalid")
        # Fail unsafe inventories/graphs before creating or taking any boundary.
        # These observations are not authority: repeat them under all locks.
        preflight = snapshot()
        commands_drained(workspace); check()
        if {str(path): digest(path.read_bytes()) if path.is_file() else None for path in proposed} != expected:
            raise DeploymentError("deployment preimage hashes changed")
        with boundary_locks(data, canary_id=canary_id):
            proposed = target_owner(workspace, data, release, configuration, source, baseline)
            protected = snapshot()
            if protected != preflight: raise DeploymentError("notification protected state changed before boundary")
            commands_drained(workspace); check()
            actual = {str(path): digest(path.read_bytes()) if path.is_file() else None for path in proposed}
            if actual != expected: raise DeploymentError("deployment preimage hashes changed")
            journal = {"schema": "openclaw.youtube.windows-deploy-journal.v1", "kind": kind, "state": "prepared",
                "revision": release["revision"], "release_sha256": identity, "workspace": str(workspace), "data_root": str(data),
                "node_id": configuration["node"]["id"], "canary_id": canary_id, "lease_id": readiness["lease_id"],
                "checkpoint_sha256": readiness["checkpoint_sha256"], "protected": protected,
                "files": [{"path": str(path), "before": base64.b64encode(path.read_bytes()).decode() if path.is_file() else None,
                    "before_mode": stat.S_IMODE(path.stat().st_mode) if path.is_file() else None,
                    "after": base64.b64encode(raw).decode(), "after_sha256": digest(raw),
                    "after_mode": stat.S_IMODE(path.stat().st_mode) if path.is_file() else 0o644} for path, raw in proposed.items()]}
            atomic(journal_path, json_bytes(journal)); check()
            for path, raw in proposed.items():
                atomic(path, raw, mode=stat.S_IMODE(path.stat().st_mode) if path.is_file() else 0o644); check()
                if path == workspace / SUPERVISOR: commands_drained(workspace)
            if any(digest(path.read_bytes()) != digest(raw) for path, raw in proposed.items()) or snapshot() != protected:
                raise DeploymentError("notification source or protected-state readback differs")
            check(); journal["state"] = "committed"; atomic(journal_path, json_bytes(journal)); check()
            return {"state": "committed", "kind": kind, "revision": release["revision"], "release_sha256": identity, "journal": str(journal_path)}


def validate_notification_journal(workspace: Path, journal_path: Path) -> None:
    if not journal_path.is_absolute() or not journal_path.is_relative_to(workspace / ".openclaw/tmp"):
        raise DeploymentError("notification journal must be a private deployment artifact under workspace .openclaw/tmp")
    safe_target(workspace, journal_path.relative_to(workspace).as_posix())


def rollback_notifications(journal_path: Path, journal: dict, readiness: dict) -> dict:
    return _rollback_compatible(journal_path, journal, readiness)


def _rollback_compatible(journal_path: Path, journal: dict, readiness: dict) -> dict:
    kind = journal["kind"]
    coordinator_only = kind == "coordinator-only"
    with notification_deadline() as check:
        workspace, data = Path(journal["workspace"]), Path(journal["data_root"])
        validate_notification_journal(workspace, journal_path)
        configuration = read(safe_target(data, "state/config/windows-worker.json"))
        if any(readiness.get(key) != journal.get(key) for key in ("canary_id", "lease_id", "checkpoint_sha256")):
            raise DeploymentError("notification rollback readiness differs from recorded run")
        paths = {str(safe_target(workspace, key)) for key in (COORDINATOR_FILES if coordinator_only else NOTIFICATION_FILES)}
        paths.add(str(safe_target(data, "state/config/windows-deployment.json")))
        rows = journal.get("files") or []
        if len(rows) != len(paths) or {row.get("path") for row in rows} != paths:
            raise DeploymentError("notification rollback write set differs")
        snapshot = lambda: notification_snapshot(workspace, data, configuration, readiness, coordinator_only=coordinator_only)
        if snapshot() != journal.get("protected"):
            raise DeploymentError("notification rollback protected state drifted")
        commands_drained(workspace); check()
        with boundary_locks(data, canary_id=journal["canary_id"]):
            if snapshot() != journal.get("protected"):
                raise DeploymentError("notification rollback protected state drifted")
            commands_drained(workspace); check()
            for row in rows:
                path = Path(row["path"])
                before = base64.b64decode(row["before"], validate=True) if row["before"] is not None else None
                after = base64.b64decode(row["after"], validate=True)
                current = path.read_bytes() if path.is_file() else None
                mode = stat.S_IMODE(path.stat().st_mode) if path.is_file() else None
                if digest(after) != row["after_sha256"] or (current, mode) not in ((before, row["before_mode"]), (after, row["after_mode"])):
                    raise DeploymentError("notification rollback source/state outcome unknown or drifted")
            # Keep the new pre-import fence until dependencies and the baseline
            # receipt are restored. The baseline supervisor has no startup
            # fence, so restoring it earlier can admit mixed loaded code.
            ordered = sorted(rows, key=lambda row: (row["path"] == str(workspace / SUPERVISOR), row["path"] == str(data / "state/config/windows-deployment.json")))
            for row in ordered:
                path = Path(row["path"])
                if row["before"] is None:
                    path.unlink(missing_ok=True)
                    fd = os.open(path.parent, os.O_RDONLY)
                    try: os.fsync(fd)
                    finally: os.close(fd)
                else: atomic(path, base64.b64decode(row["before"], validate=True), mode=row["before_mode"])
                check()
                if path == workspace / SUPERVISOR: commands_drained(workspace)
            commands_drained(workspace)
            if snapshot() != journal["protected"]:
                raise DeploymentError("notification rollback protected readback differs")
            for row in rows:
                path = Path(row["path"])
                before = base64.b64decode(row["before"], validate=True) if row["before"] is not None else None
                if (path.read_bytes() if path.is_file() else None) != before or (before is not None and stat.S_IMODE(path.stat().st_mode) != row["before_mode"]):
                    raise DeploymentError("notification rollback source readback differs")
            check(); journal["state"] = "rolled_back"; atomic(journal_path, json_bytes(journal)); check()
            return {"state": "rolled_back", "kind": kind, "journal": str(journal_path)}


def rollback(journal_path: Path, *, readiness: dict | None = None) -> dict:
    journal = read(journal_path)
    if journal.get("schema") != "openclaw.youtube.windows-deploy-journal.v1" or journal.get("state") not in {"prepared", "committed"}:
        raise DeploymentError("rollback journal invalid or already consumed")
    if journal.get("kind") in {"notification-only", "coordinator-only"}:
        if not isinstance(readiness, dict): raise DeploymentError("notification rollback requires fresh readiness")
        return _rollback_compatible(journal_path, journal, readiness)
    if journal.get("kind") is not None: raise DeploymentError("deployment journal kind unknown")
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
    variants = parser.add_mutually_exclusive_group()
    variants.add_argument("--notification-only", action="store_true", help="Preserve a stopped blocked run and native provenance while changing only compatible GCP notification source")
    variants.add_argument("--coordinator-only", action="store_true", help="Preserve installed notification/native provenance and an unarmed stopped run while changing only GCP recovery coordinator source")
    parser.add_argument("--baseline-release", type=Path)
    parser.add_argument("--baseline-deployment", type=Path, help="Exact currently installed deployment receipt for coordinator-only plan/activation")
    parser.add_argument("--readiness", type=Path, help="Fresh existing-run read-only node/checkpoint/account/assets/free-lock receipt")
    parser.add_argument("--await-windows", action="store_true", help="Hold the verified coordinator boundary up to 60s for the local Windows installation receipt on stdin")
    args = parser.parse_args()
    if args.action == "rollback":
        if not args.journal: parser.error("journal required for rollback")
        print(json.dumps(rollback(args.journal, readiness=read(args.readiness) if args.readiness else None), indent=2)); return 0
    source = source_files()
    if args.action == "inventory":
        inventory = {"repository": REPOSITORY, "compatibility": COMPATIBILITY, "files": {key: digest(raw) for key, raw in source.items()}, "wrapper_sha256": digest((BUNDLE / "windows/yt-dlp-anonymous.cmd").read_bytes())}
        if args.coordinator_only: inventory.update(kind="coordinator-only", write_files=list(COORDINATOR_FILES))
        print(json.dumps(inventory, indent=2)); return 0
    if not all((args.workspace, args.data_root, args.release, args.configuration)): parser.error("workspace, data-root, release and configuration are required")
    workspace, data = args.workspace.absolute(), args.data_root.absolute()
    if workspace.is_symlink() or data.is_symlink(): raise DeploymentError("deployment roots must be real directories")
    release, configuration = read(args.release), read(args.configuration)
    release_identity(release, source)
    if args.notification_only and (not args.baseline_release or args.baseline_deployment or args.await_windows):
        parser.error("notification-only requires baseline-release and forbids Windows installation handoff")
    if args.coordinator_only and (not args.baseline_deployment or args.baseline_release or args.await_windows):
        parser.error("coordinator-only requires baseline-deployment and forbids Windows installation handoff")
    baseline = read(args.baseline_deployment) if args.coordinator_only else read(args.baseline_release) if args.notification_only else None
    if args.action == "plan":
        if args.notification_only or args.coordinator_only:
            if not args.readiness: parser.error("compatible GCP-only plan requires fresh readiness")
            with notification_deadline():
                verify_source_revision(release["revision"], source)
                target_owner = coordinator_targets if args.coordinator_only else notification_targets
                proposed = target_owner(workspace, data, release, configuration, source, baseline)
                notification_snapshot(workspace, data, configuration, read(args.readiness), coordinator_only=args.coordinator_only)
                commands_drained(workspace)
                plan = {str(path): digest(path.read_bytes()) if path.is_file() else None for path in proposed}
        else:
            proposed = targets(workspace, data, release, configuration, source)
            plan = {str(path): digest(path.read_bytes()) if path.is_file() else None for path in proposed}
        print(json.dumps(plan, indent=2)); return 0
    if not all((args.proofs, args.expected_current, args.journal)): parser.error("proofs, expected-current and journal are required for activation")
    if args.notification_only or args.coordinator_only:
        if not args.readiness: parser.error("compatible GCP-only activation requires fresh readiness")
        activation_owner = activate_coordinator if args.coordinator_only else activate_notifications
        result = activation_owner(workspace, data, release, configuration, read(args.proofs), read(args.expected_current), args.journal, baseline, read(args.readiness))
    else:
        result = activate(workspace, data, release, configuration, read(args.proofs), read(args.expected_current), args.journal, await_windows=args.await_windows)
    print(json.dumps(result, indent=2)); return 0


if __name__ == "__main__": raise SystemExit(main())
