#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

if os.name == "nt":
    import msvcrt
else:
    import fcntl

MEDIA_EXTENSIONS = {
    ".mp4", ".mkv", ".webm", ".mov", ".avi", ".m4v",
    ".mp3", ".m4a", ".aac", ".wav", ".flac", ".ogg", ".opus",
}
SUCCESS_STATUSES = {
    "created", "refreshed", "reused", "transcript-archived",
    "metadata-only-no-captions", "archived", "complete",
}
BOT_MARKERS = (
    "confirm you’re not a bot", "confirm you're not a bot",
    "sign in to confirm you’re not a bot", "sign in to confirm you're not a bot",
    "captcha", "unusual traffic",
)
RATE_MARKERS = ("http error 429", "too many requests", "rate limit")
AGE_RESTRICTED_MARKERS = ("sign in to confirm your age", "may be inappropriate for some users")
AUTH_MARKERS = ("login required", "authentication required")
PRIVATE_MARKERS = ("private video", "this video is private", "video is private")
UNAVAILABLE_MARKERS = ("video unavailable", "video has been removed", "video was removed", "account associated with this video has been terminated", "video is no longer available", "this video has been removed")
VIDEO_ID_RE = re.compile(r"^[A-Za-z0-9_-]{11}$")
EXPECTED_YT_DLP_VERSION = "2026.08.19"
TERMINAL_SKIP_STATES = {
    "skipped_private",
    "skipped_age_restricted",
    "skipped_unavailable",
}


def terminal_state_for_failure(failure_class: str) -> str | None:
    return {
        "private_video": "skipped_private",
        "age_restricted": "skipped_age_restricted",
        "unavailable_video": "skipped_unavailable",
    }.get(failure_class)


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    directory_fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def atomic_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)
    fsync_directory(path.parent)


def append_event(path: Path, action: str, **detail: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"at": now(), "action": action, **detail}, ensure_ascii=False) + "\n")
        fh.flush()
        os.fsync(fh.fileno())


def acquire_worker_lock(base: Path, *, persist_pid: bool = True):
    """Hold a per-chunk OS lock for the process lifetime and persist its PID."""
    base.mkdir(parents=True, exist_ok=True)
    handle = (base / "worker.lock").open("a+", encoding="utf-8")
    try:
        if os.name == "nt":
            handle.seek(0)
            if not handle.read(1):
                handle.seek(0)
                handle.write("\0")
                handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (BlockingIOError, OSError):
        handle.close()
        return None
    if persist_pid:
        record_worker_pid(base)
    return handle


def record_worker_pid(base: Path) -> None:
    pid_path = base / "worker.pid"
    tmp = pid_path.with_name(pid_path.name + f".tmp-{os.getpid()}")
    with tmp.open("w", encoding="utf-8") as pid_file:
        pid_file.write(f"{os.getpid()}\n")
        pid_file.flush()
        os.fsync(pid_file.fileno())
    os.replace(tmp, pid_path)
    fsync_directory(base)


class ArchiveProcessCleanupError(RuntimeError):
    """Containment could not be proven; refuse another archive writer."""


class WindowsArchiveJob:
    """Own one attempt and its descendants, including after worker death."""

    def __init__(self) -> None:
        import ctypes
        from ctypes import wintypes

        class BasicLimits(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class IOCounters(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in (
                "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount",
            )]

        class ExtendedLimits(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", BasicLimits), ("IoInfo", IOCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        class Accounting(ctypes.Structure):
            _fields_ = [
                ("TotalUserTime", ctypes.c_longlong), ("TotalKernelTime", ctypes.c_longlong),
                ("ThisPeriodTotalUserTime", ctypes.c_longlong), ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
                ("TotalPageFaultCount", wintypes.DWORD), ("TotalProcesses", wintypes.DWORD),
                ("ActiveProcesses", wintypes.DWORD), ("TotalTerminatedProcesses", wintypes.DWORD),
            ]

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel.CreateJobObjectW.restype = wintypes.HANDLE
        kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        kernel.SetInformationJobObject.restype = wintypes.BOOL
        kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel.TerminateJobObject.restype = wintypes.BOOL
        kernel.QueryInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p]
        kernel.QueryInformationJobObject.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        self.kernel = kernel
        self.ctypes = ctypes
        self.accounting_type = Accounting
        # NULL security attributes make this handle non-inheritable: only the
        # worker owns it, so worker death kills the whole attempt automatically.
        self.handle = kernel.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        limits = ExtendedLimits()
        limits.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not kernel.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            error = ctypes.WinError(ctypes.get_last_error())
            self.close()
            raise error

    def assign(self, process: subprocess.Popen[str]) -> None:
        # CPython retains the actual CreateProcess handle until Popen cleanup;
        # using it avoids reopening a potentially recycled PID.
        if not self.kernel.AssignProcessToJobObject(self.handle, int(process._handle)):
            raise self.ctypes.WinError(self.ctypes.get_last_error())

    def terminate(self) -> None:
        if not self.kernel.TerminateJobObject(self.handle, 1):
            raise self.ctypes.WinError(self.ctypes.get_last_error())

    def wait_empty(self, timeout: float = 5) -> None:
        deadline = time.monotonic() + timeout
        while True:
            accounting = self.accounting_type()
            if not self.kernel.QueryInformationJobObject(self.handle, 1, self.ctypes.byref(accounting), self.ctypes.sizeof(accounting), None):
                raise self.ctypes.WinError(self.ctypes.get_last_error())
            if accounting.ActiveProcesses == 0:
                return
            if time.monotonic() >= deadline:
                raise ArchiveProcessCleanupError("Windows archive job still has active descendants")
            time.sleep(0.05)

    def close(self) -> None:
        if self.handle:
            if not self.kernel.CloseHandle(self.handle):
                raise self.ctypes.WinError(self.ctypes.get_last_error())
            self.handle = None


WINDOWS_ARCHIVE_BOOTSTRAP = (
    "import subprocess, sys\n"
    "if sys.stdin.readline(2) != '1\\n': raise SystemExit(125)\n"
    "code = subprocess.call(sys.argv[1:])\n"
    "raise SystemExit(code if code < 2147483648 else code - 4294967296)\n"
)


def start_archive_process(command: list[str]) -> subprocess.Popen[str]:
    kwargs: dict[str, object] = {
        "text": True,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
    }
    if os.name != "nt":
        kwargs["start_new_session"] = True
        return subprocess.Popen(command, **kwargs)
    job = WindowsArchiveJob()
    process = None
    try:
        # The private bootstrap cannot execute a tool until its parent
        # has fenced it into the Job Object. Assignment failure launches no
        # tool and never falls back to an unfenced direct process.
        process = subprocess.Popen(
            [sys.executable, "-c", WINDOWS_ARCHIVE_BOOTSTRAP, *command],
            stdin=subprocess.PIPE, **kwargs,
        )
        job.assign(process)
        process._archive_job = job
        process.stdin.write("1\n")
        process.stdin.flush()
        process.stdin.close()
        process.stdin = None
        return process
    except BaseException:
        try:
            if process is not None:
                process.kill()
                try:
                    process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
        finally:
            job.close()
        raise


def close_archive_process(process: subprocess.Popen[str]) -> None:
    job = vars(process).pop("_archive_job", None)
    if job is not None:
        try:
            # Even a normal archiver exit must not leave a detached descendant
            # writing after this attempt has finished.
            job.terminate()
            job.wait_empty()
        finally:
            job.close()


def start_guarded_archive_process(command: list[str], archive_root: Path, video_id: str) -> tuple[subprocess.Popen[str] | None, str | None]:
    """Validate the archive boundary after all pre-attempt journaling, then spawn."""
    ok, error = validate_archive_write_boundary(archive_root, video_id)
    if not ok:
        return None, error
    return start_archive_process(command), None


def terminate_archive_process(process: subprocess.Popen[str], *, force: bool = False) -> None:
    if os.name == "nt":
        job = vars(process).get("_archive_job")
        if job is None:
            raise ArchiveProcessCleanupError("Windows archive process has no containment job")
        job.terminate()
        return
    try:
        os.killpg(process.pid, signal.SIGKILL if force else signal.SIGTERM)
    except ProcessLookupError:
        pass


def communicate_archive_process(process: subprocess.Popen[str], *, timeout: float = 1200) -> tuple[str, str, int | None]:
    def text(value: str | bytes | None) -> str:
        return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value or ""

    try:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            return text(stdout), text(stderr), process.returncode
        except subprocess.TimeoutExpired as exc:
            terminate_archive_process(process)
            try:
                stdout, stderr = process.communicate(timeout=20)
            except subprocess.TimeoutExpired:
                terminate_archive_process(process, force=True)
                try:
                    stdout, stderr = process.communicate(timeout=5)
                except subprocess.TimeoutExpired as cleanup_error:
                    raise ArchiveProcessCleanupError("archive process cleanup could not be confirmed") from cleanup_error
            return text(stdout or exc.stdout), f"timeout after {timeout:g} seconds; process tree terminated\n" + text(stderr or exc.stderr), None
    finally:
        close_archive_process(process)


def run_guarded_command(command: list[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
    process = start_archive_process(command)
    stdout, stderr, code = communicate_archive_process(process, timeout=timeout)
    if code is None:
        raise subprocess.TimeoutExpired(command, timeout, output=stdout, stderr=stderr)
    return subprocess.CompletedProcess(command, code, stdout, stderr)


def path_is_reparse_point(path: Path) -> bool:
    """Return True for symlinks, Windows junctions, or other reparse points."""
    try:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        if callable(is_junction) and is_junction():
            return True
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
        return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    except OSError:
        # Archive validation is an execution boundary; unreadable metadata fails closed.
        return True


def validate_archive_root(root: Path, *, require_exists: bool = True) -> tuple[bool, str | None]:
    lexical_root = Path(os.path.abspath(root))
    root_exists = os.path.lexists(root)
    if root_exists:
        if path_is_reparse_point(root):
            return False, "archive root reparse point refused"
        if not root.is_dir():
            return False, "archive root is not a directory"
    elif require_exists:
        return False, "archive root missing"
    try:
        resolved_root = root.resolve(strict=False)
    except OSError as exc:
        return False, f"archive root cannot be resolved: {exc}"
    # Reject caller-controlled redirected ancestors, while allowing a single
    # host-level top-directory alias such as macOS `/var` -> `/private/var`.
    current = Path(lexical_root.anchor)
    for part in lexical_root.parts[1:-1]:
        current /= part
        if path_is_reparse_point(current) and current.parent != Path(current.anchor):
            return False, "archive root has a redirected ancestor"
    return True, None


def prepare_archive_root(root: Path) -> tuple[bool, str | None]:
    ok, error = validate_archive_root(root, require_exists=False)
    if not ok:
        return ok, error
    if not os.path.lexists(root):
        try:
            # The staged base must already exist.  A single-component mkdir
            # cannot silently follow an archive entry inserted before creation.
            root.mkdir()
        except FileExistsError:
            return False, "archive root appeared during guarded creation"
        except OSError as exc:
            return False, f"archive root creation failed: {exc}"
    return validate_archive_root(root)


def validate_archive_write_boundary(root: Path, video_id: str) -> tuple[bool, str | None]:
    ok, error = validate_archive_root(root)
    if not ok:
        return ok, error
    folder = root / video_id
    if not os.path.lexists(folder):
        return True, None
    if path_is_reparse_point(folder) or not folder.is_dir():
        return False, "archive target is not a safe directory"
    resolved_root = root.resolve(strict=False)
    lexical_folder = Path(os.path.abspath(folder))
    if folder.resolve(strict=False) != lexical_folder or not lexical_folder.is_relative_to(resolved_root):
        return False, "archive target escapes archive root"
    for candidate in folder.rglob("*"):
        if path_is_reparse_point(candidate):
            return False, f"archive target contains a reparse point: {candidate.relative_to(folder)}"
    return True, None


def validate_archive(root: Path, video_id: str) -> tuple[bool, str | None]:
    if not VIDEO_ID_RE.fullmatch(video_id):
        return False, "invalid video ID"
    ok, error = validate_archive_root(root)
    if not ok:
        return ok, error
    resolved_root = root.resolve(strict=False)
    folder = root / video_id
    if not folder.is_dir() or path_is_reparse_point(folder):
        return False, "archive directory missing or reparse point"
    resolved_folder = folder.resolve()
    if not resolved_folder.is_relative_to(resolved_root):
        return False, "archive directory escapes archive root"
    manifest_path = folder / "manifest.json"
    report_path = folder / "report.md"
    if not manifest_path.is_file() or path_is_reparse_point(manifest_path):
        return False, "missing manifest.json"
    if not report_path.is_file() or path_is_reparse_point(report_path):
        return False, "missing report.md"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return False, f"invalid manifest: {exc}"
    if manifest.get("video_id") != video_id:
        return False, f"video_id mismatch: {manifest.get('video_id')!r}"
    status = str(manifest.get("status") or "")
    if status and status not in SUCCESS_STATUSES:
        # File validation remains authoritative for forward compatibility.
        pass
    rel_files = manifest.get("files") or []
    if not isinstance(rel_files, list) or not rel_files:
        return False, "manifest files list missing or empty"
    for raw in rel_files:
        rel = Path(str(raw))
        if rel.is_absolute() or not rel.parts or ".." in rel.parts:
            return False, f"unsafe manifest path: {raw}"
        candidate = folder / rel
        if not candidate.is_file() or path_is_reparse_point(candidate):
            return False, f"missing listed file: {raw}"
        if not candidate.resolve().is_relative_to(resolved_folder):
            return False, f"listed file escapes archive directory: {raw}"
    for candidate in folder.rglob("*"):
        if path_is_reparse_point(candidate):
            return False, f"archive contains a reparse point: {candidate.relative_to(folder)}"
    media = [str(p) for p in folder.rglob("*") if p.is_file() and p.suffix.lower() in MEDIA_EXTENSIONS]
    if media:
        return False, f"unexpected media files: {media[:10]}"
    return True, None


def process_interrupted(detail: str, returncode: int | None = None) -> bool:
    if isinstance(returncode, int) and not isinstance(returncode, bool) and returncode & 0xFFFFFFFF == 0xC000026B:
        return True
    lowered = detail.casefold()
    return bool(re.search(r"(?<![A-Za-z0-9_])(?:0xc000026b|3221226091|-1073741205)(?![A-Za-z0-9_])", lowered)) or any(
        marker in lowered for marker in ("status_dll_init_failed_logoff", "window station is shutting down")
    )


def sanitized_error_detail(detail: str, *, limit: int = 2000) -> str:
    interrupted = process_interrupted(detail)
    # Redact complete fields before truncation can split a sensitive marker.
    detail = re.sub(r"""(?im)\b(?:authorization|proxy-authorization|set-cookie|cookie)["']?\s*[:=]\s*[^\r\n]+""", "[redacted sensitive header]", detail)
    detail = re.sub(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9_./+=-]+", "[redacted authentication]", detail)
    detail = re.sub(r"(?i)(--(?:password|username|video-password|cookies(?:-from-browser)?|netrc(?:-location|-cmd)?|add-header|proxy))(?:\s+|=)(?:\"[^\"]*\"|'[^']*'|\S+)", r"\1 [redacted]", detail)
    detail = re.sub(r"""(?im)\b([A-Za-z0-9_]*(?:token|secret|password|credential|api[_-]?key)[A-Za-z0-9_]*)(["']?\s*[:=]\s*)[^\r\n]+""", r"\1\2[redacted]", detail)
    detail = re.sub(r"(?i)(https?://)[^\s/@]+:[^\s/@]+@", r"\1[redacted]@", detail)
    detail = re.sub(r"(?i)https?://[^\s\"'<>]+", lambda match: match.group(0).split("?")[0].split("#")[0] + ("?[redacted query]" if "?" in match.group(0) else ""), detail)
    detail = re.sub(r"(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,})", "[redacted credential]", detail)
    detail = re.sub(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", "[redacted JWT]", detail)
    detail = "".join(char for char in detail if ord(char) >= 32 or char in "\n\r\t")
    # Preserve the fatal class even if a later diagnostic would fill the bound.
    prefix = "worker_session_interrupted (0xC000026B): " if interrupted else ""
    return prefix + detail[-(limit - len(prefix)):]


def classify(detail: str, returncode: int | None = None) -> str:
    if process_interrupted(detail, returncode):
        return "worker_session_interrupted"
    lowered = detail.casefold()
    if any(marker in lowered for marker in BOT_MARKERS):
        return "bot_check"
    if any(marker in lowered for marker in RATE_MARKERS):
        return "rate_limited"
    if any(marker in lowered for marker in AGE_RESTRICTED_MARKERS):
        return "age_restricted"
    if any(marker in lowered for marker in AUTH_MARKERS):
        return "auth_required"
    if any(marker in lowered for marker in UNAVAILABLE_MARKERS):
        return "unavailable_video"
    fatal_lines = "\n".join(line for line in lowered.splitlines() if "warning:" not in line)
    if "js runtime" in fatal_lines or "javascript runtime" in fatal_lines:
        return "configuration"
    if "timed out" in lowered or "timeout" in lowered:
        return "transient_timeout"
    return "error"


def wrapper_preflight(yt_dlp: str) -> tuple[str | None, str]:
    """Check the paired wrapper's offline runtime receipt before spending an attempt."""
    try:
        result = run_guarded_command([yt_dlp, "--worker-preflight"], timeout=15)
    except subprocess.TimeoutExpired as exc:
        captured = "\n".join(part.decode("utf-8", errors="replace") if isinstance(part, bytes) else part for part in (exc.stderr, exc.stdout) if part)
        if process_interrupted(captured):
            return "worker_session_interrupted", sanitized_error_detail(captured)
        return "configuration", "wrapper offline preflight unavailable"
    except (OSError, ArchiveProcessCleanupError) as exc:
        return "configuration", sanitized_error_detail("wrapper offline preflight unavailable: " + str(exc))
    captured = "\n".join(part for part in (result.stderr or "", result.stdout or "") if part)
    detail = f"wrapper preflight exited with status {result.returncode}\n{captured}"
    if process_interrupted(captured, result.returncode):
        return "worker_session_interrupted", sanitized_error_detail("worker_session_interrupted (0xC000026B)\n" + detail)
    if result.returncode != 0:
        return "configuration", sanitized_error_detail(detail)
    lines = [line.strip() for line in (result.stdout or "").splitlines()]
    node_versions = [match for line in lines if (match := re.fullmatch(r"node v([0-9]+)\.([0-9]+)\.([0-9]+)", line))]
    extractor_versions = [line for line in lines if re.fullmatch(r"[0-9]{4}\.[0-9]{2}\.[0-9]{2}", line)]
    if len(node_versions) != 1 or int(node_versions[0].group(1)) < 22:
        return "configuration", "wrapper offline preflight did not confirm one supported Node runtime (>=22)"
    if extractor_versions != [EXPECTED_YT_DLP_VERSION]:
        return "configuration", f"wrapper offline preflight did not confirm pinned yt-dlp {EXPECTED_YT_DLP_VERSION}"
    return None, f"{node_versions[0].group(0)}; yt-dlp {extractor_versions[0]}"


def source_diagnostic(url: str, yt_dlp: str) -> tuple[str | None, str | None]:
    """Run exactly one bounded anonymous probe for private/unavailable evidence."""
    try:
        probe = run_guarded_command([yt_dlp, "--skip-download", "--dump-single-json", "--no-warnings", url], timeout=45)
    except subprocess.TimeoutExpired as exc:
        captured = "\n".join(part.decode("utf-8", errors="replace") if isinstance(part, bytes) else part for part in (exc.stderr, exc.stdout) if part)
        if process_interrupted(captured):
            return "worker_session_interrupted", sanitized_error_detail(captured)
        return None, None
    except (OSError, ArchiveProcessCleanupError) as exc:
        return "configuration", sanitized_error_detail("anonymous probe containment unavailable: " + str(exc))
    captured = "\n".join(part.strip() for part in (probe.stderr or "", probe.stdout or "") if part.strip() and part.strip().lower() != "null")
    if process_interrupted(captured, probe.returncode):
        return "worker_session_interrupted", sanitized_error_detail(f"worker_session_interrupted (0xC000026B); anonymous metadata probe exited with status {probe.returncode}\n{captured}")
    lowered = captured.casefold()
    detail = sanitized_error_detail(captured)
    failure_class = classify(captured, probe.returncode)
    if failure_class in {"bot_check", "rate_limited", "auth_required", "configuration"}:
        return failure_class, detail
    if any(marker in lowered for marker in AGE_RESTRICTED_MARKERS):
        return "age_restricted", detail
    if any(marker in lowered for marker in PRIVATE_MARKERS):
        return "private_video", detail
    if any(marker in lowered for marker in UNAVAILABLE_MARKERS):
        return "unavailable_video", detail
    return None, None


def load_items(urls_path: Path, prior_status: Path, *, lease_id: str | None = None, max_attempts: int = 3, prior_metadata: dict | None = None) -> list[dict]:
    previous = {}
    if prior_status.exists():
        if path_is_reparse_point(prior_status) or not prior_status.is_file() or prior_status.stat().st_size > 4 * 1024 * 1024:
            raise ValueError("unsafe checkpoint file")
        checkpoint = None
        try:
            checkpoint = json.loads(prior_status.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            pass
        if not isinstance(checkpoint, dict) or checkpoint.get("schema") != "franck.youtube-catalog-chunk-worker.v1":
            raise ValueError("invalid checkpoint; captured data withheld")
        if checkpoint.get("lease_id") != lease_id or checkpoint.get("cookies_used") is not False or checkpoint.get("media_downloaded") is not False:
            raise ValueError("checkpoint lease or safety policy mismatch")
        if not isinstance(checkpoint.get("state"), str) or checkpoint.get("state") not in {"running", "retry_wait", "complete", "complete_with_blocked", "blocked_configuration", "blocked_interrupted", "blocked_bot_check", "blocked_auth_required", "waiting_network_cooldown"}:
            raise ValueError("checkpoint state invalid")
        if "circuit_open" in checkpoint and type(checkpoint["circuit_open"]) is not bool:
            raise ValueError("checkpoint circuit state invalid")
        if checkpoint.get("urls_sha256", hashlib.sha256(urls_path.read_bytes()).hexdigest()) != hashlib.sha256(urls_path.read_bytes()).hexdigest():
            raise ValueError("checkpoint URL hash mismatch")
        previous = checkpoint.get("items")
        if not isinstance(previous, dict):
            raise ValueError("invalid checkpoint items")
        if prior_metadata is not None:
            prior_metadata.update(checkpoint)
    items = []
    for line in urls_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        parts = line.split("\t", 1)
        if len(parts) != 2:
            raise ValueError("invalid chunk URL row")
        video_id, url = parts
        if not VIDEO_ID_RE.fullmatch(video_id):
            raise ValueError(f"invalid video ID: {video_id!r}")
        canonical_url = f"https://www.youtube.com/watch?v={video_id}"
        if url != canonical_url:
            raise ValueError(f"non-canonical YouTube URL for {video_id}")
        prior = previous.get(video_id) or {}
        if video_id in previous:
            allowed_states = TERMINAL_SKIP_STATES | {"archived", "pending", "running", "retry_wait", "blocked_error", "blocked_configuration", "blocked_interrupted", "blocked_bot_check", "blocked_auth_required", "waiting_network_cooldown"}
            if not isinstance(prior, dict) or prior.get("video_id") != video_id or prior.get("url") != canonical_url or not isinstance(prior.get("state"), str) or prior.get("state") not in allowed_states:
                raise ValueError("checkpoint item identity or state mismatch")
            attempts = prior.get("attempts")
            if type(attempts) is not int or not 0 <= attempts <= max_attempts:
                raise ValueError("checkpoint attempt budget invalid")
            if prior.get("process_exit_code") is not None and type(prior["process_exit_code"]) is not int:
                raise ValueError("checkpoint process exit code invalid")
        item = {
            "video_id": video_id,
            "url": url,
            "state": prior.get("state", "pending"),
            "attempts": int(prior.get("attempts") or 0),
            "failure_class": prior.get("failure_class"),
            "error": prior.get("error"),
            "completed_at": prior.get("completed_at"),
        }
        if "process_exit_code" in prior:
            item["process_exit_code"] = prior["process_exit_code"]
        items.append(item)
    if not items:
        raise ValueError("chunk URL file is empty")
    if len(items) > 25:
        raise ValueError(f"chunk has {len(items)} items; hard maximum is 25")
    if len({item["video_id"] for item in items}) != len(items):
        raise ValueError("chunk contains duplicate video IDs")
    if prior_status.exists() and set(previous) != {item["video_id"] for item in items}:
        raise ValueError("checkpoint item set mismatch")
    return items


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--urls", required=True)
    parser.add_argument("--archive-root", required=True)
    parser.add_argument("--python", required=True)
    parser.add_argument("--archiver", required=True)
    parser.add_argument("--yt-dlp", required=True)
    parser.add_argument("--max-attempts", type=int, default=3)
    parser.add_argument("--inter-item-sleep", type=float, default=10.0)
    parser.add_argument("--lease-id")
    parser.add_argument("--resume-blocked", action="store_true", help="Permit explicit same-lease recovery of a blocked checkpoint")
    parser.add_argument("--checkpoint-sha256", help="GCP-authorized persisted checkpoint digest for explicit recovery")
    parser.add_argument("--wrapper-preflight", action="store_true", help="Run the Windows wrapper's offline --worker-preflight once before extraction")
    args = parser.parse_args()
    if not 1 <= args.max_attempts <= 3:
        parser.error("--max-attempts must be 1..3")
    if args.inter_item_sleep < 5:
        parser.error("--inter-item-sleep must be at least 5 seconds")

    return run_worker(args)


def run_worker(args: argparse.Namespace) -> int:

    base = Path(args.base)
    archive = Path(args.archive_root)
    urls = Path(args.urls)
    status_path = base / "status.json"
    events_path = base / "events.jsonl"
    logs = base / "logs"
    base.mkdir(parents=True, exist_ok=True)

    def read_recovery_state() -> tuple[list[dict], dict, bool]:
        if getattr(args, "resume_blocked", False):
            expected = getattr(args, "checkpoint_sha256", None)
            if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected) or not status_path.is_file() or hashlib.sha256(status_path.read_bytes()).hexdigest() != expected:
                raise ValueError("authorized recovery checkpoint changed or unavailable")
        prior = {}
        items = load_items(urls, status_path, lease_id=args.lease_id, max_attempts=args.max_attempts, prior_metadata=prior)
        if getattr(args, "resume_blocked", False) and hashlib.sha256(status_path.read_bytes()).hexdigest() != args.checkpoint_sha256:
            raise ValueError("authorized recovery checkpoint changed during validation")
        prior_state = str(prior.get("state") or "")
        blocked = prior.get("circuit_open") is True or prior_state.startswith("blocked_") or prior_state == "waiting_network_cooldown" or any(item["state"].startswith("blocked_") and item["state"] != "blocked_error" for item in items)
        refused = blocked and (not getattr(args, "resume_blocked", False) or not prior.get("lease_id"))
        return items, prior, refused

    try:
        items, prior, refused = read_recovery_state()
    except (ValueError, OSError):
        print(json.dumps({"state": "checkpoint_refused", "reason": "checkpoint integrity or binding check failed"}))
        return 9
    if refused:
        print(json.dumps({"state": "resume_authorization_required", "lease_id": args.lease_id}))
        return 9
    worker_lock = acquire_worker_lock(base, persist_pid=False)
    if worker_lock is None:
        print(json.dumps({"state": "worker_lock_held", "base": str(base)}))
        return 7

    def finish(code: int) -> int:
        worker_lock.close()
        return code

    # The unlocked read rejects invalid recovery without changing its PID receipt.
    # Repeat every binding and budget check while holding the existing OS lock.
    try:
        items, prior, refused = read_recovery_state()
    except (ValueError, OSError):
        print(json.dumps({"state": "checkpoint_refused", "reason": "checkpoint integrity or binding check failed"}))
        return finish(9)
    if refused:
        print(json.dumps({"state": "resume_authorization_required", "lease_id": args.lease_id}))
        return finish(9)
    archive_ok, archive_error = prepare_archive_root(archive)
    if not archive_ok:
        print(json.dumps({"state": "unsafe_archive_root", "archive_root": str(archive), "error": archive_error}))
        return finish(8)
    logs.mkdir(parents=True, exist_ok=True)

    def write_status(state: str, **extra: object) -> None:
        counts = Counter(item["state"] for item in items)
        atomic_json(status_path, {
            "schema": "franck.youtube-catalog-chunk-worker.v1",
            "state": state,
            "updated_at": now(),
            "pid": os.getpid(),
            "total": len(items),
            "counts": dict(sorted(counts.items())),
            "cookies_used": False,
            "media_downloaded": False,
            "execution_lane": "trusted-residential-anonymous",
            "lease_id": args.lease_id,
            "urls_sha256": hashlib.sha256(urls.read_bytes()).hexdigest(),
            "items": {item["video_id"]: item for item in items},
            **extra,
        })

    for item in items:
        ok, _ = validate_archive(archive, item["video_id"])
        if item["state"] == "archived" and not ok:
            print(json.dumps({"state": "checkpoint_refused", "reason": "checkpoint archive validation failed"}))
            return finish(9)
        if ok:
            item["state"] = "archived"
            item["failure_class"] = None
            item["error"] = None

    record_worker_pid(base)
    if getattr(args, "wrapper_preflight", False) and any(item["state"] != "archived" and item["state"] not in TERMINAL_SKIP_STATES and item["attempts"] < args.max_attempts for item in items):
        preflight_class, preflight_detail = wrapper_preflight(args.yt_dlp)
        if preflight_class:
            state = "blocked_interrupted" if preflight_class == "worker_session_interrupted" else "blocked_configuration"
            write_status(state, circuit_open=True, circuit_reason=preflight_class, preflight_error=preflight_detail)
            append_event(events_path, "runtime_preflight_failed", failure_class=preflight_class, error=preflight_detail)
            return finish(4)
        append_event(events_path, "runtime_preflight_passed", versions=preflight_detail)

    write_status("running")
    append_event(events_path, "worker_started", total=len(items), lease_id=args.lease_id, cookies_used=False, media_downloaded=False)

    for index, item in enumerate(items, 1):
        if item["state"] in TERMINAL_SKIP_STATES:
            continue
        ok, _ = validate_archive(archive, item["video_id"])
        if ok:
            item["state"] = "archived"
            write_status("running", current_index=index)
            continue

        while item["attempts"] < args.max_attempts:
            def block_unsafe_boundary(boundary_error: str | None) -> int:
                item["state"] = "blocked_configuration"
                item["failure_class"] = "configuration"
                item["error"] = boundary_error
                write_status(
                    "blocked_configuration",
                    current_index=index,
                    current_video_id=item["video_id"],
                    circuit_open=True,
                    circuit_reason="unsafe_archive_boundary",
                )
                append_event(
                    events_path,
                    "circuit_opened",
                    failure_class="configuration",
                    circuit_reason="unsafe_archive_boundary",
                    video_id=item["video_id"],
                    error=boundary_error,
                )
                return finish(4)

            boundary_ok, boundary_error = validate_archive_write_boundary(archive, item["video_id"])
            if not boundary_ok:
                return block_unsafe_boundary(boundary_error)
            item["attempts"] += 1
            item["state"] = "running"
            item["failure_class"] = None
            item["error"] = None
            item.pop("process_exit_code", None)
            write_status("running", current_index=index, current_video_id=item["video_id"])
            stdout_path = logs / f"{index:02d}-{item['video_id']}-attempt-{item['attempts']}.stdout"
            stderr_path = logs / f"{index:02d}-{item['video_id']}-attempt-{item['attempts']}.stderr"
            cmd = [
                args.python, args.archiver, item["url"],
                "--archive-root", str(archive),
                "--lang", "best",
                "--yt-dlp-bin", args.yt_dlp,
                "--max-caption-candidates", "12",
                "--metadata-only-on-no-captions",
            ]
            append_event(events_path, "attempt_start", index=index, video_id=item["video_id"], attempt=item["attempts"])
            try:
                process, boundary_error = start_guarded_archive_process(cmd, archive, item["video_id"])
            except (OSError, RuntimeError) as exc:
                return block_unsafe_boundary("archive process containment unavailable: " + sanitized_error_detail(str(exc)))
            if process is None:
                return block_unsafe_boundary(boundary_error)
            try:
                stdout, stderr, returncode = communicate_archive_process(process)
            except (OSError, ArchiveProcessCleanupError) as exc:
                return block_unsafe_boundary("archive process cleanup unavailable: " + sanitized_error_detail(str(exc)))
            stdout_path.write_text(sanitized_error_detail(stdout, limit=65536), encoding="utf-8")
            stderr_path.write_text(sanitized_error_detail(stderr, limit=65536), encoding="utf-8")
            detail = (stderr + "\n" + stdout).strip()

            ok, validation_error = validate_archive(archive, item["video_id"])
            if returncode == 0 and ok:
                item["state"] = "archived"
                item["completed_at"] = now()
                item["failure_class"] = None
                item["error"] = None
                append_event(events_path, "attempt_success", index=index, video_id=item["video_id"], attempt=item["attempts"])
                write_status("running", current_index=index, last_video_id=item["video_id"])
                time.sleep(args.inter_item_sleep)
                break

            if returncode is not None and returncode != 0:
                detail = f"archive process exited with status {returncode}\n{detail}"
            failure_class = classify(detail, returncode)
            if not ok and failure_class not in {"bot_check", "auth_required", "rate_limited", "configuration", "transient_timeout", "worker_session_interrupted"}:
                diagnostic_class, diagnostic = source_diagnostic(item["url"], args.yt_dlp)
                if diagnostic_class:
                    failure_class = diagnostic_class
                    detail = f"anonymous metadata diagnostic: {diagnostic}"
            # For source-level terminal outcomes the missing archive directory
            # is only a consequence of yt-dlp refusing or lacking access.
            # Preserve the distinct bounded diagnostic instead of collapsing
            # private, age-restricted, and unavailable videos together.
            error = sanitized_error_detail(detail) or sanitized_error_detail(validation_error or "") or f"archive command returned {returncode}"
            item["failure_class"] = failure_class
            item["error"] = error
            item["process_exit_code"] = returncode
            append_event(events_path, "attempt_failed", index=index, video_id=item["video_id"], attempt=item["attempts"], failure_class=failure_class, error=error)

            terminal_state = terminal_state_for_failure(failure_class)
            if terminal_state:
                item["state"] = terminal_state
                write_status("running", current_index=index, last_video_id=item["video_id"])
                break

            if failure_class in {"bot_check", "auth_required", "rate_limited", "configuration", "worker_session_interrupted"}:
                state = {
                    "bot_check": "blocked_bot_check",
                    "auth_required": "blocked_auth_required",
                    "rate_limited": "waiting_network_cooldown",
                    "configuration": "blocked_configuration",
                    "worker_session_interrupted": "blocked_interrupted",
                }[failure_class]
                item["state"] = state
                write_status(state, current_index=index, current_video_id=item["video_id"], circuit_open=True, circuit_reason=failure_class)
                append_event(events_path, "circuit_opened", failure_class=failure_class, video_id=item["video_id"])
                return finish(4)

            if item["attempts"] >= args.max_attempts:
                item["state"] = "blocked_error"
                # An ordinary item-level failure must not strand the rest of
                # the bounded chunk.  Circuit-breaker failures still stop the
                # worker above, but an exhausted video is checkpointed and the
                # serial worker continues with the next item.
                write_status("running", current_index=index, last_video_id=item["video_id"])
                break

            item["state"] = "retry_wait"
            delay = min(180, 30 * (2 ** (item["attempts"] - 1)))
            write_status("retry_wait", current_index=index, current_video_id=item["video_id"], retry_in_seconds=delay)
            time.sleep(delay)

    failures = []
    for item in items:
        ok, error = validate_archive(archive, item["video_id"])
        if ok:
            item["state"] = "archived"
        elif item["state"] not in TERMINAL_SKIP_STATES:
            failures.append({"video_id": item["video_id"], "error": error})
    final_state = "complete" if not failures else "complete_with_blocked"
    write_status(final_state, validation_failures=failures)
    append_event(events_path, "worker_finished", state=final_state, failures=failures)
    return finish(0 if not failures else 6)


if __name__ == "__main__":
    raise SystemExit(main())
