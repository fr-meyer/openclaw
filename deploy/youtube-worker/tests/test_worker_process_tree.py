"""Native Windows process fixtures only; no provider, extractor or run state."""
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

WORKER = Path(__file__).resolve().parents[1] / "runtime/scripts/youtube_global_chunk_worker.py"
spec = importlib.util.spec_from_file_location("native_process_fixture_worker", WORKER)
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)


@unittest.skipUnless(os.name == "nt", "requires native Windows Job Objects")
class NativeWorkerProcessTreeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.receipt = self.root / "processes.json"
        self.archiver = self.root / "fixture_archiver.py"
        self.archiver.write_text(
            "import json, os, pathlib, subprocess, sys, time\n"
            "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
            "pathlib.Path(sys.argv[1]).write_text(json.dumps([os.getpid(), child.pid]))\n"
            "time.sleep(60)\n", encoding="utf-8",
        )
        from ctypes import wintypes
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.kernel.OpenProcess.restype = wintypes.HANDLE
        self.kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self.kernel.WaitForSingleObject.restype = wintypes.DWORD
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel.CloseHandle.restype = wintypes.BOOL

    def open_fixture_handles(self):
        deadline = time.monotonic() + 10
        pids = None
        while pids is None:
            try: pids = json.loads(self.receipt.read_text())
            except (FileNotFoundError, json.JSONDecodeError):
                if time.monotonic() >= deadline: self.fail("native fixture did not start")
                time.sleep(0.05)
        handles = []
        for pid in pids:
            handle = self.kernel.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE
            self.assertTrue(handle, "cannot retain fixture process handle")
            self.addCleanup(self.kernel.CloseHandle, handle)
            handles.append(handle)
        return handles

    def assert_stopped(self, handles):
        for handle in handles:
            self.assertEqual(self.kernel.WaitForSingleObject(handle, 5000), 0, "fixture descendant survived containment")

    def launch_fixture(self):
        process = worker.start_archive_process([sys.executable, str(self.archiver), str(self.receipt)])
        self.addCleanup(worker.close_archive_process, process)
        return process

    def test_timeout_termination_stops_archiver_and_descendant(self):
        process = self.launch_fixture()
        handles = self.open_fixture_handles()
        worker.terminate_archive_process(process)
        process.communicate(timeout=5)
        process._archive_job.wait_empty()
        self.assert_stopped(handles)

    def test_noninherited_job_handle_close_stops_entire_attempt(self):
        process = self.launch_fixture()
        handles = self.open_fixture_handles()
        worker.close_archive_process(process)
        process.communicate(timeout=5)
        self.assert_stopped(handles)

    def test_worker_death_closes_job_and_stops_descendants(self):
        owner_script = self.root / "fixture_worker.py"
        owner_script.write_text(
            "import importlib.util, sys, time\n"
            "spec = importlib.util.spec_from_file_location('worker', sys.argv[1])\n"
            "worker = importlib.util.module_from_spec(spec); spec.loader.exec_module(worker)\n"
            "process = worker.start_archive_process([sys.executable, sys.argv[2], sys.argv[3]])\n"
            "time.sleep(60)\n", encoding="utf-8",
        )
        owner = subprocess.Popen([sys.executable, str(owner_script), str(WORKER), str(self.archiver), str(self.receipt)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        def stop_owner():
            if owner.poll() is None: owner.kill()
            owner.wait(timeout=5)
        self.addCleanup(stop_owner)
        handles = self.open_fixture_handles()
        stop_owner()
        self.assert_stopped(handles)

    def test_bootstrap_preserves_unsigned_windows_interruption_status(self):
        script = self.root / "fixture_status.py"
        script.write_text("import ctypes\nctypes.WinDLL('kernel32').ExitProcess(0xC000026B)\n", encoding="utf-8")
        process = worker.start_archive_process([sys.executable, str(script)])
        stdout, stderr, code = worker.communicate_archive_process(process, timeout=5)
        self.assertEqual(code, 0xC000026B)
        self.assertEqual(worker.classify(stderr + stdout, code), "worker_session_interrupted")


if __name__ == "__main__": unittest.main()
