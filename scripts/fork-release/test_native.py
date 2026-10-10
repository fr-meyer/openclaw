"""Offline regressions for the retained disk-scan race and downstream receipts."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import native

HERE = Path(__file__).resolve().parent


class NativeDiskAndReceipt(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.source = self.root / "source"
        self.source.mkdir()
        self.env = patch.dict(os.environ, {
            "RUNNER_TEMP": str(self.root), "GITHUB_WORKSPACE": str(self.source),
        }, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.n = native.Native(self.source, HERE.parent.parent)
        self.store = self.n.w / "store/v11/files"
        self.store.mkdir(parents=True)
        self.stream = self.store / "stream278022"
        self.diagnostic = f"du: cannot access '{self.stream}': No such file or directory\n"
        self.free = patch.object(native.shutil, "disk_usage", return_value=SimpleNamespace(free=12 * native.GIB))
        self.free.start()
        self.addCleanup(self.free.stop)

    def scan(self, code=0, stderr="", used=100):
        return subprocess.CompletedProcess([], code,
            f"{used}\t{self.source}\n0\t{self.n.w}\n", stderr)

    def fail_scan(self, scan, message="disk scan failed"):
        with patch.object(native.subprocess, "run", return_value=scan) as probe:
            with self.assertRaisesRegex(RuntimeError, message):
                self.n.disk()
            self.assertEqual(probe.call_count, 1)
        self.assertNotIn("diskScanRaceCount", self.n.r)

    def test_disappearing_real_temporary_file_requires_clean_rescan(self):
        self.stream.write_text("temporary store data")
        def probe(*args, **kwargs):
            self.assertEqual(args[0], ["du", "-sx", "--block-size=1", str(self.source), str(self.n.w)])
            self.assertEqual(kwargs["env"]["LC_ALL"], "C")
            self.assertGreater(kwargs["timeout"], 0)
            self.assertLessEqual(kwargs["timeout"], 30)
            if self.stream.exists():
                self.stream.unlink()
                return self.scan(1, self.diagnostic)
            return self.scan(used=200)
        with patch.object(native.subprocess, "run", side_effect=probe) as scan:
            self.n.disk()
        self.assertEqual(scan.call_count, 2)
        self.assertEqual(self.n.r["diskScanRaceCount"], 1)
        self.assertEqual(self.n.r["diskScanRaceSamples"][0]["diagnostic"], self.diagnostic)
        self.assertEqual(self.n.r["peakTaskBytes"], 200)

    def test_persistent_missing_file_refuses_without_third_scan(self):
        with patch.object(native.subprocess, "run", return_value=self.scan(1, self.diagnostic)) as scan:
            with self.assertRaisesRegex(RuntimeError, "stream278022.*No such file"):
                self.n.disk()
        self.assertEqual(scan.call_count, 2)

    def test_permission_and_io_errors_never_retry(self):
        for cause in ("Permission denied", "Operation not permitted", "Input/output error"):
            with self.subTest(cause=cause):
                self.fail_scan(self.scan(1, f"du: cannot access '{self.stream}': {cause}\n"), cause)

    def test_mixed_missing_and_permission_errors_never_retry(self):
        self.fail_scan(self.scan(1, self.diagnostic + "du: cannot read directory '/private': Permission denied\n"), "Permission denied")

    def test_other_exit_or_empty_diagnostic_never_retry(self):
        for code, stderr in ((2, self.diagnostic), (1, ""), (0, self.diagnostic), (1, "unexpected warning\n")):
            with self.subTest(code=code, stderr=stderr):
                self.fail_scan(self.scan(code, stderr))

    def test_other_missing_paths_are_not_temporary_store_races(self):
        for path in (self.source / "stream278022", self.store / "normal-file", self.store / "streamX"):
            with self.subTest(path=path):
                self.fail_scan(self.scan(1, f"du: cannot access '{path}': No such file or directory\n"))

    def test_existing_or_recreated_file_refuses(self):
        self.stream.write_text("recreated")
        self.fail_scan(self.scan(1, self.diagnostic))

    def test_missing_parent_refuses(self):
        self.store.rmdir()
        self.fail_scan(self.scan(1, self.diagnostic))

    def test_symlinked_store_parent_refuses(self):
        self.store.rmdir()
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir()
        self.store.symlink_to(elsewhere, target_is_directory=True)
        self.fail_scan(self.scan(1, self.diagnostic))

    def test_lstat_permission_failure_propagates(self):
        with patch.object(native.subprocess, "run", return_value=self.scan(1, self.diagnostic)) as scan:
            real = Path.lstat
            def denied(path):
                if path == self.stream:
                    raise PermissionError("synthetic lstat permission denied")
                return real(path)
            with patch.object(Path, "lstat", denied), self.assertRaises(PermissionError):
                self.n.disk()
        self.assertEqual(scan.call_count, 1)

    def test_timeout_propagates_without_retry(self):
        with patch.object(native.subprocess, "run", side_effect=subprocess.TimeoutExpired(["du"], 30)) as scan:
            with self.assertRaises(subprocess.TimeoutExpired):
                self.n.disk()
        self.assertEqual(scan.call_count, 1)

    def test_rescan_shares_original_thirty_second_budget(self):
        with patch.object(native.time, "monotonic", side_effect=[0, 0, 7]), patch.object(native.subprocess, "run", side_effect=[self.scan(1, self.diagnostic), self.scan()]) as scan:
            self.n.disk()
        self.assertEqual([x.kwargs["timeout"] for x in scan.call_args_list], [30, 23])

    def test_exhausted_rescan_budget_does_not_launch_second_scan(self):
        with patch.object(native.time, "monotonic", side_effect=[0, 0, 30]), patch.object(native.subprocess, "run", return_value=self.scan(1, self.diagnostic)) as scan:
            with self.assertRaises(subprocess.TimeoutExpired):
                self.n.disk()
        self.assertEqual(scan.call_count, 1)

    def test_missing_malformed_negative_or_wrong_root_total_refuses(self):
        for output in ("", f"1\t{self.source}\n", f"-1\t{self.source}\n0\t{self.n.w}\n", f"1\t{self.source}\n0\t{self.source}\n", "unparseable\n\n"):
            with self.subTest(output=output), patch.object(native.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, output, "")):
                with self.assertRaisesRegex(RuntimeError, "disk scan"):
                    self.n.disk()

    def test_disk_budget_failure_not_cleared_by_rescan(self):
        with patch.object(native.subprocess, "run", return_value=self.scan(1, self.diagnostic, 10 * native.GIB + 1)) as scan:
            with self.assertRaisesRegex(RuntimeError, "disk/reserve budget"):
                self.n.disk()
        self.assertEqual(scan.call_count, 1)

    def test_clean_rescan_still_enforces_disk_budget(self):
        with patch.object(native.subprocess, "run", side_effect=[self.scan(1, self.diagnostic), self.scan(used=10 * native.GIB + 1)]):
            with self.assertRaisesRegex(RuntimeError, "disk/reserve budget"):
                self.n.disk()

    def test_reserve_failure_still_refuses(self):
        with patch.object(native.shutil, "disk_usage", return_value=SimpleNamespace(free=2 * native.GIB - 1)), patch.object(native.subprocess, "run", return_value=self.scan(1, self.diagnostic)) as scan:
            with self.assertRaisesRegex(RuntimeError, "disk/reserve budget"):
                self.n.disk()
        self.assertEqual(scan.call_count, 1)

    def test_exact_disk_and_reserve_limits_are_accepted(self):
        with patch.object(native.shutil, "disk_usage", return_value=SimpleNamespace(free=2 * native.GIB)), patch.object(native.subprocess, "run", return_value=self.scan(used=10 * native.GIB)):
            self.n.disk()

    def test_diagnostic_samples_remain_bounded(self):
        with patch.object(native.subprocess, "run", side_effect=[self.scan(1, self.diagnostic), self.scan()] * 10):
            for _ in range(10):
                self.n.disk()
        self.assertEqual(self.n.r["diskScanRaceCount"], 10)
        self.assertEqual(len(self.n.r["diskScanRaceSamples"]), 8)

    def plan(self):
        self.n.plan(json.loads((HERE / "manifest.json").read_text()), json.loads((HERE / "native-inputs.json").read_text()))

    def test_install_failure_enumerates_every_downstream_owner(self):
        self.plan()
        self.n.reached.update(("corepack", "install"))
        self.n.f.append("install")
        self.n.report_not_run()
        missing = {x["stage"] for x in self.n.u}
        self.assertEqual(len(missing), 42)
        self.assertFalse(missing & {"corepack", "install"})
        self.assertTrue({x.replace(":", "-") for x in native.TYPES} <= missing)
        self.assertTrue({"changed-plan", "changed-checks", "source-build", "cli-before"} <= missing)
        self.assertEqual(sum(x.startswith("vitest:") for x in missing), 29)
        self.assertEqual(sum(x.startswith("node:") for x in missing), 5)
        self.n.report_not_run()
        self.assertEqual(len(self.n.u), 42)

    def test_cancelled_owner_is_reported_once_without_execution(self):
        self.plan()
        self.n.cancel = True
        stage = next(x for x in self.n.planned if x.startswith("vitest:"))
        with patch.object(native.subprocess, "Popen") as start:
            self.n.run("cancelled", ["not-executed"], owners=(stage,))
        start.assert_not_called()
        self.n.report_not_run()
        declarations = [x for item in self.n.u for x in item.get("stages", [item.get("stage")])]
        self.assertEqual(declarations.count(stage), 1)
        self.assertEqual(set(declarations), set(self.n.planned))

    def test_all_executed_stages_have_no_not_run_records(self):
        self.plan()
        self.n.reached.update(self.n.planned)
        self.n.report_not_run()
        self.assertEqual(self.n.u, [])

    def test_main_exception_persists_downstream_not_run_receipt(self):
        def abort(n):
            n.plan(json.loads((HERE / "manifest.json").read_text()), json.loads((HERE / "native-inputs.json").read_text()))
            n.reached.update(("corepack", "install"))
            raise RuntimeError("install failed; dependents unrun")
        with patch.object(native.Native, "execute", abort), patch.object(sys, "argv", ["native.py", "run", "--source", str(self.source), "--tooling", str(HERE.parent.parent)]):
            self.assertEqual(native.main(), 1)
        receipt = json.loads((self.n.o / "receipt.json").read_text())
        self.assertFalse(receipt["complete"])
        self.assertEqual(len(receipt["notRun"]), 42)
        self.assertEqual(receipt["executedStages"], ["corepack", "install"])

    def test_terminated_node_owner_does_not_mark_later_files_executed(self):
        self.plan()
        paths = json.loads((HERE / "manifest.json").read_text())["gates"]["node"]
        original = self.n.run
        def synthetic(name, argv, seconds, owners):
            return original(name, [sys.executable, "-c", "import time;time.sleep(60)"], seconds, owners=owners)
        with patch.object(self.n, "run", side_effect=synthetic), patch.object(native.subprocess, "check_output", side_effect=subprocess.CalledProcessError(1, ["ps"])):
            self.n.node_contracts(paths)
        self.n.report_not_run()
        started = {x for x in self.n.reached if x.startswith("node:")}
        self.assertEqual(started, {"node:" + paths[0]})
        unrun = {x for item in self.n.u for x in item.get("stages", [item.get("stage")])}
        self.assertTrue({"node:" + x for x in paths[1:]} <= unrun)
        self.assertEqual(len(self.n.c), 5)
        self.assertTrue(all(x["exit"] is None for x in self.n.c[1:]))
        self.assertIsNone(self.n.p)

    def test_node_files_share_original_six_hundred_second_budget(self):
        paths = [f"owner-{i}.mjs" for i in range(5)]
        with patch.object(native.time, "monotonic", side_effect=[0, 0, 7, 90, 400, 600]), patch.object(self.n, "run", return_value=({"exit": 0}, "# tests 1\n# pass 1\n# fail 0\n# skipped 0\n")) as run:
            self.n.node_contracts(paths)
        self.assertEqual([x.args[2] for x in run.call_args_list], [600, 593, 510, 200, 0])
        self.assertEqual([x.args[1][-1] for x in run.call_args_list], paths)
        self.assertTrue(all(x.args[1][2] == "--test-concurrency=1" for x in run.call_args_list))

    def test_exhausted_command_budget_never_starts_owner(self):
        with patch.object(native.subprocess, "Popen") as start:
            r, _ = self.n.run("out-of-time", ["not-executed"], seconds=0, owners=("node:owner.mjs",))
        start.assert_not_called()
        self.assertIsNone(r["exit"])
        self.assertNotIn("node:owner.mjs", self.n.reached)
        self.assertEqual(self.n.u[0]["stages"], ["node:owner.mjs"])

    def test_empty_node_report_records_failure_and_continues_other_owners(self):
        with patch.object(self.n, "run", side_effect=[({"exit": 0}, ""), ({"exit": 0}, "# tests 1\n# pass 1\n# fail 0\n# skipped 0\n")]) as run:
            self.n.node_contracts(["empty.mjs", "other.mjs"])
        self.assertEqual(run.call_count, 2)
        self.assertEqual(self.n.f, ["node-contract-1"])

    def test_finalizer_reports_all_stages_when_native_never_started(self):
        with patch.object(sys, "argv", ["native.py", "finalize", "--source", str(self.source), "--tooling", str(HERE.parent.parent)]):
            self.assertEqual(native.main(), 0)
        receipt = json.loads((self.n.o / "receipt.json").read_text())
        self.assertFalse(receipt["complete"])
        self.assertEqual(len(receipt["notRun"]), 44)
        self.assertEqual(receipt["executedStages"], [])


if __name__ == "__main__":
    unittest.main()
