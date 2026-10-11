"""Cheap strict disk accounting, owned pause/cleanup, and receipt regressions."""
import contextlib
import io
import json
import signal
import time
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
NODE_TAP = "# tests 1\n# suites 0\n# pass 1\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n# duration_ms 0.01\n"


class NativeNodeSummary(unittest.TestCase):
    def test_complete_tap_and_explicit_historical_spec(self):
        counts = native.node_summary("TAP version 13\nok 1 - contract\n1..1\n" + NODE_TAP)
        self.assertEqual(counts, {"tests": 1, "suites": 0, "pass": 1, "fail": 0, "cancelled": 0, "skipped": 0, "todo": 0})
        spec = NODE_TAP.replace("# ", "ℹ ")
        self.assertEqual(native.node_summary(spec, "spec"), counts)
        with self.assertRaisesRegex(RuntimeError, "wrong reporter"):
            native.node_summary(spec)

    def test_missing_duplicate_reordered_or_nonterminal_footer_refuses(self):
        rows = NODE_TAP.splitlines()
        malformed = ["", NODE_TAP + "unexpected output\n", NODE_TAP + NODE_TAP,
                     "[BOUNDED LOG; MIDDLE OMITTED]\n" + NODE_TAP]
        for i in range(len(rows)):
            malformed.append("\n".join(rows[:i] + rows[i + 1:]) + "\n")
            malformed.append("\n".join(rows[:i] + [rows[i]] + rows[i:]) + "\n")
        malformed.append("\n".join([rows[1], rows[0]] + rows[2:]) + "\n")
        for text in malformed:
            with self.subTest(text=text), self.assertRaises(RuntimeError):
                native.node_summary(text)

    def test_malformed_counters_duration_or_mixed_reporters_refuse(self):
        rows = NODE_TAP.splitlines()
        for i, row in enumerate(rows):
            key = row.rsplit(" ", 1)[0]
            invalid = ("-1", "+1", "01", "nan", "", "1e2", "1٢", "١", "0.١")
            if i < len(rows) - 1:
                invalid += ("1.0",)
            for value in invalid:
                with self.subTest(row=row, value=value), self.assertRaises(RuntimeError):
                    native.node_summary("\n".join(rows[:i] + [key + " " + value] + rows[i + 1:]))
        with self.assertRaises(RuntimeError):
            native.node_summary(NODE_TAP.replace("# fail", "ℹ fail"))
        with self.assertRaisesRegex(RuntimeError, "unknown Node reporter"):
            native.node_summary(NODE_TAP, "unknown")

    def test_empty_inconsistent_failed_cancelled_skipped_or_todo_refuse(self):
        invalid = [NODE_TAP.replace("# tests 1", "# tests 0").replace("# pass 1", "# pass 0"),
                   NODE_TAP.replace("# pass 1", "# pass 0"),
                   NODE_TAP.replace("# pass 1", "# pass 2")]
        invalid += [NODE_TAP.replace(f"# {key} 0", f"# {key} 1")
                    for key in ("fail", "cancelled", "skipped", "todo")]
        for text in invalid:
            with self.subTest(text=text), self.assertRaisesRegex(RuntimeError, "failed/empty"):
                native.node_summary(text)


class NativeFixture(unittest.TestCase):
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


class NativeDiskAndReceipt(NativeFixture):
    def test_child_temporary_files_stay_in_the_measured_owned_work_root(self):
        code = "import json,os,tempfile;fd,path=tempfile.mkstemp();os.write(fd,b'x'*1024);os.close(fd);print(json.dumps({'path':path,'bytes':os.stat(path).st_size}));os.unlink(path)"
        child = subprocess.run([sys.executable, "-I", "-S", "-c", code], env=self.n.env, capture_output=True, text=True, timeout=10, check=True)
        result = json.loads(child.stdout)
        owned = self.n.w / "tmp"
        self.assertEqual(Path(result["path"]).parent.resolve(), owned)
        self.assertEqual(result["bytes"], 1024)
        self.assertFalse(Path(result["path"]).exists())
        self.assertTrue(owned.is_dir())
        self.assertEqual({self.n.env[key] for key in ("TMPDIR", "TMP", "TEMP")}, {str(owned)})

    def test_any_missing_entry_refuses_with_zero_unread_allowance(self):
        self.fail_scan(self.scan(1, self.diagnostic), "No such file")
        self.assertEqual(self.n.r["diskAccounting"]["unreadEntryAllowanceBytes"], 0)
        self.assertEqual(self.n.r["diskAccounting"]["unknownFootprint"], "unbounded; refuse")

    def test_permission_io_and_mixed_errors_are_fatal(self):
        for cause in ("Permission denied", "Operation not permitted", "Input/output error"):
            with self.subTest(cause=cause):
                self.fail_scan(self.scan(1, self.diagnostic + cause), cause)

    def test_other_exit_warning_or_empty_diagnostic_is_fatal(self):
        for code, stderr in ((2, self.diagnostic), (1, ""), (0, self.diagnostic), (1, "unexpected warning\n")):
            with self.subTest(code=code, stderr=stderr):
                self.fail_scan(self.scan(code, stderr))

    def test_timeout_propagates_without_retry(self):
        with patch.object(native.subprocess, "run", side_effect=subprocess.TimeoutExpired(["du"], 30)) as scan:
            with self.assertRaises(subprocess.TimeoutExpired):
                self.n.disk()
        self.assertEqual(scan.call_count, 1)

    def test_probe_and_scan_share_thirty_seconds(self):
        with patch.object(native.time, "monotonic", side_effect=[0, 0, 7, 7, 9, 10]), patch.object(native.subprocess, "run", return_value=self.scan()) as scan:
            self.n.disk()
        self.assertEqual(scan.call_args.kwargs["timeout"], 23)
        self.assertEqual(scan.call_args.args[0], ["du", "-sx", "--block-size=1", "--no-dereference", str(self.source), str(self.n.w)])
        self.assertEqual(scan.call_args.kwargs["env"]["LC_ALL"], "C")

    def test_command_and_global_deadlines_bound_probe(self):
        for global_end, command_end, expected in ((100, 4, 4), (3, 100, 3)):
            self.n.end, self.n.command_end = global_end, command_end
            with self.subTest(expected=expected), patch.object(native.time, "monotonic", return_value=0), patch.object(native.subprocess, "run", return_value=self.scan()) as scan:
                self.n.disk()
            self.assertEqual(scan.call_args.kwargs["timeout"], expected)

    def test_expired_or_cancelled_probe_does_not_scan(self):
        for cancelled in (False, True):
            self.n.cancel = cancelled
            self.n.command_end = 0
            with self.subTest(cancelled=cancelled), patch.object(native.subprocess, "run") as scan:
                with self.assertRaises((RuntimeError, subprocess.TimeoutExpired)):
                    self.n.disk()
                scan.assert_not_called()

    def test_scan_overrun_fails_even_if_du_returns_success(self):
        clock = [0]
        def overrun(*args, **kwargs):
            clock[0] = 30
            return self.scan()
        with patch.object(native.time, "monotonic", side_effect=lambda: clock[0]), patch.object(native.subprocess, "run", side_effect=overrun) as scan:
            with self.assertRaises(subprocess.TimeoutExpired):
                self.n.disk()
        scan.assert_called_once()

    def test_missing_malformed_negative_or_wrong_root_total_refuses(self):
        for output in ("", f"1\t{self.source}\n", f"-1\t{self.source}\n0\t{self.n.w}\n", f"1\t{self.source}\n0\t{self.source}\n", "unparseable\n\n"):
            with self.subTest(output=output), patch.object(native.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, output, "")):
                with self.assertRaisesRegex(RuntimeError, "disk scan"):
                    self.n.disk()

    def test_disk_ceiling_and_reserve_both_enforced(self):
        self.fail_scan(self.scan(used=10 * native.GIB + 1), "disk/reserve budget")
        with patch.object(native.shutil, "disk_usage", return_value=SimpleNamespace(free=2 * native.GIB - 1)):
            self.fail_scan(self.scan(), "disk/reserve budget")

    def test_exact_disk_and_reserve_limits_are_accepted(self):
        with patch.object(native.shutil, "disk_usage", return_value=SimpleNamespace(free=2 * native.GIB)), patch.object(native.subprocess, "run", return_value=self.scan(used=10 * native.GIB)):
            self.n.disk()

    def test_both_filesystems_require_reserve(self):
        def usage(root):
            return SimpleNamespace(free=(2 * native.GIB - 1) if root == self.n.w else 12 * native.GIB)
        with patch.object(native.shutil, "disk_usage", side_effect=usage):
            self.fail_scan(self.scan(), "disk/reserve budget")

    def test_symlinked_relative_and_overlapping_roots_refuse_before_scan(self):
        alias = self.root / "alias"
        alias.symlink_to(self.source, target_is_directory=True)
        for root in (str(alias), "relative", str(self.root)):
            with self.subTest(root=root), patch.dict(os.environ, GITHUB_WORKSPACE=root), patch.object(native.subprocess, "run") as scan:
                with self.assertRaisesRegex(RuntimeError, "disk root"):
                    self.n.disk()
                scan.assert_not_called()

    def test_source_outside_workspace_refuses_before_scan(self):
        other = self.root / "other"
        other.mkdir()
        with patch.dict(os.environ, GITHUB_WORKSPACE=str(other)), patch.object(native.subprocess, "run") as scan:
            with self.assertRaisesRegex(RuntimeError, "source escapes"):
                self.n.disk()
            scan.assert_not_called()

    def test_root_replaced_during_scan_refuses(self):
        def replace(*args, **kwargs):
            self.source.rename(self.root / "original")
            self.source.mkdir()
            return self.scan()
        with patch.object(native.subprocess, "run", side_effect=replace), self.assertRaisesRegex(RuntimeError, "root replaced"):
            self.n.disk()

    def test_root_permission_and_io_failure_propagates_before_scan(self):
        for error in (PermissionError("permission"), OSError("I/O")):
            with self.subTest(error=error), patch.object(Path, "lstat", side_effect=error), patch.object(native.subprocess, "run") as scan:
                with self.assertRaises(OSError):
                    self.n.disk()
                scan.assert_not_called()

    def test_probe_receipt_distinguishes_global_work_exhaustion_from_own_probe_timeout(self):
        for global_work, timeout, owner, phase in ((20, False, "global-work", "totals-validation"), (100, True, "probe", "du")):
            clock = [0]
            self.n.work_end, self.n.end, self.n.command_end = global_work, 200, 200
            def scan(*args, **kwargs):
                clock[0] = min(global_work, 30)
                if timeout:
                    raise subprocess.TimeoutExpired("du", 30)
                return self.scan()
            with self.subTest(owner=owner), patch.object(native.time, "monotonic", side_effect=lambda: clock[0]), patch.object(native.subprocess, "run", side_effect=scan):
                with self.assertRaises(subprocess.TimeoutExpired):
                    self.n.disk()
                self.assertIn("diskProbeFailures", self.n.r)
                failure = self.n.r["diskProbeFailures"][-1]
                self.assertEqual(failure["deadlineOwner"], owner)
                self.assertEqual(failure["failurePhase"], phase)
                self.assertEqual(failure["configuredSeconds"], 30)
                self.assertEqual(failure["availableSeconds"], min(global_work, 30))
                self.assertEqual(failure["unknownFootprint"], "unbounded; refuse")
                self.assertIsNone(self.n.probe)

    def test_shutdown_reserve_refuses_a_new_owner_before_the_native_limit(self):
        self.n.started, self.n.end, self.n.work_end = 0, 6600, 6525
        child = SimpleNamespace(pid=123456789, poll=lambda: 0, wait=lambda: 0)
        with patch.object(native.time, "monotonic", return_value=6525), patch.object(native.subprocess, "Popen", return_value=child) as launch, patch.object(self.n, "dispose_cache"), patch.object(self.n, "source_snapshot"):
            result, _ = self.n.run("late-owner", ["not-executed"])
        launch.assert_not_called()
        self.assertIsNone(result["exit"])
        self.assertNotIn("late-owner", self.n.reached)
        self.assertEqual(self.n.u[0]["stages"], ["late-owner"])

    def test_terminal_overrun_cannot_be_reported_complete(self):
        write = Path.write_text
        for during_write in (False, True):
            clock = [6599.9 if during_write else 6601]
            def execute(n):
                n.started, n.end = 0, 6600
            def persist(path, *args, **kwargs):
                result = write(path, *args, **kwargs)
                clock[0] = 6601.1
                return result
            with self.subTest(during_write=during_write), patch.object(native.Native, "execute", execute), patch.object(native.Native, "source_snapshot"), patch.object(native.time, "monotonic", side_effect=lambda: clock[0]), patch.object(Path, "write_text", persist), patch.object(sys, "argv", ["native.py", "run", "--source", str(self.source), "--tooling", str(HERE.parent.parent)]):
                self.assertEqual(native.main(), 1)
            receipt = json.loads((self.n.o / "receipt.json").read_text())
            self.assertFalse(receipt["complete"])
            self.assertTrue(receipt["timeAccounting"]["envelopeExceeded"])
            self.assertEqual(receipt["timeAccounting"]["nativeLimitSeconds"], 6600)
            self.assertIn("native total deadline exceeded", receipt["failures"])

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
        clock, finished = [0], iter((7, 90, 400, 599, 600))
        def owner(name, argv, seconds, owners):
            deadline = clock[0] + seconds
            clock[0] = next(finished)
            return {"exit": 0, "reason": None, "deadline": {"ownerEndMonotonic": deadline}}, NODE_TAP
        with patch.object(native.time, "monotonic", side_effect=lambda: clock[0]), patch.object(self.n, "run", side_effect=owner) as run:
            self.n.node_contracts(paths)
        self.assertEqual([x.args[2] for x in run.call_args_list], [600, 593, 510, 200, 1])
        self.assertEqual([x.args[1][-1] for x in run.call_args_list], paths)
        self.assertTrue(all(x.args[1][2] == "--test-concurrency=1" for x in run.call_args_list))
        self.assertTrue(all(x.args[1][3] == "--test-reporter=tap" for x in run.call_args_list))
        self.assertEqual(self.n.f, ["node-contract-5"])

    def test_expired_node_report_never_parses_or_qualifies_returned_owner(self):
        self.n.end = 1000
        record = {"exit": 0, "reason": None, "deadline": {"ownerEndMonotonic": 0}}
        with patch.object(native.time, "monotonic", return_value=0), patch.object(self.n, "run", return_value=(record, NODE_TAP)), patch.object(native, "node_summary") as parse:
            self.n.node_contracts(["owner.mjs"])
        parse.assert_not_called()
        self.assertEqual(record["exit"], 0)
        self.assertEqual(record["tests"], {})
        self.assertIn("Node report deadline exhausted", record["reportFailure"])
        self.assertEqual(self.n.f, ["node-contract-1"])

    def test_node_parser_crossing_owner_deadline_retains_failure_without_pass_totals(self):
        self.n.end = 1000
        clock = [0]
        record = {"exit": 0, "reason": None, "deadline": {"ownerEndMonotonic": 1}}
        original = native.node_summary
        def slow_parse(text):
            totals = original(text)
            clock[0] = 2
            return totals
        with patch.object(native.time, "monotonic", side_effect=lambda: clock[0]), patch.object(self.n, "run", return_value=(record, NODE_TAP)), patch.object(native, "node_summary", side_effect=slow_parse) as parse:
            self.n.node_contracts(["owner.mjs"])
        parse.assert_called_once()
        self.assertEqual(record["exit"], 0)
        self.assertEqual(record["tests"], {})
        self.assertIn("Node report deadline exhausted", record["reportFailure"])
        self.assertEqual(self.n.f, ["node-contract-1"])

    def test_missing_node_owner_bound_never_parses_or_qualifies_successful_exit(self):
        for deadline in (None, {}):
            self.n.cancel = False
            self.n.f.clear()
            record = {"exit": 0, "reason": None}
            if deadline is not None:
                record["deadline"] = deadline
            with self.subTest(deadline=deadline), patch.object(self.n, "run", return_value=(record, NODE_TAP)), patch.object(native, "node_summary") as parse:
                self.n.node_contracts(["owner.mjs"])
                parse.assert_not_called()
                self.assertEqual(record["exit"], 0)
                self.assertIsNone(record["reason"])
                self.assertEqual(record["tests"], {})
                self.assertEqual(record["reportFailure"], "Node report refused: owner deadline unavailable")
                self.assertEqual(self.n.f, ["node-contract-1"])
                self.assertTrue(self.n.cancel)

    def test_exhausted_command_budget_never_starts_owner(self):
        with patch.object(native.subprocess, "Popen") as start:
            r, _ = self.n.run("out-of-time", ["not-executed"], seconds=0, owners=("node:owner.mjs",))
        start.assert_not_called()
        self.assertIsNone(r["exit"])
        self.assertNotIn("node:owner.mjs", self.n.reached)
        self.assertEqual(self.n.u[0]["stages"], ["node:owner.mjs"])

    def test_empty_node_report_records_failure_and_continues_other_owners(self):
        with patch.object(self.n, "run", side_effect=[({"exit": 0, "reason": None, "deadline": {"ownerEndMonotonic": self.n.end}}, ""), ({"exit": 0, "reason": None, "deadline": {"ownerEndMonotonic": self.n.end}}, NODE_TAP)]) as run:
            self.n.node_contracts(["empty.mjs", "other.mjs"])
        self.assertEqual(run.call_count, 2)
        self.assertEqual(self.n.f, ["node-contract-1"])

    def test_valid_node_summary_cannot_override_failed_exit_or_reason(self):
        for exit_code, reason in ((1, None), (-15, "cancelled"), (0, "cleanup failed")):
            record = {"exit": exit_code, "reason": reason, "deadline": {"ownerEndMonotonic": self.n.end}}
            with self.subTest(exit=exit_code, reason=reason), patch.object(self.n, "run", return_value=(record, NODE_TAP)):
                self.n.node_contracts(["owner.mjs"])
            self.assertEqual(record["exit"], exit_code)
            self.assertEqual(record["reason"], reason)
            self.assertEqual(record["tests"]["pass"], 1)
            self.assertEqual(record["reportFailure"], "Node command failed/cancelled")
            self.assertEqual(self.n.f, ["node-contract-1"])
            self.n.f.clear()

    def test_truncated_node_log_is_not_requalified_from_complete_footer(self):
        record = {"exit": 0, "reason": None, "logTruncated": True, "deadline": {"ownerEndMonotonic": self.n.end}}
        with patch.object(self.n, "run", return_value=(record, NODE_TAP)):
            self.n.node_contracts(["owner.mjs"])
        self.assertEqual(record["reportFailure"], "Node report truncated")
        self.assertEqual(self.n.f, ["node-contract-1"])

    def test_finalizer_reports_all_stages_when_native_never_started(self):
        with patch.object(sys, "argv", ["native.py", "finalize", "--source", str(self.source), "--tooling", str(HERE.parent.parent)]):
            self.assertEqual(native.main(), 0)
        receipt = json.loads((self.n.o / "receipt.json").read_text())
        self.assertFalse(receipt["complete"])
        self.assertEqual(len(receipt["notRun"]), 44)
        self.assertEqual(receipt["executedStages"], [])

class OwnedPause(NativeFixture):
    def p(self, pid, state="R", group=None, session=100):
        return {"pid":pid, "parent":1, "group":group or pid, "session":session,
                "start":pid+500, "state":state, "rss":4096}

    @contextlib.contextmanager
    def simulation(self, snapshots=None, stopped=True, identity=None, signal_error=None):
        self.n.p = SimpleNamespace(pid=100)
        self.procs = {100:self.p(100), 200:self.p(200)}
        self.sent = []
        def send(fd, sig):
            self.sent.append((fd-1000, sig))
            if signal_error:
                signal_error(fd-1000, sig)
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(self.n, "owned", side_effect=snapshots, return_value=self.procs))
            stack.enter_context(patch.object(self.n, "stopped", return_value=stopped))
            stack.enter_context(patch.object(native, "identity", side_effect=identity or (lambda pid:(self.procs[pid]["group"],self.procs[pid]["start"]))))
            stack.enter_context(patch.object(native.os, "pidfd_open", side_effect=lambda pid:pid+1000, create=True))
            stack.enter_context(patch.object(native.signal, "pidfd_send_signal", side_effect=send, create=True))
            self.close = stack.enter_context(patch.object(native.os, "close"))
            yield

    def test_freezes_root_and_detached_group_then_resumes(self):
        with self.simulation(), self.n.quiesced(time.monotonic()+5):
            self.assertEqual(self.sent, [(100,signal.SIGSTOP),(200,signal.SIGSTOP)])
        self.assertEqual(self.sent[-2:], [(100,signal.SIGCONT),(200,signal.SIGCONT)])
        self.assertEqual(self.close.call_count, 2)

    def test_new_descendant_discovered_before_stable_snapshot(self):
        first={100:self.p(100)}
        later={**first,200:self.p(200)}
        with self.simulation([first,later,later,later]), self.n.quiesced(time.monotonic()+5):
            self.assertEqual(self.sent, [(100,signal.SIGSTOP),(200,signal.SIGSTOP)])

    def test_already_stopped_process_keeps_prior_state(self):
        with self.simulation():
            self.procs[200]["state"]="T"
            with self.n.quiesced(time.monotonic()+5):
                self.assertEqual(self.sent, [(100,signal.SIGSTOP)])
        self.assertEqual(self.sent, [(100,signal.SIGSTOP),(100,signal.SIGCONT)])

    def test_pid_reuse_refuses_before_signal_and_closes_handle(self):
        with self.simulation(identity=lambda pid:(pid,99999)):
            with self.assertRaisesRegex(RuntimeError,"process changed before disk pause"):
                with self.n.quiesced(time.monotonic()+5):
                    self.fail("must not admit scan")
        self.assertEqual(self.sent, [])
        self.assertEqual(self.close.call_count,1)

    def test_exited_process_is_safe_without_signal(self):
        with self.simulation(identity=lambda pid:None), self.n.quiesced(time.monotonic()+5):
            self.assertEqual(self.sent, [])
        self.assertEqual(self.close.call_count,2)

    def test_scan_errors_timeout_and_cancellation_resume_every_paused_pid(self):
        for error in (RuntimeError("ENOENT"), PermissionError("denied"), OSError("I/O"), subprocess.TimeoutExpired("du",30)):
            with self.subTest(error=error), self.simulation():
                with self.assertRaises(type(error)):
                    with self.n.quiesced(time.monotonic()+5):
                        raise error
                self.assertEqual(self.sent[-2:], [(100,signal.SIGCONT),(200,signal.SIGCONT)])
        with self.simulation(), self.assertRaisesRegex(RuntimeError,"cancelled"):
            with self.n.quiesced(time.monotonic()+5):
                self.n.cancel=True
        self.assertEqual(self.sent[-2:], [(100,signal.SIGCONT),(200,signal.SIGCONT)])

    def test_stopped_state_timeout_resumes_without_scanning(self):
        clock=[0]
        with self.simulation(stopped=False), patch.object(native.time,"monotonic",side_effect=lambda:clock[0]), patch.object(native.time,"sleep",side_effect=lambda _:clock.__setitem__(0,clock[0]+10)):
            with self.assertRaises(subprocess.TimeoutExpired):
                with self.n.quiesced(30):
                    self.fail("D/running state must not admit scan")
        self.assertEqual(self.sent[-2:], [(100,signal.SIGCONT),(200,signal.SIGCONT)])

    def test_pause_time_reduces_du_timeout_with_no_deadline_extension(self):
        clock=[0]
        with self.simulation(), patch.object(native.time,"monotonic",side_effect=lambda:clock[0]), patch.object(native.time,"sleep",side_effect=lambda _:clock.__setitem__(0,7)), patch.object(native.subprocess,"run",return_value=self.scan()) as scan:
            self.n.disk()
        self.assertEqual(scan.call_args.kwargs["timeout"],23)
        self.assertEqual(self.sent[-2:],[(100,signal.SIGCONT),(200,signal.SIGCONT)])

    def test_resume_failure_attempts_all_handles_then_refuses(self):
        def fail(pid,sig):
            if pid==100 and sig==signal.SIGCONT:raise PermissionError("denied")
        with self.simulation(signal_error=fail), self.assertRaisesRegex(RuntimeError,"resume failed"):
            with self.n.quiesced(time.monotonic()+5):pass
        self.assertEqual(self.sent[-2:],[(100,signal.SIGCONT),(200,signal.SIGCONT)])
        self.assertEqual(self.close.call_count,2)

    def test_stop_failure_still_attempts_resume(self):
        def fail(pid,sig):
            if pid==200 and sig==signal.SIGSTOP:raise PermissionError("denied")
        with self.simulation(signal_error=fail), self.assertRaises(PermissionError):
            with self.n.quiesced(time.monotonic()+5):self.fail("must not admit scan")
        self.assertEqual(self.sent[-2:],[(100,signal.SIGCONT),(200,signal.SIGCONT)])

    def test_new_or_running_writer_after_scan_refuses(self):
        first={100:self.p(100)}
        later={**first,200:self.p(200)}
        with self.simulation([first,first,later]), self.assertRaisesRegex(RuntimeError,"writers changed"):
            with self.n.quiesced(time.monotonic()+5):pass
        self.assertEqual(self.sent[-1],(100,signal.SIGCONT))

    def test_malformed_snapshot_permission_and_foreign_group_refuse(self):
        self.n.p=SimpleNamespace(pid=100)
        for output in ("bad\n", "100 1 100 100 -1\n", "100 1 100 100 4\n100 1 100 100 4\n"):
            with self.subTest(output=output),patch.object(native.subprocess,"check_output",return_value=output):
                with self.assertRaisesRegex(RuntimeError,"malformed process"):
                    self.n.owned(time.monotonic()+5)
        with patch.object(native.subprocess,"check_output",return_value="100 1 100 100 4\n"),patch.object(native,"process",side_effect=PermissionError("denied")),self.assertRaises(PermissionError):
            self.n.owned(time.monotonic()+5)
        p=self.p(100,group=os.getpgrp())
        with patch.object(native.subprocess,"check_output",return_value=f"100 1 {p['group']} 100 4\n"),patch.object(native,"process",return_value=p),self.assertRaisesRegex(RuntimeError,"supervisor group"):
            self.n.owned(time.monotonic()+5)

    def test_expired_snapshot_never_signals_new_process(self):
        clock=[0]
        with self.simulation(),patch.object(native.time,"monotonic",side_effect=lambda:clock[0]):
            def late(_):
                clock[0]=30
                return self.procs
            self.n.owned.side_effect=late
            with self.assertRaises(subprocess.TimeoutExpired):
                with self.n.quiesced(30):self.fail("expired snapshot must not admit scan")
        self.assertEqual(self.sent,[])
        self.close.assert_not_called()

    def test_deadline_expiring_during_identity_check_does_not_pause(self):
        clock=[0]
        def late(pid):
            clock[0]=30
            return pid,pid+500
        with self.simulation(identity=late),patch.object(native.time,"monotonic",side_effect=lambda:clock[0]),self.assertRaises(subprocess.TimeoutExpired):
            with self.n.quiesced(30):self.fail("must not admit scan")
        self.assertEqual(self.sent,[])
        self.assertEqual(self.close.call_count,1)

    def test_new_session_member_rss_peak_and_limit_are_enforced(self):
        self.n.p=SimpleNamespace(pid=100)
        procs={100:self.p(100),201:self.p(201,group=100)}
        for extra in (0,1):
            rows=f"100 1 100 100 0\n201 1 100 100 {12*native.GIB//1024+extra}\n"
            with self.subTest(extra=extra),patch.object(native.subprocess,"check_output",return_value=rows),patch.object(native,"process",side_effect=lambda pid:procs.get(pid)):
                if extra:
                    with self.assertRaisesRegex(RuntimeError,"RSS budget"):
                        self.n.owned(time.monotonic()+5)
                else:
                    self.assertEqual(set(self.n.owned(time.monotonic()+5)),{100,201})
        self.assertEqual(self.n.r["peakRssBytes"],12*native.GIB+1024)

    def test_fd_close_failure_does_not_skip_remaining_resume(self):
        with self.simulation(),self.assertRaisesRegex(RuntimeError,"close 100"):
            self.close.side_effect=[OSError("close failed"),None]
            with self.n.quiesced(time.monotonic()+5):pass
        self.assertEqual(self.sent[-2:],[(100,signal.SIGCONT),(200,signal.SIGCONT)])
        self.assertEqual(self.close.call_count,2)

    def test_resume_time_is_in_original_probe_deadline(self):
        clock=[0]
        def advance(pid,sig):
            if sig==signal.SIGCONT:clock[0]=30
        with self.simulation(signal_error=advance),patch.object(native.time,"monotonic",side_effect=lambda:clock[0]),self.assertRaises(subprocess.TimeoutExpired):
            with self.n.quiesced(30):pass
        self.assertEqual(self.sent[-2:],[(100,signal.SIGCONT),(200,signal.SIGCONT)])

    def test_reparented_member_survives_detached_leader_exit(self):
        self.n.p=SimpleNamespace(pid=100)
        self.n.known={200:(200,700),201:(200,701)}
        procs={100:self.p(100),201:self.p(201,group=200,session=200),202:self.p(202,group=200,session=200)}
        rows="100 1 100 100 4\n201 1 200 200 4\n202 1 200 200 4\n900 1 900 900 4\n"
        with patch.object(native.subprocess,"check_output",return_value=rows),patch.object(native,"process",side_effect=lambda pid:procs.get(pid)):
            owned=self.n.owned(time.monotonic()+5)
        self.assertEqual(set(owned),{100,201,202})
        self.assertEqual(self.n.known[201],(200,701))
        self.assertEqual(self.n.known[202],(200,702))
        self.assertNotIn(900,self.n.known)

    def test_unrelated_kernel_thread_zero_group_and_session_are_valid(self):
        self.n.p=SimpleNamespace(pid=100)
        with patch.object(native.subprocess,"check_output",return_value="2 0 0 0 0\n100 1 100 100 4\n"),patch.object(native,"process",side_effect=lambda pid:self.p(100)if pid==100 else None):
            self.assertEqual(set(self.n.owned(time.monotonic()+5)),{100})
        bad={**self.p(100),"group":0,"session":0}
        with patch.object(native.subprocess,"check_output",return_value="100 1 0 0 4\n"),patch.object(native,"process",return_value=bad),self.assertRaisesRegex(RuntimeError,"malformed owned"):
            self.n.owned(time.monotonic()+5)

    def test_reused_known_identity_does_not_claim_foreign_session(self):
        self.n.p=SimpleNamespace(pid=100)
        self.n.known={200:(200,700)}
        procs={100:self.p(100),200:{**self.p(200,session=900),"start":999}}
        with patch.object(native.subprocess,"check_output",return_value="100 1 100 100 4\n200 1 200 900 4\n"),patch.object(native,"process",side_effect=lambda pid:procs.get(pid)):
            self.assertEqual(set(self.n.owned(time.monotonic()+5)),{100})


@unittest.skipUnless(sys.platform=="linux" and hasattr(os,"pidfd_open") and hasattr(signal,"pidfd_send_signal"),"real owned-writer probe requires hosted Linux pidfds/GNU du")
class LinuxOwnedChurn(NativeFixture):
    WRITER = """import os,sys,time
from pathlib import Path
root=Path(sys.argv[1]);root.mkdir(parents=True,exist_ok=True)
(root/'ready').write_text(str(os.getpid()))
i=0
while True:
 p=root/f'stream{i}';p.write_bytes(b'x'*128);p.rename(root/f'final{i}');(root/f'final{i}').unlink();i+=1
 (root/'progress.tmp').write_text(str(i));(root/'progress.tmp').replace(root/'progress');time.sleep(.001)
"""
    def writer(self):
        self.n.p=subprocess.Popen([sys.executable,"-c",self.WRITER,str(self.store)],start_new_session=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        p=self.n.p
        def cleanup():
            if p.poll()is None:
                os.killpg(p.pid,signal.SIGCONT);os.killpg(p.pid,signal.SIGTERM)
                try:p.wait(timeout=2)
                except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait(timeout=2)
            self.n.p=None
        self.addCleanup(cleanup)
        end=time.monotonic()+2
        while not (self.store/'progress').exists():
            self.assertLess(time.monotonic(),end);time.sleep(.01)
        return p

    def test_repeated_actual_enoent_churn_admitted_by_stable_strict_snapshots(self):
        p=self.writer();self.n.command_end=time.monotonic()+10
        for _ in range(12):
            self.n.disk()
            self.assertIsNone(p.poll())
            self.assertNotIn(native.process(p.pid)["state"],("T","t"))
        self.assertEqual(self.n.r["diskSnapshots"],12)
        self.assertNotIn("diskScanRaceCount",self.n.r)
        self.assertGreater(int((self.store/'progress').read_text()),1)
        self.assertLess(self.n.r["peakTaskBytes"],1024**2)

    def test_interior_symlink_is_counted_without_following_target(self):
        outside=self.root/'outside';outside.mkdir();(outside/'data').write_bytes(b'x'*65536)
        (self.source/'link').symlink_to(outside,target_is_directory=True)
        self.n.disk()
        self.assertLess(self.n.r["peakTaskBytes"],65536)

    def test_real_scan_failure_resumes_before_runner_termination(self):
        real_run=native.subprocess.run
        def probe(argv,*args,**kwargs):
            return self.scan(1,self.diagnostic) if argv[0]=="du" else real_run(argv,*args,**kwargs)
        with patch.object(native.subprocess,"run",side_effect=probe):
            result,_=self.n.run("strict-failure",[sys.executable,"-c",self.WRITER,str(self.store)],seconds=65)
        self.assertNotEqual(result["exit"],0)
        self.assertIn("No such file",result["reason"])
        self.assertEqual(result["descendantCleanup"]["stillLiveGroups"],0)
        self.assertIsNone(self.n.p)
        self.assertTrue(self.n.cancel)



class RepairBatch(NativeFixture):
    def test_planner_counts_command_argv_not_summary_heading(self):
        log = b"""[check:changed] lanes=coreTests

[check:changed] typecheck core
$ node scripts/run-tsgo.mjs -p tsconfig.core.json

[check:changed] typecheck core tests
$ node scripts/run-tsgo-core-test-shards.mjs
src/gateway/example.test.ts: error TS2345

[check:changed] summary
   63.77s  ok         typecheck core
 289.86s  failed:2   typecheck core tests
[check:changed] FAILED (exit 2)
"""
        for duration, status, exit_code in (
            (" 289.86s", "failed:2", 2),
            ("1428.65s", "failed:2", 2),
            ("1428.65s", "ok", 0),
            ("  63.77s", "ok", 0),
        ):
            sample = log.replace(b" 289.86s  failed:2", f"{duration}  {status}".encode())
            if exit_code == 0:
                sample = sample.replace(b"[check:changed] FAILED (exit 2)\n", b"")
            with self.subTest(duration=duration, status=status):
                commands = native.planner_progress(io.BytesIO(sample))
                self.assertEqual([x["name"] for x in commands], ["typecheck core", "typecheck core tests"])
                self.assertEqual([x["status"] for x in commands], [0, exit_code])
                self.assertEqual(commands[1]["argv"], ["node", "scripts/run-tsgo-core-test-shards.mjs"])

    def test_failed_trailer_requires_complete_nonempty_summary(self):
        header = b"\n[check:changed] owner\n$ node owner.mjs\n"
        for sample in (
            header,
            header + b"\n[check:changed] summary\n",
            header + b"\n[check:changed] summary\n1428.65s failed:2 own",
            b"\n[check:changed] summary\n",
        ):
            with self.subTest(sample=sample), self.assertRaisesRegex(RuntimeError, "planner"):
                native.planner_progress(io.BytesIO(sample + b"\n[check:changed] FAILED (exit 2)\n"))

    def test_failed_command_entrypoint_retains_results_or_cancels_truncated_evidence(self):
        header = b"\n[check:changed] owner\n$ node owner.mjs\n"
        for sample, refused in (
            (header + b"\n[check:changed] summary\n1428.65s failed:2 owner\n", False),
            (header, True),
        ):
            self.n.cancel = False
            def completed(argv, **kwargs):
                kwargs["stdout"].write(sample)
                return SimpleNamespace(pid=123456789, poll=lambda: 2, wait=lambda: 2)
            root = {"pid": 123456789, "group": 123456789, "session": 123456789, "start": 1}
            with self.subTest(refused=refused), patch.object(native.subprocess, "Popen", side_effect=completed), patch.object(native, "process", return_value=root), patch.object(self.n, "closure_groups", return_value=set()), patch.object(self.n, "dispose_cache") as cleanup, patch.object(self.n, "source_snapshot"):
                result, _ = self.n.run("changed-checks", ["synthetic-planner"])
                cleanup.assert_called_once()
                self.assertEqual(result["exit"], 2)
                self.assertFalse(native.good(result))
                self.assertEqual(self.n.cancel, refused)
                if refused:
                    self.assertIn("planner progress refused", result["reason"])
                    self.assertEqual(result["plannerReached"], 0)
                else:
                    self.assertIsNone(result["reason"])
                    self.assertEqual(result["plannerReached"], 1)
                    self.assertEqual(result["plannerCommands"][0]["status"], 2)

    def test_planner_success_has_started_commands_with_unknown_completion_until_exit(self):
        result = native.planner_progress(io.BytesIO(b"\n[check:changed] owner\n$ node owner.mjs\n"))
        self.assertEqual(result, [{"name": "owner", "argv": ["node", "owner.mjs"], "status": None}])

    def test_in_process_guard_is_counted_without_a_shell_argv(self):
        log = b"\n[check:changed] test temp creation report (warning-only)\nNo new warnings.\n\n[check:changed] summary\n 515ms ok test temp creation report (warning-only)\n"
        self.assertEqual(native.planner_progress(io.BytesIO(log)), [{"name": "test temp creation report (warning-only)", "argv": None, "status": 0}])

    def test_incomplete_duplicate_or_reordered_summary_refuses(self):
        for log in (
            b"x" * 65537 + b"\n",
            b"\n[check:changed] first\n$ node one.mjs\n\n[check:changed] summary\n",
            b"\n[check:changed] first\n$ node one.mjs\n\n[check:changed] first\n$ node two.mjs\n",
            b"\n[check:changed] first\n$ node one.mjs\n\n[check:changed] second\n$ node two.mjs\n\n[check:changed] summary\n 1s ok second\n 1s ok first\n",
            b"\n[check:changed] first\n$ node one.mjs\n\n[check:changed] summary\n      1s ok first\n[check:changed] summary\n",
            b"\n[check:changed] first\n$ node one.mjs\n\n[check:changed] summary\n      1s ok first\n\n[check:changed] second\n$ node two.mjs\n",
            b"\n[check:changed] first\n$ node one.mjs\n\n[check:changed] summary\n      1s ok first\n1s ok first\n",
        ):
            with self.subTest(log=log), self.assertRaisesRegex(RuntimeError, "planner"):
                native.planner_progress(io.BytesIO(log))

    def cache(self):
        cache = self.n.w / "vitest-1"
        cache.mkdir()
        st, parent = cache.lstat(), self.n.w.lstat()
        return cache, (st.st_dev, st.st_ino), (parent.st_dev, parent.st_ino)

    def cleanup(self, cache, mark, parent_mark, groups=0):
        result = {"reason": None, "descendantCleanup": {"stillLiveGroups": groups, "leaderJoined": True, "sessionCensusComplete": True, "rootSessionObserved": True}}
        self.n.dispose_cache(cache, mark, parent_mark, result)
        return result

    @unittest.skipUnless(sys.platform=="linux", "cache footprint proof requires GNU du")
    def test_cache_cleanup_is_joined_and_does_not_follow_links_or_touch_evidence(self):
        cache, mark, parent_mark = self.cache()
        evidence = self.n.o / "receipt.json"
        evidence.write_text("preserve")
        (cache / "compiled-module").write_bytes(b"x" * 1024)
        (cache / "evidence-link").symlink_to(self.n.o, target_is_directory=True)
        result = self.cleanup(cache, mark, parent_mark)
        self.assertTrue(result["cacheCleanup"]["removed"])
        self.assertGreater(result["cacheCleanup"]["bytesBefore"], 0)
        self.assertFalse(cache.exists())
        self.assertEqual(evidence.read_text(), "preserve")
        self.assertIsNone(result["reason"])

    def test_live_captured_groups_retain_owned_cache(self):
        cache, mark, parent_mark = self.cache()
        result = self.cleanup(cache, mark, parent_mark, groups=1)
        self.assertFalse(result["cacheCleanup"]["removed"])
        self.assertTrue(cache.is_dir())
        self.assertIn("still live", result["reason"])

    def test_replaced_cache_and_foreign_path_refuse_deletion(self):
        cache, mark, parent_mark = self.cache()
        original = self.n.w / "original"
        cache.rename(original)
        cache.mkdir()
        (cache / "foreign").write_text("preserve")
        result = self.cleanup(cache, mark, parent_mark)
        self.assertIn("replaced", result["reason"])
        self.assertEqual((cache / "foreign").read_text(), "preserve")
        self.assertTrue(original.is_dir())

    def test_symlink_root_refuses_deletion(self):
        cache, mark, parent_mark = self.cache()
        cache.rmdir()
        cache.symlink_to(self.n.o, target_is_directory=True)
        result = self.cleanup(cache, mark, parent_mark)
        self.assertIn("symlink", result["reason"])
        self.assertTrue(self.n.o.is_dir())

    def test_cleanup_timeout_retains_failure_and_does_not_retry(self):
        cache, mark, parent_mark = self.cache()
        with patch.object(native.subprocess, "run", side_effect=subprocess.TimeoutExpired("du", 10)) as call:
            result = self.cleanup(cache, mark, parent_mark)
        self.assertEqual(call.call_count, 1)
        self.assertFalse(result["cacheCleanup"]["removed"])
        self.assertTrue(self.n.cancel)

    @unittest.skipUnless(sys.platform=="linux", "cache footprint proof requires GNU du")
    def test_parent_identity_change_refuses_inside_descriptor_owner(self):
        cache, mark, parent_mark = self.cache()
        result = self.cleanup(cache, mark, (parent_mark[0], parent_mark[1] + 1))
        self.assertIn("cache cleanup failed", result["reason"])
        self.assertTrue(cache.exists())

    def test_cleanup_failure_after_successful_command_keeps_entry_point_red(self):
        child = SimpleNamespace(pid=123456789, poll=lambda: 0, wait=lambda: 0)
        def refuse(cache, mark, parent_mark, result, deadline):
            result["reason"] = "cache retained"
            self.n.cancel = True
        with patch.object(native.subprocess, "Popen", return_value=child), patch.object(self.n, "dispose_cache", side_effect=refuse), patch.object(self.n, "source_snapshot"):
            result, _ = self.n.run("last-owner", ["synthetic-command"])
        self.assertEqual(result["exit"], 0)
        self.assertFalse(native.good(result))
        self.assertEqual(self.n.f, ["last-owner"])

    def test_cleanup_cannot_extend_the_original_owner_deadline(self):
        cache, mark, parent_mark = self.cache()
        with patch.object(native.time, "monotonic", return_value=20), patch.object(native.subprocess, "run") as call:
            result = {"reason": None, "descendantCleanup": {"stillLiveGroups": 0, "leaderJoined": True, "sessionCensusComplete": True, "rootSessionObserved": True}}
            self.n.dispose_cache(cache, mark, parent_mark, result, deadline=20)
        call.assert_not_called()
        self.assertFalse(result["cacheCleanup"]["removed"])
        self.assertTrue(cache.exists())

    @unittest.skipUnless(sys.version_info >= (3, 11), "descriptor-relative rmtree requires Python 3.11+")
    def test_cancelled_owner_disposes_only_its_joined_owned_cache(self):
        cache, mark, parent_mark = self.cache()
        evidence = self.n.o / "receipt.json"
        evidence.write_text("preserve")
        (cache / "compiled-module").write_bytes(b"compiled")
        (cache / "evidence-link").symlink_to(self.n.o, target_is_directory=True)
        self.n.cancel = True
        run = native.subprocess.run
        def process(argv, **kwargs):
            if argv[0] == "du":
                return subprocess.CompletedProcess(argv, 0, f"4096\t{cache}\n", "")
            return run(argv, **kwargs)
        result = {"reason": "original owner failure", "descendantCleanup": {"stillLiveGroups": 0, "leaderJoined": True, "sessionCensusComplete": True, "rootSessionObserved": True}}
        with patch.object(native.subprocess, "run", side_effect=process):
            self.n.dispose_cache(cache, mark, parent_mark, result)
        self.assertTrue(result["cacheCleanup"]["removed"])
        self.assertFalse(cache.exists())
        self.assertEqual(evidence.read_text(), "preserve")
        self.assertEqual(result["reason"], "original owner failure")
        self.assertTrue(self.n.cancel)

    def test_unjoined_leader_retains_cache_even_without_captured_descendants(self):
        cache, mark, parent_mark = self.cache()
        result = {"reason": None, "descendantCleanup": {"stillLiveGroups": 0, "leaderJoined": False}}
        with patch.object(native.subprocess, "run") as process:
            self.n.dispose_cache(cache, mark, parent_mark, result)
        process.assert_not_called()
        self.assertTrue(cache.is_dir())
        self.assertFalse(result["cacheCleanup"]["removed"])
        self.assertIn("leader not joined", result["reason"])

    def test_unresponsive_leader_has_bounded_join_and_reports_unknown_cleanup(self):
        clock, waits = [0], []
        self.n.started, self.n.end, self.n.work_end = 0, 100, 25
        def wait(timeout=None):
            self.assertIsNotNone(timeout, "every join needs its remaining deadline")
            waits.append(timeout)
            clock[0] += timeout
            raise subprocess.TimeoutExpired("synthetic owned child", timeout)
        child = SimpleNamespace(pid=123456789, poll=lambda: None, wait=wait)
        root = {"pid": child.pid, "group": child.pid, "session": child.pid, "start": 1}
        with patch.object(native.time, "monotonic", side_effect=lambda: clock[0]), patch.object(native.subprocess, "Popen", return_value=child), patch.object(native, "process", return_value=root), patch.object(native.subprocess, "check_output", side_effect=RuntimeError("original process-snapshot failure")), patch.object(native, "kill") as kill, patch.object(self.n, "source_snapshot"):
            result, _ = self.n.run("hung-owner", ["synthetic-command"])
        self.assertEqual(waits, [10, 10])
        self.assertLessEqual(clock[0], 100)
        self.assertTrue(result["started"])
        self.assertIsNone(result["exit"])
        self.assertFalse(result["descendantCleanup"]["leaderJoined"])
        self.assertIn("synthetic owned child", result["descendantCleanup"]["error"])
        self.assertFalse(result["cacheCleanup"]["removed"])
        self.assertIs(self.n.p, child)
        self.assertTrue(result["rawLogRetained"])
        self.assertTrue((self.n.w / "command.log").exists())
        self.assertTrue(self.n.cancel)
        self.assertEqual(result["reason"], "original process-snapshot failure")
        self.assertEqual(kill.call_args_list[-1].args, (child.pid, signal.SIGKILL))

    def test_expired_owner_does_not_borrow_global_time_for_source_provenance(self):
        clock = [0]
        self.n.started, self.n.end, self.n.work_end = 0, 1000, 925
        child = SimpleNamespace(pid=123456789, poll=lambda: 0, wait=lambda: 0)
        root = {"pid": child.pid, "group": child.pid, "session": child.pid, "start": 1}
        def close(cache, mark, parent, result, deadline):
            clock[0] = 300
            result["reason"] = "owner closure exhausted"
            self.n.cancel = True
        def git(*args, **kwargs):
            clock[0] = 309
            return b""
        with patch.object(native.time, "monotonic", side_effect=lambda: clock[0]), patch.object(native.subprocess, "Popen", return_value=child), patch.object(native, "process", return_value=root), patch.object(self.n, "closure_groups", return_value=set(), create=True), patch.object(self.n, "dispose_cache", side_effect=close), patch.object(native.subprocess, "check_output", side_effect=git) as read:
            result, _ = self.n.run("owner-provenance", ["synthetic-command"], seconds=300)
        read.assert_not_called()
        self.assertLessEqual(result["seconds"], 300)
        self.assertFalse(self.n.r["sourceSnapshots"][-1]["complete"])
        self.assertIn("deadline", self.n.r["sourceSnapshots"][-1]["error"])

    def test_unsampled_fast_leader_retains_cache_and_log_after_session_census(self):
        child = SimpleNamespace(pid=123456789, poll=lambda: 0, wait=lambda: 0)
        root = {"pid": child.pid, "group": child.pid, "session": child.pid, "start": 1}
        orphan = {"pid": 200, "group": 200, "session": child.pid, "start": 2}
        def record(pid, **kwargs):
            return root if pid == child.pid else orphan
        def command(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 0, f"4096\t{self.n.w / 'vitest-1'}\n", "")
        with patch.object(native.subprocess, "Popen", return_value=child), patch.object(native, "process", side_effect=record), patch.object(native.subprocess, "check_output", return_value=f"200 1 200 {child.pid}\n") as census, patch.object(native.subprocess, "run", side_effect=command) as disposal, patch.object(native, "kill") as kill, patch.object(self.n, "source_snapshot"):
            result, _ = self.n.run("fast-owner", ["synthetic-command"])
        census.assert_called_once()
        self.assertEqual(census.call_args.args[0][-1], "pid=,ppid=,pgid=,sid=")
        self.assertFalse(result["cacheCleanup"]["removed"])
        self.assertTrue((self.n.w / "vitest-1").is_dir())
        self.assertTrue((self.n.w / "command.log").exists())
        self.assertIsNone(result["descendantCleanup"]["stillLiveGroups"])
        self.assertFalse(result["descendantCleanup"]["sessionCensusComplete"])
        self.assertTrue(self.n.cancel)
        disposal.assert_not_called()
        kill.assert_not_called()

    def test_census_finds_uncaptured_root_session_writer_without_signaling_it(self):
        active, polls = [True], [0]
        pid = 123456789
        root = {"pid": pid, "group": pid, "session": pid, "start": 1}
        orphan = {"pid": 200, "group": 200, "session": pid, "start": 2}
        def poll():
            polls[0] += 1
            active[0] = polls[0] == 1
            return None if active[0] else 0
        child = SimpleNamespace(pid=pid, poll=poll, wait=lambda: 0)
        def rows(argv, **kwargs):
            return f"{pid} 1 4096\n" if argv[-1] == "pid=,ppid=,rss=" else f"200 1 200 {pid}\n"
        def record(value, **kwargs):
            return (root if active[0] or kwargs.get("dead") else None) if value == pid else orphan
        with patch.object(native.subprocess, "Popen", return_value=child), patch.object(native.subprocess, "check_output", side_effect=rows), patch.object(native, "process", side_effect=record), patch.object(native, "identity", side_effect=lambda value: (pid, 1) if active[0] and value == pid else None), patch.object(native.time, "sleep"), patch.object(self.n, "disk"), patch.object(self.n, "source_snapshot"), patch.object(native.subprocess, "run") as disposal, patch.object(native, "kill") as kill:
            result, _ = self.n.run("session-owner", ["synthetic-command"])
        self.assertEqual(result["descendantCleanup"]["stillLiveGroups"], 1)
        self.assertTrue(result["descendantCleanup"]["rootSessionObserved"])
        self.assertTrue(result["descendantCleanup"]["sessionCensusComplete"])
        self.assertFalse(result["cacheCleanup"]["removed"])
        self.assertTrue((self.n.w / "command.log").exists())
        self.assertTrue(self.n.cancel)
        disposal.assert_not_called()
        kill.assert_not_called()

    def test_census_retains_detached_session_after_its_captured_leader_exits(self):
        active, polls = [True], [0]
        pid = 123456789
        records = {
            pid: {"pid": pid, "group": pid, "session": pid, "start": 1},
            200: {"pid": 200, "group": 200, "session": 200, "start": 2},
            201: {"pid": 201, "group": 201, "session": 200, "start": 3},
        }
        def poll():
            polls[0] += 1
            active[0] = polls[0] == 1
            return None if active[0] else 0
        child = SimpleNamespace(pid=pid, poll=poll, wait=lambda: 0)
        def rows(argv, **kwargs):
            return f"{pid} 1 4096\n200 {pid} 4096\n" if argv[-1] == "pid=,ppid=,rss=" else "201 1 201 200\n"
        def record(value, **kwargs):
            if value == pid: return records[pid] if active[0] or kwargs.get("dead") else None
            return records.get(value) if active[0] or value != 200 else None
        def identity(value):
            p = records.get(value) if active[0] else None
            return (p["group"], p["start"]) if p else None
        with patch.object(native.subprocess, "Popen", return_value=child), patch.object(native.subprocess, "check_output", side_effect=rows), patch.object(native, "process", side_effect=record), patch.object(native, "identity", side_effect=identity), patch.object(native.time, "sleep"), patch.object(self.n, "disk"), patch.object(self.n, "source_snapshot"), patch.object(native.subprocess, "run") as disposal, patch.object(native, "kill") as kill:
            result, _ = self.n.run("detached-owner", ["synthetic-command"])
        self.assertEqual(result["descendantCleanup"]["stillLiveGroups"], 1)
        self.assertFalse(result["cacheCleanup"]["removed"])
        self.assertTrue((self.n.w / "command.log").exists())
        self.assertTrue(self.n.cancel)
        disposal.assert_not_called()
        kill.assert_not_called()

    def test_census_retains_captured_same_birth_pid_after_group_and_session_change(self):
        active, polls = [True], [0]
        pid = 123456789
        root = {"pid": pid, "group": pid, "session": pid, "start": 1}
        captured = {"pid": 201, "group": 200, "session": 200, "start": 3}
        migrated = {**captured, "group": 201, "session": 201}
        def poll():
            polls[0] += 1
            active[0] = polls[0] == 1
            return None if active[0] else 0
        child = SimpleNamespace(pid=pid, poll=poll, wait=lambda: 0)
        def rows(argv, **kwargs):
            return f"{pid} 1 4096\n201 {pid} 4096\n" if argv[-1] == "pid=,ppid=,rss=" else "201 1 201 201\n"
        def record(value, **kwargs):
            if value == pid: return root if active[0] or kwargs.get("dead") else None
            return captured if active[0] else migrated
        def identity(value):
            if not active[0]: return None
            p = root if value == pid else captured
            return (p["group"], p["start"])
        with patch.object(native.subprocess, "Popen", return_value=child), patch.object(native.subprocess, "check_output", side_effect=rows), patch.object(native, "process", side_effect=record), patch.object(native, "identity", side_effect=identity), patch.object(native.time, "sleep"), patch.object(self.n, "disk"), patch.object(self.n, "source_snapshot"), patch.object(native.subprocess, "run") as disposal, patch.object(native, "kill") as kill:
            result, _ = self.n.run("migrated-owner", ["synthetic-command"])
        self.assertEqual(result["descendantCleanup"]["stillLiveGroups"], 1)
        self.assertTrue(result["descendantCleanup"]["sessionCensusComplete"])
        self.assertFalse(result["cacheCleanup"]["removed"])
        self.assertTrue(result["rawLogRetained"])
        self.assertTrue(self.n.cancel)
        disposal.assert_not_called()
        kill.assert_not_called()

    def test_native_report_read_cannot_borrow_time_after_the_original_owner_deadline(self):
        clock = [0]
        self.n.end = 1000
        report = {"numTotalTests": 1, "numPassedTests": 1, "numFailedTests": 0, "numPendingTests": 0, "numTodoTests": 0, "testResults": [{"assertionResults": [{"fullName": "synthetic owner", "status": "passed", "failureMessages": []}]}]}
        result = {"exit": 0, "reason": None, "deadline": {"ownerEndMonotonic": 20}, "descendantCleanup": {"leaderJoined": True, "rootSessionObserved": True, "sessionCensusComplete": True, "stillLiveGroups": 0}}
        raw = self.n.w / "test-0.json"
        def run(*args, **kwargs):
            raw.write_text(json.dumps(report))
            return result, ""
        read = native.read
        def late_read(path):
            value = read(path)
            clock[0] = 20
            return value
        with patch.object(native.time, "monotonic", side_effect=lambda: clock[0]), patch.object(self.n, "run", side_effect=run), patch.object(native, "read", side_effect=late_read):
            self.n.test("synthetic.test.ts")
        self.assertIn("deadline", result.get("reportFailure", ""))
        self.assertTrue(result["rawReportRetained"])
        self.assertTrue(raw.is_file())
        self.assertTrue(self.n.cancel)
        self.assertEqual(clock[0], 20)

    def test_unrun_or_unbounded_owner_retains_raw_report_without_reading_it(self):
        raw = self.n.w / "test-0.json"
        report = {"numTotalTests": 1, "numPassedTests": 1, "numFailedTests": 0, "numPendingTests": 0, "numTodoTests": 0, "testResults": []}
        for exit_code in (None, 0):
            self.n.cancel = False
            result = {"exit": exit_code, "reason": "NOT_RUN_AFTER_TIME_OR_CANCELLATION" if exit_code is None else None}
            raw.write_text("synthetic raw owner evidence")
            with self.subTest(exit=exit_code), patch.object(self.n, "run", return_value=(result, "")), patch.object(native, "read", return_value=report) as read:
                self.n.test("synthetic.test.ts")
                read.assert_not_called()
                self.assertTrue(result["rawReportRetained"])
                self.assertIn("deadline unavailable", result["reportFailure"])
                self.assertTrue(raw.is_file())
                self.assertTrue(self.n.cancel)

    def test_captured_identity_probes_share_the_original_closure_deadline(self):
        active, polls, clock = [True], [0], [0]
        self.n.started, self.n.end, self.n.work_end = 0, 1000, 925
        pid = 123456789
        records = {pid: {"pid": pid, "group": pid, "session": pid, "start": 1}, 201: {"pid": 201, "group": 200, "session": 200, "start": 3}}
        def poll():
            polls[0] += 1
            active[0] = polls[0] == 1
            return None if active[0] else 0
        child = SimpleNamespace(pid=pid, poll=poll, wait=lambda: 0)
        def late_identity(value):
            clock[0] = 20
            return None
        def record(value, **kwargs):
            return records.get(value) if active[0] or kwargs.get("dead") else None
        with patch.object(native.time, "monotonic", side_effect=lambda: clock[0]), patch.object(native.time, "sleep"), patch.object(native.subprocess, "Popen", return_value=child), patch.object(native.subprocess, "check_output", return_value=f"{pid} 1 4096\n201 {pid} 4096\n"), patch.object(native, "process", side_effect=record), patch.object(native, "identity", side_effect=late_identity) as identities, patch.object(native, "kill") as kill, patch.object(self.n, "disk"), patch.object(self.n, "source_snapshot"), patch.object(native.subprocess, "run") as disposal:
            result, _ = self.n.run("identity-deadline-owner", ["synthetic-command"])
        self.assertEqual(identities.call_count, 1)
        self.assertIsNone(result["descendantCleanup"]["stillLiveGroups"])
        self.assertIn("deadline", result["descendantCleanup"]["error"])
        self.assertFalse(result["cacheCleanup"]["removed"])
        self.assertTrue(result["rawLogRetained"])
        self.assertTrue(self.n.cancel)
        disposal.assert_not_called()
        kill.assert_not_called()

    def test_planner_log_consumption_cannot_extend_the_original_owner_deadline(self):
        clock = [0]
        self.n.started, self.n.end, self.n.work_end = 0, 1000, 925
        log = b"\n[check:changed] owner\n$ node owner.mjs\n\n[check:changed] summary\n1s failed:2 owner\n"
        child = SimpleNamespace(pid=123456789, poll=lambda: 2, wait=lambda: 2)
        root = {"pid": child.pid, "group": child.pid, "session": child.pid, "start": 1}
        def launch(*args, **kwargs):
            kwargs["stdout"].write(log)
            return child
        class TimedLog:
            def __init__(self): self.stream = io.BytesIO(log)
            def __enter__(self): return self
            def __exit__(self, *args): self.stream.close()
            def __iter__(self): return self
            def __next__(self):
                line = self.readline()
                if not line: raise StopIteration
                return line
            def read(self, size): return self.stream.read(size)
            def seek(self, where): return self.stream.seek(where)
            def readline(self, size=-1):
                clock[0] = 300
                return self.stream.readline(size)
        open_file = Path.open
        def open_log(path, mode="r", *args, **kwargs):
            if path == self.n.w / "command.log" and mode == "rb": return TimedLog()
            return open_file(path, mode, *args, **kwargs)
        with patch.object(native.time, "monotonic", side_effect=lambda: clock[0]), patch.object(native.subprocess, "Popen", side_effect=launch), patch.object(native, "process", return_value=root), patch.object(self.n, "closure_groups", return_value=set(), create=True), patch.object(Path, "open", open_log), patch.object(self.n, "dispose_cache"), patch.object(self.n, "source_snapshot"):
            result, _ = self.n.run("changed-checks", ["synthetic-command"], seconds=300)
        self.assertIsNotNone(result["reason"])
        self.assertIn("deadline", result["reason"])
        self.assertEqual(result["plannerReached"], 0)
        self.assertTrue(result["rawLogRetained"])
        self.assertTrue(self.n.cancel)

    def repository(self):
        for args in (["init", "-q"],):
            subprocess.run(["git", "-C", str(self.source), *args], check=True, capture_output=True)
        (self.source / "tracked.txt").write_text("base")
        subprocess.run(["git", "-C", str(self.source), "add", "tracked.txt"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(self.source), "-c", "user.name=Synthetic", "-c", "user.email=synthetic@example.invalid", "commit", "-qm", "synthetic fixture"], check=True, capture_output=True)

    def test_source_diagnostic_records_exact_dirty_path_without_content(self):
        self.repository()
        (self.source / "tracked.txt").write_text("changed-private-looking-body")
        result = self.n.source_snapshot("after-build")
        self.assertTrue(result["complete"])
        self.assertEqual(result["unexpectedPaths"], ["tracked.txt"])
        self.assertEqual(result["paths"][0]["change"], "M")
        self.assertRegex(result["paths"][0]["baseBlob"], r"^[0-9a-f]{40}$")
        self.assertNotIn("changed-private-looking-body", json.dumps(result))

    def test_expected_tracked_and_new_overlays_require_exact_current_hash(self):
        self.repository()
        (self.source / "tracked.txt").write_text("overlay")
        (self.source / "qualification.test.ts").write_text("fixture")
        self.n.expected = {"tracked.txt": native.sha(b"overlay"), "qualification.test.ts": native.sha(b"fixture")}
        first = self.n.source_snapshot("overlay")
        self.assertEqual(first["unexpectedPaths"], [])
        self.assertEqual(len(first["paths"]), 2)
        (self.source / "qualification.test.ts").write_text("unexpected change")
        self.assertEqual(self.n.source_snapshot("changed fixture")["unexpectedPaths"], ["qualification.test.ts"])

    def test_source_deletion_and_oversized_diagnostic_remain_fail_closed(self):
        self.repository()
        (self.source / "tracked.txt").unlink()
        result = self.n.source_snapshot("deleted")
        self.assertEqual(result["paths"][0]["kind"], "missing")
        self.assertEqual(result["unexpectedPaths"], ["tracked.txt"])
        with patch.object(native.subprocess, "check_output", return_value=b"x" * 65537):
            result = self.n.source_snapshot("oversized")
        self.assertFalse(result["complete"])
        self.assertIn("oversized", result["error"])

    def test_budget_failure_keeps_root_sizes_and_distinguishes_cap_from_reserve(self):
        with patch.object(native.subprocess, "run", return_value=self.scan(used=10*native.GIB+1)):
            with self.assertRaisesRegex(RuntimeError, "budget"):
                self.n.disk()
        result = self.n.r["lastDiskSnapshot"]
        self.assertEqual(result["taskBytes"], 10*native.GIB+1)
        self.assertTrue(result["taskCapExceeded"])
        self.assertEqual(result["reserveFailedRoots"], [])


def load_tests(loader, tests, pattern):
    # Explicit workflow module loading has no discovery pattern. Discovery loads
    # test_native_batches separately, so adding it there would duplicate tests.
    if pattern is None:
        import test_native_batches
        tests.addTests(loader.loadTestsFromModule(test_native_batches))
        import test_native_sandbox
        tests.addTests(loader.loadTestsFromModule(test_native_sandbox))
    return tests


if __name__ == "__main__":
    unittest.main()
