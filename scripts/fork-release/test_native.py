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
        with patch.object(native.time, "monotonic", side_effect=[0, 0, 0, 30, 30]), patch.object(native.subprocess, "run", return_value=self.scan()):
            with self.assertRaises(subprocess.TimeoutExpired):
                self.n.disk()

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
            result,_=self.n.run("strict-failure",[sys.executable,"-c",self.WRITER,str(self.store)],seconds=5)
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
        commands = native.planner_progress(io.BytesIO(log))
        self.assertEqual([x["name"] for x in commands], ["typecheck core", "typecheck core tests"])
        self.assertEqual([x["status"] for x in commands], [0, 2])
        self.assertEqual(commands[1]["argv"], ["node", "scripts/run-tsgo-core-test-shards.mjs"])

    def test_planner_success_has_started_commands_with_unknown_completion_until_exit(self):
        result = native.planner_progress(io.BytesIO(b"\n[check:changed] owner\n$ node owner.mjs\n"))
        self.assertEqual(result, [{"name": "owner", "argv": ["node", "owner.mjs"], "status": None}])

    def test_in_process_guard_is_counted_without_a_shell_argv(self):
        log = b"\n[check:changed] test temp creation report (warning-only)\nNo new warnings.\n\n[check:changed] summary\n 515ms ok test temp creation report (warning-only)\n"
        self.assertEqual(native.planner_progress(io.BytesIO(log)), [{"name": "test temp creation report (warning-only)", "argv": None, "status": 0}])

    def test_incomplete_duplicate_or_reordered_summary_refuses(self):
        for log in (
            b"\n[check:changed] first\n$ node one.mjs\n\n[check:changed] summary\n",
            b"\n[check:changed] first\n$ node one.mjs\n\n[check:changed] first\n$ node two.mjs\n",
            b"\n[check:changed] first\n$ node one.mjs\n\n[check:changed] second\n$ node two.mjs\n\n[check:changed] summary\n 1s ok second\n 1s ok first\n",
        ):
            with self.subTest(log=log), self.assertRaisesRegex(RuntimeError, "planner"):
                native.planner_progress(io.BytesIO(log))

    def cache(self):
        cache = self.n.w / "vitest-1"
        cache.mkdir()
        st, parent = cache.lstat(), self.n.w.lstat()
        return cache, (st.st_dev, st.st_ino), (parent.st_dev, parent.st_ino)

    def cleanup(self, cache, mark, parent_mark, groups=0):
        result = {"reason": None, "descendantCleanup": {"stillLiveGroups": groups}}
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
            result = {"reason": None, "descendantCleanup": {"stillLiveGroups": 0}}
            self.n.dispose_cache(cache, mark, parent_mark, result, deadline=20)
        call.assert_not_called()
        self.assertFalse(result["cacheCleanup"]["removed"])
        self.assertTrue(cache.exists())

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


if __name__ == "__main__":
    unittest.main()
