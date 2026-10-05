"""Pure failure sequences: fake manager callbacks and temporary regular files."""
import errno
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import accounting_owner as OWNER


CID = "a" * 64
NAME = "v98proof123m1.slice"


class FakeManager:
    def __init__(self, root):
        self.root = root
        self.path = root / NAME
        self.calls = []
        self.version = "systemd 255 (255.4-1ubuntu8)\n+PAM +CGROUPS\n"
        self.reject_create = False
        self.unit = None
        self.show_hook = None
        self.show_count = 0
        self.list_failure = None

    def files(self):
        return {"cpu.stat": "usage_usec 0\nuser_usec 0\nsystem_usec 0\n",
                "cgroup.events": "populated 0\nfrozen 0\n", "cgroup.procs": "",
                "cgroup.type": "domain\n", "cgroup.kill": "0\n",
                "cpu.max": "100000 100000\n", "memory.max": str(1024 ** 3) + "\n",
                "memory.swap.max": "0\n", "pids.max": "128\n"}

    def __call__(self, argv, *, timeout, stdout_limit):
        self.calls.append(argv)
        if argv == ["systemctl", "--version"]:
            return self.version.encode()
        if argv[:2] == ["systemctl", "show"]:
            self.show_count += 1
            if self.show_hook:
                self.show_hook(self)
            return "".join(key + "=" + self.unit[key] + "\n" for key in OWNER.UNIT_FIELDS).encode()
        method = argv[8]
        if method == "StartTransientUnit":
            if self.reject_create:
                raise OWNER.Refusal("org.freedesktop.systemd1.UnitExists")
            self.path.mkdir()
            for name, contents in self.files().items():
                (self.path / name).write_text(contents)
            self.unit = dict(zip(OWNER.UNIT_FIELDS, (
                NAME, "loaded", "active", "active", "yes",
                "OpenClaw v98 owned accounting " + NAME, "b" * 32, "/" + NAME,
                "no", "inactive", "yes", "yes", "yes", "")))
        elif method == "StopUnit":
            for path in self.path.iterdir():
                path.unlink()
            self.path.rmdir()
            self.unit.update(LoadState="not-found", ActiveState="inactive", SubState="dead",
                             ControlGroup="")
        elif method == "ListUnitsByPatterns":
            if self.list_failure:
                raise self.list_failure
            if self.unit["LoadState"] == "not-found":
                rows = []
            else:
                rows = [[NAME, self.unit["Description"], self.unit["LoadState"],
                         self.unit["ActiveState"], self.unit["SubState"], "",
                         "/org/freedesktop/systemd1/unit/fake", 0, "", "/"]]
            return json.dumps({"type": "a(ssssssouso)", "data": [rows]}).encode()
        else:
            raise AssertionError("unexpected fake command " + str(argv))
        return json.dumps({"type": "o", "data": ["/org/freedesktop/systemd1/job/123"]}).encode()


class AccountingOwnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.manager = FakeManager(self.root)
        self.owner = OWNER.SliceOwner(self.manager, NAME, self.root)

    def tearDown(self):
        self.owner.close()
        self.temp.cleanup()

    def create(self):
        return self.owner.create()

    def cpu(self, value):
        (self.owner.path / "cpu.stat").write_text("usage_usec " + str(value) + "\n")

    def population(self, value):
        (self.owner.path / "cgroup.events").write_text("populated " + str(value) + "\n")

    def child(self, pid=123):
        self.owner.expect_container(CID)
        child = self.owner.path / ("docker-" + CID + ".scope")
        child.mkdir()
        (child / "cgroup.procs").write_text(str(pid) + "\n")
        info = child.stat()
        self.owner.bind_child(child, (info.st_dev, info.st_ino), pid)
        return child

    def test_name_has_no_alias_or_implicit_parent_slices(self):
        for name in ("system-v98proof1m1.slice", "v98proof1-m1.slice", "../v98proof1m1.slice",
                     "v98proof1m4.slice", "system.slice", "v98proof1m1.scope"):
            with self.subTest(name=name), self.assertRaises(OWNER.Refusal):
                OWNER.SliceOwner(self.manager, name, self.root)
        self.assertEqual(self.manager.calls, [])

    def test_create_uses_exclusive_transient_retention_and_same_limits(self):
        receipt = self.create()
        self.assertEqual(receipt["preStartCpuBaseline"], 0)
        self.assertFalse(receipt["keeperProcess"])
        self.assertEqual(receipt["invocationId"], "b" * 32)
        self.assertTrue(receipt["systemdVersion"].startswith("systemd 255"))
        argv = self.manager.calls[1]
        self.assertEqual(argv[8:12], ["StartTransientUnit", "ssa(sv)a(sa(sv))", NAME, "fail"])
        self.assertIn("StopWhenUnneeded", argv)
        self.assertIn("CPUQuotaPeriodUSec", argv)
        self.assertIn("MemorySwapMax", argv)
        self.assertEqual(argv[-1], "0")
        self.assertIsNotNone(self.owner.directory_fd)

    def test_existing_unit_is_not_adopted_or_stopped(self):
        self.manager.reject_create = True
        with self.assertRaisesRegex(OWNER.Refusal, "UnitExists"):
            self.create()
        self.assertTrue(self.owner.creation_attempted)
        self.assertFalse(self.owner.created)
        self.assertIsNone(self.owner.fd)
        self.assertFalse(any("StopUnit" in argv for argv in self.manager.calls))

    def test_existing_parent_path_or_unobservable_absence_refuses_before_mutation(self):
        for kind in ("directory", "file", "symlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temp:
                root = Path(temp); manager = FakeManager(root)
                if kind == "directory": manager.path.mkdir()
                elif kind == "file": manager.path.write_text("existing")
                else: manager.path.symlink_to(root / "missing")
                owner = OWNER.SliceOwner(manager, NAME, root)
                with self.assertRaisesRegex(OWNER.Refusal, "already exists"):
                    owner.create()
                self.assertFalse(owner.creation_attempted)
                self.assertFalse(any("StartTransientUnit" in argv or "StopUnit" in argv
                                     for argv in manager.calls))
        with patch.object(OWNER.os, "stat", side_effect=OSError(errno.EACCES, "denied")):
            with self.assertRaises(OSError) as error: self.create()
        self.assertEqual(error.exception.errno, errno.EACCES)
        self.assertFalse(self.owner.creation_attempted)
        self.assertFalse(any("StartTransientUnit" in argv for argv in self.manager.calls))

    def test_unreviewed_manager_version_refuses_before_mutation(self):
        self.manager.version = "systemd 256\n"
        with self.assertRaisesRegex(OWNER.Refusal, "major"):
            self.create()
        self.assertFalse(self.owner.creation_attempted)
        self.assertEqual(len(self.manager.calls), 1)

    def test_failed_creation_observes_unknown_custody_without_stop(self):
        original = self.manager.__call__
        def failed(argv, **kwargs):
            output = original(argv, **kwargs)
            if "StartTransientUnit" in argv:
                raise TimeoutError("reply lost after creation")
            return output
        self.owner.command = failed
        with self.assertRaises(TimeoutError):
            self.create()
        self.assertTrue(self.owner.path.exists())
        self.assertFalse(self.owner.created)
        self.assertIsNone(self.owner.identity)
        self.assertFalse(any("StopUnit" in argv for argv in self.manager.calls))

    def test_activation_timeout_retains_uncertain_unit_without_stop(self):
        now = [0.0]
        self.owner.clock = lambda: now[0]
        self.owner.pause = lambda seconds: now.__setitem__(0, now[0] + 1)
        self.manager.show_hook = lambda manager: manager.unit.update(ActiveState="activating")
        with self.assertRaisesRegex(OWNER.Refusal, "timed out"):
            self.create()
        self.assertTrue(self.owner.path.exists())
        self.assertFalse(self.owner.created)
        self.assertFalse(any("StopUnit" in argv for argv in self.manager.calls))

    def test_creation_refuses_retention_or_resource_change(self):
        for change in (lambda manager: manager.unit.update(StopWhenUnneeded="yes"),
                       lambda manager: (manager.path / "memory.swap.max").write_text("1\n"),
                       lambda manager: (manager.path / "cpu.max").write_text("max 100000\n")):
            with self.subTest(change=change):
                with tempfile.TemporaryDirectory() as temp:
                    manager = FakeManager(Path(temp)); manager.show_hook = change
                    owner = OWNER.SliceOwner(manager, NAME, Path(temp))
                    try:
                        with self.assertRaises(OWNER.Refusal): owner.create()
                        self.assertFalse(any("StopUnit" in argv for argv in manager.calls))
                    finally:
                        owner.close()

    def test_baseline_requires_no_prior_cpu_process_or_child(self):
        for change in (lambda manager: (manager.path / "cpu.stat").write_text("usage_usec 1\n"),
                       lambda manager: (manager.path / "cgroup.procs").write_text("123\n"),
                       lambda manager: (manager.path / "foreign.scope").mkdir(exist_ok=True)):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temp:
                manager = FakeManager(Path(temp)); manager.show_hook = change
                owner = OWNER.SliceOwner(manager, NAME, Path(temp))
                try:
                    with self.assertRaises(OWNER.Refusal): owner.create()
                    self.assertFalse(any("StopUnit" in argv for argv in manager.calls))
                finally:
                    owner.close()

    def test_full_lifetime_delta_includes_startup_and_tail_after_child_removal(self):
        self.create()
        child = self.child()
        self.cpu(10)  # startup, before native gate
        self.assertEqual(self.owner.cpu_delta(), 10)
        self.cpu(100)  # product
        self.assertEqual(self.owner.cpu_delta(), 100)
        (child / "cgroup.procs").unlink(); child.rmdir()
        self.cpu(120)  # supervisor tail retained by parent
        final = self.owner.final_observation(100)
        self.assertEqual(final["aggregateCpuUsec"], 120)
        self.assertEqual(final["totalCpuUsec"], 120)
        self.assertEqual(final["baselineCpuUsec"], 0)
        self.assertTrue(final["finalCpuVerified"])
        self.assertTrue(final["extinctionObserved"])

    def test_child_binding_requires_exact_direct_ancestry_identity_and_pid(self):
        self.create(); self.owner.expect_container(CID)
        child = self.owner.path / ("docker-" + CID + ".scope"); child.mkdir()
        (child / "cgroup.procs").write_text("123\n")
        info = child.stat(); identity = (info.st_dev, info.st_ino)
        for path, pin, pid in ((self.root, identity, 123), (child, (0, 0), 123),
                               (child, identity, 456)):
            with self.subTest(path=path, pid=pid), self.assertRaises(OWNER.Refusal):
                self.owner.bind_child(path, pin, pid)

    def test_child_binding_is_idempotent_only_for_the_original_directory(self):
        self.create(); child = self.child()
        identity = self.owner.child_identity
        self.owner.bind_child(child, identity, 123)
        self.assertEqual(self.owner.receipt()["childDevInode"], identity)
        child.rename(self.root / "original-child")
        child.mkdir(); (child / "cgroup.procs").write_text("123\n")
        info = child.stat()
        with self.assertRaisesRegex(OWNER.Refusal, "replaced"):
            self.owner.bind_child(child, (info.st_dev, info.st_ino), 123)
        self.assertEqual(self.owner.child_identity, identity)

    def test_population_zero_on_original_parent_is_independent_of_child_name(self):
        self.create(); child = self.child()
        self.population(1)
        self.assertTrue(self.owner.populated())
        with self.assertRaisesRegex(OWNER.Refusal, "populated"):
            self.owner.final_observation(0)
        (child / "cgroup.procs").unlink(); child.rmdir()
        self.assertTrue(self.owner.populated())  # child absence grants nothing
        self.population(0)
        self.assertFalse(self.owner.populated())

    def test_missing_parent_or_reused_name_cannot_grant_proof(self):
        self.create(); saved = self.owner.path.with_name("saved")
        self.owner.path.rename(saved)
        with self.assertRaises(FileNotFoundError): self.owner.populated()
        self.owner.path.mkdir()
        (self.owner.path / "cgroup.events").write_text("populated 0\n")
        with self.assertRaisesRegex(OWNER.Refusal, "replaced"):
            self.owner.populated()
        self.assertIsNone(self.owner.final)

    def test_missing_inactive_or_alias_counters_never_use_last_sample(self):
        self.create(); self.cpu(12); self.assertEqual(self.owner.cpu_delta(), 12)
        with patch.object(OWNER.os, "read", side_effect=OSError(errno.ENODEV, "inactive")):
            with self.assertRaises(OWNER.ObservationFailure) as error:
                self.owner.cpu_delta()
        self.assertEqual(error.exception.cause.errno, errno.ENODEV)
        self.assertEqual(self.owner.last_cpu, 12)
        (self.owner.path / "cpu.stat").unlink()
        (self.owner.path / "cpu.stat").symlink_to(self.owner.path / "cgroup.events")
        with self.assertRaises(OWNER.ObservationFailure): self.owner.cpu_delta()
        self.assertIsNone(self.owner.final)

    def test_malformed_duplicate_or_decreasing_counter_refuses(self):
        self.create(); self.cpu(10); self.owner.cpu_delta()
        for text in ("usage_usec 9\n", "usage_usec 10\nusage_usec 11\n", "usage_usec -1\n", "x" * 4096):
            with self.subTest(text=text):
                (self.owner.path / "cpu.stat").write_text(text)
                with self.assertRaises(OWNER.Refusal): self.owner.cpu_delta()

    def test_final_snapshot_refuses_repopulation_counter_drift_or_invocation_change(self):
        self.create()
        with patch.object(self.owner, "populated", side_effect=[False, True]):
            with self.assertRaisesRegex(OWNER.Refusal, "repopulated"):
                self.owner.final_observation(0)
        with patch.object(self.owner, "cpu_delta", side_effect=[10, 11]):
            with self.assertRaisesRegex(OWNER.Refusal, "unstable"):
                self.owner.final_observation(0)
        self.manager.unit["InvocationID"] = "c" * 32
        with self.assertRaisesRegex(OWNER.Refusal, "invocation"):
            self.owner.final_observation(0)
        self.assertIsNone(self.owner.final)

    def test_failed_final_retry_invalidates_an_earlier_positive_seal(self):
        self.create(); self.owner.final_observation(0)
        self.population(1)
        with self.assertRaisesRegex(OWNER.Refusal, "populated"):
            self.owner.final_observation(0)
        self.assertIsNone(self.owner.final)
        with self.assertRaisesRegex(OWNER.Refusal, "final observation"):
            self.owner.release()
        self.assertFalse(any("StopUnit" in argv for argv in self.manager.calls))

    def test_owner_drift_refuses_kill_final_and_release(self):
        for key, value in (("InvocationID", "c" * 32), ("Description", "foreign"),
                           ("ControlGroup", "/foreign.slice"), ("DropInPaths", "/foreign.conf"),
                           ("StopWhenUnneeded", "yes"), ("CollectMode", "inactive-or-failed")):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as temp:
                manager = FakeManager(Path(temp)); owner = OWNER.SliceOwner(manager, NAME, Path(temp))
                try:
                    owner.create(); owner.final_observation(0)
                    manager.unit[key] = value
                    for operation in (owner.kill, lambda: owner.final_observation(0), owner.release):
                        with self.assertRaises(OWNER.Refusal): operation()
                    self.assertFalse(any("StopUnit" in argv for argv in manager.calls))
                finally:
                    owner.close()

    def test_unexpected_parent_members_refuse_aggregate_kill(self):
        self.create(); self.owner.expect_container(CID); self.population(1)
        (self.owner.path / "foreign.scope").mkdir()
        with self.assertRaisesRegex(OWNER.Refusal, "unexpected"):
            self.owner.kill()
        self.assertEqual((self.owner.path / "cgroup.kill").read_text(), "0\n")

    def test_direct_parent_process_refuses_aggregate_kill(self):
        self.create(); self.population(1)
        (self.owner.path / "cgroup.procs").write_text("123\n")
        with self.assertRaisesRegex(OWNER.Refusal, "direct"):
            self.owner.kill()
        self.assertEqual((self.owner.path / "cgroup.kill").read_text(), "0\n")

    def test_populated_unbound_child_refuses_aggregate_kill(self):
        self.create(); self.owner.expect_container(CID); self.population(1)
        child = self.owner.path / ("docker-" + CID + ".scope"); child.mkdir()
        (child / "cgroup.procs").write_text("123\n")
        with self.assertRaisesRegex(OWNER.Refusal, "never bound"):
            self.owner.kill()
        self.assertEqual((self.owner.path / "cgroup.kill").read_text(), "0\n")

    def test_child_replacement_during_kill_open_refuses_before_write(self):
        self.create(); child = self.child(); self.population(1)
        real_open = os.open
        def replaced(name, flags, **kwargs):
            fd = real_open(name, flags, **kwargs)
            if name == "cgroup.kill":
                child.rename(self.root / "original-child")
                child.mkdir(); (child / "cgroup.procs").write_text("456\n")
            return fd
        with patch.object(OWNER.os, "open", side_effect=replaced):
            with self.assertRaisesRegex(OWNER.Refusal, "replaced"):
                self.owner.kill()
        self.assertEqual((self.owner.path / "cgroup.kill").read_text(), "0\n")

    def test_parent_replacement_during_kill_open_refuses_before_write(self):
        self.create(); self.child(); self.population(1)
        original = self.root / "original-parent"
        real_open = os.open
        def replaced(name, flags, **kwargs):
            fd = real_open(name, flags, **kwargs)
            if name == "cgroup.kill":
                self.owner.path.rename(original)
                self.owner.path.mkdir()
                (self.owner.path / "cgroup.kill").write_text("0\n")
            return fd
        with patch.object(OWNER.os, "open", side_effect=replaced):
            with self.assertRaisesRegex(OWNER.Refusal, "replaced"):
                self.owner.kill()
        self.assertEqual((original / "cgroup.kill").read_text(), "0\n")
        self.assertEqual((self.owner.path / "cgroup.kill").read_text(), "0\n")

    def test_open_and_read_or_write_failures_preserve_precise_operation(self):
        self.create(); self.child(); self.population(1)
        for syscall, operation, action in (
                ("open", "parent cpu.stat open", self.owner.cpu_total),
                ("read", "parent cpu.stat read", self.owner.cpu_total),
                ("write", "parent cgroup.kill write", self.owner.kill)):
            with self.subTest(operation=operation):
                with patch.object(OWNER.os, syscall, side_effect=OSError(errno.ENODEV, "inactive")):
                    with self.assertRaises(OWNER.ObservationFailure) as error:
                        action()
                self.assertEqual(error.exception.operation, operation)
                self.assertEqual(error.exception.cause.errno, errno.ENODEV)
        real_open = os.open
        def failed_kill(name, flags, **kwargs):
            if name == "cgroup.kill":
                raise OSError(errno.EPERM, "denied")
            return real_open(name, flags, **kwargs)
        with patch.object(OWNER.os, "open", side_effect=failed_kill):
            with self.assertRaises(OWNER.ObservationFailure) as error:
                self.owner.kill()
        self.assertEqual(error.exception.operation, "parent cgroup.kill open")
        self.assertEqual(error.exception.cause.errno, errno.EPERM)

    def test_kill_uses_owned_parent_fd_then_requires_positive_population_zero(self):
        self.create(); self.child(); self.population(1)
        real_write = os.write
        def signalled(fd, data):
            result = real_write(fd, data)
            self.population(0)
            return result
        with patch.object(OWNER.os, "write", side_effect=signalled):
            stamp = self.owner.kill()
        self.assertIsInstance(stamp, float)
        self.assertEqual((self.owner.path / "cgroup.kill").read_text(), "1\n")
        self.assertFalse(self.owner.populated())
        self.assertIsNone(self.owner.kill())

    def test_failed_kill_keeps_population_and_unit_custody_unproved(self):
        self.create(); self.child(); self.population(1)
        with patch.object(OWNER.os, "write", side_effect=OSError(errno.EPERM, "denied")):
            with self.assertRaises(OWNER.ObservationFailure): self.owner.kill()
        self.assertTrue(self.owner.populated())
        self.assertFalse(self.owner.released)
        self.assertFalse(any("StopUnit" in argv for argv in self.manager.calls))

    def test_release_requires_final_cpu_empty_namespace_and_same_owner(self):
        self.create()
        with self.assertRaisesRegex(OWNER.Refusal, "final observation"): self.owner.release()
        self.child()
        self.owner.final_observation(0)
        with self.assertRaisesRegex(OWNER.Refusal, "child"): self.owner.release()
        self.assertFalse(any("StopUnit" in argv for argv in self.manager.calls))

    def test_release_after_final_retention_removes_only_exact_unit(self):
        self.create(); self.cpu(120); final = self.owner.final_observation(100)
        released = self.owner.release()
        self.assertTrue(released["released"])
        self.assertEqual(released["invocationId"], final["invocationId"])
        self.assertIsNone(self.owner.directory_fd)
        self.assertFalse(self.owner.path.exists())
        stop = next(argv for argv in self.manager.calls if "StopUnit" in argv)
        self.assertEqual(stop[8:], ["StopUnit", "ss", NAME, "fail"])

    def test_release_never_treats_listing_error_as_unit_absence(self):
        self.create(); self.owner.final_observation(0)
        self.manager.list_failure = OWNER.Refusal("host command failed: busctl")
        with self.assertRaisesRegex(OWNER.Refusal, "busctl"):
            self.owner.release()
        self.assertFalse(self.owner.released)

    def test_release_refuses_loaded_unit_reuse_or_path_drift_after_stop(self):
        for changed in ({"InvocationID": "c" * 32}, {"ControlGroup": "/foreign.slice"}):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temp:
                manager = FakeManager(Path(temp)); original = manager.__call__
                def stop_changed(argv, **kwargs):
                    output = original(argv, **kwargs)
                    if "StopUnit" in argv:
                        manager.unit.update(LoadState="loaded", **changed)
                    return output
                owner = OWNER.SliceOwner(stop_changed, NAME, Path(temp))
                try:
                    owner.create(); owner.final_observation(0)
                    with self.assertRaises(OWNER.Refusal): owner.release()
                    self.assertFalse(owner.released)
                finally:
                    owner.close()

    def test_release_refuses_cpu_change_after_final_seal(self):
        self.create(); self.owner.final_observation(0); self.cpu(1)
        with self.assertRaisesRegex(OWNER.Refusal, "changed"):
            self.owner.release()
        self.assertFalse(any("StopUnit" in argv for argv in self.manager.calls))

    def test_descriptor_close_never_releases_uncertain_systemd_unit(self):
        self.create(); self.owner.close()
        self.assertIsNone(self.owner.fd)
        self.assertTrue(self.owner.path.exists())
        self.assertFalse(any("StopUnit" in argv for argv in self.manager.calls))


if __name__ == "__main__":
    unittest.main()
