"""Pure contract checks for the proposed host supervisor; no native execution."""
import importlib.util
import io
import errno
import json
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch


SPEC = importlib.util.spec_from_file_location("v98_host_runtime", Path(__file__).with_name("host-runtime.py"))
HOST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HOST)


def inspect_row(container_id="a" * 64):
    return {
        "Id": container_id, "Image": HOST.IMAGE_ID, "AppArmorProfile": "docker-default",
        "Config": {"User": "1000:1000", "Entrypoint": ["/proof/runner/v98-supervisor"],
                   "Cmd": ["--capability-probe"], "Healthcheck": {"Test": ["NONE"]}},
        "HostConfig": {"ReadonlyRootfs": True, "Privileged": False, "NetworkMode": "none",
                       "CapDrop": ["ALL"], "CgroupnsMode": "private", "CgroupParent": HOST.accounting_name("owned"), "PidMode": "",
                       "IpcMode": "private", "Memory": 1024 ** 3, "MemorySwap": 1024 ** 3,
                       "NanoCpus": 10 ** 9, "PidsLimit": 128, "ShmSize": 1024 ** 2,
                       "SecurityOpt": ["no-new-privileges:true"],
                       "Ulimits": [{"Name": "core", "Soft": 0, "Hard": 0}],
                       "LogConfig": {"Type": "local", "Config": {
                           "max-size": "1m", "max-file": "1", "compress": "false"}}},
        "Mounts": [{"Destination": "/proof", "Source": "/proof-host", "Type": "bind", "RW": False},
                   {"Destination": "/scratch", "Source": "/scratch-host", "Type": "bind", "RW": True}],
        "Name": "/owned", "State": {"Pid": 12345, "Running": True},
    }


def created_row(proof="/proof-host", scratch="/scratch-host", mode="--capability-probe"):
    row = inspect_row()
    row["AppArmorProfile"] = ""
    row["Mounts"][0]["Source"] = proof
    row["Mounts"][1]["Source"] = scratch
    row["Config"]["Cmd"] = [mode]
    row["State"] = {"Status": "created", "Pid": 0, "Running": False, "ExitCode": 0,
                    "Error": "logger refused"}
    return row


def daemon_facts():
    return ({"Server": {"ApiVersion": "1.48", "Os": "linux", "Arch": "amd64"}},
            {"OSType": "linux", "Architecture": "x86_64", "CgroupVersion": "2", "CgroupDriver": "systemd",
             "MemoryLimit": True, "SwapLimit": True, "CpuCfsQuota": True, "PidsLimit": True,
             "SecurityOptions": ["name=apparmor", "name=seccomp,profile=builtin"],
             "Plugins": {"Log": ["local"]}, "DefaultRuntime": "runc", "Runtimes": {"runc": {}}})


def fake_scratch_mount(path):
    path.mkdir()
    return path.stat()


class HostContractTests(unittest.TestCase):
    def setUp(self):
        # Inert parent double: absent final proof retains all owned resources.
        self.parent = MagicMock()
        self.parent.directory_fd = 123
        self.parent.path = Path("/unexecuted/task-parent")
        self.parent.identity = (1, 2)
        self.parent.receipt.return_value = {"unit": HOST.accounting_name("owned")}
        self.parent.populated.return_value = False
        self.parent.final_observation.side_effect = HOST._accounting.ObservationFailure(
            "parent cpu.stat read", OSError(errno.ENODEV, "unavailable parent"))
        owner = patch.object(HOST, "SliceOwner", return_value=self.parent)
        owner.start(); self.addCleanup(owner.stop)
        self.scratch_usage = MagicMock()
        self.scratch_usage.seal.return_value = {"path": "scratch-usage.json", "exactPeakClaimed": False}
        usage = patch.object(HOST, "ScratchUsage", return_value=self.scratch_usage)
        usage.start(); self.addCleanup(usage.stop)

    def test_container_command_scope_and_mounts(self):
        argv = HOST.create_command("owned", HOST.IMAGE_ID, "/proof-host", "/scratch-host",
                                   "--capability-probe")
        self.assertEqual(argv[:2], ["docker", "create"])
        for pair in (["--user", "1000:1000"], ["--network", "none"],
                     ["--cap-drop", "ALL"], ["--read-only", "--network"],
                     ["--cgroupns", "private"], ["--no-healthcheck", "--ulimit"]):
            self.assertIn(pair, [argv[i:i + 2] for i in range(len(argv) - 1)])
        self.assertEqual(argv[-2:], [HOST.IMAGE_ID, "--capability-probe"])
        self.assertEqual([argv[i + 1] for i, item in enumerate(argv[:-1]) if item == "--mount"],
                         ["type=bind,src=/proof-host,dst=/proof,readonly",
                          "type=bind,src=/scratch-host,dst=/scratch"])
        self.assertNotIn("--privileged", argv)
        self.assertNotIn("--pid", argv)
        self.assertIn(["--pull", "never"], [argv[i:i + 2] for i in range(len(argv) - 1)])

    def test_scratch_allocation_refusal_precedes_any_container_create(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.scratch_usage.observe.side_effect = HOST.Refusal("synthetic allocation refusal")
            with patch.object(HOST, "mount_scratch", side_effect=fake_scratch_mount), \
                 patch.object(HOST, "command") as commands:
                with self.assertRaisesRegex(HOST.Refusal, "synthetic allocation refusal"):
                    HOST.run_mode(HOST.IMAGE_ID, root, root / "attempt", "owned", "--capability-probe")
            commands.assert_not_called()
            failure = json.loads((root / "attempt/failure.json").read_text())
            self.assertFalse(failure["containerCreationAttempted"])
            self.assertEqual(failure["creationOutcome"], "NOT_ATTEMPTED")
            self.assertEqual(failure["hostFailure"]["operation"], "scratch allocation observation")

    def test_consumed_ref_or_second_run_attempt_refuses_before_source_or_host_actions(self):
        allowed = {"GITHUB_REPOSITORY": "fr-meyer/openclaw",
                   "GITHUB_REF": "refs/heads/candidate/v2026.9.8-runtime-admission-5",
                   "GITHUB_RUN_ATTEMPT": "1", "GITHUB_RUN_NUMBER": "2", "GITHUB_EVENT_NAME": "push",
                   "GITHUB_SHA": "d7" * 20, "V98_APPROVED_COMMIT": "d7" * 20, "V98_APPROVED_RUN_NUMBER": "2"}
        for key, value in [("GITHUB_REF", "refs/heads/candidate/v2026.9.8-runtime-admission-4"),
                           ("GITHUB_RUN_NUMBER", "1"), ("GITHUB_RUN_ATTEMPT", "2")]:
            with self.subTest(key=key), patch.object(HOST.os, "geteuid", return_value=0), \
                 patch.object(HOST.platform, "system", return_value="Linux"), \
                 patch.object(HOST.platform, "machine", return_value="x86_64"), \
                 patch.dict(HOST.os.environ, {**allowed, key: value}, clear=True), \
                 patch.object(HOST, "verify_source_manifest") as verified, patch.object(HOST, "command") as invoked:
                with self.assertRaisesRegex(HOST.Refusal, "wrong hosted workflow identity"):
                    HOST.execute(SimpleNamespace(tooling_commit="d7" * 20))
                verified.assert_not_called(); invoked.assert_not_called()

    def test_preflight_refuses_incompatible_daemon_and_resource_prerequisites(self):
        version, info = daemon_facts()
        args = [version, info, "unix:///var/run/docker.sock", ["cpu", "memory", "pids"], "1"]
        HOST.validate_docker_prerequisites(*args)
        for location, key, value in (
            (0, "Server", {"ApiVersion": "1.40", "Os": "linux", "Arch": "amd64"}),
            (1, "Architecture", "aarch64"), (1, "CgroupVersion", "1"),
            (1, "SecurityOptions", ["name=apparmor", "name=seccomp,profile=custom"]),
            (1, "SecurityOptions", ["name=rootless", "name=apparmor", "name=seccomp,profile=builtin"]),
            (1, "SecurityOptions", ["name=userns", "name=apparmor", "name=seccomp,profile=builtin"]),
            (1, "SwapLimit", False), (1, "PidsLimit", False),
            (1, "Plugins", {"Log": ["json-file"]}), (1, "Runtimes", {}),
            (1, "DefaultRuntime", "io.containerd.runsc.v1"),
        ):
            changed = json.loads(json.dumps(args))
            changed[location][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(HOST.Refusal):
                HOST.validate_docker_prerequisites(*changed)
        for index, value in ((2, "tcp://remote:2375"), (3, ["cpu", "memory"]), (4, "2"), (4, "3")):
            changed = list(args); changed[index] = value
            with self.subTest(index=index), self.assertRaises(HOST.Refusal):
                HOST.validate_docker_prerequisites(*changed)

    def test_proof_mount_uses_most_specific_mount_and_decodes_paths(self):
        mounts = ("1 0 1:1 / / rw - ext4 /dev/root rw\n"
                  "2 1 1:2 / /runner\\040temp rw,noexec - tmpfs tmpfs rw\n")
        self.assertEqual(HOST.proof_mount_options("/runner temp/proof", mounts), {"rw", "noexec"})
        self.assertEqual(HOST.proof_mount_options("/runner temporary/proof", mounts), {"rw"})
        with self.assertRaises(HOST.Refusal):
            HOST.proof_mount_options("/proof", "invalid")

    def test_preflight_refusal_is_retained_before_any_docker_command(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.dict(HOST.os.environ, {"DOCKER_HOST": "tcp://remote:2375"}, clear=True), \
                 patch.object(HOST, "command") as commands, self.assertRaises(HOST.Refusal):
                HOST.host_preflight(Path(temp) / "proof", temp)
            commands.assert_not_called()
            receipt = json.loads((Path(temp) / "host-preflight.json").read_text())
            self.assertEqual(receipt["status"], "HOST_PREREQUISITES_UNPROVED")
            self.assertFalse(receipt["executionAdmission"])
            self.assertIn("endpoint environment override", receipt["reason"])
            validation = Path(temp) / "validation.json"; validation.write_text("{}\n")
            custody = HOST.collect_evidence(validation, temp, Path(temp) / "upload")
            self.assertIn("host-preflight.json", [row["path"] for row in custody["copied"]])

    def test_container_logging_can_start_within_single_megabyte_budget(self):
        # Docker's local driver defaults to compression and rejects it with one
        # file. Exercise the actual command for each mode without launching Docker.
        for mode in HOST.MODE_LIMITS:
            with self.subTest(mode=mode):
                argv = HOST.create_command("owned", HOST.IMAGE_ID, "/proof-host",
                                           "/scratch-host", mode)
                driver = argv[argv.index("--log-driver") + 1]
                options = dict(argv[i + 1].split("=", 1)
                               for i, arg in enumerate(argv[:-1]) if arg == "--log-opt")
                count = int(options.get("max-file", "5"))
                compressed = options.get("compress", "true") == "true"
                self.assertEqual(driver, "local")
                self.assertFalse(count == 1 and compressed,
                                 "compression cannot be enabled when max file count is 1")
                self.assertEqual(options.get("max-size"), "1m")
                self.assertLessEqual(count * 1024 * 1024, 1024 * 1024)

    def test_actual_container_settings_fail_closed(self):
        row = inspect_row()
        self.assertEqual(HOST.inspect_container(row, "a" * 64, HOST.IMAGE_ID,
                                                "/proof-host", "/scratch-host"), 12345)
        for mutation in (
            lambda x: x["HostConfig"].update(NetworkMode="bridge"),
            lambda x: x["HostConfig"].update(CapDrop=[]),
            lambda x: x["HostConfig"].update(MemorySwap=2 * 1024 ** 3),
            lambda x: x.update(AppArmorProfile=""),
            lambda x: x["Mounts"][1].update(Source="/other"),
            lambda x: x["State"].update(Running=False),
            lambda x: x["HostConfig"]["LogConfig"]["Config"].update(compress="true"),
            lambda x: x["HostConfig"]["Ulimits"][0].update(Hard=1),
        ):
            changed = json.loads(json.dumps(row))
            mutation(changed)
            with self.subTest(changed=changed), self.assertRaises(HOST.Refusal):
                HOST.inspect_container(changed, "a" * 64, HOST.IMAGE_ID,
                                       "/proof-host", "/scratch-host")

    def test_default_apparmor_assignment_is_deferred_until_start(self):
        row = created_row()
        HOST.inspect_container_configuration(row, "a" * 64, HOST.IMAGE_ID,
                                              "/proof-host", "/scratch-host")
        row["State"].update(Running=True, Pid=12345)
        with self.assertRaisesRegex(HOST.Refusal, "AppArmor is not enforced"):
            HOST.inspect_container(row, "a" * 64, HOST.IMAGE_ID, "/proof-host", "/scratch-host")
        row["AppArmorProfile"] = "docker-default"
        self.assertEqual(HOST.inspect_container(row, "a" * 64, HOST.IMAGE_ID,
                                                "/proof-host", "/scratch-host"), 12345)

    def test_cleanup_ownership_is_distinct_from_policy_admission(self):
        row = inspect_row()
        # A runtime policy refusal still leaves authority to stop the exact
        # container created by this attempt.
        row["AppArmorProfile"] = ""
        self.assertEqual(HOST.inspect_owned_container(row, "a" * 64, "owned", HOST.IMAGE_ID,
                         "/proof-host", "/scratch-host", "--capability-probe"), 12345)
        with self.assertRaises(HOST.Refusal):
            HOST.inspect_container(row, "a" * 64, HOST.IMAGE_ID,
                                   "/proof-host", "/scratch-host")
        for mutation in (
            lambda x: x.update(Name="/other"),
            lambda x: x["Config"].update(Cmd=["--run-frozen-six-phases"]),
            lambda x: x["Mounts"][1].update(Source="/other"),
        ):
            changed = json.loads(json.dumps(row))
            mutation(changed)
            with self.subTest(changed=changed), self.assertRaises(HOST.Refusal):
                HOST.inspect_owned_container(changed, "a" * 64, "owned", HOST.IMAGE_ID,
                                             "/proof-host", "/scratch-host", "--capability-probe")

    def test_exact_id_fallback_stops_but_cannot_claim_cgroup_extinction(self):
        row = inspect_row()
        with patch.object(HOST, "docker_inspect", side_effect=[row, {
                **row, "State": {"Pid": 0, "Running": False}}]), \
                patch.object(HOST, "command", return_value=b"") as invoked:
            state = HOST.settle_created_container("a" * 64, "owned", HOST.IMAGE_ID,
                          "/proof-host", "/scratch-host", "--capability-probe")
            self.assertFalse(state["Running"])
            self.assertEqual(state["Pid"], 0)
            invoked.assert_called_once_with(["docker", "kill", "--signal=KILL", "a" * 64], timeout=5)

    def test_settlement_retains_nonzero_final_pid_without_stopped_grant(self):
        final = created_row(); final["State"]["Pid"] = 12345
        with patch.object(HOST, "docker_inspect", side_effect=[created_row(), final]), \
                patch.object(HOST, "command") as invoked:
            state = HOST.settle_created_container("a" * 64, "owned", HOST.IMAGE_ID,
                "/proof-host", "/scratch-host", "--capability-probe")
        self.assertFalse(state["stoppedVerified"])
        self.assertEqual(state["Pid"], 12345)
        invoked.assert_not_called()

    def test_settlement_refuses_final_ownership_change(self):
        final = created_row(); final["Name"] = "/other"
        with patch.object(HOST, "docker_inspect", side_effect=[created_row(), final]), \
                patch.object(HOST, "command") as invoked, self.assertRaises(HOST.Refusal):
            HOST.settle_created_container("a" * 64, "owned", HOST.IMAGE_ID,
                "/proof-host", "/scratch-host", "--capability-probe")
        invoked.assert_not_called()

    def test_failed_stop_still_observes_stopped_final_state(self):
        for final in (created_row(), inspect_row()):
            with self.subTest(running=final["State"]["Running"]), \
                    patch.object(HOST, "docker_inspect", side_effect=[inspect_row(), final]) as inspected, \
                    patch.object(HOST, "command", side_effect=HOST.Refusal("stop timed out")):
                state = HOST.settle_created_container("a" * 64, "owned", HOST.IMAGE_ID,
                    "/proof-host", "/scratch-host", "--capability-probe")
            self.assertEqual(inspected.call_count, 2)
            self.assertEqual(state["stoppedVerified"], final["State"]["Pid"] == 0)
            self.assertFalse(state["stopCommandSucceeded"])
            self.assertEqual(state["stopFailure"]["reason"], "stop timed out")

    def test_failed_stop_and_failed_final_inspect_retain_both_errors(self):
        with patch.object(HOST, "docker_inspect", side_effect=[
                inspect_row(), OSError(errno.ENODEV, "final inspect " + "x" * 4000)]), \
                patch.object(HOST, "command", side_effect=HOST.Refusal("stop timed out")), \
                self.assertRaises(HOST.SettlementFailure) as caught:
            HOST.settle_created_container("a" * 64, "owned", HOST.IMAGE_ID,
                "/proof-host", "/scratch-host", "--capability-probe")
        details = caught.exception.details
        self.assertEqual(details["stopFailure"]["reason"], "stop timed out")
        self.assertEqual(details["finalObservationFailure"]["errno"], errno.ENODEV)
        self.assertLessEqual(len(details["finalObservationFailure"]["reason"].encode()), 2000)

    def test_failed_start_retains_stopped_state_without_claiming_extinction(self):
        self.check_failed_start(b"logger refused\n", False)

    def test_oversized_stream_retains_only_bounded_prefix(self):
        self.check_failed_start(b"0123456789abcdef", True)

    def test_failed_exact_id_kill_keeps_live_resource_cleanup_unproved(self):
        self.check_failed_start(b"start request failed\n", False, kill_failure=True)

    def test_run_mode_retains_stop_and_final_inspection_failures(self):
        self.check_failed_start(b"start request failed\n", False, kill_failure=True,
                                final_inspect_failure=True)

    def check_failed_start(self, message, overflow, kill_failure=False, final_inspect_failure=False):
        class Attached:
            def __init__(self, stdout, stderr):
                self.stdout, self.stderr = stdout, stderr
            def poll(self): return 125
            def wait(self, timeout): return 125

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            stdout_r, stdout_w = os.pipe(); stderr_r, stderr_w = os.pipe()
            os.close(stdout_w); os.write(stderr_w, message); os.close(stderr_w)
            stdout = os.fdopen(stdout_r, "rb", buffering=0)
            stderr = os.fdopen(stderr_r, "rb", buffering=0)
            row = created_row()
            row["Mounts"][0]["Source"] = str(root)
            row["Mounts"][1]["Source"] = str(root / "attempt/scratch-tmpfs")
            def inspect():
                result = json.loads(json.dumps(row))
                if kill_failure and commands.call_count:
                    result["State"].update(Running=True, Pid=12345)
                return result
            # The first inspect observes a stopped created container; later
            # daemon observations can report a live task despite attach failure.
            inspections = [0]
            def observe(*_):
                if final_inspect_failure and inspections[0] == 3:
                    raise OSError(errno.ENODEV, "final state unavailable " + "x" * 4000)
                result = inspect()
                if inspections[0] == 0:
                    result["State"].update(Running=False, Pid=0)
                inspections[0] += 1
                return result
            try:
                with patch.object(HOST, "mount_scratch", side_effect=fake_scratch_mount), \
                     patch.object(HOST, "command", side_effect=(
                         [b"a" * 64, HOST.Refusal("owned kill failed")] if kill_failure
                         else [b"a" * 64])) as commands, \
                     patch.object(HOST.subprocess, "Popen", return_value=Attached(stdout, stderr)), \
                     patch.object(HOST, "docker_inspect", side_effect=observe), \
                     patch.object(HOST, "observe_owned_process", side_effect=HOST.Refusal("no live PID")), \
                     patch.object(HOST.os.path, "ismount", return_value=True), \
                     patch.object(HOST, "MAX_STDERR", 8 if overflow else HOST.MAX_STDERR), \
                     patch.object(HOST, "release_gate") as admitted, \
                     patch.object(HOST, "retain_scratch") as archived:
                    with self.assertRaisesRegex(HOST.Refusal,
                            "log budget exceeded" if overflow else (
                                "final stop was not observed" if kill_failure else "host gate was never admitted")):
                        HOST.run_mode(HOST.IMAGE_ID, root, root / "attempt", "owned", "--capability-probe")
                    self.assertEqual(commands.call_count, 2 if kill_failure else 1)
                    admitted.assert_not_called(); archived.assert_not_called()
                failure = json.loads((root / "attempt/failure.json").read_text())
                self.assertEqual((root / "attempt/product-stderr.log").read_bytes(), message[:8] if overflow else message)
                self.assertFalse(failure["extinctionObserved"])
                self.assertEqual(failure["cgroupDevInode"], [1, 2])
                self.assertEqual(failure["stoppedWithoutCgroupProof"], not kill_failure)
                if kill_failure:
                    if final_inspect_failure:
                        self.assertIsNone(failure["stoppedContainerState"])
                        details = failure["containerSettlementFailure"]
                        self.assertEqual(details["stopFailure"]["reason"], "owned kill failed")
                        self.assertEqual(details["finalObservationFailure"]["errno"], errno.ENODEV)
                    else:
                        self.assertFalse(failure["stoppedContainerState"]["stoppedVerified"])
                        self.assertTrue(failure["stoppedContainerState"]["Running"])
                        self.assertIn("exact ID kill: owned kill failed", failure["cleanupErrors"])
                else:
                    self.assertEqual(failure["stoppedContainerState"]["Pid"], 0)
                    self.assertFalse(failure["stoppedContainerState"]["Running"])
                self.assertTrue(failure["scratchMounted"])
                self.assertEqual(failure["attachReturnCode"], 125)
                self.assertEqual(failure["creationOutcome"], "EXACT_ID_OBSERVED")
            finally:
                stdout.close(); stderr.close()

    def test_failed_create_records_unknown_custody_and_no_start(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with patch.object(HOST, "mount_scratch", side_effect=fake_scratch_mount), \
                 patch.object(HOST, "command", side_effect=HOST.Refusal("create timeout")), \
                 patch.object(HOST.subprocess, "Popen") as started, \
                 patch.object(HOST.os.path, "ismount", return_value=True):
                with self.assertRaisesRegex(HOST.Refusal, "create timeout"):
                    HOST.run_mode(HOST.IMAGE_ID, root, root / "attempt", "owned", "--capability-probe")
                started.assert_not_called()
            failure = json.loads((root / "attempt/failure.json").read_text())
            self.assertEqual(failure["creationOutcome"], "UNKNOWN")
            self.assertIsNone(failure["containerId"])
            self.assertFalse(failure["extinctionObserved"])
            self.assertTrue(failure["scratchMounted"])

    def test_bad_created_log_configuration_refuses_before_start(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); row = created_row()
            row["Mounts"][0]["Source"] = str(root)
            row["Mounts"][1]["Source"] = str(root / "attempt/scratch-tmpfs")
            row["HostConfig"]["LogConfig"]["Config"]["compress"] = "true"
            with patch.object(HOST, "mount_scratch", side_effect=fake_scratch_mount), \
                 patch.object(HOST, "command", return_value=b"a" * 64), \
                 patch.object(HOST, "docker_inspect", return_value=row), \
                 patch.object(HOST.subprocess, "Popen") as started, \
                 patch.object(HOST.os.path, "ismount", return_value=True):
                with self.assertRaisesRegex(HOST.Refusal, "log budget"):
                    HOST.run_mode(HOST.IMAGE_ID, root, root / "attempt", "owned", "--capability-probe")
                started.assert_not_called()
            failure = json.loads((root / "attempt/failure.json").read_text())
            self.assertFalse(failure["extinctionObserved"])
            self.assertTrue(failure["stoppedWithoutCgroupProof"])

    def test_lifetime_counter_and_checkpoint_precede_all_destructive_cleanup(self):
        receipt, events = self.check_parent_flow()
        self.assertEqual(receipt["aggregateCpuUsecLastObserved"], 120000)
        self.assertEqual(self.parent.final_observation.call_args_list[0].args, (40000,))
        self.assertEqual(events, ["create-parent", "start", "gate", "archive", "rm", "umount", "release"])
        self.assertTrue(receipt["parentAccountingRelease"]["released"])

    def test_native_failure_keeps_primary_and_observes_complete_parent_tail(self):
        failure, events = self.check_parent_flow(native_exit=13)
        self.assertEqual(failure["primaryFailure"]["authority"], "TRUSTED_NATIVE_PHASE_EXIT")
        self.assertTrue(failure["finalCpuVerified"])
        self.assertEqual(failure["aggregateCpuUsecLastObserved"], 120000)
        self.assertIn("release", events)

    def test_missing_final_parent_counter_never_uses_last_sample(self):
        failure, events = self.check_parent_flow(final_error=True)
        self.assertEqual(failure["aggregateCpuUsecLastObserved"], 40000)
        self.assertFalse(failure["finalCpuVerified"])
        self.assertFalse(failure["extinctionObserved"])
        self.assertEqual(failure["hostFailure"]["operation"], "parent cpu.stat read")
        self.assertEqual(failure["hostFailure"]["errno"], errno.ENODEV)
        self.assertNotIn("archive", events)
        self.assertNotIn("release", events)

    def test_live_parent_error_and_native_exit_keep_independent_settlement(self):
        failure, events = self.check_parent_flow(native_exit=13, live_error=True, final_error=True)
        self.assertEqual(failure["primaryFailure"]["authority"], "TRUSTED_NATIVE_PHASE_EXIT")
        self.assertEqual(failure["hostFailure"]["operation"], "parent cpu.stat read")
        self.assertTrue(failure["stoppedContainerState"]["stoppedVerified"])
        self.assertEqual(failure["accountingSettlementFailure"]["errno"], errno.ENODEV)
        self.assertNotIn("rm", events)

    def test_checkpoint_write_failure_retains_parent_container_and_scratch(self):
        failure, events = self.check_parent_flow(checkpoint_error=True)
        self.assertTrue(failure["finalCpuVerified"])
        self.assertIsNone(failure["parentAccountingCheckpoint"])
        self.assertTrue(failure["scratchMounted"])
        self.assertNotIn("archive", events)
        self.assertNotIn("rm", events)
        self.assertNotIn("release", events)

    def test_checkpoint_survives_parent_release_failure_without_pass_receipt(self):
        failure, events = self.check_parent_flow(release_error=True)
        self.assertIsNotNone(failure["parentAccountingCheckpoint"])
        self.assertIsNone(failure["parentAccountingRelease"])
        self.assertIn("release", events)
        self.assertTrue(any("parent release" in error for error in failure["cleanupErrors"]))

    def test_changed_final_docker_owner_prevents_remove_and_parent_release(self):
        failure, events = self.check_parent_flow(removal_owner_error=True)
        self.assertIsNotNone(failure["parentAccountingCheckpoint"])
        self.assertNotIn("rm", events)
        self.assertNotIn("release", events)

    def test_policy_gate_failure_still_settles_parent_and_exact_docker(self):
        failure, events = self.check_parent_flow(gate_error=True)
        self.assertIn("seccomp refused", failure["reason"])
        self.assertNotIn("gate", events)
        self.assertTrue(failure["extinctionObserved"])
        self.assertTrue(failure["stoppedContainerState"]["stoppedVerified"])
        self.parent.kill.assert_called_once()

    def test_startup_cpu_budget_is_counted_before_gate_release(self):
        failure, events = self.check_parent_flow(live_cpu=5000001)
        self.assertIn("aggregate CPU budget exceeded", failure["reason"])
        self.assertNotIn("gate", events)
        self.assertFalse(failure["finalCpuVerified"])
        self.assertEqual(failure["finalCpuStatus"], "OBSERVED_OVER_BUDGET")

    def test_late_deadline_signal_refuses_and_retains_complete_final_proof(self):
        failure, events = self.check_parent_flow(mode="--deadline-probe", late_deadline=True)
        self.assertIn("signalled too late", failure["reason"])
        self.assertEqual(failure["deadlineKillRequestedWallSeconds"], 3.0)
        self.assertEqual(failure["deadlineSignalCompletedWallSeconds"], 3.0)
        self.assertTrue(failure["extinctionObserved"])

    def test_attach_tail_cannot_escape_complete_lifetime_wall_limit(self):
        failure, events = self.check_parent_flow(late_tail=True)
        self.assertIn("complete native lifetime exceeded wall budget", failure["reason"])
        self.assertTrue(failure["finalCpuVerified"])

    def test_scratch_usage_retention_failure_keeps_positive_parent_proof_but_retains_resources(self):
        failure, events = self.check_parent_flow(usage_error=True)
        self.assertTrue(failure["finalCpuVerified"])
        self.assertTrue(failure["extinctionObserved"])
        self.assertTrue(failure["stoppedContainerState"]["stoppedVerified"])
        self.assertIsNone(failure["parentAccountingCheckpoint"])
        self.assertIsNone(failure["parentAccountingRelease"])
        self.assertIsNone(failure["scratchUsage"])
        self.assertEqual(failure["scratchUsageFailure"]["errno"], errno.ENOSPC)
        self.assertEqual(failure["scratchUsageFailure"]["operation"], "scratch allocation observation/retention")
        self.assertTrue(failure["scratchMounted"])
        self.assertTrue(any("scratch usage retention" in e for e in failure["cleanupErrors"]))
        for action in ("archive", "rm", "umount", "release"):
            self.assertNotIn(action, events)
        self.parent.release.assert_not_called()

    def test_exact_parent_mismatch_refuses_created_container_before_start(self):
        row = created_row(); row["HostConfig"]["CgroupParent"] = "foreign.slice"
        with self.assertRaisesRegex(HOST.Refusal, "accounting parent changed"):
            HOST.inspect_owned_container(row, "a" * 64, "owned", HOST.IMAGE_ID,
                                         "/proof-host", "/scratch-host", "--capability-probe")

    def check_parent_flow(self, native_exit=0, final_error=False, live_error=False,
                          checkpoint_error=False, release_error=False, removal_owner_error=False,
                          gate_error=False, live_cpu=40000, mode="--capability-probe", late_deadline=False,
                          late_tail=False, usage_error=False):
        events = []; clock = [0.0]
        class Attached:
            def __init__(self, stdout, stderr):
                self.stdout, self.stderr, self.polls = stdout, stderr, 0
            def poll(self):
                self.polls += 1
                return None if self.polls <= (2 if late_deadline else 1) else (125 if native_exit else 0)
            def wait(self, timeout):
                if late_tail: clock[0] = 16.0
                return 125 if native_exit else 0
        controls = {key: True for key in ("fsync", "sqliteWalBackupClose", "deniedOutsideScratch", "deniedSockets")}
        native = [{"event": "host_gate_ready", "mode": mode},
                  {"event": "base_boundary_installed", "phase": 0},
                  {"event": "thread_owned", "phase": 0}, {"event": "thread_reaped", "phase": 0},
                  *[{"event": "syscall_denied", "value": 41}] * 4,
                  {"event": "syscall_denied", "value": 56},
                  *[{"event": "fsync_completed", "phase": 0}] * 4,
                  {"event": "phase_joined", "phase": 0, "value": native_exit},
                  {"event": "native_attempt_joined", "phase": 0, "value": 0}]
        issue = HOST._accounting.ObservationFailure("parent cpu.stat read", OSError(errno.ENODEV, "inactive"))
        final = {"unit": HOST.accounting_name("owned"), "invocationId": "1" * 32,
                 "cgroupDevInode": (1, 2), "preStartCpuBaseline": 0,
                 "baselineCpuUsec": 0, "aggregateCpuUsec": max(120000, live_cpu),
                 "populated": False, "extinctionObserved": True, "finalCpuVerified": True}
        self.parent.final_observation.side_effect = issue if final_error else None
        self.parent.final_observation.return_value = final
        self.parent.populated.return_value = True
        self.parent.cpu_delta.side_effect = issue if live_error else None
        self.parent.cpu_delta.return_value = live_cpu
        self.parent.create.side_effect = lambda: events.append("create-parent")
        self.parent.kill.return_value = 3.0 if late_deadline else 0.0
        self.scratch_usage.seal.side_effect = OSError(errno.ENOSPC, "scratch usage receipt full") if usage_error else None
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); out = root / "attempt"; scratch = out / "scratch-tmpfs"
            checkpoint = out / "parent-accounting-checkpoint.json"
            stdout_r, stdout_w = os.pipe(); stderr_r, stderr_w = os.pipe()
            os.write(stdout_w, b"".join((json.dumps(row) + "\n").encode() for row in native))
            os.write(stderr_w, (json.dumps({"event": "capability_controls_joined", "main": controls, "worker": controls}) + "\n").encode())
            os.close(stdout_w); os.close(stderr_w)
            stdout = os.fdopen(stdout_r, "rb", buffering=0); stderr = os.fdopen(stderr_r, "rb", buffering=0)
            pidfd = os.open(os.devnull, os.O_RDONLY); childfd = os.open(root, os.O_RDONLY)
            info = os.fstat(childfd)
            owned = (12345, 123, pidfd, childfd, root, (info.st_dev, info.st_ino))
            reads = [0]; mounted = [True]
            def inspect(_):
                row = created_row(str(root), str(scratch), mode)
                reads[0] += 1
                if reads[0] == 2:
                    row["State"].update(Running=True, Pid=12345)
                else:
                    row["State"].update(ExitCode=125 if native_exit else 0)
                if removal_owner_error and checkpoint.exists(): row["Name"] = "/foreign"
                return row
            def invoke(argv, **_):
                if argv[:2] == ["docker", "create"]: return b"a" * 64
                if argv[:2] == ["docker", "rm"]:
                    self.assertTrue(checkpoint.exists()); events.append("rm")
                if argv[0] == "umount":
                    self.assertTrue(checkpoint.exists()); events.append("umount"); mounted[0] = False
                return b""
            def archive(*_):
                row = json.loads(checkpoint.read_text())
                self.assertEqual(row["parentAccountingFinal"]["aggregateCpuUsec"], final["aggregateCpuUsec"])
                self.assertEqual(row["containerId"], "a" * 64)
                events.append("archive")
            def release():
                self.assertTrue(checkpoint.exists()); self.assertIn("rm", events)
                events.append("release")
                if release_error: raise HOST.Refusal("release unavailable")
                return {"released": True}
            self.parent.release.side_effect = release
            def gate(_):
                events.append("gate")
                if late_deadline: clock[0] = 3.0
            try:
                with patch.object(HOST, "mount_scratch", side_effect=fake_scratch_mount), \
                     patch.object(HOST, "command", side_effect=invoke), \
                     patch.object(HOST.subprocess, "Popen", side_effect=lambda *_args, **_kwargs: (events.append("start") or Attached(stdout, stderr))), \
                     patch.object(HOST, "docker_inspect", side_effect=inspect), \
                     patch.object(HOST, "observe_owned_process", return_value=owned), \
                     patch.object(HOST, "host_pid_gate", side_effect=HOST.Refusal("seccomp refused") if gate_error else None), \
                     patch.object(HOST, "proc_starttime", return_value=123), \
                     patch.object(HOST, "release_gate", side_effect=gate), \
                     patch.object(HOST, "retain_scratch", side_effect=archive), \
                     patch.object(HOST.os.path, "ismount", side_effect=lambda _: mounted[0]), \
                     patch.object(HOST.time, "monotonic", side_effect=lambda: clock[0]), \
                     patch.object(HOST, "seal_parent_checkpoint", side_effect=OSError(errno.ENOSPC, "receipt full") if checkpoint_error else HOST.seal_parent_checkpoint):
                    failed = any((native_exit, final_error, live_error, checkpoint_error, release_error,
                                  removal_owner_error, gate_error, live_cpu > HOST.MODE_LIMITS[mode][1], late_deadline, late_tail, usage_error))
                    if failed:
                        with self.assertRaises(HOST.Refusal): HOST.run_mode(HOST.IMAGE_ID, root, out, "owned", mode)
                        self.assertFalse((out / "receipt.json").exists())
                        return json.loads((out / "failure.json").read_text()), events
                    receipt = HOST.run_mode(HOST.IMAGE_ID, root, out, "owned", mode)
                    return receipt, events
            finally:
                stdout.close(); stderr.close()

    def test_scratch_archive_seals_only_within_compressed_and_metadata_caps(self):
        stream = io.BytesIO()
        writer = HOST.BoundedWriter(stream, 3)
        with self.assertRaises(HOST.Refusal):
            writer.write(b"four")
        self.assertEqual(stream.getvalue(), b"")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            scratch = root / "scratch"
            scratch.mkdir()
            for name in ("a", "b", "c"):
                (scratch / name).touch()
            target = root / "scratch.tar.gz"
            with patch.object(HOST, "MAX_ARCHIVE_ENTRIES", 2), self.assertRaisesRegex(
                    HOST.Refusal, "metadata budget"):
                HOST.retain_scratch(scratch, target)
            self.assertFalse(target.exists())
            self.assertFalse((root / ".scratch.tar.gz.partial").exists())
            for path in scratch.iterdir():
                path.unlink()
            (scratch / "a").write_bytes(b"small")
            with patch.object(HOST, "MAX_SCRATCH", 64), self.assertRaisesRegex(
                    HOST.Refusal, "compressed scratch archive"):
                HOST.retain_scratch(scratch, target)
            self.assertFalse(target.exists())
            self.assertFalse((root / ".scratch.tar.gz.partial").exists())

    def test_evidence_collector_omits_unsealed_and_oversized_scratch(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            host = root / "host"
            attempt = host / "attempt-1"
            attempt.mkdir(parents=True)
            validation = root / "validation.json"
            validation.write_text("{}\n")
            (attempt / "failure.json").write_text('{"status":"FAILED"}\n')
            (attempt / "native-stdout.jsonl").write_text('{"event":"host_gate_ready"}\n')
            (attempt / "scratch.tar.gz").write_bytes(b"x" * 65)
            (attempt / ".scratch.tar.gz.partial").write_bytes(b"unsealed")
            upload = root / "upload"
            with patch.object(HOST, "MAX_SCRATCH", 64):
                result = HOST.collect_evidence(validation, host, upload)
            self.assertFalse((upload / "attempt-1/scratch.tar.gz").exists())
            self.assertFalse((upload / "attempt-1/.scratch.tar.gz.partial").exists())
            self.assertTrue((upload / "attempt-1/failure.json").is_file())
            self.assertTrue((upload / "attempt-1/native-stdout.jsonl").is_file())
            self.assertIn("attempt-1/scratch.tar.gz", [item["path"] for item in result["omitted"]])
            self.assertLessEqual(sum(p.stat().st_size for p in upload.rglob("*") if p.is_file()),
                                 HOST.MAX_UPLOAD)

    def test_cgroup_path_and_exact_limits(self):
        with tempfile.TemporaryDirectory() as temp:
            group = Path(temp) / "system.slice" / ("docker-" + "a" * 64 + ".scope")
            group.mkdir(parents=True)
            self.assertEqual(HOST.parse_cgroup(123, "a" * 64,
                             "0::/system.slice/docker-" + "a" * 64 + ".scope\n", Path(temp)), group)
            for text in ("0::/system.slice/docker-" + "b" * 64 + ".scope\n",
                         "1:cpu:/system.slice/docker-" + "a" * 64 + ".scope\n",
                         "0::/system.slice/../docker-" + "a" * 64 + ".scope\n"):
                with self.subTest(text=text), self.assertRaises(HOST.Refusal):
                    HOST.parse_cgroup(123, "a" * 64, text, Path(temp))
        values = {"cpu.max": "100000 100000", "memory.max": str(1024 ** 3),
                  "memory.swap.max": "0", "pids.max": "128"}
        HOST.validate_cgroup_values(values)
        for key, bad in (("cpu.max", "max 100000"), ("memory.max", "max"),
                         ("memory.swap.max", "1073741824"), ("pids.max", "max")):
            with self.subTest(key=key), self.assertRaises(HOST.Refusal):
                HOST.validate_cgroup_values({**values, key: bad})
    def test_prepared_artifact_join_rejects_tamper(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            paths = [root / name for name in ("validation.json", "binding.json", "packet.json", "image.tar.gz")]
            validation = {"status": "PREPARED_IMAGE_IDENTITY_VERIFIED; RUNTIME_UNQUALIFIED",
                          "selectedReadFilesVerifiedAgainstSavedLayers": 1548,
                          "source": {"commit": HOST.SOURCE, "tree": HOST.TREE, "dockerfileSha256": "extra"},
                          "imageArchiveSha256": HOST.IMAGE_SHA, "imageConfigId": HOST.IMAGE_ID,
                          "artifactId": HOST.ARTIFACT_ID, "runId": HOST.ARTIFACT_RUN,
                          "runAttempt": HOST.ARTIFACT_ATTEMPT, "zipSha256": HOST.ZIP_SHA,
                          "githubZipDigestVerified": True}
            binding = {"sourceCommit": HOST.SOURCE, "sourceTree": HOST.TREE,
                       "imageSha256": HOST.IMAGE_SHA, "imageConfigId": HOST.IMAGE_ID,
                       "status": "STATIC_READ_POLICY_PREPARED; RUNTIME_NOT_ADMITTED",
                       "imageEntries": [{}] * 1548, "namespaceEntries": [{}] * 360}
            paths[0].write_text(json.dumps(validation))
            paths[1].write_text(json.dumps(binding))
            paths[3].write_bytes(b"synthetic image, never loaded")
            packet = {"schema": "openclaw-v98-confined-execution-packet/v1",
                      "sourceCommit": HOST.SOURCE, "sourceTree": HOST.TREE,
                      "sourceManifestPath": "scripts/proofs/v98-confined/source-manifest.json",
                      "boundary": {"readBindingSha256": HOST.sha256(paths[1])},
                      "artifact": {"imageSha256": HOST.IMAGE_SHA, "configId": HOST.IMAGE_ID,
                                   "zipSha256": HOST.ZIP_SHA}}
            paths[2].write_text(json.dumps(packet))
            with patch.object(HOST, "sha256", side_effect=lambda p: HOST.IMAGE_SHA if p == paths[3]
                      else HOST.sha256_original(p)):
                HOST.verify_prepared(*paths)
            validation["selectedReadFilesVerifiedAgainstSavedLayers"] = 1546
            paths[0].write_text(json.dumps(validation))
            with patch.object(HOST, "sha256", side_effect=lambda p: HOST.IMAGE_SHA if p == paths[3]
                      else HOST.sha256_original(p)), self.assertRaises(HOST.Refusal):
                HOST.verify_prepared(*paths)

    def test_startup_policy_retains_exact_gap_or_source_bound_config_join(self):
        base = Path(__file__).parent
        binding = HOST.read_json(base / "read-policy/runtime-read-binding.json")
        config_bound = any(row["path"] == "/etc/ssl/openssl.cnf" for row in binding["imageEntries"])
        with tempfile.TemporaryDirectory() as temp:
            if config_bound:
                HOST.startup_preflight(base, binding, temp)
            else:
                with self.assertRaisesRegex(HOST.Refusal, "static startup prerequisites"):
                    HOST.startup_preflight(base, binding, temp)
            receipt = HOST.read_json(Path(temp) / "startup-preflight.json")
            self.assertEqual(receipt["missingFileReads"],
                             [] if config_bound else [{"path": "/etc/ssl/openssl.cnf", "scopes": ["parent", "helper"]}])
            self.assertEqual(receipt["missingNamespaceMetadata"],
                             [] if config_bound else ["/etc/ssl", "/usr/lib/ssl/openssl.cnf"])
            self.assertFalse(receipt["executionAdmission"])
            validation = Path(temp) / "validation.json"; validation.write_text("{}\n")
            custody = HOST.collect_evidence(validation, temp, Path(temp) / "upload")
            self.assertIn("startup-preflight.json", [row["path"] for row in custody["copied"]])

    def test_startup_prerequisites_join_file_alias_and_packet_identities(self):
        # Synthetic binding data only: no grant is written to the real policy.
        asset = HOST.read_json(Path(__file__).with_name("startup-prerequisites.json"))
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp); (base / "read-policy").mkdir()
            asset_path = base / "startup-prerequisites.json"
            asset_path.write_text(json.dumps(asset))
            (base / "packet.json").write_text(json.dumps({"startupPrerequisitesSha256": HOST.sha256(asset_path)}))
            binding = {"imageEntries": asset["requiredCanonicalRegularFiles"],
                       "namespaceEntries": asset["requiredNamespaceMetadata"]}
            reads = "".join(row["path"] + "\n" for row in binding["imageEntries"])
            for scope in ("parent", "helper"):
                (base / "read-policy" / (scope + "-read-paths.txt")).write_text(reads)
            observed = HOST.startup_preflight(base, binding, base)
            self.assertEqual(observed["status"], "STATIC_STARTUP_PREREQUISITES_JOINED; RUNTIME_NOT_ADMITTED")
            self.assertFalse(observed["executionAdmission"])
            for section, index, key, value in (
                    ("imageEntries", 1, "sha256", "0" * 64),
                    ("namespaceEntries", 7, "target", "/other")):
                changed = json.loads(json.dumps(binding)); changed[section][index][key] = value
                with self.subTest(section=section), self.assertRaises(HOST.Refusal):
                    HOST.startup_preflight(base, changed, base)
            (base / "packet.json").write_text('{}\n')
            with self.assertRaisesRegex(HOST.Refusal, "differs from packet"):
                HOST.startup_preflight(base, binding, base)

    def test_actual_execute_preflights_known_startup_gap_before_compile_or_docker(self):
        tooling = Path(__file__).resolve().parents[3]
        binding = HOST.read_json(Path(__file__).with_name("read-policy") / "runtime-read-binding.json")
        config_bound = any(row["path"] == "/etc/ssl/openssl.cnf" for row in binding["imageEntries"])
        with tempfile.TemporaryDirectory() as temp:
            args = SimpleNamespace(tooling=tooling, source=tooling, tooling_commit="d7" * 20,
                                   validation=Path(temp) / "unused.json", image=Path(temp) / "unused-image",
                                   output=Path(temp) / "host")
            with patch.object(HOST.os, "geteuid", return_value=0), \
                 patch.object(HOST.platform, "system", return_value="Linux"), \
                 patch.object(HOST.platform, "machine", return_value="x86_64"), \
                 patch.dict(HOST.os.environ, {"GITHUB_REPOSITORY": "fr-meyer/openclaw",
                     "GITHUB_REF": "refs/heads/candidate/v2026.9.8-runtime-admission-5",
                     "GITHUB_RUN_ATTEMPT": "1", "GITHUB_RUN_NUMBER": "2", "GITHUB_EVENT_NAME": "push",
                     "GITHUB_SHA": "d7" * 20, "V98_APPROVED_COMMIT": "d7" * 20,
                     "V98_APPROVED_RUN_NUMBER": "2"}, clear=True), \
                 patch.object(HOST, "verify_source_manifest"), \
                 patch.object(HOST, "git", side_effect=[HOST.SOURCE, HOST.TREE, ""]), \
                 patch.object(HOST, "verify_prepared", return_value=(
                     {"toolingCommit": "f656dd5b26346761a8a2425645a4bc3969b6faeb"}, binding)), \
                 patch.object(HOST, "prepare_proof") as prepared, \
                 patch.object(HOST, "compile_native", side_effect=HOST.Refusal("pure compile boundary")) as compiled, \
                 patch.object(HOST, "command") as commands, \
                 patch.object(HOST.subprocess, "run") as invoked:
                with self.assertRaisesRegex(HOST.Refusal, "pure compile boundary" if config_bound else "static startup prerequisites"):
                    HOST.execute(args)
                if config_bound:
                    prepared.assert_called_once(); compiled.assert_called_once()
                else:
                    prepared.assert_not_called(); compiled.assert_not_called()
                commands.assert_not_called(); invoked.assert_not_called()
            self.assertTrue((args.output / "startup-preflight.json").is_file())

    def test_actual_execute_preserves_modes_and_requires_completed_image_cleanup(self):
        tooling = Path(__file__).resolve().parents[3]
        binding = HOST.read_json(Path(__file__).with_name("read-policy") / "runtime-read-binding.json")
        absent = SimpleNamespace(returncode=1, stdout=b"[]\n", stderr=(
            "Error response from daemon: No such image: " + HOST.IMAGE_ID + "\n").encode())
        loaded = SimpleNamespace(returncode=0, stderr=b"", stdout=json.dumps([
            {"Id": HOST.IMAGE_ID, "Os": "linux", "Architecture": "amd64"}]).encode())
        removed = SimpleNamespace(returncode=0, stdout=b"Deleted: owned image\n", stderr=b"")
        timeout = HOST.subprocess.TimeoutExpired(["docker", "image", "rm", HOST.IMAGE_ID], 15)
        cases = [
            ("timeout_then_absent", timeout, absent, HOST.subprocess.TimeoutExpired, "ABSENT"),
            ("complete", removed, absent, None, "ABSENT"),
            ("present", removed, loaded, HOST.Refusal, "PRESENT"),
            ("daemon_error", removed, SimpleNamespace(returncode=1, stdout=b"[]\n",
                stderr=b"Cannot connect to the Docker daemon\n"), HOST.Refusal, "UNKNOWN"),
            ("inspect_timeout", removed, HOST.subprocess.TimeoutExpired(
                ["docker", "image", "inspect", HOST.IMAGE_ID], 5), HOST.Refusal, "UNKNOWN"),
            ("remove_conflict", SimpleNamespace(returncode=1, stdout=b"",
                stderr=b"image is in use\n"), loaded, HOST.Refusal, "PRESENT"),
            ("inspect_identity_drift", removed, SimpleNamespace(returncode=0, stderr=b"",
                stdout=b'[{"Id":"sha256:wrong"}]\n'), HOST.Refusal, "UNKNOWN"),
            ("remove_os_error", OSError(errno.EIO, "removal failed"), absent, OSError, "ABSENT"),
            ("inspect_output_budget", removed, SimpleNamespace(returncode=1, stdout=b"x" * 65537,
                stderr=absent.stderr), HOST.Refusal, "UNKNOWN"),
            ("mode_failed", None, None, HOST.Refusal, None),
        ]
        for name, removal, inspection, failure, image_state in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                args = SimpleNamespace(tooling=tooling, source=tooling, tooling_commit="d7" * 20,
                    validation=root / "validation.json", image=root / "unused-image", output=root / "host")
                args.validation.write_text("{}\n")
                modes = [{"mode": mode, "observed": True} for mode in HOST.MODE_LIMITS]
                def docker(argv, **options):
                    if argv == ["docker", "image", "rm", HOST.IMAGE_ID]:
                        # Observable ordering: removal sees the already-written
                        # mode receipt, even if it subsequently times out.
                        self.assertEqual(HOST.read_json(args.output / "mode-observations.json")["modes"], modes)
                    next_result = docker_results.pop(0)
                    if isinstance(next_result, Exception):
                        raise next_result
                    return next_result
                docker_results = [absent, removed, loaded]
                mode_results = [modes[0], HOST.Refusal("mode ownership remains unresolved")]
                if image_state is not None:
                    docker_results += [removal, inspection]
                    mode_results = modes
                with patch.object(HOST.os, "geteuid", return_value=0), \
                     patch.object(HOST.platform, "system", return_value="Linux"), \
                     patch.object(HOST.platform, "machine", return_value="x86_64"), \
                     patch.dict(HOST.os.environ, {"GITHUB_REPOSITORY": "fr-meyer/openclaw",
                         "GITHUB_REF": "refs/heads/candidate/v2026.9.8-runtime-admission-5",
                         "GITHUB_RUN_ID": "2", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_RUN_NUMBER": "2",
                         "GITHUB_EVENT_NAME": "push", "GITHUB_SHA": "d7" * 20,
                         "V98_APPROVED_COMMIT": "d7" * 20, "V98_APPROVED_RUN_NUMBER": "2"}, clear=True), \
                     patch.object(HOST, "verify_source_manifest"), \
                     patch.object(HOST, "git", side_effect=[HOST.SOURCE, HOST.TREE, ""]), \
                     patch.object(HOST, "verify_prepared", return_value=(
                         {"toolingCommit": "f656dd5b26346761a8a2425645a4bc3969b6faeb"}, binding)), \
                     patch.object(HOST, "prepare_proof", return_value=[]), \
                     patch.object(HOST, "compile_native", return_value="inert"), \
                     patch.object(HOST, "host_preflight"), \
                     patch.object(HOST, "run_mode", side_effect=mode_results), \
                     patch.object(HOST.subprocess, "run", side_effect=docker) as invoked:
                    if failure is None:
                        HOST.execute(args)
                    else:
                        with self.assertRaises(failure):
                            HOST.execute(args)
                    if image_state is None:
                        self.assertEqual(len(invoked.call_args_list), 3)
                        self.assertFalse((args.output / "mode-observations.json").exists())
                        self.assertFalse((args.output / "image-cleanup.json").exists())
                        self.assertFalse((args.output / "qualification.json").exists())
                        continue
                    self.assertEqual(len(invoked.call_args_list), 5)
                    self.assertEqual(invoked.call_args_list[-2].args[0], ["docker", "image", "rm", HOST.IMAGE_ID])
                    self.assertEqual(invoked.call_args_list[-2].kwargs["timeout"], 15)
                    self.assertEqual(invoked.call_args_list[-1].args[0], ["docker", "image", "inspect", HOST.IMAGE_ID])
                    self.assertEqual(invoked.call_args_list[-1].kwargs["timeout"], 5)
                observations = HOST.read_json(args.output / "mode-observations.json")
                cleanup = HOST.read_json(args.output / "image-cleanup.json")
                self.assertEqual(observations["modes"], modes)
                self.assertEqual(cleanup["inspection"]["imageState"], image_state)
                self.assertEqual(cleanup["successfulRemovalAndVerifiedAbsence"], failure is None)
                if name == "timeout_then_absent":
                    self.assertEqual(cleanup["removal"]["status"], "TIMED_OUT")
                    self.assertEqual(cleanup["removal"]["failure"]["type"], "TimeoutExpired")
                self.assertEqual((args.output / "qualification.json").exists(), failure is None)
                custody = HOST.collect_evidence(args.validation, args.output, root / "upload")
                retained = {row["path"] for row in custody["copied"]}
                self.assertTrue({"mode-observations.json", "image-cleanup.json"} <= retained)
                self.assertEqual("qualification.json" in retained, failure is None)
                self.assertEqual(custody["omitted"], [])

    def test_native_observations_join_product_not_only_claims(self):
        native = [{"event": "host_gate_ready", "mode": "--capability-probe"},
                  {"event": "base_boundary_installed", "phase": 0},
                  {"event": "thread_owned", "phase": 0}, {"event": "thread_reaped", "phase": 0},
                  *[{"event": "syscall_denied", "value": 41}] * 4,
                  {"event": "syscall_denied", "value": 56},
                  *[{"event": "fsync_completed", "phase": 0}] * 4,
                  {"event": "phase_joined", "phase": 0, "value": 0},
                  {"event": "native_attempt_joined", "phase": 0, "value": 0}]
        controls = {key: True for key in ("fsync", "sqliteWalBackupClose",
                                               "deniedOutsideScratch", "deniedSockets")}
        product = [{"event": "capability_controls_joined", "main": controls, "worker": controls}]
        HOST.assess_native("--capability-probe", native, product, 0, False)
        with self.assertRaisesRegex(HOST.Refusal, "native socket/process denials"):
            HOST.assess_native("--capability-probe", native[:4] + native[8:], product, 0, False)
        with self.assertRaisesRegex(HOST.Refusal, "product observations"):
            HOST.assess_native("--capability-probe", native, [], 0, False)

    def test_trusted_stdout_requires_jsonl(self):
        with self.assertRaisesRegex(HOST.Refusal, "non-JSON"):
            HOST.parse_events(b"product text\n", b"")
        self.assertEqual(HOST.parse_events(b'{"event":"host_gate_ready"}\n', b"noise\n")[0],
                         [{"event": "host_gate_ready"}])


HOST.sha256_original = HOST.sha256


if __name__ == "__main__":
    unittest.main()
