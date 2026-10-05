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
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location("v98_host_runtime", Path(__file__).with_name("host-runtime.py"))
HOST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HOST)


def inspect_row(container_id="a" * 64):
    return {
        "Id": container_id, "Image": HOST.IMAGE_ID, "AppArmorProfile": "docker-default",
        "Config": {"User": "1000:1000", "Entrypoint": ["/proof/runner/v98-supervisor"],
                   "Cmd": ["--capability-probe"], "Healthcheck": {"Test": ["NONE"]}},
        "HostConfig": {"ReadonlyRootfs": True, "Privileged": False, "NetworkMode": "none",
                       "CapDrop": ["ALL"], "CgroupnsMode": "private", "PidMode": "",
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
            {"OSType": "linux", "Architecture": "x86_64", "CgroupVersion": "2",
             "MemoryLimit": True, "SwapLimit": True, "CpuCfsQuota": True, "PidsLimit": True,
             "SecurityOptions": ["name=apparmor", "name=seccomp,profile=builtin"],
             "Plugins": {"Log": ["local"]}, "DefaultRuntime": "runc", "Runtimes": {"runc": {}}})


class HostContractTests(unittest.TestCase):
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
                with patch.object(HOST, "mount_scratch", side_effect=lambda path: path.mkdir()), \
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
                            "log budget exceeded" if overflow else "host gate was never admitted"):
                        HOST.run_mode(HOST.IMAGE_ID, root, root / "attempt", "owned", "--capability-probe")
                    self.assertEqual(commands.call_count, 2 if kill_failure else 1)
                    admitted.assert_not_called(); archived.assert_not_called()
                failure = json.loads((root / "attempt/failure.json").read_text())
                self.assertEqual((root / "attempt/product-stderr.log").read_bytes(), message[:8] if overflow else message)
                self.assertFalse(failure["extinctionObserved"])
                self.assertIsNone(failure["cgroupDevInode"])
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
            with patch.object(HOST, "mount_scratch", side_effect=lambda path: path.mkdir()), \
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
            with patch.object(HOST, "mount_scratch", side_effect=lambda path: path.mkdir()), \
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

    def test_policy_refusal_kills_bound_group_and_writes_post_cleanup_failure(self):
        class Attached:
            def __init__(self, stdout, stderr):
                self.stdout, self.stderr = stdout, stderr

            def poll(self):
                return 0

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            stdout_r, stdout_w = os.pipe()
            stderr_r, stderr_w = os.pipe()
            os.write(stdout_w, b'{"event":"host_gate_ready","mode":"--capability-probe"}\n')
            os.close(stdout_w)
            os.close(stderr_w)
            stdout = os.fdopen(stdout_r, "rb", buffering=0)
            stderr = os.fdopen(stderr_r, "rb", buffering=0)
            pidfd = os.open(os.devnull, os.O_RDONLY)
            group_fd = os.open(temp, os.O_RDONLY)
            owned = (12345, 123, pidfd, group_fd, root, (1, 2))
            try:
                with patch.object(HOST, "mount_scratch", side_effect=lambda path: path.mkdir()), \
                     patch.object(HOST, "command", side_effect=[b"a" * 64, b"", b""]), \
                     patch.object(HOST.subprocess, "Popen", return_value=Attached(stdout, stderr)), \
                     patch.object(HOST, "docker_inspect", return_value=created_row(
                         str(root), str(root / "attempt/scratch-tmpfs"))), \
                     patch.object(HOST, "observe_owned_process", return_value=owned), \
                     patch.object(HOST, "host_pid_gate", side_effect=HOST.Refusal("seccomp refused")), \
                     patch.object(HOST, "kill_owned") as killed, \
                     patch.object(HOST, "extinction", return_value=True), \
                     patch.object(HOST, "retain_scratch") as retained:
                    with self.assertRaisesRegex(HOST.Refusal, "seccomp refused"):
                        HOST.run_mode(HOST.IMAGE_ID, root, root / "attempt", "owned", "--capability-probe")
                    killed.assert_called_once_with("a" * 64, root, (1, 2), group_fd)
                    retained.assert_called_once()
                failure = json.loads((root / "attempt/failure.json").read_text())
                self.assertTrue(failure["extinctionObserved"])
                self.assertEqual(failure["reason"], "seccomp refused")
            finally:
                stdout.close()
                stderr.close()

    def test_deadline_probe_refuses_a_host_stall_after_gate_release(self):
        clock = [0.0]
        killed = [False]

        class Attached:
            def __init__(self, stdout, stderr):
                self.stdout, self.stderr = stdout, stderr

            def poll(self):
                return 0 if killed[0] else None

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            stdout_r, stdout_w = os.pipe()
            stderr_r, stderr_w = os.pipe()
            os.write(stdout_w, b'{"event":"host_gate_ready","mode":"--deadline-probe"}\n')
            os.close(stdout_w)
            os.close(stderr_w)
            stdout = os.fdopen(stdout_r, "rb", buffering=0)
            stderr = os.fdopen(stderr_r, "rb", buffering=0)
            pidfd = os.open(os.devnull, os.O_RDONLY)
            cpu_fd = os.open(os.devnull, os.O_RDONLY)
            group_fd = os.open(temp, os.O_RDONLY)
            owned = (12345, 123, pidfd, group_fd, root, (1, 2))

            def signal(*_):
                killed[0] = True
                return clock[0]

            try:
                with patch.object(HOST, "mount_scratch", side_effect=lambda path: path.mkdir()), \
                     patch.object(HOST, "command", side_effect=[b"a" * 64, b"", b""]), \
                     patch.object(HOST.subprocess, "Popen", return_value=Attached(stdout, stderr)), \
                     patch.object(HOST, "observe_owned_process", return_value=owned), \
                     patch.object(HOST, "host_pid_gate", return_value=(0, cpu_fd)), \
                     patch.object(HOST, "docker_inspect", side_effect=[created_row(
                         str(root), str(root / "attempt/scratch-tmpfs"), "--deadline-probe"),
                         {"State": {"Pid": 12345}}]), \
                     patch.object(HOST, "proc_starttime", return_value=123), \
                     patch.object(HOST, "release_gate", side_effect=lambda _: clock.__setitem__(0, 3.0)), \
                     patch.object(HOST, "read_cgroup_cpu_fd", return_value=0), \
                     patch.object(HOST, "kill_owned", side_effect=signal), \
                     patch.object(HOST, "extinction", side_effect=lambda *_: killed[0]), \
                     patch.object(HOST, "retain_scratch"), \
                     patch.object(HOST.time, "monotonic", side_effect=lambda: clock[0]):
                    with self.assertRaisesRegex(HOST.Refusal, "signalled too late"):
                        HOST.run_mode(HOST.IMAGE_ID, root, root / "attempt", "owned", "--deadline-probe")
                failure = json.loads((root / "attempt/failure.json").read_text())
                self.assertEqual(failure["deadlineKillRequestedWallSeconds"], 3.0)
                self.assertEqual(failure["deadlineSignalCompletedWallSeconds"], 3.0)
                self.assertTrue(failure["extinctionObserved"])
            finally:
                stdout.close()
                stderr.close()

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
        self.assertEqual(HOST.cgroup_cpu("usage_usec 120\nuser_usec 70\n"), 120)
        with tempfile.TemporaryFile() as stats:
            stats.write(b"usage_usec 120\nuser_usec 70\n")
            stats.flush()
            self.assertEqual(HOST.read_cgroup_cpu_fd(stats.fileno()), 120)
            self.assertEqual(HOST.read_cgroup_cpu_fd(stats.fileno()), 120)

    def test_cpu_errors_identify_actual_seek_or_read_operation(self):
        for method, operation in (("lseek", "cpu.stat seek"), ("read", "cpu.stat read")):
            with self.subTest(method=method), tempfile.TemporaryFile() as counter, \
                    patch.object(HOST.os, method, side_effect=OSError(errno.ENODEV, "inactive")):
                with self.assertRaises(HOST.ObservationFailure) as caught:
                    HOST.read_cgroup_cpu_fd(counter.fileno())
            detail = HOST.failure_detail(caught.exception, "generic")
            self.assertEqual(detail["operation"], operation)
            self.assertEqual(detail["errno"], errno.ENODEV)
        for text in ("usage_usec 1\nusage_usec 2\n", "usage_usec -1\n", "bad row extra\n"):
            with self.subTest(text=text), self.assertRaises(HOST.Refusal):
                HOST.cgroup_cpu(text)

    def test_cgroup_extinction_requires_original_bounded_population(self):
        with tempfile.TemporaryDirectory() as temp:
            group = Path(temp) / "group"; group.mkdir()
            events = group / "cgroup.events"; events.write_text("populated 0\nfrozen 0\n")
            fd = os.open(group, os.O_RDONLY); info = os.fstat(fd)
            identity = (info.st_dev, info.st_ino)
            try:
                self.assertTrue(HOST.extinction(group, identity, fd))
                for contents in ("populated 1\n", "populated 0\npopulated 1\n", "x" * 4096):
                    events.write_text(contents)
                    if contents == "populated 1\n":
                        self.assertFalse(HOST.extinction(group, identity, fd))
                    else:
                        with self.assertRaises(HOST.Refusal):
                            HOST.extinction(group, identity, fd)
                events.unlink(); group.rmdir()
                self.assertFalse(HOST.extinction(group, identity, fd))
                group.mkdir(); events.write_text("populated 0\n")
                with self.assertRaisesRegex(HOST.Refusal, "reused"):
                    HOST.extinction(group, identity, fd)
            finally:
                os.close(fd)

    def test_cgroup_kill_cannot_follow_path_replacement(self):
        with tempfile.TemporaryDirectory() as temp:
            group = Path(temp) / "group"; group.mkdir()
            (group / "cgroup.events").write_text("populated 1\n")
            (group / "cgroup.kill").write_text("0\n")
            fd = os.open(group, os.O_RDONLY); info = os.fstat(fd)
            identity = (info.st_dev, info.st_ino)
            real_open = os.open
            held = group.with_name("original")
            def raced_open(path, flags, **kwargs):
                if path == "cgroup.kill":
                    self.assertEqual(kwargs["dir_fd"], fd)
                    self.assertTrue(flags & os.O_NOFOLLOW)
                    group.rename(held); group.mkdir()
                    (group / "cgroup.kill").write_text("0\n")
                return real_open(path, flags, **kwargs)
            try:
                with patch.object(HOST.os, "open", side_effect=raced_open), \
                        patch.object(HOST, "wait_extinction", return_value=True):
                    HOST.kill_owned("a" * 64, group, identity, fd)
                self.assertEqual((held / "cgroup.kill").read_text(), "1\n")
                self.assertEqual((group / "cgroup.kill").read_text(), "0\n")
            finally:
                os.close(fd)

    def test_native_exit_and_host_enodev_keep_independent_cleanup(self):
        self.check_bound_cpu_failure(native_exit=13, live_failure=True)

    def test_native_success_cannot_replace_missing_final_cpu(self):
        self.check_bound_cpu_failure(native_exit=0, live_failure=False)

    def test_terminal_native_refusal_marks_final_cpu_not_attempted(self):
        self.check_bound_cpu_failure(native_exit=13, live_failure=False)

    def check_bound_cpu_failure(self, native_exit, live_failure):
        class Attached:
            def __init__(self, stdout, stderr): self.stdout, self.stderr = stdout, stderr
            def poll(self): return 125 if native_exit else 0
            def wait(self, timeout): return self.poll()

        controls = {key: True for key in ("fsync", "sqliteWalBackupClose", "deniedOutsideScratch", "deniedSockets")}
        native = [{"event": "host_gate_ready", "mode": "--capability-probe"},
                  {"event": "base_boundary_installed", "phase": 0},
                  {"event": "thread_owned", "phase": 0}, {"event": "thread_reaped", "phase": 0},
                  *[{"event": "syscall_denied", "value": 41}] * 4,
                  {"event": "syscall_denied", "value": 56},
                  *[{"event": "fsync_completed", "phase": 0}] * 4,
                  {"event": "phase_joined", "phase": 0, "value": native_exit},
                  {"event": "native_attempt_joined", "phase": 0, "value": 0}]
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            stdout_r, stdout_w = os.pipe(); stderr_r, stderr_w = os.pipe()
            os.write(stdout_w, b"".join((json.dumps(row) + "\n").encode() for row in native))
            product = {"event": "capability_controls_joined", "main": controls, "worker": controls}
            os.write(stderr_w, (json.dumps(product) + "\n").encode())
            os.close(stdout_w); os.close(stderr_w)
            stdout = os.fdopen(stdout_r, "rb", buffering=0); stderr = os.fdopen(stderr_r, "rb", buffering=0)
            pidfd = os.open(os.devnull, os.O_RDONLY); cpu_fd = os.open(os.devnull, os.O_RDONLY)
            group_fd = os.open(root, os.O_RDONLY); info = os.fstat(group_fd)
            owned = (12345, 123, pidfd, group_fd, root, (info.st_dev, info.st_ino))
            created = created_row(str(root), str(root / "attempt/scratch-tmpfs"))
            running = json.loads(json.dumps(created)); running["State"].update(Pid=12345, Running=True)
            stopped = json.loads(json.dumps(created)); stopped["State"].update(ExitCode=125 if native_exit else 0)
            observations = [created, running] + ([] if live_failure else [stopped]) + [stopped, stopped]
            issue = HOST.ObservationFailure("cpu.stat read", OSError(errno.ENODEV, "inactive counter"))
            try:
                with patch.object(HOST, "mount_scratch", side_effect=lambda path: path.mkdir()), \
                     patch.object(HOST, "command", return_value=b"a" * 64) as commands, \
                     patch.object(HOST.subprocess, "Popen", return_value=Attached(stdout, stderr)), \
                     patch.object(HOST, "observe_owned_process", return_value=owned), \
                     patch.object(HOST, "host_pid_gate", return_value=(100, cpu_fd)), \
                     patch.object(HOST, "docker_inspect", side_effect=observations) as inspected, \
                     patch.object(HOST, "proc_starttime", return_value=123), \
                     patch.object(HOST, "release_gate"), \
                     patch.object(HOST, "extinction", return_value=not live_failure), \
                     patch.object(HOST, "read_cgroup_cpu_fd", side_effect=issue) as counters, \
                     patch.object(HOST, "kill_owned", side_effect=FileNotFoundError("scope absent")), \
                     patch.object(HOST.os.path, "ismount", return_value=True), \
                     patch.object(HOST, "retain_scratch") as archived:
                    with self.assertRaises(HOST.Refusal):
                        HOST.run_mode(HOST.IMAGE_ID, root, root / "attempt", "owned", "--capability-probe")
                    self.assertEqual(inspected.call_count, len(observations))
                    self.assertEqual(commands.call_count, 1)  # create only, no rm/unmount
                    archived.assert_not_called()
                    if native_exit and not live_failure:
                        counters.assert_not_called()
                failure = json.loads((root / "attempt/failure.json").read_text())
                if native_exit and not live_failure:
                    self.assertIsNone(failure["hostFailure"]["errno"])
                    self.assertEqual(failure["hostFailure"]["operation"], "exact container exit and native outcome")
                else:
                    self.assertEqual(failure["hostFailure"]["errno"], errno.ENODEV)
                    self.assertEqual(failure["hostFailure"]["operation"], "cpu.stat read")
                self.assertEqual(failure["primaryFailure"]["authority"],
                                 "TRUSTED_NATIVE_PHASE_EXIT" if native_exit else "HOST_OPERATION")
                self.assertFalse(failure["finalCpuVerified"])
                self.assertEqual(failure["finalCpuStatus"], "NOT_ATTEMPTED" if live_failure or native_exit else "ATTEMPTED_UNVERIFIED")
                self.assertFalse(failure["extinctionObserved"])
                self.assertTrue(failure["stoppedContainerState"]["stoppedVerified"])
                self.assertTrue(failure["stoppedWithoutCgroupProof"])
                self.assertTrue(failure["scratchMounted"])
                self.assertFalse((root / "attempt/receipt.json").exists())
            finally:
                stdout.close(); stderr.close()

    def test_prepared_artifact_join_rejects_tamper(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            paths = [root / name for name in ("validation.json", "binding.json", "packet.json", "image.tar.gz")]
            validation = {"status": "PREPARED_IMAGE_IDENTITY_VERIFIED; RUNTIME_UNQUALIFIED",
                          "selectedReadFilesVerifiedAgainstSavedLayers": 1547,
                          "source": {"commit": HOST.SOURCE, "tree": HOST.TREE, "dockerfileSha256": "extra"},
                          "imageArchiveSha256": HOST.IMAGE_SHA, "imageConfigId": HOST.IMAGE_ID,
                          "artifactId": HOST.ARTIFACT_ID, "runId": HOST.ARTIFACT_RUN,
                          "runAttempt": HOST.ARTIFACT_ATTEMPT, "zipSha256": HOST.ZIP_SHA,
                          "githubZipDigestVerified": True}
            binding = {"sourceCommit": HOST.SOURCE, "sourceTree": HOST.TREE,
                       "imageSha256": HOST.IMAGE_SHA, "imageConfigId": HOST.IMAGE_ID,
                       "status": "STATIC_READ_POLICY_PREPARED; RUNTIME_NOT_ADMITTED",
                       "imageEntries": [{}] * 1547, "namespaceEntries": [{}] * 358}
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

    def test_current_startup_policy_refuses_and_retains_exact_gap(self):
        base = Path(__file__).parent
        binding = HOST.read_json(base / "read-policy/runtime-read-binding.json")
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(HOST.Refusal, "static startup prerequisites"):
                HOST.startup_preflight(base, binding, temp)
            receipt = HOST.read_json(Path(temp) / "startup-preflight.json")
            self.assertEqual(receipt["missingFileReads"],
                             [{"path": "/etc/ssl/openssl.cnf", "scopes": ["parent", "helper"]}])
            self.assertEqual(receipt["missingNamespaceMetadata"],
                             ["/etc/ssl", "/usr/lib/ssl/openssl.cnf"])
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
        with tempfile.TemporaryDirectory() as temp:
            args = SimpleNamespace(tooling=tooling, source=tooling, tooling_commit="d7" * 20,
                                   validation=Path(temp) / "unused.json", image=Path(temp) / "unused-image",
                                   output=Path(temp) / "host")
            with patch.object(HOST.os, "geteuid", return_value=0), \
                 patch.object(HOST.platform, "system", return_value="Linux"), \
                 patch.object(HOST.platform, "machine", return_value="x86_64"), \
                 patch.dict(HOST.os.environ, {"GITHUB_REPOSITORY": "fr-meyer/openclaw",
                     "GITHUB_REF": "refs/heads/candidate/v2026.9.8-runtime-admission-3",
                     "GITHUB_RUN_ATTEMPT": "1", "GITHUB_RUN_NUMBER": "1"}, clear=True), \
                 patch.object(HOST, "verify_source_manifest"), \
                 patch.object(HOST, "git", side_effect=[HOST.SOURCE, HOST.TREE, ""]), \
                 patch.object(HOST, "verify_prepared", return_value=(
                     {"toolingCommit": "711da57d4e7576fb911f917cd83ead95dfd17602"}, binding)), \
                 patch.object(HOST, "prepare_proof") as prepared, \
                 patch.object(HOST, "compile_native") as compiled, \
                 patch.object(HOST, "command") as commands, \
                 patch.object(HOST.subprocess, "run") as invoked:
                with self.assertRaisesRegex(HOST.Refusal, "static startup prerequisites"):
                    HOST.execute(args)
                prepared.assert_not_called(); compiled.assert_not_called()
                commands.assert_not_called(); invoked.assert_not_called()
            self.assertTrue((args.output / "startup-preflight.json").is_file())

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
