"""Pure contract checks for the proposed host supervisor; no native execution."""
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
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
                       "SecurityOpt": ["no-new-privileges:true"]},
        "Mounts": [{"Destination": "/proof", "Source": "/proof-host", "Type": "bind", "RW": False},
                   {"Destination": "/scratch", "Source": "/scratch-host", "Type": "bind", "RW": True}],
        "Name": "/owned", "State": {"Pid": 12345, "Running": True},
    }


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
        ):
            changed = json.loads(json.dumps(row))
            mutation(changed)
            with self.subTest(changed=changed), self.assertRaises(HOST.Refusal):
                HOST.inspect_container(changed, "a" * 64, HOST.IMAGE_ID,
                                       "/proof-host", "/scratch-host")

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
            self.assertIsNone(HOST.kill_created_without_group("a" * 64, "owned", HOST.IMAGE_ID,
                              "/proof-host", "/scratch-host", "--capability-probe"))
            invoked.assert_called_once_with(["docker", "kill", "--signal=KILL", "a" * 64], timeout=5)

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
                     patch.object(HOST, "docker_inspect", return_value={"State": {"Pid": 12345}}), \
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
