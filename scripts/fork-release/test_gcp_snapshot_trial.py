"""Synthetic executor boundary tests. No Docker, systemd, database or cloud calls."""
import copy
from contextlib import ExitStack, contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import gcp_snapshot_trial as trial
import release


class SnapshotTrialTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.op = self.root / ("a" * 32)
        self.op.mkdir(mode=0o700)
        self.dataset = self.root / "dataset"
        self.dataset.mkdir()
        self.clean = {
            "schema": "openclaw.snapshot-clean-input.v1", "receiptId": "synthetic-clean",
            "restorationState": "unmigrated", "restoreReceiptSha256": "b" * 64,
            "baselineSourceSha": "c" * 40, "baselineImageDigest": "sha256:" + "d" * 64,
            "snapshotIdentity": "synthetic-snapshot", "mountRoot": str(self.dataset),
            "filesystemDevice": 2065, "devicePath": "/dev/sdb", "deviceMajorMinor": "8:16",
            "mounts": [{"source": str(self.dataset / name), "target": target, "readOnly": False}
                       for name, target in (("state", trial.STATE_TARGET), ("tmp", "/tmp"),
                                            ("cache", "/rehearsal/cache"))],
            "configSha256": "f" * 64, "integrationsDisabled": True,
        }
        self.image = {
            "schema": "openclaw.fork-release-image.v2", "architecture": "amd64",
            "sourceSha": "1" * 40, "version": "2026.10.5", "bundledCodexVersion": "0.160.0",
            "indexDigest": "sha256:" + "2" * 64, "imageDigest": "sha256:" + "3" * 64,
            "configDigest": "sha256:" + "4" * 64,
            "producer": {"kind": "gcp", "toolingSha": "5" * 40},
            "pluginPayload": [
                {"id": "codex", "codexRuntime": {"packageVersion": "0.160.0", "cliVersion": "0.160.0",
                    "initializeVersion": "0.160.0", "initialized": True, "shutdown": "exited"}},
                {"id": "workboard", "workboardRuntime": {"worker": "sqlite", "roundTrip": True, "closed": True}},
            ],
        }
        self.image.update(trial.QUALIFIED_IMAGE)
        self.image["producer"]["toolingSha"] = trial.QUALIFIED_PRODUCER
        self.plan = {
            "schema": "openclaw.snapshot-trial-plan.v1", "operationId": self.op.name,
            "toolingSha": "6" * 40, "imageReceiptSha256": "7" * 64, "cleanInputSha256": "8" * 64,
            "limits": {"memoryBytes": 24 << 30, "cpus": 4, "readBps": 128 << 20,
                "writeBps": 32 << 20, "minMemoryAvailableBytes": 25 << 30,
                "minRootFreeBytes": 2 << 30, "minDataFreeBytes": 8 << 30, "timeoutSeconds": 86400},
        }
        self.intent = {"plan": self.plan, "image": self.image, "clean": self.clean}
        self.devices = {"filesystemPath": "/dev/sdb1", "filesystemMajorMinor": "8:17",
            "devicePath": "/dev/sdb", "deviceMajorMinor": "8:16", "ioPath": "/dev/sdb",
            "ioMajorMinor": "8:16", "filesystemSysfs": "/sys/devices/synthetic/block/sdb/sdb1",
            "ioSysfs": "/sys/devices/synthetic/block/sdb"}
        (self.op / "intent.json").write_text(json.dumps(self.intent))
        (self.op / "intent.json").chmod(0o600)

    def test_closed_plan_and_clean_input(self):
        trial.validate(self.plan, self.image, self.clean)
        for key, value in (("restorationState", "partially_migrated"),
                           ("integrationsDisabled", False), ("configSha256", "bad")):
            clean = {**self.clean, key: value}
            with self.assertRaises(release.Refusal):
                trial.validate(self.plan, self.image, clean)
        for key in ("packageVersion", "initializeVersion"):
            image = copy.deepcopy(self.image)
            image["pluginPayload"][0]["codexRuntime"][key] = "0.149.0"
            with self.assertRaises(release.Refusal):
                trial.validate(self.plan, image, self.clean)
        plan = copy.deepcopy(self.plan)
        plan["limits"]["memoryBytes"] = 8 << 30
        with self.assertRaises(release.Refusal):
            trial.validate(plan, self.image, self.clean)

    def test_retained_timeline_command_requires_pinned_old_script_and_exact_create_intent(self):
        op = self.root / trial.DD_RETAINED_TIMELINE
        op.mkdir(mode=0o700)
        prior = {
            "plan": {"operationId": op.name, "toolingSha": trial.DD_RETAINED_TIMELINE_TOOLING,
                     "checkInputSha256": trial.DD_RETAINED_TIMELINE_CHECK_SHA256,
                     "imageReceiptSha256": trial.DD_RETAINED_TIMELINE_IMAGE_RECEIPT_SHA256},
            "helpers": {"gcp_rehearsal_checks.py": trial.DD_RETAINED_TIMELINE_CHECKS_SHA256},
            "check": {"schema": trial.DD_STARTUP_CHECK, "diagnosticPluginServiceTimeline": True},
        }
        args = ["create", "--entrypoint", "/usr/bin/env", "sha256:" + "a" * 64,
                "-i", "node", "-e", "new timeline script"]
        old_script = "x" * 14103
        old = [*args[:-1], old_script]
        record = op / "create-intent.json"
        trial.durable.write_once(record, trial.durable.encode({"at": "2026-10-22T00:00:00Z", "argv": old}))
        with patch.object(trial, "DD_RETAINED_TIMELINE_SCRIPT_SHA256",
                          hashlib.sha256(old_script.encode()).hexdigest()):
            self.assertEqual(trial.expected_container_cmd(op, prior, args), old[4:])
            def replace(argv):
                record.write_bytes(trial.durable.encode({"at": "2026-10-22T00:00:00Z", "argv": argv}))
            replace([*old[:-1], old_script[:-1] + "y"])
            with self.assertRaisesRegex(release.Refusal, "trial.container.historical_command"):
                trial.expected_container_cmd(op, prior, args)
            replace(["other", *old[1:]])
            with self.assertRaisesRegex(release.Refusal, "trial.container.historical_command"):
                trial.expected_container_cmd(op, prior, args)
            replace(old)
            for owner, key, value in ((prior["plan"], "toolingSha", "0" * 40),
                                      (prior["plan"], "checkInputSha256", "0" * 64),
                                      (prior["plan"], "imageReceiptSha256", "0" * 64),
                                      (prior["helpers"], "gcp_rehearsal_checks.py", "0" * 64)):
                original = owner[key]
                owner[key] = value
                with self.assertRaisesRegex(release.Refusal, "trial.container.historical_command_identity"):
                    trial.expected_container_cmd(op, prior, args)
                owner[key] = original
            other = self.root / ("f" * 32)
            self.assertEqual(trial.expected_container_cmd(other, prior, args), args[4:])
        self.assertEqual(trial.DD_RETAINED_TIMELINE_SCRIPT_SHA256,
                         "c5b9369a11369d49770136a001e3bf90556505285df0f945a5298fae342e6e80")

    def test_retained_final_timeline_preserves_exact_old_docker_command(self):
        op = self.root / trial.DD_RETAINED_FINAL_TIMELINE
        op.mkdir(mode=0o700)
        prior = {
            "plan": {"operationId": op.name, "toolingSha": trial.DD_RETAINED_FINAL_TIMELINE_TOOLING,
                     "checkInputSha256": trial.DD_RETAINED_FINAL_TIMELINE_CHECK_SHA256,
                     "imageReceiptSha256": trial.DD_FINAL_IMAGE_RECEIPT_SHA256},
            "helpers": {"gcp_rehearsal_checks.py": trial.DD_RETAINED_FINAL_TIMELINE_CHECKS_SHA256},
            "check": {"schema": trial.DD_STARTUP_CHECK, "diagnosticPluginServiceTimeline": True},
        }
        args = ["create", "--entrypoint", "/usr/bin/env", "sha256:" + "a" * 64,
                "-i", "node", "-e", "new longer timeline script"]
        old_script = "x" * 16012
        old = [*args[:-1], old_script]
        record = op / "create-intent.json"
        trial.durable.write_once(record, trial.durable.encode({"at": "2026-10-23T00:00:00Z", "argv": old}))
        with patch.object(trial, "DD_RETAINED_FINAL_TIMELINE_SCRIPT_SHA256",
                          hashlib.sha256(old_script.encode()).hexdigest()):
            self.assertEqual(trial.expected_container_cmd(op, prior, args), old[4:])
            for changed in ([*old[:-1], "y" + old_script[1:]], ["other", *old[1:]]):
                record.write_bytes(trial.durable.encode({"at": "2026-10-23T00:00:00Z", "argv": changed}))
                with self.assertRaisesRegex(release.Refusal, "trial.container.historical_command"):
                    trial.expected_container_cmd(op, prior, args)
            record.write_bytes(trial.durable.encode({"at": "2026-10-23T00:00:00Z", "argv": old}))
            for owner, key in ((prior["plan"], "toolingSha"),
                               (prior["plan"], "checkInputSha256"),
                               (prior["plan"], "imageReceiptSha256"),
                               (prior["helpers"], "gcp_rehearsal_checks.py")):
                original = owner[key]
                owner[key] = "0" * len(original)
                with self.assertRaisesRegex(release.Refusal, "trial.container.historical_command_identity"):
                    trial.expected_container_cmd(op, prior, args)
                owner[key] = original
            self.assertEqual(trial.expected_container_cmd(self.root / ("f" * 32), prior, args), args[4:])
        self.assertEqual(trial.DD_RETAINED_FINAL_TIMELINE_SCRIPT_SHA256,
                         "4a8efd90b8032095c69af0be0852081419d4b61a65cb373bd308c6373f2caff6")

    def test_retained_final_timeline_helper_manifest_is_exact_stage_manifest(self):
        helpers = {
            "gcp_build.py": "05d85444f2be56919499cd45c2dbe5cd9b821d5f2a1cbabc6c610eed9dfb0c73",
            "gcp_rehearsal_checks.py": trial.DD_RETAINED_FINAL_TIMELINE_CHECKS_SHA256,
            "gcp_snapshot_trial.py": "93320bce7a2df2926b5aecffad34072deb46ba8c9f0669142a38a01bcad0f535",
            "pr.py": "351f2a1855959346e41a682a9a8a01bcef84b8fdbf3866b697ddd996502b6a3f",
            "preflight.py": "ea9ff84927b40e0808ffb83426264b267299ee1237908548439c136b8d306f2b",
            "release.py": "7bf6bf8b9d8885694f0bce3644f4cedc41c1ac99623c6460c81c0c6a3cc53f12",
        }
        prior = {"plan": {"toolingSha": trial.DD_RETAINED_FINAL_TIMELINE_TOOLING}, "helpers": helpers}
        with patch.object(trial, "read_operation", return_value=(self.op, prior)):
            self.assertEqual(trial.read_retained(self.op), (self.op, prior))
            helpers["gcp_snapshot_trial.py"] = "0" * 64
            with self.assertRaisesRegex(release.Refusal, "trial.prior.unreviewed_helpers"):
                trial.read_retained(self.op)

    def select_phase(self, selected):
        self.plan.update({"schema": "openclaw.snapshot-trial-plan.v2", "phase": selected,
                          "checkInputSha256": "e" * 64})
        self.intent["check"] = {"schema": "openclaw.snapshot-trial-check.v1", "phase": selected}
        if selected != "doctor":
            self.intent["check"].update({"doctorOperationId": "b" * 32, "doctorResultSha256": "a" * 64})
        if selected == "startup":
            self.clean["restorationState"] = "doctor-complete"
        if selected == "rollback":
            self.image = {"schema": "openclaw.rehearsal-baseline-image.v1", "version": "2026.9.4",
                "architecture": "amd64", "sourceSha": self.clean["baselineSourceSha"],
                "indexDigest": self.clean["baselineImageDigest"], "imageDigest": "sha256:" + "5" * 64,
                "configDigest": "sha256:" + "6" * 64, "gatewayProbeContract": "healthz-readyz-v1"}
            self.intent["image"] = self.image

    def test_explicit_higher_profile_preserves_memory_and_refuses_implicit_escalation(self):
        self.plan["limits"].update(readBps=256 << 20, writeBps=64 << 20)
        trial.validate(self.plan, self.image, self.clean)
        self.select_phase("doctor")
        trial.validate(self.plan, self.image, self.clean, self.intent["check"])
        self.plan["limits"].update(readBps=320 << 20, writeBps=128 << 20)
        with self.assertRaisesRegex(release.Refusal, "trial.limits.unreviewed_envelope"):
            trial.validate(self.plan, self.image, self.clean, self.intent["check"])
        self.plan["limits"].update(readBps=256 << 20, writeBps=64 << 20)
        for key, value in (("readBps", 512 << 20), ("writeBps", 32 << 20),
                           ("readBps", 0), ("cpus", 8), ("memoryBytes", 32 << 30)):
            changed = copy.deepcopy(self.plan)
            changed["limits"][key] = value
            with self.assertRaises(release.Refusal):
                trial.validate(changed, self.image, self.clean, self.intent["check"])

    def test_explicit_16g_profile_retains_host_reserve_and_native_limits(self):
        limits = self.plan["limits"]
        limits.update(memoryBytes=16 << 30, minMemoryAvailableBytes=20 << 30,
                      readBps=256 << 20, writeBps=64 << 20)
        self.select_continuation()
        trial.validate(self.plan, self.image, self.clean, self.intent["check"])
        self.assertEqual(trial.resource_profile(limits)["id"], "memory16-read256-write64")
        args = trial.create_argv(self.op, self.intent, self.devices)
        self.assertEqual(args[args.index("--memory") + 1], str(16 << 30))
        self.assertEqual(args[args.index("--memory-swap") + 1], str(16 << 30))
        self.assertEqual(args[args.index("--cpus") + 1], "4")
        self.assertIn(f"/dev/sdb:{256 << 20}", args)
        self.assertIn(f"/dev/sdb:{64 << 20}", args)
        cg = self.root / "low-memory-cgroup"
        cg.mkdir()
        for name, value in {"memory.max": str(16 << 30), "memory.swap.max": "0", "pids.max": "512",
                            "cpu.max": "400000 100000", "io.max": f"8:16 rbps={256 << 20} wbps={64 << 20}"}.items():
            (cg / name).write_text(value)
        trial.admit_cgroup(cg, self.intent, self.devices)
        (cg / "memory.max").write_text(str(24 << 30))
        with self.assertRaisesRegex(release.Refusal, "trial.cgroup.memory"):
            trial.admit_cgroup(cg, self.intent, self.devices)
        for key, value in (("minMemoryAvailableBytes", 19 << 30),
                           ("minMemoryAvailableBytes", 21 << 30),
                           ("memoryBytes", 17 << 30), ("readBps", 128 << 20),
                           ("writeBps", 32 << 20), ("cpus", 5)):
            original = limits[key]
            limits[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(release.Refusal):
                trial.validate(self.plan, self.image, self.clean, self.intent["check"])
            limits[key] = original

    def test_explicit_16g_read320_write128_enforces_actual_io_and_reports_rates(self):
        limits = self.plan["limits"]
        limits.update(memoryBytes=16 << 30, minMemoryAvailableBytes=20 << 30,
                      readBps=320 << 20, writeBps=128 << 20)
        self.select_continuation()
        trial.validate(self.plan, self.image, self.clean, self.intent["check"])
        self.assertEqual(trial.resource_profile(limits)["id"], "memory16-read320-write128")
        args = trial.create_argv(self.op, self.intent, self.devices)
        self.assertEqual(args[args.index("--memory") + 1], str(16 << 30))
        self.assertEqual(args[args.index("--memory-swap") + 1], str(16 << 30))
        self.assertEqual(args[args.index("--cpus") + 1], "4")
        self.assertEqual(args[args.index("--device-read-bps") + 1], f"/dev/sdb:{320 << 20}")
        self.assertEqual(args[args.index("--device-write-bps") + 1], f"/dev/sdb:{128 << 20}")
        cg = self.root / "higher-io-cgroup"
        cg.mkdir()
        for name, value in {"memory.max": str(16 << 30), "memory.swap.max": "0", "pids.max": "512",
                            "cpu.max": "400000 100000",
                            "io.max": f"8:16 rbps={320 << 20} wbps={128 << 20}",
                            "io.stat": "8:16 rbytes=0 wbytes=0 rios=0 wios=0"}.items():
            (cg / name).write_text(value)
        with patch.object(trial.time, "monotonic_ns", side_effect=[10**9, 3 * 10**9]):
            first = trial.io_sample(cg, self.intent, self.devices)
            (cg / "io.stat").write_text(
                f"8:16 rbytes={640 << 20} wbytes={256 << 20} rios=1000 wios=1000")
            second = trial.io_sample(cg, self.intent, self.devices, first)
        self.assertEqual((second["readBps"], second["writeBps"]), (320 << 20, 128 << 20))
        self.assertEqual((second["readCapRatio"], second["writeCapRatio"]), (1, 1))
        (cg / "io.max").write_text(f"8:16 rbps={256 << 20} wbps={64 << 20}")
        with self.assertRaisesRegex(release.Refusal, "trial.cgroup.io"):
            trial.admit_cgroup(cg, self.intent, self.devices)
        for read, write in ((512, 128), (320, 64), (256, 128)):
            limits.update(readBps=read << 20, writeBps=write << 20)
            with self.subTest(read=read, write=write), self.assertRaisesRegex(
                    release.Refusal, "trial.limits.unreviewed_envelope"):
                trial.validate(self.plan, self.image, self.clean, self.intent["check"])

    def test_16g_profile_admission_checks_20g_host_available(self):
        self.plan["limits"].update(memoryBytes=16 << 30, minMemoryAvailableBytes=20 << 30,
                                   readBps=256 << 20, writeBps=64 << 20)
        fs = SimpleNamespace(f_bavail=200 << 30, f_frsize=1)
        with patch.object(trial.os, "statvfs", return_value=fs):
            for available, accepted in (((20 << 30) - 1024, False), (20 << 30, True)):
                meminfo = f"MemAvailable: {available // 1024} kB\n"
                with patch.object(trial.Path, "read_text", return_value=meminfo):
                    if accepted:
                        self.assertEqual(trial.capacity(self.plan, self.clean, True)["memoryAvailableBytes"],
                                         available)
                    else:
                        with self.assertRaisesRegex(release.Refusal, "trial.capacity.memory"):
                            trial.capacity(self.plan, self.clean, True)

    def select_lease_patch_pressure(self):
        self.image.update(trial.LEASE_PATCH_IMAGE)
        self.image["producer"]["toolingSha"] = trial.LEASE_PATCH_PRODUCER
        self.plan["imageReceiptSha256"] = trial.LEASE_PATCH_RECEIPT_SHA256
        self.plan["limits"].update(memoryBytes=16 << 30, minMemoryAvailableBytes=12 << 30,
                                   readBps=320 << 20, writeBps=128 << 20)
        self.select_continuation()
        self.intent["check"]["doctorOperationId"] = trial.LEASE_PATCH_PRIOR
        for artifact in self.intent["check"]["reconciliation"]["artifacts"]:
            artifact["ownerOperationId"] = trial.LEASE_PATCH_PRIOR

    def test_12g_admission_is_exact_lease_patch_image_and_successor_only(self):
        self.select_lease_patch_pressure()
        trial.validate(self.plan, self.image, self.clean, self.intent["check"])
        self.assertTrue(trial.lease_patch_pressure_profile(self.plan, self.image,
                                                           self.intent["check"]))
        for owner, key, value in (
                (self.image, "sourceSha", "f" * 40),
                (self.image["producer"], "toolingSha", "e" * 40),
                (self.plan, "imageReceiptSha256", "d" * 64),
                (self.intent["check"], "doctorOperationId", "b" * 32)):
            old = owner[key]
            owner[key] = value
            if key == "doctorOperationId":
                self.intent["check"]["reconciliation"]["artifacts"][0]["ownerOperationId"] = value
            with self.subTest(key=key), self.assertRaisesRegex(
                    release.Refusal, "trial.host_pressure.scope"):
                trial.validate(self.plan, self.image, self.clean, self.intent["check"])
            owner[key] = old
            if key == "doctorOperationId":
                self.intent["check"]["reconciliation"]["artifacts"][0]["ownerOperationId"] = old
        self.plan["limits"]["writeBps"] = 64 << 20
        with self.assertRaisesRegex(release.Refusal, "trial.limits.unreviewed_envelope"):
            trial.validate(self.plan, self.image, self.clean, self.intent["check"])
        self.plan["limits"].update(writeBps=128 << 20, minMemoryAvailableBytes=20 << 30)
        trial.validate(self.plan, self.image, self.clean, self.intent["check"])

    def test_12g_admission_allows_pinned_candidate_startup_after_doctor(self):
        self.select_lease_patch_pressure()
        self.select_phase("startup")
        trial.validate(self.plan, self.image, self.clean, self.intent["check"])
        self.assertTrue(trial.lease_patch_pressure_profile(self.plan, self.image,
                                                           self.intent["check"]))
        self.plan["phase"] = "rollback"
        with self.assertRaisesRegex(release.Refusal, "trial.host_pressure.scope"):
            trial.lease_patch_pressure_profile(self.plan, self.image, self.intent["check"])

    def test_12g_admission_capacity_boundary_and_host_sensor_parsing(self):
        self.select_lease_patch_pressure()
        fs = SimpleNamespace(f_bavail=200 << 30, f_frsize=1)
        with patch.object(trial.os, "statvfs", return_value=fs):
            for available, accepted in (((12 << 30) - 1024, False), (12 << 30, True)):
                with patch.object(trial.Path, "read_text", return_value=(
                        f"MemAvailable: {available // 1024} kB\n")):
                    if accepted:
                        self.assertEqual(trial.capacity(self.plan, self.clean, True)
                                         ["memoryAvailableBytes"], available)
                    else:
                        with self.assertRaisesRegex(release.Refusal, "trial.capacity.memory"):
                            trial.capacity(self.plan, self.clean, True)
        with patch.object(trial.Path, "read_text", side_effect=[
                "MemAvailable: 12582912 kB\n", "some avg10=0.0 avg60=0.0 avg300=0.0 total=0\n"
                "full avg10=0.21 avg60=0.1 avg300=0.0 total=100\n"]):
            self.assertEqual(trial.host_pressure_sample()["availableBytes"], 12 << 30)
        with patch.object(trial.Path, "read_text", side_effect=[
                "MemAvailable: 12582912 kB\n", "some avg10=0.0 avg60=0.0 avg300=0.0 total=0\n"]):
            with self.assertRaisesRegex(release.Refusal, "trial.host_pressure.unavailable"):
                trial.host_pressure_sample()

    def test_host_pressure_gate_immediate_memory_and_sustained_psi_refusals(self):
        def state():
            return {"samples": 0, "last": None, "minimumAvailableBytes": 12 << 30,
                    "maximumFullAvg10": 0.0, "highPsiSince": None}
        watched = state()
        with patch.object(trial, "host_pressure_sample", return_value={
                "at": "synthetic", "availableBytes": (8 << 30) - 1, "fullAvg10": 0.0}):
            with self.assertRaisesRegex(release.Refusal, "trial.host_pressure.memory"):
                trial.host_pressure_gate(watched, now=0)
        self.assertEqual(watched["minimumAvailableBytes"], (8 << 30) - 1)
        with patch.object(trial, "host_pressure_sample", return_value={
                "at": "synthetic", "availableBytes": (12 << 30) - 1, "fullAvg10": 0.0}):
            with self.assertRaisesRegex(release.Refusal, "trial.host_pressure.admission"):
                trial.host_pressure_gate(state(), admission=True, now=0)
        watched = state()
        with patch.object(trial, "host_pressure_sample", return_value={
                "at": "synthetic", "availableBytes": 12 << 30, "fullAvg10": 6.0}):
            with self.assertRaisesRegex(release.Refusal, "trial.host_pressure.admission_psi"):
                trial.host_pressure_gate(state(), admission=True, now=0)
            trial.host_pressure_gate(watched, now=0)
            trial.host_pressure_gate(watched, now=4)
            with self.assertRaisesRegex(release.Refusal, "trial.host_pressure.psi"):
                trial.host_pressure_gate(watched, now=5)
        with patch.object(trial, "host_pressure_sample", return_value={
                "at": "synthetic", "availableBytes": 12 << 30, "fullAvg10": float("nan")}):
            with self.assertRaisesRegex(release.Refusal, "trial.host_pressure.unavailable"):
                trial.host_pressure_gate(state(), now=0)

    def select_continuation(self):
        self.select_phase("doctor")
        self.clean["restorationState"] = "doctor-interrupted"
        self.intent["check"] = {"schema": trial.CONTINUATION, "phase": "doctor",
            "doctorOperationId": "b" * 32, "doctorIntentSha256": "c" * 64, "doctorResultSha256": "d" * 64,
            "reconciliation": {"observedAt": "2000-01-01T00:00:01Z",
                "artifactDisposition": "incomplete-group-reconciled", "artifactReceiptSha256": "e" * 64,
                "artifacts": [self.artifact()], "recaptureBytes": 47 << 30, "originalCaptureBytes": 4 << 30,
                "additionalReserveBytes": 8 << 30}}

    def artifact(self, **changes):
        return {"path": str(self.dataset / "state/db.sqlite.pre-startup-migration-synthetic.bak"),
                "kind": "migration-backup", "classification": "not-reusable",
                "disposition": "preserve-outside-mounts", "reason": "Synthetic incomplete group; exact owner retained for diagnosis",
                "ownerOperationId": "b" * 32, "device": 2065, "inode": 42, "links": 1,
                "sizeBytes": 24 << 30, "allocatedBytes": 23 << 30, "evidenceSha256": "f" * 64,
                "nativeDiscardOnRetry": True, "removal": None, **changes}

    def test_continuation_requires_truthful_input_and_explicit_recapture_budget(self):
        self.select_continuation()
        trial.validate(self.plan, self.image, self.clean, self.intent["check"])
        with self.assertRaisesRegex(release.Refusal, "trial.clean.identity"):
            trial.validate(self.plan, self.image, {**self.clean, "restorationState": "unmigrated"}, self.intent["check"])
        ordinary = {"schema": "openclaw.snapshot-trial-check.v1", "phase": "doctor"}
        with self.assertRaisesRegex(release.Refusal, "trial.clean.identity"):
            trial.validate(self.plan, self.image, self.clean, ordinary)
        required = self.plan["limits"]["minDataFreeBytes"] + (59 << 30)
        with self.assertRaisesRegex(release.Refusal, "trial.continuation.capacity"):
            trial.continuation_capacity({"dataFreeBytes": required - 1}, self.plan, self.intent["check"])
        resource = {"dataFreeBytes": required}
        trial.continuation_capacity(resource, self.plan, self.intent["check"])
        self.assertEqual(resource["continuationAdmission"]["requiredFreeBytes"], required)
        self.intent["check"]["reconciliation"]["recaptureBytes"] = 0
        with self.assertRaisesRegex(release.Refusal, "trial.continuation.recapture"):
            trial.validate(self.plan, self.image, self.clean, self.intent["check"])

    def test_completed_migration_reuse_still_budgets_fresh_original_capture(self):
        self.select_continuation()
        record = self.intent["check"]["reconciliation"]
        record.update(artifactDisposition="completed-group-retained", recaptureBytes=0,
                      artifacts=[self.artifact(classification="native-revalidation-required", disposition="retain",
                                               nativeDiscardOnRetry=False)])
        trial.validate(self.plan, self.image, self.clean, self.intent["check"])
        required = self.plan["limits"]["minDataFreeBytes"] + (12 << 30)
        with self.assertRaisesRegex(release.Refusal, "trial.continuation.capacity"):
            trial.continuation_capacity({"dataFreeBytes": required - 1}, self.plan, self.intent["check"])
        resources = {"dataFreeBytes": required}
        trial.continuation_capacity(resources, self.plan, self.intent["check"])
        self.assertEqual(resources["continuationAdmission"]["artifacts"]["retainedBytes"], 23 << 30)

    def test_artifact_accounting_refuses_disposal_of_protected_unknown_or_reusable_files(self):
        self.select_continuation()
        record = self.intent["check"]["reconciliation"]
        for classification in ("protected", "unknown", "native-revalidation-required"):
            record["artifacts"] = [self.artifact(classification=classification, disposition="deletion-pending")]
            with self.assertRaises(release.Refusal):
                trial.validate(self.plan, self.image, self.clean, self.intent["check"])
        for changes in ({"ownerOperationId": "c" * 32}, {"links": 2},
                        {"path": "/production/db.bak"}, {"device": 2066}, {"allocatedBytes": -1}):
            record["artifacts"] = [self.artifact(**changes)]
            with self.assertRaises(release.Refusal):
                trial.validate(self.plan, self.image, self.clean, self.intent["check"])
        record["artifacts"] = [self.artifact(disposition="retain")]
        with self.assertRaisesRegex(release.Refusal, "trial.artifacts.incomplete_survivor"):
            trial.validate(self.plan, self.image, self.clean, self.intent["check"])

    def test_artifact_accounting_does_not_credit_pending_or_reported_removed_bytes(self):
        self.select_continuation()
        record = self.intent["check"]["reconciliation"]
        record["artifacts"] = [self.artifact(disposition="deletion-pending")]
        trial.validate(self.plan, self.image, self.clean, self.intent["check"])
        with self.assertRaisesRegex(release.Refusal, "trial.artifacts.deletion_pending"):
            trial.continuation_capacity({"dataFreeBytes": 1000 << 30}, self.plan, self.intent["check"])
        record["artifacts"][0]["disposition"] = "removed"
        with self.assertRaises(release.Refusal):
            trial.validate(self.plan, self.image, self.clean, self.intent["check"])
        record["artifacts"][0]["removal"] = {
            "manifestSha256": "1" * 64, "approvalSha256": "2" * 64, "resultSha256": "3" * 64}
        trial.validate(self.plan, self.image, self.clean, self.intent["check"])
        required = self.plan["limits"]["minDataFreeBytes"] + (59 << 30)
        with self.assertRaisesRegex(release.Refusal, "trial.continuation.capacity"):
            trial.continuation_capacity({"dataFreeBytes": required - 1}, self.plan, self.intent["check"])
        resource = {"dataFreeBytes": required}
        trial.continuation_capacity(resource, self.plan, self.intent["check"])
        self.assertEqual(resource["continuationAdmission"]["artifacts"]["removedBytes"], 23 << 30)

    def test_artifact_inventory_rejects_overlapping_paths_and_duplicate_allocations(self):
        self.select_continuation()
        record = self.intent["check"]["reconciliation"]
        first = self.artifact()
        for second in (self.artifact(), self.artifact(path=first["path"] + "/nested", inode=43),
                       self.artifact(path=str(self.dataset / "another.bak"))):
            record["artifacts"] = [first, second]
            with self.assertRaises(release.Refusal):
                trial.validate(self.plan, self.image, self.clean, self.intent["check"])

    def test_pending_artifact_disposal_blocks_start_before_claim_or_dispatch(self):
        self.select_continuation()
        self.intent["check"]["reconciliation"]["artifacts"][0]["disposition"] = "deletion-pending"
        with self.start_boundaries() as (_, dispatch), patch.object(trial, "phase_prerequisites", return_value={}):
            with self.assertRaisesRegex(release.Refusal, "trial.artifacts.deletion_pending"):
                trial.start(self.op)
            dispatch.assert_not_called()
        self.assertFalse((self.op / "dataset-transfer.json").exists())
        self.assertFalse((self.op / "start-intent.json").exists())

    def test_unresolved_native_deletion_set_blocks_start_even_for_protected_files(self):
        self.select_continuation()
        record = self.intent["check"]["reconciliation"]
        for classification in ("unknown", "protected", "native-revalidation-required"):
            for membership in (True, None):
                record["artifacts"] = [self.artifact(classification=classification, disposition="retain",
                                                    nativeDiscardOnRetry=membership)]
                trial.validate(self.plan, self.image, self.clean, self.intent["check"])
                with self.start_boundaries() as (_, dispatch), patch.object(trial, "phase_prerequisites", return_value={}):
                    with self.assertRaisesRegex(release.Refusal, "trial.artifacts.native_discard_unreconciled"):
                        trial.start(self.op)
                    dispatch.assert_not_called()
                self.assertFalse((self.op / "dataset-transfer.json").exists())
        record["artifacts"] = [self.artifact(classification="protected", disposition="retain",
                                            nativeDiscardOnRetry=False)]
        trial.continuation_capacity({"dataFreeBytes": 200 << 30}, self.plan, self.intent["check"])

    def native_result(self, selected="startup"):
        return {"schema": "openclaw.rehearsal-native-check.v1",
            "phase": "candidate-startup" if selected == "startup" else "rollback-startup",
            "probeContract": "healthz-startupz-readyz-v1" if selected == "startup" else "healthz-readyz-v1",
            "healthz": {"status": 200, "ok": True}, "readyz": {"status": 200, "ready": True},
            "startupz": {"status": 200, "ok": True, "statusText": "started"} if selected == "startup" else None,
            "ready": True, "nativeExitCode": 0, "nativeSignal": None,
            "shutdown": "exited", "escalated": False, "failure": None}

    def marker(self, result):
        return (trial.checks.RESULT_PREFIX + json.dumps(result) + "\n").encode()

    def test_v2_doctor_preserves_native_command_and_requires_bound_check(self):
        self.select_phase("doctor")
        trial.validate(self.plan, self.image, self.clean, self.intent["check"])
        self.assertEqual(trial.create_argv(self.op, self.intent, self.devices)[-len(trial.DOCTOR):], trial.DOCTOR)
        with self.assertRaises(release.Refusal):
            trial.validate(self.plan, self.image, self.clean)
        self.intent["check"]["command"] = "anything"
        with self.assertRaises(release.Refusal):
            trial.validate(self.plan, self.image, self.clean, self.intent["check"])

    def test_startup_requires_postdoctor_receipt_and_fixed_bounded_native_check(self):
        self.select_phase("startup")
        trial.validate(self.plan, self.image, self.clean, self.intent["check"])
        args = trial.create_argv(self.op, self.intent, self.devices)
        self.assertEqual(args[-3:-1], ["node", "-e"])
        self.assertIn("gateway", args[-1])
        self.assertNotEqual(args[-len(trial.DOCTOR):], trial.DOCTOR)
        with self.assertRaises(release.Refusal):
            trial.validate(self.plan, self.image, {**self.clean, "restorationState": "unmigrated"}, self.intent["check"])
        self.plan["limits"]["timeoutSeconds"] = 600
        with self.assertRaisesRegex(release.Refusal, "check.timeout"):
            trial.validate(self.plan, self.image, self.clean, self.intent["check"])

    def test_rollback_admits_separate_bound_baseline_without_candidate_codex_proof(self):
        self.select_phase("rollback")
        trial.validate(self.plan, self.image, self.clean, self.intent["check"])
        loaded = {"Id": self.image["indexDigest"], "Os": "linux", "Architecture": "amd64",
            "Config": {"Env": [], "Labels": {"org.opencontainers.image.revision": self.image["sourceSha"],
                       "org.opencontainers.image.version": self.image["version"]}}}
        with patch.object(trial, "docker", return_value=json.dumps([loaded]).encode()):
            self.assertEqual(trial.observe_image(self.image, "rollback")["loadedId"], self.image["indexDigest"])
        with self.assertRaisesRegex(release.Refusal, "trial.image.not_qualified"):
            trial.observe_image(self.image)
        with self.assertRaises(release.Refusal):
            trial.validate(self.plan, self.image, {**self.clean, "baselineSourceSha": "0" * 40}, self.intent["check"])

    @contextmanager
    def prior_boundaries(self, selected="startup", doctor_state="succeeded", no_create=False,
                         historical=False, previous_candidate=False, lease_patch_candidate=False):
        successor_check = (copy.deepcopy(self.intent.get("check"))
                           if (historical or previous_candidate or lease_patch_candidate) and selected == "doctor"
                           else None)
        prior = copy.deepcopy(self.intent)
        if historical:
            prior["image"].update(trial.HISTORICAL_IMAGE)
            prior["image"]["producer"]["toolingSha"] = trial.HISTORICAL_PRODUCER
            prior["plan"]["imageReceiptSha256"] = trial.HISTORICAL_IMAGE_RECEIPT_SHA256
            prior["clean"]["restorationState"] = "unmigrated"
            if prior["plan"]["schema"] == "openclaw.snapshot-trial-plan.v2":
                prior["check"] = {"schema": "openclaw.snapshot-trial-check.v1", "phase": "doctor"}
        if previous_candidate:
            prior["image"].update(trial.PREVIOUS_IMAGE)
            prior["image"]["producer"]["toolingSha"] = trial.QUALIFIED_PRODUCER
            prior["plan"]["imageReceiptSha256"] = trial.PREVIOUS_IMAGE_RECEIPT_SHA256
            prior["plan"]["toolingSha"] = trial.PREVIOUS_PIPELINE_SHA
            prior["clean"]["restorationState"] = "doctor-interrupted"
            old_reuse = copy.deepcopy(successor_check["backupReuse"])
            old_reuse["targetSourceSha"] = trial.PREVIOUS_IMAGE["sourceSha"]
            old_reuse["targetImageReceiptSha256"] = trial.PREVIOUS_IMAGE_RECEIPT_SHA256
            prior["check"]["backupReuse"] = old_reuse
        if lease_patch_candidate:
            prior["image"].update(trial.QUALIFIED_IMAGE)
            prior["image"]["producer"]["toolingSha"] = trial.QUALIFIED_PRODUCER
            prior["plan"]["imageReceiptSha256"] = trial.LEASE_PATCH_PRIOR_IMAGE_RECEIPT_SHA256
            prior["plan"]["toolingSha"] = trial.LEASE_PATCH_PRIOR_PIPELINE_SHA
            prior["plan"]["limits"].update(readBps=256 << 20, writeBps=64 << 20)
            prior["clean"]["restorationState"] = "doctor-interrupted"
            old_reuse = copy.deepcopy(successor_check["backupReuse"])
            old_reuse["targetSourceSha"] = trial.QUALIFIED_IMAGE["sourceSha"]
            old_reuse["targetImageReceiptSha256"] = trial.LEASE_PATCH_PRIOR_IMAGE_RECEIPT_SHA256
            prior["check"]["backupReuse"] = old_reuse
        previous_id = (trial.LEASE_PATCH_PRIOR if lease_patch_candidate else
                       trial.CORRECTED_REBUILD_PRIOR if previous_candidate else "b" * 32)
        previous = self.root / previous_id
        previous.mkdir(mode=0o700)
        prior["plan"]["operationId"] = previous.name
        self.select_phase(selected)
        if selected == "doctor":
            self.select_continuation()
            if successor_check and "backupReuse" in successor_check:
                self.intent["check"]["backupReuse"] = successor_check["backupReuse"]
                self.intent["check"]["reconciliation"] = successor_check["reconciliation"]
        if selected == "rollback":
            self.clean["mountRoot"] = str(self.root / "rollback-dataset")
            self.clean["mounts"] = [{**m, "source": m["source"].replace(str(self.dataset), self.clean["mountRoot"])}
                                    for m in self.clean["mounts"]]
            self.clean["restoreReceiptSha256"] = "0" * 64
        state = {"Running": False, "Pid": 0, "ExitCode": 0 if doctor_state == "succeeded" else 1,
                 "OOMKilled": False, "StartedAt": "start", "FinishedAt": "finish"}
        result = {"operationId": previous.name, "invocationId": "f" * 32, "state": doctor_state,
                  "at": "2000-01-01T00:00:00Z",
                  "doctorComplete": doctor_state == "succeeded", "nativeExitCode": state["ExitCode"],
                  "oomKillDelta": 0, "cgroupSettlementObserved": True,
                  "cleanup": "owned_container_stopped_retained", "nativeState": state,
                  "containerId": "9" * 64,
                  "imageReceiptSha256": prior["plan"]["imageReceiptSha256"],
                  "cleanInputSha256": prior["plan"]["cleanInputSha256"]}
        if no_create:
            result.update(cleanup="not_started", containerId=None, nativeState=None,
                          nativeExitCode=None, cgroupSettlementObserved=False, doctorComplete=False)
        raw = trial.durable.encode(prior)
        records = {"intent.json": prior, "result.json": result,
                   "started.json": {"invocationId": result["invocationId"]},
                   "start-intent.json": {"intentSha256": trial.digest(raw), "mounts": {}, "image": {"env": []},
                                         "devices": self.devices}}
        if not no_create:
            records["container.json"] = {"id": result["containerId"]}
        for name, value in records.items():
            trial.durable.write_once(previous / name, trial.durable.encode(value))
        self.intent["check"]["doctorResultSha256"] = trial.digest((previous / "result.json").read_bytes())
        if selected == "doctor":
            self.intent["check"]["doctorIntentSha256"] = trial.digest(raw)
        actual = {"Id": result["containerId"], "Name": "/openclaw-doctor-" + previous.name,
                  "Config": {"Labels": {"openclaw.snapshot-trial.operation": previous.name}},
                  "State": copy.deepcopy(state)}
        service = {"LoadState": "loaded", "InvocationID": "f" * 32, "MainPID": "0",
                   "ExecMainCode": "1", "ExecMainStatus": "1", "Result": "exit-code",
                   "ActiveState": "failed", "SubState": "failed"}
        native = subprocess.CompletedProcess([], 0, "\n".join(f"{k}={v}" for k, v in service.items()), "")
        with patch.object(trial, "PRIVATE_ROOT", self.root), \
             patch.object(trial.durable, "TRIAL_ROOT", self.root), \
             patch.object(trial.durable, "native", return_value=native), \
             patch.object(trial, "read_retained", return_value=(previous, prior)), \
             patch.object(trial, "status", return_value={"state": doctor_state, "result": result}) as observe, \
             patch.object(trial, "inspect_container", return_value=actual), \
             patch.object(trial, "validate_container") as policy, \
             patch.object(trial, "block_devices", return_value=self.devices), \
             patch.object(trial, "snapshot_paths", return_value={}):
            yield prior, result, actual, observe, policy

    def test_continuation_requires_exact_stopped_failed_predecessor_and_same_dataset_image(self):
        with self.prior_boundaries("doctor", "failed") as (prior, result, actual, observe, policy):
            proof = trial.phase_prerequisites(self.op, self.intent)
            self.assertEqual(proof["invocationId"], "f" * 32)
            self.assertEqual(proof["priorResourceProfile"]["id"], "read128-write32")
            for key, value in (("Running", True), ("Pid", 123), ("StartedAt", "other"),
                               ("FinishedAt", "other"), ("ExitCode", 2), ("OOMKilled", True)):
                original = actual["State"][key]
                actual["State"][key] = value
                with self.subTest(key=key), self.assertRaisesRegex(release.Refusal, "trial.prior.container_changed"):
                    trial.phase_prerequisites(self.op, self.intent)
                actual["State"][key] = original
            for owner, key, value in ((self.plan, "imageReceiptSha256", "0" * 64),
                    (self.clean, "restoreReceiptSha256", "0" * 64), (self.clean, "snapshotIdentity", "another"),
                    (self.intent["check"], "doctorIntentSha256", "0" * 64)):
                original = owner[key]
                owner[key] = value
                with self.subTest(key=key), self.assertRaises(release.Refusal):
                    trial.phase_prerequisites(self.op, self.intent)
                owner[key] = original
            observe.return_value = {"state": "unknown", "result": result}
            with self.assertRaisesRegex(release.Refusal, "trial.prior.not_settled"):
                trial.phase_prerequisites(self.op, self.intent)

    def test_historical_cross_build_proof_is_retained_but_new_direct_transition_refuses(self):
        group = "f8c55592-a39a-8e8c-87cd-40cb5ad53f22"
        self.select_continuation()
        record = self.intent["check"]["reconciliation"]
        record.update(artifactDisposition="completed-group-retained", recaptureBytes=0,
                      artifacts=[self.artifact(
                          path=str(self.dataset / ("state/db.sqlite.pre-startup-migration-" + group + ".bak")),
                          classification="native-revalidation-required", disposition="retain",
                          nativeDiscardOnRetry=False)])
        reuse = {"schema": trial.BACKUP_REUSE,
                 "originSourceSha": trial.HISTORICAL_IMAGE["sourceSha"],
                 "originImageDigest": trial.HISTORICAL_IMAGE["indexDigest"],
                 "originImageReceiptSha256": trial.HISTORICAL_IMAGE_RECEIPT_SHA256,
                 "targetSourceSha": self.image["sourceSha"],
                 "targetImageReceiptSha256": self.plan["imageReceiptSha256"],
                 "backupId": group, "manifestSha256": "a" * 64, "backupCount": 1}
        self.intent["check"]["backupReuse"] = reuse
        trial.validate(self.plan, self.image, self.clean, self.intent["check"])
        args = trial.create_argv(self.op, self.intent, self.devices)
        proof = [value.split("=", 1)[1] for value in args
                 if value.startswith("OPENCLAW_DOCTOR_BACKUP_REUSE_PROOF=")]
        self.assertEqual(len(proof), 1)
        self.assertEqual(json.loads(proof[0])["backupId"], group)
        self.assertNotIn("backupCount", json.loads(proof[0]))
        with self.prior_boundaries("doctor", "failed", historical=True) as (prior, result, actual, observe, policy):
            reuse = self.intent["check"]["backupReuse"]
            with self.assertRaisesRegex(release.Refusal, "trial.prior.startup_binding"):
                trial.phase_prerequisites(self.op, self.intent)
            for key, value in (("originImageReceiptSha256", "f" * 64),
                               ("originSourceSha", "f" * 40), ("targetSourceSha", "f" * 40),
                               ("manifestSha256", "bad"), ("backupId", "bad")):
                original = reuse[key]
                reuse[key] = value
                with self.subTest(key=key), self.assertRaises(release.Refusal):
                    trial.validate(self.plan, self.image, self.clean, self.intent["check"])
                reuse[key] = original
            prior["image"]["indexDigest"] = "sha256:" + "0" * 64
            with self.assertRaisesRegex(release.Refusal, "trial.prior.startup_binding"):
                trial.phase_prerequisites(self.op, self.intent)

    def test_cross_build_reuse_refuses_incomplete_group_and_unqualified_image(self):
        self.select_continuation()
        self.intent["check"]["backupReuse"] = {"schema": trial.BACKUP_REUSE,
            "originSourceSha": trial.HISTORICAL_IMAGE["sourceSha"],
            "originImageDigest": trial.HISTORICAL_IMAGE["indexDigest"],
            "originImageReceiptSha256": trial.HISTORICAL_IMAGE_RECEIPT_SHA256,
            "targetSourceSha": self.image["sourceSha"],
            "targetImageReceiptSha256": self.plan["imageReceiptSha256"],
            "backupId": "f8c55592-a39a-8e8c-87cd-40cb5ad53f22",
            "manifestSha256": "a" * 64, "backupCount": 1}
        with self.assertRaisesRegex(release.Refusal, "trial.reuse.group"):
            trial.validate(self.plan, self.image, self.clean, self.intent["check"])
        self.assertIsNone(trial.backup_reuse(None))
        old = copy.deepcopy(self.image)
        old.update(trial.HISTORICAL_IMAGE)
        old["producer"]["toolingSha"] = trial.HISTORICAL_PRODUCER
        with self.assertRaisesRegex(release.Refusal, "trial.image.not_qualified"):
            trial.qualified_image(old)
        trial.qualified_image(old, retained=True)

    def test_corrected_rebuild_keeps_exact_origin_group_after_failed_previous_image(self):
        self.select_continuation()
        group = "f8c55592-a39a-8e8c-87cd-40cb5ad53f22"
        self.intent["check"]["reconciliation"].update(
            artifactDisposition="completed-group-retained", recaptureBytes=0,
            artifacts=[self.artifact(
                path=str(self.dataset / ("state/db.sqlite.pre-startup-migration-" + group + ".bak")),
                classification="native-revalidation-required", disposition="retain",
                nativeDiscardOnRetry=False)])
        self.intent["check"]["backupReuse"] = {
            "schema": trial.BACKUP_REUSE,
            "originSourceSha": trial.HISTORICAL_IMAGE["sourceSha"],
            "originImageDigest": trial.HISTORICAL_IMAGE["indexDigest"],
            "originImageReceiptSha256": trial.HISTORICAL_IMAGE_RECEIPT_SHA256,
            "targetSourceSha": trial.QUALIFIED_IMAGE["sourceSha"],
            "targetImageReceiptSha256": self.plan["imageReceiptSha256"],
            "backupId": group, "manifestSha256": "a" * 64, "backupCount": 1}
        trial.validate(self.plan, self.image, self.clean, self.intent["check"])
        with self.prior_boundaries("doctor", "failed", previous_candidate=True) as (prior, *_):
            self.intent["check"]["doctorOperationId"] = trial.CORRECTED_REBUILD_PRIOR
            binding = trial.phase_prerequisites(self.op, self.intent)
            self.assertEqual(binding["priorImageReceiptSha256"],
                             trial.PREVIOUS_IMAGE_RECEIPT_SHA256)
            self.assertEqual(binding["successorImageReceiptSha256"],
                             self.plan["imageReceiptSha256"])
            reuse = self.intent["check"]["backupReuse"]
            for owner, key, changed in (
                (self.intent["check"], "doctorOperationId", "b" * 32),
                (reuse, "backupId", "a" * 36),
                (reuse, "manifestSha256", "b" * 64),
                (reuse, "originImageReceiptSha256", "c" * 64),
                (prior["check"]["backupReuse"], "targetSourceSha", "d" * 40),
                (prior["plan"], "toolingSha", "e" * 40),
                (prior["image"], "indexDigest", "sha256:" + "f" * 64),
            ):
                original = owner[key]
                owner[key] = changed
                with self.subTest(key=key), self.assertRaisesRegex(
                    release.Refusal, "trial.prior.startup_binding"):
                    trial.phase_prerequisites(self.op, self.intent)
                owner[key] = original

    def test_previous_candidate_image_is_retained_only(self):
        previous = copy.deepcopy(self.image)
        previous.update(trial.PREVIOUS_IMAGE)
        with self.assertRaisesRegex(release.Refusal, "trial.image.not_qualified"):
            trial.qualified_image(previous)
        trial.qualified_image(previous, retained=True)
        self.assertEqual(trial.RETAINED_HELPERS[trial.PREVIOUS_PIPELINE_SHA],
                         "969db0156d9dfc0480288a913f637a8252dc7ed93988873b7399ae02922a5fb0")

    def test_lease_patch_image_preserves_exact_failed_predecessor_and_original_group(self):
        self.image.update(trial.LEASE_PATCH_IMAGE)
        self.image["producer"]["toolingSha"] = trial.LEASE_PATCH_PRODUCER
        self.plan["imageReceiptSha256"] = trial.LEASE_PATCH_RECEIPT_SHA256
        self.plan["limits"].update(memoryBytes=16 << 30, minMemoryAvailableBytes=20 << 30,
                                   readBps=320 << 20, writeBps=128 << 20)
        self.select_continuation()
        group = "f8c55592-a39a-8e8c-87cd-40cb5ad53f22"
        self.intent["check"]["reconciliation"].update(
            artifactDisposition="completed-group-retained", recaptureBytes=0,
            artifacts=[self.artifact(
                path=str(self.dataset / ("state/db.sqlite.pre-startup-migration-" + group + ".bak")),
                classification="native-revalidation-required", disposition="retain",
                nativeDiscardOnRetry=False)])
        self.intent["check"]["backupReuse"] = {
            "schema": trial.BACKUP_REUSE,
            "originSourceSha": trial.HISTORICAL_IMAGE["sourceSha"],
            "originImageDigest": trial.HISTORICAL_IMAGE["indexDigest"],
            "originImageReceiptSha256": trial.HISTORICAL_IMAGE_RECEIPT_SHA256,
            "targetSourceSha": trial.LEASE_PATCH_IMAGE["sourceSha"],
            "targetImageReceiptSha256": trial.LEASE_PATCH_RECEIPT_SHA256,
            "backupId": group, "manifestSha256": "a" * 64, "backupCount": 1}
        trial.validate(self.plan, self.image, self.clean, self.intent["check"])
        with self.prior_boundaries("doctor", "failed", lease_patch_candidate=True) as (
                prior, result, actual, observe, policy):
            self.intent["check"]["doctorOperationId"] = trial.LEASE_PATCH_PRIOR
            proof = trial.phase_prerequisites(self.op, self.intent)
            self.assertEqual(proof["priorImageReceiptSha256"],
                             trial.LEASE_PATCH_PRIOR_IMAGE_RECEIPT_SHA256)
            self.assertEqual(proof["successorImageReceiptSha256"],
                             trial.LEASE_PATCH_RECEIPT_SHA256)
            self.assertEqual(proof["priorResourceProfile"]["id"], "memory16-read256-write64")
            for owner, key, changed in (
                (self.intent["check"], "doctorOperationId", "b" * 32),
                (self.intent["check"]["backupReuse"], "backupId", "a" * 36),
                (self.intent["check"]["backupReuse"], "manifestSha256", "b" * 64),
                (self.intent["check"]["backupReuse"], "backupCount", 2),
                (prior["check"]["backupReuse"], "targetSourceSha", "d" * 40),
                (prior["plan"], "toolingSha", "e" * 40),
                (prior["image"], "indexDigest", "sha256:" + "f" * 64),
            ):
                original = owner[key]
                owner[key] = changed
                with self.subTest(key=key), self.assertRaisesRegex(
                        release.Refusal, "trial.prior.startup_binding"):
                    trial.phase_prerequisites(self.op, self.intent)
                owner[key] = original
            self.plan["limits"].update(readBps=256 << 20, writeBps=64 << 20)
            with self.assertRaisesRegex(release.Refusal, "trial.prior.startup_binding"):
                trial.phase_prerequisites(self.op, self.intent)
            self.plan["limits"].update(readBps=320 << 20, writeBps=128 << 20)
            actual["State"]["Running"] = True
            with self.assertRaisesRegex(release.Refusal, "trial.prior.container_changed"):
                trial.phase_prerequisites(self.op, self.intent)
        self.assertEqual(trial.RETAINED_HELPERS[trial.LEASE_PATCH_PRIOR_PIPELINE_SHA],
                         "bedac832d1ab2f95b9c813e95db9e41d548c2c25f381f723699dce470281a47d")

    def test_later_continuation_keeps_exact_backup_reuse_proof(self):
        self.select_continuation()
        group = "f8c55592-a39a-8e8c-87cd-40cb5ad53f22"
        self.intent["check"]["reconciliation"].update(
            artifactDisposition="completed-group-retained", recaptureBytes=0,
            artifacts=[self.artifact(
                path=str(self.dataset / ("state/db.sqlite.pre-startup-migration-" + group + ".bak")),
                classification="native-revalidation-required", disposition="retain",
                nativeDiscardOnRetry=False)])
        self.intent["check"]["backupReuse"] = {
            "schema": trial.BACKUP_REUSE,
            "originSourceSha": trial.HISTORICAL_IMAGE["sourceSha"],
            "originImageDigest": trial.HISTORICAL_IMAGE["indexDigest"],
            "originImageReceiptSha256": trial.HISTORICAL_IMAGE_RECEIPT_SHA256,
            "targetSourceSha": self.image["sourceSha"],
            "targetImageReceiptSha256": self.plan["imageReceiptSha256"],
            "backupId": group, "manifestSha256": "a" * 64, "backupCount": 1}
        with self.prior_boundaries("doctor", "failed") as (prior, *_):
            self.intent["check"]["backupReuse"] = copy.deepcopy(prior["check"]["backupReuse"])
            proof = trial.phase_prerequisites(self.op, self.intent)
            self.assertEqual(proof["backupReuseSha256"],
                             trial.digest(trial.durable.encode(self.intent["check"]["backupReuse"])))
            retained = self.intent["check"].pop("backupReuse")
            with self.assertRaisesRegex(release.Refusal, "trial.prior.startup_binding"):
                trial.phase_prerequisites(self.op, self.intent)
            self.intent["check"]["backupReuse"] = {**retained, "manifestSha256": "b" * 64}
            with self.assertRaisesRegex(release.Refusal, "trial.prior.startup_binding"):
                trial.phase_prerequisites(self.op, self.intent)

    def test_continuation_refuses_completed_predecessor_use_startup_instead(self):
        with self.prior_boundaries("doctor", "succeeded"):
            with self.assertRaisesRegex(release.Refusal, "trial.prior.not_settled"):
                trial.phase_prerequisites(self.op, self.intent)

    def test_a9_continuation_validates_old_parent_path_without_inventing_old_device_receipt(self):
        with self.prior_boundaries("doctor", "failed") as (prior, result, actual, observe, policy):
            prior["plan"]["toolingSha"] = trial.LEGACY_DEVICE_SHA
            old = self.root / ("b" * 32) / "start-intent.json"
            start_record = trial.durable.read_private(old)
            del start_record["devices"]
            old.write_bytes(trial.durable.encode(start_record))
            trial.phase_prerequisites(self.op, self.intent)
            self.assertEqual(policy.call_args.args[-1], {"ioPath": prior["clean"]["devicePath"]})
            with patch.object(trial, "block_devices", return_value={**self.devices, "ioMajorMinor": "8:32"}):
                with self.assertRaisesRegex(release.Refusal, "trial.prior.legacy_parent_changed"):
                    trial.phase_prerequisites(self.op, self.intent)

    def test_startup_resolves_private_doctor_and_fresh_container_not_embedded_result(self):
        with self.prior_boundaries() as (prior, result, actual, observe, policy):
            self.plan["cleanInputSha256"] = "0" * 64  # post-Doctor config receipt may change
            proof = trial.phase_prerequisites(self.op, self.intent)
            self.assertEqual(proof["operationId"], "b" * 32)
            policy.assert_called_once()
            actual["State"]["StartedAt"] = "another-start"
            with self.assertRaisesRegex(release.Refusal, "trial.prior.container_changed"):
                trial.phase_prerequisites(self.op, self.intent)
            actual["State"]["StartedAt"] = "start"
            observe.return_value = {"state": "unknown", "result": result}
            with self.assertRaisesRegex(release.Refusal, "trial.prior.not_settled"):
                trial.phase_prerequisites(self.op, self.intent)

    def test_startup_rejects_failed_doctor_and_changed_mount_identity(self):
        with self.prior_boundaries(doctor_state="failed"):
            with self.assertRaisesRegex(release.Refusal, "trial.prior.not_settled"):
                trial.phase_prerequisites(self.op, self.intent)

    def test_startup_rejects_wrong_result_or_remounted_dataset(self):
        with self.prior_boundaries():
            original = self.intent["check"]["doctorResultSha256"]
            self.intent["check"]["doctorResultSha256"] = "0" * 64
            with self.assertRaisesRegex(release.Refusal, "trial.prior.result_hash"):
                trial.phase_prerequisites(self.op, self.intent)
            self.intent["check"]["doctorResultSha256"] = original
            with patch.object(trial, "snapshot_paths", return_value={"replacement": {}}):
                with self.assertRaisesRegex(release.Refusal, "trial.prior.startup_mount_changed"):
                    trial.phase_prerequisites(self.op, self.intent)

    def test_rollback_accepts_settled_failure_and_reused_device_but_not_old_generation(self):
        with self.prior_boundaries("rollback", "failed") as (prior, result, actual, observe, policy):
            self.assertEqual(self.clean["filesystemDevice"], prior["clean"]["filesystemDevice"])
            trial.phase_prerequisites(self.op, self.intent)
            self.clean["restoreReceiptSha256"] = prior["clean"]["restoreReceiptSha256"]
            with self.assertRaisesRegex(release.Refusal, "trial.prior.rollback_not_fresh"):
                trial.phase_prerequisites(self.op, self.intent)
            self.clean["restoreReceiptSha256"] = "0" * 64
            self.clean["mounts"][0]["source"] = prior["clean"]["mounts"][0]["source"]
            with self.assertRaisesRegex(release.Refusal, "trial.prior.rollback_not_fresh"):
                trial.phase_prerequisites(self.op, self.intent)

    def test_prior_stopped_container_validation_uses_retained_devices_after_detach(self):
        with self.prior_boundaries("rollback", "failed") as (_, _, _, _, policy), \
             patch.object(trial, "block_devices", side_effect=AssertionError("prior device has been detached")):
            trial.phase_prerequisites(self.op, self.intent)
            self.assertEqual(policy.call_args.args[-1], self.devices)

    def test_rollback_accepts_authoritative_no_create_failure_without_inspecting_null_cid(self):
        with self.prior_boundaries("rollback", "failed", no_create=True), \
             patch.object(trial, "inspect_container") as inspect:
            proof = trial.phase_prerequisites(self.op, self.intent)
            self.assertIsNone(proof["containerId"])
            self.assertIsNone(proof["startedAt"])
            inspect.assert_not_called()
            trial.durable.write_once(self.root / ("b" * 32) / "create-intent.json", b"{}\n")
            with self.assertRaisesRegex(release.Refusal, "workload.no_create.dispatch_uncertain"):
                trial.phase_prerequisites(self.op, self.intent)

    def test_startup_still_requires_success_after_proven_no_create_doctor_failure(self):
        with self.prior_boundaries("startup", "failed", no_create=True):
            with self.assertRaisesRegex(release.Refusal, "trial.prior.not_settled"):
                trial.phase_prerequisites(self.op, self.intent)

    def continued_phase_proof(self, selected, state):
        with self.prior_boundaries(selected, state) as (prior, result, actual, observe, policy):
            prior["clean"]["restorationState"] = "doctor-interrupted"
            ancestor = {"operationId": "c" * 32, "intentSha256": "d" * 64, "resultSha256": "e" * 64}
            result["continuedFrom"] = ancestor
            raw = trial.durable.encode(result)
            (self.root / ("b" * 32) / "result.json").write_bytes(raw)
            self.intent["check"]["doctorResultSha256"] = trial.digest(raw)
            proof = trial.phase_prerequisites(self.op, self.intent)
            self.assertEqual(proof["continuedFrom"], ancestor)

    def test_startup_keeps_successful_continued_doctor_provenance(self):
        self.continued_phase_proof("startup", "succeeded")

    def test_rollback_keeps_failed_continued_doctor_provenance(self):
        self.continued_phase_proof("rollback", "failed")

    def test_overlapping_or_external_mounts_refused(self):
        for source in (str(self.root / "production"), self.clean["mounts"][0]["source"] + "/child"):
            clean = copy.deepcopy(self.clean)
            clean["mounts"][1]["source"] = source
            with self.assertRaises(release.Refusal):
                trial.validate(self.plan, self.image, clean)

    def readonly_layout(self):
        clean = copy.deepcopy(self.clean)
        clean["mounts"] = [
            {"source": str(self.dataset / "ro-worktrees"), "readOnly": True,
             "target": trial.STATE_TARGET + "/workspace-franck/.openclaw/tmp/worktrees"},
            {"source": str(self.dataset / "ro-toolkit"), "readOnly": True,
             "target": trial.STATE_TARGET + "/workspace-franck/repos/agent-toolkit"},
            *clean["mounts"],
        ]
        return clean


    def direct_clone_layout(self):
        clean = self.readonly_layout()
        state = next(m for m in clean["mounts"] if m["target"] == trial.STATE_TARGET)
        for mount in clean["mounts"][:2]:
            relative = Path(mount["target"]).relative_to(state["target"])
            mount["source"] = str(Path(state["source"]) / relative)
        return clean

    def exact_owner_layout(self):
        clean = copy.deepcopy(self.clean)
        for suffix in ("repos", "workspace/.git", "workspace-automation/.git"):
            clean["mounts"].append({"source": str(self.dataset / "state" / suffix),
                                    "target": trial.STATE_TARGET + "/" + suffix, "readOnly": True})
        return clean

    def test_exact_repos_and_workspace_git_overlays_require_matching_relative_readonly_paths(self):
        clean = self.exact_owner_layout()
        trial.validate(self.plan, self.image, clean)
        for index in range(3, 6):
            for key, value in (("readOnly", False), ("source", clean["mounts"][index]["source"] + "-other")):
                with self.subTest(index=index, key=key):
                    changed = copy.deepcopy(clean)
                    changed["mounts"][index][key] = value
                    with self.assertRaises(release.Refusal):
                        trial.validate(self.plan, self.image, changed)

    def owner_metadata_fixture(self):
        self.clean = self.exact_owner_layout()
        self.clean["filesystemDevice"] = self.dataset.stat().st_dev
        directories = {}
        for mount in self.clean["mounts"]:
            source = Path(mount["source"])
            source.mkdir(parents=True, exist_ok=True)
            current = source
            while True:
                info = current.stat()
                directories[str(current)] = {"device": info.st_dev, "inode": info.st_ino,
                                             "mode": info.st_mode, "uid": info.st_uid}
                if current == self.dataset:
                    break
                current = current.parent
        return {"schema": "openclaw.snapshot-owner-metadata.v1", "uid": 1000,
                "directories": directories, "configSha256": self.clean["configSha256"]}

    def test_data_owner_probe_fixed_command_stdin_and_no_controller_state_reads(self):
        metadata = self.owner_metadata_fixture()
        original_stat = Path.stat
        def private_stat(file, *args, **kwargs):
            if self.dataset / "state" in (file, *file.parents):
                raise PermissionError("controller cannot inspect private state")
            return original_stat(file, *args, **kwargs)
        response = subprocess.CompletedProcess([], 0, json.dumps(metadata).encode(), b"")
        for uid in (328620973, 1000):
            with self.subTest(uid=uid), patch.object(trial.os, "geteuid", return_value=uid), \
                 patch.object(trial.subprocess, "run", return_value=response) as run, \
                 patch.object(Path, "stat", private_stat), \
                 patch.object(Path, "read_bytes", side_effect=AssertionError("controller config read forbidden")):
                trial.validate(self.plan, self.image, self.clean)
                observed = trial.data_owner_metadata(self.clean)
                self.assertEqual(len(trial.source_identities(self.clean, observed)), 6)
                args = run.call_args.args[0]
                prefix = [] if uid == 1000 else ["/usr/bin/sudo", "-n", "-u", "frmeyer", "--"]
                self.assertEqual(args, [*prefix, "/usr/bin/python3", "-I", "-c", trial.DATA_OWNER_PROBE])
                request = json.loads(run.call_args.kwargs["input"])
                self.assertEqual(set(request), {"root", "sources", "config"})
                self.assertEqual(request["config"], str(self.dataset / "state/openclaw.json"))
                self.assertEqual(run.call_args.kwargs["timeout"], 30)
                self.assertEqual(run.call_args.kwargs["env"], trial.durable.SAFE_ENV)

    def test_owner_probe_rejects_wrong_identity_hash_paths_and_physical_alias(self):
        metadata = self.owner_metadata_fixture()
        changed_root = copy.deepcopy(metadata)
        changed_root["directories"][str(self.dataset)]["inode"] += 1
        wrong_paths = copy.deepcopy(metadata)
        wrong_paths["directories"]["/unexpected"] = wrong_paths["directories"][str(self.dataset)]
        for changed in ({**metadata, "uid": 0}, {**metadata, "configSha256": "0" * 64}, changed_root, wrong_paths):
            with self.subTest(value=changed), patch.object(trial.subprocess, "run", return_value=
                    subprocess.CompletedProcess([], 0, json.dumps(changed).encode(), b"")):
                with self.assertRaises(release.Refusal):
                    trial.data_owner_metadata(self.clean)
        changed = copy.deepcopy(metadata["directories"])
        changed[str(self.dataset / "tmp")] = changed[str(self.dataset / "state")]
        with self.assertRaisesRegex(release.Refusal, "trial.mount.physical_alias"):
            trial.source_identities(self.clean, changed)

    @contextmanager
    def block_device_fixture(self, whole_receipt=False):
        self.clean.update(devicePath="/dev/disk/by-id/google-synthetic" + ("" if whole_receipt else "-part1"),
                          deviceMajorMinor="8:16" if whole_receipt else "8:17", filesystemDevice=os.makedev(8, 17))
        fs = Path(self.devices["filesystemSysfs"])
        io = Path(self.devices["ioSysfs"])
        observed = {
            "links": {self.clean["devicePath"]: Path("/dev/sdb" if whole_receipt else "/dev/sdb1"),
                      "/sys/dev/block/8:17": fs, "/sys/dev/block/8:16": io},
            "files": {str(fs / "partition"): "1\n", str(fs / "dev"): "8:17\n", str(io / "dev"): "8:16\n",
                      str(fs / "uevent"): "MAJOR=8\nMINOR=17\nDEVNAME=sdb1\nDEVTYPE=partition\n",
                      str(io / "uevent"): "MAJOR=8\nMINOR=16\nDEVNAME=sdb\nDEVTYPE=disk\n"},
            "nodes": {"/dev/sdb1": os.makedev(8, 17), "/dev/sdb": os.makedev(8, 16)},
            "modes": {},
        }
        original_resolve, original_stat, original_read, original_exists = Path.resolve, Path.stat, Path.read_text, Path.exists
        def resolve(file, *args, **kwargs):
            if str(file) in observed["links"]:
                return observed["links"][str(file)]
            if str(file) in observed["nodes"] or str(file).startswith("/sys/devices/synthetic/"):
                return file
            return original_resolve(file, *args, **kwargs)
        def observed_stat(file, *args, **kwargs):
            if str(file) in observed["nodes"]:
                return SimpleNamespace(st_mode=observed["modes"].get(str(file), stat.S_IFBLK), st_rdev=observed["nodes"][str(file)])
            if file in (fs, io):
                return SimpleNamespace(st_mode=stat.S_IFDIR)
            if str(file) in observed["files"]:
                return SimpleNamespace(st_mode=stat.S_IFREG)
            if file == self.dataset:
                return SimpleNamespace(st_mode=stat.S_IFDIR, st_dev=os.makedev(8, 17))
            if file == Path("/"):
                return SimpleNamespace(st_mode=stat.S_IFDIR, st_dev=os.makedev(8, 1))
            return original_stat(file, *args, **kwargs)
        def read(file, *args, **kwargs):
            return observed["files"][str(file)] if str(file) in observed["files"] else original_read(file, *args, **kwargs)
        def exists(file):
            if str(file).startswith("/sys/devices/synthetic/"):
                return str(file) in observed["files"] or file in (fs, io)
            return original_exists(file)
        with patch.object(Path, "resolve", resolve), patch.object(Path, "stat", observed_stat), \
             patch.object(Path, "read_text", read), patch.object(Path, "exists", exists), \
             patch.object(Path, "is_mount", return_value=True):
            yield observed

    def test_partition_receipt_maps_filesystem_to_verified_whole_disk_for_io(self):
        with self.block_device_fixture():
            trial.validate(self.plan, self.image, self.clean)
            devices = trial.block_devices(self.clean)
            self.assertEqual(devices, {**self.devices, "devicePath": "/dev/sdb1", "deviceMajorMinor": "8:17"})
            args = trial.create_argv(self.op, self.intent, devices)
            self.assertEqual(args[args.index("--device-read-bps") + 1], "/dev/sdb:134217728")
            self.assertEqual(args[args.index("--device-write-bps") + 1], "/dev/sdb:33554432")
            with patch.object(trial, "data_owner_metadata", return_value={}) as probe, \
                 patch.object(trial, "source_identities", return_value={"safe": {}}):
                self.assertEqual(trial.snapshot_paths(self.clean), {"safe": {}})
                probe.assert_called_once_with(self.clean)

    def test_whole_disk_receipt_accepts_its_mounted_partition(self):
        with self.block_device_fixture(whole_receipt=True):
            self.assertEqual(trial.block_devices(self.clean), self.devices)

    def test_block_mapping_rejects_partition_parent_bad_sysfs_node_and_receipt(self):
        changes = (
            ("files", self.devices["ioSysfs"] + "/partition", "1\n"),
            ("files", self.devices["ioSysfs"] + "/dev", "8:17\n"),
            ("files", self.devices["ioSysfs"] + "/dev", "ambiguous\n"),
            ("links", "/sys/dev/block/8:16", Path("/sys/devices/synthetic/block/other")),
            ("nodes", "/dev/sdb", os.makedev(8, 32)),
            ("nodes", "/dev/sdb1", os.makedev(8, 18)),
            ("modes", "/dev/sdb", stat.S_IFREG),
        )
        for section, key, value in changes:
            with self.subTest(section=section, key=key), self.block_device_fixture() as observed:
                observed[section][key] = value
                with self.assertRaises((release.Refusal, OSError)):
                    trial.block_devices(self.clean)
        with self.block_device_fixture():
            self.clean["deviceMajorMinor"] = "8:32"
            with self.assertRaises(release.Refusal):
                trial.block_devices(self.clean)
        with self.block_device_fixture() as observed:
            del observed["nodes"]["/dev/sdb"]
            with self.assertRaises((release.Refusal, OSError)):
                trial.block_devices(self.clean)

    def test_unrelated_valid_receipt_disk_cannot_throttle_mounted_filesystem(self):
        with self.block_device_fixture() as observed:
            self.clean["deviceMajorMinor"] = "8:32"
            unrelated = Path("/sys/devices/synthetic/block/sdc")
            observed["links"][self.clean["devicePath"]] = Path("/dev/sdc")
            observed["links"]["/sys/dev/block/8:32"] = unrelated
            observed["nodes"]["/dev/sdc"] = os.makedev(8, 32)
            observed["files"][str(unrelated / "dev")] = "8:32\n"
            original_stat = Path.stat
            def stat_unrelated(file, *args, **kwargs):
                return SimpleNamespace(st_mode=stat.S_IFDIR) if file == unrelated else original_stat(file, *args, **kwargs)
            with patch.object(Path, "stat", stat_unrelated):
                with self.assertRaisesRegex(release.Refusal, "trial.dataset.device_parent"):
                    trial.block_devices(self.clean)

    @unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 1000, "native probe fixture requires Linux UID1000")
    def test_native_data_owner_probe_private_directory_and_config_hash_only(self):
        self.owner_metadata_fixture()
        state = self.dataset / "state"
        state.chmod(0o700)
        config = state / "openclaw.json"
        payload = b'{"fixture":"private-config-body-must-not-appear"}\n'
        config.write_bytes(payload)
        config.chmod(0o600)
        self.clean["configSha256"] = trial.digest(payload)
        before = config.stat()
        result = trial.data_owner_metadata(self.clean)
        self.assertEqual(result[str(state)]["uid"], 1000)
        self.assertNotIn(payload.decode().strip(), json.dumps(result))
        self.assertEqual((before.st_ino, before.st_mode, before.st_mtime_ns),
                         (config.stat().st_ino, config.stat().st_mode, config.stat().st_mtime_ns))
        config.unlink()
        config.symlink_to(self.dataset / "tmp/other-config.json")
        (self.dataset / "tmp/other-config.json").write_bytes(payload)
        with self.assertRaisesRegex(release.Refusal, "trial.owner_probe.failed"):
            trial.data_owner_metadata(self.clean)

    def test_direct_clone_ro_sources_cover_only_their_matching_rw_parent_path(self):
        clean = self.direct_clone_layout()
        clean["filesystemDevice"] = self.dataset.stat().st_dev
        for mount in clean["mounts"]:
            Path(mount["source"]).mkdir(parents=True, exist_ok=True)
        for mounts in (clean["mounts"], list(reversed(clean["mounts"]))):
            with self.subTest(order=[m["target"] for m in mounts]):
                ordered = {**clean, "mounts": mounts}
                trial.validate(self.plan, self.image, ordered)
                with patch.object(Path, "iterdir", side_effect=AssertionError("tree walk forbidden")):
                    self.assertEqual(len(trial.source_identities(ordered)), len(mounts))
                args = trial.create_argv(self.op, {**self.intent, "clean": ordered}, self.devices)
                binds = [args[i + 1] for i, arg in enumerate(args) if arg == "--mount"]
                state = next(i for i, bind in enumerate(binds) if bind.endswith("dst=" + trial.STATE_TARGET))
                for mount in clean["mounts"][:2]:
                    child = f"type=bind,src={mount['source']},dst={mount['target']},readonly"
                    self.assertGreater(binds.index(child), state)

    def test_direct_clone_rejects_mismatched_paths_rw_child_duplicate_and_root_sources(self):
        original = self.direct_clone_layout()
        mutations = [
            (0, "source", str(self.dataset / "state/workspace-franck/another-project")),
            (0, "target", trial.STATE_TARGET + "/workspace-franck/another-project"),
            (0, "target", "/data/relocated-project"),
            (0, "readOnly", False),
            (0, "source", str(self.dataset)),
            (0, "source", str(self.dataset / "state")),
            (1, "source", original["mounts"][0]["source"]),
        ]
        for index, key, value in mutations:
            with self.subTest(index=index, key=key, value=value):
                clean = copy.deepcopy(original)
                clean["mounts"][index][key] = value
                with self.assertRaises(release.Refusal):
                    trial.validate(self.plan, self.image, clean)
        clean = copy.deepcopy(original)
        clean["mounts"].append({"source": clean["mounts"][0]["source"],
                                "target": "/data/writable-alias", "readOnly": False})
        with self.assertRaisesRegex(release.Refusal, "trial.mount.source_overlap"):
            trial.validate(self.plan, self.image, clean)

    def test_direct_clone_rejects_physical_rw_alias_and_duplicate_ro_alias(self):
        clean = self.direct_clone_layout()
        clean["filesystemDevice"] = self.dataset.stat().st_dev
        for mount in clean["mounts"]:
            Path(mount["source"]).mkdir(parents=True, exist_ok=True)
        alias = self.dataset / "writable-alias"
        alias.mkdir()
        original_stat = Path.stat
        project_info = original_stat(Path(clean["mounts"][0]["source"]))
        for alias_path in (alias, Path(clean["mounts"][1]["source"])):
            with self.subTest(alias=str(alias_path)):
                changed = copy.deepcopy(clean)
                if alias_path == alias:
                    changed["mounts"].append({"source": str(alias), "target": "/data/writable-alias", "readOnly": False})
                trial.validate(self.plan, self.image, changed)
                def stat_alias(file, *args, **kwargs):
                    return project_info if file == alias_path else original_stat(file, *args, **kwargs)
                with patch.object(Path, "stat", stat_alias), \
                     patch.object(Path, "iterdir", side_effect=AssertionError("tree walk forbidden")):
                    with self.assertRaisesRegex(release.Refusal, "trial.mount.physical_alias"):
                        trial.source_identities(changed)

    def test_direct_clone_rejects_physical_parent_identity_mismatch(self):
        clean = self.direct_clone_layout()
        clean["filesystemDevice"] = self.dataset.stat().st_dev
        for mount in clean["mounts"]:
            Path(mount["source"]).mkdir(parents=True, exist_ok=True)
        state_path = self.dataset / "state"
        original_stat = Path.stat
        replacement = original_stat(self.dataset / "tmp")
        calls = []
        def changed_parent(file, *args, **kwargs):
            if file == state_path:
                calls.append(file)
                if len(calls) > 2:
                    return replacement
            return original_stat(file, *args, **kwargs)
        with patch.object(Path, "stat", changed_parent):
            with self.assertRaisesRegex(release.Refusal, "trial.mount.physical_alias"):
                trial.source_identities(clean)

    def test_readonly_projects_override_writable_state_parent_first(self):
        clean = self.readonly_layout()
        trial.validate(self.plan, self.image, clean)
        args = trial.create_argv(self.op, {**self.intent, "clean": clean}, self.devices)
        binds = [args[i + 1] for i, arg in enumerate(args) if arg == "--mount"]
        state = next(i for i, bind in enumerate(binds) if bind.endswith("dst=" + trial.STATE_TARGET))
        for mount in clean["mounts"][:2]:
            bind = f"type=bind,src={mount['source']},dst={mount['target']},readonly"
            self.assertGreater(binds.index(bind), state)
        self.clean, self.intent["clean"] = clean, clean
        code, result, _ = self.exercise_serve()
        self.assertEqual(code, 0, result)

    def test_readonly_flags_and_required_writable_mounts_are_strict(self):
        for value in (None, 1, "false"):
            clean = copy.deepcopy(self.clean)
            clean["mounts"][0]["readOnly"] = value
            with self.assertRaisesRegex(release.Refusal, "trial.mount.read_only"):
                trial.validate(self.plan, self.image, clean)
        clean = copy.deepcopy(self.clean)
        del clean["mounts"][0]["readOnly"]
        with self.assertRaisesRegex(release.Refusal, "trial.mount.fields"):
            trial.validate(self.plan, self.image, clean)
        for index in range(3):
            clean = copy.deepcopy(self.clean)
            clean["mounts"][index]["readOnly"] = True
            with self.assertRaisesRegex(release.Refusal, "trial.mount.required_writable"):
                trial.validate(self.plan, self.image, clean)

    def test_nested_rw_duplicates_and_ro_parent_shadowing_are_refused(self):
        for parent_ro, child_ro in ((False, False), (True, False), (True, True)):
            clean = copy.deepcopy(self.clean)
            clean["mounts"] += [
                {"source": str(self.dataset / "parent"), "target": "/data/workspace", "readOnly": parent_ro},
                {"source": str(self.dataset / "project"), "target": "/data/workspace/project", "readOnly": child_ro},
            ]
            with self.assertRaisesRegex(release.Refusal, "trial.mount.nested_scope"):
                trial.validate(self.plan, self.image, clean)
        clean = copy.deepcopy(self.clean)
        clean["mounts"].append({"source": str(self.dataset / "other"), "target": trial.STATE_TARGET, "readOnly": False})
        with self.assertRaisesRegex(release.Refusal, "trial.mount.duplicate_target"):
            trial.validate(self.plan, self.image, clean)
        for target in (trial.STATE_TARGET + "/agents/private", trial.STATE_TARGET + "/workspace-franck"):
            clean = copy.deepcopy(self.clean)
            clean["mounts"].append({"source": str(self.dataset / "other"), "target": target, "readOnly": True})
            with self.assertRaisesRegex(release.Refusal, "trial.mount.target_scope"):
                trial.validate(self.plan, self.image, clean)

    def test_source_roots_and_ancestors_reject_physical_alias_without_tree_walk(self):
        clean = self.readonly_layout()
        clean["filesystemDevice"] = self.dataset.stat().st_dev
        for mount in clean["mounts"]:
            Path(mount["source"]).mkdir()
        with patch.object(Path, "iterdir", side_effect=AssertionError("tree walk forbidden")):
            self.assertEqual(len(trial.source_identities(clean)), 5)
        with self.assertRaisesRegex(release.Refusal, "trial.dataset.bind"):
            trial.source_identities({**clean, "filesystemDevice": clean["filesystemDevice"] + 1})
        original_stat = Path.stat
        state_info = original_stat(self.dataset / "state")
        alias_parent = self.dataset / "alias"
        alias_project = alias_parent / "project"
        alias_project.mkdir(parents=True)
        for alias in (alias_parent, alias_project):
            changed = copy.deepcopy(clean)
            changed["mounts"][0]["source"] = str(alias_project)
            def stat_alias(file, *args, **kwargs):
                return state_info if file == alias else original_stat(file, *args, **kwargs)
            with patch.object(Path, "stat", stat_alias), \
                 patch.object(Path, "iterdir", side_effect=AssertionError("tree walk forbidden")):
                with self.assertRaisesRegex(release.Refusal, "trial.mount.physical_alias"):
                    trial.source_identities(changed)
        link = self.dataset / "symlink-alias"
        link.symlink_to(self.dataset / "state", target_is_directory=True)
        changed = copy.deepcopy(clean)
        changed["mounts"][0]["source"] = str(link)
        trial.validate(self.plan, self.image, changed)  # physical checks run as data owner at admission
        with self.assertRaisesRegex(release.Refusal, "trial.path.noncanonical"):
            trial.source_identities(changed)

    def test_only_exact_qualified_image_and_historical_producer_are_admitted(self):
        for key, original in trial.QUALIFIED_IMAGE.items():
            image = copy.deepcopy(self.image)
            image[key] = original[:-1] + ("0" if original[-1] != "0" else "1")
            with self.assertRaises(release.Refusal, msg=key):
                trial.validate(self.plan, image, self.clean)
        image = copy.deepcopy(self.image)
        image["producer"]["toolingSha"] = self.plan["toolingSha"]
        with patch.object(trial, "docker") as docker:
            with self.assertRaisesRegex(release.Refusal, "trial.image.not_qualified"):
                trial.observe_image(image)
            docker.assert_not_called()

    def test_prepare_rejects_running_adapter_or_shared_helper_mismatch_before_writes(self):
        files = {name: file.read_bytes() for name, file in trial.RUNNING_HELPERS.items()}
        for changed in ("gcp_snapshot_trial.py", "gcp_build.py", "gcp_rehearsal_checks.py"):
            pinned = {**files, changed: files[changed] + b"\n# another revision\n"}
            with patch.object(trial, "private_json", side_effect=[(self.plan, "unused"),
                    (self.image, self.plan["imageReceiptSha256"]), (self.clean, self.plan["cleanInputSha256"])]), \
                 patch.object(trial.durable, "clean_checkout"), \
                 patch.object(trial.subprocess, "check_output", side_effect=[pinned[name] for name in trial.HELPERS]), \
                 patch.object(trial.release, "private_root") as root:
                with self.assertRaisesRegex(release.Refusal, "trial.running_helper.changed"):
                    trial.prepare("plan", "image", "clean", self.root)
                root.assert_not_called()

    def test_v2_prepare_rejects_check_hash_mismatch_before_writes(self):
        self.select_phase("startup")
        with patch.object(trial, "private_json", side_effect=[(self.plan, "unused"),
                (self.image, self.plan["imageReceiptSha256"]), (self.clean, self.plan["cleanInputSha256"]),
                (self.intent["check"], "0" * 64)]), patch.object(trial.release, "private_root") as root:
            with self.assertRaisesRegex(release.Refusal, "trial.check.input_hash"):
                trial.prepare("plan", "image", "clean", self.root, "check")
            root.assert_not_called()

    def test_v2_load_rechecks_frozen_check_bytes(self):
        self.select_phase("startup")
        (self.op / "supervisor").mkdir(mode=0o700)
        for name, file in trial.RUNNING_HELPERS.items():
            trial.durable.write_once(self.op / "supervisor" / name, file.read_bytes())
        for name, value, key in (("image-receipt.json", self.image, "imageReceiptSha256"),
                                 ("clean-input.json", self.clean, "cleanInputSha256"),
                                 ("check-input.json", self.intent["check"], "checkInputSha256")):
            raw = trial.durable.encode(value)
            trial.durable.write_once(self.op / name, raw)
            self.plan[key] = trial.digest(raw)
        self.intent.update({"ownerUid": os.getuid(), "ownerGid": os.getgid(),
                            "helpers": dict(trial.LOADED_HELPER_HASHES)})
        (self.op / "intent.json").write_bytes(trial.durable.encode(self.intent))
        with patch.object(trial, "PRIVATE_ROOT", self.root):
            self.assertEqual(trial.load(self.op)[1]["check"], self.intent["check"])
            (self.op / "check-input.json").write_bytes(b"{}\n")
            with self.assertRaisesRegex(release.Refusal, "trial.check.changed"):
                trial.load(self.op)

    def test_load_and_start_bind_executing_helpers_to_frozen_pinned_bytes(self):
        (self.op / "supervisor").mkdir(mode=0o700)
        for name, file in trial.RUNNING_HELPERS.items():
            trial.durable.write_once(self.op / "supervisor" / name, file.read_bytes())
        for name, value, key in (("image-receipt.json", self.image, "imageReceiptSha256"),
                                 ("clean-input.json", self.clean, "cleanInputSha256")):
            raw = trial.durable.encode(value)
            trial.durable.write_once(self.op / name, raw)
            self.plan[key] = trial.digest(raw)
        self.intent.update({"ownerUid": os.getuid(), "ownerGid": os.getgid(),
                            "helpers": dict(trial.LOADED_HELPER_HASHES)})
        (self.op / "intent.json").write_bytes(trial.durable.encode(self.intent))
        with patch.object(trial, "PRIVATE_ROOT", self.root), patch.object(trial.sys, "platform", "linux"):
            self.assertEqual(trial.load(self.op)[1]["helpers"], trial.LOADED_HELPER_HASHES)
            for name in ("gcp_snapshot_trial.py", "gcp_build.py", "gcp_rehearsal_checks.py"):
                with patch.dict(trial.LOADED_HELPER_HASHES, {name: "0" * 64}), \
                     patch.object(trial.durable, "reserve_heavy_workload") as reserve, \
                     patch.object(trial.subprocess, "run") as dispatch:
                    with self.assertRaisesRegex(release.Refusal, "trial.running_helper.changed"):
                        trial.start(self.op)
                    reserve.assert_not_called()
                    dispatch.assert_not_called()

    def test_historical_reader_pins_a9_manifest_without_admitting_its_execution(self):
        hashes = {
            "gcp_build.py": "54871a4d6b40b55eceb48c0a503052f1369b5a63585406554599e0312eca7f41",
            "gcp_rehearsal_checks.py": "e8e3b0a328715bf3b1dd783a81412f306fccf4aebec612719c4eec0dc44ccb28",
            "gcp_snapshot_trial.py": "6000ac10e70dbf07c495338d07fffe24c24cc340cfb040feb360479fedd69731",
            "pr.py": "351f2a1855959346e41a682a9a8a01bcef84b8fdbf3866b697ddd996502b6a3f",
            "preflight.py": "ea9ff84927b40e0808ffb83426264b267299ee1237908548439c136b8d306f2b",
            "release.py": "7bf6bf8b9d8885694f0bce3644f4cedc41c1ac99623c6460c81c0c6a3cc53f12"}
        self.intent["helpers"] = hashes
        self.plan["toolingSha"] = trial.LEGACY_DEVICE_SHA
        with patch.object(trial, "read_operation", return_value=(self.op, self.intent)):
            self.assertEqual(trial.read_retained(self.op)[1], self.intent)
            with self.assertRaisesRegex(release.Refusal, "trial.running_helper.changed"):
                trial.load(self.op)
            self.plan["toolingSha"] = "0" * 40
            with self.assertRaisesRegex(release.Refusal, "trial.prior.unreviewed_helpers"):
                trial.read_retained(self.op)
            self.plan["toolingSha"] = trial.LEGACY_DEVICE_SHA
            hashes["gcp_snapshot_trial.py"] = "0" * 64
            with self.assertRaisesRegex(release.Refusal, "trial.prior.unreviewed_helpers"):
                trial.read_retained(self.op)

    def test_stopped_16g_predecessor_manifest_is_readable_but_not_executable(self):
        hashes = {
            "gcp_build.py": "7aa4980c430fd7d3fd9e9c429517c5126487810b59033cce1e807472d77e93b6",
            "gcp_rehearsal_checks.py": "e8e3b0a328715bf3b1dd783a81412f306fccf4aebec612719c4eec0dc44ccb28",
            "gcp_snapshot_trial.py": "21c0f7d958a3872505ed620f2c94ce0b127033c16431c6929e6a84abc77dbb84",
            "pr.py": "351f2a1855959346e41a682a9a8a01bcef84b8fdbf3866b697ddd996502b6a3f",
            "preflight.py": "ea9ff84927b40e0808ffb83426264b267299ee1237908548439c136b8d306f2b",
            "release.py": "7bf6bf8b9d8885694f0bce3644f4cedc41c1ac99623c6460c81c0c6a3cc53f12",
        }
        self.assertEqual(trial.digest(json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode()),
                         trial.RETAINED_HELPERS["4ad784b4c78d7109c719c22d80c0e927a3299e11"])
        self.intent["helpers"] = hashes
        self.plan["toolingSha"] = "4ad784b4c78d7109c719c22d80c0e927a3299e11"
        with patch.object(trial, "read_operation", return_value=(self.op, self.intent)):
            self.assertEqual(trial.read_retained(self.op)[1], self.intent)
            with self.assertRaisesRegex(release.Refusal, "trial.running_helper.changed"):
                trial.load(self.op)
            hashes["gcp_snapshot_trial.py"] = "0" * 64
            with self.assertRaisesRegex(release.Refusal, "trial.prior.unreviewed_helpers"):
                trial.read_retained(self.op)

    def test_historical_private_files_and_terminal_status_without_executing_old_helpers(self):
        frozen = {name: ("# retained, never imported: " + name).encode() for name in trial.HELPERS}
        (self.op / "supervisor").mkdir(mode=0o700)
        for name, raw in frozen.items():
            trial.durable.write_once(self.op / "supervisor" / name, raw)
        self.intent.update(ownerUid=os.getuid(), ownerGid=os.getgid(),
                           helpers={name: trial.digest(raw) for name, raw in frozen.items()})
        for name, value, key in (("image-receipt.json", self.image, "imageReceiptSha256"),
                                 ("clean-input.json", self.clean, "cleanInputSha256")):
            raw = trial.durable.encode(value)
            trial.durable.write_once(self.op / name, raw)
            self.plan[key] = trial.digest(raw)
        manifest = trial.digest(json.dumps(self.intent["helpers"], sort_keys=True, separators=(",", ":")).encode())
        (self.op / "intent.json").write_bytes(trial.durable.encode(self.intent))
        invocation = "f" * 32
        records = {"start-intent.json": {}, "started.json": {"invocationId": invocation, "at": "2000-01-01T00:00:00Z"},
            "result.json": {"operationId": self.op.name, "invocationId": invocation, "state": "failed",
                "imageReceiptSha256": self.plan["imageReceiptSha256"], "cleanInputSha256": self.plan["cleanInputSha256"]}}
        for name, value in records.items():
            trial.durable.write_once(self.op / name, trial.durable.encode(value))
        service = {"LoadState": "loaded", "ActiveState": "failed", "SubState": "failed", "MainPID": "0",
            "Result": "exit-code", "ExecMainCode": "1", "ExecMainStatus": "1", "InvocationID": invocation}
        with patch.object(trial, "PRIVATE_ROOT", self.root), \
             patch.dict(trial.RETAINED_HELPERS, {self.plan["toolingSha"]: manifest}), \
             patch.object(trial, "native", side_effect=lambda *args: "\n".join(f"{k}={v}" for k, v in service.items()).encode()):
            self.assertEqual(trial.read_retained(self.op)[1], self.intent)
            self.assertEqual(trial.status(self.op, retained=True)["state"], "failed")
            service["InvocationID"] = "0" * 32
            self.assertEqual(trial.status(self.op, retained=True)["state"], "unknown")
            with self.assertRaisesRegex(release.Refusal, "trial.running_helper.changed"):
                trial.load(self.op)
            file = self.op / "supervisor/gcp_snapshot_trial.py"
            file.write_bytes(b"# changed")
            with self.assertRaisesRegex(release.Refusal, "trial.helper.changed"):
                trial.read_retained(self.op)

    def test_continuation_private_records_status_binds_terminal_result_to_prior_hashes(self):
        self.private_continuation_records()

    def test_qualified_4c57_records_remain_read_only_without_new_cleanup_attestation(self):
        self.private_continuation_records(legacy=True)

    def private_continuation_records(self, legacy=False):
        self.select_continuation()
        if legacy:
            self.plan["toolingSha"] = trial.LEGACY_CONTINUATION_SHA
            self.intent["check"]["reconciliation"] = {
                "observedAt": "2000-01-01T00:00:01Z", "artifactDisposition": "incomplete-survivors-preserved",
                "artifactReceiptSha256": "e" * 64, "preservedBytes": 23 << 30,
                "recaptureBytes": 47 << 30, "additionalReserveBytes": 8 << 30}
        (self.op / "supervisor").mkdir(mode=0o700)
        hashes = {}
        for name, file in trial.RUNNING_HELPERS.items():
            raw = ("# retained, never imported: " + name).encode() if legacy else file.read_bytes()
            trial.durable.write_once(self.op / "supervisor" / name, raw)
            hashes[name] = trial.digest(raw)
        for name, value, key in (("image-receipt.json", self.image, "imageReceiptSha256"),
                ("clean-input.json", self.clean, "cleanInputSha256"),
                ("check-input.json", self.intent["check"], "checkInputSha256")):
            raw = trial.durable.encode(value)
            trial.durable.write_once(self.op / name, raw)
            self.plan[key] = trial.digest(raw)
        self.intent.update(ownerUid=os.getuid(), ownerGid=os.getgid(), helpers=hashes)
        (self.op / "intent.json").write_bytes(trial.durable.encode(self.intent))
        prior = {"operationId": "b" * 32, "intentSha256": "c" * 64, "resultSha256": "d" * 64}
        result = {"operationId": self.op.name, "invocationId": "f" * 32, "state": "failed", "phase": "doctor",
            "continuedFrom": prior, **{k: self.plan[k] for k in ("imageReceiptSha256", "cleanInputSha256", "checkInputSha256")}}
        for name, value in (("start-intent.json", {"priorDoctor": prior}),
                ("started.json", {"invocationId": "f" * 32, "at": "2000-01-01T00:00:00Z"}), ("result.json", result)):
            trial.durable.write_once(self.op / name, trial.durable.encode(value))
        service = {"LoadState": "loaded", "ActiveState": "failed", "SubState": "failed", "MainPID": "0",
            "Result": "exit-code", "ExecMainCode": "1", "ExecMainStatus": "1", "InvocationID": "f" * 32}
        manifest = trial.digest(json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode())
        with ExitStack() as stack, patch.object(trial, "PRIVATE_ROOT", self.root), patch.object(trial, "native",
                return_value="\n".join(f"{k}={v}" for k, v in service.items()).encode()):
            if legacy:
                stack.enter_context(patch.dict(trial.RETAINED_HELPERS, {trial.LEGACY_CONTINUATION_SHA: manifest}))
            self.assertEqual(trial.read_retained(self.op)[1]["clean"]["restorationState"], "doctor-interrupted")
            self.assertEqual(trial.status(self.op, retained=True)["state"], "failed")
            if legacy:
                self.assertNotIn("artifactAccounting", trial.status(self.op, retained=True))
                with patch.object(trial.sys, "platform", "linux"), patch.object(trial.subprocess, "run") as dispatch:
                    with self.assertRaisesRegex(release.Refusal, "trial.continuation.reconciliation_fields"):
                        trial.load(self.op)
                    with self.assertRaises(release.Refusal):
                        trial.start(self.op)
                    dispatch.assert_not_called()
                with patch.dict(trial.RETAINED_HELPERS, {trial.LEGACY_CONTINUATION_SHA: "0" * 64}):
                    with self.assertRaisesRegex(release.Refusal, "trial.prior.unreviewed_helpers"):
                        trial.read_retained(self.op)
                wrong = copy.deepcopy(self.plan)
                wrong["toolingSha"] = "0" * 40
                with self.assertRaisesRegex(release.Refusal, "trial.continuation.reconciliation_fields"):
                    trial.validate(wrong, self.image, self.clean, self.intent["check"], retained=True)
            result["continuedFrom"] = {**prior, "resultSha256": "0" * 64}
            (self.op / "result.json").write_bytes(trial.durable.encode(result))
            self.assertEqual(trial.status(self.op, retained=True)["state"], "unknown")

    def test_dataset_writer_check_allows_disjoint_builder_cache(self):
        calls = []
        def fake(args, timeout=30):
            calls.append(args)
            if args[0] == "ps":
                return ("9" * 64 + "\n").encode()
            return json.dumps([{"Source": str(self.dataset / "build-cache"), "RW": True}]).encode()
        with patch.object(trial, "docker", side_effect=fake):
            trial.no_other_writer(self.clean)
        with patch.object(trial, "docker", side_effect=[("9" * 64).encode(),
                json.dumps([{"Source": self.clean["mounts"][0]["source"], "RW": True}]).encode()]):
            with self.assertRaises(release.Refusal):
                trial.no_other_writer(self.clean)

    def test_loaded_index_id_is_valid(self):
        image = {"Id": self.image["indexDigest"], "Os": "linux", "Architecture": "amd64",
                 "Config": {"Env": [], "Labels": {"org.opencontainers.image.revision": self.image["sourceSha"],
                     "org.opencontainers.image.version": "2026.10.5"}}}
        with patch.object(trial, "docker", return_value=json.dumps([image]).encode()):
            self.assertEqual(trial.observe_image(self.image)["loadedId"], self.image["indexDigest"])
        image["Id"] = "sha256:" + "0" * 64
        with patch.object(trial, "docker", return_value=json.dumps([image]).encode()):
            with self.assertRaises(release.Refusal):
                trial.observe_image(self.image)

    def test_fixed_native_command_and_isolation(self):
        args = trial.create_argv(self.op, self.intent, self.devices)
        self.assertEqual(args[-len(trial.DOCTOR):], trial.DOCTOR)
        self.assertEqual(args[args.index("--memory-swap") + 1], str(24 << 30))
        self.assertEqual(args[args.index("--network") + 1], "none")
        self.assertEqual(args[args.index("--user") + 1], "1000:1000")
        self.assertIn("--read-only", args)
        self.assertNotIn("--privileged", args)
        self.assertNotIn("--rm", args)
        gate = args[args.index("-e") + 1]
        self.assertEqual(args[args.index("--entrypoint") + 1], "/usr/bin/env")
        self.assertEqual(args[args.index("--entrypoint") + 3], "-i")
        self.assertNotIn("NODE_OPTIONS=", " ".join(args))
        self.assertIn("waitFor('settled', 71)", gate)
        self.assertIn("process.exitCode = code", gate)
        self.assertIn("'READY\\n'", gate)
        self.assertNotIn("sleep", gate)
        self.assertIn("/usr/bin/timeout", args)
        self.assertEqual(args[args.index("/usr/bin/timeout") + 1:][:3],
                         ["--signal=TERM", "--kill-after=30", "86400s"])
        service = trial.service_argv(self.op)
        self.assertEqual(service[service.index("--") + 1], trial.sys.executable)

    def test_uncertain_dispatch_is_never_reissued(self):
        recorded = []
        def write_once(path, raw):
            recorded.append(path.name)
            trial.durable.write_once_original(path, raw)
        with patch.object(trial, "load", return_value=(self.op, self.intent)), \
             patch.object(trial.sys, "platform", "linux"), \
             patch.object(trial, "snapshot_paths", return_value={}), \
             patch.object(trial, "block_devices", return_value=self.devices), \
             patch.object(trial, "no_other_writer"), \
             patch.object(trial, "observe_image", return_value={"loadedId": self.image["indexDigest"], "env": []}), \
             patch.object(trial, "capacity", return_value={"dataFreeBytes": 200 << 30}), \
             patch.object(trial.durable, "reserve_heavy_workload", side_effect=lambda *args, **kwargs:
                          kwargs.get("reserve_resource", lambda: None)()), \
             patch.object(trial.Path, "read_text", return_value="synthetic-boot"), \
             patch.object(trial, "status", return_value={"state": "unknown"}), \
             patch.object(trial.subprocess, "run", side_effect=subprocess.TimeoutExpired([], 30)) as dispatch, \
             patch.object(trial.durable, "write_once_original", trial.durable.write_once, create=True), \
             patch.object(trial.durable, "write_once", side_effect=write_once):
            self.assertEqual(trial.start(self.op), {"state": "unknown"})
            self.assertEqual(trial.start(self.op), {"state": "unknown"})
            self.assertEqual(dispatch.call_count, 1)
        self.assertLess(recorded.index("start-intent.json"), recorded.index("dispatch.json"))
        self.assertIsNone(json.loads((self.op / "dispatch.json").read_bytes())["returnCode"])

    @contextmanager
    def start_boundaries(self):
        def reserve_then_publish(*args, reserve_resource=None):
            if reserve_resource is not None:
                reserve_resource()
            (self.root / "global-owner.json").write_text(json.dumps({"operation": str(args[0])}))
        with patch.object(trial, "load", return_value=(self.op, self.intent)), \
             patch.object(trial.sys, "platform", "linux"), \
             patch.object(trial, "snapshot_paths", return_value={}), \
             patch.object(trial, "block_devices", return_value=self.devices), \
             patch.object(trial, "no_other_writer"), \
             patch.object(trial, "observe_image", return_value={"loadedId": self.image["indexDigest"], "env": []}), \
             patch.object(trial, "capacity", return_value={"dataFreeBytes": 200 << 30}), \
             patch.object(trial.durable, "reserve_heavy_workload", side_effect=reserve_then_publish) as reserve, \
             patch.object(trial.Path, "read_text", return_value="synthetic-boot"), \
             patch.object(trial, "status", return_value={"state": "unknown"}), \
             patch.object(trial.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as dispatch:
            yield reserve, dispatch

    def test_dataset_conflict_never_claims_global_workload(self):
        lease = self.op.parent / ("dataset-" + trial.digest(self.clean["mountRoot"].encode()) + ".json")
        intent_hash = trial.digest((self.op / "intent.json").read_bytes())
        for conflict in ({"operationId": "b" * 32, "intentSha256": intent_hash},
                         {"operationId": self.op.name, "intentSha256": "c" * 64}):
            with self.subTest(conflict=conflict):
                original = trial.durable.encode(conflict)
                lease.write_bytes(original)
                lease.chmod(0o600)
                with self.start_boundaries() as (reserve, dispatch):
                    with self.assertRaisesRegex(release.Refusal, "trial.dataset.reserved"):
                        trial.start(self.op)
                    self.assertFalse((self.root / "global-owner.json").exists())
                    dispatch.assert_not_called()
                self.assertEqual(lease.read_bytes(), original)
                self.assertFalse((self.op / "start-intent.json").exists())

    def test_exact_predispatch_reservation_resumes_once_after_interruption(self):
        write_once = trial.durable.write_once
        def interrupted_write(file, raw):
            if file.name == "start-intent.json":
                raise OSError("synthetic interruption before dispatch intent")
            write_once(file, raw)

        lease = self.op.parent / ("dataset-" + trial.digest(self.clean["mountRoot"].encode()) + ".json")
        with self.start_boundaries() as (reserve, dispatch):
            with patch.object(trial.durable, "write_once", side_effect=interrupted_write):
                with self.assertRaisesRegex(OSError, "synthetic interruption"):
                    trial.start(self.op)
            dispatch.assert_not_called()
            self.assertFalse((self.op / "start-intent.json").exists())
            retained_bytes, retained_inode = lease.read_bytes(), lease.stat().st_ino
            self.assertEqual(trial.start(self.op), {"state": "unknown"})
            self.assertEqual(trial.start(self.op), {"state": "unknown"})
            self.assertEqual(reserve.call_count, 2)
            dispatch.assert_called_once()
        self.assertEqual(lease.read_bytes(), retained_bytes)
        self.assertEqual(lease.stat().st_ino, retained_inode)
        retained = trial.durable.read_private(self.op / "start-intent.json")
        self.assertEqual(retained["devices"], self.devices)

    def test_startup_transfers_only_exact_prior_dataset_lease_and_resumes_once(self):
        self.select_phase("startup")
        prior = {"operationId": "b" * 32, "intentSha256": "c" * 64}
        lease = self.root / ("dataset-" + trial.digest(self.clean["mountRoot"].encode()) + ".json")
        trial.durable.write_once(lease, trial.durable.encode(prior))
        write_once = trial.durable.write_once
        def interrupt(file, raw):
            if file.name == "start-intent.json":
                raise OSError("synthetic pre-dispatch interruption")
            write_once(file, raw)
        with self.start_boundaries() as (_, dispatch), \
             patch.object(trial, "phase_prerequisites", return_value=prior):
            with patch.object(trial.durable, "write_once", side_effect=interrupt):
                with self.assertRaises(OSError):
                    trial.start(self.op)
            dispatch.assert_not_called()
            self.assertEqual(trial.durable.read_private(self.op / "dataset-previous.json"), prior)
            self.assertEqual(trial.durable.read_private(lease)["operationId"], self.op.name)
            trial.start(self.op)
            trial.start(self.op)
            dispatch.assert_called_once()

    def test_startup_conflicting_dataset_lease_refused_before_global_claim(self):
        self.select_phase("startup")
        lease = self.root / ("dataset-" + trial.digest(self.clean["mountRoot"].encode()) + ".json")
        trial.durable.write_once(lease, trial.durable.encode({"operationId": "c" * 32, "intentSha256": "d" * 64}))
        with self.start_boundaries() as (_, dispatch), \
             patch.object(trial, "phase_prerequisites", return_value={"operationId": "b" * 32, "intentSha256": "c" * 64}):
            with self.assertRaisesRegex(release.Refusal, "trial.dataset.reserved"):
                trial.start(self.op)
            self.assertFalse((self.root / "global-owner.json").exists())
            dispatch.assert_not_called()

    def test_continuation_exact_transfer_preserves_raw_lease_and_recovers_before_dispatch(self):
        self.select_continuation()
        prior = {"operationId": "b" * 32, "intentSha256": "c" * 64, "resultSha256": "d" * 64}
        lease = self.root / ("dataset-" + trial.digest(self.clean["mountRoot"].encode()) + ".json")
        original = ('{ "intentSha256" : "' + "c" * 64 + '", "operationId" : "' + "b" * 32 + '" }\n').encode()
        trial.durable.write_once(lease, original)
        write_once = trial.durable.write_once
        def interrupt(file, raw):
            if file.name == "start-intent.json":
                raise OSError("synthetic pre-dispatch interruption")
            write_once(file, raw)
        with self.start_boundaries() as (_, dispatch), patch.object(trial, "phase_prerequisites", return_value=prior):
            with patch.object(trial.durable, "write_once", side_effect=interrupt):
                with self.assertRaises(OSError):
                    trial.start(self.op)
            dispatch.assert_not_called()
            self.assertEqual((self.op / "dataset-previous.json").read_bytes(), original)
            trial.verify_continuation_claim(self.op, self.intent, prior)
            trial.start(self.op)
            trial.start(self.op)
            dispatch.assert_called_once()

    def test_continuation_renamed_lease_retry_resyncs_claims_before_dispatch(self):
        self.select_continuation()
        prior = {"operationId": "b" * 32, "intentSha256": "c" * 64, "resultSha256": "d" * 64}
        lease = self.root / ("dataset-" + trial.digest(self.clean["mountRoot"].encode()) + ".json")
        trial.durable.write_once(lease, trial.durable.encode({key: prior[key]
                                                              for key in ("operationId", "intentSha256")}))
        atomic = release.atomic_json
        def renamed_without_directory_sync(file, value):
            atomic(file, value)
            raise OSError("synthetic post-rename interruption")
        with self.start_boundaries() as (_, dispatch), patch.object(trial, "phase_prerequisites", return_value=prior):
            with patch.object(release, "atomic_json", side_effect=renamed_without_directory_sync):
                with self.assertRaisesRegex(OSError, "post-rename interruption"):
                    trial.start(self.op)
            self.assertEqual(trial.durable.read_private(lease)["operationId"], self.op.name)
            self.assertFalse((self.op / "start-intent.json").exists())
            dispatch.assert_not_called()
            with patch.object(trial.durable, "sync_directory", side_effect=OSError("synthetic sync failure")):
                with self.assertRaisesRegex(OSError, "synthetic sync failure"):
                    trial.start(self.op)
            dispatch.assert_not_called()
            with patch.object(trial.durable, "sync_directory", wraps=trial.durable.sync_directory) as sync:
                trial.start(self.op)
                self.assertEqual([call.args[0] for call in sync.call_args_list[:3]],
                                 [self.op, self.op, self.root])
            trial.start(self.op)
            dispatch.assert_called_once()

    def test_continuation_existing_transfer_is_synced_before_lease_replacement(self):
        self.select_continuation()
        prior = {"operationId": "b" * 32, "intentSha256": "c" * 64, "resultSha256": "d" * 64}
        lease = self.root / ("dataset-" + trial.digest(self.clean["mountRoot"].encode()) + ".json")
        original = trial.durable.encode({key: prior[key] for key in ("operationId", "intentSha256")})
        trial.durable.write_once(lease, original)
        with self.start_boundaries() as (_, dispatch), patch.object(trial, "phase_prerequisites", return_value=prior):
            with patch.object(release, "atomic_json", side_effect=OSError("synthetic before-rename interruption")):
                with self.assertRaisesRegex(OSError, "before-rename interruption"):
                    trial.start(self.op)
            self.assertEqual(lease.read_bytes(), original)
            self.assertTrue((self.op / "dataset-transfer.json").exists())
            dispatch.assert_not_called()
            with patch.object(trial, "sync_private_claim", side_effect=OSError("synthetic receipt sync failure")):
                with self.assertRaisesRegex(OSError, "receipt sync failure"):
                    trial.start(self.op)
            self.assertEqual(lease.read_bytes(), original)
            dispatch.assert_not_called()
            trial.start(self.op)
            self.assertEqual(trial.durable.read_private(lease)["operationId"], self.op.name)
            dispatch.assert_called_once()

    def test_continuation_missing_or_unrelated_lease_never_claims_or_dispatches(self):
        self.select_continuation()
        prior = {"operationId": "b" * 32, "intentSha256": "c" * 64, "resultSha256": "d" * 64}
        lease = self.root / ("dataset-" + trial.digest(self.clean["mountRoot"].encode()) + ".json")
        with self.start_boundaries() as (_, dispatch), patch.object(trial, "phase_prerequisites", return_value=prior):
            with self.assertRaisesRegex(release.Refusal, "trial.continuation.missing_claim"):
                trial.start(self.op)
            self.assertFalse(lease.exists())
            trial.durable.write_once(lease, trial.durable.encode({"operationId": "e" * 32, "intentSha256": "f" * 64}))
            original = lease.read_bytes()
            with self.assertRaisesRegex(release.Refusal, "trial.dataset.reserved"):
                trial.start(self.op)
            self.assertEqual(lease.read_bytes(), original)
            self.assertFalse((self.root / "global-owner.json").exists())
            dispatch.assert_not_called()

    def test_continuation_reproves_predecessor_inside_global_lock_before_transfer(self):
        self.select_continuation()
        prior = {"operationId": "b" * 32, "intentSha256": "c" * 64, "resultSha256": "d" * 64}
        lease = self.root / ("dataset-" + trial.digest(self.clean["mountRoot"].encode()) + ".json")
        original = trial.durable.encode({k: prior[k] for k in ("operationId", "intentSha256")})
        trial.durable.write_once(lease, original)
        with self.start_boundaries() as (_, dispatch), patch.object(trial, "phase_prerequisites",
                side_effect=[prior, {**prior, "resultSha256": "e" * 64}]):
            with self.assertRaisesRegex(release.Refusal, "trial.prior.changed"):
                trial.start(self.op)
            self.assertEqual(lease.read_bytes(), original)
            self.assertFalse((self.root / "global-owner.json").exists())
            self.assertFalse((self.op / "dataset-transfer.json").exists())
            dispatch.assert_not_called()

    def test_exit_zero_does_not_hide_child_oom_or_missing_completion(self):
        state = {"Running": False, "Pid": 0, "ExitCode": 0, "OOMKilled": False}
        self.assertTrue(trial.successful(state, 0, True, 0))
        self.assertFalse(trial.successful(state, 0, True, 1))
        self.assertFalse(trial.successful({**state, "OOMKilled": True}, 0, True, 0))
        self.assertFalse(trial.successful(state, 0, False, 0))
        self.assertFalse(trial.successful(state, 1, True, 0))

    def test_owned_cgroup_cpu_counters_are_bounded_and_required(self):
        cg = self.root / "cpu-cgroup"
        cg.mkdir()
        for name, value in {
            "memory.current": "4096", "memory.peak": "8192", "memory.swap.current": "0",
            "memory.events": "oom 0\noom_kill 0\n",
            "memory.stat": "anon 4096\nfile 0\nkernel 0\n",
            "cpu.stat": "usage_usec 5000000\nuser_usec 4000000\nsystem_usec 1000000\n"
                        "nr_throttled 2\nthrottled_usec 30000\n",
        }.items():
            (cg / name).write_text(value)
        sample = trial.cgroup_sample(cg)
        self.assertEqual(sample["cpu"], {"usageUsec": 5000000, "userUsec": 4000000,
                                          "systemUsec": 1000000, "nrThrottled": 2,
                                          "throttledUsec": 30000})
        self.assertEqual(sample["events"]["oom_kill"], 0)
        for bad in ("usage_usec -1\nuser_usec 1\nsystem_usec 1\n",
                    "usage_usec 1\nuser_usec 1\n",
                    "usage_usec 1\nusage_usec 2\nuser_usec 1\nsystem_usec 1\n",
                    "usage_usec 1\nuser_usec 1\nsystem_usec 1\n" + "x" * 4096):
            (cg / "cpu.stat").write_text(bad)
            with self.assertRaises(release.Refusal):
                trial.cgroup_sample(cg)

    def test_live_cgroup_admission_checks_actual_limits(self):
        self.clean.update(devicePath="/dev/sdb1", deviceMajorMinor="8:17")
        cg = self.root / "cgroup"
        cg.mkdir()
        for name, value in {"memory.max": str(24 << 30), "memory.swap.max": "0", "pids.max": "512",
                            "cpu.max": "400000 100000", "io.max": "8:16 rbps=134217728 wbps=33554432"}.items():
            (cg / name).write_text(value)
        trial.admit_cgroup(cg, self.intent, self.devices)
        (cg / "io.max").write_text("8:17 rbps=134217728 wbps=33554432")
        with self.assertRaisesRegex(release.Refusal, "trial.cgroup.io"):
            trial.admit_cgroup(cg, self.intent, self.devices)
        (cg / "io.max").write_text("8:16 rbps=134217728 wbps=33554432")
        (cg / "memory.max").write_text(str(8 << 30))
        with self.assertRaises(release.Refusal):
            trial.admit_cgroup(cg, self.intent, self.devices)

    def test_io_observation_counts_rates_absent_device_and_counter_loss(self):
        cg = self.root / "cgroup-io"
        cg.mkdir()
        for name, value in {"memory.max": str(24 << 30), "memory.swap.max": "0", "pids.max": "512",
                            "cpu.max": "400000 100000", "io.max": "8:16 rbps=134217728 wbps=33554432",
                            "io.stat": ""}.items():
            (cg / name).write_text(value)
        with patch.object(trial.time, "monotonic_ns", side_effect=[10**9, 3 * 10**9, 4 * 10**9]):
            first = trial.io_sample(cg, self.intent, self.devices)
            self.assertFalse(first["deviceObserved"])
            self.assertIsNone(first["readBps"])
            (cg / "io.stat").write_text(f"8:16 rbytes={256 << 20} wbytes={64 << 20} rios=1 wios=1\n")
            second = trial.io_sample(cg, self.intent, self.devices, first)
            self.assertEqual(second["intervalSeconds"], 2)
            self.assertEqual((second["readBps"], second["writeBps"]), (128 << 20, 32 << 20))
            self.assertEqual((second["readCapRatio"], second["writeCapRatio"]), (1, 1))
            (cg / "io.stat").write_text("")
            with self.assertRaisesRegex(release.Refusal, "io_counter_lost"):
                trial.io_sample(cg, self.intent, self.devices, second)
            (cg / "io.stat").write_text("8:16 rbytes=0 wbytes=0")
            with self.assertRaisesRegex(release.Refusal, "io_counter_changed"):
                trial.io_sample(cg, self.intent, self.devices, second)

    def test_io_stat_counterless_idle_devices_do_not_block_admission(self):
        cg = self.root / "cgroup-idle-io"
        cg.mkdir()
        for name, value in {"memory.max": str(24 << 30), "memory.swap.max": "0", "pids.max": "512",
                            "cpu.max": "400000 100000", "io.max": "8:16 rbps=134217728 wbps=33554432",
                            "io.stat": "7:7\n7:6\n8:16\n"}.items():
            (cg / name).write_text(value)
        first = trial.io_sample(cg, self.intent, self.devices)
        self.assertFalse(first["deviceObserved"])
        self.assertEqual((first["rbytes"], first["wbytes"]), (0, 0))
        (cg / "io.stat").write_text("7:7\n8:16 rbytes=4096 wbytes=1024 rios=1 wios=1\n")
        second = trial.io_sample(cg, self.intent, self.devices, first)
        self.assertTrue(second["deviceObserved"])
        self.assertEqual((second["rbytes"], second["wbytes"]), (4096, 1024))
        (cg / "io.stat").write_text("7:7\n8:16\n")
        with self.assertRaisesRegex(release.Refusal, "io_counter_lost"):
            trial.io_sample(cg, self.intent, self.devices, second)
        (cg / "io.max").write_text("8:16")
        with self.assertRaisesRegex(release.Refusal, "io_rows"):
            trial.admit_cgroup(cg, self.intent, self.devices)

    def test_io_admission_refuses_ambiguous_rows_fields_and_hidden_iops_limit(self):
        cg = self.root / "cgroup-io"
        cg.mkdir()
        for name, value in {"memory.max": str(24 << 30), "memory.swap.max": "0", "pids.max": "512",
                            "cpu.max": "400000 100000"}.items():
            (cg / name).write_text(value)
        good = "8:16 rbps=134217728 wbps=33554432"
        for raw in (good + "\n" + good, good + " rbps=134217728", good + " riops=100",
                    good.replace("wbps=33554432", "wbps=max"), good + " invalid"):
            (cg / "io.max").write_text(raw)
            with self.subTest(raw=raw), self.assertRaises(release.Refusal):
                trial.admit_cgroup(cg, self.intent, self.devices)

    def test_unknown_service_is_not_not_found(self):
        (self.op / "start-intent.json").write_text("{}")
        with patch.object(trial, "load", return_value=(self.op, self.intent)), \
             patch.object(trial, "native", side_effect=release.Refusal("unavailable")):
            self.assertEqual(trial.status(self.op)["state"], "unknown")

    def test_status_requires_same_invocation_and_clean_systemd_exit(self):
        invocation = "b" * 32
        records = {
            "start-intent.json": {},
            "started.json": {"invocationId": invocation, "at": "2026-10-21T00:00:00Z"},
            "result.json": {"operationId": self.op.name, "invocationId": invocation, "state": "succeeded",
                "imageReceiptSha256": self.plan["imageReceiptSha256"],
                "cleanInputSha256": self.plan["cleanInputSha256"]},
        }
        for name, value in records.items():
            trial.durable.write_once(self.op / name, trial.durable.encode(value))
        service = {"LoadState": "loaded", "ActiveState": "active", "SubState": "exited",
                   "MainPID": "0", "Result": "success", "ExecMainCode": "1", "ExecMainStatus": "0",
                   "InvocationID": invocation}
        with patch.object(trial, "load", return_value=(self.op, self.intent)):
            with patch.object(trial, "native", return_value="\n".join(f"{k}={v}" for k, v in service.items()).encode()):
                self.assertEqual(trial.status(self.op)["state"], "succeeded")
            for key, value in (("Result", "oom-kill"), ("ExecMainCode", "2"), ("ExecMainStatus", "9"),
                               ("InvocationID", "c" * 32), ("MainPID", "123"), ("SubState", "running")):
                changed = {**service, key: value}
                with patch.object(trial, "native", return_value="\n".join(f"{k}={v}" for k, v in changed.items()).encode()):
                    self.assertEqual(trial.status(self.op)["state"], "unknown", key)

    def exercise_serve(self, *, oom_after_native_exit=False, lost_before_settlement=False, policy_drift=False,
                       readonly_drift=False, io_partition_drift=False, devices_changed=False,
                       kernel_io_drift=False, prior_changed_at_gate=False,
                       leftover_descendant=False, remove_cgroup_on_exit=False,
                       stdout=b"Doctor complete.\n", stderr=b"", host_pressure=None):
        """Run the actual supervisor loop with synthetic daemon/process/cgroup boundaries."""
        cg = self.root / "live-cgroup"
        cg.mkdir()
        for name, value in {
            "memory.max": str(self.plan["limits"]["memoryBytes"]), "memory.swap.max": "0", "pids.max": "512",
            "cpu.max": "400000 100000",
            "io.max": f"8:16 rbps={self.plan['limits']['readBps']} wbps={self.plan['limits']['writeBps']}",
            "io.stat": "8:16 rbytes=0 wbytes=0 rios=0 wios=0",
            "memory.current": "4096", "memory.peak": "8192", "memory.swap.current": "0",
            "memory.events": "oom 0\noom_kill 0\n", "memory.stat": "anon 4096\nfile 0\nkernel 0\n",
            "cpu.stat": "usage_usec 0\nuser_usec 0\nsystem_usec 0\nnr_throttled 0\nthrottled_usec 0\n",
            "cgroup.procs": "123\n124\n",
        }.items():
            (cg / name).write_text(value)
        started = {"intentSha256": trial.digest((self.op / "intent.json").read_bytes()),
                   "bootId": "synthetic-boot", "mounts": {},
                   "image": {"loadedId": self.image["indexDigest"], "env": []}, "devices": self.devices}
        prior = None
        if trial.continuing(self.intent.get("check")):
            prior = {"operationId": "b" * 32, "intentSha256": "c" * 64, "resultSha256": "d" * 64}
            started["priorDoctor"] = prior
            previous = trial.durable.encode({k: prior[k] for k in ("operationId", "intentSha256")})
            requested = {"operationId": self.op.name, "intentSha256": started["intentSha256"]}
            lease = self.root / ("dataset-" + trial.digest(self.clean["mountRoot"].encode()) + ".json")
            trial.durable.write_once(lease, trial.durable.encode(requested))
            trial.durable.write_once(self.op / "dataset-previous.json", previous)
            trial.durable.write_once(self.op / "dataset-transfer.json", trial.durable.encode({
                "previousLeaseSha256": trial.digest(previous), "successor": requested,
                "priorDoctor": prior, "checkInputSha256": self.plan["checkInputSha256"]}))
        trial.durable.write_once(self.op / "start-intent.json", trial.durable.encode(started))
        state = {"child": None, "ready": False, "sent": False, "stopped": False, "closed": False}
        stop_calls = []
        invocation = "b" * 32
        op = self.op

        def ended():
            return state["stopped"] or (op / "gate/settled").exists() or (lost_before_settlement and state["sent"])

        class Child:
            def __init__(child, *args, **kwargs):
                child.returncode = None
                out_r, out_w = os.pipe()
                err_r, err_w = os.pipe()
                child.stdout, child.stderr = os.fdopen(out_r, "rb", buffering=0), os.fdopen(err_r, "rb", buffering=0)
                child.writers = [out_w, err_w]
                state["child"] = child

            def close_writers(child):
                if not state["closed"]:
                    for fd in child.writers:
                        os.close(fd)
                    state["closed"] = True

            def poll(child):
                if ended():
                    child.returncode = 0
                return child.returncode

            def kill(child):
                child.returncode = -9
                child.close_writers()

            def wait(child, timeout=None):
                child.close_writers()
                return child.poll()

        class Selector:
            def __init__(selector):
                selector.keys = {}

            def register(selector, stream, events, name):
                selector.keys[stream] = SimpleNamespace(fileobj=stream, fd=stream.fileno(), data=name)

            def get_map(selector):
                return selector.keys

            def select(selector, timeout):
                child = state["child"]
                if not state["ready"]:
                    os.write(child.writers[0], f"OPENCLAW_TRIAL_{op.name}_READY\n".encode())
                    state["ready"] = True
                    return [(key, 1) for key in selector.keys.values() if key.data == "stdout.log"]
                if not state["sent"]:
                    self.assertTrue((op / "gate/go").exists(), "native output must follow admission")
                    os.write(child.writers[0], stdout + (b"" if stderr else
                             f"OPENCLAW_TRIAL_{op.name}_EXIT=0\n".encode()))
                    if stderr:
                        os.write(child.writers[1], stderr + f"OPENCLAW_TRIAL_{op.name}_EXIT=0\n".encode())
                    state["sent"] = True
                    return [(key, 1) for key in selector.keys.values()
                            if key.data == "stdout.log" or stderr]
                if ended():
                    child.close_writers()
                    return [(key, 1) for key in selector.keys.values()]
                return []

            def unregister(selector, stream):
                del selector.keys[stream]

            def close(selector):
                selector.keys.clear()

        args = trial.create_argv(op, self.intent, self.devices)
        entry = args.index("--entrypoint")
        fixture = {"Id": "9" * 64, "Name": "/openclaw-doctor-" + op.name,
            "Image": self.image["indexDigest"], "RestartCount": 0,
            "Config": {"Image": self.image["indexDigest"], "User": "1000:1000", "Env": [],
                "Entrypoint": [args[entry + 1]], "Cmd": args[entry + 3:],
                "Labels": {"openclaw.snapshot-trial.operation": op.name}, "Healthcheck": {"Test": ["NONE"]}},
            "HostConfig": {"NetworkMode": "none", "IpcMode": "none", "ReadonlyRootfs": True,
                "Init": True, "Privileged": False, "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges"],
                "Memory": self.plan["limits"]["memoryBytes"],
                "MemorySwap": self.plan["limits"]["memoryBytes"],
                "NanoCpus": 4 * 10**9, "PidsLimit": 512,
                "RestartPolicy": {"Name": "no"}, "LogConfig": {"Type": "none"},
                "BlkioDeviceReadBps": [{"Path": "/dev/sdb", "Rate": self.plan['limits']['readBps']}],
                "BlkioDeviceWriteBps": [{"Path": "/dev/sdb", "Rate": self.plan['limits']['writeBps']}]},
            "Mounts": [{"Type": "bind", "Source": m["source"], "Destination": m["target"], "RW": not m["readOnly"]}
                       for m in self.clean["mounts"]] +
                      [{"Type": "bind", "Source": str(op / "gate"), "Destination": trial.ADMISSION, "RW": False}],
        }

        def inspect(cid):
            value = copy.deepcopy(fixture)
            running = state["child"] is not None and not ended()
            value["State"] = {"Status": "created" if state["child"] is None else ("running" if running else "exited"),
                "Running": running, "Pid": 123 if running else 0, "ExitCode": 0,
                "OOMKilled": False, "StartedAt": "2026-10-21T00:00:00.000Z"}
            if oom_after_native_exit and state["sent"] and cg.exists():
                (cg / "memory.events").write_text("oom 1\noom_kill 1\n")
            if leftover_descendant and state["sent"] and cg.exists():
                (cg / "cgroup.procs").write_text("123\n124\n125\n")
                if (op / "gate/settled").exists():
                    # Adversarial old behavior: descendant OOM after the final
                    # sample, wrapper exits zero, and Docker removes the group.
                    (cg / "memory.events").write_text("oom 1\noom_kill 1\n")
                    shutil.rmtree(cg)
            if remove_cgroup_on_exit and ended() and cg.exists():
                shutil.rmtree(cg)
            if policy_drift and state["sent"]:
                value["HostConfig"]["Memory"] = 8 << 30
            if io_partition_drift:
                value["HostConfig"]["BlkioDeviceReadBps"][0]["Path"] = "/dev/sdb1"
            if kernel_io_drift and state["sent"] and cg.exists():
                (cg / "io.max").write_text("8:16 rbps=max wbps=max")
            if readonly_drift and state["sent"]:
                next(m for m in value["Mounts"] if m["Destination"].startswith(trial.STATE_TARGET + "/workspace"))["RW"] = True
            return value

        def docker(args, timeout=30):
            if args[0] == "create":
                return ("9" * 64).encode()
            self.assertEqual(args[:2], ["stop", "--time"])
            self.assertIn(args[2], ("1", "30"))
            stop_calls.append(args)
            state["stopped"] = True
            return b""

        clock = [0.0]
        def tick():
            clock[0] += .6
            return clock[0]

        original_read = Path.read_text
        def read_text(file, *args, **kwargs):
            return "synthetic-boot" if str(file) == "/proc/sys/kernel/random/boot_id" else original_read(file, *args, **kwargs)

        device_reads = []
        def devices(_):
            device_reads.append(True)
            if devices_changed and len(device_reads) >= int(devices_changed):
                return {**self.devices, "ioMajorMinor": "8:32"}
            return self.devices

        prior_reads = []
        def phase_prerequisites(*args):
            prior_reads.append(True)
            return {**prior, "resultSha256": "e" * 64} if prior_changed_at_gate and len(prior_reads) > 1 else prior

        pressure_reads = []
        def pressure_sample():
            pressure_reads.append(True)
            return host_pressure(len(pressure_reads))

        with ExitStack() as stack:
            for name, value in (("load", lambda _: (op, self.intent)), ("snapshot_paths", lambda _: {}),
                                ("block_devices", devices),
                                ("no_other_writer", lambda _: None), ("observe_image", lambda *args: started["image"]),
                                ("phase_prerequisites", phase_prerequisites),
                                ("capacity", lambda *args: {"dataFreeBytes": 200 << 30,
                                                             "memoryAvailableBytes": 12 << 30}), ("docker", docker),
                                ("inspect_container", inspect), ("cgroup_path", lambda _: cg)):
                stack.enter_context(patch.object(trial, name, side_effect=value))
            stack.enter_context(patch.object(trial.durable, "reserve_heavy_workload", create=True))
            stack.enter_context(patch.object(trial.subprocess, "Popen", side_effect=Child))
            stack.enter_context(patch.object(trial.selectors, "DefaultSelector", Selector))
            stack.enter_context(patch.object(trial.time, "monotonic", side_effect=tick))
            stack.enter_context(patch.object(Path, "read_text", read_text))
            if host_pressure is not None:
                stack.enter_context(patch.object(trial, "host_pressure_sample", side_effect=pressure_sample))
            stack.enter_context(patch.dict(os.environ, {"INVOCATION_ID": invocation}))
            code = trial.serve(op)
        return code, json.loads((op / "result.json").read_bytes()), stop_calls

    def test_serve_success_requires_live_cgroup_settlement(self):
        code, result, stops = self.exercise_serve()
        self.assertEqual(code, 0, result)
        self.assertEqual(result["state"], "succeeded")
        self.assertTrue(result["cgroupSettlementObserved"])
        self.assertEqual(result["nativeExitCode"], 0)
        self.assertTrue((self.op / "gate/settled").exists())
        self.assertEqual(stops, [])

    def test_serve_16g_profile_keeps_native_settlement_and_exact_result(self):
        self.plan["limits"].update(memoryBytes=16 << 30, minMemoryAvailableBytes=20 << 30,
                                   readBps=256 << 20, writeBps=64 << 20)
        self.select_phase("doctor")
        code, result, stops = self.exercise_serve()
        self.assertEqual(code, 0, result)
        self.assertEqual(result["resourceProfile"]["id"], "memory16-read256-write64")
        self.assertEqual(result["resourceProfile"]["memoryBytes"], 16 << 30)
        self.assertEqual(result["resourceProfile"]["swapBytes"], 0)
        self.assertTrue(result["cgroupSettlementObserved"])
        self.assertEqual(result["oomKillDelta"], 0)
        self.assertEqual(stops, [])

    def test_serve_16g_profile_fails_closed_on_late_cgroup_oom(self):
        self.plan["limits"].update(memoryBytes=16 << 30, minMemoryAvailableBytes=20 << 30,
                                   readBps=256 << 20, writeBps=64 << 20)
        self.select_phase("doctor")
        code, result, _ = self.exercise_serve(oom_after_native_exit=True)
        self.assertEqual(code, 1)
        self.assertEqual(result["state"], "failed")
        self.assertGreater(result["oomKillDelta"], 0)
        self.assertFalse(result["promotionAuthorized"])
        self.assertEqual(result["resourceProfile"]["id"], "memory16-read256-write64")

    def test_serve_lease_patch_lower_admission_retains_host_samples(self):
        self.select_lease_patch_pressure()
        def sample(_):
            return {"at": "synthetic", "availableBytes": 12 << 30, "fullAvg10": 0.1}
        code, result, stops = self.exercise_serve(host_pressure=sample)
        self.assertEqual(code, 0, result)
        self.assertEqual(result["state"], "succeeded")
        self.assertGreaterEqual(result["hostPressure"]["samples"], 3)
        self.assertEqual(result["hostPressure"]["minimumAvailableBytes"], 12 << 30)
        self.assertTrue((self.op / "host-pressure-admission.json").exists())
        self.assertEqual(stops, [])

    def test_serve_lease_patch_host_pressure_stops_owned_test_after_gate(self):
        self.select_lease_patch_pressure()
        def sample(_):
            return {"at": "synthetic", "availableBytes":
                    (8 << 30) - 1 if (self.op / "gate/go").exists() else (12 << 30),
                    "fullAvg10": 0.1}
        code, result, stops = self.exercise_serve(host_pressure=sample)
        self.assertEqual(code, 1)
        self.assertEqual(result["reason"], "trial.host_pressure.memory")
        self.assertEqual(result["hostPressure"]["minimumAvailableBytes"], (8 << 30) - 1)
        self.assertTrue((self.op / "gate/go").exists())
        self.assertEqual(stops, [["stop", "--time", "1", "9" * 64]])

    def test_serve_lease_patch_readmits_12g_just_before_native_gate(self):
        self.select_lease_patch_pressure()
        def sample(_):
            at_gate = (self.op / "cgroup-admission.json").exists()
            return {"at": "synthetic", "availableBytes":
                    (11 << 30) if at_gate else (12 << 30), "fullAvg10": 0.1}
        code, result, stops = self.exercise_serve(host_pressure=sample)
        self.assertEqual(code, 1)
        self.assertEqual(result["reason"], "trial.host_pressure.admission")
        self.assertTrue((self.op / "cgroup-admission.json").exists())
        self.assertFalse((self.op / "gate/go").exists())
        self.assertEqual(result["cleanup"], "owned_container_stopped_retained")
        self.assertEqual(stops, [["stop", "--time", "1", "9" * 64]])

    def test_serve_lease_patch_psi_stall_refuses_before_native_gate(self):
        self.select_lease_patch_pressure()
        def sample(_):
            at_gate = (self.op / "cgroup-admission.json").exists()
            return {"at": "synthetic", "availableBytes": 12 << 30,
                    "fullAvg10": 6.0 if at_gate else 0.1}
        code, result, stops = self.exercise_serve(host_pressure=sample)
        self.assertEqual(code, 1)
        self.assertEqual(result["reason"], "trial.host_pressure.admission_psi")
        self.assertFalse((self.op / "gate/go").exists())
        self.assertEqual(result["cleanup"], "owned_container_stopped_retained")
        self.assertEqual(stops, [["stop", "--time", "1", "9" * 64]])

    def test_serve_lease_patch_sensor_loss_after_gate_stops_owned_test(self):
        self.select_lease_patch_pressure()
        def sample(_):
            if (self.op / "gate/go").exists():
                raise release.Refusal("trial.host_pressure.unavailable")
            return {"at": "synthetic", "availableBytes": 12 << 30, "fullAvg10": 0.1}
        code, result, stops = self.exercise_serve(host_pressure=sample)
        self.assertEqual(code, 1)
        self.assertEqual(result["reason"], "trial.host_pressure.unavailable")
        self.assertTrue((self.op / "gate/go").exists())
        self.assertEqual(result["cleanup"], "owned_container_stopped_retained")
        self.assertEqual(stops, [["stop", "--time", "1", "9" * 64]])

    def test_serve_lease_patch_unavailable_host_sensor_refuses_before_create(self):
        self.select_lease_patch_pressure()
        def unavailable(_):
            raise release.Refusal("trial.host_pressure.unavailable")
        code, result, stops = self.exercise_serve(host_pressure=unavailable)
        self.assertEqual(code, 1)
        self.assertEqual(result["reason"], "trial.host_pressure.unavailable")
        self.assertFalse((self.op / "create-intent.json").exists())
        self.assertEqual(stops, [])

    def test_serve_continuation_preserves_prior_reference_on_success(self):
        self.select_continuation()
        code, result, stops = self.exercise_serve()
        self.assertEqual(code, 0, result)
        self.assertEqual(result["continuedFrom"]["operationId"], "b" * 32)
        self.assertEqual(result["checkInputSha256"], self.plan["checkInputSha256"])
        self.assertTrue(result["doctorComplete"])
        self.assertEqual(stops, [])

    def test_serve_continuation_rechecks_prior_before_native_gate(self):
        self.select_continuation()
        code, result, stops = self.exercise_serve(prior_changed_at_gate=True)
        self.assertEqual(code, 1)
        self.assertEqual(result["reason"], "trial.prior.changed")
        self.assertFalse((self.op / "gate/go").exists())
        self.assertEqual(stops, [["stop", "--time", "30", "9" * 64]])

    def test_serve_higher_profile_is_applied_observed_and_retained_at_settlement(self):
        self.plan["limits"].update(readBps=256 << 20, writeBps=64 << 20)
        code, result, stops = self.exercise_serve()
        self.assertEqual(code, 0, result)
        args = trial.durable.read_private(self.op / "create-intent.json")["argv"]
        self.assertEqual(args[args.index("--device-read-bps") + 1], f"/dev/sdb:{256 << 20}")
        self.assertEqual(args[args.index("--device-write-bps") + 1], f"/dev/sdb:{64 << 20}")
        self.assertEqual(result["resourceProfile"]["id"], "read256-write64")
        self.assertEqual(result["resourceProfile"]["mode"], "fixed")
        self.assertGreaterEqual(result["ioObservation"]["samples"], 3)
        self.assertEqual(result["ioObservation"]["last"]["writeCapBps"], 64 << 20)
        settlement = trial.durable.read_private(self.op / "native-settlement.json")
        self.assertEqual(settlement["cgroup"]["io"]["device"], "8:16")
        self.assertEqual(stops, [])

    def test_serve_refuses_kernel_io_drift_even_when_docker_configuration_is_unchanged(self):
        code, result, stops = self.exercise_serve(kernel_io_drift=True)
        self.assertEqual(code, 1)
        self.assertEqual(result["reason"], "trial.cgroup.io")
        self.assertFalse((self.op / "gate/settled").exists())
        self.assertEqual(stops, [["stop", "--time", "30", "9" * 64]])

    def test_serve_partition_receipt_uses_retained_whole_disk_docker_and_cgroup_limits(self):
        self.clean.update(devicePath="/dev/disk/by-id/google-synthetic-part1", deviceMajorMinor="8:17")
        self.devices.update(devicePath="/dev/sdb1", deviceMajorMinor="8:17")
        code, result, stops = self.exercise_serve()
        self.assertEqual(code, 0, result)
        args = trial.durable.read_private(self.op / "create-intent.json")["argv"]
        self.assertEqual(args[args.index("--device-read-bps") + 1], "/dev/sdb:134217728")
        self.assertEqual(stops, [])

    def test_serve_refuses_mapping_change_before_any_container_create(self):
        code, result, stops = self.exercise_serve(devices_changed=True)
        self.assertEqual(code, 1)
        self.assertIsNone(result["containerId"])
        self.assertEqual(result["cleanup"], "not_started")
        self.assertFalse((self.op / "create-intent.json").exists())
        self.assertFalse((self.op / "container.json").exists())
        self.assertEqual(stops, [])

    def test_serve_rechecks_mapping_immediately_before_create(self):
        code, result, stops = self.exercise_serve(devices_changed=2)
        self.assertEqual(code, 1)
        self.assertEqual(result["reason"], "trial.devices.changed")
        self.assertFalse((self.op / "create-intent.json").exists())
        self.assertEqual(stops, [])

    def test_serve_rechecks_mapping_before_releasing_native_gate(self):
        code, result, stops = self.exercise_serve(devices_changed=3)
        self.assertEqual(code, 1)
        self.assertEqual(result["reason"], "trial.devices.changed")
        self.assertTrue((self.op / "container-start-intent.json").exists())
        self.assertFalse((self.op / "gate/go").exists())
        self.assertEqual(len(stops), 1)

    def test_effective_docker_partition_io_path_is_rejected_before_native_start(self):
        code, result, stops = self.exercise_serve(io_partition_drift=True)
        self.assertEqual(code, 1)
        self.assertEqual(result["reason"], "trial.container.io")
        self.assertFalse((self.op / "container-start-intent.json").exists())

    def test_startup_serve_requires_success_receipt_and_quiescent_oom_free_exit(self):
        self.select_phase("startup")
        expected = self.native_result()
        code, result, stops = self.exercise_serve(stdout=self.marker(expected), remove_cgroup_on_exit=True)
        self.assertEqual(code, 0, result)
        self.assertEqual(result["phase"], "startup")
        self.assertEqual(result["nativeCheck"], expected)
        self.assertFalse(result["doctorComplete"])
        self.assertTrue(result["cgroupSettlementObserved"])
        self.assertEqual(stops, [])

    def test_rollback_serve_runs_baseline_check_and_retains_receipt(self):
        self.select_phase("rollback")
        expected = self.native_result("rollback")
        code, result, _ = self.exercise_serve(stdout=self.marker(expected))
        self.assertEqual(code, 0, result)
        self.assertEqual(result["phase"], "rollback")
        self.assertEqual(result["nativeCheck"], expected)

    def test_startup_exit_zero_without_result_is_not_success(self):
        self.select_phase("startup")
        code, result, _ = self.exercise_serve()
        self.assertEqual(code, 1)
        self.assertEqual(result["reason"], "trial.check.missing_result")

    def test_startup_rejects_duplicate_stdout_receipts(self):
        self.select_phase("startup")
        marker = self.marker(self.native_result())
        code, result, stops = self.exercise_serve(stdout=marker + marker)
        self.assertEqual(code, 1)
        self.assertEqual(result["reason"], "trial.check.duplicate_result")
        self.assertEqual(len(stops), 1)

    def test_startup_native_stderr_cannot_supply_check_receipt(self):
        self.select_phase("startup")
        code, result, _ = self.exercise_serve(stdout=b"native stdout\n", stderr=self.marker(self.native_result()))
        self.assertEqual(code, 1)
        self.assertEqual(result["reason"], "trial.check.missing_result")

    def test_startup_ready_receipt_without_clean_gateway_shutdown_is_failure(self):
        self.select_phase("startup")
        marker = self.marker({**self.native_result(), "nativeSignal": "SIGKILL", "escalated": True})
        code, result, _ = self.exercise_serve(stdout=marker)
        self.assertEqual(code, 1)
        self.assertEqual(result["reason"], "check.result.native")

    def test_startup_success_receipt_cannot_hide_oom(self):
        self.select_phase("startup")
        code, result, _ = self.exercise_serve(stdout=self.marker(self.native_result()), oom_after_native_exit=True)
        self.assertEqual(code, 1)
        self.assertEqual(result["reason"], "trial.cgroup.oom_kill")
        self.assertEqual(result["oomKillDelta"], 1)

    def test_serve_removed_cgroup_requires_retained_quiescence(self):
        code, result, stops = self.exercise_serve(remove_cgroup_on_exit=True)
        self.assertEqual(code, 0, result)
        self.assertTrue(result["cgroupSettlementObserved"])
        self.assertFalse((self.root / "live-cgroup").exists())
        proof = json.loads((self.op / "native-quiescence.json").read_bytes())
        self.assertEqual(proof["processes"], proof["baselineProcesses"])
        settlement = json.loads((self.op / "native-settlement.json").read_bytes())
        self.assertEqual(settlement["processes"], proof["processes"])
        self.assertEqual(stops, [])

    def test_serve_leftover_descendant_cannot_hide_late_oom(self):
        code, result, stops = self.exercise_serve(leftover_descendant=True, remove_cgroup_on_exit=True)
        self.assertEqual(code, 1)
        self.assertEqual(result["reason"], "trial.native.descendants_remain")
        self.assertFalse((self.op / "gate/settled").exists())
        self.assertFalse((self.op / "native-settlement.json").exists())
        proof = json.loads((self.op / "native-quiescence.json").read_bytes())
        self.assertEqual(proof["processes"], [123, 124, 125])
        self.assertEqual(proof["baselineProcesses"], [123, 124])
        self.assertEqual(len(stops), 1)

    def test_serve_exit_zero_cannot_hide_oom_during_settlement(self):
        code, result, stops = self.exercise_serve(oom_after_native_exit=True)
        self.assertEqual(code, 1)
        self.assertEqual(result["reason"], "trial.cgroup.oom_kill")
        self.assertEqual(result["oomKillDelta"], 1)
        self.assertFalse((self.op / "gate/settled").exists())
        self.assertEqual(len(stops), 1)
        self.assertEqual(result["cleanup"], "owned_container_stopped_retained")

    def test_serve_missing_settlement_never_passes(self):
        code, result, _ = self.exercise_serve(lost_before_settlement=True)
        self.assertEqual(code, 1)
        self.assertFalse(result["cgroupSettlementObserved"])
        self.assertEqual(result["reason"], "trial.exit.before_settlement")

    def test_serve_does_not_join_completion_across_streams(self):
        code, result, _ = self.exercise_serve(stdout=b"Doctor comp", stderr=b"lete.\n")
        self.assertEqual(code, 1)
        self.assertFalse(result["doctorComplete"])
        self.assertEqual(result["reason"], "trial.doctor.not_successful")

    def test_serve_policy_drift_does_not_prevent_owned_stop(self):
        code, result, stops = self.exercise_serve(policy_drift=True)
        self.assertEqual(code, 1)
        self.assertEqual(result["reason"], "trial.container.isolation")
        self.assertEqual(len(stops), 1)
        self.assertEqual(result["cleanup"], "owned_container_stopped_retained")

    def test_serve_rejects_readonly_project_becoming_writable(self):
        self.clean = self.readonly_layout()
        self.intent["clean"] = self.clean
        code, result, stops = self.exercise_serve(readonly_drift=True)
        self.assertEqual(code, 1)
        self.assertEqual(result["reason"], "trial.container.mounts")
        self.assertEqual(len(stops), 1)

    def test_rotating_private_log_retains_latest_and_bound(self):
        with patch.object(trial, "CAP", 8):
            log = trial.RollingLog(self.op / "native.log")
            log.append(b"12345678")
            log.append(b"abcdefgh")
            log.append(b"latest!!")
            log.close()
        self.assertEqual((self.op / "native.log").read_bytes(), b"latest!!")
        self.assertEqual((self.op / "native.log.previous").read_bytes(), b"abcdefgh")
        self.assertEqual(log.total, 24)


if __name__ == "__main__":
    unittest.main()
