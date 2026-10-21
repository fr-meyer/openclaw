"""Synthetic executor boundary tests. No Docker, systemd, database or cloud calls."""
import copy
from contextlib import ExitStack, contextmanager
import json
import os
from pathlib import Path
import shutil
import subprocess
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

    def test_readonly_projects_override_writable_state_parent_first(self):
        clean = self.readonly_layout()
        trial.validate(self.plan, self.image, clean)
        args = trial.create_argv(self.op, {**self.intent, "clean": clean})
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
        with self.assertRaisesRegex(release.Refusal, "trial.path.noncanonical"):
            trial.validate(self.plan, self.image, changed)

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
        for changed in ("gcp_snapshot_trial.py", "gcp_build.py"):
            pinned = {**files, changed: files[changed] + b"\n# another revision\n"}
            with patch.object(trial, "private_json", side_effect=[(self.plan, "unused"),
                    (self.image, self.plan["imageReceiptSha256"]), (self.clean, self.plan["cleanInputSha256"])]), \
                 patch.object(trial.durable, "clean_checkout"), \
                 patch.object(trial.subprocess, "check_output", side_effect=[pinned[name] for name in trial.HELPERS]), \
                 patch.object(trial.release, "private_root") as root:
                with self.assertRaisesRegex(release.Refusal, "trial.running_helper.changed"):
                    trial.prepare("plan", "image", "clean", self.root)
                root.assert_not_called()

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
            for name in ("gcp_snapshot_trial.py", "gcp_build.py"):
                with patch.dict(trial.LOADED_HELPER_HASHES, {name: "0" * 64}), \
                     patch.object(trial.durable, "reserve_heavy_workload") as reserve, \
                     patch.object(trial.subprocess, "run") as dispatch:
                    with self.assertRaisesRegex(release.Refusal, "trial.running_helper.changed"):
                        trial.start(self.op)
                    reserve.assert_not_called()
                    dispatch.assert_not_called()

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
        args = trial.create_argv(self.op, self.intent)
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
             patch.object(trial, "no_other_writer"), \
             patch.object(trial, "observe_image", return_value={"loadedId": self.image["indexDigest"], "env": []}), \
             patch.object(trial, "capacity", return_value={}), \
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
             patch.object(trial, "no_other_writer"), \
             patch.object(trial, "observe_image", return_value={"loadedId": self.image["indexDigest"], "env": []}), \
             patch.object(trial, "capacity", return_value={}), \
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

    def test_exit_zero_does_not_hide_child_oom_or_missing_completion(self):
        state = {"Running": False, "Pid": 0, "ExitCode": 0, "OOMKilled": False}
        self.assertTrue(trial.successful(state, 0, True, 0))
        self.assertFalse(trial.successful(state, 0, True, 1))
        self.assertFalse(trial.successful({**state, "OOMKilled": True}, 0, True, 0))
        self.assertFalse(trial.successful(state, 0, False, 0))
        self.assertFalse(trial.successful(state, 1, True, 0))

    def test_live_cgroup_admission_checks_actual_limits(self):
        cg = self.root / "cgroup"
        cg.mkdir()
        for name, value in {"memory.max": str(24 << 30), "memory.swap.max": "0", "pids.max": "512",
                            "cpu.max": "400000 100000", "io.max": "8:16 rbps=134217728 wbps=33554432"}.items():
            (cg / name).write_text(value)
        trial.admit_cgroup(cg, self.intent)
        (cg / "memory.max").write_text(str(8 << 30))
        with self.assertRaises(release.Refusal):
            trial.admit_cgroup(cg, self.intent)

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
                       readonly_drift=False,
                       leftover_descendant=False, remove_cgroup_on_exit=False,
                       stdout=b"Doctor complete.\n", stderr=b""):
        """Run the actual supervisor loop with synthetic daemon/process/cgroup boundaries."""
        cg = self.root / "live-cgroup"
        cg.mkdir()
        for name, value in {
            "memory.max": str(24 << 30), "memory.swap.max": "0", "pids.max": "512",
            "cpu.max": "400000 100000", "io.max": "8:16 rbps=134217728 wbps=33554432",
            "memory.current": "4096", "memory.peak": "8192", "memory.swap.current": "0",
            "memory.events": "oom 0\noom_kill 0\n", "memory.stat": "anon 4096\nfile 0\nkernel 0\n",
            "cgroup.procs": "123\n124\n",
        }.items():
            (cg / name).write_text(value)
        started = {"intentSha256": trial.digest((self.op / "intent.json").read_bytes()),
                   "bootId": "synthetic-boot", "mounts": {},
                   "image": {"loadedId": self.image["indexDigest"], "env": []}}
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

        args = trial.create_argv(op, self.intent)
        entry = args.index("--entrypoint")
        fixture = {"Id": "9" * 64, "Name": "/openclaw-doctor-" + op.name,
            "Image": self.image["indexDigest"], "RestartCount": 0,
            "Config": {"Image": self.image["indexDigest"], "User": "1000:1000", "Env": [],
                "Entrypoint": [args[entry + 1]], "Cmd": args[entry + 3:],
                "Labels": {"openclaw.snapshot-trial.operation": op.name}, "Healthcheck": {"Test": ["NONE"]}},
            "HostConfig": {"NetworkMode": "none", "IpcMode": "none", "ReadonlyRootfs": True,
                "Init": True, "Privileged": False, "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges"],
                "Memory": 24 << 30, "MemorySwap": 24 << 30, "NanoCpus": 4 * 10**9, "PidsLimit": 512,
                "RestartPolicy": {"Name": "no"}, "LogConfig": {"Type": "none"},
                "BlkioDeviceReadBps": [{"Path": "/dev/sdb", "Rate": 128 << 20}],
                "BlkioDeviceWriteBps": [{"Path": "/dev/sdb", "Rate": 32 << 20}]},
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
            if readonly_drift and state["sent"]:
                next(m for m in value["Mounts"] if m["Destination"].startswith(trial.STATE_TARGET + "/workspace"))["RW"] = True
            return value

        def docker(args, timeout=30):
            if args[0] == "create":
                return ("9" * 64).encode()
            self.assertEqual(args[:3], ["stop", "--time", "30"])
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

        with ExitStack() as stack:
            for name, value in (("load", lambda _: (op, self.intent)), ("snapshot_paths", lambda _: {}),
                                ("no_other_writer", lambda _: None), ("observe_image", lambda _: started["image"]),
                                ("capacity", lambda *args: {}), ("docker", docker),
                                ("inspect_container", inspect), ("cgroup_path", lambda _: cg)):
                stack.enter_context(patch.object(trial, name, side_effect=value))
            stack.enter_context(patch.object(trial.durable, "reserve_heavy_workload", create=True))
            stack.enter_context(patch.object(trial.subprocess, "Popen", side_effect=Child))
            stack.enter_context(patch.object(trial.selectors, "DefaultSelector", Selector))
            stack.enter_context(patch.object(trial.time, "monotonic", side_effect=tick))
            stack.enter_context(patch.object(Path, "read_text", read_text))
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
