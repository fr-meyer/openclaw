"""Synthetic metadata fixtures only: no Docker, GCP, or database access."""
import argparse
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import hosted_resources as h


IDENTITY = "a" * 64
SOURCE = "b" * 40
TOOLING = "c" * 40
INDEX = "sha256:" + "d" * 64


def sample_row(**overrides):
    row = {
        "observedAt": "2026-10-23T00:00:00+00:00",
        "availableMemoryBytes": 14 * h.GIB, "totalMemoryBytes": 16 * h.GIB,
        "filesystems": {label: {"totalBytes": 100 * h.GIB, "freeBytes": 85 * h.GIB} for label in ("root", "tmp")},
        "memoryPressure": {"some": {"avg10": 0, "avg60": 0, "avg300": 0, "total": 0}},
        "memoryCurrentBytes": 1 * h.GIB, "cgroupLifetimeMemoryPeakBytes": 6 * h.GIB,
        "memoryStat": {"anon": h.GIB, "file": 0},
        "memoryEvents": {"low": 0, "high": 0, "max": 0, "oom": 0, "oom_kill": 0},
        "cpuStat": {"usage_usec": 30, "nr_throttled": 1},
        "ioStat": {"rbytes": 100, "wbytes": 200},
    }
    row.update(overrides)
    return row


def docker_inspect():
    return [{"Id": IDENTITY, "Name": "/buildx_buildkit_node", "State": {"Running": True, "Pid": 123, "OOMKilled": False},
             "HostConfig": {"Memory": 8 * h.GIB, "MemorySwap": 8 * h.GIB, "CpuPeriod": 100000, "CpuQuota": 400000, "NanoCpus": 0, "CgroupnsMode": "private"}}]


class ResourceTests(unittest.TestCase):
    def test_exact_setup_node_and_local_endpoint(self):
        for endpoint in ("default", "unix:///var/run/docker.sock"):
            self.assertEqual(h.local_node("builder", [{"name": "explicit-node", "endpoint": endpoint, "status": "running"}]), "buildx_buildkit_explicit-node")
        for nodes in ([], [{"name": "n", "endpoint": "ssh://remote", "status": "running"}], [{"name": "../x", "endpoint": "default", "status": "running"}], [{"name": "n", "endpoint": "default", "status": "stopped"}], [{}, {}]):
            with self.subTest(nodes=nodes), self.assertRaises(h.Refusal):
                h.local_node("builder", nodes)

    def test_worker_exact_host_limits_identity_and_private_namespace(self):
        with patch.object(h, "command_json", return_value=docker_inspect()) as command:
            self.assertEqual(h.inspect_worker("buildx_buildkit_node", IDENTITY), {"id": IDENTITY, "pid": 123})
            self.assertEqual(command.call_args.args[0], ["docker", "--host", "unix:///var/run/docker.sock", "inspect", "--type", "container", "buildx_buildkit_node"])
        for field, value in (("Memory", 0), ("MemorySwap", -1), ("CpuQuota", 800000), ("CpuPeriod", 50000), ("NanoCpus", 4000000000), ("CgroupnsMode", "host")):
            fixture = docker_inspect()
            fixture[0]["HostConfig"][field] = value
            with self.subTest(field=field), patch.object(h, "command_json", return_value=fixture), self.assertRaises(h.Refusal):
                h.inspect_worker("buildx_buildkit_node", IDENTITY)
        for field, value in (("Id", "e" * 64), ("Name", "/other"), ("State", {"Running": False, "Pid": 0}), ("State", {"Running": True, "Pid": 123, "OOMKilled": True})):
            fixture = docker_inspect()
            fixture[0][field] = value
            with self.subTest(field=field), patch.object(h, "command_json", return_value=fixture), self.assertRaises(h.Refusal):
                h.inspect_worker("buildx_buildkit_node", IDENTITY)

    def fixture_cgroups(self, parent_memory="max", worker_memory=str(8 * h.GIB), parent_cpu="max 100000", worker_cpu="400000 100000", swap="0"):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name).resolve()
        parent = root / "docker"
        worker = parent / "worker"
        worker.mkdir(parents=True)
        for path, memory, cpu, swap_limit in ((parent, parent_memory, parent_cpu, "max"), (worker, worker_memory, worker_cpu, swap)):
            (path / "memory.max").write_text(memory)
            (path / "memory.swap.max").write_text(swap_limit)
            (path / "cpu.max").write_text(cpu)
        return root, worker

    def test_effective_ancestor_limits_include_child_max(self):
        root, worker = self.fixture_cgroups(parent_memory=str(8 * h.GIB), worker_memory="max", parent_cpu="400000 100000", worker_cpu="max 100000")
        result = h.cgroup_bounds(root, worker)
        self.assertEqual(result["effective"], {"memoryMaxBytes": 8 * h.GIB, "swapMaxBytes": 0, "cpuCores": 4})
        self.assertIsNone(result["ancestors"][0]["memoryMaxBytes"])
        self.assertEqual(result["ancestors"][1]["memoryMaxBytes"], 8 * h.GIB)

    def test_missing_looser_or_conflicting_cgroup_limits_refused(self):
        for params in ({"parent_memory": "max", "worker_memory": "max"}, {"worker_memory": str(9 * h.GIB)}, {"parent_memory": str(4 * h.GIB)}, {"parent_cpu": "200000 100000"}, {"worker_cpu": "max 100000"}, {"swap": "max"}):
            root, worker = self.fixture_cgroups(**params)
            with self.subTest(params=params), self.assertRaises(h.Refusal):
                h.cgroup_bounds(root, worker)
        root, worker = self.fixture_cgroups()
        (worker / "memory.swap.max").unlink()
        with self.assertRaises(h.Refusal):
            h.cgroup_bounds(root, worker)

    def test_host_proc_cgroup_binding_and_hidden_ancestors_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            proc = root / "proc"
            (proc / "123").mkdir(parents=True)
            (proc / "self").mkdir()
            cg = root / "cgroup"
            (cg / "docker/worker").mkdir(parents=True)
            (proc / "123/cgroup").write_text("0::/docker/worker\n")
            (proc / "self/mountinfo").write_text(f"1 0 0:1 / {cg} rw - cgroup2 cgroup rw\n")
            self.assertEqual(h.cgroup_path(123, proc), (cg, cg / "docker/worker"))
            for relative in ("/../worker", "relative", "/"):
                (proc / "123/cgroup").write_text("0::" + relative + "\n")
                with self.subTest(relative=relative), self.assertRaises(h.Refusal):
                    h.cgroup_path(123, proc)
            (proc / "123/cgroup").write_text("0::/docker/worker\n")
            (proc / "self/mountinfo").write_text(f"1 0 0:1 /hidden {cg} rw - cgroup2 cgroup rw\n")
            with self.assertRaises(h.Refusal):
                h.cgroup_path(123, proc)

    def test_admission_and_runtime_boundary_margins(self):
        first = sample_row(availableMemoryBytes=10 * h.GIB)
        for fs in first["filesystems"].values():
            fs["freeBytes"] = 8 * h.GIB
        self.assertEqual(h.violations(first, first, True), [])
        below = copy.deepcopy(first)
        below["availableMemoryBytes"] -= 1
        below["filesystems"]["root"]["freeBytes"] -= 1
        self.assertEqual(h.violations(below, first, True), ["host.available_memory_below_floor", "host.root_disk_below_floor"])
        runtime = sample_row(availableMemoryBytes=2 * h.GIB)
        for fs in runtime["filesystems"].values():
            fs["freeBytes"] = 2 * h.GIB
        self.assertEqual(h.violations(runtime, first), [])
        runtime["availableMemoryBytes"] -= 1
        runtime["filesystems"]["tmp"]["freeBytes"] -= 1
        self.assertEqual(h.violations(runtime, first), ["host.available_memory_below_floor", "host.tmp_disk_below_floor"])

    def test_max_event_is_not_oom_kill_and_counters_must_not_reset(self):
        first = sample_row()
        later = sample_row()
        later["memoryEvents"].update(max=50, high=7)
        self.assertEqual(h.violations(later, first), [])
        later["memoryEvents"].update(oom=2, oom_kill=1)
        self.assertEqual(h.violations(later, first), ["worker.oom_increased", "worker.oom_kill_increased"])
        first["memoryEvents"]["oom"] = 3
        self.assertIn("worker.event_counters_reset", h.violations(later, first))

    def test_cumulative_peak_and_sample_max_are_distinct(self):
        first = sample_row()
        last = sample_row(memoryCurrentBytes=2 * h.GIB)
        last["cpuStat"]["usage_usec"] += 17
        last["ioStat"]["wbytes"] += 99
        result = h.aggregate([first, last])
        self.assertEqual(result["sampledMemoryCurrentMaxBytes"], 2 * h.GIB)
        self.assertEqual(result["cgroupLifetimeMemoryPeakBytes"], 6 * h.GIB)
        self.assertEqual(result["cgroupLifetimeMemoryPeakAtStartBytes"], 6 * h.GIB)
        self.assertEqual(result["cpuStatDeltas"]["usage_usec"], 17)
        self.assertEqual(result["ioStatDeltas"]["wbytes"], 99)

    def state_fixture(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        state = root / "state"
        state.mkdir(mode=0o700)
        contract = {"token": "owned", "sourceSha": SOURCE, "toolingSha": TOOLING, "builderId": IDENTITY, "startedAt": "2026-10-23T00:00:00+00:00", "firstSample": sample_row()}
        h.save(state / "contract.json", contract)
        return root, state, contract

    def test_collector_finishes_with_final_sample_on_owned_stop(self):
        _, state, _ = self.state_fixture()
        h.save(state / "stop.json", {"token": "owned"})
        later = sample_row(memoryCurrentBytes=3 * h.GIB)
        with patch.object(h, "process_identity", return_value={"pid": 123, "startTicks": 7}):
            h.collect(state, sampler=lambda _: later, sleep=lambda _: self.fail("must not sleep"))
        result = h.load(state / "completed.json")
        self.assertEqual(result["reason"], "finished")
        self.assertEqual(result["violations"], [])
        self.assertEqual(result["measurements"]["sampleCount"], 2)
        self.assertEqual(result["measurements"]["sampledMemoryCurrentMaxBytes"], 3 * h.GIB)

    def test_collector_deadline_failure_and_metadata_failure_are_retained(self):
        _, state, _ = self.state_fixture()
        with patch.object(h, "process_identity", return_value={"pid": 123, "startTicks": 7}):
            h.collect(state, sampler=lambda _: self.fail("deadline must not sample"), clock=iter([0, h.DURATION]).__next__)
        self.assertEqual(h.load(state / "completed.json")["violations"], ["collector.deadline_reached"])
        _, state, _ = self.state_fixture()
        with patch.object(h, "process_identity", return_value={"pid": 123, "startTicks": 7}):
            h.collect(state, sampler=lambda _: (_ for _ in ()).throw(h.Refusal("worker.identity_changed")))
        self.assertEqual(h.load(state / "completed.json")["violations"], ["worker.identity_changed"])

    def completed_fixture(self, problems=None, reason="finished"):
        root, state, _ = self.state_fixture()
        h.save(state / "collector.json", {"pid": 123, "startTicks": 7, "token": "owned"})
        self.settled = patch.object(h, "settled_collector", return_value=True)
        self.settled.start()
        self.addCleanup(self.settled.stop)
        h.save(state / "completed.json", {"token": "owned", "collector": {"pid": 123, "startTicks": 7}, "endedAt": "2026-10-23T00:01:00+00:00", "reason": reason, "measurements": h.aggregate([sample_row(), sample_row()]), "violations": problems or []})
        return root, state

    def test_finish_binds_image_source_and_tooling_and_excludes_private_state(self):
        root, state = self.completed_fixture()
        args = argparse.Namespace(state_dir=state, output=root / "resources.json", index_digest=INDEX)
        result = h.finish(args)
        self.assertEqual(result["status"], "passed")
        self.assertEqual((result["sourceSha"], result["toolingSha"], result["indexDigest"], result["builderId"]), (SOURCE, TOOLING, INDEX, IDENTITY))
        self.assertEqual(result["schema"], "openclaw.hosted-resources.v1")
        self.assertNotIn("token", json.dumps(result))
        self.assertNotIn("pid", json.dumps(result).lower())
        self.assertEqual(h.finish(args), result)
        with self.assertRaises(h.Refusal):
            h.finish(argparse.Namespace(state_dir=state, output=state / "public.json", index_digest=INDEX))

    def test_finished_resource_receipt_cannot_be_rebound_to_another_image(self):
        root, state = self.completed_fixture()
        h.finish(argparse.Namespace(state_dir=state, output=root / "first.json", index_digest=INDEX))
        with self.assertRaisesRegex(h.Refusal, "final_binding_changed"):
            h.finish(argparse.Namespace(state_dir=state, output=root / "second.json", index_digest="sha256:" + "e" * 64))
        self.assertFalse((root / "second.json").exists())

    def test_finish_fails_closed_on_build_failure_or_sample_violation(self):
        for digest, problems, reason in (("", [], "finished"), (INDEX, ["worker.oom_increased"], "finished"), (INDEX, [], "deadline")):
            root, state = self.completed_fixture(problems, reason)
            result = h.finish(argparse.Namespace(state_dir=state, output=root / "resources.json", index_digest=digest))
            self.assertEqual(result["status"], "failed")
            self.assertTrue(result["violations"])

    def test_finish_rejects_foreign_collector_without_signalling(self):
        root, state, _ = self.state_fixture()
        h.save(state / "collector.json", {"pid": 123, "startTicks": 7, "token": "owned"})
        with patch.object(h, "process_identity", return_value={"pid": 123, "startTicks": 999}), self.assertRaisesRegex(h.Refusal, "process_replaced"):
            h.finish(argparse.Namespace(state_dir=state, output=root / "resources.json", index_digest=INDEX))
        self.assertFalse((state / "stop.json").exists())
        self.assertFalse((root / "resources.json").exists())

    def test_sanitized_command_failures_and_bounded_timeout(self):
        from subprocess import CompletedProcess, TimeoutExpired
        with patch.object(h.subprocess, "run", return_value=CompletedProcess([], 1, "sensitive", "sensitive")) as run:
            with self.assertRaisesRegex(h.Refusal, "metadata_command_failed"):
                h.command_json(["docker", "inspect"])
            self.assertEqual(run.call_args.kwargs["timeout"], 10)
        with patch.object(h.subprocess, "run", side_effect=TimeoutExpired("docker", 10)):
            with self.assertRaisesRegex(h.Refusal, "metadata_unavailable"):
                h.command_json(["docker", "inspect"])

    def test_sample_reads_only_metadata_and_rechecks_exact_binding(self):
        root, worker = self.fixture_cgroups()
        fixture = {
            "/proc/meminfo": "MemTotal: 16777216 kB\nMemAvailable: 14680064 kB\n",
            "/proc/pressure/memory": "some avg10=0 avg60=0 avg300=0 total=0\nfull avg10=0 avg60=0 avg300=0 total=0\n",
            "/proc/pressure/cpu": "some avg10=0 avg60=0 avg300=0 total=0\n",
            "/proc/pressure/io": "some avg10=0 avg60=0 avg300=0 total=0\n",
            str(worker / "memory.current"): str(h.GIB),
            str(worker / "memory.peak"): str(2 * h.GIB),
            str(worker / "memory.stat"): "anon 100\nfile 200\n",
            str(worker / "memory.events"): "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n",
            str(worker / "cpu.stat"): "usage_usec 123\nnr_throttled 0\n",
            str(worker / "io.stat"): "8:1 rbytes=100 wbytes=200 rios=1 wios=2\n",
        }
        read_file = h.read
        def metadata_read(path):
            key = str(path)
            return fixture[key] if key in fixture else read_file(path)
        contract = {"containerName": "buildx_buildkit_node"}
        fs = argparse.Namespace(f_blocks=100, f_bavail=85, f_frsize=h.GIB)
        with patch.object(h, "inspect_worker", return_value={"id": IDENTITY, "pid": 123}) as inspect, patch.object(h, "cgroup_path", return_value=(root, worker)), patch.object(h, "read", side_effect=metadata_read), patch.object(h.os, "statvfs", return_value=fs):
            first = h.sample(contract, initial=True)
            self.assertEqual(contract["builderId"], IDENTITY)
            self.assertEqual(first["availableMemoryBytes"], 14 * h.GIB)
            self.assertEqual(first["memoryStat"], {"anon": 100, "file": 200})
            self.assertEqual(h.sample(contract)["memoryCurrentBytes"], h.GIB)
            self.assertEqual(inspect.call_args.args[1], IDENTITY)
            contract["workerPid"] = 124
            with self.assertRaisesRegex(h.Refusal, "execution_changed"):
                h.sample(contract)

    def test_start_real_interface_uses_only_exact_collector(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nodes = root / "nodes.json"
            nodes.write_text(json.dumps([{"name": "node", "endpoint": "default", "status": "running"}]))
            args = argparse.Namespace(builder="builder", driver="docker-container", nodes_json=nodes, state_dir=root / "state", source_sha=SOURCE, tooling_sha=TOOLING)
            def first_sample(contract, initial=False):
                self.assertTrue(initial)
                contract.update(builderId=IDENTITY, workerPid=123, cgroupPath="/sys/fs/cgroup/worker")
                return sample_row()
            child = argparse.Namespace(pid=456, poll=lambda: None)
            def spawn(argv, **kwargs):
                contract = h.load(args.state_dir / "contract.json")
                h.save(args.state_dir / "collector.json", {"pid": 456, "startTicks": 9, "token": contract["token"]})
                self.assertEqual(argv[-3:], ["_collect", "--state-dir", str(args.state_dir)])
                self.assertTrue(kwargs["start_new_session"])
                return child
            with patch.object(h.platform, "system", return_value="Linux"), patch.object(h.platform, "machine", return_value="x86_64"), patch.object(h, "read", side_effect=lambda path: 'ID=ubuntu\nVERSION_ID="24.04"\n' if str(path) == "/etc/os-release" else Path(path).read_text()), patch.object(h, "sample", side_effect=first_sample), patch.object(h.subprocess, "Popen", side_effect=spawn) as popen, patch.object(h, "process_identity", return_value={"pid": 456, "startTicks": 9}):
                result = h.start(args)
                self.assertEqual(result["status"], "collecting")
                self.assertEqual(result["builderId"], IDENTITY)
                self.assertEqual(popen.call_count, 1)
                with self.assertRaisesRegex(h.Refusal, "state.already_exists"):
                    h.start(args)
                self.assertEqual(popen.call_count, 1)

    def test_finish_never_accepts_live_collector_after_completed_marker(self):
        root, state = self.completed_fixture()
        with patch.object(h, "settled_collector", return_value=False), patch.object(h.time, "monotonic", side_effect=[0, h.INTERVAL]):
            with self.assertRaisesRegex(h.Refusal, "exit_unconfirmed"):
                h.finish(argparse.Namespace(state_dir=state, output=root / "resources.json", index_digest=INDEX))
        self.assertFalse((root / "resources.json").exists())

    def test_pressure_and_io_metadata_parsing(self):
        self.assertEqual(h.pressure("some avg10=1.5 avg60=0 avg300=0 total=123\n")["some"]["avg10"], 1.5)
        with self.assertRaises(h.Refusal):
            h.pressure("some avg10=nan avg60=0 avg300=0 total=123\n")
        result = h.io_totals("8:1 rbytes=3 wbytes=8 rios=1 wios=2\n8:2 rbytes=10 wbytes=2 rios=1 wios=1\n")
        self.assertEqual((result["rbytes"], result["wbytes"]), (13, 10))

    def test_private_state_no_symlink_or_shared_permissions(self):
        root, state, _ = self.state_fixture()
        self.assertEqual(h.private_state(state), state.absolute())
        (root / "link").symlink_to(state, target_is_directory=True)
        with self.assertRaises(h.Refusal):
            h.private_state(root / "link")
        state.chmod(0o755)
        with self.assertRaises(h.Refusal):
            h.private_state(state)


if __name__ == "__main__":
    unittest.main()
