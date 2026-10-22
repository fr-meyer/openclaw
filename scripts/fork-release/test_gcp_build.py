"""Offline supervisor proof: synthetic Git objects and a real inert Python child."""

from contextlib import ExitStack
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import stat
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import gcp_build as build
import release

HERE = Path(__file__).resolve().parent


class BuildTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / "source"
        self.source.mkdir()
        self.tooling = self.root / "tooling"
        self.tooling.mkdir()
        self.git("init", "--quiet")
        self.git("config", "user.name", "Synthetic Fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("config", "core.hooksPath", "/dev/null")
        (self.source / "package.json").write_text('{"version":"2026.10.5"}\n')
        (self.source / "first.test.ts").write_text("export const fixture = 1;\n")
        (self.source / "second.test.ts").write_text("export const fixture = 2;\n")
        self.dockerfile = b"FROM scratch\nRUN --network=none true\n"
        (self.source / "Dockerfile").write_bytes(self.dockerfile)
        self.git("add", ".")
        self.git("commit", "--quiet", "-m", "fixture base")
        base = self.git("rev-parse", "HEAD")
        base_tree = self.git("rev-parse", "HEAD^{tree}")
        base_blob = self.git("rev-parse", "HEAD:first.test.ts")
        self.git("tag", "-a", "v2026.10.5", "-m", "synthetic release")
        tag = self.git("rev-parse", "v2026.10.5")
        (self.source / "first.test.ts").write_text("export const fixture = 3;\n")
        self.git("add", ".")
        self.git("commit", "--quiet", "-m", "fixture patch")
        sha = self.git("rev-parse", "HEAD")
        tree = self.git("rev-parse", "HEAD^{tree}")
        diff = subprocess.check_output(["git", "-C", str(self.source), "diff", "--binary",
                                        "--full-index", "--no-ext-diff", base, sha])
        self.manifest = self.root / "manifest.json"
        manifest = {
            "schema": "openclaw.fork-release.v1", "repository": "fr-meyer/openclaw",
            "candidate": "v2026.10.5-source-only", "productionEligible": False,
            "source": {"baseCommit": base, "baseTree": base_tree,
                       "patches": [{"commit": sha, "tree": tree}], "commit": sha, "tree": tree},
            "gates": {"patchLifecycle": ["first.test.ts"], "producerConsumer": ["second.test.ts"]},
            "image": {"architecture": "amd64", "extensions": "codex,workboard"},
            "review": {"prNumber": 18, "baseSha": base,
                       "changedDiffSha256": hashlib.sha256(diff).hexdigest()}}
        self.manifest.write_bytes(build.encode(manifest))
        self.inventory = self.root / "patch-inventory.json"
        self.inventory.write_bytes(build.encode({
            "schema": "openclaw.fork-patch-inventory.v1",
            "repository": manifest["repository"], "candidate": manifest["candidate"],
            "manifestSha256": build.preflight.digest(self.manifest),
            "upstream": {"tag": "v2026.10.5", "tagObject": tag, "commit": base,
                         "verificationSha256": "d" * 64},
            "patches": [{"id": "fixture", "originCommit": base, "disposition": "adapt",
                         "appliedCommit": sha, "rationale": "Synthetic owner proof",
                         "evidenceSha256": None, "regressionTests": ["first.test.ts"],
                         "dependsOn": [], "regressionOwner": "fixture",
                         "paths": [{"path": "first.test.ts", "boundary": "container",
                                    "sourceCommit": base, "sourceTree": base_tree,
                                    "sourceBlob": base_blob, "upstreamBlob": base_blob,
                                    "candidateBlob": self.git("rev-parse", "HEAD:first.test.ts")}]}]}))
        self.config = {
            "schema": "openclaw.fork-gcp-build-config.v1", "operationId": "a" * 32,
            "attempt": 1, "projectNumber": "123", "instanceId": "456", "toolingSha": "e" * 40,
            "sourceSha": sha, "sourceTree": tree,
            "manifestSha256": build.preflight.digest(self.manifest),
            "inventorySha256": build.preflight.digest(self.inventory),
            "builtAt": build.now(), "dockerExport": False,
            "builder": {"name": "existing-builder", "node": "existing-builder0",
                        "endpoint": build.ENDPOINT, "containerId": "b" * 64,
                        "imageId": "sha256:" + "c" * 64, "memoryBytes": 10737418240,
                        "memorySwapBytes": 12884901888, "cpuPeriod": 100000,
                        "cpuQuota": 500000, "cpuShares": 128, "nanoCpus": 0,
                        "pidsLimit": None, "readBps": None, "writeBps": None},
            "limits": {"timeoutSeconds": 3600, "clientMemoryBytes": 256 << 20,
                       "clientCpuQuotaPercent": 50, "clientTasksMax": 64,
                       "minFreeBytes": 1024, "minMemoryAvailableBytes": 1024}}
        self.helpers = {name: (HERE / name).read_bytes() for name in build.HELPERS}
        self.observe_builder_impl = build.observe_builder
        self.capacity_impl = build.capacity
        self.resource_sample_impl = build.resource_sample
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(build, "REVIEWED_DOCKERFILE_SHA256",
                                             hashlib.sha256(self.dockerfile).hexdigest()))
        self.stack.enter_context(patch.object(build, "PRIVATE_ROOT", self.root / "private"))
        self.stack.enter_context(patch.object(build, "tooling_bytes", return_value=self.helpers))
        self.stack.enter_context(patch.object(build, "reserve_heavy_workload",
            side_effect=lambda *args, reserve_resource=None: reserve_resource() if reserve_resource else None))
        self.stack.enter_context(patch.object(build, "observe_builder", return_value=self.config["builder"]))
        self.stack.enter_context(patch.object(build, "capacity", return_value={
            "freeBytes": 1 << 40, "memoryAvailableBytes": 1 << 40}))
        self.stack.enter_context(patch.object(build, "resource_sample", return_value={
            "freeBytes": 1 << 40, "memoryAvailableBytes": 1 << 40}))
        self.stack.enter_context(patch.object(build.sys, "platform", "linux"))
        self.op = None

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.source), *args],
                                       stderr=subprocess.PIPE).decode().strip()

    def prepare(self, config=None, root=None):
        self.op = build.prepare(root or self.root / "private", config or self.config,
                                self.manifest, self.inventory, self.source, self.tooling)
        return self.op

    def show(self, state="active", sub="running", result="success", code="0", status="0"):
        return subprocess.CompletedProcess([], 0, "\n".join([
            "LoadState=loaded", f"ActiveState={state}", f"SubState={sub}",
            f"Result={result}", f"ExecMainCode={code}", f"ExecMainStatus={status}",
            "MainPID=0", "InvocationID=" + "f" * 32]), "")

    def fake_native(self, argv):
        if "systemd-run" in " ".join(argv):
            self.assertTrue((self.op / "start-intent.json").exists())
            return subprocess.CompletedProcess(argv, 0, "Running as unit\n", "")
        return self.show()

    def cache_fixture(self):
        path = self.root / "cache-disk" / "cache"
        path.mkdir(parents=True)
        cache = {"volumeName": f"buildx_buildkit_{self.config['builder']['node']}_state",
                 "backingPath": str(path), "filesystemDevice": path.stat().st_dev,
                 "minFreeBytes": 44 << 30}
        self.config["cache"] = cache
        volume = {"Name": cache["volumeName"], "Driver": "local",
                  "Mountpoint": "/synthetic/docker/volumes/cache/_data",
                  "Options": {"type": "none", "o": "bind", "device": str(path)}}
        mounts = [{"Type": "volume", "Name": cache["volumeName"],
                   "Source": volume["Mountpoint"], "Destination": "/var/lib/buildkit",
                   "Driver": "local", "RW": True}]
        return cache, volume, mounts

    def builder_fixture(self):
        expected = self.config["builder"]
        rows = [
            {"Builder": "unrelated", "Name": "unrelated", "DriverEndpoint": "docker", "Status": ""},
            {"Builder": expected["name"], "Name": expected["name"],
             "DriverEndpoint": "docker-container", "Status": ""},
            {"Builder": expected["name"], "Name": expected["node"],
             "DriverEndpoint": build.ENDPOINT, "Status": "running"}]
        container = {"Id": expected["containerId"], "Image": expected["imageId"],
                     "State": {"Running": True},
                     "HostConfig": {"Memory": expected["memoryBytes"],
                                    "MemorySwap": expected["memorySwapBytes"],
                                    "CpuPeriod": 100000, "CpuQuota": 500000,
                                    "CpuShares": 128, "NanoCpus": 0, "PidsLimit": None,
                                    "BlkioDeviceReadBps": None, "BlkioDeviceWriteBps": None}}
        return rows, container

    def test_bound_command_and_closed_configuration(self):
        with patch.object(build.pr, "git", wraps=build.pr.git) as source_read:
            op = self.prepare()
            source_read.assert_any_call(self.source, "show",
                                        f"{self.config['sourceSha']}:Dockerfile", binary=True)
        _, intent = build.load_intent(op)
        command = intent["buildArgv"]
        self.assertEqual(command[:3], list(build.DOCKER))
        self.assertEqual(command[command.index("--network") + 1], "default")
        sha = self.config["sourceSha"]
        self.assertEqual(command[-1], "https://github.com/fr-meyer/openclaw.git"
                         f"?fetch-by-commit=true&checksum={sha}#{sha}")
        # Buildx's legacy client-side Git parser does not know this query.
        # Its default forwards the context to the pinned native frontend.
        self.assertNotIn("BUILDX_SEND_GIT_QUERY_AS_INPUT", build.SAFE_ENV)
        self.assertIn("OPENCLAW_EXTENSIONS=codex,workboard", command)
        self.assertIn("mode=max", command)
        self.assertIn("--sbom", command)
        self.assertNotIn("--load", command)
        self.assertNotIn("--push", command)
        self.assertEqual(command.count("--output"), 1)
        self.assertFalse(any("type=docker" in arg or "image.docker.tar" in arg for arg in command))
        self.assertFalse(any("mount" in arg or "secret" in arg or arg == "--allow" for arg in command))
        self.assertNotIn(str(self.source), " ".join(command))
        service = intent["serviceArgv"]
        self.assertIn("--property=RuntimeMaxSec=3600", service)
        self.assertIn("--property=Restart=no", service)
        self.assertIn("--property=KillMode=control-group", service)
        self.assertEqual(service[service.index("--uid") + 1], str(os.getuid()))
        for extra in ("command", "shell", "mount", "environment"):
            with self.subTest(extra=extra), self.assertRaisesRegex(release.Refusal, "config.fields"):
                build.validate_config({**self.config, extra: "anything"})
        changed = copy.deepcopy(self.config)
        changed["dockerExport"] = True
        with self.assertRaisesRegex(release.Refusal, "export.unqualified_transport"):
            build.validate_config(changed)
        with self.assertRaisesRegex(release.Refusal, "export.unqualified_transport"):
            build.build_argv(op, changed, "2026.10.5")

    def test_bounded_docker_compiler_heap_is_exactly_bound_and_refuses_unsafe_values(self):
        tuned = copy.deepcopy(self.config)
        tuned["buildTuning"] = {"tsdownMaxOldSpaceMb": 6144}
        op = self.prepare(tuned)
        command = build.load_intent(op)[1]["buildArgv"]
        self.assertEqual(command.count("OPENCLAW_DOCKER_BUILD_TSDOWN_MAX_OLD_SPACE_MB=6144"), 1)
        self.assertEqual(command[-1].split("#")[-1], self.config["sourceSha"])
        for value in (True, 4351, 12289, "6144"):
            with self.subTest(value=value), self.assertRaisesRegex(
                    release.Refusal, "build.tuning.tsdown_heap"):
                build.validate_config({**tuned, "buildTuning": {"tsdownMaxOldSpaceMb": value}})
        with self.assertRaisesRegex(release.Refusal, "build.tuning.fields"):
            build.validate_config({**tuned, "buildTuning": {"tsdownMaxOldSpaceMb": 6144,
                                                            "unreviewed": True}})
        with self.assertRaisesRegex(release.Refusal, "build.tuning.fields"):
            build.validate_config({**tuned, "buildTuning": None})

    def test_start_memory_reserve_is_stronger_than_continuous_reserve(self):
        limits = {**self.config["limits"], "minMemoryAvailableBytes": 10 << 30,
                  "minStartMemoryAvailableBytes": 22 << 30}
        build.validate_config({**self.config, "limits": limits})
        sample = {"freeBytes": 30 << 30, "memoryAvailableBytes": 20 << 30}
        with patch.object(build, "resource_sample", return_value=sample):
            self.assertEqual(self.capacity_impl(self.root, limits), sample)
            with self.assertRaisesRegex(release.Refusal, "start_memory_reserve"):
                self.capacity_impl(self.root, limits, starting=True)
        with self.assertRaisesRegex(release.Refusal, "build.start_reserve"):
            build.validate_config({**self.config, "limits": {**limits,
                                   "minStartMemoryAvailableBytes": 9 << 30}})

    def adaptive_fixture(self, gib=22, pressure=0.1):
        if "cache" not in self.config:
            self.cache_fixture()
        self.config["limits"]["minFreeBytes"] = 16 << 30
        self.config["builder"]["memoryBytes"] = 16 << 30
        self.config["builder"]["memorySwapBytes"] = 18 << 30
        origin = build.datetime.now(build.timezone.utc).replace(microsecond=0)
        return [{"observedAt": (origin + build.timedelta(seconds=offset)).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"), "memoryAvailableBytes": gib << 30,
                 "freeBytes": 40 << 30, "cacheFreeBytes": 60 << 30,
                 "fullMemoryPressureAvg10": pressure,
                 "gatewayContainerId": "d" * 64, "gatewayHealthy": True,
                 "gatewayOomKilled": False} for offset in (-10, -5, 0)]

    def test_adaptive_selects_only_sustained_fitting_profile_and_binds_intent(self):
        samples = self.adaptive_fixture()
        bound = build.bind_adaptive_selection(self.config, samples)
        self.assertEqual(bound["adaptiveSelection"]["profile"]["id"], "constrained-21g")
        self.assertEqual(bound["buildTuning"], {"tsdownMaxOldSpaceMb": 6144})
        self.assertEqual(bound["limits"]["minMemoryAvailableBytes"], 10 << 30)
        self.assertEqual(bound["limits"]["minStartMemoryAvailableBytes"], 21 << 30)
        self.assertEqual(self.config["limits"]["minMemoryAvailableBytes"], 1024)
        op = self.prepare(bound)
        self.assertEqual(build.load_intent(op)[1]["config"], bound)
        samples = self.adaptive_fixture(gib=27)
        self.assertEqual(build.select_profile(self.config, samples)["id"], "roomy-26g")

    def test_adaptive_no_fit_hysteresis_and_missing_or_stale_metrics(self):
        samples = self.adaptive_fixture(gib=21)
        samples[1]["memoryAvailableBytes"] = (21 << 30) - 1
        self.assertIsNone(build.bind_adaptive_selection(self.config, samples))
        self.assertEqual(list((self.root / "private").glob("*")), [])
        samples = self.adaptive_fixture(gib=22)
        for key, value in (("gatewayHealthy", False), ("gatewayOomKilled", True),
                           ("fullMemoryPressureAvg10", 5.1), ("cacheFreeBytes", 1)):
            changed = copy.deepcopy(samples)
            changed[1][key] = value
            self.assertIsNone(build.select_profile(self.config, changed), key)
        for changed in (samples[:2], [{**sample, "fullMemoryPressureAvg10": None}
                                      for sample in samples],
                        [{**sample, "observedAt": "2000-01-01T00:00:00Z"}
                         for sample in samples]):
            with self.assertRaises(release.Refusal):
                build.select_profile(self.config, changed)

    def test_adaptive_does_not_relax_existing_reserves(self):
        samples = self.adaptive_fixture(gib=25)
        self.config["limits"]["minMemoryAvailableBytes"] = 12 << 30
        self.config["limits"]["minStartMemoryAvailableBytes"] = 24 << 30
        self.config["limits"]["maxFullMemoryPressureAvg10"] = 2.0
        bound = build.bind_adaptive_selection(self.config, samples)
        self.assertEqual(bound["limits"]["minMemoryAvailableBytes"], 12 << 30)
        self.assertEqual(bound["limits"]["minStartMemoryAvailableBytes"], 24 << 30)
        self.assertEqual(bound["limits"]["maxFullMemoryPressureAvg10"], 2.0)

    def test_adaptive_raises_low_base_disk_floors_to_supported_minimum(self):
        samples = self.adaptive_fixture(gib=22)
        self.config["limits"]["minFreeBytes"] = 8 << 30
        self.config["cache"]["minFreeBytes"] = 22 << 30
        bound = build.bind_adaptive_selection(self.config, samples)
        self.assertEqual(bound["limits"]["minFreeBytes"], 16 << 30)
        self.assertEqual(bound["cache"]["minFreeBytes"], 44 << 30)
        build.validate_config(bound)

    def test_adaptive_smaller_candidate_survives_incompatible_larger_heap(self):
        samples = self.adaptive_fixture(gib=27)
        self.config["builder"]["memoryBytes"] = 8 << 30
        self.config["builder"]["memorySwapBytes"] = 10 << 30
        self.assertEqual(build.select_profile(self.config, samples)["id"],
                         "constrained-21g")
        bound = build.bind_adaptive_selection(self.config, samples)
        build.validate_config(bound)

    def qualification_fixture(self, gib=18):
        samples = self.adaptive_fixture(gib=gib)
        self.config["builder"].update({"memoryBytes": 8 << 30,
                                       "memorySwapBytes": 8 << 30,
                                       "cpuQuota": 400000})
        self.config["limits"]["minMemoryAvailableBytes"] = 10 << 30
        return samples

    def test_qualification_profile_is_exact_source_worker_and_no_swap(self):
        samples = self.qualification_fixture()
        with patch.object(build, "QUALIFICATION_SOURCE_SHA", self.config["sourceSha"]):
            bound = build.bind_adaptive_selection(self.config, samples)
            self.assertEqual(bound["adaptiveSelection"]["profile"]["id"],
                             build.QUALIFICATION_PROFILE_ID)
            self.assertEqual(bound["limits"]["minStartMemoryAvailableBytes"], 18 << 30)
            self.assertEqual(bound["limits"]["minMemoryAvailableBytes"], 10 << 30)
            self.assertEqual(bound["buildTuning"], {"tsdownMaxOldSpaceMb": 6144})
            build.validate_config(bound)
            samples[1]["memoryAvailableBytes"] = (18 << 30) - 1
            self.assertIsNone(build.select_profile(self.config, samples))
            changed = copy.deepcopy(bound)
            changed["builder"]["memorySwapBytes"] = 10 << 30
            with self.assertRaises(release.Refusal):
                build.validate_config(changed)
            changed = copy.deepcopy(bound)
            changed["builder"]["cpuQuota"] = 700000
            with self.assertRaises(release.Refusal):
                build.validate_config(changed)
        # A similar small worker on another source gets no special profile.
        samples[1]["memoryAvailableBytes"] = 18 << 30
        self.assertIsNone(build.select_profile(self.config, samples))

    def test_qualification_capacity_fails_closed_on_gateway_or_worker_oom(self):
        limits = {"minFreeBytes": 16 << 30, "minMemoryAvailableBytes": 10 << 30,
                  "maxFullMemoryPressureAvg10": 5.0}
        observed = {"freeBytes": 30 << 30, "memoryAvailableBytes": 15 << 30,
                    "memoryPressure": {"full": {"avg10": 0.0}}}
        gateway = {"gatewayHealthy": True, "gatewayOomKilled": False,
                   "oom": 0, "oomKill": 0}
        worker = {"oom": 0, "oomKill": 0}
        with patch.object(build, "resource_sample", return_value=observed), \
             patch.object(build, "gateway_runtime_sample", return_value=gateway), \
             patch.object(build, "builder_sample", return_value=worker):
            self.assertEqual(self.capacity_impl(self.root, limits,
                gateway_container_id="d" * 64, builder=self.config["builder"])["gateway"],
                gateway)
            gateway["gatewayHealthy"] = False
            with self.assertRaisesRegex(release.Refusal, "gateway_health"):
                self.capacity_impl(self.root, limits, gateway_container_id="d" * 64)
            gateway["gatewayHealthy"] = True
            gateway["oomKill"] = 1
            with self.assertRaisesRegex(release.Refusal, "gateway_health"):
                self.capacity_impl(self.root, limits, gateway_container_id="d" * 64)
            gateway["oomKill"] = 0
            worker["oom"] = 1
            with self.assertRaisesRegex(release.Refusal, "worker_oom"):
                self.capacity_impl(self.root, limits, gateway_container_id="d" * 64,
                                   builder=self.config["builder"])

    def test_qualification_cgroup_checks_effective_ancestor_and_no_swap(self):
        cid = self.config["builder"]["containerId"]
        root = self.root / "cgroup"
        path = root / "system.slice" / f"docker-{cid}.scope" / "child"
        path.mkdir(parents=True)
        data = {
            str(path / "memory.max"): "max\n",
            str(path / "memory.swap.max"): "max\n",
            str(path / "cpu.max"): "max 100000\n",
            str(path.parent / "memory.max"): str(8 << 30) + "\n",
            str(path.parent / "memory.swap.max"): "0\n",
            str(path.parent / "cpu.max"): "400000 100000\n",
        }
        # cgroup v2 roots omit controller files; only descendants have them.
        for ancestor in (root / "system.slice",):
            data[str(ancestor / "memory.max")] = "max\n"
            data[str(ancestor / "memory.swap.max")] = "max\n"
            data[str(ancestor / "cpu.max")] = "max 100000\n"

        def fake_text(item):
            if str(item).endswith("/cgroup"):
                return f"0::/{path.relative_to(root)}\n"
            return data[str(item)]

        row = {"Id": cid, "State": {"Running": True, "Pid": 4321}}
        with patch.object(build, "CGROUP_ROOT", root), \
             patch.object(build, "cgroup_text", side_effect=fake_text), \
             patch.object(build, "native", return_value=subprocess.CompletedProcess(
                 [], 0, json.dumps(row), "")):
            proof = build.verify_builder_cgroup_limits(
                {**self.config["builder"], "memoryBytes": 8 << 30})
            self.assertEqual(proof["effectiveMemoryBytes"], 8 << 30)
            self.assertEqual(proof["effectiveSwapBytes"], 0)
            data[str(path.parent / "memory.swap.max")] = str(2 << 30) + "\n"
            with self.assertRaisesRegex(release.Refusal, "worker_scope_limits"):
                build.verify_builder_cgroup_limits(self.config["builder"])
            data[str(path.parent / "memory.swap.max")] = "max\n"
            data[str(path.parent / "memory.max")] = "max\n"
            data[str(path.parent / "cpu.max")] = "max 100000\n"
            data[str(root / "system.slice" / "memory.max")] = str(8 << 30) + "\n"
            data[str(root / "system.slice" / "memory.swap.max")] = "0\n"
            data[str(root / "system.slice" / "cpu.max")] = "400000 100000\n"
            with self.assertRaisesRegex(release.Refusal, "worker_scope_limits"):
                build.verify_builder_cgroup_limits(self.config["builder"])

    def test_qualification_start_refuses_before_dispatch_on_wrong_cgroup(self):
        samples = self.qualification_fixture()
        with patch.object(build, "QUALIFICATION_SOURCE_SHA", self.config["sourceSha"]):
            op = self.prepare(build.bind_adaptive_selection(self.config, samples))
            with patch.object(build, "collect_adaptive_samples", return_value=samples), \
                 patch.object(build, "verify_builder_cgroup_limits",
                              side_effect=release.Refusal("wrong cgroup")), \
                 patch.object(build, "native") as native:
                with self.assertRaisesRegex(release.Refusal, "wrong cgroup"):
                    build.start(op)
                native.assert_not_called()
            self.assertFalse((op / "start-intent.json").exists())

    def test_adaptive_rejects_identity_and_receipt_changes(self):
        samples = self.adaptive_fixture()
        bound = build.bind_adaptive_selection(self.config, samples)
        for key, value in (("sourceSha", "f" * 40),
                           ("builderContainerId", "e" * 64),
                           ("minMemoryAvailableBytes", 1)):
            changed = copy.deepcopy(bound)
            changed["adaptiveSelection"]["profile"][key] = value
            with self.assertRaises(release.Refusal):
                build.validate_config(changed)
        changed = copy.deepcopy(bound)
        changed["adaptiveSelection"]["samples"][1]["gatewayContainerId"] = "e" * 64
        with self.assertRaisesRegex(release.Refusal, "build.adaptive.binding"):
            build.validate_config(changed)
        changed = copy.deepcopy(bound)
        changed["buildTuning"]["tsdownMaxOldSpaceMb"] = 8192
        with self.assertRaisesRegex(release.Refusal, "build.adaptive.config_changed"):
            build.validate_config(changed)
        changed = copy.deepcopy(bound)
        changed["builder"]["cpuQuota"] += 100000
        with self.assertRaisesRegex(release.Refusal, "build.adaptive.profile_identity"):
            build.validate_config(changed)
        changed = copy.deepcopy(bound)
        changed["adaptiveSelection"]["profile"]["tsdownMaxOldSpaceMb"] = 8192
        changed["adaptiveSelection"]["profileSha256"] = release.sha256(
            build.encode(changed["adaptiveSelection"]["profile"]))
        with self.assertRaisesRegex(release.Refusal, "build.adaptive.profile_unreviewed"):
            build.validate_config(changed)

    def test_adaptive_start_refuses_new_no_fit_without_dispatch_or_reservation(self):
        samples = self.adaptive_fixture()
        op = self.prepare(build.bind_adaptive_selection(self.config, samples))
        samples[1]["gatewayHealthy"] = False
        with patch.object(build, "collect_adaptive_samples", return_value=samples), \
             patch.object(build, "native") as native:
            with self.assertRaisesRegex(release.Refusal, "build.adaptive.start_no_fit"):
                build.start(op)
            native.assert_not_called()
        self.assertFalse((op / "start-intent.json").exists())
        self.assertFalse((op.parent / f"builder-{self.config['builder']['containerId']}.json").exists())

    def test_adaptive_gateway_inspection_requires_healthy_exact_container(self):
        state = {"Running": True, "OOMKilled": False, "Health": {"Status": "healthy"}}
        observed = {"Id": "d" * 64, "Name": "/" + build.PRODUCTION_GATEWAY_NAME,
                    "State": state}
        with patch.object(build, "native", return_value=subprocess.CompletedProcess(
                [], 0, json.dumps(observed), "")) as native:
            self.assertTrue(build.gateway_sample("d" * 64)["gatewayHealthy"])
            self.assertEqual(native.call_args.args[0][-1], build.PRODUCTION_GATEWAY_NAME)
        state["Health"]["Status"] = "unhealthy"
        with patch.object(build, "native", return_value=subprocess.CompletedProcess(
                [], 0, json.dumps(observed), "")):
            self.assertFalse(build.gateway_sample("d" * 64)["gatewayHealthy"])
        observed["Name"] = "/unrelated-healthy-container"
        with patch.object(build, "native", return_value=subprocess.CompletedProcess(
                [], 0, json.dumps(observed), "")):
            with self.assertRaisesRegex(release.Refusal, "gateway_identity_changed"):
                build.gateway_sample("d" * 64)
        observed["Name"] = "/" + build.PRODUCTION_GATEWAY_NAME
        observed["Id"] = "e" * 64
        with patch.object(build, "native", return_value=subprocess.CompletedProcess(
                [], 0, json.dumps(observed), "")):
            with self.assertRaisesRegex(release.Refusal, "gateway_identity_changed"):
                build.gateway_sample("d" * 64)
        with self.assertRaisesRegex(release.Refusal, "gateway_identity"):
            build.gateway_sample("d" * 7)

    def test_adaptive_cli_no_fit_creates_no_operation(self):
        samples = self.adaptive_fixture(gib=20)
        config_path = self.root / "config.json"
        config_path.write_bytes(build.encode(self.config))
        argv = ["gcp_build.py", "prepare", "--config", str(config_path),
                "--private-root", str(self.root / "private"),
                "--manifest", str(self.manifest), "--inventory", str(self.inventory),
                "--source-dir", str(self.source), "--tooling-dir", str(self.tooling),
                "--adaptive-gateway-id", "d" * 64]
        output = io.StringIO()
        with patch.object(build.sys, "argv", argv), \
             patch.object(build.sys, "stdout", output), \
             patch.object(build, "collect_adaptive_samples", return_value=samples), \
             patch.object(build, "prepare") as prepared:
            self.assertEqual(build.main(), 2)
            prepared.assert_not_called()
        result = json.loads(output.getvalue())
        self.assertEqual(result["status"], "no_fit")
        self.assertNotIn("samples", result)
        self.assertNotIn("d" * 64, output.getvalue())

    def test_adaptive_service_rechecks_before_native_child(self):
        samples = self.adaptive_fixture()
        op = self.prepare(build.bind_adaptive_selection(self.config, samples))
        with patch.object(build, "collect_adaptive_samples", return_value=samples), \
             patch.object(build, "native", side_effect=self.fake_native):
            build.start(op)
        _, intent = build.load_intent(op)
        changed = copy.deepcopy(samples)
        changed[2]["memoryAvailableBytes"] = 20 << 30
        with patch.dict(os.environ, {"INVOCATION_ID": "f" * 32}), \
             patch.object(build, "collect_adaptive_samples", return_value=changed), \
             patch.object(build.subprocess, "Popen") as launched:
            with self.assertRaisesRegex(release.Refusal, "build.adaptive.service_no_fit"):
                build.run_child(op, intent)
            launched.assert_not_called()
        self.assertEqual(build.read_private(op / "completed.json")["exitCode"], 1)

    def test_memory_full_stall_limit_cancels_before_lowering_host_reserve(self):
        limits = {**self.config["limits"], "minMemoryAvailableBytes": 10 << 30,
                  "maxFullMemoryPressureAvg10": 5.0}
        build.validate_config({**self.config, "limits": limits})
        sample = {"freeBytes": 30 << 30, "memoryAvailableBytes": 15 << 30,
                  "memoryPressure": {"full": {"avg10": 4.9}}}
        with patch.object(build, "resource_sample", return_value=sample):
            self.assertEqual(self.capacity_impl(self.root, limits), sample)
            sample["memoryPressure"]["full"]["avg10"] = 5.1
            with self.assertRaisesRegex(release.Refusal, "memory_pressure"):
                self.capacity_impl(self.root, limits)
        for value in (True, -1, 101, "5"):
            with self.subTest(value=value), self.assertRaisesRegex(
                    release.Refusal, "build.pressure_limit"):
                build.validate_config({**self.config, "limits": {**limits,
                                       "maxFullMemoryPressureAvg10": value}})

    def test_host_memory_pressure_parser_requires_both_kernel_rows(self):
        pressure = ("some avg10=2.25 avg60=1.10 avg300=0.80 total=100\n"
                    "full avg10=0.75 avg60=0.25 avg300=0.10 total=50\n")
        with patch.object(Path, "read_text", return_value=pressure):
            self.assertEqual(build.memory_pressure_sample()["full"],
                             {"avg10": 0.75, "avg60": 0.25})
        with patch.object(Path, "read_text", return_value=pressure.splitlines()[0]):
            with self.assertRaisesRegex(release.Refusal, "pressure_unavailable"):
                build.memory_pressure_sample()

    def test_missing_pressure_is_diagnostic_for_legacy_config_and_refusal_for_gated_build(self):
        # Retained v1 operations did not request a pressure gate. Their resource
        # admission must not change merely because diagnostics were added.
        build.validate_config(self.config)
        for failure in (OSError("PSI missing"), KeyError("avg10")):
            with self.subTest(failure=failure), patch.object(
                    build, "resource_sample", self.resource_sample_impl), patch.object(
                    build, "memory_pressure_sample", side_effect=failure), patch.object(
                    Path, "read_text", return_value=f"MemAvailable: {(16 << 30) // 1024} kB\n"):
                sample = self.resource_sample_impl(self.root)
                self.assertEqual(sample["memoryPressureObservationError"], str(failure))
                accepted = self.capacity_impl(self.root, self.config["limits"])
                self.assertEqual(accepted["memoryPressureObservationError"], str(failure))
                gated = {**self.config["limits"], "maxFullMemoryPressureAvg10": 5.0}
                with self.assertRaisesRegex(release.Refusal, "pressure_unavailable"):
                    self.capacity_impl(self.root, gated)

    def test_pinned_builder_cgroup_telemetry_records_peak_and_rejects_symlink(self):
        slice_root = self.root / "system.slice"
        slice_root.mkdir()
        group = slice_root / f"docker-{self.config['builder']['containerId']}.scope"
        group.mkdir()
        contents = {"memory.current": "6442450944\n", "memory.peak": "8589934592\n",
                    "memory.stat": "anon 4294967296\nfile 1610612736\nslab 536870912\n",
                    "cpu.stat": "usage_usec 42000000\nnr_periods 100\n"
                                "nr_throttled 12\nthrottled_usec 3000000\n",
                    "memory.events": "oom 0\noom_kill 0\n"}
        for name, value in contents.items():
            (group / name).write_text(value)
        with patch.object(build, "CGROUP_SLICE", slice_root):
            sample = build.builder_sample(self.config["builder"])
            self.assertEqual(sample["memoryPeakBytes"], 8589934592)
            self.assertEqual(sample["anonBytes"], 4294967296)
            self.assertEqual(sample["cpuThrottledUsec"], 3000000)
            self.assertEqual(sample["oomKill"], 0)
            group.rename(slice_root / "real")
            group.symlink_to(slice_root / "real", target_is_directory=True)
            with self.assertRaisesRegex(release.Refusal, "cgroup_unavailable"):
                build.builder_sample(self.config["builder"])

    def test_changed_dockerfile_policy_refuses_preparation_and_rechecks_before_dispatch(self):
        native_git = build.pr.git
        changed_bytes = self.dockerfile

        def read_source(root, *args, **kwargs):
            if args == ("show", f"{self.config['sourceSha']}:Dockerfile"):
                self.assertTrue(kwargs.get("binary"))
                return changed_bytes
            return native_git(root, *args, **kwargs)

        # Complete bytes are policy: instruction counts alone cannot authorize
        # directives, stage inheritance, payload copies or even a changed RUN.
        changes = [self.dockerfile.replace(b"--network=none", b"--network=default"),
                   b"# escape=`\n" + self.dockerfile,
                   self.dockerfile + b"COPY . /candidate\nRUN --network=default true\n",
                   self.dockerfile + b"ENV NODE_OPTIONS=--require=/candidate/hook.mjs\n",
                   self.dockerfile + b"SHELL [\"/candidate/shell\", \"-c\"]\n",
                   self.dockerfile + b"ONBUILD RUN true\n",
                   self.dockerfile + b"\n"]
        with patch.object(build.pr, "git", side_effect=read_source):
            for changed_bytes in changes:
                with self.subTest(dockerfile=changed_bytes), patch.object(build, "build_argv") as argv:
                    with self.assertRaisesRegex(release.Refusal, "dockerfile.network_policy_unreviewed"):
                        self.prepare()
                    argv.assert_not_called()
                    self.assertFalse((self.root / "private").exists())
            changed_bytes = self.dockerfile
            self.prepare()
            changed_bytes = changes[0]
            with patch.object(build, "native") as native:
                with self.assertRaisesRegex(release.Refusal, "dockerfile.network_policy_unreviewed"):
                    build.start(self.op)
                native.assert_not_called()
        self.assertFalse((self.op / "start-intent.json").exists())
        self.assertFalse((self.op.parent /
                          f"builder-{self.config['builder']['containerId']}.json").exists())

    def test_wrong_source_binding_and_evidence_overlap_refused_before_preparation(self):
        for key, value in (("sourceSha", "0" * 40), ("sourceTree", "0" * 40),
                           ("manifestSha256", "0" * 64), ("inventorySha256", "0" * 64)):
            with self.subTest(key=key), self.assertRaises(release.Refusal):
                self.prepare({**self.config, key: value})
        self.assertFalse((self.root / "private").exists())
        with patch.object(build, "PRIVATE_ROOT", self.source / "private"):
            with self.assertRaisesRegex(release.Refusal, "overlaps_source"):
                self.prepare(root=self.source / "private")
        (self.source / "untracked").write_text("fixture")
        with self.assertRaisesRegex(release.Refusal, "dirty"):
            self.prepare()

    def test_alternate_private_root_cannot_bypass_builder_reservation(self):
        alternate = self.root / "another-private-root"
        with self.assertRaisesRegex(release.Refusal, "private_root.not_canonical"):
            self.prepare(root=alternate)
        self.assertFalse(alternate.exists())
        op = self.prepare()
        with patch.object(build, "PRIVATE_ROOT", alternate):
            with self.assertRaisesRegex(release.Refusal, "private_root.not_canonical"):
                build.load_intent(op)

    def test_package_version_must_match_verified_upstream_tag(self):
        native_git = build.pr.git

        def read_version(root, *args, **kwargs):
            if args == ("show", f"{self.config['sourceSha']}:package.json"):
                return '{"version":"2026.10.4"}'
            return native_git(root, *args, **kwargs)

        with patch.object(build.pr, "git", side_effect=read_version):
            with self.assertRaisesRegex(release.Refusal, "version.upstream_mismatch"):
                self.prepare()
        self.assertFalse((self.root / "private").exists())

    def test_once_only_and_uncertain_dispatch_never_retries(self):
        self.prepare()
        dispatches = []

        def uncertain(argv):
            if "systemd-run" in " ".join(argv):
                dispatches.append(argv)
                self.assertEqual(build.read_private(self.op / "start-intent.json")["intentSha256"],
                                 build.preflight.digest(self.op / "intent.json"))
                raise subprocess.TimeoutExpired(argv, 30)
            return self.show()

        with patch.object(build, "native", side_effect=uncertain):
            self.assertEqual(build.start(self.op)["state"], "running")
            build.start(self.op)
            build.start(self.op)
        self.assertEqual(len(dispatches), 1)
        self.assertIsNone(build.read_private(self.op / "dispatch.json")["returnCode"])
        other = self.prepare({**self.config, "operationId": "b" * 32})
        with patch.object(build, "native", side_effect=uncertain):
            with self.assertRaisesRegex(release.Refusal, "reserved_by_other_operation"):
                build.start(other)
        self.assertEqual(len(dispatches), 1)

    def test_busy_workload_refuses_before_retaining_builder_or_dispatch(self):
        self.prepare()
        with patch.object(build, "native", side_effect=self.fake_native), \
                patch.object(build, "reserve_heavy_workload", side_effect=release.Refusal("workload.owned")), \
                self.assertRaisesRegex(release.Refusal, "workload.owned"):
            build.start(self.op)
        lease = self.op.parent / f"builder-{self.config['builder']['containerId']}.json"
        self.assertFalse(lease.exists())
        self.assertFalse((self.op / "start-intent.json").exists())
        self.assertFalse((self.op / "dispatch.json").exists())

    def test_partial_and_nonzero_service_cannot_finalize(self):
        self.prepare()
        with patch.object(build, "native", side_effect=self.fake_native):
            build.start(self.op)
        for observation in (self.show("failed", "failed", "exit-code", "1", "7"),
                            self.show("active", "exited", "success", "1", "0")):
            with patch.object(build, "native", return_value=observation):
                self.assertNotEqual(build.status(self.op)["state"], "succeeded")
        self.assertFalse((self.op / "execution.json").exists())

    def child_fixture(self, exit_code=0):
        fixture = self.root / "inert-child.py"
        fixture.write_text(
            "import json, os, pathlib, sys\n"
            "args = sys.argv[1:]\n"
            "metadata = pathlib.Path(args[args.index('--metadata-file') + 1])\n"
            "digest = 'sha256:' + '1' * 64\n"
            "metadata.write_text(json.dumps({'containerimage.digest': digest}))\n"
            "oci = metadata.parent / 'oci'\n"
            "oci.mkdir()\n"
            "(oci / 'index.json').write_text(json.dumps({'manifests':[{'digest':digest}]}))\n"
            "mask = os.umask(0o022)\n"
            "assert mask == 0o022, mask\n"
            "print('native fixture output', flush=True)\n"
            f"sys.exit({exit_code})\n")
        self.stack.enter_context(patch.object(build, "DOCKER", (sys.executable, str(fixture))))

    def descendant_pipe_fixture(self, parent_behavior):
        ready = self.root / "pipe-holder.ready"
        stop = self.root / "pipe-holder.stop"
        done = self.root / "pipe-holder.done"
        fixture = self.root / "inert-pipe-parent.py"
        fixture.write_text(
            "import os, pathlib, signal, sys, time\n"
            f"ready, stop, done = map(pathlib.Path, {tuple(map(str, (ready, stop, done)))!r})\n"
            f"behavior = {parent_behavior!r}\n"
            "def terminated(*_args):\n"
            "    sys.exit(7)\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN if behavior == 'ignore' else terminated)\n"
            "if os.fork() == 0:\n"
            "    signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "    ready.write_text(str(os.getpid()))\n"
            "    deadline = time.monotonic() + 20\n"
            "    while not stop.exists() and time.monotonic() < deadline:\n"
            "        time.sleep(0.02)\n"
            "    done.write_text('pipe holder exited')\n"
            "    os._exit(0)\n"
            "while not ready.exists():\n"
            "    time.sleep(0.01)\n"
            "print('native parent output before inherited pipe', flush=True)\n"
            "if behavior == 'exit-zero':\n"
            "    sys.exit(0)\n"
            "deadline = time.monotonic() + 20\n"
            "while time.monotonic() < deadline:\n"
            "    time.sleep(0.02)\n"
            "sys.exit(7)\n")
        self.stack.enter_context(patch.object(build, "DOCKER", (sys.executable, str(fixture))))

        def release_fixture_descendant():
            stop.touch()
            deadline = time.monotonic() + 3
            while ready.exists() and not done.exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            if ready.exists():
                self.assertTrue(done.exists(), "owned inert descendant did not acknowledge release")

        self.addCleanup(release_fixture_descendant)
        return ready, done

    def assert_descendant_pipe_cannot_hold_supervisor(self, parent_behavior, native_exit):
        ready, done = self.descendant_pipe_fixture(parent_behavior)
        self.prepare()
        with patch.object(build, "native", side_effect=self.fake_native):
            build.start(self.op)
        _, intent = build.load_intent(self.op)
        output = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")

        def capacity_after_parent_ready(*_args, **_kwargs):
            if parent_behavior != "exit-zero" and ready.exists():
                raise release.Refusal("build.capacity.memory_reserve")
            return {"freeBytes": 1 << 40, "memoryAvailableBytes": 1 << 40}

        began = time.monotonic()
        with patch.dict(os.environ, {"INVOCATION_ID": "f" * 32}), \
                patch.object(build.sys, "stdout", output), \
                patch.object(build, "capacity", side_effect=capacity_after_parent_ready):
            self.assertNotEqual(build.run_child(self.op, intent), 0)
        self.assertLess(time.monotonic() - began, 10)
        self.assertTrue(ready.exists())
        self.assertFalse(done.exists(), "pipe holder must still be alive when supervisor returns")
        completed = build.read_private(self.op / "completed.json")
        self.assertEqual(completed["nativeExitCode"], native_exit)
        self.assertEqual(build.private_bytes(self.op / "build.exit"), f"{native_exit}\n".encode())
        self.assertFalse(completed["remoteSolveTerminationObserved"])
        if parent_behavior == "exit-zero":
            self.assertEqual(completed["exitCode"], 75)
            self.assertIn("output pipe still open", completed["reason"])
        else:
            self.assertEqual(completed["exitCode"], native_exit)
            self.assertEqual(completed["reason"], "build.capacity.memory_reserve")
        self.assertIn(b"native parent output", build.private_bytes(self.op / "build.log"))
        with patch.object(build, "native", return_value=self.show("active", "exited", "success", "1", "0")):
            self.assertEqual(build.status(self.op)["state"], "incomplete")
        self.assertFalse((self.op / "execution.json").exists())

    def test_capacity_failure_drains_inherited_pipe_without_losing_primary_result(self):
        self.assert_descendant_pipe_cannot_hold_supervisor("term-exit", 7)

    def test_ignored_term_escalates_owned_client_and_bounds_inherited_pipe(self):
        self.assert_descendant_pipe_cannot_hold_supervisor("ignore", 137)

    def test_zero_exit_with_inherited_open_pipe_cannot_be_reported_successful(self):
        self.assert_descendant_pipe_cannot_hold_supervisor("exit-zero", 0)

    def test_real_child_produces_hashed_private_execution_after_native_terminal_success(self):
        self.child_fixture()
        self.prepare()
        with patch.object(build, "native", side_effect=self.fake_native):
            build.start(self.op)
        _, intent = build.load_intent(self.op)
        output = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
        with patch.dict(os.environ, {"INVOCATION_ID": "f" * 32}), patch.object(build.sys, "stdout", output):
            self.assertEqual(build.run_child(self.op, intent), 0)
        self.assertFalse((self.op / "execution.json").exists())
        with patch.object(build, "native", return_value=self.show("active", "exited", "success", "1", "0")):
            self.assertEqual(build.status(self.op)["state"], "succeeded")
            self.assertEqual(build.status(self.op)["state"], "succeeded")
        execution = build.read_private(self.op / "execution.json")
        self.assertEqual(set(execution), set("""schema operationId attempt projectNumber instanceId
            toolingSha sourceSha sourceTree manifestSha256 inventorySha256 indexDigest builtAt
            startedAt completedAt buildExitCode buildMetadataSha256 buildLogSha256""".split()))
        self.assertEqual(execution["buildMetadataSha256"],
                         build.preflight.digest(self.op / "build-metadata.json"))
        self.assertEqual(execution["buildLogSha256"], build.preflight.digest(self.op / "build.log"))
        self.assertIn(b"native fixture output", build.private_bytes(self.op / "build.log"))
        resources = [json.loads(line) for line in
                     build.private_bytes(self.op / "resources.jsonl").splitlines()]
        self.assertEqual([row["phase"] for row in resources], ["start", "end"])
        self.assertTrue(all(row["scope"] == "host" and row["resources"]["freeBytes"] == 1 << 40
                            for row in resources))
        self.assertFalse(build.read_private(self.op / "completed.json")["remoteSolveTerminationObserved"])
        with self.assertRaises(FileExistsError), patch.dict(os.environ, {"INVOCATION_ID": "f" * 32}):
            build.run_child(self.op, intent)

    def test_unreadable_native_export_cannot_publish_execution_receipt(self):
        self.child_fixture()
        self.prepare()
        with patch.object(build, "native", side_effect=self.fake_native):
            build.start(self.op)
        _, intent = build.load_intent(self.op)
        output = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
        with patch.dict(os.environ, {"INVOCATION_ID": "f" * 32}), patch.object(build.sys, "stdout", output):
            self.assertEqual(build.run_child(self.op, intent), 0)
        with patch.object(build, "native", return_value=self.show("active", "exited", "success", "1", "0")), \
                patch.object(build.os, "scandir", side_effect=PermissionError("native OCI unreadable")):
            self.assertEqual(build.status(self.op)["state"], "incomplete")
        self.assertFalse((self.op / "execution.json").exists())

    def test_resource_sampling_failure_is_retained_without_replacing_native_failure(self):
        self.child_fixture(7)
        self.prepare()
        with patch.object(build, "native", side_effect=self.fake_native):
            build.start(self.op)
        _, intent = build.load_intent(self.op)
        output = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
        with patch.dict(os.environ, {"INVOCATION_ID": "f" * 32}), \
                patch.object(build.sys, "stdout", output), \
                patch.object(build, "resource_sample", side_effect=OSError("host sample unavailable")):
            self.assertEqual(build.run_child(self.op, intent), 7)
        resources = [json.loads(line) for line in
                     build.private_bytes(self.op / "resources.jsonl").splitlines()]
        self.assertEqual(resources[-1]["phase"], "end")
        self.assertEqual(resources[-1]["observationError"], "host sample unavailable")
        self.assertEqual(build.read_private(self.op / "completed.json")["exitCode"], 7)
        self.assertIn(b"native fixture output", build.private_bytes(self.op / "build.log"))

    def assert_resource_sink_failure_preserves_native_completion(self, failing_operation):
        self.child_fixture(7)
        self.prepare()
        with patch.object(build, "native", side_effect=self.fake_native):
            build.start(self.op)
        _, intent = build.load_intent(self.op)
        record_resources = build.record_resources
        persisted = []

        def broken_diagnostic_sink(op, phase, observed=None, cache=None, builder=None):
            with patch.object(build.os, failing_operation, side_effect=OSError("diagnostic sink failed")):
                persisted.append(record_resources(op, phase, observed, cache, builder))

        output = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
        previous_umask = os.umask(0o027)
        try:
            with patch.dict(os.environ, {"INVOCATION_ID": "f" * 32}), \
                    patch.object(build.sys, "stdout", output), \
                    patch.object(build.os, "write", return_value=0) as warning, \
                    patch.object(build, "record_resources", side_effect=broken_diagnostic_sink):
                self.assertEqual(build.run_child(self.op, intent), 7)
                self.assertTrue(warning.called)
            self.assertEqual(os.umask(0o027), 0o027)
        finally:
            os.umask(previous_umask)
        self.assertEqual(persisted, [False, False])
        self.assertEqual(build.private_bytes(self.op / "build.exit"), b"7\n")
        completed = build.read_private(self.op / "completed.json")
        self.assertEqual(completed["nativeExitCode"], 7)
        self.assertEqual(completed["exitCode"], 7)
        self.assertIn(b"native fixture output", build.private_bytes(self.op / "build.log"))
        self.assertFalse((self.op / "execution.json").exists())

    def test_resource_append_failure_preserves_native_completion_and_umask(self):
        self.assert_resource_sink_failure_preserves_native_completion("open")

    def test_resource_fsync_failure_preserves_native_completion_and_umask(self):
        self.assert_resource_sink_failure_preserves_native_completion("fsync")

    def test_real_nonzero_child_keeps_logs_without_execution_receipt(self):
        self.child_fixture(7)
        self.prepare()
        with patch.object(build, "native", side_effect=self.fake_native):
            build.start(self.op)
        _, intent = build.load_intent(self.op)
        output = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
        with patch.dict(os.environ, {"INVOCATION_ID": "f" * 32}), patch.object(build.sys, "stdout", output):
            self.assertEqual(build.run_child(self.op, intent), 7)
        with patch.object(build, "native", return_value=self.show("active", "exited", "success", "1", "0")):
            self.assertEqual(build.status(self.op)["state"], "incomplete")
        self.assertEqual(build.private_bytes(self.op / "build.exit"), b"7\n")
        self.assertFalse((self.op / "execution.json").exists())

    def test_cancel_targets_only_owned_service_and_is_once_only(self):
        self.prepare()
        calls = []
        with patch.object(build, "native", side_effect=self.fake_native):
            build.start(self.op)
        build.write_once(self.op / "started.json", build.encode({
            "startedAt": build.now(), "invocationId": "f" * 32}))

        def capture(argv):
            calls.append(argv)
            return self.show()

        with patch.object(build, "native", side_effect=capture):
            self.assertFalse(build.cancel(self.op)["remoteSolveTerminationObserved"])
            build.cancel(self.op)
        stops = [argv for argv in calls if "stop" in argv]
        self.assertEqual(stops, [[*build.SYSTEMCTL, "stop",
                                 f"openclaw-image-build-{self.config['operationId']}.service"]])
        self.assertFalse(any("docker" in " ".join(argv) for argv in calls))

    def test_cancel_does_not_stop_an_unproven_or_different_service_invocation(self):
        self.prepare()
        with patch.object(build, "native", side_effect=self.fake_native):
            build.start(self.op)
        with patch.object(build, "native") as native:
            with self.assertRaisesRegex(release.Refusal, "service_owner_unproven"):
                build.cancel(self.op)
            native.assert_not_called()
        build.write_once(self.op / "started.json", build.encode({
            "startedAt": build.now(), "invocationId": "e" * 32}))
        with patch.object(build, "native", return_value=self.show()) as native:
            with self.assertRaisesRegex(release.Refusal, "service_owner_unproven"):
                build.cancel(self.op)
            self.assertTrue(all("stop" not in call.args[0] for call in native.call_args_list))
        self.assertFalse((self.op / "cancel-intent.json").exists())

    def test_native_builder_identity_and_unbounded_io_are_observed_without_mutation(self):
        expected = self.config["builder"]
        builder, container = self.builder_fixture()
        calls = []

        def inspect(argv):
            calls.append(argv)
            return subprocess.CompletedProcess(
                argv, 0, "\n".join(json.dumps(row) for row in builder)
                if "buildx" in argv else json.dumps(container), "")

        with patch.object(build, "native", side_effect=inspect):
            self.assertEqual(self.observe_builder_impl(expected), expected)
            container["Id"] = "0" * 64
            with self.assertRaisesRegex(release.Refusal, "builder.changed"):
                self.observe_builder_impl(expected)
        self.assertTrue(all("stop" not in argv and "create" not in argv and "--bootstrap" not in argv
                            for argv in calls))
        for argv in calls:
            if "buildx" in argv:
                self.assertEqual(argv, [*build.DOCKER, "--host", build.ENDPOINT, "buildx", "ls",
                                        "--no-trunc", "--timeout", "10s",
                                        "--format", build.BUILDER_FORMAT])
            else:
                self.assertIn("inspect", argv)
            projection = argv[argv.index("--format") + 1]
            self.assertEqual(projection, build.BUILDER_FORMAT if "buildx" in argv
                             else build.CONTAINER_FORMAT)
            self.assertNotIn("{{json .}}", projection)
            self.assertNotIn("Env", projection)
            self.assertNotIn("Mounts", projection)

    def test_cache_contract_is_optional_closed_and_retained_in_the_operation(self):
        build.validate_config(self.config)
        build.validate_config({**self.config, "cache": None})
        cache, _, _ = self.cache_fixture()
        self.prepare()
        _, intent = build.load_intent(self.op)
        self.assertEqual(intent["config"]["cache"], cache)
        for change in (
                {"extra": "not allowed"}, {"volumeName": "another-volume"},
                {"backingPath": "relative/cache"}, {"backingPath": "/"},
                {"backingPath": str(self.root / "cache-disk") + "/../cache"},
                {"filesystemDevice": "2065"}, {"filesystemDevice": True},
                {"minFreeBytes": 0}):
            with self.subTest(change=change), self.assertRaisesRegex(release.Refusal, "build.cache"):
                build.validate_config({**self.config, "cache": {**cache, **change}})

    def test_native_cache_binding_is_exact_and_failed_admission_never_dispatches(self):
        cache, volume, mounts = self.cache_fixture()
        builder, container = self.builder_fixture()
        calls = []

        def inspect(argv):
            calls.append(argv)
            if "buildx" in argv:
                text = "\n".join(json.dumps(row) for row in builder)
            elif "volume" in argv:
                text = json.dumps(volume)
            elif build.CACHE_MOUNT_FORMAT in argv:
                text = "\n".join(json.dumps(row) for row in mounts)
            else:
                text = json.dumps(container)
            return subprocess.CompletedProcess(argv, 0, text, "")

        with patch.object(build, "native", side_effect=inspect):
            self.assertEqual(self.observe_builder_impl(self.config["builder"], cache),
                             self.config["builder"])
            self.assertEqual(calls[-2], [*build.DOCKER, "--host", build.ENDPOINT,
                                        "volume", "inspect", "--format",
                                        build.CACHE_VOLUME_FORMAT, cache["volumeName"]])
            self.assertEqual(calls[-1], [*build.DOCKER, "--host", build.ENDPOINT,
                                        "inspect", "--format", build.CACHE_MOUNT_FORMAT,
                                        self.config["builder"]["containerId"]])
            for key, value in (("Name", "other-volume"), ("Driver", "other-driver"),
                               ("Options", {**volume["Options"], "device": "/other/cache"}),
                               ("Options", {**volume["Options"], "o": "ro,bind"}),
                               ("Options", {**volume["Options"], "extra": "unreviewed"})):
                old = volume[key]
                with self.subTest(key=key, value=value):
                    volume[key] = value
                    with self.assertRaisesRegex(release.Refusal, "cache.volume_changed"):
                        self.observe_builder_impl(self.config["builder"], cache)
                volume[key] = old
            for key, value in (("Type", "bind"), ("Name", "other-volume"),
                               ("Source", "/other/mount"), ("Destination", "/other/target"),
                               ("Driver", "other-driver"), ("RW", False)):
                old = mounts[0][key]
                with self.subTest(key=key, value=value):
                    mounts[0][key] = value
                    with self.assertRaisesRegex(release.Refusal, "cache.mount_changed"):
                        self.observe_builder_impl(self.config["builder"], cache)
                mounts[0][key] = old
            self.prepare()
            mounts[0]["RW"] = False
            with patch.object(build, "observe_builder", self.observe_builder_impl):
                with self.assertRaisesRegex(release.Refusal, "cache.mount_changed"):
                    build.start(self.op)
        self.assertFalse((self.op / "start-intent.json").exists())
        self.assertFalse((self.op.parent /
                          f"builder-{self.config['builder']['containerId']}.json").exists())
        self.assertFalse(any("systemd-run" in " ".join(argv) or "create" in argv for argv in calls))
        for argv in calls:
            projection = argv[argv.index("--format") + 1]
            self.assertNotIn("{{json .}}", projection)
            self.assertNotIn("Env", projection)

    def test_cache_sample_refuses_symlink_and_changed_backing_or_parent_device(self):
        cache, _, _ = self.cache_fixture()
        backing = Path(cache["backingPath"])
        link = backing.parent / "linked-cache"
        link.symlink_to(backing)
        with self.assertRaisesRegex(release.Refusal, "cache.path_not_canonical"):
            build.cache_sample({**cache, "backingPath": str(link)})
        with self.assertRaisesRegex(release.Refusal, "cache.filesystem_changed"):
            build.cache_sample({**cache, "filesystemDevice": cache["filesystemDevice"] + 1})
        original_stat = Path.stat

        def changed_parent(path, *args, **kwargs):
            value = original_stat(path, *args, **kwargs)
            if path == backing.parent:
                fields = list(value)
                fields[2] += 1
                return os.stat_result(fields)
            return value

        with patch.object(Path, "stat", changed_parent):
            with self.assertRaisesRegex(release.Refusal, "cache.filesystem_changed"):
                build.cache_sample(cache)

    def test_root_owned_cache_uses_only_its_verified_parent_for_free_space(self):
        cache, _, _ = self.cache_fixture()
        backing = Path(cache["backingPath"])

        def disk_usage(path):
            if path == backing:
                raise PermissionError("BuildKit owns cache root")
            self.assertEqual(path, backing.parent)
            return SimpleNamespace(free=92 << 30)

        with patch.object(build.shutil, "disk_usage", side_effect=disk_usage) as usage:
            sample = build.cache_sample(cache)
        self.assertEqual(sample, {"cacheFreeBytes": 92 << 30,
                                  "cacheSamplePath": str(backing.parent),
                                  "cacheFilesystemDevice": cache["filesystemDevice"]})
        self.assertEqual(usage.call_count, 2)

    def test_root_cache_and_memory_reserves_are_independent_and_samples_are_timestamped(self):
        cache, _, _ = self.cache_fixture()
        limits = {**self.config["limits"], "minFreeBytes": 16 << 30,
                  "minMemoryAvailableBytes": 2 << 30}
        available = {"root": 30 << 30, "cache": 92 << 30, "memory": 8 << 30}

        def disk_usage(path):
            return SimpleNamespace(free=available["cache" if str(path) == cache["backingPath"]
                                                   else "root"])

        with patch.object(build, "resource_sample", self.resource_sample_impl), patch.object(
                build, "memory_pressure_sample", return_value={"some": {"avg10": 0.0,
                                                                          "avg60": 0.0},
                                                                      "full": {"avg10": 0.0,
                                                                               "avg60": 0.0}}), patch.object(
                Path, "read_text", side_effect=lambda: f"MemAvailable: {available['memory'] // 1024} kB\n"
                ), patch.object(build.shutil, "disk_usage", side_effect=disk_usage):
            sample = self.capacity_impl(self.root, limits, cache)
            self.assertEqual(sample["freeBytes"], 30 << 30)
            self.assertEqual(sample["cacheFreeBytes"], 92 << 30)
            self.assertEqual(sample["cacheFilesystemDevice"], cache["filesystemDevice"])
            build.preflight.utc(sample["observedAt"])
            for key, value, code in (("root", (16 << 30) - 1, "disk_reserve"),
                                     ("cache", (44 << 30) - 1, "cache_reserve"),
                                     ("memory", (2 << 30) - 1, "memory_reserve")):
                old = available[key]
                available[key] = value
                with self.subTest(key=key), self.assertRaisesRegex(release.Refusal, code):
                    self.capacity_impl(self.root, limits, cache)
                available[key] = old

    def test_flat_builder_rows_reject_ambiguous_driver_node_endpoint_and_status(self):
        expected = self.config["builder"]
        driver = {"Builder": expected["name"], "Name": expected["name"],
                  "DriverEndpoint": "docker-container", "Status": ""}
        node = {"Builder": expected["name"], "Name": expected["node"],
                "DriverEndpoint": build.ENDPOINT, "Status": "running"}
        cases = [[], [driver], [driver, driver, node], [driver, node, node]]
        for field, value in (("DriverEndpoint", "docker"), ("Status", "error")):
            cases.append([{**driver, field: value}, node])
        for field, value in (("Builder", "different"), ("Name", "different-node"),
                             ("DriverEndpoint", "unix:///other.sock"), ("Status", "stopped")):
            cases.append([driver, {**node, field: value}])
        for rows in cases:
            with self.subTest(rows=rows), patch.object(
                    build, "native", return_value=subprocess.CompletedProcess(
                        [], 0, "\n".join(json.dumps(row) for row in rows), "")) as native:
                with self.assertRaises(release.Refusal):
                    self.observe_builder_impl(expected)
                self.assertEqual(native.call_count, 1)

    def test_builder_discovery_failure_stays_before_reservation_and_dispatch(self):
        self.prepare()
        with patch.object(build, "observe_builder", self.observe_builder_impl), patch.object(
                build, "native", return_value=subprocess.CompletedProcess(
                    [], 125, "", "unknown flag: --format")) as native:
            with self.assertRaisesRegex(release.Refusal, "build.builder.inspect"):
                build.start(self.op)
            self.assertEqual(native.call_count, 1)
            self.assertIn("ls", native.call_args.args[0])
            self.assertNotIn("systemd-run", " ".join(native.call_args.args[0]))
        self.assertFalse((self.op / "start-intent.json").exists())
        self.assertFalse((self.op.parent /
                          f"builder-{self.config['builder']['containerId']}.json").exists())

    def test_metadata_handoff_is_exact_and_fails_closed_on_symlink_or_unchanged_owner(self):
        self.prepare()
        _, intent = build.load_intent(self.op)
        metadata = self.op / "build-metadata.json"
        metadata.symlink_to(self.manifest)
        with patch.object(build, "native") as native:
            with self.assertRaisesRegex(release.Refusal, "unsafe_output"):
                build.take_metadata(self.op, intent)
            native.assert_not_called()
        metadata.unlink()
        metadata.write_text("{}")
        fake = os.stat_result((stat.S_IFREG | 0o600, 42, 1, 1, 0, 0, 2, 0, 0, 0))
        intent = {**intent, "uid": 123, "gid": 456}
        with patch.object(Path, "lstat", return_value=fake), patch.object(
                build, "native", return_value=subprocess.CompletedProcess([], 0, "", "")) as native:
            with self.assertRaisesRegex(release.Refusal, "handoff_changed"):
                build.take_metadata(self.op, intent)
            self.assertEqual(native.call_args_list[-1].args[0],
                             [*build.CHOWN, "123:456", str(metadata)])

    def test_handoff_capability_failure_prevents_dispatch(self):
        self.prepare()
        with patch.object(build, "native",
                          return_value=subprocess.CompletedProcess([], 1, "", "denied")):
            with self.assertRaisesRegex(release.Refusal, "handoff_unavailable"):
                build.start(self.op)
        self.assertFalse((self.op / "start-intent.json").exists())

    def test_capacity_breach_joins_only_the_owned_client_and_cannot_finalize(self):
        self.child_fixture()
        self.prepare()
        with patch.object(build, "native", side_effect=self.fake_native):
            build.start(self.op)
        _, intent = build.load_intent(self.op)
        output = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
        with patch.dict(os.environ, {"INVOCATION_ID": "f" * 32}), patch.object(
                build.sys, "stdout", output), patch.object(build, "capacity", side_effect=[
                    {"freeBytes": 9999}, release.Refusal("build.capacity.disk_reserve")]):
            self.assertNotEqual(build.run_child(self.op, intent), 0)
        completed = build.read_private(self.op / "completed.json")
        self.assertEqual(completed["reason"], "build.capacity.disk_reserve")
        self.assertFalse(completed["remoteSolveTerminationObserved"])
        with patch.object(build, "native", return_value=self.show("active", "exited", "success", "1", "0")):
            self.assertEqual(build.status(self.op)["state"], "incomplete")
        self.assertFalse((self.op / "execution.json").exists())

    def test_cache_budget_breach_joins_owned_client_and_retains_both_disk_samples(self):
        cache, _, _ = self.cache_fixture()
        self.child_fixture()
        self.prepare()
        with patch.object(build, "native", side_effect=self.fake_native):
            build.start(self.op)
        _, intent = build.load_intent(self.op)
        count = 0

        def sample(_op, configured_cache):
            nonlocal count
            self.assertEqual(configured_cache, cache)
            count += 1
            return {"observedAt": build.now(), "freeBytes": 30 << 30,
                    "memoryAvailableBytes": 8 << 30,
                    "cacheFreeBytes": (92 << 30) if count == 1 else cache["minFreeBytes"] - 1,
                    "cacheSamplePath": cache["backingPath"],
                    "cacheFilesystemDevice": cache["filesystemDevice"]}

        output = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
        with patch.dict(os.environ, {"INVOCATION_ID": "f" * 32}), patch.object(
                build.sys, "stdout", output), patch.object(
                build, "capacity", self.capacity_impl), patch.object(
                build, "resource_sample", side_effect=sample):
            self.assertNotEqual(build.run_child(self.op, intent), 0)
        completed = build.read_private(self.op / "completed.json")
        self.assertEqual(completed["reason"], "build.capacity.cache_reserve")
        self.assertFalse(completed["remoteSolveTerminationObserved"])
        resources = [json.loads(line) for line in
                     build.private_bytes(self.op / "resources.jsonl").splitlines()]
        failure = next(row for row in resources if row["phase"] == "reserve-failed")
        self.assertEqual(failure["resources"]["freeBytes"], 30 << 30)
        self.assertEqual(failure["resources"]["cacheFreeBytes"], cache["minFreeBytes"] - 1)
        build.preflight.utc(failure["resources"]["observedAt"])
        with patch.object(build, "native", return_value=self.show("active", "exited", "success", "1", "0")):
            self.assertEqual(build.status(self.op)["state"], "incomplete")
        self.assertFalse((self.op / "execution.json").exists())


class NoCreateSettlementTests(unittest.TestCase):
    """Real private receipts/reservation; only the native service is synthetic."""
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.trials, self.builds, self.heavy = (self.root / name for name in ("trials", "builds", "heavy"))
        for root in (self.trials, self.builds, self.heavy):
            root.mkdir(mode=0o700)
        self.op = self.trials / ("a" * 32)
        self.op.mkdir(mode=0o700)
        plan = {"operationId": self.op.name, "imageReceiptSha256": "b" * 64,
                "cleanInputSha256": "c" * 64, "phase": "doctor", "checkInputSha256": "d" * 64}
        self.invocation = "e" * 32
        self.completed = {"operationId": self.op.name, "invocationId": self.invocation,
            "state": "failed", "cleanup": "not_started", "containerId": None, "nativeState": None,
            "nativeExitCode": None, "cgroupSettlementObserved": False, "doctorComplete": False,
            "oomKillDelta": 0, "imageReceiptSha256": plan["imageReceiptSha256"],
            "cleanInputSha256": plan["cleanInputSha256"], "phase": "doctor",
            "checkInputSha256": plan["checkInputSha256"]}
        build.write_once(self.op / "intent.json", build.encode({"plan": plan}))
        self.hashed = build.preflight.digest(self.op / "intent.json")
        for name, value in (("start-intent.json", {"intentSha256": self.hashed}),
                            ("started.json", {"invocationId": self.invocation}), ("result.json", self.completed)):
            build.write_once(self.op / name, build.encode(value))
        self.owner = {"kind": "doctor", "operationPath": str(self.op), "intentSha256": self.hashed}
        self.service = {"LoadState": "loaded", "InvocationID": self.invocation, "MainPID": "0",
            "ExecMainCode": "1", "ExecMainStatus": "1", "Result": "exit-code",
            "ActiveState": "failed", "SubState": "failed"}
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for name, value in (("TRIAL_ROOT", self.trials), ("PRIVATE_ROOT", self.builds), ("HEAVY_ROOT", self.heavy)):
            self.stack.enter_context(patch.object(build, name, value))
        self.native = self.stack.enter_context(patch.object(build, "native", side_effect=self.observe_service))

    def observe_service(self, argv):
        self.assertIn("show", argv)
        self.assertIn("openclaw-snapshot-doctor-" + self.op.name + ".service", argv)
        return subprocess.CompletedProcess(argv, 0, "\n".join(f"{k}={v}" for k, v in self.service.items()), "")

    def test_proven_no_create_failure_releases_shared_slot_for_build_or_trial(self):
        self.assertEqual(build.prove_trial_no_create_failure(self.op, self.hashed), self.completed)
        for kind, root in (("build", self.builds), ("doctor", self.trials)):
            with self.subTest(kind=kind):
                release.atomic_json(self.heavy / "owner.json", self.owner)
                next_op = root / ("f" * 32)
                next_op.mkdir(mode=0o700)
                build.write_once(next_op / "intent.json", b"{}\n")
                build.reserve_heavy_workload(next_op, kind, build.preflight.digest(next_op / "intent.json"))
                self.assertEqual(build.read_private(self.heavy / "owner.json")["operationPath"], str(next_op))
                self.assertEqual(len(list(self.heavy.glob("settled-*.json"))), 1)

    def test_create_markers_and_dangling_marker_never_release_shared_slot(self):
        release.atomic_json(self.heavy / "owner.json", self.owner)
        next_op = self.builds / ("f" * 32)
        next_op.mkdir(mode=0o700)
        build.write_once(next_op / "intent.json", b"{}\n")
        for name in ("create-intent.json", "container.json", "container-start-intent.json"):
            for dangling in (False, True):
                with self.subTest(name=name, dangling=dangling):
                    marker = self.op / name
                    if dangling:
                        marker.symlink_to(self.op / "missing")
                    else:
                        build.write_once(marker, b"{}\n")
                    with self.assertRaisesRegex(release.Refusal, "workload.owned_or_uncertain"):
                        build.reserve_heavy_workload(next_op, "build", build.preflight.digest(next_op / "intent.json"))
                    self.assertEqual(build.read_private(self.heavy / "owner.json"), self.owner)
                    marker.unlink()

    def test_exact_terminal_service_and_result_binding_are_required(self):
        for key, value in (("InvocationID", "f" * 32), ("MainPID", "12"), ("Result", "timeout"),
                           ("ExecMainStatus", "0"), ("ExecMainCode", "2"), ("SubState", "running"),
                           ("ActiveState", "active"), ("LoadState", "not-found")):
            with self.subTest(service=key):
                original = self.service[key]
                self.service[key] = value
                with self.assertRaisesRegex(release.Refusal, "workload.no_create.service_unsettled"):
                    build.prove_trial_no_create_failure(self.op, self.hashed)
                self.service[key] = original
        for key, value in (("invocationId", "f" * 32), ("imageReceiptSha256", "0" * 64),
                           ("checkInputSha256", "0" * 64), ("state", "succeeded"), ("containerId", "1" * 64),
                           ("nativeState", {}), ("nativeExitCode", 0), ("cgroupSettlementObserved", True)):
            with self.subTest(result=key):
                release.atomic_json(self.op / "result.json", {**self.completed, key: value})
                with self.assertRaises(release.Refusal):
                    build.prove_trial_no_create_failure(self.op, self.hashed)
        release.atomic_json(self.op / "result.json", self.completed)
        release.atomic_json(self.op / "start-intent.json", {"intentSha256": "0" * 64})
        with self.assertRaisesRegex(release.Refusal, "workload.no_create.binding"):
            build.prove_trial_no_create_failure(self.op, self.hashed)

    def test_marker_appearing_during_service_observation_remains_uncertain(self):
        def observe(argv):
            build.write_once(self.op / "create-intent.json", b"{}\n")
            return self.observe_service(argv)
        with patch.object(build, "native", side_effect=observe):
            with self.assertRaisesRegex(release.Refusal, "workload.no_create.dispatch_uncertain"):
                build.prove_trial_no_create_failure(self.op, self.hashed)


if __name__ == "__main__":
    unittest.main()
