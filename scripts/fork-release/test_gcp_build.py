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
        self.stack.enter_context(patch.object(build, "PRIVATE_ROOT", self.root / "private"))
        self.stack.enter_context(patch.object(build, "tooling_bytes", return_value=self.helpers))
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
        op = self.prepare()
        _, intent = build.load_intent(op)
        command = intent["buildArgv"]
        self.assertEqual(command[:3], list(build.DOCKER))
        self.assertEqual(command[command.index("--network") + 1], "none")
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

        def capacity_after_parent_ready(*_args):
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

        def broken_diagnostic_sink(op, phase, observed=None, cache=None):
            with patch.object(build.os, failing_operation, side_effect=OSError("diagnostic sink failed")):
                persisted.append(record_resources(op, phase, observed, cache))

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


if __name__ == "__main__":
    unittest.main()
