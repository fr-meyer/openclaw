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

    def test_bound_command_and_closed_configuration(self):
        op = self.prepare()
        _, intent = build.load_intent(op)
        command = intent["buildArgv"]
        self.assertEqual(command[:3], list(build.DOCKER))
        self.assertEqual(command[command.index("--network") + 1], "none")
        self.assertEqual(command[-1], "https://github.com/fr-meyer/openclaw.git#" +
                         self.config["sourceSha"])
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

        def broken_diagnostic_sink(op, phase, observed=None):
            with patch.object(build.os, failing_operation, side_effect=OSError("diagnostic sink failed")):
                persisted.append(record_resources(op, phase, observed))

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
        builder = [
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


if __name__ == "__main__":
    unittest.main()
