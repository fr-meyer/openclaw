"""Synthetic transport contracts plus Linux-only native entry preflight fixtures.

Run in the secretless test container with the prepared root yaml dependency.
No Docker is started; Node fixtures exercise the actual entry code with private
fixture paths and a recording test wrapper, never application test code.
"""

import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import source_tests as tests


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        uid = patch.object(tests.os, "getuid", return_value=1000)
        uid.start()
        self.addCleanup(uid.stop)
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / "source"
        self.deps = self.root / "dependencies"
        self.pnpm = self.root / "pnpm"
        (self.pnpm / "bin").mkdir(parents=True)
        (self.pnpm / "package.json").write_text(json.dumps({
            "name": "pnpm", "version": "12.9.0", "bin": {"pnpm": "pnpm"}}))
        (self.pnpm / "pnpm").write_text("#!/usr/bin/env node\nimport './bin/pnpm.mjs';\n")
        (self.pnpm / "pnpm").chmod(0o700)
        (self.pnpm / "bin/pnpm.mjs").write_text("// Synthetic; never executed.\n")
        self.output = self.root / "output"
        self.source.mkdir()
        self.deps.mkdir()
        self.package = {"packageManager": "pnpm@12.9.0+sha512." + "a" * 128,
                        "devDependencies": {"vitest": "5.0.1"},
                        "dependencies": {"@modelcontextprotocol/sdk": "1.32.0"}}
        self.files = {"package.json": json.dumps(self.package),
                      "pnpm-workspace.yaml": "packages: []\n",
                      "pnpm-lock.yaml": "---\nlockfileVersion: '9.0'\n---\nlockfileVersion: '9.0'\n",
                      "test/example.test.ts": "// synthetic source; not executed\n",
                      ".env.example": "EXAMPLE=synthetic\n"}
        for name, contents in self.files.items():
            for root in (self.source, self.deps):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(contents)
        (self.deps / "node_modules/.pnpm").mkdir(parents=True)
        (self.deps / "node_modules/.pnpm/lock.yaml").write_text("lockfileVersion: '9.0'\n")
        for args in (("init", "-q"), ("add", "."),
                     ("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                      "-c", "commit.gpgsign=false", "commit", "-qm", "fixture")):
            tests.git(self.source, *args)
        self.sha = tests.git(self.source, "rev-parse", "HEAD")
        self.image = "sha256:" + "a" * 64

    def prepare(self, **kwargs):
        options = {"source": self.source, "dependencies": self.deps, "pnpm_dir": self.pnpm, "output": self.output,
                   "sha": self.sha, "image": self.image, "tests": ["test/example.test.ts"]}
        options.update(kwargs)
        return tests.prepare(**options)

    def test_source_export_preserves_binding_without_git_or_private_templates(self):
        output, expected, modules = self.prepare()
        self.assertEqual(expected["sourceSha"], self.sha)
        self.assertEqual(expected["dependencies"], self.package["dependencies"] | self.package["devDependencies"])
        self.assertEqual(modules, ["node_modules"])
        self.assertEqual((output / "source/test/example.test.ts").read_text(), self.files["test/example.test.ts"])
        self.assertFalse((output / "source/.git").exists())
        self.assertFalse((output / "source/.env.example").exists())
        self.assertEqual((output / "entry.mjs").stat().st_mode & 0o777, 0o444)
        self.assertEqual(output.stat().st_mode & 0o777, 0o700)
        self.assertTrue((output / "source/node_modules").is_dir())
        self.assertTrue((output / "source/.cache").is_dir())
        self.assertEqual(expected["installedLockSha256"], tests.digest(self.deps / "node_modules/.pnpm/lock.yaml"))

    def test_changed_dependency_inputs_require_preparation_before_container(self):
        (self.deps / "package.json").write_text("{}")
        with self.assertRaisesRegex(tests.Refusal, "preparation_required.manifests"):
            self.prepare()
        self.assertFalse(self.output.exists())

    def test_output_cannot_overlap_source_or_dependencies(self):
        for root in (self.source, self.deps, self.pnpm):
            with self.subTest(root=root), self.assertRaisesRegex(tests.Refusal, "output_overlaps_input"):
                self.prepare(output=root / "scratch")

    def test_refuses_dirty_source_and_non_file_filters(self):
        for value in ("--watch", "test/", "../example.test.ts", "/test/example.test.ts",
                      "test/example.test.ts --watch"):
            with self.subTest(value=value), self.assertRaisesRegex(tests.Refusal, "explicit_tracked_files"):
                self.prepare(tests=[value])
        (self.source / "test/example.test.ts").write_text("changed\n")
        with self.assertRaisesRegex(tests.Refusal, "dirty_source"):
            self.prepare()

    def test_container_has_only_readonly_host_mounts_and_no_inherited_process_env(self):
        output, expected, modules = self.prepare()
        command = tests.create_argv(output, self.deps, self.pnpm, expected, modules)
        mounts = [command[index + 1] for index, part in enumerate(command) if part == "--mount"]
        self.assertTrue(all(value.endswith(",readonly") for value in mounts))
        self.assertFalse(any("docker.sock" in value or "/.git" in value for value in mounts))
        self.assertEqual(command[command.index("--network") + 1], "none")
        self.assertEqual(command[command.index("--pull") + 1], "never")
        self.assertIn("--no-healthcheck", command)
        self.assertEqual(command[command.index("--memory") + 1], command[command.index("--memory-swap") + 1])
        self.assertEqual(command[command.index("--entrypoint") + 1], "/usr/bin/env")
        self.assertEqual(command[command.index(expected["imageDigest"]) + 1], "-i")
        self.assertNotIn("--privileged", command)
        self.assertEqual(command[-2:], ["node", "/control/entry.mjs"])
        self.assertEqual(command[-6:-2], ["timeout", "--signal=TERM", "--kill-after=5s", "300s"])
        self.assertIn("max-size=10m", command)
        self.assertIn("compress=false", command)
        self.assertIn("/tmp:rw,nosuid,nodev,exec,size=512m,mode=1777", command)
        with patch.object(tests.os, "getuid", return_value=0), self.assertRaisesRegex(tests.Refusal, "non_root_operator"):
            tests.create_argv(output, self.deps, self.pnpm, expected, modules)

    def run_fake(self, oom=False, timeout=False, cleanup_failure=False, logs_failure=False,
                 start_failure=False):
        output, expected, modules = self.prepare()
        container = "b" * 64
        calls = []

        def native(argv, **kwargs):
            calls.append(argv)
            if "create" in argv:
                return subprocess.CompletedProcess(argv, 0, container + "\n", "")
            if "start" in argv and start_failure:
                raise subprocess.CalledProcessError(1, argv, output="", stderr="synthetic daemon start failure")
            if "wait" in argv and timeout:
                raise subprocess.TimeoutExpired(argv, 1)
            if "inspect" in argv:
                return subprocess.CompletedProcess(argv, 0, json.dumps({
                    "Running": False, "ExitCode": 0, "OOMKilled": oom}), "")
            if "rm" in argv and cleanup_failure:
                raise subprocess.CalledProcessError(1, argv)
            return subprocess.CompletedProcess(argv, 0, "", "")

        def logs(argv, **kwargs):
            kwargs["stdout"].write(b"2026-01-01T00:00:00Z native output\n")
            if logs_failure:
                raise subprocess.TimeoutExpired(argv, 1)
            return subprocess.CompletedProcess(argv, 0)

        with patch.object(tests.sys, "platform", "linux"), patch.object(tests, "native", side_effect=native), \
                patch.object(tests.subprocess, "run", side_effect=logs), contextlib.redirect_stdout(io.StringIO()):
            code = tests.run(output, self.deps, self.pnpm, expected, modules)
        return code, json.loads((output / "receipt.json").read_text()), calls

    def test_zero_exit_with_oom_is_failed_and_exact_container_is_removed(self):
        code, receipt, calls = self.run_fake(oom=True)
        self.assertEqual(code, 1)
        self.assertEqual(receipt["state"], "failed")
        self.assertEqual(calls[-1], [*tests.DOCKER, "rm", "--force", "b" * 64])
        self.assertFalse(receipt["productionEligible"])

    def test_timeout_stops_only_owned_container_and_cannot_be_passed(self):
        code, receipt, calls = self.run_fake(timeout=True)
        self.assertEqual(code, 1)
        self.assertEqual(receipt["failure"], "tests.timeout")
        self.assertIn([*tests.DOCKER, "stop", "--time", "5", "b" * 64], calls)

    def test_log_failure_still_removes_owned_container(self):
        code, receipt, calls = self.run_fake(logs_failure=True)
        self.assertEqual(code, 1)
        self.assertEqual(receipt["failure"], "tests.logs_unavailable")
        self.assertEqual(calls[-1], [*tests.DOCKER, "rm", "--force", "b" * 64])

    def test_cleanup_failure_prevents_success(self):
        code, receipt, _ = self.run_fake(cleanup_failure=True)
        self.assertEqual(code, 1)
        self.assertEqual(receipt["failure"], "tests.cleanup_unconfirmed")

    def test_native_start_failure_survives_log_and_cleanup_failures(self):
        code, receipt, _ = self.run_fake(start_failure=True, logs_failure=True, cleanup_failure=True)
        self.assertEqual(code, 1)
        self.assertEqual(receipt["failure"], "CalledProcessError")
        self.assertEqual(receipt["nativeFailure"]["stderr"], "synthetic daemon start failure")
        self.assertEqual(receipt["logFailure"], "tests.logs_unavailable")
        self.assertEqual(receipt["cleanupFailure"], "tests.cleanup_unconfirmed")

    def test_clean_native_exit_passes_with_bound_versions(self):
        code, receipt, _ = self.run_fake()
        self.assertEqual(code, 0)
        self.assertEqual(receipt["state"], "passed")
        self.assertEqual(receipt["pnpmVersion"], "12.9.0")
        self.assertEqual(receipt["lockSha256"], tests.digest(self.source / "pnpm-lock.yaml"))
        self.assertFalse(receipt["logRetention"]["compress"])


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()

    def extract(self, entries):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            for name, kind, payload in entries:
                member = tarfile.TarInfo(name)
                member.type = kind
                member.mode = 0o755 if name.endswith(".sh") else 0o644
                if kind == tarfile.SYMTYPE or kind == tarfile.LNKTYPE:
                    member.linkname = payload
                elif kind == tarfile.REGTYPE:
                    member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload) if kind == tarfile.REGTYPE else None)
        buffer.seek(0)
        destination = self.root / "export"
        destination.mkdir()
        with tarfile.open(fileobj=buffer) as archive:
            tests.export_archive(archive, destination)
        return destination

    def test_regular_files_executable_bit_and_internal_symlink(self):
        result = self.extract([("bin/run.sh", tarfile.REGTYPE, b"#!/bin/sh\n"),
                               ("run", tarfile.SYMTYPE, "bin/run.sh")])
        self.assertEqual((result / "run").read_bytes(), b"#!/bin/sh\n")
        self.assertTrue((result / "bin/run.sh").stat().st_mode & 0o100)
        self.assertTrue((result / "run").is_symlink())

    def test_parent_traversal_and_hardlink_are_refused(self):
        for entries in ([('../outside', tarfile.REGTYPE, b"no")],
                        [('alias', tarfile.LNKTYPE, 'outside')]):
            with self.subTest(entries=entries), tempfile.TemporaryDirectory(dir=self.root) as unique:
                previous, self.root = self.root, Path(unique)
                try:
                    with self.assertRaisesRegex(tests.Refusal, "source_archive_entry"):
                        self.extract(entries)
                finally:
                    self.root = previous
        self.assertFalse((self.root / "outside").exists())

    def test_symlink_ancestor_cannot_redirect_file_write(self):
        with self.assertRaisesRegex(tests.Refusal, "source_archive_link_ancestor"):
            self.extract([("target/data", tarfile.REGTYPE, b"safe"),
                          ("alias", tarfile.SYMTYPE, "target"),
                          ("alias/overwritten", tarfile.REGTYPE, b"no")])
        self.assertFalse((self.root / "export/target/data").exists())

    def test_symlink_escape_is_refused_before_writes(self):
        with self.assertRaisesRegex(tests.Refusal, "source_archive_link"):
            self.extract([("target/data", tarfile.REGTYPE, b"safe"),
                          ("alias", tarfile.SYMTYPE, "../outside")])
        self.assertFalse((self.root / "export/target/data").exists())

    def test_duplicate_entry_cannot_replace_previous_file(self):
        with self.assertRaisesRegex(tests.Refusal, "source_archive_entry"):
            self.extract([("target", tarfile.REGTYPE, b"first"),
                          ("target", tarfile.REGTYPE, b"replacement")])


@unittest.skipUnless(sys.platform == "linux" and os.environ.get("OPENCLAW_SOURCE_TEST_PNPM_DIR"),
                     "Native entry fixtures require opt-in OPENCLAW_SOURCE_TEST_PNPM_DIR in secretless Linux")
class NativeEntryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.workspace = self.root / "workspace"
        self.control = self.root / "control"
        self.workspace.mkdir()
        self.control.mkdir()
        self.package = {"packageManager": "pnpm@12.9.0",
                        "dependencies": {"@modelcontextprotocol/sdk": "1.32.0"},
                        "devDependencies": {"vitest": "5.0.1"}}
        (self.workspace / "package.json").write_text(json.dumps(self.package))
        for name, version in {"vitest": "5.0.1", "@modelcontextprotocol/sdk": "1.32.0"}.items():
            path = self.workspace / "node_modules" / name
            path.mkdir(parents=True)
            (path / "package.json").write_text(json.dumps({"name": name, "version": version}))
        yaml_package = Path(__file__).resolve().parents[2] / "node_modules/yaml"
        self.assertTrue(yaml_package.is_dir(), "Native entry fixtures need the prepared root yaml dependency")
        (self.workspace / "node_modules/yaml").symlink_to(yaml_package, target_is_directory=True)
        (self.workspace / "node_modules/.pnpm").mkdir()
        (self.workspace / "scripts").mkdir()
        self.marker = self.workspace / "wrapper-invoked.json"
        (self.workspace / "scripts/run-vitest.mjs").write_text(
            'import fs from "node:fs"; fs.writeFileSync("wrapper-invoked.json", '
            'JSON.stringify(process.argv.slice(2))); console.log("wrapper completed");\n')
        pnpm_root = os.environ.get("OPENCLAW_SOURCE_TEST_PNPM_DIR")
        self.assertIsNotNone(pnpm_root, "Set OPENCLAW_SOURCE_TEST_PNPM_DIR to the readonly prepared 12.9.0 package")
        self.pnpm = Path(pnpm_root).resolve(strict=True)
        self.expected = {"pnpmVersion": "12.9.0", "pnpmEntrypoint": "pnpm",
                         "pnpmFileSha256": {name: tests.digest(self.pnpm / name)
                             for name in ("package.json", "pnpm", "bin/pnpm.mjs")}, "workers": 1,
                         "dependencies": {"vitest": "5.0.1", "@modelcontextprotocol/sdk": "1.32.0"},
                         "tests": ["test/example.test.ts"]}
        self.manager = {"lockfileVersion": "9.0", "importers": {".": {
            "configDependencies": {}, "packageManagerDependencies": {
                "pnpm": {"specifier": "12.9.0", "version": "12.9.0"}}}},
            "packages": {}, "snapshots": {}}
        self.project = {"lockfileVersion": "9.0", "settings": {"autoInstallPeers": True},
                        "importers": {".": {"dependencies": {"x": {"specifier": "1.0.0", "version": "1.0.0"}}}},
                        "packages": {"x@1.0.0": {"resolution": {"integrity": "sha512-fixture"}}},
                        "snapshots": {"x@1.0.0": {}}}
        self.installed = json.loads(json.dumps(self.project))
        self.entry = self.control / "entry.mjs"
        # Only fixture locations differ; all parsing, version admission and the
        # actual spawnSync wrapper dispatch execute the shipped ENTRY bytes.
        self.entry.write_text(tests.ENTRY.replace("/workspace", str(self.workspace))
                              .replace("/control", str(self.control)).replace("/toolchain/pnpm", str(self.pnpm)))

    def execute(self):
        (self.workspace / "pnpm-lock.yaml").write_text(
            "---\n" + json.dumps(self.manager) + "\n---\n" + json.dumps(self.project) + "\n")
        (self.workspace / "node_modules/.pnpm/lock.yaml").write_text(
            json.dumps(self.installed, sort_keys=True, indent=2))
        (self.control / "expected.json").write_text(json.dumps(self.expected))
        return subprocess.run(["node", str(self.entry)], cwd=self.workspace, capture_output=True,
                              text=True, timeout=40, env={**tests.ENV, "HOME": str(self.root),
                              "COREPACK_ENABLE_NETWORK": "0",
                              "npm_config_manage_package_manager_versions": "false"})

    def test_native_multidocument_lock_normalization_and_wrapper_dispatch(self):
        result = self.execute()
        if result.returncode:
            self.fail(json.dumps({"entryStderr": result.stderr, "entryStdout": result.stdout,
                                  "entryReturnCode": result.returncode}))
        self.assertEqual(json.loads(self.marker.read_text()), ["run", "--configLoader", "runner",
                         "--maxWorkers=1", "test/example.test.ts"])
        preflight = json.loads(result.stdout.splitlines()[0])
        self.assertEqual(preflight["pnpm"], "12.9.0")
        self.assertEqual(preflight["versions"], self.expected["dependencies"])

    def test_native_semantic_lock_change_does_not_invoke_wrapper(self):
        self.installed["settings"]["autoInstallPeers"] = False
        result = self.execute()
        self.assertEqual(result.returncode, 78)
        self.assertIn("tests.preparation_required.lock", result.stderr)
        self.assertFalse(self.marker.exists())

    def test_native_config_dependency_change_requires_preparation(self):
        self.manager["importers"]["."]["configDependencies"] = {"new-config": "1.0.0"}
        result = self.execute()
        self.assertEqual(result.returncode, 78)
        self.assertIn("tests.preparation_required.lock", result.stderr)
        self.assertFalse(self.marker.exists())

    def test_native_installed_version_change_does_not_invoke_wrapper(self):
        (self.workspace / "node_modules/vitest/package.json").write_text('{"version":"5.0.2"}')
        result = self.execute()
        self.assertEqual(result.returncode, 78)
        self.assertIn("tests.preparation_required.version", result.stderr)
        self.assertFalse(self.marker.exists())

    def test_native_pnpm_version_is_observed_before_wrapper(self):
        self.expected["pnpmVersion"] = "12.9.1"
        self.manager["importers"]["."]["packageManagerDependencies"]["pnpm"] = {
            "specifier": "12.9.1", "version": "12.9.1"}
        result = self.execute()
        self.assertEqual(result.returncode, 78)
        self.assertIn("tests.preparation_required.pnpm", result.stderr)
        self.assertFalse(self.marker.exists())


if __name__ == "__main__":
    unittest.main()
