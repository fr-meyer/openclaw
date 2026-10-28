"""Bootstrap boundary with inert files and mocked runtimes; no package execution."""

from contextlib import redirect_stdout
import errno
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("v108_bootstrap_driver", Path(__file__).with_name("source_validation_v108.py"))
driver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(driver)


class PnpmBootstrapTests(unittest.TestCase):
    def invoke_main(self, mutation=None):
        """Exercise the registered run path, replacing every external runtime."""
        calls, output, failure = [], io.StringIO(), None
        package = {"name": "pnpm", "version": "12.15.0", "type": "module",
                   "bin": {"pnpm": "pnpm", "pn": "pn", "pnpx": "pnpx", "pnx": "pnx"},
                   "optionalDependencies": {"@pnpm/exe.linux-x64": "12.15.0"}}
        if mutation in ("package-name", "package-version", "package-bin", "optional-version"):
            if mutation == "package-name":
                package["name"] = "other"
            elif mutation == "package-version":
                package["version"] = "12.14.0"
            elif mutation == "package-bin":
                package["bin"]["pnpm"] = "elsewhere"
            else:
                package["optionalDependencies"]["@pnpm/exe.linux-x64"] = "12.14.0"
        files = {"package.json": json.dumps(package, sort_keys=True).encode(),
                 "install.js": b"// inert initializer fixture; never executed\n",
                 "native-binary.mjs": b"// inert local import fixture; never executed\n"}
        pins = {name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()}
        if mutation in ("installer-integrity", "helper-integrity", "manifest-integrity"):
            name = {"installer-integrity": "install.js", "helper-integrity": "native-binary.mjs",
                    "manifest-integrity": "package.json"}[mutation]
            files[name] += b"unexpected"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            runtimes, source, pipeline = root / "runtimes", root / "source", root / "pipeline"
            for path in (runtimes, source, pipeline):
                path.mkdir()
            for name in ("node", "npm"):
                (runtimes / name).write_bytes(b"inert runtime fixture; never executed")
                (runtimes / name).chmod(0o755)
            outside = root / "outside"
            outside.write_bytes(b"inert outside fixture; never executed")
            event = root / "event.json"
            event.write_text("{}")
            toolchain_seen = []

            def runner(argv, **kwargs):
                argv = list(argv)
                if argv[0] == str(runtimes / "npm"):
                    calls.append(("download", argv, kwargs))
                    self.assertIn("--ignore-scripts", argv)
                    self.assertNotIn("--global", argv)
                    self.assertEqual(argv[-1], "pnpm@12.15.0")
                    toolchain = Path(argv[argv.index("--prefix") + 1])
                    toolchain_seen.append(toolchain)
                    self.assertEqual(kwargs["cwd"], toolchain)
                    wrapper = toolchain / "node_modules/pnpm"
                    wrapper.mkdir(parents=True)
                    for name, raw in files.items():
                        (wrapper / name).write_bytes(raw)
                    if mutation == "initializer-path":
                        (wrapper / "install.js").unlink()
                        (wrapper / "install.js").symlink_to(outside)
                    if mutation == "download-failure":
                        raise subprocess.CalledProcessError(1, argv, output=b"never print this output")
                elif argv == [str(runtimes / "node"), str(toolchain_seen[0] / "node_modules/pnpm/install.js")]:
                    calls.append(("initialize", argv, kwargs))
                    self.assertTrue(kwargs["check"])
                    self.assertEqual(kwargs["stdout"], subprocess.DEVNULL)
                    self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
                    if mutation == "initializer-failure":
                        raise subprocess.CalledProcessError(1, argv, output=b"never print this output")
                    native = toolchain_seen[0] / "node_modules/pnpm/pnpm"
                    native.write_bytes(b"\x7fELF inert native fixture; never executed")
                    native.chmod(0o755)
                    link = toolchain_seen[0] / "node_modules/.bin/pnpm"
                    link.parent.mkdir()
                    link.symlink_to(native)
                    if mutation == "native-path":
                        native.unlink()
                        native.symlink_to(outside)
                    elif mutation == "native-format":
                        native.write_bytes(b"# no shebang; inert\nexit 0\n")
                    elif mutation == "native-permission":
                        native.chmod(0o644)
                    elif mutation == "command-link":
                        link.unlink()
                        link.symlink_to(outside)
                elif argv[1:] == ["install", "--frozen-lockfile"]:
                    calls.append(("project-install", argv, kwargs))
                    self.assertEqual(Path(argv[0]), toolchain_seen[0] / "node_modules/pnpm/pnpm")
                    self.assertEqual(kwargs["cwd"], source)
                    self.assertNotIn("--ignore-scripts", argv)
                else:
                    calls.append(("project-command", argv, kwargs))
                    self.assertEqual(Path(argv[0]), toolchain_seen[0] / "node_modules/pnpm/pnpm")
                    self.assertEqual(argv[1:], ["tsgo:prod"])
                    self.assertEqual(kwargs["cwd"], source)
                return SimpleNamespace(returncode=0)

            def version(argv, **kwargs):
                toolchain = toolchain_seen[0]
                self.assertEqual(kwargs["cwd"], toolchain)
                if argv[0] == str(toolchain / "node_modules/pnpm/pnpm"):
                    calls.append(("pnpm-version", list(argv), kwargs))
                    if mutation == "version-oserror":
                        raise OSError(errno.ENOEXEC, "never print this error")
                    return "12.14.0\n" if mutation == "pnpm-version" else "12.15.0\n"
                self.assertEqual(argv, [str(runtimes / "node"), "--version"])
                calls.append(("node-version", list(argv), kwargs))
                return "v24.22.0\n" if mutation == "node-version" else "v24.22.1\n"

            def phase_bridge(argv, cwd, env, context, phase, ordinal, **kwargs):
                result = runner(argv, cwd=cwd, env=env, check=False)
                result.timed_out = False
                return result

            env = {"PATH": str(runtimes), "GITHUB_EVENT_PATH": str(event),
                   "GITHUB_TOKEN": "never-forward-this", "npm_lifecycle_event": "postinstall"}
            req = {"round": 2, "sourceWitness": None}
            with patch.dict(os.environ, env, clear=True), redirect_stdout(output), \
                 patch.object(sys, "argv", ["source_validation_v108.py", "run", "--pipeline-dir", str(pipeline),
                                            "--source-dir", str(source), "--profile", "types-production"]), \
                 patch.object(driver, "validate_event"), \
                 patch.object(driver, "metadata", return_value=(req, {}, "d" * 64)), \
                 patch.object(driver, "code_binding"), patch.object(driver, "deadline_check"), \
                 patch.object(driver, "profile_deadline", return_value=9999999999), \
                 patch.object(driver, "phase_process", side_effect=phase_bridge), \
                 patch.object(driver, "source_preflight"), patch.object(driver, "git", return_value=b""), \
                 patch.object(driver, "commands", return_value=[["pnpm", "tsgo:prod"]]), \
                 patch.object(driver, "resource_check", return_value={"logicalCpus": 4}), \
                 patch.object(driver, "PNPM_BOOTSTRAP_FILES", pins), \
                 patch.object(driver.subprocess, "run", side_effect=runner), \
                 patch.object(driver.subprocess, "check_output", side_effect=version):
                try:
                    self.assertEqual(driver.main(), 0)
                except (driver.release.Refusal, OSError, subprocess.CalledProcessError) as error:
                    failure = error
            for _, _, kwargs in calls:
                child = kwargs["env"]
                self.assertNotIn("GITHUB_TOKEN", child)
                self.assertNotIn("npm_lifecycle_event", child)
                self.assertEqual(child["npm_config_userconfig"], "/dev/null")
        return calls, [json.loads(line) for line in output.getvalue().splitlines()], failure

    def test_direct_exec_of_old_shebangless_contract_fails_before_running_body(self):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "inert-placeholder"
            script.write_bytes(b"# benign fixture has no shebang\nexit 0\n")
            script.chmod(0o755)
            with self.assertRaises(OSError) as error:
                subprocess.check_output([str(script)])
            self.assertEqual(error.exception.errno, errno.ENOEXEC)

    def test_initializer_precedes_absolute_owned_pnpm_and_normal_project_install(self):
        calls, records, failure = self.invoke_main()
        self.assertIsNone(failure)
        self.assertEqual([name for name, _, _ in calls], ["download", "initialize", "pnpm-version",
                         "node-version", "project-install", "project-command"])
        self.assertEqual(records[-1]["exitCodes"], [0])
        for name, argv, _ in calls:
            if name in ("pnpm-version", "project-install", "project-command"):
                self.assertTrue(Path(argv[0]).is_absolute())
                self.assertTrue(argv[0].endswith("/toolchain/node_modules/pnpm/pnpm"))

    def test_invalid_package_or_pins_refuse_before_initializer_and_project(self):
        for mutation in ("installer-integrity", "helper-integrity", "manifest-integrity", "package-name",
                         "package-version", "package-bin", "optional-version", "initializer-path"):
            with self.subTest(mutation=mutation):
                calls, records, failure = self.invoke_main(mutation)
                self.assertIsNotNone(failure)
                self.assertEqual([name for name, _, _ in calls], ["download"])
                self.assertEqual(next(r for r in reversed(records) if "bootstrapPhase" in r)["bootstrapPhase"], "verify-package")

    def test_failed_initializer_and_invalid_native_cannot_reach_project_install(self):
        for mutation in ("initializer-failure", "native-path", "native-format", "native-permission", "command-link"):
            with self.subTest(mutation=mutation):
                calls, records, failure = self.invoke_main(mutation)
                self.assertIsNotNone(failure)
                self.assertEqual([name for name, _, _ in calls], ["download", "initialize"])
                self.assertEqual(next(r for r in reversed(records) if "bootstrapPhase" in r)["bootstrapPhase"],
                                 "initialize-native" if mutation == "initializer-failure" else "verify-native")

    def test_exact_versions_and_launch_errors_refuse_before_project_install(self):
        for mutation in ("pnpm-version", "node-version", "version-oserror", "download-failure"):
            with self.subTest(mutation=mutation):
                calls, records, failure = self.invoke_main(mutation)
                self.assertIsNotNone(failure)
                self.assertFalse(any(name.startswith("project-") for name, _, _ in calls))
                last = next(r for r in reversed(records) if "bootstrapPhase" in r)
                self.assertEqual(set(last), {"campaignId", "bootstrapPhase", "status", "errorClass",
                                             "errno", "resolvedWithinOwnedToolchain", "exitCode", "signal"})
                self.assertEqual(records[-1]["phase"], "profile")
                self.assertEqual(records[-1]["status"], "refused")
                self.assertFalse(records[-1]["productionAuthorized"])
                self.assertFalse(records[-1]["imageBuilt"])
                self.assertEqual(last["status"], "refused")
                self.assertNotIn("never", json.dumps(records))
                if mutation == "version-oserror":
                    self.assertEqual(last["errorClass"], "OSError")
                    self.assertEqual(last["errno"], errno.ENOEXEC)
                    self.assertTrue(last["resolvedWithinOwnedToolchain"])

    def test_structured_summaries_flush_before_bootstrap(self):
        with patch("builtins.print") as printer:
            driver.summarize({"engineeringFloorsPassed": True}, {})
        self.assertTrue(printer.call_args.kwargs["flush"])


if __name__ == "__main__":
    unittest.main()
