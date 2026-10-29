"""Synthetic historical-fixture reader boundaries; no real Git, API or app calls."""
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("historical_v5_test_input_owner", HERE / "historical_v5_test_inputs.py")
H = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(H)


class HistoricalV5InputTests(unittest.TestCase):
    def setUp(self):
        H._CACHE.clear()
        self.addCleanup(H._CACHE.clear)

    def test_arbitrary_input_and_git_path_refuse_before_process(self):
        with patch.object(H.subprocess, "run") as child:
            for name in (None, 1, "../driver", "npm-lock.diff", "driver/extra"):
                with self.subTest(name=name), self.assertRaisesRegex(AssertionError, "input_not_allowlisted"):
                    H.p7_input(name)
            with self.assertRaisesRegex(AssertionError, "path_not_allowlisted"):
                H._read_p7("../private")
            child.assert_not_called()

    def test_fixed_read_disables_transports_and_ambient_git_overrides(self):
        result = SimpleNamespace(returncode=0, stdout=b"synthetic", stderr=b"")
        with patch.object(H.os, "environ", {"PATH": "/synthetic", "GIT_DIR": "/private", "GIT_CONFIG_COUNT": "1"}), \
             patch.object(H.subprocess, "run", return_value=result) as child:
            path = H.PINS["driver"][0]
            self.assertEqual(H._read_p7(path), b"synthetic")
        argv = child.call_args.args[0]
        self.assertEqual(argv[0], "/usr/bin/git")
        self.assertEqual(argv[-2:], ["show", H.P7 + ":" + path])
        self.assertIn("protocol.allow=never", argv)
        self.assertIn("core.hooksPath=/dev/null", argv)
        self.assertIn("--no-replace-objects", argv)
        self.assertEqual(child.call_args.kwargs["timeout"], 20)
        env = child.call_args.kwargs["env"]
        self.assertNotIn("GIT_DIR", env)
        self.assertNotIn("GIT_CONFIG_COUNT", env)
        self.assertEqual(env["GIT_NO_LAZY_FETCH"], "1")
        self.assertEqual(env["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(env["GIT_OPTIONAL_LOCKS"], "0")

    def test_failed_process_refuses_without_raw_stderr(self):
        secret = b"SYNTHETIC_PRIVATE_STDERR"
        with patch.object(H.subprocess, "run", return_value=SimpleNamespace(returncode=1, stdout=b"", stderr=secret)):
            with self.assertRaisesRegex(AssertionError, "^historical_v5.git_read_failed$") as failure:
                H._read_p7(H.PINS["driver"][0])
        self.assertNotIn(secret.decode(), str(failure.exception))

    def test_timeout_refuses_without_fallback_or_partial_acceptance(self):
        with patch.object(H.subprocess, "run", side_effect=subprocess.TimeoutExpired("synthetic", 20, output=b"valid-looking-prefix")) as child:
            with self.assertRaisesRegex(AssertionError, "^historical_v5.git_timeout$"):
                H._read_p7(H.PINS["driver"][0])
            child.assert_called_once()

    def test_exact_bytes_are_cached_once_and_returned_immutable(self):
        raw = b"synthetic fixture"
        pin = ("scripts/fork-release/source_validation_v108.py", len(raw), hashlib.sha256(raw).hexdigest())
        with patch.object(H, "PINS", {"driver": pin}), patch.object(H, "_read_p7", return_value=raw) as read:
            self.assertIs(H.p7_input("driver"), raw)
            self.assertIs(H.p7_input("driver"), raw)
            read.assert_called_once_with(pin[0])

    def test_changed_size_digest_or_type_is_never_cached(self):
        raw = b"synthetic fixture"
        pin = ("scripts/fork-release/source_validation_v108.py", len(raw), hashlib.sha256(raw).hexdigest())
        for changed in (raw + b" ", raw[:-1], raw.replace(b"s", b"x", 1), raw.decode()):
            with self.subTest(changed=changed), patch.object(H, "PINS", {"driver": pin}), \
                 patch.object(H, "_read_p7", return_value=changed):
                with self.assertRaisesRegex(AssertionError, "^historical_v5.input_pin$"):
                    H.p7_input("driver")
                self.assertEqual(H._CACHE, {})

    def test_module_identity_is_closed_before_input_read(self):
        with patch.object(H, "p7_input") as read:
            for name in (None, "__main__", "unrelated", "historical_v5_bad-name"):
                with self.subTest(name=name), self.assertRaisesRegex(AssertionError, "module_identity"):
                    H.load_p7_driver(name)
            read.assert_not_called()

    def test_shared_owner_drift_refuses_before_historical_driver_exec(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(H, "HERE", Path(directory)), \
             patch.object(H, "p7_input") as read:
            with self.assertRaisesRegex(AssertionError, "shared_owner_changed"):
                H.load_p7_driver("historical_v5_synthetic")
            read.assert_not_called()
            (Path(directory) / "release.py").write_bytes(b"changed")
            read.return_value = b"expected"
            with self.assertRaisesRegex(AssertionError, "shared_owner_changed"):
                H.load_p7_driver("historical_v5_synthetic")
            self.assertEqual(read.call_args_list[-1].args, ("release",))

    def test_fresh_test_module_keeps_historical_code_out_of_main(self):
        source = b"counter = []\nif __name__ == '__main__':\n    raise AssertionError('main must stay disarmed')\n"
        with tempfile.TemporaryDirectory() as directory, patch.object(H, "HERE", Path(directory)):
            for owner in ("release", "preflight"):
                (Path(directory) / (owner + ".py")).write_bytes(owner.encode())
            def read(name):
                return source if name == "driver" else name.encode()
            with patch.object(H, "p7_input", side_effect=read):
                first, controls = H.load_p7_driver("historical_v5_synthetic")
                first.counter.append("changed")
                second, _ = H.load_p7_driver("historical_v5_synthetic")
        self.assertEqual(second.counter, [])
        self.assertTrue(first.__file__.startswith("<historical-p7:"))
        self.assertEqual(set(controls), {"source-request.json", "manifest.json", "patch-inventory.json", "settled-usage.json"})




class HistoricalP8WorkflowTests(unittest.TestCase):
    def setUp(self):
        H._P8_WORKFLOW_CACHE = None
        self.addCleanup(setattr, H, "_P8_WORKFLOW_CACHE", None)

    def test_only_exact_fixed_preparation_head_path_and_transport_are_used(self):
        raw = b"synthetic immutable workflow\n"
        pin = (H.P8_PREPARATION_WORKFLOW[0], len(raw), hashlib.sha256(raw).hexdigest())
        result = SimpleNamespace(returncode=0, stdout=raw, stderr=b"")
        with patch.object(H, "P8_PREPARATION_WORKFLOW", pin), \
             patch.object(H.os, "environ", {"PATH": "/synthetic", "GIT_DIR": "/private", "GIT_CONFIG_COUNT": "1"}), \
             patch.object(H.subprocess, "run", return_value=result) as child:
            self.assertEqual(H.p8_preparation_workflow(), raw)
        argv = child.call_args.args[0]
        self.assertEqual(argv, ["/usr/bin/git", "--no-replace-objects", "-c", "protocol.allow=never", "-c",
            "core.hooksPath=/dev/null", "-c", "gc.auto=0", "-c", "maintenance.auto=false",
            "-C", str(H.PIPELINE), "show", "e96941f0c8c05a45d7df32ca7e45758e12609be7:" + pin[0]])
        self.assertEqual(child.call_args.kwargs["timeout"], 20)
        env = child.call_args.kwargs["env"]
        self.assertNotIn("GIT_DIR", env); self.assertNotIn("GIT_CONFIG_COUNT", env)
        for key, value in {"GIT_NO_LAZY_FETCH": "1", "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}.items():
            self.assertEqual(env[key], value)

    def test_workflow_pin_is_actual_preparation_not_current_metadata(self):
        self.assertEqual(H.P8_PREPARATION, "e96941f0c8c05a45d7df32ca7e45758e12609be7")
        self.assertEqual(H.P8_PREPARATION_WORKFLOW, (".github/workflows/future-v108-source-validation.yml", 4460,
            "c3c00a6e3d24ffd387b351fc3f44edab5078ab68a7aed1975b4449bedbb63ae5"))
        with patch.object(H.subprocess, "run") as child:
            for args in (("current",), ("../private",), ("b" * 40, "path")):
                with self.subTest(args=args), self.assertRaises(TypeError):
                    H.p8_preparation_workflow(*args)
            child.assert_not_called()

    def test_exact_verified_workflow_is_cached_immutable_and_separate_from_p7(self):
        raw = b"synthetic immutable workflow\n"
        pin = (H.P8_PREPARATION_WORKFLOW[0], len(raw), hashlib.sha256(raw).hexdigest())
        before = dict(H._CACHE)
        with patch.object(H, "P8_PREPARATION_WORKFLOW", pin), \
             patch.object(H.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=raw)) as child:
            self.assertIs(H.p8_preparation_workflow(), raw)
            self.assertIs(H.p8_preparation_workflow(), raw)
            child.assert_called_once()
        self.assertEqual(H._CACHE, before)

    def test_wrong_digest_size_or_type_refuses_without_cache(self):
        raw = b"synthetic immutable workflow\n"
        pin = (H.P8_PREPARATION_WORKFLOW[0], len(raw), hashlib.sha256(raw).hexdigest())
        for changed in (raw + b" ", raw[:-1], raw.replace(b"s", b"x", 1), raw.decode()):
            with self.subTest(changed=changed), patch.object(H, "P8_PREPARATION_WORKFLOW", pin), \
                 patch.object(H.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=changed)):
                with self.assertRaisesRegex(AssertionError, "^historical_p8.workflow_pin$"):
                    H.p8_preparation_workflow()
                self.assertIsNone(H._P8_WORKFLOW_CACHE)

    def test_missing_or_failed_object_never_returns_current_or_raw_error(self):
        secret = b"SYNTHETIC_PRIVATE_STDERR"
        for code in (1, 124, -15, None, False):
            with self.subTest(code=code), patch.object(H.subprocess, "run",
                    return_value=SimpleNamespace(returncode=code, stdout=b"", stderr=secret)) as child:
                with self.assertRaisesRegex(AssertionError, "^historical_p8.git_read_failed$") as failure:
                    H.p8_preparation_workflow()
                self.assertNotIn(secret.decode(), str(failure.exception))
                child.assert_called_once(); self.assertIsNone(H._P8_WORKFLOW_CACHE)

    def test_timeout_valid_prefix_cannot_pass_or_fallback(self):
        error = subprocess.TimeoutExpired("fixed historical lookup", 20, output=b"synthetic", stderr=b"PRIVATE")
        with patch.object(H.subprocess, "run", side_effect=error) as child:
            with self.assertRaisesRegex(AssertionError, "^historical_p8.git_timeout$") as failure:
                H.p8_preparation_workflow()
            child.assert_called_once(); self.assertIsNone(H._P8_WORKFLOW_CACHE)
            self.assertNotIn("PRIVATE", str(failure.exception))


if __name__ == "__main__":
    unittest.main()
