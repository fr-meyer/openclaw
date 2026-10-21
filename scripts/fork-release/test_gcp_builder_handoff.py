from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

import gcp_build as build
import gcp_builder_handoff as subject
import release


class BuilderHandoffTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.old = self.root / ("a" * 32)
        self.new = self.root / ("b" * 32)
        self.old.mkdir(mode=0o700)
        self.new.mkdir(mode=0o700)
        (self.new / "supervisor").mkdir(mode=0o700)
        build.write_once(self.new / "supervisor/gcp_build.py", Path(build.__file__).read_bytes())
        self.builder = {"containerId": "c" * 64}
        self.origin = {"config": {"builder": self.builder, "sourceSha": "d" * 40}}
        self.target = {"config": {"builder": self.builder, "sourceSha": "e" * 40}}
        build.write_once(self.old / "intent.json", b"origin\n")
        build.write_once(self.new / "intent.json", b"target\n")
        build.write_once(self.old / "execution.json", b"execution\n")
        build.write_once(self.old / "completed.json", build.encode({
            "exitCode": 0, "nativeExitCode": 0, "reason": "client succeeded",
            "invocationId": "f" * 32,
        }))
        self.lease = self.root / f"builder-{'c' * 64}.json"
        build.write_once(self.lease, build.encode({
            "operationId": self.old.name,
            "intentSha256": build.preflight.digest(self.old / "intent.json"),
        }))
        def load(path):
            value = Path(path)
            return value, self.origin if value == self.old else self.target
        self.patches = [
            patch.object(build, "PRIVATE_ROOT", self.root),
            patch.object(build, "load_intent", side_effect=load),
            patch.object(build, "status", return_value={
                "state": "succeeded", "dispatchRecorded": True,
                "service": {"InvocationID": "f" * 32, "MainPID": "0"},
            }),
        ]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def test_transfer_and_crash_reconciliation(self):
        first = subject.handoff(self.old, self.new)
        self.assertEqual(first, subject.handoff(self.old, self.new))
        self.assertEqual(build.read_private(self.lease)["operationId"], self.new.name)
        self.assertEqual(build.read_private(self.new / "builder-handoff.json"), first)
        (self.new / "builder-handoff.json").unlink()
        self.assertEqual(first, subject.handoff(self.old, self.new))

    def test_refuses_incomplete_or_uncertain_origin(self):
        with patch.object(build, "status", return_value={
            "state": "incomplete", "dispatchRecorded": True, "service": {},
        }), self.assertRaisesRegex(release.Refusal, "origin.not_succeeded"):
            subject.handoff(self.old, self.new)
        self.assertEqual(build.read_private(self.lease)["operationId"], self.old.name)

    def test_refuses_other_lease_owner(self):
        self.lease.unlink()
        build.write_once(self.lease, build.encode({"operationId": "z" * 32,
                                                  "intentSha256": "x" * 64}))
        with self.assertRaisesRegex(release.Refusal, "lease.other_owner"):
            subject.handoff(self.old, self.new)

    def test_refuses_started_target(self):
        build.write_once(self.new / "start-intent.json", b"started")
        with self.assertRaisesRegex(release.Refusal, "target.started"):
            subject.handoff(self.old, self.new)

    def test_refuses_legacy_target_without_start_fence(self):
        (self.new / "supervisor/gcp_build.py").unlink()
        build.write_once(self.new / "supervisor/gcp_build.py", b"legacy start")
        with self.assertRaisesRegex(release.Refusal, "tooling_lacks_start_fence"):
            subject.handoff(self.old, self.new)
        self.assertEqual(build.read_private(self.lease)["operationId"], self.old.name)
        self.assertFalse((self.new / "builder-handoff-intent.json").exists())

    def test_refuses_changed_builder_or_source(self):
        self.target["config"]["builder"] = {"containerId": "1" * 64}
        with self.assertRaisesRegex(release.Refusal, "builder.changed"):
            subject.handoff(self.old, self.new)
        self.target["config"]["builder"] = self.builder
        self.target["config"]["sourceSha"] = self.origin["config"]["sourceSha"]
        with self.assertRaisesRegex(release.Refusal, "source.unchanged"):
            subject.handoff(self.old, self.new)

    def test_crash_after_replace_requires_retry_before_start(self):
        original = build.sync_directory
        failed = False

        def interrupt(path):
            nonlocal failed
            if Path(path) == self.root and not failed:
                failed = True
                raise OSError("injected directory sync failure")
            return original(path)

        with patch.object(build, "sync_directory", side_effect=interrupt):
            with self.assertRaisesRegex(OSError, "injected directory sync failure"):
                subject.handoff(self.old, self.new)
        self.assertEqual(build.read_private(self.lease)["operationId"], self.new.name)
        self.assertFalse((self.new / "builder-handoff.json").exists())
        with self.assertRaises(OSError):
            build.verify_builder_handoff(self.new, self.target)
        subject.handoff(self.old, self.new)
        build.verify_builder_handoff(self.new, self.target)

    def test_target_operation_lock_serializes_transfer(self):
        finished = threading.Event()
        errors = []

        def run():
            try:
                subject.handoff(self.old, self.new)
            except Exception as error:
                errors.append(error)
            finally:
                finished.set()

        with build.operation_lock(self.new):
            thread = threading.Thread(target=run)
            thread.start()
            self.assertFalse(finished.wait(0.05))
            self.assertEqual(build.read_private(self.lease)["operationId"], self.old.name)
        thread.join(timeout=2)
        self.assertTrue(finished.is_set())
        self.assertEqual(errors, [])
        build.verify_builder_handoff(self.new, self.target)


if __name__ == "__main__":
    unittest.main()
