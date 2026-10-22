from pathlib import Path
import json
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import gcp_build as build
import gcp_builder_recovery as subject
import release


class BuilderRecoveryTest(unittest.TestCase):
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
        self.builder = {"containerId": "c" * 64, "imageId": "sha256:" + "d" * 64}
        self.origin = {"config": {"builder": self.builder, "sourceSha": "e" * 40}}
        self.target = {"config": {"builder": self.builder, "sourceSha": "e" * 40}}
        build.write_once(self.old / "intent.json", b"origin\n")
        build.write_once(self.new / "intent.json", build.encode(self.target))
        self.completed = {"completedAt": "2026-10-22T04:40:32Z", "exitCode": 130,
                          "nativeExitCode": 130, "reason": "build.capacity.memory_reserve",
                          "remoteSolveTerminationObserved": False, "invocationId": "f" * 32}
        build.write_once(self.old / "completed.json", build.encode(self.completed))
        build.write_once(self.old / "build.exit", b"130\n")
        self.lease = self.root / f"builder-{'c' * 64}.json"
        build.write_once(self.lease, build.encode({"operationId": self.old.name,
            "intentSha256": build.preflight.digest(self.old / "intent.json")}))
        self.stopped = {"Id": "c" * 64, "Image": self.builder["imageId"],
            "State": {"Running": False, "Restarting": False, "Pid": 0,
                      "FinishedAt": "2026-10-22T04:42:47.62055506Z"}}
        self.status = {"state": "failed", "dispatchRecorded": True,
            "service": {"InvocationID": "f" * 32, "MainPID": "0",
                        "ActiveState": "failed", "SubState": "failed",
                        "Result": "exit-code", "LoadState": "loaded",
                        "ExecMainCode": "1", "ExecMainStatus": "130"}}

        def load(path):
            value = Path(path)
            return value, self.origin if value == self.old else self.target

        def native(_):
            class Result:
                returncode = 0
                stdout = json.dumps(self.stopped)
            return Result()

        for obj, name, value in (
            (build, "PRIVATE_ROOT", self.root),
            (build, "load_intent", load),
            (build, "status", lambda _: self.status),
            (build, "native", native),
        ):
            item = patch.object(obj, name, value)
            item.start()
            self.addCleanup(item.stop)

    def test_failed_origin_transfers_only_after_stopped_worker(self):
        first = subject.recover(self.old, self.new)
        self.assertEqual(first, subject.recover(self.old, self.new))
        self.assertEqual(build.read_private(self.lease)["operationId"], self.new.name)
        self.assertEqual(first["originCompletedSha256"],
                         build.preflight.digest(self.old / "completed.json"))
        build.verify_builder_handoff(self.new, self.target)

    def test_refuses_running_worker(self):
        self.stopped["State"]["Running"] = True
        with self.assertRaisesRegex(release.Refusal, "builder.not_stopped"):
            subject.recover(self.old, self.new)
        self.assertEqual(build.read_private(self.lease)["operationId"], self.old.name)

    def test_refuses_stop_before_failed_client_completed(self):
        self.stopped["State"]["FinishedAt"] = "2026-10-22T04:30:00Z"
        with self.assertRaisesRegex(release.Refusal, "stop_precedes_failure"):
            subject.recover(self.old, self.new)

    def test_refuses_changed_container_identity(self):
        self.stopped["Id"] = "0" * 64
        with self.assertRaisesRegex(release.Refusal, "builder.not_stopped"):
            subject.recover(self.old, self.new)

    def test_refuses_uncertain_origin(self):
        self.status["service"]["MainPID"] = "123"
        with self.assertRaisesRegex(release.Refusal, "origin.not_terminal_failed"):
            subject.recover(self.old, self.new)

    def test_refuses_changed_stop_receipt(self):
        subject.recover(self.old, self.new)
        (self.new / "builder-stopped.json").write_text("{}\n")
        with self.assertRaisesRegex(release.Refusal, "stop_proof.changed"):
            build.verify_builder_handoff(self.new, self.target)

    def test_refuses_other_lease_owner(self):
        self.lease.unlink()
        build.write_once(self.lease, build.encode({"operationId": "z" * 32,
                                                  "intentSha256": "0" * 64}))
        with self.assertRaisesRegex(release.Refusal, "lease.other_owner"):
            subject.recover(self.old, self.new)

    def test_shared_workload_releases_only_to_proven_recovery_successor(self):
        subject.recover(self.old, self.new)
        build.write_once(self.old / "started.json", build.encode({"invocationId": "f" * 32}))
        owner = {"kind": "build", "operationPath": str(self.old),
                 "intentSha256": build.preflight.digest(self.old / "intent.json")}

        def service(_):
            return subprocess.CompletedProcess([], 0,
                "\n".join(f"{key}={value}" for key, value in self.status["service"].items()), "")

        with patch.object(build, "native", side_effect=service):
            with self.assertRaisesRegex(release.Refusal, "solve_unsettled"):
                build.heavy_workload_settled(owner)
            build.heavy_workload_settled(owner, successor=self.new)
            (self.new / "builder-stopped.json").write_text("{}\n")
            with self.assertRaisesRegex(release.Refusal, "stop_proof.changed"):
                build.heavy_workload_settled(owner, successor=self.new)


if __name__ == "__main__":
    unittest.main()
