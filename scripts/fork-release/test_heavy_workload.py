"""Cooperative heavyweight workload serialization; no native workloads launched."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import gcp_build as build
import release


class HeavyWorkloadTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.builds = self.root / "builds"
        self.trials = self.root / "trials"
        self.builds.mkdir(mode=0o700)
        self.trials.mkdir(mode=0o700)
        for name, value in (("HEAVY_ROOT", self.root / "heavy"), ("PRIVATE_ROOT", self.builds),
                            ("TRIAL_ROOT", self.trials)):
            mock = patch.object(build, name, value)
            mock.start()
            self.addCleanup(mock.stop)
        self.a = self.operation(self.builds, "a")
        self.b = self.operation(self.trials, "b")

    def operation(self, parent, letter):
        op = parent / (letter * 32)
        op.mkdir(mode=0o700)
        build.write_once(op / "intent.json", b"{}\n")
        return op

    def reserve(self, op, kind):
        build.reserve_heavy_workload(op, kind, build.preflight.digest(op / "intent.json"))

    def completed(self, op, kind, failed=False):
        build.write_once(op / "started.json", build.encode({"invocationId": "f" * 32}))
        value = {"invocationId": "f" * 32}
        if kind == "build":
            value.update(exitCode=1 if failed else 0, nativeExitCode=1 if failed else 0)
        else:
            value.update(state="failed" if failed else "succeeded", containerId="c" * 64,
                         cleanup="owned_container_stopped_retained", nativeState={
                             "Running": False, "Pid": 0, "StartedAt": "start", "FinishedAt": "end"})
        build.write_once(op / ("completed.json" if kind == "build" else "result.json"), build.encode(value))

    def native(self, args):
        if "inspect" in args:
            return subprocess.CompletedProcess(args, 0, json.dumps({"Running": False, "Pid": 0,
                "StartedAt": "start", "FinishedAt": "end"}), "")
        return subprocess.CompletedProcess(args, 0, "\n".join([
            "LoadState=loaded", "SubState=exited", "MainPID=0", "Result=success",
            "ExecMainCode=1", "ExecMainStatus=0", "InvocationID=" + "f" * 32]), "")

    def test_same_operation_is_idempotent_and_pending_build_blocks_doctor(self):
        self.reserve(self.a, "build")
        self.reserve(self.a, "build")
        with self.assertRaisesRegex(release.Refusal, "owned_or_uncertain"):
            self.reserve(self.b, "doctor")
        self.assertEqual(build.read_private(build.HEAVY_ROOT / "owner.json")["operationPath"], str(self.a))

    def test_settled_build_advances_to_doctor_and_preserves_prior_owner(self):
        self.reserve(self.a, "build")
        self.completed(self.a, "build")
        with patch.object(build, "native", side_effect=self.native):
            self.reserve(self.b, "doctor")
        self.assertEqual(build.read_private(build.HEAVY_ROOT / "owner.json")["kind"], "doctor")
        self.assertEqual(len(list(build.HEAVY_ROOT.glob("settled-*.json"))), 1)
        with self.assertRaisesRegex(release.Refusal, "owned_or_uncertain"):
            self.reserve(self.a, "build")

    def test_failed_build_client_does_not_prove_daemon_solve_stopped(self):
        self.reserve(self.a, "build")
        self.completed(self.a, "build", failed=True)
        with patch.object(build, "native", side_effect=self.native), self.assertRaises(release.Refusal):
            self.reserve(self.b, "doctor")

    def test_missing_unit_or_changed_invocation_never_releases_ownership(self):
        self.reserve(self.a, "build")
        self.completed(self.a, "build")
        for result in (subprocess.CompletedProcess([], 1, "", ""),
                       subprocess.CompletedProcess([], 0, self.native([]).stdout.replace("f" * 32, "e" * 32), "")):
            with self.subTest(result=result.returncode), patch.object(build, "native", return_value=result), \
                    self.assertRaises(release.Refusal):
                self.reserve(self.b, "doctor")

    def test_terminal_doctor_requires_fresh_stopped_container(self):
        self.reserve(self.b, "doctor")
        self.completed(self.b, "doctor")
        with patch.object(build, "native", side_effect=lambda args: (
                subprocess.CompletedProcess(args, 0, '{"Running":true,"Pid":123}', "")
                if "inspect" in args else self.native(args))), self.assertRaises(release.Refusal):
            self.reserve(self.a, "build")
        with patch.object(build, "native", side_effect=self.native):
            self.reserve(self.a, "build")

    def test_changed_intent_cannot_renew_same_operation(self):
        self.reserve(self.a, "build")
        (self.a / "intent.json").write_text('{"changed":true}')
        with self.assertRaises(release.Refusal):
            self.reserve(self.a, "build")

    def test_busy_doctor_does_not_reserve_builder_and_resource_conflict_does_not_claim_global(self):
        intent = {"config": {"builder": {"containerId": "c" * 64}}}
        claim = lambda: build.reserve_builder(self.a, intent)
        lease = self.a.parent / ("builder-" + "c" * 64 + ".json")
        self.reserve(self.b, "doctor")
        with self.assertRaises(release.Refusal):
            build.reserve_heavy_workload(self.a, "build", build.preflight.digest(self.a / "intent.json"),
                                         reserve_resource=claim)
        self.assertFalse(lease.exists())
        self.completed(self.b, "doctor")
        build.write_once(lease, build.encode({"operationId": "d" * 32, "intentSha256": "e" * 64}))
        with patch.object(build, "native", side_effect=self.native), self.assertRaises(release.Refusal):
            build.reserve_heavy_workload(self.a, "build", build.preflight.digest(self.a / "intent.json"),
                                         reserve_resource=claim)
        self.assertEqual(build.read_private(build.HEAVY_ROOT / "owner.json")["operationPath"], str(self.b))

    def test_resource_claim_can_resume_before_global_publication(self):
        intent = {"config": {"builder": {"containerId": "c" * 64}}}
        claim = lambda: build.reserve_builder(self.a, intent)
        with patch.object(build.release, "atomic_json", side_effect=OSError("interrupted")), \
                self.assertRaises(OSError):
            build.reserve_heavy_workload(self.a, "build", build.preflight.digest(self.a / "intent.json"),
                                         reserve_resource=claim)
        self.assertFalse((build.HEAVY_ROOT / "owner.json").exists())
        build.reserve_heavy_workload(self.a, "build", build.preflight.digest(self.a / "intent.json"),
                                     reserve_resource=claim)
        self.assertEqual(build.read_private(build.HEAVY_ROOT / "owner.json")["operationPath"], str(self.a))


if __name__ == "__main__":
    unittest.main()
