from pathlib import Path
import copy
import hashlib
import json
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import gcp_build as build
import gcp_builder_recovery as subject
import release
import test_gcp_build as build_fixture


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
        build.write_once(self.old / "intent.json", build.encode(self.origin))
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

    def qualification_resources(self):
        before = {"name": "existing", "node": "existing0", "endpoint": build.ENDPOINT,
                  "containerId": "c" * 64, "imageId": "sha256:" + "d" * 64,
                  "memoryBytes": 16 << 30, "memorySwapBytes": 18 << 30,
                  "cpuPeriod": 100000, "cpuQuota": 700000, "cpuShares": 128,
                  "nanoCpus": 0, "pidsLimit": None, "readBps": None,
                  "writeBps": None}
        after = {**before, "memoryBytes": 8 << 30, "memorySwapBytes": 8 << 30,
                 "cpuQuota": 400000}
        self.origin["config"].update({"builder": before, "sourceSha": "e" * 40})
        self.target["config"].update({"builder": after, "sourceSha": "e" * 40,
                                      "adaptiveSelection": {"profile": {
                                          "id": build.QUALIFICATION_PROFILE_ID}}})
        (self.old / "intent.json").write_bytes(build.encode(self.origin))
        (self.new / "intent.json").write_bytes(build.encode(self.target))
        self.lease.write_bytes(build.encode({"operationId": self.old.name,
            "intentSha256": build.preflight.digest(self.old / "intent.json")}))
        build.write_once(self.new / "supervisor/other", b"unused")
        return before, after

    def test_exact_stopped_resource_transition_and_lost_reply_reconcile(self):
        before, after = self.qualification_resources()
        observed = dict(before)
        updates = []

        def native(argv):
            if "update" in argv:
                updates.append(argv)
                observed.update({key: after[key] for key in subject.RESOURCE_FIELDS})
                # The Docker reply is uncertain; exact readback proves outcome.
                raise subprocess.TimeoutExpired(argv, 30)
            if subject.STOP_FORMAT in argv:
                return subprocess.CompletedProcess(argv, 0, json.dumps(self.stopped), "")
            if build.CONTAINER_FORMAT in argv:
                row = {"Id": observed["containerId"], "Image": observed["imageId"],
                       "State": {"Running": False}, "HostConfig": {
                           "Memory": observed["memoryBytes"],
                           "MemorySwap": observed["memorySwapBytes"],
                           "CpuPeriod": observed["cpuPeriod"],
                           "CpuQuota": observed["cpuQuota"],
                           "CpuShares": observed["cpuShares"],
                           "NanoCpus": observed["nanoCpus"],
                           "PidsLimit": observed["pidsLimit"],
                           "BlkioDeviceReadBps": observed["readBps"],
                           "BlkioDeviceWriteBps": observed["writeBps"]}}
                return subprocess.CompletedProcess(argv, 0, json.dumps(row), "")
            raise AssertionError(argv)

        with patch.object(build, "QUALIFICATION_SOURCE_SHA", "e" * 40), \
             patch.object(build, "native", side_effect=native):
            first = subject.recover(self.old, self.new)
            self.assertEqual(first, subject.recover(self.old, self.new))
            self.assertEqual(len(updates), 1)
            self.assertIn("--memory-swap", updates[0])
            self.assertEqual(build.read_private(self.lease)["operationId"], self.new.name)
            self.assertIn("resourceTransitionSha256", first)
            build.verify_builder_handoff(self.new, self.target)
            intent_path = self.new / "builder-handoff-intent.json"
            original_intent = intent_path.read_bytes()
            without_transition = build.read_private(intent_path)
            del without_transition["resourceTransitionSha256"]
            intent_path.write_bytes(build.encode(without_transition))
            with self.assertRaisesRegex(release.Refusal, "resource_transition_required"):
                build.verify_builder_handoff(self.new, self.target)
            intent_path.write_bytes(original_intent)
            (self.new / "resource-transition.json").write_text("{}\n")
            with self.assertRaisesRegex(release.Refusal, "resource_transition"):
                build.verify_builder_handoff(self.new, self.target)

    def test_partial_resource_update_refuses_without_transferring_lease(self):
        before, after = self.qualification_resources()
        observed = dict(before)

        def native(argv):
            if "update" in argv:
                observed["memoryBytes"] = after["memoryBytes"]
                return subprocess.CompletedProcess(argv, 1, "", "partial")
            if subject.STOP_FORMAT in argv:
                return subprocess.CompletedProcess(argv, 0, json.dumps(self.stopped), "")
            if build.CONTAINER_FORMAT in argv:
                host = {"Memory": observed["memoryBytes"],
                        "MemorySwap": observed["memorySwapBytes"],
                        "CpuPeriod": observed["cpuPeriod"],
                        "CpuQuota": observed["cpuQuota"],
                        "CpuShares": observed["cpuShares"],
                        "NanoCpus": observed["nanoCpus"],
                        "PidsLimit": observed["pidsLimit"],
                        "BlkioDeviceReadBps": observed["readBps"],
                        "BlkioDeviceWriteBps": observed["writeBps"]}
                return subprocess.CompletedProcess(argv, 0, json.dumps({
                    "Id": observed["containerId"], "Image": observed["imageId"],
                    "State": {"Running": False}, "HostConfig": host}), "")
            raise AssertionError(argv)

        with patch.object(build, "QUALIFICATION_SOURCE_SHA", "e" * 40), \
             patch.object(build, "native", side_effect=native):
            with self.assertRaisesRegex(release.Refusal, "resource_transition.readback"):
                subject.recover(self.old, self.new)
            self.assertEqual(build.read_private(self.lease)["operationId"], self.old.name)
            self.assertTrue((self.new / "resource-transition-intent.json").exists())
            self.assertTrue((self.new / "resource-transition-repair-intent.json").exists())
            self.assertFalse((self.new / "resource-transition.json").exists())
            with self.assertRaisesRegex(release.Refusal, "repair_exhausted"):
                subject.recover(self.old, self.new)

    def test_one_bounded_partial_resource_repair_reaches_exact_target(self):
        before, after = self.qualification_resources()
        partial = {**before, "memoryBytes": after["memoryBytes"]}
        observed = dict(before)
        updates = []

        def native(argv):
            if "update" in argv:
                updates.append(argv)
                observed.update(partial if len(updates) == 1 else after)
            return subprocess.CompletedProcess(argv, 0, json.dumps(self.stopped), "")

        with patch.object(build, "QUALIFICATION_SOURCE_SHA", "e" * 40), \
             patch.object(build, "native", side_effect=native), \
             patch.object(subject, "stopped_resources",
                          side_effect=lambda _: dict(observed)):
            result = subject.recover(self.old, self.new)
        self.assertEqual(len(updates), 2)
        self.assertIn("resourceTransitionSha256", result)
        self.assertEqual(build.read_private(self.lease)["operationId"], self.new.name)
        transition = build.read_private(self.new / "resource-transition.json")
        self.assertEqual(transition["repairIntentSha256"], build.preflight.digest(
            self.new / "resource-transition-repair-intent.json"))
        build.verify_builder_handoff(self.new, self.target)

    def test_resource_transition_refuses_unapproved_cpu_or_source(self):
        before, after = self.qualification_resources()
        self.target["config"]["builder"]["cpuQuota"] = 500000
        with patch.object(build, "QUALIFICATION_SOURCE_SHA", "e" * 40):
            with self.assertRaisesRegex(release.Refusal, "resource_transition.unreviewed"):
                subject.recover(self.old, self.new)
        self.target["config"]["builder"]["cpuQuota"] = after["cpuQuota"]
        self.target["config"]["sourceSha"] = "f" * 40
        with patch.object(build, "QUALIFICATION_SOURCE_SHA", "e" * 40):
            with self.assertRaisesRegex(release.Refusal, "resource_transition.unreviewed"):
                subject.recover(self.old, self.new)

    def test_retained_source_can_transition_resources_only_to_corrected_source(self):
        before, after = self.qualification_resources()
        self.origin["config"]["sourceSha"] = "e" * 40
        self.target["config"]["sourceSha"] = "f" * 40
        (self.old / "intent.json").write_bytes(build.encode(self.origin))
        (self.new / "intent.json").write_bytes(build.encode(self.target))
        self.lease.write_bytes(build.encode({"operationId": self.old.name,
            "intentSha256": build.preflight.digest(self.old / "intent.json")}))
        with patch.object(build, "RETAINED_QUALIFICATION_SOURCE_SHA", "e" * 40), \
             patch.object(build, "QUALIFICATION_SOURCE_SHA", "f" * 40), \
             patch.object(subject, "stopped_resources", side_effect=[before, after]):
            subject.qualification_transition(self.origin, self.target)
            receipt = subject.recover(self.old, self.new)
            self.assertIn("resourceTransitionSha256", receipt)
            build.verify_builder_handoff(self.new, self.target)
            self.origin["config"]["sourceSha"] = "a" * 40
            with self.assertRaisesRegex(release.Refusal, "resource_transition.unreviewed"):
                subject.qualification_transition(self.origin, self.target)

    def test_legacy_resource_transition_replays_only_recorded_intent(self):
        before, after = self.qualification_resources()
        with patch.object(build, "QUALIFICATION_SOURCE_SHA", "f" * 40), \
             patch.object(build, "RETAINED_QUALIFICATION_SOURCE_SHA", "e" * 40):
            with self.assertRaisesRegex(release.Refusal, "legacy_transition.not_recorded"):
                subject.recover(self.old, self.new)
            self.assertEqual(build.read_private(self.lease)["operationId"], self.old.name)
        with patch.object(build, "QUALIFICATION_SOURCE_SHA", "e" * 40), \
             patch.object(subject, "stopped_resources", side_effect=[before, after]):
            subject.recover(self.old, self.new)
        (self.new / "builder-handoff.json").unlink()
        with patch.object(build, "QUALIFICATION_SOURCE_SHA", "f" * 40), \
             patch.object(build, "RETAINED_QUALIFICATION_SOURCE_SHA", "e" * 40), \
             patch.object(subject, "stopped_resources", return_value=after):
            receipt = subject.recover(self.old, self.new)
            self.assertIn("resourceTransitionSha256", receipt)
            build.verify_builder_handoff(self.new, self.target)
            self.assertEqual(build.read_private(self.lease)["operationId"], self.new.name)

    def test_prepared_retained_source_cutover_preserves_original_receipt(self):
        _, after = self.qualification_resources()
        self.origin["config"]["builder"] = after
        for intent in (self.origin, self.target):
            intent["config"].update({"sourceTree": "1" * 40,
                                      "manifestSha256": "2" * 64,
                                      "inventorySha256": "3" * 64})
        (self.old / "intent.json").write_bytes(build.encode(self.origin))
        (self.new / "intent.json").write_bytes(build.encode(self.target))
        self.lease.write_bytes(build.encode({"operationId": self.old.name,
            "intentSha256": build.preflight.digest(self.old / "intent.json")}))
        subject.recover(self.old, self.new)
        old_receipt = (self.new / "builder-handoff.json").read_bytes()
        third = self.root / ("3" * 32)
        third.mkdir(mode=0o700)
        (third / "supervisor").mkdir(mode=0o700)
        build.write_once(third / "supervisor/gcp_build.py", Path(build.__file__).read_bytes())
        corrected = json.loads(json.dumps(self.target))
        corrected["config"].update({"sourceSha": "f" * 40,
                                    "sourceTree": "4" * 40,
                                    "manifestSha256": "5" * 64,
                                    "inventorySha256": "6" * 64,
                                    "adaptiveSelection": {"profile": {
                                        "id": build.QUALIFICATION_PROFILE_ID,
                                        "minStartMemoryAvailableBytes":
                                        build.QUALIFICATION_START_BYTES,
                                        "minMemoryAvailableBytes":
                                        build.QUALIFICATION_RUNNING_FLOOR_BYTES}}})
        build.write_once(third / "intent.json", build.encode(corrected))
        original_load = build.load_intent

        def load(path):
            if Path(path) == third:
                return third, corrected
            return original_load(path)
        with patch.object(build, "RETAINED_QUALIFICATION_SOURCE_SHA", "e" * 40), \
             patch.object(build, "QUALIFICATION_SOURCE_SHA", "f" * 40), \
             patch.object(build, "load_intent", side_effect=load):
            subject.transfer_prepared(self.new, third)
            build.verify_builder_handoff(third, corrected)
            self.assertEqual((self.new / "builder-handoff.json").read_bytes(), old_receipt)
            self.assertEqual(build.read_private(self.lease)["operationId"], third.name)
            corrected["config"]["builder"] = {**after, "cpuQuota": 1}
            self.assertFalse(build.prepared_binding_compatible(self.target, corrected))
            corrected["config"]["builder"] = after
            corrected["config"]["sourceSha"] = "a" * 40
            self.assertFalse(build.prepared_binding_compatible(self.target, corrected))

    def test_prepared_handoff_preserves_transition_without_dispatch(self):
        before, after = self.qualification_resources()
        third = self.root / ("3" * 32)
        third.mkdir(mode=0o700)
        (third / "supervisor").mkdir(mode=0o700)
        build.write_once(third / "supervisor/gcp_build.py", Path(build.__file__).read_bytes())
        build.write_once(third / "intent.json", build.encode(self.target))
        with patch.object(build, "QUALIFICATION_SOURCE_SHA", "e" * 40), \
             patch.object(subject, "stopped_resources", side_effect=[before, after]):
            subject.recover(self.old, self.new)
        first = subject.transfer_prepared(self.new, third)
        self.assertEqual(first, subject.transfer_prepared(self.new, third))
        self.assertEqual(build.read_private(self.lease)["operationId"], third.name)
        build.verify_builder_handoff(third, self.target)
        self.assertFalse((third / "start-intent.json").exists())
        build.write_once(self.old / "started.json", build.encode({"invocationId": "f" * 32}))
        owner = {"kind": "build", "operationPath": str(self.old),
                 "intentSha256": build.preflight.digest(self.old / "intent.json")}

        def service(_):
            return subprocess.CompletedProcess([], 0,
                "\n".join(f"{key}={value}" for key, value in self.status["service"].items()), "")

        with patch.object(build, "native", side_effect=service):
            build.heavy_workload_settled(owner, successor=third)
        intermediate_receipt = self.new / "builder-handoff.json"
        successor_proposal = third / "builder-handoff-intent.json"
        successor_receipt = third / "builder-handoff.json"
        original = {path: path.read_bytes() for path in
                    (intermediate_receipt, successor_proposal, successor_receipt)}
        forged = build.read_private(intermediate_receipt)
        forged["targetLeaseSha256"] = "0" * 64
        intermediate_receipt.write_bytes(build.encode(forged))
        proposal = build.read_private(successor_proposal)
        proposal["originHandoffSha256"] = build.preflight.digest(intermediate_receipt)
        successor_proposal.write_bytes(build.encode(proposal))
        receipt = build.read_private(successor_receipt)
        receipt["originHandoffSha256"] = proposal["originHandoffSha256"]
        successor_receipt.write_bytes(build.encode(receipt))
        with patch.object(build, "native", side_effect=service):
            with self.assertRaisesRegex(release.Refusal, "prepared_origin_changed"):
                build.heavy_workload_settled(owner, successor=third)
        for path, data in original.items():
            path.write_bytes(data)
        transition_path = self.new / "resource-transition.json"
        original_transition = transition_path.read_bytes()
        transition_path.write_text("{}\n")
        with self.assertRaisesRegex(release.Refusal, "prepared_recovery_changed"):
            build.verify_builder_handoff(third, self.target)
        transition_path.write_bytes(original_transition)
        (self.new / "start-intent.json").write_text("{}\n")
        with self.assertRaisesRegex(release.Refusal, "prepared_dispatched"):
            build.verify_builder_handoff(third, self.target)

    def test_prepared_handoff_refuses_dispatched_origin(self):
        before, after = self.qualification_resources()
        third = self.root / ("3" * 32)
        third.mkdir(mode=0o700)
        (third / "supervisor").mkdir(mode=0o700)
        build.write_once(third / "supervisor/gcp_build.py", Path(build.__file__).read_bytes())
        build.write_once(third / "intent.json", build.encode(self.target))
        with patch.object(build, "QUALIFICATION_SOURCE_SHA", "e" * 40), \
             patch.object(subject, "stopped_resources", side_effect=[before, after]):
            subject.recover(self.old, self.new)
        (self.new / "start-intent.json").write_text("{}\n")
        with self.assertRaisesRegex(release.Refusal, "origin_or_target_dispatched"):
            subject.transfer_prepared(self.new, third)
        self.assertEqual(build.read_private(self.lease)["operationId"], self.new.name)
        (self.new / "start-intent.json").unlink()
        (third / "completed.json").write_text("{}\n")
        with self.assertRaisesRegex(release.Refusal, "origin_or_target_dispatched"):
            subject.transfer_prepared(self.new, third)
        self.assertEqual(build.read_private(self.lease)["operationId"], self.new.name)
        (third / "completed.json").unlink()
        build.write_once(third / "builder-handoff.json", b"{}\n")
        with self.assertRaisesRegex(release.Refusal, "prepared.receipt.changed"):
            subject.transfer_prepared(self.new, third)
        self.assertEqual(build.read_private(self.lease)["operationId"], self.new.name)
        self.assertFalse((third / "builder-handoff-intent.json").exists())

    def test_two_prepared_handoffs_preserve_failed_workload_proof(self):
        before, after = self.qualification_resources()
        with patch.object(build, "QUALIFICATION_SOURCE_SHA", "e" * 40), \
             patch.object(subject, "stopped_resources", side_effect=[before, after]):
            subject.recover(self.old, self.new)
        for ident in ("3", "4"):
            op = self.root / (ident * 32)
            op.mkdir(mode=0o700)
            (op / "supervisor").mkdir(mode=0o700)
            build.write_once(op / "supervisor/gcp_build.py", Path(build.__file__).read_bytes())
            build.write_once(op / "intent.json", build.encode(self.target))
        third, fourth = self.root / ("3" * 32), self.root / ("4" * 32)
        subject.transfer_prepared(self.new, third)
        subject.transfer_prepared(third, fourth)
        self.assertEqual(build.read_private(self.lease)["operationId"], fourth.name)
        build.verify_builder_handoff(fourth, self.target)
        build.write_once(self.old / "started.json", build.encode({"invocationId": "f" * 32}))
        owner = {"kind": "build", "operationPath": str(self.old),
                 "intentSha256": build.preflight.digest(self.old / "intent.json")}

        def service(_):
            return subprocess.CompletedProcess([], 0,
                "\n".join(f"{key}={value}" for key, value in self.status["service"].items()), "")

        with patch.object(build, "native", side_effect=service):
            build.heavy_workload_settled(owner, successor=fourth)

    def test_prepared_handoff_accepts_same_builder_recovery_without_transition(self):
        subject.recover(self.old, self.new)
        third = self.root / ("3" * 32)
        third.mkdir(mode=0o700)
        (third / "supervisor").mkdir(mode=0o700)
        build.write_once(third / "supervisor/gcp_build.py", Path(build.__file__).read_bytes())
        build.write_once(third / "intent.json", build.encode(self.target))
        subject.transfer_prepared(self.new, third)
        self.assertFalse((self.new / "resource-transition.json").exists())
        self.assertEqual(build.read_private(self.lease)["operationId"], third.name)
        build.verify_builder_handoff(third, self.target)

    def test_prepared_handoff_depth_refuses_before_lease_transfer(self):
        before, after = self.qualification_resources()
        with patch.object(build, "QUALIFICATION_SOURCE_SHA", "e" * 40), \
             patch.object(subject, "stopped_resources", side_effect=[before, after]):
            subject.recover(self.old, self.new)
        previous = self.new
        for ident in ("3", "4", "5", "6", "7"):
            op = self.root / (ident * 32)
            op.mkdir(mode=0o700)
            (op / "supervisor").mkdir(mode=0o700)
            build.write_once(op / "supervisor/gcp_build.py", Path(build.__file__).read_bytes())
            build.write_once(op / "intent.json", build.encode(self.target))
            if ident == "7":
                with self.assertRaisesRegex(release.Refusal, "prepared_depth"):
                    subject.transfer_prepared(previous, op)
                self.assertEqual(build.read_private(self.lease)["operationId"], previous.name)
                self.assertFalse((op / "builder-handoff-intent.json").exists())
            else:
                subject.transfer_prepared(previous, op)
                build.verify_builder_handoff(op, self.target)
                previous = op


class FrozenLegacyReplayTest(unittest.TestCase):
    def test_actual_prepared_snapshot_replays_after_lease_move(self):
        fixture = build_fixture.BuildTests(methodName="runTest")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        samples = fixture.qualification_fixture()
        retained_sha = fixture.config["sourceSha"]
        before = copy.deepcopy(fixture.config["builder"])
        before.update({"memoryBytes": 16 << 30, "memorySwapBytes": 18 << 30,
                       "cpuQuota": 700000})
        origin_config = copy.deepcopy(fixture.config)
        origin_config["builder"] = before
        target_config = None
        with patch.object(build, "QUALIFICATION_SOURCE_SHA", retained_sha):
            target_config = build.bind_adaptive_selection(fixture.config, samples)
            target_config["operationId"] = "b" * 32
            old = fixture.prepare(origin_config)
            frozen = b"# frozen legacy gcp_build supervisor fixture\n"
            fixture.helpers["gcp_build.py"] = frozen
            new = fixture.prepare(target_config)
            self.assertEqual(build.load_intent(new)[1]["config"], target_config)
        after = target_config["builder"]
        completed = {"completedAt": "2026-10-22T04:40:32Z", "exitCode": 130,
                     "nativeExitCode": 130, "reason": "build.capacity.memory_reserve",
                     "remoteSolveTerminationObserved": False,
                     "invocationId": "f" * 32}
        build.write_once(old / "completed.json", build.encode(completed))
        build.write_once(old / "build.exit", b"130\n")
        lease = old.parent / f"builder-{after['containerId']}.json"
        old_value = {"operationId": old.name,
                     "intentSha256": build.preflight.digest(old / "intent.json")}
        new_value = {"operationId": new.name,
                     "intentSha256": build.preflight.digest(new / "intent.json")}
        build.write_once(lease, build.encode(old_value))
        proof = {"schema": "openclaw.gcp-builder-stopped.v1",
                 "originOperationId": old.name, "builderId": after["containerId"],
                 "builderImageId": after["imageId"],
                 "finishedAt": "2026-10-22T04:42:47Z",
                 "originCompletedAt": completed["completedAt"]}
        build.write_once(new / "builder-stopped.json", build.encode(proof))
        with patch.object(build, "QUALIFICATION_SOURCE_SHA", retained_sha), \
             patch.object(subject, "stopped_resources", side_effect=[before, after]), \
             patch.object(build, "native", return_value=subprocess.CompletedProcess(
                 [], 0, "", "")):
            subject.transition_resources(old, new, build.load_intent(old)[1],
                                         build.load_intent(new)[1], proof)
        lease.write_bytes(build.encode(new_value))  # Prior process lost its final reply.
        status = {"state": "failed", "dispatchRecorded": True,
                  "service": {"InvocationID": "f" * 32, "MainPID": "0",
                              "ActiveState": "failed", "SubState": "failed",
                              "Result": "exit-code"}}
        with patch.object(build, "QUALIFICATION_SOURCE_SHA", "f" * 40), \
             patch.object(build, "RETAINED_QUALIFICATION_SOURCE_SHA", retained_sha), \
             patch.object(subject, "RETAINED_BUILD_SHA256", "0" * 64):
            with self.assertRaisesRegex(release.Refusal, "target.tooling_changed"):
                subject.recover(old, new)
        with patch.object(build, "QUALIFICATION_SOURCE_SHA", "f" * 40), \
             patch.object(build, "RETAINED_QUALIFICATION_SOURCE_SHA", retained_sha), \
             patch.object(subject, "RETAINED_BUILD_SHA256",
                          hashlib.sha256(frozen).hexdigest()), \
             patch.object(subject, "stopped_resources", return_value=after), \
             patch.object(build, "status", return_value=status):
            self.assertEqual(build.load_intent(new)[1]["config"], target_config)
            receipt = subject.recover(old, new)
            self.assertIn("resourceTransitionSha256", receipt)
            self.assertEqual(build.read_private(lease), new_value)
            self.assertEqual(receipt, subject.recover(old, new))
            with patch.object(build, "native") as native:
                with self.assertRaisesRegex(release.Refusal, "retained_source_only"):
                    build.start(new)
                native.assert_not_called()


if __name__ == "__main__":
    unittest.main()
