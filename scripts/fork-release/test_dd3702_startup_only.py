"""Synthetic dd3702 cross-image startup admission tests; no remote or DB work."""

import copy
import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from pathlib import Path

import gcp_snapshot_trial as trial
import release
import test_gcp_snapshot_trial as baseline


class Dd3702StartupOnly(unittest.TestCase):
    def setUp(self):
        # Reuse the existing small in-memory plan fixture, not its test cases.
        self.fixture = baseline.SnapshotTrialTests("test_closed_plan_and_clean_input")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.select_phase("startup")
        self.plan = self.fixture.plan
        self.clean = self.fixture.clean
        self.plan["limits"].update(memoryBytes=16 << 30, minMemoryAvailableBytes=20 << 30,
                                   readBps=320 << 20, writeBps=128 << 20,
                                   timeoutSeconds=940)
        self.image = copy.deepcopy(self.fixture.image)
        self.image.update(sourceSha="9" * 40, sourceTree="8" * 40,
                          indexDigest="sha256:" + "7" * 64)
        self.image["producer"]["toolingSha"] = "6" * 40
        self.check = {"schema": trial.DD_STARTUP_CHECK, "phase": "startup",
                      "doctorOperationId": trial.DD_DOCTOR,
                      "doctorResultSha256": trial.DD_DOCTOR_RESULT_SHA256,
                      "priorStartupResultSha256": "5" * 64,
                      "coverageReceiptSha256": "4" * 64,
                      "coverage": {}}

    def bound(self):
        return patch.multiple(trial, DD_FINAL_IMAGE={key: self.image[key] for key in
                                   trial.LEASE_PATCH_IMAGE},
                              DD_FINAL_PRODUCER=self.image["producer"]["toolingSha"],
                              DD_PRIOR_STARTUP_RESULT_SHA256="5" * 64,
                              DD_FINAL_COVERAGE_SHA256="4" * 64)

    def test_final_pins_are_deliberately_unbound(self):
        with self.assertRaisesRegex(release.Refusal, "trial.dd_final.check_identity"):
            trial.validate(self.plan, self.image, self.clean, self.check)
        with patch.object(trial, "DD_FINAL_IMAGE", None):
            with self.assertRaisesRegex(release.Refusal, "trial.dd_final.image_unbound"):
                trial.qualified_image(self.image, dd_final_startup=True)

    def test_prepared_status_discloses_disabled_pin_mismatch(self):
        self.fixture.intent["check"] = self.check
        with patch.object(trial, "load", return_value=(self.fixture.op, self.fixture.intent)):
            observed = trial.status(self.fixture.op)
        self.assertEqual(observed["state"], "prepared")
        self.assertEqual(observed["pluginPinStatus"],
                         "EXPECTED_MISMATCH_CONTROLLER_DISABLED")
        self.assertFalse(observed["promotionAuthorized"])

    def test_new_check_allows_only_new_image_and_exact_prior(self):
        with self.bound():
            trial.validate(self.plan, self.image, self.clean, self.check)
            trial.qualified_image(self.image, dd_final_startup=True)
            with self.assertRaisesRegex(release.Refusal, "trial.image.not_qualified"):
                trial.qualified_image(self.image)
            bad = copy.deepcopy(self.check)
            bad["doctorResultSha256"] = "a" * 64
            with self.assertRaisesRegex(release.Refusal, "trial.dd_final.check_identity"):
                trial.validate(self.plan, self.image, self.clean, bad)
            bad = copy.deepcopy(self.check)
            bad["priorStartupResultSha256"] = "a" * 64
            with self.assertRaisesRegex(release.Refusal, "trial.dd_final.check_identity"):
                trial.validate(self.plan, self.image, self.clean, bad)
            bad_image = copy.deepcopy(self.image)
            bad_image["indexDigest"] = "sha256:" + "a" * 64
            with self.assertRaisesRegex(release.Refusal, "trial.image.not_qualified"):
                trial.validate(self.plan, bad_image, self.clean, self.check)
            self.plan["phase"] = "doctor"
            with self.assertRaises(release.Refusal):
                trial.validate(self.plan, self.image, self.clean, self.check)

    def test_diagnostic_gateway_trace_requires_explicit_final_startup_check(self):
        self.assertFalse(trial.dd_diagnostic_trace(self.check))
        with self.bound():
            trial.validate(self.plan, self.image, self.clean, self.check)
            diagnostic = copy.deepcopy(self.check)
            diagnostic["diagnosticPluginServiceTrace"] = True
            self.assertTrue(trial.dd_diagnostic_trace(diagnostic))
            trial.validate(self.plan, self.image, self.clean, diagnostic)
            disabled = copy.deepcopy(diagnostic)
            disabled["diagnosticPluginServiceTrace"] = False
            with self.assertRaisesRegex(release.Refusal, "trial.dd_final.check_fields"):
                trial.validate(self.plan, self.image, self.clean, disabled)
        self.assertFalse(trial.dd_diagnostic_trace({"schema": "openclaw.snapshot-trial-check.v1",
                                                    "diagnosticPluginServiceTrace": True}))

    def test_diagnostic_timeline_requires_a_single_exact_final_startup_opt_in(self):
        self.assertFalse(trial.dd_diagnostic_timeline(self.check))
        with self.bound():
            timeline = copy.deepcopy(self.check)
            timeline["diagnosticPluginServiceTimeline"] = True
            timeline["diagnosticPredecessorOperationId"] = "c" * 32
            timeline["diagnosticPredecessorResultSha256"] = "b" * 64
            self.assertTrue(trial.dd_diagnostic_timeline(timeline))
            trial.validate(self.plan, self.image, self.clean, timeline)
            disabled = copy.deepcopy(timeline)
            disabled["diagnosticPluginServiceTimeline"] = False
            with self.assertRaisesRegex(release.Refusal, "trial.dd_final.check_fields"):
                trial.validate(self.plan, self.image, self.clean, disabled)
            both = copy.deepcopy(timeline)
            both["diagnosticPluginServiceTrace"] = True
            with self.assertRaisesRegex(release.Refusal, "trial.dd_final.diagnostic_exclusive"):
                trial.validate(self.plan, self.image, self.clean, both)
        self.assertFalse(trial.dd_diagnostic_timeline({"schema": "openclaw.snapshot-trial-check.v1",
                                                       "diagnosticPluginServiceTimeline": True}))

    def test_timeline_result_has_distinct_bounded_contract(self):
        result = {"schema": "openclaw.rehearsal-native-check.v1", "phase": "candidate-startup",
                  "probeContract": "healthz-startupz-readyz-v1",
                  "healthz": {"status": 200, "ok": True, "statusText": "live"},
                  "startupz": {"status": 200, "ok": True, "statusText": "started"},
                  "readyz": {"status": 200, "ready": True}, "ready": True,
                  "nativeExitCode": 0, "nativeSignal": None, "shutdown": "exited",
                  "escalated": False, "failure": None,
                  "timeline": {"schema": "openclaw.rehearsal-plugin-service-timeline.v1",
                               "status": "observed", "fileBytes": 200, "observedBytes": 200,
                               "directoryDevice": "11", "directoryInode": "12",
                               "fileDevice": "11", "fileInode": "13",
                               "sha256": "a" * 64, "topLevelNameSha256": None,
                               "serviceNameSha256": "b" * 64,
                               "startCount": 1, "endCount": 0, "errorCount": 0,
                               "unmatchedCount": 1, "oldestUnmatchedSeconds": 180,
                               "topLevelStartCount": 0, "topLevelEndCount": 0,
                               "topLevelErrorCount": 0, "topLevelUnmatchedCount": 0,
                               "rawRetained": True}}
        self.assertEqual(trial.checks.validate_result(result, "candidate-startup",
                                                       diagnostic_timeline=True), result)
        with self.assertRaisesRegex(release.Refusal, "check.result.fields"):
            trial.checks.validate_result(result, "candidate-startup")
        result["timeline"]["observedBytes"] = 199
        with self.assertRaisesRegex(release.Refusal, "check.result.timeline_binding"):
            trial.checks.validate_result(result, "candidate-startup", diagnostic_timeline=True)

    def test_failed_timeline_marker_retains_bounded_projection_before_success_gate(self):
        base = {"schema": "openclaw.rehearsal-native-check.v1", "phase": "candidate-startup",
                "probeContract": "healthz-startupz-readyz-v1",
                "healthz": {"status": 200, "ok": True, "statusText": "live"},
                "startupz": {"status": 503, "ok": False, "statusText": "starting"},
                "readyz": {"status": 503, "ready": False}, "ready": False,
                "nativeExitCode": None, "nativeSignal": "SIGTERM", "shutdown": "exited",
                "escalated": False, "failure": "diagnostic_timeline_unmatched_service",
                "timeline": {"schema": "openclaw.rehearsal-plugin-service-timeline.v1",
                             "status": "early-stop", "directoryDevice": "11",
                             "directoryInode": "12", "fileDevice": "11", "fileInode": "13",
                             "fileBytes": 200, "observedBytes": 200,
                             "sha256": "a" * 64,
                             "topLevelNameSha256": hashlib.sha256(
                                 b"sidecars.plugin-services").hexdigest(),
                             "serviceNameSha256": None,
                             "startCount": 1, "endCount": 0, "errorCount": 0,
                             "unmatchedCount": 1, "oldestUnmatchedSeconds": 180,
                             "topLevelStartCount": 1, "topLevelEndCount": 0,
                             "topLevelErrorCount": 0, "topLevelUnmatchedCount": 1,
                             "rawRetained": True}}
        marker = trial.checks.RESULT_PREFIX + json.dumps(base, separators=(",", ":"))
        self.assertLessEqual(len(marker.encode()), 4096)
        parsed = trial.checks.parse_result(marker)
        projection = trial.checks.validate_diagnostic_timeline_failure(
            parsed, "candidate-startup")
        self.assertEqual(projection, base["timeline"])
        with self.assertRaisesRegex(release.Refusal, "check.result.native"):
            trial.checks.validate_result(parsed, "candidate-startup", diagnostic_timeline=True)
        bad = copy.deepcopy(parsed)
        bad["failure"] = "startup_deadline"
        with self.assertRaisesRegex(release.Refusal, "check.result.timeline_failure_binding"):
            trial.checks.validate_diagnostic_timeline_failure(bad, "candidate-startup")
        limit = copy.deepcopy(parsed)
        limit["failure"] = "diagnostic_timeline_limit"
        limit["timeline"]["status"] = "limit"
        limit["timeline"]["fileBytes"] = 8 * 1024 * 1024 + 1
        self.assertEqual(trial.checks.validate_diagnostic_timeline_failure(
            limit, "candidate-startup"), limit["timeline"])

    def test_diagnostic_trace_is_scoped_to_native_startup_child(self):
        contract = "healthz-startupz-readyz-v1"
        ordinary = trial.checks.command("candidate-startup", 940, contract)
        traced = trial.checks.command("candidate-startup", 940, contract, diagnostic_trace=True)
        self.assertEqual(hashlib.sha256(trial.checks.NATIVE.encode()).hexdigest(),
                         "403ce198958925ea92807f68b816e970a34e668b282cd5b323f8f212d79313ef")
        self.assertEqual(hashlib.sha256(ordinary[2].encode()).hexdigest(),
                         "906b5987d705eab0d4074f1f494e4c98b49d08fed500a17db6713349aeb68333")
        self.assertNotIn("OPENCLAW_GATEWAY_STARTUP_TRACE", ordinary[2])
        self.assertEqual(traced[2].count("OPENCLAW_GATEWAY_STARTUP_TRACE:'1'"), 1)
        self.assertEqual(traced[2].replace(", OPENCLAW_GATEWAY_STARTUP_TRACE:'1'", ""),
                         ordinary[2])
        with self.assertRaisesRegex(release.Refusal, "check.diagnostic_trace_scope"):
            trial.checks.command("rollback-startup", 940, "healthz-readyz-v1", diagnostic_trace=True)
        if node := shutil.which("node"):
            for script in (ordinary[2], traced[2]):
                checked = subprocess.run([node, "--check", "-"], input=script,
                                         text=True, capture_output=True, timeout=5)
                self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_container_command_binds_opt_in_trace_to_exact_check(self):
        ordinary = {**self.fixture.intent, "check": self.check}
        diagnostic = copy.deepcopy(ordinary)
        diagnostic["check"]["diagnosticPluginServiceTrace"] = True
        with self.bound():
            normal_argv = trial.create_argv(self.fixture.op, ordinary, self.fixture.devices)
            traced_argv = trial.create_argv(self.fixture.op, diagnostic, self.fixture.devices)
        self.assertNotIn("OPENCLAW_GATEWAY_STARTUP_TRACE", normal_argv[-1])
        self.assertEqual(traced_argv[-1].count("OPENCLAW_GATEWAY_STARTUP_TRACE:'1'"), 1)
        self.assertEqual(normal_argv[:-1], traced_argv[:-1])

    def test_container_command_binds_timeline_to_exact_operation(self):
        ordinary = {**self.fixture.intent, "check": self.check}
        diagnostic = copy.deepcopy(ordinary)
        diagnostic["check"]["diagnosticPluginServiceTimeline"] = True
        diagnostic["check"]["diagnosticPredecessorOperationId"] = "c" * 32
        diagnostic["check"]["diagnosticPredecessorResultSha256"] = "b" * 64
        with self.bound():
            normal_argv = trial.create_argv(self.fixture.op, ordinary, self.fixture.devices)
            timeline_argv = trial.create_argv(self.fixture.op, diagnostic, self.fixture.devices)
        self.assertNotIn("OPENCLAW_DIAGNOSTICS_TIMELINE_PATH", normal_argv[-1])
        self.assertIn(self.fixture.op.name, timeline_argv[-1])
        self.assertIn("OPENCLAW_DIAGNOSTICS_TIMELINE_PATH", timeline_argv[-1])
        self.assertEqual(normal_argv[:-1], timeline_argv[:-1])

    def test_timeline_predecessor_requires_exact_failed_settled_startup(self):
        predecessor = "c" * 32
        result_sha = "b" * 64
        prior_bytes = b"synthetic prior intent"
        prior_intent_sha = trial.digest(prior_bytes)
        prior = {"plan": copy.deepcopy(self.plan), "clean": copy.deepcopy(self.clean),
                 "check": copy.deepcopy(self.check)}
        prior["plan"]["operationId"] = predecessor
        result = {"state": "failed", "cleanup": "owned_container_stopped_retained",
                  "operationId": predecessor,
                  "promotionAuthorized": False, "checkInputSha256": self.plan["checkInputSha256"],
                  "imageReceiptSha256": self.plan["imageReceiptSha256"],
                  "cleanInputSha256": self.plan["cleanInputSha256"],
                  "containerId": "d" * 64,
                  "nativeState": {"Running": False, "Pid": 0, "StartedAt": "start",
                                  "FinishedAt": "finish", "ExitCode": 1, "OOMKilled": False}}
        container = {"State": copy.deepcopy(result["nativeState"])}
        started = {"intentSha256": prior_intent_sha, "image": {"env": []}}
        check = {**self.check, "diagnosticPluginServiceTimeline": True,
                 "diagnosticPredecessorOperationId": predecessor,
                 "diagnosticPredecessorResultSha256": result_sha}
        intent = {"plan": self.plan, "clean": self.clean, "image": self.image, "check": check}
        previous = Path(self.fixture.op.parent) / predecessor
        with patch.object(trial, "read_retained", return_value=(previous, prior)), \
             patch.object(trial, "DD_PRIOR_STARTUP_RESULT_SHA256", "5" * 64), \
             patch.object(trial, "private_json", return_value=(result, result_sha)), \
             patch.object(trial, "status", return_value={"state": "failed", "result": result}), \
             patch.object(trial.durable, "private_bytes", return_value=prior_bytes), \
             patch.object(trial.durable, "read_private", return_value=started), \
             patch.object(trial, "inspect_container", return_value=container), \
             patch.object(trial, "validate_owned_container"), \
             patch.object(trial, "validate_container"), \
             patch.object(trial, "retained_devices", return_value=self.fixture.devices), \
             patch.object(trial.durable, "heavy_workload_settled") as settled:
            self.assertEqual(trial.validate_dd_diagnostic_predecessor(check, intent),
                             {"operationId": predecessor, "intentSha256": prior_intent_sha})
            settled.assert_called_once()
            wrong_result = {**check, "diagnosticPredecessorResultSha256": "f" * 64}
            with self.assertRaisesRegex(release.Refusal, "diagnostic_predecessor_changed"):
                trial.validate_dd_diagnostic_predecessor(wrong_result, intent)
            container["State"]["Running"] = True
            with self.assertRaisesRegex(release.Refusal, "diagnostic_predecessor_active"):
                trial.validate_dd_diagnostic_predecessor(check, intent)

    def test_timeline_claim_requires_exact_settled_predecessor_transfer(self):
        op = self.fixture.op
        predecessor = {"operationId": "c" * 32, "intentSha256": "d" * 64}
        diagnostic = {**self.check, "diagnosticPluginServiceTimeline": True,
                      "diagnosticPredecessorOperationId": predecessor["operationId"],
                      "diagnosticPredecessorResultSha256": "b" * 64}
        intent = {**self.fixture.intent, "check": diagnostic}
        lease = op.parent / ("dataset-" + trial.digest(self.clean["mountRoot"].encode()) + ".json")
        requested = {"operationId": op.name,
                     "intentSha256": trial.digest((op / "intent.json").read_bytes())}
        lease.write_bytes(trial.durable.encode(requested))
        lease.chmod(0o600)
        previous_file = op / "dataset-previous.json"
        previous_file.write_bytes(trial.durable.encode(predecessor))
        previous_file.chmod(0o600)
        trial.verify_dd_startup_claim(op, intent, {"datasetLeasePredecessor": predecessor})
        with self.assertRaisesRegex(release.Refusal, "trial.dd_final.lease_predecessor"):
            trial.verify_dd_startup_claim(op, intent, {"datasetLeasePredecessor": {
                "operationId": trial.DD_PRIOR_STARTUP, "intentSha256": "d" * 64}})
        lease.write_bytes(trial.durable.encode(predecessor))
        with self.assertRaisesRegex(release.Refusal, "trial.dd_final.lease_changed"):
            trial.verify_dd_startup_claim(op, intent, {"datasetLeasePredecessor": predecessor})

    def test_timeline_raw_cleanup_waits_for_settlement_and_pins_exact_owned_file(self):
        projection = {"directoryDevice": "11", "directoryInode": "12",
                      "fileDevice": "11", "fileInode": "13",
                      "observedBytes": 100, "sha256": "a" * 64}
        with patch.object(trial.subprocess, "run") as run:
            retained = trial.cleanup_dd_timeline_raw(self.fixture.op, self.clean, projection,
                                                      stopped=True, settled=False)
            self.assertEqual(retained["status"], "RETAINED_UNSETTLED")
            run.assert_not_called()
            run.return_value = SimpleNamespace(returncode=0, stdout=b'{"status":"REMOVED"}', stderr=b"")
            removed = trial.cleanup_dd_timeline_raw(self.fixture.op, self.clean, projection,
                                                     stopped=True, settled=True)
            self.assertEqual(removed["status"], "REMOVED")
            request = json.loads(run.call_args.kwargs["input"])
            self.assertEqual(request["operationId"], self.fixture.op.name)
            self.assertEqual(request["timeline"], projection)
            self.assertEqual(request["cacheSource"], next(row["source"] for row in
                self.clean["mounts"] if row["target"] == "/rehearsal/cache"))
            run.return_value = SimpleNamespace(returncode=2, stdout=b"", stderr=b"")
            unknown = trial.cleanup_dd_timeline_raw(self.fixture.op, self.clean, projection,
                                                     stopped=True, settled=True)
            self.assertEqual(unknown["status"], "RETAINED_CLEANUP_UNKNOWN")

    def test_timeline_owner_cleanup_rejects_wrong_inode_and_preserves_siblings(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            operation = "c" * 32
            directory = root / ("startup-timeline-" + operation)
            directory.mkdir(mode=0o700)
            target = directory / "events.jsonl"
            content = b'{"type":"span.start","name":"synthetic"}\n'
            target.write_bytes(content)
            target.chmod(0o600)
            sibling = root / "unrelated.txt"
            sibling.write_text("keep")
            folder_stat, file_stat = directory.stat(), target.stat()
            metadata = {"directoryDevice": str(folder_stat.st_dev),
                        "directoryInode": str(folder_stat.st_ino),
                        "fileDevice": str(file_stat.st_dev),
                        "fileInode": str(file_stat.st_ino),
                        "observedBytes": len(content),
                        "sha256": hashlib.sha256(content).hexdigest()}
            request = {"schema": "openclaw.timeline-owned-cleanup.v1",
                       "cacheSource": str(root), "operationId": operation,
                       "timeline": metadata}
            # Exercise the exact helper under this test process's UID.
            helper = trial._TIMELINE_OWNER_CLEANUP.replace("1000", str(os.getuid()))
            command = ["python3", "-I", "-B", "-S", "-c", helper]
            wrong = copy.deepcopy(request)
            wrong["timeline"]["fileInode"] = str(file_stat.st_ino + 1)
            refused = subprocess.run(command, input=trial.durable.encode(wrong),
                                     capture_output=True, timeout=5)
            self.assertNotEqual(refused.returncode, 0)
            self.assertTrue(target.exists())
            accepted = subprocess.run(command, input=trial.durable.encode(request),
                                      capture_output=True, timeout=5)
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertEqual(accepted.stdout, b'{"status":"REMOVED"}')
            self.assertFalse(directory.exists())
            self.assertEqual(sibling.read_text(), "keep")

    def test_prestart_image_inspection_keeps_new_check_bound(self):
        loaded = {"Id": self.image["indexDigest"], "Os": "linux", "Architecture": "amd64",
                  "Config": {"Labels": {"org.opencontainers.image.revision": self.image["sourceSha"],
                                        "org.opencontainers.image.version": self.image["version"]},
                             "Volumes": None, "Env": []}}
        with self.bound(), patch.object(trial, "docker", return_value=json.dumps([loaded]).encode()):
            with self.assertRaisesRegex(release.Refusal, "trial.image.not_qualified"):
                trial.observe_image(self.image, "startup")
            self.assertEqual(trial.observe_image(self.image, "startup", self.check)["loadedId"],
                             self.image["indexDigest"])

    def test_original_backup_metadata_is_exact_and_read_only(self):
        root = self.fixture.dataset
        rows, files = [], []
        for number in range(11):
            item = root / (f"agent{number}.sqlite.pre-startup-migration-{trial.DD_BACKUP_ID}.bak")
            item.write_bytes(b"synthetic")
            info = item.lstat()
            allocated = info.st_blocks * 512
            rows.append({"path": str(item), "kind": "migration-backup",
                         "classification": "native-revalidation-required",
                         "disposition": "retain", "nativeDiscardOnRetry": False,
                         "device": info.st_dev, "inode": info.st_ino, "links": info.st_nlink,
                         "sizeBytes": info.st_size, "allocatedBytes": allocated})
            files.append({"path": str(item), "device": info.st_dev, "inode": info.st_ino,
                          "links": info.st_nlink, "sizeBytes": info.st_size,
                          "allocatedBytes": allocated, "modifiedNs": info.st_mtime_ns,
                          "changedNs": info.st_ctime_ns, "ownerUid": info.st_uid,
                          "mode": stat.S_IMODE(info.st_mode)})
        files.sort(key=lambda entry: entry["path"])
        prior = {"clean": {"mountRoot": str(root)},
                 "check": {"reconciliation": {"artifacts": rows}}}
        receipt = {"backupId": trial.DD_BACKUP_ID,
                   "backupManifestSha256": "a" * 64, "backupFiles": files}
        reuse = {"backupId": trial.DD_BACKUP_ID, "backupCount": 11,
                 "manifestSha256": "a" * 64,
                 "targetSourceSha": trial.LEASE_PATCH_IMAGE["sourceSha"],
                 "targetImageReceiptSha256": trial.LEASE_PATCH_RECEIPT_SHA256}
        by_path = {row["path"]: row for row in files}
        observed = [{key: value for key, value in by_path[row["path"]].items() if key != "path"}
                    for row in rows]
        with patch.object(trial, "backup_reuse", return_value=reuse), \
             patch.object(trial, "backup_owner_stats", return_value=observed):
            trial.validate_dd_original_backup_files(prior, receipt)
            files[0]["modifiedNs"] += 1
            with self.assertRaisesRegex(release.Refusal, "trial.dd_final.backup_changed"):
                trial.validate_dd_original_backup_files(prior, receipt)

    def test_dataset_transfer_requires_settled_startup_lease_not_older_doctor(self):
        op = self.fixture.op
        intent = self.fixture.intent
        intent["check"] = self.check
        lease = op.parent / ("dataset-" + trial.digest(self.clean["mountRoot"].encode()) + ".json")
        current = {"operationId": trial.DD_PRIOR_STARTUP, "intentSha256": "a" * 64}
        older = {"operationId": trial.DD_DOCTOR, "intentSha256": "b" * 64}
        prior = {**older, "datasetLeasePredecessor": current}
        def reserve(*_args, reserve_resource=None):
            reserve_resource()
        def attempt():
            with patch.object(trial, "load", return_value=(op, intent)), \
                 patch.object(trial.sys, "platform", "linux"), \
                 patch.object(trial, "phase_prerequisites", return_value=prior), \
                 patch.object(trial, "snapshot_paths", return_value={}), \
                 patch.object(trial, "block_devices", return_value=self.fixture.devices), \
                 patch.object(trial, "no_other_writer"), \
                 patch.object(trial, "observe_image", return_value={"loadedId": self.image["indexDigest"], "env": []}), \
                 patch.object(trial, "capacity", return_value={"dataFreeBytes": 200 << 30}), \
                 patch.object(trial.durable, "reserve_heavy_workload", side_effect=reserve), \
                 patch.object(trial.Path, "read_text", return_value="synthetic-boot"), \
                 patch.object(trial, "status", return_value={"state": "unknown"}), \
                 patch.object(trial.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as dispatch:
                result = trial.start(op)
                return result, dispatch.call_count
        with self.assertRaisesRegex(release.Refusal, "trial.dd_final.missing_predecessor_claim"):
            attempt()
        self.assertFalse((op / "start-intent.json").exists())
        reservation = {"operationId": op.name,
                       "intentSha256": trial.digest((op / "intent.json").read_bytes())}
        lease.write_bytes(trial.durable.encode(reservation))
        lease.chmod(0o600)
        with self.assertRaisesRegex(release.Refusal, "trial.dd_final.lease_changed"):
            attempt()
        self.assertFalse((op / "start-intent.json").exists())
        lease.write_bytes(trial.durable.encode(older))
        lease.chmod(0o600)
        with self.assertRaisesRegex(release.Refusal, "trial.dataset.reserved"):
            attempt()
        self.assertFalse((op / "start-intent.json").exists())
        lease.write_bytes(trial.durable.encode(current))
        self.assertEqual(attempt(), ({"state": "unknown"}, 1))
        self.assertEqual(trial.durable.read_private(lease),
                         {"operationId": op.name,
                          "intentSha256": trial.digest((op / "intent.json").read_bytes())})
        trial.verify_dd_startup_claim(op, intent, prior)
        lease.write_bytes(trial.durable.encode(older))
        with self.assertRaisesRegex(release.Refusal, "trial.dd_final.lease_changed"):
            trial.verify_dd_startup_claim(op, intent, prior)
        lease.write_bytes(trial.durable.encode({"operationId": op.name,
                             "intentSha256": trial.digest((op / "intent.json").read_bytes())}))
        (op / "dataset-previous.json").write_bytes(trial.durable.encode(older))
        with self.assertRaisesRegex(release.Refusal, "trial.dd_final.lease_changed"):
            trial.verify_dd_startup_claim(op, intent, prior)


if __name__ == "__main__":
    unittest.main()
