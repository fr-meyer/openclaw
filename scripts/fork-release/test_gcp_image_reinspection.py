"""Synthetic orchestration; no image, Docker, cloud or database execution."""
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

import gcp_image_reinspection as driver
import hosted_privacy

SOURCE, TOOLING, ORIGINAL = "a" * 40, "b" * 40, "c" * 40
INDEX, IMAGE, CONFIG = ("sha256:" + char * 64 for char in "def")
CLOCK = datetime(2026, 10, 24, 12, 0, tzinfo=timezone.utc)


def save(path, value):
    raw = driver.encoded(value)
    path.write_bytes(raw)
    path.chmod(0o600)
    return driver.digest(raw)


def privacy_report():
    return {"schema": "openclaw.hosted-privacy.v2", "status": "passed", "sourceSha": SOURCE,
            "toolingSha": TOOLING, "indexDigest": INDEX, "imageDigest": IMAGE, "configDigest": CONFIG,
            "inspectionComplete": True, "findings": [], "representativeLimit": 64,
            "representativesTruncated": False, "locationIndex": [], "locationIndexTruncated": False,
            "locationIndexLimit": 4096, "locationIndexByteLimit": 524288,
            "findingSummary": {"unit": hosted_privacy.COUNT_UNIT, "total": 0,
                               "byRule": dict.fromkeys(hosted_privacy.FINDING_RULES, 0),
                               "byUnit": dict.fromkeys(hosted_privacy.FINDING_UNITS, 0)}}


class FakeOwners:
    def __init__(self, fixture, mode="passed"):
        self.fixture, self.mode, self.calls = fixture, mode, []
        self.after_privacy = None

    def __call__(self, args):
        self.calls.append(args)
        if args[1].endswith("hosted_privacy.py"):
            value = privacy_report()
            if self.mode == "findings":
                value["status"] = "failed"
                value["findings"] = [{"rule": "service_token", "locationSha256": "1" * 64}]
                value["findingSummary"]["total"] = 1
                value["findingSummary"]["byRule"]["service_token"] = 1
                value["findingSummary"]["byUnit"]["archive_member"] = 1
            if self.mode == "incomplete":
                value.update({"status": "failed", "inspectionComplete": False, "refusal": "unsupported_config"})
            save(Path(args[args.index("--output") + 1]), value)
            if self.after_privacy:
                self.after_privacy()
            if self.mode == "inconsistent-exit":
                return 1
            return 0 if value["status"] == "passed" else 1
        if args[2] in ("capture-retained-gcp-origin", "capture-retained-hosted-origin"):
            if self.mode == "capture-failed":
                return 1
            hosted = args[2] == "capture-retained-hosted-origin"
            value = {"schema": f"openclaw.retained-{'hosted' if hosted else 'gcp'}-build-context.v1", "status": "captured",
                                 "qualified": False, "productionAuthorized": False, "sourceSha": SOURCE,
                                 "sourceTree": "1" * 40, "indexDigest": INDEX,
                                 "inspectionToolingSha": TOOLING}
            if hosted:
                value.update(originAuthenticated=self.mode != "capture-unauthenticated",
                             hostedPlanSha256=self.fixture.plan["hostedPlanSha256"], resourcesSha256=self.fixture.original_pin,
                             archiveSha256=self.fixture.hosted_plan["archiveSha256"], producer=self.fixture.producer())
            else:
                value["executionSha256"] = self.fixture.plan["executionSha256"]
            save(Path(args[4]), value)
            return 0
        if args[2] in ("verify-retained-gcp", "verify-retained-hosted"):
            if self.mode == "verify-timeout":
                raise subprocess.TimeoutExpired(args, 900)
            out = Path(args[4]).parent
            return 0 if (out / "receipt.json").exists() and (out / "admission.json").exists() else 1
        if args[2] not in ("qualify-retained-gcp", "qualify-retained-hosted"):
            raise AssertionError("Unexpected command owner")
        plan, out = json.loads(Path(args[3]).read_text()), Path(args[4])
        self.fixture.test.assertEqual(plan["originalResourcesSha256"], self.fixture.original_pin)
        self.fixture.test.assertEqual(driver.private_data(plan["originalResourcesPath"])[1], self.fixture.original_pin)
        self.fixture.test.assertEqual(out.stat().st_mode & 0o777, 0o700)
        self.fixture.test.assertEqual(list(out.iterdir()), [])
        if args[2] == "qualify-retained-hosted":
            save(out / "hosted-authentication.json", {"producer": self.fixture.producer(), "originAuthenticated": True})
        save(out / "static.json", {"schema": "openclaw.fork-release-static.v1", "sourceSha": SOURCE,
                                    "indexDigest": INDEX, "inspectionToolingSha": TOOLING,
                                    "status": "failed" if self.mode == "static-failed" else "passed"})
        save(out / "origin.json", {"sourceSha": SOURCE, "indexDigest": INDEX})
        save(out / "diagnostics.json", {"status": "passed"})
        if self.mode in ("findings", "static-failed"):
            return 1
        save(out / "native-attempt.json", {"toolingSha": TOOLING})
        if self.mode == "interrupted":
            raise subprocess.TimeoutExpired(args, 900)
        save(out / "receipt.json", {"schema": "openclaw.fork-release-image.v2", "sourceSha": SOURCE,
                                    "indexDigest": INDEX, "imageDigest": IMAGE, "configDigest": CONFIG,
                                    "producer": self.fixture.producer()})
        if self.mode == "receipt-without-admission":
            raise subprocess.TimeoutExpired(args, 900)
        for name in ("native.json", "native-execution.json", "admission.json"):
            save(out / name, {"status": "passed"})
        return 0

    def actions(self):
        return ["privacy" if a[1].endswith("hosted_privacy.py") else a[2] for a in self.calls]


class Fixture:
    def __init__(self, root, test):
        root = root.resolve()
        self.root, self.test, self.current = root, test, CLOCK
        root.chmod(0o700)
        self.source, self.oci, self.build = (root / name for name in ("source", "oci", "old-build"))
        for path in (self.source, self.oci, self.build):
            path.mkdir(mode=0o700)
        self.execution, self.manifest, self.inventory = self.build / "execution.json", root / "manifest.json", root / "inventory.json"
        execution_pin = save(self.execution, {"synthetic": "original-owned-build"})
        save(self.manifest, {"source": {"commit": SOURCE}})
        save(self.inventory, {})
        self.plan = {"schema": "openclaw.retained-gcp-input.v1", "manifestPath": str(self.manifest),
                     "inventoryPath": str(self.inventory), "sourceDir": str(self.source), "ociDir": str(self.oci),
                     "executionPath": str(self.execution), "originalToolingSha": ORIGINAL,
                     "executionSha256": execution_pin, "inspectionToolingSha": TOOLING}
        self.plan_path, self.original, self.admission = (root / name for name in ("plan.json", "original-resources.json", "admission.json"))
        self.plan_pin = save(self.plan_path, self.plan)
        self.original_pin = save(self.original, {"toolingSha": ORIGINAL, "sourceSha": SOURCE, "opaque": "original-resource-input"})
        self.admission_value = {"schema": "openclaw.fork-release-reinspection-resource-admission.v1",
                                "sourceSha": SOURCE, "indexDigest": INDEX, "inspectionToolingSha": TOOLING,
                                "checkedAt": driver.utc(CLOCK - timedelta(seconds=5)),
                                "expiresAt": driver.utc(CLOCK + timedelta(seconds=100)), "status": "passed",
                                "checks": {"capacity": "passed", "ownership": "passed", "heavyWorkload": "clear"}}
        self.admission_pin = save(self.admission, self.admission_value)
        self.state = root / ("3" * 32)

    def producer(self):
        if self.plan["schema"] == "openclaw.retained-hosted-input.v1":
            return {"workflowSha": ORIGINAL, "runId": "123", "attempt": "2"}
        return {"kind": "gcp", "toolingSha": ORIGINAL, "operationId": "2" * 32, "attempt": 1,
                "executionSha256": self.plan["executionSha256"]}

    def use_hosted(self):
        custody = self.root / "custody"
        custody.mkdir(mode=0o700)
        self.original = custody / "resources.json"
        self.original_pin = save(self.original, {"schema": "openclaw.hosted-resources.v1", "status": "passed",
            "sourceSha": SOURCE, "toolingSha": ORIGINAL, "indexDigest": INDEX, "violations": []})
        self.hosted_path = self.root / "hosted-plan.json"
        self.hosted_plan = {"schema": "openclaw.retained-hosted-origin-input.v1", "sourceDir": str(self.source),
            "ociDir": str(self.oci), "manifestPath": str(self.manifest), "inventoryPath": str(self.inventory),
            "metadataPath": str(custody / "build-metadata.json"), "originPath": str(custody / "build-origin.json"),
            "archivePath": str(self.root / "retained-oci.tar"), "resourcesPath": str(self.original),
            "workflowSha": ORIGINAL, "workflowRef": "refs/heads/synthetic-release", "inspectionToolingSha": TOOLING,
            "runId": "123", "attempt": "2", "jobId": "456", "archiveSha256": "4" * 64, "originSha256": "5" * 64,
            "manifestSha256": "6" * 64, "inventorySha256": "7" * 64, "buildMetadataSha256": "8" * 64,
            "resourcesSha256": self.original_pin, "indexDigest": INDEX, "builtAt": driver.utc(CLOCK)}
        pin = save(self.hosted_path, self.hosted_plan)
        self.plan = {key: self.plan[key] for key in ("manifestPath", "inventoryPath", "sourceDir", "ociDir", "inspectionToolingSha")}
        self.plan.update(schema="openclaw.retained-hosted-input.v1", hostedPlanPath=str(self.hosted_path), hostedPlanSha256=pin)
        self.plan_pin = save(self.plan_path, self.plan)

    def run(self, owners, **overrides):
        args = {"admission_path": self.admission, "admission_pin": self.admission_pin,
                "original_resources": self.original, "resources_pin": self.original_pin,
                "node": sys.executable, "execute": owners, "clock": lambda: self.current}
        if self.plan["schema"] == "openclaw.retained-hosted-input.v1":
            args.update(mode="hosted", original_resources=None, resources_pin=None)
        args.update(overrides)
        with patch.object(driver.gcp_build, "clean_checkout"):
            return driver.inspect(self.plan_path, self.plan_pin, self.state, **args)


class DriverTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.f = Fixture(Path(self.temp.name), self)

    def test_hosted_cli_uses_genuine_producer_and_signed_resources_not_gcp_identity(self):
        self.f.use_hosted()
        owner, output = FakeOwners(self.f), io.StringIO()
        arguments = ["--mode", "hosted", "--plan", str(self.f.plan_path), "--plan-sha256", self.f.plan_pin,
                     "--state-dir", str(self.f.state), "--resource-admission", str(self.f.admission),
                     "--resource-admission-sha256", self.f.admission_pin, "--node", sys.executable]
        with patch.object(driver.gcp_build, "clean_checkout"), redirect_stdout(output):
            status = driver.main(arguments, execute=owner, clock=lambda: CLOCK)
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(output.getvalue())["schema"], "openclaw.hosted-image-reinspection-summary.v1")
        self.assertEqual(owner.actions(), ["capture-retained-hosted-origin", "privacy", "qualify-retained-hosted", "verify-retained-hosted"])
        intent = json.loads((self.f.state / "intent.json").read_text())
        self.assertNotIn("executionSha256", intent)
        self.assertEqual(intent["originalProducer"], self.f.producer())
        qualified_plan = json.loads((self.f.state / "qualification-plan.json").read_text())
        self.assertEqual(qualified_plan["schema"], "openclaw.retained-hosted-qualification.v1")
        self.assertEqual(qualified_plan["originalResourcesSha256"], self.f.original_pin)
        self.assertEqual((self.f.state / "original-resources.json").read_bytes(), self.f.original.read_bytes())
        handoff = json.loads((self.f.state / "handoff.json").read_text())
        self.assertEqual(handoff["originalProducer"], self.f.producer())
        self.assertNotIn("operationId", handoff["originalProducer"])

    def test_hosted_complete_resume_only_verifies_and_authentication_bytes_are_pinned(self):
        self.f.use_hosted()
        owner = FakeOwners(self.f)
        self.f.run(owner)
        owner.calls.clear()
        self.f.current += timedelta(days=1)
        self.assertTrue(self.f.run(owner, admission_path=None, admission_pin=None)["qualified"])
        self.assertEqual(owner.actions(), ["verify-retained-hosted"])
        save(self.f.state / "qualification/hosted-authentication.json", {"originAuthenticated": True, "changed": True})
        owner.calls.clear()
        with self.assertRaisesRegex(driver.Refusal, "stage_changed"):
            self.f.run(owner)
        self.assertEqual(owner.calls, [])

    def test_explicit_hosted_custody_pair_flows_through_owned_stages_and_qualification_plan(self):
        self.f.use_hosted()
        custody = self.f.root / "synthetic-custody.json"
        pin = save(custody, {"synthetic": "custody transport only; authentication belongs to image owner"})
        self.f.plan.update(authenticationCustodyPath=str(custody), authenticationCustodySha256=pin)
        self.f.plan_pin = save(self.f.plan_path, self.f.plan)
        owners = FakeOwners(self.f)
        result = self.f.run(owners)
        self.assertTrue(result["qualified"])
        qualified = driver.document(self.f.state / "qualification-plan.json")[0]
        self.assertEqual(qualified["authenticationCustodyPath"], str(custody))
        self.assertEqual(qualified["authenticationCustodySha256"], pin)
        self.assertEqual(owners.actions(), ["capture-retained-hosted-origin", "privacy", "qualify-retained-hosted", "verify-retained-hosted"])
        completed = driver.document(self.f.state / "capture.completed.json")[0]
        self.assertEqual(completed["outputs"], {"capture.json": driver.private_data(self.f.state / "capture.json")[1]})

    def test_partial_or_changed_hosted_custody_refuses_before_stage_creation(self):
        self.f.use_hosted()
        custody = self.f.root / "synthetic-custody.json"; save(custody, {})
        original = dict(self.f.plan)
        for values in ({"authenticationCustodyPath": str(custody)},
                       {"authenticationCustodyPath": str(custody), "authenticationCustodySha256": "f"*64}):
            with self.subTest(values=values):
                self.f.plan = {**original, **values}; self.f.plan_pin = save(self.f.plan_path, self.f.plan)
                owners = FakeOwners(self.f)
                with self.assertRaises(ValueError): self.f.run(owners)
                self.assertEqual(owners.calls, []); self.assertFalse(self.f.state.exists())

    def test_hosted_plan_mismatch_or_arbitrary_resource_override_never_calls_owner(self):
        self.f.use_hosted()
        owner = FakeOwners(self.f)
        with self.assertRaisesRegex(driver.Refusal, "hosted.resource_override"):
            self.f.run(owner, original_resources=self.f.original, resources_pin=self.f.original_pin)
        self.f.plan["sourceDir"] = str(self.f.build)
        self.f.plan_pin = save(self.f.plan_path, self.f.plan)
        with self.assertRaisesRegex(driver.Refusal, "hosted.plan_mismatch"):
            self.f.run(owner)
        self.assertEqual(owner.calls, [])

    def test_hosted_requires_explicit_mode_and_true_owner_authentication(self):
        self.f.use_hosted()
        owner = FakeOwners(self.f, "capture-unauthenticated")
        with self.assertRaisesRegex(driver.Refusal, "plan.invalid"):
            self.f.run(owner, mode="gcp")
        with self.assertRaisesRegex(driver.Refusal, "hosted.authentication_mismatch"):
            self.f.run(owner)
        self.assertEqual(owner.actions(), ["capture-retained-hosted-origin"])

    def test_hosted_findings_still_collect_static_without_native_and_uncertainty_never_reruns(self):
        for mode in ("findings", "interrupted"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                f = Fixture(Path(tmp), self)
                f.use_hosted()
                owner = FakeOwners(f, mode)
                result = f.run(owner)
                self.assertFalse(result["qualified"])
                self.assertEqual(result["checks"]["static"], "passed")
                self.assertEqual((f.state / "qualification/native-attempt.json").exists(), mode == "interrupted")
                owner.calls.clear()
                self.assertFalse(f.run(owner)["qualified"])
                self.assertEqual(owner.calls, [])

    def test_hosted_nested_plan_pin_and_archived_resources_change_fail_before_capture(self):
        for target in ("plan", "resources"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as tmp:
                f = Fixture(Path(tmp), self)
                f.use_hosted()
                path = f.hosted_path if target == "plan" else f.original
                path.write_bytes(path.read_bytes() + b" ")
                owner = FakeOwners(f)
                with self.assertRaises(ValueError):
                    f.run(owner)
                self.assertEqual(owner.calls, [])

    def test_qualified_handoff_preserves_producer_without_build_or_transfer(self):
        owner = FakeOwners(self.f)
        result = self.f.run(owner)
        self.assertEqual(result["status"], "qualified")
        self.assertFalse(result["productionAuthorized"])
        handoff = json.loads((self.f.state / "handoff.json").read_text())
        self.assertEqual(handoff["originalProducer"]["toolingSha"], ORIGINAL)
        self.assertEqual(handoff["inspectionToolingSha"], TOOLING)
        self.assertFalse(handoff["rebuildRequired"])
        self.assertEqual(owner.actions(), ["capture-retained-gcp-origin", "privacy", "qualify-retained-gcp", "verify-retained-gcp"])
        self.assertTrue(all(not any(word in a for word in ("buildx", "gcloud", "systemd-run")) for args in owner.calls for a in args))
        for name in ("intent.json", "base-plan.json", "original-resources.json", "handoff.json"):
            self.assertEqual((self.f.state / name).stat().st_mode & 0o777, 0o600)

    def test_optional_loaded_transport_is_pinned_forwarded_and_resumed_without_native(self):
        self.f.plan["smokeTransport"] = "loaded"
        self.f.plan_pin = save(self.f.plan_path, self.f.plan)
        owner = FakeOwners(self.f)
        self.assertTrue(self.f.run(owner)["qualified"])
        qualified_plan = json.loads((self.f.state / "qualification-plan.json").read_text())
        self.assertEqual(qualified_plan["smokeTransport"], "loaded")
        self.assertEqual(json.loads((self.f.state / "base-plan.json").read_text()), self.f.plan)
        self.f.current += timedelta(days=1)
        owner.calls.clear()
        self.assertTrue(self.f.run(owner, admission_path=None, admission_pin=None)["qualified"])
        self.assertEqual(owner.actions(), ["verify-retained-gcp"])

    def test_transport_scope_is_closed_before_any_owner_runs(self):
        for value in ("skopeo", "docker", "LOADED", "loaded --pull", "", None, False, ["loaded"], {"command": "load"}):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as tmp:
                f = Fixture(Path(tmp), self)
                f.plan["smokeTransport"] = value
                f.plan_pin = save(f.plan_path, f.plan)
                owner = FakeOwners(f)
                with self.assertRaisesRegex(driver.Refusal, "plan.invalid"):
                    f.run(owner)
                self.assertEqual(owner.calls, [])
        self.f.plan["importCommand"] = "synthetic-unapproved-command"
        self.f.plan_pin = save(self.f.plan_path, self.f.plan)
        owner = FakeOwners(self.f)
        with self.assertRaisesRegex(driver.Refusal, "plan.invalid"):
            self.f.run(owner)
        self.assertEqual(owner.calls, [])

    def test_loaded_transport_change_refuses_completed_and_lost_outcome_resume(self):
        for lost_outcome in (False, True):
            with self.subTest(lost_outcome=lost_outcome), tempfile.TemporaryDirectory() as tmp:
                f = Fixture(Path(tmp), self)
                f.plan["smokeTransport"] = "loaded"
                f.plan_pin = save(f.plan_path, f.plan)
                owner = FakeOwners(f)
                f.run(owner)
                if lost_outcome:
                    (f.state / "qualify.completed.json").unlink()
                path = f.state / "qualification-plan.json"
                changed = json.loads(path.read_text())
                del changed["smokeTransport"]
                save(path, changed)
                owner.calls.clear()
                with self.assertRaisesRegex(driver.Refusal, "stage_inputs_changed"):
                    f.run(owner)
                self.assertEqual(owner.calls, [])

    def test_findings_collect_static_but_block_native_and_handoff(self):
        owner = FakeOwners(self.f, "findings")
        result = self.f.run(owner)
        self.assertEqual(result["checks"], {"metadata": "passed", "resources": "passed", "privacy": "failed", "static": "passed", "native": "blocked"})
        self.assertFalse((self.f.state / "qualification/native-attempt.json").exists())
        self.assertIn("--qualify-public-members", next(a for a in owner.calls if a[1].endswith("hosted_privacy.py")))
        self.assertFalse((self.f.state / "handoff.json").exists())

    def test_structure_and_static_failures_are_distinct(self):
        for mode in ("incomplete", "static-failed"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                f = Fixture(Path(tmp), self)
                owner = FakeOwners(f, mode)
                result = f.run(owner)
                self.assertEqual(result["checks"]["native"], "blocked")
                self.assertEqual(result["checks"]["static"], "blocked" if mode == "incomplete" else "failed")
                self.assertEqual("qualify-retained-gcp" in owner.actions(), mode != "incomplete")

    def test_capture_failure_never_invents_origin(self):
        owner = FakeOwners(self.f, "capture-failed")
        result = self.f.run(owner)
        self.assertEqual(result["reason"], "metadata.unconfirmed")
        self.assertEqual(owner.actions(), ["capture-retained-gcp-origin"])
        self.assertFalse((self.f.state / "privacy.json").exists())

    def test_stale_or_wrong_resource_admission_blocks_heavy_work(self):
        for key, value in (("expiresAt", driver.utc(CLOCK - timedelta(seconds=1))), ("indexDigest", "sha256:" + "9" * 64), ("status", "failed")):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as tmp:
                f = Fixture(Path(tmp), self)
                f.admission_value[key] = value
                f.admission_pin = save(f.admission, f.admission_value)
                owner = FakeOwners(f)
                result = f.run(owner)
                self.assertEqual(result["checks"]["resources"], "failed")
                self.assertEqual(owner.actions(), ["capture-retained-gcp-origin"])

    def test_admission_is_rechecked_after_privacy(self):
        owner = FakeOwners(self.f)
        owner.after_privacy = lambda: setattr(self.f, "current", CLOCK + timedelta(seconds=101))
        result = self.f.run(owner)
        self.assertEqual(result["reason"], "resource.admission_refused")
        self.assertEqual(owner.actions(), ["capture-retained-gcp-origin", "privacy"])

    def test_inconsistent_scanner_exit_cannot_reach_native(self):
        owner = FakeOwners(self.f, "inconsistent-exit")
        result = self.f.run(owner)
        self.assertEqual(result["reason"], "privacy.exit_inconsistent")
        self.assertEqual(owner.actions(), ["capture-retained-gcp-origin", "privacy"])

    def test_verifier_timeout_is_redacted_and_never_repeats_native(self):
        owner = FakeOwners(self.f, "verify-timeout")
        result = self.f.run(owner)
        self.assertEqual(result["reason"], "native.verification_failed")
        owner.calls.clear()
        result = self.f.run(owner)
        self.assertEqual(result["reason"], "native.verification_failed")
        self.assertEqual(owner.actions(), ["verify-retained-gcp"])
        self.assertFalse(result["qualified"])

    def test_complete_resume_only_verifies_without_new_admission_or_native(self):
        owner = FakeOwners(self.f)
        self.f.run(owner)
        owner.calls.clear()
        self.f.current += timedelta(days=1)
        result = self.f.run(owner, admission_path=None, admission_pin=None)
        self.assertEqual(result["status"], "qualified")
        self.assertEqual(owner.actions(), ["verify-retained-gcp"])

    def test_failed_static_resume_reuses_completed_outcome(self):
        owner = FakeOwners(self.f, "findings")
        self.f.run(owner)
        owner.calls.clear()
        result = self.f.run(owner, admission_path=None, admission_pin=None)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["checks"]["native"], "blocked")
        self.assertEqual(owner.actions(), [])

    def test_uncertain_native_or_missing_last_admission_commit_never_retries(self):
        for mode in ("interrupted", "receipt-without-admission"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                f = Fixture(Path(tmp), self)
                owner = FakeOwners(f, mode)
                f.run(owner)
                owner.calls.clear()
                result = f.run(owner)
                self.assertFalse(result["qualified"])
                self.assertEqual(result["checks"]["native"], "uncertain")
                self.assertEqual(owner.actions(), [])

    def test_missing_controller_outcome_reconciles_complete_owner_receipts(self):
        owner = FakeOwners(self.f)
        self.f.run(owner)
        (self.f.state / "qualify.completed.json").unlink()
        owner.calls.clear()
        result = self.f.run(owner)
        self.assertEqual(result["status"], "qualified")
        self.assertEqual(owner.actions(), ["verify-retained-gcp"])

    def test_pin_or_completed_receipt_change_refuses_reuse(self):
        owner = FakeOwners(self.f)
        old = self.f.plan_path.read_bytes()
        self.f.plan_path.write_bytes(old + b" ")
        with self.assertRaisesRegex(driver.Refusal, "pin_changed"):
            self.f.run(owner)
        self.assertEqual(owner.calls, [])
        self.f.plan_path.write_bytes(old)
        self.f.run(owner)
        save(self.f.state / "qualification/receipt.json", {"changed": True})
        owner.calls.clear()
        with self.assertRaisesRegex(driver.Refusal, "stage_changed"):
            self.f.run(owner)
        self.assertEqual(owner.calls, [])

    def test_changed_qualification_plan_blocks_completed_and_uncertain_resume(self):
        for lost_outcome in (False, True):
            with self.subTest(lost_outcome=lost_outcome), tempfile.TemporaryDirectory() as tmp:
                f = Fixture(Path(tmp), self)
                owner = FakeOwners(f)
                f.run(owner)
                if lost_outcome:
                    (f.state / "qualify.completed.json").unlink()
                plan_path = f.state / "qualification-plan.json"
                plan_path.write_bytes(plan_path.read_bytes() + b" ")
                owner.calls.clear()
                with self.assertRaisesRegex(driver.Refusal, "stage_inputs_changed"):
                    f.run(owner)
                self.assertEqual(owner.calls, [])

    def test_simultaneous_stage_callers_execute_at_most_once(self):
        self.f.state.mkdir(mode=0o700)
        barrier = threading.Barrier(2)
        original = driver.write_once
        calls = []

        def claim(path, raw, **kwargs):
            if path.name == "race.started.json":
                barrier.wait(timeout=5)
            return original(path, raw, **kwargs)

        def invoke():
            return driver.stage(self.f.state, "race", ["synthetic-owner"], self.f.state, (),
                                lambda args: calls.append(args) or 0, lambda: CLOCK)

        with patch.object(driver, "write_once", side_effect=claim), ThreadPoolExecutor(2) as pool:
            results = list(pool.map(lambda _: invoke(), range(2)))
        self.assertEqual(len(calls), 1)
        self.assertEqual(sorted(r["status"] for r in results), ["completed", "uncertain"])

    def test_unknown_existing_state_and_input_overlap_are_refused(self):
        self.f.state.mkdir(mode=0o700)
        sentinel = self.f.state / "keep"
        sentinel.write_text("synthetic")
        with self.assertRaisesRegex(driver.Refusal, "not_owned_operation"):
            self.f.run(FakeOwners(self.f))
        self.assertEqual(sentinel.read_text(), "synthetic")
        self.f.state = self.f.oci / ("4" * 32)
        with self.assertRaisesRegex(driver.Refusal, "overlaps_input"):
            self.f.run(FakeOwners(self.f))

    def test_cli_refusal_is_redacted_and_does_not_execute_owners(self):
        result = subprocess.run([sys.executable, str(Path(driver.__file__)), "--plan", str(self.f.plan_path), "--plan-sha256", "0" * 64,
                                 "--state-dir", str(self.f.state), "--original-resources", str(self.f.original),
                                 "--original-resources-sha256", self.f.original_pin], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, "")
        self.assertNotIn(self.temp.name, result.stdout)
        self.assertNotIn("original-resource-input", result.stdout)
        self.assertEqual(json.loads(result.stdout)["status"], "refused")


if __name__ == "__main__":
    unittest.main()
