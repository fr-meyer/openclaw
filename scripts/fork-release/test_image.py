import json
from pathlib import Path
import subprocess
import tempfile
import unittest
import preflight

HERE = Path(__file__).parent

class ImageBoundaryTests(unittest.TestCase):
    def test_ordinary_verifier_refuses_retained_qualification_metadata_before_oci(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / "receipt.json"
            receipt.write_text(json.dumps({"schema": "openclaw.fork-release-image.v2",
                                           "reinspection": {"schema": "openclaw.retained-gcp-qualification.v1"}}))
            result = subprocess.run(["node", str(HERE / "image.mjs"), "verify",
                                     str(HERE / "manifest.json"), str(HERE / "patch-inventory.json"),
                                     str(receipt), str(Path(directory) / "missing-oci")],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Retained qualification requires verify-retained-gcp", result.stderr)
            self.assertNotIn("ENOENT", result.stderr)

    def test_actual_receipt_verifier_rejects_malformed_present_runtime_proof_before_oci(self):
        manifest = json.loads((HERE / "manifest.json").read_text())
        value = {
            "schema": "openclaw.fork-release-image.v2",
            "manifestSha256": preflight.digest(HERE / "manifest.json"),
            "inventorySha256": preflight.digest(HERE / "patch-inventory.json"),
            "repository": manifest["repository"], "sourceSha": manifest["source"]["commit"],
            "sourceTree": manifest["source"]["tree"], "architecture": manifest["image"]["architecture"],
            "selectedExtensions": manifest["image"]["extensions"], "version": "2026.10.5",
            "bundledCodexVersion": "0.160.0", "indexDigest": "sha256:" + "a" * 64,
            "imageDigest": "sha256:" + "b" * 64, "configDigest": "sha256:" + "c" * 64,
            "pluginPayload": [],
        }
        for name in manifest["image"]["extensions"].split(","):
            entry = {"id": name, "package": "@openclaw/" + name, "version": "2026.10.5"}
            if name == "codex":
                entry["codexRuntime"] = {"cliVersion": "0.160.0", "packageVersion": "0.160.0",
                                         "initializeVersion": "0.160.0", "initialized": True, "shutdown": "exited"}
            if name == "workboard":
                entry["workboardRuntime"] = {"worker": "sqlite", "roundTrip": True, "closed": True}
            value["pluginPayload"].append(entry)
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / "receipt.json"
            for proof in (None, {}, {key: value[key] for key in ("sourceSha", "imageDigest", "configDigest")}):
                value["runtimeQualification"] = proof
                receipt.write_text(json.dumps(value))
                result = subprocess.run(["node", str(HERE / "image.mjs"), "verify",
                                         str(HERE / "manifest.json"), str(HERE / "patch-inventory.json"),
                                         str(receipt), str(Path(directory) / "missing-oci")],
                                        capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("ENOENT", result.stderr)
                self.assertRegex(result.stderr, "Runtime proof|runtime expectations")

    def test_actual_verifier_refuses_metadata_only_codex_evidence_before_oci(self):
        manifest = json.loads((HERE / "manifest.json").read_text())
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / "receipt.json"
            receipt.write_text(json.dumps({
                "schema": "openclaw.fork-release-image.v2",
                "manifestSha256": preflight.digest(HERE / "manifest.json"),
                "inventorySha256": preflight.digest(HERE / "patch-inventory.json"),
                "repository": manifest["repository"],
                "sourceSha": manifest["source"]["commit"],
                "sourceTree": manifest["source"]["tree"],
                "architecture": manifest["image"]["architecture"],
                "selectedExtensions": manifest["image"]["extensions"],
                "version": "2026.10.5",
                "bundledCodexVersion": "0.160.0",
                "pluginPayload": [{"id": name, "package": "@openclaw/" + name,
                                   "version": "2026.10.5"}
                                  for name in manifest["image"]["extensions"].split(",")],
            }))
            result = subprocess.run(["node", str(HERE / "image.mjs"), "verify",
                                     str(HERE / "manifest.json"), str(HERE / "patch-inventory.json"),
                                     str(receipt), str(Path(directory) / "missing-oci")],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Exact bundled Codex runtime evidence missing", result.stderr)
            self.assertNotIn("ENOENT", result.stderr)

    def test_actual_node_consumer_refuses_old_and_wrong_inventory_receipts_before_oci(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / "receipt.json"
            for value, expected in (
                ({"schema": "openclaw.fork-release-image.v1"}, "Wrong image receipt schema"),
                ({"schema": "openclaw.fork-release-image.v2",
                  "manifestSha256": preflight.digest(HERE / "manifest.json"),
                  "inventorySha256": "0" * 64}, "Image receipt inventory changed"),
            ):
                receipt.write_text(json.dumps(value))
                result = subprocess.run(["node", str(HERE / "image.mjs"), "verify",
                                         str(HERE / "manifest.json"), str(HERE / "patch-inventory.json"),
                                         str(receipt), str(Path(directory) / "missing-oci")],
                                        capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)
                self.assertNotIn("ENOENT", result.stderr)


    def test_actual_private_cli_refuses_source_without_creating_private_state(self):
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory) / "private"
            result = subprocess.run(["python3", str(HERE / "release.py"), "run",
                                     "--manifest", str(HERE / "manifest.json"),
                                     "--inventory", str(HERE / "patch-inventory.json"),
                                     "--source-dir", directory, "--private-root", str(private),
                                     "--image-receipt", str(Path(directory) / "missing-receipt")],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Fork release refused: preflight:", result.stderr)
            self.assertNotIn("Traceback", result.stderr)
            self.assertFalse(private.exists())

    def test_actual_runtime_bridge_refuses_wrong_inventory_before_private_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            gate = Path(directory) / "private-gate"
            gate.write_text('#!/bin/sh\nprintf invoked > "$0.invoked"\nexit 91\n')
            gate.chmod(0o700)
            path = Path(directory) / "receipt.json"
            path.write_text(json.dumps({"schema": "openclaw.fork-release-image.v2",
                                        "manifestSha256": preflight.digest(HERE / "manifest.json"),
                                        "inventorySha256": "0" * 64}))
            result = subprocess.run(["python3", str(HERE / "ops_gate.py"), "image",
                                     "--manifest", str(HERE / "manifest.json"),
                                     "--inventory", str(HERE / "patch-inventory.json"),
                                     "--image-receipt", str(path), "--gate", str(gate),
                                     "--candidate-image", "never-invoked"],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("image receipt inventory mismatch", result.stderr)
            self.assertNotIn("gate command failed", result.stderr)
            self.assertNotIn("Traceback", result.stderr)
            self.assertFalse(Path(str(gate) + ".invoked").exists())


if __name__ == "__main__":
    unittest.main()
