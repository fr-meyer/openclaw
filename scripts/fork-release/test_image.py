import json
from pathlib import Path
import subprocess
import tempfile
import unittest
import preflight

HERE = Path(__file__).parent

class ImageBoundaryTests(unittest.TestCase):
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
            path = Path(directory) / "receipt.json"
            path.write_text(json.dumps({"schema": "openclaw.fork-release-image.v2",
                                        "manifestSha256": preflight.digest(HERE / "manifest.json"),
                                        "inventorySha256": "0" * 64}))
            result = subprocess.run(["python3", str(HERE / "ops_gate.py"), "image",
                                     "--manifest", str(HERE / "manifest.json"),
                                     "--inventory", str(HERE / "patch-inventory.json"),
                                     "--image-receipt", str(path), "--gate", "/bin/false",
                                     "--candidate-image", "never-invoked"],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("image receipt inventory mismatch", result.stderr)
            self.assertNotIn("gate command failed", result.stderr)
            self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
