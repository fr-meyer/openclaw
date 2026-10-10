import importlib.util
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location("fork_ops_gate", HERE / "ops_gate.py")
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class GateTests(unittest.TestCase):
    def setUp(self):
        self.source = "b" * 40
        self.receipt = {"configDigest": "sha256:" + "c" * 64}

    def test_pre_gate_binds_image_id_and_source(self):
        payload = {"schemaVersion": 1, "status": "ok", "mode": "pre-deploy",
                   "imageId": self.receipt["configDigest"],
                   "manifestSha256": "a" * 64,
                   "cumulative": {"revision": self.source}}
        gate.validate_gate(payload, "image", self.receipt, self.source)
        payload["cumulative"]["revision"] = "d" * 40
        with self.assertRaisesRegex(gate.Refusal, "source revision"):
            gate.validate_gate(payload, "image", self.receipt, self.source)

    def test_post_gate_binds_running_image_and_health(self):
        payload = {"schemaVersion": 1, "status": "ok", "mode": "post-deploy",
                   "contract": {"imageId": self.receipt["configDigest"]},
                   "state": {"running": True, "oomKilled": False,
                             "restartCount": 0, "health": "healthy"},
                   "endpoints": {"healthz": {"ok": True}, "readyz": {"ready": True}},
                   "broker": {"captionBridgePushPreflight": {
                       "status": "ready", "selected_auth_actor": "mergeguez[bot]",
                       "write_performed": False}}}
        gate.validate_gate(payload, "post", self.receipt, self.source)
        payload["contract"]["imageId"] = "sha256:" + "e" * 64
        with self.assertRaisesRegex(gate.Refusal, "running gateway image ID"):
            gate.validate_gate(payload, "post", self.receipt, self.source)

    def test_malformed_gate_payload_refuses_cleanly(self):
        with self.assertRaisesRegex(gate.Refusal, "root gate payload"):
            gate.validate_gate(None, "image", self.receipt, self.source)
        payload = {"schemaVersion": 1, "status": "ok", "mode": "pre-deploy",
                   "imageId": self.receipt["configDigest"],
                   "manifestSha256": "a" * 64, "cumulative": None}
        with self.assertRaisesRegex(gate.Refusal, "cumulative gate payload"):
            gate.validate_gate(payload, "image", self.receipt, self.source)


if __name__ == "__main__":
    unittest.main()
