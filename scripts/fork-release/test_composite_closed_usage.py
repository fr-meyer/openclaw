"""Five focused local checks; immutable retained public metadata only."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
CANDIDATE = HERE / "candidates/v2026.10.8-source-only"
SPEC = importlib.util.spec_from_file_location("composite_under_test", HERE / "composite_closed_usage.py")
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)


class Composite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proof = (CANDIDATE / "crabline-settled-usage.json").read_bytes()
        cls.original = (CANDIDATE / "re2js-settled-usage.json").read_bytes()
        cls.stage = (CANDIDATE / "re2js-closed-provider-usage.json").read_bytes()

    def test_actual_positive_preserves_every_record_and_canonical(self):
        old = json.loads(self.original); stage = json.loads(self.stage)
        result = C.resolve_composite(self.proof, self.original, self.stage)
        self.assertEqual(result["runs"][:213], old["runs"])
        self.assertEqual(result["runCount"], 243)
        self.assertEqual(result["runnerMinutesObserved"], 2437)
        self.assertEqual(result["sourceRunIds"], old["sourceRunIds"] + ["40851844749", "40856125444"])
        for appended, raw in zip(result["runs"][213:], stage["records"]):
            self.assertEqual({k: appended[k] for k in raw["run"]}, raw["run"])
            self.assertEqual(appended["jobs"], raw["jobs"])
            self.assertEqual(appended["actorLogin"], raw["actorLogin"])
            self.assertEqual(appended["triggeringActorLogin"], raw["triggeringActorLogin"])
            self.assertEqual(appended["artifactRows"], raw["artifacts"])
        self.assertEqual(result["closedProviderStage"], {k: v for k, v in stage.items() if k != "records"})
        self.assertNotIn("closedStageLimits", result)
        self.assertNotIn(b"Sentinel_", self.stage)
        self.assertNotIn(b"Sentinel_", C.canonical(result))
        self.assertNotIn("authority", stage)
        self.assertNotIn("phaseCaps", stage)
        self.assertEqual(C.digest(C.canonical(result)), json.loads(self.proof)["resolvedCanonicalSha256"])
        self.assertFalse(result["referenceComposition"]["oldUnusedAuthorityCarried"])
        result["referenceComposition"]["segments"][0]["bytes"] = 0
        self.assertEqual(C.SEGMENTS[0]["bytes"], 1376744)

    def test_segment_tampering_missing_and_wrong_byte_type_refuse(self):
        for old, stage in [(self.original + b" ", self.stage), (self.original, self.stage + b" "),
                           (self.original[:-1], self.stage), (self.original.decode(), self.stage)]:
            with self.subTest(oldType=type(old).__name__, stageLength=len(stage)):
                with self.assertRaises(ValueError): C.resolve_composite(self.proof, old, stage)

    def test_duplicate_keys_constants_unknown_fields_refuse(self):
        for raw in [b'{"schema":"x","schema":"y"}', b'{"x":NaN}', b'{"x":Infinity}',
                    self.proof[:-2] + b',"path":"/arbitrary"}']:
            with self.subTest(rawLength=len(raw)):
                with self.assertRaises(ValueError): C.resolve_composite(raw, self.original, self.stage)

    def test_counts_ids_retired_authority_and_canonical_hash_refuse(self):
        proof = json.loads(self.proof)
        cases = []
        for key, value in [("runCount", True), ("runnerMinutesObserved", 2438),
                           ("sourceRunIds", list(reversed(C.SOURCE_IDS))), ("oldUnusedAuthorityCarried", True),
                           ("resolvedCanonicalSha256", "0" * 64), ("closedAt", "2026-10-29T14:10:00+00:00")]:
            item = copy.deepcopy(proof); item[key] = value; cases.append(item)
        item = copy.deepcopy(proof); item["segments"][0]["bytes"] = True; cases.append(item)
        for item in cases:
            with self.subTest(changed=[k for k in proof if proof[k] != item[k]]):
                with self.assertRaises(ValueError): C.resolve_composite(json.dumps(item).encode(), self.original, self.stage)

    def test_shape_unknown_reference_and_oversize_refuse(self):
        proof = json.loads(self.proof)
        for item in [{k: v for k, v in proof.items() if k != "segments"},
                     dict(proof, sourceRunIds=proof["sourceRunIds"] + ["123"]),
                     dict(proof, resolvedCanonicalSha256=None)]:
            with self.assertRaises(ValueError): C.resolve_composite(json.dumps(item).encode(), self.original, self.stage)
        with self.assertRaises(ValueError): C.resolve_composite(b" " * 16385, self.original, self.stage)


if __name__ == "__main__":
    unittest.main()
