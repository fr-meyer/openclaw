"""Focused delta proof: only the v109 runtime lane changes from reviewed R1."""

import hashlib
import importlib.util
from pathlib import Path
import sys
import types
import unittest


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


current = load(HERE / "release.py", "node_current_release")
proof_tests = load(HERE / "test_source_reconciliation_v109.py", "node_proof_tests")
OLD = '("v2026.10.6", "v2026.10.7", "v2026.10.8")'
NEW = '("v2026.10.6", "v2026.10.7", "v2026.10.8", "v2026.10.9")'


def original_r1():
    text = (HERE / "release.py").read_text()
    assert text.count(NEW) == 1
    restored = text.replace(NEW, OLD, 1)
    assert hashlib.sha256(restored.encode()).hexdigest() == \
        "3c0cf1e2ee11504fa601faa13a5e5efbe3551684d27626f03e2b00c252728403"
    module = types.ModuleType("original_r1_node_selection")
    module.__file__ = str(HERE / "release.py")
    exec(compile(restored, module.__file__, "exec"), module.__dict__)
    return module


class ValidationNodeDeltaCases(unittest.TestCase):
    def test_v109_selects_supported_node(self):
        inventory = {"upstream": {"tag": "v2026.10.9"}}
        self.assertEqual(original_r1().validation_node_version(inventory), "24.21.0")
        self.assertEqual(current.validation_node_version(inventory), "24.22.1")

    def test_105_retains_previous_node(self):
        inventory = {"upstream": {"tag": "v2026.10.5"}}
        self.assertEqual(current.validation_node_version(inventory), "24.21.0")
        self.assertEqual(current.validation_node_version(inventory), original_r1().validation_node_version(inventory))

    def test_106_through_108_are_unchanged(self):
        old = original_r1()
        for tag in ("v2026.10.6", "v2026.10.7", "v2026.10.8"):
            with self.subTest(tag=tag):
                inventory = {"upstream": {"tag": tag}}
                self.assertEqual(current.validation_node_version(inventory), "24.22.1")
                self.assertEqual(current.validation_node_version(inventory), old.validation_node_version(inventory))

    def test_default_and_unknown_lanes_remain_unchanged(self):
        old = original_r1()
        for inventory in ({}, {"upstream": None}, {"upstream": {}},
                          {"upstream": {"tag": "v2026.10.10"}}, {"upstream": {"tag": "main"}}):
            with self.subTest(inventory=inventory):
                self.assertEqual(current.validation_node_version(inventory), "24.21.0")
                self.assertEqual(current.validation_node_version(inventory), old.validation_node_version(inventory))

    def test_only_node_tuple_changed_and_reviewed_helper_is_pinned(self):
        original_r1()
        self.assertEqual(hashlib.sha256((HERE / "source_reconciliation_v109.py").read_bytes()).hexdigest(),
                         "aabbc7684d8ab1b9da2f4529fbd146d6d1ad69105a08aa8cc44ccf1e3bba7e54")
        self.assertEqual(hashlib.sha256(proof_tests.original_release_text().encode()).hexdigest(),
                         "d809c07015cd86e717c750ae87fa7849baf7e27a86209d0ca55b068c236246ac")

    def test_malformed_inventory_outcomes_are_unchanged(self):
        old = original_r1()
        for inventory in (None, {"upstream": True}, {"upstream": "wrong"}, {"upstream": {"other": True}}):
            outcomes = []
            for module in (old, current):
                try:
                    outcomes.append(("returned", module.validation_node_version(inventory)))
                except (AttributeError, KeyError, TypeError) as error:
                    outcomes.append((type(error).__name__, str(error)))
            with self.subTest(inventory=inventory):
                self.assertEqual(outcomes[0], outcomes[1])


if __name__ == "__main__":
    unittest.main()
