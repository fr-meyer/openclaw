"""The named A2UI regression adapter is one exact exception, never a wildcard."""

from pathlib import Path
import hashlib
import sys
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from test_source_reconciliation_v109 import GitObjects, checker, release


class SecurityRegressionNameCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.fixture = GitObjects(cls.temp.name)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def record(self, path):
        f = self.fixture
        entries = {**f.result_entries, **f.entries({path: b"// synthetic regression entrypoint\n"})}
        return f.make_result(entries=entries, edit=lambda d: next(
            row for row in d["sourcePaths"] if row["path"] == path).update(disposition="ADAPTED_SECURITY_TEST"))

    def check(self, record):
        checker.check_v109_reconciliation(record[0], self.fixture.repo, record[1],
                                          git=release.git, need=release.need)

    def test_exact_reviewed_regression_path_passes(self):
        raw = (HERE / "source_reconciliation_v109.py").read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
                         "aabbc7684d8ab1b9da2f4529fbd146d6d1ad69105a08aa8cc44ccf1e3bba7e54")
        original = raw.decode().replace(
            '                need(re.fullmatch(r".+\\.test\\.[cm]?[jt]s", name) is not None\n'
            '                     or name == "test/scripts/a2ui-zod-bounds.regression.mjs",\n',
            '                need(re.fullmatch(r".+\\.test\\.[cm]?[jt]s", name) is not None,\n', 1)
        self.assertEqual(hashlib.sha256(original.encode()).hexdigest(),
                         "b2beec3d5344634543bcc275a27578c6f24c6ea98e690e1d0dd065503933bc0d")
        record = self.record("test/scripts/a2ui-zod-bounds.regression.mjs")
        self.check(record)
        release.check_source_graph(record[0], self.fixture.repo)

    def test_near_miss_names_remain_refused(self):
        for path in ("test/scripts/a2ui-zod-bounds.regression.js",
                     "test/scripts/a2ui-zod-bound.regression.mjs",
                     "other/test/scripts/a2ui-zod-bounds.regression.mjs",
                     "test/scripts/A2UI-zod-bounds.regression.mjs"):
            with self.subTest(path=path), self.assertRaises(release.Refusal):
                self.check(self.record(path))

    def test_existing_test_rule_and_non_test_refusal_stay_intact(self):
        self.check(self.fixture.initial)
        record = self.fixture.make_result(edit=lambda d: next(
            row for row in d["sourcePaths"] if row["path"] == "app.txt").update(disposition="ADAPTED_SECURITY_TEST"))
        with self.assertRaises(release.Refusal):
            self.check(record)


if __name__ == "__main__":
    unittest.main()
