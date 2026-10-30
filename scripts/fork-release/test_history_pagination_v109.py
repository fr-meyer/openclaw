"""Pure finite GitHub-search fixtures; no client/network/Git/app execution."""
import ast
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import math
import re
import time
import types
import unittest
import urllib.parse

PATH = Path(__file__).with_name("source_validation_v109.py")
TREE = ast.parse(PATH.read_text())
CONSTANTS = {"HISTORY_START", "HISTORY_MAXIMUM", "HISTORY_QUERY_MAXIMUM", "HISTORY_SEARCH_CAP", "OLD_SOURCE_BRANCH"}
FUNCTIONS = {"history_rows", "history_created_range", "now_utc", "provider_epoch"}


class Refusal(RuntimeError):
    pass


def need(value, code):
    if not value:
        raise Refusal(code)


def owner():
    module = types.ModuleType("actual_bounded_history_under_test")
    module.__dict__.update(datetime=datetime, timezone=timezone, math=math, time=time,
        urllib=urllib, policy=types.SimpleNamespace(need=need, Refusal=Refusal,
            REPOSITORY="fr-meyer/openclaw", RUN_ID=re.compile(r"[1-9][0-9]*\Z"),
            PIPELINE_BRANCH="task/v107-source-binding", SOURCE_BRANCH="prep/v2026.10.9-remediation"))
    nodes = [node for node in TREE.body if
        isinstance(node, ast.FunctionDef) and node.name in FUNCTIONS or
        isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in CONSTANTS for t in node.targets)]
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(PATH), "exec"), module.__dict__)
    return module


def row(m, rid, second, branch=None):
    return {"id": rid, "created_at": m.now_utc(second), "head_branch": branch or m.policy.PIPELINE_BRANCH}


class Provider:
    """Explicitly modeled filtered search; count clamping is intentional."""
    def __init__(self, m, rows, clamp=True):
        self.m, self.rows, self.clamp, self.calls = m, rows, clamp, []

    def __call__(self, path):
        self.calls.append(path)
        assert ".." not in path
        route, raw = path.split("?", 1)
        assert route == "/repos/fr-meyer/openclaw/actions/runs"
        q = urllib.parse.parse_qs(raw, strict_parsing=True)
        assert set(q) == {"branch", "created", "per_page", "page"}
        assert all(len(value) == 1 for value in q.values()) and q["per_page"] == ["100"]
        first, last = q["created"][0].split("..")
        lo, hi = self.m.provider_epoch(first), self.m.provider_epoch(last)
        got = sorted((deepcopy(r) for r in self.rows if r["head_branch"] == q["branch"][0]
            and lo <= self.m.provider_epoch(r["created_at"]) <= hi), key=lambda r: r["id"])
        page = int(q["page"][0])
        return {"total_count": min(len(got), 1000) if self.clamp else len(got),
            "workflow_runs": got[(page - 1) * 100:page * 100]}


class HistoryPaginationTests(unittest.TestCase):
    def setUp(self):
        self.m = owner()
        self.start = int(self.m.provider_epoch(self.m.HISTORY_START))
        self.end = self.start + 9

    def test_all_three_fixed_branches_and_zero_collections(self):
        branches = (self.m.policy.PIPELINE_BRANCH, self.m.OLD_SOURCE_BRANCH, self.m.policy.SOURCE_BRANCH)
        rows = [row(self.m, i + 1, self.start + i, branch) for i, branch in enumerate(branches)]
        api = Provider(self.m, rows)
        self.assertEqual(self.m.history_rows(api, self.end), {str(r["id"]): r for r in rows})
        self.assertEqual(len(api.calls), 3)
        self.assertEqual(self.m.history_rows(Provider(self.m, []), self.end), {})

    def test_clamped_1300_is_complete_not_silently_limited_to1000(self):
        rows = [row(self.m, i + 1, self.start + i % 10) for i in range(1300)]
        api = Provider(self.m, rows)
        actual = self.m.history_rows(api, self.end)
        self.assertEqual(len(actual), 1300)
        self.assertEqual(actual, {str(r["id"]): r for r in rows})
        self.assertIn("%2E%2E", api.calls[0])
        self.assertGreater(len(api.calls), 13)

    def test_exact1000_is_ambiguous_and_must_partition(self):
        rows = [row(self.m, i + 1, self.start + i % 10) for i in range(1000)]
        api = Provider(self.m, rows)
        self.assertEqual(len(self.m.history_rows(api, self.end)), 1000)
        # The parent window is probed once, never followed by its page2.
        root_range = api.calls[0].split("&per_page", 1)[0]
        self.assertFalse(any(p.startswith(root_range) and p.endswith("page=2") for p in api.calls))

    def test_split_boundaries_are_disjoint_and_inclusive(self):
        rows = [row(self.m, i + 1, self.start + (4 if i < 500 else 5)) for i in range(1000)]
        actual = self.m.history_rows(Provider(self.m, rows), self.end)
        self.assertEqual(set(actual), {str(i + 1) for i in range(1000)})

    def test_singleton_second_saturation_refuses(self):
        rows = [row(self.m, i + 1, self.start) for i in range(1000)]
        with self.assertRaisesRegex(Refusal, "single_second_overflow"):
            self.m.history_rows(Provider(self.m, rows), self.start)

    def test_complete_page_count_and_stability_required(self):
        rows = [row(self.m, i + 1, self.start) for i in range(101)]
        for change in ("incomplete", "total"):
            base = Provider(self.m, rows)
            def api(path):
                value = base(path)
                if path.endswith("page=2"):
                    if change == "incomplete": value["workflow_runs"] = []
                    else: value["total_count"] += 1
                return value
            with self.subTest(change=change), self.assertRaisesRegex(Refusal, "collection_changed"):
                self.m.history_rows(api, self.end)

    def test_duplicate_native_ids_refuse_even_if_records_identical(self):
        value = row(self.m, 1, self.start)
        with self.assertRaisesRegex(Refusal, "collection_duplicate"):
            self.m.history_rows(Provider(self.m, [value, value]), self.end)

    def test_branch_and_created_membership_positive(self):
        for change in ("branch", "old", "future"):
            value = row(self.m, 1, self.start)
            if change == "branch": value["head_branch"] = "main"
            elif change == "old": value["created_at"] = self.m.now_utc(self.start - 1)
            else: value["created_at"] = self.m.now_utc(self.end + 1)
            with self.subTest(change=change), self.assertRaises(Refusal):
                self.m.history_rows(lambda p: {"total_count": 1, "workflow_runs": [value]}, self.end)

    def test_global2000_cap_is_not_a_per_branch_allowance(self):
        rows = [row(self.m, i + 1, self.start + i % 10) for i in range(2001)]
        with self.assertRaisesRegex(Refusal, "history_total_cap"):
            self.m.history_rows(Provider(self.m, rows), self.end)

    def test_bool_negative_or_wrong_type_total_refuses(self):
        for value in (True, -1, "0", None):
            with self.subTest(value=value), self.assertRaisesRegex(Refusal, "complete_provider_collection"):
                self.m.history_rows(lambda p: {"total_count": value, "workflow_runs": []}, self.end)

    def test_deadline_rate_or_transport_failure_is_not_retried(self):
        for message in ("v9.api_deadline", "HTTP429", "transport"):
            calls = []
            def api(path):
                calls.append(path)
                raise Refusal(message)
            with self.subTest(message=message), self.assertRaisesRegex(Refusal, message):
                self.m.history_rows(api, self.end)
            self.assertEqual(len(calls), 1)

    def test_fixed_query_cap_refuses_before_another_request(self):
        self.m.HISTORY_QUERY_MAXIMUM = 1
        api = Provider(self.m, [])
        with self.assertRaisesRegex(Refusal, "history_query_cap"):
            self.m.history_rows(api, self.end)
        self.assertEqual(len(api.calls), 1)

    def test_invalid_clock_and_created_bounds_refuse(self):
        for value in (True, "123", float("inf"), float("nan"), self.start - 1):
            api = Provider(self.m, [])
            with self.subTest(value=value), self.assertRaises(Refusal): self.m.history_rows(api, value)
            self.assertEqual(api.calls, [])
        for first, last in ((True, 1), (self.start + 1, self.start)):
            with self.assertRaises(Refusal): self.m.history_created_range(first, last)

    def test_original_api_fixed_route_and_redirect_guards_unchanged(self):
        current_class = next(n for n in TREE.body if isinstance(n, ast.ClassDef) and n.name == "API")
        # AST pin was measured from the immutable aa438c36 ancestor; no private
        # source path is required by the later physical public test layout.
        self.assertEqual(hashlib.sha256(ast.dump(current_class).encode()).hexdigest(),
            "e117e534d6b935f2374206e991dcddffa316a820a7d19036a1bc6b221e4edd81")


if __name__ == "__main__":
    unittest.main()
