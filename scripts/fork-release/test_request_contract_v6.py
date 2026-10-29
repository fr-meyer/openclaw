"""Synthetic V6 admission/source contracts; no process, API or app execution."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
STAGE = HERE.parents[1]


def load_contract():
    # Parent's future registered layout uses its maintained driver directly.
    integrated = HERE / "source_validation_v108.py"
    if integrated.exists():
        spec = importlib.util.spec_from_file_location("v6_contract_test_owner", integrated)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    original = STAGE / "pipeline/scripts/fork-release/source_validation_v108.py"
    sys.path.insert(0, str(original.parent))
    try:
        spec = importlib.util.spec_from_file_location("v6_contract_test_owner", original)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    for name in ("request_contract_v6.py", "history_contract_v6.py"):
        exec(compile((HERE / name).read_text(), str(HERE / name), "exec"), module.__dict__)
    return module


D = load_contract()


def encoded(value):
    return (json.dumps(value, indent=2) + "\n").encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def oid(label):
    return hashlib.sha1(label.encode()).hexdigest()


def tree_raw(value):
    return b"".join((" ".join(value[path]) + "\t" + path).encode() + b"\0" for path in sorted(value))


class Fixture:
    """Fake Git transport protects pure shape/mode/ledger logic, not real objects."""
    def __init__(self):
        self.current, self.current_tree = oid("SYNTHETIC C"), oid("SYNTHETIC C tree")
        self.package_old = encoded({"name": "synthetic-no-execution", "dependencies": {"npm": "12.2.0", "other": "1.0.0"}})
        self.package_new = encoded({"name": "synthetic-no-execution", "dependencies": {"npm": "12.2.1", "other": "1.0.0"}})
        self.lock_old, self.lock_new = b"synthetic old lock\n", b"synthetic new locked npm12.2.1\n"
        self.workspace = b"synthetic unchanged workspace policy\n"
        self.diff = b"synthetic exact full-index dependency diff\n"
        self.changed = sorted(("package.json", "pnpm-lock.yaml", "scripts/generate-npm-package-lock.mts",
            "test/scripts/generate-npm-package-lock.test.ts", "scripts/fork-release/native_tests.mjs",
            "test/scripts/native-security-ownership.test.ts"))
        self.before = {path: ("100644", "blob", oid("old " + path)) for path in D.V6_SOURCE_PATHS}
        self.before.update({"pnpm-workspace.yaml": ("100644", "blob", blob(self.workspace)),
            "src/runtime.ts": ("100644", "blob", oid("unchanged runtime")),
            "security.patch": ("100644", "blob", oid("unchanged patch")),
            "static-link": ("120000", "blob", oid("unchanged symlink")),
            D.V4_LEDGER_PATH: ("100644", "blob", oid("old ledger"))})
        self.before["package.json"] = ("100644", "blob", blob(self.package_old))
        self.before["pnpm-lock.yaml"] = ("100644", "blob", blob(self.lock_old))
        self.after = dict(self.before)
        for path in self.changed:
            self.after[path] = ("100644", "blob", oid("new " + path))
        self.after["package.json"] = ("100644", "blob", blob(self.package_new))
        self.after["pnpm-lock.yaml"] = ("100644", "blob", blob(self.lock_new))
        self.after[D.V4_LEDGER_PATH] = ("100644", "blob", oid("new ledger"))
        rows = [{"path": path, "upstream107": None, "fork107": {"mode": "100644", "blob": self.before[path][2]},
            "upstream108": None, "result": {"mode": "100644", "blob": self.before[path][2]},
            "disposition": "CARRIED_EXACT"} for path in D.V6_SOURCE_PATHS]
        rows += [{"path": "unchanged/%03d.ts" % n, "upstream107": None, "fork107": None, "upstream108": None,
            "result": {"mode": "100644", "blob": oid(str(n))}, "disposition": "CARRIED_EXACT"} for n in range(241)]
        self.old_ledger = {"schema": "openclaw-v108-source-reconciliation-v1", "qualificationTransferred": False,
            "paths": sorted(rows, key=lambda row: row["path"])}
        self.new_ledger = copy.deepcopy(self.old_ledger)
        for row in self.new_ledger["paths"]:
            if row["path"] in self.changed:
                row["result"]["blob"] = self.after[row["path"]][2]
                row["disposition"] = D.V4_DISPOSITION
        self.generation = {"schema": "openclaw.v108.npm-lock-derivation.v1", "status": "derived_only",
            "sourceSha": D.V6_BASE_SOURCE, "sourceTree": D.V6_BASE_TREE, "pipelineHead": oid("prep pipeline"),
            "runId": "93000000000", "runAttempt": 1, "sourcePackageSha256": digest(self.package_old),
            "sourceLockSha256": digest(self.lock_old), "packageSha256": digest(self.package_new),
            "lockSha256": digest(self.lock_new), "npmVersion": "12.2.1", "npmIntegrity": D.V6_NPM_INTEGRITY,
            "nodeVersion": "24.22.1", "pnpmVersion": "12.15.0", "workspaceSha256": digest(self.workspace),
            "changedPaths": ["package.json", "pnpm-lock.yaml"], "gitDiffSha256": digest(self.diff),
            "allOtherTrackedEntriesUnchanged": True, "startedAt": "2026-10-29T01:00:00Z",
            "finishedAt": "2026-10-29T01:00:12.500000Z", "commandSeconds": 12.5,
            "exitCode": 0, "timedOut": False, "cleanupSettled": None,
            "qualified": False, "imageBuilt": False, "productionAuthorized": False}
        prep = {"runId": self.generation["runId"], "pipelineHead": self.generation["pipelineHead"],
            "artifactId": 888000, "artifactSha256": "a" * 64, "generationReceiptSha256": digest(encoded(self.generation)),
            "packageSha256": digest(self.package_new), "lockSha256": digest(self.lock_new)}
        self.pins = {"sourceSha": self.current, "sourceTree": self.current_tree,
            "manifestSha256": "b" * 64, "inventorySha256": "c" * 64,
            "settledUsageSha256": D.V6_BASELINE_SHA256, "preparation": prep, "priorValidationRuns": [],
            "sourceHops": [{"sourceSha": self.current, "sourceTree": self.current_tree}], "previousSourceHopCount": 0}
        unchanged = digest(tree_raw({path: entry for path, entry in self.before.items()
            if path not in {*self.changed, D.V4_LEDGER_PATH}}))
        self.request = {"schema": D.V6_SCHEMA, "campaignId": D.V6_CAMPAIGN, "profilePolicy": D.V6_POLICY,
            "sourceAuthorization": D.V6_AUTHORIZATION, "stageRound": 1, "lifetimeOperatorRound": 9,
            "profiles": list(D.V6_PROFILES), **{key: self.pins[key] for key in ("sourceSha", "sourceTree",
                "manifestSha256", "inventorySha256", "settledUsageSha256")},
            "priorRunIds": [*D.V6_PRIOR_SOURCE_IDS, prep["runId"]], "lockPreparation": copy.deepcopy(prep),
            "sourceWitness": {"schema": "openclaw.v108.npm-source-equivalence.v1", "scope": D.V6_SCOPE,
                "closedBaselineSha256": D.V6_BASELINE_SHA256, "hops": [{"sourceSha": self.current,
                    "sourceTree": self.current_tree, "step": {"parentSha": D.V6_BASE_SOURCE,
                        "parentTree": D.V6_BASE_TREE, "changedPaths": self.changed,
                        "unchangedTreeSha256": unchanged}}]}}
        self.calls = []

    def targeted(self, profiles=("types-tests", "compatibility")):
        prior = {"runId": "93000000001", "pipelineHead": oid("full pipeline"), "requestSha256": "d" * 64}
        self.pins.update(priorValidationRuns=[prior], previousSourceHopCount=1)
        self.request.update(stageRound=2, lifetimeOperatorRound=10, profiles=list(profiles),
            priorRunIds=[*self.request["priorRunIds"], prior["runId"]])

    def git(self, *args):
        self.calls.append(args)
        if args[:3] == ("show", "-s", "--format=%P"):
            return (D.V6_BASE_SOURCE + "\n").encode()
        if args[0] == "rev-parse":
            return ((D.V6_BASE_TREE if args[1].startswith(D.V6_BASE_SOURCE) else self.current_tree) + "\n").encode()
        if args[:3] == ("ls-tree", "-r", "-z"):
            return tree_raw(self.before if args[3] == D.V6_BASE_SOURCE else self.after)
        if args[0] == "show":
            commit, path = args[1].split(":", 1)
            old = commit == D.V6_BASE_SOURCE
            return {"package.json": self.package_old if old else self.package_new,
                "pnpm-lock.yaml": self.lock_old if old else self.lock_new,
                "pnpm-workspace.yaml": self.workspace,
                D.V4_LEDGER_PATH: encoded(self.old_ledger if old else self.new_ledger)}[path]
        if args[:6] == ("-c", "diff.algorithm=myers", "-c", "core.quotePath=true", "diff", "--no-ext-diff"):
            return self.diff
        raise AssertionError("Unexpected synthetic Git call")


class RequestV6Tests(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()

    def validate(self):
        return D.validate_request_v6(self.f.request, self.f.pins)

    def refused(self):
        with self.assertRaises(D.V6ContractRefusal):
            self.validate()

    def source(self):
        # These fixture hashes are explicitly synthetic. They are never emitted
        # as operational constants/pins or asserted to describe real sourceB.
        with patch.object(D, "V6_PREVIOUS_PACKAGE_SHA256", digest(self.f.package_old)), \
                patch.object(D, "V6_PREVIOUS_LOCK_SHA256", digest(self.f.lock_old)):
            return D.verify_source_equivalence_v6(self.f.request, self.f.pins, self.f.git, encoded(self.f.generation))

    def test_full_all_fifteen_fresh_profiles_and_no_historical_coverage(self):
        self.validate()
        result = self.source()
        self.assertEqual(len(self.f.request["profiles"]), 15)
        self.assertEqual(sum(D.V6_PROFILE_MINUTES.values()) + 40, 1015)
        self.assertFalse(result["historicalCoverageReused"])
        self.assertFalse(result["sameSourceReceiptRelabeled"])
        self.assertFalse(result["productionAuthorized"])
        self.assertEqual(len(self.f.new_ledger["paths"]), 249)

    def test_unbound_pins_fail_closed(self):
        with self.assertRaises(D.V6ContractRefusal):
            D.validate_request_v6(self.f.request, None)

    def test_old_v5_schema_and_wrong_authority_refuse(self):
        for field, value in (("schema", D.V5_SCHEMA), ("sourceAuthorization", "old-authority"),
                ("profilePolicy", "donor-repair-v1")):
            with self.subTest(field=field):
                old = self.f.request[field]
                self.f.request[field] = value
                self.refused()
                self.f.request[field] = old

    def test_unknown_fields_missing_fixed_profile_duplicate_and_order_refuse(self):
        original = copy.deepcopy(self.f.request)
        for mutation in ("extra", "missing", "duplicate", "unknown", "reordered"):
            with self.subTest(mutation=mutation):
                self.f.request = copy.deepcopy(original)
                if mutation == "extra": self.f.request["waiver"] = True
                elif mutation == "missing": self.f.request["profiles"].pop()
                elif mutation == "duplicate": self.f.request["profiles"][-1] = self.f.request["profiles"][0]
                elif mutation == "unknown": self.f.request["profiles"][-1] = "image-build"
                else: self.f.request["profiles"].reverse()
                self.refused()

    def test_round_requires_positive_exact_integer_one_or_two(self):
        for value in (True, 0, 3, "1", 1.0):
            with self.subTest(value=value):
                self.f.request["stageRound"] = value
                self.refused()

    def test_manifest_baseline_preparation_and_prior_run_tampering_refuse(self):
        original = copy.deepcopy(self.f.request)
        for mutation in ("manifest", "baseline", "prep", "prior"):
            with self.subTest(mutation=mutation):
                self.f.request = copy.deepcopy(original)
                if mutation == "manifest": self.f.request["manifestSha256"] = "f" * 64
                elif mutation == "baseline": self.f.request["settledUsageSha256"] = "f" * 64
                elif mutation == "prep": self.f.request["lockPreparation"]["artifactId"] += 1
                else: self.f.request["priorRunIds"].pop()
                self.refused()

    def test_initial_package_and_lock_both_required(self):
        self.f.request["sourceWitness"]["hops"][0]["step"]["changedPaths"].remove("pnpm-lock.yaml")
        self.refused()

    def test_unapproved_runtime_source_or_workspace_in_scope_refuses(self):
        for value in ("src/runtime.ts", "pnpm-workspace.yaml"):
            with self.subTest(path=value):
                original = list(self.f.changed)
                self.f.request["sourceWitness"]["hops"][0]["step"]["changedPaths"] = sorted([*original, value])
                self.refused()

    def test_source_refuses_unrelated_mode_blob_or_origin_change(self):
        for mutation in ("runtime", "mode", "origin"):
            with self.subTest(mutation=mutation):
                self.f = Fixture()
                if mutation == "runtime": self.f.after["src/runtime.ts"] = ("100644", "blob", oid("bad runtime"))
                elif mutation == "mode":
                    path = self.f.changed[0]
                    self.f.after[path] = ("100755", "blob", self.f.after[path][2])
                else: self.f.new_ledger["paths"][0]["fork107"] = None
                with self.assertRaises((D.V6ContractRefusal, D.V4ContractRefusal)):
                    self.source()

    def test_source_requires_exact_generated_lock_and_workspace_and_diff(self):
        for mutation in ("lock", "workspace", "diff"):
            with self.subTest(mutation=mutation):
                self.f = Fixture()
                if mutation == "lock": self.f.lock_new += b"tamper"
                elif mutation == "workspace": self.f.generation["workspaceSha256"] = "f" * 64
                else: self.f.diff += b"tamper"
                if mutation == "workspace":
                    self.f.pins["preparation"]["generationReceiptSha256"] = digest(encoded(self.f.generation))
                    self.f.request["lockPreparation"] = copy.deepcopy(self.f.pins["preparation"])
                with self.assertRaises(D.V6ContractRefusal): self.source()

    def test_generation_changed_name_version_or_type_cannot_qualify(self):
        for field, value in (("npmVersion", "12.2.0"), ("nodeVersion", "26.0.0"),
                ("pnpmVersion", "12.16.0"), ("exitCode", False), ("timedOut", True),
                ("qualified", True), ("productionAuthorized", True), ("cleanupSettled", True)):
            with self.subTest(field=field):
                self.f = Fixture()
                self.f.generation[field] = value
                self.f.pins["preparation"]["generationReceiptSha256"] = digest(encoded(self.f.generation))
                with self.assertRaises(D.V6ContractRefusal):
                    D.validate_generation_receipt_v6(encoded(self.f.generation), self.f.pins)

    def test_generation_missing_unknown_field_invalid_clock_and_hash_refuse(self):
        for mutation in ("missing", "extra", "clock", "hash"):
            with self.subTest(mutation=mutation):
                self.f = Fixture()
                if mutation == "missing": self.f.generation.pop("cleanupSettled")
                elif mutation == "extra": self.f.generation["stderr"] = "SYNTHETIC_PRIVATE"
                elif mutation == "clock": self.f.generation["finishedAt"] = "2026-10-29T00:00:00Z"
                if mutation != "hash":
                    self.f.pins["preparation"]["generationReceiptSha256"] = digest(encoded(self.f.generation))
                with self.assertRaises(D.V6ContractRefusal):
                    D.validate_generation_receipt_v6(encoded(self.f.generation) + (b" " if mutation == "hash" else b""), self.f.pins)

    def test_json_duplicate_and_nonfinite_are_refused(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(D.V6ContractRefusal): D._v6_json(raw)

    def test_same_source_target_two_profiles_fit_but_two_ninety_minute_profiles_do_not(self):
        self.f.targeted()
        self.validate()
        self.assertEqual(D.booking_v6(self.f.request, 45, 900, 13)["currentRoundBookedMinutes"], 190)
        self.f.request["profiles"] = ["types-tests", "types-scripts"]
        self.refused()

    def test_target_cannot_omit_affected_new_source_owners(self):
        self.f.targeted()
        second = {"sourceSha": oid("new target"), "sourceTree": oid("new target tree")}
        self.f.pins["sourceHops"].append(second)
        self.f.pins.update(second)
        self.f.request.update(second)
        self.f.request["sourceWitness"]["hops"].append({**second, "step": {
            "parentSha": self.f.current, "parentTree": self.f.current_tree,
            "changedPaths": ["test/scripts/native-security-ownership.test.ts"], "unchangedTreeSha256": "e" * 64}})
        self.refused()

    def test_full_worst_case_accounting_preserves_all_existing_usage(self):
        result = D.booking_v6(self.f.request, 45, 0, 13)
        self.assertEqual(result["newStageBookedMinutes"], 1337)
        self.assertEqual(result["bookedRunnerMinutes"], 2574)
        self.assertEqual(result["sourceFetchStageBookedMinutes"], 1646)
        self.assertEqual(result["newAncillaryRemainingReserveMinutes"], 64)
        self.assertFalse(result["currentSourceCoverageReusedFromF5"])

    def test_accounting_no_double_credit_actual_usage_and_no_extra_preparation(self):
        first = D.booking_v6(self.f.request, 7, 0, 13)
        self.assertEqual(first["newStageBookedMinutes"], 7 + 1015 + 200 + 77)
        for values in ((46, 0, 0), (45, 1, 0), (45, 0, 78), (True, 0, 0)):
            with self.subTest(values=values), self.assertRaises(D.V6ContractRefusal): D.booking_v6(self.f.request, *values)


if __name__ == "__main__":
    unittest.main()
