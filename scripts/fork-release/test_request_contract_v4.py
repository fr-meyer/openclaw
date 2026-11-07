"""Pure synthetic v4 contract cases: no Git/process/network/Node execution."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

INTEGRATED_DRIVER = Path(__file__).with_name("source_validation_v108.py")
CONTRACT_PATH = INTEGRATED_DRIVER if INTEGRATED_DRIVER.is_file() else Path(__file__).with_name("request_contract_v4.py")
SPEC = importlib.util.spec_from_file_location("request_contract_v4", CONTRACT_PATH)
contract = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(contract)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def oid(label):
    return hashlib.sha1(label.encode()).hexdigest()


def tree_bytes(entries):
    return b"".join((" ".join(entry) + "\t" + path).encode() + b"\0"
                    for path, entry in sorted(entries.items()))


def unchanged_digest(entries, changed):
    return hashlib.sha256(tree_bytes({path: entry for path, entry in entries.items() if path not in changed})).hexdigest()


class Fixture:
    def __init__(self):
        c = contract
        self.parent = c.V4_PARENT_SOURCE
        self.first = oid("synthetic stage B")
        self.first_tree = oid("synthetic tree B")
        self.current = self.first
        self.current_tree = self.first_tree
        self.parents = {self.first: self.parent}
        self.tree_ids = {self.parent: c.V4_PARENT_TREE, self.first: self.first_tree}
        self.before = {path: ("100644", "blob", oid("old " + path)) for path in c.V4_SOURCE_PATHS}
        self.before.update({
            "package.json": ("100644", "blob", oid("unchanged package")),
            "pnpm-lock.yaml": ("100644", "blob", oid("unchanged lock")),
            "patches/security.patch": ("100644", "blob", oid("unchanged security patch")),
            "src/runtime.ts": ("100644", "blob", oid("unchanged production runtime")),
            "static-link": ("120000", "blob", oid("unchanged link")),
            c.V4_LEDGER_PATH: ("100644", "blob", oid("old ledger")),
        })
        self.after = dict(self.before)
        for path in (*c.V4_SOURCE_PATHS, c.V4_LEDGER_PATH):
            self.after[path] = ("100644", "blob", oid("new " + path))
        refs = {name: oid(name) for name in ("upstream107", "fork107Source", "upstream108")}
        rows = []
        for path in sorted(c.V4_SOURCE_PATHS - {c.V4_GENERATOR_PATH}):
            rows.append({"path": path, "upstream107": {"mode": "100644", "blob": oid("upstream " + path)},
                         "fork107": None, "upstream108": None,
                         "result": {"mode": "100644", "blob": self.before[path][2]},
                         "disposition": c.V4_DISPOSITION if path.startswith("test/v108") else "CARRIED_EXACT"})
        for number in range(245):
            rows.append({"path": f"unchanged/{number:03d}.ts", "upstream107": None, "fork107": None,
                         "upstream108": None, "result": {"mode": "100644", "blob": oid(str(number))},
                         "disposition": "CARRIED_EXACT"})
        rows.sort(key=lambda row: row["path"])
        self.old_ledger = {"schema": "openclaw-v108-source-reconciliation-v1", **refs,
                           "priorForkDeltaPaths": 243, "qualificationTransferred": False, "paths": rows}
        self.new_ledger = copy.deepcopy(self.old_ledger)
        for row in self.new_ledger["paths"]:
            if row["path"] in c.V4_SOURCE_PATHS:
                row["result"]["blob"] = self.after[row["path"]][2]
                row["disposition"] = c.V4_DISPOSITION
        origin = {"mode": "100644", "blob": self.before[c.V4_GENERATOR_PATH][2]}
        self.new_ledger["paths"].append({"path": c.V4_GENERATOR_PATH, "upstream107": origin,
            "fork107": origin, "upstream108": origin, "result": {"mode": "100644", "blob": self.after[c.V4_GENERATOR_PATH][2]},
            "disposition": c.V4_DISPOSITION})
        self.new_ledger["paths"].sort(key=lambda row: row["path"])
        self.ledgers = {self.parent: self.old_ledger, self.first: self.new_ledger}
        self.trees = {self.parent: self.before, self.first: self.after}
        self.origins = {(ref, c.V4_GENERATOR_PATH): self.before[c.V4_GENERATOR_PATH] for ref in refs.values()}
        self.historical = {"schema": "openclaw.fork-source-validation-request.v3", "sourceSha": c.V4_PARENT_SOURCE,
            "sourceTree": c.V4_PARENT_TREE, "manifestSha256": c.V4_PARENT_MANIFEST, "inventorySha256": c.V4_PARENT_INVENTORY}
        self.pins = {"sourceSha": self.first, "sourceTree": self.first_tree, "firstSourceSha": self.first,
            "firstSourceTree": self.first_tree, "manifestSha256": "1" * 64, "inventorySha256": "2" * 64,
            "firstManifestSha256": "1" * 64, "firstInventorySha256": "2" * 64, "settledUsageSha256": "3" * 64,
            "priorRunIds": ["40607329263", "40609889437", "40616416909", "40639374411", c.V4_PARENT_RUN]}
        excluded = {*c.V4_SOURCE_PATHS, c.V4_LEDGER_PATH}
        self.request = {"schema": c.V4_SCHEMA, "campaignId": c.V4_CAMPAIGN, "profilePolicy": c.V4_POLICY,
            "round": 4, "lifetimeOperatorRound": 5, "profiles": list(c.V4_INITIAL_PROFILES),
            **{key: self.pins[key] for key in ("sourceSha", "sourceTree", "firstSourceSha", "firstSourceTree",
                "manifestSha256", "inventorySha256", "settledUsageSha256", "priorRunIds")},
            "sourceAuthorization": c.V4_AUTHORIZATION,
            "sourceWitness": {"schema": "openclaw.v108.fixture-generator-equivalence.v1", "scope": c.V4_SCOPE,
                "closedPrefixSha256": c.V4_CLOSED_PREFIX_SHA256,
                "stageBase": {"parentSha": self.parent, "parentTree": c.V4_PARENT_TREE,
                    "changedPaths": sorted(c.V4_SOURCE_PATHS), "unchangedTreeSha256": unchanged_digest(self.before, excluded)},
                "corrective": None}}
        self.calls = []

    def git(self, *args):
        self.calls.append(args)
        if args[:3] == ("show", "-s", "--format=%P"):
            return (self.parents[args[3]] + "\n").encode()
        if args[0] == "rev-parse":
            return (self.tree_ids[args[1].removesuffix("^{tree}")] + "\n").encode()
        if args[:3] == ("ls-tree", "-r", "-z"):
            return tree_bytes(self.trees[args[3]])
        if args[:2] == ("ls-tree", "-z"):
            entry = self.origins.get((args[2], args[4]))
            return tree_bytes({args[4]: entry}) if entry else b""
        if args[0] == "show":
            ref, path = args[1].split(":", 1)
            if ref == contract.V4_PARENT_PIPELINE and path == contract.V4_REQUEST_PATH:
                return encoded(self.historical)
            if path == contract.V4_LEDGER_PATH:
                return encoded(self.ledgers[ref])
        raise AssertionError("Unexpected synthetic Git call")

    def correction(self, paths):
        c = contract
        current = oid("synthetic correction C")
        current_tree = oid("synthetic correction tree C")
        self.parents[current] = self.first
        self.tree_ids[current] = current_tree
        after = dict(self.after)
        ledger = copy.deepcopy(self.new_ledger)
        for path in paths:
            after[path] = ("100644", "blob", oid("corrected " + path))
            next(row for row in ledger["paths"] if row["path"] == path)["result"]["blob"] = after[path][2]
        after[c.V4_LEDGER_PATH] = ("100644", "blob", oid("corrected ledger"))
        self.trees[current] = after
        self.ledgers[current] = ledger
        self.pins.update(sourceSha=current, sourceTree=current_tree, manifestSha256="4" * 64, inventorySha256="5" * 64)
        self.pins["priorRunIds"] = [*self.pins["priorRunIds"], "99999"]
        self.request.update(round=5, lifetimeOperatorRound=6, sourceSha=current, sourceTree=current_tree,
            manifestSha256="4" * 64, inventorySha256="5" * 64, priorRunIds=self.pins["priorRunIds"],
            profiles=sorted(c.v4_required_correction_profiles(paths)))
        self.request["sourceWitness"]["corrective"] = {"parentSha": self.first, "parentTree": self.first_tree,
            "changedPaths": sorted(paths), "unchangedTreeSha256": unchanged_digest(self.after, {*paths, c.V4_LEDGER_PATH})}
        return current


class RequestTests(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()

    def refused(self):
        with self.assertRaises(contract.V4ContractRefusal):
            contract.validate_request_v4(self.f.request, self.f.pins)

    def test_initial_and_new_budget(self):
        self.assertIs(contract.validate_request_v4(self.f.request, self.f.pins), self.f.request)
        self.assertEqual(sum(contract.V4_PROFILE_MINUTES.values()) + contract.V4_BOUNDARY_MINUTES, 475)
        self.assertEqual(contract.V4_PROFILE_MINUTES["doctor-1"], 60)

    def test_historical_schemas_and_legacy_field_refused(self):
        for schema in ("openclaw.fork-source-validation-request.v2", "openclaw.fork-source-validation-request.v3"):
            with self.subTest(schema=schema):
                self.f.request["schema"] = schema
                self.refused()
        self.f.request["schema"] = contract.V4_SCHEMA
        self.f.request["initialResume"] = None
        self.refused()

    def test_exact_authorization_policy_and_scope(self):
        for key in ("sourceAuthorization", "profilePolicy", "campaignId"):
            original = self.f.request[key]
            self.f.request[key] = "caller-selected"
            self.refused()
            self.f.request[key] = original
        self.f.request["sourceWitness"]["scope"] = "test-only"
        self.refused()

    def test_type_round_lifetime_and_limit(self):
        for number in (True, 3, 6):
            self.f.request["round"] = number
            self.refused()
        self.f.request["round"] = 4
        self.f.request["lifetimeOperatorRound"] = 6
        self.refused()

    def test_pins_not_request_selectable(self):
        self.f.request["sourceSha"] = oid("different")
        self.refused()
        self.f = Fixture()
        self.f.pins["arbitrary"] = None
        self.refused()

    def test_profiles_complete_ordered_and_unique(self):
        for profiles in ([], list(reversed(contract.V4_INITIAL_PROFILES)), ["dependency"] * 7,
                         ["doctor-2"], [*contract.V4_INITIAL_PROFILES, "types-production"]):
            self.f.request["profiles"] = profiles
            self.refused()

    def test_witness_required_even_same_source_correction(self):
        self.f.request.update(round=5, lifetimeOperatorRound=6, profiles=["pipeline-contracts"])
        self.f.pins["priorRunIds"] = [*self.f.pins["priorRunIds"], "99999"]
        self.f.request["priorRunIds"] = self.f.pins["priorRunIds"]
        contract.validate_request_v4(self.f.request, self.f.pins)
        self.f.request["sourceWitness"] = None
        self.refused()

    def test_correction_bounded_and_affected_owners(self):
        self.f.correction({contract.V4_GENERATOR_PATH})
        contract.validate_request_v4(self.f.request, self.f.pins)
        self.assertEqual(sum(contract.V4_PROFILE_MINUTES[p] for p in self.f.request["profiles"]) + 25, 355)
        self.f.request["profiles"] = ["dependency"]
        self.refused()
        self.f.request["profiles"] = list(contract.V4_INITIAL_PROFILES)
        contract.validate_request_v4(self.f.request, self.f.pins)
        self.assertEqual(sum(contract.V4_PROFILE_MINUTES[p] for p in self.f.request["profiles"]) + 25,
                         contract.V4_CORRECTION_MINUTES)
        self.assertEqual(contract.V4_CORRECTION_MINUTES, 475)
        self.f.request["profiles"].append("not-approved")
        self.refused()

    def test_same_source_correction_may_replay_all_seven_but_not_add_a_round(self):
        self.f.request.update(round=5, lifetimeOperatorRound=6)
        self.f.pins["priorRunIds"] = [*self.f.pins["priorRunIds"], "99999"]
        self.f.request["priorRunIds"] = self.f.pins["priorRunIds"]
        contract.validate_request_v4(self.f.request, self.f.pins)
        self.assertIsNone(self.f.request["sourceWitness"]["corrective"])
        self.f.request.update(round=6, lifetimeOperatorRound=7)
        self.refused()

    def test_stage_witness_cannot_omit_generator_or_rename_scope(self):
        self.f.request["sourceWitness"]["stageBase"]["changedPaths"].remove(contract.V4_GENERATOR_PATH)
        self.refused()


class EquivalenceTests(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()

    def verify(self):
        return contract.verify_source_equivalence_v4(self.f.request, self.f.pins, self.f.git)

    def refused(self):
        with self.assertRaises(contract.V4ContractRefusal):
            self.verify()

    def test_initial_all_four_and_exact_generator_row(self):
        result = self.verify()
        self.assertEqual(result["stageBase"]["changedPaths"], sorted(contract.V4_SOURCE_PATHS))
        self.assertFalse(result["sameSourceReceiptRelabeled"])
        self.assertFalse(result["testOnly"])
        self.assertTrue(result["generatorOwnerChanged"])
        self.assertEqual(len(self.f.old_ledger["paths"]), 248)
        self.assertEqual(len(self.f.new_ledger["paths"]), 249)

    def test_corrective_is_direct_from_stage_base_and_preserves_first_witness(self):
        current = self.f.correction({contract.V4_GENERATOR_PATH})
        result = self.verify()
        self.assertEqual(result["stageBase"]["parentSha"], contract.V4_PARENT_SOURCE)
        self.assertEqual(result["corrective"]["parentSha"], self.f.first)
        self.assertEqual(result["corrective"]["sourceSha"], current)
        self.assertEqual(result["reusedReceiptSourceSha"], contract.V4_PARENT_SOURCE)

    def test_merge_or_wrong_parent_refused(self):
        self.f.parents[self.f.first] += " " + oid("second parent")
        self.refused()

    def test_wrong_parent_or_current_tree_refused(self):
        self.f.tree_ids[self.f.parent] = oid("wrong tree")
        self.refused()
        self.f = Fixture()
        self.f.tree_ids[self.f.first] = oid("wrong tree")
        self.refused()

    def test_extra_production_dependency_lock_patch_or_mode_change_refused(self):
        for path in ("src/runtime.ts", "package.json", "pnpm-lock.yaml", "patches/security.patch"):
            with self.subTest(path=path):
                self.f = Fixture()
                self.f.after[path] = ("100644", "blob", oid("changed protected"))
                self.refused()
        self.f = Fixture()
        path = contract.V4_GENERATOR_PATH
        self.f.after[path] = ("100755", "blob", self.f.after[path][2])
        self.refused()

    def test_added_or_deleted_tracked_path_refused(self):
        self.f.after["extra.ts"] = ("100644", "blob", oid("extra"))
        self.refused()
        self.f = Fixture()
        del self.f.after["src/runtime.ts"]
        self.refused()

    def test_changed_set_cannot_be_witnessed_with_unchanged_file(self):
        self.f.after[contract.V4_GENERATOR_PATH] = self.f.before[contract.V4_GENERATOR_PATH]
        self.refused()

    def test_ledger_top_level_origins_row_fields_pathset_and_disposition_preserved(self):
        mutations = (
            lambda value: value.update(qualificationTransferred=True),
            lambda value: value["paths"][0].update(upstream108=None),
            lambda value: value["paths"][0].update(extra=True),
            lambda value: value["paths"].pop(),
            lambda value: value["paths"].append(copy.deepcopy(value["paths"][0])),
            lambda value: value["paths"][0].update(disposition="CARRIED_EXACT"),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.f = Fixture()
                mutation(self.f.new_ledger)
                self.refused()

    def test_preserved_json_types_are_exact_not_python_equal(self):
        self.f.new_ledger["qualificationTransferred"] = 0
        self.refused()
        self.f = Fixture()
        self.f.new_ledger["priorForkDeltaPaths"] = 243.0
        self.refused()

    def test_non_json_numeric_constant_refused(self):
        original = self.f.git
        def invalid(*args):
            if args == ("show", self.f.first + ":" + contract.V4_LEDGER_PATH):
                return encoded(self.f.new_ledger).replace(b'"priorForkDeltaPaths": 243', b'"priorForkDeltaPaths": NaN')
            return original(*args)
        with self.assertRaisesRegex(contract.V4ContractRefusal, "invalid_json_constant"):
            contract.verify_source_equivalence_v4(self.f.request, self.f.pins, invalid)

    def test_only_generator_may_gain_row_and_it_is_derived_not_caller_supplied(self):
        row = next(row for row in self.f.new_ledger["paths"] if row["path"] == contract.V4_GENERATOR_PATH)
        row["fork107"]["blob"] = oid("invented origin")
        self.refused()
        self.f = Fixture()
        path = "test/v108-remediation-security.test.mjs"
        self.f.old_ledger["paths"] = [row for row in self.f.old_ledger["paths"] if row["path"] != path]
        self.refused()

    def test_initial_requires_the_one_generator_row_addition(self):
        new = next(row for row in self.f.new_ledger["paths"] if row["path"] == contract.V4_GENERATOR_PATH)
        old = copy.deepcopy(new)
        old["result"]["blob"] = self.f.before[contract.V4_GENERATOR_PATH][2]
        self.f.old_ledger["paths"] = [old, *self.f.old_ledger["paths"][1:]]
        self.refused()

    def test_wrong_old_result_or_unapproved_disposition_refused(self):
        row = next(row for row in self.f.old_ledger["paths"] if row["path"] in contract.V4_SOURCE_PATHS)
        row["result"]["blob"] = oid("stale old result")
        self.refused()
        self.f = Fixture()
        row = next(row for row in self.f.old_ledger["paths"] if row["path"] in contract.V4_SOURCE_PATHS)
        row["disposition"] = "UNREVIEWED"
        self.refused()

    def test_duplicate_json_key_or_bad_git_entry_refused(self):
        original = self.f.git
        def duplicate(*args):
            if args == ("show", self.f.first + ":" + contract.V4_LEDGER_PATH):
                return b'{"paths":[],"paths":[]}'
            return original(*args)
        with self.assertRaisesRegex(contract.V4ContractRefusal, "duplicate_json_key"):
            contract.verify_source_equivalence_v4(self.f.request, self.f.pins, duplicate)
        self.f.request["sourceWitness"]["stageBase"]["unchangedTreeSha256"] = "0" * 64
        self.refused()


class ReuseTests(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()
        jobs = [{"name": f"source ({profile})", "status": "completed", "conclusion": "success",
                 "runner_id": 123, "runner_name": "synthetic", "steps": [{"conclusion": "success"}]}
                for profile in contract.V4_PARENT_PASSED_PROFILES]
        jobs.extend({"name": f"source ({profile})", "status": "completed", "conclusion": "failure"}
                    for profile in ("types-tests", "doctor-1", "pipeline-contracts", "compatibility"))
        jobs.append({"name": "source (models-1)", "status": "completed", "conclusion": "cancelled"})
        self.run = {"id": int(contract.V4_PARENT_RUN), "head_sha": contract.V4_PARENT_PIPELINE, "run_attempt": 1,
            "event": "pull_request", "status": "completed", "path": ".github/workflows/future-v108-source-validation.yml",
            "head_branch": "task/v107-source-binding", "jobs": jobs}
        self.prefix = {"runs": [self.run, *({"id": number} for number in range(98))], "runnerMinutesObserved": 886}

    def verify(self):
        raw = encoded(self.prefix)
        # Synthetic fixture pin, never a substitute for the production fixed69a4 hash.
        with patch.object(contract, "V4_CLOSED_PREFIX_SHA256", hashlib.sha256(raw).hexdigest()):
            return contract.validate_reused_profile_evidence_v4(raw, self.f.git)

    def test_exact_eight_reused_from_ten_verified_passes(self):
        result = self.verify()
        self.assertEqual(result["profiles"], list(contract.V4_REUSED_PROFILES))
        self.assertEqual(len(result["passedParentProfiles"]), 10)
        self.assertNotIn("dependency", result["profiles"])
        self.assertNotIn("types-scripts", result["profiles"])
        self.assertFalse(result["relabeledAsCurrentSourcePass"])

    def test_fixed_prefix_bytes_required(self):
        with self.assertRaises(contract.V4ContractRefusal):
            contract.validate_reused_profile_evidence_v4(encoded(self.prefix), self.f.git)

    def test_partial_failed_or_unacquired_reused_profile_refused(self):
        for field, value in (("conclusion", "failure"), ("status", "in_progress"), ("runner_id", None), ("steps", [])):
            with self.subTest(field=field):
                job = next(job for job in self.run["jobs"] if job["name"] == "source (sqlite)")
                original = job.get(field)
                job[field] = value
                with self.assertRaises(contract.V4ContractRefusal):
                    self.verify()
                job[field] = original

    def test_failed_profiles_do_not_become_passes_and_duplicates_refused(self):
        job = next(job for job in self.run["jobs"] if job["name"] == "source (doctor-1)")
        job["conclusion"] = "success"
        with self.assertRaises(contract.V4ContractRefusal):
            self.verify()
        job["conclusion"] = "failure"
        self.run["jobs"].append(copy.deepcopy(self.run["jobs"][0]))
        with self.assertRaises(contract.V4ContractRefusal):
            self.verify()

    def test_parent_run_attempt_and_control_metadata_binding(self):
        self.run["run_attempt"] = 2
        with self.assertRaises(contract.V4ContractRefusal):
            self.verify()
        self.run["run_attempt"] = 1
        self.f.historical["inventorySha256"] = "0" * 64
        with self.assertRaises(contract.V4ContractRefusal):
            self.verify()


if __name__ == "__main__":
    unittest.main()
