"""Small synthetic Python-only V5 requests/Git bytes; no process/API/test runtime."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
INTEGRATED = HERE / "source_validation_v108.py"
Q = HERE.parent.parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


contract = load("v5_request_under_test", INTEGRATED if INTEGRATED.is_file() else HERE / "request_contract_v5.py")
old_tests = load("v4_synthetic_fixtures", HERE / "test_request_contract_v4.py" if INTEGRATED.is_file()
                 else Q / "request-contract/test_request_contract_v4.py")
if not INTEGRATED.is_file():
    contract._v4_verify_step = old_tests.contract._v4_verify_step
    contract.validate_reused_profile_evidence_v4 = old_tests.contract.validate_reused_profile_evidence_v4
V4_REFUSAL = contract.V4ContractRefusal if INTEGRATED.is_file() else old_tests.contract.V4ContractRefusal


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


class V5Fixture:
    def __init__(self):
        self.git_fixture = old_tests.Fixture()
        f = self.git_fixture
        old_first = f.first
        for mapping in (f.parents, f.tree_ids, f.trees, f.ledgers):
            mapping[contract.V5_FIRST_SOURCE] = mapping.pop(old_first)
        f.first, f.first_tree = contract.V5_FIRST_SOURCE, contract.V5_FIRST_TREE
        f.tree_ids[f.first] = f.first_tree
        self.pins = {**f.pins, "sourceSha":f.first, "sourceTree":f.first_tree,
            "firstSourceSha":f.first, "firstSourceTree":f.first_tree,
            "settledUsageSha256":contract.V5_BASELINE_SHA256,
            "priorRunIds":list(contract.V5_CLOSED_SOURCE_RUN_IDS), "sourceHops":[], "previousSourceHopCount":0}
        self.request = {"schema":contract.V5_SCHEMA, "campaignId":contract.V5_CAMPAIGN,
            "profilePolicy":contract.V5_POLICY,"stageRound":0,"lifetimeOperatorRound":7,
            "profiles":list(contract.V5_PROFILES),"sourceAuthorization":contract.V5_AUTHORIZATION,
            **{key:self.pins[key] for key in ("sourceSha","sourceTree","firstSourceSha","firstSourceTree",
                 "manifestSha256","inventorySha256","settledUsageSha256","priorRunIds")},
            "sourceWitness":{"schema":"openclaw.v108.fixture-generator-equivalence.v2","scope":contract.V5_SCOPE,
                "originalClosedPrefixSha256":contract.V5_ORIGINAL_PREFIX_SHA256,
                "closedBaselineSha256":contract.V5_BASELINE_SHA256,
                "stageBase":copy.deepcopy(f.request["sourceWitness"]["stageBase"]),"correctionHops":[]}}

    def round(self, number):
        self.request.update(stageRound=number,lifetimeOperatorRound=7+number)
        self.pins["priorRunIds"] = [*contract.V5_CLOSED_SOURCE_RUN_IDS,*[str(88881+n) for n in range(number)]]
        self.request["priorRunIds"] = self.pins["priorRunIds"]

    def hop(self, paths):
        f = self.git_fixture
        parent, parent_tree = self.pins["sourceSha"], self.pins["sourceTree"]
        index = len(self.pins["sourceHops"])+1
        current, tree = old_tests.oid("hop"+str(index)), old_tests.oid("hop tree"+str(index))
        before = f.trees[parent]
        after = dict(before)
        ledger = copy.deepcopy(f.ledgers[parent])
        for path in paths:
            after[path] = ("100644","blob",old_tests.oid("hop"+str(index)+path))
            next(row for row in ledger["paths"] if row["path"]==path)["result"]["blob"] = after[path][2]
        after[old_tests.contract.V4_LEDGER_PATH] = ("100644","blob",old_tests.oid("hop ledger"+str(index)))
        f.trees[current], f.ledgers[current], f.parents[current], f.tree_ids[current] = after,ledger,parent,tree
        step = {"parentSha":parent,"parentTree":parent_tree,"changedPaths":sorted(paths),
            "unchangedTreeSha256":old_tests.unchanged_digest(before,{*paths,old_tests.contract.V4_LEDGER_PATH})}
        self.pins["sourceHops"].append({"sourceSha":current,"sourceTree":tree})
        self.request["sourceWitness"]["correctionHops"].append({"sourceSha":current,"sourceTree":tree,"step":step})
        self.pins.update(sourceSha=current,sourceTree=tree,manifestSha256=str(index+3)*64,inventorySha256=str(index+5)*64)
        for key in ("sourceSha","sourceTree","manifestSha256","inventorySha256"):
            self.request[key] = self.pins[key]
        return current


class V5Tests(unittest.TestCase):
    def setUp(self):
        # Synthetic-only binding; never an operational default or a real P7 ID.
        self.baseline = patch.object(contract,"V5_BASELINE_SHA256","9"*64)
        self.ids = patch.object(contract,"V5_CLOSED_SOURCE_RUN_IDS",(
            "40607329263","40609889437","40616416909","40639374411","40647629182","40681376480","77777"))
        self.baseline.start();self.ids.start();self.addCleanup(self.ids.stop);self.addCleanup(self.baseline.stop)
        self.f = V5Fixture()

    def validate(self):
        return contract.validate_request_v5(self.f.request,self.f.pins)

    def verify(self):
        return contract.verify_source_equivalence_v5(self.f.request,self.f.pins,self.f.git_fixture.git)

    def refused(self):
        with self.assertRaises(contract.V5ContractRefusal):self.validate()

    def test_initial_complete_closed_budget_and_source_identity(self):
        self.validate();result=self.verify()
        self.assertEqual(result["sourceSha"],contract.V5_FIRST_SOURCE)
        self.assertEqual(result["correctionHops"],[])
        self.assertFalse(result["testOnly"]);self.assertFalse(result["sameSourceReceiptRelabeled"])
        self.assertEqual(sum(contract.V5_PROFILE_MINUTES.values())+30+10,520)
        self.assertEqual(3*520+90,contract.V5_STAGE_MINUTES)
        self.assertEqual(contract.V5_PRIOR_MINUTES+contract.V5_STAGE_MINUTES,2578)

    def test_policy_measurement_preserves_historical_versions(self):
        for schema,policy,admission,doctor,profiles in ((contract.V5_SCHEMA,contract.V5_POLICY,30,90,7),
                ("openclaw.fork-source-validation-request.v4","five-gate-repair-v1",15,60,7),
                ("openclaw.fork-source-validation-request.v3",None,15,45,15)):
            record={"schema":schema}
            if policy:record["profilePolicy"]=policy
            limits=contract.validation_budget_for_record_v5(record)
            self.assertEqual(limits["admissionMinutes"],admission)
            self.assertEqual(limits["profileMinutes"]["doctor-1"],doctor)
            self.assertEqual(len(limits["profileMinutes"]),profiles)
            limits["profileMinutes"]["doctor-1"]=-1
            self.assertEqual(contract.validation_budget_for_record_v5(record)["profileMinutes"]["doctor-1"],doctor)
        for record in ({"schema":"unknown"},{"schema":contract.V5_SCHEMA,"profilePolicy":"other"}):
            with self.assertRaises(contract.V5ContractRefusal):contract.validation_budget_for_record_v5(record)

    def test_unbound_baseline_and_legacy_operational_inputs_refuse(self):
        with patch.object(contract,"V5_BASELINE_SHA256",None):self.refused()
        for schema in ("openclaw.fork-source-validation-request.v2","openclaw.fork-source-validation-request.v3",
                       "openclaw.fork-source-validation-request.v4"):
            self.f.request["schema"]=schema;self.refused()

    def test_schema_fields_policy_auth_and_pins_are_closed(self):
        for key in ("profilePolicy","sourceAuthorization","sourceSha","sourceTree","settledUsageSha256"):
            old=self.f.request[key];self.f.request[key]="unreviewed";self.refused();self.f.request[key]=old
        self.f.request["round"]=0;self.refused();del self.f.request["round"]
        self.f.pins["arbitrary"]=True;self.refused()

    def test_exact_three_lifetime_rounds_and_no_more(self):
        for number in (0,1,2):
            self.f.round(number);self.validate()
        for number in (True,-1,3):
            self.f.request["stageRound"]=number;self.refused()
        self.f.round(2);self.f.request["lifetimeOperatorRound"]=10;self.refused()

    def test_initial_profiles_complete_and_later_subset_closed(self):
        self.f.request["profiles"]=["dependency"];self.refused()
        self.f.round(1);self.validate()
        for profiles in ([],["dependency","dependency"],["doctor-3"],["$(bad)"]):
            self.f.request["profiles"]=profiles;self.refused()

    def test_same_b_controller_only_rounds_keep_stage_base_proof(self):
        self.f.round(2);self.f.request["profiles"]=["pipeline-contracts"]
        self.verify()
        self.f.request["sourceWitness"]["stageBase"]=None;self.refused()

    def test_two_direct_source_hops_with_full_git_proof(self):
        self.f.round(1);self.f.hop({"scripts/generate-npm-package-lock.mts"});self.verify()
        self.f.pins["previousSourceHopCount"]=1;self.f.round(2)
        self.f.hop({"test/v108-remediation-security.test.mjs"})
        result=self.verify();self.assertEqual(len(result["correctionHops"]),2)
        self.assertEqual(result["correctionHops"][1]["parentSha"],result["correctionHops"][0]["sourceSha"])

    def test_old_source_hop_is_reverified_without_unneeded_owner_reruns(self):
        self.f.round(1);self.f.hop({"scripts/generate-npm-package-lock.mts"})
        self.f.round(2);self.f.pins["previousSourceHopCount"]=1
        self.f.request["profiles"]=["doctor-1"];self.verify()
        current=self.f.pins["sourceSha"]
        self.f.git_fixture.trees[current]["package.json"]=("100644","blob",old_tests.oid("changed protected"))
        with self.assertRaises(V4_REFUSAL):self.verify()

    def test_new_hop_requires_affected_owner_set(self):
        self.f.round(1);self.f.hop({"scripts/generate-npm-package-lock.mts"})
        self.f.request["profiles"]=["doctor-1"];self.refused()
        self.f.request["profiles"]=sorted(contract.v5_required_correction_profiles({"scripts/generate-npm-package-lock.mts"}))
        self.verify()

    def test_hop_omission_wrong_parent_merge_or_path_is_not_equivalence(self):
        self.f.round(1);current=self.f.hop({"test/v108-remediation-security.test.mjs"})
        original=copy.deepcopy(self.f.request["sourceWitness"]["correctionHops"])
        self.f.request["sourceWitness"]["correctionHops"]=[];self.refused()
        self.f.request["sourceWitness"]["correctionHops"]=original
        self.f.git_fixture.parents[current]+=" "+old_tests.oid("merge")
        with self.assertRaises(V4_REFUSAL):self.verify()

    def test_source_hops_bounded_no_duplicates_or_two_new_in_one_round(self):
        self.f.round(2);self.f.hop({"test/v108-remediation-security.test.mjs"})
        self.f.hop({"test/scripts/generate-npm-package-lock.test.ts"});self.refused()
        self.f.pins["previousSourceHopCount"]=1;self.validate()
        self.f.pins["sourceHops"].append(copy.deepcopy(self.f.pins["sourceHops"][-1]));self.refused()

    def test_json_duplicate_and_non_json_constants_refuse(self):
        for raw in (b'{"stageRound":0,"stageRound":1}',b'{"value":NaN}'):
            with self.assertRaises(contract.V5ContractRefusal):contract._v5_json(raw)


class BaselineReuseTests(unittest.TestCase):
    def setUp(self):
        source = (HERE / "fixtures/v108-settled-closed99.json") if INTEGRATED.is_file() else (
            Q / "pipeline/scripts/fork-release/candidates/v2026.10.8-source-only/settled-usage.json")
        self.original_raw=source.read_bytes()
        self.assertEqual(hashlib.sha256(self.original_raw).hexdigest(),contract.V5_ORIGINAL_PREFIX_SHA256)
        self.original=json.loads(self.original_raw)
        self.baseline={"schema":"openclaw.v108.closed-source-usage.v3","repository":"fr-meyer/openclaw",
            "campaignId":contract.V5_CAMPAIGN,"runnerMinutesObserved":928,"runCount":141,
            "previousPrefixSha256":contract.V5_ORIGINAL_PREFIX_SHA256,"previousPrefixRunCount":99,
            "previousPrefixMinutes":886,"previousPrefixPipeline":contract.V5_ORIGINAL_PREFIX_PIPELINE,
            "runs":copy.deepcopy(self.original["runs"])+[{"id":90000000000+n} for n in range(42)]}
        self.git_fixture=old_tests.Fixture()
    def git(self,*args):
        if args==("show",contract.V5_ORIGINAL_PREFIX_PIPELINE+":"+contract.V5_SETTLED_USAGE_PATH):return self.original_raw
        return self.git_fixture.git(*args)
    def verify(self):
        raw=encoded(self.baseline)
        with patch.object(contract,"V5_BASELINE_SHA256",hashlib.sha256(raw).hexdigest()):
            return contract.validate_reused_profile_evidence_v5(raw,self.git)
    def test_reverify_original_bytes_and_eight_f5_passes_without_relabel(self):
        result=self.verify();self.assertEqual(len(result["profiles"]),8)
        self.assertEqual(result["sourceSha"],"f5c198efedd78625e5a1b4a133d58ebfb3dae1c5")
        self.assertEqual(result["closedPrefixSha256"],contract.V5_ORIGINAL_PREFIX_SHA256)
        self.assertTrue(result["originalPrefixRawGitReverified"])
        self.assertFalse(result["relabeledAsCurrentSourcePass"])
    def test_new_baseline_hash_and_old_git_bytes_are_required(self):
        with patch.object(contract,"V5_BASELINE_SHA256","0"*64),self.assertRaises(contract.V5ContractRefusal):
            contract.validate_reused_profile_evidence_v5(encoded(self.baseline),self.git)
        self.original_raw+=b" "
        with self.assertRaises(contract.V5ContractRefusal):self.verify()
    def test_count_minutes_duplicate_or_old99_type_drift_refuse(self):
        for key,value in (("runCount",140),("runnerMinutesObserved",929),("previousPrefixMinutes",886.0)):
            old=self.baseline[key];self.baseline[key]=value
            with self.assertRaises(contract.V5ContractRefusal):self.verify()
            self.baseline[key]=old
        self.baseline["runs"][-1]=copy.deepcopy(self.baseline["runs"][0])
        with self.assertRaises(contract.V5ContractRefusal):self.verify()
    def test_old99_subset_must_be_identical(self):
        self.baseline["runs"][0]["observedRunnerMinutes"]=0.0
        with self.assertRaises(contract.V5ContractRefusal):self.verify()


if __name__=="__main__":unittest.main()
