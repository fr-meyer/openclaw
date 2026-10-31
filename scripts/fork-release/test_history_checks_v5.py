"""Local synthetic provider boundary tests with genuine immutable141/928 history.

No HTTP, app/Node execution, dependencies, Git mutations or runner actions.
"""
import ast
import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
from pathlib import Path
import re
import importlib.util
import sys
import tempfile
import types
import unittest

HERE = Path(__file__).resolve().parent
PIPELINE = HERE.parents[1]
CURRENT = "9000000099"
HEAD = "a" * 40
NOW = datetime(2026, 10, 28, 14, tzinfo=timezone.utc)


class Refusal(ValueError):
    pass


def need(value, code):
    if not value:
        raise Refusal(code)


class Clock(datetime):
    @classmethod
    def now(cls, tz=None):
        return NOW


def load_fragment():
    # Fresh module state per test, from exact immutable P7 Python bytes.
    # V6 current controls/CLI never supply a historical V5 fixture.
    from historical_v5_test_inputs import load_p7_driver
    module, _ = load_p7_driver("historical_v5_history_owner_fixture")
    ns = module.__dict__
    ns["need"] = need
    ns["datetime"] = Clock
    ns["V5_STAGE_PINS"] = copy.deepcopy(ns["V5_STAGE_PINS"])
    ns["V5_STAGE_RUN_PINS"] = []
    return ns


def instant(value):
    return value.isoformat().replace("+00:00", "Z")


class HistoryV5Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Byte-exact approved public fixtures. No API, Git, network or processes.
        cls.git_blobs = {
            "2946a1678e712de90727a9e599a5f2cd47ad2151:scripts/fork-release/candidates/v2026.10.8-source-only/settled-usage.json":
                (HERE / "fixtures/v108-settled-closed99.json").read_bytes(),
            "0dd3c9ef205939350f41ab2187232268c7c44ab8:scripts/fork-release/candidates/v2026.10.8-source-only/source-request.json":
                (HERE / "fixtures/v108-source-request-v3-0dd.json").read_bytes(),
        }

    def setUp(self):
        self.ns = load_fragment()
        self.temp = tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        from historical_v5_test_inputs import p7_input
        self.raw = p7_input("settled-usage.json");self.prefix = json.loads(self.raw)
        p = self.root / self.ns["V5_SETTLED_USAGE_PATH"];p.parent.mkdir(parents=True);p.write_bytes(self.raw)
        self.workflow = p7_input("workflow")
        self.workflow = self.workflow.replace(b"    timeout-minutes: 15\n", b"    timeout-minutes: 30\n", 1)
        w = self.root / self.ns["WORKFLOW"];w.parent.mkdir(parents=True);w.write_bytes(self.workflow)
        pins = self.ns["V5_STAGE_PINS"]
        self.request = {"schema":self.ns["V5_SCHEMA"], "campaignId":self.ns["V5_CAMPAIGN"],
          "profilePolicy":self.ns["V5_POLICY"], "stageRound":0, "lifetimeOperatorRound":7,
          "profiles":list(self.ns["V5_PROFILES"]), "sourceAuthorization":self.ns["V5_AUTHORIZATION"],
          **{k:copy.deepcopy(pins[k]) for k in ("sourceSha", "sourceTree", "firstSourceSha", "firstSourceTree",
             "manifestSha256", "inventorySha256", "settledUsageSha256", "priorRunIds")},
          "sourceWitness":{"schema":"openclaw.v108.fixture-generator-equivalence.v2", "scope":self.ns["V5_SCOPE"],
            "originalClosedPrefixSha256":self.ns["V5_ORIGINAL_PREFIX_SHA256"], "closedBaselineSha256":self.ns["V5_BASELINE_SHA256"],
            "stageBase":{"parentSha":self.ns["V4_PARENT_SOURCE"], "parentTree":self.ns["V4_PARENT_TREE"],
                         "changedPaths":sorted(self.ns["V5_SOURCE_PATHS"]), "unchangedTreeSha256":"f"*64}, "correctionHops":[]}}
        repo = {"full_name":self.ns["REPOSITORY"], "private":False}
        self.pr = {"number":28, "state":"open", "draft":True,
            "head":{"repo":repo,"ref":self.ns["BRANCH"],"sha":HEAD},
            "base":{"repo":repo,"ref":self.ns["BASE_BRANCH"],"sha":self.ns["BASE"]}}
        self.event = {"action":"synchronize", "number":28, "repository":repo, "pull_request":self.pr}
        self.env = {"GITHUB_ACTIONS":"true", "RUNNER_OS":"Linux", "RUNNER_ENVIRONMENT":"github-hosted",
            "GITHUB_EVENT_NAME":"pull_request", "GITHUB_RUN_ATTEMPT":"1", "GITHUB_REPOSITORY":self.ns["REPOSITORY"],
            "GITHUB_REF":"refs/pull/28/merge", "GITHUB_WORKFLOW_REF":self.ns["REPOSITORY"]+"/"+self.ns["WORKFLOW"]+"@refs/pull/28/merge",
            "GITHUB_WORKFLOW_SHA":"b"*40, "GITHUB_RUN_ID":CURRENT}
        self.history = {}
        for row in self.prefix["runs"]:
            run = {key:copy.deepcopy(row[key]) for key in self.ns["V5_PROVIDER_RUN_HEADERS"]}
            run.update(repository=repo, head_repository=repo, display_title=self.ns["CAMPAIGN"], pull_requests=[{"number":28}])
            self.history[str(run["id"])] = run
        self.history[CURRENT] = self.run_record(CURRENT,self.ns["WORKFLOW"],"in_progress",HEAD)
        self.count=0;self.tables={CURRENT:{"total_count":1,"jobs":[self.job(CURRENT,"admission",status="in_progress")]}}
        self.contents={};self.artifacts={};self.calls=[];self.source_tip=pins["sourceSha"]
        def fake_git(root,*args):
            self.calls.append(("git",args))
            if args[0] == "show":return self.git_blobs[args[1]]
            if args[:2] == ("merge-base","--is-ancestor"):return b""
            raise AssertionError(args)
        self.ns["git"] = fake_git

    def run_record(self,rid,path,status="completed",head=HEAD):
        repo={"full_name":self.ns["REPOSITORY"],"private":False}
        return {"id":int(rid),"path":path,"head_sha":head,"event":"pull_request","run_attempt":1,
            "head_branch":self.ns["BRANCH"],"display_title":self.ns["CAMPAIGN"],"status":status,
            "conclusion":"success" if status=="completed" else None,"repository":repo,"head_repository":repo,
            "pull_requests":[{"number":28}],"created_at":"2026-10-28T13:59:00Z","updated_at":"2026-10-28T14:00:00Z"}

    def job(self,rid,name,minutes=1,status="completed",acquired=True):
        self.count+=1
        return {"id":int(rid)*1000+self.count,"run_id":int(rid),"head_sha":self.history[rid]["head_sha"],
            "run_attempt":1,"name":name,"status":status,"conclusion":"success" if status=="completed" else None,
            "runner_id":12 if acquired else None,"runner_name":"hosted" if acquired else None,
            "runner_group_name":"GitHub Actions" if acquired else None,"labels":["ubuntu-24.04"],
            "steps":[{"name":"synthetic"}] if acquired else [],
            "started_at":instant(NOW-timedelta(minutes=minutes)) if acquired else None,
            "completed_at":instant(NOW) if status=="completed" and acquired else None}

    def api(self,route):
        self.calls.append(("api",route));root="/repos/"+self.ns["REPOSITORY"]
        if route==root+"/pulls/28":return copy.deepcopy(self.pr)
        if route==root+"/git/ref/heads/"+self.ns["BASE_BRANCH"]:
            return {"ref":"refs/heads/"+self.ns["BASE_BRANCH"],"object":{"type":"commit","sha":self.ns["TARGET_BRANCH_TIP"]}}
        if route==root+"/git/ref/heads/"+self.ns["V5_SOURCE_BRANCH"]:
            return {"ref":"refs/heads/"+self.ns["V5_SOURCE_BRANCH"],"object":{"type":"commit","sha":self.source_tip}}
        if route.startswith(root+"/actions/runs?branch="):
            page=int(route.rsplit("=",1)[1]);rows=list(self.history.values())
            return {"total_count":len(rows),"workflow_runs":copy.deepcopy(rows[(page-1)*100:page*100])}
        m=re.fullmatch(root+r"/actions/runs/([0-9]+)/jobs\?filter=all&per_page=100",route)
        if m:return copy.deepcopy(self.tables[m[1]])
        m=re.fullmatch(root+r"/actions/runs/([0-9]+)/artifacts\?per_page=100",route)
        if m:
            rows=self.artifacts.get(m[1],[]);return {"total_count":len(rows),"artifacts":copy.deepcopy(rows)}
        if route.startswith(root+"/contents/"):
            raw=self.contents[route.split("/contents/",1)[1]]
            return {"type":"file","encoding":"base64","size":len(raw),"content":base64.b64encode(raw).decode()}
        raise AssertionError(route)

    def check(self):return self.ns["history_checks_v5"](self.request,self.event,self.env,self.root,self.api)

    def prior(self,unexpanded=False):
        rid="9000000098";head="c"*40
        raw=(json.dumps(self.request,sort_keys=True)+"\n").encode()
        self.contents[self.ns["REQUEST"]+"?ref="+head]=raw
        self.contents[self.ns["WORKFLOW"]+"?ref="+head]=self.workflow
        self.ns["V5_STAGE_RUN_PINS"].append({"runId":rid,"pipelineHead":head,"requestSha256":hashlib.sha256(raw).hexdigest()})
        self.history[rid]=self.run_record(rid,self.ns["WORKFLOW"],head=head)
        self.history[rid]["created_at"]="2026-10-28T13:55:00Z"
        names=["admission","final"]+["source ("+p+")" for p in self.request["profiles"]]
        if unexpanded:
            # Use real P5 job fields, not fabricated defaults, rebinding only
            # synthetic run/head/timing identities to this test's future run.
            actual=next(r for r in self.prefix["runs"] if str(r["id"])=="40681376480")
            jobs=copy.deepcopy(actual["jobs"])
            for j in jobs:j.update(run_id=int(rid),head_sha=head)
            self.history[rid]["conclusion"]="failure"
        else:jobs=[self.job(rid,n) for n in names]
        self.tables[rid]={"total_count":len(jobs),"jobs":jobs}
        self.request["priorRunIds"].append(rid);self.ns["V5_STAGE_PINS"]["priorRunIds"].append(rid)
        self.request.update(stageRound=1,lifetimeOperatorRound=8)
        return rid

    def test_actual141_provider_projection_and_initial2578_booking(self):
        facts=self.check();self.assertEqual(facts["bookedRunnerMinutes"],2578)
        self.assertEqual((facts["currentRoundBookedMinutes"],facts["futureTargetedReserveMinutes"]),(520,1040))
        self.assertEqual((len(facts["historicalJobTableSha256"]),facts["actualSettledRunnerMinutes"]),(141,928))
        self.assertEqual((facts["reusedProfileCount"],facts["observedRetainedWorkflowArtifactBytes"]),(8,8090))
        self.assertTrue(any(r.get("artifactRows") for r in self.prefix["runs"]))
        self.assertFalse(any("artifactRows" in r for r in self.history.values()))
        self.assertEqual(len([c for c in self.calls if c[0]=="api" and "/jobs?" in c[1]]),1)

    def test_real_failed_P5_P6_tables_charge5_15_and_no_fake_named_profile(self):
        budget=self.ns["validation_budget_for_record_v5"]({"schema":self.ns["V4_SCHEMA"],"profilePolicy":self.ns["V4_POLICY"]})
        for rid,minutes in [("40681376480",5),("40688279536",15)]:
            row=next(r for r in self.prefix["runs"] if str(r["id"])==rid)
            self.assertEqual(self.ns["observed_minutes_v5"]({"total_count":3,"jobs":row["jobs"]},list(budget["profileMinutes"]),budget),minutes)
            self.assertTrue(self.ns["_h5_unexpanded_failed_initial"](row["jobs"]))
        self.prior(unexpanded=True);facts=self.check()
        self.assertEqual(facts["firstSourceReceipt"]["profileResults"],{})
        self.assertEqual(facts["priorUnresolvedProfiles"],sorted(self.ns["V5_PROFILES"]))
        self.assertEqual(facts["bookedRunnerMinutes"],2063)

    def test_successful_prior_allows_targeted_subset_preserves_source_provenance(self):
        self.prior();self.request["profiles"]=["pipeline-contracts"]
        facts=self.check();self.assertEqual(facts["priorUnresolvedProfiles"],[])
        self.assertEqual(facts["bookedRunnerMinutes"],1617)
        self.assertFalse(facts["firstSourceReceipt"]["relabeledAsCurrentSourcePass"])

    def test_unresolved_failed_or_unexpanded_cannot_be_omitted(self):
        self.prior(unexpanded=True);self.request["profiles"]=["pipeline-contracts"]
        with self.assertRaisesRegex(Refusal,"unresolved_prior_profiles_selected"):self.check()

    def test_unknown_future_controls_refuse(self):
        self.prior();self.ns["V5_STAGE_RUN_PINS"]=[]
        with self.assertRaisesRegex(Refusal,"genuine_stage_controls"):self.check()

    def test_wrong_prior_request_digest_refuses(self):
        self.prior();self.ns["V5_STAGE_RUN_PINS"][0]["requestSha256"]="e"*64
        with self.assertRaisesRegex(Refusal,"prior_stage_request_digest"):self.check()

    def test_prior_source_hop_count_cannot_be_forged(self):
        self.prior();self.ns["V5_STAGE_PINS"]["previousSourceHopCount"]=1
        with self.assertRaises(ValueError):self.check()

    def test_prefix_changed_updated_status_or_attempt_refuses(self):
        rid=str(self.prefix["runs"][0]["id"])
        for k,v in [("updated_at","2026-10-28T14:00:00Z"),("status","queued"),("run_attempt",2)]:
            with self.subTest(k=k):
                old=self.history[rid][k];self.history[rid][k]=v
                with self.assertRaises(Refusal):self.check()
                self.history[rid][k]=old

    def test_prefix_raw_mutation_refuses(self):
        (self.root/self.ns["V5_SETTLED_USAGE_PATH"]).write_bytes(self.raw+b" ")
        with self.assertRaisesRegex(Refusal,"prefix_digest"):self.check()

    def test_extra_source_round_current_head_rerun_or_private_refuses(self):
        for k,v in [("head_sha","d"*40),("run_attempt",2),("path",".github/workflows/other.yml")]:
            old=self.history[CURRENT][k];self.history[CURRENT][k]=v
            with self.assertRaises(Refusal):self.check()
            self.history[CURRENT][k]=old
        self.history[CURRENT]["repository"]["private"]=True
        with self.assertRaises(Refusal):self.check()

    def test_source_ref_and_pr_base_draft_changes_refuse(self):
        self.source_tip="e"*40
        with self.assertRaisesRegex(Refusal,"source_branch_tip"):self.check()
        self.source_tip=self.request["sourceSha"];self.pr["draft"]=False
        with self.assertRaises(Refusal):self.check()

    def test_pending_ancillary_truthful_no_wait_full90_reserve(self):
        rid="9000000100";path=next(r["path"] for r in self.prefix["runs"] if r["path"]!=self.ns["WORKFLOW"])
        self.history[rid]=self.run_record(rid,path,"queued")
        self.tables[rid]={"total_count":1,"jobs":[self.job(rid,"fixed",status="queued",acquired=False)]}
        facts=self.check();self.assertFalse(facts["ancillaryUsageComplete"])
        self.assertEqual(facts["pendingAncillaryRunIds"],[rid]);self.assertEqual(facts["ancillaryReservationBookedMinutes"],90)
        self.assertEqual(facts["newAncillaryRemainingReserveMinutes"],90);self.assertFalse(facts["ancillaryWaitPerformed"])

    def test_acquired_pending_charged_and_unknown_acquisition_refuses(self):
        rid="9000000100";path=next(r["path"] for r in self.prefix["runs"] if r["path"]!=self.ns["WORKFLOW"])
        self.history[rid]=self.run_record(rid,path,"in_progress")
        self.tables[rid]={"total_count":1,"jobs":[self.job(rid,"fixed",minutes=12,status="in_progress")]}
        self.assertEqual(self.check()["observedNewAncillaryRunnerMinutes"],12)
        self.tables[rid]["jobs"][0]["runner_id"]=None
        with self.assertRaises(Refusal):self.check()

    def test_artifact_bytes_count_and_64MiB_refusal(self):
        self.artifacts[CURRENT]=[{"id":999,"size_in_bytes":123,"expired":False}]
        self.assertEqual(self.check()["observedRetainedWorkflowArtifactBytes"],8213)
        self.artifacts[CURRENT][0]["size_in_bytes"]=64*1024*1024
        with self.assertRaisesRegex(Refusal,"artifact_storage_bound"):self.check()

    def test_three_page_history_bound_and_duplicate_ids_refuse(self):
        original=self.api
        def bad(route):
            result=original(route)
            if "/actions/runs?" in route:result["total_count"]=301
            return result
        with self.assertRaisesRegex(Refusal,"branch_page"):self.ns["history_checks_v5"](self.request,self.event,self.env,self.root,bad)

    def test_fresh_job_requires_positive_run_attempt(self):
        del self.tables[CURRENT]["jobs"][0]["run_attempt"]
        with self.assertRaisesRegex(Refusal,"fresh_job_binding"):self.check()

    def test_new_admission30_doctor90_and_old_v4_doctor60_policy(self):
        self.prior();rid=self.request["priorRunIds"][-1];table=self.tables[rid]
        for j in table["jobs"]:
            if j["name"]=="admission":j["started_at"]=instant(NOW-timedelta(minutes=29))
            if j["name"]=="source (doctor-1)":j["started_at"]=instant(NOW-timedelta(minutes=89))
        self.assertEqual(self.check()["observedNewPriorRunnerMinutes"],125)
        v4=self.ns["validation_budget_for_record_v5"]({"schema":self.ns["V4_SCHEMA"],"profilePolicy":self.ns["V4_POLICY"]})
        with self.assertRaisesRegex(Refusal,"terminal_job_duration"):
            self.ns["observed_minutes_v5"](table,list(self.ns["V5_PROFILES"]),v4)

    def test_second_correction_requires_two_genuine_completed_predecessors(self):
        self.prior();first_raw=self.contents[self.ns["REQUEST"]+"?ref="+"c"*40]
        # Synthetic genuine publication/request binding of completed correction1.
        rid="9000000097";head="d"*40
        raw=(json.dumps(self.request,sort_keys=True)+"\n").encode()
        self.contents[self.ns["REQUEST"]+"?ref="+head]=raw
        self.contents[self.ns["WORKFLOW"]+"?ref="+head]=self.workflow
        self.ns["V5_STAGE_RUN_PINS"].append({"runId":rid,"pipelineHead":head,"requestSha256":hashlib.sha256(raw).hexdigest()})
        self.history[rid]=self.run_record(rid,self.ns["WORKFLOW"],head=head)
        self.history[rid]["created_at"]="2026-10-28T13:57:00Z"
        names=["admission","final"]+["source ("+p+")" for p in self.request["profiles"]]
        jobs=[self.job(rid,n) for n in names]
        self.tables[rid]={"total_count":len(jobs),"jobs":jobs}
        self.ns["V5_STAGE_PINS"]["priorRunIds"].append(rid);self.request["priorRunIds"].append(rid)
        self.request.update(stageRound=2,lifetimeOperatorRound=9,profiles=["pipeline-contracts"])
        facts=self.check();self.assertEqual(facts["bookedRunnerMinutes"],1106)
        self.assertEqual(facts["operatorRoundsRemaining"],0)
        self.assertEqual(facts["futureTargetedReserveMinutes"],0)
        self.assertEqual(len(facts["firstSourceReceipts"]),2)
        self.history[rid]["status"]="in_progress"
        with self.assertRaisesRegex(Refusal,"prior_stage_terminal"):self.check()

    def test_positive_previous_hop_count_must_match_actual_prior_request(self):
        self.prior()
        hop={"sourceSha":"d"*40,"sourceTree":"e"*40,
             "step":{"parentSha":self.ns["V5_FIRST_SOURCE"],"parentTree":self.ns["V5_FIRST_TREE"],
                     "changedPaths":["test/v108-remediation-security.test.mjs"],"unchangedTreeSha256":"f"*64}}
        self.request["sourceWitness"]["correctionHops"]=[hop]
        pins=self.ns["V5_STAGE_PINS"];pins.update(sourceSha="d"*40,sourceTree="e"*40,
             manifestSha256="1"*64,inventorySha256="2"*64,
             sourceHops=[{"sourceSha":"d"*40,"sourceTree":"e"*40}],previousSourceHopCount=1)
        self.request.update(sourceSha="d"*40,sourceTree="e"*40,manifestSha256="1"*64,inventorySha256="2"*64)
        # Standalone request disallows count1 in round1 before history is reached.
        with self.assertRaisesRegex(ValueError,"previous_source_hop_count"):self.check()

    def test_current_attempt_boolean_and_unknown_runner_refuse(self):
        self.tables[CURRENT]["jobs"][0]["run_attempt"]=True
        with self.assertRaisesRegex(Refusal,"fresh_job_binding"):self.check()
        self.tables[CURRENT]["jobs"][0]["run_attempt"]=1
        self.tables[CURRENT]["jobs"][0]["labels"]=["self-hosted"]
        with self.assertRaisesRegex(Refusal,"current_public_admission"):self.check()

    def test_new_source_unexpanded_failure_invalidates_affected_old_successes(self):
        self.prior()  # Actual-shaped synthetic initial: all seven source84 gates passed.
        source,tree="d"*40,"e"*40
        hop={"sourceSha":source,"sourceTree":tree,
             "step":{"parentSha":self.ns["V5_FIRST_SOURCE"],"parentTree":self.ns["V5_FIRST_TREE"],
                     "changedPaths":["test/v108-remediation-security.test.mjs"],"unchangedTreeSha256":"f"*64}}
        pins=self.ns["V5_STAGE_PINS"]
        pins.update(sourceSha=source,sourceTree=tree,manifestSha256="1"*64,inventorySha256="2"*64,
                    sourceHops=[{"sourceSha":source,"sourceTree":tree}],previousSourceHopCount=0)
        self.request.update(sourceSha=source,sourceTree=tree,manifestSha256="1"*64,inventorySha256="2"*64)
        self.request["sourceWitness"]["correctionHops"]=[hop]
        self.workflow=self.workflow.replace(self.ns["V5_FIRST_SOURCE"].encode(),source.encode())
        (self.root/self.ns["WORKFLOW"]).write_bytes(self.workflow);self.source_tip=source
        rid,head="9000000097","f"*40
        raw=(json.dumps(self.request,sort_keys=True)+"\n").encode()
        self.contents[self.ns["REQUEST"]+"?ref="+head]=raw
        self.contents[self.ns["WORKFLOW"]+"?ref="+head]=self.workflow
        self.ns["V5_STAGE_RUN_PINS"].append({"runId":rid,"pipelineHead":head,"requestSha256":hashlib.sha256(raw).hexdigest()})
        self.history[rid]=self.run_record(rid,self.ns["WORKFLOW"],head=head)
        self.history[rid].update(created_at="2026-10-28T13:57:00Z",conclusion="failure")
        jobs=copy.deepcopy(next(r for r in self.prefix["runs"] if str(r["id"])=="40681376480")["jobs"])
        for j in jobs:j.update(run_id=int(rid),head_sha=head)
        self.tables[rid]={"total_count":3,"jobs":jobs}
        pins["priorRunIds"].append(rid);self.request["priorRunIds"].append(rid)
        pins["previousSourceHopCount"]=1
        self.request.update(stageRound=2,lifetimeOperatorRound=9,profiles=["pipeline-contracts"])
        with self.assertRaisesRegex(Refusal,"unresolved_prior_profiles_selected"):self.check()
        affected={"dependency","types-tests","compatibility","pipeline-contracts"}
        self.request["profiles"]=[p for p in self.ns["V5_PROFILES"] if p in affected]
        facts=self.check();self.assertEqual(set(facts["priorUnresolvedProfiles"]),affected)
        self.assertEqual(facts["priorStageProfileResults"]["doctor-1"],"success")
        self.assertEqual(set(facts["firstSourceReceipts"][1]["invalidatedPriorProfiles"]),affected)
        self.assertEqual(facts["firstSourceReceipts"][1]["profileResults"],{})
        self.assertFalse(facts["firstSourceReceipts"][0]["relabeledAsCurrentSourcePass"])

    def test_workflow_security_preserves_readonly_and_trigger_controls(self):
        p=self.root/self.ns["WORKFLOW"]
        for old,new in [(b"contents: read",b"contents: write"),(b"max-parallel: 3",b"max-parallel: 4"),
                        (b"timeout-minutes: 30",b"timeout-minutes: 31")]:
            p.write_bytes(self.workflow.replace(old,new,1))
            with self.assertRaises(Refusal):self.check()
            p.write_bytes(self.workflow)


if __name__=="__main__":unittest.main()
