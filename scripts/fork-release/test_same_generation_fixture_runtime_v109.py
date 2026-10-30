"""Pure runtime composition tests, never an H2 candidate or provider observation.

The policy seam models its separately tested positive closed-variant validator.
The actual runtime AST is exercised with explicitly synthetic requests/rows.
No application, subprocess, Git, SDK, client or network operation is performed.
"""
import ast
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import types
import unittest

PATH=Path(__file__).with_name("source_validation_v109.py")
FUNCTIONS={"preparation_pipeline_ancestry","bounded_source_history","source_result"}
TREE=ast.parse(PATH.read_text())
H="edd010829dcb622d7dc60dc90f7097048cb78819"
H_RUN="41052090949"
H_PIPELINE="3722c8935ded3b3e249054fe6db2f3a50def8b8c"
PROFILES=("dependency","types-production","types-tests","types-scripts","workboard-1","workboard-2",
    "models-1","models-2","sqlite","doctor-1","doctor-2","doctor-3","memory","pipeline-contracts","compatibility")


class Refusal(RuntimeError):pass


def need(value,code):
    if not value:raise Refusal(code)


def encode(value):return json.dumps(value,sort_keys=True,separators=(",",":")).encode()
def digest(raw):return hashlib.sha256(raw).hexdigest()


def runtime():
    m=types.ModuleType("actual_same_generation_runtime_under_test")
    m.subprocess=subprocess
    m.policy=types.SimpleNamespace(need=need,Refusal=Refusal,digest=digest,
        run_grant=lambda b:b.get("ciRunGrant"),same_generation_fixture_correction=lambda b:b.get("fixtureCaseValidated")is True,
        FAILED_PREPARATION_PIN={"runId":"40997868140"},SECOND_FAILED_PREPARATION_PIN={
            "runId":"41003661031","pipelineHead":"1"*40,"requestSha256":digest(b"synthetic second failure request")},
        REPOSITORY="fr-meyer/openclaw",CAMPAIGN="future-v109-grouped-validation-20261030",PROFILES=PROFILES)
    m.TERMINAL=frozenset(("success","failure","neutral","cancelled","skipped","timed_out",
        "action_required","stale","startup_failure"))
    m.RESULT_SCHEMA="openclaw.v109.source-validation-result.v1"
    nodes=[node for node in TREE.body if isinstance(node,ast.FunctionDef)and node.name in FUNCTIONS]
    assert {n.name for n in nodes}==FUNCTIONS
    exec(compile(ast.Module(body=nodes,type_ignores=[]),str(PATH),"exec"),m.__dict__)
    return m


def pin(row):return {"runId":row[0],"pipelineHead":row[1]["head_sha"],"requestSha256":digest(row[3])}


def fixture():
    m=runtime()
    g={"sourceSha":"g"*40,"sourceTree":"a"*40,"manifestSha256":"1"*64,"inventorySha256":"2"*64}
    h={"sourceSha":H,"sourceTree":"b"*40,"manifestSha256":"3"*64,"inventorySha256":"4"*64}
    # A symbolic unit-test H2 only; no real candidate, commit or binding exists.
    h2={"sourceSha":"2"*40,"sourceTree":"c"*40,"manifestSha256":"5"*64,"inventorySha256":"6"*64}
    generation={"runId":"41043479025","pipelineHead":"8"*40,"artifactId":12972087389,
        "receiptSha256":"7"*64}
    authority="801209d1bbbd51b5dd315f7c9367aacc4f12cf15430c23a0f46775d568ccf532"
    b={"fixtureCaseValidated":True,"preparation":g,"validation":{"source":h,"generation":generation,"preparationAttempt":6},
        "ciRunGrant":{"authoritySha256":authority,"nextExecution":{}},"correction":{
            "source":h2,"parentSource":H,"generation":deepcopy(generation),"preparationAttempt":6}}
    old=m.policy.SECOND_FAILED_PREPARATION_PIN
    rows=[(old["runId"],{"head_sha":old["pipelineHead"],"status":"completed","conclusion":"failure"},
        {"phase":"lock-preparation"},b"synthetic second failure request")]
    for sequence in range(1,7):
        phase="lock-preparation"if sequence<=4 else"validation"if sequence==5 else"correction"
        source=g if sequence<=4 else h if sequence==5 else h2
        request={"phase":phase,"preparationAttempt":sequence+2 if sequence<=4 else 6,"source":deepcopy(source),
            "generation":None if sequence<=4 else deepcopy(generation),"executionSequence":sequence,
            "runAllowanceSha256":authority,"priorRunPins":[pin(rows[-1])],"profiles":[]if sequence<=4 else list(PROFILES)}
        rid=str(42000000000+sequence)
        if sequence==4:rid=generation["runId"]
        if sequence==5:rid=H_RUN
        head=H_PIPELINE if sequence==5 else str(sequence)*40
        status="in_progress"if sequence==6 else"completed"
        conclusion=None if sequence==6 else"success"if sequence==4 else"failure"
        rows.append((rid,{"head_sha":head,"status":status,"conclusion":conclusion},request,encode(request)))
    b["correction"]["priorValidation"]=pin(rows[5])
    request=rows[-1][2]
    b["ciRunGrant"]["nextExecution"]={"sequence":6,"phase":"correction","preparationAttempt":6,
        "priorSourceRun":pin(rows[-2]),"reasonCode":"prior_failure"}
    return m,b,rows,request,rows[-1][0]


def retry(m,b,rows):
    rows[-1][1].update(status="completed",conclusion="failure")
    request=deepcopy(rows[-1][2]);request.update(executionSequence=7,priorRunPins=[pin(rows[-1])])
    current="42000000007"
    rows.append((current,{"head_sha":"7"*40,"status":"in_progress","conclusion":None},request,encode(request)))
    b["ciRunGrant"]["nextExecution"].update(sequence=7,priorSourceRun=pin(rows[-2]))
    return request,current


class SameGenerationFixtureRuntimeTests(unittest.TestCase):
    def test_actual_prep6_history_keeps_original_h_and_accepts_only_bound_h2(self):
        m,b,rows,q,current=fixture();before=deepcopy((b,rows,q))
        result=m.bounded_source_history(b,q,rows,current)
        self.assertTrue(result["sameGenerationFixtureCorrection"])
        self.assertEqual(result["correctedApplicationCandidates"],1)
        self.assertEqual(result["sameCorrectedCandidateExecutions"],1)
        self.assertEqual(rows[5][2]["source"],b["validation"]["source"])
        self.assertEqual((b,rows,q),before)

    def test_active_success_cancel_timeout_or_skipped_h_never_authorizes_first_correction(self):
        for status,conclusion in (("in_progress",None),("completed","success"),("completed","cancelled"),
                ("completed","timed_out"),("completed","skipped")):
            m,b,rows,q,current=fixture();rows[5][1].update(status=status,conclusion=conclusion)
            with self.subTest(status=status,conclusion=conclusion),self.assertRaises(Refusal):
                m.bounded_source_history(b,q,rows,current)

    def test_missing_or_different_h_prior_pin_refuses(self):
        for change in ("missing","runId","head","request"):
            m,b,rows,q,current=fixture()
            if change=="missing":del rows[5]
            elif change=="runId":b["correction"]["priorValidation"]["runId"]="41052090950"
            elif change=="head":b["correction"]["priorValidation"]["pipelineHead"]="0"*40
            else:b["correction"]["priorValidation"]["requestSha256"]="0"*64
            with self.subTest(change=change),self.assertRaises(Refusal):m.bounded_source_history(b,q,rows,current)

    def test_failed_preparation_is_not_failed_h_validation(self):
        m,b,rows,q,current=fixture()
        rows[5][2].update(phase="lock-preparation",source=deepcopy(b["preparation"]),generation=None)
        rows[5]=(rows[5][0],rows[5][1],rows[5][2],encode(rows[5][2]))
        b["correction"]["priorValidation"]=pin(rows[5]);q["priorRunPins"]=[pin(rows[5])]
        b["ciRunGrant"]["nextExecution"]["priorSourceRun"]=pin(rows[5])
        with self.assertRaisesRegex(Refusal,"failed_validation"):m.bounded_source_history(b,q,rows,current)

    def test_unbound_branch_fake_prep1_prep7_or_changed_generation_refuses(self):
        for change in ("unbound","prep1","prep7","generation"):
            m,b,rows,q,current=fixture()
            if change=="unbound":b["fixtureCaseValidated"]=False
            elif change=="generation":q["generation"]["artifactId"]+=1
            else:q["preparationAttempt"]=1 if change=="prep1" else 7
            with self.subTest(change=change),self.assertRaises(Refusal):m.bounded_source_history(b,q,rows,current)

    def test_historical_h_request_is_not_rewritten_as_h2(self):
        m,b,rows,q,current=fixture();rows[5][2]["source"]=deepcopy(b["correction"]["source"])
        with self.assertRaisesRegex(Refusal,"same_derived_source"):m.bounded_source_history(b,q,rows,current)

    def test_later_pipeline_only_retry_reuses_one_same_corrected_candidate(self):
        m,b,rows,q,current=fixture();q,current=retry(m,b,rows)
        result=m.bounded_source_history(b,q,rows,current)
        self.assertEqual(result["correctedApplicationCandidates"],1)
        self.assertEqual(result["sameCorrectedCandidateExecutions"],2)

    def test_h3_or_rebinding_correction_record_cannot_replace_h2(self):
        for rebind in (False,True):
            m,b,rows,q,current=fixture();q,current=retry(m,b,rows)
            q["source"]["sourceSha"]="3"*40
            if rebind:b["correction"]["source"]=deepcopy(q["source"])
            with self.subTest(rebind=rebind),self.assertRaises(Refusal):m.bounded_source_history(b,q,rows,current)

    def test_no_later_h_or_new_lock_after_first_h2_correction(self):
        for phase in ("validation","lock-preparation"):
            m,b,rows,q,current=fixture();q,current=retry(m,b,rows)
            q.update(phase=phase,source=deepcopy(b["validation"]["source"]if phase=="validation"else b["preparation"]),
                generation=deepcopy(b["validation"]["generation"])if phase=="validation"else None)
            with self.subTest(phase=phase),self.assertRaisesRegex(Refusal,"no_source_rebind"):
                m.bounded_source_history(b,q,rows,current)

    def test_skipped_reordered_or_duplicate_sequence_refuses(self):
        for change in ("skip","reorder","duplicate"):
            m,b,rows,q,current=fixture()
            if change=="skip":del rows[3]
            elif change=="reorder":rows[3][2]["executionSequence"],rows[4][2]["executionSequence"]=4,3
            else:rows.append(deepcopy(rows[-1]))
            with self.subTest(change=change),self.assertRaises(Refusal):m.bounded_source_history(b,q,rows,current)

    def test_correction_requires_both_prior_pipeline_and_same_generation_ancestry(self):
        m,b,rows,q,current=fixture();calls=[]
        m.preparation_pipeline_ancestry(lambda *a:calls.append(a),"9"*40,q,b)
        self.assertEqual(calls,[("merge-base","--is-ancestor",H_PIPELINE,"9"*40),
            ("merge-base","--is-ancestor",q["generation"]["pipelineHead"],"9"*40)])
        for failure_index in (1,2):
            calls=[]
            def read(*args):
                calls.append(args)
                if len(calls)==failure_index:raise subprocess.CalledProcessError(1,["synthetic metadata"])
            with self.subTest(failure_index=failure_index),self.assertRaisesRegex(Refusal,"pipeline_ancestry"):
                m.preparation_pipeline_ancestry(read,"9"*40,q,b)

    def test_unbound_correction_never_reaches_generation_ancestry(self):
        m,b,rows,q,current=fixture();b["fixtureCaseValidated"]=False;calls=[]
        with self.assertRaisesRegex(Refusal,"correction_not_bound"):
            m.preparation_pipeline_ancestry(lambda *a:calls.append(a),"9"*40,q,b)
        self.assertEqual(len(calls),1)

    def test_preceding_original_h_validation_and_g_history_remain_valid(self):
        m,b,rows,q,current=fixture();b["fixtureCaseValidated"]=False;rows=rows[:-1]
        rows[-1][1].update(status="in_progress",conclusion=None);q=rows[-1][2];current=rows[-1][0]
        b["ciRunGrant"]["nextExecution"].update(sequence=5,phase="validation",priorSourceRun=pin(rows[-2]),reasonCode="generation_ready")
        result=m.bounded_source_history(b,q,rows,current)
        self.assertFalse(result["sameGenerationFixtureCorrection"])
        self.assertEqual(result["correctedApplicationCandidates"],0)

    def test_correction_result_still_requires_all_fifteen_and_cannot_hide_failure(self):
        m,b,rows,q,current=fixture()
        for outcome,expected in (("success","passed"),("failure","failed"),("cancelled","failed"),("skipped","failed")):
            value=m.source_result(q,encode(q),{"GITHUB_RUN_ID":current},"9"*40,"success",outcome)
            self.assertEqual(value["status"],expected);self.assertEqual(value["selectedProfiles"],list(PROFILES))
            self.assertEqual(value["sourceSha"],b["correction"]["source"]["sourceSha"])
            self.assertTrue(value["all15Required"]);self.assertFalse(value["historicalCoverageReused"])
            self.assertFalse(value["imageBuilt"]);self.assertFalse(value["productionAuthorized"])


if __name__=="__main__":unittest.main()
