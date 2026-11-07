"""Runtime grant controls with synthetic plans/provider rows; no host/client work."""
from copy import deepcopy
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import bounded_run_contract_v109 as allowance
import source_validation_contract_v109 as policy
import source_validation_v109 as m


def setup(phase="lock-preparation",sequence=1):
    g={"sourceSha":"a"*40,"sourceTree":"b"*40}
    h={"sourceSha":"c"*40,"sourceTree":"d"*40}
    generation={"runId":"50000000001","pipelineHead":"e"*40}
    plan={"sequence":sequence,"phase":phase,"preparationAttempt":3,
        "source":deepcopy(g if phase=="lock-preparation"else h),
        "priorSourceRun":deepcopy(policy.SECOND_FAILED_PREPARATION_PIN),
        "reasonCode":"initial_recovery"if sequence==1 else"prior_failure",
        "reservations":{"current":45 if phase=="lock-preparation" else 1075,
            "pendingValidation":1075 if phase=="lock-preparation" else 0,"conditionalImage":180,"incidental":28}}
    grant={"authoritySha256":allowance.AUTHORITY_SHA256,"nextExecution":plan,"bookedAdditionalAttempts":[]}
    b={"ciRunGrant":grant,"preparation":g,"validation":{"source":h,"generation":generation}}
    q={"phase":phase,"preparationAttempt":3,"source":deepcopy(plan["source"]),
        "generation":None if phase=="lock-preparation"else deepcopy(generation),
        "executionSequence":sequence,"runAllowanceSha256":allowance.AUTHORITY_SHA256,
        "priorRunPins":[deepcopy(plan["priorSourceRun"])]}
    p=deepcopy(policy.SECOND_FAILED_PREPARATION_PIN)
    prior_q={"phase":"lock-preparation","preparationAttempt":2,"source":deepcopy(g),"generation":None,
        "priorRunPins":[deepcopy(policy.FAILED_PREPARATION_PIN)]}
    prior_raw=b"synthetic old second request"
    b["ciRunGrant"]["nextExecution"]["priorSourceRun"]=deepcopy(p)
    q["priorRunPins"]=[deepcopy(p)]
    rows=[(p["runId"],{"head_sha":p["pipelineHead"],"status":"completed","conclusion":"failure"},prior_q,prior_raw)]
    current="50000000001"
    rows.append((current,{"head_sha":"f"*40,"status":"in_progress","conclusion":None},q,b"synthetic current request"))
    return b,q,rows,current


def minute_rows():
    rows={(rid,1):0 for rid in allowance.PREFIX_RUN_IDS}
    rows[(allowance.PREFIX_RUN_IDS[0],1)]=38
    rows[("50000000001",1)]=1
    return rows


class BoundedRunRuntimeTests(unittest.TestCase):
    def setUp(self):
        # A fixed modeled old-content read, not an invented historical payload.
        # Real archived first/second requests are independently replayed by the
        # maintained failure-proof controls. Every other digest remains real.
        real=policy.digest
        self.digest_patch=patch.object(policy,"digest",side_effect=lambda raw:
            policy.SECOND_FAILED_PREPARATION_PIN["requestSha256"] if raw==b"synthetic old second request"else real(raw))
        self.digest_patch.start();self.addCleanup(self.digest_patch.stop)

    def test_initial_source_sequence_and_prior_terminal_identity(self):
        b,q,rows,current=setup()
        self.assertEqual(m.bounded_source_history(b,q,rows,current)["reviewedLogicalExecutions"],1)
        for field,value in (("status","in_progress"),("head_sha","0"*40),("conclusion",None)):
            changed=deepcopy(rows);changed[0][1][field]=value
            with self.subTest(field=field),self.assertRaises(policy.Refusal):
                m.bounded_source_history(b,q,changed,current)

    def test_sequence_duplicate_gap_future_or_wrong_current_refuses(self):
        b,q,rows,current=setup()
        cases=[rows+[deepcopy(rows[-1])],rows[:-1],deepcopy(rows),deepcopy(rows)]
        cases[2][-1][2]["executionSequence"]=2
        cases[3][-1]=(current+"1",*cases[3][-1][1:])
        for index,changed in enumerate(cases):
            with self.subTest(case=index),self.assertRaises(policy.Refusal):m.bounded_source_history(b,q,changed,current)

    def test_no_unsequenced_new_source_or_foreign_grant(self):
        b,q,rows,current=setup()
        changed=deepcopy(rows);del changed[-1][2]["executionSequence"]
        with self.assertRaisesRegex(policy.Refusal,"unsequenced_source"):m.bounded_source_history(b,q,changed,current)
        changed=deepcopy(rows);changed[-1][2]["runAllowanceSha256"]="0"*64
        with self.assertRaisesRegex(policy.Refusal,"source_sequence"):m.bounded_source_history(b,q,changed,current)

    def test_lock_retry_stays_original_source_and_never_claims_generation(self):
        b,q,rows,current=setup()
        for field,value in (("source",{"sourceSha":"0"*40}),("generation",{"runId":"7"})):
            changed=deepcopy(rows);changed[-1][2][field]=value
            with self.subTest(field=field),self.assertRaisesRegex(policy.Refusal,"unchanged_preparation_source"):
                m.bounded_source_history(b,q,changed,current)

    def test_validation_reuses_same_genuine_derived_generation(self):
        b,q,rows,current=setup("validation")
        b["ciRunGrant"]["nextExecution"]["reasonCode"]="reviewed_pipeline_correction"
        self.assertEqual(m.bounded_source_history(b,q,rows,current)["sourceExecutionSequence"],1)
        for field,value in (("source",{"sourceSha":"0"*40}),("generation",{"runId":"7"})):
            changed=deepcopy(rows);changed[-1][2][field]=value
            with self.subTest(field=field),self.assertRaisesRegex(policy.Refusal,"same_derived_source"):
                m.bounded_source_history(b,q,changed,current)

    def test_second_reviewed_retry_can_reuse_phase_attempt_after_terminal_failure(self):
        b,q,rows,current=setup()
        first=rows.pop();first[1].update(status="completed",conclusion="failure")
        rows.append(first)
        next_pin={"runId":first[0],"pipelineHead":first[1]["head_sha"],"requestSha256":policy.digest(first[3])}
        q=deepcopy(q);q["executionSequence"]=2;q["priorRunPins"]=[deepcopy(next_pin)]
        b["ciRunGrant"]["nextExecution"].update(sequence=2,priorSourceRun=deepcopy(next_pin),reasonCode="prior_failure")
        current="50000000002";rows.append((current,{"head_sha":"e"*40,"status":"in_progress","conclusion":None},q,b"next request"))
        self.assertEqual(m.bounded_source_history(b,q,rows,current)["reviewedLogicalExecutions"],2)
        rows[1][1]["conclusion"]="success"
        with self.assertRaisesRegex(policy.Refusal,"prior_failure"):m.bounded_source_history(b,q,rows,current)

    def test_generation_ready_requires_prior_successful_lock(self):
        b,q,rows,current=setup()
        first=rows.pop();first[1].update(status="completed",conclusion="success");rows.append(first)
        pin={"runId":first[0],"pipelineHead":first[1]["head_sha"],"requestSha256":policy.digest(first[3])}
        b["ciRunGrant"]["nextExecution"].update(sequence=2,phase="validation",source=deepcopy(b["validation"]["source"]),
            priorSourceRun=deepcopy(pin),reasonCode="generation_ready")
        q=deepcopy(q);q.update(executionSequence=2,phase="validation",source=deepcopy(b["validation"]["source"]),
            generation=deepcopy(b["validation"]["generation"]),priorRunPins=[deepcopy(pin)])
        current="50000000002";rows.append((current,{"head_sha":"e"*40,"status":"in_progress","conclusion":None},q,b"validation request"))
        self.assertEqual(m.bounded_source_history(b,q,rows,current)["reviewedLogicalExecutions"],2)
        rows[1][1]["conclusion"]="failure"
        with self.assertRaisesRegex(policy.Refusal,"generation_ready"):m.bounded_source_history(b,q,rows,current)

    def test_metadata_plan_ancestry_and_validation_generation_ancestry(self):
        for phase in ("lock-preparation","validation"):
            b,q,rows,current=setup(phase);calls=[]
            m.preparation_pipeline_ancestry(lambda *a:calls.append(a),"f"*40,q,b)
            expected=[("merge-base","--is-ancestor",b["ciRunGrant"]["nextExecution"]["priorSourceRun"]["pipelineHead"],"f"*40)]
            if phase=="validation":expected.append(("merge-base","--is-ancestor",q["generation"]["pipelineHead"],"f"*40))
            self.assertEqual(calls,expected)
            def wrong(*args):raise subprocess.CalledProcessError(1,["synthetic"])
            with self.assertRaisesRegex(policy.Refusal,"pipeline_ancestry"):m.preparation_pipeline_ancestry(wrong,"f"*40,q,b)

    def test_exact_closed_prefix_floor_and_full_initial_reservation(self):
        b,q,rows,current=setup();observed=minute_rows()
        total,facts=m.bounded_minute_booking(b["ciRunGrant"],observed,current,1)
        self.assertEqual(total,39);self.assertEqual(facts["prefixMinutesObserved"],38)
        self.assertEqual(facts["maximumNewMinutesBooked"],38+45+1075+180+28)
        observed[(allowance.PREFIX_RUN_IDS[0],1)]=37
        with self.assertRaisesRegex(policy.Refusal,"prefix_minute_floor"):m.bounded_minute_booking(b["ciRunGrant"],observed,current,1)
        del observed[(allowance.PREFIX_RUN_IDS[1],1)]
        with self.assertRaisesRegex(policy.Refusal,"prefix_minutes_missing"):m.bounded_minute_booking(b["ciRunGrant"],observed,current,1)

    def test_booked_minute_floors_apply_per_attempt_no_cross_attempt_refund(self):
        b,q,rows,current=setup();observed=minute_rows()
        observed[("50000000002",1)]=2;observed[("50000000003",1)]=10
        b["ciRunGrant"]["bookedAdditionalAttempts"]=[{"runId":"50000000002","nativeAttempt":1,"runnerMinutes":10},
            {"runId":"50000000003","nativeAttempt":1,"runnerMinutes":2}]
        total,facts=m.bounded_minute_booking(b["ciRunGrant"],observed,current,1)
        self.assertEqual(total,59)  # prefix38 + current1 + max(2,10) + max(10,2)
        self.assertTrue(facts["perAttemptBookedMinuteFloorsApplied"])
        del observed[("50000000002",1)]
        with self.assertRaisesRegex(policy.Refusal,"booked_minutes_missing"):m.bounded_minute_booking(b["ciRunGrant"],observed,current,1)

    def test_budget_overflow_and_current_elapsed_cap_refuse(self):
        b,q,rows,current=setup();observed=minute_rows();observed[("50000000002",1)]=1500
        with self.assertRaisesRegex(ValueError,"cumulative_runner_budget"):m.bounded_minute_booking(b["ciRunGrant"],observed,current,1)
        observed=minute_rows();observed[(current,1)]=46
        with self.assertRaisesRegex(ValueError,"current_phase_cap"):m.bounded_minute_booking(b["ciRunGrant"],observed,current,46)

    def test_native_rerun_count_is_emitted_before_fresh_native_gate(self):
        b,q,rows,current=setup()
        history={rid:{"id":int(rid),"run_attempt":1}for rid in allowance.PREFIX_RUN_IDS}
        history[current]={"id":int(current),"run_attempt":3}
        resolver=types.SimpleNamespace(resolve_baseline_258=lambda *args:{"runs":[]})
        with patch.object(m,"history_rows",return_value=history),patch.object(m,"regular",return_value=b"pinned fixture"),\
             patch.object(m,"closed_baseline",side_effect=AssertionError("must account before header validation")),\
             patch.object(m,"public_run",side_effect=AssertionError("must not reach public_run before accounting")),patch.object(m,"emit")as emitted:
            with self.assertRaisesRegex(policy.Refusal,"attempt_observation"):
                m.history_checks(Path("/synthetic"),b,q,b"q","f"*40,{}, {"GITHUB_RUN_ID":current},None,resolver,0)
        value=emitted.call_args.args[0]
        self.assertEqual(value["additionalAttemptCount"],3);self.assertEqual(value["stageAttemptCount"],45)
        self.assertEqual(value["unsupportedNativeReruns"],[current])

    def test_historical_rerun_is_emitted_before_unchanged_header_refusal(self):
        b,q,rows,current=setup();historical="40616416909"
        history={rid:{"id":int(rid),"run_attempt":1}for rid in allowance.PREFIX_RUN_IDS}
        history[current]={"id":int(current),"run_attempt":1}
        history[historical]={"id":int(historical),"run_attempt":2}
        resolver=types.SimpleNamespace(resolve_baseline_258=lambda *args:{"runs":[{"id":int(historical)}]})
        with patch.object(m,"history_rows",return_value=history),patch.object(m,"regular",return_value=b"pinned fixture"),\
             patch.object(m,"closed_baseline",side_effect=AssertionError("must account first"))as header,patch.object(m,"emit")as emitted:
            with self.assertRaisesRegex(policy.Refusal,"attempt_observation"):
                m.history_checks(Path("/synthetic"),b,q,b"q","f"*40,{}, {"GITHUB_RUN_ID":current},None,resolver,0)
        header.assert_not_called()
        value=emitted.call_args.args[0]
        self.assertEqual(value["additionalAttemptCount"],2)
        self.assertEqual(value["stageAttemptCount"],44)
        self.assertEqual(value["unsupportedNativeReruns"],[historical])

    def test_complete_historical_header_gate_remains_after_supported_count(self):
        b,q,rows,current=setup();historical="40616416909"
        history={rid:{"id":int(rid),"run_attempt":1}for rid in allowance.PREFIX_RUN_IDS}
        history[current]={"id":int(current),"run_attempt":1}
        history[historical]={"id":int(historical),"run_attempt":1}
        resolver=types.SimpleNamespace(resolve_baseline_258=lambda *args:{"runs":[{"id":int(historical)}]})
        with patch.object(m,"history_rows",return_value=history),patch.object(m,"regular",return_value=b"pinned fixture"),\
             patch.object(m,"closed_baseline",side_effect=policy.Refusal("v9.closed_provider_header_changed"))as header,\
             patch.object(m,"emit")as emitted:
            with self.assertRaisesRegex(policy.Refusal,"closed_provider_header_changed"):
                m.history_checks(Path("/synthetic"),b,q,b"q","f"*40,{}, {"GITHUB_RUN_ID":current},None,resolver,0)
        header.assert_called_once()
        self.assertEqual(emitted.call_args.args[0]["additionalAttemptCount"],1)

    def test_only_fixed_owned_refusal_codes_are_projected(self):
        self.assertEqual(m.safe_refusal_code(allowance.Refusal("v9.run_grant_fields")),"v9.run_grant_fields")
        self.assertEqual(m.safe_refusal_code(policy.Refusal("v9.closed_request")),"v9.closed_request")
        for error in (ValueError("v9.run_grant_fields"),allowance.Refusal("v9.run_grant.private"),
                      allowance.Refusal("private synthetic diagnostic value")):
            with self.subTest(error_type=type(error).__name__):
                self.assertEqual(m.safe_refusal_code(error),"v9.runtime_refused")


if __name__=="__main__":unittest.main()
