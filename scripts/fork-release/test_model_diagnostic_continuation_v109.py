"""Closed second diagnostic controls; synthetic terminal states, never observations."""
from copy import deepcopy
from pathlib import Path
import unittest

import bounded_run_contract_v109 as grants
import model_diagnostic_v109 as model
import source_validation_contract_v109 as policy

HERE=Path(__file__).parent
FIRST_RAW=(HERE/"fixtures/v109-published-first-diagnostic-request.json").read_bytes()
SOURCE_RAW=(HERE/"fixtures/v109-h-diagnostic-source-request.json").read_bytes()
SOURCE=policy.parse(SOURCE_RAW)
NOW=policy.utc("2026-10-31T00:00:00Z").timestamp()
CURRENT="99900000001"  # Unit-test ID only; not an actual run or activation.


def selected():
    value=model.template_continuation()
    value.update(status="REVIEWED",routingMode="DIAGNOSTIC",reviewSha256="7"*64)
    return value


def native(rid,head,status="completed",conclusion="failure"):
    return {"id":int(rid),"run_attempt":1,"head_sha":head,"status":status,"conclusion":conclusion,
        "path":model.WORKFLOW,"name":model.CAMPAIGN,"display_title":model.CAMPAIGN,
        "head_branch":policy.PIPELINE_BRANCH,"event":"pull_request",
        "repository":{"full_name":policy.REPOSITORY,"private":False},
        "actor":{"login":"fr-meyer"},"triggering_actor":{"login":"fr-meyer"}}


def fixture():
    prior=policy.parse(FIRST_RAW);current=selected()
    rows=[(model.FIRST_DIAGNOSTIC["runId"],native(model.FIRST_DIAGNOSTIC["runId"],model.FIRST_DIAGNOSTIC["pipelineHead"]),prior,FIRST_RAW),
        (CURRENT,native(CURRENT,"c"*40,"in_progress",None),current,policy.encode(current))]
    grant={"bookedAdditionalAttempts":[{"runId":model.FIRST_DIAGNOSTIC["runId"],"nativeAttempt":1,"runnerMinutes":120}]}
    minutes={(model.FIRST_DIAGNOSTIC["runId"],1):100,(CURRENT,1):3}
    return rows,grant,minutes


class DiagnosticContinuationTests(unittest.TestCase):
    def test_disarmed_constructor_preserves_legacy_v1_without_creating_authority(self):
        self.assertEqual(policy.digest(FIRST_RAW),model.FIRST_DIAGNOSTIC["requestSha256"])
        old=policy.parse(FIRST_RAW);old.update(status="DISARMED",routingMode="SOURCE",reviewSha256=None)
        self.assertEqual(model.template(),old)
        second=model.template_continuation()
        self.assertEqual(model.validate(second,SOURCE_RAW),second)
        self.assertEqual(second["priorDiagnosticRun"],model.FIRST_DIAGNOSTIC)
        self.assertEqual(second["status"],"DISARMED");self.assertIsNone(second["reviewSha256"])
        self.assertNotIn("executionSequence",second)
        with self.assertRaises(policy.Refusal):model.validate(second,SOURCE_RAW,active=True,now=NOW)

    def test_only_exact_second_schema_prior_and_same_h_generation_are_accepted(self):
        model.validate(selected(),SOURCE_RAW,active=True,now=NOW)
        for key,value in (("schema",model.SCHEMA),("diagnosticId","model-cleanliness-r3"),("sourceSha","f"*40),
                ("generationSha256","f"*64),("sourceRequestSha256","f"*64),("profiles",["models-1"]),
                ("priorDiagnosticRun",{**model.FIRST_DIAGNOSTIC,"runId":"41079925427"})):
            changed=selected();changed[key]=value
            with self.subTest(key=key),self.assertRaises(policy.Refusal):model.validate(changed,SOURCE_RAW)
        legacy=policy.parse(FIRST_RAW);legacy["priorDiagnosticRun"]=dict(model.FIRST_DIAGNOSTIC)
        with self.assertRaises(policy.Refusal):model.validate(legacy,SOURCE_RAW)

    def test_positive_closed_continuation_is_pure_and_applies_no_second_debit(self):
        rows,grant,minutes=fixture();before=deepcopy((rows,grant,minutes))
        proof=model.once_current(rows,CURRENT,grant,minutes)
        self.assertTrue(proof["continuationOnly"]);self.assertEqual(proof["priorObservedMinutes"],100)
        self.assertEqual(proof["priorBookedMinutes"],120);self.assertEqual(proof["additionalChargeAppliedHere"],0)
        self.assertFalse(proof["sourceExecutionAdvanced"]);self.assertEqual((rows,grant,minutes),before)

    def test_active_or_missing_terminal_conclusion_refuses_without_retry(self):
        for status,conclusion in (("in_progress",None),("queued",None),("completed",None),("completed","unknown")):
            rows,grant,minutes=fixture();rows[0][1].update(status=status,conclusion=conclusion)
            with self.subTest(status=status,conclusion=conclusion),self.assertRaises(policy.Refusal):
                model.once_current(rows,CURRENT,grant,minutes)

    def test_wrong_head_native_attempt_or_identity_is_not_the_original_diagnostic(self):
        for key,value in (("head_sha","f"*40),("run_attempt",2),("run_attempt",True),("id",41079925427)):
            rows,grant,minutes=fixture();rows[0][1][key]=value
            with self.subTest(key=key,value=value),self.assertRaises(policy.Refusal):model.once_current(rows,CURRENT,grant,minutes)
        rows,grant,minutes=fixture();rows[1][1]["run_attempt"]=2
        with self.assertRaises(policy.Refusal):model.once_current(rows,CURRENT,grant,minutes)

    def test_exact_original_raw_bytes_and_value_pair_are_required(self):
        for change in ("space","value","missing","current"):
            rows,grant,minutes=fixture()
            if change=="space":rows[0]=(*rows[0][:3],FIRST_RAW+b" ")
            elif change=="value":rows[0][2]["reviewSha256"]="8"*64
            elif change=="missing":rows[0]=rows[0][:3]
            else:rows[1]=(*rows[1][:3],b"{}")
            with self.subTest(change=change),self.assertRaises(policy.Refusal):model.once_current(rows,CURRENT,grant,minutes)

    def test_prior_cost_must_be_explicitly_observed_and_genuinely_booked(self):
        for change in ("no-grant","no-booking","missing-observation","underbooked","wrong-native","duplicate","bool"):
            rows,grant,minutes=fixture()
            if change=="no-grant":grant=None
            elif change=="no-booking":grant["bookedAdditionalAttempts"]=[]
            elif change=="missing-observation":minutes.pop((model.FIRST_DIAGNOSTIC["runId"],1))
            elif change=="underbooked":grant["bookedAdditionalAttempts"][0]["runnerMinutes"]=99
            elif change=="wrong-native":grant["bookedAdditionalAttempts"][0]["nativeAttempt"]=2
            elif change=="duplicate":grant["bookedAdditionalAttempts"]*=2
            else:grant["bookedAdditionalAttempts"][0]["runnerMinutes"]=True
            with self.subTest(change=change),self.assertRaises(policy.Refusal):model.once_current(rows,CURRENT,grant,minutes)

    def test_missing_prior_duplicate_current_or_third_active_diagnostic_refuses(self):
        for change in ("missing","duplicate","third"):
            rows,grant,minutes=fixture()
            if change=="missing":rows.pop(0)
            elif change=="duplicate":rows.append(deepcopy(rows[1]))
            else:rows.append(("99900000002",native("99900000002","d"*40),selected(),policy.encode(selected())))
            with self.subTest(change=change),self.assertRaises(policy.Refusal):model.once_current(rows,CURRENT,grant,minutes)

    def test_legacy_three_tuple_single_route_and_reverse_hold_stay_accepted(self):
        old=policy.parse(FIRST_RAW);rid=model.FIRST_DIAGNOSTIC["runId"]
        rows=[(rid,native(rid,model.FIRST_DIAGNOSTIC["pipelineHead"]),old),
            ("99900000002",native("99900000002","d"*40),model.template())]
        self.assertIsNone(model.once_current(rows,rid))
        self.assertEqual(model.validate(old,SOURCE_RAW),old)

    def test_second_route_still_uses_original_failed_source_predecessor(self):
        source_run=native(model.PRIOR["runId"],model.PRIOR["pipelineHead"])
        source_run.update(path=policy.WORKFLOW,name=policy.CAMPAIGN,display_title=policy.CAMPAIGN)
        row=(model.PRIOR["runId"],source_run,SOURCE,SOURCE_RAW)
        self.assertEqual(model.predecessor([row],selected()),model.PRIOR["runId"])
        source_run["status"]="in_progress"
        with self.assertRaises(policy.Refusal):model.predecessor([row],selected())

    def test_budget_charges_old_attempt_once_and_keeps_full_future_reservations(self):
        rows,grant,minutes=fixture()
        minutes.update({(rid,1):1 if i<38 else 0 for i,rid in enumerate(grants.PREFIX_RUN_IDS)})
        model.once_current(rows,CURRENT,grant,minutes)
        charged,proof=model.budget(None,grant,minutes,CURRENT,3,selected())
        self.assertEqual(charged,38+120+3)
        self.assertEqual(proof["otherMinutesCharged"],38+120)
        self.assertEqual(proof["maximumNewMinutesBooked"],38+120+160+1075+180+50)
        self.assertEqual(proof["futureFull15Reserved"],1075);self.assertFalse(proof["sourceExecutionAdvanced"])


if __name__=="__main__":unittest.main()
