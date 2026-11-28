"""Historical425 accounting and targeted successor round use the same original allowance."""
import base64
import copy
from datetime import datetime
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import test_source_validation_v108 as support

driver=support.driver


def content(raw):return {"type":"file","encoding":"base64","size":len(raw),"content":base64.b64encode(raw).decode()}


class RecoveryBudgetTests(unittest.TestCase):
    def setUp(self):
        self.pins=patch.multiple(driver,SOURCE=support.SOURCE,TREE=support.TREE,FIRST_SOURCE=support.SOURCE,FIRST_TREE=support.TREE)
        self.pins.start();self.addCleanup(self.pins.stop)
    def fixture(self,root):
        req=support.request(3,["types-tests"],[*driver.RETAINED_SOURCE_RUN_IDS,"998"])
        req,event,env,responses,api,runs,tables=support.history_fixture(root,req)
        prior=support.run_record("998",support.OLD_HEAD,driver.WORKFLOW,"failure")
        prior["created_at"]="2026-10-28T04:40:00Z";runs.insert(-1,prior)
        tables["998"]=support.source_jobs(legacy=False)
        first=support.request();first["settledUsageSha256"]=req["settledUsageSha256"]
        responses["/contents/"+driver.REQUEST+"?ref="+support.OLD_HEAD]=content(json.dumps(first).encode())
        responses["/contents/"+driver.WORKFLOW+"?ref="+support.OLD_HEAD]=content(b"frozen workflow")
        return req,event,env,responses,api,runs,tables
    def test_first_new_round_actual_usage_and_current_targeted_max_not_old_failures_refunded(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);req,event,env,responses,api,runs,tables=self.fixture(root)
            with patch.object(driver.subprocess,"run"),patch.object(driver,"datetime",wraps=datetime) as clock:
                clock.now.return_value=support.NOW;b=driver.history_checks(req,event,env,root,api)
            self.assertEqual(b["observedNewPriorRunnerMinutes"],17)
            self.assertEqual(b["bookedRunnerMinutes"],425+17+115+135)
            self.assertEqual(b["firstSourceReceipt"]["sourceSha"],support.SOURCE)
    def test_unsettled_prior_new_run_changed_workflow_old_source_or_extra_round_refuses(self):
        for mutation in ("running","workflow","source"):
            with tempfile.TemporaryDirectory() as directory:
                root=Path(directory);req,event,env,responses,api,runs,tables=self.fixture(root)
                if mutation=="running":next(r for r in runs if r["id"]==998)["status"]="in_progress"
                elif mutation=="workflow":responses["/contents/"+driver.WORKFLOW+"?ref="+support.OLD_HEAD]=content(b"changed permissions")
                else:
                    old=support.request();old["sourceSha"]="c"*40;old["firstSourceSha"]="c"*40;old["settledUsageSha256"]=req["settledUsageSha256"]
                    responses["/contents/"+driver.REQUEST+"?ref="+support.OLD_HEAD]=content(json.dumps(old).encode())
                with patch.object(driver.subprocess,"run"),patch.object(driver,"datetime",wraps=datetime) as clock:
                    clock.now.return_value=support.NOW
                    with self.assertRaises(driver.release.Refusal):driver.history_checks(req,event,env,root,api)
        bad=support.request();bad["round"]=4
        with self.assertRaises(driver.release.Refusal):driver.validate_request(bad)
    def test_witnessed_source_checkout_ref_change_is_only_allowed_workflow_delta(self):
        for drift in (False,True):
            with tempfile.TemporaryDirectory() as directory:
                root=Path(directory);req,event,env,responses,api,runs,tables=self.fixture(root)
                old=("ref: "+support.SOURCE+"\nref: "+support.SOURCE+"\npermissions: read\n").encode()
                current="c"*40;tree="f"*40
                new=old.replace(support.SOURCE.encode(),current.encode())
                if drift:new+=b"permissions: write\n"
                (root/driver.WORKFLOW).write_bytes(new)
                responses["/contents/"+driver.WORKFLOW+"?ref="+support.OLD_HEAD]=content(old)
                req.update(sourceSha=current,sourceTree=tree,
                    profiles=["types-tests","doctor-1","doctor-2","doctor-3"],
                    sourceWitness={"schema":"openclaw.v108.test-only-successor.v1",
                        "parentSha":support.SOURCE,"parentTree":support.TREE,
                        "changedPaths":["src/commands/doctor-config-preflight.process.test.ts"],
                        "unchangedTreeSha256":"f"*64})
                with patch.multiple(driver,SOURCE=current,TREE=tree),patch.object(driver.subprocess,"run"),patch.object(driver,"datetime",wraps=datetime) as clock:
                    clock.now.return_value=support.NOW
                    if drift:
                        with self.assertRaises(driver.release.Refusal):driver.history_checks(req,event,env,root,api)
                    else:
                        result=driver.history_checks(req,event,env,root,api)
                        self.assertEqual(result["firstSourceReceipt"]["sourceSha"],support.SOURCE)
                        self.assertFalse(result["firstSourceReceipt"]["relabeledAsCurrentSourcePass"])

    def test_prior_usage_snapshot_omission_or_wrong_digest_cannot_lower425(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);req,*_=support.history_fixture(root,support.request())
            value=json.loads((root/driver.SETTLED_USAGE).read_text());value["runs"].pop()
            (root/driver.SETTLED_USAGE).write_text(json.dumps(value))
            with self.assertRaises(driver.release.Refusal):driver.settled_usage(root,req)
    def test_zero_runner_cancellation_needs_explicit_fields_and_old_labels_are_not_new_fallback(self):
        table={"total_count":1,"jobs":[support.job("metadata",0,"cancelled",False)]}
        self.assertEqual(driver.observed_minutes(table,legacy=True),0)
        for name in ("runner_id","runner_name","steps"):
            bad=copy.deepcopy(table);bad["jobs"][0].pop(name)
            with self.assertRaises(driver.release.Refusal):driver.observed_minutes(bad,legacy=True)
        table={"total_count":1,"jobs":[support.job("metadata",1,legacy_label=True)]}
        self.assertEqual(driver.observed_minutes(table,legacy=True),1)
        with self.assertRaises(driver.release.Refusal):driver.observed_minutes(table,legacy=False)

if __name__=="__main__":unittest.main()
