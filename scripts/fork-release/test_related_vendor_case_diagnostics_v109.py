"""Focused finite per-case diagnostics; synthetic inputs, no package execution."""
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import json
import tempfile
import unittest
from unittest.mock import patch
import npm_vendor_derivation_v109 as v
import source_validation_v109 as controller
import source_validation_contract_v109 as p


def need(value,code):
    if not value:raise ValueError(code)
def encoded(value):return (json.dumps(value,indent=2)+"\n").encode()

def failed_receipt(legacy=False):
    cases=[{"name":name,"passed":True} for name in v.PACKAGE_CASE_NAMES]
    operations=("consumers.cli_version","pack.root_cli","global.install")
    for index,operation in zip((49,50,51),operations):
        cases[index]={"name":v.PACKAGE_CASE_NAMES[index],"passed":False,"code":"MODULE_NOT_FOUND","assertion":{"operator":"strictEqual","actual":1,"expected":0}}
        if not legacy:cases[index].update(operation=operation,cause={"name":{"state":"recognized","value":"TimeoutError"},"code":{"state":"recognized","value":"MODULE_NOT_FOUND"},"ownerReason":{"state":"recognized","value":"delivery.global_prefix"}})
    return {"schema":"openclaw.npm-glob-vendor-qualification.v1","status":"failed","phase":"actual_package_tests","reason":"npm-vendor.qualification_package_tests_failed",
        "packageExecuted":True,"imageTested":False,"actualBunRuntimeTested":False,
        "exceptionCause":{"name":{"state":"recognized","value":"Error"},"code":{"state":"absent"}},
        "tests":{"schema":"openclaw.npm-vendor-actual-package-tests.v1","passed":False,"caseCount":52,"passedCount":49,"cases":cases,
            "packageExecutionHost":"ci-only","imageTested":False,"publicPackTested":False,"actualBunRuntimeTested":False}}


class RelatedCaseDiagnosticTests(unittest.TestCase):
    def test_exact_case_vocabulary_is_distinct_from_top_level_exception(self):
        self.assertEqual((len(v.CASE_OPERATIONS),len(v.CASE_ERROR_NAMES),len(v.CASE_ERROR_CODES),len(v.CASE_OWNER_REASONS)),(53,11,28,60))
        self.assertIn("TimeoutError",v.CASE_ERROR_NAMES);self.assertNotIn("TimeoutError",v.EXCEPTION_NAMES)
        self.assertIn("MODULE_NOT_FOUND",v.CASE_ERROR_CODES);self.assertNotIn("MODULE_NOT_FOUND",v.EXCEPTION_CODES)
        cause=failed_receipt()["tests"]["cases"][49]["cause"]
        self.assertEqual(v.failed_case_cause(cause),cause)
        with self.assertRaises(ValueError):v.exception_cause({"name":cause["name"],"code":cause["code"]},need)

    def test_actual49of52_operation_owner_cause_and_assertions_are_retained(self):
        result=v.failed_qualification_projection(encoded(failed_receipt()),need)["packageTests"]
        self.assertEqual(result["state"],"available");self.assertEqual(result["counters"],{"caseCount":52,"passedCount":49,"failedCount":3})
        self.assertEqual([row["index"] for row in result["failedCases"]],[50,51,52])
        self.assertEqual([row["operation"] for row in result["failedCases"]],["consumers.cli_version","pack.root_cli","global.install"])
        for row in result["failedCases"]:
            self.assertEqual(row["cause"]["ownerReason"],{"state":"recognized","value":"delivery.global_prefix"})
            self.assertEqual(row["assertion"],{"operator":"strictEqual","actual":1,"expected":0})
            self.assertEqual(row["code"],{"state":"recognized","value":"MODULE_NOT_FOUND"})

    def test_legacy_gen2_rows_report_missing_without_invented_cause(self):
        result=v.failed_package_test_details(failed_receipt(legacy=True))
        self.assertEqual(result["state"],"available")
        for row in result["failedCases"]:
            self.assertEqual(row["operationState"],"missing");self.assertEqual(row["causeState"],"missing")
            self.assertNotIn("operation",row);self.assertNotIn("cause",row)

    def test_absent_and_unrecognized_fields_remain_explicit(self):
        value=failed_receipt();cause=value["tests"]["cases"][49]["cause"]
        cause.update(name={"state":"absent"},code={"state":"unrecognized"},ownerReason={"state":"unrecognized"})
        result=v.failed_package_test_details(value)
        self.assertEqual(result["failedCases"][0]["cause"],cause)
        value["tests"]["cases"][49]["cause"]=None
        self.assertEqual(v.failed_package_test_details(value)["reason"],"case_cause")

    def test_private_unknown_values_never_escape_the_strict_envelope(self):
        mutations=[lambda row:row.update(operation="PRIVATE /path/token"),lambda row:row["cause"].update(ownerReason={"state":"recognized","value":"PRIVATE owner"}),
            lambda row:row["cause"].update(code={"state":"recognized","value":"PRIVATE code"}),lambda row:row["cause"].update(name={"state":"unrecognized","value":"PRIVATE name"}),
            lambda row:row["cause"].update(rawMessage="PRIVATE message"),lambda row:row.update(cause={"name":{"state":"absent"},"code":{"state":"absent"}})]
        for mutate in mutations:
            value=failed_receipt();mutate(value["tests"]["cases"][49]);result=v.failed_package_test_details(value)
            self.assertEqual(result["state"],"invalid");self.assertNotIn("PRIVATE",json.dumps(result));self.assertNotIn("/path/",json.dumps(result))

    def test_exact_qualification_control26_and_pass_gate_unchanged(self):
        record={"schema":v.SCHEMA,"sourceGeneration":3,"workspaceSha256":"a"*64,"patchSha256":"b"*64,"proofSha256":"c"*64,"producerRuntimeSha256":"d"*64}
        receipt={"schema":"openclaw.npm-glob-vendor-qualification.v1","status":"passed","phase":"complete","reason":"all_52_cases_passed","packageExecuted":True,
            "imageTested":False,"actualBunRuntimeTested":False,"proofSha256":record["proofSha256"],"patchSha256":record["patchSha256"],"originalSha256":v.ORIGINAL_SHA256,
            "derivedSha256":"e"*64,"packageExecutionAttempted":True,"testResultEvidence":{"file":"npm-vendor-actual-test-result.private.json","bytes":1,"sha256":"f"*64,"storedBytes":1,"storedSha256":"f"*64,"truncated":False,"limitBytes":131072},
            "tests":{"schema":"openclaw.npm-vendor-actual-package-tests.v1","passed":True,"caseCount":52,"passedCount":52,"cases":[{"name":name,"passed":True} for name in v.PACKAGE_CASE_NAMES],
                "packageExecutionHost":"ci-only","imageTested":False,"publicPackTested":True,"actualBunRuntimeTested":False}}
        evidence={"schema":"openclaw.v109.npm-vendor-qualification-evidence.v1","qualifierRuntimeSha256":"d"*64,"receiptSha256":v.digest(encoded(receipt)),"receipt":receipt,
            "controls":[{"path":name,"runtimeSha256":"a"*64,"receiptSha256":"b"*64,"caseCount":count,"passedCount":count,"exitCode":0,"timedOut":False,"cleanupSettled":True} for name,count in v.CONTROL_TESTS]}
        self.assertEqual([count for _,count in v.CONTROL_TESTS],[30,26]);self.assertIs(v.validate_qualification(evidence,record,need),evidence)
        wrong=deepcopy(evidence);wrong["controls"][1].update(caseCount=22,passedCount=22)
        with self.assertRaises(ValueError):v.validate_qualification(wrong,record,need)
        wrong=deepcopy(evidence);wrong["receipt"]["tests"]["cases"][0].update(operation="case.entry");wrong["receiptSha256"]=v.digest(encoded(wrong["receipt"]))
        with self.assertRaises(ValueError):v.validate_qualification(wrong,record,need)

    def test_existing_failure_file_and_stdout_carry_only_validated_new_fields(self):
        with tempfile.TemporaryDirectory() as temporary:
            home=Path(temporary).resolve();source=home/"source";source.mkdir()
            for name in [v.QUALIFIER]+[name for name,_ in v.CONTROL_TESTS]:
                path=source/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b"reviewed-source")
            def phase(argv,cwd,environment,context,operation,ordinal):
                if operation=="vendor-controls":
                    target=Path(next(value.split("=",1)[1] for value in argv if value.startswith("--test-reporter-destination=")))
                    count=v.CONTROL_TESTS[ordinal][1];target.write_text("TAP version 13\n"+"".join("# %s %s\n"%(k,n) for k,n in (("tests",count),("pass",count),("fail",0),("cancelled",0),("skipped",0),("todo",0))))
                if operation=="vendor-actual-qualification":Path(argv[-1]).write_bytes(encoded(failed_receipt()))
                return SimpleNamespace(returncode=1 if operation=="vendor-actual-qualification" else 0,timed_out=False,cleanup_settled=True)
            record={"schema":v.SCHEMA,"sourceGeneration":3,"workspaceSha256":"a"*64,"patchSha256":"b"*64,"proofSha256":"c"*64,"producerRuntimeSha256":"d"*64}
            args=(source,record,{"original":home/"original","derived":home/"derived"},{"RUNNER_TEMP":str(home/"runner")},SimpleNamespace(phase_process=phase),{}, {"CI":"true"},home)
            with patch.object(controller,"emit") as output,self.assertRaisesRegex(ValueError,"actual_qualification_failed"):controller.qualify_npm_vendor(*args)
            safe=p.parse((home/"runner/v109-lock-diagnostic/vendor-qualification.safe.json").read_bytes())
            self.assertEqual(safe["packageTests"]["failedCases"][1]["operation"],"pack.root_cli")
            self.assertEqual(safe["packageTests"]["failedCases"][2]["cause"]["ownerReason"]["value"],"delivery.global_prefix")
            self.assertEqual(output.call_args.args[0],safe);self.assertFalse(safe["qualificationAccepted"])
            self.assertNotIn("rawMessage",json.dumps(safe))


if __name__=="__main__":unittest.main()
