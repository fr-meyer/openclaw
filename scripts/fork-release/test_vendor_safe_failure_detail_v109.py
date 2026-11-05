"""Safe failed-case/footer diagnostics only; no package or network execution."""
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


def receipt():
    cases=[{"name":name,"passed":True} for name in v.PACKAGE_CASE_NAMES]
    for index in (0,51):cases[index]={"name":v.PACKAGE_CASE_NAMES[index],"passed":False,"code":"ERR_ASSERTION","assertion":{"operator":"strictEqual","actual":2,"expected":0}}
    tests={"schema":"openclaw.npm-vendor-actual-package-tests.v1","passed":False,"caseCount":52,"passedCount":50,"cases":cases,
        "packageExecutionHost":"ci-only","imageTested":False,"publicPackTested":False,"actualBunRuntimeTested":False}
    return {"schema":"openclaw.npm-glob-vendor-qualification.v1","status":"failed","phase":"actual_package_tests","reason":"npm-vendor.qualification_package_tests_failed",
        "packageExecuted":True,"imageTested":False,"actualBunRuntimeTested":False,"tests":tests,
        "exceptionCause":{"name":{"state":"recognized","value":"Error"},"code":{"state":"absent"}}}


def encoded(value):return (json.dumps(value,indent=2)+"\n").encode()
def need(value,code):
    if not value:raise ValueError(code)


def tap(count,fail=0):
    return ("TAP version 13\n"+("not ok 2 - PRIVATE MESSAGE /path/environment\n" if fail else "ok 1 - PRIVATE TEST NAME\n")+
        "".join("# %s %s\n"%(key,value) for key,value in (("tests",count),("pass",count-fail),("fail",fail),("cancelled",0),("skipped",0),("todo",0)))).encode()


class SafeVendorFailureDetailTests(unittest.TestCase):
    def test_actual52_failed_indices_names_counters_numeric_assertions_survive(self):
        result=v.failed_qualification_projection(encoded(receipt()),need)["packageTests"]
        self.assertEqual(result["state"],"available")
        self.assertEqual(result["counters"],{"caseCount":52,"passedCount":50,"failedCount":2})
        self.assertEqual([row["index"] for row in result["failedCases"]],[1,52])
        self.assertEqual([row["name"] for row in result["failedCases"]],[v.PACKAGE_CASE_NAMES[0],v.PACKAGE_CASE_NAMES[51]])
        self.assertEqual(result["failedCases"][0]["assertion"],{"operator":"strictEqual","actual":2,"expected":0})

    def test_missing_and_invalid_tests_are_distinct(self):
        value=receipt();value.pop("tests");self.assertEqual(v.failed_package_test_details(value),{"state":"missing"})
        value["tests"]=None;self.assertEqual(v.failed_package_test_details(value)["state"],"invalid")
        value=receipt();value["tests"]["passedCount"]=False
        self.assertEqual(v.failed_package_test_details(value)["reason"],"counter_shape")

    def test_unknown_private_case_and_assertion_values_are_never_echoed(self):
        mutations=[lambda x:x["tests"]["cases"][0].update(name="PRIVATE SECRET NAME"),
            lambda x:x["tests"]["cases"][0]["assertion"].update(operator="PRIVATE OPERATOR"),
            lambda x:x["tests"]["cases"][0]["assertion"].update(actual="PRIVATE NUMBER"),
            lambda x:x["tests"]["cases"][0].update(message="PRIVATE MESSAGE"),
            lambda x:x["tests"]["cases"][0]["assertion"].update(operator={"PRIVATE":"object"}),
            lambda x:x["tests"]["cases"][0]["assertion"].update(actual=float("inf"))]
        for mutate in mutations:
            value=receipt();mutate(value);result=v.failed_package_test_details(value)
            self.assertEqual(result["state"],"invalid")
            self.assertNotIn("PRIVATE",json.dumps(result));self.assertNotIn("Infinity",json.dumps(result))
        value=receipt();value["tests"]["cases"][0]["code"]="PRIVATE ERROR CODE"
        result=v.failed_package_test_details(value)
        self.assertEqual(result["failedCases"][0]["code"],{"state":"unrecognized"})
        self.assertNotIn("PRIVATE",json.dumps(result))

    def test_footer_retains_only_fixed_script_index_and_numbers(self):
        summary=v.control_footer_projection(0,1,False,tap(30,1),"available")
        self.assertEqual(summary["controlIndex"],0);self.assertEqual(summary["script"],v.CONTROL_TESTS[0][0])
        self.assertEqual(summary["footer"]["notOkIndices"],[2]);self.assertEqual(summary["footer"]["counters"]["fail"],1)
        self.assertEqual(summary["exitCode"],1);self.assertFalse(summary["timedOut"])
        self.assertNotIn("PRIVATE",json.dumps(summary));self.assertNotIn("/path/",json.dumps(summary))
        self.assertFalse(summary["qualificationAccepted"])

    def test_footer_missing_incomplete_invalid_and_timeout_explicit(self):
        self.assertEqual(v.control_footer_projection(1,None,None)["footer"],{"state":"unavailable","reason":"missing"})
        self.assertEqual(v.control_footer_projection(1,124,True,None,"incomplete")["footer"]["reason"],"incomplete")
        invalid=v.control_footer_projection(1,1,False,b"TAP version 13\n# tests 22\n","available")
        self.assertEqual(invalid["footer"]["state"],"invalid")
        invalid=v.control_footer_projection(1,1,False,b"\xff","available")
        self.assertEqual(invalid["footer"]["reason"],"tap_utf8")
        with self.assertRaises(ValueError):v.control_footer_projection(99,0,False,tap(30),"available")

    def run_failure(self,control_failure=False,missing_tap=False,vendor_snapshot=False):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        home=Path(temporary.name).resolve();source=home/"source";source.mkdir()
        for name in [v.QUALIFIER]+[name for name,_ in v.CONTROL_TESTS]:
            path=source/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b"fixed-reviewed-source")
        operations=[]
        def phase(argv,cwd,environment,context,operation,ordinal):
            operations.append(operation)
            if operation=="vendor-controls":
                if not missing_tap:
                    destination=Path(next(value.split("=",1)[1] for value in argv if value.startswith("--test-reporter-destination=")))
                    destination.write_bytes(tap(v.CONTROL_TESTS[ordinal][1],1 if control_failure else 0))
                return SimpleNamespace(returncode=1 if control_failure or missing_tap else 0,timed_out=False,cleanup_settled=True)
            if operation=="vendor-actual-qualification":Path(argv[-1]).write_bytes(encoded(receipt()))
            return SimpleNamespace(returncode=1 if operation=="vendor-actual-qualification" else 0,timed_out=False,cleanup_settled=True)
        record={"schema":v.SCHEMA,"sourceGeneration":2,"workspaceSha256":"a"*64,"patchSha256":"b"*64,"proofSha256":"c"*64,"producerRuntimeSha256":"d"*64}
        environment={"RUNNER_TEMP":str(home/"runner"),"GITHUB_RUN_ID":"50000000001"}
        before_snapshot=None
        if vendor_snapshot:
            request={"source":{"sourceSha":"a"*40,"sourceTree":"b"*40,"fileSha256":{"pnpm-lock.yaml":"c"*64}}}
            public_sources={v.WORKSPACE:b"public-workspace\n",v.PATCH:b"public-compiled-js-patch\n",v.PROOF:b'{"public":"vendor-proof"}\n'}
            controller.retain_unvalidated_lock(b"public-lock\n",b"public-lock-diff\n",request,environment,"2026-11-05T01:00:00Z",vendor_files=public_sources)
            before_snapshot=(home/"runner/v109-lock-diagnostic/lock-diagnostic.json").read_bytes()
        args=(source,record,{"original":home/"original.tgz","derived":home/"derived.tgz"},environment,SimpleNamespace(phase_process=phase),{}, {"CI":"true"},home)
        with patch.object(controller,"emit") as output,self.assertRaises(ValueError):controller.qualify_npm_vendor(*args)
        safe=p.parse((home/"runner/v109-lock-diagnostic/vendor-qualification.safe.json").read_bytes())
        if vendor_snapshot:
            after_snapshot=(home/"runner/v109-lock-diagnostic/lock-diagnostic.json").read_bytes()
            self.assertEqual(before_snapshot,after_snapshot)
            metadata=p.parse(after_snapshot)
            self.assertFalse(metadata["acceptedAsGeneration"]);self.assertFalse(metadata["sourceQualified"])
            self.assertEqual(metadata["qualificationState"],"qualification_not_completed")
            for name,raw in public_sources.items():
                self.assertEqual((home/"runner/v109-lock-diagnostic"/name).read_bytes(),raw)
                self.assertEqual(metadata["vendorSourceFiles"][name]["sha256"],p.digest(raw))
        return safe,[call.args[0] for call in output.call_args_list],operations

    def test_real_failed_package_projection_saved_and_emitted_without_tap(self):
        safe,emitted,operations=self.run_failure()
        self.assertEqual(safe["packageTests"]["counters"]["failedCount"],2)
        self.assertEqual(len(safe["controlFooters"]),2)
        self.assertEqual(emitted[-1],safe);self.assertFalse(safe["qualificationAccepted"])
        self.assertNotIn("PRIVATE",json.dumps(emitted));self.assertEqual(operations[-1],"vendor-actual-qualification")

    def test_control_failure_has_same_safe_output_and_never_runs_qualifier(self):
        safe,emitted,operations=self.run_failure(control_failure=True)
        self.assertEqual(safe["diagnosticState"],"control_failure")
        self.assertEqual(safe["controlFooters"][0]["footer"]["counters"]["fail"],1)
        self.assertEqual(safe["controlFooters"][0]["footer"]["notOkIndices"],[2])
        self.assertNotIn("vendor-actual-qualification",operations);self.assertNotIn("PRIVATE",json.dumps(emitted))

    def test_public_vendor_snapshot_survives_failure_without_rewriting_original_receipt(self):
        safe,_,_=self.run_failure(vendor_snapshot=True)
        self.assertEqual(safe["packageTests"]["counters"]["failedCount"],2)
        self.assertFalse(safe["qualificationAccepted"])

    def test_diagnostic_snapshot_rejects_extra_payload_and_total_cap(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();env={"RUNNER_TEMP":str(root),"GITHUB_RUN_ID":"50000000001"}
            request={"source":{"sourceSha":"a"*40,"sourceTree":"b"*40,"fileSha256":{"pnpm-lock.yaml":"c"*64}}}
            valid={v.WORKSPACE:b"workspace",v.PATCH:b"patch",v.PROOF:b"proof"}
            with self.assertRaisesRegex(ValueError,"exact_public_sources"):
                controller.retain_unvalidated_lock(b"lock",b"diff",request,env,"2026-11-05T01:00:00Z",vendor_files={**valid,"npm.tgz":b"forbidden"})
            oversize={**valid,v.PATCH:b"x"*(2*1024*1024-65536)}
            with self.assertRaisesRegex(ValueError,"lock_diagnostic_size"):
                controller.retain_unvalidated_lock(b"lock",b"diff",request,env,"2026-11-05T01:00:00Z",vendor_files=oversize)
            self.assertFalse((root/"v109-lock-diagnostic").exists())

    def test_missing_control_tap_still_keeps_unavailable_summary(self):
        safe,_,operations=self.run_failure(missing_tap=True)
        self.assertEqual(safe["controlFooters"][0]["footer"],{"state":"unavailable","reason":"missing"})
        self.assertNotIn("vendor-actual-qualification",operations)


if __name__=="__main__":unittest.main()
