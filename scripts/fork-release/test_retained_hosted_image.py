"""Real image CLI bridge with synthetic hosted crypto-owner/native transports."""
from datetime import datetime, timezone
import json
import os
import unittest

import test_hosted_image_binding as fixtures


class RetainedHostedImageTests(unittest.TestCase):
    git = fixtures.StaticDiagnosticTests.git
    digest = staticmethod(fixtures.StaticDiagnosticTests.digest)
    inputs = fixtures.StaticDiagnosticTests.inputs
    private_json = staticmethod(fixtures.RetainedGcpQualificationTests.private_json)

    def set_privacy(self, **changes):
        fixtures.RetainedGcpQualificationTests.set_privacy(self, **changes)
        self.plan["schema"] = "openclaw.retained-hosted-qualification.v1"
        self.private_json(self.plan_path, self.plan)

    def run_owner(self, command="qualify-retained-hosted", plan=None, output=None):
        if command == "qualify-retained-hosted":
            self.env["RETAINED_OUTPUT"] = str(output or self.output)
        return fixtures.RetainedGcpQualificationTests.run_owner(self, command, plan, output)

    def setUp(self):
        fixtures.RetainedGcpQualificationTests.setUp(self)
        self.producer = {"workflowSha": "c" * 40, "runId": "42", "attempt": "1"}
        self.private_json(self.resources, {"schema":"openclaw.hosted-resources.v1","status":"passed",
            "sourceSha":self.sha,"toolingSha":self.producer["workflowSha"],
            "indexDigest":self.resource["indexDigest"],"violations":[]})
        self.hosted_plan = self.state / "hosted-origin-plan.json"
        nested = {key:str(value) for key,value in (("manifestPath",self.manifest),("inventoryPath",self.inventory),
            ("sourceDir",self.source),("ociDir",self.oci),("resourcesPath",self.resources))}
        nested.update(workflowSha=self.producer["workflowSha"],runId="42",attempt="1",inspectionToolingSha=self.tooling,
            archiveSha256="1"*64,originSha256="2"*64,resourcesSha256=self.digest(self.resources),
            buildMetadataSha256="3"*64,indexDigest=self.resource["indexDigest"],builtAt="2026-10-23T10:00:00Z")
        self.private_json(self.hosted_plan,nested)
        self.base={"schema":"openclaw.retained-hosted-input.v1",
            **{key:nested[key] for key in ("manifestPath","inventoryPath","sourceDir","ociDir","inspectionToolingSha")},
            "hostedPlanPath":str(self.hosted_plan),"hostedPlanSha256":self.digest(self.hosted_plan),"smokeTransport":"loaded"}
        self.private_json(self.base_path,self.base)
        self.capture={"schema":"openclaw.retained-hosted-build-context.v1","status":"captured",
            "originAuthenticated":True,"qualified":False,"nativeExecuted":False,"productionAuthorized":False,
            "repository":"fr-meyer/openclaw","sourceSha":self.sha,"sourceTree":self.tree,"producer":self.producer,
            "manifestSha256":self.digest(self.manifest),"inventorySha256":self.digest(self.inventory),
            "indexDigest":nested["indexDigest"],"builtAt":nested["builtAt"],"buildMetadataSha256":nested["buildMetadataSha256"],
            "custodySha256":nested["originSha256"],"resourcesSha256":nested["resourcesSha256"],
            "resourceAssessment":"passed","archiveSha256":nested["archiveSha256"],"ociClosureSha256":"4"*64,
            "planSha256":self.digest(self.hosted_plan),"inspectionToolingSha":self.tooling,
            "capturedAt":datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "attestationVerificationSha256":"5"*64,"apiCanonicalSha256":"6"*64}
        self.capture_path=self.state/"synthetic-crypto-owner.json"
        self.private_json(self.capture_path,self.capture)
        self.authority_log=self.state/"authority-calls.jsonl"
        preload=self.preload.read_text()
        needle="  if (command !== 'docker' && command !== 'skopeo') {"
        self.assertIn(needle,preload)
        preload=preload.replace(needle,r"""
  if (command === 'python3' && args[0].endsWith('/hosted_image_context.py')) {
    fs.appendFileSync(process.env.HOSTED_AUTHORITY_LOG, JSON.stringify(args) + '\n');
    if (process.env.HOSTED_AUTHORITY_FAIL === 'yes') throw new Error('synthetic signature verification refused');
    const value = fs.readFileSync(process.env.HOSTED_CAPTURE,'utf8');
    fs.writeFileSync(args[args.indexOf('--output')+1],value,{flag:'wx',mode:0o600});
    return value;
  }
"""+needle)
        self.preload.write_text(preload)
        self.env.update(HOSTED_CAPTURE=str(self.capture_path),HOSTED_AUTHORITY_LOG=str(self.authority_log),
                        RETAINED_INSPECT_DIGEST=nested["indexDigest"])
        self.set_privacy()

    def test_hosted_origin_qualifies_without_fake_github_environment_and_reverifies_without_native(self):
        self.assertFalse(any(key.startswith("GITHUB_") for key in self.env))
        code,capture=self.run_owner("capture-retained-hosted-origin",self.base_path,self.state/"captured.json")
        self.assertEqual(code.returncode,0,capture)
        self.assertEqual(capture["producer"],self.producer)
        self.assertEqual(capture["hostedPlanSha256"],self.digest(self.hosted_plan))
        self.assertFalse(self.native_log.exists())
        result,report=self.run_owner()
        self.assertEqual(result.returncode,0,report)
        receipt=json.loads((self.output/"receipt.json").read_text())
        self.assertEqual(receipt["producer"],self.producer)
        self.assertNotIn("kind",receipt["producer"])
        self.assertNotIn("originalExecutionSha256",receipt["reinspection"])
        self.assertEqual(receipt["reinspection"]["schema"],"openclaw.retained-hosted-qualification.v1")
        self.assertEqual(receipt["reinspection"]["hostedAuthenticationSha256"],self.digest(self.output/"hosted-authentication.json"))
        self.assertEqual(receipt["reinspection"]["originalToolingSha"],self.producer["workflowSha"])
        self.assertEqual(receipt["reinspection"]["inspectionToolingSha"],self.tooling)
        native=self.native_log.read_bytes();before=self.authority_log.read_bytes()
        result,proof=self.run_owner("verify-retained-hosted",output=self.output/"receipt.json")
        self.assertEqual(result.returncode,0,proof)
        self.assertEqual(self.native_log.read_bytes(),native)

        self.assertGreater(len(self.authority_log.read_bytes()),len(before),"Verification trusted saved authentication JSON")
        self.env["HOSTED_AUTHORITY_FAIL"]="yes"
        result,_=self.run_owner("verify-retained-hosted",output=self.output/"receipt.json")
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.native_log.read_bytes(),native)

    def use_historical_authentication(self):
        custody = self.state / "synthetic-custody.json"
        self.private_json(custody, {"synthetic": "transport fixture; Python owner validates real custody"})
        self.base.update(authenticationCustodyPath=str(custody), authenticationCustodySha256=self.digest(custody))
        self.private_json(self.base_path, self.base); self.set_privacy()
        self.capture.update(authenticationMethod="historical_verified_capture_reuse",
            authenticationCustodySha256=self.digest(custody), originalCaptureSha256="7"*64,
            originalPlanSha256="8"*64, originalInspectionToolingSha="9"*40,
            originalCapturedAt=self.capture["capturedAt"], nativeAttestationVerificationPerformed=False,
            canonicalApiFetched=False)
        self.private_json(self.capture_path, self.capture)

    def test_explicit_historical_authentication_routes_capture_qualify_verify_without_native_reexecution(self):
        self.use_historical_authentication()
        result, value = self.run_owner("capture-retained-hosted-origin", self.base_path, self.state/"reused.json")
        self.assertEqual(result.returncode, 0, value)
        self.assertEqual(value["authenticationMethod"], "historical_verified_capture_reuse")
        result, value = self.run_owner(); self.assertEqual(result.returncode, 0, value)
        native = self.native_log.read_bytes()
        result, value = self.run_owner("verify-retained-hosted", output=self.output/"receipt.json")
        self.assertEqual(result.returncode, 0, value); self.assertEqual(self.native_log.read_bytes(), native)
        requests = [json.loads(line) for line in self.authority_log.read_text().splitlines()]
        self.assertTrue(requests)
        for args in requests:
            self.assertEqual(args[1], "reuse")
            self.assertEqual(args[args.index("--custody-sha256")+1], self.base["authenticationCustodySha256"])
        changed = dict(self.capture, originalCaptureSha256="f"*64)
        self.private_json(self.capture_path, changed)
        result, _ = self.run_owner("verify-retained-hosted", output=self.output/"receipt.json")
        self.assertNotEqual(result.returncode, 0); self.assertEqual(self.native_log.read_bytes(), native)

    def test_historical_authentication_does_not_bypass_stale_admission(self):
        self.use_historical_authentication()
        self.resource.update(checkedAt="2026-10-23T10:01:00Z", expiresAt="2026-10-23T10:02:00Z")
        self.private_json(self.resource_path, self.resource); self.set_privacy()
        result, report = self.run_owner()
        self.assertEqual(result.returncode, 1); self.assertEqual(report["static"], "passed", report)
        self.assertFalse(self.native_log.exists()); self.assertFalse((self.output/"native-attempt.json").exists())

    def test_historical_authentication_does_not_bypass_private_findings(self):
        self.use_historical_authentication()
        scan = json.loads(self.privacy.read_text())
        self.set_privacy(status="failed", findings=[{"rule":"synthetic"}],
            findingSummary={**scan["findingSummary"], "total":1})
        result, report = self.run_owner()
        self.assertEqual(result.returncode, 1); self.assertEqual(report["privacy"], "failed", report)
        self.assertFalse(self.native_log.exists()); self.assertFalse((self.output/"receipt.json").exists())

    def test_crypto_failure_or_changed_archive_pin_blocks_before_native(self):
        for index,change in enumerate(({"originAuthenticated":False},{"archiveSha256":"f"*64})):
            with self.subTest(change=change):
                self.private_json(self.capture_path,{**self.capture,**change})
                target=self.state/("refused-"+str(index));target.mkdir(mode=0o700)
                result,report=self.run_owner(output=target)
                self.assertEqual(result.returncode,1)
                self.assertFalse(report["qualified"])
                self.assertFalse(self.native_log.exists())

    def test_complete_privacy_findings_still_collect_static_without_native(self):
        scan=json.loads(self.privacy.read_text())
        self.set_privacy(status="failed",findings=[{"rule":"synthetic"}],
            findingSummary={**scan["findingSummary"],"total":1})
        result,report=self.run_owner()
        self.assertEqual(result.returncode,1)
        self.assertEqual(report["static"],"passed",report)
        self.assertEqual(report["privacy"],"failed")
        self.assertFalse(self.native_log.exists())

    def test_original_resource_failure_cannot_qualify_but_static_evidence_survives(self):
        self.private_json(self.capture_path,{**self.capture,"resourceAssessment":"failed"})
        result,report=self.run_owner()
        self.assertEqual(result.returncode,1)
        self.assertEqual(report["static"],"passed",report)
        self.assertFalse(self.native_log.exists())
        self.assertFalse((self.output/"receipt.json").exists())

    def test_hosted_fresh_resource_request_uses_real_github_invocation_identity(self):
        self.env.update(RETAINED_STATIC_ELAPSED_MS="301000",RETAINED_RESOURCE_RESPONSE="fresh")
        result,report=self.run_owner()
        self.assertEqual(result.returncode,0,report)
        request=json.loads((self.output/"resource-refresh/01-request.json").read_text())
        self.assertEqual(request["originalOperationId"],"https://github.com/fr-meyer/openclaw/actions/runs/42/attempts/1")
        self.assertFalse(request["originalOperationId"]=="d"*32)

    def test_hosted_plan_is_refused_by_unchanged_gcp_entrypoint(self):
        result,report=self.run_owner("qualify-retained-gcp")
        self.assertEqual(result.returncode,1)
        self.assertFalse(report["qualified"])
        self.assertFalse(self.native_log.exists())

    def test_stale_review_diff_is_rejected_before_origin_authority_or_native(self):
        manifest=json.loads(self.manifest.read_text())
        manifest["review"]={"prNumber":26,"baseSha":manifest["source"]["baseCommit"],"changedDiffSha256":"0"*64}
        self.private_json(self.manifest,manifest)
        inventory=json.loads(self.inventory.read_text());inventory["manifestSha256"]=self.digest(self.manifest)
        self.private_json(self.inventory,inventory)
        self.capture.update(manifestSha256=self.digest(self.manifest),inventorySha256=self.digest(self.inventory))
        self.private_json(self.capture_path,self.capture)
        result,report=self.run_owner()
        self.assertEqual(result.returncode,1)
        self.assertFalse(report["qualified"])
        self.assertFalse(self.authority_log.exists())
        self.assertFalse(self.native_log.exists())

    def test_arbitrary_original_resource_substitution_cannot_gain_native_qualification(self):
        self.private_json(self.resources,{"schema":"after-the-fact-caller-claim"})
        self.set_privacy()
        result,report=self.run_owner()
        self.assertEqual(result.returncode,1)
        self.assertFalse(report["qualified"])
        self.assertFalse(self.native_log.exists())


if __name__=="__main__":unittest.main()
