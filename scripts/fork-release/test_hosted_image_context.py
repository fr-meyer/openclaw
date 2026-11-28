"""Hosted origin entrypoint with genuine local archives and inert API/GH owners."""
import copy
from contextlib import ExitStack, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import hosted_image_context as owner
from test_hosted_image_binding import layout


class HostedOriginTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "package.json").write_text('{"version":"2026.10.5"}')
        self.oci = self.root / "oci"
        self.oci.mkdir()
        image, _ = layout(self.oci, source=owner.SOURCE, version_label="2026.10.5")
        (self.oci / "ingest").mkdir()
        self.workflow = "a" * 40
        self.inspector = "c" * 40
        controls = self.root / "controls"
        controls.mkdir(mode=0o700)
        self.paths = {key: controls / name for key, name in (
            ("manifestPath", "manifest.json"), ("inventoryPath", "patch-inventory.json"),
            ("metadataPath", "build-metadata.json"), ("originPath", "build-origin.json"),
            ("archivePath", "retained-oci.tar"), ("resourcesPath", "resources.json"))}
        self.paths["archivePath"] = self.root / "retained-oci.tar"
        self.write(self.paths["manifestPath"], {"schema":"openclaw.fork-release.v1", "repository":owner.REPOSITORY,
            "source":{"commit":owner.SOURCE,"tree":owner.TREE},
            "image":{"architecture":"amd64","extensions":"codex,workboard"}})
        self.write(self.paths["inventoryPath"], {"schema":"openclaw.fork-patch-inventory.v1",
            "repository":owner.REPOSITORY,"manifestSha256":self.hash(self.paths["manifestPath"])})
        self.write(self.paths["metadataPath"], {"containerimage.digest":image["indexDigest"]})
        self.write(self.paths["resourcesPath"], {"schema":"openclaw.hosted-resources.v1","status":"passed",
            "sourceSha":owner.SOURCE,"toolingSha":self.workflow,"indexDigest":image["indexDigest"],"violations":[]})
        self.origin = {"schema":"openclaw.hosted-build-custody.v1", "repository":owner.REPOSITORY,
            "producer":{"workflowSha":self.workflow,"runId":"42","attempt":"1"},
            "sourceSha":owner.SOURCE,"sourceTree":owner.TREE,
            "manifestSha256":self.hash(self.paths["manifestPath"]),
            "inventorySha256":self.hash(self.paths["inventoryPath"]),"indexDigest":image["indexDigest"],
            "builtAt":"2026-10-23T10:00:00Z","buildMetadataSha256":self.hash(self.paths["metadataPath"]),
            "resourcesSha256":self.hash(self.paths["resourcesPath"])}
        self.write(self.paths["originPath"], self.origin)
        inputs = owner.private_oci_bundle.Inputs(controls, self.oci)
        try:
            self.write(controls / owner.private_oci_bundle.INVENTORY_FILE, inputs.oci_inventory())
            _, specs = owner.private_oci_bundle.inspect_inputs(inputs)
            owner.private_oci_bundle.write_tar(inputs, specs, self.paths["archivePath"],
                                               owner.private_oci_bundle.MAX_BYTES)
        finally:
            inputs.close()
        self.paths["archivePath"].chmod(0o600)
        self.plan = {"schema":"openclaw.retained-hosted-origin-input.v1", "sourceDir":str(self.source),
            "ociDir":str(self.oci),**{key:str(value) for key,value in self.paths.items()},
            "workflowSha":self.workflow,"workflowRef":"refs/heads/release-pipeline/v105-image-only-20261024",
            "inspectionToolingSha":self.inspector,"runId":"42","attempt":"1","jobId":"77",
            "archiveSha256":self.hash(self.paths["archivePath"]),"originSha256":self.hash(self.paths["originPath"]),
            **{key:self.origin[key] for key in ("manifestSha256","inventorySha256","buildMetadataSha256","resourcesSha256","indexDigest","builtAt")}}
        self.plan_path = self.root / "plan.json"
        (self.root / "result").mkdir(mode=0o700)
        self.output = self.root / "result/capture.json"
        self.run = {"id":42,"run_attempt":1,"head_sha":self.workflow,"path":owner.WORKFLOW,
            "repository":{"full_name":owner.REPOSITORY},"head_repository":{"full_name":owner.REPOSITORY},
            "head_branch":self.plan["workflowRef"].removeprefix("refs/heads/"),"event":"push",
            "status":"completed","conclusion":"failure"}
        self.job = {"id":77,"run_id":42,"run_attempt":1,"head_sha":self.workflow,
            "name":"qualify-and-prepare","status":"completed","conclusion":"failure",
            "completed_at":"2026-10-23T10:03:00Z","steps":[
                {"name":owner.BUILD_STEP,"status":"completed","conclusion":"success",
                 "started_at":"2026-10-23T10:00:00Z","completed_at":"2026-10-23T10:01:00Z"},
                {"name":owner.ATTEST_STEP,"status":"completed","conclusion":"success",
                 "started_at":"2026-10-23T10:02:00Z","completed_at":"2026-10-23T10:03:00Z"}]}
        signer=f"https://github.com/{owner.REPOSITORY}/{owner.WORKFLOW}@{self.plan['workflowRef']}"
        self.proof=[{"attestation":{},"verificationResult":{
            "signature":{"certificate":{"issuer":"https://token.actions.githubusercontent.com",
                "sourceRepositoryURI":f"https://github.com/{owner.REPOSITORY}","sourceRepositoryDigest":self.workflow,
                "buildSignerDigest":self.workflow,"buildSignerURI":signer,
                "subjectAlternativeName":signer,"sourceRepositoryRef":self.plan["workflowRef"],
                "runnerEnvironment":"github-hosted",
                "runInvocationURI":f"https://github.com/{owner.REPOSITORY}/actions/runs/42/attempts/1"}},
            "verifiedTimestamps":[{"type":"Tlog","timestamp":"2026-10-23T10:02:00Z"}],
            "statement":{"predicateType":"https://slsa.dev/provenance/v1",
                "subject":[{"name":"retained-oci.tar","digest":{"sha256":self.plan["archiveSha256"]}}]}}}]

    @staticmethod
    def hash(path): return hashlib.sha256(path.read_bytes()).hexdigest()

    @staticmethod
    def write(path,value):
        path.write_text(json.dumps(value)); path.chmod(0o600)

    def git(self,root,*args,**_kwargs):
        if args[:2]==("rev-parse","HEAD"):
            return owner.SOURCE if Path(root)==self.source else self.inspector
        if args[:2]==("rev-parse","HEAD^{tree}"): return owner.TREE
        if args[0]=="status": return ""
        raise AssertionError(args)

    def entry(self,mode="capture",native_code=0,native_effect=None):
        self.write(self.plan_path,self.plan)
        def api(path):
            if path==f"repos/{owner.REPOSITORY}/actions/runs/42/attempts/1": return self.run
            if path==f"repos/{owner.REPOSITORY}/actions/jobs/77": return self.job
            raise AssertionError(path)
        output=io.StringIO()
        with patch.object(owner.pr,"git",side_effect=self.git), patch.object(owner.pr,"fetch_public_json",side_effect=api) as fetch, \
             patch.object(owner,"verifier_executable",return_value=owner.GH), \
             patch.object(owner.subprocess,"run",side_effect=native_effect,return_value=SimpleNamespace(returncode=native_code,
                 stdout=json.dumps(self.proof).encode(),stderr=b"private-error-not-for-output")) as native,redirect_stdout(output):
            code=owner.main([mode,"--plan",str(self.plan_path),"--plan-sha256",self.hash(self.plan_path),"--output",str(self.output)])
        value=json.loads(output.getvalue())
        self.assertNotIn("private-error-not-for-output",output.getvalue())
        return code,value,fetch,native

    def test_offline_preparation_never_authenticates_saved_claims_or_invokes_authorities(self):
        code,value,fetch,native=self.entry("prepare")
        self.assertEqual(code,0,value)
        self.assertEqual(value["status"],"prepared")
        self.assertFalse(value["originAuthenticated"])
        self.assertFalse(value["qualified"])
        fetch.assert_not_called();native.assert_not_called()

    def test_pinned_gh_string_san_capture_uses_native_crypto_and_api_even_when_privacy_job_failed(self):
        code,value,fetch,native=self.entry()
        self.assertEqual(code,0,value)
        self.assertTrue(value["originAuthenticated"])
        self.assertEqual(value["producer"],self.origin["producer"])
        self.assertEqual(value["builtAt"],self.origin["builtAt"])
        self.assertEqual(value["inspectionToolingSha"],self.inspector)
        self.assertFalse(value["qualified"]);self.assertFalse(value["nativeExecuted"])
        self.assertEqual(fetch.call_count,2)
        argv=native.call_args.args[0]
        with patch.object(owner,"verifier_executable",return_value=owner.GH):
            self.assertEqual(argv,owner.command(self.plan))
        self.assertEqual(argv[0],owner.GH)
        self.assertIn("--deny-self-hosted-runners",argv)
        self.assertIn("--signer-digest",argv)
        self.assertNotIn("--bundle",argv)
        self.assertEqual(self.output.stat().st_mode&0o777,0o600)

    def test_failed_native_verification_cannot_be_replaced_by_plausible_json(self):
        code,value,fetch,_=self.entry(native_code=1)
        self.assertNotEqual(code,0)
        self.assertFalse(value["originAuthenticated"])
        self.assertFalse(self.output.exists());fetch.assert_not_called()

    def test_certificate_invocation_signer_subject_and_runner_mismatch_refuse(self):
        original=copy.deepcopy(self.proof)
        signer=original[0]["verificationResult"]["signature"]["certificate"]["subjectAlternativeName"]
        for field,value in (("runInvocationURI","https://github.com/fr-meyer/openclaw/actions/runs/42/attempts/2"),
                            ("subjectAlternativeName",signer+"/changed"),
                            ("subjectAlternativeName",{"type":"URI","value":signer}),
                            ("subjectAlternativeName",[signer]),
                            ("subjectAlternativeName",None),
                            ("sourceRepositoryDigest","f"*40),
                            ("sourceRepositoryRef","refs/heads/other"),
                            ("buildSignerDigest","f"*40),("sourceRepositoryURI","https://github.com/other/repo"),
                            ("runnerEnvironment","self-hosted")):
            with self.subTest(field=field):
                self.proof=copy.deepcopy(original)
                self.proof[0]["verificationResult"]["signature"]["certificate"][field]=value
                code,_,fetch,_=self.entry()
                self.assertNotEqual(code,0);self.assertFalse(self.output.exists());fetch.assert_not_called()
        self.proof=copy.deepcopy(original)
        self.proof[0]["verificationResult"]["statement"]["subject"][0]["digest"]["sha256"]="f"*64
        code,_,fetch,_=self.entry()
        self.assertNotEqual(code,0);fetch.assert_not_called()

    def test_canonical_api_wrong_attempt_source_or_missing_attest_step_refuse(self):
        original=copy.deepcopy(self.job)
        for field,value in (("run_attempt",2),("head_sha","f"*40),("steps",original["steps"][:1])):
            with self.subTest(field=field):
                self.job=copy.deepcopy(original);self.job[field]=value
                code,_,_,_=self.entry()
                self.assertNotEqual(code,0);self.assertFalse(self.output.exists())

    def test_signed_retained_bytes_survive_upload_failure_or_cancelled_ack(self):
        for outcome in ("failure", "cancelled"):
            with self.subTest(outcome=outcome):
                self.job["steps"][1]["conclusion"] = outcome
                self.job["conclusion"] = self.run["conclusion"] = outcome
                code,value,_,_=self.entry()
                self.assertEqual(code,0,value)
                self.assertTrue(value["originAuthenticated"])
                self.assertEqual(value["retentionStepOutcome"],outcome)
                self.assertFalse(value["qualified"])
                self.output.unlink()

    def test_failed_docker_step_is_not_rescued_by_a_signed_archive(self):
        self.job["steps"][0]["conclusion"]="failure"
        code,value,_,_=self.entry()
        self.assertNotEqual(code,0)
        self.assertFalse(value["originAuthenticated"])
        self.assertFalse(self.output.exists())

    def test_authentic_failed_resources_remain_failed_and_unqualified(self):
        resources=json.loads(self.paths["resourcesPath"].read_text())
        resources.update(status="failed",violations=["worker.oom_increased"])
        self.write(self.paths["resourcesPath"],resources)
        self.origin["resourcesSha256"]=self.hash(self.paths["resourcesPath"])
        self.write(self.paths["originPath"],self.origin)
        self.paths["archivePath"].unlink()
        inputs=owner.private_oci_bundle.Inputs(self.paths["originPath"].parent,self.oci)
        try:
            _,specs=owner.private_oci_bundle.inspect_inputs(inputs)
            owner.private_oci_bundle.write_tar(inputs,specs,self.paths["archivePath"],owner.private_oci_bundle.MAX_BYTES)
        finally:
            inputs.close()
        self.plan.update(resourcesSha256=self.origin["resourcesSha256"],
                         originSha256=self.hash(self.paths["originPath"]),archiveSha256=self.hash(self.paths["archivePath"]))
        self.proof[0]["verificationResult"]["statement"]["subject"][0]["digest"]["sha256"]=self.plan["archiveSha256"]
        code,value,_,_=self.entry()
        self.assertEqual(code,0,value)
        self.assertTrue(value["originAuthenticated"])
        self.assertEqual(value["resourceAssessment"],"failed")
        self.assertIn("original_resource_assessment_failed",value["blockers"])
        self.assertFalse(value["qualified"])

    def test_archive_or_metadata_tampering_prevents_any_authority_call(self):
        self.paths["metadataPath"].write_text('{"containerimage.digest":"changed"}')
        code,_,fetch,native=self.entry()
        self.assertNotEqual(code,0);fetch.assert_not_called();native.assert_not_called()

    def test_authenticated_flag_or_saved_verifier_path_is_not_an_input(self):
        self.plan["authenticated"]=True
        code,_,fetch,native=self.entry()
        self.assertNotEqual(code,0);fetch.assert_not_called();native.assert_not_called()

    def test_capture_plan_cannot_choose_a_private_verifier(self):
        self.plan["ghExecutable"] = str(self.root / "caller-selected-gh")
        code,_,fetch,native = self.entry()
        self.assertNotEqual(code,0);fetch.assert_not_called();native.assert_not_called()

    def add_bundle(self):
        self.bundle=self.root/"public-attestation.jsonl"
        self.bundle.write_bytes(b'{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}\n')
        self.bundle.chmod(0o600)
        self.plan.update(attestationBundlePath=str(self.bundle),attestationBundleSha256=self.hash(self.bundle))

    def test_explicit_bundle_is_snapshotted_for_native_verification_without_auth_fallback(self):
        self.add_bundle();raw=self.bundle.read_bytes();seen=[]
        def verify(argv,**_kwargs):
            snapshot=Path(argv[argv.index("--bundle")+1])
            seen.append(snapshot)
            self.assertNotEqual(snapshot,self.bundle)
            self.assertEqual(snapshot.read_bytes(),raw)
            self.assertEqual(snapshot.stat().st_mode&0o777,0o600)
            return SimpleNamespace(returncode=0,stdout=json.dumps(self.proof).encode(),stderr=b"")
        code,value,fetch,native=self.entry(native_effect=verify)
        self.assertEqual(code,0,value)
        self.assertTrue(value["originAuthenticated"])
        self.assertEqual(value["attestationBundleSha256"],self.hash(self.bundle))
        self.assertEqual(native.call_count,1);self.assertEqual(fetch.call_count,2)
        self.assertEqual(len(seen),1);self.assertFalse(seen[0].exists())
        self.assertEqual(value["verificationCommand"][value["verificationCommand"].index("--bundle")+1],
                         "<private-attestation-bundle>")

    def test_bundle_input_never_substitutes_for_native_signature_verification(self):
        self.add_bundle()
        self.bundle.write_text(json.dumps(self.proof))
        self.plan["attestationBundleSha256"]=self.hash(self.bundle)
        code,value,fetch,native=self.entry(native_code=1)
        self.assertNotEqual(code,0);self.assertFalse(value["originAuthenticated"])
        self.assertEqual(native.call_count,1);fetch.assert_not_called()

    def test_partial_wrong_hash_or_nonprivate_bundle_refuses_before_native(self):
        self.add_bundle();complete=dict(self.plan)
        for change in ("missing_path","missing_pin","wrong_pin","public_file"):
            with self.subTest(change=change):
                self.plan=dict(complete);self.bundle.chmod(0o600)
                if change=="missing_path": del self.plan["attestationBundlePath"]
                elif change=="missing_pin": del self.plan["attestationBundleSha256"]
                elif change=="wrong_pin": self.plan["attestationBundleSha256"]="f"*64
                else: self.bundle.chmod(0o644)
                code,_,fetch,native=self.entry()
                self.assertNotEqual(code,0);fetch.assert_not_called();native.assert_not_called()

    def test_changed_original_bundle_after_snapshot_cannot_publish_capture(self):
        self.add_bundle()
        def verify(argv,**_kwargs):
            self.assertEqual(Path(argv[argv.index("--bundle")+1]).read_bytes(),self.bundle.read_bytes())
            self.bundle.write_bytes(b"changed after verified snapshot")
            return SimpleNamespace(returncode=0,stdout=json.dumps(self.proof).encode(),stderr=b"")
        code,_,_,native=self.entry(native_effect=verify)
        self.assertNotEqual(code,0);self.assertEqual(native.call_count,1)
        self.assertFalse(self.output.exists())

    def nested_driver_prepare(self):
        import gcp_image_reinspection as driver
        self.write(self.plan_path,self.plan)
        outer={"schema":"openclaw.retained-hosted-input.v1",
               **{key:self.plan[key] for key in ("manifestPath","inventoryPath","sourceDir","ociDir","inspectionToolingSha")},
               "hostedPlanPath":str(self.plan_path),"hostedPlanSha256":self.hash(self.plan_path)}
        outer_path=self.root/"outer.json";self.write(outer_path,outer)
        parent=self.root/"inspection";parent.mkdir(mode=0o700)
        state=parent/("a"*32)
        with patch.object(driver.gcp_build,"clean_checkout"):
            return driver.prepare(outer_path,self.hash(outer_path),state,None,None,"hosted")

    def test_existing_hosted_driver_accepts_pinned_bundle_in_nested_plan(self):
        self.add_bundle()
        outer,state,intent=self.nested_driver_prepare()
        self.assertEqual(intent["hostedPlanSha256"],self.hash(self.plan_path))
        nested,_=owner.plan_at(outer["hostedPlanPath"],outer["hostedPlanSha256"])
        self.assertEqual(nested["attestationBundleSha256"],self.hash(self.bundle))
        self.assertTrue((state/"intent.json").exists())

    def test_existing_hosted_driver_rejects_partial_nested_bundle(self):
        self.add_bundle();del self.plan["attestationBundleSha256"]
        with self.assertRaises(ValueError): self.nested_driver_prepare()
        self.assertFalse((self.root/"inspection"/("a"*32)).exists())

    def historical_inputs(self):
        code, original, _, _ = self.entry()
        self.assertEqual(code, 0, original)
        self.original_capture = self.output
        self.original_plan = self.root / "original-plan.json"
        self.original_plan.write_bytes(self.plan_path.read_bytes()); self.original_plan.chmod(0o600)
        self.native_proof = self.root / "original-native.json"
        self.native_proof.write_bytes(json.dumps(self.proof).encode()); self.native_proof.chmod(0o600)
        self.canonical_api = self.root / "canonical-api.json"
        self.canonical_api.write_bytes(owner.encoded({"run": self.run, "job": self.job})); self.canonical_api.chmod(0o600)
        self.custody_path = self.root / "custody.json"
        self.custody = {"schema": "openclaw.retained-hosted-authentication-custody.v1",
            "currentPlanSha256": self.hash(self.plan_path), "originalPlanPath": str(self.original_plan),
            "originalPlanSha256": self.hash(self.original_plan), "originalCapturePath": str(self.original_capture),
            "originalCaptureSha256": self.hash(self.original_capture), "nativeVerificationPath": str(self.native_proof),
            "canonicalApiPath": str(self.canonical_api)}
        self.reuse_number = 0
        return original

    def reuse_entry(self, synthetic_authority=True, custody_hash=None, dirty=False, current_plan_hash=None):
        self.reuse_number += 1
        self.output = self.root / ("result/reuse-" + str(self.reuse_number) + ".json")
        self.write(self.plan_path, self.plan)
        self.custody["currentPlanSha256"] = current_plan_hash or self.hash(self.plan_path)
        self.write(self.custody_path, self.custody)
        def git(root, *args, **kwargs):
            return "dirty" if dirty and args[0] == "status" else self.git(root, *args, **kwargs)
        output = io.StringIO()
        with ExitStack() as stack:
            stack.enter_context(patch.object(owner.pr, "git", side_effect=git))
            fetch = stack.enter_context(patch.object(owner.pr, "fetch_public_json", side_effect=AssertionError("network forbidden")))
            native = stack.enter_context(patch.object(owner.subprocess, "run", side_effect=AssertionError("native forbidden")))
            if synthetic_authority:
                stack.enter_context(patch.object(owner, "ORIGINAL_CAPTURE_SHA256", self.custody["originalCaptureSha256"]))
                stack.enter_context(patch.object(owner, "ORIGINAL_PLAN_SHA256", self.custody["originalPlanSha256"]))
            with redirect_stdout(output):
                code = owner.main(["reuse", "--plan", str(self.plan_path), "--plan-sha256", self.hash(self.plan_path),
                    "--custody", str(self.custody_path), "--custody-sha256", custody_hash or self.hash(self.custody_path),
                    "--output", str(self.output)])
        fetch.assert_not_called(); native.assert_not_called()
        return code, json.loads(output.getvalue())

    def test_historical_reuse_allows_local_relocation_and_new_inspector_without_fresh_authentication(self):
        original = self.historical_inputs(); unchanged = self.original_capture.read_bytes()
        relocated = self.root / "relocated.tar"; self.paths["archivePath"].rename(relocated)
        self.plan["archivePath"] = str(relocated)
        self.inspector = self.plan["inspectionToolingSha"] = "d" * 40
        code, value = self.reuse_entry()
        self.assertEqual(code, 0, value)
        self.assertEqual(value["authenticationMethod"], "historical_verified_capture_reuse")
        self.assertEqual(value["originalCaptureSha256"], self.hash(self.original_capture))
        self.assertEqual(value["originalInspectionToolingSha"], original["inspectionToolingSha"])
        for key in ("producer", "sourceSha", "sourceTree", "builtAt", "capturedAt", "workflowOutcome", "jobOutcome"):
            self.assertEqual(value[key], original[key])
        self.assertFalse(value["nativeAttestationVerificationPerformed"]); self.assertFalse(value["canonicalApiFetched"])
        self.assertFalse(value["qualified"]); self.assertEqual(self.original_capture.read_bytes(), unchanged)

    def test_self_selected_well_formed_saved_capture_is_not_authentication_authority(self):
        self.historical_inputs()
        code, value = self.reuse_entry(synthetic_authority=False)
        self.assertNotEqual(code, 0); self.assertFalse(value["originAuthenticated"])
        self.assertFalse(self.output.exists())

    def test_historical_reuse_requires_exact_pins_private_complete_evidence_and_unchanged_inputs(self):
        self.historical_inputs()
        saved = {p: p.read_bytes() for p in (self.original_capture, self.original_plan, self.native_proof, self.canonical_api,
                                            self.paths["archivePath"])}
        original_plan, custody = copy.deepcopy(self.plan), dict(self.custody)
        for change in ("custody_hash", "current_plan_hash", "capture_hash", "plan_hash", "missing_proof", "native_hash", "api_hash",
                       "nonprivate_proof", "extra_field", "job", "archive", "source", "dirty"):
            with self.subTest(change=change):
                for path, raw in saved.items(): path.write_bytes(raw); path.chmod(0o600)
                self.plan, self.custody = copy.deepcopy(original_plan), dict(custody)
                if change == "capture_hash": self.custody["originalCaptureSha256"] = "f" * 64
                elif change == "plan_hash": self.custody["originalPlanSha256"] = "f" * 64
                elif change == "missing_proof": self.native_proof.unlink()
                elif change == "native_hash": self.native_proof.write_bytes(b"[]")
                elif change == "api_hash": self.canonical_api.write_bytes(b"{}")
                elif change == "nonprivate_proof": self.native_proof.chmod(0o644)
                elif change == "extra_field": self.custody["authenticated"] = True
                elif change == "job": self.plan["jobId"] = "88"
                elif change == "archive": self.paths["archivePath"].write_bytes(b"changed")
                elif change == "source": self.plan["sourceDir"] = str(self.root / "different-source")
                code, value = self.reuse_entry(custody_hash="f" * 64 if change == "custody_hash" else None,
                                             dirty=change == "dirty",
                                             current_plan_hash="f" * 64 if change == "current_plan_hash" else None)
                self.assertNotEqual(code, 0); self.assertFalse(value["originAuthenticated"])
                self.assertFalse(self.output.exists())

    def test_historical_evidence_rechecks_certificate_run_and_chronology_despite_consistent_fixture_hashes(self):
        original = self.historical_inputs(); proof, run, job = copy.deepcopy(self.proof), copy.deepcopy(self.run), copy.deepcopy(self.job)
        for change in ("san_shape", "san_uri", "signer_digest", "subject", "runner", "run", "step_order", "outcome", "captured_at"):
            with self.subTest(change=change):
                self.proof, self.run, self.job = copy.deepcopy(proof), copy.deepcopy(run), copy.deepcopy(job)
                certificate = self.proof[0]["verificationResult"]["signature"]["certificate"]
                capture = dict(original)
                if change == "san_shape": certificate["subjectAlternativeName"] = {"type": "URI", "value": certificate["subjectAlternativeName"]}
                elif change == "san_uri": certificate["subjectAlternativeName"] += "/other"
                elif change == "signer_digest": certificate["sourceRepositoryDigest"] = "f" * 40
                elif change == "subject": self.proof[0]["verificationResult"]["statement"]["subject"][0]["digest"]["sha256"] = "f" * 64
                elif change == "runner": certificate["runnerEnvironment"] = "self-hosted"
                elif change == "run": self.run["run_attempt"] = 2
                elif change == "step_order": self.job["steps"][1]["started_at"] = "2026-10-23T09:00:00Z"
                elif change == "outcome": capture["workflowOutcome"] = "success"
                elif change == "captured_at": capture["capturedAt"] = "2026-10-23T10:00:30Z"
                self.native_proof.write_bytes(json.dumps(self.proof).encode())
                self.canonical_api.write_bytes(owner.encoded({"run": self.run, "job": self.job}))
                capture.update(attestationVerificationSha256=self.hash(self.native_proof), apiCanonicalSha256=self.hash(self.canonical_api))
                self.write(self.original_capture, capture); self.custody["originalCaptureSha256"] = self.hash(self.original_capture)
                code, value = self.reuse_entry()
                self.assertNotEqual(code, 0); self.assertFalse(value["originAuthenticated"])


class FixedLinuxVerifierTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()
        self.path=self.root/owner.LINUX_GH_RELATIVE
        self.path.parent.mkdir(parents=True,mode=0o755)
        self.addCleanup(patch.stopall)
        patch.object(owner,"TOOLING",self.root).start()
        patch.object(owner.sys,"platform","linux").start()

    def binary(self,size=None):
        with self.path.open("wb") as stream:
            stream.truncate(owner.LINUX_GH_BYTES if size is None else size)
        self.path.chmod(0o755)

    def test_missing_fixed_tool_does_not_fall_back_to_system_or_path_cli(self):
        with patch.dict(os.environ,{"PATH":str(self.root)}):
            with self.assertRaises((OSError,ValueError)):
                owner.verifier_executable()

    def test_exact_policy_size_and_hash_select_only_fixed_tool_without_execution(self):
        self.binary()
        class ExpectedHash:
            def update(self,_value): pass
            def hexdigest(self): return owner.LINUX_GH_SHA256
        with patch.object(owner.hashlib,"sha256",return_value=ExpectedHash()), \
             patch.object(owner.subprocess,"run") as native:
            self.assertEqual(owner.verifier_executable(),str(self.path))
            native.assert_not_called()

    def test_wrong_size_or_hash_is_refused(self):
        self.binary(3)
        with self.assertRaises(ValueError): owner.verifier_executable()
        self.binary()
        with self.assertRaises(ValueError): owner.verifier_executable()

    def test_leaf_or_parent_symlinks_and_writable_tool_are_refused(self):
        elsewhere=self.root/"other-gh"
        elsewhere.write_bytes(b"not a verifier")
        self.path.symlink_to(elsewhere)
        with self.assertRaises(ValueError): owner.verifier_executable()
        self.path.unlink();self.binary();self.path.chmod(0o777)
        with self.assertRaises(ValueError): owner.verifier_executable()
        self.path.chmod(0o755);self.path.parent.chmod(0o777)
        with self.assertRaises(ValueError): owner.verifier_executable()

    def test_wrong_owner_is_refused_before_hashing(self):
        self.binary()
        original=os.fstat
        def foreign(descriptor):
            value=original(descriptor)
            return SimpleNamespace(st_mode=value.st_mode,st_uid=os.getuid()+1000,
                                   st_size=value.st_size)
        with patch.object(owner.os,"fstat",side_effect=foreign), \
             patch.object(owner.hashlib,"sha256") as hashing:
            with self.assertRaises(ValueError): owner.verifier_executable()
            hashing.assert_not_called()

    def test_root_owned_setuid_or_setgid_binary_is_refused_before_hashing(self):
        self.binary()
        original=os.fstat
        for bits in (0o4000,0o2000):
            with self.subTest(bits=bits):
                def privileged(descriptor):
                    value=original(descriptor)
                    return SimpleNamespace(st_mode=value.st_mode|bits,st_uid=0,st_size=value.st_size)
                with patch.object(owner.os,"fstat",side_effect=privileged), \
                     patch.object(owner.hashlib,"sha256") as hashing:
                    with self.assertRaises(ValueError): owner.verifier_executable()
                    hashing.assert_not_called()

    def test_mac_keeps_existing_native_cli_without_fixed_linux_install(self):
        with patch.object(owner.sys,"platform","darwin"):
            self.assertEqual(owner.verifier_executable(),owner.GH)


if __name__=="__main__": unittest.main()
