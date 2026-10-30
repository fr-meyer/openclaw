"""Synthetic policy/derivation tests; never operational approval or source pins."""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

OWNER = Path(__file__).with_name("source_validation_contract_v109.py")
if not OWNER.is_file():
    OWNER = Path(__file__).parents[1] / "pipeline/scripts/fork-release/source_validation_contract_v109.py"
spec = importlib.util.spec_from_file_location("v109_contract_under_test", OWNER)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def source(sha="a", tree="b"):
    return {"sourceSha": sha * 40, "sourceTree": tree * 40,
        "manifestSha256": "1" * 64, "inventorySha256": "2" * 64,
        "fileSha256": {p: str(i + 3) * 64 for i, p in enumerate(m.INPUTS)}}


def binding():
    return {"schema": m.BINDINGS_SCHEMA, "status": "DISARMED", "campaignId": m.CAMPAIGN,
        "repository": m.REPOSITORY, "workflow": m.WORKFLOW, "pipelineBranch": m.PIPELINE_BRANCH,
        "sourceBranch": m.SOURCE_BRANCH, "baseBranch": m.BASE_BRANCH, "baseSha": m.BASE,
        "upstream": deepcopy(m.UPSTREAM), "baseline": {"sourceSha": m.BASELINE_SOURCE,
            "pipelineHead": m.BASELINE_PIPELINE, "sourceRunId": m.BASELINE_RUN, "runCount": 258,
            "runnerMinutes": 2944, "publicProofSha256": "7" * 64},
        "preparation": source(), "preparationCorrection": None,
        "validation": None, "correction": None, "authorization": None,
        "newRecoveryTests": ["src/state/startup-fts-repair.test.ts"]}


def authorization():
    # Synthetic dates and facts; never written into the prepared operational input.
    return {"schema": m.AUTH_SCHEMA, "label": "future-v109-grouped-20261101T000000Z",
        "approvedAt": "2026-11-01T00:00:00Z", "expiresAt": "2026-11-05T00:00:00Z",
        "maximumRunnerMinutes": 2500, "maximumSourceCampaigns": 2,
        "maximumParallelSourceJobs": 3, "maximumLockPreparations": 2,
        "diagnosticByteCeiling": m.DIAGNOSTIC_BYTES, "lockArtifactByteCeiling": m.ARTIFACT_BYTES,
        "imageExecutionAllowedHere": False, "cloudAccessAllowedHere": False,
        "newSecretsAllowedHere": False}


def populated():
    b = binding()
    lock, diff = b"lockfileVersion: '9.0'\n", b"diff --git a/pnpm-lock.yaml b/pnpm-lock.yaml\n"
    generation = {"schema": m.GENERATION_SCHEMA, "status": "derived_only",
        "sourceSha": b["preparation"]["sourceSha"], "sourceTree": b["preparation"]["sourceTree"],
        "pipelineHead": "e" * 40, "runId": "123456789", "runAttempt": 1,
        "packageSha256": b["preparation"]["fileSha256"]["package.json"],
        "workspaceSha256": b["preparation"]["fileSha256"]["pnpm-workspace.yaml"],
        "sourceLockSha256": b["preparation"]["fileSha256"]["pnpm-lock.yaml"],
        "generatedLockSha256": m.digest(lock),
        "ledgerSha256": b["preparation"]["fileSha256"][m.LEDGER],
        "nodeVersion": "24.22.1", "pnpmVersion": "12.15.0", "changedPaths": ["pnpm-lock.yaml"],
        "gitDiffSha256": m.digest(diff), "allOtherTrackedEntriesUnchanged": True,
        "startedAt": "2026-11-01T00:01:00Z", "finishedAt": "2026-11-01T00:03:00Z",
        "exitCode": 0, "timedOut": False, "cleanupSettled": None,
        "imageBuilt": False, "qualified": False, "productionAuthorized": False,
        "lockSecuritySha256":"1"*64,
        "registryEvidence": {"proofSha256":m.REGISTRY_PROOF_SHA256,
            "packages":deepcopy(list(m.REGISTRY_PINS)), "checkKind":"recheck_pinned_registry_metadata_age_and_integrity",
            "parentDependency":{"package":"@azure/msal-node","version":"7.1.1",
                "dependency":"@azure/msal-common","dependencyVersion":"16.14.3"},
            "registry": "https://registry.npmjs.org/", "checkedAt": "2026-11-01T00:02:00Z",
            "minimumAgeMinutes": 10080}}
    raw = m.encode(generation)
    h = source("c", "d")
    h["fileSha256"]["pnpm-lock.yaml"] = m.digest(lock)
    h["fileSha256"][m.LEDGER] = "8" * 64
    b["validation"] = {"source": h, "unchangedTreeSha256": "9" * 64, "preparationAttempt": 1,
        "generation": {"runId": generation["runId"], "runAttempt": 1,
            "pipelineHead": generation["pipelineHead"], "artifactId": 123,
            "artifactSha256": "f" * 64, "receiptSha256": m.digest(raw),
            "generatedLockSha256": generation["generatedLockSha256"], "gitDiffSha256": m.digest(diff)}}
    return b, {"pnpm-lock.yaml": lock, "lock.diff": diff, "generation.json": raw}


def preparation_correction(b):
    p = source("e", "f")
    p["fileSha256"]["pnpm-workspace.yaml"] = "8" * 64
    p["fileSha256"][m.LEDGER] = "9" * 64
    paths = sorted(("pnpm-workspace.yaml", m.LEDGER))
    return {"source": p, "parentSource": b["preparation"]["sourceSha"],
        "changedPaths": paths, "contentSha256": {p: "8" * 64 for p in paths},
        "unchangedTreeSha256": "7" * 64,
        "priorFailure": {"runId": "987654321", "pipelineHead": "e" * 40, "requestSha256": "d" * 64},
        "priorPhase": "lock-preparation"}


class ContractTests(unittest.TestCase):
    def test_disarmed_binding_structure(self):
        self.assertEqual(m.validate_bindings(binding())["status"], "DISARMED")

    def test_disarmed_cannot_activate(self):
        with self.assertRaisesRegex(m.Refusal, "v9.disarmed"):
            m.validate_bindings(binding(), active=True)

    def test_no_fabricated_postlock_source(self):
        with self.assertRaisesRegex(m.Refusal, "validation_not_bound"):
            m.request_for(binding(), "validation")

    def test_closed_preparation_request(self):
        b = binding(); r = m.request_for(b, "lock-preparation")
        self.assertEqual(m.validate_request(r, b)["profiles"], [])
        self.assertIsNone(r["generation"])

    def test_unknown_command_surface_refused(self):
        with self.assertRaises(m.Refusal):
            m.request_for(binding(), "build-image")

    def test_request_extra_fields_refused(self):
        b = binding(); r = m.request_for(b, "lock-preparation"); r["command"] = ["sh", "-c", "anything"]
        with self.assertRaisesRegex(m.Refusal, "closed_request"):
            m.validate_request(r, b)

    def test_exact_96_hour_clock(self):
        a = authorization(); self.assertEqual(m.validate_authorization(a), a)
        a["expiresAt"] = "2026-11-05T00:00:01Z"
        with self.assertRaisesRegex(m.Refusal, "96_hour"):
            m.validate_authorization(a)

    def test_authorization_boolean_minute_refused(self):
        a = authorization(); a["maximumLockPreparations"] = True
        with self.assertRaises(m.Refusal):m.validate_authorization(a)

    def test_no_cloud_secrets_or_image_permission(self):
        for field in ("imageExecutionAllowedHere", "cloudAccessAllowedHere", "newSecretsAllowedHere"):
            a = authorization(); a[field] = True
            with self.subTest(field=field), self.assertRaises(m.Refusal):m.validate_authorization(a)

    def test_future_or_expired_clock_refused(self):
        a = authorization()
        for now in (0, m.utc(a["expiresAt"]).timestamp()):
            with self.subTest(now=now), self.assertRaisesRegex(m.Refusal,"authorization_clock"):
                m.validate_authorization(a, now)

    def test_binding_unknown_fields_refused(self):
        b=binding();b["nativeRuntimeAllowed"]=True
        with self.assertRaises(m.Refusal):m.validate_bindings(b)

    def test_fixed_branch_and_official_tag(self):
        for field in ("pipelineBranch", "sourceBranch", "baseSha"):
            b=binding();b[field]="other"
            with self.subTest(field=field),self.assertRaises(m.Refusal):m.validate_bindings(b)
        b=binding();b["upstream"]["commit"]="f"*40
        with self.assertRaises(m.Refusal):m.validate_bindings(b)

    def test_source_input_file_set_closed(self):
        b=binding();b["preparation"]["fileSha256"][".npmrc"]="a"*64
        with self.assertRaises(m.Refusal):m.validate_bindings(b)

    def test_baseline_cannot_relabel_old_count(self):
        b=binding();b["baseline"]["runnerMinutes"]=2437
        with self.assertRaises(m.Refusal):m.validate_bindings(b)

    def test_recovery_selection_live_or_escape_refused(self):
        for value in (["../live.test.ts"],["src/state/foo.live.test.ts"],[]):
            b=binding();b["newRecoveryTests"]=value
            with self.subTest(value=value),self.assertRaises(m.Refusal):m.validate_bindings(b)

    def test_full_and_corrected_campaign_caps_include_boundaries(self):
        self.assertEqual(m.ADMISSION_MINUTES+sum(m.PROFILE_MINUTES.values())+m.FINAL_MINUTES,1075)
        self.assertEqual(m.budget(m.request_for(binding(),"lock-preparation"))["maximumBookedMinutes"],2470)
        self.assertLessEqual(2470,m.MAXIMUM_NEW_MINUTES)

    def test_second_preparation_unbound_or_third_refuses(self):
        b=binding()
        for number in (2,3):
            with self.subTest(number=number),self.assertRaises(m.Refusal):m.request_for(b,"lock-preparation",number)

    def test_second_preparation_requires_exact_reviewed_correction(self):
        b=binding();b["preparationCorrection"]=preparation_correction(b)
        m.validate_bindings(b);r=m.request_for(b,"lock-preparation",2)
        self.assertEqual(r["source"],b["preparationCorrection"]["source"])
        self.assertEqual(r["priorRunPins"],[b["preparationCorrection"]["priorFailure"]])
        r["source"]=deepcopy(b["preparation"])
        with self.assertRaises(m.Refusal):m.validate_request(r,b)

    def test_preparation_correction_no_parent_or_extra_package_change(self):
        for field,value in (("parentSource","1"*40),("priorPhase","arbitrary")):
            b=binding();b["preparationCorrection"]=preparation_correction(b);b["preparationCorrection"][field]=value
            with self.subTest(field=field),self.assertRaises(m.Refusal):m.validate_bindings(b)
        b=binding();b["preparationCorrection"]=preparation_correction(b)
        b["preparationCorrection"]["source"]["fileSha256"]["package.json"]="a"*64
        with self.assertRaises(m.Refusal):m.validate_bindings(b)

    def test_full_request_has_all15_fresh_profiles(self):
        b,_=populated();r=m.request_for(b,"validation")
        self.assertEqual(r["profiles"],list(m.PROFILES));m.validate_request(r,b)
        r["profiles"].pop()
        with self.assertRaises(m.Refusal):m.validate_request(r,b)

    def test_dependency_changes_cannot_hide_in_lock_derivation(self):
        b,_=populated();b["validation"]["source"]["fileSha256"]["package.json"]="c"*64
        with self.assertRaisesRegex(m.Refusal,"lock_only"):
            m.validate_bindings(b)

    def test_generation_complete_synthetic_fixture_accepts(self):
        b,files=populated();r=m.verify_generated_artifact(files,b)
        self.assertEqual(r["status"],"derived_only")

    def test_generation_tampered_hash_refuses(self):
        b,files=populated();files["pnpm-lock.yaml"]+=b"bad"
        with self.assertRaisesRegex(m.Refusal,"artifact_hashes"):
            m.verify_generated_artifact(files,b)

    def test_generation_extra_artifact_member_refuses(self):
        b,files=populated();files["secret.txt"]=b"anything"
        with self.assertRaises(m.Refusal):m.verify_generated_artifact(files,b)

    def test_generation_timeout_or_wrong_changed_path_refuses(self):
        for key,value in (("timedOut",True),("exitCode",124),("changedPaths",["package.json"]),("imageBuilt",True)):
            b,files=populated();g=m.parse(files["generation.json"]);g[key]=value;files["generation.json"]=m.encode(g)
            b["validation"]["generation"]["receiptSha256"]=m.digest(files["generation.json"])
            with self.subTest(key=key),self.assertRaises(m.Refusal):m.verify_generated_artifact(files,b)

    def test_registry_age_and_integrity_refuse(self):
        b,files=populated();g=m.parse(files["generation.json"]);e=g["registryEvidence"]
        for k,v in (("distIntegrity","sha1-short"),("version","7.1.0"),("publishedAt","2026-10-31T00:00:00Z")):
            bad=deepcopy(e);bad["packages"][0][k]=v
            with self.subTest(k=k),self.assertRaises(m.Refusal):m.validate_registry_evidence(bad,m.utc(g["finishedAt"]).timestamp())
        bad=deepcopy(e);bad["registry"]="https://other.invalid/"
        with self.assertRaises(m.Refusal):m.validate_registry_evidence(bad,m.utc(g["finishedAt"]).timestamp())
        bad=deepcopy(e);bad["checkedAt"]="2026-10-22T00:02:00Z"
        with self.assertRaisesRegex(m.Refusal,"seven_day_age"):
            m.validate_registry_evidence(bad,m.utc(bad["checkedAt"]).timestamp())

    def test_registry_explicit_timestamp_not_author_date(self):
        b,files=populated();g=m.parse(files["generation.json"]);e=g["registryEvidence"]
        self.assertEqual(m.validate_registry_evidence(e,m.utc(g["finishedAt"]).timestamp())["packages"][0]["publishedAt"],"2026-10-21T19:21:33.186Z")
        del e["packages"][0]["publishedAt"]
        with self.assertRaises(m.Refusal):m.validate_registry_evidence(e,m.utc(g["finishedAt"]).timestamp())

    def test_actual_pinned_public_registry_producer_rechecks(self):
        path=Path(__file__).parent/"candidates/v2026.10.9-source-only/registry-metadata.json"
        if not path.is_file():
            path=Path(__file__).parents[2]/"price-access-preparation-r1/registry-metadata-r1/PUBLIC-NPM-METADATA-HANDOFF.private.json"
        raw=path.read_bytes()
        value=m.recheck_registry_proof(raw,"2026-11-01T00:02:00Z")
        self.assertEqual(value["packages"],list(m.REGISTRY_PINS))
        self.assertEqual(value["parentDependency"]["dependencyVersion"],"16.14.3")
        with self.assertRaises(m.Refusal):m.recheck_registry_proof(raw+b" ","2026-11-01T00:02:00Z")

    def test_deterministic_derived_ledger_only_lock_result(self):
        b,_=populated();before={"schema":"openclaw.v109.fork-carry-reconciliation.v1","lockState":"pending_ci_derivation",
            "sourcePaths":[{"path":"a.ts","result":{"mode":"100644","blob":"a"*40},"disposition":"carry"},
                {"path":"pnpm-lock.yaml","result":{"mode":"100644","blob":"b"*40},"disposition":"pending"}],
            "selfExclusion":m.LEDGER,"note":"preserved"}
        after=m.parse(m.expected_derived_ledger(m.encode(before),"c"*40,b["validation"]["generation"]))
        self.assertEqual(after["sourcePaths"][0],before["sourcePaths"][0]);self.assertEqual(after["note"],before["note"])
        self.assertEqual(after["sourcePaths"][1]["result"]["blob"],"c"*40)
        self.assertEqual(set(after["lockDerivation"]),{"runId","attempt","artifactSha256","generatedLockSha256","receiptSha256"})
        self.assertEqual(after["lockState"],"ci_derived")

    def test_derived_ledger_duplicate_lock_row_refuses(self):
        b,_=populated();row={"path":"pnpm-lock.yaml","result":{"mode":"100644","blob":"a"*40}}
        old={"schema":"openclaw.v109.fork-carry-reconciliation.v1","lockState":"pending_ci_derivation","sourcePaths":[row,row]}
        with self.assertRaises(m.Refusal):m.expected_derived_ledger(m.encode(old),"c"*40,b["validation"]["generation"])

    def test_duplicate_json_and_constants_refuse(self):
        for raw in (b'{"a":1,"a":2}',b'{"a":NaN}'):
            with self.subTest(raw=raw),self.assertRaises(m.Refusal):m.parse(raw)

    def test_recovery_no_future_operational_identity_created(self):
        b=binding();self.assertIsNone(b["authorization"]);self.assertIsNone(b["validation"])
        self.assertIsNone(b["correction"]);self.assertEqual(b["status"],"DISARMED")


class ReviewedInterfaceDeltaTests(unittest.TestCase):
    def test_only_two_reviewed_synthetic_live_names_accepted(self):
        b=binding(); b["newRecoveryTests"]=sorted(m.SYNTHETIC_LIVE_UNIT_PATHS)
        self.assertEqual(m.validate_bindings(b),b)
        for path in ("src/agents/provider.live.test.ts", "test/scripts/live-provider.test.ts",
                "src/agents/tool-search.live-diagnostics-other.test.ts"):
            bad=deepcopy(b);bad["newRecoveryTests"]=sorted(bad["newRecoveryTests"]+[path])
            with self.subTest(path=path),self.assertRaisesRegex(m.Refusal,"reviewed_new_recovery"):
                m.validate_bindings(bad)

    def test_artifact_owner_forwards_explicit_phase_without_inferring_it(self):
        from unittest.mock import patch
        files={"pnpm-lock.yaml":b"lock", "lock.diff":b"diff", "generation.json":b"receipt"}
        receipt={"generatedLockSha256":m.digest(files["pnpm-lock.yaml"]),
            "gitDiffSha256":m.digest(files["lock.diff"])}
        with patch.object(m,"validate_generation",return_value=receipt) as validate:
            self.assertEqual(m.verify_generated_artifact(files,{},"correction"),receipt)
            validate.assert_called_once_with(b"receipt",{},"correction")
        with patch.object(m,"validate_generation",return_value=receipt) as validate:
            m.verify_generated_artifact(files,{})
            validate.assert_called_once_with(b"receipt",{},"validation")


class PipelinePreparationRecoveryTests(unittest.TestCase):
    def actual_binding(self):
        path=Path(__file__).parent/"candidates/v2026.10.9-source-only/ci-bindings.json"
        value=m.parse(path.read_bytes())
        # Replay the historical pre-H intake state in an isolated unit fixture.
        # Later all15 CI uses a real H validation binding; it must not change this
        # fixture's phase or be mistaken for missing live evidence.
        value["validation"]=None;value["correction"]=None
        return value

    def test_attempt2_reuses_original_real_g_without_h_or_empty_commit(self):
        b=self.actual_binding();m.validate_bindings(b,active=True)
        self.assertEqual(m.preparation_for(b,2),b["preparation"])
        self.assertIsNone(b["validation"]);self.assertIsNone(b["correction"])
        self.assertEqual(b["preparation"]["sourceSha"],"ba04217f6642091b94f396669318d068e6007ed7")
        q=m.request_for(b,"lock-preparation",2)
        self.assertEqual(q["source"],b["preparation"]);self.assertEqual(q["preparationAttempt"],2)
        self.assertEqual(q["priorRunPins"],[m.FAILED_PREPARATION_PIN]);self.assertIsNone(q["generation"])

    def test_original_attempt1_remains_valid_historical_request(self):
        b=self.actual_binding();b["preparationCorrection"]=None
        q=m.request_for(b,"lock-preparation",1)
        self.assertEqual(m.digest(m.encode(q)),m.FAILED_PREPARATION_PIN["requestSha256"])
        m.validate_request(q,b,active=True)

    def test_attempt2_without_closed_recovery_refuses(self):
        b=self.actual_binding();b["preparationCorrection"]=None
        with self.assertRaisesRegex(m.Refusal,"second_preparation_not_bound"):
            m.request_for(b,"lock-preparation",2)

    def test_changed_g_cannot_be_called_pipeline_only_recovery(self):
        b=self.actual_binding();b["preparationCorrection"]["source"]["sourceSha"]="f"*40
        with self.assertRaisesRegex(m.Refusal,"exact_pipeline_only"):
            m.validate_bindings(b)

    def test_other_prior_run_code_evidence_or_attempt_refuses(self):
        for field,value in (("reasonCode","v9.any_failure"),("evidenceSha256","a"*64),
                ("failedPreparationAttempt",2),("failedPreparationAttempt",True),
                ("nextPreparationAttempt",1),("nextPreparationAttempt",3)):
            b=self.actual_binding();b["preparationCorrection"][field]=value
            with self.subTest(field=field,value=value),self.assertRaises(m.Refusal):m.validate_bindings(b)
        b=self.actual_binding();b["preparationCorrection"]["priorFailure"]["runId"]="1234"
        with self.assertRaises(m.Refusal):m.validate_bindings(b)

    def test_closed_pipeline_shape_does_not_accept_source_edit_or_extra_fields(self):
        for extra in ({"changedPaths":[]},{"parentSource":"a"*40},{"sourceChanged":False}):
            b=self.actual_binding();b["preparationCorrection"].update(extra)
            with self.subTest(extra=extra),self.assertRaisesRegex(m.Refusal,"pipeline_recovery_fields"):
                m.validate_bindings(b)

    def test_source_correction_variant_retains_nonempty_path_requirement(self):
        b=self.actual_binding();b["preparationCorrection"]={"source":deepcopy(b["preparation"]),
            "parentSource":b["preparation"]["sourceSha"],"changedPaths":[],"contentSha256":{},
            "unchangedTreeSha256":"a"*64,"priorFailure":deepcopy(m.FAILED_PREPARATION_PIN),
            "priorPhase":"lock-preparation"}
        with self.assertRaisesRegex(m.Refusal,"correction_changed_paths"):m.validate_bindings(b)

    def test_one_correction_is_consumed_before_validation(self):
        b=self.actual_binding();b["correction"]={}
        with self.assertRaisesRegex(m.Refusal,"pipeline_correction_already_consumed"):
            m.validate_bindings(b)

    def test_actual_public_failure_evidence_is_closed_and_cannot_be_tampered(self):
        b=self.actual_binding();path=Path(__file__).parent/m.PREPARATION_FAILURE_EVIDENCE.split('/')[-1]
        path=Path(__file__).parent/"candidates/v2026.10.9-source-only"/path.name
        raw=path.read_bytes();e=m.validate_pipeline_recovery_evidence(raw,b)
        self.assertEqual(e["runId"],"40997868140");self.assertEqual(e["artifactCount"],0)
        for field in ("sourceCheckoutPerformed","lockGenerationExecuted","generationProduced"):
            self.assertIs(e[field],False)
        with self.assertRaisesRegex(m.Refusal,"evidence_digest"):
            m.validate_pipeline_recovery_evidence(raw+b" ",b)

    def test_advertised_pr_base_remains_unchanged_by_pipeline_recovery(self):
        self.assertEqual(m.BASE,"a65f70c5dad17b39bc3ee26ba92cde6d00bfb259")
        self.assertEqual(self.actual_binding()["baseSha"],m.BASE)
        # Actual merge-target/tree ownership is the runtime's typed DAG proof;
        # this request field continues to bind the advertised PR metadata.

    def test_time_money_attempt_privilege_envelope_not_expanded(self):
        b=self.actual_binding();q=m.request_for(b,"lock-preparation",2);v=m.budget(q)
        self.assertEqual(m.AUTH_HOURS,96);self.assertEqual(v["maximumNewMinutes"],2500)
        self.assertEqual(v["maximumLockPreparations"],2);self.assertEqual(v["maximumSourceCampaigns"],2)
        for k in ("imageExecutionAllowedHere","cloudAccessAllowedHere","newSecretsAllowedHere"):
            self.assertIs(b["authorization"][k],False)

    def test_pure_generated_source_proof_does_not_require_a_fake_g2(self):
        # Synthetic Git model only, not real H or native recovery evidence.
        from test_source_derivation_v109 import repository
        b,files,read,trees,gate,entries,content,parents=repository()
        b["preparationCorrection"]={"schema":m.PIPELINE_RECOVERY_SCHEMA,
            "source":deepcopy(b["preparation"]),"priorPhase":"lock-preparation",
            "priorFailure":deepcopy(m.FAILED_PREPARATION_PIN),"failedPreparationAttempt":1,
            "nextPreparationAttempt":2,"reasonCode":"v9.workflow_merge_parents",
            "evidenceSha256":m.PREPARATION_FAILURE_EVIDENCE_SHA256}
        b["validation"]["preparationAttempt"]=2
        proof=m.verify_derived_source(read,b,"validation",files["generation.json"],
            read_tree=trees,verify_lock=gate)
        self.assertEqual(proof["preparationAttempt"],2)
        self.assertFalse(proof["sourceCorrectionVerified"])
        self.assertEqual(proof["preparationSource"],b["preparation"]["sourceSha"])


if __name__ == "__main__":
    unittest.main()
