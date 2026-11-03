"""Synthetic protocol tests only; no candidate import, Git, package or API use."""
from copy import deepcopy
import hashlib
import json
import unittest

import source_contract_v110 as c
import lockfile_policy_v110 as lock


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def authorization():
    # Public projection of the actual approved scope, not an execution receipt.
    return {"schema": "openclaw.v110.source-authorization.v1",
        "recordedAt": "2026-11-03T09:12:23Z",
        "approvalReceiptSha256": "97931a883800bfa1c19df32054989c6fc3d9ff688ec181631ad8a333c058cc2d",
        "proposalSha256": "721662912807288539c324acd281d9e5b86526aa3ed70f8afd49564d93e7fb33",
        "expiresAt": "2026-11-06T03:14:21Z", "packageNotBefore": "2026-11-04T09:59:50Z",
        "stageRunnerMinutes": 2400, "totalRunnerMinutes": 25000,
        "totalTaxInclusiveUSD": "25.00", "maxMaterialGenerations": 2,
        "maxSubstantiveExecutions": 4, "maxConcurrentSourceJobs": 3,
        "imageBuildAllowed": False, "newAccessAllowed": False,
        "cloudAllowed": False, "productionAllowed": False}


def bindings():
    paths = ["scripts/fork-release/source_contract_v110.py",
        "scripts/fork-release/source_validation_v110.py",
        "scripts/fork-release/lockfile_policy_v110.py",
        "scripts/fork-release/source_validation_selection_v110.py",
        "scripts/fork-release/source_validation_v108.py",
        "scripts/fork-release/source_validation_v109.py",
        "scripts/fork-release/bounded_run_contract_v109.py"]
    return {"schema": "openclaw.v110.ci-bindings.v1", "repository": "fr-meyer/openclaw",
        "draftPr": {"number": 39, "headBranch": "task/v110-source-validation",
            "baseBranch": "release-pipeline/v105-image-only-20261024",
            "baseSha": "918890b9f72b2d0372995362e8ea3088e0f87431"},
        "pipeline": {"codeCommit": "a" * 40, "codeTree": "b" * 40,
            "codeFiles": {p: {"sha256": "c" * 64, "bytes": 20} for p in paths}},
        "authorization": authorization(),
        "ownerWindow": {"referenceSha256": "d" * 64, "checkedAt": "2026-11-04T09:59:50Z",
            "expiresAt": "2026-11-05T23:00:00Z", "source109Released": True,
            "source109NeededAttemptsUsed": 270, "source109BookedArtifactBytes": 783765,
            "source109LatestLedgerSha256": "8" * 64, "maximumSourceJobs": 3},
        "generations": [{"number": 1, "material": {
            "sourceSha": "034a1c09b80d70dfbb462650730102cfd6dee96e",
            "sourceTree": "8ad99415b29a89cfede24980e7440de7fbb5cead",
            "fileSha256": dict(c.INITIAL_INPUT_HASHES)}, "correction": None, "validation": None}],
        "activeGeneration": 1, "newRecoveryTests": list(c.RECOVERY_TESTS)}


def security(before, generated):
    return {"schema": "openclaw.v110.generated-lock-security.v1",
        "beforeLockSha256": before, "generatedLockSha256": generated,
        "workspaceImporters": 3,
        "criticalVersionSets": {"fast-uri": ["4.2.3"], "follow-redirects": ["1.16.2"],
            "minimatch": ["11.0.1"], "qs": ["6.16.1"], "zod": ["4.6.6"],
            "undici": ["8.12.2"], "npm": ["12.2.1"], "vitest": ["5.0.5"],
            "@azure/msal-node": ["7.1.1"], "@azure/msal-common": ["16.14.3"]},
        "msalCommonConsumers": {"@azure/msal-node@7.1.1": "16.14.3"},
        "patchesSha256": sha(lock.canonical({name: value[1] for name, value in lock.PATCHES.items()})),
        "closureAge": {"schema": "openclaw.v110.complete-closure-age.v1",
            "observedAt": "2026-11-04T10:10:00Z", "minimumReleaseAgeMinutes": 10080,
            "strict": True, "selectedTupleCount": 20, "checkedTupleCount": 20,
            "registryPackageCount": 17, "unknownTupleCount": 0,
            "allSelectedExclusionsAlsoChecked": True, "tuplesSha256": "e" * 64,
            "maximumPublishedAt": "2026-10-28T09:59:49.641Z",
            "maximumEligibleAt": "2026-11-04T09:59:50Z",
            "rawRegistryMetadataRetainedInArtifact": False},
        "allSelectedRegistryIntegritiesMatched": True, "nativeAdvisoryAuditsStillRequired": True,
        "exactGeneratedDiffReviewRequiredBeforeCommit": True,
        "unrelatedGeneratedDiffAutomaticallyApproved": False,
        "qualified": False, "imageBuilt": False, "productionAuthorized": False}


def artifact_fixture():
    b = bindings(); m = b["generations"][0]["material"]
    generated, diff = b"synthetic generated lock\n", b"synthetic lock delta\n"
    receipt = {"schema": "openclaw.v110.lock-derivation.v1", "status": "derived_only",
        "sourceSha": m["sourceSha"], "sourceTree": m["sourceTree"],
        "pipelineHead": "f" * 40, "runId": "123456", "runAttempt": 1,
        "packageSha256": m["fileSha256"]["package.json"],
        "workspaceSha256": m["fileSha256"]["pnpm-workspace.yaml"],
        "sourceLockSha256": m["fileSha256"]["pnpm-lock.yaml"],
        "ledgerSha256": m["fileSha256"][c.LEDGER],
        "generatedLockSha256": sha(generated), "gitDiffSha256": sha(diff),
        "nodeVersion": "24.22.1", "pnpmVersion": "12.15.0", "changedPaths": ["pnpm-lock.yaml"],
        "allOtherTrackedEntriesUnchanged": True, "startedAt": "2026-11-04T10:00:00Z",
        "finishedAt": "2026-11-04T10:10:00Z", "exitCode": 0, "timedOut": False,
        "cleanupSettled": True, "imageBuilt": False, "qualified": False,
        "productionAuthorized": False, "lockSecurity": security(m["fileSha256"]["pnpm-lock.yaml"], sha(generated))}
    files = {"pnpm-lock.yaml": generated, "lock.diff": diff, "generation.json": c.encode(receipt)}
    producer = {"authenticated": True, "runId": "123456", "pipelineHead": "f" * 40,
        "artifactId": 654321, "artifactSha256": "a" * 64, "runAttempt": 1, "conclusion": "success"}
    p = {k: producer[k] for k in ("runId", "pipelineHead", "artifactId", "artifactSha256")}
    p.update(receiptSha256=sha(files["generation.json"]), generatedLockSha256=sha(generated), gitDiffSha256=sha(diff))
    return b, receipt, files, producer, p


def native_producer():
    b, receipt, files, producer, p = artifact_fixture()
    run = {"id": 123456, "repository": {"id": 42, "full_name": "fr-meyer/openclaw", "private": False},
        "head_repository": {"id": 42, "full_name": "fr-meyer/openclaw"},
        "actor": {"login": "fr-meyer"}, "triggering_actor": {"login": "fr-meyer"},
        "head_sha": "f" * 40, "head_branch": "task/v110-source-validation",
        "path": ".github/workflows/future-v110-source-validation.yml", "event": "pull_request",
        "run_attempt": 1, "status": "completed", "conclusion": "success",
        "created_at": "2026-11-04T09:59:50Z", "pull_requests": [{"number": 39,
            "head": {"sha": "f" * 40, "ref": "task/v110-source-validation"},
            "base": {"sha": c.BASE, "ref": c.BASE_BRANCH}}]}
    artifact = {"id": 654321, "name": "v110-lock-preparation-123456-attempt1",
        "digest": "sha256:" + "a" * 64, "size_in_bytes": 2000, "expired": False,
        "created_at": "2026-11-04T10:11:00Z", "expires_at": "2026-11-07T10:11:00Z",
        "workflow_run": {"id": 123456, "head_sha": "f" * 40,
            "head_branch": "task/v110-source-validation", "repository_id": 42, "head_repository_id": 42}}
    return b, run, artifact, producer, p


class ContractTests(unittest.TestCase):
    def test_json_rejects_duplicate_keys_constants_and_bad_encoding(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'\xff', b'{'):
            with self.subTest(raw=raw), self.assertRaises(c.Refusal): c.parse(raw)

    def test_disarmed_records_can_prepare_but_never_admit(self):
        b = bindings(); b["draftPr"]["number"] = None
        b["pipeline"].update(codeCommit=None, codeTree=None, codeFiles={})
        b["ownerWindow"] = b["authorization"] = None
        b["generations"][0]["material"]["sourceSha"] = None
        c.validate_bindings(b)
        with self.assertRaises(c.Refusal): c.validate_bindings(b, True, "2026-11-04T10:00:00Z")

    def test_fixed_scope_does_not_accept_more_money_minutes_or_images(self):
        for key, value in (("stageRunnerMinutes", 2401), ("totalTaxInclusiveUSD", "26.00"),
                           ("imageBuildAllowed", True), ("newAccessAllowed", True), ("maxConcurrentSourceJobs", 4)):
            a = authorization(); a[key] = value
            with self.subTest(key=key), self.assertRaises(c.Refusal): c.validate_authorization(a)

    def test_age_floor_and_deadline_are_not_advisory(self):
        for stamp in ("2026-11-04T09:59:49Z", "2026-11-06T03:14:21Z"):
            with self.subTest(stamp=stamp), self.assertRaises(c.Refusal): c.validate_authorization(authorization(), True, stamp)
        c.validate_authorization(authorization(), True, "2026-11-04T09:59:50Z")

    def test_operator_observation_clock_is_not_invented_user_seconds(self):
        a = authorization(); a["recordedAt"] = "2026-11-03T09:11:00Z"
        with self.assertRaises(c.Refusal): c.validate_authorization(a)

    def test_active_request_binds_target_source_and_all_protocol_types(self):
        b = bindings(); request = c.request_for(b, "lock-preparation")
        c.validate_request(request, b, True, "2026-11-04T10:00:00Z")
        for key, value in (("generation", True), ("imageBuilt", 0), ("campaign", "future-v109-grouped-validation-20261030")):
            bad = deepcopy(request); bad[key] = value
            with self.subTest(key=key), self.assertRaises(c.Refusal): c.validate_request(bad, b)

    def test_request_rejects_changed_binding_even_if_source_unchanged(self):
        b = bindings(); request = c.request_for(b, "lock-preparation")
        b["draftPr"]["number"] = 40
        with self.assertRaises(c.Refusal): c.validate_request(request, b)

    def test_current_base_binding_refuses_historical_pr_projection(self):
        self.assertEqual(c.BASE, "918890b9f72b2d0372995362e8ea3088e0f87431")
        b = bindings()
        c.validate_bindings(b)
        b["draftPr"]["baseSha"] = "a65f70c5dad17b39bc3ee26ba92cde6d00bfb259"
        with self.assertRaisesRegex(c.Refusal, "v110.pr_identity"): c.validate_bindings(b)
        b, run, artifact, _, p = native_producer()
        run["pull_requests"][0]["base"]["sha"] = "a65f70c5dad17b39bc3ee26ba92cde6d00bfb259"
        with self.assertRaisesRegex(c.Refusal, "v110.native_producer_pr_binding"):
            c.validate_producer(run, artifact, p, b["draftPr"], "a" * 64, "2026-11-04T10:12:00Z")

    def test_missing_code_member_and_other_pr_route_refuse_before_execution(self):
        for change in ("member", "branch", "number"):
            b = bindings()
            if change == "member": del b["pipeline"]["codeFiles"]["scripts/fork-release/source_validation_v108.py"]
            elif change == "branch": b["draftPr"]["headBranch"] = "task/v107-source-binding"
            else: b["draftPr"]["number"] = True
            with self.subTest(change=change), self.assertRaises(c.Refusal): c.validate_bindings(b, True, "2026-11-04T10:00:00Z")

    def test_workflow_is_bound_by_event_not_cyclic_code_manifest(self):
        b = bindings(); b["pipeline"]["codeFiles"][c.WORKFLOW] = {"sha256": "1" * 64, "bytes": 100}
        with self.assertRaises(c.Refusal): c.validate_bindings(b)

    def test_removed_migration_case_cannot_become_partial_success(self):
        b = bindings(); b["newRecoveryTests"].pop()
        with self.assertRaises(c.Refusal): c.validate_bindings(b)

    def test_owner_release_is_explicit_and_must_cover_phase(self):
        b = bindings(); b["ownerWindow"]["source109Released"] = False
        with self.assertRaises(c.Refusal): c.validate_bindings(b, True, "2026-11-04T10:00:00Z")
        b = bindings(); b["ownerWindow"]["expiresAt"] = "2026-11-04T10:45:00Z"
        with self.assertRaises(c.Refusal): c.validate_bindings(b, True, "2026-11-04T10:00:00Z")

    def test_unexpired_explicit_intent_is_not_a_five_minute_cache(self):
        b = bindings()
        c.validate_bindings(b, True, "2026-11-04T11:00:00Z")
        c.validate_admitted_window(b["ownerWindow"], "2026-11-04T11:00:00Z", "2026-11-04T12:30:00Z")
        with self.assertRaises(c.Refusal): c.validate_admitted_window(b["ownerWindow"], "2026-11-04T11:00:00Z", "2026-11-05T23:00:00Z")

    def test_validation_window_uses_bounded_critical_path_not_generation_duration(self):
        window = bindings()["ownerWindow"]
        window["expiresAt"] = "2026-11-04T18:00:00Z"
        c.validate_window(window, True, "2026-11-04T10:00:00Z", "validation")
        with self.assertRaises(c.Refusal): c.validate_window(window, True, "2026-11-04T10:00:01Z", "validation")

    def test_owner_window_cannot_forget_retained_artifacts_or_latest_ledger(self):
        for key, value in (("source109BookedArtifactBytes", 783764),
                           ("source109BookedArtifactBytes", c.DIAGNOSTIC_BYTES + 1),
                           ("source109BookedArtifactBytes", True),
                           ("source109LatestLedgerSha256", None)):
            window = bindings()["ownerWindow"]; window[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(c.Refusal): c.validate_window(window)
        window = bindings()["ownerWindow"]; del window["source109LatestLedgerSha256"]
        with self.assertRaises(c.Refusal): c.validate_window(window)

    def test_first_material_tree_and_five_inputs_are_the_reviewed_draft(self):
        for key in ("sourceTree", "fileSha256"):
            b = bindings()
            if key == "sourceTree": b["generations"][0]["material"][key] = "0" * 40
            else: b["generations"][0]["material"][key]["package.json"] = "0" * 64
            with self.subTest(key=key), self.assertRaises(c.Refusal): c.validate_bindings(b)

    def test_validation_requires_actual_h_not_a_preparation_label(self):
        with self.assertRaises(c.Refusal): c.request_for(bindings(), "validation")

    def test_authentic_files_are_accepted_before_h_exists(self):
        b, receipt, files, producer, _ = artifact_fixture()
        self.assertIsNone(b["generations"][0]["validation"])
        self.assertEqual(c.verify_generated_artifact(files, b, producer=producer), receipt)
        self.assertIsNone(b["generations"][0]["validation"])

    def test_extra_artifact_member_wrong_hash_and_failed_cleanup_refuse(self):
        for kind in ("extra", "lock", "cleanup", "foreign_run"):
            b, _, files, producer, _ = artifact_fixture()
            if kind == "extra": files["private.txt"] = b"synthetic"
            elif kind == "lock": files["pnpm-lock.yaml"] += b"tampered"
            elif kind == "cleanup":
                raw = c.parse(files["generation.json"]); raw["cleanupSettled"] = False; files["generation.json"] = c.encode(raw)
            else: producer["runId"] = "123457"
            with self.subTest(kind=kind), self.assertRaises((c.Refusal, lock.LockRefusal)): c.verify_generated_artifact(files, b, producer=producer)

    def test_incomplete_full_closure_cannot_use_good_source_hashes(self):
        b, _, files, producer, _ = artifact_fixture()
        raw = c.parse(files["generation.json"]); raw["lockSecurity"]["closureAge"]["unknownTupleCount"] = 1
        files["generation.json"] = c.encode(raw)
        with self.assertRaises(lock.LockRefusal): c.verify_generated_artifact(files, b, producer=producer)

    def test_native_producer_binds_independent_download_and_native_run(self):
        b, run, artifact, expected, p = native_producer()
        self.assertEqual(c.validate_producer(run, artifact, p, b["draftPr"], "a" * 64, "2026-11-04T10:12:00Z"), expected)

    def test_later_pr_head_does_not_replace_immutable_producer_run_head(self):
        b, run, artifact, expected, p = native_producer()
        run["pull_requests"][0]["head"]["sha"] = "1" * 40
        self.assertEqual(c.validate_producer(run, artifact, p, b["draftPr"], "a" * 64, "2026-11-04T10:12:00Z"), expected)
        run["head_sha"] = "1" * 40
        with self.assertRaises(c.Refusal): c.validate_producer(run, artifact, p, b["draftPr"], "a" * 64, "2026-11-04T10:12:00Z")

    def test_self_declared_manifest_cannot_replace_native_artifact_identity(self):
        for kind in ("digest", "workflow", "actor", "attempt", "expiry", "pr", "repo"):
            b, run, artifact, _, p = native_producer()
            if kind == "digest": artifact["digest"] = "sha256:" + "b" * 64
            elif kind == "workflow": run["path"] = ".github/workflows/future-v109-source-validation.yml"
            elif kind == "actor": run["actor"]["login"] = "other"
            elif kind == "attempt": run["run_attempt"] = 2
            elif kind == "expiry": artifact["expired"] = True
            elif kind == "pr": run["pull_requests"][0]["number"] = 28
            else: run["head_repository"]["full_name"] = "other/openclaw"
            with self.subTest(kind=kind), self.assertRaises(c.Refusal): c.validate_producer(run, artifact, p, b["draftPr"], "a" * 64, "2026-11-04T10:12:00Z")

    def test_malformed_native_nested_records_refuse_with_a_safe_code(self):
        for key in ("actor", "triggering_actor"):
            b, run, artifact, _, p = native_producer(); run[key] = None
            with self.subTest(key=key), self.assertRaises(c.Refusal): c.validate_producer(run, artifact, p, b["draftPr"], "a" * 64, "2026-11-04T10:12:00Z")
        b, run, artifact, _, p = native_producer(); run["pull_requests"][0]["head"] = []
        with self.assertRaises(c.Refusal): c.validate_producer(run, artifact, p, b["draftPr"], "a" * 64, "2026-11-04T10:12:00Z")

    def test_authentication_bit_is_not_truthiness(self):
        b, _, files, producer, _ = artifact_fixture(); producer["authenticated"] = 1
        with self.assertRaises(c.Refusal): c.verify_generated_artifact(files, b, producer=producer)

    def test_derived_ledger_changes_only_lock_result_and_actual_receipt(self):
        _, _, _, _, p = artifact_fixture()
        before = {"schema": "openclaw.v110.fork-carry-reconciliation.v1",
            "lockState": "pending_secretless_ci_derivation", "historical": {"kept": "unchanged"},
            "sourcePaths": [{"path": "pnpm-lock.yaml", "result": {"mode": "100644", "blob": "1" * 40, "sha256": "2" * 64}, "disposition": "pending"},
                            {"path": "src/owner.ts", "result": {"mode": "100644", "blob": "3" * 40, "sha256": "4" * 64}}]}
        raw = c.encode(before); derived = c.parse(c.expected_derived_ledger(raw, "5" * 40, p))
        self.assertEqual(derived["historical"], {"kept": "unchanged"})
        self.assertEqual(derived["sourcePaths"][1], before["sourcePaths"][1])
        self.assertEqual(derived["sourcePaths"][0]["result"], {"mode": "100644", "blob": "5" * 40, "sha256": p["generatedLockSha256"]})
        self.assertEqual(derived["lockDerivation"]["artifactId"], 654321)
        self.assertEqual(c.encode(before), raw)
        with self.assertRaises(c.Refusal): c.expected_derived_ledger(c.encode(derived), "5" * 40, p)

    def test_no_third_material_generation_or_unreviewed_second_generation(self):
        b = bindings(); b["generations"].append(deepcopy(b["generations"][0])); b["generations"][1]["number"] = 2
        with self.assertRaises(c.Refusal): c.validate_bindings(b)
        b["generations"].append(deepcopy(b["generations"][0]))
        with self.assertRaises(c.Refusal): c.validate_bindings(b)


class DerivedTreeTests(unittest.TestCase):
    """Synthetic Git protocol fixture; never represented as native Git proof."""
    def fixture(self):
        _, _, _, _, pinset = artifact_fixture()
        old = {p: ("synthetic " + p).encode() for p in c.INPUTS}
        old[c.LEDGER] = c.encode({"schema": "openclaw.v110.fork-carry-reconciliation.v1",
            "lockState": "pending_secretless_ci_derivation", "sourcePaths": [{
                "path": "pnpm-lock.yaml", "result": {"mode": "100644", "blob": "1" * 40,
                "sha256": sha(old["pnpm-lock.yaml"])}, "disposition": "pending"}]})
        new = dict(old); new["pnpm-lock.yaml"] = b"synthetic generated lock\n"
        blob = hashlib.sha1(b"blob " + str(len(new["pnpm-lock.yaml"])).encode() + b"\0" + new["pnpm-lock.yaml"]).hexdigest()
        # Independent expected wire record; do not manufacture expected bytes
        # through expected_derived_ledger(), the function later under test.
        wire = json.loads(old[c.LEDGER]); wire["lockState"] = "ci_derived"
        wire["sourcePaths"][0]["result"] = {"mode": "100644", "blob": blob, "sha256": sha(new["pnpm-lock.yaml"])}
        wire["sourcePaths"][0]["disposition"] = "AUTHENTIC_CI_DERIVED_LOCK_ONLY"
        wire["lockDerivation"] = {"runId": "123456", "attempt": 1, "artifactId": 654321,
            "artifactSha256": "a" * 64, "receiptSha256": pinset["receiptSha256"],
            "generatedLockSha256": sha(new["pnpm-lock.yaml"])}
        new[c.LEDGER] = (json.dumps(wire, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode()
        objects = {"1" * 40: old, "2" * 40: new}; trees = {}
        for commit, data in objects.items():
            trees[commit] = {p: ("100644", "blob", hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()) for p, raw in data.items()}
        material = {"sourceSha": "1" * 40, "sourceTree": "3" * 40, "fileSha256": {p: sha(v) for p, v in old.items()}}
        unchanged = [[p, *trees["1" * 40][p]] for p in sorted(old) if p not in (c.LEDGER, "pnpm-lock.yaml")]
        witness = sha(json.dumps(unchanged, sort_keys=True, separators=(",", ":"), allow_nan=False).encode())
        validation = {"source": {"sourceSha": "2" * 40, "sourceTree": "4" * 40,
            "fileSha256": {p: sha(v) for p, v in new.items()}}, "generation": pinset, "unchangedTreeSha256": witness}
        parents = ["1" * 40]
        def read(*args):
            if args[0] == "rev-parse": return (("3" if args[1].startswith("1") else "4") * 40 + "\n").encode()
            if args[:3] == ("show", "-s", "--format=%P"): return (" ".join(parents) + "\n").encode()
            if args[0] == "show":
                commit, name = args[1].split(":", 1); return objects[commit][name]
            raise AssertionError(args)
        return material, validation, objects, trees, parents, read

    def test_real_derivation_rule_accepts_only_genuine_lock_and_ledger_delta(self):
        material, validation, _, trees, _, read = self.fixture()
        self.assertEqual(c._verify_h_delta(read, lambda sha, tree: trees[sha], material, validation), trees["2" * 40])

    def test_unrelated_file_change_cannot_hide_behind_good_lock_receipt(self):
        material, validation, objects, trees, _, read = self.fixture()
        raw = b"unreviewed source change"; objects["2" * 40]["package.json"] = raw
        validation["source"]["fileSha256"]["package.json"] = sha(raw)
        trees["2" * 40]["package.json"] = ("100644", "blob", hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest())
        with self.assertRaisesRegex(c.Refusal, "v110.derived_exact_delta"):
            c._verify_h_delta(read, lambda sha, tree: trees[sha], material, validation)

    def test_wrong_derived_parent_refuses_before_tree_delta_acceptance(self):
        material, validation, _, trees, parents, read = self.fixture(); parents[:] = ["5" * 40]
        with self.assertRaisesRegex(c.Refusal, "v110.derived_single_parent"):
            c._verify_h_delta(read, lambda sha, tree: trees[sha], material, validation)

    def test_matching_derived_bytes_do_not_allow_executable_or_symlink_inputs(self):
        for name in ("pnpm-lock.yaml", c.LEDGER):
            for mode in ("100755", "120000"):
                material, validation, _, trees, _, read = self.fixture()
                _, kind, blob = trees["2" * 40][name]
                trees["2" * 40][name] = (mode, kind, blob)
                with self.subTest(path=name, mode=mode), self.assertRaisesRegex(c.Refusal, "v110.derived_regular_inputs"):
                    c._verify_h_delta(read, lambda sha, tree: trees[sha], material, validation)


if __name__ == "__main__":
    unittest.main()
