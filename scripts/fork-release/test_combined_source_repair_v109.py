"""Synthetic approved Gen6/conditional-Gen7 boundaries; no candidate execution."""
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch
import os
import re
import socket
import subprocess
import textwrap
import time
import unittest
import urllib.request

import bounded_run_contract_v109 as run
import lockfile_policy_v109 as lock
import npm_vendor_derivation_v109 as vendor
import release
import source_reconciliation_v109 as recon
import source_validation_contract_v109 as policy
import source_validation_v109 as controller
from test_vendor_repair_continuation_v109 import grant as historical_grant
from test_h3_source_stage_v109 import fixture as historical_bindings


HERE = Path(__file__).resolve().parent


def family(count):
    value = {"schema": policy.H3_FAMILY_SCHEMA, "publicAmendmentSha256": run.H3_AMENDMENT_SHA256,
        "anchor": deepcopy(policy.H3_ANCHOR), "generations": []}
    previous = deepcopy(value["anchor"])
    for number in range(1, count + 1):
        paths = ({"package.json"} if number == 1 else {vendor.PRODUCER} if number == 2 else
            {"test/v108-remediation-security.test.mjs"} if number == 3 else
            set(policy.H3_VENDOR_CONTINUATION_PATHS) if number == 4 else
            set(policy.H3_VENDOR_PAYLOAD_PATHS) if number == 5 else set(policy.H3_COMBINED_SOURCE_REPAIR_PATHS))
        paths.add(policy.LEDGER)
        source = deepcopy(previous)
        source.update(sourceSha=format(number, "040x"), sourceTree=format(number + 100, "040x"))
        value["generations"].append({"number": number, "parentSource": deepcopy(previous), "preparation": source,
            "changedPaths": sorted(paths), "contentSha256": {name: "c" * 64 for name in paths},
            "unchangedTreeSha256": "d" * 64, "validation": None})
        previous = source
    return value


def grant(number=6):
    value = historical_grant(True, number)
    value["sourceSuccessorAmendment"].update(run.h3_stage_descriptor(True, True))
    value["sourceSuccessorAmendment"]["vendorRepairContinuation"] = run.vendor_repair_combined_source_allocation()
    value["expiresAt"] = "2026-11-07T03:14:21Z"
    value["nextExecution"].update(sequence=25, preparationAttempt=17)
    value["nextExecution"]["reservations"]["incidental"] = 194
    return value


def bindings(number=6):
    value = historical_bindings()
    source_family = family(number)
    source = source_family["generations"][-1]["preparation"]
    value.update(sourceSuccessor=source_family, preparation=source, validation=None)
    value["ciRunGrant"].update(grant(number))
    digest = policy.digest(policy.canonical(source_family))
    amendment = value["ciRunGrant"]["sourceSuccessorAmendment"]
    amendment.update(sourceFamilySha256=digest)
    value["ciRunGrant"]["nextExecution"].update(source=source, sourceFamilySha256=digest)
    return value


class CombinedSourceRepairTests(unittest.TestCase):
    def setUp(self):
        for owner, name in ((subprocess, "Popen"), (socket, "socket"),
                (urllib.request, "urlopen"), (urllib.request, "build_opener")):
            guard = patch.object(owner, name, side_effect=AssertionError("real host/network action forbidden"))
            guard.start(); self.addCleanup(guard.stop)

    def test_exact_approved_projection_carries_unused_once(self):
        value = run.vendor_repair_combined_source_allocation()
        self.assertEqual(value["resourceAllocationRecord"], {
            "decisionSha256": "dc24e48bfe15dcb343affc4e04573fca260fdb119560d2a4e47332a02e0cd423",
            "kind": "human-approved-source-repair-scope-extension", "newHumanApproval": True})
        self.assertEqual(run.digest(value["resourceAllocationRecord"]),
            "cd6a9bb8612967df27906094f31a694a842a9bfe05ad1c459e71b84ba1b876be")
        self.assertEqual(sum(value["privateComponentMaximumMinutes"].values()), 3122)
        self.assertEqual(sum(value["vendorComponentMaximumMinutes"].values()), 3192)
        self.assertEqual(sum(value["stagePools"].values()), 3873)
        self.assertEqual(sum(value["futurePools"].values()), 2300)
        self.assertEqual(value["futureEnvelopeRunnerMinutes"] - value["carriedUnusedRunnerMinutes"], 832)
        self.assertNotIn("maximumValidationWaves", value)
        self.assertNotIn("maximumAdditionalPreparations", value)
        self.assertEqual(value["plannedFullCostValidationSlots"], 2)
        self.assertEqual(value["plannedFullCostPreparationSlots"], 2)

    def test_every_projection_field_and_nested_limit_is_closed(self):
        expected = run.vendor_repair_combined_source_allocation()
        for key in expected:
            bad = deepcopy(expected); bad[key] = None
            with self.subTest(key=key), self.assertRaises((ValueError, TypeError)):
                run.validate_vendor_repair_continuation(bad)
        for key, child in expected.items():
            if type(child) is not dict: continue
            for item in child:
                bad = deepcopy(expected); bad[key][item] = False if child[item] is True else True
                with self.subTest(key=key, item=item), self.assertRaises(ValueError):
                    run.validate_vendor_repair_continuation(bad)
        bad = deepcopy(expected); bad["newAccess"] = True
        with self.assertRaises(ValueError): run.validate_vendor_repair_continuation(bad)
        self.assertIs(run.validate_vendor_repair_continuation(expected), expected)
        self.assertEqual(run.vendor_continuation_from_digest(run.digest(expected)), expected)

    def test_generations_six_and_seven_require_own_new_marker(self):
        for number in (6, 7):
            value = grant(number)
            self.assertEqual(run.source_successor_amendment(value)["sourceGeneration"], number)
            self.assertEqual(run.effective_expires_at(value), "2026-11-07T03:14:21Z")
            self.assertEqual(run.maximum_new_minutes(value), 25000)
            value["sourceSuccessorAmendment"]["vendorRepairContinuation"] = run.vendor_repair_derivation_recovery_allocation()
            with self.subTest(number=number), self.assertRaises(ValueError): run.source_successor_amendment(value)
        for number in (1, 3, 4, 5, 8, True):
            with self.subTest(number=number), self.assertRaises(ValueError): run.source_successor_amendment(grant(number))

    def test_new_descriptor_cannot_change_old_authority_and_vice_versa(self):
        old = historical_grant(True, 5)
        self.assertEqual(run.effective_expires_at(old), "2026-11-06T03:14:21Z")
        self.assertEqual(run.source_successor_amendment(old)["maximumStageBookedMinutes"], 5915)
        value = grant(); value["sourceSuccessorAmendment"].update(run.h3_stage_descriptor(True))
        with self.assertRaises(ValueError): run.source_successor_amendment(value)
        value = grant(); value["expiresAt"] = "2026-11-08T03:14:21Z"
        with self.assertRaises(ValueError): run.maximum_new_minutes(value)
        with self.assertRaises(ValueError): run.h3_stage_descriptor(False, True)

    def test_two_planning_slots_do_not_reset_or_limit_needed_records(self):
        value = grant(); plan = value["nextExecution"]
        self.assertIs(run.validate_plan(plan), plan)
        plan.update(sequence=999, preparationAttempt=1001)
        self.assertIs(run.validate_plan(plan), plan)
        self.assertEqual(run.maximum_new_minutes(value), 25000)
        self.assertEqual((value["maximumAdditionalAttempts"], value["maximumStageAttempts"]), (1000, 1042))
        value["maximumAdditionalAttempts"] = 1001
        with self.assertRaises(ValueError): run.maximum_new_minutes(value)

    def test_prefix_preserving_cumulative_budget_and_global_projection(self):
        value = grant()
        components = {"preparationObservedMinutes": 220, "sourceObservedMinutes": 1039,
            "incidentalObservedMinutes": 134, "imageObservedMinutes": 0,
            "remainingImageFamilyReserveMinutes": 180, "remainingIncidentalReserveMinutes": 60}
        result = run.validate_h3_budget(value, value["nextExecution"], 3608, 0, components)
        self.assertEqual(result["remainingStagePoolReservationMinutes"], 2300 + 180)
        self.assertEqual(result["totalBookedMinutes"], 2215 + 3873)
        self.assertEqual(result["totalBookedMinutes"] + 2400, 8488)
        self.assertEqual(result["maximumNewMinutes"], 25000)
        self.assertEqual(value["moneyCeilingUSD"], "25.00")
        with self.assertRaises(ValueError): run.validate_h3_budget(value, value["nextExecution"], 3609, 0, components)
        for name, maximum in (("preparationObservedMinutes", 310), ("sourceObservedMinutes", 3189),
                ("incidentalObservedMinutes", 194), ("imageObservedMinutes", 180)):
            bad = dict(components); bad[name] = maximum + 1
            with self.subTest(name=name), self.assertRaises(ValueError):
                run.validate_h3_budget(value, value["nextExecution"], 3608, 0, bad)

    def test_native_minute_facts_select_own_cumulative_stage(self):
        value = grant(); value["bookedAdditionalAttempts"] = []
        facts = {"grant": value, "prefix": {"records": [{"runId": "1", "runnerMinutes": 2215}]},
            "run_minutes": {("1", 1): 2215, ("2", 1): 220, ("3", 1): 1039, ("4", 1): 134, ("5", 1): 0},
            "run_pools": {"1": "incidental", "2": "preparation", "3": "source", "4": "incidental", "5": "preparation"}}
        charged, components = controller.h3_minute_facts(facts, "5", 0)
        self.assertEqual(charged, 3608)
        self.assertEqual(components["remainingIncidentalReserveMinutes"], 60)
        facts["run_minutes"][("4", 1)] = 195
        with self.assertRaisesRegex(ValueError, "component_ceiling"): controller.h3_minute_facts(facts, "5", 0)

    def test_exact_family_paths_and_eighth_generation_refused(self):
        for number in (6, 7):
            value = family(number)
            self.assertIs(policy.validate_h3_family(value, 7), value)
            with self.assertRaises(ValueError): policy.validate_h3_family(value, 5)
        with self.assertRaises(ValueError): policy.validate_h3_family(family(8), 7)
        for mode in ("extra", "missing-gen6-path", "old-generation-new-path", "wrong-parent", "unknown-field", "boolean-number"):
            value = family(6); step = value["generations"][-1]
            if mode == "extra":
                step["changedPaths"].append("scripts/unreviewed.ts"); step["changedPaths"].sort(); step["contentSha256"]["scripts/unreviewed.ts"] = "c" * 64
            if mode == "missing-gen6-path":
                name = "src/test-utils/npm-command.ts"; step["changedPaths"].remove(name); del step["contentSha256"][name]
            if mode == "old-generation-new-path":
                step = value["generations"][0]; name = "src/test-utils/npm-command.ts"; step["changedPaths"].append(name); step["changedPaths"].sort(); step["contentSha256"][name] = "c" * 64
            if mode == "wrong-parent": step["parentSource"] = deepcopy(policy.H3_ANCHOR)
            if mode == "unknown-field": step["newAccess"] = True
            if mode == "boolean-number": step["number"] = True
            with self.subTest(mode=mode), self.assertRaises(ValueError): policy.validate_h3_family(value, 7)

    def test_owned_disarmed_request_uses_full_original_caps_and_new_deadline(self):
        value = bindings(); request = policy.request_for(value, "lock-preparation", 17)
        self.assertIs(policy.validate_request(request, value), request)
        self.assertEqual(policy.source_authorization_window(value)[1], "2026-11-07T03:14:21Z")
        self.assertEqual(policy.h3_stage_contract(value, request), run.h3_stage_descriptor(True, True))
        budget = policy.budget(request)
        self.assertEqual((budget["phaseMaximumMinutes"], budget["maximumMaterialSourceGenerations"]), (45, 7))
        self.assertEqual(budget["profileMinutes"], policy.PROFILE_MINUTES)
        self.assertEqual(budget["maximumStageBookedMinutes"], 6088)
        self.assertEqual((budget["maximumAdditionalWorkflowAttempts"], budget["maximumSourceCampaigns"]), (1000, 1000))
        request["vendorRepairContinuationSha256"] = run.digest(run.vendor_repair_continuation())
        with self.assertRaises(ValueError): policy.validate_request(request, value)

    def test_lock_floor_and_end_select_exact_owned_continuation(self):
        def inputs(number=6):
            return {"amendmentSha256": run.H3_AMENDMENT_SHA256, "sourceGeneration": number,
                "checkedAt": "2026-11-06T04:00:00Z", "packageBytes": b"{}", "workspaceBytes": b"policy",
                "fileTransferPackageBytes": b"{}", "excludedAgeProofBytes": b"{}", "excludedAgeProofSha256": "a" * 64,
                "targetMetadataProofBytes": b"{}", "targetMetadataProofSha256": "b" * 64,
                "sourceContinuationScope": {"authority": run.vendor_repair_combined_source_allocation(),
                    "sourceGeneration": number, "sourceFamilySha256": "c" * 64}}
        for number in (6, 7):
            with patch.object(lock, "strict_json", side_effect=GraphBoundary()), self.assertRaises(GraphBoundary):
                lock.validate_h3_source_inputs(inputs(number))
        for mode in ("eighth", "old-marker", "old-generation", "after-end", "before-floor", "unknown-scope-field"):
            value = inputs()
            if mode == "eighth": value["sourceGeneration"] = value["sourceContinuationScope"]["sourceGeneration"] = 8
            if mode == "old-marker": value["sourceContinuationScope"]["authority"] = run.vendor_repair_derivation_recovery_allocation()
            if mode == "old-generation": value["sourceGeneration"] = value["sourceContinuationScope"]["sourceGeneration"] = 5
            if mode == "after-end": value["checkedAt"] = "2026-11-07T03:14:21Z"
            if mode == "before-floor": value["checkedAt"] = "2026-11-04T09:59:49Z"
            if mode == "unknown-scope-field": value["sourceContinuationScope"]["newAccess"] = True
            with self.subTest(mode=mode), self.assertRaises(ValueError): lock.validate_h3_source_inputs(value)

    def test_vendor_records_seven_are_source_facts_not_approval(self):
        for number in (6, 7):
            record = {"schema": vendor.SCHEMA, "sourceGeneration": number, **{name: "a" * 64 for name in
                ("workspaceSha256", "patchSha256", "proofSha256", "producerRuntimeSha256")}}
            self.assertIs(vendor.validate_record(record, policy.need, generation=number), record)
            record["sourceGeneration"] = 8
            with self.assertRaises(ValueError): vendor.validate_record(record, policy.need)

    def test_owned_payload_fixture_inherited_from_exact_g5_source_step(self):
        for number in (6, 7):
            value = bindings(number); request = policy.request_for(value, "lock-preparation", 17)
            context = {"bindings": value, "request": request, "operationIdentity": controller.owned_identity(request)}
            self.assertTrue(controller.vendor_payload_fixture_selected({"sourceGeneration": number}, context))
            context["operationIdentity"] = "wrong"
            with self.assertRaises(ValueError): controller.vendor_payload_fixture_selected({"sourceGeneration": number}, context)

    def test_original_combined_four_inline_clock_guards_remain_pinned(self):
        from unittest.mock import mock_open
        blocks = []
        for name in ("v109-h3-lock-preparation.yml", "v109-h3-source-validation.yml"):
            pins = {"v109-h3-lock-preparation.yml": "fe1a5b57c0aaa892248ae9a9ba49bcb11b450b55772505daeea2504c08c3bd1a",
                "v109-h3-source-validation.yml": "67caba4781ec125e1d8ce70363dba50b2e8d70f83e505f9bf4ca4f88dafd749f"}
            target = name.replace("v109-h3-", "v109-gen6-prep17-")
            raw = (HERE / "fixtures" / target).read_bytes()
            self.assertEqual(policy.digest(raw), pins[name])
            text = raw.decode("utf8")
            blocks.extend(textwrap.dedent(body) for body in re.findall(r"python3 - <<'PY'\n(.*?)          PY", text, re.S) if "def utc(v):" in body)
        self.assertEqual(len(blocks), 4)
        now = policy.utc("2026-11-06T04:00:00Z").timestamp()
        env = {"V109_APPROVED_AT": "2026-10-30T03:14:21Z", "V109_EXPIRES_AT": "2026-11-07T03:14:21Z", "GITHUB_ENV": "/synthetic/not-opened"}
        for block in blocks:
            writer = mock_open()
            with patch.dict(os.environ, env, clear=True), patch.object(time, "time", return_value=now), patch("builtins.open", writer):
                exec(compile(block, "<combined-clock>", "exec"), {})
            writer.assert_called_once_with("/synthetic/not-opened", "a")
            for end, clock in (("2026-11-06T03:14:21Z", now), ("2026-11-08T03:14:21Z", now),
                    (env["V109_EXPIRES_AT"], policy.utc(env["V109_EXPIRES_AT"]).timestamp())):
                writer = mock_open()
                with patch.dict(os.environ, {**env, "V109_EXPIRES_AT": end}, clear=True), patch.object(time, "time", return_value=clock), patch("builtins.open", writer), self.assertRaises(SystemExit):
                    exec(compile(block, "<combined-clock>", "exec"), {})
                writer.assert_not_called()


class GraphBoundary(Exception): pass


def graph(count):
    integration = {"commit": "1" * 40, "tree": "2" * 40}
    successors = [{"commit": format(i + 1000, "040x"), "tree": format(i + 2000, "040x")} for i in range(count)]
    tip = successors[-1] if successors else integration
    merge = {"schema": recon.MERGE_SCHEMA, "commonCommit": "3" * 40, "commonTree": "4" * 40,
        "forkCommit": "5" * 40, "forkTree": "6" * 40, "integration": integration,
        "successors": successors, "securitySource": {"commit": "5" * 40, "tree": "6" * 40},
        "reconciliation": {"path": recon.PROOF_PATH, "blob": "7" * 40, "sha256": "8" * 64}}
    return {"baseCommit": "9" * 40, "baseTree": "a" * 40, **tip, "patches": [dict(tip)], "merge": merge}


class CombinedGraphTests(unittest.TestCase):
    def test_thirteen_authenticates_every_tree_and_parent_before_body_read(self):
        source = graph(13); release.validate_merge_shape(source)
        merge = source["merge"]; lineage = [merge["integration"], *merge["successors"]]
        trees = {merge["commonCommit"]: merge["commonTree"], merge["forkCommit"]: merge["forkTree"], source["baseCommit"]: source["baseTree"], **{row["commit"]: row["tree"] for row in lineage}}
        parents = {lineage[0]["commit"]: [merge["forkCommit"], source["baseCommit"]]}
        parents.update({row["commit"]: [previous["commit"]] for previous, row in zip(lineage, lineage[1:])})
        for mode in ("valid", "tree", "integration-parent", "last-parent", "common-ancestor"):
            seen = []
            def read(root, *args):
                seen.append(args)
                if args[0] == "rev-parse": return "f" * 40 if mode == "tree" else trees[args[1].split("^", 1)[0]]
                if args[:3] == ("show", "-s", "--format=%P"):
                    if mode == "integration-parent" and args[3] == lineage[0]["commit"] or mode == "last-parent" and args[3] == lineage[-1]["commit"]: return "f" * 40
                    return " ".join(parents[args[3]])
                if args[:2] == ("merge-base", "--all"): return "f" * 40 if mode == "common-ancestor" else merge["commonCommit"]
                raise GraphBoundary()
            with self.subTest(mode=mode), self.assertRaises(GraphBoundary if mode == "valid" else ValueError):
                recon.check_v109_reconciliation(source, Path("/synthetic/not-opened"), git=read, need=policy.need)
            if mode == "valid": self.assertEqual(len([call for call in seen if call[:3] == ("show", "-s", "--format=%P")]), 14)

    def test_fourteenth_duplicate_tip_patch_and_security_refuse_before_io(self):
        for mode in ("fourteen", "duplicate", "tip", "patch", "security", "unknown-field"):
            source = graph(14 if mode == "fourteen" else 13)
            if mode == "duplicate": source["merge"]["successors"][1] = deepcopy(source["merge"]["successors"][0])
            if mode == "tip": source["tree"] = "f" * 40
            if mode == "patch": source["patches"].append(deepcopy(source["patches"][0]))
            if mode == "security": source["merge"]["securitySource"]["commit"] = "f" * 40
            if mode == "unknown-field": source["merge"]["newAccess"] = True
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                recon.check_v109_reconciliation(source, Path("/synthetic/not-opened"), git=lambda *args: self.fail("refusal must precede I/O"), need=policy.need)
            if mode != "security":
                with self.assertRaises(release.Refusal): release.validate_merge_shape(source)


if __name__ == "__main__": unittest.main()
