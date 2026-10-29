"""Synthetic V7 contract cases; fixed historical lock bytes are not CI coverage."""
import ast
import copy
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import types
import unittest

HERE = Path(__file__).resolve().parent
_BASE_LOCK_CACHE = None


def owner():
    """Load only actual maintained pure functions, without operational imports."""
    path = HERE / "source_validation_v108.py"
    tree = ast.parse(path.read_text())
    constants = {"V6_SCHEMA", "V6_PROFILES", "V6_PROFILE_MINUTES", "V6_PRIOR_SOURCE_IDS",
        "V6_PRIOR_RUNS", "V6_PRIOR_MINUTES", "V6_HISTORY_MAX_RUNS", "V6_OVERALL_MINUTES",
        "V6_DIAGNOSTIC_BYTES", "V6_PREPARATION_ARTIFACT_BYTES", "V6_CAMPAIGN"}
    helpers = {"_v6_need", "_v6_matches", "_v6_equal", "_v6_json", "_v6_preparation_pin", "timestamp"}
    nodes = []
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and
                (t.id.startswith("R7_") or t.id in constants) for t in node.targets):
            nodes.append(node)
        elif isinstance(node, (ast.FunctionDef, ast.ClassDef)) and (
                node.name.startswith(("_r7_", "_h7_", "R7", "V6Contract")) or
                node.name in helpers or node.name.endswith("_v7")):
            nodes.append(node)
    class Refusal(ValueError):
        pass
    def need(ok, code):
        if not ok:
            raise Refusal(code)
    scope = dict(re=re, json=json, hashlib=hashlib, math=math, datetime=datetime,
        timezone=timezone, need=need)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec"), scope)
    return types.SimpleNamespace(**scope), scope


def base_lock():
    global _BASE_LOCK_CACHE
    if _BASE_LOCK_CACHE is None:
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        env.update(GIT_NO_LAZY_FETCH="1", GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0",
            GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null")
        source = HERE.parents[1].parent / "source"
        child = subprocess.run(["/usr/bin/git", "--no-replace-objects", "-c", "protocol.allow=never",
            "-c", "core.hooksPath=/dev/null", "-c", "gc.auto=0", "-c", "maintenance.auto=false",
            "-C", str(source), "show", "9b0a696bf62f045889d76044f84a0c372c8dddcc:pnpm-lock.yaml"],
            env=env, capture_output=True, timeout=20)
        if child.returncode != 0:
            raise AssertionError("r7.fixture_fixed_source_object_unavailable")
        _BASE_LOCK_CACHE = child.stdout
    if hashlib.sha256(_BASE_LOCK_CACHE).hexdigest() != "5e631697caa53422d40dde5ae04a7ee0d84321921891062a4f580ca11b55fc50":
        raise AssertionError("r7.fixture_fixed_source_object_digest")
    return _BASE_LOCK_CACHE


class Contract(unittest.TestCase):
    def setUp(self):
        self.d, self.g = owner()
        d = self.d
        self.workspace = b'overrides:\n  "@openclaw/crabline@0.1.29>re2js": 2.8.7\nminimumReleaseAge: 10080\n'
        self.prep = dict(sourceSha="a" * 40, sourceTree="b" * 40,
            packageSha256=d.R7_BASE_PACKAGE_SHA256, sourceLockSha256=d.R7_BASE_LOCK_SHA256,
            workspaceSha256=hashlib.sha256(self.workspace).hexdigest(), securityTestSha256="1" * 64,
            ledgerSha256="2" * 64, metadataProofSha256=d.R7_METADATA_PROOF_SHA256)
        self.g["R7_PREPARATION_PINS"] = self.prep
        self.pins = dict(sourceSha="c" * 40, sourceTree="d" * 40, manifestSha256="3" * 64,
            inventorySha256="4" * 64, baseline=dict(sha256=d.R7_BASELINE_SHA256, runCount=213,
                runnerMinutesObserved=1798, artifactSnapshot=dict(count=19, bytes=198278),
                sourceRunIds=list(d.R7_BASELINE_SOURCE_IDS)),
            preparation=dict(runId="90000000001", pipelineHead="e" * 40, artifactId=1,
                artifactSha256="5" * 64, generationReceiptSha256="6" * 64,
                packageSha256=d.R7_BASE_PACKAGE_SHA256, lockSha256="7" * 64), priorValidationRuns=[],
            sourceHops=[dict(sourceSha="a" * 40, sourceTree="b" * 40), dict(sourceSha="c" * 40, sourceTree="d" * 40)])
        hops = []
        parent, tree = d.R7_BASE_SOURCE, d.R7_BASE_TREE
        for pin, paths in zip(self.pins["sourceHops"], [d.R7_PREPARED_PATHS, d.R7_DERIVED_PATHS]):
            hops.append(dict(**pin, step=dict(parentSha=parent, parentTree=tree,
                changedPaths=list(paths), unchangedTreeSha256="8" * 64)))
            parent, tree = pin["sourceSha"], pin["sourceTree"]
        self.request = dict(schema=d.R7_SCHEMA, campaignId=d.V6_CAMPAIGN, profilePolicy=d.R7_POLICY,
            sourceAuthorization=d.R7_AUTHORIZATION, stageRound=1, lifetimeOperatorRound=11,
            profiles=list(d.V6_PROFILES), sourceSha=self.pins["sourceSha"], sourceTree=self.pins["sourceTree"],
            manifestSha256=self.pins["manifestSha256"], inventorySha256=self.pins["inventorySha256"],
            settledUsageSha256=d.R7_BASELINE_SHA256, priorRunIds=[*self.pins["baseline"]["sourceRunIds"],
                self.pins["preparation"]["runId"]], lockPreparation=copy.deepcopy(self.pins["preparation"]),
            sourceWitness=dict(schema="openclaw.v108.re2js-source-equivalence.v1", scope=d.R7_SOURCE_SCOPE,
                closedBaselineSha256=d.R7_BASELINE_SHA256, hops=hops))
        self.registry = dict(checkedAt="2026-10-29T08:00:00.000000Z", minimumAgeMinutes=10080,
            publishedAt=d.R7_RE2JS_PUBLISHED_AT, targetName="re2js", targetVersion="2.8.7",
            targetIntegrity=d.R7_RE2JS_INTEGRITY, targetGitHead=d.R7_RE2JS_GIT_HEAD,
            targetNodeEngine=d.R7_RE2JS_ENGINE, parentName="@openclaw/crabline", parentVersion="0.1.29",
            parentDeclaredRe2js="2.8.6", parentNodeEngine=">=22", parentIntegrity=d.R7_PARENT_INTEGRITY,
            targetManifestSha256="1" * 64, packumentSha256="2" * 64, parentManifestSha256="3" * 64,
            manifestPackumentAgreement=True)
        self.registry["ageMinutes"] = (datetime.fromisoformat(self.registry["checkedAt"].replace("Z", "+00:00")) -
            datetime.fromisoformat(d.R7_RE2JS_PUBLISHED_AT.replace("Z", "+00:00"))).total_seconds() / 60

    def refuse(self, call, code):
        with self.assertRaisesRegex(self.d.R7ContractRefusal, re.escape(code)):
            call()

    def test_disarmed_source_pins_refuse(self):
        self.refuse(lambda: self.d.validate_request_v7(self.request, None), "r7.stage_pins")

    def test_prep_context_is_not_fake_v6_request(self):
        context = dict(schema=self.d.R7_PREPARATION_CONTEXT_SCHEMA, sourceSha="a" * 40, sourceTree="b" * 40)
        self.d.validate_preparation_context_v7(context, self.prep)
        context["schema"] = self.d.V6_SCHEMA
        self.refuse(lambda: self.d.validate_preparation_context_v7(context, self.prep), "r7.preparation_context")

    def test_full15_and_worst1470_booking(self):
        self.d.validate_request_v7(self.request, self.pins)
        result = self.d.booking_v7(self.request, self.pins, 45, 0, 50)
        self.assertEqual(result["newStageBookedMinutes"], 1470)
        self.assertEqual(result["currentRoundBookedMinutes"], 1075)
        self.assertEqual(result["bookedRunnerMinutes"], 3268)

    def test_old_doctor_caps_preserved(self):
        self.assertEqual(self.d.V6_PROFILE_MINUTES["doctor-2"], 45)
        self.assertEqual(self.d.V6_PROFILE_MINUTES["doctor-3"], 45)
        self.assertEqual(self.d.R7_PROFILE_MINUTES["doctor-1"], 90)
        self.assertEqual(self.d.R7_PROFILE_MINUTES["doctor-2"], 75)

    def test_initial_missing_profile_refuses(self):
        self.request["profiles"].pop()
        self.refuse(lambda: self.d.validate_request_v7(self.request, self.pins), "r7.all15_fresh")

    def test_extra_source_path_refuses(self):
        self.request["sourceWitness"]["hops"][0]["step"]["changedPaths"].append("package.json")
        self.refuse(lambda: self.d.validate_request_v7(self.request, self.pins), "r7.hop_scope")

    def test_no_unknown_baseline_or_old_source_credit(self):
        self.pins["baseline"]["runCount"] = 214
        self.refuse(lambda: self.d.validate_request_v7(self.request, self.pins), "r7.closed_baseline_pins")

    def test_baseline_keeps_actual_prefix_order(self):
        self.assertEqual(self.d.R7_BASELINE_SOURCE_IDS[:3], ("40616416909", "40609889437", "40607329263"))
        self.pins["baseline"]["sourceRunIds"][:3] = sorted(self.pins["baseline"]["sourceRunIds"][:3])
        self.refuse(lambda: self.d.validate_request_v7(self.request, self.pins), "r7.baseline_source_runs")

    def test_only_one_target_and_no_source_hop(self):
        pin = dict(runId="90000000002", pipelineHead="f" * 40, requestSha256="a" * 64)
        self.pins["priorValidationRuns"] = [pin]
        self.request.update(stageRound=2, lifetimeOperatorRound=12, profiles=["doctor-2", "doctor-3"])
        self.request["priorRunIds"].append(pin["runId"])
        self.d.validate_request_v7(self.request, self.pins)
        self.assertEqual(self.d.booking_v7(self.request, self.pins, 45, 1075, 50)["currentRoundBookedMinutes"], 190)
        self.request["stageRound"] = 3
        self.refuse(lambda: self.d.validate_request_v7(self.request, self.pins), "r7.once_full_once_targeted")

    def test_target_budget_cannot_drop_required_owners_silently(self):
        self.pins["priorValidationRuns"] = [dict(runId="90000000002", pipelineHead="f" * 40, requestSha256="a" * 64)]
        self.request.update(stageRound=2, lifetimeOperatorRound=12,
            profiles=["dependency", "types-tests", "doctor-2", "doctor-3"])
        self.request["priorRunIds"].append("90000000002")
        self.refuse(lambda: self.d.validate_request_v7(self.request, self.pins), "r7.round_booking")

    def test_authentic_metadata_and_age(self):
        self.d.validate_re2js_registry_checks_v7(self.registry)
        for key, bad in [("targetIntegrity", "sha512-bad"), ("parentDeclaredRe2js", "^2.8.6"),
                ("targetNodeEngine", ">=18"), ("manifestPackumentAgreement", 1)]:
            changed = dict(self.registry, **{key: bad})
            self.refuse(lambda: self.d.validate_re2js_registry_checks_v7(changed), "r7.authentic_registry_binding")

    def test_age_is_recomputed_not_claimed(self):
        changed = dict(self.registry, checkedAt="2026-10-18T08:00:00.000000Z", ageMinutes=10081)
        self.refuse(lambda: self.d.validate_re2js_registry_checks_v7(changed), "r7.registry_minimum_age")

    def test_metadata_extra_or_missing_refuses(self):
        changed = dict(self.registry, transportFallback=True)
        self.refuse(lambda: self.d.validate_re2js_registry_checks_v7(changed), "r7.authentic_registry_binding")
        changed = dict(self.registry);del changed["parentIntegrity"]
        self.refuse(lambda: self.d.validate_re2js_registry_checks_v7(changed), "r7.authentic_registry_binding")

    def test_lock_changes_only_four_qualified_parts(self):
        before = base_lock()
        old = ("  re2js@2.8.6:\n    resolution: {integrity: sha512-xLgQil4kIUCrAzVk9fRSkxkFNwmygLFjVxXrLc65aE1F0+Zsb8rxumFBy4XKyvgMCTL6kilDq3EZ0piE2dP/Dg==}\n    engines: {node: '>=18.0.0'}\n").encode()
        new = ("  re2js@2.8.7:\n    resolution: {integrity: " + self.d.R7_RE2JS_INTEGRITY + "}\n    engines: {node: '>=20.0.0'}\n").encode()
        generated = before.replace(b"overrides:\n", b"overrides:\n  '@openclaw/crabline@0.1.29>re2js': 2.8.7\n").replace(old, new).replace(b"      re2js: 2.8.6\n", b"      re2js: 2.8.7\n").replace(b"  re2js@2.8.6: {}\n", b"  re2js@2.8.7: {}\n")
        self.d.validate_re2js_lock_delta_v7(before, generated, self.workspace, self.registry)
        for bad in [before, generated + b"\n", generated.replace(b"npm@12.2.1", b"npm@12.2.2")]:
            self.refuse(lambda: self.d.validate_re2js_lock_delta_v7(before, bad, self.workspace, self.registry),
                "r7.unrelated_resolution_or_format_change")

    def generation(self):
        d = self.d
        return dict(schema="openclaw.v108.re2js-lock-derivation.v1", status="derived_only", **self.prep,
            baseSourceSha=d.R7_BASE_SOURCE, baseSourceTree=d.R7_BASE_TREE,
            pipelineHead=self.pins["preparation"]["pipelineHead"], runId=self.pins["preparation"]["runId"],
            runAttempt=1, lockSha256=self.pins["preparation"]["lockSha256"], re2jsVersion="2.8.7",
            re2jsIntegrity=d.R7_RE2JS_INTEGRITY, parentName="@openclaw/crabline", parentVersion="0.1.29",
            parentDeclaredRe2js="2.8.6", nodeVersion="24.22.1", pnpmVersion="12.15.0",
            registryChecks=copy.deepcopy(self.registry), changedPaths=["pnpm-lock.yaml"], gitDiffSha256="9" * 64,
            allOtherTrackedEntriesUnchanged=True, startedAt="2026-10-29T07:59:59.000000Z",
            finishedAt="2026-10-29T08:00:01.000000Z", commandSeconds=2.0, exitCode=0,
            timedOut=False, cleanupSettled=None, qualified=False, imageBuilt=False, productionAuthorized=False)

    def check_generation(self, value):
        raw = (json.dumps(value, sort_keys=True) + "\n").encode()
        self.pins["preparation"]["generationReceiptSha256"] = hashlib.sha256(raw).hexdigest()
        return self.d.validate_re2js_generation_receipt_v7(raw, self.pins)

    def test_exact_derived_receipt_accepts_only_genuine_shape(self):
        result = self.check_generation(self.generation())
        self.assertEqual(result["changedPaths"], ["pnpm-lock.yaml"])
        self.assertFalse(result["qualified"])

    def test_generation_wrong_source_and_qualification_refuse(self):
        self.refuse(lambda: self.check_generation(dict(self.generation(), sourceSha="c" * 40)),
            "r7.generation_identity")
        for change in [dict(qualified=True), dict(exitCode=False), dict(timedOut=True),
                dict(changedPaths=["package.json", "pnpm-lock.yaml"])]:
            self.refuse(lambda: self.check_generation(dict(self.generation(), **change)), "r7.generation_outcome")

    def test_generation_clock_and_digest_refuse(self):
        self.refuse(lambda: self.check_generation(dict(self.generation(), finishedAt="2026-10-29T07:59:59.000000Z")),
            "r7.generation_clock_bound")
        with self.assertRaisesRegex(self.d.V6ContractRefusal, "v6.invalid_json_constant"):
            self.check_generation(dict(self.generation(), commandSeconds=float("inf")))

    def test_primitive_loader_does_not_activate_driver_or_helpers(self):
        tree = ast.parse((HERE / "source_validation_v108.py").read_text())
        fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "commands")
        text = ast.get_source_segment((HERE / "source_validation_v108.py").read_text(), fn)
        self.assertIn('names += ("test_request_contract_v7.py", "test_re2js_lock_preparation_v108.py")', text)
        self.assertNotIn("main", self.g)
        self.assertNotIn("command", self.g)


if __name__ == "__main__":
    unittest.main()
