"""Pure fixture-correction vectors; no actual H2, approval or execution facts."""
from copy import deepcopy
from contextlib import ExitStack
from pathlib import Path
import hashlib
import unittest
from unittest.mock import patch

import test_third_preparation_contract_v109 as legacy
import test_bounded_run_contract_v109 as allowance

m = legacy.m
H_VALIDATION = {'source': {'sourceSha': 'edd010829dcb622d7dc60dc90f7097048cb78819', 'sourceTree': '2e553992d3f93937dcb4b85683e4aae24a087074', 'manifestSha256': '9032a1666ee82ae7882d280c5bbb5a6e02e127c7c1526b61aef3667973621c58', 'inventorySha256': '07d0d8e96cb428ce8151e36d8c08eb4bc0cd055f4185186a1f40ac0a6f1add71', 'fileSha256': {'package.json': '557f352a2e5e8ecd40944311ec3470f1d2679a8207ea12cd7ea7317b64770de0', 'pnpm-workspace.yaml': 'd7d436368006b9e298c2754a8ab7f6574c260aa3fb011228fef1a9adf20fee19', 'pnpm-lock.yaml': '32b1cecff004966696f50bce80de7c7b8d37f33305e3417f81e020c6a887b068', 'custom-patches/reconciliation-2026.10.9.json': '7f3ef17a22f8afaf709ae252f96068ae49e9037f52e0cd9cb29c479b74850303'}}, 'generation': {'runId': '41043479025', 'runAttempt': 1, 'pipelineHead': 'b5462c264f3a7b2f55e3d5c5d4aa926ec25de2c6', 'artifactId': 12972087389, 'artifactSha256': '4b5386aa4d4f37b378658309f6e58239a1ddc949550d416cc2f6b6ca9ab4cc7c', 'receiptSha256': 'a5f490eff76fa1b9c62fc2e3ed038234397e65e8e9c9adfa526c070db94d4e87', 'generatedLockSha256': '32b1cecff004966696f50bce80de7c7b8d37f33305e3417f81e020c6a887b068', 'gitDiffSha256': 'b3bc34958fd1c467d18a21ace7e9b1e9d64e3af577f043e9fa5553a5a91ef612'}, 'unchangedTreeSha256': '3981f4ab7a5e4736c11ce4356b65b706e04a6bad6e313f176791f4e93149e3f3', 'preparationAttempt': 6}


def blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def vectors():
    root = Path(__file__).parent / "fixtures"
    return ((root / "v109-lease-type-import-before.ts.txt").read_bytes(),
        (root / "v109-lease-type-import-after.ts.txt").read_bytes())


def fixture_row():
    return {"path": m.FIXTURE_CORRECTION_PATH, "base108": None,
        "fork108": {"mode": "100644", "blob": m.FIXTURE_CORRECTION_BEFORE_BLOB},
        "upstream109": None, "result": {"mode": "100644", "blob": m.FIXTURE_CORRECTION_BEFORE_BLOB},
        "disposition": "CARRIED_EXACT"}


def ledger_vector():
    return m.encode({"schema": "openclaw.v109.fork-carry-reconciliation.v1", "lockState": "ci_derived",
        "sourcePaths": [fixture_row(), {"path": "pnpm-lock.yaml", "result": {"mode": "100644", "blob": "a" * 40},
            "disposition": "LOCK_CONTROLLED_DERIVATION"}],
        "lockDerivation": {"runId": 41043479025, "receiptSha256": "b" * 64},
        "historical108Proof": {"source": "c" * 40}, "qualificationTransferred": False,
        "selfExclusion": {"path": m.LEDGER, "reason": "result-blob self-reference excluded"}})


def correction_binding():
    b = legacy.recovery_binding()
    b["validation"] = deepcopy(H_VALIDATION)
    target = deepcopy(H_VALIDATION["source"])
    target.update(sourceSha="f" * 40, sourceTree="e" * 40, manifestSha256="d" * 64, inventorySha256="e" * 64)
    ledger = m.expected_fixture_correction_ledger(ledger_vector(), m.FIXTURE_CORRECTION_AFTER_BLOB)
    target["fileSha256"][m.LEDGER] = m.digest(ledger)
    b["correction"] = {"source": target, "parentSource": m.FIXTURE_CORRECTION_PARENT,
        "changedPaths": sorted((m.FIXTURE_CORRECTION_PATH, m.LEDGER)),
        "contentSha256": {m.FIXTURE_CORRECTION_PATH: m.FIXTURE_CORRECTION_AFTER_SHA256, m.LEDGER: m.digest(ledger)},
        "unchangedTreeSha256": "9" * 64, "priorValidation": deepcopy(m.FIXTURE_CORRECTION_PRIOR_VALIDATION),
        "preparationAttempt": 6, "generation": deepcopy(H_VALIDATION["generation"])}
    b["ciRunGrant"] = allowance.grant()
    b["ciRunGrant"]["nextExecution"].update(sequence=6, phase="correction", preparationAttempt=6,
        source=deepcopy(target), priorSourceRun=deepcopy(m.FIXTURE_CORRECTION_PRIOR_VALIDATION),
        reasonCode="prior_failure", reservations={"current": 1075, "pendingValidation": 0, "conditionalImage": 180, "incidental": 50})
    return b


def model():
    """In-memory G/H/H2 graph. Constants patched only to bind synthetic receipts."""
    import test_source_derivation_v109 as old
    b, files, _, _, gate, old_trees, old_content, old_parents = old.repository()
    g0, h0 = b["preparation"]["sourceSha"], b["validation"]["source"]["sourceSha"]
    g, h, h2 = m.ORIGINAL_RECOVERY_SOURCE_SHA, m.FIXTURE_CORRECTION_PARENT, "f" * 40
    content = {g: deepcopy(old_content[g0]), h: deepcopy(old_content[h0])}
    before, after = vectors()
    content[g][m.FIXTURE_CORRECTION_PATH] = before
    initial = m.parse(content[g][m.LEDGER]); initial["sourcePaths"].append(fixture_row())
    content[g][m.LEDGER] = m.encode(initial)
    b["preparation"]["sourceSha"] = g
    for p in m.INPUTS: b["preparation"]["fileSha256"][p] = m.digest(content[g][p])
    receipt = m.parse(files["generation.json"])
    receipt.update(sourceSha=g, sourceTree=b["preparation"]["sourceTree"],
        packageSha256=m.digest(content[g]["package.json"]),
        workspaceSha256=m.digest(content[g]["pnpm-workspace.yaml"]),
        sourceLockSha256=m.digest(content[g]["pnpm-lock.yaml"]), ledgerSha256=m.digest(content[g][m.LEDGER]))
    files["generation.json"] = m.encode(receipt)
    generation = b["validation"]["generation"]; generation["receiptSha256"] = m.digest(files["generation.json"])
    content[h][m.FIXTURE_CORRECTION_PATH] = before
    content[h][m.LEDGER] = m.expected_derived_ledger(content[g][m.LEDGER], blob(content[h]["pnpm-lock.yaml"]), generation)
    b["validation"]["source"]["sourceSha"] = h; b["validation"]["preparationAttempt"] = 6
    for p in m.INPUTS: b["validation"]["source"]["fileSha256"][p] = m.digest(content[h][p])
    b["status"] = "DISARMED"; b["authorization"] = legacy.original_authorization()
    b["preparationCorrection"] = deepcopy(legacy.recovery_binding()["preparationCorrection"])
    b["preparationCorrection"]["source"] = deepcopy(b["preparation"])
    content[h2] = deepcopy(content[h]); content[h2][m.FIXTURE_CORRECTION_PATH] = after
    content[h2][m.LEDGER] = m.expected_fixture_correction_ledger(content[h][m.LEDGER], blob(after))
    target = deepcopy(b["validation"]["source"]); target.update(sourceSha=h2, sourceTree="e" * 40)
    target["fileSha256"][m.LEDGER] = m.digest(content[h2][m.LEDGER])
    entries = {sha: {p: ("100644", "blob", blob(raw)) for p, raw in data.items()} for sha, data in content.items()}
    b["validation"]["unchangedTreeSha256"] = m.tree_digest(entries[g], ("pnpm-lock.yaml", m.LEDGER))
    b["correction"] = {"source": target, "parentSource": h,
        "changedPaths": sorted((m.FIXTURE_CORRECTION_PATH, m.LEDGER)),
        "contentSha256": {m.FIXTURE_CORRECTION_PATH: m.digest(after), m.LEDGER: m.digest(content[h2][m.LEDGER])},
        "unchangedTreeSha256": m.tree_digest(entries[h], (m.FIXTURE_CORRECTION_PATH, m.LEDGER)),
        "priorValidation": deepcopy(m.FIXTURE_CORRECTION_PRIOR_VALIDATION),
        "preparationAttempt": 6, "generation": deepcopy(generation)}
    b["ciRunGrant"] = allowance.grant(); b["ciRunGrant"]["nextExecution"].update(
        sequence=6, phase="correction", preparationAttempt=6, source=deepcopy(target),
        priorSourceRun=deepcopy(m.FIXTURE_CORRECTION_PRIOR_VALIDATION), reasonCode="prior_failure",
        reservations={"current": 1075, "pendingValidation": 0, "conditionalImage": 180, "incidental": 50})
    parents = {g: [m.BASELINE_SOURCE, m.UPSTREAM["commit"]], h: [g], h2: [h]}
    tree_names = {g: b["preparation"]["sourceTree"], h: b["validation"]["source"]["sourceTree"], h2: target["sourceTree"]}
    def read(*args):
        if args[0] == "rev-parse": return (tree_names[args[1].split("^")[0]] + "\n").encode()
        if args[:3] == ("show", "-s", "--format=%P"): return (" ".join(parents[args[3]]) + "\n").encode()
        if args[0] == "show":
            sha, path = args[1].split(":", 1); return content[sha][path]
        raise AssertionError(args)
    def trees(sha, tree):
        if tree != tree_names[sha]: raise AssertionError("wrong synthetic tree")
        return deepcopy(entries[sha])
    overrides = {"FIXTURE_CORRECTION_SOURCE_PIN_SHA256": m.digest(m.canonical(b["validation"]["source"])),
        "FIXTURE_CORRECTION_GENERATION_SHA256": m.digest(m.canonical(generation))}
    return b, files, read, trees, gate, entries, content, parents, overrides


class FixtureCorrectionTests(unittest.TestCase):
    def proof(self, model_value, phase="correction"):
        b, files, read, trees, gate, entries, content, parents, overrides = model_value
        with ExitStack() as stack:
            for key, value in overrides.items(): stack.enter_context(patch.object(m, key, value))
            return m.verify_derived_source(read, b, phase, files["generation.json"], read_tree=trees, verify_lock=gate)

    def test_actual_type_only_vectors_are_exact(self):
        before, after = vectors()
        self.assertEqual(m.digest(before), m.FIXTURE_CORRECTION_BEFORE_SHA256)
        self.assertEqual(m.digest(after), m.FIXTURE_CORRECTION_AFTER_SHA256)
        self.assertEqual(blob(before), m.FIXTURE_CORRECTION_BEFORE_BLOB)
        self.assertEqual(blob(after), m.FIXTURE_CORRECTION_AFTER_BLOB)
        self.assertEqual(before.split(b"const verification", 1)[1], after.split(b"const verification", 1)[1])

    def test_closed_actual_shaped_binding_and_fresh_all15_request(self):
        b = correction_binding(); before = m.canonical(b)
        self.assertEqual(m.validate_bindings(b), b)
        q = m.request_for(b, "correction")
        self.assertEqual(q["phase"], "correction"); self.assertEqual(q["preparationAttempt"], 6)
        self.assertEqual(q["generation"], H_VALIDATION["generation"])
        self.assertEqual(q["profiles"], list(m.PROFILES))
        self.assertEqual(m.budget(q)["phaseMaximumMinutes"], 1075)
        self.assertEqual(m.canonical(b), before)
        with self.assertRaises(m.Refusal): m.validate_request(q, b, active=True, now=1793350000)
        # Reviewed examples remain in memory, never active candidate files.
        b["status"] = "APPROVED_CI"; b["ciRunGrant"]["status"] = "APPROVED"
        plan = b["ciRunGrant"]["nextExecution"]
        plan.update(status="REVIEWED", reviewSha256="a" * 64, requestSha256=m.digest(m.encode(q)))
        self.assertEqual(m.validate_request(q, b, active=True,
            now=m.utc("2026-10-30T12:30:00Z").timestamp()), q)

    def test_parent_preparation_generation_and_dependency_drift_refuse(self):
        for kind in ("parent", "prep1", "prep7", "generation", "generation_both", "package.json", "pnpm-workspace.yaml", "pnpm-lock.yaml"):
            b = correction_binding(); c = b["correction"]
            if kind == "parent": c["parentSource"] = "a" * 40
            elif kind.startswith("prep"): c["preparationAttempt"] = int(kind[-1])
            elif kind == "generation": c["generation"]["runId"] = "41043479026"
            elif kind == "generation_both":
                c["generation"]["runId"] = "41043479026"
                b["validation"]["generation"] = deepcopy(c["generation"])
            else: c["source"]["fileSha256"][kind] = "a" * 64
            with self.subTest(kind=kind), self.assertRaises(m.Refusal): m.validate_bindings(b)

    def test_missing_extra_paths_content_or_prior_validation_refuse(self):
        for kind in ("missing", "extra", "content", "prior", "witness"):
            b = correction_binding(); c = b["correction"]
            if kind == "missing": c["changedPaths"].remove(m.LEDGER)
            elif kind == "extra": c["changedPaths"].append("src/runtime.ts")
            elif kind == "content": c["contentSha256"][m.FIXTURE_CORRECTION_PATH] = "a" * 64
            elif kind == "prior": c["priorValidation"]["runId"] = "41052090950"
            else: c["unchangedTreeSha256"] = None
            with self.subTest(kind=kind), self.assertRaises(m.Refusal): m.validate_bindings(b)

    def test_helper_changes_only_result_and_disposition(self):
        before = m.parse(ledger_vector()); after = m.parse(m.expected_fixture_correction_ledger(m.encode(before), m.FIXTURE_CORRECTION_AFTER_BLOB))
        expected = deepcopy(before); expected["sourcePaths"][0]["result"]["blob"] = m.FIXTURE_CORRECTION_AFTER_BLOB
        expected["sourcePaths"][0]["disposition"] = "ADAPTED_SECURITY_TEST"
        self.assertEqual(after, expected)
        self.assertIs(type(after["lockDerivation"]["runId"]), int)
        for kind in ("state", "row", "duplicate", "blob"):
            value = deepcopy(before)
            if kind == "state": value["lockState"] = "pending_ci_derivation"
            elif kind == "row": value["sourcePaths"][0]["result"]["blob"] = "a" * 40
            elif kind == "duplicate": value["sourcePaths"].append(deepcopy(value["sourcePaths"][0]))
            with self.subTest(kind=kind), self.assertRaises(m.Refusal):
                m.expected_fixture_correction_ledger(m.encode(value), "a" * 40 if kind == "blob" else m.FIXTURE_CORRECTION_AFTER_BLOB)

    def test_full_synthetic_g_h_h2_proof_preserves_original_generation(self):
        data = model(); proof = self.proof(data)
        self.assertEqual(proof["generatedSourceSha"], m.FIXTURE_CORRECTION_PARENT)
        self.assertEqual(proof["generatedChangedPaths"], sorted(("pnpm-lock.yaml", m.LEDGER)))
        self.assertEqual(proof["changedPaths"], sorted((m.FIXTURE_CORRECTION_PATH, m.LEDGER)))
        self.assertTrue(proof["fixtureOnlyCorrectionVerified"])
        original = self.proof(data, "validation")
        self.assertEqual(original["sourceSha"], m.FIXTURE_CORRECTION_PARENT)
        self.assertFalse(original["sourceCorrectionVerified"])

    def test_graph_parent_path_mode_and_unchanged_witness_refuse(self):
        for kind in ("parent", "runtime", "mode", "witness"):
            data = model(); b, files, read, trees, gate, entries, content, parents, overrides = data
            h2 = b["correction"]["source"]["sourceSha"]
            if kind == "parent": parents[h2] = [b["preparation"]["sourceSha"]]
            elif kind == "runtime": entries[h2]["extra.ts"] = ("100644", "blob", "f" * 40)
            elif kind == "mode": entries[h2][m.FIXTURE_CORRECTION_PATH] = ("100755", "blob", m.FIXTURE_CORRECTION_AFTER_BLOB)
            else: b["correction"]["unchangedTreeSha256"] = "a" * 64
            with self.subTest(kind=kind), self.assertRaises(m.Refusal): self.proof(data)

    def test_unrelated_ledger_mutation_refuses_even_with_rebound_hashes(self):
        for kind in ("lockDerivation", "lockDerivation_type", "origin", "disposition", "count"):
            data = model(); b, files, read, trees, gate, entries, content, parents, overrides = data
            h2 = b["correction"]["source"]["sourceSha"]; value = m.parse(content[h2][m.LEDGER])
            if kind == "lockDerivation": value["lockDerivation"]["runId"] += 1
            elif kind == "lockDerivation_type": value["lockDerivation"]["runId"] = str(value["lockDerivation"]["runId"])
            elif kind == "origin": value["sourcePaths"][1]["fork108"] = None
            elif kind == "disposition": value["sourcePaths"][0]["disposition"] = "WAIVED"
            else: value["sourcePaths"].append({"path": "extra", "result": None})
            raw = m.encode(value); content[h2][m.LEDGER] = raw; entries[h2][m.LEDGER] = ("100644", "blob", blob(raw))
            b["correction"]["contentSha256"][m.LEDGER] = m.digest(raw)
            b["correction"]["source"]["fileSha256"][m.LEDGER] = m.digest(raw)
            b["ciRunGrant"]["nextExecution"]["source"] = deepcopy(b["correction"]["source"])
            with self.subTest(kind=kind), self.assertRaises(m.Refusal): self.proof(data)


if __name__ == "__main__": unittest.main()
