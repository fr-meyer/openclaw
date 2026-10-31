"""Review-owned pure fixture for an actual closed second-generation artifact.

No validation function is mocked; all identities and bytes are synthetic.
"""
from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
from test_source_validation_contract_v109 import m, populated, source


def correction_artifact():
    bindings, original_files = populated()
    prior = {"runId": "234567890", "pipelineHead": "9" * 40,
             "requestSha256": "8" * 64}
    preparation = source("e", "f")
    preparation["fileSha256"]["pnpm-lock.yaml"] = (
        bindings["validation"]["source"]["fileSha256"]["pnpm-lock.yaml"])
    bindings["preparationCorrection"] = {
        "source": preparation,
        "parentSource": bindings["validation"]["source"]["sourceSha"],
        "changedPaths": ["src/control.test.ts"],
        "contentSha256": {"src/control.test.ts": "7" * 64},
        "unchangedTreeSha256": "6" * 64,
        "priorFailure": prior, "priorPhase": "validation"}
    lock, diff = b"corrected generated lock\n", b"corrected lock diff\n"
    receipt = m.parse(original_files["generation.json"])
    receipt.update(
        sourceSha=preparation["sourceSha"],
        sourceTree=preparation["sourceTree"], runId="345678901",
        packageSha256=preparation["fileSha256"]["package.json"],
        workspaceSha256=preparation["fileSha256"]["pnpm-workspace.yaml"],
        sourceLockSha256=preparation["fileSha256"]["pnpm-lock.yaml"],
        ledgerSha256=preparation["fileSha256"][m.LEDGER],
        generatedLockSha256=m.digest(lock), gitDiffSha256=m.digest(diff))
    raw = m.encode(receipt)
    generation = deepcopy(bindings["validation"]["generation"])
    generation.update(
        runId=receipt["runId"], artifactId=456,
        receiptSha256=m.digest(raw), generatedLockSha256=m.digest(lock),
        gitDiffSha256=m.digest(diff))
    target = source("7", "8")
    target["fileSha256"]["pnpm-lock.yaml"] = m.digest(lock)
    bindings["correction"] = {
        "source": target, "parentSource": preparation["sourceSha"],
        "changedPaths": sorted(("pnpm-lock.yaml", m.LEDGER)),
        "contentSha256": {"pnpm-lock.yaml": m.digest(lock),
                          m.LEDGER: target["fileSha256"][m.LEDGER]},
        "unchangedTreeSha256": "5" * 64, "priorValidation": prior,
        "preparationAttempt": 2, "generation": generation}
    files = {"pnpm-lock.yaml": lock, "lock.diff": diff,
             "generation.json": raw}
    return bindings, files


class RealCorrectionArtifactTests(unittest.TestCase):
    def test_closed_second_generation_accepts_explicit_correction(self):
        bindings, files = correction_artifact()
        m.validate_bindings(bindings)
        expected = m.validate_generation(files["generation.json"], bindings,
                                         "correction")
        self.assertEqual(m.verify_generated_artifact(files, bindings,
                         "correction"), expected)
        self.assertEqual(expected["runId"], "345678901")

    def test_same_artifact_still_refuses_legacy_default_phase(self):
        bindings, files = correction_artifact()
        with self.assertRaisesRegex(m.Refusal, "generation_receipt_pin"):
            m.verify_generated_artifact(files, bindings)

    def test_wrong_or_non_generation_phase_refuses(self):
        bindings, files = correction_artifact()
        for phase in ("validation", "lock-preparation", "anything"):
            with self.subTest(phase=phase), self.assertRaises(m.Refusal):
                m.verify_generated_artifact(files, bindings, phase)

    def test_correct_phase_still_checks_lock_and_diff_hashes(self):
        for name in ("pnpm-lock.yaml", "lock.diff"):
            bindings, files = correction_artifact()
            files[name] += b"tamper"
            with self.subTest(name=name), self.assertRaisesRegex(
                    m.Refusal, "generated_artifact_hashes"):
                m.verify_generated_artifact(files, bindings, "correction")

    def test_correct_phase_still_checks_receipt_identity(self):
        bindings, files = correction_artifact()
        receipt = m.parse(files["generation.json"])
        receipt["sourceSha"] = "0" * 40
        files["generation.json"] = m.encode(receipt)
        bindings["correction"]["generation"]["receiptSha256"] = m.digest(
            files["generation.json"])
        with self.assertRaisesRegex(m.Refusal, "generation_receipt_values"):
            m.verify_generated_artifact(files, bindings, "correction")

    def test_initial_artifact_legacy_default_still_accepts(self):
        bindings, files = populated()
        self.assertEqual(m.verify_generated_artifact(files, bindings)["runId"],
                         "123456789")


if __name__ == "__main__":
    unittest.main()
