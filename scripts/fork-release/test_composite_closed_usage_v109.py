"""Pure baseline composition cases; no network, process, clock or candidate code."""
import copy
from pathlib import Path
import unittest

import composite_closed_usage_v109 as owner

HERE = Path(__file__).absolute().parent
CANDIDATE = HERE / "candidates"


def inputs():
    old = CANDIDATE / "v2026.10.8-source-only"
    new = CANDIDATE / "v2026.10.9-source-only"
    return ((new / "closed-258-proof.json").read_bytes(),
            (old / "crabline-settled-usage.json").read_bytes(),
            (old / "re2js-settled-usage.json").read_bytes(),
            (old / "re2js-closed-provider-usage.json").read_bytes(),
            (new / "closed-15-provider-usage.json").read_bytes())


class ClosedBaseline258(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = inputs()
        cls.previous = owner.resolve_composite(cls.raw[1], cls.raw[2], cls.raw[3])
        cls.stage = owner.decode(cls.raw[4], 2 * 1024 * 1024)

    def derive(self, previous=None, stage=None):
        return owner._derive(copy.deepcopy(self.previous if previous is None else previous),
                             copy.deepcopy(self.stage if stage is None else stage))

    def rejected_stage(self, mutate, code):
        value = copy.deepcopy(self.stage)
        mutate(value)
        with self.assertRaisesRegex(ValueError, code):
            self.derive(stage=value)

    def test_actual_pinned_inputs_resolve258_and2944(self):
        result = owner.resolve_baseline_258(*self.raw)
        self.assertEqual((result["runCount"], result["runnerMinutesObserved"]), (258, 2944))
        self.assertEqual(owner.digest(owner.canonical(result)), owner.RESOLVED_SHA256)
        self.assertEqual(result["sourceRunIds"], owner.SOURCE_IDS)

    def test_previous243_bytes_and_rows_stay_exact(self):
        result = owner.resolve_baseline_258(*self.raw)
        self.assertEqual(owner.canonical(result["runs"][:243]), owner.canonical(self.previous["runs"]))
        self.assertEqual(self.previous["runCount"], 243)
        self.assertEqual(self.previous["runnerMinutesObserved"], 2437)

    def test_artifact_snapshot_adds_only_one622_byte_item(self):
        result = owner.resolve_baseline_258(*self.raw)
        self.assertEqual(result["artifactSnapshot"], {"count": 23, "bytes": 387814})
        # The inherited snapshot includes five historical artifact identities
        # not present in the old row collection; this owner does not invent rows.
        self.assertEqual(sum(len(r.get("artifactRows", [])) for r in result["runs"]), 18)

    def test_no_old_or_new_authority_transferred(self):
        result = owner.resolve_baseline_258(*self.raw)
        self.assertIs(result["referenceComposition"]["oldUnusedAuthorityCarried"], False)
        self.assertIs(result["historicalCoverageTransferred"], False)
        self.assertIs(result["executionAuthorized"], False)
        raw = owner.canonical(result)
        self.assertNotIn(b"Sentinel_", raw)
        self.assertNotIn(b"publicationSlots", raw)

    def test_stage15_raw_tamper_refused(self):
        values = list(self.raw)
        values[4] += b" "
        with self.assertRaisesRegex(ValueError, "baseline258.exact_segment_bytes"):
            owner.resolve_baseline_258(*values)

    def test_proof_raw_tamper_refused(self):
        values = list(self.raw)
        values[0] += b" "
        with self.assertRaisesRegex(ValueError, "baseline258.closed_proof"):
            owner.resolve_baseline_258(*values)

    def test_existing243_reference_tamper_refused(self):
        values = list(self.raw)
        values[1] += b" "
        with self.assertRaisesRegex(ValueError, "baseline258.exact_segment_bytes"):
            owner.resolve_baseline_258(*values)

    def test_original213_tamper_still_owned_by_existing_resolver(self):
        values = list(self.raw)
        values[2] += b" "
        with self.assertRaisesRegex(ValueError, "composite.exact_segment_bytes"):
            owner.resolve_baseline_258(*values)

    def test_duplicate_json_key_refused(self):
        with self.assertRaisesRegex(ValueError, "baseline258.duplicate_json_key"):
            owner.decode(b'{"a":1,"a":2}', 100)

    def test_nonfinite_json_refused(self):
        with self.assertRaisesRegex(ValueError, "baseline258.nonfinite_json"):
            owner.decode(b'{"a":NaN}', 100)

    def test_stage_summary_extra_control_field_refused(self):
        self.rejected_stage(lambda d: d.update(authority="not an input"), "baseline258.closed15_summary")

    def test_stage_record_private_control_field_refused(self):
        self.rejected_stage(lambda d: d["records"][0].update(publicationSlots=[]),
                            "baseline258.public_provider_record")

    def test_provider_header_change_refused(self):
        self.rejected_stage(lambda d: d["records"][0]["run"].update(head_sha="0" * 40),
                            "baseline258.public_provider_header")

    def test_actor_change_refused(self):
        self.rejected_stage(lambda d: d["records"][0].update(actorLogin="other"),
                            "baseline258.public_provider_record")

    def test_changed_stored_usage_refused(self):
        self.rejected_stage(lambda d: d["records"][0].update(observedMinutes=1),
                            "baseline258.measured_totals")

    def test_bool_is_not_an_integer_usage(self):
        self.rejected_stage(lambda d: d["records"][0].update(observedMinutes=True),
                            "baseline258.public_provider_record")

    def test_duplicate_run_id_refused(self):
        def mutate(d):
            header = d["records"][1]["run"]
            header["id"] = d["records"][0]["run"]["id"]
            header["html_url"] = d["records"][0]["run"]["html_url"]
        self.rejected_stage(mutate, "baseline258.unique_terminal_run")

    def test_duplicate_job_id_across_old_and_new_refused(self):
        old_id = self.previous["runs"][0]["jobs"][0]["id"]
        self.rejected_stage(lambda d: d["records"][0]["jobs"][0].update(id=old_id),
                            "baseline258.unique_terminal_job")

    def test_nonterminal_job_refused(self):
        self.rejected_stage(lambda d: d["records"][0]["jobs"][0].update(status="in_progress"),
                            "baseline258.unique_terminal_job")

    def test_main_role_or_selected_profiles_cannot_be_relabelled(self):
        def mutate(d):
            main = next(r for r in d["records"] if r["run"]["id"] == 40901336241)
            main["jobs"][0]["name"] = "unrelated"
        self.rejected_stage(mutate, "baseline258.closed_main_role")

    def test_duplicate_artifact_refused(self):
        def mutate(d):
            artifact = next(r["artifacts"][0] for r in d["records"] if r["artifacts"])
            d["records"][0]["artifacts"].append(copy.deepcopy(artifact))
        self.rejected_stage(mutate, "baseline258.unique_artifact")


if __name__ == "__main__":
    unittest.main()
