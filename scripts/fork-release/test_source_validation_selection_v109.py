"""Pure selection/caller regressions; no candidate or application is executed."""
import hashlib
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).parents[1]
CODE = Path(__file__).parent
if not (CODE / 'source_validation_contract_v109.py').is_file():
    CODE = ROOT / 'pipeline/scripts/fork-release'
HISTORICAL = Path('evidence/v108-preparation-20261027/local-integration-r1/pipeline-preparation-r1/activation-r1/successor-remediation-r1/five-gate-repair-r1/source-fetch-stage-r1/re2js-followup-r1/crabline-successor-activation-r1/driver/pipeline/scripts/fork-release')
sys.path[:0] = [str(CODE), str(HISTORICAL)]
import source_validation_contract_v109 as contract
import source_validation_selection_v109 as selection


def paths():
    return sorted(set(selection.REQUIRED_SOURCE_TESTS + selection.REQUIRED_HELPERS +
        tuple(selection.legacy.V6_RUNTIME_COMPATIBILITY_TESTS) +
        tuple('test/'+n for n in selection.NATIVE_DEPENDENCY_NAMES) + (
        'test/v108-remediation-security.test.mjs',
        'extensions/workboard/src/claim.test.ts', 'extensions/workboard/src/intent.test.ts',
        'extensions/memory-wiki/src/state.test.ts',
        'src/agents/model-provider.synthetic.test.ts', 'src/agents/model-provider.live.test.ts',
        'src/commands/doctor-state.test.ts', 'src/commands/doctor-session.process.test.ts',
        'src/agents/model-candidate.test.ts',
    )))


class SelectionTests(unittest.TestCase):
    def test_complete_required_roots_and_helpers_have_fresh_families(self):
        result = selection.coverage(paths())
        self.assertEqual(result['requiredNewOrChangedTests'], list(selection.REQUIRED_SOURCE_TESTS))
        self.assertTrue(result['freshSourceCoverageRequired'])
        self.assertFalse(result['priorGenerationCoverageReused'])

    def test_every_required_root_selected_and_live_defaults_stay_out(self):
        all_selected = set()
        for profile in contract.PROFILES: all_selected.update(selection.selected_tests(paths(), profile))
        self.assertTrue(set(selection.REQUIRED_SOURCE_TESTS) <= all_selected)
        self.assertNotIn('src/agents/model-provider.live.test.ts', all_selected)
        self.assertIn('src/agents/tool-search.live-diagnostics.test.ts', all_selected)
        self.assertIn('test/scripts/ci-hydrate-live-auth.test.ts', all_selected)

    def test_family_shards_disjoint_complete_and_deterministic(self):
        for group in [('models-1','models-2'),('doctor-1','doctor-2','doctor-3'),('workboard-1','workboard-2')]:
            got = [selection.selected_tests(paths(), p) for p in group]
            flat = [x for values in got for x in values]
            self.assertEqual(len(flat), len(set(flat)))
            self.assertEqual(got, [selection.selected_tests(list(reversed(paths())), p) for p in group])

    def test_missing_new_regression_or_helper_refuses(self):
        for name in (selection.REQUIRED_SOURCE_TESTS[0], selection.REQUIRED_HELPERS[0]):
            with self.subTest(name=name), self.assertRaisesRegex(contract.Refusal,'complete_changed'):
                selection.coverage([p for p in paths() if p != name])

    def test_dependency_maintained_patch_check_and_both_audits_before_native(self):
        result = selection.commands('/pipeline','/source','dependency', paths(),
            {'phase':'validation'}, {'newRecoveryTests': list(selection.REQUIRED_SOURCE_TESTS)})
        self.assertEqual(result[:3], [['pnpm','deps:patches:check'],['pnpm','audit'],['pnpm','audit','--prod']])
        self.assertEqual(set(Path(p).name for p in result[3][5:]), selection.NATIVE_DEPENDENCY_NAMES)
        self.assertEqual(result[3][1],'/pipeline/scripts/fork-release/native_tests.mjs')

    def test_dependency_duplicate_or_missing_native_refuses(self):
        for changed in ([p for p in paths() if p != 'test/body-parser-security.test.mjs'],
                paths()+['test/elsewhere/body-parser-security.test.mjs']):
            with self.assertRaisesRegex(contract.Refusal,'complete_native'):
                selection.commands('/p','/s','dependency',changed,{'phase':'validation'},
                    {'newRecoveryTests': list(selection.REQUIRED_SOURCE_TESTS)})

    def test_compatibility_preserves_fork_security_and_current_source_lock_check(self):
        result = selection.commands('/pipeline','/source','compatibility',paths(),
            {'phase':'validation','source':{'sourceSha':'a'*40}},
            {'newRecoveryTests': list(selection.REQUIRED_SOURCE_TESTS)})
        self.assertIn('test/v108-remediation-security.test.mjs',result[0])
        self.assertEqual(result[2], ['pnpm','deps:npm-lock:check:changed','--base',
            contract.BASELINE_SOURCE,'--head','a'*40])
        self.assertIn('12.2.1',result[3][-1])

    def test_unknown_profile_pending_phase_and_mutated_binding_refuse(self):
        for profile, request, binding in [
                ('image',{'phase':'validation'},{'newRecoveryTests':list(selection.REQUIRED_SOURCE_TESTS)}),
                ('dependency',{'phase':'lock-preparation'},{'newRecoveryTests':list(selection.REQUIRED_SOURCE_TESTS)}),
                ('dependency',{'phase':'validation'},{'newRecoveryTests':[]})]:
            with self.assertRaises(contract.Refusal): selection.commands('/p','/s',profile,paths(),request,binding)

    def test_unsafe_or_duplicate_tracked_paths_refuse(self):
        for changed in [paths()+['../bad.test.ts'], paths()+['/tmp/test.ts'], paths()+[paths()[0]]]:
            with self.assertRaises(contract.Refusal): selection.coverage(changed)

    def test_mocked_live_unit_identity_is_positive_not_name_exception(self):
        helpers = {p: hashlib.sha256(p.encode()).hexdigest() for p in (
            'scripts/ci-hydrate-live-auth.sh','src/agents/tool-search.live-diagnostics.ts')}
        units = {p: hashlib.sha256(p.encode()).hexdigest() for p in selection.MOCKED_UNITS}
        with patch.object(selection,'MOCKED_HELPERS',helpers), patch.object(selection,'MOCKED_UNITS',units):
            self.assertFalse(selection.verify_mocked_units(lambda p:p.encode())['liveProviderCredentialsAllowed'])
            with self.assertRaisesRegex(contract.Refusal,'exact_mocked'):
                selection.verify_mocked_units(lambda p:p.encode()+b'changed')
            with self.assertRaisesRegex(contract.Refusal,'exact_mocked'):
                selection.verify_mocked_units(lambda p:'not bytes')

    def test_incomplete_helper_preparation_never_claims_safe_live_units(self):
        with patch.object(selection,'MOCKED_HELPERS',{}), self.assertRaisesRegex(contract.Refusal,'preparation_complete'):
            selection.verify_mocked_units(lambda _: b'anything')

    def test_fixed_pipeline_test_modules_must_exist_and_define_tests(self):
        self.assertFalse(selection.verify_pipeline_contract_files(
            lambda p:b"def test_synthetic(): pass\n")["missingModuleAccepted"])
        for raw in (b"", b"# no tests here", b"broken Python???", "not bytes"):
            with self.subTest(raw=raw),self.assertRaises(contract.Refusal):
                selection.verify_pipeline_contract_files(lambda p:raw)

    def test_pipeline_contracts_do_not_run_active_historical_campaign_contracts(self):
        self.assertIn('test_source_reconciliation_v109.py',selection.PIPELINE_CONTRACT_TESTS)
        self.assertIn('test_shared_owner_hook_v109.py',selection.PIPELINE_CONTRACT_TESTS)
        for name in ('test_historical_jobs_v109.py', 'test_historical_reconciliation_v109.py',
                'test_third_preparation_contract_v109.py', 'test_third_preparation_runtime_v109.py',
                'test_bounded_run_contract_v109.py', 'test_bounded_run_runtime_v109.py',
                'test_history_pagination_v109.py', 'test_h_fixture_correction_contract_v109.py',
                'test_same_generation_fixture_runtime_v109.py'):
            self.assertIn(name, selection.PIPELINE_CONTRACT_TESTS)
            self.assertEqual(selection.PIPELINE_CONTRACT_TESTS.count(name), 1)
        self.assertNotIn('test_runtime_contract_v8.py',selection.PIPELINE_CONTRACT_TESTS)
        result=selection.commands('/pipeline','/source','pipeline-contracts',paths(),{'phase':'validation'},
            {'newRecoveryTests':list(selection.REQUIRED_SOURCE_TESTS)})
        self.assertTrue(all(cmd[0]=='python3' and cmd[-1].endswith('.py') for cmd in result))

if __name__=='__main__':unittest.main()
