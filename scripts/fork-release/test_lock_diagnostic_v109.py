"""Synthetic lock-custody regressions; no pnpm, application, Git, network or CI."""
import contextlib
import io
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

import lockfile_policy_v109 as lockpolicy
import source_validation_contract_v109 as policy
import source_validation_v109 as owner


class LockDiagnosticTests(unittest.TestCase):
    def setup_case(self, root, *, exit_code=0, timed_out=False):
        source=root/'source';source.mkdir();pipeline=root/'pipeline';pipeline.mkdir()
        (source/'pnpm-lock.yaml').write_bytes(b'original synthetic public lock')
        candidate=pipeline/owner.CANDIDATE;candidate.mkdir(parents=True)
        (candidate/'registry-metadata.json').write_bytes(b'{}')
        event=root/'event.json';event.write_bytes(b'{}')
        request={'phase':'lock-preparation','source':{'sourceSha':'a'*40,'sourceTree':'b'*40,
            'fileSha256':{name:'c'*64 for name in ('package.json','pnpm-workspace.yaml','pnpm-lock.yaml',policy.LEDGER)}}}
        env={'RUNNER_TEMP':str(root),'GITHUB_RUN_ID':'123456789','GITHUB_EVENT_PATH':str(event)}
        class Core:
            def clean_env(self,*args):return {'PATH':'SYNTHETIC'}
            def resource_check(self,*args):pass
            def phase_process(self,*args):
                (source/'pnpm-lock.yaml').write_bytes(b'generated synthetic public lock')
                return types.SimpleNamespace(returncode=exit_code,timed_out=timed_out,cleanup_settled=True)
        return source,pipeline,request,env,Core()

    def invoke(self, source,pipeline,request,env,core,*,security=None,delta=None):
        responses=delta or [b'pnpm-lock.yaml\n',b'',b'closed synthetic public diff']
        with patch.object(owner,'static_source',return_value={}),\
             patch.object(policy,'recheck_registry_proof',return_value={'synthetic':True}),\
             patch.object(owner,'internal_bootstrap'),\
             patch.object(owner,'git_read',side_effect=responses),\
             patch.object(owner,'event_binding',return_value='d'*40),\
             patch.object(lockpolicy,'verify_lock_security',side_effect=security or (lambda *args:{'synthetic':True})),\
             contextlib.redirect_stdout(io.StringIO()):
            owner.derive(pipeline,source,{},request,env,core,{'deadlineEpoch':9999999999})

    def test_owned_fixed_lock_refusal_only_is_public(self):
        self.assertEqual(owner.safe_refusal_code(lockpolicy.LockRefusal('v9.two_pnpm_documents')),'v9.two_pnpm_documents')
        for error in (ValueError('v9.two_pnpm_documents'),lockpolicy.LockRefusal('private secret'),
                      lockpolicy.LockRefusal('v9.two\nprivate'),lockpolicy.LockRefusal('v9.nested.private')):
            self.assertEqual(owner.safe_refusal_code(error),'v9.runtime_refused')

    def test_rejected_security_preserves_bytes_before_gate_and_never_generation(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve();case=self.setup_case(root)
            def reject(*args):
                out=root/'v109-lock-diagnostic'
                self.assertEqual((out/'pnpm-lock.yaml').read_bytes(),args[1])
                self.assertFalse((root/'v109-lock-artifact').exists())
                raise lockpolicy.LockRefusal('v9.carried_security_versions_preserved')
            with self.assertRaisesRegex(lockpolicy.LockRefusal,'carried_security_versions_preserved'):
                self.invoke(*case,security=reject)
            out=root/'v109-lock-diagnostic'
            self.assertEqual(sorted(p.name for p in out.iterdir()),['lock-diagnostic.json','lock.diff','pnpm-lock.yaml'])
            meta=policy.parse((out/'lock-diagnostic.json').read_bytes())
            self.assertEqual(meta['status'],'unvalidated');self.assertIs(meta['acceptedAsGeneration'],False)
            self.assertIs(meta['securityCheckCompleted'],False)
            self.assertEqual(meta['generatedLockSha256'],policy.digest((out/'pnpm-lock.yaml').read_bytes()))
            self.assertEqual(meta['gitDiffSha256'],policy.digest((out/'lock.diff').read_bytes()))
            for key in ('imageBuilt','qualified','productionAuthorized'):self.assertIs(meta[key],False)
            for p in out.iterdir():self.assertEqual(p.stat().st_mode&0o777,0o600)
            self.assertFalse((root/'v109-lock-artifact').exists())

    def test_success_still_requires_security_and_exact_official_three_members(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve();case=self.setup_case(root);seen=[]
            def accept(*args):seen.append(True);return {'synthetic':True}
            self.invoke(*case,security=accept)
            self.assertEqual(seen,[True]);out=root/'v109-lock-artifact'
            self.assertEqual(sorted(p.name for p in out.iterdir()),['generation.json','lock.diff','pnpm-lock.yaml'])
            self.assertEqual(policy.parse((out/'generation.json').read_bytes())['status'],'derived_only')

    def test_failed_or_timed_out_pnpm_does_not_capture_or_approve(self):
        for code,timed in ((1,False),(0,True),(None,True)):
            with self.subTest(code=code,timed=timed),tempfile.TemporaryDirectory() as folder:
                root=Path(folder).resolve();case=self.setup_case(root,exit_code=code,timed_out=timed)
                with self.assertRaisesRegex(policy.Refusal,'lock_derivation_failed'):self.invoke(*case)
                self.assertFalse((root/'v109-lock-diagnostic').exists());self.assertFalse((root/'v109-lock-artifact').exists())

    def test_unexpected_worktree_delta_not_uploaded(self):
        for delta in ([b'package.json\npnpm-lock.yaml\n',b''],[b'pnpm-lock.yaml\n',b'untracked-private-file']):
            with self.subTest(delta=delta),tempfile.TemporaryDirectory() as folder:
                root=Path(folder).resolve();case=self.setup_case(root)
                with self.assertRaisesRegex(policy.Refusal,'lock_only_worktree_delta'):self.invoke(*case,delta=delta)
                self.assertFalse((root/'v109-lock-diagnostic').exists());self.assertFalse((root/'v109-lock-artifact').exists())

    def test_combined_diagnostic_cap_refuses_before_writing(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve();source,pipeline,r,e,c=self.setup_case(root)
            with self.assertRaisesRegex(policy.Refusal,'lock_diagnostic_size'):
                owner.retain_unvalidated_lock(b'x'*policy.ARTIFACT_BYTES,b'diff',r,e,'2026-10-30T07:00:00Z')
            self.assertFalse((root/'v109-lock-diagnostic').exists())

    def test_existing_output_not_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve();case=self.setup_case(root);out=root/'v109-lock-diagnostic';out.mkdir()
            marker=out/'pnpm-lock.yaml';marker.write_bytes(b'original retained bytes')
            with self.assertRaisesRegex(policy.Refusal,'lock_diagnostic_output_fresh'):self.invoke(*case)
            self.assertEqual(marker.read_bytes(),b'original retained bytes');self.assertFalse((root/'v109-lock-artifact').exists())

    def test_custody_write_failure_cannot_publish_generation(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve();case=self.setup_case(root)
            with patch.object(owner,'private_write',side_effect=OSError('synthetic write failure')):
                with self.assertRaises(OSError):self.invoke(*case)
            self.assertFalse((root/'v109-lock-artifact').exists())

    def test_failure_only_workflow_is_distinct_from_official_artifact(self):
        raw=(Path(__file__).parent/'fixtures/v109-lock-preparation.yml').read_text()
        block=raw.split('      - name: Retain bounded unvalidated lock diagnostic on refusal\n',1)[1].split('      - name: Retain exact lock derivation for review\n',1)[0]
        self.assertIn("if: failure() && steps.derivation.outcome == 'failure'",block)
        self.assertIn('name: v109-lock-diagnostic-${{ github.run_id }}-attempt1',block)
        self.assertIn('retention-days: 3',block)
        self.assertEqual(block.count('${{ runner.temp }}/v109-lock-diagnostic/'),3)
        self.assertNotIn('generation.json',block);self.assertNotIn('secrets.',block)


if __name__=='__main__':unittest.main()
