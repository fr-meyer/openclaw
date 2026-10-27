"""Public synthetic contract tests; no real report or Linux proof."""
import ast
from contextlib import contextmanager
import hashlib
import json
import shutil
from pathlib import Path
import signal
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

import consumer_compat as c

ROOT=Path(__file__).resolve().parent


class CompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='public-consumer-contract-')
        self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name).resolve()

    def test_actual_seven_case_suite_and_closed_summary(self):
        result=c.run_suite(ROOT,self.base/'scratch')
        self.assertEqual(set(result),{'schema','status','testsRun','failures','sourceHashes',
                                     'elapsedMilliseconds','fixtureOnly','nativeProof'})
        self.assertEqual(result['status'],'passed')
        self.assertEqual(result['testsRun'],7)
        self.assertEqual(result['failures'],[])
        self.assertTrue(result['fixtureOnly']);self.assertFalse(result['nativeProof'])
        self.assertLessEqual(result['elapsedMilliseconds'],240000)
        self.assertEqual(result['sourceHashes'],{name:pin for name,(_path,pin) in c.PINS.items()})
        self.assertEqual(list((self.base/'scratch').iterdir()),[])

    def test_sources_preserve_recorded_validation_definition_ast(self):
        record=json.loads((ROOT/'PUBLIC-CONSUMER-ORIGIN.json').read_bytes())
        for name,row in record['sources'].items():
            tree=ast.parse((ROOT/name).read_bytes())
            funcs={node.name:ast.dump(node,include_attributes=False) for node in tree.body
                   if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef))}
            self.assertEqual(len(funcs),row['definitionCount'])
            self.assertEqual(hashlib.sha256(json.dumps(funcs,sort_keys=True).encode()).hexdigest(),
                             row['definitionASTSha256'])
            self.assertTrue(row['allFunctionAndClassASTsUnchanged'])

    def test_synthetic_source_and_plan_are_bound_not_a_saved_verdict(self):
        privacy,export,plan=c._load(ROOT)
        self.assertEqual(plan['sourceSha'],c.SOURCE)
        self.assertEqual(privacy.PUBLIC_MEMBER_QUALIFICATION['sourceSha'],c.SOURCE)
        self.assertEqual(privacy.PUBLIC_MEMBER_QUALIFICATION['planSha256'],
                         c.PINS['public-member-comparisons-v105-workboard.json'][1])
        self.assertEqual(privacy.REPOSITORY,'example/fixture')
        self.assertEqual(len(plan['entries']),1)
        self.assertEqual(plan['entries'][0]['evidence']['reference'],
                         'https://example.invalid/synthetic-fixture.txt')

    def test_changed_source_plan_refuses_before_code_execution(self):
        source=self.base/'source';source.mkdir()
        for name in c.PINS:shutil.copyfile(ROOT/name,source/name)
        (source/'public-member-comparisons-v105-workboard.json').write_bytes(b'{}')
        with self.assertRaisesRegex(c.CompatibilityRefusal,'source_pin'):
            c.run_suite(source,self.base/'scratch')
        self.assertFalse((self.base/'scratch').exists())

    def test_source_symlink_and_group_writable_input_refuse(self):
        path=self.base/'alias.py';path.symlink_to(ROOT/'hosted_export.py')
        with self.assertRaisesRegex(c.CompatibilityRefusal,'source_path'):
            c._source_bytes(path,c.PINS['hosted_export.py'][1])
        regular=self.base/'regular.py';regular.write_bytes(b'public');regular.chmod(0o666)
        with self.assertRaisesRegex(c.CompatibilityRefusal,'source_identity'):
            c._source_bytes(regular,c.digest(b'public'))

    def test_existing_scratch_refuses_without_modifying_it(self):
        scratch=self.base/'scratch';scratch.mkdir();keep=scratch/'keep';keep.write_bytes(b'unmodified')
        with self.assertRaisesRegex(c.CompatibilityRefusal,'scratch_fresh'):c.run_suite(ROOT,scratch)
        self.assertEqual(keep.read_bytes(),b'unmodified')

    def test_ambient_consumer_module_is_not_adopted(self):
        foreign=types.ModuleType('hosted_privacy')
        with patch.dict(sys.modules,{'hosted_privacy':foreign}):
            with self.assertRaisesRegex(c.CompatibilityRefusal,'ambient_consumer_module'):c._load(ROOT)
            self.assertIs(sys.modules['hosted_privacy'],foreign)

    def test_successful_load_restores_module_registry(self):
        self.assertNotIn('hosted_privacy',sys.modules)
        c._load(ROOT)
        self.assertNotIn('hosted_privacy',sys.modules)
        self.assertNotIn('hosted_export',sys.modules)

    def test_one_unexpected_case_failure_stops_without_hidden_retry(self):
        calls=[]
        class Unexpected(unittest.TestCase):
            def test_case(self):calls.append(1);self.fail('synthetic failure body is not returned')
        def fail_suite(*_args):return unittest.defaultTestLoader.loadTestsFromTestCase(Unexpected)
        with patch.object(c,'_suite',fail_suite):
            result=c.run_suite(ROOT,self.base/'scratch')
        self.assertEqual(calls,[1]);self.assertEqual(result['status'],'failed')
        self.assertEqual(result['testsRun'],1)
        self.assertEqual(result['failures'],[{'case':'test_case','type':'AssertionError'}])
        self.assertNotIn('failure body',json.dumps(result))

    def test_timeout_cannot_be_a_successful_empty_result(self):
        @contextmanager
        def expired():raise c.CompatibilityTimeout('synthetic');yield
        with patch.object(c,'_deadline',expired):
            result=c.run_suite(ROOT,self.base/'scratch')
        self.assertEqual(result['status'],'failed');self.assertEqual(result['testsRun'],0)
        self.assertEqual(result['failures'],[{'case':'suite','type':'CompatibilityTimeout'}])

    def test_timer_setup_error_still_restores_previous_handler(self):
        operations=[];attempts=[0]
        def fake_timer(kind,value):
            attempts[0]+=1;operations.append(('timer',value))
            if attempts[0]==1:raise OSError('synthetic timer setup')
        def fake_signal(kind,handler):operations.append(('handler',handler))
        with patch.object(c.signal,'getsignal',return_value='previous'), \
             patch.object(c.signal,'getitimer',return_value=(0,0)), \
             patch.object(c.signal,'signal',side_effect=fake_signal), \
             patch.object(c.signal,'setitimer',side_effect=fake_timer):
            with self.assertRaises(OSError):
                with c._deadline():self.fail('setup did not refuse')
        self.assertIn(('timer',0),operations)
        self.assertEqual(operations[-1],('handler','previous'))

    def test_timer_cleanup_error_never_joins_a_passing_suite(self):
        @contextmanager
        def failed_cleanup():yield {'cleanupErrors':['OSError'],'outerExpired':False}
        with patch.object(c,'_deadline',failed_cleanup):
            result=c.run_suite(ROOT,self.base/'scratch')
        self.assertEqual(result['testsRun'],7)
        self.assertEqual(result['status'],'failed')
        self.assertEqual(result['failures'],[{'case':'timer','type':'TimerRestoreError'}])


if __name__=='__main__':unittest.main()
