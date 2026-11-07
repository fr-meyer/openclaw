"""Actual integrated Python dispatch with synthetic transport/process boundaries."""
import ast
import copy
import builtins
import dis
import types
import importlib.util
import json
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
OWNER=HERE if (HERE/'source_validation_v108.py').is_file() else HERE/'pipeline/scripts/fork-release'
sys.path.insert(0,str(OWNER))
spec=importlib.util.spec_from_file_location('r8_runtime_owner',OWNER/'source_validation_v108.py')
D=importlib.util.module_from_spec(spec);spec.loader.exec_module(D)
ROOT=OWNER.parents[1]
C=OWNER/'candidates/v2026.10.8-source-only'

def request():return json.loads((C/'source-request.json').read_bytes())

class Runtime(unittest.TestCase):
    def test_metadata_uses_genuine_f_and_retained_generation(self):
        r,m,h=D.metadata(ROOT)
        self.assertEqual(r,request());self.assertEqual(h,D.R8_STAGE_PINS['manifestSha256'])
        self.assertEqual((m['source']['commit'],m['source']['tree']),(D.R8_SOURCE,D.R8_TREE))
        self.assertEqual(D.operational_input_paths(r),(D.R8_SETTLED_USAGE_PATH,D.R7_PREPARATION_PROOF_PATH))

    def test_r8_identity_deadline_caps_without_historical_mutation(self):
        r=request()
        self.assertEqual(D.source_identity_for(r),(D.R8_SOURCE,D.R8_TREE))
        self.assertEqual(D.approval_deadline_for(r),'2026-10-30T08:03:19Z')
        self.assertEqual(D.profile_minutes_for(r)['doctor-2'],75)
        self.assertEqual(D.R7_STAGE_PINS['sourceSha'],'76522eaa2dd93a4933b5c87f7451eab1d458f8be')
        self.assertEqual(D.R7_DEADLINE,'2026-10-30T00:03:19Z')
        self.assertEqual(D.source_identity_for(None),(D.SOURCE,D.TREE))
        self.assertEqual(D.profile_minutes_for(None)['doctor-1'],45)

    def test_clock_shared_thirty_minutes_and_deadline(self):
        start=int(D.timestamp('2026-10-29T15:00:00Z').timestamp())
        env={'GITHUB_JOB':'admission','SOURCE_ADMISSION_STARTED_EPOCH':str(start)}
        with patch.object(D.time,'time',return_value=start+1790):
            self.assertEqual(D.admission_deadline(env,request()),start+1740)
        for now in (start-1,start+1800):
            with patch.object(D.time,'time',return_value=now),self.assertRaises(D.R8ContractRefusal):
                D.admission_deadline(env,request())

    def test_runtime_history_and_equivalence_dispatch_exact_pins(self):
        r=request();event={};env={};api=object();reader=object()
        with patch.object(D,'history_checks_v8',return_value={'synthetic':1}) as h:
            self.assertEqual(D.history_checks_for_operational_request(r,event,env,ROOT,api),{'synthetic':1})
            h.assert_called_once_with(r,event,env,ROOT,api,D.R8_STAGE_PINS)
        with patch.object(D,'verify_source_equivalence_v8',return_value={'synthetic':2}) as v:
            self.assertEqual(D.verify_operational_source(r,ROOT,reader),{'synthetic':2})
            self.assertEqual(v.call_args[0][:3],(r,D.R8_STAGE_PINS,reader))

    def test_compatibility_and_all_historical_contracts_plus_new_suites(self):
        r=request();paths=[*D.V6_RUNTIME_COMPATIBILITY_TESTS,'test/v108-remediation-security.test.mjs']
        self.assertEqual(D.selected_tests(paths,'compatibility',r),list(D.V6_RUNTIME_COMPATIBILITY_TESTS))
        argv=D.commands(ROOT,Path('/synthetic-source'),'types-tests',paths,r)
        self.assertEqual(argv,[['pnpm','tsgo:test']])
        planned=D.commands(ROOT,Path('/synthetic-source'),'pipeline-contracts',paths,r)
        names=[a[-1] for a in planned]
        for name in ('test_request_contract_v6.py','test_request_contract_v7.py','test_targeted_tag_reuse_v108.py',
                     'test_request_contract_v8.py','test_history_checks_v8.py','test_runtime_contract_v8.py','test_composite_closed_usage.py'):
            self.assertIn(name,names)
        self.assertNotIn('test_v108_runtime_contract_v4.py',names)

    def test_r8_tag_guard_accepts_only_closed_r8_both_rounds(self):
        # No real Git/process calls: stop at the first inventory guard after
        # exact request validation; this proves correct entry, not object import.
        for number in (1,2):
            # This loop owns two synthetic UNIT contexts, independent of
            # whether the real current invocation is full or targeted.
            r=request();pins=copy.deepcopy(D.R8_STAGE_PINS)
            pins['priorValidationRuns']=[]
            r.update(stageRound=1,lifetimeOperatorRound=12,profiles=list(D.V6_PROFILES),
                priorRunIds=list(D.R8_BASELINE_SOURCE_IDS))
            if number==2:
                pins['priorValidationRuns']=[{'runId':'99000000001','pipelineHead':'a'*40,'requestSha256':'b'*64}]
                r.update(stageRound=2,lifetimeOperatorRound=13,profiles=['pipeline-contracts'],
                    priorRunIds=[*r['priorRunIds'],'99000000001'])
            with patch.object(D,'R8_STAGE_PINS',pins),self.assertRaises(D.R7ContractRefusal) as caught:
                D.reuse_upstream_tag_v8(ROOT,Path('/synthetic'),r,{},None,{}, {'request':r})
            self.assertEqual(str(caught.exception),'r7.tag_reuse_inventory')
        r=request();r['schema']=D.R7_SCHEMA
        with self.assertRaises(D.R8ContractRefusal):D.reuse_upstream_tag_v8(ROOT,None,r,{},None,{}, {'request':r})

    def test_r8_refusals_fixed_projection_no_payload(self):
        self.assertEqual(D.runtime_refusal_code_v7(D.R8ContractRefusal('r8.stage_pins')),'r8.stage_pins')
        self.assertEqual(D.runtime_refusal_code_v7(D.R8ContractRefusal('secret payload')),'r8.unprojected')
        self.assertEqual(D.runtime_refusal_code_v7(D.R7ContractRefusal('r7.closed_request')),'r7.closed_request')

    def test_history_global_dependencies_are_bound_in_actual_driver(self):
        def check(code):
            for instruction in dis.get_instructions(code):
                if instruction.opname == 'LOAD_GLOBAL':
                    self.assertTrue(instruction.argval in D.__dict__ or
                        hasattr(builtins, instruction.argval), instruction.argval)
            for value in code.co_consts:
                if isinstance(value, types.CodeType): check(value)
        for name,value in vars(D).items():
            if isinstance(value,types.FunctionType) and (name.startswith('_h8_') or
                    name in ('booking_v8','workflow_security_v8','history_checks_v8')):
                check(value.__code__)
        self.assertEqual(D.R8_DIAGNOSTIC_BYTES,64*1024*1024)

    def test_code_binding_and_donor_have_r8_fixed_owner_closure(self):
        source=(OWNER/'source_validation_v108.py').read_text();tree=ast.parse(source)
        funcs={n.name:ast.get_source_segment(source,n) for n in tree.body if isinstance(n,ast.FunctionDef)}
        self.assertIn('scripts/fork-release/composite_closed_usage.py',funcs['code_binding'])
        self.assertIn('len(commits) == 12',funcs['fetch_closure'])
        self.assertIn('reuse_upstream_tag_v8(',funcs['fetch_closure'])
        self.assertIn('source_preflight(pipeline, source, manifest, manifest_hash)',funcs['fetch_closure'])
        self.assertIn('local_closure_donor_uri',funcs['fetch_closure'])
        self.assertNotIn('--filter',funcs['fetch_closure'])
        self.assertNotIn('--depth',funcs['fetch_closure'])

if __name__=='__main__':unittest.main()
