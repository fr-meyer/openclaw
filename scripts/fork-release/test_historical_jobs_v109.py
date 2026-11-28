"""Pure synthetic metadata comparator tests, never provider observations.

Load only actual comparator AST and constants. No operational owner imports,
Git/client/process commands, files rewritten, source code or network execution.
The synthetic complete native envelopes deliberately model provider metadata;
no added value is claimed to have been observed on a historical run.
"""
import ast
from copy import deepcopy
import json
from pathlib import Path
import re
import types
import unittest

PATH=Path(__file__).with_name('source_validation_v109.py')
tree=ast.parse(PATH.read_text())
functions={'_historical_fact_equal','_historical_steps_match','historical_jobs_match'}
schema_constants={'HISTORICAL_JOB_PROJECTED_FIELDS','HISTORICAL_JOB_NATIVE_FIELDS','HISTORICAL_PRESENCE_ORDER','HISTORICAL_STEP_PROJECTED_FIELDS','HISTORICAL_STEP_NATIVE_FIELDS'}
selected=[node for node in tree.body if
    isinstance(node,ast.FunctionDef) and node.name in functions or
    isinstance(node,ast.Assign) and any(isinstance(target,ast.Name) and target.id in schema_constants for target in node.targets)]
m=types.ModuleType('actual_historical_comparator_under_test')
m.policy=types.SimpleNamespace(pin=lambda value,bits=256:type(value)is str and
    re.fullmatch(r'[0-9a-f]{'+str(bits//4)+r'}',value)is not None)
exec(compile(ast.Module(body=selected,type_ignores=[]),str(PATH),'exec'),m.__dict__)

RUN={'id':12345,'head_sha':'a'*40,'run_attempt':1}


def synthetic_native_fixture(jid=777):
    """Explicit model, not a reconstruction or new native provider receipt."""
    return {'id':jid,'run_id':RUN['id'],'workflow_name':'synthetic workflow','head_branch':'synthetic branch',
        'run_url':'https://example.invalid/synthetic/run','run_attempt':1,'node_id':'synthetic node',
        'head_sha':RUN['head_sha'],'url':'https://example.invalid/synthetic/job',
        'html_url':'https://example.invalid/synthetic/html','status':'completed','conclusion':'success',
        'created_at':'2026-01-01T00:00:00Z','started_at':'2026-01-01T00:00:01Z',
        'completed_at':'2026-01-01T00:01:00Z','name':'synthetic job',
        'steps':[{'name':'synthetic setup','status':'completed','conclusion':'success','number':1,
                  'started_at':'2026-01-01T00:00:01Z','completed_at':'2026-01-01T00:00:02Z'},
                 {'name':'synthetic check','status':'completed','conclusion':'success','number':2,
                  'started_at':'2026-01-01T00:00:02Z','completed_at':'2026-01-01T00:01:00Z'}],
        'check_run_url':'https://example.invalid/synthetic/check','labels':['ubuntu-24.04'],
        'runner_id':999,'runner_name':'synthetic runner','runner_group_id':1,'runner_group_name':'GitHub Actions'}


def projected(native,presence=False):
    value={key:deepcopy(native[key]) for key in m.HISTORICAL_JOB_PROJECTED_FIELDS}
    value['steps']=[{key:step[key] for key in m.HISTORICAL_STEP_PROJECTED_FIELDS} for step in native['steps']]
    if presence:value['_fieldsPresent']=list(m.HISTORICAL_PRESENCE_ORDER)
    return value


def match(native,old,run=None):
    return m.historical_jobs_match(native,old,RUN if run is None else run)


class HistoricalJobsTests(unittest.TestCase):
    def test_three_known_producer_shapes_match_and_preserve_input(self):
        n=synthetic_native_fixture()
        for old in (projected(n),projected(n,True),deepcopy(n)):
            before=json.dumps([n,old],sort_keys=True)
            with self.subTest(keys=len(old)):self.assertTrue(match([n],[old]))
            self.assertEqual(json.dumps([n,old],sort_keys=True),before)
            if len(old)<23:self.assertNotIn('run_attempt',old)

    def test_projection_is_not_a_complete_native_reply(self):
        n=synthetic_native_fixture()
        for old in (projected(n),projected(n,True)):
            self.assertFalse(match([deepcopy(old)],[old]))

    def test_unrecorded_native_fields_and_new_metadata_are_not_changed_facts(self):
        n=synthetic_native_fixture();old=projected(n,True)
        n['workflow_name']='changed unrecorded metadata';n['created_at']='unrecorded timestamp'
        n['provider_new_field']={'nested':[True,None,3]}
        self.assertTrue(match([n],[old]))

    def test_every_full_native_recorded_fact_remains_exact(self):
        original=synthetic_native_fixture()
        for field in m.HISTORICAL_JOB_NATIVE_FIELDS-{'steps'}:
            n=deepcopy(original)
            value=n[field]
            n[field]=value+1 if type(value)is int else ['different'] if type(value)is list else 'different'
            with self.subTest(field=field):self.assertFalse(match([n],[original]))

    def test_recorded_none_is_not_missing_or_empty(self):
        n=synthetic_native_fixture();n.update(runner_id=None,runner_name=None,runner_group_name=None)
        old=projected(n)
        self.assertTrue(match([n],[old]))
        for field in ('runner_id','runner_name','runner_group_name'):
            absent=deepcopy(n);del absent[field]
            empty=deepcopy(n);empty[field]=''
            with self.subTest(field=field):
                self.assertFalse(match([absent],[old]));self.assertFalse(match([empty],[old]))

    def test_every_complete_native_field_must_be_explicitly_present(self):
        n=synthetic_native_fixture();old=projected(n)
        for field in m.HISTORICAL_JOB_NATIVE_FIELDS:
            bad=deepcopy(n);del bad[field]
            with self.subTest(field=field):self.assertFalse(match([bad],[old]))

    def test_positive_job_context_is_bound_even_when_not_recorded(self):
        n=synthetic_native_fixture();old=projected(n)
        for key,value in (('run_id',54321),('run_id',True),('head_sha','b'*40),('run_attempt',2),('run_attempt',True)):
            bad=deepcopy(n);bad[key]=value
            with self.subTest(key=key,value=value):self.assertFalse(match([bad],[old]))
        for key,value in (('id',True),('id',None),('run_attempt',True),('run_attempt',None),('head_sha','bad')):
            run=deepcopy(RUN);run[key]=value
            with self.subTest(run_key=key):self.assertFalse(match([n],[old],run))

    def test_exact_id_set_count_and_no_duplicate_ids(self):
        a=synthetic_native_fixture(1);b=synthetic_native_fixture(2);old=[projected(a),projected(b,True)]
        self.assertTrue(match([b,a],old))
        for native in ([a],[a,a],[a,b,b],[a,synthetic_native_fixture(3)]):
            self.assertFalse(match(native,old))
        self.assertFalse(match([a,b],[old[0],deepcopy(old[0])]))
        bad=deepcopy(a);bad['id']=True
        self.assertFalse(match([bad],[projected(a)]))

    def test_original_presence_provenance_not_required_from_provider(self):
        n=synthetic_native_fixture();old=projected(n,True)
        self.assertNotIn('_fieldsPresent',n);self.assertTrue(match([n],[old]))
        for change in ('missing','duplicate','unknown','wrong-order','wrong-type'):
            bad=deepcopy(old)
            if change=='missing':bad['_fieldsPresent'].pop()
            elif change=='duplicate':bad['_fieldsPresent'][-1]=bad['_fieldsPresent'][0]
            elif change=='unknown':bad['_fieldsPresent'][-1]='new-original-field'
            elif change=='wrong-order':bad['_fieldsPresent'].reverse()
            else:bad['_fieldsPresent']=tuple(bad['_fieldsPresent'])
            with self.subTest(change=change):self.assertFalse(match([n],[bad]))

    def test_unknown_frozen_job_shape_refuses(self):
        n=synthetic_native_fixture();old=projected(n)
        bad=deepcopy(old);bad['unreviewed_field']=1
        self.assertFalse(match([n],[bad]))
        del old['runner_name'];self.assertFalse(match([n],[old]))

    def test_step_count_and_order_are_recorded_facts(self):
        n=synthetic_native_fixture();old=projected(n)
        for transform in (lambda x:x.reverse(),lambda x:x.pop(),lambda x:x.append(deepcopy(x[-1]))):
            bad=deepcopy(n);transform(bad['steps']);self.assertFalse(match([bad],[old]))

    def test_step_recorded_values_are_type_exact(self):
        n=synthetic_native_fixture();old=projected(n)
        for key,value in (('name','different'),('status','queued'),('conclusion',None),('number',True),('number',3)):
            bad=deepcopy(n);bad['steps'][0][key]=value
            with self.subTest(key=key):self.assertFalse(match([bad],[old]))
        bad=deepcopy(n);bad['runner_id']=True;old=projected(n);old['runner_id']=1
        self.assertFalse(match([bad],[old]))

    def test_known_four_and_six_step_fields_only(self):
        n=synthetic_native_fixture()
        self.assertTrue(match([n],[projected(n)]));self.assertTrue(match([n],[deepcopy(n)]))
        for count in (3,5):
            old=projected(n) if count==3 else deepcopy(n)
            del old['steps'][0]['number' if count==3 else 'started_at']
            with self.subTest(count=count):self.assertFalse(match([n],[old]))

    def test_native_step_envelope_explicit_and_unknown_extras_ignored(self):
        n=synthetic_native_fixture();old=projected(n)
        n['steps'][0]['new_provider_metadata']=42
        self.assertTrue(match([n],[old]))
        del n['steps'][0]['completed_at'];self.assertFalse(match([n],[old]))

    def test_only_recorded_step_timestamps_compared(self):
        n=synthetic_native_fixture();projected_old=projected(n);native_old=deepcopy(n)
        n['steps'][0]['completed_at']='changed unrecorded metadata'
        self.assertTrue(match([n],[projected_old]));self.assertFalse(match([n],[native_old]))

    def test_empty_collections_require_positive_run_identity(self):
        self.assertTrue(match([],[]));self.assertFalse(match([],[],{}))
        self.assertFalse(match(None,[]));self.assertFalse(match([],{}))


if __name__=='__main__':unittest.main()
