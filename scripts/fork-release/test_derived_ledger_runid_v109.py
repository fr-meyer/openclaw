"""Synthetic one-field ABI proof; no actual H, Git writes or process calls."""
import ast
from copy import deepcopy
import hashlib
import importlib.util
from pathlib import Path
import sys
import unittest

HERE=Path(__file__).resolve().parent
POLICY=HERE/'source_validation_contract_v109.py'
if not POLICY.is_file():POLICY=HERE/'files/scripts/fork-release/source_validation_contract_v109.py'
CHECKER=HERE/'source_reconciliation_v109.py'
if not CHECKER.is_file():CHECKER=HERE/'proof-code/source_reconciliation_v109.py'
sys.path.insert(0,str(HERE/'proof-code'))

def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
m=load('derived_ledger_policy_under_test',POLICY)
checker=load('unchanged_v4_receipt_consumer',CHECKER)


def pin():
 # Synthetic provider identifiers/pins, never an operational generation record.
 return {'runId':'123456789','runAttempt':1,'pipelineHead':'a'*40,'artifactId':123,
  'artifactSha256':'b'*64,'receiptSha256':'c'*64,'generatedLockSha256':'d'*64,'gitDiffSha256':'e'*64}


def ledger():
 return {'schema':'openclaw.v109.fork-carry-reconciliation.v1','lockState':'pending_ci_derivation',
  'sourcePaths':[{'path':'pnpm-lock.yaml','result':{'mode':'100644','blob':'f'*40},'disposition':'LOCK_CONTROLLED_DERIVATION'}],
  'unrelatedSyntheticField':{'preserved':[1,2,3]}}


def actual_v4_receipt_guard(derived):
 # Execute the actual pinned consumer's receipt assignment and predicate,
 # unmodified. This is the narrow ABI seam, not a full Git/source-graph replay.
 raw=CHECKER.read_bytes()
 if hashlib.sha256(raw).hexdigest()!='aabbc7684d8ab1b9da2f4529fbd146d6d1ad69105a08aa8cc44ccf1e3bba7e54':raise AssertionError('checker pin')
 function=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name=='check_v109_reconciliation')
 conditional=next(n for n in function.body if isinstance(n,ast.If)and isinstance(n.test,ast.Compare)and
  any(isinstance(c,ast.Constant)and c.value=='pending_ci_derivation'for c in n.test.comparators))
 statements=conditional.orelse[:2]
 if not (isinstance(statements[0],ast.Assign)and isinstance(statements[1],ast.Expr)and
     any(isinstance(x,ast.Constant)and x.value=='invalid 10.9 lock derivation receipt'for x in ast.walk(statements[1]))):raise AssertionError('actual receipt predicate missing')
 def need(value,code):
  if not value:raise ValueError(code)
 scope=dict(vars(checker));scope.update(ledger=derived,need=need)
 exec(compile(ast.fix_missing_locations(ast.Module(body=statements,type_ignores=[])),'actual-v4-receipt-predicate','exec'),scope)


class LedgerRunIdTests(unittest.TestCase):
 def test_actual_v4_consumer_accepts_derived_integer(self):
  result=m.parse(m.expected_derived_ledger(m.encode(ledger()),'1'*40,pin()))
  actual_v4_receipt_guard(result)
  self.assertIs(type(result['lockDerivation']['runId']),int);self.assertEqual(result['lockDerivation']['runId'],123456789)
 def test_only_committed_ledger_uses_integer_provider_pin_stays_string(self):
  before=ledger();beforeRaw=m.encode(before);g=pin();original=deepcopy(g)
  out=m.parse(m.expected_derived_ledger(beforeRaw,'1'*40,g))
  self.assertEqual(g,original);self.assertIs(type(g['runId']),str);self.assertEqual(m.generation_pin(g),original)
  expected=deepcopy(before);expected['sourcePaths'][0]['result']={'mode':'100644','blob':'1'*40};expected['lockState']='ci_derived'
  expected['lockDerivation']={'runId':123456789,'attempt':1,'artifactSha256':g['artifactSha256'],
   'generatedLockSha256':g['generatedLockSha256'],'receiptSha256':g['receiptSha256']}
  self.assertEqual(out,expected);self.assertEqual(beforeRaw,m.encode(before))
 def test_wrong_type_run_ids_refuse_before_any_coercion(self):
  class Trap:
   called=False
   def __int__(self):self.called=True;raise AssertionError('coerced before validation')
  trap=Trap()
  for value in (123,True,None,trap):
   g=pin();g['runId']=value
   with self.subTest(kind=type(value).__name__),self.assertRaises(m.Refusal):m.expected_derived_ledger(m.encode(ledger()),'1'*40,g)
  self.assertFalse(trap.called)
 def test_invalid_string_ids_and_hash_pins_refuse_without_mutation(self):
  for value in ('','0','0123','-1','+1','1.0','1e3','123x'):
   g=pin();g['runId']=value;old=deepcopy(g)
   with self.subTest(value=value),self.assertRaises(m.Refusal):m.expected_derived_ledger(m.encode(ledger()),'1'*40,g)
   self.assertEqual(g,old)
  for key,value in [('artifactSha256','x'*64),('receiptSha256','c'*63),('artifactId',True),('runAttempt',True)]:
   g=pin();g[key]=value;old=deepcopy(g)
   with self.subTest(key=key),self.assertRaises(m.Refusal):m.expected_derived_ledger(m.encode(ledger()),'1'*40,g)
   self.assertEqual(g,old)
 def test_invalid_initial_ledger_or_lock_blob_refuses_without_input_changes(self):
  before=ledger();before['lockDerivation']={};raw=m.encode(before);g=pin();old=deepcopy(g)
  with self.assertRaises(m.Refusal):m.expected_derived_ledger(raw,'1'*40,g)
  with self.assertRaises(m.Refusal):m.expected_derived_ledger(m.encode(ledger()),'x'*40,g)
  self.assertEqual(raw,m.encode(before));self.assertEqual(g,old)
 def test_unchanged_v4_predicate_still_refuses_string_bool_and_nonpositive(self):
  good=m.parse(m.expected_derived_ledger(m.encode(ledger()),'1'*40,pin()))
  for value in ('123456789',True,0,-1):
   bad=deepcopy(good);bad['lockDerivation']['runId']=value
   with self.subTest(value=value),self.assertRaisesRegex(ValueError,'invalid 10.9 lock derivation receipt'):actual_v4_receipt_guard(bad)

if __name__=='__main__':unittest.main()
