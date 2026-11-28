"""Bounded synthetic request/source contracts; no API, package or app execution."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
OWNER = HERE if (HERE / 'source_validation_v108.py').is_file() else HERE / 'pipeline/scripts/fork-release'
sys.path.insert(0, str(OWNER))
spec = importlib.util.spec_from_file_location('r8_request_owner', OWNER / 'source_validation_v108.py')
D = importlib.util.module_from_spec(spec); spec.loader.exec_module(D)
CANDIDATE = OWNER / 'candidates/v2026.10.8-source-only'


def request():
    # A canonical full-round UNIT subject shares genuine reviewed source/control
    # bytes with the current request; it is never an operational invocation or
    # a claim that the current round is full. The runtime suite checks that input.
    value = json.loads((CANDIDATE / 'source-request.json').read_bytes())
    value.update(stageRound=1, lifetimeOperatorRound=12, profiles=list(D.V6_PROFILES),
        priorRunIds=list(D.R8_BASELINE_SOURCE_IDS))
    return value


def base_pins():
    value = copy.deepcopy(D.R8_STAGE_PINS)
    value['priorValidationRuns'] = []
    return value


class Request(unittest.TestCase):
    def test_full_unit_subject_genuine_source_and_closed_budget(self):
        r=request(); self.assertIs(D.validate_request_v8(r,base_pins()),r)
        b=D.validation_budget_v8(r)
        self.assertEqual(sum(b['profileMinutes'].values())+b['admissionMinutes']+b['finalMinutes'],1075)
        self.assertEqual((r['stageRound'],r['lifetimeOperatorRound']),(1,12))
        self.assertEqual(r['priorRunIds'],list(D.R8_BASELINE_SOURCE_IDS))
        self.assertEqual(r['lockPreparation'],D.R7_STAGE_PINS['preparation'])
        self.assertEqual(D.booking_v8(r,base_pins(),0,0)['bookedRunnerMinutes'],3862)

    def test_legacy_unknown_extra_missing_auth_schema_refuse(self):
        for change in [{'schema':D.R7_SCHEMA},{'sourceAuthorization':'wrong'}, {'profilePolicy':D.R7_POLICY},
                       {'unknown':False},{'schema':8}]:
            r=request();r.update(change)
            with self.subTest(change=change),self.assertRaises(D.R8ContractRefusal):D.validate_request_v8(r,base_pins())
        r=request();del r['sourceWitness']
        with self.assertRaises(D.R8ContractRefusal):D.validate_request_v8(r,base_pins())

    def test_rounds_boolean_replay_profiles_and_lifetime_refuse(self):
        for change in [{'stageRound':True},{'stageRound':0},{'stageRound':3},{'lifetimeOperatorRound':11},
                       {'lifetimeOperatorRound':True},{'profiles':['dependency']}, {'profiles':[]},
                       {'profiles':['dependency','dependency']},{'profiles':[{}]}, {'profiles':['unknown']}]:
            r=request();r.update(change)
            with self.subTest(change=change),self.assertRaises(D.R8ContractRefusal):D.validate_request_v8(r,base_pins())

    def test_source_control_baseline_preparation_or_witness_drift_refuse(self):
        for key in ('sourceSha','sourceTree','manifestSha256','inventorySha256','settledUsageSha256'):
            r=request();r[key]='0'*len(r[key])
            with self.subTest(key=key),self.assertRaises(D.R8ContractRefusal):D.validate_request_v8(r,base_pins())
        for key in ('lockPreparation','sourceWitness'):
            r=request();r[key]=dict(r[key],extra='x')
            with self.subTest(key=key),self.assertRaises(D.R8ContractRefusal):D.validate_request_v8(r,base_pins())

    def test_pin_baseline_types_and_prior_collision_refuse(self):
        for key,value in [('runCount',True),('runnerMinutesObserved',2438),('artifactSnapshot',{'count':22,'bytes':True}),
                          ('closedAt','2026-10-29T14:10:00Z'),('resolvedSha256','f'*64)]:
            pins=copy.deepcopy(base_pins());pins['baseline'][key]=value
            with self.subTest(key=key),self.assertRaises(D.R8ContractRefusal):D.validate_request_v8(request(),pins)
        pins=copy.deepcopy(base_pins());pins['priorValidationRuns']=[{'runId':D.R8_BASELINE_SOURCE_IDS[-1],
            'pipelineHead':'a'*40,'requestSha256':'b'*64}]
        with self.assertRaises(D.R8ContractRefusal):D.validate_request_v8(request(),pins)

    def test_target_exact_prior_and_inclusive_300_minute_boundary(self):
        pins=copy.deepcopy(base_pins());pins['priorValidationRuns']=[{'runId':'99000000001',
            'pipelineHead':'a'*40,'requestSha256':'b'*64}]
        r=request();r.update(stageRound=2,lifetimeOperatorRound=13,
            profiles=['types-tests','types-scripts','pipeline-contracts'],priorRunIds=[*r['priorRunIds'],'99000000001'])
        self.assertIs(D.validate_request_v8(r,pins),r)
        r['profiles']=['types-tests','types-scripts','workboard-1','pipeline-contracts']
        with self.assertRaises(D.R8ContractRefusal):D.validate_request_v8(r,pins)
        r['profiles']=['pipeline-contracts'];r['sourceWitness']['hops'][0]['step']['parentSha']='b'*40
        with self.assertRaises(D.R8ContractRefusal):D.validate_request_v8(r,pins)

    def test_no_preparation_charge_and_once_target_reservation(self):
        r=request();v=D.booking_v8(r,base_pins(),0,49)
        self.assertEqual(v['newStageBookedMinutes'],1425)
        self.assertEqual(v['futureTargetedReserveMinutes'],300)
        self.assertFalse(v['newPreparationExecutionAuthorized'])
        self.assertFalse(v['preparationChargedAgain'])
        for prior,ancillary in [(1,0),(0,51),(True,0),(0,True)]:
            with self.assertRaises(D.R8ContractRefusal):D.booking_v8(r,base_pins(),prior,ancillary)

    def test_source_verifier_calls_exact_single_step_and_historical_generation(self):
        raw=(CANDIDATE/D.R7_PREPARATION_PROOF_PATH.split('/')[-1]).read_bytes()
        # Tiny payload doubles model calls only; actual fixed hashes stay checked.
        payload={p:('synthetic '+p).encode() for p in D.R8_SOURCE_BLOBS}
        package=b'synthetic package';lock=b'synthetic lock'
        prep=copy.deepcopy(D.R7_STAGE_PINS)
        prep['preparation']['packageSha256']=hashlib.sha256(package).hexdigest()
        prep['preparation']['lockSha256']=hashlib.sha256(lock).hexdigest()
        def read(*args):
            self.assertEqual(args[0],'show');ref,path=args[1].split(':',1)
            self.assertIn(ref,(D.R8_BASE_SOURCE,D.R8_SOURCE))
            return package if path=='package.json' else lock if path=='pnpm-lock.yaml' else payload[path]
        with patch.object(D,'R7_STAGE_PINS',prep),patch.object(D,'R8_SOURCE_BLOBS',
                {k:hashlib.sha256(v).hexdigest() for k,v in payload.items()}),\
             patch.object(D,'validate_re2js_generation_receipt_v7',return_value={'synthetic':True}) as generation,\
             patch.object(D,'_v4_verify_step',return_value={'syntheticStep':True}) as step:
            r=request();r['lockPreparation']=copy.deepcopy(prep['preparation'])
            v=D.verify_source_equivalence_v8(r,base_pins(),read,raw)
            generation.assert_called_once_with(raw,prep)
            step.assert_called_once_with(read,D.R8_SOURCE,D.R8_TREE,r['sourceWitness']['hops'][0]['step'],initial=False)
            self.assertFalse(v['historicalCoverageReused']);self.assertTrue(v['packageAndLockUnchanged'])

    def test_source_dependency_or_fixture_change_refuses(self):
        r=request()
        with patch.object(D,'validate_re2js_generation_receipt_v7',return_value={}),\
             patch.object(D,'_v4_verify_step',return_value={}),\
             self.assertRaises(D.R8ContractRefusal):
            D.verify_source_equivalence_v8(r,base_pins(),lambda *args:b'changed',b'proof')

    def test_real_source_witness_shape_refuses_extra_hop_parent_path(self):
        for mutate in [lambda p:p['sourceWitness']['hops'].append(copy.deepcopy(p['sourceWitness']['hops'][0])),
                       lambda p:p['sourceWitness']['hops'][0]['step']['changedPaths'].append('package.json'),
                       lambda p:p['sourceWitness']['hops'][0]['step'].update(parentSha='a'*40)]:
            pins=copy.deepcopy(base_pins());mutate(pins)
            with self.assertRaises(D.R8ContractRefusal):D.validate_request_v8(request(),pins)


if __name__=='__main__':unittest.main()
