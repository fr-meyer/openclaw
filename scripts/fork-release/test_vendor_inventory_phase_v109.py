"""Changed-boundary tests for the fixed data-only post-failure diagnostic."""
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch
import hashlib
import json
import time
import shutil
import unittest

import bounded_run_contract_v109 as run
import npm_vendor_derivation_v109 as vendor
import source_validation_contract_v109 as policy
import source_validation_v109 as controller


def encoded(value):return (json.dumps(value,separators=(',',':'))+'\n').encode()
def proof():return encoded({'original':{'files':[{'path':'package.json'}]},'derived':{'inventorySha256':'b'*64}})
def diagnostic(proof_raw):
    return {'schema':vendor.INVENTORY_DIAGNOSTIC_SCHEMA,'status':'observed','reason':'differences_observed',
        'qualificationAccepted':False,'imageBuilt':False,'complete':True,
        'proofSha256':vendor.digest(proof_raw),'expectedInventorySha256':'b'*64,
        'observed':{'entries':1,'expectedFilesRead':1,'bytes':1,'verificationEntries':1,'proofMetadataBytes':0,'selectorMetadataBytes':0},
        'privacy':{'unknownNamesHashed':True,'unknownContentsRead':False,'unknownLinkTargetsRead':False,'declaredNpmSelectorTargetMetadataRead':False},
        'limits':dict(vendor.INVENTORY_DIAGNOSTIC_LIMITS),'deadlineKind':'cooperative_30s_requires_outer_whole_call_deadline',
        'counts':{'missing':0,'extra':0,'type':0,'mode':1,'size':0,'content':0,'links':0},
        'countsComplete':True,'differenceCount':1,'differencesTruncated':False,
        'differences':[{'kind':'changed','path':'package.json','changes':['mode'],
            'expected':{'kind':'file','mode':420,'size':1,'sha256':'c'*64},
            'actual':{'kind':'file','mode':493,'size':1,'sha256':'c'*64}}]}


class InventoryCallerTests(unittest.TestCase):
    def setUp(self):
        self.temp=TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name).resolve();self.source=self.base/'source';self.source.mkdir();self.home=self.base/'home';self.home.mkdir()
        p=self.source/vendor.PROOF;p.parent.mkdir();p.write_bytes(proof())
        self.record={'proofSha256':vendor.digest(proof())}
        self.authenticated={}
        for name in vendor.INVENTORY_DIAGNOSTIC_FILES:
            target=self.source/name;target.parent.mkdir(parents=True,exist_ok=True)
            body=('// synthetic fixed source '+name+'\n').encode();target.write_bytes(body);self.authenticated[name]=body
        guard=patch.object(vendor,'INVENTORY_PROOF_OWNER_SHA256',hashlib.sha256(self.authenticated['scripts/lib/npm-glob-vendor-proof.mjs']).hexdigest())
        guard.start();self.addCleanup(guard.stop)
        def local_blob(root,*args,deadline=None):
            self.assertEqual(root,self.source);self.assertEqual(args[0],'show')
            expected_prefix='a'*40+':'
            self.assertTrue(args[1].startswith(expected_prefix))
            return self.authenticated[args[1][len(expected_prefix):]]
        guard=patch.object(controller,'git_read',side_effect=local_blob);guard.start();self.addCleanup(guard.stop)
        request={'source':{'sourceSha':'a'*40,'sourceTree':'b'*40},'vendorRepairContinuationSha256':run.digest(run.vendor_repair_continuation())}
        self.context={'deadlineEpoch':time.time()+1000,'request':request,
            'bindings':{'ciRunGrant':{'sourceSuccessorAmendment':{'vendorRepairContinuation':run.vendor_repair_continuation()}}},
            'operationIdentity':controller.owned_identity(request)}
        self.original=SimpleNamespace(returncode=2,timed_out=False,cleanup_settled=None)

    def collect(self,raw=None,result=None,context=None,original=None):
        self.calls=[]
        if raw is None:raw=encoded(diagnostic(proof()))
        if result is None:result=SimpleNamespace(returncode=0,timed_out=False,cleanup_settled=None)
        def process(argv,cwd,env,ctx,phase,ordinal):
            self.calls.append((argv,cwd,env,ctx,phase,ordinal))
            Path(argv[argv.index('--receipt')+1]).write_bytes(raw)
            return result
        core=SimpleNamespace(phase_process=process)
        return controller.collect_vendor_inventory_diagnostic(self.source,self.record,{'RUNNER_TEMP':str(self.base)},core,
            self.context if context is None else context,{'PATH':'/fixed'},self.home,self.original if original is None else original)

    def test_fixed_argv_deadline_cleanup_and_false_qualification(self):
        now=time.time();value=self.collect();self.assertEqual(value['state'],'available');self.assertFalse(value['qualificationAccepted'])
        argv,cwd,env,ctx,phase,index=self.calls[0]
        self.assertEqual(argv,['node',vendor.INVENTORY_DIAGNOSTIC,'--repo-root',str(self.source),'--proof',str(self.source/vendor.PROOF),'--receipt',str(self.home/'vendor-inventory.json')])
        self.assertLessEqual(ctx['deadlineEpoch'],time.time()+40);self.assertGreaterEqual(ctx['deadlineEpoch'],now+39)
        self.assertEqual(ctx['request'],self.context['request']);self.assertEqual((phase,index),('vendor-inventory-diagnostic',0))
        self.assertEqual(value['cleanupMaximumSeconds'],20);self.assertEqual(env['GITHUB_ACTIONS'],'true')

    def test_parent_budget_reserves_cleanup_and_refuses_under_sixty(self):
        value=self.collect(context={**self.context,'deadlineEpoch':time.time()+59})
        self.assertEqual(value['state'],'unavailable');self.assertEqual(self.calls,[])

    def test_unsettled_qualifier_cleanup_prevents_read(self):
        value=self.collect(original=SimpleNamespace(returncode=124,timed_out=True,cleanup_settled=False))
        self.assertEqual(value['reason'],'qualification_cleanup_unsettled');self.assertEqual(self.calls,[])

    def test_timeout_with_complete_json_does_not_accept_diagnostic(self):
        value=self.collect(result=SimpleNamespace(returncode=124,timed_out=True,cleanup_settled=True))
        self.assertEqual(value['state'],'unavailable');self.assertNotIn('report',value)
        self.assertEqual(value['capture']['state'],'complete')

    def test_non_boolean_cleanup_cannot_pass(self):
        value=self.collect(result=SimpleNamespace(returncode=0,timed_out=False,cleanup_settled=1))
        self.assertEqual(value['state'],'unavailable');self.assertNotIn('report',value)

    def test_wrong_proof_binding_is_not_projected(self):
        value=diagnostic(proof());value['proofSha256']='d'*64
        observed=self.collect(raw=encoded(value));self.assertEqual(observed['reason'],'report_invalid');self.assertNotIn('report',observed)

    def test_private_unknown_path_rejected_after_prefix_custody(self):
        value=diagnostic(proof());value['differences'][0]['path']='/private/never-export'
        raw=encoded(value);observed=self.collect(raw=raw)
        self.assertEqual(observed['reason'],'report_invalid');self.assertNotIn('/private/',json.dumps(observed))
        self.assertEqual((self.home/'vendor-captures/vendor-inventory.raw').read_bytes(),raw)

    def test_extra_unknown_name_can_only_be_hash(self):
        value=diagnostic(proof());value['differences']=[{'kind':'extra','pathSha256':'e'*64,
            'actual':{'kind':'link','mode':511,'size':9,'contentRead':False}}]
        observed=self.collect(raw=encoded(value));self.assertEqual(observed['state'],'available')
        value['differences'][0]['actual']['target']='/private/never-export'
        with self.assertRaises(policy.Refusal):vendor.inventory_diagnostic_projection(encoded(value),proof(),policy.need)

    def test_invalid_and_oversize_prefix_retained_before_refusal(self):
        raw=b'{malformed';observed=self.collect(raw=raw)
        self.assertEqual(observed['reason'],'report_invalid');self.assertEqual(observed['capture']['sha256'],hashlib.sha256(raw).hexdigest())
        self.assertEqual((self.home/'vendor-captures/vendor-inventory.raw').read_bytes(),raw)

    def test_oversize_is_incomplete_not_valid_json_acceptance(self):
        raw=encoded(diagnostic(proof()))+b' '*65536;observed=self.collect(raw=raw)
        self.assertEqual(observed['state'],'unavailable');self.assertEqual(observed['capture']['state'],'incomplete')
        self.assertEqual((self.home/'vendor-captures/vendor-inventory.raw').stat().st_size,65536)

    def test_refused_diagnostic_is_data_not_package_pass(self):
        value={'schema':vendor.INVENTORY_DIAGNOSTIC_SCHEMA,'status':'refused','reason':'unstable_input',
            'qualificationAccepted':False,'imageBuilt':False,'complete':False}
        observed=self.collect(raw=encoded(value),result=SimpleNamespace(returncode=2,timed_out=False,cleanup_settled=None))
        self.assertEqual(observed['state'],'available');self.assertFalse(observed['report']['qualificationAccepted'])

    def test_unknown_reason_and_private_extra_field_rejected(self):
        for key in ('reason','private'):
            value=diagnostic(proof());value[key]='secret-not-exportable'
            with self.assertRaises(policy.Refusal):vendor.inventory_diagnostic_projection(encoded(value),proof(),policy.need)

    def test_each_fixed_diagnostic_source_tamper_prevents_child(self):
        for name in vendor.INVENTORY_DIAGNOSTIC_FILES:
            with self.subTest(path=name):
                target=self.source/name;original=target.read_bytes();target.write_bytes(original+b'changed')
                value=self.collect()
                self.assertEqual(self.calls,[]);self.assertEqual(value['state'],'unavailable')
                self.assertEqual(value['reason'],'diagnostic_code_changed')
                target.write_bytes(original)
                # A refusal may retain private capture metadata; use a fresh
                # capture directory for the next distinct synthetic scenario.
                shutil.rmtree(self.home/'vendor-captures',ignore_errors=True)

    def test_generated_proof_and_fixed_proof_owner_binding_prevent_child(self):
        target=self.source/vendor.PROOF;original=target.read_bytes();target.write_bytes(original+b'changed')
        value=self.collect();self.assertEqual(self.calls,[]);self.assertEqual(value['reason'],'source_proof_changed')
        target.write_bytes(original);shutil.rmtree(self.home/'vendor-captures',ignore_errors=True)
        name='scripts/lib/npm-glob-vendor-proof.mjs';self.authenticated[name]+=b'changed'
        (self.source/name).write_bytes(self.authenticated[name])
        value=self.collect();self.assertEqual(self.calls,[]);self.assertEqual(value['reason'],'proof_owner_changed')

    def test_missing_or_symlinked_diagnostic_code_prevents_child(self):
        target=self.source/vendor.INVENTORY_DIAGNOSTIC;body=target.read_bytes();target.unlink()
        value=self.collect();self.assertEqual(self.calls,[]);self.assertEqual(value['state'],'unavailable')
        shutil.rmtree(self.home/'vendor-captures',ignore_errors=True)
        other=self.source/'fixed-synthetic.mjs';other.write_bytes(body);target.symlink_to(other)
        value=self.collect();self.assertEqual(self.calls,[]);self.assertEqual(value['state'],'unavailable')

    def test_final_fixed_refusal_codes_preserve_safe_cause(self):
        for reason in ('receipt_write_refused','selector_fd_refused'):
            with self.subTest(reason=reason):
                value={'schema':vendor.INVENTORY_DIAGNOSTIC_SCHEMA,'status':'refused','reason':reason,
                    'qualificationAccepted':False,'imageBuilt':False,'complete':False}
                observed=vendor.inventory_diagnostic_projection(encoded(value),proof(),policy.need)
                self.assertEqual(observed['reason'],reason)
                self.assertFalse(observed['qualificationAccepted'])

    def test_combined_failure_report_reserve_keeps_legacy_and_near_boundary(self):
        for index,(continuation,body_bytes,refused) in enumerate(((True,policy.ARTIFACT_BYTES-131072,True),
                (False,policy.ARTIFACT_BYTES-131072,False),(True,policy.ARTIFACT_BYTES-196608-8192,False))):
            with self.subTest(continuation=continuation,bodyBytes=body_bytes):
                directory=self.base/('reserve-'+str(index));directory.mkdir()
                request={'source':{'sourceSha':'a'*40,'sourceTree':'b'*40,'fileSha256':{'pnpm-lock.yaml':'c'*64}}}
                if continuation:request['vendorRepairContinuationSha256']=run.digest(run.vendor_repair_continuation())
                if refused:
                    with self.assertRaisesRegex(policy.Refusal,'lock_diagnostic_size'):
                        controller.retain_unvalidated_lock(b'x'*body_bytes,b'',request,
                            {'RUNNER_TEMP':str(directory),'GITHUB_RUN_ID':'1'},'2026-11-05T00:00:00Z')
                    self.assertFalse((directory/'v109-lock-diagnostic').exists())
                else:
                    controller.retain_unvalidated_lock(b'x'*body_bytes,b'',request,
                        {'RUNNER_TEMP':str(directory),'GITHUB_RUN_ID':'1'},'2026-11-05T00:00:00Z')
                    actual=sum(p.stat().st_size for p in (directory/'v109-lock-diagnostic').iterdir())
                    self.assertLessEqual(actual+(131072+65536 if continuation else 65536),policy.ARTIFACT_BYTES)

    def test_qualification_failure_stays_terminal_after_successful_diagnostic(self):
        self.home.joinpath('vendor-captures').mkdir()
        for script,count in vendor.CONTROL_TESTS:
            target=self.source/script;target.parent.mkdir(parents=True,exist_ok=True);target.write_text('// synthetic only\n')
        calls=[]
        def process(argv,cwd,env,ctx,phase,index):
            calls.append(phase)
            if phase=='vendor-controls':
                count=vendor.CONTROL_TESTS[index][1]
                Path(argv[3].split('=',1)[1]).write_text(f'TAP version 13\n1..{count}\n# tests {count}\n# pass {count}\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n')
            if phase=='vendor-actual-qualification':
                Path(argv[argv.index('--receipt')+1]).write_bytes(b'{}')
                return SimpleNamespace(returncode=2,timed_out=False,cleanup_settled=None)
            if phase=='vendor-inventory-diagnostic':Path(argv[argv.index('--receipt')+1]).write_bytes(encoded(diagnostic(proof())))
            return SimpleNamespace(returncode=0,timed_out=False,cleanup_settled=None)
        env={'RUNNER_TEMP':str(self.base)};(self.base/'v109-lock-diagnostic').mkdir()
        with patch.object(vendor,'failed_qualification_projection',return_value={'schema':'synthetic-safe-failure','qualificationAccepted':False}),self.assertRaisesRegex(policy.Refusal,'vendor_actual_qualification_failed'):
            controller.qualify_npm_vendor(self.source,self.record,{'original':self.base/'original','derived':self.base/'derived'},env,
                SimpleNamespace(phase_process=process),self.context,{},self.home)
        self.assertEqual(calls[-2:],['vendor-actual-qualification','vendor-inventory-diagnostic'])
        safe=json.loads((self.base/'v109-lock-diagnostic/vendor-qualification.safe.json').read_bytes())
        self.assertEqual(safe['inventoryDiagnostic']['state'],'available');self.assertFalse(safe['qualificationAccepted'])


if __name__=='__main__':unittest.main()
