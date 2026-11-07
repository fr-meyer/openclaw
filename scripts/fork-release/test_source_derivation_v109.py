"""In-memory Git-tree and safe result boundary proofs, with no process calls."""
from copy import deepcopy
import hashlib
import importlib.util
from pathlib import Path
import unittest

from test_source_validation_contract_v109 import m, populated


def blob(raw):
    return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()


def repository():
    b,files=populated();g=b["preparation"]["sourceSha"];h=b["validation"]["source"]["sourceSha"]
    old={"package.json":b'{}\n',"pnpm-workspace.yaml":b'minimumReleaseAge: 10080\n',
         "pnpm-lock.yaml":b'old lock\n',"extra.ts":b'unchanged\n'}
    old[m.LEDGER]=m.encode({"schema":"openclaw.v109.fork-carry-reconciliation.v1",
        "lockState":"pending_ci_derivation","sourcePaths":[{"path":"pnpm-lock.yaml",
        "result":{"mode":"100644","blob":blob(old['pnpm-lock.yaml'])},"disposition":"LOCK_CONTROLLED_DERIVATION"}],
        "selfExclusion":m.LEDGER})
    for p in m.INPUTS:b["preparation"]["fileSha256"][p]=m.digest(old[p])
    security={"synthetic_gate":"passed"}
    receipt=m.parse(files["generation.json"])
    receipt.update(packageSha256=m.digest(old['package.json']),workspaceSha256=m.digest(old['pnpm-workspace.yaml']),
        sourceLockSha256=m.digest(old['pnpm-lock.yaml']),ledgerSha256=m.digest(old[m.LEDGER]),
        lockSecuritySha256=m.digest(m.canonical(security)))
    files["generation.json"]=m.encode(receipt)
    pin=b["validation"]["generation"];pin["receiptSha256"]=m.digest(files["generation.json"])
    new=deepcopy(old);new['pnpm-lock.yaml']=files['pnpm-lock.yaml']
    new[m.LEDGER]=m.expected_derived_ledger(old[m.LEDGER],blob(new['pnpm-lock.yaml']),pin)
    for p in m.INPUTS:b["validation"]["source"]["fileSha256"][p]=m.digest(new[p])
    trees={g:{p:('100644','blob',blob(v))for p,v in old.items()},
           h:{p:('100644','blob',blob(v))for p,v in new.items()}}
    b['validation']['unchangedTreeSha256']=m.tree_digest(trees[g],('pnpm-lock.yaml',m.LEDGER))
    content={g:old,h:new};parents={g:[m.BASELINE_SOURCE,m.UPSTREAM['commit']],h:[g]}
    tree_names={g:b['preparation']['sourceTree'],h:b['validation']['source']['sourceTree']}
    def read(*args):
        if args[0]=='rev-parse':return(tree_names[args[1].split('^')[0]]+'\n').encode()
        if args[:3]==('show','-s','--format=%P'):return(' '.join(parents[args[3]])+'\n').encode()
        if args[0]=='show':
            revision,path=args[1].split(':',1);return content[revision][path]
        raise AssertionError(args)
    def read_tree(sha,tree):
        if tree!=tree_names[sha]:raise AssertionError('wrong tree')
        return deepcopy(trees[sha])
    return b,files,read,read_tree,lambda *a:deepcopy(security),trees,content,parents


class DerivationTests(unittest.TestCase):
    def test_complete_single_parent_lock_and_ledger_derivation(self):
        b,f,read,trees,gate,*_=repository()
        proof=m.verify_derived_source(read,b,'validation',f['generation.json'],read_tree=trees,verify_lock=gate)
        self.assertTrue(proof['allOtherTrackedBytesUnchanged'])
        self.assertEqual(proof['changedPaths'],sorted(('pnpm-lock.yaml',m.LEDGER)))
        self.assertFalse(proof['imageBuilt']);self.assertFalse(proof['productionAuthorized'])

    def test_extra_application_change_refuses(self):
        b,f,read,reader,gate,trees,*_=repository();h=b['validation']['source']['sourceSha']
        trees[h]['extra.ts']=('100644','blob','f'*40)
        with self.assertRaisesRegex(m.Refusal,'only_generated'):
            m.verify_derived_source(read,b,'validation',f['generation.json'],read_tree=reader,verify_lock=gate)

    def test_non_direct_or_merge_parent_refuses(self):
        for new_parent in (['f'*40],['a'*40,'f'*40]):
            b,f,read,reader,gate,_,_,parents=repository();parents[b['validation']['source']['sourceSha']]=new_parent
            with self.subTest(parent=new_parent),self.assertRaisesRegex(m.Refusal,'single_generated'):
                m.verify_derived_source(read,b,'validation',f['generation.json'],read_tree=reader,verify_lock=gate)

    def test_initial_integration_parent_order_refuses(self):
        b,f,read,reader,gate,_,_,parents=repository();parents[b['preparation']['sourceSha']].reverse()
        with self.assertRaisesRegex(m.Refusal,'integration_parents'):
            m.verify_derived_source(read,b,'validation',f['generation.json'],read_tree=reader,verify_lock=gate)

    def test_ledger_extra_field_refuses_even_if_blob_hash_agrees(self):
        b,f,read,reader,gate,trees,content,_=repository();h=b['validation']['source']['sourceSha']
        value=m.parse(content[h][m.LEDGER]);value['waiver']=True;raw=m.encode(value)
        content[h][m.LEDGER]=raw;trees[h][m.LEDGER]=('100644','blob',blob(raw))
        b['validation']['source']['fileSha256'][m.LEDGER]=m.digest(raw)
        with self.assertRaisesRegex(m.Refusal,'exact_derived_ledger'):
            m.verify_derived_source(read,b,'validation',f['generation.json'],read_tree=reader,verify_lock=gate)

    def test_unpatched_graph_callback_refuses(self):
        b,f,read,reader,_,*_=repository()
        def reject(*a):raise ValueError('v9.no_unpatched_zod3_resolution')
        with self.assertRaisesRegex(ValueError,'zod3'):
            m.verify_derived_source(read,b,'validation',f['generation.json'],read_tree=reader,verify_lock=reject)

    def test_security_receipt_hash_binding_cannot_be_omitted(self):
        b,f,read,reader,gate,*_=repository()
        with self.assertRaisesRegex(m.Refusal,'security_binding'):
            m.verify_derived_source(read,b,'validation',f['generation.json'],read_tree=reader,verify_lock=lambda*a:{'different':True})

    def test_mode_change_refuses(self):
        b,f,read,reader,gate,trees,*_=repository();h=b['validation']['source']['sourceSha']
        old=trees[h]['pnpm-lock.yaml'];trees[h]['pnpm-lock.yaml']=('100755',old[1],old[2])
        with self.assertRaisesRegex(m.Refusal,'only_generated'):
            m.verify_derived_source(read,b,'validation',f['generation.json'],read_tree=reader,verify_lock=gate)


def result_fixture():
    b,_=populated();request=m.encode(m.request_for(b,'validation'));r=m.parse(request)
    pin={'runId':'987654321','runAttempt':1,'pipelineHead':'f'*40,'requestSha256':m.digest(request)}
    value={'schema':'openclaw.v109.source-validation-result.v1','repository':m.REPOSITORY,'campaignId':m.CAMPAIGN,
        'phase':'validation','status':'passed',**pin,**{k:r['source'][k] for k in('sourceSha','sourceTree','manifestSha256','inventorySha256')},
        'generationReceiptSha256':r['generation']['receiptSha256'],'selectedProfiles':list(m.PROFILES),
        'admissionResult':'success','sourceMatrixResult':'success','all15Required':True,'freshCoverage':True,
        'historicalCoverageReused':False,'imageBuilt':False,'nativeImageExecuted':False,'productionAuthorized':False}
    return b,request,pin,value


class ResultTests(unittest.TestCase):
    def test_safe_complete_result_accepts_only_actual_pin(self):
        b,request,pin,value=result_fixture();raw=m.encode(value)
        self.assertEqual(m.validate_source_result(raw,b,request,pin,expected_result_sha256=m.digest(raw))['status'],'passed')

    def test_incomplete_profile_or_failure_refuses(self):
        for key,v in (('selectedProfiles',list(m.PROFILES)[:-1]),('status','failed'),('sourceMatrixResult','failure'),
                      ('historicalCoverageReused',True),('nativeImageExecuted',True),('productionAuthorized',True),('runAttempt',True)):
            b,request,pin,value=result_fixture();value[key]=v;raw=m.encode(value)
            with self.subTest(key=key),self.assertRaises(m.Refusal):m.validate_source_result(raw,b,request,pin,expected_result_sha256=m.digest(raw))

    def test_wrong_hash_or_extra_private_field_refuses(self):
        b,request,pin,value=result_fixture();raw=m.encode(value)
        with self.assertRaisesRegex(m.Refusal,'result_hash'):m.validate_source_result(raw,b,request,pin,expected_result_sha256='a'*64)
        value['rawStderr']='never permitted';raw=m.encode(value)
        with self.assertRaisesRegex(m.Refusal,'result_fields'):m.validate_source_result(raw,b,request,pin,expected_result_sha256=m.digest(raw))

    def test_other_source_or_run_refuses(self):
        for key in ('sourceSha','pipelineHead','generationReceiptSha256'):
            b,request,pin,value=result_fixture()
            value[key]='a'*(40 if key!='generationReceiptSha256' else 64)
            raw=m.encode(value)
            with self.subTest(key=key),self.assertRaises(m.Refusal):m.validate_source_result(raw,b,request,pin,expected_result_sha256=m.digest(raw))


if __name__=='__main__':unittest.main()
