// Pure/local negative harness checks; no tar, compiler, or vendor package execution.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, realpathSync, readFileSync, lstatSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { qualificationArguments, projectPackageTestResult, qualifyNpmGlobBackport, preserveQualificationEvidence, captureAndProjectPackageTestResult, projectQualificationExceptionCause } from './qualify-npm-glob-vendor-backport.mjs';
const result=()=>({schema:'openclaw.npm-vendor-actual-package-tests.v1',passed:true,cases:Array.from({length:52},(_,i)=>({name:`case-${i}`,passed:true})),originalVersion:'12.2.1',derivedVersion:'12.2.1',globVersion:'13.0.6',packageExecutionHost:'ci-only',imageTested:false,publicPackTested:true,actualBunRuntimeTested:false});
test('fixed complete CLI accepted',()=>assert.equal(qualificationArguments(['--original-npm','/a','--derived-npm','/b','--repo-root','/c','--receipt','/d']).repoRoot,'/c'));
for(const args of [[],['--other','/x'],['--original-npm','/a','--derived-npm','/b','--repo-root','/c','--receipt','/d','--retry']])test(`unknown/missing qualification args refuse ${args.length}`,()=>assert.throws(()=>qualificationArguments(args)));
test('synthetic 52-case conclusion accepted without claiming image/Bun runtime',()=>{
 const projected=projectPackageTestResult(result());assert.equal(projected.passedCount,52);assert.equal(projected.imageTested,false);assert.equal(projected.actualBunRuntimeTested,false);
});
for(const [name,change] of [
 ['missing-case',r=>r.cases.pop()],['duplicate-case',r=>r.cases[1].name=r.cases[0].name],['wrong-original',r=>r.originalVersion='12.2.0'],
 ['image-claim',r=>r.imageTested=true],['missing-public-pack',r=>r.publicPackTested=false],['false-success',r=>r.cases[0].passed=false],
])test(`rejects ${name}`,()=>{const r=result();change(r);assert.throws(()=>projectPackageTestResult(r));});
test('failure projection removes raw assertion message/observed arbitrary data',()=>{
 const r=result();r.passed=false;r.cases[0]={name:'case-0',passed:false,code:'ERR_ASSERTION',assertion:{operator:'strictEqual',actual:0,expected:1},operation:'case.entry',cause:{name:{state:'recognized',value:'AssertionError'},code:{state:'recognized',value:'ERR_ASSERTION'},ownerReason:{state:'absent'}},message:'DO_NOT_COPY_PRIVATE_MESSAGE',observed:{unexpected:'DO_NOT_COPY'}};
 const s=projectPackageTestResult(r);assert.equal(s.passed,false);assert.equal(s.publicPackTested,false);assert.ok(!JSON.stringify(s).includes('DO_NOT_COPY'));assert.deepEqual(s.cases[0].assertion,{operator:'strictEqual',actual:0,expected:1});
 r.cases[0].assertion.actual='DO_NOT_COPY';assert.throws(()=>projectPackageTestResult(r),/package_assertion_shape/);
});
test('disarmed CI refuses before reading archives/proof or producing receipt',async()=>{
 const before=process.env.GITHUB_ACTIONS;delete process.env.GITHUB_ACTIONS;
 try{await assert.rejects(qualifyNpmGlobBackport({originalArchive:'/not-read',derivedArchive:'/not-read',repoRoot:'/not-read',receiptPath:'/not-written'}),/qualification_ci_only/);}finally{if(before!==undefined)process.env.GITHUB_ACTIONS=before;}
});
test('missing proof stores bounded private structured failure before any archive use',async()=>{
 const originalEnv={CI:process.env.CI,GITHUB_ACTIONS:process.env.GITHUB_ACTIONS};process.env.CI='true';process.env.GITHUB_ACTIONS='true';
 const root=realpathSync(mkdtempSync(path.join(tmpdir(),'vendor-qualified-negative-'))),receipt=path.join(root,'receipt.json');
 try{
  await assert.rejects(qualifyNpmGlobBackport({originalArchive:'/not-read',derivedArchive:'/not-read',repoRoot:root,receiptPath:receipt}),/qualification_failed/);
  assert.ok(existsSync(receipt));const raw=readFileSync(receipt);const body=JSON.parse(raw);assert.equal(body.phase,'proof');assert.equal(body.packageExecuted,false);assert.equal(body.status,'failed');assert.deepEqual(body.exceptionCause,{name:{state:'recognized',value:'Error'},code:{state:'recognized',value:'ENOENT'}});assert.ok(raw.length<64*1024);assert.equal(lstatSync(receipt).mode&0o7777,0o600);
 }finally{for(const key of ['CI','GITHUB_ACTIONS'])if(originalEnv[key]===undefined)delete process.env[key];else process.env[key]=originalEnv[key];rmSync(root,{recursive:true,force:true});}
});

function custodyFixture(body){const root=realpathSync(mkdtempSync(path.join(tmpdir(),'vendor-custody-negative-')));try{return body(root,path.join(root,'qualified.json'));}finally{rmSync(root,{recursive:true,force:true});}}
test('malformed result is fsynced privately before shape refusal',()=>custodyFixture((root,receiptPath)=>{
 const evidence={};const malformed={schema:'wrong',message:'PRIVATE_RESULT_BEFORE_REFUSAL'};
 assert.throws(()=>captureAndProjectPackageTestResult({receiptPath,result:malformed,evidence}),/package_test_shape/);
 assert.equal(evidence.testResultEvidence.truncated,false);const file=path.join(root,evidence.testResultEvidence.file);
 assert.ok(readFileSync(file,'utf8').includes('PRIVATE_RESULT_BEFORE_REFUSAL'));assert.equal(lstatSync(file).mode&0o7777,0o600);
 assert.ok(!JSON.stringify(evidence).includes('PRIVATE_RESULT_BEFORE_REFUSAL'));
}));
test('oversize result keeps bounded prefix/full hash then refuses',()=>custodyFixture((root,receiptPath)=>{
 const evidence={};const result={message:'X'.repeat(200000)};
 assert.throws(()=>captureAndProjectPackageTestResult({receiptPath,result,evidence}),/qualification_result_truncated/);
 const e=evidence.testResultEvidence;assert.equal(e.storedBytes,131072);assert.ok(e.bytes>e.storedBytes);assert.equal(e.truncated,true);assert.equal(readFileSync(path.join(root,e.file)).length,131072);assert.match(e.sha256,/^[a-f0-9]{64}$/);
}));
test('oversize exception keeps bounded private context and honest truncation',()=>custodyFixture((root,receiptPath)=>{
 const e=preserveQualificationEvidence({receiptPath,kind:'exception',bytes:Buffer.from('PRIVATE_ERROR'.repeat(4000))});
 assert.equal(e.storedBytes,16384);assert.equal(e.truncated,true);assert.ok(readFileSync(path.join(root,e.file),'utf8').startsWith('PRIVATE_ERROR'));assert.equal(lstatSync(path.join(root,e.file)).mode&0o7777,0o600);
}));
test('private evidence O_EXCL never overwrites original failure context',()=>custodyFixture((root,receiptPath)=>{
 const e=preserveQualificationEvidence({receiptPath,kind:'exception',bytes:Buffer.from('FIRST_PRIVATE')});
 assert.throws(()=>preserveQualificationEvidence({receiptPath,kind:'exception',bytes:Buffer.from('SECOND_PRIVATE')}));assert.equal(readFileSync(path.join(root,e.file),'utf8'),'FIRST_PRIVATE');
}));

test('safe exception cause retains positive known Node setup code',()=>{
 const error=new Error('DO_NOT_COPY_MESSAGE');error.code='ERR_MODULE_NOT_FOUND';
 assert.deepEqual(projectQualificationExceptionCause(error),{name:{state:'recognized',value:'Error'},code:{state:'recognized',value:'ERR_MODULE_NOT_FOUND'}});
});
test('unknown exception class/code retain explicit state without raw values',()=>{
 const out=projectQualificationExceptionCause({name:'PRIVATE_CLASS',code:'PRIVATE_CODE',message:'PRIVATE_MESSAGE',stack:'PRIVATE_STACK',env:{SECRET:'PRIVATE_ENV'}});
 assert.deepEqual(out,{name:{state:'unrecognized'},code:{state:'unrecognized'}});assert.ok(!JSON.stringify(out).includes('PRIVATE'));
});
test('absent and invalid exception fields remain distinct',()=>{
 assert.deepEqual(projectQualificationExceptionCause({}),{name:{state:'absent'},code:{state:'absent'}});
 assert.deepEqual(projectQualificationExceptionCause({name:null,code:0}),{name:{state:'unrecognized'},code:{state:'unrecognized'}});
});
test('safe exception projection never invokes getters and recognizes native prototype name',()=>{
 let reads=0;const error={get name(){reads++;return 'Error';},get code(){reads++;return 'ENOENT';}};
 assert.deepEqual(projectQualificationExceptionCause(error),{name:{state:'unrecognized'},code:{state:'unrecognized'}});assert.equal(reads,0);
 assert.deepEqual(projectQualificationExceptionCause(new TypeError('hidden')),{name:{state:'recognized',value:'TypeError'},code:{state:'absent'}});
});

function failedDiagnosticResult(){const r=result();r.passed=false;r.cases[0]={name:'case-0',passed:false,code:'ERR_ASSERTION',assertion:{operator:'strictEqual',actual:1,expected:0},operation:'pack.installed_verify',cause:{name:{state:'recognized',value:'Error'},code:{state:'absent'},ownerReason:{state:'recognized',value:'npm-vendor.installed_inventory'}}};return r;}
test('failed operation and literal owner reason survive strict safe projection',()=>{
 const row=projectPackageTestResult(failedDiagnosticResult()).cases[0];assert.equal(row.operation,'pack.installed_verify');assert.deepEqual(row.cause.ownerReason,{state:'recognized',value:'npm-vendor.installed_inventory'});assert.equal(row.assertion.actual,1);
});
test('unknown or missing failed-case operation refuses',()=>{
 const r=failedDiagnosticResult();r.cases[0].operation='PRIVATE_UNKNOWN_OPERATION';assert.throws(()=>projectPackageTestResult(r),/package_case_operation/);delete r.cases[0].operation;assert.throws(()=>projectPackageTestResult(r),/package_case_operation/);
});
test('unknown cause values and extra raw fields refuse rather than leak',()=>{
 const r=failedDiagnosticResult();r.cases[0].cause.ownerReason.value='PRIVATE_UNKNOWN_REASON';assert.throws(()=>projectPackageTestResult(r),/package_case_cause_shape/);
 r.cases[0].cause.ownerReason={state:'unrecognized',message:'PRIVATE_MESSAGE'};assert.throws(()=>projectPackageTestResult(r),/package_case_cause_shape/);
 r.cases[0].cause.ownerReason={state:'recognized',value:'npm-vendor.installed_inventory'};r.cases[0].cause.code={state:'recognized',value:'PRIVATE_CODE'};assert.throws(()=>projectPackageTestResult(r),/package_case_cause_shape/);
});
test('absent/unrecognized per-case cause states remain explicit without raw data',()=>{
 const r=failedDiagnosticResult();r.cases[0].cause={name:{state:'unrecognized'},code:{state:'absent'},ownerReason:{state:'unrecognized'}};r.cases[0].code='PRIVATE_RAW_CODE';
 const safe=projectPackageTestResult(r).cases[0];assert.deepEqual(safe.cause,r.cases[0].cause);assert.equal(safe.code,'case_failed');assert.ok(!JSON.stringify(safe).includes('PRIVATE'));
});
