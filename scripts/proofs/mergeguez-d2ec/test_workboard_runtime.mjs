import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {stripTypeScriptTypes} from 'node:module';
// Actual frozen public source selected from the sealed patch, evaluated only with
// explicit unit doubles. No Worker, helper, database, container or build executes.
const root = path.dirname(fileURLToPath(import.meta.url));
const contract = JSON.parse(fs.readFileSync(path.join(root, 'contract.json'), 'utf8'));
const patch = fs.readFileSync(path.join(root, 'workboard-source.patch'), 'utf8');
assert.equal(crypto.createHash('sha256').update(patch).digest('hex'), '0cce713b2f9651eae7df7e6f357d2c9bf99f7bb5552835aa218b4871c87d860b');
function patchSection(relative) {
  const marker = `diff --git a/${relative} b/${relative}\n`;
  const start = patch.indexOf(marker); assert(start >= 0, 'named source patch section absent');
  const end = patch.indexOf('\ndiff --git ', start + marker.length);
  return patch.slice(start, end < 0 ? undefined : end);
}
function selectedPostimageHunk(relative) {
  const section = patchSection(relative); let hunk = false; const result = [];
  for (const line of section.split('\n')) {
    if (line.startsWith('@@ ')) { hunk = true; continue; }
    if (!hunk || line.startsWith('\\ No newline')) continue;
    if (line.startsWith('+') || line.startsWith(' ')) result.push(line.slice(1));
  }
  return result.join('\n') + '\n';
}
function addedSource(relative) {
  assert(patchSection(relative).includes('new file mode 100644\n'), 'source must be an added complete file');
  const source = selectedPostimageHunk(relative);
  const pin = contract.source_inputs.find(input => input.path === relative); assert(pin);
  assert.equal(Buffer.byteLength(source), pin.bytes);
  assert.equal(crypto.createHash('sha256').update(source).digest('hex'), pin.sha256);
  return source;
}
const source = fs.readFileSync(path.join(root, 'runtime.mjs'), 'utf8');
assert.equal(crypto.createHash('sha256').update(source).digest('hex'), '9109dbde876b6fb13c5e5c3ba6c35aac8949b9d04d8992fb8b8aee13ef779006');
const cases = [];
async function test(name, fn) {await fn(); cases.push(name);}
const dispositionSource = source.slice(source.indexOf('function workboardFailureDisposition('),source.indexOf('const uptime ='));
const disposition = vm.runInNewContext(dispositionSource+';workboardFailureDisposition');
const uuid = '12345678-1234-4123-8123-123456789abc';
const qualificationContext = {operationId:uuid, sourceBootId:uuid, sourceGenerationId:uuid, profileSha256:'a'.repeat(64), captureInvoked:true, synthetic:true};
const recoveryContext = {contract:'workboard.native-runtime-logical-recovery.v1',kind:'capture',operationId:uuid,assuranceSha256:'a'.repeat(64),binding:{sourceBootId:uuid,sourceOwnerId:'workboard-native-'+uuid,sourceGenerationId:uuid,...Object.fromEntries(['profileSha256','schemaSha256','assuranceSha256','captureIntervalSha256','manifestSha256','inputSha256'].map(key=>[key,'a'.repeat(64)]))}};
await test('unknown plus cleanup keeps no-retry and both safe operation contexts',()=>{
 const cause=Object.assign(Error('private bytes must not serialize'),{code:'PRIVATE_ACKNOWLEDGEMENT_OUTCOME_UNKNOWN',recoveryContext});
 const error=Object.assign(Error('cleanup'),{cause,code:'outcome-unknown',cleanupCodes:['WORKBOARD_STORE_CLOSE_FAILED','CUSTODIAN_CLOSE_FAILED','SQLITE_BROKER_DRAIN_FAILED'],qualificationContext});
 const result=disposition(error); assert.equal(result.outcomeUnknown,true);assert.equal(result.retryAllowed,false);assert.equal(result.reconciliationRequired,true);assert.equal(result.cleanupCodes.length,3);assert.equal(result.operationContext.operationId,uuid);assert.equal(result.custodyContext.binding.manifestSha256,'a'.repeat(64));assert(!JSON.stringify(result).includes('private bytes'));
});
await test('nonError and undefined produce bounded failure',()=>{for(const e of [undefined,null,'private message',123]){const r=disposition(e);assert.equal(r.code,'WORKBOARD_NATIVE_OPERATION_FAILED');assert.equal(r.retryAllowed,false);assert.equal(r.operationContext,null);}});
await test('accessor error and context fields are never executed',()=>{
 let reads=0;const bad={};for(const key of ['code','cause','cleanupCodes','qualificationContext','recoveryContext'])Object.defineProperty(bad,key,{get(){reads++;throw Error('secret');}});
 const r=disposition(bad);assert.equal(reads,0);assert.equal(r.code,'WORKBOARD_NATIVE_OPERATION_FAILED');
});
await test('arbitrary codes, stacks and cleanup payloads are excluded',()=>{
 const r=disposition({code:'SECRET_TOKEN_VALUE',stack:'private stack',cleanupCodes:['SECRET_TOKEN_VALUE','CUSTODIAN_CLOSE_FAILED','CUSTODIAN_CLOSE_FAILED'],qualificationContext:{...qualificationContext,profileSha256:'private'}});
 assert.equal(r.code,'WORKBOARD_NATIVE_OPERATION_FAILED');assert.deepEqual(Array.from(r.cleanupCodes),['CUSTODIAN_CLOSE_FAILED']);assert.equal(r.operationContext,null);assert(!JSON.stringify(r).includes('SECRET'));
});
await test('oversized cleanup metadata is bounded',()=>{const r=disposition({cleanupCodes:Array(10000).fill('CUSTODIAN_CLOSE_FAILED')});assert.equal(r.cleanupCodes.length,2);assert(r.cleanupCodes.includes('CLEANUP_DIAGNOSTICS_TRUNCATED'));});
await test('primary companion cleanup diagnostics survive outer joined cleanup wrapper',()=>{const r=disposition({code:'outcome-unknown',cleanupCodes:['WORKBOARD_STORE_CLOSE_FAILED'],cause:{cleanupCodes:['DESCRIPTOR_CLOSE_FAILED','TEMPORARY_UNLINK_FAILED']}});assert.deepEqual(Array.from(r.cleanupCodes),['WORKBOARD_STORE_CLOSE_FAILED','DESCRIPTOR_CLOSE_FAILED','TEMPORARY_UNLINK_FAILED']);});
await test('malformed or non-synthetic custody binding is omitted',()=>{
 const r=disposition({recoveryContext:{...recoveryContext,binding:{...recoveryContext.binding,sourceOwnerId:'private-owner'}}});assert.equal(r.custodyContext,null);
});
const footer = source.slice(source.indexOf('try { await main(); } catch (error)'));
async function runFooter(error) {
 let writes=[];const receipt={complete:false};const process={};
 const context=vm.createContext({main:async()=>{throw error;},contract:{qualification_scope:'workboard-native-worker-logical-recovery.synthetic.v1'},receipt,process,workboardFailureDisposition:disposition,fs:{mkdirSync(){},writeFileSync(file,bytes){writes.push({file,bytes});}},reports:'/synthetic-output',phase:'offline-native'});
 const module=new vm.SourceTextModule(footer,{context}); await module.link(()=>{throw Error('unexpected');}); await module.evaluate();return{receipt,process,writes};
}
await test('actual producer catch/finally writes unknown cleanup receipt once',async()=>{
 const r=await runFooter(Object.assign(Error('private'),{code:'outcome-unknown',cleanupCodes:['CUSTODIAN_CLOSE_FAILED'],qualificationContext}));
 assert.equal(r.process.exitCode,1);assert.equal(r.writes.length,1);const saved=JSON.parse(r.writes[0].bytes);assert.equal(saved.complete,false);assert.equal(saved.workboardFailure.outcomeUnknown,true);assert.equal(saved.workboardFailure.retryAllowed,false);assert.equal(saved.workboardFailure.cleanupCodes[0],'CUSTODIAN_CLOSE_FAILED');assert(!r.writes[0].bytes.includes('private'));
});
await test('actual producer catch/finally preserves undefined as failure without TypeError',async()=>{const r=await runFooter(undefined);assert.equal(r.process.exitCode,1);assert.equal(r.writes.length,1);assert.equal(r.receipt.error,'WORKBOARD_NATIVE_OPERATION_FAILED');});
const branchStart=source.indexOf("if (contract.qualification_scope === 'workboard-native-worker-logical-recovery.synthetic.v1') {");
const branchEnd=source.indexOf('    } else {\n      await run(contract.native_argv',branchStart);
const branch = source.slice(branchStart,branchEnd)+'    }';
async function nativeBranch(options={}) {
 const calls=[], env={QUALIFICATION_JOB:'real-parent-context',UNRELATED:'restore-me'};let live=true,retainedGuard;
 const result={schema:'workboard-native-worker-logical-recovery.synthetic.v1',completed:true,synthetic:true,productionAcceptance:false,fullRecoveryReady:false,originalFactoryTargetIssuerJoined:true,storeAndCustodianJoined:true,revokedCallRejected:true,postAcknowledgementRestoreQualified:false};
 const process={env},receipt={};const context=vm.createContext({contract:{qualification_scope:result.schema,source_commit:'c'.repeat(40),source_tree:'d'.repeat(40)},phase:'offline-native',process,receipt,remaining(){calls.push('remaining');assert(live);return 10;},requireThat(ok,m){assert(ok,m);},path,sha(){return'a'.repeat(64);},actual:{sha256:'b'.repeat(64)},fs:{mkdirSync(){calls.push('mkdir');},writeFileSync(){calls.push('write');}}});
 const target = new vm.SyntheticModule(['runWorkboardPrivateRecoveryQualification'], function(){this.setExport('runWorkboardPrivateRecoveryQualification',async input=>{
   calls.push('proof');retainedGuard=input.assertCurrent;assert.equal(input.python,'/usr/bin/python3');assert.equal(env.UNRELATED,undefined);assert.equal(env.OPENCLAW_STATE_DIR,'/qualification/native-state/workboard-runtime');input.assertCurrent();if(options.fail)throw options.fail;return result;
 });},{context});await target.link(()=>{throw Error('unexpected');});await target.evaluate();
 const module=new vm.SourceTextModule(branch,{context,importModuleDynamically:async specifier=>{assert.equal(specifier,'/artifact/dist/proofs/workboard-private-recovery-controller.js');calls.push('import');if(options.retireAtImport)live=false;return target;}});
 await module.link(()=>{throw Error('unexpected');});let failure;try{await module.evaluate();}catch(e){failure=e;}
 return{calls,env,receipt,failure,retainedGuard};
}
await test('actual native branch invokes same-process live closure and restores environment',async()=>{const r=await nativeBranch();assert.equal(r.failure,undefined);assert.equal(r.receipt.native.synthetic,true);assert.equal(r.receipt.native.productionAcceptance,false);assert.equal(r.env.UNRELATED,'restore-me');assert.equal(r.env.OPENCLAW_STATE_DIR,undefined);assert.throws(r.retainedGuard,/native proof owner retired/);});
await test('actual branch stops after import retirement before proof and restores environment',async()=>{const r=await nativeBranch({retireAtImport:true});assert(r.failure);assert(!r.calls.includes('proof'));assert(!r.calls.includes('write'));assert.equal(r.env.UNRELATED,'restore-me');});
await test('actual branch retires retained closure and restores environment on failure',async()=>{const primary=Object.assign(Error('unit-only'),{code:'outcome-unknown'}),r=await nativeBranch({fail:primary});assert.equal(r.failure,primary);assert.equal(r.env.UNRELATED,'restore-me');assert.throws(r.retainedGuard,/native proof owner retired/);assert(!r.calls.includes('write'));});
const apiHunk = selectedPostimageHunk('extensions/workboard/api.ts');
const apiSource=stripTypeScriptTypes(apiHunk.slice(apiHunk.indexOf('export async function openWorkboardRecoveryQualificationStore(')),{mode:'strip'});
async function factoryCase(retired) {
 const calls=[];let current=true;const context=vm.createContext({URL});
 const apiPort=new vm.SyntheticModule(['definePluginEntry'],function(){this.setExport('definePluginEntry',()=>{});},{context});
 const storePort=new vm.SyntheticModule(['WorkboardStore'],function(){this.setExport('WorkboardStore',{openSqlite(url,options){calls.push({url,options});return{originalFactory:true};}});},{context});await storePort.link(()=>{});await storePort.evaluate();
 const module=new vm.SourceTextModule(apiSource,{context,importModuleDynamically:async specifier=>{assert.equal(specifier,'./src/store.js');if(retired)current=false;return storePort;}});
 await module.link(()=>{throw Error('unexpected static factory import');});await module.evaluate();
 let result,failure;try{result=await module.namespace.openWorkboardRecoveryQualificationStore({dbPath:'/synthetic/file',workerModuleUrl:new URL('file:///synthetic/worker.js')},()=>{assert(current,'retired');});}catch(e){failure=e;}
 return{calls,result,failure};
}
await test('actual plugin factory forwards only the pinned dbPath and original Worker URL',async()=>{const r=await factoryCase(false);assert.equal(r.result.originalFactory,true);assert.equal(r.calls.length,1);assert.equal(r.calls[0].options.dbPath,'/synthetic/file');assert.equal(r.calls[0].url.href,'file:///synthetic/worker.js');});
await test('actual lazy factory rechecks owner after import before original opener',async()=>{const r=await factoryCase(true);assert(r.failure);assert.equal(r.calls.length,0);});
const storeSource=selectedPostimageHunk('extensions/workboard/src/store.ts');
const methodStart=storeSource.indexOf('static openSqlite('),methodEnd=storeSource.indexOf('\n  }',methodStart)+4;
const method=stripTypeScriptTypes(storeSource.slice(methodStart,methodEnd).replace('static openSqlite','function openSqlite'),{mode:'strip'});
await test('actual original store factory preserves default and explicit dbPath forwarding',()=>{
 const calls=[], context={createWorkboardSqliteStores(input){calls.push(input);return{cards:{},storeMarker:true};},WorkboardStore:class{constructor(cards,stores){this.cards=cards;this.stores=stores;}}};
 const open=vm.runInNewContext(method+';openSqlite',context),url=new URL('file:///synthetic/worker.js');
 assert.equal(open(url).stores.storeMarker,true);assert.equal(calls[0].dbPath,undefined);open(url,{dbPath:'/synthetic/db'});assert.equal(calls[1].dbPath,'/synthetic/db');assert.equal(calls[1].workerModuleUrl,url);
});
console.log(JSON.stringify({schema:'workboard.source-composition-producer-units.v1',passed:cases.length,cases,ports:'actual selected source evaluated with explicit unit doubles',nativeWorkerStarted:false,helperStarted:false,databaseOpened:false,containerStarted:false,productionAcceptance:false}));
