#!/usr/bin/env node
// One CI-only actual-package qualification. No registry/fetch/install/lifecycle commands.
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, chmodSync, rmSync, openSync, writeSync, fsyncSync, closeSync, existsSync, lstatSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { NPM_VENDOR_PINS as P, sha256, readNpmVendorProof, verifyOriginalNpmVendorDirectory, verifyInstalledNpmVendorDirectory } from './lib/npm-glob-vendor-proof.mjs';
import { authenticateOriginalNpmArchive, verifyNpmVendorTarball, readBoundedNpmArchive } from './lib/npm-glob-vendor-archive.mjs';
const fail=code=>{throw new Error(`npm-vendor.${code}`);};
const ASSERTION_OPERATORS=new Set(['strictEqual','notStrictEqual','deepStrictEqual','notDeepStrictEqual','equal','notEqual','deepEqual','notDeepEqual','ok','match','doesNotMatch','throws','doesNotThrow','rejects','doesNotReject','fail','ifError','==','!=','===','!==','>','<','>=','<=','unavailable']);
export const QUALIFICATION_EXCEPTION_NAMES=Object.freeze(['Error','TypeError','SyntaxError','RangeError','ReferenceError','EvalError','URIError','AggregateError','AssertionError']);
export const QUALIFICATION_EXCEPTION_CODES=Object.freeze(['ERR_MODULE_NOT_FOUND','ERR_PACKAGE_PATH_NOT_EXPORTED','ERR_REQUIRE_ESM','ERR_UNKNOWN_FILE_EXTENSION','ERR_INVALID_PACKAGE_CONFIG','ERR_INVALID_PACKAGE_TARGET','ERR_PACKAGE_IMPORT_NOT_DEFINED','ERR_UNSUPPORTED_DIR_IMPORT','ERR_INVALID_ARG_TYPE','ERR_INVALID_ARG_VALUE','ERR_INVALID_RETURN_VALUE','ERR_ASSERTION','ERR_BUFFER_TOO_LARGE','ERR_OUT_OF_RANGE','ERR_INVALID_URL','ERR_INVALID_FILE_URL_PATH','ERR_INVALID_FILE_URL_HOST','ERR_UNKNOWN_BUILTIN_MODULE','ABORT_ERR','ENOENT','EACCES','EPERM','EEXIST','ENOTDIR','EISDIR','ENOSPC','EROFS','EMFILE','ENFILE','EIO','ENAMETOOLONG','ELOOP','ETIMEDOUT']);
function finiteExceptionField(error,key,allowed) {
  if(error===null||!['object','function'].includes(typeof error))return {state:'absent'};
  try {
    let object=error;
    for(let depth=0;object!==null&&depth<8;depth++,object=Object.getPrototypeOf(object)) {
      const field=Object.getOwnPropertyDescriptor(object,key);if(!field)continue;
      if(!Object.hasOwn(field,'value'))return {state:'unrecognized'}; // Never invoke diagnostic getters.
      if(field.value===undefined)return {state:'absent'};
      return typeof field.value==='string'&&allowed.includes(field.value)?{state:'recognized',value:field.value}:{state:'unrecognized'};
    }
    return object===null?{state:'absent'}:{state:'unrecognized'};
  } catch {return {state:'unrecognized'};}
}
export function projectQualificationExceptionCause(error) {
  return {name:finiteExceptionField(error,'name',QUALIFICATION_EXCEPTION_NAMES),code:finiteExceptionField(error,'code',QUALIFICATION_EXCEPTION_CODES)};
}
export function qualificationArguments(args) {
  const keys=['--original-npm','--derived-npm','--repo-root','--receipt'];
  if(args.length!==8||keys.some((key,i)=>args[i*2]!==key)||args.some(a=>typeof a!=='string'||!a||a.includes('\0')))fail('qualification_arguments');
  return {originalArchive:args[1],derivedArchive:args[3],repoRoot:args[5],receiptPath:args[7]};
}
export function projectPackageTestResult(result) {
  if(!result||result.schema!=='openclaw.npm-vendor-actual-package-tests.v1'||!Array.isArray(result.cases)||result.cases.length!==52||
    typeof result.passed!=='boolean'||result.originalVersion!==P.npmVersion||result.derivedVersion!==P.npmVersion||result.globVersion!==P.globVersion||
    result.packageExecutionHost!=='ci-only'||result.imageTested!==false||result.publicPackTested!==true||result.actualBunRuntimeTested!==false)fail('package_test_shape');
  const names=new Set();const cases=result.cases.map(row=>{
    if(!row||typeof row.name!=='string'||!/^[A-Za-z0-9._:/ -]{1,180}$/.test(row.name)||names.has(row.name)||typeof row.passed!=='boolean')fail('package_case_shape');
    names.add(row.name);const safe={name:row.name,passed:row.passed};
    if(!row.passed){
      safe.code=typeof row.code==='string'&&/^[A-Za-z0-9._:/-]{1,100}$/.test(row.code)?row.code:'case_failed';
      const a=row.assertion;if(!a||typeof a!=='object'||Array.isArray(a)||Object.keys(a).some(k=>!['operator','actual','expected'].includes(k))||!ASSERTION_OPERATORS.has(a.operator))fail('package_assertion_shape');
      safe.assertion={operator:a.operator};for(const key of ['actual','expected'])if(Object.hasOwn(a,key)){if(typeof a[key]!=='number'||!Number.isFinite(a[key]))fail('package_assertion_shape');safe.assertion[key]=a[key];}
    }
    return safe; // Never copies assertion message or arbitrary observed fields.
  });
  const passedCount=cases.filter(row=>row.passed).length;
  if(result.passed!==(passedCount===52))fail('package_test_conclusion');
  return {schema:result.schema,passed:result.passed,caseCount:52,passedCount,cases,packageExecutionHost:'ci-only',imageTested:false,publicPackTested:result.passed,actualBunRuntimeTested:false};
}
function writeAll(fd,bytes){let offset=0;while(offset<bytes.length){const written=writeSync(fd,bytes,offset,bytes.length-offset);if(written<1)fail('qualification_evidence_short_write');offset+=written;}}
export function preserveQualificationEvidence({receiptPath,kind,bytes}) {
  const config=kind==='result'?{file:'npm-vendor-actual-test-result.private.json',limitBytes:131072}:kind==='exception'?{file:'npm-vendor-qualification-exception.private.txt',limitBytes:16384}:null;
  if(!config||!Buffer.isBuffer(bytes))fail('qualification_evidence_input');
  const prefix=bytes.subarray(0,config.limitBytes);const file=path.join(path.dirname(receiptPath),config.file);
  // Preserve the raw prefix first, before hashes, parsing, shape checks or refusal.
  const fd=openSync(file,'wx',0o600);try{writeAll(fd,prefix);fsyncSync(fd);}finally{closeSync(fd);}
  return {file:config.file,bytes:bytes.length,sha256:sha256(bytes),storedBytes:prefix.length,storedSha256:sha256(prefix),truncated:bytes.length>prefix.length,limitBytes:config.limitBytes};
}
export function captureAndProjectPackageTestResult({receiptPath,result,evidence}) {
  const serialized=JSON.stringify(result,null,2);const bytes=Buffer.from((serialized===undefined?'undefined':serialized)+'\n');
  evidence.testResultEvidence=preserveQualificationEvidence({receiptPath,kind:'result',bytes});
  if(evidence.testResultEvidence.truncated)fail('qualification_result_truncated');
  return projectPackageTestResult(result);
}
function readInput(file,limit) {
  const stat=lstatSync(file);if(!stat.isFile()||stat.isSymbolicLink()||stat.size>limit)fail('qualification_input_bound');return readFileSync(file);
}
function storeReceipt(file,value) {
  const raw=Buffer.from(JSON.stringify(value,null,2)+'\n');if(raw.length>64*1024)fail('qualification_receipt_bound');
  const fd=openSync(file,'wx',0o600);try{writeAll(fd,raw);fsyncSync(fd);}finally{closeSync(fd);}
}
function extractAuthenticated(files,root) {
  mkdirSync(root,{mode:0o700});
  for(const row of files.values()){
    const target=path.join(root,row.path);mkdirSync(path.dirname(target),{recursive:true,mode:0o700});
    writeFileSync(target,row.bytes,{flag:'wx',mode:row.mode});chmodSync(target,row.mode);
  }
}
export async function qualifyNpmGlobBackport({originalArchive,derivedArchive,repoRoot,receiptPath}) {
  if(process.env.GITHUB_ACTIONS!=='true'||process.env.CI!=='true')fail('qualification_ci_only');
  for(const file of [originalArchive,derivedArchive,repoRoot,receiptPath])if(typeof file!=='string'||!path.isAbsolute(file)||path.normalize(file)!==file||file.includes('\0'))fail('qualification_path');
  const parent=path.dirname(receiptPath);if(!lstatSync(parent).isDirectory()||realpathSync(parent)!==parent||existsSync(receiptPath))fail('qualification_receipt_path');
  const evidence={schema:'openclaw.npm-glob-vendor-qualification.v1',status:'failed',phase:'proof',reason:'not_completed',packageExecuted:false,imageTested:false,actualBunRuntimeTested:false};
  let stage;
  try {
    const root=realpathSync(repoRoot);if(root!==repoRoot||!lstatSync(root).isDirectory())fail('qualification_repo');
    const proofBytes=readInput(path.join(root,'patches/npm-12.2.1.glob-cancellation.proof.json'),1024*1024);const proof=readNpmVendorProof(proofBytes);
    const patch=readInput(path.join(root,'patches/npm@12.2.1.patch'),2*1024*1024);
    if(patch.length!==proof.patch.size||sha256(patch)!==proof.patch.sha256)fail('qualification_patch');
    evidence.proofSha256=sha256(proofBytes);evidence.patchSha256=sha256(patch);
    evidence.phase='archive_authentication';
    const originalBytes=readInput(originalArchive,8*1024*1024);const original=authenticateOriginalNpmArchive(originalBytes);
    const derivedBytes=readInput(derivedArchive,8*1024*1024);verifyNpmVendorTarball({tarball:derivedBytes,proof});const derived=readBoundedNpmArchive(derivedBytes);
    evidence.originalSha256=sha256(originalBytes);evidence.derivedSha256=sha256(derivedBytes);
    evidence.phase='owned_staging';stage=mkdtempSync(path.join(tmpdir(),'openclaw-vendor-qualification-'));const originalRoot=path.join(stage,'original');const derivedRoot=path.join(stage,'derived');
    extractAuthenticated(original,originalRoot);extractAuthenticated(derived,derivedRoot);
    verifyOriginalNpmVendorDirectory({packageRoot:originalRoot,proof,patchBytes:patch});verifyInstalledNpmVendorDirectory({packageRoot:derivedRoot,proof,patchBytes:patch});
    evidence.phase='actual_package_tests';
    // Fixed reviewed source path, never caller-selected or archive-provided code.
    const tests=await import(pathToFileURL(path.join(root,'scripts/test-npm-vendor-package.mjs')).href);
    if(typeof tests.runNpmVendorPackageTests!=='function')fail('qualification_test_interface');
    evidence.packageExecutionAttempted=true;evidence.packageExecuted='unknown';
    const actualResult=await tests.runNpmVendorPackageTests({originalRoot,derivedRoot,repoRoot:root});
    evidence.tests=captureAndProjectPackageTestResult({receiptPath,result:actualResult,evidence});
    evidence.packageExecuted=true;
    if(!evidence.tests.passed)fail('qualification_package_tests_failed');
    evidence.status='passed';evidence.phase='complete';evidence.reason='all_52_cases_passed';
  } catch(error) {
    const bytes=Buffer.from(String(error?.stack??error));
    try{evidence.exceptionEvidence=preserveQualificationEvidence({receiptPath,kind:'exception',bytes});}catch{evidence.exceptionEvidence={status:'unavailable',reason:'private_evidence_write_failed'};}
    evidence.exceptionCause=projectQualificationExceptionCause(error);
    evidence.reason=typeof error?.message==='string'&&/^npm-vendor\.[a-z0-9_]+$/.test(error.message)?error.message:'qualification_failed';
    storeReceipt(receiptPath,evidence);throw new Error(`npm-vendor.qualification_failed:${evidence.phase}:${evidence.reason}`);
  } finally {if(stage)rmSync(stage,{recursive:true,force:true});}
  storeReceipt(receiptPath,evidence);return evidence;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(path.resolve(process.argv[1])).href){
  const result=await qualifyNpmGlobBackport(qualificationArguments(process.argv.slice(2)));
  console.log(JSON.stringify({schema:result.schema,status:result.status,caseCount:result.tests.caseCount,passedCount:result.tests.passedCount,imageTested:false,actualBunRuntimeTested:false}));
}
