// Synthetic/local source tests only. Never imports tar/esbuild or vendor code.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, rmSync, symlinkSync, writeFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { NPM_VENDOR_PINS as P, NPM_VENDOR_CHANGED_PATHS as CHANGED, sha256, canonicalInventorySha256, validateNpmVendorProof, readNpmVendorProof, verifyInstalledNpmVendorDirectory, inventoryMode } from './lib/npm-glob-vendor-proof.mjs';
import { applyWalkerCancellationFix, createFullFilePatch, buildNpmGlobBackport } from './lib/npm-glob-vendor-backport.mjs';
import { authenticateOriginalNpmArchive } from './lib/npm-glob-vendor-archive.mjs';
const original=readNpmVendorProof(readFileSync(new URL('../patches/npm-12.2.1.glob-cancellation.proof.json',import.meta.url))).original.files;
const rows=original.map(r=>({...r}));
const changes=CHANGED.map(name=>{const r=rows.find(r=>r.path===name);const old=r.sha256;r.sha256=sha256(Buffer.from(`synthetic:${name}`));r.size=1;return {path:name,oldSha256:old,newSha256:r.sha256,size:r.size,mode:r.mode};});
const proof={schema:'openclaw.npm-glob-vendor-backport.v1',npmVersion:P.npmVersion,original:{integrity:P.originalIntegrity,sha256:P.originalSha256,inventorySha256:P.originalInventorySha256,mapsAbsent:true,files:original},repair:{globVersion:P.globVersion,fixCommit:P.fixCommit,sourceCommit:P.sourceCommit,sourceSha256:P.sourceSha256,upstreamFixSha256:P.upstreamFixSha256,changedFiles:changes},compiler:{name:'esbuild',version:P.esbuildVersion,integrity:P.esbuildIntegrity},derived:{integrity:P.originalIntegrity,sha256:'a'.repeat(64),inventorySha256:canonicalInventorySha256(rows)},patch:{filename:'npm@12.2.1.patch',sha256:'b'.repeat(64),size:1},maps:CHANGED.map(p=>({path:`${p}.map`,size:1,sha256:'c'.repeat(64)})).sort((a,b)=>a.path<b.path?-1:1)};
const copy=()=>structuredClone(proof);
test('actual authenticated original canonical inventory binding',()=>assert.equal(canonicalInventorySha256(original),P.originalInventorySha256));
test('closed synthetic proof derives exact1942files/four replacements',()=>assert.equal(validateNpmVendorProof(proof).files.length,1942));
test('proof duplicate JSON keys rejected by canonical custody',()=>assert.throws(()=>readNpmVendorProof(Buffer.from('{"schema":"x","schema":"y"}\n'))));
test('proof pretty canonical bytes accepted',()=>assert.equal(readNpmVendorProof(Buffer.from(JSON.stringify(proof,null,2)+'\n')).schema,proof.schema));
for(const [name,mutate] of [
 ['originalSRI',p=>p.original.integrity='x'],['original inventory tamper',p=>p.original.files[0].sha256='d'.repeat(64)],
 ['originalmapsfalse',p=>p.original.mapsAbsent=false],['additionaloriginalfile',p=>p.original.files.push(p.original.files[0])],
 ['wrongfix',p=>p.repair.fixCommit='a'.repeat(40)],['wrongsource',p=>p.repair.sourceSha256='a'.repeat(64)],
 ['wrongcompiler',p=>p.compiler.version='0.28.3'],['fifthchange',p=>p.repair.changedFiles.push(p.repair.changedFiles[0])],
 ['unapprovedpath',p=>p.repair.changedFiles[0].path='package.json'],['wrongbeforehash',p=>p.repair.changedFiles[0].oldSha256='a'.repeat(64)],
 ['unchangedreplacement',p=>p.repair.changedFiles[0].newSha256=p.repair.changedFiles[0].oldSha256],
 ['addedmapshipped',p=>p.original.files[0].path='node_modules/glob/dist/esm/walker.js.map'],
 ['missingmap',p=>p.maps.pop()],['mapoversize',p=>p.maps[0].size=9*1024*1024],
 ['wrongderivedinventory',p=>p.derived.inventorySha256='a'.repeat(64)],['unknownproofkey',p=>p.qualification=true],
])test(`refuses ${name}`,()=>{const p=copy();mutate(p);assert.throws(()=>validateNpmVendorProof(p));});
test('all five official semantic hunks reproduce exact upstream fixed source',()=>{
 const root=new URL('./lib/npm-glob-vendor-sources/',import.meta.url);
 const parent=readFileSync(new URL('fix-parent-walker.ts.txt',root),'utf8'),fixed=readFileSync(new URL('fix-walker.ts.txt',root),'utf8');
 assert.equal(applyWalkerCancellationFix(parent),fixed);
 const old=readFileSync(new URL('glob13-walker.ts.txt',root),'utf8');const repaired=applyWalkerCancellationFix(old);
 assert.equal((repaired.match(/if \(this.signal\?\.aborted\) return cb\(\)/g)||[]).length,4);
 assert.ok(!repaired.includes('  onResume(fn: () => unknown) {\n    if (this.signal?.aborted) return'));
});
test('partial or already patched semantic inputs refuse',()=>assert.throws(()=>applyWalkerCancellationFix('onResume incomplete')));
test('wrong original archive refuses BEFORE tar package use',()=>assert.throws(()=>authenticateOriginalNpmArchive(Buffer.from('bad')),/original_archive_identity/));
test('CI guard refuses before tar/compiler/package use',async()=>{
 const old=process.env.GITHUB_ACTIONS;delete process.env.GITHUB_ACTIONS;
 try{await assert.rejects(buildNpmGlobBackport({originalTarball:Buffer.alloc(0),globSourceTarball:Buffer.alloc(0),outputDir:'/unused'}),/ci_only/);}finally{if(old!==undefined)process.env.GITHUB_ACTIONS=old;}
});
test('fullfile patch names only four exact paths and newline markers',()=>{
 const before=new Map(CHANGED.map(p=>[p,{bytes:Buffer.from('old\nlast')} ]));const after=new Map(CHANGED.map(p=>[p,{bytes:Buffer.from('new\nlast\n')} ]));
 const text=createFullFilePatch(before,after).toString();assert.equal((text.match(/^diff --git /gm)||[]).length,4);assert.equal((text.match(/^\\ No newline at end of file$/gm)||[]).length,4);
});
test('installed verifier refuses nested link without following outside root',()=>{
 const root=mkdtempSync(path.join(tmpdir(),'vendor-proof-fixture-'));
 try{symlinkSync('/unreadable-outside',path.join(root,'link'));assert.throws(()=>verifyInstalledNpmVendorDirectory({packageRoot:root,proof}),/installed_link/);}finally{rmSync(root,{recursive:true,force:true});}
});
test('installed verifier refuses missing/full inventory drift',()=>{
 const root=mkdtempSync(path.join(tmpdir(),'vendor-proof-fixture-'));
 try{writeFileSync(path.join(root,'package.json'),'{}');assert.throws(()=>verifyInstalledNpmVendorDirectory({packageRoot:root,proof}),/installed_inventory/);}finally{rmSync(root,{recursive:true,force:true});}
});

for(const bit of [0o4000,0o2000,0o1000])test(`mode collector rejects special permission bit ${bit.toString(8)}`,()=>assert.throws(()=>inventoryMode(0o644|bit),/inventory_mode/));
