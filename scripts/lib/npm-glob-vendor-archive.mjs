// Shared bounded archive owner. Parsing/packing uses the repository's locked tar,
// not npm pack, lifecycle hooks, shell tar, or a second hand-written tar parser.
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { NPM_VENDOR_PINS, sha256, integrity, canonicalInventorySha256,
  validateNpmVendorProof, verifyInstalledNpmVendorDirectory, inventoryMode } from './npm-glob-vendor-proof.mjs';

const fail = code => { throw new Error(`npm-vendor.${code}`); };
const require = createRequire(import.meta.url);
function tarOwner() { return require('tar'); }
export function readBoundedNpmArchive(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length > 8*1024*1024) fail('archive_bound');
  const tar=tarOwner(); const files=new Map();let expanded=0,error;
  const parser=tar.list({sync:true,strict:true,onReadEntry(entry) {
    const name=entry.path;
    if (entry.type!=='File' || entry.linkpath || typeof name!=='string' || !name.startsWith('package/') ||
      name.includes('\\') || /[\x00-\x1f\x7f]/.test(name) || name.normalize('NFC')!==name ||
      name.split('/').some(p=>!p || p==='.' || p==='..') || files.has(name.slice(8)) || files.size>=20000 ||
      !Number.isSafeInteger(entry.size) || entry.size<0 || entry.size>8*1024*1024 || ![0o644,0o755].includes(entry.mode&0o7777)) fail('archive_member');
    expanded+=entry.size;if(expanded>32*1024*1024)fail('archive_expansion');
    const chunks=[];let size=0;files.set(name.slice(8),null);
    entry.on('data',b=>{size+=b.length;if(size>entry.size)fail('archive_member_bound');chunks.push(b);});
    entry.on('end',()=>{if(size!==entry.size)fail('archive_member_size');const data=Buffer.concat(chunks);files.set(name.slice(8),{path:name.slice(8),mode:inventoryMode(entry.mode),size,sha256:sha256(data),bytes:data});});
  }});
  parser.on('error',e=>{error=e;});parser.end(bytes);if(error)throw error;
  if([...files.values()].some(row=>!row))fail('archive_unsettled');
  return files;
}
export const archiveInventory=files=>[...files.values()].sort((a,b)=>a.path<b.path?-1:a.path>b.path?1:0).map(({path,mode,size,sha256})=>({path,mode,size,sha256}));
export function authenticateOriginalNpmArchive(bytes) {
  // Integrity is checked BEFORE the parser or any package source is used.
  if (!Buffer.isBuffer(bytes) || bytes.length>8*1024*1024 || integrity(bytes)!==NPM_VENDOR_PINS.originalIntegrity || sha256(bytes)!==NPM_VENDOR_PINS.originalSha256)fail('original_archive_identity');
  const files=readBoundedNpmArchive(bytes);
  if(canonicalInventorySha256(archiveInventory(files))!==NPM_VENDOR_PINS.originalInventorySha256)fail('original_archive_inventory');
  return files;
}
export function createCanonicalNpmTarball(files) {
  const ordered=[...files.values()].sort((a,b)=>a.path<b.path?-1:a.path>b.path?1:0);
  const stage=mkdtempSync(path.join(tmpdir(),'openclaw-npm-vendor-'));
  try {
    for(const row of ordered){
      if(!Buffer.isBuffer(row.bytes)||row.bytes.length!==row.size||sha256(row.bytes)!==row.sha256)fail('pack_bytes');
      const file=path.join(stage,'package',row.path);mkdirSync(path.dirname(file),{recursive:true});writeFileSync(file,row.bytes,{flag:'wx',mode:row.mode});chmodSync(file,row.mode);
    }
    const tar=tarOwner();
    const output=path.join(stage,'derived.tgz');
    tar.create({sync:true,file:output,cwd:stage,gzip:{level:9},portable:true,noPax:true,mtime:new Date(0),follow:false},ordered.map(row=>`package/${row.path}`));
    const bytes=readFileSync(output);if(bytes.length>8*1024*1024)fail('pack_bound');return bytes;
  } finally {rmSync(stage,{recursive:true,force:true});}
}
export function verifyNpmVendorTarball({tarball,proof}) {
  const facts=validateNpmVendorProof(proof);
  if(!Buffer.isBuffer(tarball)||sha256(tarball)!==proof.derived.sha256||integrity(tarball)!==proof.derived.integrity)fail('derived_archive_identity');
  const files=readBoundedNpmArchive(tarball);
  if(JSON.stringify(archiveInventory(files))!==JSON.stringify(facts.files))fail('derived_archive_inventory');return facts;
}
export function createVerifiedNpmVendorTarball({packageRoot,proof}) {
  const facts=verifyInstalledNpmVendorDirectory({packageRoot,proof});
  const files=new Map(facts.files.map(row=>[row.path,{...row,bytes:readFileSync(path.join(facts.packageRoot,row.path))}]));
  const bytes=createCanonicalNpmTarball(files);verifyNpmVendorTarball({tarball:bytes,proof});return bytes;
}
