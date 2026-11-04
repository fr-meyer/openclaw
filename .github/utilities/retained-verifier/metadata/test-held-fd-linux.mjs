// Ordinary synthetic files and real Linux descriptors, with fake DB/package ports.
// This does not import SQLite, candidate packages or private/retained data.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import http from 'node:http';
import https from 'node:https';
import childProcess from 'node:child_process';
import {runPhase} from './native-copy-worker.mjs';
import {runPhase as oldRunPhase} from './native-copy-worker-before.mjs';

const output=process.stdout.write.bind(process.stdout);
const real=Object.fromEntries(['realpathSync','lstatSync','fstatSync','statfsSync','readdirSync','mkdirSync',
  'writeSync','fsyncSync','openSync','closeSync','unlinkSync','rmdirSync','linkSync','symlinkSync'].map(k=>[k,fs[k].bind(fs)]));
const constants={O_RDONLY:fs.constants.O_RDONLY,O_NOFOLLOW:fs.constants.O_NOFOLLOW,O_NONBLOCK:fs.constants.O_NONBLOCK};
const writeFlags={create:fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,replace:fs.constants.O_WRONLY|fs.constants.O_TRUNC|fs.constants.O_NOFOLLOW};
assert.equal(process.versions.node,'24.22.1');assert.equal(process.platform,'linux');assert.equal(process.arch,'x64');
assert.equal(process.getuid(),1000);assert.equal(process.getgid(),1000);assert.equal(process.argv.length,3);
const root=process.argv[2];
assert.equal(path.resolve(root),root);assert.equal(real.realpathSync(root),root);
assert.match(root,/^\/tmp\/ocv-synthetic-metadata-[A-Za-z0-9_-]+\/fd-fixtures$/);
const parent=real.lstatSync(path.dirname(root),{bigint:true}),rootFact=real.lstatSync(root,{bigint:true});
assert.equal(parent.isDirectory(),true);assert.equal(parent.uid,0n);assert.equal(parent.mode,0o40755n);
assert.equal(rootFact.isDirectory(),true);assert.equal(rootFact.uid,1000n);assert.equal(rootFact.gid,1000n);assert.equal(rootFact.mode,0o40700n);
assert.deepEqual(real.readdirSync(root),[]);

const denied=[];const deny=()=>{denied.push('forbidden');throw new Error('synthetic_effect_forbidden');};
for(const object of [fs,net,http,https,childProcess])for(const key of Object.keys(object))if(typeof object[key]==='function')try{object[key]=deny;}catch{}
for(const key of ['setTimeout','setInterval','setImmediate','fetch'])globalThis[key]=deny;
process.kill=deny;process.exit=deny;
const DIR='/maintenance/copy',FILE=DIR+'/fixture.sqlite',PIN='a'.repeat(64);
const cases=[];let realOpen=0,realClose=0,realFstat=0,closedFstat=0;
const opened=new Set();
function writeOrdinary(file,buffer,replace=false){const fd=real.openSync(file,replace?writeFlags.replace:writeFlags.create,0o600);try{let offset=0;while(offset<buffer.length){const n=real.writeSync(fd,buffer,offset,buffer.length-offset);assert.ok(n>0);offset+=n;}real.fsyncSync(fd);}finally{real.closeSync(fd);}}
function fail(code=11){throw Object.assign(new Error('synthetic_port_failure'),{errcode:code});}

function fixture(name,options={}){
  assert.match(name,/^[a-z0-9-]{1,64}$/);
  const directory=path.join(root,name),main=path.join(directory,'fixture.sqlite');
  real.mkdirSync(directory,{mode:0o700});
  const owned=[main,main+'-wal',main+'-shm'];
  writeOrdinary(main,Buffer.alloc(40960,83));
  writeOrdinary(main+'-wal',options.initialWal?Buffer.from([83]):Buffer.alloc(0));
  writeOrdinary(main+'-shm',Buffer.alloc(32768));
  if(options.symlink){real.unlinkSync(main);writeOrdinary(path.join(root,name+'-target'),Buffer.alloc(40960,83));owned.push(path.join(root,name+'-target'));real.symlinkSync(path.join(root,name+'-target'),main);}
  if(options.hardlink){const link=path.join(root,name+'-link');real.linkSync(main,link);owned.push(link);}
  const initial=real.lstatSync(main,{bigint:true});
  const p={schema:'ocv.disposable-copy-native-profile.v1',ownerSessionId:'1'.repeat(32),grantSha256:'3'.repeat(64),
    sourceSha:'1'.repeat(40),indexDigest:'sha256:'+'2'.repeat(64),
    copyMainIdentity:Object.fromEntries(['dev','ino','uid','gid','nlink','mode'].map(k=>[k,String(initial[k])])),
    sourceMainIdentity:{dev:'0',ino:'0'},initialMainBytes:40960,initialPageCount:10,pageSize:4096,hostPageBytes:4096};
  // Profiles remain valid so the path guard, rather than a synthetic profile check, rejects these files.
  if(options.symlink||options.hardlink){p.copyMainIdentity.nlink='1';p.copyMainIdentity.mode=String(0o100600);}
  const events=[];let databaseClosed=false,outputAttempted=false,offset=0,workerCloseCalls=0,free=4,pages=10,db;
  const started=Number(process.hrtime.bigint()/1000000n);
  function mapped(value){assert.ok([DIR,FILE,FILE+'-wal',FILE+'-shm'].includes(value),'fixed synthetic path only');return value===DIR?directory:main+value.slice(FILE.length);}
  class Statement{
    constructor(sql){this.sql=sql;}
    *iterate(){
      const sql=this.sql;
      if(sql==='PRAGMA main.quick_check'){if(options.quickFail)fail();yield{quick_check:'ok'};return;}
      if(sql.startsWith('SELECT role,')){yield{role:'agent',schema_version:25,agent_id:'fixture-agent'};return;}
      const values={'SELECT sqlite_version() AS version':'3.53.4','SELECT sqlite_source_id() AS source':'synthetic-sqlite-source',
        "SELECT sqlite_compileoption_used('TEMP_STORE=0') AS forcedFile":0,'SELECT vec_version() AS version':'v0.1.9',
        'PRAGMA main.user_version':25,'PRAGMA main.journal_mode':'wal','PRAGMA main.page_size':4096,
        'PRAGMA main.page_count':pages,'PRAGMA main.freelist_count':free,'PRAGMA main.auto_vacuum':2,
        'PRAGMA main.cache_spill':0,'PRAGMA temp_store':2,'PRAGMA main.mmap_size':0,'PRAGMA main.max_page_count':10};
      assert.ok(Object.hasOwn(values,sql),'fixed synthetic SQL only');yield{value:values[sql]};
    }
    close(){}
  }
  class Database{
    constructor(){db=this;this.isOpen=true;this.isTransaction=false;}
    prepare(sql){return new Statement(sql);}
    exec(sql){assert.ok(['PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY; PRAGMA main.cache_spill=OFF; PRAGMA main.mmap_size=0;','PRAGMA query_only=ON','PRAGMA main.max_page_count=10'].includes(sql));}
    enableLoadExtension(value){assert.equal(value,false);}
    close(){databaseClosed=true;this.isOpen=false;if(options.finalWal)writeOrdinary(main+'-wal',Buffer.from([83]),true);if(options.databaseCloseFail)fail(5);}
  }
  const io={started,now:()=>Number(process.hrtime.bigint()/1000000n)+offset,nodeVersion:process.versions.node,
    platform:process.platform,arch:process.arch,uid:process.getuid(),gid:process.getgid(),DatabaseSync:Database,
    outputAttempted:()=>outputAttempted,
    fs:{constants,lstatSync:(value,settings)=>real.lstatSync(mapped(value),settings),
      readdirSync:value=>real.readdirSync(mapped(value)),statfsSync:(value,settings)=>real.statfsSync(mapped(value),settings),
      openSync:(value,flags)=>{assert.equal(value,FILE);assert.equal(flags,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);const fd=real.openSync(mapped(value),flags);events.push(['open',fd]);opened.add(fd);realOpen++;return fd;},
      fstatSync:(fd,settings)=>{events.push(['fstat',fd,opened.has(fd),databaseClosed]);try{const value=real.fstatSync(fd,settings);realFstat++;return databaseClosed&&options.finalHeldMismatch?{...value,ino:value.ino+1n}:value;}catch(error){if(error.code==='EBADF'){closedFstat++;assert.equal(error.errno,-9);}throw error;}},
      closeSync:fd=>{workerCloseCalls++;events.push(['close',fd]);assert.ok(opened.has(fd));if(options.fdCloseFail)fail(5);if(options.fdCloseUnknown)throw new Error('synthetic_unknown_close');real.closeSync(fd);opened.delete(fd);realClose++;if(options.outputOnClose)outputAttempted=true;if(options.elapsedOnClose)offset+=600000;}},
    packages:async()=>({loadVec:async()=>({ok:true}),configure:(_database,config)=>({
      checkpoint:()=>config.runMaintenance(()=>true),
      reclaimFreePages:hooks=>config.runMaintenance(()=>{hooks.beforeMutation();db.isTransaction=true;hooks.beforeMutation();
        const count=Math.min(4,free);free-=count;pages-=count;hooks.onCommit();db.isTransaction=false;hooks.afterCommit();hooks.beforeMutation();
        return{checkpointCompleted:true,vacuumPasses:1,vacuumPagesRequested:count};}),
      stop:async()=>{},close:()=>true})})};
  return{events,state:()=>({workerCloseCalls,live:opened.size}),run:(phase,owner=runPhase)=>owner(p,phase,PIN,io),
    cleanup:()=>{for(const fd of [...opened]){real.closeSync(fd);opened.delete(fd);realClose++;}for(const file of owned.reverse())real.unlinkSync(file);real.rmdirSync(directory);}};
}

async function test(name,fn){await fn();assert.equal(opened.size,0);assert.deepEqual(real.readdirSync(root),[]);cases.push({name,passed:true});}
async function withFixture(name,options,fn){const value=fixture(name,options);try{return await fn(value);}finally{value.cleanup();}}
function refused(value,stage,code){assert.equal(value.status,'REFUSED');assert.deepEqual(value.failure,{stage,code});}

await test('old-order-real-fd-ebadf',()=>withFixture('old',{},async h=>{
  const value=await h.run('before',oldRunPhase);assert.equal(value.quickCheck,'ok');refused(value,10,0);
  assert.equal(h.state().workerCloseCalls,1);assert.equal(h.state().live,0);assert.ok(h.events.some(e=>e[0]==='fstat'&&e[2]===false));
}));
await test('fixed-before-after-reclaim-real-fd',async()=>{
  for(const phase of ['before','after','reclaim'])await withFixture(phase,{},async h=>{
    const value=await h.run(phase);assert.equal(value.status,'PASS');assert.equal(value.failure,null);assert.equal(h.state().workerCloseCalls,1);assert.equal(h.state().live,0);
    assert.equal(h.events.some(e=>e[0]==='fstat'&&e[2]===false),false);const end=h.events.findLastIndex(e=>e[0]==='fstat');assert.equal(h.events[end][3],true);assert.ok(end<h.events.findIndex(e=>e[0]==='close'));
  });
});
await test('final-held-identity-refusal-closes',()=>withFixture('identity',{finalHeldMismatch:true},async h=>{refused(await h.run('before'),10,202);assert.equal(h.state().workerCloseCalls,1);assert.equal(h.state().live,0);}));
await test('actual-final-wal-refusal-closes',()=>withFixture('wal',{finalWal:true},async h=>{refused(await h.run('before'),10,203);assert.equal(h.state().workerCloseCalls,1);assert.equal(h.state().live,0);}));
await test('close-failure-refuses-with-owned-cleanup',()=>withFixture('close-fail',{fdCloseFail:true},async h=>{refused(await h.run('before'),10,5);assert.equal(h.state().workerCloseCalls,1);assert.equal(h.state().live,1);}));
await test('unknown-close-failure-is-classified',()=>withFixture('unknown-close',{fdCloseUnknown:true},async h=>{refused(await h.run('before'),10,234);assert.equal(h.state().workerCloseCalls,1);assert.equal(h.state().live,1);}));
await test('first-failure-precedence-preserved',()=>withFixture('precedence',{quickFail:true,databaseCloseFail:true,fdCloseFail:true},async h=>{refused(await h.run('before'),7,11);assert.equal(h.state().workerCloseCalls,1);assert.equal(h.state().live,1);}));
await test('unopened-real-paths-stay-closed',async()=>{
  for(const [name,options,code]of [['initial-wal',{initialWal:true},203],['symlink',{symlink:true},202],['hardlink',{hardlink:true},202]])await withFixture(name,options,async h=>{refused(await h.run('before'),2,code);assert.equal(h.state().workerCloseCalls,0);assert.equal(h.events.some(e=>e[0]==='open'),false);});
});
await test('output-guard-after-close-preserved',()=>withFixture('output',{outputOnClose:true},async h=>{refused(await h.run('before'),10,222);assert.equal(h.state().workerCloseCalls,1);assert.equal(h.state().live,0);}));
await test('elapsed-guard-after-close-preserved',()=>withFixture('elapsed',{elapsedOnClose:true},async h=>{refused(await h.run('before'),11,201);assert.equal(h.state().workerCloseCalls,1);assert.equal(h.state().live,0);}));
assert.equal(realOpen,realClose);assert.equal(opened.size,0);assert.equal(closedFstat,1);assert.ok(realFstat>0);assert.equal(denied.length,0);
const value={schema:'ocv.synthetic-worker-real-fd-proof.v1',status:'PASS',interpreter:{version:process.versions.node,platform:process.platform,arch:process.arch,uid:process.getuid(),gid:process.getgid()},
  cases,caseCount:cases.length,realFd:{readonlyNoFollowOpen:true,heldIdentityCheckedBeforeSingleClose:true,oldClosedFstatErrno:-9,oldClosedFstatCode:'EBADF',oldRunPhaseReproduced:true,fixedRunPhasePassed:true,allOwnedDescriptorsClosed:true,allOwnedFilesRemoved:true},
  scope:{ordinarySyntheticFilesOnly:true,actualRunPhase:true,actualFilesystem:true,syntheticDatabasePorts:true,syntheticPackagePorts:true,candidatePackagesImported:false,sqliteImported:false,databasesOpened:false,privateDataAccessed:false,nativeMaintenanceProved:false},deniedEffectAttempts:0};
const raw=JSON.stringify(value)+'\n';assert.ok(Buffer.byteLength(raw)<=4096);output(raw);
