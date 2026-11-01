'use strict';
// Pure virtual process/clock fixture; no spawn, database, timeout or sleep.
const assert=require('node:assert/strict'),{EventEmitter}=require('node:events');
const {supervise}=require('./metadata_supervisor.cjs');
const crypto=require('node:crypto'),hash=x=>crypto.createHash('sha256').update(x).digest('hex');
const value={schema:'ocv.retained-clone-schema-registry-hygiene.v1',status:'METADATA_CONSISTENT',sqliteVersion:'3.50.4',rows:Array.from({length:11},(_,ordinal)=>({ordinal,pathSha256:'b'.repeat(64),role:ordinal===0?'global':'agent',userVersion:ordinal===0?20:25,schemaVersion:ordinal===0?20:25,appVersionMatches:true,writerStamp:{kind:'text',utf8Bytes:9,sha256:hash('2026.10.5')},ownerMatches:true,catalogCounts:{table:1,index:0,view:0,trigger:0},hygiene:{registryRows:ordinal===0?10:0,deletionRows:0,heldRows:0}})),integrityFreshnessMigrationProductionEstablished:false};
let cases=0;
async function run(kind){
 let now=0,timer,kills=0,clear=0,clockCalls=0;const child=new EventEmitter();child.pid=kind==='missingpid'?undefined:123;child.stdout=new EventEmitter();child.stderr=kind==='badstream'?null:new EventEmitter();child.kill=signal=>{assert.equal(signal,'SIGKILL');kills++;return true;};
 const io={execPath:'/usr/local/bin/node',now:()=>{clockCalls++;return kind==='badclock'&&clockCalls===2?NaN:now;},spawn:(exe,argv,options)=>{assert.equal(exe,io.execPath);assert.deepEqual(argv,['--no-warnings','/run/metadata-reader.cjs','a'.repeat(64)]);assert.deepEqual(options,{shell:false,stdio:['ignore','pipe','pipe'],env:{PATH:'/usr/local/bin:/usr/bin:/bin',HOME:'/nonexistent',LANG:'C',LC_ALL:'C',TZ:'UTC'}});if(kind==='spawnthrow')throw Error('private spawn');return child;},setTimer:(fn,ms)=>{assert.equal(ms,60000);timer=fn;return 1;},clearTimer:id=>{assert.equal(id,1);clear++;},waitClose:async(_child,record)=>{
   await Promise.resolve();
   if(kind==='timeout'){now=60000;timer();assert.equal(kills,1);now=60025;}
   if(kind==='oversize')child.stdout.emit('data',Buffer.alloc(14337));
   else if(kind==='fault')child.emit('error',Error('private credential'));
   else if(kind==='streamerror')child.stderr.emit('error',Error('private path'));
   else child.stdout.emit('data',Buffer.from(kind==='malformed'?'private secret':JSON.stringify(value)));
   if(kind==='stderr')child.stderr.emit('data',Buffer.from('private SQL'));
   for(const s of [child.stdout,child.stderr].filter(Boolean)){s.emit('end');if(kind!=='unclosed')s.emit('close');}
   if(kind==='lateclose')now=60001;else if(kind!=='timeout')now=25;
   record(kind==='nonzero'?1:kind==='timeout'?null:0,kind==='timeout'?'SIGKILL':null);
 }};
 const result=await supervise('a'.repeat(64),io);assert.equal(clear,['missingpid','badstream','badclock','spawnthrow'].includes(kind)?0:1);
 if(kind==='good'){assert.equal(result.status,'COMPLETED');assert.deepEqual(result.value,value);assert.equal(result.childCloseObserved,true);assert.equal(result.streamsClosed,true);assert.equal(kills,0);}
 else{assert.equal(result.status,'REFUSED');assert.equal(result.value,null);assert.ok(!JSON.stringify(result).includes('private'));if(['timeout','oversize','fault','streamerror','missingpid','badstream','badclock'].includes(kind))assert.equal(kills,1);}
 cases++;
}
async function diagnostic(kind){
 const child=new EventEmitter();child.pid=42;child.stdout=new EventEmitter();child.stderr=new EventEmitter();child.kill=()=>true;let now=0;
 const failure={ordinal:2,pathSha256:'b'.repeat(64),stage:6,code:129,sqliteVersion:'3.50.4'};
 if(kind==='extra')failure.private='private SQL';if(kind==='ordinal')failure.ordinal=11;if(kind==='hash')failure.pathSha256='/private';if(kind==='code')failure.code=65536;if(kind==='version')failure.sqliteVersion='private version';
 const result=await supervise('a'.repeat(64),{execPath:'/node',now:()=>now,spawn:()=>child,setTimer:()=>1,clearTimer:()=>{},waitClose:async(_child,record)=>{await Promise.resolve();const data={schema:'ocv.retained-clone-schema-registry-hygiene.v1',status:'INCOMPLETE',rows:[{private:'application-record-not-propagated'}],failure,integrityFreshnessMigrationProductionEstablished:false};child.stdout.emit('data',Buffer.from(JSON.stringify(data)));child.stderr.emit('data',Buffer.from(kind==='mismatch'?'private error':JSON.stringify(failure)+'\n'));for(const stream of[child.stdout,child.stderr]){stream.emit('end');if(kind!=='partial')stream.emit('close');}now=kind==='deadline'?60000:20;record(1,kind==='signal'?'SIGTERM':null);}});
 assert.equal(result.status,'REFUSED');assert.equal(result.value,null);assert.ok(!JSON.stringify(result).includes('private')&&!JSON.stringify(result).includes('application-record'));
 if(kind==='good')assert.deepEqual(result.failure,failure);else assert.equal(result.failure,null);cases++;
}
async function writerDiagnostic(kind){
 const child=new EventEmitter();child.pid=42;child.stdout=new EventEmitter();child.stderr=new EventEmitter();child.kill=()=>true;
 const d={kind:'text',utf8Bytes:0,sha256:'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'};
 if(['null','nontext','oversized'].includes(kind))Object.assign(d,{kind,utf8Bytes:null,sha256:null});
 const failure={ordinal:0,pathSha256:'b'.repeat(64),stage:6,code:12916,sqliteVersion:'3.50.4',writerStamp:d};
 if(kind==='missing')delete failure.writerStamp;if(kind==='extra')d.raw='not-permitted';if(kind==='boolbytes')d.utf8Bytes=true;if(kind==='bytes129')d.utf8Bytes=129;
 if(kind==='wronghash')d.sha256='not-a-hash';if(kind==='nontexthash')d.kind='nontext';if(kind==='wrongstage')failure.stage=5;if(kind==='wrongmask')failure.code=12901;
 const result=await supervise('a'.repeat(64),{execPath:'/node',now:()=>20,spawn:()=>child,setTimer:()=>1,clearTimer:()=>{},waitClose:async(_child,record)=>{await Promise.resolve();const data={schema:'ocv.retained-clone-schema-registry-hygiene.v1',status:'INCOMPLETE',rows:[],failure,integrityFreshnessMigrationProductionEstablished:false};child.stdout.emit('data',Buffer.from(JSON.stringify(data)));child.stderr.emit('data',Buffer.from(JSON.stringify(kind==='substitution'?{...failure,writerStamp:{kind:'null',utf8Bytes:null,sha256:null}}:failure)+'\n'));for(const s of[child.stdout,child.stderr]){s.emit('end');s.emit('close');}record(1,null);}});
 assert.equal(result.status,'REFUSED');assert.equal(result.value,null);
 if(['text','null','nontext','oversized','missing'].includes(kind)){assert.deepEqual(result.failure,failure);assert.equal(result.errorClass,0);}else{assert.equal(result.failure,null);assert.equal(result.errorClass,5);}assert.ok(!JSON.stringify(result).includes('not-permitted'));cases++;
}
async function derivativeFault(){
 const {fixture}=require('./test_metadata_reader.cjs'),reader=require('./metadata_reader.cjs'),crypto=require('node:crypto');
 const x=fixture({rows:(k,v,n)=>k==='schema'&&n===0?v.map(row=>({...row,app_version:'synthetic-hash-fault'})):v});
 const createHash=crypto.createHash;let actual;
 try{crypto.createHash=(...args)=>{const h=createHash(...args),update=h.update.bind(h);h.update=(value,...rest)=>{if(value==='synthetic-hash-fault')throw Error('synthetic-derivative-fault');return update(value,...rest);};return h;};actual=reader.collect(x.profile,x.io);}finally{crypto.createHash=createHash;}
 assert.equal(actual.status,'INCOMPLETE');assert.equal(actual.failure.code,0);assert.equal(actual.failure.stage,6);assert.ok(!Object.hasOwn(actual.failure,'writerStamp'));
 const child=new EventEmitter();child.pid=42;child.stdout=new EventEmitter();child.stderr=new EventEmitter();child.kill=()=>true;
 const result=await supervise('a'.repeat(64),{execPath:'/node',now:()=>20,spawn:()=>child,setTimer:()=>1,clearTimer:()=>{},waitClose:async(_child,record)=>{await Promise.resolve();child.stdout.emit('data',Buffer.from(JSON.stringify(actual)));child.stderr.emit('data',Buffer.from(JSON.stringify(actual.failure)+'\n'));for(const s of[child.stdout,child.stderr]){s.emit('end');s.emit('close');}record(1,null);}});
 assert.equal(result.status,'REFUSED');assert.equal(result.value,null);assert.equal(result.errorClass,0);assert.deepEqual(result.failure,actual.failure);assert.ok(!JSON.stringify(result).includes('synthetic-hash-fault'));cases++;
}
async function successDescriptor(kind){
 const data=JSON.parse(JSON.stringify(value)),row=data.rows[0],d=row.writerStamp;
 if(kind==='null'){row.writerStamp={kind:'null',utf8Bytes:null,sha256:null};row.appVersionMatches=false;}
 if(kind==='previous'){d.utf8Bytes=24;d.sha256=hash('synthetic-previous-build');row.appVersionMatches=false;}
 if(kind==='empty'){d.utf8Bytes=0;d.sha256=hash('');row.appVersionMatches=false;}
 if(kind==='true-null')row.writerStamp={kind:'null',utf8Bytes:null,sha256:null};
 if(kind==='false-current')row.appVersionMatches=false;
 if(kind==='true-other'){d.sha256='0'.repeat(64);}
 if(kind==='current-wrong-length'){d.utf8Bytes=0;row.appVersionMatches=false;}
 if(kind==='empty-wrong-hash'){d.utf8Bytes=0;d.sha256='0'.repeat(64);row.appVersionMatches=false;}
 if(kind==='empty-wrong-length'){d.sha256=hash('');row.appVersionMatches=false;}
 if(kind==='number')row.appVersionMatches=1;
 if(kind==='missing')delete row.writerStamp;
 if(kind==='extra')d.raw='not-permitted';
 if(kind==='kind')d.kind='nontext';
 if(kind==='oversized')d.utf8Bytes=129;
 if(kind==='boolbytes')d.utf8Bytes=true;
 if(kind==='null-bytes')row.writerStamp={kind:'null',utf8Bytes:0,sha256:null};
 if(kind==='wrong-role')row.role='agent';
 if(kind==='wrong-schema')row.schemaVersion=19;
 const child=new EventEmitter();child.pid=42;child.stdout=new EventEmitter();child.stderr=new EventEmitter();child.kill=()=>true;
 const result=await supervise('a'.repeat(64),{execPath:'/node',now:()=>20,spawn:()=>child,setTimer:()=>1,clearTimer:()=>{},waitClose:async(_c,record)=>{await Promise.resolve();child.stdout.emit('data',Buffer.from(JSON.stringify(data)));for(const stream of[child.stdout,child.stderr]){stream.emit('end');stream.emit('close');}record(0,null);}});
 if(['current','null','previous','empty'].includes(kind)){assert.equal(result.status,'COMPLETED');assert.deepEqual(result.value,data);}else{assert.equal(result.status,'REFUSED');assert.equal(result.value,null);assert.equal(result.errorClass,5);}cases++;
}
(async()=>{for(const kind of ['good','timeout','lateclose','oversize','fault','streamerror','malformed','stderr','nonzero','unclosed','missingpid','badstream','badclock','spawnthrow'])await run(kind);for(const kind of['good','extra','ordinal','hash','code','version','mismatch','partial','deadline','signal'])await diagnostic(kind);for(const kind of['text','null','nontext','oversized','missing','extra','boolbytes','bytes129','wronghash','nontexthash','wrongstage','wrongmask','substitution'])await writerDiagnostic(kind);await derivativeFault();for(const kind of['current','null','previous','empty','true-null','false-current','true-other','number','missing','extra','kind','oversized','boolbytes','null-bytes','wrong-role','wrong-schema','current-wrong-length','empty-wrong-hash','empty-wrong-length'])await successDescriptor(kind);console.log(JSON.stringify({sourceOnly:true,realTimersOrProcesses:false,cases,allPassed:true}));})().catch(()=>{process.stderr.write('synthetic_supervisor_test_refused\n');process.exitCode=1;});
