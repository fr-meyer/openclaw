'use strict';
// Pure virtual process/clock fixture; no spawn, database, timeout or sleep.
const assert=require('node:assert/strict'),{EventEmitter}=require('node:events');
const {supervise}=require('./metadata_supervisor.cjs');
const value={schema:'ocv.retained-clone-schema-registry-hygiene.v1',status:'METADATA_CONSISTENT',rows:Array.from({length:11},(_,ordinal)=>({ordinal})),integrityFreshnessMigrationProductionEstablished:false};
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
(async()=>{for(const kind of ['good','timeout','lateclose','oversize','fault','streamerror','malformed','stderr','nonzero','unclosed','missingpid','badstream','badclock','spawnthrow'])await run(kind);for(const kind of['good','extra','ordinal','hash','code','version','mismatch','partial','deadline','signal'])await diagnostic(kind);console.log(JSON.stringify({sourceOnly:true,realTimersOrProcesses:false,cases,allPassed:true}));})().catch(()=>{process.stderr.write('synthetic_supervisor_test_refused\n');process.exitCode=1;});
