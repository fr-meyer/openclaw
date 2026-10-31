'use strict';
// One source-owned query controller. SQLite runs only in its separate child.
// Docker's outer controller independently owns the complete120-second action.
const {spawn}=require('node:child_process');
const QUERY_MS=60000,OUT=14336,ERR=4096;
function need(v){if(v!==true)throw Error('metadata_supervisor_refused');}
async function supervise(pin,io){
 need(typeof pin==='string'&&/^[a-f0-9]{64}$/.test(pin));
 const started=io.now();need(Number.isFinite(started));
 let child=null,timer=null,closePromise=null;
 let timedOut=false,signalSent=false,errorClass=0,bytes=[0,0],parts=[[],[]],eof=[false,false],streamsClosed=[false,false],closed=false,exitCode=null,exitSignal=null;
 function kill(){if(signalSent||child===null)return;signalSent=true;try{need(typeof child.kill==='function'&&child.kill('SIGKILL')===true);}catch(_){errorClass=4;}}
 try{
  child=io.spawn(io.execPath,['--no-warnings','/run/metadata-reader.cjs',pin],{shell:false,stdio:['ignore','pipe','pipe'],env:{PATH:'/usr/local/bin:/usr/bin:/bin',HOME:'/nonexistent',LANG:'C',LC_ALL:'C',TZ:'UTC'}});
  need(child!==null&&typeof child.on==='function');
  child.on('error',()=>{errorClass=1;kill();});
  // Install the terminal wait before validating any post-spawn state.
  closePromise=io.waitClose(child,(code,signal)=>{closed=true;exitCode=code;exitSignal=signal;});
  need(Number.isInteger(child.pid)&&child.pid>0);
  for(const [n,stream]of [child.stdout,child.stderr].entries()){
   need(stream!==null&&typeof stream?.on==='function');
   stream.on('data',data=>{if(!Buffer.isBuffer(data)){errorClass=2;kill();return;}bytes[n]+=data.length;if(bytes[n]>(n===0?OUT:ERR)){errorClass=2;kill();return;}parts[n].push(data);});
   stream.on('error',()=>{errorClass=3;kill();});
   stream.on('end',()=>{eof[n]=true;});stream.on('close',()=>{streamsClosed[n]=true;});
  }
  const left=QUERY_MS-(io.now()-started);need(Number.isFinite(left));
  timer=io.setTimer(()=>{timedOut=true;kill();},Math.max(0,left));
 }catch(_){errorClass=6;kill();}
 finally{
  if(closePromise!==null){try{await closePromise;}catch(_){errorClass=6;kill();}}
  if(timer!==null)io.clearTimer(timer);
 }
 let elapsed=io.now()-started;
 if(!Number.isFinite(elapsed)||elapsed<0){errorClass=6;elapsed=null;}
 if(elapsed!==null&&elapsed>=QUERY_MS)timedOut=true;
 const complete=eof.every(Boolean)&&streamsClosed.every(Boolean);
 const result={schema:'ocv.retained-metadata-query-supervision.v1',status:'REFUSED',profileSha256:pin,queryLimitMilliseconds:QUERY_MS,elapsedMilliseconds:elapsed===null?null:Math.ceil(elapsed),childCloseObserved:closed,ownedChildUncertain:!closed,streamsEOF:eof.every(Boolean),streamsClosed:streamsClosed.every(Boolean),childExitCode:Number.isInteger(exitCode)?exitCode:null,childSignal:exitSignal==='SIGKILL'?'SIGKILL':exitSignal===null?null:'OTHER',deadlineReached:timedOut,killSubmitted:signalSent,errorClass,stdoutBytes:bytes[0],stderrBytes:bytes[1],value:null,failure:null};
 if(closed&&complete&&!timedOut&&!signalSent&&errorClass===0&&exitCode===0&&exitSignal===null&&bytes[0]<=OUT&&bytes[1]===0){
  try{const value=JSON.parse(Buffer.concat(parts[0]).toString('utf8'));need(value.schema==='ocv.retained-clone-schema-registry-hygiene.v1'&&value.status==='METADATA_CONSISTENT'&&value.integrityFreshnessMigrationProductionEstablished===false&&Array.isArray(value.rows)&&value.rows.length===11&&!Object.hasOwn(value,'failure')&&!Object.hasOwn(value,'cleanupFailureCode'));result.value=value;result.status='COMPLETED';}catch(_){result.errorClass=5;}
 }
 if(closed&&complete&&!timedOut&&!signalSent&&errorClass===0&&exitCode===1&&exitSignal===null&&bytes[0]<=OUT&&bytes[1]>0&&bytes[1]<=ERR){
  try{
   const data=JSON.parse(Buffer.concat(parts[0]).toString('utf8')),failure=data.failure;
   need(data.schema==='ocv.retained-clone-schema-registry-hygiene.v1'&&data.status==='INCOMPLETE'&&data.integrityFreshnessMigrationProductionEstablished===false);
   need(failure!==null&&typeof failure==='object'&&!Array.isArray(failure)&&Object.keys(failure).sort().join('|')==='code|ordinal|pathSha256|sqliteVersion|stage');
   need(Number.isInteger(failure.ordinal)&&failure.ordinal>=-1&&failure.ordinal<=10&&Number.isInteger(failure.stage)&&failure.stage>=0&&failure.stage<=11&&Number.isInteger(failure.code)&&failure.code>=0&&failure.code<=65535);
   need((failure.ordinal===-1&&failure.pathSha256===null)||(failure.ordinal>=0&&typeof failure.pathSha256==='string'&&/^[a-f0-9]{64}$/.test(failure.pathSha256)));
   need(failure.sqliteVersion===null||(typeof failure.sqliteVersion==='string'&&/^3\.[0-9]{1,3}\.[0-9]{1,3}$/.test(failure.sqliteVersion)));
   need(Buffer.concat(parts[1]).toString('utf8')===JSON.stringify(failure)+'\n');
   result.failure=failure;
  }catch(_){result.errorClass=5;}
 }
 need(Buffer.byteLength(JSON.stringify(result))<=16383);return result;
}
async function main(){
 let result;
 try{need(process.argv.length===3&&process.versions.node==='24.22.1');result=await supervise(process.argv[2],{spawn,execPath:process.execPath,now:()=>Number(process.hrtime.bigint()/1000000n),setTimer:(fn,ms)=>setTimeout(fn,ms),clearTimer:id=>clearTimeout(id),waitClose:(child,record)=>new Promise(resolve=>child.once('close',(code,signal)=>{record(code,signal);resolve();}))});}
 catch(_){result={schema:'ocv.retained-metadata-query-supervision.v1',status:'REFUSED',errorClass:6};}
 process.stdout.write(JSON.stringify(result)+'\n');if(result.status!=='COMPLETED')process.exitCode=1;
}
module.exports={supervise,QUERY_MS};
if(require.main===module)main();
