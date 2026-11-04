// Inert source draft. The host's separate maintenance permit owns invocation.
import fs from 'node:fs';
import crypto from 'node:crypto';
import {pathToFileURL} from 'node:url';

const SOURCE='1111111111111111111111111111111111111111';
const INDEX='sha256:2222222222222222222222222222222222222222222222222222222222222222';
const GRANT='3333333333333333333333333333333333333333333333333333333333333333';
const SOURCE_ID='synthetic-sqlite-source';
const DIR='/maintenance/copy',FILE=DIR+'/fixture.sqlite';
const MAIN_MAX=31487344640,WAL_MAX=536870912,SHM_MAX=8388608,UNIT_PAGES=4,MAX_UNITS=1024;
const PHASE_MS={before:600000,reclaim:300000,after:600000};
// Keep native JS diagnostics behind one fixed boundary, including deferred exit work.
export function outputBoundary(stdout,stderr){
 const writeOut=stdout.write.bind(stdout),writeErr=stderr.write.bind(stderr);let attempted=false;
 const sink=(...args)=>{attempted=true;const callback=args.at(-1);if(typeof callback==='function')callback();return true;};
 stdout.write=sink;stderr.write=sink;
 return{attempted:()=>attempted,writeOut,writeErr};
}
const SQL={version:'SELECT sqlite_version() AS version',source:'SELECT sqlite_source_id() AS source',tempPolicy:"SELECT sqlite_compileoption_used('TEMP_STORE=0') AS forcedFile",vec:'SELECT vec_version() AS version',user:'PRAGMA main.user_version',schema:"SELECT role,schema_version,agent_id FROM main.schema_meta WHERE meta_key='primary' LIMIT 2",pageSize:'PRAGMA main.page_size',pageCount:'PRAGMA main.page_count',freelistCount:'PRAGMA main.freelist_count',autoVacuum:'PRAGMA main.auto_vacuum',wal:'PRAGMA main.journal_mode',spill:'PRAGMA main.cache_spill',temp:'PRAGMA temp_store',mmap:'PRAGMA main.mmap_size',max:'PRAGMA main.max_page_count',quick:'PRAGMA main.quick_check'};
const hash=raw=>crypto.createHash('sha256').update(raw).digest('hex');
function fields(v,keys){return v!==null&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join('|')===keys.slice().sort().join('|');}
class Refused extends Error{constructor(code){super('native_copy_refused');this.closedCode=code;}}
function need(v,code){if(v!==true)throw new Refused(code);}
function hex(v){return typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);}
function digits(v){return typeof v==='string'&&/^(0|[1-9][0-9]{0,19})$/.test(v);}
export function validateProfile(p){
 need(fields(p,['schema','ownerSessionId','grantSha256','sourceSha','indexDigest','copyMainIdentity','sourceMainIdentity','initialMainBytes','initialPageCount','pageSize','hostPageBytes']),200);
 need(p.schema==='ocv.disposable-copy-native-profile.v1'&&/^[a-f0-9]{32}$/.test(p.ownerSessionId)&&p.grantSha256===GRANT&&p.sourceSha===SOURCE&&p.indexDigest===INDEX,200);
 const c=p.copyMainIdentity,s=p.sourceMainIdentity;
 need(fields(c,['dev','ino','uid','gid','nlink','mode'])&&Object.values(c).every(digits)&&fields(s,['dev','ino'])&&Object.values(s).every(digits),200);
 need(c.uid==='1000'&&c.gid==='1000'&&c.nlink==='1'&&c.mode===String(0o100600)&&(c.dev!==s.dev||c.ino!==s.ino),200);
 need(p.pageSize===4096&&Number.isSafeInteger(p.initialMainBytes)&&p.initialMainBytes>0&&p.initialMainBytes<=MAIN_MAX&&Number.isSafeInteger(p.initialPageCount)&&p.initialPageCount>0&&p.initialPageCount*4096===p.initialMainBytes,200);
 need(Number.isInteger(p.hostPageBytes)&&p.hostPageBytes>=4096&&p.hostPageBytes<=65536&&(p.hostPageBytes&(p.hostPageBytes-1))===0,200);
 return p;
}
function scalar(db,key){const statement=db.prepare(SQL[key]);let primary;
 try{const rows=[];for(const row of statement.iterate()){need(rows.length<1,210);rows.push(row);}need(rows.length===1&&Object.keys(rows[0]).length===1,210);return Object.values(rows[0])[0];}
 catch(error){primary=error;throw error;}finally{try{statement.close();}catch(error){if(primary===undefined)throw error;}}
}
function metrics(db,p){
 const q={pageSize:scalar(db,'pageSize'),pageCount:scalar(db,'pageCount'),freelistCount:scalar(db,'freelistCount'),autoVacuum:scalar(db,'autoVacuum')};
 need(Object.values(q).every(Number.isSafeInteger)&&q.pageSize===4096&&q.pageCount>0&&q.pageCount<=p.initialPageCount&&q.freelistCount>=0&&q.freelistCount<=q.pageCount&&q.autoVacuum===2,211);return q;
}
function owner(db){
 need(scalar(db,'user')===25,212);const statement=db.prepare(SQL.schema);let primary;
 try{const rows=[];for(const row of statement.iterate()){need(rows.length<2,212);rows.push(row);}need(rows.length===1&&fields(rows[0],['role','schema_version','agent_id'])&&rows[0].role==='agent'&&rows[0].schema_version===25&&rows[0].agent_id==='fixture-agent',212);}
 catch(error){primary=error;throw error;}finally{try{statement.close();}catch(error){if(primary===undefined)throw error;}}
}
function code(error){return Number.isInteger(error?.closedCode)?error.closedCode:Number.isInteger(error?.errcode)&&error.errcode>=0&&error.errcode<=65535?error.errcode:0;}
export async function runPhase(p,phase,pin,io){
 const started=io.started??io.now();let stage=0,db=null,maintenance=null,fd=null,closing=false,unitStage='none',failure=null;
 const result={schema:'ocv.disposable-copy-native-phase.v1',phase,status:'REFUSED',profileSha256:pin,nodeVersion:null,sqliteVersion:null,packageAdmission:{nativeOwnerAvailable:false,vecAvailable:false},schemaOwnerMatched:false,pageMetrics:null,quickCheck:null,units:0,requestedPages:0,freedPages:0,checkpointComplete:false,elapsedMilliseconds:0,failure:null};
 function tick(){need(!io.outputAttempted?.(),222);need(Number.isFinite(io.now())&&io.now()-started>=0&&(closing||io.now()-started<PHASE_MS[phase]),201);}
 function space(inFlight=false){const value=io.fs.statfsSync(DIR,{bigint:true});need(value.bsize>0n&&value.bavail>=0n&&value.bsize*value.bavail>=12884901888n+(inFlight?BigInt(WAL_MAX+SHM_MAX):0n),223);}
 function family(zero=false){
  const directory=io.fs.lstatSync(DIR,{bigint:true});need(directory.isDirectory()&&!directory.isSymbolicLink()&&directory.uid===1000n&&directory.gid===1000n&&directory.mode===0o40700n,202);
  need(io.fs.readdirSync(DIR).every(name=>['fixture.sqlite','fixture.sqlite-wal','fixture.sqlite-shm'].includes(name)),202);
  const main=io.fs.lstatSync(FILE,{bigint:true});need(main.isFile()&&!main.isSymbolicLink()&&Object.entries(p.copyMainIdentity).every(([k,v])=>String(main[k])===v)&&main.size>0n&&main.size<=BigInt(p.initialMainBytes),202);
  if(fd!==null){const held=io.fs.fstatSync(fd,{bigint:true});need(held.dev===main.dev&&held.ino===main.ino&&held.nlink===1n,202);}
  let wal=0;
  for(const [suffix,limit]of[['-wal',WAL_MAX],['-shm',SHM_MAX]]){let st;try{st=io.fs.lstatSync(FILE+suffix,{bigint:true});}catch(error){need(error.code==='ENOENT',202);continue;}need(st.isFile()&&!st.isSymbolicLink()&&st.uid===1000n&&st.gid===1000n&&st.nlink===1n&&st.mode===0o100600n&&st.size>=0n&&st.size<=BigInt(limit),202);if(suffix==='-wal')wal=Number(st.size);}
  need(!zero||wal===0,203);return wal;
 }
 function current(zero=false){tick();family(zero||phase!=='reclaim');space(zero);}
 try{
  stage=1;validateProfile(p);need(Object.hasOwn(PHASE_MS,phase)&&hex(pin)&&Number.isFinite(started),200);tick();
  stage=2;need(io.nodeVersion==='24.22.1'&&io.platform==='linux'&&io.arch==='x64'&&io.uid===1000&&io.gid===1000,204);result.nodeVersion=io.nodeVersion;family(phase!=='reclaim');space();
  fd=io.fs.openSync(FILE,io.fs.constants.O_RDONLY|io.fs.constants.O_NOFOLLOW|io.fs.constants.O_NONBLOCK);family(phase!=='reclaim');
  stage=3;const api=await io.packages();tick();need(typeof api.configure==='function'&&typeof api.loadVec==='function',205);result.packageAdmission.nativeOwnerAvailable=true;
  stage=4;db=new io.DatabaseSync('file://'+FILE+(phase==='reclaim'?'?mode=rw&vfs=unix':'?mode=ro&immutable=1&vfs=unix'),{readOnly:phase!=='reclaim',allowExtension:true,enableForeignKeyConstraints:false,enableDoubleQuotedStringLiterals:false,timeout:0,defensive:true,limits:{length:262144,sqlLength:8192,attach:0}});current();
  db.exec('PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY; PRAGMA main.cache_spill=OFF; PRAGMA main.mmap_size=0;');
  need(scalar(db,'temp')===2&&scalar(db,'tempPolicy')===0&&scalar(db,'spill')===0&&scalar(db,'mmap')===0,206);
  const version=scalar(db,'version');need(version==='3.53.4'&&scalar(db,'source')===SOURCE_ID,207);result.sqliteVersion=version;
  stage=5;const loaded=await api.loadVec({db});current();need(loaded?.ok===true&&scalar(db,'vec')==='v0.1.9',208);db.enableLoadExtension(false);result.packageAdmission.vecAvailable=true;
  stage=6;owner(db);need(phase!=='reclaim'||scalar(db,'wal')==='wal',209);result.schemaOwnerMatched=true;result.pageMetrics=metrics(db,p);
  if(phase!=='reclaim'){
   db.exec('PRAGMA query_only=ON');stage=7;current();const statement=db.prepare(SQL.quick);let count=0,primary;
   try{for(const row of statement.iterate()){current();need(count===0&&Object.keys(row).length===1&&Object.values(row)[0]==='ok',213);count++;}need(count===1,213);}
   catch(error){primary=error;throw error;}finally{try{statement.close();}catch(error){if(primary===undefined)throw error;}}
   result.quickCheck='ok';
  }else{
   stage=8;current(true);db.exec('PRAGMA main.max_page_count='+p.initialPageCount);need(scalar(db,'max')===p.initialPageCount,214);
   maintenance=api.configure(db,{databasePath:FILE,busyTimeoutMs:0,autoCheckpointPages:0,checkpointIntervalMs:0,checkpointMode:'TRUNCATE',runMaintenance:operation=>{current();return operation();},onCheckpointError:()=>{}});
   need(typeof maintenance.checkpoint==='function'&&typeof maintenance.reclaimFreePages==='function'&&typeof maintenance.stop==='function'&&typeof maintenance.close==='function',215);
   current();need(maintenance.checkpoint()===true,216);current(true);
   stage=9;
   while(result.units<MAX_UNITS&&result.requestedPages<4096&&result.pageMetrics.freelistCount>0){
    current(true);need(db.isTransaction===false,217);unitStage='preVacuum';result.units++;
    const value=maintenance.reclaimFreePages({maxPages:UNIT_PAGES,
     beforeMutation:()=>{need(['preVacuum','postCommit'].includes(unitStage),218);current(unitStage==='preVacuum');},
     onCommit:()=>{need(unitStage==='preVacuum'&&db.isTransaction===true,218);current(true);unitStage='commitPending';},
     afterCommit:()=>{need(unitStage==='commitPending'&&db.isTransaction===false,218);unitStage='postCommit';current();}});
    need(typeof value?.checkpointCompleted==='boolean'&&value.checkpointCompleted===true&&Number.isInteger(value.vacuumPasses)&&[0,1].includes(value.vacuumPasses)&&Number.isInteger(value.vacuumPagesRequested)&&value.vacuumPagesRequested>=0&&value.vacuumPagesRequested<=UNIT_PAGES,219);
    need(value.vacuumPasses===0?(unitStage==='preVacuum'&&value.vacuumPagesRequested===0):unitStage==='postCommit',219);
    need(maintenance.checkpoint()===true,216);current(true);need(db.isTransaction===false,217);unitStage='none';
    const next=metrics(db,p);need(next.pageCount<=result.pageMetrics.pageCount&&next.freelistCount<=result.pageMetrics.freelistCount,220);
    result.requestedPages+=value.vacuumPagesRequested;result.freedPages+=result.pageMetrics.freelistCount-next.freelistCount;result.pageMetrics=next;
    need(result.requestedPages<=4096&&result.freedPages<=65536,220);result.checkpointComplete=true;if(value.vacuumPasses===0)break;
   }
   need(maintenance.checkpoint()===true,216);current(true);result.checkpointComplete=true;
  }
 }catch(error){failure={stage,code:code(error)};}
 finally{
  closing=true;
  if(maintenance!==null){try{await maintenance.stop();need(maintenance.close()===true,216);}catch(error){failure??={stage:10,code:code(error)};}}
  if(db!==null){try{db.close();}catch(error){failure??={stage:10,code:code(error)};}}
  if(fd!==null){try{io.fs.closeSync(fd);}catch(error){failure??={stage:10,code:code(error)};}}
  try{family(true);space();need(!io.outputAttempted?.(),222);}catch(error){failure??={stage:10,code:code(error)};}
 }
 const elapsed=io.now()-started;result.elapsedMilliseconds=Number.isFinite(elapsed)&&elapsed>=0?Math.ceil(elapsed):null;
 if(result.elapsedMilliseconds===null||result.elapsedMilliseconds>=PHASE_MS[phase])failure??={stage:11,code:201};
 result.failure=failure;result.status=failure===null?'PASS':'REFUSED';need(Buffer.byteLength(JSON.stringify(result)+'\n')<=14336,221);return result;
}
function readProfile(pin){
 need(hex(pin),200);const file='/synthetic/profile.json',before=fs.lstatSync(file,{bigint:true});need(before.isFile()&&!before.isSymbolicLink()&&before.uid===0n&&before.gid===0n&&before.nlink===1n&&before.mode===0o100444n&&before.size>0n&&before.size<=8192n,200);
 const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);try{const held=fs.fstatSync(fd,{bigint:true});need(held.dev===before.dev&&held.ino===before.ino&&held.size===before.size&&held.mtimeNs===before.mtimeNs,200);const buffer=Buffer.alloc(8193);let length=0,n;while((n=fs.readSync(fd,buffer,length,buffer.length-length,null))!==0){length+=n;need(length<=8192,200);}const raw=buffer.subarray(0,length),after=fs.lstatSync(file,{bigint:true}),end=fs.fstatSync(fd,{bigint:true});need(raw.length===Number(before.size)&&hash(raw)===pin&&[after,end].every(s=>s.dev===before.dev&&s.ino===before.ino&&s.mode===before.mode&&s.uid===before.uid&&s.gid===before.gid&&s.nlink===1n&&s.size===before.size&&s.mtimeNs===before.mtimeNs&&s.ctimeNs===before.ctimeNs),200);return validateProfile(JSON.parse(raw));}finally{fs.closeSync(fd);}
}
async function main(){
 const now=()=>Number(process.hrtime.bigint()/1000000n),started=now(),boundary=outputBoundary(process.stdout,process.stderr);process.env.OPENCLAW_LOG_LEVEL='silent';
 let result;const phase=process.argv[3],pin=process.argv[2];
 try{need(process.argv.length===4&&Object.hasOwn(PHASE_MS,phase),200);const profile=readProfile(pin);const sqlite=await import('node:sqlite');result=await runPhase(profile,phase,pin,{fs,started,DatabaseSync:sqlite.DatabaseSync,nodeVersion:process.versions.node,platform:process.platform,arch:process.arch,uid:process.getuid(),gid:process.getgid(),now,outputAttempted:boundary.attempted,packages:async()=>{const owner=await import('/synthetic/unavailable-owner-module.mjs'),vec=await import('/synthetic/unavailable-vec-module.mjs');return{configure:owner.configureSqliteConnectionPragmas,loadVec:vec.loadSqliteVecExtension};}});}
 catch(error){result={schema:'ocv.disposable-copy-native-phase.v1',phase:Object.hasOwn(PHASE_MS,phase)?phase:null,status:'REFUSED',profileSha256:hex(pin)?pin:null,failure:{stage:0,code:code(error)}};}
 const raw=JSON.stringify(result)+'\n';need(Buffer.byteLength(raw)<=14336,221);boundary.writeOut(raw);if(result.status!=='PASS'){const diagnostic=JSON.stringify(result.failure)+'\n';need(Buffer.byteLength(diagnostic)<=4096,221);boundary.writeErr(diagnostic);process.exitCode=1;}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)await main();
