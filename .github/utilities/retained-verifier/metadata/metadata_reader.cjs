'use strict';
// Fixed retained-clone metadata adapter of production_schema_inventory.py.
// It issues no grant and cannot enforce a hard deadline inside synchronous
// SQLite. The source-bound controller must own the60s capture/120s action.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto');
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const SQL = Object.freeze({
  only: 'PRAGMA query_only=ON', trusted: 'PRAGMA trusted_schema=OFF',
  onlyRead: 'PRAGMA query_only', trustedRead: 'PRAGMA trusted_schema',
  version: 'SELECT sqlite_version() AS version', uv: 'PRAGMA main.user_version',
  tables: 'PRAGMA main.table_list',
  catalog: 'SELECT type FROM main.sqlite_schema LIMIT 513',
  schema: "SELECT role,schema_version,agent_id,app_version FROM main.schema_meta WHERE meta_key='primary' LIMIT 2",
  registry: 'SELECT agent_id,substr(path,1,1025) AS path,schema_version FROM main.agent_databases LIMIT 257',
  deletion: 'SELECT agent_id,substr(agent_dir,1,1025) AS agent_dir,substr(database_paths_json,1,65537) AS paths,cleanup_completed,delete_files FROM main.agent_deletion_journal LIMIT 257',
  held: "SELECT substr(report_json,1,65537) AS report FROM main.migration_sources WHERE source_key='agent-deletion-journal-reconstruction' LIMIT 2"
});
const COLS = Object.freeze({
  sqlite_master: ['name','type'], sqlite_schema: ['name','type'],
  schema_meta: ['meta_key','role','schema_version','agent_id','app_version'],
  agent_databases: ['agent_id','path','schema_version'],
  agent_deletion_journal: ['agent_id','agent_dir','database_paths_json','cleanup_completed','delete_files'],
  migration_sources: ['source_key','report_json']
});
class Refused extends Error { constructor(code) { super('metadata_refused'); this.metadataCode=code; } }
function need(value,code) { if (value !== true) throw new Refused(code); }
function fields(value,keys) { return value!==null && typeof value==='object' && !Array.isArray(value) && Object.keys(value).sort().join('|')===keys.slice().sort().join('|'); }
function identity(st) { return ['dev','ino','size','uid','gid','nlink','mode','mtimeNs','ctimeNs'].map(key=>String(st[key])).join(':'); }
function pin(st) { return Object.fromEntries(['dev','ino','size','uid','gid','nlink','mode','mtimeNs','ctimeNs'].map(key=>[key,String(st[key])])); }
function validPin(value) { return fields(value,['dev','ino','size','uid','gid','nlink','mode','mtimeNs','ctimeNs']) && Object.values(value).every(v=>typeof v==='string' && /^(0|[1-9][0-9]{0,19})$/.test(v)); }
function validateProfile(p) {
  need(fields(p,['schema','sourceSha','indexDigest','platformDigest','configDigest','grantSha256','dataset','rows','admission']),100);
  need(p.schema==='ocv.retained-clone-metadata-profile.v1' && /^[a-f0-9]{40}$/.test(p.sourceSha) && /^[a-f0-9]{64}$/.test(p.grantSha256),100);
  need(['indexDigest','platformDigest','configDigest'].every(k=>/^sha256:[a-f0-9]{64}$/.test(p[k])),100);
  need(fields(p.dataset,['testDiskId','filesystemUuid','sourceSnapshotId']) && Object.values(p.dataset).every(v=>typeof v==='string' && v.length>0 && v.length<=80),100);
  need(fields(p.admission,['ownerSessionId','vmId','bootId','sourceOwnerProofSha256','readOnlyMountsVerified','noWritersVerified','exactDatasetVerified','controllerHardQuerySeconds','controllerWholeActionSeconds','noRetry','established']),101);
  const a=p.admission;
  need(a.established===true && a.readOnlyMountsVerified===true && a.noWritersVerified===true && a.exactDatasetVerified===true && a.noRetry===true && a.controllerHardQuerySeconds===60 && a.controllerWholeActionSeconds===120,101);
  need(/^[a-f0-9]{32}$/.test(a.ownerSessionId) && /^[a-f0-9]{64}$/.test(a.sourceOwnerProofSha256) && /^[0-9]{1,20}$/.test(a.vmId) && /^[a-f0-9-]{36}$/.test(a.bootId),101);
  need(Array.isArray(p.rows) && p.rows.length===11,102);
  const paths=new Set(), agents=new Set();
  p.rows.forEach((r,n)=>{
    need(fields(r,['ordinal','relativePath','pathSha256','role','agentId','files']) && r.ordinal===n && typeof r.relativePath==='string',102);
    need((n===0 && r.role==='global' && r.agentId===null && r.relativePath==='state/openclaw.sqlite') || (n>0 && r.role==='agent' && typeof r.agentId==='string' && /^[a-z0-9][a-z0-9_-]{0,127}$/.test(r.agentId) && r.relativePath==='agents/'+r.agentId+'/agent/openclaw-agent.sqlite'),102);
    need(r.pathSha256===hash(r.relativePath) && !paths.has(r.relativePath),102);paths.add(r.relativePath);
    if(n>0){need(!agents.has(r.agentId),102);agents.add(r.agentId);}
    need(fields(r.files,['main','wal','shm','journal']) && validPin(r.files.main),103);
    for(const k of ['wal','shm','journal'])need(fields(r.files[k],['state','identity']) && ((r.files[k].state==='absent' && r.files[k].identity===null)||(r.files[k].state==='present' && validPin(r.files[k].identity))),103);
    need(r.files.journal.state==='absent' && r.files.wal.state===r.files.shm.state,103);
    if(r.files.wal.state==='present')need(BigInt(r.files.wal.identity.size)>=32n && BigInt(r.files.shm.identity.size)>0n,103);
  });
  return p;
}
function target(row,key) { return '/metadata/db-'+String(row.ordinal).padStart(2,'0')+'/main.sqlite'+({main:'',wal:'-wal',shm:'-shm',journal:'-journal'}[key]); }
function authorizer(constants,global) {
  return (action,a,b,db,origin)=>{
    if(origin!==null)return constants.SQLITE_DENY;
    if(action===constants.SQLITE_SELECT)return constants.SQLITE_OK;
    if(action===constants.SQLITE_READ && db==='main' && Object.hasOwn(COLS,a) && COLS[a].includes(b) && (global || ['sqlite_master','sqlite_schema','schema_meta'].includes(a)))return constants.SQLITE_OK;
    if(action===constants.SQLITE_FUNCTION && a===null && ['substr','sqlite_version'].includes(b))return constants.SQLITE_OK;
    if(action===constants.SQLITE_PRAGMA && (db===null||db==='main') && ((a==='query_only'&&(b===null||b==='ON'))||(a==='trusted_schema'&&(b===null||b==='OFF'))||(['user_version','table_list'].includes(a)&&b===null)))return constants.SQLITE_OK;
    return constants.SQLITE_DENY;
  };
}
function collect(profile,io) {
  const p=validateProfile(profile);need(io.nodeVersion==='24.22.1' && Number.isInteger(io.uid) && io.uid>0 && Number.isInteger(io.gid) && io.gid>=0,104);
  const files=new Map(), held=[], result={schema:'ocv.retained-clone-schema-registry-hygiene.v1',status:'INCOMPLETE',sqliteVersion:null,rows:[],integrityFreshnessMigrationProductionEstablished:false};
  let ordinal=-1,stage=0;
  const end=io.now()+60000;
  const tick=()=>need(io.now()<end,105);
  function stat(name) { return io.fs.lstatSync(name,{bigint:true}); }
  function checkFile(name,expected) {
    const before=stat(name);need(before.isFile()&&!before.isSymbolicLink() && before.uid===BigInt(io.uid) && before.gid===BigInt(io.gid) && before.nlink===1n && (before.mode&0o022n)===0n && identity(before)===identity(expected),110);
    const fd=io.fs.openSync(name,io.fs.constants.O_RDONLY|io.fs.constants.O_NOFOLLOW|io.fs.constants.O_NONBLOCK);
    held.push(fd);const opened=io.fs.fstatSync(fd,{bigint:true});need(identity(opened)===identity(before),110);files.set(name,{fd,pin:identity(before)});
  }
  function expectedSt(v) { return Object.fromEntries(Object.entries(v).map(([k,x])=>[k,BigInt(x)])); }
  function fsRecheck() { for(const [name,item]of files)need(identity(io.fs.fstatSync(item.fd,{bigint:true}))===item.pin && identity(stat(name))===item.pin,111); }
  function mounts() {
    const text=io.fs.readFileSync('/proc/self/mountinfo','utf8');need(Buffer.byteLength(text)<=262144,112);
    const wanted=new Set();
    for(const r of p.rows)for(const k of ['main','wal','shm'])if(k==='main'||r.files[k].state==='present')wanted.add(target(r,k));
    const found=[];
    for(const line of text.split('\n')){
      const f=line.split(' ');if(f.length<7)continue;const name=f[4];
      if(name==='/metadata'||name.startsWith('/metadata/')){need(wanted.has(name)&&f[5].split(',').includes('ro')&&/^[1-9][0-9]*$/.test(f[0]),112);found.push(f.slice(0,6).join(' '));wanted.delete(name);}
    }
    need(wanted.size===0,112);return found.sort().join('\n');
  }
  function query(db,key,cap=256) {
    tick();need(Object.hasOwn(SQL,key),120);const s=db.prepare(SQL[key]);const out=[];
    let primary;
    try { for(const row of s.iterate()){tick();need(out.length<cap,121);out.push(row);} }
    catch(error){primary=error;throw error;}
    finally {try{s.close();}catch(error){result.cleanupFailureCode=Number.isInteger(error.errcode)?error.errcode:0;if(primary===undefined)throw error;}}
    return out;
  }
  function scalar(db,key) { const x=query(db,key,1);need(x.length===1,122);return Object.values(x[0])[0]; }
  function mapLocator(agent,locator,directory=false) {
    const row=p.rows.find(r=>r.agentId===agent);need(row!==undefined && typeof locator==='string' && locator.length<=1024,130);
    const relative=directory?row.relativePath.slice(0,row.relativePath.lastIndexOf('/')):row.relativePath;
    need(locator===relative||locator==='/home/node/.openclaw/'+relative,130);return row;
  }
  try {
    stage=1;const mountBefore=mounts();
    for(const r of p.rows){
      ordinal=r.ordinal;stage=2;tick();
      const directory='/metadata/db-'+String(ordinal).padStart(2,'0');
      for(const d of ['/metadata',directory]){const s=stat(d);need(s.isDirectory()&&!s.isSymbolicLink()&&s.uid===0n&&s.gid===0n&&(s.mode&0o022n)===0n&&io.fs.realpathSync(d)===d,113);}
      for(const k of ['main','wal','shm','journal']){
        const name=target(r,k);
        if(k==='main'||r.files[k].state==='present')checkFile(name,expectedSt(k==='main'?r.files.main:r.files[k].identity));
        else {let absent=false;try{stat(name);}catch(e){if(e.code==='ENOENT')absent=true;else throw e;}need(absent,114);}
      }
    }
    for(const r of p.rows){
      ordinal=r.ordinal;stage=3;tick();let db,primary;
      try {
        db=new io.DatabaseSync(target(r,'main'),{readOnly:true,allowExtension:false,enableForeignKeyConstraints:false,enableDoubleQuotedStringLiterals:false,timeout:0,defensive:true,limits:{length:262144,sqlLength:4096,attach:0}});
        need(typeof db.setAuthorizer==='function'&&typeof db.enableLoadExtension==='function',123);
        db.setAuthorizer(authorizer(io.constants,r.role==='global'));db.enableLoadExtension(false);
        stage=4;db.exec(SQL.only);db.exec(SQL.trusted);need(scalar(db,'onlyRead')===1&&scalar(db,'trustedRead')===0,124);
        const version=scalar(db,'version');need(typeof version==='string'&&/^3\.[0-9]{1,3}\.[0-9]{1,3}$/.test(version),125);
        if(result.sqliteVersion===null)result.sqliteVersion=version;need(result.sqliteVersion===version,125);
        stage=5;const objects=query(db,'catalog',512);const counts={table:0,index:0,view:0,trigger:0};
        for(const row of objects){need(Object.hasOwn(counts,row.type),126);counts[row.type]++;}
        const tables=query(db,'tables',512);const required=r.role==='global'?['schema_meta','agent_databases','agent_deletion_journal','migration_sources']:['schema_meta'];
        for(const name of required){const t=tables.filter(t=>t.schema==='main'&&t.name===name);need(t.length===1&&t[0].type==='table'&&t[0].strict===1,127);}
        stage=6;const uv=scalar(db,'uv'), values=query(db,'schema',2);need(values.length===1,128);const s=values[0],expected=r.role==='global'?20:25;
        need(s.role===r.role&&s.schema_version===expected&&uv===expected&&s.agent_id===r.agentId&&s.app_version==='2026.10.5',129);
        const hygiene={registryRows:0,deletionRows:0,heldRows:0};
        if(r.role==='global'){
          stage=7;const registry=query(db,'registry');hygiene.registryRows=registry.length;const registered=new Set();
          for(const x of registry){mapLocator(x.agent_id,x.path);need(x.schema_version===25&&!registered.has(x.agent_id),130);registered.add(x.agent_id);}
          need(registered.size===10&&p.rows.slice(1).every(x=>registered.has(x.agentId)),130);
          stage=8;const deletions=query(db,'deletion');hygiene.deletionRows=deletions.length;
          for(const x of deletions){
            need(typeof x.agent_id==='string'&&/^[a-z0-9][a-z0-9_-]{0,127}$/.test(x.agent_id)&&x.cleanup_completed===1&&x.delete_files===1,131);
            const directory='agents/'+x.agent_id+'/agent',database=directory+'/openclaw-agent.sqlite';
            need(typeof x.agent_dir==='string'&&[directory,'/home/node/.openclaw/'+directory,'/home/frmeyer/.openclaw/'+directory].includes(x.agent_dir),131);
            need(typeof x.paths==='string'&&Buffer.byteLength(x.paths)<=65536,131);
            const paths=JSON.parse(x.paths);need(Array.isArray(paths)&&paths.length<=256&&new Set(paths).size===paths.length,131);
            for(const value of paths)need(typeof value==='string'&&[database,'/home/node/.openclaw/'+database,'/home/frmeyer/.openclaw/'+database].includes(value),131);
          }
          const reports=query(db,'held',1);
          if(reports.length){const raw=reports[0].report;need(typeof raw==='string'&&Buffer.byteLength(raw)<=65536,132);const h=JSON.parse(raw);need(h!==null&&typeof h==='object'&&!Array.isArray(h)&&Array.isArray(h.held)&&h.held.length===0,132);hygiene.heldRows=h.held.length;}
        }
        result.rows.push({ordinal:r.ordinal,pathSha256:r.pathSha256,role:r.role,userVersion:uv,schemaVersion:s.schema_version,appVersionMatches:true,ownerMatches:true,catalogCounts:counts,hygiene});
      } catch(error) { primary=error;throw error; } finally {
        if(db!==undefined)try{db.close();}catch(error){result.cleanupFailureCode=Number.isInteger(error.errcode)?error.errcode:0;if(primary===undefined){stage=10;throw error;}}
      }
    }
    stage=9;fsRecheck();need(mounts()===mountBefore,112);result.status='METADATA_CONSISTENT';
  } catch(error) {
    const code=Number.isInteger(error.metadataCode)?error.metadataCode:(Number.isInteger(error.errcode)&&error.errcode>=0&&error.errcode<=65535?error.errcode:0);
    result.failure={ordinal,pathSha256:ordinal>=0?p.rows[ordinal].pathSha256:null,stage,code,sqliteVersion:result.sqliteVersion};
  } finally {for(const fd of held)try{io.fs.closeSync(fd);}catch(error){result.cleanupFailureCode=0;result.status='INCOMPLETE';if(result.failure===undefined)result.failure={ordinal,pathSha256:ordinal>=0?p.rows[ordinal].pathSha256:null,stage:11,code:0,sqliteVersion:result.sqliteVersion};}}
  need(Buffer.byteLength(JSON.stringify(result))<=16384,140);return result;
}
function main() {
  let result;
  try {
    need(process.argv.length===3&&/^[a-f0-9]{64}$/.test(process.argv[2]),100);
    const raw=readProfile(fs,process.argv[2]);
    const profile=JSON.parse(raw);validateProfile(profile);need(process.versions.node==='24.22.1',104);
    const sqlite=require('node:sqlite');
    result=collect(profile,{fs,DatabaseSync:sqlite.DatabaseSync,constants:sqlite.constants,nodeVersion:process.versions.node,uid:process.getuid(),gid:process.getgid(),now:()=>Number(process.hrtime.bigint()/1000000n)});
  } catch(error) {result={schema:'ocv.retained-clone-schema-registry-hygiene.v1',status:'INCOMPLETE',rows:[],failure:{ordinal:-1,pathSha256:null,stage:0,code:Number.isInteger(error.metadataCode)?error.metadataCode:0,sqliteVersion:null},integrityFreshnessMigrationProductionEstablished:false};}
  const raw=JSON.stringify(result);need(Buffer.byteLength(raw)<=16384,140);process.stdout.write(raw+'\n');
  if(result.status!=='METADATA_CONSISTENT'){const diagnostic=JSON.stringify(result.failure);need(Buffer.byteLength(diagnostic)<=4095,141);process.stderr.write(diagnostic+'\n');process.exitCode=1;}
}
function readProfile(port,pinSha) {
  const name='/run/metadata-profile.json',before=port.lstatSync(name,{bigint:true});
  need(before.isFile()&&!before.isSymbolicLink()&&before.uid===0n&&before.gid===0n&&before.nlink===1n&&before.mode===0o100444n&&before.size>0n&&before.size<=65536n,100);
  const fd=port.openSync(name,port.constants.O_RDONLY|port.constants.O_NOFOLLOW|port.constants.O_NONBLOCK);
  let raw,primary;
  try {
    need(identity(port.fstatSync(fd,{bigint:true}))===identity(before),100);
    raw=Buffer.alloc(Number(before.size)+1);let used=0;
    while(used<raw.length){const count=port.readSync(fd,raw,used,raw.length-used,null);if(count===0)break;used+=count;}
    need(used===Number(before.size)&&identity(port.fstatSync(fd,{bigint:true}))===identity(before)&&identity(port.lstatSync(name,{bigint:true}))===identity(before),100);
    raw=raw.subarray(0,used);need(hash(raw)===pinSha,100);
  } catch(error){primary=error;throw error;} finally {try{port.closeSync(fd);}catch(error){if(primary===undefined)throw error;}}
  return raw;
}
module.exports={SQL,authorizer,validateProfile,collect,readProfile};
if(require.main===module)main();
