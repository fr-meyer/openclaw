'use strict';
// Synthetic CI database factory and actual SQLite authorizer refusal proof.
// No retained-clone profile, real database path or user authorization is used.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const {DatabaseSync,constants}=require('node:sqlite');
const reader=require('./metadata_reader.cjs');
assert.equal(process.versions.node,'24.22.1');
function schema(db,n){
 db.exec('CREATE TABLE schema_meta(meta_key TEXT PRIMARY KEY,role TEXT,schema_version INTEGER,agent_id TEXT,app_version TEXT) STRICT;CREATE TABLE app_records(secret TEXT) STRICT;INSERT INTO app_records VALUES(\'synthetic-application-record-must-not-appear\');');
 db.prepare('INSERT INTO schema_meta VALUES(?,?,?,?,?)').run('primary',n===0?'global':'agent',n===0?20:25,n===0?null:'synthetic-'+String(n).padStart(2,'0'),'2026.10.5');
 db.exec('PRAGMA user_version='+(n===0?20:25));
 if(n===0){
  db.exec('CREATE TABLE agent_databases(agent_id TEXT,path TEXT,schema_version INTEGER) STRICT;CREATE TABLE agent_deletion_journal(agent_id TEXT,agent_dir TEXT,database_paths_json TEXT,cleanup_completed INTEGER,delete_files INTEGER) STRICT;CREATE TABLE migration_sources(source_key TEXT,report_json TEXT) STRICT;');
  const s=db.prepare('INSERT INTO agent_databases VALUES(?,?,?)');
  for(let k=1;k<11;k++){const agent='synthetic-'+String(k).padStart(2,'0');s.run(agent,'agents/'+agent+'/agent/openclaw-agent.sqlite',25);}s.close();
 }
}
function build(root){
 fs.mkdirSync(root,{recursive:false,mode:0o700});
 for(let n=0;n<11;n++){
  const dir=path.join(root,String(n).padStart(2,'0'));fs.mkdirSync(dir,{mode:0o755});
  const name=path.join(dir,'main.sqlite'),db=new DatabaseSync(name);
  if(n===0)db.exec('PRAGMA journal_mode=WAL');schema(db,n);
  if(n===0){
   // Copy one closed synthetic point-in-time WAL image; the eventual copies
   // have no writer, and are the only files mounted to the reader namespace.
   const copies=['','-wal','-shm'].map(s=>{const to=name+s+'.copy';fs.copyFileSync(name+s,to);return[to,name+s];});
   db.close();for(const [from,to]of copies)fs.renameSync(from,to);
  }else db.close();
  for(const file of fs.readdirSync(dir)){const p=path.join(dir,file);fs.chownSync(p,1000,1000);fs.chmodSync(p,0o600);}
 }
}
function deny(){
 const db=new DatabaseSync(':memory:',{allowExtension:false,defensive:true});schema(db,0);
 db.setAuthorizer(reader.authorizer(constants,true));db.exec(reader.SQL.only);db.exec(reader.SQL.trusted);
 const allowed=db.prepare(reader.SQL.schema);assert.equal(allowed.get().schema_version,20);allowed.close();
 for(const sql of ['SELECT secret FROM app_records','UPDATE schema_meta SET schema_version=21','ATTACH DATABASE \'/tmp/not-permitted\' AS other','PRAGMA writable_schema=ON','PRAGMA query_only=OFF','PRAGMA trusted_schema=ON','SELECT load_extension(\'not-permitted\')'])assert.throws(()=>db.prepare(sql));
 db.close();process.stdout.write(JSON.stringify({sqliteVersion:require('node:sqlite').DatabaseSync?process.versions.sqlite:null,authorizerPositiveAndSevenRefusals:true,applicationRecordsReturned:false})+'\n');
}
if(process.argv.length===4&&process.argv[2]==='build')build(process.argv[3]);
else if(process.argv.length===3&&process.argv[2]==='deny')deny();
else throw Error('synthetic_fixture_arguments');
