'use strict';
// Synthetic-only persisted schema initialization witness. Exact reader limits,
// SQL and authorizer stay unchanged; no retained paths, profile or data appear.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const {DatabaseSync,constants}=require('node:sqlite');
const reader=require('./metadata_reader.cjs');
assert.equal(process.versions.node,'24.22.1');
const LIMITS=Object.freeze({length:262144,sqlLength:8192,attach:0});
const OPTIONS=Object.freeze({readOnly:true,allowExtension:false,enableForeignKeyConstraints:false,
 enableDoubleQuotedStringLiterals:false,timeout:0,defensive:true,limits:LIMITS});
const LONG='CREATE TABLE synthetic_long ('+Array.from({length:320},(_,i)=>'column_'+String(i).padStart(3,'0')+' TEXT').join(',')+') STRICT;';
const ABOVE='CREATE TABLE synthetic_above ('+Array.from({length:640},(_,i)=>'column_'+String(i).padStart(3,'0')+' TEXT').join(',')+') STRICT;';
const CASES=Object.freeze([
 ['small',''],
 ['long',''+LONG],
 ['public_table',null],
 ['generated_function','CREATE TABLE synthetic_generated(source TEXT,derived TEXT GENERATED ALWAYS AS (lower(source)) VIRTUAL) STRICT;'],
 ['expression_index','CREATE TABLE synthetic_expression(document TEXT) STRICT;CREATE INDEX synthetic_expression_idx ON synthetic_expression(json_extract(document,\'$.synthetic\'));']
]);
function build(root){
 fs.mkdirSync(root,{mode:0o755});
 const publicSql=fs.readFileSync(path.join(__dirname,'source_table.sql'),'utf8');
 assert.ok(Buffer.byteLength(LONG)>4096&&Buffer.byteLength(LONG)<=8192&&Buffer.byteLength(publicSql)>4096&&Buffer.byteLength(publicSql)<=8192&&Buffer.byteLength(ABOVE)>8192&&Buffer.byteLength(ABOVE)<=16384);
 for(const [name,sql]of [...CASES,['above_limit',ABOVE]]){
  const file=path.join(root,name+'.sqlite'),db=new DatabaseSync(file,{allowExtension:false});
  try{require('./linux_fixture.cjs').schema(db,0);if(sql===null)db.exec(publicSql);else if(sql)db.exec(sql);}finally{db.close();}
  fs.chmodSync(file,0o600);fs.chownSync(file,1000,1000);
 }
}
function kind(error){return Number.isInteger(error.errcode)?1:error instanceof assert.AssertionError?2:error instanceof TypeError?3:4;}
function number(error){return Number.isInteger(error.errcode)&&error.errcode>=0&&error.errcode<=65535?error.errcode:0;}
function probe(file,name,versionState){
 let db,primitive=0,failure=null,closed=false,callbacks=0;
 let statementCloseFailureCode=null,databaseCloseFailureCode=null,versionValidated=false;
 const denied=[];
 try{
  primitive=1;db=new DatabaseSync(file,OPTIONS);
  primitive=2;const check=reader.authorizer(constants,true);
  db.setAuthorizer((...args)=>{
   callbacks++;assert.ok(callbacks<=4096);
   const value=check(...args);
   if(value!==constants.SQLITE_OK&&denied.length<32)denied.push({action:args[0],functionCode:args[0]===constants.SQLITE_FUNCTION?(args[2]==='lower'?1:args[2]==='json_extract'?2:0):0});
   return value;
  });
  primitive=3;db.enableLoadExtension(false);
  // All five operations in stage4, including the version query/validation.
  primitive=4;db.exec(reader.SQL.only);
  primitive=5;db.exec(reader.SQL.trusted);
  function scalar(key){const s=db.prepare(reader.SQL[key]),rows=[];let primary;try{for(const row of s.iterate())rows.push(row);assert.equal(rows.length,1);return Object.values(rows[0])[0];}catch(error){primary=error;throw error;}finally{try{s.close();}catch(error){statementCloseFailureCode=number(error);if(primary===undefined)throw error;}}}
  primitive=6;assert.equal(scalar('onlyRead'),1);
  primitive=7;assert.equal(scalar('trustedRead'),0);
  primitive=8;const version=scalar('version');assert.ok(typeof version==='string'&&/^3\.[0-9]{1,3}\.[0-9]{1,3}$/.test(version));if(versionState.value===null)versionState.value=version;assert.equal(versionState.value,version);versionValidated=true;
 }catch(error){failure={primitive,code:number(error),kind:kind(error)};}
 finally{if(db!==undefined){try{db.close();closed=true;}catch(error){databaseCloseFailureCode=number(error);failure=failure||{primitive:9,code:number(error),kind:kind(error)};}}}
 return {name,initializationPassed:failure===null,failure,connectionReturned:db!==undefined,connectionClosed:closed,statementCloseFailureCode,databaseCloseFailureCode,versionValidated,authorizerCallbacks:callbacks,denied};
}
function deny(file){
 const db=new DatabaseSync(file,OPTIONS);let denials=0;
 try{
  db.setAuthorizer(reader.authorizer(constants,true));db.enableLoadExtension(false);db.exec(reader.SQL.only);db.exec(reader.SQL.trusted);
  for(const sql of ['SELECT secret FROM app_records','UPDATE schema_meta SET schema_version=21','ATTACH DATABASE \'/tmp/not-permitted\' AS other','PRAGMA writable_schema=ON','PRAGMA query_only=OFF','PRAGMA trusted_schema=ON','SELECT load_extension(\'not-permitted\')']){
   assert.throws(()=>db.prepare(sql));denials++;
  }
 }finally{db.close();}
 return denials;
}
function run(root){
 assert.equal(process.getuid(),1000);assert.equal(process.getgid(),1000);
 // The root-verified fixed closure is copied beneath owned /tmp work0755.
 // Prove reader1000 can traverse/read it, without changing checkout ancestors.
 for(const name of ['schema_init_probe.cjs','metadata_reader.cjs','linux_fixture.cjs','source_table.sql']){
  const file=path.join(__dirname,name),st=fs.lstatSync(file);assert.ok(st.isFile()&&!st.isSymbolicLink());
  assert.equal(st.uid,0);assert.equal(st.gid,0);assert.equal(st.nlink,1);assert.equal(st.mode&0o777,0o444);
  fs.accessSync(file,fs.constants.R_OK);assert.equal(fs.realpathSync(file),file);assert.ok(fs.readFileSync(file).length>0);
 }
 const versionState={value:null};
 const rows=CASES.map(([name])=>probe(path.join(root,name+'.sqlite'),name,versionState));
 const above=probe(path.join(root,'above_limit.sqlite'),'above_limit',versionState);
 let denials=0,negativeCheckFailureCode=null;
 try{denials=deny(path.join(root,'small.sqlite'));}catch(error){negativeCheckFailureCode=number(error);}
 const result={schema:'ocv.synthetic-sqlite-schema-init-witness.v1',nodeVersion:process.versions.node,
  sqliteVersion:process.versions.sqlite,limits:LIMITS,readonly:true,extensionsDisabled:true,
  authorizerUnchanged:true,sourceCopiesReadableByReader:true,sourceReaderSha256:require('node:crypto').createHash('sha256').update(fs.readFileSync(path.join(__dirname,'metadata_reader.cjs'))).digest('hex'),
  publicSourceCreateBytes:fs.statSync(path.join(__dirname,'source_table.sql')).size,
  syntheticLongCreateBytes:Buffer.byteLength(LONG),aboveLimitCreateBytes:Buffer.byteLength(ABOVE),aboveLimit:above,fixedPrimitiveIds:[1,2,3,4,5,6,7,8,9],cases:rows,
  exactReadonlyAuthorizerNegativeCases:denials,negativeCheckFailureCode,privateDataAccessed:false,applicationRowsReturned:false};
 const raw=JSON.stringify(result);assert.ok(Buffer.byteLength(raw)<=16384);process.stdout.write(raw+'\n');
 // Emit every case before aggregate assertions, including a constructor with
 // no returned handle. No opened handle or close failure is silently waived.
 assert.ok(rows.every(r=>r.initializationPassed&&r.versionValidated));assert.equal(negativeCheckFailureCode,null);assert.equal(denials,7);
 assert.equal(above.initializationPassed,false);assert.deepEqual(above.failure,{primitive:8,code:11,kind:1});assert.ok(above.connectionReturned&&above.connectionClosed);assert.equal(above.statementCloseFailureCode,null);assert.equal(above.databaseCloseFailureCode,null);assert.deepEqual(above.denied,[]);
 assert.ok(rows.every(r=>r.statementCloseFailureCode===null&&r.databaseCloseFailureCode===null&&
  (r.connectionReturned?r.connectionClosed:r.failure!==null&&r.failure.primitive===1)));
}
assert.equal(process.argv.length,4);
if(process.argv[2]==='build')build(process.argv[3]);else{assert.equal(process.argv[2],'run');run(process.argv[3]);}
