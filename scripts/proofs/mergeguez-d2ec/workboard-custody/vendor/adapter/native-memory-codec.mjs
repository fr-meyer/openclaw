// Isolated native in-memory SQLite codec; no source/destination path opener.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';
import {fileURLToPath} from 'node:url';
export const CONTRACT='workboard.native-descriptor-recovery.v2';
export const CORE_SOURCE_SHA256=crypto.createHash('sha256').update(fs.readFileSync(fileURLToPath(import.meta.url))).digest('hex');
const SCHEMA_PATH=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'schema.sql');
const DDL_SHA='ddf7208a4e79d53b4cde461de6c6ce32d322537069cefd5c603f835e13f2bc25';
const MAX_BYTES=64*1024*1024,MAX_ROWS=100000;
export const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
export const canonical=value=>JSON.stringify(value,(_,v)=>v&&typeof v==='object'&&!Array.isArray(v)?Object.fromEntries(Object.keys(v).sort().map(k=>[k,v[k]])):v);
const q=name=>'"'+name.replaceAll('"','""')+'"';
export class NativeCodecError extends Error{constructor(code){super(code);this.code=code;}}
const fail=code=>{throw new NativeCodecError(code);};
function schemaObjects(db) {return db.prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name").all().map(r=>[r.type,r.name,r.tbl_name,r.sql]);}
function schemaDdl() {const raw=fs.readFileSync(SCHEMA_PATH);if(sha(raw)!==DDL_SHA)fail('SCHEMA_SOURCE_CHANGED');return raw.toString();}
function expectedSchema() {const db=new DatabaseSync(':memory:');try{db.exec(schemaDdl());return schemaObjects(db);}finally{db.close();}}
function encode(v) {
  if(v===null)return {type:'null'};
  if(typeof v==='bigint')return {type:'integer',decimal:v.toString()};
  if(typeof v==='number'&&Number.isFinite(v))return {type:'real',value:v};
  if(typeof v==='string')return {type:'text',value:v};
  if(v instanceof Uint8Array)return {type:'blob',base64:Buffer.from(v).toString('base64'),bytes:v.length,sha256:sha(v)};
  fail('UNSUPPORTED_SQLITE_VALUE');
}
function decode(v) {
  if(canonical(Object.keys(v).sort())===canonical(['type'])&&v.type==='null')return null;
  if(v.type==='integer'&&/^(-?(0|[1-9][0-9]*))$/.test(v.decimal)&&Object.keys(v).length===2){const n=BigInt(v.decimal);if(n<-(1n<<63n)||n>=(1n<<63n))fail('INTEGER_RANGE');return n;}
  if(v.type==='text'&&typeof v.value==='string'&&Object.keys(v).length===2)return v.value;
  if(v.type==='real'&&typeof v.value==='number'&&Number.isFinite(v.value)&&Object.keys(v).length===2)return v.value;
  if(v.type==='blob'&&typeof v.base64==='string'&&Object.keys(v).length===4){const b=Buffer.from(v.base64,'base64');if(b.toString('base64')!==v.base64||b.length!==v.bytes||sha(b)!==v.sha256)fail('BLOB_REFERENCE_MISMATCH');return b;}
  fail('INVALID_TYPED_VALUE');
}
function rawExport(db,deadline=Infinity) {
  if(db.prepare('PRAGMA encoding').get().encoding!=='UTF-8')fail('SOURCE_ENCODING_UNSUPPORTED');
  const pragmaNumber=name=>Number(Object.values(db.prepare('PRAGMA '+name).get())[0]);
  if(pragmaNumber('page_count')*pragmaNumber('page_size')>MAX_BYTES)fail('RECOVERY_BYTE_LIMIT');
  if(canonical(schemaObjects(db))!==canonical(expectedSchema()))fail('ACTUAL_SCHEMA_MISMATCH');
  if(db.prepare('PRAGMA quick_check').all().some(r=>Object.values(r)[0]!=='ok'))fail('DATABASE_INTEGRITY_FAILED');
  const versions=db.prepare('SELECT id FROM workboard_schema_migrations').all().map(r=>r.id);
  if(!versions.includes('schema-3')||versions.some(x=>!['schema-1','schema-2','schema-3'].includes(x)))fail('SCHEMA_VERSION_MISMATCH');
  const objects=schemaObjects(db),tables={};let count=0,bytes=0;
  for(const name of objects.filter(r=>r[0]==='table').map(r=>r[1]).sort()) {
    const info=db.prepare('PRAGMA table_xinfo('+q(name)+')').all(),columns=info.map(r=>r.name);
    const textColumns=info.map((column,index)=>({column,index})).filter(({column})=>column.type==='TEXT');
    // Native text decoding can replace invalid UTF-8. Bind exported strings to
    // the original SQLite TEXT bytes before accepting any logical projection.
    const stmt=db.prepare('SELECT *'+textColumns.map(({column})=>',CAST('+q(column.name)+' AS BLOB)').join('')+' FROM '+q(name));stmt.setReadBigInts(true);stmt.setReturnArrays(true);
    const rows=[];
    for(const selected of stmt.iterate()) {
      const row=selected.slice(0,columns.length);
      for(const [ordinal,{index}]of textColumns.entries()){
        const value=row[index],bytes=selected[columns.length+ordinal];
        if(value!==null&&(!(bytes instanceof Uint8Array)||typeof value!=='string'||!Buffer.from(value,'utf8').equals(Buffer.from(bytes))))fail('LOSSY_SQLITE_TEXT');
      }
      if(++count>MAX_ROWS)fail('RECOVERY_ROW_LIMIT');if(performance.now()>deadline)fail('RECOVERY_DEADLINE');
      const value=row.map(encode);bytes+=Buffer.byteLength(canonical(value));if(bytes>MAX_BYTES)fail('RECOVERY_BYTE_LIMIT');rows.push(value);
    }
    rows.sort((a,b)=>{const x=canonical(a),y=canonical(b);return x<y?-1:x>y?1:0;});
    tables[name]={columns,rows,sha256:sha(canonical(rows))};
  }
  const scalar=p=>Object.values(db.prepare('PRAGMA '+p).get())[0];
  return {contract:CONTRACT,schemaVersion:3,schemaObjects:objects,schemaSha256:sha(canonical(objects)),
    applicationId:scalar('application_id'),userVersion:scalar('user_version'),tables};
}

function warnings(db) {
  const rows=sql=>db.prepare(sql).all();
  return {foreignKeyViolations:rows('PRAGMA foreign_key_check'),
    danglingDependencyTargets:rows('SELECT id,target_card_id FROM workboard_card_links WHERE target_card_id IS NOT NULL AND target_card_id NOT IN (SELECT id FROM workboard_cards) ORDER BY id'),
    implicitBoards:rows('SELECT id,board_id FROM workboard_cards WHERE board_id NOT IN (SELECT id FROM workboard_boards) ORDER BY id'),
    orphanBlobIds:rows('SELECT attachment_id FROM workboard_attachment_blobs WHERE attachment_id NOT IN (SELECT id FROM workboard_card_attachments) ORDER BY attachment_id'),
    missingBlobIds:rows('SELECT id FROM workboard_card_attachments WHERE id NOT IN (SELECT attachment_id FROM workboard_attachment_blobs) ORDER BY id'),
    blobSizeMismatches:rows('SELECT a.id FROM workboard_card_attachments a JOIN workboard_attachment_blobs b ON a.id=b.attachment_id WHERE a.byte_size!=length(b.content) ORDER BY a.id'),
    danglingSubscriptionReferences:rows('SELECT id,board_id,card_id FROM workboard_notification_subscriptions WHERE board_id NOT IN (SELECT id FROM workboard_boards) OR (card_id IS NOT NULL AND card_id NOT IN (SELECT id FROM workboard_cards)) ORDER BY id')};
}
function revisions(exported) {
  const table=exported.tables.workboard_cards;
  return table.rows.map(row=>({cardId:row[table.columns.indexOf('id')].value,
    updatedAt:row[table.columns.indexOf('updated_at')],rowSha256:sha(canonical(row))})).sort((a,b)=>a.cardId<b.cardId?-1:a.cardId>b.cardId?1:0);
}

export function captureOwnedDatabase(database) {
 if(!(database instanceof DatabaseSync)||!database.isOpen)fail('NATIVE_OWNER_CLOSED');
 if(database.isTransaction)fail('SOURCE_TRANSACTION_ACTIVE');
 const deadline=performance.now()+5000;database.exec('BEGIN DEFERRED');
 try {const exported=rawExport(database,deadline),diagnostics=warnings(database);database.exec('COMMIT');return {exported,diagnostics,cardRevisions:revisions(exported)};}
 catch(e){if(database.isTransaction)database.exec('ROLLBACK');throw e;}
}
export function snapshotBytes(exported) {
 const db=new DatabaseSync(':memory:',{enableForeignKeyConstraints:false});
 try{
  db.exec(schemaDdl());db.exec('BEGIN IMMEDIATE');
  for(const [name,t]of Object.entries(exported.tables)){
   const stmt=db.prepare('INSERT INTO '+q(name)+' ('+t.columns.map(q).join(',')+') VALUES ('+t.columns.map(()=>'?').join(',')+')');
   for(const row of t.rows)stmt.run(...row.map(decode));
  }
  for(const key of ['applicationId','userVersion'])if(!Number.isInteger(exported[key])||exported[key]<-2147483648||exported[key]>2147483647)fail('SQLITE_HEADER_RANGE');
  db.exec('PRAGMA application_id='+exported.applicationId);db.exec('PRAGMA user_version='+exported.userVersion);db.exec('COMMIT');
  if(canonical(rawExport(db))!==canonical(exported))fail('RESTORE_LOGICAL_MISMATCH');
  const bytes=Buffer.from(db.serialize());if(bytes.length>MAX_BYTES)fail('RECOVERY_BYTE_LIMIT');return bytes;
 }finally{db.close();}
}
export function inspectSnapshotBytes(bytes) {
 if(!(bytes instanceof Uint8Array)||bytes.length>MAX_BYTES||Buffer.from(bytes).subarray(0,16).toString('latin1')!=='SQLite format 3\0')fail('SNAPSHOT_BYTES_INVALID');
 const db=new DatabaseSync(':memory:');
 try{db.deserialize(bytes);return rawExport(db);}finally{db.close();}
}
export function verifySnapshotBytes(bytes,exported) {
 if(canonical(inspectSnapshotBytes(bytes))!==canonical(exported))fail('SNAPSHOT_EXPORT_MISMATCH');return true;
}
export const schemaDdlSha256=DDL_SHA;
