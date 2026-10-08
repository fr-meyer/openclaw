import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
const here=path.dirname(fileURLToPath(import.meta.url));
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const limit=96*1024*1024;
// Wire-only policy derived from exact v6 helper; no producer authority is granted.
const CLEANUP_CODES=new Set(["BOOTSTRAP_CLOSE_FAILED","CLEANUP_DIAGNOSTICS_TRUNCATED","CLEANUP_DIAGNOSTIC_INVALID","CLEANUP_FAILED","CUSTODY_STACK_CLOSE_FAILED","DESCRIPTOR_CLOSE_FAILED","DIRECTORY_CLOSE_FAILED","FAILURE_RECEIPT_FAILED","FILE_CLOSE_FAILED","FINALIZATION_FAILED","GIT_DIRECTORY_CLOSE_FAILED","LOCK_CLOSE_FAILED","OUTPUT_CLOSE_FAILED","PATHSPEC_CLOSE_FAILED","PATHSPEC_UNLINK_FAILED","RECEIPT_WRITE_FAILED","RESTORE_TEMP_CLEANUP_FAILED","TEMPORARY_UNLINK_FAILED"]);
function frozenCleanupCodes(value){
 if(value===undefined||value===null)return Object.freeze([]);
 if(!Array.isArray(value))return Object.freeze(['CLEANUP_DIAGNOSTIC_INVALID']);
 const result=value.slice(0,64).map(code=>typeof code==='string'&&CLEANUP_CODES.has(code)?code:'CLEANUP_DIAGNOSTIC_INVALID');
 if(value.length>64)result[63]='CLEANUP_DIAGNOSTICS_TRUNCATED';
 return Object.freeze(result);
}
const wireCode=code=>typeof code==='string'&&/^[A-Z0-9_]{1,64}$/.test(code)?code:'WORKER_OPERATION_FAILED';
function frozenDisposition(value){
 if(value===undefined)return undefined;
 if(value&&typeof value==='object'&&!Array.isArray(value)&&value.recorded===true&&['failed','indeterminate'].includes(value.state)&&Number.isSafeInteger(value.revision)&&value.revision>=1)return Object.freeze({recorded:true,state:value.state,revision:value.revision});
 if(value&&typeof value==='object'&&!Array.isArray(value)&&value.recorded===false)return Object.freeze({recorded:false,code:wireCode(value.code),cleanupCodes:frozenCleanupCodes(value.cleanupCodes)});
 return Object.freeze({recorded:false,code:'WORKER_BOOKKEEPING_INVALID',cleanupCodes:Object.freeze(['CLEANUP_DIAGNOSTIC_INVALID'])});
}
export class WorkerError extends Error{
 constructor(code,disposition,cleanupCodes){super(code);this.code=code;Object.defineProperty(this,'cleanupCodes',{value:frozenCleanupCodes(cleanupCodes),enumerable:true});const fixed=frozenDisposition(disposition);if(fixed)Object.defineProperty(this,'failureDisposition',{value:fixed,enumerable:true});}
}
const BOOTSTRAP=String.raw`
import hashlib,json,os,sys,types,resource
try:
    fd_limit=resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    if not isinstance(fd_limit,int) or not 3<=fd_limit<=1048576: raise ValueError()
    os.closerange(3,fd_limit)
    line=sys.stdin.buffer.readline(2*1024*1024+1)
    if len(line)>2*1024*1024: raise ValueError()
    capsule=json.loads(line)
    if capsule.get('synthetic') is not True or capsule.get('uid')!=os.geteuid(): raise ValueError()
    expected_names=['family_publish_io','workboard_private_custody','workboard_acceptance_ledger','workboard_private_proof_keeper','recovery_worker']
    records=capsule['modules']
    if [r['name'] for r in records]!=expected_names: raise ValueError()
    compiled=[]
    # All buffers/hash/compile checks finish before any helper executes.
    for record in records:
        source=record['source'].encode('utf-8')
        if len(source)>512*1024 or hashlib.sha256(source).hexdigest()!=record['sha256']: raise ValueError()
        filename='<sealed:'+record['name']+':'+record['sha256']+'>'
        compiled.append((record,filename,compile(source,filename,'exec')))
    for record,filename,code in compiled:
        module=types.ModuleType(record['name'])
        module.__file__=filename
        module.__source_sha256__=record['sha256']
        sys.modules[record['name']]=module
        exec(code,module.__dict__)
    sys.modules['recovery_worker'].serve(capsule['policy'])
except BaseException:
    sys.stdout.write(json.dumps({'ok':False,'code':'SEALED_WORKER_FAILED'})+'\n')
    sys.stdout.flush()
    sys.exit(1)
`;
const names=[['family_publish_io','shared/family_publish_io.py'],['workboard_private_custody','custody/workboard_private_custody.py'],
 ['workboard_acceptance_ledger','ledger/workboard_acceptance_ledger.py'],['workboard_private_proof_keeper','proof_keeper.py'],['recovery_worker','recovery_worker.py']];
function readModule(name,filename,expected) {
 const stat=fs.lstatSync(filename);if(!stat.isFile()||stat.isSymbolicLink()||stat.size>512*1024)throw new WorkerError('MODULE_FILE_INVALID');
 const fd=fs.openSync(filename,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
 try{const before=fs.fstatSync(fd);if(!before.isFile()||before.size>512*1024)throw new WorkerError('MODULE_FILE_INVALID');const bytes=Buffer.alloc(before.size);let offset=0;while(offset<bytes.length){const n=fs.readSync(fd,bytes,offset,bytes.length-offset,offset);if(!n)throw new WorkerError('MODULE_FILE_CHANGED');offset+=n;}
  const after=fs.fstatSync(fd),probe=Buffer.alloc(1);if(fs.readSync(fd,probe,0,1,offset)!==0||before.ino!==stat.ino||before.dev!==stat.dev||before.size!==after.size||before.mtimeMs!==after.mtimeMs||before.ctimeMs!==after.ctimeMs)throw new WorkerError('MODULE_FILE_CHANGED');
  const digest=sha(bytes);if(expected!==digest)throw new WorkerError('MODULE_SOURCE_BINDING_MISMATCH');return {name,sha256:digest,source:bytes.toString('utf8')};
 }finally{fs.closeSync(fd);}
}
export function workerSourceManifest() {return Object.fromEntries(names.map(([n,f])=>[n,sha(fs.readFileSync(path.join(here,f)))]));}
export class SealedPythonClient {
 constructor({python,policy,approvedModules,timeoutMs=10000}) {
  if(!path.isAbsolute(python)||policy.synthetic!==true||!approvedModules)throw new WorkerError('SYNTHETIC_WORKER_POLICY_REQUIRED');
  const modules=names.map(([n,f])=>readModule(n,path.join(here,f),approvedModules[n]));
  const capsule=JSON.stringify({synthetic:true,uid:process.geteuid(),modules,policy})+'\n';if(Buffer.byteLength(capsule)>2*1024*1024)throw new WorkerError('MODULE_CAPSULE_LIMIT');
  this.binding=Object.freeze({compiledModules:Object.freeze(Object.fromEntries(modules.map(r=>[r.name,r.sha256]))),bootstrapSha256:sha(BOOTSTRAP),
   exactCompiledModuleBytesBound:true,interpreterLoadedImageVerified:false,productionAcceptance:false});
  this.child=spawn(python,['-I','-u','-c',BOOTSTRAP],{stdio:['pipe','pipe','pipe'],env:{PATH:'/usr/bin:/bin'},cwd:here});
  this.buffer='';this.pending=null;this.queue=Promise.resolve();this.closed=false;this.timeoutMs=timeoutMs;this.next=0;this.queued=0;this.bootResponseSeen=false;this.startupFailure=null;
  this.child.stdout.setEncoding('utf8');this.child.stdout.on('data',chunk=>{
   this.buffer+=chunk;if(Buffer.byteLength(this.buffer)>limit){this.abort('WORKER_RESPONSE_LIMIT');return;}
   let end;while((end=this.buffer.indexOf('\n'))>=0){const line=this.buffer.slice(0,end);this.buffer=this.buffer.slice(end+1);const current=this.pending;
    try{const out=JSON.parse(line);
     if(out.kind==='startup-failure'){
      const fields=Object.keys(out).sort().join(',');
      if(this.bootResponseSeen||this.startupFailure||out.ok!==false||fields!=='cleanupCodes,code,kind,ok')throw Error();
      const failure=new WorkerError(wireCode(out.code),undefined,out.cleanupCodes);this.startupFailure=failure;this.closed=true;
      if(current){clearTimeout(current.timer);this.pending=null;current.reject(failure);}this.child.kill();return;
     }
     if(!current){this.abort('WORKER_UNEXPECTED_RESPONSE');return;}
     if(out.id!==current.id||typeof out.ok!=='boolean')throw Error();
     const failure=out.ok?null:new WorkerError(wireCode(out.code),out.failureDisposition,out.cleanupCodes);
     this.bootResponseSeen=true;clearTimeout(current.timer);this.pending=null;out.ok?current.resolve(out.result):current.reject(failure);
    }
    catch{this.abort('WORKER_RESPONSE_INVALID');}
   }
  });
  this.child.stderr.on('data',()=>{}); // Never expose private exception paths/content.
  this.child.stdin.on('error',()=>this.abort('WORKER_WRITE_FAILED'));
  this.child.stdout.on('error',()=>this.abort('WORKER_READ_FAILED'));
  this.child.stderr.on('error',()=>this.abort('WORKER_DIAGNOSTIC_FAILED'));
  this.child.on('error',()=>this.abort('WORKER_START_FAILED'));this.child.on('exit',()=>{this.closed=true;if(this.pending)this.abort('WORKER_EXITED');});
  this.child.stdin.write(capsule,e=>{if(e)this.abort('WORKER_WRITE_FAILED');});
 }
 abort(code){this.closed=true;if(this.pending){clearTimeout(this.pending.timer);this.pending.reject(new WorkerError(code));this.pending=null;}this.child.kill();}
 call(action,payload={},beforeSend) {
  try{payload=JSON.parse(JSON.stringify(payload));}catch{return Promise.reject(new WorkerError('WORKER_REQUEST_INVALID'));}
  if(this.queued>=8)return Promise.reject(new WorkerError('WORKER_QUEUE_LIMIT'));this.queued++;
  const task=()=>new Promise((resolve,reject)=>{
   if(this.closed){reject(this.startupFailure??new WorkerError('WORKER_CLOSED'));return;}
   try{if(beforeSend!==undefined){if(typeof beforeSend!=='function')throw new WorkerError('WORKER_ADMISSION_CALLBACK_INVALID');beforeSend();}}catch(error){reject(error);return;}
   const id=++this.next,wire=JSON.stringify({id,action,payload})+'\n';if(Buffer.byteLength(wire)>limit){reject(new WorkerError('WORKER_REQUEST_LIMIT'));return;}
   const timer=setTimeout(()=>this.abort('WORKER_OUTCOME_UNKNOWN'),this.timeoutMs);this.pending={id,resolve,reject,timer};this.child.stdin.write(wire,e=>{if(e)this.abort('WORKER_WRITE_FAILED');});
  });const result=this.queue.then(task).finally(()=>{this.queued--;});this.queue=result.catch(()=>{});return result;
 }
 close(){
  if(this.closePromise)return this.closePromise;
  this.closePromise=(async()=>{
   if(this.child.exitCode!==null||this.child.signalCode!==null)return;
   let primary;
   try{if(!this.closed){const ack=await this.call('close');if(ack?.closed!==true||ack?.ownersClosed!==true)throw new WorkerError('WORKER_CLOSE_INVALID');}}
   catch(error){primary=error;}
   this.child.stdin.end();
   try{await new Promise((resolve,reject)=>{
    if(this.child.exitCode!==null||this.child.signalCode!==null){resolve();return;}
    const timer=setTimeout(()=>{this.child.kill();reject(new WorkerError('WORKER_CLOSE_OUTCOME_UNKNOWN'));},this.timeoutMs);
    this.child.once('exit',()=>{clearTimeout(timer);resolve();});
   });}catch(error){if(!primary)primary=error;}
   this.closed=true;if(primary)throw primary;
  })();return this.closePromise;
 }
}
