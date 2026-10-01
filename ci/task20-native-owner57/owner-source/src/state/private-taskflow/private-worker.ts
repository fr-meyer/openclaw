/** Closed control-plane commands on the existing canonical shared-state actor. No executor. */
import {runOpenClawStateWriteTransaction,type OpenClawStateDatabase} from "../openclaw-state-db.js";
import {requestSqliteWorkerOperationAdmission} from "../../infra/sqlite-worker-operation-admission.js";
import {deferSqlitePostCommitPublication} from "../../infra/sqlite-post-commit.js";
import {bindSubagentRunRecord,rowToSubagentRunRecord} from "../../agents/subagents/registry/subagent-registry.store.codec.js";
import {writeSubagentRunValuesInDatabase} from "../../agents/subagents/registry/subagent-registry.store.kernel.js";
import {acquireTaskFlowWorkerLeaseInDatabase,releaseTaskFlowWorkerLeaseInDatabase} from "./task-flow-worker-lease.store.kernel.js";
import {bindTaskFlowWorkerLeaseLaunchInDatabase} from "./task-flow-worker-lease-task.kernel.js";
import {ensureTaskFlowWorkerLeaseSchema} from "./private-schema.js";
import {runSqliteReadOperationSync} from "../../infra/sqlite-schema-facts.js";
import type {PrivateTaskFlowWorkerOperations} from "./private-worker-contract.js";
type Command={ [K in keyof PrivateTaskFlowWorkerOperations]:{type:K;input:PrivateTaskFlowWorkerOperations[K]["input"]} }[keyof PrivateTaskFlowWorkerOperations];
const families=new Set(["taskflow.private.acquire","taskflow.private.register","taskflow.private.release"]);
export function isPrivateTaskFlowCommand(command:{type:string}):command is Command{return families.has(command.type);}
const refuse=(ok:unknown,reason:string):asserts ok=>{if(!ok)throw new Error(reason);};
/** Main-process admission retains the original opaque capability and validates it at both ordered stages. */
export function executePrivateTaskFlowCommand(command:Command,open:()=>OpenClawStateDatabase){
 const {owner,writeId,value}=command.input;
 refuse(typeof writeId==="string"&&writeId.length>0,"PRIVATE_WRITE_ID_REQUIRED");
 refuse(owner.ownerKey&&owner.holderId&&owner.generation,"PRIVATE_OWNER_REQUIRED");
 let committed=false;let result:unknown;
 try{
  result=runOpenClawStateWriteTransaction(database=>runSqliteReadOperationSync(database.db,()=>{
   const db=database.db;ensureTaskFlowWorkerLeaseSchema(db);
   requestSqliteWorkerOperationAdmission({stage:"transaction",facts:writeId});
   if(command.type==="taskflow.private.acquire"){
    const acquisition=command.input.value;
    refuse(acquisition.globalLimit===2,"PRIVATE_CAPACITY_MUST_REMAIN_TWO");
    result=acquireTaskFlowWorkerLeaseInDatabase(db,{...acquisition,ownerKey:owner.ownerKey,holderId:owner.holderId,ownerGeneration:owner.generation});
   }else{
    const data=command.input.value;const lease=data.lease;const identity=data.identity;
    const row=db.prepare("SELECT * FROM task_flow_worker_leases WHERE lease_id=?").get(lease.leaseId);
    refuse(row&&row.owner_key===owner.ownerKey&&row.holder_id===owner.holderId&&row.owner_generation===owner.generation&&
     row.flow_id===lease.flowId&&row.attempt_key===lease.attemptKey&&row.fencing_token===lease.fencingToken&&
     row.repository_key===lease.repositoryKey&&row.workspace_key===lease.workspaceKey,"PRIVATE_LEASE_CAS_REFUSED");
    refuse(identity.runId==="taskflow:"+lease.attemptKey&&identity.lifecycleGeneration===owner.generation,"PRIVATE_RUN_IDENTITY_REFUSED");
    const raw=db.prepare("SELECT * FROM subagent_runs WHERE run_id=?").get(identity.runId);
    if(command.type==="taskflow.private.register"){
     const entry=command.input.value.entry;
     refuse(!raw,"PRIVATE_EXISTING_CANONICAL_REPLAY_REFUSED");
     refuse(entry.runId===identity.runId&&entry.taskRunId===identity.runId&&entry.childSessionKey===identity.childSessionKey&&
      entry.requesterSessionKey===identity.requesterSessionKey&&entry.execution.lifecycleGeneration===identity.lifecycleGeneration&&
      ["queued","running"].includes(entry.execution.status)&&entry.execution.endedAt===undefined&&
      Number.isSafeInteger(entry.generation)&&entry.generation!>0,"PRIVATE_NATIVE_ENTRY_REFUSED");
     writeSubagentRunValuesInDatabase(database,[bindSubagentRunRecord(entry)]);
     db.prepare("INSERT INTO task_flow_native_bindings(lease_id,run_id,child_session_key,requester_session_key,entry_generation,owner_generation,fencing_token) VALUES(?,?,?,?,?,?,?)")
      .run(lease.leaseId,identity.runId,identity.childSessionKey,identity.requesterSessionKey,entry.generation!,owner.generation,lease.fencingToken);
     const bound=bindTaskFlowWorkerLeaseLaunchInDatabase(db,{...lease,ownerKey:owner.ownerKey,canonicalRunId:identity.runId,
      childSessionKey:identity.childSessionKey,nowMs:data.nowMs});
     refuse(bound.bound,"PRIVATE_ATOMIC_BIND_REFUSED:"+(bound.bound?"":bound.reason));
     result={bound:true,entryGeneration:entry.generation!};
    }else{
     const release=command.input.value;
     refuse(typeof release.claimId==="string"&&release.claimId.length>0&&typeof release.instanceId==="string"&&release.instanceId.length>0,"PRIVATE_NATIVE_CLAIM_REQUIRED");
     const entry=raw&&rowToSubagentRunRecord(raw as never);
     const binding=db.prepare("SELECT * FROM task_flow_native_bindings WHERE lease_id=?").get(lease.leaseId);
     refuse(binding&&binding.run_id===identity.runId&&binding.child_session_key===identity.childSessionKey&&
      binding.requester_session_key===identity.requesterSessionKey&&binding.entry_generation===release.expectedEntryGeneration&&
      binding.owner_generation===owner.generation&&binding.fencing_token===lease.fencingToken,"PRIVATE_NATIVE_BINDING_CAS_REFUSED");
     refuse(entry&&entry.runId===identity.runId&&entry.taskRunId===identity.runId&&entry.childSessionKey===identity.childSessionKey&&
      entry.requesterSessionKey===identity.requesterSessionKey&&entry.generation===release.expectedEntryGeneration&&
      entry.execution.lifecycleGeneration===owner.generation&&entry.execution.status==="terminal"&&
      Number.isFinite(entry.execution.endedAt)&&entry.execution.outcome?.status==="ok"&&entry.execution.outcome.reason==="completed",
      "PRIVATE_COMMITTED_NATIVE_TERMINAL_REQUIRED");
     // The native completion owner alone writes canonical terminal state. This command only rereads it.
     const released=releaseTaskFlowWorkerLeaseInDatabase(db,{...lease,ownerKey:owner.ownerKey,nowMs:release.nowMs});
     refuse(released.released,"PRIVATE_TERMINAL_LEASE_REFUSED:"+(released.released?"":released.reason));
     result={released:true};
    }
   }
   requestSqliteWorkerOperationAdmission({stage:"commit",facts:writeId});
   const value=result;deferSqlitePostCommitPublication(db,()=>{committed=true;});return value;
  }),{database:open()});
 }catch(error){if(!committed)throw error;}
 return {writeId,result};
}
