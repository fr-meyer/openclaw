import {getActiveAgentRunDelegatedAuthority,validateAgentRunDelegatedAuthority} from "../infra/agent-run-registry.js";
import type {AgentRunDelegatedAuthority} from "../infra/agent-run-authority.types.js";
import {assertPrivateTaskFlowSettlementTicket} from "./private-taskflow-lifecycle.js";
/** Host-only opaque capability port. Every operation uses the canonical native shared-state actor. */
import {randomUUID} from "node:crypto";
import {captureOpenClawStateWorkerContext} from "../state/openclaw-state-worker-context.js";
import {runOpenClawStateWorkerOperation} from "../state/openclaw-state-worker-store.js";
import {createSqliteWorkerOperationAdmission} from "../infra/sqlite-worker-operation-admission.js";
import {hasSqliteWorkerOutcomeUnknown} from "../infra/sqlite-worker-contract.js";
import {SubagentRegistryWriteError,withSubagentRegistryWriteAuthority,assertSubagentRegistryWriteSourceCurrent} from "../agents/subagents/registry/subagent-registry-persistence.js";
import type {AcquireTaskFlowWorkerLeaseInput} from "../state/private-taskflow/task-flow-worker-lease.types.js";
import type {PrivateOwner,PrivateLeaseBinding} from "../state/private-taskflow/private-worker-contract.js";
import type {PrivateTaskFlowHost} from "./private-taskflow-lifecycle.js";
export function createPrivateTaskFlowHostAdapter(options:{
 owner:PrivateOwner;stateDir:string;gatewayContext:PrivateTaskFlowHost["gatewayContext"];
 assertCurrent():void;now():number;
}){
 const owner=Object.freeze({...options.owner});const sourceGuard=options.assertCurrent;const clock=options.now;
 const state=captureOpenClawStateWorkerContext({env:{...process.env,OPENCLAW_STATE_DIR:options.stateDir}});
 const capabilities=new WeakMap<object,{lease:PrivateLeaseBinding;binding:ReturnType<PrivateTaskFlowHost["binding"]>;execution?:{instance:AgentRunDelegatedAuthority["operationalRunInstance"];authority:AgentRunDelegatedAuthority;releaseIssued:boolean}}> ();
 const lookup=(cap:object)=>{sourceGuard();state.admission.assertCurrent();const value=capabilities.get(cap);if(!value)throw new Error("PRIVATE_OPAQUE_CAPABILITY_REQUIRED");return value;};
 async function write(type:string,value:unknown,guard:()=>void){
  const writeId=randomUUID();let stage="waiting",commitGranted=false,acknowledged=false;
  const assertCurrent=()=>{sourceGuard();assertSubagentRegistryWriteSourceCurrent(state);guard();};assertCurrent();
  try{
   const receipt=await runOpenClawStateWorkerOperation(state,scope=>scope.execute({type,input:{writeId,owner,value}} as never),{
    existingOnly:true,assertCurrent,createAdmission:()=>({nativeLocations:[state.admission.databasePath,state.admission.identity.canonicalPath],
     admission:createSqliteWorkerOperationAdmission((request,grant)=>{
      if(request.facts!==writeId||!((stage==="waiting"&&request.stage==="transaction")||(stage==="transaction"&&request.stage==="commit")))
       throw new Error("PRIVATE_NATIVE_ADMISSION_ORDER_REFUSED");
      assertCurrent();if(!grant())throw new Error("PRIVATE_NATIVE_ADMISSION_EXPIRED");stage=request.stage;commitGranted=stage==="commit";
     })}),
   }) as {writeId:string;result:any}|undefined;
   if(!receipt||receipt.writeId!==writeId)throw new Error("PRIVATE_NATIVE_ACK_IDENTITY_REFUSED");acknowledged=true;assertCurrent();return receipt.result;
  }catch(error){throw new SubagentRegistryWriteError(acknowledged?"committed":commitGranted||hasSqliteWorkerOutcomeUnknown(error)?"unknown":"not-committed",error,acknowledged?"superseded":undefined);}
 }
 const host:PrivateTaskFlowHost=Object.freeze({
  gatewayContext:options.gatewayContext,binding:cap=>lookup(cap).binding,assertCurrent:cap=>{lookup(cap);},
  async registerCanonicalAtomically(cap,identity,entry,guard){
   const captured=lookup(cap);if(identity!==captured.binding&&JSON.stringify(identity)!==JSON.stringify(captured.binding))throw new Error("PRIVATE_BINDING_CHANGED");
   return withSubagentRegistryWriteAuthority([identity.runId],{context:state,assertCurrent:guard},authority=>
    write("taskflow.private.register",{lease:captured.lease,identity,entry,nowMs:clock()},()=>{
     authority.assertCurrent();if(lookup(cap)!==captured)throw new Error("PRIVATE_CAPABILITY_CHANGED");guard();
    }));
  },
  attachNativeExecution(cap,instance,authority){
   const captured=lookup(cap);
   if(!authority||authority.operationalRunInstance!==instance||authority.lifecycleGeneration!==owner.generation||
    getActiveAgentRunDelegatedAuthority(authority.operationalRunInstance)!==authority||!validateAgentRunDelegatedAuthority(authority as AgentRunDelegatedAuthority))
    throw new Error("PRIVATE_ACTUAL_NATIVE_EXECUTION_REQUIRED");
   if(captured.execution)throw new Error("PRIVATE_EXECUTION_ALREADY_ATTACHED");
   captured.execution={instance:authority.operationalRunInstance,authority:authority as AgentRunDelegatedAuthority,releaseIssued:false};
  },
  async releaseNativeTerminal(cap,identity,guard,settlementTicket){
   const captured=lookup(cap);for(const key of ["runId","childSessionKey","requesterSessionKey","lifecycleGeneration"] as const)
    if(identity[key]!==captured.binding[key])throw new Error("PRIVATE_TERMINAL_IDENTITY_CHANGED");
   const execution=captured.execution;
   if(!execution||execution.instance!==identity.operationalRunInstance||execution.authority.claimId!==identity.claimId||execution.releaseIssued)
    throw new Error("PRIVATE_CAPTURED_NATIVE_EXECUTION_REQUIRED");
   const instance=execution.instance;
   const assertOwnedSettlement=()=>{
    if(lookup(cap)!==captured||captured.execution!==execution||
      getActiveAgentRunDelegatedAuthority(instance)!==execution.authority||!validateAgentRunDelegatedAuthority(execution.authority))
     throw new Error("PRIVATE_NATIVE_EXECUTION_RETIRED_OR_REPLACED");
    assertPrivateTaskFlowSettlementTicket(settlementTicket,cap,instance,execution.authority);
    guard();
   };
   assertOwnedSettlement();execution.releaseIssued=true; // Seal before await; unknown ACK cannot be replayed.
   return write("taskflow.private.release",{lease:captured.lease,identity,expectedEntryGeneration:identity.expectedEntryGeneration,
    claimId:execution.authority.claimId,instanceId:instance.instanceId,nowMs:clock()},assertOwnedSettlement);
  },
 });
 return Object.freeze({host,
  async acquire(input:AcquireTaskFlowWorkerLeaseInput,selection:{childSessionKey:string;requesterSessionKey:string;pluginId:string;provider:string;model:string}){
   const result=await write("taskflow.private.acquire",{...input,nowMs:clock()},sourceGuard);
   if(!result.acquired)return {result};
   const capability=Object.freeze(Object.create(null));const lease=result.lease;
   const binding=Object.freeze({runId:"taskflow:"+lease.attemptKey,childSessionKey:selection.childSessionKey,requesterSessionKey:selection.requesterSessionKey,
    lifecycleGeneration:owner.generation,pluginId:selection.pluginId,provider:selection.provider,model:selection.model});
   capabilities.set(capability,{binding,lease:Object.freeze({leaseId:lease.leaseId,flowId:lease.flowId,attemptKey:lease.attemptKey,fencingToken:lease.fencingToken,
    repositoryKey:lease.repositoryKey,workspaceKey:lease.workspaceKey,worktreeId:input.worktreeId!,expectedFlowRevision:lease.flowRevision})});
   return {result,capability};
  },
 });
}
