import type {SubagentRunRecord} from "../../agents/subagents/registry/subagent-registry.types.js";
import type {AcquireTaskFlowWorkerLeaseInput,AcquireTaskFlowWorkerLeaseResult} from "./task-flow-worker-lease.types.js";
export type PrivateOwner={ownerKey:string;holderId:string;generation:string};
export type PrivateLeaseBinding={leaseId:string;flowId:string;attemptKey:string;fencingToken:number;repositoryKey:string;workspaceKey:string;worktreeId:string;expectedFlowRevision:number};
export type PrivateWrite<T>={writeId:string;owner:PrivateOwner;value:T};
export type PrivateCanonicalIdentity={runId:string;childSessionKey:string;requesterSessionKey:string;lifecycleGeneration:string};
export type PrivateTaskFlowWorkerOperations={
 "taskflow.private.acquire":{input:PrivateWrite<AcquireTaskFlowWorkerLeaseInput>;output:{writeId:string;result:AcquireTaskFlowWorkerLeaseResult}};
 "taskflow.private.register":{input:PrivateWrite<{lease:PrivateLeaseBinding;identity:PrivateCanonicalIdentity;entry:SubagentRunRecord;nowMs:number}>;output:{writeId:string;result:{bound:boolean;entryGeneration:number}}};
 "taskflow.private.release":{input:PrivateWrite<{lease:PrivateLeaseBinding;identity:PrivateCanonicalIdentity;expectedEntryGeneration:number;claimId:string;instanceId:string;nowMs:number}>;output:{writeId:string;result:{released:boolean}}};
};
