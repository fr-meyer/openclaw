// Internal lease projection; fixture-only JS signatures require production type qualification.
// Lease-only projection of the actual pinned canonical subagent row. No task runtime/writer.
import {parseTaskFlowStatus,parseOptionalTaskFlowSyncMode} from './task-flow-registry.types.js';
import {rowToSubagentRunRecord} from '../../agents/subagents/registry/subagent-registry.store.codec.js';
export function readTaskFlowRecord(db,flowId){
 const row=db.prepare('SELECT flow_id,sync_mode,shape,owner_key,controller_id,revision,status,cancel_requested_at,ended_at,updated_at FROM flow_runs WHERE flow_id=?').get(flowId);
 if(!row)return undefined;
 const syncMode=parseOptionalTaskFlowSyncMode(row.sync_mode)??(row.shape==='single_task'?'task_mirrored':'managed');
 return {flowId:row.flow_id,syncMode,ownerKey:row.owner_key,controllerId:row.controller_id??undefined,revision:row.revision,
 status:parseTaskFlowStatus(row.status),updatedAt:row.updated_at,cancelRequestedAt:row.cancel_requested_at??undefined,endedAt:row.ended_at??undefined};
}
export function readTaskRecord(db,taskId){
 if(!/^taskflow:[0-9a-f]{64}$/.test(taskId))return undefined;
 const row=db.prepare('SELECT * FROM subagent_runs WHERE run_id=?').get(taskId);if(!row)return undefined;
 const entry=rowToSubagentRunRecord(row);if(!entry||entry.taskRunId!==taskId||entry.runId!==taskId)return undefined;
 const lease=db.prepare('SELECT * FROM task_flow_worker_leases WHERE attempt_key=?').get(taskId.slice(9));
 if(!lease||entry.execution.lifecycleGeneration!==lease.owner_generation)return undefined;
 const binding=db.prepare('SELECT * FROM task_flow_native_bindings WHERE lease_id=?').get(lease.lease_id);
 if(!binding||binding.run_id!==taskId||binding.child_session_key!==entry.childSessionKey||binding.requester_session_key!==entry.requesterSessionKey||binding.entry_generation!==entry.generation||binding.owner_generation!==lease.owner_generation||binding.fencing_token!==lease.fencing_token)return undefined;
 let status,endedAt;
 if(['queued','running'].includes(entry.execution.status)&&entry.execution.endedAt===undefined)status=entry.execution.status;
 else if(entry.execution.status==='terminal'&&Number.isFinite(entry.execution.endedAt)&&entry.execution.outcome?.status==='ok'&&entry.execution.outcome?.reason==='completed'){
  status='succeeded';endedAt=entry.execution.endedAt;
 }else return undefined; // Interrupted, unknown and malformed terminal states never count as dead/drained.
 return {taskId,runId:taskId,sourceId:taskId,runtime:'subagent',childSessionKey:entry.childSessionKey,status,endedAt,
  terminalOutcome:status==='succeeded'?'completed':undefined,error:entry.execution.outcome?.error};
}
