import type { Selectable } from "kysely";
import type { DB } from "../state/openclaw-state-db.generated.js";
import {
  managedTaskFlowStatuses,
  type ManagedTaskFlowRecord,
  type ManagedTaskJson,
  type ManagedTaskRunRecord,
} from "./managed-task-flow-contract.js";

type FlowRow = Selectable<DB["flow_runs"]>;
type TaskRow = Selectable<DB["task_runs"]>;
export function required(value: string, label: string): string {
  const normalized = value.trim();
  if (!normalized) {
    throw new Error(`${label} is required`);
  }
  return normalized;
}
export function integer(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be a nonnegative safe integer`);
  }
  return value;
}
function isJson(value: unknown): value is ManagedTaskJson {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return true;
  }
  if (typeof value === "number") {
    return Number.isFinite(value);
  }
  if (Array.isArray(value)) {
    return value.every(isJson);
  }
  return (
    typeof value === "object" &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null) &&
    Object.values(value).every(isJson)
  );
}
function decodeJson(encoded: string): ManagedTaskJson {
  const value: unknown = JSON.parse(encoded);
  if (!isJson(value)) {
    throw new Error("Invalid persisted managed task JSON");
  }
  return value;
}
export function encodeJson(value: ManagedTaskJson): string {
  if (!isJson(value)) {
    throw new Error("Invalid managed task JSON");
  }
  return JSON.stringify(value);
}
export function decodeFlow(row: FlowRow): ManagedTaskFlowRecord {
  const status = managedTaskFlowStatuses.find((value) => value === row.status);
  const notifyPolicy = (["done_only", "state_changes", "silent"] as const).find(
    (value) => value === row.notify_policy,
  );
  if (row.sync_mode !== "managed" || !status || !notifyPolicy) {
    throw new Error("Invalid persisted managed task-flow state");
  }
  return {
    flowId: row.flow_id,
    syncMode: "managed",
    ownerKey: row.owner_key,
    revision: integer(row.revision, "Flow revision"),
    status,
    notifyPolicy,
    goal: row.goal,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    ...(row.controller_id === null ? {} : { controllerId: row.controller_id }),
    ...(row.current_step === null ? {} : { currentStep: row.current_step }),
    ...(row.blocked_task_id === null ? {} : { blockedTaskId: row.blocked_task_id }),
    ...(row.blocked_summary === null ? {} : { blockedSummary: row.blocked_summary }),
    ...(row.state_json === null ? {} : { stateJson: decodeJson(row.state_json) }),
    ...(row.wait_json === null ? {} : { waitJson: decodeJson(row.wait_json) }),
    ...(row.cancel_requested_at === null ? {} : { cancelRequestedAt: row.cancel_requested_at }),
    ...(row.ended_at === null ? {} : { endedAt: row.ended_at }),
  };
}
export function decodeTask(row: TaskRow): ManagedTaskRunRecord {
  return {
    observationSource: "legacy-task",
    id: row.task_id,
    runtime: row.runtime,
    ownerKey: row.owner_key,
    scopeKind: row.scope_kind,
    task: row.task,
    status: row.status,
    deliveryStatus: row.delivery_status,
    notifyPolicy: row.notify_policy,
    createdAt: row.created_at,
    ...(row.task_kind === null ? {} : { taskKind: row.task_kind }),
    ...(row.source_id === null ? {} : { sourceId: row.source_id }),
    ...(row.requester_session_key === null
      ? {}
      : { requesterSessionKey: row.requester_session_key }),
    ...(row.child_session_key === null ? {} : { childSessionKey: row.child_session_key }),
    ...(row.parent_flow_id === null ? {} : { parentFlowId: row.parent_flow_id }),
    ...(row.parent_task_id === null ? {} : { parentTaskId: row.parent_task_id }),
    ...(row.agent_id === null ? {} : { agentId: row.agent_id }),
    ...(row.requester_agent_id === null ? {} : { requesterAgentId: row.requester_agent_id }),
    ...(row.run_id === null ? {} : { runId: row.run_id }),
    ...(row.label === null ? {} : { label: row.label }),
    ...(row.started_at === null ? {} : { startedAt: row.started_at }),
    ...(row.ended_at === null ? {} : { endedAt: row.ended_at }),
    ...(row.last_event_at === null ? {} : { lastEventAt: row.last_event_at }),
    ...(row.cleanup_after === null ? {} : { cleanupAfter: row.cleanup_after }),
    ...(row.tool_use_count === null ? {} : { toolUseCount: row.tool_use_count }),
    ...(row.last_tool_name === null ? {} : { lastToolName: row.last_tool_name }),
    ...(row.error === null ? {} : { error: row.error }),
    ...(row.progress_summary === null ? {} : { progressSummary: row.progress_summary }),
    ...(row.terminal_summary === null ? {} : { terminalSummary: row.terminal_summary }),
    ...(row.terminal_outcome === null ? {} : { terminalOutcome: row.terminal_outcome }),
    ...(row.detail_json === null ? {} : { detail: decodeJson(row.detail_json) }),
  };
}

/** This is a read projection of the normal native owner, never a second task row/writer. */
