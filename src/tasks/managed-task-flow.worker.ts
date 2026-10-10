import { randomUUID } from "node:crypto";
import { isMainThread } from "node:worker_threads";
import type { Insertable, Selectable, Updateable } from "kysely";
import {
  SUBAGENT_ENDED_REASON_COMPLETE,
  SUBAGENT_ENDED_REASON_KILLED,
} from "../agents/subagents/registry/subagent-lifecycle-events.js";
import { rowToSubagentRunRecord } from "../agents/subagents/registry/subagent-registry.store.codec.js";
import type { SubagentRunRecord } from "../agents/subagents/registry/subagent-registry.types.js";
import { executeSqliteQuerySync, getNodeSqliteKysely } from "../infra/kysely-sync.js";
import type { SqliteWorkerCommand } from "../infra/sqlite-worker-contract.js";
import {
  deferSqliteWorkerCommitReceipt,
  requestSqliteWorkerOperationAdmission,
} from "../infra/sqlite-worker-operation-admission.js";
import type { DB } from "../state/openclaw-state-db.generated.js";
import {
  runOpenClawStateWriteTransaction,
  type OpenClawStateDatabaseOptions,
} from "../state/openclaw-state-db.js";
import type { OpenClawStateReadOnlyDatabase } from "../state/openclaw-state-read.types.js";
import {
  managedTaskFlowStatuses,
  type ManagedTaskCapacitySnapshot,
  type ManagedTaskFlowRecord,
  type ManagedTaskFlowReadOperations,
  type ManagedTaskFlowWriteOperations,
  type ManagedTaskJson,
  type ManagedTaskRunRecord,
} from "./managed-task-flow-contract.js";

type Database = Pick<DB, "flow_runs" | "task_runs" | "subagent_runs">;
type FlowRow = Selectable<DB["flow_runs"]>;
type TaskRow = Selectable<DB["task_runs"]>;
export {
  isManagedTaskFlowReadCommand,
  isManagedTaskFlowWriteCommand,
} from "./managed-task-flow-contract.js";

function assertWorker(): void {
  if (isMainThread) {
    throw new Error("Managed task-flow storage requires its admitted SQLite worker");
  }
}
function required(value: string, label: string): string {
  const normalized = value.trim();
  if (!normalized) {
    throw new Error(`${label} is required`);
  }
  return normalized;
}
function integer(value: number, label: string): number {
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
function encodeJson(value: ManagedTaskJson): string {
  if (!isJson(value)) {
    throw new Error("Invalid managed task JSON");
  }
  return JSON.stringify(value);
}
function decodeFlow(row: FlowRow): ManagedTaskFlowRecord {
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
function decodeTask(row: TaskRow): ManagedTaskRunRecord {
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
function projectSubagent(
  entry: SubagentRunRecord,
  ownerKey: string,
  controllerId: string,
): ManagedTaskRunRecord | undefined {
  const pluginId = controllerId.replace(/\/v1$/, "");
  if (
    entry.label !== `plugin:${pluginId}` ||
    (entry.childSessionKey !== ownerKey &&
      entry.requesterSessionKey !== ownerKey &&
      entry.controllerSessionKey !== ownerKey) ||
    entry.completionTarget === "parent" ||
    entry.collect ||
    entry.runId.startsWith("taskflow:")
  ) {
    return undefined;
  }
  const execution = entry.execution;
  const outcome = execution.outcome;
  const terminal = execution.status === "terminal" && execution.endedAt !== undefined;
  const status =
    execution.status === "queued" || execution.status === "running"
      ? execution.status
      : terminal && entry.endedReason === SUBAGENT_ENDED_REASON_KILLED
        ? "cancelled"
        : terminal && outcome?.status === "timeout"
          ? "timed_out"
          : terminal && outcome?.status === "error"
            ? "failed"
            : terminal &&
                outcome?.status === "ok" &&
                entry.endedReason === SUBAGENT_ENDED_REASON_COMPLETE
              ? "succeeded"
              : "unknown";
  return {
    observationSource: "native-subagent",
    id: entry.taskRunId ?? entry.runId,
    runtime: "subagent",
    ownerKey: entry.requesterSessionKey,
    scopeKind: "session",
    task: entry.task,
    status,
    deliveryStatus: entry.delivery?.status ?? "not_required",
    notifyPolicy: entry.expectsCompletionMessage ? "done_only" : "silent",
    createdAt: entry.createdAt,
    runId: entry.runId,
    label: entry.label,
    requesterSessionKey: entry.requesterSessionKey,
    childSessionKey: entry.childSessionKey,
    generation: entry.generation,
    startedAt: execution.startedAt,
    endedAt: execution.endedAt,
    error: outcome && "error" in outcome ? outcome.error : undefined,
    terminalOutcome: status === "succeeded" ? "completed" : terminal ? outcome?.status : undefined,
  };
}

function selectNativeTasks(
  database: OpenClawStateReadOnlyDatabase,
  ownerKey: string,
  controllerId: string,
  taskId?: string,
): ManagedTaskRunRecord[] {
  let query = getNodeSqliteKysely<Database>(database.db)
    .selectFrom("subagent_runs")
    .selectAll()
    .where((eb) =>
      eb.or([
        eb("child_session_key", "=", ownerKey),
        eb("requester_session_key", "=", ownerKey),
        eb("controller_session_key", "=", ownerKey),
      ]),
    );
  if (taskId) {
    query = query.where((eb) =>
      eb.or([
        eb("run_id", "=", taskId),
        eb(
          eb.fn<string>("json_extract", [eb.ref("payload_json"), eb.val("$.taskRunId")]),
          "=",
          taskId,
        ),
      ]),
    );
  }
  const tasks = executeSqliteQuerySync(
    database.db,
    query.orderBy("created_at", "desc").orderBy("run_id", "asc"),
  ).rows.flatMap((row) => {
    const entry = rowToSubagentRunRecord(row);
    if (!entry) {
      return [];
    }
    const projected = projectSubagent(entry, ownerKey, controllerId);
    return projected && (!taskId || projected.id === taskId || projected.runId === taskId)
      ? [projected]
      : [];
  });
  if (taskId && tasks.length > 1) {
    throw new Error("Native task identity has competing original run observations");
  }
  return tasks;
}

function capacitySnapshot(
  database: OpenClawStateReadOnlyDatabase,
  controllerId: string,
  ownerSessionKeys: string[],
): ManagedTaskCapacitySnapshot {
  const owners = [
    ...new Set(ownerSessionKeys.map((key) => required(key, "Capacity owner key"))),
  ].toSorted();
  if (owners.length === 0 || owners.length > 64 || owners.length !== ownerSessionKeys.length) {
    throw new Error("Capacity snapshot requires 1–64 unique canonical owners");
  }
  const rows = executeSqliteQuerySync(
    database.db,
    getNodeSqliteKysely<Database>(database.db)
      .selectFrom("flow_runs")
      .selectAll()
      .where("controller_id", "=", controllerId)
      .where("sync_mode", "=", "managed")
      .where("owner_key", "in", owners)
      .where("status", "not in", ["succeeded", "failed", "cancelled", "lost"])
      .orderBy("owner_key", "asc")
      .orderBy("flow_id", "asc")
      .limit(4097),
  ).rows;
  if (rows.length > 4096) {
    throw new Error("Capacity snapshot exceeds its admitted bound");
  }
  const flows = rows.map(decodeFlow);
  return {
    ownerSessionKeys: owners,
    flows,
    snapshot: flows.map(({ flowId, ownerKey, revision }) => ({ flowId, ownerKey, revision })),
  };
}
function selectFlow(
  database: OpenClawStateReadOnlyDatabase,
  ownerKey: string,
  controllerId: string,
  flowId: string,
) {
  return executeSqliteQuerySync(
    database.db,
    getNodeSqliteKysely<Database>(database.db)
      .selectFrom("flow_runs")
      .selectAll()
      .where("owner_key", "=", ownerKey)
      .where("controller_id", "=", controllerId)
      .where("sync_mode", "=", "managed")
      .where("flow_id", "=", flowId),
  ).rows[0];
}

/** Called only inside the retained read-only worker's admitted database scope. */
export function executeManagedTaskFlowReadCommand<Key extends keyof ManagedTaskFlowReadOperations>(
  database: OpenClawStateReadOnlyDatabase,
  command: { type: Key; input: ManagedTaskFlowReadOperations[Key]["input"] },
): ManagedTaskFlowReadOperations[Key]["output"];
export function executeManagedTaskFlowReadCommand(
  database: OpenClawStateReadOnlyDatabase,
  command: SqliteWorkerCommand<ManagedTaskFlowReadOperations>,
): ManagedTaskFlowReadOperations[keyof ManagedTaskFlowReadOperations]["output"] {
  assertWorker();
  const ownerKey = required(command.input.ownerKey, "Flow owner key");
  const kysely = getNodeSqliteKysely<Database>(database.db);
  switch (command.type) {
    case "tasks.managedFlows.capacitySnapshot":
      return capacitySnapshot(
        database,
        required(command.input.controllerId, "Flow controller ID"),
        command.input.ownerSessionKeys,
      );
    case "tasks.managedFlows.get": {
      const row = selectFlow(
        database,
        ownerKey,
        required(command.input.controllerId, "Flow controller ID"),
        required(command.input.flowId, "Flow ID"),
      );
      return row ? decodeFlow(row) : undefined;
    }
    case "tasks.managedFlows.list":
      return executeSqliteQuerySync(
        database.db,
        kysely
          .selectFrom("flow_runs")
          .selectAll()
          .where("owner_key", "=", ownerKey)
          .where("controller_id", "=", required(command.input.controllerId, "Flow controller ID"))
          .where("sync_mode", "=", "managed")
          .orderBy("updated_at", "desc")
          .orderBy("flow_id", "asc"),
      ).rows.map(decodeFlow);
    case "tasks.runs.get": {
      const legacyOwnerObservation = command.input.legacyOwnerObservation;
      const row = executeSqliteQuerySync(
        database.db,
        kysely
          .selectFrom("task_runs")
          .selectAll()
          .where("owner_key", "=", ownerKey)
          .where((eb) =>
            legacyOwnerObservation
              ? eb.and([])
              : eb.or([
                  eb("label", "=", `plugin:${command.input.controllerId.replace(/\/v1$/, "")}`),
                  eb.exists(
                    eb
                      .selectFrom("flow_runs")
                      .select("flow_id")
                      .whereRef("flow_runs.flow_id", "=", "task_runs.parent_flow_id")
                      .where("flow_runs.sync_mode", "=", "managed")
                      .where("flow_runs.controller_id", "=", command.input.controllerId),
                  ),
                ]),
          )
          .where("task_id", "=", required(command.input.taskId, "Task ID")),
      ).rows[0];
      const legacy = row ? decodeTask(row) : undefined;
      const native = selectNativeTasks(
        database,
        ownerKey,
        required(command.input.controllerId, "Flow controller ID"),
        legacy?.runId ?? command.input.taskId,
      )[0];
      return native && (!legacy || native.id === legacy.id) ? native : legacy;
    }
    case "tasks.runs.list": {
      const legacyOwnerObservation = command.input.legacyOwnerObservation;
      const legacy = executeSqliteQuerySync(
        database.db,
        kysely
          .selectFrom("task_runs")
          .selectAll()
          .where("owner_key", "=", ownerKey)
          .where((eb) =>
            legacyOwnerObservation
              ? eb.and([])
              : eb.or([
                  eb("label", "=", `plugin:${command.input.controllerId.replace(/\/v1$/, "")}`),
                  eb.exists(
                    eb
                      .selectFrom("flow_runs")
                      .select("flow_id")
                      .whereRef("flow_runs.flow_id", "=", "task_runs.parent_flow_id")
                      .where("flow_runs.sync_mode", "=", "managed")
                      .where("flow_runs.controller_id", "=", command.input.controllerId),
                  ),
                ]),
          )
          .orderBy("created_at", "desc")
          .orderBy("task_id", "asc"),
      ).rows.map(decodeTask);
      const native = selectNativeTasks(
        database,
        ownerKey,
        required(command.input.controllerId, "Flow controller ID"),
      );
      if (new Set(native.map((task) => task.id)).size !== native.length) {
        throw new Error("Native task list has competing original run observations");
      }
      const merged = new Map(legacy.map((task) => [task.id, task]));
      for (const task of native) {
        merged.set(task.id, task);
      }
      return [...merged.values()].toSorted(
        (a, b) => b.createdAt - a.createdAt || a.id.localeCompare(b.id),
      );
    }
  }
  throw new Error("Unsupported managed task-flow read command");
}

/** The broker holds the admitted physical owner through this native transaction and reply. */
export function executeManagedTaskFlowWriteCommand<
  Key extends keyof ManagedTaskFlowWriteOperations,
>(
  command: { type: Key; input: ManagedTaskFlowWriteOperations[Key]["input"] },
  databaseOptions: OpenClawStateDatabaseOptions,
): ManagedTaskFlowWriteOperations[Key]["output"];
export function executeManagedTaskFlowWriteCommand(
  command: SqliteWorkerCommand<ManagedTaskFlowWriteOperations>,
  databaseOptions: OpenClawStateDatabaseOptions,
): ManagedTaskFlowWriteOperations[keyof ManagedTaskFlowWriteOperations]["output"] {
  assertWorker();
  const input = command.input;
  const ownerKey = required(input.ownerKey, "Flow owner key");
  const controllerId = required(input.controllerId, "Flow controller ID");
  const updatedAt = integer(input.updatedAt ?? Date.now(), "Flow update timestamp");
  return runOpenClawStateWriteTransaction<
    ManagedTaskFlowWriteOperations[keyof ManagedTaskFlowWriteOperations]["output"]
  >(
    (database) => {
      requestSqliteWorkerOperationAdmission({ stage: "transaction", facts: undefined });
      const kysely = getNodeSqliteKysely<Database>(database.db);
      if (command.type === "tasks.managedFlows.create") {
        const fields = command.input;
        const status = managedTaskFlowStatuses.find(
          (value) => value === (fields.status ?? "queued"),
        );
        const notifyPolicy = (["done_only", "state_changes", "silent"] as const).find(
          (value) => value === (fields.notifyPolicy ?? "done_only"),
        );
        if (!status || !notifyPolicy) {
          throw new Error("Invalid managed task-flow creation state");
        }
        if (fields.dedupe) {
          const identity = fields.stateJson;
          const keys = fields.dedupe.stateFields;
          if (
            !identity ||
            typeof identity !== "object" ||
            Array.isArray(identity) ||
            keys.length === 0 ||
            keys.length > 8 ||
            new Set(keys).size !== keys.length ||
            keys.some(
              (key) =>
                !Object.hasOwn(identity, key) ||
                key.length === 0 ||
                key.length > 128 ||
                !["string", "number", "boolean"].includes(typeof identity[key]),
            )
          ) {
            throw new Error("Managed flow deduplication requires bounded primitive state identity");
          }
          const existing = executeSqliteQuerySync(
            database.db,
            kysely
              .selectFrom("flow_runs")
              .selectAll()
              .where("owner_key", "=", ownerKey)
              .where("controller_id", "=", controllerId)
              .where("sync_mode", "=", "managed")
              .where("status", "not in", ["succeeded", "failed", "cancelled", "lost"])
              .orderBy("updated_at", "desc")
              .orderBy("flow_id", "asc")
              .limit(4097),
          ).rows;
          if (existing.length > 4096) {
            throw new Error("Managed flow deduplication exceeds its admitted bound");
          }
          const matching = existing.map(decodeFlow).find((flow) => {
            const state = flow.stateJson;
            return (
              state !== null &&
              typeof state === "object" &&
              !Array.isArray(state) &&
              keys.every((key) => Object.hasOwn(state, key) && state[key] === identity[key])
            );
          });
          if (matching) {
            requestSqliteWorkerOperationAdmission({ stage: "commit", facts: undefined });
            return { ...matching, deduplicated: true };
          }
        }
        const row: Insertable<DB["flow_runs"]> = {
          flow_id: randomUUID(),
          shape: null,
          sync_mode: "managed",
          owner_key: ownerKey,
          requester_origin_json: null,
          controller_id: required(fields.controllerId, "Flow controller ID"),
          revision: 0,
          status,
          notify_policy: notifyPolicy,
          goal: required(fields.goal, "Flow goal"),
          current_step: fields.currentStep ?? null,
          blocked_task_id: fields.blockedTaskId ?? null,
          blocked_summary: fields.blockedSummary ?? null,
          state_json: fields.stateJson === undefined ? null : encodeJson(fields.stateJson),
          wait_json: fields.waitJson === undefined ? null : encodeJson(fields.waitJson),
          cancel_requested_at: null,
          created_at: integer(fields.createdAt ?? updatedAt, "Flow creation timestamp"),
          updated_at: updatedAt,
          ended_at: fields.endedAt == null ? null : integer(fields.endedAt, "Flow end timestamp"),
        };
        executeSqliteQuerySync(database.db, kysely.insertInto("flow_runs").values(row));
        const created = selectFlow(database, ownerKey, controllerId, row.flow_id);
        if (!created) {
          throw new Error("Created managed task flow was not retained");
        }
        const flow = decodeFlow(created);
        deferSqliteWorkerCommitReceipt(database.db, {
          type: command.type,
          ownerKey,
          controllerId,
          flowId: flow.flowId,
          revision: flow.revision,
          applied: true,
        });
        requestSqliteWorkerOperationAdmission({ stage: "commit", facts: undefined });
        return flow;
      }
      const fields = command.input;
      const flowId = required(fields.flowId, "Flow ID");
      const expectedRevision = integer(fields.expectedRevision, "Expected flow revision");
      const currentRow = selectFlow(database, ownerKey, controllerId, flowId);
      if (!currentRow) {
        requestSqliteWorkerOperationAdmission({ stage: "commit", facts: undefined });
        return { applied: false, code: "not_found" };
      }
      const current = decodeFlow(currentRow);
      if (current.revision !== expectedRevision) {
        requestSqliteWorkerOperationAdmission({ stage: "commit", facts: undefined });
        return { applied: false, code: "revision_conflict", current };
      }
      if (command.type === "tasks.managedFlows.reserve") {
        const captured = command.input.capacitySnapshot;
        const fresh = capacitySnapshot(database, controllerId, captured.ownerSessionKeys);
        if (
          !fresh.ownerSessionKeys.includes(ownerKey) ||
          JSON.stringify(fresh.snapshot) !== JSON.stringify(captured.snapshot)
        ) {
          requestSqliteWorkerOperationAdmission({ stage: "commit", facts: undefined });
          return { applied: false, code: "capacity_snapshot_conflict", current };
        }
      }
      const patch: Updateable<DB["flow_runs"]> = {
        revision: integer(expectedRevision + 1, "Next flow revision"),
        updated_at: updatedAt,
        ...(fields.currentStep === undefined ? {} : { current_step: fields.currentStep }),
        ...(fields.stateJson === undefined ? {} : { state_json: encodeJson(fields.stateJson) }),
      };
      if (["succeeded", "failed", "cancelled", "lost"].includes(current.status)) {
        requestSqliteWorkerOperationAdmission({ stage: "commit", facts: undefined });
        return { applied: false, code: "terminal_state", current };
      }
      switch (fields.mutation) {
        case "resume":
          if (
            fields.status !== undefined &&
            fields.status !== "queued" &&
            fields.status !== "running"
          ) {
            throw new Error("A managed task flow can resume only queued or running");
          }
          Object.assign(patch, {
            status: fields.status ?? "queued",
            wait_json: null,
            blocked_task_id: null,
            blocked_summary: null,
            ended_at: null,
          });
          break;
        case "setWaiting":
          Object.assign(patch, {
            status:
              fields.blockedTaskId?.trim() || fields.blockedSummary?.trim() ? "blocked" : "waiting",
            ended_at: null,
            ...(fields.waitJson === undefined ? {} : { wait_json: encodeJson(fields.waitJson) }),
            blocked_task_id: fields.blockedTaskId?.trim() || null,
            blocked_summary: fields.blockedSummary?.trim() || null,
          });
          break;
        case "finish":
        case "fail":
          Object.assign(patch, {
            status: fields.mutation === "finish" ? "succeeded" : "failed",
            wait_json: null,
            ended_at: integer(fields.endedAt ?? updatedAt, "Flow end timestamp"),
            blocked_task_id:
              fields.mutation === "finish"
                ? null
                : fields.blockedTaskId === undefined
                  ? currentRow.blocked_task_id
                  : fields.blockedTaskId,
            blocked_summary:
              fields.mutation === "finish"
                ? null
                : fields.blockedSummary === undefined
                  ? currentRow.blocked_summary
                  : fields.blockedSummary,
          });
          break;
        default:
          throw new Error("Invalid managed task-flow mutation");
      }
      executeSqliteQuerySync(
        database.db,
        kysely
          .updateTable("flow_runs")
          .set(patch)
          .where("flow_id", "=", flowId)
          .where("owner_key", "=", ownerKey)
          .where("controller_id", "=", controllerId)
          .where("sync_mode", "=", "managed")
          .where("revision", "=", expectedRevision),
      );
      const updated = selectFlow(database, ownerKey, controllerId, flowId);
      if (!updated || updated.revision !== expectedRevision + 1) {
        throw new Error("Managed task-flow revision did not advance atomically");
      }
      const flow = decodeFlow(updated);
      deferSqliteWorkerCommitReceipt(database.db, {
        type: command.type,
        ownerKey,
        controllerId,
        flowId: flow.flowId,
        revision: flow.revision,
        applied: true,
      });
      requestSqliteWorkerOperationAdmission({ stage: "commit", facts: undefined });
      return { applied: true, flow };
    },
    databaseOptions,
    { operationLabel: command.type },
  );
}
