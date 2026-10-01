import crypto from "node:crypto";
import { readTaskRecord } from "./private-readers.js";
import type { DatabaseSync } from "node:sqlite";
import { executeSqliteQuerySync, executeSqliteQueryTakeFirstSync } from "../../infra/kysely-sync.js";
import { ensureTaskFlowWorkerLeaseSchema } from "./private-schema.js";
import {
  advanceWorkerLeaseNamespace,
  appendWorkerLeaseEvent,
  assertBoundedWorkerLeaseText,
  assertWorkerLeaseWorkspaceIdentity,
  locateBoundWorkerLease,
  readOwnedWorkerLease,
  readWorkerLeaseStoreVersion,
  validateBoundWorkerLeaseInput,
  workerLeaseKysely,
  workerLeaseFlowCanLaunch,
  workerLeaseRowToRecord,
  workerLeaseWorktreeIsAuthoritative,
} from "./task-flow-worker-lease.store.shared.js";
import type {
  AbortTaskFlowWorkerLeaseLaunchInput,
  AbortTaskFlowWorkerLeaseLaunchResult,
  BindTaskFlowWorkerLeaseLaunchInput,
  BindTaskFlowWorkerLeaseLaunchResult,
} from "./task-flow-worker-lease.types.js";
import type { TaskRecord } from "./task-registry.types.js";
import { isTerminalTaskStatus } from "./task-registry.types.js";

export function deriveTaskFlowWorkerRunId(attemptKey: string): string {
  if (!/^[0-9a-f]{64}$/u.test(attemptKey)) {
    throw new Error("attemptKey must be exactly 64 lowercase hexadecimal characters.");
  }
  return `taskflow:${attemptKey}`;
}

export function taskTerminalLiveness(
  task: TaskRecord,
): "terminal" | "cancelled" | "dead" | undefined {
  if (!isTerminalTaskStatus(task.status) || task.endedAt === undefined) {
    return undefined;
  }
  if (task.status === "cancelled") {
    return "cancelled";
  }
  if (task.status === "timed_out" || task.status === "lost") {
    return "dead";
  }
  return "terminal";
}

export function terminalTaskEvidenceDigest(task: TaskRecord): string {
  const payload = JSON.stringify({
    schema: "openclaw.task-flow-worker-terminal.v1",
    taskId: task.taskId,
    runId: task.runId,
    status: task.status,
    endedAt: task.endedAt,
    terminalOutcome: task.terminalOutcome ?? null,
    error: task.error ?? null,
    terminalSummary: task.terminalSummary ?? null,
  });
  return `sha256:${crypto.createHash("sha256").update(payload).digest("hex")}`;
}

export function unlaunchedWorkerLeaseEvidenceDigest(leaseId: string, attemptKey: string): string {
  return `sha256:${crypto
    .createHash("sha256")
    .update(`openclaw.task-flow-worker-unlaunched.v1\0${leaseId}\0${attemptKey}`)
    .digest("hex")}`;
}

export function hasWorkerLeaseLaunchEvent(db: DatabaseSync, leaseId: string): boolean {
  const latest = executeSqliteQueryTakeFirstSync(
    db,
    workerLeaseKysely(db)
      .selectFrom("task_flow_worker_lease_events")
      .select("event_kind")
      .where("lease_id", "=", leaseId)
      .where("event_kind", "in", ["launch", "launch_aborted"])
      .orderBy("event_id", "desc")
      .limit(1),
  );
  return latest?.event_kind === "launch";
}

/** Caller holds BEGIN IMMEDIATE; only the Gateway's pre-dispatch path invokes this. */
export function abortTaskFlowWorkerLeaseLaunchInDatabase(
  db: DatabaseSync,
  rawInput: AbortTaskFlowWorkerLeaseLaunchInput & { ownerKey: string },
): AbortTaskFlowWorkerLeaseLaunchResult {
  ensureTaskFlowWorkerLeaseSchema(db);
  const base = validateBoundWorkerLeaseInput(rawInput);
  const located = locateBoundWorkerLease(db, base);
  if (!located.found) {
    return { aborted: false, reason: located.reason, storeVersion: 0 };
  }
  const row = located.row;
  const storeVersion = readWorkerLeaseStoreVersion(db, row.namespace);
  if (row.released_at_ms !== null) {
    return { aborted: false, reason: "released", lease: workerLeaseRowToRecord(row), storeVersion };
  }
  const taskId = assertBoundedWorkerLeaseText(
    rawInput.canonicalTaskIdentity,
    "canonicalTaskIdentity",
  );
  if (row.canonical_task_identity !== taskId || !hasWorkerLeaseLaunchEvent(db, row.lease_id)) {
    return {
      aborted: false,
      reason: "task_identity_conflict",
      lease: workerLeaseRowToRecord(row),
      storeVersion,
    };
  }
  const advanced = advanceWorkerLeaseNamespace(db, row.namespace, base.nowMs, {
    fencingToken: false,
  });
  executeSqliteQuerySync(
    db,
    workerLeaseKysely(db)
      .updateTable("task_flow_worker_leases")
      .set({ canonical_task_identity: null, liveness: "unknown", updated_at_ms: base.nowMs })
      .where("lease_id", "=", row.lease_id)
      .where("canonical_task_identity", "=", taskId),
  );
  const lease = readOwnedWorkerLease(db, row.lease_id, base.ownerKey);
  if (!lease || lease.canonical_task_identity !== null) {
    throw new Error("Worker lease pre-dispatch abort was not committed.");
  }
  appendWorkerLeaseEvent(db, {
    namespace: row.namespace,
    leaseId: row.lease_id,
    flowId: row.flow_id,
    attemptKey: row.attempt_key,
    eventKind: "launch_aborted",
    result: "before_dispatch",
    fencingToken: row.fencing_token,
    storeVersion: advanced.storeVersion,
    nowMs: base.nowMs,
  });
  return {
    aborted: true,
    lease: workerLeaseRowToRecord(lease),
    storeVersion: advanced.storeVersion,
  };
}

/** Caller holds the shared-state BEGIN IMMEDIATE transaction. */
export function bindTaskFlowWorkerLeaseLaunchInDatabase(
  db: DatabaseSync,
  rawInput: BindTaskFlowWorkerLeaseLaunchInput & { ownerKey: string },
): BindTaskFlowWorkerLeaseLaunchResult {
  ensureTaskFlowWorkerLeaseSchema(db);
  const base = validateBoundWorkerLeaseInput(rawInput);
  const located = locateBoundWorkerLease(db, base);
  if (!located.found) {
    return { bound: false, reason: located.reason, storeVersion: 0 };
  }
  const row = located.row;
  const storeVersion = readWorkerLeaseStoreVersion(db, row.namespace);
  const workspaceKey = assertWorkerLeaseWorkspaceIdentity(rawInput.workspaceKey);
  if (row.repository_key !== rawInput.repositoryKey || row.workspace_key !== workspaceKey) {
    return {
      bound: false,
      reason: "placement_mismatch",
      lease: workerLeaseRowToRecord(row),
      storeVersion,
    };
  }
  if (row.released_at_ms !== null) {
    return { bound: false, reason: "released", lease: workerLeaseRowToRecord(row), storeVersion };
  }
  if (row.state !== "active") {
    return {
      bound: false,
      reason: "reconciliation_required",
      lease: workerLeaseRowToRecord(row),
      storeVersion,
    };
  }
  if (row.expires_at_ms <= base.nowMs) {
    return { bound: false, reason: "expired", lease: workerLeaseRowToRecord(row), storeVersion };
  }
  if (!workerLeaseFlowCanLaunch(db, row)) {
    return {
      bound: false,
      reason: "flow_not_active",
      lease: workerLeaseRowToRecord(row),
      storeVersion,
    };
  }

  if (
    !workerLeaseWorktreeIsAuthoritative(db, {
      flowId: row.flow_id,
      worktreeId: rawInput.worktreeId,
      repositoryKey: row.repository_key,
    })
  ) {
    return {
      bound: false,
      reason: "worktree_not_authoritative",
      lease: workerLeaseRowToRecord(row),
      storeVersion,
    };
  }

  const canonicalRunId = assertBoundedWorkerLeaseText(rawInput.canonicalRunId, "canonicalRunId");
  if (canonicalRunId !== deriveTaskFlowWorkerRunId(row.attempt_key)) {
    return {
      bound: false,
      reason: "task_identity_conflict",
      lease: workerLeaseRowToRecord(row),
      storeVersion,
    };
  }
  const childSessionKey = assertBoundedWorkerLeaseText(rawInput.childSessionKey, "childSessionKey");
  const nativeTask = readTaskRecord(db, canonicalRunId);
  const tasks = nativeTask ? [{ task_id: nativeTask.taskId, runtime: nativeTask.runtime,
    source_id: nativeTask.sourceId, run_id: nativeTask.runId, child_session_key: nativeTask.childSessionKey,
    status: nativeTask.status, ended_at: nativeTask.endedAt ?? null }] : [];
  if (tasks.length === 0) {
    return {
      bound: false,
      reason: "task_not_found",
      lease: workerLeaseRowToRecord(row),
      storeVersion,
    };
  }
  if (tasks.length !== 1) {
    return {
      bound: false,
      reason: "task_identity_conflict",
      lease: workerLeaseRowToRecord(row),
      storeVersion,
    };
  }
  const task = tasks[0]!;
  if (
    task.runtime !== "subagent" ||
    task.source_id !== canonicalRunId ||
    task.run_id !== canonicalRunId ||
    task.child_session_key !== childSessionKey
  ) {
    return {
      bound: false,
      reason: "task_identity_conflict",
      lease: workerLeaseRowToRecord(row),
      storeVersion,
    };
  }
  if ((task.status !== "queued" && task.status !== "running") || task.ended_at !== null) {
    return {
      bound: false,
      reason: "task_not_active",
      lease: workerLeaseRowToRecord(row),
      storeVersion,
    };
  }
  if (row.canonical_task_identity !== null) {
    if (row.canonical_task_identity !== task.task_id) {
      return {
        bound: false,
        reason: "task_identity_conflict",
        lease: workerLeaseRowToRecord(row),
        storeVersion,
      };
    }
    return {
      bound: true,
      idempotent: true,
      canonicalTaskIdentity: task.task_id,
      lease: workerLeaseRowToRecord(row),
      storeVersion,
    };
  }

  const advanced = advanceWorkerLeaseNamespace(db, row.namespace, base.nowMs, {
    fencingToken: false,
  });
  executeSqliteQuerySync(
    db,
    workerLeaseKysely(db)
      .updateTable("task_flow_worker_leases")
      .set({
        canonical_task_identity: task.task_id,
        liveness: "live",
        updated_at_ms: base.nowMs,
      })
      .where("lease_id", "=", row.lease_id)
      .where("canonical_task_identity", "is", null),
  );
  const lease = readOwnedWorkerLease(db, row.lease_id, base.ownerKey);
  if (!lease || lease.canonical_task_identity !== task.task_id) {
    throw new Error("Worker lease launch binding was not committed.");
  }
  appendWorkerLeaseEvent(db, {
    namespace: row.namespace,
    leaseId: row.lease_id,
    flowId: row.flow_id,
    attemptKey: row.attempt_key,
    eventKind: "launch",
    result: "bound",
    fencingToken: row.fencing_token,
    storeVersion: advanced.storeVersion,
    detail: { taskId: task.task_id, runId: canonicalRunId, worktreeId: rawInput.worktreeId },
    nowMs: base.nowMs,
  });
  return {
    bound: true,
    idempotent: false,
    canonicalTaskIdentity: task.task_id,
    lease: workerLeaseRowToRecord(lease),
    storeVersion: advanced.storeVersion,
  };
}
