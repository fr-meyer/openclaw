// Connection-bound, linearizable managed-flow worker admission operations.
import crypto from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { executeSqliteQuerySync } from "../../infra/kysely-sync.js";
import { ensureTaskFlowWorkerLeaseSchema } from "./private-schema.js";
import { readTaskFlowRecord } from "./private-readers.js";
import { isTerminalTaskFlow } from "./task-flow-registry.types.js";
import {
  abortTaskFlowWorkerLeaseLaunchInDatabase,
  bindTaskFlowWorkerLeaseLaunchInDatabase,
  deriveTaskFlowWorkerRunId,
  hasWorkerLeaseLaunchEvent,
  taskTerminalLiveness,
  terminalTaskEvidenceDigest,
  unlaunchedWorkerLeaseEvidenceDigest,
} from "./task-flow-worker-lease-task.kernel.js";
import {
  advanceWorkerLeaseNamespace,
  appendWorkerLeaseEvent,
  assertBoundedWorkerLeaseText,
  assertNonNegativeWorkerLeaseInteger,
  assertWorkerLeaseLiveness,
  assertWorkerLeaseWorkspaceIdentity,
  bumpWorkerLeaseFlowRevision,
  deriveWorkerLeaseNamespace,
  immutableWorkerLeaseAcquireMatches,
  listActiveWorkerLeases,
  locateBoundWorkerLease,
  normalizeWorkerLeaseRepositoryKey,
  readOwnedWorkerLease,
  readWorkerLeaseByAttempt,
  readWorkerLeaseStoreVersion,
  rejectWorkerLeaseAcquire,
  validateBoundWorkerLeaseInput,
  validateWorkerLeaseAcquire,
  workerLeaseKysely,
  workerLeaseFlowCanLaunch,
  workerLeaseReconcileIsTerminal,
  workerLeaseRowToRecord,
  workerLeaseWorktreeIsAuthoritative,
  type BoundAcquire,
  type BoundReconcile,
  type BoundRelease,
  type BoundRenew,
  type ResolvedBoundAcquire,
} from "./task-flow-worker-lease.store.shared.js";
import type {
  AcquireTaskFlowWorkerLeaseResult,
  ReconcileTaskFlowWorkerLeaseResult,
  ReleaseTaskFlowWorkerLeaseResult,
  RenewTaskFlowWorkerLeaseResult,
} from "./task-flow-worker-lease.types.js";
import { readTaskRecord } from "./private-readers.js";
import { isTerminalTaskStatus } from "./task-registry.types.js";

export {
  abortTaskFlowWorkerLeaseLaunchInDatabase,
  bindTaskFlowWorkerLeaseLaunchInDatabase,
  deriveTaskFlowWorkerRunId,
};
export { validateTaskFlowWorkerLeaseInDatabase } from "./task-flow-worker-lease.validation.kernel.js";

/** Caller holds the shared-state BEGIN IMMEDIATE transaction. */
export function acquireTaskFlowWorkerLeaseInDatabase(
  db: DatabaseSync,
  rawInput: BoundAcquire,
): AcquireTaskFlowWorkerLeaseResult {
  ensureTaskFlowWorkerLeaseSchema(db);
  const validated = validateWorkerLeaseAcquire(rawInput);
  const existing = readWorkerLeaseByAttempt(db, validated.attemptKey);
  if (existing) {
    // A global attempt collision owned by another session is intentionally
    // indistinguishable from an inaccessible flow. Do not append an event or
    // expose any lease/domain detail across the owner boundary.
    if (existing.owner_key !== validated.ownerKey) {
      return { acquired: false, reason: "flow_not_found", storeVersion: 0, contending: [] };
    }
    const input: ResolvedBoundAcquire = {
      ...validated,
      namespace: existing.namespace,
      controllerId: existing.controller_id,
    };
    if (!immutableWorkerLeaseAcquireMatches(existing, input)) {
      return rejectWorkerLeaseAcquire(db, input, "attempt_identity_conflict", { lease: existing });
    }
    if (!workerLeaseWorktreeIsAuthoritative(db, input)) {
      return rejectWorkerLeaseAcquire(db, input, "worktree_not_authoritative", {
        lease: existing,
      });
    }
    if (existing.released_at_ms !== null) {
      return rejectWorkerLeaseAcquire(db, input, "attempt_released", { lease: existing });
    }
    if (existing.state !== "active" || existing.expires_at_ms <= input.nowMs) {
      const transitionedToReconciliation = existing.state === "active";
      if (existing.state === "active") {
        executeSqliteQuerySync(
          db,
          workerLeaseKysely(db)
            .updateTable("task_flow_worker_leases")
            .set({ state: "reconciliation_required", updated_at_ms: input.nowMs })
            .where("lease_id", "=", existing.lease_id),
        );
      }
      const refreshed = readOwnedWorkerLease(db, existing.lease_id, input.ownerKey) ?? existing;
      return rejectWorkerLeaseAcquire(db, input, "attempt_reconciliation_required", {
        lease: refreshed,
        ...(transitionedToReconciliation
          ? {
              audit: {
                eventKind: "state",
                result: "reconciliation_required",
                detail: { trigger: "acquire_expired" },
              },
            }
          : {}),
      });
    }
    if (!workerLeaseFlowCanLaunch(db, existing)) {
      return rejectWorkerLeaseAcquire(db, input, "flow_not_active", { lease: existing });
    }
    const advanced = advanceWorkerLeaseNamespace(db, input.namespace, input.nowMs, {
      fencingToken: false,
    });
    appendWorkerLeaseEvent(db, {
      namespace: input.namespace,
      leaseId: existing.lease_id,
      flowId: input.flowId,
      attemptKey: input.attemptKey,
      eventKind: "acquire",
      result: "idempotent",
      fencingToken: existing.fencing_token,
      storeVersion: advanced.storeVersion,
      nowMs: input.nowMs,
    });
    return {
      acquired: true,
      idempotent: true,
      lease: workerLeaseRowToRecord(existing),
      storeVersion: advanced.storeVersion,
      flowRevision: existing.flow_revision,
    };
  }

  const flow = readTaskFlowRecord(db, validated.flowId);
  // Pre-admission access/type failures have no authoritative lease namespace.
  // They are deliberately not written to the lease audit log, avoiding both
  // cross-owner disclosure and an unauthenticated audit-amplification path.
  if (!flow || flow.ownerKey !== validated.ownerKey) {
    return { acquired: false, reason: "flow_not_found", storeVersion: 0, contending: [] };
  }
  if (flow.syncMode !== "managed" || !flow.controllerId) {
    return {
      acquired: false,
      reason: "flow_not_managed",
      storeVersion: 0,
      currentFlowRevision: flow.revision,
      contending: [],
    };
  }
  if (
    flow.cancelRequestedAt !== undefined ||
    flow.endedAt !== undefined ||
    isTerminalTaskFlow(flow)
  ) {
    return {
      acquired: false,
      reason: "flow_not_active",
      storeVersion: 0,
      currentFlowRevision: flow.revision,
      contending: [],
    };
  }
  const input: ResolvedBoundAcquire = {
    ...validated,
    namespace: deriveWorkerLeaseNamespace(flow.controllerId),
    controllerId: flow.controllerId,
  };
  if (flow.revision !== input.expectedFlowRevision) {
    return rejectWorkerLeaseAcquire(db, input, "revision_conflict", {
      currentFlowRevision: flow.revision,
    });
  }
  if (!workerLeaseWorktreeIsAuthoritative(db, input)) {
    return rejectWorkerLeaseAcquire(db, input, "worktree_not_authoritative");
  }

  const active = listActiveWorkerLeases(db, input.namespace);
  if (active.length >= input.globalLimit) {
    return rejectWorkerLeaseAcquire(db, input, "global_capacity", { contending: active });
  }
  const repositoryContenders = active.filter(
    (lease) => lease.repository_key === input.repositoryKey,
  );
  if (repositoryContenders.length > 0) {
    return rejectWorkerLeaseAcquire(db, input, "repository_busy", {
      contending: repositoryContenders,
    });
  }
  const workspaceContenders = active.filter((lease) => lease.workspace_key === input.workspaceKey);
  if (workspaceContenders.length > 0) {
    return rejectWorkerLeaseAcquire(db, input, "workspace_busy", {
      contending: workspaceContenders,
    });
  }

  const advanced = advanceWorkerLeaseNamespace(db, input.namespace, input.nowMs, {
    fencingToken: true,
  });
  const leaseId = crypto.randomUUID();
  const flowRevision = flow.revision + 1;
  executeSqliteQuerySync(
    db,
    workerLeaseKysely(db)
      .updateTable("flow_runs")
      .set({ revision: flowRevision, updated_at: Math.max(flow.updatedAt, input.nowMs) })
      .where("flow_id", "=", flow.flowId)
      .where("revision", "=", flow.revision),
  );
  executeSqliteQuerySync(
    db,
    workerLeaseKysely(db).insertInto("task_flow_worker_leases").values({
      lease_id: leaseId,
      namespace: input.namespace,
      controller_id: input.controllerId,
      owner_key: input.ownerKey,
      flow_id: input.flowId,
      flow_revision: flowRevision,
      attempt_key: input.attemptKey,
      kind: input.kind,
      repository_key: input.repositoryKey,
      workspace_key: input.workspaceKey,
      holder_id: input.holderId,
      owner_generation: input.ownerGeneration,
      canonical_task_identity: null,
      liveness: "unknown",
      state: "active",
      fencing_token: advanced.fencingToken,
      acquired_at_ms: input.nowMs,
      updated_at_ms: input.nowMs,
      expires_at_ms: input.expiresAtMs,
      released_at_ms: null,
      terminal_evidence_digest: null,
    }),
  );
  const stored = readOwnedWorkerLease(db, leaseId, input.ownerKey);
  if (!stored) {
    throw new Error("Worker lease disappeared during acquisition.");
  }
  appendWorkerLeaseEvent(db, {
    namespace: input.namespace,
    leaseId,
    flowId: input.flowId,
    attemptKey: input.attemptKey,
    eventKind: "acquire",
    result: "acquired",
    fencingToken: advanced.fencingToken,
    storeVersion: advanced.storeVersion,
    nowMs: input.nowMs,
  });
  return {
    acquired: true,
    idempotent: false,
    lease: workerLeaseRowToRecord(stored),
    storeVersion: advanced.storeVersion,
    flowRevision,
  };
}

export function renewTaskFlowWorkerLeaseInDatabase(
  db: DatabaseSync,
  rawInput: BoundRenew,
): RenewTaskFlowWorkerLeaseResult {
  ensureTaskFlowWorkerLeaseSchema(db);
  const base = validateBoundWorkerLeaseInput(rawInput);
  const expiresAtMs = assertNonNegativeWorkerLeaseInteger(rawInput.expiresAtMs, "expiresAtMs");
  if (expiresAtMs <= base.nowMs) {
    throw new Error("expiresAtMs must be later than nowMs.");
  }
  const located = locateBoundWorkerLease(db, base);
  if (!located.found) {
    return { renewed: false, reason: located.reason, storeVersion: 0 };
  }
  const row = located.row;
  if (row.released_at_ms !== null) {
    return {
      renewed: false,
      reason: "released",
      storeVersion: readWorkerLeaseStoreVersion(db, row.namespace),
      lease: workerLeaseRowToRecord(row),
    };
  }
  if (row.state !== "active") {
    return {
      renewed: false,
      reason: "reconciliation_required",
      storeVersion: readWorkerLeaseStoreVersion(db, row.namespace),
      lease: workerLeaseRowToRecord(row),
    };
  }
  if (row.expires_at_ms <= base.nowMs) {
    const advanced = advanceWorkerLeaseNamespace(db, row.namespace, base.nowMs, {
      fencingToken: false,
    });
    executeSqliteQuerySync(
      db,
      workerLeaseKysely(db)
        .updateTable("task_flow_worker_leases")
        .set({ state: "reconciliation_required", updated_at_ms: base.nowMs })
        .where("lease_id", "=", row.lease_id),
    );
    const lease = readOwnedWorkerLease(db, row.lease_id, base.ownerKey) ?? row;
    appendWorkerLeaseEvent(db, {
      namespace: row.namespace,
      leaseId: row.lease_id,
      flowId: row.flow_id,
      attemptKey: row.attempt_key,
      eventKind: "state",
      result: "reconciliation_required",
      fencingToken: row.fencing_token,
      storeVersion: advanced.storeVersion,
      detail: { trigger: "renew_expired" },
      nowMs: base.nowMs,
    });
    return {
      renewed: false,
      reason: "expired",
      storeVersion: advanced.storeVersion,
      lease: workerLeaseRowToRecord(lease),
    };
  }
  const advanced = advanceWorkerLeaseNamespace(db, row.namespace, base.nowMs, {
    fencingToken: false,
  });
  executeSqliteQuerySync(
    db,
    workerLeaseKysely(db)
      .updateTable("task_flow_worker_leases")
      .set({ expires_at_ms: expiresAtMs, updated_at_ms: base.nowMs })
      .where("lease_id", "=", row.lease_id),
  );
  const lease = readOwnedWorkerLease(db, row.lease_id, base.ownerKey);
  if (!lease) {
    throw new Error("Worker lease disappeared during renewal.");
  }
  appendWorkerLeaseEvent(db, {
    namespace: row.namespace,
    leaseId: row.lease_id,
    flowId: row.flow_id,
    attemptKey: row.attempt_key,
    eventKind: "renew",
    result: "renewed",
    fencingToken: row.fencing_token,
    storeVersion: advanced.storeVersion,
    nowMs: base.nowMs,
  });
  return {
    renewed: true,
    lease: workerLeaseRowToRecord(lease),
    storeVersion: advanced.storeVersion,
  };
}

export function releaseTaskFlowWorkerLeaseInDatabase(
  db: DatabaseSync,
  rawInput: BoundRelease,
): ReleaseTaskFlowWorkerLeaseResult {
  ensureTaskFlowWorkerLeaseSchema(db);
  const base = validateBoundWorkerLeaseInput(rawInput);
  const located = locateBoundWorkerLease(db, base);
  if (!located.found) {
    return { released: false, reason: located.reason, storeVersion: 0 };
  }
  const row = located.row;
  let liveness: "terminal" | "cancelled" | "dead";
  let evidence: string;
  if (!row.canonical_task_identity) {
    // Only the host-owned launch binding can dispatch this attempt. An expired
    // lease with no binding and no durable launch event can therefore be
    // recovered without trusting caller-authored liveness or task evidence.
    if (row.expires_at_ms > base.nowMs || hasWorkerLeaseLaunchEvent(db, row.lease_id)) {
      return {
        released: false,
        reason: "canonical_task_required",
        storeVersion: readWorkerLeaseStoreVersion(db, row.namespace),
        lease: workerLeaseRowToRecord(row),
      };
    }
    liveness = "dead";
    evidence = unlaunchedWorkerLeaseEvidenceDigest(row.lease_id, row.attempt_key);
  } else {
    const task = readTaskRecord(db, row.canonical_task_identity);
    if (!task) {
      return {
        released: false,
        reason: "task_not_found",
        storeVersion: readWorkerLeaseStoreVersion(db, row.namespace),
        lease: workerLeaseRowToRecord(row),
      };
    }
    const canonicalRunId = deriveTaskFlowWorkerRunId(row.attempt_key);
    if (
      task.runtime !== "subagent" ||
      task.sourceId !== canonicalRunId ||
      task.runId !== canonicalRunId ||
      task.taskId !== row.canonical_task_identity
    ) {
      return {
        released: false,
        reason: "task_identity_conflict",
        storeVersion: readWorkerLeaseStoreVersion(db, row.namespace),
        lease: workerLeaseRowToRecord(row),
      };
    }
    const terminalLiveness = taskTerminalLiveness(task);
    if (!terminalLiveness) {
      return {
        released: false,
        reason: "task_not_terminal",
        storeVersion: readWorkerLeaseStoreVersion(db, row.namespace),
        lease: workerLeaseRowToRecord(row),
      };
    }
    liveness = terminalLiveness;
    evidence = terminalTaskEvidenceDigest(task);
  }
  if (row.released_at_ms !== null) {
    if (row.terminal_evidence_digest !== evidence || row.liveness !== liveness) {
      return {
        released: false,
        reason: "task_identity_conflict",
        storeVersion: readWorkerLeaseStoreVersion(db, row.namespace),
        lease: workerLeaseRowToRecord(row),
      };
    }
    return {
      released: true,
      idempotent: true,
      lease: workerLeaseRowToRecord(row),
      storeVersion: readWorkerLeaseStoreVersion(db, row.namespace),
      flowRevision: row.flow_revision,
    };
  }
  const flowRevision = bumpWorkerLeaseFlowRevision(db, {
    flowId: row.flow_id,
    ownerKey: row.owner_key,
    expectedRevision: rawInput.expectedFlowRevision,
    nowMs: base.nowMs,
  });
  if (!flowRevision.applied) {
    return {
      released: false,
      reason: flowRevision.reason,
      storeVersion: readWorkerLeaseStoreVersion(db, row.namespace),
      ...(flowRevision.current === undefined ? {} : { currentFlowRevision: flowRevision.current }),
      lease: workerLeaseRowToRecord(row),
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
        liveness,
        state: "released",
        released_at_ms: base.nowMs,
        updated_at_ms: base.nowMs,
        terminal_evidence_digest: evidence,
        ...(flowRevision.flowRevision === undefined
          ? {}
          : { flow_revision: flowRevision.flowRevision }),
      })
      .where("lease_id", "=", row.lease_id),
  );
  const lease = readOwnedWorkerLease(db, row.lease_id, base.ownerKey);
  if (!lease) {
    throw new Error("Worker lease disappeared during release.");
  }
  appendWorkerLeaseEvent(db, {
    namespace: row.namespace,
    leaseId: row.lease_id,
    flowId: row.flow_id,
    attemptKey: row.attempt_key,
    eventKind: "release",
    result: liveness,
    fencingToken: row.fencing_token,
    storeVersion: advanced.storeVersion,
    evidenceDigest: evidence,
    nowMs: base.nowMs,
  });
  return {
    released: true,
    idempotent: false,
    lease: workerLeaseRowToRecord(lease),
    storeVersion: advanced.storeVersion,
    ...(flowRevision.flowRevision === undefined ? {} : { flowRevision: flowRevision.flowRevision }),
  };
}

export function reconcileTaskFlowWorkerLeaseInDatabase(
  db: DatabaseSync,
  rawInput: BoundReconcile,
): ReconcileTaskFlowWorkerLeaseResult {
  ensureTaskFlowWorkerLeaseSchema(db);
  const base = validateBoundWorkerLeaseInput(rawInput);
  const liveness = assertWorkerLeaseLiveness(rawInput.liveness);
  const located = locateBoundWorkerLease(db, base);
  if (!located.found) {
    return { reconciled: false, reason: located.reason, storeVersion: 0 };
  }
  const row = located.row;
  if (workerLeaseReconcileIsTerminal(rawInput)) {
    const released = releaseTaskFlowWorkerLeaseInDatabase(db, {
      ownerKey: base.ownerKey,
      leaseId: base.leaseId,
      flowId: base.flowId,
      attemptKey: base.attemptKey,
      fencingToken: base.fencingToken,
      expectedFlowRevision: rawInput.expectedFlowRevision,
      nowMs: base.nowMs,
    });
    return released.released
      ? {
          reconciled: true,
          idempotent: released.idempotent,
          lease: released.lease,
          storeVersion: released.storeVersion,
          ...(released.flowRevision === undefined ? {} : { flowRevision: released.flowRevision }),
        }
      : {
          reconciled: false,
          reason: released.reason,
          storeVersion: released.storeVersion,
          ...(released.currentFlowRevision === undefined
            ? {}
            : { currentFlowRevision: released.currentFlowRevision }),
          ...(released.lease ? { lease: released.lease } : {}),
        };
  }
  const repositoryKey = normalizeWorkerLeaseRepositoryKey(rawInput.repositoryKey);
  const workspaceKey = assertWorkerLeaseWorkspaceIdentity(rawInput.workspaceKey);
  if (row.repository_key !== repositoryKey || row.workspace_key !== workspaceKey) {
    return {
      reconciled: false,
      reason: "placement_mismatch",
      storeVersion: readWorkerLeaseStoreVersion(db, row.namespace),
      lease: workerLeaseRowToRecord(row),
    };
  }
  if (!workerLeaseWorktreeIsAuthoritative(db, rawInput)) {
    return {
      reconciled: false,
      reason: "worktree_not_authoritative",
      storeVersion: readWorkerLeaseStoreVersion(db, row.namespace),
      lease: workerLeaseRowToRecord(row),
    };
  }
  if (row.released_at_ms !== null) {
    return {
      reconciled: false,
      reason: "invalid_transition",
      storeVersion: readWorkerLeaseStoreVersion(db, row.namespace),
      lease: workerLeaseRowToRecord(row),
    };
  }
  const canonicalTaskIdentity = row.canonical_task_identity;
  if (liveness === "unknown") {
    const idempotent = row.state === "reconciliation_required" && row.liveness === "unknown";
    const advanced = advanceWorkerLeaseNamespace(db, row.namespace, base.nowMs, {
      fencingToken: false,
    });
    executeSqliteQuerySync(
      db,
      workerLeaseKysely(db)
        .updateTable("task_flow_worker_leases")
        .set({
          liveness: "unknown",
          state: "reconciliation_required",
          canonical_task_identity: canonicalTaskIdentity,
          updated_at_ms: base.nowMs,
        })
        .where("lease_id", "=", row.lease_id),
    );
    const lease = readOwnedWorkerLease(db, row.lease_id, base.ownerKey) ?? row;
    appendWorkerLeaseEvent(db, {
      namespace: row.namespace,
      leaseId: row.lease_id,
      flowId: row.flow_id,
      attemptKey: row.attempt_key,
      eventKind: idempotent ? "reconcile" : "state",
      result: idempotent ? "unknown" : "reconciliation_required",
      fencingToken: row.fencing_token,
      storeVersion: advanced.storeVersion,
      ...(idempotent ? {} : { detail: { trigger: "reconcile_unknown" } }),
      nowMs: base.nowMs,
    });
    return {
      reconciled: true,
      idempotent,
      lease: workerLeaseRowToRecord(lease),
      storeVersion: advanced.storeVersion,
    };
  }

  const holderId = rawInput.holderId
    ? assertBoundedWorkerLeaseText(rawInput.holderId, "holderId")
    : row.holder_id;
  const ownerGeneration = rawInput.ownerGeneration
    ? assertBoundedWorkerLeaseText(rawInput.ownerGeneration, "ownerGeneration")
    : row.owner_generation;
  const expiresAtMs = rawInput.expiresAtMs;
  if (expiresAtMs === undefined || !Number.isSafeInteger(expiresAtMs) || expiresAtMs < 0) {
    return {
      reconciled: false,
      reason: "invalid_transition",
      storeVersion: readWorkerLeaseStoreVersion(db, row.namespace),
      lease: workerLeaseRowToRecord(row),
    };
  }
  if (!canonicalTaskIdentity || expiresAtMs <= base.nowMs) {
    return {
      reconciled: false,
      reason: "invalid_transition",
      storeVersion: readWorkerLeaseStoreVersion(db, row.namespace),
      lease: workerLeaseRowToRecord(row),
    };
  }
  const canonicalTask = readTaskRecord(db, canonicalTaskIdentity);
  const canonicalRunId = deriveTaskFlowWorkerRunId(row.attempt_key);
  if (
    !canonicalTask ||
    canonicalTask.runtime !== "subagent" ||
    canonicalTask.sourceId !== canonicalRunId ||
    canonicalTask.runId !== canonicalRunId ||
    isTerminalTaskStatus(canonicalTask.status) ||
    canonicalTask.endedAt !== undefined
  ) {
    return {
      reconciled: false,
      reason: "invalid_transition",
      storeVersion: readWorkerLeaseStoreVersion(db, row.namespace),
      lease: workerLeaseRowToRecord(row),
    };
  }
  const adoption =
    row.state !== "active" ||
    holderId !== row.holder_id ||
    ownerGeneration !== row.owner_generation;
  let flowRevision: number | undefined;
  let advanced: { fencingToken: number; storeVersion: number };
  if (adoption) {
    const bumped = bumpWorkerLeaseFlowRevision(db, {
      flowId: row.flow_id,
      ownerKey: row.owner_key,
      expectedRevision: rawInput.expectedFlowRevision,
      nowMs: base.nowMs,
    });
    if (!bumped.applied) {
      return {
        reconciled: false,
        reason: bumped.reason,
        storeVersion: readWorkerLeaseStoreVersion(db, row.namespace),
        ...(bumped.current === undefined ? {} : { currentFlowRevision: bumped.current }),
        lease: workerLeaseRowToRecord(row),
      };
    }
    flowRevision = bumped.flowRevision;
    advanced = advanceWorkerLeaseNamespace(db, row.namespace, base.nowMs, { fencingToken: true });
  } else {
    advanced = advanceWorkerLeaseNamespace(db, row.namespace, base.nowMs, { fencingToken: false });
  }
  executeSqliteQuerySync(
    db,
    workerLeaseKysely(db)
      .updateTable("task_flow_worker_leases")
      .set({
        holder_id: holderId,
        owner_generation: ownerGeneration,
        canonical_task_identity: canonicalTaskIdentity,
        liveness: "live",
        state: "active",
        expires_at_ms: expiresAtMs,
        updated_at_ms: base.nowMs,
        ...(adoption ? { fencing_token: advanced.fencingToken } : {}),
        ...(flowRevision === undefined ? {} : { flow_revision: flowRevision }),
      })
      .where("lease_id", "=", row.lease_id),
  );
  const lease = readOwnedWorkerLease(db, row.lease_id, base.ownerKey);
  if (!lease) {
    throw new Error("Worker lease disappeared during reconciliation.");
  }
  appendWorkerLeaseEvent(db, {
    namespace: row.namespace,
    leaseId: row.lease_id,
    flowId: row.flow_id,
    attemptKey: row.attempt_key,
    eventKind: adoption ? "state" : "reconcile",
    result: adoption ? "active" : "live",
    fencingToken: lease.fencing_token,
    storeVersion: advanced.storeVersion,
    ...(adoption ? { detail: { trigger: "reconcile_adopted" } } : {}),
    nowMs: base.nowMs,
  });
  return {
    reconciled: true,
    idempotent: !adoption && row.liveness === "live" && row.expires_at_ms === expiresAtMs,
    lease: workerLeaseRowToRecord(lease),
    storeVersion: advanced.storeVersion,
    ...(flowRevision === undefined ? {} : { flowRevision }),
  };
}
