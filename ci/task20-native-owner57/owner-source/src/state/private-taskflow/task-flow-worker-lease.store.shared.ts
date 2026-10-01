// Shared validation, row mapping, and namespace primitives for worker leases.
import type { DatabaseSync } from "node:sqlite";
import type { Selectable } from "kysely";
import {
  executeSqliteQuerySync,
  executeSqliteQueryTakeFirstSync,
  getNodeSqliteKysely,
} from "../../infra/kysely-sync.js";
import { normalizeSqliteNumber } from "../../infra/sqlite-number.js";
import type { DB as OpenClawStateDatabase } from "../openclaw-state-db.generated.js";
import { readTaskFlowRecord } from "./private-readers.js";
import { isTerminalTaskFlow } from "./task-flow-registry.types.js";
import type {
  AcquireTaskFlowWorkerLeaseResult,
  ResolvedAcquireTaskFlowWorkerLeaseInput,
  ResolvedReconcileTaskFlowWorkerLeaseInput,
  ResolvedValidateTaskFlowWorkerLeaseInput,
  ReleaseTaskFlowWorkerLeaseInput,
  RenewTaskFlowWorkerLeaseInput,
  TaskFlowWorkerLease,
  TaskFlowWorkerLeaseContention,
  TaskFlowWorkerLeaseLiveness,
  TaskFlowWorkerLeaseState,
} from "./task-flow-worker-lease.types.js";
import {
  TASK_FLOW_WORKER_LEASE_EVENT_RETENTION_MAX,
  TASK_FLOW_WORKER_LEASE_GLOBAL_LIMIT_MAX,
} from "./task-flow-worker-lease.types.js";

type LeaseStoreDatabase = Pick<
  OpenClawStateDatabase,
  | "flow_runs"
  | "task_flow_worker_lease_namespaces"
  | "task_flow_worker_leases"
  | "task_flow_worker_lease_events"
  | "task_runs"
  | "worktrees"
>;
export type LeaseRow = Selectable<OpenClawStateDatabase["task_flow_worker_leases"]>;

/** A lease is not launch authority after its managed flow ends or requests cancellation. */
export function workerLeaseFlowCanLaunch(db: DatabaseSync, row: LeaseRow): boolean {
  const flow = readTaskFlowRecord(db, row.flow_id);
  return (
    flow !== undefined &&
    flow.ownerKey === row.owner_key &&
    flow.syncMode === "managed" &&
    flow.controllerId === row.controller_id &&
    flow.cancelRequestedAt === undefined &&
    flow.endedAt === undefined &&
    !isTerminalTaskFlow(flow)
  );
}

/** Verifies the exact flow-owned registry row while the caller holds BEGIN IMMEDIATE. */
export function workerLeaseWorktreeIsAuthoritative(
  db: DatabaseSync,
  input: {
    flowId: string;
    worktreeId: string;
    repositoryKey: string;
  },
): boolean {
  const flowId = assertBoundedWorkerLeaseText(input.flowId, "flowId");
  const worktreeId = assertBoundedWorkerLeaseText(input.worktreeId, "worktreeId");
  const repositoryKey = normalizeWorkerLeaseRepositoryKey(input.repositoryKey);
  const worktree = executeSqliteQueryTakeFirstSync(
    db,
    workerLeaseKysely(db)
      .selectFrom("worktrees")
      .select(["repo_fingerprint", "owner_kind", "owner_id", "removed_at"])
      .where("id", "=", worktreeId),
  );
  const current = executeSqliteQueryTakeFirstSync(
    db,
    workerLeaseKysely(db)
      .selectFrom("worktrees")
      .select("id")
      .where("owner_kind", "=", "task-flow")
      .where("owner_id", "=", flowId)
      .where("removed_at", "is", null)
      .orderBy("created_at", "desc")
      .limit(1),
  );
  return (
    worktree !== undefined &&
    current?.id === worktreeId &&
    worktree.removed_at === null &&
    worktree.owner_kind === "task-flow" &&
    worktree.owner_id === flowId &&
    (!repositoryKey.startsWith("hostrepo:v1:") ||
      `hostrepo:v1:${worktree.repo_fingerprint}` === repositoryKey)
  );
}

export type BoundAcquire = ResolvedAcquireTaskFlowWorkerLeaseInput & { ownerKey: string };
export type ResolvedBoundAcquire = ReturnType<typeof validateWorkerLeaseAcquire> & {
  namespace: string;
  controllerId: string;
};
export type BoundRenew = RenewTaskFlowWorkerLeaseInput & { ownerKey: string };
export type BoundRelease = ReleaseTaskFlowWorkerLeaseInput & { ownerKey: string };
export type BoundReconcile = ResolvedReconcileTaskFlowWorkerLeaseInput & { ownerKey: string };
export type BoundValidate = ResolvedValidateTaskFlowWorkerLeaseInput & { ownerKey: string };

export function workerLeaseReconcileIsTerminal(
  input: BoundReconcile,
): input is Extract<BoundReconcile, { liveness: "terminal" | "cancelled" | "dead" }> {
  return (
    input.liveness === "terminal" || input.liveness === "cancelled" || input.liveness === "dead"
  );
}

const ATTEMPT_KEY_PATTERN = /^[0-9a-f]{64}$/u;
const EVIDENCE_DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const IDENTIFIER_MAX_LENGTH = 1_024;
const TASK_FLOW_WORKER_LEASE_HOST_NAMESPACE = "host/task-flow-workers";
const WORKSPACE_IDENTITY_PATTERN =
  /^(?:hostfs:v1:[a-z0-9_-]+:[0-9a-f]+:[0-9a-f]+|hostworktree:v1:[a-z0-9_-]+:[0-9a-f]+:[0-9a-f]+|hostremote:v1:[0-9a-f]{64}|hostlegacy:v1:[0-9a-f]{64})$/u;
const HOST_REPOSITORY_IDENTITY_PATTERN = /^hostrepo:v1:[0-9a-f]{16}$/u;
const REPOSITORY_OWNER_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?$/u;
const REPOSITORY_NAME_PATTERN = /^[a-z0-9](?:[a-z0-9._-]{0,98}[a-z0-9])?$/u;

export function workerLeaseKysely(db: DatabaseSync) {
  return getNodeSqliteKysely<LeaseStoreDatabase>(db);
}

function containsControlCharacter(value: string): boolean {
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if (code <= 0x1f || code === 0x7f) {
      return true;
    }
  }
  return false;
}

export function assertBoundedWorkerLeaseText(value: string, label: string): string {
  if (
    value.length === 0 ||
    value.length > IDENTIFIER_MAX_LENGTH ||
    value !== value.trim() ||
    containsControlCharacter(value)
  ) {
    throw new Error(`${label} must be normalized non-control text up to 1024 characters.`);
  }
  return value;
}

export function normalizeWorkerLeaseRepositoryKey(value: string): string {
  const normalized = assertBoundedWorkerLeaseText(
    value.normalize("NFKC"),
    "repositoryKey",
  ).toLowerCase();
  if (HOST_REPOSITORY_IDENTITY_PATTERN.test(normalized)) {
    return normalized;
  }
  const segments = normalized.split("/");
  if (
    segments.length !== 2 ||
    !REPOSITORY_OWNER_PATTERN.test(segments[0] ?? "") ||
    !REPOSITORY_NAME_PATTERN.test(segments[1] ?? "") ||
    segments[1] === "." ||
    segments[1] === ".." ||
    segments[1]?.endsWith(".git")
  ) {
    throw new Error("repositoryKey must be a canonical owner/repository identifier.");
  }
  return `${segments[0]}/${segments[1]}`;
}

export function assertWorkerLeaseWorkspaceIdentity(value: string): string {
  if (!WORKSPACE_IDENTITY_PATTERN.test(value)) {
    throw new Error("workspaceKey must be a host-issued placement identity.");
  }
  return value;
}

export function deriveWorkerLeaseNamespace(controllerId: string): string {
  assertBoundedWorkerLeaseText(controllerId, "persisted controllerId");
  return TASK_FLOW_WORKER_LEASE_HOST_NAMESPACE;
}

export function assertNonNegativeWorkerLeaseInteger(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative safe integer.`);
  }
  return value;
}

export function resolveWorkerLeaseNow(nowMs: number | undefined): number {
  return assertNonNegativeWorkerLeaseInteger(nowMs ?? Date.now(), "nowMs");
}

export function validateBoundWorkerLeaseInput(input: {
  leaseId: string;
  flowId: string;
  attemptKey: string;
  fencingToken: number;
  ownerKey: string;
  nowMs?: number;
}): {
  leaseId: string;
  flowId: string;
  attemptKey: string;
  fencingToken: number;
  ownerKey: string;
  nowMs: number;
} {
  const fencingToken = assertNonNegativeWorkerLeaseInteger(input.fencingToken, "fencingToken");
  if (fencingToken < 1) {
    throw new Error("fencingToken must be greater than zero.");
  }
  return {
    leaseId: assertBoundedWorkerLeaseText(input.leaseId, "leaseId"),
    flowId: assertBoundedWorkerLeaseText(input.flowId, "flowId"),
    attemptKey: assertWorkerLeaseAttemptKey(input.attemptKey),
    fencingToken,
    ownerKey: assertBoundedWorkerLeaseText(input.ownerKey, "ownerKey"),
    nowMs: resolveWorkerLeaseNow(input.nowMs),
  };
}

export function assertWorkerLeaseAttemptKey(value: string): string {
  if (!ATTEMPT_KEY_PATTERN.test(value)) {
    throw new Error("attemptKey must be exactly 64 lowercase hexadecimal characters.");
  }
  return value;
}

export function assertWorkerLeaseEvidenceDigest(value: string): string {
  if (!EVIDENCE_DIGEST_PATTERN.test(value)) {
    throw new Error(
      "evidence digest must be sha256 followed by 64 lowercase hexadecimal characters.",
    );
  }
  return value;
}

function parseLeaseState(value: string): TaskFlowWorkerLeaseState {
  if (value === "active" || value === "reconciliation_required" || value === "released") {
    return value;
  }
  throw new Error(`Invalid persisted worker lease state: ${JSON.stringify(value)}`);
}

export function assertWorkerLeaseLiveness(value: string): TaskFlowWorkerLeaseLiveness {
  if (
    value === "unknown" ||
    value === "live" ||
    value === "terminal" ||
    value === "cancelled" ||
    value === "dead"
  ) {
    return value;
  }
  throw new Error(`Invalid persisted worker lease liveness: ${JSON.stringify(value)}`);
}

export function workerLeaseRowToRecord(row: LeaseRow): TaskFlowWorkerLease {
  return {
    leaseId: row.lease_id,
    namespace: row.namespace,
    controllerId: row.controller_id,
    flowId: row.flow_id,
    flowRevision: normalizeSqliteNumber(row.flow_revision) ?? 0,
    attemptKey: row.attempt_key,
    kind: row.kind,
    repositoryKey: row.repository_key,
    workspaceKey: row.workspace_key,
    holderId: row.holder_id,
    ownerGeneration: row.owner_generation,
    ...(row.canonical_task_identity ? { canonicalTaskIdentity: row.canonical_task_identity } : {}),
    liveness: assertWorkerLeaseLiveness(row.liveness),
    state: parseLeaseState(row.state),
    fencingToken: normalizeSqliteNumber(row.fencing_token) ?? 0,
    acquiredAtMs: normalizeSqliteNumber(row.acquired_at_ms) ?? 0,
    updatedAtMs: normalizeSqliteNumber(row.updated_at_ms) ?? 0,
    expiresAtMs: normalizeSqliteNumber(row.expires_at_ms) ?? 0,
    ...(row.released_at_ms == null
      ? {}
      : { releasedAtMs: normalizeSqliteNumber(row.released_at_ms) ?? 0 }),
    ...(row.terminal_evidence_digest
      ? { terminalEvidenceDigest: row.terminal_evidence_digest }
      : {}),
  };
}

export function workerLeaseContention(row: LeaseRow): TaskFlowWorkerLeaseContention {
  const lease = workerLeaseRowToRecord(row);
  return {
    leaseId: lease.leaseId,
    flowId: lease.flowId,
    attemptKey: lease.attemptKey,
    kind: lease.kind,
    repositoryKey: lease.repositoryKey,
    workspaceKey: lease.workspaceKey,
    state: lease.state,
    fencingToken: lease.fencingToken,
    expiresAtMs: lease.expiresAtMs,
  };
}

export function readWorkerLeaseStoreVersion(db: DatabaseSync, namespace: string): number {
  const row = executeSqliteQueryTakeFirstSync(
    db,
    workerLeaseKysely(db)
      .selectFrom("task_flow_worker_lease_namespaces")
      .select("store_version")
      .where("namespace", "=", namespace),
  );
  return normalizeSqliteNumber(row?.store_version ?? null) ?? 0;
}

function ensureNamespace(db: DatabaseSync, namespace: string, nowMs: number): void {
  executeSqliteQuerySync(
    db,
    workerLeaseKysely(db)
      .insertInto("task_flow_worker_lease_namespaces")
      .values({ namespace, next_fencing_token: 0, store_version: 0, updated_at_ms: nowMs })
      .onConflict((conflict) => conflict.column("namespace").doNothing()),
  );
}

export function advanceWorkerLeaseNamespace(
  db: DatabaseSync,
  namespace: string,
  nowMs: number,
  options: { fencingToken: boolean },
): { fencingToken: number; storeVersion: number } {
  ensureNamespace(db, namespace, nowMs);
  executeSqliteQuerySync(
    db,
    workerLeaseKysely(db)
      .updateTable("task_flow_worker_lease_namespaces")
      .set((expression) => ({
        store_version: expression("store_version", "+", 1),
        ...(options.fencingToken
          ? { next_fencing_token: expression("next_fencing_token", "+", 1) }
          : {}),
        updated_at_ms: nowMs,
      }))
      .where("namespace", "=", namespace),
  );
  const row = executeSqliteQueryTakeFirstSync(
    db,
    workerLeaseKysely(db)
      .selectFrom("task_flow_worker_lease_namespaces")
      .select(["next_fencing_token", "store_version"])
      .where("namespace", "=", namespace),
  );
  if (!row) {
    throw new Error("Worker lease namespace disappeared during its transaction.");
  }
  return {
    fencingToken: normalizeSqliteNumber(row.next_fencing_token) ?? 0,
    storeVersion: normalizeSqliteNumber(row.store_version) ?? 0,
  };
}

export function appendWorkerLeaseEvent(
  db: DatabaseSync,
  params: {
    namespace: string;
    leaseId?: string;
    flowId: string;
    attemptKey: string;
    eventKind: string;
    result: string;
    fencingToken?: number;
    storeVersion: number;
    evidenceDigest?: string;
    detail?: Record<string, unknown>;
    nowMs: number;
  },
): void {
  executeSqliteQuerySync(
    db,
    workerLeaseKysely(db)
      .insertInto("task_flow_worker_lease_events")
      .values({
        namespace: params.namespace,
        lease_id: params.leaseId ?? null,
        flow_id: params.flowId,
        attempt_key: params.attemptKey,
        event_kind: params.eventKind,
        result: params.result,
        fencing_token: params.fencingToken ?? null,
        store_version: params.storeVersion,
        evidence_digest: params.evidenceDigest ?? null,
        detail_json: params.detail ? JSON.stringify(params.detail) : null,
        occurred_at_ms: params.nowMs,
      }),
  );
  const oldestRetained = executeSqliteQueryTakeFirstSync(
    db,
    workerLeaseKysely(db)
      .selectFrom("task_flow_worker_lease_events")
      .select("event_id")
      .where("namespace", "=", params.namespace)
      .orderBy("event_id", "desc")
      .limit(1)
      .offset(TASK_FLOW_WORKER_LEASE_EVENT_RETENTION_MAX - 1),
  );
  const cutoffEventId = normalizeSqliteNumber(oldestRetained?.event_id ?? null);
  if (cutoffEventId !== undefined) {
    const protectedEventIds: number[] = [];
    for (const lease of listActiveWorkerLeases(db, params.namespace)) {
      // Keep both the committed admission and the actual latest state/fencing
      // transition for each unresolved lease. Routine renewals, denials, and
      // idempotent reconciliation cannot rotate out that transition.
      for (const selection of ["acquired", "state"] as const) {
        let candidateEvents = workerLeaseKysely(db)
          .selectFrom("task_flow_worker_lease_events")
          .select("event_id")
          .where("namespace", "=", params.namespace)
          .where("lease_id", "=", lease.lease_id);
        if (selection === "acquired") {
          candidateEvents = candidateEvents
            .where("event_kind", "=", "acquire")
            .where("result", "=", "acquired");
        } else {
          candidateEvents = candidateEvents.where((expression) =>
            expression.or([
              expression("event_kind", "=", "state"),
              expression.and([
                expression("event_kind", "=", "reconcile"),
                expression("result", "in", ["unknown", "adopted"]),
              ]),
            ]),
          );
        }
        const protectedEvent = executeSqliteQueryTakeFirstSync(
          db,
          candidateEvents.orderBy("event_id", "desc").limit(1),
        );
        const protectedEventId = normalizeSqliteNumber(protectedEvent?.event_id ?? null);
        if (protectedEventId !== undefined) {
          protectedEventIds.push(protectedEventId);
        }
      }
    }
    let deletion = workerLeaseKysely(db)
      .deleteFrom("task_flow_worker_lease_events")
      .where("namespace", "=", params.namespace)
      .where("event_id", "<", cutoffEventId);
    if (protectedEventIds.length > 0) {
      deletion = deletion.where("event_id", "not in", protectedEventIds);
    }
    executeSqliteQuerySync(db, deletion);
  }
}

export function readWorkerLeaseByAttempt(
  db: DatabaseSync,
  attemptKey: string,
): LeaseRow | undefined {
  return executeSqliteQueryTakeFirstSync(
    db,
    workerLeaseKysely(db)
      .selectFrom("task_flow_worker_leases")
      .selectAll()
      .where("attempt_key", "=", attemptKey),
  );
}

export function readOwnedWorkerLease(
  db: DatabaseSync,
  leaseId: string,
  ownerKey: string,
): LeaseRow | undefined {
  return executeSqliteQueryTakeFirstSync(
    db,
    workerLeaseKysely(db)
      .selectFrom("task_flow_worker_leases")
      .selectAll()
      .where("lease_id", "=", leaseId)
      .where("owner_key", "=", ownerKey),
  );
}

export function locateBoundWorkerLease(
  db: DatabaseSync,
  input: ReturnType<typeof validateBoundWorkerLeaseInput>,
):
  | { found: true; row: LeaseRow }
  | {
      found: false;
      reason: "not_found" | "flow_mismatch" | "attempt_mismatch" | "stale_fencing_token";
    } {
  const row = readOwnedWorkerLease(db, input.leaseId, input.ownerKey);
  if (!row) {
    return { found: false, reason: "not_found" };
  }
  if (row.attempt_key !== input.attemptKey) {
    return { found: false, reason: "attempt_mismatch" };
  }
  if (row.flow_id !== input.flowId) {
    return { found: false, reason: "flow_mismatch" };
  }
  if (row.fencing_token !== input.fencingToken) {
    return { found: false, reason: "stale_fencing_token" };
  }
  return { found: true, row };
}

export function listActiveWorkerLeases(db: DatabaseSync, namespace: string): LeaseRow[] {
  return executeSqliteQuerySync(
    db,
    workerLeaseKysely(db)
      .selectFrom("task_flow_worker_leases")
      .selectAll()
      .where("namespace", "=", namespace)
      .where("released_at_ms", "is", null)
      .orderBy("fencing_token", "asc"),
  ).rows;
}

export function immutableWorkerLeaseAcquireMatches(
  row: LeaseRow,
  input: ResolvedBoundAcquire,
): boolean {
  return (
    row.namespace === input.namespace &&
    row.controller_id === input.controllerId &&
    row.owner_key === input.ownerKey &&
    row.flow_id === input.flowId &&
    row.attempt_key === input.attemptKey &&
    row.kind === input.kind &&
    row.repository_key === input.repositoryKey &&
    row.workspace_key === input.workspaceKey &&
    row.holder_id === input.holderId &&
    row.owner_generation === input.ownerGeneration
  );
}

export function validateWorkerLeaseAcquire(input: BoundAcquire): BoundAcquire & { nowMs: number } {
  const nowMs = resolveWorkerLeaseNow(input.nowMs);
  const globalLimit = assertNonNegativeWorkerLeaseInteger(input.globalLimit, "globalLimit");
  if (globalLimit < 1 || globalLimit > TASK_FLOW_WORKER_LEASE_GLOBAL_LIMIT_MAX) {
    throw new Error(
      `globalLimit must be between 1 and ${TASK_FLOW_WORKER_LEASE_GLOBAL_LIMIT_MAX}.`,
    );
  }
  assertNonNegativeWorkerLeaseInteger(input.expectedFlowRevision, "expectedFlowRevision");
  assertNonNegativeWorkerLeaseInteger(input.expiresAtMs, "expiresAtMs");
  if (input.expiresAtMs <= nowMs) {
    throw new Error("expiresAtMs must be later than nowMs.");
  }
  return {
    ...input,
    ownerKey: assertBoundedWorkerLeaseText(input.ownerKey, "ownerKey"),
    flowId: assertBoundedWorkerLeaseText(input.flowId, "flowId"),
    attemptKey: assertWorkerLeaseAttemptKey(input.attemptKey),
    kind: assertBoundedWorkerLeaseText(input.kind, "kind"),
    worktreeId: assertBoundedWorkerLeaseText(input.worktreeId, "worktreeId"),
    repositoryKey: normalizeWorkerLeaseRepositoryKey(input.repositoryKey),
    workspaceKey: assertWorkerLeaseWorkspaceIdentity(input.workspaceKey),
    holderId: assertBoundedWorkerLeaseText(input.holderId, "holderId"),
    ownerGeneration: assertBoundedWorkerLeaseText(input.ownerGeneration, "ownerGeneration"),
    globalLimit,
    nowMs,
  };
}

export function bumpWorkerLeaseFlowRevision(
  db: DatabaseSync,
  params: { flowId: string; ownerKey: string; expectedRevision?: number; nowMs: number },
):
  | { applied: true; flowRevision?: number }
  | { applied: false; reason: "revision_required" | "revision_conflict"; current?: number } {
  const flow = readTaskFlowRecord(db, params.flowId);
  if (!flow) {
    return { applied: true };
  }
  if (flow.ownerKey !== params.ownerKey) {
    return { applied: false, reason: "revision_conflict", current: flow.revision };
  }
  if (params.expectedRevision === undefined) {
    return { applied: false, reason: "revision_required", current: flow.revision };
  }
  if (flow.revision !== params.expectedRevision) {
    return { applied: false, reason: "revision_conflict", current: flow.revision };
  }
  const flowRevision = flow.revision + 1;
  executeSqliteQuerySync(
    db,
    workerLeaseKysely(db)
      .updateTable("flow_runs")
      .set({ revision: flowRevision, updated_at: Math.max(flow.updatedAt, params.nowMs) })
      .where("flow_id", "=", flow.flowId)
      .where("revision", "=", flow.revision),
  );
  return { applied: true, flowRevision };
}

export function rejectWorkerLeaseAcquire(
  db: DatabaseSync,
  input: ResolvedBoundAcquire,
  reason: Exclude<AcquireTaskFlowWorkerLeaseResult, { acquired: true }>["reason"],
  options: {
    currentFlowRevision?: number;
    lease?: LeaseRow;
    contending?: LeaseRow[];
    audit?: { eventKind: string; result: string; detail?: Record<string, unknown> };
  } = {},
): AcquireTaskFlowWorkerLeaseResult {
  const advanced = advanceWorkerLeaseNamespace(db, input.namespace, input.nowMs, {
    fencingToken: false,
  });
  appendWorkerLeaseEvent(db, {
    namespace: input.namespace,
    leaseId: options.lease?.lease_id,
    flowId: input.flowId,
    attemptKey: input.attemptKey,
    eventKind: options.audit?.eventKind ?? "acquire",
    result: options.audit?.result ?? reason,
    fencingToken: options.lease
      ? (normalizeSqliteNumber(options.lease.fencing_token) ?? undefined)
      : undefined,
    storeVersion: advanced.storeVersion,
    detail: {
      request: {
        controllerId: input.controllerId,
        ownerKey: input.ownerKey,
        expectedFlowRevision: input.expectedFlowRevision,
        kind: input.kind,
        repositoryKey: input.repositoryKey,
        workspaceKey: input.workspaceKey,
        holderId: input.holderId,
        ownerGeneration: input.ownerGeneration,
        globalLimit: input.globalLimit,
        expiresAtMs: input.expiresAtMs,
      },
      ...(options.currentFlowRevision === undefined
        ? {}
        : { currentFlowRevision: options.currentFlowRevision }),
      contenders: (options.contending ?? []).map((row) => row.lease_id),
      ...options.audit?.detail,
    },
    nowMs: input.nowMs,
  });
  return {
    acquired: false,
    reason,
    storeVersion: advanced.storeVersion,
    ...(options.currentFlowRevision === undefined
      ? {}
      : { currentFlowRevision: options.currentFlowRevision }),
    ...(options.lease ? { lease: workerLeaseRowToRecord(options.lease) } : {}),
    // Capacity is global, but lease identity is owner-private. Keep same-owner
    // results actionable without disclosing foreign flows, attempts, domains,
    // fencing tokens, or expiry to another controller session.
    contending: (options.contending ?? [])
      .filter((row) => row.owner_key === input.ownerKey)
      .map(workerLeaseContention),
  };
}
