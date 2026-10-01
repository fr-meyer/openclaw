import type { DatabaseSync } from "node:sqlite";
import { ensureTaskFlowWorkerLeaseSchema } from "./private-schema.js";
import {
  assertWorkerLeaseWorkspaceIdentity,
  locateBoundWorkerLease,
  normalizeWorkerLeaseRepositoryKey,
  readWorkerLeaseStoreVersion,
  validateBoundWorkerLeaseInput,
  workerLeaseFlowCanLaunch,
  workerLeaseRowToRecord,
  workerLeaseWorktreeIsAuthoritative,
  type BoundValidate,
} from "./task-flow-worker-lease.store.shared.js";
import type { ValidateTaskFlowWorkerLeaseResult } from "./task-flow-worker-lease.types.js";
import { readTaskRecord } from "./private-readers.js";

/** Validates launch/report custody on the caller's existing database connection. */
export function validateTaskFlowWorkerLeaseInDatabase(
  db: DatabaseSync,
  rawInput: BoundValidate,
): ValidateTaskFlowWorkerLeaseResult {
  ensureTaskFlowWorkerLeaseSchema(db);
  const base = validateBoundWorkerLeaseInput(rawInput);
  if (rawInput.purpose !== "launch" && rawInput.purpose !== "report") {
    throw new Error("purpose must be launch or report.");
  }
  const located = locateBoundWorkerLease(db, base);
  if (!located.found) {
    return { valid: false, reason: located.reason, storeVersion: 0 };
  }
  const row = located.row;
  const storeVersion = readWorkerLeaseStoreVersion(db, row.namespace);
  const repositoryKey = normalizeWorkerLeaseRepositoryKey(rawInput.repositoryKey);
  const workspaceKey = assertWorkerLeaseWorkspaceIdentity(rawInput.workspaceKey);
  if (row.repository_key !== repositoryKey || row.workspace_key !== workspaceKey) {
    return {
      valid: false,
      reason: "placement_mismatch",
      storeVersion,
      lease: workerLeaseRowToRecord(row),
    };
  }
  if (!workerLeaseWorktreeIsAuthoritative(db, rawInput)) {
    return {
      valid: false,
      reason: "worktree_not_authoritative",
      storeVersion,
      lease: workerLeaseRowToRecord(row),
    };
  }
  if (row.released_at_ms !== null) {
    return { valid: false, reason: "released", storeVersion, lease: workerLeaseRowToRecord(row) };
  }
  if (rawInput.purpose === "launch") {
    if (row.state !== "active") {
      return {
        valid: false,
        reason: "reconciliation_required",
        storeVersion,
        lease: workerLeaseRowToRecord(row),
      };
    }
    if (row.expires_at_ms <= base.nowMs) {
      return { valid: false, reason: "expired", storeVersion, lease: workerLeaseRowToRecord(row) };
    }
    if (!workerLeaseFlowCanLaunch(db, row)) {
      return {
        valid: false,
        reason: "flow_not_active",
        storeVersion,
        lease: workerLeaseRowToRecord(row),
      };
    }
    // A fresh reservation is checked immediately before it enters the Gateway
    // dispatch boundary. Its canonical task is intentionally assigned inside
    // that boundary. Once bound, every later launch check must still prove the
    // exact task is active.
    if (row.canonical_task_identity) {
      const task = readTaskRecord(db, row.canonical_task_identity);
      if (
        !task ||
        (task.status !== "queued" && task.status !== "running") ||
        task.endedAt != null
      ) {
        return {
          valid: false,
          reason: "task_not_active",
          storeVersion,
          lease: workerLeaseRowToRecord(row),
        };
      }
    }
  }
  return { valid: true, lease: workerLeaseRowToRecord(row), storeVersion };
}
