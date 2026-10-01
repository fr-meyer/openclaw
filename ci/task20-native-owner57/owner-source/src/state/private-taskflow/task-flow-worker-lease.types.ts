// Host-owned admission contracts for managed-flow worker launches.

export const TASK_FLOW_WORKER_LEASE_GLOBAL_LIMIT_MAX = 2;
export const TASK_FLOW_WORKER_LEASE_EVENT_RETENTION_MAX = 10_000;

export type TaskFlowWorkerLeaseLiveness = "unknown" | "live" | "terminal" | "cancelled" | "dead";

export type TaskFlowWorkerLeaseState = "active" | "reconciliation_required" | "released";

/** Host-validated identity attached to a managed worker process launch. */
export type TaskFlowWorkerLeaseLaunchBinding = {
  ownerSessionKey: string;
  leaseId: string;
  flowId: string;
  attemptKey: string;
  fencingToken: number;
};

/** Exact host-held placement carried from final launch binding into command admission. */
export type TaskFlowWorkerPlacementAuthority = Readonly<{
  flowId: string;
  worktreeId: string;
  cwd: string;
  repositoryKey: string;
  workspaceKey: string;
}>;

/** Host-resolved facts used only at the final Gateway dispatch boundary. */
export type BindTaskFlowWorkerLeaseLaunchInput = TaskFlowWorkerLeaseLaunchBinding & {
  canonicalRunId: string;
  childSessionKey: string;
  worktreeId: string;
  repositoryKey: string;
  workspaceKey: string;
  nowMs?: number;
};

export type BindTaskFlowWorkerLeaseLaunchResult =
  | {
      bound: true;
      idempotent: boolean;
      canonicalTaskIdentity: string;
      lease: TaskFlowWorkerLease;
      storeVersion: number;
    }
  | {
      bound: false;
      reason:
        | "not_found"
        | "attempt_mismatch"
        | "flow_mismatch"
        | "placement_mismatch"
        | "stale_fencing_token"
        | "released"
        | "reconciliation_required"
        | "expired"
        | "worktree_not_authoritative"
        | "task_not_found"
        | "task_identity_conflict"
        | "flow_not_active"
        | "task_not_active";
      lease?: TaskFlowWorkerLease;
      storeVersion: number;
    };

/** The Gateway may undo a committed binding only before invoking the dispatcher. */
export type AbortTaskFlowWorkerLeaseLaunchInput = TaskFlowWorkerLeaseLaunchBinding & {
  canonicalTaskIdentity: string;
  nowMs?: number;
};

export type AbortTaskFlowWorkerLeaseLaunchResult =
  | { aborted: true; lease: TaskFlowWorkerLease; storeVersion: number }
  | {
      aborted: false;
      reason:
        | "not_found"
        | "attempt_mismatch"
        | "flow_mismatch"
        | "stale_fencing_token"
        | "released"
        | "task_identity_conflict";
      lease?: TaskFlowWorkerLease;
      storeVersion: number;
    };

export type TaskFlowWorkerLease = {
  leaseId: string;
  namespace: string;
  controllerId: string;
  flowId: string;
  flowRevision: number;
  attemptKey: string;
  kind: string;
  repositoryKey: string;
  workspaceKey: string;
  holderId: string;
  ownerGeneration: string;
  canonicalTaskIdentity?: string;
  liveness: TaskFlowWorkerLeaseLiveness;
  state: TaskFlowWorkerLeaseState;
  fencingToken: number;
  acquiredAtMs: number;
  updatedAtMs: number;
  expiresAtMs: number;
  releasedAtMs?: number;
  terminalEvidenceDigest?: string;
};

export type TaskFlowWorkerLeaseContention = Pick<
  TaskFlowWorkerLease,
  | "leaseId"
  | "flowId"
  | "attemptKey"
  | "kind"
  | "repositoryKey"
  | "workspaceKey"
  | "state"
  | "fencingToken"
  | "expiresAtMs"
>;

export type AcquireTaskFlowWorkerLeaseInput = {
  flowId: string;
  expectedFlowRevision: number;
  attemptKey: string;
  kind: string;
  holderId: string;
  ownerGeneration: string;
  globalLimit: number;
  expiresAtMs: number;
  nowMs?: number;
};

/** Internal worker input after the host has resolved its placement authority. */
export type ResolvedAcquireTaskFlowWorkerLeaseInput = AcquireTaskFlowWorkerLeaseInput & {
  worktreeId: string;
  repositoryKey: string;
  workspaceKey: string;
};

export type AcquireTaskFlowWorkerLeaseResult =
  | {
      acquired: true;
      idempotent: boolean;
      lease: TaskFlowWorkerLease;
      storeVersion: number;
      flowRevision: number;
    }
  | {
      acquired: false;
      reason:
        | "flow_not_found"
        | "flow_not_managed"
        | "flow_not_active"
        | "revision_conflict"
        | "attempt_identity_conflict"
        | "attempt_released"
        | "attempt_reconciliation_required"
        | "worktree_not_authoritative"
        | "global_capacity"
        | "repository_busy"
        | "workspace_busy";
      storeVersion: number;
      currentFlowRevision?: number;
      lease?: TaskFlowWorkerLease;
      contending: TaskFlowWorkerLeaseContention[];
    };

export type RenewTaskFlowWorkerLeaseInput = {
  leaseId: string;
  flowId: string;
  attemptKey: string;
  fencingToken: number;
  expiresAtMs: number;
  nowMs?: number;
};

export type RenewTaskFlowWorkerLeaseResult =
  | { renewed: true; lease: TaskFlowWorkerLease; storeVersion: number }
  | {
      renewed: false;
      reason:
        | "not_found"
        | "attempt_mismatch"
        | "flow_mismatch"
        | "stale_fencing_token"
        | "released"
        | "reconciliation_required"
        | "expired";
      storeVersion: number;
      lease?: TaskFlowWorkerLease;
    };

export type ReleaseTaskFlowWorkerLeaseInput = {
  leaseId: string;
  flowId: string;
  attemptKey: string;
  fencingToken: number;
  expectedFlowRevision?: number;
  nowMs?: number;
};

export type ReleaseTaskFlowWorkerLeaseResult =
  | {
      released: true;
      idempotent: boolean;
      lease: TaskFlowWorkerLease;
      storeVersion: number;
      flowRevision?: number;
    }
  | {
      released: false;
      reason:
        | "not_found"
        | "attempt_mismatch"
        | "flow_mismatch"
        | "stale_fencing_token"
        | "canonical_task_required"
        | "task_not_found"
        | "task_identity_conflict"
        | "task_not_terminal"
        | "revision_required"
        | "revision_conflict";
      storeVersion: number;
      currentFlowRevision?: number;
      lease?: TaskFlowWorkerLease;
    };

export type ReconcileTaskFlowWorkerLeaseInput = {
  leaseId: string;
  flowId: string;
  attemptKey: string;
  fencingToken: number;
  liveness: TaskFlowWorkerLeaseLiveness;
  holderId?: string;
  ownerGeneration?: string;
  expectedFlowRevision?: number;
  expiresAtMs?: number;
  nowMs?: number;
};

/** Internal worker input; only nonterminal reconciliation depends on current placement. */
export type ResolvedReconcileTaskFlowWorkerLeaseInput = Omit<
  ReconcileTaskFlowWorkerLeaseInput,
  "liveness"
> &
  (
    | { liveness: "terminal" | "cancelled" | "dead" }
    | {
        liveness: "unknown" | "live";
        worktreeId: string;
        repositoryKey: string;
        workspaceKey: string;
      }
  );

export type ReconcileTaskFlowWorkerLeaseResult =
  | {
      reconciled: true;
      idempotent: boolean;
      lease: TaskFlowWorkerLease;
      storeVersion: number;
      flowRevision?: number;
    }
  | {
      reconciled: false;
      reason:
        | "not_found"
        | "attempt_mismatch"
        | "flow_mismatch"
        | "placement_mismatch"
        | "worktree_not_authoritative"
        | "stale_fencing_token"
        | "invalid_transition"
        | "canonical_task_required"
        | "task_not_found"
        | "task_identity_conflict"
        | "task_not_terminal"
        | "revision_required"
        | "revision_conflict";
      storeVersion: number;
      currentFlowRevision?: number;
      lease?: TaskFlowWorkerLease;
    };

export type ValidateTaskFlowWorkerLeaseInput = {
  leaseId: string;
  flowId: string;
  attemptKey: string;
  fencingToken: number;
  purpose: "launch" | "report";
  nowMs?: number;
};

/** Internal worker input carrying the current host-resolved placement. */
export type ResolvedValidateTaskFlowWorkerLeaseInput = ValidateTaskFlowWorkerLeaseInput & {
  worktreeId: string;
  repositoryKey: string;
  workspaceKey: string;
};

export type ValidateTaskFlowWorkerLeaseResult =
  | { valid: true; lease: TaskFlowWorkerLease; storeVersion: number }
  | {
      valid: false;
      reason:
        | "not_found"
        | "attempt_mismatch"
        | "flow_mismatch"
        | "placement_mismatch"
        | "worktree_not_authoritative"
        | "stale_fencing_token"
        | "released"
        | "reconciliation_required"
        | "expired"
        | "flow_not_active"
        | "task_not_active";
      storeVersion: number;
      lease?: TaskFlowWorkerLease;
    };
