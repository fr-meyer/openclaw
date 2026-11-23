import { PHASE } from "./controller-constants.mjs";
import {
  findingsAreActionable,
  infrastructureBackoffMs,
  infrastructureReasonFromBlocker,
  retryPhase,
} from "./controller-policy.mjs";
import { blockState, budgetBlock, isLifecycleState, isTerminalState } from "./controller-state.mjs";
import {
  applyWorkerFailure,
  applyWorkerProtocolViolation,
  workerKindForPhase,
} from "./controller-workers.mjs";
export { blockState } from "./controller-state.mjs";

export function recoverState(
  state,
  workerTask,
  now = Date.now(),
  reservationGraceMs = 120_000,
  extras = {},
) {
  if (isTerminalState(state)) {
    return { changed: false, state, effect: "none", reason: "not_recoverable" };
  }
  if (state.launchOutcome?.status === "unknown") {
    const sessionKey = state.activeWorker?.sessionKey;
    if (
      sessionKey &&
      state.launchOutcome.sessionKey === sessionKey &&
      workerTask?.observationSource === "native-subagent" &&
      workerTask.childSessionKey === sessionKey &&
      typeof workerTask.runId === "string" &&
      workerTask.runId &&
      typeof workerTask.id === "string" &&
      workerTask.id
    ) {
      return {
        changed: true,
        state: {
          ...state,
          activeWorker: { ...state.activeWorker, runId: workerTask.runId, taskId: workerTask.id },
          launchOutcome: {
            status: "accepted",
            sessionKey,
            runId: workerTask.runId,
            observedAt: now,
          },
          updatedAt: now,
        },
        effect: "wait",
        reason: "native_launch_reconciled",
      };
    }
    return { changed: false, state, effect: "wait", reason: "native_launch_outcome_unknown" };
  }
  if (state.pendingGithubReconciliation) {
    if (now > state.deadlineAt) {
      return blockState(state, "github_head_reconciliation_deadline_exhausted", now);
    }
    return {
      changed: false,
      state,
      effect: "reconcile",
      reason: "github_head_reconciliation_pending",
    };
  }
  if (state.phase === PHASE.BLOCKED) {
    if (
      state.blocker === "findings_unusable" ||
      state.blocker === "changes_requested_without_actionable_paths"
    ) {
      return { changed: false, state, effect: "none", reason: "not_recoverable" };
    }
    const infrastructureReason = infrastructureReasonFromBlocker(state.blocker);
    if (!infrastructureReason) {
      return { changed: false, state, effect: "none", reason: "not_recoverable" };
    }
    if (retryPhase(state) === PHASE.REMEDIATION_QUEUED && !findingsAreActionable(state.findings)) {
      return blockState(state, "findings_unusable", now);
    }
    const attempt = Math.max(1, Number(state.infrastructureRetryCount) || 0);
    const retryAt = now + infrastructureBackoffMs(attempt);
    return {
      changed: true,
      state: {
        ...state,
        phase: retryPhase(state),
        activeWorker: null,
        retryCount: 0,
        infrastructureRetryCount: attempt,
        infrastructureRetryAt: retryAt,
        infrastructureLastFailure: infrastructureReason,
        wait: {
          kind: "infrastructure_backoff",
          reason: infrastructureReason,
          attempt,
          retryAt,
        },
        blocker: null,
        updatedAt: now,
      },
      effect: "wait",
      reason: "legacy_infrastructure_block_requeued",
    };
  }
  if (!state.activeWorker) {
    if (state.phase === PHASE.MERGE_QUEUED) {
      if (state.wait?.kind === "check_suite") {
        return { changed: false, state, effect: "wait", reason: "check_suite_event_wait" };
      }
      return { changed: false, state, effect: "continue", reason: "queued_merge" };
    }
    if (workerKindForPhase(state.phase)) {
      if (state.reviewLease?.kind === "review" && state.reviewLease.headSha !== state.headSha) {
        if (now > state.deadlineAt) {
          return blockState(state, "review_wait_deadline_exhausted", now);
        }
        return {
          changed: false,
          state,
          effect: "wait",
          reason: "prior_review_lease_held",
        };
      }
      const budget = budgetBlock(state, now);
      if (budget) {
        return budget;
      }
      const protocolRetryAt = Number.isFinite(state.protocolRetryAt) ? state.protocolRetryAt : null;
      if (Number.isFinite(protocolRetryAt) && protocolRetryAt > now) {
        return { changed: false, state, effect: "wait", reason: "protocol_backoff" };
      }
      if (Number.isFinite(protocolRetryAt)) {
        return {
          changed: true,
          state: {
            ...state,
            protocolRetryAt: null,
            wait: null,
            updatedAt: now,
          },
          effect: "continue",
          reason: "protocol_backoff_elapsed",
        };
      }
      const retryAt = Number.isFinite(state.infrastructureRetryAt)
        ? state.infrastructureRetryAt
        : null;
      if (Number.isFinite(retryAt) && retryAt > now) {
        return { changed: false, state, effect: "wait", reason: "infrastructure_backoff" };
      }
      if (Number.isFinite(retryAt)) {
        return {
          changed: true,
          state: {
            ...state,
            infrastructureRetryAt: null,
            wait: null,
            updatedAt: now,
          },
          effect: "continue",
          reason: "infrastructure_backoff_elapsed",
        };
      }
      return { changed: false, state, effect: "continue", reason: "queued_step" };
    }
    if (state.phase === PHASE.REVIEW_WAITING) {
      if (now > state.deadlineAt) {
        return blockState(state, "review_wait_deadline_exhausted", now);
      }
      return {
        changed: false,
        state,
        effect: "wait",
        reason: "review_in_progress",
      };
    }
    if (state.phase === PHASE.WAITING_HEAD_EVENT && now > state.deadlineAt) {
      return blockState(state, "head_confirmation_deadline_exhausted", now);
    }
    return { changed: false, state, effect: "wait", reason: "external_wait" };
  }
  const reservedAt = Number(state.activeWorker.reservedAt) || 0;
  const age = now - reservedAt;
  if (workerTask && new Set(["queued", "running"]).has(workerTask.status)) {
    const processStartedAt = Number(extras.processStartedAt);
    const sessionAlive = extras.sessionAlive;
    if (Number.isFinite(processStartedAt) && reservedAt < processStartedAt - 5_000) {
      return applyWorkerFailure(
        state,
        state.activeWorker.sessionKey,
        "worker_lost_after_process_restart",
        now,
      );
    }
    if (sessionAlive !== true && age >= reservationGraceMs) {
      return applyWorkerFailure(
        state,
        state.activeWorker.sessionKey,
        sessionAlive === false ? "worker_session_missing" : "worker_session_liveness_unknown",
        now,
      );
    }
    return {
      changed: false,
      state,
      effect: "wait",
      reason: sessionAlive === true ? "worker_active" : "worker_session_liveness_grace",
    };
  }
  if (!workerTask && age < reservationGraceMs) {
    return { changed: false, state, effect: "wait", reason: "worker_start_grace" };
  }
  if (workerTask?.status === "succeeded") {
    if (state.activeWorker.kind === "remediation" && !findingsAreActionable(state.findings)) {
      return blockState(state, "findings_unusable", now);
    }
    return applyWorkerProtocolViolation(
      state,
      state.activeWorker.sessionKey,
      state.activeWorker.kind === "remediation" ? "remediation_evidence" : "review_report",
      now,
    );
  }
  if (workerTask && new Set(["failed", "timed_out", "cancelled", "lost"]).has(workerTask.status)) {
    const detail =
      typeof workerTask.error === "string" && workerTask.error.trim()
        ? workerTask.error.trim().slice(0, 300)
        : workerTask.status;
    return applyWorkerFailure(
      state,
      state.activeWorker.sessionKey,
      `worker_execution_failed:${detail}`,
      now,
    );
  }
  return applyWorkerFailure(state, state.activeWorker.sessionKey, "worker_not_active", now);
}

export function flowMatches(state, repo, prNumber) {
  return isLifecycleState(state) && state.repo === repo && state.prNumber === prNumber;
}
