import { CONTROLLER_ID } from "./controller.mjs";
import { stateOf } from "./runtime-config.mjs";
import {
  ACTIVE_TASK_STATUSES,
  DEAD_SESSION_STATUSES,
  TERMINAL_TASK_STATUSES,
  trackTaskBinding,
  withTaskBindings,
} from "./runtime-foundation.mjs";
import {
  persistState,
  processStartedAtMs,
  requireApplied,
  scheduleWake,
  workerGenerationForState,
} from "./runtime-state-primitives.mjs";

export function statusView(flow) {
  const state = stateOf(flow);
  if (!state) {
    return null;
  }
  const controlPlaneProgress = {
    revision: flow.revision,
    status: flow.status,
    phase: state.phase,
    cycle: state.cycle,
    retryCount: state.retryCount,
    infrastructureRetryCount: state.infrastructureRetryCount ?? 0,
    protocolRetryCount: state.protocolRetryCount ?? 0,
    wait: state.wait,
    blocker: state.blocker,
  };
  return {
    flowId: flow.flowId,
    revision: flow.revision,
    status: flow.status,
    repo: state.repo,
    prNumber: state.prNumber,
    headSha: state.headSha,
    githubUpdatedAt: state.githubUpdatedAt ?? null,
    phase: state.phase,
    cycle: state.cycle,
    retryCount: state.retryCount,
    infrastructureRetryCount: state.infrastructureRetryCount ?? 0,
    workerGeneration: workerGenerationForState(state),
    infrastructureRetryAt: state.infrastructureRetryAt ?? null,
    infrastructureLastFailure: state.infrastructureLastFailure ?? null,
    protocolRetryCount: state.protocolRetryCount ?? 0,
    protocolRetryAt: state.protocolRetryAt ?? null,
    deadlineAt: state.deadlineAt,
    fixerModel: state.fixerModel ?? null,
    fixerFallbackModel: state.fixerFallbackModel ?? null,
    publisherBoundary: state.publisherBoundary ?? null,
    pendingPublication: state.pendingPublication ?? null,
    mergePolicyDigest: state.mergePolicyDigest ?? null,
    brokerRepoAlias: state.brokerRepoAlias ?? null,
    remediatorProfile: state.remediatorProfile
      ? {
          schemaVersion: state.remediatorProfile.schemaVersion,
          digest: state.remediatorProfileDigest,
          repository: state.remediatorProfile.repository,
          pullRequests: state.remediatorProfile.pullRequests,
        }
      : null,
    mergeAuthorization: state.mergeAuthorization
      ? {
          schemaVersion: state.mergeAuthorization.schemaVersion,
          authorizationId: state.mergeAuthorization.authorizationId,
          authorizer: state.mergeAuthorization.authorizer,
          authorizedAt: state.mergeAuthorization.authorizedAt,
          expiresAt: state.mergeAuthorization.expiresAt,
          repository: state.mergeAuthorization.repository,
          prNumber: state.mergeAuthorization.prNumber,
          baseRef: state.mergeAuthorization.baseRef,
          mergeMethod: state.mergeAuthorization.mergeMethod,
          sourceRef: state.mergeAuthorization.sourceRef,
          policyVersion: state.mergeAuthorization.policyVersion,
          policyDigest: state.mergeAuthorization.policyDigest,
          revokedAt: state.mergeAuthorization.revokedAt,
          supersededBy: state.mergeAuthorization.supersededBy,
          digest: state.mergeAuthorization.digest,
        }
      : null,
    fixerAttestation: state.fixerAttestation ?? null,
    workspacePreflight: state.workspacePreflight ?? null,
    flowWorkspace: state.flowWorkspace ?? null,
    queuedPosition: state.wait?.kind === "parallel_slot" ? state.wait.position : null,
    lastGhostCleanup: state.lastGhostCleanup ?? null,
    activeWorker: state.activeWorker
      ? {
          kind: state.activeWorker.kind,
          sessionKey: state.activeWorker.sessionKey,
          runId: state.activeWorker.runId,
          taskId: state.activeWorker.taskId,
          claimRef: state.activeWorker.claimRef ?? null,
          profileDigest: state.activeWorker.profileDigest ?? null,
        }
      : null,
    reviewLease: state.reviewLease
      ? {
          kind: state.reviewLease.kind,
          headSha: state.reviewLease.headSha,
          claimRef: state.reviewLease.claimRef ?? null,
          reviewId: state.reviewLease.reviewId ?? null,
        }
      : null,
    review: state.review,
    findingsCount: state.findings.length,
    wait: state.wait,
    blocker: state.blocker,
    mergeReady: state.mergeReady,
    mergeGates: state.mergeGates ?? null,
    controlPlaneProgress,
    prEffects: state.prEffects ?? "none",
    latestExternalMilestone: state.latestExternalMilestone ?? null,
    lastTerminalEnvelope: state.lastTerminalEnvelope ?? null,
    terminalSupersession: state.terminalSupersession ?? null,
    terminalCleanup: state.terminalCleanup ?? null,
    merged: state.merged ?? null,
  };
}

export function agentIdFromSessionKey(sessionKey) {
  if (typeof sessionKey !== "string") {
    return null;
  }
  const match = /^agent:([^:]+):/.exec(sessionKey);
  return match?.[1] ?? null;
}

export function requireOwnerContext(ctx, ownerSessionKey) {
  if (!ownerSessionKey || ctx.sessionKey !== ownerSessionKey) {
    throw new Error("controller_action_requires_owner_session");
  }
}

export function canInspectStatus(config, ctx, ownerSessionKey, state) {
  if (ctx.sessionKey === ownerSessionKey || state?.activeWorker?.sessionKey === ctx.sessionKey) {
    return true;
  }
  const agentId =
    typeof ctx.agentId === "string" && ctx.agentId.trim()
      ? ctx.agentId.trim()
      : agentIdFromSessionKey(ctx.sessionKey);
  return Boolean(agentId && config.statusAgentIds.includes(agentId));
}

export async function resolveAccessibleFlow(boundFlows, flowId) {
  return await withTaskBindings(async () => {
    const flow = await boundFlows.get(flowId);
    if (!flow || flow.controllerId !== CONTROLLER_ID || !stateOf(flow)) {
      throw new Error("flow_not_found");
    }
    return flow;
  });
}

export function workerTaskMatches(worker, task) {
  if (!worker || !task) {
    return false;
  }
  const workerAgentId = agentIdFromSessionKey(worker.sessionKey);
  const taskSessionKey = task.childSessionKey ?? task.sessionKey;
  if (taskSessionKey !== worker.sessionKey) {
    return false;
  }
  if (task.agentId && workerAgentId && task.agentId !== workerAgentId) {
    return false;
  }
  if (worker.runId) {
    return task.runId === worker.runId;
  }
  return task.childSessionKey === worker.sessionKey;
}

export function workerAgentMainSessionKey(workerSessionKey) {
  const agentId = agentIdFromSessionKey(workerSessionKey);
  return agentId ? `agent:${agentId}:main` : null;
}

export async function workerTaskLedgers(api, ownerSessionKey, worker) {
  return await withTaskBindings(async () => {
    const workerAgentId = agentIdFromSessionKey(worker.sessionKey) ?? undefined;
    const ownerAgentId = agentIdFromSessionKey(ownerSessionKey) ?? undefined;
    const workerMainSessionKey = workerAgentMainSessionKey(worker.sessionKey);
    const bindings = [
      {
        sessionKey: worker.sessionKey,
        agentId: workerAgentId,
      },
      ...(workerMainSessionKey
        ? [{ sessionKey: workerMainSessionKey, agentId: workerAgentId }]
        : []),
      ...(ownerSessionKey ? [{ sessionKey: ownerSessionKey, agentId: ownerAgentId }] : []),
    ];
    const seen = new Set();
    const ledgers = [];
    for (const binding of bindings) {
      const key = `${binding.sessionKey}\u0000${binding.agentId ?? ""}`;
      if (!binding.sessionKey || seen.has(key)) {
        continue;
      }
      seen.add(key);
      try {
        ledgers.push(await trackTaskBinding(api.runtime.tasks.runs.bindSession(binding)));
      } catch {
        // One inaccessible ledger must not hide an exact task from another owner/worker ledger.
      }
    }
    return ledgers;
  });
}

export async function taskForWorker(api, ownerSessionKey, worker) {
  return await withTaskBindings(async () => {
    if (!worker?.sessionKey) {
      return undefined;
    }
    const ledgers = await workerTaskLedgers(api, ownerSessionKey, worker);
    if (worker.taskId) {
      for (const runs of ledgers) {
        const exact = await runs.get(worker.taskId);
        if (workerTaskMatches(worker, exact)) {
          return exact;
        }
      }
    }
    const seenTaskIds = new Set();
    for (const runs of ledgers) {
      for (const task of await runs.list()) {
        if (!task?.id || seenTaskIds.has(task.id)) {
          continue;
        }
        seenTaskIds.add(task.id);
        if (workerTaskMatches(worker, task)) {
          return task;
        }
      }
    }
    return undefined;
  });
}

export async function currentWorkerTask(api, ownerSessionKey, state) {
  return await withTaskBindings(async () => {
    return await taskForWorker(api, ownerSessionKey, state.activeWorker);
  });
}

export function workerMatchesTerminalLifecycleEvent(worker, event) {
  if (
    !worker ||
    event?.stream !== "lifecycle" ||
    !new Set(["end", "error"]).has(event?.data?.phase)
  ) {
    return false;
  }
  if (worker.runId) {
    return event.runId === worker.runId;
  }
  return Boolean(event.sessionKey && event.sessionKey === worker.sessionKey);
}

export async function reconcileOrphanedWorker(api, ownerSessionKey, orphanedWorker, expectedFlow) {
  return await withTaskBindings(async () => {
    if (!orphanedWorker?.sessionKey) {
      return { safe: true, reason: "no_orphan" };
    }
    const task = await taskForWorker(api, ownerSessionKey, orphanedWorker);
    if (task && TERMINAL_TASK_STATUSES.has(task.status)) {
      return { safe: true, reason: "orphan_task_terminal", task };
    }
    const alive = sessionAlive(api, orphanedWorker.sessionKey);
    if (task && ACTIVE_TASK_STATUSES.has(task.status)) {
      for (const runs of await workerTaskLedgers(api, ownerSessionKey, orphanedWorker)) {
        const exact = await runs.get(task.id);
        if (!workerTaskMatches(orphanedWorker, exact) || typeof runs.cancel !== "function") {
          continue;
        }
        try {
          const cancelled = await runs.cancel({ taskId: task.id, expectedFlow, cfg: api.config });
          if (cancelled?.cancelled || TERMINAL_TASK_STATUSES.has(cancelled?.task?.status)) {
            return { safe: true, reason: "orphan_task_cancelled", task: cancelled.task ?? task };
          }
        } catch {
          // Liveness below remains the authoritative fallback for stale task projections.
        }
      }
    }
    if (alive === false) {
      return {
        safe: true,
        reason: task ? "orphan_session_dead_task_stale" : "orphan_session_dead",
      };
    }
    return {
      safe: false,
      reason: alive === true ? "orphan_session_still_alive" : "orphan_session_liveness_unknown",
    };
  });
}

export async function reconcileOrphanBeforeEffect(api, config, boundFlows, flow, state) {
  return await withTaskBindings(async () => {
    if (
      !state?.orphanedWorker ||
      !new Set(["review_completion_received", "worker_report_received"]).has(
        state.orphanedWorker.reason,
      )
    ) {
      return { safe: true, flow, state, reconciled: false };
    }
    const orphan = await reconcileOrphanedWorker(api, flow.ownerKey, state.orphanedWorker, {
      flowId: flow.flowId,
      revision: flow.revision,
    });
    if (!orphan.safe) {
      await scheduleWake(api, config, flow, "recover");
      return { safe: false, flow, state, reconciled: false, reason: orphan.reason };
    }
    const orphanedWorker = state.orphanedWorker;
    const reconciledAt = Date.now();
    const nextState = {
      ...state,
      orphanedWorker: null,
      lastGhostCleanup: {
        sessionKey: orphanedWorker.sessionKey,
        runId: orphanedWorker.runId ?? null,
        taskId: orphanedWorker.taskId ?? null,
        reason: orphan.reason,
        reconciledAt,
      },
      updatedAt: reconciledAt,
    };
    return {
      safe: true,
      flow: requireApplied(await persistState(boundFlows, flow, nextState)),
      state: nextState,
      reconciled: true,
      reason: orphan.reason,
    };
  });
}

export function sessionAlive(api, sessionKey) {
  if (typeof sessionKey !== "string" || !sessionKey) {
    return undefined;
  }
  const getSessionEntry = api.runtime?.agent?.session?.getSessionEntry;
  if (typeof getSessionEntry !== "function") {
    return undefined;
  }
  const agentId = agentIdFromSessionKey(sessionKey) ?? undefined;
  let entry;
  try {
    entry = getSessionEntry({ agentId, sessionKey });
  } catch {
    return undefined;
  }
  if (!entry || entry.endedAt || entry.abortedLastRun === true) {
    return false;
  }
  const status = typeof entry.status === "string" ? entry.status.toLowerCase() : "";
  if (DEAD_SESSION_STATUSES.has(status)) {
    return false;
  }
  return true;
}

export function workerSessionAlive(api, state) {
  return sessionAlive(api, state?.activeWorker?.sessionKey);
}

export function recoverExtras(api, state) {
  return {
    processStartedAt: processStartedAtMs(),
    sessionAlive: workerSessionAlive(api, state),
  };
}
