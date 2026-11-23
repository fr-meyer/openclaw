import { blockState } from "./controller-state.mjs";
import { PHASE } from "./controller.mjs";
import { flowWaitJson, ownerSessionKeyForRepo, stateOf } from "./runtime-config.mjs";
import {
  NOTIFICATION_KIND_PHASE_TRUTH,
  TOOL_NAME,
  withTaskBindings,
} from "./runtime-foundation.mjs";

export function workerGenerationForState(state) {
  return Math.max(0, Number(state?.workerGeneration) || 0);
}

export function primaryFixerFailureGrant(flow, state) {
  const failure = state.primaryFixerFailure;
  if (
    !failure ||
    failure.consumedAt !== null ||
    failure.flowId !== flow.flowId ||
    failure.headSha !== state.headSha ||
    failure.cycle !== state.cycle ||
    failure.primaryModel !== state.fixerModel ||
    failure.ref !==
      `primary-failure:${failure.flowId}:${failure.headSha}:` +
        `${failure.cycle}:${failure.workerTaskId}`
  ) {
    return null;
  }
  return {
    ref: failure.ref,
    flowId: failure.flowId,
    reason: failure.reason,
    primaryModel: failure.primaryModel,
    headSha: failure.headSha,
    cycle: failure.cycle,
  };
}

export function processStartedAtMs() {
  return Date.now() - Math.floor(process.uptime() * 1000);
}

export async function persistState(boundFlows, flow, initialState) {
  return await withTaskBindings(async () => {
    let state = initialState;
    const nextRevision = flow.revision + 1;
    state = {
      ...state,
      flowId: flow.flowId,
      latestExternalMilestone:
        state.latestExternalMilestone && state.latestExternalMilestone.observedRevision === null
          ? { ...state.latestExternalMilestone, observedRevision: nextRevision }
          : state.latestExternalMilestone,
      terminalSupersession:
        state.terminalSupersession && state.terminalSupersession.sourceRevision == null
          ? { ...state.terminalSupersession, sourceRevision: nextRevision }
          : state.terminalSupersession,
    };
    const common = {
      flowId: flow.flowId,
      expectedRevision: flow.revision,
      currentStep: state.phase,
      stateJson: state,
      updatedAt: state.updatedAt,
    };
    if (state.phase === PHASE.MERGED) {
      return await boundFlows.finish({
        flowId: flow.flowId,
        expectedRevision: flow.revision,
        stateJson: state,
        updatedAt: state.updatedAt,
        endedAt: state.updatedAt,
      });
    }
    if (state.phase === PHASE.FAILED) {
      return await boundFlows.fail({
        flowId: flow.flowId,
        expectedRevision: flow.revision,
        stateJson: state,
        blockedSummary: state.blocker ?? "PR lifecycle failed",
        updatedAt: state.updatedAt,
        endedAt: state.updatedAt,
      });
    }
    if (
      state.phase === PHASE.BLOCKED ||
      state.phase === PHASE.MERGE_READY ||
      state.phase === PHASE.REVIEW_WAITING ||
      state.phase === PHASE.WAITING_HEAD_EVENT
    ) {
      return await boundFlows.setWaiting({
        ...common,
        waitJson: flowWaitJson(state),
        ...(state.phase === PHASE.BLOCKED
          ? { blockedSummary: state.blocker ?? "Manual intervention required" }
          : {}),
      });
    }
    return await boundFlows.resume({ ...common, status: "running" });
  });
}

export function requireApplied(mutation) {
  if (!mutation.applied) {
    const error = new Error(`flow_mutation_${mutation.code}`);
    error.current = mutation.current;
    throw error;
  }
  return mutation.flow;
}

export function recoveryTag(flowId) {
  return `mprl-${flowId.replace(/[^a-zA-Z0-9-]/g, "").slice(0, 24)}`;
}

export function notificationTag(flowId) {
  return `mprn-${flowId.replace(/[^a-zA-Z0-9-]/g, "").slice(0, 24)}`;
}

export async function clearWake(api, config, flow) {
  const state = stateOf(flow);
  const sessionKeys = new Set([flow?.ownerKey, ownerSessionKeyForRepo(config, state?.repo)]);
  for (const sessionKey of sessionKeys) {
    if (!sessionKey) {
      continue;
    }
    await api.session.workflow.unscheduleSessionTurnsByTag({
      sessionKey,
      tag: recoveryTag(flow.flowId),
    });
  }
}

export async function scheduleWake(api, config, flow, kind) {
  const state = stateOf(flow);
  const sessionKey = ownerSessionKeyForRepo(config, state?.repo);
  if (!sessionKey) {
    return undefined;
  }
  const defaultDelayMs = config.recoveryDelayMinutes * 60_000;
  const retryAt = Number.isFinite(state?.infrastructureRetryAt)
    ? state.infrastructureRetryAt
    : null;
  const delayMs =
    kind === "continue"
      ? 1_000
      : Math.max(defaultDelayMs, retryAt === null ? 0 : retryAt - Date.now());
  const action = kind === "continue" ? "continue" : "recover";
  const tag = recoveryTag(flow.flowId);
  await clearWake(api, config, flow);
  return await api.session.workflow.scheduleSessionTurn({
    sessionKey,
    agentId: sessionKey.split(":")[1] || undefined,
    message:
      `Native PR lifecycle wake. Call ${TOOL_NAME} exactly once with ` +
      `${JSON.stringify({ action, flowId: flow.flowId, expectedRevision: flow.revision })}. ` +
      "Do not perform repository work in this controller turn. Summarize only the returned state.",
    delayMs,
    deleteAfterRun: true,
    deliveryMode: "none",
    name: `Broker PR lifecycle ${action} ${flow.flowId}`,
    tag,
  });
}

export function notificationEventId(flow, state, kind) {
  return `mprn:${flow.flowId}:${flow.revision}:${state.headSha}:${state.phase}:${kind}`;
}

export function notificationKindMatchesPhase(state, kind) {
  return NOTIFICATION_KIND_PHASE_TRUTH[kind]?.(state) === true;
}

export function renderNotification(state, kind) {
  const label = `${state.repo}#${state.prNumber}`;
  if (kind === "merged") {
    return (
      `${label} merged into dev from exact reviewed head ${state.headSha}. ` +
      "Cause: every exact-head review, finding, required-check, mergeability, actor, and authorization gate passed. " +
      "Safety: the verified merge receipt is retained and no main/master merge was permitted. " +
      "Action: plugin-owned wakes and stale notifications were superseded. Next gate: none."
    );
  }
  if (kind === "approval_gate") {
    return (
      `${label} is merge-ready at exact head ${state.headSha}. ` +
      `Cause: review ${state.mergeReady?.reviewId ?? "unidentified"} has complete coverage and zero findings. ` +
      "Safety: no merge was attempted without a current scope-bound authorization. " +
      "Action: record an explicit authorization for this exact base branch in repository policy, then call the owner-only authorize action with this flowId and its current expectedRevision."
    );
  }
  if (kind === "check_wait") {
    const failed = state.mergeGates?.gates?.requiredChecks?.failed ?? [];
    const pending = state.mergeGates?.gates?.requiredChecks?.pending ?? [];
    const names =
      [...failed, ...pending].map((check) => check.name).join(", ") || "required checks";
    return (
      `${label} is waiting at exact head ${state.headSha}. Cause: ${names} are not green. ` +
      "Safety: the PR remains unmerged and no retry budget is consumed by a deterministic check result. " +
      "Action: the controller parked on a check_suite event. Next gate: a fresh check event for this exact head."
    );
  }
  return (
    `${label} is blocked at exact head ${state.headSha}. Cause: ${state.blocker ?? "manual intervention required"}. ` +
    "Safety: the PR remains unmerged and plugin-owned continuation artifacts were superseded. " +
    "Action: the lifecycle stopped fail-closed. Next gate: resolve the named blocker, then use owner admission."
  );
}

export async function clearNotification(api, config, flow) {
  if (!config.notificationSessionKey) {
    return undefined;
  }
  return await api.session.workflow.unscheduleSessionTurnsByTag({
    sessionKey: config.notificationSessionKey,
    tag: notificationTag(flow.flowId),
  });
}

export async function clearTerminalArtifacts(api, config, flow) {
  await clearWake(api, config, flow);
  await clearNotification(api, config, flow);
  return {
    wakesCancelled: true,
    notificationsSuperseded: true,
    workerEventsClosed: true,
  };
}

export function matchingNotificationOutcome(deliveries, kind, state) {
  return (Array.isArray(deliveries) ? deliveries : []).find(
    (delivery) =>
      delivery.kind === kind &&
      delivery.headSha === state.headSha &&
      delivery.phase === state.phase,
  );
}

export function notificationDeliveryConfirmed(delivery) {
  return delivery?.deliveryState === "confirmed" && Number.isInteger(delivery.confirmedAt);
}

export function notificationDeliveryRetryable(delivery) {
  return (
    (delivery?.deliveryState === "pending" || delivery?.deliveryState === "sending") &&
    typeof delivery?.message === "string" &&
    delivery.message.length > 0
  );
}

export async function notifyLifecycleOutcome(api, config, flow, state, kind) {
  if (!config.notificationSessionKey) {
    return undefined;
  }
  const existing = matchingNotificationOutcome(state.notificationDeliveries, kind, state);
  if (notificationDeliveryConfirmed(existing)) {
    return undefined;
  }
  const candidate =
    existing?.eventId && Number.isInteger(existing.sourceRevision)
      ? {
          flowId: flow.flowId,
          expectedRevision: existing.sourceRevision,
          headSha: existing.headSha,
          phase: existing.phase,
          notificationKind: kind,
          notificationEventId: existing.eventId,
        }
      : {
          flowId: flow.flowId,
          expectedRevision: flow.revision,
          headSha: state.headSha,
          phase: state.phase,
          notificationKind: kind,
          notificationEventId: notificationEventId(flow, state, kind),
        };
  const tag = notificationTag(flow.flowId);
  await clearNotification(api, config, flow);
  return await api.session.workflow.scheduleSessionTurn({
    sessionKey: config.notificationSessionKey,
    message:
      `Revision-fenced PR lifecycle notification. Call ${TOOL_NAME} exactly once with ` +
      `${JSON.stringify({ action: "notify", ...candidate })}. ` +
      "If deliver is true, call " +
      `${TOOL_NAME} exactly once with ` +
      `${JSON.stringify({ action: "notify", ...candidate, acknowledge: true })} ` +
      "to confirm that exact notification event and revision before emitting any user-facing text. " +
      "Emit the returned message exactly and nothing else only after acknowledgement returns confirmed:true. " +
      "If acknowledgement is rejected or not confirmed, emit no user-facing text. " +
      "If deliver is false, emit no user-facing text and stop. Do not call message, sessions_send, or any other tool.",
    delayMs: 1_000,
    deleteAfterRun: true,
    deliveryMode: "announce",
    name: `PR lifecycle ${kind} ${state.repo}#${state.prNumber}`,
    tag,
  });
}

export function notificationAlreadyRendered(state, kind) {
  return (Array.isArray(state.notificationDeliveries) ? state.notificationDeliveries : []).some(
    (delivery) =>
      delivery.kind === kind &&
      delivery.headSha === state.headSha &&
      notificationDeliveryConfirmed(delivery),
  );
}

export async function persistTerminalCleanup(api, config, boundFlows, flow, state, kind) {
  return await withTaskBindings(async () => {
    const cleanup = await clearTerminalArtifacts(api, config, flow);
    const eventId =
      state.terminalSupersession?.eventId ?? `terminal:${flow.flowId}:${state.headSha}:${kind}`;
    let terminalFlow = flow;
    let terminalState = state;
    if (state.terminalCleanup?.eventId !== eventId) {
      terminalState = {
        ...state,
        terminalCleanup: { schemaVersion: 1, eventId, ...cleanup, completedAt: Date.now() },
        updatedAt: Date.now(),
      };
      terminalFlow = requireApplied(await persistState(boundFlows, flow, terminalState));
      terminalState = stateOf(terminalFlow);
    }
    await notifyLifecycleOutcome(api, config, terminalFlow, terminalState, kind);
    return terminalFlow;
  });
}

export async function notifyMergeReady(api, config, flow, state) {
  return await notifyLifecycleOutcome(api, config, flow, state, "approval_gate");
}

export function enforceModeGate(state, now = Date.now()) {
  if (state.mode === "observe") {
    return { changed: false, state, effect: "none", reason: "observe_mode" };
  }
  if (state.mode === "dogfood" && state.phase === PHASE.REMEDIATION_QUEUED) {
    return blockState(state, "dogfood_review_complete_live_remediation_not_enabled", now);
  }
  if (state.phase === PHASE.REMEDIATION_QUEUED && state.publisherBoundary?.ready !== true) {
    return blockState(state, "publisher_not_attested", now);
  }
  if (state.phase === PHASE.REMEDIATION_QUEUED && !state.remediatorProfile) {
    return blockState(state, "remediator_profile_missing", now);
  }
  if (
    state.phase === PHASE.REMEDIATION_QUEUED &&
    state.remediatorProfileDigest !== state.configuredRemediatorProfileDigest
  ) {
    return blockState(state, "remediator_profile_digest_drift", now);
  }
  return { changed: false, state, effect: "continue", reason: "mode_allows_step" };
}

export function flowWorkspacePath(policy, state) {
  const recorded =
    (typeof state?.flowWorkspace?.path === "string" && state.flowWorkspace.path.trim()) ||
    (typeof state?.workspacePreflight?.workspace === "string" &&
      state.workspacePreflight.workspace.trim()) ||
    "";
  if (recorded) {
    return recorded;
  }
  return policy.workspace;
}
