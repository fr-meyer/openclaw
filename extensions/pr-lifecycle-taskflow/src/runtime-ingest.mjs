import {
  CONTROLLER_ID,
  PHASE,
  applyCheckSuiteEvent,
  applyPullRequestEvent,
  applyReviewResult,
  createState,
  normalizeCheckSuiteEvent,
  recoverState,
  refreshPolicySnapshot,
  workerKindForPhase,
} from "./controller.mjs";
import {
  createFixedWindowLimiter,
  createInFlightLimiter,
  mapHttpError,
  parseBrokerReviewEvent,
  parseGitHubPullRequest,
  readJsonBody,
  requestKey,
  requireJsonPost,
  verifySha256Signature,
  writeJson,
} from "./http.mjs";
import {
  bindFlowsForSession,
  findMatchingFlow,
  ownerSessionKeyForRepo,
  stateOf,
} from "./runtime-config.mjs";
import { acquirePullRequestAdmissionLock } from "./runtime-contention.mjs";
import { requireLifecycleHost, withTaskBindings } from "./runtime-foundation.mjs";
import {
  workerGenerationForState,
  enforceModeGate,
  persistState,
  requireApplied,
  scheduleWake,
} from "./runtime-state-primitives.mjs";
import { dispatchWorker, applyEffect } from "./runtime-worker-orchestration.mjs";

export async function ingestPullRequest(api, config, event) {
  return await withTaskBindings(async () => {
    const policy = config.repositories.get(event.repo);
    if (!policy || !policy.enabled) {
      return { accepted: false, reason: "repository_not_enabled" };
    }
    let existingMatch = await findMatchingFlow(api, config, event.repo, event.prNumber);
    if (!existingMatch) {
      const admissionLock = acquirePullRequestAdmissionLock(api, event.repo, event.prNumber);
      if (!admissionLock) {
        const concurrentMatch = await findMatchingFlow(api, config, event.repo, event.prNumber);
        if (!concurrentMatch) {
          return { accepted: false, created: false, reason: "flow_admission_lock_held" };
        }
        existingMatch = concurrentMatch;
      } else {
        try {
          existingMatch = await findMatchingFlow(api, config, event.repo, event.prNumber);
          if (!existingMatch) {
            const boundFlows = await bindFlowsForSession(
              api,
              ownerSessionKeyForRepo(config, event.repo),
            );
            const state = createState(event, policy);
            requireLifecycleHost(api);
            const flow = await boundFlows.createManaged({
              controllerId: CONTROLLER_ID,
              dedupe: { stateFields: ["repo", "prNumber", "headSha"] },
              goal: `Bring ${event.repo}#${event.prNumber} to exact-head Broker merge-readiness`,
              status: "running",
              notifyPolicy: "silent",
              currentStep: state.phase,
              stateJson: state,
              createdAt: state.startedAt,
              updatedAt: state.updatedAt,
            });
            if (state.mode !== "observe") {
              await scheduleWake(api, config, flow, "continue");
            }
            return { accepted: true, created: true, flowId: flow.flowId, revision: flow.revision };
          }
        } finally {
          admissionLock.release();
        }
      }
    }
    const { boundFlows, flow: existing } = existingMatch;
    const currentState = stateOf(existing);
    const transition = applyPullRequestEvent(currentState, event, policy);
    if (
      currentState?.phase === PHASE.BLOCKED &&
      currentState.blocker === "dogfood_review_complete_live_remediation_not_enabled" &&
      policy.mode === "active"
    ) {
      const base = transition.changed ? transition.state : currentState;
      const refreshed = refreshPolicySnapshot(base, policy, Date.now(), {
        resetDeadline: true,
      }).state;
      const next = {
        ...refreshed,
        phase:
          refreshed.phase === PHASE.REVIEW_QUEUED
            ? PHASE.REVIEW_QUEUED
            : currentState.findings.length > 0
              ? PHASE.REMEDIATION_QUEUED
              : PHASE.REVIEW_QUEUED,
        workerGeneration: workerGenerationForState(currentState) + 1,
        wait: null,
        blocker: null,
        updatedAt: Date.now(),
      };
      const flow = requireApplied(await persistState(boundFlows, existing, next));
      await applyEffect(api, config, boundFlows, flow, next, "continue");
      return {
        accepted: true,
        created: false,
        flowId: flow.flowId,
        revision: flow.revision,
        reason: "active_mode_reopen_dogfood_block",
      };
    }
    if (
      currentState?.phase === PHASE.BLOCKED &&
      currentState.blocker === "publisher_not_attested" &&
      policy.mode === "active" &&
      policy.publisherBrokerId &&
      policy.publisherAttestationRef &&
      event.eventId.startsWith("owner-admit:")
    ) {
      const base = transition.changed ? transition.state : currentState;
      const refreshed = refreshPolicySnapshot(base, policy, Date.now(), {
        resetDeadline: true,
      }).state;
      const next = {
        ...refreshed,
        phase: currentState.findings.length > 0 ? PHASE.REMEDIATION_QUEUED : PHASE.REVIEW_QUEUED,
        workerGeneration: workerGenerationForState(currentState) + 1,
        activeWorker: null,
        wait: null,
        blocker: null,
        updatedAt: Date.now(),
      };
      const flow = requireApplied(await persistState(boundFlows, existing, next));
      await applyEffect(api, config, boundFlows, flow, next, "continue");
      return {
        accepted: true,
        created: false,
        flowId: flow.flowId,
        revision: flow.revision,
        reason: "owner_admit_reopen_attested_publisher",
      };
    }
    if (
      currentState?.phase === PHASE.BLOCKED &&
      currentState.blocker === "review_fix_cycle_budget_exhausted" &&
      policy.mode === "active" &&
      policy.maxCycles > currentState.cycle &&
      event.eventId.startsWith("owner-admit:")
    ) {
      const base = transition.changed ? transition.state : currentState;
      const refreshed = refreshPolicySnapshot(base, policy, Date.now(), {
        resetDeadline: true,
      }).state;
      const next = {
        ...refreshed,
        phase: currentState.findings.length > 0 ? PHASE.REMEDIATION_QUEUED : PHASE.REVIEW_QUEUED,
        // A reopened flow is a new execution generation; reusing the old key adopts stale history.
        workerGeneration: workerGenerationForState(currentState) + 1,
        retryCount: 0,
        infrastructureRetryCount: 0,
        infrastructureRetryAt: null,
        infrastructureLastFailure: null,
        orphanedWorker: null,
        activeWorker: null,
        wait: null,
        blocker: null,
        updatedAt: Date.now(),
      };
      const flow = requireApplied(await persistState(boundFlows, existing, next));
      await applyEffect(api, config, boundFlows, flow, next, "continue");
      return {
        accepted: true,
        created: false,
        flowId: flow.flowId,
        revision: flow.revision,
        reason: "owner_admit_reopen_cycle_budget",
      };
    }
    if (
      currentState?.phase === PHASE.BLOCKED &&
      currentState.blocker === "wall_time_budget_exhausted" &&
      policy.mode === "active" &&
      event.eventId.startsWith("owner-admit:")
    ) {
      const base = transition.changed ? transition.state : currentState;
      const refreshed = refreshPolicySnapshot(base, policy, Date.now(), {
        resetDeadline: true,
      }).state;
      const next = {
        ...refreshed,
        phase: currentState.findings.length > 0 ? PHASE.REMEDIATION_QUEUED : PHASE.REVIEW_QUEUED,
        workerGeneration: workerGenerationForState(currentState) + 1,
        activeWorker: null,
        wait: null,
        blocker: null,
        updatedAt: Date.now(),
      };
      const flow = requireApplied(await persistState(boundFlows, existing, next));
      await applyEffect(api, config, boundFlows, flow, next, "continue");
      return {
        accepted: true,
        created: false,
        flowId: flow.flowId,
        revision: flow.revision,
        reason: "owner_admit_reopen_wall_time_budget",
      };
    }
    if (
      currentState?.phase === PHASE.BLOCKED &&
      typeof currentState.blocker === "string" &&
      (currentState.blocker.startsWith("worker_failure_exhausted:") ||
        currentState.blocker === "worker_completed_without_structured_report") &&
      event.eventId.startsWith("owner-admit:")
    ) {
      const base = transition.changed ? transition.state : currentState;
      const refreshed = refreshPolicySnapshot(base, policy, Date.now(), {
        resetDeadline: true,
      }).state;
      const infrastructureRecovery = recoverState(refreshed, undefined, Date.now());
      if (infrastructureRecovery.reason === "legacy_infrastructure_block_requeued") {
        const flow = requireApplied(
          await persistState(boundFlows, existing, infrastructureRecovery.state),
        );
        await applyEffect(
          api,
          config,
          boundFlows,
          flow,
          infrastructureRecovery.state,
          infrastructureRecovery.effect,
        );
        return {
          accepted: true,
          created: false,
          flowId: flow.flowId,
          revision: flow.revision,
          reason: "owner_admit_requeue_infrastructure_failure",
        };
      }
      const next = {
        ...refreshed,
        phase:
          policy.mode === "active" && currentState.findings.length > 0
            ? PHASE.REMEDIATION_QUEUED
            : PHASE.REVIEW_QUEUED,
        retryCount: 0,
        infrastructureRetryCount: 0,
        workerGeneration: workerGenerationForState(currentState) + 1,
        infrastructureRetryAt: null,
        infrastructureLastFailure: null,
        orphanedWorker: null,
        activeWorker: null,
        wait: null,
        blocker: null,
        updatedAt: Date.now(),
      };
      const flow = requireApplied(await persistState(boundFlows, existing, next));
      await applyEffect(api, config, boundFlows, flow, next, "continue");
      return {
        accepted: true,
        created: false,
        flowId: flow.flowId,
        revision: flow.revision,
        reason: "owner_admit_reopen_worker_failure",
      };
    }
    if (
      currentState?.phase === PHASE.BLOCKED &&
      typeof currentState.blocker === "string" &&
      (currentState.blocker === "findings_unusable" ||
        currentState.blocker === "changes_requested_without_actionable_paths") &&
      event.eventId.startsWith("owner-admit:")
    ) {
      const base = transition.changed ? transition.state : currentState;
      const refreshed = refreshPolicySnapshot(base, policy, Date.now(), {
        resetDeadline: true,
      }).state;
      const next = {
        ...refreshed,
        phase: PHASE.REVIEW_QUEUED,
        review: null,
        findings: [],
        retryCount: 0,
        infrastructureRetryCount: 0,
        workerGeneration: workerGenerationForState(currentState) + 1,
        infrastructureRetryAt: null,
        infrastructureLastFailure: null,
        orphanedWorker: null,
        activeWorker: null,
        wait: null,
        blocker: null,
        updatedAt: Date.now(),
      };
      const flow = requireApplied(await persistState(boundFlows, existing, next));
      await applyEffect(api, config, boundFlows, flow, next, "continue");
      return {
        accepted: true,
        created: false,
        flowId: flow.flowId,
        revision: flow.revision,
        reason: "owner_admit_reopen_unusable_findings",
      };
    }
    if (event.eventId.startsWith("owner-admit:")) {
      const base = transition.changed ? transition.state : currentState;
      const refreshed = refreshPolicySnapshot(base, policy, Date.now(), {
        resetDeadline: true,
      }).state;
      const flow = requireApplied(await persistState(boundFlows, existing, refreshed));
      const effect =
        workerKindForPhase(refreshed.phase) && !refreshed.activeWorker ? "continue" : "none";
      await applyEffect(api, config, boundFlows, flow, refreshed, effect);
      return {
        accepted: true,
        created: false,
        flowId: flow.flowId,
        revision: flow.revision,
        reason: "owner_admit_policy_refreshed",
      };
    }
    if (!transition.changed) {
      return {
        accepted: true,
        created: false,
        flowId: existing.flowId,
        revision: existing.revision,
        reason: transition.reason,
      };
    }
    const flow = requireApplied(await persistState(boundFlows, existing, transition.state));
    await applyEffect(api, config, boundFlows, flow, transition.state, transition.effect);
    return {
      accepted: true,
      created: false,
      flowId: flow.flowId,
      revision: flow.revision,
      reason: transition.reason,
    };
  });
}

export async function ingestReviewResult(api, config, event) {
  return await withTaskBindings(async () => {
    const match = await findMatchingFlow(api, config, event.repo, event.prNumber);
    if (!match) {
      return { accepted: false, reason: "matching_active_flow_not_found" };
    }
    const { boundFlows, flow } = match;
    const transition = applyReviewResult(stateOf(flow), event);
    if (!transition.changed) {
      return {
        accepted: true,
        flowId: flow.flowId,
        revision: flow.revision,
        reason: transition.reason,
      };
    }
    let nextState = transition.state;
    let nextEffect = transition.effect;
    const gate = enforceModeGate(nextState);
    if (gate.changed) {
      nextState = gate.state;
      nextEffect = gate.effect;
    }
    const updated = requireApplied(await persistState(boundFlows, flow, nextState));
    await applyEffect(api, config, boundFlows, updated, nextState, nextEffect, {
      dispatchImmediately: true,
    });
    const current = (await boundFlows.get(updated.flowId)) ?? updated;
    return { accepted: true, flowId: current.flowId, revision: current.revision };
  });
}

export async function ingestCheckSuite(api, config, eventInput) {
  return await withTaskBindings(async () => {
    const event = normalizeCheckSuiteEvent(eventInput);
    const match = await findMatchingFlow(api, config, event.repo, event.prNumber, {
      headSha: event.headSha,
      nonTerminalOnly: true,
    });
    if (!match) {
      return { accepted: false, reason: "matching_active_flow_not_found" };
    }
    const { boundFlows, flow } = match;
    const transition = applyCheckSuiteEvent(stateOf(flow), event);
    if (!transition.changed) {
      return {
        accepted: true,
        flowId: flow.flowId,
        revision: flow.revision,
        reason: transition.reason,
      };
    }
    let updated = requireApplied(await persistState(boundFlows, flow, transition.state));
    if (transition.effect === "continue") {
      updated = await dispatchWorker(api, config, boundFlows, updated);
    }
    const current = (await boundFlows.get(updated.flowId)) ?? updated;
    return {
      accepted: true,
      flowId: current.flowId,
      revision: current.revision,
      reason: transition.reason,
    };
  });
}

export function createRouteHandler(options) {
  const rateLimiter = createFixedWindowLimiter();
  const inFlightLimiter = createInFlightLimiter();
  return async (req, res) => {
    const key = requestKey(req, options.kind);
    let release;
    try {
      requireJsonPost(req);
      if (!rateLimiter.allow(key)) {
        throw new Error("rate_limited");
      }
      release = inFlightLimiter.acquire(key);
      if (!release) {
        throw new Error("too_many_in_flight");
      }
      const { body, json } = await readJsonBody(req, options.bodyOptions);
      const signatureHeader =
        options.kind === "github"
          ? req.headers["x-hub-signature-256"]
          : req.headers["x-broker-signature-256"];
      const signature = Array.isArray(signatureHeader) ? signatureHeader[0] : signatureHeader;
      if (!verifySha256Signature(body, options.secret, signature)) {
        throw new Error("invalid_signature");
      }
      const event =
        options.kind === "github"
          ? parseGitHubPullRequest(req, json)
          : parseBrokerReviewEvent(req, json);
      const events = Array.isArray(event) ? event : [event];
      const outcomes = [];
      for (const item of events) {
        outcomes.push(await options.ingest(item));
      }
      if (outcomes.some((outcome) => outcome?.reason === "flow_admission_lock_held")) {
        writeJson(res, 503, {
          ok: false,
          error: "flow_admission_lock_held",
          retryable: true,
        });
        return true;
      }
      const response = outcomes.length === 1 ? outcomes[0] : { accepted: true, outcomes };
      writeJson(res, 202, { ok: true, ...response });
      return true;
    } catch (error) {
      const mapped = mapHttpError(error);
      writeJson(res, mapped.status, { ok: false, error: mapped.code });
      return true;
    } finally {
      release?.();
    }
  };
}
