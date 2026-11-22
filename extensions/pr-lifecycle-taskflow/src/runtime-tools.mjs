import { isTerminalState } from "./controller-state.mjs";
import {
  PHASE,
  applyWorkerReport,
  authorizeMergeReady,
  normalizePullRequestEvent,
  recoverState,
  refreshPolicySnapshot,
} from "./controller.mjs";
import {
  findMatchingFlow,
  ownerSessionKeyForRepo,
  resolveFlowBinding,
  result,
  stateOf,
} from "./runtime-config.mjs";
import { TOOL_NAME, withTaskBindings } from "./runtime-foundation.mjs";
import { ingestPullRequest } from "./runtime-ingest.mjs";
import { reconcileRemediationEvidence } from "./runtime-remediation.mjs";
import {
  clearWake,
  enforceModeGate,
  matchingNotificationOutcome,
  notificationAlreadyRendered,
  notificationDeliveryConfirmed,
  notificationDeliveryRetryable,
  notificationEventId,
  notificationKindMatchesPhase,
  notifyMergeReady,
  persistState,
  persistTerminalCleanup,
  renderNotification,
  requireApplied,
  scheduleWake,
} from "./runtime-state-primitives.mjs";
import {
  canInspectStatus,
  currentWorkerTask,
  reconcileOrphanBeforeEffect,
  recoverExtras,
  requireOwnerContext,
  statusView,
} from "./runtime-status-primitives.mjs";
import { dispatchWorker, reconcileGithubHead } from "./runtime-worker-orchestration.mjs";
import { applyEffect } from "./runtime-worker-orchestration.mjs";
import { isWorkspaceHeadMismatchBlock } from "./runtime-workspace-primitives.mjs";
import { revalidateWorkspaceHeadBlock } from "./runtime-workspace.mjs";

export function toolSchema() {
  return {
    type: "object",
    additionalProperties: false,
    properties: {
      action: {
        type: "string",
        enum: ["status", "continue", "recover", "report", "admit", "authorize", "notify"],
      },
      flowId: { type: "string", minLength: 1 },
      repo: { type: "string", minLength: 1 },
      prNumber: { type: "integer", minimum: 1 },
      baseSha: { type: "string", pattern: "^[0-9a-f]{40}$" },
      baseRef: { type: "string", minLength: 1 },
      expectedRevision: { type: "integer", minimum: 0 },
      kind: { type: "string", enum: ["review", "remediation"] },
      outcome: { type: "string", minLength: 1 },
      headSha: { type: "string", pattern: "^[0-9a-f]{40}$" },
      cycle: { type: "integer", minimum: 0 },
      reviewId: { type: "string" },
      summary: { type: "string" },
      claimRef: { type: "string" },
      newHeadSha: { type: "string", pattern: "^[0-9a-f]{40}$" },
      coverageComplete: { type: "boolean" },
      retryAllowed: { type: "boolean" },
      testsPassed: { type: "boolean" },
      publicationConfirmed: { type: "boolean" },
      verificationComplete: { type: "boolean" },
      fixerModel: { type: "string", minLength: 1 },
      fixerAttested: { type: "boolean" },
      fixerAttestationRef: { type: "string", minLength: 1 },
      fixerFallbackReason: { type: "string", minLength: 1 },
      fixerPrimaryFailureRef: { type: "string", minLength: 1 },
      profileDigest: { type: "string", pattern: "^[0-9a-f]{64}$" },
      outcomeClass: {
        type: "string",
        enum: [
          "success",
          "preflight_failure",
          "policy_rejection",
          "test_failure",
          "publication_failure",
          "execution_failure",
          "protocol_violation",
        ],
      },
      finalStage: { type: "string", minLength: 1, maxLength: 120 },
      phase: { type: "string", minLength: 1 },
      notificationKind: {
        type: "string",
        enum: ["merged", "blocked", "approval_gate", "check_wait"],
      },
      notificationEventId: { type: "string", minLength: 1, maxLength: 500 },
      acknowledge: { type: "boolean" },
      findings: {
        type: "array",
        maxItems: 20,
        items: {
          type: "object",
          additionalProperties: false,
          required: ["id", "severity", "summary"],
          properties: {
            id: { type: "string" },
            severity: { type: "string", enum: ["blocker", "high", "medium", "low", "info"] },
            summary: { type: "string" },
            path: { type: "string" },
            line: { type: "integer", minimum: 1 },
            evidence: { type: "string" },
          },
        },
      },
    },
    required: ["action"],
  };
}

export function createControllerTool(api, config, ctx) {
  return {
    name: TOOL_NAME,
    label: "Broker PR lifecycle",
    description:
      "Inspect, continue, recover, authorize, or report one exact-head Broker PR lifecycle TaskFlow.",
    parameters: toolSchema(),
    execute: async (_toolCallId, input) => {
      return await withTaskBindings(async () => {
        if (!config.enabled || !config.ownerSessionKey) {
          throw new Error("pr_lifecycle_taskflow_is_not_enabled");
        }
        if (input.action === "admit") {
          const event = normalizePullRequestEvent({
            eventId: `owner-admit:${Date.now()}:${input.headSha ?? "missing"}`,
            action: "synchronize",
            repo: input.repo,
            prNumber: input.prNumber,
            headSha: input.headSha,
            baseSha: input.baseSha,
            baseRef: input.baseRef,
            headRepo: input.repo,
          });
          const exactResolved = input.flowId
            ? await resolveFlowBinding(api, config, input.flowId, ctx.sessionKey)
            : null;
          const exactState = exactResolved ? stateOf(exactResolved.flow) : null;
          if (
            exactState &&
            (exactState.repo !== event.repo || exactState.prNumber !== event.prNumber)
          ) {
            throw new Error("flow_scope_mismatch");
          }
          requireOwnerContext(ctx, ownerSessionKeyForRepo(config, exactState?.repo ?? event.repo));
          const matching =
            exactResolved ?? (await findMatchingFlow(api, config, event.repo, event.prNumber));
          if (matching && isWorkspaceHeadMismatchBlock(stateOf(matching.flow))) {
            if (!input.flowId) {
              throw new Error("workspace_revalidation_requires_flow_id");
            }
            const revalidated = await revalidateWorkspaceHeadBlock(
              api,
              config,
              matching,
              input,
              event,
            );
            return result(revalidated);
          }
          const ingested = await ingestPullRequest(api, config, event);
          const match = await findMatchingFlow(api, config, event.repo, event.prNumber);
          return result({
            ok: true,
            admit: ingested,
            flow: match?.flow ? statusView(match.flow) : null,
          });
        }
        if (!input.flowId) {
          throw new Error("flowId is required");
        }
        const resolved = await resolveFlowBinding(api, config, input.flowId, ctx.sessionKey);
        const boundFlows = resolved.boundFlows;
        let flow = resolved.flow;
        let state = stateOf(flow);
        const ownerKey = ownerSessionKeyForRepo(config, state.repo);
        if (input.action === "status") {
          const state = stateOf(flow);
          if (!canInspectStatus(config, ctx, ownerKey, state)) {
            throw new Error("flow_status_not_visible_to_this_session");
          }
          return result(statusView(flow));
        }
        if (input.action === "notify") {
          if (
            !new Set(["merged", "blocked", "approval_gate", "check_wait"]).has(
              input.notificationKind,
            )
          ) {
            throw new Error("notification_kind_invalid");
          }
          if (!config.notificationSessionKey || ctx.sessionKey !== config.notificationSessionKey) {
            throw new Error("notification_action_requires_notification_sink");
          }
          const exactCandidate =
            input.expectedRevision === flow.revision &&
            input.headSha === state.headSha &&
            input.phase === state.phase &&
            input.notificationEventId === notificationEventId(flow, state, input.notificationKind);
          if (!notificationKindMatchesPhase(state, input.notificationKind)) {
            if (exactCandidate) {
              throw new Error("notification_kind_phase_mismatch");
            }
            return result({
              ok: true,
              deliver: false,
              superseded: true,
              sourceRevision: input.expectedRevision ?? null,
              currentRevision: flow.revision,
              currentHeadSha: state.headSha,
              currentPhase: state.phase,
            });
          }
          const deliveries = Array.isArray(state.notificationDeliveries)
            ? state.notificationDeliveries
            : [];
          const existingAttempt = deliveries.find(
            (delivery) => delivery.eventId === input.notificationEventId,
          );
          const sameAttemptTarget =
            existingAttempt?.sourceRevision === input.expectedRevision &&
            existingAttempt?.headSha === state.headSha &&
            existingAttempt?.phase === state.phase &&
            existingAttempt?.kind === input.notificationKind &&
            input.headSha === state.headSha &&
            input.phase === state.phase;
          if (sameAttemptTarget && notificationDeliveryConfirmed(existingAttempt)) {
            return result({ ok: true, deliver: false, duplicate: true, confirmed: true });
          }
          if (input.acknowledge === true) {
            if (sameAttemptTarget && notificationDeliveryRetryable(existingAttempt)) {
              const confirmedAt = Date.now();
              const next = {
                ...state,
                notificationDeliveries: deliveries.map((delivery) =>
                  delivery.eventId === input.notificationEventId &&
                  delivery.sourceRevision === input.expectedRevision
                    ? {
                        ...delivery,
                        deliveryState: "confirmed",
                        confirmedAt,
                      }
                    : delivery,
                ),
                updatedAt: confirmedAt,
              };
              flow = requireApplied(await persistState(boundFlows, flow, next));
              return result({
                ok: true,
                deliver: false,
                confirmed: true,
                eventId: input.notificationEventId,
                sourceRevision: input.expectedRevision,
                message: existingAttempt.message,
              });
            }
            if (exactCandidate) {
              throw new Error("notification_acknowledgement_missing_delivery");
            }
            return result({
              ok: true,
              deliver: false,
              superseded: true,
              confirmed: false,
              sourceRevision: input.expectedRevision ?? null,
              currentRevision: flow.revision,
              currentHeadSha: state.headSha,
              currentPhase: state.phase,
            });
          }
          if (sameAttemptTarget && notificationDeliveryRetryable(existingAttempt)) {
            return result({
              ok: true,
              deliver: true,
              retry: true,
              eventId: input.notificationEventId,
              sourceRevision: input.expectedRevision,
              message: existingAttempt.message,
            });
          }
          if (!exactCandidate) {
            return result({
              ok: true,
              deliver: false,
              superseded: true,
              sourceRevision: input.expectedRevision ?? null,
              currentRevision: flow.revision,
              currentHeadSha: state.headSha,
              currentPhase: state.phase,
            });
          }
          const existingSameOutcome = matchingNotificationOutcome(
            deliveries,
            input.notificationKind,
            state,
          );
          if (notificationDeliveryConfirmed(existingSameOutcome)) {
            return result({ ok: true, deliver: false, duplicate: true, confirmed: true });
          }
          if (notificationDeliveryRetryable(existingSameOutcome)) {
            return result({
              ok: true,
              deliver: true,
              retry: true,
              eventId: existingSameOutcome.eventId,
              sourceRevision: existingSameOutcome.sourceRevision,
              message: existingSameOutcome.message,
            });
          }
          const message = renderNotification(state, input.notificationKind);
          const next = {
            ...state,
            notificationDeliveries: [
              ...deliveries,
              {
                eventId: input.notificationEventId,
                sourceRevision: flow.revision,
                headSha: state.headSha,
                phase: state.phase,
                kind: input.notificationKind,
                deliveryState: "pending",
                message,
                renderedAt: Date.now(),
              },
            ].slice(-32),
            updatedAt: Date.now(),
          };
          flow = requireApplied(await persistState(boundFlows, flow, next));
          return result({
            ok: true,
            deliver: true,
            retry: false,
            eventId: input.notificationEventId,
            sourceRevision: input.expectedRevision,
            message,
          });
        }
        if (input.action === "report") {
          const state = stateOf(flow);
          const transition = applyWorkerReport(state, input, ctx.sessionKey);
          flow = requireApplied(await persistState(boundFlows, flow, transition.state));
          let nextState = transition.state;
          let nextEffect = transition.effect;
          const gate = enforceModeGate(nextState);
          if (gate.changed) {
            nextState = gate.state;
            nextEffect = gate.effect;
            flow = requireApplied(await persistState(boundFlows, flow, nextState));
          }
          await applyEffect(api, config, boundFlows, flow, nextState, nextEffect);
          return result({ ok: true, transition: transition.reason, flow: statusView(flow) });
        }
        requireOwnerContext(ctx, ownerKey);
        if (input.action === "authorize" && !Number.isInteger(input.expectedRevision)) {
          throw new Error("merge_authorization_requires_expected_revision");
        }
        if (input.expectedRevision !== undefined && input.expectedRevision !== flow.revision) {
          return result({
            ok: true,
            staleWake: true,
            expectedRevision: input.expectedRevision,
            flow: statusView(flow),
          });
        }
        if (input.action === "authorize") {
          const policy = config.repositories.get(state.repo);
          if (!policy || !policy.enabled) {
            throw new Error("repository_policy_missing_or_disabled");
          }
          const transition = authorizeMergeReady(state, policy);
          if (!transition.changed) {
            return result({
              ok: true,
              authorization: transition.reason,
              queued: false,
              flow: statusView(flow),
            });
          }
          flow = requireApplied(await persistState(boundFlows, flow, transition.state));
          await applyEffect(api, config, boundFlows, flow, transition.state, transition.effect);
          flow = (await boundFlows.get(flow.flowId)) ?? flow;
          return result({
            ok: true,
            authorization: transition.reason,
            queued: true,
            flow: statusView(flow),
          });
        }
        if (input.action === "recover") {
          requireOwnerContext(ctx, ownerKey);
          if (state.pendingGithubReconciliation) {
            const reconciled = await reconcileGithubHead(api, config, boundFlows, flow, state);
            if (!reconciled.resolved) {
              return result({
                ok: true,
                recovery: reconciled.reason,
                flow: statusView(flow),
              });
            }
            flow = reconciled.flow;
            state = reconciled.state;
            if (reconciled.effect !== "none") {
              return result({
                ok: true,
                recovery: reconciled.reason,
                flow: statusView(flow),
              });
            }
          }
          const policy = config.repositories.get(state.repo);
          if (!policy || !policy.enabled) {
            throw new Error("repository_policy_missing_or_disabled");
          }
          let orphanRecoveryReason = null;
          if (state.orphanedWorker) {
            const reconciled = await reconcileOrphanBeforeEffect(
              api,
              config,
              boundFlows,
              flow,
              state,
            );
            if (!reconciled.safe) {
              return result({
                ok: true,
                recovery: `orphan_reconciliation_pending:${reconciled.reason}`,
                flow: statusView(flow),
              });
            }
            flow = reconciled.flow;
            state = reconciled.state;
            orphanRecoveryReason = `orphan_reconciled:${reconciled.reason}`;
            if (state.phase === PHASE.BLOCKED) {
              flow = await persistTerminalCleanup(api, config, boundFlows, flow, state, "blocked");
              return result({
                ok: true,
                recovery: `orphan_reconciled:${reconciled.reason}`,
                flow: statusView(flow),
              });
            }
            if (isTerminalState(state)) {
              await clearWake(api, config, flow);
              return result({
                ok: true,
                recovery: `orphan_reconciled:${reconciled.reason}`,
                flow: statusView(flow),
              });
            }
          }
          if (state.phase === PHASE.MERGE_READY) {
            if (flow.status === "succeeded") {
              flow = requireApplied(
                await persistState(boundFlows, flow, { ...state, updatedAt: Date.now() }),
              );
              state = stateOf(flow);
            }
            await clearWake(api, config, flow);
            if (!notificationAlreadyRendered(state, "approval_gate")) {
              await notifyMergeReady(api, config, flow, state);
            }
            return result({
              ok: true,
              recovery: orphanRecoveryReason ?? "approval_gate",
              flow: statusView(flow),
            });
          }
          const refreshed = refreshPolicySnapshot(state, policy);
          if (refreshed.changed) {
            flow = requireApplied(await persistState(boundFlows, flow, refreshed.state));
            state = refreshed.state;
          }
          state = stateOf(flow);
          const evidence = await reconcileRemediationEvidence(api, config, boundFlows, flow);
          if (evidence.changed) {
            const evidenceFlow = (await boundFlows.get(flow.flowId)) ?? evidence.flow;
            return result({
              ok: true,
              recovery: evidence.reason,
              flow: statusView(evidenceFlow),
            });
          }
          const transition = recoverState(
            state,
            await currentWorkerTask(api, resolved.sessionKey, state),
            Date.now(),
            120_000,
            recoverExtras(api, state),
          );
          if (transition.changed) {
            flow = requireApplied(await persistState(boundFlows, flow, transition.state));
          }
          if (transition.effect === "continue") {
            flow = await dispatchWorker(api, config, boundFlows, flow);
          } else if (transition.effect === "reconcile") {
            const reconciled = await reconcileGithubHead(
              api,
              config,
              boundFlows,
              flow,
              transition.state,
            );
            flow = reconciled.flow;
          } else if (
            !isTerminalState(transition.state) &&
            transition.state.phase !== PHASE.BLOCKED
          ) {
            await scheduleWake(api, config, flow, "recover");
          }
          return result({ ok: true, recovery: transition.reason, flow: statusView(flow) });
        }
        if (input.action === "continue") {
          flow = await dispatchWorker(api, config, boundFlows, flow);
          return result({ ok: true, flow: statusView(flow) });
        }
        throw new Error("unsupported_action");
      });
    },
  };
}
