import { recoverState } from "./controller.mjs";
import { collectLifecycleFlows, resolveFlowBinding, stateOf } from "./runtime-config.mjs";
import { withTaskBindings } from "./runtime-foundation.mjs";
import { reconcileRemediationEvidence } from "./runtime-remediation.mjs";
import {
  persistState,
  processStartedAtMs,
  requireApplied,
  scheduleWake,
} from "./runtime-state-primitives.mjs";
import { statusView, workerMatchesTerminalLifecycleEvent } from "./runtime-status-primitives.mjs";
import { applyEffect } from "./runtime-worker-orchestration.mjs";
export {
  statusView,
  agentIdFromSessionKey,
  requireOwnerContext,
  canInspectStatus,
  resolveAccessibleFlow,
  workerTaskMatches,
  workerAgentMainSessionKey,
  workerTaskLedgers,
  taskForWorker,
  currentWorkerTask,
  workerMatchesTerminalLifecycleEvent,
  reconcileOrphanedWorker,
  reconcileOrphanBeforeEffect,
  sessionAlive,
  workerSessionAlive,
  recoverExtras,
} from "./runtime-status-primitives.mjs";

export async function reconcileTerminalWorkerEvent(api, config, event) {
  return await withTaskBindings(async () => {
    if (event?.stream !== "lifecycle" || !new Set(["end", "error"]).has(event?.data?.phase)) {
      return { handled: false, reason: "not_terminal_worker_event" };
    }
    for (const candidate of await collectLifecycleFlows(api, config)) {
      const candidateState = stateOf(candidate);
      if (!workerMatchesTerminalLifecycleEvent(candidateState?.activeWorker, event)) {
        continue;
      }
      const resolved = await resolveFlowBinding(api, config, candidate.flowId, candidate.ownerKey);
      const boundFlows = resolved.boundFlows;
      let flow = resolved.flow;
      let state = stateOf(flow);
      if (!workerMatchesTerminalLifecycleEvent(state?.activeWorker, event)) {
        return { handled: false, reason: "worker_event_superseded" };
      }

      if (state.activeWorker.kind === "remediation") {
        const evidence = await reconcileRemediationEvidence(api, config, boundFlows, flow);
        if (evidence.changed) {
          flow = (await boundFlows.get(flow.flowId)) ?? evidence.flow;
          return {
            handled: true,
            reason: evidence.reason,
            flow: statusView(flow),
          };
        }
        if (event.data.phase === "end") {
          // The host command writes immutable evidence before returning. If filesystem
          // visibility trails the terminal event, use one bounded controller wake.
          await scheduleWake(api, config, flow, "recover");
          return {
            handled: true,
            reason: "remediation_evidence_pending",
            flow: statusView(flow),
          };
        }
      }

      const terminalTask = {
        status: event.data.phase === "end" ? "succeeded" : "failed",
        error:
          typeof event.data.error === "string"
            ? event.data.error
            : typeof event.data.reason === "string"
              ? event.data.reason
              : event.data.phase,
      };
      const transition = recoverState(state, terminalTask, Date.now(), 0, {
        processStartedAt: processStartedAtMs(),
        sessionAlive: false,
      });
      if (transition.changed) {
        flow = requireApplied(await persistState(boundFlows, flow, transition.state));
        state = transition.state;
      }
      await applyEffect(api, config, boundFlows, flow, state, transition.effect, {
        dispatchImmediately: true,
      });
      flow = (await boundFlows.get(flow.flowId)) ?? flow;
      return { handled: true, reason: transition.reason, flow: statusView(flow) };
    }
    return { handled: false, reason: "active_worker_not_found" };
  });
}
