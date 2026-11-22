import { blockState } from "./controller-state.mjs";
import { applyWorkerReport } from "./controller.mjs";
import { stateOf } from "./runtime-config.mjs";
import { withTaskBindings } from "./runtime-foundation.mjs";
import { remediationReportFromEvidence } from "./runtime-remediation-primitives.mjs";
import { enforceModeGate, persistState, requireApplied } from "./runtime-state-primitives.mjs";
import { applyEffect } from "./runtime-worker-orchestration.mjs";
export {
  remediationRoot,
  remediationJobId,
  pathCovered,
  executableAvailable,
  canonicalRepoFromRemote,
  readWorkspaceIdentity,
  validateRemediatorAdmission,
  remediationJobBinding,
  prepareRemediationJob,
  verifyRemediationEvidence,
  remediationReportFromEvidence,
} from "./runtime-remediation-primitives.mjs";

export async function reconcileRemediationEvidence(api, config, boundFlows, flow) {
  return await withTaskBindings(async () => {
    const state = stateOf(flow);
    if (!state || state.activeWorker?.kind !== "remediation") {
      return { changed: false, flow, reason: "no_active_remediation" };
    }
    let input;
    try {
      input = remediationReportFromEvidence(api, state, config);
    } catch (error) {
      const detail = error instanceof Error ? error.message : "unknown";
      const blocked = blockState(state, `remediation_evidence_invalid:${detail.slice(0, 240)}`);
      const blockedFlow = requireApplied(await persistState(boundFlows, flow, blocked.state));
      await applyEffect(api, config, boundFlows, blockedFlow, blocked.state, blocked.effect);
      return { changed: true, flow: blockedFlow, reason: "remediation_evidence_invalid" };
    }
    if (!input) {
      return { changed: false, flow, reason: "remediation_evidence_missing" };
    }
    const transition = applyWorkerReport(state, input, state.activeWorker.sessionKey);
    let nextState = transition.state;
    let nextEffect = transition.effect;
    let nextFlow = requireApplied(await persistState(boundFlows, flow, nextState));
    const gate = enforceModeGate(nextState);
    if (gate.changed) {
      nextState = gate.state;
      nextEffect = gate.effect;
      nextFlow = requireApplied(await persistState(boundFlows, nextFlow, nextState));
    }
    await applyEffect(api, config, boundFlows, nextFlow, nextState, nextEffect, {
      dispatchImmediately: true,
    });
    nextFlow = (await boundFlows.get(nextFlow.flowId)) ?? nextFlow;
    return { changed: true, flow: nextFlow, reason: "remediation_evidence_reconciled" };
  });
}
