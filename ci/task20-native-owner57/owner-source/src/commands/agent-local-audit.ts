/** Direct-local agent audit writer lifecycle shared by CLI entrypoints. */
import { createAuditEventRecorder } from "../audit/audit-recorder.js";
import { configureExecutionDecisionWorkSink } from "../audit/execution-decision-work.js";
import {
  configureExecutionIdentityAdmissionSink,
  hasExecutionIdentityAdmissionSink,
} from "../audit/execution-identity-admission.js";
import { configureRuntimeActionDecisionSink } from "../audit/runtime-action-decision.js";
import type { OpenClawConfig } from "../config/types.openclaw.js";
import { onAgentAuditEvent } from "../infra/agent-events.js";
import { onTrustedToolExecutionEvent } from "../infra/diagnostic-events.js";
import { GatewayScheduler } from "../infra/gateway-scheduler.js";

/** Own one direct-process writer unless a surrounding runtime already owns it. */
export function startAgentLocalAuditWriter(
  config: OpenClawConfig,
  options: { stateDir?: string } = {},
): (() => Promise<void>) | undefined {
  if (hasExecutionIdentityAdmissionSink()) {
    return undefined;
  }
  const scheduler = new GatewayScheduler();
  const recorder = createAuditEventRecorder({
    scheduler,
    getConfig: () => config,
    ...(options.stateDir ? { stateDir: options.stateDir } : {}),
  });
  const clearAdmissionSink = configureExecutionIdentityAdmissionSink(
    recorder.recordExecutionIdentity,
  );
  const clearDecisionWorkSink = configureExecutionDecisionWorkSink(
    recorder.recordExecutionDecisionWork,
  );
  const clearRuntimeActionSink = configureRuntimeActionDecisionSink(
    recorder.recordExecutionDecision,
  );
  const unsubscribeAgentAudit = onAgentAuditEvent(recorder.record);
  const unsubscribeToolAudit = onTrustedToolExecutionEvent(recorder.recordTool);
  let stopPromise: Promise<void> | undefined;
  return () => {
    if (stopPromise) {
      return stopPromise;
    }
    let resolveStop!: () => void;
    let rejectStop!: (reason: unknown) => void;
    // Publish the single stop promise before callbacks can reenter this owner.
    stopPromise = new Promise<void>((resolve, reject) => {
      resolveStop = resolve;
      rejectStop = reject;
    });
    void (async () => {
      scheduler.beginClose();
      clearRuntimeActionSink();
      clearDecisionWorkSink();
      clearAdmissionSink();
      try {
        await recorder.stop();
      } finally {
        // Keep the original recorder observing late lifecycle/tool evidence until
        // its drain settles; stopping admission is not terminal evidence.
        unsubscribeToolAudit();
        unsubscribeAgentAudit();
        await scheduler.stop();
      }
    })().then(resolveStop, rejectStop);
    return stopPromise;
  };
}
