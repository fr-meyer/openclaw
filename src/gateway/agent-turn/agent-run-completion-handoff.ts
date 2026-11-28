import { ErrorCodes, errorShape } from "../../../packages/gateway-protocol/src/index.js";
import { resolveExactSubagentCompletionEvent } from "../../agents/subagents/announce/subagent-announce-handoff.js";
import { consumeSubagentCompletionToolHandoff } from "../subagent-completion-tool-handoff.js";
import { setGatewayDedupeEntries } from "./agent-dedupe.js";
import type { resolveAgentRunAdmissionModel } from "./agent-run-admission-model.js";
import type { PrepareAgentRunDispatchParams } from "./agent-run-admission-types.js";
import type { PreparedAgentRunUserTurn } from "./agent-run-user-turn.js";

export function resolveAgentRunCompletionToolHandoff(
  params: PrepareAgentRunDispatchParams,
  userTurn: PreparedAgentRunUserTurn,
  resolvedRuntime: ReturnType<typeof resolveAgentRunAdmissionModel>["resolvedRuntime"],
) {
  const completionEvent = resolveExactSubagentCompletionEvent({
    inputProvenance: userTurn.inputProvenance,
    internalEvents: params.request.internalEvents,
  });
  return params.providerOverride === undefined &&
    params.modelOverride === undefined &&
    params.restoredCronContinuation === undefined
    ? consumeSubagentCompletionToolHandoff({
        handoffId: params.client?.internal?.delegatedToolPolicyHandoffId,
        sourceTool: userTurn.inputProvenance?.sourceTool,
        sourceSessionKey:
          userTurn.inputProvenance?.kind === "inter_session" &&
          userTurn.inputProvenance.sourceTool === "subagent_settle"
            ? userTurn.inputProvenance.sourceSessionKey
            : completionEvent?.childSessionKey,
        sourceSessionId: completionEvent?.childSessionId,
        targetSessionKey: params.resolvedSessionKey,
        targetSessionId: params.getAdmittedSessionId(),
        idempotencyKey: params.request.idempotencyKey,
        provider: resolvedRuntime.provider,
        model: resolvedRuntime.model,
      })
    : undefined;
}

export function rejectUnavailableAgentRunContinuation(
  params: PrepareAgentRunDispatchParams,
): boolean {
  if (
    params.abortForLifecycleRotation({
      sessionKey: params.resolvedSessionKey,
      agentId: params.activeSessionAgentId,
    })
  ) {
    return true;
  }
  if (params.restoredCronContinuationIdentity && !params.restoredCronContinuation) {
    params.io.emitAcceptance([
      false,
      undefined,
      errorShape(ErrorCodes.UNAVAILABLE, "cron run continuation could not be restored"),
    ]);
    return true;
  }

  return false;
}

export function recordAcceptedAgentRunDedupe<Accepted extends object>(
  params: PrepareAgentRunDispatchParams,
  accepted: Accepted,
  controlUiVisible: boolean,
) {
  setGatewayDedupeEntries({
    dedupe: params.context.dedupe,
    keys: params.agentDedupeKeys,
    entry: {
      ts: Date.now(),
      ok: true,
      payload: {
        ...accepted,
        controlUiVisible,
        dedupeKeys: params.agentDedupeKeys,
        ownerConnId: params.ownerConnId,
        ownerDeviceId: params.ownerDeviceId,
      },
    },
  });
}
