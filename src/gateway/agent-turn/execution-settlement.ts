import { assertAgentRunLifecycleGenerationCurrent } from "../../infra/agent-events.js";
import type { SubagentExecution } from "../../plugins/runtime/types.js";
import type { ChatAbortControllerEntry } from "../chat-abort.js";
import type { AgentTurnContext } from "./types.js";

export type AgentTurnExecutionOwner = SubagentExecution & {
  readonly runId: string;
  readonly sessionKey: string;
};

export type AgentTurnExecutionSettlement = {
  owner: AgentTurnExecutionOwner;
  track: (execution: Promise<void>) => void;
  markUnknown: () => void;
};

/** Admission captures the producer owner before exposing acceptance. No replay lookup. */
export function createAgentTurnExecutionSettlement(params: {
  runId: string;
  sessionKey: string;
  entry: ChatAbortControllerEntry;
  lifecycleGeneration: string;
  context: AgentTurnContext;
}): AgentTurnExecutionSettlement {
  let state: ReturnType<SubagentExecution["observeSettlement"]> = "pending";
  let tracked = false;
  const operationalRunInstance = params.entry.operationalRunInstance;
  const lifetimeSignal = params.context.requestEntryLifetime?.signal;
  const resolveGatewayContext = params.context.resolveGatewayContext;
  const gatewayContext = resolveGatewayContext?.();
  const owner = Object.freeze({
    runId: params.runId,
    sessionKey: params.sessionKey,
    observeSettlement: () => {
      lifetimeSignal?.throwIfAborted();
      if (
        resolveGatewayContext &&
        (!gatewayContext || resolveGatewayContext() !== gatewayContext)
      ) {
        throw new Error("Agent execution settlement Gateway was retired");
      }
      assertAgentRunLifecycleGenerationCurrent(params.lifecycleGeneration);
      const current = params.context.chatAbortControllers.get(params.runId);
      if (
        (current && current !== params.entry) ||
        params.entry.operationalRunInstance !== operationalRunInstance
      ) {
        throw new Error("Agent execution settlement owner was replaced");
      }
      // Normal registration removal is not completion; only the captured producer can settle.
      return state;
    },
  });
  return {
    owner,
    track: (execution) => {
      if (tracked) {
        throw new Error("Agent execution settlement already has a producer");
      }
      tracked = true;
      void execution.then(
        () => {
          state = "settled";
        },
        () => {
          state = "unknown";
        },
      );
    },
    markUnknown: () => {
      state = "unknown";
    },
  };
}

/** Track the raw producer before a best-effort logging catch can mask rejection. */
export function trackAgentTurnExecutionSettlement(
  settlement: AgentTurnExecutionSettlement | undefined,
  start: () => Promise<void>,
): Promise<void> {
  try {
    const execution = start();
    settlement?.track(execution);
    return execution;
  } catch (error) {
    settlement?.markUnknown();
    throw error;
  }
}
