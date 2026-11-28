import type { AgentMessage } from "../../agents/runtime/index.js";
import type { SessionManagerAppendMessage } from "../../agents/sessions/session-manager-types.js";
import { applyAssistantDeliveryDirectives } from "./transcript-assistant-delivery.js";

export type AssistantBeforeMessageWrite = (params: {
  message: AgentMessage;
  agentId?: string;
  sessionKey?: string;
}) => AgentMessage | null;

export function applyBeforeMessageWriteToAssistant(params: {
  message: SessionManagerAppendMessage;
  beforeMessageWrite?: AssistantBeforeMessageWrite;
  explicitIdempotencyKey?: string;
  agentId?: string;
  sessionKey: string;
}): SessionManagerAppendMessage | undefined {
  const nextMessage = params.beforeMessageWrite
    ? params.beforeMessageWrite({
        message: params.message as AgentMessage,
        ...(params.agentId ? { agentId: params.agentId } : {}),
        sessionKey: params.sessionKey,
      })
    : params.message;
  if (nextMessage?.role !== "assistant") {
    return undefined;
  }
  return Object.assign(
    applyAssistantDeliveryDirectives(nextMessage),
    params.explicitIdempotencyKey ? { idempotencyKey: params.explicitIdempotencyKey } : {},
  ) as SessionManagerAppendMessage;
}
