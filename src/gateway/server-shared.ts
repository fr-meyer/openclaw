import type { ErrorShape } from "../../packages/gateway-protocol/src/schema/frames.js";

export const PENDING_CHAT_SEND_DEDUPE_PREFIX = "pending-chat:";

export function pendingChatSendDedupeKey(runId: string): string {
  return `${PENDING_CHAT_SEND_DEDUPE_PREFIX}${runId}`;
}

export const AGENT_DURABLE_NO_TOOLS_MODE = "durable-no-tools-v1";

export class AgentExecutionModeMismatchError extends Error {
  constructor() {
    super("Agent idempotency key is bound to a different execution mode.");
    this.name = "AgentExecutionModeMismatchError";
  }
}

// Dedupe entries cache recent request results so repeated gateway calls can
// replay the same success/error payload without re-running the method.
export type DedupeEntry = {
  ts: number;
  ok: boolean;
  /** Optional effectful-request fingerprint for methods with caller-supplied operation ids. */
  requestIdentity?: string;
  /** Admission-owned mode; a missing value retains the legacy/default contract. */
  readonly agentExecutionMode?: typeof AGENT_DURABLE_NO_TOOLS_MODE;
  /** Retain source privacy for diagnostic replay after the live session binding is gone. */
  incognito?: true;
  payload?: unknown;
  error?: ErrorShape;
};
