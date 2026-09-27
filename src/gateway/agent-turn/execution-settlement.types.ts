import type { SubagentExecution } from "../../plugins/runtime/subagent-execution.types.js";

export type AgentTurnExecutionOwner = SubagentExecution & {
  readonly runId: string;
  readonly sessionKey: string;
};

export type AgentTurnExecutionSettlement = {
  owner: AgentTurnExecutionOwner;
  track: (execution: Promise<void>) => void;
  markUnknown: () => void;
};
