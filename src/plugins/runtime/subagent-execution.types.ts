export type SubagentExecution = {
  /** Live producer settlement, including host cleanup; never resource fencing evidence. */
  observeSettlement: () => "pending" | "settled" | "unknown";
};
