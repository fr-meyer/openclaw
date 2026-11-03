import type { SessionStateNotice } from "../../../sessions/session-state-events.kernel.js";
import type { SessionStateWorkerOperations } from "../../../sessions/session-state-events.worker-contract.js";
import type {
  ManagedFlowNativeKillClaim,
  ManagedFlowNativeLaunchClaim,
} from "../../../tasks/managed-task-flow-kill-claim.worker.js";
import type { SubagentRunSqliteRow } from "./subagent-registry.store.row.js";

export type SubagentRegistryWrite = {
  writeId: string;
  values: readonly SubagentRunSqliteRow[];
  deleteRunIds: readonly string[];
  /** Managed-flow ownership is checked in the same transaction as the native row. */
  managedFlowKillClaim?: ManagedFlowNativeKillClaim;
  managedFlowLaunchClaim?: ManagedFlowNativeLaunchClaim;
  terminalEvents?: readonly Pick<
    SessionStateWorkerOperations["sessionState.record"]["input"],
    "event" | "now" | "acpControl" | "sessionEntryCurrentSource"
  >[];
};

export type SubagentRegistryWriteReceipt = {
  writeId: string;
  notices: SessionStateNotice[];
};
