import type {
  NodeWorkerLaunchReceipt,
  NodeWorkerTerminalState,
} from "./node-worker-launch-receipt.js";

export type NodeWorkerTurnJournalSnapshotQuery = {
  turnId: string;
  ownerLaunchId: string;
};

export type NodeWorkerTurnJournalSnapshot = {
  turn:
    | {
        turnId: string;
        ownerLaunchId: string;
        planHash: string;
        runId: string;
        state: "running" | NodeWorkerTerminalState;
        resultJson: string | null;
        errorText: string | null;
        completedAtMs: number | null;
        createdAtMs: number;
        updatedAtMs: number;
      }
    | undefined;
  owner: NodeWorkerLaunchReceipt;
};
