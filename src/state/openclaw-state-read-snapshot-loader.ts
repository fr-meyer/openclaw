import type { DatabaseSync } from "node:sqlite";
import { toStringifiedError } from "@openclaw/normalization-core/error-coercion";
import type {
  OpenClawStateReadCommand,
  OpenClawStateReadReply,
} from "./openclaw-state-read.types.js";
import { isReadRequest } from "./openclaw-state-read.validation.js";
import { encodeOpenClawStateWorkerError } from "./openclaw-state-worker-error.js";

type SnapshotReader =
  typeof import("../node-host/node-worker-turn-store.kernel.js").readNodeWorkerTurnJournalSnapshotInDatabase;
type SnapshotCommand = Extract<
  OpenClawStateReadCommand,
  { type: "nodeWorker.turnJournalSnapshot" }
>;
type SnapshotReply = Extract<OpenClawStateReadReply, { type: "nodeWorker.turnJournalSnapshot" }>;

let snapshotReader: SnapshotReader | undefined;

/** Defer the journal kernel while preserving synchronous replies for existing read commands. */
export function loadNodeWorkerTurnSnapshotReaderIfNeeded(
  input: unknown,
  resume: () => OpenClawStateReadReply | Promise<OpenClawStateReadReply>,
): Promise<OpenClawStateReadReply> | undefined {
  if (
    !isReadRequest(input) ||
    input.command.type !== "nodeWorker.turnJournalSnapshot" ||
    snapshotReader
  ) {
    return undefined;
  }
  return import("../node-host/node-worker-turn-store.kernel.js").then(
    ({ readNodeWorkerTurnJournalSnapshotInDatabase }) => {
      snapshotReader = readNodeWorkerTurnJournalSnapshotInDatabase;
      return resume();
    },
    (value: unknown): OpenClawStateReadReply => {
      const error = toStringifiedError(value);
      return {
        ok: false,
        message: error.message,
        error: encodeOpenClawStateWorkerError(error, { includeOrdinary: true }),
      };
    },
  );
}

/** Caller has already admitted the read-only database snapshot. */
export function readNodeWorkerTurnSnapshotReply(
  database: DatabaseSync,
  command: SnapshotCommand,
): SnapshotReply {
  if (!snapshotReader) {
    throw new Error("Node worker snapshot reader was not loaded");
  }
  return {
    ok: true,
    type: command.type,
    sourceAdmitted: true,
    snapshot: snapshotReader(database, command),
  };
}
