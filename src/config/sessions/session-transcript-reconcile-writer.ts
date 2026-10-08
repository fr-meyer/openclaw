import { randomInt } from "node:crypto";
import { setImmediate as yieldToGateway } from "node:timers/promises";
import { isRecord } from "@openclaw/normalization-core/record-coerce";
import { executeSqliteQueryTakeFirstSync } from "../../infra/kysely-sync.js";
import {
  hasSqliteWorkerOutcomeUnknown,
  SqliteWorkerError,
} from "../../infra/sqlite-worker-contract.js";
import type { SqliteWorkerOperationAdmission } from "../../infra/sqlite-worker-operation-admission.js";
import type { RetainedWorkerTransactionAdmission } from "../../infra/sqlite-worker-operation-settlement.js";
import { sessionChanges } from "../../sessions/session-row-changes.js";
import {
  getOpenClawAgentDatabaseIfOpen,
  isIncognitoOpenClawAgentSqlitePath,
  withOpenClawAgentDatabaseAsync,
  runOpenClawAgentWriteTransaction,
  type OpenClawAgentDatabase,
  type OpenClawAgentDatabaseOptions,
} from "../../state/openclaw-agent-db.js";
import type { OpenClawAgentDatabaseExecution } from "../../state/openclaw-agent-execution.js";
import { withSessionEntryWorker } from "./session-accessor.sqlite-replacement-worker.js";
import {
  getSessionKysely,
  runExclusiveSqliteSessionWrite,
} from "./session-accessor.sqlite-scope.js";
import type { SqliteSessionWriteOperation } from "./session-accessor.sqlite-write-operation.js";
import {
  appendPreparedSessionTranscriptProjectionChunkInTransaction,
  claimPreparedSessionTranscriptProjectionInTransaction,
  deletePreparedSessionTranscriptProjectionChunkInTransaction,
  finalizePreparedSessionTranscriptProjectionInTransaction,
  type PreparedSessionTranscriptProjectionMetadata,
} from "./session-transcript-projection-rebuild.js";
import type { MemoryTranscriptProjectionSource } from "./session-transcript-reconcile-memory.js";
import {
  isSessionTranscriptReconcileWriteResult,
  type SessionTranscriptReconcileWrite,
  type SessionTranscriptReconcileWriteKind,
  type SessionTranscriptReconcileWriteResultFor,
} from "./session-transcript-reconcile-write-contract.js";
import type { EncodedTranscriptFtsChunk } from "./session-transcript-reconcile.worker.js";

const PROJECTION_WRITE_CHUNK_ROWS = 512;
type ReconcileDatabaseOptions = OpenClawAgentDatabaseOptions & {
  env: NodeJS.ProcessEnv;
  path: string;
};
export type ActivePreparedProjection = {
  claimId: number;
  plan: PreparedSessionTranscriptProjectionMetadata;
};

export type SessionTranscriptReconcileWriter = {
  write<K extends SessionTranscriptReconcileWriteKind>(
    command: SessionTranscriptReconcileWrite & { kind: K },
  ): Promise<SessionTranscriptReconcileWriteResultFor<K>>;
};

function rejectUnknownWrite(cause: unknown): never {
  if (hasSqliteWorkerOutcomeUnknown(cause)) {
    throw cause;
  }
  const error = new SqliteWorkerError(
    "Transcript projection write has no confirmed native completion and commit receipt",
    "outcome-unknown",
  );
  error.cause = cause;
  throw error;
}

/** The caller retains this executor through planner settlement and independent lease cleanup. */
export function createSessionTranscriptReconcileWriter(
  options: OpenClawAgentDatabaseOptions & { path: string; env: NodeJS.ProcessEnv },
  execution: OpenClawAgentDatabaseExecution,
  assertCurrent: () => void,
): SessionTranscriptReconcileWriter {
  return {
    async write(command) {
      let admitted:
        | {
            admission: SqliteWorkerOperationAdmission;
            retained: RetainedWorkerTransactionAdmission;
          }
        | undefined;
      return await withSessionEntryWorker(
        options,
        execution.fileIdentity?.physicalIdentity,
        assertCurrent,
        async (owner, source) => {
          // Preserve first-use repair/creation through the same admitted worker owner.
          if (command.kind === "preflight") {
            await owner.prepare(source);
          }
          const result = await owner.runExisting(source, async (worker) => {
            const outcome = await worker
              .execute({ type: "session.transcriptIndex.write", input: command })
              .then(
                (value) => ({ ok: true as const, value }),
                (error: unknown) => ({ ok: false as const, error }),
              );
            if (admitted) {
              await admitted.retained.settled;
              const facts = admitted.admission.committed?.facts;
              if (
                admitted.admission.settlement?.kind === "completed" &&
                isRecord(facts) &&
                facts.kind === "session-transcript-index-write" &&
                isSessionTranscriptReconcileWriteResult(facts.result, command.kind)
              ) {
                const receipt = facts.result;
                // Publish a proved commit even when delivery or later cleanup failed.
                // This remains inside the phase's writer FIFO, after native COMMIT.
                if (receipt.kind === "finalize" && receipt.finalized && receipt.sessionKey) {
                  sessionChanges.emit({ storePath: options.path, sessionKey: receipt.sessionKey });
                }
                if (!outcome.ok) {
                  throw outcome.error;
                }
                return { value: receipt };
              }
              if (admitted.admission.settlement?.kind !== "completed" || outcome.ok) {
                rejectUnknownWrite(outcome.ok ? undefined : outcome.error);
              }
            } else if (outcome.ok) {
              rejectUnknownWrite(undefined);
            }
            if (!outcome.ok) {
              throw outcome.error;
            }
            return rejectUnknownWrite(undefined);
          });
          if (!result) {
            throw new Error("Transcript projection lost its retained database before write");
          }
          return result.value;
        },
        (admission, retained, facts) => {
          if (
            !isRecord(facts) ||
            !isRecord(facts.publication) ||
            facts.publication.kind !== "session-transcript-index-write" ||
            !isSessionTranscriptReconcileWriteResult(facts.publication.result, command.kind)
          ) {
            throw new Error("Transcript projection commit omitted its phase receipt");
          }
          admitted = { admission, retained };
        },
        execution,
      );
    },
  };
}

function nextProjectionClaimId(): number {
  return -randomInt(1, 2 ** 47);
}

export async function runProjectionWrite<T>(
  databaseOptions: ReconcileDatabaseOptions,
  operationLabel: Extract<SqliteSessionWriteOperation, `sessions.transcript-index.${string}`>,
  operation: (database: OpenClawAgentDatabase) => T,
  memorySource?: MemoryTranscriptProjectionSource,
): Promise<T> {
  return await runExclusiveSqliteSessionWrite(
    databaseOptions,
    async () => {
      const write = () => {
        // Disposal revokes a memory source. Check inside the queue before the opener
        // can materialize a successor database for a late worker result.
        memorySource?.assertCurrentOwner();
        return runOpenClawAgentWriteTransaction(operation, databaseOptions, { operationLabel });
      };
      return !isIncognitoOpenClawAgentSqlitePath(databaseOptions.path, databaseOptions) &&
        !getOpenClawAgentDatabaseIfOpen(databaseOptions)
        ? withOpenClawAgentDatabaseAsync(databaseOptions, write)
        : write();
    },
    operationLabel,
  );
}

export async function claimPreparedSessionTranscriptProjection(
  databaseOptions: ReconcileDatabaseOptions,
  plan: PreparedSessionTranscriptProjectionMetadata,
  memorySource?: MemoryTranscriptProjectionSource,
  writer?: SessionTranscriptReconcileWriter,
): Promise<ActivePreparedProjection | undefined> {
  const claimId = nextProjectionClaimId();
  const claimed = writer
    ? (await writer.write({ kind: "claim", plan, claimId })).owned
    : await runProjectionWrite(
        databaseOptions,
        "sessions.transcript-index.claim",
        (database) =>
          (!memorySource || memorySource.isCurrentPlan(plan)) &&
          claimPreparedSessionTranscriptProjectionInTransaction(database.db, plan, claimId),
        memorySource,
      );
  if (!claimed) {
    return undefined;
  }

  let deleteResult = { hasMore: true, owned: true };
  while (deleteResult.hasMore && deleteResult.owned) {
    deleteResult = writer
      ? await writer.write({
          kind: "delete-chunk",
          maxRowsPerTable: PROJECTION_WRITE_CHUNK_ROWS,
          sessionId: plan.sessionId,
          claimId,
        })
      : await runProjectionWrite(
          databaseOptions,
          "sessions.transcript-index.delete-chunk",
          (database) =>
            deletePreparedSessionTranscriptProjectionChunkInTransaction(database.db, {
              maxRowsPerTable: PROJECTION_WRITE_CHUNK_ROWS,
              sessionId: plan.sessionId,
              claimId,
            }),
          memorySource,
        );
    await yieldToGateway();
  }
  if (!deleteResult.owned) {
    return undefined;
  }
  return { claimId, plan };
}

export function decodeFtsChunk(chunk: EncodedTranscriptFtsChunk) {
  const decoder = new TextDecoder();
  return chunk.rows.map((row) => ({
    messageId: row.messageId,
    role: row.role,
    text: decoder.decode(
      chunk.textBytes.subarray(row.textByteOffset, row.textByteOffset + row.textByteLength),
    ),
    timestamp: row.timestamp,
  }));
}

export async function appendPreparedProjectionChunk(
  databaseOptions: ReconcileDatabaseOptions,
  active: ActivePreparedProjection,
  rows:
    | {
        activeRows: Parameters<
          typeof appendPreparedSessionTranscriptProjectionChunkInTransaction
        >[1]["activeRows"];
      }
    | {
        ftsRows: Parameters<
          typeof appendPreparedSessionTranscriptProjectionChunkInTransaction
        >[1]["ftsRows"];
      },
  memorySource?: MemoryTranscriptProjectionSource,
  writer?: SessionTranscriptReconcileWriter,
): Promise<boolean> {
  const owned = writer
    ? (
        await writer.write(
          "activeRows" in rows
            ? {
                kind: "active-chunk",
                activeRows: rows.activeRows,
                claimId: active.claimId,
                sessionId: active.plan.sessionId,
              }
            : {
                kind: "fts-chunk",
                ftsRows: rows.ftsRows,
                claimId: active.claimId,
                sessionId: active.plan.sessionId,
              },
        )
      ).owned
    : await runProjectionWrite(
        databaseOptions,
        "activeRows" in rows
          ? "sessions.transcript-index.active-chunk"
          : "sessions.transcript-index.fts-chunk",
        (database) =>
          appendPreparedSessionTranscriptProjectionChunkInTransaction(database.db, {
            ...rows,
            claimId: active.claimId,
            sessionId: active.plan.sessionId,
          }),
        memorySource,
      );
  await yieldToGateway();
  return owned;
}

export async function finalizePreparedProjection(
  databaseOptions: ReconcileDatabaseOptions,
  active: ActivePreparedProjection,
  memorySource?: MemoryTranscriptProjectionSource,
  writer?: SessionTranscriptReconcileWriter,
): Promise<boolean> {
  if (writer) {
    return (await writer.write({ kind: "finalize", plan: active.plan, claimId: active.claimId }))
      .finalized;
  }
  return await runProjectionWrite(
    databaseOptions,
    "sessions.transcript-index.finalize",
    (database) => {
      const finalized =
        (!memorySource || memorySource.isCurrentPlan(active.plan)) &&
        finalizePreparedSessionTranscriptProjectionInTransaction(
          database.db,
          active.plan,
          active.claimId,
        );
      const session =
        finalized &&
        executeSqliteQueryTakeFirstSync(
          database.db,
          getSessionKysely(database.db)
            .selectFrom("session_windows")
            .select("session_key")
            .where("session_id", "=", active.plan.sessionId),
        );
      if (session) {
        sessionChanges.emit(
          { storePath: database.path, sessionKey: session.session_key },
          database.db,
        );
      }
      return finalized;
    },
    memorySource,
  );
}
