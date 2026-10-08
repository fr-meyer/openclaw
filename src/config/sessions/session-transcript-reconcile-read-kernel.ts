import { sqlitePrimaryResultCode } from "../../infra/sqlite-error-diagnostics.js";
import {
  assertTransactionUsable,
  runSqliteDeferredTransactionSync,
} from "../../infra/sqlite-transaction.js";
import { assertExistingDatabaseIdentity } from "../../infra/sqlite-worker-identity.js";
import {
  isOpenClawAgentDatabasePathCurrent,
  readOpenClawAgentDatabaseIdentity,
} from "../../state/openclaw-agent-db-identity.js";
import { classifyOpenClawAgentDatabaseReadError } from "../../state/openclaw-agent-db-read-error.js";
import { withScopedOpenClawAgentDatabaseReadOnly } from "../../state/openclaw-agent-db-readonly-scope.js";
import { cloneEnvWithPlatformSemantics } from "../config-env-vars.js";
import { encodeSessionTranscriptWorkerError } from "./session-history-worker-errors.js";
import {
  hasOrphanedTranscriptIndexRows,
  hasSessionsNeedingTranscriptIndexReconcile,
  sessionTranscriptIndexNeedsReconcile,
} from "./session-transcript-index.js";
import type {
  SessionTranscriptWorkerInput,
  SessionTranscriptWorkerValues,
} from "./session-transcript-worker.types.js";

/** Execute one fresh deferred snapshot inside the caller's existing readonly history scope. */
export function readSessionTranscriptReconcilePending(
  request: Extract<SessionTranscriptWorkerInput, { kind: "transcript-reconcile-pending" }>,
): SessionTranscriptWorkerValues["transcript-reconcile-pending"] {
  class ReconcileDataReadError extends Error {
    constructor(
      readonly readError: unknown,
      readonly database: import("node:sqlite").DatabaseSync,
    ) {
      super("Session transcript reconcile data read failed", { cause: readError });
    }
  }
  let source: SessionTranscriptWorkerValues["transcript-reconcile-pending"]["source"];
  try {
    const read = withScopedOpenClawAgentDatabaseReadOnly(
      (database) => {
        const physical = readOpenClawAgentDatabaseIdentity(database);
        if (
          typeof physical.identity !== "string" ||
          !isOpenClawAgentDatabasePathCurrent(database)
        ) {
          throw new Error("Session transcript reconcile physical owner changed");
        }
        if (request.fileIdentity) {
          assertExistingDatabaseIdentity(
            database.path,
            request.fileIdentity.key,
            request.fileIdentity.birthtime,
          );
        }
        source = {
          agentId: database.agentId,
          path: database.path,
          databaseIdentity: physical.identity,
          databaseBirthtime: physical.birthtime,
        };
        return runSqliteDeferredTransactionSync(database.db, () => {
          try {
            return request.sessionId === undefined
              ? hasSessionsNeedingTranscriptIndexReconcile(database.db) ||
                  hasOrphanedTranscriptIndexRows(database.db)
              : sessionTranscriptIndexNeedsReconcile(database.db, request.sessionId);
          } catch (error) {
            throw new ReconcileDataReadError(
              sqlitePrimaryResultCode(error) === 1
                ? classifyOpenClawAgentDatabaseReadError(database.db, error)
                : error,
              database.db,
            );
          }
        });
      },
      { ...request.database, env: cloneEnvWithPlatformSemantics(request.env) },
    );
    return {
      kind: "transcript-reconcile-pending" as const,
      source,
      result: { found: read.found, pending: read.found && read.value },
    };
  } catch (error) {
    if (!(error instanceof ReconcileDataReadError)) {
      throw error;
    }
    // Only a settled data-query failure becomes uncertain read data. Admission,
    // physical ownership, transaction cleanup and worker retirement still reject.
    assertTransactionUsable(error.database);
    if (error.database.isOpen && error.database.isTransaction) {
      throw error.readError;
    }
    const readError = encodeSessionTranscriptWorkerError(error.readError);
    if (!readError || readError.kind === "fence") {
      throw error.readError;
    }
    return { kind: "transcript-reconcile-pending" as const, source, readError };
  }
}
