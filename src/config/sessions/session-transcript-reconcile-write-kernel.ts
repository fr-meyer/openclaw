import { executeSqliteQueryTakeFirstSync } from "../../infra/kysely-sync.js";
import type { OpenClawAgentDatabase } from "../../state/openclaw-agent-db-contract.js";
import { getSessionKysely } from "./session-accessor.sqlite-scope.js";
import {
  deleteOrphanedTranscriptIndexRowsInTransaction,
  hasSessionsNeedingTranscriptIndexReconcile,
} from "./session-transcript-index.js";
import {
  appendPreparedSessionTranscriptProjectionChunkInTransaction,
  claimPreparedSessionTranscriptProjectionInTransaction,
  deletePreparedSessionTranscriptProjectionChunkInTransaction,
  finalizePreparedSessionTranscriptProjectionInTransaction,
} from "./session-transcript-projection-rebuild.js";
import type {
  SessionTranscriptReconcileWrite,
  SessionTranscriptReconcileWriteResult,
} from "./session-transcript-reconcile-write-contract.js";

/** The existing executor owns the synchronous transaction around each bounded phase. */
export function executeSessionTranscriptReconcileWrite(
  database: OpenClawAgentDatabase,
  command: SessionTranscriptReconcileWrite,
): SessionTranscriptReconcileWriteResult {
  switch (command.kind) {
    case "preflight":
      deleteOrphanedTranscriptIndexRowsInTransaction(database.db);
      return {
        kind: command.kind,
        hasWork: hasSessionsNeedingTranscriptIndexReconcile(database.db),
      };
    case "claim":
      return {
        kind: command.kind,
        owned: claimPreparedSessionTranscriptProjectionInTransaction(
          database.db,
          command.plan,
          command.claimId,
        ),
      };
    case "delete-chunk":
      return {
        kind: command.kind,
        ...deletePreparedSessionTranscriptProjectionChunkInTransaction(database.db, command),
      };
    case "active-chunk":
    case "fts-chunk":
      return {
        kind: command.kind,
        owned: appendPreparedSessionTranscriptProjectionChunkInTransaction(database.db, command),
      };
    case "finalize": {
      const finalized = finalizePreparedSessionTranscriptProjectionInTransaction(
        database.db,
        command.plan,
        command.claimId,
      );
      const session =
        finalized &&
        executeSqliteQueryTakeFirstSync(
          database.db,
          getSessionKysely(database.db)
            .selectFrom("session_windows")
            .select("session_key")
            .where("session_id", "=", command.plan.sessionId),
        );
      return {
        kind: command.kind,
        finalized,
        ...(session ? { sessionKey: session.session_key } : {}),
      };
    }
    case "orphan-sweep":
      deleteOrphanedTranscriptIndexRowsInTransaction(database.db);
      return { kind: command.kind };
  }
}
