import path from "node:path";
import type { Result } from "@openclaw/normalization-core/result";
import {
  assertExistingDatabaseIdentity,
  readDatabasePathIdentitySync,
} from "../../infra/sqlite-worker-identity.js";
import { WorkerTaskError } from "../../infra/worker-task-pool.js";
import { isIncognitoOpenClawAgentSqlitePath } from "../../state/openclaw-agent-db.paths.js";
import { historyLane, maintenanceLane } from "./session-transcript-worker-resources.js";
import { retainSessionHistoryWorkerDatabase } from "./session-transcript-worker-runtime.js";
import type { SessionTranscriptReconcilePendingRead } from "./session-transcript-worker.types.js";
import { captureSessionTranscriptStorageEnvironment } from "./transcript-target-binding.js";

export type SessionTranscriptReconcileReaderFileIdentity = Readonly<{
  key: string;
  birthtime?: string;
}>;

/** Retain the existing durable reader before yielding; each request owns a fresh snapshot. */
export function captureSessionTranscriptReconcileReader(
  target: { agentId: string; path: string; env: NodeJS.ProcessEnv },
  lane: "history" | "maintenance" = "history",
  expectedFileIdentity?: SessionTranscriptReconcileReaderFileIdentity,
): {
  readonly fileIdentity: SessionTranscriptReconcileReaderFileIdentity | undefined;
  assertCurrent(): void;
  isRevokedFailure(error: unknown): boolean;
  read(sessionId?: string): Promise<Result<SessionTranscriptReconcilePendingRead, unknown>>;
  release(): Promise<void>;
} {
  const captured = {
    agentId: target.agentId,
    path: path.resolve(target.path),
    env: captureSessionTranscriptStorageEnvironment(target.env),
  };
  if (isIncognitoOpenClawAgentSqlitePath(captured.path, captured)) {
    throw new Error("Incognito transcript reconciliation requires its process-held owner");
  }
  const identity = readDatabasePathIdentitySync(captured.path);
  if (
    expectedFileIdentity &&
    (!expectedFileIdentity.key.startsWith("file:") ||
      identity.key !== expectedFileIdentity.key ||
      (expectedFileIdentity.birthtime !== undefined &&
        identity.birthtime !== expectedFileIdentity.birthtime))
  ) {
    throw new Error("Session transcript reconcile reader physical identity changed before renewal");
  }
  // A renewed cache owner retains the original file receipt; a later stat must
  // never authorize a replacement occupying the same locator.
  const fileIdentity = identity.key.startsWith("file:")
    ? Object.freeze({
        key: expectedFileIdentity?.key ?? identity.key,
        birthtime: expectedFileIdentity ? expectedFileIdentity.birthtime : identity.birthtime,
      })
    : undefined;
  const retained = retainSessionHistoryWorkerDatabase(
    captured,
    lane === "maintenance" ? maintenanceLane : historyLane,
  );
  const pending = new Set<Promise<unknown>>();
  let closing = false;
  let release: Promise<void> | undefined;
  const assertCurrent = () => {
    if (closing) {
      throw new WorkerTaskError("Session transcript reconcile reader was released", "unavailable");
    }
    retained.owner.assertCurrent();
    if (fileIdentity) {
      assertExistingDatabaseIdentity(captured.path, fileIdentity.key, fileIdentity.birthtime);
    }
  };
  return {
    fileIdentity,
    assertCurrent,
    isRevokedFailure: (error) => retained.isRevokedFailure(error),
    read(sessionId) {
      assertCurrent();
      const reading = retained.owner.readTranscriptReconcilePendingResult({
        env: captured.env,
        sessionId,
        fileIdentity,
      });
      pending.add(reading);
      void reading.then(
        () => pending.delete(reading),
        () => pending.delete(reading),
      );
      return reading;
    },
    release() {
      if (!release) {
        closing = true;
        release = (async () => {
          await Promise.allSettled(pending);
          retained.release();
        })().catch((error: unknown) => {
          // Failed owner release remains retryable without admitting another read.
          release = undefined;
          throw error;
        });
      }
      return release;
    },
  };
}
