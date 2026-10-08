// Per-session readiness consumes the reconciliation owner's live map and admission closures.
import { setTimeout as delay } from "node:timers/promises";
import { isIncognitoSessionKey, resolveAgentIdFromSessionKey } from "../../routing/session-key.js";
import {
  captureAgentDeletionDatabaseCleanupTarget,
  getAgentDeletionDatabaseCleanup,
} from "../../state/agent-deletion-cleanup.js";
import { hasAgentDatabaseMaintenanceAuthority } from "../../state/openclaw-agent-db-lease.js";
import { withOpenClawAgentDatabaseReadOnly } from "../../state/openclaw-agent-db-readonly.js";
import { waitForAgentDatabaseResourceClose } from "../../state/openclaw-agent-db-resources.js";
import {
  resolveOpenClawAgentSqlitePath,
  type OpenClawAgentDatabaseOptions,
} from "../../state/openclaw-agent-db.js";
import { supportsOpenClawAgentDatabaseExecution } from "../../state/openclaw-agent-execution.js";
import { captureOpenClawStateWorkerContext } from "../../state/openclaw-state-worker-context.js";
import type { SessionTranscriptReadScope } from "./session-accessor.sqlite-contract.js";
import {
  prepareSqliteTranscriptReadScope,
  resolveSqliteTranscriptReadScope,
  resolveSqliteWriteAdmissionScope,
  toDatabaseOptions,
  type ResolvedTranscriptReadScope,
} from "./session-accessor.sqlite-scope.js";
import { sessionTranscriptIndexNeedsReconcile } from "./session-transcript-index.js";
import { releaseReconcileResources } from "./session-transcript-reconcile-custody.js";
import {
  captureSessionTranscriptReconcileGeneration,
  isSessionTranscriptReconcileGenerationCurrent,
} from "./session-transcript-reconcile-pool.js";
import { captureSessionTranscriptReconcileReader } from "./session-transcript-reconcile-reader.js";

const PROJECTION_READY_POLL_MS = 10;
type ReadinessReconcileParams = OpenClawAgentDatabaseOptions & {
  env: NodeJS.ProcessEnv;
  generation: number;
  preferredSessionId?: string;
  expectedFileIdentity?: { key: string; birthtime?: string };
};
type TranscriptReconcileReadinessOwner = {
  get(
    key: string,
  ): { generation: number; signal?: AbortSignal; promise?: Promise<unknown> } | undefined;
  start(params: ReadinessReconcileParams): void;
};

/** Waits only until the requested session's scheduled projection rebuild settles. */
export async function waitForSessionTranscriptProjectionInOwner(
  scope: SessionTranscriptReadScope,
  owner: TranscriptReconcileReadinessOwner,
  abortSignal?: AbortSignal,
): Promise<void> {
  const captured = { ...scope, env: { ...(scope.env ?? process.env) } };
  const generation = captureSessionTranscriptReconcileGeneration();
  const incognito = isIncognitoSessionKey(captured.sessionKey);
  // Retain the original shared-state authority before even exact locators yield.
  const stateContext = incognito
    ? undefined
    : captureOpenClawStateWorkerContext({ env: captured.env });
  const exactAdmission = incognito
    ? undefined
    : resolveSqliteWriteAdmissionScope({
        ...captured,
        sessionKey: captured.sessionKey ?? "",
      });
  const deletion = incognito
    ? undefined
    : captureAgentDeletionDatabaseCleanupTarget({
        ...captured,
        agentId:
          exactAdmission?.agentId ??
          captured.agentId ??
          resolveAgentIdFromSessionKey(captured.sessionKey, captured.defaultAgentId ?? "main"),
      });
  if (
    deletion &&
    (!exactAdmission ||
      exactAdmission.agentId !== deletion.agentId ||
      resolveOpenClawAgentSqlitePath(toDatabaseOptions(exactAdmission)) !== deletion.path)
  ) {
    throw new Error("Transcript readiness requires its exact deletion cleanup locator");
  }
  const assertSourceCurrent = () => {
    abortSignal?.throwIfAborted();
    stateContext?.maintenanceScope?.assertAdmission();
    stateContext?.admission.assertCurrent();
    deletion?.assertCurrent();
  };
  const native =
    incognito ||
    stateContext?.maintenanceScope?.ownsSchemaMaintenance === true ||
    hasAgentDatabaseMaintenanceAuthority() ||
    deletion !== undefined;
  // Process-held authority cannot be transferred into custom-target discovery.
  const resolved = native
    ? resolveSqliteTranscriptReadScope(captured)
    : await prepareSqliteTranscriptReadScope(captured, abortSignal);
  assertSourceCurrent();
  if (!isSessionTranscriptReconcileGenerationCurrent(generation)) {
    return;
  }
  const databaseOptions: ReadinessReconcileParams = {
    ...toDatabaseOptions(resolved),
    env: captured.env,
    generation,
  };
  const key = resolveOpenClawAgentSqlitePath(databaseOptions);
  if (deletion && !getAgentDeletionDatabaseCleanup({ ...databaseOptions, path: key })) {
    throw new Error("Transcript readiness differs from its exact deletion cleanup target");
  }
  if (native) {
    return await waitForNativeTranscriptProjection(
      resolved,
      databaseOptions,
      abortSignal,
      assertSourceCurrent,
      owner,
    );
  }
  if (!supportsOpenClawAgentDatabaseExecution(databaseOptions)) {
    throw new Error("Transcript readiness source changed during asynchronous discovery");
  }
  const readerOptions = { ...databaseOptions, path: key };
  let reader: ReturnType<typeof captureSessionTranscriptReconcileReader> | undefined =
    captureSessionTranscriptReconcileReader(readerOptions);
  const originalFile = reader.fileIdentity;
  const needsReconcile = async () => {
    assertSourceCurrent();
    if (!reader) {
      if (!originalFile) {
        throw new Error("Transcript readiness cannot renew an unbound physical database");
      }
      reader = captureSessionTranscriptReconcileReader(readerOptions, "history", originalFile);
    }
    const pending = await reader.read(resolved.sessionId);
    assertSourceCurrent();
    reader.assertCurrent();
    if (!pending.ok) {
      throw pending.error;
    }
    return pending.value.found && pending.value.pending;
  };
  let failure: { error: unknown } | undefined;
  try {
    let running = owner.get(key);
    while (running) {
      if (!isSessionTranscriptReconcileGenerationCurrent(generation)) {
        await running.promise;
        return;
      }
      let revokedRead: { error: unknown } | undefined;
      if (!running.signal?.aborted) {
        try {
          if (!(await needsReconcile())) {
            return;
          }
        } catch (error) {
          // Only this retained owner's exact revocation may renew the read. Query,
          // transport and cleanup failures keep their ordinary refusal contract.
          if (!running.signal?.aborted || !reader?.isRevokedFailure(error)) {
            throw error;
          }
          revokedRead = { error };
        }
      }
      if (running.signal?.aborted) {
        await releaseReconcileResources(async () => {
          await reader?.release();
          reader = undefined;
        }, revokedRead);
        await running.promise;
        await waitForAgentDatabaseResourceClose(readerOptions);
        assertSourceCurrent();
        if (!isSessionTranscriptReconcileGenerationCurrent(generation)) {
          return;
        }
        if (owner.get(key) === undefined && (await needsReconcile())) {
          owner.start({
            ...databaseOptions,
            ...(originalFile ? { expectedFileIdentity: originalFile } : {}),
            preferredSessionId: resolved.sessionId,
          });
        }
      } else {
        await delay(
          PROJECTION_READY_POLL_MS,
          undefined,
          abortSignal ? { signal: abortSignal } : undefined,
        );
        assertSourceCurrent();
      }
      running = owner.get(key);
    }
  } catch (error) {
    failure = { error };
    throw error;
  } finally {
    await releaseReconcileResources(async () => {
      await reader?.release();
    }, failure);
  }
}

/** Incognito, maintenance and exact deletion cleanup retain their native readiness kernel. */
async function waitForNativeTranscriptProjection(
  resolved: ResolvedTranscriptReadScope,
  databaseOptions: ReadinessReconcileParams,
  abortSignal: AbortSignal | undefined,
  assertCurrent: () => void,
  owner: TranscriptReconcileReadinessOwner,
): Promise<void> {
  const key = resolveOpenClawAgentSqlitePath(databaseOptions);
  const needsReconcile = () => {
    assertCurrent();
    const pending = withOpenClawAgentDatabaseReadOnly(
      ({ db }) => sessionTranscriptIndexNeedsReconcile(db, resolved.sessionId),
      databaseOptions,
    );
    return pending.found && pending.value;
  };
  let running = owner.get(key);
  while (running) {
    // Revoked work retains its close fence until settlement. Keep waiting without
    // admitting a reader or recreating a disposed incognito owner.
    if (!running.signal?.aborted && !needsReconcile()) {
      return;
    }
    await delay(
      PROJECTION_READY_POLL_MS,
      undefined,
      abortSignal ? { signal: abortSignal } : undefined,
    );
    assertCurrent();
    if (
      owner.get(key) === undefined &&
      running.signal?.aborted &&
      isSessionTranscriptReconcileGenerationCurrent(running.generation) &&
      needsReconcile()
    ) {
      // This waiting caller still needs the existing disk projection after cache
      // turnover. Re-admit through the owner without reviving a retired lifecycle.
      owner.start({
        ...databaseOptions,
        generation: running.generation,
        preferredSessionId: resolved.sessionId,
      });
    }
    running = owner.get(key);
  }
}
