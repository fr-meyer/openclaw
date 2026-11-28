import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { resolveStateDir } from "../config/paths.js";
import type { SqliteIntegrityConfirmation } from "../infra/sqlite-integrity.js";
import { normalizeAgentId } from "../routing/session-key.js";
import {
  assertAgentCreationClaimAccess,
  assertAgentCreationClaimAliases,
} from "./agent-creation-claim.js";
import { assertAgentDatabaseAdmitted } from "./agent-database-admission.js";
import {
  assertAgentDeletionCleanupAliases,
  assertAgentDeletionDatabaseCleanupAccess,
} from "./agent-deletion-cleanup.js";
import { readAgentDeletionJournal } from "./agent-deletion-journal.js";
import { artifactPreservingReads } from "./artifact-preserving-state-reads.js";
import { createOpenClawAgentDatabaseAdmissionOwner } from "./openclaw-agent-db-admission.js";
import type {
  OpenClawAgentDatabase,
  OpenClawAgentDatabaseOptions,
} from "./openclaw-agent-db-contract.js";
import {
  isOpenClawAgentDatabasePathCurrent,
  readOpenClawAgentDatabaseIdentity,
} from "./openclaw-agent-db-identity.js";
import {
  agentDatabaseLifecycle as cache,
  closeOpenClawAgentDatabaseByPathAsync,
  refreshAgentDatabaseIdleTimer,
  retainAgentDatabase,
} from "./openclaw-agent-db-lifecycle.js";
import { createOpenClawAgentDatabaseOpenSteps } from "./openclaw-agent-db-open.js";
import {
  matchesAgentDatabaseReadCandidatePath,
  type OpenClawAgentDatabaseReadCandidateResource,
} from "./openclaw-agent-db-resources.js";
import { invalidateOpenClawAgentDatabaseValidation } from "./openclaw-agent-db-validation-cache.js";
import {
  isIncognitoOpenClawAgentSqlitePath,
  isSameOpenClawAgentDatabasePath,
  resolveOpenClawAgentSqlitePath,
} from "./openclaw-agent-db.paths.js";
import { clearOpenClawDatabaseQuarantine } from "./openclaw-quarantine-store.js";
import { observeOpenClawDatabaseMaintenanceResource } from "./openclaw-state-db-async-lifecycle.js";
import type { OpenClawStateDatabaseOptions } from "./openclaw-state-db-contract.js";

export {
  OPENCLAW_AGENT_SCHEMA_VERSION,
  type OpenClawAgentDatabase,
  type OpenClawAgentDatabaseOptions,
} from "./openclaw-agent-db-contract.js";
export { deferOpenClawAgentPostCommitPublication } from "./openclaw-agent-db-lifecycle.js";
export { ensureOpenClawAgentDatabasePermissions } from "./openclaw-agent-db-permissions.js";
export {
  listOpenClawRegisteredAgentDatabases,
  readOpenClawAgentDatabaseRegistryToken,
} from "./openclaw-agent-db-registry.js";
export { ensureOpenClawAgentDatabaseSchema } from "./openclaw-agent-db-schema.js";
export {
  isIncognitoOpenClawAgentSqlitePath,
  resolveIncognitoOpenClawAgentSqlitePath,
  resolveOpenClawAgentSqlitePath,
} from "./openclaw-agent-db.paths.js";

/** Drain the live owner before reconfirming an advisory failure in a native child. */
export async function confirmOpenClawAgentDatabaseIntegrity(
  pathname: string,
  lifetime?: import("./openclaw-database-verify.impl.js").DatabaseVerifyWorkerLifetime,
): Promise<SqliteIntegrityConfirmation> {
  const resolvedPath = path.resolve(pathname);
  await closeOpenClawAgentDatabaseByPathAsync(resolvedPath);
  // Closing breaks process ownership of the pathname. A replacement must
  // revalidate and claim its schema before the path can become trusted again.
  invalidateOpenClawAgentDatabaseValidation(resolvedPath);
  const { confirmDatabaseVerifyWorker } = await import("./openclaw-database-verify.impl.js");
  return confirmDatabaseVerifyWorker(
    { path: resolvedPath, kind: "agent", label: resolvedPath },
    lifetime,
  );
}

/**
 * Clear a terminal open failure after doctor rewrites the database file.
 * Returns false when the persisted quarantine row survived; callers must
 * surface that, or the next open re-quarantines the repaired file.
 */
export function clearOpenClawAgentDatabaseOpenFailure(
  pathname: string,
  options: OpenClawStateDatabaseOptions = {},
): boolean {
  const resolvedPath = path.resolve(pathname);
  const cleared = clearOpenClawDatabaseQuarantine(resolvedPath, { env: options.env });
  cache.terminal.clear(resolvedPath);
  return cleared;
}

export type { OpenClawAgentDatabaseWriteAdmission } from "./openclaw-agent-db-admission.js";
export const {
  openOpenClawAgentDatabase,
  runOpenClawAgentWriteTransaction,
  withOpenClawAgentDatabaseAsync,
  withOpenClawAgentDatabaseRuntime,
  withOpenClawAgentDatabaseRuntimeFromExecution,
  withOpenClawAgentDatabaseAdmission,
} = createOpenClawAgentDatabaseAdmissionOwner(
  createOpenClawAgentDatabaseOpenSteps(getOpenClawAgentDatabaseIfOpen),
);

/** Retain the exact verified connection across awaits; explicit disposal still revokes it. */
export function borrowOpenClawAgentDatabase(options: OpenClawAgentDatabaseOptions): {
  db: DatabaseSync;
  release: () => void;
} {
  const { db } = openOpenClawAgentDatabase(options);
  return { db, release: retainAgentDatabase(db) };
}

export function isOpenClawAgentDatabaseOpen(pathname: string): boolean {
  return cache.databases.get(path.resolve(pathname))?.db.isOpen === true;
}

/** Return the matching live cache entry without materializing a database. */
export function getOpenClawAgentDatabaseIfOpen(
  options: OpenClawAgentDatabaseOptions,
): OpenClawAgentDatabase | undefined {
  const agentId = normalizeAgentId(options.agentId);
  assertAgentDatabaseAdmitted(agentId, { env: options.env });
  const pathname = resolveOpenClawAgentSqlitePath({ ...options, agentId });
  // Incognito skips durable database leases, but still follows the agent deletion fence.
  if (
    isIncognitoOpenClawAgentSqlitePath(pathname, options) &&
    readAgentDeletionJournal(agentId, { env: options.env }, "runtime")
  ) {
    throw new Error(`OpenClaw agent database is unavailable while agent ${agentId} is deleted.`);
  }
  const database = cache.databases.get(pathname);
  if (!database?.db.isOpen) {
    assertAgentDeletionCleanupAliases(options, isSameOpenClawAgentDatabasePath);
    assertAgentCreationClaimAliases(options);
    return undefined;
  }
  if (cache.failures.has(pathname)) {
    throw cache.failures.get(pathname);
  }
  if (database.agentId !== agentId) {
    throw new Error(
      `OpenClaw agent database ${pathname} is already open for agent ${database.agentId}; requested agent ${agentId}.`,
    );
  }
  assertAgentDeletionDatabaseCleanupAccess(database, options);
  assertAgentCreationClaimAccess(database, options);
  observeOpenClawDatabaseMaintenanceResource(database.db);
  refreshAgentDatabaseIdleTimer(database);
  return database;
}

/** Existing native admission only: no open, companion, snapshot, extension or close fallback. */
export function borrowCommittedOpenClawAgentDatabaseIfOpen(options: OpenClawAgentDatabaseOptions) {
  if (artifactPreservingReads.getStore()) {
    throw new Error("Inspection context unsupported");
  }
  const pathname = resolveOpenClawAgentSqlitePath(options);
  const ownerLease = cache.leases.get(pathname);
  // Admission follows the actual native owner's captured namespace, never caller alias selection.
  if (
    !ownerLease ||
    path.resolve(resolveStateDir(options.env ?? process.env)) !==
      path.resolve(resolveStateDir(ownerLease.env)) ||
    (options.env ?? process.env).OPENCLAW_SUPERVISOR_MODE !==
      ownerLease.env.OPENCLAW_SUPERVISOR_MODE
  ) {
    throw new Error("Native owner namespace unavailable");
  }
  const database = getOpenClawAgentDatabaseIfOpen({ ...options, env: ownerLease.env });
  if (
    !database ||
    !database.db.isOpen ||
    database.db.isTransaction ||
    cache.incognito.has(database)
  ) {
    throw new Error("Committed native owner unavailable");
  }
  const identity = readOpenClawAgentDatabaseIdentity(database);
  // In-memory/unregistered identities cannot certify a currently selected physical file.
  if (typeof identity.identity !== "string" || !isOpenClawAgentDatabasePathCurrent(database)) {
    throw new Error("Native owner physical file unavailable");
  }
  let released = false;
  const assertCurrent = () => {
    if (
      released ||
      cache.leases.get(pathname) !== ownerLease ||
      cache.databases.get(pathname) !== database ||
      !isOpenClawAgentDatabasePathCurrent(database)
    ) {
      throw new Error("Native owner changed");
    }
    assertAgentDatabaseAdmitted(database.agentId, { env: ownerLease.env });
  };
  assertCurrent();
  const release = retainAgentDatabase(database.db);
  return {
    database,
    assertCurrent,
    release: () => {
      if (!released) {
        released = true;
        release();
      }
    },
  };
}

/** Pin only admitted native readers already present in captured discovery families. */
export function retainOpenClawAgentDatabaseReadCandidates(
  candidates: readonly Pick<OpenClawAgentDatabaseReadCandidateResource, "path" | "scope">[],
  env: NodeJS.ProcessEnv,
): { databases: readonly OpenClawAgentDatabase[]; release: () => void } {
  const retained: Array<{ database: OpenClawAgentDatabase; release: () => void }> = [];
  const release = () => {
    for (const reader of retained.toReversed()) {
      reader.release();
    }
  };
  try {
    for (const database of cache.databases.values()) {
      if (
        !database.db.isOpen ||
        database.db.isTransaction ||
        cache.incognito.has(database) ||
        !candidates.some((candidate) =>
          matchesAgentDatabaseReadCandidatePath(candidate, database.path),
        )
      ) {
        continue;
      }
      let admitted: OpenClawAgentDatabase | undefined;
      try {
        admitted = getOpenClawAgentDatabaseIfOpen({
          agentId: database.agentId,
          path: database.path,
          env,
        });
      } catch {
        // A refused cached writer cannot supply a read continuation. Fresh reads
        // retain the existing independent read-only schema and ownership checks.
        continue;
      }
      if (admitted === database) {
        retained.push({ database, release: retainAgentDatabase(database.db) });
      }
    }
    return { databases: retained.map(({ database }) => database), release };
  } catch (error) {
    release();
    throw error;
  }
}

export {
  closeOpenClawAgentDatabaseByPath,
  closeOpenClawAgentDatabaseByPathAsync,
  closeOpenClawAgentDatabasesForTest,
  closeOpenClawAgentDatabasesAsync,
  inspectOpenClawAgentDatabaseOwner,
  isIncognitoOpenClawAgentDatabase,
  listOpenIncognitoAgentDatabases,
  readOpenIncognitoAgentDatabaseGeneration,
  recordOpenClawAgentDatabaseOpenFailure,
  settleOpenClawAgentDatabaseWorkerClose,
  type OpenClawAgentDatabaseWorkerCloseResult,
} from "./openclaw-agent-db-lifecycle.js";
