import type { DatabaseSync } from "node:sqlite";
import { sql } from "kysely";
import { resolveStateDir } from "../config/paths.js";
import { isGatewayExternallySupervised } from "../infra/gateway-supervision.js";
import { registerNodeSqliteDisposeCallback } from "../infra/kysely-sync-cache-state.js";
import {
  enableNodeSqliteKyselyStatementCache,
  executeSqliteQuerySync,
  executeSqliteQueryTakeFirstSync,
  getNodeSqliteKysely,
} from "../infra/kysely-sync.js";
import {
  openNodeSqliteDatabase,
  resolveExistingSqliteFileUri,
  supportsNodeSqliteExtensionLoading,
} from "../infra/node-sqlite.js";
import { setSqliteBusyTimeout } from "../infra/sqlite-busy-timeout.js";
import { quarantineOrphanedSqliteSidecars } from "../infra/sqlite-files.js";
import {
  isTerminalSqliteIntegrityError,
  type SqliteIntegrityDiagnostics,
  type SqliteIntegrityOperation,
} from "../infra/sqlite-integrity.js";
import { admitSqliteSchema } from "../infra/sqlite-schema-facts.js";
import { isSqliteSchemaVersionError } from "../infra/sqlite-user-version.js";
import { prepareSqliteDatabaseDirectory } from "../infra/sqlite-wal-filesystem.js";
import { createSqliteWalReclamationResult } from "../infra/sqlite-wal-reclamation.js";
import {
  configureSqliteConnectionPragmas,
  configureSqlitePreSchemaPragmas,
  registerSqliteCacheExitClose,
  type SqliteWalMaintenance,
} from "../infra/sqlite-wal.js";
import { assertExistingDatabaseIdentity } from "../infra/sqlite-worker-identity.js";
import { requestSqliteWorkerOperationAdmission } from "../infra/sqlite-worker-operation-admission.js";
import { normalizeAgentId } from "../routing/session-key.js";
import {
  assertAgentCreationClaimCurrent,
  registerAgentCreationClaimHandle,
  reserveAgentCreationClaimAdmission,
} from "./agent-creation-claim.js";
import { assertAgentDatabaseAdmitted } from "./agent-database-admission.js";
import {
  getAgentDeletionDatabaseCleanup,
  registerAgentDeletionDatabaseCleanup,
} from "./agent-deletion-cleanup.js";
import { assertCanonicalSessionValidationSchema } from "./openclaw-agent-canonical-validation-schema.js";
import type {
  OpenClawAgentDatabase,
  OpenClawAgentDatabaseOptions,
  OpenClawAgentDatabaseRegistrationObserver,
  OpenClawAgentDatabaseRepairAdmission,
} from "./openclaw-agent-db-contract.js";
import {
  assertOpenClawAgentDatabaseIdentity,
  registerOpenClawAgentDatabaseIdentity,
  readOpenClawAgentDatabaseIdentity,
} from "./openclaw-agent-db-identity.js";
import { agentDatabaseAdmissionProvenanceRefusal } from "./openclaw-agent-db-lease-provenance.js";
import {
  hasAgentDatabaseMaintenanceAuthority,
  assertOpenClawAgentDatabaseLease,
  claimOpenClawAgentDatabaseLease,
  recordOpenClawAgentDatabaseAdmission,
  releaseOpenClawAgentDatabaseLease,
  type OpenClawAgentIntegrityVerificationReceiver,
  type prepareOpenClawAgentDatabaseWorkerLease,
} from "./openclaw-agent-db-lease.js";
import {
  agentDatabaseLifecycle as cache,
  startAgentDatabaseOpenTiming,
  recordOpenClawAgentDatabaseOpenFailure,
  closeCachedOpenClawAgentDatabase,
  createAgentDatabaseScopeOwnedClose,
  closeMaintenanceAgentDatabase,
  closeOpenClawAgentDatabaseByPathAsync,
  closeOpenClawAgentDatabases,
  refreshAgentDatabaseIdleTimer,
  registerAgentDatabaseHandle,
  retainIncognitoSharedState,
  retainFailedAgentDatabaseClose,
  revokePendingAgentDatabaseOpen,
  type PendingAgentDatabaseOpen,
} from "./openclaw-agent-db-lifecycle.js";
import * as openingRefusal from "./openclaw-agent-db-opening-refusal.js";
import { ensureOpenClawAgentDatabasePermissions } from "./openclaw-agent-db-permissions.js";
import { closeIdleOpenClawAgentDatabaseReadOnly } from "./openclaw-agent-db-readonly-scope.js";
import { registerOpenClawAgentDatabase } from "./openclaw-agent-db-registry.js";
import { assertAgentDatabaseResourceAdmission } from "./openclaw-agent-db-resources.js";
import {
  assertCanonicalAgentPersistenceVersion,
  assertCurrentAgentSchemaMetadata,
  assertExistingAgentSchemaOwner,
  assertSupportedAgentSchemaVersion,
  readExistingAgentSchemaMeta,
} from "./openclaw-agent-db-schema-helpers.js";
import {
  agentDatabaseIntegrityBeforeMutationSteps,
  ensureOpenClawAgentSchema,
} from "./openclaw-agent-db-schema.js";
import { revalidateAgentDatabaseTerminalOpen } from "./openclaw-agent-db-terminal.js";
import {
  adoptOpenClawAgentDatabaseValidation,
  adoptOpenClawAgentDatabaseSchema,
  getOpenClawAgentDatabaseValidation,
  hasOpenClawAgentDatabaseValidationSpelling,
  invalidateOpenClawAgentDatabaseValidation,
  publishOpenClawAgentDatabaseSchema,
} from "./openclaw-agent-db-validation-cache.js";
import {
  assertIncognitoAgentDatabasePathAvailable,
  isIncognitoOpenClawAgentSqlitePath,
  resolveOpenClawAgentSqlitePath,
} from "./openclaw-agent-db.paths.js";
import { registerOpenClawAgentWalMaintenance } from "./openclaw-agent-db.wal.js";
import { requestOpenClawAgentDatabaseIntegrityCheck } from "./openclaw-database-verify.js";
import {
  readOpenClawDatabaseQuarantineFailure,
  resolveAgentDatabaseIntegrityGateReason,
  type OpenClawAgentIntegrityVerification,
} from "./openclaw-quarantine-store.js";
import { getOpenClawDatabaseMaintenanceScope } from "./openclaw-state-db-async-lifecycle.js";
import { OPENCLAW_SQLITE_BUSY_TIMEOUT_MS } from "./openclaw-state-db.js";

export function createOpenClawAgentDatabaseOpenSteps(
  getOpenClawAgentDatabaseIfOpen: (
    options: OpenClawAgentDatabaseOptions,
  ) => OpenClawAgentDatabase | undefined,
) {
  return function* openOpenClawAgentDatabaseSteps(
    options: OpenClawAgentDatabaseOptions,
    pending?: PendingAgentDatabaseOpen,
    preparedLease?: ReturnType<typeof prepareOpenClawAgentDatabaseWorkerLease>,
    registrationObserver?: OpenClawAgentDatabaseRegistrationObserver,
    repairAdmission?: OpenClawAgentDatabaseRepairAdmission,
  ): SqliteIntegrityOperation<OpenClawAgentDatabase> {
    const agentId = normalizeAgentId(options.agentId);
    assertAgentDatabaseAdmitted(agentId, { env: options.env });
    const databaseOptions = { ...options, agentId };
    const pathname = resolveOpenClawAgentSqlitePath(databaseOptions);
    const assertCurrent = (database?: Pick<OpenClawAgentDatabase, "db" | "path">) => {
      repairAdmission?.assertCurrent?.();
      if (repairAdmission?.expectedIdentity) {
        if (database) {
          assertOpenClawAgentDatabaseIdentity(database, repairAdmission.expectedIdentity);
        } else {
          assertExistingDatabaseIdentity(
            pathname,
            repairAdmission.expectedIdentity.key,
            repairAdmission.expectedIdentity.birthtime,
          );
        }
      }
    };
    assertCurrent();
    assertAgentCreationClaimCurrent(databaseOptions);
    getAgentDeletionDatabaseCleanup(databaseOptions)?.assertCurrent();
    const incognito = isIncognitoOpenClawAgentSqlitePath(pathname, databaseOptions);
    // A live successful cache entry is authoritative; failed entries remain only for disposal.
    const opened = getOpenClawAgentDatabaseIfOpen(databaseOptions);
    if (opened) {
      assertCurrent(opened);
      if (preparedLease) {
        throw new Error("A prepared Worker lease cannot adopt an existing agent database handle");
      }
      if (pending?.workerPrepared) {
        adoptOpenClawAgentDatabaseSchema(opened, true, true);
      }
      return opened;
    }
    assertAgentDatabaseResourceAdmission({ agentId, path: pathname });
    if (!pending) {
      revokePendingAgentDatabaseOpen(pathname);
    }
    const cached = cache.databases.get(pathname);
    const allowExtension = !process.permission && supportsNodeSqliteExtensionLoading();
    if (incognito) {
      // The sentinel has no reachable durable owner, so doctor cannot safely migrate a collision.
      // Refuse operator-created state instead of silently shadowing it with volatile writes.
      assertIncognitoAgentDatabasePathAvailable(pathname);
      if (cached) {
        closeCachedOpenClawAgentDatabase(cached);
        cache.databases.delete(pathname);
        cache.failures.delete(pathname);
      }
      // After the collision probe, this sentinel is only a cache key: SQLite opens :memory:,
      // and no directory, lease, registry row, WAL sidecar, or file write may be created.
      const db = openNodeSqliteDatabase(":memory:", { allowExtension });
      db.enableLoadExtension(false);
      if (!openingRefusal.mainThread) {
        // Worker-owned incognito must never spill SQLite temporary content to disk.
        executeSqliteQuerySync(db, {
          compile: () => sql`PRAGMA temp_store=MEMORY`.compile(getNodeSqliteKysely(db)),
        });
        // Admit the memory-only policy before schema work can use temporary pages.
        const tempStore = executeSqliteQueryTakeFirstSync(db, {
          compile: () => sql`PRAGMA temp_store`.compile(getNodeSqliteKysely(db)),
        });
        if (
          !tempStore ||
          typeof tempStore !== "object" ||
          !("temp_store" in tempStore) ||
          tempStore.temp_store !== 2
        ) {
          throw new Error("Incognito actor requires memory-only SQLite temporary storage");
        }
      }
      configureSqlitePreSchemaPragmas(db, {
        busyTimeoutMs: OPENCLAW_SQLITE_BUSY_TIMEOUT_MS,
      });
      const walMaintenance = configureSqliteConnectionPragmas(db, {
        busyTimeoutMs: OPENCLAW_SQLITE_BUSY_TIMEOUT_MS,
        databaseLabel: `openclaw-agent-incognito:${agentId}`,
        foreignKeys: true,
        synchronous: "NORMAL",
      });
      ensureOpenClawAgentSchema(db, agentId, pathname);
      admitSqliteSchema(db);
      assertCanonicalSessionValidationSchema(db);
      registerOpenClawAgentDatabaseIdentity(db);
      const database = { agentId, db, path: pathname, walMaintenance };
      cache.incognito.add(database);
      cache.unregisterExitClose ??= registerSqliteCacheExitClose(closeOpenClawAgentDatabases);
      cache.databases.set(pathname, database);
      cache.generation += 1;
      registerNodeSqliteDisposeCallback(db, retainIncognitoSharedState(options.env));
      getOpenClawDatabaseMaintenanceScope()?.own(database.db, "agent-handles", () =>
        closeMaintenanceAgentDatabase(database),
      );
      return database;
    }
    if (!repairAdmission?.expectedIdentity) {
      quarantineOrphanedSqliteSidecars(pathname);
    }
    // Latched paths are quarantined; every fresh open fails fast here until
    // doctor repairs the file and clears the latch plus the persisted row.
    revalidateAgentDatabaseTerminalOpen(pathname);
    const persistedFailure = readOpenClawDatabaseQuarantineFailure("agent", pathname, {
      env: databaseOptions.env,
    });
    if (persistedFailure) {
      recordOpenClawAgentDatabaseOpenFailure(pathname, persistedFailure);
      throw persistedFailure;
    }
    if (cached) {
      // A closed handle can leave Kysely and WAL helpers cached; clear both before reopening.
      closeCachedOpenClawAgentDatabase(cached);
      cache.databases.delete(pathname);
      cache.failures.delete(pathname);
    }
    // Lease release must retain its original state owner after ambient env changes.
    const leaseEnvironment = {
      ...(options.env ?? process.env),
      OPENCLAW_STATE_DIR: resolveStateDir(options.env ?? process.env),
      ...(isGatewayExternallySupervised(options.env ?? process.env)
        ? { OPENCLAW_SUPERVISOR_MODE: "external" }
        : {}),
    };
    if (
      preparedLease &&
      (preparedLease.receipt.agentId !== agentId || preparedLease.receipt.path !== pathname)
    ) {
      throw new Error("Prepared agent database lease belongs to another store");
    }
    let verification: OpenClawAgentIntegrityVerification | undefined;
    let reuseIntegrity = false;
    let integrityRevoked = false;
    const diagnostics: SqliteIntegrityDiagnostics = {};
    const validation = pending?.validation ?? preparedLease?.validation;
    const captureVerification: OpenClawAgentIntegrityVerificationReceiver = (
      record,
      runtimeIntegrityAllowed,
      invalidated,
      because,
    ) => {
      verification = record;
      reuseIntegrity = runtimeIntegrityAllowed;
      integrityRevoked = invalidated;
      diagnostics.because = invalidated ? because : undefined;
      if (invalidated && validation) {
        // Stale-peer cleanup precedes adoption of proof already transferred by the host.
        Atomics.store(new Int32Array(validation.valid), 0, 0);
      }
    };
    const releaseOptions = { env: leaseEnvironment, initializationAgentPaths: [pathname] };
    assertCurrent();
    const leaseId = preparedLease
      ? preparedLease.claim(captureVerification)
      : claimOpenClawAgentDatabaseLease(
          { agentId, path: pathname, env: leaseEnvironment },
          undefined,
          captureVerification,
        );
    if (pending) {
      pending.assertHeld = () =>
        assertOpenClawAgentDatabaseLease(leaseId, {
          agentId,
          path: pathname,
          env: leaseEnvironment,
        });
    }
    const finishPhase = startAgentDatabaseOpenTiming(
      agentId,
      pathname,
      pending ? "async" : "sync",
      diagnostics,
    );
    let openedDb: DatabaseSync | undefined;
    let openedDatabase: OpenClawAgentDatabase | undefined;
    let openedWalMaintenance: SqliteWalMaintenance | undefined;
    let releaseCreationAdmission: (() => void) | undefined;
    try {
      assertCurrent();
      if (!repairAdmission?.expectedIdentity) {
        ensureOpenClawAgentDatabasePermissions(pathname, databaseOptions);
        prepareSqliteDatabaseDirectory(pathname);
      }
      closeIdleOpenClawAgentDatabaseReadOnly(pathname);
      // Ordinary agent state also works with SQLite builds that omit extensions.
      // Trusted borrowers may enable them only when both the runtime and permissions allow it.
      const db = openNodeSqliteDatabase(
        repairAdmission?.expectedIdentity ? resolveExistingSqliteFileUri(pathname) : pathname,
        { allowExtension },
      );
      openedDb = db;
      registerOpenClawAgentDatabaseIdentity(db);
      assertCurrent({ db, path: pathname });
      if (repairAdmission?.expectedIdentity) {
        ensureOpenClawAgentDatabasePermissions(pathname, databaseOptions);
      }
      db.enableLoadExtension(false);
      enableNodeSqliteKyselyStatementCache(db);
      if (preparedLease) {
        // Worker TEMP policy precedes schema/session caches and any exposed connection.
        executeSqliteQuerySync(db, {
          compile: () => sql`PRAGMA temp_store = FILE`.compile(getNodeSqliteKysely(db)),
        });
      }
      finishPhase("open");
      // Eviction churn must avoid migration/convergence and registry busy waits.
      // Version and owner can change while evicted, so their read-only gates run on every open.
      const validationDatabase = { db, path: pathname, agentId };
      if (validation) {
        adoptOpenClawAgentDatabaseValidation(validationDatabase, validation);
      }
      let isValidatedReopen = Boolean(getOpenClawAgentDatabaseValidation(validationDatabase));
      // Live worker admission already applied the foreign-lease integrity policy.
      const reuseAdmittedIntegrity =
        reuseIntegrity || (pending?.workerPrepared === true && !integrityRevoked);
      let reusedSchema = false;
      let walMaintenance: SqliteWalMaintenance;
      try {
        setSqliteBusyTimeout(db, OPENCLAW_SQLITE_BUSY_TIMEOUT_MS);
        reusedSchema = adoptOpenClawAgentDatabaseSchema(
          validationDatabase,
          reuseAdmittedIntegrity,
          pending?.workerPrepared,
        );
        assertSupportedAgentSchemaVersion(db, pathname);
        const existingSchema = readExistingAgentSchemaMeta(db);
        assertExistingAgentSchemaOwner(existingSchema, agentId, pathname);
        if (reusedSchema) {
          assertCurrentAgentSchemaMetadata(existingSchema, agentId, pathname);
        }
        if (pending) {
          releaseCreationAdmission = reserveAgentCreationClaimAdmission(
            pending,
            databaseOptions,
            async () => {
              await closeOpenClawAgentDatabaseByPathAsync(pathname, agentId);
            },
          );
        }
        // Runtime proof survives last-lease close; cold opens require clean-close proof.
        // Runtime proof carries owner revocation; every open still checks schema convergence.
        diagnostics.integrityGateReason = resolveAgentDatabaseIntegrityGateReason(
          validationDatabase,
          { verification, validation, integrityRevoked, reuseIntegrity },
        );
        diagnostics.because ??= integrityRevoked
          ? agentDatabaseAdmissionProvenanceRefusal(preparedLease?.provenance, pathname)
          : undefined;
        if (preparedLease && !openingRefusal.mainThread) {
          requestSqliteWorkerOperationAdmission({
            stage: "prepare",
            facts: { kind: "agent-validation-start", lease: preparedLease.receipt },
          });
        }
        const requiresCurrentVersionConvergence = yield* agentDatabaseIntegrityBeforeMutationSteps(
          db,
          agentId,
          pathname,
          diagnostics,
          verification,
          isValidatedReopen && reuseAdmittedIntegrity,
          integrityRevoked && !diagnostics.because,
          reusedSchema,
          preparedLease?.deferUnverifiedIntegrity,
        );
        assertCurrent(validationDatabase);
        if (!diagnostics.integrityGateOutcome || diagnostics.integrityGateOutcome === "cached") {
          delete diagnostics.integrityGateReason;
        }
        if (isValidatedReopen && (!existingSchema || requiresCurrentVersionConvergence)) {
          // New files and same-version divergence cannot inherit an earlier validation.
          // The existing full path initializes or converges them before exposure.
          invalidateOpenClawAgentDatabaseValidation(pathname);
          isValidatedReopen = false;
        }
        assertCanonicalAgentPersistenceVersion(db, pathname);
        finishPhase("validation");
        configureSqlitePreSchemaPragmas(db, {
          busyTimeoutMs: OPENCLAW_SQLITE_BUSY_TIMEOUT_MS,
        });
        walMaintenance = configureSqliteConnectionPragmas(db, {
          busyTimeoutMs: OPENCLAW_SQLITE_BUSY_TIMEOUT_MS,
          databaseLabel: `openclaw-agent:${agentId}`,
          databasePath: pathname,
          foreignKeys: true,
          synchronous: "NORMAL",
        });
        openedWalMaintenance = walMaintenance;
        finishPhase("configuration");
        assertCurrent(validationDatabase);
        if (!isValidatedReopen) {
          ensureOpenClawAgentSchema(db, agentId, pathname);
        }
        finishPhase("schema");
      } catch (err) {
        if (diagnostics.integrityGateOutcome === "failed") {
          finishPhase("validation");
        }
        openedWalMaintenance?.close();
        if (db.isOpen) {
          db.close();
        }
        const current = cache.databases.get(pathname);
        if (!current || current.db === db) {
          invalidateOpenClawAgentDatabaseValidation(pathname);
        }
        if (
          err instanceof Error &&
          (isSqliteSchemaVersionError(err) || isTerminalSqliteIntegrityError(err))
        ) {
          recordOpenClawAgentDatabaseOpenFailure(pathname, err);
        }
        throw err;
      }
      assertCurrent({ db, path: pathname });
      ensureOpenClawAgentDatabasePermissions(pathname, databaseOptions);
      if (!reusedSchema) {
        admitSqliteSchema(db);
        assertCanonicalSessionValidationSchema(db);
      }
      const database = { agentId, db, path: pathname, walMaintenance };
      openedDatabase = database;
      if (hasAgentDatabaseMaintenanceAuthority()) {
        throw new Error(
          "Agent database maintenance is in progress; retry after openclaw doctor --fix completes.",
        );
      }
      registerAgentDeletionDatabaseCleanup(database, databaseOptions)?.registerClose(
        createAgentDatabaseScopeOwnedClose(database, "Agent deletion cleanup"),
      );
      registerAgentCreationClaimHandle(database, databaseOptions)?.registerClose(
        createAgentDatabaseScopeOwnedClose(database, "Agent creation claim"),
      );
      // Physical proof does not register a newly used lexical alias.
      if (!isValidatedReopen || !hasOpenClawAgentDatabaseValidationSpelling(pathname)) {
        assertCurrent(database);
        registerOpenClawAgentDatabase(
          { agentId, path: pathname, env: options.env, admittedDb: db },
          registrationObserver,
        );
      } else if (!reusedSchema) {
        publishOpenClawAgentDatabaseSchema(database);
      }
      cache.terminal.clear(pathname);
      // Safety net for processes that end without an orderly close: agent DBs have
      // no shutdown owner like the ACP/gateway state DB closes. Closing unregisters.
      cache.unregisterExitClose ??= registerSqliteCacheExitClose(closeOpenClawAgentDatabases);
      finishPhase("registration");
      const deferred = diagnostics.integrityGateMode === "deferred";
      registerAgentDatabaseHandle(database, leaseId, leaseEnvironment, deferred);
      const identity = readOpenClawAgentDatabaseIdentity(database).identity;
      assertCurrent(database);
      if (
        deferred ||
        (diagnostics.integrityGateOutcome === "cached" && !(isValidatedReopen && reuseIntegrity))
      ) {
        const check = deferred ? "full" : "quick";
        if (preparedLease) {
          requestSqliteWorkerOperationAdmission({
            stage: "prepare",
            facts: {
              kind: "agent-integrity-check",
              lease: preparedLease.receipt,
              check,
            },
          });
        } else {
          requestOpenClawAgentDatabaseIntegrityCheck({
            path: pathname,
            env: leaseEnvironment,
            check,
          });
        }
      }
      if (typeof identity === "string") {
        recordOpenClawAgentDatabaseAdmission(
          leaseId,
          { agentId, path: pathname, env: leaseEnvironment },
          identity,
          !deferred && diagnostics.integrityGateOutcome !== "cached",
        );
      }
      refreshAgentDatabaseIdleTimer(database);
      if (openingRefusal.mainThread) {
        registerOpenClawAgentWalMaintenance(database, leaseEnvironment);
      }
      getOpenClawDatabaseMaintenanceScope()?.own(database.db, "agent-handles", () =>
        closeMaintenanceAgentDatabase(database),
      );
      releaseCreationAdmission?.();
      return database;
    } catch (error) {
      const refusal = openingRefusal.classifyAgentDatabaseOpeningRefusal(error, preparedLease);
      let closeError: unknown;
      if (openedDatabase) {
        try {
          closeCachedOpenClawAgentDatabase(openedDatabase);
        } catch (caught) {
          closeError = caught;
        }
      }
      if (openedDb?.isOpen) {
        if (
          pending &&
          cache.databases.has(pathname) &&
          cache.databases.get(pathname)?.db !== openedDb
        ) {
          // A synchronous opener may supersede pending work. Retain failed cleanup
          // with its original native owner; never overwrite the replacement cache/lease.
          const retainedDb = openedDb;
          retainFailedAgentDatabaseClose(agentId, pathname, () => {
            openedWalMaintenance?.close();
            if (retainedDb.isOpen) {
              retainedDb.close();
            }
            releaseOpenClawAgentDatabaseLease(leaseId, releaseOptions);
          });
          throw error;
        }
        invalidateOpenClawAgentDatabaseValidation(pathname);
        const retainedDatabase =
          openedDatabase ??
          ({
            agentId,
            db: openedDb,
            path: pathname,
            walMaintenance: openedWalMaintenance ?? {
              checkpoint: () => false,
              stop: async () => {},
              reclaimFreePages: createSqliteWalReclamationResult,
              close: () => false,
            },
          } satisfies OpenClawAgentDatabase);
        // Failed opens remain disposal-owned but cannot become successful cache hits.
        cache.databases.set(pathname, retainedDatabase);
        refreshAgentDatabaseIdleTimer(retainedDatabase);
        cache.leases.set(pathname, { leaseId, env: leaseEnvironment });
        cache.failures.set(pathname, closeError ?? error);
        getOpenClawDatabaseMaintenanceScope()?.own(retainedDatabase.db, "agent-handles", () =>
          closeMaintenanceAgentDatabase(retainedDatabase),
        );
        cache.unregisterExitClose ??= registerSqliteCacheExitClose(closeOpenClawAgentDatabases);
      } else if (!refusal.deferLeaseRelease) {
        try {
          releaseOpenClawAgentDatabaseLease(leaseId, releaseOptions, refusal.closeOutcome);
        } catch (releaseError) {
          retainFailedAgentDatabaseClose(agentId, pathname, () =>
            releaseOpenClawAgentDatabaseLease(leaseId, releaseOptions, refusal.closeOutcome),
          );
          throw releaseError;
        }
      }
      throw closeError ?? error;
    }
  };
}
