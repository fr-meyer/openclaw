import fs from "node:fs/promises";
import path from "node:path";
import { formatErrorMessage, toErrorObject } from "openclaw/plugin-sdk/error-runtime";
import {
  resolveAgentWorkspaceDir,
  resolveMemorySearchConfig,
  resolveUserPath,
  type OpenClawConfig,
} from "openclaw/plugin-sdk/memory-core-host-engine-foundation";
import type {
  MemoryProviderStatus,
  MemorySearchManager,
  MemorySyncParams,
  MemoryWorkspaceFiles,
} from "openclaw/plugin-sdk/memory-core-host-engine-storage";
import { normalizeAgentId } from "openclaw/plugin-sdk/routing";
import { assertBoundedMemoryBootstrap } from "./bounded-admission-bootstrap.js";
import {
  assertBoundedMemoryOperation,
  boundedMemoryAdmissionActive,
  MemoryAdmissionRefused,
  preflightBoundedMemorySources,
  claimBoundedMemorySync,
  withBoundedMemoryWork,
  assertBoundedMemoryIdentity,
  bootstrapBoundedMemoryProvider,
} from "./bounded-admission.js";
import type { MemoryCoreAcquireLocalService } from "./embedding-local-service.js";
import type { EmbeddingProviderResult } from "./embeddings.js";
import { MemoryCandidateOrchestration } from "./manager-candidate-orchestration.js";
import { MemoryIndexDatabase } from "./manager-database-context.js";
import { isMemoryEmbeddingOperationError } from "./manager-embedding-errors.js";
import { memoryManagerLog as log, type MemoryManagerStateOptions } from "./manager-owner-state.js";
import {
  resolveEffectiveMemorySearchSettings,
  resolveMemoryEmbeddingProviderRequirement,
} from "./manager-provider-lifecycle.js";
import { collectPublishedMemoryStatus } from "./manager-published-status.js";
import { createMemoryIndexManagerRegistryGetter } from "./manager-registry-store.js";
import {
  normalizeMemoryIndexManagerPurpose,
  resolveMemoryIndexManagerCacheKey,
  type MemoryIndexManagerPurpose,
  type MemoryManagerAdmission,
} from "./manager-registry.js";
import { waitForMemoryReindexLock } from "./manager-reindex-lock.js";
import { resolveMemoryIndexProviderIdentities } from "./manager-reindex-state.js";
import { runMemorySearchMaintenance } from "./manager-search-maintenance.js";
import { hasTargetedSessionSyncParams } from "./manager-sync-control.js";
import type { MemoryCoreRuntimeHost } from "./runtime-host.js";
const getMemoryIndexManagerRegistry = createMemoryIndexManagerRegistryGetter<MemoryIndexManager>();
export { getMemoryIndexManagerRegistry };

const candidateStoreAdmission = Symbol("memory-candidate-store");

export class MemoryIndexManager
  extends MemoryCandidateOrchestration
  implements MemorySearchManager
{
  protected get managerOwner(): MemoryIndexManager {
    return this;
  }
  static async get(params: {
    memoryFiles?: MemoryWorkspaceFiles;
    cfg: OpenClawConfig;
    agentId: string;
    purpose?: MemoryIndexManagerPurpose;
    admission?: MemoryManagerAdmission;
    inspectSources?: boolean;
    acquireLocalService?: MemoryCoreAcquireLocalService;
    runInBackgroundContext?: MemoryCoreRuntimeHost["runInBackgroundContext"];
    maintenanceSource?: MemoryIndexManager;
    candidateStore?: {
      path: string;
      operationId: string;
      admission: typeof candidateStoreAdmission;
    };
  }): Promise<MemoryIndexManager | null> {
    if (
      params.candidateStore &&
      (params.candidateStore.admission !== candidateStoreAdmission ||
        params.purpose !== "cli" ||
        params.maintenanceSource)
    ) {
      throw new Error("Invalid isolated candidate store admission");
    }
    const source = params.maintenanceSource;
    // Do not derive an ordinary maintenance manager from candidate custody.
    // Refuse before registry/provider/database acquisition rather than dropping
    // the candidate restriction on a newly constructed owner.
    source?.assertOrdinaryMemoryAdmission();
    const memoryFiles = source?.memoryFiles ?? params.memoryFiles;
    memoryFiles?.assertCurrent();
    const cfg = source?.cfg ?? params.cfg;
    const agentId = source?.agentId ?? normalizeAgentId(params.agentId);
    assertBoundedMemoryOperation(agentId);
    await preflightBoundedMemorySources(agentId);
    const purpose = normalizeMemoryIndexManagerPurpose(params.purpose);
    const managerRegistry = source?.managerRegistry ?? getMemoryIndexManagerRegistry();
    return await managerRegistry.acquire(
      { agentId, purpose, ...(params.admission ? { admission: params.admission } : {}) },
      {
        prepare: () => {
          const configuredSettings = source?.settings ?? resolveMemorySearchConfig(cfg, agentId);
          const settings =
            configuredSettings && params.candidateStore
              ? {
                  ...configuredSettings,
                  store: { ...configuredSettings.store, databasePath: params.candidateStore.path },
                }
              : configuredSettings;
          if (!settings) {
            return null;
          }
          const workspaceDir = source?.workspaceDir ?? resolveAgentWorkspaceDir(cfg, agentId);
          const providerRequirement =
            source?.providerRequirement ??
            resolveMemoryEmbeddingProviderRequirement({
              cfg,
              agentId,
              settings,
            });
          const key = resolveMemoryIndexManagerCacheKey({
            agentId,
            workspaceDir,
            settings,
            providerRequirement,
            purpose,
            acquireLocalService: params.acquireLocalService,
          });
          const databaseOptions = MemoryIndexDatabase.captureWriteOptions(
            agentId,
            settings.store.databasePath,
            source?.publishedDatabase,
          );
          return {
            key,
            create: async () => {
              let manager: MemoryIndexManager | undefined;
              try {
                if (source && (!source.publishedDatabase.db.isOpen || purpose !== "maintenance")) {
                  throw new Error("Memory maintenance source connection is unavailable");
                }
                const effectiveSettings = resolveEffectiveMemorySearchSettings(settings);
                const publishedDatabase = await MemoryIndexDatabase.openPublished({
                  agentId,
                  beforeSchema: (db) => assertBoundedMemoryBootstrap(db, agentId, settings),
                  writeOptions: databaseOptions,
                  readOnly: purpose === "status",
                  allowExtension: effectiveSettings.store.vector.enabled,
                  maintenanceSource: source?.publishedDatabase,
                  schema: {
                    cacheEnabled: effectiveSettings.cache.enabled,
                    ftsEnabled: effectiveSettings.query.hybrid.enabled,
                    ftsTokenizer: effectiveSettings.store.fts.tokenizer,
                  },
                });
                manager = new MemoryIndexManager({
                  managerRegistry,
                  cacheKey: key,
                  cfg,
                  agentId,
                  workspaceDir,
                  memoryFiles,
                  settings,
                  providerRequirement,
                  purpose,
                  acquireLocalService: params.acquireLocalService,
                  runInBackgroundContext: source?.backgroundRunner ?? params.runInBackgroundContext,
                  maintenanceSource: source,
                  candidateOperationId: params.candidateStore?.operationId,
                  databaseOptions,
                  publishedDatabase,
                });
                managerRegistry.track(manager, key);
                // Filesystem discovery is asynchronous and must not hold the
                // agent database's write admission while attaching watchers.
                await manager.memoryWatcherReady;
                await manager.loadBatchSubmissionStatus();
                if (params.inspectSources) {
                  await manager.inspectDiagnosticSourceState();
                }
                memoryFiles?.assertCurrent();
                return manager;
              } catch (error) {
                try {
                  await manager?.close();
                } catch (cleanupError) {
                  throw new AggregateError(
                    [error, cleanupError],
                    "Memory manager preparation cleanup failed",
                    { cause: cleanupError },
                  );
                }
                throw error;
              }
            },
            reuse: ({ closing, closed, db, memoryFiles: files, backgroundRunner }) =>
              !closing &&
              !closed &&
              db.isOpen &&
              files === memoryFiles &&
              backgroundRunner === (source?.backgroundRunner ?? params.runInBackgroundContext),
          };
        },
      },
    );
  }
  private constructor(params: MemoryManagerStateOptions) {
    super(params);
  }

  /** Allocate a named isolated export using the native manager and DB owners.
   * Existing export custody blocks restart before any provider initialization.
   * The config is candidate-only input, never installed as serving configuration.
   */
  async createCandidateManager(params: {
    cfg: OpenClawConfig;
    operationId: string;
  }): Promise<MemoryIndexManager> {
    if (
      this.closed ||
      this.closing ||
      this.candidateOperationId ||
      !/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/.test(params.operationId)
    ) {
      throw new Error("Invalid serving owner or candidate operation identity");
    }
    return await this.withManagerOperation(async () => {
      const servingPath = await fs.realpath(resolveUserPath(this.settings.store.databasePath));
      const directory = servingPath + ".memory-candidate-" + params.operationId;
      await fs.mkdir(directory, { mode: 0o700 });
      // Empty directories on initialization failure remain an explicit recovery
      // decision, not a reason to recursively remove unknown/accepted work.
      const manager = await MemoryIndexManager.get({
        cfg: params.cfg,
        agentId: this.agentId,
        purpose: "cli",
        candidateStore: {
          path: path.join(directory, "store.sqlite"),
          operationId: params.operationId,
          admission: candidateStoreAdmission,
        },
        acquireLocalService: this.acquireLocalService,
        runInBackgroundContext: this.backgroundRunner,
        memoryFiles: this.memoryFiles,
      });
      if (!manager) {
        throw new Error("Candidate memory configuration is disabled");
      }
      return manager;
    });
  }

  override async search(
    ...args: Parameters<MemoryCandidateOrchestration["search"]>
  ): ReturnType<MemoryCandidateOrchestration["search"]> {
    // Refuse before inherited retrieval can initialize/query a provider or
    // bootstrap an empty index through syncAdmitted rather than public sync.
    this.assertOrdinaryMemoryAdmission();
    return await super.search(...args);
  }

  async bootstrapBoundedProvider(): Promise<void> {
    assertBoundedMemoryOperation(this.agentId);
    // Exact installed OpenAI adapter only. Its constructor resolves transport
    // but performs no embedding dispatch; all embedding calls start below.
    if (this.settings.provider !== "openai") {
      throw new MemoryAdmissionRefused();
    }
    const result = await bootstrapBoundedMemoryProvider(this.agentId, async () =>
      this.createConfiguredEmbeddingProvider(),
    );
    await this.adoptBoundedProvider(result);
  }
  async adoptBoundedProvider(result: EmbeddingProviderResult): Promise<void> {
    assertBoundedMemoryOperation(this.agentId);
    if (
      !boundedMemoryAdmissionActive(this.agentId) ||
      this.syncing ||
      this.providerInitialized ||
      !result.provider ||
      result.fallbackFrom
    ) {
      throw new MemoryAdmissionRefused();
    }
    const identity = resolveMemoryIndexProviderIdentities({
      provider: result.provider,
      cacheKeyData: result.runtime?.cacheKeyData,
    }).at(0);
    assertBoundedMemoryIdentity(this.agentId, result.provider, identity?.providerKey ?? null);
    this.applyProviderResult(result);
    this.providerKey = this.computeProviderKey();
    this.batch = this.resolveBatchConfig();
    if (this.batch.enabled) {
      throw new MemoryAdmissionRefused();
    }
  }
  async sync(params?: MemorySyncParams): Promise<void> {
    this.assertOrdinaryMemoryAdmission();
    assertBoundedMemoryOperation(this.agentId);
    if (boundedMemoryAdmissionActive(this.agentId)) {
      claimBoundedMemorySync(this.agentId);
      if (
        this.syncing ||
        this.closed ||
        this.closing ||
        params?.force ||
        params?.sessions ||
        params?.archiveFiles ||
        this.batch.enabled ||
        this.memoryFullRetryDirty ||
        this.sessionsFullRetryDirty ||
        !this.providerInitialized ||
        !this.provider
      ) {
        throw new MemoryAdmissionRefused();
      }
      assertBoundedMemoryIdentity(this.agentId, this.provider, this.providerKey);
      if (
        this.resolveCurrentIndexIdentityState({ meta: this.readMeta(), providerKeyKnown: true })
          .status !== "valid"
      ) {
        throw new MemoryAdmissionRefused();
      }
      return await this.withManagerOperation(() =>
        withBoundedMemoryWork(this.agentId, async () => {
          this.beginSyncProviderGeneration();
          try {
            await this.syncMemoryFiles({ needsFullReindex: false });
          } finally {
            this.endSyncProviderGeneration();
          }
        }),
      );
    }
    if (this.purpose === "status") {
      throw new Error("Memory status managers are read-only");
    }
    if (this.closing || this.closed) {
      return;
    }
    // Close must drain accepted syncs through provider initialization and final writes.
    return await this.withManagerOperation(async () => {
      if (hasTargetedSessionSyncParams(params) && this.sessionSyncQueue.hasPending) {
        // A failed queued batch stays manager-owned. Route the next targeted
        // call through the queue even while idle so it adopts that retained work.
        return await this.sessionSyncQueue.enqueue(params);
      }
      return await this.syncAdmitted(params);
    });
  }
  protected async syncPublishedIndexInBackground(params: { reason: string }): Promise<void> {
    this.assertOrdinaryMemoryAdmission();
    if (this.syncing) {
      return await this.syncing;
    }
    await this.syncOutcomes.track(() =>
      runMemorySearchMaintenance({
        reason: params.reason,
        takeDirtyGeneration: () => this.takeSearchMaintenanceRequest(),
        restoreDirtyGeneration: (generation) => this.adoptReindexRetryState(generation),
        acquireManager: () =>
          MemoryIndexManager.get({
            cfg: this.cfg,
            agentId: this.agentId,
            purpose: "maintenance",
            acquireLocalService: this.acquireLocalService,
            maintenanceSource: this,
          }),
      }),
    );
  }
  protected async syncAdmitted(
    params?: MemorySyncParams,
    options?: {
      allowEmbeddingBootstrapFallback?: boolean;
      queuedSessionOwner?: boolean;
    },
  ): Promise<void> {
    assertBoundedMemoryOperation(this.agentId);
    if (boundedMemoryAdmissionActive(this.agentId)) {
      throw new MemoryAdmissionRefused();
    }
    // Covers search bootstrap, queued sessions and all inherited sync callers.
    this.assertOrdinaryMemoryAdmission();
    if (this.syncing) {
      if (hasTargetedSessionSyncParams(params)) {
        if (options?.queuedSessionOwner) {
          // Another caller claimed the sync slot after this queue owner was
          // created. Wait for it, then retry admission instead of enqueueing
          // into the promise that is already awaiting this call.
          await this.syncing.catch(() => undefined);
          if (this.closing || this.closed) {
            return;
          }
          return await this.syncAdmitted(params, options);
        }
        return this.sessionSyncQueue.enqueue(params);
      }
      try {
        await this.syncing;
        // Watch events accepted after source planning belong to the next pass.
        // Joining the old promise alone would strand them until another search.
        if (
          params?.reason === "watch" &&
          this.dirty &&
          !this.closing &&
          !this.closed &&
          this.memoryWatchGeneration > this.syncingMemoryWatchGeneration
        ) {
          return await this.syncAdmitted(params, options);
        }
        return;
      } catch (err) {
        if (
          options?.allowEmbeddingBootstrapFallback &&
          this.providerRequirement.mode === "optional" &&
          (!this.providerInitialized || this.embeddingBootstrapFailure !== undefined)
        ) {
          if (!this.embeddingBootstrapFailure) {
            this.markEmbeddingBootstrapFailure(err);
          }
          return await this.syncAdmitted(params, options);
        }
        throw err;
      }
    }
    // An intentional no-progress pass may remain dirty. Only newly accepted
    // watch facts can admit another pass; joined callers cannot spin on dirty.
    this.syncingMemoryWatchGeneration = this.memoryWatchGeneration;
    const run = () =>
      this.publishedDatabase.withPublicationGeneration(async () => {
        const hadBootstrapFailure = this.embeddingBootstrapFailure !== undefined;
        let forceFtsOnly =
          this.embeddingBootstrapFailure !== undefined &&
          this.getCachedEmbeddingAvailability()?.ok === false;
        if (!forceFtsOnly) {
          try {
            await this.ensureProviderInitialized();
          } catch (err) {
            if (this.providerRequirement.mode !== "optional") {
              throw err;
            }
            // Background indexing must establish optional keyword fallback before the first search.
            this.markEmbeddingBootstrapFailure(err);
            forceFtsOnly = true;
          }
          if (hadBootstrapFailure && !this.provider) {
            this.refreshEmbeddingBootstrapFailure(this.embeddingBootstrapFailure!);
            forceFtsOnly = true;
          }
        }
        const runGeneration = async (keywordOnly: boolean) => {
          // Reset must not overtake embeddings awaiting their final incremental writes.
          // All sync generations own the existing maintenance lease through cleanup.
          const dbPath = resolveUserPath(this.settings.store.databasePath);
          const lock = await waitForMemoryReindexLock(dbPath, { waitForActive: true });
          try {
            await this.publishedDatabase.closePublicationWorker();
            this.beginSyncProviderGeneration({ forceFtsOnly: keywordOnly });
            try {
              await this.runSync(params).then(
                () => this.publishedDatabase.closePublicationWorker(),
                async (error: unknown) => {
                  const [cleanup] = await Promise.allSettled([
                    this.publishedDatabase.closePublicationWorker(),
                  ]);
                  if (cleanup.status === "rejected") {
                    throw new AggregateError(
                      [error, cleanup.reason],
                      `${String(error)}; Memory sync cleanup failed: ${String(cleanup.reason)}`,
                      { cause: error },
                    );
                  }
                  throw error;
                },
              );
            } finally {
              this.endSyncProviderGeneration();
            }
          } finally {
            await lock.release();
          }
        };
        try {
          await runGeneration(forceFtsOnly);
        } catch (err) {
          const canDegrade =
            this.providerRequirement.mode === "optional" &&
            (options?.allowEmbeddingBootstrapFallback || hadBootstrapFailure) &&
            isMemoryEmbeddingOperationError(err);
          if (!canDegrade) {
            throw err;
          }
          const failedProvider = this.provider?.id ?? this.settings.provider;
          this.markEmbeddingBootstrapFailure(err, {
            retainProvider: this.provider !== null,
            provider: failedProvider,
          });
          forceFtsOnly = true;
          await runGeneration(true);
        }
        if (
          hadBootstrapFailure &&
          !forceFtsOnly &&
          this.provider &&
          this.refreshIndexIdentityDirty({ providerKeyKnown: true }).status === "valid" &&
          (await this.confirmEmbeddingBootstrapRecovery())
        ) {
          this.clearEmbeddingBootstrapFailureAfterRecovery();
        }
      });
    this.syncing = this.syncOutcomes.track(run, true).finally(() => {
      this.syncing = null;
    });
    return this.syncing;
  }

  status(): MemoryProviderStatus {
    if (this.closing || this.closed) {
      throw new Error("Memory index manager is closed");
    }
    return this.withPublishedDatabase(() => this.publishedStatus());
  }

  private publishedStatus(): MemoryProviderStatus {
    if (this.embeddingBootstrapFailure) {
      this.refreshKeywordFallbackIndexIdentity();
    } else {
      this.refreshIndexIdentityDirty({
        providerKeyKnown: this.providerInitialized,
      });
    }
    const status = collectPublishedMemoryStatus(
      {
        activeBackgroundSearchSyncs: () => this.activeBackgroundSearchSyncs,
        automaticRebuildNotice: () => this.automaticRebuildNotice,
        batch: () => this.batch,
        batchFailure: () => this.batchFailure,
        batchFailureLimit: () => this.batchFailureLimit,
        cache: () => this.cache,
        database: () => this.database,
        db: () => this.db,
        dirty: () => this.dirty,
        embeddingBootstrapFailure: () => this.embeddingBootstrapFailure,
        fallbackFrom: () => this.fallbackFrom,
        fallbackReason: () => this.fallbackReason,
        fts: () => this.fts,
        indexIdentityDirty: () => this.indexIdentityDirty,
        indexIdentityState: () => this.indexIdentityState,
        memoryWatcherHealth: () => this.memoryWatcherHealth,
        provider: () => this.provider,
        providerInitialized: () => this.providerInitialized,
        providerLifecycle: () => this.providerLifecycle,
        providerUnavailableReason: () => this.providerUnavailableReason,
        sessionsDirty: () => this.sessionsDirty,
        settings: () => this.settings,
        sourceInspections: () => this.sourceInspections,
        sources: () => this.sources,
        syncOutcomes: () => this.syncOutcomes,
        syncing: () => this.syncing,
        vector: () => this.vector,
        workspaceDir: () => this.workspaceDir,
      },
      {
        buildSourceFilter: () => this.buildSourceFilter(),
        hasSemanticChunks: () => this.hasSemanticChunks(),
        resolveConfiguredIndexIdentity: () => this.resolveConfiguredIndexIdentity(),
      },
    );
    if (status.batch) {
      status.batch.submissionQuarantine = this.readBatchSubmissionQuarantineStatus();
    }
    return status;
  }

  async close(): Promise<void> {
    const existingClose = this.closePromise;
    if (existingClose) {
      await existingClose;
      return;
    }
    const closeOperation = this.withPublishedDatabase(() =>
      this.publishedDatabaseReleased ? this.retryFailedClose() : this.closeOnce(),
    );
    this.closePromise = closeOperation;
    try {
      await closeOperation;
      this.managerRegistry.deleteIfCurrent(this.cacheKey, this);
    } catch (err) {
      if (this.closePromise === closeOperation) {
        this.closePromise = null;
      }
      throw err;
    }
  }

  private async retryFailedClose(): Promise<void> {
    const errors: unknown[] = [];
    // A retained observer failure must not strand independently owned resources.
    await this.closeWatchResources().catch((error: unknown) => errors.push(error));
    const retirementErrors = await this.drainPendingProviderRetirements();
    if (this.providersPendingRetirement.size > 0) {
      errors.push(toErrorObject(retirementErrors.at(-1), "Embedding provider retirement failed"));
    }
    if (!this.publishedDatabaseReleased) {
      try {
        await this.publishedDatabase.closePublicationWorker();
        this.publishedDatabase.release();
        this.publishedDatabaseReleased = true;
      } catch (error) {
        errors.push(error);
      }
    }
    if (errors.length === 1) {
      throw errors[0];
    }
    if (errors.length > 1) {
      throw new AggregateError(errors, "Memory manager cleanup failed");
    }
  }

  private async closeOnce(): Promise<void> {
    this.closing = true;
    this.sessionSyncQueue.clear();
    this.abortEmbeddingBatches();
    await this.awaitManagerIdle();
    this.closed = true;
    const pendingProviderInit = this.providerInitPromise;
    const pendingFallbackInit = this.fallbackProviderInitPromise;
    const reportPendingWorkError = (err: unknown) => {
      log.warn(`memory close: pending manager work failed: ${formatErrorMessage(err)}`);
    };
    await pendingProviderInit?.catch(reportPendingWorkError);
    await pendingFallbackInit?.catch(reportPendingWorkError);
    // Initialization may attach sync work; observe its promise only after it settles.
    await this.syncing?.catch(reportPendingWorkError);
    await this.retryFailedClose();
  }
}
