import { observeNativeSources, type SourceObservation } from "./manager-source-observation.js";
import { parseCandidateMetadata, snapshotCandidateReloadRequest } from "./manager-candidate-schema.js";
import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { formatErrorMessage, toErrorObject } from "openclaw/plugin-sdk/error-runtime";
import {
  createSubsystemLogger,
  resolveAgentWorkspaceDir,
  resolveMemorySearchConfig,
  resolveUserPath,
  type OpenClawConfig,
  type ResolvedMemorySearchConfig,
} from "openclaw/plugin-sdk/memory-core-host-engine-foundation";
import type {
  MemoryProviderStatus,
  MemorySearchManager,
  MemorySyncParams,
  MemoryWorkspaceFiles,
} from "openclaw/plugin-sdk/memory-core-host-engine-storage";
import { normalizeAgentId } from "openclaw/plugin-sdk/routing";
import type { withOpenClawAgentDatabaseWrite } from "openclaw/plugin-sdk/sqlite-runtime";
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
import type { EmbeddingProvider, EmbeddingProviderResult } from "./embeddings.js";
import { getMemoryManagerLifecycle, markMemoryIndexingLive } from "./lifecycle.js";
import {
  MemoryCandidateBuildError,
  type MemoryCandidateManifest,
  type MemoryCandidateRequest,
} from "./manager-candidate.js";
import { readMemoryDatabaseRevision } from "./manager-db-kernel.js";
import { readMemoryIndexMetadata } from "./manager-retrieval-read.js";
import { readMemoryShadowIdentity } from "./manager-shadow-task.js";
import { MemoryIndexDatabase } from "./manager-database-context.js";
import { isMemoryEmbeddingOperationError } from "./manager-embedding-errors.js";
import {
  resolveEffectiveMemorySearchSettings,
  resolveMemoryEmbeddingProviderRequirement,
  type MemoryEmbeddingProviderRequirement,
} from "./manager-provider-lifecycle.js";
import type { MemoryProviderLifecycleState } from "./manager-provider-state.js";
import { collectPublishedMemoryStatus } from "./manager-published-status.js";
import { getMemoryIndexManagerRegistry } from "./manager-registry-store.js";
import {
  MemoryManagerRegistry,
  type MemoryManagerProviderFactory,
  normalizeMemoryIndexManagerPurpose,
  resolveMemoryIndexManagerCacheKey,
  type MemoryIndexManagerPurpose,
  type MemoryManagerAdmission,
} from "./manager-registry.js";
import { waitForMemoryReindexLock } from "./manager-reindex-lock.js";
import {
  resolveMemoryIndexProviderIdentities,
  type MemoryIndexIdentityState,
} from "./manager-reindex-state.js";
import { runMemorySearchMaintenance } from "./manager-search-maintenance.js";
import { MemorySearchOrchestration } from "./manager-search-orchestration.js";
import type { MemoryEmbeddingBatchConfig } from "./manager-sync-base.js";
import {
  MemoryTargetedSessionSyncQueue,
  hasTargetedSessionSyncParams,
} from "./manager-sync-control.js";
import type { MemoryCoreRuntimeHost } from "./runtime-host.js";
export { getMemoryIndexManagerRegistry };
const log = createSubsystemLogger("memory");
const candidateStoreAdmission = Symbol("memory-candidate-store");

export class MemoryIndexManager extends MemorySearchOrchestration implements MemorySearchManager {
  private readonly managerRegistry: MemoryManagerRegistry<MemoryIndexManager>;
  protected readonly createProvider: MemoryManagerProviderFactory = (adapter, create) =>
    this.managerRegistry.createProvider(this, adapter, create);
  protected releaseProvider(provider: EmbeddingProvider): void {
    this.managerRegistry.releaseProvider(this, provider);
  }
  protected canPublishEmbeddingProbe(): boolean {
    return this.managerRegistry.canPublishProbe(this);
  }
  protected getEmbeddingProbeOwners() {
    return this.managerRegistry.getProbeOwners(this);
  }
  protected get embeddingProbeCache() {
    return this.managerRegistry.embeddingProbeCache;
  }
  protected readonly cacheKey: string;
  protected readonly purpose: MemoryIndexManagerPurpose;
  protected override readonly acquireLocalService?: MemoryCoreAcquireLocalService;
  private readonly backgroundRunner?: MemoryCoreRuntimeHost["runInBackgroundContext"];
  protected readonly runInBackgroundContext = <T>(run: () => T): T => {
    if (!this.backgroundRunner) {
      throw new Error("Memory background work requires a plugin lifecycle owner");
    }
    return this.backgroundRunner(run);
  };
  protected override readonly memoryFiles?: MemoryWorkspaceFiles;
  protected readonly cfg: OpenClawConfig;
  protected readonly agentId: string;
  protected readonly workspaceDir: string;
  protected readonly settings: ResolvedMemorySearchConfig;
  protected readonly providerRequirement: MemoryEmbeddingProviderRequirement;
  private closePromise: Promise<void> | null = null;
  private publishedDatabaseReleased = false;
  protected providerUnavailableReason?: string;
  protected override providerLifecycle: MemoryProviderLifecycleState;
  protected batch: MemoryEmbeddingBatchConfig;
  protected publishedDatabase: MemoryIndexDatabase;
  protected readonly cache: { enabled: boolean; maxEntries?: number };
  private syncing: Promise<void> | null = null;
  private candidateBuildClaimed = false;
  private candidateOperationId?: string;
  private syncingMemoryWatchGeneration = 0;
  private readonly sessionSyncQueue = new MemoryTargetedSessionSyncQueue({
    isClosed: () => this.closing || this.closed,
    getSyncing: () => this.syncing,
    sync: (params) => this.syncAdmitted(params, { queuedSessionOwner: true }),
  });
  protected indexIdentityState: MemoryIndexIdentityState;
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
    candidateStore?: { path: string; operationId: string; admission: typeof candidateStoreAdmission };
  }): Promise<MemoryIndexManager | null> {
    if (params.candidateStore && (
      params.candidateStore.admission !== candidateStoreAdmission ||
      params.purpose !== "cli" || params.maintenanceSource
    )) {
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
          const settings = configuredSettings && params.candidateStore
            ? { ...configuredSettings, store: { ...configuredSettings.store,
                databasePath: params.candidateStore.path } }
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
  private constructor(params: {
    memoryFiles?: MemoryWorkspaceFiles;
    managerRegistry: MemoryManagerRegistry<MemoryIndexManager>;
    cacheKey: string;
    cfg: OpenClawConfig;
    agentId: string;
    workspaceDir: string;
    settings: ResolvedMemorySearchConfig;
    providerRequirement: MemoryEmbeddingProviderRequirement;
    purpose: MemoryIndexManagerPurpose;
    acquireLocalService?: MemoryCoreAcquireLocalService;
    runInBackgroundContext?: MemoryCoreRuntimeHost["runInBackgroundContext"];
    maintenanceSource?: MemoryIndexManager;
    candidateOperationId?: string;
    databaseOptions: Parameters<typeof withOpenClawAgentDatabaseWrite>[0] & { path: string };
    publishedDatabase: MemoryIndexDatabase;
  }) {
    super(params.maintenanceSource?.automaticRebuildNotice);
    this.managerRegistry = params.managerRegistry;
    const effectiveSettings = resolveEffectiveMemorySearchSettings(params.settings);
    const dbPath = params.databaseOptions.path;
    this.cacheKey = params.cacheKey;
    this.acquireLocalService = params.acquireLocalService;
    this.backgroundRunner = params.runInBackgroundContext;
    this.purpose = params.purpose;
    // Set before construction can attach watchers or expose the manager.
    this.candidateOperationId = params.candidateOperationId;
    this.cfg = params.cfg;
    this.agentId = params.agentId;
    this.workspaceDir = params.workspaceDir;
    this.memoryFiles = params.memoryFiles;
    this.settings = {
      ...effectiveSettings,
      store: { ...effectiveSettings.store, databasePath: dbPath },
    };
    this.providerRequirement = params.providerRequirement;
    this.providerLifecycle = { mode: "pending", requestedProvider: this.settings.provider };
    for (const memorySource of effectiveSettings.sources) {
      this.sources.add(memorySource);
    }
    this.publishedDatabase = params.publishedDatabase;
    try {
      this.providerKey = this.computeProviderKey();
      this.cache = {
        enabled: effectiveSettings.cache.enabled,
        maxEntries: effectiveSettings.cache.maxEntries,
      };
      this.vector.enabled = effectiveSettings.store.vector.enabled;
      this.vector.extensionPath = effectiveSettings.store.vector.extensionPath;
      const meta = this.readMeta();
      if (meta?.vectorDims) {
        this.vector.dims = meta.vectorDims;
      }
      this.indexIdentityState = this.resolveCurrentIndexIdentityState({
        meta,
        providerKeyKnown: false,
      });
      this.indexIdentityDirty =
        this.indexIdentityState.status === "mismatched" ||
        (this.indexIdentityState.status === "missing" && this.sources.has("memory"));
      const transient = this.purpose !== "default";
      const invalidatedSources = new Set(
        (this.database.hasIndex
          ? (this.db
              .prepare("SELECT DISTINCT source FROM memory_index_sources WHERE hash = ''")
              .all() as Array<{ source?: unknown }>)
          : []
        ).flatMap((row) =>
          row.source === "memory" || row.source === "sessions" ? [row.source] : [],
        ),
      );
      this.memorySourceProvenanceRepairPending =
        this.sources.has("memory") && invalidatedSources.has("memory");
      this.dirty =
        (this.sources.has("memory") && (!transient || !meta)) ||
        this.memorySourceProvenanceRepairPending;
      if (this.sources.has("sessions") && invalidatedSources.has("sessions")) {
        // Migration cannot map a durable session source path back to one live
        // transcript file. Carry a full-session retry so unchanged and deleted
        // transcripts both converge on the next startup/search sync.
        this.sessionsDirty = true;
        this.sessionsFullRetryDirty = true;
      }
      this.batch = this.resolveBatchConfig();
      if (!transient && !boundedMemoryAdmissionActive(this.agentId)) {
        markMemoryIndexingLive();
        this.runInBackgroundContext(() => {
          this.ensureWatcher();
          this.ensureSessionListener();
          this.ensureIntervalSync();
          void this.runInBackgroundContext(() => this.ensureSessionStartupCatchup()).catch(
            (err: unknown) => {
              log.warn("memory session startup catch-up failed: " + String(err));
            },
          );
        });
      }
    } catch (err) {
      this.publishedDatabase.release();
      throw err;
    }
  }

  /** Allocate a named isolated export using the native manager and DB owners.
   * Existing export custody blocks restart before any provider initialization.
   * The config is candidate-only input, never installed as serving configuration.
   */
  async createCandidateManager(params: {
    cfg: OpenClawConfig;
    operationId: string;
  }): Promise<MemoryIndexManager> {
    if (this.closed || this.closing || this.candidateOperationId ||
      !/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/.test(params.operationId)) {
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

  /** Internal build-only boundary on a dedicated, isolated CLI manager.
   * The serving manager is observed for identity, never reconfigured.
   * No activation, resubmission or retained-artifact cleanup is exposed here.
   */
  async buildCandidate(
    serving: MemoryIndexManager,
    request: MemoryCandidateRequest,
  ): Promise<MemoryCandidateManifest> {
    if (
      this === serving || this.purpose !== "cli" || this.closed || this.closing ||
      serving.closed || serving.closing || this.syncing || this.candidateBuildClaimed ||
      this.candidateOperationId !== request.operationId ||
      this.agentId !== serving.agentId || this.workspaceDir !== serving.workspaceDir ||
      this.settings.fallback !== "none"
    ) {
      throw new Error("Memory candidate requires an idle isolated CLI manager with no fallback");
    }
    if (
      !/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/.test(request.operationId) ||
      !request.expected.provider || !request.expected.model ||
      !Number.isSafeInteger(request.expected.dimensions) || request.expected.dimensions <= 0
    ) {
      throw new Error("Invalid memory candidate operation or provider identity");
    }
    // Claim before any await. Ordinary sync can never auto-publish this manager.
    this.candidateBuildClaimed = true;
    const expected = { ...request.expected };
    const operationId = request.operationId;
    const signal = request.signal;
    const controllerRequest = request.controller ? {
      accountId: request.controller.accountId, route: request.controller.route,
      sourceRevision: request.controller.sourceRevision,
    } : undefined;
    const run = this.withManagerOperation(async () => {
      signal?.throwIfAborted();
      const ownPath = await fs.realpath(resolveUserPath(this.settings.store.databasePath));
      const servingPath = await fs.realpath(resolveUserPath(serving.settings.store.databasePath));
      const ownIdentity = readMemoryShadowIdentity(ownPath);
      const servingIdentity = readMemoryShadowIdentity(servingPath);
      if (ownPath === servingPath || (
        ownIdentity.device === servingIdentity.device && ownIdentity.inode === servingIdentity.inode
      )) {
        throw new Error("Memory candidate store aliases the serving database");
      }
      if (this.closed || this.closing || serving.closed || serving.closing) {
        throw new Error("Memory candidate owner retired during admission");
      }
      const sourceFence = serving.candidateSourceFence();
      const assertSourceCurrent = () => {
        if (serving.candidateSourceFence() !== sourceFence) {
          throw new Error("Candidate serving source index changed during build");
        }
      };
      const directory = ownPath + ".memory-candidate-" + operationId;
      const databasePath = path.join(directory, "index.sqlite");
      // Exclusive deterministic export custody. Existing work after restart
      // must be reconciled, never silently replaced or purchased again.
      await fs.mkdir(directory, { mode: 0o700 });
      let sourceWorkStarted = false;
      let complete = false;
      let retainedManifest: MemoryCandidateManifest | undefined;
      try {
        signal?.throwIfAborted();
        await this.publishedDatabase.withPublicationGeneration(async () => {
          const lock = await waitForMemoryReindexLock(ownPath, { waitForActive: true });
          const admissionFailures: unknown[] = [];
          try {
            await this.ensureProviderInitialized();
            signal?.throwIfAborted();
            if (this.provider?.id !== expected.provider || this.provider.model !== expected.model) {
              throw new Error("Memory candidate configured provider differs from approved identity");
            }
            const provider = this.provider;
            const runtime = this.providerRuntime;
            const build = async (controller?: import("openclaw/plugin-sdk/embedding-provider-runtime-contract").EmbeddingCandidateControllerIdentity) => {
            assertSourceCurrent();
            if (this.settings.outputDimensionality !== expected.dimensions) {
              throw new Error("Memory candidate configured dimensions differ from approved identity");
            }
            await this.ensureVectorReady();
            signal?.throwIfAborted();
            await this.publishedDatabase.closePublicationWorker();
            this.beginSyncProviderGeneration();
            const buildFailures: unknown[] = [];
            try {
              const manifest = await this.runInPlaceReindex(undefined, {
                databasePath,
                stamp: {
                  version: 1, sourceFence, controller, cacheFileIdentity: readMemoryShadowIdentity(ownPath),
                  operationId, phase: "building",
                  servingDatabasePath: servingPath,
                  servingFileIdentity: servingIdentity,
                  cacheDatabasePath: ownPath,
                },
                expected, signal,
                onSourceWork: () => { sourceWorkStarted = true; },
              });
              if (!manifest) {
                throw new Error("Memory candidate build returned no retained artifact");
              }
              assertSourceCurrent();
              retainedManifest = manifest;
              complete = true;
              signal?.throwIfAborted();
            } catch (error) { buildFailures.push(error); }
            finally {
              try { this.endSyncProviderGeneration(); } catch (error) { buildFailures.push(error); }
              try { await this.publishedDatabase.closePublicationWorker(); }
              catch (error) { buildFailures.push(error); }
            }
            if (buildFailures.length === 1) { throw buildFailures[0]; }
            if (buildFailures.length > 1) { throw new AggregateError(buildFailures,
              "Candidate source/worker cleanup failed", { cause: buildFailures[0] }); }
            };
            if (provider.id === "openai") {
              if (!controllerRequest || controllerRequest.sourceRevision !== sourceFence ||
                !runtime || !this.settings.remote?.batch?.enabled) {
                throw new Error("Persistent OpenAI candidate requires explicit durable Batch journal binding");
              }
              await this.managerRegistry.withCandidateBatch(this, provider, runtime, {
                agentId: this.agentId,
                journal: { path: path.join(path.dirname(ownPath), "batch.sqlite"),
                  migrationId: operationId, accountId: controllerRequest.accountId,
                  route: controllerRequest.route, sourceRevision: controllerRequest.sourceRevision },
                expected: { model: expected.model, dimensions: expected.dimensions },
              }, async (batchEmbed, identity) => {
                // Only the current registered owner can install this runtime.
                // Direct document/query embedding is forbidden, not a fallback.
                const refuse = async () => { throw new Error("Candidate direct embedding fallback forbidden"); };
                this.provider = { ...provider, embedQuery: refuse, embedBatch: refuse };
                this.providerRuntime = { ...runtime, batchEmbed, batchEmbedPartial: undefined,
                  batchFailureMode: "fail-closed", sourceWideBatchEmbed: true };
                this.batch = this.resolveBatchConfig();
                try { await build(structuredClone(identity)); }
                finally { this.provider = provider; this.providerRuntime = runtime; this.batch = this.resolveBatchConfig(); }
              });
            } else {
              if (controllerRequest) { throw new Error("Candidate controller requires the registered OpenAI provider"); }
              await build();
            }
          } catch (error) { admissionFailures.push(error); }
          finally {
            try { await lock.release(); } catch (error) { admissionFailures.push(error); }
          }
          if (admissionFailures.length === 1) { throw admissionFailures[0]; }
          if (admissionFailures.length > 1) { throw new AggregateError(admissionFailures,
            "Candidate source/admission cleanup failed", { cause: admissionFailures[0] }); }
        });
        // withPublicationGeneration deliberately returns void. Return the
        // retained result only after its cleanup and native admission release.
        if (!retainedManifest) {
          throw new Error("Memory candidate publication generation returned no retained manifest");
        }
        return retainedManifest;
      } catch (error) {
        if (sourceWorkStarted) {
          throw new MemoryCandidateBuildError(
            databasePath, complete ? "retained-complete" : "retained-unreconciled", error,
          );
        }
        // Only pre-source failures are disposable. Do not recursively delete a
        // directory if SQLite cleanup failed and its owned artifact remains.
        try { await fs.rmdir(directory); } catch { /* Preserve cleanup uncertainty. */ }
        throw error;
      }
    });
    this.syncing = run.then(() => undefined, () => undefined);
    try {
      return await run;
    } finally {
      this.syncing = null;
    }
  }

  /** Index-generation fence, not proof that an external corpus is authorized. */
  candidateSourceFence(): string {
    this.assertOrdinaryMemoryAdmission();
    if (this.closed || this.closing || this.syncing || this.dirty || this.sessionsDirty) {
      throw new Error("Serving index must be settled before candidate source admission");
    }
    return createHash("sha256").update(JSON.stringify({
      path: resolveUserPath(this.settings.store.databasePath),
      file: readMemoryShadowIdentity(resolveUserPath(this.settings.store.databasePath)),
      revision: readMemoryDatabaseRevision(this.db),
    })).digest("hex");
  }

  /** Native observation only. Never a promotion fence or persisted candidate authority. */
  async observeCandidateSources(): Promise<SourceObservation> {
    this.assertOrdinaryMemoryAdmission();
    const snapshot = { workspaceDir: this.workspaceDir, sources: [...this.sources],
      settings: structuredClone({ extraPaths: this.settings.extraPaths, multimodal: this.settings.multimodal }),
      files: this.memoryFiles, indexFence: this.candidateSourceFence() };
    return await this.withManagerOperation(async () => {
      const result = await observeNativeSources({ ...snapshot, sessions: () => this.listSessionCorpusEntries(true) });
      if (this.candidateSourceFence() !== snapshot.indexFence ||
        JSON.stringify([...this.sources]) !== JSON.stringify(snapshot.sources) ||
        JSON.stringify({ extraPaths: this.settings.extraPaths, multimodal: this.settings.multimodal }) !== JSON.stringify(snapshot.settings)) {
        return { ...result, status: "unverified", digest: null, issues: [...result.issues, "index-fence-changed"] };
      }
      return result;
    });
  }

  /** Read only; reload never resumes work, submits a provider job or activates. */
  async loadCandidateManifest(request: MemoryCandidateRequest): Promise<MemoryCandidateManifest> {
    this.assertOrdinaryMemoryAdmission();
    const snapshot = snapshotCandidateReloadRequest(request);
    return await this.withManagerOperation(async () => {
      const sourceFence = this.candidateSourceFence();
      const servingPath = await fs.realpath(resolveUserPath(this.settings.store.databasePath));
      const outer = servingPath + ".memory-candidate-" + snapshot.operationId;
      const cachePath = path.join(outer, "store.sqlite");
      const databasePath = path.join(cachePath + ".memory-candidate-" + snapshot.operationId, "index.sqlite");
      for (const directory of [outer, path.dirname(databasePath)]) {
        const info = await fs.lstat(directory);
        if (!info.isDirectory() || info.isSymbolicLink() || (info.mode & 0o077) !== 0 ||
          (typeof process.getuid === "function" && info.uid !== process.getuid()) ||
          await fs.realpath(directory) !== directory) { throw new Error("Invalid private candidate reload custody"); }
      }
      const inspectLeaf = async (filename: string) => {
        const leaf = await fs.lstat(filename, { bigint: true });
        if (!leaf.isFile() || leaf.isSymbolicLink() || (leaf.mode & 0o077n) !== 0n ||
          (typeof process.getuid === "function" && leaf.uid !== BigInt(process.getuid())) ||
          await fs.realpath(filename) !== filename) {
          throw new Error("Candidate/cache leaf custody is unsafe");
        }
        return { device: String(leaf.dev), inode: String(leaf.ino) };
      };
      const fileIdentity = await inspectLeaf(databasePath);
      const cacheIdentity = await inspectLeaf(cachePath);
      const database = await MemoryIndexDatabase.openPublished({
        agentId: this.agentId,
        writeOptions: MemoryIndexDatabase.captureWriteOptions(this.agentId, databasePath),
        readOnly: true, allowExtension: false,
        schema: { cacheEnabled: true, ftsEnabled: false, ftsTokenizer: this.settings.store.fts.tokenizer },
      });
      try {
        const meta = parseCandidateMetadata(readMemoryIndexMetadata(database.db).serialized);
        const stamp = meta?.candidate;
        if (!meta || stamp?.version !== 1 || stamp.phase !== "complete" ||
          stamp.operationId !== snapshot.operationId || stamp.sourceFence !== sourceFence ||
          stamp.servingDatabasePath !== servingPath || stamp.cacheDatabasePath !== cachePath ||
          JSON.stringify(stamp.candidateFileIdentity) !== JSON.stringify(fileIdentity) ||
          JSON.stringify(stamp.cacheFileIdentity) !== JSON.stringify(cacheIdentity) ||
          meta.provider !== snapshot.expected.provider || meta.model !== snapshot.expected.model ||
          meta.vectorDims !== snapshot.expected.dimensions || !meta.providerKey || !meta.scopeHash) {
          throw new Error("Candidate persistent manifest identity/source fence mismatch");
        }
        if (snapshot.expected.provider === "openai") {
          const controller = stamp.controller;
          if (!snapshot.controller || !controller || controller.agentId !== this.agentId ||
            controller.journal.path !== path.join(outer, "batch.sqlite") ||
            controller.journal.migrationId !== snapshot.operationId ||
            controller.journal.sourceRevision !== sourceFence ||
            controller.journal.accountId !== snapshot.controller.accountId ||
            controller.journal.route !== snapshot.controller.route ||
            snapshot.controller.sourceRevision !== sourceFence ||
            controller.expected.model !== meta.model || controller.expected.dimensions !== meta.vectorDims ||
            controller.identity !== createHash("sha256").update(JSON.stringify({
              migrationId: controller.journal.migrationId, sourceRevision: controller.journal.sourceRevision,
              accountId: controller.journal.accountId, route: controller.journal.route,
              agentId: controller.agentId, model: controller.expected.model, dimensions: controller.expected.dimensions,
            })).digest("hex")) {
            throw new Error("Candidate controller reload linkage mismatch");
          }
        } else if (stamp.controller || snapshot.controller) { throw new Error("Unexpected candidate controller linkage"); }
        if (sourceFence !== this.candidateSourceFence()) { throw new Error("Candidate source changed during reload"); }
        if (JSON.stringify(await inspectLeaf(databasePath)) !== JSON.stringify(fileIdentity) ||
          JSON.stringify(await inspectLeaf(cachePath)) !== JSON.stringify(cacheIdentity)) {
          throw new Error("Candidate/cache leaf changed during inspection");
        }
        // Exact native readonly owner returns db/path/close, NOT handle inode.
        // No pathname check can invent proof of the opened SQLite file descriptor.
        return { databasePath, fileIdentity, meta, activation: "manual-only",
          inspection: { status: "unverified-inspection-only", openedIdentity: "unavailable",
            cacheIdentity, cacheStatus: "path-identity-only" } };
      } finally { database.release(); }
    });
  }

  private assertOrdinaryMemoryAdmission(): void {
    if (this.candidateOperationId || this.candidateBuildClaimed) {
      throw new Error("A candidate-only manager cannot search, maintain or publish through ordinary admission");
    }
  }

  override async search(
    ...args: Parameters<MemorySearchOrchestration["search"]>
  ): ReturnType<MemorySearchOrchestration["search"]> {
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
