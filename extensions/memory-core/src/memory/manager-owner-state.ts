import {
  createSubsystemLogger,
  type OpenClawConfig,
  type ResolvedMemorySearchConfig,
} from "openclaw/plugin-sdk/memory-core-host-engine-foundation";
import type {
  MemorySyncParams,
  MemoryWorkspaceFiles,
} from "openclaw/plugin-sdk/memory-core-host-engine-storage";
import type { withOpenClawAgentDatabaseWrite } from "openclaw/plugin-sdk/sqlite-runtime";
import { boundedMemoryAdmissionActive } from "./bounded-admission.js";
import type { MemoryCoreAcquireLocalService } from "./embedding-local-service.js";
import type { EmbeddingProvider } from "./embeddings.js";
import { markMemoryIndexingLive } from "./lifecycle.js";
import { MemoryIndexDatabase } from "./manager-database-context.js";
import {
  resolveEffectiveMemorySearchSettings,
  type MemoryEmbeddingProviderRequirement,
} from "./manager-provider-lifecycle.js";
import type { MemoryProviderLifecycleState } from "./manager-provider-state.js";
import type {
  ClosableMemoryManager,
  MemoryManagerProviderOwnerRegistry,
  MemoryManagerProviderFactory,
  MemoryIndexManagerPurpose,
} from "./manager-registry.js";
import type { MemoryIndexIdentityState } from "./manager-reindex-state.js";
import { MemorySearchOrchestration } from "./manager-search-orchestration.js";
import type { MemoryEmbeddingBatchConfig } from "./manager-sync-base.js";
import { MemoryTargetedSessionSyncQueue } from "./manager-sync-control.js";
import type { MemoryCoreRuntimeHost } from "./runtime-host.js";
const log = createSubsystemLogger("memory");
export { log as memoryManagerLog };

export type MemoryManagerStateOptions = {
  memoryFiles?: MemoryWorkspaceFiles;
  managerRegistry: MemoryManagerProviderOwnerRegistry;
  cacheKey: string;
  cfg: OpenClawConfig;
  agentId: string;
  workspaceDir: string;
  settings: ResolvedMemorySearchConfig;
  providerRequirement: MemoryEmbeddingProviderRequirement;
  purpose: MemoryIndexManagerPurpose;
  acquireLocalService?: MemoryCoreAcquireLocalService;
  runInBackgroundContext?: MemoryCoreRuntimeHost["runInBackgroundContext"];
  maintenanceSource?: MemoryManagerState;
  candidateOperationId?: string;
  databaseOptions: Parameters<typeof withOpenClawAgentDatabaseWrite>[0] & { path: string };
  publishedDatabase: MemoryIndexDatabase;
};

export abstract class MemoryManagerState extends MemorySearchOrchestration {
  protected readonly providerOwnerRegistry: MemoryManagerProviderOwnerRegistry;
  protected readonly createProvider: MemoryManagerProviderFactory = (adapter, create) =>
    this.providerOwnerRegistry.createProvider(this.managerOwner, adapter, create);
  protected releaseProvider(provider: EmbeddingProvider): void {
    this.providerOwnerRegistry.releaseProvider(this.managerOwner, provider);
  }
  protected canPublishEmbeddingProbe(): boolean {
    return this.providerOwnerRegistry.canPublishProbe(this.managerOwner);
  }
  protected getEmbeddingProbeOwners() {
    return this.providerOwnerRegistry.getProbeOwners(this.managerOwner);
  }
  protected get embeddingProbeCache() {
    return this.providerOwnerRegistry.embeddingProbeCache;
  }
  protected readonly cacheKey: string;
  protected readonly purpose: MemoryIndexManagerPurpose;
  protected override readonly acquireLocalService?: MemoryCoreAcquireLocalService;
  protected readonly backgroundRunner?: MemoryCoreRuntimeHost["runInBackgroundContext"];
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
  protected closePromise: Promise<void> | null = null;
  protected publishedDatabaseReleased = false;
  protected providerUnavailableReason?: string;
  protected override providerLifecycle: MemoryProviderLifecycleState;
  protected batch: MemoryEmbeddingBatchConfig;
  protected publishedDatabase: MemoryIndexDatabase;
  protected readonly cache: { enabled: boolean; maxEntries?: number };
  protected syncing: Promise<void> | null = null;
  protected candidateBuildClaimed = false;
  protected candidateOperationId?: string;
  protected syncingMemoryWatchGeneration = 0;
  protected readonly sessionSyncQueue = new MemoryTargetedSessionSyncQueue({
    isClosed: () => this.closing || this.closed,
    getSyncing: () => this.syncing,
    sync: (params) => this.syncAdmitted(params, { queuedSessionOwner: true }),
  });
  protected indexIdentityState: MemoryIndexIdentityState;
  protected abstract get managerOwner(): ClosableMemoryManager;

  protected abstract override syncAdmitted(
    params?: MemorySyncParams,
    options?: {
      allowEmbeddingBootstrapFallback?: boolean;
      queuedSessionOwner?: boolean;
    },
  ): Promise<void>;

  protected constructor(params: MemoryManagerStateOptions) {
    super(params.maintenanceSource?.automaticRebuildNotice);
    this.providerOwnerRegistry = params.managerRegistry;
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

  protected assertOrdinaryMemoryAdmission(): void {
    if (this.candidateOperationId || this.candidateBuildClaimed) {
      throw new Error(
        "A candidate-only manager cannot search, maintain or publish through ordinary admission",
      );
    }
  }
}
