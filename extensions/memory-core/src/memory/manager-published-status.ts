import type { DatabaseSync } from "node:sqlite";
import {
  resolveUserPath,
  type ResolvedMemorySearchConfig,
} from "openclaw/plugin-sdk/memory-core-host-engine-foundation";
import {
  MEMORY_EMBEDDING_CACHE_TABLE,
  MEMORY_INDEX_VECTOR_TABLE,
  type MemoryProviderStatus,
  type MemorySource,
} from "openclaw/plugin-sdk/memory-core-host-engine-storage";
import type { EmbeddingProvider } from "./embeddings.js";
import { getLocalEmbeddingRuntimeFacts } from "./manager-provider-runtime-facts.js";
import type { MemoryProviderLifecycleState } from "./manager-provider-state.js";
import type { MemoryIndexIdentityState } from "./manager-reindex-state.js";
import {
  collectMemoryStatusAggregate,
  collectMemoryStorageStatus,
  resolveStatusProviderInfo,
} from "./manager-status-state.js";
import type { MemoryEmbeddingBatchConfig } from "./manager-sync-base.js";
import { resolvePersistedMemoryVectorIndexState } from "./manager-vector-rebuild-state.js";

// A synchronous borrowed view only. Never stored, scheduled, or used outside published status.
type PublishedStatusView = {
  activeBackgroundSearchSyncs: { size: number };
  automaticRebuildNotice: unknown;
  batch: MemoryEmbeddingBatchConfig;
  batchFailure: { count: number; lastError?: string; lastProvider?: string };
  batchFailureLimit: number;
  buildSourceFilter: () => { sql: string; params: MemorySource[] };
  cache: { enabled: boolean; maxEntries?: number };
  database: { hasIndex: boolean };
  db: DatabaseSync;
  dirty: boolean;
  embeddingBootstrapFailure: unknown;
  fallbackFrom: string | undefined;
  fallbackReason: string | undefined;
  fts: { enabled: boolean; available: boolean; loadError?: string };
  hasSemanticChunks: () => boolean;
  indexIdentityDirty: boolean;
  indexIdentityState: MemoryIndexIdentityState;
  memoryWatcherHealth: unknown;
  provider: EmbeddingProvider | null;
  providerInitialized: boolean;
  providerLifecycle: MemoryProviderLifecycleState;
  providerUnavailableReason: string | undefined;
  resolveConfiguredIndexIdentity: () => { provider: { model?: string } } | undefined;
  sessionsDirty: boolean;
  settings: ResolvedMemorySearchConfig;
  sourceInspections: Map<MemorySource, { eligible: number | null; issues: string[] }>;
  sources: Iterable<MemorySource>;
  syncOutcomes: { lastError: MemoryProviderStatus["lastSyncError"] };
  syncing: Promise<void> | null;
  vector: {
    enabled: boolean;
    available: boolean | null;
    semanticAvailable?: boolean;
    extensionPath?: string;
    loadError?: string;
    dims?: number;
  };
  workspaceDir: string;
};

export function collectPublishedMemoryStatus(
  read: {
    [
      Key in Exclude<
        keyof PublishedStatusView,
        "buildSourceFilter" | "hasSemanticChunks" | "resolveConfiguredIndexIdentity"
      >
    ]: () => PublishedStatusView[Key];
  },
  methods: Pick<
    PublishedStatusView,
    "buildSourceFilter" | "hasSemanticChunks" | "resolveConfiguredIndexIdentity"
  >,
): MemoryProviderStatus {
  const sourceFilter = methods.buildSourceFilter();
  const statusDb = read.database().hasIndex ? read.db() : undefined;
  const aggregateState = collectMemoryStatusAggregate({
    db: statusDb,
    sources: read.sources(),
    sourceFilterSql: sourceFilter.sql,
    sourceFilterParams: sourceFilter.params,
    // Source inspection is explicit; routine query status must stay count-only.
    includeChunkBytes: read.sourceInspections().size > 0,
  });

  // Status projects the effective keyword-only search mode while degraded.
  // Sync generations still snapshot this.provider so recovery can rebuild vectors.
  const providerInfo = resolveStatusProviderInfo({
    provider: read.embeddingBootstrapFailure() ? null : read.provider(),
    providerInitialized: read.embeddingBootstrapFailure() ? true : read.providerInitialized(),
    requestedProvider: read.settings().provider,
    resolveConfiguredModel: () =>
      methods.resolveConfiguredIndexIdentity()?.provider.model || read.settings().model,
  });
  const storage =
    read.sourceInspections().size > 0
      ? collectMemoryStorageStatus(statusDb, resolveUserPath(read.settings().store.databasePath))
      : undefined;
  return {
    backend: "builtin",
    files: aggregateState.files,
    chunks: aggregateState.chunks,
    dirty:
      read.dirty() ||
      read.sessionsDirty() ||
      read.indexIdentityDirty() ||
      read.syncing() !== null ||
      read.activeBackgroundSearchSyncs().size > 0,
    lastSyncError: read.syncOutcomes().lastError,
    workspaceDir: read.workspaceDir(),
    dbPath: read.settings().store.databasePath,
    storage,
    provider: providerInfo.provider,
    model: providerInfo.model,
    requestedProvider: read.settings().provider,
    sources: Array.from(read.sources()),
    extraPaths: read.settings().extraPaths,
    sourceCounts: aggregateState.sourceCounts.map((entry) =>
      Object.assign(entry, read.sourceInspections().get(entry.source) ?? {}),
    ),
    cache: read.cache().enabled
      ? {
          enabled: true,
          entries:
            storage?.embeddingCacheEntries ??
            (
              statusDb
                ?.prepare(`SELECT COUNT(*) as c FROM ${MEMORY_EMBEDDING_CACHE_TABLE}`)
                // SAFETY: This new statement selects COUNT(*) AS c with default numeric SQLite reads.
                .get() as { c: number } | undefined
            )?.c ??
            0,
          maxEntries: read.cache().maxEntries,
        }
      : { enabled: false, maxEntries: read.cache().maxEntries },
    fts: {
      enabled: read.fts().enabled,
      available: read.fts().available,
      error: read.fts().loadError,
    },
    fallback: read.fallbackReason()
      ? { from: read.fallbackFrom() ?? "local", reason: read.fallbackReason()! }
      : undefined,
    vector: {
      enabled: read.vector().enabled,
      index: statusDb
        ? resolvePersistedMemoryVectorIndexState({
            db: read.db(),
            vectorTable: MEMORY_INDEX_VECTOR_TABLE,
            metaVectorDims: read.vector().dims,
            hasSemanticChunks: methods.hasSemanticChunks(),
          })
        : { state: "empty" },
      storeAvailable: read.vector().available ?? undefined,
      semanticAvailable: read.vector().semanticAvailable,
      available: read.vector().semanticAvailable,
      extensionPath: read.vector().extensionPath,
      loadError: read.vector().loadError,
      dims: read.vector().dims,
    },
    batch: {
      enabled: read.batch().enabled,
      failures: read.batchFailure().count,
      limit: read.batchFailureLimit(),
      wait: read.batch().wait,
      concurrency: read.batch().concurrency,
      pollIntervalMs: read.batch().pollIntervalMs,
      timeoutMs: read.batch().timeoutMs,
      lastError: read.batchFailure().lastError,
      lastProvider: read.batchFailure().lastProvider,
    },
    custom: {
      watcher: read.memoryWatcherHealth(),
      llamaCppRuntime: getLocalEmbeddingRuntimeFacts(read.provider()),
      searchMode: providerInfo.searchMode,
      providerState: read.providerLifecycle(),
      providerUnavailableReason: read.providerUnavailableReason(),
      indexIdentity: read.indexIdentityState(),
      automaticRebuildNotice: read.automaticRebuildNotice(),
    },
  };
}
