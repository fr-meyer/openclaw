import { createDeferred } from "openclaw/plugin-sdk/concurrency-runtime";
import { expectDefined } from "openclaw/plugin-sdk/expect-runtime";
import type { EmbeddingProvider } from "./embeddings.js";
import { readMemoryDatabaseRevision } from "./manager-db-kernel.js";
import { MemoryManagerEmbeddingCacheOps } from "./manager-embedding-cache-ops.js";
import {
  resolveMemoryIndexProviderIdentities,
  type MemoryIndexProviderIdentity,
} from "./manager-reindex-state.js";

const EMBEDDING_INDEX_CONCURRENCY = 4;

export abstract class MemoryManagerProviderUseOps extends MemoryManagerEmbeddingCacheOps {
  private activeProviderUses = new Map<
    EmbeddingProvider,
    ReturnType<typeof createDeferred<void>> & { count: number }
  >();
  private syncProviderGenerationRelease: (() => void) | null = null;
  private syncProviderGenerationOwners = 0;

  protected acquireProviderUse(provider: EmbeddingProvider): () => void {
    const use = this.activeProviderUses.get(provider) ?? {
      ...createDeferred(),
      count: 0,
    };
    use.count += 1;
    this.activeProviderUses.set(provider, use);
    let released = false;
    return () => {
      if (released) {
        return;
      }
      released = true;
      use.count -= 1;
      if (use.count > 0) {
        return;
      }
      this.activeProviderUses.delete(provider);
      use.resolve();
    };
  }

  protected async withProviderUse<T>(
    provider: EmbeddingProvider,
    run: () => Promise<T>,
  ): Promise<T> {
    const release = this.acquireProviderUse(provider);
    try {
      return await run();
    } finally {
      release();
    }
  }

  protected async awaitProviderIdle(provider: EmbeddingProvider): Promise<void> {
    const use = this.activeProviderUses.get(provider);
    if (!use) {
      return;
    }
    await use.promise;
  }

  protected override beginSyncProviderGeneration(options?: { forceFtsOnly?: boolean }): void {
    if (this.syncProviderGeneration) {
      this.syncProviderGenerationOwners += 1;
      return;
    }
    const provider = options?.forceFtsOnly ? null : this.provider;
    const runtime = provider ? this.providerRuntime : undefined;
    const identities = resolveMemoryIndexProviderIdentities({
      provider,
      cacheKeyData: runtime?.cacheKeyData,
      aliases: runtime?.indexIdentityAliases,
    });
    const providerKey = expectDefined(
      identities.at(0),
      "primary memory provider identity",
    ).providerKey;
    const database = this.database;
    const generation = {
      database,
      databaseRevision: readMemoryDatabaseRevision(database.db),
      cacheWritesInvalidated: false,
      providerKey,
      identities,
    };
    this.syncProviderGeneration = provider
      ? { ...generation, kind: "semantic", provider, ...(runtime ? { runtime } : {}) }
      : { ...generation, kind: "fts-only", provider: null };
    this.syncProviderGenerationRelease = provider ? this.acquireProviderUse(provider) : null;
    this.syncProviderGenerationOwners = 1;
  }

  protected override endSyncProviderGeneration(): void {
    if (this.syncProviderGenerationOwners > 1) {
      this.syncProviderGenerationOwners -= 1;
      return;
    }
    this.syncProviderGenerationOwners = 0;
    this.syncProviderGeneration = null;
    this.syncProviderGenerationRelease?.();
    this.syncProviderGenerationRelease = null;
  }

  protected computeProviderKey(): string {
    return expectDefined(
      this.resolveProviderIndexIdentities().at(0),
      "primary memory provider identity",
    ).providerKey;
  }

  protected resolveProviderIndexIdentities(): MemoryIndexProviderIdentity[] {
    return resolveMemoryIndexProviderIdentities({
      provider: this.provider,
      cacheKeyData: this.providerRuntime?.cacheKeyData,
      aliases: this.providerRuntime?.indexIdentityAliases,
    });
  }

  protected getIndexConcurrency(): number {
    if (this.batch.enabled) {
      return this.batch.concurrency;
    }
    const configured = this.settings.remote?.nonBatchConcurrency;
    if (typeof configured === "number" && Number.isFinite(configured)) {
      return Math.max(1, Math.floor(configured));
    }
    const provider = this.syncProviderGeneration
      ? this.syncProviderGeneration.provider
      : this.provider;
    return provider?.id === "ollama" ? 1 : EMBEDDING_INDEX_CONCURRENCY;
  }
}
