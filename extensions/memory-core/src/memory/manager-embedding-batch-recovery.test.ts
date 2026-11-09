import path from "node:path";
import { createDeferred } from "openclaw/plugin-sdk/concurrency-runtime";
import { ensureMemoryIndexSchema } from "openclaw/plugin-sdk/memory-core-host-engine-storage";
import { useAutoCleanupTempDirTracker } from "openclaw/plugin-sdk/test-env";
import { afterEach, describe, expect, it, vi } from "vitest";
import { selectedMemoryLineageIdentity } from "../memory-entry-origins-task.js";
import { markMemoryForgotten } from "../memory-forget-kernel.js";
import { ensureMemorySessionTombstones } from "../memory-session-tombstones.js";
import { MemoryIndexDatabase } from "./manager-database-context.js";
import { readMemoryDatabaseRevision } from "./manager-db-kernel.js";
import { MemoryManagerEmbeddingOps } from "./manager-embedding-ops.js";

const tempDirs = useAutoCleanupTempDirTracker((cleanup) => afterEach(cleanup));

function harness() {
  const candidates = [0, 1, 2].map((index) => ({ chunk: { text: `synthetic-${index}` } }));
  const batchEmbed = vi.fn().mockResolvedValue({
    kind: "partial",
    embeddings: [[1, 2], null, null],
    reason: "synthetic partial job",
  });
  const persist = vi.fn(async () => {});
  const sync = vi.fn(async () => [
    [3, 4],
    [5, 6],
  ]);
  const assertCurrent = vi.fn();
  const generation = {
    kind: "semantic",
    cacheWritesInvalidated: false,
    database: { read: vi.fn(async () => 1) },
    databaseRevision: 1,
    provider: { id: "openai", model: "text-embedding-3-small", dimensions: 2 },
    runtime: { batchFailureMode: "fail-closed", batchEmbedPartial: batchEmbed },
  };
  const manager = Object.assign(Object.create(MemoryManagerEmbeddingOps.prototype), {
    agentId: "main",
    batch: {
      enabled: true,
      wait: true,
      concurrency: 2,
      pollIntervalMs: 2000,
      timeoutMs: 90_000_000,
    },
    batchFailure: { count: 0 },
    collectCachedEmbeddings: async () => ({
      embeddings: [[], [], []],
      missing: [0, 1, 2],
      missingCandidates: candidates,
    }),
    assertEmbeddingCacheGenerationCurrent: assertCurrent,
    persistGeneratedEmbeddings: persist,
    embedChunksInBatches: sync,
  }) as {
    embedChunksWithBatch: (
      items: unknown[],
      source: string,
      generation: unknown,
    ) => Promise<number[][]>;
    withGeneratedEmbeddingCacheWrite: (generation: unknown, mutation: unknown) => Promise<void>;
    embedBatchWithRetry: (
      inputs: string[],
      generation: unknown,
      candidates: unknown[],
      progress: (items: unknown[], vectors: number[][]) => void,
    ) => Promise<number[][]>;
    resolveBatchConfig: () => { enabled: boolean };
    shouldDeferSourceWideBatch: () => boolean;
  };
  return {
    manager,
    candidates,
    batchEmbed,
    persist,
    sync,
    assertCurrent,
    generation,
    run: () => manager.embedChunksWithBatch(candidates, "memory", generation),
  };
}

describe("host-owned selective Batch recovery", () => {
  it("admits a runtime exposing only the optional partial-result capability", () => {
    const h = harness();
    Object.assign(h.generation.runtime, { sourceWideBatchEmbed: true });
    Object.assign(h.manager, {
      provider: h.generation.provider,
      providerRuntime: h.generation.runtime,
      settings: { remote: { batch: { enabled: true } } },
    });
    expect(h.manager.resolveBatchConfig().enabled).toBe(true);
    expect(h.manager.shouldDeferSourceWideBatch()).toBe(true);
  });

  it("blocks fallback after the real cache owner invalidates a revision-conflicted generation", async () => {
    const h = harness();
    const mutate = vi.fn(
      async (
        _mutation: unknown,
        assertCurrent: () => void,
        revision: () => number | undefined,
        invalidate: () => void,
      ) => {
        assertCurrent();
        expect(revision()).toBe(1);
        invalidate();
        return false;
      },
    );
    const database = { closed: false, db: { isOpen: true }, mutateEmbeddingCache: mutate };
    const generation = Object.assign(h.generation, { database, databaseRevision: 1 });
    Reflect.deleteProperty(h.manager, "assertEmbeddingCacheGenerationCurrent");
    Object.assign(h.manager, {
      closed: false,
      syncProviderGeneration: generation,
      publishedDatabase: database,
      withPublishedDatabase: async (run: () => Promise<void>) => await run(),
    });
    Object.defineProperty(h.manager, "database", { value: database });
    h.persist.mockImplementationOnce(
      async () =>
        await h.manager.withGeneratedEmbeddingCacheWrite(generation, {
          kind: "upsert",
          header: { agentId: "main", provider: generation.provider, providerKey: "synthetic" },
          entries: [{ hash: "synthetic", embedding: [1, 2] }],
        }),
    );
    await expect(h.run()).rejects.toMatchObject({ partialEmbeddings: [[1, 2], null, null] });
    expect(generation.cacheWritesInvalidated).toBe(true);
    expect(mutate).toHaveBeenCalledOnce();
    expect(h.sync).not.toHaveBeenCalled();
  });

  it("makes zero sync requests after forget with no partial vectors to trigger cache CAS", async () => {
    const h = harness();
    const database = MemoryIndexDatabase.openShadow(
      path.join(tempDirs.make("batch-recovery-revocation-"), "index.sqlite"),
      false,
    );
    try {
      ensureMemoryIndexSchema({ db: database.db, cacheEnabled: true, ftsEnabled: false });
      ensureMemorySessionTombstones(database.db);
      const revision = readMemoryDatabaseRevision(database.db);
      const generation = Object.assign(h.generation, { database, databaseRevision: revision });
      const embed = vi.fn(async () => [[3, 4]]);
      Object.assign(generation.provider, { embedBatch: embed });
      Reflect.deleteProperty(h.manager, "assertEmbeddingCacheGenerationCurrent");
      Object.assign(h.manager, {
        closed: false,
        syncProviderGeneration: generation,
        publishedDatabase: database,
        withProviderUse: async (_provider: unknown, run: () => Promise<unknown>) => await run(),
        resolveEmbeddingTimeout: () => 1000,
        markLocalEmbeddingProviderDegraded: () => {},
      });
      h.batchEmbed.mockImplementationOnce(async () => {
        expect(
          markMemoryForgotten(database.db, {
            agentId: "main",
            sessionIds: ["synthetic-session"],
            entryKeys: [],
            identity: selectedMemoryLineageIdentity([], new Set(["synthetic-session"]), new Set()),
          }),
        ).toEqual({ current: true });
        return { kind: "partial", embeddings: [null, null, null], reason: "no Batch output" };
      });
      h.sync.mockImplementationOnce(
        async (...args: unknown[]) =>
          await h.manager.embedBatchWithRetry(
            ["synthetic"],
            generation,
            [h.candidates[0]],
            args[3] as (items: unknown[], vectors: number[][]) => void,
          ),
      );
      const error = await h.run().catch((value: unknown) => value);
      expect(embed).not.toHaveBeenCalled();
      expect(error).toMatchObject({ message: expect.stringMatching(/generation invalidated/) });
      expect(generation.cacheWritesInvalidated).toBe(true);
      expect(h.persist).not.toHaveBeenCalled();
    } finally {
      await database.closeShadow();
    }
  });

  it("fences a later real synchronous retry after generation invalidation", async () => {
    const h = harness();
    const database = { closed: false, db: { isOpen: true }, read: vi.fn(async () => 1) };
    const generation = Object.assign(h.generation, { database });
    const embed = vi.fn(async () => {
      generation.cacheWritesInvalidated = true;
      throw new Error("synthetic network error");
    });
    Object.assign(generation.provider, { embedBatch: embed });
    Reflect.deleteProperty(h.manager, "assertEmbeddingCacheGenerationCurrent");
    Object.assign(h.manager, {
      closed: false,
      syncProviderGeneration: generation,
      publishedDatabase: database,
      withProviderUse: async (_provider: unknown, run: () => Promise<unknown>) => await run(),
      resolveEmbeddingTimeout: () => 1000,
      waitForEmbeddingRetry: async () => {},
      markLocalEmbeddingProviderDegraded: () => {},
    });
    await expect(
      h.manager.embedBatchWithRetry(["synthetic"], generation, [h.candidates[1]], () => {}),
    ).rejects.toThrow(/generation invalidated/);
    expect(embed).toHaveBeenCalledOnce();
    expect(database.read).toHaveBeenCalledOnce();
  });

  it("does not enter the provider when authorization settles after the synchronous watchdog", async () => {
    vi.useFakeTimers();
    try {
      const h = harness();
      const authorization = createDeferred<number>();
      const database = {
        closed: false,
        db: { isOpen: true },
        read: vi.fn(async () => await authorization.promise),
      };
      const generation = Object.assign(h.generation, { database });
      const embed = vi.fn(async () => [[3, 4]]);
      Object.assign(generation.provider, { embedBatch: embed });
      Reflect.deleteProperty(h.manager, "assertEmbeddingCacheGenerationCurrent");
      Object.assign(h.manager, {
        closed: false,
        syncProviderGeneration: generation,
        publishedDatabase: database,
        withProviderUse: async (_provider: unknown, run: () => Promise<unknown>) => await run(),
        resolveEmbeddingTimeout: () => 1000,
        waitForEmbeddingRetry: async () => {
          throw new Error("synthetic stop after watchdog");
        },
        markLocalEmbeddingProviderDegraded: () => {},
      });
      const result = h.manager
        .embedBatchWithRetry(["synthetic"], generation, [h.candidates[0]], () => {})
        .catch((error: unknown) => error);
      await vi.advanceTimersByTimeAsync(1000);
      expect(await result).toBeInstanceOf(Error);
      authorization.resolve(1);
      await vi.advanceTimersByTimeAsync(0);
      expect(embed).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });

  it("retains a validated real synchronous response before its cache write fails", async () => {
    const h = harness();
    Object.assign(h.generation.provider, {
      embedBatch: vi.fn(async () => [
        [3, 4],
        [5, 6],
      ]),
    });
    Object.assign(h.manager, {
      withProviderUse: async (_provider: unknown, run: () => Promise<unknown>) => await run(),
      resolveEmbeddingTimeout: () => 1000,
      markLocalEmbeddingProviderDegraded: () => {},
    });
    h.persist
      .mockResolvedValueOnce(undefined)
      .mockRejectedValueOnce(new Error("synthetic cache write failure"));
    h.sync.mockImplementationOnce(
      async (...args: unknown[]) =>
        await h.manager.embedBatchWithRetry(
          ["one", "two"],
          h.generation,
          h.candidates.slice(1),
          args[3] as (items: unknown[], vectors: number[][]) => void,
        ),
    );
    await expect(h.run()).rejects.toMatchObject({
      partialEmbeddings: [
        [1, 2],
        [3, 4],
        [5, 6],
      ],
    });
    expect(h.persist).toHaveBeenCalledTimes(2);
    expect(h.generation.cacheWritesInvalidated).toBe(true);
  });
  it("does not invoke synchronous recovery when every partial position is valid", async () => {
    const h = harness();
    h.batchEmbed.mockResolvedValueOnce({
      kind: "partial",
      embeddings: [
        [1, 2],
        [3, 4],
        [5, 6],
      ],
      reason: "terminal job with complete valid output",
    });
    await expect(h.run()).resolves.toEqual([
      [1, 2],
      [3, 4],
      [5, 6],
    ]);
    expect(h.sync).not.toHaveBeenCalled();
  });

  it("retains vectors but never starts paid fallback after a storage failure", async () => {
    const h = harness();
    h.persist.mockRejectedValueOnce(new Error("synthetic checkpoint write failed"));
    const error = await h.run().catch((value: unknown) => value);
    expect(error).toMatchObject({
      code: "MEMORY_EMBEDDING_PERSISTENCE_FAILED",
      partialEmbeddings: [[1, 2], null, null],
    });
    expect(h.sync).not.toHaveBeenCalled();
    expect(h.generation.cacheWritesInvalidated).toBe(true);
    expect(JSON.stringify(error)).not.toContain("partialEmbeddings");
  });
  it("persists valid vectors before synchronously recovering only missing inputs in the same generation", async () => {
    const h = harness();
    await expect(h.run()).resolves.toEqual([
      [1, 2],
      [3, 4],
      [5, 6],
    ]);
    expect(h.batchEmbed).toHaveBeenCalledOnce();
    expect(h.persist).toHaveBeenCalledWith([h.candidates[0]], [[1, 2]], h.generation);
    expect(h.sync).toHaveBeenCalledWith(
      h.candidates.slice(1),
      h.generation,
      8000,
      expect.any(Function),
    );
    expect(h.persist.mock.invocationCallOrder[0]).toBeLessThan(h.sync.mock.invocationCallOrder[0]!);
  });

  it("retains both Batch and earlier synchronous successes when later recovery fails", async () => {
    const h = harness();
    h.sync.mockImplementationOnce(async (...args: unknown[]) => {
      const progress = args[3] as (items: unknown[], vectors: number[][]) => void;
      progress([h.candidates[1]], [[3, 4]]);
      throw new Error("synthetic terminal synchronous failure");
    });
    await expect(h.run()).rejects.toMatchObject({ partialEmbeddings: [[1, 2], [3, 4], null] });
    expect(h.batchEmbed).toHaveBeenCalledOnce();
    expect(h.sync).toHaveBeenCalledOnce();
  });

  it("does not start fallback network work after generation authority changes during persistence", async () => {
    const h = harness();
    let stale = false;
    h.persist.mockImplementationOnce(async () => {
      stale = true;
    });
    h.assertCurrent.mockImplementation(() => {
      if (stale) {
        throw new Error("stale generation");
      }
    });
    await expect(h.run()).rejects.toThrow("stale generation");
    expect(h.sync).not.toHaveBeenCalled();
  });

  it("rejects wrong-dimensional partial vectors before persistence and recovers just those inputs", async () => {
    const h = harness();
    h.batchEmbed.mockResolvedValueOnce({
      kind: "partial",
      embeddings: [[9], [1, 2], [5, 6]],
      reason: "invalid dimension",
    });
    h.sync.mockResolvedValueOnce([[3, 4]]);
    await expect(h.run()).resolves.toEqual([
      [3, 4],
      [1, 2],
      [5, 6],
    ]);
    expect(h.persist).toHaveBeenCalledWith(
      h.candidates.slice(1),
      [
        [1, 2],
        [5, 6],
      ],
      h.generation,
    );
    expect(h.sync).toHaveBeenCalledWith(
      [h.candidates[0]],
      h.generation,
      8000,
      expect.any(Function),
    );
  });
});
