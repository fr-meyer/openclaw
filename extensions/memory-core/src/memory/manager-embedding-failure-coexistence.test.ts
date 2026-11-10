import type { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryIndexDatabase } from "./manager-database-context.js";
import { createManagerIndexFixture } from "./manager-index.test-support.js";
import type { MemoryIndexMeta } from "./manager-reindex-state.js";

const { closeAllMemorySearchManagers, getMemorySearchManager } = await import("./index.js");

function publishedRows(db: DatabaseSync) {
  return {
    meta: db.prepare("SELECT key, value FROM memory_index_meta ORDER BY key").all(),
    sources: db.prepare("SELECT * FROM memory_index_sources ORDER BY path, source").all(),
    chunks: db.prepare("SELECT * FROM memory_index_chunks ORDER BY id").all(),
    vectors: db
      .prepare("SELECT id, hex(embedding) AS embedding FROM memory_index_chunks_vec ORDER BY id")
      .all(),
  };
}

function openAiCacheRows(db: DatabaseSync) {
  return db
    .prepare(
      "SELECT hash, dims, length(embedding) AS bytes FROM memory_embedding_cache WHERE provider = 'openai' AND model = 'text-embedding-3-small' ORDER BY hash",
    )
    .all() as Array<{ hash: string; dims: number; bytes: number }>;
}

function failBeforePublication(manager: object) {
  return vi
    .spyOn(manager as { writeMeta: (meta: MemoryIndexMeta) => void }, "writeMeta")
    .mockImplementation(() => {
      throw new Error("synthetic pre-publication failure");
    });
}

describe("two-provider memory reindex failure", () => {
  const fixture = createManagerIndexFixture({
    getMemorySearchManager,
    closeAllMemorySearchManagers,
  });

  afterEach(() => vi.restoreAllMocks());

  it.each([true, false])(
    "keeps Mistral published across failed OpenAI rebuilds and manager reopen (cache enabled: %s)",
    async (cacheEnabled) => {
      const serving = await fixture.getFreshManager(
        fixture.createConfig({
          provider: "mistral",
          model: "synthetic-mistral-embed",
          outputDimensionality: 1024,
          vectorEnabled: true,
          sources: ["memory"],
          cacheEnabled: true,
        }),
        "cli",
      );
      await serving.sync({ reason: "baseline", force: true });
      // SAFETY: The fixture owns the real published SQLite connection.
      const db = Reflect.get(serving, "db") as DatabaseSync;
      const baseline = publishedRows(db);
      const meta = JSON.parse((baseline.meta[0] as { value: string }).value) as MemoryIndexMeta;
      expect(meta).toMatchObject({
        provider: "mistral",
        model: "synthetic-mistral-embed",
        vectorDims: 1024,
      });
      const semanticQuery = "alphaish";
      await expect(serving.search(semanticQuery, { lexicalOnly: true })).resolves.toEqual([]);
      expect((await serving.search(semanticQuery)).length).toBeGreaterThan(0);

      const targetConfig = fixture.createConfig({
        provider: "openai",
        model: "text-embedding-3-small",
        outputDimensionality: 256,
        vectorEnabled: true,
        sources: ["memory"],
        cacheEnabled,
      });
      const publishShadow = vi.spyOn(MemoryIndexDatabase.prototype, "publishShadow");
      const candidate = await fixture.getFreshManager(targetConfig, "cli");
      const firstFailure = failBeforePublication(candidate);
      const callsBeforeFirst = fixture.provider.embedBatchCalls;
      try {
        await expect(candidate.sync({ reason: "candidate-failure", force: true })).rejects.toThrow(
          "synthetic pre-publication failure",
        );
      } finally {
        firstFailure.mockRestore();
      }
      expect(fixture.provider.embedBatchCalls).toBeGreaterThan(callsBeforeFirst);
      expect(publishShadow).not.toHaveBeenCalled();
      expect(publishedRows(db)).toEqual(baseline);
      expect((await serving.search(semanticQuery)).length).toBeGreaterThan(0);
      const retained = openAiCacheRows(db);
      if (cacheEnabled) {
        expect(retained.length).toBeGreaterThan(0);
        expect(retained.every((row) => row.dims === 256 && row.bytes === 256 * 8)).toBe(true);
      } else {
        expect(retained).toEqual([]);
      }
      await candidate.close();
      const reopened = await fixture.getFreshManager(targetConfig, "cli");
      const secondFailure = failBeforePublication(reopened);
      const callsBeforeRetry = fixture.provider.embedBatchCalls;
      try {
        await expect(reopened.sync({ reason: "candidate-retry", force: true })).rejects.toThrow(
          "synthetic pre-publication failure",
        );
      } finally {
        secondFailure.mockRestore();
      }
      if (cacheEnabled) {
        expect(fixture.provider.embedBatchCalls).toBe(callsBeforeRetry);
      } else {
        expect(fixture.provider.embedBatchCalls).toBeGreaterThan(callsBeforeRetry);
      }
      expect(openAiCacheRows(db)).toEqual(retained);
      expect(publishedRows(db)).toEqual(baseline);
      expect((await serving.search(semanticQuery)).length).toBeGreaterThan(0);
      expect(publishShadow).not.toHaveBeenCalled();
    },
  );
});
