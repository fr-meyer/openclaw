import { parseCandidateMetadata } from "./manager-candidate-schema.js";
import { DatabaseSync } from "node:sqlite";
import fs from "node:fs/promises";
import path from "node:path";
import { createHash } from "node:crypto";
import type { MemoryEmbeddingProviderAdapter } from "openclaw/plugin-sdk/memory-core-host-engine-embeddings";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createManagerIndexFixture } from "./manager-index.test-support.js";
import * as reindexLock from "./manager-reindex-lock.js";
import { MemoryIndexDatabase } from "./manager-database-context.js";
const { closeAllMemorySearchManagers, getMemorySearchManager } = await import("./index.js");

describe("candidate registered-owner manager bridge", () => {
  const fixture = createManagerIndexFixture({ getMemorySearchManager, closeAllMemorySearchManagers });
  afterEach(() => vi.restoreAllMocks());
  async function setup(mode: "complete" | "unknown" | "identity-drift" = "complete") {
    fixture.provider.identityAlias.provider = "mistral";
    fixture.provider.syntheticDimensionsByModel = { "mistral-embed": 1024 };
    const serving = await fixture.getFreshManager(fixture.createConfig({
      provider: "mistral", model: "mistral-embed", fallback: "none", outputDimensionality: 1024,
      vectorEnabled: true, cacheEnabled: true,
    }), "cli");
    await serving.sync({ reason: "cli", force: true });
    const calls = { bound: 0, direct: 0 };
    // Standard synthetic adapter, created through the REAL native owner callback.
    // Native journal/recovery HTTP behavior is covered by the separate controller selector.
    const adapter: MemoryEmbeddingProviderAdapter = {
      id: "openai", transport: "remote",
      create: async () => ({
        provider: { id: "openai", model: "text-embedding-3-small",
          embedQuery: async () => { calls.direct++; throw new Error("unexpected direct query"); },
          embedBatch: async () => { calls.direct++; throw new Error("unexpected direct source"); } },
        runtime: {
          id: "openai", sourceWideBatchEmbed: true, batchFailureMode: "fail-closed",
          batchEmbed: async () => { throw new Error("unbound batch forbidden"); },
          cacheKeyData: { provider: "openai", model: "text-embedding-3-small", outputDimensionality: 256 },
          withCandidateBatch: async (admission, run) => {
            const j = admission.journal;
            const identity = createHash("sha256").update(JSON.stringify({
              migrationId: j.migrationId, sourceRevision: j.sourceRevision,
              accountId: j.accountId, route: j.route, agentId: admission.agentId,
              model: admission.expected.model, dimensions: admission.expected.dimensions,
            })).digest("hex");
            return await run(async (batch) => {
              calls.bound++;
              if (mode === "unknown") { throw new Error("synthetic accepted submission UNKNOWN"); }
              return batch.chunks.map(() => [1, ...Array(255).fill(0)]);
            }, { ...admission, identity,
              ...(mode === "identity-drift" ? { journal: { ...j, accountId: "changed" } } : {}) });
          },
        },
      }),
    };
    fixture.provider.candidateAdapter = adapter;
    const cfg = fixture.createConfig({ provider: "openai", model: "text-embedding-3-small", fallback: "none",
      outputDimensionality: 256, vectorEnabled: true, cacheEnabled: true, batchEnabled: true });
    const operationId = "registered-openai";
    const candidate = await serving.createCandidateManager({ cfg, operationId });
    fixture.trackManager(candidate);
    const request = { operationId, expected: { provider: "openai", model: "text-embedding-3-small", dimensions: 256 },
      controller: { accountId: "fixture-account", route: "https://synthetic.example/v1",
        sourceRevision: serving.candidateSourceFence() } };
    return { serving, candidate, request, calls, cfg };
  }
  it("uses only owned bound Batch execution, retains complete SQLite metadata and reloads read-only", async () => {
    const { serving, candidate, request, calls } = await setup();
    const publish = vi.spyOn(MemoryIndexDatabase.prototype, "publishShadow");
    const built = await candidate.buildCandidate(serving, request);
    await candidate.close();
    const reloaded = await serving.loadCandidateManifest(request);
    expect(reloaded).toMatchObject(built);
    expect(parseCandidateMetadata(JSON.stringify(built.meta))).toEqual(built.meta);
    expect(reloaded.inspection).toMatchObject({ status: "unverified-inspection-only", openedIdentity: "unavailable" });
    expect(reloaded.meta.candidate).toMatchObject({ version: 1, phase: "complete",
      controller: { journal: { accountId: "fixture-account" } } });
    expect(calls.bound).toBeGreaterThan(0);
    expect(calls.direct).toBe(0);
    expect(publish).not.toHaveBeenCalled();
    const submitted = calls.bound;
    await serving.loadCandidateManifest(request);
    expect(calls.bound).toBe(submitted);
  });
  it("rejects a structurally forged runtime not captured by its provider owner", async () => {
    const { serving, candidate, request, calls } = await setup();
    const initialize = Reflect.get(candidate, "ensureProviderInitialized") as () => Promise<void>;
    await initialize.call(candidate);
    const runtime = Reflect.get(candidate, "providerRuntime");
    Reflect.set(candidate, "providerRuntime", { ...runtime });
    await expect(candidate.buildCandidate(serving, request)).rejects.toThrow("not owned");
    expect(calls.bound).toBe(0);
    expect(calls.direct).toBe(0);
  });
  it("rejects registered controller identity drift before source embedding", async () => {
    const { serving, candidate, request, calls } = await setup("identity-drift");
    await expect(candidate.buildCandidate(serving, request)).rejects.toThrow("changed its admitted identity");
    expect(calls.bound).toBe(0);
    expect(calls.direct).toBe(0);
  });
  it("refuses an UNKNOWN manager restart without another source submission", async () => {
    const { serving, candidate, request, calls, cfg } = await setup("unknown");
    await expect(candidate.buildCandidate(serving, request)).rejects.toMatchObject({ disposition: "retained-unreconciled" });
    await candidate.close();
    const submitted = calls.bound;
    await expect(serving.createCandidateManager({ cfg, operationId: request.operationId }))
      .rejects.toMatchObject({ code: "EEXIST" });
    await expect(serving.loadCandidateManifest(request)).rejects.toThrow("manifest");
    expect(calls.bound).toBe(submitted);
    expect(calls.direct).toBe(0);
  });
  it("refuses reload after serving source-index generation drift", async () => {
    const { serving, candidate, request, calls } = await setup();
    await candidate.buildCandidate(serving, request);
    await serving.sync({ reason: "cli", force: true });
    const submitted = calls.bound;
    await expect(serving.loadCandidateManifest(request)).rejects.toThrow("source fence");
    expect(calls.bound).toBe(submitted);
  });

  it("ignores runtime controller path/migration extras and retains native operation custody", async () => {
    const { serving, candidate, request } = await setup();
    const extras = { ...request.controller, path: "/unowned/escape.sqlite", migrationId: "different" };
    const built = await candidate.buildCandidate(serving, { ...request, controller: extras });
    expect(built.meta.candidate?.controller?.journal.migrationId).toBe(request.operationId);
    expect(built.meta.candidate?.controller?.journal.path)
      .toBe(path.join(path.dirname(built.meta.candidate!.cacheDatabasePath), "batch.sqlite"));
  });
  it("refuses a moved candidate leaf symlink even when target inode is unchanged", async () => {
    const { serving, candidate, request } = await setup();
    const built = await candidate.buildCandidate(serving, request);
    await candidate.close();
    const moved = built.databasePath + ".moved";
    await fs.rename(built.databasePath, moved);
    await fs.symlink(moved, built.databasePath);
    await expect(serving.loadCandidateManifest(request)).rejects.toThrow("leaf custody");
  });
  it("refuses candidate leaf public permissions before native readonly open", async () => {
    const { serving, candidate, request } = await setup();
    const built = await candidate.buildCandidate(serving, request);
    await candidate.close();
    await fs.chmod(built.databasePath, 0o644);
    const opened = vi.spyOn(MemoryIndexDatabase, "openPublished");
    await expect(serving.loadCandidateManifest(request)).rejects.toThrow("leaf custody");
    expect(opened).not.toHaveBeenCalled();
  });
  it("refuses missing cache rather than claiming verified cache custody", async () => {
    const { serving, candidate, request } = await setup();
    const built = await candidate.buildCandidate(serving, request);
    await candidate.close();
    await fs.unlink(built.meta.candidate!.cacheDatabasePath);
    await expect(serving.loadCandidateManifest(request)).rejects.toMatchObject({ code: "ENOENT" });
  });
  it("refuses a replaced private regular cache with a different retained identity", async () => {
    const { serving, candidate, request } = await setup();
    const built = await candidate.buildCandidate(serving, request);
    await candidate.close();
    const cache = built.meta.candidate!.cacheDatabasePath;
    await fs.rename(cache, cache + ".old");
    await fs.copyFile(cache + ".old", cache);
    await fs.chmod(cache, 0o600);
    await expect(serving.loadCandidateManifest(request)).rejects.toThrow("manifest identity");
  });
  it("returns a retained manifest after successful admission release", async () => {
    const { serving, candidate, request, calls } = await setup();
    const wait = reindexLock.waitForMemoryReindexLock;
    const released: string[] = [];
    vi.spyOn(reindexLock, "waitForMemoryReindexLock").mockImplementation(async (...args) => {
      const lock = await wait(...args);
      return { ...lock, release: async () => { await lock.release(); released.push("release"); } };
    });
    const built = await candidate.buildCandidate(serving, request);
    expect(built.meta.candidate?.phase).toBe("complete");
    expect(calls.bound).toBeGreaterThan(0);
    expect(released).toEqual(["release"]);
  });
  it("preserves actual source, generation, worker and admission release failures", async () => {
    const { serving, candidate, request, calls } = await setup("unknown");
    const database = Reflect.get(candidate, "publishedDatabase") as MemoryIndexDatabase;
    const cleanupError = new Error("synthetic worker cleanup failed");
    const generationError = new Error("synthetic generation cleanup failed");
    const releaseError = new Error("synthetic admission release failed");
    const trace: string[] = [];
    const closeWorker = database.closePublicationWorker.bind(database);
    const close = vi.spyOn(database, "closePublicationWorker").mockImplementation(async () => {
      if (calls.bound === 0) { trace.push("initial-close"); await closeWorker(); return; }
      trace.push("source-reached-worker-close"); throw cleanupError;
    });
    const end = Reflect.get(candidate, "endSyncProviderGeneration") as () => void;
    Reflect.set(candidate, "endSyncProviderGeneration", () => {
      end.call(candidate); trace.push("source-reached-generation-end"); throw generationError;
    });
    const wait = reindexLock.waitForMemoryReindexLock;
    vi.spyOn(reindexLock, "waitForMemoryReindexLock").mockImplementation(async (...args) => {
      const lock = await wait(...args);
      return { ...lock, release: async () => {
        await lock.release(); trace.push("admission-release"); throw releaseError;
      } };
    });
    try {
      const failure = await candidate.buildCandidate(serving, request).catch((error) => error);
      expect(failure).toMatchObject({ disposition: "retained-unreconciled" });
      expect(calls.bound).toBeGreaterThan(0);
      expect(calls.direct).toBe(0);
      expect(trace).toEqual(["initial-close", "source-reached-generation-end",
        "source-reached-worker-close", "admission-release"]);
      const flatten = (error: unknown): unknown[] => error instanceof AggregateError
        ? [error, ...error.errors.flatMap(flatten)] : [error];
      const errors = flatten(failure.cause);
      expect(errors).toContain(cleanupError);
      expect(errors).toContain(generationError);
      expect(errors).toContain(releaseError);
      expect(errors.some((error) => String(error).includes("UNKNOWN"))).toBe(true);
      expect(failure.cause).toBeInstanceOf(AggregateError);
      expect(flatten(failure.cause.cause).some((error) => String(error).includes("UNKNOWN"))).toBe(true);
    } finally { close.mockRestore(); Reflect.set(candidate, "endSyncProviderGeneration", end); }
  });
  it("rejects actual retained SQLite nested metadata corruption through readonly reload", async () => {
    const { serving, candidate, request, calls } = await setup();
    const built = await candidate.buildCandidate(serving, request);
    await candidate.close();
    const corrupt = new DatabaseSync(built.databasePath);
    try {
      const value = { ...built.meta, candidate: { ...built.meta.candidate, controller: { journal: null } } };
      const update = corrupt.prepare("UPDATE memory_index_meta SET value = ? WHERE key = ?")
        .run(JSON.stringify(value), "memory_index_meta_v1");
      expect(Number(update.changes)).toBe(1);
    } finally { corrupt.close(); }
    const before = await fs.readFile(built.databasePath);
    const servingDb = Reflect.get(serving, "db") as DatabaseSync;
    const servingChanges = servingDb.prepare("SELECT total_changes() AS count").get();
    const publish = vi.spyOn(MemoryIndexDatabase.prototype, "publishShadow");
    const opened = vi.spyOn(MemoryIndexDatabase, "openPublished");
    const submitted = calls.bound;
    await expect(serving.loadCandidateManifest(request)).rejects.toThrow("Invalid persisted candidate schema v1");
    expect(opened).toHaveBeenCalledWith(expect.objectContaining({ readOnly: true, allowExtension: false }));
    expect(publish).not.toHaveBeenCalled();
    expect(calls.bound).toBe(submitted); expect(calls.direct).toBe(0);
    expect(servingDb.prepare("SELECT total_changes() AS count").get()).toEqual(servingChanges);
    expect(await fs.readFile(built.databasePath)).toEqual(before);
  });

});
