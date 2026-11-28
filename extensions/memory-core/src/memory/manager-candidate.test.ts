import fs from "node:fs/promises";
import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { createDeferred } from "openclaw/plugin-sdk/extension-shared";
import { listSessionTranscriptCorpusEntriesForAgent } from "openclaw/plugin-sdk/memory-core-host-engine-sessions";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryCandidateBuildError } from "./manager-candidate.js";
import { MemoryIndexDatabase } from "./manager-database-context.js";
import { createManagerIndexFixture } from "./manager-index.test-support.js";
import { compareSourceObservations } from "./manager-source-observation.js";

const { closeAllMemorySearchManagers, getMemorySearchManager } = await import("./index.js");

describe("persistent build-only cross-provider candidate", () => {
  const fixture = createManagerIndexFixture({
    getMemorySearchManager,
    closeAllMemorySearchManagers,
  });
  afterEach(() => vi.restoreAllMocks());

  async function setup(operationId = "openai256-fixture") {
    // Opt-in synthetic vectors exercise 1024-to-256 at the real manager boundary.
    // This is not live provider, paid Batch or route qualification.
    fixture.provider.syntheticDimensionsByModel = {
      "mistral-embed": 1024,
      "text-embedding-3-small": 256,
    };
    fixture.provider.identityAlias.provider = "mistral";
    await fs.writeFile(path.join(fixture.paths.memory, "candidate.md"), "Alpha violet preference.");
    const serving = await fixture.getFreshManager(
      fixture.createConfig({
        provider: "mistral",
        model: "mistral-embed",
        fallback: "none",
        vectorEnabled: true,
        outputDimensionality: 1024,
        cacheEnabled: true,
      }),
      "cli",
    );
    await serving.sync({ reason: "cli", force: true });
    const cfg = fixture.createConfig({
      provider: "openai",
      model: "text-embedding-3-small",
      fallback: "none",
      vectorEnabled: true,
      outputDimensionality: 256,
      cacheEnabled: true,
    });
    const candidate = await serving.createCandidateManager({ cfg, operationId });
    fixture.trackManager(candidate);
    // SAFETY: fixture-owned manager and database, never a production DB.
    const db = Reflect.get(serving, "db") as DatabaseSync;
    const rows = () =>
      db
        .prepare(
          "SELECT id, model, hex(embedding) AS embedding FROM memory_index_chunks ORDER BY id",
        )
        .all();
    const request = {
      operationId,
      // The fixture's OpenAI adapter deliberately returns id mock.
      expected: { provider: "mock", model: "text-embedding-3-small", dimensions: 256 },
    };
    return { serving, candidate, cfg, db, rows, request };
  }

  it("keeps Mistral serving/query/index unchanged during build, never publishes, retains candidate", async () => {
    const { serving, candidate, rows, request } = await setup();
    const published = vi.spyOn(MemoryIndexDatabase.prototype, "publishShadow");
    const before = rows();
    const provider = Reflect.get(serving, "provider");
    const entered = createDeferred<void>();
    const release = createDeferred<void>();
    fixture.provider.beforeEmbedBatch = async () => {
      entered.resolve();
      await release.promise;
    };
    const building = candidate.buildCandidate(serving, request);
    await Promise.race([
      entered.promise,
      building.then(() => {
        throw new Error("Candidate completed without entering its source gate");
      }),
    ]);
    try {
      expect(Reflect.get(serving, "provider")).toBe(provider);
      expect(provider).toMatchObject({ id: "mistral", model: "mistral-embed" });
      expect(await serving.search("alpha violet", { minScore: 0 })).not.toEqual([]);
      expect(rows()).toEqual(before);
      expect(published).not.toHaveBeenCalled();
    } finally {
      release.resolve();
    }
    const manifest = await building;
    expect(manifest).toMatchObject({
      activation: "manual-only",
      meta: {
        provider: "mock",
        model: "text-embedding-3-small",
        vectorDims: 256,
        candidate: { operationId: request.operationId, phase: "complete" },
      },
    });
    expect(rows()).toEqual(before);
    expect(Reflect.get(serving, "provider")).toBe(provider);
    expect(published).not.toHaveBeenCalled();
    await expect(candidate.sync({ reason: "cli", force: true })).rejects.toThrow("candidate-only");
    await candidate.close();
    expect((await fs.stat(manifest.databasePath)).isFile()).toBe(true);
    expect((await fs.stat(manifest.meta.candidate!.cacheDatabasePath)).isFile()).toBe(true);
  });

  it("preserves ordinary automatic rebuild publication and temporary cleanup", async () => {
    const { serving } = await setup();
    const published = vi.spyOn(MemoryIndexDatabase.prototype, "publishShadow");
    await serving.sync({ reason: "cli", force: true });
    expect(published).toHaveBeenCalledTimes(1);
    const db = Reflect.get(serving, "db") as DatabaseSync;
    const entries = await fs.readdir(path.dirname(db.location()!));
    expect(entries.filter((name) => name.includes(".memory-reindex-"))).toEqual([]);
  });

  it("rejects configured dimension mismatch before source calls and removes disposable inner custody", async () => {
    const { serving, candidate, request } = await setup();
    const calls = fixture.provider.embedBatchCalls;
    await expect(
      candidate.buildCandidate(serving, {
        ...request,
        expected: { ...request.expected, dimensions: 128 },
      }),
    ).rejects.toThrow("configured dimensions");
    expect(fixture.provider.embedBatchCalls).toBe(calls);
    const db = Reflect.get(candidate, "db") as DatabaseSync;
    await expect(
      fs.stat(db.location()! + ".memory-candidate-" + request.operationId),
    ).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("retains source-stage errors as unreconciled rather than deleting possibly paid work", async () => {
    const { serving, candidate, rows, request } = await setup();
    const before = rows();
    fixture.provider.embedBatchPermanentFailure = Object.assign(new Error("synthetic HTTP 400"), {
      status: 400,
    });
    let retained: MemoryCandidateBuildError | undefined;
    try {
      await candidate.buildCandidate(serving, request);
    } catch (error) {
      expect(error).toBeInstanceOf(MemoryCandidateBuildError);
      retained = error as MemoryCandidateBuildError;
    }
    expect(retained?.disposition).toBe("retained-unreconciled");
    expect((await fs.stat(retained!.databasePath)).isFile()).toBe(true);
    expect(rows()).toEqual(before);
    await expect(candidate.buildCandidate(serving, request)).rejects.toThrow("idle isolated");
  });

  it("does not describe local cancellation as remote cancellation or dispose submitted work", async () => {
    const { serving, candidate, rows, request } = await setup();
    const before = rows();
    const abort = new AbortController();
    fixture.provider.beforeEmbedBatch = async () => {
      abort.abort();
    };
    await expect(
      candidate.buildCandidate(serving, { ...request, signal: abort.signal }),
    ).rejects.toMatchObject({
      name: "MemoryCandidateBuildError",
      disposition: "retained-unreconciled",
    });
    const db = Reflect.get(candidate, "db") as DatabaseSync;
    expect(
      (
        await fs.stat(
          path.join(db.location()! + ".memory-candidate-" + request.operationId, "index.sqlite"),
        )
      ).isFile(),
    ).toBe(true);
    expect(rows()).toEqual(before);
  });

  it("refuses existing operation custody after close/restart without another provider submission", async () => {
    const { serving, candidate, cfg, request } = await setup();
    const manifest = await candidate.buildCandidate(serving, request);
    await candidate.close();
    const calls = fixture.provider.embedBatchCalls;
    await expect(
      serving.createCandidateManager({ cfg, operationId: request.operationId }),
    ).rejects.toMatchObject({ code: "EEXIST" });
    expect(fixture.provider.embedBatchCalls).toBe(calls);
    expect((await fs.stat(manifest.databasePath)).isFile()).toBe(true);
  });

  it("fails closed for real OpenAI identity until durable controller binding is integrated", async () => {
    const { serving, candidate, request } = await setup();
    // Opt into the existing synthetic adapter's exact-provider identity path.
    fixture.provider.identityAlias.provider = "openai";
    const calls = fixture.provider.embedBatchCalls;
    await expect(
      candidate.buildCandidate(serving, {
        ...request,
        expected: { ...request.expected, provider: "openai" },
      }),
    ).rejects.toThrow("explicit durable Batch journal binding");
    expect(fixture.provider.embedBatchCalls).toBe(calls);
  });

  it("rejects path traversal before creating operation artifacts", async () => {
    const { serving, cfg } = await setup();
    await expect(
      serving.createCandidateManager({ cfg, operationId: "../outside" }),
    ).rejects.toThrow("Invalid serving owner or candidate operation identity");
  });

  it("refuses fresh exact-OpenAI candidate search before provider or source admission", async () => {
    const { candidate } = await setup();
    fixture.provider.identityAlias.provider = "openai";
    const batchCalls = fixture.provider.embedBatchCalls;
    const queryCalls = fixture.provider.embedQueryCalls;
    const creations = fixture.provider.providerCalls.length;
    const published = vi.spyOn(MemoryIndexDatabase.prototype, "publishShadow");
    await expect(candidate.search("alpha violet")).rejects.toThrow("candidate-only");
    await expect(candidate.search("")).rejects.toThrow("candidate-only");
    expect(fixture.provider.embedBatchCalls).toBe(batchCalls);
    expect(fixture.provider.embedQueryCalls).toBe(queryCalls);
    expect(fixture.provider.providerCalls).toHaveLength(creations);
    expect(published).not.toHaveBeenCalled();
  });

  it("refuses search and inherited shared sync after an exact-OpenAI build refusal", async () => {
    const { serving, candidate, request } = await setup();
    fixture.provider.identityAlias.provider = "openai";
    const batchCalls = fixture.provider.embedBatchCalls;
    const queryCalls = fixture.provider.embedQueryCalls;
    const published = vi.spyOn(MemoryIndexDatabase.prototype, "publishShadow");
    await expect(
      candidate.buildCandidate(serving, {
        ...request,
        expected: { ...request.expected, provider: "openai" },
      }),
    ).rejects.toThrow("explicit durable Batch journal binding");
    await expect(candidate.search("alpha violet")).rejects.toThrow("candidate-only");
    const admitted = Reflect.get(candidate, "syncAdmitted") as (params: {
      reason: string;
    }) => Promise<void>;
    await expect(admitted.call(candidate, { reason: "search-bootstrap" })).rejects.toThrow(
      "candidate-only",
    );
    expect(fixture.provider.embedBatchCalls).toBe(batchCalls);
    expect(fixture.provider.embedQueryCalls).toBe(queryCalls);
    expect(published).not.toHaveBeenCalled();
  });

  it("refuses candidate search maintenance and maintenance-derived manager allocation", async () => {
    const { candidate, cfg } = await setup();
    fixture.provider.identityAlias.provider = "openai";
    const batchCalls = fixture.provider.embedBatchCalls;
    const queryCalls = fixture.provider.embedQueryCalls;
    const creations = fixture.provider.providerCalls.length;
    const published = vi.spyOn(MemoryIndexDatabase.prototype, "publishShadow");
    const maintenance = Reflect.get(candidate, "syncPublishedIndexInBackground") as (params: {
      reason: string;
    }) => Promise<void>;
    await expect(maintenance.call(candidate, { reason: "search" })).rejects.toThrow(
      "candidate-only",
    );
    const { MemoryIndexManager } = await import("./manager.js");
    await expect(
      MemoryIndexManager.get({
        cfg,
        agentId: "main",
        purpose: "maintenance",
        maintenanceSource: candidate,
      }),
    ).rejects.toThrow("candidate-only");
    expect(fixture.provider.embedBatchCalls).toBe(batchCalls);
    expect(fixture.provider.embedQueryCalls).toBe(queryCalls);
    expect(fixture.provider.providerCalls).toHaveLength(creations);
    expect(published).not.toHaveBeenCalled();
  });

  it("preserves ordinary serving search bootstrap and background maintenance admission", async () => {
    fixture.provider.identityAlias.provider = "mistral";
    fixture.provider.syntheticDimensionsByModel = { "mistral-embed": 1024 };
    const serving = await fixture.getFreshManager(
      fixture.createConfig({
        provider: "mistral",
        model: "mistral-embed",
        fallback: "none",
        vectorEnabled: true,
        outputDimensionality: 1024,
        cacheEnabled: true,
      }),
      "cli",
    );
    const published = vi.spyOn(MemoryIndexDatabase.prototype, "publishShadow");
    expect(await serving.search("alpha", { minScore: 0 })).not.toEqual([]);
    expect(fixture.provider.embedBatchCalls).toBeGreaterThan(0);
    expect(published).toHaveBeenCalled();
    const maintenance = Reflect.get(serving, "syncPublishedIndexInBackground") as (params: {
      reason: string;
    }) => Promise<void>;
    await expect(maintenance.call(serving, { reason: "search" })).resolves.toBeUndefined();
  });
  it("reloads genuine nonopenai writer metadata as inspection only", async () => {
    const { serving, candidate, request } = await setup("schema-nonopenai");
    const built = await candidate.buildCandidate(serving, request);
    await candidate.close();
    const loaded = await serving.loadCandidateManifest(request);
    expect(loaded.meta).toEqual(built.meta);
    expect(loaded.meta.provider).toBe("mock");
    expect(loaded.inspection).toMatchObject({
      status: "unverified-inspection-only",
      openedIdentity: "unavailable",
      cacheStatus: "path-identity-only",
    });
  });

  it("observes unsynced native content/add/delete and POSIX access drift without index writes", async () => {
    const { serving, db } = await setup("observe-native");
    const filename = path.join(fixture.paths.memory, "candidate.md");
    const calls = fixture.provider.embedBatchInputCalls;
    const writes = db.prepare("SELECT total_changes() AS count").get();
    const publish = vi.spyOn(MemoryIndexDatabase.prototype, "publishShadow");
    const first = await serving.observeCandidateSources();
    expect(first.status).toBe("observed-not-atomic");
    await fs.writeFile(filename, "Changed without native sync");
    const content = await serving.observeCandidateSources();
    expect(content.indexFence).toBe(first.indexFence);
    expect(compareSourceObservations(first, content)).toBe("changed");
    const addition = path.join(fixture.paths.memory, "added.md");
    await fs.writeFile(addition, "New source");
    const added = await serving.observeCandidateSources();
    expect(compareSourceObservations(content, added)).toBe("changed");
    await fs.unlink(addition);
    const removed = await serving.observeCandidateSources();
    expect(compareSourceObservations(added, removed)).toBe("changed");
    const info = await fs.stat(filename);
    await fs.chmod(filename, (info.mode & 0o777) ^ 0o040);
    const access = await serving.observeCandidateSources();
    expect(compareSourceObservations(removed, access)).toBe("changed");
    expect(access.indexFence).toBe(first.indexFence);
    expect(fixture.provider.embedBatchInputCalls).toBe(calls);
    expect(publish).not.toHaveBeenCalled();
    expect(db.prepare("SELECT total_changes() AS count").get()).toEqual(writes);
  });
  it("uses native extra-root enumeration and fails closed for enabled session content coverage", async () => {
    const extra = path.join(fixture.paths.root, "extra-observe");
    await fs.mkdir(extra, { recursive: true });
    const memoryCfg = fixture.createConfig({
      provider: "mistral",
      model: "mistral-embed",
      fallback: "none",
      extraPaths: [extra],
      sources: ["memory"],
    });
    const memoryManager = await fixture.getFreshManager(memoryCfg, "cli");
    await memoryManager.sync({ reason: "cli", force: true });
    const emptyExtra = await memoryManager.observeCandidateSources();
    expect(emptyExtra.status).toBe("observed-not-atomic");
    await fs.writeFile(path.join(extra, "native-extra.md"), "Synthetic extra root source");
    const populated = await memoryManager.observeCandidateSources();
    expect(compareSourceObservations(emptyExtra, populated)).toBe("changed");
    const noExtra = await fixture.getFreshManager(
      fixture.createConfig({
        provider: "mistral",
        model: "mistral-embed",
        fallback: "none",
        sources: ["memory"],
      }),
      "cli",
    );
    await noExtra.sync({ reason: "cli", force: true });
    expect((await noExtra.observeCandidateSources()).scopeDigest).not.toBe(populated.scopeDigest);
    const cfg = fixture.createConfig({
      provider: "mistral",
      model: "mistral-embed",
      fallback: "none",
      extraPaths: [extra],
      sources: ["memory", "sessions"],
      sessionMemory: true,
    });
    const manager = await fixture.getFreshManager(cfg, "cli");
    await fixture.seedSessionTranscript({
      sessionId: "observation-session",
      messages: [{ role: "user", content: "synthetic observation only", timestamp: Date.now() }],
    });
    await manager.sync({ reason: "cli", force: true });
    const before = await manager.observeCandidateSources();
    expect(before.status).toBe("unverified");
    expect(before.digest).toBeNull();
    expect(before.issues).toContain(
      "session-readonly-content-and-completeness-receipt-unavailable",
    );
  });
  it("refuses pathname substitution between lstat and the actual opened source handle", async () => {
    const { serving } = await setup("observe-substitute");
    const target = path.join(fixture.paths.memory, "candidate.md");
    const moved = target + ".saved";
    const open = fs.open.bind(fs);
    let substituted = false;
    const spy = vi.spyOn(fs, "open").mockImplementation(async (filename, flags, mode) => {
      if (filename === target && !substituted) {
        substituted = true;
        await fs.rename(target, moved);
        await fs.symlink(moved, target);
      }
      return await open(filename, flags, mode);
    });
    try {
      const observation = await serving.observeCandidateSources();
      expect(substituted).toBe(true);
      expect(observation.status).toBe("unverified");
      expect(observation.digest).toBeNull();
    } finally {
      spy.mockRestore();
      if (substituted) {
        await fs.unlink(target);
        await fs.rename(moved, target);
      }
    }
  });

  it("keeps independently synced enabled-empty session coverage unverified", async () => {
    const manager = await fixture.getFreshManager(
      fixture.createConfig({
        provider: "mistral",
        model: "mistral-embed",
        fallback: "none",
        sources: ["memory", "sessions"],
        sessionMemory: true,
      }),
      "cli",
    );
    expect(
      await listSessionTranscriptCorpusEntriesForAgent("main", {
        readOnly: true,
        includeContentRevision: false,
      }),
    ).toEqual([]);
    await manager.sync({ reason: "cli", force: true });
    // Observation-only baseline starts after genuine native arrangement above.
    const calls = fixture.provider.embedBatchInputCalls;
    const db = Reflect.get(manager, "db") as DatabaseSync;
    const writes = db.prepare("SELECT total_changes() AS count").get();
    const publish = vi.spyOn(MemoryIndexDatabase.prototype, "publishShadow");
    const observation = await manager.observeCandidateSources();
    expect(observation.status).toBe("unverified");
    expect(observation.digest).toBeNull();
    expect(observation.issues).toContain(
      "session-readonly-content-and-completeness-receipt-unavailable",
    );
    expect(fixture.provider.embedBatchInputCalls).toBe(calls);
    expect(publish).not.toHaveBeenCalled();
    expect(db.prepare("SELECT total_changes() AS count").get()).toEqual(writes);
  });
});
