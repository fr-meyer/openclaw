import { formatErrorMessage } from "openclaw/plugin-sdk/error-runtime";
import { expectDefined } from "openclaw/plugin-sdk/expect-runtime";
import {
  formatEmbeddingModelInput,
  isEmbeddingBatchUnavailableError,
  resolveEmbeddingInputFormatVersion,
} from "openclaw/plugin-sdk/memory-core-host-engine-embeddings";
import {
  buildFileEntry,
  buildMultimodalChunkForIndexing,
  runWithConcurrency,
  type MemorySource,
} from "openclaw/plugin-sdk/memory-core-host-engine-storage";
import { chunkItems } from "openclaw/plugin-sdk/text-chunking";
import {
  withMemoryWorkspaceLock,
  withMemoryWorkspacePreparation,
} from "../memory-workspace-lock.js";
import { readSessionResetRecallCutoffMetadata } from "../session-reset-recall-metadata.js";
import {
  assertBoundedMemoryOperation,
  assertBoundedMemorySnapshot,
  boundedMemoryAdmissionActive,
  MemoryAdmissionRefused,
} from "./bounded-admission.js";
import {
  MemoryManagerEmbeddingRetryOps,
  embeddingOperationLog as log,
} from "./embedding-retry-ops.js";
import { countBatchSources, formatBatchSourceCounts } from "./manager-batch-source-counts.js";
import { MemoryBatchSubmissionOwner } from "./manager-batch-submission.js";
import type { IndexedMemoryChunk } from "./manager-chunk-writer.js";
import { prepareMemoryIndexInWorker } from "./manager-cpu-worker-runtime.js";
import { recoverMemoryEmbeddingBatch } from "./manager-embedding-batch-recovery.js";
import type { MemoryEmbeddingCacheCandidate } from "./manager-embedding-cache-ops.js";
import {
  runMemoryEmbeddingBatchTimeoutRetry,
  resolveMemoryEmbeddingBatch,
} from "./manager-embedding-policy.js";
import { resolveChunkProvenance } from "./manager-index-preparation.js";
import { readMemoryIndexSource } from "./manager-index-source.js";
import type { MemorySourceIndexReplacement } from "./manager-source-index-kernel.js";
import type {
  MemoryIndexWorkItem,
  MemorySemanticProviderGeneration,
  MemorySyncProviderGeneration,
} from "./manager-sync-ops.js";
import { logMemoryVectorDegradedWrite } from "./manager-vector-warning.js";
import { resolveMemoryPathClassification } from "./memory-path-provenance.js";

const EMBEDDING_BATCH_MAX_TOKENS = 8000;
const SOURCE_WIDE_BATCH_MAX_FILES = 2048;
const SOURCE_WIDE_BATCH_MAX_REQUESTS = 50000;

type MemoryIndexEntry = MemoryIndexWorkItem["entry"];

type PreparedMemoryIndexEntry = {
  entry: MemoryIndexEntry;
  source: MemorySource;
  chunks: IndexedMemoryChunk[];
  structuredInputBytes?: number;
};

export abstract class MemoryManagerEmbeddingOps extends MemoryManagerEmbeddingRetryOps {
  protected readonly batchFailureLimit = 2;
  protected batchFailure: { count: number; lastError?: string; lastProvider?: string } = {
    count: 0,
  };
  private readonly batchAbortController = new AbortController();
  private readonly batchSubmissionOwner = new MemoryBatchSubmissionOwner(async (command) => {
    const database = this.publishedDatabase;
    try {
      return await database.runBatchSubmission(command, () => {
        if (
          this.closing ||
          this.closed ||
          this.publishedDatabase !== database ||
          !database.db.isOpen
        ) {
          throw new Error("Native batch submission owner changed");
        }
      });
    } catch (error) {
      // Reconcile an uncertain commit for display, never replay a paid submission.
      if (!this.closing && !this.closed && this.publishedDatabase === database) {
        await this.loadBatchSubmissionStatus().catch(() => undefined);
      }
      throw error;
    }
  });

  protected async loadBatchSubmissionStatus(): Promise<void> {
    const database = this.publishedDatabase;
    const version = this.batchSubmissionOwner.captureStatusVersion();
    const status = await database.readBatchSubmissionStatus();
    if (this.closed || this.closing || this.publishedDatabase !== database) {
      throw new Error("Native batch status owner changed");
    }
    this.batchSubmissionOwner.installStatus(status, version);
  }
  protected readBatchSubmissionQuarantineStatus() {
    return this.batchSubmissionOwner.readStatus();
  }

  protected async assertNoBatchSubmissionQuarantine(): Promise<void> {
    await this.batchSubmissionOwner.assertReady();
  }

  clearBatchSubmissionQuarantine(): Promise<boolean> {
    return this.batchSubmissionOwner.clear();
  }

  protected async commitBatchSubmissionQuarantine(): Promise<void> {
    await this.batchSubmissionOwner.commit();
  }

  protected abortEmbeddingBatches(): void {
    this.batchAbortController.abort();
  }

  private async embedChunksWithBatch(
    candidates: MemoryEmbeddingCacheCandidate[],
    source: string,
    generation: MemorySemanticProviderGeneration,
    debugContext: Record<string, unknown> = {},
  ): Promise<number[][]> {
    const provider = generation.provider;
    const batchEmbed = resolveMemoryEmbeddingBatch(generation.runtime);
    if (!batchEmbed) {
      return this.embedChunksInBatches(candidates, generation, EMBEDDING_BATCH_MAX_TOKENS);
    }
    const { embeddings, missing, missingCandidates } = await this.collectCachedEmbeddings(
      candidates,
      generation,
    );
    this.assertEmbeddingCacheGenerationCurrent(generation);
    if (missing.length === 0) {
      return embeddings;
    }

    const missingChunks = missingCandidates.map((candidate) => ({
      ...candidate.chunk,
      sourceKey: JSON.stringify({
        source: candidate.source,
        path: candidate.entry.path,
        startLine: candidate.chunk.startLine,
        endLine: candidate.chunk.endLine,
      }),
    }));
    const batchResult = this.batch.enabled
      ? await runMemoryEmbeddingBatchTimeoutRetry({
          failureMode: generation.runtime?.batchFailureMode,
          onRetry: () =>
            log.warn(`memory embeddings: ${provider.id} batch timed out; retrying once`),
          run: () =>
            batchEmbed({
              agentId: this.agentId,
              chunks: resolveEmbeddingInputFormatVersion(provider.model)
                ? missingChunks.map((chunk) => ({
                    ...chunk,
                    ...formatEmbeddingModelInput(chunk, provider.model, "document"),
                    ...(chunk.embeddingInput
                      ? {
                          embeddingInput: formatEmbeddingModelInput(
                            chunk.embeddingInput,
                            provider.model,
                            "document",
                          ),
                        }
                      : {}),
                  }))
                : missingChunks,
              wait: this.batch.wait,
              concurrency: this.batch.concurrency,
              pollIntervalMs: this.batch.pollIntervalMs,
              timeoutMs: this.batch.timeoutMs,
              signal: this.batchAbortController.signal,
              submissionLifecycle: this.batchSubmissionOwner.createLifecycle({
                provider: { id: provider.id, model: provider.model },
                providerKey: generation.providerKey,
                dimensions: generation.embeddingDimensions ?? undefined,
              }),
              debug: (message, data) =>
                log.debug(message, { ...data, source, chunks: candidates.length, ...debugContext }),
            }),
        })
      : null;
    let batchEmbeddings: number[][];
    // Completion accounting is synchronous: concurrent batches cannot interleave updates.
    if (batchResult?.kind === "success") {
      if (this.batchFailure.count > 0) {
        log.debug("memory embeddings: batch recovered; resetting failure count");
      }
      // An in-flight success clears failures without re-enabling disabled batching.
      this.batchFailure = { count: 0 };
      if (!batchResult.value) {
        return this.embedChunksInBatches(candidates, generation, EMBEDDING_BATCH_MAX_TOKENS);
      }
      if (!Array.isArray(batchResult.value)) {
        log.warn("memory embeddings: recovering only missing Batch inputs with the same provider", {
          provider: provider.id,
          reason: batchResult.value.reason,
        });
        const recovered = await recoverMemoryEmbeddingBatch({
          partial: batchResult.value,
          count: missingCandidates.length,
          dimensions: generation.embeddingDimensions ?? provider.dimensions,
          assertCurrent: () => {
            this.batchAbortController.signal.throwIfAborted();
            this.assertEmbeddingCacheGenerationCurrent(generation);
            if (generation.cacheWritesInvalidated) {
              throw new Error("Memory embedding recovery generation invalidated");
            }
          },
          persist: async (indices, vectors) => {
            try {
              await this.persistGeneratedEmbeddings(
                indices.map((index) => missingCandidates[index]!),
                vectors,
                generation,
              );
            } catch (error) {
              generation.cacheWritesInvalidated = true;
              throw error;
            }
          },
          recover: (indices, onSuccess) => {
            const selected = indices.map((index) => missingCandidates[index]!);
            const positions = new Map(
              selected.map((candidate, position) => [candidate, indices[position]!]),
            );
            return this.embedChunksInBatches(
              selected,
              generation,
              EMBEDDING_BATCH_MAX_TOKENS,
              (items, vectors) =>
                onSuccess(
                  items.map((item) => positions.get(item)!),
                  vectors,
                ),
            );
          },
        });
        for (const [index, item] of missing.entries()) {
          embeddings[item] = recovered[index]!;
        }
        return embeddings;
      }
      batchEmbeddings = batchResult.value;
      await this.persistGeneratedEmbeddings(missingCandidates, batchEmbeddings, generation);
    } else {
      if (batchResult) {
        const message = formatErrorMessage(batchResult.error);
        if (
          generation.runtime?.batchFailureMode === "error" ||
          generation.runtime?.batchFailureMode === "fail-closed"
        ) {
          this.batchFailure = {
            count: this.batchFailure.count + batchResult.attempts,
            lastError: message,
            lastProvider: provider.id,
          };
          throw batchResult.error;
        }
        const forceDisable = isEmbeddingBatchUnavailableError(batchResult.error);
        if (this.batch.enabled) {
          const count =
            this.batchFailure.count +
            (forceDisable ? this.batchFailureLimit : batchResult.attempts);
          this.batchFailure = { count, lastError: message, lastProvider: provider.id };
          this.batch.enabled = !(forceDisable || count >= this.batchFailureLimit);
        }
        const suffix = this.batch.enabled ? "keeping batch enabled" : "disabling batch";
        log.warn(
          `memory embeddings: ${provider.id} batch failed (${this.batchFailure.count}/${this.batchFailureLimit}); ${suffix}; falling back to non-batch embeddings: ${message}`,
        );
      }
      batchEmbeddings = await this.embedChunksInBatches(
        missingCandidates,
        generation,
        EMBEDDING_BATCH_MAX_TOKENS,
      );
    }
    for (const [index, item] of missing.entries()) {
      embeddings[item] = batchEmbeddings[index] ?? [];
    }
    return embeddings;
  }

  private async writeChunks(
    { entry, source, chunks }: PreparedMemoryIndexEntry,
    generation: MemorySyncProviderGeneration | null,
    embeddings: number[][],
    vectorReady: boolean,
  ): Promise<void> {
    const database = this.database;
    const sourceDatabase = generation?.database ?? this.publishedDatabase;
    const session =
      source === "sessions"
        ? {
            agentId: this.agentId,
            sessionId: expectDefined(entry.sessionId, "memory index session identity"),
          }
        : undefined;
    await withMemoryWorkspaceLock(this.workspaceDir, async () => {
      const assertCurrent = () => {
        assertBoundedMemoryOperation(this.agentId);
        if (
          this.closed ||
          database.closed ||
          !database.db.isOpen ||
          this.database !== database ||
          sourceDatabase !== this.publishedDatabase ||
          sourceDatabase.closed ||
          !sourceDatabase.db.isOpen ||
          (generation && this.syncProviderGeneration !== generation)
        ) {
          throw new Error("Memory source owner changed before replacement");
        }
      };
      if (session) {
        // Forget shares this cross-process lock. The prepared predicate remains
        // current through native commit only while this lock and original owner
        // stay retained; a shadow's empty tombstone table cannot authorize it.
        const predicate = await sourceDatabase.read(
          { type: "session.current", input: session },
          assertCurrent,
        );
        assertCurrent();
        if (predicate === "forgotten") {
          this.markFailedFullReindexRetry({ memory: false, sessions: true });
          throw new Error(
            "A session was forgotten while memory indexing was running; retry the memory index.",
          );
        }
      }
      const createReplacement = (): MemorySourceIndexReplacement => ({
        entry: { path: entry.path, hash: entry.hash, mtimeMs: entry.mtimeMs, size: entry.size },
        chunks,
        embeddings,
        model: generation?.provider?.model ?? "fts-only",
        now: Date.now(),
        vectorReady,
        ...(session ? { source: "sessions", ...session } : { source: "memory" }),
      });
      const prepare = async (): Promise<boolean> => {
        if (source === "memory") {
          const current = await (this.memoryFiles?.inspectFile ?? buildFileEntry)(
            entry.absPath,
            this.workspaceDir,
            this.settings.multimodal,
          );
          if (current?.hash !== entry.hash) {
            this.dirty = true;
            log.debug("memory source changed while indexing; queued incremental retry", {
              path: entry.path,
            });
            return false;
          }
        }
        assertCurrent();
        return true;
      };
      const published = await database.replaceSource(createReplacement(), assertCurrent, prepare);
      if (!published) {
        return;
      }
      if (generation && database === generation.database) {
        if (published.beforeRevision !== generation.databaseRevision) {
          generation.cacheWritesInvalidated = true;
        }
        // Admission can resume another writer before this continuation runs.
        // Adopt only the revision captured by our committed publication.
        generation.databaseRevision = published.databaseRevision;
      }
      this.database.vectorDegradedWriteWarningShown = logMemoryVectorDegradedWrite({
        vectorEnabled: this.vector.enabled,
        vectorReady,
        chunkCount: chunks.length,
        warningShown: this.database.vectorDegradedWriteWarningShown,
        loadError: this.vector.loadError,
        warn: (message) => log.warn(message),
      });
    });
  }

  private async prepareIndexEntry(
    entry: MemoryIndexEntry,
    source: MemorySource,
    generation: MemorySyncProviderGeneration | null,
  ): Promise<PreparedMemoryIndexEntry | null> {
    assertBoundedMemoryOperation(this.agentId);
    if (
      boundedMemoryAdmissionActive(this.agentId) &&
      (source !== "memory" || entry.kind === "multimodal" || this.batch.enabled)
    ) {
      throw new MemoryAdmissionRefused();
    }
    const kind = entry.kind;
    const suppliedContent = entry.content;
    const prepare = async (): Promise<PreparedMemoryIndexEntry | null> => {
      if (kind === "multimodal") {
        const multimodalChunk: Awaited<
          ReturnType<NonNullable<typeof this.memoryFiles>["buildMultimodalChunk"]>
        > = await (this.memoryFiles?.buildMultimodalChunk ?? buildMultimodalChunkForIndexing)(
          entry,
        );
        if (!multimodalChunk) {
          this.dirty = true;
          await this.deleteIndexedFile(entry.path, source);
          return null;
        }
        const pathClassification = await resolveMemoryPathClassification({
          absolutePath: entry.absPath,
          source,
          workspaceDir: this.workspaceDir,
          readSource: this.memoryFiles ? multimodalChunk : undefined,
        });
        const chunk: IndexedMemoryChunk = {
          ...multimodalChunk.chunk,
          importance: null,
          triggers: null,
          projectKey: null,
        };
        chunk.provenance = resolveChunkProvenance(
          entry,
          source,
          chunk,
          pathClassification.originClass,
        );
        return {
          entry,
          source,
          chunks: [chunk],
          structuredInputBytes: multimodalChunk.structuredInputBytes,
        };
      }

      const read = await readMemoryIndexSource({
        absolutePath: entry.absPath,
        workspaceDir: this.workspaceDir,
        source,
        suppliedContent,
        memoryFiles: this.memoryFiles,
      });
      if (!read) {
        this.dirty = true;
        return null;
      }
      assertBoundedMemorySnapshot(this.agentId, entry.absPath, read.content, entry.hash);
      const cutoff = readSessionResetRecallCutoffMetadata(entry);
      const prepared = await prepareMemoryIndexInWorker({
        entry: {
          path: entry.path,
          mtimeMs: entry.mtimeMs,
          lineMap: entry.lineMap,
          lineProvenance: entry.lineProvenance,
        },
        source,
        content: read.content,
        pathClassification: read.pathClassification,
        chunking: this.settings.chunking,
        cutoffLine: cutoff.state === "valid" ? cutoff.cutoffLine : undefined,
        provider:
          generation?.kind === "semantic"
            ? { id: generation.provider.id, maxInputTokens: generation.provider.maxInputTokens }
            : undefined,
        hardMaxInputTokens: EMBEDDING_BATCH_MAX_TOKENS,
      });
      return {
        entry:
          prepared.contentHash !== undefined ? { ...entry, hash: prepared.contentHash } : entry,
        source,
        chunks: prepared.chunks,
      };
    };
    return source === "sessions" && kind !== "multimodal" && typeof suppliedContent === "string"
      ? withMemoryWorkspacePreparation(this.workspaceDir, prepare)
      : withMemoryWorkspaceLock(this.workspaceDir, prepare);
  }

  protected override async indexFiles(items: MemoryIndexWorkItem[]): Promise<void> {
    if (items.length === 0) {
      return;
    }
    this.beginSyncProviderGeneration();
    try {
      await this.indexFilesWithGeneration(items, this.syncProviderGeneration);
    } finally {
      this.endSyncProviderGeneration();
    }
  }

  private async indexFilesWithGeneration(
    items: MemoryIndexWorkItem[],
    generation: MemorySyncProviderGeneration | null,
  ): Promise<void> {
    const batchEmbed =
      generation?.kind === "semantic" ? resolveMemoryEmbeddingBatch(generation.runtime) : undefined;
    if (
      generation?.kind !== "semantic" ||
      !this.batch.enabled ||
      !batchEmbed ||
      generation.runtime?.sourceWideBatchEmbed !== true
    ) {
      await runWithConcurrency(
        items.map(
          (item) => async () =>
            await this.indexFileWithGeneration(item.entry, item.source, generation),
        ),
        this.getIndexConcurrency(),
      );
      return;
    }

    const itemSourceCounts = countBatchSources(items);
    log.debug(
      `memory embeddings: source-wide batch prepare files=${items.length} sources=${formatBatchSourceCounts(
        itemSourceCounts,
      )} maxFiles=${SOURCE_WIDE_BATCH_MAX_FILES} maxRequests=${SOURCE_WIDE_BATCH_MAX_REQUESTS}`,
      {
        files: items.length,
        sources: itemSourceCounts,
        maxFiles: SOURCE_WIDE_BATCH_MAX_FILES,
        maxRequests: SOURCE_WIDE_BATCH_MAX_REQUESTS,
      },
    );

    let prepared: PreparedMemoryIndexEntry[] = [];
    let preparedRequestCount = 0;
    let sourceWideBatchGroup = 0;
    const flushPrepared = async (reason: "max-files" | "max-requests" | "end") => {
      if (prepared.length === 0) {
        return;
      }
      const current = prepared;
      const candidates = current.flatMap((item) =>
        item.chunks.map((chunk) => ({ chunk, entry: item.entry, source: item.source })),
      );
      const chunkCount = candidates.length;
      const sourceCounts = countBatchSources(current);
      const source = Object.keys(sourceCounts).toSorted().join("+") || "unknown";
      sourceWideBatchGroup += 1;
      const chunkBatches = chunkItems(candidates, SOURCE_WIDE_BATCH_MAX_REQUESTS);
      log.debug(
        `memory embeddings: source-wide batch submit group=${sourceWideBatchGroup} source=${source} files=${current.length} chunks=${chunkCount} requests=${chunkBatches.length} sources=${formatBatchSourceCounts(
          sourceCounts,
        )} reason=${reason}`,
        {
          source,
          files: current.length,
          chunks: chunkCount,
          requests: chunkBatches.length,
          sources: sourceCounts,
          group: sourceWideBatchGroup,
          reason,
          maxFiles: SOURCE_WIDE_BATCH_MAX_FILES,
          maxRequests: SOURCE_WIDE_BATCH_MAX_REQUESTS,
        },
      );
      const embeddings: number[][] = [];
      for (let requestIndex = 0; requestIndex < chunkBatches.length; requestIndex += 1) {
        const chunkBatch = chunkBatches[requestIndex] ?? [];
        embeddings.push(
          ...(await this.embedChunksWithBatch(chunkBatch, source, generation, {
            sourceWideFiles: current.length,
            sourceWideSources: sourceCounts,
            sourceWideBatchGroup,
            sourceWideRequestGroup: requestIndex + 1,
            sourceWideRequestGroups: chunkBatches.length,
          })),
        );
      }
      candidates.length = 0;
      chunkBatches.length = 0;
      const sample = embeddings.find((embedding) => embedding.length > 0);
      const vectorReady = sample ? await this.ensureVectorReady(sample.length) : false;
      let offset = 0;
      for (const item of current) {
        const fileEmbeddings = embeddings.slice(offset, offset + item.chunks.length);
        await this.writeChunks(item, generation, fileEmbeddings, vectorReady);
        // Publication has settled; later files must not retain completed vectors.
        // oxlint-disable-next-line unicorn/no-array-fill-with-reference-type -- Completed slots are never read or mutated.
        embeddings.fill([], offset, offset + item.chunks.length);
        offset += item.chunks.length;
      }
      prepared = [];
      preparedRequestCount = 0;
    };

    for (const item of items) {
      if (item.entry.kind === "multimodal") {
        await this.indexFileWithGeneration(item.entry, item.source, generation);
        continue;
      }
      const preparedEntry = await this.prepareIndexEntry(item.entry, item.source, generation);
      if (!preparedEntry) {
        continue;
      }
      const nextWouldExceedRequests =
        preparedRequestCount + preparedEntry.chunks.length > SOURCE_WIDE_BATCH_MAX_REQUESTS;
      if (prepared.length > 0 && nextWouldExceedRequests) {
        await flushPrepared("max-requests");
      }
      prepared.push(preparedEntry);
      preparedRequestCount += preparedEntry.chunks.length;
      if (
        prepared.length >= SOURCE_WIDE_BATCH_MAX_FILES ||
        preparedRequestCount >= SOURCE_WIDE_BATCH_MAX_REQUESTS
      ) {
        await flushPrepared(
          prepared.length >= SOURCE_WIDE_BATCH_MAX_FILES ? "max-files" : "max-requests",
        );
      }
    }
    await flushPrepared("end");
  }

  protected async indexFile(entry: MemoryIndexEntry, source: MemorySource): Promise<void> {
    this.beginSyncProviderGeneration();
    try {
      await this.indexFileWithGeneration(entry, source, this.syncProviderGeneration);
    } finally {
      this.endSyncProviderGeneration();
    }
  }

  private async indexFileWithGeneration(
    entry: MemoryIndexEntry,
    source: MemorySource,
    generation: MemorySyncProviderGeneration | null,
  ): Promise<void> {
    // Multimodal files require an embedding provider; skip in FTS-only mode.
    if (generation?.kind !== "semantic" && entry.kind === "multimodal") {
      return;
    }
    const prepared = await this.prepareIndexEntry(entry, source, generation);
    if (!prepared) {
      return;
    }
    if (generation?.kind !== "semantic") {
      await this.writeChunks(prepared, generation, [], false);
      return;
    }

    let embeddings: number[][];
    try {
      const candidates = prepared.chunks.map((chunk) => ({
        chunk,
        entry: prepared.entry,
        source: prepared.source,
      }));
      embeddings = this.batch.enabled
        ? await this.embedChunksWithBatch(candidates, source, generation)
        : await this.embedChunksInBatches(candidates, generation, EMBEDDING_BATCH_MAX_TOKENS);
    } catch (err) {
      const message = formatErrorMessage(err);
      if (
        entry.kind === "multimodal" &&
        /(413|payload too large|request too large|input too large|too many tokens|input limit|request size)/i.test(
          message,
        )
      ) {
        log.warn("memory embeddings: skipping multimodal file rejected as too large", {
          path: entry.path,
          bytes: prepared.structuredInputBytes,
          provider: generation.provider.id,
          model: generation.provider.model,
          error: message,
        });
        await this.writeChunks({ ...prepared, chunks: [] }, generation, [], false);
        return;
      }
      throw err;
    }
    const sample = embeddings.find((embedding) => embedding.length > 0);
    const vectorReady = sample ? await this.ensureVectorReady(sample.length) : false;
    await this.writeChunks(prepared, generation, embeddings, vectorReady);
  }
}
/* oxlint-disable max-lines -- TODO: split this grandfathered oversized file. */
