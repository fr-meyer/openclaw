import { formatErrorMessage } from "openclaw/plugin-sdk/error-runtime";
import {
  formatEmbeddingModelInput,
  isEmbeddingBatchUnavailableError,
  resolveEmbeddingInputFormatVersion,
} from "openclaw/plugin-sdk/memory-core-host-engine-embeddings";
import { createSubsystemLogger } from "openclaw/plugin-sdk/memory-core-host-engine-foundation";
import { recoverMemoryEmbeddingBatch } from "./manager-embedding-batch-recovery.js";
import {
  MemoryManagerEmbeddingCacheOps,
  type MemoryEmbeddingCacheCandidate,
} from "./manager-embedding-cache-ops.js";
import {
  resolveMemoryEmbeddingBatch,
  runMemoryEmbeddingBatchTimeoutRetry,
} from "./manager-embedding-policy.js";
import type { MemorySemanticProviderGeneration } from "./manager-sync-ops.js";

export const EMBEDDING_BATCH_MAX_TOKENS = 8000;
const log = createSubsystemLogger("memory");

/** One asynchronous Batch owner, including selective recovery and failure accounting. */
export abstract class MemoryManagerEmbeddingBatchOps extends MemoryManagerEmbeddingCacheOps {
  protected readonly batchFailureLimit = 2;
  protected batchFailure: { count: number; lastError?: string; lastProvider?: string } = {
    count: 0,
  };
  protected async embedChunksWithBatch(
    candidates: MemoryEmbeddingCacheCandidate[],
    source: string,
    generation: MemorySemanticProviderGeneration,
    debugContext: Record<string, unknown> = {},
  ): Promise<number[][]> {
    const { provider, runtime } = generation;
    const batchEmbed = resolveMemoryEmbeddingBatch(runtime);
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

    const missingChunks = missingCandidates.map((candidate) => candidate.chunk);
    const batchResult = this.batch.enabled
      ? await runMemoryEmbeddingBatchTimeoutRetry({
          failureMode: runtime?.batchFailureMode,
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
          assertCurrent: () => this.assertEmbeddingRecoveryCurrent(generation),
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
}
