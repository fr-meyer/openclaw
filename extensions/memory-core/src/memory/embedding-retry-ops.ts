import { randomUUID } from "node:crypto";
import { formatErrorMessage } from "openclaw/plugin-sdk/error-runtime";
import {
  formatEmbeddingModelInput,
  type EmbeddingInput,
  type MemoryEmbeddingProviderRuntime,
} from "openclaw/plugin-sdk/memory-core-host-engine-embeddings";
import { createSubsystemLogger } from "openclaw/plugin-sdk/memory-core-host-engine-foundation";
import {
  createMemorySearchDeadlineControl,
  MEMORY_SEARCH_DEADLINE_CONTROL,
  type MemorySearchDeadlineControl,
} from "openclaw/plugin-sdk/memory-core-host-engine-storage";
import { MAX_TIMER_TIMEOUT_MS, resolveTimerTimeoutMs } from "openclaw/plugin-sdk/number-runtime";
import { sleepWithAbort } from "openclaw/plugin-sdk/runtime-env";
import {
  boundedMemoryAdmissionActive,
  MemoryAdmissionRefused,
  reserveBoundedMemoryRoot,
  withBoundedMemoryWork,
} from "./bounded-admission.js";
import type { EmbeddingProvider } from "./embeddings.js";
import type { MemoryEmbeddingCacheCandidate } from "./manager-embedding-cache-ops.js";
import { createMemoryEmbeddingOperationError } from "./manager-embedding-errors.js";
import {
  runMemoryEmbeddingBatchRetryWithSplit,
  runMemoryEmbeddingRetryLoop,
} from "./manager-embedding-policy.js";
import { MemoryManagerProviderUseOps } from "./manager-provider-use-ops.js";
import type { MemorySemanticProviderGeneration } from "./manager-sync-ops.js";
import { runEmbeddingOperationWithTimeout } from "./paused-deadline.js";

export const embeddingOperationLog = createSubsystemLogger("memory");
const log = embeddingOperationLog;

const EMBEDDING_TIMEOUTS_MS = {
  query: { remote: 60_000, local: 5 * 60_000 },
  batch: { remote: 2 * 60_000, local: 10 * 60_000 },
};
export abstract class MemoryManagerEmbeddingRetryOps extends MemoryManagerProviderUseOps {
  protected abstract markLocalEmbeddingProviderDegraded(err: unknown): void;
  protected override async embedBatchWithRetry(
    inputs: Array<string | EmbeddingInput>,
    generation?: MemorySemanticProviderGeneration,
    cacheCandidates?: MemoryEmbeddingCacheCandidate[],
  ): Promise<number[][]> {
    if (inputs.length === 0) {
      return [];
    }
    const provider = generation?.provider ?? this.provider;
    if (!provider) {
      throw new Error("Cannot embed batch in FTS-only mode (no embedding provider)");
    }
    const structured = inputs.some((input) => typeof input !== "string");
    const label = structured ? "structured batch" : "batch";
    const requestItems = inputs.map((input, index) => ({
      input,
      cacheCandidate: cacheCandidates?.[index],
    }));
    try {
      return await this.withProviderUse(
        provider,
        async () =>
          await runMemoryEmbeddingBatchRetryWithSplit({
            items: requestItems,
            run: async (batchItems) => {
              if (
                boundedMemoryAdmissionActive(this.agentId) &&
                batchItems.some((item) => typeof item.input !== "string")
              ) {
                throw new MemoryAdmissionRefused();
              }
              await reserveBoundedMemoryRoot(
                this.agentId,
                randomUUID(),
                batchItems.map((item) =>
                  typeof item.input === "string" ? item.input : JSON.stringify(item.input),
                ),
                provider,
                generation?.providerKey ?? this.providerKey,
              );
              const timeoutMs = this.resolveEmbeddingTimeout(
                "batch",
                provider,
                generation?.runtime,
              );
              log.debug(`memory embeddings: ${label} start`, {
                provider: provider.id,
                items: batchItems.length,
                timeoutMs,
              });
              const result = await runEmbeddingOperationWithTimeout({
                timeoutMs,
                message: `memory embeddings batch timed out after ${Math.round(timeoutMs / 1000)}s`,
                run: async (signal) =>
                  await withBoundedMemoryWork(this.agentId, () =>
                    provider.embedBatch(
                      batchItems.map((item) =>
                        formatEmbeddingModelInput(item.input, provider.model, "document"),
                      ),
                      { signal, inputType: "document" },
                    ),
                  ),
              });
              if (!structured) {
                log.debug("memory embeddings: batch completed", {
                  provider: provider.id,
                  items: batchItems.length,
                });
              }
              return result;
            },
            onSuccess: async (batchItems, batchEmbeddings) => {
              if (!generation) {
                return;
              }
              const batchCandidates = batchItems.flatMap((item) =>
                item.cacheCandidate ? [item.cacheCandidate] : [],
              );
              if (batchCandidates.length !== batchItems.length) {
                return;
              }
              await this.persistGeneratedEmbeddings(batchCandidates, batchEmbeddings, generation);
            },
            waitForRetry: async (delayMs) => {
              await this.waitForEmbeddingRetry(
                delayMs,
                structured ? "retrying structured batch" : "retrying",
              );
            },
            onSplit: ({ itemCount, splitAt }) => {
              log.warn(
                `memory embeddings ${label} failed; splitting ${itemCount} inputs into ${splitAt} + ${itemCount - splitAt}`,
              );
            },
          }),
      );
    } catch (err) {
      if (!structured) {
        log.debug("memory embeddings: batch failed", {
          provider: provider.id,
          error: formatErrorMessage(err),
        });
      }
      this.markLocalEmbeddingProviderDegraded(err);
      throw createMemoryEmbeddingOperationError({
        operation: structured ? "structured-batch" : "batch",
        providerId: provider.id,
        cause: err,
      });
    }
  }

  private async waitForEmbeddingRetry(
    delayMs: number,
    action: string,
    signal?: AbortSignal,
  ): Promise<void> {
    log.warn(`memory embeddings retryable error; ${action} in ${delayMs}ms`);
    await sleepWithAbort(delayMs, signal);
  }

  private resolveEmbeddingTimeout(
    kind: "query" | "batch",
    provider: EmbeddingProvider | null = this.provider,
    providerRuntime: MemoryEmbeddingProviderRuntime | undefined = this.providerRuntime,
  ): number {
    const configuredTimeoutSeconds = this.settings.sync.embeddingBatchTimeoutSeconds;
    if (
      kind === "batch" &&
      typeof configuredTimeoutSeconds === "number" &&
      configuredTimeoutSeconds > 0
    ) {
      return resolveTimerTimeoutMs(configuredTimeoutSeconds * 1000, MAX_TIMER_TIMEOUT_MS);
    }
    const defaults = EMBEDDING_TIMEOUTS_MS[kind];
    const runtimeTimeoutMs =
      kind === "query"
        ? providerRuntime?.inlineQueryTimeoutMs
        : providerRuntime?.inlineBatchTimeoutMs;
    return typeof runtimeTimeoutMs === "number" && runtimeTimeoutMs > 0
      ? resolveTimerTimeoutMs(runtimeTimeoutMs, defaults.remote)
      : defaults[provider?.id === "local" ? "local" : "remote"];
  }

  protected async probeEmbeddingProvider(
    provider: EmbeddingProvider,
    providerRuntime: MemoryEmbeddingProviderRuntime | undefined,
  ): Promise<void> {
    const timeoutMs = this.resolveEmbeddingTimeout("query", provider, providerRuntime);
    const deadlineControl = createMemorySearchDeadlineControl();
    try {
      await runEmbeddingOperationWithTimeout({
        timeoutMs,
        message: `memory embedding probe timed out after ${Math.round(timeoutMs / 1000)}s`,
        deadlineControl,
        run: (signal) =>
          this.withProviderUse(provider, () =>
            provider.embed(formatEmbeddingModelInput("ping", provider.model, "query"), {
              signal,
              inputType: "query",
              [MEMORY_SEARCH_DEADLINE_CONTROL]: deadlineControl,
            }),
          ),
      });
    } catch (error) {
      if (provider === this.provider) {
        this.markLocalEmbeddingProviderDegraded(error);
      }
      throw error;
    }
  }

  protected async embedQueryWithRetry(
    text: string,
    signal?: AbortSignal,
    providerOverride?: EmbeddingProvider,
    providerRuntimeOverride?: MemoryEmbeddingProviderRuntime,
    deadlineControl?: MemorySearchDeadlineControl,
  ): Promise<number[]> {
    const provider = providerOverride ?? this.provider;
    const providerRuntime = providerOverride ? providerRuntimeOverride : this.providerRuntime;
    if (!provider) {
      throw new Error("Cannot embed query in FTS-only mode (no embedding provider)");
    }
    try {
      return await this.withProviderUse(
        provider,
        async () =>
          await runMemoryEmbeddingRetryLoop({
            profile: "query",
            run: async () => {
              signal?.throwIfAborted();
              const timeoutMs = this.resolveEmbeddingTimeout("query", provider, providerRuntime);
              log.debug("memory embeddings: query start", { provider: provider.id, timeoutMs });
              return await runEmbeddingOperationWithTimeout({
                timeoutMs,
                message: `memory embeddings query timed out after ${Math.round(timeoutMs / 1000)}s`,
                signal,
                deadlineControl,
                run: async (opSignal) =>
                  await provider.embed(formatEmbeddingModelInput(text, provider.model, "query"), {
                    signal: opSignal,
                    inputType: "query",
                    ...(deadlineControl
                      ? { [MEMORY_SEARCH_DEADLINE_CONTROL]: deadlineControl }
                      : {}),
                  }),
              });
            },
            signal,
            waitForRetry: async (delayMs) => {
              await this.waitForEmbeddingRetry(delayMs, "retrying query", signal);
            },
          }),
      );
    } catch (err) {
      throw createMemoryEmbeddingOperationError({
        operation: "query",
        providerId: provider.id,
        cause: err,
      });
    }
  }

  protected async withTimeout<T>(
    promise: Promise<T>,
    timeoutMs: number,
    message: string,
  ): Promise<T> {
    return await runEmbeddingOperationWithTimeout({ timeoutMs, message, run: () => promise });
  }
}
