import {
  isMissingEmbeddingApiKeyError,
  mapBatchEmbeddingsByIndex,
  sanitizeEmbeddingCacheHeaders,
  type MemoryEmbeddingProviderAdapter,
} from "openclaw/plugin-sdk/embedding-provider-adapter";
import type { EmbeddingBatchOptions } from "openclaw/plugin-sdk/embedding-provider-runtime-contract";
import { OPENAI_DEFAULT_EMBEDDING_MODEL } from "./default-models.js";

function resolveEmbeddingCacheExcludedHeaders(providerId: string, baseUrl: string): string[] {
  const excludedHeaders = ["authorization", "x-api-key", "api-key"];
  if (providerId !== "openai") {
    return excludedHeaders;
  }
  if (URL.parse(baseUrl)?.hostname.toLowerCase().replace(/\.+$/, "") === "api.openai.com") {
    // Native attribution changes on every upgrade; cache identity must describe embeddings,
    // not the OpenClaw build that requested them.
    excludedHeaders.push("version", "user-agent");
  }
  return excludedHeaders;
}

export const openAiMemoryEmbeddingProviderAdapter: MemoryEmbeddingProviderAdapter = {
  id: "openai",
  defaultModel: OPENAI_DEFAULT_EMBEDDING_MODEL,
  transport: "remote",
  authProviderId: "openai",
  // OpenAI may take the full 24-hour completion window; allow an extra hour for settlement.
  batchTimeoutMinutes: 1500,
  autoSelectPriority: 20,
  allowExplicitWhenConfiguredAuto: true,
  shouldContinueAutoSelection: isMissingEmbeddingApiKeyError,
  create: async (options) => {
    const resolvedProvider = options.provider ?? "openai";
    const { createOpenAiEmbeddingProvider } = await import("./embedding-provider.js");
    const { provider, client } = await createOpenAiEmbeddingProvider({
      ...options,
      provider: resolvedProvider,
      fallback: "none",
    });
    const batchEmbed = async (batch: EmbeddingBatchOptions): Promise<number[][]> => {
      const inputType = client.documentInputType ?? client.inputType;
      const { OPENAI_BATCH_ENDPOINT, runOpenAiEmbeddingBatches } =
        await import("./embedding-batch.js");
      const byCustomId = await runOpenAiEmbeddingBatches({
        openAi: client,
        agentId: batch.agentId,
        requests: batch.chunks.map((chunk, index) => ({
          custom_id: String(index),
          method: "POST",
          url: OPENAI_BATCH_ENDPOINT,
          body: {
            model: client.model,
            input: chunk.text,
            ...(typeof client.outputDimensionality === "number"
              ? { dimensions: client.outputDimensionality }
              : {}),
            ...(inputType ? { input_type: inputType } : {}),
          },
        })),
        wait: batch.wait,
        concurrency: batch.concurrency,
        pollIntervalMs: batch.pollIntervalMs,
        timeoutMs: batch.timeoutMs,
        debug: batch.debug,
      });
      return mapBatchEmbeddingsByIndex(byCustomId, batch.chunks.length);
    };
    return {
      provider,
      runtime: {
        id: "openai",
        sourceWideBatchEmbed: true,
        batchFailureMode: "fail-closed",
        cacheKeyData: {
          provider: resolvedProvider,
          baseUrl: client.baseUrl,
          model: client.model,
          outputDimensionality: client.outputDimensionality,
          documentInputType: client.documentInputType ?? client.inputType,
          headers: sanitizeEmbeddingCacheHeaders(
            client.headers,
            resolveEmbeddingCacheExcludedHeaders(resolvedProvider, client.baseUrl),
          ),
        },
        batchEmbed,
        batchEmbedPartial: async (batch) => {
          try {
            return await batchEmbed(batch);
          } catch (error) {
            const { OpenAiEmbeddingBatchError } = await import("./embedding-batch.js");
            if (!(error instanceof OpenAiEmbeddingBatchError)) {
              throw error;
            }
            return {
              kind: "partial",
              embeddings: batch.chunks.map(
                (_, index) => error.embeddings.get(String(index)) ?? null,
              ),
              reason: error.message,
            };
          }
        },
      },
    };
  },
};
