import { createHash } from "node:crypto";
import {
  isMissingEmbeddingApiKeyError,
  mapBatchEmbeddingsByIndex,
  sanitizeEmbeddingCacheHeaders,
  type MemoryEmbeddingProviderAdapter,
} from "openclaw/plugin-sdk/embedding-provider-adapter";
import type { EmbeddingProviderBatchRuntime } from "openclaw/plugin-sdk/embedding-provider-runtime-contract";
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
    // Match the synchronous provider's document request fields, not its query fields.
    const documentInput = client.documentInputType ?? client.inputType;
    const documentInputType = typeof documentInput === "string" && documentInput.trim().length > 0
      ? documentInput.trim() : undefined;
    const documentBody = (text: string) => ({
      model: client.model,
      input: text,
      ...(typeof client.outputDimensionality === "number"
        ? { dimensions: client.outputDimensionality } : {}),
      ...(documentInputType ? { input_type: documentInputType } : {}),
    });
    const batchEmbed: EmbeddingProviderBatchRuntime["batchEmbed"] = async (batch) => {
      // Credentials do not grant journal custody. Refuse only when batching is invoked.
      if (!client.batchJournal) {
        throw new Error("OpenAI Batch requires controller-provisioned journal context");
      }
      const { OPENAI_BATCH_ENDPOINT, runOpenAiEmbeddingBatches } =
        await import("./embedding-batch.js");
      const byCustomId = await runOpenAiEmbeddingBatches({
        openAi: client,
        agentId: batch.agentId,
        journal: client.batchJournal,
        requests: batch.chunks.map((chunk, index) => ({
          custom_id: String(index), method: "POST", url: OPENAI_BATCH_ENDPOINT,
          body: documentBody(chunk.text),
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
          documentInputType,
          headers: sanitizeEmbeddingCacheHeaders(
            client.headers,
            resolveEmbeddingCacheExcludedHeaders(resolvedProvider, client.baseUrl),
          ),
        },
        withCandidateBatch: (admission, run) => {
          // Capture primitives before dynamic import or returning to the caller.
          const accepted = {
            agentId: admission.agentId,
            journal: { path: admission.journal.path, migrationId: admission.journal.migrationId,
              sourceRevision: admission.journal.sourceRevision, accountId: admission.journal.accountId,
              route: admission.journal.route },
            expected: { model: admission.expected.model, dimensions: admission.expected.dimensions },
          };
          const operation = (async () => {
            const { withOpenAiBatchController } = await import("./embedding-batch-controller.js");
            return await withOpenAiBatchController({ client, agentId: accepted.agentId,
              journal: accepted.journal, expected: accepted.expected }, async (controller) => {
              let active = true;
              const pending = new Set<Promise<number[][]>>();
              const failures: unknown[] = [];
              const track = (work: Promise<number[][]>) => {
                pending.add(work);
                void work.then(() => { pending.delete(work); }, (error) => {
                  pending.delete(work); if (!failures.includes(error)) { failures.push(error); }
                });
                return work;
              };
              let result: Awaited<ReturnType<typeof run>> | undefined;
              try {
                result = await run((batch) => {
                  try {
                    if (!active || batch.agentId !== accepted.agentId) {
                      throw new Error("Candidate Batch agent/custody changed after admission");
                    }
                    const chunks = structuredClone(batch.chunks);
                    const execution = { wait: batch.wait, concurrency: batch.concurrency,
                      pollIntervalMs: batch.pollIntervalMs, timeoutMs: batch.timeoutMs, debug: batch.debug };
                    const requests = chunks.map((chunk) => {
                      if (!chunk.sourceKey || !chunk.hash) {
                        throw new Error("Candidate Batch requires stable native source/chunk identity");
                      }
                      const body = documentBody(chunk.text);
                      const custom_id = createHash("sha256").update(JSON.stringify({
                        source: chunk.sourceKey, chunk: chunk.hash, body,
                      })).digest("hex");
                      return { custom_id, method: "POST" as const, url: "/v1/embeddings" as const, body };
                    });
                    const ids = requests.map((request) => request.custom_id);
                    const unique = [...new Map(requests.map((request) => [request.custom_id, request])).values()];
                    const work = (async () => {
                      const vectors = await controller.runBatch(unique, execution);
                      return ids.map((id) => {
                        const vector = vectors.get(id);
                        if (!vector) { throw new Error("Candidate Batch output identity missing"); }
                        return vector;
                      });
                    })();
                    return track(work); // Includes mapping; never an unobserved async wrapper.
                  } catch (error) { return track(Promise.reject(error)); }
                }, { ...accepted, identity: controller.manifest.identity });
              } catch (error) {
                const index = failures.indexOf(error); if (index >= 0) { failures.splice(index, 1); }
                failures.unshift(error);
              } finally {
                active = false;
                while (pending.size) { await Promise.allSettled([...pending]); }
              }
              if (failures.length === 1) { throw failures[0]; }
              if (failures.length > 1) { throw new AggregateError(failures,
                "Candidate adapter callback/mapping failed", { cause: failures[0] }); }
              return result!;
            });
          })();
          void operation.catch(() => {});
          return operation;
        },
        batchEmbed,
        batchEmbedPartial: async (batch) => {
          try {
            return await batchEmbed(batch);
          } catch (error) {
            const { OpenAiEmbeddingBatchError } = await import("./embedding-batch.js");
            if (!(error instanceof OpenAiEmbeddingBatchError) || error.recoveryBlocked) {
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
