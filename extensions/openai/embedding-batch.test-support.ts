import type { runOpenAiEmbeddingBatches } from "./embedding-batch.js";

export function singleRequestBatchParams(
  fetchImpl: typeof fetch,
  pollIntervalMs: number,
  timeoutMs: number,
): Parameters<typeof runOpenAiEmbeddingBatches>[0] {
  return {
    openAi: {
      baseUrl: "https://openai-compatible.example/v1",
      headers: { Authorization: "Bearer test" },
      model: "text-embedding-3-small",
      fetchImpl,
    },
    agentId: "main",
    requests: [
      {
        custom_id: "0",
        method: "POST",
        url: "/v1/embeddings",
        body: { model: "text-embedding-3-small", input: "payload" },
      },
    ],
    wait: true,
    concurrency: 1,
    pollIntervalMs,
    timeoutMs,
  };
}

export function fetchInputUrl(input: RequestInfo | URL): string {
  if (typeof input === "string") {
    return input;
  }
  if (input instanceof URL) {
    return input.href;
  }
  return input.url;
}
