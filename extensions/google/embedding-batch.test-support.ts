import { vi } from "vitest";
import { runGeminiEmbeddingBatches } from "./embedding-batch.js";
import type { GeminiEmbeddingClient } from "./embedding-provider.js";

export function fetchInputUrl(input: RequestInfo | URL): string {
  if (typeof input === "string") {
    return input;
  }
  if (input instanceof URL) {
    return input.href;
  }
  return input.url;
}

export function jsonResponse(value: unknown, status = 200): Response {
  return Response.json(value, { status });
}

export function makeGeminiClient(
  baseUrl = "https://generativelanguage.googleapis.com/v1beta",
): GeminiEmbeddingClient {
  return {
    baseUrl,
    model: "gemini-embedding-001",
    modelPath: "models/gemini-embedding-001",
    headers: { "x-goog-api-client": "test-client" },
    apiKeys: ["test-key"],
    ssrfPolicy: undefined,
  };
}

type GeminiBatchRequest = Parameters<typeof runGeminiEmbeddingBatches>[0]["requests"][number];
type SubmissionLifecycle = NonNullable<
  Parameters<typeof runGeminiEmbeddingBatches>[0]["submissionLifecycle"]
>;

export function batchRequest(customId: string, text: string): GeminiBatchRequest {
  return {
    custom_id: customId,
    chunkHash: customId,
    request: {
      model: "models/gemini-embedding-001",
      content: { parts: [{ text }] },
      taskType: "RETRIEVAL_DOCUMENT",
    },
  };
}

export function singleRequest(): GeminiBatchRequest[] {
  return [batchRequest("r0", "hello")];
}

export type BatchStage = "upload" | "create" | "status" | "download";

export function batchStageForUrl(url: string): BatchStage {
  if (url.includes("/upload/")) {
    return "upload";
  }
  if (url.includes(":asyncBatchEmbedContent")) {
    return "create";
  }
  if (url.includes("/batches/")) {
    return "status";
  }
  if (url.includes(":download")) {
    return "download";
  }
  throw new Error(`unexpected Gemini batch URL: ${url}`);
}

export function defaultBatchResponse(stage: BatchStage): Response {
  switch (stage) {
    case "upload":
      return Response.json({ file: { name: "files/f-ok" } });
    case "create":
      return Response.json({
        name: "batches/b-0",
        done: false,
        metadata: { state: "BATCH_STATE_PENDING" },
      });
    case "status":
      return Response.json({
        name: "batches/b-0",
        done: true,
        metadata: { state: "BATCH_STATE_SUCCEEDED" },
        response: { responsesFile: "files/out-0" },
      });
    case "download":
      return new Response(
        JSON.stringify({ key: "r0", response: { embedding: { values: [1, 0, 0] } } }),
        { status: 200 },
      );
  }
  throw new Error("unexpected Gemini batch stage");
}

export function stubBatchFetch(
  override?: (stage: BatchStage, url: string, init?: RequestInit) => Response | undefined,
): ReturnType<typeof vi.fn> {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = fetchInputUrl(input);
    const stage = batchStageForUrl(url);
    return override?.(stage, url, init) ?? defaultBatchResponse(stage);
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

export function runBatch(
  requests = singleRequest(),
  gemini = makeGeminiClient(),
  submissionLifecycle?: SubmissionLifecycle,
): Promise<Map<string, number[]>> {
  return runGeminiEmbeddingBatches({
    gemini,
    agentId: "main",
    requests,
    wait: true,
    concurrency: 1,
    pollIntervalMs: 1,
    timeoutMs: 5_000,
    ...(submissionLifecycle ? { submissionLifecycle } : {}),
  });
}

export function createSubmissionLifecycle() {
  return {
    resumeAccepted: vi.fn<NonNullable<SubmissionLifecycle["resumeAccepted"]>>(async () => null),
    started: vi.fn<SubmissionLifecycle["started"]>(),
    accepted: vi.fn<SubmissionLifecycle["accepted"]>(),
    rejected: vi.fn<SubmissionLifecycle["rejected"]>(),
  } satisfies SubmissionLifecycle;
}

export async function captureRejection(promise: Promise<unknown>): Promise<unknown> {
  return await promise.then(
    () => undefined,
    (error: unknown) => error,
  );
}

export function makeOversizedResponse(status = 200): {
  response: Response;
  getReadCount: () => number;
  wasCanceled: () => boolean;
} {
  const chunkSize = 1024 * 1024;
  const chunkCount = 20; // 20 MiB — over 16 MiB cap
  let readCount = 0;
  let canceled = false;
  return {
    response: new Response(
      new ReadableStream<Uint8Array>({
        pull(controller) {
          if (readCount >= chunkCount) {
            controller.close();
            return;
          }
          readCount += 1;
          controller.enqueue(new Uint8Array(chunkSize));
        },
        cancel() {
          canceled = true;
        },
      }),
      { status, headers: { "Content-Type": "application/json" } },
    ),
    getReadCount: () => readCount,
    wasCanceled: () => canceled,
  };
}
