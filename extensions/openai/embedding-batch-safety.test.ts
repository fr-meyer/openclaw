import { createDeferred } from "openclaw/plugin-sdk/concurrency-runtime";
import { afterEach, describe, expect, it, vi } from "vitest";
import { runOpenAiEmbeddingBatches } from "./embedding-batch.js";
import { fetchInputUrl, singleRequestBatchParams } from "./embedding-batch.test-support.js";

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe("OpenAI native batch submission safety", () => {
  it.each(["500", "lost response", "timeout", "missing id", "redirect"])(
    "does not repeat create after %s and reports its uploaded input",
    async (failure) => {
      vi.useFakeTimers();
      const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        if (fetchInputUrl(input).endsWith("/files") && init?.method === "POST") {
          return Response.json({ id: "input-uncertain" });
        }
        if (failure === "redirect") {
          return new Response(null, { status: 307, headers: { Location: "/v1/batches" } });
        }
        if (failure === "500") {
          return Response.json({ error: { message: "upstream unavailable" } }, { status: 500 });
        }
        if (failure === "missing id") {
          return Response.json({ status: "validating" });
        }
        throw new Error(failure === "timeout" ? "request timed out" : "fetch failed");
      });
      const pending = runOpenAiEmbeddingBatches(singleRequestBatchParams(fetchImpl, 1, 1000));
      const outcome = pending.catch((error: unknown) => error);
      await vi.runAllTimersAsync();
      expect(await outcome).toMatchObject({
        message: expect.stringMatching(/submission outcome unknown.*input-uncertain/i),
      });
      expect(
        fetchImpl.mock.calls.filter(
          ([input, init]) => fetchInputUrl(input).endsWith("/batches") && init?.method === "POST",
        ),
      ).toHaveLength(1);
    },
  );

  it("polls the accepted job beyond one hour without another create", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(0);
    const statusIds: string[] = [];
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = fetchInputUrl(input);
      if (url.endsWith("/files") && init?.method === "POST") {
        return Response.json({ id: "input-long" });
      }
      if (url.endsWith("/batches") && init?.method === "POST") {
        return Response.json({ id: "batch-long", status: "in_progress" });
      }
      if (url.endsWith("/batches/batch-long")) {
        statusIds.push(url);
        if (statusIds.length === 1) {
          return Response.json({ error: { message: "temporary" } }, { status: 503 });
        }
        return Response.json({
          id: "batch-long",
          status: "completed",
          output_file_id: "output-long",
        });
      }
      return new Response(
        JSON.stringify({
          custom_id: "0",
          response: { status_code: 200, body: { data: [{ embedding: [1] }] } },
        }),
      );
    });
    const pending = runOpenAiEmbeddingBatches({
      ...singleRequestBatchParams(fetchImpl, 2_000, 1500 * 60_000),
      debug: (message) => {
        if (message.includes("batch-long in_progress")) {
          vi.setSystemTime(61 * 60_000);
        }
      },
    });
    await vi.runAllTimersAsync();
    await expect(pending).resolves.toEqual(new Map([["0", [1]]]));
    expect(Date.now()).toBeGreaterThan(60 * 60_000);
    expect(statusIds).toHaveLength(2);
    expect(
      fetchImpl.mock.calls.filter(([input]) => fetchInputUrl(input).endsWith("/batches")),
    ).toHaveLength(1);
  });

  it.each(["download", "missing", "duplicate", "partial error", "dimensions"])(
    "retains all accepted group IDs after %s failure without recreating groups",
    async (failure) => {
      vi.useFakeTimers();
      const requests = ["0", "1"].map((custom_id) => ({
        custom_id,
        method: "POST" as const,
        url: "/v1/embeddings" as const,
        body: { model: "text-embedding-3-small", input: `synthetic-${custom_id}` },
      }));
      let uploads = 0;
      let creates = 0;
      const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = fetchInputUrl(input);
        if (url.endsWith("/files") && init?.method === "POST") {
          return Response.json({ id: `input-${uploads++}` });
        }
        if (url.endsWith("/batches") && init?.method === "POST") {
          const index = creates++;
          return Response.json({
            id: `batch-${index}`,
            status: "completed",
            output_file_id: `output-${index}`,
          });
        }
        const index = url.endsWith("output-0/content") ? 0 : 1;
        if (index === 1 && failure === "download") {
          return new Response("download unavailable", { status: 503 });
        }
        if (index === 1 && failure === "missing") {
          return new Response("");
        }
        const line = {
          custom_id: failure === "duplicate" && index === 1 ? "0" : String(index),
          response: {
            status_code: index === 1 && failure === "partial error" ? 400 : 200,
            body: {
              data: [{ embedding: Array(failure === "dimensions" ? 1536 : 256).fill(1) }],
              error: { message: "synthetic rejected input" },
            },
          },
        };
        return new Response(JSON.stringify(line));
      });
      const params = singleRequestBatchParams(fetchImpl, 1, 1000);
      const rejection = expect(
        runOpenAiEmbeddingBatches({
          ...params,
          openAi: { ...params.openAi, outputDimensionality: 256 },
          requests,
          maxJsonlBytes: Buffer.byteLength(JSON.stringify(requests[0])),
        }),
      ).rejects.toMatchObject({
        batchReceipts: [
          { inputFileId: "input-0", batchId: "batch-0" },
          { inputFileId: "input-1", batchId: "batch-1" },
        ],
      });
      await vi.runAllTimersAsync();
      await rejection;
      expect(creates).toBe(2);
      expect(uploads).toBe(2);
    },
  );

  it("drains a concurrently accepted group before reporting all reconciliation IDs", async () => {
    const secondCreateStarted = createDeferred<void>();
    const acceptSecond = createDeferred<void>();
    const firstFailed = createDeferred<void>();
    let creates = 0;
    let uploads = 0;
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = fetchInputUrl(input);
      if (url.endsWith("/files") && init?.method === "POST") {
        return Response.json({ id: `input-${uploads++}` });
      }
      if (url.endsWith("/batches") && init?.method === "POST") {
        const index = creates++;
        if (index === 1) {
          secondCreateStarted.resolve();
          await acceptSecond.promise;
        }
        return Response.json({
          id: `batch-${index}`,
          status: "completed",
          output_file_id: `output-${index}`,
        });
      }
      if (url.endsWith("output-0/content")) {
        await secondCreateStarted.promise;
        firstFailed.resolve();
        return new Response("output unavailable", { status: 400 });
      }
      return new Response(
        JSON.stringify({
          custom_id: "1",
          response: { status_code: 200, body: { data: [{ embedding: [1] }] } },
        }),
      );
    });
    const params = singleRequestBatchParams(fetchImpl, 1, 1000);
    const requests = ["0", "1"].map((custom_id) =>
      Object.assign({}, params.requests[0]!, { custom_id }),
    );
    let settled = false;
    const outcome = runOpenAiEmbeddingBatches({
      ...params,
      requests,
      concurrency: 2,
      maxJsonlBytes: Buffer.byteLength(JSON.stringify(requests[0])),
    })
      .catch((error: unknown) => error)
      .finally(() => {
        settled = true;
      });
    await firstFailed.promise;
    expect(settled).toBe(false);
    acceptSecond.resolve();
    expect(await outcome).toMatchObject({
      batchReceipts: [
        { inputFileId: "input-0", batchId: "batch-0" },
        { inputFileId: "input-1", batchId: "batch-1" },
      ],
    });
    expect(creates).toBe(2);
  });
});
