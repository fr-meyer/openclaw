import { afterEach, describe, expect, it, vi } from "vitest";
import { OpenAiEmbeddingBatchError, runOpenAiEmbeddingBatches } from "./embedding-batch.js";
import { fetchInputUrl, singleRequestBatchParams } from "./embedding-batch.test-support.js";

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

const output = (id: string, value = 1, dimensions = 256) => ({
  custom_id: id,
  response: {
    status_code: 200,
    body: { model: "text-embedding-3-small", data: [{ embedding: Array(dimensions).fill(value) }] },
  },
});

async function settle<T>(pending: Promise<T>): Promise<T | unknown> {
  const result = pending.catch((error: unknown) => error);
  await vi.runAllTimersAsync();
  return await result;
}

describe("OpenAI selective Batch recovery", () => {
  it("keeps valid canonical output from a provider-qualified proxy routing alias", async () => {
    vi.useFakeTimers();
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = fetchInputUrl(input);
      if (url.endsWith("/files") && init?.method === "POST") {
        return Response.json({ id: "input" });
      }
      if (url.endsWith("/batches") && init?.method === "POST") {
        return Response.json({ id: "batch", status: "completed", output_file_id: "output" });
      }
      return new Response(JSON.stringify(output("0")));
    });
    const params = singleRequestBatchParams(fetchImpl, 1, 1000);
    const model = "openai/text-embedding-3-small";
    const result = await settle(
      runOpenAiEmbeddingBatches({
        ...params,
        openAi: { ...params.openAi, model },
        requests: params.requests.map((request) =>
          Object.assign({}, request, {
            body: { ...request.body, model },
          }),
        ),
      }),
    );
    expect(result).toBeInstanceOf(Map);
    expect((result as Map<string, number[]>).get("0")).toHaveLength(256);
  });

  it.each(["extra vector", "invalid index"])(
    "rejects %s with the canonical single-vector validator",
    async (mode) => {
      vi.useFakeTimers();
      const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = fetchInputUrl(input);
        if (url.endsWith("/files") && init?.method === "POST") {
          return Response.json({ id: "input" });
        }
        if (url.endsWith("/batches") && init?.method === "POST") {
          return Response.json({ id: "batch", status: "completed", output_file_id: "output" });
        }
        return new Response(
          JSON.stringify({
            custom_id: "0",
            response: {
              status_code: 200,
              body: {
                data:
                  mode === "extra vector"
                    ? [{ embedding: [1] }, { embedding: [2] }]
                    : [{ index: 1, embedding: [1] }],
              },
            },
          }),
        );
      });
      const result = await settle(
        runOpenAiEmbeddingBatches(singleRequestBatchParams(fetchImpl, 1, 1000)),
      );
      expect(result).toBeInstanceOf(OpenAiEmbeddingBatchError);
      expect((result as OpenAiEmbeddingBatchError).embeddings.size).toBe(0);
      expect(JSON.stringify(result)).not.toContain('"embeddings"');
    },
  );

  it.each(["TimeoutError", "AbortError"])(
    "distinguishes a temporary read timeout from %s cancellation",
    async (name) => {
      vi.useFakeTimers();
      let polls = 0;
      const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = fetchInputUrl(input);
        if (url.endsWith("/files") && init?.method === "POST") {
          return Response.json({ id: "input" });
        }
        if (url.endsWith("/batches") && init?.method === "POST") {
          return Response.json({ id: "batch", status: "in_progress" });
        }
        if (url.endsWith("/batches/batch")) {
          if (++polls === 1) {
            throw new DOMException("The operation was aborted due to timeout", name);
          }
          return Response.json({ id: "batch", status: "completed", output_file_id: "output" });
        }
        return new Response(JSON.stringify(output("0")));
      });
      const result = await settle(
        runOpenAiEmbeddingBatches(singleRequestBatchParams(fetchImpl, 1, 1000)),
      );
      expect(polls).toBe(name === "TimeoutError" ? 2 : 1);
      expect(result).toBeInstanceOf(name === "TimeoutError" ? Map : OpenAiEmbeddingBatchError);
    },
  );

  it("follows guarded output GET redirects without replaying creation", async () => {
    vi.useFakeTimers();
    let creates = 0;
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = fetchInputUrl(input);
      if (url.endsWith("/files") && init?.method === "POST") {
        return Response.json({ id: "input" });
      }
      if (url.endsWith("/batches") && init?.method === "POST") {
        creates++;
        return Response.json({ id: "batch", status: "completed", output_file_id: "output" });
      }
      if (url.endsWith("/files/output/content")) {
        return new Response(null, {
          status: 302,
          headers: { Location: "/v1/files/redirected/content" },
        });
      }
      return new Response(JSON.stringify(output("0")));
    });
    expect(
      await settle(runOpenAiEmbeddingBatches(singleRequestBatchParams(fetchImpl, 1, 1000))),
    ).toBeInstanceOf(Map);
    expect(creates).toBe(1);
    expect(
      fetchImpl.mock.calls.some(([input]) =>
        fetchInputUrl(input).endsWith("/files/redirected/content"),
      ),
    ).toBe(true);
  });

  it("does not restart the cumulative async budget for another group", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(0);
    let creates = 0;
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = fetchInputUrl(input);
      if (url.endsWith("/files") && init?.method === "POST") {
        return Response.json({ id: "input" });
      }
      if (url.endsWith("/batches") && init?.method === "POST") {
        creates++;
        return Response.json({ id: "batch", status: "completed", output_file_id: "output" });
      }
      vi.setSystemTime(1500 * 60_000);
      return new Response(JSON.stringify(output("0")));
    });
    const params = singleRequestBatchParams(fetchImpl, 1, 1500 * 60_000);
    const result = await settle(
      runOpenAiEmbeddingBatches({
        ...params,
        requests: [params.requests[0]!, { ...params.requests[0]!, custom_id: "1" }],
        maxJsonlBytes: Buffer.byteLength(JSON.stringify(params.requests[0])),
      }),
    );
    expect(creates).toBe(1);
    expect(result).toBeInstanceOf(OpenAiEmbeddingBatchError);
    expect((result as OpenAiEmbeddingBatchError).embeddings.has("0")).toBe(true);
  });
  it.each(["completed", "expired", "cancelled", "failed"])(
    "retains valid rows before and after item errors in %s output",
    async (status) => {
      vi.useFakeTimers();
      let downloaded = false;
      const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = fetchInputUrl(input);
        if (url.endsWith("/files") && init?.method === "POST") {
          return Response.json({ id: "input" });
        }
        if (url.endsWith("/batches") && init?.method === "POST") {
          return Response.json({
            id: "batch",
            status,
            output_file_id: "output",
            error_file_id: "errors",
          });
        }
        if (url.endsWith("/files/errors/content")) {
          return new Response(
            JSON.stringify({ custom_id: "1", error: { message: "synthetic failure" } }),
          );
        }
        downloaded = true;
        return new Response(
          [
            output("0"),
            { custom_id: "1", response: { status_code: 400 } },
            output("2", 2, 1536),
            output("3", 3),
          ]
            .map((line) => JSON.stringify(line))
            .join("\n"),
        );
      });
      const params = singleRequestBatchParams(fetchImpl, 1, 1000);
      const result = await settle(
        runOpenAiEmbeddingBatches({
          ...params,
          openAi: { ...params.openAi, outputDimensionality: 256 },
          requests: [0, 1, 2, 3].map((id) =>
            Object.assign({}, params.requests[0]!, { custom_id: String(id) }),
          ),
        }),
      );
      expect(downloaded).toBe(true);
      expect(result).toBeInstanceOf(OpenAiEmbeddingBatchError);
      const error = result as OpenAiEmbeddingBatchError;
      expect([...error.embeddings.keys()]).toEqual(["0", "3"]);
      expect(error.embeddings.get("3")).toEqual(Array(256).fill(3));
      expect(error.batchReceipts).toMatchObject([{ inputFileId: "input", batchId: "batch" }]);
    },
  );

  it.each(["found", "multiple", "unresolved", "list failure"])(
    "reconciles uncertain creation (%s) without another create",
    async (mode) => {
      vi.useFakeTimers();
      let metadata: Record<string, string> = {};
      let creates = 0;
      let lists = 0;
      const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = new URL(fetchInputUrl(input));
        if (url.pathname.endsWith("/files") && init?.method === "POST") {
          return Response.json({ id: "input-unknown" });
        }
        if (url.pathname.endsWith("/batches") && init?.method === "POST") {
          creates++;
          metadata = (JSON.parse(String(init.body)) as { metadata: Record<string, string> })
            .metadata;
          throw new Error("fetch failed");
        }
        if (url.pathname.endsWith("/batches")) {
          lists++;
          if (mode === "list failure") {
            return new Response("unavailable", { status: 503 });
          }
          if (mode === "unresolved") {
            return Response.json({ data: [], has_more: false });
          }
          if (!url.searchParams.has("after")) {
            return Response.json({
              data: [
                {
                  id: "unrelated",
                  input_file_id: "input-unknown",
                  metadata: { ...metadata, operation: "different-operation" },
                },
              ],
              has_more: true,
            });
          }
          return Response.json({
            data: (mode === "multiple" ? [0, 1] : [0]).map((id) => ({
              id: `batch-${id}`,
              input_file_id: "input-unknown",
              metadata,
              status: "completed",
              output_file_id: `output-${id}`,
            })),
            has_more: false,
          });
        }
        return new Response(JSON.stringify(output(url.pathname.includes("output-1") ? "1" : "0")));
      });
      const params = singleRequestBatchParams(fetchImpl, 1, 1000);
      const requests =
        mode === "multiple"
          ? [params.requests[0]!, { ...params.requests[0]!, custom_id: "1" }]
          : params.requests;
      const result = await settle(runOpenAiEmbeddingBatches({ ...params, requests }));
      expect(creates).toBe(1);
      expect(lists).toBe(mode === "list failure" ? 3 : mode === "unresolved" ? 1 : 2);
      if (mode === "found" || mode === "multiple") {
        expect(result).toBeInstanceOf(Map);
        expect((result as Map<string, number[]>).size).toBe(requests.length);
      } else {
        expect(result).toBeInstanceOf(OpenAiEmbeddingBatchError);
        expect((result as Error).message).toMatch(/outcome unknown.*may duplicate accepted work/);
      }
    },
  );

  it("retries a safe output GET against the same accepted job", async () => {
    vi.useFakeTimers();
    let downloads = 0;
    let creates = 0;
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = fetchInputUrl(input);
      if (url.endsWith("/files") && init?.method === "POST") {
        return Response.json({ id: "input" });
      }
      if (url.endsWith("/batches") && init?.method === "POST") {
        creates++;
        return Response.json({ id: "batch", status: "completed", output_file_id: "output" });
      }
      if (++downloads === 1) {
        return new Response("temporary", { status: 503 });
      }
      return new Response(JSON.stringify(output("0")));
    });
    const result = await settle(
      runOpenAiEmbeddingBatches(singleRequestBatchParams(fetchImpl, 1, 1000)),
    );
    expect(result).toBeInstanceOf(Map);
    expect(downloads).toBe(2);
    expect(creates).toBe(1);
  });

  it("retains validated rows across malformed output and never overwrites a duplicate ID", async () => {
    vi.useFakeTimers();
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = fetchInputUrl(input);
      if (url.endsWith("/files") && init?.method === "POST") {
        return Response.json({ id: "input" });
      }
      if (url.endsWith("/batches") && init?.method === "POST") {
        return Response.json({ id: "batch", status: "completed", output_file_id: "output" });
      }
      return new Response(
        [JSON.stringify(output("0")), JSON.stringify(output("0", 9)), "malformed"].join("\n"),
      );
    });
    const params = singleRequestBatchParams(fetchImpl, 1, 1000);
    const result = await settle(
      runOpenAiEmbeddingBatches({
        ...params,
        requests: [0, 1, 2].map((id) =>
          Object.assign({}, params.requests[0]!, { custom_id: String(id) }),
        ),
      }),
    );
    expect(result).toBeInstanceOf(OpenAiEmbeddingBatchError);
    expect((result as OpenAiEmbeddingBatchError).embeddings.get("0")).toEqual(Array(256).fill(1));
    expect((result as OpenAiEmbeddingBatchError).embeddings.size).toBe(1);
  });
});
