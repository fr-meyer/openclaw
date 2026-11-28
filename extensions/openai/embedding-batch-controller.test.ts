import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { expectDefined } from "@openclaw/normalization-core";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  withOpenAiBatchController,
  type OpenAiBoundBatchController,
} from "./embedding-batch-controller.js";
import { fetchInputUrl } from "./embedding-batch.test-support.js";
import type { OpenAiEmbeddingClient } from "./embedding-provider.js";

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => fs.rm(root, { recursive: true, force: true })));
});
const requests = [
  {
    custom_id: "item-0",
    method: "POST" as const,
    url: "/v1/embeddings" as const,
    body: { model: "text-embedding-3-small", input: "synthetic only", dimensions: 256 },
  },
];
const execution = {
  wait: false,
  concurrency: 1,
  pollIntervalMs: 1,
  timeoutMs: 60_000,
  debug: () => {},
};
async function setup(mode: "complete" | "upload-lost" | "create-lost" | "pending" = "complete") {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "openai-controller-"));
  roots.push(root);
  await fs.chmod(root, 0o700);
  const counts = { uploads: 0, creates: 0, reads: 0 };
  const uploaded: string[] = [];
  const status = () => ({
    id: "accepted",
    status: mode === "pending" ? "validating" : "completed",
    output_file_id: "output",
  });
  const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = fetchInputUrl(input);
    if (url.endsWith("/files") && init?.method === "POST") {
      counts.uploads++;
      uploaded.push(await ((init!.body as FormData).get("file") as Blob).text());
      if (mode === "upload-lost") {
        throw new TypeError("upload response lost");
      }
      return Response.json({ id: "paid-input" });
    }
    if (url.endsWith("/batches") && init?.method === "POST") {
      counts.creates++;
      if (mode === "create-lost") {
        throw new TypeError("accepted response lost");
      }
      return Response.json(status());
    }
    if (url.includes("/batches?")) {
      return Response.json({ data: [], has_more: false });
    }
    if (url.endsWith("/batches/accepted")) {
      counts.reads++;
      return Response.json(status());
    }
    if (url.endsWith("/files/output/content")) {
      return new Response(
        JSON.stringify({
          custom_id: "item-0",
          response: {
            status_code: 200,
            body: { data: [{ index: 0, embedding: [1, ...Array(255).fill(0)] }] },
          },
        }) + "\n",
      );
    }
    throw new Error("Unexpected synthetic endpoint " + url);
  });
  const client: OpenAiEmbeddingClient = {
    baseUrl: "https://openai-compatible.example/v1",
    headers: {},
    model: "text-embedding-3-small",
    outputDimensionality: 256,
    fetchImpl,
  };
  const params = {
    client,
    agentId: "main",
    expected: { model: client.model, dimensions: 256 },
    journal: {
      path: path.join(root, "receipts.sqlite"),
      migrationId: "migration",
      sourceRevision: "a".repeat(40),
      accountId: "fixture-account",
      route: client.baseUrl,
    },
  };
  return { root, client, params, counts, fetchImpl, uploaded };
}

describe("native durable Batch controller binding", () => {
  it("returns the same pinned manifest on reopen without changing the original client", async () => {
    const { params, client, fetchImpl } = await setup();
    const first = await withOpenAiBatchController(
      params,
      async (controller) => controller.manifest,
    );
    const reopened = await withOpenAiBatchController(
      params,
      async (controller) => controller.manifest,
    );
    expect(reopened).toEqual(first);
    expect(client.batchJournal).toBeUndefined();
    expect(fetchImpl).not.toHaveBeenCalled();
    expect((await fs.stat(first.journal.path)).isFile()).toBe(true);
  });
  it("pins one operation/account/source identity per receipt DB", async () => {
    const { params, fetchImpl } = await setup();
    await withOpenAiBatchController(params, async () => {});
    await expect(
      withOpenAiBatchController(
        {
          ...params,
          journal: {
            ...params.journal,
            migrationId: "different-operation",
          },
        },
        async () => {},
      ),
    ).rejects.toThrow("identity mismatch");
    expect(fetchImpl).not.toHaveBeenCalled();
  });
  it("fences a controller retained beyond its native custody callback", async () => {
    const { params, fetchImpl } = await setup();
    let escaped: OpenAiBoundBatchController | undefined;
    await withOpenAiBatchController(params, async (controller) => {
      escaped = controller;
    });
    await expect(escaped!.runBatch(requests, execution)).rejects.toThrow("retired");
    expect(fetchImpl).not.toHaveBeenCalled();
  });
  it.each(["upload-lost", "create-lost", "pending"] as const)(
    "reopens %s receipts without another upload/create or synchronous fallback",
    async (mode) => {
      const { params, counts } = await setup(mode);
      for (let reopen = 0; reopen < 2; reopen++) {
        await expect(
          withOpenAiBatchController(params, (controller) =>
            controller.runBatch(requests, execution),
          ),
        ).rejects.toBeDefined();
      }
      expect(counts.uploads).toBe(1);
      expect(counts.creates).toBe(mode === "upload-lost" ? 0 : 1);
    },
  );
  it("reloads accepted completed results without purchasing the batch again", async () => {
    const { params, counts } = await setup();
    for (let reopen = 0; reopen < 2; reopen++) {
      const result = await withOpenAiBatchController(params, (controller) =>
        controller.runBatch(requests, execution),
      );
      expect(result.get("item-0")).toHaveLength(256);
    }
    expect(counts.uploads).toBe(1);
    expect(counts.creates).toBe(1);
  });
  it("rejects route or vector identity drift before any provider operation", async () => {
    const { params, fetchImpl } = await setup();
    await expect(
      withOpenAiBatchController(
        {
          ...params,
          expected: {
            ...params.expected,
            dimensions: 1024,
          },
        },
        async () => {},
      ),
    ).rejects.toThrow("admission");
    await expect(
      withOpenAiBatchController(
        {
          ...params,
          journal: {
            ...params.journal,
            route: "https://different.example/v1",
          },
        },
        async () => {},
      ),
    ).rejects.toThrow("admission");
    expect(fetchImpl).not.toHaveBeenCalled();
  });
  it("reopens durable accepted work after callback interruption without repurchase", async () => {
    const { params, counts } = await setup();
    await expect(
      withOpenAiBatchController(params, async (controller) => {
        await controller.runBatch(requests, execution);
        throw new Error("synthetic controller interruption after receipt commit");
      }),
    ).rejects.toThrow("controller interruption");
    const result = await withOpenAiBatchController(params, (controller) =>
      controller.runBatch(requests, execution),
    );
    expect(result.get("item-0")).toHaveLength(256);
    expect(counts.uploads).toBe(1);
    expect(counts.creates).toBe(1);
  });
  it("refuses a competing operation while native custody is held", async () => {
    const { params, fetchImpl } = await setup();
    await withOpenAiBatchController(params, async () => {
      await expect(withOpenAiBatchController(params, async () => {})).rejects.toBeDefined();
    });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("captures nested request bytes and execution capabilities before pending journal inspection", async () => {
    const { params, counts, uploaded } = await setup("pending");
    const entered = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    const originalDebug = vi.fn();
    const changedDebug = vi.fn();
    await expect(
      withOpenAiBatchController(params, async (controller) => {
        const originalLstat = fs.lstat;
        const inspection = vi.spyOn(fs, "lstat").mockImplementationOnce(async (...args) => {
          entered.resolve();
          await release.promise;
          return await originalLstat(...args);
        });
        const input = structuredClone(requests);
        const controls = { ...execution, debug: originalDebug };
        const work = controller.runBatch(input, controls);
        try {
          await entered.promise;
          expectDefined(input[0]).custom_id = "mutated-id";
          expectDefined(input[0]).body.input = "mutated private payload must not upload";
          controls.wait = true;
          controls.concurrency = 0;
          controls.timeoutMs = 1;
          controls.debug = changedDebug;
        } finally {
          release.resolve();
        }
        try {
          await work;
        } finally {
          inspection.mockRestore();
        }
      }),
    ).rejects.toBeDefined();
    const sent = JSON.parse(expectDefined(uploaded[0]).trim());
    expect(sent.custom_id).toBe("item-0");
    expect(sent.body.input).toBe("synthetic only");
    expect(sent.body.dimensions).toBe(256);
    expect(counts.uploads).toBe(1);
    expect(counts.creates).toBe(1);
    expect(counts.reads).toBe(0); // original wait:false, not caller-mutated wait:true
    expect(changedDebug).not.toHaveBeenCalled();
    expect(originalDebug).toHaveBeenCalled();
  });

  it("drains an unawaited failed batch without an escaped unhandled promise or masked callback error", async () => {
    const { params, counts } = await setup("upload-lost");
    const callbackError = new Error("callback primary failure");
    const unhandled: unknown[] = [];
    const listener = (reason: unknown) => {
      unhandled.push(reason);
    };
    process.on("unhandledRejection", listener);
    let escaped: Promise<Map<string, number[]>> | undefined;
    try {
      const failure = await withOpenAiBatchController(params, async (controller) => {
        escaped = controller.runBatch(requests, execution);
        // Intentionally do not await or attach a handler to the returned promise.
        throw callbackError;
      }).catch((error: unknown) => error);
      await new Promise<void>((resolve) => setImmediate(resolve));
      expect(unhandled).toEqual([]);
      expect(failure).toBeInstanceOf(AggregateError);
      expect((failure as AggregateError).cause).toBe(callbackError);
      expect((failure as AggregateError).errors[0]).toBe(callbackError);
      await expect(escaped).rejects.toBeDefined();
      expect(counts.uploads).toBe(1);
      expect(counts.creates).toBe(0);
      // Custody was released only after accepted work drained; reopen is possible,
      // but UNKNOWN upload identity still prevents another provider submission.
      await expect(
        withOpenAiBatchController(params, (controller) => controller.runBatch(requests, execution)),
      ).rejects.toBeDefined();
      expect(counts.uploads).toBe(1);
    } finally {
      process.removeListener("unhandledRejection", listener);
    }
  });
});
