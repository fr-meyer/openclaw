import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { expectDefined } from "@openclaw/normalization-core";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  resolveMemoryEmbeddingBatch,
  runMemoryEmbeddingBatchTimeoutRetry,
} from "../memory-core/src/memory/manager-embedding-policy.js";
import { MemoryManagerRegistry } from "../memory-core/src/memory/manager-registry.js";
import { OpenAiEmbeddingBatchError } from "./embedding-batch.js";
import { fetchInputUrl } from "./embedding-batch.test-support.js";
import type { OpenAiEmbeddingClient } from "./embedding-provider.js";
const injected = vi.hoisted(() => ({ client: null as OpenAiEmbeddingClient | null }));
vi.mock("./embedding-provider.js", async (original) => ({
  ...(await original<typeof import("./embedding-provider.js")>()),
  createOpenAiEmbeddingProvider: async () => ({
    client: injected.client!,
    provider: {
      id: "openai",
      model: "text-embedding-3-small",
      embed: vi.fn(),
      embedBatch: vi.fn(),
    },
  }),
}));
const { openAiMemoryEmbeddingProviderAdapter: adapter } =
  await import("./memory-embedding-adapter.js");
const roots: string[] = [];
afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => fs.rm(root, { recursive: true, force: true })));
});
async function setup(
  failUpload = false,
  inputType?: string,
  documentInputType?: string,
  pending = false,
) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "candidate-chain-"));
  roots.push(root);
  await fs.chmod(root, 0o700);
  const counts = { uploads: 0, creates: 0 };
  const files = new Map<
    string,
    Array<{
      custom_id: string;
      body: { input: string; model: string; dimensions?: number; input_type?: string };
    }>
  >();
  const jobs = new Map<string, { input_file_id: string; metadata: unknown }>();
  injected.client = {
    baseUrl: "https://synthetic.example/v1",
    headers: {},
    model: "text-embedding-3-small",
    outputDimensionality: 256,
    inputType,
    documentInputType,
    fetchImpl: vi.fn(async (input, init) => {
      const url = fetchInputUrl(input);
      if (url.endsWith("/files") && init?.method === "POST") {
        counts.uploads++;
        if (failUpload) {
          throw new TypeError("synthetic upload timed out; response lost");
        }
        const id = "input-" + counts.uploads;
        const payload = await ((init.body as FormData).get("file") as Blob).text();
        files.set(
          id,
          payload
            .trim()
            .split("\n")
            .map((line) => JSON.parse(line)),
        );
        return Response.json({ id });
      }
      if (url.endsWith("/batches") && init?.method === "POST") {
        counts.creates++;
        const id = "job-" + counts.creates;
        jobs.set(id, JSON.parse(init.body as string));
        return Response.json({
          id,
          status: pending ? "validating" : "completed",
          ...(pending ? {} : { output_file_id: id }),
        });
      }
      const jobId = url.split("/").pop()!;
      if (url.includes("/batches/") && jobs.has(jobId)) {
        return Response.json({
          id: jobId,
          status: pending ? "validating" : "completed",
          ...(pending ? {} : { output_file_id: jobId }),
          ...jobs.get(jobId),
        });
      }
      if (url.endsWith("/content")) {
        const id = url.split("/").at(-2)!;
        const job = jobs.get(id)!;
        return new Response(
          files
            .get(job.input_file_id)!
            .map((request) =>
              JSON.stringify({
                custom_id: request.custom_id,
                response: {
                  status_code: 200,
                  body: { data: [{ index: 0, embedding: [1, ...Array(255).fill(0)] }] },
                },
              }),
            )
            .join("\n") + "\n",
        );
      }
      if (url.includes("/batches?")) {
        return Response.json({ data: [], has_more: false });
      }
      throw new Error("Unexpected synthetic URL " + url);
    }),
  };
  const registry = new MemoryManagerRegistry<{ close(): Promise<void> }>();
  const manager = { close: async () => {} };
  registry.track(manager, "candidate-chain");
  const created = await registry.createProvider(manager, adapter, () =>
    adapter.create({
      config: {} as never,
      model: "text-embedding-3-small",
      fallback: "none",
      dimensions: 256,
    }),
  );
  const admission = {
    agentId: "main",
    journal: {
      path: path.join(root, "receipts.sqlite"),
      migrationId: "stable",
      sourceRevision: "a".repeat(40),
      accountId: "synthetic",
      route: injected.client.baseUrl,
    },
    expected: { model: "text-embedding-3-small", dimensions: 256 },
  };
  const invoke = <T>(run: Parameters<typeof registry.withCandidateBatch<T>>[4]) =>
    registry.withCandidateBatch(manager, created.provider!, created.runtime!, admission, run);
  const options = (text: string) => ({
    agentId: "main",
    chunks: [{ text, hash: "hash-" + text, sourceKey: "memory:file:" + text }],
    wait: false,
    concurrency: 1,
    pollIntervalMs: 1,
    timeoutMs: 1000,
    debug: () => {},
  });
  return { counts, files, invoke, options, admission, created, client: injected.client };
}
describe("real registered OpenAI adapter/controller/journal chain", () => {
  it("keeps two same-sized invocations distinct and exact replay/reopen purchase-free", async () => {
    const { invoke, options, counts, files } = await setup();
    for (let reopen = 0; reopen < 2; reopen++) {
      await invoke(async (batch) => {
        expect(await batch(options("A"))).toHaveLength(1);
        expect(await batch(options("B"))).toHaveLength(1);
        expect(await batch(options("A"))).toHaveLength(1);
      });
    }
    expect(counts).toEqual({ uploads: 2, creates: 2 });
    const ids = [...files.values()].flat().map((request) => request.custom_id);
    expect(new Set(ids).size).toBe(2);
    expect(ids.every((id) => /^[a-f0-9]{64}$/.test(id))).toBe(true);
  });
  it("captures chunk count and body before caller mutation, through actual provider upload", async () => {
    const { invoke, options, files } = await setup();
    await invoke(async (batch) => {
      const input = options("original");
      const pending = batch(input);
      expectDefined(input.chunks[0], "Expected the original OpenAI embedding chunk").text =
        "mutated";
      input.chunks.push(...options("extra").chunks);
      expect(await pending).toHaveLength(1);
    });
    expect([...files.values()].flat().map((request) => request.body.input)).toEqual(["original"]);
  });
  it("drains combined escaped failure, observes returned rejection and retains callback cause", async () => {
    const { invoke, options, counts } = await setup(true);
    const primary = new Error("callback primary");
    const unhandled: unknown[] = [];
    const listener = (reason: unknown) => {
      unhandled.push(reason);
    };
    process.on("unhandledRejection", listener);
    let escaped: Promise<number[][] | null> | undefined;
    try {
      const failure = await invoke(async (batch) => {
        escaped = batch(options("A"));
        throw primary;
      }).catch((error) => error);
      await new Promise<void>((resolve) => setImmediate(resolve));
      expect(unhandled).toEqual([]);
      const flatten = (error: unknown): unknown[] =>
        error instanceof AggregateError ? [error, ...error.errors.flatMap(flatten)] : [error];
      expect(flatten(failure)).toContain(primary);
      await expect(escaped).rejects.toBeDefined();
      expect(counts).toEqual({ uploads: 1, creates: 0 });
    } finally {
      process.removeListener("unhandledRejection", listener);
    }
  });
  it("keeps caller admission mutations outside the privately frozen registry baseline", async () => {
    const { invoke, options, admission, counts } = await setup();
    const work = invoke(async (batch, identity) => {
      expect(identity.journal.accountId).toBe("synthetic");
      expect(Object.isFrozen(identity.journal)).toBe(true);
      expect(await batch(options("A"))).toHaveLength(1);
    });
    admission.journal.accountId = "mutated";
    admission.journal.path = "/unowned/escape.sqlite";
    await work;
    expect(counts).toEqual({ uploads: 1, creates: 1 });
  });
  it("constructs ordinary providers without journal custody but refuses batch invocation", async () => {
    const { created, options, counts } = await setup();
    expect(created.provider).toBeDefined();
    expect(created.runtime?.batchFailureMode).toBe("fail-closed");
    await expect(created.runtime!.batchEmbed!(options("ordinary"))).rejects.toThrow(
      "controller-provisioned journal context",
    );
    await expect(created.runtime!.batchEmbedPartial!(options("ordinary"))).rejects.toThrow(
      "controller-provisioned journal context",
    );
    expect(counts).toEqual({ uploads: 0, creates: 0 });
    expect(created.provider!.embedBatch).not.toHaveBeenCalled();
  });

  it.each(["unknown", "accepted-timeout"])(
    "propagates %s through native manager policy without replay or fallback",
    async (mode) => {
      const { created, client, admission, options, counts } = await setup(
        mode === "unknown",
        undefined,
        undefined,
        mode === "accepted-timeout",
      );
      client!.batchJournal = admission.journal;
      const selected = created.provider;
      const batch = resolveMemoryEmbeddingBatch(created.runtime)!;
      const onRetry = vi.fn();
      const failure = await runMemoryEmbeddingBatchTimeoutRetry({
        failureMode: created.runtime!.batchFailureMode,
        onRetry,
        run: () => batch({ ...options(mode), wait: true, timeoutMs: 1000, pollIntervalMs: 1000 }),
      }).catch((error: unknown) => error);
      expect(failure).toBeInstanceOf(OpenAiEmbeddingBatchError);
      expect(failure).toMatchObject({ recoveryBlocked: true });
      expect(String(failure)).toMatch(
        mode === "accepted-timeout" ? /timed out/i : /unresolved|UNKNOWN/i,
      );
      expect(onRetry).not.toHaveBeenCalled();
      expect(counts).toEqual({ uploads: 1, creates: mode === "unknown" ? 0 : 1 });
      expect(created.provider).toBe(selected);
      expect(created.provider!.embedBatch).not.toHaveBeenCalled();
    },
  );

  it("binds candidate identity and ordinary requests to the same effective document fields", async () => {
    const ids: string[] = [];
    for (const documentInputType of [" document ", "different-document"]) {
      const { invoke, options, files, created, client, admission } = await setup(
        false,
        "query-default",
        documentInputType,
      );
      const input = options("paired");
      await invoke(async (batch) => {
        await batch(input);
      });
      const candidate = [...files.values()].flat()[0]!;
      const body = {
        model: "text-embedding-3-small",
        input: "paired",
        dimensions: 256,
        input_type: documentInputType.trim(),
      };
      expect(candidate.body).toEqual(body);
      expect(candidate.custom_id).toBe(
        createHash("sha256")
          .update(
            JSON.stringify({
              source: expectDefined(input.chunks[0], "Expected the original OpenAI embedding chunk")
                .sourceKey,
              chunk: expectDefined(input.chunks[0], "Expected the original OpenAI embedding chunk")
                .hash,
              body,
            }),
          )
          .digest("hex"),
      );
      expect(created.runtime!.cacheKeyData).toMatchObject({ documentInputType: body.input_type });
      ids.push(candidate.custom_id);
      // Separate explicit fixture custody for the ordinary entry, never credentials as authority.
      client!.batchJournal = { ...admission.journal, migrationId: "ordinary" };
      await created.runtime!.batchEmbed!(input);
      const ordinary = [...files.values()].flat().find((request) => request.custom_id === "0");
      expect(ordinary?.body).toEqual(body);
      expect(created.provider!.embed).not.toHaveBeenCalled();
    }
    expect(ids[0]).not.toBe(ids[1]);
  });
});
