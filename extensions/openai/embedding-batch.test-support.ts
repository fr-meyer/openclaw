import { join } from "node:path";
import { afterEach, beforeEach, vi } from "vitest";
import { createTempDirTracker } from "../../test/helpers/temp-dir.js";
import * as journalRuntime from "./embedding-batch-journal.js";
import type { OpenAiBatchJournalContext } from "./embedding-batch-journal.js";
import { runOpenAiEmbeddingBatches } from "./embedding-batch.js";

type BatchParams = Parameters<typeof runOpenAiEmbeddingBatches>[0];
const tempDirs = createTempDirTracker();
const contexts = new Map<string, OpenAiBatchJournalContext>();
const journalWork = new Set<Promise<unknown>>();
const batchWork = new Set<Promise<unknown>>();
const originalJournalUpdate = journalRuntime.updateOpenAiBatchJournal;
let trackingInstalled = false;
let restoreJournalTracking: (() => void) | undefined;

beforeEach(() => {
  trackingInstalled = false;
});

afterEach(async () => {
  // Never remove a private journal while its real worker or submission owns it.
  await drainJournalWorkers();
  restoreJournalTracking?.();
  restoreJournalTracking = undefined;
  if (batchWork.size) {
    throw new Error("Batch fixture still owns an unsettled submission; retaining its journal");
  }
  tempDirs.cleanup();
  contexts.clear();
});

export function trackBatchJournalWorkers() {
  if (trackingInstalled) return;
  trackingInstalled = true;
  const spy = vi.spyOn(journalRuntime, "updateOpenAiBatchJournal").mockImplementation((params) => {
    const work = originalJournalUpdate(params);
    journalWork.add(work);
    void work.then(
      () => journalWork.delete(work),
      () => journalWork.delete(work),
    );
    return work;
  });
  restoreJournalTracking = () => spy.mockRestore();
}

async function drainJournalWorkers() {
  while (journalWork.size) {
    // Event-driven worker completion, not real sleeps or wall-clock polling.
    await Promise.allSettled([...journalWork]);
  }
}

export function createBatchTestJournal(route: string): OpenAiBatchJournalContext {
  const prior = contexts.get(route);
  if (prior) return prior;
  const root = tempDirs.make("openai-batch-fixture-");
  const context = {
    path: join(root, "intents.sqlite"),
    migrationId: "synthetic-test-migration",
    sourceRevision: "synthetic-source-v1",
    accountId: "synthetic-account",
    route,
  };
  contexts.set(route, context);
  return context;
}

/** Only legacy synthetic callers use this fixture. Production custody stays mandatory. */
export function runTestOpenAiEmbeddingBatches(params: BatchParams) {
  trackBatchJournalWorkers();
  const dimensions = params.openAi.outputDimensionality ?? 1;
  const work = runOpenAiEmbeddingBatches({
    ...params,
    openAi: { ...params.openAi, outputDimensionality: dimensions },
    journal:
      params.journal ?? params.openAi.batchJournal ?? createBatchTestJournal(params.openAi.baseUrl),
    requests: params.requests.map((request) => ({
      ...request,
      body: { ...request.body, dimensions: request.body.dimensions ?? dimensions },
    })),
  });
  batchWork.add(work);
  void work.then(
    () => batchWork.delete(work),
    () => batchWork.delete(work),
  );
  return work;
}

/** Drain real disk ownership without advancing the virtual provider deadline. */
async function flushBatchJournal() {
  await vi.advanceTimersByTimeAsync(0);
  while (journalWork.size) {
    await drainJournalWorkers();
    await vi.advanceTimersByTimeAsync(0);
  }
}

export async function advanceBatchTimersByTimeAsync(milliseconds: number) {
  await flushBatchJournal();
  await vi.advanceTimersByTimeAsync(milliseconds);
  await flushBatchJournal();
}

export async function runAllBatchTimersAsync() {
  await flushBatchJournal();
  await vi.runAllTimersAsync();
  while (journalWork.size) {
    await flushBatchJournal();
    await vi.runAllTimersAsync();
  }
}

export function singleRequestBatchParams(
  fetchImpl: typeof fetch,
  pollIntervalMs: number,
  timeoutMs: number,
  dimensions = 1,
): BatchParams {
  return {
    openAi: {
      baseUrl: "https://openai-compatible.example/v1",
      headers: { Authorization: "Bearer ***" },
      model: "text-embedding-3-small",
      outputDimensionality: dimensions,
      fetchImpl,
    },
    agentId: "main",
    requests: [
      {
        custom_id: "0",
        method: "POST",
        url: "/v1/embeddings",
        body: { model: "text-embedding-3-small", input: "payload", dimensions },
      },
    ],
    wait: true,
    concurrency: 1,
    pollIntervalMs,
    timeoutMs,
  };
}

export function fetchInputUrl(input: RequestInfo | URL): string {
  if (typeof input === "string") return input;
  if (input instanceof URL) return input.href;
  return input.url;
}
