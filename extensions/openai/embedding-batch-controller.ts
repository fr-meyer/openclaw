import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { acquireFileLock } from "openclaw/plugin-sdk/file-lock";
import type { EmbeddingBatchExecutionParams } from "openclaw/plugin-sdk/memory-core-host-engine-embeddings";
import {
  updateOpenAiBatchJournal,
  type OpenAiBatchJournalContext,
} from "./embedding-batch-journal.js";
import type { OpenAiBatchRequest } from "./embedding-batch-recovery.js";
import { runOpenAiEmbeddingBatches } from "./embedding-batch.js";
import type { OpenAiEmbeddingClient } from "./embedding-provider.js";

export type OpenAiBatchControllerManifest = Readonly<{
  journal: Readonly<OpenAiBatchJournalContext>;
  identity: string;
  model: string;
  dimensions: number;
}>;

export type OpenAiBoundBatchController = {
  readonly manifest: OpenAiBatchControllerManifest;
  runBatch(
    requests: OpenAiBatchRequest[],
    execution: EmbeddingBatchExecutionParams,
  ): Promise<Map<string, number[]>>;
};

/** A bounded operation, not a service or authorization to transmit a corpus.
 * Callers must still supply approved account/route/source/spend admission.
 * Existing receipt recovery owns UNKNOWN and accepted-job reconciliation.
 */
export async function withOpenAiBatchController<T>(
  params: {
    client: OpenAiEmbeddingClient;
    journal: OpenAiBatchJournalContext;
    agentId: string;
    expected: { model: string; dimensions: number };
  },
  run: (controller: OpenAiBoundBatchController) => Promise<T>,
): Promise<T> {
  const inputClient = { ...params.client, headers: { ...params.client.headers } };
  const journal = Object.freeze({ ...params.journal });
  const expected = { ...params.expected };
  const agentId = params.agentId;
  const route = new URL(journal.route);
  if (
    route.protocol !== "https:" ||
    route.username ||
    route.password ||
    route.search ||
    route.hash ||
    journal.route !== inputClient.baseUrl ||
    !agentId ||
    !/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(journal.migrationId) ||
    !/^[a-f0-9]{40,64}$/.test(journal.sourceRevision) ||
    !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$/.test(journal.accountId) ||
    expected.model !== "text-embedding-3-small" ||
    expected.dimensions !== 256 ||
    inputClient.model !== expected.model ||
    inputClient.outputDimensionality !== expected.dimensions ||
    !path.isAbsolute(journal.path) ||
    inputClient.batchJournal
  ) {
    throw new Error("Invalid or prebound OpenAI Batch controller admission");
  }
  const parent = await fs.realpath(path.dirname(journal.path));
  const directory = await fs.lstat(parent);
  if (
    journal.path !== path.join(parent, path.basename(journal.path)) ||
    !directory.isDirectory() ||
    (directory.mode & 0o077) !== 0 ||
    (typeof process.getuid === "function" && directory.uid !== process.getuid())
  ) {
    throw new Error("OpenAI Batch controller requires an owned private canonical directory");
  }
  const identity = createHash("sha256")
    .update(
      JSON.stringify({
        migrationId: journal.migrationId,
        sourceRevision: journal.sourceRevision,
        accountId: journal.accountId,
        route: journal.route,
        agentId,
        model: expected.model,
        dimensions: expected.dimensions,
      }),
    )
    .digest("hex");
  const lock = await acquireFileLock(journal.path, {
    retries: { retries: 0, factor: 1, minTimeout: 1, maxTimeout: 1 },
    stale: 30_000,
    staleRecovery: "remove-if-definitely-stale",
  });
  let active = true;
  let batchActive = false;
  let pending: Promise<Map<string, number[]>> | undefined;
  let result: T | undefined;
  const failures: unknown[] = [];
  try {
    // A reserved, non-provider intent pins the controller identity in the SAME
    // existing receipt DB. Reopen never creates a second state/journal owner.
    const receipt = await updateOpenAiBatchJournal({
      path: journal.path,
      operationId: "controller:identity",
      identity,
    });
    if (
      receipt.receipt.phase !== "upload-unknown" ||
      receipt.receipt.inputFileId ||
      receipt.receipt.batchId
    ) {
      throw new Error("Invalid OpenAI Batch controller identity marker");
    }
    const file = await fs.lstat(journal.path);
    if (!file.isFile() || file.isSymbolicLink() || (file.mode & 0o077) !== 0) {
      throw new Error("Invalid OpenAI Batch controller journal artifact");
    }
    // Do not mutate or leak the original provider client; binding lives only
    // within this owner. Frozen adapter/provider postimages stay unchanged.
    const client: OpenAiEmbeddingClient = {
      ...inputClient,
      batchJournal: journal,
    };
    const manifest = Object.freeze({ journal, identity, ...expected });
    const controller: OpenAiBoundBatchController = {
      manifest,
      runBatch: (requests, execution) => {
        const observe = (work: Promise<Map<string, number[]>>) => {
          // Observation handles escape without replacing caller-visible failure.
          void work.catch(() => {});
          return work;
        };
        if (!active || batchActive) {
          return observe(
            Promise.reject(new Error("OpenAI Batch controller custody is retired or already busy")),
          );
        }
        let requestSnapshot: OpenAiBatchRequest[];
        let executionSnapshot: EmbeddingBatchExecutionParams;
        try {
          // Capture the full nested request before the first await or return.
          requestSnapshot = structuredClone(requests);
          // Native contract has scalar controls and a debug capability only.
          // Preserve the callback; do not clone functions or AbortSignals.
          executionSnapshot = {
            wait: execution.wait,
            pollIntervalMs: execution.pollIntervalMs,
            timeoutMs: execution.timeoutMs,
            concurrency: execution.concurrency,
            debug: execution.debug,
          };
          if (
            !Array.isArray(requestSnapshot) ||
            requestSnapshot.some(
              (request) =>
                request.method !== "POST" ||
                request.url !== "/v1/embeddings" ||
                typeof request.custom_id !== "string" ||
                !request.custom_id ||
                request.body.model !== expected.model ||
                request.body.dimensions !== expected.dimensions ||
                typeof request.body.input !== "string",
            ) ||
            typeof executionSnapshot.wait !== "boolean" ||
            !Number.isFinite(executionSnapshot.pollIntervalMs) ||
            executionSnapshot.pollIntervalMs < 0 ||
            !Number.isFinite(executionSnapshot.timeoutMs) ||
            executionSnapshot.timeoutMs <= 0 ||
            !Number.isSafeInteger(executionSnapshot.concurrency) ||
            executionSnapshot.concurrency < 1 ||
            (executionSnapshot.debug !== undefined && typeof executionSnapshot.debug !== "function")
          ) {
            throw new Error(
              "OpenAI Batch invocation differs from admitted request/execution identity",
            );
          }
        } catch (error) {
          return observe(Promise.reject(error));
        }
        batchActive = true;
        pending = (async () => {
          try {
            const current = await fs.lstat(journal.path);
            if (
              !current.isFile() ||
              current.isSymbolicLink() ||
              current.dev !== file.dev ||
              current.ino !== file.ino ||
              (current.mode & 0o077) !== 0
            ) {
              throw new Error("OpenAI Batch controller journal identity changed");
            }
            const vectors = await runOpenAiEmbeddingBatches({
              ...executionSnapshot,
              openAi: client,
              agentId,
              requests: requestSnapshot,
              journal,
            });
            if (
              [...vectors.values()].some(
                (vector) =>
                  vector.length !== expected.dimensions ||
                  vector.some((value) => !Number.isFinite(value)),
              )
            ) {
              throw new Error("OpenAI Batch results differ from admitted vector dimensions");
            }
            return vectors;
          } finally {
            batchActive = false;
          }
        })();
        // No async-method wrapper: returned promise === owned/drained promise.
        return observe(pending);
      },
    };
    result = await run(controller);
  } catch (error) {
    failures.push(error);
  } finally {
    active = false;
    // An escaped promise cannot outlive the native operation lease. Retire
    // new calls first, then drain accepted work before releasing ownership.
    try {
      await pending;
    } catch (error) {
      if (!failures.includes(error)) {
        failures.push(error);
      }
    }
    try {
      await lock.release();
    } catch (error) {
      if (!failures.includes(error)) {
        failures.push(error);
      }
    }
  }
  if (failures.length === 1) {
    throw failures[0];
  }
  if (failures.length > 1) {
    throw new AggregateError(failures, "OpenAI Batch controller callback/drain/release failed", {
      cause: failures[0],
    });
  }
  return result as T;
}
