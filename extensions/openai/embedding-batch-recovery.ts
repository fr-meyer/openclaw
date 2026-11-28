import { createHash } from "node:crypto";
import { coerceErrorMessage } from "openclaw/plugin-sdk/error-runtime";
import {
  buildBatchHeaders,
  extractBatchErrorMessage,
  formatBatchErrorDetail,
  readEmbeddingBatchJsonl,
  readEmbeddingVectors,
  resolveEmbeddingEndpointUrl,
  uploadBatchJsonlFile,
  withRemoteHttpResponse,
  type EmbeddingBatchExecutionParams,
  type EmbeddingBatchStatus,
  type ProviderBatchOutputLine,
} from "openclaw/plugin-sdk/memory-core-host-engine-embeddings";
import {
  assertOkOrThrowProviderError,
  createProviderOperationDeadline,
  readProviderJsonResponse,
  readProviderTextResponse,
  resolveProviderOperationTimeoutMs,
  waitProviderOperationPollInterval,
} from "openclaw/plugin-sdk/provider-http";
import { asOptionalRecord } from "openclaw/plugin-sdk/string-coerce-runtime";
import {
  updateOpenAiBatchJournal,
  type OpenAiBatchJournalContext,
} from "./embedding-batch-journal.js";
import type { OpenAiEmbeddingClient } from "./embedding-provider.js";

export type OpenAiBatchRequest = {
  custom_id: string;
  method: "POST";
  url: "/v1/embeddings";
  body: { model: string; input: string; dimensions?: number; input_type?: string };
};

type OpenAiBatchStatus = EmbeddingBatchStatus & {
  input_file_id?: string;
  metadata?: { source?: string; agent?: string; operation?: string };
};

export type OpenAiBatchReceipt = {
  inputFileId: string;
  batchId?: string;
  operationId: string;
};

const TERMINAL = new Set(["completed", "failed", "expired", "cancelled", "canceled"]);
const MAX_ASYNC_MS = 1500 * 60_000;
const MAX_READ_ATTEMPTS = 3;
const MAX_RECONCILIATION_PAGES = 3;

function diagnostic(error: unknown): string {
  return formatBatchErrorDetail(coerceErrorMessage(error)) ?? "unknown error";
}

function transient(error: unknown): boolean {
  const fields = asOptionalRecord(error);
  if (fields?.code === "OPENAI_BATCH_ASYNC_DEADLINE") {
    return false;
  }
  if (fields?.code === "OPENAI_BATCH_READ_TIMEOUT") {
    return true;
  }
  if (fields?.name === "AbortError") {
    return false;
  }
  const status = fields?.status;
  return (
    fields?.name === "TimeoutError" ||
    (typeof status === "number" &&
      ([408, 409, 425, 429].includes(status) || (status >= 500 && status <= 599))) ||
    /ECONNRESET|ECONNREFUSED|ETIMEDOUT|EAI_AGAIN|fetch failed|network error|timed out/i.test(
      coerceErrorMessage(error),
    )
  );
}

class OpenAiBatchUploadRejectedError extends Error {}
class OpenAiBatchConclusiveItemFailure extends Error {}

export class OpenAiBatchRecoveryBlockedError extends Error {
  readonly recoveryBlocked = true;
}

/** Durable submission facts; successful vectors remain host-owned. */
export class OpenAiBatchRecovery {
  readonly receipts: OpenAiBatchReceipt[] = [];
  private readonly deadline;

  constructor(
    private readonly client: OpenAiEmbeddingClient,
    private readonly agentId: string,
    private readonly options: EmbeddingBatchExecutionParams,
    private readonly journal?: OpenAiBatchJournalContext,
  ) {
    this.deadline = createProviderOperationDeadline({
      label: "openai batch recovery",
      timeoutMs: Math.min(MAX_ASYNC_MS, options.timeoutMs),
    });
  }

  private remaining(): number {
    this.options.signal?.throwIfAborted();
    try {
      return resolveProviderOperationTimeoutMs({
        deadline: this.deadline,
        defaultTimeoutMs: Math.min(MAX_ASYNC_MS, this.options.timeoutMs),
      });
    } catch (error) {
      throw Object.assign(
        new Error("OpenAI cumulative asynchronous Batch budget exhausted", { cause: error }),
        { code: "OPENAI_BATCH_ASYNC_DEADLINE" },
      );
    }
  }

  private async fetch<T>(
    path: string,
    parse: (response: Response) => Promise<T>,
    init?: RequestInit,
    query?: Record<string, string>,
  ): Promise<T> {
    const url = new URL(resolveEmbeddingEndpointUrl(this.client.baseUrl, path));
    for (const [key, value] of Object.entries(query ?? {})) {
      url.searchParams.set(key, value);
    }
    const timeoutSignal = AbortSignal.timeout(Math.min(120_000, this.remaining()));
    const signal = this.options.signal
      ? AbortSignal.any([this.options.signal, timeoutSignal])
      : timeoutSignal;
    try {
      return await withRemoteHttpResponse({
        url: url.toString(),
        ssrfPolicy: this.client.ssrfPolicy,
        fetchImpl: this.client.fetchImpl,
        signal,
        ...(init ? { maxRedirects: 0 } : {}),
        init: { ...init, headers: buildBatchHeaders(this.client, { json: true }) },
        onResponse: async (response) => {
          await assertOkOrThrowProviderError(response, `openai.batch-${init ? "create" : "read"}`);
          return await parse(response);
        },
      });
    } catch (error) {
      this.options.signal?.throwIfAborted();
      if (!init && signal.aborted) {
        this.remaining();
        throw Object.assign(new Error("OpenAI Batch read timed out", { cause: error }), {
          code: "OPENAI_BATCH_READ_TIMEOUT",
        });
      }
      throw error;
    }
  }

  private async read<T>(
    path: string,
    parse: (response: Response) => Promise<T>,
    query?: Record<string, string>,
  ): Promise<T> {
    for (let attempt = 1; ; attempt++) {
      try {
        return await this.fetch(path, parse, undefined, query);
      } catch (error) {
        if (attempt >= MAX_READ_ATTEMPTS || !transient(error)) {
          throw error;
        }
        await waitProviderOperationPollInterval({
          deadline: this.deadline,
          pollIntervalMs: 300 * attempt,
        });
      }
    }
  }

  async submit(group: OpenAiBatchRequest[]): Promise<OpenAiBatchStatus[]> {
    try {
      return await this.submitDurably(group);
    } catch (error) {
      if (
        error instanceof OpenAiBatchRecoveryBlockedError ||
        error instanceof OpenAiBatchUploadRejectedError
      ) {
        throw error;
      }
      throw new OpenAiBatchRecoveryBlockedError(
        "OpenAI Batch durable submission unresolved; no create retry or synchronous fallback",
        { cause: error },
      );
    }
  }

  private async submitDurably(group: OpenAiBatchRequest[]): Promise<OpenAiBatchStatus[]> {
    const journal = this.journal ? Object.freeze({ ...this.journal }) : undefined;
    if (
      !journal ||
      !journal.migrationId ||
      !journal.sourceRevision ||
      !journal.accountId ||
      journal.route !== this.client.baseUrl ||
      group.length === 0 ||
      !Number.isInteger(this.client.outputDimensionality) ||
      this.client.outputDimensionality! <= 0 ||
      group.some(
        (request) =>
          request.body.model !== this.client.model ||
          request.body.dimensions !== this.client.outputDimensionality,
      )
    ) {
      throw new Error(
        "OpenAI Batch requires controller-provisioned journal and exact route/scope/account identity",
      );
    }
    const hash = (value: unknown) =>
      createHash("sha256").update(JSON.stringify(value)).digest("hex");
    const operationId = hash([journal.migrationId, group.map((request) => request.custom_id)]);
    const identity = JSON.stringify({
      migration: journal.migrationId,
      source: journal.sourceRevision,
      account: journal.accountId,
      route: journal.route,
      agent: this.agentId,
      model: this.client.model,
      dimensions: this.client.outputDimensionality ?? null,
      inputHash: hash(group),
    });
    const update = (transition?: { inputFileId: string; batchId?: string }) =>
      updateOpenAiBatchJournal({ path: journal.path, operationId, identity, transition });
    const admission = await update();
    const saved = admission.receipt;
    if (!admission.inserted) {
      if (saved.phase === "upload-rejected") {
        // Replay only the durable negative discriminator, never the parent upload.
        throw new OpenAiBatchUploadRejectedError(
          "openai batch file upload failed: 413 durable rejection",
        );
      }
      if (!saved.inputFileId) {
        throw new Error(
          "OpenAI Batch prior upload outcome unknown; manual reconciliation required",
        );
      }
      const receipt: OpenAiBatchReceipt = {
        operationId,
        inputFileId: saved.inputFileId,
        ...(saved.batchId ? { batchId: saved.batchId } : {}),
      };
      this.receipts.push(receipt);
      if (saved.phase === "accepted" && saved.batchId) {
        const status = await this.read(`batches/${encodeURIComponent(saved.batchId)}`, (response) =>
          readProviderJsonResponse<OpenAiBatchStatus>(response, "openai.batch-status"),
        );
        if (status.id !== saved.batchId) {
          throw new Error("OpenAI resumed Batch ID mismatch");
        }
        return [status];
      }
      const matches = await this.reconcile(receipt);
      if (matches.length !== 1) {
        throw new Error("OpenAI Batch create remains UNKNOWN after bounded reconciliation");
      }
      await update({ inputFileId: saved.inputFileId, batchId: matches[0]!.id! });
      return matches;
    }
    // A committed upload-unknown row exists before even the first provider call.
    let inputFileId: string;
    try {
      inputFileId = await uploadBatchJsonlFile({
        client: this.client,
        requests: group,
        errorPrefix: "openai batch file upload failed",
        signal: this.options.signal
          ? AbortSignal.any([
              this.options.signal,
              AbortSignal.timeout(Math.min(120_000, this.remaining())),
            ])
          : AbortSignal.timeout(Math.min(120_000, this.remaining())),
      });
    } catch (error) {
      // Only the helper's exact HTTP 413 rejection is a known negative upload.
      // Generic errors, missing IDs and every create failure remain UNKNOWN.
      const message = coerceErrorMessage(error);
      if (/^openai batch file upload failed: 413\b/.test(message)) {
        await updateOpenAiBatchJournal({
          path: journal.path,
          operationId,
          identity,
          rejectedUpload: true,
        });
        throw new OpenAiBatchUploadRejectedError(message, { cause: error });
      }
      throw error;
    }
    const receipt: OpenAiBatchReceipt = { inputFileId, operationId };
    this.receipts.push(receipt);
    await update({ inputFileId });
    let status: OpenAiBatchStatus;
    try {
      status = await this.fetch(
        "batches",
        (response) => readProviderJsonResponse<OpenAiBatchStatus>(response, "openai.batch-create"),
        {
          method: "POST",
          body: JSON.stringify({
            input_file_id: inputFileId,
            endpoint: "/v1/embeddings",
            completion_window: "24h",
            metadata: { source: "openclaw-memory", agent: this.agentId, operation: operationId },
          }),
        },
      );
      if (typeof status?.id !== "string" || !status.id.trim()) {
        throw new Error("missing batch id");
      }
    } catch (error) {
      const matches = await this.reconcile(receipt);
      if (matches.length !== 1) {
        throw new OpenAiBatchRecoveryBlockedError(
          "OpenAI Batch create remains UNKNOWN; bounded list miss is not absence; synchronous fallback forbidden",
          { cause: error },
        );
      }
      status = matches[0]!;
    }
    // Failure here preserves UNKNOWN, rather than retrying create or downgrading to sync.
    await update({ inputFileId, batchId: status.id! });
    receipt.batchId = status.id;
    return [status];
  }

  private async reconcile(receipt: OpenAiBatchReceipt): Promise<OpenAiBatchStatus[]> {
    const matches = new Map<string, OpenAiBatchStatus>();
    let after: string | undefined;
    for (let page = 0; page < MAX_RECONCILIATION_PAGES; page++) {
      const result = await this.read(
        "batches",
        (response) =>
          readProviderJsonResponse<{ data?: OpenAiBatchStatus[]; has_more?: boolean }>(
            response,
            "openai.batch-list",
          ),
        { limit: "100", ...(after ? { after } : {}) },
      );
      const data = Array.isArray(result.data) ? result.data : [];
      for (const status of data) {
        if (
          typeof status.id === "string" &&
          status.id &&
          status.input_file_id === receipt.inputFileId &&
          status.metadata?.operation === receipt.operationId &&
          status.metadata.source === "openclaw-memory" &&
          status.metadata.agent === this.agentId
        ) {
          if (!matches.has(status.id)) {
            matches.set(status.id, status);
            if (!receipt.batchId) {
              receipt.batchId = status.id;
            } else {
              this.receipts.push({ ...receipt, batchId: status.id });
            }
          }
        }
      }
      const next = data.at(-1)?.id;
      if (!result.has_more || !next || next === after) {
        break;
      }
      after = next;
    }
    return [...matches.values()].toSorted(
      (left, right) => Number(Boolean(right.output_file_id)) - Number(Boolean(left.output_file_id)),
    );
  }

  async collect(
    initial: OpenAiBatchStatus,
    group: OpenAiBatchRequest[],
    vectors: Map<string, number[]>,
  ): Promise<void> {
    try {
      await this.collectAccepted(initial, group, vectors);
    } catch (error) {
      if (error instanceof OpenAiBatchConclusiveItemFailure) {
        throw error;
      }
      // An accepted job is not failed work merely because collection stopped.
      // Preserve the no-sync-fallback classification across the adapter boundary.
      throw new OpenAiBatchRecoveryBlockedError(coerceErrorMessage(error), { cause: error });
    }
  }

  private async collectAccepted(
    initial: OpenAiBatchStatus,
    group: OpenAiBatchRequest[],
    vectors: Map<string, number[]>,
  ): Promise<void> {
    const batchId = initial.id!;
    const problems: string[] = [];
    const conclusivelyFailed = new Set<string>();
    const ambiguousFailures = new Set<string>();
    const expected = new Set(group.map((request) => request.custom_id));
    let status = initial;
    let lastTransient: unknown;
    const remaining = () => {
      try {
        return this.remaining();
      } catch {
        throw new Error(
          `openai batch ${batchId} timed out after ${Math.min(MAX_ASYNC_MS, this.options.timeoutMs)}ms`,
          lastTransient ? { cause: lastTransient } : undefined,
        );
      }
    };
    let delay = Math.min(this.options.pollIntervalMs, remaining());
    while (!TERMINAL.has(status.status ?? "")) {
      if (!this.options.wait) {
        break;
      }
      remaining();
      this.options.debug?.(`openai batch ${batchId} ${status.status ?? "unknown"}; waiting`, {});
      await waitProviderOperationPollInterval({ deadline: this.deadline, pollIntervalMs: delay });
      remaining();
      try {
        status = await this.fetch(`batches/${encodeURIComponent(batchId)}`, (response) =>
          readProviderJsonResponse<OpenAiBatchStatus>(response, "openai.batch-status"),
        );
        if (status.id !== undefined && status.id !== batchId) {
          throw new Error("batch id mismatch");
        }
        lastTransient = undefined;
      } catch (error) {
        if (!transient(error)) {
          throw error;
        }
        lastTransient = error;
        this.options.debug?.(`openai batch ${batchId} status check failed: ${diagnostic(error)}`);
      }
      delay = Math.min(5 * 60_000, delay * 2);
    }
    if (status.output_file_id) {
      await this.read(
        `files/${encodeURIComponent(status.output_file_id)}/content`,
        async (response) => {
          if (!response.body) throw new Error("openai batch output has no readable body");
          const seen = new Set<string>();
          await readEmbeddingBatchJsonl<ProviderBatchOutputLine>(response, {
            label: "openai.batch-file-content",
            maxRecords: group.length,
            onRecord: (line) => {
              const id = line.custom_id;
              if (!id || !expected.has(id)) return true;
              if (seen.has(id)) {
                ambiguousFailures.add(id);
                return true;
              }
              seen.add(id);
              if (vectors.has(id)) {
                return !group.every((request) => vectors.has(request.custom_id));
              }
              const body = line.response?.body;
              const dimensions =
                this.client.outputDimensionality ?? vectors.values().next().value?.length;
              try {
                if (
                  line.error ||
                  (line.response?.status_code ?? 0) < 200 ||
                  (line.response?.status_code ?? 0) >= 300
                ) {
                  const code = line.response?.status_code;
                  if (typeof code === "number" ? code < 200 || code >= 300 : Boolean(line.error)) {
                    conclusivelyFailed.add(id);
                  }
                  throw new Error(`${id}: failed embedding response`);
                }
                const [vector] = readEmbeddingVectors(
                  typeof body === "object" ? body?.data : undefined,
                  1,
                  `openai batch response ${id}`,
                );
                if (!vector || (dimensions !== undefined && vector.length !== dimensions)) {
                  throw Object.assign(
                    new Error(`openai batch response ${id}: invalid embedding dimensions`),
                    { code: "INVALID_EMBEDDING_RESPONSE" },
                  );
                }
                vectors.set(id, vector);
              } catch (error) {
                if (!conclusivelyFailed.has(id)) ambiguousFailures.add(id);
                problems.push(diagnostic(error));
              }
              return !group.every((request) => vectors.has(request.custom_id));
            },
          });
        },
      );
    }
    if (group.every((request) => vectors.has(request.custom_id))) {
      return;
    }
    let detail: string | undefined = problems[0];
    if (status.error_file_id) {
      try {
        const text = await this.read(
          `files/${encodeURIComponent(status.error_file_id)}/content`,
          (response) => readProviderTextResponse(response, "openai.batch-file-content"),
        );
        // Preserve the text reader's byte bound and the input-sized physical row budget.
        const rows = text.split("\n");
        if (rows.at(-1) === "") rows.pop();
        if (rows.length > group.length)
          throw new Error("openai batch error file exceeds record budget");
        const records = rows
          .filter((line) => line.trim())
          .map((line) => {
            const parsed = asOptionalRecord(JSON.parse(line));
            if (!parsed || Array.isArray(parsed)) {
              throw new Error("malformed batch error record");
            }
            return parsed;
          });
        const diagnosticRecords = records.map((record) => {
          const error = asOptionalRecord(record.error);
          const response = asOptionalRecord(record.response);
          const body = asOptionalRecord(response?.body);
          const nestedError = asOptionalRecord(body?.error);
          return {
            error: { message: typeof error?.message === "string" ? error.message : undefined },
            response: {
              message: typeof response?.message === "string" ? response.message : undefined,
              body:
                typeof response?.body === "string"
                  ? response.body
                  : {
                      error: {
                        message:
                          typeof nestedError?.message === "string"
                            ? nestedError.message
                            : undefined,
                      },
                    },
            },
          };
        });
        detail = extractBatchErrorMessage(diagnosticRecords);
        const errorIds = new Set<string>();
        for (const record of records) {
          const line = asOptionalRecord(record);
          const id = line?.custom_id;
          const response = asOptionalRecord(line?.response);
          const code = response?.status_code;
          if (typeof id === "string" && expected.has(id)) {
            if (errorIds.has(id)) ambiguousFailures.add(id);
            errorIds.add(id);
            if (typeof code === "number" && code >= 200 && code < 300) ambiguousFailures.add(id);
            if (typeof code === "number" ? code < 200 || code >= 300 : Boolean(line?.error)) {
              conclusivelyFailed.add(id);
            }
          }
        }
      } catch (error) {
        throw new Error("openai batch declared error file remains unreadable or incomplete", {
          cause: error,
        });
      }
    }
    const message = `openai batch ${batchId} ${status.status ?? "unknown"}: missing or invalid embedding responses${detail ? `; ${formatBatchErrorDetail(detail)}` : ""}`;
    if (
      TERMINAL.has(status.status ?? "") &&
      group.every(
        (request) =>
          vectors.has(request.custom_id) ||
          (conclusivelyFailed.has(request.custom_id) && !ambiguousFailures.has(request.custom_id)),
      )
    ) {
      // Existing host recovery is allowed only for explicitly failed terminal records.
      throw new OpenAiBatchConclusiveItemFailure(message);
    }
    throw new Error(message);
  }
}
