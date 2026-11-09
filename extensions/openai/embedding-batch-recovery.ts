import { randomUUID } from "node:crypto";
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

/** In-run remote facts only. Successful vectors belong to the host's cache/checkpoint owner. */
export class OpenAiBatchRecovery {
  readonly receipts: OpenAiBatchReceipt[] = [];
  private readonly deadline;

  constructor(
    private readonly client: OpenAiEmbeddingClient,
    private readonly agentId: string,
    private readonly options: EmbeddingBatchExecutionParams,
  ) {
    this.deadline = createProviderOperationDeadline({
      label: "openai batch recovery",
      timeoutMs: Math.min(MAX_ASYNC_MS, options.timeoutMs),
    });
  }

  private remaining(): number {
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
    const signal = AbortSignal.timeout(Math.min(120_000, this.remaining()));
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
    const inputFileId = await uploadBatchJsonlFile({
      client: this.client,
      requests: group,
      errorPrefix: "openai batch file upload failed",
      signal: AbortSignal.timeout(Math.min(120_000, this.remaining())),
    });
    const receipt: OpenAiBatchReceipt = { inputFileId, operationId: randomUUID() };
    this.receipts.push(receipt);
    try {
      const status = await this.fetch(
        "batches",
        (response) => readProviderJsonResponse<OpenAiBatchStatus>(response, "openai.batch-create"),
        {
          method: "POST",
          body: JSON.stringify({
            input_file_id: inputFileId,
            endpoint: "/v1/embeddings",
            completion_window: "24h",
            metadata: {
              source: "openclaw-memory",
              agent: this.agentId,
              operation: receipt.operationId,
            },
          }),
        },
      );
      if (typeof status?.id !== "string" || !status.id.trim()) {
        throw new Error("missing batch id");
      }
      receipt.batchId = status.id;
      return [status];
    } catch (error) {
      this.options.debug?.("memory embeddings: reconciling uncertain OpenAI Batch creation", {
        inputFileId,
      });
      try {
        const matches = await this.reconcile(receipt);
        if (matches.length > 0) {
          return matches;
        }
      } catch (reconciliationError) {
        this.options.debug?.("memory embeddings: OpenAI Batch reconciliation unavailable", {
          inputFileId,
          error: diagnostic(reconciliationError),
        });
      }
      throw new Error(
        `openai batch submission outcome unknown (input_file_id=${inputFileId}); bounded reconciliation could not establish acceptance; synchronous recovery may duplicate accepted work: ${diagnostic(error)}`,
        { cause: error },
      );
    }
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
    const batchId = initial.id!;
    const problems: string[] = [];
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
      const expected = new Set(group.map((request) => request.custom_id));
      await this.read(
        `files/${encodeURIComponent(status.output_file_id)}/content`,
        async (response) => {
          const seen = new Set<string>();
          await readEmbeddingBatchJsonl<ProviderBatchOutputLine>(response, {
            label: "openai.batch-file-content",
            maxRecords: group.length,
            onRecord: (line) => {
              const id = line.custom_id;
              if (!id || !expected.has(id) || seen.has(id)) {
                return true;
              }
              seen.add(id);
              if (vectors.has(id)) {
                return seen.size < expected.size;
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
                  throw new Error(`${id}: failed embedding response`);
                }
                const [vector] = readEmbeddingVectors(
                  typeof body === "object" ? body?.data : undefined,
                  1,
                  `openai batch response ${id}`,
                  dimensions,
                );
                vectors.set(id, vector!);
              } catch (error) {
                problems.push(diagnostic(error));
              }
              return seen.size < expected.size;
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
        detail = extractBatchErrorMessage(
          text
            .split("\n")
            .filter(Boolean)
            .map((line) => JSON.parse(line)),
        );
      } catch (error) {
        detail = diagnostic(error);
      }
    }
    throw new Error(
      `openai batch ${batchId} ${status.status ?? "unknown"}: missing or invalid embedding responses${detail ? `; ${formatBatchErrorDetail(detail)}` : ""}`,
    );
  }
}
