// Google plugin module implements embedding batch behavior.
import crypto from "node:crypto";
import { createSubsystemLogger } from "openclaw/plugin-sdk/logging-core";
import {
  buildEmbeddingBatchGroupOptions,
  runEmbeddingBatchGroups,
  buildBatchHeaders,
  debugEmbeddingsLog,
  EmbeddingBatchUnavailableError,
  formatBatchErrorDetail,
  normalizeBatchBaseUrl,
  readEmbeddingBatchJsonl,
  sanitizeAndNormalizeEmbedding,
  withRemoteHttpResponse,
  type EmbeddingBatchExecutionParams,
} from "openclaw/plugin-sdk/memory-core-host-engine-embeddings";
import {
  assertOkOrThrowProviderError,
  createProviderOperationDeadline,
  createProviderHttpError,
  readProviderJsonObjectResponse,
  resolveProviderOperationTimeoutMs,
  waitProviderOperationPollInterval,
} from "openclaw/plugin-sdk/provider-http";
import type { GeminiEmbeddingClient, GeminiTextEmbeddingRequest } from "./embedding-provider.js";
import { parseGeminiAuth } from "./gemini-auth.js";

type GeminiBatchRequest = {
  custom_id: string;
  request: GeminiTextEmbeddingRequest;
};

type GeminiBatchOperation = {
  name?: string;
  done?: boolean;
  metadata?: {
    state?: string;
    output?: {
      responsesFile?: string;
    };
  };
  response?: { responsesFile?: string };
  error?: { code?: number; message?: string };
};

type GeminiBatchState = "pending" | "succeeded" | "failed" | "cancelled" | "expired" | "unknown";

type GeminiBatchOutputLine = {
  // Alternate ids and direct embeddings are shipped compatible-endpoint shapes.
  key?: string;
  custom_id?: string;
  request_id?: string;
  embedding?: { values?: number[] };
  response?: {
    embedding?: { values?: number[] };
    error?: { message?: string };
  };
  error?: { message?: string };
};

const GEMINI_BATCH_MAX_REQUESTS = 50000;
// Tier 2 permits 5M enqueued embedding tokens across active jobs. A 10 MiB JSONL
// ceiling targets roughly 2.5M text tokens at four characters per token, leaving
// substantial headroom for tokenizer variance and JSON overhead. Quota rejections
// still split recursively below as a final fail-safe.
const GEMINI_BATCH_TIER2_ENQUEUED_TOKEN_LIMIT = 5_000_000;
const GEMINI_BATCH_MAX_JSONL_BYTES = 10 * 1024 * 1024;
const GEMINI_BATCH_OUTPUT_DOWNLOAD_MAX_ATTEMPTS = 2;
const log = createSubsystemLogger("memory/embeddings/gemini-batch");

function bindGeminiBatchAuth(client: GeminiEmbeddingClient): GeminiEmbeddingClient {
  const apiKey = client.apiKeys[0];
  if (!apiKey) {
    throw new Error("gemini batch requires an API key");
  }
  // Files and batch operations are credential-scoped. Keep one selected
  // credential for upload, creation, polling, and output download.
  return {
    ...client,
    headers: {
      ...parseGeminiAuth(apiKey).headers,
      ...client.headers,
    },
  };
}

function hashText(text: string): string {
  return crypto.createHash("sha256").update(text).digest("hex");
}

function formatGeminiBatchError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

class GeminiBatchOutputIncompleteError extends Error {}

function isRetryableGeminiBatchOutputError(error: unknown): boolean {
  if (error instanceof GeminiBatchOutputIncompleteError) {
    return true;
  }
  const message = formatGeminiBatchError(error);
  if (/gemini\.batch-file-content\s*\((?:408|409|425|429|500|502|503|504)\)/i.test(message)) {
    return true;
  }
  return /malformed JSONL record|fetch failed|network|socket|stream|terminated|premature|unexpected end/i.test(
    message,
  );
}

function hasProviderHttpStatus(error: unknown): boolean {
  if (!error || typeof error !== "object") {
    return false;
  }
  const candidate = error as { status?: unknown; statusCode?: unknown };
  return typeof candidate.status === "number" || typeof candidate.statusCode === "number";
}

type GeminiBatchSplitReason = "upload-too-large" | "batch-token-quota";

function classifyGeminiBatchSplitError(error: unknown): GeminiBatchSplitReason | null {
  const message = formatGeminiBatchError(error);
  if (
    /gemini\.batch-file-upload/i.test(message) &&
    (/\b413\b/.test(message) ||
      /payload too large/i.test(message) ||
      /request body too large/i.test(message) ||
      /file too large/i.test(message) ||
      /maximum allowed/i.test(message) ||
      /max(?:imum)? (?:body|payload|file) (?:size )?(?:exceeded|limit)/i.test(message))
  ) {
    return "upload-too-large";
  }
  if (
    /gemini\.batch-create\s*\(429\)/i.test(message) &&
    /quota|resource[_ -]?exhausted|enqueued tokens?/i.test(message)
  ) {
    return "batch-token-quota";
  }
  return null;
}

function getGeminiVersionedRouteBase(baseUrl: string, route: "upload" | "download"): string | null {
  const trimmed = baseUrl.replace(/\/$/, "");
  const match = trimmed.match(/^(.*)\/(v\d+(?:alpha|beta)?)$/);
  return match ? `${match[1]}/${route}/${match[2]}` : null;
}

function getGeminiUploadUrl(baseUrl: string): string {
  return getGeminiVersionedRouteBase(baseUrl, "upload") ?? `${baseUrl.replace(/\/$/, "")}/upload`;
}

function getGeminiDownloadUrl(baseUrl: string, fileId: string): string {
  const file = fileId.startsWith("files/") ? fileId : `files/${fileId}`;
  const trimmed = baseUrl.replace(/\/$/, "");
  let officialGoogleOrigin = false;
  try {
    officialGoogleOrigin =
      new URL(trimmed).origin.toLowerCase() === "https://generativelanguage.googleapis.com";
  } catch {
    // Custom base URLs are preserved below.
  }
  const downloadBase = officialGoogleOrigin
    ? (getGeminiVersionedRouteBase(trimmed, "download") ?? trimmed)
    : trimmed;
  return `${downloadBase}/${file}:download?alt=media`;
}

function getGeminiBatchState(operation: GeminiBatchOperation): GeminiBatchState {
  // REST discovery uses BATCH_STATE_* while the public guide and SDK expose
  // JOB_STATE_* for the same operation metadata.
  const rawState = operation.metadata?.state?.replace(/^(?:BATCH|JOB)_STATE_/, "");
  if (rawState === "FAILED") {
    return "failed";
  }
  if (rawState === "CANCELLED" || rawState === "CANCELED") {
    return "cancelled";
  }
  if (rawState === "EXPIRED") {
    return "expired";
  }
  if (operation.error) {
    return "failed";
  }
  if (operation.done === false) {
    return "pending";
  }
  if (operation.done === true) {
    return "succeeded";
  }
  if (rawState === "SUCCEEDED") {
    return "succeeded";
  }
  if (rawState === "PENDING" || rawState === "RUNNING") {
    return "pending";
  }
  return "unknown";
}

function getGeminiBatchOutputFileId(operation: GeminiBatchOperation): string | undefined {
  // Google currently documents response.responsesFile while the official SDK
  // consumes metadata.output.responsesFile. Accept both raw Operation shapes.
  const responseFile = operation.response?.responsesFile;
  const metadataFile = operation.metadata?.output?.responsesFile;
  if (responseFile && metadataFile && responseFile !== metadataFile) {
    throw new Error("gemini batch operation returned conflicting output files");
  }
  return responseFile ?? metadataFile;
}

function buildGeminiUploadBody(params: { jsonl: string; displayName: string }): {
  body: Blob;
  contentType: string;
} {
  const boundary = `openclaw-${hashText(params.displayName)}`;
  const jsonPart = JSON.stringify({
    file: {
      displayName: params.displayName,
      mimeType: "application/jsonl",
    },
  });
  const delimiter = `--${boundary}\r\n`;
  const closeDelimiter = `--${boundary}--\r\n`;
  const parts = [
    `${delimiter}Content-Type: application/json; charset=UTF-8\r\n\r\n${jsonPart}\r\n`,
    `${delimiter}Content-Type: application/jsonl; charset=UTF-8\r\n\r\n${params.jsonl}\r\n`,
    closeDelimiter,
  ];
  const body = new Blob([parts.join("")], { type: "multipart/related" });
  return {
    body,
    contentType: `multipart/related; boundary=${boundary}`,
  };
}

async function submitGeminiBatch(params: {
  gemini: GeminiEmbeddingClient;
  requests: GeminiBatchRequest[];
  agentId: string;
}): Promise<GeminiBatchOperation> {
  const baseUrl = normalizeBatchBaseUrl(params.gemini);
  const jsonl = params.requests
    .map((request) =>
      JSON.stringify({
        key: request.custom_id,
        request: request.request,
      }),
    )
    .join("\n");
  const displayName = `memory-embeddings-${hashText(String(Date.now()))}`;
  const uploadPayload = buildGeminiUploadBody({ jsonl, displayName });

  const uploadUrl = `${getGeminiUploadUrl(baseUrl)}/files?uploadType=multipart`;
  debugEmbeddingsLog("memory embeddings: gemini batch upload", {
    uploadUrl,
    baseUrl,
    requests: params.requests.length,
  });
  const filePayload = await withRemoteHttpResponse({
    url: uploadUrl,
    ssrfPolicy: params.gemini.ssrfPolicy,
    init: {
      method: "POST",
      headers: {
        ...buildBatchHeaders(params.gemini, { json: false }),
        "Content-Type": uploadPayload.contentType,
      },
      body: uploadPayload.body,
    },
    onResponse: async (fileRes) => {
      await assertOkOrThrowProviderError(fileRes, "gemini.batch-file-upload");
      return (await readProviderJsonObjectResponse(fileRes, "gemini.batch-file-upload")) as {
        file?: { name?: string };
      };
    },
  });
  const fileId = filePayload.file?.name;
  if (!fileId) {
    throw new Error("gemini batch file upload failed: missing file id");
  }

  const batchBody = {
    batch: {
      displayName: `memory-embeddings-${params.agentId}`,
      inputConfig: {
        file_name: fileId,
      },
    },
  };

  const batchEndpoint = `${baseUrl}/${params.gemini.modelPath}:asyncBatchEmbedContent`;
  debugEmbeddingsLog("memory embeddings: gemini batch create", {
    batchEndpoint,
    fileId,
  });
  return await withRemoteHttpResponse({
    url: batchEndpoint,
    ssrfPolicy: params.gemini.ssrfPolicy,
    init: {
      method: "POST",
      headers: buildBatchHeaders(params.gemini, { json: true }),
      body: JSON.stringify(batchBody),
    },
    onResponse: async (batchRes) => {
      if (batchRes.status === 404) {
        const cause = await createProviderHttpError(batchRes, "gemini.batch-create");
        throw new EmbeddingBatchUnavailableError(
          "gemini asyncBatchEmbedContent not available for this request",
          { cause },
        );
      }
      await assertOkOrThrowProviderError(batchRes, "gemini.batch-create");
      return (await readProviderJsonObjectResponse(
        batchRes,
        "gemini.batch-create",
      )) as GeminiBatchOperation;
    },
  });
}

async function fetchGeminiBatchStatus(params: {
  gemini: GeminiEmbeddingClient;
  batchName: string;
  signal?: AbortSignal;
}): Promise<GeminiBatchOperation> {
  const baseUrl = normalizeBatchBaseUrl(params.gemini);
  const name = params.batchName.startsWith("batches/")
    ? params.batchName
    : `batches/${params.batchName}`;
  const statusUrl = `${baseUrl}/${name}`;
  debugEmbeddingsLog("memory embeddings: gemini batch status", { statusUrl });
  return await withRemoteHttpResponse({
    url: statusUrl,
    ssrfPolicy: params.gemini.ssrfPolicy,
    signal: params.signal,
    init: {
      headers: buildBatchHeaders(params.gemini, { json: true }),
    },
    onResponse: async (res) => {
      await assertOkOrThrowProviderError(res, "gemini.batch-status");
      return (await readProviderJsonObjectResponse(
        res,
        "gemini.batch-status",
      )) as GeminiBatchOperation;
    },
  });
}

function applyGeminiBatchOutputLine(params: {
  line: GeminiBatchOutputLine;
  remaining: Set<string>;
  errors: string[];
  byCustomId: Map<string, number[]>;
}): void {
  const customId = params.line.key ?? params.line.custom_id ?? params.line.request_id;
  // Only the first response for a submitted id may mutate results.
  if (!customId || !params.remaining.delete(customId)) {
    return;
  }
  const error = params.line.error?.message || params.line.response?.error?.message;
  if (error) {
    params.errors.push(`${customId}: ${error}`);
    return;
  }
  const embedding = sanitizeAndNormalizeEmbedding(
    params.line.embedding?.values ?? params.line.response?.embedding?.values ?? [],
  );
  if (embedding.length === 0) {
    params.errors.push(`${customId}: empty embedding`);
    return;
  }
  params.byCustomId.set(customId, embedding);
}

async function fetchGeminiBatchOutput(params: {
  gemini: GeminiEmbeddingClient;
  fileId: string;
  expectedRecords: number;
  remaining: Set<string>;
  errors: string[];
  byCustomId: Map<string, number[]>;
}): Promise<void> {
  const baseUrl = normalizeBatchBaseUrl(params.gemini);
  const downloadUrl = getGeminiDownloadUrl(baseUrl, params.fileId);
  debugEmbeddingsLog("memory embeddings: gemini batch download", { downloadUrl });
  await withRemoteHttpResponse({
    url: downloadUrl,
    ssrfPolicy: params.gemini.ssrfPolicy,
    init: {
      headers: buildBatchHeaders(params.gemini, { json: true }),
    },
    onResponse: async (res) => {
      await assertOkOrThrowProviderError(res, "gemini.batch-file-content");
      await readEmbeddingBatchJsonl<GeminiBatchOutputLine>(res, {
        label: "gemini.batch-file-content",
        // Retries reread the same immutable output from the beginning. Count the
        // original group size so already-consumed records do not exhaust the cap.
        maxRecords: params.expectedRecords,
        onRecord: (line) => {
          applyGeminiBatchOutputLine({
            line,
            remaining: params.remaining,
            errors: params.errors,
            byCustomId: params.byCustomId,
          });
          return params.errors.length === 0 && params.remaining.size > 0;
        },
      });
    },
  });
}

async function downloadGeminiBatchOutputWithRetry(params: {
  gemini: GeminiEmbeddingClient;
  batchName: string;
  fileId: string;
  group: number;
  groups: number;
  requests: number;
  remaining: Set<string>;
  errors: string[];
  byCustomId: Map<string, number[]>;
  debug?: (message: string, data?: Record<string, unknown>) => void;
}): Promise<void> {
  const context = {
    batchName: params.batchName,
    outputFileId: params.fileId,
    group: params.group,
    groups: params.groups,
    requests: params.requests,
  };
  for (let attempt = 1; attempt <= GEMINI_BATCH_OUTPUT_DOWNLOAD_MAX_ATTEMPTS; attempt += 1) {
    log.info("memory embeddings: gemini batch output download started", {
      ...context,
      attempt,
      maxAttempts: GEMINI_BATCH_OUTPUT_DOWNLOAD_MAX_ATTEMPTS,
      remaining: params.remaining.size,
    });
    params.debug?.("memory embeddings: gemini batch output download started", {
      ...context,
      attempt,
      maxAttempts: GEMINI_BATCH_OUTPUT_DOWNLOAD_MAX_ATTEMPTS,
      remaining: params.remaining.size,
    });
    try {
      await fetchGeminiBatchOutput({
        gemini: params.gemini,
        fileId: params.fileId,
        expectedRecords: params.requests,
        remaining: params.remaining,
        errors: params.errors,
        byCustomId: params.byCustomId,
      });
      if (params.errors.length > 0) {
        log.warn("memory embeddings: gemini batch output contained a provider error", {
          ...context,
          attempt,
          error: formatBatchErrorDetail(params.errors[0]) ?? "unknown error",
        });
        return;
      }
      if (params.remaining.size > 0) {
        throw new GeminiBatchOutputIncompleteError(
          `gemini batch output incomplete: missing ${params.remaining.size} of ${params.requests} responses`,
        );
      }
      log.info("memory embeddings: gemini batch output download completed", {
        ...context,
        attempt,
      });
      params.debug?.("memory embeddings: gemini batch output download completed", {
        ...context,
        attempt,
      });
      return;
    } catch (error) {
      const retryable = isRetryableGeminiBatchOutputError(error);
      const errorMessage = formatBatchErrorDetail(formatGeminiBatchError(error)) ?? "unknown error";
      log.warn("memory embeddings: gemini batch output download failed", {
        ...context,
        attempt,
        maxAttempts: GEMINI_BATCH_OUTPUT_DOWNLOAD_MAX_ATTEMPTS,
        remaining: params.remaining.size,
        retryable,
        error: errorMessage,
      });
      params.debug?.("memory embeddings: gemini batch output download failed", {
        ...context,
        attempt,
        maxAttempts: GEMINI_BATCH_OUTPUT_DOWNLOAD_MAX_ATTEMPTS,
        remaining: params.remaining.size,
        retryable,
        error: errorMessage,
      });
      if (!retryable || attempt === GEMINI_BATCH_OUTPUT_DOWNLOAD_MAX_ATTEMPTS) {
        // Preserve structured ProviderHttpError fields for callers and existing
        // retry/status classification. The preceding durable log carries context.
        if (hasProviderHttpStatus(error)) {
          throw error;
        }
        throw new Error(
          `gemini batch ${params.batchName} output download failed after ${attempt} attempt${attempt === 1 ? "" : "s"}: ${errorMessage}`,
          { cause: error },
        );
      }
      log.warn("memory embeddings: retrying existing Gemini batch output file", {
        ...context,
        nextAttempt: attempt + 1,
      });
    }
  }
}

async function waitForGeminiBatch(params: {
  gemini: GeminiEmbeddingClient;
  batchName: string;
  wait: boolean;
  pollIntervalMs: number;
  timeoutMs: number;
  debug?: (message: string, data?: Record<string, unknown>) => void;
  initial?: GeminiBatchOperation;
}): Promise<{ outputFileId: string }> {
  const deadline = createProviderOperationDeadline({
    label: `gemini batch ${params.batchName}`,
    timeoutMs: params.timeoutMs,
  });
  let current: GeminiBatchOperation | undefined = params.initial;
  while (true) {
    const operation = current
      ? current
      : await fetchGeminiBatchStatus({
          gemini: params.gemini,
          batchName: params.batchName,
          signal: AbortSignal.timeout(
            resolveProviderOperationTimeoutMs({
              deadline,
              defaultTimeoutMs: params.timeoutMs,
            }),
          ),
        });
    const state = getGeminiBatchState(operation);
    if (state === "succeeded") {
      const outputFileId = getGeminiBatchOutputFileId(operation);
      if (!outputFileId) {
        throw new Error(`gemini batch ${params.batchName} completed without output file`);
      }
      return { outputFileId };
    }
    if (state === "failed" || state === "cancelled" || state === "expired") {
      const rawMessage =
        operation.error?.message ??
        (operation.error?.code === undefined ? "unknown error" : `code ${operation.error.code}`);
      throw new Error(
        `gemini batch ${params.batchName} ${state}: ${formatBatchErrorDetail(rawMessage) ?? "unknown error"}`,
      );
    }
    if (!params.wait) {
      throw new Error(
        `gemini batch ${params.batchName} submitted; enable remote.batch.wait to await completion`,
      );
    }
    params.debug?.(
      `gemini batch ${params.batchName} ${state}; waiting up to ${params.pollIntervalMs}ms`,
    );
    await waitProviderOperationPollInterval({
      deadline,
      pollIntervalMs: params.pollIntervalMs,
    });
    current = undefined;
  }
}

export async function runGeminiEmbeddingBatches(
  params: {
    gemini: GeminiEmbeddingClient;
    agentId: string;
    requests: GeminiBatchRequest[];
    maxJsonlBytes?: number;
  } & EmbeddingBatchExecutionParams,
): Promise<Map<string, number[]>> {
  const gemini = bindGeminiBatchAuth(params.gemini);
  return await runEmbeddingBatchGroups({
    ...buildEmbeddingBatchGroupOptions(params, {
      maxRequests: GEMINI_BATCH_MAX_REQUESTS,
      maxJsonlBytes: params.maxJsonlBytes ?? GEMINI_BATCH_MAX_JSONL_BYTES,
      debugLabel: "memory embeddings: gemini batch submit",
    }),
    shouldSplitGroupOnError: (error) => classifyGeminiBatchSplitError(error) !== null,
    onSplitGroup: ({ error, group, parts, depth }) => {
      params.debug?.("memory embeddings: gemini batch rejected; splitting group", {
        requests: group.length,
        parts: parts.map((part) => part.length),
        depth,
        reason: classifyGeminiBatchSplitError(error) ?? "unknown",
        tier2EnqueuedTokenLimit: GEMINI_BATCH_TIER2_ENQUEUED_TOKEN_LIMIT,
        error: formatBatchErrorDetail(formatGeminiBatchError(error)) ?? "unknown error",
      });
    },
    runGroup: async ({ group, groupIndex, groups, byCustomId, pollIntervalMs, timeoutMs }) => {
      const batchInfo = await submitGeminiBatch({
        gemini,
        requests: group,
        agentId: params.agentId,
      });
      const batchName = batchInfo.name ?? "";
      if (!batchName) {
        throw new Error("gemini batch create failed: missing batch name");
      }

      params.debug?.("memory embeddings: gemini batch created", {
        batchName,
        state: getGeminiBatchState(batchInfo),
        group: groupIndex + 1,
        groups,
        requests: group.length,
      });
      log.info("memory embeddings: gemini batch created", {
        batchName,
        state: getGeminiBatchState(batchInfo),
        group: groupIndex + 1,
        groups,
        requests: group.length,
      });

      const completed = await waitForGeminiBatch({
        gemini,
        batchName,
        wait: params.wait,
        pollIntervalMs,
        timeoutMs,
        debug: params.debug,
        initial: batchInfo,
      });
      log.info("memory embeddings: gemini batch output ready", {
        batchName,
        outputFileId: completed.outputFileId,
        group: groupIndex + 1,
        groups,
        requests: group.length,
      });

      const errors: string[] = [];
      const remaining = new Set(group.map((request) => request.custom_id));
      await downloadGeminiBatchOutputWithRetry({
        gemini,
        batchName,
        fileId: completed.outputFileId,
        group: groupIndex + 1,
        groups,
        requests: group.length,
        remaining,
        errors,
        byCustomId,
        debug: params.debug,
      });

      if (errors.length > 0) {
        throw new Error(
          `gemini batch ${batchName} failed: ${formatBatchErrorDetail(errors[0]) ?? "unknown error"}`,
        );
      }
      if (remaining.size > 0) {
        throw new Error(`gemini batch ${batchName} missing ${remaining.size} embedding responses`);
      }
    },
  });
}
