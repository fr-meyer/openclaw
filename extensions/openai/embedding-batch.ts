import { coerceErrorMessage } from "openclaw/plugin-sdk/error-runtime";
import {
  buildEmbeddingBatchGroupOptions,
  EMBEDDING_BATCH_ENDPOINT,
  formatBatchErrorDetail,
  runEmbeddingBatchGroups,
  type EmbeddingBatchExecutionParams,
} from "openclaw/plugin-sdk/memory-core-host-engine-embeddings";
import {
  OpenAiBatchRecovery,
  type OpenAiBatchReceipt,
  type OpenAiBatchRequest,
} from "./embedding-batch-recovery.js";
import type { OpenAiEmbeddingClient } from "./embedding-provider.js";

export const OPENAI_BATCH_ENDPOINT = EMBEDDING_BATCH_ENDPOINT;
const OPENAI_BATCH_MAX_REQUESTS = 50000;
// Leave headroom below the provider's 200 MB input-file limit.
const OPENAI_BATCH_MAX_JSONL_BYTES = 190 * 1024 * 1024;

/** Validated in-run successes remain available even when remote work only partly completes. */
export class OpenAiEmbeddingBatchError extends Error {
  constructor(
    readonly embeddings: Map<string, number[]>,
    readonly batchReceipts: OpenAiBatchReceipt[],
    cause: unknown,
  ) {
    const ids = batchReceipts
      .map(
        ({ inputFileId, batchId }) =>
          `input_file_id=${inputFileId} batch_id=${batchId ?? "unknown"}`,
      )
      .join("; ");
    super(`${coerceErrorMessage(cause)}${ids ? `; reconciliation IDs: ${ids}` : ""}`, { cause });
    Object.defineProperty(this, "embeddings", { value: embeddings, enumerable: false });
  }
}

function uploadTooLarge(error: unknown): boolean {
  const message = coerceErrorMessage(error);
  return (
    /openai batch file upload failed/i.test(message) &&
    /\b413\b|payload too large|request body too large|file too large|maximum allowed|max(?:imum)? (?:body|payload|file) (?:size )?(?:exceeded|limit)/i.test(
      message,
    )
  );
}

export async function runOpenAiEmbeddingBatches(
  params: {
    openAi: OpenAiEmbeddingClient;
    agentId: string;
    requests: OpenAiBatchRequest[];
    maxJsonlBytes?: number;
  } & EmbeddingBatchExecutionParams,
): Promise<Map<string, number[]>> {
  const ids = new Set(params.requests.map((request) => request.custom_id));
  if (ids.size !== params.requests.length || ids.has("")) {
    throw new Error("OpenAI embedding batch requires unique nonempty input IDs");
  }
  if (params.requests.some((request) => request.body.model !== params.openAi.model)) {
    throw new Error("OpenAI embedding batch model differs from its provider identity");
  }
  const recovery = new OpenAiBatchRecovery(params.openAi, params.agentId, params);
  const embeddings = new Map<string, number[]>();
  const failures: unknown[] = [];
  try {
    await runEmbeddingBatchGroups({
      ...buildEmbeddingBatchGroupOptions(params, {
        maxRequests: OPENAI_BATCH_MAX_REQUESTS,
        maxJsonlBytes: params.maxJsonlBytes ?? OPENAI_BATCH_MAX_JSONL_BYTES,
        debugLabel: "memory embeddings: openai batch submit",
      }),
      shouldSplitGroupOnError: uploadTooLarge,
      onSplitGroup: ({ error, group, parts, depth }) => {
        params.debug?.("memory embeddings: openai batch upload too large; splitting group", {
          requests: group.length,
          parts: parts.map((part) => part.length),
          depth,
          error: formatBatchErrorDetail(coerceErrorMessage(error)),
        });
      },
      runGroup: async ({ group }) => {
        try {
          const statuses = await recovery.submit(group);
          for (const status of statuses) {
            try {
              await recovery.collect(status, group, embeddings);
            } catch (error) {
              failures.push(error);
            }
            if (group.every((request) => embeddings.has(request.custom_id))) {
              break;
            }
          }
        } catch (error) {
          if (group.length > 1 && uploadTooLarge(error)) {
            throw error;
          }
          failures.push(error);
        }
      },
    });
  } catch (error) {
    failures.push(error);
  }
  if (embeddings.size !== params.requests.length) {
    throw new OpenAiEmbeddingBatchError(
      embeddings,
      recovery.receipts,
      failures[0] ?? new Error("OpenAI batch missing embedding responses"),
    );
  }
  return embeddings;
}
