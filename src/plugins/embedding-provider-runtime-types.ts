/** One text chunk submitted through a provider-owned asynchronous embedding batch. */
export type EmbeddingBatchChunk = {
  text: string;
  /** Stable native source/chunk location, required only for durable candidate batching. */
  sourceKey?: string;
  /** Native content hash, required only for durable candidate batching. */
  hash?: string;
};

/** Host-controlled execution parameters for an asynchronous embedding batch. */
export type EmbeddingBatchOptions = {
  agentId: string;
  chunks: EmbeddingBatchChunk[];
  wait: boolean;
  concurrency: number;
  pollIntervalMs: number;
  timeoutMs: number;
  debug: (message: string, data?: Record<string, unknown>) => void;
};

/** Validated partial results; the host recovers only null positions with the same provider. */
export type EmbeddingBatchPartialResult = {
  kind: "partial";
  embeddings: Array<number[] | null>;
  reason: string;
};

export type EmbeddingBatchResult = number[][] | EmbeddingBatchPartialResult;

/** Provider-owned asynchronous batching capability, independent of host runtime metadata. */
export type EmbeddingProviderBatchRuntime = {
  /** Invoked only through the native registry's exact provider/runtime owner. */
  withCandidateBatch?: <T>(
    admission: EmbeddingCandidateAdmission,
    run: (batch: EmbeddingProviderBatchRuntime["batchEmbed"], identity: EmbeddingCandidateControllerIdentity) => Promise<T>,
  ) => Promise<T>;
  /** Returns one vector per chunk in input order, or null for fallback unless fail-closed. */
  batchEmbed: (options: EmbeddingBatchOptions) => Promise<number[][] | null>;
  /** Optional selective-recovery capability; legacy batchEmbed keeps its original return shape. */
  batchEmbedPartial?: (options: EmbeddingBatchOptions) => Promise<EmbeddingBatchResult | null>;
  /** Only true enables batching across dirty files; false or omission retains per-file batches. */
  sourceWideBatchEmbed?: boolean;
  /** Never replay a failed invocation or fall back wholesale; explicit partial results recover selectively. */
  batchFailureMode?: "fail-closed";
};

/** Candidate-only durable admission. Account/source/spend authorization is external. */
export type EmbeddingCandidateAdmission = {
  agentId: string;
  journal: { path: string; migrationId: string; sourceRevision: string; accountId: string; route: string };
  expected: { model: string; dimensions: number };
};
export type EmbeddingCandidateControllerIdentity = EmbeddingCandidateAdmission & { identity: string };
