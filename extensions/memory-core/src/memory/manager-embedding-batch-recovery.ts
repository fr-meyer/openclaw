import type { EmbeddingBatchResult } from "openclaw/plugin-sdk/embedding-provider-runtime-contract";
import { formatErrorMessage } from "openclaw/plugin-sdk/error-runtime";
import { isValidMemoryEmbedding } from "./manager-embedding-cache.js";

/** Host-owned selective recovery. Successful vectors survive a later recovery failure. */
export async function recoverMemoryEmbeddingBatch(params: {
  partial: Exclude<EmbeddingBatchResult, number[][]>;
  count: number;
  dimensions?: number;
  assertCurrent: () => void;
  persist: (indices: number[], vectors: number[][]) => Promise<void>;
  recover: (
    indices: number[],
    onSuccess: (indices: number[], vectors: number[][]) => void,
  ) => Promise<number[][]>;
}): Promise<number[][]> {
  if (params.partial.embeddings.length !== params.count) {
    throw new Error("partial embedding batch returned an invalid input count");
  }
  let dimensions =
    params.dimensions ??
    params.partial.embeddings.find((v) => v !== null && isValidMemoryEmbedding(v))?.length;
  const vectors = params.partial.embeddings.map((vector) =>
    vector !== null && isValidMemoryEmbedding(vector, dimensions) ? vector : null,
  );
  const completed: number[] = [];
  const missing: number[] = [];
  for (const [index, vector] of vectors.entries()) {
    (vector ? completed : missing).push(index);
  }
  const missingSet = new Set(missing);
  let phase = "persistence";
  const valid = (values: number[][]) => {
    dimensions ??= values[0]?.length;
    return values.every((value) => isValidMemoryEmbedding(value, dimensions));
  };
  try {
    params.assertCurrent();
    if (completed.length > 0) {
      await params.persist(
        completed,
        completed.map((index) => vectors[index]!),
      );
    }
    // Worker admission awaits: do not start network work with stale authority.
    params.assertCurrent();
    if (missing.length === 0) {
      return vectors.map((vector) => vector!);
    }
    phase = "synchronous recovery";
    const recovered = await params.recover(missing, (indices, values) => {
      params.assertCurrent();
      if (indices.length !== values.length || !valid(values)) {
        throw new Error("synchronous embedding recovery returned invalid vectors");
      }
      for (const [position, index] of indices.entries()) {
        if (!missingSet.has(index)) {
          throw new Error("invalid synchronous recovery input index");
        }
        vectors[index] = values[position]!;
      }
    });
    if (recovered.length !== missing.length || !valid(recovered)) {
      throw new Error("synchronous embedding recovery returned invalid vectors");
    }
    for (const [position, index] of missing.entries()) {
      vectors[index] = recovered[position]!;
    }
    params.assertCurrent();
    return vectors.map((vector) => vector!);
  } catch (error) {
    const failure = Object.assign(
      new Error(
        `${phase} failed: ${formatErrorMessage(error)}; validated results retained; ${params.partial.reason}`,
        { cause: error },
      ),
      {
        code:
          phase === "persistence"
            ? "MEMORY_EMBEDDING_PERSISTENCE_FAILED"
            : "MEMORY_EMBEDDING_RECOVERY_FAILED",
      },
    );
    // Keep recovery data available to the caller without serializing vectors into logs.
    Object.defineProperty(failure, "partialEmbeddings", { value: vectors });
    throw failure;
  }
}
