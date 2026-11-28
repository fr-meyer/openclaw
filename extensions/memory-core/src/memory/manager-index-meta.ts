import type { EmbeddingCandidateControllerIdentity } from "openclaw/plugin-sdk/embedding-provider-runtime-contract";
import type { MemorySource } from "openclaw/plugin-sdk/memory-core-host-engine-storage";
import type { MemoryShadowConnection } from "./manager-shadow-task.js";

/** Candidate export identity, never authority to activate an index. */
export type MemoryCandidateStamp = {
  version?: 1;
  sourceFence?: string;
  controller?: EmbeddingCandidateControllerIdentity;
  cacheFileIdentity?: MemoryShadowConnection["fileIdentity"];
  candidateFileIdentity?: MemoryShadowConnection["fileIdentity"];
  operationId: string;
  phase: "building" | "complete";
  servingDatabasePath: string;
  cacheDatabasePath: string;
  servingFileIdentity: MemoryShadowConnection["fileIdentity"];
};

export type MemoryIndexMeta = {
  candidate?: MemoryCandidateStamp;
  model: string;
  provider: string;
  providerKey?: string;
  sources?: MemorySource[];
  scopeHash?: string;
  chunkTokens: number;
  chunkOverlap: number;
  chunkingVersion?: number;
  embeddingInputFormatVersion?: number;
  vectorDims?: number;
  ftsTokenizer?: string;
  provenanceVersion?: number;
};
