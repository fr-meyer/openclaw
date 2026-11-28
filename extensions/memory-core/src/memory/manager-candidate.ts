import type { MemoryIndexMeta } from "./manager-index-meta.js";
import type { MemoryShadowConnection } from "./manager-shadow-task.js";

export type { MemoryCandidateStamp } from "./manager-index-meta.js";

export type MemoryCandidateRequest = {
  controller?: { accountId: string; route: string; sourceRevision: string };
  operationId: string;
  expected: { provider: string; model: string; dimensions: number };
  signal?: AbortSignal;
};

export type MemoryCandidateManifest = {
  inspection?: {
    status: "unverified-inspection-only";
    openedIdentity: "unavailable";
    cacheIdentity: MemoryShadowConnection["fileIdentity"];
    cacheStatus: "path-identity-only";
  };
  databasePath: string;
  fileIdentity: MemoryShadowConnection["fileIdentity"];
  meta: MemoryIndexMeta;
  activation: "manual-only";
};

export class MemoryCandidateBuildError extends Error {
  constructor(
    readonly databasePath: string,
    readonly disposition: "retained-unreconciled" | "retained-complete",
    cause: unknown,
  ) {
    super("Memory candidate retained; reconcile its cache/provider journal before retry", {
      cause,
    });
    this.name = "MemoryCandidateBuildError";
  }
}
