import { isRecord } from "@openclaw/normalization-core/record-coerce";
import type {
  PreparedSessionTranscriptProjection,
  PreparedSessionTranscriptProjectionMetadata,
} from "./session-transcript-projection-rebuild.js";

export type SessionTranscriptReconcileWrite =
  | { kind: "preflight" }
  | { kind: "claim"; plan: PreparedSessionTranscriptProjectionMetadata; claimId: number }
  | { kind: "delete-chunk"; sessionId: string; claimId: number; maxRowsPerTable: number }
  | {
      kind: "active-chunk";
      sessionId: string;
      claimId: number;
      activeRows: PreparedSessionTranscriptProjection["activeRows"];
    }
  | {
      kind: "fts-chunk";
      sessionId: string;
      claimId: number;
      ftsRows: PreparedSessionTranscriptProjection["ftsRows"];
    }
  | { kind: "finalize"; plan: PreparedSessionTranscriptProjectionMetadata; claimId: number }
  | { kind: "orphan-sweep" };

export type SessionTranscriptReconcileWriteResult =
  | { kind: "preflight"; hasWork: boolean }
  | { kind: "claim" | "active-chunk" | "fts-chunk"; owned: boolean }
  | { kind: "delete-chunk"; owned: boolean; hasMore: boolean }
  | { kind: "finalize"; finalized: boolean; sessionKey?: string }
  | { kind: "orphan-sweep" };

export type SessionTranscriptReconcileWriteKind = SessionTranscriptReconcileWrite["kind"];
export type SessionTranscriptReconcileWriteResultFor<
  K extends SessionTranscriptReconcileWriteKind,
> = SessionTranscriptReconcileWriteResult & { kind: K };

/** Private commit facts are evidence of settlement, never a substitute for live admission. */
export function isSessionTranscriptReconcileWriteResult<
  K extends SessionTranscriptReconcileWriteKind,
>(value: unknown, kind: K): value is SessionTranscriptReconcileWriteResultFor<K> {
  if (!isRecord(value) || value.kind !== kind) {
    return false;
  }
  switch (kind) {
    case "preflight":
      return typeof value.hasWork === "boolean";
    case "claim":
    case "active-chunk":
    case "fts-chunk":
      return typeof value.owned === "boolean";
    case "delete-chunk":
      return typeof value.owned === "boolean" && typeof value.hasMore === "boolean";
    case "finalize":
      return (
        typeof value.finalized === "boolean" &&
        (value.sessionKey === undefined ||
          (value.finalized && typeof value.sessionKey === "string"))
      );
    case "orphan-sweep":
      return true;
  }
}
