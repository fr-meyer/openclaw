import type { BuildSessionEntryOptions } from "../../../packages/memory-host-sdk/src/host/session-files.js";
import type { PreparedSessionHistoryReadTarget } from "../../gateway/session-history-read.types.js";
import type { SessionRowTranscriptReadParams } from "../../gateway/session-row-transcript-backfill.types.js";
import type { SensitiveTextRedactionSnapshot } from "../../logging/redact.js";
import type { UserTurnTranscriptAdmissionReceipt } from "../../sessions/user-turn-transcript.types.js";
import type { OpenClawRegisteredAgentDatabase } from "../../state/openclaw-agent-db-contract.js";
import type { SessionActivitySummaryBatchInput } from "./activity-summary-source.types.js";
import type { readOwnedWarmSessionSnapshotSync } from "./session-accessor.sqlite-read.js";
import type {
  SessionEntryReadScope,
  SessionTranscriptReadScope,
} from "./session-accessor.types.js";
import type { CanonicalSessionReaderContinuation } from "./session-canonical-key.js";
import type {
  SessionEntryCurrentFacts,
  SessionEntryCurrentSource,
} from "./session-entry-current.types.js";
import type { CapturedSessionEntryReadSource } from "./session-entry-read-source.types.js";
import type { SessionEntryReadWorkerInput } from "./session-entry-read.types.js";
import type { SessionHistoryWorkerRequest } from "./session-history-types.js";

export type SessionSqliteTargetWorkerInput = {
  kind: "sqlite-target";
  storePath: string;
  agentId?: string;
  defaultAgentId?: string;
  env: NodeJS.ProcessEnv;
  registeredDatabases: readonly Pick<OpenClawRegisteredAgentDatabase, "agentId" | "path">[];
};

export type SessionResetRecallWorkerInput = {
  kind: "session-reset-recall";
  scope: {
    agentId: string;
    sessionId: string;
    sessionKey?: string;
    storePath: string;
  };
  admission?: UserTurnTranscriptAdmissionReceipt;
};

/** Compute data only: this message carries no owner admission authority. */
export type SessionEntryProjectionWorkerInput = {
  kind: "session-entry-projection";
  binding: string;
  absPath: string;
  options: { agentId: string; sessionId: string; storePath: string; parseYieldEveryLines?: number };
  snapshot: Extract<
    ReturnType<typeof readOwnedWarmSessionSnapshotSync>,
    { status: "observed-not-atomic" }
  >["value"];
  redaction: SensitiveTextRedactionSnapshot;
};

export type SessionEntryWorkerInput = {
  kind: "session-entry";
  absPath: string;
  options: Omit<BuildSessionEntryOptions, "onTranscriptMessage" | "parseYieldEveryLines"> & {
    agentId: string;
    sessionId: string;
    storePath: string;
  };
  admission?: UserTurnTranscriptAdmissionReceipt;
  redaction: SensitiveTextRedactionSnapshot;
};

export type SessionTranscriptHistoryWorkerInput = {
  kind: "history-page";
  database: { agentId: string; path: string };
  request: SessionHistoryWorkerRequest;
  target: Omit<PreparedSessionHistoryReadTarget, "database">;
  admission?: UserTurnTranscriptAdmissionReceipt;
};

export type SessionPreviewWorkerInput = {
  kind: "session-preview";
  database: { agentId: string; path: string };
  target: {
    agentId: string;
    sessionId: string;
    sessionKey?: string;
    entryValidationKey?: string;
  };
  env?: NodeJS.ProcessEnv;
  maxItems: number;
  maxChars: number;
  admission?: UserTurnTranscriptAdmissionReceipt;
};

export type SessionTitleFieldsWorkerInput = {
  kind: "session-title-fields";
  database: { agentId: string; path: string };
  scope: SessionTranscriptReadScope;
  includeInterSession?: boolean;
  admission?: UserTurnTranscriptAdmissionReceipt;
};

export type SessionActivitySummarySourceWorkerInput = SessionActivitySummaryBatchInput & {
  kind: "session-activity-summary-source";
  database: { agentId: string; path: string };
  admission?: UserTurnTranscriptAdmissionReceipt;
};

export type SessionRowBackfillWorkerInput = {
  kind: "session-row-backfill";
  database: { agentId: string; path: string };
  params: SessionRowTranscriptReadParams;
};

export type SessionEntryCurrentWorkerInput = Omit<SessionEntryReadWorkerInput, "kind"> & {
  kind: "session-entry-current";
  source?: SessionEntryCurrentSource;
};

export type SessionEntryCurrentWorkerResult = {
  kind: "session-entry-current";
  entry: SessionEntryCurrentFacts | undefined;
  source?: CapturedSessionEntryReadSource & { databaseIdentity: string };
};

export type SessionDiagnosticTextWorkerInput = {
  kind: "session-diagnostic-text";
  database: { agentId: string; path: string };
  scope: SessionEntryReadScope & { agentId: string; databaseAgentId: string; sessionId: string };
  continuation?: CanonicalSessionReaderContinuation;
  admission?: UserTurnTranscriptAdmissionReceipt;
};

export type SessionStoreSummaryWorkerInput = {
  kind: "session-store-summary";
  database: { agentId: string; path: string };
  env: NodeJS.ProcessEnv;
  agentIds: readonly string[];
  recentLimit: number;
  continuation?: CanonicalSessionReaderContinuation;
};
