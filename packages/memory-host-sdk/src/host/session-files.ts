import fsSync from "node:fs";
import path from "node:path";
import { safeStatSync } from "@openclaw/fs-safe/path";
import { asOptionalRecord } from "@openclaw/normalization-core/record-coerce";
import { normalizeAgentId } from "./config-utils.js";
import { normalizeComparablePath, readRegularFile, statRegularFile } from "./fs-utils.js";
import { hashText } from "./hash.js";
import {
  captureSensitiveTextRedactionSnapshot,
  createSensitiveTextRedactor,
  createSubsystemLogger,
  getSecretRedactionRegistryRevision,
  redactSensitiveText,
} from "./openclaw-runtime-io.js";
import {
  assertBoundIncognitoMemorySyncAccess,
  captureIncognitoMemoryReader,
  captureSessionTranscriptStorageEnvironment,
  DREAMING_NARRATIVE_RUN_PREFIX,
  isDreamingNarrativeSessionStoreKey,
  extractAgentIdFromSessionPath,
  extractAgentIdFromSessionsDir,
  HEARTBEAT_PROMPT,
  HEARTBEAT_TOKEN,
  hasInterSessionUserProvenance,
  isCompactionCheckpointTranscriptFileName,
  isCronRunSessionKey,
  isExecCompletionEvent,
  isHeartbeatUserMessage,
  isIncognitoOpenClawAgentSqlitePath,
  isIncognitoSessionKey,
  isSessionArchiveArtifactName,
  isSilentReplyPayloadText,
  isUsageCountedSessionTranscriptFileName,
  materializeSessionArchiveForRead,
  parseUsageCountedSessionIdFromFileName,
  prepareSessionEntryInWorker,
  prepareOwnedSessionEntryProjectionInWorker,
  readRestoredSessionTranscript,
  readTranscriptStatsSync,
  readTranscriptExportSnapshotReadOnlySync,
  resolveSessionTranscriptsDirForAgent,
  SessionTranscriptColdError,
  stripInboundMetadata,
  stripInternalRuntimeContext,
} from "./openclaw-runtime-session.js";
import { retryTransientMemoryRead } from "./read-retry.js";
import {
  collectRawSessionText,
  hashSessionEntrySnapshot,
  parseSessionTimestampMs,
  projectSessionEntryRecord,
  renderSessionExportLines,
} from "./session-entry-projection.js";
import { resolveBuildSessionSqliteIdentity } from "./session-entry-source.js";
import { classifySessionMessageOrigin } from "./session-provenance.js";
import { resolveSessionResetRecallCutoff } from "./session-reset-recall.js";
import {
  listSessionTranscriptCorpusEntriesForAgentSync,
  type SessionTranscriptCorpusEntry,
} from "./session-transcript-corpus.js";
import type {
  MemorySessionSyncTarget,
  MemoryEntryProvenance,
  MemoryOriginClass,
  MemorySessionKind,
} from "./types.js";

export {
  listSessionTranscriptCorpusEntriesForAgent,
  type SessionTranscriptCorpusEntry,
  type SessionTranscriptCorpusOptions,
} from "./session-transcript-corpus.js";
export { readTranscriptStatsBatchReadOnlySync } from "./openclaw-runtime-session.js";

const SESSION_ENTRY_PARSE_YIELD_LINES = 250;
const DIRECT_CRON_PROMPT_RE = /^\[cron:[^\]]+\]\s*/;
const SESSION_RESET_RECALL_CUTOFF = Symbol.for("openclaw.memory.sessionResetRecallCutoff");
type SessionResetRecallCutoff = ReturnType<typeof resolveSessionResetRecallCutoff>;

export type SessionFileEntry = {
  path: string;
  absPath: string;
  mtimeMs: number;
  /** Canonical SQLite mutation watermark, independent of source activity. */
  revisionMs?: number;
  size: number;
  hash: string;
  content: string;
  /** Maps each content line (0-indexed) to its 1-indexed JSONL source line. */
  lineMap: number[];
  /** Maps each content line (0-indexed) to epoch ms; 0 means unknown timestamp. */
  messageTimestampsMs: number[];
  /** Provenance aligned one-for-one with exported content lines. */
  lineProvenance: MemoryEntryProvenance[];
  /** True when this transcript belongs to an internal dreaming narrative run. */
  generatedByDreamingNarrative?: boolean;
  /** True when this transcript belongs to an isolated cron run session. */
  generatedByCronRun?: boolean;
  sessionKind: MemorySessionKind;
};

export type SessionFileState = Pick<
  SessionFileEntry,
  "path" | "absPath" | "mtimeMs" | "revisionMs" | "size"
>;

export type SessionEntrySnapshot = NonNullable<
  ReturnType<typeof readTranscriptExportSnapshotReadOnlySync>
>;

export type BuildSessionEntryOptions = {
  /** Explicit admitted-owner or local warm projection: never restore/materialize or invoke opaque readers. */
  readPolicy?: "no-restore";
  /** Optional preclassification from a caller-managed dreaming transcript lookup. */
  generatedByDreamingNarrative?: boolean;
  /** Optional preclassification from a caller-managed cron transcript lookup. */
  generatedByCronRun?: boolean;
  sessionKind?: MemorySessionKind;
  /** Session key for identity-backed transcript readers. */
  sessionKey?: string;
  /** Direct SQLite identity for live runtime transcripts. */
  agentId?: string;
  sessionId?: string;
  storePath?: string;
  /** Activity timestamp for transcript sources that do not have filesystem stats. */
  updatedAtMs?: number;
  /** Override for tests or specialized callers that need a tighter parse yield cadence. */
  parseYieldEveryLines?: number;
  /** Observe persisted messages before memory indexing drops tool-only content. */
  onTranscriptMessage?: (message: unknown, observedAt: number) => void;
};

/** A refused projection is not an empty/complete source snapshot. No private path in this error. */
export class SessionEntryNoRestoreError extends Error {
  readonly status = "unverified";
  constructor(readonly reason: "opaque-reader" | "unsupported-sqlite-custody" | "archive" | "missing" | "native-read" | "unprojectable") {
    super("Session projection unavailable under no-restore policy");
    this.name = "SessionEntryNoRestoreError";
  }
}
function captureSessionProjectionOptions(opts: BuildSessionEntryOptions): BuildSessionEntryOptions {
  if (opts.readPolicy !== undefined && opts.readPolicy !== "no-restore") { throw new SessionEntryNoRestoreError("unprojectable"); }
  return opts.readPolicy === "no-restore" ? Object.freeze({ ...opts }) : opts;
}
function assertNoRestoreLocalProjection(absPath: string, opts: BuildSessionEntryOptions): void {
  if (opts.readPolicy !== "no-restore") { return; }
  if (opts.onTranscriptMessage || opts.sessionKey !== undefined || isIncognitoSessionKey(opts.sessionKey)) {
    throw new SessionEntryNoRestoreError("opaque-reader");
  }
  // Native SQLite/actor snapshots need a separately attested no-restore owner contract.
  // Do not invoke worker/incognito/container fallback merely because policy was requested.
  if (opts.agentId !== undefined || opts.sessionId !== undefined || opts.storePath !== undefined || resolveBuildSessionSqliteIdentity(absPath, opts)) {
    throw new SessionEntryNoRestoreError("unsupported-sqlite-custody");
  }
  // Caller classification hints are not a native eligibility receipt in this mode.
  if (opts.generatedByDreamingNarrative !== undefined || opts.generatedByCronRun !== undefined) {
    throw new SessionEntryNoRestoreError("opaque-reader");
  }
  try {
    const candidate = fsSync.realpathSync.native(absPath);
    const parent = fsSync.realpathSync.native(path.dirname(absPath));
    // Reject candidate/parent aliases rather than silently falling back to container custody.
    if (normalizeComparablePath(candidate) !== normalizeComparablePath(path.resolve(absPath)) ||
      normalizeComparablePath(parent) !== normalizeComparablePath(path.resolve(path.dirname(absPath)))) {
      throw new SessionEntryNoRestoreError("opaque-reader");
    }
    const agentId = extractAgentIdFromSessionPath(candidate) ?? "main";
    const configuredRoot = resolveSessionTranscriptsDirForAgent(agentId);
    const configuredAgents = path.dirname(path.dirname(configuredRoot));
    const physicalRoot = fsSync.realpathSync.native(configuredRoot);
    const physicalAgents = fsSync.realpathSync.native(configuredAgents);
    const ownerRoots = [physicalRoot];
    // Only configured owner-root metadata, never corpus discovery or actor callbacks.
    for (const owner of fsSync.readdirSync(configuredAgents, { withFileTypes: true })) {
      if (!owner.isDirectory() && !owner.isSymbolicLink()) { continue; }
      if (normalizeAgentId(owner.name) !== owner.name) { throw new SessionEntryNoRestoreError("opaque-reader"); }
      const root = fsSync.realpathSync.native(resolveSessionTranscriptsDirForAgent(owner.name));
      if (!fsSync.statSync(root).isDirectory()) { throw new SessionEntryNoRestoreError("opaque-reader"); }
      ownerRoots.push(root);
    }
    if (!fsSync.statSync(physicalRoot).isDirectory() || !fsSync.statSync(physicalAgents).isDirectory()) {
      throw new SessionEntryNoRestoreError("opaque-reader");
    }
    const inside = (root: string, value: string) => {
      const relative = path.relative(normalizeComparablePath(root), normalizeComparablePath(value));
      return relative === "" || (!path.isAbsolute(relative) && relative !== ".." && !relative.startsWith(".." + path.sep));
    };
    // Physical ancestry covers aliased configured state roots and all ordinary agent descendants.
    // The exact native owner root is checked separately in case it is itself aliased outside agents/.
    if ([physicalAgents, ...ownerRoots].some((root) => inside(root, candidate) || inside(root, parent))) {
      throw new SessionEntryNoRestoreError("opaque-reader");
    }
  } catch {
    // Missing/unverifiable configured roots are ambiguity, never proof of local noncanonical custody.
    throw new SessionEntryNoRestoreError("opaque-reader");
  }
  if (isSessionArchiveArtifactName(path.basename(absPath))) {
    throw new SessionEntryNoRestoreError("archive");
  }
}

type SessionTranscriptClassification = {
  dreamingNarrativeTranscriptPaths: ReadonlySet<string>;
  cronRunTranscriptPaths: ReadonlySet<string>;
};

export function readSessionEntryResetRecallCutoff(
  entry: SessionFileEntry,
): SessionResetRecallCutoff {
  const value: unknown = Object.getOwnPropertyDescriptor(entry, SESSION_RESET_RECALL_CUTOFF)?.value;
  if (!value || typeof value !== "object" || !("state" in value)) {
    return { state: "invalid" };
  }
  if (value.state === "absent" || value.state === "invalid") {
    return { state: value.state };
  }
  if (value.state === "valid" && "cutoffLine" in value && typeof value.cutoffLine === "number") {
    return { state: "valid", cutoffLine: value.cutoffLine };
  }
  return { state: "invalid" };
}

function attachSessionEntryResetRecallCutoff(
  entry: SessionFileEntry,
  cutoff: SessionResetRecallCutoff,
): SessionFileEntry {
  Object.defineProperty(entry, SESSION_RESET_RECALL_CUTOFF, {
    configurable: false,
    enumerable: false,
    value: cutoff,
    writable: false,
  });
  return entry;
}

export function matchesSessionEntryPrefixHash(
  entry: SessionFileEntry,
  lineCount: number,
  expectedHash: string,
): boolean {
  const lines = entry.content ? entry.content.split("\n") : [];
  if (!Number.isInteger(lineCount) || lineCount < 0 || lineCount > lines.length) {
    return false;
  }
  const resetRecallCutoff = readSessionEntryResetRecallCutoff(entry);
  const prefix = {
    content: lines.slice(0, lineCount).join("\n"),
    lineMap: entry.lineMap.slice(0, lineCount),
    messageTimestampsMs: entry.messageTimestampsMs.slice(0, lineCount),
    lineProvenance: entry.lineProvenance.slice(0, lineCount),
  };
  // Content alone is insufficient: rewrites and resets can retain the same rendered text.
  return hashSessionEntrySnapshot({ ...prefix, resetRecallCutoff }) === expectedHash;
}

type SessionTranscriptStoreEntry = {
  sessionFile?: unknown;
  sessionId?: unknown;
};

function shouldSkipTranscriptFileForDreaming(absPath: string): boolean {
  const fileName = path.basename(absPath);
  // Compaction checkpoints are always skipped: they are derived snapshots of an
  // active session and would double-index the same content.
  if (isCompactionCheckpointTranscriptFileName(fileName)) {
    return true;
  }
  // Legacy backups and `.jsonl.bak.<iso>` rotations are opaque pre-archive
  // copies, not a user-facing session artifact; skip them too.
  if (
    isSessionArchiveArtifactName(fileName) &&
    !isUsageCountedSessionTranscriptFileName(fileName)
  ) {
    return true;
  }
  // Usage-counted archives (`.jsonl.reset.<iso>` / `.jsonl.deleted.<iso>`) are
  // the rotated-but-retained copies of real sessions and must stay indexed so
  // `memory_search` can surface hits on post-reset / post-delete history.
  return false;
}

function isUsageCountedSessionArchiveTranscriptPath(absPath: string): boolean {
  const fileName = path.basename(absPath);
  return (
    isUsageCountedSessionTranscriptFileName(fileName) &&
    isSessionArchiveArtifactName(fileName) &&
    parseUsageCountedSessionIdFromFileName(fileName) !== null
  );
}

function hasDreamingNarrativeIdentity(value: unknown): boolean {
  return typeof value === "string" && isDreamingNarrativeSessionStoreKey(value);
}

function isDreamingNarrativeGeneratedRecord(record: unknown): boolean {
  const candidate = asOptionalRecord(record);
  if (!candidate) {
    return false;
  }
  const data = asOptionalRecord(candidate.data);
  if (
    candidate.type === "custom" &&
    candidate.customType === "openclaw:bootstrap-context:full" &&
    typeof data?.runId === "string" &&
    data.runId.startsWith(DREAMING_NARRATIVE_RUN_PREFIX)
  ) {
    return true;
  }
  const message = candidate.type === "message" ? asOptionalRecord(candidate.message) : undefined;
  const metadata = asOptionalRecord(message?.["__openclaw"]);
  return (
    hasDreamingNarrativeIdentity(candidate.runId) ||
    hasDreamingNarrativeIdentity(candidate.sessionKey) ||
    hasDreamingNarrativeIdentity(data?.runId) ||
    hasDreamingNarrativeIdentity(data?.sessionKey) ||
    ((message?.role === "assistant" || message?.role === "toolResult") &&
      hasDreamingNarrativeIdentity(metadata?.runId))
  );
}

function hasCronRunSessionKey(value: unknown): boolean {
  return typeof value === "string" && isCronRunSessionKey(value);
}

function isCronRunGeneratedRecord(record: unknown): boolean {
  const candidate = asOptionalRecord(record);
  return (
    hasCronRunSessionKey(candidate?.sessionKey) ||
    hasCronRunSessionKey(asOptionalRecord(candidate?.data)?.sessionKey)
  );
}

function resolveSessionStoreTranscriptResolvedPath(
  sessionsDir: string,
  entry: SessionTranscriptStoreEntry | undefined,
): string | null {
  if (typeof entry?.sessionFile === "string" && entry.sessionFile.trim().length > 0) {
    const sessionFile = entry.sessionFile.trim();
    return path.isAbsolute(sessionFile) ? sessionFile : path.resolve(sessionsDir, sessionFile);
  }
  if (typeof entry?.sessionId === "string" && entry.sessionId.trim().length > 0) {
    return path.join(sessionsDir, `${entry.sessionId.trim()}.jsonl`);
  }
  return null;
}

function isCanonicalSessionsDirForAgent(sessionsDir: string, agentId: string): boolean {
  return (
    normalizeComparablePath(sessionsDir) ===
    normalizeComparablePath(resolveSessionTranscriptsDirForAgent(agentId))
  );
}

function loadSessionTranscriptClassificationForSessionsDir(
  sessionsDir: string,
  strictRead = false,
): SessionTranscriptClassification {
  const agentId = extractAgentIdFromSessionsDir(sessionsDir);
  if (agentId && isCanonicalSessionsDirForAgent(sessionsDir, agentId)) {
    return classifySessionTranscriptCorpusEntries(
      listSessionTranscriptCorpusEntriesForAgentSync(agentId, { includeContentRevision: false }),
    );
  }
  const storePath = path.join(sessionsDir, "sessions.json");
  const store = readSessionTranscriptClassificationStore(storePath, strictRead);
  const dreamingTranscriptPaths = new Set<string>();
  const cronRunTranscriptPaths = new Set<string>();
  for (const [sessionKey, entry] of Object.entries(store)) {
    const resolved = resolveSessionStoreTranscriptResolvedPath(sessionsDir, entry);
    if (!resolved) {
      continue;
    }
    const transcriptPath = normalizeComparablePath(resolved);
    if (isDreamingNarrativeSessionStoreKey(sessionKey)) {
      dreamingTranscriptPaths.add(transcriptPath);
    }
    if (isCronRunSessionKey(sessionKey)) {
      cronRunTranscriptPaths.add(transcriptPath);
    }
  }
  return {
    dreamingNarrativeTranscriptPaths: dreamingTranscriptPaths,
    cronRunTranscriptPaths,
  };
}

function readSessionTranscriptClassificationStore(
  storePath: string,
  strictRead = false,
): Record<string, SessionTranscriptStoreEntry> {
  try {
    const parsed = JSON.parse(fsSync.readFileSync(storePath, "utf-8")) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      if (strictRead) { throw new SessionEntryNoRestoreError("unprojectable"); }
      return {};
    }
    return parsed as Record<string, SessionTranscriptStoreEntry>;
  } catch {
    if (strictRead) { throw new SessionEntryNoRestoreError("native-read"); }
    return {};
  }
}

function classifySessionTranscriptCorpusEntries(
  corpusEntries: readonly SessionTranscriptCorpusEntry[],
): SessionTranscriptClassification {
  const dreamingTranscriptPaths = new Set<string>();
  const cronRunTranscriptPaths = new Set<string>();
  for (const entry of corpusEntries) {
    if (entry.transcriptSource === "sqlite") {
      continue;
    }
    const normalizedPath = normalizeComparablePath(entry.sessionFile);
    if (entry.generatedByDreamingNarrative) {
      dreamingTranscriptPaths.add(normalizedPath);
    }
    if (entry.generatedByCronRun) {
      cronRunTranscriptPaths.add(normalizedPath);
    }
  }
  return {
    dreamingNarrativeTranscriptPaths: dreamingTranscriptPaths,
    cronRunTranscriptPaths,
  };
}

function classifySessionTranscriptFromSessionStore(absPath: string, strictRead = false): {
  generatedByDreamingNarrative: boolean;
  generatedByCronRun: boolean;
} {
  const sessionsDir = path.dirname(absPath);
  const normalizedAbsPath = normalizeComparablePath(absPath);
  const primarySessionId = parseUsageCountedSessionIdFromFileName(path.basename(absPath));
  const normalizedPrimaryPath =
    primarySessionId && isSessionArchiveArtifactName(path.basename(absPath))
      ? normalizeComparablePath(path.join(sessionsDir, `${primarySessionId}.jsonl`))
      : null;
  const classification = loadSessionTranscriptClassificationForSessionsDir(sessionsDir, strictRead);
  const hasClassifiedPath = (paths: ReadonlySet<string>) =>
    paths.has(normalizedAbsPath) ||
    (normalizedPrimaryPath !== null && paths.has(normalizedPrimaryPath));
  return {
    generatedByDreamingNarrative: hasClassifiedPath(
      classification.dreamingNarrativeTranscriptPaths,
    ),
    generatedByCronRun: hasClassifiedPath(classification.cronRunTranscriptPaths),
  };
}

export function sessionPathForFile(absPath: string): string {
  const agentId = extractAgentIdFromSessionPath(absPath);
  return path
    .join("sessions", ...(agentId ? [agentId] : []), path.basename(absPath))
    .replace(/\\/g, "/");
}

/** Returns the logical memory path for a live SQLite-backed session transcript. */
export function sessionPathForSessionIdentity(agentId: string, sessionId: string): string {
  return path.join("sessions", normalizeAgentId(agentId), `${sessionId}.jsonl`).replace(/\\/g, "/");
}

/**
 * Parses a deprecated path-shaped memory sync hint only when it points at an
 * OpenClaw-owned usage-counted transcript in the canonical agent sessions dir.
 */
export function parseCanonicalSessionSyncTargetFromPath(
  sessionFile: string,
): MemorySessionSyncTarget | null {
  const trimmed = sessionFile.trim();
  if (!trimmed) {
    return null;
  }
  const resolved = path.resolve(trimmed);
  const fileName = path.basename(resolved);
  const sessionId = parseUsageCountedSessionIdFromFileName(fileName);
  if (!sessionId || !isUsageCountedSessionTranscriptFileName(fileName)) {
    return null;
  }
  const agentId = extractAgentIdFromSessionPath(resolved);
  if (!agentId) {
    return null;
  }
  const canonicalSessionsDir = normalizeComparablePath(
    resolveSessionTranscriptsDirForAgent(agentId),
  );
  if (normalizeComparablePath(path.dirname(resolved)) !== canonicalSessionsDir) {
    return null;
  }
  return { agentId, sessionId };
}

function normalizeSessionText(value: string): string {
  return value.replace(/\s+/g, " ").trim();
}

const GENERATED_SYSTEM_MESSAGE_RE = /^System(?: \(untrusted\))?: \[[^\]]+\]\s*/;

function sanitizeSessionText(text: string, role: "user" | "assistant"): string | null {
  // Metadata envelopes require their original newlines; strip them before whitespace normalization.
  const strippedInbound = role === "user" ? stripInboundMetadata(text) : text;
  const strippedInternal = stripInternalRuntimeContext(strippedInbound);
  const normalized = normalizeSessionText(strippedInternal);
  if (!normalized) {
    return null;
  }
  if (
    role === "user" &&
    (GENERATED_SYSTEM_MESSAGE_RE.test(normalized) ||
      DIRECT_CRON_PROMPT_RE.test(normalized) ||
      isHeartbeatUserMessage({ role, content: normalized }, HEARTBEAT_PROMPT))
  ) {
    return null;
  }
  if (isSilentReplyPayloadText(normalized)) {
    return null;
  }
  // Assistant-side machinery acks: HEARTBEAT_OK is the canonical "all clear,
  // nothing to do" reply to a heartbeat tick. Drop on the assistant side
  // directly so we do not have to rely on cross-message coupling with the
  // preceding user message (which a real user could spoof).
  if (role === "assistant" && normalized === HEARTBEAT_TOKEN) {
    return null;
  }
  const withoutSystemEnvelope = normalized.replace(GENERATED_SYSTEM_MESSAGE_RE, "").trim();
  if (isExecCompletionEvent(withoutSystemEnvelope)) {
    return null;
  }
  return normalized;
}

function isRecalledMemoryMessage(message: { provenance?: unknown }): boolean {
  const provenance = message.provenance as { kind?: unknown; sourceTool?: unknown } | undefined;
  return (
    provenance?.kind === "internal_system" &&
    (provenance.sourceTool === "memory_search" || provenance.sourceTool === "memory_get")
  );
}

function resolveSessionEntryParseYieldLines(opts: BuildSessionEntryOptions): number {
  const configured = opts.parseYieldEveryLines;
  if (typeof configured === "number" && Number.isFinite(configured)) {
    return Math.max(1, Math.floor(configured));
  }
  return SESSION_ENTRY_PARSE_YIELD_LINES;
}

function sqliteSessionFileState(
  absPath: string,
  identity: { agentId: string; sessionId: string },
  stats: ReturnType<typeof readTranscriptStatsSync>,
  updatedAtMs?: number,
): SessionFileState {
  return {
    absPath,
    path: sessionPathForSessionIdentity(identity.agentId, identity.sessionId),
    mtimeMs: updatedAtMs ?? stats.maxSeq,
    revisionMs: stats.lastMutationAtMs ?? stats.maxSeq,
    size: stats.sizeBytes,
  };
}

export function statSessionEntrySync(
  absPath: string,
  opts: BuildSessionEntryOptions = {},
  transcriptStats?: ReturnType<typeof readTranscriptStatsSync>,
): SessionFileState | null {
  const sqliteIdentity = resolveBuildSessionSqliteIdentity(absPath, opts);
  if (sqliteIdentity) {
    if (!transcriptStats) {
      assertBoundIncognitoMemorySyncAccess(
        sqliteIdentity,
        "statSessionEntrySync",
        "buildSessionEntry",
      );
    }
    const stats = transcriptStats ?? readTranscriptStatsSync(sqliteIdentity);
    return sqliteSessionFileState(absPath, sqliteIdentity, stats, opts.updatedAtMs);
  }
  const stat = safeStatSync(absPath);
  return stat?.isFile()
    ? {
        absPath,
        path: sessionPathForFile(absPath),
        mtimeMs: stat.mtimeMs,
        size: stat.size,
      }
    : null;
}

async function yieldSessionEntryParseIfNeeded(
  lineIndex: number,
  everyLines: number,
): Promise<void> {
  if (lineIndex > 0 && lineIndex % everyLines === 0) {
    await new Promise<void>((resolve) => {
      setImmediate(resolve);
    });
  }
}

/** Only native admission may produce this prepared snapshot; never exported to caller snapshots. */
async function buildOwnedNoRestoreEntry(absPath: string, opts: BuildSessionEntryOptions): Promise<SessionFileEntry | null> {
  try {
    if (!opts.agentId || !opts.sessionId || !opts.storePath || !opts.sessionKey ||
      normalizeComparablePath(path.resolve(absPath)) !== normalizeComparablePath(path.resolve(opts.storePath))) {
      throw new SessionEntryNoRestoreError("unsupported-sqlite-custody");
    }
    if (opts.onTranscriptMessage || opts.generatedByCronRun !== undefined || opts.generatedByDreamingNarrative !== undefined ||
      opts.sessionKind !== undefined || opts.updatedAtMs !== undefined) { throw new SessionEntryNoRestoreError("opaque-reader"); }
    const env = captureSessionTranscriptStorageEnvironment(process.env);
    const { sessionKey } = opts;
    for (let attempt = 0; attempt < 2; attempt++) {
      const redaction = captureSensitiveTextRedactionSnapshot();
      const result = await prepareOwnedSessionEntryProjectionInWorker(absPath,
        { agentId: opts.agentId, sessionId: opts.sessionId, storePath: opts.storePath, sessionKey,
          parseYieldEveryLines: opts.parseYieldEveryLines }, env);
      if (result.registryRevision !== redaction.registryRevision) { continue; }
      const entry = result.entry;
      if (!entry) { throw new SessionEntryNoRestoreError("unprojectable"); }
      attachSessionEntryResetRecallCutoff(entry, result.resetRecallCutoff);
      if (redaction.registryRevision === getSecretRedactionRegistryRevision()) { return entry; }
    }
    throw new SessionEntryNoRestoreError("native-read");
  } catch (error) {
    if (error instanceof SessionEntryNoRestoreError) { throw error; }
    throw new SessionEntryNoRestoreError("native-read");
  }
}

export async function buildSessionEntry(
  absPath: string,
  opts: BuildSessionEntryOptions = {},
  source?: {
    memoryEntry(
      absPath: string,
      options: BuildSessionEntryOptions,
    ): Promise<SessionFileEntry | null>;
  },
): Promise<SessionFileEntry | null> {
  opts = captureSessionProjectionOptions(opts);
  if (opts.readPolicy === "no-restore") {
    if (source) { throw new SessionEntryNoRestoreError("opaque-reader"); }
    if (opts.agentId !== undefined || opts.sessionId !== undefined || opts.storePath !== undefined) {
      return await buildOwnedNoRestoreEntry(absPath, opts);
    }
    assertNoRestoreLocalProjection(absPath, opts);
    return await buildSessionEntryInProcess(absPath, opts);
  }
  if (source) {
    return source.memoryEntry(absPath, opts);
  }
  const identity = resolveBuildSessionSqliteIdentity(absPath, opts);
  const incognito = identity && captureIncognitoMemoryReader(identity);
  if (incognito) {
    return incognito.memoryEntry(absPath, opts);
  }
  const prepare = async () => {
    // Unbound private stores retain their native owner until the atomic cutover.
    if (
      identity &&
      !opts.onTranscriptMessage &&
      opts.parseYieldEveryLines === undefined &&
      !isIncognitoSessionKey(opts.sessionKey) &&
      !isIncognitoOpenClawAgentSqlitePath(identity.storePath, { agentId: identity.agentId })
    ) {
      const options = { ...opts, ...identity };
      for (let attempt = 0; attempt < 2; attempt++) {
        const redaction = captureSensitiveTextRedactionSnapshot();
        const prepared = await prepareSessionEntryInWorker(absPath, options, redaction);
        if (redaction.registryRevision === getSecretRedactionRegistryRevision()) {
          return prepared.entry
            ? attachSessionEntryResetRecallCutoff(prepared.entry, prepared.resetRecallCutoff)
            : null;
        }
      }
      throw new Error(
        "Session transcript redaction changed during preparation; retry the operation.",
      );
    }
    return buildSessionEntryInProcess(absPath, opts);
  };
  try {
    return await prepare();
  } catch (error) {
    if (!(error instanceof SessionTranscriptColdError) || identity?.sessionId !== error.sessionId) {
      throw error;
    }
    return readRestoredSessionTranscript(identity, prepare);
  }
}

/** The shared transcript worker runs the same projection with task-local redaction. */
export async function buildSessionEntryInProcess(
  absPath: string,
  opts: BuildSessionEntryOptions = {},
  redactText: (text: string) => string = (text) => redactSensitiveText(text, { mode: "tools" }),
): Promise<SessionFileEntry | null> {
  if (opts.readPolicy === "no-restore" && arguments.length > 2) { throw new SessionEntryNoRestoreError("opaque-reader"); }
  opts = captureSessionProjectionOptions(opts);
  if (opts.readPolicy === "no-restore" && (opts.agentId !== undefined || opts.sessionId !== undefined || opts.storePath !== undefined)) {
    return await buildOwnedNoRestoreEntry(absPath, opts);
  }
  assertNoRestoreLocalProjection(absPath, opts);
  return buildSessionEntryFromSource(absPath, opts, redactText);
}

/** Project an actor-owned snapshot without reopening its physical store on the caller. */
export async function buildSessionEntryFromSnapshot(
  absPath: string,
  opts: BuildSessionEntryOptions & {
    agentId: string;
    sessionId: string;
    storePath: string;
  },
  snapshot: SessionEntrySnapshot,
  assertCurrent: () => void,
): Promise<SessionFileEntry | null> {
  captureSessionProjectionOptions(opts);
  if (opts.readPolicy === "no-restore") { throw new SessionEntryNoRestoreError("opaque-reader"); }
  assertCurrent();
  const { onTranscriptMessage, ...options } = opts;
  const result = await buildSessionEntryFromSource(
    absPath,
    {
      ...structuredClone(options),
      ...(onTranscriptMessage
        ? {
            onTranscriptMessage(message, observedAt) {
              assertCurrent();
              onTranscriptMessage(message, observedAt);
              assertCurrent();
            },
          }
        : {}),
    },
    (text) => redactSensitiveText(text, { mode: "tools" }),
    snapshot,
  );
  assertCurrent();
  return result;
}

/** @internal Pure compute DATA only. Never an owner receipt; producer must admit before enqueue. */
export async function computeSessionEntryProjectionData(
  absPath: string,
  options: Pick<BuildSessionEntryOptions, "agentId" | "sessionId" | "storePath" | "parseYieldEveryLines">,
  snapshot: SessionEntrySnapshot,
  redaction: ReturnType<typeof captureSensitiveTextRedactionSnapshot>,
) {
  const entry = await buildSessionEntryFromSource(absPath,
    { agentId: options.agentId, sessionId: options.sessionId, storePath: options.storePath,
      parseYieldEveryLines: options.parseYieldEveryLines, readPolicy: "no-restore" },
    createSensitiveTextRedactor(redaction),
    { ...snapshot, events: snapshot.events.map(projectSessionEntryRecord) });
  if (!entry) { throw new SessionEntryNoRestoreError("unprojectable"); }
  return { entry, resetRecallCutoff: readSessionEntryResetRecallCutoff(entry) };
}

async function buildSessionEntryFromSource(
  absPath: string,
  opts: BuildSessionEntryOptions,
  redactText: (text: string) => string,
  preparedSnapshot?: SessionEntrySnapshot,
): Promise<SessionFileEntry | null> {
  const sqliteIdentity = resolveBuildSessionSqliteIdentity(absPath, opts);
  try {
    const snapshot =
      preparedSnapshot ??
      (sqliteIdentity
        ? readTranscriptExportSnapshotReadOnlySync(sqliteIdentity, {
            // Observers require original messages and run only after the snapshot closes.
            projectEvent: opts.onTranscriptMessage ? undefined : projectSessionEntryRecord,
          })
        : null);
    const sqliteSource =
      snapshot && sqliteIdentity
        ? {
            ...sqliteSessionFileState(absPath, sqliteIdentity, snapshot.stats, opts.updatedAtMs),
            records: snapshot.events,
            resetRecallCutoff: resolveSessionResetRecallCutoff(snapshot.events),
            sessionKey: snapshot.sessionKey,
          }
        : null;
    if (sqliteIdentity && !sqliteSource) {
      return null;
    }
    let raw = "";
    let mtimeMs: number;
    let size: number;
    let memoryPath: string;
    if (sqliteSource) {
      mtimeMs = sqliteSource.mtimeMs;
      size = sqliteSource.size;
      memoryPath = sqliteSource.path;
    } else {
      const regularFile = await statRegularFile(absPath);
      if (regularFile.missing) {
        if (opts.readPolicy === "no-restore") { throw new SessionEntryNoRestoreError("missing"); }
        return null;
      }
      const stat = regularFile.stat;
      if (shouldSkipTranscriptFileForDreaming(absPath)) {
        return {
          path: sessionPathForFile(absPath),
          absPath,
          mtimeMs: stat.mtimeMs,
          size: stat.size,
          hash: hashText("\n\n"),
          content: "",
          lineMap: [],
          messageTimestampsMs: [],
          lineProvenance: [],
          sessionKind: opts.sessionKind ?? "unknown",
        };
      }
      raw = (
        await retryTransientMemoryRead(
          () =>
            readRegularFile({
              filePath: isUsageCountedSessionArchiveTranscriptPath(absPath)
                ? materializeSessionArchiveForRead(absPath)
                : absPath,
            }),
          `read session transcript ${absPath}`,
        )
      ).buffer.toString("utf-8");
      mtimeMs = stat.mtimeMs;
      size = stat.size;
      memoryPath = sessionPathForFile(absPath);
    }
    const collected: string[] = [];
    const lineMap: number[] = [];
    const messageTimestampsMs: number[] = [];
    const lineProvenance: MemoryEntryProvenance[] = [];
    const parseYieldEveryLines = resolveSessionEntryParseYieldLines(opts);
    const sqliteSessionKey = !opts.sessionKey ? sqliteSource?.sessionKey : undefined;
    const sessionStoreClassification =
      !sqliteIdentity &&
      (opts.generatedByDreamingNarrative === undefined || opts.generatedByCronRun === undefined)
        ? classifySessionTranscriptFromSessionStore(absPath, opts.readPolicy === "no-restore")
        : null;
    let generatedByDreamingNarrative =
      opts.generatedByDreamingNarrative ??
      (sqliteSessionKey ? isDreamingNarrativeSessionStoreKey(sqliteSessionKey) : undefined) ??
      sessionStoreClassification?.generatedByDreamingNarrative ??
      false;
    let generatedByCronRun =
      opts.generatedByCronRun ??
      (sqliteSessionKey ? isCronRunSessionKey(sqliteSessionKey) : undefined) ??
      sessionStoreClassification?.generatedByCronRun ??
      false;
    const sessionKind = opts.sessionKind ?? "unknown";
    const allowArchiveRecordCronClassification =
      isUsageCountedSessionArchiveTranscriptPath(absPath);
    // A heartbeat owns every generated response until the next user turn. The
    // persisted runtime provenance makes this coupling safe from text spoofing.
    let insideHeartbeatTurn = false;
    let insideRecalledMemoryTurn = false;
    let turnOrigin: MemoryOriginClass = "untrusted";
    // SQLite is fully snapshotted before yielding or invoking observers. Archives
    // retain raw line ordinals, including blank and malformed JSONL entries.
    for (
      let jsonlIdx = 0, lineStart = 0;
      sqliteSource ? jsonlIdx < sqliteSource.records.length : lineStart <= raw.length;
      jsonlIdx++
    ) {
      await yieldSessionEntryParseIfNeeded(jsonlIdx, parseYieldEveryLines);
      let record: unknown;
      if (sqliteSource) {
        record = sqliteSource.records[jsonlIdx];
      } else {
        const newlineIndex = raw.indexOf("\n", lineStart);
        const lineEnd = newlineIndex === -1 ? raw.length : newlineIndex;
        const line = raw.slice(lineStart, lineEnd);
        lineStart = newlineIndex === -1 ? raw.length + 1 : newlineIndex + 1;
        if (!line.trim()) {
          continue;
        }
        try {
          record = JSON.parse(line);
        } catch {
          if (opts.readPolicy === "no-restore") { throw new SessionEntryNoRestoreError("unprojectable"); }
          continue;
        }
      }
      if (opts.readPolicy === "no-restore" && (!record || typeof record !== "object" || Array.isArray(record))) {
        throw new SessionEntryNoRestoreError("unprojectable");
      }
      const identifiesDreamingNarrative =
        !generatedByDreamingNarrative && isDreamingNarrativeGeneratedRecord(record);
      const identifiesCronRun =
        !generatedByCronRun &&
        allowArchiveRecordCronClassification &&
        isCronRunGeneratedRecord(record);
      if (identifiesDreamingNarrative || identifiesCronRun) {
        generatedByDreamingNarrative ||= identifiesDreamingNarrative;
        generatedByCronRun ||= identifiesCronRun;
        collected.length = 0;
        lineMap.length = 0;
        messageTimestampsMs.length = 0;
        lineProvenance.length = 0;
      }
      if (
        !record ||
        typeof record !== "object" ||
        (record as { type?: unknown }).type !== "message"
      ) {
        continue;
      }
      const message = (record as { message?: unknown }).message as
        | { role?: unknown; content?: unknown; provenance?: unknown }
        | undefined;
      if (!message || typeof message.role !== "string") {
        if (opts.readPolicy === "no-restore") { throw new SessionEntryNoRestoreError("unprojectable"); }
        continue;
      }
      if (message.role !== "user" && message.role !== "assistant") {
        continue;
      }
      const timestampMs = parseSessionTimestampMs(
        record as { timestamp?: unknown },
        message as { timestamp?: unknown },
      );
      opts.onTranscriptMessage?.(message, Math.max(0, Math.floor(timestampMs || mtimeMs)));
      const inputProvenance = message.provenance as
        | { kind?: unknown; sourceTool?: unknown }
        | undefined;
      const isHeartbeatUser =
        message.role === "user" &&
        inputProvenance?.kind === "internal_system" &&
        inputProvenance.sourceTool === "heartbeat";
      if (message.role === "user") {
        insideHeartbeatTurn = isHeartbeatUser;
        insideRecalledMemoryTurn = isRecalledMemoryMessage(message);
        turnOrigin = classifySessionMessageOrigin(message, turnOrigin);
      }
      if (message.role === "user" && hasInterSessionUserProvenance(message)) {
        continue;
      }
      // Observers and turn provenance still see excluded messages; text export does not.
      if (
        insideHeartbeatTurn ||
        insideRecalledMemoryTurn ||
        generatedByDreamingNarrative ||
        generatedByCronRun
      ) {
        continue;
      }
      const rawText = collectRawSessionText(message.content);
      if (rawText === null) {
        if (opts.readPolicy === "no-restore") { throw new SessionEntryNoRestoreError("unprojectable"); }
        continue;
      }

      // User text is not trusted archive-wide provenance. Per-message sanitization
      // drops cron prompts without clearing unrelated content from the archive.
      const text = sanitizeSessionText(rawText, message.role);
      if (!text) {
        continue;
      }
      const safe = redactText(text);
      const label = message.role === "user" ? "User" : "Assistant";
      const renderedLines = renderSessionExportLines(label, safe);
      const memoryProvenance: MemoryEntryProvenance = {
        originClass: classifySessionMessageOrigin(message, turnOrigin),
        sessionKind,
        observedAt: Math.max(0, Math.floor(timestampMs || mtimeMs)),
      };
      collected.push(...renderedLines);
      lineMap.push(...renderedLines.map(() => jsonlIdx + 1));
      messageTimestampsMs.push(...renderedLines.map(() => timestampMs));
      lineProvenance.push(...renderedLines.map(() => memoryProvenance));
    }
    const content = collected.join("\n");
    const entry: SessionFileEntry = {
      path: memoryPath,
      absPath,
      mtimeMs,
      ...(sqliteSource ? { revisionMs: sqliteSource.revisionMs } : {}),
      size,
      hash: hashSessionEntrySnapshot({
        content,
        lineMap,
        messageTimestampsMs,
        lineProvenance,
        resetRecallCutoff: sqliteSource?.resetRecallCutoff ?? { state: "absent" },
      }),
      content,
      lineMap,
      messageTimestampsMs,
      lineProvenance,
      sessionKind,
      ...(generatedByDreamingNarrative ? { generatedByDreamingNarrative: true } : {}),
      ...(generatedByCronRun ? { generatedByCronRun: true } : {}),
    };
    return attachSessionEntryResetRecallCutoff(
      entry,
      sqliteSource?.resetRecallCutoff ?? { state: "absent" },
    );
  } catch (err) {
    if (opts.readPolicy === "no-restore") {
      if (err instanceof SessionEntryNoRestoreError) { throw err; }
      throw new SessionEntryNoRestoreError("native-read");
    }
    if (sqliteIdentity) {
      throw err;
    }
    createSubsystemLogger("memory").debug(`Failed reading session file ${absPath}: ${String(err)}`);
    return null;
  }
}
/* oxlint-disable max-lines -- TODO: split this grandfathered oversized file. */
