import path from "node:path";
import { normalizeComparablePath, readRegularFile, statRegularFile } from "./fs-utils.js";
import { hashText } from "./hash.js";
import {
  type SessionFileEntry,
  type SessionEntrySnapshot,
  type BuildSessionEntryOptions,
  SessionEntryNoRestoreError,
  captureSessionProjectionOptions,
  assertNoRestoreLocalProjection,
  readSessionEntryResetRecallCutoff,
  attachSessionEntryResetRecallCutoff,
  shouldSkipTranscriptFileForDreaming,
  isUsageCountedSessionArchiveTranscriptPath,
  isDreamingNarrativeGeneratedRecord,
  isCronRunGeneratedRecord,
  classifySessionTranscriptFromSessionStore,
  sessionPathForFile,
  sqliteSessionFileState,
  sanitizeSessionText,
  isRecalledMemoryMessage,
  resolveSessionEntryParseYieldLines,
  yieldSessionEntryParseIfNeeded,
} from "./memory-sessions-entry-support.js";
import {
  captureSensitiveTextRedactionSnapshot,
  createSensitiveTextRedactor,
  createSubsystemLogger,
  getSecretRedactionRegistryRevision,
  redactSensitiveText,
} from "./openclaw-runtime-io.js";
import {
  captureIncognitoMemoryReader,
  captureSessionTranscriptStorageEnvironment,
  isDreamingNarrativeSessionStoreKey,
  hasInterSessionUserProvenance,
  isCronRunSessionKey,
  isIncognitoOpenClawAgentSqlitePath,
  isIncognitoSessionKey,
  materializeSessionArchiveForRead,
  prepareSessionEntryInWorker,
  prepareOwnedSessionEntryProjectionInWorker,
  readRestoredSessionTranscript,
  readTranscriptExportSnapshotReadOnlySync,
  SessionTranscriptColdError,
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
import type { MemoryEntryProvenance, MemoryOriginClass } from "./types.js";

export {
  type SessionFileEntry,
  type SessionFileState,
  type SessionEntrySnapshot,
  type BuildSessionEntryOptions,
  SessionEntryNoRestoreError,
  readSessionEntryResetRecallCutoff,
  matchesSessionEntryPrefixHash,
  sessionPathForFile,
  sessionPathForSessionIdentity,
  parseCanonicalSessionSyncTargetFromPath,
  statSessionEntrySync,
} from "./memory-sessions-entry-support.js";

export {
  listSessionTranscriptCorpusEntriesForAgent,
  type SessionTranscriptCorpusEntry,
  type SessionTranscriptCorpusOptions,
} from "./session-transcript-corpus.js";
export { readTranscriptStatsBatchReadOnlySync } from "./openclaw-runtime-session.js";

async function buildOwnedNoRestoreEntry(
  absPath: string,
  opts: BuildSessionEntryOptions,
): Promise<SessionFileEntry | null> {
  try {
    if (
      !opts.agentId ||
      !opts.sessionId ||
      !opts.storePath ||
      !opts.sessionKey ||
      normalizeComparablePath(path.resolve(absPath)) !==
        normalizeComparablePath(path.resolve(opts.storePath))
    ) {
      throw new SessionEntryNoRestoreError("unsupported-sqlite-custody");
    }
    if (
      opts.onTranscriptMessage ||
      opts.generatedByCronRun !== undefined ||
      opts.generatedByDreamingNarrative !== undefined ||
      opts.sessionKind !== undefined ||
      opts.updatedAtMs !== undefined
    ) {
      throw new SessionEntryNoRestoreError("opaque-reader");
    }
    const env = captureSessionTranscriptStorageEnvironment(process.env);
    const { sessionKey } = opts;
    for (let attempt = 0; attempt < 2; attempt++) {
      const redaction = captureSensitiveTextRedactionSnapshot();
      const result = await prepareOwnedSessionEntryProjectionInWorker(
        absPath,
        {
          agentId: opts.agentId,
          sessionId: opts.sessionId,
          storePath: opts.storePath,
          sessionKey,
          parseYieldEveryLines: opts.parseYieldEveryLines,
        },
        env,
      );
      if (result.registryRevision !== redaction.registryRevision) {
        continue;
      }
      const entry = result.entry;
      if (!entry) {
        throw new SessionEntryNoRestoreError("unprojectable");
      }
      attachSessionEntryResetRecallCutoff(entry, result.resetRecallCutoff);
      if (redaction.registryRevision === getSecretRedactionRegistryRevision()) {
        return entry;
      }
    }
    throw new SessionEntryNoRestoreError("native-read");
  } catch (error) {
    if (error instanceof SessionEntryNoRestoreError) {
      throw error;
    }
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
  const projectionOptions = captureSessionProjectionOptions(opts);
  if (projectionOptions.readPolicy === "no-restore") {
    if (source) {
      throw new SessionEntryNoRestoreError("opaque-reader");
    }
    if (
      projectionOptions.agentId !== undefined ||
      projectionOptions.sessionId !== undefined ||
      projectionOptions.storePath !== undefined
    ) {
      return await buildOwnedNoRestoreEntry(absPath, projectionOptions);
    }
    assertNoRestoreLocalProjection(absPath, projectionOptions);
    return await buildSessionEntryInProcess(absPath, projectionOptions);
  }
  if (source) {
    return source.memoryEntry(absPath, projectionOptions);
  }
  const identity = resolveBuildSessionSqliteIdentity(absPath, projectionOptions);
  const incognito = identity && captureIncognitoMemoryReader(identity);
  if (incognito) {
    return incognito.memoryEntry(absPath, projectionOptions);
  }
  const prepare = async () => {
    // Unbound private stores retain their native owner until the atomic cutover.
    if (
      identity &&
      !projectionOptions.onTranscriptMessage &&
      projectionOptions.parseYieldEveryLines === undefined &&
      !isIncognitoSessionKey(projectionOptions.sessionKey) &&
      !isIncognitoOpenClawAgentSqlitePath(identity.storePath, { agentId: identity.agentId })
    ) {
      const options = { ...projectionOptions, ...identity };
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
    return buildSessionEntryInProcess(absPath, projectionOptions);
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
  if (opts.readPolicy === "no-restore" && arguments.length > 2) {
    throw new SessionEntryNoRestoreError("opaque-reader");
  }
  const projectionOptions = captureSessionProjectionOptions(opts);
  if (
    projectionOptions.readPolicy === "no-restore" &&
    (projectionOptions.agentId !== undefined ||
      projectionOptions.sessionId !== undefined ||
      projectionOptions.storePath !== undefined)
  ) {
    return await buildOwnedNoRestoreEntry(absPath, projectionOptions);
  }
  assertNoRestoreLocalProjection(absPath, projectionOptions);
  return buildSessionEntryFromSource(absPath, projectionOptions, redactText);
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
  if (opts.readPolicy === "no-restore") {
    throw new SessionEntryNoRestoreError("opaque-reader");
  }
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
  options: Pick<
    BuildSessionEntryOptions,
    "agentId" | "sessionId" | "storePath" | "parseYieldEveryLines"
  >,
  snapshot: SessionEntrySnapshot,
  redaction: ReturnType<typeof captureSensitiveTextRedactionSnapshot>,
) {
  const entry = await buildSessionEntryFromSource(
    absPath,
    {
      agentId: options.agentId,
      sessionId: options.sessionId,
      storePath: options.storePath,
      parseYieldEveryLines: options.parseYieldEveryLines,
      readPolicy: "no-restore",
    },
    createSensitiveTextRedactor(redaction),
    { ...snapshot, events: snapshot.events.map(projectSessionEntryRecord) },
  );
  if (!entry) {
    throw new SessionEntryNoRestoreError("unprojectable");
  }
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
        if (opts.readPolicy === "no-restore") {
          throw new SessionEntryNoRestoreError("missing");
        }
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
          if (opts.readPolicy === "no-restore") {
            throw new SessionEntryNoRestoreError("unprojectable");
          }
          continue;
        }
      }
      if (
        opts.readPolicy === "no-restore" &&
        (!record || typeof record !== "object" || Array.isArray(record))
      ) {
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
        if (opts.readPolicy === "no-restore") {
          throw new SessionEntryNoRestoreError("unprojectable");
        }
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
        if (opts.readPolicy === "no-restore") {
          throw new SessionEntryNoRestoreError("unprojectable");
        }
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
      if (err instanceof SessionEntryNoRestoreError) {
        throw err;
      }
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
