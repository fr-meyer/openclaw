import path from "node:path";
import { captureSensitiveTextRedactionSnapshot } from "../../logging/redact.js";
import { readOwnedWarmSessionSnapshotSync } from "./session-accessor.sqlite-read.js";
import { captureSessionTranscriptStorageEnvironment } from "./transcript-target-binding.js";
import {
  resolveWorkerPoolSize,
  SESSION_TRANSCRIPT_FOREGROUND_WORKERS,
} from "../../infra/worker-pool-sizing.js";
import type { SensitiveTextRedactionSnapshot } from "../../logging/redact.js";
import type { readSessionTranscriptModelContext } from "./session-accessor.sqlite-model-context.js";
import type { SessionTranscriptRuntimeTarget } from "./session-accessor.types.js";
import type { SessionContextMessagesWorkerInput } from "./session-history-read.types.js";
import { unwrapSessionTranscriptWorkerReply } from "./session-history-worker-errors.js";
import { resolveSessionTranscriptReadFence } from "./session-transcript-read-fence.js";
import { createSessionTranscriptReadPool } from "./session-transcript-read-pools.js";
import type {
  SessionEntryWorkerInput,
  SessionEntryProjectionWorkerInput,
  SessionResetRecallWorkerInput,
  SessionModelContextWorkerInput,
  SessionSqliteTargetWorkerInput,
} from "./session-transcript-worker.types.js";

// Callers retain writer admission and validate snapshots before consuming parallel reads.
const modelContextReads = createSessionTranscriptReadPool<
  | SessionModelContextWorkerInput
  | SessionSqliteTargetWorkerInput
  | SessionContextMessagesWorkerInput
>(SESSION_TRANSCRIPT_FOREGROUND_WORKERS);

// Background transcript exports cannot occupy the foreground context worker.
const sessionEntries = createSessionTranscriptReadPool<
  SessionEntryWorkerInput | SessionResetRecallWorkerInput | SessionEntryProjectionWorkerInput
>(resolveWorkerPoolSize("singleton"), true);

export async function readSessionTranscriptModelContextInWorker(
  target: SessionTranscriptRuntimeTarget,
  admission: SessionModelContextWorkerInput["admission"],
  signal?: AbortSignal,
  through?: SessionModelContextWorkerInput["through"],
  limits?: SessionModelContextWorkerInput["limits"],
  expectedIdentity?: SessionModelContextWorkerInput["expectedIdentity"],
): Promise<ReturnType<typeof readSessionTranscriptModelContext>> {
  signal?.throwIfAborted();
  const value = unwrapSessionTranscriptWorkerReply(
    await modelContextReads.run(
      { kind: "model-context", target, admission, through, limits, expectedIdentity },
      { timeoutMs: 60_000, signal },
    ),
  );
  if (!("events" in value)) {
    throw new Error("Session context worker returned a database target instead of context");
  }
  return value;
}

export async function resolveSessionSqliteTargetInWorker(
  input: Omit<SessionSqliteTargetWorkerInput, "kind">,
  signal?: AbortSignal,
) {
  signal?.throwIfAborted();
  const value = unwrapSessionTranscriptWorkerReply(
    await modelContextReads.run(
      { kind: "sqlite-target", ...input },
      { inputBytes: JSON.stringify(input).length * 2, timeoutMs: 60_000, signal },
    ),
  );
  if (!("target" in value)) {
    throw new Error("Session context worker returned context instead of a database target");
  }
  return value.target;
}

export async function readSessionTranscriptContextMessagesInWorker(
  target: SessionTranscriptRuntimeTarget,
  admission: SessionContextMessagesWorkerInput["admission"],
  signal?: AbortSignal,
  expectedIdentity?: SessionContextMessagesWorkerInput["expectedIdentity"],
) {
  signal?.throwIfAborted();
  const value = unwrapSessionTranscriptWorkerReply(
    await modelContextReads.run(
      { kind: "context-messages", target, admission, expectedIdentity },
      { timeoutMs: 60_000, signal },
    ),
  );
  if (!("messages" in value)) {
    throw new Error("Session context worker returned a different context operation");
  }
  return value;
}

/** Only locators enter; the actual native owner selects data BEFORE any enqueue. */
export async function prepareOwnedSessionEntryProjectionInWorker(
  absPath: string,
  options: SessionEntryProjectionWorkerInput["options"] & { sessionKey: string },
  env: NodeJS.ProcessEnv,
  signal?: AbortSignal,
) {
  try {
    signal?.throwIfAborted();
    const captured = Object.freeze({ agentId: options.agentId, sessionId: options.sessionId,
      storePath: options.storePath, sessionKey: options.sessionKey, parseYieldEveryLines: options.parseYieldEveryLines });
    if (path.resolve(absPath) !== path.resolve(captured.storePath)) { throw new Error(); }
    const namespace = captureSessionTranscriptStorageEnvironment(env);
    const redaction = captureSensitiveTextRedactionSnapshot();
    const observed = readOwnedWarmSessionSnapshotSync({ ...captured, env: namespace });
    if (observed.status !== "observed-not-atomic") { throw new Error(); }
    const binding = JSON.stringify([absPath, captured.agentId, captured.sessionId, captured.storePath,
      observed.value.sessionKey, redaction.registryRevision]);
    const input: SessionEntryProjectionWorkerInput = {
      kind: "session-entry-projection", binding, absPath,
      options: { agentId: captured.agentId, sessionId: captured.sessionId, storePath: captured.storePath,
        parseYieldEveryLines: captured.parseYieldEveryLines },
      snapshot: observed.value, redaction,
    };
    // Existing native pool owns task ids, cancellation, deadline and the reply promise.
    const result = unwrapSessionTranscriptWorkerReply<"session-entry" | "session-reset-recall" | "session-entry-projection">(await sessionEntries.run(input,
      { inputBytes: JSON.stringify(input).length * 2, timeoutMs: 60_000, signal }));
    signal?.throwIfAborted();
    if (!("kind" in result) || result.kind !== "session-entry-projection" ||
      result.binding !== binding || result.registryRevision !== redaction.registryRevision ||
      !result.entry || result.entry.absPath !== absPath || typeof result.entry.content !== "string" ||
      typeof result.entry.hash !== "string" || !result.resetRecallCutoff ||
      typeof result.resetRecallCutoff.state !== "string") { throw new Error(); }
    return result;
  } catch { throw new Error("Native session projection unavailable"); }
}

export async function prepareSessionEntryInWorker(
  absPath: string,
  options: SessionEntryWorkerInput["options"],
  redaction: SensitiveTextRedactionSnapshot,
) {
  const receipt = resolveSessionTranscriptReadFence(options);
  const result = unwrapSessionTranscriptWorkerReply<"session-entry" | "session-reset-recall">(
    await sessionEntries.run(
      {
        kind: "session-entry",
        absPath,
        options,
        redaction,
        ...(receipt ? { admission: { ...receipt } } : {}),
      },
      {
        inputBytes:
          2 *
          (absPath.length +
            options.agentId.length +
            options.sessionId.length +
            options.storePath.length +
            (options.sessionKey?.length ?? 0) +
            redaction.registeredSecretValues.reduce((bytes, value) => bytes + value.length, 0)),
      },
    ),
  );
  if (!("entry" in result)) {
    throw new Error("Session transcript worker returned reset metadata instead of an export");
  }
  return result;
}

export async function readSessionResetRecallCutoffInWorker(
  scope: SessionResetRecallWorkerInput["scope"],
) {
  const receipt = resolveSessionTranscriptReadFence(scope);
  const result = unwrapSessionTranscriptWorkerReply<"session-entry" | "session-reset-recall">(
    await sessionEntries.run(
      {
        kind: "session-reset-recall",
        scope,
        ...(receipt ? { admission: { ...receipt } } : {}),
      },
      { inputBytes: JSON.stringify(scope).length * 2 },
    ),
  );
  if (!("cutoff" in result)) {
    throw new Error("Session transcript worker returned an export instead of reset metadata");
  }
  return result.cutoff;
}
