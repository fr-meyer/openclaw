import { ok, type Result } from "@openclaw/normalization-core/result";
import { beforeEach, expect, it, vi } from "vitest";
import {
  hasSqliteWorkerOutcomeUnknown,
  SqliteWorkerError,
} from "../../infra/sqlite-worker-contract.js";
import type { DatabasePathIdentity } from "../../infra/sqlite-worker-identity.js";
import { createDeferredCore } from "../../shared/deferred.js";
import type {
  AgentDatabaseExecutionFileIdentity,
  AgentDatabaseRequestExecutionSource,
} from "../../state/openclaw-agent-execution-contract.js";
import type {
  captureOpenClawAgentDatabaseExecution,
  OpenClawAgentDatabaseExecution,
} from "../../state/openclaw-agent-execution.js";
import type { SessionTranscriptReconcileOperation } from "./session-transcript-reconcile-pool.js";
import type { captureSessionTranscriptReconcileReader } from "./session-transcript-reconcile-reader.js";
import type {
  SessionTranscriptReconcileWrite,
  SessionTranscriptReconcileWriteResult,
} from "./session-transcript-reconcile-write-contract.js";
import {
  isSessionTranscriptIndexReconcileRunning,
  reconcileSessionTranscriptIndexes,
  startSessionTranscriptIndexReconcile,
  waitForSessionTranscriptIndexReconcile,
} from "./session-transcript-reconcile.js";

// Deterministic entry/admission boundaries only: these cases launch no workers,
// create no SQLite files and make no assertion about native transport placement.
const owned = vi.hoisted(() => {
  const target: { identity: DatabasePathIdentity | undefined } = { identity: undefined };
  return {
    ...target,
    captureExecution: vi.fn<typeof captureOpenClawAgentDatabaseExecution>(),
    captureReader: vi.fn<typeof captureSessionTranscriptReconcileReader>(),
    read: vi.fn<() => Promise<Result<{ found: boolean; pending: boolean }, unknown>>>(),
    releaseReader: vi.fn<() => Promise<void>>(),
    phase:
      vi.fn<
        (command: SessionTranscriptReconcileWrite) => Promise<SessionTranscriptReconcileWriteResult>
      >(),
    pool: vi.fn<
      (
        generation: number,
        run: (operation: SessionTranscriptReconcileOperation) => Promise<unknown>,
        owner?: { agentId: string; path: string },
      ) => Promise<unknown>
    >(),
    startTask: vi.fn<SessionTranscriptReconcileOperation["startTask"]>(),
    nativeFallback: vi.fn<() => never>(),
    warn: vi.fn<(message: string) => void>(),
  };
});

vi.mock("node:timers/promises", async (importOriginal) => ({
  ...(await importOriginal<typeof import("node:timers/promises")>()),
  setImmediate: async () => undefined,
  setTimeout: async () => undefined,
}));
vi.mock("../../infra/sqlite-worker-identity.js", () => ({
  readDatabasePathIdentitySync: () => {
    if (!owned.identity) {
      throw new Error("Entry fixture has no physical target");
    }
    return owned.identity;
  },
}));
vi.mock("../../logging/subsystem.js", () => ({
  createSubsystemLogger: () => ({ warn: owned.warn }),
}));
vi.mock("../../state/openclaw-agent-execution.js", () => ({
  supportsOpenClawAgentDatabaseExecution: () => true,
  captureOpenClawAgentDatabaseExecution: owned.captureExecution,
}));
vi.mock("../../state/openclaw-agent-db.js", () => ({
  resolveOpenClawAgentSqlitePath: (options: { path: string }) => options.path,
  getOpenClawAgentDatabaseIfOpen: () => undefined,
  isIncognitoOpenClawAgentDatabase: () => false,
  isIncognitoOpenClawAgentSqlitePath: () => false,
  borrowOpenClawAgentDatabase: owned.nativeFallback,
  withOpenClawAgentDatabaseAsync: owned.nativeFallback,
  runOpenClawAgentWriteTransaction: owned.nativeFallback,
}));
vi.mock("../../state/openclaw-agent-db-readonly.js", () => ({
  withOpenClawAgentDatabaseReadOnly: owned.nativeFallback,
}));
vi.mock("./session-accessor.sqlite-scope.js", () => ({
  runExclusiveSqliteSessionWrite: async (_options: unknown, run: () => Promise<unknown>) =>
    await run(),
  getSessionKysely: owned.nativeFallback,
}));
vi.mock("./session-transcript-reconcile-pool.js", () => ({
  captureSessionTranscriptReconcileGeneration: () => 7,
  isSessionTranscriptReconcileGenerationCurrent: (generation: number) => generation === 7,
  runSessionTranscriptReconcileOperation: owned.pool,
}));
vi.mock("./session-transcript-reconcile-reader.js", () => ({
  captureSessionTranscriptReconcileReader: owned.captureReader,
}));
vi.mock("./session-transcript-reconcile-writer.js", () => ({
  createSessionTranscriptReconcileWriter: () => ({ write: owned.phase }),
}));

beforeEach(() => {
  vi.resetAllMocks();
  owned.nativeFallback.mockImplementation(() => {
    throw new Error("Durable reconciliation attempted parent native fallback");
  });
  owned.startTask.mockImplementation(async () => {
    throw new Error("Entry fixture unexpectedly started a planner");
  });
  owned.pool.mockImplementation(
    async (_generation, run) =>
      await run({
        signal: new AbortController().signal,
        retainLeaseForCleanup() {},
        startTask: owned.startTask,
      }),
  );
  owned.releaseReader.mockResolvedValue(undefined);
});

function fixture(pathname: string, missing = false) {
  const options = {
    agentId: "main",
    path: pathname,
    env: { OPENCLAW_STATE_DIR: "/synthetic/state" },
  };
  let accepted: AgentDatabaseExecutionFileIdentity | undefined;
  const physical = (identity: string): DatabasePathIdentity => ({
    key: `file:${identity}`,
    canonicalPath: pathname,
    birthtime: identity,
  });
  owned.identity = missing
    ? { key: `path:${pathname}`, canonicalPath: pathname }
    : physical("original");
  if (!missing) {
    accepted = {
      kind: "file",
      physicalIdentity: "original",
      nativeLocation: pathname,
      birthtime: "original",
    };
  }
  const prepare = vi
    .fn<OpenClawAgentDatabaseExecution["prepare"]>()
    .mockImplementation(async () => {
      if (!accepted) {
        owned.identity = physical("created");
        accepted = {
          kind: "file",
          physicalIdentity: "created",
          nativeLocation: pathname,
          birthtime: "created",
        };
      }
    });
  const releaseExecution = vi.fn<() => Promise<void>>().mockResolvedValue(undefined);
  const execution: OpenClawAgentDatabaseExecution = {
    agentId: options.agentId,
    path: pathname,
    get fileIdentity() {
      return accepted;
    },
    assertCurrent() {},
    prepare,
    async runExisting() {
      throw new Error("Entry fixture must not execute a native phase");
    },
    release: releaseExecution,
  };
  const source: AgentDatabaseRequestExecutionSource = {
    assertCurrent() {},
    createAdmission() {
      throw new Error("Entry fixture must not grant native access");
    },
  };
  owned.captureExecution.mockReturnValue(execution);
  owned.captureReader.mockImplementation((_target, _lane, expected) => ({
    fileIdentity: expected,
    assertCurrent() {},
    isRevokedFailure: () => false,
    read: owned.read,
    release: owned.releaseReader,
  }));
  owned.read.mockResolvedValue(ok({ found: !missing, pending: true }));
  owned.phase.mockImplementation(async (command) => {
    expect(command.kind).toBe("preflight");
    await execution.prepare(source);
    return { kind: "preflight", hasWork: false };
  });
  return { options, execution, source, physical, releaseExecution, prepare };
}

it("keeps unknown completion fenced when a pending request and reader cleanup failure coincide", async () => {
  const { options, releaseExecution } = fixture("/synthetic/unknown-cleanup.sqlite");
  const entered = createDeferredCore<void>();
  const phase = createDeferredCore<SessionTranscriptReconcileWriteResult>();
  const unknown = new SqliteWorkerError("Native phase completion unavailable", "outcome-unknown");
  const cleanup = new Error("Retained reader release failed");
  owned.phase.mockImplementationOnce(() => {
    entered.resolve();
    return phase.promise;
  });
  owned.releaseReader.mockRejectedValueOnce(cleanup);
  // A buggy handoff can finish deterministically, so the replay assertion fails
  // rather than allowing an accidental second planner to hang this case.
  owned.read
    .mockResolvedValueOnce(ok({ found: true, pending: true }))
    .mockResolvedValue(ok({ found: true, pending: false }));
  startSessionTranscriptIndexReconcile(options);
  await entered.promise;
  startSessionTranscriptIndexReconcile(options);
  phase.reject(unknown);
  await waitForSessionTranscriptIndexReconcile(options);
  expect(owned.pool).toHaveBeenCalledOnce();
  expect(owned.captureExecution).toHaveBeenCalledOnce();
  expect(owned.phase).toHaveBeenCalledOnce();
  expect(owned.read).toHaveBeenCalledOnce();
  expect(owned.startTask).not.toHaveBeenCalled();
  expect(owned.nativeFallback).not.toHaveBeenCalled();
  expect(releaseExecution).toHaveBeenCalledOnce();
  expect(isSessionTranscriptIndexReconcileRunning(options)).toBe(false);
});

it("preserves unknown write and both cleanup failures through the direct entry", async () => {
  const { options, releaseExecution } = fixture("/synthetic/direct-unknown.sqlite");
  const unknown = new SqliteWorkerError("Native phase completion unavailable", "outcome-unknown");
  const readerCleanup = new Error("Reader cleanup failed");
  const executorCleanup = new Error("Executor cleanup failed");
  owned.phase.mockRejectedValueOnce(unknown);
  owned.releaseReader.mockRejectedValueOnce(readerCleanup);
  releaseExecution.mockRejectedValueOnce(executorCleanup);
  const failure: unknown = await reconcileSessionTranscriptIndexes(options).catch(
    (error: unknown) => error,
  );
  expect(hasSqliteWorkerOutcomeUnknown(failure)).toBe(true);
  expect(failure).toBeInstanceOf(AggregateError);
  if (!(failure instanceof AggregateError)) {
    throw new Error("Entry did not preserve both cleanup failures");
  }
  expect(failure.errors).toContain(executorCleanup);
  const readerFailure: unknown = failure.cause;
  expect(readerFailure).toBeInstanceOf(AggregateError);
  if (!(readerFailure instanceof AggregateError)) {
    throw new Error("Reader cleanup replaced the primary unknown outcome");
  }
  expect(readerFailure.errors).toEqual([unknown, readerCleanup]);
  expect(owned.phase).toHaveBeenCalledOnce();
  expect(owned.startTask).not.toHaveBeenCalled();
  expect(owned.nativeFallback).not.toHaveBeenCalled();
});

it("refuses a foreign file appearing after missing-store capture before a clean read", async () => {
  const { options, physical, releaseExecution } = fixture("/synthetic/absent-race.sqlite", true);
  owned.read.mockResolvedValue(ok({ found: true, pending: false }));
  const run = owned.pool.getMockImplementation();
  if (!run) {
    throw new Error("Entry fixture has no admission operation");
  }
  owned.pool.mockImplementation((...args) => {
    owned.identity = physical("foreign");
    return run(...args);
  });
  await expect(reconcileSessionTranscriptIndexes(options)).rejects.toThrow(
    "captured physical database target",
  );
  expect(owned.captureExecution.mock.calls[0]?.[1]).toEqual({
    expectedCreationIdentity: { key: `path:${options.path}`, canonicalPath: options.path },
  });
  expect(owned.captureReader).not.toHaveBeenCalled();
  expect(owned.read).not.toHaveBeenCalled();
  expect(owned.phase).not.toHaveBeenCalled();
  expect(owned.startTask).not.toHaveBeenCalled();
  expect(owned.nativeFallback).not.toHaveBeenCalled();
  expect(releaseExecution).toHaveBeenCalledOnce();
});

it("accepts owned first-use creation and retains its receipt for a pending clean probe", async () => {
  const { options, execution, source, prepare } = fixture(
    "/synthetic/owned-first-use.sqlite",
    true,
  );
  const entered = createDeferredCore<void>();
  const finish = createDeferredCore<void>();
  owned.phase.mockImplementationOnce(async () => {
    await execution.prepare(source);
    entered.resolve();
    await finish.promise;
    return { kind: "preflight", hasWork: false };
  });
  owned.read
    .mockResolvedValueOnce(ok({ found: false, pending: false }))
    .mockResolvedValue(ok({ found: true, pending: false }));
  startSessionTranscriptIndexReconcile(options);
  await entered.promise;
  startSessionTranscriptIndexReconcile(options);
  finish.resolve();
  await waitForSessionTranscriptIndexReconcile(options);
  expect(owned.pool).toHaveBeenCalledOnce();
  expect(prepare).toHaveBeenCalledOnce();
  expect(owned.phase).toHaveBeenCalledOnce();
  expect(owned.read).toHaveBeenCalledTimes(2);
  expect(owned.captureReader.mock.calls[1]?.[2]).toEqual({
    key: "file:created",
    birthtime: "created",
  });
  expect(owned.warn).not.toHaveBeenCalled();
  expect(owned.startTask).not.toHaveBeenCalled();
  expect(owned.nativeFallback).not.toHaveBeenCalled();
});

it("refuses same-locator replacement after owned prepare before a latched second probe", async () => {
  const { options, execution, source, physical, prepare } = fixture(
    "/synthetic/created-replacement.sqlite",
    true,
  );
  const entered = createDeferredCore<void>();
  const finish = createDeferredCore<void>();
  owned.phase.mockImplementationOnce(async () => {
    await execution.prepare(source);
    entered.resolve();
    await finish.promise;
    return { kind: "preflight", hasWork: false };
  });
  owned.read
    .mockResolvedValueOnce(ok({ found: false, pending: false }))
    .mockResolvedValue(ok({ found: true, pending: false }));
  // The first pass accepts its own file. Replacement happens as that reader
  // releases, immediately before the pending pass can create a new reader.
  owned.releaseReader.mockImplementationOnce(async () => {
    owned.identity = physical("replacement");
  });
  startSessionTranscriptIndexReconcile(options);
  await entered.promise;
  startSessionTranscriptIndexReconcile(options);
  finish.resolve();
  await waitForSessionTranscriptIndexReconcile(options);
  expect(owned.pool).toHaveBeenCalledOnce();
  expect(prepare).toHaveBeenCalledOnce();
  expect(owned.phase).toHaveBeenCalledOnce();
  expect(owned.captureReader).toHaveBeenCalledOnce();
  expect(owned.read).toHaveBeenCalledOnce();
  expect(owned.warn).toHaveBeenCalledWith(
    expect.stringContaining("captured physical database target"),
  );
  expect(owned.startTask).not.toHaveBeenCalled();
  expect(owned.nativeFallback).not.toHaveBeenCalled();
  expect(isSessionTranscriptIndexReconcileRunning(options)).toBe(false);
});
