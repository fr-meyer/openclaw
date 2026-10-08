import { err, ok, type Result } from "@openclaw/normalization-core/result";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { createDeferredCore } from "../../shared/deferred.js";
import { captureSessionTranscriptReconcileReader } from "./session-transcript-reconcile-reader.js";
import { historyLane, maintenanceLane } from "./session-transcript-worker-resources.js";
import type {
  SessionHistoryWorkerDatabase,
  SessionTranscriptReconcilePendingRead,
} from "./session-transcript-worker.types.js";

type RetainedReader = {
  owner: Pick<
    SessionHistoryWorkerDatabase,
    "assertCurrent" | "readTranscriptReconcilePendingResult"
  >;
  isRevokedFailure(error: unknown): boolean;
  release(): void;
};

const owned = vi.hoisted(() => ({
  read: vi.fn<SessionHistoryWorkerDatabase["readTranscriptReconcilePendingResult"]>(),
  assertCurrent: vi.fn<() => void>(),
  release: vi.fn<() => void>(),
  isRevokedFailure: vi.fn<(error: unknown) => boolean>(),
  retain: vi.fn<(options: unknown, lane: unknown) => RetainedReader>(),
  assertIdentity: vi.fn<(path: string, identity: string, birthtime?: string) => void>(),
  identity: { key: "file:1:2", canonicalPath: "/synthetic/reconcile.sqlite", birthtime: "3" },
}));
vi.mock("./session-transcript-worker-runtime.js", () => ({
  retainSessionHistoryWorkerDatabase: owned.retain,
}));
vi.mock("./session-transcript-worker-resources.js", () => ({
  historyLane: { name: "existing foreground" },
  maintenanceLane: { name: "existing maintenance" },
}));
vi.mock("../../infra/sqlite-worker-identity.js", () => ({
  readDatabasePathIdentitySync: () => owned.identity,
  assertExistingDatabaseIdentity: owned.assertIdentity,
}));

beforeEach(() => {
  vi.resetAllMocks();
  owned.identity = {
    key: "file:1:2",
    canonicalPath: "/synthetic/reconcile.sqlite",
    birthtime: "3",
  };
  owned.isRevokedFailure.mockReturnValue(false);
  owned.retain.mockReturnValue({
    owner: {
      assertCurrent: owned.assertCurrent,
      readTranscriptReconcilePendingResult: owned.read,
    },
    isRevokedFailure: owned.isRevokedFailure,
    release: owned.release,
  });
});
afterEach(() => vi.restoreAllMocks());

function capture() {
  const env = { OPENCLAW_STATE_DIR: "/synthetic/state", PRIVATE_READER_TEST_TOKEN: "excluded" };
  const reader = captureSessionTranscriptReconcileReader({
    agentId: "main",
    path: "/synthetic/reconcile.sqlite",
    env,
  });
  env.OPENCLAW_STATE_DIR = "/synthetic/successor";
  return reader;
}

it("captures exact durable custody before the first read, without retaining unrelated env", async () => {
  const reader = capture();
  expect(owned.retain).toHaveBeenCalledWith(
    {
      agentId: "main",
      path: "/synthetic/reconcile.sqlite",
      env: { OPENCLAW_STATE_DIR: "/synthetic/state" },
    },
    historyLane,
  );
  owned.read.mockResolvedValue(ok({ found: true, pending: true }));
  await expect(reader.read("selected")).resolves.toEqual(ok({ found: true, pending: true }));
  expect(owned.read).toHaveBeenCalledWith({
    env: { OPENCLAW_STATE_DIR: "/synthetic/state" },
    sessionId: "selected",
    fileIdentity: { key: "file:1:2", birthtime: "3" },
  });
  await reader.release();
  expect(owned.release).toHaveBeenCalledOnce();
});

it("preserves uncertain data separately from rejected worker reads", async () => {
  const reader = capture();
  const dataError = new Error("uncertain projection query");
  const workerError = new Error("worker cleanup failed");
  owned.read.mockResolvedValueOnce(err(dataError)).mockRejectedValueOnce(workerError);
  await expect(reader.read()).resolves.toEqual(err(dataError));
  await expect(reader.read()).rejects.toBe(workerError);
  expect(owned.read).toHaveBeenCalledTimes(2);
  await reader.release();
});

it("delegates revocation classification to the retained owner without matching error text", async () => {
  const reader = capture();
  const revocation = new Error("database revoked");
  owned.isRevokedFailure.mockImplementation((error) => error === revocation);
  expect(reader.isRevokedFailure(revocation)).toBe(true);
  expect(reader.isRevokedFailure(new Error("database revoked"))).toBe(false);
  expect(owned.isRevokedFailure).toHaveBeenCalledTimes(2);
  await reader.release();
});

it("joins accepted reads before release and refuses successor reads", async () => {
  const reader = capture();
  const pending = createDeferredCore<Result<SessionTranscriptReconcilePendingRead, unknown>>();
  owned.read.mockReturnValueOnce(pending.promise);
  const reading = reader.read();
  const releasing = reader.release();
  expect(owned.release).not.toHaveBeenCalled();
  expect(() => reader.read()).toThrow("released");
  pending.resolve(ok({ found: false, pending: false }));
  await reading;
  await releasing;
  expect(owned.release).toHaveBeenCalledOnce();
});

it("refuses revoked or replaced ownership before dispatch and keeps release retryable", async () => {
  const reader = capture();
  owned.assertIdentity.mockImplementationOnce(() => {
    throw new Error("physical owner replaced");
  });
  expect(() => reader.read()).toThrow("physical owner replaced");
  expect(owned.read).not.toHaveBeenCalled();
  owned.assertCurrent.mockImplementationOnce(() => {
    throw new Error("database revoked");
  });
  expect(() => reader.read()).toThrow("database revoked");
  owned.release.mockImplementationOnce(() => {
    throw new Error("retained cleanup failed");
  });
  await expect(reader.release()).rejects.toThrow("retained cleanup failed");
  await expect(reader.release()).resolves.toBeUndefined();
  expect(owned.release).toHaveBeenCalledTimes(2);
});

it("keeps process-held incognito state outside durable worker admission", () => {
  expect(() =>
    captureSessionTranscriptReconcileReader({
      agentId: "main",
      path: "/synthetic/state/agents/main/agent/incognito-openclaw-agent.sqlite",
      env: { OPENCLAW_STATE_DIR: "/synthetic/state" },
    }),
  ).toThrow("process-held owner");
  expect(owned.retain).not.toHaveBeenCalled();
});

it("uses the existing maintenance lane for the whole-store probe", async () => {
  const reader = captureSessionTranscriptReconcileReader(
    {
      agentId: "main",
      path: "/synthetic/reconcile.sqlite",
      env: { OPENCLAW_STATE_DIR: "/synthetic/state" },
    },
    "maintenance",
  );
  expect(owned.retain.mock.calls[0]?.[1]).toBe(maintenanceLane);
  await reader.release();
});

it("renews the cache owner with the original immutable physical receipt", async () => {
  const original = capture();
  const identity = original.fileIdentity;
  expect(identity).toEqual({ key: "file:1:2", birthtime: "3" });
  expect(Object.isFrozen(identity)).toBe(true);
  await original.release();
  const expected = { key: "file:1:2", birthtime: "3" };
  const renewed = captureSessionTranscriptReconcileReader(
    { agentId: "main", path: "/synthetic/reconcile.sqlite", env: {} },
    "history",
    expected,
  );
  // Later caller mutation and same-locator cache turnover cannot replace the receipt.
  expected.key = "file:successor";
  expected.birthtime = "successor";
  owned.read.mockResolvedValueOnce(ok({ found: true, pending: true }));
  await renewed.read("selected");
  expect(owned.read.mock.calls.at(-1)?.[0].fileIdentity).toEqual(identity);
  expect(owned.assertIdentity).toHaveBeenLastCalledWith(
    "/synthetic/reconcile.sqlite",
    "file:1:2",
    "3",
  );
  await renewed.release();
});

it.each([
  { key: "file:replacement", birthtime: "3" },
  { key: "file:1:2", birthtime: "replacement" },
  { key: "path:/synthetic/reconcile.sqlite", birthtime: "3" },
])(
  "refuses a replaced or non-file renewal before retaining custody: $key/$birthtime",
  async (identity) => {
    const original = capture();
    const expected = original.fileIdentity;
    await original.release();
    // Keep the recorded original receipt while the locator is replaced or recycled.
    owned.identity = { ...identity, canonicalPath: "/synthetic/reconcile.sqlite" };
    owned.retain.mockClear();
    expect(() =>
      captureSessionTranscriptReconcileReader(
        { agentId: "main", path: "/synthetic/reconcile.sqlite", env: {} },
        "history",
        expected,
      ),
    ).toThrow("identity changed before renewal");
    expect(owned.retain).not.toHaveBeenCalled();
  },
);

it("keeps the original receipt in dispatch if replacement races a renewed reader", async () => {
  const original = capture();
  const expected = original.fileIdentity;
  await original.release();
  const renewed = captureSessionTranscriptReconcileReader(
    { agentId: "main", path: "/synthetic/reconcile.sqlite", env: {} },
    "history",
    expected,
  );
  owned.read.mockImplementationOnce(async (input) => {
    // Admission checked the original file, but a replacement happened before the
    // worker opened it. The worker must still receive the original expected identity.
    expect(input.fileIdentity).toEqual(expected);
    throw new Error("worker rejected replacement physical owner");
  });
  await expect(renewed.read("selected")).rejects.toThrow("replacement physical owner");
  await renewed.release();
});

it("preserves missing-store probes without treating absence as a renewal grant", async () => {
  owned.identity = {
    key: "path:/synthetic/reconcile.sqlite",
    canonicalPath: "/synthetic/reconcile.sqlite",
    birthtime: "unused for absence",
  };
  const reader = capture();
  expect(reader.fileIdentity).toBeUndefined();
  owned.read.mockResolvedValueOnce(ok({ found: false, pending: false }));
  await expect(reader.read()).resolves.toEqual(ok({ found: false, pending: false }));
  expect(owned.assertIdentity).not.toHaveBeenCalled();
  await reader.release();
  owned.retain.mockClear();
  expect(() =>
    captureSessionTranscriptReconcileReader(
      { agentId: "main", path: "/synthetic/reconcile.sqlite", env: {} },
      "history",
      { key: owned.identity.key },
    ),
  ).toThrow("identity changed before renewal");
  expect(owned.retain).not.toHaveBeenCalled();
});
