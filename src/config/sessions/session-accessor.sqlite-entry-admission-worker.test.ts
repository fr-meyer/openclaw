import { beforeEach, expect, it, vi } from "vitest";
import { createDeferred } from "../../../test/helpers/promise.js";
import { loadSessionEntryForAdmission } from "./session-accessor.sqlite-entry-admission.js";

const fixture = vi.hoisted(() => ({
  database: { path: "/synthetic/admission.sqlite" },
  claim: { assertCurrent: vi.fn(), release: vi.fn() },
  open: vi.fn(),
  borrow: vi.fn(),
  read: vi.fn(),
  withReader: vi.fn(),
  incognito: false,
  pathCurrent: true,
  entry: { sessionId: "original", updatedAt: 1 },
}));

vi.mock("../../infra/sqlite-worker-identity.js", () => ({
  readDatabasePathIdentitySync: vi.fn(() => {
    throw new Error("Warm admission must keep its existing native owner");
  }),
}));
vi.mock("../../state/openclaw-agent-db-identity.js", () => ({
  createOpenClawAgentDatabaseClaim: () => fixture.claim,
  readOpenClawAgentDatabaseIdentity: () => ({ identity: "physical", birthtime: "birth" }),
  isOpenClawAgentDatabasePathCurrent: () => fixture.pathCurrent,
}));
vi.mock("../../state/openclaw-agent-db.js", () => ({
  getOpenClawAgentDatabaseIfOpen: () => fixture.database,
  openOpenClawAgentDatabase: () => {
    fixture.open();
    return fixture.database;
  },
  borrowOpenClawAgentDatabase: () => {
    fixture.borrow();
    return { release: vi.fn() };
  },
  resolveOpenClawAgentSqlitePath: () => fixture.database.path,
  isIncognitoOpenClawAgentSqlitePath: () => fixture.incognito,
  withOpenClawAgentDatabaseAsync: vi.fn(),
}));
vi.mock("./session-accessor.sqlite-entry-store.js", () => ({
  readSessionEntryRow: () => ({ entry: fixture.entry }),
}));
vi.mock("./session-accessor.sqlite-scope.js", () => ({
  resolveSqliteScope: (scope: { sessionKey: string }) => ({ ...scope, agentId: "main" }),
  toDatabaseOptions: () => ({ agentId: "main", env: { OPENCLAW_STATE_DIR: "/synthetic" } }),
}));
vi.mock("./session-transcript-worker-runtime.js", () => ({
  withSessionHistoryWorkerDatabase: fixture.withReader,
}));

const scope = { agentId: "main", sessionKey: "agent:main:admission" };
const receipt = { identity: "physical", birthtime: "birth" };

beforeEach(() => {
  vi.resetAllMocks();
  fixture.incognito = false;
  fixture.pathCurrent = true;
  fixture.withReader.mockImplementation(async (_options, run) =>
    run({ readExactEntries: fixture.read }),
  );
  fixture.read.mockResolvedValue({
    entries: [{ entry: fixture.entry }],
    databaseIdentity: receipt,
  });
});

it("retains the captured claim and exact authorization read across the lazy operation", async () => {
  const controller = new AbortController();
  const result = await loadSessionEntryForAdmission(scope, { signal: controller.signal });
  expect(result).toEqual({ entry: fixture.entry, databaseClaim: fixture.claim });
  expect(fixture.open).toHaveBeenCalledTimes(1);
  expect(fixture.borrow).toHaveBeenCalledTimes(1);
  expect(fixture.read).toHaveBeenCalledWith(
    {
      sessionKeys: [scope.sessionKey],
      env: { OPENCLAW_STATE_DIR: "/synthetic" },
      includeAuthorization: true,
    },
    controller.signal,
  );
  expect(fixture.claim.assertCurrent).toHaveBeenCalledTimes(1);
  expect(fixture.claim.release).not.toHaveBeenCalled();
});

it("rechecks authority after native capture before admitting a reader", async () => {
  const revoked = new Error("authority expired at module boundary");
  await expect(
    loadSessionEntryForAdmission(scope, {
      assertCurrent: () => {
        if (fixture.open.mock.calls.length > 0) {
          throw revoked;
        }
      },
    }),
  ).rejects.toBe(revoked);
  expect(fixture.borrow).toHaveBeenCalledTimes(1);
  expect(fixture.withReader).not.toHaveBeenCalled();
  expect(fixture.claim.release).toHaveBeenCalledTimes(1);
});

it.each(["claim", "path", "receipt"] as const)(
  "refuses a settled row after its retained %s changes during the worker read",
  async (changed) => {
    const entered = createDeferred();
    const read = createDeferred<{
      entries: { entry: typeof fixture.entry }[];
      databaseIdentity: typeof receipt;
    }>();
    fixture.read.mockImplementation(() => {
      entered.resolve();
      return read.promise;
    });
    const claimFailure = new Error("claim retired during worker read");
    const operation = loadSessionEntryForAdmission(scope);
    await entered.promise;
    if (changed === "claim") {
      fixture.claim.assertCurrent.mockImplementation(() => {
        throw claimFailure;
      });
    } else if (changed === "path") {
      fixture.pathCurrent = false;
    }
    read.resolve({
      entries: [{ entry: fixture.entry }],
      databaseIdentity: changed === "receipt" ? { ...receipt, identity: "replacement" } : receipt,
    });
    await expect(operation).rejects.toThrow(
      changed === "claim" ? claimFailure.message : "Session database changed during admission read",
    );
    expect(fixture.open).toHaveBeenCalledTimes(1);
    expect(fixture.claim.release).toHaveBeenCalledTimes(1);
  },
);

it("keeps incognito admission on its captured native row without a worker read", async () => {
  fixture.incognito = true;
  await expect(loadSessionEntryForAdmission(scope)).resolves.toEqual({
    entry: fixture.entry,
    databaseClaim: fixture.claim,
  });
  expect(fixture.withReader).not.toHaveBeenCalled();
  expect(fixture.claim.release).not.toHaveBeenCalled();
});
