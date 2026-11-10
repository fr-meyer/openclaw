import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { Worker } from "node:worker_threads";
import { isRecord } from "@openclaw/normalization-core/record-coerce";
import { expect, it, vi } from "vitest";
import { drainGlobalSingletonLifecycleState } from "../shared/global-singleton.js";
import { initializeSqliteRuntimeCapabilities } from "./bun-sqlite-library.js";
import {
  useSqliteWorkerStoreFixture,
  appendWorkerRow as append,
  readWorkerRows as read,
} from "./sqlite-worker-fixture.test-support.js";
import { createSqliteWorkerOperationAdmission } from "./sqlite-worker-operation-admission.js";
import {
  closeUnclaimedSharedStateSqliteWorkers,
  hasUnclaimedSharedStateSqliteCleanup,
  openAgentDatabaseSqliteWorkerStore,
} from "./sqlite-worker-store.js";
import type { FixtureOperations } from "./sqlite-worker-store.test-support.js";

vi.mock("node:os", async (importOriginal) => ({
  ...(await importOriginal<typeof import("node:os")>()),
  availableParallelism: () => 32,
}));

const { stores, databasePath, open } = useSqliteWorkerStoreFixture(
  "openclaw-sqlite-worker-open-refusal-",
);

const { explicitSqliteCloseReleasesNativeResources } = await initializeSqliteRuntimeCapabilities();

it
  .skipIf(!explicitSqliteCloseReleasesNativeResources)
  .each(["branded native work", "unbranded native work", "re-export"] as const)(
  "retires custom factory refusal rather than trusting its %s",
  async (kind) => {
    const file = databasePath();
    const root = path.dirname(file);
    await writeFile(file, "");
    const modulePath = path.join(root, "custom-refusal.mjs");
    const backend = new URL("../state/openclaw-agent-execution.worker.ts", import.meta.url).href;
    await writeFile(
      modulePath,
      kind === "re-export"
        ? `export { createSqliteWorkerBackend, openExistingSqliteWorkerBackend } from ${JSON.stringify(backend)};`
        : `
        import { DatabaseSync } from "node:sqlite";
        import { createSqliteWorkerPreNativeOpenRefusal, SqliteWorkerOpenRefusedError } from ${JSON.stringify(new URL("./sqlite-worker-open-refusal.ts", import.meta.url).href)};
        import { requestSqliteWorkerOperationAdmission } from ${JSON.stringify(new URL("./sqlite-worker-operation-admission.ts", import.meta.url).href)};
        const retained = [];
        export function openExistingSqliteWorkerBackend(input, context) {
          const database = new DatabaseSync(context.databasePath);
          retained.push(database);
          database.exec("CREATE TABLE entries (id INTEGER PRIMARY KEY, value TEXT NOT NULL); INSERT INTO entries (value) VALUES ('committed before refusal'); BEGIN IMMEDIATE; INSERT INTO entries (value) VALUES ('must roll back')");
          try { requestSqliteWorkerOperationAdmission({ stage: "open", facts: input }); }
          catch (error) { throw ${kind === "branded native work" ? "createSqliteWorkerPreNativeOpenRefusal(error)" : "new SqliteWorkerOpenRefusedError(error)"}; }
          throw new Error("Fixture guard unexpectedly granted");
        }
      `,
    );
    const siblings = [];
    for (let index = 0; index < 4; index++) {
      const store = await open(databasePath());
      siblings.push({ store, receipt: await append(store, "before custom refusal") });
    }
    const refusal = new Error("Synthetic custom factory admission refused");
    let openingRequests = 0;
    let refusedThread = -1;
    const replies: Record<string, unknown>[] = [];
    const requests = vi.spyOn(Worker.prototype, "postMessage");
    const messages = vi.spyOn(Worker.prototype, "emit").mockImplementation(function (
      this: Worker,
      event: string | symbol,
      ...args: unknown[]
    ) {
      const reply = args[0];
      if (
        event === "message" &&
        isRecord(reply) &&
        reply.ok === false &&
        requests.mock.calls.some(
          ([request], index) =>
            requests.mock.contexts[index] === this &&
            request.type === "open" &&
            request.databasePath === file &&
            request.id === reply.id,
        )
      ) {
        refusedThread = this.threadId;
        replies.push(reply);
      }
      return EventEmitter.prototype.emit.call(this, event, ...args);
    });
    try {
      await expect(
        openAgentDatabaseSqliteWorkerStore<FixtureOperations>(
          {
            moduleUrl: pathToFileURL(modulePath),
            databasePath: file,
            existingOnly: true,
            input: {
              agentId: "main",
              databasePath: file,
              stateDatabasePath: path.join(root, "state.sqlite"),
              leaseId: "synthetic",
              environment: { OPENCLAW_STATE_DIR: root },
            },
          },
          {
            stateContext: { environment: { OPENCLAW_STATE_DIR: root } },
            assertCurrent() {},
            createAdmission: () => ({
              nativeLocations: [file],
              admission: createSqliteWorkerOperationAdmission((request, grant) => {
                if (request.stage === "open" && ++openingRequests === 2) {
                  throw refusal;
                }
                grant();
              }),
            }),
          },
        ),
      ).rejects.toBe(refusal);
      expect(openingRequests).toBe(2);
      expect(replies).toHaveLength(1);
      expect(replies[0]).toMatchObject({ openOutcome: "refused-before-agent-open" });
      expect(replies[0]?.preNativeOpenRefusal).toBeUndefined();
      expect(replies[0]?.openNotEntered).toBeUndefined();
      expect(siblings.some(({ receipt }) => receipt.threadId === refusedThread)).toBe(true);
      for (const { store, receipt } of siblings) {
        if (receipt.threadId === refusedThread) {
          await expect(append(store, "must not enter")).rejects.toBeInstanceOf(Error);
        } else {
          expect(await append(store, "healthy carrier survives")).toEqual({
            ...receipt,
            writes: 2,
          });
        }
      }
      const recovered = await open(file);
      expect(await read(recovered)).toEqual(
        kind === "re-export" ? [] : ["committed before refusal"],
      );
    } finally {
      messages.mockRestore();
      requests.mockRestore();
      await Promise.allSettled(siblings.map(({ store }) => store.close()));
      for (const { store } of siblings) {
        stores.delete(store);
      }
      await drainGlobalSingletonLifecycleState();
    }
  },
);

it.skipIf(!explicitSqliteCloseReleasesNativeResources)(
  "refuses before native factory entry without retiring pooled siblings or blocking recovery",
  async () => {
    const file = databasePath();
    const root = path.dirname(file);
    const seeded = await open(file);
    await seeded.close();
    const siblings = [];
    for (let index = 0; index < 4; index++) {
      const store = await open(databasePath());
      siblings.push({ store, receipt: await append(store, "before refusal") });
    }
    const refused = new Error("Fixture opening authority revoked");
    let allowed = false;
    const markerPath = path.join(root, "factory-entered");
    const reopen = async () => {
      const store = await openAgentDatabaseSqliteWorkerStore<FixtureOperations>(
        {
          moduleUrl: new URL("./sqlite-worker-store.test-support.ts", import.meta.url),
          databasePath: file,
          existingOnly: true,
          input: { type: "observe", markerPath },
        },
        {
          stateContext: {
            environment: { OPENCLAW_STATE_DIR: root },
          },
          assertCurrent() {},
          createAdmission: () => ({
            nativeLocations: [file],
            admission: createSqliteWorkerOperationAdmission((request, grant) => {
              expect(request).toEqual({ stage: "open", facts: { type: "observe", markerPath } });
              if (!allowed) {
                throw refused;
              }
              grant();
            }),
          }),
        },
      );
      if (store) {
        stores.add(store);
      }
      return store;
    };
    const requests = vi.spyOn(Worker.prototype, "postMessage");
    try {
      await expect(reopen()).rejects.toBe(refused);
      const opening = requests.mock.calls.findIndex(
        ([request]) => request.type === "open" && request.databasePath === file,
      );
      const targetWorker = requests.mock.contexts[opening];
      assert(targetWorker instanceof Worker, "Expected the refused request's native Worker");
      expect(siblings.map(({ receipt }) => receipt.threadId)).toContain(targetWorker.threadId);
      await expect(readFile(markerPath)).rejects.toMatchObject({ code: "ENOENT" });
      expect(hasUnclaimedSharedStateSqliteCleanup(file)).toBe(false);
      await closeUnclaimedSharedStateSqliteWorkers(file);
      allowed = true;
      const recovered = await reopen();
      expect(recovered).toBeDefined();
      expect(await readFile(markerPath, "utf8")).toBe("factory called");
      await recovered?.close();
      for (const { store, receipt } of siblings) {
        expect(await append(store, "after cleanup")).toEqual({ ...receipt, writes: 2 });
        expect(await read(store)).toEqual(["before refusal", "after cleanup"]);
      }
    } finally {
      requests.mockRestore();
      await drainGlobalSingletonLifecycleState();
    }
  },
);
