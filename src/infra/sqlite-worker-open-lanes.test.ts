import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { writeFile } from "node:fs/promises";
import { getEnvironmentData, setEnvironmentData, Worker } from "node:worker_threads";
import { isRecord } from "@openclaw/normalization-core/record-coerce";
import { it, expect, vi } from "vitest";
import { withinTest } from "../../test/helpers/promise.js";
import { createDeferredCore } from "../shared/deferred.js";
import { initializeSqliteRuntimeCapabilities } from "./bun-sqlite-library.js";
import { SqliteWorkerBroker } from "./sqlite-worker-broker.js";
import {
  useSqliteWorkerStoreFixture,
  appendWorkerRow as append,
  readWorkerRows as read,
} from "./sqlite-worker-fixture.test-support.js";
import type { FixtureOpenInput, FixtureOperations } from "./sqlite-worker-store.test-support.js";

vi.mock("node:os", async (importOriginal) => ({
  ...(await importOriginal<typeof import("node:os")>()),
  availableParallelism: () => 32,
}));

const { databasePath } = useSqliteWorkerStoreFixture("sqlite-worker-open-lanes-");
const { explicitSqliteCloseReleasesNativeResources } = await initializeSqliteRuntimeCapabilities();
const poolIt = explicitSqliteCloseReleasesNativeResources ? it : it.skip;

poolIt(
  "opens unrelated existing databases beside a blocked native factory at full pool capacity",
  async ({ signal }) => {
    const broker = new SqliteWorkerBroker();
    const files = Array.from({ length: 5 }, () => databasePath());
    await Promise.all(files.map((file) => writeFile(file, "")));
    const busyFile = files[0];
    const independentFile = files[4];
    assert(busyFile && independentFile);
    const gateKey = `sqlite-worker-open-gate:${busyFile}`;
    const previousGate = getEnvironmentData(gateKey);
    const gate = new Int32Array(new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT));
    setEnvironmentData(gateKey, gate.buffer);
    const entered = createDeferredCore();
    const messages = vi.spyOn(Worker.prototype, "emit");
    messages.mockImplementation(function (
      this: Worker,
      event: string | symbol,
      ...args: unknown[]
    ) {
      if (event === "message" && isRecord(args[0]) && args[0].sqliteFixtureOpening === busyFile) {
        entered.resolve();
        return true;
      }
      return EventEmitter.prototype.emit.call(this, event, ...args);
    });
    const pending: Promise<unknown>[] = [];
    const openStore = (pathname: string, input?: FixtureOpenInput) => {
      const opening = broker.open<FixtureOperations>({
        moduleUrl: new URL("./sqlite-worker-store.test-support.ts", import.meta.url),
        databasePath: pathname,
        input,
      });
      pending.push(opening);
      return opening;
    };
    let slowSettled = false;
    const slow = openStore(busyFile, { type: "block-open", gateKey }).finally(() => {
      slowSettled = true;
    });
    try {
      await withinTest(entered.promise, signal);
      // The remaining three opens fill the four-worker pool while the first
      // factory is still synchronously blocked on its own native thread.
      for (const file of files.slice(1, 4)) {
        assert(await withinTest(openStore(file), signal));
      }
      const independent = await withinTest(openStore(independentFile), signal);
      assert(independent);
      expect(
        await withinTest(append(independent, "unrelated database remains responsive"), signal),
      ).toMatchObject({
        writes: 1,
      });
      expect(await withinTest(read(independent), signal)).toEqual([
        "unrelated database remains responsive",
      ]);
      expect(slowSettled).toBe(false);
    } finally {
      Atomics.store(gate, 0, 1);
      Atomics.notify(gate, 0);
      await Promise.allSettled([...pending, slow]);
      messages.mockRestore();
      setEnvironmentData(gateKey, previousGate);
      await broker.close();
    }
  },
);
