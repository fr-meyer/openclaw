import fs from "node:fs";
import path from "node:path";
import { Worker } from "node:worker_threads";
import { afterEach, assert, expect, it, vi } from "vitest";
import { useAutoCleanupTempDirTracker } from "../../test/helpers/temp-dir.js";
import { drainGlobalSingletonLifecycleState } from "../shared/global-singleton.js";
import { getOpenClawAgentDatabaseValidation } from "../state/openclaw-agent-db-validation-cache.js";
import {
  closeOpenClawAgentDatabasesAsync,
  closeOpenClawAgentDatabasesForTest,
  openOpenClawAgentDatabase,
} from "../state/openclaw-agent-db.js";
import type { AgentDatabaseRequestExecutionSource } from "../state/openclaw-agent-execution-admission-contract.js";
import { captureOpenClawAgentDatabaseExecution } from "../state/openclaw-agent-execution.js";
import {
  closeOpenClawStateDatabaseAsync,
  closeOpenClawStateDatabaseForTest,
} from "../state/openclaw-state-db.js";
import { initializeSqliteRuntimeCapabilities } from "./bun-sqlite-library.js";
import { createSqliteWorkerOperationAdmission } from "./sqlite-worker-operation-admission.js";
import type { SqliteWorkerOperationSettlement } from "./sqlite-worker-operation-settlement.js";
import { openSqliteWorkerStore, type SqliteWorkerStore } from "./sqlite-worker-store.js";
import type { FixtureOperations } from "./sqlite-worker-store.test-support.js";

vi.mock("node:os", async (importOriginal) => ({
  ...(await importOriginal<typeof import("node:os")>()),
  availableParallelism: () => 32,
}));

const dirs = useAutoCleanupTempDirTracker((cleanup) =>
  afterEach(async () => {
    await drainGlobalSingletonLifecycleState();
    await closeOpenClawAgentDatabasesAsync();
    await closeOpenClawStateDatabaseAsync();
    closeOpenClawAgentDatabasesForTest();
    closeOpenClawStateDatabaseForTest();
    cleanup();
  }),
);
const { explicitSqliteCloseReleasesNativeResources } = await initializeSqliteRuntimeCapabilities();

it.skipIf(!explicitSqliteCloseReleasesNativeResources).each(["existing", "creating"] as const)(
  "preserves a pooled agent and integrity receipt through a first-guard %s refusal, then recovers",
  async (route) => {
    const root = fs.realpathSync(dirs.make("agent-first-guard-refusal-"));
    const env = { OPENCLAW_STATE_DIR: root };
    const protectedDatabase = openOpenClawAgentDatabase({ agentId: "main", env });
    const protectedExecution = captureOpenClawAgentDatabaseExecution({ agentId: "main", env });
    if (route === "existing") {
      openOpenClawAgentDatabase({ agentId: "target", env });
    }
    const target = captureOpenClawAgentDatabaseExecution({ agentId: "target", env });
    const refusal = new Error("Synthetic caller revoked at the first agent factory guard");
    const settlements: Promise<SqliteWorkerOperationSettlement>[] = [];
    let openingRequests = 0;
    let allowed = false;
    const source = (reject: boolean): AgentDatabaseRequestExecutionSource => ({
      assertCurrent: () => (reject ? target : protectedExecution).assertCurrent(),
      createAdmission(binding) {
        return (operation) => {
          if (reject) {
            settlements.push(operation.settled);
          }
          return {
            nativeLocations: binding.nativeLocations,
            admission: createSqliteWorkerOperationAdmission((request, grant) => {
              if (reject && request.stage === "open") {
                openingRequests += 1;
                if (!allowed && openingRequests === 2) {
                  throw refusal;
                }
              }
              binding.authorize(request);
              if (!grant()) {
                throw new Error("Synthetic source lost its admission");
              }
            }, binding.attachment),
          };
        };
      },
    });
    const protectedSource = source(false);
    const targetSource = source(true);
    const siblings: SqliteWorkerStore<FixtureOperations>[] = [];
    const requests = vi.spyOn(Worker.prototype, "postMessage");
    try {
      expect(
        await protectedExecution.runExisting(protectedSource, async () => "protected ready"),
      ).toBe("protected ready");
      const protectedOpen = requests.mock.calls.findIndex(
        ([request]) => request.type === "open" && request.databasePath === protectedDatabase.path,
      );
      const protectedWorker = requests.mock.contexts[protectedOpen];
      assert(protectedWorker instanceof Worker);
      const validation = getOpenClawAgentDatabaseValidation(protectedDatabase);
      assert(validation);
      for (let index = 0; index < 3; index++) {
        siblings.push(
          await openSqliteWorkerStore<FixtureOperations>({
            moduleUrl: new URL("./sqlite-worker-store.test-support.ts", import.meta.url),
            databasePath: path.join(root, `sibling-${index}.sqlite`),
            input: undefined,
          }),
        );
      }
      const opening =
        route === "creating"
          ? target.prepare(targetSource)
          : target.runExisting(targetSource, async () => "must not enter");
      await expect(opening).rejects.toBe(refusal);
      expect(openingRequests).toBe(2);
      const targetOpen = requests.mock.calls.findIndex(
        ([request]) => request.type === "open" && request.databasePath === target.path,
      );
      expect(requests.mock.contexts[targetOpen]).toBe(protectedWorker);
      expect(await settlements[0]).toEqual({ kind: "not-entered", error: refusal });
      expect(getOpenClawAgentDatabaseValidation(protectedDatabase)).toBe(validation);
      expect(Atomics.load(new Int32Array(validation.valid), 0)).toBe(1);
      expect(
        await protectedExecution.runExisting(protectedSource, async () => "protected survives"),
      ).toBe("protected survives");
      if (route === "creating") {
        expect(fs.existsSync(target.path)).toBe(false);
      }
      for (const sibling of siblings) {
        expect(
          await sibling.execute({
            type: "append",
            input: { value: "survives first guard refusal" },
          }),
        ).toMatchObject({ writes: 1 });
      }
      allowed = true;
      await target.prepare(targetSource);
      expect(await target.runExisting(targetSource, async () => "fresh recovery")).toBe(
        "fresh recovery",
      );
    } finally {
      requests.mockRestore();
      await Promise.allSettled([
        target.release(),
        protectedExecution.release(),
        ...siblings.map((store) => store.close()),
      ]);
    }
  },
);
