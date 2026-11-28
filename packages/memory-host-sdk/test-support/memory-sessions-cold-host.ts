import assert from "node:assert/strict";
import type { OpenClawConfig } from "../../../src/config/types.js";
import {
  resolveRuntimeWorkerThreadExecArgv,
  resolveRuntimeWorkerUrl,
} from "../../../src/infra/runtime-worker-url.js";
import {
  resolveTestNodeExecPath,
  spawnNodeEvalSync,
} from "../../../src/test-utils/node-process.js";
import { cleanupSessionStateForTest } from "../../../src/test-utils/session-state-cleanup.js";

/** Cold maintenance needs a real main-thread host, not the unit-support thread pool. */
export async function prepareSessionColdStateInHost(
  config: OpenClawConfig,
  env: NodeJS.ProcessEnv,
): Promise<void> {
  const stateDir = env.OPENCLAW_STATE_DIR;
  assert.ok(stateDir, "Cold-state setup requires its isolated state directory");
  // Release the test thread's actual handles before the process owner admits writers.
  await cleanupSessionStateForTest({ stateDir });
  const resolveHostModule = (sourceWorkerName: string, distWorkerPath: string) =>
    resolveRuntimeWorkerUrl({
      currentModuleUrl: import.meta.url,
      sourceWorkerName,
      distWorkerPath,
    });
  const maintenance = resolveHostModule(
    "../../../src/config/sessions/session-cold-storage",
    "config/sessions/session-cold-storage.js",
  );
  const agents = resolveHostModule(
    "../../../src/state/openclaw-agent-db",
    "state/openclaw-agent-db.js",
  );
  const state = resolveHostModule(
    "../../../src/state/openclaw-state-db",
    "state/openclaw-state-db.js",
  );
  const runtimeArgs = resolveRuntimeWorkerThreadExecArgv(maintenance, resolveTestNodeExecPath());
  const preload = runtimeArgs[1];
  const child = spawnNodeEvalSync(
    `
      import assert from "node:assert/strict";
      import { isMainThread } from "node:worker_threads";
      assert.equal(isMainThread, true, "Cold maintenance requires a genuine host owner");
      const { runSessionColdStorageMaintenance } = await import(${JSON.stringify(maintenance.href)});
      const { closeOpenClawAgentDatabasesAsync } = await import(${JSON.stringify(agents.href)});
      const { closeOpenClawStateDatabaseAsync } = await import(${JSON.stringify(state.href)});
      const errors = [];
      try {
        await runSessionColdStorageMaintenance({ config: ${JSON.stringify(config)} });
      } catch (error) {
        errors.push(error);
      }
      // Native agent actors settle before the state authority that lent their admission.
      for (const close of [closeOpenClawAgentDatabasesAsync, closeOpenClawStateDatabaseAsync]) {
        try { await close(); } catch (error) { errors.push(error); }
      }
      if (errors.length) {
        throw new AggregateError(errors, "Cold-state host setup or owned cleanup failed");
      }
    `,
    {
      env: { ...process.env, ...env },
      imports: preload ? [preload] : [],
      timeout: 30_000,
      maxBuffer: 1024 * 1024,
    },
  );
  assert.ifError(child.error);
  assert.equal(child.signal, null, child.stderr);
  assert.equal(child.status, 0, child.stderr);
}
