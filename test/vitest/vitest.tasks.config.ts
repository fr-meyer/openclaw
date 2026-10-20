// Vitest tasks config wires the tasks test shard.
import { databaseWorkerCoreTestFiles } from "./vitest.database-worker-core-paths.mjs";
import { createScopedVitestConfig } from "./vitest.scoped-config.ts";

export function createTasksVitestConfig(env?: Record<string, string | undefined>) {
  return createScopedVitestConfig(["src/tasks/**/*.test.ts"], {
    dir: "src",
    env,
    exclude: databaseWorkerCoreTestFiles,
    name: "tasks",
    passWithNoTests: true,
  });
}

export default createTasksVitestConfig();
