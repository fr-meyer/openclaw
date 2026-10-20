import { createSqliteWorkerWriteAdmission } from "../infra/sqlite-worker-store.js";
import type { OpenClawStateWorkerContext } from "../state/openclaw-state-worker-context.types.js";
import type { OpenClawStateWorkerOperations } from "../state/openclaw-state-worker-contract.js";
import { runOpenClawStateWorkerOperation } from "../state/openclaw-state-worker-store.js";
import type { ManagedTaskFlowWriteOperations } from "./managed-task-flow-contract.js";

type FixtureWriteOperations = ManagedTaskFlowWriteOperations &
  Pick<OpenClawStateWorkerOperations, "subagents.persistChanges">;

/** Fixture seeding retains the test database's live authority through native commit. */
export function executeManagedTaskFlowFixtureWrite<Key extends keyof FixtureWriteOperations>(
  context: OpenClawStateWorkerContext,
  command: { type: Key; input: FixtureWriteOperations[Key]["input"] },
): Promise<FixtureWriteOperations[Key]["output"]> {
  const assertCurrent = () => context.admission.assertCurrent();
  return runOpenClawStateWorkerOperation(context, (scope) => scope.execute(command), {
    assertCurrent,
    createAdmission: createSqliteWorkerWriteAdmission(assertCurrent, [
      context.admission.databasePath,
    ]),
  });
}
