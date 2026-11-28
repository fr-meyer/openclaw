import type { SqliteWorkerCommand } from "../infra/sqlite-worker-contract.js";
import { executeExistingOpenClawStateRead } from "../state/openclaw-state-db-readonly.js";
import type { ManagedTaskFlowReadOperations } from "../tasks/managed-task-flow-contract.js";
import type { GatewayManagedTaskFlowBindingContext } from "./server-managed-task-flow-binding.types.js";

type GatewayManagedTaskFlowReadContext = Pick<
  GatewayManagedTaskFlowBindingContext,
  "runWithReadOnlyWorkers" | "stateContext"
> & {
  assertCurrent: () => void;
  getSignal: () => AbortSignal | undefined;
};

export function executeGatewayManagedTaskFlowRead<Key extends keyof ManagedTaskFlowReadOperations>(
  context: GatewayManagedTaskFlowReadContext,
  command: {
    type: Key;
    input: ManagedTaskFlowReadOperations[Key]["input"];
  },
): Promise<ManagedTaskFlowReadOperations[Key]["output"]>;
export async function executeGatewayManagedTaskFlowRead(
  context: GatewayManagedTaskFlowReadContext,
  command: SqliteWorkerCommand<ManagedTaskFlowReadOperations>,
): Promise<ManagedTaskFlowReadOperations[keyof ManagedTaskFlowReadOperations]["output"]> {
  const { runWithReadOnlyWorkers, stateContext, assertCurrent, getSignal } = context;
  const result = await runWithReadOnlyWorkers(() =>
    executeExistingOpenClawStateRead(
      { env: stateContext.environment, path: stateContext.admission.databasePath },
      command,
      { context: stateContext, current: true, signal: getSignal() },
    ),
  );
  assertCurrent();
  if (!result?.ok || result.type !== command.type || !("value" in result)) {
    throw new Error("Managed task-flow observation database became unavailable");
  }
  switch (result.type) {
    case "tasks.managedFlows.capacitySnapshot":
    case "tasks.managedFlows.get":
    case "tasks.managedFlows.list":
    case "tasks.runs.get":
    case "tasks.runs.list":
      return result.value;
    default:
      throw new Error("Managed task-flow reader returned an unrelated observation");
  }
}
