import { resolveRuntimeWorkerUrl } from "openclaw/plugin-sdk/process-runtime";
import {
  openOpenClawAgentSqliteWorkerStore,
  withOpenClawAgentDatabaseRuntime,
  runOpenClawAgentWriteAdmission,
} from "openclaw/plugin-sdk/sqlite-runtime";
import { captureMemoryAgentDatabaseOptions } from "../memory-agent-database.js";
import type {
  BoundedAllocation,
  BoundedWorkerOperations,
} from "./bounded-admission-worker-task.js";
import type { BoundedMemoryPolicy, BoundedMemoryEscrow } from "./bounded-admission.js";
import { memoryCpuProcessEntrypoints } from "./manager-cpu-entrypoints.js";

type Receipt = {
  remaining?: { stopped: number; phase: string; expires: number };
  debits?: unknown[];
};
export async function openBoundedMemoryWorkerOwner(
  policy: BoundedMemoryPolicy,
  allocation: Record<"forward" | "recovery", BoundedAllocation>,
  assertInvocationCurrent: () => void,
) {
  assertInvocationCurrent();
  const options = captureMemoryAgentDatabaseOptions(policy.agent);
  const moduleUrl = resolveRuntimeWorkerUrl(memoryCpuProcessEntrypoints.boundedAdmission);
  const worker = await withOpenClawAgentDatabaseRuntime(
    options,
    ({ db }) =>
      openOpenClawAgentSqliteWorkerStore<BoundedWorkerOperations>(options, db, {
        moduleUrl,
        input: { agentId: policy.agent },
      }),
    assertInvocationCurrent,
  );
  let closed = false;
  let stopped = false;
  let receipt: Receipt = {};
  const execute = async <K extends keyof BoundedWorkerOperations>(
    type: K,
    input: BoundedWorkerOperations[K]["input"],
  ) => {
    if (closed) {
      throw new Error("Bounded owner closed");
    }
    assertInvocationCurrent();
    const output = await runOpenClawAgentWriteAdmission(
      options,
      async (_identity, assertAdmission) =>
        worker.run(
          (scope) => scope.execute({ type, input } as Parameters<typeof scope.execute>[0]),
          () => {
            assertInvocationCurrent();
            assertAdmission();
          },
        ),
      true,
    );
    if (type !== "required") {
      receipt = output as Receipt;
    }
    return output;
  };
  try {
    await execute("initialize", { policy, allocation });
  } catch (error) {
    await worker.close();
    throw error;
  }
  const escrow: BoundedMemoryEscrow = {
    assertActive(operation, phase, now) {
      assertInvocationCurrent();
      if (
        closed ||
        stopped ||
        operation !== policy.operation ||
        !receipt.remaining ||
        receipt.remaining.stopped !== 0 ||
        receipt.remaining.phase !== phase ||
        now >= receipt.remaining.expires
      ) {
        throw new Error("Inactive native escrow");
      }
    },
    async debit(operation, phase, root, need) {
      await execute("debit", { operation, phase, root, need });
    },
    async stop(operation) {
      stopped = true;
      await execute("stop", { operation });
    },
    async recovery() {
      await execute("recovery", { operation: policy.operation });
      stopped = false;
    },
    async resumeOrdinary(operation) {
      stopped = true;
      await execute("resume", { operation });
    },
    receipt() {
      return structuredClone(receipt);
    },
  };
  return {
    escrow,
    async close() {
      if (closed) {
        return;
      }
      stopped = true;
      closed = true;
      await worker.close();
    },
  };
}

export async function discoverBoundedMemoryRequirement(agentId: string): Promise<boolean> {
  const options = captureMemoryAgentDatabaseOptions(agentId);
  const moduleUrl = resolveRuntimeWorkerUrl(memoryCpuProcessEntrypoints.boundedAdmission);
  return withOpenClawAgentDatabaseRuntime(options, async ({ db }) => {
    const worker = await openOpenClawAgentSqliteWorkerStore<BoundedWorkerOperations>(options, db, {
      moduleUrl,
      input: { agentId },
    });
    try {
      return (await worker.execute(
        { type: "required", input: { agentId } },
        () => undefined,
      )) as boolean;
    } finally {
      await worker.close();
    }
  });
}
