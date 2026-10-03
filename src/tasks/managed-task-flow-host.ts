import type {
  BoundManagedTaskFlows,
  BoundManagedTaskRuns,
  ManagedTaskFlowCreate,
  ManagedTaskFlowExecute,
  ManagedTaskFlowMutation,
  ManagedTaskFlowResume,
  ManagedTaskFlowWorkerOperations,
} from "./managed-task-flow-contract.js";
import { isManagedTaskFlowObservation } from "./managed-task-flow-contract.js";

/** The current runtime owner grants this bound capability; a session string cannot grant it. */
export type ManagedTaskFlowSessionAuthority = {
  ownerKey: string;
  controllerId: string;
  assertCurrent(): void;
  assertOwnerSelection(ownerSessionKeys: readonly string[]): void;
  readonly legacyOwnerObservation: boolean;
};

/**
 * Compose with the canonical shared-state worker and read-only worker owners.
 * execute must retain native work through settlement and use transaction/commit
 * admission for writes. This module never opens SQLite or launches a task.
 */
export function createManagedTaskFlowHost(options: {
  assertCurrent(): void;
  bindSessionAuthority(input: {
    sessionKey: string;
    agentId?: string;
  }): ManagedTaskFlowSessionAuthority;
  execute: ManagedTaskFlowExecute;
  cancel: (authority: ManagedTaskFlowSessionAuthority, taskId: string) => Promise<unknown>;
}) {
  let closed = false;
  let closing: Promise<void> | undefined;
  const pending = new Set<Promise<unknown>>();
  const assertOwnerCurrent = options.assertCurrent.bind(options);
  const bindSessionAuthority = options.bindSessionAuthority.bind(options);
  const dispatch = options.execute.bind(options);
  const close = (): Promise<void> => {
    // Revoke retained bindings synchronously, then join accepted native work.
    closed = true;
    closing ??= Promise.allSettled(pending).then(() => undefined);
    return closing;
  };

  const assertActive = () => {
    if (closed) {
      throw new Error("Managed task-flow host is closed");
    }
    assertOwnerCurrent();
  };
  const bind = (input: { sessionKey: string; agentId?: string }) => {
    assertActive();
    const sessionKey = input.sessionKey.trim();
    if (!sessionKey) {
      throw new Error("Managed task-flow binding requires a session key");
    }
    const authority = bindSessionAuthority({ ...input, sessionKey });
    const ownerKey = authority.ownerKey.trim();
    if (!ownerKey) {
      throw new Error("Managed task-flow binding requires an admitted owner key");
    }
    const controllerId = authority.controllerId.trim();
    if (!controllerId) {
      throw new Error("Managed task-flow binding requires an admitted controller ID");
    }
    const assertSessionCurrent = authority.assertCurrent.bind(authority);
    const assertCurrent = () => {
      assertActive();
      assertSessionCurrent();
    };
    assertCurrent();

    const execute = async <Key extends keyof ManagedTaskFlowWorkerOperations>(command: {
      type: Key;
      input: ManagedTaskFlowWorkerOperations[Key]["input"];
    }): Promise<ManagedTaskFlowWorkerOperations[Key]["output"]> => {
      assertCurrent();
      // Capture payload bytes before an asynchronous transport can yield.
      const captured = structuredClone(command);
      const operation = Promise.resolve().then(async () => {
        assertCurrent();
        const result = await dispatch(captured, { assertCurrent });
        if (isManagedTaskFlowObservation(captured.type, result)) {
          assertCurrent();
        }
        return result;
      });
      pending.add(operation);
      void operation.then(
        () => pending.delete(operation),
        () => pending.delete(operation),
      );
      return operation;
    };
    return { sessionKey, ownerKey, controllerId, execute, assertCurrent, authority };
  };

  const managedFlows = {
    bindSession(input: { sessionKey: string }): BoundManagedTaskFlows {
      const { sessionKey, ownerKey, controllerId, execute, assertCurrent, authority } = bind(input);
      const mutate = (
        mutation: "finish" | "fail" | "setWaiting" | "resume",
        fields: ManagedTaskFlowResume,
      ) =>
        execute({
          type: "tasks.managedFlows.mutate",
          input: { ...fields, ownerKey, controllerId, mutation },
        });
      return {
        sessionKey,
        assertCurrent,
        close,
        capacitySnapshot: (fields) => {
          const ownerSessionKeys = [...fields.ownerSessionKeys];
          assertCurrent();
          authority.assertOwnerSelection(ownerSessionKeys);
          return execute({
            type: "tasks.managedFlows.capacitySnapshot",
            input: { ownerKey, controllerId, ownerSessionKeys },
          });
        },
        reserve: (fields) => {
          const captured = structuredClone(fields);
          assertCurrent();
          authority.assertOwnerSelection(captured.capacitySnapshot.ownerSessionKeys);
          return execute({
            type: "tasks.managedFlows.reserve",
            input: { ...captured, ownerKey, controllerId, mutation: "resume" },
          });
        },
        get: (flowId) =>
          execute({ type: "tasks.managedFlows.get", input: { ownerKey, controllerId, flowId } }),
        list: () => execute({ type: "tasks.managedFlows.list", input: { ownerKey, controllerId } }),
        createManaged: async (fields: ManagedTaskFlowCreate) => {
          if (fields.controllerId !== controllerId) {
            throw new Error("Managed task-flow controller differs from its admitted owner");
          }
          return execute({
            type: "tasks.managedFlows.create",
            input: { ...fields, ownerKey, controllerId },
          });
        },
        finish: (fields: ManagedTaskFlowMutation) => mutate("finish", fields),
        fail: (fields: ManagedTaskFlowMutation) => mutate("fail", fields),
        setWaiting: (fields: ManagedTaskFlowMutation) => mutate("setWaiting", fields),
        resume: (fields: ManagedTaskFlowResume) => mutate("resume", fields),
      };
    },
  };
  const runs = {
    bindSession(input: { sessionKey: string; agentId?: string }): BoundManagedTaskRuns {
      const { sessionKey, ownerKey, controllerId, execute, assertCurrent, authority } = bind(input);
      return {
        sessionKey,
        close,
        get: (taskId) =>
          execute({
            type: "tasks.runs.get",
            input: {
              ownerKey,
              controllerId,
              taskId,
              legacyOwnerObservation: authority.legacyOwnerObservation,
            },
          }),
        list: () =>
          execute({
            type: "tasks.runs.list",
            input: {
              ownerKey,
              controllerId,
              legacyOwnerObservation: authority.legacyOwnerObservation,
            },
          }),
        cancel: async ({ taskId }) => {
          assertCurrent();
          const operation = Promise.resolve().then(() => {
            assertCurrent();
            return options.cancel(authority, taskId);
          });
          pending.add(operation);
          void operation.then(
            () => pending.delete(operation),
            () => pending.delete(operation),
          );
          return operation;
        },
      };
    },
  };
  return {
    managedFlows,
    runs,
    close,
  };
}
