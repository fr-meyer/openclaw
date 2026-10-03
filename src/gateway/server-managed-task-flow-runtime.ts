import { AsyncLocalStorage } from "node:async_hooks";
import { captureSqliteReadOnlyWorkerScope } from "../infra/sqlite-readonly-worker-context.js";
import type { SqliteWorkerCommand } from "../infra/sqlite-worker-contract.js";
import { createSqliteWorkerWriteAdmission } from "../infra/sqlite-worker-store.js";
import { pluginInstanceInvocation } from "../plugins/plugin-instance-invocation.js";
import {
  getPluginInstanceOwner,
  hasCurrentPluginInstanceAuthority,
} from "../plugins/plugin-instance-scope.js";
import {
  getInProcessGatewayRequestContext,
  getPluginRuntimeGatewayRequestScope,
} from "../plugins/runtime/gateway-request-scope.js";
import type { PluginRuntime } from "../plugins/runtime/types.js";
import { parseAgentSessionKey, isIncognitoSessionKey } from "../routing/session-key.js";
import { executeExistingOpenClawStateRead } from "../state/openclaw-state-db-readonly.js";
import { captureOpenClawStateWorkerContext } from "../state/openclaw-state-worker-context.js";
import { runOpenClawStateWorkerOperation } from "../state/openclaw-state-worker-store.js";
import {
  isManagedTaskFlowReadCommand,
  type ManagedTaskFlowReadOperations,
  type ManagedTaskFlowWorkerOperations,
} from "../tasks/managed-task-flow-contract.js";
import { createManagedTaskFlowHost } from "../tasks/managed-task-flow-host.js";
import type { GatewayContextResolver } from "./server-methods/types.js";
import { prepareGatewaySessionAccessAuthority } from "./session-access-authority.js";

/**
 * Released controller compatibility uses the existing shared-state actor and normal
 * subagent owner. It supplies neither canonical Tasks writes nor private TaskFlow launches.
 */
export function createGatewayManagedTaskFlowRuntime(
  resolveGatewayContext?: GatewayContextResolver,
  runtimeLifetime?: AbortSignal,
): NonNullable<PluginRuntime["tasks"]> {
  const runWithReadOnlyWorkers = captureSqliteReadOnlyWorkerScope();
  const stateContext = captureOpenClawStateWorkerContext();
  const closers = new Set<() => Promise<void>>();
  const assertRuntimeCurrent = () => {
    runtimeLifetime?.throwIfAborted();
    stateContext.admission.assertCurrent();
  };
  const retire = () => {
    // Each closer synchronously revokes admission, then joins the native result.
    for (const close of closers) {
      void close().catch(() => undefined);
    }
  };
  runtimeLifetime?.addEventListener("abort", retire, { once: true });

  const bindHost = (input: { sessionKey: string; agentId?: string }) => {
    assertRuntimeCurrent();
    const currentScope = getPluginRuntimeGatewayRequestScope();
    const scope = currentScope && { ...currentScope };
    const context = getInProcessGatewayRequestContext(resolveGatewayContext);
    const gatewayResolver =
      resolveGatewayContext ?? scope?.resolveGatewayContext ?? context?.resolveGatewayContext;
    const client = scope?.client;
    const pluginId = scope?.pluginId?.trim();
    const invocation = pluginInstanceInvocation.getStore();
    const owner = invocation && getPluginInstanceOwner(invocation.instance);
    const instance = owner?.instance;
    if (
      !scope ||
      !owner ||
      !context ||
      !gatewayResolver ||
      gatewayResolver() !== context ||
      !pluginId ||
      !instance ||
      instance !== invocation?.instance ||
      instance.pluginId !== pluginId ||
      !hasCurrentPluginInstanceAuthority(pluginId)
    ) {
      throw new Error(
        "Controller state requires a current plugin instance and original Gateway binding",
      );
    }
    const sessionKey = input.sessionKey.trim();
    const parsed = parseAgentSessionKey(sessionKey);
    if (
      !parsed ||
      isIncognitoSessionKey(sessionKey) ||
      sessionKey !== input.sessionKey ||
      (input.agentId !== undefined && input.agentId !== parsed.agentId)
    ) {
      throw new Error("Managed task-flow binding requires a canonical session key");
    }
    const agentId = input.agentId;
    const controllerId = `${pluginId}/v1`;
    const consumer = instance.retainConsumer(undefined, scope.pluginRegistry);
    const inCapturedFrame = AsyncLocalStorage.snapshot();
    const runOwned = <T>(operation: () => T): T =>
      inCapturedFrame(() => runWithReadOnlyWorkers(() => consumer.run(operation)));
    const assertIngressCurrent = () => {
      assertRuntimeCurrent();
      scope.signal?.throwIfAborted();
      client?.connectionSignal?.throwIfAborted();
      if (
        owner.revoked ||
        instance.lifecycle.signal.aborted ||
        client?.invalidated ||
        scope.hasCurrentClientAuthority?.() === false ||
        gatewayResolver() !== context
      ) {
        throw new Error("Managed task-flow caller authority retired");
      }
      // This runs under the retained native consumer's exact token, never an ID lookup.
      runOwned(() => {
        if (!instance.hasActiveCall) {
          throw new Error("Managed task-flow plugin invocation retired");
        }
      });
    };
    type Access = Awaited<ReturnType<typeof prepareGatewaySessionAccessAuthority>>;
    let access: ReturnType<Access["retain"]> | undefined;
    let admittedAuthority: Access | undefined;
    let preparation: Promise<void> | undefined;
    let closed = false;
    const assertBindingIngressCurrent = () => {
      if (closed) {
        throw new Error("Managed task-flow session binding closed");
      }
      assertIngressCurrent();
    };
    const assertCurrent = () => {
      assertBindingIngressCurrent();
      admittedAuthority?.assertCurrent();
      access?.assertCurrent();
    };
    const prepare = () =>
      (preparation ??= runOwned(async () => {
        assertCurrent();
        await scope.revalidate?.();
        assertCurrent();
        // Background service/event callbacks own only their plugin's controller
        // state and labeled native run observations. They do not borrow a fake
        // operator or obtain session/approval authority from a configured key.
        if (!client) {
          return;
        }
        const admitted = await prepareGatewaySessionAccessAuthority({
          policy: { mode: "write" },
          requestParams: { sessionKey, ...(agentId ? { agentId } : {}) },
          client,
          context,
          ownSessionOnly: true,
          hasCurrentClientAuthority: scope.hasCurrentClientAuthority,
          assertInvocationCurrent: assertBindingIngressCurrent,
        });
        try {
          assertCurrent();
          admitted.assertCurrent();
          access = admitted.retain();
          admittedAuthority = admitted;
          access.signal.addEventListener("abort", onAbort, { once: true });
          assertCurrent();
        } catch (error) {
          admitted.release();
          throw error;
        }
      }));

    function executeRead<Key extends keyof ManagedTaskFlowReadOperations>(command: {
      type: Key;
      input: ManagedTaskFlowReadOperations[Key]["input"];
    }): Promise<ManagedTaskFlowReadOperations[Key]["output"]>;
    async function executeRead(
      command: SqliteWorkerCommand<ManagedTaskFlowReadOperations>,
    ): Promise<ManagedTaskFlowReadOperations[keyof ManagedTaskFlowReadOperations]["output"]> {
      const result = await runWithReadOnlyWorkers(() =>
        executeExistingOpenClawStateRead(
          { env: stateContext.environment, path: stateContext.admission.databasePath },
          command,
          { context: stateContext, current: true, signal: access?.signal },
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
    function execute<Key extends keyof ManagedTaskFlowWorkerOperations>(
      command: { type: Key; input: ManagedTaskFlowWorkerOperations[Key]["input"] },
      authority: { assertCurrent(): void },
    ): Promise<ManagedTaskFlowWorkerOperations[Key]["output"]>;
    async function execute(
      command: SqliteWorkerCommand<ManagedTaskFlowWorkerOperations>,
      authority: { assertCurrent(): void },
    ): Promise<ManagedTaskFlowWorkerOperations[keyof ManagedTaskFlowWorkerOperations]["output"]> {
      await prepare();
      const check = () => {
        assertCurrent();
        authority.assertCurrent();
      };
      check();
      if (isManagedTaskFlowReadCommand(command)) {
        const value = await runOwned(() => executeRead(command));
        check();
        return value;
      }
      return runOwned(() =>
        runOpenClawStateWorkerOperation(
          stateContext,
          async (worker) => {
            check();
            // Native commit/reply settlement stays inside this retained operation.
            // The host checks only observations after this promise returns.
            return worker.execute(command);
          },
          {
            assertCurrent: check,
            createAdmission: createSqliteWorkerWriteAdmission(check, [
              stateContext.admission.databasePath,
            ]),
          },
        ),
      );
    }
    const host = createManagedTaskFlowHost({
      assertCurrent,
      bindSessionAuthority: () => ({
        ownerKey: sessionKey,
        controllerId,
        assertCurrent,
        legacyOwnerObservation: Boolean(client),
        assertOwnerSelection(ownerSessionKeys) {
          assertCurrent();
          if (
            ownerSessionKeys.length === 0 ||
            ownerSessionKeys.length > 64 ||
            new Set(ownerSessionKeys).size !== ownerSessionKeys.length ||
            !ownerSessionKeys.includes(sessionKey) ||
            ownerSessionKeys.some(
              (key) =>
                key !== key.trim() || !parseAgentSessionKey(key) || isIncognitoSessionKey(key),
            ) ||
            (client && ownerSessionKeys.some((key) => key !== sessionKey))
          ) {
            throw new Error("Capacity selection differs from admitted controller owners");
          }
        },
      }),
      execute,
      cancel: async (authority, taskId) => {
        await prepare();
        assertCurrent();
        authority.assertCurrent();
        return runOwned(async () => {
          const task = await executeRead({
            type: "tasks.runs.get",
            input: {
              ownerKey: sessionKey,
              controllerId,
              taskId,
              legacyOwnerObservation: Boolean(client),
            },
          });
          assertCurrent();
          authority.assertCurrent();
          if (
            !task ||
            task.observationSource !== "native-subagent" ||
            !task.childSessionKey ||
            !task.runId ||
            task.id !== taskId ||
            task.generation === undefined ||
            !Number.isSafeInteger(task.generation) ||
            task.generation < 1 ||
            task.status === "unknown"
          ) {
            throw new Error(
              "Cancellation requires an exact current native publisher run observation",
            );
          }
          const cfg = context.getRuntimeConfig();
          const { killSubagentRunAdmin } =
            await import("../agents/subagents/registry/subagent-control-kill.js");
          const checkCancellationCurrent = () => {
            assertCurrent();
            authority.assertCurrent();
            if (context.getRuntimeConfig() !== cfg) {
              throw new Error("Native cancellation configuration changed");
            }
          };
          checkCancellationCurrent();
          // Caller-provided cfg cannot redirect the current Gateway owner.
          const result = await killSubagentRunAdmin(
            {
              cfg,
              sessionKey: task.childSessionKey,
              expectedRunId: task.runId,
              expectedTaskRunId: task.id,
              expectedGeneration: task.generation,
              expectedOwnerKey: task.requesterSessionKey,
            },
            { assertCurrent: checkCancellationCurrent },
          );
          if (
            !result.found ||
            result.runId !== task.runId ||
            result.sessionKey !== task.childSessionKey ||
            result.error
          ) {
            return {
              cancelled: false,
              error: result.found
                ? (result.error ?? "Native cancellation target changed")
                : "Native cancellation target unavailable",
            };
          }
          const terminalTask =
            result.targetState?.state === "terminal" ? result.targetState.task : undefined;
          // Descendant kills never establish terminality of this original target.
          return {
            cancelled: terminalTask?.status === "cancelled",
            ...(terminalTask ? { task: { ...terminalTask } } : {}),
          };
        });
      },
    });
    let closing: Promise<void> | undefined;
    const close = (): Promise<void> => {
      closed = true;
      return (closing ??= (async () => {
        let primaryFailure: unknown;
        let hasPrimaryFailure = false;
        try {
          await host.close();
          await preparation?.catch(() => undefined);
        } catch (error) {
          primaryFailure = error;
          hasPrimaryFailure = true;
        }
        const failures: unknown[] = [];
        const cleanup = (operation: () => void) => {
          try {
            operation();
          } catch (error) {
            failures.push(error);
          }
        };
        cleanup(() => access?.release());
        cleanup(() => admittedAuthority?.release());
        cleanup(() => consumer.release());
        cleanup(() => access?.signal.removeEventListener("abort", onAbort));
        cleanup(() => scope.signal?.removeEventListener("abort", onAbort));
        cleanup(() => client?.connectionSignal?.removeEventListener("abort", onAbort));
        cleanup(() => instance.lifecycle.signal.removeEventListener("abort", onAbort));
        closers.delete(close);
        if (hasPrimaryFailure) {
          if (failures.length > 0) {
            throw new AggregateError(
              [primaryFailure, ...failures],
              "Controller binding close and cleanup did not verify",
            );
          }
          throw primaryFailure;
        }
        if (failures.length > 0) {
          throw new AggregateError(failures, "Controller binding cleanup did not verify");
        }
      })());
    };
    const onAbort = () => void close().catch(() => undefined);
    closers.add(close);
    scope.signal?.addEventListener("abort", onAbort, { once: true });
    client?.connectionSignal?.addEventListener("abort", onAbort, { once: true });
    instance.lifecycle.signal.addEventListener("abort", onAbort, { once: true });
    try {
      assertCurrent();
    } catch (error) {
      void close().catch(() => undefined);
      throw error;
    }
    return { host, close };
  };

  return {
    authorityVersion: 1,
    availability: Object.freeze({
      managedFlows: true,
      taskRuns: true,
      controllerParity: true,
      canonicalTaskCreate: false,
      workerLaunch: false,
    }),
    managedFlows: {
      bindSession: (input) => {
        const { host, close } = bindHost(input);
        try {
          return { ...host.managedFlows.bindSession(input), close };
        } catch (error) {
          void close().catch(() => undefined);
          throw error;
        }
      },
    },
    runs: {
      bindSession: (input) => {
        const { host, close } = bindHost(input);
        try {
          return { ...host.runs.bindSession(input), close };
        } catch (error) {
          void close().catch(() => undefined);
          throw error;
        }
      },
    },
  };
}
