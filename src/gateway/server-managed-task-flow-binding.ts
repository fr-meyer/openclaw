import { AsyncLocalStorage } from "node:async_hooks";
import { isRecord } from "@openclaw/normalization-core/record-coerce";
import {
  captureGatewayToolCallerAssertion,
  getGatewayToolCallerIdentity,
} from "../agents/tools/gateway-caller-context.js";
import type { SqliteWorkerCommand } from "../infra/sqlite-worker-contract.js";
import { createSqliteWorkerWriteAdmission } from "../infra/sqlite-worker-store.js";
import { parseAgentSessionKey, isIncognitoSessionKey } from "../routing/session-key.js";
import { runOpenClawStateWorkerOperation } from "../state/openclaw-state-worker-store.js";
import {
  isManagedTaskFlowReadCommand,
  type ManagedTaskFlowReadOperations,
  type ManagedTaskFlowWriteOperations,
  type ManagedTaskFlowWorkerOperations,
} from "../tasks/managed-task-flow-contract.js";
import { createManagedTaskFlowHost } from "../tasks/managed-task-flow-host.js";
import { resolveGatewayManagedTaskFlowBindingScope } from "./server-managed-task-flow-binding-scope.js";
import type { GatewayManagedTaskFlowBindingContext } from "./server-managed-task-flow-binding.types.js";
import {
  configuredManagedFlowOwners,
  isClaimedManagedFlowNativeRun,
} from "./server-managed-task-flow-policy.js";
import { executeGatewayManagedTaskFlowRead } from "./server-managed-task-flow-read.js";
import { prepareGatewaySessionAccessAuthority } from "./session-access-authority.js";

export function bindGatewayManagedTaskFlowHost(
  input: { sessionKey: string; agentId?: string },
  kind: "flow" | "run",
  bindingContext: GatewayManagedTaskFlowBindingContext,
) {
  const {
    resolveGatewayContext,
    runWithReadOnlyWorkers,
    stateContext,
    closers,
    assertRuntimeCurrent,
    nativeLaunchClaims,
  } = bindingContext;
  assertRuntimeCurrent();
  const {
    scope,
    context,
    gatewayResolver,
    client,
    pluginId,
    owner,
    instance,
    sessionKey,
    agentId,
    controllerId,
    ownerConfig,
    configuredOwners,
    statusAgentIds,
  } = resolveGatewayManagedTaskFlowBindingScope(input, kind, resolveGatewayContext);
  const ambient = getGatewayToolCallerIdentity();
  const assertAmbient = ambient && captureGatewayToolCallerAssertion();
  const clientTool = client?.internal?.agentToolCaller;
  const clientRun = client?.internal?.agentRuntimeIdentity;
  const clientActor = clientTool ?? clientRun;
  if (
    (ambient && !assertAmbient) ||
    (ambient &&
      clientActor &&
      (ambient.sessionKey !== clientActor.sessionKey || ambient.agentId !== clientActor.agentId)) ||
    (clientTool &&
      clientRun &&
      (clientTool.sessionKey !== clientRun.sessionKey ||
        clientTool.agentId !== clientRun.agentId)) ||
    (clientTool && !clientTool.assertCurrent) ||
    (clientRun && context.validateAgentRuntimeApprovalAuthority?.(clientRun) !== true)
  ) {
    throw new Error("Managed task-flow caller has no current actor proof");
  }
  const actor = ambient ?? clientActor;
  if (kind === "run" && !actor) {
    // Detached publisher recovery needs only its configured owner ledger.
    // Worker/main probes may fail closed; the owner ledger can still locate
    // the exact native run through its trusted requester backlink.
    if (
      !configuredManagedFlowOwners(ownerConfig, pluginId, sessionKey, false).includes(sessionKey)
    ) {
      throw new Error("Detached controller run binding lacks a configured owner");
    }
  }
  const actorRunId = (
    ambient?.operationalRunInstance?.runId ?? clientRun?.operationalRunInstance.runId
  )?.trim();
  const foreignRunObserver = Boolean(
    kind === "run" &&
    actor &&
    actor.sessionKey !== sessionKey &&
    configuredManagedFlowOwners(ownerConfig, pluginId, actor.sessionKey, false).includes(
      actor.sessionKey,
    ),
  );
  const statusOnly = Boolean(
    !foreignRunObserver &&
    actor &&
    actor.sessionKey !== sessionKey &&
    statusAgentIds.includes(actor.agentId),
  );
  const workerCandidate = Boolean(
    !foreignRunObserver && actor && actor.sessionKey !== sessionKey && actorRunId,
  );
  if (
    actor &&
    actor.sessionKey !== sessionKey &&
    !statusOnly &&
    !workerCandidate &&
    !foreignRunObserver
  ) {
    throw new Error("Managed task-flow caller has no controller owner or native observer grant");
  }
  const consumer = instance.retainConsumer(undefined, scope.pluginRegistry);
  const inCapturedFrame = AsyncLocalStorage.snapshot();
  const runOwned = <T>(operation: () => T): T =>
    inCapturedFrame(() => runWithReadOnlyWorkers(() => consumer.run(operation)));
  const assertIngressCurrent = () => {
    assertRuntimeCurrent();
    scope.signal?.throwIfAborted();
    client?.connectionSignal?.throwIfAborted();
    assertAmbient?.();
    clientTool?.assertCurrent?.();
    if (
      (ambient &&
        (getGatewayToolCallerIdentity() !== ambient ||
          (ambient.gatewayContextResolver && ambient.gatewayContextResolver() !== context))) ||
      (clientActor && client?.internal?.agentToolCaller !== clientTool) ||
      (clientRun &&
        (client?.internal?.agentRuntimeIdentity !== clientRun ||
          context.validateAgentRuntimeApprovalAuthority?.(clientRun) !== true)) ||
      owner.revoked ||
      instance.lifecycle.signal.aborted ||
      client?.invalidated ||
      scope.hasCurrentClientAuthority?.() === false ||
      gatewayResolver() !== context ||
      context.getRuntimeConfig() !== ownerConfig
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
  type Access = Awaited<ReturnType<typeof prepareGatewaySessionAccessAuthority>>["authority"];
  let access: ReturnType<Access["retain"]> | undefined;
  let admittedAuthority: Access | undefined;
  let preparation: Promise<void> | undefined;
  let closed = false;
  let workerGrant:
    | { flowId: string; runId: string; generation: number; taskId: string; revision: number }
    | undefined;
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
      if (!client || statusOnly || workerCandidate || foreignRunObserver) {
        return;
      }
      const prepared = await prepareGatewaySessionAccessAuthority({
        policy: { mode: "write" },
        requestParams: { sessionKey, ...(agentId ? { agentId } : {}) },
        client,
        context,
        ownSessionOnly: true,
        hasCurrentClientAuthority: scope.hasCurrentClientAuthority,
        assertInvocationCurrent: assertBindingIngressCurrent,
      });
      const admitted = prepared.authority;
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
  }): Promise<ManagedTaskFlowReadOperations[Key]["output"]> {
    return executeGatewayManagedTaskFlowRead<Key>(
      { runWithReadOnlyWorkers, stateContext, assertCurrent, getSignal: () => access?.signal },
      command,
    );
  }

  const proveCurrentWorker = async (flow: unknown): Promise<boolean> => {
    if (!workerCandidate || !actor || !actorRunId || !isRecord(flow)) {
      return false;
    }
    const state = flow.stateJson;
    const activeWorker = isRecord(state) ? state.activeWorker : undefined;
    if (
      !isRecord(activeWorker) ||
      activeWorker.sessionKey !== actor.sessionKey ||
      activeWorker.runId !== actorRunId ||
      typeof flow.flowId !== "string" ||
      typeof flow.revision !== "number"
    ) {
      return false;
    }
    const native = await runOwned(() =>
      executeRead({
        type: "tasks.runs.list",
        input: {
          ownerKey: actor.sessionKey,
          controllerId,
          legacyOwnerObservation: false,
        },
      }),
    );
    const matches = native.filter(
      (run) =>
        run.observationSource === "native-subagent" &&
        run.label === `plugin:${pluginId}` &&
        run.requesterSessionKey === flow.ownerKey &&
        run.childSessionKey === actor.sessionKey &&
        run.runId === actorRunId &&
        run.status === "running" &&
        Number.isSafeInteger(run.generation) &&
        (run.generation ?? 0) > 0 &&
        activeWorker.nativeGeneration === run.generation &&
        (activeWorker.taskId == null || activeWorker.taskId === run.id),
    );
    if (matches.length !== 1) {
      return false;
    }
    workerGrant = {
      flowId: flow.flowId,
      runId: actorRunId,
      generation: matches[0]!.generation!,
      taskId: matches[0]!.id,
      revision: flow.revision,
    };
    return true;
  };
  function execute<Key extends keyof ManagedTaskFlowWorkerOperations>(
    command: { type: Key; input: ManagedTaskFlowWorkerOperations[Key]["input"] },
    authority: { assertCurrent(): void },
  ): Promise<ManagedTaskFlowWorkerOperations[Key]["output"]>;
  async function execute(
    command: SqliteWorkerCommand<ManagedTaskFlowWorkerOperations>,
    authority: { assertCurrent(): void },
  ): Promise<ManagedTaskFlowWorkerOperations[keyof ManagedTaskFlowWorkerOperations]["output"]> {
    if (foreignRunObserver) {
      if (command.type !== "tasks.runs.get" && command.type !== "tasks.runs.list") {
        throw new Error("Configured owner may only inspect its claimed native workers");
      }
      await prepare();
      const ownerFlows = await runOwned(() =>
        executeRead({
          type: "tasks.managedFlows.list",
          input: { ownerKey: actor!.sessionKey, controllerId },
        }),
      );
      let selected;
      if (command.type === "tasks.runs.get") {
        const observed = await runOwned(() =>
          executeRead({
            type: "tasks.runs.get",
            input: { ...command.input, legacyOwnerObservation: false },
          }),
        );
        selected =
          observed &&
          isClaimedManagedFlowNativeRun(observed, ownerFlows, actor!.sessionKey, controllerId)
            ? observed
            : undefined;
      } else {
        const observed = await runOwned(() =>
          executeRead({
            type: "tasks.runs.list",
            input: { ...command.input, legacyOwnerObservation: false },
          }),
        );
        selected = observed.filter((run) =>
          isClaimedManagedFlowNativeRun(run, ownerFlows, actor!.sessionKey, controllerId),
        );
      }
      assertCurrent();
      authority.assertCurrent();
      return selected;
    }
    if (workerCandidate && command.type === "tasks.managedFlows.get") {
      await prepare();
      const flow = await runOwned(() => executeRead(command));
      assertCurrent();
      authority.assertCurrent();
      if (!flow) {
        return undefined;
      }
      if (
        workerGrant?.flowId === flow.flowId &&
        workerGrant.runId === actorRunId &&
        workerGrant.revision === flow.revision
      ) {
        return flow;
      }
      if (await proveCurrentWorker(flow)) {
        return flow;
      }
      return statusOnly ? flow : undefined;
    }
    if (workerCandidate && command.type === "tasks.managedFlows.mutate") {
      if (
        !workerGrant ||
        workerGrant.flowId !== command.input.flowId ||
        workerGrant.runId !== actorRunId ||
        workerGrant.revision !== command.input.expectedRevision
      ) {
        throw new Error("Worker transition lacks its exact current native flow grant");
      }
      const native = await runOwned(() =>
        executeRead({
          type: "tasks.runs.get",
          input: {
            ownerKey: actor!.sessionKey,
            controllerId,
            taskId: actorRunId!,
            legacyOwnerObservation: false,
          },
        }),
      );
      if (
        native?.observationSource !== "native-subagent" ||
        native.childSessionKey !== actor?.sessionKey ||
        native.runId !== actorRunId ||
        native.generation !== workerGrant.generation ||
        native.status !== "running"
      ) {
        throw new Error("Worker's exact native generation is no longer active");
      }
    } else if (workerCandidate && !statusOnly && command.type !== "tasks.managedFlows.get") {
      throw new Error("Worker may only access its exact current managed flow");
    }
    if (
      statusOnly &&
      command.type !== "tasks.managedFlows.get" &&
      command.type !== "tasks.managedFlows.list" &&
      !(workerGrant && command.type === "tasks.managedFlows.mutate")
    ) {
      throw new Error("Configured status agent may only inspect managed flows");
    }
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
    const dispatchWrite = <Key extends keyof ManagedTaskFlowWriteOperations>(writeCommand: {
      type: Key;
      input: ManagedTaskFlowWriteOperations[Key]["input"];
    }): Promise<ManagedTaskFlowWriteOperations[Key]["output"]> =>
      runOwned(() =>
        runOpenClawStateWorkerOperation(
          stateContext,
          async (worker) => {
            check();
            // Native commit/reply settlement stays inside this retained operation.
            // The host checks only observations after this promise returns.
            return worker.execute(writeCommand);
          },
          {
            assertCurrent: check,
            createAdmission: createSqliteWorkerWriteAdmission(check, [
              stateContext.admission.databasePath,
            ]),
          },
        ),
      );
    if (command.type === "tasks.managedFlows.mutate") {
      // Overwrite even a JavaScript caller's undeclared extra field. Only this
      // captured Gateway/native actor can attach a worker transaction grant.
      const result = await dispatchWrite({
        type: command.type,
        input: {
          ...command.input,
          nativeWorkerGrant:
            workerCandidate && workerGrant
              ? {
                  childSessionKey: actor!.sessionKey,
                  runId: workerGrant.runId,
                  generation: workerGrant.generation,
                  taskId: workerGrant.taskId,
                }
              : undefined,
        },
      });
      if (workerGrant && result.applied) {
        workerGrant.revision = result.flow.revision;
      }
      return result;
    }
    if (
      command.type === "tasks.managedFlows.reserve" ||
      command.type === "tasks.managedFlows.create"
    ) {
      return dispatchWrite(command);
    }
    throw new Error("Managed task-flow write command is unavailable");
  }
  const host = createManagedTaskFlowHost({
    assertCurrent,
    captureNativeLaunch: async (authority, launch) => {
      if (
        kind !== "flow" ||
        statusOnly ||
        workerCandidate ||
        foreignRunObserver ||
        (client && (!actor || actor.sessionKey !== sessionKey)) ||
        !launch.flowId ||
        !Number.isSafeInteger(launch.expectedRevision) ||
        launch.expectedRevision < 0 ||
        !parseAgentSessionKey(launch.childSessionKey) ||
        isIncognitoSessionKey(launch.childSessionKey)
      ) {
        throw new Error("Native launch requires the current managed-flow owner actor");
      }
      await prepare();
      const flow = await runOwned(() =>
        executeRead({
          type: "tasks.managedFlows.get",
          input: { ownerKey: sessionKey, controllerId, flowId: launch.flowId },
        }),
      );
      assertCurrent();
      authority.assertCurrent();
      const state = flow?.stateJson;
      const worker =
        isRecord(state) && isRecord(state.activeWorker) ? state.activeWorker : undefined;
      const outcome =
        isRecord(state) && isRecord(state.launchOutcome) ? state.launchOutcome : undefined;
      if (
        !flow ||
        flow.revision !== launch.expectedRevision ||
        flow.status !== "running" ||
        worker?.sessionKey !== launch.childSessionKey ||
        worker.runId != null ||
        worker.taskId != null ||
        outcome?.status !== "unknown" ||
        outcome.sessionKey !== launch.childSessionKey
      ) {
        throw new Error("Native launch lost its exact prelaunch flow claim");
      }
      const capability = Object.freeze({});
      nativeLaunchClaims.set(capability, {
        pluginId,
        ownerKey: sessionKey,
        controllerId,
        flowId: flow.flowId,
        revision: flow.revision,
        childSessionKey: launch.childSessionKey,
        assertCurrent,
        used: false,
      });
      return capability;
    },
    bindSessionAuthority: () => ({
      ownerKey: sessionKey,
      controllerId,
      assertCurrent,
      legacyOwnerObservation: Boolean(client),
      assertOwnerSelection(ownerSessionKeys) {
        assertCurrent();
        if (
          ownerSessionKeys.length !== configuredOwners.length ||
          new Set(ownerSessionKeys).size !== configuredOwners.length ||
          ownerSessionKeys.some((key) => !configuredOwners.includes(key))
        ) {
          throw new Error("Capacity selection differs from admitted controller owners");
        }
      },
    }),
    execute,
    cancel: async (authority, { taskId, expectedFlow }) => {
      if (statusOnly || workerCandidate) {
        throw new Error("Configured status agent cannot cancel a native run");
      }
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
        const claimOwnerKey = foreignRunObserver ? actor!.sessionKey : sessionKey;
        const claimedFlows = (
          await executeRead({
            type: "tasks.managedFlows.list",
            input: { ownerKey: claimOwnerKey, controllerId },
          })
        ).filter((flow) =>
          isClaimedManagedFlowNativeRun(task, [flow], claimOwnerKey, controllerId),
        );
        if (
          claimedFlows.length !== 1 ||
          !expectedFlow ||
          typeof expectedFlow.flowId !== "string" ||
          !expectedFlow.flowId.trim() ||
          !Number.isSafeInteger(expectedFlow.revision) ||
          expectedFlow.revision < 0 ||
          (task.status !== "running" && task.status !== "queued") ||
          !Number.isSafeInteger(claimedFlows[0]?.revision)
        ) {
          throw new Error("Controller owner no longer claims the exact live native worker");
        }
        const claimedFlow = claimedFlows[0]!;
        if (
          claimedFlow.flowId !== expectedFlow.flowId ||
          claimedFlow.revision !== expectedFlow.revision
        ) {
          throw new Error("Controller flow changed since native cancellation was requested");
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
          {
            assertCurrent: checkCancellationCurrent,
            managedFlowKillClaim: {
              ownerKey: claimOwnerKey,
              controllerId,
              flowId: claimedFlow.flowId,
              revision: claimedFlow.revision,
              childSessionKey: task.childSessionKey,
              runId: task.runId,
              taskId: task.id,
              generation: task.generation,
            },
          },
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
}
