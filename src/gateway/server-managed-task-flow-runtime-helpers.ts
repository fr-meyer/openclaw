import { isRecord } from "@openclaw/normalization-core/record-coerce";
import type { OpenClawConfig } from "../config/types.openclaw.js";
import { parseAgentSessionKey, isIncognitoSessionKey } from "../routing/session-key.js";
import type { ManagedTaskFlowReadOperations } from "../tasks/managed-task-flow-contract.js";
import type { createManagedTaskFlowHost } from "../tasks/managed-task-flow-host.js";
import type { ManagedFlowNativeLaunchClaim } from "../tasks/managed-task-flow-kill-claim.worker.js";
import type { GatewayContextResolver } from "./server-methods/types.js";

export type RetainedNativeLaunch = ManagedFlowNativeLaunchClaim & {
  pluginId: string;
  assertCurrent: () => void;
  used: boolean;
};
type ExecuteRead = <Key extends keyof ManagedTaskFlowReadOperations>(command: {
  type: Key;
  input: ManagedTaskFlowReadOperations[Key]["input"];
}) => Promise<ManagedTaskFlowReadOperations[Key]["output"]>;

/** The installed controller's owner roster comes from the live, validated Gateway config. */
export function configuredManagedFlowOwners(
  config: OpenClawConfig,
  pluginId: string,
  boundSessionKey: string,
  allowBoundFallback = true,
): string[] {
  const entry = config.plugins?.entries?.[pluginId]?.config;
  if (!isRecord(entry)) {
    return allowBoundFallback ? [boundSessionKey] : [];
  }
  if (entry.ownerSessionKey != null && typeof entry.ownerSessionKey !== "string") {
    throw new Error("Configured controller owner key is malformed");
  }
  const keys: string[] = [];
  const add = (candidate: unknown) => {
    if (typeof candidate === "string" && candidate && !keys.includes(candidate)) {
      keys.push(candidate);
    }
  };
  add(entry.ownerSessionKey);
  if (
    !Array.isArray(entry.legacyOwnerSessionKeys) &&
    entry.legacyOwnerSessionKeys !== undefined &&
    entry.legacyOwnerSessionKeys !== null
  ) {
    throw new Error("Configured controller owner roster is malformed");
  }
  for (const candidate of Array.isArray(entry.legacyOwnerSessionKeys)
    ? entry.legacyOwnerSessionKeys
    : []) {
    if (typeof candidate !== "string") {
      throw new Error("Configured controller legacy owner key is malformed");
    }
    add(candidate);
  }
  if (entry.repositories != null && !isRecord(entry.repositories)) {
    throw new Error("Configured controller repository owner roster is malformed");
  }
  for (const policy of Object.values(isRecord(entry.repositories) ? entry.repositories : {})) {
    if (
      !isRecord(policy) ||
      (policy.ownerSessionKey != null && typeof policy.ownerSessionKey !== "string")
    ) {
      throw new Error("Configured controller repository owner key is malformed");
    }
    add(policy.ownerSessionKey);
  }
  if (keys.length === 0) {
    return allowBoundFallback ? [boundSessionKey] : [];
  }
  if (
    keys.length > 64 ||
    !keys.includes(boundSessionKey) ||
    keys.some(
      (key) => key !== key.trim() || !parseAgentSessionKey(key) || isIncognitoSessionKey(key),
    )
  ) {
    throw new Error("Configured controller owner roster is not a canonical bound set");
  }
  return keys;
}

export function configuredStatusAgentIds(config: OpenClawConfig, pluginId: string): string[] {
  const entry = config.plugins?.entries?.[pluginId]?.config;
  if (!isRecord(entry) || entry.statusAgentIds == null) {
    return [];
  }
  if (
    !Array.isArray(entry.statusAgentIds) ||
    entry.statusAgentIds.length > 32 ||
    entry.statusAgentIds.some((id) => typeof id !== "string" || !/^[A-Za-z0-9_.-]+$/u.test(id))
  ) {
    throw new Error("Configured controller status-agent roster is malformed");
  }
  return entry.statusAgentIds;
}

/** Observe only native rows still claimed by this controller's exact owner. */
export function isClaimedManagedFlowNativeRun(
  run: unknown,
  flows: readonly unknown[],
  ownerKey: string,
  controllerId: string,
): boolean {
  if (
    !isRecord(run) ||
    run.observationSource !== "native-subagent" ||
    run.label !== `plugin:${controllerId.replace(/\/v1$/, "")}` ||
    run.requesterSessionKey !== ownerKey ||
    typeof run.childSessionKey !== "string" ||
    typeof run.runId !== "string" ||
    typeof run.id !== "string" ||
    typeof run.generation !== "number" ||
    !Number.isSafeInteger(run.generation) ||
    run.generation < 1
  ) {
    return false;
  }
  return flows.some((flow) => {
    if (
      !isRecord(flow) ||
      flow.ownerKey !== ownerKey ||
      flow.controllerId !== controllerId ||
      !isRecord(flow.stateJson)
    ) {
      return false;
    }
    return [flow.stateJson.activeWorker, flow.stateJson.orphanedWorker].some(
      (claim) =>
        isRecord(claim) &&
        claim.sessionKey === run.childSessionKey &&
        claim.runId === run.runId &&
        (claim.taskId == null || claim.taskId === run.id) &&
        claim.nativeGeneration === run.generation,
    );
  });
}

export function createManagedFlowCancellation({
  statusOnly,
  workerCandidate,
  prepare,
  assertCurrent,
  runOwned,
  executeRead,
  sessionKey,
  controllerId,
  client,
  foreignRunObserver,
  actor,
  context,
}: {
  statusOnly: boolean;
  workerCandidate: boolean;
  prepare: () => Promise<void>;
  assertCurrent: () => void;
  runOwned: <T>(operation: () => T) => T;
  executeRead: ExecuteRead;
  sessionKey: string;
  controllerId: string;
  client: unknown;
  foreignRunObserver: boolean;
  actor: { sessionKey: string } | undefined;
  context: NonNullable<ReturnType<GatewayContextResolver>>;
}): NonNullable<Parameters<typeof createManagedTaskFlowHost>[0]["cancel"]> {
  return async (authority, { taskId, expectedFlow }) => {
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
        throw new Error("Cancellation requires an exact current native publisher run observation");
      }
      const claimOwnerKey = foreignRunObserver ? actor!.sessionKey : sessionKey;
      const claimedFlows = (
        await executeRead({
          type: "tasks.managedFlows.list",
          input: { ownerKey: claimOwnerKey, controllerId },
        })
      ).filter((flow) => isClaimedManagedFlowNativeRun(task, [flow], claimOwnerKey, controllerId));
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
  };
}
