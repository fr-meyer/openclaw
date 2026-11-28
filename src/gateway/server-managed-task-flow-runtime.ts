import path from "node:path";
import { captureSqliteReadOnlyWorkerScope } from "../infra/sqlite-readonly-worker-context.js";
import { pluginInstanceInvocation } from "../plugins/plugin-instance-invocation.js";
import {
  getPluginInstance,
  getPluginInstanceOwner,
  hasCurrentPluginInstanceAuthority,
} from "../plugins/plugin-instance-scope.js";
import { capturePluginLifecycleAuthority } from "../plugins/registry-lifecycle.js";
import type { PluginRecord, PluginRegistry } from "../plugins/registry-types.js";
import {
  getInProcessGatewayRequestContext,
  getPluginRuntimeGatewayRequestScope,
} from "../plugins/runtime/gateway-request-scope.js";
import type {
  PluginLifecycleControllerCapability,
  PluginRuntime,
} from "../plugins/runtime/types.js";
import { captureOpenClawStateWorkerContext } from "../state/openclaw-state-worker-context.js";
import type { ManagedFlowNativeLaunchClaim } from "../tasks/managed-task-flow-kill-claim.worker.js";
import { bindGatewayManagedTaskFlowHost } from "./server-managed-task-flow-binding.js";
import type { RetainedNativeLaunch } from "./server-managed-task-flow-binding.types.js";
import type { GatewayContextResolver } from "./server-methods/types.js";

export {
  configuredManagedFlowOwners,
  isClaimedManagedFlowNativeRun,
} from "./server-managed-task-flow-policy.js";

type TaskFlowRuntime = NonNullable<PluginRuntime["tasks"]>;
type GatewayLifecycleIssuer = (
  record: PluginRecord,
  view: PluginRegistry,
) => PluginLifecycleControllerCapability | undefined;

// Lexical custody: the sole set() is inside the actual Gateway factory below.
// The exported query cannot enroll, replace, or supply a caller-owned issuer.
const gatewayLifecycleIssuers = new WeakMap<TaskFlowRuntime, GatewayLifecycleIssuer>();

export function issueGatewayTaskFlowLifecycle(
  tasks: TaskFlowRuntime,
  record: PluginRecord,
  view: PluginRegistry,
): PluginLifecycleControllerCapability | undefined {
  return gatewayLifecycleIssuers.get(tasks)?.(record, view);
}

function lifecycleSourceIdentity(record: PluginRecord) {
  const rootDir = record.rootDir;
  if (
    record.id !== "pr-lifecycle-taskflow" ||
    record.origin !== "config" ||
    !rootDir ||
    !path.isAbsolute(rootDir) ||
    path.normalize(rootDir) !== rootDir ||
    record.source !== path.join(rootDir, "index.mjs")
  ) {
    return undefined;
  }
  const normalized = rootDir.replaceAll("\\", "/");
  if (
    normalized === "/tmp" ||
    normalized.startsWith("/tmp/") ||
    normalized.includes("/.openclaw/tmp/") ||
    normalized.includes("/.openclaw/worktrees/")
  ) {
    return undefined;
  }
  return Object.freeze({ source: record.source, rootDir });
}

const nativeLaunchClaims = new WeakMap<object, RetainedNativeLaunch>();

/** Only a current owner-bound TaskFlow port can mint this in-process object. */
export function consumeGatewayManagedFlowNativeLaunch(
  capability: unknown,
  pluginId: string,
  childSessionKey: string,
): ManagedFlowNativeLaunchClaim & { assertCurrent: () => void } {
  const claim =
    capability && typeof capability === "object" ? nativeLaunchClaims.get(capability) : undefined;
  if (
    !claim ||
    claim.used ||
    claim.pluginId !== pluginId ||
    claim.childSessionKey !== childSessionKey
  ) {
    throw new Error("Native launch lacks its exact current managed-flow capability");
  }
  claim.assertCurrent();
  claim.used = true;
  const { ownerKey, controllerId, flowId, revision, assertCurrent } = claim;
  return Object.freeze({
    ownerKey,
    controllerId,
    flowId,
    revision,
    childSessionKey,
    assertCurrent,
  });
}

/** The installed controller's owner roster comes from the live, validated Gateway config. */
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

  const bindHost = (input: { sessionKey: string; agentId?: string }, kind: "flow" | "run") =>
    bindGatewayManagedTaskFlowHost(input, kind, {
      resolveGatewayContext,
      runWithReadOnlyWorkers,
      stateContext,
      closers,
      assertRuntimeCurrent,
      nativeLaunchClaims,
    });

  const tasks: NonNullable<PluginRuntime["tasks"]> = {
    authorityVersion: 1,
    availability: Object.freeze({
      managedFlows: true,
      taskRuns: true,
      // The installed controller remains inert until the scoped status, report,
      // and native root-cancel paths pass packaged runtime qualification.
      controllerParity: false,
      canonicalTaskCreate: false,
      workerLaunch: false,
    }),
    managedFlows: {
      bindSession: (input) => {
        const { host, close } = bindHost(input, "flow");
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
        const { host, close } = bindHost(input, "run");
        try {
          return { ...host.runs.bindSession(input), close };
        } catch (error) {
          void close().catch(() => undefined);
          throw error;
        }
      },
    },
  };
  // Unbound/direct factory callers cannot advertise the registered controller.
  if (!resolveGatewayContext || !runtimeLifetime) {
    return tasks;
  }
  gatewayLifecycleIssuers.set(tasks, (record, view) => {
    assertRuntimeCurrent();
    const identity = lifecycleSourceIdentity(record);
    if (!identity) {
      return undefined;
    }
    const context = getInProcessGatewayRequestContext(resolveGatewayContext);
    const scope = getPluginRuntimeGatewayRequestScope();
    const invocation = pluginInstanceInvocation.getStore();
    const owner = invocation && getPluginInstanceOwner(invocation.instance);
    const instance = owner?.instance;
    if (
      !context ||
      resolveGatewayContext() !== context ||
      scope?.pluginId !== record.id ||
      scope.pluginSource !== identity.source ||
      scope.pluginRegistry !== view ||
      !owner ||
      owner.revoked ||
      owner.record !== record ||
      !instance ||
      getPluginInstance(record) !== instance ||
      instance !== invocation?.instance ||
      instance.pluginId !== record.id ||
      instance.lifecycle.signal.aborted ||
      !hasCurrentPluginInstanceAuthority(record.id) ||
      !capturePluginLifecycleAuthority(view, record, {
        registration: true,
        admittedRuntime: true,
      })?.()
    ) {
      throw new Error("Lifecycle descriptor requires its original current Gateway/plugin owner");
    }
    // Describes these real ports only. bindHost still requires the original
    // Gateway resolver, current PluginInstance, actor and configured owner;
    // captureNativeLaunch still issues a separate exact-revision one-use claim.
    return Object.freeze({
      authorityVersion: 1,
      pluginId: "pr-lifecycle-taskflow",
      source: identity.source,
      rootDir: identity.rootDir,
      managedFlows: true,
      taskRuns: true,
      nativeLaunch: true,
    });
  });
  return tasks;
}
