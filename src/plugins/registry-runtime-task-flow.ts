import { issueGatewayTaskFlowLifecycle } from "../gateway/server-managed-task-flow-runtime.js";
import type { PluginRecord, PluginRegistry } from "./registry-types.js";
import type { PluginRuntime } from "./runtime/types.js";

type TaskFlowRuntime = NonNullable<PluginRuntime["tasks"]>;
type ControllerAdmission = {
  record: PluginRecord;
  assertCurrent(): void;
  invoke<T>(run: () => T): T;
  currentView(): PluginRegistry;
};

const PACKAGED_MERGEGUEZ_ROOT = "/app/runtime-plugins/mergeguez-pr-lifecycle";
const PACKAGED_MERGEGUEZ_ENTRY = `${PACKAGED_MERGEGUEZ_ROOT}/index.mjs`;

/** The shared Gateway facet stays conservative; only the exact packaged record advertises parity. */
export function projectPackagedMergeguezTaskFlowRuntime(
  tasks: NonNullable<PluginRuntime["tasks"]>,
  record: Pick<PluginRecord, "id" | "source" | "origin" | "rootDir">,
  admission?: ControllerAdmission,
): NonNullable<PluginRuntime["tasks"]> {
  const controllerParity =
    tasks.availability.managedFlows === true &&
    tasks.availability.taskRuns === true &&
    record.id === "mergeguez-pr-lifecycle" &&
    record.origin === "config" &&
    record.rootDir === PACKAGED_MERGEGUEZ_ROOT &&
    record.source === PACKAGED_MERGEGUEZ_ENTRY;
  // Never propagate an unverified marker from a custom/fallback runtime.
  const { lifecycleController: _unverifiedController, ...base } = tasks;
  const projected: TaskFlowRuntime = {
    ...base,
    availability: Object.freeze({ ...tasks.availability, controllerParity }),
  };
  if (record.id === "pr-lifecycle-taskflow" && admission) {
    const identity = Object.freeze({
      id: record.id,
      source: record.source,
      rootDir: record.rootDir,
      origin: record.origin,
    });
    const assertIdentityCurrent = () => {
      admission.assertCurrent();
      if (
        admission.record !== record ||
        record.id !== identity.id ||
        record.source !== identity.source ||
        record.rootDir !== identity.rootDir ||
        record.origin !== identity.origin
      ) {
        throw new Error("Lifecycle controller registration identity changed");
      }
    };
    const withController = <T>(run: () => T): T => {
      assertIdentityCurrent();
      return admission.invoke(() => {
        // The producer, not this projection, joins exact owner.record and the
        // scoped current registry view through genuine lifecycle authority.
        if (!issueGatewayTaskFlowLifecycle(tasks, admission.record, admission.currentView())) {
          throw new Error("Lifecycle controller producer is unavailable");
        }
        return run();
      });
    };
    Object.defineProperty(projected, "lifecycleController", {
      enumerable: true,
      get: () => {
        assertIdentityCurrent();
        return admission.invoke(() =>
          issueGatewayTaskFlowLifecycle(tasks, admission.record, admission.currentView()),
        );
      },
    });
    projected.managedFlows = {
      bindSession: (input) => withController(() => tasks.managedFlows.bindSession(input)),
    };
    projected.runs = {
      bindSession: (input) => withController(() => tasks.runs.bindSession(input)),
    };
  }
  return projected;
}

/** Cache by the lazy host facet identity without sharing one plugin's projection with another. */
export function createPackagedMergeguezTaskFlowProjector(
  record: Pick<PluginRecord, "id" | "source" | "origin" | "rootDir">,
  admission?: ControllerAdmission,
) {
  let cached:
    | { source: NonNullable<PluginRuntime["tasks"]>; value: NonNullable<PluginRuntime["tasks"]> }
    | undefined;
  return (source: PluginRuntime["tasks"]): PluginRuntime["tasks"] => {
    if (!source) {
      return source;
    }
    if (cached?.source !== source) {
      cached = { source, value: projectPackagedMergeguezTaskFlowRuntime(source, record, admission) };
    }
    return cached.value;
  };
}
