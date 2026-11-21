import type { PluginRecord } from "./registry-types.js";
import type { PluginRuntime } from "./runtime/types.js";

const PACKAGED_MERGEGUEZ_ROOT = "/app/runtime-plugins/mergeguez-pr-lifecycle";
const BUNDLED_LIFECYCLE_ROOT = "/app/extensions/pr-lifecycle-taskflow";
const BUNDLED_LIFECYCLE_ENTRY = BUNDLED_LIFECYCLE_ROOT + "/index.mjs";
const PACKAGED_MERGEGUEZ_ENTRY = `${PACKAGED_MERGEGUEZ_ROOT}/index.mjs`;

/** The shared Gateway facet stays conservative; only the exact packaged record advertises parity. */
export function projectPackagedMergeguezTaskFlowRuntime(
  tasks: NonNullable<PluginRuntime["tasks"]>,
  record: Pick<PluginRecord, "id" | "source" | "origin" | "rootDir">,
): NonNullable<PluginRuntime["tasks"]> {
  const controllerParity =
    tasks.availability.managedFlows &&
    tasks.availability.taskRuns &&
    record.id === "mergeguez-pr-lifecycle" &&
    record.origin === "config" &&
    record.rootDir === PACKAGED_MERGEGUEZ_ROOT &&
    record.source === PACKAGED_MERGEGUEZ_ENTRY;
  const lifecycleController =
    tasks.authorityVersion === 1 &&
    tasks.availability.managedFlows &&
    tasks.availability.taskRuns &&
    tasks.availability.managedFlowNativeLaunch === true &&
    record.id === "pr-lifecycle-taskflow" &&
    record.origin === "bundled" &&
    record.rootDir === BUNDLED_LIFECYCLE_ROOT &&
    record.source === BUNDLED_LIFECYCLE_ENTRY
      ? Object.freeze({
          authorityVersion: 1 as const,
          pluginId: "pr-lifecycle-taskflow" as const,
          source: record.source,
          rootDir: record.rootDir,
          managedFlows: true as const,
          taskRuns: true as const,
          nativeLaunch: true as const,
        })
      : undefined;
  return {
    ...tasks,
    // Never forward a capability projected for another record.
    lifecycleController,
    availability: Object.freeze({ ...tasks.availability, controllerParity }),
  };
}

/** Cache by the lazy host facet identity without sharing one plugin's projection with another. */
export function createPackagedMergeguezTaskFlowProjector(
  record: Pick<PluginRecord, "id" | "source" | "origin" | "rootDir">,
) {
  let cached:
    | { source: NonNullable<PluginRuntime["tasks"]>; value: NonNullable<PluginRuntime["tasks"]> }
    | undefined;
  return (source: PluginRuntime["tasks"]): PluginRuntime["tasks"] => {
    if (!source) {
      return source;
    }
    if (cached?.source !== source) {
      cached = { source, value: projectPackagedMergeguezTaskFlowRuntime(source, record) };
    }
    return cached.value;
  };
}
