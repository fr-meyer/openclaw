import type { PluginRecord } from "./registry-types.js";
import type { PluginRuntime } from "./runtime/types.js";

const PACKAGED_MERGEGUEZ_ROOT = "/app/runtime-plugins/mergeguez-pr-lifecycle";
const PACKAGED_MERGEGUEZ_ENTRY = `${PACKAGED_MERGEGUEZ_ROOT}/index.mjs`;

/** The shared Gateway facet stays conservative; only the exact packaged record advertises parity. */
export function projectPackagedMergeguezTaskFlowRuntime(
  tasks: NonNullable<PluginRuntime["tasks"]>,
  record: Pick<PluginRecord, "id" | "source" | "origin" | "rootDir">,
): NonNullable<PluginRuntime["tasks"]> {
  const controllerParity =
    tasks.availability.managedFlows === true &&
    tasks.availability.taskRuns === true &&
    record.id === "mergeguez-pr-lifecycle" &&
    record.origin === "config" &&
    record.rootDir === PACKAGED_MERGEGUEZ_ROOT &&
    record.source === PACKAGED_MERGEGUEZ_ENTRY;
  return {
    ...tasks,
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
