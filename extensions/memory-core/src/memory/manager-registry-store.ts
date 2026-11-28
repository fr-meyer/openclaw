import { createPluginRuntimeStore } from "openclaw/plugin-sdk/runtime-store";
import { getMemoryManagerLifecycle } from "./lifecycle.js";
import { MemoryManagerRegistry } from "./manager-registry.js";
import type { MemoryIndexManager } from "./manager.js";

// Provider layers depend on registry contracts; concrete assembly stays with this manager.
const managerRegistryStore = createPluginRuntimeStore<MemoryManagerRegistry<MemoryIndexManager>>({
  key: "memory-core:manager-registry",
  errorMessage: "Memory manager registry is not initialized",
});

export function getMemoryIndexManagerRegistry(): MemoryManagerRegistry<MemoryIndexManager> {
  let registry = managerRegistryStore.tryGetRuntime();
  if (!registry) {
    registry = new MemoryManagerRegistry(getMemoryManagerLifecycle());
    managerRegistryStore.setRuntime(registry);
  }
  return registry;
}
