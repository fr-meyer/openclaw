import { createPluginRuntimeStore } from "openclaw/plugin-sdk/runtime-store";
import { getMemoryManagerLifecycle } from "./lifecycle.js";
import { MemoryManagerRegistry } from "./manager-registry.js";

// Concrete manager assembly supplies T; this module never imports the manager implementation.
export function createMemoryIndexManagerRegistryGetter<T extends { close(): Promise<void> }>() {
  const managerRegistryStore = createPluginRuntimeStore<MemoryManagerRegistry<T>>({
    key: "memory-core:manager-registry",
    errorMessage: "Memory manager registry is not initialized",
  });
  return function getMemoryIndexManagerRegistry(): MemoryManagerRegistry<T> {
    let registry = managerRegistryStore.tryGetRuntime();
    if (!registry) {
      registry = new MemoryManagerRegistry<T>(getMemoryManagerLifecycle());
      managerRegistryStore.setRuntime(registry);
    }
    return registry;
  };
}
