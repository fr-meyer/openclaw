import type { OpenClawConfig } from "openclaw/plugin-sdk/memory-core-host-engine-foundation";
import { beforeEach, describe, expect, it, vi } from "vitest";

const builtinManager = vi.hoisted(() => ({
  search: vi.fn(async () => []),
  readFile: vi.fn(async () => ({ status: "ok" as const, text: "", path: "MEMORY.md" })),
  status: vi.fn(() => ({ backend: "builtin" as const, provider: "openai" })),
  probeEmbeddingAvailability: vi.fn(async () => ({ ok: true })),
  probeVectorAvailability: vi.fn(async () => true),
}));
const memoryIndexGet = vi.hoisted(() => vi.fn(async () => builtinManager));
const closeAllMemoryIndexManagers = vi.hoisted(() => vi.fn(async () => {}));
const closeMemoryIndexManagersForAgent = vi.hoisted(() => vi.fn(async () => {}));

vi.mock("../../manager-runtime.js", () => ({
  MemoryIndexManager: { get: memoryIndexGet },
  closeAllMemoryIndexManagers,
  closeMemoryIndexManagersForAgent,
}));

import { closeMemorySearchManager, getMemorySearchManager } from "./search-manager.js";

describe("builtin memory search manager", () => {
  beforeEach(() => {
    memoryIndexGet.mockClear();
    memoryIndexGet.mockResolvedValue(builtinManager);
    closeAllMemoryIndexManagers.mockClear();
    closeMemoryIndexManagersForAgent.mockClear();
  });

  it("returns the builtin initialization error", async () => {
    memoryIndexGet.mockRejectedValueOnce(new Error("index unavailable"));

    await expect(
      getMemorySearchManager({ cfg: {} as OpenClawConfig, agentId: "main" }),
    ).resolves.toMatchObject({ manager: null, error: "index unavailable" });
  });

  it("normalizes the agent id before scoped cleanup", async () => {
    const cfg = {} as OpenClawConfig;
    await getMemorySearchManager({ cfg, agentId: " Main " });

    await closeMemorySearchManager({ cfg, agentId: " Main " });

    expect(closeMemoryIndexManagersForAgent).toHaveBeenCalledWith({ agentId: "main" });
  });

  it("passes admission to the manager and reports a timed-out lookup as unavailable", async () => {
    const cfg = {} as OpenClawConfig;
    const admission = { signal: new AbortController().signal, waitMs: 100 };
    memoryIndexGet.mockRejectedValueOnce(new Error("Memory manager admission timed out"));

    await expect(
      getMemorySearchManager({ cfg, agentId: "main", admission }),
    ).resolves.toMatchObject({
      manager: null,
      error: "Memory manager admission timed out",
    });
    expect(memoryIndexGet).toHaveBeenCalledWith(
      expect.objectContaining({ cfg, agentId: "main", admission }),
    );
  });
});
