import { getEventListeners } from "node:events";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryManagerRegistry } from "./manager-registry.js";

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((accept) => {
    resolve = accept;
  });
  return { promise, resolve };
}

type TestManager = { close(): Promise<void> };

async function acquire(
  registry: MemoryManagerRegistry<TestManager>,
  agentId: string,
  create: () => TestManager,
  admission?: { signal?: AbortSignal; waitMs?: number },
) {
  return await registry.acquire(
    { agentId, purpose: "default", admission },
    {
      prepare: () => ({ key: `${agentId}:test:default`, create, reuse: () => true }),
    },
  );
}

afterEach(() => vi.useRealTimers());

describe("memory manager admission", () => {
  it("bounds the global close wait without canceling close or creating an abandoned manager", async () => {
    vi.useFakeTimers();
    const registry = new MemoryManagerRegistry<TestManager>({});
    const closeGate = deferred<void>();
    const close = vi.fn(() => closeGate.promise);
    const create = vi.fn(() => ({ close: async () => {} }));
    await acquire(registry, "main", () => ({ close }));
    const closing = registry.closeAll();
    const canceled = new AbortController();
    const aborted = acquire(registry, "main", create, { signal: canceled.signal, waitMs: 100 });
    const timedOut = acquire(registry, "main", create, { waitMs: 100 });
    const timeoutCheck = expect(timedOut).rejects.toThrow("Memory manager admission timed out");
    canceled.abort(new Error("caller canceled"));
    await expect(aborted).rejects.toThrow("caller canceled");
    await vi.advanceTimersByTimeAsync(100);
    await timeoutCheck;
    expect(close).toHaveBeenCalledOnce();
    expect(create).not.toHaveBeenCalled();
    closeGate.resolve();
    await closing;
    expect(create).not.toHaveBeenCalled();
  });

  it("bounds a scoped close wait while another agent can enter", async () => {
    vi.useFakeTimers();
    const registry = new MemoryManagerRegistry<TestManager>({});
    const closeGate = deferred<void>();
    const close = vi.fn(() => closeGate.promise);
    await acquire(registry, "main", () => ({ close }));
    const closing = registry.closeForAgent({ agentId: "main", purpose: "default" });
    const blockedCreate = vi.fn(() => ({ close: async () => {} }));
    const blocked = acquire(registry, "main", blockedCreate, { waitMs: 100 });
    const blockedCheck = expect(blocked).rejects.toThrow("Memory manager admission timed out");
    const otherCreate = vi.fn(() => ({ close: async () => {} }));
    await expect(acquire(registry, "other", otherCreate, { waitMs: 100 })).resolves.toBeTruthy();
    await vi.advanceTimersByTimeAsync(100);
    await blockedCheck;
    expect(blockedCreate).not.toHaveBeenCalled();
    closeGate.resolve();
    await closing;
    await registry.closeAll();
    expect(blockedCreate).not.toHaveBeenCalled();
  });

  it("does not admit a caller canceled behind a scoped close", async () => {
    const registry = new MemoryManagerRegistry<TestManager>({});
    const closeGate = deferred<void>();
    await acquire(registry, "main", () => ({ close: () => closeGate.promise }));
    const closing = registry.closeForAgent({ agentId: "main", purpose: "default" });
    const canceled = new AbortController();
    const create = vi.fn(() => ({ close: async () => {} }));
    const waiting = acquire(registry, "main", create, { signal: canceled.signal });

    canceled.abort(new Error("caller canceled"));
    await expect(waiting).rejects.toThrow("caller canceled");
    closeGate.resolve();
    await closing;
    await registry.closeAll();
    expect(create).not.toHaveBeenCalled();
    expect(getEventListeners(canceled.signal, "abort")).toHaveLength(0);
  });

  it("does not enqueue a caller already canceled at admission", async () => {
    const registry = new MemoryManagerRegistry<TestManager>({});
    const canceled = new AbortController();
    canceled.abort(new Error("already canceled"));
    const create = vi.fn(() => ({ close: async () => {} }));

    await expect(acquire(registry, "main", create, { signal: canceled.signal })).rejects.toThrow(
      "already canceled",
    );
    expect(create).not.toHaveBeenCalled();
    await registry.closeAll();
    expect(create).not.toHaveBeenCalled();
  });

  it("keeps ownership of a factory that started before cancellation", async () => {
    vi.useFakeTimers();
    const registry = new MemoryManagerRegistry<TestManager>({});
    const factoryGate = deferred<TestManager>();
    const started = deferred<void>();
    const close = vi.fn(async () => {});
    const canceled = new AbortController();
    const create = vi.fn(() => {
      started.resolve();
      return factoryGate.promise;
    });
    const pending = registry.acquire(
      { agentId: "main", purpose: "default", admission: { signal: canceled.signal, waitMs: 100 } },
      { prepare: () => ({ key: "main:test:default", create, reuse: () => true }) },
    );
    await started.promise;
    expect(create).toHaveBeenCalledOnce();
    expect(vi.getTimerCount()).toBe(0);
    expect(getEventListeners(canceled.signal, "abort")).toHaveLength(0);
    canceled.abort(new Error("caller canceled"));
    await vi.advanceTimersByTimeAsync(100);
    const manager = { close };
    factoryGate.resolve(manager);
    await expect(pending).resolves.toBe(manager);
    await registry.closeAll();
    expect(close).toHaveBeenCalledOnce();
  });
});
