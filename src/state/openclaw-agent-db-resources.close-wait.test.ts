import { expect, it, vi } from "vitest";
import { createDeferredCore } from "../shared/deferred.js";
import {
  drainAgentDatabaseResources,
  hasOpenClawAgentDatabaseAsyncResources,
  registerOpenClawAgentDatabaseAsyncResource,
  revokeAgentDatabaseResources,
  waitForAgentDatabaseResourceClose,
} from "./openclaw-agent-db-resources.js";

// The resource owner/drain/wait implementation is real. There is no database,
// native opener, worker or timer in these synthetic closer fixtures.
vi.mock("./openclaw-state-db-async-lifecycle.js", () => ({
  getOpenClawDatabaseMaintenanceScope: () => undefined,
}));

it("joins the matching native close fence after all registered resources have closed", async () => {
  const selection = { agentId: "main", path: "/synthetic/resource-wait/native.sqlite" };
  const nativeEntered = createDeferredCore<void>();
  const nativeFinish = createDeferredCore<void>();
  const resource = {
    ...selection,
    revoke: vi.fn<() => void>(),
    close: vi.fn<() => Promise<void>>().mockResolvedValue(undefined),
  };
  const unregister = registerOpenClawAgentDatabaseAsyncResource(resource);
  const closeNative = vi.fn(async () => {
    nativeEntered.resolve();
    await nativeFinish.promise;
  });
  const closing = drainAgentDatabaseResources(selection, closeNative);
  let renewed: (() => void) | undefined;
  try {
    await nativeEntered.promise;
    expect(hasOpenClawAgentDatabaseAsyncResources()).toBe(false);
    expect(() => registerOpenClawAgentDatabaseAsyncResource(resource)).toThrow("are closing");
    const waiting = waitForAgentDatabaseResourceClose(selection).then(() => {
      // Premature wait completion would try to renew under the still-held fence.
      renewed = registerOpenClawAgentDatabaseAsyncResource(resource);
    });
    const outcome = waiting.then(
      () => undefined,
      (error: unknown) => error,
    );
    await waitForAgentDatabaseResourceClose({ ...selection, agentId: "unrelated" });
    expect(resource.close).toHaveBeenCalledOnce();
    expect(resource.revoke).toHaveBeenCalledOnce();
    expect(closeNative).toHaveBeenCalledOnce();
    nativeFinish.resolve();
    await closing;
    await expect(outcome).resolves.toBeUndefined();
    expect(renewed).toBeTypeOf("function");
    expect(resource.close).toHaveBeenCalledOnce();
    expect(resource.revoke).toHaveBeenCalledOnce();
    expect(closeNative).toHaveBeenCalledOnce();
  } finally {
    nativeFinish.resolve();
    await closing;
    renewed?.();
    unregister();
  }
});

it("joins only a matching closing resource and does not revoke or close while waiting", async () => {
  const selection = { agentId: "main", path: "/synthetic/resource-wait/worker.sqlite" };
  const closeEntered = createDeferredCore<void>();
  const closeFinish = createDeferredCore<void>();
  const resource = {
    ...selection,
    revoke: vi.fn<() => void>(),
    close: vi.fn(async () => {
      closeEntered.resolve();
      await closeFinish.promise;
    }),
  };
  const unregister = registerOpenClawAgentDatabaseAsyncResource(resource);
  const closing = Promise.all(revokeAgentDatabaseResources(selection));
  let renewed: (() => void) | undefined;
  try {
    await closeEntered.promise;
    // Actor unregistration must not erase its already-retained closing custody.
    unregister();
    const waiting = waitForAgentDatabaseResourceClose(selection).then(() => {
      renewed = registerOpenClawAgentDatabaseAsyncResource(resource);
    });
    const outcome = waiting.then(
      () => undefined,
      (error: unknown) => error,
    );
    await waitForAgentDatabaseResourceClose({ ...selection, agentId: "unrelated" });
    await waitForAgentDatabaseResourceClose({
      ...selection,
      path: "/synthetic/resource-wait/unrelated.sqlite",
    });
    expect(resource.close).toHaveBeenCalledOnce();
    expect(resource.revoke).toHaveBeenCalledOnce();
    closeFinish.resolve();
    await closing;
    await expect(outcome).resolves.toBeUndefined();
    expect(renewed).toBeTypeOf("function");
    expect(resource.close).toHaveBeenCalledOnce();
    expect(resource.revoke).toHaveBeenCalledOnce();
  } finally {
    closeFinish.resolve();
    await closing;
    renewed?.();
    unregister();
  }
});

it("propagates failure from an in-flight matching native close without another close", async () => {
  const selection = { agentId: "main", path: "/synthetic/resource-wait/native-failure.sqlite" };
  const nativeEntered = createDeferredCore<void>();
  const nativeFinish = createDeferredCore<void>();
  const failure = new Error("Synthetic native close failed");
  const closeNative = vi.fn(async () => {
    nativeEntered.resolve();
    await nativeFinish.promise;
  });
  const closing = drainAgentDatabaseResources(selection, closeNative);
  const closeOutcome = closing.catch((error: unknown) => error);
  try {
    await nativeEntered.promise;
    const waiting = waitForAgentDatabaseResourceClose(selection);
    const waitOutcome = waiting.catch((error: unknown) => error);
    nativeFinish.reject(failure);
    const rejected: unknown = await waitOutcome;
    expect(rejected).toBeInstanceOf(AggregateError);
    if (!(rejected instanceof AggregateError)) {
      throw new Error("Native close failure was not retained by the wait");
    }
    expect(rejected.errors).toContain(failure);
    await expect(closeOutcome).resolves.toBe(failure);
    expect(closeNative).toHaveBeenCalledOnce();
  } finally {
    nativeFinish.resolve();
    await closeOutcome;
  }
});

it("joins both overlapping native drains passed the same caller selection object", async () => {
  const selection = { agentId: "main", path: "/synthetic/resource-wait/overlap.sqlite" };
  const firstEntered = createDeferredCore<void>();
  const firstFinish = createDeferredCore<void>();
  const secondEntered = createDeferredCore<void>();
  const secondFinish = createDeferredCore<void>();
  const closeFirst = vi.fn(async () => {
    firstEntered.resolve();
    await firstFinish.promise;
  });
  const closeSecond = vi.fn(async () => {
    secondEntered.resolve();
    await secondFinish.promise;
  });
  const resource = {
    ...selection,
    revoke: vi.fn<() => void>(),
    close: vi.fn<() => Promise<void>>().mockResolvedValue(undefined),
  };
  const first = drainAgentDatabaseResources(selection, closeFirst);
  const second = drainAgentDatabaseResources(selection, closeSecond);
  let renewed: (() => void) | undefined;
  try {
    await Promise.all([firstEntered.promise, secondEntered.promise]);
    const waiting = waitForAgentDatabaseResourceClose(selection).then(() => {
      renewed = registerOpenClawAgentDatabaseAsyncResource(resource);
    });
    const outcome = waiting.then(
      () => undefined,
      (error: unknown) => error,
    );
    firstFinish.resolve();
    await first;
    expect(() => registerOpenClawAgentDatabaseAsyncResource(resource)).toThrow("are closing");
    await waitForAgentDatabaseResourceClose({ ...selection, agentId: "unrelated" });
    expect(closeFirst).toHaveBeenCalledOnce();
    expect(closeSecond).toHaveBeenCalledOnce();
    expect(resource.close).not.toHaveBeenCalled();
    expect(resource.revoke).not.toHaveBeenCalled();
    secondFinish.resolve();
    await second;
    await expect(outcome).resolves.toBeUndefined();
    expect(renewed).toBeTypeOf("function");
    expect(closeFirst).toHaveBeenCalledOnce();
    expect(closeSecond).toHaveBeenCalledOnce();
    expect(resource.close).not.toHaveBeenCalled();
    expect(resource.revoke).not.toHaveBeenCalled();
  } finally {
    firstFinish.resolve();
    secondFinish.resolve();
    await Promise.all([first, second]);
    renewed?.();
  }
});

it("refuses retained failed cleanup without retrying or revoking from wait", async () => {
  const selection = { agentId: "main", path: "/synthetic/resource-wait/retained-failure.sqlite" };
  const failure = new Error("Synthetic resource cleanup failed");
  const resource = {
    ...selection,
    revoke: vi.fn<() => void>(),
    close: vi.fn<() => Promise<void>>().mockRejectedValueOnce(failure),
  };
  const unregister = registerOpenClawAgentDatabaseAsyncResource(resource);
  try {
    const [settled] = await Promise.allSettled(revokeAgentDatabaseResources(selection));
    expect(settled).toEqual({ status: "rejected", reason: failure });
    unregister();
    await expect(waitForAgentDatabaseResourceClose(selection)).rejects.toThrow();
    await expect(waitForAgentDatabaseResourceClose(selection)).rejects.toThrow();
    expect(resource.close).toHaveBeenCalledOnce();
    expect(resource.revoke).toHaveBeenCalledOnce();
    expect(() => registerOpenClawAgentDatabaseAsyncResource(resource)).toThrow("are closing");
    await waitForAgentDatabaseResourceClose({ ...selection, agentId: "unrelated" });
    expect(resource.close).toHaveBeenCalledOnce();
    expect(resource.revoke).toHaveBeenCalledOnce();
  } finally {
    // Only fixture teardown explicitly retries its synthetic closer through the
    // existing revoke API; the wait API above must never initiate that retry.
    resource.close.mockResolvedValue(undefined);
    await Promise.all(revokeAgentDatabaseResources(selection));
    unregister();
  }
});
