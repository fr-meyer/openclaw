import { expect, it, vi } from "vitest";
import { withinTest } from "../../test/helpers/promise.js";
import { createDeferredCore } from "../shared/deferred.js";
import { SqliteWorkerInputAdmission } from "./sqlite-worker-input-admission.js";

it("cancels queued identity preparation and releases its input before a slow predecessor settles", async ({
  signal,
}) => {
  const admission = new SqliteWorkerInputAdmission({
    queuedBytes: () => 0,
    isClosing: () => false,
    maxQueuedBytes: 20,
    maxQueuedInputBytes: 20,
    maxMessageBytes: 10,
  });
  const preparing = createDeferredCore();
  const release = createDeferredCore();
  const first = admission.open(10, async () => {
    preparing.resolve();
    await release.promise;
    return { keys: ["physical:first"], dispatch: async () => {} };
  });
  const canceled = new AbortController();
  const prepareCanceled = vi.fn(async () => ({ dispatch: async () => {} }));
  const second = admission.open(10, prepareCanceled, canceled.signal);
  try {
    await withinTest(preparing.promise, signal);
    expect(admission.retainedBytes).toBe(20);
    const reason = new Error("identity waiter canceled");
    const rejected = expect(second).rejects.toBe(reason);
    canceled.abort(reason);
    await withinTest(rejected, signal);
    expect(prepareCanceled).not.toHaveBeenCalled();
    expect(admission.retainedBytes).toBe(10);
  } finally {
    release.resolve();
    await Promise.allSettled([first, second]);
    await admission.joinOpens();
  }
  expect(admission.retainedBytes).toBe(0);
});

it("joins identity preparation and every open lane without reordering conflicting callers", async ({
  signal,
}) => {
  const admission = new SqliteWorkerInputAdmission({
    queuedBytes: () => 0,
    isClosing: () => false,
    maxQueuedBytes: 30,
    maxQueuedInputBytes: 30,
    maxMessageBytes: 10,
  });
  const preparing = createDeferredCore();
  const releasePreparation = createDeferredCore();
  const releaseFirst = createDeferredCore();
  const unrelatedEntered = createDeferredCore();
  const releaseUnrelated = createDeferredCore();
  const dispatched: string[] = [];
  const first = admission.open(10, async () => {
    preparing.resolve();
    await releasePreparation.promise;
    return {
      keys: ["physical:first"],
      dispatch: async () => {
        dispatched.push("first");
        await releaseFirst.promise;
      },
    };
  });
  const prepareSecond = vi.fn(async () => ({
    keys: ["physical:first"],
    dispatch: async () => {
      dispatched.push("second");
    },
  }));
  const second = admission.open(10, prepareSecond);
  const unrelated = admission.open(10, async () => ({
    keys: ["physical:unrelated"],
    dispatch: async () => {
      dispatched.push("unrelated");
      unrelatedEntered.resolve();
      await releaseUnrelated.promise;
    },
  }));
  let joined = false;
  const joining = admission.joinOpens().then(() => {
    joined = true;
  });
  try {
    await withinTest(preparing.promise, signal);
    expect(prepareSecond).not.toHaveBeenCalled();
    expect(admission.retainedBytes).toBe(30);
    await expect(admission.open(1, prepareSecond)).rejects.toMatchObject({ code: "overloaded" });
    expect(joined).toBe(false);
    releasePreparation.resolve();
    await withinTest(unrelatedEntered.promise, signal);
    expect(dispatched).toEqual(["first", "unrelated"]);
    releaseFirst.resolve();
    await withinTest(Promise.all([first, second]), signal);
    expect(dispatched).toEqual(["first", "unrelated", "second"]);
    expect(admission.retainedBytes).toBe(10);
    expect(joined).toBe(false);
    releaseUnrelated.resolve();
    await withinTest(joining, signal);
    expect(admission.retainedBytes).toBe(0);
  } finally {
    releasePreparation.resolve();
    releaseFirst.resolve();
    releaseUnrelated.resolve();
    await Promise.allSettled([first, second, unrelated, joining]);
  }
});
