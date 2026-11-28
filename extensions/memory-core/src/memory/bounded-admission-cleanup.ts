// Cleanup carries only resource custody, never fresh mutation authority.
export async function withBoundedOwnerCleanup<T>(
  resources: {
    release?: () => Promise<void>;
    closeManager?: () => Promise<void>;
    closeOwner: () => Promise<void>;
  },
  run: () => Promise<T>,
): Promise<T> {
  let failed = false;
  let original: unknown;
  let result!: T;
  try {
    result = await run();
  } catch (error) {
    failed = true;
    original = error;
  }
  const failures: Array<{ stage: string; error: unknown }> = [];
  for (const [stage, close] of [
    ["release", resources.release],
    ["manager", resources.closeManager],
    ["owner", resources.closeOwner],
  ] as const) {
    if (!close) {
      continue;
    }
    try {
      await close();
    } catch (error) {
      failures.push({ stage, error });
    }
  }
  if (failures.length) {
    if (failed) {
      // Preserve the original thrown value/identity. A denied durable stop
      // is not retried with invented authority; its required marker stays.
      if (original instanceof Error && Object.isExtensible(original)) {
        Object.defineProperty(original, "boundedCleanupFailures", {
          value: failures,
          enumerable: true,
        });
        Object.defineProperty(original, "requiredTombstoneRetained", {
          value: true,
          enumerable: true,
        });
      }
    } else {
      const error = new AggregateError(
        failures.map((item) => item.error),
        "Bounded memory cleanup failed; required owner tombstone retained",
      );
      Object.defineProperty(error, "boundedCleanupFailures", {
        value: failures,
        enumerable: true,
      });
      Object.defineProperty(error, "requiredTombstoneRetained", {
        value: true,
        enumerable: true,
      });
      throw error;
    }
  }
  if (failed) {
    throw original;
  }
  return result;
}
