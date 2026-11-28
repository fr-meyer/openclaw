/** Keep real Error identity, while preserving opaque rejection diagnostics as a cause. */
export function memoryRejectionError(reason: unknown): Error {
  if (reason instanceof Error) {
    return reason;
  }
  let message: string;
  try {
    message = String(reason);
  } catch {
    message = "Memory operation rejected with an unprintable non-Error value";
  }
  return new Error(message, { cause: reason });
}
