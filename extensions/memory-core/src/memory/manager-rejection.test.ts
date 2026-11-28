import { describe, expect, it } from "vitest";
import { memoryRejectionError } from "./manager-rejection.js";

describe("memory rejection diagnostics", () => {
  it("retains real cancellation Error identity and cause", () => {
    const reason = new Error("cancelled", { cause: "original" });
    reason.name = "AbortError";
    expect(memoryRejectionError(reason)).toBe(reason);
    expect(memoryRejectionError(reason).cause).toBe("original");
  });

  it("retains primitive and opaque rejection causes without swallowing them", () => {
    const opaque = { detail: "provider rejection" };
    for (const reason of ["cancelled", 0, null, undefined, opaque]) {
      const error = memoryRejectionError(reason);
      expect(error).toBeInstanceOf(Error);
      expect(error.message).toBe(String(reason));
      expect(error.cause).toBe(reason);
    }
  });

  it("keeps the original cause even when diagnostic stringification fails", () => {
    const reason = {
      toString() {
        throw new Error("cannot stringify");
      },
    };
    const error = memoryRejectionError(reason);
    expect(error.message).toBe("Memory operation rejected with an unprintable non-Error value");
    expect(error.cause).toBe(reason);
  });
});
