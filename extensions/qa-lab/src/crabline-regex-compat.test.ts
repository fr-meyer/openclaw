import { ManifestSchema } from "@openclaw/crabline";
import { describe, expect, it } from "vitest";

function parseRegexFixture(pattern: string) {
  return ManifestSchema.safeParse({
    providers: { test: { adapter: "loopback" } },
    fixtures: [
      {
        id: "regex-compat",
        provider: "test",
        mode: "roundtrip",
        target: { id: "fixture" },
        inboundMatch: { strategy: "regex", pattern },
      },
    ],
  });
}

describe("Crabline regex dependency compatibility", () => {
  it("accepts supported syntax through manifest validation", () => {
    expect(parseRegexFixture("^hello\\s+world$").success).toBe(true);
  });

  it.each(["(a)\\1", "(?<=hello)world"])("rejects unsupported syntax %s", (pattern) => {
    const result = parseRegexFixture(pattern);
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues).toContainEqual(
        expect.objectContaining({
          path: ["fixtures", 0, "inboundMatch", "pattern"],
          message: "inboundMatch.pattern must use syntax supported by the linear-time regex engine",
        }),
      );
    }
  });

  it("keeps the pattern length limit", () => {
    const result = parseRegexFixture("a".repeat(513));
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues).toContainEqual(
        expect.objectContaining({
          path: ["fixtures", 0, "inboundMatch", "pattern"],
          message: "inboundMatch.pattern must contain at most 512 characters",
        }),
      );
    }
  });
});
