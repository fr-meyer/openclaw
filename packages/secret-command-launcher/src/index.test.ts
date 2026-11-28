import { describe, expect, it } from "vitest";
import {
  buildSecretCommandLaunchPlan,
  redactResolvedSecrets,
  summarizeSecretCommandLaunchPlan,
} from "./index.js";

describe("secret command launcher", () => {
  it("places resolved secrets only in the child environment", () => {
    const plan = buildSecretCommandLaunchPlan({
      command: "/opt/example/bin/example-mcp",
      args: ["--stdio"],
      cwd: "/var/lib/example-mcp",
      baseEnv: { LANG: "C.UTF-8", OMITTED: undefined },
      secrets: [{ name: "EXAMPLE_API_TOKEN", value: "synthetic-secret-value" }],
    });
    expect(plan.env.EXAMPLE_API_TOKEN).toBe("synthetic-secret-value");
    expect(plan.args.join(" ")).not.toContain("synthetic-secret-value");
    expect(plan.secretEnvironmentNames).toEqual(["EXAMPLE_API_TOKEN"]);
  });

  it("rejects shell lookup, invalid names, duplicates, and secret-bearing arguments", () => {
    expect(() => buildSecretCommandLaunchPlan({ command: "example-mcp", secrets: [] })).toThrow(
      /absolute path/,
    );
    expect(() =>
      buildSecretCommandLaunchPlan({
        command: "/opt/example/bin/example-mcp",
        secrets: [{ name: "lowercase", value: "synthetic" }],
      }),
    ).toThrow(/invalid secret environment name/);
    expect(() =>
      buildSecretCommandLaunchPlan({
        command: "/opt/example/bin/example-mcp",
        secrets: [
          { name: "EXAMPLE_TOKEN", value: "first-secret" },
          { name: "EXAMPLE_TOKEN", value: "second-secret" },
        ],
      }),
    ).toThrow(/duplicate/);
    expect(() =>
      buildSecretCommandLaunchPlan({
        command: "/opt/example/bin/example-mcp",
        args: ["--token=synthetic-secret"],
        secrets: [{ name: "EXAMPLE_TOKEN", value: "synthetic-secret" }],
      }),
    ).toThrow(/must not appear/);
    expect(() =>
      buildSecretCommandLaunchPlan({
        command: "/opt/example/bin/example-mcp",
        baseEnv: { lowercase: "value" },
        secrets: [],
      }),
    ).toThrow(/invalid base environment name/);
    expect(() =>
      buildSecretCommandLaunchPlan({
        command: "/opt/example/bin/example-mcp",
        baseEnv: { EXAMPLE_TOKEN: "placeholder" },
        secrets: [{ name: "EXAMPLE_TOKEN", value: "synthetic-secret" }],
      }),
    ).toThrow(/conflicts with base environment/);
  });

  it("summarizes plans without including secret values", () => {
    const plan = buildSecretCommandLaunchPlan({
      command: "/opt/example/bin/example-mcp",
      baseEnv: { LANG: "C.UTF-8" },
      secrets: [{ name: "EXAMPLE_TOKEN", value: "synthetic-secret" }],
    });
    const summary = JSON.stringify(summarizeSecretCommandLaunchPlan(plan));
    expect(summary).not.toContain("synthetic-secret");
    expect(summary).toContain("EXAMPLE_TOKEN");
  });

  it("redacts overlapping resolved secret values longest-first", () => {
    const redacted = redactResolvedSecrets("long-secret then secret", [
      { name: "SHORT_SECRET", value: "secret" },
      { name: "LONG_SECRET", value: "long-secret" },
    ]);
    expect(redacted).toBe("[redacted] then [redacted]");
  });
});
