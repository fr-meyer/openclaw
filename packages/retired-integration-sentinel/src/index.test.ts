import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import {
  formatRetiredIntegrationNotice,
  resolveRetiredIntegrationStatus,
  runRetiredIntegrationSentinel,
} from "./index.js";

describe("retired integration sentinel", () => {
  it("returns stable structured retirement status", () => {
    expect(
      resolveRetiredIntegrationStatus({
        id: "example-adapter",
        reason: "the integration was intentionally retired",
      }),
    ).toEqual({
      id: "example-adapter",
      status: "retired",
      reason: "the integration was intentionally retired",
      exitCode: 64,
    });
  });

  it("formats a bounded fail-closed notice", () => {
    const notice = formatRetiredIntegrationNotice(
      resolveRetiredIntegrationStatus({
        id: "example-adapter",
        reason: "superseded by a reviewed path",
        replacement: "use the maintained adapter",
      }),
    );
    expect(notice).toBe(
      "blocked: integration example-adapter is retired; reason: superseded by a reviewed path; replacement: use the maintained adapter",
    );
  });

  it("ignores untrusted arguments and never invokes a retired command", () => {
    const writeError = vi.fn();
    const result = runRetiredIntegrationSentinel({
      sentinel: {
        id: "example-adapter",
        reason: "retired",
        exitCode: 78,
      },
      argv: ["--unsafe", "value"],
      writeError,
    });
    expect(result).toBe(78);
    expect(writeError).toHaveBeenCalledWith(
      "blocked: integration example-adapter is retired; reason: retired\n",
    );
  });

  it("rejects unsafe identifiers and invalid exit codes", () => {
    expect(() =>
      resolveRetiredIntegrationStatus({ id: "Invalid Name", reason: "retired" }),
    ).toThrow(/lowercase stable identifier/);
    expect(() =>
      resolveRetiredIntegrationStatus({ id: "example", reason: "retired", exitCode: 0 }),
    ).toThrow(/between 1 and 255/);
    expect(() =>
      resolveRetiredIntegrationStatus({ id: "example", reason: "retired\nforged" }),
    ).toThrow(/safe characters/);
  });

  it("ships an executable sentinel that ignores arguments and exits non-zero", () => {
    const executable = fileURLToPath(
      new URL("../bin/retired-integration-sentinel.mjs", import.meta.url),
    );
    const result = spawnSync(process.execPath, [executable, "--unsafe", "ignored"], {
      encoding: "utf8",
      env: {
        OPENCLAW_RETIRED_INTEGRATION_ID: "example-adapter",
        OPENCLAW_RETIRED_INTEGRATION_REASON: "intentionally retired",
        OPENCLAW_RETIRED_INTEGRATION_EXIT_CODE: "78",
      },
    });
    expect(result.status).toBe(78);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe(
      "blocked: integration example-adapter is retired; reason: intentionally retired\n",
    );
    expect(result.stderr).not.toContain("--unsafe");
  });
});
