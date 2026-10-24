import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { expect, it } from "vitest";
import { resolveTestNodeExecPath } from "../../src/test-utils/node-process.js";

// The GCP image executor fixtures use POSIX fake executables and /dev/null.
// Keep their native runner inside the normal suite owner on Linux and macOS.
it.skipIf(process.platform === "win32")(
  "runs all native GCP image source and immutable smoke regressions",
  () => {
    const result = spawnSync(
      resolveTestNodeExecPath(),
      [
        "--test",
        "--test-reporter=tap",
        join(process.cwd(), "scripts/fork-release/gcp-image-context.node.mjs"),
      ],
      { cwd: process.cwd(), encoding: "utf8", timeout: 30_000 },
    );
    expect(result.error, `${result.stdout}\n${result.stderr}`).toBeUndefined();
    expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
    expect(result.stdout).toMatch(/^# tests 7$/m);
    expect(result.stdout).toMatch(/^# fail 0$/m);
    expect(result.stdout).toMatch(/^# skipped 0$/m);
  },
  35_000,
);
