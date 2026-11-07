import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { resolvePnpmLockOverridePlan } from "../../scripts/generate-npm-package-lock.mts";

const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("npm lock peer override policy", () => {
  const lock = {
    packages: {
      "@agentclientprotocol/sdk@2.0.1": {
        peerDependencies: { zod: "^3.25.76 || ^4.0.0" },
      },
      "runtime-parent@1.0.0": {},
      "unaudited-peer@1.0.0": { peerDependencies: { zod: "^4.0.0" } },
      "zod@4.6.6": {},
      "zod@4.6.7": {},
    },
    snapshots: {
      "@agentclientprotocol/sdk@2.0.1(zod@4.6.7)": { dependencies: { zod: "4.6.7" } },
      "runtime-parent@1.0.0": { dependencies: { zod: "4.6.6" } },
      "unaudited-peer@1.0.0(zod@4.6.6)": { dependencies: { zod: "4.6.6" } },
      "zod@4.6.6": {},
      "zod@4.6.7": {},
    },
  };

  it("does not turn a resolved peer edge into an npm runtime pin", () => {
    const plan = resolvePnpmLockOverridePlan(lock);
    expect(plan.scopedVersionOverrides["@agentclientprotocol/sdk@2.0.1"]).toBeUndefined();
    expect(plan.scopedVersionOverrides["runtime-parent@1.0.0"]).toEqual({ zod: "4.6.6" });
    expect(plan.scopedVersionOverrides["unaudited-peer@1.0.0"]).toEqual({ zod: "4.6.6" });
  });

  it("retains the declared peer range beside a separately pinned runtime edge", () => {
    const root = mkdtempSync(path.join(tmpdir(), "openclaw-npm-peer-policy-"));
    tempDirs.push(root);
    writeFileSync(path.join(root, "pnpm-lock.yaml"), JSON.stringify(lock));
    writeFileSync(
      path.join(root, "pnpm-workspace.yaml"),
      JSON.stringify({
        overrides: { "@agentclientprotocol/sdk@2.0.1>zod": "^3.25.76 || ^4.0.0" },
      }),
    );
    const script = `import { readNpmLockOverrides } from ${JSON.stringify(new URL("../../scripts/generate-npm-package-lock.mts", import.meta.url).href)};
      console.log(JSON.stringify(readNpmLockOverrides(
        { dependencies: { "@agentclientprotocol/sdk": "2.0.1", "runtime-parent": "1.0.0" } },
        ${JSON.stringify(root)}
      )));`;
    const result = spawnSync(
      process.execPath,
      ["--import", import.meta.resolve("tsx"), "--input-type=module", "-e", script],
      { encoding: "utf8", env: { ...process.env, OPENCLAW_NPM_PACKAGE_LOCK_REPO_ROOT: root } },
    );
    expect(result.status, result.stderr).toBe(0);
    const overrides = JSON.parse(result.stdout);
    expect(overrides["@agentclientprotocol/sdk@2.0.1"].zod).toBe("^3.25.76 || ^4.0.0");
    expect(overrides["runtime-parent@1.0.0"].zod).toBe("4.6.6");
  });
});
