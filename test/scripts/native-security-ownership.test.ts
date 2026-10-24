// Metadata ownership only: actual native execution is proved by the adapter/runner tests.
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  NATIVE_SECURITY_ADAPTER,
  NATIVE_RUNNER_PROOF,
  NATIVE_SECURITY_TEST_FILES,
  OPTIONAL_NATIVE_SECURITY_TEST_FILES,
  nativeSecurityAdapterForPath,
} from "../../scripts/fork-release/native_tests.mjs";
import { createChangedNodeTestShards } from "../../scripts/lib/ci-changed-node-test-plan.mts";
import {
  ciTestShardRequiresBun,
  resolveCiTestRuntimeSelections,
} from "../../scripts/lib/ci-test-runtime.mts";
import {
  buildVitestRunPlans,
  resolveChangedTestTargetPlan,
} from "../../scripts/test-projects.test-support.mts";
import * as ownership from "../vitest-projects-config.test-support.js";
import { expandNativeSecurityTestOwnership } from "../vitest-projects-config.test-support.js";
import { fullSuiteVitestShards } from "../vitest/vitest.test-shards.mjs";
import { toolingIsolatedTestFiles } from "../vitest/vitest.tooling-isolated-paths.mjs";

const ROOT = fileURLToPath(new URL("../../", import.meta.url));
const ISOLATED = "test/vitest/vitest.tooling-isolated.config.ts";
const DOCKER_STANDALONE = [
  "scripts/docker/package-current-publisher.test.mjs",
  "scripts/docker/runtime-plugins/mergeguez-pr-lifecycle/test/current-parity.test.mjs",
  "scripts/docker/runtime-plugins/mergeguez-pr-lifecycle/test/runtime-pin-transition.test.mjs",
];

describe("native security suite ownership", () => {
  it("registers one actual isolated adapter in the full suite", () => {
    expect(
      toolingIsolatedTestFiles.filter((file) => file === NATIVE_SECURITY_ADAPTER),
    ).toHaveLength(1);
    expect(
      fullSuiteVitestShards.flatMap((shard) => shard.projects).filter((file) => file === ISOLATED),
    ).toHaveLength(1);
    expect(buildVitestRunPlans([NATIVE_SECURITY_ADAPTER], ROOT)).toMatchObject([
      { config: ISOLATED, includePatterns: [NATIVE_SECURITY_ADAPTER] },
    ]);
  });

  it.each([NATIVE_SECURITY_ADAPTER, NATIVE_RUNNER_PROOF])(
    "keeps native subprocess owner %s on Node under every runtime policy",
    (file) => {
      expect(toolingIsolatedTestFiles.filter((owned) => owned === file)).toHaveLength(1);
      expect(buildVitestRunPlans([file], ROOT)).toMatchObject([
        { config: ISOLATED, includePatterns: [file] },
      ]);
      for (const policy of ["node", "bun-compatible", "dual"] as const) {
        for (const selection of [
          { targets: [file] },
          { configs: [ISOLATED], includePatterns: [file] },
        ]) {
          expect(resolveCiTestRuntimeSelections(selection, policy, ROOT)).toEqual([
            { runtime: "node" },
          ]);
          expect(ciTestShardRequiresBun(selection, policy, ROOT)).toBe(false);
        }
      }
    },
  );

  it("retains an executable Node owner or fails closed for a deleted native member through the outer planner", () => {
    const root = mkdtempSync(path.join(tmpdir(), "native-deleted-owner-"));
    try {
      mkdirSync(path.join(root, "test/scripts"), { recursive: true });
      writeFileSync(path.join(root, "package.json"), '{"type":"module"}\n');
      writeFileSync(
        path.join(root, NATIVE_SECURITY_ADAPTER),
        "// Synthetic metadata-only adapter.\n",
      );
      const reasons: string[] = [];
      const shards = createChangedNodeTestShards([NATIVE_SECURITY_TEST_FILES[0]], {
        cwd: root,
        runnerBackend: "github",
        onFallback: (reason) => reasons.push(reason),
      });
      // This tiny checkout may lack broader canonical metadata, but never admit an empty success.
      expect(shards).not.toEqual([]);
      if (shards === null) {
        expect(reasons.length).toBeGreaterThan(0);
        expect(reasons).not.toContain("missing native security test owner");
        return;
      }
      expect(shards.length).toBeGreaterThan(0);
      expect(
        shards.some(
          (shard) =>
            shard.targets?.includes(NATIVE_SECURITY_ADAPTER) ||
            shard.includePatterns?.includes(NATIVE_SECURITY_ADAPTER) ||
            shard.groups?.some(
              (group) =>
                group.configs.includes(ISOLATED) &&
                (!group.includePatterns || group.includePatterns.includes(NATIVE_SECURITY_ADAPTER)),
            ),
        ),
      ).toBe(true);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("fails closed through the outer planner when the native adapter was deleted", () => {
    const root = mkdtempSync(path.join(tmpdir(), "native-deleted-adapter-"));
    try {
      const reasons: string[] = [];
      expect(
        createChangedNodeTestShards([NATIVE_SECURITY_ADAPTER], {
          cwd: root,
          runnerBackend: "github",
          onFallback: (reason) => reasons.push(reason),
        }),
      ).toBeNull();
      expect(reasons).toContain("missing native security test owner");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("does not credit native coverage when the actual adapter was not discovered", () => {
    const ordinary = ["test/scripts/example.test.ts"];
    expect(expandNativeSecurityTestOwnership(ordinary)).toEqual(ordinary);
    expect(expandNativeSecurityTestOwnership(ordinary)).not.toContain(
      NATIVE_SECURITY_TEST_FILES[0],
    );
  });

  it("credits each declared native member through the discovered adapter exactly once", () => {
    const files = [NATIVE_SECURITY_ADAPTER];
    const expanded = expandNativeSecurityTestOwnership(files);
    expect(files).toEqual([NATIVE_SECURITY_ADAPTER]);
    expect(new Set(NATIVE_SECURITY_TEST_FILES).size).toBe(NATIVE_SECURITY_TEST_FILES.length);
    for (const file of NATIVE_SECURITY_TEST_FILES) {
      expect(
        expanded.filter((owned) => owned === file),
        file,
      ).toHaveLength(1);
    }
    // Do not erase a direct duplicate; the aggregate auditor must still reject it.
    const [member] = NATIVE_SECURITY_TEST_FILES;
    expect(
      expandNativeSecurityTestOwnership([NATIVE_SECURITY_ADAPTER, member]).filter(
        (file) => file === member,
      ),
    ).toHaveLength(2);
  });

  it("retains legacy MCP ownership without taking existing Docker native owners", () => {
    expect(OPTIONAL_NATIVE_SECURITY_TEST_FILES).toEqual([
      "test/mcp-nowistay-schema-compatibility.test.mjs",
      "test/mcp-nowistay-sdk-regression.test.mjs",
    ]);
    const expanded = expandNativeSecurityTestOwnership([NATIVE_SECURITY_ADAPTER]);
    const standalone =
      "standaloneNodeTestFiles" in ownership
        ? (ownership.standaloneNodeTestFiles as readonly string[])
        : [];
    for (const file of OPTIONAL_NATIVE_SECURITY_TEST_FILES) {
      expect(expanded).toContain(file);
      expect(standalone).not.toContain(file);
    }
    for (const file of DOCKER_STANDALONE) {
      expect(expanded).not.toContain(file);
      if ("standaloneNodeTestFiles" in ownership) {
        expect(standalone).toContain(file);
      }
    }
  });

  it.each(NATIVE_SECURITY_TEST_FILES)(
    "maps changed native member %s to the executable adapter",
    (file) => {
      expect(resolveChangedTestTargetPlan([file], { cwd: ROOT })).toMatchObject({
        mode: "targets",
        targets: [NATIVE_SECURITY_ADAPTER],
      });
    },
  );

  it("retains a removed declared member and adapter as nonempty changed owners", () => {
    const missingRoot = path.join(ROOT, ".native-ownership-missing-fixture");
    for (const file of [NATIVE_SECURITY_TEST_FILES[0], NATIVE_SECURITY_ADAPTER]) {
      expect(resolveChangedTestTargetPlan([file], { cwd: missingRoot })).toMatchObject({
        mode: "targets",
        targets: [NATIVE_SECURITY_ADAPTER],
      });
    }
  });

  it("maps shared runner changes but refuses an undeclared native file", () => {
    expect(nativeSecurityAdapterForPath("scripts/fork-release/native_tests.mjs")).toBe(
      NATIVE_SECURITY_ADAPTER,
    );
    expect(
      resolveChangedTestTargetPlan(["scripts/fork-release/native_tests.mjs"], { cwd: ROOT }),
    ).toMatchObject({
      mode: "targets",
      targets: [NATIVE_SECURITY_ADAPTER, NATIVE_RUNNER_PROOF],
    });
    expect(nativeSecurityAdapterForPath("test/unregistered-native.test.mjs")).toBeNull();
  });
});
