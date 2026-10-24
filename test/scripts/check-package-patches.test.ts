// Check Package Patches tests cover check package patches script behavior.
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { collectPackagePatchViolations } from "../../scripts/check-package-patches.mts";
import { cleanupTempDirs, makeTempDir as makeTempRepoRoot } from "../helpers/temp-dir.js";
import { createNestedGitEnv, writeJsonFile } from "../helpers/temp-repo.js";

const tempDirs: string[] = [];
const toolPatch = "scripts/actionlint-cache-mode.patch";
const toolConsumer = "scripts/check-workflows.mts";

function git(cwd: string, args: string[]) {
  execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    env: createNestedGitEnv(),
  });
}

function makeRepo() {
  const dir = makeTempRepoRoot(tempDirs, "openclaw-package-patches-");
  git(dir, ["init", "-q", "--initial-branch=main"]);
  writeJsonFile(path.join(dir, "package.json"), { name: "fixture" });
  writeFileSync(path.join(dir, "pnpm-workspace.yaml"), "packages:\n  - .\n", "utf8");
  writeFileSync(path.join(dir, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n", "utf8");
  git(dir, ["add", "package.json", "pnpm-workspace.yaml", "pnpm-lock.yaml"]);
  return dir;
}

function addReviewedToolPatch(dir: string) {
  mkdirSync(path.join(dir, "scripts"));
  for (const file of [toolPatch, toolConsumer]) {
    writeFileSync(path.join(dir, file), readFileSync(file));
  }
  git(dir, ["add", toolPatch, toolConsumer]);
}

afterEach(() => {
  cleanupTempDirs(tempDirs);
});

describe("check-package-patches", () => {
  it("allows the exact reviewed non-pnpm tool patch with its tracked consumer", () => {
    const dir = makeRepo();
    addReviewedToolPatch(dir);
    expect(collectPackagePatchViolations(dir)).toEqual([]);
  });

  it.each(["patch", "consumer", "missing consumer", "untracked consumer", "directory consumer"])(
    "rejects a tool approval with changed %s",
    (changed) => {
      const dir = makeRepo();
      addReviewedToolPatch(dir);
      if (changed === "missing consumer") {
        rmSync(path.join(dir, toolConsumer));
      } else if (changed === "untracked consumer") {
        git(dir, ["rm", "--cached", toolConsumer]);
      } else if (changed === "directory consumer") {
        rmSync(path.join(dir, toolConsumer));
        mkdirSync(path.join(dir, toolConsumer));
      } else {
        const target = path.join(dir, changed === "patch" ? toolPatch : toolConsumer);
        writeFileSync(target, `${readFileSync(target, "utf8")}\n`);
      }
      expect(collectPackagePatchViolations(dir)).toEqual([
        {
          file: toolPatch,
          kind: "toolSourcePatchApproval",
          detail: "tool source patch or tracked consumer differs from the exact reviewed approval",
        },
      ]);
    },
  );

  it("rejects the exact tool patch bytes at any unowned path", () => {
    const dir = makeRepo();
    addReviewedToolPatch(dir);
    const otherPatch = "scripts/other-tool.patch";
    writeFileSync(path.join(dir, otherPatch), readFileSync(toolPatch));
    git(dir, ["add", otherPatch]);
    expect(collectPackagePatchViolations(dir)).toEqual([
      { file: otherPatch, kind: "patchFile", detail: "new package patch file" },
    ]);
  });

  it.each<{ file: string; patchReference: string | { hash: string; path: string } }>([
    { file: "pnpm-workspace.yaml", patchReference: toolPatch },
    { file: "pnpm-workspace.yaml", patchReference: `./${toolPatch}` },
    { file: "pnpm-lock.yaml", patchReference: toolPatch },
    { file: "pnpm-lock.yaml", patchReference: `./${toolPatch}` },
    { file: "pnpm-lock.yaml", patchReference: { hash: "fixture-hash", path: `./${toolPatch}` } },
  ])(
    "rejects pnpm reuse of the tool patch in $file: $patchReference",
    ({ file, patchReference }) => {
      const dir = makeRepo();
      addReviewedToolPatch(dir);
      writeFileSync(
        path.join(dir, file),
        `patchedDependencies:\n  'vitest@5.0.1': ${JSON.stringify(patchReference)}\n`,
      );
      expect(collectPackagePatchViolations(dir)).toEqual([
        {
          file,
          kind: "toolSourcePatchPnpmReference",
          detail: `vitest@5.0.1 -> ${typeof patchReference === "string" ? patchReference : patchReference.path}`,
        },
      ]);
    },
  );

  it("rejects package-local declarations of the approved tool patch", () => {
    const dir = makeRepo();
    addReviewedToolPatch(dir);
    writeJsonFile(path.join(dir, "package.json"), {
      name: "fixture",
      pnpm: { patchedDependencies: { "actionlint@1.0.0": toolPatch } },
    });
    expect(collectPackagePatchViolations(dir)).toEqual([
      {
        file: "package.json",
        kind: "packageJsonPatchedDependency",
        detail: `actionlint@1.0.0 -> ${toolPatch}`,
      },
    ]);
  });

  it("allows approved pnpm patches together", () => {
    const approvedPatches = [
      ["@a2ui/lit@0.11.0", "patches/@a2ui__lit@0.11.0.patch"],
      ["@a2ui/web_core@0.11.0", "patches/@a2ui__web_core@0.11.0.patch"],
      ["@discord/embedded-app-sdk@2.5.0", "patches/@discord__embedded-app-sdk@2.5.0.patch"],
      ["zod@4.6.6", "patches/zod@4.6.6.patch"],
      ["@awesome.me/webawesome@3.13.0", "patches/@awesome.me__webawesome@3.13.0.patch"],
      ["baileys@7.0.0-rc12", "patches/baileys@7.0.0-rc12.patch"],
      ["baileys@7.0.0-rc13", "patches/baileys@7.0.0-rc13.patch"],
      ["baileys@7.0.0-rc14", "patches/baileys@7.0.0-rc14.patch"],
      ["vitest@5.0.1", "patches/vitest@5.0.1.patch"],
      ["matrix-js-sdk@42.4.0", "patches/matrix-js-sdk@42.4.0.patch"],
    ] as const;
    const dir = makeRepo();
    mkdirSync(path.join(dir, "patches"), { recursive: true });
    writeFileSync(
      path.join(dir, "pnpm-workspace.yaml"),
      `packages:
  - .
patchedDependencies:
${approvedPatches.map(([specifier, patchPath]) => `  "${specifier}": "${patchPath}"`).join("\n")}
`,
      "utf8",
    );
    writeFileSync(
      path.join(dir, "pnpm-lock.yaml"),
      `lockfileVersion: '9.0'
patchedDependencies:
${approvedPatches.map(([specifier]) => `  "${specifier}": a9aea1790d2c65b1ae543c77faca4119bbfb91ee3b6ca6c38d1cad4f5702ada2`).join("\n")}
`,
      "utf8",
    );
    for (const [, patchPath] of approvedPatches) {
      writeFileSync(path.join(dir, patchPath), "diff\n", "utf8");
    }
    git(dir, ["add", "pnpm-workspace.yaml", "pnpm-lock.yaml", "patches"]);

    expect(collectPackagePatchViolations(dir)).toEqual([]);
  });

  it.each([
    ["@a2ui/web_core@0.99.0", "patches/@a2ui__web_core@0.99.0.patch"],
    ["@discord/embedded-app-sdk@2.5.0", "patches/@discord__embedded-app-sdk@2.5.0-other.patch"],
    ["zod@4.6.7", "patches/zod@4.6.7.patch"],
    ["zod@4.6.6", "patches/zod@4.6.6-unreviewed.patch"],
    ["left-pad@1.3.0", "patches/left-pad@1.3.0.patch"],
    ["matrix-js-sdk@42.4.1", "patches/matrix-js-sdk@42.4.1.patch"],
    ["matrix-js-sdk@42.4.0", "patches/matrix-js-sdk@42.4.0-other.patch"],
  ])("rejects unapproved workspace patch %s -> %s", (specifier, patchPath) => {
    const dir = makeRepo();
    mkdirSync(path.join(dir, "patches"), { recursive: true });
    mkdirSync(path.join(dir, "fixtures"), { recursive: true });
    writeFileSync(
      path.join(dir, "pnpm-workspace.yaml"),
      `packages:
  - .
patchedDependencies:
  "${specifier}": "${patchPath}"
`,
      "utf8",
    );
    writeFileSync(path.join(dir, patchPath), "diff\n", "utf8");
    writeFileSync(path.join(dir, "fixtures", "fixture.patch"), "diff\n", "utf8");
    git(dir, ["add", "pnpm-workspace.yaml", "patches", "fixtures"]);

    expect(collectPackagePatchViolations(dir)).toEqual([
      {
        file: "pnpm-workspace.yaml",
        kind: "patchedDependency",
        detail: `${specifier} -> ${patchPath}`,
      },
      {
        file: "fixtures/fixture.patch",
        kind: "patchFile",
        detail: "new package patch file",
      },
      {
        file: patchPath,
        kind: "patchFile",
        detail: "new package patch file",
      },
    ]);
  });

  it("allows deleted legacy patch files during the commit that removes them", () => {
    const dir = makeRepo();
    mkdirSync(path.join(dir, "patches"), { recursive: true });
    writeFileSync(
      path.join(dir, "patches", "@agentclientprotocol__claude-agent-acp@0.33.1.patch"),
      "diff\n",
      "utf8",
    );
    git(dir, ["add", "patches"]);
    rmSync(path.join(dir, "patches", "@agentclientprotocol__claude-agent-acp@0.33.1.patch"));

    expect(collectPackagePatchViolations(dir)).toEqual([]);
  });

  it.each([false, true])(
    "rejects lockfile and package-local patches with toolchain metadata %s",
    (withToolchain) => {
      const dir = makeRepo();
      writeJsonFile(path.join(dir, "package.json"), {
        name: "fixture",
        pnpm: {
          patchedDependencies: {
            "nested@1.0.0": "patches/nested.patch",
          },
        },
      });
      writeFileSync(
        path.join(dir, "pnpm-lock.yaml"),
        `${withToolchain ? "---\nlockfileVersion: '9.0'\npatchedDependencies:\n  toolchain@1.0.0: toolhash\n---\n" : ""}lockfileVersion: '9.0'
patchedDependencies:
  hidden@1.0.0: abc123
`,
        "utf8",
      );
      git(dir, ["add", "package.json", "pnpm-lock.yaml"]);

      expect(collectPackagePatchViolations(dir)).toEqual([
        ...(withToolchain
          ? [
              {
                file: "pnpm-lock.yaml",
                kind: "patchedDependency",
                detail: "toolchain@1.0.0 -> toolhash",
              },
            ]
          : []),
        {
          file: "pnpm-lock.yaml",
          kind: "patchedDependency",
          detail: "hidden@1.0.0 -> abc123",
        },
        {
          file: "package.json",
          kind: "packageJsonPatchedDependency",
          detail: "nested@1.0.0 -> patches/nested.patch",
        },
      ]);
    },
  );

  it("skips tracked package manifests deleted in the worktree", () => {
    const dir = makeRepo();
    mkdirSync(path.join(dir, "packages", "deleted"), { recursive: true });
    writeJsonFile(path.join(dir, "packages", "deleted", "package.json"), {
      name: "deleted",
      pnpm: {
        patchedDependencies: {
          "deleted-only@1.0.0": "patches/deleted-only.patch",
        },
      },
    });
    git(dir, ["add", "packages/deleted/package.json"]);
    rmSync(path.join(dir, "packages", "deleted", "package.json"));

    expect(collectPackagePatchViolations(dir)).toEqual([]);
  });
});
