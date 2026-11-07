import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { expect, it } from "vitest";
import {
  recordUpdateCompatibilityRelease,
  writeUpdateCompatibilityChunks,
} from "../../scripts/lib/update-compat-chunks.mts";
import { createScriptTestHarness } from "./test-helpers.js";
import {
  previousReleaseInventory,
  writeUpdateCompatibilityBuildFixture,
} from "./update-compat-chunks.test-support.js";

const { createTempDir } = createScriptTestHarness();
const chunk = previousReleaseInventory.releases[0]!.chunks.find((entry) =>
  /-[A-Za-z0-9_-]{8}\.m?js$/.test(entry.path),
)!;
const namedExport = {
  kind: "named export",
  source: 'export { helper as NAME } from "external-package";',
};
const namespaceImport = {
  kind: "namespace import",
  source: 'import * as NAME from "external-package"; export { NAME };',
};

it.each([
  'import { safePath as helper } from "@openclaw/fs-safe/path"; export { helper };',
  'import helper from "external-package"; export { helper };',
  'export { safePath as helper } from "@openclaw/fs-safe/path";',
  'export * as helper from "external-package";',
  'import * as helper from "external-package"; export { helper };',
])("keeps published updater bridges usable beside %s", async (external) => {
  const root = createTempDir("update-compat-external-");
  fs.writeFileSync(path.join(root, "package.json"), '{"type":"module"}');
  writeUpdateCompatibilityBuildFixture(root);
  fs.writeFileSync(
    path.join(root, "dist/unrelated-worker.mjs"),
    `//#region ${chunk.exports[0]!.origin.module}\n${external}\n`,
  );
  writeUpdateCompatibilityChunks({
    distDir: path.join(root, "dist"),
    sourceDir: root,
    inventory: previousReleaseInventory,
  });
  const legacy = await import(pathToFileURL(path.join(root, "dist", chunk.path)).href);
  for (const { exported, origin } of chunk.exports) {
    expect(await legacy[exported]()).toBe(origin.symbol);
  }
});

it.each([namedExport, namespaceImport])(
  "refuses a required updater implementation replaced with an external $kind",
  ({ source: template }) => {
    const root = createTempDir("update-compat-required-external-");
    writeUpdateCompatibilityBuildFixture(root);
    const origin = chunk.exports[0]!.origin;
    const source = path.join(root, origin.module);
    fs.mkdirSync(path.dirname(source), { recursive: true });
    fs.writeFileSync(source, `${template.replaceAll("NAME", origin.symbol)}\n`);
    expect(() =>
      writeUpdateCompatibilityChunks({
        distDir: path.join(root, "dist"),
        sourceDir: root,
        inventory: previousReleaseInventory,
      }),
    ).toThrow("Cannot resolve current source binding");
    expect(fs.existsSync(path.join(root, "dist", chunk.path))).toBe(false);
  },
);

it.each([
  namedExport,
  { kind: "namespace export", source: 'export * as NAME from "external-package";' },
])("refuses to omit a published external $kind", ({ source }) => {
  const root = createTempDir("update-compat-published-external-");
  fs.mkdirSync(path.join(root, "dist"));
  fs.writeFileSync(
    path.join(root, "package.json"),
    JSON.stringify({ name: "openclaw", version: "2026.9.1" }),
  );
  fs.writeFileSync(
    path.join(root, "dist/build-info.json"),
    JSON.stringify({ version: "2026.9.1", buildId: "fixture", commit: "0".repeat(40) }),
  );
  fs.writeFileSync(
    path.join(root, "dist/command.mjs"),
    '//#region src/cli/update-cli/update-command-service-command.ts\nexport async function restart() { return await import("./surface-abcdefgh.mjs"); }\n',
  );
  fs.writeFileSync(
    path.join(root, "dist/surface-abcdefgh.mjs"),
    `//#region src/infra/value.ts\nexport const owned = 1;\n${source.replaceAll("NAME", "external")}\n`,
  );
  expect(() =>
    recordUpdateCompatibilityRelease({
      packageDir: root,
      integrity: `sha512-${Buffer.alloc(64).toString("base64")}`,
    }),
  ).toThrow("Cannot trace surface-abcdefgh.mjs export external to its release source");
});

it("bridges Rolldown module labels without trusting a same-named export in a string", async () => {
  const root = createTempDir("update-compat-module-labels-");
  fs.writeFileSync(path.join(root, "package.json"), '{"type":"module"}');
  writeUpdateCompatibilityBuildFixture(root);
  const distDir = path.join(root, "dist");
  for (const file of fs.readdirSync(distDir)) {
    if (!file.startsWith("candidate-")) {
      continue;
    }
    const target = path.join(distDir, file);
    fs.writeFileSync(target, fs.readFileSync(target, "utf8").replaceAll("//#region ", "// "));
  }
  const origin = chunk.exports[0]!.origin;
  fs.writeFileSync(
    path.join(distDir, "unrelated-worker.mjs"),
    "// src/infra/unrelated.ts\nconst example = `\n// " +
      origin.module +
      "\n`;\nfunction " +
      origin.symbol +
      '() { return "wrong owner"; }\nexport { ' +
      origin.symbol +
      " };\n",
  );
  writeUpdateCompatibilityChunks({
    distDir,
    sourceDir: root,
    inventory: previousReleaseInventory,
  });
  const legacy = await import(pathToFileURL(path.join(distDir, chunk.path)).href);
  for (const { exported, origin: expected } of chunk.exports) {
    expect(await legacy[exported]()).toBe(expected.symbol);
  }
});

it("records updater imports and export origins from Rolldown module labels", () => {
  const root = createTempDir("update-compat-record-labels-");
  const distDir = path.join(root, "dist");
  fs.mkdirSync(distDir, { recursive: true });
  fs.writeFileSync(path.join(root, "package.json"), '{"name":"openclaw","version":"2026.10.1"}');
  fs.writeFileSync(
    path.join(distDir, "build-info.json"),
    JSON.stringify({ version: "2026.10.1", buildId: "fixture", commit: "0".repeat(40) }),
  );
  fs.writeFileSync(
    path.join(distDir, "command.mjs"),
    '// src/cli/update-cli/update-command-service-command.ts\nexport async function restart() { return (await import("./surface-abcdefgh.mjs")).owned(); }\n',
  );
  fs.writeFileSync(
    path.join(distDir, "surface-abcdefgh.mjs"),
    '// src/daemon/inspect.ts\nexport function owned() { return "owned"; }\n',
  );
  const recorded = recordUpdateCompatibilityRelease({
    packageDir: root,
    integrity: "sha512-Zml4dHVyZQ==",
  });
  expect(recorded.chunks).toEqual([
    {
      path: "surface-abcdefgh.mjs",
      imports: [
        {
          importer: "command.mjs",
          owner: "src/cli/update-cli/update-command-service-command.ts",
          exports: ["owned"],
        },
      ],
      exports: [
        { exported: "owned", origin: { module: "src/daemon/inspect.ts", symbol: "owned" } },
      ],
    },
  ]);
});
