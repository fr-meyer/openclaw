import fs from "node:fs";
import path from "node:path";
import { Rolldown } from "tsdown";
import { expect, it } from "vitest";

const root = path.resolve(import.meta.dirname, "../../..");
const graphEntry = "\0session-history-runtime-import-contract";
const runtimePath = path.join(root, "src/config/sessions/session-transcript-worker-runtime.ts");
const admissionWorkerPath = path.join(
  root,
  "src/config/sessions/session-accessor.sqlite-entry-admission-worker.ts",
);
const entryPaths = [
  "src/config/sessions/session-accessor.sqlite-creation-worker.ts",
  "src/config/sessions/session-accessor.sqlite-entry-admission.ts",
  "src/config/sessions/session-accessor.sqlite-page-reclamation.ts",
  "src/config/sessions/session-history-eviction.ts",
  "src/gateway/session-transcript-preview.ts",
  "src/gateway/session-transcript-title-reader.ts",
].map((file) => path.join(root, file));

/** Bundle actual import edges in memory; unrelated dependencies are external and output never runs. */
async function bundleRuntimeImportContract() {
  const sources = new Set([...entryPaths, runtimePath, admissionWorkerPath]);
  const warnings: { code: string | undefined; message: string }[] = [];
  const bundle = await Rolldown.rolldown({
    input: graphEntry,
    platform: "node",
    checks: { ineffectiveDynamicImport: true },
    onwarn(warning) {
      warnings.push({ code: warning.code, message: warning.message });
    },
    plugins: [
      {
        name: "session-history-runtime-import-contract",
        resolveId(specifier, importer) {
          if (specifier === graphEntry || entryPaths.includes(specifier)) {
            return specifier;
          }
          if (importer && specifier.startsWith(".")) {
            const candidate = path
              .resolve(path.dirname(importer), specifier)
              .replace(/\.js$/, ".ts");
            if (sources.has(candidate)) {
              return candidate;
            }
          }
          return { id: specifier, external: true };
        },
        load(id) {
          if (id === graphEntry) {
            return entryPaths.map((file) => `export * from ${JSON.stringify(file)};`).join("\n");
          }
          return sources.has(id) ? fs.readFileSync(id, "utf8") : undefined;
        },
      },
    ],
  });
  try {
    const result = await bundle.generate({ format: "esm" });
    return { warnings, chunks: result.output.filter((output) => output.type === "chunk") };
  } finally {
    await bundle.close();
  }
}

it("bundles the source runtime callers without an ineffective dynamic owner import", async () => {
  const { warnings } = await bundleRuntimeImportContract();
  expect(warnings.filter((warning) => warning.code === "INEFFECTIVE_DYNAMIC_IMPORT")).toEqual([]);
});

it("keeps durable admission worker reading behind its own dynamic execution chunk", async () => {
  const { warnings, chunks } = await bundleRuntimeImportContract();
  expect(warnings.filter((warning) => warning.code === "INEFFECTIVE_DYNAMIC_IMPORT")).toEqual([]);
  const admission = chunks.find((chunk) => Object.hasOwn(chunk.modules, admissionWorkerPath));
  expect(admission).toBeDefined();
  expect(admission?.isEntry).toBe(false);
  expect(admission?.isDynamicEntry).toBe(true);
  expect(chunks.find((chunk) => chunk.isEntry)?.dynamicImports).toContain(admission?.fileName);
});
