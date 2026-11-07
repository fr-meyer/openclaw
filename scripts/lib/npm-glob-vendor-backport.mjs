// CI-only producer. Package/compiler code must never be executed for local preparation.
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, rmSync, existsSync } from "node:fs";
import { builtinModules, createRequire } from "node:module";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  authenticateOriginalNpmArchive,
  readBoundedNpmArchive,
  archiveInventory,
  createCanonicalNpmTarball,
  verifyNpmVendorTarball,
} from "./npm-glob-vendor-archive.mjs";
import {
  NPM_VENDOR_PINS as P,
  NPM_VENDOR_CHANGED_PATHS as CHANGED,
  sha256,
  integrity,
  canonicalInventorySha256,
  validateNpmVendorProof,
} from "./npm-glob-vendor-proof.mjs";

const require = createRequire(import.meta.url);
const fail = (code) => {
  throw new Error(`npm-vendor.${code}`);
};
const utf8 = (b) => {
  const s = new TextDecoder("utf-8", { fatal: true }).decode(b);
  if (!Buffer.from(s).equals(b)) fail("utf8");
  return s;
};
function replaceOnce(source, before, after) {
  if (source.split(before).length !== 2) fail("semantic_hunk");
  return source.replace(before, after);
}
export function applyWalkerCancellationFix(source) {
  const type = source.includes("  onResume(fn: () => unknown) {") ? "unknown" : "any";
  source = replaceOnce(
    source,
    `  onResume(fn: () => ${type}) {\n    if (this.signal?.aborted) return\n`,
    `  onResume(fn: () => ${type}) {\n`,
  );
  if (source.split("if (this.signal?.aborted) cb()").length !== 5) fail("callback_hunks");
  return source.replaceAll(
    "if (this.signal?.aborted) cb()",
    "if (this.signal?.aborted) return cb()",
  );
}
function sourceAsset(name, expected) {
  const b = readFileSync(new URL(`./npm-glob-vendor-sources/${name}`, import.meta.url));
  if (sha256(b) !== expected) fail("source_asset");
  return b;
}
function fixedSource() {
  const source = sourceAsset("glob13-walker.ts.txt", P.sourceSha256);
  const parent = sourceAsset("fix-parent-walker.ts.txt", P.fixParentSha256);
  const fixed = sourceAsset("fix-walker.ts.txt", P.upstreamFixSha256);
  if (applyWalkerCancellationFix(utf8(parent)) !== utf8(fixed)) fail("upstream_fix_equivalence");
  return { original: source, patched: Buffer.from(applyWalkerCancellationFix(utf8(source))) };
}
export function authenticateGlobSourceArchive(bytes, originalFiles) {
  if (
    !Buffer.isBuffer(bytes) ||
    bytes.length > 2 * 1024 * 1024 ||
    integrity(bytes) !== P.globIntegrity
  )
    fail("glob_archive_identity");
  const files = readBoundedNpmArchive(bytes);
  const identity = JSON.parse(utf8(files.get("package.json")?.bytes ?? Buffer.alloc(0)));
  if (identity.name !== "glob" || identity.version !== P.globVersion) fail("glob_manifest");
  for (const changed of CHANGED) {
    const standalone = changed.slice("node_modules/glob/".length);
    if (!files.get(standalone)?.bytes.equals(originalFiles.get(changed)?.bytes ?? Buffer.alloc(0)))
      fail("glob_js_binding");
  }
  for (const mode of ["commonjs", "esm"]) {
    const map = JSON.parse(utf8(files.get(`dist/${mode}/walker.js.map`)?.bytes ?? Buffer.alloc(0)));
    if (
      map.version !== 3 ||
      !Array.isArray(map.sources) ||
      map.sources.length !== 1 ||
      map.sources[0] !== "../../src/walker.ts" ||
      !Array.isArray(map.sourcesContent) ||
      map.sourcesContent.length !== 1 ||
      typeof map.sourcesContent[0] !== "string" ||
      sha256(Buffer.from(map.sourcesContent[0])) !== P.sourceSha256
    )
      fail("glob_source_map");
  }
  if (
    [...originalFiles.keys()].some((p) => p.startsWith("node_modules/glob/") && p.endsWith(".map"))
  )
    fail("npm_maps_unexpected");
  return files;
}
export function createFullFilePatch(original, derived) {
  const out = [];
  for (const name of CHANGED) {
    const old = utf8(original.get(name).bytes),
      now = utf8(derived.get(name).bytes);
    const lines = (s) => {
      const a = s.split("\n");
      if (a.at(-1) === "") a.pop();
      return a;
    };
    const before = lines(old),
      after = lines(now);
    out.push(
      `diff --git a/${name} b/${name}`,
      `--- a/${name}`,
      `+++ b/${name}`,
      `@@ -1,${before.length} +1,${after.length} @@`,
    );
    before.forEach((line, i) => {
      out.push(`-${line}`);
      if (i === before.length - 1 && !old.endsWith("\n")) out.push("\\ No newline at end of file");
    });
    after.forEach((line, i) => {
      out.push(`+${line}`);
      if (i === after.length - 1 && !now.endsWith("\n")) out.push("\\ No newline at end of file");
    });
  }
  const bytes = Buffer.from(out.join("\n") + "\n");
  if (bytes.length > 2 * 1024 * 1024) fail("patch_bound");
  return bytes;
}
function writeNew(file, bytes) {
  writeFileSync(file, bytes, { flag: "wx", mode: 0o600 });
}
export async function buildNpmGlobBackport({ originalTarball, globSourceTarball, outputDir }) {
  if (process.env.GITHUB_ACTIONS !== "true" || process.env.CI !== "true") fail("ci_only");
  // No compiler import, extraction, or source use before both archive identities.
  const original = authenticateOriginalNpmArchive(originalTarball);
  authenticateGlobSourceArchive(globSourceTarball, original);
  const source = fixedSource();
  if (existsSync(outputDir)) fail("output_exists");
  mkdirSync(outputDir, { recursive: false, mode: 0o700 });
  const compiler = require("esbuild");
  if (compiler.version !== P.esbuildVersion) fail("compiler_version");
  const compilerPackage = JSON.parse(readFileSync(require.resolve("esbuild/package.json"), "utf8"));
  if (compilerPackage.name !== "esbuild" || compilerPackage.version !== P.esbuildVersion)
    fail("compiler_package");
  const files = new Map([...original].map(([name, row]) => [name, { ...row }]));
  const maps = [];
  const stage = mkdtempSync(path.join(tmpdir(), "openclaw-glob-compiler-"));
  const compiledInputs = new Map();
  try {
    // The resolver reads only this authenticated original npm graph. No root dependency fallback.
    for (const row of files.values()) {
      const file = path.join(stage, "package", row.path);
      mkdirSync(path.dirname(file), { recursive: true });
      writeFileSync(file, row.bytes, { flag: "wx", mode: row.mode });
    }
    const npmRoot = path.join(stage, "package");
    for (const mode of ["commonjs", "esm"]) {
      const name = `node_modules/glob/dist/${mode}/walker.js`;
      const result = await compiler.transform(utf8(source.patched), {
        loader: "ts",
        format: mode === "commonjs" ? "cjs" : "esm",
        target: "es2022",
        sourcemap: "external",
        sourcesContent: true,
        sourcefile: "glob/src/walker.ts",
        tsconfigRaw: {},
        legalComments: "inline",
      });
      const bytes = Buffer.from(result.code);
      const row = { ...files.get(name), bytes, size: bytes.length, sha256: sha256(bytes) };
      files.set(name, row);
      writeFileSync(path.join(npmRoot, name), bytes);
      maps.push({ path: `${name}.map`, bytes: Buffer.from(result.map) });
    }
    const builtin = new Set(builtinModules.flatMap((n) => [n, `node:${n}`]));
    for (const mode of ["commonjs", "esm"]) {
      const name = `node_modules/glob/dist/${mode}/index.min.js`;
      const result = await compiler.build({
        absWorkingDir: npmRoot,
        entryPoints: [`node_modules/glob/dist/${mode}/index.js`],
        outfile: path.join(npmRoot, name),
        bundle: true,
        minify: true,
        platform: "node",
        format: mode === "commonjs" ? "cjs" : "esm",
        sourcemap: "external",
        sourcesContent: true,
        write: false,
        metafile: true,
        tsconfigRaw: {},
        nodePaths: [],
        logLevel: "silent",
        plugins: [
          {
            name: "authenticated-npm-graph",
            setup(build) {
              build.onResolve({ filter: /.*/ }, async (args) => {
                if (args.pluginData?.authenticatedResolution) return undefined;
                if (builtin.has(args.path)) return { path: args.path, external: true };
                const resolved = await build.resolve(args.path, {
                  resolveDir: args.resolveDir || npmRoot,
                  importer: args.importer,
                  kind: args.kind,
                  pluginData: { authenticatedResolution: true },
                });
                if (resolved.errors.length || resolved.external) fail("compiler_resolution");
                const relative = path.relative(npmRoot, resolved.path).split(path.sep).join("/");
                if (!files.has(relative)) fail("compiler_outside_original");
                return { path: resolved.path };
              });
              build.onLoad({ filter: /.*/ }, (args) => {
                const relative = path.relative(npmRoot, args.path).split(path.sep).join("/");
                const row = files.get(relative);
                if (!row) fail("compiler_input");
                compiledInputs.set(relative, row.sha256);
                const extension = path.extname(relative);
                if (![".js", ".cjs", ".mjs", ".json"].includes(extension))
                  fail("compiler_input_type");
                // Original npm deliberately omits maps. Strip only inert missing-map directives in compiler inputs.
                const contents = utf8(row.bytes).replace(/^\/\/[#@] sourceMappingURL=.*$/gm, "");
                return {
                  contents,
                  loader: extension === ".json" ? "json" : "js",
                  resolveDir: path.dirname(args.path),
                };
              });
            },
          },
        ],
      });
      if (result.warnings.length || result.outputFiles.length !== 2) fail("compiler_output");
      const js = result.outputFiles.find((f) => f.path === path.join(npmRoot, name));
      const map = result.outputFiles.find((f) => f.path === path.join(npmRoot, `${name}.map`));
      if (!js || !map) fail("compiler_output_paths");
      const bytes = Buffer.from(js.contents);
      files.set(name, { ...files.get(name), bytes, size: bytes.length, sha256: sha256(bytes) });
      maps.push({ path: `${name}.map`, bytes: Buffer.from(map.contents) });
    }
  } finally {
    rmSync(stage, { recursive: true, force: true });
  }
  const before = archiveInventory(original),
    after = archiveInventory(files);
  const changed = after.filter((row, i) => JSON.stringify(row) !== JSON.stringify(before[i]));
  if (
    changed.map((r) => r.path).join("\0") !== CHANGED.join("\0") ||
    before.length !== after.length
  )
    fail("delta_inventory");
  const tarball = createCanonicalNpmTarball(files),
    patch = createFullFilePatch(original, files);
  const mapRows = maps
    .sort((a, b) => (a.path < b.path ? -1 : 1))
    .map(({ path, bytes }) => ({ path, size: bytes.length, sha256: sha256(bytes) }));
  if (mapRows.reduce((n, r) => n + r.size, 0) > 8 * 1024 * 1024) fail("maps_bound");
  const proof = {
    schema: "openclaw.npm-glob-vendor-backport.v1",
    npmVersion: P.npmVersion,
    original: {
      integrity: P.originalIntegrity,
      sha256: P.originalSha256,
      inventorySha256: P.originalInventorySha256,
      mapsAbsent: true,
      files: before,
    },
    repair: {
      globVersion: P.globVersion,
      fixCommit: P.fixCommit,
      sourceCommit: P.sourceCommit,
      sourceSha256: P.sourceSha256,
      upstreamFixSha256: P.upstreamFixSha256,
      changedFiles: changed.map((row) => ({
        path: row.path,
        oldSha256: original.get(row.path).sha256,
        newSha256: row.sha256,
        size: row.size,
        mode: row.mode,
      })),
    },
    compiler: { name: "esbuild", version: P.esbuildVersion, integrity: P.esbuildIntegrity },
    derived: {
      integrity: integrity(tarball),
      sha256: sha256(tarball),
      inventorySha256: canonicalInventorySha256(after),
    },
    patch: { filename: "npm@12.2.1.patch", sha256: sha256(patch), size: patch.length },
    maps: mapRows,
  };
  validateNpmVendorProof(proof);
  verifyNpmVendorTarball({ tarball, proof });
  writeNew(path.join(outputDir, "npm-12.2.1-openclaw-glob-backport.tgz"), tarball);
  writeNew(path.join(outputDir, "npm@12.2.1.patch"), patch);
  writeNew(
    path.join(outputDir, "npm-12.2.1.glob-cancellation.proof.json"),
    Buffer.from(JSON.stringify(proof, null, 2) + "\n"),
  );
  const mapDir = path.join(outputDir, "maps");
  mkdirSync(mapDir, { mode: 0o700 });
  for (const row of maps) writeNew(path.join(mapDir, row.path.replaceAll("/", "__")), row.bytes);
  writeNew(
    path.join(outputDir, "derivation.json"),
    Buffer.from(
      JSON.stringify(
        {
          schema: "openclaw.npm-glob-derivation.v1",
          originalGlobIntegrity: P.globIntegrity,
          patchedTypeScriptSha256: sha256(source.patched),
          compilerInputs: [...compiledInputs].sort(),
          originalMapsAbsent: true,
          shippedFilesChanged: 4,
          mapsShipped: false,
        },
        null,
        2,
      ) + "\n",
    ),
  );
  return {
    artifact: {
      name: "npm",
      version: P.npmVersion,
      spec: path.join(outputDir, "npm-12.2.1-openclaw-glob-backport.tgz"),
      integrity: proof.derived.integrity,
    },
    proof,
  };
}
