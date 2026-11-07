#!/usr/bin/env node
// Explicit CI producer; never fetches archives or runs npm/package lifecycle commands.
import { readFileSync } from "node:fs";
import path from "node:path";
import { buildNpmGlobBackport } from "./lib/npm-glob-vendor-backport.mjs";
const args = process.argv.slice(2);
const expected = ["--original-npm", "--original-glob", "--output-dir"];
if (args.length !== 6 || expected.some((key, i) => args[i * 2] !== key) || args.some((a) => !a))
  throw new Error("npm-vendor.arguments");
const result = await buildNpmGlobBackport({
  originalTarball: readFileSync(path.resolve(args[1])),
  globSourceTarball: readFileSync(path.resolve(args[3])),
  outputDir: path.resolve(args[5]),
});
console.log(
  JSON.stringify({
    schema: result.proof.schema,
    npmVersion: result.proof.npmVersion,
    derivedSha256: result.proof.derived.sha256,
    inventorySha256: result.proof.derived.inventorySha256,
    changedFiles: result.proof.repair.changedFiles.map((row) => row.path),
  }),
);
