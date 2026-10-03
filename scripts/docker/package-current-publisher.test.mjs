import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const script = fileURLToPath(new URL("./package-current-publisher.mjs", import.meta.url));
const source = fileURLToPath(new URL("./runtime-plugins/mergeguez-pr-lifecycle", import.meta.url));
const commit = "1e197fa258704d70e17a9efd831b2e3ecbc6e6f4";

function run(...args) {
  return spawnSync(process.execPath, [script, ...args], { encoding: "utf8" });
}

test("staged publisher binds exact source, then rejects changed image bytes", async () => {
  const root = await mkdtemp(join(tmpdir(), "openclaw-publisher-package-"));
  const out = join(root, "staged");
  try {
    const staged = run("--source", source, "--out", out, "--commit", commit);
    assert.equal(staged.status, 0, staged.stderr);
    const manifest = JSON.parse(await readFile(join(out, "publisher-source.json"), "utf8"));
    assert.equal(manifest.sourceCommit, commit);
    assert.equal(manifest.packageVersion, "0.1.1");
    assert.equal(Object.keys(manifest.files).length, 7);
    assert.equal(run("--verify", out).status, 0);

    const file = join(out, "mergeguez-pr-lifecycle", "src", "runtime.mjs");
    await writeFile(file, `${await readFile(file, "utf8")}\n// changed after staging\n`);
    const changed = run("--verify", out);
    assert.notEqual(changed.status, 0);
    assert.match(changed.stderr, /SHA-256 mismatch: src\/runtime\.mjs/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("invalid source revision fails before producing a package", async () => {
  const root = await mkdtemp(join(tmpdir(), "openclaw-publisher-commit-"));
  const out = join(root, "staged");
  try {
    const result = run("--source", source, "--out", out, "--commit", "mutable-tag");
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /exact lowercase 40-character Git SHA/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
