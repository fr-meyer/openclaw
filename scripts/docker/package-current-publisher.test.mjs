import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const script = fileURLToPath(new URL("./package-current-publisher.mjs", import.meta.url));
const source = fileURLToPath(new URL("./runtime-plugins/mergeguez-pr-lifecycle", import.meta.url));
const commit = "a".repeat(40); // Synthetic package provenance for the staging test.

function run(...args) {
  return spawnSync(process.execPath, [script, ...args], { encoding: "utf8" });
}

void test("staged publisher binds exact source, then rejects changed image bytes", async () => {
  const root = await mkdtemp(join(tmpdir(), "openclaw-publisher-package-"));
  const out = join(root, "staged");
  try {
    const staged = run("--source", source, "--out", out, "--commit", commit);
    assert.equal(staged.status, 0, staged.stderr);
    const manifest = JSON.parse(await readFile(join(out, "publisher-source.json"), "utf8"));
    assert.equal(manifest.sourceCommit, commit);
    assert.equal(manifest.packageVersion, "0.1.1");
    assert.equal(Object.keys(manifest.files).length, 8);
    assert.match(manifest.files["src/runtime-pin-transition.mjs"], /^[a-f0-9]{64}$/);
    assert.equal(run("--verify", out).status, 0);

    const applier = join(out, "mergeguez-pr-lifecycle", "src", "runtime-pin-transition.mjs");
    const originalApplier = await readFile(applier, "utf8");
    await writeFile(applier, `${originalApplier}\n// changed after staging\n`);
    const changedApplier = run("--verify", out);
    assert.notEqual(changedApplier.status, 0);
    assert.match(changedApplier.stderr, /SHA-256 mismatch: src\/runtime-pin-transition\.mjs/);
    await writeFile(applier, originalApplier);
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

void test("invalid source revision fails before producing a package", async () => {
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

void test("9.9 image plan binds the stable tag and candidate publisher bytes", async () => {
  const root = await mkdtemp(join(tmpdir(), "openclaw-v99-publisher-plan-"));
  const packagePath = "scripts/docker/runtime-plugins/mergeguez-pr-lifecycle";
  const git = (...args) =>
    execFileSync("git", args, {
      cwd: root,
      encoding: "utf8",
      env: { ...process.env, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null" },
    }).trim();
  const commitFixture = (message) => {
    git("add", ".");
    git(
      "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
      "commit", "--allow-empty", "-qm", message,
    );
    return git("rev-parse", "HEAD");
  };
  try {
    await mkdir(join(root, "scripts/docker/runtime-plugins"), { recursive: true });
    await cp(source, join(root, packagePath), { recursive: true });
    git("init", "-q");
    const upstream = commitFixture("synthetic stable source");
    git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
      "tag", "-a", "v2026.9.9", "-m", "synthetic stable tag");
    const runtimeBytes = await readFile(join(root, packagePath, "src/runtime.mjs"));
    const runtimeSha256 = (await import("node:crypto"))
      .createHash("sha256").update(runtimeBytes).digest("hex");
    const cut = {
      schema: "openclaw-v99-source-preparation-v1",
      status: "SOURCE_ONLY_UNQUALIFIED",
      upstream: {
        tag: "v2026.9.9", commit: upstream,
        tree: git("rev-parse", `${upstream}^{tree}`),
      },
      publisher: {
        path: packagePath,
        packageName: "@fr-meyer/openclaw-mergeguez-pr-lifecycle",
        packageVersion: "0.1.1",
        runtimeSha256,
      },
    };
    await mkdir(join(root, "custom-patches"));
    const manifestPath = join(root, "custom-patches/manifest.json");
    await writeFile(manifestPath, JSON.stringify(cut));
    const head = commitFixture("synthetic 9.9 source candidate");
    const plan = () => spawnSync(process.execPath, [script, "--plan-image", "true"], {
      cwd: root, encoding: "utf8",
    });
    const accepted = plan();
    assert.equal(accepted.status, 0, accepted.stderr);
    const body = JSON.parse(accepted.stdout);
    assert.equal(body.schema, "openclaw-v99-preparation-image-plan-v1");
    assert.equal(body.sourceCommit, head);
    assert.equal(body.upstreamCommit, upstream);
    assert.equal(body.executed, false);
    assert.equal(body.sourceQualified, false);

    cut.publisher.runtimeSha256 = "0".repeat(64);
    await writeFile(manifestPath, JSON.stringify(cut));
    commitFixture("synthetic false publisher hash");
    const rejected = plan();
    assert.notEqual(rejected.status, 0);
    assert.match(rejected.stderr, /Publisher runtime differs from its source binding/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
