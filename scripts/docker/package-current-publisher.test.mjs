import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
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

void test("image plan rejects a successor hash attributed to different committed bytes", async () => {
  const root = await mkdtemp(join(tmpdir(), "openclaw-publisher-source-binding-"));
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
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.invalid",
      "commit",
      "--allow-empty",
      "-qm",
      message,
    );
    return git("rev-parse", "HEAD");
  };
  try {
    await mkdir(join(root, "scripts/docker/runtime-plugins"), { recursive: true });
    await cp(source, join(root, packagePath), { recursive: true });
    const runtimePath = join(root, packagePath, "src/runtime.mjs");
    const actualRuntime = await readFile(runtimePath);
    await writeFile(
      runtimePath,
      Buffer.concat([actualRuntime, Buffer.from("\n// synthetic checkpoint\n")]),
    );
    git("init", "-q");
    const upstream = commitFixture("synthetic upstream");
    const orderedCommits = Array.from({ length: 14 }, (_, index) => ({
      commit: commitFixture(`synthetic checkpoint ${index}`),
    }));
    const checkpoint = orderedCommits.at(-1).commit;
    await writeFile(runtimePath, actualRuntime);
    const successor = commitFixture("synthetic publisher successor");
    const runtimeSha256 = (await import("node:crypto"))
      .createHash("sha256")
      .update(actualRuntime)
      .digest("hex");
    const cut = {
      schema: "openclaw-v98-local-cut-manifest-v2",
      upstream: { commit: upstream, tree: git("rev-parse", `${upstream}^{tree}`) },
      orderedCommits,
      qualifiedSourceCheckpoint: {
        commit: checkpoint,
        tree: git("rev-parse", `${checkpoint}^{tree}`),
        publisherPackageVersion: "0.1.1",
      },
      publisherSourceSuccessor: {
        status: "reviewed-source-runtime-unqualified",
        baseCheckpoint: checkpoint,
        sourceCommit: successor,
        tree: git("rev-parse", `${successor}^{tree}`),
        publisherPackagePath: packagePath,
        publisherPackageVersion: "0.1.1",
        publisherRuntimeSha256: runtimeSha256,
      },
    };
    await mkdir(join(root, "custom-patches"));
    const manifestPath = join(root, "custom-patches/manifest.json");
    await writeFile(manifestPath, JSON.stringify(cut));
    const head = commitFixture("synthetic final composition");
    const plan = () =>
      spawnSync(process.execPath, [script, "--plan-image", "true"], {
        cwd: root,
        encoding: "utf8",
      });
    const accepted = plan();
    assert.equal(accepted.status, 0, accepted.stderr);
    assert.equal(JSON.parse(accepted.stdout).sourceCommit, head);
    assert.equal(JSON.parse(accepted.stdout).publisherSourceCommit, successor);
    assert.equal(JSON.parse(accepted.stdout).executed, false);

    // Hash, tree and ancestry each match their named value, but the asserted
    // source commit contains different runtime bytes. Admission must refuse.
    cut.publisherSourceSuccessor.sourceCommit = checkpoint;
    cut.publisherSourceSuccessor.tree = cut.qualifiedSourceCheckpoint.tree;
    await writeFile(manifestPath, JSON.stringify(cut));
    commitFixture("synthetic false attribution");
    const rejected = plan();
    assert.notEqual(rejected.status, 0);
    assert.match(
      rejected.stderr,
      /source commit does not contain current target bytes: src\/runtime\.mjs/,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
