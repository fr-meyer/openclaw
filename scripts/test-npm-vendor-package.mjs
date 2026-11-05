// CI-only actual-package tests. The maintained owner must authenticate both roots
// before calling this module; this module does not fetch, install, or trust markers.
import assert from "node:assert/strict";
import * as fs from "node:fs";
import { mkdtemp, mkdir, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";

const EXPORTS = [
  ["cjs-normal", "require", ".", "dist/commonjs/index.min.js"],
  ["cjs-raw", "require", "./raw", "dist/commonjs/index.js"],
  ["esm-normal", "import", ".", "dist/esm/index.min.js"],
  ["esm-raw", "import", "./raw", "dist/esm/index.js"],
];
const turn = () => new Promise((resolve) => setImmediate(resolve));
const ASSERTION_OPERATORS = new Set([
  "strictEqual", "notStrictEqual", "deepStrictEqual", "notDeepStrictEqual",
  "equal", "notEqual", "deepEqual", "notDeepEqual", "ok", "match", "doesNotMatch",
  "throws", "doesNotThrow", "rejects", "doesNotReject", "fail", "ifError",
  "==", "!=", "===", "!==", ">", "<", ">=", "<=",
]);

// Assertion counts are safe, decisive evidence. Never turn strings, arrays,
// objects, or an arbitrary operator into the public diagnostic projection.
export function projectNpmVendorAssertionEvidence(error) {
  const evidence = { operator: ASSERTION_OPERATORS.has(error?.operator) ? error.operator : "unavailable" };
  for (const field of ["actual", "expected"]) {
    if (typeof error?.[field] === "number" && Number.isFinite(error[field])) evidence[field] = error[field];
  }
  return evidence;
}

async function bounded(promise, code, ms = 5000) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(code)), ms);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function checkedRoot(root) {
  assert.equal(typeof root, "string");
  assert.equal(path.isAbsolute(root), true);
  const resolved = await realpath(root);
  assert.equal(resolved, path.resolve(root), "package root must not use symlinks");
  const manifest = JSON.parse(await readFile(path.join(root, "package.json"), "utf8"));
  assert.equal(manifest.name, "npm");
  assert.equal(manifest.version, "12.2.1");
  return { root: resolved, require: createRequire(path.join(resolved, "package.json")) };
}

async function loadGlobForms(npm) {
  const globRoot = path.join(npm.root, "node_modules/glob");
  const manifest = JSON.parse(await readFile(path.join(globRoot, "package.json"), "utf8"));
  assert.equal(manifest.name, "glob");
  assert.equal(manifest.version, "13.0.6");
  const forms = new Map();
  for (const [name, condition, subpath, relative] of EXPORTS) {
    assert.equal(manifest.exports[subpath][condition].default, `./${relative}`);
    const filename = path.join(globRoot, relative);
    const st = await fs.promises.lstat(filename);
    assert.equal(st.isFile() && !st.isSymbolicLink(), true);
    if (condition === "require") assert.equal(npm.require.resolve(subpath === "." ? "glob" : "glob/raw"), filename);
    const api = condition === "require"
      ? npm.require(subpath === "." ? "glob" : "glob/raw")
      : await import(pathToFileURL(filename).href);
    for (const key of ["glob", "globSync", "globStream", "globStreamSync", "Glob"]) {
      assert.equal(typeof api[key], "function", `${name}.${key}`);
    }
    forms.set(name, api);
  }
  return forms;
}

async function fixture(root) {
  const expected = [];
  async function branch(relative, depth) {
    await mkdir(path.join(root, relative), { recursive: true });
    const file = path.posix.join(relative, "f.txt");
    await writeFile(path.join(root, file), file);
    expected.push(file);
    if (depth) {
      for (const child of ["a", "b"]) await branch(path.posix.join(relative, child), depth - 1);
    }
  }
  await branch("", 4);
  await writeFile(path.join(root, ".hidden"), "hidden");
  return expected.sort();
}

// All asynchronous directory callbacks are known to the fixture, so the abort
// assertion drains them rather than sleeping and guessing whether work stopped.
function instrumentedFs(controller, abortFirst = false) {
  const state = { calls: 0, startsAfterAbort: 0, pending: new Set() };
  function start() {
    if (controller?.signal.aborted) state.startsAfterAbort++;
    state.calls++;
    if (abortFirst && state.calls === 1) controller.abort(new Error("fixture.abort"));
  }
  const cfs = {
    ...fs,
    readdir(directory, options, callback) {
      if (typeof options === "function") { callback = options; options = undefined; }
      start();
      let settle;
      const pending = new Promise((resolve) => { settle = resolve; });
      state.pending.add(pending);
      queueMicrotask(() => {
        try {
          const entries = fs.readdirSync(directory, options);
          callback(null, entries);
        } catch (error) {
          callback(error);
        } finally {
          state.pending.delete(pending);
          settle();
        }
      });
    },
    readdirSync(directory, options) {
      start();
      return fs.readdirSync(directory, options);
    },
  };
  async function drain() {
    for (let n = 0; n < 256; n++) {
      if (state.pending.size) await Promise.all([...state.pending]);
      await turn();
      if (!state.pending.size) return;
    }
    throw new Error("fixture.callback_drain_exceeded");
  }
  return { state, cfs, drain };
}

function collectStream(stream) {
  return new Promise((resolve, reject) => {
    const values = [];
    stream.on("data", (entry) => values.push(entry));
    stream.once("error", reject);
    stream.once("end", () => resolve(values));
    stream.resume();
  });
}

async function abortObservation(api, cwd, kind, pre) {
  const controller = new AbortController();
  if (pre) controller.abort(new Error("fixture.abort"));
  const monitored = instrumentedFs(controller, !pre);
  const options = { cwd, nodir: true, signal: controller.signal, fs: monitored.cfs };
  if (kind === "sync") {
    assert.throws(() => api.globSync("**/*.txt", options), (error) => error === controller.signal.reason);
  } else {
    let promise;
    if (kind === "async") promise = api.glob("**/*.txt", options);
    else promise = collectStream(kind === "stream" ? api.globStream("**/*.txt", options) : api.globStreamSync("**/*.txt", options));
    await assert.rejects(bounded(promise, "abort.did_not_settle"), (error) => error === controller.signal.reason);
  }
  await monitored.drain();
  return { calls: monitored.state.calls, startsAfterAbort: monitored.state.startsAfterAbort,
    pendingCallbacks: monitored.state.pending.size };
}

async function abortCase(api, cwd, kind, pre) {
  const observed = await abortObservation(api, cwd, kind, pre);
  assert.equal(observed.startsAfterAbort, 0, "new traversal began after cancellation");
  assert.equal(observed.calls, pre ? 0 : 1, "unexpected filesystem traversal count");
  return observed;
}

async function positiveCase(api, cwd, expected) {
  const opts = { cwd, nodir: true };
  assert.deepEqual(api.globSync("**/*.txt", opts).sort(), expected);
  assert.deepEqual((await api.glob("**/*.txt", opts)).sort(), expected);
  assert.deepEqual((await bounded(collectStream(api.globStream("**/*.txt", opts)), "stream.did_not_settle")).sort(), expected);
  assert.deepEqual((await bounded(collectStream(api.globStreamSync("**/*.txt", opts)), "stream_sync.did_not_settle")).sort(), expected);
}

async function pausedCase(api, cwd, expected, sync) {
  const monitored = instrumentedFs();
  const opts = { cwd, nodir: true, fs: monitored.cfs };
  const stream = sync ? api.globStreamSync("**/*.txt", opts) : api.globStream("**/*.txt", opts);
  // Leave the stream without a consumer while owned pending reads complete.
  stream.pause();
  await monitored.drain();
  assert.ok(monitored.state.calls > 0);
  const values = await bounded(collectStream(stream), "pause.did_not_settle");
  assert.deepEqual(values.sort(), expected);
  await monitored.drain();
}

function cli(npm, args, scratch, timeoutMs = 15000) {
  const env = {
    PATH: path.dirname(process.execPath), HOME: scratch, LANG: "C.UTF-8", LC_ALL: "C.UTF-8",
    npm_config_cache: path.join(scratch, "cli-cache"), npm_config_userconfig: "/dev/null",
    npm_config_globalconfig: "/dev/null", npm_config_offline: "true", npm_config_audit: "false",
    npm_config_fund: "false", npm_config_ignore_scripts: "true", npm_config_update_notifier: "false",
  };
  const child = spawnSync(process.execPath, [path.join(npm.root, "bin/npm-cli.js"), ...args], {
    cwd: scratch, env, encoding: "utf8", timeout: timeoutMs, maxBuffer: 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
  assert.equal(child.error, undefined, "npm CLI subprocess error");
  assert.equal(child.signal, null, "npm CLI subprocess signalled");
  assert.equal(child.status, 0, `npm CLI failure: ${args[0]}`);
  return child.stdout;
}

async function consumerCases(npm, scratch) {
  assert.equal(cli(npm, ["--version"], scratch).trim(), "12.2.1");
  const cache = npm.require("cacache");
  const cacheRoot = path.join(scratch, "direct-cache");
  const content = Buffer.from("synthetic npm cache fixture\n");
  const integrity = await cache.put(cacheRoot, "fixture-key", content);
  const entry = await cache.get(cacheRoot, "fixture-key");
  assert.deepEqual(entry.data, content);
  assert.equal(String(entry.integrity), String(integrity));
  const cacheProof = await cache.verify(cacheRoot);
  assert.equal(cacheProof.badContentCount, 0);

  const workspace = path.join(scratch, "workspace");
  await mkdir(path.join(workspace, "packages", "alpha"), { recursive: true });
  const manifest = { name: "fixture-root", version: "1.0.0", workspaces: ["packages/*"] };
  await writeFile(path.join(workspace, "package.json"), JSON.stringify(manifest));
  await writeFile(path.join(workspace, "packages/alpha/package.json"), JSON.stringify({ name: "fixture-alpha", version: "1.0.0" }));
  const mapWorkspaces = npm.require("@npmcli/map-workspaces");
  const mapped = await mapWorkspaces({ cwd: workspace, pkg: manifest });
  assert.deepEqual([...mapped.entries()], [["fixture-alpha", path.join(workspace, "packages/alpha")]]);

  const packageJson = npm.require("@npmcli/package-json");
  const loaded = await packageJson.load(workspace);
  assert.equal(loaded.content.name, "fixture-root");
  assert.equal(loaded.content.version, "1.0.0");

  const packRoot = path.join(scratch, "pack-fixture");
  await mkdir(packRoot);
  await writeFile(path.join(packRoot, "package.json"), JSON.stringify({ name: "vendor-fixture", version: "1.0.0", files: ["index.js"] }));
  await writeFile(path.join(packRoot, "index.js"), "module.exports = 42;\n");
  await writeFile(path.join(packRoot, "excluded.txt"), "not packed");
  const Arborist = npm.require("@npmcli/arborist");
  const tree = await new Arborist({ path: packRoot }).loadActual();
  const files = await npm.require("npm-packlist")(tree);
  assert.deepEqual(files.sort(), ["index.js", "package.json"]);
  const packResult = JSON.parse(cli(npm, ["pack", packRoot, "--json", "--pack-destination", scratch], scratch));
  assert.equal(packResult.length, 1);
  assert.equal(packResult[0].filename, "vendor-fixture-1.0.0.tgz");
  assert.deepEqual(packResult[0].files.map((entry) => entry.path).sort(), ["index.js", "package.json"]);
  cli(npm, ["cache", "add", path.join(scratch, packResult[0].filename)], scratch);
  cli(npm, ["cache", "verify"], scratch);
}

function sourceDiff(repoRoot) {
  const child = spawnSync("git", ["-c", "protocol.allow=never", "diff", "--no-ext-diff", "--no-textconv", "--binary", "HEAD", "--"], {
    cwd: repoRoot, env: { PATH: process.env.PATH, GIT_NO_LAZY_FETCH: "1", GIT_TERMINAL_PROMPT: "0" },
    timeout: 15000, maxBuffer: 8 * 1024 * 1024,
  });
  assert.equal(child.error, undefined);
  assert.equal(child.status, 0);
  return createHash("sha256").update(child.stdout).digest("hex");
}

async function publicPackCase(repoRoot, npm, scratch) {
  const owner = await import(pathToFileURL(path.join(repoRoot, "scripts/lib/npm-vendor-delivery.mjs")).href);
  const lifecycle = await import(pathToFileURL(path.join(repoRoot, "scripts/package-manifest.mjs")).href);
  const baseline = sourceDiff(repoRoot);
  const manifestBytes = await readFile(path.join(repoRoot, "package.json"));
  const npmEntry = await fs.promises.lstat(path.join(repoRoot, "node_modules/npm"));
  const oldLink = npmEntry.isSymbolicLink() ? await fs.promises.readlink(path.join(repoRoot, "node_modules/npm")) : null;
  const verified = owner.verifyInstalledNpmVendor(repoRoot);
  try {
    await lifecycle.preparePackageManifest(repoRoot);
    const prepared = JSON.parse(await readFile(path.join(repoRoot, "package.json"), "utf8"));
    assert.equal(prepared.dependencies.npm, "12.2.1");
    assert.equal(prepared.bundleDependencies.includes("npm"), true);
    const regular = await fs.promises.lstat(path.join(repoRoot, "node_modules/npm"));
    assert.equal(regular.isDirectory() && !regular.isSymbolicLink(), true);
    const output = JSON.parse(cli(npm, ["pack", repoRoot, "--ignore-scripts", "--json", "--pack-destination", scratch], scratch, 60000));
    assert.equal(output.length, 1);
    assert.equal(path.basename(output[0].filename), output[0].filename);
    const filename = path.join(scratch, output[0].filename);
    const tar = createRequire(path.join(repoRoot, "package.json"))("tar");
    const rows = [];
    let packedManifest;
    tar.list({ file: filename, sync: true, strict: true, onReadEntry(entry) {
      if (entry.path === "package/package.json") {
        const chunks = [];
        entry.on("data", (bytes) => chunks.push(bytes));
        entry.on("end", () => { packedManifest = JSON.parse(Buffer.concat(chunks).toString("utf8")); });
      } else if (entry.path.startsWith("package/node_modules/npm/")) {
        if (entry.type === "Directory") return;
        assert.equal(entry.type, "File");
        const chunks = [];
        entry.on("data", (bytes) => chunks.push(bytes));
        entry.on("end", () => {
          const bytes = Buffer.concat(chunks);
          rows.push({ path: entry.path.slice("package/node_modules/npm/".length), mode: entry.mode & 0o7777,
            size: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex") });
        });
      }
      assert.notEqual(entry.path, "package/package-lock.json");
      assert.notEqual(entry.path, "package/npm-shrinkwrap.json");
    } });
    rows.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
    assert.deepEqual(rows, verified.files, "published npm inventory must equal the verified derived package");
    assert.equal(packedManifest.dependencies.npm, "12.2.1");
    assert.equal(packedManifest.bundleDependencies.includes("npm"), true);
    await rm(filename);
  } finally {
    await lifecycle.restorePackageManifest(repoRoot);
  }
  assert.deepEqual(await readFile(path.join(repoRoot, "package.json")), manifestBytes);
  assert.equal(sourceDiff(repoRoot), baseline, "pack lifecycle changed tracked source");
  const restored = await fs.promises.lstat(path.join(repoRoot, "node_modules/npm"));
  assert.equal(restored.isSymbolicLink(), npmEntry.isSymbolicLink());
  if (oldLink !== null) assert.equal(await fs.promises.readlink(path.join(repoRoot, "node_modules/npm")), oldLink);
}

async function globalDeliveryCase(repoRoot, original, scratch) {
  const owner = await import(pathToFileURL(path.join(repoRoot, "scripts/lib/npm-vendor-delivery.mjs")).href);
  const prefix = path.join(scratch, "global-prefix");
  await mkdir(path.join(prefix, "lib/node_modules"), { recursive: true });
  await mkdir(path.join(prefix, "bin"));
  await fs.promises.cp(original.root, path.join(prefix, "lib/node_modules/npm"), { recursive: true, dereference: false });
  await fs.promises.symlink("../lib/node_modules/npm/bin/npm-cli.js", path.join(prefix, "bin/npm"));
  await fs.promises.symlink("../lib/node_modules/npm/bin/npx-cli.js", path.join(prefix, "bin/npx"));
  owner.installGlobalNpmVendor(repoRoot, prefix);
  const env = { PATH: `${path.join(prefix, "bin")}${path.delimiter}${path.dirname(process.execPath)}`,
    HOME: scratch, npm_config_userconfig: "/dev/null", npm_config_globalconfig: "/dev/null",
    npm_config_cache: path.join(scratch, "global-cli-cache"), npm_config_offline: "true",
    npm_config_update_notifier: "false", npm_config_ignore_scripts: "true" };
  for (const name of ["npm", "npx"]) {
    const child = spawnSync(name, ["--version"], { cwd: scratch, env, encoding: "utf8", timeout: 10000, maxBuffer: 1024 * 1024 });
    assert.equal(child.error, undefined);
    assert.equal(child.signal, null);
    assert.equal(child.status, 0);
    assert.equal(child.stdout.trim(), "12.2.1");
  }
  const npmCommand = await import(pathToFileURL(path.join(repoRoot, "src/infra/npm-command.ts")).href);
  assert.deepEqual(npmCommand.resolveNpmCommand(["--version"]), npmCommand.resolveBundledNpmCommand(["--version"]));
  const command = npmCommand.resolveBundledNpmCommand(["--version"]);
  assert.equal(command[0], process.execPath);
  assert.equal(await realpath(path.resolve(command[1], "../..")), owner.verifyInstalledNpmVendor(repoRoot).packageRoot);
  const child = spawnSync(command[0], command.slice(1), { cwd: scratch, env, encoding: "utf8", timeout: 10000, maxBuffer: 1024 * 1024 });
  assert.equal(child.status, 0);
  assert.equal(child.stdout.trim(), "12.2.1");
  // Actual Docker and Bun runtimes remain separate qualification gates. This
  // proves their maintained byte-delivery owner and bundled CLI resolution.
}

/** Invoke only after the authoritative original/derived inventory verifier passes. */
export async function runNpmVendorPackageTests({ originalRoot, derivedRoot, repoRoot }) {
  const original = await checkedRoot(originalRoot);
  const derived = await checkedRoot(derivedRoot);
  assert.notEqual(original.root, derived.root);
  const scratch = await realpath(await mkdtemp(path.join(os.tmpdir(), "npm-vendor-actual-tests-")));
  const cases = [];
  async function record(name, action) {
    try {
      const observed = await action();
      cases.push({ name, passed: true, ...(observed === undefined ? {} : { observed }) });
    }
    catch (error) {
      cases.push({ name, passed: false, code: error?.code ?? "assertion_failed",
        assertion: projectNpmVendorAssertionEvidence(error),
        message: String(error?.message ?? error).slice(0, 2000) });
    }
  }
  try {
    const cwd = path.join(scratch, "tree");
    const expected = await fixture(cwd);
    const originalForms = await loadGlobForms(original);
    const forms = await loadGlobForms(derived);
    for (const [name, api] of forms) {
      await record(`${name}.positive`, () => positiveCase(api, cwd, expected));
      await record(`${name}.original-positive-parity`, () => positiveCase(originalForms.get(name), cwd, expected));
      for (const kind of ["async", "sync", "stream", "stream-sync"]) {
        await record(`${name}.${kind}.pre-abort`, () => abortCase(api, cwd, kind, true));
        await record(`${name}.${kind}.mid-abort`, () => abortCase(api, cwd, kind, false));
      }
      for (const sync of [false, true]) await record(`${name}.pause.${sync ? "sync" : "async"}`, () => pausedCase(api, cwd, expected, sync));
    }
    // The original must expose the regression through a real exported path;
    // a passing patched run alone does not prove that this harness finds it.
    await record("original-regression-positive-control", async () => {
      const observed = await abortObservation(originalForms.get("esm-normal"), cwd, "async", false);
      assert.ok(observed.startsAfterAbort > 0, "original bundle did not start traversal after abort");
      assert.equal(observed.pendingCallbacks, 0);
      return observed;
    });
    await record("actual-npm-consumers", () => consumerCases(derived, scratch));
    if (repoRoot !== undefined) {
      await record("actual-public-pack-delivery", () => publicPackCase(repoRoot, derived, scratch));
      await record("actual-offline-global-delivery", () => globalDeliveryCase(repoRoot, original, scratch));
    }
    return {
      schema: "openclaw.npm-vendor-actual-package-tests.v1",
      passed: cases.every((entry) => entry.passed),
      cases,
      originalVersion: "12.2.1", derivedVersion: "12.2.1", globVersion: "13.0.6",
      packageExecutionHost: "ci-only", imageTested: false,
      publicPackTested: repoRoot !== undefined,
      actualBunRuntimeTested: false,
    };
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
}
