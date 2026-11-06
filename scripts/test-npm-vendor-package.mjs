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
import { types } from "node:util";
import { resolveNpmJsonEntries } from "./lib/npm-json-output.mts";

const EXPORTS = [
  ["cjs-normal", "require", ".", "dist/commonjs/index.min.js"],
  ["cjs-raw", "require", "./raw", "dist/commonjs/index.js"],
  ["esm-normal", "import", ".", "dist/esm/index.min.js"],
  ["esm-raw", "import", "./raw", "dist/esm/index.js"],
];
const turn = () => new Promise((resolve) => setImmediate(resolve));
export const NPM_VENDOR_FAILURE_OPERATIONS = Object.freeze([
  "case.entry",
  "consumers.cli_version", "consumers.cache_put", "consumers.cache_get", "consumers.cache_verify",
  "consumers.workspace_fixture", "consumers.map_workspaces", "consumers.package_json_load",
  "consumers.pack_fixture", "consumers.arborist_load", "consumers.packlist", "consumers.cli_pack",
  "consumers.cli_cache_add", "consumers.cli_cache_verify",
  "pack.owner_import", "pack.manifest_owner_import", "pack.source_diff_before", "pack.manifest_capture",
  "pack.installed_entry_capture", "pack.installed_verify", "pack.manifest_prepare", "pack.prepared_manifest_read",
  "pack.bundle_assertions", "pack.root_cli", "pack.archive_inventory", "pack.artifact_cleanup",
  "pack.manifest_restore", "pack.manifest_restoration_assertions", "pack.source_diff_after", "pack.installed_restoration_assertions",
  "global.owner_import", "global.fixture_setup", "global.install", "global.npm_entrypoint_spawn",
  "global.npm_entrypoint_assertions", "global.npx_entrypoint_spawn", "global.npx_entrypoint_assertions",
  "global.resolver_import", "global.resolver_assertions", "global.bundled_cli_spawn", "global.bundled_cli_assertions",
  "cli.version.spawn", "cli.version.exit", "cli.version.output", "cli.pack.spawn", "cli.pack.exit", "cli.pack.output",
  "cli.cache_add.spawn", "cli.cache_add.exit", "cli.cache_add.output", "cli.cache_verify.spawn", "cli.cache_verify.exit", "cli.cache_verify.output",
]);
export const NPM_VENDOR_ERROR_NAMES = Object.freeze([
  "Error", "TypeError", "RangeError", "SyntaxError", "ReferenceError", "URIError", "EvalError",
  "AggregateError", "AssertionError", "AbortError", "TimeoutError",
]);
export const NPM_VENDOR_NODE_CODES = Object.freeze([
  "ERR_ASSERTION", "ENOENT", "EACCES", "EPERM", "EEXIST", "ENOTDIR", "EISDIR", "ENOTEMPTY",
  "EINVAL", "ENAMETOOLONG", "ELOOP", "EMFILE", "ENFILE", "ENOSPC", "EROFS", "ETIMEDOUT", "ABORT_ERR",
  "ERR_MODULE_NOT_FOUND", "MODULE_NOT_FOUND", "ERR_UNKNOWN_FILE_EXTENSION", "ERR_PACKAGE_PATH_NOT_EXPORTED",
  "ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX", "ERR_INVALID_ARG_TYPE", "ERR_INVALID_ARG_VALUE", "ERR_OUT_OF_RANGE",
  "ERR_STREAM_PREMATURE_CLOSE", "ERR_STREAM_DESTROYED", "ERR_CHILD_PROCESS_STDIO_MAXBUFFER",
]);
const DELIVERY_REASONS = new Map([
  ["npm vendor source configuration is invalid", "delivery.source_configuration_invalid"],
  ["npm vendor source configuration is required", "delivery.source_configuration_required"],
  ["npm vendor proof input is not regular", "delivery.proof_input_not_regular"],
  ["npm vendor source patch differs from its proof", "delivery.patch_binding"],
  ["npm vendor package must be inside its source root", "delivery.package_outside_source_root"],
  ["npm vendor artifact is root-package only", "delivery.root_artifact_only"],
  ["original npm archive differs from authenticated source proof", "delivery.original_archive"],
  ["npm vendor artifact changed; cleanup refused", "delivery.artifact_cleanup_changed"],
  ["npm vendor staging path must be a regular source-owned entry", "delivery.staging_path"],
  ["npm vendor pack staging belongs to another or changed owner", "delivery.pack_staging_owner"],
  ["npm vendor pack staging failed; receipt retained", "delivery.pack_staging_failed"],
  ["npm vendor staging recovery binding differs", "delivery.restore_binding"],
  ["npm vendor staged bytes changed; restore refused", "delivery.restore_changed"],
  ["npm vendor global prefix must be a regular canonical directory", "delivery.global_prefix"],
  ["global npm directory is unexpected", "delivery.global_directory"],
  ["global npm entrypoint differs from pinned Node image layout", "delivery.global_entrypoint"],
  ["Docker npm delivery requires root in the runtime build stage", "delivery.global_cli_root"],
]);
export const NPM_VENDOR_OWNER_REASONS = Object.freeze([
  ...DELIVERY_REASONS.values(),
  ...["change_binding", "change_count", "change_shape", "compiler_binding", "compiler_shape", "derived_binding", "derived_shape",
    "installed_inventory", "installed_link", "installed_type", "inventory_count", "inventory_mode", "inventory_row", "inventory_shape",
    "map_binding", "map_count", "map_shape", "original_binding", "original_shape", "patch_binding", "patch_bytes", "patch_shape",
    "path", "proof_bytes", "proof_identity", "proof_json", "proof_noncanonical", "proof_shape", "repair_binding", "repair_shape", "root",
    "archive_bound", "archive_expansion", "archive_member", "archive_member_bound", "archive_member_size", "archive_unsettled",
    "derived_archive_identity", "derived_archive_inventory", "original_archive_identity", "original_archive_inventory", "pack_bound", "pack_bytes"]
    .map((reason) => `npm-vendor.${reason}`),
]);
const OPERATIONS = new Set(NPM_VENDOR_FAILURE_OPERATIONS);
const tagged = (value, allowed) => value === undefined ? { state: "absent" }
  : allowed.includes(value) ? { state: "recognized", value } : { state: "unrecognized" };

function diagnosticData(object, key) {
  const seen = new Set();
  let current = object;
  for (let depth = 0; depth < 4 && current !== null &&
      (typeof current === "object" || typeof current === "function"); depth++) {
    if (seen.has(current) || types.isProxy(current)) return { state: "unrecognized" };
    seen.add(current);
    try {
      const descriptor = Object.getOwnPropertyDescriptor(current, key);
      if (descriptor !== undefined) return Object.hasOwn(descriptor, "value")
        ? { state: "data", value: descriptor.value } : { state: "unrecognized" };
      current = Object.getPrototypeOf(current);
    } catch { return { state: "unrecognized" }; }
  }
  return current === null || (typeof current !== "object" && typeof current !== "function")
    ? { state: "absent" } : { state: "unrecognized" };
}

function tagDiagnosticData(data, allowed) {
  return data.state === "unrecognized" ? { state: "unrecognized" }
    : tagged(data.state === "data" ? data.value : undefined, allowed);
}

export function createNpmVendorOperationCheckpoint() {
  let operation = "case.entry";
  const checkpoint = (next) => {
    if (!OPERATIONS.has(next)) throw new Error("fixture.operation_unrecognized");
    operation = next;
  };
  checkpoint.current = () => operation;
  return checkpoint;
}

export function projectNpmVendorFailureCause(error) {
  const code = diagnosticData(error, "code");
  const actual = diagnosticData(error, "actual");
  let cause = code.state === "data" && code.value === "ERR_ASSERTION" &&
    actual.state === "data" && types.isNativeError(actual.value) ? actual.value : error;
  const seen = new Set();
  for (let depth = 0; depth < 4 && cause && typeof cause === "object" && !seen.has(cause); depth++) {
    seen.add(cause);
    const next = diagnosticData(cause, "cause");
    if (next.state === "unrecognized") return { name: { state: "unrecognized" },
      code: { state: "unrecognized" }, ownerReason: { state: "unrecognized" } };
    if (next.state !== "data" || !next.value || typeof next.value !== "object" || seen.has(next.value)) break;
    cause = next.value;
  }
  const message = diagnosticData(cause, "message");
  const literal = message.state === "data"
    ? { state: "data", value: DELIVERY_REASONS.get(message.value) ?? message.value } : message;
  return { name: tagDiagnosticData(diagnosticData(cause, "name"), NPM_VENDOR_ERROR_NAMES),
    code: tagDiagnosticData(diagnosticData(cause, "code"), NPM_VENDOR_NODE_CODES),
    ownerReason: tagDiagnosticData(literal, NPM_VENDOR_OWNER_REASONS) };
}

export function createNpmVendorFixtureConfig(scratch) {
  const user = path.join(scratch, "npm-user.empty.npmrc");
  const global = path.join(scratch, "npm-global.empty.npmrc");
  fs.writeFileSync(user, "", { flag: "wx", mode: 0o600 });
  fs.writeFileSync(global, "", { flag: "wx", mode: 0o600 });
  return Object.freeze({ user, global });
}
const ASSERTION_OPERATORS = new Set([
  "strictEqual", "notStrictEqual", "deepStrictEqual", "notDeepStrictEqual",
  "equal", "notEqual", "deepEqual", "notDeepEqual", "ok", "match", "doesNotMatch",
  "throws", "doesNotThrow", "rejects", "doesNotReject", "fail", "ifError",
  "==", "!=", "===", "!==", ">", "<", ">=", "<=",
]);

// Assertion counts are safe, decisive evidence. Never turn strings, arrays,
// objects, or an arbitrary operator into the public diagnostic projection.
export function projectNpmVendorAssertionEvidence(error) {
  const operator = diagnosticData(error, "operator");
  const evidence = { operator: operator.state === "data" && ASSERTION_OPERATORS.has(operator.value) ? operator.value : "unavailable" };
  for (const field of ["actual", "expected"]) {
    const data = diagnosticData(error, field);
    if (data.state === "data" && typeof data.value === "number" && Number.isFinite(data.value)) evidence[field] = data.value;
  }
  return evidence;
}

export function recordNpmVendorCaseFailure(name, error, checkpoint) {
  const operation = checkpoint.current();
  if (!OPERATIONS.has(operation)) throw new Error("fixture.operation_unrecognized");
  const code = tagDiagnosticData(diagnosticData(error, "code"), NPM_VENDOR_NODE_CODES);
  const message = diagnosticData(error, "message");
  return { name, passed: false, code: code.state === "recognized" ? code.value : "assertion_failed", operation,
    cause: projectNpmVendorFailureCause(error), assertion: projectNpmVendorAssertionEvidence(error),
    message: message.state === "data" && typeof message.value === "string"
      ? message.value.slice(0, 2000) : "diagnostic.message_unavailable" };
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

function cli(npm, args, scratch, config, checkpoint, timeoutMs = 15000) {
  const command = args[0] === "--version" ? "version" : args[0] === "pack" ? "pack"
    : args[0] === "cache" && args[1] === "add" ? "cache_add"
      : args[0] === "cache" && args[1] === "verify" ? "cache_verify" : null;
  if (command === null) throw new Error("fixture.cli_operation_unrecognized");
  const env = {
    PATH: path.dirname(process.execPath), HOME: scratch, LANG: "C.UTF-8", LC_ALL: "C.UTF-8",
    npm_config_cache: path.join(scratch, "cli-cache"), npm_config_userconfig: config.user,
    npm_config_globalconfig: config.global, npm_config_offline: "true", npm_config_audit: "false",
    npm_config_fund: "false", npm_config_ignore_scripts: "true", npm_config_update_notifier: "false",
  };
  checkpoint(`cli.${command}.spawn`);
  const child = spawnSync(process.execPath, [path.join(npm.root, "bin/npm-cli.js"), ...args], {
    cwd: scratch, env, encoding: "utf8", timeout: timeoutMs, maxBuffer: 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
  checkpoint(`cli.${command}.exit`);
  assert.equal(child.error, undefined, "npm CLI subprocess error");
  assert.equal(child.signal, null, "npm CLI subprocess signalled");
  assert.equal(child.status, 0, `npm CLI failure: ${args[0]}`);
  checkpoint(`cli.${command}.output`);
  return child.stdout;
}

export function resolveNpmVendorPackResult(stdout, expected) {
  const entries = resolveNpmJsonEntries(JSON.parse(stdout));
  assert.equal(entries.length, 1);
  const result = entries[0];
  assert.equal(result?.name, expected.name);
  assert.equal(result?.version, expected.version);
  assert.equal(result?.filename, expected.filename);
  assert.equal(path.basename(result.filename), result.filename);
  return result;
}

async function consumerCases(npm, scratch, config, checkpoint) {
  checkpoint("consumers.cli_version");
  assert.equal(cli(npm, ["--version"], scratch, config, checkpoint).trim(), "12.2.1");
  const cache = npm.require("cacache");
  const cacheRoot = path.join(scratch, "direct-cache");
  const content = Buffer.from("synthetic npm cache fixture\n");
  checkpoint("consumers.cache_put");
  const integrity = await cache.put(cacheRoot, "fixture-key", content);
  checkpoint("consumers.cache_get");
  const entry = await cache.get(cacheRoot, "fixture-key");
  assert.deepEqual(entry.data, content);
  assert.equal(String(entry.integrity), String(integrity));
  checkpoint("consumers.cache_verify");
  const cacheProof = await cache.verify(cacheRoot);
  assert.equal(cacheProof.badContentCount, 0);

  checkpoint("consumers.workspace_fixture");
  const workspace = path.join(scratch, "workspace");
  await mkdir(path.join(workspace, "packages", "alpha"), { recursive: true });
  const manifest = { name: "fixture-root", version: "1.0.0", workspaces: ["packages/*"] };
  await writeFile(path.join(workspace, "package.json"), JSON.stringify(manifest));
  await writeFile(path.join(workspace, "packages/alpha/package.json"), JSON.stringify({ name: "fixture-alpha", version: "1.0.0" }));
  checkpoint("consumers.map_workspaces");
  const mapWorkspaces = npm.require("@npmcli/map-workspaces");
  const mapped = await mapWorkspaces({ cwd: workspace, pkg: manifest });
  assert.deepEqual([...mapped.entries()], [["fixture-alpha", path.join(workspace, "packages/alpha")]]);

  checkpoint("consumers.package_json_load");
  const packageJson = npm.require("@npmcli/package-json");
  const loaded = await packageJson.load(workspace);
  assert.equal(loaded.content.name, "fixture-root");
  assert.equal(loaded.content.version, "1.0.0");

  checkpoint("consumers.pack_fixture");
  const packRoot = path.join(scratch, "pack-fixture");
  await mkdir(packRoot);
  await writeFile(path.join(packRoot, "package.json"), JSON.stringify({ name: "vendor-fixture", version: "1.0.0", files: ["index.js"] }));
  await writeFile(path.join(packRoot, "index.js"), "module.exports = 42;\n");
  await writeFile(path.join(packRoot, "excluded.txt"), "not packed");
  checkpoint("consumers.arborist_load");
  const Arborist = npm.require("@npmcli/arborist");
  const tree = await new Arborist({ path: packRoot }).loadActual();
  checkpoint("consumers.packlist");
  const files = await npm.require("npm-packlist")(tree);
  assert.deepEqual(files.sort(), ["index.js", "package.json"]);
  checkpoint("consumers.cli_pack");
  const packResult = resolveNpmVendorPackResult(
    cli(npm, ["pack", packRoot, "--json", "--pack-destination", scratch], scratch, config, checkpoint),
    { name: "vendor-fixture", version: "1.0.0", filename: "vendor-fixture-1.0.0.tgz" },
  );
  assert.deepEqual(packResult.files.map((entry) => entry.path).sort(), ["index.js", "package.json"]);
  checkpoint("consumers.cli_cache_add");
  cli(npm, ["cache", "add", path.join(scratch, packResult.filename)], scratch, config, checkpoint);
  checkpoint("consumers.cli_cache_verify");
  cli(npm, ["cache", "verify"], scratch, config, checkpoint);
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

async function publicPackCase(repoRoot, npm, scratch, config, checkpoint) {
  checkpoint("pack.owner_import");
  const owner = await import(pathToFileURL(path.join(repoRoot, "scripts/lib/npm-vendor-delivery.mjs")).href);
  checkpoint("pack.manifest_owner_import");
  const lifecycle = await import(pathToFileURL(path.join(repoRoot, "scripts/package-manifest.mjs")).href);
  checkpoint("pack.source_diff_before");
  const baseline = sourceDiff(repoRoot);
  checkpoint("pack.manifest_capture");
  const manifestBytes = await readFile(path.join(repoRoot, "package.json"));
  checkpoint("pack.installed_entry_capture");
  const npmEntry = await fs.promises.lstat(path.join(repoRoot, "node_modules/npm"));
  const oldLink = npmEntry.isSymbolicLink() ? await fs.promises.readlink(path.join(repoRoot, "node_modules/npm")) : null;
  let failedOperation;
  try {
    checkpoint("pack.manifest_prepare");
    await lifecycle.preparePackageManifest(repoRoot);
    checkpoint("pack.installed_verify");
    const verified = owner.verifyInstalledNpmVendor(repoRoot);
    checkpoint("pack.prepared_manifest_read");
    const prepared = JSON.parse(await readFile(path.join(repoRoot, "package.json"), "utf8"));
    checkpoint("pack.bundle_assertions");
    assert.equal(prepared.dependencies.npm, "12.2.1");
    assert.equal(prepared.bundleDependencies.includes("npm"), true);
    const regular = await fs.promises.lstat(path.join(repoRoot, "node_modules/npm"));
    assert.equal(regular.isDirectory() && !regular.isSymbolicLink(), true);
    checkpoint("pack.root_cli");
    const output = resolveNpmVendorPackResult(
      cli(npm, ["pack", repoRoot, "--ignore-scripts", "--json", "--pack-destination", scratch], scratch, config, checkpoint, 60000),
      { name: prepared.name, version: prepared.version, filename: `${prepared.name}-${prepared.version}.tgz` },
    );
    const filename = path.join(scratch, output.filename);
    checkpoint("pack.archive_inventory");
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
    checkpoint("pack.artifact_cleanup");
    await rm(filename);
  } catch (error) {
    failedOperation = checkpoint.current();
    throw error;
  } finally {
    checkpoint("pack.manifest_restore");
    await lifecycle.restorePackageManifest(repoRoot);
    // Successful cleanup must not replace the checkpoint of the actual failure.
    if (failedOperation !== undefined) checkpoint(failedOperation);
  }
  checkpoint("pack.manifest_restoration_assertions");
  assert.deepEqual(await readFile(path.join(repoRoot, "package.json")), manifestBytes);
  checkpoint("pack.source_diff_after");
  assert.equal(sourceDiff(repoRoot), baseline, "pack lifecycle changed tracked source");
  checkpoint("pack.installed_restoration_assertions");
  const restored = await fs.promises.lstat(path.join(repoRoot, "node_modules/npm"));
  assert.equal(restored.isSymbolicLink(), npmEntry.isSymbolicLink());
  if (oldLink !== null) assert.equal(await fs.promises.readlink(path.join(repoRoot, "node_modules/npm")), oldLink);
}

async function globalDeliveryCase(repoRoot, original, scratch, config, checkpoint) {
  checkpoint("global.owner_import");
  const owner = await import(pathToFileURL(path.join(repoRoot, "scripts/lib/npm-vendor-delivery.mjs")).href);
  checkpoint("global.fixture_setup");
  const prefix = path.join(scratch, "global-prefix");
  await mkdir(path.join(prefix, "lib/node_modules"), { recursive: true });
  await mkdir(path.join(prefix, "bin"));
  await fs.promises.cp(original.root, path.join(prefix, "lib/node_modules/npm"), { recursive: true, dereference: false });
  await fs.promises.symlink("../lib/node_modules/npm/bin/npm-cli.js", path.join(prefix, "bin/npm"));
  await fs.promises.symlink("../lib/node_modules/npm/bin/npx-cli.js", path.join(prefix, "bin/npx"));
  const originalEntry = await fs.promises.lstat(path.join(repoRoot, "node_modules/npm"), { bigint: true });
  const originalLink = originalEntry.isSymbolicLink() ? await fs.promises.readlink(path.join(repoRoot, "node_modules/npm")) : null;
  let packageLocal;
  let failedOperation;
  try {
    checkpoint("global.install");
    packageLocal = owner.prepareNpmVendorForRuntime(repoRoot);
    const local = owner.verifyInstalledNpmVendor(repoRoot);
    assert.equal(packageLocal.originalSourceVerified, false);
    assert.equal(packageLocal.payloadVerified, true);
    assert.equal(local.packageRoot, packageLocal.sourceRoot);
    const delivered = owner.installGlobalNpmVendor(repoRoot, prefix);
    assert.equal(delivered.sourceInventoryVerified, true);
    assert.equal(delivered.sourceInventorySha256, local.inventorySha256);
    assert.deepEqual(delivered.files, local.files, "both delivered npm trees must match the complete proof");
    const env = { PATH: `${path.join(prefix, "bin")}${path.delimiter}${path.dirname(process.execPath)}`,
      HOME: scratch, npm_config_userconfig: config.user, npm_config_globalconfig: config.global,
      npm_config_cache: path.join(scratch, "global-cli-cache"), npm_config_offline: "true",
      npm_config_update_notifier: "false", npm_config_ignore_scripts: "true" };
    for (const name of ["npm", "npx"]) {
      checkpoint(name === "npm" ? "global.npm_entrypoint_spawn" : "global.npx_entrypoint_spawn");
      const child = spawnSync(name, ["--version"], { cwd: scratch, env, encoding: "utf8", timeout: 10000, maxBuffer: 1024 * 1024 });
      checkpoint(name === "npm" ? "global.npm_entrypoint_assertions" : "global.npx_entrypoint_assertions");
      assert.equal(child.error, undefined);
      assert.equal(child.signal, null);
      assert.equal(child.status, 0);
      assert.equal(child.stdout.trim(), "12.2.1");
    }
    checkpoint("global.resolver_import");
    const npmCommand = await import(pathToFileURL(path.join(repoRoot, "src/infra/npm-command.ts")).href);
    checkpoint("global.resolver_assertions");
    const command = npmCommand.resolveBundledNpmCommand(["--version"]);
    const versions = Object.getOwnPropertyDescriptor(process, "versions");
    try {
      // Both runtime-selection branches must choose the strictly verified local
      // payload. This is selection parity, not execution of an actual Bun VM.
      for (const bun of [undefined, "1.4.2"]) {
        Object.defineProperty(process, "versions", { ...versions, value: { ...versions.value, bun } });
        assert.deepEqual(npmCommand.resolveNpmCommand(["--version"]), command);
      }
    } finally {
      Object.defineProperty(process, "versions", versions);
    }
    assert.equal(command[0], process.execPath);
    assert.equal(await realpath(path.resolve(command[1], "../..")), local.packageRoot);
    assert.equal(delivered.sourceRoot, local.packageRoot);
    checkpoint("global.bundled_cli_spawn");
    const child = spawnSync(command[0], command.slice(1), { cwd: scratch, env, encoding: "utf8", timeout: 10000, maxBuffer: 1024 * 1024 });
    checkpoint("global.bundled_cli_assertions");
    assert.equal(child.status, 0);
    assert.equal(child.stdout.trim(), "12.2.1");
    // Actual Docker and Bun runtimes remain separate qualification gates. This
    // verifies the maintained delivery owner and its real packaged CLI route.
  } catch (error) {
    failedOperation = checkpoint.current();
    throw error;
  } finally {
    checkpoint("global.install");
    if (packageLocal !== undefined) {
      packageLocal.restore();
      const restored = await fs.promises.lstat(path.join(repoRoot, "node_modules/npm"), { bigint: true });
      assert.equal(restored.dev, originalEntry.dev);
      assert.equal(restored.ino, originalEntry.ino);
      if (originalLink !== null) assert.equal(await fs.promises.readlink(path.join(repoRoot, "node_modules/npm")), originalLink);
    }
    if (failedOperation !== undefined) checkpoint(failedOperation);
  }
}

/** Invoke only after the authoritative original/derived inventory verifier passes. */
export async function runNpmVendorPackageTests({ originalRoot, derivedRoot, repoRoot }) {
  const original = await checkedRoot(originalRoot);
  const derived = await checkedRoot(derivedRoot);
  assert.notEqual(original.root, derived.root);
  const scratch = await realpath(await mkdtemp(path.join(os.tmpdir(), "npm-vendor-actual-tests-")));
  const cases = [];
  async function record(name, action) {
    const checkpoint = createNpmVendorOperationCheckpoint();
    try {
      const observed = await action(checkpoint);
      cases.push({ name, passed: true, ...(observed === undefined ? {} : { observed }) });
    }
    catch (error) {
      cases.push(recordNpmVendorCaseFailure(name, error, checkpoint));
    }
  }
  try {
    const config = createNpmVendorFixtureConfig(scratch);
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
    await record("actual-npm-consumers", (checkpoint) => consumerCases(derived, scratch, config, checkpoint));
    if (repoRoot !== undefined) {
      await record("actual-public-pack-delivery", (checkpoint) => publicPackCase(repoRoot, derived, scratch, config, checkpoint));
      await record("actual-offline-global-delivery", (checkpoint) => globalDeliveryCase(repoRoot, original, scratch, config, checkpoint));
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
