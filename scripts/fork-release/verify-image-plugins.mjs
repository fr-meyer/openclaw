#!/usr/bin/env node
import { spawn, spawnSync } from "node:child_process";
import {
  accessSync,
  constants,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
} from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const OUTPUT_LIMIT = 64 * 1024;
const SELF = fileURLToPath(import.meta.url);

function need(value, message) {
  if (!value) throw new Error(message);
}

function regularFile(path) {
  const stat = lstatSync(path);
  need(stat.isFile() && !stat.isSymbolicLink(), `Plugin payload is not a regular file: ${path}`);
  return readFileSync(path);
}

function json(path) {
  return JSON.parse(regularFile(path).toString("utf8"));
}

function containedFile(root, path) {
  const actual = realpathSync(path);
  const inside = relative(realpathSync(root), actual);
  need(
    inside && !inside.startsWith("..") && !isAbsolute(inside),
    "Runtime artifact escaped image root",
  );
  need(lstatSync(actual).isFile(), "Runtime artifact is not a regular file");
  return actual;
}

function runtimeEnvironment(directory) {
  const env = { PATH: process.env.PATH, LANG: "C.UTF-8" };
  for (const [key, name] of Object.entries({
    HOME: "home",
    CODEX_HOME: "codex",
    XDG_CONFIG_HOME: "config",
    XDG_CACHE_HOME: "cache",
    OPENCLAW_STATE_DIR: "state",
    TMPDIR: "tmp",
  })) {
    env[key] = join(directory, name);
    mkdirSync(env[key], { mode: 0o700 });
  }
  // Never inherit operator auth, config, NODE_OPTIONS, command overrides or proxies.
  env.OPENCLAW_CONFIG_PATH = join(directory, "absent-config.json");
  return env;
}

function inspectCodexExecutable(root, expectedVersion, env) {
  need(
    process.platform === "linux" && process.arch === "x64",
    "Codex image proof requires linux/x64",
  );
  const plugin = json(join(root, "extensions/codex/package.json"));
  need(
    plugin.dependencies?.["@openai/codex"] === expectedVersion,
    "Codex dependency differs from source pin",
  );
  const alias = "@openai/codex-linux-x64";
  need(
    plugin.openclaw.install?.requiredPlatformPackages?.includes(alias),
    "Codex platform requirement missing",
  );
  // Resolve from the packaged plugin root used by the native plugin loader.
  const requirePlugin = createRequire(join(root, "dist/extensions/codex/package.json"));
  const manifestPath = containedFile(root, requirePlugin.resolve("@openai/codex/package.json"));
  const installed = json(manifestPath);
  need(
    installed.name === "@openai/codex" && installed.version === expectedVersion,
    "Installed Codex package differs from source pin",
  );
  const platformVersion = `${expectedVersion}-linux-x64`;
  need(
    installed.optionalDependencies?.[alias] === `npm:@openai/codex@${platformVersion}`,
    "Codex platform alias differs from source pin",
  );
  const requireCodex = createRequire(manifestPath);
  const platformManifest = containedFile(root, requireCodex.resolve(`${alias}/package.json`));
  const platform = json(platformManifest);
  need(
    platform.name === "@openai/codex" &&
      platform.version === platformVersion &&
      JSON.stringify(platform.os) === '["linux"]' &&
      JSON.stringify(platform.cpu) === '["x64"]',
    "Installed Codex platform package differs from source pin",
  );
  const launcher = containedFile(root, requirePlugin.resolve("@openai/codex/bin/codex.js"));
  const native = containedFile(
    root,
    join(dirname(platformManifest), "vendor/x86_64-unknown-linux-musl/bin/codex"),
  );
  accessSync(native, constants.X_OK);
  const result = spawnSync(process.execPath, [launcher, "--version"], {
    cwd: root,
    env,
    encoding: "utf8",
    timeout: 15_000,
    maxBuffer: OUTPUT_LIMIT,
    killSignal: "SIGKILL",
  });
  need(
    !result.error && result.status === 0,
    "Managed Codex --version failed or exceeded its bounds",
  );
  need(
    result.stdout.trim() === `codex-cli ${expectedVersion}`,
    "Managed Codex CLI version differs from source pin",
  );
  return {
    native,
    evidence: {
      packageVersion: installed.version,
      platformAlias: alias,
      platformVersion,
      cliVersion: expectedVersion,
    },
  };
}

export async function smokeCodexAppServer(
  native,
  env,
  hostVersion,
  expectedVersion,
  timeoutMs = 30_000,
) {
  return new Promise((resolveProof, reject) => {
    const child = spawn(native, ["app-server", "--listen", "stdio://"], {
      cwd: env.HOME,
      env,
      stdio: ["pipe", "pipe", "pipe"],
    });
    let failure;
    let initialized = false;
    let outputBytes = 0;
    let pending = "";
    let drainTimer;
    const fail = (message) => {
      failure ??= new Error(message);
      child.kill("SIGKILL");
      // A failed child cannot retain the verifier through inherited pipes.
      drainTimer ??= setTimeout(() => {
        child.stdin.destroy();
        child.stdout.destroy();
        child.stderr.destroy();
      }, 1_000);
    };
    const timer = setTimeout(
      () => fail("Codex app-server initialize/shutdown timed out"),
      timeoutMs,
    );
    const count = (chunk) => {
      outputBytes += Buffer.byteLength(chunk);
      if (outputBytes > OUTPUT_LIMIT) fail("Codex app-server output exceeded its bound");
      return !failure;
    };
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      if (!count(chunk)) return;
      pending += chunk;
      for (let newline; (newline = pending.indexOf("\n")) >= 0;) {
        const line = pending.slice(0, newline);
        pending = pending.slice(newline + 1);
        if (!line.trim()) continue;
        try {
          const response = JSON.parse(line);
          if (response.id !== 1) continue;
          need(
            !initialized && !response.error,
            "Codex initialize returned an error or duplicate response",
          );
          const version = /^[^/]+\/(\d+\.\d+\.\d+)(?:[\s(]|$)/u.exec(
            response.result?.userAgent ?? "",
          )?.[1];
          need(
            version === expectedVersion,
            "Codex initialize runtime version differs from source pin",
          );
          initialized = true;
          // Complete the native handshake, then close its input and join shutdown.
          child.stdin.end(`${JSON.stringify({ method: "initialized" })}\n`);
        } catch (error) {
          fail(
            error instanceof SyntaxError ? "Codex app-server emitted invalid JSON" : error.message,
          );
        }
      }
    });
    child.stderr.on("data", count);
    child.stdin.on("error", () => fail("Codex app-server input failed"));
    child.on("error", () => fail("Codex app-server could not start"));
    child.on("spawn", () =>
      child.stdin.write(
        `${JSON.stringify({
          id: 1,
          method: "initialize",
          params: {
            clientInfo: {
              name: "openclaw",
              title: "OpenClaw image verification",
              version: hostVersion,
            },
            capabilities: { experimentalApi: true },
          },
        })}\n`,
      ),
    );
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      clearTimeout(drainTimer);
      if (failure) reject(failure);
      else if (!initialized || code !== 0 || signal)
        reject(new Error("Codex app-server did not initialize and shut down cleanly"));
      else
        resolveProof({ initializeVersion: expectedVersion, initialized: true, shutdown: "exited" });
    });
  });
}

async function smokeWorkboardWorker(root, directory) {
  const runtimePath = containedFile(root, join(root, "dist/plugin-sdk/sqlite-runtime.js"));
  const moduleUrl = pathToFileURL(
    containedFile(root, join(root, "dist/extensions/workboard/src/sqlite-store.worker.js")),
  );
  const { openSqliteWorkerStore } = await import(pathToFileURL(runtimePath).href);
  const databasePath = join(directory, "workboard.sqlite");
  const store = await openSqliteWorkerStore({ moduleUrl, databasePath, input: undefined });
  let connection;
  const execute = async (type, input) => {
    const result = await store.execute({ type, input });
    need(result?.ok === true, `Workboard native operation failed: ${type}`);
    return result.value;
  };
  try {
    const opened = await execute("connection.open", undefined);
    connection = opened?.connection;
    need(Number.isInteger(connection) && connection > 0, "Workboard connection was not admitted");
    const board = { id: "image-proof", name: "Image proof", createdAt: 1, updatedAt: 1 };
    await execute("boards.register", { connection, args: [board.id, { version: 1, board }] });
    const result = await execute("boards.lookup", { connection, args: [board.id] });
    need(
      result?.version === 1 &&
        Object.entries(board).every(([key, value]) => result.board?.[key] === value),
      "Workboard native write/read did not round trip",
    );
    need(lstatSync(databasePath).isFile(), "Workboard native database was not created");
    await execute("connection.close", { connection });
    connection = undefined;
  } finally {
    try {
      if (connection !== undefined) await execute("connection.close", { connection });
    } finally {
      await store.close();
    }
  }
  return { worker: "sqlite", roundTrip: true, closed: true };
}

function versionParts(version) {
  need(/^\d{4}\.\d{1,2}\.\d{1,2}$/u.test(version), `Invalid plugin version: ${version}`);
  return version.split(".").map(Number);
}

function atLeast(version, minimum) {
  const left = versionParts(version);
  const right = versionParts(minimum);
  for (let i = 0; i < left.length; i += 1) {
    if (left[i] !== right[i]) return left[i] > right[i];
  }
  return true;
}

export async function inspectImagePlugins(root, extensions, version, expectedCodexVersion) {
  need(/^\d+\.\d+\.\d+$/u.test(expectedCodexVersion), "Missing exact source-pinned Codex version");
  const ids = extensions.split(",");
  need(
    ids.length > 0 && ids.every((id) => /^[a-z0-9][a-z0-9-]*$/u.test(id)),
    "Invalid selected plugin IDs",
  );
  need(new Set(ids).size === ids.length, "Duplicate selected plugin ID");
  need(json(join(root, "package.json")).version === version, "Image host version changed");
  const inspected = [];
  for (const id of ids) {
    const packageJson = json(join(root, "extensions", id, "package.json"));
    const descriptor = json(join(root, "extensions", id, "openclaw.plugin.json"));
    need(descriptor.id === id, `Plugin identity changed: ${id}`);
    need(
      Array.isArray(packageJson.openclaw?.extensions) &&
        packageJson.openclaw.extensions.includes("./index.ts"),
      `Plugin entry missing: ${id}`,
    );
    regularFile(join(root, "dist", "extensions", id, "index.js"));
    const builtPackage = json(join(root, "dist", "extensions", id, "package.json"));
    need(
      builtPackage.name === packageJson.name && builtPackage.version === packageJson.version,
      `Compiled plugin package identity changed: ${id}`,
    );
    if (id === "codex") {
      need(
        packageJson.name === "@openclaw/codex" && packageJson.version === version,
        "Codex plugin package does not match the image host",
      );
      need(atLeast(packageJson.version, "2026.9.7"), "Codex plugin predates admission minimum");
      need(
        packageJson.openclaw.compat?.pluginApi === `>=${version}` &&
          packageJson.openclaw.build?.openclawVersion === version,
        "Codex plugin API/build compatibility differs from the image host",
      );
      need(
        descriptor.providers?.includes("codex") &&
          descriptor.doctorContract?.configRepair === true &&
          descriptor.doctorContract?.stateMigrations?.length > 0,
        "Codex Doctor contract missing from image",
      );
    } else if (id === "workboard") {
      need(
        packageJson.name === "@openclaw/workboard" &&
          packageJson.version === version &&
          packageJson.peerDependencies?.openclaw === `>=${version}`,
        "Workboard plugin compatibility differs from the image host",
      );
      need(
        packageJson.openclaw.build?.workerEntries?.includes("./src/sqlite-store.worker.ts"),
        "Workboard native worker declaration missing",
      );
      regularFile(join(root, "dist/extensions/workboard/src/sqlite-store.worker.js"));
    }
    inspected.push({ id, package: packageJson.name, version: packageJson.version });
  }
  const directory = mkdtempSync(join(tmpdir(), "openclaw-image-plugin-proof-"));
  try {
    const env = runtimeEnvironment(directory);
    for (const entry of inspected) {
      if (entry.id === "codex") {
        const { native, evidence } = inspectCodexExecutable(root, expectedCodexVersion, env);
        entry.codexRuntime = {
          ...evidence,
          ...(await smokeCodexAppServer(native, env, version, expectedCodexVersion)),
        };
      } else if (entry.id === "workboard") {
        // The native broker and SQLite worker execute in a separately bounded process.
        const result = spawnSync(process.execPath, [SELF, "--workboard", root, directory], {
          cwd: root,
          env,
          encoding: "utf8",
          timeout: 30_000,
          maxBuffer: OUTPUT_LIMIT,
          killSignal: "SIGKILL",
        });
        need(
          !result.error && result.status === 0,
          `Workboard native smoke failed or exceeded its bounds${result.stderr ? `: ${result.stderr.trim()}` : ""}`,
        );
        entry.workboardRuntime = JSON.parse(result.stdout);
        need(
          entry.workboardRuntime?.worker === "sqlite" &&
            entry.workboardRuntime.roundTrip === true &&
            entry.workboardRuntime.closed === true,
          "Workboard native smoke evidence missing",
        );
      }
    }
    return inspected;
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const [root, extensions, version, expectedCodexVersion] = process.argv.slice(2);
    const proof =
      root === "--workboard"
        ? await smokeWorkboardWorker(extensions, version)
        : await inspectImagePlugins(root, extensions, version, expectedCodexVersion);
    process.stdout.write(`${JSON.stringify(proof)}\n`);
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
