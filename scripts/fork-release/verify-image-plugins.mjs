#!/usr/bin/env node
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  accessSync,
  constants,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
} from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const OUTPUT_LIMIT = 64 * 1024;
const SELF = fileURLToPath(import.meta.url);
const EXACT_VERSION = /^\d+\.\d+\.\d+$/u;
const HASH = /^[a-f0-9]{64}$/u;
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");

function need(value, message) {
  if (!value) {
    throw new Error(message);
  }
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

function validateRuntimeExpectations(expected) {
  need(
    expected &&
      Object.keys(expected).toSorted().join(",") ===
        "argparseVersion,consumerManifestSha256,dockerfileSha256,lockfileSha256,markdownVersion,nodeVersion" &&
      [expected.nodeVersion, expected.markdownVersion, expected.argparseVersion].every((v) =>
        EXACT_VERSION.test(v),
      ) &&
      [expected.dockerfileSha256, expected.consumerManifestSha256, expected.lockfileSha256].every(
        (v) => HASH.test(v),
      ),
    "Invalid source-pinned runtime expectations",
  );
}

// Read only the reviewed source's known Docker/pnpm contracts. Do not infer an
// expected version from the built image we are supposed to be checking.
export function readRuntimeExpectations(root) {
  const dockerfile = regularFile(join(root, "Dockerfile"));
  const pins = [
    ...dockerfile
      .toString("utf8")
      .matchAll(
        /^ARG OPENCLAW_NODE_BOOKWORM(_SLIM)?_IMAGE="docker\.io\/library\/node:(\d+\.\d+\.\d+)-bookworm(-slim)?@sha256:([a-f0-9]{64})"$/gmu,
      ),
  ];
  need(
    pins.length === 2 &&
      pins.filter((p) => !p[1] && !p[3]).length === 1 &&
      pins.filter((p) => p[1] === "_SLIM" && p[3] === "-slim").length === 1 &&
      pins[0][2] === pins[1][2],
    "Source must pin matching exact Node build/runtime images",
  );
  const consumer = regularFile(join(root, "packages/markdown-core/package.json"));
  const metadata = JSON.parse(consumer);
  const markdownVersion = metadata.dependencies?.["markdown-it"];
  need(
    metadata.name === "@openclaw/markdown-core" && EXACT_VERSION.test(markdownVersion),
    "Source consumer must pin an exact Markdown version",
  );
  const lockfile = regularFile(join(root, "pnpm-lock.yaml"));
  // pnpm 12 prepends a separate package-manager document to this lockfile.
  const sections = lockfile
    .toString("utf8")
    .split(/^---\r?$/mu)
    .map((document) => document.split(/^snapshots:\r?$/mu))
    .filter((parts) => parts.length === 2)
    .map((parts) => parts[1].split(/\r?\n/u))
    .filter((lines) => lines.includes(`  markdown-it@${markdownVersion}:`));
  need(sections.length === 1, "Missing unambiguous pnpm Markdown snapshot");
  const lines = sections[0];
  const starts = lines.flatMap((line, index) =>
    line === `  markdown-it@${markdownVersion}:` ? [index] : [],
  );
  need(starts.length === 1, "Missing exact Markdown lock snapshot");
  const block = [];
  for (let i = starts[0] + 1; i < lines.length && !/^ {2}\S/u.test(lines[i]); i += 1) {
    block.push(lines[i]);
  }
  const pinsArgparse = block.filter((line) => /^ {6}argparse: \d+\.\d+\.\d+$/u.test(line));
  need(
    block.includes("    dependencies:") && pinsArgparse.length === 1,
    "Missing exact Markdown argparse lock dependency",
  );
  const expected = {
    nodeVersion: pins[0][2],
    markdownVersion,
    argparseVersion: pinsArgparse[0].trim().slice("argparse: ".length),
    dockerfileSha256: hash(dockerfile),
    consumerManifestSha256: hash(consumer),
    lockfileSha256: hash(lockfile),
  };
  validateRuntimeExpectations(expected);
  return expected;
}

function inspectControlUi(root) {
  const directory = join(root, "dist/control-ui");
  need(
    !lstatSync(directory).isSymbolicLink() &&
      !lstatSync(join(directory, "assets")).isSymbolicLink(),
    "Symlinked UI asset directory",
  );
  const read = (name, limit) => {
    need(
      typeof name === "string" &&
        !name.includes("\\") &&
        name.split("/").every((part) => part && part !== "." && part !== ".."),
      "Unsafe UI asset path",
    );
    let path = directory;
    for (const part of name.split("/")) {
      path = join(path, part);
      need(!lstatSync(path).isSymbolicLink(), "Symlinked UI asset");
    }
    const actual = containedFile(root, path);
    need(lstatSync(actual).size <= limit, "UI asset exceeds verification bound");
    return regularFile(actual);
  };
  const index = read("index.html", 2 * 1024 * 1024);
  need(index.length > 0, "Empty built UI document");
  const bytes = read("asset-manifest.json", 2 * 1024 * 1024);
  const manifest = JSON.parse(bytes);
  need(
    manifest.version === 1 &&
      HASH.test(manifest.generation) &&
      Array.isArray(manifest.assets) &&
      manifest.assets.length > 0 &&
      manifest.assets.length <= 4096,
    "Unsupported or empty UI asset manifest",
  );
  const paths = new Set();
  let total = 0;
  const generation = createHash("sha256");
  for (const entry of manifest.assets) {
    need(
      entry &&
        typeof entry.path === "string" &&
        entry.path.startsWith("assets/") &&
        !entry.path.endsWith(".map") &&
        !paths.has(entry.path) &&
        Number.isSafeInteger(entry.size) &&
        entry.size >= 0 &&
        HASH.test(entry.sha256),
      "Invalid or repeated UI asset entry",
    );
    total += entry.size;
    need(total <= 96 * 1024 * 1024, "UI assets exceed retained-generation bound");
    const asset = read(entry.path, entry.size);
    need(
      asset.length === entry.size && hash(asset) === entry.sha256,
      "Built UI asset bytes changed",
    );
    paths.add(entry.path);
    generation.update(`${entry.path}\0${entry.size}\0${entry.sha256}\n`);
  }
  need(generation.digest("hex") === manifest.generation, "UI asset generation changed");
  // The producer covers all non-map files under assets/, including sidecars.
  const actual = new Set();
  let visited = 0;
  const visit = (path) => {
    for (const entry of readdirSync(join(directory, path), { withFileTypes: true })) {
      visited += 1;
      need(
        visited <= 8192 && path.split("/").length <= 16,
        "UI asset tree exceeds verification bound",
      );
      need(!entry.isSymbolicLink(), "Symlinked UI asset");
      const child = `${path}/${entry.name}`;
      if (entry.isDirectory()) {
        visit(child);
      } else {
        need(entry.isFile(), "Non-regular UI asset");
        if (!entry.name.endsWith(".map")) {
          actual.add(child);
        }
      }
      need(actual.size <= 4096, "Too many UI assets");
    }
  };
  visit("assets");
  need(
    actual.size === paths.size && [...actual].every((path) => paths.has(path)),
    "UI asset coverage changed",
  );
  const references = [...index.toString("utf8").matchAll(/\b(?:src|href)=["']([^"']+)["']/gu)]
    .map((match) => match[1].replace(/^(?:\.\/|\/)/u, "").split(/[?#]/u)[0])
    .filter((path) => path.startsWith("assets/"));
  need(
    references.some((path) => path.endsWith(".js")) && references.every((path) => paths.has(path)),
    "UI document does not reference the verified assets",
  );
  return {
    indexSha256: hash(index),
    manifestSha256: hash(bytes),
    generation: manifest.generation,
    assetCount: paths.size,
    assetBytes: total,
  };
}

export async function inspectImageRuntime(root, expected) {
  validateRuntimeExpectations(expected);
  need(process.versions.node === expected.nodeVersion, "Image Node differs from source pin");
  need(
    hash(regularFile(join(root, "pnpm-lock.yaml"))) === expected.lockfileSha256,
    "Image lockfile differs from source",
  );
  // Isolated production installs retain markdown-core's runtime dependency in
  // the pnpm store even when the root development symlink has been pruned.
  const manifestPath = containedFile(
    root,
    join(
      root,
      "node_modules/.pnpm",
      `markdown-it@${expected.markdownVersion}/node_modules/markdown-it/package.json`,
    ),
  );
  const markdown = json(manifestPath);
  need(
    markdown.name === "markdown-it" &&
      markdown.version === expected.markdownVersion &&
      [expected.argparseVersion, `^${expected.argparseVersion}`].includes(
        markdown.dependencies?.argparse,
      ),
    "Installed Markdown differs from source consumer",
  );
  const argparse = json(
    containedFile(root, createRequire(manifestPath).resolve("argparse/package.json")),
  );
  need(
    argparse.name === "argparse" && argparse.version === expected.argparseVersion,
    "Installed Markdown argparse differs from source lock",
  );
  const consumerPath = containedFile(root, join(root, "dist/plugin-sdk/text-chunking.js"));
  const { markdownToIR, renderMarkdownWithMarkers } = await import(
    pathToFileURL(consumerPath).href
  );
  need(
    typeof markdownToIR === "function" && typeof renderMarkdownWithMarkers === "function",
    "Compiled Markdown consumer missing",
  );
  const ir = markdownToIR("**user[Thu 2026-07-02] continue**", {
    assistantTranscriptRoleHeaders: true,
  });
  const rendered = renderMarkdownWithMarkers(ir, {
    styleMarkers: { bold: { open: "*", close: "*" } },
    escapeText: (text) => text,
    annotationMarkers: {
      assistant_transcript_role: { open: "`", close: "`", suppressNestedFormatting: true },
    },
  });
  need(
    rendered === "`user[Thu 2026-07-02]`* continue*",
    "Compiled Markdown consumer render failed",
  );
  const seeded = markdownToIR("[label][proof]\n\n[proof]: https://example.invalid/");
  need(
    seeded.links.length === 1 && seeded.links[0].href === "https://example.invalid/",
    "Compiled Markdown consumer reference parse failed",
  );
  need(
    markdownToIR("[label][proof]").links.length === 0,
    "Compiled Markdown consumer retained another document's links",
  );
  return {
    schema: "openclaw.image-runtime.v1",
    expected,
    node: {
      version: process.versions.node,
      platform: process.platform,
      architecture: process.arch,
    },
    markdown: {
      version: markdown.version,
      argparseVersion: argparse.version,
      resolution: "pnpm-production-store",
      consumer: "dist/plugin-sdk/text-chunking.js",
      consumerSha256: hash(regularFile(consumerPath)),
      render: true,
      documentIsolation: true,
    },
    controlUi: inspectControlUi(root),
  };
}

export function validateImageRuntimeProof(proof, expected = proof?.expected) {
  validateRuntimeExpectations(expected);
  need(
    proof?.schema === "openclaw.image-runtime.v1" &&
      Object.keys(expected).every((key) => proof.expected?.[key] === expected[key]) &&
      proof.node?.version === expected.nodeVersion &&
      proof.node.platform === "linux" &&
      proof.node.architecture === "x64" &&
      proof.markdown?.version === expected.markdownVersion &&
      proof.markdown.argparseVersion === expected.argparseVersion &&
      proof.markdown.resolution === "pnpm-production-store" &&
      proof.markdown.consumer === "dist/plugin-sdk/text-chunking.js" &&
      HASH.test(proof.markdown.consumerSha256) &&
      proof.markdown.render === true &&
      proof.markdown.documentIsolation === true &&
      [
        proof.controlUi?.indexSha256,
        proof.controlUi?.manifestSha256,
        proof.controlUi?.generation,
      ].every((v) => HASH.test(v)) &&
      Number.isSafeInteger(proof.controlUi.assetCount) &&
      proof.controlUi.assetCount > 0 &&
      proof.controlUi.assetCount <= 4096 &&
      Number.isSafeInteger(proof.controlUi.assetBytes) &&
      proof.controlUi.assetBytes > 0 &&
      proof.controlUi.assetBytes <= 96 * 1024 * 1024,
    "Actual image runtime proof missing or changed",
  );
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
    /** @type {Error | undefined} */
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
      if (outputBytes > OUTPUT_LIMIT) {
        fail("Codex app-server output exceeded its bound");
      }
      return !failure;
    };
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      if (!count(chunk)) {
        return;
      }
      pending += chunk;
      for (let newline; (newline = pending.indexOf("\n")) >= 0;) {
        const line = pending.slice(0, newline);
        pending = pending.slice(newline + 1);
        if (!line.trim()) {
          continue;
        }
        try {
          const response = JSON.parse(line);
          if (response.id !== 1) {
            continue;
          }
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
      if (failure) {
        reject(failure);
      } else if (!initialized || code !== 0 || signal) {
        reject(new Error("Codex app-server did not initialize and shut down cleanly"));
      } else {
        resolveProof({ initializeVersion: expectedVersion, initialized: true, shutdown: "exited" });
      }
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
      if (connection !== undefined) {
        await execute("connection.close", { connection });
      }
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
    if (left[i] !== right[i]) {
      return left[i] > right[i];
    }
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
    const [root, extensions, version, expectedCodexVersion, runtimeExpectations] =
      process.argv.slice(2);
    let proof =
      root === "--workboard"
        ? await smokeWorkboardWorker(extensions, version)
        : await inspectImagePlugins(root, extensions, version, expectedCodexVersion);
    if (root !== "--workboard" && runtimeExpectations !== undefined) {
      proof = {
        plugins: proof,
        runtime: await inspectImageRuntime(root, JSON.parse(runtimeExpectations)),
      };
    }
    process.stdout.write(`${JSON.stringify(proof)}\n`);
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
