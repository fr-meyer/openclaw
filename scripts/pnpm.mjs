// Source-checkout pnpm entrypoint; bootstrap, shims and caches stay in this checkout.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { constants as osConstants } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { isSupportedOpenClawNodeVersion } from "../node-version.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const source = path.join(root, "scripts", "pnpm-bootstrap");
const manifest = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8"));
const pin = /^pnpm@(\d+\.\d+\.\d+)\+sha512\.[a-f0-9]{128}$/u.exec(manifest.packageManager);
if (!pin) {
  throw new Error("package.json must pin an exact pnpm version with SHA-512 integrity.");
}
if (!isSupportedOpenClawNodeVersion(process.versions.node)) {
  throw new Error(`Node ${process.versions.node} does not satisfy ${manifest.engines.node}.`);
}

// A new bootstrap lock gets its own directory; never replace a shared/global install.
const lock = readFileSync(path.join(source, "package-lock.json"));
const bootstrapManifest = readFileSync(path.join(source, "package.json"));
const bootstrapVersion = JSON.parse(bootstrapManifest).dependencies.corepack;
const key = createHash("sha256").update(bootstrapManifest).update(lock).digest("hex").slice(0, 16);
const local = path.join(root, ".local", "toolchain");
const bootstrap = path.join(local, `bootstrap-${key}`);
const corepack = path.join(bootstrap, "node_modules", "corepack", "dist", "corepack.js");
const bin = path.join(bootstrap, "node_modules", ".bin");
const env = {
  ...process.env,
  COREPACK_HOME: path.join(local, "corepack-home"),
  COREPACK_DEFAULT_TO_LATEST: "0",
  COREPACK_ENABLE_AUTO_PIN: "0",
  COREPACK_ENABLE_DOWNLOAD_PROMPT: "0",
  COREPACK_ENABLE_PROJECT_SPEC: "1",
  COREPACK_ENABLE_STRICT: "1",
  COREPACK_NPM_REGISTRY: "https://registry.npmjs.org",
  PNPM_HOME: bin,
  PNPM_CONFIG_STORE_DIR: process.env.PNPM_CONFIG_STORE_DIR || path.join(local, "pnpm-store"),
  PNPM_CONFIG_CACHE_DIR: process.env.PNPM_CONFIG_CACHE_DIR || path.join(local, "pnpm-cache"),
  npm_config_cache: path.join(local, "npm-cache"),
  PATH: [bin, path.dirname(process.execPath), process.env.PATH || ""].join(path.delimiter),
};
// Private mirror credentials must not follow the forced public registry.
delete env.COREPACK_NPM_TOKEN;
delete env.COREPACK_NPM_USERNAME;
delete env.COREPACK_NPM_PASSWORD;

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { cwd: root, env, stdio: "inherit", ...options });
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    process.exit(result.status ?? 128 + (osConstants.signals[result.signal] ?? 0));
  }
  return result;
}

if (!existsSync(corepack)) {
  if (process.env.COREPACK_ENABLE_NETWORK === "0") {
    throw new Error(
      "Local Corepack is absent. Run node scripts/pnpm.mjs --setup with network access first.",
    );
  }
  mkdirSync(bootstrap, { recursive: true });
  copyFileSync(path.join(source, "package.json"), path.join(bootstrap, "package.json"));
  copyFileSync(path.join(source, "package-lock.json"), path.join(bootstrap, "package-lock.json"));
  // Only Corepack's locked, dependency-free package is installed, with no lifecycle scripts.
  const npmArgs = [
    "ci",
    "--prefix",
    bootstrap,
    "--registry=https://registry.npmjs.org",
    "--ignore-scripts",
    "--bin-links=true",
    "--no-audit",
    "--no-fund",
  ];
  if (process.platform === "win32") {
    // npm's standard installation is a cmd shim; use its JS CLI beside this Node.
    run(process.execPath, [
      path.join(path.dirname(process.execPath), "node_modules/npm/bin/npm-cli.js"),
      ...npmArgs,
    ]);
  } else {
    run("npm", npmArgs);
  }
}
const installedVersion = JSON.parse(
  readFileSync(path.join(bootstrap, "node_modules", "corepack", "package.json"), "utf8"),
).version;
if (installedVersion !== bootstrapVersion) {
  throw new Error(`Local Corepack ${installedVersion} differs from locked ${bootstrapVersion}.`);
}
for (const name of ["corepack", "pnpm"]) {
  const shim = path.join(bin, process.platform === "win32" ? `${name}.cmd` : name);
  if (!existsSync(shim)) {
    throw new Error(
      `Local ${name} shim is missing from ${bin}; bootstrap installation is incomplete.`,
    );
  }
}

const setup = process.argv.slice(2).join(" ") === "--setup";
if (setup) {
  const result = run(process.execPath, [corepack, "pnpm", "--version"], {
    stdio: ["inherit", "pipe", "inherit"],
    encoding: "utf8",
  });
  const version = result.stdout.trim();
  if (version !== pin[1]) {
    throw new Error(`Expected pnpm ${pin[1]}, got ${version}.`);
  }
  console.log(`Node ${process.versions.node}; Corepack ${installedVersion}; pnpm ${version}`);
  console.log(`Local tools: ${bin}`);
} else {
  run(process.execPath, [corepack, "pnpm", ...process.argv.slice(2)]);
}
