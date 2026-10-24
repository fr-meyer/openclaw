/** Native node:test contracts shared by hosted callers and the Vitest owner. */
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, realpathSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { pathToFileURL } from "node:url";

export const NATIVE_SECURITY_ADAPTER = "test/scripts/native-security.test.ts";
export const NATIVE_RUNNER_PROOF = "test/scripts/native-runner.test.ts";
export const OPTIONAL_NATIVE_SECURITY_TEST_FILES = Object.freeze([
  "test/mcp-nowistay-schema-compatibility.test.mjs",
  "test/mcp-nowistay-sdk-regression.test.mjs",
]);
export const NATIVE_SECURITY_TEST_FILES = Object.freeze([
  "test/zod-container-bounds.test.mjs",
  "test/a2ui-native-zod-regression.test.mjs",
  "test/discord-native-zod-regression.test.mjs",
  "test/body-parser-security.test.mjs",
  "test/msal-parent-compat.test.mjs",
  "test/undici-security.test.mjs",
  ...OPTIONAL_NATIVE_SECURITY_TEST_FILES,
]);
const NATIVE_ENV_KEYS = ["PATH", "LANG", "LC_ALL", "TZ", "TMPDIR", "CI"];
const NATIVE_PLATFORM_ENV_KEYS = ["SystemRoot", "SYSTEMROOT", "WINDIR", "TMP", "TEMP"];
const REQUIREMENTS = Object.freeze({
  "test/a2ui-native-zod-regression.test.mjs": {
    resolveVia: "@modelcontextprotocol/sdk/client/index.js",
    package: "ajv",
    version: "8.20.0",
    environmentKey: "A2UI_TEST_VALIDATOR_PROJECT",
  },
});

export function nativeSecurityAdapterForPath(file) {
  if (typeof file !== "string") {
    return null;
  }
  const normalized = file.replaceAll("\\", "/").replace(/^\.\//u, "");
  return normalized === NATIVE_SECURITY_ADAPTER ||
    normalized === "scripts/fork-release/native_tests.mjs" ||
    NATIVE_SECURITY_TEST_FILES.includes(normalized)
    ? NATIVE_SECURITY_ADAPTER
    : null;
}

export function nativeSecurityTargetsForPath(file) {
  if (typeof file !== "string") {
    return null;
  }
  const normalized = file.replaceAll("\\", "/").replace(/^\.\//u, "");
  if (normalized === "scripts/fork-release/native_tests.mjs") {
    return [NATIVE_SECURITY_ADAPTER, NATIVE_RUNNER_PROOF];
  }
  const adapter = nativeSecurityAdapterForPath(normalized);
  return adapter ? [adapter] : null;
}

function sourceDirectory(sourceRoot) {
  if (typeof sourceRoot !== "string" || !sourceRoot.trim()) {
    throw new Error("An explicit source root is required");
  }
  const root = realpathSync(path.resolve(sourceRoot));
  if (!statSync(root).isDirectory()) {
    throw new Error("Source root must be a directory");
  }
  return root;
}

function nativeFile(root, file) {
  if (
    typeof file !== "string" ||
    path.isAbsolute(file) ||
    /[\\\0\r\n]/u.test(file) ||
    file.split("/").some((part) => part === "." || part === ".." || !part) ||
    !/\.(?:test|e2e)\.mjs$/u.test(file)
  ) {
    throw new Error("Invalid native test path");
  }
  const actual = realpathSync(path.join(root, file));
  if (!actual.startsWith(root + path.sep) || !statSync(actual).isFile()) {
    throw new Error("Native test must be a file inside the source root");
  }
  return file;
}

export function listNativeSecurityTests(sourceRoot) {
  const root = sourceDirectory(sourceRoot);
  const ownsLegacyMcp = existsSync(
    path.join(root, "src/agents/mcp-http-tool-schema-compatibility.ts"),
  );
  return NATIVE_SECURITY_TEST_FILES.filter(
    (file) =>
      !OPTIONAL_NATIVE_SECURITY_TEST_FILES.includes(file) ||
      ownsLegacyMcp ||
      existsSync(path.join(root, file)),
  ).map((file) => nativeFile(root, file));
}

export function nativeChildEnv(sourceRoot, testFiles, parentEnv = process.env) {
  const root = sourceDirectory(sourceRoot);
  const env = Object.fromEntries(NATIVE_ENV_KEYS.map((key) => [key, parentEnv[key] ?? ""]));
  for (const key of NATIVE_PLATFORM_ENV_KEYS) {
    if (typeof parentEnv[key] === "string") {
      env[key] = parentEnv[key];
    }
  }
  if (!env.PATH) {
    throw new Error("Native tests require the configured Node PATH");
  }
  for (const file of testFiles) {
    const requirement = REQUIREMENTS[file];
    if (!requirement) {
      continue;
    }
    // Metadata resolution is lazy: importing this module before installation
    // never loads candidate packages or attempts to locate a validator.
    const source = createRequire(path.join(root, "package.json"));
    const owner = createRequire(source.resolve(requirement.resolveVia));
    const manifest = owner.resolve(`${requirement.package}/package.json`);
    if (JSON.parse(readFileSync(manifest, "utf8")).version !== requirement.version) {
      throw new Error(`Native A2UI gate requires frozen Ajv ${requirement.version}`);
    }
    env[requirement.environmentKey] = path.dirname(manifest);
  }
  return env;
}

export function runNativeTests({
  sourceRoot,
  testFiles,
  completedVitestFiles = [],
  parentEnv = process.env,
}) {
  if (process.versions.bun) {
    throw new Error("Native node:test contracts require the supported Node runtime");
  }
  const root = sourceDirectory(sourceRoot);
  if (!Array.isArray(testFiles) || !Array.isArray(completedVitestFiles)) {
    throw new Error("Test selections must be arrays");
  }
  let selected = [...new Set(testFiles.map((file) => nativeFile(root, file)))];
  const coveredByAdapter = completedVitestFiles.includes(NATIVE_SECURITY_ADAPTER);
  if (coveredByAdapter) {
    const adapter = realpathSync(path.join(root, NATIVE_SECURITY_ADAPTER));
    if (!adapter.startsWith(root + path.sep) || !statSync(adapter).isFile()) {
      throw new Error("Completed native adapter must exist inside the source root");
    }
    const covered = new Set(listNativeSecurityTests(root));
    selected = selected.filter((file) => !covered.has(file));
  }
  if (!selected.length) {
    if (!coveredByAdapter) {
      throw new Error("No native tests selected");
    }
    return { status: 0, signal: null, error: undefined, testFiles: [], coveredByAdapter: true };
  }
  const result = spawnSync(
    process.execPath,
    ["--test", "--test-concurrency=1", "--test-timeout=60000", ...selected],
    { cwd: root, env: nativeChildEnv(root, selected, parentEnv), stdio: "inherit", timeout: 90000 },
  );
  return {
    status: result.status ?? 1,
    signal: result.signal,
    error: result.error?.code,
    testFiles: selected,
    coveredByAdapter,
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    const args = process.argv.slice(2);
    let sourceRoot;
    let testFiles;
    const completedVitestFiles = [];
    for (let index = 0; index < args.length; index++) {
      const arg = args[index];
      if (arg === "--") {
        testFiles = args.slice(index + 1);
        break;
      }
      if (arg === "--source-root" && sourceRoot === undefined && args[index + 1]) {
        sourceRoot = args[++index];
      } else if (arg === "--completed-vitest" && args[index + 1]) {
        completedVitestFiles.push(args[++index]);
      } else {
        throw new Error(
          "Usage: native_tests.mjs --source-root PATH [--completed-vitest PATH] -- TEST...",
        );
      }
    }
    if (testFiles === undefined) {
      throw new Error("Native test paths must follow --");
    }
    process.exitCode = runNativeTests({ sourceRoot, testFiles, completedVitestFiles }).status;
  } catch (error) {
    console.error(`[native tests] ${error.message}`);
    process.exitCode = 2;
  }
}
