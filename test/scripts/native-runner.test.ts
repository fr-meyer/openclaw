import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, expect, it } from "vitest";
import {
  NATIVE_SECURITY_ADAPTER,
  NATIVE_SECURITY_TEST_FILES,
  OPTIONAL_NATIVE_SECURITY_TEST_FILES,
  listNativeSecurityTests,
  nativeChildEnv,
  nativeSecurityAdapterForPath,
  runNativeTests,
} from "../../scripts/fork-release/native_tests.mjs";

const roots: string[] = [];
const helper = fileURLToPath(
  new URL("../../scripts/fork-release/native_tests.mjs", import.meta.url),
);
const safeEnv = () => ({
  PATH: process.env.PATH ?? "",
  LANG: "C.UTF-8",
  LC_ALL: "C.UTF-8",
  TZ: "UTC",
  TMPDIR: tmpdir(),
  CI: "true",
});
function put(root: string, file: string, source: string) {
  const target = path.join(root, file);
  mkdirSync(path.dirname(target), { recursive: true });
  writeFileSync(target, source);
  return target;
}
function fixture() {
  const root = mkdtempSync(path.join(tmpdir(), "native-owner-"));
  roots.push(root);
  put(root, "package.json", '{"private":true,"type":"module"}');
  for (const file of NATIVE_SECURITY_TEST_FILES) {
    if (!OPTIONAL_NATIVE_SECURITY_TEST_FILES.includes(file)) {
      put(root, file, 'import test from "node:test"; test("synthetic native member", () => {});');
    }
  }
  return root;
}
function validator(root: string, version = "8.20.0") {
  const sdk = "node_modules/@modelcontextprotocol/sdk";
  put(
    root,
    `${sdk}/package.json`,
    JSON.stringify({
      name: "@modelcontextprotocol/sdk",
      type: "module",
      exports: { "./client/index.js": "./client/index.js" },
    }),
  );
  put(root, `${sdk}/client/index.js`, "export {};");
  return put(
    root,
    `${sdk}/node_modules/ajv/package.json`,
    JSON.stringify({ name: "ajv", version }),
  );
}
afterEach(() => {
  for (const root of roots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

it("keeps the import/ownership mapper dependency-free and precise", () => {
  expect(nativeSecurityAdapterForPath("test\\undici-security.test.mjs")).toBe(
    NATIVE_SECURITY_ADAPTER,
  );
  expect(nativeSecurityAdapterForPath(NATIVE_SECURITY_ADAPTER)).toBe(NATIVE_SECURITY_ADAPTER);
  expect(nativeSecurityAdapterForPath("scripts/fork-release/native_tests.mjs")).toBe(
    NATIVE_SECURITY_ADAPTER,
  );
  expect(nativeSecurityAdapterForPath("scripts/docker/unrelated.test.mjs")).toBeNull();
  const root = fixture();
  const result = spawnSync(
    process.execPath,
    [
      "--input-type=module",
      "-e",
      `await import(${JSON.stringify(new URL("../../scripts/fork-release/native_tests.mjs", import.meta.url).href)});`,
    ],
    { cwd: root, env: safeEnv(), encoding: "utf8", timeout: 5000 },
  );
  expect(result.status, result.stderr).toBe(0);
});

it("owns mandatory security members and only present legacy MCP members", () => {
  const root = fixture();
  expect(listNativeSecurityTests(root)).toHaveLength(6);
  put(
    root,
    "src/agents/mcp-http-tool-schema-compatibility.ts",
    "// synthetic feature ownership metadata",
  );
  expect(() => listNativeSecurityTests(root)).toThrow();
  for (const file of OPTIONAL_NATIVE_SECURITY_TEST_FILES) {
    put(root, file, "// synthetic legacy member");
  }
  expect(listNativeSecurityTests(root)).toEqual(NATIVE_SECURITY_TEST_FILES);
  rmSync(path.join(root, "test/undici-security.test.mjs"));
  expect(() => listNativeSecurityTests(root)).toThrow();
});

it("constructs only the allowlisted child context, not credentials or overrides", () => {
  const root = fixture();
  const parent = {
    ...safeEnv(),
    GITHUB_TOKEN: "synthetic-secret",
    AZURE_CLIENT_SECRET: "synthetic-secret",
    HTTPS_PROXY: "http://synthetic.invalid",
    NODE_OPTIONS: "--require=synthetic-invalid",
    MSAL_TEST_PROJECT: "synthetic-override",
    A2UI_TEST_VALIDATOR_PROJECT: "synthetic-spoof",
  };
  const child = nativeChildEnv(root, ["test/undici-security.test.mjs"], parent);
  expect(child).toEqual(safeEnv());
  const platformEnv = { SystemRoot: "C:\\Windows", TEMP: "C:\\native-fixture-temp" };
  expect(nativeChildEnv(root, [], { ...parent, ...platformEnv })).toEqual({
    ...safeEnv(),
    ...platformEnv,
  });
  expect(parent.GITHUB_TOKEN).toBe("synthetic-secret");
  expect(() => nativeChildEnv(root, [], { PATH: "" })).toThrow(/PATH/);
});

it("computes the frozen validator context only when selected and refuses drift", () => {
  const root = fixture();
  expect(() =>
    nativeChildEnv(root, ["test/a2ui-native-zod-regression.test.mjs"], safeEnv()),
  ).toThrow();
  const manifest = validator(root);
  const child = nativeChildEnv(root, ["test/a2ui-native-zod-regression.test.mjs"], {
    ...safeEnv(),
    A2UI_TEST_VALIDATOR_PROJECT: "synthetic-spoof",
  });
  expect(child).toEqual({ ...safeEnv(), A2UI_TEST_VALIDATOR_PROJECT: path.dirname(manifest) });
  writeFileSync(manifest, '{"name":"ajv","version":"8.21.0"}');
  expect(() =>
    nativeChildEnv(root, ["test/a2ui-native-zod-regression.test.mjs"], safeEnv()),
  ).toThrow(/frozen Ajv/);
});

it("executes an actual Node child with allowed context and no synthetic secrets", () => {
  const root = fixture();
  const marker = path.join(root, "executed.json");
  put(
    root,
    "test/proof.test.mjs",
    `import test from "node:test"; import assert from "node:assert/strict"; import {writeFileSync} from "node:fs";
    test("actual secretless child", () => { for (const key of ["GITHUB_TOKEN","AZURE_CLIENT_SECRET","HTTPS_PROXY","NODE_OPTIONS","MSAL_TEST_PROJECT","A2UI_TEST_VALIDATOR_PROJECT"]) assert.equal(process.env[key], undefined); assert.equal(process.env.CI,"true"); writeFileSync(${JSON.stringify(marker)},JSON.stringify({node:process.versions.node,ci:process.env.CI})); });`,
  );
  const result = runNativeTests({
    sourceRoot: root,
    testFiles: ["test/proof.test.mjs", "test/proof.test.mjs"],
    parentEnv: {
      ...safeEnv(),
      GITHUB_TOKEN: "synthetic-secret",
      AZURE_CLIENT_SECRET: "synthetic-secret",
      HTTPS_PROXY: "http://synthetic.invalid",
      NODE_OPTIONS: "--require=synthetic-invalid",
      MSAL_TEST_PROJECT: "synthetic-override",
      A2UI_TEST_VALIDATOR_PROJECT: "synthetic-spoof",
    },
  });
  expect(result.status).toBe(0);
  expect(result.testFiles).toEqual(["test/proof.test.mjs"]);
  expect(JSON.parse(readFileSync(marker, "utf8"))).toEqual({
    node: process.versions.node,
    ci: "true",
  });
});

it("propagates an actual native failure and refuses invalid or missing selection", () => {
  const root = fixture();
  put(
    root,
    "test/failure.test.mjs",
    'import test from "node:test"; import assert from "node:assert/strict"; test("expected synthetic failure",()=>assert.fail("synthetic regression"));',
  );
  const result = spawnSync(
    process.execPath,
    [helper, "--source-root", root, "--", "test/failure.test.mjs"],
    { cwd: root, env: safeEnv(), encoding: "utf8", timeout: 10000 },
  );
  expect(result.status).toBe(1);
  expect(result.stdout).toContain("synthetic regression");
  expect(() => runNativeTests({ sourceRoot: root, testFiles: [] })).toThrow(/No native/);
  expect(() => runNativeTests({ sourceRoot: root, testFiles: ["../outside.test.mjs"] })).toThrow(
    /Invalid/,
  );
  expect(() =>
    runNativeTests({ sourceRoot: root, testFiles: ["test/missing.test.mjs"] }),
  ).toThrow();
  const outside = fixture();
  const external = put(outside, "test/outside.test.mjs", "// must not execute");
  symlinkSync(external, path.join(root, "test/outside.test.mjs"));
  expect(() => runNativeTests({ sourceRoot: root, testFiles: ["test/outside.test.mjs"] })).toThrow(
    /inside/,
  );
});

it("suppresses only successfully completed adapter members and retains other owners", () => {
  const root = fixture();
  put(root, NATIVE_SECURITY_ADAPTER, "// physical synthetic completion fixture");
  const covered = runNativeTests({
    sourceRoot: root,
    testFiles: ["test/zod-container-bounds.test.mjs"],
    completedVitestFiles: [NATIVE_SECURITY_ADAPTER],
  });
  expect(covered).toMatchObject({ status: 0, testFiles: [], coveredByAdapter: true });
  const cli = spawnSync(
    process.execPath,
    [
      helper,
      "--source-root",
      root,
      "--completed-vitest",
      NATIVE_SECURITY_ADAPTER,
      "--",
      "test/zod-container-bounds.test.mjs",
    ],
    { cwd: root, env: safeEnv(), encoding: "utf8", timeout: 5000 },
  );
  expect(cli.status, cli.stderr).toBe(0);
  expect(cli.stdout).toBe("");
  const marker = path.join(root, "other-owner-executed");
  put(
    root,
    "scripts/docker/owner-proof.test.mjs",
    `import test from "node:test"; import {writeFileSync} from "node:fs"; test("unrelated owner preserved",()=>writeFileSync(${JSON.stringify(marker)},"yes"));`,
  );
  const other = runNativeTests({
    sourceRoot: root,
    testFiles: ["test/zod-container-bounds.test.mjs", "scripts/docker/owner-proof.test.mjs"],
    completedVitestFiles: [NATIVE_SECURITY_ADAPTER],
    parentEnv: safeEnv(),
  });
  expect(other.testFiles).toEqual(["scripts/docker/owner-proof.test.mjs"]);
  expect(readFileSync(marker, "utf8")).toBe("yes");
  rmSync(path.join(root, "test/undici-security.test.mjs"));
  expect(() =>
    runNativeTests({
      sourceRoot: root,
      testFiles: ["test/zod-container-bounds.test.mjs"],
      completedVitestFiles: [NATIVE_SECURITY_ADAPTER],
    }),
  ).toThrow();
});
