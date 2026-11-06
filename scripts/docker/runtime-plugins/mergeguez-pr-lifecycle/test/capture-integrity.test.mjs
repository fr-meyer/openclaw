import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { __testing } from "../src/runtime.mjs";

const pluginRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const runtimePath = join(pluginRoot, "src", "runtime.mjs");
const runtimeBytes = readFileSync(runtimePath);
const pin = createHash("sha256").update(runtimeBytes).digest("hex");

function withCaptureFixture(callback) {
  const root = mkdtempSync(join(dirname(fileURLToPath(import.meta.url)), "capture-proof-"));
  const originalRoot = join(root, "installed");
  const originalEntry = join(originalRoot, "index.mjs");
  const originalRuntime = join(originalRoot, "src", "runtime.mjs");
  const stateDir = join(root, ".openclaw");
  const captureRuntime = join(
    stateDir,
    "tmp",
    "plugin-captures",
    "openclaw-plugin-build-fixture",
    "src",
    "runtime.mjs",
  );
  const previousStateDir = process.env.OPENCLAW_STATE_DIR;
  try {
    mkdirSync(dirname(originalRuntime), { recursive: true });
    mkdirSync(dirname(captureRuntime), { recursive: true });
    writeFileSync(originalEntry, "export default {};\n");
    copyFileSync(runtimePath, originalRuntime);
    copyFileSync(runtimePath, captureRuntime);
    process.env.OPENCLAW_STATE_DIR = stateDir;
    const options = {
      loadedPath: captureRuntime,
      rootDir: originalRoot,
      source: originalEntry,
      runtimeSource: originalEntry,
    };
    callback({ root, originalRoot, originalRuntime, captureRuntime, options });
  } finally {
    if (previousStateDir === undefined) delete process.env.OPENCLAW_STATE_DIR;
    else process.env.OPENCLAW_STATE_DIR = previousStateDir;
    rmSync(root, { recursive: true, force: true });
  }
}

void test("packaged runtime accepts only an identity-bound, equal-hash managed capture", () => {
  withCaptureFixture(({ root, originalRuntime, captureRuntime, options }) => {
    const check = (overrides = {}, expectedPath = originalRuntime, expectedPin = pin) =>
      __testing.runtimeSourceIntegrity(expectedPath, expectedPin, { ...options, ...overrides });
    assert.equal(check().verified, true);
    assert.equal(check().durable, false);
    assert.equal(check({}, originalRuntime, "0".repeat(64)).verified, false);
    assert.equal(check({}, join(root, "wrong", "runtime.mjs")).verified, false);
    assert.equal(check({ source: join(root, "wrong", "index.mjs") }).verified, false);
    assert.equal(check({ runtimeSource: join(root, "wrong", "index.mjs") }).verified, false);

    const unrelatedCopy = join(root, "unrelated", "src", "runtime.mjs");
    mkdirSync(dirname(unrelatedCopy), { recursive: true });
    copyFileSync(runtimePath, unrelatedCopy);
    assert.equal(check({ loadedPath: unrelatedCopy }).verified, false);

    writeFileSync(originalRuntime, `${runtimeBytes.toString("utf8")}\n`);
    assert.equal(check().verified, false);
    copyFileSync(runtimePath, originalRuntime);
    writeFileSync(captureRuntime, `${runtimeBytes.toString("utf8")}\n`);
    assert.equal(check().verified, false);
  });
});

void test("packaged runtime rejects a temporary original hidden behind a durable symlink", () => {
  withCaptureFixture(({ root, captureRuntime }) => {
    const temporaryOriginal = mkdtempSync(join(tmpdir(), "mergeguez-disposable-original-"));
    try {
      const temporaryEntry = join(temporaryOriginal, "index.mjs");
      const temporaryRuntime = join(temporaryOriginal, "src", "runtime.mjs");
      mkdirSync(dirname(temporaryRuntime), { recursive: true });
      writeFileSync(temporaryEntry, "export default {};\n");
      copyFileSync(runtimePath, temporaryRuntime);
      const linkedRoot = join(root, "linked-installed");
      symlinkSync(temporaryOriginal, linkedRoot, "dir");
      assert.equal(
        __testing.runtimeSourceIntegrity(join(linkedRoot, "src", "runtime.mjs"), pin, {
          loadedPath: captureRuntime,
          rootDir: linkedRoot,
          source: join(linkedRoot, "index.mjs"),
          runtimeSource: join(linkedRoot, "index.mjs"),
        }).verified,
        false,
      );
    } finally {
      rmSync(temporaryOriginal, { recursive: true, force: true });
    }
  });
});
