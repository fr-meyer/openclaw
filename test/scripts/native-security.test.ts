import { fileURLToPath } from "node:url";
import { expect, it } from "vitest";
import {
  listNativeSecurityTests,
  runNativeTests,
} from "../../scripts/fork-release/native_tests.mjs";

// These files use node:test. One Node suite executes them; Vitest owns only
// this adapter and must never collect the native files as empty Vitest suites.
it("runs the maintained native security and legacy MCP contracts", () => {
  const sourceRoot = fileURLToPath(new URL("../../", import.meta.url));
  const result = runNativeTests({ sourceRoot, testFiles: listNativeSecurityTests(sourceRoot) });
  expect(result.status, result.error ?? result.signal ?? "native suite failed").toBe(0);
}, 120_000);
