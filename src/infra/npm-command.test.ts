import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { resolveNpmCommand } from "./npm-command.js";

const cliPath = path.join(
  path.dirname(createRequire(import.meta.url).resolve("npm/package.json")),
  "bin",
  "npm-cli.js",
);

const originalVersions = process.versions;
afterEach(() => {
  Object.defineProperty(process, "versions", { value: originalVersions });
  vi.restoreAllMocks();
});

describe("npm invocation", () => {
  it.each([
    { bun: undefined, args: ["view", "@openclaw/irc", "version"], command: [process.execPath, cliPath] },
    { bun: "1.4.2", args: ["install", "--ignore-scripts"], command: [process.execPath, cliPath] },
  ])("preserves npm arguments with Bun version $bun", ({ bun, args, command }) => {
    Object.defineProperty(process, "versions", { value: { ...originalVersions, bun } });
    const stat = vi.spyOn(fs, "statSync");
    expect(resolveNpmCommand(args)).toEqual([...command, ...args]);
    expect(stat).toHaveBeenCalledWith(cliPath);
  });

  it.each([undefined, "1.4.2"])("fails closed on missing bundled npm under Bun version %s", (bun) => {
    Object.defineProperty(process, "versions", { value: { ...originalVersions, bun } });
    vi.spyOn(fs, "statSync").mockImplementation(() => {
      throw Object.assign(new Error("missing"), { code: "ENOENT" });
    });
    expect(() => resolveNpmCommand(["install"])).toThrow(
      expect.objectContaining({
        name: "BundledNpmCliNotFoundError",
        code: "BUNDLED_NPM_CLI_NOT_FOUND",
        cause: expect.objectContaining({ code: "ENOENT" }),
      }),
    );
    expect(() => resolveNpmCommand(["install"])).toThrow(cliPath);
  });
});
