import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import vm from "node:vm";
import { parse } from "acorn";
import { describe, expect, it, vi } from "vitest";
import {
  createStandaloneCodegenAdapter,
  createStandaloneCodegenTransform,
} from "../../scripts/lib/bun-standalone-codegen.mjs";

const program = {
  signature: "SOURCE\nreturn value + prefix;",
  code: "const prefix = 3;\nreturn value + prefix;",
  params: ["value"],
};

describe("standalone fixed code generation", () => {
  it.each(["//#region", "//"])(
    "recognizes bundled source owners and receiver (%s)",
    async (label) => {
      const root = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-standalone-label-"));
      const runtimeRoot = path.join(root, "runtime");
      const distRoot = path.join(runtimeRoot, "dist");
      fs.mkdirSync(path.join(distRoot, "worker"), { recursive: true });
      const owners = [
        ["staged-inputs", "src/media/staged-inputs.ts"],
        ["sandbox-workspace-paths", "src/shared/sandbox-workspace-paths.ts"],
        ["workspace-manifest", "src/gateway/worker-environments/workspace-path-exclusions.ts"],
        ["workspace-hash-memo", "src/gateway/worker-environments/workspace-hash-memo.ts"],
        [
          "workspace-manifest-script.runtime",
          "src/gateway/worker-environments/workspace-manifest-script.runtime.ts",
        ],
        ["workspace-seed-retention", "src/worker/workspace-seed-retention.ts"],
      ];
      for (const [entry, owner] of owners) {
        fs.writeFileSync(path.join(distRoot, `${entry}-fixture.mjs`), `${label} ${owner}\n`);
      }
      const receiver = path.join(distRoot, "worker", "workspace-rsync-receiver.mjs");
      fs.writeFileSync(
        receiver,
        `import { compileFunction } from "node:vm";
const REMOTE_WORKSPACE_ACCEPTED_RSYNC_RECEIVER_JS = "return 41;";
const REMOTE_WORKSPACE_RSYNC_RECEIVER_JS = "return 42;";
${label} src/worker/workspace-rsync-receiver.ts
export const select = (accepted) => compileFunction(accepted ? REMOTE_WORKSPACE_ACCEPTED_RSYNC_RECEIVER_JS : REMOTE_WORKSPACE_RSYNC_RECEIVER_JS, ["require"]);`,
      );
      let capturedReceiver = "";
      vi.stubGlobal("Bun", {
        build: async ({ plugins }: { plugins: Array<{ setup: (build: unknown) => void }> }) => {
          let onLoad: ((input: { path: string }) => Promise<{ contents: string }>) | undefined;
          const plugin = plugins[0];
          if (!plugin) {
            throw new Error("Missing standalone capture plugin");
          }
          plugin.setup({
            onLoad: (_filter: unknown, callback: typeof onLoad) => {
              onLoad = callback;
            },
          });
          if (!onLoad) {
            throw new Error("Missing standalone capture loader");
          }
          capturedReceiver = (await onLoad({ path: receiver })).contents;
          return { success: false, logs: [] };
        },
      });
      try {
        await expect(
          createStandaloneCodegenAdapter({
            runtimeRoot,
            outputRoot: path.join(root, "output"),
            parse,
          }),
        ).rejects.toThrow("Static program capture build failed");
        expect(capturedReceiver).toContain("__openclawCaptureStaticFunction");
      } finally {
        vi.unstubAllGlobals();
        fs.rmSync(root, { recursive: true, force: true });
      }
    },
  );

  it("emits an executable lexical function and respects a shadowed compiler binding", () => {
    const transform = createStandaloneCodegenTransform({ programs: [program], parse });
    const source = `import { compileFunction as compile } from "node:vm";
const SOURCE = "const prefix = 3;";
const fn = compile(\`\${SOURCE}\nreturn value + prefix;\`, ["value"]);
function local(compile) { return compile("not a fixed program"); }
[fn(4), local(() => 11)];`;
    const result = transform.transform({ filename: "/runtime/dist/example.mjs", contents: source });
    expect(result.count).toBe(1);
    expect(vm.runInNewContext(result.contents.slice(result.contents.indexOf("\n") + 1))).toEqual([
      7, 11,
    ]);
    expect(transform.residuals).toEqual([]);
  });

  it("records unsupported runtime programs instead of inventing captured behavior", () => {
    const transform = createStandaloneCodegenTransform({ programs: [program], parse });
    const source = `import { compileFunction } from "node:vm";
export const dynamic = (source) => compileFunction(source, []);`;
    expect(transform.transform({ filename: "dynamic.mjs", contents: source }).contents).toBe(
      source,
    );
    expect(transform.residuals).toEqual([
      { filename: "dynamic.mjs", expression: "compileFunction(source, [])" },
    ]);
  });

  it.each([false, true])("preserves JIT library behavior unless AOT is requested (%s)", (aot) => {
    const transform = createStandaloneCodegenTransform({ programs: [], parse, aot });
    const source = "Error.stackTraceLimit = 9; delete Error.prepareStackTrace;";
    const result = transform.transform({ filename: "library.mjs", contents: source });
    expect(result.guardedIntrinsicWrites).toBe(aot ? 2 : 0);
    if (!aot) {
      expect(result.contents).toBe(source);
    }
    const Error = Object.freeze({ stackTraceLimit: 2, prepareStackTrace: undefined });
    if (aot) {
      expect(() => vm.runInNewContext(`'use strict'; ${result.contents}`, { Error })).not.toThrow();
      expect(Error.stackTraceLimit).toBe(2);
    } else {
      expect(() => vm.runInNewContext(`'use strict'; ${result.contents}`, { Error })).toThrow();
    }
  });

  it("only disables TypeBox acceleration in AOT mode", () => {
    const source = "export function CanEvaluate() { return true; }";
    const filename = "/runtime/node_modules/typebox/build/system/environment/evaluate.mjs";
    for (const aot of [false, true]) {
      const transform = createStandaloneCodegenTransform({ programs: [], parse, aot });
      const result = transform.transform({ filename, contents: source });
      const evaluate = vm.runInNewContext(
        `${result.contents.replace("export ", "")} CanEvaluate;`,
        {
          Settings: { Get: () => ({ useAcceleration: false }) },
        },
      );
      expect(evaluate()).toBe(!aot);
      if (!aot) {
        expect(result.contents).toBe(source);
      }
    }
  });
});
