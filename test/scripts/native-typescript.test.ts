import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  createNativeTypeScriptParser,
  createNativeTypeScriptProject,
  createNativeTypeScriptProjectAsync,
  type NativeTypeScriptProject,
} from "../../scripts/lib/native-typescript.mts";

describe("native TypeScript source ownership", () => {
  const parser = createNativeTypeScriptParser();
  afterAll(() => parser.close());

  it("replaces batch contents without invalidating already returned syntax trees", () => {
    const [first, second] = parser.parseSourceFiles([
      { fileName: "first.ts", text: "export type First = { value: string };" },
      { fileName: "second.ts", text: "export const second = 2;" },
    ]);
    expect(first?.getText()).toBe("export type First = { value: string };");
    expect(second?.getText()).toBe("export const second = 2;");
    expect(parser.getSyntacticDiagnostics()).toEqual([]);

    parser.parseSourceFiles([]);
    const replacement = parser.parseSourceFile("replacement.ts", "const broken = ;");
    expect(replacement.getText()).toBe("const broken = ;");
    expect(parser.getSyntacticDiagnostics("replacement.ts")).toEqual([
      expect.objectContaining({ code: 1109, text: "Expression expected." }),
    ]);
    expect(first?.getText()).toBe("export type First = { value: string };");
  });

  it("rejects reuse after the owner closes", () => {
    const closedParser = createNativeTypeScriptParser();
    closedParser.close();
    closedParser.close();
    expect(() => closedParser.parseSourceFile("closed.ts", "const value = 1;")).toThrow(
      "Native TypeScript parser is closed",
    );
  });
});

describe("native TypeScript semantic overlays", () => {
  const root = path.resolve(".artifacts", "native-typescript-virtual-fixture");
  const source = path.join(root, "consumer.ts");
  let session: NativeTypeScriptProject;

  beforeAll(() => {
    session = createNativeTypeScriptProject({
      cwd: root,
      configFileName: "tsconfig.json",
      files: {
        "tsconfig.json": JSON.stringify({
          compilerOptions: { noLib: true, strict: true, types: [], module: "nodenext" },
          files: ["consumer.ts"],
        }),
        "consumer.ts": 'import { value } from "./dependency.js"; const count: number = value;',
        "dependency.ts": 'export const value = "text";',
      },
    });
  });
  afterAll(() => session?.close());

  it("resolves virtual dependencies and reports real cross-file type errors", () => {
    expect(session.project.program.getSourceFileNames()).toContain(
      path.join(root, "dependency.ts").split(path.sep).join("/"),
    );
    expect(session.project.program.getSemanticDiagnostics(source)).toEqual([
      expect.objectContaining({
        code: 2322,
        text: "Type 'string' is not assignable to type 'number'.",
      }),
    ]);
  });

  it("keeps a host file hidden when the base callback denies listings", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-native-overlay-"));
    try {
      fs.writeFileSync(path.join(root, "host.ts"), "export const host = 1;");
      const isolated = createNativeTypeScriptProject({
        cwd: root,
        configFileName: "tsconfig.json",
        files: {
          "tsconfig.json": JSON.stringify({
            compilerOptions: { noLib: true, types: [] },
            include: ["*.ts"],
          }),
          "virtual.ts": "export const virtual = 1;",
        },
        fs: {
          readFile: () => undefined,
          fileExists: () => false,
          directoryExists: () => false,
          getAccessibleEntries: () => undefined,
          realpath: (file) => file,
        },
      });
      try {
        const names = isolated.project.program.getSourceFileNames();
        expect(names).toContain(path.join(root, "virtual.ts").split(path.sep).join("/"));
        expect(names).not.toContain(path.join(root, "host.ts").split(path.sep).join("/"));
      } finally {
        isolated.close();
      }
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it("discovers a host symlink through an overlay project glob", () => {
    if (process.platform === "win32") {
      return;
    }
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-native-symlink-"));
    try {
      fs.writeFileSync(path.join(root, "target.ts"), "export const linked = 2;");
      fs.symlinkSync("target.ts", path.join(root, "alias.ts"));
      const linked = createNativeTypeScriptProject({
        cwd: root,
        configFileName: "tsconfig.json",
        files: {
          "tsconfig.json": JSON.stringify({
            compilerOptions: { noLib: true, types: [] },
            include: ["alias*.ts"],
          }),
        },
      });
      try {
        const program = linked.project.program;
        expect(program.getSourceFileNames()).toContain(
          path.join(root, "alias.ts").split(path.sep).join("/"),
        );
        expect(
          program.getSourceFileNames().some((name) =>
            program.getSourceFile(name)?.getText().includes("export const linked = 2;"),
          ),
        ).toBe(true);
      } finally {
        linked.close();
      }
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it("opens a virtual project through the asynchronous API", async () => {
    const root = path.resolve(".artifacts", "native-typescript-async-fixture");
    const asynchronous = await createNativeTypeScriptProjectAsync({
      cwd: root,
      configFileName: "tsconfig.json",
      files: {
        "tsconfig.json": JSON.stringify({
          compilerOptions: { noLib: true, types: [] },
          files: ["virtual.ts"],
        }),
        "virtual.ts": "export const virtual = 1;",
      },
    });
    try {
      expect(await asynchronous.project.program.getSourceFileNames()).toContain(
        path.join(root, "virtual.ts").split(path.sep).join("/"),
      );
    } finally {
      await asynchronous.close();
    }
  });
});
