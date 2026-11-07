import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import type { SourceFile } from "typescript/ast";
import {
  serverFS,
  type FileSystemCallbacks,
  type FileSystemEntries,
} from "typescript/fs";
import {
  API,
  type CreateSnapshotParams,
  type Diagnostic,
  type Project,
  type Snapshot,
} from "typescript/sync";

export type NativeTypeScriptSource = { fileName: string; text: string };
export type NativeTypeScriptParser = ReturnType<typeof createNativeTypeScriptParser>;
export type NativeTypeScriptProject = ReturnType<typeof createNativeTypeScriptProject>;

type FileSystem = {
  readFile?: (file: string) => string | undefined | typeof serverFS.useOS;
  fileExists?: (file: string) => boolean | undefined;
  directoryExists?: (directory: string) => boolean | undefined;
  realpath?: (file: string) => string | undefined;
  getAccessibleEntries?: (directory: string) => FileSystemEntries | undefined;
};

type ProjectOptions = {
  cwd: string;
  configFileName: string;
  files?: Readonly<Record<string, string>>;
  fs?: FileSystem;
};

/** Select the same installed compiler as the native API, including in relocated tooling. */
export function resolveInstalledNativeTypeScriptCompiler() {
  const require = createRequire(import.meta.url);
  const packageJson = require.resolve("typescript/package.json");
  const getExePath: { default: () => string } = require(
    path.join(path.dirname(packageJson), "lib/getExePath.js"),
  );
  return { executable: getExePath.default(), packageJson };
}

function compilerFileName(cwd: string, file: string) {
  return path.resolve(cwd, file).split(path.sep).join("/");
}

function directoryEntries(directory: string): FileSystemEntries {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(directory, { withFileTypes: true });
  } catch (error) {
    if (
      error instanceof Error &&
      "code" in error &&
      (error.code === "ENOENT" || error.code === "ENOTDIR")
    ) {
      return { files: [], directories: [], symlinks: [] };
    }
    throw error;
  }
  const files: string[] = [];
  const directories: string[] = [];
  const symlinks: string[] = [];
  for (const entry of entries) {
    if (entry.isSymbolicLink()) {
      symlinks.push(entry.name);
    }
    const isDirectory = entry.isSymbolicLink()
      ? fs.statSync(path.join(directory, entry.name), { throwIfNoEntry: false })?.isDirectory()
      : entry.isDirectory();
    (isDirectory ? directories : files).push(entry.name);
  }
  return { files, directories, symlinks };
}

function emptyDirectoryEntries(): FileSystemEntries {
  return { files: [], directories: [], symlinks: [] };
}

/** The 7.1 beta removed the virtual callback helper; retain its in-memory contract here. */
function createVirtualFileSystem(contents: Readonly<Record<string, string>>) {
  const files = new Map(Object.entries(contents).map(([file, text]) => [path.resolve(file), text]));
  const directories = new Set<string>();
  for (const file of files.keys()) {
    for (let directory = path.dirname(file); ; directory = path.dirname(directory)) {
      directories.add(directory);
      if (directory === path.dirname(directory)) {
        break;
      }
    }
  }
  return {
    readFile: (file: string) => files.get(path.resolve(file)),
    fileExists: (file: string) => files.has(path.resolve(file)),
    directoryExists: (directory: string) => directories.has(path.resolve(directory)),
    realpath: (file: string) => path.resolve(file),
    getAccessibleEntries(directory: string): FileSystemEntries {
      const root = path.resolve(directory);
      return {
        files: [...files.keys()]
          .filter((file) => path.dirname(file) === root)
          .map((file) => path.basename(file)),
        directories: [...directories]
          .filter((child) => child !== root && path.dirname(child) === root)
          .map((child) => path.basename(child)),
        symlinks: [],
      };
    },
  };
}

function completeFileSystem(base: FileSystem): FileSystemCallbacks {
  return {
    readFile: base.readFile ?? serverFS.useOS,
    fileExists: base.fileExists
      ? (file) => base.fileExists?.(file) ?? serverFS.useOS
      : serverFS.useOS,
    directoryExists: base.directoryExists
      ? (directory) => base.directoryExists?.(directory) ?? serverFS.useOS
      : serverFS.useOS,
    realpath: base.realpath
      ? (file) => base.realpath?.(file) ?? serverFS.identity
      : serverFS.useOS,
    getAccessibleEntries: base.getAccessibleEntries
      ? (directory) => base.getAccessibleEntries?.(directory) ?? emptyDirectoryEntries()
      : serverFS.useOS,
    stat: serverFS.fakeStat,
    writeFile: serverFS.noop,
    removeFile: serverFS.noop,
  };
}

function overlayFileSystem(
  cwd: string,
  files: Readonly<Record<string, string>>,
  base: FileSystem = {},
): FileSystemCallbacks {
  const contents = Object.fromEntries(
    Object.entries(files).map(([file, text]) => [compilerFileName(cwd, file), text]),
  );
  const virtual = createVirtualFileSystem(contents);
  const hasFile = (file: string) => Object.hasOwn(contents, compilerFileName(cwd, file));
  return {
    readFile: (file) =>
      hasFile(file)
        ? contents[compilerFileName(cwd, file)]
        : base.readFile
          ? base.readFile(file)
          : serverFS.useOS,
    fileExists: (file) =>
      hasFile(file) ? true : (base.fileExists?.(file) ?? serverFS.useOS),
    directoryExists: (directory) =>
      virtual.directoryExists(directory)
        ? true
        : base.directoryExists
          ? (base.directoryExists(directory) ?? serverFS.useOS)
          : serverFS.useOS,
    realpath: (file) =>
      hasFile(file)
        ? compilerFileName(cwd, file)
        : base.realpath
          ? (base.realpath(file) ?? serverFS.identity)
          : serverFS.useOS,
    getAccessibleEntries(directory) {
      const added = virtual.getAccessibleEntries(directory);
      const existing = base.getAccessibleEntries
        ? (base.getAccessibleEntries(directory) ?? emptyDirectoryEntries())
        : directoryEntries(directory);
      return {
        files: [...new Set([...existing.files, ...added.files])],
        directories: [...new Set([...existing.directories, ...added.directories])],
        symlinks: [...new Set([...(existing.symlinks ?? []), ...(added.symlinks ?? [])])],
      };
    },
    stat: serverFS.fakeStat,
    writeFile: serverFS.noop,
    removeFile: serverFS.noop,
  };
}

/** Own one native compiler process and its immutable semantic snapshot. */
export function createNativeTypeScriptProject(options: ProjectOptions) {
  const cwd = path.resolve(options.cwd);
  const configFileName = compilerFileName(cwd, options.configFileName);
  const api = new API({
    cwd,
    fs: options.files
      ? overlayFileSystem(cwd, options.files, options.fs)
      : options.fs
        ? completeFileSystem(options.fs)
        : undefined,
  });
  let snapshot: Snapshot;
  let project: Project;
  try {
    snapshot = api.createSnapshot({ openProjects: [configFileName], ensurePrograms: true });
    const opened = snapshot.getConfiguredProject(configFileName);
    if (!opened) {
      throw new Error(`Native TypeScript did not open ${configFileName}`);
    }
    project = opened;
  } catch (error) {
    api.close();
    throw error;
  }
  let closed = false;
  const close = () => {
    if (closed) {
      return;
    }
    closed = true;
    api.close();
  };
  return { api, snapshot, project, close, [Symbol.dispose]: close };
}

/** The async transport keeps its child referenced while close ends the server's input. */
export async function createNativeTypeScriptProjectAsync(options: ProjectOptions) {
  const { API: AsyncAPI } = await import("typescript/async");
  const cwd = path.resolve(options.cwd);
  const configFileName = compilerFileName(cwd, options.configFileName);
  const api = new AsyncAPI({
    cwd,
    fs: options.files
      ? overlayFileSystem(cwd, options.files, options.fs)
      : options.fs
        ? completeFileSystem(options.fs)
        : undefined,
  });
  try {
    const snapshot = await api.createSnapshot({
      openProjects: [configFileName],
      ensurePrograms: true,
    });
    const project = snapshot.getConfiguredProject(configFileName);
    if (!project) {
      throw new Error(`Native TypeScript did not open ${configFileName}`);
    }
    let closePromise: Promise<void> | undefined;
    const close = () => (closePromise ??= api.close());
    return { api, snapshot, project, close, [Symbol.asyncDispose]: close };
  } catch (error) {
    await api.close();
    throw error;
  }
}

/** Batch syntax scans share one explicit process; source trees remain local after disposal. */
export function createNativeTypeScriptParser({
  cwd = process.cwd(),
  tsserverPath,
}: { cwd?: string; tsserverPath?: string } = {}) {
  const root = path.resolve(cwd);
  const configFileName = compilerFileName(root, ".openclaw-native-parser.tsconfig.json");
  let files: Record<string, string> = {};
  let virtual = createVirtualFileSystem(files);
  let api: API | undefined;
  let snapshot: Snapshot | undefined;
  let project: Project | undefined;
  let sourceNames: string[] = [];
  let closed = false;
  const assertOpen = () => {
    if (closed) {
      throw new Error("Native TypeScript parser is closed");
    }
  };
  const parseSourceFiles = (sources: readonly NativeTypeScriptSource[]): readonly SourceFile[] => {
    assertOpen();
    if (sources.length === 0) {
      snapshot?.dispose();
      snapshot = undefined;
      project = undefined;
      return [];
    }
    const previous = snapshot;
    const names = sources.map((source) => compilerFileName(root, source.fileName));
    if (new Set(names).size !== names.length) {
      throw new Error("Native TypeScript parser received duplicate source paths");
    }
    if (names.includes(configFileName)) {
      throw new Error(`Native TypeScript parser source conflicts with ${configFileName}`);
    }
    files = Object.fromEntries(
      sources.map((source) => [compilerFileName(root, source.fileName), source.text]),
    );
    files[configFileName] = JSON.stringify({
      compilerOptions: {
        allowJs: true,
        experimentalDecorators: true,
        jsx: "preserve",
        noLib: true,
        noResolve: true,
        target: "esnext",
        types: [],
      },
      files: names,
    });
    virtual = createVirtualFileSystem(files);
    api ??= new API({
      cwd: root,
      tsserverPath,
      fs: {
        readFile: (file) => virtual.readFile(file),
        fileExists: (file) => virtual.fileExists(file),
        directoryExists: (directory) => virtual.directoryExists(directory),
        getAccessibleEntries: (directory) => virtual.getAccessibleEntries(directory),
        realpath: (file) => file,
        stat: serverFS.fakeStat,
        writeFile: serverFS.noop,
        removeFile: serverFS.noop,
      },
    });
    const previousNames = new Set(sourceNames);
    const currentNames = new Set(names);
    const changes: CreateSnapshotParams = {
      ...(previous ? {} : { openProjects: [configFileName] }),
      // A config-file change reloads its root list; invalidateAll retains the old roots.
      fileNotifications: {
        changed: [configFileName, ...names.filter((name) => previousNames.has(name))],
        created: names.filter((name) => !previousNames.has(name)),
        deleted: sourceNames.filter((name) => !currentNames.has(name)),
      },
      ensurePrograms: true,
    };
    snapshot = previous ? previous.update(changes) : api.createSnapshot(changes);
    sourceNames = names;
    previous?.dispose();
    project = snapshot.getConfiguredProject(configFileName);
    if (!project) {
      throw new Error("Native TypeScript did not open the syntax scan project");
    }
    const program = project.program;
    return names.map((fileName) => {
      const sourceFile = program.getSourceFile(fileName);
      if (!sourceFile) {
        throw new Error(`Native TypeScript did not parse ${fileName}`);
      }
      return sourceFile;
    });
  };
  const close = () => {
    if (closed) {
      return;
    }
    closed = true;
    api?.close();
    api = undefined;
    project = undefined;
    snapshot = undefined;
    files = {};
    virtual = createVirtualFileSystem(files);
    sourceNames = [];
  };
  return {
    parseSourceFiles,
    parseSourceFile(fileName: string, text: string): SourceFile {
      const sourceFile = parseSourceFiles([{ fileName, text }])[0];
      if (!sourceFile) {
        throw new Error(`Native TypeScript did not parse ${fileName}`);
      }
      return sourceFile;
    },
    getSyntacticDiagnostics(fileName?: string): readonly Diagnostic[] {
      assertOpen();
      return (
        project?.program.getSyntacticDiagnostics(
          fileName === undefined ? undefined : compilerFileName(root, fileName),
        ) ?? []
      );
    },
    close,
    [Symbol.dispose]: close,
  };
}
