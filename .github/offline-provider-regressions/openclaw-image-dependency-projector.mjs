#!/usr/bin/env node
import { createHash } from "node:crypto";
import fs from "node:fs";
import { builtinModules } from "node:module";
import path from "node:path";

const [projectInput, imageModulesInput] = process.argv.slice(2);
if (!projectInput || !imageModulesInput) {
  throw new Error(
    "usage: openclaw-image-dependency-projector.mjs <project-root> <image-node-modules>",
  );
}

const projectRoot = fs.realpathSync(projectInput);
const imageModules = fs.realpathSync(imageModulesInput);
const virtualStore = path.join(imageModules, ".pnpm");
const targetModules = path.join(projectRoot, "node_modules");
if (!fs.statSync(virtualStore).isDirectory()) {
  throw new Error(`image virtual store is missing: ${virtualStore}`);
}
if (fs.existsSync(targetModules)) {
  throw new Error(`project node_modules must be absent: ${targetModules}`);
}

const manifest = JSON.parse(fs.readFileSync(path.join(projectRoot, "package.json"), "utf8"));
const requested = new Map();
function addRequestedDependencies(pkg) {
  for (const group of ["dependencies", "devDependencies", "optionalDependencies"]) {
    for (const [name, spec] of Object.entries(pkg[group] ?? {})) {
      if (!requested.has(name)) {
        requested.set(name, String(spec));
      }
    }
  }
}
addRequestedDependencies(manifest);

const workspacePackages = new Map();
if (typeof manifest.name === "string") workspacePackages.set(manifest.name, projectRoot);
function scanWorkspace(directory, depth = 0) {
  if (depth > 4 || !fs.existsSync(directory)) return;
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (
      !entry.isDirectory() ||
      ["node_modules", ".git", ".artifacts", "coverage"].includes(entry.name)
    )
      continue;
    const child = path.join(directory, entry.name);
    const packageJson = path.join(child, "package.json");
    if (fs.existsSync(packageJson)) {
      const pkg = JSON.parse(fs.readFileSync(packageJson, "utf8"));
      if (typeof pkg.name === "string") workspacePackages.set(pkg.name, child);
      addRequestedDependencies(pkg);
    }
    scanWorkspace(child, depth + 1);
  }
}
for (const root of ["packages", "extensions"]) scanWorkspace(path.join(projectRoot, root));

const storeEntries = fs
  .readdirSync(virtualStore, { withFileTypes: true })
  .filter((entry) => entry.isDirectory())
  .map((entry) => entry.name);

function packageVersion(candidate) {
  try {
    return JSON.parse(fs.readFileSync(path.join(candidate, "package.json"), "utf8")).version;
  } catch {
    return undefined;
  }
}

// Aliases support exact SemVer only; ordinary range behavior is unchanged.
const exactVersionPattern =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/;
const parsedRequests = new Map();
function parsePackageRequest(name, spec = "") {
  const key = JSON.stringify([name, spec]);
  if (parsedRequests.has(key)) return parsedRequests.get(key);
  let canonical = name;
  let selector = spec;
  const alias = spec.startsWith("npm:");
  if (alias) {
    const match = /^npm:((?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*)@([^\s@]+)$/.exec(spec);
    if (!match || !exactVersionPattern.test(match[2])) {
      throw new Error("unsupported or malformed npm alias: " + name);
    }
    canonical = match[1];
    selector = match[2];
  }
  const result = { canonical, exact: exactVersionPattern.test(selector) ? selector : null, alias };
  parsedRequests.set(key, result);
  return result;
}

function chooseImagePackage(name, spec) {
  const request = parsePackageRequest(name, spec);
  const direct = path.join(imageModules, name);
  const hoisted = path.join(virtualStore, "node_modules", name);
  const canonical = request.canonical;
  const encoded = canonical.startsWith("@") ? canonical.replace("/", "+") : canonical;
  const aliasEncoded = name.startsWith("@") ? name.replace("/", "+") : name;
  const candidates = [direct, hoisted];
  for (const entry of storeEntries) {
    if (entry.startsWith(`${aliasEncoded}@`)) {
      candidates.push(path.join(virtualStore, entry, "node_modules", name));
    }
    if (entry.startsWith(`${encoded}@`)) {
      candidates.push(path.join(virtualStore, entry, "node_modules", canonical));
    }
  }
  const unique = [
    ...new Set(
      candidates
        .filter((candidate) => fs.existsSync(candidate))
        .map((candidate) => fs.realpathSync(candidate)),
    ),
  ];
  if (unique.length === 0) return null;
  if (unique.length === 1) return unique[0];
  const exact = request.exact;
  if (exact) {
    const matches = unique.filter((candidate) => packageVersion(candidate) === exact);
    if (matches.length === 1) return matches[0];
  }
  if (request.alias) return null;
  if (fs.existsSync(direct)) return fs.realpathSync(direct);
  return null;
}

// Derive declaration roots from the canonical SDK config and source imports as DATA.
// No candidate module/config is imported or evaluated. Installed versions are resolved below.
function declarationRegistryGraph() {
  const configs = new Map();
  const inputs = new Map();
  const roots = new Map();
  const builtins = new Set(builtinModules.map((name) => name.replace(/^node:/, "")));
  const inside = (file) => {
    const resolved = fs.realpathSync(file);
    const rel = path.relative(projectRoot, resolved);
    if (rel.startsWith("..") || path.isAbsolute(rel)) {
      throw new Error("declaration source escapes candidate: " + file);
    }
    return resolved;
  };
  const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
  function config(file) {
    file = inside(file);
    if (configs.has(file)) return configs.get(file);
    const bytes = fs.readFileSync(file, "utf8");
    inputs.set(file, digest(bytes));
    const json = bytes.replace(/"(?:\\.|[^"\\])*"|\/\*[\s\S]*?\*\/|\/\/[^\n]*/g, (part) =>
      part.startsWith('"') ? part : " ",
    );
    const current = JSON.parse(json.replace(/,\s*([}\]])/g, "$1"));
    let inherited = { options: {}, pathBase: path.dirname(file) };
    if (current.extends) {
      if (typeof current.extends !== "string" || !current.extends.startsWith(".")) {
        throw new Error("unsupported SDK config extends; review graph derivation");
      }
      inherited = config(path.resolve(path.dirname(file), current.extends));
    }
    const result = {
      options: { ...inherited.options, ...current.compilerOptions },
      pathBase: current.compilerOptions?.paths ? path.dirname(file) : inherited.pathBase,
      include: current.include ?? inherited.include,
      exclude: current.exclude ?? inherited.exclude ?? [],
      directory: path.dirname(file),
    };
    configs.set(file, result);
    return result;
  }
  const sdk = config(path.join(projectRoot, "packages/plugin-sdk/tsconfig.json"));
  if (!Array.isArray(sdk.include) || sdk.include.length === 0) {
    throw new Error("SDK declaration include set absent");
  }
  const queue = [...fs.globSync(sdk.include, { cwd: sdk.directory, exclude: sdk.exclude })]
    .map((name) => path.resolve(sdk.directory, name))
    .sort();
  const ambientModules = new Set();
  for (const file of queue.filter((name) => name.endsWith(".d.ts"))) {
    for (const match of fs
      .readFileSync(inside(file), "utf8")
      .matchAll(/declare\s+module\s+["']([^"']+)["']/g)) {
      ambientModules.add(match[1]);
    }
  }
  const seen = new Set();
  const unresolvedLocal = new Set();
  function localFile(file) {
    const stem = file.replace(/\.(?:mjs|cjs|js)$/, "");
    for (const candidate of [
      file,
      stem + ".ts",
      stem + ".tsx",
      stem + ".mts",
      stem + ".cts",
      stem + ".d.ts",
      path.join(file, "index.ts"),
      path.join(file, "index.d.ts"),
    ]) {
      if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) return inside(candidate);
    }
  }
  function accept(spec, owner) {
    if (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(spec) || builtins.has(spec) || ambientModules.has(spec))
      return;
    if (spec.startsWith(".")) {
      const file = localFile(path.resolve(path.dirname(owner), spec));
      if (file) queue.push(file);
      else unresolvedLocal.add(path.relative(projectRoot, owner) + " -> " + spec);
      return;
    }
    for (const [pattern, targets] of Object.entries(sdk.options.paths ?? {}).sort(
      ([left], [right]) => right.replace("*", "").length - left.replace("*", "").length,
    )) {
      const at = pattern.indexOf("*");
      const matches =
        at < 0
          ? spec === pattern
          : spec.startsWith(pattern.slice(0, at)) && spec.endsWith(pattern.slice(at + 1));
      if (!matches) continue;
      const middle = at < 0 ? "" : spec.slice(at, spec.length - (pattern.length - at - 1));
      for (const target of targets) {
        const file = localFile(path.resolve(sdk.pathBase, target.replace("*", middle)));
        if (file) {
          queue.push(file);
          return;
        }
      }
      // TypeScript falls back to registry resolution if a paths substitution is absent.
    }
    const name = spec.startsWith("@") ? spec.split("/").slice(0, 2).join("/") : spec.split("/")[0];
    if (workspacePackages.has(name)) {
      throw new Error("workspace SDK import lacks canonical source path mapping: " + spec);
    }
    if (!requested.has(name))
      throw new Error(
        "SDK registry import not declared by streamed manifests: " +
          name +
          " in " +
          path.relative(projectRoot, owner),
      );
    if (!roots.has(name)) roots.set(name, path.relative(projectRoot, owner));
  }
  for (const name of sdk.options.types ?? []) {
    accept(
      name.startsWith("@types/") ? name : "@types/" + name,
      path.join(projectRoot, "packages/plugin-sdk/tsconfig.json"),
    );
  }
  while (queue.length) {
    const file = inside(queue.pop());
    if (seen.has(file)) continue;
    seen.add(file);
    if (!/\.(?:[cm]?tsx?|json)$/.test(file)) continue;
    const text = fs.readFileSync(file, "utf8");
    inputs.set(file, digest(text));
    if (file.endsWith(".json")) continue;
    // Lex quoted module specifiers; comments/templates are not import statements.
    const tokens =
      text.match(
        /\/\*[\s\S]*?\*\/|\/\/[^\n]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`|[A-Za-z_$][\w$]*|[^\s]/g,
      ) ?? [];
    const clean = tokens.filter((token) => !token.startsWith("//") && !token.startsWith("/*"));
    for (let i = 0; i < clean.length; i++) {
      let literal;
      const token = clean[i];
      if (clean[i - 1] === ".") continue;
      if (token === "import" && /^["']/.test(clean[i + 1] ?? "")) literal = clean[i + 1];
      if ((token === "import" || token === "require") && clean[i + 1] === "(")
        literal = clean[i + 2];
      const exportStart = clean[i + 1] === "type" ? i + 2 : i + 1;
      const exportClause = token === "export" && ["{", "*"].includes(clean[exportStart]);
      if ((token === "import" && clean[i + 1] !== "(") || exportClause) {
        for (let j = i + 1; j < Math.min(i + 150, clean.length); j++) {
          if ([";", "=", "("].includes(clean[j])) break;
          if (clean[j] === "from") {
            literal = clean[j + 1];
            break;
          }
        }
      }
      if (!literal || !/^["']/.test(literal)) continue;
      const spec = literal.slice(1, -1);
      if (spec.includes("\\")) throw new Error("escaped SDK module specifier needs graph review");
      accept(spec, file);
    }
    for (const match of text.matchAll(/<reference\s+types=["']([^"']+)["']/g)) {
      accept(match[1].startsWith("@types/") ? match[1] : "@types/" + match[1], file);
    }
  }
  const graph = {
    config: "packages/plugin-sdk/tsconfig.json",
    sourceFiles: seen.size,
    sourceDigest: digest(
      [...inputs]
        .sort()
        .map(([name, sha]) => path.relative(projectRoot, name) + " " + sha)
        .join("\n"),
    ),
    registryRoots: Object.fromEntries([...roots].sort()),
    unresolvedLocal: [...unresolvedLocal].sort(),
  };
  // Missing relative source cannot safely contribute hidden declaration roots.
  const generatedInputs = new Set([
    "src/state/openclaw-agent-db.generated.ts -> ../../.artifacts/kysely/openclaw-agent-db.generated.js",
    "src/state/openclaw-state-db.generated.ts -> ../../.artifacts/kysely/openclaw-state-db.generated.js",
  ]);
  if (
    graph.unresolvedLocal.some((item) => !generatedInputs.has(item)) ||
    (graph.unresolvedLocal.length > 0 && !roots.has("kysely"))
  ) {
    throw new Error(
      "SDK source graph has unresolved inputs: " + JSON.stringify(graph.unresolvedLocal),
    );
  }
  return graph;
}
const declarationGraph = declarationRegistryGraph();
process.stdout.write(JSON.stringify({ declarationGraph }) + "\n");
if (process.argv.includes("--declaration-roots-only")) process.exit(0);

// The compiler boundary requires physical checkout-local compiler and native executable.
// Copy only its installed pnpm entry closure; leave the rest readonly image projections.
const compiler = chooseImagePackage("typescript", requested.get("typescript") ?? "");
if (!compiler) throw new Error("missing installed compiler");
function assertPackageIdentity(candidate, name, spec) {
  const request = parsePackageRequest(name, spec);
  const installed = JSON.parse(fs.readFileSync(path.join(candidate, "package.json"), "utf8"));
  if (installed.name !== request.canonical) {
    throw new Error("installed package name mismatch: " + name);
  }
  if (request.exact && installed.version !== request.exact) {
    throw new Error("installed package version mismatch: " + name);
  }
}
assertPackageIdentity(compiler, "typescript", requested.get("typescript"));
const selected = new Set();
const selectionCauses = new Map();
const storeEntry = (file) => {
  const rel = path.relative(virtualStore, file);
  if (rel.startsWith("..") || path.isAbsolute(rel))
    throw new Error("compiler closure escapes image store");
  const first = rel.split(path.sep)[0];
  if (!first || first === "node_modules") throw new Error("compiler closure lacks pnpm entry");
  return first;
};
function selectEntry(entry, cause) {
  if (selected.has(entry)) return;
  selected.add(entry);
  selectionCauses.set(entry, cause);
  function scan(dir) {
    const items = fs.readdirSync(dir, { withFileTypes: true });
    items.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const item of items) {
      const file = path.join(dir, item.name);
      if (item.isSymbolicLink()) {
        if (!fs.existsSync(file)) {
          throw new Error("dangling hydration link: " + path.relative(virtualStore, file));
        }
        selectEntry(storeEntry(fs.realpathSync(file)), {
          kind: "installed-symlink",
          from: path.relative(virtualStore, file),
          parent: entry,
        });
      } else if (item.isDirectory()) scan(file);
    }
  }
  scan(path.join(virtualStore, entry));
}
selectEntry(storeEntry(compiler), { kind: "compiler", root: "typescript" });
// Native declaration emission admits package files by physical checkout location.
const typeRoots = new Set([
  ...Object.keys(declarationGraph.registryRoots),
  "@types/node",
  ...Object.keys(declarationGraph.registryRoots)
    .map((name) => "@types/" + (name.startsWith("@") ? name.slice(1).replace("/", "__") : name))
    .filter((name) => requested.has(name)),
]);
for (const name of [...typeRoots].sort()) {
  const source = chooseImagePackage(name, requested.get(name) ?? "");
  if (!source) throw new Error("missing installed declaration root: " + name);
  const expected = requested.get(name);
  assertPackageIdentity(source, name, expected);
  selectEntry(storeEntry(source), { kind: "declaration-root", root: name });
}
// Retain every installed link target. Peer links, executable links, and interior
// aliases are not evidence that their declaration or metadata reads are unused.
const limitBytes = 256 * 1024 * 1024;
function measureEntry(entry) {
  let bytes = 0;
  let files = 0;
  function countFiles(dir) {
    for (const item of fs.readdirSync(dir, { withFileTypes: true })) {
      const file = path.join(dir, item.name);
      if (item.isDirectory()) countFiles(file);
      else if (item.isFile()) {
        bytes += fs.statSync(file).size;
        files += 1;
        if (!Number.isSafeInteger(bytes)) throw new Error("unsafe hydration byte count");
      } else if (!item.isSymbolicLink()) {
        throw new Error("unsupported hydration filesystem entry");
      }
    }
  }
  countFiles(path.join(virtualStore, entry));
  return { entry, bytes, files, selectedCause: selectionCauses.get(entry) };
}
const measurements = [...selected].sort().map(measureEntry);
const copiedBytes = measurements.reduce((sum, item) => sum + item.bytes, 0);
if (!Number.isSafeInteger(copiedBytes)) throw new Error("unsafe hydration total");
const hydrationPlan = {
  mode: "conservative-installed-link-closure",
  totalBytes: copiedBytes,
  entryCount: selected.size,
  fileCount: measurements.reduce((sum, item) => sum + item.files, 0),
  limit: "256 MiB",
  limitBytes,
  withinLimit: copiedBytes <= limitBytes,
  selectedEntries: measurements.map(({ entry, bytes, files }) => ({ entry, bytes, files })),
  largestEntries: [...measurements]
    .sort((a, b) => b.bytes - a.bytes || (a.entry < b.entry ? -1 : a.entry > b.entry ? 1 : 0))
    .slice(0, 12),
};
// Emit before the first target write, including on over-cap failure.
process.stdout.write(JSON.stringify({ hydrationPlan }) + "\n");
if (process.argv.includes("--hydration-plan-only")) {
  process.exit(hydrationPlan.withinLimit ? 0 : 2);
}
if (!hydrationPlan.withinLimit) {
  throw new Error(
    "compiler/declaration closure exceeds 256 MiB hydration cap: " +
      copiedBytes +
      " > " +
      limitBytes,
  );
}
fs.mkdirSync(targetModules, { mode: 0o755 });
const localStore = path.join(targetModules, ".pnpm");
fs.mkdirSync(localStore);
for (const entry of fs.readdirSync(virtualStore)) {
  const from = path.join(virtualStore, entry);
  const to = path.join(localStore, entry);
  if (selected.has(entry)) fs.cpSync(from, to, { recursive: true, dereference: false });
  else fs.symlinkSync(from, to);
}
// pnpm normally uses relative links. Relocate any absolute links within copied entries.
function relocateLinks(dir) {
  for (const item of fs.readdirSync(dir, { withFileTypes: true })) {
    const file = path.join(dir, item.name);
    if (item.isDirectory()) relocateLinks(file);
    else if (item.isSymbolicLink() && path.isAbsolute(fs.readlinkSync(file))) {
      const actual = fs.realpathSync(file);
      const local = path.join(localStore, path.relative(virtualStore, actual));
      fs.unlinkSync(file);
      fs.symlinkSync(local, file);
    }
  }
}
for (const entry of selected) relocateLinks(path.join(localStore, entry));
const localize = (source) => {
  const rel = path.relative(virtualStore, source);
  return selected.has(rel.split(path.sep)[0]) ? path.join(localStore, rel) : source;
};
const bins = path.join(targetModules, ".bin");
fs.mkdirSync(bins);
process.stdout.write(
  JSON.stringify({ compilerHydrationEntries: [...selected], compilerHydrationBytes: copiedBytes }) +
    "\n",
);
let projected = 0;
const unavailable = [];
for (const [name, spec] of [...requested].sort(([left], [right]) => left.localeCompare(right))) {
  let source;
  if (spec.startsWith("workspace:")) {
    source = workspacePackages.get(name);
    if (!source) throw new Error(`workspace dependency is missing from streamed source: ${name}`);
  } else {
    source = chooseImagePackage(name, spec);
    if (!source) {
      unavailable.push(name);
      continue;
    }
  }
  source = localize(source);
  const destination = path.join(targetModules, name);
  fs.mkdirSync(path.dirname(destination), { recursive: true, mode: 0o755 });
  fs.symlinkSync(source, destination, "dir");
  const packageManifest = JSON.parse(fs.readFileSync(path.join(source, "package.json"), "utf8"));
  const packageBins =
    typeof packageManifest.bin === "string"
      ? { [name.split("/").at(-1)]: packageManifest.bin }
      : (packageManifest.bin ?? {});
  for (const [binName, relativeBin] of Object.entries(packageBins)) {
    if (!/^[A-Za-z0-9_.-]+$/.test(binName)) throw new Error("invalid dependency bin name");
    const link = path.join(bins, binName);
    let linked = false;
    try {
      fs.lstatSync(link);
      linked = true;
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
    if (!linked) fs.symlinkSync(path.resolve(source, relativeBin), link);
  }
  projected += 1;
}

// UI dependencies live at their own workspace prefix, not the ambient root.
const uiRoot = path.join(projectRoot, "ui");
const uiManifest = path.join(uiRoot, "package.json");
if (fs.existsSync(uiManifest)) {
  const ui = JSON.parse(fs.readFileSync(uiManifest, "utf8"));
  const uiModules = path.join(uiRoot, "node_modules");
  fs.mkdirSync(uiModules, { recursive: true });
  const specs = {
    ...ui.dependencies,
    ...ui.devDependencies,
    ...ui.optionalDependencies,
  };
  for (const [name, spec] of Object.entries(specs)) {
    const source = String(spec).startsWith("workspace:")
      ? workspacePackages.get(name)
      : chooseImagePackage(name, String(spec));
    if (!source) {
      throw new Error("missing installed UI dependency: " + name);
    }
    const exact = String(spec).match(/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/)?.[0];
    if (exact && packageVersion(source) !== exact) {
      throw new Error("UI version mismatch: " + name);
    }
    const destination = path.join(uiModules, name);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.symlinkSync(localize(source), destination, "dir");
  }
}

process.stdout.write(
  `projected_dependencies=${projected} unavailable_dependencies=${unavailable.length}\n`,
);
