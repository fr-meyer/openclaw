#!/usr/bin/env node
import { createHash } from "node:crypto";
import fs from "node:fs";
import { builtinModules } from "node:module";
import path from "node:path";

const [projectInput, imageModulesInput, ...flags] = process.argv.slice(2);
const inventoryOnly = flags.includes("--inventory-only");
if (
  flags.some(
    (flag) =>
      !["--inventory-only", "--declaration-roots-only", "--hydration-plan-only"].includes(flag),
  ) ||
  (inventoryOnly && flags.length !== 1)
)
  throw new Error("invalid projector mode configuration");
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
// Resolve UI registry packages from the installed UI importer, never ambient guesses.
// Preflight every binding before measurement or the first target write.
const uiRoot = path.join(projectRoot, "ui");
const uiModules = path.join(uiRoot, "node_modules");
const uiManifest = path.join(uiRoot, "package.json");
const uiBindings = new Map();
function uiPathExists(file) {
  try {
    fs.lstatSync(file);
    return true;
  } catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
}
const uiPresent = uiPathExists(uiManifest);
const packageNamePattern = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/;
function requireCanonicalFile(file) {
  if (!fs.lstatSync(file).isFile() || fs.realpathSync(file) !== file) {
    throw new Error("noncanonical UI package manifest: " + file);
  }
  return JSON.parse(fs.readFileSync(file, "utf8"));
}
function installedUiPackage(name, spec) {
  const request = parsePackageRequest(name, spec);
  if (!request.exact) throw new Error("UI registry dependency must be exact: " + name);
  const importer = path.join(path.dirname(imageModules), "ui", "node_modules");
  // Parent components cannot redirect the installed importer or store elsewhere.
  if (fs.realpathSync(importer) !== importer || fs.realpathSync(virtualStore) !== virtualStore) {
    throw new Error("noncanonical installed UI importer/store");
  }
  const binding = path.join(importer, name);
  if (fs.realpathSync(path.dirname(binding)) !== path.dirname(binding)) {
    throw new Error("noncanonical UI importer scope: " + name);
  }
  if (!fs.lstatSync(binding).isSymbolicLink()) {
    throw new Error("UI dependency lacks installed importer link: " + name);
  }
  const source = fs.realpathSync(binding); // dangling links fail closed, no ambient fallback
  const rel = path.relative(virtualStore, source);
  const parts = rel.split(path.sep);
  const expectedTail = ["node_modules", ...request.canonical.split("/")];
  const entryPrefix = request.canonical.replace("/", "+") + "@" + request.exact;
  const entrySuffix = parts[0].slice(entryPrefix.length);
  if (
    !parts[0].startsWith(entryPrefix) ||
    (entrySuffix !== "" && !entrySuffix.startsWith("_")) ||
    !parts[0] ||
    parts[0] === "." ||
    parts[0] === ".." ||
    parts[0] === "node_modules" ||
    /[\\\x00-\x1f\x7f]/.test(parts[0]) ||
    path.isAbsolute(rel) ||
    parts.length !== expectedTail.length + 1 ||
    !expectedTail.every((part, index) => parts[index + 1] === part) ||
    !fs.statSync(source).isDirectory()
  ) {
    throw new Error("UI importer target is not a canonical store package: " + name);
  }
  requireCanonicalFile(path.join(source, "package.json"));
  assertPackageIdentity(source, name, spec);
  return source;
}
if (uiPresent) {
  if (fs.realpathSync(uiRoot) !== uiRoot || uiPathExists(uiModules)) {
    throw new Error("UI source prefix must be canonical and node_modules absent");
  }
  const ui = requireCanonicalFile(uiManifest);
  if (!ui || typeof ui !== "object" || Array.isArray(ui)) throw new Error("invalid UI manifest");
  for (const group of [
    "peerDependencies",
    "peerDependenciesMeta",
    "bundledDependencies",
    "bundleDependencies",
  ]) {
    if (Object.hasOwn(ui, group)) throw new Error("unsupported UI dependency group: " + group);
  }
  for (const group of ["dependencies", "devDependencies", "optionalDependencies"]) {
    const specs = ui[group] === undefined ? {} : ui[group];
    if (!specs || typeof specs !== "object" || Array.isArray(specs))
      throw new Error("invalid UI dependency group");
    for (const [name, spec] of Object.entries(specs)) {
      if (!packageNamePattern.test(name) || typeof spec !== "string" || uiBindings.has(name)) {
        throw new Error("invalid or duplicate UI dependency: " + name);
      }
      let source;
      if (spec.startsWith("workspace:")) {
        if (spec !== "workspace:*") throw new Error("unsupported UI workspace selector: " + spec);
        source = workspacePackages.get(name);
        if (!source) throw new Error("missing UI workspace dependency: " + name);
        const rel = path.relative(projectRoot, fs.realpathSync(source));
        if (
          rel.startsWith("..") ||
          path.isAbsolute(rel) ||
          requireCanonicalFile(path.join(source, "package.json")).name !== name
        ) {
          throw new Error("invalid UI workspace binding: " + name);
        }
      } else {
        source = installedUiPackage(name, spec);
      }
      uiBindings.set(name, source);
    }
  }
}

// Strict native enumeration admits EVERY symlink child, not merely imports.
// Preserve the complete installed view; measure all physical files before writes.
// This may exceed the unchanged cap. Such incompatibility must fail closed.
const limitBytes = 320 * 1024 * 1024;
for (const name of new Set([
  ...Object.keys(declarationGraph.registryRoots),
  "@types/node",
  ...Object.keys(declarationGraph.registryRoots)
    .map((name) => "@types/" + (name.startsWith("@") ? name.slice(1).replace("/", "__") : name))
    .filter((name) => requested.has(name)),
])) {
  const source = chooseImagePackage(name, requested.get(name) ?? "");
  if (!source) throw new Error("missing installed declaration root: " + name);
  assertPackageIdentity(source, name, requested.get(name));
}
const physicalFiles = [];
const installedLinks = [];
const directories = [];
function insideImage(file) {
  const rel = path.relative(imageModules, file);
  if (rel === ".." || rel.startsWith(".." + path.sep) || path.isAbsolute(rel))
    throw new Error("installed view escapes image node_modules: " + file);
  return rel;
}
function inspectInstalled(dir) {
  for (const item of fs
    .readdirSync(dir, { withFileTypes: true })
    .sort((a, b) => a.name.localeCompare(b.name))) {
    const file = path.join(dir, item.name);
    const rel = insideImage(file);
    if (item.isDirectory()) {
      if (fs.realpathSync(file) !== file)
        throw new Error("noncanonical installed directory: " + rel);
      directories.push(rel);
      inspectInstalled(file);
    } else if (item.isFile()) {
      const size = fs.statSync(file).size;
      physicalFiles.push({ path: rel, bytes: size, mode: fs.statSync(file).mode & 0o777 });
    } else if (item.isSymbolicLink()) {
      const actual = fs.realpathSync(file); // dangling/cyclic links fail before writes
      const relative = path.relative(imageModules, actual);
      if (relative === ".." || relative.startsWith(".." + path.sep) || path.isAbsolute(relative)) {
        // Only an exact installed workspace path with matching canonical manifest
        // may map to its streamed counterpart. Never admit arbitrary external dirs.
        const imageRoot = path.dirname(imageModules);
        const matches = [...workspacePackages].filter(([name, source]) => {
          const expected = path.join(imageRoot, path.relative(projectRoot, source));
          return (
            actual === expected &&
            fs.realpathSync(source) === source &&
            requireCanonicalFile(path.join(actual, "package.json")).name === name &&
            requireCanonicalFile(path.join(source, "package.json")).name === name
          );
        });
        if (matches.length !== 1) throw new Error("unrecognized external installed link: " + rel);
        installedLinks.push({ path: rel, target: matches[0][1], directory: true, workspace: true });
        continue;
      }
      const st = fs.statSync(actual);
      if (!st.isDirectory() && !st.isFile())
        throw new Error("unsupported installed link target: " + rel);
      installedLinks.push({ path: rel, target: insideImage(actual), directory: st.isDirectory() });
    } else throw new Error("unsupported installed filesystem entry: " + rel);
  }
}
inspectInstalled(imageModules);
// Authenticate all package-shaped installed links by target manifest and canonical
// store location. Renamed aliases require exact authoritative streamed npm requests.
const bindingReceipts = [];
for (const link of installedLinks) {
  if (!link.directory || link.workspace) continue;
  const parts = link.path.split(path.sep);
  const at = parts.lastIndexOf("node_modules");
  let name;
  if (at >= 0) name = parts.slice(at + 1).join("/");
  else name = link.path.split(path.sep).join("/");
  if (!packageNamePattern.test(name)) continue; // interior links retain validated physical identity
  const source = path.join(imageModules, link.target);
  const metadata = requireCanonicalFile(path.join(source, "package.json"));
  if (!packageNamePattern.test(metadata.name) || !exactVersionPattern.test(metadata.version))
    throw new Error("invalid installed binding identity: " + link.path);
  const rel = path.relative(virtualStore, source);
  const entry = rel.split(path.sep)[0];
  const prefix = metadata.name.replace("/", "+") + "@" + metadata.version;
  const suffix = entry.slice(prefix.length);
  if (
    source !== path.join(virtualStore, entry, "node_modules", metadata.name) ||
    !entry.startsWith(prefix) ||
    (suffix !== "" && !suffix.startsWith("_"))
  )
    throw new Error("noncanonical installed binding target: " + link.path);
  if (metadata.name !== name) {
    let spec = requested.get(name);
    // Entry-local aliases are authenticated by that installed parent's manifest.
    const components = link.path.split(path.sep);
    if (
      components[0] === ".pnpm" &&
      components[1] !== "node_modules" &&
      components[2] === "node_modules"
    ) {
      const parentModules = path.join(virtualStore, components[1], "node_modules");
      const parentCandidates = [];
      for (const child of fs.readdirSync(parentModules, { withFileTypes: true })) {
        if (!child.isDirectory()) continue;
        if (child.name.startsWith("@")) {
          for (const scoped of fs.readdirSync(path.join(parentModules, child.name), {
            withFileTypes: true,
          }))
            if (scoped.isDirectory())
              parentCandidates.push(path.join(parentModules, child.name, scoped.name));
        } else parentCandidates.push(path.join(parentModules, child.name));
      }
      const specs = new Set();
      for (const parent of parentCandidates) {
        const pkg = requireCanonicalFile(path.join(parent, "package.json"));
        for (const group of ["dependencies", "optionalDependencies", "peerDependencies"])
          if (typeof pkg[group]?.[name] === "string") specs.add(pkg[group][name]);
      }
      if (specs.size !== 1)
        throw new Error("ambiguous installed parent alias authority: " + link.path);
      spec = [...specs][0];
    }
    if (spec === undefined) {
      const specs = new Set();
      for (const file of physicalFiles.filter(
        (file) => path.basename(file.path) === "package.json",
      )) {
        const pkg = requireCanonicalFile(path.join(imageModules, file.path));
        for (const group of ["dependencies", "optionalDependencies", "peerDependencies"])
          if (typeof pkg[group]?.[name] === "string" && pkg[group][name].startsWith("npm:"))
            specs.add(pkg[group][name]);
      }
      if (specs.size !== 1)
        throw new Error("missing or ambiguous installed hoisted alias authority: " + name);
      spec = [...specs][0];
    }
    if (typeof spec !== "string" || !spec.startsWith("npm:"))
      throw new Error("installed rename lacks authoritative exact npm alias: " + name);
    assertPackageIdentity(source, name, spec);
  }
  bindingReceipts.push({
    path: link.path,
    target: link.target,
    name: metadata.name,
    version: metadata.version,
  });
}
// Preflight root additions as well; no late resolution failure may leave target writes.
const rootBindings = new Map();
const unavailable = [];
for (const [name, spec] of requested) {
  if (!packageNamePattern.test(name)) throw new Error("invalid root dependency name");
  let source;
  if (spec.startsWith("workspace:")) {
    source = workspacePackages.get(name);
    if (!source) throw new Error("missing workspace root: " + name);
  } else {
    source = chooseImagePackage(name, spec);
    if (!source) {
      unavailable.push(name);
      continue;
    }
    insideImage(source);
    assertPackageIdentity(source, name, spec);
  }
  const existing = path.join(imageModules, name);
  const installedWorkspace = installedLinks.find((link) => link.path === name && link.workspace);
  if (
    fs.existsSync(existing) &&
    (installedWorkspace?.target ?? fs.realpathSync(existing)) !== source
  )
    throw new Error("installed root binding conflicts with requested source: " + name);
  rootBindings.set(name, source);
}
const copiedBytes = physicalFiles.reduce((sum, item) => sum + item.bytes, 0);
if (!Number.isSafeInteger(copiedBytes)) throw new Error("unsafe installed view size");
const hydrationPlan = {
  mode: "complete-installed-physical-view",
  totalBytes: copiedBytes,
  fileCount: physicalFiles.length,
  entryCount: storeEntries.filter((name) => name !== "node_modules").length,
  limitBytes,
  withinLimit: copiedBytes <= limitBytes,
  physicalFiles,
  bindingReceipts,
  installedLinks,
};
process.stdout.write(JSON.stringify({ hydrationPlan }) + "\n");
if (inventoryOnly) {
  process.stdout.write(
    JSON.stringify({
      inventoryComplete: true,
      planComplete: true,
      diagnosticOnly: true,
      actualTotalBytes: copiedBytes,
      actualTotalFiles: physicalFiles.length,
      actualTotalEntries: hydrationPlan.entryCount,
      capBytes: limitBytes,
      withinCap: hydrationPlan.withinLimit,
      declarationGraph,
      workspaceMappings: Object.fromEntries(workspacePackages),
      rootBindings: Object.fromEntries(rootBindings),
      uiBindings: Object.fromEntries(uiBindings),
      hydrationPlan,
    }) + "\n",
  );
  process.exit(0); // completed measurement is not product qualification
}
if (process.argv.includes("--hydration-plan-only")) process.exit(hydrationPlan.withinLimit ? 0 : 2);
if (!hydrationPlan.withinLimit)
  throw new Error(
    "complete compiler-visible installed view exceeds hydration cap: " +
      copiedBytes +
      " > " +
      limitBytes,
  );
// Every actual installed package (including the original SDK/compiler closure)
// remains present. Internal alias metadata files are counted, not filtered out.
fs.mkdirSync(targetModules);
for (const rel of directories) fs.mkdirSync(path.join(targetModules, rel), { recursive: true });
for (const item of physicalFiles) {
  const destination = path.join(targetModules, item.path);
  fs.copyFileSync(path.join(imageModules, item.path), destination);
  fs.chmodSync(destination, item.mode);
}
for (const link of installedLinks) {
  const destination = path.join(targetModules, link.path);
  const target = link.workspace ? link.target : path.join(targetModules, link.target);
  fs.symlinkSync(
    path.relative(path.dirname(destination), target),
    destination,
    link.directory ? "dir" : "file",
  );
}
const localize = (source) => {
  const rel = path.relative(imageModules, source);
  return rel === ".." || rel.startsWith(".." + path.sep) || path.isAbsolute(rel)
    ? source
    : path.join(targetModules, rel);
};
for (const [name, source] of rootBindings) {
  const destination = path.join(targetModules, name);
  if (fs.existsSync(destination)) {
    if (fs.realpathSync(destination) !== fs.realpathSync(localize(source)))
      throw new Error("installed root binding conflicts with requested source: " + name);
    continue;
  }
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.symlinkSync(localize(source), destination, "dir");
}
if (uiPresent) {
  fs.mkdirSync(uiModules, { recursive: true });
  for (const [name, source] of uiBindings) {
    const destination = path.join(uiModules, name);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.symlinkSync(localize(source), destination, "dir");
  }
}
let actualCopiedBytes = 0;
let actualCopiedFiles = 0;
function verifyLocal(dir) {
  for (const item of fs.readdirSync(dir, { withFileTypes: true })) {
    const file = path.join(dir, item.name);
    if (item.isDirectory()) verifyLocal(file);
    else if (item.isFile()) {
      actualCopiedBytes += fs.statSync(file).size;
      actualCopiedFiles += 1;
    } else if (item.isSymbolicLink()) {
      const rel = path.relative(projectRoot, fs.realpathSync(file));
      if (rel === ".." || rel.startsWith(".." + path.sep) || path.isAbsolute(rel))
        throw new Error("copied binding escapes checkout: " + file);
    } else throw new Error("unsupported copied entry");
  }
}
verifyLocal(targetModules);
if (uiPresent) verifyLocal(uiModules);
if (actualCopiedBytes !== copiedBytes || actualCopiedFiles !== physicalFiles.length)
  throw new Error("installed physical view inventory differs from preflight");
process.stdout.write(
  JSON.stringify({
    projectionSetupComplete: true,
    actualCopiedBytes,
    actualCopiedFiles,
    copiedEntryCount: hydrationPlan.entryCount,
    limitBytes,
    sdkRegistryRootCount: Object.keys(declarationGraph.registryRoots).length,
    projectedRootDependencies: rootBindings.size,
    unavailableRootDependencies: unavailable.length,
    uiBindingCount: uiBindings.size,
    uiLocalStoreBindings: [...uiBindings.values()].filter((source) =>
      source.startsWith(virtualStore + path.sep),
    ).length,
    uiReadonlyImageBindings: 0,
    uiWorkspaceBindings: [...uiBindings.values()].filter(
      (source) => !source.startsWith(virtualStore + path.sep),
    ).length,
  }) + "\n",
);
