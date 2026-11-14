#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";

const [projectInput, imageModulesInput] = process.argv.slice(2);
if (!projectInput || !imageModulesInput) {
  throw new Error("usage: openclaw-image-dependency-projector.mjs <project-root> <image-node-modules>");
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
      if (!requested.has(name)) requested.set(name, String(spec));
    }
  }
}
addRequestedDependencies(manifest);

const workspacePackages = new Map();
if (typeof manifest.name === "string") workspacePackages.set(manifest.name, projectRoot);
function scanWorkspace(directory, depth = 0) {
  if (depth > 4 || !fs.existsSync(directory)) return;
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (!entry.isDirectory() || ["node_modules", ".git", ".artifacts", "coverage"].includes(entry.name)) continue;
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

const storeEntries = fs.readdirSync(virtualStore, { withFileTypes: true })
  .filter((entry) => entry.isDirectory())
  .map((entry) => entry.name);

function packageVersion(candidate) {
  try {
    return JSON.parse(fs.readFileSync(path.join(candidate, "package.json"), "utf8")).version;
  } catch {
    return undefined;
  }
}

function chooseImagePackage(name, spec) {
  const direct = path.join(imageModules, name);
  const hoisted = path.join(virtualStore, "node_modules", name);
  const encoded = name.startsWith("@") ? name.replace("/", "+") : name;
  const candidates = [direct, hoisted];
  for (const entry of storeEntries) {
    if (entry.startsWith(`${encoded}@`)) {
      candidates.push(path.join(virtualStore, entry, "node_modules", name));
    }
  }
  const unique = [...new Set(candidates.filter((candidate) => fs.existsSync(candidate)).map((candidate) => fs.realpathSync(candidate)))];
  if (unique.length === 0) return null;
  if (unique.length === 1) return unique[0];
  const exact = spec.match(/^(?:npm:)?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$/)?.[1];
  if (exact) {
    const matches = unique.filter((candidate) => packageVersion(candidate) === exact);
    if (matches.length === 1) return matches[0];
  }
  if (fs.existsSync(direct)) return fs.realpathSync(direct);
  return null;
}

fs.mkdirSync(targetModules, { mode: 0o755 });
fs.symlinkSync(virtualStore, path.join(targetModules, ".pnpm"), "dir");
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
  const destination = path.join(targetModules, name);
  fs.mkdirSync(path.dirname(destination), { recursive: true, mode: 0o755 });
  fs.symlinkSync(source, destination, "dir");
  projected += 1;
}

process.stdout.write(`projected_dependencies=${projected} unavailable_dependencies=${unavailable.length}\n`);
