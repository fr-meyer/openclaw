import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
// Trusted stdlib observer only. Never imports candidate or native modules.
import fs from "node:fs";
import path from "node:path";
const hash = (b) => createHash("sha256").update(b).digest("hex"),
  json = (v) => JSON.stringify(v);
const digest = (p) => hash(fs.readFileSync(p));
export function inventory(root, rejectLinks = false) {
  if (fs.realpathSync(root) !== root) throw Error("noncanonical observed root");
  const rows = {},
    seen = new Set();
  let logical = 0,
    allocated = 0;
  function walk(dir) {
    for (const name of fs.readdirSync(dir).sort()) {
      const file = path.join(dir, name),
        rel = path.relative(root, file),
        s = fs.lstatSync(file),
        key = s.dev + ":" + s.ino;
      if (s.isSymbolicLink()) {
        if (rejectLinks) throw Error("cache symlink denied");
        const real = fs.realpathSync(file);
        if (
          real !== root &&
          !real.startsWith(root + "/") &&
          !(root === "/app/node_modules" && (real === "/app" || real.startsWith("/app/")))
        )
          throw Error("distribution external symlink");
        rows[rel] = { type: "link", target: fs.readlinkSync(file), canonical: real };
      } else if (s.isDirectory()) {
        rows[rel] = { type: "directory" };
        walk(file);
      } else if (s.isFile()) {
        rows[rel] = { type: "file", bytes: s.size, sha256: digest(file) };
        logical += s.size;
      } else throw Error("unsupported observed inode");
      if (!seen.has(key)) {
        seen.add(key);
        allocated += s.blocks * 512;
      }
    }
  }
  walk(root);
  return {
    root,
    logicalBytes: logical,
    allocatedBytes: allocated,
    inventorySha256: hash(json(rows)),
    entries: rows,
  };
}
function packageRoot(file, name) {
  let at = path.dirname(fs.realpathSync(file));
  for (let i = 0; i < 8; i++, at = path.dirname(at)) {
    const p = path.join(at, "package.json");
    if (fs.existsSync(p) && JSON.parse(fs.readFileSync(p)).name === name) return at;
  }
  throw Error("canonical " + name + " distribution absent");
}
export function observe(runner = spawnSync) {
  const receipt = JSON.parse(fs.readFileSync("/opt/layout/layout-receipt.json"));
  const r = runner(
    process.execPath,
    [
      "/opt/layout/openclaw-image-dependency-projector.mjs",
      "/app",
      "/app/node_modules",
      "--in-place-inventory-only",
    ],
    {
      cwd: "/app",
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
      env: {
        PATH: "/usr/local/bin:/usr/bin:/bin",
        HOME: "/tmp/home",
        COREPACK_ENABLE_NETWORK: "0",
        COREPACK_HOME: "/opt/corepack",
      },
    },
  );
  if (r.error || r.status !== 0) throw Error("independent complete strict graph observer failed");
  const records = r.stdout.trim().split("\n").map(JSON.parse),
    graph = records.find((x) => x.inventoryComplete);
  if (
    !graph ||
    JSON.stringify(Object.keys(graph.declarationGraph.registryRoots).sort()) !==
      JSON.stringify(receipt.sdkRootIds) ||
    JSON.stringify(Object.keys(graph.uiBindings).sort()) !== JSON.stringify(receipt.uiBindingNames)
  )
    throw Error("SDK62/UI52 identity mismatch");
  const modules = inventory("/app/node_modules"),
    cache = inventory("/opt/offline-cache", true),
    store = inventory("/opt/offline-store"),
    corepack = inventory("/opt/corepack");
  if (
    modules.logicalBytes > 3 * 2 ** 30 ||
    modules.allocatedBytes > 3 * 2 ** 30 ||
    cache.logicalBytes > 256 * 2 ** 20 ||
    cache.allocatedBytes > 256 * 2 ** 20
  )
    throw Error("module/cache ceiling exceeded");
  const canonical = fs.realpathSync("/usr/local/bin/pnpm"),
    corepackRoot = packageRoot(canonical, "corepack"),
    corepackDistribution = inventory(corepackRoot),
    pnpmManifests = [];
  for (const [name, row] of Object.entries(corepack.entries))
    if (row.type === "file" && path.basename(name) === "package.json") {
      const p = JSON.parse(fs.readFileSync(path.join("/opt/corepack", name)));
      if (p.name === "pnpm" && p.version === "12.9.0") pnpmManifests.push(name);
    }
  if (pnpmManifests.length !== 1) throw Error("unique full pnpm12.9.0 distribution absent");
  const pnpmDistribution = inventory(path.dirname(path.join("/opt/corepack", pnpmManifests[0])));
  const version = runner("/usr/local/bin/pnpm", ["--version"], {
    encoding: "utf8",
    maxBuffer: 4096,
    env: {
      PATH: "/usr/local/bin:/usr/bin:/bin",
      COREPACK_HOME: "/opt/corepack",
      COREPACK_ENABLE_NETWORK: "0",
      COREPACK_DEFAULT_TO_LATEST: "0",
    },
  });
  if (version.error || version.status !== 0 || version.stdout.trim() !== "12.9.0")
    throw Error("actual offline pnpm version mismatch");
  const pythonCanonical = fs.realpathSync("/usr/bin/python3");
  if (!/^\/usr\/.*python3(?:\.[0-9]+)?$/.test(pythonCanonical))
    throw Error("Python canonical interpreter absent");
  const py = runner(pythonCanonical, ["--version"], { encoding: "utf8", maxBuffer: 4096 });
  if (py.error || py.status !== 0 || !/^Python 3\./.test(py.stdout || py.stderr))
    throw Error("Python interpreter unavailable");
  const metadata = {};
  for (const e of receipt.sourceFiles) {
    const parts = e.path.split("/"),
      take =
        ["package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml", ".npmrc"].includes(e.path) ||
        (path.basename(e.path) === "package.json" &&
          ["packages", "extensions", "examples", "ui"].includes(parts[0])) ||
        parts[0] === "patches";
    if (take) {
      const p = path.join("/app", e.path);
      if (fs.realpathSync(p) !== p || digest(p) !== e.sha256)
        throw Error("observed inert metadata mismatch");
      metadata[e.path] = e.sha256;
    }
  }
  const summary = (v) => Object.fromEntries(Object.entries(v).filter(([k]) => k !== "entries"));
  return {
    schema: 1,
    graph,
    phase: "NETWORK_NONE_ACTUAL_GRAPH_AND_DISTRIBUTION_OBSERVATION",
    candidateTree: receipt.candidateTree,
    receiptSha256: digest("/opt/layout/layout-receipt.json"),
    graphSha256: hash(r.stdout),
    sdkRootIds: receipt.sdkRootIds,
    uiBindingNames: receipt.uiBindingNames,
    metadata,
    cacheHashes: Object.fromEntries(
      Object.entries(cache.entries)
        .filter(([, v]) => v.type === "file")
        .map(([k, v]) => [k, v.sha256]),
    ),
    measures: {
      modules: summary(modules),
      cache: summary(cache),
      store: summary(store),
      corepack: summary(corepack),
    },
    pnpm: {
      version: "12.9.0",
      canonical,
      shimSha256: digest("/usr/local/bin/pnpm"),
      distribution: pnpmDistribution,
    },
    corepackDistribution,
    python: {
      canonical: pythonCanonical,
      sha256: digest(pythonCanonical),
      version: (py.stdout || py.stderr).trim(),
    },
    productQualified: false,
  };
}
if (process.argv[1]?.endsWith("/phase1-observer.mjs")) {
  try {
    console.log("PHASE1_OBSERVATION=" + Buffer.from(JSON.stringify(observe())).toString("base64"));
  } catch (e) {
    console.error("PHASE1_OBSERVER_FAILED=" + e.message);
    process.exitCode = 1;
  }
}
