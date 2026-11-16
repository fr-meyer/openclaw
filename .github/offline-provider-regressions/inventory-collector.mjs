#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
const [candidate, imageModules, output, tooling] = process.argv.slice(2);
if (
  process.argv.length !== 6 ||
  candidate !== "/candidate" ||
  imageModules !== "/app/node_modules" ||
  output !== "/inventory" ||
  tooling !== "/tooling"
)
  throw new Error("fixed inventory-only container paths required");
const write = (name, value) =>
  fs.writeFileSync(path.join(output, name), JSON.stringify(value, null, 2) + "\n");
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
let stage = "initialize";
const steps = [];
function scan(root, hashFiles = false) {
  const files = [],
    links = [],
    directories = [],
    packages = [],
    errors = [];
  let regularBytes = 0;
  function walk(directory) {
    let entries;
    try {
      entries = fs
        .readdirSync(directory, { withFileTypes: true })
        .sort((a, b) => a.name.localeCompare(b.name));
    } catch (error) {
      errors.push({ path: directory, code: error.code, message: error.message });
      return;
    }
    for (const entry of entries) {
      const file = path.join(directory, entry.name),
        rel = path.relative(root, file);
      try {
        const st = fs.lstatSync(file);
        if (st.isDirectory()) {
          directories.push(rel);
          walk(file);
        } else if (st.isSymbolicLink()) {
          const record = { path: rel, spelling: fs.readlinkSync(file) };
          try {
            record.canonicalTarget = fs.realpathSync(file);
            record.targetRelativeToImage = path.relative(imageModules, record.canonicalTarget);
            record.targetDirectory = fs.statSync(record.canonicalTarget).isDirectory();
            const manifest = path.join(record.canonicalTarget, "package.json");
            if (record.targetDirectory && fs.existsSync(manifest)) {
              const pkg = JSON.parse(fs.readFileSync(manifest, "utf8"));
              record.packageIdentity = { name: pkg.name, version: pkg.version };
            }
          } catch (error) {
            record.error = { code: error.code, message: error.message };
          }
          links.push(record);
        } else if (st.isFile()) {
          regularBytes += st.size;
          if (!Number.isSafeInteger(regularBytes))
            throw new Error("unsafe raw inventory byte count");
          files.push({
            path: rel,
            bytes: st.size,
            mode: st.mode & 0o777,
            ...(hashFiles ? { sha256: sha(fs.readFileSync(file)) } : {}),
          });
          if (entry.name === "package.json") {
            try {
              const pkg = JSON.parse(fs.readFileSync(file, "utf8"));
              packages.push({
                path: rel,
                name: pkg.name,
                version: pkg.version,
                dependencies: pkg.dependencies,
                optionalDependencies: pkg.optionalDependencies,
                peerDependencies: pkg.peerDependencies,
              });
            } catch (error) {
              packages.push({ path: rel, error: error.message });
            }
          }
        } else errors.push({ path: rel, message: "unsupported entry type" });
      } catch (error) {
        errors.push({ path: rel, code: error.code, message: error.message });
      }
    }
  }
  walk(root);
  return {
    root,
    scanComplete: errors.length === 0,
    regularBytes,
    regularFiles: files.length,
    storeEntryCount: directories.filter(
      (name) => /^\.pnpm\/[^/]+$/.test(name) && name !== ".pnpm/node_modules",
    ).length,
    directories,
    files,
    links,
    packages,
    errors,
  };
}
function command(label, argv, stdoutFile, stderrFile) {
  stage = label;
  const out = fs.openSync(path.join(output, stdoutFile), "w"),
    err = fs.openSync(path.join(output, stderrFile), "w");
  let result;
  try {
    result = spawnSync(argv[0], argv.slice(1), {
      cwd: candidate,
      stdio: ["ignore", out, err],
      timeout: 1200000,
    });
  } finally {
    fs.closeSync(out);
    fs.closeSync(err);
  }
  const row = {
    step: label,
    argv,
    status: result.status,
    signal: result.signal,
    error: result.error?.message,
  };
  steps.push(row);
  write("steps.json", steps);
  return row;
}
let exit = 1;
try {
  stage = "raw-installed-view";
  const raw = scan(imageModules);
  write("raw-installed-view.json", raw);
  stage = "raw-ui-bindings";
  const ui = scan("/app/ui/node_modules");
  write("raw-ui-bindings.json", ui);
  stage = "cache-physical-inventory";
  const cache = scan("/opt/offline-cache", true);
  write("cache-files.json", cache);
  stage = "cache-manifest";
  const manifest = fs.readFileSync("/opt/offline-cache.SHA256");
  fs.writeFileSync(path.join(output, "offline-cache.SHA256"), manifest);
  const cacheHashes = command(
    "cache-readonly-hash-check",
    ["sha256sum", "-c", "--quiet", "/opt/offline-cache.SHA256"],
    "cache-hash-check.stdout",
    "cache-hash-check.stderr",
  );
  const cacheDu = command(
    "cache-readonly-allocation",
    ["du", "-sk", "/opt/offline-cache"],
    "cache-du.stdout",
    "cache-du.stderr",
  );
  const duOutput = fs.readFileSync(path.join(output, "cache-du.stdout"), "utf8");
  const sizeMatch = /^([0-9]+)\s+\/opt\/offline-cache\s*$/.exec(duOutput);
  const allocatedKiB = sizeMatch ? Number(sizeMatch[1]) : null;
  write("cache-summary.json", {
    manifestSha256: sha(manifest),
    hashesStatus: cacheHashes.status,
    duStatus: cacheDu.status,
    allocatedKiB,
    allocatedBytes: allocatedKiB === null ? null : allocatedKiB * 1024,
    allocatedCapKiB: 131072,
    withinAllocatedCap: allocatedKiB === null ? null : allocatedKiB <= 131072,
    regularBytes: cache.regularBytes,
    regularFiles: cache.regularFiles,
    readOnly: true,
    pnpmInvoked: false,
  });
  const planner = command(
    "full-view-planner-inventory-only",
    [
      process.execPath,
      path.join(tooling, "openclaw-image-dependency-projector.mjs"),
      candidate,
      imageModules,
      "--inventory-only",
    ],
    "planner.ndjson",
    "planner.stderr",
  );
  stage = "planner-receipt";
  let plan;
  const records = [];
  for (const line of fs
    .readFileSync(path.join(output, "planner.ndjson"), "utf8")
    .split("\n")
    .filter(Boolean)) {
    try {
      records.push(JSON.parse(line));
    } catch (error) {
      records.push({ unparsedDiagnostic: line, error: error.message });
    }
  }
  const graph = records.find((record) => record.declarationGraph)?.declarationGraph;
  if (graph) write("declaration-graph.json", graph);
  if (planner.status === 0) {
    plan = records.find((record) => record.inventoryComplete === true);
    if (!plan || !plan.planComplete || plan.capBytes !== 335544320)
      throw new Error("missing complete fixed-cap inventory receipt");
    write("complete-plan.json", plan);
  }
  const noProjectionWrites =
    !fs.existsSync(path.join(candidate, "node_modules")) &&
    !fs.existsSync(path.join(candidate, "ui/node_modules"));
  if (!noProjectionWrites) throw new Error("inventory mode unexpectedly materialized dependencies");
  const success =
    raw.scanComplete &&
    ui.scanComplete &&
    cache.scanComplete &&
    cacheHashes.status === 0 &&
    cacheDu.status === 0 &&
    allocatedKiB !== null &&
    planner.status === 0 &&
    Boolean(plan);
  exit = success ? 0 : 1;
  write("RESULT.json", {
    diagnosticOnly: true,
    inventoryObserved: true,
    productQualified: false,
    status: !success
      ? "DIAGNOSTIC_FAILURE"
      : plan.withinCap
        ? "INVENTORY_COMPLETE_WITHIN_CAP"
        : "INVENTORY_COMPLETE_CAP_EXCEEDED",
    planComplete: Boolean(plan),
    noProjectionWrites,
    planner,
    rawScanComplete: raw.scanComplete,
    uiScanComplete: ui.scanComplete,
    capBytes: 335544320,
    withinCap: plan?.withinCap ?? null,
    actualTotalBytes: plan?.actualTotalBytes ?? raw.regularBytes,
    actualTotalFiles: plan?.actualTotalFiles ?? raw.regularFiles,
    cacheAllocationObserved: allocatedKiB,
    rawInventoryAvailable: true,
    exit,
  });
} catch (error) {
  exit = 1;
  write("RESULT.json", {
    diagnosticOnly: true,
    productQualified: false,
    status: "DIAGNOSTIC_FAILURE",
    stage,
    error: { name: error.name, code: error.code, message: error.message, stack: error.stack },
    exit: 1,
  });
} finally {
  const files = {};
  for (const name of fs.readdirSync(output).sort()) {
    const file = path.join(output, name);
    if (name !== "filesSHA256.json" && fs.lstatSync(file).isFile())
      files[name] = sha(fs.readFileSync(file));
  }
  write("filesSHA256.json", files);
}
process.exitCode = exit;
