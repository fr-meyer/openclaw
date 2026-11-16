#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
// Trusted metadata reader. No candidate or installed code is imported.
import fs from "node:fs";
import path from "node:path";
import { gzipSync } from "node:zlib";
const [root, modules, projector] = process.argv.slice(2);
const hash = (b) => createHash("sha256").update(b).digest("hex");
const expectedProjector = "4bb6bcf446ffed9b570605d7693ddc598130b767a9fc6d5e3d0adc8cbe92894b";
const decodedLimit = 16777216,
  wireLimit = 524288;
let emitted = 0;
function emit(v) {
  const s = JSON.stringify(v) + "\n";
  emitted += Buffer.byteLength(s);
  if (emitted > wireLimit) throw Error("wire bound");
  process.stdout.write(s);
}
function need(v, message) {
  if (!v) throw Error(message);
}
try {
  need(root && modules && projector, "arguments");
  need(
    fs.realpathSync(root) === root && fs.realpathSync(projector) === projector,
    "noncanonical trusted paths",
  );
  need(hash(fs.readFileSync(projector)) === expectedProjector, "projector pin");
  const store = fs.realpathSync(path.join(modules, ".pnpm"));
  function relative(f) {
    const r = path.relative(store, f);
    need(r && !r.startsWith("..") && !path.isAbsolute(r), "store escape");
    return r;
  }
  const policyPins = {
    "scripts/lib/local-check-runtime.mts": {
      gitBlob: "57bd5caf153df3c65714321cbe8639676be6018a",
      sha256: "0677859daa8187b8a5b6a1653a6ba559539f9111d85f440e6716dc4582bcc1e5",
      bytes: 14813,
    },
    "scripts/lib/native-declaration-emitter.mts": {
      gitBlob: "5c49e853bf83ff6ae0535bd6bd547f6adf7b72cd",
      sha256: "d1ebce66c0f3b5559569c7f724e9efced98d32c6a1def1a4827224e4e2ae045d",
      bytes: 9602,
    },
    "scripts/lib/native-declaration-filesystem.mts": {
      gitBlob: "a74c907a72057a8da0d0669fade56d5b8c40bd4a",
      sha256: "480b4a5c7c2b227470fa016b87ee60baac60c2a9721ef386e5ddcc5d7b737518",
      bytes: 7785,
    },
    "scripts/lib/native-declaration-subprocess.mts": {
      gitBlob: "d653350827dcd23d3718cf63a8577ba826fd3a9b",
      sha256: "c37d4038c7853e43f45ff03502128bf4d4c19f7158729406eddd3761d3936660",
      bytes: 5153,
    },
    "scripts/lib/native-typescript-toolchain.mts": {
      gitBlob: "20d4ca6c84f4be82eeb312776792ba80fe8fb330",
      sha256: "f856c77465d791e9c518b63da583e476b63d28f912c46ab4ca0b277dcd1c2a4e",
      bytes: 2017,
    },
    "scripts/lib/tsdown-declaration-boundary.mts": {
      gitBlob: "38e586422eb39f2d46633c33fa03770f09166bae",
      sha256: "94d0223a68a164ec2ba0898976f2b075b25681c102721d34b199152e3885e6b7",
      bytes: 8515,
    },
  };
  const policies = Object.entries(policyPins).map(([name, pin]) => {
    const f = path.join(root, name);
    need(fs.realpathSync(f) === f, "policy symlink");
    const b = fs.readFileSync(f);
    need(b.length === pin.bytes && hash(b) === pin.sha256, "policy pin " + name);
    return { path: name, sha256: hash(b), bytes: b.length, source: b.toString("utf8") };
  });
  need(!fs.existsSync(path.join(root, "node_modules")), "already hydrated");
  const r = spawnSync(process.execPath, [projector, root, modules, "--hydration-plan-only"], {
    encoding: "utf8",
    maxBuffer: decodedLimit,
    timeout: 600000,
    env: { PATH: "/usr/local/bin:/usr/bin:/bin", HOME: "/tmp", COREPACK_ENABLE_NETWORK: "0" },
  });
  need(!r.error && [0, 2].includes(r.status) && !r.stderr.trim(), "projector failure");
  need(!fs.existsSync(path.join(root, "node_modules")), "hydration write");
  const records = r.stdout
    .trim()
    .split("\n")
    .map((l) => JSON.parse(l));
  need(records.length === 2, "projector records");
  const graph = records[0].declarationGraph,
    plan = records[1].hydrationPlan;
  need(
    graph &&
      graph.registryRoots &&
      plan &&
      plan.mode === "conservative-installed-link-closure" &&
      plan.limitBytes === 268435456 &&
      Number.isSafeInteger(plan.totalBytes) &&
      typeof plan.withinLimit === "boolean" &&
      plan.withinLimit === plan.totalBytes <= plan.limitBytes &&
      (r.status === 0) === plan.withinLimit,
    "plan schema",
  );
  emit({
    schema: 1,
    kind: "summary",
    complete: false,
    measurementOnly: true,
    projectorSha256: expectedProjector,
    projectorExit: r.status,
    platform: process.platform,
    arch: process.arch,
    declarationGraph: graph,
    hydrationPlan: plan,
  });
  const selection = plan.selectedEntries;
  need(Array.isArray(selection) && selection.length === plan.entryCount, "selected entry count");
  let selectedBytes = 0,
    selectedFiles = 0,
    previous = "";
  for (const item of selection) {
    need(
      item &&
        typeof item.entry === "string" &&
        /^[A-Za-z0-9@_+().,=~-]+$/.test(item.entry) &&
        !item.entry.includes("..") &&
        item.entry !== "node_modules" &&
        item.entry > previous &&
        Number.isSafeInteger(item.bytes) &&
        item.bytes >= 0 &&
        Number.isSafeInteger(item.files) &&
        item.files >= 0,
      "selected entry schema/order",
    );
    previous = item.entry;
    selectedBytes += item.bytes;
    selectedFiles += item.files;
    need(
      Number.isSafeInteger(selectedBytes) && Number.isSafeInteger(selectedFiles),
      "selected totals",
    );
  }
  need(selectedBytes === plan.totalBytes && selectedFiles === plan.fileCount, "selected totals");
  const selected = selection.map((item) => item.entry),
    edges = [],
    entries = [],
    manifests = [],
    nativeFiles = [];
  let metadataBytes = 0;
  function admit(v) {
    metadataBytes += Buffer.byteLength(JSON.stringify(v));
    need(metadataBytes <= decodedLimit - 262144, "decoded inventory bound");
    return v;
  }
  // Links are evidence only. Selection comes exclusively from the actual projector.
  function scan(dir) {
    for (const item of fs.readdirSync(dir, { withFileTypes: true })) {
      const f = path.join(dir, item.name);
      if (item.isDirectory()) scan(f);
      else if (item.isSymbolicLink()) {
        const target = fs.realpathSync(f),
          targetEntry = relative(target).split(path.sep)[0];
        need(selected.includes(targetEntry), "link outside selected plan");
        edges.push(admit({ from: relative(f), to: relative(target) }));
      }
    }
  }
  for (const entry of selected) scan(path.join(store, entry));
  const principal = new Set();
  for (const entry of [...selected].sort()) {
    const nm = path.join(store, entry, "node_modules");
    for (const e of fs.readdirSync(nm, { withFileTypes: true })) {
      if (!e.isDirectory()) continue;
      if (e.name.startsWith("@")) {
        for (const q of fs.readdirSync(path.join(nm, e.name), { withFileTypes: true }))
          if (q.isDirectory()) principal.add(path.join(nm, e.name, q.name, "package.json"));
      } else principal.add(path.join(nm, e.name, "package.json"));
    }
    let bytes = 0,
      files = 0,
      allocatedBytes = 0;
    const inodes = new Set();
    function walk(dir, native = false) {
      for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
        const f = path.join(dir, e.name);
        if (e.isDirectory()) walk(f, native);
        else if (e.isFile()) {
          const st = fs.statSync(f);
          bytes += st.size;
          files++;
          const key = st.dev + ":" + st.ino;
          if (!inodes.has(key)) {
            inodes.add(key);
            allocatedBytes += st.blocks * 512;
          }
          if (native) nativeFiles.push(admit({ path: relative(f), bytes: st.size }));
        } else need(e.isSymbolicLink(), "unsupported entry");
      }
    }
    // Native package detection uses actual principal manifest identity, not guessed platform pruning.
    for (const f of principal) {
      if (!f.startsWith(path.join(store, entry) + path.sep) || !fs.existsSync(f)) continue;
      const raw = fs.readFileSync(f);
      need(raw.length <= 4194304, "manifest bound");
      const p = JSON.parse(raw);
      const m = { path: relative(f), sha256: hash(raw) };
      for (const k of [
        "name",
        "version",
        "os",
        "cpu",
        "libc",
        "exports",
        "types",
        "typings",
        "bin",
        "dependencies",
        "optionalDependencies",
        "peerDependencies",
        "peerDependenciesMeta",
      ])
        if (p[k] !== undefined) m[k] = p[k];
      manifests.push(admit(m));
      if (typeof p.name === "string" && /typescript|tsgo/.test(p.name)) {
        function nativeWalk(d) {
          for (const e of fs.readdirSync(d, { withFileTypes: true })) {
            const q = path.join(d, e.name);
            if (e.isDirectory()) nativeWalk(q);
            else if (e.isFile())
              nativeFiles.push(admit({ path: relative(q), bytes: fs.statSync(q).size }));
          }
        }
        nativeWalk(path.dirname(f));
      }
    }
    walk(path.join(store, entry));
    const expected = selection[entries.length];
    need(
      entry === expected.entry && bytes === expected.bytes && files === expected.files,
      "per-entry reconciliation",
    );
    entries.push(admit({ entry, bytes, files, allocatedBytes, uniqueInodes: inodes.size }));
  }
  need(
    entries.length === plan.entryCount &&
      entries.reduce((n, e) => n + e.bytes, 0) === plan.totalBytes &&
      entries.reduce((n, e) => n + e.files, 0) === plan.fileCount,
    "R2 inventory reconciliation",
  );
  need(
    entries.every((item, i) => item.entry === selection[i].entry),
    "exact selected entry set",
  );
  const compilerRecord = manifests.find(
    (m) => m.name === "typescript" || m.name === "@typescript/native-preview",
  );
  need(compilerRecord, "compiler identity");
  const compilerRoot = path.dirname(path.join(store, compilerRecord.path));
  const manifest = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
  const compilerRaw = fs.readFileSync(path.join(compilerRoot, "package.json")),
    compilerManifest = JSON.parse(compilerRaw);
  const output = {
    schema: 1,
    complete: true,
    scope: "selected-installed-link-closure",
    measurementOnly: true,
    physicalHydrationWrites: 0,
    candidateImports: 0,
    policies,
    compiler: {
      path: relative(compilerRoot),
      requested:
        manifest.dependencies?.typescript ??
        manifest.devDependencies?.typescript ??
        manifest.optionalDependencies?.typescript,
      name: compilerManifest.name,
      version: compilerManifest.version,
      manifestSha256: hash(compilerRaw),
    },
    entries,
    edges,
    manifests,
    nativeFiles,
    byteSemantics:
      "bytes is logical regular-file sum (hardlinks counted per path); allocatedBytes and uniqueInodes deduplicate within each entry only, not exclusive physical image disk use",
  };
  const raw = Buffer.from(JSON.stringify(output));
  need(raw.length <= decodedLimit, "decoded bound");
  const zipped = gzipSync(raw, { level: 9, mtime: 0 });
  const encoded = zipped.toString("base64"),
    size = 48000,
    chunks = Math.ceil(encoded.length / size);
  need(emitted + encoded.length + chunks * 150 + 2048 <= wireLimit, "compressed wire bound");
  emit({
    schema: 1,
    kind: "inventory-header",
    codec: "gzip+base64",
    decodedLimit,
    decodedBytes: raw.length,
    decodedSha256: hash(raw),
    compressedBytes: zipped.length,
    entryCount: entries.length,
    expectedChunks: chunks,
    complete: false,
  });
  for (let i = 0; i < chunks; i++)
    emit({ kind: "inventory-chunk", index: i, data: encoded.slice(i * size, (i + 1) * size) });
  emit({
    schema: 1,
    kind: "inventory-end",
    expectedChunks: chunks,
    decodedSha256: hash(raw),
    complete: true,
  });
} catch {
  emit({
    schema: 1,
    kind: "measurement-error",
    complete: false,
    error: "metadata measurement failed; preceding summary if present remains diagnostic only",
  });
  process.exitCode = 1;
}
