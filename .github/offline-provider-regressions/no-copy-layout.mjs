#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { deflateSync } from "node:zlib";
const SELF = fileURLToPath(import.meta.url),
  TOOLS = path.dirname(SELF);
const sha = (value, algorithm = "sha256") => createHash(algorithm).update(value).digest("hex");
const json = (value) => JSON.stringify(value, null, 2) + "\n";
const fail = (message) => {
  throw new Error(message);
};
const fixedImage = (value) => /^sha256:[a-f0-9]{64}$/.test(value);
const positive = (value) => Number.isSafeInteger(value) && value > 0;
const logicalPath = (value) =>
  typeof value === "string" &&
  value.length > 0 &&
  !value.includes(String.fromCharCode(92)) &&
  !value.includes(String.fromCharCode(0)) &&
  !path.posix.isAbsolute(value) &&
  value.split("/").every((part) => part && part !== "." && part !== "..");
export function fileDigest(file) {
  const hash = createHash("sha256"),
    buffer = Buffer.alloc(65536),
    fd = fs.openSync(file, "r");
  try {
    let n;
    while ((n = fs.readSync(fd, buffer, 0, buffer.length, null)) !== 0)
      hash.update(buffer.subarray(0, n));
  } finally {
    fs.closeSync(fd);
  }
  return hash.digest("hex");
}
function canonical(file) {
  if (fs.realpathSync(file) !== path.resolve(file)) fail("noncanonical input: " + file);
  return path.resolve(file);
}
function writeNew(file, data, mode = 0o644) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, data, { flag: "wx", mode });
}
function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}
function object(type, body) {
  const raw = Buffer.concat([Buffer.from(type + " " + body.length + "\0"), body]);
  return { oid: sha(raw, "sha1"), compressed: deflateSync(raw) };
}
function treeObjects(entries) {
  const root = new Map(),
    objects = new Map();
  for (const entry of entries) {
    let node = root;
    const parts = entry.path.split("/");
    for (const part of parts.slice(0, -1)) {
      if (!node.has(part)) node.set(part, new Map());
      node = node.get(part);
      if (!(node instanceof Map)) fail("source file/directory collision");
    }
    if (node.has(parts.at(-1))) fail("duplicate source path");
    node.set(parts.at(-1), entry);
  }
  function build(node) {
    const records = [...node].map(([name, item]) => ({
      name,
      directory: item instanceof Map,
      item,
    }));
    records.sort((a, b) =>
      Buffer.compare(
        Buffer.from(a.name + (a.directory ? "/" : "")),
        Buffer.from(b.name + (b.directory ? "/" : "")),
      ),
    );
    const body = Buffer.concat(
      records.map(({ name, directory, item }) =>
        Buffer.concat([
          Buffer.from((directory ? "40000" : item.mode) + " " + name + "\0"),
          Buffer.from(directory ? build(item) : item.oid, "hex"),
        ]),
      ),
    );
    const result = object("tree", body);
    objects.set(result.oid, result.compressed);
    return result.oid;
  }
  return { tree: build(root), objects };
}
function indexBytes(entries) {
  const header = Buffer.alloc(12);
  header.write("DIRC");
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(entries.length, 8);
  const records = [...entries]
    .sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)))
    .map((entry) => {
      const name = Buffer.from(entry.path),
        length = Math.ceil((62 + name.length + 1) / 8) * 8,
        record = Buffer.alloc(length);
      record.writeUInt32BE(parseInt(entry.mode, 8), 24);
      record.writeUInt32BE(entry.bytes, 36);
      Buffer.from(entry.oid, "hex").copy(record, 40);
      record.writeUInt16BE(Math.min(name.length, 4095), 60);
      name.copy(record, 62);
      return record;
    });
  const body = Buffer.concat([header, ...records]);
  return Buffer.concat([body, Buffer.from(sha(body, "sha1"), "hex")]);
}
function limits(config) {
  for (const key of [
    "sourceLimitBytes",
    "sourceFileLimit",
    "singleSourceFileLimitBytes",
    "metadataLimitBytes",
    "immutableLimitBytes",
    "receiptLimitBytes",
  ])
    if (!positive(config[key])) fail("explicit reviewed finite limit required: " + key);
  if (config.receiptLimitBytes < 128 * 1024 || config.receiptLimitBytes > 64 * 1024 * 1024)
    fail("host receipt budget exceeds fixed64MiB reservation");
  if (
    !/^[a-f0-9]{40}$/.test(config.expectedTree) ||
    !/^[a-f0-9]{64}$/.test(config.expectedLockSha256)
  )
    fail("exact source tree/lock provenance required");
}
export function sourcePlan(config) {
  limits(config);
  const root = canonical(config.sourceRoot),
    trackedFile = canonical(config.trackedManifest);
  if (
    !/^[a-f0-9]{64}$/.test(config.expectedTrackedManifestSha256 ?? "") ||
    fileDigest(trackedFile) !== config.expectedTrackedManifestSha256
  )
    fail("approved complete tracked-manifest digest mismatch");
  const tracked = readJson(trackedFile);
  if (!Array.isArray(tracked) || tracked.length > config.sourceFileLimit)
    fail("source file budget");
  const entries = [],
    seen = new Set(),
    blobs = new Map();
  let bytes = 0;
  for (const item of tracked) {
    if (
      item.path === "packages/plugin-sdk/dist" ||
      item.path.startsWith("packages/plugin-sdk/dist/")
    )
      fail("tracked input collides with SDK generated mount");
    if (
      !logicalPath(item.path) ||
      item.path.split("/").some((p) => ["node_modules", ".git", ".artifacts"].includes(p)) ||
      !["100644", "100755", "120000"].includes(item.mode)
    )
      fail("unsupported/protected source path or mode");
    if (seen.has(item.path)) fail("duplicate source manifest path");
    seen.add(item.path);
    const file = path.join(root, item.path),
      st = fs.lstatSync(file);
    let data;
    if (fs.realpathSync(path.dirname(file)) !== path.dirname(file))
      fail("source traverses symlinked directory");
    if (item.mode !== "120000" && fs.realpathSync(file) !== file)
      fail("noncanonical regular source file");
    if (item.mode === "120000") {
      if (!st.isSymbolicLink() || path.isAbsolute(fs.readlinkSync(file)))
        fail("source symlink mode/absolute-target mismatch");
      const actual = fs.realpathSync(file),
        rel = path.relative(root, actual);
      if (rel === ".." || rel.startsWith(".." + path.sep) || path.isAbsolute(rel))
        fail("external candidate symlink");
      data = Buffer.from(fs.readlinkSync(file));
    } else {
      if (
        !st.isFile() ||
        (st.mode & 0o111 ? "100755" : "100644") !== item.mode ||
        st.size > config.singleSourceFileLimitBytes
      )
        fail("source file/mode/size mismatch");
      data = fs.readFileSync(file);
    }
    bytes += data.length;
    if (!Number.isSafeInteger(bytes) || bytes > config.sourceLimitBytes) fail("source byte budget");
    if (!/^[a-f0-9]{64}$/.test(item.sha256 ?? "") || sha(data) !== item.sha256)
      fail("tracked SHA256 content mismatch");
    const blob = object("blob", data);
    if (item.oid && item.oid !== blob.oid) fail("tracked blob mismatch");
    entries.push({
      path: item.path,
      mode: item.mode,
      oid: blob.oid,
      bytes: data.length,
      sha256: sha(data),
    });
    blobs.set(blob.oid, { bytes: blob.compressed.length, sha256: sha(blob.compressed) });
  }
  const graph = treeObjects(entries);
  if (graph.tree !== config.expectedTree) fail("exact candidate tree mismatch");
  const lock = entries.find((e) => e.path === "pnpm-lock.yaml");
  if (!lock || lock.sha256 !== config.expectedLockSha256) fail("lock provenance mismatch");
  const commit = object(
    "commit",
    Buffer.from(
      "tree " +
        graph.tree +
        "\nauthor Isolated Snapshot <snapshot@invalid> 0 +0000\ncommitter Isolated Snapshot <snapshot@invalid> 0 +0000\n\nImmutable source snapshot\n",
    ),
  );
  graph.objects.set(commit.oid, commit.compressed);
  const index = indexBytes(entries);
  const gitBytes =
    index.length +
    [...blobs.values()].reduce((a, b) => a + b.bytes, 0) +
    [...graph.objects.values()].reduce((a, b) => a + b.length, 0) +
    1024;
  return {
    root,
    entries,
    bytes,
    tree: graph.tree,
    gitBytes,
    index,
    objects: graph.objects,
    commit: commit.oid,
    blobObjects: blobs,
  };
}
export function isMetadata(name) {
  return (
    path.posix.basename(name) === "package.json" ||
    ["pnpm-lock.yaml", "pnpm-workspace.yaml", ".npmrc"].includes(name) ||
    name.startsWith("patches/")
  );
}
function inertMetadata(plan, config) {
  const entries = plan.entries.filter((entry) => isMetadata(entry.path));
  if (entries.some((entry) => entry.mode === "120000")) fail("inert metadata symlink");
  const required = ["package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml", ".npmrc"];
  if (required.some((p) => !entries.some((e) => e.path === p))) fail("missing inert metadata");
  if (
    plan.entries.some((e) =>
      [".pnpmfile.cjs", "pnpmfile.cjs"].includes(path.posix.basename(e.path)),
    )
  )
    fail("candidate pnpm hook present");
  if (
    /pnpmfile|readPackage|afterAllResolved|(?:^|\n)\s*(?:ignore-scripts|ignore-pnpmfile)\s*=\s*false/i.test(
      fs.readFileSync(path.join(plan.root, ".npmrc"), "utf8"),
    )
  )
    fail("unsafe pnpm config");
  const bytes = entries.reduce((n, e) => n + e.bytes, 0);
  if (bytes > config.metadataLimitBytes) fail("inert metadata budget");
  const manifest = entries.map(({ path, mode, bytes, sha256 }) => ({ path, mode, bytes, sha256 }));
  if (sha(json(manifest)) !== config.expectedMetadataSha256)
    fail("approved complete inert metadata digest mismatch");
  return { entries, bytes, manifest };
}
function copyEntry(root, destination, entry) {
  const file = path.join(root, entry.path),
    data = entry.mode === "120000" ? Buffer.from(fs.readlinkSync(file)) : fs.readFileSync(file);
  if (sha(data) !== entry.sha256) fail("source changed after preflight");
  const target = path.join(destination, entry.path);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  if (entry.mode === "120000") fs.symlinkSync(data.toString(), target);
  else writeNew(target, data, entry.mode === "100755" ? 0o755 : 0o644);
}
export function prepareInert(config, destination) {
  const plan = sourcePlan(config),
    metadata = inertMetadata(plan, config);
  if (fs.existsSync(destination)) fail("new inert context required");
  canonical(path.dirname(path.resolve(destination)));
  const dockerfile =
    fs
      .readFileSync(path.join(TOOLS, "Dockerfile"), "utf8")
      .replace("COPY . /app", "COPY manifests/ /app/") +
    "\nCOPY trusted /opt/layout\nRUN node /opt/layout/no-copy-layout.mjs snapshot /opt/layout/image-manifest.json\n";
  fs.mkdirSync(destination);
  for (const entry of metadata.entries)
    copyEntry(plan.root, path.join(destination, "manifests"), entry);
  writeNew(path.join(destination, "Dockerfile"), dockerfile);
  writeNew(path.join(destination, "trusted/no-copy-layout.mjs"), fs.readFileSync(SELF));
  writeNew(
    path.join(destination, "trusted/openclaw-image-dependency-projector.mjs"),
    fs.readFileSync(path.join(TOOLS, "openclaw-image-dependency-projector.mjs")),
  );
  writeNew(path.join(destination, "inert-manifest.json"), json(metadata.manifest));
  writeNew(path.join(destination, "trusted/inert-manifest.json"), json(metadata.manifest));
  writeNew(path.join(destination, "trusted/dependency-Dockerfile"), dockerfile);
  return {
    phase: "NETWORKED_INERT_ONLY",
    candidateTree: plan.tree,
    metadataBytes: metadata.bytes,
    metadataSha256: sha(json(metadata.manifest)),
    candidateSourceIncluded: false,
    dependencyOrCacheCopies: 0,
    dockerfileSha256: sha(dockerfile),
  };
}
export function snapshot(output) {
  if (output !== "/opt/layout/image-manifest.json" || process.cwd() !== "/app")
    fail("fixed network-preparation snapshot paths required");
  const roots = ["/app", "/opt/offline-store", "/opt/offline-cache", "/opt/corepack"],
    files = [],
    links = [],
    directories = [];
  let bytes = 0;
  function walk(directory) {
    for (const entry of fs
      .readdirSync(directory, { withFileTypes: true })
      .sort((a, b) => a.name.localeCompare(b.name))) {
      const file = path.join(directory, entry.name),
        st = fs.lstatSync(file);
      if (st.isDirectory()) {
        directories.push(file);
        walk(file);
      } else if (st.isFile()) {
        bytes += st.size;
        if (!Number.isSafeInteger(bytes)) fail("unsafe immutable accounting");
        files.push({ path: file, bytes: st.size, sha256: fileDigest(file), mode: st.mode & 0o777 });
      } else if (st.isSymbolicLink())
        links.push({
          path: file,
          spelling: fs.readlinkSync(file),
          canonicalTarget: fs.realpathSync(file),
        });
      else fail("unsupported protected entry: " + file);
    }
  }
  for (const root of roots) {
    canonical(root);
    walk(root);
  }
  const value = {
    version: 1,
    approvedMetadataSha256: fileDigest("/opt/layout/inert-manifest.json"),
    toolingSha256: fileDigest(SELF),
    dependencyDockerfileSha256: fileDigest("/opt/layout/dependency-Dockerfile"),
    phase: "NETWORKED_INERT_ONLY",
    candidateCodePresent: false,
    roots,
    logicalBytes: bytes,
    files,
    links,
    directories,
    metadataOnlyAtAppRoot: true,
  };
  writeNew(output, json(value));
  return { protectedLogicalBytes: bytes, fileCount: files.length, sha256: fileDigest(output) };
}
export function prepareFinal(config, destination) {
  const plan = sourcePlan(config);
  inertMetadata(plan, config);
  if (fileDigest(canonical(config.baseImageReceipt)) !== config.expectedBaseImageReceiptSha256)
    fail("approved opaque base-image receipt digest mismatch");
  const image = readJson(canonical(config.baseImageReceipt)),
    raw = fs.readFileSync(canonical(config.baseSnapshot)),
    base = JSON.parse(raw);
  if (
    sha(raw) !== config.expectedBaseSnapshotSha256 ||
    base.dependencyDockerfileSha256 !== config.expectedDependencyRecipeSha256
  )
    fail("approved base snapshot/recipe digest mismatch");
  if (
    !fixedImage(image.id) ||
    !positive(image.size) ||
    image.snapshotSha256 !== sha(raw) ||
    base.phase !== "NETWORKED_INERT_ONLY" ||
    base.candidateCodePresent !== false ||
    base.approvedMetadataSha256 !== config.expectedMetadataSha256 ||
    base.toolingSha256 !== fileDigest(SELF)
  )
    fail("immutable dependency-image provenance mismatch");
  const files = new Map(base.files.map((entry) => [entry.path, entry])),
    links = new Map(base.links.map((entry) => [entry.path, entry])),
    directories = new Set(base.directories),
    copy = [];
  for (const entry of plan.entries) {
    const file = "/app/" + entry.path,
      protectedFile = files.get(file);
    if (protectedFile) {
      if (
        entry.mode === "120000" ||
        entry.sha256 !== protectedFile.sha256 ||
        entry.bytes !== protectedFile.bytes ||
        (protectedFile.mode & 0o111 ? "100755" : "100644") !== entry.mode
      )
        fail("protected source/metadata collision: " + entry.path);
      continue;
    }
    if (isMetadata(entry.path)) fail("candidate metadata absent from dependency image");
    if (directories.has(file) || links.has(file)) fail("protected path collision");
    for (
      let parent = path.posix.dirname(file);
      parent !== "/app";
      parent = path.posix.dirname(parent)
    )
      if (files.has(parent) || links.has(parent)) fail("source traverses protected file/link");
    copy.push(entry);
  }
  const extras = config.extraTrustedModules ?? [],
    extraNames = new Set();
  let extraBytes = 0;
  for (const module of extras) {
    if (
      !/^[a-z][a-z0-9_-]*\.(?:mjs|py|json)$/.test(module.name) ||
      ["no-copy-layout.mjs", "openclaw-image-dependency-projector.mjs"].includes(module.name) ||
      extraNames.has(module.name) ||
      !/^[a-f0-9]{64}$/.test(module.sha256)
    )
      fail("invalid extra trusted module identity");
    canonical(module.file);
    const rel = path.relative(plan.root, module.file);
    if (rel !== ".." && !rel.startsWith(".." + path.sep) && !path.isAbsolute(rel))
      fail("candidate source cannot masquerade as trusted setup module");
    if (fileDigest(module.file) !== module.sha256) fail("extra trusted module pin mismatch");
    extraNames.add(module.name);
    extraBytes += fs.statSync(module.file).size;
  }
  if (extraBytes > config.metadataLimitBytes) fail("trusted tooling metadata budget");
  const copyBytes = copy.reduce((n, e) => n + e.bytes, 0),
    immutableUpperBound =
      image.size +
      copyBytes +
      plan.gitBytes +
      plan.entries.reduce((n, e) => n + (e.path.split("/").length + 4) * 8192, 0) +
      raw.length +
      1024 * 1024 +
      extraBytes;
  if (
    !Number.isSafeInteger(immutableUpperBound) ||
    immutableUpperBound > config.immutableLimitBytes
  )
    fail("separate immutable-image budget exceeded before writes");
  if (fs.existsSync(destination)) fail("new final context required");
  canonical(path.dirname(path.resolve(destination)));

  const gitConfig =
    "[core]\n repositoryformatversion = 0\n bare = false\n filemode = true\n worktree = /app\n hooksPath = /dev/null\n";
  const gitManifest = {
    index: sha(plan.index),
    HEAD: sha("ref: refs/heads/isolated-readonly\n"),
    "refs/heads/isolated-readonly": sha(plan.commit + "\n"),
    config: sha(gitConfig),
  };
  for (const [oid, item] of plan.blobObjects)
    gitManifest["objects/" + oid.slice(0, 2) + "/" + oid.slice(2)] = item.sha256;
  for (const [oid, data] of plan.objects)
    gitManifest["objects/" + oid.slice(0, 2) + "/" + oid.slice(2)] = sha(data);
  for (const [key, count] of [
    ["sdkRootIds", 62],
    ["uiBindingNames", 52],
  ])
    if (
      !Array.isArray(config[key]) ||
      config[key].length !== count ||
      new Set(config[key]).size !== count ||
      config[key].some(
        (x) =>
          typeof x !== "string" || !/^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/.test(x),
      )
    )
      fail("complete independently bound root identities required: " + key);
  const receipt = {
    sdkRootIds: [...config.sdkRootIds].sort(),
    uiBindingNames: [...config.uiBindingNames].sort(),
    gitManifest,
    version: 1,
    canonicalRoot: "/app",
    candidateTree: plan.tree,
    lockSha256: config.expectedLockSha256,
    metadataSha256: config.expectedMetadataSha256,
    baseImage: image.id,
    baseImageSize: image.size,
    baseSnapshotSha256: sha(raw),
    protectedLogicalBytes: base.logicalBytes,
    sourceCopiedBytes: copyBytes,
    sourceCopiedFiles: copy.length,
    gitSnapshotBytes: plan.gitBytes,
    immutableUpperBound,
    immutableLimitBytes: config.immutableLimitBytes,
    writableAccounting: WRITABLE,
    dependencyOrCacheCopies: 0,
    finalImageHasCandidateRun: false,
    sourceFiles: plan.entries,
    toolingPins: {
      "no-copy-layout.mjs": fileDigest(SELF),
      "openclaw-image-dependency-projector.mjs": fileDigest(
        path.join(TOOLS, "openclaw-image-dependency-projector.mjs"),
      ),
    },
  };
  for (const module of extras) receipt.toolingPins[module.name] = module.sha256;
  if (config.offlineQualification) {
    const q = config.offlineQualification;
    if (
      !extraNames.has("offline_lock.py") ||
      !extraNames.has("offline-spec.json") ||
      !extraNames.has("offline-image-receipt.json") ||
      !/^\/usr\/.*python3(?:\.[0-9]+)?$/.test(q.pythonCanonical) ||
      !/^[a-f0-9]{64}$/.test(q.pythonSha256)
    )
      fail("offline stage requires pinned recipe/spec/graph receipt/interpreter");
    receipt.offlineQualification = q;
  }
  const receiptText = json(receipt),
    receiptSha256 = sha(receiptText);
  const dockerfile =
    "ARG DEPENDENCY_IMAGE\nFROM " +
    image.id +
    "\nCOPY source/ /app/\nCOPY git/ /app/.git/\nCOPY trusted/ /opt/layout/\nLABEL org.openclaw.layout.receipt-sha256=" +
    receiptSha256 +
    "\nWORKDIR /app\n";
  fs.mkdirSync(destination);
  fs.mkdirSync(path.join(destination, "source"));
  for (const entry of copy) copyEntry(plan.root, path.join(destination, "source"), entry);
  for (const entry of plan.entries) {
    const data =
      entry.mode === "120000"
        ? Buffer.from(fs.readlinkSync(path.join(plan.root, entry.path)))
        : fs.readFileSync(path.join(plan.root, entry.path));
    const blob = object("blob", data);
    if (blob.oid !== entry.oid) fail("source race during git snapshot");
    plan.objects.set(blob.oid, blob.compressed);
  }
  for (const [oid, data] of plan.objects)
    writeNew(path.join(destination, "git/objects", oid.slice(0, 2), oid.slice(2)), data);
  writeNew(path.join(destination, "git/index"), plan.index);
  writeNew(path.join(destination, "git/HEAD"), "ref: refs/heads/isolated-readonly\n");
  writeNew(path.join(destination, "git/refs/heads/isolated-readonly"), plan.commit + "\n");
  writeNew(path.join(destination, "git/config"), gitConfig);
  writeNew(path.join(destination, "trusted/layout-receipt.json"), receiptText);
  writeNew(path.join(destination, "trusted/no-copy-layout.mjs"), fs.readFileSync(SELF));
  writeNew(
    path.join(destination, "trusted/openclaw-image-dependency-projector.mjs"),
    fs.readFileSync(path.join(TOOLS, "openclaw-image-dependency-projector.mjs")),
  );
  writeNew(path.join(destination, "Dockerfile"), dockerfile);
  for (const module of extras) {
    if (fileDigest(module.file) !== module.sha256) fail("trusted module changed after preflight");
    writeNew(path.join(destination, "trusted", module.name), fs.readFileSync(module.file));
  }
  return {
    receiptSha256,
    receipt,
    phase: "OFFLINE_COPY_ONLY",
    buildArgv: [
      "docker",
      "build",
      "--network",
      "none",
      "--pull=false",
      "--iidfile",
      "FINAL_IMAGE_ID_FILE",
      "-f",
      path.join(destination, "Dockerfile"),
      destination,
    ],
    candidateRUN: false,
    protectedMetadataOverwritten: false,
  };
}
export const WRITABLE = {
  totalLimitBytes: 2147483648,
  hostReceipts: 64 * 1024 * 1024,
  dockerDeviceReservation: 128 * 1024 * 1024,
  mounts: [
    { path: "/tmp", bytes: 1088 * 1024 * 1024, inodes: 65536, exec: true },
    { path: "/app/.artifacts", bytes: 256 * 1024 * 1024, inodes: 32768, exec: false },
    { path: "/app/packages/plugin-sdk/dist", bytes: 256 * 1024 * 1024, inodes: 32768, exec: false },
    { path: "/qualification", bytes: 256 * 1024 * 1024, inodes: 32768, exec: false },
  ],
  rootGit: "immutable image snapshot; GIT_OPTIONAL_LOCKS=0",
  noWritableDependencyOrCacheMount: true,
};
export function runtimeArgv(config, receipt, image) {
  if (
    config.externalExecution !== true ||
    config.hostDiskFloorValidated !== true ||
    !/^[a-f0-9]{64}$/.test(config.executionApprovalSha256 ?? "") ||
    config.executionApprovalSha256 ===
      "b9aea3fa0873e1636cae70f81f7c79b022cb8410dcd41d75bdfe8361f6543189"
  )
    fail("fresh external execution and host-floor authority required");
  if (!fixedImage(config.finalImageId) || image !== config.finalImageId)
    fail("CLI image differs from independently admitted finalImageId");
  if (
    !fixedImage(image) ||
    receipt.canonicalRoot !== "/app" ||
    receipt.candidateTree !== config.expectedTree ||
    receipt.lockSha256 !== config.expectedLockSha256 ||
    receipt.metadataSha256 !== config.expectedMetadataSha256
  )
    fail("runtime source/image provenance mismatch");
  if (
    !positive(config.uid) ||
    !positive(config.gid) ||
    !positive(config.timeoutSeconds) ||
    config.timeoutSeconds > 3600 ||
    !Array.isArray(config.command) ||
    !["/usr/local/bin/node", "/usr/local/bin/pnpm", "/bin/bash"].includes(config.command[0]) ||
    config.command.some((s) => typeof s !== "string" || s.includes("\0"))
  )
    fail("invalid bounded runtime identity/command");
  const args = [
    "run",
    "--rm",
    "--pull",
    "never",
    "--network",
    "none",
    "--read-only",
    "--security-opt",
    "no-new-privileges",
    "--cap-drop",
    "ALL",
    "--pids-limit",
    "512",
    "--shm-size",
    "64m",
    "--user",
    config.uid + ":" + config.gid,
    "--label",
    "openclaw.purpose=no-copy-immutable-layout",
    "--workdir",
    "/app",
  ];
  if (config._ownedName)
    args.push(
      "--name",
      config._ownedName,
      "--label",
      "openclaw.layout.token=" + config._ownedToken,
    );
  for (const mount of WRITABLE.mounts)
    args.push(
      "--tmpfs",
      mount.path +
        ":rw,nosuid,nodev," +
        (mount.exec ? "exec" : "noexec") +
        ",size=" +
        mount.bytes +
        ",nr_inodes=" +
        mount.inodes +
        ",uid=" +
        config.uid +
        ",gid=" +
        config.gid +
        ",mode=0700",
    );
  for (const item of [
    "HOME=/tmp/home",
    "TMPDIR=/tmp",
    "XDG_CACHE_HOME=/tmp/cache",
    "GIT_OPTIONAL_LOCKS=0",
    "GIT_CONFIG_GLOBAL=/dev/null",
    "GIT_CONFIG_NOSYSTEM=1",
    "CI=true",
    "COREPACK_ENABLE_NETWORK=0",
    "COREPACK_DEFAULT_TO_LATEST=0",
    "PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN=false",
    "OPENCLAW_NODE_TEST_PLAN_CONTINUE_ON_FAILURE=1",
  ])
    args.push("--env", item);
  args.push(
    "--entrypoint",
    "/usr/bin/timeout",
    image,
    "--signal=TERM",
    "--kill-after=15",
    String(config.timeoutSeconds),
    "/usr/local/bin/node",
    "/opt/layout/no-copy-layout.mjs",
    "guard",
    config.receiptSha256,
    ...config.command,
  );
  return args;
}
function docker(config, args, raw = false) {
  const binary = canonical(config.dockerBinary);
  if (!fs.statSync(binary).isFile()) fail("Docker binary must be canonical regular file");
  const result = spawnSync(binary, args, {
    encoding: "utf8",
    maxBuffer: config.receiptLimitBytes - 65536,
    env: { PATH: "/usr/bin:/bin", HOME: process.env.HOME ?? "/tmp", DOCKER_BUILDKIT: "1" },
  });
  if (
    Buffer.byteLength(result.stdout ?? "") + Buffer.byteLength(result.stderr ?? "") >
    config.receiptLimitBytes - 65536
  )
    fail("aggregate host receipt byte budget exceeded");
  if (result.error || (!raw && result.status !== 0))
    fail(
      "Docker failed: " +
        json({
          status: result.status,
          error: result.error?.message,
          stderr: (result.stderr ?? "").slice(0, 2048),
        }),
    );
  return raw
    ? {
        stdout: result.stdout ?? "",
        stderr: result.stderr ?? "",
        status: result.status,
        signal: result.signal,
      }
    : result.stdout;
}
export function run(config, receiptFile, image) {
  limits(config);
  const raw = fs.readFileSync(canonical(receiptFile));
  if (sha(raw) !== config.receiptSha256) fail("receipt digest mismatch");
  const receipt = JSON.parse(raw);
  if (
    config.fullValidation === true &&
    (!receipt.offlineQualification ||
      receipt.toolingPins?.["offline_lock.py"] !==
        "31d877c7123b1bf2e6b829eb8621cbe25425d58dc70ed4c87f66d3f041fb1426")
  )
    fail("full validation requires genuine pinned offline R2 stage");
  if (
    config.ownedContainerCleanupApproved !== true ||
    receipt.immutableLimitBytes !== config.immutableLimitBytes ||
    json([...config.sdkRootIds].sort()) !== json(receipt.sdkRootIds) ||
    json([...config.uiBindingNames].sort()) !== json(receipt.uiBindingNames)
  )
    fail("exact reviewed bounds/graph/owned-cleanup authority required");
  const token = randomBytes(16).toString("hex"),
    name = "openclaw-no-copy-" + token,
    owned = { ...config, _ownedName: name, _ownedToken: token },
    argv = runtimeArgv(owned, receipt, image);
  const info = JSON.parse(docker(config, ["image", "inspect", image]));
  if (
    !Array.isArray(info) ||
    info.length !== 1 ||
    info[0].Id !== image ||
    info[0].Config?.Labels?.["org.openclaw.layout.receipt-sha256"] !== config.receiptSha256 ||
    Object.keys(info[0].Config?.Volumes ?? {}).length ||
    !positive(info[0].Size) ||
    info[0].Size > receipt.immutableLimitBytes
  )
    fail("final immutable image provenance/size/anonymous-volume guard");
  let result;
  try {
    result = docker(config, argv, true);
  } finally {
    const probe = docker(config, ["container", "inspect", name], true);
    if (probe.status === 0) {
      const container = JSON.parse(probe.stdout);
      if (
        !Array.isArray(container) ||
        container.length !== 1 ||
        container[0].Config?.Labels?.["openclaw.layout.token"] !== token ||
        container[0].Image !== image
      )
        fail("refuse cleanup without exact owned-container identity");
      if (container[0].State?.Running) docker(config, ["kill", "--signal", "KILL", name]);
    } else if (probe.status !== 1 || !/(?:No such container|No such object)/.test(probe.stderr))
      fail("owned-container cleanup could not be verified");
  }
  return { ...result, argv: [config.dockerBinary, ...argv], actualProductQualified: false };
}
function verifyProtected(base) {
  for (const file of base.files)
    if (
      !fs.lstatSync(file.path).isFile() ||
      fs.realpathSync(file.path) !== file.path ||
      fs.statSync(file.path).size !== file.bytes ||
      (fs.statSync(file.path).mode & 0o777) !== file.mode ||
      fileDigest(file.path) !== file.sha256
    )
      fail("protected immutable file mismatch: " + file.path);
  for (const link of base.links)
    if (
      !fs.lstatSync(link.path).isSymbolicLink() ||
      fs.readlinkSync(link.path) !== link.spelling ||
      fs.realpathSync(link.path) !== link.canonicalTarget
    )
      fail("protected alias mismatch: " + link.path);
}
export function verifySandboxFacts(facts) {
  if (
    !positive(facts.uid) ||
    !positive(facts.gid) ||
    facts.noNewPrivileges !== 1 ||
    !/^0+$/.test(facts.capEff) ||
    !positive(facts.pidsMax) ||
    facts.pidsMax > 512 ||
    json(facts.interfaces) !== json(["lo"])
  )
    fail("runtime uid/capability/network/PID sandbox mismatch");
  const mounts = new Map(facts.mounts.map((m) => [m.point, m]));
  if (!mounts.get("/")?.options.includes("ro")) fail("runtime root filesystem is not read-only");
  const expected = [
    ...WRITABLE.mounts,
    { path: "/dev", bytes: 64 * 1024 * 1024 },
    { path: "/dev/shm", bytes: 64 * 1024 * 1024 },
  ];
  const devices = new Set();
  let total = WRITABLE.hostReceipts;
  for (const item of expected) {
    const mount = mounts.get(item.path);
    if (!mount || mount.type !== "tmpfs" || !mount.options.includes("rw"))
      fail("missing explicit bounded tmpfs: " + item.path);
    const size = /(?:^|,)size=([0-9]+)([kmg]?)(?:,|$)/.exec(mount.superOptions);
    if (!size) fail("unmeasured tmpfs size");
    const bytes = Number(size[1]) * { "": 1, k: 1024, m: 1048576, g: 1073741824 }[size[2]];
    if (!positive(bytes) || bytes > item.bytes)
      fail("actual tmpfs exceeds approved writable bound");
    total += bytes;
    devices.add(mount.device);
  }
  for (const mount of facts.mounts) {
    if (mount.type === "tmpfs" && mount.options.includes("rw") && !devices.has(mount.device))
      fail("unaccounted writable tmpfs");
    if (
      ["/app", "/opt/offline-store", "/opt/offline-cache", "/opt/corepack"].some(
        (p) => mount.point === p || mount.point.startsWith(p + "/"),
      ) &&
      !["/app/.artifacts", "/app/packages/plugin-sdk/dist"].includes(mount.point) &&
      !mount.options.includes("ro")
    )
      fail("unapproved writable candidate/dependency mount");
  }
  for (const mount of facts.mounts) {
    if (!mount.options.includes("rw")) continue;
    if (expected.some((m) => m.path === mount.point) && mount.type === "tmpfs") continue;
    // Kernel APIs provide no disk-backed writable storage. Exact path/type pairs only.
    if (
      (mount.type === "proc" && (mount.point === "/proc" || mount.point.startsWith("/proc/"))) ||
      (mount.type === "devpts" && mount.point === "/dev/pts") ||
      (mount.type === "mqueue" && mount.point === "/dev/mqueue")
    )
      continue;
    // Engine metadata binds are admitted only after actual uid access verification.
    if (
      ["/etc/hosts", "/etc/hostname", "/etc/resolv.conf"].includes(mount.point) &&
      facts.engineMetadataNonWritable === true
    )
      continue;
    fail("unapproved writable mount: " + mount.point + " type=" + mount.type);
  }
  if (total > WRITABLE.totalLimitBytes) fail("aggregate writable budget exceeds2GiB");
  return {
    sandboxVerified: true,
    actualWritableUpperBoundBytes: total,
    hardLimitBytes: WRITABLE.totalLimitBytes,
  };
}
function actualSandboxFacts() {
  const mounts = fs
    .readFileSync("/proc/self/mountinfo", "utf8")
    .trim()
    .split("\n")
    .map((line) => {
      const parts = line.split(" "),
        at = parts.indexOf("-");
      return {
        point: parts[4],
        device: parts[2],
        options: parts[5].split(","),
        type: parts[at + 1],
        superOptions: parts[at + 3],
      };
    });
  const status = fs.readFileSync("/proc/self/status", "utf8"),
    capEff = /^CapEff:\s*([a-f0-9]+)$/m.exec(status)?.[1],
    noNewPrivileges = Number(/^NoNewPrivs:\s*([0-9]+)$/m.exec(status)?.[1]);
  const pidsFile = ["/sys/fs/cgroup/pids.max", "/sys/fs/cgroup/pids/pids.max"].find((p) =>
    fs.existsSync(p),
  );
  if (!pidsFile) fail("PID quota cannot be independently verified");
  for (const file of ["/etc/hosts", "/etc/hostname", "/etc/resolv.conf"]) {
    let writable = false;
    try {
      fs.accessSync(file, fs.constants.W_OK);
      writable = true;
    } catch {}
    if (writable) fail("unbounded writable engine metadata bind");
  }
  return {
    engineMetadataNonWritable: true,
    mounts,
    capEff,
    noNewPrivileges,
    pidsMax: Number(fs.readFileSync(pidsFile, "utf8").trim()),
    interfaces: fs.readdirSync("/sys/class/net").sort(),
    uid: process.getuid(),
    gid: process.getgid(),
  };
}
export function executeStages(
  receipt,
  base,
  command,
  verify = () => verifyProtected(base),
  runner = spawnSync,
) {
  if (receipt.offlineQualification) {
    const q = receipt.offlineQualification;
    if (
      canonical(q.pythonCanonical) !== q.pythonCanonical ||
      fileDigest(q.pythonCanonical) !== q.pythonSha256
    )
      fail("offline Python interpreter provenance mismatch");
    let qualification;
    try {
      qualification = runner(
        q.pythonCanonical,
        ["-I", "-B", "/opt/layout/offline_lock.py", "/opt/layout/offline-spec.json"],
        { cwd: "/app", stdio: "inherit" },
      );
    } finally {
      verify();
    }
    if (qualification.error || qualification.status !== 0)
      fail("offline frozen-lock qualification failed; product command not started");
  }
  let result;
  try {
    result = runner(command[0], command.slice(1), { cwd: "/app", stdio: "inherit" });
  } finally {
    verify();
  }
  if (result.error) throw result.error;
  return result;
}
export function guard(expected, command) {
  if (process.cwd() !== "/app" || !/^[a-f0-9]{64}$/.test(expected))
    fail("fixed runtime compiler root/receipt required");
  const sandbox = verifySandboxFacts(actualSandboxFacts());
  const raw = fs.readFileSync("/opt/layout/layout-receipt.json");
  if (sha(raw) !== expected) fail("embedded layout receipt mismatch");
  const receipt = JSON.parse(raw);
  if (receipt.canonicalRoot !== "/app" || receipt.dependencyOrCacheCopies !== 0)
    fail("invalid no-copy receipt");
  for (const [name, digest] of Object.entries(receipt.toolingPins))
    if (fileDigest(path.join("/opt/layout", name)) !== digest) fail("trusted tooling pin mismatch");
  const snapshotRaw = fs.readFileSync("/opt/layout/image-manifest.json");
  if (sha(snapshotRaw) !== receipt.baseSnapshotSha256) fail("protected snapshot digest mismatch");
  const base = JSON.parse(snapshotRaw);
  verifyProtected(base);
  for (const entry of receipt.sourceFiles) {
    const file = path.join("/app", entry.path),
      data = entry.mode === "120000" ? Buffer.from(fs.readlinkSync(file)) : fs.readFileSync(file);
    if (sha(data) !== entry.sha256) fail("candidate file mismatch before execution");
    if (entry.mode === "120000") {
      const rel = path.relative("/app", fs.realpathSync(file));
      if (rel === ".." || rel.startsWith(".." + path.sep) || path.isAbsolute(rel))
        fail("source alias outside compiler root");
    } else if (
      fs.realpathSync(file) !== file ||
      (fs.statSync(file).mode & 0o111 ? "100755" : "100644") !== entry.mode
    )
      fail("candidate canonical mode/path mismatch");
  }

  const expectedFiles = new Set([
    ...base.files.map((e) => e.path),
    ...base.links.map((e) => e.path),
    ...receipt.sourceFiles.map((e) => "/app/" + e.path),
    ...Object.keys(receipt.gitManifest).map((p) => "/app/.git/" + p),
  ]);
  function checkExact(directory) {
    for (const item of fs.readdirSync(directory, { withFileTypes: true })) {
      const file = path.join(directory, item.name);
      if (["/app/.artifacts", "/app/packages/plugin-sdk/dist"].includes(file)) continue;
      if (item.isDirectory()) checkExact(file);
      else if (!expectedFiles.has(file)) fail("unexpected immutable checkout entry: " + file);
    }
  }
  for (const root of base.roots) checkExact(root);
  for (const [name, digest] of Object.entries(receipt.gitManifest))
    if (
      !fs.lstatSync(path.join("/app/.git", name)).isFile() ||
      fs.realpathSync(path.join("/app/.git", name)) !== path.join("/app/.git", name) ||
      fileDigest(path.join("/app/.git", name)) !== digest
    )
      fail("immutable Git snapshot mismatch");
  fs.mkdirSync("/tmp/home", { recursive: true });
  fs.mkdirSync("/tmp/cache", { recursive: true });
  fs.mkdirSync("/app/.artifacts/layout", { recursive: true });
  const out = fs.openSync("/app/.artifacts/layout/graph.ndjson", "wx");
  let graph;
  try {
    graph = spawnSync(
      process.execPath,
      [
        "/opt/layout/openclaw-image-dependency-projector.mjs",
        "/app",
        "/app/node_modules",
        "--in-place-inventory-only",
      ],
      { stdio: ["ignore", out, "inherit"] },
    );
  } finally {
    fs.closeSync(out);
  }
  if (graph.error || graph.status !== 0)
    fail("strict complete in-place SDK/UI/workspace graph validation failed");
  const records = fs
      .readFileSync("/app/.artifacts/layout/graph.ndjson", "utf8")
      .trim()
      .split("\n")
      .map(JSON.parse),
    plan = records.find((x) => x.inventoryComplete);
  if (
    !plan?.inPlaceImmutable ||
    plan.hydrationPerformed !== false ||
    !plan.planComplete ||
    plan.compilerRoot !== "/app"
  )
    fail("missing exact no-copy in-place graph receipt");
  if (
    json(Object.keys(plan.declarationGraph.registryRoots).sort()) !== json(receipt.sdkRootIds) ||
    json(Object.keys(plan.uiBindings).sort()) !== json(receipt.uiBindingNames)
  )
    fail("complete SDK62/UI52 identity set differs from approved graph");
  process.stdout.write(
    json({
      sandbox,
      layoutGraph: plan,
      protectedGraphValidated: true,
      legacyCopyCapQualified: false,
    }),
  );
  if (!["/usr/local/bin/node", "/usr/local/bin/pnpm", "/bin/bash"].includes(command[0]))
    fail("invalid product command");
  const result = executeStages(receipt, base, command, () => {
    verifyProtected(base);
    for (const root of base.roots) checkExact(root);
    for (const entry of receipt.sourceFiles) {
      const file = path.join("/app", entry.path),
        data = entry.mode === "120000" ? Buffer.from(fs.readlinkSync(file)) : fs.readFileSync(file);
      if (sha(data) !== entry.sha256) fail("candidate content changed after command");
    }
    for (const [name, digest] of Object.entries(receipt.gitManifest))
      if (fileDigest(path.join("/app/.git", name)) !== digest)
        fail("Git baseline changed after command");
  });
  process.exitCode = result.status ?? 1;
  return { productExit: process.exitCode, graphValidated: true };
}
if (process.argv[1] && path.resolve(process.argv[1]) === SELF) {
  try {
    const [mode, ...args] = process.argv.slice(2);
    let result;
    if (mode === "sandbox-check") result = verifySandboxFacts(readJson(args[0]));
    else if (mode === "snapshot") result = snapshot(args[0]);
    else if (mode === "inert") result = prepareInert(readJson(args[0]), args[1]);
    else if (mode === "compose") result = prepareFinal(readJson(args[0]), args[1]);
    else if (mode === "run") result = run(readJson(args[0]), args[1], args[2]);
    else if (mode === "guard") result = guard(args[0], args.slice(1));
    else fail("mode must be inert|compose|snapshot|run|guard");
    if (mode === "run") {
      process.stdout.write(result.stdout);
      process.stderr.write(result.stderr);
      process.stderr.write(
        json({
          dockerExit: result.status,
          argvSha256: sha(json(result.argv)),
          actualProductQualified: false,
        }),
      );
      process.exitCode = result.status ?? 1;
    } else process.stdout.write(json(result));
  } catch (error) {
    process.stderr.write(
      json({ status: "LAYOUT_FAILED_CLOSED", error: String(error.message).slice(0, 2048) }),
    );
    process.exitCode = 1;
  }
}
