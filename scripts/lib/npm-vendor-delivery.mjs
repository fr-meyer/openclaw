// Delivery adapter only. The proof owner authenticates every installed/archive
// member; package lifecycles and Docker consume those facts without exemptions.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  readdirSync,
  renameSync,
  rmSync,
  rmdirSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import {
  createVerifiedNpmVendorTarball,
  verifyNpmVendorTarball,
} from "./npm-glob-vendor-archive.mjs";
import { readNpmVendorProof, verifyInstalledNpmVendorDirectory } from "./npm-glob-vendor-proof.mjs";
import { stageNpmVendorPayload } from "./npm-vendor-payload.mjs";

const PROOF = "patches/npm-12.2.1.glob-cancellation.proof.json";
const PATCH = "patches/npm@12.2.1.patch";
const STATE = ".artifacts/npm-vendor-delivery";
const ARTIFACT_DIR = ".openclaw-npm-vendor-artifact";
const SHA = (bytes) => createHash("sha256").update(bytes).digest("hex");

export function isNpmVendorBackportConfigured(manifest) {
  const config = manifest?.openclaw?.npmVendorBackport;
  if (config === undefined) return false;
  if (
    !config ||
    typeof config !== "object" ||
    Array.isArray(config) ||
    Object.keys(config).sort().join(",") !== "patch,proof" ||
    config.proof !== PROOF ||
    config.patch !== PATCH ||
    manifest.name !== "openclaw" ||
    manifest.dependencies?.npm !== "12.2.1"
  ) {
    throw new Error("npm vendor source configuration is invalid");
  }
  return true;
}

function context(repoRoot) {
  const root = realpathSync(repoRoot);
  const manifest = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8"));
  if (!isNpmVendorBackportConfigured(manifest)) {
    throw new Error("npm vendor source configuration is required");
  }
  for (const filename of [PROOF, PATCH]) {
    const stat = lstatSync(path.join(root, filename));
    if (!stat.isFile() || stat.isSymbolicLink())
      throw new Error("npm vendor proof input is not regular");
  }
  const proofBytes = readFileSync(path.join(root, PROOF));
  const patchBytes = readFileSync(path.join(root, PATCH));
  const proof = readNpmVendorProof(proofBytes);
  if (proof.patch?.sha256 !== SHA(patchBytes) || proof.patch?.size !== patchBytes.length) {
    throw new Error("npm vendor source patch differs from its proof");
  }
  return { root, proof, patchBytes, proofSha256: SHA(proofBytes) };
}

function inside(root, filename) {
  const relative = path.relative(root, filename);
  if (
    !relative ||
    relative === ".." ||
    relative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relative)
  ) {
    throw new Error("npm vendor package must be inside its source root");
  }
}

function selectedNpmRoot(ctx) {
  const packageRoot = realpathSync(path.join(ctx.root, "node_modules/npm"));
  inside(ctx.root, packageRoot);
  return packageRoot;
}

export function verifyInstalledNpmVendor(repoRoot) {
  const ctx = context(repoRoot);
  const packageRoot = selectedNpmRoot(ctx);
  const verified = verifyInstalledNpmVendorDirectory({
    packageRoot,
    proof: ctx.proof,
    patchBytes: ctx.patchBytes,
  });
  return {
    ...verified,
    proofSha256: ctx.proofSha256,
    originalIntegrity: ctx.proof.original.integrity,
  };
}

function stagePayload(ctx, packageRoot, outputRoot) {
  const result = stageNpmVendorPayload({
    packageRoot,
    proof: ctx.proof,
    patchBytes: ctx.patchBytes,
    outputRoot,
  });
  if (
    result.sourceRoot !== packageRoot ||
    result.payloadRoot !== outputRoot ||
    result.npmVersion !== "12.2.1" ||
    result.proofSha256 !== ctx.proofSha256 ||
    result.inventorySha256 !== ctx.proof.derived.inventorySha256 ||
    result.payloadVerified !== true ||
    result.ambientSourceVerified !== false
  ) {
    throw new Error("npm vendor payload stage returned mismatched facts");
  }
  return result;
}

function identity(filename) {
  const stat = lstatSync(filename, { bigint: true });
  if (!stat.isDirectory() || stat.isSymbolicLink())
    throw new Error("npm vendor owned directory changed");
  return { dev: stat.dev.toString(), ino: stat.ino.toString() };
}

function sameIdentity(filename, expected) {
  const current = identity(filename);
  if (current.dev !== expected.dev || current.ino !== expected.ino) {
    throw new Error("npm vendor owned directory identity changed");
  }
}

export function prepareNpmVendorArtifact(repoRoot, packageDir) {
  const ctx = context(repoRoot);
  if (realpathSync(packageDir) !== ctx.root)
    throw new Error("npm vendor artifact is root-package only");
  const directory = path.join(ctx.root, ARTIFACT_DIR);
  // A deterministic spec keeps lock evidence stable. Never adopt an old owner.
  mkdirSync(directory, { mode: 0o700 });
  const dirIdentity = identity(directory);
  const filename = path.join(directory, "npm-12.2.1-glob-backport.tgz");
  let expected;
  try {
    const payload = stagePayload(ctx, selectedNpmRoot(ctx), path.join(directory, "payload"));
    const payloadIdentity = identity(payload.payloadRoot);
    const bytes = createVerifiedNpmVendorTarball({
      packageRoot: payload.payloadRoot,
      proof: ctx.proof,
    });
    verifyNpmVendorTarball({ tarball: bytes, proof: ctx.proof });
    expected = SHA(bytes);
    sameIdentity(directory, dirIdentity);
    sameIdentity(payload.payloadRoot, payloadIdentity);
    rmSync(payload.payloadRoot, { recursive: true });
    writeFileSync(filename, bytes, { flag: "wx", mode: 0o600 });
    const integrity = `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
    let cleaned = false;
    return {
      artifact: {
        name: "npm",
        version: "12.2.1",
        spec: `file:./${ARTIFACT_DIR}/${path.basename(filename)}`,
        integrity,
      },
      tarball: bytes,
      proofSha256: ctx.proofSha256,
      originalIntegrity: ctx.proof.original.integrity,
      verifyOriginalTarball(originalBytes) {
        if (
          !Buffer.isBuffer(originalBytes) ||
          originalBytes.length > 8 * 1024 * 1024 ||
          SHA(originalBytes) !== ctx.proof.original.sha256 ||
          `sha512-${createHash("sha512").update(originalBytes).digest("base64")}` !==
            ctx.proof.original.integrity
        ) {
          throw new Error("original npm archive differs from authenticated source proof");
        }
        return { originalIntegrity: ctx.proof.original.integrity, proofSha256: ctx.proofSha256 };
      },
      verifyTarball(bytesToVerify) {
        return verifyNpmVendorTarball({ tarball: bytesToVerify, proof: ctx.proof });
      },
      cleanup() {
        if (cleaned) return;
        sameIdentity(directory, dirIdentity);
        if (
          readdirSync(directory).join(",") !== path.basename(filename) ||
          !lstatSync(filename).isFile() ||
          lstatSync(filename).isSymbolicLink() ||
          SHA(readFileSync(filename)) !== expected
        ) {
          throw new Error("npm vendor artifact changed; cleanup refused");
        }
        rmSync(filename);
        rmdirSync(directory);
        cleaned = true;
      },
    };
  } catch (error) {
    sameIdentity(directory, dirIdentity);
    // Partial output is private evidence, never an instruction to delete it.
    if (readdirSync(directory).length === 0) rmdirSync(directory);
    throw error;
  }
}

function statePaths(root) {
  const artifacts = path.join(root, ".artifacts");
  const directory = path.join(root, STATE);
  const receipt = path.join(directory, "receipt.json");
  for (const [filename, directoryExpected] of [
    [artifacts, true],
    [directory, true],
    [receipt, false],
  ]) {
    let stat;
    try {
      stat = lstatSync(filename);
    } catch (error) {
      if (error.code === "ENOENT") continue;
      throw error;
    }
    if (stat.isSymbolicLink() || (directoryExpected ? !stat.isDirectory() : !stat.isFile())) {
      throw new Error("npm vendor staging path must be a regular source-owned entry");
    }
  }
  return {
    artifacts,
    directory,
    receipt,
    backup: path.join(directory, "npm.original-entry"),
    payload: path.join(directory, "npm.payload"),
    npm: path.join(root, "node_modules/npm"),
  };
}

function present(filename) {
  try {
    lstatSync(filename);
    return true;
  } catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
}

function originalEntry(filename, sourceRoot) {
  const entry = lstatSync(filename, { bigint: true });
  if (!entry.isSymbolicLink() && !entry.isDirectory())
    throw new Error("npm vendor source entry is unexpected");
  const source = identity(sourceRoot);
  return {
    kind: entry.isSymbolicLink() ? "symlink" : "directory",
    dev: entry.dev.toString(),
    ino: entry.ino.toString(),
    link: entry.isSymbolicLink() ? readlinkSync(filename) : null,
    sourceRoot,
    sourceDev: source.dev,
    sourceIno: source.ino,
  };
}

function checkOriginal(filename, original) {
  const entry = lstatSync(filename, { bigint: true });
  if (
    entry.dev.toString() !== original.dev ||
    entry.ino.toString() !== original.ino ||
    (original.kind === "symlink"
      ? !entry.isSymbolicLink() || readlinkSync(filename) !== original.link
      : !entry.isDirectory() || entry.isSymbolicLink())
  ) {
    throw new Error("npm vendor original entry changed; restore refused");
  }
}

function readReceipt(ctx, paths) {
  const receipt = JSON.parse(readFileSync(paths.receipt, "utf8"));
  const original = receipt.original;
  const ids = [
    receipt.staged,
    original && { dev: original.dev, ino: original.ino },
    original && { dev: original.sourceDev, ino: original.sourceIno },
  ];
  if (
    Object.keys(receipt).sort().join(",") !==
      "inventorySha256,original,ownerPid,proofSha256,schema,staged" ||
    receipt.schema !== "openclaw.npm-vendor-pack-staging.v2" ||
    !Number.isSafeInteger(receipt.ownerPid) ||
    receipt.ownerPid <= 0 ||
    receipt.proofSha256 !== ctx.proofSha256 ||
    receipt.inventorySha256 !== ctx.proof.derived.inventorySha256 ||
    !original ||
    Object.keys(original).sort().join(",") !== "dev,ino,kind,link,sourceDev,sourceIno,sourceRoot" ||
    !["symlink", "directory"].includes(original.kind) ||
    typeof original.sourceRoot !== "string" ||
    (original.kind === "symlink" ? typeof original.link !== "string" : original.link !== null) ||
    ids.some(
      (value) =>
        !value ||
        Object.keys(value).sort().join(",") !== "dev,ino" ||
        typeof value.dev !== "string" ||
        !/^(0|[1-9][0-9]*)$/.test(value.dev) ||
        typeof value.ino !== "string" ||
        !/^(0|[1-9][0-9]*)$/.test(value.ino),
    )
  ) {
    throw new Error("npm vendor staging recovery binding differs");
  }
  const allowed = new Set(["receipt.json", "npm.original-entry", "npm.payload"]);
  if (readdirSync(paths.directory).some((name) => !allowed.has(name))) {
    throw new Error("npm vendor staging directory has unowned entries");
  }
  return receipt;
}

function verifyStaged(ctx, filename, staged) {
  sameIdentity(filename, staged);
  return verifyInstalledNpmVendorDirectory({
    packageRoot: filename,
    proof: ctx.proof,
    patchBytes: ctx.patchBytes,
  });
}

export function prepareNpmVendorForPack(repoRoot) {
  const root = realpathSync(repoRoot);
  const manifest = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8"));
  if (!isNpmVendorBackportConfigured(manifest)) return false;
  const ctx = context(root);
  const paths = statePaths(root);
  if (existsSync(paths.receipt)) {
    const receipt = readReceipt(ctx, paths);
    if (receipt.ownerPid !== process.pid || !present(paths.backup) || present(paths.payload)) {
      throw new Error("npm vendor pack staging belongs to another or incomplete owner");
    }
    checkOriginal(paths.backup, receipt.original);
    verifyStaged(ctx, paths.npm, receipt.staged);
    return false;
  }
  const sourceRoot = selectedNpmRoot(ctx);
  const original = originalEntry(paths.npm, sourceRoot);
  if (!existsSync(paths.artifacts)) mkdirSync(paths.artifacts, { mode: 0o700 });
  // Never adopt even an empty ignored directory left by another invocation.
  mkdirSync(paths.directory, { mode: 0o700 });
  try {
    const payload = stagePayload(ctx, sourceRoot, paths.payload);
    const receipt = {
      schema: "openclaw.npm-vendor-pack-staging.v2",
      ownerPid: process.pid,
      proofSha256: ctx.proofSha256,
      inventorySha256: payload.inventorySha256,
      original,
      staged: identity(paths.payload),
    };
    writeFileSync(paths.receipt, `${JSON.stringify(receipt)}\n`, { flag: "wx", mode: 0o600 });
    renameSync(paths.npm, paths.backup);
    renameSync(paths.payload, paths.npm);
    verifyStaged(ctx, paths.npm, receipt.staged);
  } catch (error) {
    throw new Error("npm vendor pack staging failed; owned evidence retained", { cause: error });
  }
  return true;
}

function verifyOriginalPayload(ctx, paths, filename, original) {
  checkOriginal(filename, original);
  // A relative pnpm link is interpreted at its ORIGINAL location, not backup.
  const sourceRoot =
    original.kind === "symlink"
      ? realpathSync(path.resolve(path.dirname(paths.npm), original.link))
      : realpathSync(filename);
  inside(ctx.root, sourceRoot);
  if (original.kind === "symlink" && sourceRoot !== original.sourceRoot)
    throw new Error("npm vendor original target changed");
  sameIdentity(sourceRoot, { dev: original.sourceDev, ino: original.sourceIno });
  const temporary = mkdtempSync(path.join(paths.directory, "restore-payload-"));
  const temporaryIdentity = identity(temporary);
  stagePayload(ctx, sourceRoot, path.join(temporary, "npm"));
  sameIdentity(temporary, temporaryIdentity);
  rmSync(temporary, { recursive: true });
}

export function restoreNpmVendorForPack(repoRoot) {
  const root = realpathSync(repoRoot);
  const paths = statePaths(root);
  if (!existsSync(paths.receipt)) return false;
  const ctx = context(root);
  const receipt = readReceipt(ctx, paths);
  const hasBackup = present(paths.backup),
    hasNpm = present(paths.npm),
    hasPayload = present(paths.payload);
  if (hasBackup) {
    if (hasNpm && hasPayload)
      throw new Error("npm vendor staged entry is ambiguous; restore refused");
    const staged = hasNpm ? paths.npm : hasPayload ? paths.payload : null;
    if (staged) verifyStaged(ctx, staged, receipt.staged);
    verifyOriginalPayload(ctx, paths, paths.backup, receipt.original);
    if (staged) rmSync(staged, { recursive: true });
    renameSync(paths.backup, paths.npm);
  } else {
    if (!hasNpm) throw new Error("npm vendor original backup is unavailable");
    checkOriginal(paths.npm, receipt.original);
    if (hasPayload) verifyStaged(ctx, paths.payload, receipt.staged);
    verifyOriginalPayload(ctx, paths, paths.npm, receipt.original);
    if (hasPayload) rmSync(paths.payload, { recursive: true });
  }
  checkOriginal(paths.npm, receipt.original);
  if (readdirSync(paths.directory).join(",") !== "receipt.json")
    throw new Error("npm vendor recovery has uncertain entries");
  rmSync(paths.receipt);
  rmdirSync(paths.directory);
  return true;
}

/** Canonicalize the physical Docker package-local tree before node_modules is copied.
 * The original extra-bearing directory is only renamed to private build evidence
 * outside node_modules; its unknown entries are never copied or authenticated.
 */
export function prepareNpmVendorForRuntime(repoRoot) {
  const ctx = context(repoRoot);
  const modules = path.join(ctx.root, "node_modules");
  if (
    realpathSync(modules) !== modules ||
    !lstatSync(modules).isDirectory() ||
    lstatSync(modules).isSymbolicLink()
  ) {
    throw new Error("npm vendor runtime modules must be a physical project directory");
  }
  const sourceRoot = selectedNpmRoot(ctx);
  inside(modules, sourceRoot);
  const original = originalEntry(path.join(modules, "npm"), sourceRoot);
  const originalIdentity = identity(sourceRoot);
  const artifacts = path.join(ctx.root, ".artifacts");
  if (!present(artifacts)) mkdirSync(artifacts, { mode: 0o700 });
  if (
    !lstatSync(artifacts).isDirectory() ||
    lstatSync(artifacts).isSymbolicLink() ||
    realpathSync(artifacts) !== artifacts
  ) {
    throw new Error("npm vendor runtime rollback parent must be a physical project directory");
  }
  const directory = mkdtempSync(path.join(artifacts, "npm-vendor-runtime-"));
  const directoryIdentity = identity(directory);
  const staged = path.join(directory, "npm.payload"),
    backup = path.join(directory, "npm.original");
  const receiptPath = path.join(directory, "receipt.json");
  const payload = stagePayload(ctx, sourceRoot, staged);
  const stagedIdentity = identity(staged);
  const receiptBytes = Buffer.from(
    `${JSON.stringify({
      schema: "openclaw.npm-vendor-runtime-staging.v1",
      proofSha256: ctx.proofSha256,
      inventorySha256: payload.inventorySha256,
      sourceRoot,
      original,
      originalIdentity,
      stagedIdentity,
    })}\n`,
  );
  writeFileSync(receiptPath, receiptBytes, { flag: "wx", mode: 0o600 });
  sameIdentity(sourceRoot, originalIdentity);
  renameSync(sourceRoot, backup);
  renameSync(staged, sourceRoot);
  sameIdentity(sourceRoot, stagedIdentity);
  const verified = verifyInstalledNpmVendor(repoRoot);
  let restored = false;
  return {
    ...verified,
    sourceRoot,
    originalSourceVerified: false,
    payloadVerified: true,
    rollbackDirectory: directory,
    restore() {
      if (restored) return false;
      sameIdentity(directory, directoryIdentity);
      if (
        readdirSync(directory).sort().join(",") !== "npm.original,receipt.json" ||
        !lstatSync(receiptPath).isFile() ||
        lstatSync(receiptPath).isSymbolicLink() ||
        !readFileSync(receiptPath).equals(receiptBytes) ||
        selectedNpmRoot(ctx) !== sourceRoot
      ) {
        throw new Error("npm vendor runtime rollback state changed; restore refused");
      }
      if (original.kind === "symlink") checkOriginal(path.join(modules, "npm"), original);
      sameIdentity(sourceRoot, stagedIdentity);
      verifyInstalledNpmVendorDirectory({
        packageRoot: sourceRoot,
        proof: ctx.proof,
        patchBytes: ctx.patchBytes,
      });
      sameIdentity(backup, originalIdentity);
      // Only the original's proof members are read again. Unknown entries remain
      // opaque and will return with the exact original inode on successful restore.
      const temporary = mkdtempSync(path.join(directory, "restore-payload-"));
      const temporaryIdentity = identity(temporary);
      stagePayload(ctx, backup, path.join(temporary, "npm"));
      sameIdentity(temporary, temporaryIdentity);
      rmSync(temporary, { recursive: true });
      sameIdentity(sourceRoot, stagedIdentity);
      sameIdentity(backup, originalIdentity);
      rmSync(sourceRoot, { recursive: true });
      renameSync(backup, sourceRoot);
      sameIdentity(sourceRoot, originalIdentity);
      checkOriginal(path.join(modules, "npm"), original);
      rmSync(receiptPath);
      rmdirSync(directory);
      restored = true;
      return true;
    },
  };
}

export function installGlobalNpmVendor(repoRoot, prefix) {
  if (
    realpathSync(prefix) !== path.resolve(prefix) ||
    realpathSync(path.join(prefix, "lib/node_modules")) !== path.join(prefix, "lib/node_modules")
  ) {
    throw new Error("npm vendor global prefix must be a regular canonical directory");
  }
  prefix = realpathSync(prefix);
  const ctx = context(repoRoot);
  // Docker's package-local tree is already canonicalized before its COPY. The
  // global owner independently requires its complete inventory before delivery.
  const local = verifyInstalledNpmVendor(repoRoot);
  const sourceRoot = local.packageRoot;
  const npmDir = path.join(prefix, "lib/node_modules/npm");
  if (!lstatSync(npmDir).isDirectory() || lstatSync(npmDir).isSymbolicLink())
    throw new Error("global npm directory is unexpected");
  for (const [name, target] of [
    ["npm", "npm-cli.js"],
    ["npx", "npx-cli.js"],
  ]) {
    const link = path.join(prefix, "bin", name);
    if (
      !lstatSync(link).isSymbolicLink() ||
      readlinkSync(link) !== `../lib/node_modules/npm/bin/${target}`
    ) {
      throw new Error("global npm entrypoint differs from pinned Node image layout");
    }
  }
  const temporary = mkdtempSync(path.join(prefix, "lib/node_modules/.npm-vendor-"));
  const staged = path.join(temporary, "npm"),
    backup = path.join(temporary, "npm.previous");
  const payload = stagePayload(ctx, sourceRoot, staged);
  const stagedIdentity = identity(staged),
    previousIdentity = identity(npmDir);
  renameSync(npmDir, backup);
  renameSync(staged, npmDir);
  sameIdentity(npmDir, stagedIdentity);
  const verified = verifyInstalledNpmVendorDirectory({
    packageRoot: npmDir,
    proof: ctx.proof,
    patchBytes: ctx.patchBytes,
  });
  sameIdentity(backup, previousIdentity);
  rmSync(backup, { recursive: true });
  rmdirSync(temporary);
  return {
    ...verified,
    sourceRoot: payload.sourceRoot,
    sourceInventoryVerified: true,
    sourceInventorySha256: local.inventorySha256,
    proofSha256: ctx.proofSha256,
    originalIntegrity: ctx.proof.original.integrity,
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  if (process.getuid?.() !== 0)
    throw new Error("Docker npm delivery requires root in the runtime build stage");
  if (process.argv[2] === "prepare-runtime") {
    assert.deepEqual(process.argv.slice(2), ["prepare-runtime", "--repo-root", "/app"]);
    prepareNpmVendorForRuntime("/app");
  } else {
    assert.deepEqual(process.argv.slice(2), [
      "install-global",
      "--repo-root",
      "/app",
      "--prefix",
      "/usr/local",
    ]);
    installGlobalNpmVendor("/app", "/usr/local");
  }
}
