// Delivery adapter only. The proof owner authenticates every installed/archive
// member; package lifecycles and Docker consume those facts without exemptions.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readlinkSync,
  realpathSync, readdirSync, renameSync, rmSync, rmdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import {
  readNpmVendorProof, verifyInstalledNpmVendorDirectory,
} from "./npm-glob-vendor-proof.mjs";
import { createVerifiedNpmVendorTarball, verifyNpmVendorTarball } from "./npm-glob-vendor-archive.mjs";

const PROOF = "patches/npm-12.2.1.glob-cancellation.proof.json";
const PATCH = "patches/npm@12.2.1.patch";
const STATE = ".artifacts/npm-vendor-delivery";
const ARTIFACT_DIR = ".openclaw-npm-vendor-artifact";
const SHA = (bytes) => createHash("sha256").update(bytes).digest("hex");

export function isNpmVendorBackportConfigured(manifest) {
  const config = manifest?.openclaw?.npmVendorBackport;
  if (config === undefined) return false;
  if (!config || typeof config !== "object" || Array.isArray(config) ||
      Object.keys(config).sort().join(",") !== "patch,proof" ||
      config.proof !== PROOF || config.patch !== PATCH ||
      manifest.name !== "openclaw" || manifest.dependencies?.npm !== "12.2.1") {
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
    if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("npm vendor proof input is not regular");
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
  if (!relative || relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error("npm vendor package must be inside its source root");
  }
}

export function verifyInstalledNpmVendor(repoRoot) {
  const ctx = context(repoRoot);
  const packageRoot = realpathSync(path.join(ctx.root, "node_modules/npm"));
  inside(ctx.root, packageRoot);
  const verified = verifyInstalledNpmVendorDirectory({ packageRoot, proof: ctx.proof, patchBytes: ctx.patchBytes });
  return { ...verified, proofSha256: ctx.proofSha256, originalIntegrity: ctx.proof.original.integrity };
}

export function prepareNpmVendorArtifact(repoRoot, packageDir) {
  const ctx = context(repoRoot);
  if (realpathSync(packageDir) !== ctx.root) throw new Error("npm vendor artifact is root-package only");
  const verified = verifyInstalledNpmVendor(ctx.root);
  const directory = path.join(ctx.root, ARTIFACT_DIR);
  // A deterministic file spec keeps lock evidence stable; an existing owner or
  // interrupted artifact is a refusal, never an automatic cleanup instruction.
  mkdirSync(directory, { mode: 0o700 });
  const filename = path.join(directory, "npm-12.2.1-glob-backport.tgz");
  let expected;
  try {
    const bytes = createVerifiedNpmVendorTarball({ packageRoot: verified.packageRoot, proof: ctx.proof });
    verifyNpmVendorTarball({ tarball: bytes, proof: ctx.proof });
    expected = SHA(bytes);
    writeFileSync(filename, bytes, { flag: "wx", mode: 0o600 });
    const integrity = `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
    const dirIdentity = lstatSync(directory);
    let cleaned = false;
    return {
      artifact: { name: "npm", version: "12.2.1", spec: `file:./${ARTIFACT_DIR}/${path.basename(filename)}`, integrity },
      tarball: bytes,
      proofSha256: ctx.proofSha256,
      originalIntegrity: ctx.proof.original.integrity,
      verifyOriginalTarball(originalBytes) {
        if (!Buffer.isBuffer(originalBytes) || originalBytes.length > 8 * 1024 * 1024 ||
            SHA(originalBytes) !== ctx.proof.original.sha256 ||
            `sha512-${createHash("sha512").update(originalBytes).digest("base64")}` !== ctx.proof.original.integrity) {
          throw new Error("original npm archive differs from authenticated source proof");
        }
        return { originalIntegrity: ctx.proof.original.integrity, proofSha256: ctx.proofSha256 };
      },
      verifyTarball(bytesToVerify) {
        return verifyNpmVendorTarball({ tarball: bytesToVerify, proof: ctx.proof });
      },
      cleanup() {
        if (cleaned) return;
        const current = lstatSync(directory);
        if (!current.isDirectory() || current.isSymbolicLink() || current.ino !== dirIdentity.ino || current.dev !== dirIdentity.dev ||
            readdirSync(directory).join(",") !== path.basename(filename) ||
            !lstatSync(filename).isFile() || lstatSync(filename).isSymbolicLink() || SHA(readFileSync(filename)) !== expected) {
          throw new Error("npm vendor artifact changed; cleanup refused");
        }
        rmSync(filename);
        rmdirSync(directory);
        cleaned = true;
      },
    };
  } catch (error) {
    // Failed writes remain visible for reconciliation unless the directory is
    // still empty and therefore contains no uncertain output bytes.
    if (readdirSync(directory).length === 0) rmdirSync(directory);
    throw error;
  }
}

function statePaths(root) {
  const artifacts = path.join(root, ".artifacts");
  const directory = path.join(root, STATE);
  const receipt = path.join(directory, "receipt.json");
  for (const [filename, directoryExpected] of [[artifacts, true], [directory, true], [receipt, false]]) {
    let stat;
    try { stat = lstatSync(filename); }
    catch (error) { if (error.code === "ENOENT") continue; throw error; }
    if (stat.isSymbolicLink() || (directoryExpected ? !stat.isDirectory() : !stat.isFile())) {
      throw new Error("npm vendor staging path must be a regular source-owned entry");
    }
  }
  return { artifacts, directory, receipt, backup: path.join(directory, "npm.original-link"), npm: path.join(root, "node_modules/npm") };
}

export function prepareNpmVendorForPack(repoRoot) {
  const root = realpathSync(repoRoot);
  const manifest = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8"));
  if (!isNpmVendorBackportConfigured(manifest)) return false;
  const verified = verifyInstalledNpmVendor(root);
  const paths = statePaths(root);
  if (existsSync(paths.receipt)) {
    const receipt = JSON.parse(readFileSync(paths.receipt, "utf8"));
    if (receipt.schema !== "openclaw.npm-vendor-pack-staging.v1" || receipt.proofSha256 !== verified.proofSha256 ||
        receipt.inventorySha256 !== verified.inventorySha256 || receipt.ownerPid !== process.pid ||
        !lstatSync(paths.npm).isDirectory() || lstatSync(paths.npm).isSymbolicLink()) {
      throw new Error("npm vendor pack staging belongs to another or changed owner");
    }
    return false;
  }
  const entry = lstatSync(paths.npm);
  // A regular installed tree is already packable; verify its full inventory but
  // do not take ownership of it or later remove it as staging.
  if (!entry.isSymbolicLink()) return false;
  const originalLink = readlinkSync(paths.npm);
  if (!existsSync(paths.artifacts)) mkdirSync(paths.artifacts, { mode: 0o700 });
  // Do not adopt even an empty ignored directory from a different or interrupted
  // owner. Existing matching receipts are handled by the reentry branch above.
  mkdirSync(paths.directory, { mode: 0o700 });
  const receipt = { schema: "openclaw.npm-vendor-pack-staging.v1", ownerPid: process.pid,
    proofSha256: verified.proofSha256, inventorySha256: verified.inventorySha256, originalLink };
  writeFileSync(paths.receipt, `${JSON.stringify(receipt)}\n`, { flag: "wx", mode: 0o600 });
  renameSync(paths.npm, paths.backup);
  try {
    cpSync(verified.packageRoot, paths.npm, { recursive: true, dereference: false, errorOnExist: true, force: false });
    verifyInstalledNpmVendor(root);
  } catch (error) {
    // Keep the backup and receipt on uncertainty. A separate explicit restore
    // checks all staged bytes before replacing anything.
    throw new Error("npm vendor pack staging failed; receipt retained", { cause: error });
  }
  return true;
}

export function restoreNpmVendorForPack(repoRoot) {
  const root = realpathSync(repoRoot);
  const paths = statePaths(root);
  if (!existsSync(paths.receipt)) return false;
  const receipt = JSON.parse(readFileSync(paths.receipt, "utf8"));
  if (Object.keys(receipt).sort().join(",") !== "inventorySha256,originalLink,ownerPid,proofSha256,schema" ||
      receipt.schema !== "openclaw.npm-vendor-pack-staging.v1" || typeof receipt.originalLink !== "string" ||
      !Number.isSafeInteger(receipt.ownerPid) || !lstatSync(paths.backup).isSymbolicLink() ||
      readlinkSync(paths.backup) !== receipt.originalLink) throw new Error("npm vendor staging recovery binding differs");
  const verified = verifyInstalledNpmVendor(root);
  if (receipt.proofSha256 !== verified.proofSha256 || receipt.inventorySha256 !== verified.inventorySha256 ||
      !lstatSync(paths.npm).isDirectory() || lstatSync(paths.npm).isSymbolicLink() ||
      readdirSync(paths.directory).sort().join(",") !== "npm.original-link,receipt.json") {
    throw new Error("npm vendor staged bytes changed; restore refused");
  }
  // Moving a relative symlink to the backup changes its resolution. Verify the
  // original target at its original location before deleting the staged tree.
  const originalTarget = realpathSync(path.resolve(path.dirname(paths.npm), receipt.originalLink));
  inside(root, originalTarget);
  const ctx = context(root);
  verifyInstalledNpmVendorDirectory({ packageRoot: originalTarget, proof: ctx.proof, patchBytes: ctx.patchBytes });
  rmSync(paths.npm, { recursive: true });
  renameSync(paths.backup, paths.npm);
  verifyInstalledNpmVendor(root);
  rmSync(paths.receipt);
  rmdirSync(paths.directory);
  return true;
}

export function installGlobalNpmVendor(repoRoot, prefix) {
  if (realpathSync(prefix) !== path.resolve(prefix) ||
      realpathSync(path.join(prefix, "lib/node_modules")) !== path.join(prefix, "lib/node_modules")) {
    throw new Error("npm vendor global prefix must be a regular canonical directory");
  }
  const verified = verifyInstalledNpmVendor(repoRoot);
  const npmDir = path.join(prefix, "lib/node_modules/npm");
  if (!lstatSync(npmDir).isDirectory() || lstatSync(npmDir).isSymbolicLink()) throw new Error("global npm directory is unexpected");
  for (const [name, target] of [["npm", "npm-cli.js"], ["npx", "npx-cli.js"]]) {
    const link = path.join(prefix, "bin", name);
    if (!lstatSync(link).isSymbolicLink() || readlinkSync(link) !== `../lib/node_modules/npm/bin/${target}`) {
      throw new Error("global npm entrypoint differs from pinned Node image layout");
    }
  }
  const temporary = mkdtempSync(path.join(prefix, "lib/node_modules/.npm-vendor-"));
  const staged = path.join(temporary, "npm");
  const backup = path.join(temporary, "npm.previous");
  const ctx = context(repoRoot);
  cpSync(verified.packageRoot, staged, { recursive: true, dereference: false, errorOnExist: true, force: false });
  verifyInstalledNpmVendorDirectory({ packageRoot: staged, proof: ctx.proof, patchBytes: ctx.patchBytes });
  renameSync(npmDir, backup);
  renameSync(staged, npmDir);
  verifyInstalledNpmVendorDirectory({ packageRoot: npmDir, proof: ctx.proof, patchBytes: ctx.patchBytes });
  rmSync(backup, { recursive: true });
  rmdirSync(temporary);
  return verified;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  assert.deepEqual(process.argv.slice(2), ["install-global", "--repo-root", "/app", "--prefix", "/usr/local"]);
  if (process.getuid?.() !== 0) throw new Error("Docker npm delivery requires root in the runtime build stage");
  installGlobalNpmVendor("/app", "/usr/local");
}
