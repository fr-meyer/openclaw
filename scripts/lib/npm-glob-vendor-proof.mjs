// Exact npm 12.2.1 / Glob 13.0.6 backport identity and offline delivery verifier.
// No network, package loading, lifecycle scripts, or compiler dependency.
import { createHash } from "node:crypto";
import { lstatSync, readdirSync, readFileSync, realpathSync } from "node:fs";
import path from "node:path";

export const NPM_VENDOR_PINS = Object.freeze({
  npmVersion: "12.2.1",
  globVersion: "13.0.6",
  originalIntegrity:
    "sha512-bKCmFRVT/BB+YPEYbZwQ1XUI3N5t4xKSpU1MxOjo7z3iWzKBJ0ZXRC1xFdEN+TC7N5TdywaBzf2dMXGJq/e2PQ==",
  originalSha256: "228bd64aaef23270dbdbd2cf3d5ef5c467602ef38c4066246cef1984adab9a67",
  originalInventorySha256: "c9a016c3ef9993a88d8dad15ecb5d508a59f5f958c3ff6352d8b4ccfe5362fa3",
  globIntegrity:
    "sha512-Wjlyrolmm8uDpm/ogGyXZXb1Z+Ca2B8NbJwqBVg0axK9GbBeoS7yGV6vjXnYdGm6X53iehEuxxbyiKp8QmN4Vw==",
  sourceCommit: "e80cb38ae60d6cbff9e75f39032a994858994d35",
  sourceSha256: "ae534f35edd3837a2969ecdd4ea90853cc1b9a9c8e4d10108e5e0994fb5e001e",
  fixCommit: "4682e8c9babee1b385202ede36389634e12076d7",
  upstreamFixSha256: "22adee340137e4f0636701c99bb5f75fb572d38c91ff5de0b77b80f453c18e4a",
  fixParentSha256: "d0bee3a7741067f0720ed89d0a86b86b194164c4f2c663b54ec089953ac488ae",
  esbuildVersion: "0.28.2",
  esbuildIntegrity:
    "sha512-HKVLS8dvII+xoKW9kmqxbRKrnWEXfJJr/FZhhJmiqIB0e053QNYFqOBouTMO/k5sID4MvCiUCvv8b9M4h32wIA==",
});
export const NPM_VENDOR_CHANGED_PATHS = Object.freeze([
  "node_modules/glob/dist/commonjs/index.min.js",
  "node_modules/glob/dist/commonjs/walker.js",
  "node_modules/glob/dist/esm/index.min.js",
  "node_modules/glob/dist/esm/walker.js",
]);
const HEX = /^[a-f0-9]{64}$/;
const SRI = /^sha512-[A-Za-z0-9+/]{86}==$/;
const fail = (code) => {
  throw new Error(`npm-vendor.${code}`);
};
// Include setuid, setgid and sticky bits; silently masking them is not exact identity.
export function inventoryMode(mode) {
  const exact = mode & 0o7777;
  if (![0o644, 0o755].includes(exact)) fail("inventory_mode");
  return exact;
}
export const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
export const integrity = (bytes) => `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
const jsonBytes = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
function exactKeys(value, names, label) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).sort().join("\0") !== [...names].sort().join("\0")
  )
    fail(label);
}
function safePath(name) {
  if (
    typeof name !== "string" ||
    !name ||
    name.includes("\\") ||
    /[\x00-\x1f\x7f]/.test(name) ||
    name.normalize("NFC") !== name ||
    name.split("/").some((p) => !p || p === "." || p === "..")
  )
    fail("path");
  return name;
}
function inventory(rows) {
  if (!Array.isArray(rows) || rows.length !== 1942) fail("inventory_count");
  let previous = "";
  return rows.map((row) => {
    exactKeys(row, ["path", "mode", "size", "sha256"], "inventory_shape");
    safePath(row.path);
    if (
      row.path <= previous ||
      ![0o644, 0o755].includes(row.mode) ||
      !Number.isSafeInteger(row.size) ||
      row.size < 0 ||
      row.size > 8 * 1024 * 1024 ||
      !HEX.test(row.sha256)
    )
      fail("inventory_row");
    previous = row.path;
    return { path: row.path, mode: row.mode, size: row.size, sha256: row.sha256 };
  });
}
export function canonicalInventorySha256(rows) {
  return sha256(Buffer.from(`${JSON.stringify(rows)}\n`));
}
export function validateNpmVendorProof(proof) {
  exactKeys(
    proof,
    ["schema", "npmVersion", "original", "repair", "compiler", "derived", "patch", "maps"],
    "proof_shape",
  );
  if (
    proof.schema !== "openclaw.npm-glob-vendor-backport.v1" ||
    proof.npmVersion !== NPM_VENDOR_PINS.npmVersion
  )
    fail("proof_identity");
  exactKeys(
    proof.original,
    ["integrity", "sha256", "inventorySha256", "mapsAbsent", "files"],
    "original_shape",
  );
  const original = inventory(proof.original.files);
  if (
    proof.original.mapsAbsent !== true ||
    proof.original.integrity !== NPM_VENDOR_PINS.originalIntegrity ||
    proof.original.sha256 !== NPM_VENDOR_PINS.originalSha256 ||
    proof.original.inventorySha256 !== NPM_VENDOR_PINS.originalInventorySha256 ||
    canonicalInventorySha256(original) !== NPM_VENDOR_PINS.originalInventorySha256
  )
    fail("original_binding");
  exactKeys(
    proof.repair,
    [
      "globVersion",
      "fixCommit",
      "sourceCommit",
      "sourceSha256",
      "upstreamFixSha256",
      "changedFiles",
    ],
    "repair_shape",
  );
  for (const key of [
    "globVersion",
    "fixCommit",
    "sourceCommit",
    "sourceSha256",
    "upstreamFixSha256",
  ])
    if (proof.repair[key] !== NPM_VENDOR_PINS[key]) fail("repair_binding");
  if (!Array.isArray(proof.repair.changedFiles) || proof.repair.changedFiles.length !== 4)
    fail("change_count");
  const files = original.map((row) => ({ ...row }));
  proof.repair.changedFiles.forEach((row, i) => {
    exactKeys(row, ["path", "oldSha256", "newSha256", "size", "mode"], "change_shape");
    const before = files.find((file) => file.path === row.path);
    if (
      row.path !== NPM_VENDOR_CHANGED_PATHS[i] ||
      !before ||
      row.oldSha256 !== before.sha256 ||
      row.newSha256 === before.sha256 ||
      !HEX.test(row.newSha256) ||
      !Number.isSafeInteger(row.size) ||
      row.size < 1 ||
      row.size > 2 * 1024 * 1024 ||
      row.mode !== before.mode
    )
      fail("change_binding");
    before.sha256 = row.newSha256;
    before.size = row.size;
  });
  exactKeys(proof.compiler, ["name", "version", "integrity"], "compiler_shape");
  if (
    proof.compiler.name !== "esbuild" ||
    proof.compiler.version !== NPM_VENDOR_PINS.esbuildVersion ||
    proof.compiler.integrity !== NPM_VENDOR_PINS.esbuildIntegrity
  )
    fail("compiler_binding");
  exactKeys(proof.derived, ["integrity", "sha256", "inventorySha256"], "derived_shape");
  if (
    !SRI.test(proof.derived.integrity) ||
    !HEX.test(proof.derived.sha256) ||
    proof.derived.inventorySha256 !== canonicalInventorySha256(files)
  )
    fail("derived_binding");
  exactKeys(proof.patch, ["filename", "sha256", "size"], "patch_shape");
  if (
    proof.patch.filename !== "npm@12.2.1.patch" ||
    !HEX.test(proof.patch.sha256) ||
    !Number.isSafeInteger(proof.patch.size) ||
    proof.patch.size < 1 ||
    proof.patch.size > 2 * 1024 * 1024
  )
    fail("patch_binding");
  if (!Array.isArray(proof.maps) || proof.maps.length !== 4) fail("map_count");
  const mapPaths = [...NPM_VENDOR_CHANGED_PATHS].map((p) => `${p}.map`).sort();
  proof.maps.forEach((row, i) => {
    exactKeys(row, ["path", "size", "sha256"], "map_shape");
    if (
      row.path !== mapPaths[i] ||
      !Number.isSafeInteger(row.size) ||
      row.size < 1 ||
      row.size > 4 * 1024 * 1024 ||
      !HEX.test(row.sha256)
    )
      fail("map_binding");
  });
  return {
    npmVersion: proof.npmVersion,
    proofSha256: sha256(jsonBytes(proof)),
    inventorySha256: proof.derived.inventorySha256,
    files,
  };
}
export function readNpmVendorProof(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length > 1024 * 1024) fail("proof_bytes");
  let parsed;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch {
    fail("proof_json");
  }
  if (!jsonBytes(parsed).equals(bytes)) fail("proof_noncanonical"); // rejects duplicate keys and encoding drift
  validateNpmVendorProof(parsed);
  return parsed;
}
function verifyNpmDirectory({ packageRoot, proof, patchBytes }, originalOnly) {
  const facts = validateNpmVendorProof(proof);
  if (
    patchBytes !== undefined &&
    (!Buffer.isBuffer(patchBytes) ||
      patchBytes.length !== proof.patch.size ||
      sha256(patchBytes) !== proof.patch.sha256)
  )
    fail("patch_bytes");
  const root = realpathSync(packageRoot);
  if (!lstatSync(root).isDirectory()) fail("root");
  if (originalOnly) {
    facts.files = proof.original.files;
    facts.inventorySha256 = proof.original.inventorySha256;
  }
  const actual = [];
  function walk(dir, prefix) {
    for (const name of readdirSync(dir).sort()) {
      const relative = safePath(prefix ? `${prefix}/${name}` : name);
      const file = path.join(dir, name);
      const stat = lstatSync(file);
      if (stat.isSymbolicLink()) fail("installed_link");
      if (stat.isDirectory()) walk(file, relative);
      else if (stat.isFile())
        actual.push({
          path: relative,
          mode: inventoryMode(stat.mode),
          size: stat.size,
          sha256: sha256(readFileSync(file)),
        });
      else fail("installed_type");
    }
  }
  walk(root, "");
  actual.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  if (JSON.stringify(actual) !== JSON.stringify(facts.files)) fail("installed_inventory");
  return { ...facts, packageRoot: root };
}
export function verifyInstalledNpmVendorDirectory(options) {
  return verifyNpmDirectory(options, false);
}
export function verifyOriginalNpmVendorDirectory(options) {
  return verifyNpmDirectory(options, true);
}
