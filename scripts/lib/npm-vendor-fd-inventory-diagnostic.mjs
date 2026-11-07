// Fixed data-only diagnostic. Existing phase_process owns40s deadline+20s cleanup.
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { readNpmVendorProof, validateNpmVendorProof } from "./npm-glob-vendor-proof.mjs";
const SCHEMA = "openclaw.npm-vendor-fd-inventory-diagnostic.v2";
const refused = (reason) => ({
  schema: SCHEMA,
  status: "refused",
  reason,
  qualificationAccepted: false,
  imageBuilt: false,
  complete: false,
});
const sourcePath = (value) =>
  typeof value === "string" &&
  value.length <= 4096 &&
  value.startsWith("/") &&
  value !== "/" &&
  !value.includes("\\") &&
  !value.includes("\0") &&
  !value
    .slice(1)
    .split("/")
    .some((p) => !p || p === "." || p === "..");
function client(mode, payload, timeout, maxBuffer) {
  const input = Buffer.from(JSON.stringify(payload));
  if (input.length > 1024 * 1024) return null;
  const child = spawnSync(
    "/usr/bin/python3",
    [
      "-I",
      "-B",
      fileURLToPath(new URL("./npm-vendor-fd-inventory-collector.py", import.meta.url)),
      mode,
    ],
    {
      input,
      encoding: "utf8",
      timeout,
      killSignal: "SIGKILL",
      maxBuffer,
      env: { PATH: "/usr/bin:/bin", LANG: "C.UTF-8", LC_ALL: "C.UTF-8" },
      stdio: ["pipe", "pipe", "pipe"],
    },
  );
  if (child.error || child.signal || ![0, 2].includes(child.status)) return null;
  try {
    return JSON.parse(child.stdout);
  } catch {
    return null;
  }
}
export function diagnoseInstalledNpmInventory({ sourceRoot }) {
  if (!sourcePath(sourceRoot)) return refused("input_binding_refused");
  if (process.platform !== "linux") return refused("unsupported_platform");
  // Prelude reads only the fixed source proof with held nofollow FDs, never package data.
  const capture = client("--read-proof-v1", { sourceRoot }, 3000, 2 * 1024 * 1024);
  if (capture?.schema === SCHEMA && capture.status === "refused") return capture;
  if (
    capture?.schema !== "openclaw.npm-vendor-proof-read.v1" ||
    capture.status !== "observed" ||
    typeof capture.proofBase64 !== "string" ||
    capture.proofBase64.length > 1400000
  )
    return refused("proof_reader_refused");
  let facts;
  try {
    const bytes = Buffer.from(capture.proofBase64, "base64");
    if (bytes.toString("base64") !== capture.proofBase64 || bytes.length !== capture.proof.bytes)
      throw new Error("capture");
    const proof = readNpmVendorProof(bytes);
    facts = validateNpmVendorProof(proof);
    if (facts.proofSha256 !== capture.proof.sha256) throw new Error("capture");
  } catch {
    return refused("untrusted_proof_or_binding");
  }
  const payload = {
    schema: "openclaw.npm-vendor-selected-input.v1",
    sourceRoot,
    sourceIdentity: capture.sourceIdentity,
    sourceSnapshot: capture.sourceSnapshot,
    proof: capture.proof,
    facts: {
      proofSha256: facts.proofSha256,
      expectedInventorySha256: facts.inventorySha256,
      files: facts.files,
    },
  };
  const report = client("--selected-facts-v1", payload, 35000, 96 * 1024);
  if (
    !report ||
    report.schema !== SCHEMA ||
    !["observed", "refused"].includes(report.status) ||
    report.qualificationAccepted !== false ||
    report.imageBuilt !== false ||
    typeof report.complete !== "boolean" ||
    JSON.stringify(report).length > 64 * 1024 ||
    (report.proofSha256 !== undefined && report.proofSha256 !== facts.proofSha256) ||
    (report.expectedInventorySha256 !== undefined &&
      report.expectedInventorySha256 !== facts.inventorySha256)
  )
    return refused("client_envelope_refused");
  return report;
}
