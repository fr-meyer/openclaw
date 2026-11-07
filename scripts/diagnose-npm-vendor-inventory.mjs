#!/usr/bin/env node
import { openSync, closeSync, writeSync, fsyncSync } from "node:fs";
import path from "node:path";
import { diagnoseInstalledNpmInventory } from "./lib/npm-vendor-fd-inventory-diagnostic.mjs";
const refused = (reason) => ({
  schema: "openclaw.npm-vendor-fd-inventory-diagnostic.v2",
  status: "refused",
  reason,
  qualificationAccepted: false,
  imageBuilt: false,
  complete: false,
});
let report, receipt;
try {
  const args = process.argv.slice(2),
    keys = ["--repo-root", "--proof", "--receipt"];
  if (
    args.length !== 6 ||
    keys.some((key, i) => args[2 * i] !== key) ||
    args.some((a) => !a || a.includes("\0"))
  )
    throw new Error("arguments");
  const root = args[1],
    proof = args[3];
  receipt = args[5];
  if (
    !path.isAbsolute(root) ||
    path.normalize(root) !== root ||
    proof !== path.join(root, "patches/npm-12.2.1.glob-cancellation.proof.json") ||
    !path.isAbsolute(receipt) ||
    path.normalize(receipt) !== receipt
  )
    throw new Error("input_binding_refused");
  report =
    process.env.GITHUB_ACTIONS === "true" && process.env.CI === "true"
      ? diagnoseInstalledNpmInventory({ sourceRoot: root })
      : refused("ci_only");
} catch (error) {
  report = refused(
    ["arguments", "input_binding_refused"].includes(error?.message)
      ? error.message
      : "client_refused",
  );
}
try {
  if (
    typeof receipt !== "string" ||
    !path.isAbsolute(receipt) ||
    path.normalize(receipt) !== receipt
  )
    throw new Error("no_receipt");
  const bytes = Buffer.from(JSON.stringify(report) + "\n");
  if (bytes.length > 64 * 1024) throw new Error("output_cap");
  const fd = openSync(receipt, "wx", 0o600);
  try {
    let offset = 0;
    while (offset < bytes.length) {
      const n = writeSync(fd, bytes, offset, bytes.length - offset);
      if (n < 1) throw new Error("short_write");
      offset += n;
    }
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
} catch {
  if (receipt !== undefined) report = refused("receipt_write_refused");
}
console.log(
  JSON.stringify({
    schema: report.schema,
    status: report.status,
    reason: report.reason,
    qualificationAccepted: false,
    imageBuilt: false,
    complete: report.complete,
  }),
);
process.exitCode = report.status === "observed" ? 0 : 2;
