import { createHash } from "node:crypto";
// The only action is a constant trusted NOOP, surrounded by stdlib provenance measurements.
import fs from "node:fs";
import { inventory } from "./phase1-observer.mjs";
const digest = (p) => createHash("sha256").update(fs.readFileSync(p)).digest("hex");
export function verifyBaseline(baseline) {
  if (
    !baseline.python.canonical.startsWith("/usr/") ||
    fs.realpathSync(baseline.python.canonical) !== baseline.python.canonical ||
    digest(baseline.python.canonical) !== baseline.python.sha256
  )
    throw Error("Python baseline mismatch");
  for (const key of ["pnpmDistribution", "corepackDistribution"]) {
    const expected = baseline[key];
    if (
      !(
        expected.root.startsWith("/opt/corepack/") ||
        expected.root.startsWith("/usr/local/lib/node_modules/corepack")
      )
    )
      throw Error("distribution canonical root boundary");
    const actual = inventory(expected.root);
    if (actual.inventorySha256 !== expected.inventorySha256)
      throw Error("full " + key + " baseline mismatch");
  }
  return {
    pythonSha256: baseline.python.sha256,
    pnpmDistributionSha256: baseline.pnpmDistribution.inventorySha256,
    corepackDistributionSha256: baseline.corepackDistribution.inventorySha256,
  };
}
if (process.argv[1]?.endsWith("/phase1-noop.mjs")) {
  try {
    const baseline = JSON.parse(fs.readFileSync("/opt/layout/phase1-baseline.json")),
      before = verifyBaseline(baseline);
    console.log("PHASE1_TRUSTED_NOOP");
    const after = verifyBaseline(baseline);
    if (JSON.stringify(before) !== JSON.stringify(after))
      throw Error("before/after immutable provenance mismatch");
    console.log("PHASE1_POSTFLIGHT=" + JSON.stringify({ before, after, productQualified: false }));
  } catch (e) {
    console.error("PHASE1_NOOP_POSTFLIGHT_FAILED=" + e.message);
    process.exitCode = 1;
  }
}
