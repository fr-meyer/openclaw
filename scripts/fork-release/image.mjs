#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  verifyDockerReleaseLayout,
  smokeDockerReleaseImage,
} from "../docker-release-artifacts.mjs";

const SHA = /^[0-9a-f]{40}$/u;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const positive = /^[1-9][0-9]*$/u;

function need(value, message) {
  if (!value) throw new Error(message);
}

function json(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function hash(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function validateManifest(path) {
  const manifest = json(path);
  need(manifest.schema === "openclaw.fork-release.v1", "Wrong fork release manifest schema");
  need(manifest.repository === "fr-meyer/openclaw", "Wrong fork release repository");
  need(
    SHA.test(manifest.source?.commit) && SHA.test(manifest.source?.tree),
    "Invalid pinned source",
  );
  need(manifest.image?.architecture === "amd64", "Only linux/amd64 is staged");
  return manifest;
}

async function checkedLayout({ manifest, receipt, ociDir }) {
  const result = await verifyDockerReleaseLayout({
    directory: ociDir,
    architecture: manifest.image.architecture,
    sourceSha: manifest.source.commit,
    version: receipt.version,
    builtAt: receipt.builtAt,
    expectedDigest: receipt.indexDigest,
  });
  need(result.imageDigest === receipt.imageDigest, "Image manifest digest changed");
  need(result.configDigest === receipt.configDigest, "Image config digest changed");
  return result;
}

async function main() {
  const [command, manifestPath, inventoryPath, third, fourth, fifth, sixth] = process.argv.slice(2);
  need(
    ["seal", "verify"].includes(command),
    "Usage: image.mjs seal MANIFEST INVENTORY SOURCE OCI DIGEST OUTPUT | verify MANIFEST INVENTORY RECEIPT OCI",
  );
  const manifest = validateManifest(manifestPath);
  const preflightPath = fileURLToPath(new URL("preflight.py", import.meta.url));
  const preflightArgs = ["--manifest", manifestPath, "--inventory", inventoryPath];
  execFileSync("python3", [preflightPath, ...preflightArgs, "--metadata-only"], { stdio: "pipe" });
  const inventoryHash = hash(inventoryPath);
  if (command === "verify") {
    const receipt = json(third);
    need(receipt.schema === "openclaw.fork-release-image.v2", "Wrong image receipt schema");
    need(
      receipt.manifestSha256 === hash(manifestPath),
      "Image receipt belongs to another manifest",
    );
    need(receipt.inventorySha256 === inventoryHash, "Image receipt inventory changed");
    need(
      receipt.repository === manifest.repository &&
        receipt.sourceSha === manifest.source.commit &&
        receipt.sourceTree === manifest.source.tree,
      "Image source identity changed",
    );
    need(receipt.architecture === manifest.image.architecture, "Image architecture changed");
    need(
      [receipt.indexDigest, receipt.imageDigest, receipt.configDigest].every((value) =>
        DIGEST.test(value),
      ),
      "Invalid image digest",
    );
    need(
      SHA.test(receipt.producer?.workflowSha) &&
        positive.test(String(receipt.producer?.runId)) &&
        positive.test(String(receipt.producer?.attempt)),
      "Invalid producer identity",
    );
    need(
      receipt.artifactName ===
        `fork-release-${receipt.sourceSha}-${receipt.producer.runId}-${receipt.producer.attempt}`,
      "Image artifact name changed",
    );
    if (manifest.review) {
      need(SHA.test(receipt.review?.headSha), "Image receipt lacks exact PR head");
      for (const key of ["prNumber", "baseSha", "changedDiffSha256"]) {
        need(receipt.review[key] === manifest.review[key], `Image PR ${key} changed`);
      }
    }
    await checkedLayout({ manifest, receipt, ociDir: fourth });
    console.log(`Verified ${receipt.indexDigest} for ${receipt.sourceSha}`);
    return;
  }
  const [sourceDir, ociDir, expectedDigest, outputPath] = [third, fourth, fifth, sixth];
  execFileSync("python3", [preflightPath, ...preflightArgs, "--source-dir", sourceDir], {
    stdio: "pipe",
  });
  need(DIGEST.test(expectedDigest), "Missing exact BuildKit digest");
  need(process.env.GITHUB_REPOSITORY === manifest.repository, "Wrong producer repository");
  need(
    SHA.test(process.env.GITHUB_WORKFLOW_SHA) &&
      positive.test(process.env.GITHUB_RUN_ID) &&
      positive.test(process.env.GITHUB_RUN_ATTEMPT),
    "Missing producer identity",
  );
  need(
    process.env.GITHUB_SHA === process.env.GITHUB_WORKFLOW_SHA,
    "Workflow source and checkout differ",
  );
  const sourceSha = execFileSync("git", ["-C", sourceDir, "rev-parse", "HEAD"], {
    encoding: "utf8",
  }).trim();
  const sourceTree = execFileSync("git", ["-C", sourceDir, "rev-parse", "HEAD^{tree}"], {
    encoding: "utf8",
  }).trim();
  need(
    sourceSha === manifest.source.commit && sourceTree === manifest.source.tree,
    "Build source is not pinned candidate",
  );
  const toolingRoot = dirname(dirname(dirname(manifestPath)));
  const toolingSha = execFileSync("git", ["-C", toolingRoot, "rev-parse", "HEAD"], {
    encoding: "utf8",
  }).trim();
  if (manifest.review) {
    const parent = execFileSync("git", ["-C", toolingRoot, "show", "-s", "--format=%P", "HEAD"], {
      encoding: "utf8",
    }).trim();
    need(parent === sourceSha, "PR head is not the metadata seal above the source");
  }
  const version = json(`${sourceDir}/package.json`).version;
  const receipt = {
    schema: "openclaw.fork-release-image.v2",
    manifestSha256: hash(manifestPath),
    inventorySha256: inventoryHash,
    repository: manifest.repository,
    sourceSha,
    sourceTree,
    architecture: manifest.image.architecture,
    version,
    builtAt: process.env.BUILT_AT,
    indexDigest: expectedDigest,
    producer: {
      workflowSha: process.env.GITHUB_WORKFLOW_SHA,
      runId: process.env.GITHUB_RUN_ID,
      attempt: process.env.GITHUB_RUN_ATTEMPT,
    },
    artifactName: `fork-release-${sourceSha}-${process.env.GITHUB_RUN_ID}-${process.env.GITHUB_RUN_ATTEMPT}`,
    ...(manifest.review ? { review: { ...manifest.review, headSha: toolingSha } } : {}),
  };
  const image = await verifyDockerReleaseLayout({
    directory: ociDir,
    architecture: receipt.architecture,
    sourceSha,
    version,
    builtAt: receipt.builtAt,
    expectedDigest,
  });
  smokeDockerReleaseImage(ociDir, receipt.architecture, "default", image.configDigest);
  receipt.imageDigest = image.imageDigest;
  receipt.configDigest = image.configDigest;
  writeFileSync(outputPath, `${JSON.stringify(receipt, null, 2)}\n`, { flag: "wx", mode: 0o600 });
  console.log(`Prepared and smoked ${receipt.indexDigest}`);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
