#!/usr/bin/env node

import { execFileSync } from "node:child_process";
// Stage the separately installed publisher as inert image content. The caller
// supplies source revision provenance; this script binds it to exact file bytes.
import { createHash } from "node:crypto";
import { copyFile, mkdir, readFile, lstat, writeFile } from "node:fs/promises";
import { basename, join, resolve } from "node:path";

const PACKAGE_NAME = "mergeguez-pr-lifecycle";
const SOURCE_PATH = `scripts/docker/runtime-plugins/${PACKAGE_NAME}`;
const PACKAGE_FILES = [
  "README.md",
  "index.mjs",
  "openclaw.plugin.json",
  "package.json",
  "src/controller.mjs",
  "src/http.mjs",
  "src/runtime-pin-transition.mjs",
  "src/runtime.mjs",
];
const MANIFEST_NAME = "publisher-source.json";
const SCHEMA = "openclaw-current-publisher-image-package-v1";

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function parseArgs(argv) {
  const args = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!flag?.startsWith("--") || value === undefined || args.has(flag)) {
      throw new Error("Expected unique --flag value pairs");
    }
    args.set(flag, value);
  }
  return args;
}

function git(...args) {
  return execFileSync("git", args, { encoding: "utf8" }).trim();
}

async function regularBytes(path) {
  const stat = await lstat(path);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error(`Publisher input must be a regular file: ${path}`);
  }
  return readFile(path);
}

async function packageHashes(source) {
  const files = {};
  for (const file of PACKAGE_FILES) {
    files[file] = sha256(await regularBytes(join(source, file)));
  }
  return files;
}

function assertCommit(commit) {
  if (commit !== "" && !/^[0-9a-f]{40}$/.test(commit)) {
    throw new Error("Source commit must be an exact lowercase 40-character Git SHA or empty");
  }
}

async function stage(args) {
  const source = resolve(args.get("--source") ?? SOURCE_PATH);
  const out = resolve(args.get("--out") ?? "");
  const commit = args.get("--commit");
  if (!args.has("--out") || commit === undefined) {
    throw new Error("Stage requires --source, --out, and --commit (empty is unbound)");
  }
  assertCommit(commit);
  const packageJson = JSON.parse(await regularBytes(join(source, "package.json")));
  if (packageJson.name !== "@fr-meyer/openclaw-mergeguez-pr-lifecycle") {
    throw new Error("Unexpected publisher package identity");
  }
  const files = await packageHashes(source);
  await mkdir(out);
  await mkdir(join(out, PACKAGE_NAME));
  await mkdir(join(out, PACKAGE_NAME, "src"));
  for (const file of PACKAGE_FILES) {
    await copyFile(join(source, file), join(out, PACKAGE_NAME, file));
  }
  const manifest = {
    schema: SCHEMA,
    sourceCommit: commit || null,
    sourcePath: SOURCE_PATH,
    packageName: packageJson.name,
    packageVersion: packageJson.version,
    files,
  };
  await writeFile(join(out, MANIFEST_NAME), `${JSON.stringify(manifest, null, 2)}\n`);
  await copyFile(new URL(import.meta.url), join(out, "verify-package.mjs"));
  await verify(out);
  process.stdout.write(`${JSON.stringify(manifest)}\n`);
}

async function verify(out) {
  const manifest = JSON.parse(await regularBytes(join(out, MANIFEST_NAME)));
  if (
    manifest.schema !== SCHEMA ||
    manifest.sourcePath !== SOURCE_PATH ||
    manifest.packageName !== "@fr-meyer/openclaw-mergeguez-pr-lifecycle" ||
    !manifest.packageVersion ||
    Object.keys(manifest.files).join("\n") !== PACKAGE_FILES.join("\n")
  ) {
    throw new Error("Publisher package manifest contract mismatch");
  }
  assertCommit(manifest.sourceCommit ?? "");
  const actual = await packageHashes(join(out, PACKAGE_NAME));
  for (const file of PACKAGE_FILES) {
    if (actual[file] !== manifest.files[file]) {
      throw new Error(`Publisher package SHA-256 mismatch: ${file}`);
    }
  }
  const packageJson = JSON.parse(await regularBytes(join(out, PACKAGE_NAME, "package.json")));
  if (
    packageJson.name !== manifest.packageName ||
    packageJson.version !== manifest.packageVersion
  ) {
    throw new Error("Publisher package identity mismatch");
  }
  return manifest;
}

async function planImage() {
  const head = git("rev-parse", "HEAD");
  assertCommit(head);
  if (git("status", "--porcelain", "--untracked-files=normal")) {
    throw new Error("Image plan requires a clean source checkout");
  }
  const cut = JSON.parse(await readFile("custom-patches/manifest.json", "utf8"));
  if (
    cut.schema !== "openclaw-v99-source-preparation-v1" ||
    cut.status !== "SOURCE_ONLY_UNQUALIFIED" ||
    cut.upstream.tag !== "v2026.9.9" ||
    git("rev-parse", `${cut.upstream.tag}^{}`) !== cut.upstream.commit ||
    git("rev-parse", `${cut.upstream.commit}^{tree}`) !== cut.upstream.tree
  ) {
    throw new Error("9.9 source preparation manifest or tag binding differs from Git");
  }
  git("merge-base", "--is-ancestor", cut.upstream.commit, head);
  const publisher = cut.publisher;
  if (publisher.path !== SOURCE_PATH || publisher.packageName !== "@fr-meyer/openclaw-mergeguez-pr-lifecycle") {
    throw new Error("Publisher identity differs from 9.9 source preparation manifest");
  }
  const source = resolve(SOURCE_PATH);
  const packageJson = JSON.parse(await regularBytes(join(source, "package.json")));
  if (packageJson.version !== publisher.packageVersion) {
    throw new Error("Publisher version differs from its source binding");
  }
  const files = await packageHashes(source);
  if (files["src/runtime.mjs"] !== publisher.runtimeSha256) {
    throw new Error("Publisher runtime differs from its source binding");
  }
  // The source-only candidate binds every packaged byte to this local HEAD.
  for (const file of PACKAGE_FILES) {
    const committedBytes = execFileSync("git", [
      "show",
      `${head}:${SOURCE_PATH}/${file}`,
    ]);
    if (sha256(committedBytes) !== files[file]) {
      throw new Error(`Candidate commit does not contain current publisher bytes: ${file}`);
    }
  }
  const command = [
    "docker",
    "buildx",
    "build",
    "--file",
    "Dockerfile",
    "--platform",
    "<observed-target-platform>",
    "--build-arg",
    `GIT_COMMIT=${head}`,
    "--build-arg",
    "OPENCLAW_PARITY_IMAGE=1",
    "--build-arg",
    "OPENCLAW_BUILD_TIMESTAMP=<operator-selected-utc-timestamp>",
    "--build-arg",
    "OPENCLAW_EXTENSIONS=workboard",
    "--label",
    `org.opencontainers.image.revision=${head}`,
    "--label",
    "org.opencontainers.image.source=https://github.com/fr-meyer/openclaw",
    "--metadata-file",
    "<operator-selected-output-path>",
    "--tag",
    `openclaw-v99-prep:${head.slice(0, 12)}`,
    "--load",
    `https://github.com/fr-meyer/openclaw.git#${head}`,
  ];
  process.stdout.write(
    `${JSON.stringify(
      {
        schema: "openclaw-v99-preparation-image-plan-v1",
        sourceCommit: head,
        upstreamCommit: cut.upstream.commit,
        sourceQualified: false,
        buildExecuted: false,
        productionAccepted: false,
        publisherPath: SOURCE_PATH,
        publisherVersion: packageJson.version,
        publisherFiles: files,
        command,
        executed: false,
      },
      null,
      2,
    )}\n`,
  );
}

try {
  const args = parseArgs(process.argv.slice(2));
  if (args.has("--verify") && args.size === 1) {
    const manifest = await verify(resolve(args.get("--verify")));
    process.stdout.write(
      `${JSON.stringify({ verified: true, sourceCommit: manifest.sourceCommit })}\n`,
    );
  } else if (args.has("--plan-image") && args.size === 1 && args.get("--plan-image") === "true") {
    await planImage();
  } else {
    await stage(args);
  }
} catch (error) {
  process.stderr.write(`${basename(process.argv[1])}: ${error.message}\n`);
  process.exitCode = 1;
}
