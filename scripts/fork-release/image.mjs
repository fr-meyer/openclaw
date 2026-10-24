#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readdirSync,
  readSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";
import {
  verifyDockerReleaseLayout,
  smokeDockerReleaseImage,
} from "../docker-release-artifacts.mjs";
import { isDirectRunUrl } from "../lib/direct-run.mjs";
import {
  assertCleanSourceCheckout,
  producerArtifactName,
  readGcpExecution,
  validateProducer,
} from "./gcp-image-context.mjs";
import { readRuntimeExpectations, validateImageRuntimeProof } from "./verify-image-plugins.mjs";

const SHA = /^[0-9a-f]{40}$/u;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;

function need(value, message) {
  if (!value) {
    throw new Error(message);
  }
}

function json(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function hash(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function validateManifest(path) {
  return validateManifestValue(json(path));
}

function validateManifestValue(manifest) {
  need(manifest.schema === "openclaw.fork-release.v1", "Wrong fork release manifest schema");
  need(manifest.repository === "fr-meyer/openclaw", "Wrong fork release repository");
  need(
    SHA.test(manifest.source?.commit) && SHA.test(manifest.source?.tree),
    "Invalid pinned source",
  );
  need(manifest.image?.architecture === "amd64", "Only linux/amd64 is staged");
  need(
    typeof manifest.image.extensions === "string" &&
      manifest.image.extensions.split(",").every((id) => /^[a-z0-9][a-z0-9-]*$/u.test(id)),
    "Invalid selected image extensions",
  );
  need(manifest.image.extensions.split(",").includes("codex"), "Image must include Codex plugin");
  return manifest;
}

export function inspectLoadedPlugins(
  manifest,
  version,
  imageReference,
  codexVersion,
  runtimeExpectations,
  beforeNative,
) {
  need(DIGEST.test(imageReference), "Plugin inspection requires an immutable image digest");
  need(/^\d+\.\d+\.\d+$/u.test(codexVersion), "Missing exact source-pinned Codex version");
  need(
    beforeNative === undefined || typeof beforeNative === "function",
    "Invalid owned plugin admission callback",
  );
  const verifierSource = fileURLToPath(new URL("verify-image-plugins.mjs", import.meta.url));
  const verifierRoot = mkdtempSync(join(tmpdir(), "openclaw-image-verifier-"));
  try {
    chmodSync(verifierRoot, 0o700);
    // Private checkouts can make this script 0600. Stage its exact bytes for the
    // image's normal user without exposing the checkout or changing its mode.
    const source = openSync(verifierSource, constants.O_RDONLY | constants.O_NOFOLLOW);
    let verifierBytes;
    try {
      need(fstatSync(source).isFile(), "Image verifier must be a regular file");
      verifierBytes = readFileSync(source);
    } finally {
      closeSync(source);
    }
    const verifier = join(verifierRoot, "verify-image-plugins.mjs");
    writeFileSync(verifier, verifierBytes, { flag: "wx", mode: 0o600 });
    chmodSync(verifier, 0o444);
    need(
      lstatSync(verifier).isFile() &&
        hash(verifier) === createHash("sha256").update(verifierBytes).digest("hex"),
      "Staged image verifier differs from the source bytes",
    );
    const container = execFileSync(
      "docker",
      [
        "create",
        "--pull",
        "never",
        "--platform",
        `linux/${manifest.image.architecture}`,
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "64",
        "--memory",
        "1g",
        "--memory-swap",
        "1g",
        "--cpus",
        "1",
        "--init",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=256m,mode=1777",
        "--mount",
        `type=bind,source=${verifier},target=/tmp/verify-image-plugins.mjs,readonly`,
        "--entrypoint",
        "node",
        imageReference,
        "/tmp/verify-image-plugins.mjs",
        "/app",
        manifest.image.extensions,
        version,
        codexVersion,
        ...(runtimeExpectations === undefined ? [] : [JSON.stringify(runtimeExpectations)]),
      ],
      { encoding: "utf8", timeout: 30_000, maxBuffer: 256 * 1024, killSignal: "SIGKILL" },
    ).trim();
    need(/^[0-9a-f]{64}$/u.test(container), "Invalid owned plugin-check container identity");
    try {
      beforeNative?.();
      const output = execFileSync("docker", ["start", "--attach", container], {
        encoding: "utf8",
        timeout: 120_000,
        maxBuffer: 256 * 1024,
        killSignal: "SIGKILL",
      });
      need(
        execFileSync(
          "docker",
          [
            "inspect",
            "--format",
            "{{.State.Running}} {{.State.ExitCode}} {{.State.OOMKilled}}",
            container,
          ],
          {
            encoding: "utf8",
            timeout: 30_000,
            killSignal: "SIGKILL",
          },
        ).trim() === "false 0 false",
        "Plugin check did not complete successfully",
      );
      const proof = JSON.parse(output);
      if (runtimeExpectations !== undefined) {
        need(Array.isArray(proof?.plugins), "Image plugin proof missing");
        validateImageRuntimeProof(proof.runtime, runtimeExpectations);
      }
      return proof;
    } finally {
      // The create response grants authority over this exact test container only.
      execFileSync("docker", ["rm", "--force", container], {
        timeout: 30_000,
        killSignal: "SIGKILL",
      });
    }
  } finally {
    // This unique directory is owned by this invocation, including create errors.
    rmSync(verifierRoot, { recursive: true, force: true });
  }
}

export function hostedGitBuildContext(manifest) {
  need(
    manifest.repository === "fr-meyer/openclaw" && SHA.test(manifest.source?.commit),
    "Invalid hosted Git source identity",
  );
  return {
    kind: "git",
    repository: `https://github.com/${manifest.repository}`,
    sourceSha: manifest.source.commit,
  };
}

export async function verifyImageLayout({ manifest, receipt, ociDir }) {
  validateProducer(receipt.producer);
  let sourceRepository = receipt.producer.kind === "gcp" ? manifest.repository : undefined;
  if (Object.hasOwn(receipt, "buildContext")) {
    const context = receipt.buildContext;
    const expected = hostedGitBuildContext(manifest);
    need(
      receipt.producer.kind !== "gcp" &&
        context &&
        typeof context === "object" &&
        !Array.isArray(context) &&
        Object.keys(context).toSorted().join(",") === "kind,repository,sourceSha" &&
        Object.keys(expected).every((key) => context[key] === expected[key]),
      "Hosted Git build context differs from the pinned source",
    );
    sourceRepository = manifest.repository;
  }
  // Legacy hosted v2 receipts without this marker retain their original local-
  // context verification. They do not qualify for the new hosted export gate.
  return verifyDockerReleaseLayout({
    directory: ociDir,
    architecture: manifest.image.architecture,
    sourceSha: manifest.source.commit,
    sourceRepository,
    version: receipt.version,
    builtAt: receipt.builtAt,
    expectedDigest: receipt.indexDigest,
  });
}

function diagnosticJson(path) {
  const descriptor = openSync(
    path,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const before = fstatSync(descriptor);
    const limit = 1024 * 1024;
    need(before.isFile() && before.size <= limit, "static.input_refused");
    // A regular file can grow after fstat. Bound allocation and every read,
    // including a one-byte overflow probe, instead of reading through EOF.
    const buffer = Buffer.alloc(limit + 1);
    let length = 0;
    while (true) {
      const count = readSync(
        descriptor,
        buffer,
        length,
        Math.min(64 * 1024, buffer.length - length),
        null,
      );
      if (count === 0) {
        break;
      }
      length += count;
      need(length <= limit, "static.input_refused");
    }
    const bytes = buffer.subarray(0, length);
    const after = fstatSync(descriptor);
    need(
      bytes.length === before.size &&
        before.mtimeMs === after.mtimeMs &&
        before.ctimeMs === after.ctimeMs,
      "static.input_refused",
    );
    return {
      value: JSON.parse(bytes.toString("utf8")),
      sha256: createHash("sha256").update(bytes).digest("hex"),
    };
  } finally {
    closeSync(descriptor);
  }
}

// This is a non-executing diagnostic, not a build attestation or release seal.
// Origin facts and inspection tooling are caller inputs; their hashes preserve
// those assertions without turning them into authenticated producer evidence.
export async function inspectLayoutStatic({
  manifestPath,
  inventoryPath,
  sourceDir,
  ociDir,
  originalBuildPath,
  privacyPath,
  inspectionToolingSha,
  performedAt,
}) {
  const report = {
    schema: "openclaw.fork-release-static.v1",
    status: "blocked",
    sourceSha: null,
    sourceTree: null,
    manifestSha256: null,
    inventorySha256: null,
    indexDigest: null,
    imageDigest: null,
    configDigest: null,
    builtAt: null,
    originalBuildSha256: null,
    privacyReceiptSha256: null,
    inspectionToolingSha: null,
    performedAt: null,
    staticOnly: true,
    nativeExecuted: false,
    productionAuthorized: false,
    promotable: false,
    reason: "static.input_refused",
  };
  try {
    need(SHA.test(inspectionToolingSha), "static.input_refused");
    const utc = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u;
    const canonicalTime = (value) =>
      typeof value === "string" &&
      utc.test(value) &&
      Number.isFinite(Date.parse(value)) &&
      new Date(value).toISOString() === value.replace("Z", ".000Z");
    need(
      canonicalTime(performedAt) && Date.parse(performedAt) <= Date.now(),
      "static.input_refused",
    );
    const manifestInput = diagnosticJson(manifestPath),
      inventoryInput = diagnosticJson(inventoryPath);
    const manifest = validateManifestValue(manifestInput.value);
    const inventoryHash = inventoryInput.sha256,
      manifestHash = manifestInput.sha256;
    const origin = diagnosticJson(originalBuildPath),
      privacy = diagnosticJson(privacyPath);
    const build = origin.value,
      scan = privacy.value;
    const fields = [
      "schema",
      "repository",
      "sourceSha",
      "sourceTree",
      "manifestSha256",
      "inventorySha256",
      "architecture",
      "version",
      "builtAt",
      "indexDigest",
      "imageDigest",
      "configDigest",
      "producer",
      ...(build?.producer?.kind === "gcp" ? [] : ["buildContext"]),
    ];
    need(
      build &&
        typeof build === "object" &&
        !Array.isArray(build) &&
        Object.keys(build).toSorted().join(",") === fields.toSorted().join(",") &&
        build.schema === "openclaw.fork-release-build-origin.v1" &&
        build.repository === manifest.repository &&
        build.sourceSha === manifest.source.commit &&
        build.sourceTree === manifest.source.tree &&
        build.manifestSha256 === manifestHash &&
        build.inventorySha256 === inventoryHash &&
        build.architecture === manifest.image.architecture &&
        /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/u.test(build.version) &&
        canonicalTime(build.builtAt) &&
        build.builtAt <= performedAt &&
        [build.indexDigest, build.imageDigest, build.configDigest].every(
          (value) => typeof value === "string" && DIGEST.test(value),
        ),
      "static.input_refused",
    );
    validateProducer(build.producer);
    Object.assign(report, {
      sourceSha: build.sourceSha,
      sourceTree: build.sourceTree,
      manifestSha256: manifestHash,
      inventorySha256: inventoryHash,
      indexDigest: build.indexDigest,
      imageDigest: build.imageDigest,
      configDigest: build.configDigest,
      builtAt: build.builtAt,
      originalBuildSha256: origin.sha256,
      privacyReceiptSha256: privacy.sha256,
      inspectionToolingSha,
      performedAt,
    });
    report.reason = "static.privacy_structure_incomplete";
    need(
      scan?.schema === "openclaw.hosted-privacy.v2" &&
        scan.inspectionComplete === true &&
        ["passed", "failed"].includes(scan.status) &&
        !Object.hasOwn(scan, "refusal") &&
        scan.sourceSha === build.sourceSha &&
        scan.toolingSha === inspectionToolingSha &&
        ["indexDigest", "imageDigest", "configDigest"].every((key) => scan[key] === build[key]),
      "static.privacy_structure_incomplete",
    );
    // The JS layout reader is safe to use only after the bound privacy owner
    // completed structural traversal within these static-reader input budgets.
    const caps = {
      blob_bytes: 8 * 1024 ** 3,
      total_blob_bytes: 16 * 1024 ** 3,
      json_bytes: 32 * 1024 ** 2,
      json_nodes: 1000000,
      blobs: 1024,
      manifests: 16,
      layers: 256,
    };
    need(
      Object.entries(caps).every(
        ([key, cap]) =>
          Number.isSafeInteger(scan.limits?.[key]) &&
          scan.limits[key] > 0 &&
          scan.limits[key] <= cap,
      ) &&
        [
          ["blobBytes", "total_blob_bytes"],
          ["jsonNodes", "json_nodes"],
          ["layers", "layers"],
        ].every(
          ([key, limit]) =>
            Number.isSafeInteger(scan.counts?.[key]) &&
            scan.counts[key] >= 0 &&
            scan.counts[key] <= scan.limits[limit],
        ),
      "static.privacy_structure_incomplete",
    );
    report.reason = "static.source_refused";
    assertCleanSourceCheckout(sourceDir);
    const preflightPath = fileURLToPath(new URL("preflight.py", import.meta.url));
    execFileSync(
      "python3",
      [
        preflightPath,
        "--manifest",
        manifestPath,
        "--inventory",
        inventoryPath,
        "--source-dir",
        sourceDir,
      ],
      { stdio: "pipe" },
    );
    need(json(join(sourceDir, "package.json")).version === build.version, "static.source_refused");
    report.reason = "static.verification_failed";
    report.status = "failed";
    const image = await verifyImageLayout({ manifest, receipt: build, ociDir });
    need(
      image.imageDigest === build.imageDigest && image.configDigest === build.configDigest,
      "static.verification_failed",
    );
    need(
      diagnosticJson(manifestPath).sha256 === manifestHash &&
        diagnosticJson(inventoryPath).sha256 === inventoryHash &&
        diagnosticJson(originalBuildPath).sha256 === origin.sha256 &&
        diagnosticJson(privacyPath).sha256 === privacy.sha256,
      "static.verification_failed",
    );
    report.status = "passed";
    report.reason = null;
  } catch {
    // Errors can include attacker-controlled JSON fields or private input paths.
    // Only the fixed current-phase reason may enter the public diagnostic.
  }
  return report;
}

const RETAINED_BASE_FIELDS = [
  "schema",
  "manifestPath",
  "inventoryPath",
  "sourceDir",
  "ociDir",
  "executionPath",
  "originalToolingSha",
  "executionSha256",
  "inspectionToolingSha",
];
const RETAINED_QUALIFICATION_FIELDS = [
  "privacyPath",
  "privacySha256",
  "resourceAdmissionPath",
  "resourceAdmissionSha256",
  "originalResourcesPath",
  "originalResourcesSha256",
];
const HEX = /^[0-9a-f]{64}$/u;
const nowUtc = () => new Date().toISOString().replace(/\.\d{3}Z$/u, "Z");
const canonicalUtc = (value) =>
  typeof value === "string" &&
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u.test(value) &&
  Number.isFinite(Date.parse(value)) &&
  new Date(value).toISOString() === value.replace("Z", ".000Z");
const same = isDeepStrictEqual;
const closedFields = (value, fields) =>
  value &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.keys(value).toSorted().join(",") === fields.toSorted().join(",");

function privateOwned(path, directory = false) {
  const info = lstatSync(path);
  need(
    (directory ? info.isDirectory() : info.isFile()) &&
      !info.isSymbolicLink() &&
      info.uid === process.getuid() &&
      (info.mode & 0o077) === 0,
    "retained.private_input_refused",
  );
  need(
    isAbsolute(path) && resolve(path) === path && realpathSync(path) === path,
    "retained.private_input_refused",
  );
}

function separate(left, right) {
  for (const [parent, child] of [
    [left, right],
    [right, left],
  ]) {
    const path = relative(parent, child);
    need(path === ".." || path.startsWith("../"), "retained.paths_overlap");
  }
}

function writeRetained(path, value) {
  const descriptor = openSync(
    path,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
    0o600,
  );
  try {
    writeFileSync(descriptor, `${JSON.stringify(value, null, 2)}\n`);
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
  const directory = openSync(dirname(path), constants.O_RDONLY | constants.O_DIRECTORY);
  try {
    fsyncSync(directory);
  } finally {
    closeSync(directory);
  }
}

function retainedPlan(planPath, qualification) {
  privateOwned(planPath);
  const plan = diagnosticJson(planPath).value;
  const fields = [...RETAINED_BASE_FIELDS, ...(qualification ? RETAINED_QUALIFICATION_FIELDS : [])];
  need(
    plan &&
      typeof plan === "object" &&
      !Array.isArray(plan) &&
      Object.keys(plan).toSorted().join(",") === fields.toSorted().join(",") &&
      plan.schema ===
        (qualification
          ? "openclaw.retained-gcp-qualification.v1"
          : "openclaw.retained-gcp-input.v1"),
    "retained.plan_refused",
  );
  for (const key of fields.filter((key) => key.endsWith("Path") || key.endsWith("Dir"))) {
    need(
      typeof plan[key] === "string" && isAbsolute(plan[key]) && resolve(plan[key]) === plan[key],
      "retained.plan_refused",
    );
  }
  for (const path of [
    planPath,
    ...fields.filter((key) => key.endsWith("Path")).map((key) => plan[key]),
  ]) {
    separate(path, plan.sourceDir);
    separate(path, plan.ociDir);
  }
  need(
    SHA.test(plan.originalToolingSha) &&
      SHA.test(plan.inspectionToolingSha) &&
      HEX.test(plan.executionSha256) &&
      (!qualification ||
        RETAINED_QUALIFICATION_FIELDS.filter((key) => key.endsWith("Sha256")).every((key) =>
          HEX.test(plan[key]),
        )),
    "retained.plan_refused",
  );
  return plan;
}

function inspectionTooling(expected) {
  const root = fileURLToPath(new URL("../../", import.meta.url));
  assertCleanSourceCheckout(root);
  const actual = execFileSync("git", ["-C", root, "rev-parse", "HEAD"], {
    encoding: "utf8",
  }).trim();
  need(actual === expected, "retained.inspection_tooling_changed");
  return actual;
}

function authenticatedRetainedContext(plan) {
  inspectionTooling(plan.inspectionToolingSha);
  const manifestInput = diagnosticJson(plan.manifestPath),
    inventoryInput = diagnosticJson(plan.inventoryPath);
  const manifest = validateManifestValue(manifestInput.value);
  need(
    realpathSync(plan.sourceDir) === plan.sourceDir && realpathSync(plan.ociDir) === plan.ociDir,
    "retained.plan_refused",
  );
  assertCleanSourceCheckout(plan.sourceDir);
  need(
    execFileSync("git", ["-C", plan.sourceDir, "rev-parse", "HEAD"], {
      encoding: "utf8",
    }).trim() === manifest.source.commit &&
      execFileSync("git", ["-C", plan.sourceDir, "rev-parse", "HEAD^{tree}"], {
        encoding: "utf8",
      }).trim() === manifest.source.tree,
    "retained.source_changed",
  );
  if (manifest.review) {
    need(
      SHA.test(manifest.review.baseSha) && HEX.test(manifest.review.changedDiffSha256),
      "retained.review_changed",
    );
    const diff = execFileSync("git", [
      "-C",
      plan.sourceDir,
      "diff",
      "--binary",
      "--full-index",
      "--no-ext-diff",
      manifest.review.baseSha,
      manifest.source.commit,
    ]);
    need(
      createHash("sha256").update(diff).digest("hex") === manifest.review.changedDiffSha256,
      "retained.review_changed",
    );
  }
  const execution = diagnosticJson(plan.executionPath);
  need(
    execution.sha256 === plan.executionSha256 && DIGEST.test(execution.value.indexDigest),
    "retained.execution_changed",
  );
  need(
    plan.ociDir === join(dirname(realpathSync(plan.executionPath)), "oci"),
    "retained.oci_not_original",
  );
  const { producer, builtAt } = readGcpExecution(plan.executionPath, {
    sourceDir: plan.sourceDir,
    sourceSha: manifest.source.commit,
    sourceTree: manifest.source.tree,
    toolingSha: plan.originalToolingSha,
    manifestSha256: manifestInput.sha256,
    inventorySha256: inventoryInput.sha256,
    indexDigest: execution.value.indexDigest,
  });
  need(producer.executionSha256 === plan.executionSha256, "retained.execution_changed");
  return {
    manifest,
    context: {
      schema: "openclaw.retained-gcp-build-context.v1",
      status: "captured",
      qualified: false,
      productionAuthorized: false,
      repository: manifest.repository,
      sourceSha: manifest.source.commit,
      sourceTree: manifest.source.tree,
      manifestSha256: manifestInput.sha256,
      inventorySha256: inventoryInput.sha256,
      architecture: manifest.image.architecture,
      version: diagnosticJson(join(plan.sourceDir, "package.json")).value.version,
      builtAt,
      indexDigest: execution.value.indexDigest,
      producer,
      executionSha256: plan.executionSha256,
      inspectionToolingSha: plan.inspectionToolingSha,
    },
  };
}

export function captureRetainedGcpOrigin(planPath, outputPath) {
  const plan = retainedPlan(planPath, false),
    { context } = authenticatedRetainedContext(plan);
  privateOwned(dirname(outputPath), true);
  separate(dirname(outputPath), plan.sourceDir);
  separate(dirname(outputPath), plan.ociDir);
  writeRetained(outputPath, context);
  return context;
}

function retainedPrivacy(plan, context) {
  privateOwned(plan.privacyPath);
  const input = diagnosticJson(plan.privacyPath);
  need(
    input.sha256 === plan.privacySha256 &&
      input.value.sourceSha === context.sourceSha &&
      input.value.toolingSha === plan.inspectionToolingSha &&
      input.value.indexDigest === context.indexDigest &&
      [input.value.imageDigest, input.value.configDigest].every(
        (value) => typeof value === "string" && DIGEST.test(value),
      ),
    "retained.privacy_changed",
  );
  return input.value;
}

function qualifiedMemberReportHash(scan) {
  // This hash names the qualification subreports; the separate privacy hash
  // binds their original serialized bytes and the full traversal evidence.
  return Object.hasOwn(scan, "publicMemberQualification")
    ? createHash("sha256")
        .update(
          JSON.stringify({
            comparisons: scan.publicMemberComparisons,
            qualification: scan.publicMemberQualification,
          }),
        )
        .digest("hex")
    : null;
}

function requireRetainedCleanPrivacy(plan, context) {
  const output = execFileSync(
    "python3",
    [
      fileURLToPath(new URL("hosted_export.py", import.meta.url)),
      "check-privacy",
      "--privacy",
      plan.privacyPath,
      "--sha256",
      plan.privacySha256,
      "--source-sha",
      context.sourceSha,
      "--tooling-sha",
      plan.inspectionToolingSha,
      "--index-digest",
      context.indexDigest,
      "--oci",
      plan.ociDir,
    ],
    { encoding: "utf8", stdio: "pipe", timeout: 600_000, maxBuffer: 64 * 1024 },
  );
  const proof = JSON.parse(output);
  need(
    proof.status === "passed" &&
      proof.privacyReceiptSha256 === plan.privacySha256 &&
      HEX.test(proof.ociClosureSha256),
    "retained.privacy_closure_refused",
  );
  return proof.ociClosureSha256;
}

function resourceRecord(
  plan,
  context,
  evidence = { path: plan.resourceAdmissionPath, sha256: plan.resourceAdmissionSha256 },
) {
  privateOwned(evidence.path);
  const input = diagnosticJson(evidence.path),
    value = input.value;
  need(
    input.sha256 === evidence.sha256 &&
      value &&
      typeof value === "object" &&
      Object.keys(value).toSorted().join(",") ===
        [
          "schema",
          "sourceSha",
          "indexDigest",
          "inspectionToolingSha",
          "checkedAt",
          "expiresAt",
          "status",
          "checks",
        ]
          .toSorted()
          .join(",") &&
      value.schema === "openclaw.fork-release-reinspection-resource-admission.v1" &&
      value.status === "passed" &&
      value.sourceSha === context.sourceSha &&
      value.indexDigest === context.indexDigest &&
      value.inspectionToolingSha === plan.inspectionToolingSha &&
      same(value.checks, { capacity: "passed", ownership: "passed", heavyWorkload: "clear" }) &&
      canonicalUtc(value.checkedAt) &&
      canonicalUtc(value.expiresAt) &&
      Date.parse(value.expiresAt) - Date.parse(value.checkedAt) > 0 &&
      Date.parse(value.expiresAt) - Date.parse(value.checkedAt) <= 300_000,
    "retained.resource_admission_refused",
  );
  return input;
}

function resourceAdmission(plan, context, at = nowUtc(), evidence) {
  const { value } = resourceRecord(plan, context, evidence);
  need(
    canonicalUtc(at) && value.checkedAt <= at && at <= value.expiresAt,
    "retained.resource_admission_refused",
  );
  return at;
}

const RESOURCE_BOUNDARIES = ["import", "workspace", "plugins"];
const resourceEvidenceHash = (checks, refreshes) =>
  createHash("sha256").update(JSON.stringify({ checks, refreshes })).digest("hex");
const refreshPaths = (directory, sequence) => {
  const root = join(directory, "resource-refresh"),
    prefix = String(sequence).padStart(2, "0");
  return {
    root,
    request: join(root, `${prefix}-request.json`),
    response: join(root, `${prefix}-response.json`),
    admission: join(root, `${prefix}-admission.json`),
  };
};

function readResourceRefresh(plan, context, directory, qualificationId, entry) {
  need(
    closedFields(entry, [
      "sequence",
      "requestSha256",
      "responseSha256",
      "resourceAdmissionSha256",
    ]) &&
      Number.isSafeInteger(entry.sequence) &&
      entry.sequence >= 1 &&
      entry.sequence <= 3 &&
      [entry.requestSha256, entry.responseSha256, entry.resourceAdmissionSha256].every((value) =>
        HEX.test(value),
      ),
    "retained.resource_refresh_refused",
  );
  const paths = refreshPaths(directory, entry.sequence);
  privateOwned(paths.root, true);
  privateOwned(paths.request);
  privateOwned(paths.response);
  const request = diagnosticJson(paths.request),
    response = diagnosticJson(paths.response);
  need(
    request.sha256 === entry.requestSha256 &&
      response.sha256 === entry.responseSha256 &&
      closedFields(request.value, [
        "schema",
        "qualificationId",
        "originalOperationId",
        "nonce",
        "boundary",
        "sourceSha",
        "indexDigest",
        "inspectionToolingSha",
        "requestedAt",
      ]) &&
      request.value.schema === "openclaw.retained-resource-request.v1" &&
      request.value.qualificationId === qualificationId &&
      request.value.originalOperationId === context.producer.operationId &&
      /^[0-9a-f]{32}$/u.test(request.value.nonce) &&
      RESOURCE_BOUNDARIES.includes(request.value.boundary) &&
      request.value.sourceSha === context.sourceSha &&
      request.value.indexDigest === context.indexDigest &&
      request.value.inspectionToolingSha === plan.inspectionToolingSha &&
      canonicalUtc(request.value.requestedAt) &&
      closedFields(response.value, [
        "schema",
        "qualificationId",
        "nonce",
        "requestSha256",
        "resourceAdmissionSha256",
      ]) &&
      response.value.schema === "openclaw.retained-resource-response.v1" &&
      response.value.qualificationId === qualificationId &&
      response.value.nonce === request.value.nonce &&
      response.value.requestSha256 === request.sha256 &&
      response.value.resourceAdmissionSha256 === entry.resourceAdmissionSha256,
    "retained.resource_refresh_refused",
  );
  const evidence = { path: paths.admission, sha256: entry.resourceAdmissionSha256 };
  const resource = resourceRecord(plan, context, evidence);
  need(resource.value.checkedAt >= request.value.requestedAt, "retained.resource_refresh_refused");
  return { request: request.value, evidence };
}

function freshResourceBoundary(session, boundary) {
  const { plan, context, directory, qualificationId } = session;
  need(RESOURCE_BOUNDARIES[session.checks.length] === boundary, "retained.resource_order_refused");
  let at = nowUtc(),
    record = resourceRecord(plan, context, session.current);
  need(record.value.checkedAt <= at, "retained.resource_admission_refused");
  if (record.value.expiresAt < at) {
    const sequence = session.refreshes.length + 1,
      paths = refreshPaths(directory, sequence);
    if (sequence === 1) mkdirSync(paths.root, { mode: 0o700 });
    privateOwned(paths.root, true);
    const request = {
      schema: "openclaw.retained-resource-request.v1",
      qualificationId,
      originalOperationId: context.producer.operationId,
      nonce: randomBytes(16).toString("hex"),
      boundary,
      sourceSha: context.sourceSha,
      indexDigest: context.indexDigest,
      inspectionToolingSha: plan.inspectionToolingSha,
      requestedAt: at,
    };
    writeRetained(paths.request, request);
    const requestSha256 = hash(paths.request);
    const deadline = performance.now() + 60_000,
      pause = new Int32Array(new SharedArrayBuffer(4));
    while (!lstatMaybe(paths.response) && performance.now() < deadline) {
      Atomics.wait(pause, 0, 0, Math.min(250, Math.max(0, deadline - performance.now())));
    }
    need(
      lstatMaybe(paths.response) && performance.now() <= deadline,
      "retained.resource_refresh_timeout",
    );
    privateOwned(paths.response);
    const response = diagnosticJson(paths.response);
    const entry = {
      sequence,
      requestSha256,
      responseSha256: response.sha256,
      resourceAdmissionSha256: response.value.resourceAdmissionSha256,
    };
    const refreshed = readResourceRefresh(plan, context, directory, qualificationId, entry);
    at = nowUtc();
    resourceAdmission(plan, context, at, refreshed.evidence);
    session.current = refreshed.evidence;
    session.refreshes.push(entry);
  } else {
    resourceAdmission(plan, context, at, session.current);
  }
  session.checks.push({
    boundary,
    checkedAt: at,
    resourceAdmissionSha256: session.current.sha256,
    refreshSequence: session.refreshes.length,
  });
}

function verifyResourceHistory(plan, context, directory, admission) {
  need(
    /^[0-9a-f]{32}$/u.test(admission.qualificationId) &&
      Array.isArray(admission.resourceRefreshes) &&
      admission.resourceRefreshes.length <= 3 &&
      Array.isArray(admission.resourceChecks) &&
      admission.resourceChecks.length === 3,
    "retained.resource_history_refused",
  );
  resourceRecord(plan, context);
  const refreshes = admission.resourceRefreshes.map((entry, index) => {
    need(entry.sequence === index + 1, "retained.resource_history_refused");
    return readResourceRefresh(plan, context, directory, admission.qualificationId, entry);
  });
  need(
    new Set(refreshes.map((entry) => entry.request.nonce)).size === refreshes.length,
    "retained.resource_history_refused",
  );
  let previousSequence = 0;
  const used = new Set();
  admission.resourceChecks.forEach((check, index) => {
    need(
      closedFields(check, [
        "boundary",
        "checkedAt",
        "resourceAdmissionSha256",
        "refreshSequence",
      ]) &&
        check.boundary === RESOURCE_BOUNDARIES[index] &&
        canonicalUtc(check.checkedAt) &&
        admission.startedAt <= check.checkedAt &&
        check.checkedAt <= admission.completedAt &&
        (index === 0 || admission.resourceChecks[index - 1].checkedAt <= check.checkedAt) &&
        Number.isSafeInteger(check.refreshSequence) &&
        check.refreshSequence >= previousSequence &&
        check.refreshSequence <= previousSequence + 1 &&
        check.refreshSequence <= refreshes.length,
      "retained.resource_history_refused",
    );
    const refreshed = check.refreshSequence === 0 ? null : refreshes[check.refreshSequence - 1];
    const evidence = refreshed?.evidence ?? {
      path: plan.resourceAdmissionPath,
      sha256: plan.resourceAdmissionSha256,
    };
    if (refreshed) {
      need(
        admission.startedAt <= refreshed.request.requestedAt &&
          refreshed.request.requestedAt <= check.checkedAt,
        "retained.resource_history_refused",
      );
      if (!used.has(check.refreshSequence))
        need(refreshed.request.boundary === check.boundary, "retained.resource_history_refused");
      used.add(check.refreshSequence);
    }
    need(check.resourceAdmissionSha256 === evidence.sha256, "retained.resource_history_refused");
    resourceAdmission(plan, context, check.checkedAt, evidence);
    previousSequence = check.refreshSequence;
  });
  need(used.size === refreshes.length, "retained.resource_history_refused");
}

function originalResources(plan) {
  privateOwned(plan.originalResourcesPath);
  need(
    diagnosticJson(plan.originalResourcesPath).sha256 === plan.originalResourcesSha256,
    "retained.original_resources_changed",
  );
}

function nativeRetainedCheck({
  manifest,
  context,
  origin,
  runtimeExpected,
  codexVersion,
  plan,
  resources,
}) {
  const smoke = smokeDockerReleaseImage(
    plan.ociDir,
    context.architecture,
    "default",
    origin.configDigest,
    {
      isolation: "secretless",
      beforeNative: () => freshResourceBoundary(resources, "workspace"),
    },
  );
  return inspectLoadedPlugins(
    manifest,
    context.version,
    smoke.imageReference,
    codexVersion,
    runtimeExpected,
    () => freshResourceBoundary(resources, "plugins"),
  );
}

function validateRetainedRuntime(native, expected, manifest, codexVersion) {
  validateImageRuntimeProof(native.runtimeQualification, expected);
  const plugins = native.pluginPayload;
  need(
    native.selectedExtensions === manifest.image.extensions &&
      native.bundledCodexVersion === codexVersion &&
      Array.isArray(plugins) &&
      plugins.map((entry) => entry.id).join(",") === manifest.image.extensions &&
      plugins.every(
        (entry) => entry.package === `@openclaw/${entry.id}` && entry.version === native.version,
      ) &&
      ["sourceSha", "imageDigest", "configDigest"].every(
        (key) => native.runtimeQualification[key] === native[key],
      ),
    "retained.native_proof_refused",
  );
  const codex = plugins.find((entry) => entry.id === "codex")?.codexRuntime;
  const workboard = plugins.find((entry) => entry.id === "workboard")?.workboardRuntime;
  need(
    codex &&
      [codex.cliVersion, codex.packageVersion, codex.initializeVersion].every(
        (value) => value === native.bundledCodexVersion,
      ) &&
      codex.initialized === true &&
      codex.shutdown === "exited" &&
      (!manifest.image.extensions.split(",").includes("workboard") ||
        (workboard?.worker === "sqlite" &&
          workboard.roundTrip === true &&
          workboard.closed === true)),
    "retained.native_proof_refused",
  );
}

export async function qualifyRetainedGcp(planPath, outputDir) {
  let phase = "retained.input_refused",
    outputReady = false;
  const diagnostics = {
    schema: "openclaw.retained-gcp-diagnostics.v1",
    status: "failed",
    qualified: false,
    productionAuthorized: false,
    privacy: "blocked",
    static: "blocked",
    native: "blocked",
    reason: phase,
  };
  try {
    const plan = retainedPlan(planPath, true);
    privateOwned(outputDir, true);
    separate(outputDir, plan.sourceDir);
    separate(outputDir, plan.ociDir);
    need(outputDir !== dirname(plan.executionPath), "retained.output_overlaps_build");
    need(!lstatMaybe(join(outputDir, "native-attempt.json")), "retained.native_attempt_uncertain");
    need(readdirSync(outputDir).length === 0, "retained.output_not_empty");
    const planSha256 = diagnosticJson(planPath).sha256;
    outputReady = true;
    phase = "retained.execution_refused";
    const { manifest, context } = authenticatedRetainedContext(plan);
    originalResources(plan);
    phase = "retained.privacy_refused";
    const scan = retainedPrivacy(plan, context);
    const origin = {
      schema: "openclaw.fork-release-build-origin.v1",
      ...Object.fromEntries(
        [
          "repository",
          "sourceSha",
          "sourceTree",
          "manifestSha256",
          "inventorySha256",
          "architecture",
          "version",
          "builtAt",
          "indexDigest",
          "producer",
        ].map((key) => [key, context[key]]),
      ),
      imageDigest: scan.imageDigest,
      configDigest: scan.configDigest,
    };
    const originPath = join(outputDir, "origin.json");
    writeRetained(originPath, origin);
    const performedAt = nowUtc();
    const staticReport = await inspectLayoutStatic({
      manifestPath: plan.manifestPath,
      inventoryPath: plan.inventoryPath,
      sourceDir: plan.sourceDir,
      ociDir: plan.ociDir,
      originalBuildPath: originPath,
      privacyPath: plan.privacyPath,
      inspectionToolingSha: plan.inspectionToolingSha,
      performedAt,
    });
    writeRetained(join(outputDir, "static.json"), staticReport);
    diagnostics.static = staticReport.status;
    let ociClosureSha256;
    try {
      ociClosureSha256 = requireRetainedCleanPrivacy(plan, context);
      diagnostics.privacy = "passed";
    } catch {
      diagnostics.privacy = "failed";
    }
    need(
      diagnostics.privacy === "passed" && staticReport.status === "passed",
      "retained.qualification_blocked",
    );
    phase = "retained.native_refused";
    const startedAt = nowUtc(),
      qualificationId = randomBytes(16).toString("hex");
    const resources = {
      plan,
      context,
      directory: outputDir,
      qualificationId,
      current: { path: plan.resourceAdmissionPath, sha256: plan.resourceAdmissionSha256 },
      checks: [],
      refreshes: [],
    };
    freshResourceBoundary(resources, "import");
    const runtimeExpected = readRuntimeExpectations(plan.sourceDir);
    const codexVersion = diagnosticJson(join(plan.sourceDir, "extensions/codex/package.json")).value
      .dependencies?.["@openai/codex"];
    need(/^\d+\.\d+\.\d+$/u.test(codexVersion), "retained.native_source_refused");
    writeRetained(join(outputDir, "native-attempt.json"), {
      schema: "openclaw.retained-native-attempt.v1",
      sourceSha: context.sourceSha,
      indexDigest: context.indexDigest,
      inspectionToolingSha: plan.inspectionToolingSha,
      qualificationId,
      startedAt,
    });
    diagnostics.native = "failed";
    const inspected = nativeRetainedCheck({
      manifest,
      context,
      origin,
      runtimeExpected,
      codexVersion,
      plan,
      resources,
    });
    const completedAt = nowUtc();
    const native = {
      schema: "openclaw.fork-release-image.v2",
      ...Object.fromEntries(
        [
          "manifestSha256",
          "inventorySha256",
          "repository",
          "sourceSha",
          "sourceTree",
          "architecture",
          "version",
          "builtAt",
          "indexDigest",
          "producer",
        ].map((key) => [key, context[key]]),
      ),
      selectedExtensions: manifest.image.extensions,
      bundledCodexVersion: codexVersion,
      artifactName: producerArtifactName(context.sourceSha, context.producer),
      ...(manifest.review ? { review: { ...manifest.review, headSha: context.sourceSha } } : {}),
      pluginPayload: inspected.plugins,
      runtimeQualification: {
        ...inspected.runtime,
        sourceSha: context.sourceSha,
        imageDigest: origin.imageDigest,
        configDigest: origin.configDigest,
      },
      imageDigest: origin.imageDigest,
      configDigest: origin.configDigest,
    };
    validateRetainedRuntime(native, runtimeExpected, manifest, codexVersion);
    authenticatedRetainedContext(plan);
    originalResources(plan);
    retainedPrivacy(plan, context);
    verifyResourceHistory(plan, context, outputDir, {
      qualificationId,
      resourceChecks: resources.checks,
      resourceRefreshes: resources.refreshes,
      startedAt,
      completedAt,
    });
    need(diagnosticJson(planPath).sha256 === planSha256, "retained.plan_changed");
    // Intermediate native facts are deliberately not a consumable image seal.
    writeRetained(join(outputDir, "native.json"), {
      schema: "openclaw.retained-native-facts.v1",
      promotable: false,
      productionAuthorized: false,
      imageReceipt: native,
    });
    const capture = {
      schema: "openclaw.fork-release-native-execution.v1",
      status: "passed",
      nativeExecuted: true,
      ...Object.fromEntries(
        ["sourceSha", "sourceTree", "indexDigest", "imageDigest", "configDigest"].map((key) => [
          key,
          origin[key],
        ]),
      ),
      originalBuildSha256: hash(originPath),
      nativeReceiptSha256: hash(join(outputDir, "native.json")),
      verifierToolingSha: plan.inspectionToolingSha,
      qualificationId,
      resourceAdmissionSha256: resources.current.sha256,
      resourceEvidenceSha256: resourceEvidenceHash(resources.checks, resources.refreshes),
      performedAt: completedAt,
    };
    writeRetained(join(outputDir, "native-execution.json"), capture);
    const admission = {
      schema: "openclaw.retained-gcp-admission.v1",
      status: "passed",
      productionAuthorized: false,
      originalExecutionSha256: plan.executionSha256,
      originalToolingSha: plan.originalToolingSha,
      inspectionToolingSha: plan.inspectionToolingSha,
      originalResourcesSha256: plan.originalResourcesSha256,
      resourceAdmissionSha256: plan.resourceAdmissionSha256,
      qualificationId,
      resourceChecks: resources.checks,
      resourceRefreshes: resources.refreshes,
      startedAt,
      completedAt,
      nativeAttemptSha256: hash(join(outputDir, "native-attempt.json")),
      originSha256: hash(originPath),
      privacySha256: plan.privacySha256,
      staticSha256: hash(join(outputDir, "static.json")),
      qualifiedMemberReportSha256: qualifiedMemberReportHash(scan),
      ociClosureSha256,
      nativeReceiptSha256: capture.nativeReceiptSha256,
      nativeExecutionSha256: hash(join(outputDir, "native-execution.json")),
    };
    const admissionSha256 = createHash("sha256")
      .update(`${JSON.stringify(admission, null, 2)}\n`)
      .digest("hex");
    const receipt = {
      ...native,
      reinspection: {
        schema: "openclaw.retained-gcp-qualification.v1",
        originalExecutionSha256: plan.executionSha256,
        originalToolingSha: plan.originalToolingSha,
        inspectionToolingSha: plan.inspectionToolingSha,
        originSha256: admission.originSha256,
        privacySha256: admission.privacySha256,
        staticSha256: admission.staticSha256,
        qualifiedMemberReportSha256: admission.qualifiedMemberReportSha256,
        ociClosureSha256: admission.ociClosureSha256,
        nativeReceiptSha256: admission.nativeReceiptSha256,
        nativeExecutionSha256: admission.nativeExecutionSha256,
        admissionSha256,
        performedAt: completedAt,
      },
    };
    // Publish the consumable image receipt only after the complete admission is
    // durable. An interrupted admission without a final receipt is incomplete.
    writeRetained(join(outputDir, "admission.json"), admission);
    writeRetained(join(outputDir, "receipt.json"), receipt);
    diagnostics.status = "passed";
    diagnostics.qualified = true;
    diagnostics.native = "passed";
    diagnostics.reason = null;
  } catch {
    diagnostics.reason = phase;
  }
  if (outputReady) {
    try {
      writeRetained(join(outputDir, "diagnostics.json"), diagnostics);
    } catch {
      diagnostics.status = "failed";
      diagnostics.qualified = false;
      diagnostics.reason = "retained.output_uncertain";
    }
  }
  return diagnostics;
}

function lstatMaybe(path) {
  try {
    return lstatSync(path);
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
}

export async function verifyRetainedGcp(planPath, receiptPath) {
  const plan = retainedPlan(planPath, true),
    { manifest, context } = authenticatedRetainedContext(plan);
  originalResources(plan);
  const scan = retainedPrivacy(plan, context);
  const ociClosureSha256 = requireRetainedCleanPrivacy(plan, context);
  privateOwned(dirname(receiptPath), true);
  privateOwned(receiptPath);
  const receipt = diagnosticJson(receiptPath).value;
  const directory = dirname(receiptPath),
    proof = receipt.reinspection;
  need(
    proof &&
      proof.schema === "openclaw.retained-gcp-qualification.v1" &&
      Object.keys(proof).toSorted().join(",") ===
        [
          "schema",
          "originalExecutionSha256",
          "originalToolingSha",
          "inspectionToolingSha",
          "originSha256",
          "privacySha256",
          "staticSha256",
          "nativeReceiptSha256",
          "nativeExecutionSha256",
          "qualifiedMemberReportSha256",
          "ociClosureSha256",
          "admissionSha256",
          "performedAt",
        ]
          .toSorted()
          .join(",") &&
      proof.originalExecutionSha256 === plan.executionSha256 &&
      proof.originalToolingSha === plan.originalToolingSha &&
      proof.inspectionToolingSha === plan.inspectionToolingSha &&
      proof.privacySha256 === plan.privacySha256 &&
      proof.ociClosureSha256 === ociClosureSha256 &&
      proof.qualifiedMemberReportSha256 === qualifiedMemberReportHash(scan),
    "retained.admission_refused",
  );
  for (const [name, key] of [
    ["origin.json", "originSha256"],
    ["static.json", "staticSha256"],
    ["native.json", "nativeReceiptSha256"],
    ["native-execution.json", "nativeExecutionSha256"],
    ["admission.json", "admissionSha256"],
  ]) {
    privateOwned(join(directory, name));
    need(hash(join(directory, name)) === proof[key], "retained.report_changed");
  }
  const origin = diagnosticJson(join(directory, "origin.json")).value,
    staticReport = diagnosticJson(join(directory, "static.json")).value,
    facts = diagnosticJson(join(directory, "native.json")).value,
    capture = diagnosticJson(join(directory, "native-execution.json")).value,
    admission = diagnosticJson(join(directory, "admission.json")).value;
  need(
    closedFields(facts, ["schema", "promotable", "productionAuthorized", "imageReceipt"]) &&
      facts.schema === "openclaw.retained-native-facts.v1" &&
      facts.promotable === false &&
      facts.productionAuthorized === false,
    "retained.native_facts_changed",
  );
  const native = facts.imageReceipt;
  const without = { ...receipt };
  delete without.reinspection;
  need(same(without, native), "retained.native_changed");
  need(
    closedFields(origin, [
      "schema",
      "repository",
      "sourceSha",
      "sourceTree",
      "manifestSha256",
      "inventorySha256",
      "architecture",
      "version",
      "builtAt",
      "indexDigest",
      "producer",
      "imageDigest",
      "configDigest",
    ]) &&
      origin.schema === "openclaw.fork-release-build-origin.v1" &&
      same(origin.producer, context.producer),
    "retained.origin_changed",
  );
  need(
    receipt.schema === "openclaw.fork-release-image.v2" &&
      receipt.producer.kind === "gcp" &&
      same(receipt.producer, context.producer) &&
      [
        "repository",
        "sourceSha",
        "sourceTree",
        "manifestSha256",
        "inventorySha256",
        "indexDigest",
        "builtAt",
        "version",
        "architecture",
      ].every((key) => receipt[key] === context[key]) &&
      receipt.imageDigest === scan.imageDigest &&
      receipt.configDigest === scan.configDigest &&
      receipt.artifactName === producerArtifactName(context.sourceSha, context.producer),
    "retained.identity_changed",
  );
  need(
    !manifest.review || same(receipt.review, { ...manifest.review, headSha: context.sourceSha }),
    "retained.review_changed",
  );
  need(
    staticReport.status === "passed" &&
      staticReport.staticOnly === true &&
      staticReport.nativeExecuted === false &&
      staticReport.originalBuildSha256 === proof.originSha256 &&
      staticReport.privacyReceiptSha256 === plan.privacySha256 &&
      staticReport.inspectionToolingSha === plan.inspectionToolingSha &&
      staticReport.schema === "openclaw.fork-release-static.v1" &&
      staticReport.promotable === false &&
      staticReport.productionAuthorized === false &&
      staticReport.reason === null &&
      [
        "sourceSha",
        "sourceTree",
        "manifestSha256",
        "inventorySha256",
        "indexDigest",
        "imageDigest",
        "configDigest",
        "builtAt",
      ].every((key) => staticReport[key] === receipt[key] && origin[key] === receipt[key]),
    "retained.static_changed",
  );
  need(
    closedFields(admission, [
      "schema",
      "status",
      "productionAuthorized",
      "originalExecutionSha256",
      "originalToolingSha",
      "inspectionToolingSha",
      "originalResourcesSha256",
      "resourceAdmissionSha256",
      "qualificationId",
      "resourceChecks",
      "resourceRefreshes",
      "startedAt",
      "completedAt",
      "nativeAttemptSha256",
      "originSha256",
      "privacySha256",
      "staticSha256",
      "qualifiedMemberReportSha256",
      "ociClosureSha256",
      "nativeReceiptSha256",
      "nativeExecutionSha256",
    ]) &&
      admission.schema === "openclaw.retained-gcp-admission.v1" &&
      admission.status === "passed" &&
      admission.productionAuthorized === false &&
      admission.originalExecutionSha256 === plan.executionSha256 &&
      admission.originalToolingSha === plan.originalToolingSha &&
      admission.inspectionToolingSha === plan.inspectionToolingSha &&
      admission.originalResourcesSha256 === plan.originalResourcesSha256 &&
      admission.resourceAdmissionSha256 === plan.resourceAdmissionSha256 &&
      admission.qualifiedMemberReportSha256 === proof.qualifiedMemberReportSha256 &&
      admission.ociClosureSha256 === proof.ociClosureSha256 &&
      [
        "originSha256",
        "privacySha256",
        "staticSha256",
        "nativeReceiptSha256",
        "nativeExecutionSha256",
      ].every((key) => admission[key] === proof[key]) &&
      canonicalUtc(admission.startedAt) &&
      canonicalUtc(admission.completedAt) &&
      admission.startedAt <= admission.completedAt &&
      admission.completedAt <= nowUtc() &&
      canonicalUtc(staticReport.performedAt) &&
      staticReport.performedAt <= admission.startedAt &&
      admission.completedAt === proof.performedAt &&
      Array.isArray(admission.resourceChecks) &&
      admission.resourceChecks.length === 3,
    "retained.admission_changed",
  );
  verifyResourceHistory(plan, context, directory, admission);
  privateOwned(join(directory, "native-attempt.json"));
  const attempt = diagnosticJson(join(directory, "native-attempt.json"));
  need(
    closedFields(attempt.value, [
      "schema",
      "sourceSha",
      "indexDigest",
      "inspectionToolingSha",
      "qualificationId",
      "startedAt",
    ]) &&
      attempt.sha256 === admission.nativeAttemptSha256 &&
      attempt.value.schema === "openclaw.retained-native-attempt.v1" &&
      attempt.value.sourceSha === context.sourceSha &&
      attempt.value.indexDigest === context.indexDigest &&
      attempt.value.inspectionToolingSha === plan.inspectionToolingSha &&
      attempt.value.qualificationId === admission.qualificationId &&
      attempt.value.startedAt === admission.startedAt,
    "retained.native_attempt_changed",
  );
  need(
    closedFields(capture, [
      "schema",
      "status",
      "nativeExecuted",
      "sourceSha",
      "sourceTree",
      "indexDigest",
      "imageDigest",
      "configDigest",
      "originalBuildSha256",
      "nativeReceiptSha256",
      "verifierToolingSha",
      "qualificationId",
      "resourceAdmissionSha256",
      "resourceEvidenceSha256",
      "performedAt",
    ]) &&
      capture.schema === "openclaw.fork-release-native-execution.v1" &&
      capture.status === "passed" &&
      capture.nativeExecuted === true &&
      capture.originalBuildSha256 === proof.originSha256 &&
      capture.nativeReceiptSha256 === proof.nativeReceiptSha256 &&
      capture.verifierToolingSha === plan.inspectionToolingSha &&
      capture.qualificationId === admission.qualificationId &&
      capture.resourceAdmissionSha256 === admission.resourceChecks.at(-1).resourceAdmissionSha256 &&
      capture.resourceEvidenceSha256 ===
        resourceEvidenceHash(admission.resourceChecks, admission.resourceRefreshes) &&
      capture.performedAt === proof.performedAt &&
      ["sourceSha", "sourceTree", "indexDigest", "imageDigest", "configDigest"].every(
        (key) => capture[key] === receipt[key] && origin[key] === receipt[key],
      ),
    "retained.native_capture_changed",
  );
  const codexVersion = diagnosticJson(join(plan.sourceDir, "extensions/codex/package.json")).value
    .dependencies?.["@openai/codex"];
  validateRetainedRuntime(native, readRuntimeExpectations(plan.sourceDir), manifest, codexVersion);
  const image = await verifyImageLayout({ manifest, receipt, ociDir: plan.ociDir });
  need(
    image.imageDigest === receipt.imageDigest && image.configDigest === receipt.configDigest,
    "retained.image_changed",
  );
  return {
    schema: "openclaw.retained-gcp-verification.v1",
    status: "passed",
    sourceSha: receipt.sourceSha,
    indexDigest: receipt.indexDigest,
    imageDigest: receipt.imageDigest,
    configDigest: receipt.configDigest,
    imageReceiptSha256: hash(receiptPath),
    ociClosureSha256,
    originalToolingSha: plan.originalToolingSha,
    inspectionToolingSha: plan.inspectionToolingSha,
    productionAuthorized: false,
  };
}

async function main() {
  if (
    ["capture-retained-gcp-origin", "qualify-retained-gcp", "verify-retained-gcp"].includes(
      process.argv[2],
    )
  ) {
    let report;
    try {
      need(process.argv.length === 5, "retained.arguments_refused");
      report =
        process.argv[2] === "capture-retained-gcp-origin"
          ? captureRetainedGcpOrigin(process.argv[3], process.argv[4])
          : await (process.argv[2] === "qualify-retained-gcp"
              ? qualifyRetainedGcp(process.argv[3], process.argv[4])
              : verifyRetainedGcp(process.argv[3], process.argv[4]));
    } catch {
      report = {
        schema: "openclaw.retained-gcp-diagnostics.v1",
        status: "failed",
        qualified: false,
        productionAuthorized: false,
        reason: "retained.input_refused",
      };
    }
    console.log(JSON.stringify(report));
    process.exitCode = ["passed", "captured"].includes(report.status) ? 0 : 1;
    return;
  }

  if (process.argv[2] === "inspect-layout") {
    const args = process.argv.slice(3);
    let report;
    if (args.length === 9) {
      const [
        manifestPath,
        inventoryPath,
        sourceDir,
        ociDir,
        originalBuildPath,
        privacyPath,
        inspectionToolingSha,
        performedAt,
      ] = args;
      report = await inspectLayoutStatic({
        manifestPath,
        inventoryPath,
        sourceDir,
        ociDir,
        originalBuildPath,
        privacyPath,
        inspectionToolingSha,
        performedAt,
      });
      try {
        writeFileSync(args[8], `${JSON.stringify(report, null, 2)}\n`, { flag: "wx", mode: 0o600 });
      } catch {
        report = { ...report, status: "failed", reason: "static.output_unavailable" };
      }
    } else {
      report = {
        schema: "openclaw.fork-release-static.v1",
        status: "blocked",
        staticOnly: true,
        nativeExecuted: false,
        productionAuthorized: false,
        promotable: false,
        reason: "static.arguments_refused",
      };
    }
    console.log(JSON.stringify(report));
    process.exitCode = report.status === "passed" ? 0 : 1;
    return;
  }
  const [
    command,
    manifestPath,
    inventoryPath,
    third,
    fourth,
    fifth,
    sixth,
    executionPath,
    smokeTransport,
  ] = process.argv.slice(2);
  need(
    ["seal", "seal-gcp", "verify"].includes(command),
    "Usage: image.mjs seal MANIFEST INVENTORY SOURCE OCI DIGEST OUTPUT | seal-gcp MANIFEST INVENTORY SOURCE OCI DIGEST OUTPUT PRIVATE_EXECUTION [skopeo|loaded] | verify MANIFEST INVENTORY RECEIPT OCI",
  );
  need(
    smokeTransport === undefined ||
      (command === "seal-gcp" && ["skopeo", "loaded"].includes(smokeTransport)),
    "Invalid explicit smoke transport",
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
      !Object.hasOwn(receipt, "reinspection"),
      "Retained qualification requires verify-retained-gcp",
    );
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
      receipt.selectedExtensions === manifest.image.extensions &&
        Array.isArray(receipt.pluginPayload) &&
        receipt.pluginPayload.map((entry) => entry.id).join(",") === manifest.image.extensions,
      "Image plugin payload evidence changed",
    );
    need(
      receipt.pluginPayload.some(
        (entry) =>
          entry.id === "codex" &&
          entry.package === "@openclaw/codex" &&
          entry.version === receipt.version,
      ),
      "Codex plugin evidence differs from image host",
    );
    const codexRuntime = receipt.pluginPayload.find((entry) => entry.id === "codex")?.codexRuntime;
    need(
      /^\d+\.\d+\.\d+$/u.test(receipt.bundledCodexVersion) &&
        codexRuntime?.cliVersion === receipt.bundledCodexVersion &&
        codexRuntime?.packageVersion === receipt.bundledCodexVersion &&
        codexRuntime?.initializeVersion === receipt.bundledCodexVersion &&
        codexRuntime?.initialized === true &&
        codexRuntime?.shutdown === "exited",
      "Exact bundled Codex runtime evidence missing",
    );
    if (manifest.image.extensions.split(",").includes("workboard")) {
      const workboardRuntime = receipt.pluginPayload.find(
        (entry) => entry.id === "workboard",
      )?.workboardRuntime;
      need(
        workboardRuntime?.worker === "sqlite" &&
          workboardRuntime.roundTrip === true &&
          workboardRuntime.closed === true,
        "Workboard native runtime evidence missing",
      );
    }
    need(
      [receipt.indexDigest, receipt.imageDigest, receipt.configDigest].every((value) =>
        DIGEST.test(value),
      ),
      "Invalid image digest",
    );
    // Original v2/GCP receipts remain readable. Newly sealed hosted exports
    // require this proof at their export gate and cannot strip it to qualify.
    if (Object.hasOwn(receipt, "runtimeQualification")) {
      const proof = receipt.runtimeQualification;
      need(
        proof?.sourceSha === receipt.sourceSha &&
          proof.imageDigest === receipt.imageDigest &&
          proof.configDigest === receipt.configDigest,
        "Runtime proof image/source changed",
      );
      validateImageRuntimeProof(proof);
    }
    validateProducer(receipt.producer);
    need(
      receipt.artifactName === producerArtifactName(receipt.sourceSha, receipt.producer),
      "Image artifact name changed",
    );
    if (manifest.review) {
      need(SHA.test(receipt.review?.headSha), "Image receipt lacks exact PR head");
      for (const key of ["prNumber", "baseSha", "changedDiffSha256"]) {
        need(receipt.review[key] === manifest.review[key], `Image PR ${key} changed`);
      }
      if (receipt.producer.kind === "gcp") {
        need(
          receipt.review.headSha === receipt.sourceSha,
          "GCP image review head differs from source",
        );
      }
    }
    const image = await verifyImageLayout({ manifest, receipt, ociDir: fourth });
    need(image.imageDigest === receipt.imageDigest, "Image manifest digest changed");
    need(image.configDigest === receipt.configDigest, "Image config digest changed");
    console.log(`Verified ${receipt.indexDigest} for ${receipt.sourceSha}`);
    return;
  }
  const [sourceDir, ociDir, expectedDigest, outputPath] = [third, fourth, fifth, sixth];
  assertCleanSourceCheckout(sourceDir);
  execFileSync("python3", [preflightPath, ...preflightArgs, "--source-dir", sourceDir], {
    stdio: "pipe",
  });
  need(DIGEST.test(expectedDigest), "Missing exact BuildKit digest");
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
  let reviewHead;
  if (manifest.review) {
    if (command === "seal-gcp") {
      // GCP preparation binds the source PR directly. Its manifest/inventory can
      // be private external inputs; neither their directory nor tooling HEAD
      // pretends to be a metadata-only child in that PR.
      reviewHead = sourceSha;
      const productDiff = execFileSync("git", [
        "-C",
        sourceDir,
        "diff",
        "--binary",
        "--full-index",
        "--no-ext-diff",
        manifest.review.baseSha,
        sourceSha,
      ]);
      need(
        createHash("sha256").update(productDiff).digest("hex") ===
          manifest.review.changedDiffSha256,
        "GCP image PR diff binding changed",
      );
    } else {
      const metadataRoot = dirname(dirname(dirname(manifestPath)));
      reviewHead = execFileSync("git", ["-C", metadataRoot, "rev-parse", "HEAD"], {
        encoding: "utf8",
      }).trim();
      const parent = execFileSync(
        "git",
        ["-C", metadataRoot, "show", "-s", "--format=%P", "HEAD"],
        {
          encoding: "utf8",
        },
      ).trim();
      need(parent === sourceSha, "PR head is not the metadata seal above the source");
    }
  }
  const version = json(`${sourceDir}/package.json`).version;
  const codexVersion = json(`${sourceDir}/extensions/codex/package.json`).dependencies?.[
    "@openai/codex"
  ];
  need(/^\d+\.\d+\.\d+$/u.test(codexVersion), "Source must pin an exact bundled Codex version");
  const runtimeExpected = command === "seal" ? readRuntimeExpectations(sourceDir) : undefined;
  let producer;
  let builtAt;
  if (command === "seal-gcp") {
    need(executionPath, "Private GCP execution evidence required");
    const trustedRoot = fileURLToPath(new URL("../../", import.meta.url));
    const trustedSha = execFileSync("git", ["-C", trustedRoot, "rev-parse", "HEAD"], {
      encoding: "utf8",
    }).trim();
    need(
      execFileSync("git", ["-C", trustedRoot, "status", "--porcelain"], {
        encoding: "utf8",
      }).trim() === "",
      "GCP sealing requires clean committed tooling",
    );
    ({ producer, builtAt } = readGcpExecution(executionPath, {
      sourceDir,
      sourceSha,
      sourceTree,
      toolingSha: trustedSha,
      manifestSha256: hash(manifestPath),
      inventorySha256: inventoryHash,
      indexDigest: expectedDigest,
    }));
  } else {
    need(process.env.GITHUB_REPOSITORY === manifest.repository, "Wrong producer repository");
    need(
      process.env.GITHUB_SHA === process.env.GITHUB_WORKFLOW_SHA,
      "Workflow source and checkout differ",
    );
    producer = {
      workflowSha: process.env.GITHUB_WORKFLOW_SHA,
      runId: process.env.GITHUB_RUN_ID,
      attempt: process.env.GITHUB_RUN_ATTEMPT,
    };
    validateProducer(producer);
    builtAt = process.env.BUILT_AT;
  }
  const receipt = {
    schema: "openclaw.fork-release-image.v2",
    manifestSha256: hash(manifestPath),
    inventorySha256: inventoryHash,
    repository: manifest.repository,
    sourceSha,
    sourceTree,
    architecture: manifest.image.architecture,
    selectedExtensions: manifest.image.extensions,
    version,
    bundledCodexVersion: codexVersion,
    builtAt,
    indexDigest: expectedDigest,
    producer,
    artifactName: producerArtifactName(sourceSha, producer),
    ...(producer.kind !== "gcp" ? { buildContext: hostedGitBuildContext(manifest) } : {}),
    ...(manifest.review ? { review: { ...manifest.review, headSha: reviewHead } } : {}),
  };
  const image = await verifyImageLayout({ manifest, receipt, ociDir });
  const smoke = smokeDockerReleaseImage(
    ociDir,
    receipt.architecture,
    "default",
    image.configDigest,
    {
      isolation: "secretless",
      transport: smokeTransport,
      ...(smokeTransport === "loaded" ? { loadedIndexDigest: image.indexDigest } : {}),
    },
  );
  const inspected = inspectLoadedPlugins(
    manifest,
    version,
    smoke.imageReference,
    codexVersion,
    runtimeExpected,
  );
  receipt.pluginPayload = producer.kind === "gcp" ? inspected : inspected.plugins;
  if (producer.kind !== "gcp") {
    receipt.runtimeQualification = {
      ...inspected.runtime,
      sourceSha,
      imageDigest: image.imageDigest,
      configDigest: image.configDigest,
    };
  }
  receipt.imageDigest = image.imageDigest;
  receipt.configDigest = image.configDigest;
  writeFileSync(outputPath, `${JSON.stringify(receipt, null, 2)}\n`, { flag: "wx", mode: 0o600 });
  console.log(`Prepared and smoked ${receipt.indexDigest}`);
}

if (isDirectRunUrl(process.argv[1], import.meta.url)) {
  main().catch(
    /** @param {unknown} error */ (error) => {
      console.error(error instanceof Error ? error.message : String(error));
      process.exitCode = 1;
    },
  );
}
