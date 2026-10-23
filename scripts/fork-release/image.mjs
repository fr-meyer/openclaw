#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  mkdtempSync,
  openSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
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

const SHA = /^[0-9a-f]{40}$/u;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;

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
  need(
    typeof manifest.image.extensions === "string" &&
      manifest.image.extensions.split(",").every((id) => /^[a-z0-9][a-z0-9-]*$/u.test(id)),
    "Invalid selected image extensions",
  );
  need(manifest.image.extensions.split(",").includes("codex"), "Image must include Codex plugin");
  return manifest;
}

export function inspectLoadedPlugins(manifest, version, imageReference, codexVersion) {
  need(DIGEST.test(imageReference), "Plugin inspection requires an immutable image digest");
  need(/^\d+\.\d+\.\d+$/u.test(codexVersion), "Missing exact source-pinned Codex version");
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
      ],
      { encoding: "utf8", timeout: 30_000, maxBuffer: 256 * 1024, killSignal: "SIGKILL" },
    ).trim();
    need(/^[0-9a-f]{64}$/u.test(container), "Invalid owned plugin-check container identity");
    try {
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
      return JSON.parse(output);
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
        Object.keys(context).sort().join(",") === "kind,repository,sourceSha" &&
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

async function main() {
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
  receipt.pluginPayload = inspectLoadedPlugins(
    manifest,
    version,
    smoke.imageReference,
    codexVersion,
  );
  receipt.imageDigest = image.imageDigest;
  receipt.configDigest = image.configDigest;
  writeFileSync(outputPath, `${JSON.stringify(receipt, null, 2)}\n`, { flag: "wx", mode: 0o600 });
  console.log(`Prepared and smoked ${receipt.indexDigest}`);
}

if (isDirectRunUrl(process.argv[1], import.meta.url)) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
