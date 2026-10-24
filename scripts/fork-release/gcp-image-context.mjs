import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";

const SHA = /^[0-9a-f]{40}$/u;
const HEX256 = /^[0-9a-f]{64}$/u;
const positive = /^[1-9][0-9]*$/u;
const utc = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u;

function need(value, message) {
  if (!value) {
    throw new Error(message);
  }
}

function hash(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function privateBytes(path) {
  const stat = lstatSync(path);
  need(
    stat.isFile() && stat.uid === process.getuid() && (stat.mode & 0o077) === 0,
    "GCP execution evidence must be an owned private regular file",
  );
  return readFileSync(path);
}

export function assertCleanSourceCheckout(sourceDir) {
  const status = execFileSync(
    "git",
    ["-C", sourceDir, "status", "--porcelain", "--untracked-files=all"],
    { encoding: "utf8" },
  );
  need(status.trim() === "", "Image sealing requires a clean source checkout");
}

export function producerArtifactName(sourceSha, producer) {
  return producer.kind === "gcp"
    ? `fork-release-${sourceSha}-gcp-${producer.operationId}-${producer.attempt}`
    : `fork-release-${sourceSha}-${producer.runId}-${producer.attempt}`;
}

export function validateProducer(producer) {
  need(
    producer && typeof producer === "object" && !Array.isArray(producer),
    "Invalid producer identity",
  );
  const fields =
    producer.kind === "gcp"
      ? ["kind", "toolingSha", "operationId", "attempt", "executionSha256"]
      : ["workflowSha", "runId", "attempt"];
  need(
    Object.keys(producer).toSorted().join(",") === fields.toSorted().join(","),
    "Invalid producer fields",
  );
  need(positive.test(String(producer.attempt)), "Invalid producer attempt");
  if (producer.kind === "gcp") {
    need(
      SHA.test(producer.toolingSha) &&
        /^[0-9a-f]{32}$/u.test(producer.operationId) &&
        HEX256.test(producer.executionSha256),
      "Invalid GCP producer identity",
    );
  } else {
    need(
      SHA.test(producer.workflowSha) && positive.test(String(producer.runId)),
      "Invalid producer identity",
    );
  }
}

// This is a private supervisor attestation, not a cloud identity verifier.
// The supervisor and this evidence directory must be outside candidate mounts;
// candidate-provided JSON never establishes an execution or its authority.
export function readGcpExecution(path, expected) {
  const root = dirname(realpathSync(path));
  const stat = lstatSync(root);
  need(
    stat.isDirectory() && stat.uid === process.getuid() && (stat.mode & 0o077) === 0,
    "GCP execution directory must be owned and private",
  );
  const source = realpathSync(expected.sourceDir);
  for (const [parent, child] of [
    [source, root],
    [root, source],
  ]) {
    const childPath = relative(parent, child);
    need(
      childPath === ".." || childPath.startsWith(`..${sep}`),
      "GCP execution evidence must be outside the candidate tree",
    );
  }
  const raw = privateBytes(path);
  const execution = JSON.parse(raw.toString("utf8"));
  const fields = [
    "schema",
    "operationId",
    "attempt",
    "projectNumber",
    "instanceId",
    "toolingSha",
    "sourceSha",
    "sourceTree",
    "manifestSha256",
    "inventorySha256",
    "indexDigest",
    "builtAt",
    "startedAt",
    "completedAt",
    "buildExitCode",
    "buildMetadataSha256",
    "buildLogSha256",
  ];
  need(
    execution &&
      typeof execution === "object" &&
      !Array.isArray(execution) &&
      Object.keys(execution).toSorted().join(",") === fields.toSorted().join(","),
    "Invalid GCP execution fields",
  );
  need(
    execution.schema === "openclaw.fork-gcp-image-execution.v1" &&
      /^[0-9a-f]{32}$/u.test(execution.operationId) &&
      positive.test(String(execution.attempt)) &&
      typeof execution.projectNumber === "string" &&
      positive.test(execution.projectNumber) &&
      typeof execution.instanceId === "string" &&
      positive.test(execution.instanceId),
    "Invalid GCP execution identity",
  );
  for (const name of [
    "toolingSha",
    "sourceSha",
    "sourceTree",
    "manifestSha256",
    "inventorySha256",
    "indexDigest",
  ]) {
    need(execution[name] === expected[name], `GCP execution ${name} changed`);
  }
  need(
    ["builtAt", "startedAt", "completedAt"].every(
      (key) =>
        utc.test(execution[key]) &&
        Number.isFinite(Date.parse(execution[key])) &&
        new Date(execution[key]).toISOString() === execution[key].replace("Z", ".000Z"),
    ),
    "Invalid GCP execution timestamps",
  );
  need(
    execution.builtAt <= execution.startedAt &&
      execution.startedAt <= execution.completedAt &&
      Date.parse(execution.completedAt) <= Date.now(),
    "GCP execution time order changed",
  );
  need(
    execution.buildExitCode === 0 &&
      privateBytes(join(root, "build.exit")).toString("utf8").trim() === "0",
    "GCP build did not complete successfully",
  );
  const metadataBytes = privateBytes(join(root, "build-metadata.json"));
  need(
    HEX256.test(execution.buildMetadataSha256) &&
      hash(metadataBytes) === execution.buildMetadataSha256 &&
      JSON.parse(metadataBytes.toString("utf8"))["containerimage.digest"] === expected.indexDigest,
    "GCP BuildKit metadata changed",
  );
  need(
    HEX256.test(execution.buildLogSha256) &&
      hash(privateBytes(join(root, "build.log"))) === execution.buildLogSha256,
    "GCP build log changed",
  );
  const producer = {
    kind: "gcp",
    toolingSha: execution.toolingSha,
    operationId: execution.operationId,
    attempt: execution.attempt,
    executionSha256: hash(raw),
  };
  validateProducer(producer);
  return { producer, builtAt: execution.builtAt };
}
