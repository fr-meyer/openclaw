import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { smokeDockerReleaseImage } from "../docker-release-artifacts.mjs";
import {
  assertCleanSourceCheckout,
  readGcpExecution,
  producerArtifactName,
  validateProducer,
} from "./gcp-image-context.mjs";
import { inspectLoadedPlugins } from "./image.mjs";

const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const digest = `sha256:${"a".repeat(64)}`;

test("seal entry refuses dirty tracked and untracked source before reading working metadata", () => {
  const root = mkdtempSync(join(tmpdir(), "fork-image-source-"));
  const source = join(root, "source");
  mkdirSync(source);
  const git = (...args) =>
    execFileSync("git", ["-C", source, ...args], {
      encoding: "utf8",
      env: { ...process.env, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null" },
    });
  const image = fileURLToPath(new URL("./image.mjs", import.meta.url));
  const manifest = fileURLToPath(new URL("./manifest.json", import.meta.url));
  const inventory = fileURLToPath(new URL("./patch-inventory.json", import.meta.url));
  const output = join(root, "must-not-exist.json");
  const packagePath = join(source, "package.json");
  const original = '{"version":"2026.10.5"}\n';
  const refuse = () => {
    const result = spawnSync(
      process.execPath,
      [
        image,
        "seal-gcp",
        manifest,
        inventory,
        source,
        join(root, "missing-oci"),
        digest,
        output,
        join(root, "missing-execution.json"),
      ],
      { encoding: "utf8" },
    );
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Image sealing requires a clean source checkout/u);
    assert.equal(existsSync(output), false);
  };
  try {
    git("init", "-q");
    writeFileSync(packagePath, original);
    git("add", "package.json");
    git(
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.invalid",
      "commit",
      "-qm",
      "synthetic clean image source",
    );
    assertCleanSourceCheckout(source);

    writeFileSync(packagePath, "not even valid package JSON");
    refuse();
    git("add", "package.json");
    refuse();
    writeFileSync(packagePath, original);
    git("add", "package.json");
    assertCleanSourceCheckout(source);

    mkdirSync(join(source, "untracked"));
    writeFileSync(join(source, "untracked", "candidate-input"), "uncommitted source");
    refuse();
  } finally {
    rmSync(root, { recursive: true });
  }
});

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "fork-gcp-image-"));
  const evidence = join(root, "private");
  const sourceDir = join(root, "source");
  mkdirSync(evidence, { mode: 0o700 });
  mkdirSync(sourceDir);
  const expected = {
    sourceDir,
    sourceSha: "b".repeat(40),
    sourceTree: "c".repeat(40),
    toolingSha: "d".repeat(40),
    manifestSha256: "e".repeat(64),
    inventorySha256: "f".repeat(64),
    indexDigest: digest,
  };
  const metadata = JSON.stringify({ "containerimage.digest": digest });
  const log = "synthetic BuildKit completion\n";
  for (const [name, bytes] of [
    ["build-metadata.json", metadata],
    ["build.log", log],
    ["build.exit", "0\n"],
  ])
    writeFileSync(join(evidence, name), bytes, { mode: 0o600 });
  const execution = {
    schema: "openclaw.fork-gcp-image-execution.v1",
    operationId: "1".repeat(32),
    attempt: "1",
    projectNumber: "1234",
    instanceId: "5678",
    ...Object.fromEntries(Object.entries(expected).filter(([key]) => key !== "sourceDir")),
    builtAt: "2020-01-01T00:00:00Z",
    startedAt: "2020-01-01T00:00:01Z",
    completedAt: "2020-01-01T00:00:02Z",
    buildExitCode: 0,
    buildMetadataSha256: hash(metadata),
    buildLogSha256: hash(log),
  };
  const path = join(evidence, "execution.json");
  const save = () => writeFileSync(path, JSON.stringify(execution), { mode: 0o600 });
  save();
  return { root, evidence, expected, execution, path, save };
}

test("GCP seal binds private execution and emits no cloud identifiers", () => {
  const f = fixture();
  try {
    const { producer, builtAt } = readGcpExecution(f.path, f.expected);
    assert.equal(builtAt, f.execution.builtAt);
    assert.equal(producer.executionSha256, hash(readFileSync(f.path)));
    assert.equal(
      producerArtifactName(f.expected.sourceSha, producer),
      `fork-release-${f.expected.sourceSha}-gcp-${f.execution.operationId}-1`,
    );
    assert.deepEqual(Object.keys(producer).sort(), [
      "attempt",
      "executionSha256",
      "kind",
      "operationId",
      "toolingSha",
    ]);
  } finally {
    rmSync(f.root, { recursive: true });
  }
});

test("GCP seal refuses changed bindings, incomplete runs and writable evidence", () => {
  const f = fixture();
  try {
    for (const key of [
      "sourceSha",
      "sourceTree",
      "toolingSha",
      "manifestSha256",
      "inventorySha256",
      "indexDigest",
    ]) {
      assert.throws(
        () => readGcpExecution(f.path, { ...f.expected, [key]: "changed" }),
        new RegExp(`GCP execution ${key} changed`, "u"),
      );
    }
    writeFileSync(join(f.evidence, "build.exit"), "137\n");
    assert.throws(() => readGcpExecution(f.path, f.expected), /did not complete successfully/u);
    writeFileSync(join(f.evidence, "build.exit"), "0\n");
    writeFileSync(join(f.evidence, "build.log"), "changed");
    assert.throws(() => readGcpExecution(f.path, f.expected), /build log changed/u);
    writeFileSync(join(f.evidence, "build.log"), "synthetic BuildKit completion\n");
    chmodSync(f.path, 0o644);
    assert.throws(() => readGcpExecution(f.path, f.expected), /private regular file/u);
    chmodSync(f.path, 0o600);
    assert.throws(
      () => readGcpExecution(f.path, { ...f.expected, sourceDir: f.root }),
      /outside the candidate tree/u,
    );
    f.execution.privateCredentials = "must never be projected";
    f.save();
    assert.throws(() => readGcpExecution(f.path, f.expected), /Invalid GCP execution fields/u);
  } finally {
    rmSync(f.root, { recursive: true });
  }
});

test("producer kinds remain distinct and refuse extra fields", () => {
  const github = { workflowSha: "a".repeat(40), runId: "42", attempt: "1" };
  validateProducer(github);
  assert.equal(producerArtifactName("b".repeat(40), github), `fork-release-${"b".repeat(40)}-42-1`);
  assert.throws(() => validateProducer({ ...github, kind: "gcp" }), /Invalid producer fields/u);
  assert.throws(
    () => validateProducer({ ...github, opaqueMetadata: "private" }),
    /Invalid producer fields/u,
  );
});

test("native smoke retains its flow under bounded no-network Docker execution", () => {
  const root = mkdtempSync(join(tmpdir(), "fork-image-smoke-"));
  const capture = join(root, "calls.jsonl");
  const previous = Object.fromEntries(
    ["PATH", "SMOKE_CAPTURE", "SMOKE_DIGEST", "SMOKE_FAIL_START"].map((key) => [
      key,
      process.env[key],
    ]),
  );
  const fake = `#!${process.execPath}
import { appendFileSync } from "node:fs";
import { basename } from "node:path";
const command = basename(process.argv[1]);
const args = process.argv.slice(2);
appendFileSync(process.env.SMOKE_CAPTURE, JSON.stringify({ command, args }) + "\\n");
if (command === "docker" && args[0] === "image") console.log(process.env.SMOKE_DIGEST);
if (command === "docker" && args[0] === "create") console.log("1".repeat(64));
if (command === "docker" && args[0] === "inspect") console.log("false 0");
if (command === "docker" && args[0] === "start" && process.env.SMOKE_FAIL_START === "1") process.exit(17);
`;
  try {
    for (const command of ["docker", "skopeo"])
      writeFileSync(join(root, command), fake, { mode: 0o700 });
    process.env.PATH = `${root}:${previous.PATH}`;
    process.env.SMOKE_CAPTURE = capture;
    process.env.SMOKE_DIGEST = digest;
    smokeDockerReleaseImage("/synthetic/oci", "amd64", "default", digest, {
      isolation: "secretless",
    });
    const calls = readFileSync(capture, "utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    assert.deepEqual(
      calls.map((call) => call.command),
      ["skopeo", "docker", "docker", "docker", "docker", "docker"],
    );
    const run = calls[2].args;
    assert.equal(run[0], "create");
    assert.ok(run.includes("--read-only"));
    for (const [flag, value] of [
      ["--network", "none"],
      ["--cap-drop", "ALL"],
      ["--security-opt", "no-new-privileges"],
      ["--pids-limit", "128"],
      ["--memory", "2g"],
      ["--cpus", "1"],
      ["--tmpfs", "/tmp:rw,nosuid,nodev,size=536870912"],
    ]) {
      assert.equal(run[run.indexOf(flag) + 1], value);
    }
    assert.equal(run[run.indexOf("--entrypoint") + 2], digest);
    assert.match(run.at(-1), /workspace bootstrap smoke/u);
    assert.match(run.at(-1), /Missing workspace template:/u);
    assert.deepEqual(calls.at(-1).args, ["rm", "--force", "1".repeat(64)]);

    writeFileSync(capture, "");
    smokeDockerReleaseImage("/synthetic/oci", "amd64", "default", digest, {
      isolation: "secretless",
      transport: "loaded",
    });
    const loaded = readFileSync(capture, "utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    assert.equal(
      loaded.some((call) => call.command === "skopeo"),
      false,
    );
    assert.equal(loaded[0].args.at(-1), digest);

    writeFileSync(capture, "");
    process.env.SMOKE_DIGEST = `sha256:${"b".repeat(64)}`;
    assert.throws(
      () =>
        smokeDockerReleaseImage("/synthetic/oci", "amd64", "default", digest, {
          isolation: "secretless",
          transport: "loaded",
        }),
      /does not match the prepared OCI image/u,
    );
    const mismatch = readFileSync(capture, "utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    assert.equal(mismatch.length, 1);
    assert.equal(mismatch[0].args[0], "image");

    process.env.SMOKE_DIGEST = digest;
    process.env.SMOKE_FAIL_START = "1";
    writeFileSync(capture, "");
    assert.throws(() =>
      smokeDockerReleaseImage("/synthetic/oci", "amd64", "default", digest, {
        isolation: "secretless",
        transport: "loaded",
      }),
    );
    const failure = readFileSync(capture, "utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    assert.deepEqual(failure.at(-1).args, ["rm", "--force", "1".repeat(64)]);
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    rmSync(root, { recursive: true });
  }
});

test("loaded index smoke requires an exact digest and the explicit loaded transport", () => {
  for (const options of [
    { loadedIndexDigest: digest },
    { transport: "skopeo", loadedIndexDigest: digest },
    { transport: "loaded", loadedIndexDigest: "openclaw:mutable" },
    { transport: "loaded", loadedIndexDigest: [digest] },
    { transport: "loaded", loadedIndexDigest: null },
  ]) {
    assert.throws(
      () => smokeDockerReleaseImage("/synthetic/oci", "amd64", "default", digest, options),
      /Loaded smoke index requires loaded transport and an exact digest/u,
    );
  }
  assert.throws(
    () =>
      smokeDockerReleaseImage("/synthetic/oci", "unknown", "default", digest, {
        transport: "loaded",
        loadedIndexDigest: digest,
      }),
    /Unsupported loaded smoke platform/u,
  );
});

test("loaded OCI index remains immutable through smoke and platform-pinned plugin inspection", () => {
  const root = mkdtempSync(join(tmpdir(), "fork-index-smoke-"));
  const capture = join(root, "calls.jsonl");
  const indexDigest = `sha256:${"c".repeat(64)}`;
  const previous = Object.fromEntries(
    ["PATH", "SMOKE_CAPTURE", "SMOKE_DIGEST", "SMOKE_FAIL_START"].map((key) => [
      key,
      process.env[key],
    ]),
  );
  const fake = `#!${process.execPath}
import { appendFileSync } from "node:fs";
const args = process.argv.slice(2);
appendFileSync(process.env.SMOKE_CAPTURE, JSON.stringify(args) + "\\n");
if (args[0] === "image") console.log(process.env.SMOKE_DIGEST);
if (args[0] === "create") console.log("2".repeat(64));
if (args[0] === "inspect") console.log("false 0");
if (args[0] === "run" && args.includes("/tmp/verify-image-plugins.mjs")) console.log("[]");
if (args[0] === "start" && process.env.SMOKE_FAIL_START === "1") process.exit(17);
`;
  const calls = () =>
    readFileSync(capture, "utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
  const options = {
    isolation: "secretless",
    transport: "loaded",
    loadedIndexDigest: indexDigest,
  };
  try {
    writeFileSync(join(root, "docker"), fake, { mode: 0o700 });
    process.env.PATH = `${root}:${previous.PATH}`;
    process.env.SMOKE_CAPTURE = capture;
    process.env.SMOKE_DIGEST = indexDigest;
    delete process.env.SMOKE_FAIL_START;
    const smoke = smokeDockerReleaseImage("/synthetic/oci", "amd64", "default", digest, options);
    assert.equal(smoke.imageReference, indexDigest);
    const observed = calls();
    assert.deepEqual(observed[0], ["image", "inspect", "--format", "{{.Id}}", indexDigest]);
    const create = observed[1];
    assert.equal(create[0], "create");
    assert.equal(create[create.indexOf("--platform") + 1], "linux/amd64");
    assert.equal(create[create.indexOf("--entrypoint") + 2], indexDigest);
    assert.equal(create[create.indexOf("--network") + 1], "none");
    assert.ok(create.includes("--read-only"));
    assert.ok(!create.includes(digest));
    assert.deepEqual(observed.at(-1), ["rm", "--force", "2".repeat(64)]);

    assert.deepEqual(
      inspectLoadedPlugins(
        { image: { architecture: "amd64", extensions: "codex,workboard" } },
        "2026.10.5",
        smoke.imageReference,
      ),
      [],
    );
    const plugins = calls().at(-1);
    assert.equal(plugins[0], "run");
    assert.equal(plugins[plugins.indexOf("--platform") + 1], "linux/amd64");
    assert.equal(plugins[plugins.indexOf("--entrypoint") + 2], indexDigest);
    assert.equal(plugins[plugins.indexOf("--network") + 1], "none");
    assert.ok(plugins.includes("--read-only"));
    assert.ok(!plugins.includes(digest));

    writeFileSync(capture, "");
    process.env.SMOKE_DIGEST = digest;
    assert.throws(
      () => smokeDockerReleaseImage("/synthetic/oci", "amd64", "default", digest, options),
      /does not match the prepared OCI image/u,
    );
    assert.deepEqual(calls(), [["image", "inspect", "--format", "{{.Id}}", indexDigest]]);

    writeFileSync(capture, "");
    process.env.SMOKE_DIGEST = indexDigest;
    process.env.SMOKE_FAIL_START = "1";
    assert.throws(() =>
      smokeDockerReleaseImage("/synthetic/oci", "amd64", "default", digest, options),
    );
    assert.deepEqual(calls().at(-1), ["rm", "--force", "2".repeat(64)]);
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    rmSync(root, { recursive: true });
  }
});
