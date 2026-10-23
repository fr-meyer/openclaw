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
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
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

void test("seal entry refuses dirty tracked and untracked source before reading working metadata", () => {
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
  ]) {
    writeFileSync(join(evidence, name), bytes, { mode: 0o600 });
  }
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

void test("GCP seal binds private execution and emits no cloud identifiers", () => {
  const f = fixture();
  try {
    const { producer, builtAt } = readGcpExecution(f.path, f.expected);
    assert.equal(builtAt, f.execution.builtAt);
    assert.equal(producer.executionSha256, hash(readFileSync(f.path)));
    assert.equal(
      producerArtifactName(f.expected.sourceSha, producer),
      `fork-release-${f.expected.sourceSha}-gcp-${f.execution.operationId}-1`,
    );
    assert.deepEqual(Object.keys(producer).toSorted(), [
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

void test("GCP seal refuses changed bindings, incomplete runs and writable evidence", () => {
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

void test("producer kinds remain distinct and refuse extra fields", () => {
  const github = { workflowSha: "a".repeat(40), runId: "42", attempt: "1" };
  validateProducer(github);
  assert.equal(producerArtifactName("b".repeat(40), github), `fork-release-${"b".repeat(40)}-42-1`);
  assert.throws(() => validateProducer({ ...github, kind: "gcp" }), /Invalid producer fields/u);
  assert.throws(
    () => validateProducer({ ...github, opaqueMetadata: "private" }),
    /Invalid producer fields/u,
  );
});

void test("native smoke retains its flow under bounded no-network Docker execution", () => {
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
    for (const command of ["docker", "skopeo"]) {
      writeFileSync(join(root, command), fake, { mode: 0o700 });
    }
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
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
    rmSync(root, { recursive: true });
  }
});

void test("loaded index smoke requires an exact digest and the explicit loaded transport", () => {
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

void test("loaded OCI index remains immutable through smoke and platform-pinned plugin inspection", () => {
  const root = mkdtempSync(join(tmpdir(), "fork-index-smoke-"));
  const capture = join(root, "calls.jsonl");
  const verifierCapture = join(root, "verifiers.jsonl");
  const verifierSource = fileURLToPath(new URL("./verify-image-plugins.mjs", import.meta.url));
  const sourceHash = hash(readFileSync(verifierSource));
  const sourceMode = statSync(verifierSource).mode & 0o777;
  const unrelated = join(root, "unrelated-file");
  const indexDigest = `sha256:${"c".repeat(64)}`;
  const previous = Object.fromEntries(
    [
      "PATH",
      "TMPDIR",
      "SMOKE_CAPTURE",
      "SMOKE_DIGEST",
      "SMOKE_FAIL_START",
      "SMOKE_VERIFIER_CAPTURE",
      "SMOKE_PLUGIN_FAILURE",
      "SMOKE_RUNTIME_PROOF",
    ].map((key) => [key, process.env[key]]),
  );
  const fake = `#!${process.execPath}
import { createHash } from "node:crypto";
import { appendFileSync, readFileSync, statSync } from "node:fs";
import { dirname } from "node:path";
const args = process.argv.slice(2);
appendFileSync(process.env.SMOKE_CAPTURE, JSON.stringify(args) + "\\n");
if (args[0] === "image") console.log(process.env.SMOKE_DIGEST);
if (args[0] === "create" && args.includes("/tmp/verify-image-plugins.mjs")) {
  const mount = args[args.indexOf("--mount") + 1];
  const prefix = "type=bind,source=";
  const suffix = ",target=/tmp/verify-image-plugins.mjs,readonly";
  if (!mount.startsWith(prefix) || !mount.endsWith(suffix)) throw Error("Unexpected verifier mount");
  const path = mount.slice(prefix.length, -suffix.length);
  appendFileSync(process.env.SMOKE_VERIFIER_CAPTURE, JSON.stringify({
    path, mode: statSync(path).mode & 0o777, directoryMode: statSync(dirname(path)).mode & 0o777,
    sha256: createHash("sha256").update(readFileSync(path)).digest("hex"),
  }) + "\\n");
  if (process.env.SMOKE_PLUGIN_FAILURE === "create") process.exit(19);
}
if (args[0] === "create") console.log(process.env.SMOKE_PLUGIN_FAILURE === "identity" ? "invalid" : "2".repeat(64));
if (args[0] === "rm" && process.env.SMOKE_PLUGIN_FAILURE === "cleanup") process.exit(23);
if (args[0] === "inspect") console.log(args.includes("{{.State.Running}} {{.State.ExitCode}} {{.State.OOMKilled}}") ? "false 0 false" : "false 0");
if (args[0] === "start" && readFileSync(process.env.SMOKE_CAPTURE, "utf8").includes("/tmp/verify-image-plugins.mjs")) console.log(process.env.SMOKE_RUNTIME_PROOF || "[]");
if (args[0] === "start" && process.env.SMOKE_FAIL_START === "1") process.exit(17);
`;
  const calls = () =>
    readFileSync(capture, "utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
  const verifiers = () =>
    readFileSync(verifierCapture, "utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
  const assertVerifierCleaned = () => {
    const verifier = verifiers().at(-1);
    assert.notEqual(verifier.path, verifierSource);
    assert.equal(dirname(dirname(verifier.path)), root);
    assert.equal(verifier.mode, 0o444);
    assert.equal(verifier.directoryMode, 0o700);
    assert.equal(verifier.sha256, sourceHash);
    assert.equal(existsSync(dirname(verifier.path)), false);
    assert.equal(hash(readFileSync(verifierSource)), sourceHash);
    assert.equal(statSync(verifierSource).mode & 0o777, sourceMode);
    assert.equal(readFileSync(unrelated, "utf8"), "preserved");
  };
  const options = {
    isolation: "secretless",
    transport: "loaded",
    loadedIndexDigest: indexDigest,
  };
  try {
    writeFileSync(join(root, "docker"), fake, { mode: 0o700 });
    writeFileSync(unrelated, "preserved");
    process.env.PATH = `${root}:${previous.PATH}`;
    process.env.TMPDIR = root;
    process.env.SMOKE_VERIFIER_CAPTURE = verifierCapture;
    delete process.env.SMOKE_PLUGIN_FAILURE;
    delete process.env.SMOKE_RUNTIME_PROOF;
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
        "0.160.0",
      ),
      [],
    );
    const plugins = calls().find(
      (args) => args[0] === "create" && args.includes("/tmp/verify-image-plugins.mjs"),
    );
    assert.equal(plugins[0], "create");
    assert.equal(plugins[plugins.indexOf("--platform") + 1], "linux/amd64");
    assert.equal(plugins[plugins.indexOf("--entrypoint") + 2], indexDigest);
    assert.equal(plugins[plugins.indexOf("--network") + 1], "none");
    assert.ok(plugins.includes("--read-only"));
    assert.ok(!plugins.includes("--user"));
    assert.equal(plugins[plugins.indexOf("--cap-drop") + 1], "ALL");
    assert.equal(plugins[plugins.indexOf("--security-opt") + 1], "no-new-privileges");
    assertVerifierCleaned();
    assert.ok(!plugins.includes(digest));
    assert.equal(plugins.at(-1), "0.160.0");
    assert.equal(plugins[plugins.indexOf("--memory") + 1], "1g");
    assert.equal(plugins[plugins.indexOf("--memory-swap") + 1], "1g");
    assert.deepEqual(calls().at(-1), ["rm", "--force", "2".repeat(64)]);

    const expected = {
      nodeVersion: "24.22.1",
      markdownVersion: "15.0.3",
      argparseVersion: "3.0.3",
      dockerfileSha256: "1".repeat(64),
      consumerManifestSha256: "2".repeat(64),
      lockfileSha256: "3".repeat(64),
    };
    const runtime = {
      schema: "openclaw.image-runtime.v1",
      expected,
      node: { version: "24.22.1", platform: "linux", architecture: "x64" },
      markdown: {
        version: "15.0.3",
        argparseVersion: "3.0.3",
        resolution: "pnpm-production-store",
        consumer: "dist/plugin-sdk/text-chunking.js",
        consumerSha256: "4".repeat(64),
        render: true,
        documentIsolation: true,
      },
      controlUi: {
        indexSha256: "5".repeat(64),
        manifestSha256: "6".repeat(64),
        generation: "7".repeat(64),
        assetCount: 1,
        assetBytes: 50,
      },
    };
    process.env.SMOKE_RUNTIME_PROOF = JSON.stringify({ plugins: [], runtime });
    writeFileSync(capture, "");
    const qualified = inspectLoadedPlugins(
      { image: { architecture: "amd64", extensions: "codex,workboard" } },
      "2026.10.5",
      indexDigest,
      "0.160.0",
      expected,
    );
    assert.deepEqual(qualified.runtime, runtime);
    const qualifiedCreate = calls().find((args) => args[0] === "create");
    assert.deepEqual(JSON.parse(qualifiedCreate.at(-1)), expected);
    assert.equal(qualifiedCreate[qualifiedCreate.indexOf("--entrypoint") + 2], indexDigest);
    assertVerifierCleaned();
    for (const wrong of [
      [],
      { plugins: [], runtime: { ...runtime, node: { ...runtime.node, version: "24.21.0" } } },
    ]) {
      process.env.SMOKE_RUNTIME_PROOF = JSON.stringify(wrong);
      assert.throws(
        () =>
          inspectLoadedPlugins(
            { image: { architecture: "amd64", extensions: "codex,workboard" } },
            "2026.10.5",
            indexDigest,
            "0.160.0",
            expected,
          ),
        /proof/u,
      );
      assertVerifierCleaned();
    }
    delete process.env.SMOKE_RUNTIME_PROOF;

    writeFileSync(capture, "");
    process.env.SMOKE_FAIL_START = "1";
    assert.throws(() =>
      inspectLoadedPlugins(
        { image: { architecture: "amd64", extensions: "codex,workboard" } },
        "2026.10.5",
        indexDigest,
        "0.160.0",
      ),
    );
    assert.deepEqual(calls().at(-1), ["rm", "--force", "2".repeat(64)]);
    assertVerifierCleaned();
    delete process.env.SMOKE_FAIL_START;

    for (const phase of ["create", "identity", "cleanup"]) {
      writeFileSync(capture, "");
      process.env.SMOKE_PLUGIN_FAILURE = phase;
      assert.throws(() =>
        inspectLoadedPlugins(
          { image: { architecture: "amd64", extensions: "codex,workboard" } },
          "2026.10.5",
          indexDigest,
          "0.160.0",
        ),
      );
      assertVerifierCleaned();
      if (phase === "cleanup") {
        assert.deepEqual(calls().at(-1), ["rm", "--force", "2".repeat(64)]);
      } else {
        assert.deepEqual(
          calls().map((args) => args[0]),
          ["create"],
        );
      }
    }
    delete process.env.SMOKE_PLUGIN_FAILURE;

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
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
    rmSync(root, { recursive: true });
  }
});
