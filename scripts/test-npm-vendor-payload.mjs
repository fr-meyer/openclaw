// Fixed Linux CI data-only controls. No vendor import, package invocation or tar.
import assert from "node:assert/strict";
import {
  constants,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  openSync,
  closeSync,
  fsyncSync,
  lstatSync,
  realpathSync,
  rmSync,
  symlinkSync,
  chmodSync,
  existsSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  readNpmVendorProof,
  validateNpmVendorProof,
  verifyInstalledNpmVendorDirectory,
} from "./lib/npm-glob-vendor-proof.mjs";
import { stageNpmVendorPayload } from "./lib/npm-vendor-payload.mjs";

const EXPECTED = 16;
const CASES = [
  "canonical-payload",
  "unknown-source-entries-not-copied",
  "strict-output-extra-refused",
  "selected-content-tamper-refused",
  "selected-mode-tamper-refused",
  "selected-size-tamper-refused",
  "selected-link-refused",
  "source-root-link-refused",
  "source-ancestor-link-refused",
  "output-parent-link-refused",
  "existing-output-refused",
  "overlap-refused",
  "patch-tamper-refused",
  "proof-tamper-refused",
  "missing-source-file-refused",
  "unsafe-output-parent-refused",
];
const result = {
  schema: "openclaw.npm-vendor-payload-controls.v1",
  status: "refused",
  expectedCaseCount: EXPECTED,
  testCount: 0,
  passedCount: 0,
  failedCount: 0,
  cases: [],
  host: process.platform === "linux" ? "linux" : "unsupported",
  dataOnly: true,
  packageExecuted: false,
  imageBuilt: false,
  qualified: false,
  failure: { state: "absent" },
};
const reportName = "v109-npm-vendor-payload-controls.json";
let owned, ownedIdentity;
function privateWrite(filename, bytes) {
  const fd = openSync(
    filename,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
    0o600,
  );
  try {
    writeFileSync(fd, bytes);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}
function retainFailure(index, error) {
  // Private working-disk prefix only; never uploaded or printed by this script.
  if (!process.env.RUNNER_TEMP) return;
  let text = "unavailable";
  try {
    if (error instanceof Error) text = `${error.name}\n${error.message}\n${error.stack ?? ""}`;
  } catch {}
  privateWrite(
    path.join(process.env.RUNNER_TEMP, `v109-payload-control-${index}.error.private`),
    Buffer.from(text).subarray(0, 16384),
  );
}
const PAYLOAD_FAILURES = [
  "bounds",
  "directory_type",
  "elapsed",
  "output_changed",
  "output_write",
  "overlap",
  "parent",
  "patch",
  "path",
  "platform",
  "source_changed",
  "source_file",
  "source_hash",
  "source_link",
  "io",
].map((name) => `npm-vendor.payload_${name}`);
const NODE_CODES = [
  "ENOENT",
  "EEXIST",
  "ELOOP",
  "ENOTDIR",
  "EACCES",
  "EPERM",
  "EMFILE",
  "ENFILE",
  "ENOSPC",
  "EIO",
  "ERR_ASSERTION",
];
function safeFailure(error) {
  try {
    const message = Object.getOwnPropertyDescriptor(error, "message"),
      code = Object.getOwnPropertyDescriptor(error, "code");
    const value = message && "value" in message ? message.value : undefined;
    const nodeCode = code && "value" in code ? code.value : undefined;
    const known = PAYLOAD_FAILURES.includes(value)
      ? value
      : nodeCode === "ERR_ASSERTION"
        ? "assertion_failed"
        : value === "controls_not_admitted"
          ? "admission_refused"
          : value === "canonical_control_failed"
            ? "positive_control_failed"
            : value === "fixture_owner_changed"
              ? "cleanup_refused"
              : "unrecognized";
    return {
      state: "present",
      reason: known,
      nodeCode: NODE_CODES.includes(nodeCode)
        ? nodeCode
        : nodeCode === undefined
          ? "absent"
          : "unrecognized",
    };
  } catch {
    return { state: "present", reason: "unrecognized", nodeCode: "unrecognized" };
  }
}
function check(index, body) {
  const row = { name: CASES[index], passed: false };
  try {
    body();
    row.passed = true;
  } catch (error) {
    retainFailure(index, error);
    row.failure = safeFailure(error);
  }
  result.cases.push(row);
}
try {
  if (
    process.argv.length !== 2 ||
    process.env.GITHUB_ACTIONS !== "true" ||
    process.env.CI !== "true" ||
    process.platform !== "linux" ||
    !process.env.RUNNER_TEMP
  )
    throw new Error("controls_not_admitted");
  const repoRoot = realpathSync(fileURLToPath(new URL("..", import.meta.url)));
  const proof = readNpmVendorProof(
    readFileSync(path.join(repoRoot, "patches/npm-12.2.1.glob-cancellation.proof.json")),
  );
  const patchBytes = readFileSync(path.join(repoRoot, "patches/npm@12.2.1.patch"));
  const facts = validateNpmVendorProof(proof);
  const sourceRoot = realpathSync(path.join(repoRoot, "node_modules/npm"));
  const relative = path.relative(repoRoot, sourceRoot);
  assert.ok(
    relative &&
      relative !== ".." &&
      !relative.startsWith(`..${path.sep}`) &&
      !path.isAbsolute(relative),
  );
  owned = realpathSync(mkdtempSync(path.join(tmpdir(), "openclaw-payload-controls-")));
  ownedIdentity = lstatSync(owned);
  const payload = path.join(owned, "payload");
  const stage = (packageRoot, outputRoot, extra = {}) =>
    stageNpmVendorPayload({ packageRoot, outputRoot, proof, patchBytes, ...extra });
  let canonical;
  check(0, () => {
    canonical = stage(sourceRoot, payload);
    assert.ok(
      canonical.payloadVerified === true &&
        canonical.ambientSourceVerified === false &&
        canonical.sourceRoot === sourceRoot &&
        canonical.payloadRoot === payload,
    );
    assert.ok(
      canonical.files.length === 1942 &&
        canonical.inventorySha256 === proof.derived.inventorySha256,
    );
    assert.ok(
      verifyInstalledNpmVendorDirectory({ packageRoot: payload, proof, patchBytes }).files
        .length === 1942,
    );
  });
  // A failure of the full positive control is terminal; don't invent dependent results.
  if (result.cases[0]?.passed !== true) throw new Error("canonical_control_failed");
  const first = facts.files[0],
    firstBytes = readFileSync(path.join(payload, first.path));
  assert.ok(firstBytes.length > 0);
  const fixture = (name, modify) => {
    const directory = path.join(owned, name);
    mkdirSync(directory, { mode: 0o700 });
    const filename = path.join(directory, first.path);
    mkdirSync(path.dirname(filename), { recursive: true });
    writeFileSync(filename, firstBytes, { flag: "wx", mode: first.mode });
    chmodSync(filename, first.mode);
    if (modify) modify(directory, filename);
    return directory;
  };
  let second;
  check(1, () => {
    const unknown = path.join(payload, "fixture-untrusted-helper"),
      link = path.join(payload, "fixture-untrusted-link");
    writeFileSync(unknown, "synthetic unknown bytes", { mode: 0o000, flag: "wx" });
    symlinkSync(path.join(owned, "nonexistent-target"), link);
    try {
      second = stage(payload, path.join(owned, "second-payload"));
      assert.ok(second.ambientSourceVerified === false && second.payloadVerified === true);
      assert.ok(
        !existsSync(path.join(second.payloadRoot, "fixture-untrusted-helper")) &&
          !existsSync(path.join(second.payloadRoot, "fixture-untrusted-link")),
      );
      assert.ok(
        verifyInstalledNpmVendorDirectory({ packageRoot: second.payloadRoot, proof, patchBytes })
          .files.length === 1942,
      );
    } finally {
      rmSync(unknown);
      rmSync(link);
    }
  });
  check(2, () => {
    const unknown = path.join(payload, "fixture-unexpected-output");
    writeFileSync(unknown, "synthetic output tamper", { flag: "wx", mode: 0o644 });
    try {
      assert.throws(
        () => verifyInstalledNpmVendorDirectory({ packageRoot: payload, proof, patchBytes }),
        /npm-vendor\.installed_inventory/,
      );
    } finally {
      rmSync(unknown);
    }
  });
  check(3, () => {
    const source = fixture("content", (_dir, file) => {
      const changed = Buffer.from(firstBytes);
      changed[0] ^= 1;
      writeFileSync(file, changed);
    });
    assert.throws(
      () => stage(source, path.join(owned, "content-out")),
      /npm-vendor\.payload_source_hash/,
    );
  });
  check(4, () => {
    const source = fixture("mode", (_dir, file) => chmodSync(file, 0o600));
    assert.throws(
      () => stage(source, path.join(owned, "mode-out")),
      /npm-vendor\.payload_source_file/,
    );
  });
  check(5, () => {
    const source = fixture("size", (_dir, file) =>
      writeFileSync(file, Buffer.concat([firstBytes, Buffer.from("x")])),
    );
    assert.throws(
      () => stage(source, path.join(owned, "size-out")),
      /npm-vendor\.payload_source_file/,
    );
  });
  check(6, () => {
    const source = fixture("link", (_dir, file) => {
      rmSync(file);
      symlinkSync(path.join(payload, first.path), file);
    });
    assert.throws(
      () => stage(source, path.join(owned, "link-out")),
      /npm-vendor\.payload_source_link/,
    );
  });
  check(7, () => {
    const alias = path.join(owned, "root-alias");
    symlinkSync(payload, alias);
    assert.throws(
      () => stage(alias, path.join(owned, "alias-out")),
      /npm-vendor\.payload_source_link/,
    );
  });
  check(8, () => {
    const alias = path.join(owned, "ancestor-alias");
    symlinkSync(owned, alias);
    assert.throws(
      () => stage(path.join(alias, "payload"), path.join(owned, "ancestor-out")),
      /npm-vendor\.payload_source_link/,
    );
  });
  check(9, () => {
    const alias = path.join(owned, "output-parent-alias");
    symlinkSync(owned, alias);
    assert.throws(
      () => stage(payload, path.join(alias, "new-output")),
      /npm-vendor\.payload_source_link/,
    );
  });
  check(10, () => {
    const existing = path.join(owned, "existing");
    mkdirSync(existing);
    assert.throws(() => stage(payload, existing), /npm-vendor\.payload_io/);
    assert.ok(lstatSync(existing).isDirectory());
  });
  check(11, () =>
    assert.throws(
      () => stage(payload, path.join(payload, "overlap")),
      /npm-vendor\.payload_overlap/,
    ),
  );
  check(12, () =>
    assert.throws(
      () =>
        stage(payload, path.join(owned, "bad-patch"), {
          patchBytes: Buffer.from("untrusted patch"),
        }),
      /npm-vendor\.payload_patch/,
    ),
  );
  check(13, () => {
    const changed = structuredClone(proof);
    changed.original.integrity = "untrusted";
    assert.throws(
      () => stage(payload, path.join(owned, "bad-proof"), { proof: changed }),
      /npm-vendor\.original_binding/,
    );
  });
  check(14, () => {
    const empty = path.join(owned, "empty");
    mkdirSync(empty);
    assert.throws(() => stage(empty, path.join(owned, "missing-file")), /npm-vendor\.payload_io/);
  });
  check(15, () => {
    const publicParent = path.join(owned, "public-parent");
    mkdirSync(publicParent, { mode: 0o755 });
    chmodSync(publicParent, 0o755);
    assert.throws(
      () => stage(payload, path.join(publicParent, "output")),
      /npm-vendor\.payload_parent/,
    );
  });
  result.status =
    result.cases.length === EXPECTED && result.cases.every((row) => row.passed)
      ? "passed"
      : "failed";
} catch (error) {
  result.status = result.cases.length ? "failed" : "refused";
  try {
    retainFailure("setup", error);
  } catch {}
  result.failure = safeFailure(error);
} finally {
  if (owned) {
    try {
      const current = lstatSync(owned);
      if (
        !current.isDirectory() ||
        current.isSymbolicLink() ||
        current.dev !== ownedIdentity.dev ||
        current.ino !== ownedIdentity.ino
      )
        throw new Error("fixture_owner_changed");
      rmSync(owned, { recursive: true });
    } catch (error) {
      result.status = "failed";
      try {
        retainFailure("cleanup", error);
      } catch {}
      result.failure = safeFailure(error);
    }
  }
}
result.testCount = result.cases.length;
result.passedCount = result.cases.filter((row) => row.passed).length;
result.failedCount = result.cases.filter((row) => !row.passed).length;
const bytes = Buffer.from(`${JSON.stringify(result)}\n`);
try {
  if (!process.env.RUNNER_TEMP || bytes.length > 8192) throw new Error("report_unavailable");
  privateWrite(path.join(process.env.RUNNER_TEMP, reportName), bytes);
} catch {
  result.status = "refused";
  result.failure = { state: "present", reason: "report_refused", nodeCode: "absent" };
}
process.stdout.write(`${JSON.stringify(result)}\n`);
process.exitCode = result.status === "passed" ? 0 : 1;
