import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, open, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";
import {
  readMatrixCryptoAsset,
  runWithVerifiedMatrixCryptoAsset,
} from "./run-with-matrix-crypto-cache.mjs";

// openclaw-temp-dir: allow native node:test fixture; no transformed test imports.
const root = await mkdtemp(join(tmpdir(), "openclaw-matrix-crypto-cache-"));
after(() => rm(root, { recursive: true, force: true }));
const helper = fileURLToPath(new URL("./run-with-matrix-crypto-cache.mjs", import.meta.url));
const assetArch = ["x64", "arm64"].includes(process.arch) ? process.arch : "x64";
const filename = `matrix-sdk-crypto.linux-${assetArch}-gnu.node`;
const fixture = { filename, bytes: Buffer.from("synthetic native-asset transport fixture") };

test("CLI refuses unverified bytes before running a lifecycle command", async () => {
  const assetPath = join(root, filename);
  if (process.platform !== "linux" || !["x64", "arm64"].includes(process.arch)) {
    assert.throws(() => readMatrixCryptoAsset(assetPath), /supports Linux x64\/arm64/);
    return;
  }
  const marker = join(root, "unexpected-child");
  await writeFile(assetPath, "incorrect asset");
  const failed = spawnSync(
    process.execPath,
    [
      helper,
      assetPath,
      "--",
      process.execPath,
      "-e",
      "require('fs').writeFileSync(process.argv[1], 'ran')",
      marker,
    ],
    { encoding: "utf8", timeout: 10_000 },
  );
  assert.equal(failed.status, 1, failed.stderr);
  assert.match(failed.stderr, /asset size\/type mismatch/);
  await assert.rejects(readFile(marker), { code: "ENOENT" });

  // Correct-sized but altered bytes must fail the digest, not merely a length check.
  const file = await open(assetPath, "w");
  try {
    await file.truncate(process.arch === "x64" ? 24_788_544 : 22_354_632);
  } finally {
    await file.close();
  }
  assert.throws(() => readMatrixCryptoAsset(assetPath), /SHA-256 mismatch/);
  assert.throws(
    () => readMatrixCryptoAsset(join(root, "other.node")),
    /Expected Matrix crypto asset/,
  );
  await rm(assetPath);
  await symlink(marker, assetPath);
  assert.throws(() => readMatrixCryptoAsset(assetPath), { code: "ELOOP" });
});

test("native child gets only the exact loopback asset route and retains argv/environment", async () => {
  const observation = join(root, "transport-url");
  const expectedArgument = "one argument; $(must-not-run)";
  const code = `
    import assert from 'node:assert/strict';
    import { writeFileSync } from 'node:fs';
    const [observation, expectedPath, argument] = process.argv.slice(1);
    assert.equal(process.env.PATH, expectedPath);
    assert.equal(argument, 'one argument; $(must-not-run)');
    const base = process.env.MATRIX_SDK_CRYPTO_DOWNLOADS_BASE_URL;
    const url = new URL(base);
    assert.equal(url.hostname, '127.0.0.1');
    assert.equal(url.protocol, 'http:');
    writeFileSync(observation, base);
    const asset = base + '/v0.6.6/${filename}';
    const get = await fetch(asset);
    assert.equal(get.status, 200);
    assert.equal(await get.text(), 'synthetic native-asset transport fixture');
    const head = await fetch(asset, {method: 'HEAD'});
    assert.equal(head.status, 200);
    assert.equal(Number(head.headers.get('content-length')), ${fixture.bytes.length});
    assert.equal(await head.text(), '');
    assert.equal((await fetch(asset, {method: 'POST'})).status, 405);
    for (const path of ['/v0.6.5/${filename}', '/v0.6.6/other.node', '/v0.6.6/${filename}?query=1']) {
      assert.equal((await fetch(base + path)).status, 404);
    }
  `;
  assert.equal(
    await runWithVerifiedMatrixCryptoAsset(fixture, process.execPath, [
      "--input-type=module",
      "-e",
      code,
      observation,
      process.env.PATH,
      expectedArgument,
    ]),
    0,
  );
  const base = await readFile(observation, "utf8");
  await assert.rejects(fetch(`${base}/v0.6.6/${filename}`));
});

test("child failure and spawn failure settle without retaining the server", async () => {
  const observation = join(root, "failure-url");
  const code =
    "require('fs').writeFileSync(process.argv[1], process.env.MATRIX_SDK_CRYPTO_DOWNLOADS_BASE_URL); process.exit(23)";
  assert.equal(
    await runWithVerifiedMatrixCryptoAsset(fixture, process.execPath, ["-e", code, observation]),
    23,
  );
  await assert.rejects(fetch(await readFile(observation, "utf8")));
  await assert.rejects(
    runWithVerifiedMatrixCryptoAsset(fixture, join(root, "missing-native-command"), []),
    { code: "ENOENT" },
  );
});

test(
  "SIGTERM reaches the native child and cannot become a successful install",
  { skip: process.platform === "win32" },
  async () => {
    const marker = join(root, "signal-forwarded");
    const childCode = `
    const {writeFileSync} = require('fs');
    const {connect} = require('net');
    const url = new URL(process.env.MATRIX_SDK_CRYPTO_DOWNLOADS_BASE_URL);
    const socket = connect(Number(url.port), url.hostname, () => process.kill(process.ppid, 'SIGTERM'));
    process.on('SIGTERM', () => {
      writeFileSync(process.argv[1], process.env.MATRIX_SDK_CRYPTO_DOWNLOADS_BASE_URL);
      socket.destroy();
      process.exit(0);
    });
  `;
    // Isolate the real signal from node:test; no detached process or sleep/poll loop.
    const harness = `
    import {runWithVerifiedMatrixCryptoAsset} from ${JSON.stringify(new URL("./run-with-matrix-crypto-cache.mjs", import.meta.url).href)};
    process.exitCode = await runWithVerifiedMatrixCryptoAsset(
      {filename: ${JSON.stringify(filename)}, bytes: Buffer.from('synthetic signal fixture')},
      process.execPath, ['-e', ${JSON.stringify(childCode)}, ${JSON.stringify(marker)}]);
  `;
    const result = spawnSync(process.execPath, ["--input-type=module", "-e", harness], {
      encoding: "utf8",
      timeout: 10_000,
    });
    assert.equal(result.status, 143, result.stderr);
    await assert.rejects(fetch(await readFile(marker, "utf8")));
  },
);
