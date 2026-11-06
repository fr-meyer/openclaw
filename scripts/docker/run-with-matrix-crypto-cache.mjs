#!/usr/bin/env node

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { closeSync, constants, fstatSync, openSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { constants as osConstants } from "node:os";
import { basename } from "node:path";
import { fileURLToPath } from "node:url";

// Official v0.6.6 release asset digests; keep acquisition and these pins aligned.
// https://github.com/matrix-org/matrix-rust-sdk-crypto-nodejs/releases/tag/v0.6.6
const ASSETS = Object.freeze({
  x64: Object.freeze({
    filename: "matrix-sdk-crypto.linux-x64-gnu.node",
    size: 24_788_544,
    sha256: "aeb21029ac6bb29cd06493f67b19a5a75b3d0371a1ab452fe59f78249350f0f7",
  }),
  arm64: Object.freeze({
    filename: "matrix-sdk-crypto.linux-arm64-gnu.node",
    size: 22_354_632,
    sha256: "c43c347f39786ee9f2d11b5ae3088d182c1a81636f2b68dc2297fe6716be2891",
  }),
});

/** Read once so the served bytes cannot change after integrity verification. */
export function readMatrixCryptoAsset(assetPath) {
  const asset = ASSETS[process.arch];
  if (process.platform !== "linux" || !asset) {
    throw new Error("Matrix crypto cache supports Linux x64/arm64 glibc builds only");
  }
  if (basename(assetPath) !== asset.filename) {
    throw new Error(`Expected Matrix crypto asset ${asset.filename}`);
  }
  const descriptor = openSync(assetPath, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = fstatSync(descriptor);
    if (!stat.isFile() || stat.size !== asset.size) {
      throw new Error("Matrix crypto asset size/type mismatch");
    }
    const bytes = readFileSync(descriptor);
    if (createHash("sha256").update(bytes).digest("hex") !== asset.sha256) {
      throw new Error("Matrix crypto asset SHA-256 mismatch");
    }
    return { filename: asset.filename, bytes };
  } finally {
    closeSync(descriptor);
  }
}

/** Serve an admitted asset while the unchanged native install owns lifecycles. */
export async function runWithVerifiedMatrixCryptoAsset(asset, command, args) {
  if (!command || !Object.values(ASSETS).some(({ filename }) => filename === asset.filename)) {
    throw new Error("Expected admitted Matrix crypto asset and native command");
  }
  const assetRoute = `/v0.6.6/${asset.filename}`;
  const server = createServer((request, response) => {
    if (request.url !== assetRoute) {
      response.writeHead(404).end();
    } else if (request.method !== "GET" && request.method !== "HEAD") {
      response.writeHead(405, { Allow: "GET, HEAD" }).end();
    } else {
      response.writeHead(200, {
        "Content-Type": "application/octet-stream",
        "Content-Length": asset.bytes.length,
      });
      response.end(request.method === "HEAD" ? undefined : asset.bytes);
    }
  });
  server.maxConnections = 4;
  server.headersTimeout = 10_000;
  server.requestTimeout = 30_000;
  let child;
  let interrupted;
  const forward = (signal) => {
    interrupted ??= signal;
    if (child?.exitCode === null && child.signalCode === null) {
      child.kill(signal);
    }
  };
  const onInterrupt = () => forward("SIGINT");
  const onTerminate = () => forward("SIGTERM");
  try {
    await new Promise((resolve, reject) => {
      const fail = (error) => reject(error);
      server.once("error", fail);
      server.listen(0, "127.0.0.1", () => {
        server.off("error", fail);
        resolve();
      });
    });
    const address = server.address();
    if (!address || typeof address === "string") {
      throw new Error("Matrix crypto cache did not bind a loopback port");
    }
    child = spawn(command, args, {
      stdio: "inherit",
      env: {
        ...process.env,
        MATRIX_SDK_CRYPTO_DOWNLOADS_BASE_URL: `http://127.0.0.1:${address.port}`,
      },
    });
    process.on("SIGINT", onInterrupt);
    process.on("SIGTERM", onTerminate);
    const result = await new Promise((resolve, reject) => {
      child.once("error", reject);
      child.once("close", (code, signal) => resolve({ code, signal }));
    });
    const signal = interrupted ?? result.signal;
    return signal ? 128 + (osConstants.signals[signal] ?? 1) : (result.code ?? 1);
  } finally {
    process.off("SIGINT", onInterrupt);
    process.off("SIGTERM", onTerminate);
    if (server.listening) {
      await new Promise((resolve) => {
        server.close(resolve);
        server.closeAllConnections();
      });
    }
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const [assetPath, separator, command, ...args] = process.argv.slice(2);
    if (!assetPath || separator !== "--" || !command) {
      throw new Error("Usage: run-with-matrix-crypto-cache.mjs ASSET_PATH -- COMMAND [ARGS...]");
    }
    process.exitCode = await runWithVerifiedMatrixCryptoAsset(
      readMatrixCryptoAsset(assetPath),
      command,
      args,
    );
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
