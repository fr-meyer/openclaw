// Execute only inside the separately approved, native supervised Linux attempt.
import assert from "node:assert/strict";
import fs from "node:fs";
import net from "node:net";
import { Resolver } from "node:dns/promises";
import { spawnSync } from "node:child_process";
import { DatabaseSync, backup } from "node:sqlite";
import { getHeapStatistics } from "node:v8";
import { Worker, isMainThread, parentPort, workerData, resourceLimits } from "node:worker_threads";

const mode = process.argv[2];
const sentinel = "/dev/shm/v98-outside-sentinel";
const root = "/scratch/probes";

function deniedFs(operation) {
  assert.throws(operation, (error) => error.code === "EACCES");
}

async function deniedSocket(host) {
  await new Promise((resolve, reject) => {
    const socket = net.createConnection({ host, port: 9 });
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error("socket denial timed out"));
    }, 750);
    socket.once("connect", () => {
      clearTimeout(timer);
      socket.destroy();
      reject(new Error("network connection admitted"));
    });
    socket.once("error", (error) => {
      clearTimeout(timer);
      if (error.code !== "EPERM") reject(error);
      else resolve();
    });
  });
}

async function exercise(label) {
  const dir = `${root}/${label}`;
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const file = fs.openSync(`${dir}/fsync-control`, "wx", 0o600);
  try {
    fs.writeSync(file, "synthetic fsync control\n");
    fs.fsyncSync(file);
  } finally { fs.closeSync(file); }
  const directory = fs.openSync(dir, "r");
  try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); }

  // Sentinel is a real writable UID1000 file, created before Landlock in the
  // container's private 1MiB shm. EACCES cannot be a read-only-mount fake.
  deniedFs(() => fs.readFileSync(sentinel));
  deniedFs(() => fs.writeFileSync(sentinel, "escape"));
  deniedFs(() => fs.writeFileSync("/dev/shm/v98-unowned-output", "escape"));
  deniedFs(() => fs.readdirSync("/app"));
  deniedFs(() => fs.readFileSync("/proc/self/mem"));
  await deniedSocket("127.0.0.1");
  await deniedSocket("::1");
  const resolver = new Resolver({ timeout: 100, tries: 1 });
  resolver.setServers(["127.0.0.1"]);
  await assert.rejects(resolver.resolve4("v98-synthetic-control.invalid"));
  resolver.cancel();
  // DNS errors alone are not isolation proof: the host also requires trusted
  // denied-socket observations from the native syscall owner.

  const db = new DatabaseSync(`${dir}/wal.sqlite`);
  let keepAlive;
  try {
    assert.equal(db.prepare("PRAGMA journal_mode=WAL").get().journal_mode, "wal");
    db.exec("PRAGMA synchronous=FULL; CREATE TABLE synthetic(value TEXT); INSERT INTO synthetic VALUES('control');");
    assert.equal(db.prepare("PRAGMA integrity_check").get().integrity_check, "ok");
    keepAlive = setInterval(() => {}, 50);
    assert.ok(await backup(db, `${dir}/backup.sqlite`) > 0);
    db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
  } finally {
    clearInterval(keepAlive);
    db.close();
  }
  const copy = new DatabaseSync(`${dir}/backup.sqlite`, { readOnly: true });
  try { assert.equal(copy.prepare("SELECT value FROM synthetic").get().value, "control"); }
  finally { copy.close(); }
  return { label, fsync: true, sqliteWalBackupClose: true, deniedOutsideScratch: true, deniedSockets: true,
    heapSizeLimitBytes: getHeapStatistics().heap_size_limit, workerResourceLimits: resourceLimits };
}

if (!isMainThread) {
  if (workerData.deadline === true) {
    parentPort.postMessage({ workerReady: true });
    setInterval(() => {}, 1000);
  } else {
    parentPort.postMessage(await exercise("worker"));
    parentPort.close();
  }
} else {
  assert.ok(["--capability-probe", "--deadline-probe"].includes(mode));
  assert.equal(process.env.HOME, "/scratch/home");
  assert.equal(process.env.XDG_CACHE_HOME, "/scratch/cache");
  assert.equal(process.env.PARITY_FIXTURE_SCRATCH_ROOT, "/scratch");
  assert.equal(process.env.NODE_OPTIONS, "--max-old-space-size=128");
  assert.equal(fs.existsSync("/scratch/synthetic-parity-fixture"), false);
  fs.mkdirSync(root, { recursive: true, mode: 0o700 });
  if (mode === "--deadline-probe") {
    const worker = new Worker(new URL(import.meta.url), {
      workerData: { deadline: true }, resourceLimits: { maxOldGenerationSizeMb: 512 },
    });
    worker.once("message", () => {
      console.error(JSON.stringify({ event: "deadline_worker_ready" }));
      setInterval(() => {}, 1000);
    });
    worker.once("error", (error) => { throw error; });
  } else {
    const main = await exercise("main");
    const child = spawnSync("/usr/local/bin/node", ["-e", "process.exit(0)"], { stdio: "inherit" });
    assert.equal(child.status, null);
    assert.equal(child.error?.code, "EPERM");
    const workerResult = await new Promise((resolve, reject) => {
      const worker = new Worker(new URL(import.meta.url), {
        workerData: { deadline: false }, resourceLimits: { maxOldGenerationSizeMb: 512 },
      });
      let message;
      worker.once("message", (value) => { message = value; });
      worker.once("error", reject);
      worker.once("exit", (code) => {
        if (code !== 0 || !message) reject(new Error("Worker did not join successfully"));
        else resolve(message);
      });
    });
    console.error(JSON.stringify({ event: "capability_controls_joined", main, worker: workerResult }));
  }
}
