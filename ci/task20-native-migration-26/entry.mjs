import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import { createInterface } from "node:readline";

const input = createInterface({ input: process.stdin });
const queued = [];
let pending;
let closed = false;
let received = 0;
input.on("line", (value) => {
  if (++received > 2 || !["TASK20_GO", "TASK20_CLOSE"].includes(value)) {
    throw new Error("fixture control protocol mismatch");
  }
  if (pending) pending(value);
  else queued.push(value);
});
input.on("close", () => {
  closed = true;
  if (pending) pending(undefined);
});
async function receive(expected) {
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => finish(new Error("fixture admission/close timeout")), 10_000);
    function finish(error) {
      clearTimeout(timer);
      pending = undefined;
      error ? reject(error) : resolve();
    }
    const accept = (value) => finish(value === expected ? undefined : new Error("fixture admission/close mismatch or EOF"));
    if (queued.length) accept(queued.shift());
    else if (closed) accept(undefined);
    else pending = accept;
  });
}

assert.equal(process.version, "v24.19.0");
assert.equal(process.platform, "linux");
assert.equal(process.arch, "x64");
assert.equal(process.versions.modules, "137");
assert.equal(process.versions.napi, "10");
assert.equal(process.versions.v8, "13.6.233.17-node.51");
assert.equal(process.versions.sqlite, "3.53.3");
const libc = process.report.getReport().header.glibcVersionRuntime;
assert.equal(libc, "2.36");
assert.equal(process.getuid(), 1000);
assert.equal(process.getgid(), 1000);
assert.equal(process.env.NODE_OPTIONS, undefined);
const status = Object.fromEntries(fs.readFileSync("/proc/self/status", "utf8").trim().split("\n").map((line) => {
  const index = line.indexOf(":");
  return [line.slice(0, index), line.slice(index + 1).trim()];
}));
assert.equal(status.NoNewPrivs, "1");
assert.equal(BigInt("0x" + status.CapEff), 0n);
assert.equal(BigInt("0x" + status.CapBnd), 0n);
const mounts = fs.readFileSync("/proc/self/mountinfo", "utf8").trim().split("\n").map((line) => {
  const fields = line.split(" ");
  return { target: fields[4], options: fields[5].split(","), filesystem: fields[fields.indexOf("-") + 1] };
});
for (const target of ["/", "/work", "/entry.mjs", "/watchdog.mjs", "/dev/shm", "/dev/mqueue"]) {
  assert.ok(mounts.some((mount) => mount.target === target && mount.options.includes("ro")), target);
}
assert.ok(mounts.some((mount) => mount.target === "/fixture" && mount.filesystem === "tmpfs" &&
  ["rw", "nosuid", "nodev", "noexec"].every((option) => mount.options.includes(option))));
assert.throws(() => fs.accessSync("/dev", fs.constants.W_OK));
const capacity = fs.statfsSync("/fixture", { bigint: true });
assert.equal(capacity.bsize * capacity.blocks, 16n * 1024n * 1024n);
assert.equal(fs.statSync("/fixture").uid, 1000);
assert.equal(fs.statSync("/fixture").gid, 1000);
console.log("TASK20_CONFINEMENT " + JSON.stringify({ noNewPrivileges: true, effectiveCapabilities: "0",
  boundingCapabilities: "0", fixtureCapacityBytes: Number(capacity.bsize * capacity.blocks), mounts }));
const fd = fs.openSync(process.execPath, "r");
const hash = crypto.createHash("sha256");
const buffer = Buffer.alloc(1024 * 1024);
let bytes = 0;
try {
  for (;;) {
    const count = fs.readSync(fd, buffer);
    if (!count) break;
    bytes += count;
    hash.update(buffer.subarray(0, count));
  }
} finally {
  fs.closeSync(fd);
}
console.log("TASK20_RUNTIME " + JSON.stringify({ version: process.version, versions: process.versions,
  architecture: process.arch, glibcVersionRuntime: libc, nodeBytes: bytes, nodeSha256: hash.digest("hex"),
  uid: process.getuid(), gid: process.getgid(), nodeOptions: null }));
// Native migration imports remain behind the external resource/confinement admission.
const admitted = receive("TASK20_GO");
console.log("TASK20_READY " + JSON.stringify({ phase: "ADMISSION_WAIT_NATIVE_MIGRATION_NOT_IMPORTED" }));
await admitted;
await import("/work/fixture-source/synthetic-migration-fixture.mjs");
const result = JSON.parse(fs.readFileSync("/fixture/component-result.json", "utf8"));
console.log("TASK20_COMPONENT " + JSON.stringify(result));
const cpu = Object.fromEntries(fs.readFileSync("/sys/fs/cgroup/cpu.stat", "utf8").trim().split("\n").map((line) => line.split(/\s+/u)));
const events = Object.fromEntries(fs.readFileSync("/sys/fs/cgroup/memory.events", "utf8").trim().split("\n").map((line) => line.split(/\s+/u)));
console.log("TASK20_FINAL_COUNTERS " + JSON.stringify({ cpuSeconds: Number(cpu.usage_usec) / 1e6,
  peakMemoryBytes: Number(fs.readFileSync("/sys/fs/cgroup/memory.peak", "utf8")),
  oom: Number(events.oom), oomKill: Number(events.oom_kill),
  fixtureUsedBytes: Number(fs.statfsSync("/fixture", { bigint: true }).bsize *
    (fs.statfsSync("/fixture", { bigint: true }).blocks - fs.statfsSync("/fixture", { bigint: true }).bfree)) }));
await receive("TASK20_CLOSE");
input.close();
