// Extracted functions with an invented filesystem/SQLite owner. Never import
// node:sqlite, open a database, or execute the fixture entry point.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";

const text = fs.readFileSync(process.argv[2], "utf8");
const extract = (name) => {
  const start = text.indexOf(`function ${name}(`);
  assert(start >= 0, name);
  const tail = text.slice(start), end = tail.indexOf("\n}\n");
  assert(end >= 0, name);
  return tail.slice(0, end + 3);
};
const digest = (raw) => createHash("sha256").update(raw).digest("hex");
const root = "/invented", phase = "predecessor";
let passed = 0;
function check(name, run) { run(); passed += 1; process.stdout.write(`PASS ${name}\n`); }
function model(options = {}) {
  let next = 1, ownerCalls = 0, ownerCloses = 0;
  const files = new Map(), descriptors = new Map();
  const stat = (data, changes = {}) => ({ dev: 8, ino: next++, size: data.length, uid: 1000, gid: 1000,
    nlink: 1, isFile: () => true, ...changes });
  const mainPaths = [path.join(root, phase, "state/openclaw.sqlite"), path.join(root, phase, "plugins/workboard/workboard.sqlite")];
  for (const name of mainPaths) files.set(name, { data: Buffer.from(name), stat: stat(Buffer.from(name)) });
  const fakeFs = {
    constants: { O_RDONLY: 0, O_NOFOLLOW: 256 },
    lstatSync(name) {
      options.statHook?.(name, files);
      if (!files.has(name)) throw Object.assign(new Error("absent"), { code: "ENOENT" });
      return { ...files.get(name).stat };
    },
    openSync(name, flags) {
      assert.equal(flags, 256);
      const file = files.get(name);
      if (!file || !file.stat.isFile()) throw Object.assign(new Error("no-follow"), { code: "ELOOP" });
      const fd = next++; descriptors.set(fd, file); return fd;
    },
    fstatSync(fd) { return { ...descriptors.get(fd).stat }; },
    readFileSync(fd) {
      if (options.readFailure) throw options.readFailure;
      return descriptors.get(fd).data;
    },
    closeSync(fd) { descriptors.delete(fd); if (options.fdCloseFailure) throw options.fdCloseFailure; },
  };
  class FakeDatabase {
    constructor(name) {
      ownerCalls += 1; this.name = name;
      if (options.openFailure) throw options.openFailure;
    }
    prepare(sql) {
      assert.equal(sql, "PRAGMA wal_checkpoint(TRUNCATE)");
      return { get: () => {
        if (options.checkpointFailure) throw options.checkpointFailure;
        if (options.mainMutation) files.get(this.name).data = Buffer.from("changed main");
        return options.row ?? { busy: 0, log: 0, checkpointed: 0 };
      } };
    }
    close() {
      ownerCloses += 1;
      if (options.closeFailure) throw options.closeFailure;
      if (!options.retainSidecars) { files.delete(this.name + "-wal"); files.delete(this.name + "-shm"); }
    }
  }
  const context = vm.createContext({ fs: fakeFs, path, DatabaseSync: FakeDatabase, sha256: digest, AggregateError });
  vm.runInContext(["sqlitePath", "requireConsolidated", "readSidecarStat", "readMainPin", "captureReadBoundary",
    "settleReadBoundary", "closeDatabases"].map(extract).join("\n"), context);
  function sidecars() {
    for (const name of mainPaths) {
      files.set(name + "-wal", { data: Buffer.alloc(0), stat: stat(Buffer.alloc(0)) });
      files.set(name + "-shm", { data: Buffer.alloc(32768), stat: stat(Buffer.alloc(32768)) });
    }
  }
  return { context, files, descriptors, mainPaths, sidecars,
    get ownerCalls() { return ownerCalls; }, get ownerCloses() { return ownerCloses; } };
}
check("observed empty readonly WAL/SHM is settled by two closed SQLite owners", () => {
  const m = model(), pins = m.context.captureReadBoundary(root, phase); m.sidecars();
  m.context.settleReadBoundary(root, phase, pins);
  assert.equal(m.ownerCalls, 2); assert.equal(m.ownerCloses, 2); assert.equal(m.descriptors.size, 0);
  assert.equal(m.files.size, 2);
});
check("already consolidated reads need no writable owner", () => {
  const m = model(), pins = m.context.captureReadBoundary(root, phase);
  m.context.settleReadBoundary(root, phase, pins); assert.equal(m.ownerCalls, 0);
});
check("pre-read dangling/nonregular sidecars refuse, including lstat failure", () => {
  for (const kind of ["symlink", "file", "permission"]) {
    const m = model(kind === "permission" ? { statHook: (name) => { if (name.endsWith("-wal")) throw Object.assign(new Error("denied"), { code: "EACCES" }); } } : {});
    if (kind !== "permission") m.files.set(m.mainPaths[0] + "-wal", { stat: { isFile: () => kind !== "symlink" } });
    assert.throws(() => m.context.captureReadBoundary(root, phase)); assert.equal(m.ownerCalls, 0);
  }
});
check("nonempty, missing, foreign, linked or symlinked families refuse before any owner", () => {
  for (const change of ["nonempty", "missing", "foreign", "linked", "symlink", "journal", "shmsize"]) {
    const m = model(), pins = m.context.captureReadBoundary(root, phase); m.sidecars();
    const name = m.mainPaths[1], wal = m.files.get(name + "-wal"), shm = m.files.get(name + "-shm");
    if (change === "nonempty") wal.stat.size = 1;
    if (change === "missing") m.files.delete(name + "-shm");
    if (change === "foreign") wal.stat.uid = 0;
    if (change === "linked") wal.stat.nlink = 2;
    if (change === "symlink") wal.stat.isFile = () => false;
    if (change === "journal") m.files.set(name + "-journal", wal);
    if (change === "shmsize") shm.stat.size = 65536;
    assert.throws(() => m.context.settleReadBoundary(root, phase, pins), /SIDECARS_UNEXPECTED/);
    assert.equal(m.ownerCalls, 0);
  }
});
check("main inode, hash or size drift refuses before owner", () => {
  for (const change of ["inode", "hash", "size"]) {
    const m = model(), pins = m.context.captureReadBoundary(root, phase); m.sidecars();
    const file = m.files.get(m.mainPaths[0]);
    if (change === "inode") file.stat.ino += 1;
    if (change === "hash") file.data = Buffer.from("changed");
    if (change === "size") file.stat.size += 1;
    assert.throws(() => m.context.settleReadBoundary(root, phase, pins), /MAIN_CHANGED/); assert.equal(m.ownerCalls, 0);
  }
});
check("replacement after validation refuses before writable owner", () => {
  let calls = 0, enabled = false;
  const m = model({ statHook: (name, files) => {
    if (enabled && name === m.mainPaths[0] + "-wal" && ++calls === 2) files.get(name).stat.ino += 10;
  } }), pins = m.context.captureReadBoundary(root, phase);
  m.sidecars(); enabled = true;
  assert.throws(() => m.context.settleReadBoundary(root, phase, pins), /SIDECAR_CHANGED/); assert.equal(m.ownerCalls, 0);
});
check("open and checkpoint failures preserve primary and always close existing owner", () => {
  for (const kind of ["openFailure", "checkpointFailure"]) {
    const error = new Error(kind), m = model({ [kind]: error }), pins = m.context.captureReadBoundary(root, phase); m.sidecars();
    assert.throws(() => m.context.settleReadBoundary(root, phase, pins), e => e === error);
    assert.equal(m.ownerCloses, kind === "openFailure" ? 0 : 1);
  }
});
check("checkpoint results, failed close, retained sidecars and changed mains never pass", () => {
  for (const options of [{ row: { busy: 1, log: 0, checkpointed: 0 } }, { row: { busy: 0, log: -1, checkpointed: -1 } },
    { row: { busy: 0, log: 1, checkpointed: 1 } }, { row: {} }, { closeFailure: new Error("close") },
    { retainSidecars: true }, { mainMutation: true }]) {
    const m = model(options), pins = m.context.captureReadBoundary(root, phase); m.sidecars();
    assert.throws(() => m.context.settleReadBoundary(root, phase, pins)); assert.equal(m.ownerCloses, 1);
  }
});
check("checkpoint plus close error retains both exact failures", () => {
  const first = new Error("checkpoint"), second = new Error("close"), m = model({ checkpointFailure: first, closeFailure: second });
  const pins = m.context.captureReadBoundary(root, phase); m.sidecars();
  assert.throws(() => m.context.settleReadBoundary(root, phase, pins), e => e instanceof AggregateError && e.errors[0] === first && e.errors[1] === second);
});
check("main read plus FD close failure retains both and closes descriptor", () => {
  const first = new Error("read"), second = new Error("fdclose"), m = model({ readFailure: first, fdCloseFailure: second });
  assert.throws(() => m.context.captureReadBoundary(root, phase), e => e instanceof AggregateError && e.errors[0] === first && e.errors[1] === second);
  assert.equal(m.descriptors.size, 0); assert.equal(m.ownerCalls, 0);
});
check("read-body and both readonly close failures are all retained", () => {
  const primary = new Error("body"), first = new Error("readclose1"), second = new Error("readclose2"), m = model();
  assert.throws(() => m.context.closeDatabases([{ close() { throw first; } }, { close() { throw second; } }], primary),
    e => e instanceof AggregateError && e.errors[0] === primary && e.errors[1] === first && e.errors[2] === second);
});
check("prepare/assert readers remain readonly and settlement follows successful close", () => {
  for (const [start, end, close, settle] of [["async function prepare(", "function assertPhase(",
    "closeDatabases([workboardRead, stateRead], readFailure);", 'settleReadBoundary(root, "predecessor", readBoundary);'],
    ["function assertPhase(", "async function migrateCandidate(", "closeDatabases([workboardDb, stateDb], readFailure);", "settleReadBoundary(root, phase, readBoundary);"]]) {
    const body = text.slice(text.indexOf(start), text.indexOf(end));
    assert(body.includes("{ readOnly: true }")); assert(body.indexOf(settle) > body.indexOf(close));
    assert(body.includes("readFailure = error;\n    throw error;\n  } finally {"));
  }
  assert(extract("settleReadBoundary").includes('owner.prepare("PRAGMA wal_checkpoint(TRUNCATE)")'));
  assert(!extract("settleReadBoundary").includes("unlink") && !extract("settleReadBoundary").includes("rmSync"));
});
process.stdout.write(JSON.stringify({ passed, sqliteExecution: false, entryPointExecution: false, permissionModelChanged: false }) + "\n");
