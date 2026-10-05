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
check("Doctor diagnostics retain warnings before later assertion failure", () => {
  const records = [], context = vm.createContext({ diagnosticState: { doctorResult: "NOT_CALLED", versions: {} }, process: { stderr: { write: raw => records.push(JSON.parse(raw)) } } });
  vm.runInContext(extract("captureDoctorResult"), context);
  context.captureDoctorResult({ warnings: ["Failed migrating shared state: synthetic reason"], changes: [] });
  assert.equal(records[0].warnings.entries[0].text, "Failed migrating shared state: synthetic reason");
  assert.equal(records[0].warnings.count, 1); assert.equal(records[0].warnings.entries[0].truncated, false);
  const migrate = text.slice(text.indexOf("async function migrateCandidate("), text.indexOf("function restore("));
  assert(migrate.indexOf("captureDoctorResult(result);") > migrate.indexOf('"doctor",'));
  assert(migrate.indexOf("captureDoctorResult(result);") < migrate.indexOf('assertPhase(root, "candidate",'));
  assert(migrate.indexOf('assertPhase(root, "predecessor");') < migrate.indexOf('"WORKBOARD_BYTES_CHANGED_BY_STATE_MIGRATION"'));
});
check("Doctor diagnostics bound escaped UTF-8 output and expose every truncation", () => {
  const raw = [], context = vm.createContext({ diagnosticState: { doctorResult: "NOT_CALLED", versions: {} }, process: { stderr: { write: row => raw.push(row) } } });
  vm.runInContext(extract("captureDoctorResult"), context);
  for (const character of ["\u0000", "\ud800", "\u{1f642}", "\"", "\\"]) {
    context.captureDoctorResult({ warnings: Array(100).fill(character.repeat(2000)), changes: Array(100).fill(character.repeat(2000)) });
    const row = raw.at(-1), record = JSON.parse(row);
    assert(Buffer.byteLength(row, "utf8") < 32768);
    assert.equal(record.warnings.count, 100); assert.equal(record.warnings.omittedEntries, 92);
    assert.equal(record.warnings.entries.length, 8); assert(record.warnings.entries.every(entry => entry.truncated && entry.text.length === 512));
    assert.equal(record.changes.omittedEntries, 96); assert.equal(record.changes.entries.length, 4);
    assert(record.changes.entries.every(entry => entry.truncated && entry.text.length === 256));
  }
});
check("all phases report the actual version before preserving strict version and metadata gates", () => {
  for (const phase of ["predecessor", "candidate", "rollback"]) {
    const expectedVersion = phase === "candidate" ? 19 : 17;
    for (const scenario of [{ actualVersion: 17, metadataDelta: 0 }, { actualVersion: 19, metadataDelta: 0 },
      { actualVersion: undefined, metadataDelta: 0 }, { actualVersion: expectedVersion, metadataDelta: -1 }]) {
      const { actualVersion, metadataDelta } = scenario;
      const records = [], owners = [], queries = [], events = [];
      class ReadonlyDatabase {
        constructor(name, options) { assert.equal(options.readOnly, true); this.name = name; owners.push(this); }
        prepare(sql) {
          queries.push(sql);
          if (sql === "PRAGMA user_version") return { get: () => ({ user_version: actualVersion }) };
          if (sql.startsWith("SELECT role,schema_version")) return { get: () => ({ role: "global", schema_version: expectedVersion + metadataDelta, agent_id: null }) };
          if (sql.startsWith("SELECT controller_id,status")) return { get: () => ({ controller_id: "mergeguez-pr-lifecycle/v1", status: "blocked" }) };
          throw new Error("unexpected query: " + sql);
        }
        close() { events.push("close"); }
      }
      const context = vm.createContext({ diagnosticState: { doctorResult: "NOT_CALLED", versions: {} }, SCHEMA: "invented", fs: { readFileSync: name => name.endsWith("manifest.json") ? JSON.stringify({ schema: "invented", syntheticOnly: true, state: {}, workboard: {}, files: {}, predecessorDbHashes: { state: "hash", workboard: "hash" }, workboardSchemaSha256: "schema" }) : "invented" },
        path, DatabaseSync: ReadonlyDatabase, sqlitePath: (_root, phase, which) => `${phase}/${which}`, requireConsolidated() {}, captureReadBoundary() {},
        settleReadBoundary() { events.push("settle"); }, assertIntegrity() {}, schemaDigest: () => "schema", WORKBOARD_TABLES: [], sha256: () => "hash", columns: () => ["controller_store_path", "requester_store_path"],
        process: { stdout: { write(raw) { records.push(JSON.parse(raw)); events.push("write"); } }, stderr: { write(raw) { records.push(JSON.parse(raw)); events.push("write"); } } }, AggregateError });
      vm.runInContext(extract("closeDatabases") + extract("captureStateVersion") + extract("captureFixtureFailure") + extract("assertPhase"), context);
      if (actualVersion !== expectedVersion) assert.throws(() => context.assertPhase(root, phase), /STATE_VERSION_MISMATCH/);
      else if (metadataDelta !== 0) assert.throws(() => context.assertPhase(root, phase), /STATE_METADATA_MISMATCH/);
      else context.assertPhase(root, phase);
      assert.equal(records[0].phase, phase); assert.equal(records[0].expectedVersion, expectedVersion);
      assert.equal(records[0].actualVersion, actualVersion ?? null); assert.equal(queries.filter(sql => sql === "PRAGMA user_version").length, 1);
      assert.equal(owners.length, 2); assert.equal(events.filter(event => event === "close").length, 2);
      assert(events.indexOf("write") < events.indexOf("close"));
      assert.equal(events.includes("settle"), actualVersion === expectedVersion && metadataDelta === 0);
      assert.equal(queries.some(sql => sql.startsWith("SELECT role,schema_version")), actualVersion === expectedVersion);
    }
  }
});
function failureModel(options = {}) {
  const records = [], events = [];
  let queries = 0, opens = 0, closes = 0;
  class ReadonlyDatabase {
    constructor(_name, settings) { assert.equal(settings.readOnly, true); opens += 1; }
    prepare(sql) {
      if (sql === "PRAGMA user_version") return { get() {
        queries += 1;
        if (options.queryError && (queries === 1 || options.queryAlwaysFails)) throw options.queryError;
        return { user_version: options.version ?? 19 };
      } };
      if (sql.startsWith("SELECT role,schema_version")) return { get: () => ({ role: "global", schema_version: 19, agent_id: null }) };
      if (sql.startsWith("SELECT controller_id,status")) return { get: () => ({ controller_id: "mergeguez-pr-lifecycle/v1", status: "blocked" }) };
      throw new Error(sql);
    }
    close() { closes += 1; events.push("close"); }
  }
  const context = vm.createContext({ diagnosticState: { doctorResult: "RETURNED_AND_CAPTURED", versions: {} },
    SCHEMA: "invented", fs: { readFileSync: () => JSON.stringify({ schema: "invented", syntheticOnly: true,
      state: {}, workboard: {}, files: {}, workboardSchemaSha256: "schema" }) }, path,
    DatabaseSync: ReadonlyDatabase, sqlitePath: (_root, phase, which) => `${phase}/${which}`,
    requireConsolidated() {}, captureReadBoundary() {}, settleReadBoundary() { events.push("settle"); },
    assertIntegrity() { events.push("integrity"); if (options.integrityError) throw options.integrityError; },
    schemaDigest: () => "schema", WORKBOARD_TABLES: [], columns: () => ["controller_store_path", "requester_store_path"],
    process: { stdout: { write: raw => records.push(JSON.parse(raw)) }, stderr: { write(raw) { records.push(JSON.parse(raw)); events.push("diagnostic"); } } }, AggregateError });
  vm.runInContext(["closeDatabases", "captureStateVersion", "captureFixtureFailure", "assertPhase"].map(extract).join("\n"), context);
  return { context, records, events, get queries() { return queries; }, get opens() { return opens; }, get closes() { return closes; } };
}
check("candidate version is retained before either existing migration guard fails", () => {
  for (const message of ["PREDECESSOR_BYTES_CHANGED:state", "WORKBOARD_BYTES_CHANGED_BY_STATE_MIGRATION"]) {
    const primary = new Error(message), m = failureModel({ version: 17 });
    assert.throws(() => m.context.assertPhase(root, "candidate", () => { m.events.push("guard"); throw primary; }), error => error === primary);
    m.context.captureFixtureFailure("migrate", primary);
    assert.equal(m.records[0].actualVersion, 17); assert.equal(m.records.at(-1).versions.candidate.actualVersion, 17);
    assert.equal(m.records.at(-1).doctorResult, "RETURNED_AND_CAPTURED");
    assert(m.events.indexOf("diagnostic") < m.events.indexOf("guard")); assert(!m.events.includes("integrity"));
    assert.equal(m.opens, 1); assert.equal(m.closes, 1); assert.equal(m.queries, 1);
  }
});
check("failed diagnostic read cannot replace the original integrity failure", () => {
  const primary = new Error("original integrity"), m = failureModel({ queryError: new Error("diagnostic read"), integrityError: primary });
  assert.throws(() => m.context.assertPhase(root, "candidate"), error => error === primary);
  assert.equal(m.records[0].availability, "READ_FAILED"); assert.equal(m.queries, 1);
  assert.equal(m.opens, 2); assert.equal(m.closes, 2); assert(!m.events.includes("settle"));
});
check("the original later version query still runs after a failed diagnostic read", () => {
  const m = failureModel({ queryError: new Error("diagnostic read") });
  m.context.assertPhase(root, "candidate");
  assert.equal(m.queries, 2); assert.equal(m.records[1].actualVersion, 19);
  assert.equal(m.records[1].availability, "CAPTURED_ON_ASSERTION"); assert(m.events.includes("settle"));
  const primary = new Error("original version query"), failed = failureModel({ queryError: primary, queryAlwaysFails: true });
  assert.throws(() => failed.context.assertPhase(root, "candidate"), error => error === primary);
  assert.equal(failed.queries, 2); assert.equal(failed.closes, 2); assert(!failed.events.includes("settle"));
});
check("bounded failure stderr distinguishes observed versions from unavailable Doctor results", () => {
  const raw = [], state = { doctorResult: "AWAITING_RETURN", versions: {} }, context = vm.createContext({ diagnosticState: state,
    process: { stderr: { write: row => raw.push(row) } } });
  vm.runInContext(extract("captureFixtureFailure"), context);
  context.captureFixtureFailure("migrate", new Error("before return"));
  let record = JSON.parse(raw.at(-1)); assert.equal(record.doctorResult, "THREW_BEFORE_RETURN; WARNINGS_UNAVAILABLE");
  assert.deepEqual(record.unobservedVersions, ["predecessor", "candidate", "rollback"]);
  for (const phase of ["predecessor", "candidate", "rollback"]) state.versions[phase] = {
    expectedVersion: phase === "candidate" ? 19 : 17, actualVersion: null,
    availability: "READ_FAILED", error: "\u0000".repeat(512),
  };
  context.captureFixtureFailure("\u0000".repeat(10000), "\u0000".repeat(10000));
  assert(Buffer.byteLength(raw.at(-1), "utf8") < 32768);
  record = JSON.parse(raw.at(-1)); assert.equal(record.command.length, 64); assert.equal(record.error.length, 512);
  assert.deepEqual(record.unobservedVersions, []);
  const tail = text.slice(text.indexOf("const [command, untrustedRoot"));
  assert(tail.includes("try { captureFixtureFailure(command, error); } catch {}\n  throw error;"));
});
check("Doctor returning is distinguished from formatter or sink failure", () => {
  const migrate = text.slice(text.indexOf("async function migrateCandidate("), text.indexOf("function restore("));
  const start = migrate.indexOf('  );\n', migrate.indexOf('const result = await')) + 5;
  const end = migrate.indexOf('  assertPhase(root, "candidate",');
  assert(start > 4 && end > start);
  const afterReturn = migrate.slice(start, end);
  for (const mode of ["formatter", "sink"]) {
    const primary = new Error(mode), records = [];
    let writes = 0;
    const state = { doctorResult: "AWAITING_RETURN", versions: {} };
    const context = vm.createContext({ diagnosticState: state,
      result: { warnings: mode === "formatter" ? [{ slice() { throw primary; } }] : [], changes: [] },
      process: { stderr: { write(raw) { if (mode === "sink" && ++writes === 1) throw primary; records.push(JSON.parse(raw)); } } } });
    vm.runInContext(extract("captureDoctorResult") + extract("captureFixtureFailure"), context);
    assert.throws(() => vm.runInContext(afterReturn, context), error => error === primary);
    context.captureFixtureFailure("migrate", primary);
    assert.equal(records.at(-1).doctorResult, "RETURNED; CAPTURE_UNAVAILABLE");
    assert.notEqual(records.at(-1).doctorResult, "THREW_BEFORE_RETURN; WARNINGS_UNAVAILABLE");
  }
});
process.stdout.write(JSON.stringify({ passed, sqliteExecution: false, entryPointExecution: false, permissionModelChanged: false }) + "\n");
