import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { registerHooks } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";

const run = path.dirname(fileURLToPath(import.meta.url));
const base = path.dirname(run);
const source = "/work/source";
const fixture = "/fixture";
const closure = JSON.parse(fs.readFileSync("/work/control/expanded-closure-linux.json"));
const missingRoots = closure.directRootLinks.map((item) => item.name);
const sourceUrl = pathToFileURL(source + path.sep).href;
const anchor = pathToFileURL("/work/extra-anchor/anchor.mjs").href;
registerHooks({ resolve(specifier, context, nextResolve) {
  if (context.parentURL?.startsWith(sourceUrl) && missingRoots.some((name) => specifier === name || specifier.startsWith(name + "/"))) {
    return nextResolve(specifier, { ...context, parentURL: anchor });
  }
  return nextResolve(specifier, context);
} });

// Original native transaction owner, not a substitute BEGIN/COMMIT driver.
const { runStateSchemaMigrationTransaction } = await import(pathToFileURL(path.join(source, "src/state/openclaw-state-db-maintenance.ts")));
const { migrateTaskFlowWorktreeOwnerCheckInTransaction: migrate, classifyTaskFlowWorktreeOwnerCheck: classify } =
  await import("./compiled/migration-fixture-module.ts");
const { extractSqliteTableSchema } = await import(pathToFileURL(path.join(source, "src/infra/sqlite-schema-sql.ts")));
const targetSchema = fs.readFileSync(path.join(run, "compiled/openclaw-state-schema.sql"), "utf8");
const stockSchema = fs.readFileSync(path.join(source, "src/state/openclaw-state-schema.sql"), "utf8");
const block = (schema, table) => extractSqliteTableSchema(schema, table);
const stockTable = block(stockSchema, "worktrees");
const targetTable = block(targetSchema, "worktrees");
const indexes = [...targetSchema.matchAll(/CREATE INDEX IF NOT EXISTS idx_worktrees_\w+\s+ON worktrees\([^;]+\);/gu)].map((match) => match[0]).join("\n");
const cases = [];
const stable = (value) => JSON.stringify(value, (_, item) => typeof item === "bigint" ? { bigint: item.toString() } : item instanceof Uint8Array ? { hex: Buffer.from(item).toString("hex") } : item);
const snapshot = (db) => {
  const query = db.prepare("SELECT rowid AS implicit_rowid, * FROM worktrees ORDER BY rowid");
  query.setReadBigInts(true);
  return {
    rows: stable(query.all()),
    catalog: stable(db.prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name").all()),
    metadata: stable(db.prepare("SELECT * FROM schema_meta").all()),
    child: stable(db.prepare("SELECT * FROM synthetic_child").all()),
    chunks: stable(db.prepare("SELECT * FROM worktree_provisioned_file_chunks").all()),
    privateCustody: stable(db.prepare("SELECT * FROM synthetic_private_lease_custody").all()),
    unrelatedCatalog: stable(db.prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE tbl_name != 'worktrees' ORDER BY type,name").all()),
    schemaCookie: db.prepare("PRAGMA schema_version").get().schema_version,
    userVersion: db.prepare("PRAGMA user_version").get().user_version,
  };
};
let counter = 0;
function database(table = stockTable) {
  const filename = path.join(fixture, `synthetic-${++counter}.sqlite`);
  const db = new DatabaseSync(filename);
  db.exec(table + indexes + block(stockSchema, "schema_meta") + block(stockSchema, "config_machine_state") + block(stockSchema, "worktree_provisioned_file_chunks"));
  db.exec("PRAGMA user_version=19; PRAGMA foreign_keys=ON;");
  db.prepare("INSERT INTO schema_meta VALUES ('primary','global',19,NULL,'synthetic-pinned-v97',1,1)").run();
  db.prepare("INSERT INTO config_machine_state VALUES ('state.schema.contentVersion','19',1)").run();
  db.exec("CREATE TABLE synthetic_child (id TEXT PRIMARY KEY, worktree_id TEXT REFERENCES worktrees(id)) STRICT; CREATE TABLE synthetic_private_lease_custody (id TEXT PRIMARY KEY,payload BLOB NOT NULL) STRICT;");
  const insert = db.prepare("INSERT INTO worktrees (rowid,id,repo_fingerprint,repo_root,path,branch,base_ref,owner_kind,owner_id,snapshot_ref,provisioned_paths_json,created_at,last_active_at,removed_at,run_end_cleanup_json,gc_protection_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
  for (const [index, owner] of ["manual", "workboard", "session"].entries()) {
    const id = `fixture-${index}`;
    insert.run(9007199254740993n + BigInt(index), id, "fingerprint", "/synthetic/repo", "/synthetic/é/工作/" + id, "branch", "base", owner,
      index === 0 ? null : "owner", index === 0 ? null : "refs/openclaw/snapshots/fixture",
      index === 0 ? null : '[ "é", "nul\\u0000value" ]', 9007199254740900n, 9007199254740901n,
      index === 0 ? null : 9007199254740902n, index === 0 ? null : '{ "outcome" : "unknown" }',
      index === 0 ? null : '{ "revision" : "lease-generation-7", "reason" : "unknown authority — retain" }');
    db.prepare("INSERT INTO synthetic_child VALUES (?,?)").run("child-" + index, id);
    db.prepare("INSERT INTO worktree_provisioned_file_chunks VALUES (?, ?, 0, ?)").run(id, "binary-file", Buffer.from([0, 255, index, 127]));
  }
  db.prepare("INSERT INTO synthetic_private_lease_custody VALUES ('active-unknown',?)").run(Buffer.from([0, 255, 127, 1]));
  return { db, filename };
}
function transaction(db, filename, operation = () => migrate(db)) {
  return runStateSchemaMigrationTransaction(db, filename, operation, { busyTimeoutMs: 1000, databaseLabel: filename, operationLabel: "synthetic.taskflow-worktree-check" });
}
function test(name, operation) {
  operation(); cases.push({ name, status: "PASS" });
}
function refusal(name, modify, expectation = /TaskFlow worktree migration/u) {
  test(name, () => {
    const { db, filename } = database();
    try {
      modify(db); const before = snapshot(db);
      assert.throws(() => transaction(db, filename), expectation);
      assert.deepEqual(snapshot(db), before);
      assert.equal(db.isTransaction, false);
      assert.equal(db.prepare("PRAGMA foreign_keys").get().foreign_keys, 1);
    } finally { db.close(); }
  });
}
try {
  test("exact stock STRICT→target preserves rowids/all15 columns/JSON/binary/foreign keys/private custody and clean reopen", () => {
    let { db, filename } = database();
    const before = snapshot(db); assert.equal(classify(db), "stock");
    assert.equal(transaction(db, filename), true); assert.equal(classify(db), "target");
    const after = snapshot(db);
    for (const key of ["rows", "metadata", "child", "chunks", "privateCustody", "userVersion", "unrelatedCatalog"]) assert.equal(after[key], before[key]);
    assert.equal(db.prepare("PRAGMA foreign_key_check").get(), undefined);
    assert.equal(db.prepare("PRAGMA foreign_keys").get().foreign_keys, 1);
    db.close(); db = new DatabaseSync(filename);
    try { assert.equal(classify(db), "target"); assert.equal(snapshot(db).rows, before.rows); }
    finally { db.close(); }
  });
  test("exact target is idempotent without catalog/cookie/metadata/data changes", () => {
    const { db, filename } = database(targetTable);
    try { const before = snapshot(db); assert.equal(transaction(db, filename), false); assert.deepEqual(snapshot(db), before); }
    finally { db.close(); }
  });
  test("target accepts retained task-flow owner and preserves gc_protection_json", () => {
    const { db, filename } = database();
    try {
      transaction(db, filename);
      db.prepare("UPDATE worktrees SET owner_kind='task-flow' WHERE id='fixture-1'").run();
      assert.equal(db.prepare("SELECT gc_protection_json FROM worktrees WHERE id='fixture-1'").get().gc_protection_json,
        '{ "revision" : "lease-generation-7", "reason" : "unknown authority — retain" }');
    } finally { db.close(); }
  });
  refusal("unknown column refuses without mutation", db => db.exec("ALTER TABLE worktrees ADD COLUMN unknown TEXT"));
  refusal("missing gc column refuses without dropping protection", db => db.exec("ALTER TABLE worktrees DROP COLUMN gc_protection_json"));
  refusal("unknown index refuses", db => db.exec("CREATE INDEX custom_worktree_index ON worktrees(owner_id)"));
  refusal("missing canonical index refuses", db => db.exec("DROP INDEX idx_worktrees_removed_at"));
  refusal("attached trigger refuses", db => db.exec("CREATE TRIGGER custom_worktree_trigger AFTER INSERT ON worktrees BEGIN SELECT 1; END"));
  refusal("cross-table trigger referencing worktrees refuses", db => db.exec("CREATE TRIGGER custom_child_trigger AFTER INSERT ON synthetic_child BEGIN SELECT id FROM worktrees; END"));
  refusal("dependent view refuses", db => db.exec("CREATE VIEW custom_worktree_view AS SELECT id FROM worktrees"));
  refusal("existing migration artifact refuses", db => db.exec("CREATE TABLE worktrees_taskflow_owner_migration_new (id TEXT) STRICT"));
  refusal("wrong schema role refuses", db => db.exec("UPDATE schema_meta SET role='agent'"));
  refusal("metadata/published version mismatch refuses", db => db.exec("UPDATE schema_meta SET schema_version=18"));
  refusal("content version mismatch refuses", db => db.exec("UPDATE config_machine_state SET value_json='18'"));
  refusal("missing physical content marker refuses", db => db.exec("DELETE FROM config_machine_state WHERE state_key='state.schema.contentVersion'"));
  refusal("invalid physical content marker refuses", db => db.exec("UPDATE config_machine_state SET value_json='invalid'"));
  refusal("higher physical content marker refuses", db => db.exec("UPDATE config_machine_state SET value_json='20'"));
  test("non-STRICT preimage refuses without mutation", () => {
    const { db, filename } = database(stockTable.replace(") STRICT;", ");"));
    try { const before = snapshot(db); assert.throws(() => transaction(db, filename), /unknown table preimage/u); assert.deepEqual(snapshot(db), before); }
    finally { db.close(); }
  });
  test("closed synthetic archive restores original source/schema/data as one rollback copy", () => {
    let { db, filename } = database(); const before = snapshot(db); db.close();
    const archive = filename + ".sealed-backup"; fs.copyFileSync(filename, archive);
    db = new DatabaseSync(filename);
    try { assert.equal(transaction(db, filename), true); assert.equal(classify(db), "target"); } finally { db.close(); }
    const restored = filename + ".restored"; fs.copyFileSync(archive, restored);
    db = new DatabaseSync(restored);
    try { assert.equal(classify(db), "stock"); assert.deepEqual(snapshot(db), before); }
    finally { db.close(); }
  });
  test("no transaction refuses without mutation", () => {
    const { db } = database(); try { const before = snapshot(db); assert.throws(() => migrate(db), /maintenance transaction/u); assert.deepEqual(snapshot(db), before); } finally { db.close(); }
  });
  test("transaction without native foreign-key handling refuses", () => {
    const { db } = database(); try { const before = snapshot(db); db.exec("BEGIN IMMEDIATE"); assert.throws(() => migrate(db), /foreign-key handling/u); db.exec("ROLLBACK"); assert.deepEqual(snapshot(db), before); } finally { db.close(); }
  });
  for (const phase of ["CREATE TABLE worktrees_taskflow", "INSERT INTO worktrees_taskflow", "DROP TABLE worktrees", "ALTER TABLE worktrees_taskflow", "CREATE INDEX IF NOT EXISTS idx_worktrees_repo"]) {
    test("native transaction fault rollback after " + phase, () => {
      const { db, filename } = database();
      try {
        const before = snapshot(db); let injected = false;
        const handle = new Proxy(db, { get(target, property) {
          if (property === "exec") return sql => { target.exec(sql); if (sql.startsWith(phase)) { injected = true; throw new Error("synthetic fault after " + phase); } };
          const value = Reflect.get(target, property, target); return typeof value === "function" ? value.bind(target) : value;
        } });
        assert.throws(() => transaction(db, filename, () => migrate(handle)), /synthetic fault/u);
        assert.equal(injected, true); assert.deepEqual(snapshot(db), before);
        assert.equal(db.isTransaction, false); assert.equal(db.prepare("PRAGMA foreign_keys").get().foreign_keys, 1);
      } finally { db.close(); }
    });
  }
  const result = { status: "SYNTHETIC_NATIVE_MAINTENANCE_COMPONENT_PASS", cases, nativeTransactionOwner: "original pinned runStateSchemaMigrationTransaction", migrationHelper: "whole source with relative-import rebasing only", databaseFamilies: counter, realDataOpened: false, providersCalled: false, gatewayStarted: false, fullDoctorCallSiteExecuted: false, fullT06Accepted: false, all13CompleteGatesOpen: true };
  fs.writeFileSync(path.join(fixture, "component-result.json"), JSON.stringify(result, null, 2) + "\n");
  console.log(JSON.stringify({ status: result.status, testsPassed: cases.length, databaseFamilies: counter, fullT06Accepted: false }));
} catch (error) {
  fs.writeFileSync(path.join(fixture, "component-error.json"), JSON.stringify({ status: "SYNTHETIC_COMPONENT_FAILED", name: error.name, message: error.message, stack: error.stack, cases }, null, 2) + "\n");
  throw error;
}
