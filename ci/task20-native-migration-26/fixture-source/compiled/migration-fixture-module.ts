import type { DatabaseSync } from "node:sqlite";
import { normalizeSchemaSql, extractSqliteTableSchema, quoteSqliteIdentifier } from "file:///work/source/src/infra/sqlite-schema-sql.ts";
import { OPENCLAW_STATE_SCHEMA_SQL } from "file:///work/fixture-source/compiled/openclaw-state-schema.mjs";
import { OPENCLAW_STATE_SCHEMA_VERSION } from "file:///work/source/src/state/openclaw-state-db-contract.ts";

const TARGET_CHECK = "owner_kind IN ('manual', 'workboard', 'session', 'task-flow')";
const STOCK_CHECK = "owner_kind IN ('manual', 'workboard', 'session')";
const TEMP_TABLE = "worktrees_taskflow_owner_migration_new";
const COLUMNS = [
  "id", "repo_fingerprint", "repo_root", "path", "branch", "base_ref", "owner_kind",
  "owner_id", "snapshot_ref", "provisioned_paths_json", "created_at", "last_active_at",
  "removed_at", "run_end_cleanup_json", "gc_protection_json",
] as const;

function contract() {
  const target = extractSqliteTableSchema(OPENCLAW_STATE_SCHEMA_SQL, "worktrees");
  if (target.split(TARGET_CHECK).length !== 2 || target.includes(STOCK_CHECK)) {
    throw new Error("TaskFlow worktree migration requires the exact four-owner source contract");
  }
  const indexes = [...OPENCLAW_STATE_SCHEMA_SQL.matchAll(
    /CREATE INDEX IF NOT EXISTS (idx_worktrees_\w+)\s+ON worktrees\([^;]+\);/gu,
  )].map((match) => ({ name: match[1]!, sql: match[0] }));
  if (indexes.length !== 2) {
    throw new Error("TaskFlow worktree migration index contract is not recognized");
  }
  return { target, stock: target.replace(TARGET_CHECK, STOCK_CHECK), indexes };
}

/** Classifies only the exact catalog; never opens another handle or changes admission. */
export function classifyTaskFlowWorktreeOwnerCheck(db: DatabaseSync): "absent" | "stock" | "target" {
  const expected = contract();
  if (db.prepare("SELECT 1 FROM sqlite_schema WHERE name = ?").get(TEMP_TABLE)) {
    throw new Error("TaskFlow worktree migration artifact already exists; preserve and inspect it");
  }
  const row = db.prepare("SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'worktrees'").get();
  if (!row) {
    return "absent";
  }
  const sql = normalizeSchemaSql(String(row.sql));
  // SQLite ALTER TABLE RENAME emits the quoted table name. Admit that exact
  // spelling only; column/constraint/options remain the pinned contract.
  const spellings = (ddl: string) => [normalizeSchemaSql(ddl), normalizeSchemaSql(
    ddl.replace("CREATE TABLE IF NOT EXISTS worktrees", 'CREATE TABLE "worktrees"'),
  )];
  const kind = spellings(expected.target).includes(sql) ? "target"
    : spellings(expected.stock).includes(sql) ? "stock" : undefined;
  if (!kind) {
    throw new Error("TaskFlow worktree migration refuses an unknown table preimage");
  }
  const objects = db.prepare(
    "SELECT type, name, sql FROM sqlite_schema WHERE tbl_name = 'worktrees' AND sql IS NOT NULL AND type != 'table' ORDER BY name",
  ).all();
  if (objects.length !== expected.indexes.length || objects.some((object) =>
    object.type !== "index" || !expected.indexes.some((index) =>
      index.name === object.name && normalizeSchemaSql(index.sql) === normalizeSchemaSql(String(object.sql)),
    ),
  )) {
    throw new Error("TaskFlow worktree migration refuses unknown or missing attached objects");
  }
  const dependentObjects = db.prepare(
    "SELECT sql FROM sqlite_schema WHERE type IN ('view', 'trigger') AND sql IS NOT NULL",
  ).all();
  if (dependentObjects.some((object) => /\bworktrees\b/iu.test(String(object.sql)))) {
    throw new Error("TaskFlow worktree migration refuses unadmitted dependent views or triggers");
  }
  return kind;
}

/** Doctor calls this inside the native maintenance transaction, after owner admission. */
export function migrateTaskFlowWorktreeOwnerCheckInTransaction(db: DatabaseSync): boolean {
  if (!db.isTransaction || Number(db.prepare("PRAGMA foreign_keys").get()?.foreign_keys) !== 0) {
    throw new Error("TaskFlow worktree migration requires native maintenance transaction and foreign-key handling");
  }
  const marker = db.prepare("SELECT value_json FROM config_machine_state WHERE state_key = 'state.schema.contentVersion'").get();
  let contentVersion: unknown;
  try {
    contentVersion = marker && JSON.parse(String(marker.value_json));
  } catch {
    throw new Error("TaskFlow worktree migration requires an exact valid physical content19 marker");
  }
  const metadata = db.prepare("SELECT role, schema_version FROM schema_meta WHERE meta_key = 'primary'").get();
  if (metadata?.role !== "global" || metadata.schema_version !== OPENCLAW_STATE_SCHEMA_VERSION ||
      Number(db.prepare("PRAGMA user_version").get()?.user_version) !== OPENCLAW_STATE_SCHEMA_VERSION ||
      contentVersion !== OPENCLAW_STATE_SCHEMA_VERSION) {
    throw new Error("TaskFlow worktree migration requires the exact global state19 role/version contract");
  }
  const kind = classifyTaskFlowWorktreeOwnerCheck(db);
  if (kind === "target") {
    return false;
  }
  if (kind !== "stock") {
    throw new Error("TaskFlow worktree migration cannot recreate missing existing state");
  }
  const expected = contract();
  db.exec(expected.target.replace("CREATE TABLE IF NOT EXISTS worktrees", `CREATE TABLE ${TEMP_TABLE}`));
  const selected = ["rowid", ...COLUMNS].map(quoteSqliteIdentifier).join(", ");
  db.exec(`INSERT INTO ${TEMP_TABLE} (${selected}) SELECT ${selected} FROM worktrees;`);
  for (const [left, right] of [["worktrees", TEMP_TABLE], [TEMP_TABLE, "worktrees"]]) {
    if (db.prepare(`SELECT 1 AS differs FROM (SELECT ${selected} FROM ${left} EXCEPT SELECT ${selected} FROM ${right}) LIMIT 1`).get()) {
      throw new Error("TaskFlow worktree migration preserved-data comparison failed");
    }
  }
  db.exec("DROP TABLE worktrees;");
  db.exec(`ALTER TABLE ${TEMP_TABLE} RENAME TO worktrees;`);
  for (const index of expected.indexes) {
    db.exec(index.sql);
  }
  if (classifyTaskFlowWorktreeOwnerCheck(db) !== "target" ||
      db.prepare("PRAGMA foreign_key_check").get() ||
      db.prepare("PRAGMA integrity_check").get()?.integrity_check !== "ok") {
    throw new Error("TaskFlow worktree migration final catalog/integrity check failed");
  }
  // No version/role publication is invented: the native maintenance owner retains it.
  return true;
}
