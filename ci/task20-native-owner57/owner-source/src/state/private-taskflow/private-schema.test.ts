import path from "node:path";
import { constants, DatabaseSync, StatementSync } from "node:sqlite";
import { afterEach, describe, expect, it, vi } from "vitest";
import { observeSqliteReadSql } from "../../../test/helpers/sqlite-statement-execution-counter.js";
import { useAutoCleanupTempDirTracker } from "../../../test/helpers/temp-dir.js";
import { enableNodeSqliteKyselyStatementCache } from "../../infra/kysely-sync-cache-state.js";
import { openNodeSqliteDatabase } from "../../infra/node-sqlite.js";
import { runSqlitePinnedReadSnapshotSync } from "../../infra/sqlite-pinned-read-snapshot.js";
import {
  admitSqliteSchema,
  getAdmittedSqliteSchemaContract,
  registerSqliteSchemaAdmissionContract,
  runSqliteReadOperationSync,
} from "../../infra/sqlite-schema-facts.js";
import { createSqliteWalReclamationResult } from "../../infra/sqlite-wal-reclamation.js";
import { openClawStateDatabaseCache, requireOpenClawStateDatabaseIdentity } from "../openclaw-state-db-cache.js";
import { openTrackedStateDatabase } from "../openclaw-state-db-handle.js";
import type { OpenClawStateDatabase } from "../openclaw-state-db-contract.js";
import {
  ensureTaskFlowWorkerLeaseSchema,
  registerTaskFlowWorkerLeaseSchemaAdmission,
  taskFlowWorkerLeaseSchemaSql,
} from "./private-schema.js";

describe("TaskFlow private schema uses native admission", () => {
  const tempDirs = useAutoCleanupTempDirTracker(afterEach);
  const databases: DatabaseSync[] = [];
  const namedIndexes = [
    "idx_task_flow_worker_leases_active_repository",
    "idx_task_flow_worker_leases_active_workspace",
    "idx_task_flow_worker_leases_active_capacity",
    "idx_task_flow_worker_lease_events_namespace_version",
  ];

  function prepared(sql = taskFlowWorkerLeaseSchemaSql, location = ":memory:") {
    const database = openNodeSqliteDatabase(location);
    databases.push(database);
    database.exec(sql);
    enableNodeSqliteKyselyStatementCache(database);
    registerTaskFlowWorkerLeaseSchemaAdmission(database);
    return database;
  }

  function admitted(sql = taskFlowWorkerLeaseSchemaSql, location = ":memory:") {
    const database = prepared(sql, location);
    admitSqliteSchema(database);
    return database;
  }

  function secondConnection(location: string) {
    // Deliberately untracked: emulate a genuinely foreign writer, not a sibling publication.
    const database = new DatabaseSync(location);
    databases.push(database);
    return database;
  }

  afterEach(() => {
    for (const database of databases.splice(0)) {
      if (database.isOpen) database.close();
    }
  });

  it("does not create missing private state or admit commands without it", () => {
    const database = admitted("CREATE TABLE ordinary(id INTEGER);");
    expect(() => ensureTaskFlowWorkerLeaseSchema(database)).toThrow("PRIVATE_SCHEMA_NOT_ADMITTED");
    expect(database.prepare("SELECT name FROM sqlite_schema WHERE name LIKE 'task_flow_%'").all()).toEqual([]);
  });

  it("admits complete four-table and four-index contracts", () => {
    expect(() => ensureTaskFlowWorkerLeaseSchema(admitted())).not.toThrow();
  });

  it.each(namedIndexes)("refuses missing named index %s at admission", (index) => {
    const database = prepared();
    database.exec(`DROP INDEX ${index}`);
    expect(() => admitSqliteSchema(database)).toThrow();
    expect(() => ensureTaskFlowWorkerLeaseSchema(database)).toThrow("PRIVATE_SCHEMA_NOT_ADMITTED");
  });

  it("refuses a drifted unique-index predicate", () => {
    const database = prepared();
    database.exec(`DROP INDEX idx_task_flow_worker_leases_active_repository;
      CREATE UNIQUE INDEX idx_task_flow_worker_leases_active_repository
      ON task_flow_worker_leases(namespace, repository_key) WHERE released_at_ms IS NOT NULL;`);
    expect(() => admitSqliteSchema(database)).toThrow();
  });

  it("preserves quoted constraint text instead of collapsing its whitespace", () => {
    const database = prepared(taskFlowWorkerLeaseSchemaSql.replace("'reconciliation_required'", "'reconciliation_ required'"));
    expect(() => admitSqliteSchema(database)).toThrow();
  });

  it("refuses a partial installation at admission", () => {
    const database = prepared("CREATE TABLE task_flow_native_bindings(lease_id TEXT PRIMARY KEY) STRICT;");
    expect(() => admitSqliteSchema(database)).toThrow();
  });

  it("does no private catalog checks across repeated commands and foreign data commits", () => {
    const filename = path.join(tempDirs.make("taskflow-admission-data-"), "state.sqlite");
    const reader = admitted(`${taskFlowWorkerLeaseSchemaSql}\nCREATE TABLE ordinary(id INTEGER);`, filename);
    reader.exec("PRAGMA journal_mode=WAL");
    // Consume native invalidation from setup before counting only hot-path work.
    ensureTaskFlowWorkerLeaseSchema(reader);
    const writer = secondConnection(filename);
    const observation = observeSqliteReadSql(StatementSync.prototype);
    try {
      for (let index = 0; index < 100; index += 1) {
        writer.prepare("INSERT INTO ordinary VALUES (?)").run(index);
        runSqliteReadOperationSync(reader, () => {
          ensureTaskFlowWorkerLeaseSchema(reader);
          ensureTaskFlowWorkerLeaseSchema(reader);
        });
      }
      expect(observation.queries.filter((sql) => /sqlite_schema|sqlite_master|pragma_table_info|pragma_index/iu.test(sql))).toEqual([]);
    } finally {
      observation.restore();
    }
  });

  it("rejects foreign index drift on the next unpinned use and accepts a repaired cold contract", () => {
    const filename = path.join(tempDirs.make("taskflow-admission-ddl-"), "state.sqlite");
    const reader = admitted(undefined, filename);
    reader.exec("PRAGMA journal_mode=WAL");
    ensureTaskFlowWorkerLeaseSchema(reader);
    const writer = secondConnection(filename);
    writer.exec("DROP INDEX idx_task_flow_worker_leases_active_capacity");
    expect(() => ensureTaskFlowWorkerLeaseSchema(reader)).toThrow();
    // Explicit synthetic maintenance, never runtime self-repair.
    writer.exec("CREATE INDEX idx_task_flow_worker_leases_active_capacity ON task_flow_worker_leases(namespace, released_at_ms, fencing_token)");
    expect(() => ensureTaskFlowWorkerLeaseSchema(reader)).not.toThrow();
  });

  it("honors a pinned snapshot before observing foreign drift", () => {
    const filename = path.join(tempDirs.make("taskflow-admission-snapshot-"), "state.sqlite");
    const reader = admitted(undefined, filename);
    reader.exec("PRAGMA journal_mode=WAL");
    ensureTaskFlowWorkerLeaseSchema(reader);
    const writer = secondConnection(filename);
    runSqlitePinnedReadSnapshotSync(reader, () => {
      ensureTaskFlowWorkerLeaseSchema(reader);
      writer.exec("DROP INDEX idx_task_flow_worker_leases_active_capacity");
      expect(() => ensureTaskFlowWorkerLeaseSchema(reader)).not.toThrow();
    });
    expect(() => ensureTaskFlowWorkerLeaseSchema(reader)).toThrow();
  });

  it("revokes speculative facts on rollback even if SQLite reuses a schema cookie", () => {
    const database = admitted();
    database.exec("BEGIN; DROP INDEX idx_task_flow_worker_leases_active_capacity");
    expect(() => ensureTaskFlowWorkerLeaseSchema(database)).toThrow();
    database.exec("ROLLBACK");
    expect(() => ensureTaskFlowWorkerLeaseSchema(database)).not.toThrow();
  });

  it("never transfers positive admission from a closed handle to a successor", () => {
    const predecessor = admitted();
    predecessor.close();
    expect(() => ensureTaskFlowWorkerLeaseSchema(predecessor)).toThrow("PRIVATE_SCHEMA_NOT_ADMITTED");
    expect(() => ensureTaskFlowWorkerLeaseSchema(admitted("CREATE TABLE ordinary(id INTEGER);"))).toThrow("PRIVATE_SCHEMA_NOT_ADMITTED");
    expect(() => ensureTaskFlowWorkerLeaseSchema(admitted())).not.toThrow();
  });

  it("rejects registration after publication", () => {
    const database = admitted();
    expect(() => registerSqliteSchemaAdmissionContract(database, { validate: () => true })).toThrow("unpublished tracked handle");
  });

  it("publishes no partial positive contract after a later validator refuses admission", () => {
    const database = prepared();
    const positive = Object.freeze({ validate: () => true });
    const refusal = new Error("synthetic later admission refusal");
    registerSqliteSchemaAdmissionContract(database, positive);
    registerSqliteSchemaAdmissionContract(database, { validate: () => { throw refusal; } });
    expect(() => admitSqliteSchema(database)).toThrow(refusal);
    expect(getAdmittedSqliteSchemaContract(database, positive)).toBeUndefined();
    expect(() => ensureTaskFlowWorkerLeaseSchema(database)).toThrow("PRIVATE_SCHEMA_NOT_ADMITTED");
  });

  it("refuses private runtime facts while a dynamic authorizer is installed", () => {
    const database = admitted();
    database.setAuthorizer(() => constants.SQLITE_OK);
    expect(() => ensureTaskFlowWorkerLeaseSchema(database)).toThrow("PRIVATE_SCHEMA_NOT_ADMITTED");
    database.setAuthorizer(null);
    expect(() => ensureTaskFlowWorkerLeaseSchema(database)).not.toThrow();
  });
  function unpublishedRefusalHandle(walClose: () => boolean): OpenClawStateDatabase {
    const filename = path.join(tempDirs.make("taskflow-admission-publication-"), "state.sqlite");
    const db = openTrackedStateDatabase(filename);
    databases.push(db);
    db.exec(taskFlowWorkerLeaseSchemaSql);
    db.exec("DROP INDEX idx_task_flow_worker_leases_active_capacity");
    enableNodeSqliteKyselyStatementCache(db);
    return {
      db,
      path: filename,
      walMaintenance: {
        checkpoint: () => false,
        close: walClose,
        reclaimFreePages: createSqliteWalReclamationResult,
      },
    };
  }

  it("actual native publisher closes an exact unpublished handle after private admission refusal", () => {
    const close = vi.fn(() => true);
    const database = unpublishedRefusalHandle(close);
    expect(() => openClawStateDatabaseCache.publishOpenClawStateDatabase(database, {})).toThrow();
    expect(close).toHaveBeenCalledOnce();
    expect(database.db.isOpen).toBe(false);
    expect(() => requireOpenClawStateDatabaseIdentity(database)).toThrow("no recorded database identity");
  });

  it("actual native publisher preserves admission and WAL cleanup failures while closing the handle", () => {
    const cleanupFailure = new Error("synthetic WAL-close failure");
    const close = vi.fn(() => { throw cleanupFailure; });
    const database = unpublishedRefusalHandle(close);
    let caught: unknown;
    try { openClawStateDatabaseCache.publishOpenClawStateDatabase(database, {}); }
    catch (error) { caught = error; }
    expect(caught).toBeInstanceOf(AggregateError);
    if (!(caught instanceof AggregateError)) throw new Error("Expected aggregate cleanup evidence");
    expect(caught.errors[0]).toBe(caught.cause);
    expect(caught.errors).toContain(cleanupFailure);
    expect(close).toHaveBeenCalledOnce();
    expect(database.db.isOpen).toBe(false);
    expect(() => requireOpenClawStateDatabaseIdentity(database)).toThrow("no recorded database identity");
  });
});
