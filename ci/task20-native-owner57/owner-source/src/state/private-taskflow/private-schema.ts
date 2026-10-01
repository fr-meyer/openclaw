import type { DatabaseSync } from "node:sqlite";
import { assertSqliteSchemaContains } from "../../infra/sqlite-schema-contract.js";
import {
  getAdmittedSqliteSchemaContract,
  registerSqliteSchemaAdmissionContract,
  type SqliteSchemaAdmissionContract,
  type SqliteSchemaFacts,
} from "../../infra/sqlite-schema-facts.js";

// Preserve the three frozen213 DDL/index contracts and the reviewed native binding verbatim.
// No schema creation, migration, or SQL-normalization shortcut belongs to runtime commands.
export const nativeBindingSql = "CREATE TABLE IF NOT EXISTS task_flow_native_bindings (\n lease_id TEXT NOT NULL PRIMARY KEY,\n run_id TEXT NOT NULL UNIQUE,\n child_session_key TEXT NOT NULL,\n requester_session_key TEXT NOT NULL,\n entry_generation INTEGER NOT NULL CHECK(entry_generation>0),\n owner_generation TEXT NOT NULL,\n fencing_token INTEGER NOT NULL CHECK(fencing_token>0)\n) STRICT;";
export const taskFlowWorkerLeaseSchemaSql = "CREATE TABLE IF NOT EXISTS task_flow_worker_lease_namespaces (\n  namespace TEXT NOT NULL PRIMARY KEY,\n  next_fencing_token INTEGER NOT NULL DEFAULT 0 CHECK (next_fencing_token >= 0),\n  store_version INTEGER NOT NULL DEFAULT 0 CHECK (store_version >= 0),\n  updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0)\n) STRICT;\nCREATE TABLE IF NOT EXISTS task_flow_worker_leases (\n  lease_id TEXT NOT NULL PRIMARY KEY,\n  namespace TEXT NOT NULL CHECK (length(namespace) > 0),\n  controller_id TEXT NOT NULL CHECK (length(controller_id) > 0),\n  owner_key TEXT NOT NULL CHECK (length(owner_key) > 0),\n  flow_id TEXT NOT NULL CHECK (length(flow_id) > 0),\n  flow_revision INTEGER NOT NULL CHECK (flow_revision >= 0),\n  attempt_key TEXT NOT NULL CHECK (\n    length(attempt_key) = 64 AND attempt_key NOT GLOB '*[^0-9a-f]*'\n  ),\n  kind TEXT NOT NULL CHECK (length(kind) > 0),\n  repository_key TEXT NOT NULL CHECK (length(repository_key) > 0),\n  workspace_key TEXT NOT NULL CHECK (length(workspace_key) > 0),\n  holder_id TEXT NOT NULL CHECK (length(holder_id) > 0),\n  owner_generation TEXT NOT NULL CHECK (length(owner_generation) > 0),\n  canonical_task_identity TEXT CHECK (\n    canonical_task_identity IS NULL OR length(canonical_task_identity) > 0\n  ),\n  liveness TEXT NOT NULL CHECK (liveness IN ('unknown', 'live', 'terminal', 'cancelled', 'dead')),\n  state TEXT NOT NULL CHECK (state IN ('active', 'reconciliation_required', 'released')),\n  fencing_token INTEGER NOT NULL CHECK (fencing_token > 0),\n  acquired_at_ms INTEGER NOT NULL CHECK (acquired_at_ms >= 0),\n  updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0),\n  expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms >= 0),\n  released_at_ms INTEGER CHECK (\n    released_at_ms IS NULL OR released_at_ms >= acquired_at_ms\n  ),\n  terminal_evidence_digest TEXT CHECK (\n    terminal_evidence_digest IS NULL OR (\n      length(terminal_evidence_digest) = 71\n      AND terminal_evidence_digest GLOB 'sha256:*'\n      AND substr(terminal_evidence_digest, 8) NOT GLOB '*[^0-9a-f]*'\n    )\n  ),\n  CHECK (\n    (\n      state = 'released'\n      AND liveness IN ('terminal', 'cancelled', 'dead')\n      AND released_at_ms IS NOT NULL\n      AND terminal_evidence_digest IS NOT NULL\n    ) OR (\n      state <> 'released'\n      AND liveness IN ('unknown', 'live')\n      AND released_at_ms IS NULL\n      AND terminal_evidence_digest IS NULL\n    )\n  ),\n  UNIQUE (attempt_key)\n) STRICT;\nCREATE UNIQUE INDEX IF NOT EXISTS idx_task_flow_worker_leases_active_repository\n  ON task_flow_worker_leases(namespace, repository_key)\n  WHERE released_at_ms IS NULL;\nCREATE UNIQUE INDEX IF NOT EXISTS idx_task_flow_worker_leases_active_workspace\n  ON task_flow_worker_leases(namespace, workspace_key)\n  WHERE released_at_ms IS NULL;\nCREATE INDEX IF NOT EXISTS idx_task_flow_worker_leases_active_capacity\n  ON task_flow_worker_leases(namespace, released_at_ms, fencing_token);\nCREATE TABLE IF NOT EXISTS task_flow_worker_lease_events (\n  event_id INTEGER PRIMARY KEY,\n  namespace TEXT NOT NULL,\n  lease_id TEXT,\n  flow_id TEXT NOT NULL,\n  attempt_key TEXT NOT NULL CHECK (\n    length(attempt_key) = 64 AND attempt_key NOT GLOB '*[^0-9a-f]*'\n  ),\n  event_kind TEXT NOT NULL,\n  result TEXT NOT NULL,\n  fencing_token INTEGER,\n  store_version INTEGER NOT NULL CHECK (store_version > 0),\n  evidence_digest TEXT CHECK (\n    evidence_digest IS NULL OR (\n      length(evidence_digest) = 71\n      AND evidence_digest GLOB 'sha256:*'\n      AND substr(evidence_digest, 8) NOT GLOB '*[^0-9a-f]*'\n    )\n  ),\n  detail_json TEXT,\n  occurred_at_ms INTEGER NOT NULL CHECK (occurred_at_ms >= 0)\n) STRICT;\nCREATE INDEX IF NOT EXISTS idx_task_flow_worker_lease_events_namespace_version\n  ON task_flow_worker_lease_events(namespace, store_version, event_id);\nCREATE TABLE IF NOT EXISTS task_flow_native_bindings (\n lease_id TEXT NOT NULL PRIMARY KEY,\n run_id TEXT NOT NULL UNIQUE,\n child_session_key TEXT NOT NULL,\n requester_session_key TEXT NOT NULL,\n entry_generation INTEGER NOT NULL CHECK(entry_generation>0),\n owner_generation TEXT NOT NULL,\n fencing_token INTEGER NOT NULL CHECK(fencing_token>0)\n) STRICT;";
const privateTables = ["task_flow_worker_lease_namespaces", "task_flow_worker_leases", "task_flow_worker_lease_events", "task_flow_native_bindings"] as const;

const leaseSchemaAdmission: SqliteSchemaAdmissionContract = Object.freeze({
  validate: (database: DatabaseSync, facts: SqliteSchemaFacts) => {
    // Ordinary native state without this optional private owner remains usable.
    // A partially installed private schema must fail at admission, never fabricate missing state.
    if (!privateTables.some((name) => facts.tables.has(name))) {
      return false;
    }
    assertSqliteSchemaContains(
      database,
      "TaskFlow private lease schema",
      taskFlowWorkerLeaseSchemaSql,
    );
    return true;
  },
});

/** Called only by the native cold publisher, before admitSqliteSchema/exposure. */
export function registerTaskFlowWorkerLeaseSchemaAdmission(database: DatabaseSync): void {
  registerSqliteSchemaAdmissionContract(database, leaseSchemaAdmission);
}

/** Compatibility entry point for retained kernels: consume native prepared facts only. */
export function ensureTaskFlowWorkerLeaseSchema(database: DatabaseSync): void {
  if (getAdmittedSqliteSchemaContract(database, leaseSchemaAdmission) !== true) {
    throw new Error("PRIVATE_SCHEMA_NOT_ADMITTED");
  }
}
