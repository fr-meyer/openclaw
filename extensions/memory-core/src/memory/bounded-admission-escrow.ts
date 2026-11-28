import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import type { DatabaseSync } from "node:sqlite";
import { openNodeSqliteDatabase } from "openclaw/plugin-sdk/memory-core-host-engine-knn";
import { BOUNDED_MEMORY_SCHEMA } from "./bounded-admission-schema.js";
import {
  type BoundedMemoryPolicy,
  type BoundedMemoryEscrow,
  boundedMemoryAdmissionActive,
  assertBoundedMemoryOperation,
  validateBoundedMemoryPolicy,
  requireBoundedMemoryAdmission,
} from "./bounded-admission.js";
import type { MemoryIndexMeta } from "./manager-reindex-state.js";
// Called by explicit owner bootstrap before any manager acquisition. Persisted
// required owners fail closed even when an activation policy is absent/stale.
export function restoreBoundedMemoryRequirements(db: DatabaseSync) {
  db.exec(BOUNDED_MEMORY_SCHEMA);
  for (const row of db
    .prepare("SELECT agent FROM memory_operation_owners WHERE required=1")
    .all()) {
    if (!boundedMemoryAdmissionActive(String(row.agent))) {
      requireBoundedMemoryAdmission(String(row.agent));
    }
  }
}
type Allocation = { calls: number; mass: number; money: number };
type Phase = "forward" | "recovery";
// Narrow SQLite primitive: synchronous immediate transaction performs atomic
// compare-and-debit across manager instances. Never await inside this section.
export function createBoundedMemoryEscrow(
  db: DatabaseSync,
  sourcePolicy: BoundedMemoryPolicy,
  sourceAllocation: Record<Phase, Allocation>,
  admission?: { begin(): void; commit(): void },
) {
  validateBoundedMemoryPolicy(sourcePolicy);
  const policy = structuredClone(sourcePolicy);
  const allocation = structuredClone(sourceAllocation);
  for (const part of ["forward", "recovery"] as const) {
    const a = allocation[part];
    if (Object.keys(a).toSorted().join(",") !== "calls,mass,money") {
      throw new Error("allocation shape");
    }
    for (const n of Object.values(a)) {
      if (!Number.isSafeInteger(n) || n <= 0) {
        throw new Error("allocation");
      }
    }
  }
  const pin = createHash("sha256").update(JSON.stringify({ policy, allocation })).digest("hex");
  // Debit must survive process/power interruption before provider dispatch. This
  // explicit feature use strengthens only the owning SQLite connection.
  db.exec("PRAGMA synchronous=FULL");
  function tx<T>(run: () => T): T {
    db.exec("BEGIN IMMEDIATE");
    try {
      admission?.begin();
      const out = run();
      admission?.commit();
      db.exec("COMMIT");
      return out;
    } catch (e) {
      db.exec("ROLLBACK");
      throw e;
    }
  }
  tx(() => {
    db.exec(BOUNDED_MEMORY_SCHEMA);
    db.prepare(
      "INSERT INTO memory_operation_owners VALUES(?,1) ON CONFLICT(agent) DO UPDATE SET required=1",
    ).run(policy.agent);
    const old = db
      .prepare("SELECT policy_pin FROM memory_operation_escrow WHERE operation=?")
      .get(policy.operation);
    if (old && old.policy_pin !== pin) {
      throw new Error("policy drift");
    }
    if (!old) {
      db.prepare("INSERT INTO memory_operation_escrow VALUES(?,?,?,'forward',0,?,?,?,?,?,?)").run(
        policy.operation,
        pin,
        policy.expiresAt,
        allocation.forward.calls,
        allocation.forward.mass,
        allocation.forward.money,
        allocation.recovery.calls,
        allocation.recovery.mass,
        allocation.recovery.money,
      );
    }
  });
  function active(operation: string, phase: Phase, now: number) {
    const row = db
      .prepare("SELECT * FROM memory_operation_escrow WHERE operation=?")
      .get(operation);
    if (
      !row ||
      operation !== policy.operation ||
      !["forward", "recovery"].includes(phase) ||
      !Number.isSafeInteger(now) ||
      row.policy_pin !== pin ||
      row.stopped !== 0 ||
      row.phase !== phase ||
      now >= Number(row.expires)
    ) {
      throw new Error("inactive escrow");
    }
    return row;
  }
  return {
    assertActive(operation, phase, now) {
      active(operation, phase, now);
    },
    debit(operation, phase, root, need, now) {
      const admitted = tx(() => {
        const row = active(operation, phase, now);
        if (
          !root ||
          typeof root !== "string" ||
          Object.keys(need).toSorted().join(",") !== "calls,mass,money"
        ) {
          throw new Error("invalid debit");
        }
        for (const value of Object.values(need)) {
          if (!Number.isSafeInteger(value) || value <= 0) {
            throw new Error("invalid debit");
          }
        }
        if (Object.entries(need).some(([key, value]) => value > Number(row[phase + "_" + key]))) {
          db.prepare("UPDATE memory_operation_escrow SET stopped=1 WHERE operation=?").run(
            operation,
          );
          return false;
        }
        db.prepare("INSERT INTO memory_operation_debits VALUES(?,?,?,?,?,?)").run(
          operation,
          root,
          phase,
          need.calls,
          need.mass,
          need.money,
        );
        // Phase is a closed internal union, not a caller-supplied SQL identifier.
        if (phase === "forward") {
          db.prepare(
            "UPDATE memory_operation_escrow SET forward_calls=forward_calls-?,forward_mass=forward_mass-?,forward_money=forward_money-? WHERE operation=?",
          ).run(need.calls, need.mass, need.money, operation);
        } else {
          db.prepare(
            "UPDATE memory_operation_escrow SET recovery_calls=recovery_calls-?,recovery_mass=recovery_mass-?,recovery_money=recovery_money-? WHERE operation=?",
          ).run(need.calls, need.mass, need.money, operation);
        }
        return true;
      });
      if (!admitted) {
        throw new Error("budget");
      }
    },
    stop(operation) {
      if (operation !== policy.operation) {
        throw new Error("operation");
      }
      tx(() =>
        db.prepare("UPDATE memory_operation_escrow SET stopped=1 WHERE operation=?").run(operation),
      );
    },
    resumeOrdinary(operation) {
      if (operation !== policy.operation) {
        throw new Error("operation");
      }
      tx(() => {
        db.prepare("UPDATE memory_operation_escrow SET stopped=1 WHERE operation=?").run(operation);
        db.prepare("UPDATE memory_operation_owners SET required=0 WHERE agent=?").run(policy.agent);
      });
    },
    receipt(operation) {
      return {
        remaining: db
          .prepare("SELECT * FROM memory_operation_escrow WHERE operation=?")
          .get(operation),
        debits: db
          .prepare("SELECT * FROM memory_operation_debits WHERE operation=? ORDER BY root")
          .all(operation),
      };
    },
    recovery() {
      tx(() => {
        const row = db
          .prepare("SELECT phase FROM memory_operation_escrow WHERE operation=?")
          .get(policy.operation);
        if (row?.phase !== "forward" || Date.now() >= policy.expiresAt) {
          throw new Error("recovery transition");
        }
        db.prepare(
          "UPDATE memory_operation_escrow SET phase='recovery', stopped=0 WHERE operation=?",
        ).run(policy.operation);
      });
    },
  } satisfies BoundedMemoryEscrow;
}

// Manager-open boundary only, not request-time polling. Read-only discovery must
// precede the canonical writable owner open and all provider initialization.
export function assertBoundedMemoryDatabaseRegistration(path: string, agent: string) {
  if (!existsSync(path)) {
    return;
  }
  const db = openNodeSqliteDatabase(path, { readOnly: true });
  try {
    const table = db
      .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='memory_operation_owners'")
      .get();
    if (
      table &&
      db.prepare("SELECT required FROM memory_operation_owners WHERE agent=?").get(agent)
        ?.required === 1
    ) {
      if (!boundedMemoryAdmissionActive(agent)) {
        requireBoundedMemoryAdmission(agent);
      }
      assertBoundedMemoryOperation(agent);
    }
  } finally {
    db.close();
  }
}

export function readBoundedMemoryIndexMeta(path: string, agent: string): MemoryIndexMeta | null {
  assertBoundedMemoryOperation(agent);
  if (!existsSync(path)) {
    return null;
  }
  const db = openNodeSqliteDatabase(path, { readOnly: true });
  try {
    const table = db
      .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='memory_index_meta'")
      .get();
    if (!table) {
      return null;
    }
    const row = db
      .prepare("SELECT value FROM memory_index_meta WHERE key='memory_index_meta_v1'")
      .get();
    // SAFETY: writeMeta(meta: MemoryIndexMeta) JSON-serializes this owned index metadata row.
    return row && typeof row.value === "string" ? (JSON.parse(row.value) as MemoryIndexMeta) : null;
  } finally {
    db.close();
  }
}
