import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  releaseExitedOpenClawAgentDatabaseLeaseInDatabase,
  type OpenClawAgentDatabaseWorkerLeaseReceipt,
} from "./openclaw-agent-db-lease.js";

const verification = vi.hoisted(() => ({ clear: vi.fn() }));

// The actual lease owner and Kysely queries run against native in-memory SQLite.
// Only the separate integrity-store side effect is replaced; no file is opened.
vi.mock("./openclaw-quarantine-store.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./openclaw-quarantine-store.js")>()),
  clearOpenClawAgentIntegrityVerification: verification.clear,
}));

const syntheticStateDir = path.join(os.tmpdir(), "openclaw-exited-lease-owner-fixture");
const receipt: OpenClawAgentDatabaseWorkerLeaseReceipt = {
  leaseId: "exited-lease",
  agentId: "synthetic-agent",
  path: path.join(syntheticStateDir, "agent.sqlite"),
  ownerPid: 12345,
  ownerStartTime: 1000,
  sharedStatePath: path.join(syntheticStateDir, "state", "openclaw.sqlite"),
  sharedStateIdentity: "file:synthetic-state",
};

let database: DatabaseSync;

function leaseIds() {
  return database.prepare("SELECT lease_id FROM agent_database_leases ORDER BY lease_id").all();
}

beforeEach(() => {
  verification.clear.mockReset();
  database = new DatabaseSync(":memory:");
  database.exec(`CREATE TABLE agent_database_leases (
    lease_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    path TEXT NOT NULL,
    owner_pid INTEGER NOT NULL,
    owner_start_time INTEGER,
    provenance TEXT,
    opened_at INTEGER NOT NULL
  )`);
  // Synthetic bootstrap rows only. Both leases share a path, so clearing its
  // verification is conservative while deleting another owner's lease is not.
  const insert = database.prepare("INSERT INTO agent_database_leases VALUES (?, ?, ?, ?, ?, ?, ?)");
  insert.run(
    receipt.leaseId,
    receipt.agentId,
    receipt.path,
    receipt.ownerPid,
    receipt.ownerStartTime,
    null,
    0,
  );
  insert.run("surviving-lease", receipt.agentId, receipt.path, 23456, 2000, null, 0);
  // The real caller owns this transaction through joined native-worker exit.
  database.exec("BEGIN");
});

afterEach(() => {
  try {
    if (database.isTransaction) {
      database.exec("ROLLBACK");
    }
  } finally {
    database.close();
  }
});

describe("exited agent lease database-owner cleanup", () => {
  it("retains verification for a proved refusal before native open", () => {
    const invalidate = vi.fn();
    releaseExitedOpenClawAgentDatabaseLeaseInDatabase(
      database,
      receipt,
      "refused-before-open",
      invalidate,
    );
    expect(invalidate).not.toHaveBeenCalled();
    expect(verification.clear).not.toHaveBeenCalled();
    expect(leaseIds()).toEqual([{ lease_id: "surviving-lease" }]);
  });

  it("revokes verification for an unknown outcome and deletes only the exact lease", () => {
    const invalidate = vi.fn(() => {
      expect(leaseIds()).toEqual([{ lease_id: "exited-lease" }, { lease_id: "surviving-lease" }]);
    });
    releaseExitedOpenClawAgentDatabaseLeaseInDatabase(database, receipt, "unknown", invalidate);
    expect(invalidate).toHaveBeenCalledTimes(1);
    expect(verification.clear).toHaveBeenCalledExactlyOnceWith(
      receipt.path,
      { OPENCLAW_STATE_DIR: syntheticStateDir },
      "revoke",
    );
    expect(leaseIds()).toEqual([{ lease_id: "surviving-lease" }]);
  });

  it.each([
    { label: "agent", changes: { agentId: "different-agent" } },
    { label: "path", changes: { path: path.join(syntheticStateDir, "other.sqlite") } },
    { label: "PID", changes: { ownerPid: 34567 } },
    { label: "process start", changes: { ownerStartTime: 3000 } },
  ])("refuses a mismatched $label without deleting or invalidating", ({ changes }) => {
    const invalidate = vi.fn();
    expect(() =>
      releaseExitedOpenClawAgentDatabaseLeaseInDatabase(
        database,
        { ...receipt, ...changes },
        "unknown",
        invalidate,
      ),
    ).toThrow("lease cleanup receipt no longer matches");
    expect(invalidate).not.toHaveBeenCalled();
    expect(verification.clear).not.toHaveBeenCalled();
    expect(leaseIds()).toEqual([{ lease_id: "exited-lease" }, { lease_id: "surviving-lease" }]);
  });

  it("is idempotent for a missing lease without touching surviving owners", () => {
    const invalidate = vi.fn();
    releaseExitedOpenClawAgentDatabaseLeaseInDatabase(
      database,
      { ...receipt, leaseId: "missing-lease" },
      "unknown",
      invalidate,
    );
    expect(invalidate).not.toHaveBeenCalled();
    expect(verification.clear).not.toHaveBeenCalled();
    expect(leaseIds()).toEqual([{ lease_id: "exited-lease" }, { lease_id: "surviving-lease" }]);
  });

  it("retains the lease if invalidation authority refuses", () => {
    const failure = new Error("synthetic invalidation refusal");
    expect(() =>
      releaseExitedOpenClawAgentDatabaseLeaseInDatabase(database, receipt, "unknown", () => {
        throw failure;
      }),
    ).toThrow(failure);
    expect(verification.clear).not.toHaveBeenCalled();
    // Inspect inside the original transaction: a rollback cannot hide an early delete.
    expect(leaseIds()).toEqual([{ lease_id: "exited-lease" }, { lease_id: "surviving-lease" }]);
  });
});
