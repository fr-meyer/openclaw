import fs from "node:fs/promises";
import path from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import * as snapshots from "../../infra/sqlite-snapshot-source.js";
import { createUserTurnTranscriptRecorder } from "../../sessions/user-turn-transcript.js";
import {
  recordAgentDatabaseAdmissions,
  readAgentDatabaseAdmissionRefusal,
  assertAgentDatabaseAdmitted,
} from "../../state/agent-database-admission.js";
import { withArtifactPreservingStateReads } from "../../state/artifact-preserving-state-reads.js";
import {
  openOpenClawAgentDatabase,
  closeOpenClawAgentDatabaseByPathAsync,
  borrowCommittedOpenClawAgentDatabaseIfOpen,
  runOpenClawAgentWriteTransaction,
} from "../../state/openclaw-agent-db.js";
import { withOpenClawTestState } from "../../test-utils/openclaw-test-state.js";
import { replaceSessionEntry } from "./session-accessor.sqlite-entry.js";
import {
  readOwnedWarmSessionSnapshotSync,
  readTranscriptExportSnapshotReadOnlySync,
} from "./session-accessor.sqlite-read.js";
import { replaceTranscriptEvents } from "./session-accessor.sqlite-transcript-write.js";
import * as coldReads from "./session-cold-storage-read.js";
import { runSessionColdStorageMaintenance } from "./session-cold-storage.js";
import { runWithSessionTranscriptReadFence } from "./session-transcript-read-fence.js";
import { waitForSessionTranscriptIndexReconcile } from "./session-transcript-reconcile.js";
afterEach(() => vi.restoreAllMocks());
async function fixture(run: (value: Awaited<ReturnType<typeof arrange>>) => Promise<void>) {
  await withOpenClawTestState({ label: "owned-warm-receipt", scenario: "minimal" }, async (state) =>
    run(await arrange(state.env)),
  );
}
async function arrange(env: NodeJS.ProcessEnv) {
  const target = {
    agentId: "main",
    sessionId: "warm-owner",
    sessionKey: "agent:main:warm-owner",
    env,
  };
  await replaceSessionEntry(target, { sessionId: target.sessionId, updatedAt: 1 });
  await replaceTranscriptEvents(target, [
    { type: "session", id: target.sessionId, version: 3 },
    {
      type: "message",
      id: "user",
      timestamp: 1,
      message: { role: "user", content: "synthetic warm native owner" },
    },
  ]);
  await waitForSessionTranscriptIndexReconcile({ agentId: "main", env });
  const database = openOpenClawAgentDatabase({ agentId: "main", env });
  return { target: { ...target, storePath: database.path }, database };
}
it("reads actual committed native events with strict binding and no new connection/artifact/SQL mutation", async () => {
  await fixture(async ({ target, database }) => {
    const ordinary = readTranscriptExportSnapshotReadOnlySync(target);
    const baseline = database.db.prepare("SELECT total_changes() AS n").get();
    const files = await fs.readdir(path.dirname(database.path));
    const opener = vi.spyOn(snapshots, "openSqliteReadOnlyDatabase");
    const restore = vi.spyOn(coldReads, "readRestoredSessionTranscript");
    const observed = readOwnedWarmSessionSnapshotSync(target);
    expect(observed.status).toBe("observed-not-atomic");
    if (observed.status !== "observed-not-atomic") {
      throw new Error("native receipt missing");
    }
    expect(observed.value.events).toEqual(ordinary?.events);
    expect(observed.value.stats).toEqual(ordinary?.stats);
    expect(observed.receipt).toMatchObject({
      nativeOwner: "existing-committed",
      noMaterialization: true,
      nativeOpenedHandleIdentity: false,
    });
    expect(database.db.prepare("SELECT total_changes() AS n").get()).toEqual(baseline);
    expect(await fs.readdir(path.dirname(database.path))).toEqual(files);
    expect(opener).not.toHaveBeenCalled();
    expect(restore).not.toHaveBeenCalled();
    expect(database.db.isOpen).toBe(true);
  });
});
it("refuses wrong key/id/agent/store and leaves the native owner open after errors", async () => {
  await fixture(async ({ target, database }) => {
    for (const override of [
      { sessionId: "foreign" },
      { sessionKey: "agent:main:foreign" },
      { sessionKey: "agent:other:warm-owner" },
      { agentId: "other" },
      { storePath: path.join(path.dirname(database.path), "foreign.sqlite") },
    ]) {
      expect(readOwnedWarmSessionSnapshotSync({ ...target, ...override }).status).toBe(
        "unverified",
      );
      expect(database.db.isOpen).toBe(true);
      expect(database.db.isTransaction).toBe(false);
    }
    expect(readOwnedWarmSessionSnapshotSync(target).status).toBe("observed-not-atomic");
  });
});
it("refuses aliased physical stores and foreign captured storage namespace", async () => {
  await fixture(async ({ target, database }) => {
    const alias = database.path + ".alias";
    await fs.symlink(database.path, alias);
    expect(readOwnedWarmSessionSnapshotSync({ ...target, storePath: alias }).status).toBe(
      "unverified",
    );
    expect(
      readOwnedWarmSessionSnapshotSync({
        ...target,
        env: {
          ...target.env,
          OPENCLAW_STATE_DIR: path.join(path.dirname(database.path), "foreign-state"),
        },
      }).status,
    ).toBe("unverified");
    expect(database.db.isOpen).toBe(true);
  });
});
it("rejects active transactions and inspection scopes without companions, fresh opens or snapshots", async () => {
  await fixture(async ({ target, database }) => {
    const opener = vi.spyOn(snapshots, "openSqliteReadOnlyDatabase");
    database.db.exec("BEGIN");
    try {
      expect(readOwnedWarmSessionSnapshotSync(target).status).toBe("unverified");
    } finally {
      database.db.exec("ROLLBACK");
    }
    expect(
      withArtifactPreservingStateReads(() => readOwnedWarmSessionSnapshotSync(target), {
        agentDatabases: true,
      }).status,
    ).toBe("unverified");
    expect(opener).not.toHaveBeenCalled();
    expect(database.db.isOpen).toBe(true);
    const lease = borrowCommittedOpenClawAgentDatabaseIfOpen({
      agentId: "main",
      path: database.path,
      env: target.env,
    });
    lease.release();
    lease.release();
    expect(database.db.isOpen).toBe(true);
  });
});
it("requires a real already admitted native owner rather than a caller locator", async () => {
  await fixture(async ({ target, database }) => {
    await closeOpenClawAgentDatabaseByPathAsync(database.path, target.agentId);
    const opener = vi.spyOn(snapshots, "openSqliteReadOnlyDatabase");
    expect(readOwnedWarmSessionSnapshotSync(target).status).toBe("unverified");
    expect(opener).not.toHaveBeenCalled();
  });
});
it("refuses a genuinely native cold transcript without restoring or materializing", async () => {
  await fixture(async ({ target }) => {
    runOpenClawAgentWriteTransaction(
      ({ db }) => {
        db.prepare(
          "UPDATE session_windows SET updated_at = 1, transcript_updated_at = 1 WHERE session_id = ?",
        ).run(target.sessionId);
      },
      { agentId: "main", env: target.env },
    );
    await runSessionColdStorageMaintenance({
      config: {
        agents: { entries: { main: {} } },
        session: {
          store: target.storePath,
          maintenance: { coldStorage: { enabled: true, afterDays: 30 } },
        },
      },
    });
    const database = openOpenClawAgentDatabase({ agentId: "main", env: target.env });
    expect(
      database.db
        .prepare("SELECT session_id FROM session_transcript_cold_archives WHERE session_id = ?")
        .get(target.sessionId),
    ).toBeDefined();
    const restore = vi.spyOn(coldReads, "readRestoredSessionTranscript");
    const opener = vi.spyOn(snapshots, "openSqliteReadOnlyDatabase");
    expect(readOwnedWarmSessionSnapshotSync(target).status).toBe("unverified");
    expect(restore).not.toHaveBeenCalled();
    expect(opener).not.toHaveBeenCalled();
    expect(database.db.isOpen).toBe(true);
  });
});

it("refuses an incompatible live native schema without repair or closing the owner", async () => {
  await fixture(async ({ target, database }) => {
    const version = database.db.prepare("PRAGMA user_version").get()?.user_version;
    database.db.exec("PRAGMA user_version = 2147483647");
    try {
      expect(readOwnedWarmSessionSnapshotSync(target).status).toBe("unverified");
      expect(database.db.isOpen).toBe(true);
    } finally {
      database.db.exec("PRAGMA user_version = " + String(version));
    }
  });
});

it("refuses a quiescent native canonical file replacement while original owner remains open", async () => {
  await fixture(async ({ target, database }) => {
    await withOpenClawTestState(
      { label: "replacement-native-B", scenario: "minimal" },
      async (state) => {
        const other = await arrange(state.env);
        await replaceTranscriptEvents(other.target, [
          { type: "session", id: target.sessionId, version: 3 },
          {
            type: "message",
            id: "other-user",
            timestamp: 2,
            message: { role: "user", content: "different native B contents" },
          },
        ]);
        await waitForSessionTranscriptIndexReconcile({ agentId: "main", env: state.env });
        expect(
          JSON.stringify(readTranscriptExportSnapshotReadOnlySync(other.target)?.events),
        ).toContain("different native B contents");
        await closeOpenClawAgentDatabaseByPathAsync(other.database.path, "main");
        const retained = database.path + ".retained-A";
        await fs.rename(database.path, retained);
        await fs.rename(other.database.path, database.path);
        try {
          const baseline = await fs.readdir(path.dirname(database.path));
          const opener = vi.spyOn(snapshots, "openSqliteReadOnlyDatabase");
          const restore = vi.spyOn(coldReads, "readRestoredSessionTranscript");
          expect(readOwnedWarmSessionSnapshotSync(target).status).toBe("unverified");
          expect(database.db.isOpen).toBe(true);
          expect(database.db.isTransaction).toBe(false);
          expect(opener).not.toHaveBeenCalled();
          expect(restore).not.toHaveBeenCalled();
          expect(await fs.readdir(path.dirname(database.path))).toEqual(baseline);
        } finally {
          await fs.rename(database.path, other.database.path);
          await fs.rename(retained, database.path);
        }
      },
    );
  });
});
it("keeps actual owner refusal effective through same-physical state aliases", async () => {
  await fixture(async ({ target, database }) => {
    const root = target.env.OPENCLAW_STATE_DIR;
    if (!root) {
      throw new Error("isolated state missing");
    }
    const alias = path.join(root, "same-state-alias");
    await fs.symlink(root, alias, "dir");
    const refusal = {
      agentId: "main",
      paths: [database.path],
      code: "agent-database-inspection-failed" as const,
      reason: "synthetic native owner refusal",
      repairHint: "synthetic fixture only",
    };
    recordAgentDatabaseAdmissions([refusal], { env: target.env });
    expect(() => assertAgentDatabaseAdmitted("main", { env: target.env })).toThrow();
    const baseline = await fs.readdir(path.dirname(database.path));
    const opener = vi.spyOn(snapshots, "openSqliteReadOnlyDatabase");
    const restore = vi.spyOn(coldReads, "readRestoredSessionTranscript");
    expect(readOwnedWarmSessionSnapshotSync(target).status).toBe("unverified");
    expect(
      readOwnedWarmSessionSnapshotSync({
        ...target,
        env: { ...target.env, OPENCLAW_STATE_DIR: alias },
      }).status,
    ).toBe("unverified");
    expect(readAgentDatabaseAdmissionRefusal("main", { env: target.env })).toBe(refusal);
    expect(database.db.isOpen).toBe(true);
    expect(database.db.isTransaction).toBe(false);
    expect(opener).not.toHaveBeenCalled();
    expect(restore).not.toHaveBeenCalled();
    expect(await fs.readdir(path.dirname(database.path))).toEqual(baseline);
  });
});

it("matches ordinary export at a real native admitted user-turn boundary", async () => {
  await fixture(async ({ target }) => {
    const recorder = createUserTurnTranscriptRecorder({
      target: { ...target, sessionEntry: undefined },
      input: { text: "current admitted input must stay hidden", timestamp: 2 },
      updateMode: "none",
    });
    await recorder.persistApproved();
    const admission = recorder.getAdmissionReceipt();
    if (!admission) {
      throw new Error("native admission missing");
    }
    const later = createUserTurnTranscriptRecorder({
      target: { ...target, sessionEntry: undefined },
      input: { text: "later input must stay hidden", timestamp: 3 },
      updateMode: "none",
    });
    await later.persistApproved();
    runWithSessionTranscriptReadFence(admission, () => {
      const ordinary = readTranscriptExportSnapshotReadOnlySync(target);
      const observed = readOwnedWarmSessionSnapshotSync(target);
      expect(observed.status).toBe("observed-not-atomic");
      if (observed.status !== "observed-not-atomic") {
        throw new Error("native snapshot unavailable");
      }
      expect(observed.value.events).toEqual(ordinary?.events);
      expect(JSON.stringify(observed.value.events)).toContain("synthetic warm native owner");
      expect(JSON.stringify(observed.value.events)).not.toContain(
        "current admitted input must stay hidden",
      );
      expect(JSON.stringify(observed.value.events)).not.toContain("later input must stay hidden");
    });
    await replaceTranscriptEvents(target, [{ type: "session", id: target.sessionId, version: 3 }]);
    runWithSessionTranscriptReadFence(admission, () => {
      expect(() => readTranscriptExportSnapshotReadOnlySync(target)).toThrow();
      expect(readOwnedWarmSessionSnapshotSync(target)).toEqual({
        status: "unverified",
        reason: "native-warm-owner-snapshot-unavailable",
      });
    });
  });
});
