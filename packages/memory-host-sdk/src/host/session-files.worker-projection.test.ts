import fsSync from "node:fs";
import { afterEach, expect, it, vi } from "vitest";
import { replaceSessionEntry } from "../../../../src/config/sessions/session-accessor.sqlite-entry.js";
import { replaceTranscriptEvents } from "../../../../src/config/sessions/session-accessor.sqlite-transcript-write.js";
import { runWithSessionTranscriptReadFence } from "../../../../src/config/sessions/session-transcript-read-fence.js";
import { waitForSessionTranscriptIndexReconcile } from "../../../../src/config/sessions/session-transcript-reconcile.js";
import * as sqliteSnapshots from "../../../../src/infra/sqlite-snapshot-source.js";
import { WorkerTaskPool } from "../../../../src/infra/worker-task-pool.js";
import { createUserTurnTranscriptRecorder } from "../../../../src/sessions/user-turn-transcript.js";
import {
  openOpenClawAgentDatabase,
  closeOpenClawAgentDatabaseByPathAsync,
  runOpenClawAgentWriteTransaction,
} from "../../../../src/state/openclaw-agent-db.js";
import { withOpenClawTestState } from "../../../../src/test-utils/openclaw-test-state.js";
import { captureSensitiveTextRedactionSnapshot } from "./openclaw-runtime-io.js";
import * as runtime from "./openclaw-runtime-session.js";
import { prepareSessionColdStateInHost } from "./session-files.cold-host.test-support.js";
import {
  buildSessionEntry,
  buildSessionEntryInProcess,
  buildSessionEntryFromSnapshot,
  computeSessionEntryProjectionData,
  readSessionEntryResetRecallCutoff,
} from "./session-files.js";
afterEach(() => vi.restoreAllMocks());
async function fixture(run: (value: Awaited<ReturnType<typeof arrange>>) => Promise<void>) {
  await withOpenClawTestState(
    { label: "sdk-native-worker-projection", scenario: "minimal" },
    async (state) => run(await arrange(state.env)),
  );
}
async function arrange(env: NodeJS.ProcessEnv) {
  const target = {
    agentId: "main",
    sessionId: "worker-native",
    sessionKey: "agent:main:worker-native",
    env,
  };
  await replaceSessionEntry(target, { sessionId: target.sessionId, updatedAt: 1 });
  await replaceTranscriptEvents(target, [
    { type: "session", id: target.sessionId, version: 3 },
    { type: "reset", id: "reset" },
    {
      type: "message",
      id: "user",
      timestamp: 1000,
      message: { role: "user", content: "genuine native worker data" },
    },
  ]);
  await waitForSessionTranscriptIndexReconcile({ agentId: "main", env });
  const database = openOpenClawAgentDatabase({ agentId: "main", env });
  return { target: { ...target, storePath: database.path }, database };
}
it("uses real native selected data and real transcript worker for full shared projection parity", async () => {
  await fixture(async ({ target, database }) => {
    const ordinary = await buildSessionEntryInProcess(database.path, target);
    const total = database.db.prepare("SELECT total_changes() AS n").get();
    const run = vi.spyOn(WorkerTaskPool.prototype, "run");
    const restore = vi.spyOn(runtime, "readRestoredSessionTranscript");
    const projected = await buildSessionEntry(database.path, {
      ...target,
      readPolicy: "no-restore",
    });
    expect(projected).toEqual(ordinary);
    if (!projected || !ordinary) {
      throw new Error("projection missing");
    }
    expect(readSessionEntryResetRecallCutoff(projected)).toEqual(
      readSessionEntryResetRecallCutoff(ordinary),
    );
    expect(
      run.mock.calls.some(
        ([job]) => (job as { kind?: string }).kind === "session-entry-projection",
      ),
    ).toBe(true);
    expect(database.db.prepare("SELECT total_changes() AS n").get()).toEqual(total);
    expect(restore).not.toHaveBeenCalled();
  });
});
it("fails native key/namespace/owner admission before any worker enqueue", async () => {
  await fixture(async ({ target, database }) => {
    const run = vi.spyOn(WorkerTaskPool.prototype, "run");
    await expect(
      runtime.prepareOwnedSessionEntryProjectionInWorker(
        database.path,
        { ...target, sessionId: "foreign" },
        target.env,
      ),
    ).rejects.toThrow("Native session projection unavailable");
    await expect(
      runtime.prepareOwnedSessionEntryProjectionInWorker(database.path, target, {
        ...target.env,
        OPENCLAW_STATE_DIR: database.path + ".foreign",
      }),
    ).rejects.toThrow();
    await closeOpenClawAgentDatabaseByPathAsync(database.path, "main");
    await expect(
      runtime.prepareOwnedSessionEntryProjectionInWorker(database.path, target, target.env),
    ).rejects.toThrow();
    expect(run).not.toHaveBeenCalled();
  });
});
it("refuses actual native cold state before dispatch instead of restore/materialization", async () => {
  await fixture(async ({ target, database }) => {
    runOpenClawAgentWriteTransaction(
      ({ db }) => {
        db.prepare(
          "UPDATE session_windows SET updated_at = 1, transcript_updated_at = 1 WHERE session_id = ?",
        ).run(target.sessionId);
      },
      { agentId: "main", env: target.env },
    );
    await prepareSessionColdStateInHost(
      {
        agents: { entries: { main: {} } },
        session: {
          store: database.path,
          maintenance: { coldStorage: { enabled: true, afterDays: 30 } },
        },
      },
      target.env,
    );
    const owner = openOpenClawAgentDatabase({ agentId: "main", env: target.env });
    expect(
      owner.db
        .prepare("SELECT session_id FROM session_transcript_cold_archives WHERE session_id = ?")
        .get(target.sessionId),
    ).toBeDefined();
    const run = vi.spyOn(WorkerTaskPool.prototype, "run");
    const restore = vi.spyOn(runtime, "readRestoredSessionTranscript");
    await expect(
      buildSessionEntry(database.path, { ...target, readPolicy: "no-restore" }),
    ).rejects.toMatchObject({ status: "unverified" });
    expect(run).not.toHaveBeenCalled();
    expect(restore).not.toHaveBeenCalled();
  });
});
it("sanitizes wrong replies, transport timeout and cancellation without ordinary fallback", async () => {
  await fixture(async ({ target, database }) => {
    const run = vi.spyOn(WorkerTaskPool.prototype, "run");
    const fallback = vi.spyOn(runtime, "prepareSessionEntryInWorker");
    const restore = vi.spyOn(runtime, "readRestoredSessionTranscript");
    run.mockResolvedValueOnce({ ok: true, value: { kind: "wrong", entry: null } });
    await expect(
      buildSessionEntry(database.path, { ...target, readPolicy: "no-restore" }),
    ).rejects.toMatchObject({ status: "unverified" });
    run.mockRejectedValueOnce(new Error("synthetic transport timeout"));
    await expect(
      buildSessionEntry(database.path, { ...target, readPolicy: "no-restore" }),
    ).rejects.toMatchObject({ status: "unverified" });
    const cancelled = new AbortController();
    cancelled.abort();
    await expect(
      runtime.prepareOwnedSessionEntryProjectionInWorker(
        database.path,
        target,
        target.env,
        cancelled.signal,
      ),
    ).rejects.toThrow("Native session projection unavailable");
    expect(fallback).not.toHaveBeenCalled();
    expect(restore).not.toHaveBeenCalled();
  });
});
it("does not let forged public snapshots or opaque callbacks dispatch a strict projection", async () => {
  await fixture(async ({ target, database }) => {
    const snapshot = runtime.readTranscriptExportSnapshotReadOnlySync(target);
    if (!snapshot) {
      throw new Error("fixture snapshot missing");
    }
    const run = vi.spyOn(WorkerTaskPool.prototype, "run");
    const opaque = { memoryEntry: vi.fn() };
    const observer = vi.fn();
    await expect(
      buildSessionEntryFromSnapshot(
        database.path,
        { ...target, readPolicy: "no-restore" },
        { ...snapshot, events: [] },
        observer,
      ),
    ).rejects.toMatchObject({ status: "unverified" });
    await expect(
      buildSessionEntry(database.path, { ...target, readPolicy: "no-restore" }, opaque),
    ).rejects.toMatchObject({ status: "unverified" });
    expect(run).not.toHaveBeenCalled();
    expect(observer).not.toHaveBeenCalled();
    expect(opaque.memoryEntry).not.toHaveBeenCalled();
  });
});

it("computes genuine selected snapshot data without path/DB reads or owner claims", async () => {
  await fixture(async ({ target, database }) => {
    const selected = runtime.readOwnedWarmSessionSnapshotSync(target);
    if (selected.status !== "observed-not-atomic") {
      throw new Error("native selection missing");
    }
    const redaction = captureSensitiveTextRedactionSnapshot();
    const reads = vi.spyOn(fsSync, "readFileSync");
    const stats = vi.spyOn(fsSync, "statSync");
    const opens = vi.spyOn(sqliteSnapshots, "openSqliteReadOnlyDatabase");
    const restore = vi.spyOn(runtime, "readRestoredSessionTranscript");
    const materialize = vi.spyOn(runtime, "materializeSessionArchiveForRead");
    const data = await computeSessionEntryProjectionData(
      database.path,
      target,
      selected.value,
      redaction,
    );
    expect(data.entry.content).toContain("genuine native worker data");
    expect("receipt" in data).toBe(false);
    expect("status" in data).toBe(false);
    expect(reads).not.toHaveBeenCalled();
    expect(stats).not.toHaveBeenCalled();
    expect(opens).not.toHaveBeenCalled();
    expect(restore).not.toHaveBeenCalled();
    expect(materialize).not.toHaveBeenCalled();
  });
});

it("rejects a stale native admitted-turn fence before projection worker enqueue", async () => {
  await fixture(async ({ target, database }) => {
    const recorder = createUserTurnTranscriptRecorder({
      target: { ...target, sessionEntry: undefined },
      input: { text: "native fenced input", timestamp: 2000 },
      updateMode: "none",
    });
    await recorder.persistApproved();
    const admission = recorder.getAdmissionReceipt();
    if (!admission) {
      throw new Error("native admission missing");
    }
    await replaceTranscriptEvents(target, [{ type: "session", id: target.sessionId, version: 3 }]);
    const run = vi.spyOn(WorkerTaskPool.prototype, "run");
    await runWithSessionTranscriptReadFence(admission, async () => {
      await expect(
        runtime.prepareOwnedSessionEntryProjectionInWorker(database.path, target, target.env),
      ).rejects.toThrow("Native session projection unavailable");
    });
    expect(run).not.toHaveBeenCalled();
  });
});
