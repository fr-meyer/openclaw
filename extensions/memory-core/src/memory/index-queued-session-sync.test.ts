import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { createDeferred } from "openclaw/plugin-sdk/extension-shared";
import type { MemorySyncParams } from "openclaw/plugin-sdk/memory-core-host-engine-storage";
import { resolveOpenClawAgentSqlitePath } from "openclaw/plugin-sdk/sqlite-runtime";
import { useSqliteWorkerFault } from "openclaw/plugin-sdk/sqlite-runtime-testing";
import { describe, expect, it, vi } from "vitest";
import { createManagerIndexFixture } from "./manager-index.test-support.js";
import type { MemoryTargetedSessionSyncQueue } from "./manager-sync-control.js";

const fault = useSqliteWorkerFault([
  {
    name: "fail_queued_session_publication",
    match: /^insert into memory_index_chunks\b/u,
    sql: `CREATE TEMP TRIGGER fail_queued_session_publication AFTER INSERT ON main.memory_index_chunks
      BEGIN SELECT RAISE(FAIL, 'forced queued session publication failure'); END;`,
  },
]);

const { closeAllMemorySearchManagers, getMemorySearchManager } = await import("./index.js");

function sessionTarget(sessionId: string, sessionKey: string) {
  return { agentId: "main", sessionId, sessionKey };
}

describe("memory queued session sync", () => {
  const fixture = createManagerIndexFixture({
    getMemorySearchManager,
    closeAllMemorySearchManagers,
  });
  const {
    createConfig: createCfg,
    getFreshManager,
    seedSessionTranscript: seedMemoryIndexSessionTranscript,
  } = fixture;

  async function seedSession(
    sessionId: string,
    content: string,
    options: { role: "user" | "assistant"; timestamp: number | string; sessionKey?: string },
  ) {
    const { sessionKey, ...message } = options;
    await seedMemoryIndexSessionTranscript({
      sessionId,
      sessionKey,
      messages: [{ ...message, content }],
    });
  }

  async function getReconfiguredSessionManager(sources: Array<"memory" | "sessions">) {
    const config = { sources, sessionMemory: true, model: "old-embed" };
    const previous = await getFreshManager(createCfg(config));
    await previous.sync({ reason: "test", force: true });
    await previous.close();
    return getFreshManager(createCfg({ ...config, provider: "gemini", model: "new-embed" }));
  }

  it("clears dirty after sessions-only identity reindex", async () => {
    await seedSession("session-identity", "Session-only identity marker.", {
      role: "assistant",
      timestamp: "2026-04-07T15:25:04.113Z",
    });

    const nextManager = await getReconfiguredSessionManager(["sessions"]);
    expect(nextManager.status().dirty).toBe(true);

    await nextManager.sync({ reason: "test", force: true });

    expect(nextManager.status().dirty).toBe(false);
    expect(nextManager.status().custom?.indexIdentity).toEqual({ status: "valid" });
  });

  it("drains retained queued targets through the next idle sync call", async () => {
    const markers = {
      blocker: "BLOCKER FAILED SYNC 729",
      retained: "RETAINED RETRY TARGET 729",
      trigger: "IDLE TRIGGER TARGET 729",
    };
    const sessionKey = (sessionId: string) => `agent:main:proof:${sessionId}`;
    const manager = await getFreshManager(
      createCfg({
        provider: "none",
        sources: ["sessions"],
        sessionMemory: true,
      }),
      "cli",
    );
    const dbPath = resolveOpenClawAgentSqlitePath({ agentId: "main" });
    try {
      await manager.sync({ reason: "test-baseline", force: true });
      for (const [sessionId, marker] of Object.entries(markers)) {
        await seedSession(sessionId, marker, {
          role: "user",
          timestamp: Date.now(),
          sessionKey: sessionKey(sessionId),
        });
      }

      fault.enable();

      const active = manager.sync({
        reason: "test-failed-owner",
        sessions: [sessionTarget("blocker", sessionKey("blocker"))],
      });
      const failedQueued = manager.sync({
        reason: "test-queued-retained",
        sessions: [sessionTarget("retained", sessionKey("retained"))],
      });
      const failures = await Promise.allSettled([active, failedQueued]);
      for (const result of failures) {
        assert.ok(result.status === "rejected", "expected failed SQLite publication to reject");
        expect(result.reason).toMatchObject({
          message: "forced queued session publication failure",
        });
      }
      fault.disable();

      const ftsMatchCount = (marker: string): number => {
        const observer = new DatabaseSync(dbPath, { readOnly: true });
        try {
          return (
            observer
              .prepare(
                "SELECT COUNT(*) AS count FROM memory_index_chunks_fts WHERE memory_index_chunks_fts MATCH ?",
              )
              .get(`"${marker}"`) as { count: number }
          ).count;
        } finally {
          observer.close();
        }
      };

      expect(ftsMatchCount(markers.retained)).toBe(0);
      expect(ftsMatchCount(markers.trigger)).toBe(0);
      // Hand ordinary dirty state to maintenance so recovery must use the retained queue.
      manager.takeReindexRetryStateForMaintenance();
      const recoveryState = manager as unknown as {
        syncing: Promise<void> | null;
        sessionSyncQueue: MemoryTargetedSessionSyncQueue;
        sessionsDirtyFiles: Set<string>;
        sessionsFullRetryDirty: boolean;
      };
      expect(recoveryState.syncing).toBeNull();
      expect(recoveryState.sessionSyncQueue.sessions.size).toBe(1);
      expect(recoveryState.sessionsDirtyFiles.size).toBe(0);
      expect(recoveryState.sessionsFullRetryDirty).toBe(false);

      const recoveryProgress = vi.fn();
      const recovery = manager.sync({
        reason: "test-recovery-trigger",
        sessions: [sessionTarget("trigger", sessionKey("trigger"))],
        progress: recoveryProgress,
      });
      // A full sync can claim `syncing` before the retained queue owner resumes.
      // Both owners must settle without the queue awaiting its own promise.
      const competingFullSync = manager.sync({ reason: "test-competing-full-sync" });
      const recoveryResults = await Promise.allSettled([recovery, competingFullSync]);
      expect(recoveryResults.map((result) => result.status)).toEqual(["fulfilled", "fulfilled"]);

      expect(ftsMatchCount(markers.retained)).toBeGreaterThan(0);
      expect(ftsMatchCount(markers.trigger)).toBeGreaterThan(0);
      expect(recoveryState.sessionSyncQueue.sessions.size).toBe(0);
      expect(recoveryProgress).toHaveBeenCalled();
    } finally {
      fault.disable();
      await manager.close?.();
    }
  });

  it("drains retained queued targets from a live rejection transition", async () => {
    const markers = {
      retained: "LIVE REJECTION RETAINED TARGET 729",
      transition: "LIVE REJECTION TRANSITION TARGET 729",
      trigger: "LIVE REJECTION RECOVERY TARGET 729",
    };
    const sessionKey = (sessionId: string) => `agent:main:live-rejection:${sessionId}`;
    // Startup catchup must not consume the controlled sync mocks.
    const manager = await getFreshManager(
      createCfg({
        provider: "none",
        sources: ["sessions"],
        sessionMemory: true,
      }),
      "cli",
    );
    const activeSyncGate = createDeferred<void>();
    const queuedSyncGate = createDeferred<void>();
    const owner = manager as unknown as {
      sessionSyncQueue: MemoryTargetedSessionSyncQueue;
      syncing: Promise<void> | null;
      runSync: (params?: MemorySyncParams) => Promise<void>;
    };
    const originalRunSync = owner.runSync.bind(owner);
    const runSyncSpy = vi
      .spyOn(owner, "runSync")
      .mockImplementationOnce(async (params) => await originalRunSync(params))
      .mockImplementationOnce(async () => await activeSyncGate.promise)
      .mockImplementationOnce(async () => await queuedSyncGate.promise)
      .mockImplementation(async (params) => await originalRunSync(params));
    const queuedError = new Error("controlled queued rejection");
    try {
      await manager.sync({ reason: "test-live-rejection-baseline", force: true });
      for (const [sessionId, marker] of Object.entries(markers)) {
        await seedSession(sessionId, marker, {
          role: "user",
          timestamp: Date.now(),
          sessionKey: sessionKey(sessionId),
        });
      }

      const active = manager.sync({
        reason: "test-live-rejection-owner",
        sessions: [sessionTarget("active", sessionKey("active"))],
      });
      const queuedProgress = vi.fn();
      const failedQueued = manager.sync({
        reason: "test-live-rejection-queued",
        sessions: [sessionTarget("retained", sessionKey("retained"))],
        force: true,
        progress: queuedProgress,
      });
      const failuresPromise = Promise.allSettled([active, failedQueued]);
      activeSyncGate.resolve();
      await vi.waitFor(() => {
        expect(runSyncSpy).toHaveBeenCalledTimes(3);
        expect(owner.syncing).not.toBeNull();
        expect(owner.sessionSyncQueue.pending).not.toBeNull();
      });
      const rejectingQueuedSync = owner.syncing;
      if (!rejectingQueuedSync) {
        throw new Error("expected a live queued sync");
      }

      const transitionResult = createDeferred<PromiseSettledResult<void>>();
      let transitionState:
        | { syncingNull: boolean; queueOwnerLive: boolean; queuedTargets: number }
        | undefined;
      const transitionProgress = vi.fn();
      void rejectingQueuedSync.catch(() => {
        transitionState = {
          syncingNull: owner.syncing === null,
          queueOwnerLive: owner.sessionSyncQueue.pending !== null,
          queuedTargets: owner.sessionSyncQueue.sessions.size,
        };
        const transitionCall = manager.sync({
          reason: "test-live-rejection-transition",
          sessions: [sessionTarget("transition", sessionKey("transition"))],
          progress: transitionProgress,
        });
        void transitionCall.then(
          (value) => transitionResult.resolve({ status: "fulfilled", value }),
          (reason: unknown) => transitionResult.resolve({ status: "rejected", reason }),
        );
      });

      queuedSyncGate.reject(queuedError);
      const failures = await failuresPromise;
      const transitionFailure = await transitionResult.promise;
      expect(failures[0]?.status).toBe("fulfilled");
      expect(failures[1]?.status).toBe("rejected");
      expect(transitionFailure.status).toBe("rejected");
      if (failures[1]?.status !== "rejected" || transitionFailure.status !== "rejected") {
        throw new Error("expected shared queued rejection");
      }
      expect(failures[1].reason).toBe(queuedError);
      expect(transitionFailure.reason).toBe(queuedError);
      expect(transitionState).toEqual({
        syncingNull: true,
        queueOwnerLive: true,
        queuedTargets: 0,
      });
      expect(Array.from(owner.sessionSyncQueue.sessions.values())).toEqual([
        sessionTarget("transition", sessionKey("transition")),
        sessionTarget("retained", sessionKey("retained")),
      ]);
      expect(queuedProgress).not.toHaveBeenCalled();
      expect(transitionProgress).not.toHaveBeenCalled();

      const recoveryProgress = vi.fn();
      await manager.sync({
        reason: "test-live-rejection-recovery",
        sessions: [sessionTarget("trigger", sessionKey("trigger"))],
        progress: recoveryProgress,
      });

      const dbPath = resolveOpenClawAgentSqlitePath({ agentId: "main" });
      const observer = new DatabaseSync(dbPath, { readOnly: true });
      try {
        const indexedCount = (marker: string) =>
          (
            observer
              .prepare("SELECT COUNT(*) AS count FROM memory_index_chunks WHERE text LIKE ?")
              .get(`%${marker}%`) as { count: number }
          ).count;
        expect(indexedCount(markers.retained)).toBeGreaterThan(0);
        expect(indexedCount(markers.transition)).toBeGreaterThan(0);
        expect(indexedCount(markers.trigger)).toBeGreaterThan(0);
      } finally {
        observer.close();
      }
      expect(owner.sessionSyncQueue.sessions.size).toBe(0);
      expect(recoveryProgress).toHaveBeenCalled();
      expect(transitionProgress).not.toHaveBeenCalled();
    } finally {
      activeSyncGate.resolve();
      queuedSyncGate.reject(queuedError);
      await manager.close?.();
      runSyncSpy.mockRestore();
    }
  });

  it("clears retained queued targets when close interrupts a competing sync", async () => {
    const manager = await getFreshManager(
      createCfg({
        provider: "none",
        sources: ["sessions"],
        sessionMemory: true,
      }),
    );
    const fullSyncGate = createDeferred<void>();
    const owner = manager as unknown as {
      sessionSyncQueue: MemoryTargetedSessionSyncQueue;
      closing: boolean;
      closed: boolean;
      syncAdmitted: (params?: MemorySyncParams) => Promise<void>;
      runSync: (params?: MemorySyncParams) => Promise<void>;
    };
    const syncAdmitted = vi.spyOn(owner, "syncAdmitted");
    const runSyncSpy = vi.spyOn(owner, "runSync").mockReturnValueOnce(fullSyncGate.promise);
    const progress = vi.fn();
    owner.sessionSyncQueue.sessions.set("retained", {
      agentId: "main",
      sessionId: "retained-close",
      sessionKey: "agent:main:retained-close",
    });

    try {
      const recovery = manager.sync({
        reason: "test-close-recovery",
        sessions: [sessionTarget("trigger-close", "agent:main:trigger-close")],
        force: true,
        progress,
      });
      const competingFullSync = manager.sync({ reason: "test-close-competing-full-sync" });

      await vi.waitFor(() => {
        expect(syncAdmitted).toHaveBeenCalledTimes(2);
      });
      const closing = manager.close?.() ?? Promise.resolve();
      expect(owner.closing).toBe(true);
      fullSyncGate.resolve();

      await expect(Promise.all([recovery, competingFullSync, closing])).resolves.toEqual([
        undefined,
        undefined,
        undefined,
      ]);
      expect(runSyncSpy).toHaveBeenCalledTimes(1);
      expect(syncAdmitted).toHaveBeenCalledTimes(2);
      expect(owner.closed).toBe(true);
      expect(owner.sessionSyncQueue.sessions.size).toBe(0);
      expect(owner.sessionSyncQueue.progressCallbacks.size).toBe(0);
      expect(owner.sessionSyncQueue.force).toBe(false);
      expect(progress).not.toHaveBeenCalled();
    } finally {
      fullSyncGate.resolve();
      await manager.close?.();
      runSyncSpy.mockRestore();
      syncAdmitted.mockRestore();
    }
  });
});
