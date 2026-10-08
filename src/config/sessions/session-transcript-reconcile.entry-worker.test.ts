import fs from "node:fs";
import path from "node:path";
import * as timers from "node:timers/promises";
import { deserialize } from "node:v8";
import { MessagePort, Worker } from "node:worker_threads";
import { isRecord } from "@openclaw/normalization-core/record-coerce";
import { expect, it, vi } from "vitest";
import { waitForAcceptedChatSendRetry } from "../../gateway/server-methods/chat-send-retry.js";
import { readSessionPreviewItemsFromTranscriptAsync } from "../../gateway/session-transcript-preview.js";
import { openNodeSqliteDatabase } from "../../infra/node-sqlite.js";
import { readDatabasePathIdentitySync } from "../../infra/sqlite-worker-identity.js";
import { WorkerTaskPool } from "../../infra/worker-task-pool.js";
import { sessionChanges } from "../../sessions/session-row-changes.js";
import { createDeferredCore } from "../../shared/deferred.js";
import { OPENCLAW_AGENT_SCHEMA_VERSION } from "../../state/openclaw-agent-db-contract.js";
import {
  closeOpenClawAgentDatabaseByPathAsync,
  closeOpenClawAgentDatabasesAsync,
} from "../../state/openclaw-agent-db.js";
import { runOpenClawAgentWorkerWrite } from "../../state/openclaw-agent-write-admission.js";
import { closeOpenClawStateDatabaseForTest } from "../../state/openclaw-state-db.js";
import { captureOpenClawStateWorkerContext } from "../../state/openclaw-state-worker-context.js";
import { withOpenClawTestState } from "../../test-utils/openclaw-test-state.js";
import { persistSessionTranscriptTurn } from "./session-accessor.transcript-turn.js";
import { SessionTranscriptProjectionUnavailableError } from "./session-transcript-projection-error.js";
import { closeSessionTranscriptReconcileWorkerPool } from "./session-transcript-reconcile-pool.js";
import type { SessionTranscriptReconcileWrite } from "./session-transcript-reconcile-write-contract.js";
import {
  isSessionTranscriptIndexReconcileRunning,
  reconcileSessionTranscriptIndexes,
  startSessionTranscriptIndexReconcile,
  waitForSessionTranscriptIndexReconcile,
} from "./session-transcript-reconcile.js";
import { observeReconcileHostSqlite } from "./session-transcript-reconcile.sql-observer.test-support.js";

vi.mock("node:timers/promises", async (importOriginal) => ({
  ...(await importOriginal<typeof import("node:timers/promises")>()),
}));

/** Keep the unfiltered native ledger; report numeric counts instead of SQL diffs. */
function expectNoHostSqlite(observation: ReturnType<typeof observeReconcileHostSqlite>) {
  expect(observation.counts()).toEqual({
    constructor: 0,
    prepare: 0,
    exec: 0,
    close: 0,
    get: 0,
    all: 0,
    run: 0,
    iterate: 0,
  });
}

/** Observe real dispatch; only the selected native command's delivery is withheld. */
function observeNativeDispatch() {
  const commands: Array<{ threadId: number; command: SessionTranscriptReconcileWrite }> = [];
  const reads: Array<{
    threadId: number;
    kind: string;
    sessionId?: string;
    fileIdentity?: unknown;
  }> = [];
  let readResult:
    | { sessionId: string; worker?: Worker; taskId?: number; hold(deliver: () => void): void }
    | undefined;
  let intercept:
    | ((command: SessionTranscriptReconcileWrite, deliver: () => void) => boolean)
    | undefined;
  // oxlint-disable-next-line typescript/unbound-method -- Reflect.apply preserves the intercepted Worker receiver.
  const postMessage = Worker.prototype.postMessage;
  const posted = vi.spyOn(Worker.prototype, "postMessage").mockImplementation(function (
    this: Worker,
    ...args: Parameters<Worker["postMessage"]>
  ) {
    const message: unknown = args[0];
    if (isRecord(message) && message.type === "execute" && message.input instanceof Uint8Array) {
      const decoded: unknown = deserialize(message.input);
      if (
        isRecord(decoded) &&
        decoded.type === "session.transcriptIndex.write" &&
        isRecord(decoded.input)
      ) {
        const command = decoded.input as SessionTranscriptReconcileWrite;
        const deliver = () => {
          commands.push({ threadId: this.threadId, command });
          Reflect.apply(postMessage, this, args);
        };
        if (intercept?.(command, deliver)) {
          return;
        }
        deliver();
        return;
      }
    }
    if (isRecord(message) && isRecord(message.input) && typeof message.input.kind === "string") {
      reads.push({
        threadId: this.threadId,
        kind: message.input.kind,
        ...(typeof message.input.sessionId === "string"
          ? { sessionId: message.input.sessionId }
          : {}),
        ...(message.input.fileIdentity ? { fileIdentity: message.input.fileIdentity } : {}),
      });
      if (
        readResult &&
        !readResult.worker &&
        message.input.kind === "transcript-reconcile-pending" &&
        message.input.sessionId === readResult.sessionId &&
        typeof message.taskId === "number"
      ) {
        readResult.worker = this;
        readResult.taskId = message.taskId;
      }
    }
    Reflect.apply(postMessage, this, args);
  });
  // Delay one completed native read's result, preserving every real task,
  // authority exchange, data row, worker close and later dispatch.
  // oxlint-disable-next-line typescript/unbound-method -- Reflect.apply supplies the Worker receiver.
  const emit = Worker.prototype.emit;
  const emitted = vi.spyOn(Worker.prototype, "emit").mockImplementation(function (
    this: Worker,
    event: string | symbol,
    ...args: unknown[]
  ) {
    const result = args[0];
    if (
      event === "message" &&
      readResult?.worker === this &&
      isRecord(result) &&
      result.status === "ok" &&
      result.taskId === readResult.taskId
    ) {
      const gate = readResult;
      readResult = undefined;
      gate.hold(() => Reflect.apply(emit, this, [event, ...args]));
      return false;
    }
    return Boolean(Reflect.apply(emit, this, [event, ...args]));
  });
  return {
    commands,
    reads,
    holdReadResult(sessionId: string) {
      const reached = createDeferredCore();
      let deliver: (() => void) | undefined;
      const gate = {
        sessionId,
        hold(send: () => void) {
          deliver = send;
          reached.resolve();
        },
      };
      readResult = gate;
      return {
        reached: reached.promise,
        release() {
          if (readResult === gate) {
            readResult = undefined;
          }
          const send = deliver;
          deliver = undefined;
          send?.();
        },
      };
    },
    hold(match: (command: SessionTranscriptReconcileWrite) => boolean) {
      const reached = createDeferredCore();
      let deliver: (() => void) | undefined;
      const handler: NonNullable<typeof intercept> = (command, send) => {
        if (!match(command)) {
          return false;
        }
        intercept = undefined;
        deliver = send;
        reached.resolve();
        return true;
      };
      intercept = handler;
      return {
        reached: reached.promise,
        release() {
          if (intercept === handler) {
            intercept = undefined;
          }
          const send = deliver;
          deliver = undefined;
          send?.();
        },
      };
    },
    restore() {
      posted.mockRestore();
      emitted.mockRestore();
    },
  };
}

it("keeps preview-triggered durable repair and chat retry off the host while another session remains pending", async () => {
  await withOpenClawTestState(
    { scenario: "external-service", label: "reconcile-entry-worker" },
    async (state) => {
      const storePath = path.join(state.agentDir("main"), "openclaw-agent.sqlite");
      const options = { agentId: "main", path: storePath, env: state.env };
      const scope = {
        agentId: "main",
        sessionId: "selected",
        sessionKey: "agent:main:selected",
        storePath,
        env: state.env,
      };
      for (const sessionId of ["selected", "slow"]) {
        await persistSessionTranscriptTurn(
          { ...scope, sessionId, sessionKey: `agent:main:${sessionId}` },
          {
            messages: [
              {
                eventId: `${sessionId}-message`,
                parentId: null,
                message: { role: "user", content: sessionId },
              },
            ],
            touchSessionEntry: false,
          },
        );
      }
      await waitForSessionTranscriptIndexReconcile(options);
      await closeOpenClawAgentDatabasesAsync(state.stateDir);
      closeOpenClawStateDatabaseForTest();
      const fixture = openNodeSqliteDatabase(storePath);
      fixture.exec("UPDATE session_transcript_index_state SET needs_rebuild = 1");
      fixture.close();
      const dispatch = observeNativeDispatch();
      const preflight = dispatch.hold((command) => command.kind === "preflight");
      const polled = createDeferredCore();
      const wake = createDeferredCore();
      const delay = vi
        .spyOn(timers, "setTimeout")
        .mockImplementation(async <T>(_ms: number, value?: T) => {
          polled.resolve();
          await wake.promise;
          return value as T;
        });
      const observation = observeReconcileHostSqlite({ control: [], data: [storePath] });
      const publications = vi.fn();
      const unsubscribe = sessionChanges.subscribe(publications);
      let slow: ReturnType<typeof dispatch.hold> | undefined;
      let retry: Promise<void> | undefined;
      try {
        // This is the actual preview scheduling entry; its retryable response does
        // not wait for repair or create a second reconciliation owner.
        await expect(
          readSessionPreviewItemsFromTranscriptAsync(scope, 3, 100),
        ).rejects.toBeInstanceOf(SessionTranscriptProjectionUnavailableError);
        await timers.setImmediate();
        expectNoHostSqlite(observation);
        await Promise.race([
          preflight.reached,
          waitForSessionTranscriptIndexReconcile(options).then(() => {
            throw new Error("Preview repair settled before its native preflight gate");
          }),
        ]);
        expect(isSessionTranscriptIndexReconcileRunning(options)).toBe(true);
        retry = waitForAcceptedChatSendRetry(
          scope,
          new SessionTranscriptProjectionUnavailableError(scope.sessionId),
          new AbortController().signal,
        );
        await Promise.race([
          polled.promise,
          retry.then(() => {
            throw new Error("Chat retry settled before its selected-session pending probe");
          }),
        ]);
        let progress = false;
        await timers.setImmediate().then(() => {
          progress = true;
        });
        expect(progress).toBe(true);
        expectNoHostSqlite(observation);
        slow = dispatch.hold(
          (command) => command.kind === "claim" && command.plan.sessionId === "slow",
        );
        preflight.release();
        await Promise.race([
          slow.reached,
          waitForSessionTranscriptIndexReconcile(options).then(() => {
            throw new Error("Repair settled before the unrelated-session claim gate");
          }),
        ]);
        expect(publications).toHaveBeenCalledWith(
          expect.objectContaining({ sessionKey: scope.sessionKey }),
        );
        wake.resolve();
        await retry;
        expect(isSessionTranscriptIndexReconcileRunning(options)).toBe(true);
        expect(dispatch.reads).toEqual(
          expect.arrayContaining([
            expect.objectContaining({
              kind: "transcript-reconcile-pending",
              sessionId: scope.sessionId,
            }),
            expect.objectContaining({ kind: "transcript-reconcile-pending" }),
          ]),
        );
        slow.release();
        await waitForSessionTranscriptIndexReconcile(options);
        expect(new Set(dispatch.commands.map(({ command }) => command.kind))).toEqual(
          new Set([
            "preflight",
            "claim",
            "delete-chunk",
            "active-chunk",
            "fts-chunk",
            "finalize",
            "orphan-sweep",
          ]),
        );
        expect(
          [...dispatch.commands, ...dispatch.reads].every(({ threadId }) => threadId > 0),
        ).toBe(true);
        expectNoHostSqlite(observation);
        expect(Object.values(observation.counts())).toEqual(Array(8).fill(0));
      } finally {
        preflight.release();
        slow?.release();
        wake.resolve();
        try {
          await retry?.catch(() => {});
          await waitForSessionTranscriptIndexReconcile(options);
          await closeSessionTranscriptReconcileWorkerPool();
          await closeOpenClawAgentDatabasesAsync(state.stateDir);
        } finally {
          observation.restore();
          delay.mockRestore();
          dispatch.restore();
          unsubscribe();
        }
      }
      expectNoHostSqlite(observation);
      // Fixture inspection happens after the zero-host ledger is closed. These are
      // actual durable native results, not supplied mock rows or fake receipts.
      const completed = openNodeSqliteDatabase(storePath);
      try {
        expect(
          completed
            .prepare(
              "SELECT session_id, needs_rebuild FROM session_transcript_index_state ORDER BY session_id",
            )
            .all(),
        ).toEqual([
          { session_id: "selected", needs_rebuild: 0 },
          { session_id: "slow", needs_rebuild: 0 },
        ]);
        expect(
          completed.prepare("SELECT text FROM session_transcript_fts ORDER BY text").all(),
        ).toEqual([{ text: "selected" }, { text: "slow" }]);
      } finally {
        completed.close();
      }
    },
  );
});

it("preserves first-use writable admission when the durable store is absent", async () => {
  await withOpenClawTestState(
    { scenario: "external-service", label: "reconcile-entry-missing" },
    async (state) => {
      const storePath = path.join(state.agentDir("main"), "openclaw-agent.sqlite");
      const options = { agentId: "main", path: storePath, env: state.env };
      expect(fs.existsSync(storePath)).toBe(false);
      closeOpenClawStateDatabaseForTest();
      const dispatch = observeNativeDispatch();
      const observation = observeReconcileHostSqlite({ control: [], data: [storePath] });
      try {
        await expect(reconcileSessionTranscriptIndexes(options)).resolves.toEqual({
          reconciledSessions: 0,
        });
        expect(fs.existsSync(storePath)).toBe(true);
        expect(dispatch.commands).toEqual([
          expect.objectContaining({ command: { kind: "preflight" }, threadId: expect.any(Number) }),
        ]);
        expect(dispatch.commands[0]?.threadId).toBeGreaterThan(0);
        expectNoHostSqlite(observation);
      } finally {
        try {
          await closeSessionTranscriptReconcileWorkerPool();
          await closeOpenClawAgentDatabasesAsync(state.stateDir);
        } finally {
          observation.restore();
          dispatch.restore();
        }
      }
      expectNoHostSqlite(observation);
      const completed = openNodeSqliteDatabase(storePath);
      try {
        expect(completed.prepare("PRAGMA user_version").get()).toEqual({
          user_version: OPENCLAW_AGENT_SCHEMA_VERSION,
        });
        expect(completed.prepare("SELECT count(*) AS count FROM session_windows").get()).toEqual({
          count: 0,
        });
      } finally {
        completed.close();
      }
    },
  );
});

it("renews an in-flight readiness reader after exact cache revocation while retaining its original owners", async () => {
  await withOpenClawTestState(
    { scenario: "external-service", label: "reconcile-entry-renewal" },
    async (state) => {
      const storePath = path.join(state.agentDir("main"), "openclaw-agent.sqlite");
      const options = { agentId: "main", path: storePath, env: state.env };
      const scope = {
        agentId: "main",
        sessionId: "selected",
        sessionKey: "agent:main:selected",
        storePath,
        env: state.env,
      };
      await persistSessionTranscriptTurn(scope, {
        messages: [
          { eventId: "message", parentId: null, message: { role: "user", content: "renewed" } },
        ],
        touchSessionEntry: false,
      });
      await waitForSessionTranscriptIndexReconcile(options);
      await closeOpenClawAgentDatabasesAsync(state.stateDir);
      closeOpenClawStateDatabaseForTest();
      const fixture = openNodeSqliteDatabase(storePath);
      fixture.exec("UPDATE session_transcript_index_state SET needs_rebuild = 1");
      fixture.close();
      const physical = readDatabasePathIdentitySync(storePath);
      const shared = captureOpenClawStateWorkerContext({ env: state.env });
      const dispatch = observeNativeDispatch();
      const history = dispatch.holdReadResult(scope.sessionId);
      const paused = createDeferredCore();
      let continuePlanner: (() => void) | undefined;
      let holdPlanner = true;
      // Withhold a real prepared plan's acknowledgement after its claim commits.
      // No native write is left uncertain merely to create the cache-turnover race.
      // oxlint-disable-next-line typescript/unbound-method -- Reflect.apply preserves the intercepted MessagePort receiver.
      const postMessage = MessagePort.prototype.postMessage;
      const planner = vi.spyOn(MessagePort.prototype, "postMessage").mockImplementation(function (
        this: MessagePort,
        ...args: Parameters<MessagePort["postMessage"]>
      ) {
        const message: unknown = args[0];
        if (holdPlanner && isRecord(message) && message.type === "continue") {
          holdPlanner = false;
          continuePlanner = () => Reflect.apply(postMessage, this, args);
          paused.resolve();
          return;
        }
        Reflect.apply(postMessage, this, args);
      });
      const wake = createDeferredCore();
      const delay = vi
        .spyOn(timers, "setTimeout")
        .mockImplementation(async <T>(_ms: number, value?: T) => {
          await wake.promise;
          return value as T;
        });
      const unsubscribe = sessionChanges.subscribe((change) => {
        if ("sessionKey" in change && change.sessionKey === scope.sessionKey) {
          wake.resolve();
        }
      });
      const observation = observeReconcileHostSqlite({ control: [], data: [storePath] });
      let retry: Promise<void> | undefined;
      let closing: Promise<boolean> | undefined;
      try {
        startSessionTranscriptIndexReconcile({ ...options, preferredSessionId: scope.sessionId });
        await Promise.race([
          paused.promise,
          waitForSessionTranscriptIndexReconcile(options).then(() => {
            throw new Error("Repair settled before the prepared-plan acknowledgement gate");
          }),
        ]);
        retry = waitForAcceptedChatSendRetry(
          scope,
          new SessionTranscriptProjectionUnavailableError(scope.sessionId),
          new AbortController().signal,
        );
        await Promise.race([
          history.reached,
          retry.then(() => {
            throw new Error("Readiness settled before its completed native read was held");
          }),
        ]);
        const oldRepair = waitForSessionTranscriptIndexReconcile(options);
        closing = closeOpenClawAgentDatabaseByPathAsync(storePath, scope.agentId);
        history.release();
        continuePlanner?.();
        continuePlanner = undefined;
        await closing;
        await oldRepair;
        await retry;
        await waitForSessionTranscriptIndexReconcile(options);
        const selected = dispatch.reads.filter(
          ({ kind, sessionId }) =>
            kind === "transcript-reconcile-pending" && sessionId === scope.sessionId,
        );
        expect(selected.length).toBeGreaterThanOrEqual(2);
        expect(new Set(selected.map(({ threadId }) => threadId)).size).toBeGreaterThanOrEqual(2);
        expect(
          selected.every(
            ({ fileIdentity }) =>
              isRecord(fileIdentity) &&
              fileIdentity.key === physical.key &&
              fileIdentity.birthtime === physical.birthtime,
          ),
        ).toBe(true);
        expect(readDatabasePathIdentitySync(storePath)).toEqual(physical);
        shared.admission.assertCurrent();
        expectNoHostSqlite(observation);
      } finally {
        holdPlanner = false;
        history.release();
        continuePlanner?.();
        wake.resolve();
        try {
          await Promise.allSettled([retry, closing].filter((pending) => pending !== undefined));
          await waitForSessionTranscriptIndexReconcile(options);
          await closeSessionTranscriptReconcileWorkerPool();
          await closeOpenClawAgentDatabasesAsync(state.stateDir);
        } finally {
          observation.restore();
          delay.mockRestore();
          planner.mockRestore();
          dispatch.restore();
          unsubscribe();
        }
      }
      expectNoHostSqlite(observation);
      const completed = openNodeSqliteDatabase(storePath);
      try {
        expect(
          completed
            .prepare(
              "SELECT needs_rebuild FROM session_transcript_index_state WHERE session_id = ?",
            )
            .get(scope.sessionId),
        ).toEqual({ needs_rebuild: 0 });
        expect(completed.prepare("SELECT text FROM session_transcript_fts").all()).toEqual([
          { text: "renewed" },
        ]);
      } finally {
        completed.close();
      }
    },
  );
});

it("does not skip a queued dirty writer by probing its earlier clean snapshot", async () => {
  await withOpenClawTestState(
    { scenario: "external-service", label: "reconcile-entry-fifo" },
    async (state) => {
      const storePath = path.join(state.agentDir("main"), "openclaw-agent.sqlite");
      const options = { agentId: "main", path: storePath, env: state.env };
      const scope = {
        agentId: "main",
        sessionId: "selected",
        sessionKey: "agent:main:selected",
        storePath,
        env: state.env,
      };
      await persistSessionTranscriptTurn(scope, {
        messages: [{ eventId: "root", parentId: null, message: { role: "user", content: "root" } }],
        touchSessionEntry: false,
      });
      await waitForSessionTranscriptIndexReconcile(options);
      await closeOpenClawAgentDatabasesAsync(state.stateDir);
      closeOpenClawStateDatabaseForTest();
      const occupied = createDeferredCore();
      const release = createDeferredCore();
      // Reserve the real shared writer FIFO. A native foreign-writer fixture then
      // dirties the selected projection without a parent SQLite helper or mock.
      const blocker = runOpenClawAgentWorkerWrite(options, async () => {
        occupied.resolve();
        await release.promise;
      });
      await occupied.promise;
      const dirtyPeer = new WorkerTaskPool<
        { path: string; sessionId: string },
        { threadId: number; changed: number }
      >({
        workerUrl: new URL(
          "./session-transcript-reconcile.dirty-peer.test-support.mjs",
          import.meta.url,
        ),
        maxWorkers: 1,
      });
      const dispatch = observeNativeDispatch();
      const observation = observeReconcileHostSqlite({ control: [], data: [storePath] });
      const dirty = runOpenClawAgentWorkerWrite(options, () =>
        dirtyPeer.run({ path: storePath, sessionId: scope.sessionId }, { inputBytes: 512 }),
      );
      let completed = false;
      const repairing = reconcileSessionTranscriptIndexes({
        ...options,
        preferredSessionId: scope.sessionId,
      }).then((result) => {
        completed = true;
        return result;
      });
      try {
        await timers.setImmediate();
        expect(completed).toBe(false);
        expect(
          dispatch.reads.filter(({ kind }) => kind === "transcript-reconcile-pending"),
        ).toEqual([]);
        expectNoHostSqlite(observation);
        release.resolve();
        await blocker;
        const committed = await dirty;
        expect(committed.changed).toBe(1);
        expect(committed.threadId).toBeGreaterThan(0);
        await repairing;
        await waitForSessionTranscriptIndexReconcile(options);
        expect(dispatch.commands.some(({ command }) => command.kind === "finalize")).toBe(true);
        expect(dispatch.reads.some(({ kind }) => kind === "transcript-reconcile-pending")).toBe(
          true,
        );
        expectNoHostSqlite(observation);
      } finally {
        release.resolve();
        try {
          await Promise.allSettled([blocker, dirty, repairing]);
          await dirtyPeer.close();
          await waitForSessionTranscriptIndexReconcile(options);
          await closeSessionTranscriptReconcileWorkerPool();
          await closeOpenClawAgentDatabasesAsync(state.stateDir);
        } finally {
          observation.restore();
          dispatch.restore();
        }
      }
      expectNoHostSqlite(observation);
      const completedDatabase = openNodeSqliteDatabase(storePath);
      try {
        expect(
          completedDatabase.prepare("SELECT text FROM session_transcript_fts ORDER BY text").all(),
        ).toEqual([{ text: "root" }]);
        expect(
          completedDatabase
            .prepare(
              "SELECT needs_rebuild FROM session_transcript_index_state WHERE session_id = ?",
            )
            .get(scope.sessionId),
        ).toEqual({ needs_rebuild: 0 });
      } finally {
        completedDatabase.close();
      }
    },
  );
});
