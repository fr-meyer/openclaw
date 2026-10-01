import { randomUUID } from "node:crypto";
/** Non-blocking process-owned queue for audit metadata persistence. */
import type { DecisionReceiptV1 } from "../../packages/gateway-protocol/src/index.js";
import { resolveStateDir } from "../config/paths.js";
import type { GatewayScheduler } from "../infra/gateway-scheduler.js";
import type { SqliteWorkerCommand } from "../infra/sqlite-worker-contract.js";
import { OPENCLAW_SQLITE_BUSY_TIMEOUT_MS } from "../state/openclaw-state-db.js";
import { captureOpenClawStateWorkerContext } from "../state/openclaw-state-worker-context.js";
import type { AuditEventInput } from "./audit-event-types.js";
import {
  formatAuditWriterError,
  formatAuditWriterRequestError,
} from "./audit-event-writer.errors.js";
import type {
  AuditWriterOperations,
  AuditWriterRequest,
  AuditWriterResult,
} from "./audit-event-writer.types.js";
import { parseExecutionDecisionWork } from "./execution-decision-work.js";
import type { ExecutionDecisionWork } from "./execution-decision-work.types.js";
import type { ExecutionIdentityAdmissionWork } from "./execution-identity-admission.js";

const MAX_PENDING_AUDIT_EVENTS = 4_096;
const MAX_PROTECTED_ORIGINAL_EVENT_RECEIPTS = MAX_PENDING_AUDIT_EVENTS * 2;
const AUDIT_MAINTENANCE_INTERVAL_MS = 60 * 60_000;
const AUDIT_LOCK_RETRY_DELAY_MS = 25;
const AUDIT_LOCK_RETRY_MAX_DELAY_MS = 1_000;
const AUDIT_LOCK_CONTENTION_REPORT_MS = 1_000;
const AUDIT_WRITER_SHUTDOWN_TIMEOUT_MS = OPENCLAW_SQLITE_BUSY_TIMEOUT_MS + 5_000;

type AuditMaintenanceAttempt = "settled" | "more" | "retry";

export type AuditWriterFlushReceipt = { contract: "audit-writer-flush/v1"; writerInstanceId: string;
  acceptedSequence: number; committedSequence: number; integrity: boolean };

export type AuditRunIdentity = Readonly<{ runId: string; lifecycleGeneration: string }>;
/** Live writer custody only. This handle does not authorize restart adoption or snapshot completeness. */
export type AuditRunTerminalGuard = Readonly<{
  assertCurrent(): void;
  assertCommitted(): void;
  /** Original live observation only; this does not prove audit completeness. */
  assertNoToolActionsObserved(): void;
}>;

export type AuditEventWriter = {
  writerInstanceId: string;
  flush: () => Promise<AuditWriterFlushReceipt>;
  ready: Promise<void>;
  record: (input: AuditEventInput) => boolean;
  protectRunTerminal: (identity: AuditRunIdentity, options?: {
    forbidToolActions?: true;
    /** Requires original insertion acknowledgements; never snapshot completeness. */
    requireOriginalEventReceipt?: true;
  }) => AuditRunTerminalGuard;
  observeRunTerminal: (identity: AuditRunIdentity, input: AuditEventInput) => boolean;
  observeRunToolAction: (runId: string) => boolean;
  recordRunEvent: (identity: AuditRunIdentity, input: AuditEventInput) => boolean;
  hasProtectedRunTerminal: (identity: AuditRunIdentity) => boolean | undefined;
  /** Reports only queue acceptance; persistence succeeds or fails asynchronously. */
  recordExecutionIdentity: (work: ExecutionIdentityAdmissionWork) => boolean;
  /** For decision owners without a native durable record; approvals must not use this path. */
  recordExecutionDecision: (receipt: DecisionReceiptV1) => boolean;
  /** Raw private refs are projected only after this work reaches the FIFO owner. */
  recordExecutionDecisionWork: (work: ExecutionDecisionWork) => boolean;
  stop: () => Promise<void>;
};

/** Start one bounded queue; retain the owner environment or claimed state rejects its writes. */
export function createAuditEventWriter(options: {
  scheduler: GatewayScheduler;
  stateDir?: string;
  maxPending?: number;
  onContention?: (message: string) => void;
  onError?: (error: string) => void;
}): AuditEventWriter {
  const { scheduler } = options;
  const database = {
    env: { ...process.env, OPENCLAW_STATE_DIR: options.stateDir ?? resolveStateDir(process.env) },
  };
  const maxPending = Math.max(1, Math.floor(options.maxPending ?? MAX_PENDING_AUDIT_EVENTS));
  const queue: AuditWriterRequest[] = [];
  const writerInstanceId = randomUUID();
  let acceptedSequence = 0;
  let committedSequence = 0;
  let integrity = true;
  const requestSequences = new WeakMap<AuditWriterRequest, number>();
  // Retain the original private admission for the writer's lifetime. Diagnostic
  // eviction cannot retire it; capacity exhaustion refuses new protected runs.
  const protectedRuns = new Map<string, {
    identity: AuditRunIdentity; terminal?: string; sequence?: number; invalid: boolean;
    forbidToolActions: boolean;
    requireOriginalEventReceipt: boolean;
    terminalInsertionSequence?: number;
    guard: AuditRunTerminalGuard;
  }>();
  // Only enqueue from the original protected run can attach this private custody.
  const requestReceiptOwners = new WeakMap<AuditWriterRequest, string>();
  // One native FIFO cannot reissue a prior inserted row to a successor run.
  // Retain this custody for the original writer lifetime; never evict to admit.
  const originalEventIds = new Set<string>();
  let lastOriginalSequence = 0;
  let strictRunCount = 0;
  const runKey = (identity: AuditRunIdentity) => JSON.stringify([identity.lifecycleGeneration, identity.runId]);
  const terminalBytes = (input: AuditEventInput) => JSON.stringify([
    input.sourceId, input.sourceSequence, input.occurredAt, input.kind, input.action,
    input.status, input.agentId ?? null, input.kind === "message" ? null : input.sessionKey ?? null,
    input.runId ?? null, input.actorType, input.actorId,
    input.kind === "message" ? null : input.sessionId ?? null, input.errorCode ?? null,
  ]);
  const observeOriginalReceipt = (request: AuditWriterRequest, result: AuditWriterResult) => {
    const key = requestReceiptOwners.get(request);
    if (key === undefined) return;
    const entry = protectedRuns.get(key);
    if (!entry) return;
    const receipt = result.status === "settled" ? result.originalEvent : undefined;
    const event = receipt?.event;
    const hasOriginalIdentity = !!event && typeof event.eventId === "string" &&
      event.eventId.length > 0 && event.eventId.length <= 512 &&
      Number.isSafeInteger(event.sequence) && event.sequence >= 1;
    let originalIdentityRefused = true;
    if (hasOriginalIdentity && event) {
      originalIdentityRefused = event.sequence <= lastOriginalSequence ||
        originalEventIds.has(event.eventId) ||
        originalEventIds.size >= MAX_PROTECTED_ORIGINAL_EVENT_RECEIPTS;
      // Burn returned identities even when their admission or correlation was
      // invalidated. They cannot later acknowledge a successor request.
      lastOriginalSequence = Math.max(lastOriginalSequence, event.sequence);
      if (originalEventIds.size < MAX_PROTECTED_ORIGINAL_EVENT_RECEIPTS) originalEventIds.add(event.eventId);
    }
    if (request.type !== "record-event" || request.requireOriginalEventReceipt !== true ||
        !entry.requireOriginalEventReceipt || result.status !== "settled" ||
        result.originalEventUnavailable === true || !receipt || !event ||
        receipt.sourceId !== request.input.sourceId || event.kind !== "agent_run" ||
        event.schemaVersion !== 1 || event.redaction !== "metadata_only" ||
        originalIdentityRefused ||
        terminalBytes({...event, sourceId: receipt.sourceId}) !== terminalBytes(request.input)) {
      // A missing/mismatched opt-in witness invalidates this original guard.
      // It cannot turn an ordinary diagnostic acknowledgement into authority.
      entry.invalid = true;
      return;
    }
    // Identity retention never clears entry.invalid or revives its guard.
    if (event.action === "agent.run.finished") {
      entry.terminalInsertionSequence = requestSequences.get(request);
    }
  };
  const barriers: {target: number; resolve: (receipt: AuditWriterFlushReceipt) => void; reject: (error: Error) => void}[] = [];
  const settleBarriers = () => {
    for (let i = barriers.length - 1; i >= 0; i--) {
      const barrier = barriers[i];
      if (!integrity || committedSequence >= barrier.target) {
        barriers.splice(i, 1);
        if (!integrity) barrier.reject(new Error("Audit writer integrity lost"));
        else barrier.resolve({contract: "audit-writer-flush/v1", writerInstanceId, acceptedSequence: barrier.target, committedSequence, integrity});
      }
    }
  };
  let stopped = false;
  let draining = false;
  let shutdownExpired = false;
  let unavailable = false;
  let maintenancePending = true;
  let readyPending = true;
  let scheduled: ReturnType<typeof setImmediate> | undefined;
  let retryTimer: ReturnType<typeof setTimeout> | undefined;
  let lockRetryAttempt = 0;
  let lockContentionDelayMs = 0;
  let lockContentionReported = false;
  let resolveReady!: () => void;
  const ready = new Promise<void>((resolve) => {
    resolveReady = resolve;
  });
  let stopPromise: Promise<void> | undefined;
  let resolveStop: (() => void) | undefined;
  let stopTimer: ReturnType<typeof setTimeout> | undefined;

  const fail = (error: unknown) => {
    integrity = false; settleBarriers();
    options.onError?.(formatAuditWriterError(error));
  };
  const reportContention = (message: string) => {
    options.onContention?.(formatAuditWriterError(message));
  };
  const execute = async (
    command: SqliteWorkerCommand<AuditWriterOperations>,
  ): Promise<AuditWriterResult> => {
    const context = captureOpenClawStateWorkerContext(database);
    const { runOpenClawStateWorkerOperation } =
      await import("../state/openclaw-state-worker-store.js");
    if (shutdownExpired) {
      return { status: "settled" };
    }
    // Existing state opens lazily inside the zero-busy-timeout audit command.
    const result = await runOpenClawStateWorkerOperation<AuditWriterResult>(
      context,
      (scope) =>
        shutdownExpired ? Promise.resolve({ status: "settled" } as const) : scope.execute(command),
      { existingOnly: true },
    );
    return (
      result ??
      runOpenClawStateWorkerOperation<AuditWriterResult>(context, (scope) =>
        shutdownExpired ? Promise.resolve({ status: "settled" } as const) : scope.execute(command),
      )
    );
  };
  const observeLockContention = () => {
    lockRetryAttempt += 1;
  };
  const resetLockContention = () => {
    lockRetryAttempt = 0;
    lockContentionDelayMs = 0;
    lockContentionReported = false;
  };
  const reportMaintenance = async (): Promise<AuditMaintenanceAttempt> => {
    let more = false;
    for (const family of ["events", "identity", "decisions", "progress"] as const) {
      if (shutdownExpired) {
        break;
      }
      try {
        const result = await execute({ type: "audit.writer.prune", input: family });
        if (result.status === "retry") {
          observeLockContention();
          return "retry";
        }
        if (result.error !== undefined) {
          fail(result.error);
        }
        more = (result.deleted ?? 0) > 0 || more;
      } catch (error) {
        fail(error);
      }
    }
    return more ? "more" : "settled";
  };
  const processRequest = async (request: AuditWriterRequest): Promise<AuditWriterResult> => {
    try {
      return await execute({ type: "audit.writer.process", input: request });
    } catch (error) {
      // Rejected transport/settlement can follow a commit; never replay that request.
      return { status: "settled", error: formatAuditWriterRequestError(request, error) };
    }
  };
  const finishStop = () => {
    if (stopTimer) {
      clearTimeout(stopTimer);
      stopTimer = undefined;
    }
    const finish = resolveStop;
    resolveStop = undefined;
    finish?.();
  };
  const schedule = () => {
    if (draining || shutdownExpired) {
      return;
    }
    if (retryTimer) {
      if (stopped) {
        retryTimer.ref?.();
      }
      return;
    }
    if (scheduled) {
      if (stopped) {
        scheduled.ref?.();
      }
      return;
    }
    scheduled = setImmediate(() => {
      void drainOne();
    });
    if (!stopped) {
      scheduled.unref?.();
    }
  };
  const scheduleRetry = () => {
    const delayMs = Math.min(
      AUDIT_LOCK_RETRY_MAX_DELAY_MS,
      AUDIT_LOCK_RETRY_DELAY_MS * 2 ** Math.min(6, Math.max(0, lockRetryAttempt - 1)),
    );
    lockContentionDelayMs += delayMs;
    if (!lockContentionReported && lockContentionDelayMs >= AUDIT_LOCK_CONTENTION_REPORT_MS) {
      lockContentionReported = true;
      reportContention("audit event persistence delayed by SQLite lock contention");
    }
    retryTimer = setTimeout(() => {
      retryTimer = undefined;
      void drainOne();
    }, delayMs);
    if (!stopped) {
      retryTimer.unref?.();
    }
  };
  async function drainOne() {
    scheduled = undefined;
    if (draining || shutdownExpired) {
      return;
    }
    draining = true;
    let retry = false;
    try {
      if (maintenancePending) {
        maintenancePending = false;
        const maintenance = await reportMaintenance();
        if (readyPending) {
          readyPending = false;
          resolveReady();
        }
        maintenancePending ||= maintenance !== "settled";
        if (maintenance === "retry") {
          retry = true;
          return;
        }
        resetLockContention();
      }
      if (shutdownExpired) {
        return;
      }
      // Keep the in-flight head in the bounded queue until native settlement.
      const request = queue[0];
      if (request) {
        const result = await processRequest(request);
        if (result.status === "retry") {
          observeLockContention();
          retry = true;
        } else {
          // Release settled capacity before an error observer can enqueue or throw.
          queue.shift();
          resetLockContention();
          if (shutdownExpired) fail("Audit mutation acknowledgement arrived after shutdown expiry");
          else if (result.error !== undefined) fail(result.error);
          else {
            observeOriginalReceipt(request, result);
            const sequence = requestSequences.get(request);
            if (sequence !== committedSequence + 1) fail("Audit FIFO acknowledgement gap");
            else committedSequence = sequence;
            settleBarriers();
          }
        }
      }
    } finally {
      draining = false;
      if (shutdownExpired) {
        finishStop();
      } else if (retry) {
        scheduleRetry();
      } else if (queue.length > 0 || maintenancePending) {
        schedule();
      } else if (stopped) {
        finishStop();
      }
    }
  }
  const maintenanceJob = scheduler.schedule({
    id: "audit:maintenance",
    atMs: scheduler.now() + AUDIT_MAINTENANCE_INTERVAL_MS,
    everyMs: AUDIT_MAINTENANCE_INTERVAL_MS,
    run: () => {
      maintenancePending = true;
      schedule();
    },
  });
  schedule();

  const enqueue = (message: AuditWriterRequest, receiptOwnerKey?: string): boolean => {
    if (stopped || unavailable || queue.length >= maxPending) {
      if (!stopped) {
        fail(
          unavailable
            ? "audit event writer is unavailable; dropping metadata"
            : `audit event queue is full (${maxPending}); dropping metadata`,
        );
      }
      return false;
    }
    try {
      const boundedMessage =
        message.type === "record-execution-decision-work"
          ? { ...message, work: parseExecutionDecisionWork(message.work) }
          : message;
      // Preserve the former Worker boundary's clone and prototype-stripping contract.
      const cloned = structuredClone(boundedMessage);
      if (receiptOwnerKey !== undefined) requestReceiptOwners.set(cloned, receiptOwnerKey);
      acceptedSequence += 1; requestSequences.set(cloned, acceptedSequence);
      queue.push(cloned);
      schedule();
      return true;
    } catch (error) {
      if (message.type !== "record-event") {
        fail(
          message.type === "record-execution-identity"
            ? "audit execution identity envelope could not be queued"
            : "audit execution decision receipt could not be queued",
        );
      } else {
        unavailable = true;
        fail(error);
      }
      return false;
    }
  };

  const observeRunTerminal = (identity: AuditRunIdentity, input: AuditEventInput): boolean => {
    const protectedRun = protectedRuns.get(runKey(identity));
    if (!protectedRun) return false;
    if (input.runId !== protectedRun.identity.runId || input.kind !== "agent_run" ||
        input.action !== "agent.run.finished") {
      protectedRun.invalid = true; fail("Protected audit terminal identity changed"); return true;
    }
    if (protectedRun.invalid) return true;
    if (protectedRun.terminal === undefined) return false;
    if (protectedRun.terminal !== terminalBytes(input)) {
      protectedRun.invalid = true; fail("Protected audit terminal changed after acceptance");
    }
    return true;
  };

  const observeRunToolAction = (runId: string): boolean => {
    if (strictRunCount === 0) return false;
    let invalidated = false;
    // Trusted tool events carry a run correlation, not a lifecycle generation.
    // Conservatively invalidate every strict admission with that exact run id.
    // Keep this original custody after stop; closed enqueue is not evidence loss.
    for (const entry of protectedRuns.values()) {
      if (entry.forbidToolActions && entry.identity.runId === runId) {
        entry.invalid = true;
        invalidated = true;
      }
    }
    // A run-policy violation invalidates its original guard, not unrelated
    // evidence on this shared writer. Actual storage/queue loss still fails FIFO.
    return invalidated;
  };

  return {
    writerInstanceId,
    flush: () => {
      if (!integrity || shutdownExpired || stopped || barriers.length >= maxPending) return Promise.reject(new Error("Audit flush unavailable"));
      return new Promise((resolve, reject) => {
        barriers.push({target: acceptedSequence, resolve, reject}); settleBarriers(); schedule();
      });
    },
    ready,
    record: (input) => enqueue({ type: "record-event", input }),
    protectRunTerminal: (input, protection = {}) => {
      if (!input.runId || !input.lifecycleGeneration || input.runId.length > 512 || input.lifecycleGeneration.length > 512) {
        throw new Error("Protected audit identity invalid");
      }
      const identity = Object.freeze({runId: input.runId, lifecycleGeneration: input.lifecycleGeneration});
      const key = runKey(identity);
      if (protectedRuns.has(key) || protectedRuns.size >= MAX_PENDING_AUDIT_EVENTS) {
        throw new Error("Protected audit admission replay or capacity refused");
      }
      const entry = {identity, invalid: false, forbidToolActions: protection.forbidToolActions === true,
        requireOriginalEventReceipt: protection.requireOriginalEventReceipt === true,
        terminalInsertionSequence: undefined as number | undefined,
        terminal: undefined as string | undefined,
        sequence: undefined as number | undefined, guard: undefined as unknown as AuditRunTerminalGuard};
      const assertCurrent = () => {
        if (protectedRuns.get(key) !== entry || entry.invalid || !integrity || stopped || shutdownExpired || unavailable) {
          throw new Error("Protected audit custody unavailable");
        }
      };
      entry.guard = Object.freeze({assertCurrent, assertNoToolActionsObserved: () => {
        assertCurrent();
        if (!entry.forbidToolActions) {
          throw new Error("Protected run was not admitted as a no-tool run");
        }
      }, assertCommitted: () => {
        assertCurrent();
        if (entry.terminal === undefined || entry.sequence === undefined || entry.sequence > committedSequence ||
            (entry.requireOriginalEventReceipt && entry.terminalInsertionSequence !== entry.sequence)) {
          throw new Error("Protected audit terminal not committed");
        }
      }});
      if (!integrity || stopped || shutdownExpired || unavailable) throw new Error("Protected audit writer unavailable");
      protectedRuns.set(key, entry);
      if (entry.forbidToolActions) strictRunCount += 1;
      return entry.guard;
    },
    observeRunTerminal,
    observeRunToolAction,
    recordRunEvent: (identity, input) => {
      const entry = protectedRuns.get(runKey(identity));
      if (input.action === "agent.run.finished" && observeRunTerminal(identity, input)) {
        return !!entry && !entry.invalid && integrity;
      }
      if (entry?.invalid) return false;
      if (entry && (entry.terminal !== undefined || input.runId !== entry.identity.runId || input.kind !== "agent_run")) {
        entry.invalid = true; fail("Protected audit lifecycle changed after acceptance"); return false;
      }
      // Clone before deriving custody bytes, just as the native worker queue does.
      const captured = structuredClone(input);
      const accepted = enqueue({type: "record-event", input: captured,
        ...(entry?.requireOriginalEventReceipt ? {requireOriginalEventReceipt: true as const} : {})},
        entry?.requireOriginalEventReceipt ? runKey(entry.identity) : undefined);
      if (entry && accepted && captured.action === "agent.run.finished") {
        entry.terminal = terminalBytes(captured); entry.sequence = acceptedSequence;
      }
      return accepted;
    },
    hasProtectedRunTerminal: (identity) => {
      const entry = protectedRuns.get(runKey(identity));
      return entry ? entry.terminal !== undefined && !entry.invalid && integrity && !stopped && !shutdownExpired : undefined;
    },
    recordExecutionIdentity: (work) => enqueue({ type: "record-execution-identity", work }),
    recordExecutionDecision: (receipt) => enqueue({ type: "record-execution-decision", receipt }),
    recordExecutionDecisionWork: (work) =>
      enqueue({ type: "record-execution-decision-work", work }),
    stop: () => {
      if (stopPromise) {
        return stopPromise;
      }
      stopped = true;
      maintenanceJob.cancel();
      maintenancePending = true;
      stopPromise = new Promise<void>((resolve) => {
        resolveStop = resolve;
        stopTimer = setTimeout(() => {
          shutdownExpired = true;
          maintenancePending = false;
          queue.length = 0;
          if (scheduled) {
            clearImmediate(scheduled);
            scheduled = undefined;
          }
          if (retryTimer) {
            clearTimeout(retryTimer);
            retryTimer = undefined;
          }
          fail("audit event writer shutdown timed out; pending metadata may be lost");
          if (readyPending && !draining) {
            readyPending = false;
            resolveReady();
          }
          // The deadline drops waiting metadata, but a submitted mutation must settle.
          if (!draining) {
            finishStop();
          }
        }, AUDIT_WRITER_SHUTDOWN_TIMEOUT_MS);
        stopTimer.unref?.();
        schedule();
      });
      return stopPromise;
    },
  };
}
