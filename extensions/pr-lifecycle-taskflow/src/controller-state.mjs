import { PHASE, STATE_SCHEMA_VERSION, TERMINAL_PHASES } from "./controller-constants.mjs";
import { appendSeenEvent, cleanText, isRepo, isSha } from "./controller-validation.mjs";

export function isLifecycleState(value) {
  return Boolean(
    value &&
    typeof value === "object" &&
    value.schemaVersion === STATE_SCHEMA_VERSION &&
    isRepo(value.repo) &&
    Number.isInteger(value.prNumber) &&
    isSha(value.headSha) &&
    typeof value.phase === "string" &&
    Array.isArray(value.seenEventIds),
  );
}

export function isTerminalState(state) {
  return TERMINAL_PHASES.has(state.phase);
}

export function budgetBlock(state, now, eventId) {
  if (now > state.deadlineAt) {
    return blockState(state, "wall_time_budget_exhausted", now, eventId);
  }
  if (state.cycle > state.maxCycles) {
    return blockState(state, "review_fix_cycle_budget_exhausted", now, eventId);
  }
  return null;
}

export function blockState(state, reason, ...timing) {
  const [now = Date.now(), eventId] = timing;
  const blocker = cleanText(reason, 1000, "blocker");
  const next = appendSeenEvent(
    {
      ...state,
      phase: PHASE.BLOCKED,
      activeWorker: null,
      reviewLease: null,
      wait: { kind: "manual_intervention", since: now },
      blocker,
      mergeReady: null,
      terminalSupersession: state.terminalSupersession ?? {
        schemaVersion: 1,
        eventId: `terminal:${state.flowId ?? `${state.repo}#${state.prNumber}`}:${state.headSha}:blocked`,
        flowId: state.flowId ?? null,
        repository: state.repo,
        prNumber: state.prNumber,
        headSha: state.headSha,
        phase: PHASE.BLOCKED,
        reason: blocker,
        emittedAt: now,
      },
      updatedAt: now,
    },
    eventId,
  );
  return { changed: true, state: next, effect: "blocked", reason: next.blocker };
}
