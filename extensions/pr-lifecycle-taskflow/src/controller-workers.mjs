import {
  FALLBACK_FIXER_MODEL,
  FIXER_FALLBACK_INFRASTRUCTURE_REASONS,
  INFRASTRUCTURE_BACKOFF_BASE_MS,
  MAX_INFRASTRUCTURE_RETRIES,
  MAX_PROTOCOL_RETRIES,
  PHASE,
  PRIMARY_FIXER_MODEL,
} from "./controller-constants.mjs";
import { applyReviewResult } from "./controller-events.mjs";
import {
  classifyWorkerFailure,
  infrastructureBackoffMs,
  retryPhase,
} from "./controller-policy.mjs";
import { budgetBlock, isLifecycleState } from "./controller-state.mjs";
import { blockState } from "./controller-state.mjs";
import {
  cleanText,
  isSha,
  optionalCleanText,
  recordExternalMilestone,
  recordTerminalEnvelope,
  sanitizeFindings,
  terminalEnvelope,
} from "./controller-validation.mjs";

export function workerKindForPhase(phase) {
  if (phase === PHASE.REVIEW_QUEUED) {
    return "review";
  }
  if (phase === PHASE.REMEDIATION_QUEUED) {
    return "remediation";
  }
  return null;
}

export function reserveWorker(state, kind, sessionKey, now = Date.now(), flowId = null) {
  if (!isLifecycleState(state)) {
    throw new Error("stored lifecycle state is invalid");
  }
  if (state.activeWorker) {
    return { changed: false, state, reason: "worker_already_reserved" };
  }
  if (state.reviewLease?.kind === "review" && state.reviewLease.headSha !== state.headSha) {
    return { changed: false, state, effect: "wait", reason: "prior_review_lease_held" };
  }
  const expectedKind = workerKindForPhase(state.phase);
  if (!expectedKind || expectedKind !== kind) {
    return { changed: false, state, reason: "phase_not_dispatchable" };
  }
  const protocolRetryAt = Number.isFinite(state.protocolRetryAt) ? state.protocolRetryAt : null;
  if (Number.isFinite(protocolRetryAt) && protocolRetryAt > now) {
    return { changed: false, state, effect: "wait", reason: "protocol_backoff" };
  }
  const infrastructureRetryAt = Number.isFinite(state.infrastructureRetryAt)
    ? state.infrastructureRetryAt
    : null;
  const budget = budgetBlock(state, now);
  if (budget) {
    return budget;
  }
  if (Number.isFinite(infrastructureRetryAt) && infrastructureRetryAt > now) {
    return { changed: false, state, effect: "wait", reason: "infrastructure_backoff" };
  }
  let baseState =
    Number.isFinite(infrastructureRetryAt) || Number.isFinite(protocolRetryAt)
      ? {
          ...state,
          infrastructureRetryAt: null,
          protocolRetryAt: null,
          wait: null,
        }
      : state;
  if (kind === "remediation" && baseState.cycle >= baseState.maxCycles) {
    return blockState(baseState, "review_fix_cycle_budget_exhausted", now);
  }
  const next = {
    ...baseState,
    phase: kind === "review" ? PHASE.REVIEW_RUNNING : PHASE.REMEDIATION_RUNNING,
    activeWorker: {
      flowId: flowId ? cleanText(flowId, 200, "flowId") : null,
      kind,
      sessionKey: cleanText(sessionKey, 500, "sessionKey"),
      headSha: state.headSha,
      cycle: state.cycle,
      reservedAt: now,
      runId: null,
      taskId: null,
      profileDigest: kind === "remediation" ? (state.remediatorProfileDigest ?? null) : null,
      claimRef: kind === "review" ? `mprl-review:${state.headSha}:${state.cycle}:${now}` : null,
    },
    wait: null,
    blocker: null,
    updatedAt: now,
  };
  return { changed: true, state: next, effect: "start_worker", reason: "reserved" };
}

export function attachWorkerRun(state, sessionKey, runId, taskId, now = Date.now()) {
  if (!state.activeWorker || state.activeWorker.sessionKey !== sessionKey) {
    return { changed: false, state, reason: "worker_reservation_changed" };
  }
  return {
    changed: true,
    state: {
      ...state,
      activeWorker: {
        ...state.activeWorker,
        runId: cleanText(runId, 200, "runId"),
        taskId: taskId ? cleanText(taskId, 200, "taskId") : null,
      },
      updatedAt: now,
    },
    effect: "none",
    reason: "worker_attached",
  };
}

export function assertWorkerReportMatches(state, report, callerSessionKey) {
  const worker = state.activeWorker;
  if (!worker) {
    throw new Error("flow has no active worker");
  }
  if (worker.sessionKey !== callerSessionKey) {
    throw new Error("worker session does not own this step");
  }
  if (report.kind !== worker.kind) {
    throw new Error("worker report kind does not match the reserved step");
  }
  if (report.headSha !== worker.headSha || report.headSha !== state.headSha) {
    throw new Error("worker report is not bound to the current exact head");
  }
  if (report.cycle !== worker.cycle || report.cycle !== state.cycle) {
    throw new Error("worker report cycle is stale");
  }
  if (worker.kind === "review" && report.claimRef !== worker.claimRef) {
    throw new Error("worker report claim does not match controller-issued claim");
  }
  if (
    worker.kind === "remediation" &&
    worker.profileDigest &&
    report.profileDigest !== worker.profileDigest
  ) {
    throw new Error("worker report remediator profile digest is stale");
  }
  return worker;
}

export function primaryFixerFailureFromReport(state, report, now) {
  const worker = state.activeWorker;
  const primary = state.fixerModel ?? PRIMARY_FIXER_MODEL;
  if (
    !worker?.flowId ||
    !worker?.runId ||
    !worker.taskId ||
    report.fixerModel !== primary ||
    !report.fixerAttested ||
    !report.fixerAttestationRef ||
    !FIXER_FALLBACK_INFRASTRUCTURE_REASONS.has(report.fixerFallbackReason) ||
    report.fixerPrimaryFailureRef ||
    state.primaryFixerFailure ||
    report.newHeadSha ||
    report.testsPassed ||
    report.publicationConfirmed ||
    report.verificationComplete
  ) {
    return null;
  }
  return {
    ref: `primary-failure:${worker.flowId}:${state.headSha}:${state.cycle}:${worker.taskId}`,
    flowId: worker.flowId,
    reason: report.fixerFallbackReason,
    primaryModel: primary,
    modelAttestationRef: report.fixerAttestationRef,
    headSha: state.headSha,
    cycle: state.cycle,
    workerSessionKey: worker.sessionKey,
    workerRunId: worker.runId,
    workerTaskId: worker.taskId,
    recordedAt: now,
    consumedAt: null,
    consumedBy: null,
  };
}

export function fixerAttestationFromReport(state, report, now) {
  if (!report.fixerAttested || !report.fixerModel || !report.fixerAttestationRef) {
    return null;
  }
  const primary = state.fixerModel ?? PRIMARY_FIXER_MODEL;
  const fallback = state.fixerFallbackModel ?? FALLBACK_FIXER_MODEL;
  if (report.fixerModel !== primary && report.fixerModel !== fallback) {
    return null;
  }
  if (
    report.fixerModel === primary &&
    (report.fixerFallbackReason || report.fixerPrimaryFailureRef)
  ) {
    return null;
  }
  if (report.fixerModel === fallback) {
    const primaryFailure = state.primaryFixerFailure;
    if (
      !FIXER_FALLBACK_INFRASTRUCTURE_REASONS.has(report.fixerFallbackReason) ||
      !report.fixerPrimaryFailureRef ||
      !primaryFailure ||
      primaryFailure.consumedAt !== null ||
      primaryFailure.ref !== report.fixerPrimaryFailureRef ||
      primaryFailure.reason !== report.fixerFallbackReason ||
      primaryFailure.primaryModel !== primary ||
      primaryFailure.flowId !== state.activeWorker?.flowId ||
      primaryFailure.headSha !== state.headSha ||
      primaryFailure.cycle !== state.cycle ||
      !primaryFailure.workerSessionKey ||
      !primaryFailure.workerRunId ||
      !primaryFailure.workerTaskId ||
      primaryFailure.ref !==
        `primary-failure:${primaryFailure.flowId}:${primaryFailure.headSha}:` +
          `${primaryFailure.cycle}:${primaryFailure.workerTaskId}`
    ) {
      return null;
    }
  }
  return {
    model: report.fixerModel,
    primaryModel: primary,
    fallbackUsed: report.fixerModel === fallback,
    fallbackReason: report.fixerFallbackReason ?? null,
    primaryFailureRef: report.fixerPrimaryFailureRef ?? null,
    ref: report.fixerAttestationRef,
    attestedAt: now,
  };
}

export function consumedPrimaryFixerFailure(state, fixerAttestation, now) {
  if (!fixerAttestation?.fallbackUsed || !state.primaryFixerFailure) {
    return null;
  }
  return {
    ...state.primaryFixerFailure,
    consumedAt: now,
    consumedBy: {
      sessionKey: state.activeWorker?.sessionKey ?? null,
      flowId: state.activeWorker?.flowId ?? null,
      runId: state.activeWorker?.runId ?? null,
      taskId: state.activeWorker?.taskId ?? null,
    },
  };
}

export function applyWorkerReport(state, reportInput, callerSessionKey, now = Date.now()) {
  if (!isLifecycleState(state)) {
    throw new Error("stored lifecycle state is invalid");
  }
  if (!reportInput || typeof reportInput !== "object" || Array.isArray(reportInput)) {
    throw new Error("worker report must be an object");
  }
  const report = {
    kind: cleanText(reportInput.kind, 20, "kind"),
    outcome: cleanText(reportInput.outcome, 80, "outcome"),
    headSha: cleanText(reportInput.headSha, 40, "headSha").toLowerCase(),
    cycle: reportInput.cycle,
    reviewId: optionalCleanText(reportInput.reviewId, 120, "reviewId"),
    summary: optionalCleanText(reportInput.summary, 1000, "summary"),
    claimRef: optionalCleanText(reportInput.claimRef, 500, "claimRef"),
    newHeadSha:
      reportInput.newHeadSha === undefined
        ? undefined
        : cleanText(reportInput.newHeadSha, 40, "newHeadSha").toLowerCase(),
    coverageComplete: reportInput.coverageComplete === true,
    retryAllowed: reportInput.retryAllowed === true,
    testsPassed: reportInput.testsPassed === true,
    publicationConfirmed: reportInput.publicationConfirmed === true,
    verificationComplete: reportInput.verificationComplete === true,
    fixerModel: optionalCleanText(reportInput.fixerModel, 100, "fixerModel"),
    fixerAttested: reportInput.fixerAttested === true,
    fixerAttestationRef: optionalCleanText(
      reportInput.fixerAttestationRef,
      500,
      "fixerAttestationRef",
    ),
    fixerFallbackReason: optionalCleanText(
      reportInput.fixerFallbackReason,
      500,
      "fixerFallbackReason",
    ),
    fixerPrimaryFailureRef: optionalCleanText(
      reportInput.fixerPrimaryFailureRef,
      500,
      "fixerPrimaryFailureRef",
    ),
    profileDigest: optionalCleanText(reportInput.profileDigest, 64, "profileDigest"),
    outcomeClass: optionalCleanText(reportInput.outcomeClass, 80, "outcomeClass"),
    finalStage: optionalCleanText(reportInput.finalStage, 120, "finalStage"),
    findings: sanitizeFindings(reportInput.findings ?? []),
  };
  if (
    report.outcomeClass &&
    !new Set([
      "success",
      "preflight_failure",
      "policy_rejection",
      "test_failure",
      "publication_failure",
      "execution_failure",
      "protocol_violation",
    ]).has(report.outcomeClass)
  ) {
    throw new Error("outcomeClass is invalid");
  }
  const worker = assertWorkerReportMatches(state, report, callerSessionKey);
  const reportedWorker = {
    ...worker,
    reason: "worker_report_received",
    clearedAt: now,
  };
  const cleared = recordTerminalEnvelope(
    {
      ...state,
      activeWorker: null,
      infrastructureRetryCount: 0,
      infrastructureRetryAt: null,
      infrastructureLastFailure: null,
      protocolRetryCount: 0,
      protocolRetryAt: null,
      orphanedWorker: reportedWorker,
      pendingPublication: null,
      updatedAt: now,
    },
    terminalEnvelope(state, worker, report, now),
  );

  if (report.kind === "review") {
    if (report.outcome === "waiting_review") {
      const next = {
        ...cleared,
        phase: PHASE.REVIEW_WAITING,
        reviewLease: {
          kind: "review",
          flowId: worker.flowId ?? null,
          sessionKey: worker.sessionKey,
          headSha: state.headSha,
          cycle: state.cycle,
          claimRef: worker.claimRef,
          reviewId: report.reviewId ?? null,
          reservedAt: Number.isFinite(worker.reservedAt) ? worker.reservedAt : now,
          waitingSince: now,
        },
        wait: {
          kind: "broker_review",
          headSha: state.headSha,
          reviewId: report.reviewId ?? null,
          claimRef: worker.claimRef,
          since: now,
        },
        blocker: null,
      };
      return { changed: true, state: next, effect: "wait", reason: "review_in_progress" };
    }
    if (
      new Set(["approved", "changes_requested", "failed_retryable", "failed_terminal"]).has(
        report.outcome,
      )
    ) {
      const claimRef = worker.claimRef;
      return applyReviewResult(
        {
          ...cleared,
          reviewLease: {
            kind: "review",
            flowId: worker.flowId ?? null,
            sessionKey: worker.sessionKey,
            headSha: worker.headSha,
            cycle: worker.cycle,
            claimRef,
            reviewId: report.reviewId ?? state.reviewLease?.reviewId ?? null,
            reservedAt: Number.isFinite(worker.reservedAt) ? worker.reservedAt : now,
          },
        },
        {
          eventId: `worker:${worker.runId ?? worker.sessionKey}:${report.outcome}`,
          repo: state.repo,
          prNumber: state.prNumber,
          headSha: state.headSha,
          outcome: report.outcome,
          reviewId: report.reviewId,
          claimRef,
          coverageComplete: report.coverageComplete,
          retryAllowed: report.retryAllowed,
          findings: report.findings,
          summary: report.summary,
        },
        now,
      );
    }
    return blockState(cleared, `unsupported_review_worker_outcome:${report.outcome}`, now);
  }

  if (report.kind !== "remediation") {
    throw new Error("worker report kind is invalid");
  }
  if (report.outcome === "primary_fixer_failed_retryable") {
    const primaryFixerFailure = primaryFixerFailureFromReport(state, report, now);
    if (!primaryFixerFailure) {
      return blockState(cleared, "primary_fixer_failure_evidence_invalid", now);
    }
    return {
      changed: true,
      state: {
        ...cleared,
        phase: PHASE.REMEDIATION_QUEUED,
        primaryFixerFailure,
        infrastructureRetryCount: Math.max(0, Number(state.infrastructureRetryCount) || 0) + 1,
        infrastructureRetryAt: null,
        infrastructureLastFailure: `primary_fixer:${primaryFixerFailure.reason}`,
        wait: null,
        blocker: null,
      },
      effect: "continue",
      reason: "primary_fixer_failure_recorded",
    };
  }
  if (report.outcome === "fixed_and_published") {
    const fixerAttestation = fixerAttestationFromReport(state, report, now);
    if (
      !report.testsPassed ||
      !report.publicationConfirmed ||
      !isSha(report.newHeadSha) ||
      !fixerAttestation
    ) {
      return blockState(cleared, "remediation_missing_test_or_publication_evidence", now);
    }
    if (report.newHeadSha === state.headSha) {
      return blockState(cleared, "published_head_did_not_change", now);
    }
    const nextCycle = state.cycle + 1;
    if (nextCycle > state.maxCycles) {
      return blockState(cleared, "review_fix_cycle_budget_exhausted", now);
    }
    const published = recordExternalMilestone(cleared, {
      kind: "commit_published",
      headSha: report.newHeadSha,
      observedAt: now,
      observedRevision: null,
      url: `https://github.com/${state.repo}/pull/${state.prNumber}/commits/${report.newHeadSha}`,
      receipt: { attestationRef: report.fixerAttestationRef },
    });
    const next = {
      ...published,
      phase: PHASE.WAITING_HEAD_EVENT,
      pendingPublication: {
        headSha: report.newHeadSha,
        cycle: nextCycle,
        fixerAttestation,
      },
      wait: {
        kind: "pull_request_head_confirmation",
        headSha: report.newHeadSha,
        since: now,
      },
      review: null,
      findings: [],
      primaryFixerFailure: consumedPrimaryFixerFailure(state, fixerAttestation, now),
      blocker: null,
    };
    return { changed: true, state: next, effect: "wait", reason: "awaiting_head_confirmation" };
  }
  if (report.outcome === "re_review_same_head") {
    const fixerAttestation = fixerAttestationFromReport(state, report, now);
    if (!report.verificationComplete || !fixerAttestation) {
      return blockState(cleared, "same_head_rereview_without_verification", now);
    }
    const nextCycle = state.cycle + 1;
    if (nextCycle > state.maxCycles) {
      return blockState(cleared, "review_fix_cycle_budget_exhausted", now);
    }
    return {
      changed: true,
      state: {
        ...cleared,
        phase: PHASE.REVIEW_QUEUED,
        cycle: nextCycle,
        retryCount: 0,
        cycleStartedAt: now,
        deadlineAt: state.deadlineAt,
        fixerAttestation,
        primaryFixerFailure: consumedPrimaryFixerFailure(state, fixerAttestation, now),
        wait: null,
        blocker: null,
      },
      effect: "continue",
      reason: "same_head_rereview",
    };
  }
  if (report.outcome === "stale_head") {
    return {
      changed: true,
      state: {
        ...cleared,
        phase: PHASE.WAITING_HEAD_EVENT,
        wait: { kind: "pull_request_head", since: now },
        blocker: null,
      },
      effect: "wait",
      reason: "stale_head",
    };
  }
  if (report.outcome === "ambiguous_publication") {
    return blockState(cleared, "ambiguous_publication_requires_reconciliation", now);
  }
  return blockState(cleared, report.summary ?? `remediation_blocked:${report.outcome}`, now);
}

export function applyWorkerFailure(state, callerSessionKey, reason, now = Date.now()) {
  if (!state.activeWorker || state.activeWorker.sessionKey !== callerSessionKey) {
    return { changed: false, state, effect: "none", reason: "stale_worker_failure" };
  }
  const kind = state.activeWorker.kind;
  const normalizedReason = cleanText(reason, 500, "reason");
  const cleared = recordTerminalEnvelope(
    { ...state, activeWorker: null, updatedAt: now },
    terminalEnvelope(
      state,
      state.activeWorker,
      { outcome: "execution_failure", summary: normalizedReason },
      now,
      { outcomeClass: "execution_failure", finalStage: `${kind}_execution` },
    ),
  );
  if (classifyWorkerFailure(normalizedReason) === "infrastructure") {
    if (now > state.deadlineAt) {
      return blockState(cleared, "wall_time_budget_exhausted", now);
    }
    const attempt = Math.max(0, Number(state.infrastructureRetryCount) || 0) + 1;
    if (attempt > MAX_INFRASTRUCTURE_RETRIES) {
      return blockState(cleared, `infrastructure_retry_exhausted:${normalizedReason}`, now);
    }
    const retryAt = Math.min(now + infrastructureBackoffMs(attempt), state.deadlineAt + 1);
    return {
      changed: true,
      state: {
        ...cleared,
        phase: retryPhase(state, kind),
        infrastructureRetryCount: attempt,
        infrastructureRetryAt: retryAt,
        infrastructureLastFailure: normalizedReason,
        orphanedWorker: {
          ...state.activeWorker,
          reason: normalizedReason,
          clearedAt: now,
        },
        wait: {
          kind: "infrastructure_backoff",
          reason: normalizedReason,
          attempt,
          retryAt,
        },
        blocker: null,
      },
      effect: "wait",
      reason: "retry_infrastructure",
    };
  }
  if (state.retryCount >= state.maxRetries || now > state.deadlineAt) {
    return blockState(cleared, `worker_failure_exhausted:${normalizedReason}`, now);
  }
  return {
    changed: true,
    state: {
      ...cleared,
      phase: retryPhase(state, kind),
      retryCount: state.retryCount + 1,
      wait: null,
      blocker: null,
    },
    effect: "continue",
    reason: "retry_worker",
  };
}

export function applyWorkerProtocolViolation(state, callerSessionKey, stage, now = Date.now()) {
  if (!state.activeWorker || state.activeWorker.sessionKey !== callerSessionKey) {
    return { changed: false, state, effect: "none", reason: "stale_worker_protocol_violation" };
  }
  const worker = state.activeWorker;
  const finalStage = cleanText(stage, 120, "stage");
  const reason = `worker_protocol_violation:${finalStage}`;
  const cleared = recordTerminalEnvelope(
    { ...state, activeWorker: null, updatedAt: now },
    terminalEnvelope(state, worker, { outcome: reason, summary: reason }, now, {
      outcomeClass: "protocol_violation",
      finalStage,
    }),
  );
  const attempt = Math.max(0, Number(state.protocolRetryCount) || 0) + 1;
  if (attempt > MAX_PROTOCOL_RETRIES) {
    return blockState(cleared, `${reason}:retry_exhausted`, now);
  }
  const retryAt = now + INFRASTRUCTURE_BACKOFF_BASE_MS;
  return {
    changed: true,
    state: {
      ...cleared,
      phase: retryPhase(state, worker.kind),
      protocolRetryCount: attempt,
      protocolRetryAt: retryAt,
      orphanedWorker: {
        ...worker,
        reason,
        clearedAt: now,
      },
      wait: { kind: "protocol_backoff", reason, attempt, retryAt },
      blocker: null,
    },
    effect: "wait",
    reason: "retry_worker_protocol_violation",
  };
}
