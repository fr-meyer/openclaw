import { PHASE, STATE_SCHEMA_VERSION } from "./controller-constants.mjs";
import {
  findingsAreActionable,
  mergePolicyDigest,
  normalizePolicy,
  publisherBoundaryFromPolicy,
} from "./controller-policy.mjs";
import { blockState, budgetBlock, isLifecycleState, isTerminalState } from "./controller-state.mjs";
import {
  appendSeenEvent,
  maxGithubUpdatedAt,
  normalizeCheckSuiteEvent,
  normalizePullRequestEvent,
  normalizeReviewResult,
  recordExternalMilestone,
  reviewMilestone,
  staleCheckSuiteEvent,
} from "./controller-validation.mjs";
export { isLifecycleState, isTerminalState, budgetBlock } from "./controller-state.mjs";

export function applyCheckSuiteEvent(state, eventInput, now = Date.now()) {
  if (!isLifecycleState(state)) {
    throw new Error("stored lifecycle state is invalid");
  }
  const event = normalizeCheckSuiteEvent(eventInput);
  if (event.repo !== state.repo || event.prNumber !== state.prNumber) {
    throw new Error("check suite event does not match this flow");
  }
  if (state.seenEventIds.includes(event.eventId)) {
    return { changed: false, state, effect: "none", reason: "duplicate_event" };
  }
  if (event.headSha !== state.headSha) {
    return { changed: false, state, effect: "none", reason: "stale_head_result" };
  }
  const currentWait = state.phase === PHASE.MERGE_QUEUED ? state.wait : null;
  if (staleCheckSuiteEvent(currentWait, event)) {
    return {
      changed: true,
      state: appendSeenEvent({ ...state, updatedAt: now }, event.eventId),
      effect: "none",
      reason: "stale_check_suite_event",
    };
  }
  const completedForQueuedMerge =
    state.phase === PHASE.MERGE_QUEUED && event.action === "completed";
  const next = appendSeenEvent(
    {
      ...state,
      wait: completedForQueuedMerge
        ? null
        : state.phase === PHASE.MERGE_QUEUED
          ? {
              kind: "check_suite",
              origin: "github_event",
              since: now,
              headSha: state.headSha,
              action: event.action,
              suiteId: event.suiteId,
              githubUpdatedAt: event.githubUpdatedAt,
              url: event.url,
            }
          : state.wait,
      updatedAt: now,
    },
    event.eventId,
  );
  return {
    changed: true,
    state: next,
    effect: completedForQueuedMerge ? "continue" : "none",
    reason: completedForQueuedMerge
      ? "check_suite_reconcile"
      : state.phase === PHASE.MERGE_QUEUED
        ? "check_suite_pending"
        : "check_suite_recorded",
  };
}

export function createState(eventInput, policyInput, now = Date.now()) {
  const event = normalizePullRequestEvent(eventInput);
  const policy = normalizePolicy(policyInput);
  const currentMergePolicyDigest = mergePolicyDigest(policy, event.repo);
  if (
    policy.mergeAuthorization &&
    policy.mergeAuthorization.policyDigest !== currentMergePolicyDigest
  ) {
    throw new Error("mergeAuthorization.policyDigest does not match repository policy");
  }
  if (!policy.enabled) {
    throw new Error("repository policy is disabled");
  }
  if (!policy.baseBranches.includes(event.baseRef)) {
    throw new Error("pull request base branch is not allowlisted");
  }
  if (!policy.allowForks && event.headRepo !== event.repo) {
    throw new Error("fork pull requests are not allowed");
  }
  return {
    schemaVersion: STATE_SCHEMA_VERSION,
    repo: event.repo,
    prNumber: event.prNumber,
    headSha: event.headSha,
    baseSha: event.baseSha,
    baseRef: event.baseRef,
    headRef: event.headRef,
    phase: PHASE.REVIEW_QUEUED,
    cycle: 0,
    retryCount: 0,
    infrastructureRetryCount: 0,
    infrastructureRetryAt: null,
    infrastructureLastFailure: null,
    protocolRetryCount: 0,
    protocolRetryAt: null,
    orphanedWorker: null,
    lastGhostCleanup: null,
    workspacePreflight: null,
    maxCycles: policy.maxCycles,
    maxRetries: policy.maxRetries,
    wallTimeMinutes: policy.wallTimeMinutes,
    startedAt: now,
    cycleStartedAt: now,
    deadlineAt: now + policy.wallTimeMinutes * 60_000,
    mode: policy.mode,
    reviewActor: policy.reviewActor,
    authorActor: policy.authorActor,
    fixerModel: policy.fixerModel,
    fixerFallbackModel: policy.fixerFallbackModel,
    publisherBoundary: publisherBoundaryFromPolicy(policy),
    githubUpdatedAt: event.githubUpdatedAt,
    pendingGithubReconciliation: null,
    pendingPublication: null,
    remediatorProfile: policy.remediatorProfile,
    remediatorProfileDigest: policy.remediatorProfile?.digest ?? null,
    configuredRemediatorProfileDigest: policy.remediatorProfile?.digest ?? null,
    mergeAuthorization: policy.mergeAuthorization,
    configuredMergeAuthorizationDigest: policy.mergeAuthorization?.digest ?? null,
    mergePolicyDigest: currentMergePolicyDigest,
    brokerRepoAlias: policy.brokerRepoAlias,
    autoMergeBaseBranches: policy.autoMergeBaseBranches,
    autoMergeMethod: policy.autoMergeMethod,
    activeWorker: null,
    reviewLease: null,
    fixerAttestation: null,
    primaryFixerFailure: null,
    review: null,
    findings: [],
    wait: null,
    blocker: null,
    mergeReady: null,
    mergeGates: null,
    prEffects: "none",
    latestExternalMilestone: null,
    externalMilestoneHistory: [],
    lastTerminalEnvelope: null,
    terminalEnvelopeHistory: [],
    terminalSupersession: null,
    notificationDeliveries: [],
    seenEventIds: [event.eventId],
    updatedAt: now,
  };
}

export function reviewLeaseBindingReason(lease, result) {
  if (!lease || lease.kind !== "review") {
    return "unsolicited_review_result";
  }
  if (lease.claimRef && result.claimRef !== lease.claimRef) {
    return "mismatched_review_claim";
  }
  if (lease.reviewId && result.reviewId !== lease.reviewId) {
    return "mismatched_review_id";
  }
  return null;
}

export function matchingCurrentReviewLease(state) {
  if (!state || typeof state !== "object") {
    return null;
  }
  if (
    state.activeWorker?.kind === "review" &&
    state.activeWorker.headSha === state.headSha &&
    state.activeWorker.cycle === state.cycle
  ) {
    return state.activeWorker;
  }
  if (
    state.reviewLease?.kind === "review" &&
    state.reviewLease.headSha === state.headSha &&
    state.reviewLease.cycle === state.cycle
  ) {
    return state.reviewLease;
  }
  return null;
}

export function holdsReviewLease(state) {
  if (!state || typeof state !== "object") {
    return false;
  }
  if (state.activeWorker?.kind === "review") {
    return true;
  }
  return state.reviewLease?.kind === "review";
}

export function holdsWorkerLease(state) {
  return Boolean(state?.activeWorker) || Boolean(state?.orphanedWorker) || holdsReviewLease(state);
}

export function applyPullRequestEvent(state, eventInput, policyInput, now = Date.now()) {
  if (!isLifecycleState(state)) {
    throw new Error("stored lifecycle state is invalid");
  }
  const event = normalizePullRequestEvent(eventInput);
  const policy = normalizePolicy(policyInput);
  if (event.repo !== state.repo || event.prNumber !== state.prNumber) {
    throw new Error("pull request event does not match this flow");
  }
  const currentMergePolicyDigest = mergePolicyDigest(policy, event.repo);
  if (
    policy.mergeAuthorization &&
    policy.mergeAuthorization.policyDigest !== currentMergePolicyDigest
  ) {
    return blockState(state, "merge_authorization_policy_digest_mismatch", now, event.eventId);
  }
  if (state.seenEventIds.includes(event.eventId)) {
    return { changed: false, state, effect: "none", reason: "duplicate_event" };
  }
  if (!policy.baseBranches.includes(event.baseRef)) {
    return blockState(state, "base_branch_not_allowlisted", now, event.eventId);
  }
  if (!policy.allowForks && event.headRepo !== event.repo) {
    return blockState(state, "fork_not_allowed", now, event.eventId);
  }
  const baseChanged = event.baseSha !== state.baseSha || event.baseRef !== state.baseRef;
  if (
    (event.headSha !== state.headSha || baseChanged) &&
    event.eventId.startsWith("github:") &&
    // oxlint-disable-next-line typescript/no-unnecessary-boolean-literal-compare -- Only literal true grants authority; preserve rejection of truthy non-booleans at runtime.
    event.authoritative !== true
  ) {
    if (
      Number.isSafeInteger(state.githubUpdatedAt) &&
      event.githubUpdatedAt < state.githubUpdatedAt
    ) {
      return { changed: false, state, effect: "none", reason: "stale_github_event" };
    }
    if (
      Number.isSafeInteger(state.githubUpdatedAt) &&
      event.githubUpdatedAt === state.githubUpdatedAt
    ) {
      const ambiguous = appendSeenEvent(
        {
          ...state,
          pendingGithubReconciliation: {
            eventId: event.eventId,
            action: event.action,
            headSha: event.headSha,
            baseSha: event.baseSha,
            baseRef: event.baseRef,
            headRepo: event.headRepo,
            githubUpdatedAt: event.githubUpdatedAt,
            detectedAt: now,
          },
          wait: {
            kind: "github_head_reconciliation",
            since: now,
            eventId: event.eventId,
          },
          updatedAt: now,
        },
        event.eventId,
      );
      return {
        changed: true,
        state: ambiguous,
        effect: "reconcile",
        reason: "github_event_order_ambiguous",
      };
    }
  }
  if (event.headSha === state.headSha && !baseChanged) {
    if (isTerminalState(state)) {
      return {
        changed: true,
        state: appendSeenEvent(
          {
            ...state,
            githubUpdatedAt: maxGithubUpdatedAt(state, event),
            pendingGithubReconciliation: null,
            wait: null,
            updatedAt: now,
          },
          event.eventId,
        ),
        effect: "none",
        reason: "terminal_same_head",
      };
    }
    return {
      changed: true,
      state: appendSeenEvent(
        {
          ...state,
          githubUpdatedAt: maxGithubUpdatedAt(state, event),
          pendingGithubReconciliation: null,
          wait: null,
          updatedAt: now,
        },
        event.eventId,
      ),
      effect: "none",
      reason: "same_head_event",
    };
  }
  const changeReason =
    event.headSha !== state.headSha ? "pull_request_head_changed" : "pull_request_base_changed";
  const orphanedWorker = state.activeWorker
    ? {
        ...state.activeWorker,
        reason: changeReason,
        clearedAt: now,
      }
    : state.orphanedWorker
      ? {
          ...state.orphanedWorker,
          reason: changeReason,
          clearedAt: now,
        }
      : state.reviewLease?.kind === "review"
        ? {
            kind: "review",
            sessionKey: state.reviewLease.sessionKey,
            flowId: state.reviewLease.flowId ?? null,
            headSha: state.reviewLease.headSha,
            cycle: state.reviewLease.cycle,
            reservedAt: state.reviewLease.reservedAt,
            runId: null,
            taskId: null,
            reason: changeReason,
            clearedAt: now,
          }
        : (state.orphanedWorker ?? null);
  const policyDeadline = now + policy.wallTimeMinutes * 60_000;
  const deadlineAt = Number.isFinite(state.deadlineAt)
    ? Math.min(state.deadlineAt, policyDeadline)
    : policyDeadline;
  if (state.pendingPublication && !event.eventId.startsWith("github:")) {
    return {
      changed: false,
      state,
      effect: "wait",
      reason: "pending_publication_requires_github_confirmation",
    };
  }
  const pendingPublication =
    event.eventId.startsWith("github:") &&
    event.action === "synchronize" &&
    state.pendingPublication?.headSha === event.headSha &&
    Number.isInteger(state.pendingPublication?.cycle) &&
    state.pendingPublication.cycle === state.cycle + 1
      ? state.pendingPublication
      : null;
  const next = appendSeenEvent(
    {
      ...supersedeExternalMilestone(state, now),
      headSha: event.headSha,
      baseSha: event.baseSha,
      baseRef: event.baseRef,
      headRef: event.headRef,
      phase: PHASE.REVIEW_QUEUED,
      cycle: pendingPublication?.cycle ?? 0,
      retryCount: 0,
      infrastructureRetryCount: 0,
      infrastructureRetryAt: null,
      infrastructureLastFailure: null,
      protocolRetryCount: 0,
      protocolRetryAt: null,
      orphanedWorker,
      maxCycles: policy.maxCycles,
      maxRetries: policy.maxRetries,
      wallTimeMinutes: policy.wallTimeMinutes,
      startedAt: Number.isFinite(state.startedAt) ? state.startedAt : now,
      cycleStartedAt: now,
      deadlineAt,
      lastGhostCleanup: null,
      workspacePreflight: null,
      mode: policy.mode,
      reviewActor: policy.reviewActor,
      authorActor: policy.authorActor,
      fixerModel: policy.fixerModel,
      fixerFallbackModel: policy.fixerFallbackModel,
      publisherBoundary: publisherBoundaryFromPolicy(policy),
      githubUpdatedAt: maxGithubUpdatedAt(state, event),
      pendingGithubReconciliation: null,
      pendingPublication: null,
      remediatorProfile: policy.remediatorProfile,
      remediatorProfileDigest: policy.remediatorProfile?.digest ?? null,
      configuredRemediatorProfileDigest: policy.remediatorProfile?.digest ?? null,
      mergeAuthorization: policy.mergeAuthorization,
      configuredMergeAuthorizationDigest: policy.mergeAuthorization?.digest ?? null,
      mergePolicyDigest: currentMergePolicyDigest,
      brokerRepoAlias: policy.brokerRepoAlias,
      autoMergeBaseBranches: policy.autoMergeBaseBranches,
      autoMergeMethod: policy.autoMergeMethod,
      activeWorker: null,
      reviewLease:
        state.reviewLease?.kind === "review"
          ? {
              ...state.reviewLease,
              reason: "pull_request_head_changed",
              supersededByHeadSha: event.headSha,
            }
          : null,
      fixerAttestation: pendingPublication?.fixerAttestation ?? null,
      primaryFixerFailure: pendingPublication ? state.primaryFixerFailure : null,
      review: null,
      findings: [],
      wait: null,
      blocker: null,
      mergeReady: null,
      mergeGates: null,
      terminalSupersession: null,
      updatedAt: now,
    },
    event.eventId,
  );
  return {
    changed: true,
    state: next,
    effect: "continue",
    reason: pendingPublication
      ? "published_head_confirmed"
      : event.headSha === state.headSha
        ? "base_changed"
        : "new_head",
  };
}

export function applyReviewResult(state, resultInput, now = Date.now()) {
  if (!isLifecycleState(state)) {
    throw new Error("stored lifecycle state is invalid");
  }
  const result = normalizeReviewResult(resultInput);
  if (result.repo !== state.repo || result.prNumber !== state.prNumber) {
    throw new Error("review result does not match this flow");
  }
  if (state.seenEventIds.includes(result.eventId)) {
    return { changed: false, state, effect: "none", reason: "duplicate_event" };
  }
  if (result.headSha !== state.headSha) {
    if (state.reviewLease?.kind === "review" && state.reviewLease.headSha === result.headSha) {
      const staleBinding = reviewLeaseBindingReason(state.reviewLease, result);
      if (staleBinding) {
        return { changed: false, state, effect: "none", reason: staleBinding };
      }
      return {
        changed: true,
        state: appendSeenEvent(
          {
            ...state,
            reviewLease: null,
            orphanedWorker:
              state.orphanedWorker?.headSha === result.headSha ? null : state.orphanedWorker,
            updatedAt: now,
          },
          result.eventId,
        ),
        effect: "none",
        reason: "stale_head_lease_released",
      };
    }
    return {
      changed: false,
      state,
      effect: "none",
      reason: "stale_head_result",
    };
  }
  if (
    !new Set([PHASE.REVIEW_QUEUED, PHASE.REVIEW_RUNNING, PHASE.REVIEW_WAITING]).has(state.phase)
  ) {
    return { changed: false, state, effect: "none", reason: "unexpected_review_phase" };
  }
  const lease = matchingCurrentReviewLease(state);
  if (!lease) {
    return { changed: false, state, effect: "none", reason: "unsolicited_review_result" };
  }
  const bindingReason = reviewLeaseBindingReason(lease, result);
  if (bindingReason) {
    return { changed: false, state, effect: "none", reason: bindingReason };
  }
  if (result.outcome === "approved" && !result.reviewId) {
    return { changed: false, state, effect: "none", reason: "approval_without_review_id" };
  }
  const activeReviewWorker =
    state.activeWorker?.kind === "review"
      ? {
          ...state.activeWorker,
          reason: "review_completion_received",
          clearedAt: now,
        }
      : null;
  const withEvent = appendSeenEvent(
    activeReviewWorker
      ? {
          ...state,
          activeWorker: null,
          orphanedWorker: activeReviewWorker,
        }
      : state,
    result.eventId,
  );
  const milestone = reviewMilestone(state, result, now);
  const withReviewEffect = milestone ? recordExternalMilestone(withEvent, milestone) : withEvent;
  const review = {
    reviewId: result.reviewId ?? null,
    headSha: result.headSha,
    outcome: result.outcome,
    coverageComplete: result.coverageComplete,
    findingsCount: result.findings.length,
    summary: result.summary ?? null,
    observedAt: now,
  };
  if (result.outcome === "approved") {
    if (!result.coverageComplete || result.findings.length !== 0) {
      return blockState(withReviewEffect, "approval_without_complete_zero_finding_coverage", now);
    }
    const next = {
      ...withReviewEffect,
      phase: PHASE.MERGE_READY,
      activeWorker: null,
      reviewLease: null,
      infrastructureRetryCount: 0,
      infrastructureRetryAt: null,
      infrastructureLastFailure: null,
      protocolRetryCount: 0,
      protocolRetryAt: null,
      orphanedWorker: withReviewEffect.orphanedWorker ?? null,
      review,
      findings: [],
      wait: null,
      blocker: null,
      mergeReady: {
        headSha: state.headSha,
        reviewId: result.reviewId ?? null,
        coverageComplete: true,
        findingsCount: 0,
        reachedAt: now,
        mergeAuthorized: false,
        mergeMethod: state.autoMergeMethod ?? "merge",
        authorizationDigest: null,
        authorizationAdoptedAt: null,
      },
      updatedAt: now,
    };
    return {
      changed: true,
      state: next,
      effect: "merge_ready",
      reason: "approved",
    };
  }
  if (result.outcome === "changes_requested") {
    if (!result.coverageComplete || result.findings.length === 0) {
      return blockState(withReviewEffect, "changes_requested_without_complete_findings", now);
    }
    if (!findingsAreActionable(result.findings)) {
      return blockState(withReviewEffect, "changes_requested_without_actionable_paths", now);
    }
    const reviewed = {
      ...withReviewEffect,
      review,
      findings: result.findings,
    };
    const budget = budgetBlock(reviewed, now);
    if (budget) {
      return budget;
    }
    if (reviewed.cycle >= reviewed.maxCycles) {
      return blockState(reviewed, "review_fix_cycle_budget_exhausted", now);
    }
    const next = {
      ...reviewed,
      phase: PHASE.REMEDIATION_QUEUED,
      activeWorker: null,
      reviewLease: null,
      fixerAttestation: null,
      primaryFixerFailure: null,
      review,
      findings: result.findings,
      wait: null,
      blocker: null,
      retryCount: 0,
      infrastructureRetryCount: 0,
      infrastructureRetryAt: null,
      infrastructureLastFailure: null,
      protocolRetryCount: 0,
      protocolRetryAt: null,
      orphanedWorker: reviewed.orphanedWorker ?? null,
      updatedAt: now,
    };
    return { changed: true, state: next, effect: "continue", reason: "findings_ready" };
  }
  if (result.outcome === "failed_retryable") {
    if (!result.retryAllowed || state.retryCount >= state.maxRetries) {
      return blockState(withReviewEffect, "review_retry_not_allowed_or_exhausted", now);
    }
    const budget = budgetBlock(withReviewEffect, now);
    if (budget) {
      return budget;
    }
    const next = {
      ...withReviewEffect,
      phase: PHASE.REVIEW_QUEUED,
      activeWorker: null,
      reviewLease: null,
      review,
      wait: null,
      blocker: null,
      retryCount: state.retryCount + 1,
      updatedAt: now,
    };
    return { changed: true, state: next, effect: "continue", reason: "retry_review" };
  }
  return blockState(withReviewEffect, "review_failed_terminal", now);
}
