import assert from "node:assert/strict";
import test from "node:test";
import {
  PHASE,
  applyPullRequestEvent,
  applyWorkerFailure,
  applyWorkerReport,
  createState,
  holdsReviewLease,
  holdsWorkerLease,
  recoverState,
  reserveWorker,
} from "../src/controller.mjs";
import {
  NOW,
  SHA_A,
  SHA_B,
  SHA_C,
  applyCurrentReview,
  attachWorkerIdentity,
  finding,
  policy,
  prEvent,
  reserve,
} from "./controller-helpers-1.mjs";

void test("retries only publication-confirmed retryable reviews within budget", () => {
  const state = createState(prEvent(), policy({ maxRetries: 1 }), NOW);
  const notAllowed = applyCurrentReview(
    state,
    { outcome: "failed_retryable", retryAllowed: false },
    NOW + 1,
  );
  assert.equal(notAllowed.state.phase, PHASE.BLOCKED);

  const retry = applyCurrentReview(
    state,
    { outcome: "failed_retryable", retryAllowed: true },
    NOW + 1,
  );
  assert.equal(retry.state.phase, PHASE.REVIEW_QUEUED);
  assert.equal(retry.state.retryCount, 1);

  const exhausted = applyCurrentReview(
    { ...state, retryCount: 1 },
    { outcome: "failed_retryable", retryAllowed: true },
    NOW + 1,
  );
  assert.equal(exhausted.state.phase, PHASE.BLOCKED);
});

void test("reserves exactly one worker for the phase", () => {
  const state = createState(prEvent(), policy(), NOW);
  const first = reserveWorker(state, "review", "agent:owner-agent:subagent:one", NOW + 1);
  assert.equal(first.state.phase, PHASE.REVIEW_RUNNING);
  const second = reserveWorker(first.state, "review", "agent:owner-agent:subagent:two", NOW + 2);
  assert.equal(second.changed, false);
  assert.equal(second.reason, "worker_already_reserved");
  const wrongKind = reserveWorker(
    state,
    "remediation",
    "agent:owner-agent:subagent:wrong",
    NOW + 2,
  );
  assert.equal(wrongKind.changed, false);
  assert.equal(wrongKind.reason, "phase_not_dispatchable");
});

void test("fences worker reports by session, kind, head, and cycle", () => {
  const state = reserve(createState(prEvent(), policy(), NOW));
  const baseReport = {
    kind: "review",
    outcome: "waiting_review",
    headSha: SHA_A,
    cycle: 0,
    claimRef: state.activeWorker.claimRef,
  };
  assert.throws(
    () => applyWorkerReport(state, baseReport, "agent:owner-agent:subagent:other", NOW + 20),
    /does not own/,
  );
  assert.throws(
    () =>
      applyWorkerReport(state, { ...baseReport, headSha: SHA_C }, state.activeWorker.sessionKey),
    /exact head/,
  );
  assert.throws(
    () => applyWorkerReport(state, { ...baseReport, cycle: 1 }, state.activeWorker.sessionKey),
    /cycle is stale/,
  );
  assert.throws(
    () =>
      applyWorkerReport(
        state,
        { ...baseReport, claimRef: "claim:worker-supplied" },
        state.activeWorker.sessionKey,
        NOW + 20,
      ),
    /controller-issued claim/,
  );
});

void test("rejects an orphaned worker report before terminal-envelope or orphan mutation", () => {
  const reserved = reserve(createState(prEvent(), policy(), NOW));
  const orphanedWorker = {
    ...reserved.activeWorker,
    reason: "pull_request_head_changed",
    clearedAt: NOW + 15,
  };
  const lastTerminalEnvelope = {
    schemaVersion: 1,
    outcome: "prior_envelope",
    recordedAt: NOW + 5,
  };
  const terminalEnvelopeHistory = [{ schemaVersion: 1, outcome: "older_envelope" }];
  const state = {
    ...reserved,
    activeWorker: null,
    orphanedWorker,
    lastTerminalEnvelope,
    terminalEnvelopeHistory,
  };
  assert.throws(
    () =>
      applyWorkerReport(
        state,
        {
          kind: "review",
          outcome: "waiting_review",
          headSha: SHA_A,
          cycle: 0,
          claimRef: orphanedWorker.claimRef,
        },
        orphanedWorker.sessionKey,
        NOW + 20,
      ),
    { message: "flow has no active worker" },
  );
  assert.equal(state.activeWorker, null);
  assert.equal(state.orphanedWorker, orphanedWorker);
  assert.deepEqual(state.orphanedWorker, {
    ...reserved.activeWorker,
    reason: "pull_request_head_changed",
    clearedAt: NOW + 15,
  });
  assert.equal(state.lastTerminalEnvelope, lastTerminalEnvelope);
  assert.deepEqual(state.lastTerminalEnvelope, {
    schemaVersion: 1,
    outcome: "prior_envelope",
    recordedAt: NOW + 5,
  });
  assert.equal(state.terminalEnvelopeHistory, terminalEnvelopeHistory);
  assert.deepEqual(state.terminalEnvelopeHistory, [
    { schemaVersion: 1, outcome: "older_envelope" },
  ]);
});

void test("review worker can enter an external wait without polling", () => {
  const state = reserve(createState(prEvent(), policy(), NOW));
  const transition = applyWorkerReport(
    state,
    {
      kind: "review",
      outcome: "waiting_review",
      headSha: SHA_A,
      cycle: 0,
      reviewId: "pending-1",
      claimRef: state.activeWorker.claimRef,
    },
    state.activeWorker.sessionKey,
    NOW + 20,
  );
  assert.equal(transition.effect, "wait");
  assert.equal(transition.state.phase, PHASE.REVIEW_WAITING);
  assert.equal(transition.state.activeWorker, null);
  assert.equal(transition.state.wait.kind, "broker_review");
  assert.equal(transition.state.reviewLease.kind, "review");
  assert.equal(transition.state.reviewLease.claimRef, state.activeWorker.claimRef);
  assert.equal(holdsReviewLease(transition.state), true);
  assert.equal(holdsWorkerLease(transition.state), true);
});

void test("worker reports retain the exact worker identity as an orphan", () => {
  let state = createState(prEvent(), policy(), NOW);
  state = applyCurrentReview(
    state,
    { outcome: "changes_requested", findings: [finding()] },
    NOW + 1,
  ).state;
  state = attachWorkerIdentity(
    reserve(state, "remediation", "agent:author-worker:subagent:remediation"),
    "remediation",
  );
  const transition = applyWorkerReport(
    state,
    {
      kind: "remediation",
      ...remediationBinding(state),
      outcome: "fixed_and_published",
      headSha: SHA_A,
      cycle: 0,
      newHeadSha: SHA_C,
      testsPassed: true,
      publicationConfirmed: true,
      ...fixerProof(),
    },
    state.activeWorker.sessionKey,
    NOW + 20,
  );
  assert.equal(transition.state.phase, PHASE.WAITING_HEAD_EVENT);
  assert.equal(transition.state.activeWorker, null);
  assert.deepEqual(transition.state.orphanedWorker, {
    ...state.activeWorker,
    reason: "worker_report_received",
    clearedAt: NOW + 20,
  });
  assert.equal(holdsWorkerLease(transition.state), true);
});

void test("remediation accepts only tested, publication-confirmed new heads", () => {
  let state = createState(prEvent(), policy(), NOW);
  state = applyCurrentReview(
    state,
    { outcome: "changes_requested", findings: [finding()] },
    NOW + 1,
  ).state;
  state = reserve(state, "remediation", "agent:owner-agent:subagent:remediation");
  const incomplete = applyWorkerReport(
    state,
    {
      kind: "remediation",
      ...remediationBinding(state),
      outcome: "fixed_and_published",
      headSha: SHA_A,
      cycle: 0,
      newHeadSha: SHA_C,
      testsPassed: true,
      publicationConfirmed: false,
    },
    state.activeWorker.sessionKey,
    NOW + 20,
  );
  assert.equal(incomplete.state.phase, PHASE.BLOCKED);

  const fixed = applyWorkerReport(
    state,
    {
      kind: "remediation",
      ...remediationBinding(state),
      outcome: "fixed_and_published",
      headSha: SHA_A,
      cycle: 0,
      newHeadSha: SHA_C,
      testsPassed: true,
      publicationConfirmed: true,
      ...fixerProof(),
    },
    state.activeWorker.sessionKey,
    NOW + 20,
  );
  assert.equal(fixed.effect, "wait");
  assert.equal(fixed.reason, "awaiting_head_confirmation");
  assert.equal(fixed.state.phase, PHASE.WAITING_HEAD_EVENT);
  assert.equal(fixed.state.headSha, SHA_A);
  assert.equal(fixed.state.cycle, 0);
  assert.equal(fixed.state.pendingPublication.headSha, SHA_C);
  assert.equal(fixed.state.fixerAttestation, null);

  const ownerAttempt = applyPullRequestEvent(
    fixed.state,
    prEvent({
      eventId: "owner-admit:untrusted-head",
      action: "synchronize",
      headSha: SHA_C,
    }),
    policy(),
    NOW + 25,
  );
  assert.equal(ownerAttempt.changed, false);
  assert.equal(ownerAttempt.reason, "pending_publication_requires_github_confirmation");
  assert.equal(ownerAttempt.state.headSha, SHA_A);

  const confirmed = applyPullRequestEvent(
    fixed.state,
    prEvent({
      eventId: "github:event-2",
      action: "synchronize",
      headSha: SHA_C,
      updatedAt: "2026-09-05T00:00:02Z",
    }),
    policy(),
    NOW + 30,
  );
  assert.equal(confirmed.reason, "published_head_confirmed");
  assert.equal(confirmed.state.phase, PHASE.REVIEW_QUEUED);
  assert.equal(confirmed.state.headSha, SHA_C);
  assert.equal(confirmed.state.cycle, 1);
  assert.equal(confirmed.state.pendingPublication, null);
  assert.deepEqual(confirmed.state.findings, []);
  assert.equal(confirmed.state.fixerAttestation.model, "primary-fixer");
});

void test("fallback fixer requires exact single-use controller-owned primary failure evidence", () => {
  let state = createState(prEvent(), policy(), NOW);
  state = applyCurrentReview(
    state,
    { outcome: "changes_requested", findings: [finding()] },
    NOW + 1,
  ).state;
  state = attachWorkerIdentity(
    reserve(state, "remediation", "agent:author-worker:subagent:primary"),
    "primary",
  );
  const fabricated = applyWorkerReport(
    state,
    {
      kind: "remediation",
      ...remediationBinding(state),
      outcome: "re_review_same_head",
      headSha: SHA_A,
      cycle: 0,
      verificationComplete: true,
      ...fixerProof({
        fixerModel: "fallback-fixer",
        fixerFallbackReason: "primary_model_transport_unavailable",
        fixerPrimaryFailureRef: "primary-failure:fabricated",
      }),
    },
    state.activeWorker.sessionKey,
    NOW + 20,
  );
  assert.equal(fabricated.state.phase, PHASE.BLOCKED);

  const contentFailure = applyWorkerReport(
    state,
    {
      kind: "remediation",
      ...remediationBinding(state),
      outcome: "primary_fixer_failed_retryable",
      headSha: SHA_A,
      cycle: 0,
      ...fixerProof({ fixerFallbackReason: "primary_model_content_failure" }),
    },
    state.activeWorker.sessionKey,
    NOW + 20,
  );
  assert.equal(contentFailure.state.phase, PHASE.BLOCKED);

  const recorded = applyWorkerReport(
    state,
    {
      kind: "remediation",
      ...remediationBinding(state),
      outcome: "primary_fixer_failed_retryable",
      headSha: SHA_A,
      cycle: 0,
      ...fixerProof({
        fixerFallbackReason: "primary_model_transport_unavailable",
      }),
    },
    state.activeWorker.sessionKey,
    NOW + 20,
  );
  assert.equal(recorded.state.phase, PHASE.REMEDIATION_QUEUED);
  assert.equal(recorded.reason, "primary_fixer_failure_recorded");
  assert.equal(recorded.state.primaryFixerFailure.headSha, SHA_A);
  assert.equal(recorded.state.primaryFixerFailure.cycle, 0);
  assert.equal(recorded.state.primaryFixerFailure.workerRunId, "run-primary");
  assert.equal(recorded.state.primaryFixerFailure.workerTaskId, "task-primary");
  const failureRef = recorded.state.primaryFixerFailure.ref;

  const repeatedPrimaryState = attachWorkerIdentity(
    reserve(recorded.state, "remediation", "agent:author-worker:subagent:repeat-primary", NOW + 21),
    "repeat-primary",
  );
  const repeatedPrimary = applyWorkerReport(
    repeatedPrimaryState,
    {
      kind: "remediation",
      ...remediationBinding(state),
      outcome: "primary_fixer_failed_retryable",
      headSha: SHA_A,
      cycle: 0,
      ...fixerProof({ fixerFallbackReason: "primary_model_timeout" }),
    },
    repeatedPrimaryState.activeWorker.sessionKey,
    NOW + 30,
  );
  assert.equal(repeatedPrimary.state.phase, PHASE.BLOCKED);

  for (const [label, primaryFixerFailure] of [
    ["stale head", { ...recorded.state.primaryFixerFailure, headSha: SHA_B }],
    ["stale cycle", { ...recorded.state.primaryFixerFailure, cycle: 1 }],
  ]) {
    const staleState = attachWorkerIdentity(
      reserve(
        { ...recorded.state, primaryFixerFailure },
        "remediation",
        `agent:author-worker:subagent:${label.replace(" ", "-")}`,
        NOW + 21,
      ),
      label.replace(" ", "-"),
    );
    const stale = applyWorkerReport(
      staleState,
      {
        kind: "remediation",
        ...remediationBinding(state),
        outcome: "re_review_same_head",
        headSha: SHA_A,
        cycle: 0,
        verificationComplete: true,
        ...fixerProof({
          fixerModel: "fallback-fixer",
          fixerFallbackReason: "primary_model_transport_unavailable",
          fixerPrimaryFailureRef: failureRef,
        }),
      },
      staleState.activeWorker.sessionKey,
      NOW + 30,
    );
    assert.equal(stale.state.phase, PHASE.BLOCKED, label);
  }

  const otherFlowState = attachWorkerIdentity(
    reserve(recorded.state, "remediation", "agent:author-worker:subagent:other-flow", NOW + 21),
    "other-flow",
    "flow-other",
  );
  const otherFlow = applyWorkerReport(
    otherFlowState,
    {
      kind: "remediation",
      ...remediationBinding(state),
      outcome: "re_review_same_head",
      headSha: SHA_A,
      cycle: 0,
      verificationComplete: true,
      ...fixerProof({
        fixerModel: "fallback-fixer",
        fixerFallbackReason: "primary_model_transport_unavailable",
        fixerPrimaryFailureRef: failureRef,
      }),
    },
    otherFlowState.activeWorker.sessionKey,
    NOW + 30,
  );
  assert.equal(otherFlow.state.phase, PHASE.BLOCKED);

  const fallbackState = attachWorkerIdentity(
    reserve(recorded.state, "remediation", "agent:author-worker:subagent:fallback", NOW + 21),
    "fallback",
  );
  const accepted = applyWorkerReport(
    fallbackState,
    {
      kind: "remediation",
      ...remediationBinding(state),
      outcome: "re_review_same_head",
      headSha: SHA_A,
      cycle: 0,
      verificationComplete: true,
      ...fixerProof({
        fixerModel: "fallback-fixer",
        fixerFallbackReason: "primary_model_transport_unavailable",
        fixerPrimaryFailureRef: failureRef,
      }),
    },
    fallbackState.activeWorker.sessionKey,
    NOW + 30,
  );
  assert.equal(accepted.state.phase, PHASE.REVIEW_QUEUED);
  assert.equal(accepted.state.fixerAttestation.fallbackUsed, true);
  assert.equal(accepted.state.fixerAttestation.primaryFailureRef, failureRef);
  assert.equal(accepted.state.primaryFixerFailure.consumedAt, NOW + 30);
  assert.equal(accepted.state.primaryFixerFailure.consumedBy.runId, "run-fallback");

  const reusedState = attachWorkerIdentity(
    reserve(
      {
        ...recorded.state,
        primaryFixerFailure: accepted.state.primaryFixerFailure,
      },
      "remediation",
      "agent:author-worker:subagent:reuse",
      NOW + 31,
    ),
    "reuse",
  );
  const reused = applyWorkerReport(
    reusedState,
    {
      kind: "remediation",
      ...remediationBinding(state),
      outcome: "re_review_same_head",
      headSha: SHA_A,
      cycle: 0,
      verificationComplete: true,
      ...fixerProof({
        fixerModel: "fallback-fixer",
        fixerFallbackReason: "primary_model_transport_unavailable",
        fixerPrimaryFailureRef: failureRef,
      }),
    },
    reusedState.activeWorker.sessionKey,
    NOW + 40,
  );
  assert.equal(reused.state.phase, PHASE.BLOCKED);
});

void test("primary fixer attestation rejects fallback-only evidence fields", () => {
  let state = createState(prEvent(), policy(), NOW);
  state = applyCurrentReview(
    state,
    { outcome: "changes_requested", findings: [finding()] },
    NOW + 1,
  ).state;
  state = reserve(state, "remediation", "agent:author-worker:subagent:remediation");
  const transition = applyWorkerReport(
    state,
    {
      kind: "remediation",
      ...remediationBinding(state),
      outcome: "re_review_same_head",
      headSha: SHA_A,
      cycle: 0,
      verificationComplete: true,
      ...fixerProof({
        fixerFallbackReason: "primary_model_timeout",
        fixerPrimaryFailureRef: "task:should-not-exist",
      }),
    },
    state.activeWorker.sessionKey,
    NOW + 20,
  );
  assert.equal(transition.state.phase, PHASE.BLOCKED);
});

void test("two fix cycles end at a final review and never launch a third fixer", () => {
  const reserved = reserve(createState(prEvent(), policy({ maxCycles: 2 }), NOW));
  const state = {
    ...reserved,
    cycle: 2,
    activeWorker: {
      ...reserved.activeWorker,
      cycle: 2,
    },
  };
  const transition = applyCurrentReview(
    state,
    { outcome: "changes_requested", findings: [finding()] },
    NOW + 20,
  );
  assert.equal(transition.state.phase, PHASE.BLOCKED);
  assert.equal(transition.state.blocker, "review_fix_cycle_budget_exhausted");
});

void test("ambiguous publication is a durable manual block", () => {
  let state = createState(prEvent(), policy(), NOW);
  state = applyCurrentReview(
    state,
    { outcome: "changes_requested", findings: [finding()] },
    NOW + 1,
  ).state;
  state = reserve(state, "remediation", "agent:owner-agent:subagent:remediation");
  const transition = applyWorkerReport(
    state,
    {
      kind: "remediation",
      ...remediationBinding(state),
      outcome: "ambiguous_publication",
      headSha: SHA_A,
      cycle: 0,
    },
    state.activeWorker.sessionKey,
    NOW + 20,
  );
  assert.equal(transition.state.phase, PHASE.BLOCKED);
  assert.match(transition.state.blocker, /requires_reconciliation/);
});

void test("bounded same-head re-review requires independent verification", () => {
  let state = createState(prEvent(), policy(), NOW);
  state = applyCurrentReview(
    state,
    { outcome: "changes_requested", findings: [finding()] },
    NOW + 1,
  ).state;
  state = reserve(state, "remediation", "agent:owner-agent:subagent:remediation");
  const rejected = applyWorkerReport(
    state,
    {
      kind: "remediation",
      ...remediationBinding(state),
      outcome: "re_review_same_head",
      headSha: SHA_A,
      cycle: 0,
      verificationComplete: false,
    },
    state.activeWorker.sessionKey,
    NOW + 20,
  );
  assert.equal(rejected.state.phase, PHASE.BLOCKED);

  const accepted = applyWorkerReport(
    state,
    {
      kind: "remediation",
      ...remediationBinding(state),
      outcome: "re_review_same_head",
      headSha: SHA_A,
      cycle: 0,
      verificationComplete: true,
      ...fixerProof(),
    },
    state.activeWorker.sessionKey,
    NOW + 20,
  );
  assert.equal(accepted.state.phase, PHASE.REVIEW_QUEUED);
  assert.equal(accepted.state.headSha, SHA_A);
  assert.equal(accepted.state.cycle, 1);
});

void test("worker failure retries within budget and ignores stale failure reports", () => {
  const state = reserve(createState(prEvent(), policy({ maxRetries: 1 }), NOW));
  const stale = applyWorkerFailure(state, "agent:owner-agent:subagent:other", "failed", NOW + 20);
  assert.equal(stale.changed, false);
  const retry = applyWorkerFailure(state, state.activeWorker.sessionKey, "failed", NOW + 20);
  assert.equal(retry.state.phase, PHASE.REVIEW_QUEUED);
  assert.equal(retry.state.retryCount, 1);
  const reReserved = reserve(retry.state);
  const exhausted = applyWorkerFailure(
    reReserved,
    reReserved.activeWorker.sessionKey,
    "failed again",
    NOW + 30,
  );
  assert.equal(exhausted.state.phase, PHASE.BLOCKED);
});

void test("restart recovery waits for active work and blocks success without a report", () => {
  const state = reserve(createState(prEvent(), policy(), NOW));
  const active = recoverState(state, { status: "running" }, NOW + 200_000, 120_000, {
    sessionAlive: true,
  });
  assert.equal(active.effect, "wait");
  assert.equal(active.reason, "worker_active");
  const missingReport = recoverState(state, { status: "succeeded" }, NOW + 200_000);
  assert.equal(missingReport.effect, "wait");
  assert.equal(missingReport.reason, "retry_worker_protocol_violation");
  assert.equal(missingReport.state.phase, PHASE.REVIEW_QUEUED);
  assert.equal(missingReport.state.activeWorker, null);
  assert.equal(missingReport.state.retryCount, 0);
  assert.equal(missingReport.state.infrastructureRetryCount, 0);
  assert.equal(missingReport.state.protocolRetryCount, 1);
  assert.equal(missingReport.state.wait.kind, "protocol_backoff");
  assert.equal(missingReport.state.lastTerminalEnvelope.outcomeClass, "protocol_violation");
  assert.equal(missingReport.state.lastTerminalEnvelope.finalStage, "review_report");
});
