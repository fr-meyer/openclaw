import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { Readable } from "node:stream";
import test from "node:test";
import {
  PHASE,
  applyPullRequestEvent,
  applyReviewResult,
  applyWorkerFailure,
  applyWorkerReport,
  classifyWorkerFailure,
  createState,
  holdsReviewLease,
  recoverState,
  refreshPolicySnapshot,
  reserveWorker,
  sanitizeFindings,
} from "../src/controller.mjs";
import {
  createFixedWindowLimiter,
  createInFlightLimiter,
  parseBrokerReviewEvent,
  parseGitHubPullRequest,
  readJsonBody,
  verifySha256Signature,
} from "../src/http.mjs";
import {
  NOW,
  SHA_A,
  SHA_B,
  SHA_C,
  applyCurrentReview,
  finding,
  policy,
  prEvent,
  reserve,
  reviewResult,
} from "./controller-helpers-1.mjs";

void test("unstructured remediator success retries only when findings have paths", () => {
  const reviewed = applyCurrentReview(
    createState(prEvent(), policy(), NOW),
    { outcome: "changes_requested", findings: [finding()] },
    NOW + 1,
  ).state;
  const reserved = reserve(
    reviewed,
    "remediation",
    "agent:author-worker:subagent:mprl-flow-0-remediation",
  );
  const missingReport = recoverState(reserved, { status: "succeeded" }, NOW + 200_000);
  assert.equal(missingReport.reason, "retry_worker_protocol_violation");
  assert.equal(missingReport.state.phase, PHASE.REMEDIATION_QUEUED);
  assert.equal(missingReport.state.retryCount, 0);
  assert.equal(missingReport.state.protocolRetryCount, 1);
  assert.equal(missingReport.state.lastTerminalEnvelope.finalStage, "remediation_evidence");

  const pathless = {
    ...reserved,
    findings: [
      {
        id: "blocking-findings",
        severity: "blocker",
        summary: "Authoritative review requested changes with 2 blocking findings",
      },
    ],
  };
  const unusable = recoverState(pathless, { status: "succeeded" }, NOW + 200_000);
  assert.equal(unusable.state.phase, PHASE.BLOCKED);
  assert.equal(unusable.state.blocker, "findings_unusable");
  assert.equal(recoverState(unusable.state, undefined, NOW + 201_000).reason, "not_recoverable");
});

void test("restart recovery gives new reservations a grace period", () => {
  const state = reserve(createState(prEvent(), policy(), NOW));
  const grace = recoverState(state, undefined, NOW + 60_000);
  assert.equal(grace.effect, "wait");
  assert.equal(grace.reason, "worker_start_grace");
  const retry = recoverState(state, undefined, NOW + 200_000);
  assert.equal(retry.effect, "wait");
  assert.equal(retry.reason, "retry_infrastructure");
  assert.equal(retry.state.phase, PHASE.REVIEW_QUEUED);
  assert.equal(retry.state.retryCount, 0);
  assert.equal(retry.state.infrastructureRetryCount, 1);
  assert.equal(retry.state.infrastructureRetryAt, NOW + 500_000);
});

void test("review wait recovery keeps the pending review lease until completion", () => {
  let state = reserve(createState(prEvent(), policy({ maxRetries: 1 }), NOW));
  const workerClaimRef = state.activeWorker.claimRef;
  state = applyWorkerReport(
    state,
    {
      kind: "review",
      outcome: "waiting_review",
      headSha: SHA_A,
      cycle: 0,
      claimRef: workerClaimRef,
    },
    state.activeWorker.sessionKey,
    NOW + 20,
  ).state;
  const waiting = recoverState(state, undefined, NOW + 200_000);
  assert.equal(waiting.changed, false);
  assert.equal(waiting.effect, "wait");
  assert.equal(waiting.reason, "review_in_progress");
  assert.equal(waiting.state.phase, PHASE.REVIEW_WAITING);
  assert.equal(waiting.state.retryCount, 0);
  assert.equal(holdsReviewLease(waiting.state), true);

  const exhausted = recoverState(state, undefined, state.deadlineAt + 1);
  assert.equal(exhausted.state.phase, PHASE.BLOCKED);
  assert.match(exhausted.state.blocker, /review_wait_deadline_exhausted/);
  assert.equal(exhausted.state.reviewLease, null);
});

void test("head changes keep a waiting review lease until the old head completes", () => {
  let state = reserve(createState(prEvent(), policy(), NOW));
  const waitingWorker = state.activeWorker;
  state = applyWorkerReport(
    state,
    {
      kind: "review",
      outcome: "waiting_review",
      headSha: SHA_A,
      cycle: 0,
      claimRef: waitingWorker.claimRef,
    },
    waitingWorker.sessionKey,
    NOW + 20,
  ).state;
  const synced = applyPullRequestEvent(
    state,
    prEvent({
      eventId: "github:event-2",
      action: "synchronize",
      headSha: SHA_C,
      updatedAt: "2026-09-05T00:00:02Z",
    }),
    policy(),
    NOW + 100,
  );
  assert.equal(synced.state.phase, PHASE.REVIEW_QUEUED);
  assert.equal(synced.state.headSha, SHA_C);
  assert.equal(synced.state.reviewLease.headSha, SHA_A);
  assert.equal(synced.state.reviewLease.supersededByHeadSha, SHA_C);
  assert.equal(synced.state.orphanedWorker.sessionKey, waitingWorker.sessionKey);
  assert.equal(holdsReviewLease(synced.state), true);
  const reserved = reserveWorker(
    synced.state,
    "review",
    "agent:owner-agent:subagent:new-head",
    NOW + 110,
  );
  assert.equal(reserved.changed, false);
  assert.equal(reserved.reason, "prior_review_lease_held");
  const recovered = recoverState(synced.state, undefined, NOW + 200_000);
  assert.equal(recovered.effect, "wait");
  assert.equal(recovered.reason, "prior_review_lease_held");

  const mismatchedStale = applyReviewResult(
    synced.state,
    reviewResult({
      eventId: "broker:old-head-wrong",
      headSha: SHA_A,
      outcome: "approved",
      claimRef: "claim:other",
    }),
    NOW + 290,
  );
  assert.equal(mismatchedStale.changed, false);
  assert.equal(mismatchedStale.reason, "mismatched_review_claim");
  const released = applyReviewResult(
    synced.state,
    reviewResult({
      eventId: "broker:old-head",
      headSha: SHA_A,
      outcome: "approved",
      claimRef: synced.state.reviewLease.claimRef,
    }),
    NOW + 300,
  );
  assert.equal(released.reason, "stale_head_lease_released");
  assert.equal(released.state.reviewLease, null);
  assert.equal(released.state.headSha, SHA_C);
  const next = reserveWorker(
    released.state,
    "review",
    "agent:owner-agent:subagent:new-head",
    NOW + 310,
  );
  assert.equal(next.changed, true);
  assert.equal(next.state.phase, PHASE.REVIEW_RUNNING);
});

void test("process-restart zombie running task retries", () => {
  const state = reserve(createState(prEvent(), policy(), NOW));
  const restarted = recoverState(state, { status: "running" }, NOW + 200_000, 120_000, {
    processStartedAt: NOW + 60_000,
  });
  assert.equal(restarted.effect, "wait");
  assert.equal(restarted.reason, "retry_infrastructure");
  assert.equal(restarted.state.phase, PHASE.REVIEW_QUEUED);
  assert.equal(restarted.state.activeWorker, null);
  assert.equal(restarted.state.retryCount, 0);
  assert.equal(restarted.state.infrastructureRetryCount, 1);
});

void test("missing worker session after grace retries", () => {
  const state = reserve(createState(prEvent(), policy(), NOW));
  const missing = recoverState(state, { status: "running" }, NOW + 200_000, 120_000, {
    sessionAlive: false,
  });
  assert.equal(missing.effect, "wait");
  assert.equal(missing.reason, "retry_infrastructure");
  assert.equal(missing.state.phase, PHASE.REVIEW_QUEUED);
  assert.equal(missing.state.activeWorker, null);
  assert.equal(missing.state.retryCount, 0);
  assert.equal(missing.state.infrastructureRetryCount, 1);
});

void test("live worker session stays worker_active", () => {
  const state = reserve(createState(prEvent(), policy(), NOW));
  const live = recoverState(state, { status: "running" }, NOW + 200_000, 120_000, {
    sessionAlive: true,
    processStartedAt: NOW - 1_000,
  });
  assert.equal(live.effect, "wait");
  assert.equal(live.reason, "worker_active");
  assert.equal(live.state.activeWorker.sessionKey, state.activeWorker.sessionKey);
});

void test("unknown worker-session liveness is retryable infrastructure after grace", () => {
  const state = reserve(createState(prEvent(), policy(), NOW));
  const unknown = recoverState(state, { status: "running" }, NOW + 200_000, 120_000, {
    sessionAlive: undefined,
  });
  assert.equal(unknown.effect, "wait");
  assert.equal(unknown.reason, "retry_infrastructure");
  assert.equal(unknown.state.retryCount, 0);
  assert.equal(unknown.state.infrastructureRetryCount, 1);
  assert.equal(unknown.state.infrastructureLastFailure, "worker_session_liveness_unknown");
});

void test("infrastructure retries use capped backoff without consuming content budget", () => {
  let state = reserve(
    createState(prEvent(), policy({ maxRetries: 1, wallTimeMinutes: 10_080 }), NOW),
  );
  const delays = [];
  for (let attempt = 1; attempt <= 7; attempt += 1) {
    const failedAt = NOW + attempt;
    const failure = applyWorkerFailure(
      state,
      state.activeWorker.sessionKey,
      "worker_session_missing",
      failedAt,
    );
    delays.push(failure.state.infrastructureRetryAt - failedAt);
    assert.equal(failure.effect, "wait");
    assert.equal(failure.state.retryCount, 0);
    assert.equal(failure.state.phase, PHASE.REVIEW_QUEUED);
    state = reserveWorker(
      failure.state,
      "review",
      `agent:owner-agent:subagent:infra-${attempt}`,
      failure.state.infrastructureRetryAt,
    ).state;
  }
  assert.deepEqual(
    delays,
    [300_000, 600_000, 1_200_000, 2_400_000, 4_800_000, 7_200_000, 7_200_000],
  );
});

void test("infrastructure backoffs cannot renew the absolute lifecycle deadline", () => {
  let state = reserve(createState(prEvent(), policy({ maxRetries: 1, wallTimeMinutes: 5 }), NOW));
  const deadlineAt = state.deadlineAt;
  const firstFailure = applyWorkerFailure(
    state,
    state.activeWorker.sessionKey,
    "worker_session_missing",
    NOW,
  );
  assert.equal(firstFailure.state.deadlineAt, deadlineAt);
  state = reserveWorker(
    firstFailure.state,
    "review",
    "agent:owner-agent:subagent:infra-retry",
    firstFailure.state.infrastructureRetryAt,
  ).state;
  assert.equal(state.deadlineAt, deadlineAt);
  const secondFailure = applyWorkerFailure(
    state,
    state.activeWorker.sessionKey,
    "worker_session_missing",
    deadlineAt + 1,
  );
  assert.equal(secondFailure.state.phase, PHASE.BLOCKED);
  assert.equal(secondFailure.state.blocker, "wall_time_budget_exhausted");
  assert.equal(secondFailure.state.deadlineAt, deadlineAt);
});

void test("remediation cycles cannot renew the absolute lifecycle deadline", () => {
  let state = createState(prEvent(), policy(), NOW);
  const deadlineAt = state.deadlineAt;
  state = applyCurrentReview(
    state,
    { outcome: "changes_requested", findings: [finding()] },
    NOW + 1,
  ).state;
  state = reserve(state, "remediation", "agent:author-worker:subagent:fix-deadline");
  const published = applyWorkerReport(
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
  assert.equal(published.state.deadlineAt, deadlineAt);

  state = applyCurrentReview(
    createState(prEvent(), policy(), NOW),
    { outcome: "changes_requested", findings: [finding()] },
    NOW + 1,
  ).state;
  state = reserve(state, "remediation", "agent:author-worker:subagent:verify-deadline");
  const sameHead = applyWorkerReport(
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
  assert.equal(sameHead.state.deadlineAt, deadlineAt);
});

void test("legacy infrastructure exhaustion requeues while content exhaustion stays blocked", () => {
  const base = createState(prEvent(), policy(), NOW);
  const infraBlocked = {
    ...base,
    phase: PHASE.BLOCKED,
    blocker: "worker_failure_exhausted:task_link_failed:ownership mismatch",
    wait: { kind: "manual_intervention", since: NOW },
  };
  const recovered = recoverState(infraBlocked, undefined, NOW + 1);
  assert.equal(recovered.effect, "wait");
  assert.equal(recovered.reason, "legacy_infrastructure_block_requeued");
  assert.equal(recovered.state.phase, PHASE.REVIEW_QUEUED);
  assert.equal(recovered.state.blocker, null);

  const contentBlocked = {
    ...base,
    phase: PHASE.BLOCKED,
    blocker: "worker_failure_exhausted:validation_failed",
  };
  assert.equal(recoverState(contentBlocked, undefined, NOW + 1).reason, "not_recoverable");
  assert.equal(classifyWorkerFailure("validation_failed"), "content");
  assert.equal(
    classifyWorkerFailure("worker_execution_failed:gateway restart interrupted worker"),
    "infrastructure",
  );
  assert.equal(classifyWorkerFailure("worker_execution_failed:validation_failed"), "content");
});

void test("routine policy refresh preserves the absolute deadline", () => {
  const state = createState(prEvent(), policy({ maxCycles: 2, maxRetries: 1 }), NOW);
  const refreshed = refreshPolicySnapshot(
    state,
    policy({ mode: "dogfood", maxCycles: 2, maxRetries: 4, wallTimeMinutes: 180 }),
    NOW + 10,
  );
  assert.equal(refreshed.changed, true);
  assert.equal(refreshed.state.mode, "dogfood");
  assert.equal(refreshed.state.maxCycles, 2);
  assert.equal(refreshed.state.maxRetries, 4);
  assert.equal(refreshed.state.deadlineAt, NOW + 120 * 60_000);

  const unchanged = refreshPolicySnapshot(
    refreshed.state,
    policy({
      mode: "dogfood",
      maxCycles: 2,
      maxRetries: 4,
      wallTimeMinutes: 180,
    }),
    NOW + 20,
  );
  assert.equal(unchanged.changed, false);
  assert.equal(unchanged.state.deadlineAt, refreshed.state.deadlineAt);

  const shortened = refreshPolicySnapshot(
    refreshed.state,
    policy({ mode: "dogfood", maxCycles: 2, maxRetries: 4, wallTimeMinutes: 60 }),
    NOW + 20,
  );
  assert.equal(shortened.state.deadlineAt, NOW + 20 + 60 * 60_000);
});

void test("head confirmation waiting expires without adopting a worker-reported head", () => {
  let state = createState(prEvent(), policy({ wallTimeMinutes: 5 }), NOW);
  state = applyCurrentReview(
    state,
    { outcome: "changes_requested", findings: [finding()] },
    NOW + 1,
  ).state;
  state = reserve(state, "remediation", "agent:author-worker:subagent:confirmation-timeout");
  const published = applyWorkerReport(
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
  const expired = recoverState(published.state, undefined, published.state.deadlineAt + 1);
  assert.equal(expired.state.phase, PHASE.BLOCKED);
  assert.equal(expired.state.blocker, "head_confirmation_deadline_exhausted");
  assert.equal(expired.state.headSha, SHA_A);
});

void test("sanitizes and bounds findings before durable storage", () => {
  assert.deepEqual(sanitizeFindings([finding()])[0], finding());
  assert.throws(() => sanitizeFindings([{ ...finding(), secret: "no" }]), /not allowed/);
  assert.throws(() => sanitizeFindings([finding({ summary: "x\u0000y" })]), /invalid/);
  assert.throws(() => sanitizeFindings([finding({ path: 0 })]), /must be a string/);
  assert.throws(
    () => sanitizeFindings(Array.from({ length: 21 }, (_, i) => finding({ id: `f${i}` }))),
    /at most 20/,
  );
  for (const path of [
    "/etc/passwd",
    "../outside.js",
    "src/../outside.js",
    "./src/file.js",
    "src//file.js",
    "C:\\outside.js",
    "src\\outside.js",
  ]) {
    assert.throws(
      () => sanitizeFindings([finding({ path })]),
      /normalized repository-relative path/,
      path,
    );
  }
  assert.equal(
    sanitizeFindings([finding({ path: ".github/workflows/check.yml" })])[0].path,
    ".github/workflows/check.yml",
  );
});

void test("verifies HMAC signatures over exact raw bytes", () => {
  const body = Buffer.from('{"hello":"world"}');
  const signature = `sha256=${createHmac("sha256", "secret").update(body).digest("hex")}`;
  assert.equal(verifySha256Signature(body, "secret", signature), true);
  assert.equal(verifySha256Signature(body, "other", signature), false);
  assert.equal(verifySha256Signature(body, "secret", "sha256=short"), false);
});

void test("parses bounded GitHub PR and Broker review envelopes", () => {
  const githubReq = {
    headers: {
      "x-github-event": "pull_request",
      "x-github-delivery": "delivery-1",
    },
  };
  const github = parseGitHubPullRequest(githubReq, {
    action: "opened",
    repository: { full_name: "example-org/example-repo" },
    pull_request: {
      number: 42,
      head: { sha: SHA_A, repo: { full_name: "example-org/example-repo" } },
      base: { sha: SHA_B, ref: "dev" },
      updated_at: "2026-09-05T00:00:01Z",
    },
  });
  assert.equal(github.eventId, "github:delivery-1");
  assert.equal(github.headSha, SHA_A);
  assert.equal(github.githubUpdatedAt, Date.parse("2026-09-05T00:00:01Z"));

  const checkSuiteReq = {
    headers: {
      "x-github-event": "check_suite",
      "x-github-delivery": "delivery-suite",
    },
  };
  const checkSuites = parseGitHubPullRequest(checkSuiteReq, {
    action: "completed",
    repository: { full_name: "example-org/example-repo" },
    check_suite: {
      id: 1,
      head_sha: SHA_A,
      updated_at: "2026-09-05T00:00:02Z",
      url: "https://api.github.com/check-suites/1",
      pull_requests: [{ number: 42 }, { number: 44 }, { number: 42 }],
    },
  });
  assert.deepEqual(
    checkSuites.map((event) => [event.prNumber, event.eventId]),
    [
      [42, "github:delivery-suite:pr:42"],
      [44, "github:delivery-suite:pr:44"],
    ],
  );
  assert.equal(checkSuites[0].suiteId, "1");
  assert.equal(checkSuites[0].githubUpdatedAt, Date.parse("2026-09-05T00:00:02Z"));

  const brokerReq = {
    headers: {
      "x-broker-event": "review.completed",
      "x-broker-delivery": "delivery-2",
    },
  };
  const broker = parseBrokerReviewEvent(brokerReq, {
    repository: "example-org/example-repo",
    pullRequest: 42,
    headSha: SHA_A,
    outcome: "changes_requested",
    reviewId: "123",
    claimRef: "mprl-review:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:0:1780000000000",
    coverageComplete: true,
    findings: [finding()],
  });
  assert.equal(broker.eventId, "broker:delivery-2");
  assert.equal(broker.findings.length, 1);
  assert.equal(
    broker.claimRef,
    "mprl-review:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:0:1780000000000",
  );
  assert.throws(
    () =>
      parseBrokerReviewEvent(brokerReq, {
        repository: "example-org/example-repo",
        pullRequest: 42,
        headSha: SHA_A,
        outcome: "changes_requested",
        reviewId: "123",
        coverageComplete: true,
        findings: [finding()],
      }),
    /claimRef is required/,
  );
});

void test("rejects oversized JSON before parsing", async () => {
  const req = Readable.from([Buffer.alloc(20, 65)]);
  await assert.rejects(() => readJsonBody(req, { maxBytes: 10, timeoutMs: 1_000 }), /too_large/);
});

void test("stops buffering oversized request bodies after rejection", async () => {
  const req = new Readable({ read() {} });
  const pending = readJsonBody(req, { maxBytes: 8, timeoutMs: 1_000 });
  req.push(Buffer.alloc(6, 65));
  req.push(Buffer.alloc(6, 66));
  req.push(Buffer.alloc(2048, 67));
  await assert.rejects(pending, /too_large/);
  req.push(Buffer.alloc(4096, 68));
});

void test("bounds rate and in-flight limiter state", () => {
  const rate = createFixedWindowLimiter({ maxRequests: 2, maxKeys: 2, windowMs: 100 });
  assert.equal(rate.allow("a", 0), true);
  assert.equal(rate.allow("a", 1), true);
  assert.equal(rate.allow("a", 2), false);
  assert.equal(rate.allow("b", 2), true);
  assert.equal(rate.allow("c", 2), true);
  assert.equal(rate.size(), 2);

  const inFlight = createInFlightLimiter({ maxPerKey: 1, maxKeys: 1 });
  const release = inFlight.acquire("a");
  assert.equal(typeof release, "function");
  assert.equal(inFlight.acquire("a"), null);
  assert.equal(inFlight.acquire("b"), null);
  release();
  assert.equal(typeof inFlight.acquire("b"), "function");
});

// Regressions restored from the P0/P1 implementation snapshot after three-way recovery.

void test("rejects count-only changes-requested findings without paths", () => {
  const state = createState(prEvent(), policy(), NOW);
  const blocked = applyCurrentReview(
    state,
    {
      outcome: "changes_requested",
      coverageComplete: true,
      findings: [
        {
          id: "blocking-findings",
          severity: "blocker",
          summary: "Authoritative review requested changes with 2 blocking findings",
        },
      ],
    },
    NOW + 1,
  );
  assert.equal(blocked.state.phase, PHASE.BLOCKED);
  assert.equal(blocked.state.blocker, "changes_requested_without_actionable_paths");
});

void test("rejects mixed-severity remediation when any finding lacks a path", () => {
  const state = createState(prEvent(), policy(), NOW);
  const blocked = applyCurrentReview(
    state,
    {
      outcome: "changes_requested",
      coverageComplete: true,
      findings: [
        finding({ severity: "high", path: "src/high.mjs" }),
        finding({ id: "medium-pathless", severity: "medium", path: "" }),
      ],
    },
    NOW + 1,
  );
  assert.equal(blocked.state.phase, PHASE.BLOCKED);
  assert.equal(blocked.state.blocker, "changes_requested_without_actionable_paths");
});

void test("idle queued reservation cannot renew an expired absolute deadline", () => {
  const state = createState(prEvent(), policy({ wallTimeMinutes: 120 }), NOW);
  const afterDeadline = NOW + 120 * 60_000 + 1;
  const reserved = reserveWorker(state, "review", "agent:owner-agent:subagent:idle", afterDeadline);
  assert.equal(reserved.changed, true);
  assert.equal(reserved.state.phase, PHASE.BLOCKED);
  assert.equal(reserved.state.blocker, "wall_time_budget_exhausted");
  assert.equal(reserved.state.deadlineAt, state.deadlineAt);

  const withinBudget = reserveWorker(state, "review", "agent:owner-agent:subagent:fresh", NOW + 10);
  assert.equal(withinBudget.state.deadlineAt, state.deadlineAt);
});

void test("restart recovery waits for active work and retries success without a report", () => {
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
