import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { Readable } from "node:stream";
import test from "node:test";
import {
  PHASE,
  applyCheckSuiteEvent,
  applyPullRequestEvent,
  applyReviewResult,
  applyWorkerFailure,
  authorizeMergeReady,
  applyWorkerReport,
  classifyWorkerFailure,
  createState,
  holdsReviewLease,
  holdsWorkerLease,
  isTerminalState,
  mergePolicyDigest,
  normalizeMergeAuthorization,
  normalizePolicy,
  normalizeRemediatorProfile,
  recoverState,
  refreshPolicySnapshot,
  reserveWorker,
  sanitizeFindings,
} from "../src/controller.mjs";
import {
  createFixedWindowLimiter,
  createInFlightLimiter,
  parseGitHubPullRequest,
  parseBrokerReviewEvent,
  readJsonBody,
  verifySha256Signature,
} from "../src/http.mjs";

const SHA_A = "a".repeat(40);
const SHA_B = "b".repeat(40);
const SHA_C = "c".repeat(40);
const NOW = 1_788_000_000_000;
const githubTimestamp = (second) => new Date(Date.UTC(2026, 8, 5, 0, 0, second)).toISOString();

function remediatorProfile(overrides = {}) {
  return {
    schemaVersion: 1,
    repository: "example-org/example-repo",
    pullRequests: [42],
    headBranchPattern: "^feat/",
    baseBranches: ["dev"],
    seedWorkspace: "/workspace/repo",
    worktreeRoot: "/workspace",
    allowedWritePaths: ["src/"],
    requiredTestPaths: ["src/"],
    validationCommands: [{ argv: ["node", "--version"], covers: ["src/"], timeoutSeconds: 30 }],
    publicationMode: "attested-broker",
    publicationRoute: "exact-lease",
    commitSubject: "fix: apply reviewed PR remediation",
    attestationPolicy: "required",
    ...overrides,
  };
}

function mergeAuthorization(overrides = {}) {
  return {
    schemaVersion: 1,
    authorizationId: "auth-example-repo-42",
    authorizer: "owner-agent",
    authorizedAt: NOW - 1_000,
    expiresAt: NOW + 60_000,
    repository: "example-org/example-repo",
    prNumber: 42,
    baseRef: "dev",
    mergeMethod: "merge",
    sourceRef: "approval:2026-09-15T01:11:00+09:00",
    policyVersion: "pr-lifecycle-taskflow/v1",
    policyDigest: "e".repeat(64),
    revokedAt: null,
    supersededBy: null,
    ...overrides,
  };
}

function policy(overrides = {}) {
  return {
    enabled: true,
    mode: "active",
    workspace: "/workspace/repo",
    brokerRepoAlias: "example-repo",
    baseBranches: ["dev"],
    reviewActor: "broker",
    authorActor: "author-worker",
    mergeActor: "broker[bot]",
    reviewWorkerAgentId: "broker-review-launcher",
    authorWorkerAgentId: "author-worker",
    publisherBrokerId: "attested-broker/v1",
    publisherAttestationRef: "proof:author-worker-test-boundary",
    remediatorProfile: remediatorProfile(),
    maxCycles: 2,
    maxRetries: 2,
    wallTimeMinutes: 120,
    ...overrides,
  };
}

function prEvent(overrides = {}) {
  return {
    eventId: "github:event-1",
    action: "opened",
    repo: "example-org/example-repo",
    prNumber: 42,
    headSha: SHA_A,
    baseSha: SHA_B,
    baseRef: "dev",
    headRepo: "example-org/example-repo",
    headRef: "feat/example",
    updatedAt: githubTimestamp(1),
    ...overrides,
  };
}

function reviewResult(overrides = {}) {
  return {
    eventId: "broker:review-1",
    repo: "example-org/example-repo",
    prNumber: 42,
    headSha: SHA_A,
    outcome: "approved",
    reviewId: "9000000001",
    coverageComplete: true,
    retryAllowed: false,
    findings: [],
    ...overrides,
  };
}

function finding(overrides = {}) {
  return {
    id: "finding-1",
    severity: "high",
    summary: "Projected cycles can exceed the wall-time budget.",
    path: "src/example-repo/ritournelle/supervisor.py",
    line: 42,
    evidence: "Bounded test fixture reproduces the issue.",
    ...overrides,
  };
}

function fixerProof(overrides = {}) {
  return {
    fixerModel: "primary-fixer",
    fixerAttested: true,
    fixerAttestationRef: "sha256:" + "d".repeat(64),
    ...overrides,
  };
}

function remediationBinding(state) {
  return { profileDigest: state.activeWorker?.profileDigest };
}

function reserve(
  state,
  kind = "review",
  sessionKey = "agent:owner-agent:subagent:mprl-flow-0-review",
  now = NOW + 10,
) {
  const reserved = reserveWorker(state, kind, sessionKey, now);
  assert.equal(reserved.changed, true);
  return reserved.state;
}

function withCurrentReviewLease(state, now = NOW + 10) {
  if (state.activeWorker?.kind === "review") {
    return state;
  }
  if (state.reviewLease?.kind === "review" && state.reviewLease.headSha === state.headSha) {
    return state;
  }
  return reserve(state, "review", "agent:owner-agent:subagent:mprl-flow-0-review", now);
}

function applyCurrentReview(state, overrides = {}, now = NOW + 20) {
  const leased = withCurrentReviewLease(state);
  const lease = leased.activeWorker?.kind === "review" ? leased.activeWorker : leased.reviewLease;
  return applyReviewResult(
    leased,
    reviewResult({
      claimRef: lease?.claimRef,
      reviewId: lease?.reviewId ?? "9000000001",
      ...overrides,
    }),
    now,
  );
}

function attachWorkerIdentity(state, suffix, flowId = "flow-controller-test") {
  return {
    ...state,
    activeWorker: {
      ...state.activeWorker,
      flowId,
      runId: `run-${suffix}`,
      taskId: `task-${suffix}`,
    },
  };
}

test("normalizes policy and enforces actor separation", () => {
  const normalized = normalizePolicy(policy());
  assert.equal(normalized.reviewActor, "broker");
  assert.equal(normalized.authorActor, "author-worker");
  assert.equal(normalized.brokerRepoAlias, "example-repo");
  assert.equal(normalized.fixerModel, "primary-fixer");
  assert.equal(normalized.fixerFallbackModel, "fallback-fixer");
  assert.equal(normalized.publisherBrokerId, "attested-broker/v1");
  assert.throws(
    () => normalizePolicy(policy({ publisherAttestationRef: undefined })),
    /must be configured together/,
  );
  assert.throws(
    () => normalizePolicy(policy({ authorActor: "Broker" })),
    /reviewActor and authorActor must be distinct/,
  );
  assert.equal(
    normalizePolicy(policy({ reviewActor: "other-reviewer" })).reviewActor,
    "other-reviewer",
  );
  assert.throws(
    () => normalizePolicy(policy({ authorWorkerAgentId: "Broker-Review-Launcher" })),
    /WorkerAgentId.*must be distinct/,
  );
  assert.throws(
    () => normalizePolicy(policy({ authorWorkerAgentId: "owner-agent" })),
    /authorActor must match authorWorkerAgentId/,
  );
  assert.equal(
    normalizePolicy(policy({ fixerModel: "custom-primary" })).fixerModel,
    "custom-primary",
  );
  assert.throws(
    () => normalizePolicy(policy({ fixerFallbackModel: "primary-fixer" })),
    /fixerModel and fixerFallbackModel must be distinct/,
  );
  assert.throws(() => normalizePolicy(policy({ maxCycles: 0 })), /maxCycles/);
  assert.throws(() => normalizePolicy(policy({ maxCycles: 3 })), /maxCycles/);
  assert.throws(() => normalizePolicy(policy({ maxRetries: 11 })), /maxRetries/);
  assert.throws(() => normalizePolicy(policy({ wallTimeMinutes: 4 })), /wallTimeMinutes/);
  assert.throws(
    () => normalizePolicy(policy({ workspace: "relative/repo" })),
    /normalized absolute path/,
  );
  assert.throws(
    () => normalizePolicy(policy({ brokerRepoAlias: undefined })),
    /brokerRepoAlias must be a string/,
  );
  assert.throws(
    () => normalizePolicy(policy({ brokerRepoAlias: "example-org/example-repo" })),
    /brokerRepoAlias is invalid/,
  );
  assert.notEqual(
    mergePolicyDigest(normalized, "example-org/example-repo"),
    mergePolicyDigest(
      normalizePolicy(policy({ brokerRepoAlias: "example-repo-secondary" })),
      "example-org/example-repo",
    ),
  );
  assert.throws(
    () =>
      normalizePolicy(
        policy({ remediatorProfile: remediatorProfile({ publicationRoute: "raw-push" }) }),
      ),
    /publication or attestation policy is invalid/,
  );
});

test("rejects non-normalized declarative profile paths and incomplete test coverage", () => {
  for (const invalidPath of ["../src", "./src", "src\\test.mjs", "src//test.mjs", "."]) {
    assert.throws(
      () => normalizeRemediatorProfile(remediatorProfile({ allowedWritePaths: [invalidPath] })),
      /repository-relative path/,
    );
  }
  for (const invalidRoot of ["/", "/workspace/../escape", "/workspace//double", "/workspace/"]) {
    assert.throws(
      () => normalizeRemediatorProfile(remediatorProfile({ worktreeRoot: invalidRoot })),
      /normalized absolute path/,
    );
  }
  assert.throws(
    () =>
      normalizeRemediatorProfile(
        remediatorProfile({
          requiredTestPaths: ["test/runtime.test.mjs"],
          validationCommands: [{ argv: ["node", "--test"], covers: ["test/controller.test.mjs"] }],
        }),
      ),
    /required test-path coverage is incomplete/,
  );
});

test("creates an exact-head review flow with bounded budgets", () => {
  const state = createState(prEvent(), policy(), NOW);
  assert.equal(state.phase, PHASE.REVIEW_QUEUED);
  assert.equal(state.headSha, SHA_A);
  assert.equal(state.cycle, 0);
  assert.equal(state.maxCycles, 2);
  assert.equal(state.fixerModel, "primary-fixer");
  assert.equal(state.deadlineAt, NOW + 120 * 60_000);
  assert.deepEqual(state.seenEventIds, ["github:event-1"]);
  assert.equal(state.mergeReady, null);
});

test("rejects non-allowlisted bases and forks by default", () => {
  assert.throws(
    () => createState(prEvent({ baseRef: "main" }), policy(), NOW),
    /base branch is not allowlisted/,
  );
  assert.throws(
    () => createState(prEvent({ headRepo: "someone/fork" }), policy(), NOW),
    /fork pull requests are not allowed/,
  );
});

test("deduplicates pull-request deliveries", () => {
  const state = createState(prEvent(), policy(), NOW);
  const transition = applyPullRequestEvent(state, prEvent(), policy(), NOW + 1);
  assert.equal(transition.changed, false);
  assert.equal(transition.reason, "duplicate_event");
  assert.equal(transition.state, state);
});

test("accepts the first signed head update after owner admission", () => {
  const admitted = createState(
    prEvent({ eventId: "owner-admit:initial-head", action: "synchronize", updatedAt: undefined }),
    policy(),
    NOW,
  );
  assert.equal(admitted.githubUpdatedAt, null);

  const transition = applyPullRequestEvent(
    admitted,
    prEvent({
      eventId: "github:first-synchronize",
      action: "synchronize",
      headSha: SHA_C,
      updatedAt: githubTimestamp(2),
    }),
    policy(),
    NOW + 1,
  );

  assert.equal(transition.changed, true);
  assert.equal(transition.reason, "new_head");
  assert.equal(transition.state.headSha, SHA_C);
  assert.equal(transition.state.githubUpdatedAt, Date.parse(githubTimestamp(2)));
});

test("same-head base advancement invalidates queued review work", () => {
  const state = reserve(createState(prEvent(), policy(), NOW));
  const transition = applyPullRequestEvent(
    state,
    prEvent({
      eventId: "github:base-advanced-before-review",
      action: "synchronize",
      baseSha: SHA_C,
      updatedAt: githubTimestamp(2),
    }),
    policy(),
    NOW + 100,
  );
  assert.equal(transition.changed, true);
  assert.equal(transition.reason, "base_changed");
  assert.equal(transition.state.phase, PHASE.REVIEW_QUEUED);
  assert.equal(transition.state.headSha, SHA_A);
  assert.equal(transition.state.baseSha, SHA_C);
  assert.equal(transition.state.review, null);
  assert.equal(transition.state.mergeReady, null);
  assert.equal(transition.state.activeWorker, null);
  assert.equal(transition.state.orphanedWorker.reason, "pull_request_base_changed");
});

test("same-head base advancement invalidates merge-ready evidence", () => {
  const ready = applyCurrentReview(createState(prEvent(), policy(), NOW), {}, NOW + 1).state;
  assert.equal(ready.phase, PHASE.MERGE_READY);
  const transition = applyPullRequestEvent(
    ready,
    prEvent({
      eventId: "github:base-advanced-after-review",
      action: "synchronize",
      baseSha: SHA_C,
      updatedAt: githubTimestamp(2),
    }),
    policy(),
    NOW + 100,
  );
  assert.equal(transition.changed, true);
  assert.equal(transition.reason, "base_changed");
  assert.equal(transition.state.phase, PHASE.REVIEW_QUEUED);
  assert.equal(transition.state.baseSha, SHA_C);
  assert.equal(transition.state.review, null);
  assert.equal(transition.state.mergeReady, null);
});

test("invalidates stale work and restarts at a new exact head", () => {
  let state = createState(prEvent(), policy(), NOW);
  state = reserve(state);
  const oldWorker = state.activeWorker;
  const deadlineAt = state.deadlineAt;
  const transition = applyPullRequestEvent(
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
  assert.equal(transition.changed, true);
  assert.equal(transition.effect, "continue");
  assert.equal(transition.state.headSha, SHA_C);
  assert.equal(transition.state.phase, PHASE.REVIEW_QUEUED);
  assert.equal(transition.state.activeWorker, null);
  assert.deepEqual(transition.state.orphanedWorker, {
    ...oldWorker,
    reason: "pull_request_head_changed",
    clearedAt: NOW + 100,
  });
  assert.equal(transition.state.deadlineAt, deadlineAt);
  assert.equal(transition.state.review, null);
});

test("preserves an active remediation worker as an orphan on head change", () => {
  let state = createState(prEvent(), policy(), NOW);
  state = applyCurrentReview(
    state,
    { outcome: "changes_requested", findings: [finding()] },
    NOW + 1,
  ).state;
  state = reserve(state, "remediation", "agent:author-worker:subagent:fix-old-head");
  const oldWorker = state.activeWorker;
  const transition = applyPullRequestEvent(
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
  assert.equal(transition.state.phase, PHASE.REVIEW_QUEUED);
  assert.equal(transition.state.activeWorker, null);
  assert.deepEqual(transition.state.orphanedWorker, {
    ...oldWorker,
    reason: "pull_request_head_changed",
    clearedAt: NOW + 100,
  });
});

test("new exact head adopts the current policy mode", () => {
  const state = createState(prEvent(), policy({ mode: "dogfood" }), NOW);
  const transition = applyPullRequestEvent(
    state,
    prEvent({
      eventId: "github:event-2",
      action: "synchronize",
      headSha: SHA_C,
      updatedAt: "2026-09-05T00:00:02Z",
    }),
    policy({ mode: "active" }),
    NOW + 100,
  );
  assert.equal(transition.state.mode, "active");
  assert.equal(transition.state.phase, PHASE.REVIEW_QUEUED);
  assert.equal(transition.effect, "continue");
});

test("rejects out-of-order GitHub heads after delivery IDs are evicted", () => {
  let state = createState(prEvent({ updatedAt: githubTimestamp(1) }), policy(), NOW);
  state = applyPullRequestEvent(
    state,
    prEvent({
      eventId: "github:newer-head",
      action: "synchronize",
      headSha: SHA_C,
      updatedAt: githubTimestamp(3),
    }),
    policy(),
    NOW + 1,
  ).state;
  for (let second = 4; second <= 70; second += 1) {
    state = applyPullRequestEvent(
      state,
      prEvent({
        eventId: `github:filler-${second}`,
        action: "synchronize",
        headSha: SHA_C,
        updatedAt: githubTimestamp(second),
      }),
      policy(),
      NOW + second,
    ).state;
  }
  const stale = applyPullRequestEvent(
    state,
    prEvent({
      eventId: "github:old-delivery-after-eviction",
      action: "synchronize",
      headSha: SHA_A,
      updatedAt: githubTimestamp(2),
    }),
    policy(),
    NOW + 100,
  );
  assert.equal(stale.changed, false);
  assert.equal(stale.reason, "stale_github_event");
  assert.equal(stale.state.headSha, SHA_C);

  const ambiguous = applyPullRequestEvent(
    state,
    prEvent({
      eventId: "github:equal-timestamp-different-head",
      action: "synchronize",
      headSha: SHA_B,
      updatedAt: new Date(state.githubUpdatedAt).toISOString(),
    }),
    policy(),
    NOW + 101,
  );
  assert.equal(ambiguous.changed, true);
  assert.equal(ambiguous.effect, "reconcile");
  assert.equal(ambiguous.reason, "github_event_order_ambiguous");
  assert.equal(ambiguous.state.headSha, SHA_C);
  assert.equal(ambiguous.state.pendingGithubReconciliation.headSha, SHA_B);
  assert.ok(ambiguous.state.seenEventIds.includes("github:equal-timestamp-different-head"));
});

test("ignores stale-head review completion", () => {
  const state = createState(prEvent({ headSha: SHA_C }), policy(), NOW);
  const transition = applyReviewResult(state, reviewResult({ headSha: SHA_A }), NOW + 1);
  assert.equal(transition.changed, false);
  assert.equal(transition.reason, "stale_head_result");
});

test("ignores same-head review replays after the flow advanced to remediation", () => {
  const state = {
    ...createState(prEvent(), policy(), NOW),
    phase: PHASE.REMEDIATION_QUEUED,
  };
  const transition = applyReviewResult(state, reviewResult(), NOW + 1);
  assert.equal(transition.changed, false);
  assert.equal(transition.reason, "unexpected_review_phase");
});

test("requires complete zero-finding coverage for merge-ready", () => {
  const state = createState(prEvent(), policy(), NOW);
  const incomplete = applyCurrentReview(state, { coverageComplete: false }, NOW + 1);
  assert.equal(incomplete.state.phase, PHASE.BLOCKED);
  assert.match(incomplete.state.blocker, /approval_without_complete/);

  const contradictory = applyCurrentReview(state, { findings: [finding()] }, NOW + 1);
  assert.equal(contradictory.state.phase, PHASE.BLOCKED);
});

test("marks only an exact-head complete approval as merge-ready without authorizing merge", () => {
  const state = createState(prEvent(), policy(), NOW);
  const transition = applyCurrentReview(state, {}, NOW + 1);
  assert.equal(transition.effect, "merge_ready");
  assert.equal(transition.state.phase, PHASE.MERGE_READY);
  assert.equal(transition.state.mergeReady.headSha, SHA_A);
  assert.equal(transition.state.mergeReady.reviewId, "9000000001");
  assert.equal(transition.state.mergeReady.mergeAuthorized, false);
});

test("rejects unsolicited and mismatched review completions", () => {
  const queued = createState(prEvent(), policy(), NOW);
  const unsolicited = applyReviewResult(queued, reviewResult(), NOW + 1);
  assert.equal(unsolicited.changed, false);
  assert.equal(unsolicited.reason, "unsolicited_review_result");
  assert.equal(queued.phase, PHASE.REVIEW_QUEUED);

  const running = reserve(queued);
  const workerClaimRef = running.activeWorker.claimRef;
  const mismatchedClaim = applyReviewResult(
    running,
    reviewResult({ claimRef: "claim:other" }),
    NOW + 20,
  );
  assert.equal(mismatchedClaim.changed, false);
  assert.equal(mismatchedClaim.reason, "mismatched_review_claim");

  const waiting = applyWorkerReport(
    running,
    {
      kind: "review",
      outcome: "waiting_review",
      headSha: SHA_A,
      cycle: 0,
      claimRef: workerClaimRef,
      reviewId: "review-bound",
    },
    running.activeWorker.sessionKey,
    NOW + 21,
  ).state;
  const mismatchedId = applyReviewResult(
    waiting,
    reviewResult({
      claimRef: workerClaimRef,
      reviewId: "review-other",
    }),
    NOW + 22,
  );
  assert.equal(mismatchedId.changed, false);
  assert.equal(mismatchedId.reason, "mismatched_review_id");

  const missingId = applyReviewResult(
    waiting,
    reviewResult({
      claimRef: workerClaimRef,
      reviewId: "",
    }),
    NOW + 23,
  );
  assert.equal(missingId.changed, false);
  assert.equal(missingId.reason, "mismatched_review_id");
  const missingBoundId = applyReviewResult(
    waiting,
    reviewResult({
      claimRef: workerClaimRef,
      reviewId: "",
      outcome: "changes_requested",
      findings: [finding()],
    }),
    NOW + 23,
  );
  assert.equal(missingBoundId.changed, false);
  assert.equal(missingBoundId.reason, "mismatched_review_id");

  const approved = applyReviewResult(
    waiting,
    reviewResult({
      claimRef: workerClaimRef,
      reviewId: "review-bound",
    }),
    NOW + 24,
  );
  assert.equal(approved.effect, "merge_ready");
  assert.equal(approved.state.mergeReady.reviewId, "review-bound");
  assert.equal(approved.state.mergeReady.mergeAuthorized, false);
});

void test("requires owner authorization after every exact approved review", () => {
  assert.throws(
    () =>
      createState(
        prEvent(),
        policy({ autoMergeBaseBranches: ["dev"], mergeAuthorization: mergeAuthorization() }),
        NOW,
      ),
    /policyDigest does not match repository policy/,
  );
  const rawPolicy = policy({ autoMergeBaseBranches: ["dev"] });
  rawPolicy.mergeAuthorization = mergeAuthorization({
    policyDigest: mergePolicyDigest(normalizePolicy(rawPolicy), "example-org/example-repo"),
  });
  const state = createState(prEvent(), rawPolicy, NOW);
  const transition = applyCurrentReview(state, {}, NOW + 1);
  assert.equal(transition.effect, "merge_ready");
  assert.equal(transition.reason, "approved");
  assert.equal(transition.state.phase, PHASE.MERGE_READY);
  assert.equal(transition.state.mergeReady.headSha, SHA_A);
  assert.equal(transition.state.mergeReady.mergeAuthorized, false);
  assert.equal(transition.state.mergeReady.authorizationDigest, null);
  assert.equal(transition.state.mergeReady.mergeMethod, "merge");
  const authorized = authorizeMergeReady(transition.state, rawPolicy, NOW + 2);
  assert.equal(authorized.effect, "continue");
  assert.equal(authorized.state.phase, PHASE.MERGE_QUEUED);
  assert.equal(authorized.state.mergeReady.mergeAuthorized, true);
  const rerun = applyCheckSuiteEvent(
    authorized.state,
    {
      eventId: "github:checks-rerequested",
      action: "rerequested",
      repo: "example-org/example-repo",
      prNumber: 42,
      headSha: SHA_A,
      suiteId: "200",
      updatedAt: "2026-09-05T00:00:02Z",
    },
    NOW + 3,
  );
  assert.equal(rerun.effect, "none");
  assert.equal(rerun.reason, "check_suite_pending");
  assert.equal(rerun.state.wait.kind, "check_suite");
  assert.equal(rerun.state.wait.suiteId, "200");
  assert.equal(rerun.state.wait.githubUpdatedAt, Date.parse("2026-09-05T00:00:02Z"));
  assert.equal(recoverState(rerun.state, undefined, NOW + 4).reason, "check_suite_event_wait");
  const staleCompletion = applyCheckSuiteEvent(
    rerun.state,
    {
      eventId: "github:older-check-completed",
      action: "completed",
      repo: "example-org/example-repo",
      prNumber: 42,
      headSha: SHA_A,
      suiteId: "199",
      updatedAt: "2026-09-05T00:00:01Z",
    },
    NOW + 4,
  );
  assert.equal(staleCompletion.effect, "none");
  assert.equal(staleCompletion.reason, "stale_check_suite_event");
  assert.equal(staleCompletion.state.wait.suiteId, "200");
  const currentCompletion = applyCheckSuiteEvent(
    staleCompletion.state,
    {
      eventId: "github:equal-timestamp-check-completed",
      action: "completed",
      repo: "example-org/example-repo",
      prNumber: 42,
      headSha: SHA_A,
      suiteId: "200",
      updatedAt: "2026-09-05T00:00:02Z",
    },
    NOW + 5,
  );
  assert.equal(currentCompletion.effect, "continue");
  assert.equal(currentCompletion.reason, "check_suite_reconcile");
  assert.equal(currentCompletion.state.wait, null);
  const legacyWaitState = {
    ...authorized.state,
    wait: { kind: "check_suite", since: NOW, headSha: SHA_A, action: "rerequested" },
  };
  const legacyCompletion = applyCheckSuiteEvent(
    legacyWaitState,
    {
      eventId: "github:legacy-check-completed",
      action: "completed",
      repo: "example-org/example-repo",
      prNumber: 42,
      headSha: SHA_A,
      suiteId: "201",
      updatedAt: "2026-09-05T00:00:04Z",
    },
    NOW + 6,
  );
  assert.equal(legacyCompletion.reason, "stale_check_suite_event");
  assert.equal(legacyCompletion.state.wait.suiteId, undefined);
  const legacyUpgrade = applyCheckSuiteEvent(
    legacyCompletion.state,
    {
      eventId: "github:legacy-check-rerequested",
      action: "rerequested",
      repo: "example-org/example-repo",
      prNumber: 42,
      headSha: SHA_A,
      suiteId: "202",
      updatedAt: "2026-09-05T00:00:05Z",
    },
    NOW + 7,
  );
  assert.equal(legacyUpgrade.reason, "check_suite_pending");
  assert.equal(legacyUpgrade.state.wait.suiteId, "202");
  const recovery = recoverState(authorized.state, undefined, NOW + 3);
  assert.equal(recovery.effect, "continue");
  assert.equal(recovery.reason, "queued_merge");

  assert.throws(
    () => normalizePolicy(policy({ autoMergeMethod: "squash" })),
    /autoMergeMethod must be merge/,
  );
  assert.throws(
    () => normalizeMergeAuthorization(mergeAuthorization({ mergeMethod: "rebase" })),
    /mergeAuthorization.mergeMethod must be merge/,
  );
});

test("adopts a durable authorization only for the exact merge-ready review", () => {
  const reviewPolicy = policy({ autoMergeBaseBranches: ["dev"] });
  const ready = applyCurrentReview(createState(prEvent(), reviewPolicy, NOW), {}, NOW + 1);
  assert.equal(ready.state.phase, PHASE.MERGE_READY);
  assert.equal(isTerminalState(ready.state), false);
  assert.equal(ready.state.mergeAuthorization, null);

  const authorizedPolicy = policy({ autoMergeBaseBranches: ["dev"] });
  authorizedPolicy.mergeAuthorization = mergeAuthorization({
    policyDigest: mergePolicyDigest(normalizePolicy(authorizedPolicy), "example-org/example-repo"),
  });
  const queued = authorizeMergeReady(ready.state, authorizedPolicy, NOW + 2);
  assert.equal(queued.changed, true);
  assert.equal(queued.effect, "continue");
  assert.equal(queued.reason, "owner_authorized_merge_queued");
  assert.equal(queued.state.phase, PHASE.MERGE_QUEUED);
  assert.equal(queued.state.headSha, ready.state.headSha);
  assert.equal(queued.state.review.reviewId, ready.state.review.reviewId);
  assert.equal(queued.state.mergeReady.mergeAuthorized, true);
  assert.equal(queued.state.mergeReady.authorizationDigest, queued.state.mergeAuthorization.digest);
  assert.equal(queued.state.mergeReady.authorizationAdoptedAt, NOW + 2);

  const expiredPolicy = policy({ autoMergeBaseBranches: ["dev"] });
  expiredPolicy.mergeAuthorization = mergeAuthorization({
    expiresAt: NOW + 1,
    policyDigest: mergePolicyDigest(normalizePolicy(expiredPolicy), "example-org/example-repo"),
  });
  const expired = authorizeMergeReady(ready.state, expiredPolicy, NOW + 2);
  assert.equal(expired.changed, false);
  assert.equal(expired.reason, "merge_authorization_not_ready");
  assert.strictEqual(expired.state, ready.state);
});

test("review completion preserves a still-running review worker as an orphan", () => {
  const state = attachWorkerIdentity(reserve(createState(prEvent(), policy(), NOW)), "review");
  const transition = applyReviewResult(
    state,
    reviewResult({ claimRef: state.activeWorker.claimRef }),
    NOW + 24,
  );
  assert.equal(transition.effect, "merge_ready");
  assert.equal(transition.state.activeWorker, null);
  assert.deepEqual(transition.state.orphanedWorker, {
    ...state.activeWorker,
    reason: "review_completion_received",
    clearedAt: NOW + 24,
  });
  assert.equal(holdsWorkerLease(transition.state), true);
});

test("moves complete changes-requested findings into bounded remediation", () => {
  const state = createState(prEvent(), policy(), NOW);
  const transition = applyCurrentReview(
    state,
    {
      outcome: "changes_requested",
      coverageComplete: true,
      findings: [finding()],
    },
    NOW + 1,
  );
  assert.equal(transition.effect, "continue");
  assert.equal(transition.state.phase, PHASE.REMEDIATION_QUEUED);
  assert.equal(transition.state.findings.length, 1);
});

test("rejects changes-requested without complete structured findings", () => {
  const state = createState(prEvent(), policy(), NOW);
  const noFindings = applyCurrentReview(
    state,
    { outcome: "changes_requested", findings: [] },
    NOW + 1,
  );
  assert.equal(noFindings.state.phase, PHASE.BLOCKED);
  const incomplete = applyCurrentReview(
    state,
    {
      outcome: "changes_requested",
      coverageComplete: false,
      findings: [finding()],
    },
    NOW + 1,
  );
  assert.equal(incomplete.state.phase, PHASE.BLOCKED);
});

test("retries only publication-confirmed retryable reviews within budget", () => {
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

test("reserves exactly one worker for the phase", () => {
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

test("fences worker reports by session, kind, head, and cycle", () => {
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

test("rejects an orphaned worker report before terminal-envelope or orphan mutation", () => {
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

test("review worker can enter an external wait without polling", () => {
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

test("worker reports retain the exact worker identity as an orphan", () => {
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

test("remediation accepts only tested, publication-confirmed new heads", () => {
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

test("fallback fixer requires exact single-use controller-owned primary failure evidence", () => {
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

test("primary fixer attestation rejects fallback-only evidence fields", () => {
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

test("two fix cycles end at a final review and never launch a third fixer", () => {
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

test("ambiguous publication is a durable manual block", () => {
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

test("bounded same-head re-review requires independent verification", () => {
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

test("worker failure retries within budget and ignores stale failure reports", () => {
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

test("restart recovery waits for active work and blocks success without a report", () => {
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

test("review wait recovery keeps the pending review lease until completion", () => {
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

test("head changes keep a waiting review lease until the old head completes", () => {
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

test("process-restart zombie running task retries", () => {
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

test("missing worker session after grace retries", () => {
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

test("live worker session stays worker_active", () => {
  const state = reserve(createState(prEvent(), policy(), NOW));
  const live = recoverState(state, { status: "running" }, NOW + 200_000, 120_000, {
    sessionAlive: true,
    processStartedAt: NOW - 1_000,
  });
  assert.equal(live.effect, "wait");
  assert.equal(live.reason, "worker_active");
  assert.equal(live.state.activeWorker.sessionKey, state.activeWorker.sessionKey);
});

test("unknown worker-session liveness is retryable infrastructure after grace", () => {
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

test("infrastructure retries use capped backoff without consuming content budget", () => {
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

test("infrastructure backoffs cannot renew the absolute lifecycle deadline", () => {
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

test("remediation cycles cannot renew the absolute lifecycle deadline", () => {
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

test("legacy infrastructure exhaustion requeues while content exhaustion stays blocked", () => {
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

test("routine policy refresh preserves the absolute deadline", () => {
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

test("head confirmation waiting expires without adopting a worker-reported head", () => {
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

test("sanitizes and bounds findings before durable storage", () => {
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

test("verifies HMAC signatures over exact raw bytes", () => {
  const body = Buffer.from('{"hello":"world"}');
  const signature = `sha256=${createHmac("sha256", "secret").update(body).digest("hex")}`;
  assert.equal(verifySha256Signature(body, "secret", signature), true);
  assert.equal(verifySha256Signature(body, "other", signature), false);
  assert.equal(verifySha256Signature(body, "secret", "sha256=short"), false);
});

test("parses bounded GitHub PR and Broker review envelopes", () => {
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

test("rejects oversized JSON before parsing", async () => {
  const req = Readable.from([Buffer.alloc(20, 65)]);
  await assert.rejects(() => readJsonBody(req, { maxBytes: 10, timeoutMs: 1_000 }), /too_large/);
});

test("stops buffering oversized request bodies after rejection", async () => {
  const req = new Readable({ read() {} });
  const pending = readJsonBody(req, { maxBytes: 8, timeoutMs: 1_000 });
  req.push(Buffer.alloc(6, 65));
  req.push(Buffer.alloc(6, 66));
  req.push(Buffer.alloc(2048, 67));
  await assert.rejects(pending, /too_large/);
  req.push(Buffer.alloc(4096, 68));
});

test("bounds rate and in-flight limiter state", () => {
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

void test("infrastructure retries exhaust into a non-auto-requeued block", () => {
  let state = reserve(
    createState(prEvent(), policy({ maxRetries: 1, wallTimeMinutes: 10_080 }), NOW),
  );
  let now = NOW + 10;
  for (let attempt = 1; attempt <= 8; attempt += 1) {
    const failure = applyWorkerFailure(
      state,
      state.activeWorker.sessionKey,
      "worker_session_missing",
      now + 1,
    );
    assert.equal(failure.state.phase, PHASE.REVIEW_QUEUED);
    now = failure.state.infrastructureRetryAt;
    state = reserveWorker(
      failure.state,
      "review",
      `agent:owner-agent:subagent:cap-${attempt}`,
      now,
    ).state;
    assert.equal(state.phase, PHASE.REVIEW_RUNNING);
  }
  const exhausted = applyWorkerFailure(
    state,
    state.activeWorker.sessionKey,
    "worker_session_missing",
    now + 1,
  );
  assert.equal(exhausted.state.phase, PHASE.BLOCKED);
  assert.match(exhausted.state.blocker, /^infrastructure_retry_exhausted:/);
  assert.equal(recoverState(exhausted.state, undefined, NOW + 21).reason, "not_recoverable");
});

void test("owner recovery refreshes a stale policy snapshot without resetting an unchanged deadline", () => {
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
  assert.equal(refreshed.state.deadlineAt, state.deadlineAt);

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
});
