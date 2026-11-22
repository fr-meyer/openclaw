import assert from "node:assert/strict";
import test from "node:test";
import {
  PHASE,
  applyCheckSuiteEvent,
  applyPullRequestEvent,
  applyReviewResult,
  applyWorkerReport,
  authorizeMergeReady,
  createState,
  holdsWorkerLease,
  isTerminalState,
  mergePolicyDigest,
  normalizeMergeAuthorization,
  normalizePolicy,
  normalizeRemediatorProfile,
  recoverState,
} from "../src/controller.mjs";
import {
  NOW,
  SHA_A,
  SHA_B,
  SHA_C,
  applyCurrentReview,
  attachWorkerIdentity,
  finding,
  githubTimestamp,
  mergeAuthorization,
  policy,
  prEvent,
  remediatorProfile,
  reserve,
  reviewResult,
} from "./controller-helpers-1.mjs";

void test("normalizes policy and enforces actor separation", () => {
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

void test("rejects non-normalized declarative profile paths and incomplete test coverage", () => {
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

void test("creates an exact-head review flow with bounded budgets", () => {
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

void test("rejects non-allowlisted bases and forks by default", () => {
  assert.throws(
    () => createState(prEvent({ baseRef: "main" }), policy(), NOW),
    /base branch is not allowlisted/,
  );
  assert.throws(
    () => createState(prEvent({ headRepo: "someone/fork" }), policy(), NOW),
    /fork pull requests are not allowed/,
  );
});

void test("deduplicates pull-request deliveries", () => {
  const state = createState(prEvent(), policy(), NOW);
  const transition = applyPullRequestEvent(state, prEvent(), policy(), NOW + 1);
  assert.equal(transition.changed, false);
  assert.equal(transition.reason, "duplicate_event");
  assert.equal(transition.state, state);
});

void test("accepts the first signed head update after owner admission", () => {
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

void test("same-head base advancement invalidates queued review work", () => {
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

void test("same-head base advancement invalidates merge-ready evidence", () => {
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

void test("invalidates stale work and restarts at a new exact head", () => {
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

void test("preserves an active remediation worker as an orphan on head change", () => {
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

void test("new exact head adopts the current policy mode", () => {
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

void test("rejects out-of-order GitHub heads after delivery IDs are evicted", () => {
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

void test("ignores stale-head review completion", () => {
  const state = createState(prEvent({ headSha: SHA_C }), policy(), NOW);
  const transition = applyReviewResult(state, reviewResult({ headSha: SHA_A }), NOW + 1);
  assert.equal(transition.changed, false);
  assert.equal(transition.reason, "stale_head_result");
});

void test("ignores same-head review replays after the flow advanced to remediation", () => {
  const state = {
    ...createState(prEvent(), policy(), NOW),
    phase: PHASE.REMEDIATION_QUEUED,
  };
  const transition = applyReviewResult(state, reviewResult(), NOW + 1);
  assert.equal(transition.changed, false);
  assert.equal(transition.reason, "unexpected_review_phase");
});

void test("requires complete zero-finding coverage for merge-ready", () => {
  const state = createState(prEvent(), policy(), NOW);
  const incomplete = applyCurrentReview(state, { coverageComplete: false }, NOW + 1);
  assert.equal(incomplete.state.phase, PHASE.BLOCKED);
  assert.match(incomplete.state.blocker, /approval_without_complete/);

  const contradictory = applyCurrentReview(state, { findings: [finding()] }, NOW + 1);
  assert.equal(contradictory.state.phase, PHASE.BLOCKED);
});

void test("marks only an exact-head complete approval as merge-ready without authorizing merge", () => {
  const state = createState(prEvent(), policy(), NOW);
  const transition = applyCurrentReview(state, {}, NOW + 1);
  assert.equal(transition.effect, "merge_ready");
  assert.equal(transition.state.phase, PHASE.MERGE_READY);
  assert.equal(transition.state.mergeReady.headSha, SHA_A);
  assert.equal(transition.state.mergeReady.reviewId, "9000000001");
  assert.equal(transition.state.mergeReady.mergeAuthorized, false);
});

void test("rejects unsolicited and mismatched review completions", () => {
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

void test("adopts a durable authorization only for the exact merge-ready review", () => {
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

void test("review completion preserves a still-running review worker as an orphan", () => {
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

void test("moves complete changes-requested findings into bounded remediation", () => {
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

void test("rejects changes-requested without complete structured findings", () => {
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
