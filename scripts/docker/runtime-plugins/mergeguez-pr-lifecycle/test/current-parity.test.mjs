import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHmac } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import test from "node:test";
import {
  PHASE,
  STATE_SCHEMA_VERSION,
  MAX_INFRASTRUCTURE_RETRIES,
  PRIMARY_FIXER_MODEL,
  FALLBACK_FIXER_MODEL,
  REVIEW_ACTOR,
  AUTHOR_ACTOR,
  applyPullRequestEvent,
  applyReviewResult,
  applyWorkerFailure,
  recoverState,
  findingsAreActionable,
  isSha,
  isRepo,
  sanitizeFindings,
} from "../src/controller.mjs";
import {
  BODY_TIMEOUT_MS,
  MAX_BODY_BYTES,
  parseGitHubPullRequest,
  parseMergeguezReviewEvent,
  readJsonBody,
} from "../src/http.mjs";
import * as runtime from "../src/runtime.mjs";
import {
  OWNER,
  REPO,
  SHA_A,
  SHA_B,
  fixture,
  pluginConfig,
  prEvent,
  assertAllClosed,
} from "./inert-parity-host.mjs";

const { __testing, proposeInstalledPublisherRuntimePinMigration, registerMergeguezPrLifecycle } =
  runtime;

const get = (f, id) => f.kernel.get(OWNER, id);
const details = (value) => value.details;
const continueFlow = (f, id, extra = {}) =>
  f.tool().execute("call", { action: "continue", flowId: id, ...extra });

void test("retained publisher policy exports govern persisted defaults and retry exhaustion", () => {
  const state = fixture().seed().stateJson;
  assert.equal(STATE_SCHEMA_VERSION, 1);
  assert.equal(state.schemaVersion, STATE_SCHEMA_VERSION);
  assert.equal(state.reviewActor, REVIEW_ACTOR);
  assert.equal(state.authorActor, AUTHOR_ACTOR);
  assert.equal(state.fixerModel, PRIMARY_FIXER_MODEL);
  assert.equal(state.fixerFallbackModel, FALLBACK_FIXER_MODEL);
  assert.equal(MAX_INFRASTRUCTURE_RETRIES, 8);
  const sessionKey = "agent:reviewer:subagent:policy-contract";
  const failure = (count) =>
    applyWorkerFailure(
      {
        ...state,
        activeWorker: { kind: "review", sessionKey },
        infrastructureRetryCount: count,
      },
      sessionKey,
      "worker_session_missing",
      state.startedAt,
    );
  const lastRetry = failure(MAX_INFRASTRUCTURE_RETRIES - 1);
  assert.equal(lastRetry.effect, "wait");
  assert.equal(lastRetry.state.infrastructureRetryCount, MAX_INFRASTRUCTURE_RETRIES);
  const exhausted = failure(MAX_INFRASTRUCTURE_RETRIES);
  assert.equal(exhausted.state.phase, PHASE.BLOCKED);
  assert.equal(exhausted.state.blocker, "infrastructure_retry_exhausted:worker_session_missing");
});

void test("new PR head preserves the old worker for exact reconciliation", () => {
  const f = fixture();
  const worker = {
    kind: "review",
    sessionKey: "agent:reviewer:subagent:prior-head",
    runId: "prior-run",
    taskId: "prior-task",
    headSha: SHA_A,
  };
  const state = {
    ...f.seed().stateJson,
    activeWorker: worker,
    phase: PHASE.REVIEW_RUNNING,
    flowWorkspace: { path: "/inert/speculoos-pr319", headSha: SHA_A },
    workspacePreflight: { workspace: "/inert/speculoos-pr319", headSha: SHA_A },
  };
  const next = applyPullRequestEvent(
    state,
    prEvent({ eventId: "github:new-head", headSha: SHA_B, baseSha: SHA_A }),
    f.config.repositories.get(REPO),
  );
  assert.equal(next.reason, "new_head");
  assert.equal(next.state.headSha, SHA_B);
  assert.deepEqual(next.state.orphanedWorker, { ...worker, launchOutcome: null });
  assert.equal(next.state.activeWorker, null);
  assert.equal(next.state.workspacePreflight, null);
  assert.equal(next.state.flowWorkspace.headSha, SHA_A);
  assert.throws(
    () => applyPullRequestEvent(
      { ...state, orphanedWorker: { sessionKey: "another-worker" } },
      prEvent({ eventId: "github:two-workers", headSha: SHA_B }),
      f.config.repositories.get(REPO),
    ),
    /new_head_has_multiple_unreconciled_workers/,
  );
});

void test("same-head base change invalidates review and retains worker custody", () => {
  const f = fixture();
  const worker = {
    kind: "review",
    sessionKey: "agent:reviewer:subagent:base-drift",
    runId: "base-drift-run",
    headSha: SHA_A,
  };
  const state = {
    ...f.seed().stateJson,
    phase: PHASE.REVIEW_RUNNING,
    activeWorker: worker,
    review: { outcome: "approved" },
    mergeReady: { mergeAuthorized: true },
  };
  const changed = applyPullRequestEvent(
    state,
    prEvent({ eventId: "github:base-drift", baseSha: "c".repeat(40) }),
    f.config.repositories.get(REPO),
  );
  assert.equal(changed.reason, "base_changed");
  assert.equal(changed.state.phase, PHASE.REVIEW_QUEUED);
  assert.equal(changed.state.headSha, SHA_A);
  assert.equal(changed.state.baseSha, "c".repeat(40));
  assert.equal(changed.state.review, null);
  assert.equal(changed.state.mergeReady, null);
  assert.equal(changed.state.orphanedWorker.runId, worker.runId);
});

void test("edited GitHub PR ingress carries a same-head base change", () => {
  const event = parseGitHubPullRequest(
    { headers: { "x-github-event": "pull_request", "x-github-delivery": "base-edit" } },
    {
      action: "edited",
      repository: { full_name: REPO },
      pull_request: {
        number: 319,
        updated_at: "2026-10-09T00:00:01Z",
        head: { sha: SHA_A, repo: { full_name: REPO } },
        base: { sha: "c".repeat(40), ref: "dev" },
      },
    },
  );
  assert.equal(event.action, "edited");
  assert.equal(event.baseSha, "c".repeat(40));
  assert.equal(event.prUpdatedAt, Date.parse("2026-10-09T00:00:01Z"));
  const f = fixture();
  const state = {
    ...f.seed().stateJson,
    prEventUpdatedAt: Date.parse("2026-10-09T00:00:00Z"),
    prEventAction: "opened",
  };
  const transition = applyPullRequestEvent(
    state,
    event,
    f.config.repositories.get(REPO),
  );
  assert.equal(transition.reason, "base_changed");
  assert.equal(
    applyReviewResult(transition.state, {
      eventId: "review:pre-edit-base",
      repo: REPO,
      prNumber: 319,
      headSha: SHA_A,
      baseSha: SHA_B,
      outcome: "approved",
      coverageComplete: true,
      findings: [],
    }).reason,
    "stale_base_result",
  );
  assert.throws(
    () => parseGitHubPullRequest(
      { headers: { "x-github-event": "pull_request", "x-github-delivery": "missing-time" } },
      {
        action: "edited",
        repository: { full_name: REPO },
        pull_request: {
          number: 319,
          head: { sha: SHA_A, repo: { full_name: REPO } },
          base: { sha: SHA_B, ref: "dev" },
        },
      },
    ),
    /updated_at is required/,
  );
});

void test("PR revision ordering rejects older and ambiguous exact identities", () => {
  const f = fixture();
  const policy = f.config.repositories.get(REPO);
  const older = "2026-10-09T00:00:00Z";
  const newer = "2026-10-09T00:00:01Z";
  const state = {
    ...f.seed().stateJson,
    headSha: "c".repeat(40),
    prEventUpdatedAt: Date.parse(newer),
    prEventAction: "synchronize",
  };
  const stale = applyPullRequestEvent(
    state,
    prEvent({ eventId: "github:older", prUpdatedAt: older }),
    policy,
  );
  assert.equal(stale.changed, false);
  assert.equal(stale.reason, "stale_pr_event_revision");
  assert.equal(stale.state, state);
  const ambiguous = applyPullRequestEvent(
    state,
    prEvent({ eventId: "github:ambiguous", action: "edited", prUpdatedAt: newer }),
    policy,
  );
  assert.equal(ambiguous.state.phase, PHASE.BLOCKED);
  assert.equal(ambiguous.reason, "pr_event_revision_ambiguous");
  const legacy = applyPullRequestEvent(
    f.seed().stateJson,
    prEvent({ eventId: "github:legacy", headSha: "c".repeat(40), prUpdatedAt: newer }),
    policy,
  );
  assert.equal(legacy.reason, "legacy_pr_event_revision_unverified");
});

void test("revision blocked flow requires explicit owner admission to resume review", async () => {
  const f = fixture();
  const flow = f.seed({
    phase: PHASE.BLOCKED,
    blocker: "pr_event_revision_ambiguous",
    prEventUpdatedAt: Date.parse("2026-10-09T00:00:01Z"),
    prEventAction: "edited",
  });
  const routine = await __testing.ingestPullRequest(
    f.api,
    f.config,
    prEvent({ eventId: "github:revision-redelivery", prUpdatedAt: "2026-10-09T00:00:02Z" }),
  );
  assert.equal(routine.created, false);
  assert.equal(get(f, flow.flowId).stateJson.phase, PHASE.BLOCKED);
  const admitted = await __testing.ingestPullRequest(
    f.api,
    f.config,
    prEvent({ eventId: "owner-admit:revision-recovery" }),
  );
  assert.equal(admitted.reason, "owner_admit_reopen_pr_revision_block");
  const state = get(f, flow.flowId).stateJson;
  assert.equal(state.phase, PHASE.REVIEW_QUEUED);
  assert.equal(state.prEventUpdatedAt, null);
  assert.equal(state.review, null);
  assert.equal(state.blocker, null);
  assertAllClosed(assert, f.calls);
});

void test("disallowed base blocks without losing an active worker", () => {
  const f = fixture();
  const worker = {
    kind: "review",
    sessionKey: "agent:reviewer:subagent:disallowed-base",
    runId: "disallowed-run",
    taskId: "disallowed-task",
    headSha: SHA_A,
  };
  const state = { ...f.seed().stateJson, phase: PHASE.REVIEW_RUNNING, activeWorker: worker };
  const event = prEvent({ eventId: "github:disallowed-base", baseRef: "main" });
  const blocked = applyPullRequestEvent(state, event, f.config.repositories.get(REPO));
  assert.equal(blocked.state.phase, PHASE.BLOCKED);
  assert.equal(blocked.state.activeWorker, null);
  assert.deepEqual(blocked.state.orphanedWorker, { ...worker, launchOutcome: null });
  assert.throws(
    () => applyPullRequestEvent(
      { ...state, orphanedWorker: { sessionKey: "agent:reviewer:subagent:older" } },
      event,
      f.config.repositories.get(REPO),
    ),
    /block_has_multiple_unreconciled_workers/,
  );
});

void test("blocked ingress cancels the exact native worker before clearing orphan custody", async () => {
  const f = fixture();
  const worker = {
    kind: "review",
    sessionKey: "agent:reviewer:subagent:blocked-native",
    runId: "blocked-run",
    taskId: "blocked-task",
    headSha: SHA_A,
  };
  const flow = f.seed({ phase: PHASE.REVIEW_RUNNING, activeWorker: worker });
  f.kernel.observations.set(worker.taskId, {
    id: worker.taskId,
    requesterSessionKey: OWNER,
    childSessionKey: worker.sessionKey,
    observationSource: "native-subagent",
    agentId: "reviewer",
    runId: worker.runId,
    status: "running",
  });
  await __testing.ingestPullRequest(
    f.api,
    f.config,
    prEvent({ eventId: "github:blocked-native", baseRef: "main" }),
  );
  const blocked = get(f, flow.flowId).stateJson;
  assert.equal(blocked.phase, PHASE.BLOCKED);
  assert.equal(blocked.orphanedWorker, null);
  assert.equal(blocked.lastGhostCleanup.reason, "orphan_task_cancelled");
  assert.equal(f.calls.cancels.length, 1);
  assert.equal(f.calls.launches.length, 0);
  assertAllClosed(assert, f.calls);
});

void test("dogfood block requires owner admission before live remediation", async () => {
  const f = fixture();
  const flow = f.seed({
    phase: PHASE.BLOCKED,
    mode: "dogfood",
    blocker: "dogfood_review_complete_live_remediation_not_enabled",
    findings: [{ id: "fix", severity: "high", summary: "Fix", path: "src/fix.ts" }],
  });
  const github = await __testing.ingestPullRequest(
    f.api,
    f.config,
    prEvent({ eventId: "github:dogfood-redelivery", action: "synchronize" }),
  );
  assert.equal(github.reason, undefined);
  assert.equal(get(f, flow.flowId).stateJson.phase, PHASE.BLOCKED);
  assert.equal(f.calls.launches.length, 0);
  const admitted = await __testing.ingestPullRequest(
    f.api,
    f.config,
    prEvent({ eventId: "owner-admit:dogfood", action: "synchronize" }),
  );
  assert.equal(admitted.reason, "active_mode_reopen_dogfood_block");
  assert.equal(get(f, flow.flowId).stateJson.phase, PHASE.REMEDIATION_QUEUED);
  assertAllClosed(assert, f.calls);
});

void test("blocked ingress retains orphan custody when every run ledger is unavailable", async () => {
  const f = fixture();
  const worker = {
    kind: "review",
    sessionKey: "agent:reviewer:subagent:blocked-unavailable",
    runId: "unavailable-run",
    taskId: "unavailable-task",
    headSha: SHA_A,
  };
  const flow = f.seed({ phase: PHASE.REVIEW_RUNNING, activeWorker: worker });
  f.hooks.bindRuns = () => {
    throw new Error("fixture_denied");
  };
  await __testing.ingestPullRequest(
    f.api,
    f.config,
    prEvent({ eventId: "github:blocked-unavailable", baseRef: "main" }),
  );
  const blocked = get(f, flow.flowId).stateJson;
  assert.equal(blocked.phase, PHASE.BLOCKED);
  assert.equal(blocked.orphanedWorker.runId, worker.runId);
  assert.equal(blocked.lastGhostCleanup, null);
  await __testing.reconcileAtStartup(f.api, f.config);
  assert.equal(get(f, flow.flowId).stateJson.orphanedWorker.runId, worker.runId);
  assert.equal(f.calls.launches.length, 0);
  assertAllClosed(assert, f.calls);
});

void test("new-head orphan with unknown launch stays held without a task", async () => {
  const f = fixture();
  const worker = { sessionKey: "agent:reviewer:subagent:unknown", runId: null, taskId: null };
  const result = await __testing.reconcileOrphanedWorker(f.api, OWNER, {
    ...worker,
    launchOutcome: { status: "unknown" },
  });
  assert.equal(result.safe, false);
  assert.equal(result.reason, "orphan_launch_outcome_unknown");
  assertAllClosed(assert, f.calls);
});

void test("absent session cannot settle an unobserved native orphan", async () => {
  const f = fixture();
  const result = await __testing.reconcileOrphanedWorker(f.api, OWNER, {
    sessionKey: "agent:reviewer:subagent:missing-task",
    runId: "accepted-native-run",
    taskId: "missing-task",
  });
  assert.equal(result.safe, false);
  assert.equal(result.reason, "orphan_run_observation_missing");
  assertAllClosed(assert, f.calls);
});

void test("cycle-budget owner admission preserves an unreconciled review worker", async () => {
  const original = pluginConfig();
  const f = fixture(pluginConfig({
    repositories: {
      [REPO]: { ...original.repositories[REPO], maxCycles: 3 },
    },
  }));
  const worker = {
    kind: "review",
    sessionKey: "agent:reviewer:subagent:budget-orphan",
    runId: "budget-run",
    taskId: "budget-task",
    headSha: SHA_A,
  };
  const flow = f.seed({
    phase: PHASE.BLOCKED,
    blocker: "review_fix_cycle_budget_exhausted",
    cycle: 2,
    maxCycles: 2,
    orphanedWorker: worker,
  }, { status: "blocked" });
  f.hooks.bindRuns = () => {
    throw new Error("fixture_denied");
  };
  const admitted = await __testing.ingestPullRequest(
    f.api,
    f.config,
    prEvent({ eventId: "owner-admit:budget-reopen" }),
  );
  assert.equal(admitted.reason, "owner_admit_reopen_cycle_budget");
  assert.equal(get(f, flow.flowId).stateJson.orphanedWorker.runId, worker.runId);
  await continueFlow(f, flow.flowId);
  assert.equal(get(f, flow.flowId).stateJson.orphanedWorker.runId, worker.runId);
  assert.equal(f.calls.launches.length, 0);
  assertAllClosed(assert, f.calls);
});

void test("external review result retains old-head and active worker custody", () => {
  const f = fixture();
  const worker = {
    kind: "review",
    sessionKey: "agent:reviewer:subagent:review-result",
    runId: "review-result-run",
    taskId: "review-result-task",
    headSha: SHA_A,
  };
  const input = {
    eventId: "review:custody",
    repo: REPO,
    prNumber: 319,
    headSha: SHA_A,
    baseSha: SHA_B,
    outcome: "approved",
    coverageComplete: true,
    findings: [],
  };
  for (const state of [
    { ...f.seed().stateJson, phase: PHASE.REVIEW_QUEUED, orphanedWorker: worker },
    { ...f.seed().stateJson, phase: PHASE.REVIEW_RUNNING, activeWorker: worker },
  ]) {
    const next = applyReviewResult(state, input);
    assert.equal(next.state.phase, PHASE.MERGE_READY);
    assert.equal(next.state.activeWorker, null);
    assert.equal(next.state.orphanedWorker.runId, worker.runId);
  }
  assert.throws(
    () => applyReviewResult(
      { ...f.seed().stateJson, phase: PHASE.REVIEW_RUNNING, activeWorker: worker, orphanedWorker: worker },
      input,
    ),
    /review_result_has_multiple_unreconciled_workers/,
  );
});

void test("a delayed review from a previous base cannot approve the new base", () => {
  const f = fixture();
  const state = { ...f.seed().stateJson, baseSha: "c".repeat(40) };
  const result = applyReviewResult(state, {
    eventId: "review:stale-base",
    repo: REPO,
    prNumber: 319,
    headSha: SHA_A,
    baseSha: SHA_B,
    outcome: "approved",
    coverageComplete: true,
    findings: [],
  });
  assert.equal(result.changed, false);
  assert.equal(result.reason, "stale_base_result");
  assert.equal(result.state, state);
  assert.throws(
    () => parseMergeguezReviewEvent(
      { headers: { "x-mergeguez-event": "review.completed", "x-mergeguez-delivery": "old" } },
      { repository: REPO, pullRequest: 319, headSha: SHA_A, outcome: "approved" },
    ),
    /baseSha/,
  );
});

void test("ingress transitions retain every unsettled exact worker identity", () => {
  const f = fixture();
  const worker = {
    kind: "review",
    sessionKey: "agent:reviewer:subagent:transition-invariant",
    runId: "transition-run",
    taskId: "transition-task",
    headSha: SHA_A,
  };
  const state = { ...f.seed().stateJson, phase: PHASE.REVIEW_RUNNING, activeWorker: worker };
  const policy = f.config.repositories.get(REPO);
  const review = (outcome, findings = []) => ({
    eventId: `review:${outcome}`,
    repo: REPO,
    prNumber: 319,
    headSha: SHA_A,
    baseSha: SHA_B,
    outcome,
    coverageComplete: true,
    findings,
  });
  const cases = [
    ["new head", () => applyPullRequestEvent(state, prEvent({ eventId: "head", headSha: SHA_B }), policy)],
    ["blocked base", () => applyPullRequestEvent(state, prEvent({ eventId: "blocked", baseRef: "main" }), policy)],
    ["changed base", () => applyPullRequestEvent(state, prEvent({ eventId: "base", baseSha: "c".repeat(40) }), policy)],
    ["review approved", () => applyReviewResult(state, review("approved"))],
    ["review changes", () => applyReviewResult(state, review("changes_requested", [
      { id: "fix", severity: "high", summary: "Fix", path: "src/fix.ts" },
    ]))],
    ["review terminal failure", () => applyReviewResult(state, review("failed_terminal"))],
  ];
  for (const [name, transition] of cases) {
    const next = transition().state;
    assert.equal(
      next.activeWorker?.runId === worker.runId || next.orphanedWorker?.runId === worker.runId,
      true,
      `${name} discarded the worker`,
    );
  }
});

void test("external approval remains waiting until its exact worker is reconciled", async () => {
  const f = fixture();
  const worker = {
    kind: "review",
    sessionKey: "agent:reviewer:subagent:approval-worker",
    runId: "approval-run",
    taskId: "approval-task",
    headSha: SHA_A,
  };
  const claimRef = "claim:approval-worker";
  const flow = f.seed({
    phase: PHASE.REVIEW_WAITING,
    orphanedWorker: worker,
    wait: { kind: "mergeguez_review", headSha: SHA_A, claimRef },
  }, { status: "waiting" });
  f.kernel.observations.set(worker.taskId, {
    id: worker.taskId,
    requesterSessionKey: OWNER,
    childSessionKey: worker.sessionKey,
    observationSource: "native-subagent",
    agentId: "reviewer",
    runId: worker.runId,
    status: "running",
  });
  f.hooks.bindRuns = () => {
    throw new Error("fixture_denied");
  };
  await __testing.ingestReviewResult(f.api, f.config, {
    eventId: "review:approval-worker",
    repo: REPO,
    prNumber: 319,
    headSha: SHA_A,
    baseSha: SHA_B,
    claimRef,
    outcome: "approved",
    coverageComplete: true,
    findings: [],
  });
  assert.equal(get(f, flow.flowId).status, "waiting");
  assert.equal(get(f, flow.flowId).stateJson.orphanedWorker.runId, worker.runId);
  assert.equal(f.calls.cancels.length, 0);
  f.hooks.bindRuns = undefined;
  const recovery = details(await f.tool().execute("recover", { action: "recover", flowId: flow.flowId }));
  assert.equal(recovery.ok, true);
  assert.equal(get(f, flow.flowId).status, "succeeded");
  assert.equal(get(f, flow.flowId).stateJson.orphanedWorker, null);
  assert.equal(f.calls.cancels.length, 1);
  assertAllClosed(assert, f.calls);
});

void test("automatic merge waits for an unreconciled review worker", async () => {
  const f = fixture();
  const worker = {
    kind: "review",
    sessionKey: "agent:reviewer:subagent:merge-hold",
    runId: "merge-hold-run",
    taskId: "merge-hold-task",
    headSha: SHA_A,
  };
  const flow = f.seed({
    phase: PHASE.REVIEW_WAITING,
    orphanedWorker: worker,
    wait: { kind: "mergeguez_review", headSha: SHA_A, claimRef: "claim:merge-hold" },
    autoMergeBaseBranches: ["dev"],
  }, { status: "waiting" });
  f.hooks.bindRuns = () => {
    throw new Error("fixture_denied");
  };
  let brokerCalls = 0;
  f.api.testRunMergeguez = () => {
    brokerCalls += 1;
    throw new Error("broker_must_not_run");
  };
  await __testing.ingestReviewResult(f.api, f.config, {
    eventId: "review:merge-hold",
    repo: REPO,
    prNumber: 319,
    headSha: SHA_A,
    baseSha: SHA_B,
    claimRef: "claim:merge-hold",
    outcome: "approved",
    coverageComplete: true,
    findings: [],
  });
  assert.equal(get(f, flow.flowId).stateJson.phase, PHASE.MERGE_QUEUED);
  assert.equal(get(f, flow.flowId).stateJson.orphanedWorker.runId, worker.runId);
  assert.equal(brokerCalls, 0);
  assertAllClosed(assert, f.calls);
});

void test("unreconciled orphan occupies the repository parallel slot", () => {
  const f = fixture();
  const orphan = {
    kind: "review",
    sessionKey: "agent:reviewer:subagent:slot-orphan",
    runId: "slot-run",
    headSha: SHA_A,
  };
  f.seed({ phase: PHASE.REVIEW_QUEUED, orphanedWorker: orphan });
  const contender = f.seed({ prNumber: 320 });
  const snapshot = f.kernel.snapshot([OWNER]);
  const slot = __testing.evaluateParallelSlot(
    f.config,
    { list: () => snapshot.flows },
    contender,
    contender.stateJson,
    "review",
  );
  assert.equal(slot.ok, false);
  assert.equal(slot.wait.scope, "repo");
  assert.equal(
    __testing.activeReviewLeaseHolder(
      { list: () => snapshot.flows },
      contender.flowId,
      contender.stateJson,
      f.config.repositories,
    )?.stateJson.orphanedWorker.runId,
    orphan.runId,
  );
});

void test("automatic merge refuses a changed remote base before invoking merge-pr", async () => {
  const f = fixture();
  const state = {
    ...f.seed().stateJson,
    phase: PHASE.MERGE_QUEUED,
    autoMergeBaseBranches: ["dev"],
    mergeReady: { mergeAuthorized: true },
  };
  const calls = [];
  f.api.testRunMergeguez = async (args) => {
    calls.push(args);
    return {
      head: { sha: state.headSha, repo: state.repo },
      base: { ref: "dev", sha: SHA_A },
      merged: false,
    };
  };
  await assert.rejects(
    __testing.autoMergeReceipt(f.api, state),
    /automatic_merge_remote_base_changed/,
  );
  assert.equal(calls.length, 1);
  assert.equal(calls[0][0], "pr-state");
});

void test("automatic merge rejects unsupported receipt methods before broker calls", async () => {
  const f = fixture();
  for (const method of ["squash", "rebase"]) {
    const state = {
      ...f.seed().stateJson,
      phase: PHASE.MERGE_QUEUED,
      autoMergeMethod: method,
      autoMergeBaseBranches: ["dev"],
      mergeReady: { mergeAuthorized: true },
    };
    await assert.rejects(
      __testing.autoMergeReceipt(f.api, state),
      /automatic_merge_method_unsupported_by_atomic_receipt/,
    );
  }
  assert.equal(f.calls.events.length, 0);
});

void test("automatic merge pins the reviewed base at the protected broker boundary", async () => {
  const f = fixture();
  const state = {
    ...f.seed().stateJson,
    phase: PHASE.MERGE_QUEUED,
    autoMergeBaseBranches: ["dev"],
    mergeReady: { mergeAuthorized: true },
  };
  const mergedSha = "c".repeat(40);
  const calls = [];
  let baseDriftsAfterPreflight = true;
  let brokerSupportsAtomicGate = true;
  let missingAtomicProof = false;
  let alreadyMerged = false;
  f.api.testRunMergeguez = async (args) => {
    calls.push(args);
    if (args[0] === "pr-state") {
      return {
        head: { sha: state.headSha, repo: state.repo, ref: "feat/reviewed" },
        base: { ref: "dev", sha: state.baseSha },
        merged: alreadyMerged,
        state: "open",
        draft: false,
        mergeable: true,
        reviewers: {
          mergeguez_review: {
            status: "approved",
            coverage_complete: true,
            reviewed_head_sha: state.headSha,
            reviewed_base_sha: state.baseSha,
            findings_count: 0,
            blocking_findings_count: 0,
          },
        },
        checks: {
          ready: true,
          check_runs: [{ name: "Mergeguez review", status: "completed", conclusion: "success" }],
        },
      };
    }
    if (baseDriftsAfterPreflight) {
      throw new Error("taskflow merge gates observed base branch or SHA drift");
    }
    if (!brokerSupportsAtomicGate) {
      throw new Error("unsupported merge-pr argument");
    }
    return {
      merged: true,
      base: "dev",
      head_sha: state.headSha,
      actor_verification: "passed",
      sha: mergedSha,
      taskflow_gates: missingAtomicProof
        ? null
        : {
            required_checks_ready: true,
            mergeguez_check_ready: true,
            mergeguez_check_app_id: 12345,
            exact_review_ready: true,
            atomic_base_update: true,
            reviewed_base_sha: state.baseSha,
            reviewed_head_sha: state.headSha,
            actual_merge_commit_sha: mergedSha,
            actual_merge_parents: [state.baseSha, state.headSha],
            atomic_enforcement: {
              kind: "github_branch_protection",
              branch: "dev",
              matches_policy: true,
              strict: true,
              enforce_admins: true,
              mergeguez_app_id: 12345,
              required_status_checks: [{ context: "Mergeguez review", app_id: 12345 }],
            },
          },
    };
  };
  await assert.rejects(
    __testing.autoMergeReceipt(f.api, state),
    /taskflow merge gates observed base branch or SHA drift/,
  );
  assert.deepEqual(calls[1], [
    "merge-pr", "speculoos", "319", "--expected-base", "dev",
    "--expected-base-sha", state.baseSha,
    "--expected-head-branch", "feat/reviewed",
    "--expected-head-sha", state.headSha,
    "--expected-actor-login", "mergeguez[bot]",
    "--merge-method", "merge", "--require-taskflow-gates", "--json",
  ]);

  baseDriftsAfterPreflight = false;
  brokerSupportsAtomicGate = false;
  await assert.rejects(
    __testing.autoMergeReceipt(f.api, state),
    /unsupported merge-pr argument/,
  );
  brokerSupportsAtomicGate = true;
  missingAtomicProof = true;
  await assert.rejects(__testing.autoMergeReceipt(f.api, state), /automatic_merge_receipt_invalid/);
  missingAtomicProof = false;
  const receipt = await __testing.autoMergeReceipt(f.api, state);
  assert.equal(receipt.taskflow_gates.atomic_base_update, true);
  assert.deepEqual(receipt.taskflow_gates.actual_merge_parents, [state.baseSha, state.headSha]);

  alreadyMerged = true;
  await assert.rejects(
    __testing.autoMergeReceipt(f.api, state),
    /automatic_merge_already_merged_requires_exact_reconciliation/,
  );
});

void test("new head rebinds a clean dedicated worktree and holds a dirty one", async () => {
  const root = mkdtempSync(join(tmpdir(), "mergeguez-v99-worktree-"));
  const seed = join(root, "seed");
  const dest = join(root, "speculoos-pr319");
  const git = (...args) => execFileSync("git", args, { encoding: "utf8" }).trim();
  try {
    git("init", "-q", seed);
    git("-C", seed, "config", "user.name", "Fixture");
    git("-C", seed, "config", "user.email", "fixture@example.invalid");
    writeFileSync(join(seed, "fixture.txt"), "old\n");
    git("-C", seed, "add", "fixture.txt");
    git("-C", seed, "commit", "-qm", "old");
    const oldHead = git("-C", seed, "rev-parse", "HEAD");
    writeFileSync(join(seed, "fixture.txt"), "new\n");
    git("-C", seed, "commit", "-qam", "new");
    const newHead = git("-C", seed, "rev-parse", "HEAD");
    git("-C", seed, "worktree", "add", "--detach", dest, oldHead);
    const f = fixture();
    const policy = { ...f.config.repositories.get(REPO), workspace: seed, maxParallelPrs: 2 };
    const state = {
      ...f.seed().stateJson,
      headSha: newHead,
      flowWorkspace: { path: dest, headSha: oldHead },
    };
    delete f.api.testProvisionFlowWorktree;
    assert.equal(await __testing.ensureFlowWorkspace(f.api, policy, state), dest);
    assert.equal(git("-C", dest, "rev-parse", "HEAD"), newHead);
    writeFileSync(join(dest, "untracked.txt"), "retain\n");
    await assert.rejects(
      __testing.ensureFlowWorkspace(f.api, policy, {
        ...state,
        headSha: oldHead,
        flowWorkspace: { path: dest, headSha: newHead },
      }),
      /flow_workspace_not_clean/,
    );
    assert.equal(git("-C", dest, "rev-parse", "HEAD"), newHead);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

void test("retained review input exports normalize findings and require actionable scope", () => {
  assert.equal(isSha(SHA_A), true);
  assert.equal(isSha("a".repeat(39)), false);
  assert.equal(isRepo(REPO), true);
  assert.equal(isRepo("owner/repo/extra"), false);
  const findings = sanitizeFindings([
    { id: " issue ", severity: " HIGH ", summary: " Fix it ", path: " src/main.ts " },
    { id: "context", severity: "info", summary: "Additional context" },
  ]);
  assert.deepEqual(findings[0], {
    id: "issue",
    severity: "high",
    summary: "Fix it",
    path: "src/main.ts",
  });
  assert.equal(findingsAreActionable(findings), true);
  assert.equal(findingsAreActionable([{ ...findings[0], path: " " }]), false);
  assert.throws(
    () => sanitizeFindings([{ ...findings[0], unexpected: true }]),
    /unexpected is not allowed/,
  );
});

void test("retained HTTP body reader enforces its default size limit", async () => {
  assert.equal(MAX_BODY_BYTES, 256 * 1024);
  const overhead = Buffer.byteLength(JSON.stringify({ value: "" }));
  const atLimit = Buffer.from(JSON.stringify({ value: "x".repeat(MAX_BODY_BYTES - overhead) }));
  assert.equal(atLimit.length, MAX_BODY_BYTES);
  const tooLarge = Buffer.concat([atLimit, Buffer.from(" ")]);
  await assert.rejects(readJsonBody(Readable.from([tooLarge])), /request_body_too_large/);
  const accepted = await readJsonBody(Readable.from([atLimit]));
  assert.equal(accepted.json.value.length, MAX_BODY_BYTES - overhead);
});

void test("rejected HTTP body stops reading and removes its listeners", async () => {
  const request = new Readable({ read() {} });
  const rejected = assert.rejects(
    readJsonBody(request, { maxBytes: 3 }),
    /request_body_too_large/,
  );
  request.push(Buffer.alloc(4));
  await rejected;
  assert.equal(request.isPaused(), true);
  for (const event of ["data", "end", "error", "aborted"]) {
    assert.equal(request.listenerCount(event), 0);
  }
  request.destroy();
});

void test("retained HTTP body reader expires an incomplete body at its default deadline", async (t) => {
  assert.equal(BODY_TIMEOUT_MS, 15_000);
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const request = new Readable({ read() {} });
  let settled = false;
  const pending = readJsonBody(request).finally(() => {
    settled = true;
  });
  const rejected = assert.rejects(pending, /request_body_timeout/);
  t.mock.timers.tick(BODY_TIMEOUT_MS - 1);
  await Promise.resolve();
  await Promise.resolve();
  assert.equal(settled, false);
  t.mock.timers.tick(1);
  await rejected;
  assert.equal(settled, true);
  assert.equal(request.isPaused(), true);
  for (const event of ["data", "end", "error", "aborted"]) {
    assert.equal(request.listenerCount(event), 0);
  }
  request.destroy();
});

void test("async PR ingress awaits creation and preserves state, workflow and owner", async () => {
  const f = fixture();
  const outcome = await __testing.ingestPullRequest(f.api, f.config, prEvent());
  assert.equal(outcome.created, true);
  assert.equal(get(f, outcome.flowId).stateJson.headSha, SHA_A);
  assert.deepEqual(f.kernel.writes[0].input.dedupe, { stateFields: ["repo", "prNumber"] });
  assert.equal(f.calls.schedules.length, 1);
  assert.equal(f.calls.schedules[0].sessionKey, OWNER);
  assert.equal(f.calls.schedules[0].deleteAfterRun, true);
  assertAllClosed(assert, f.calls);
});

void test("concurrent Promise ingress converges in the inert native transaction without state overwrite", async () => {
  const older = "2026-10-09T00:00:00Z";
  const newer = "2026-10-09T00:00:01Z";
  for (const [action, changed, expected] of [
    ["synchronize", { headSha: "c".repeat(40) }, { headSha: "c".repeat(40) }],
    ["edited", { baseSha: "c".repeat(40) }, { baseSha: "c".repeat(40) }],
  ]) {
    const f = fixture();
    // Both lookups suspend before their empty result, reproducing the original create race.
    const outcomes = await Promise.all([
      __testing.ingestPullRequest(
        f.api,
        f.config,
        prEvent({ eventId: `first:${action}`, prUpdatedAt: older }),
      ),
      __testing.ingestPullRequest(
        f.api,
        f.config,
        prEvent({ eventId: `newer:${action}`, action, prUpdatedAt: newer, ...changed }),
      ),
    ]);
    assert.equal(f.kernel.flows.size, 1);
    assert.equal(outcomes.filter((value) => value.created).length, 1);
    assert.equal(outcomes[0].flowId, outcomes[1].flowId);
    const state = get(f, outcomes[0].flowId).stateJson;
    assert.equal(state.headSha, expected.headSha ?? SHA_A);
    assert.equal(state.baseSha, expected.baseSha ?? SHA_B);
    assert.equal(state.prEventUpdatedAt, Date.parse(newer));
    assert.ok(state.seenEventIds.includes(`newer:${action}`));
    assert.ok(f.calls.schedules.length >= 1);
    assertAllClosed(assert, f.calls);
  }
});

void test("terminal rows retain original reopen semantics and are not deduplicated", async () => {
  const f = fixture();
  f.seed({ phase: PHASE.MERGE_READY }, { status: "succeeded" });
  const outcome = await __testing.ingestPullRequest(
    f.api,
    f.config,
    prEvent({ eventId: "reopened", action: "reopened" }),
  );
  assert.equal(outcome.created, true);
  assert.equal(f.kernel.flows.size, 2);
  assertAllClosed(assert, f.calls);
});

void test("owner status and stale wake entrypoints await lookups and close the selected binding", async () => {
  const f = fixture();
  const flow = f.seed();
  const tool = f.tool();
  const status = details(await tool.execute("status", { action: "status", flowId: flow.flowId }));
  assert.equal(status.flowId, flow.flowId);
  const stale = details(
    await tool.execute("stale", { action: "continue", flowId: flow.flowId, expectedRevision: 99 }),
  );
  assert.equal(stale.staleWake, true);
  assert.equal(f.calls.launches.length, 0);
  assert.equal(f.kernel.writes.length, 1);
  assertAllClosed(assert, f.calls);
});

void test("normal launch keeps original timeout spelling, tool allowance and held guard until acknowledgement", async () => {
  const f = fixture();
  const flow = f.seed();
  const outcome = details(await continueFlow(f, flow.flowId));
  assert.equal(outcome.flow.activeWorker.runId, "native-1");
  assert.equal(outcome.flow.activeWorker.taskId, "observed-native-1");
  const request = f.calls.launches[0];
  assert.equal(request.runTimeoutSeconds, 3600);
  assert.equal("timeoutSeconds" in request, false);
  assert.deepEqual(request.toolsAlsoAllow, ["mergeguez_pr_lifecycle"]);
  assert.equal(request.deliver, false);
  assert.equal(request.lightContext, true);
  assert.equal(typeof request.assertCurrent, "function");
  assert.throws(() => request.assertCurrent(), /fixture_binding_closed/);
  assert.equal(f.calls.snapshots.length, 2);
  assert.ok(f.calls.snapshots[1].snapshot[0].revision > f.calls.snapshots[0].snapshot[0].revision);
  assertAllClosed(assert, f.calls);
});

void test("selected binding remains live until accepted async launch work has settled", async () => {
  const f = fixture();
  const flow = f.seed();
  let acknowledge;
  const pending = new Promise((resolve) => {
    acknowledge = resolve;
  });
  let entered;
  const started = new Promise((resolve) => {
    entered = resolve;
  });
  f.hooks.launch = async (request) => {
    entered(request);
    return await pending;
  };
  const operation = continueFlow(f, flow.flowId);
  const request = await Promise.race([
    started,
    operation.then(() => {
      throw new Error("launch completed without entering original subagent owner");
    }),
  ]);
  assert.doesNotThrow(() => request.assertCurrent());
  assert.ok(f.calls.bindings.some((binding) => binding.kind === "flows" && !binding.closed));
  acknowledge({ runId: "accepted-but-not-observed", sessionKey: request.sessionKey });
  const result = details(await operation);
  assert.equal(result.flow.blocker, "worker_launch_outcome_unknown");
  assertAllClosed(assert, f.calls);
});

void test("capacity is refreshed after preflight and an inserted occupant prevents launch", async () => {
  const f = fixture();
  const flow = f.seed();
  let snapshots = 0;
  f.hooks.operation = (_binding, name) => {
    if (name === "snapshot" && ++snapshots === 2) {
      f.seed({
        prNumber: 320,
        activeWorker: { kind: "review", sessionKey: "agent:other:subagent:x" },
        phase: PHASE.REVIEW_RUNNING,
      });
    }
  };
  await continueFlow(f, flow.flowId);
  assert.equal(f.calls.launches.length, 0);
  assert.equal(f.calls.reservations.length, 0);
  assert.equal(get(f, flow.flowId).stateJson.wait.kind, "parallel_slot");
  assertAllClosed(assert, f.calls);
});

void test("worker transaction rejects capacity snapshot changed after selection without launching", async () => {
  const f = fixture();
  const flow = f.seed();
  f.hooks.operation = (_binding, name) => {
    if (name === "reserve") {
      f.seed({ prNumber: 321 });
    }
  };
  await continueFlow(f, flow.flowId);
  assert.equal(f.calls.reservations.length, 1);
  assert.equal(f.calls.launches.length, 0);
  assert.equal(get(f, flow.flowId).stateJson.activeWorker, null);
  assertAllClosed(assert, f.calls);
});

void test("snapshot fence fields and flow values are detached before async reserve", () => {
  const original = {
    ownerSessionKeys: [OWNER],
    snapshot: [{ flowId: "flow", ownerKey: OWNER, revision: 1 }],
    flows: [{ stateJson: { repo: REPO } }],
  };
  const captured = __testing.captureCapacitySnapshot(original);
  original.snapshot[0].revision = 999;
  original.ownerSessionKeys[0] = "evil";
  original.flows[0].stateJson.repo = "evil";
  assert.equal(captured.snapshot[0].revision, 1);
  assert.equal(captured.ownerSessionKeys[0], OWNER);
  assert.equal(captured.flows[0].stateJson.repo, REPO);
  assert.throws(() => {
    captured.snapshot[0].revision = 10;
  }, TypeError);
  assert.throws(() => captured.ownerSessionKeys.push("evil"), TypeError);
});

void test("invocation throw is unknown launch, retains reservation, and startup never relaunches it", async () => {
  const f = fixture();
  const flow = f.seed();
  f.hooks.launch = async () => {
    const admitted = get(f, flow.flowId).stateJson;
    assert.equal(admitted.launchOutcome.status, "unknown");
    assert.equal(admitted.launchOutcome.sessionKey, admitted.activeWorker.sessionKey);
    assert.equal(admitted.activeWorker.runId, null);
    throw new Error("ack transport lost after admission");
  };
  const outcome = details(await continueFlow(f, flow.flowId));
  assert.equal(outcome.flow.blocker, "worker_launch_outcome_unknown");
  const held = get(f, flow.flowId).stateJson;
  assert.ok(held.activeWorker);
  assert.equal(held.launchOutcome.status, "unknown");
  const count = f.kernel.writes.length;
  await __testing.reconcileAtStartup(f.api, f.config);
  await f.calls.tools[0]
    .factory({ sessionKey: OWNER })
    .execute("recover", { action: "recover", flowId: flow.flowId });
  assert.equal(f.calls.launches.length, 1);
  assert.equal(f.kernel.writes.length, count);
  assertAllClosed(assert, f.calls);
});

void test("restart keeps a persisted prelaunch reservation without a run acknowledgement", async () => {
  const f = fixture();
  const now = Date.now();
  const worker = {
    kind: "review",
    sessionKey: "agent:reviewer:subagent:crash-before-ack",
    runId: null,
    taskId: null,
    reservedAt: now - 180_000,
  };
  const flow = f.seed({
    phase: PHASE.REVIEW_RUNNING,
    activeWorker: worker,
    launchOutcome: { status: "unknown", sessionKey: worker.sessionKey, observedAt: now - 180_000 },
  });
  const recovery = __testing.recoverObservedState(
    get(f, flow.flowId).stateJson, undefined, now, 120_000, { sessionAlive: false });
  assert.equal(recovery.changed, false);
  assert.equal(recovery.effect, "hold");
  assert.equal(recovery.reason, "worker_launch_outcome_unknown");
  await __testing.reconcileAtStartup(f.api, f.config);
  assert.equal(get(f, flow.flowId).stateJson.activeWorker.sessionKey, worker.sessionKey);
  assert.equal(f.calls.launches.length, 0);
  assertAllClosed(assert, f.calls);
});

void test("mismatched session acknowledgement is held with exact observed session evidence", async () => {
  const f = fixture();
  const flow = f.seed();
  f.hooks.launch = async () => ({
    runId: "stray-run",
    sessionKey: "agent:reviewer:subagent:unexpected",
  });
  await continueFlow(f, flow.flowId);
  const state = get(f, flow.flowId).stateJson;
  assert.equal(state.blocker, "worker_launch_outcome_unknown");
  assert.equal(state.launchOutcome.observedSessionKey, "agent:reviewer:subagent:unexpected");
  assert.equal(state.launchOutcome.runId, "stray-run");
  assertAllClosed(assert, f.calls);
});

void test("terminal event awaits enumeration and native unknown overrides bare end plus absent session", async () => {
  const f = fixture();
  const flow = f.seed();
  await continueFlow(f, flow.flowId);
  const state = get(f, flow.flowId).stateJson;
  f.kernel.observations.get(state.activeWorker.taskId).status = "unknown";
  const before = get(f, flow.flowId).revision;
  const result = await __testing.reconcileTerminalWorkerEvent(f.api, f.config, {
    stream: "lifecycle",
    runId: state.activeWorker.runId,
    sessionKey: state.activeWorker.sessionKey,
    data: { phase: "end" },
  });
  assert.equal(result.reason, "native_worker_outcome_unknown");
  assert.equal(get(f, flow.flowId).revision, before);
  assert.equal(f.calls.launches.length, 1);
  assertAllClosed(assert, f.calls);
});

void test("bare terminal event with missing or still-running observation cannot credit success or retry work", async () => {
  for (const status of ["missing", "running"]) {
    const f = fixture();
    const flow = f.seed();
    await continueFlow(f, flow.flowId);
    const state = get(f, flow.flowId).stateJson;
    if (status === "missing") {
      f.kernel.observations.clear();
    }
    const before = get(f, flow.flowId).revision;
    const result = await __testing.reconcileTerminalWorkerEvent(f.api, f.config, {
      stream: "lifecycle",
      runId: state.activeWorker.runId,
      data: { phase: "end" },
    });
    assert.equal(result.reason, "worker_terminal_observation_pending");
    assert.equal(get(f, flow.flowId).revision, before);
    assert.equal(f.calls.launches.length, 1);
    assert.equal(f.calls.schedules.at(-1).deleteAfterRun, true);
    assertAllClosed(assert, f.calls);
  }
});

void test("unknown retained legacy observation stays held through startup, recover and terminal event", async () => {
  const f = fixture();
  const flow = f.seed();
  await continueFlow(f, flow.flowId);
  const state = get(f, flow.flowId).stateJson;
  const observation = f.kernel.observations.get(state.activeWorker.taskId);
  observation.observationSource = "legacy-task";
  observation.status = "unknown";
  const before = get(f, flow.flowId).revision;
  await __testing.reconcileAtStartup(f.api, f.config);
  const tool = f.calls.tools[0].factory({ sessionKey: OWNER });
  const recovered = details(
    await tool.execute("recover", { action: "recover", flowId: flow.flowId }),
  );
  assert.equal(recovered.recovery, "legacy_worker_outcome_unknown");
  const terminal = await __testing.reconcileTerminalWorkerEvent(f.api, f.config, {
    stream: "lifecycle",
    runId: state.activeWorker.runId,
    data: { phase: "end" },
  });
  assert.equal(terminal.reason, "legacy_worker_outcome_unknown");
  assert.equal(get(f, flow.flowId).revision, before);
  assert.equal(f.calls.launches.length, 1);
  assertAllClosed(assert, f.calls);
});

void test("known terminal observation drives original structured-report recovery without assuming lifecycle end success", async () => {
  const f = fixture();
  const flow = f.seed();
  await continueFlow(f, flow.flowId);
  const state = get(f, flow.flowId).stateJson;
  const observation = f.kernel.observations.get(state.activeWorker.taskId);
  observation.status = "failed";
  observation.error = "explicit worker error";
  const result = await __testing.reconcileTerminalWorkerEvent(f.api, f.config, {
    stream: "lifecycle",
    runId: state.activeWorker.runId,
    data: { phase: "end" },
  });
  assert.equal(result.handled, true);
  assert.ok(
    get(f, flow.flowId).stateJson.retryCount > 0 ||
      get(f, flow.flowId).stateJson.infrastructureRetryCount > 0,
  );
  assertAllClosed(assert, f.calls);
});

void test("startup leaves historical infrastructure block unchanged and removes its wake", async () => {
  const f = fixture();
  const flow = f.seed(
    { phase: PHASE.BLOCKED, blocker: "worker_start_failed:rate_limit" },
    { status: "blocked" },
  );
  const before = get(f, flow.flowId);
  await __testing.reconcileAtStartup(f.api, f.config);
  assert.deepEqual(get(f, flow.flowId), before);
  assert.equal(f.calls.schedules.length, 0);
  assert.ok(f.calls.unschedules.length);
  assertAllClosed(assert, f.calls);
});

void test("legacy exact task observation remains read-only and does not create or adopt a lease", async () => {
  const f = fixture();
  const worker = {
    sessionKey: "agent:reviewer:subagent:legacy",
    runId: "old-run",
    taskId: "old-id",
  };
  f.kernel.observations.set("old-id", {
    id: "old-id",
    observationSource: "legacy-task",
    requesterSessionKey: OWNER,
    childSessionKey: worker.sessionKey,
    agentId: "reviewer",
    runId: worker.runId,
    status: "running",
  });
  const task = await __testing.currentWorkerTask(f.api, OWNER, { activeWorker: worker });
  assert.equal(task.id, "old-id");
  assert.equal(task.observationSource, "legacy-task");
  assert.equal(f.kernel.flows.size, 0);
  assert.equal(f.calls.cancels.length, 0);
  assertAllClosed(assert, f.calls);
});

void test("one denied ledger does not hide an exact observation from the admitted owner", async () => {
  const f = fixture();
  const worker = {
    sessionKey: "agent:reviewer:subagent:legacy",
    runId: "old-run",
    taskId: "old-id",
  };
  f.hooks.bindRuns = (session) => {
    if (session !== OWNER) {
      throw new Error("fixture_denied");
    }
  };
  f.kernel.observations.set("old-id", {
    id: "old-id",
    requesterSessionKey: OWNER,
    childSessionKey: worker.sessionKey,
    observationSource: "legacy-task",
    agentId: "reviewer",
    runId: worker.runId,
    status: "running",
  });
  assert.equal(
    (await __testing.currentWorkerTask(f.api, OWNER, { activeWorker: worker })).id,
    "old-id",
  );
  assertAllClosed(assert, f.calls);
});

void test("denied run ledgers hold recovery and orphan reconciliation when no exact task is visible", async () => {
  const f = fixture();
  const worker = {
    kind: "review",
    sessionKey: "agent:reviewer:subagent:denied-ledgers",
    runId: "denied-run",
    taskId: "denied-task",
    reservedAt: Date.now() - 150_000,
  };
  f.hooks.bindRuns = () => {
    throw new Error("fixture_denied");
  };
  const state = { ...f.seed().stateJson, phase: PHASE.REVIEW_RUNNING, activeWorker: worker };
  const observation = await __testing.currentWorkerTask(f.api, OWNER, state);
  assert.equal(observation.status, "unavailable");
  const recovery = __testing.recoverObservedState(state, observation, Date.now(), 120_000, {
    sessionAlive: false,
  });
  assert.equal(recovery.effect, "hold");
  assert.equal(recovery.reason, "worker_observation_unavailable");
  assert.equal(recovery.state.activeWorker.runId, worker.runId);
  const orphan = await __testing.reconcileOrphanedWorker(f.api, OWNER, worker);
  assert.equal(orphan.safe, false);
  assert.equal(orphan.reason, "orphan_run_observation_unavailable");
  assertAllClosed(assert, f.calls);
});

void test("missing observation for an attached run cannot consume retry budget", async () => {
  const f = fixture();
  const now = Date.now();
  const worker = {
    kind: "review",
    sessionKey: "agent:reviewer:subagent:missing-attached",
    runId: "accepted-native-run",
    taskId: "accepted-native-task",
    reservedAt: now - 180_000,
  };
  const state = { ...f.seed().stateJson, phase: PHASE.REVIEW_RUNNING, activeWorker: worker };
  const observation = await __testing.currentWorkerTask(f.api, OWNER, state);
  assert.equal(observation, undefined);
  const recovery = __testing.recoverObservedState(state, observation, now, 120_000, {
    sessionAlive: false,
  });
  assert.equal(recovery.changed, false);
  assert.equal(recovery.effect, "wait");
  assert.equal(recovery.reason, "worker_run_observation_missing");
  assert.equal(recovery.state.activeWorker.runId, worker.runId);
  assert.equal(recovery.state.retryCount, state.retryCount);
  assertAllClosed(assert, f.calls);
});

void test("native unknown orphan remains held even when session is absent", async () => {
  const f = fixture();
  const worker = {
    sessionKey: "agent:reviewer:subagent:unknown",
    runId: "run-u",
    taskId: "unknown-id",
  };
  f.kernel.observations.set("unknown-id", {
    id: "unknown-id",
    requesterSessionKey: OWNER,
    childSessionKey: worker.sessionKey,
    observationSource: "native-subagent",
    generation: 1,
    agentId: "reviewer",
    runId: worker.runId,
    status: "unknown",
  });
  const result = await __testing.reconcileOrphanedWorker(f.api, OWNER, worker);
  assert.equal(result.safe, false);
  assert.equal(result.reason, "orphan_native_outcome_unknown");
  assert.equal(f.calls.cancels.length, 0);
  assertAllClosed(assert, f.calls);
});

void test("native orphan cancellation awaits the existing owner and closes ephemeral ledgers", async () => {
  const f = fixture();
  const worker = {
    sessionKey: "agent:reviewer:subagent:orphan",
    runId: "run-o",
    taskId: "orphan-id",
  };
  f.kernel.observations.set("orphan-id", {
    id: "orphan-id",
    requesterSessionKey: OWNER,
    childSessionKey: worker.sessionKey,
    observationSource: "native-subagent",
    generation: 1,
    agentId: "reviewer",
    runId: worker.runId,
    status: "running",
  });
  const result = await __testing.reconcileOrphanedWorker(f.api, OWNER, worker);
  assert.equal(result.safe, true);
  assert.equal(result.reason, "orphan_task_cancelled");
  assert.equal(f.calls.cancels.length, 1);
  assertAllClosed(assert, f.calls);
});

void test("native cancellation error, nonacknowledgement and throw remain held despite absent session", async () => {
  for (const outcome of [
    { cancelled: false },
    { cancelled: true, error: "cleanup incomplete" },
    { killed: true },
    "throw",
  ]) {
    const f = fixture();
    const worker = {
      sessionKey: "agent:reviewer:subagent:orphan",
      runId: "run-o",
      taskId: "orphan-id",
    };
    f.kernel.observations.set("orphan-id", {
      id: "orphan-id",
      requesterSessionKey: OWNER,
      childSessionKey: worker.sessionKey,
      observationSource: "native-subagent",
      generation: 1,
      agentId: "reviewer",
      runId: worker.runId,
      status: "running",
    });
    f.hooks.cancel = () => {
      if (outcome === "throw") {
        throw new Error("unknown cancellation transport");
      }
      return outcome;
    };
    const result = await __testing.reconcileOrphanedWorker(f.api, OWNER, worker);
    assert.equal(result.safe, false);
    assert.equal(result.reason, "orphan_native_cancellation_unknown");
    assert.equal(f.calls.cancels.length, 1);
    assertAllClosed(assert, f.calls);
  }
});

void test("legacy active orphan cannot be adopted or declared cancelled from absent liveness", async () => {
  const f = fixture();
  const worker = {
    sessionKey: "agent:reviewer:subagent:legacy",
    runId: "old-run",
    taskId: "old-id",
  };
  f.kernel.observations.set("old-id", {
    id: "old-id",
    requesterSessionKey: OWNER,
    childSessionKey: worker.sessionKey,
    observationSource: "legacy-task",
    agentId: "reviewer",
    runId: worker.runId,
    status: "running",
  });
  const result = await __testing.reconcileOrphanedWorker(f.api, OWNER, worker);
  assert.equal(result.safe, false);
  assert.equal(result.reason, "orphan_legacy_cancellation_unavailable");
  assert.equal(f.calls.cancels.length, 0);
  assertAllClosed(assert, f.calls);
});

void test("async review ingestion retains merge-ready terminal semantics and explicit merge authorization", async () => {
  const f = fixture(pluginConfig({ notificationSessionKey: OWNER }));
  const claimRef = "claim:async-review";
  const flow = f.seed({
    phase: PHASE.REVIEW_WAITING,
    wait: { kind: "mergeguez_review", headSha: SHA_A, claimRef },
  }, { status: "waiting" });
  const event = {
    eventId: "review-approved",
    repo: REPO,
    prNumber: 319,
    headSha: SHA_A,
    baseSha: SHA_B,
    claimRef,
    outcome: "approved",
    reviewId: "synthetic-review",
    coverageComplete: true,
    retryAllowed: false,
    findings: [],
  };
  const result = await __testing.ingestReviewResult(f.api, f.config, event);
  const stored = get(f, flow.flowId);
  assert.equal(result.accepted, true);
  assert.equal(stored.stateJson.phase, PHASE.MERGE_READY);
  assert.equal(stored.status, "succeeded");
  assert.ok(f.calls.schedules.some((wake) => wake.message.includes("explicit")));
  assert.equal(f.calls.launches.length, 0);
  assertAllClosed(assert, f.calls);
});

void test("worker report entrypoint awaits CAS and retains worker caller identity", async () => {
  const f = fixture();
  const flow = f.seed();
  await continueFlow(f, flow.flowId);
  const worker = get(f, flow.flowId).stateJson.activeWorker;
  const tool = f.calls.tools[0].factory({ sessionKey: worker.sessionKey });
  const result = details(
    await tool.execute("report", {
      action: "report",
      flowId: flow.flowId,
      kind: "review",
      outcome: "approved",
      headSha: SHA_A,
      reviewedBaseSha: SHA_B,
      cycle: 0,
      coverageComplete: true,
      reviewId: "synthetic-worker-report",
      findings: [],
    }),
  );
  assert.equal(result.ok, true);
  assert.equal(get(f, flow.flowId).stateJson.phase, PHASE.MERGE_READY);
  assert.equal(get(f, flow.flowId).stateJson.orphanedWorker, null);
  assert.equal(f.calls.cancels.length, 1);
  assertAllClosed(assert, f.calls);
});

void test("worker waiting report binds the claim used by a later signed completion", async () => {
  const f = fixture();
  const flow = f.seed();
  await continueFlow(f, flow.flowId);
  const worker = get(f, flow.flowId).stateJson.activeWorker;
  const claimRef = "claim:worker-issued-319";
  const tool = f.calls.tools[0].factory({ sessionKey: worker.sessionKey });
  const waiting = details(await tool.execute("report", {
    action: "report",
    flowId: flow.flowId,
    kind: "review",
    outcome: "waiting_review",
    headSha: SHA_A,
    cycle: 0,
    claimRef,
  }));
  assert.equal(waiting.ok, true);
  assert.equal(get(f, flow.flowId).stateJson.wait.claimRef, claimRef);
  const old = await __testing.ingestReviewResult(f.api, f.config, {
    eventId: "review:old-worker-claim", repo: REPO, prNumber: 319, headSha: SHA_A,
    baseSha: SHA_B, claimRef: "claim:older", outcome: "approved",
    coverageComplete: true, findings: [],
  });
  assert.equal(old.reason, "stale_claim_result");
  assert.equal(get(f, flow.flowId).stateJson.phase, PHASE.REVIEW_WAITING);
  const matched = await __testing.ingestReviewResult(f.api, f.config, {
    eventId: "review:matching-worker-claim", repo: REPO, prNumber: 319, headSha: SHA_A,
    baseSha: SHA_B, claimRef, outcome: "approved", coverageComplete: true, findings: [],
  });
  assert.equal(matched.accepted, true);
  assert.equal(get(f, flow.flowId).stateJson.phase, PHASE.MERGE_READY);
  assertAllClosed(assert, f.calls);
});

void test("periodic recovery preserves a live review claim until signed completion", async () => {
  const f = fixture();
  const claimRef = "claim:pending-across-wakes";
  const flow = f.seed({
    phase: PHASE.REVIEW_WAITING,
    retryCount: 2,
    wait: {
      kind: "mergeguez_review",
      headSha: SHA_A,
      claimRef,
      since: Date.now() - 6 * 60_000,
    },
    deadlineAt: Date.now() + 30 * 60_000,
  }, { status: "waiting" });
  const initialRevision = flow.revision;
  for (let wake = 0; wake < 2; wake += 1) {
    const recovery = details(await f.tool().execute("recover", {
      action: "recover",
      flowId: flow.flowId,
    }));
    assert.equal(recovery.ok, true);
    assert.equal(recovery.recovery, "review_claim_pending");
    const current = get(f, flow.flowId);
    assert.equal(current.revision, initialRevision);
    assert.equal(current.stateJson.phase, PHASE.REVIEW_WAITING);
    assert.equal(current.stateJson.wait.claimRef, claimRef);
    assert.equal(current.stateJson.retryCount, 2);
    assert.equal(f.calls.launches.length, 0);
  }
  const stale = await __testing.ingestReviewResult(f.api, f.config, {
    eventId: "review:stale-after-wakes", repo: REPO, prNumber: 319,
    headSha: SHA_A, baseSha: SHA_B, claimRef: "claim:retired",
    outcome: "approved", coverageComplete: true, findings: [],
  });
  assert.equal(stale.reason, "stale_claim_result");
  const matching = await __testing.ingestReviewResult(f.api, f.config, {
    eventId: "review:matching-after-wakes", repo: REPO, prNumber: 319,
    headSha: SHA_A, baseSha: SHA_B, claimRef,
    outcome: "approved", coverageComplete: true, findings: [],
  });
  assert.equal(matching.accepted, true);
  assert.equal(get(f, flow.flowId).stateJson.phase, PHASE.MERGE_READY);
  assert.equal(f.calls.launches.length, 0);
  assertAllClosed(assert, f.calls);
});

void test("expired review claim blocks without starting a replacement review", () => {
  const f = fixture();
  const state = {
    ...f.seed().stateJson,
    phase: PHASE.REVIEW_WAITING,
    retryCount: 2,
    wait: { kind: "mergeguez_review", headSha: SHA_A, claimRef: "claim:expired" },
    deadlineAt: 100,
  };
  const recovered = recoverState(state, undefined, 101);
  assert.equal(recovered.state.phase, PHASE.BLOCKED);
  assert.equal(recovered.reason, "review_wait_deadline_exceeded");
  assert.equal(recovered.state.retryCount, 2);
  assert.equal(recovered.state.activeWorker, null);
});

void test("external wait without a claim blocks before accepting signed results", async () => {
  const f = fixture();
  const flow = f.seed();
  await continueFlow(f, flow.flowId);
  const worker = get(f, flow.flowId).stateJson.activeWorker;
  const tool = f.calls.tools[0].factory({ sessionKey: worker.sessionKey });
  await tool.execute("report", {
    action: "report", flowId: flow.flowId, kind: "review",
    outcome: "waiting_review", headSha: SHA_A, cycle: 0,
  });
  const state = get(f, flow.flowId).stateJson;
  assert.equal(state.phase, PHASE.BLOCKED);
  assert.equal(state.blocker, "review_claim_missing");
  assert.equal(state.mergeReady, null);
  assert.equal(f.calls.launches.length, 1);
  assertAllClosed(assert, f.calls);
});

void test("worker report cannot approve a different or unproven reviewed base", async () => {
  for (const [label, reviewedBaseSha, blocker] of [
    ["stale", SHA_A, "review_worker_reviewed_base_changed"],
    ["missing", undefined, "review_worker_reviewed_base_missing"],
  ]) {
    const f = fixture();
    const flow = f.seed();
    await continueFlow(f, flow.flowId);
    const worker = get(f, flow.flowId).stateJson.activeWorker;
    const tool = f.calls.tools[0].factory({ sessionKey: worker.sessionKey });
    const result = details(
      await tool.execute("report", {
        action: "report",
        flowId: flow.flowId,
        kind: "review",
        outcome: "approved",
        headSha: SHA_A,
        ...(reviewedBaseSha ? { reviewedBaseSha } : {}),
        cycle: 0,
        coverageComplete: true,
        reviewId: `synthetic-${label}-base-report`,
        findings: [],
      }),
    );
    assert.equal(result.ok, true);
    const state = get(f, flow.flowId).stateJson;
    assert.equal(state.phase, PHASE.BLOCKED);
    assert.equal(state.blocker, blocker);
    assert.equal(state.mergeReady, null);
    assertAllClosed(assert, f.calls);
  }
});

void test("startup queued observation and owner recovery use async bindings without running work at startup", async () => {
  const f = fixture();
  const flow = f.seed();
  await __testing.reconcileAtStartup(f.api, f.config);
  assert.equal(f.calls.launches.length, 0);
  assert.equal(f.calls.schedules.length, 1);
  const result = details(
    await f.tool().execute("recover", { action: "recover", flowId: flow.flowId }),
  );
  assert.equal(result.ok, true);
  assert.equal(f.calls.launches.length, 1);
  assertAllClosed(assert, f.calls);
});

void test("primary native observation error survives cleanup errors and every allocated binding closes", async () => {
  const f = fixture();
  const primary = new Error("native observation unavailable");
  Object.freeze(primary);
  f.hooks.operation = (_binding, name) => {
    if (name === "runs.list") {
      throw primary;
    }
  };
  f.hooks.close = (binding) => {
    binding.closed = true;
    throw Object.assign(new Error("private close failure"), { code: "close_failed" });
  };
  await assert.rejects(
    __testing.currentWorkerTask(f.api, OWNER, {
      activeWorker: { sessionKey: "agent:reviewer:subagent:x", runId: "x" },
    }),
    (error) => error === primary,
  );
  assert.deepEqual(__testing.bindingCleanupFailureCodes(primary), [
    "close_failed",
    "close_failed",
    "close_failed",
  ]);
  assertAllClosed(assert, f.calls);
});

void test("binding cleanup preserves frozen primary, attempts all owners and exposes only bounded codes", async () => {
  const primary = new Error("primary-private-payload");
  Object.freeze(primary);
  const attempted = [];
  const f = fixture();
  const owners = Array.from({ length: 11 }, (_, index) => ({
    close: async () => {
      attempted.push(index);
      throw Object.assign(new Error("private failure payload"), {
        code: index === 1 ? "unsafe text\n" : `close_${index}`,
      });
    },
  }));
  await assert.rejects(
    __testing.withTaskBindingClosure(f.api, owners, async () => {
      throw primary;
    }),
    (error) => error === primary,
  );
  assert.equal(attempted.length, 11);
  assert.equal(__testing.bindingCleanupFailureCodes(primary).length, 8);
  assert.equal(__testing.bindingCleanupFailureCodes(primary)[1], "task_binding_close_failed");
  assert.ok(!JSON.stringify(f.calls.logs).includes("private failure payload"));
});

void test("successful operation with failed binding closure fails closed", async () => {
  const f = fixture();
  let secondClosed = false;
  await assert.rejects(
    __testing.withTaskBindingClosure(
      f.api,
      [
        {
          close: async () => {
            throw Object.assign(new Error("private"), { code: "custody_close" });
          },
        },
        {
          close: async () => {
            secondClosed = true;
          },
        },
      ],
      async () => "success",
    ),
    (error) =>
      error.code === "task_binding_close_failed" &&
      __testing.bindingCleanupFailureCodes(error)[0] === "custody_close",
  );
  assert.equal(secondClosed, true);
});

void test("advertised parity validates run port and closes already allocated owners on incompatibility", async () => {
  const f = fixture();
  const original = f.api.runtime.tasks.runs.bindSession;
  let calls = 0;
  f.api.runtime.tasks.runs.bindSession = async (input) => {
    const bound = await original(input);
    if (++calls === 2) {
      delete bound.cancel;
    }
    return bound;
  };
  await assert.rejects(
    __testing.currentWorkerTask(f.api, OWNER, {
      activeWorker: { sessionKey: "agent:reviewer:subagent:x", runId: "x" },
    }),
    /publisher_run_parity_port_unavailable/,
  );
  assertAllClosed(assert, f.calls);
});

void test("compatibility guard permits parity with canonical creation and private launch disabled", () => {
  const f = fixture();
  registerMergeguezPrLifecycle(f.api);
  assert.equal(f.calls.services.length, 1);
  assert.equal(f.calls.events.length, 1);
  for (const unavailable of ["version", "parity"]) {
    const other = fixture();
    if (unavailable === "version") {
      other.api.runtime.tasks.authorityVersion = 0;
    } else {
      other.api.runtime.tasks.availability.controllerParity = false;
    }
    registerMergeguezPrLifecycle(other.api);
    assert.equal(other.calls.services.length, 0);
    assert.equal(other.calls.events.length, 0);
  }
});

void test("old installed source pin remains fail-closed on changed runtime despite enabled config", () => {
  const f = fixture(
    pluginConfig({
      expectedRuntimeSha256: "7e6cbe8ab75213049fc21f85dc5df4b2c740ac9cfd35edd1d4aadc4a92167e74",
    }),
  );
  registerMergeguezPrLifecycle(f.api);
  assert.equal(f.calls.services.length, 0);
  assert.ok(f.calls.logs.some((log) => log.message.includes("source integrity failed")));
});

void test("pure pin migration requires exact installed preimage and same path, emits no authority or config writes", () => {
  const path = "/installed/mergeguez/runtime.mjs";
  const old = "7e6cbe8ab75213049fc21f85dc5df4b2c740ac9cfd35edd1d4aadc4a92167e74";
  const config = {
    enabled: true,
    expectedRuntimePath: path,
    expectedRuntimeSha256: old,
    privateSecret: "do-not-copy",
  };
  const transition = { fromPath: path, toPath: path, fromSha256: old, toSha256: "d".repeat(64) };
  const proposal = proposeInstalledPublisherRuntimePinMigration(config, transition);
  assert.equal(proposal.applied, false);
  assert.equal(proposal.requiresPluginOwnedDoctorRelease, true);
  assert.equal(config.expectedRuntimeSha256, old);
  assert.equal("privateSecret" in proposal.patch, false);
  transition.toSha256 = "e".repeat(64);
  assert.equal(proposal.patch.expectedRuntimeSha256, "d".repeat(64));
  for (const bad of [
    { fromPath: "/different" },
    { toPath: "/relocated" },
    { fromSha256: "a".repeat(64) },
    { toSha256: old },
    { toSha256: "bad" },
  ]) {
    assert.throws(() =>
      proposeInstalledPublisherRuntimePinMigration(config, { ...transition, ...bad }),
    );
  }
  assert.throws(
    () =>
      proposeInstalledPublisherRuntimePinMigration(
        { ...config, expectedRuntimeSha256: "d".repeat(64) },
        transition,
      ),
    /preimage_mismatch/,
  );
});

void test("signed HTTP webhook retains async ingestion and authentication with no external side effects", async () => {
  const f = fixture();
  const secret = "synthetic-only";
  const body = Buffer.from(
    JSON.stringify({
      action: "opened",
      repository: { full_name: REPO },
      pull_request: {
        number: 319,
        updated_at: "2026-10-09T00:00:00Z",
        head: { sha: SHA_A, repo: { full_name: REPO } },
        base: { sha: SHA_B, ref: "dev" },
      },
    }),
  );
  const request = Readable.from([body]);
  request.method = "POST";
  request.headers = {
    "content-type": "application/json",
    "x-github-event": "pull_request",
    "x-github-delivery": "synthetic-delivery",
    "x-hub-signature-256": `sha256=${createHmac("sha256", secret).update(body).digest("hex")}`,
  };
  request.socket = { remoteAddress: "127.0.0.1" };
  let response;
  const res = {
    setHeader() {},
    end: (value) => {
      response = JSON.parse(value);
    },
  };
  await __testing.createRouteHandler({
    kind: "github",
    secret,
    ingest: (event) => __testing.ingestPullRequest(f.api, f.config, event),
  })(request, res);
  assert.equal(res.statusCode, 202);
  assert.equal(response.created, true);
  assert.equal(f.kernel.flows.size, 1);
  assertAllClosed(assert, f.calls);
});

void test("signed review ingress binds approval to reviewed base and active claim", async () => {
  const activeClaim = "claim:synthetic-review-319";
  for (const [label, baseSha, claimRef, waiting, statusCode, reason] of [
    ["matching", SHA_B, activeClaim, true, 202, undefined],
    ["missing-base", undefined, activeClaim, true, 400, undefined],
    ["stale-base", "c".repeat(40), activeClaim, true, 202, "stale_base_result"],
    ["malformed-base", "not-a-sha", activeClaim, true, 400, undefined],
    ["stale-claim", SHA_B, "claim:previous-cycle", true, 202, "stale_claim_result"],
    ["missing-claim", SHA_B, undefined, true, 400, undefined],
    ["not-waiting", SHA_B, activeClaim, false, 202, "review_claim_not_active"],
  ]) {
    const f = fixture();
    const flow = waiting
      ? f.seed({
          phase: PHASE.REVIEW_WAITING,
          wait: { kind: "mergeguez_review", headSha: SHA_A, claimRef: activeClaim },
        }, { status: "waiting" })
      : f.seed();
    const secret = "synthetic-review-only";
    const body = Buffer.from(
      JSON.stringify({
        repository: REPO,
        pullRequest: 319,
        headSha: SHA_A,
        ...(claimRef === undefined ? {} : { claimRef }),
        ...(baseSha === undefined ? {} : { baseSha }),
        outcome: "approved",
        coverageComplete: true,
        findings: [],
      }),
    );
    const request = Readable.from([body]);
    request.method = "POST";
    request.headers = {
      "content-type": "application/json",
      "x-mergeguez-event": "review.completed",
      "x-mergeguez-delivery": `synthetic-${label}`,
      "x-mergeguez-signature-256": `sha256=${createHmac("sha256", secret).update(body).digest("hex")}`,
    };
    request.socket = { remoteAddress: "127.0.0.1" };
    let response;
    const res = {
      setHeader() {},
      end: (value) => {
        response = JSON.parse(value);
      },
    };
    await __testing.createRouteHandler({
      kind: "mergeguez",
      secret,
      ingest: (event) => __testing.ingestReviewResult(f.api, f.config, event),
    })(request, res);
    assert.equal(res.statusCode, statusCode, label);
    assert.equal(response.reason, reason, label);
    const state = get(f, flow.flowId).stateJson;
    assert.equal(state.phase,
      label === "matching" ? PHASE.MERGE_READY : waiting ? PHASE.REVIEW_WAITING : PHASE.REVIEW_QUEUED,
      label);
    assertAllClosed(assert, f.calls);
  }
});

void test("controller rejects an old claim before changing a waiting review", () => {
  const f = fixture();
  const state = {
    ...f.seed().stateJson,
    phase: PHASE.REVIEW_WAITING,
    wait: { kind: "mergeguez_review", headSha: SHA_A, claimRef: "claim:current" },
  };
  const result = applyReviewResult(state, {
    eventId: "review:old-claim",
    repo: REPO,
    prNumber: 319,
    headSha: SHA_A,
    baseSha: SHA_B,
    claimRef: "claim:prior",
    outcome: "approved",
    coverageComplete: true,
    findings: [],
  });
  assert.equal(result.reason, "stale_claim_result");
  assert.equal(result.changed, false);
  assert.equal(result.state, state);
});
