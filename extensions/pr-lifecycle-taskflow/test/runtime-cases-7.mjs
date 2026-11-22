import assert from "node:assert/strict";
import test from "node:test";
import { PHASE } from "../src/controller.mjs";
import { __testing, registerPrLifecycleTaskflow } from "../src/runtime.mjs";
import {
  OWNER,
  SHA_A,
  SHA_B,
  SHA_C,
  finding,
  makeApi,
  pluginConfig,
  prEvent,
  reviewEvent,
  toolFor,
} from "./runtime-helpers-1.mjs";
import { details, launchWaitingReview, notificationCandidate } from "./runtime-helpers-2.mjs";

void test("a worker agent main-ledger task is attached to the launched worker", async () => {
  const { api, bound, calls, storeFor } = makeApi();
  api.runtime.subagent.run = async (params) => {
    calls.subagents.push(params);
    const workerMainStore = storeFor("agent:broker-review-launcher:main");
    workerMainStore.tasks.set("worker-main-task", {
      taskId: "worker-main-task",
      parentFlowId: "worker-main-flow",
      runId: "run-worker-main",
      childSessionKey: params.sessionKey,
      agentId: "broker-review-launcher",
      status: "running",
    });
    return { runId: "run-worker-main", sessionKey: params.sessionKey };
  };
  registerPrLifecycleTaskflow(api);
  const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const created = await __testing.ingestPullRequest(api, config, prEvent());
  const flow = bound.get(created.flowId);
  const output = details(
    await toolFor(calls, OWNER).execute("continue", {
      action: "continue",
      flowId: flow.flowId,
      expectedRevision: flow.revision,
    }),
  );
  assert.equal(output.flow.phase, PHASE.REVIEW_RUNNING);
  assert.equal(output.flow.activeWorker.runId, "run-worker-main");
  assert.equal(output.flow.activeWorker.taskId, "worker-main-task");
  assert.equal(output.flow.infrastructureRetryCount, 0);
  assert.equal(calls.subagents.at(-1).runTimeoutSeconds, 3600);
});

void test("owner recovery consumes immutable remediation evidence without a worker report tool", async () => {
  const { api, bound, calls } = makeApi();
  registerPrLifecycleTaskflow(api);
  const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const created = await __testing.ingestPullRequest(api, config, prEvent());
  const ownerTool = toolFor(calls, OWNER);

  let flow = bound.get(created.flowId);
  await ownerTool.execute("review-start", {
    action: "continue",
    flowId: flow.flowId,
    expectedRevision: flow.revision,
  });
  flow = bound.get(flow.flowId);
  const reviewClaimRef = flow.stateJson.activeWorker.claimRef;
  const reviewTool = toolFor(calls, flow.stateJson.activeWorker.sessionKey);
  await reviewTool.execute("review-wait", {
    action: "report",
    flowId: flow.flowId,
    kind: "review",
    outcome: "waiting_review",
    headSha: SHA_A,
    cycle: 0,
    claimRef: reviewClaimRef,
  });
  await __testing.ingestReviewResult(
    api,
    config,
    reviewEvent({
      outcome: "changes_requested",
      findings: [finding()],
      eventId: "broker:evidence-recovery",
      claimRef: reviewClaimRef,
    }),
  );
  flow = bound.get(flow.flowId);
  assert.equal(flow.stateJson.phase, PHASE.REMEDIATION_RUNNING);
  assert.equal(calls.subagents.at(-1).toolsAlsoAllow, undefined);
  assert.match(
    calls.subagents.at(-1).message,
    /controller reads and verifies the immutable host evidence directly/,
  );
  assert.doesNotMatch(calls.subagents.at(-1).message, /action=report/);

  api.testReadRemediationEvidence = () => ({
    action: "report",
    kind: "remediation",
    outcome: "fixed_and_published",
    headSha: SHA_A,
    cycle: 0,
    newHeadSha: SHA_C,
    testsPassed: true,
    publicationConfirmed: true,
    fixerModel: "primary-fixer",
    fixerAttested: true,
    fixerAttestationRef: "sha256:" + "e".repeat(64),
    profileDigest: flow.stateJson.activeWorker.profileDigest,
  });
  const output = details(
    await ownerTool.execute("recover-evidence", {
      action: "recover",
      flowId: flow.flowId,
      expectedRevision: flow.revision,
    }),
  );
  assert.equal(output.recovery, "remediation_evidence_reconciled");
  assert.equal(output.flow.phase, PHASE.WAITING_HEAD_EVENT);
  assert.equal(output.flow.headSha, SHA_A);
  assert.equal(output.flow.cycle, 0);
  assert.equal(output.flow.activeWorker, null);
  assert.equal(calls.verifiedRemediationEvidence.length, 1);

  await __testing.ingestPullRequest(
    api,
    config,
    prEvent({
      eventId: "github:evidence-head-confirmed",
      action: "synchronize",
      headSha: SHA_C,
      updatedAt: "2026-09-05T00:00:02Z",
    }),
  );
  flow = bound.get(flow.flowId);
  await ownerTool.execute("review-after-evidence", {
    action: "continue",
    flowId: flow.flowId,
    expectedRevision: flow.revision,
  });
  flow = bound.get(flow.flowId);
  assert.equal(flow.stateJson.phase, PHASE.REVIEW_RUNNING);
  assert.equal(flow.stateJson.headSha, SHA_C);
  assert.equal(flow.stateJson.cycle, 1);
});

void test("terminal remediation lifecycle evidence launches one exact-head re-review", async () => {
  const { api, bound, calls } = makeApi();
  registerPrLifecycleTaskflow(api);
  const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const created = await __testing.ingestPullRequest(api, config, prEvent());
  const ownerTool = toolFor(calls, OWNER);

  let flow = bound.get(created.flowId);
  await ownerTool.execute("review-start", {
    action: "continue",
    flowId: flow.flowId,
    expectedRevision: flow.revision,
  });
  flow = bound.get(flow.flowId);
  const reviewClaimRef = flow.stateJson.activeWorker.claimRef;
  const reviewTool = toolFor(calls, flow.stateJson.activeWorker.sessionKey);
  await reviewTool.execute("review-wait", {
    action: "report",
    flowId: flow.flowId,
    kind: "review",
    outcome: "waiting_review",
    headSha: SHA_A,
    cycle: 0,
    claimRef: reviewClaimRef,
  });
  await __testing.ingestReviewResult(
    api,
    config,
    reviewEvent({
      outcome: "changes_requested",
      findings: [finding()],
      eventId: "broker:lifecycle-evidence",
      claimRef: reviewClaimRef,
    }),
  );
  flow = bound.get(flow.flowId);
  assert.equal(flow.stateJson.phase, PHASE.REMEDIATION_RUNNING);
  const remediation = structuredClone(flow.stateJson.activeWorker);

  api.testReadRemediationEvidence = () => ({
    action: "report",
    kind: "remediation",
    outcome: "fixed_and_published",
    headSha: SHA_A,
    cycle: 0,
    newHeadSha: SHA_C,
    testsPassed: true,
    publicationConfirmed: true,
    fixerModel: "primary-fixer",
    fixerAttested: true,
    fixerAttestationRef: "sha256:" + "f".repeat(64),
    profileDigest: remediation.profileDigest,
  });
  assert.equal(calls.agentEventSubscriptions.length, 1);
  const subscription = calls.agentEventSubscriptions[0];
  await subscription.handle({
    runId: remediation.runId,
    sessionKey: remediation.sessionKey,
    stream: "lifecycle",
    data: { phase: "end" },
  });
  flow = bound.get(flow.flowId);
  assert.equal(flow.stateJson.phase, PHASE.WAITING_HEAD_EVENT);
  assert.equal(flow.stateJson.headSha, SHA_A);
  assert.equal(flow.stateJson.cycle, 0);
  assert.equal(flow.stateJson.activeWorker, null);
  assert.equal(calls.subagents.length, 2);

  await __testing.ingestPullRequest(
    api,
    config,
    prEvent({
      eventId: "github:lifecycle-head-confirmed",
      action: "synchronize",
      headSha: SHA_C,
      updatedAt: "2026-09-05T00:00:02Z",
    }),
  );
  flow = bound.get(flow.flowId);
  await ownerTool.execute("review-after-terminal-evidence", {
    action: "continue",
    flowId: flow.flowId,
    expectedRevision: flow.revision,
  });
  flow = bound.get(flow.flowId);
  assert.equal(flow.stateJson.phase, PHASE.REVIEW_RUNNING);
  assert.equal(flow.stateJson.headSha, SHA_C);
  assert.equal(flow.stateJson.cycle, 1);
  assert.equal(flow.stateJson.activeWorker.kind, "review");
  assert.equal(calls.subagents.length, 3);

  await subscription.handle({
    runId: remediation.runId,
    sessionKey: remediation.sessionKey,
    stream: "lifecycle",
    data: { phase: "end" },
  });
  assert.equal(calls.subagents.length, 3);
});

void test("terminal review infrastructure failure schedules one bounded retry without polling", async () => {
  const { api, bound, calls } = makeApi();
  registerPrLifecycleTaskflow(api);
  const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const created = await __testing.ingestPullRequest(api, config, prEvent());
  const ownerTool = toolFor(calls, OWNER);
  let flow = bound.get(created.flowId);
  await ownerTool.execute("review-start", {
    action: "continue",
    flowId: flow.flowId,
    expectedRevision: flow.revision,
  });
  flow = bound.get(flow.flowId);
  const worker = structuredClone(flow.stateJson.activeWorker);
  const subscription = calls.agentEventSubscriptions[0];
  const schedulesBefore = calls.schedules.length;

  await subscription.handle({
    runId: worker.runId,
    sessionKey: worker.sessionKey,
    stream: "lifecycle",
    data: { phase: "error", error: "gateway restart" },
  });
  flow = bound.get(flow.flowId);
  assert.equal(flow.stateJson.phase, PHASE.REVIEW_QUEUED);
  assert.equal(flow.stateJson.activeWorker, null);
  assert.equal(flow.stateJson.infrastructureRetryCount, 1);
  assert.match(flow.stateJson.infrastructureLastFailure, /gateway restart/);
  assert.equal(calls.schedules.length, schedulesBefore + 1);
  assert.equal(calls.schedules.at(-1).deliveryMode, "none");
  assert.match(calls.schedules.at(-1).message, /Do not perform repository work/);

  await subscription.handle({
    runId: worker.runId,
    sessionKey: worker.sessionKey,
    stream: "lifecycle",
    data: { phase: "error", error: "gateway restart" },
  });
  assert.equal(calls.schedules.length, schedulesBefore + 1);
  assert.equal(calls.subagents.length, 1);
});

void test("owner admit reopens cycle budget only after the configured limit increases", async () => {
  const { api, bound, calls } = makeApi();
  api.pluginConfig.repositories["example-org/example-repo"].maxCycles = 1;
  registerPrLifecycleTaskflow(api);
  const initialConfig = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const created = await __testing.ingestPullRequest(api, initialConfig, prEvent());
  const stored = bound.flows.get(created.flowId);
  stored.status = "blocked";
  stored.stateJson = {
    ...stored.stateJson,
    phase: PHASE.BLOCKED,
    blocker: "review_fix_cycle_budget_exhausted",
    wait: { kind: "manual_intervention", since: 1 },
    activeWorker: null,
    cycle: 1,
    maxCycles: 1,
    workerGeneration: 4,
    findings: [finding()],
  };

  const unchanged = await __testing.ingestPullRequest(
    api,
    initialConfig,
    prEvent({
      eventId: "owner-admit:cycle-budget-unchanged",
      action: "synchronize",
    }),
  );
  assert.equal(unchanged.reason, "owner_admit_policy_refreshed");
  assert.equal(bound.get(created.flowId).stateJson.phase, PHASE.BLOCKED);
  assert.equal(bound.get(created.flowId).stateJson.blocker, "review_fix_cycle_budget_exhausted");

  api.pluginConfig.repositories["example-org/example-repo"].maxCycles = 2;
  const expandedConfig = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const reopened = await __testing.ingestPullRequest(
    api,
    expandedConfig,
    prEvent({
      eventId: "owner-admit:cycle-budget-expanded",
      action: "synchronize",
    }),
  );
  assert.equal(reopened.reason, "owner_admit_reopen_cycle_budget");
  const flow = bound.get(created.flowId);
  assert.equal(flow.stateJson.phase, PHASE.REMEDIATION_QUEUED);
  assert.equal(flow.stateJson.maxCycles, 2);
  assert.equal(flow.stateJson.cycle, 1);
  assert.equal(flow.stateJson.workerGeneration, 5);
  assert.equal(flow.stateJson.blocker, null);
  assert.equal(flow.stateJson.retryCount, 0);
  assert.equal(flow.stateJson.activeWorker, null);
  assert.equal(calls.schedules.at(-1).tag.startsWith("mprl-"), true);
});

void test("owner admit requeues a worker completed without a structured report as infrastructure", async () => {
  const { api, bound, calls } = makeApi();
  registerPrLifecycleTaskflow(api);
  const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const created = await __testing.ingestPullRequest(api, config, prEvent());
  const stored = bound.flows.get(created.flowId);
  stored.status = "blocked";
  stored.stateJson = {
    ...stored.stateJson,
    phase: PHASE.BLOCKED,
    blocker: "worker_completed_without_structured_report",
    wait: { kind: "manual_intervention", since: 1 },
    activeWorker: null,
    retryCount: 0,
    workerGeneration: 4,
  };
  const admitted = details(
    await toolFor(calls, OWNER).execute("admit-unstructured-completion-reopen", {
      action: "admit",
      repo: "example-org/example-repo",
      prNumber: 42,
      headSha: SHA_A,
      baseSha: SHA_B,
      baseRef: "dev",
    }),
  );
  assert.equal(admitted.admit.reason, "owner_admit_requeue_infrastructure_failure");
  const flow = bound.get(created.flowId);
  assert.equal(flow.stateJson.phase, PHASE.REVIEW_QUEUED);
  assert.equal(flow.stateJson.retryCount, 0);
  assert.equal(flow.stateJson.workerGeneration, 4);
  assert.equal(flow.stateJson.infrastructureRetryCount, 1);
  assert.ok(flow.stateJson.infrastructureRetryAt > Date.now());
  assert.equal(flow.stateJson.blocker, null);
});

void test("owner admit reopens unusable findings into review_queued only", async () => {
  const { api, bound, calls } = makeApi();
  registerPrLifecycleTaskflow(api);
  const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const created = await __testing.ingestPullRequest(api, config, prEvent());
  const stored = bound.flows.get(created.flowId);
  stored.status = "blocked";
  stored.stateJson = {
    ...stored.stateJson,
    phase: PHASE.BLOCKED,
    blocker: "findings_unusable",
    wait: { kind: "manual_intervention", since: 1 },
    activeWorker: null,
    workerGeneration: 5,
    deadlineAt: Date.now() - 1,
    review: {
      reviewId: null,
      headSha: SHA_A,
      outcome: "changes_requested",
      coverageComplete: true,
      findingsCount: 1,
      summary: "2 blocking findings",
      observedAt: 1,
    },
    findings: [{ id: "finding-1", severity: "high", summary: "2 blocking findings" }],
  };
  const admitted = details(
    await toolFor(calls, OWNER).execute("admit-unusable-findings-reopen", {
      action: "admit",
      repo: "example-org/example-repo",
      prNumber: 42,
      headSha: SHA_A,
      baseSha: SHA_B,
      baseRef: "dev",
    }),
  );
  assert.equal(admitted.admit.reason, "owner_admit_reopen_unusable_findings");
  const flow = bound.get(created.flowId);
  assert.equal(flow.stateJson.phase, PHASE.REVIEW_QUEUED);
  assert.equal(flow.stateJson.blocker, null);
  assert.equal(flow.stateJson.review, null);
  assert.deepEqual(flow.stateJson.findings, []);
  assert.equal(flow.stateJson.workerGeneration, 6);
  assert.equal(flow.stateJson.activeWorker, null);
  assert.ok(flow.stateJson.deadlineAt > Date.now());
});

void test("owner admit reopens pathless changes_requested into review_queued only", async () => {
  const { api, bound, calls } = makeApi();
  registerPrLifecycleTaskflow(api);
  const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const created = await __testing.ingestPullRequest(api, config, prEvent());
  const stored = bound.flows.get(created.flowId);
  stored.status = "blocked";
  stored.stateJson = {
    ...stored.stateJson,
    phase: PHASE.BLOCKED,
    blocker: "changes_requested_without_actionable_paths",
    wait: { kind: "manual_intervention", since: 1 },
    activeWorker: null,
    workerGeneration: 3,
    findings: [{ id: "finding-1", severity: "high", summary: "count-only" }],
  };
  const admitted = details(
    await toolFor(calls, OWNER).execute("admit-pathless-changes-reopen", {
      action: "admit",
      repo: "example-org/example-repo",
      prNumber: 42,
      headSha: SHA_A,
      baseSha: SHA_B,
      baseRef: "dev",
    }),
  );
  assert.equal(admitted.admit.reason, "owner_admit_reopen_unusable_findings");
  const flow = bound.get(created.flowId);
  assert.equal(flow.stateJson.phase, PHASE.REVIEW_QUEUED);
  assert.deepEqual(flow.stateJson.findings, []);
  assert.notEqual(flow.stateJson.phase, PHASE.REMEDIATION_QUEUED);
});

void test("owner admit reopens a wall-time budget block without a dummy head", async () => {
  const { api, bound, calls } = makeApi();
  registerPrLifecycleTaskflow(api);
  const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const created = await __testing.ingestPullRequest(api, config, prEvent());
  const stored = bound.flows.get(created.flowId);
  stored.status = "blocked";
  stored.stateJson = {
    ...stored.stateJson,
    phase: PHASE.BLOCKED,
    blocker: "wall_time_budget_exhausted",
    wait: { kind: "manual_intervention", since: 1 },
    activeWorker: null,
    workerGeneration: 2,
    deadlineAt: Date.now() - 1,
  };
  const admitted = details(
    await toolFor(calls, OWNER).execute("admit-wall-time-reopen", {
      action: "admit",
      repo: "example-org/example-repo",
      prNumber: 42,
      headSha: SHA_A,
      baseSha: SHA_B,
      baseRef: "dev",
    }),
  );
  assert.equal(admitted.admit.reason, "owner_admit_reopen_wall_time_budget");
  const flow = bound.get(created.flowId);
  assert.equal(flow.stateJson.phase, PHASE.REVIEW_QUEUED);
  assert.equal(flow.stateJson.blocker, null);
  assert.equal(flow.stateJson.workerGeneration, 3);
  assert.equal(flow.stateJson.activeWorker, null);
  assert.ok(flow.stateJson.deadlineAt > Date.now());
});

void test("continue cannot bypass an expired absolute wall-time deadline", async () => {
  const { api, bound, calls } = makeApi();
  registerPrLifecycleTaskflow(api);
  const tool = toolFor(calls, OWNER);
  const admitted = details(
    await tool.execute("admit-idle", {
      action: "admit",
      repo: "example-org/example-repo",
      prNumber: 42,
      headSha: SHA_A,
      baseSha: SHA_B,
      baseRef: "dev",
    }),
  );
  bound.flows.get(admitted.admit.flowId).stateJson.deadlineAt = Date.now() - 1;
  const continued = details(
    await tool.execute("continue-idle", {
      action: "continue",
      flowId: admitted.admit.flowId,
      expectedRevision: admitted.admit.revision,
    }),
  );
  assert.equal(continued.flow.phase, PHASE.BLOCKED);
  assert.equal(continued.flow.blocker, "wall_time_budget_exhausted");
  assert.equal(calls.subagents.length, 0);
});

void test("continue persists a blocked reservation instead of launching a worker", async () => {
  const { api, bound, calls } = makeApi();
  registerPrLifecycleTaskflow(api);
  const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const created = await __testing.ingestPullRequest(api, config, prEvent());
  const stored = bound.flows.get(created.flowId);
  stored.stateJson = {
    ...stored.stateJson,
    phase: PHASE.REMEDIATION_QUEUED,
    cycle: 2,
    maxCycles: 2,
    findings: [finding()],
    activeWorker: null,
    blocker: null,
  };
  const continued = details(
    await toolFor(calls, OWNER).execute("continue-blocked-reserve", {
      action: "continue",
      flowId: created.flowId,
      expectedRevision: stored.revision,
    }),
  );
  assert.equal(continued.flow.phase, PHASE.BLOCKED);
  assert.equal(continued.flow.blocker, "review_fix_cycle_budget_exhausted");
  assert.equal(continued.flow.activeWorker, null);
  assert.equal(calls.subagents.length, 0);
});

void test("revision-fenced notifications drop stale progress and safely replay a terminal outcome", async () => {
  const { api, bound, calls } = makeApi(pluginConfig({ notificationSessionKey: OWNER }));
  registerPrLifecycleTaskflow(api);
  const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const created = await __testing.ingestPullRequest(api, config, prEvent());
  const waiting = await launchWaitingReview(bound, calls, created.flowId);
  await __testing.ingestReviewResult(
    api,
    config,
    reviewEvent({ claimRef: waiting.stateJson.reviewLease.claimRef }),
  );
  const stale = bound.get(created.flowId);
  assert.equal(stale.stateJson.phase, PHASE.MERGE_READY);
  assert.equal(stale.stateJson.prEffects, "review_published");
  assert.equal(stale.stateJson.latestExternalMilestone.observedRevision, stale.revision);
  const staleCandidate = {
    action: "notify",
    flowId: stale.flowId,
    expectedRevision: stale.revision,
    headSha: stale.stateJson.headSha,
    phase: stale.stateJson.phase,
    notificationKind: "approval_gate",
    notificationEventId:
      `mprn:${stale.flowId}:${stale.revision}:${stale.stateJson.headSha}:` +
      `${stale.stateJson.phase}:approval_gate`,
  };

  await __testing.ingestPullRequest(
    api,
    config,
    prEvent({
      eventId: "github:new-head-after-approval",
      action: "synchronize",
      headSha: SHA_C,
      updatedAt: "2026-09-05T00:00:02Z",
    }),
  );
  api.testReadWorkspaceHead = async () => SHA_A;
  api.__testReadWorkspaceHead = async () => SHA_A;
  let current = bound.get(created.flowId);
  const sinkTool = toolFor(calls, OWNER);
  await sinkTool.execute("block-new-head", {
    action: "continue",
    flowId: current.flowId,
    expectedRevision: current.revision,
  });
  current = bound.get(created.flowId);
  assert.equal(current.stateJson.phase, PHASE.BLOCKED);
  assert.equal(current.stateJson.prEffects, "none");
  assert.equal(current.stateJson.externalMilestoneHistory.at(-1).kind, "review_published");
  assert.ok(current.stateJson.externalMilestoneHistory.at(-1).supersededAt);
  const status = details(
    await sinkTool.execute("status-after-block", { action: "status", flowId: current.flowId }),
  );
  assert.equal(status.controlPlaneProgress.revision, current.revision);
  assert.equal(status.controlPlaneProgress.phase, PHASE.BLOCKED);
  assert.equal(status.prEffects, "none");
  assert.equal(status.latestExternalMilestone, null);

  const dropped = details(await sinkTool.execute("stale-notification", staleCandidate));
  assert.equal(dropped.deliver, false);
  assert.equal(dropped.superseded, true);
  const terminalCandidate = {
    action: "notify",
    flowId: current.flowId,
    expectedRevision: current.revision,
    headSha: current.stateJson.headSha,
    phase: current.stateJson.phase,
    notificationKind: "blocked",
    notificationEventId:
      `mprn:${current.flowId}:${current.revision}:${current.stateJson.headSha}:` +
      `${current.stateJson.phase}:blocked`,
  };
  const delivered = details(await sinkTool.execute("terminal-notification", terminalCandidate));
  assert.equal(delivered.deliver, true);
  assert.match(delivered.message, /blocked at exact head/);
  const replay = details(await sinkTool.execute("terminal-notification-replay", terminalCandidate));
  assert.equal(replay.deliver, true);
  assert.equal(replay.retry, true);
  assert.equal(replay.eventId, delivered.eventId);
  assert.equal(replay.message, delivered.message);
  const attempts = bound.get(created.flowId).stateJson.notificationDeliveries;
  assert.equal(attempts.length, 1);
  assert.equal(attempts[0].deliveryState, "pending");
});

void test("notify rejects a forged merged announcement in merge_ready", async () => {
  const { api, bound, calls } = makeApi(pluginConfig({ notificationSessionKey: OWNER }));
  registerPrLifecycleTaskflow(api);
  const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const created = await __testing.ingestPullRequest(api, config, prEvent());
  const waiting = await launchWaitingReview(bound, calls, created.flowId);
  await __testing.ingestReviewResult(
    api,
    config,
    reviewEvent({ claimRef: waiting.stateJson.reviewLease.claimRef }),
  );
  const ready = bound.get(created.flowId);
  assert.equal(ready.stateJson.phase, PHASE.MERGE_READY);
  const sinkTool = toolFor(calls, OWNER);

  await assert.rejects(
    () => sinkTool.execute("forged-merged-in-merge-ready", notificationCandidate(ready, "merged")),
    /notification_kind_phase_mismatch/,
  );
  await assert.rejects(
    () => sinkTool.execute("blocked-in-merge-ready", notificationCandidate(ready, "blocked")),
    /notification_kind_phase_mismatch/,
  );
  await assert.rejects(
    () => sinkTool.execute("check-wait-in-merge-ready", notificationCandidate(ready, "check_wait")),
    /notification_kind_phase_mismatch/,
  );
  assert.deepEqual(bound.get(created.flowId).stateJson.notificationDeliveries, []);

  const delivered = details(
    await sinkTool.execute(
      "approval-gate-in-merge-ready",
      notificationCandidate(ready, "approval_gate"),
    ),
  );
  assert.equal(delivered.deliver, true);
  assert.match(delivered.message, /is merge-ready at exact head/);
  const recorded = bound.get(created.flowId).stateJson.notificationDeliveries;
  assert.equal(recorded.length, 1);
  assert.equal(recorded[0].kind, "approval_gate");
  assert.equal(recorded[0].phase, PHASE.MERGE_READY);
  assert.equal(recorded[0].deliveryState, "pending");
  assert.equal(recorded[0].confirmedAt, undefined);
});
