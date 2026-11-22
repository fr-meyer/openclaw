import assert from "node:assert/strict";
import test from "node:test";
import { PHASE, mergePolicyDigest, normalizePolicy } from "../src/controller.mjs";
import { __testing, registerPrLifecycleTaskflow } from "../src/runtime.mjs";
import {
  OWNER,
  SHA_A,
  SHA_B,
  SHA_C,
  authorizedAutoMergePolicy,
  finding,
  makeApi,
  mergeAuthorization,
  pluginConfig,
  prEvent,
  reviewEvent,
  taskflowGateReceipt,
  toolFor,
} from "./runtime-helpers-1.mjs";
import {
  admitAndStartReview,
  bindQueuedReview,
  details,
  launchWaitingReview,
  ownerAuthorizeAndContinue,
} from "./runtime-helpers-2.mjs";

test("old-head review completion releases the retained lease after synchronize", async () => {
  const { api, bound, calls } = makeApi();
  registerPrLifecycleTaskflow(api);
  const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const created = await __testing.ingestPullRequest(api, config, prEvent());
  const waiting = await launchWaitingReview(bound, calls, created.flowId);
  const claimRef = waiting.stateJson.reviewLease.claimRef;
  await __testing.ingestPullRequest(
    api,
    config,
    prEvent({
      eventId: "github:event-2",
      action: "synchronize",
      headSha: SHA_C,
      updatedAt: "2026-09-05T00:00:02Z",
    }),
  );
  let flow = bound.get(created.flowId);
  assert.equal(flow.stateJson.headSha, SHA_C);
  assert.equal(flow.stateJson.reviewLease.headSha, SHA_A);
  const released = await __testing.ingestReviewResult(
    api,
    config,
    reviewEvent({
      eventId: "broker:old-head",
      headSha: SHA_A,
      claimRef,
    }),
  );
  assert.equal(released.accepted, true);
  flow = bound.get(created.flowId);
  assert.equal(flow.stateJson.reviewLease, null);
  assert.equal(flow.stateJson.headSha, SHA_C);
  assert.equal(flow.stateJson.phase, PHASE.REVIEW_QUEUED);
});

test("dogfood mode permits review but blocks live remediation", async () => {
  const dogfood = pluginConfig({
    repositories: {
      "example-org/example-repo": {
        ...pluginConfig().repositories["example-org/example-repo"],
        mode: "dogfood",
      },
    },
  });
  const { api, bound, calls } = makeApi(dogfood);
  const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const created = await __testing.ingestPullRequest(api, config, prEvent());
  const claimRef = bindQueuedReview(bound, created.flowId);
  await __testing.ingestReviewResult(
    api,
    config,
    reviewEvent({ outcome: "changes_requested", findings: [finding()], claimRef }),
  );
  const flow = bound.get(created.flowId);
  assert.equal(flow.status, "blocked");
  assert.equal(flow.stateJson.phase, PHASE.BLOCKED);
  assert.match(flow.stateJson.blocker, /live_remediation_not_enabled/);
  assert.equal(calls.schedules.length, 1);
  assert.equal(calls.unschedules.at(-1).tag.startsWith("mprl-"), true);
});

test("active mode blocks remediation until the Author worker publisher is attested", async () => {
  const repository = {
    ...pluginConfig().repositories["example-org/example-repo"],
  };
  delete repository.publisherBrokerId;
  delete repository.publisherAttestationRef;
  const { api, bound, calls } = makeApi(
    pluginConfig({
      repositories: { "example-org/example-repo": repository },
    }),
  );
  const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const created = await __testing.ingestPullRequest(api, config, prEvent());
  const claimRef = bindQueuedReview(bound, created.flowId);
  await __testing.ingestReviewResult(
    api,
    config,
    reviewEvent({ outcome: "changes_requested", findings: [finding()], claimRef }),
  );
  const flow = bound.get(created.flowId);
  assert.equal(flow.stateJson.phase, PHASE.BLOCKED);
  assert.equal(flow.stateJson.blocker, "publisher_not_attested");
  assert.equal(flow.stateJson.publisherBoundary.ready, false);
  assert.equal(calls.subagents.length, 0);
});

test("owner admit reopens a publisher block only after attestation is configured", async () => {
  const repository = {
    ...pluginConfig().repositories["example-org/example-repo"],
  };
  delete repository.publisherBrokerId;
  delete repository.publisherAttestationRef;
  const raw = pluginConfig({ repositories: { "example-org/example-repo": repository } });
  const { api, bound } = makeApi(raw);
  const unattestedConfig = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const created = await __testing.ingestPullRequest(api, unattestedConfig, prEvent());
  const claimRef = bindQueuedReview(bound, created.flowId);
  await __testing.ingestReviewResult(
    api,
    unattestedConfig,
    reviewEvent({ outcome: "changes_requested", findings: [finding()], claimRef }),
  );
  raw.repositories["example-org/example-repo"].publisherBrokerId = "attested-broker/v1";
  raw.repositories["example-org/example-repo"].publisherAttestationRef =
    "proof:live-boundary-readback";
  const attestedConfig = __testing.normalizeRuntimeConfig(raw);
  const reopened = await __testing.ingestPullRequest(
    api,
    attestedConfig,
    prEvent({ eventId: "owner-admit:publisher-ready", action: "synchronize" }),
  );
  assert.equal(reopened.reason, "owner_admit_reopen_attested_publisher");
  const flow = bound.get(created.flowId);
  assert.equal(flow.stateJson.phase, PHASE.REMEDIATION_QUEUED);
  assert.equal(flow.stateJson.publisherBoundary.ready, true);
  assert.equal(flow.stateJson.publisherBoundary.brokerId, "attested-broker/v1");
});

test("active policy reopens a dogfood remediation block", async () => {
  const dogfood = pluginConfig({
    repositories: {
      "example-org/example-repo": {
        ...pluginConfig().repositories["example-org/example-repo"],
        mode: "dogfood",
      },
    },
  });
  const { api, bound, calls } = makeApi(dogfood);
  const dogfoodConfig = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const created = await __testing.ingestPullRequest(api, dogfoodConfig, prEvent());
  const claimRef = bindQueuedReview(bound, created.flowId);
  await __testing.ingestReviewResult(
    api,
    dogfoodConfig,
    reviewEvent({ outcome: "changes_requested", findings: [finding()], claimRef }),
  );
  assert.equal(bound.get(created.flowId).stateJson.phase, PHASE.BLOCKED);
  api.pluginConfig.repositories["example-org/example-repo"].mode = "active";
  const activeConfig = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const reopened = await __testing.ingestPullRequest(
    api,
    activeConfig,
    prEvent({ eventId: "github:event-2", action: "synchronize" }),
  );
  assert.equal(reopened.reason, "active_mode_reopen_dogfood_block");
  const flow = bound.get(created.flowId);
  assert.equal(flow.stateJson.mode, "active");
  assert.equal(flow.stateJson.phase, PHASE.REMEDIATION_QUEUED);
  assert.equal(flow.stateJson.blocker, null);
  assert.equal(calls.schedules.at(-1).tag.startsWith("mprl-"), true);
});

test("owner authorize revision-fences post-review merge authorization", async () => {
  const repositoryPolicy = {
    ...pluginConfig().repositories["example-org/example-repo"],
    autoMergeBaseBranches: ["dev"],
  };
  const configInput = pluginConfig({
    repositories: { "example-org/example-repo": repositoryPolicy },
  });
  const { api, bound, calls } = makeApi(configInput);
  const initialConfig = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const created = await __testing.ingestPullRequest(api, initialConfig, prEvent());
  const claimRef = bindQueuedReview(bound, created.flowId);
  await __testing.ingestReviewResult(api, initialConfig, reviewEvent({ claimRef }));
  const ready = bound.get(created.flowId);
  assert.equal(ready.stateJson.phase, PHASE.MERGE_READY);
  assert.equal(ready.stateJson.mergeAuthorization, null);

  const authorizedPolicy = { ...repositoryPolicy };
  authorizedPolicy.mergeAuthorization = mergeAuthorization({
    policyDigest: mergePolicyDigest(normalizePolicy(authorizedPolicy), "example-org/example-repo"),
  });
  api.pluginConfig.repositories["example-org/example-repo"] = authorizedPolicy;
  calls.schedules.length = 0;
  registerPrLifecycleTaskflow(api);
  const authorizationInput = {
    action: "authorize",
    flowId: ready.flowId,
    expectedRevision: ready.revision,
  };
  await assert.rejects(
    () => toolFor(calls, "agent:intruder:main").execute("authorize-denied", authorizationInput),
    /controller_action_requires_owner_session/,
  );
  await assert.rejects(
    () =>
      toolFor(calls, OWNER).execute("authorize-unfenced", {
        action: "authorize",
        flowId: ready.flowId,
      }),
    /merge_authorization_requires_expected_revision/,
  );
  const stale = details(
    await toolFor(calls, OWNER).execute("authorize-stale", {
      ...authorizationInput,
      expectedRevision: ready.revision - 1,
    }),
  );
  assert.equal(stale.staleWake, true);
  assert.equal(bound.get(created.flowId).stateJson.phase, PHASE.MERGE_READY);

  const queued = details(
    await toolFor(calls, OWNER).execute("authorize-exact", authorizationInput),
  );
  assert.equal(queued.authorization, "owner_authorized_merge_queued");
  assert.equal(queued.queued, true);
  assert.equal(queued.flow.phase, PHASE.MERGE_QUEUED);
  assert.equal(queued.flow.status, "running");
  assert.equal(
    queued.flow.mergeAuthorization.digest,
    bound.get(created.flowId).stateJson.mergeReady.authorizationDigest,
  );
  assert.equal(calls.schedules.length, 1);
  assert.match(calls.schedules[0].message, /"action":"continue"/);
});

test("owner admit refreshes a stale live policy snapshot and deadline", async () => {
  const { api, bound, calls } = makeApi();
  registerPrLifecycleTaskflow(api);
  const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const created = await __testing.ingestPullRequest(api, config, prEvent());
  const stored = bound.flows.get(created.flowId);
  stored.stateJson = {
    ...stored.stateJson,
    mode: "observe",
    maxCycles: 1,
    maxRetries: 0,
    wallTimeMinutes: 60,
    deadlineAt: Date.now() - 1,
    fixerModel: null,
    fixerFallbackModel: null,
  };
  const before = Date.now();
  const admitted = details(
    await toolFor(calls, OWNER).execute("admit-refresh", {
      action: "admit",
      repo: "example-org/example-repo",
      prNumber: 42,
      headSha: SHA_A,
      baseSha: SHA_B,
      baseRef: "dev",
    }),
  );
  const refreshed = bound.get(created.flowId).stateJson;
  assert.equal(admitted.admit.reason, "owner_admit_policy_refreshed");
  assert.equal(refreshed.mode, "active");
  assert.equal(refreshed.maxCycles, 2);
  assert.equal(refreshed.maxRetries, 2);
  assert.equal(refreshed.wallTimeMinutes, 120);
  assert.equal(refreshed.fixerModel, "primary-fixer");
  assert.ok(refreshed.deadlineAt >= before + 120 * 60_000);
});

test("owner admit requeues an exhausted infrastructure failure with bounded backoff", async () => {
  const { api, bound, calls } = makeApi();
  registerPrLifecycleTaskflow(api);
  const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const created = await __testing.ingestPullRequest(api, config, prEvent());
  const stored = bound.flows.get(created.flowId);
  stored.status = "blocked";
  stored.stateJson = {
    ...stored.stateJson,
    phase: PHASE.BLOCKED,
    blocker:
      "worker_failure_exhausted:task_link_failed:Task backing ownership could not be verified.",
    wait: { kind: "manual_intervention", since: 1 },
    activeWorker: null,
    retryCount: 1,
  };
  const tool = toolFor(calls, OWNER);
  const admitted = details(
    await tool.execute("admit-reopen", {
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
  assert.equal(flow.stateJson.blocker, null);
  assert.equal(flow.stateJson.retryCount, 0);
  assert.equal(flow.stateJson.infrastructureRetryCount, 1);
  assert.ok(flow.stateJson.infrastructureRetryAt > Date.now());
});

test("owner admit explicitly reopens an exhausted content failure", async () => {
  const { api, bound, calls } = makeApi();
  registerPrLifecycleTaskflow(api);
  const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const created = await __testing.ingestPullRequest(api, config, prEvent());
  const stored = bound.flows.get(created.flowId);
  stored.status = "blocked";
  stored.stateJson = {
    ...stored.stateJson,
    phase: PHASE.BLOCKED,
    blocker: "worker_failure_exhausted:validation_failed",
    wait: { kind: "manual_intervention", since: 1 },
    activeWorker: null,
    retryCount: 2,
  };
  const admitted = details(
    await toolFor(calls, OWNER).execute("admit-content-reopen", {
      action: "admit",
      repo: "example-org/example-repo",
      prNumber: 42,
      headSha: SHA_A,
      baseSha: SHA_B,
      baseRef: "dev",
    }),
  );
  assert.equal(admitted.admit.reason, "owner_admit_reopen_worker_failure");
  const flow = bound.get(created.flowId);
  assert.equal(flow.stateJson.phase, PHASE.REVIEW_QUEUED);
  assert.equal(flow.stateJson.retryCount, 0);
  assert.equal(flow.stateJson.blocker, null);
});

test("owner admit starts an active review worker after continue", async () => {
  const { api, bound, calls } = makeApi();
  registerPrLifecycleTaskflow(api);
  const tool = toolFor(calls, OWNER);
  const admitted = details(
    await tool.execute("admit-1", {
      action: "admit",
      repo: "example-org/example-repo",
      prNumber: 42,
      headSha: SHA_A,
      baseSha: SHA_B,
      baseRef: "dev",
    }),
  );
  assert.equal(admitted.ok, true);
  assert.equal(admitted.admit.created, true);
  const continued = details(
    await tool.execute("continue-1", {
      action: "continue",
      flowId: admitted.admit.flowId,
      expectedRevision: admitted.admit.revision,
    }),
  );
  assert.equal(continued.flow.phase, PHASE.REVIEW_RUNNING);
  assert.equal(continued.flow.activeWorker.kind, "review");
  assert.equal(bound.get(admitted.admit.flowId).stateJson.mode, "active");
});

test("observe mode records state without starting or scheduling workers", async () => {
  const observe = pluginConfig({
    repositories: {
      "example-org/example-repo": {
        ...pluginConfig().repositories["example-org/example-repo"],
        mode: "observe",
      },
    },
  });
  const { api, bound, calls } = makeApi(observe);
  const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const created = await __testing.ingestPullRequest(api, config, prEvent());
  assert.equal(bound.get(created.flowId).stateJson.phase, PHASE.REVIEW_QUEUED);
  assert.equal(calls.schedules.length, 0);
  assert.equal(calls.subagents.length, 0);
});

test("startup reconciliation uses bounded scheduled wakes rather than polling loops", async () => {
  const { api, calls } = makeApi();
  const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
  await __testing.ingestPullRequest(api, config, prEvent());
  calls.schedules.length = 0;
  calls.unschedules.length = 0;
  await __testing.reconcileAtStartup(api, config);
  assert.equal(calls.schedules.length, 1);
  assert.equal(calls.schedules[0].delayMs, 1_000);
  assert.equal(calls.schedules[0].deleteAfterRun, true);
  assert.equal(calls.schedules[0].deliveryMode, "none");
});

test("restart migrates legacy merge-ready state and permits authorization and merge", async () => {
  const repositoryPolicy = authorizedAutoMergePolicy();
  const { api, bound, calls } = makeApi(
    pluginConfig({ repositories: { "example-org/example-repo": repositoryPolicy } }),
  );
  api.testRunBroker = async (args) => {
    if (args[0] === "pr-state") {
      return {
        repo: "example-org/example-repo",
        state: "open",
        merged: false,
        draft: false,
        mergeable: true,
        base: { ref: "dev", sha: SHA_B, repo: "example-org/example-repo" },
        head: { ref: "feat/example", sha: SHA_A, repo: "example-org/example-repo" },
        checks: {
          ready: true,
          check_runs: [
            {
              name: "Broker review",
              app: "broker",
              status: "completed",
              conclusion: "success",
            },
          ],
        },
        reviewers: {
          broker_review: {
            status: "approved",
            coverage_complete: true,
            reviewed_base_sha: SHA_B,
            reviewed_head_sha: SHA_A,
            findings_count: 0,
            blocking_findings_count: 0,
          },
        },
      };
    }
    return {
      repo: "example-org/example-repo",
      number: 42,
      merged: true,
      base: "dev",
      head_sha: SHA_A,
      sha: SHA_C,
      actor_verification: "passed",
      merged_by: { login: "broker[bot]" },
      taskflow_gates: taskflowGateReceipt(),
    };
  };
  registerPrLifecycleTaskflow(api);
  const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const created = await __testing.ingestPullRequest(api, config, prEvent());
  const claimRef = bindQueuedReview(bound, created.flowId);
  await __testing.ingestReviewResult(api, config, reviewEvent({ claimRef }));
  const legacy = bound.flows.get(created.flowId);
  assert.equal(legacy.stateJson.phase, PHASE.MERGE_READY);
  assert.equal(legacy.status, "waiting");
  legacy.status = "succeeded";
  legacy.endedAt = Date.now();

  calls.schedules.length = 0;
  await __testing.reconcileAtStartup(api, config);
  const recovered = bound.get(created.flowId);
  assert.equal(recovered.stateJson.phase, PHASE.MERGE_READY);
  assert.equal(recovered.status, "waiting");
  assert.equal(recovered.endedAt, null);
  assert.equal(calls.schedules.length, 0);

  await ownerAuthorizeAndContinue(calls, bound, created.flowId);
  const merged = bound.get(created.flowId);
  assert.equal(merged.stateJson.phase, PHASE.MERGED);
  assert.equal(merged.status, "succeeded");
  assert.equal(merged.stateJson.merged.receipt.sha, SHA_C);
});

test("startup refreshes policy and requeues a legacy infrastructure block", async () => {
  const { api, bound, calls } = makeApi();
  const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const created = await __testing.ingestPullRequest(api, config, prEvent());
  const stored = bound.flows.get(created.flowId);
  stored.status = "blocked";
  stored.stateJson = {
    ...stored.stateJson,
    phase: PHASE.BLOCKED,
    blocker: "worker_failure_exhausted:task_link_failed:ownership mismatch",
    maxRetries: 0,
    wallTimeMinutes: 60,
    deadlineAt: Date.now() - 1,
  };
  calls.schedules.length = 0;
  await __testing.reconcileAtStartup(api, config);
  const recovered = bound.get(created.flowId);
  assert.equal(recovered.stateJson.phase, PHASE.REVIEW_QUEUED);
  assert.equal(recovered.stateJson.blocker, null);
  assert.equal(recovered.stateJson.maxRetries, 2);
  assert.equal(recovered.stateJson.wallTimeMinutes, 120);
  assert.equal(recovered.stateJson.infrastructureLastFailure.startsWith("task_link_failed"), true);
  assert.equal(calls.schedules.length, 1);
  assert.equal(calls.schedules[0].delayMs, 5 * 60_000);
  assert.match(calls.schedules[0].message, /"action":"recover"/);
});

test("restart recovery selects the current canonical worker instead of aggregate history", () => {
  const { api, bound } = makeApi();
  bound.tasks.set("task-old", {
    taskId: "task-old",
    parentFlowId: "flow-1",
    runId: "run-old",
    childSessionKey: "agent:owner-agent:subagent:old",
    status: "succeeded",
  });
  bound.tasks.set("task-current", {
    taskId: "task-current",
    parentFlowId: "flow-1",
    runId: "run-current",
    childSessionKey: "agent:owner-agent:subagent:current",
    status: "failed",
  });
  const current = __testing.currentWorkerTask(api, OWNER, {
    activeWorker: {
      taskId: "task-current",
      runId: "run-current",
      sessionKey: "agent:owner-agent:subagent:current",
    },
  });
  assert.equal(current.id, "task-current");
  assert.equal(current.status, "failed");
});

test("recover cancels the dead canonical worker before redispatch", async () => {
  const { api, bound, calls, storeFor, sessionEntries } = makeApi();
  registerPrLifecycleTaskflow(api);
  const tool = toolFor(calls, OWNER);
  const { continued } = await admitAndStartReview(tool);
  const workerKey = continued.flow.activeWorker.sessionKey;
  const oldTaskId = continued.flow.activeWorker.taskId;
  const stored = bound.flows.get(continued.flow.flowId);
  stored.stateJson.activeWorker.reservedAt = Date.now() - 200_000;
  sessionEntries.set(workerKey, {
    sessionId: "dead-worker",
    updatedAt: Date.now(),
    endedAt: Date.now() - 1_000,
    status: "failed",
  });
  const recovered = details(
    await tool.execute("recover-ghost", {
      action: "recover",
      flowId: continued.flow.flowId,
      expectedRevision: stored.revision,
    }),
  );
  assert.equal(recovered.ok, true);
  assert.equal(recovered.recovery, "retry_infrastructure");
  assert.equal(recovered.flow.activeWorker, null);
  assert.equal(recovered.flow.infrastructureRetryCount, 1);

  const waiting = bound.flows.get(continued.flow.flowId);
  waiting.stateJson.infrastructureRetryAt = Date.now() - 1;
  const retried = details(
    await tool.execute("recover-ghost-after-backoff", {
      action: "recover",
      flowId: continued.flow.flowId,
      expectedRevision: waiting.revision,
    }),
  );
  assert.notEqual(retried.flow.activeWorker?.sessionKey, workerKey);
  assert.match(retried.flow.activeWorker.sessionKey, /-0-i1-review$/);
  assert.equal(storeFor(workerKey).getTask(oldTaskId).status, "cancelled");
  assert.equal(retried.flow.lastGhostCleanup.taskId, oldTaskId);
  assert.equal(retried.flow.lastGhostCleanup.reason, "orphan_task_cancelled");
});

test("an unavailable session registry still cancels the exact canonical task before retry", async () => {
  const { api, bound, calls, storeFor } = makeApi();
  api.runtime.agent.session.getSessionEntry = () => {
    throw new Error("session registry temporarily unavailable");
  };
  registerPrLifecycleTaskflow(api);
  const tool = toolFor(calls, OWNER);
  const { continued } = await admitAndStartReview(tool);
  const workerKey = continued.flow.activeWorker.sessionKey;
  const oldTaskId = continued.flow.activeWorker.taskId;
  const stored = bound.flows.get(continued.flow.flowId);
  stored.stateJson.activeWorker.reservedAt = Date.now() - 200_000;

  const recovered = details(
    await tool.execute("recover-unknown", {
      action: "recover",
      flowId: continued.flow.flowId,
      expectedRevision: stored.revision,
    }),
  );
  assert.equal(recovered.recovery, "retry_infrastructure");
  assert.match(
    recovered.flow.infrastructureLastFailure,
    /^worker_(?:session_liveness_unknown|lost_after_process_restart)$/,
  );

  const waiting = bound.flows.get(continued.flow.flowId);
  waiting.stateJson.infrastructureRetryAt = Date.now() - 1;
  const retried = details(
    await tool.execute("recover-unknown-after-backoff", {
      action: "recover",
      flowId: continued.flow.flowId,
      expectedRevision: waiting.revision,
    }),
  );
  assert.equal(storeFor(workerKey).getTask(oldTaskId).status, "cancelled");
  assert.notEqual(retried.flow.activeWorker.sessionKey, workerKey);
});

test("recover keeps a live worker session as worker_active", async () => {
  const { api, bound, calls, sessionEntries } = makeApi();
  registerPrLifecycleTaskflow(api);
  const tool = toolFor(calls, OWNER);
  const { continued } = await admitAndStartReview(tool);
  const workerKey = continued.flow.activeWorker.sessionKey;
  const stored = bound.flows.get(continued.flow.flowId);
  sessionEntries.set(workerKey, {
    sessionId: "live-worker",
    updatedAt: Date.now(),
    status: "running",
  });
  const recovered = details(
    await tool.execute("recover-live", {
      action: "recover",
      flowId: continued.flow.flowId,
      expectedRevision: stored.revision,
    }),
  );
  assert.equal(recovered.ok, true);
  assert.equal(recovered.recovery, "worker_active");
  assert.equal(recovered.flow.activeWorker.sessionKey, workerKey);
});

test("workerSessionAlive treats ended or missing session entries as dead", () => {
  const { api, sessionEntries } = makeApi();
  const key = "agent:broker-review-launcher:subagent:mprl-dead";
  const state = { activeWorker: { sessionKey: key } };
  assert.equal(__testing.workerSessionAlive(api, state), false);
  sessionEntries.set(key, { sessionId: "s", updatedAt: 1, endedAt: 2, status: "failed" });
  assert.equal(__testing.workerSessionAlive(api, state), false);
  sessionEntries.set(key, { sessionId: "s", updatedAt: 1, status: "running" });
  assert.equal(__testing.workerSessionAlive(api, state), true);
});

// Regressions restored from the P0/P1 implementation snapshot after three-way recovery.
