import assert from "node:assert/strict";
import test from "node:test";
import {
  PHASE,
  applyReviewResult,
  authorizeMergeReady,
  createState,
  reserveWorker,
} from "../src/controller.mjs";
import { __testing, registerPrLifecycleTaskflow } from "../src/runtime.mjs";
import {
  SHA_A,
  SHA_B,
  SHA_C,
  authorizedAutoMergePolicy,
  makeApi,
  pluginConfig,
  prEvent,
  reviewEvent,
  taskflowGateReceipt,
} from "./runtime-helpers-1.mjs";
import { launchWaitingReview, ownerAuthorizeAndContinue } from "./runtime-helpers-2.mjs";

void test("automatic merge rechecks exact-head review and checks before an authorized merge", async () => {
  const repositoryPolicy = authorizedAutoMergePolicy();
  const queued = createState(prEvent(), repositoryPolicy);
  const reserved = reserveWorker(
    queued,
    "review",
    "agent:broker-review-launcher:subagent:auto-merge",
    2,
    "flow-auto-merge",
  ).state;
  const reviewed = applyReviewResult(
    reserved,
    reviewEvent({ claimRef: reserved.activeWorker.claimRef }),
    3,
  ).state;
  assert.equal(reviewed.phase, PHASE.MERGE_READY);
  assert.equal(reviewed.mergeReady.mergeAuthorized, false);
  const state = authorizeMergeReady(reviewed, repositoryPolicy, 4).state;
  assert.equal(state.phase, PHASE.MERGE_QUEUED);
  const normalizedPolicy = __testing
    .normalizeRuntimeConfig({
      repositories: { "example-org/example-repo": repositoryPolicy },
    })
    .repositories.get("example-org/example-repo");
  const { api } = makeApi();
  const calls = [];
  let brokerCheckApp = "github-actions";
  let brokerGatesReady = false;
  let brokerAppBindingValid = true;
  let remoteAlreadyMerged = false;
  let reconciledHeadSha = SHA_A;
  let reconciledMergedAt = "1970-01-01T00:00:01.000Z";
  api.testRunBroker = async (args) => {
    calls.push(args);
    if (args[0] === "pr-state") {
      if (remoteAlreadyMerged) {
        return {
          repo: "example-org/example-repo",
          number: 42,
          state: "closed",
          merged: true,
          base: { ref: "dev", sha: SHA_B, repo: "example-org/example-repo" },
          head: { ref: "feat/example", sha: reconciledHeadSha, repo: "example-org/example-repo" },
          merge_commit_sha: SHA_C,
          merged_at: reconciledMergedAt,
          merged_by: { login: "broker[bot]" },
        };
      }
      return {
        repo: "example-org/example-repo",
        state: "open",
        merged: false,
        draft: false,
        mergeable: true,
        base: { ref: "dev", sha: SHA_B, repo: "example-org/example-repo" },
        head: {
          ref: "feat/example",
          sha: SHA_A,
          repo: "example-org/example-repo",
        },
        checks: {
          ready: true,
          check_runs: [
            {
              name: "Broker review",
              app: brokerCheckApp,
              status: "completed",
              conclusion: "success",
            },
            {
              name: "Optional diagnostic",
              app: "github-actions",
              status: "completed",
              conclusion: "failure",
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
      taskflow_gates: taskflowGateReceipt({
        required_checks_ready: brokerGatesReady,
        ...(brokerAppBindingValid
          ? {}
          : {
              atomic_enforcement: {
                broker_app_id: 54321,
                required_status_checks: [{ context: "Broker review", app_id: 54321 }],
              },
            }),
      }),
    };
  };
  await assert.rejects(
    () => __testing.autoMergeReceipt(api, state, normalizedPolicy),
    /automatic_merge_gates_not_satisfied:brokerCheck/,
  );
  brokerCheckApp = "broker";
  calls.length = 0;
  await assert.rejects(
    () => __testing.autoMergeReceipt(api, state, normalizedPolicy),
    /automatic_merge_receipt_invalid/,
  );
  brokerGatesReady = true;
  brokerAppBindingValid = false;
  calls.length = 0;
  await assert.rejects(
    () => __testing.autoMergeReceipt(api, state, normalizedPolicy),
    /automatic_merge_receipt_invalid/,
  );
  brokerAppBindingValid = true;
  calls.length = 0;
  const receipt = await __testing.autoMergeReceipt(api, state, normalizedPolicy);
  assert.equal(receipt.merged, true);
  assert.deepEqual(calls[0], ["pr-state", "example-repo", "42", "--expected-sha", SHA_A, "--json"]);
  assert.deepEqual(calls[1], [
    "merge-pr",
    "example-repo",
    "42",
    "--expected-base",
    "dev",
    "--expected-base-sha",
    SHA_B,
    "--expected-head-branch",
    "feat/example",
    "--expected-head-sha",
    SHA_A,
    "--expected-actor-login",
    "broker[bot]",
    "--merge-method",
    "merge",
    "--require-taskflow-gates",
    "--json",
  ]);
  const completed = __testing.mergedState(state, receipt, 123);
  assert.equal(completed.phase, PHASE.MERGED);
  assert.equal(completed.merged.headSha, SHA_A);
  assert.equal(completed.merged.mergedAt, 123);

  remoteAlreadyMerged = true;
  calls.length = 0;
  const reconciled = await __testing.autoMergeReceipt(api, state, normalizedPolicy);
  assert.equal(reconciled.reconciled, true);
  assert.equal(reconciled.sha, SHA_C);
  assert.equal(reconciled.head_sha, SHA_A);
  assert.equal(reconciled.merged_by.login, "broker[bot]");
  assert.equal(calls.length, 1);

  reconciledHeadSha = SHA_B;
  await assert.rejects(
    () => __testing.autoMergeReceipt(api, state, normalizedPolicy),
    /automatic_merge_reconciliation_identity_mismatch/,
  );

  reconciledHeadSha = SHA_A;
  reconciledMergedAt = "1969-12-31T23:59:59.000Z";
  await assert.rejects(
    () => __testing.autoMergeReceipt(api, state, normalizedPolicy),
    /automatic_merge_reconciliation_identity_mismatch/,
  );
});

void test("merge lock renewal prevents parallel holders and fences an expired owner", () => {
  const { api } = makeApi();
  let now = 0;
  const entries = new Map();
  const pruneExpired = () => {
    for (const [key, entry] of entries) {
      if (entry.expiresAt <= now) {
        entries.delete(key);
      }
    }
  };
  api.runtime.state.openSyncKeyedStore = () => ({
    registerIfAbsent(key, value, opts = {}) {
      pruneExpired();
      if (entries.has(key)) {
        return false;
      }
      entries.set(key, { value: structuredClone(value), expiresAt: now + opts.ttlMs });
      return true;
    },
    update(key, updateValue, opts = {}) {
      pruneExpired();
      const entry = entries.get(key);
      const next = updateValue(entry ? structuredClone(entry.value) : undefined);
      if (next === undefined) {
        return false;
      }
      entries.set(key, { value: structuredClone(next), expiresAt: now + opts.ttlMs });
      return true;
    },
    deleteIf(key, predicate) {
      pruneExpired();
      const entry = entries.get(key);
      if (!entry || !predicate(structuredClone(entry.value))) {
        return false;
      }
      entries.delete(key);
      return true;
    },
  });
  const state = { repo: "example-org/example-repo", baseRef: "dev", headSha: SHA_A };
  const first = __testing.acquireMergeLock(api, { flowId: "flow-1" }, state, now);
  assert.ok(first);
  assert.equal(__testing.acquireMergeLock(api, { flowId: "flow-2" }, state, now), null);

  now = 60_001;
  assert.equal(first.assertAndRenew(now), true);
  now = 120_001;
  assert.equal(__testing.acquireMergeLock(api, { flowId: "flow-2" }, state, now), null);

  now = 180_002;
  const second = __testing.acquireMergeLock(api, { flowId: "flow-2" }, state, now);
  assert.ok(second);
  assert.equal(first.assertAndRenew(now), false);
  assert.equal(first.release(), false);
  assert.equal(second.assertAndRenew(now), true);
  assert.equal(second.release(), true);
});

void test("automatic merge checks its lock before the external commit point and preserves the receipt after expiry", async () => {
  const repositoryPolicy = authorizedAutoMergePolicy();
  const queued = createState(prEvent(), repositoryPolicy);
  const reserved = reserveWorker(
    queued,
    "review",
    "agent:broker-review-launcher:subagent:auto-merge-lock",
    2,
    "flow-auto-merge-lock",
  ).state;
  const reviewed = applyReviewResult(
    reserved,
    reviewEvent({ claimRef: reserved.activeWorker.claimRef }),
    3,
  ).state;
  const state = authorizeMergeReady(reviewed, repositoryPolicy, 4).state;
  const normalizedPolicy = __testing
    .normalizeRuntimeConfig({
      repositories: { "example-org/example-repo": repositoryPolicy },
    })
    .repositories.get("example-org/example-repo");
  const { api } = makeApi();
  let lockHeld = true;
  let lockChecks = 0;
  let mergeCalls = 0;
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
    mergeCalls += 1;
    lockHeld = false;
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

  const receipt = await __testing.autoMergeReceipt(api, state, normalizedPolicy, null, () => {
    lockChecks += 1;
    if (!lockHeld) {
      throw new Error("merge_lock_lost");
    }
  });
  assert.equal(receipt.sha, SHA_C);
  assert.equal(mergeCalls, 1);
  assert.equal(lockChecks, 3);
});

void test("automatic merge durably reconciles an exact already-merged PR after the commit point", async () => {
  const repositoryPolicy = authorizedAutoMergePolicy();
  const { api, bound, calls } = makeApi(
    pluginConfig({ repositories: { "example-org/example-repo": repositoryPolicy } }),
  );
  const brokerCalls = [];
  api.testRunBroker = async (args) => {
    brokerCalls.push(args);
    assert.equal(args[0], "pr-state");
    return {
      repo: "example-org/example-repo",
      number: 42,
      state: "closed",
      merged: true,
      base: { ref: "dev", sha: SHA_B, repo: "example-org/example-repo" },
      head: { ref: "feat/example", sha: SHA_A, repo: "example-org/example-repo" },
      merge_commit_sha: SHA_C,
      merged_at: "1970-01-01T00:00:01.000Z",
      merged_by: { login: "broker[bot]" },
    };
  };
  registerPrLifecycleTaskflow(api);
  const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const created = await __testing.ingestPullRequest(api, config, prEvent());
  const waiting = await launchWaitingReview(bound, calls, created.flowId);
  await __testing.ingestReviewResult(
    api,
    config,
    reviewEvent({ claimRef: waiting.stateJson.reviewLease.claimRef }),
  );

  const result = await ownerAuthorizeAndContinue(calls, bound, created.flowId);
  assert.equal(result.flow.phase, PHASE.MERGED);
  assert.equal(result.flow.merged.receipt.reconciled, true);
  assert.equal(result.flow.merged.receipt.sha, SHA_C);
  assert.equal(result.flow.latestExternalMilestone.receipt.sha, SHA_C);
  assert.equal(brokerCalls.length, 1);
});

void test("automatic merge aborts when a check-suite rerun parks the revision after gate read", async () => {
  const repositoryPolicy = authorizedAutoMergePolicy();
  const { api, bound, calls } = makeApi(
    pluginConfig({ repositories: { "example-org/example-repo": repositoryPolicy } }),
  );
  let flowId = "";
  let mergeCalls = 0;
  api.testRunBroker = async (args) => {
    if (args[0] === "merge-pr") {
      mergeCalls += 1;
      return {
        merged: true,
        base: "dev",
        head_sha: SHA_A,
        sha: SHA_C,
        actor_verification: "passed",
        merged_by: { login: "broker[bot]" },
        taskflow_gates: taskflowGateReceipt(),
      };
    }
    const stored = bound.flows.get(flowId);
    stored.stateJson = {
      ...stored.stateJson,
      wait: {
        kind: "check_suite",
        since: Date.now(),
        headSha: SHA_A,
        action: "rerequested",
        suiteId: "123",
        githubUpdatedAt: Date.parse("2026-09-05T00:00:02Z"),
        url: "https://api.github.com/check-suites/123",
      },
      updatedAt: Date.now(),
    };
    stored.revision += 1;
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
  };
  registerPrLifecycleTaskflow(api);
  const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const created = await __testing.ingestPullRequest(api, config, prEvent());
  flowId = created.flowId;
  const waiting = await launchWaitingReview(bound, calls, flowId);
  await __testing.ingestReviewResult(
    api,
    config,
    reviewEvent({ claimRef: waiting.stateJson.reviewLease.claimRef }),
  );
  assert.equal(bound.get(flowId).stateJson.phase, PHASE.MERGE_READY);
  await ownerAuthorizeAndContinue(calls, bound, flowId);

  const current = bound.get(flowId);
  assert.equal(mergeCalls, 0);
  assert.equal(current.stateJson.phase, PHASE.MERGE_QUEUED);
  assert.equal(current.stateJson.wait.kind, "check_suite");
  assert.equal(current.stateJson.wait.action, "rerequested");
  assert.equal(current.stateJson.merged, undefined);
});

void test("automatic merge persists its receipt across a same-head revision race", async () => {
  const repositoryPolicy = authorizedAutoMergePolicy();
  const { api, bound, calls } = makeApi(
    pluginConfig({ repositories: { "example-org/example-repo": repositoryPolicy } }),
  );
  let flowId = "";
  let mergeCalls = 0;
  api.testRunBroker = async (args) => {
    if (args[0] === "merge-pr") {
      mergeCalls += 1;
      const stored = bound.flows.get(flowId);
      stored.stateJson = {
        ...stored.stateJson,
        wait: {
          kind: "check_suite",
          origin: "github_event",
          since: Date.now(),
          headSha: SHA_A,
          action: "rerequested",
          suiteId: "45",
          githubUpdatedAt: Date.parse("2026-09-05T00:00:02Z"),
        },
        updatedAt: Date.now(),
      };
      stored.revision += 1;
      return {
        merged: true,
        base: "dev",
        head_sha: SHA_A,
        sha: SHA_C,
        actor_verification: "passed",
        merged_by: { login: "broker[bot]" },
        taskflow_gates: taskflowGateReceipt(),
      };
    }
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
  };
  registerPrLifecycleTaskflow(api);
  const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const created = await __testing.ingestPullRequest(api, config, prEvent());
  flowId = created.flowId;
  const waiting = await launchWaitingReview(bound, calls, flowId);
  await __testing.ingestReviewResult(
    api,
    config,
    reviewEvent({ claimRef: waiting.stateJson.reviewLease.claimRef }),
  );
  await ownerAuthorizeAndContinue(calls, bound, flowId);

  const current = bound.get(flowId);
  assert.equal(mergeCalls, 1);
  assert.equal(current.stateJson.phase, PHASE.MERGED);
  assert.equal(current.stateJson.wait, null);
  assert.equal(current.stateJson.merged.receipt.sha, SHA_C);
  assert.equal(current.stateJson.latestExternalMilestone.receipt.sha, SHA_C);
});

void test("red required checks park on check_suite without spending retries, then recheck exact head", async () => {
  const repositoryPolicy = authorizedAutoMergePolicy();
  const { api, bound, calls } = makeApi(
    pluginConfig({ repositories: { "example-org/example-repo": repositoryPolicy } }),
  );
  let checksGreen = false;
  api.testRunBroker = async (args) => {
    if (args[0] === "merge-pr") {
      return {
        merged: true,
        base: "dev",
        head_sha: SHA_A,
        sha: SHA_C,
        actor_verification: "passed",
        merged_by: { login: "broker[bot]" },
        taskflow_gates: taskflowGateReceipt(),
      };
    }
    return {
      repo: "example-org/example-repo",
      state: "open",
      merged: false,
      draft: false,
      mergeable: true,
      base: { ref: "dev", sha: SHA_B, repo: "example-org/example-repo" },
      head: { ref: "feat/example", sha: SHA_A, repo: "example-org/example-repo" },
      checks: {
        ready: checksGreen,
        check_runs: [
          {
            name: "Broker review",
            app: "broker",
            status: "completed",
            conclusion: "success",
          },
          {
            name: "Exact v0.2.0 on Windows",
            status: "completed",
            conclusion: checksGreen ? "success" : "failure",
            details_url: "https://github.com/example-org/example-repo/actions/runs/123",
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
  };
  registerPrLifecycleTaskflow(api);
  const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const created = await __testing.ingestPullRequest(api, config, prEvent());
  const waiting = await launchWaitingReview(bound, calls, created.flowId);
  await __testing.ingestReviewResult(
    api,
    config,
    reviewEvent({ claimRef: waiting.stateJson.reviewLease.claimRef }),
  );
  assert.equal(bound.get(created.flowId).stateJson.phase, PHASE.MERGE_READY);
  await ownerAuthorizeAndContinue(calls, bound, created.flowId);
  let flow = bound.get(created.flowId);
  assert.equal(flow.stateJson.phase, PHASE.MERGE_QUEUED);
  assert.equal(flow.stateJson.wait.kind, "check_suite");
  assert.equal(flow.stateJson.infrastructureRetryCount, 0);
  assert.equal(
    flow.stateJson.mergeGates.gates.requiredChecks.failed[0].name,
    "Exact v0.2.0 on Windows",
  );
  assert.equal(
    flow.stateJson.mergeGates.gates.requiredChecks.failed[0].url,
    "https://github.com/example-org/example-repo/actions/runs/123",
  );
  assert.equal(flow.stateJson.prEffects, "check_published");
  assert.equal(flow.stateJson.latestExternalMilestone.headSha, SHA_A);

  checksGreen = true;
  await __testing.ingestCheckSuite(api, config, {
    type: "check_suite",
    eventId: "github:check-suite-green",
    action: "completed",
    repo: "example-org/example-repo",
    prNumber: 42,
    headSha: SHA_A,
    suiteId: "123",
    updatedAt: "2026-09-05T00:00:03Z",
    url: "https://github.com/example-org/example-repo/actions/runs/124",
  });
  flow = bound.get(created.flowId);
  assert.equal(flow.stateJson.phase, PHASE.MERGED);
  assert.equal(flow.stateJson.prEffects, "merged");
  assert.equal(flow.stateJson.merged.headSha, SHA_A);
  assert.equal(flow.stateJson.infrastructureRetryCount, 0);
  assert.equal(flow.stateJson.terminalCleanup.wakesCancelled, true);
});
