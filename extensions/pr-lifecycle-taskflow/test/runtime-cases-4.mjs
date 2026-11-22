import assert from "node:assert/strict";
import test from "node:test";
import { PHASE, createState } from "../src/controller.mjs";
import { __testing, registerPrLifecycleTaskflow } from "../src/runtime.mjs";
import {
  OWNER,
  SHA_A,
  SHA_C,
  finding,
  makeApi,
  pluginConfig,
  prEvent,
  remediatorProfile,
  toolFor,
} from "./runtime-helpers-1.mjs";
import { details } from "./runtime-helpers-2.mjs";

test("one controller-owned review lease fences concurrent PR review launches", async () => {
  const { api, bound, calls } = makeApi();
  registerPrLifecycleTaskflow(api);
  const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const first = await __testing.ingestPullRequest(api, config, prEvent());
  const second = await __testing.ingestPullRequest(
    api,
    config,
    prEvent({ eventId: "github:event-2", prNumber: 44 }),
  );
  const ownerTool = toolFor(calls, OWNER);
  let firstFlow = bound.get(first.flowId);
  await ownerTool.execute("start-first", {
    action: "continue",
    flowId: first.flowId,
    expectedRevision: firstFlow.revision,
  });
  firstFlow = bound.get(first.flowId);
  assert.equal(firstFlow.stateJson.activeWorker.kind, "review");
  assert.equal(calls.subagents.length, 1);

  const secondFlow = bound.get(second.flowId);
  const output = details(
    await ownerTool.execute("start-second", {
      action: "continue",
      flowId: second.flowId,
      expectedRevision: secondFlow.revision,
    }),
  );
  assert.equal(calls.subagents.length, 1);
  assert.equal(output.flow.phase, PHASE.REVIEW_QUEUED);
  assert.equal(output.flow.activeWorker, null);
  assert.equal(calls.schedules.at(-1).delayMs, 5 * 60_000);
});

test("pending external review keeps the durable lease after the worker waits", async () => {
  const { api, bound, calls } = makeApi();
  registerPrLifecycleTaskflow(api);
  const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const first = await __testing.ingestPullRequest(api, config, prEvent());
  const second = await __testing.ingestPullRequest(
    api,
    config,
    prEvent({ eventId: "github:event-2", prNumber: 44 }),
  );
  const ownerTool = toolFor(calls, OWNER);
  let firstFlow = bound.get(first.flowId);
  await ownerTool.execute("start-first", {
    action: "continue",
    flowId: first.flowId,
    expectedRevision: firstFlow.revision,
  });
  firstFlow = bound.get(first.flowId);
  const claimRef = firstFlow.stateJson.activeWorker.claimRef;
  const workerTool = toolFor(calls, firstFlow.stateJson.activeWorker.sessionKey);
  await workerTool.execute("wait-first", {
    action: "report",
    flowId: first.flowId,
    kind: "review",
    outcome: "waiting_review",
    headSha: SHA_A,
    cycle: 0,
    claimRef,
  });
  firstFlow = bound.get(first.flowId);
  assert.equal(firstFlow.stateJson.phase, PHASE.REVIEW_WAITING);
  assert.equal(firstFlow.stateJson.activeWorker, null);
  assert.equal(firstFlow.stateJson.reviewLease.claimRef, claimRef);

  const secondFlow = bound.get(second.flowId);
  const output = details(
    await ownerTool.execute("start-second", {
      action: "continue",
      flowId: second.flowId,
      expectedRevision: secondFlow.revision,
    }),
  );
  assert.equal(calls.subagents.length, 1);
  assert.equal(output.flow.phase, PHASE.REVIEW_QUEUED);
  assert.equal(output.flow.activeWorker, null);

  const recovered = details(
    await ownerTool.execute("recover-first", {
      action: "recover",
      flowId: first.flowId,
      expectedRevision: firstFlow.revision,
    }),
  );
  assert.equal(recovered.recovery, "review_in_progress");
  assert.equal(recovered.flow.phase, PHASE.REVIEW_WAITING);
  assert.equal(calls.subagents.length, 1);
});

test("one atomic workspace lock fences simultaneous review and remediation across owner sessions", async () => {
  const secondOwner = "agent:owner-agent:dashboard:legacy-owner";
  const { api, calls, storeFor } = makeApi(
    pluginConfig({
      legacyOwnerSessionKeys: [secondOwner],
      repositories: {
        "example-org/example-repo": {
          ...pluginConfig().repositories["example-org/example-repo"],
          remediatorProfile: remediatorProfile({ pullRequests: [42, 44] }),
        },
      },
    }),
  );
  const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const repositoryPolicy = config.repositories.get("example-org/example-repo");
  const firstStore = storeFor(OWNER);
  const secondStore = storeFor(secondOwner);
  const firstState = createState(prEvent(), repositoryPolicy);
  const secondState = {
    ...createState(prEvent({ eventId: "github:event-2", prNumber: 44 }), repositoryPolicy),
    phase: PHASE.REMEDIATION_QUEUED,
    findings: [finding()],
  };
  const firstFlow = firstStore.createManaged({
    controllerId: "pr-lifecycle-taskflow/v1",
    goal: "first simultaneous flow",
    status: "running",
    stateJson: firstState,
  });
  const secondFlow = secondStore.createManaged({
    controllerId: "pr-lifecycle-taskflow/v1",
    goal: "second simultaneous flow",
    status: "running",
    stateJson: secondState,
  });
  let arrivals = 0;
  let releasePreflight;
  const bothAtPreflight = new Promise((resolve) => {
    releasePreflight = resolve;
  });
  api.__testReadWorkspaceHead = async (_workspace, expectedHeadSha) => {
    arrivals += 1;
    if (arrivals === 2) {
      releasePreflight();
    }
    await bothAtPreflight;
    return expectedHeadSha;
  };

  await Promise.all([
    __testing.dispatchWorker(api, config, firstStore, firstFlow),
    __testing.dispatchWorker(api, config, secondStore, secondFlow),
  ]);

  const activeStates = [
    firstStore.get(firstFlow.flowId).stateJson,
    secondStore.get(secondFlow.flowId).stateJson,
  ].filter((state) => state.activeWorker);
  assert.equal(calls.subagents.length, 1);
  assert.equal(activeStates.length, 1);
  assert.equal(
    calls.schedules.some((schedule) => schedule.delayMs === 5 * 60_000),
    true,
  );
});

test("one atomic global lock fences simultaneous reservations across repositories", async () => {
  const secondOwner = "agent:owner-agent:dashboard:caption-owner";
  const policy = {
    enabled: true,
    mode: "active",
    baseBranches: ["dev"],
    reviewActor: "broker",
    authorActor: "author-worker",
    mergeActor: "broker[bot]",
    reviewWorkerAgentId: "broker-review-launcher",
    authorWorkerAgentId: "author-worker",
    maxCycles: 2,
    maxRetries: 2,
    wallTimeMinutes: 120,
  };
  const { api, calls, storeFor } = makeApi(
    pluginConfig({
      maxParallelPrsGlobal: 1,
      repositories: {
        "example-org/example-repo": {
          ...policy,
          workspace: "/workspace/example-repo",
          brokerRepoAlias: "example-repo",
          ownerSessionKey: OWNER,
        },
        "example-org/sample-app": {
          ...policy,
          workspace: "/workspace/sample-app",
          brokerRepoAlias: "sample-app",
          ownerSessionKey: secondOwner,
        },
      },
    }),
  );
  const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const first = await __testing.ingestPullRequest(api, config, prEvent());
  const second = await __testing.ingestPullRequest(
    api,
    config,
    prEvent({
      eventId: "github:event-global-cap-second",
      repo: "example-org/sample-app",
      prNumber: 44,
      headRepo: "example-org/sample-app",
    }),
  );
  const firstStore = storeFor(OWNER);
  const secondStore = storeFor(secondOwner);
  const firstFlow = firstStore.get(first.flowId);
  const secondFlow = secondStore.get(second.flowId);
  let arrivals = 0;
  let releasePreflight;
  const bothAtPreflight = new Promise((resolve) => {
    releasePreflight = resolve;
  });
  api.__testReadWorkspaceHead = async (_workspace, expectedHeadSha) => {
    arrivals += 1;
    if (arrivals === 2) releasePreflight();
    await bothAtPreflight;
    return expectedHeadSha;
  };

  await Promise.all([
    __testing.dispatchWorker(api, config, firstStore, firstFlow),
    __testing.dispatchWorker(api, config, secondStore, secondFlow),
  ]);

  const states = [firstStore.get(first.flowId).stateJson, secondStore.get(second.flowId).stateJson];
  assert.equal(calls.subagents.length, 1);
  assert.equal(states.filter((state) => state.activeWorker).length, 1);
  const waiting = states.find((state) => !state.activeWorker);
  assert.equal(waiting.wait.scope, "global");
  assert.equal(waiting.wait.cap, 1);
  assert.equal(
    __testing.contentionLockKey(config, states[0]),
    __testing.contentionLockKey(config, states[1]),
  );
});

test("a synchronized head cancels the old exact worker before redispatch", async () => {
  const { api, bound, calls, storeFor } = makeApi();
  registerPrLifecycleTaskflow(api);
  const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const created = await __testing.ingestPullRequest(api, config, prEvent());
  const ownerTool = toolFor(calls, OWNER);
  let flow = bound.get(created.flowId);
  await ownerTool.execute("start-old-head", {
    action: "continue",
    flowId: flow.flowId,
    expectedRevision: flow.revision,
  });
  flow = bound.get(flow.flowId);
  const oldWorker = flow.stateJson.activeWorker;
  assert.equal(storeFor(oldWorker.sessionKey).getTask(oldWorker.taskId).status, "running");

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
  flow = bound.get(flow.flowId);
  assert.equal(flow.stateJson.activeWorker, null);
  assert.equal(flow.stateJson.orphanedWorker.sessionKey, oldWorker.sessionKey);

  const continued = details(
    await ownerTool.execute("start-new-head", {
      action: "continue",
      flowId: flow.flowId,
      expectedRevision: flow.revision,
    }),
  );
  assert.equal(storeFor(oldWorker.sessionKey).getTask(oldWorker.taskId).status, "cancelled");
  assert.equal(calls.subagents.length, 2);
  assert.equal(continued.flow.headSha, SHA_C);
  assert.equal(continued.flow.phase, PHASE.REVIEW_RUNNING);
  assert.notEqual(continued.flow.activeWorker.sessionKey, oldWorker.sessionKey);
  assert.equal(continued.flow.lastGhostCleanup.reason, "orphan_task_cancelled");
});

test("distinct repositories with distinct workspaces launch reviews in parallel", async () => {
  const { api, bound, calls } = makeApi(
    pluginConfig({
      repositories: {
        "example-org/example-repo": {
          enabled: true,
          mode: "active",
          workspace: "/workspace/example-repo",
          brokerRepoAlias: "example-repo",
          baseBranches: ["dev"],
          reviewActor: "broker",
          authorActor: "author-worker",
          mergeActor: "broker[bot]",
          reviewWorkerAgentId: "broker-review-launcher",
          authorWorkerAgentId: "author-worker",
          maxCycles: 2,
          maxRetries: 2,
          wallTimeMinutes: 120,
        },
        "example-org/sample-app": {
          enabled: true,
          mode: "active",
          workspace: "/workspace/sample-app",
          brokerRepoAlias: "sample-app",
          baseBranches: ["main"],
          reviewActor: "broker",
          authorActor: "author-worker",
          mergeActor: "broker[bot]",
          reviewWorkerAgentId: "broker-review-launcher",
          authorWorkerAgentId: "author-worker",
          maxCycles: 2,
          maxRetries: 2,
          wallTimeMinutes: 120,
        },
      },
    }),
  );
  registerPrLifecycleTaskflow(api);
  const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const first = await __testing.ingestPullRequest(api, config, prEvent());
  const second = await __testing.ingestPullRequest(
    api,
    config,
    prEvent({
      eventId: "github:event-bridge",
      repo: "example-org/sample-app",
      prNumber: 44,
      baseRef: "main",
      headRepo: "example-org/sample-app",
    }),
  );
  const ownerTool = toolFor(calls, OWNER);
  let firstFlow = bound.get(first.flowId);
  await ownerTool.execute("start-example-repo", {
    action: "continue",
    flowId: first.flowId,
    expectedRevision: firstFlow.revision,
  });
  firstFlow = bound.get(first.flowId);
  assert.equal(firstFlow.stateJson.activeWorker.kind, "review");
  assert.equal(calls.subagents.length, 1);

  const secondFlow = bound.get(second.flowId);
  const output = details(
    await ownerTool.execute("start-sample-app", {
      action: "continue",
      flowId: second.flowId,
      expectedRevision: secondFlow.revision,
    }),
  );
  assert.equal(calls.subagents.length, 2);
  assert.equal(output.flow.phase, PHASE.REVIEW_RUNNING);
  assert.equal(output.flow.activeWorker.kind, "review");
  assert.equal(output.flow.repo, "example-org/sample-app");
  assert.equal(calls.subagents[0].cwd, "/workspace/example-repo");
  assert.equal(calls.subagents[1].cwd, "/workspace/sample-app");
});

test("three distinct repositories with distinct workspaces launch reviews in parallel", async () => {
  const policy = {
    enabled: true,
    mode: "active",
    baseBranches: ["dev"],
    reviewActor: "broker",
    authorActor: "author-worker",
    mergeActor: "broker[bot]",
    reviewWorkerAgentId: "broker-review-launcher",
    authorWorkerAgentId: "author-worker",
    maxCycles: 2,
    maxRetries: 2,
    wallTimeMinutes: 120,
  };
  const { api, bound, calls } = makeApi(
    pluginConfig({
      repositories: {
        "example-org/example-repo": {
          ...policy,
          workspace: "/workspace/example-repo",
          brokerRepoAlias: "example-repo",
        },
        "example-org/sample-app": {
          ...policy,
          workspace: "/workspace/sample-app",
          brokerRepoAlias: "sample-app",
        },
        "example-org/sample-service": {
          ...policy,
          workspace: "/workspace/sample-service",
          brokerRepoAlias: "sample-service",
        },
      },
    }),
  );
  registerPrLifecycleTaskflow(api);
  const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const first = await __testing.ingestPullRequest(api, config, prEvent());
  const second = await __testing.ingestPullRequest(
    api,
    config,
    prEvent({
      eventId: "github:event-bridge",
      repo: "example-org/sample-app",
      prNumber: 44,
      headRepo: "example-org/sample-app",
    }),
  );
  const third = await __testing.ingestPullRequest(
    api,
    config,
    prEvent({
      eventId: "github:event-sample-service",
      repo: "example-org/sample-service",
      prNumber: 110,
      headSha: SHA_C,
      headRepo: "example-org/sample-service",
    }),
  );
  const ownerTool = toolFor(calls, OWNER);
  const firstFlow = bound.get(first.flowId);
  await ownerTool.execute("start-example-repo", {
    action: "continue",
    flowId: first.flowId,
    expectedRevision: firstFlow.revision,
  });
  const secondFlow = bound.get(second.flowId);
  await ownerTool.execute("start-sample-app", {
    action: "continue",
    flowId: second.flowId,
    expectedRevision: secondFlow.revision,
  });
  const thirdFlow = bound.get(third.flowId);
  const output = details(
    await ownerTool.execute("start-sample-service", {
      action: "continue",
      flowId: third.flowId,
      expectedRevision: thirdFlow.revision,
    }),
  );
  assert.equal(calls.subagents.length, 3);
  assert.equal(output.flow.phase, PHASE.REVIEW_RUNNING);
  assert.equal(output.flow.activeWorker.kind, "review");
  assert.equal(output.flow.repo, "example-org/sample-service");
  assert.equal(calls.subagents[0].cwd, "/workspace/example-repo");
  assert.equal(calls.subagents[1].cwd, "/workspace/sample-app");
  assert.equal(calls.subagents[2].cwd, "/workspace/sample-service");
});

test("per-repo owner sessions isolate controller wakes and continue rights", async () => {
  const exampleRepoOwner = "agent:owner-agent:dashboard:example-repo";
  const captionOwner = "agent:owner-agent:dashboard:sample-app";
  const policy = {
    enabled: true,
    mode: "active",
    baseBranches: ["dev"],
    reviewActor: "broker",
    authorActor: "author-worker",
    mergeActor: "broker[bot]",
    reviewWorkerAgentId: "broker-review-launcher",
    authorWorkerAgentId: "author-worker",
    maxCycles: 2,
    maxRetries: 2,
    wallTimeMinutes: 120,
  };
  const { api, calls, storeFor } = makeApi(
    pluginConfig({
      repositories: {
        "example-org/example-repo": {
          ...policy,
          workspace: "/workspace/example-repo",
          brokerRepoAlias: "example-repo",
          ownerSessionKey: exampleRepoOwner,
        },
        "example-org/sample-app": {
          ...policy,
          workspace: "/workspace/sample-app",
          brokerRepoAlias: "sample-app",
          ownerSessionKey: captionOwner,
        },
      },
    }),
  );
  registerPrLifecycleTaskflow(api);
  const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const first = await __testing.ingestPullRequest(api, config, prEvent());
  const second = await __testing.ingestPullRequest(
    api,
    config,
    prEvent({
      eventId: "github:event-bridge",
      repo: "example-org/sample-app",
      prNumber: 44,
      headRepo: "example-org/sample-app",
    }),
  );
  assert.equal(
    __testing.ownerSessionKeyForRepo(config, "example-org/example-repo"),
    exampleRepoOwner,
  );
  assert.equal(__testing.ownerSessionKeyForRepo(config, "example-org/sample-app"), captionOwner);
  assert.ok(storeFor(exampleRepoOwner).get(first.flowId));
  assert.equal(storeFor(captionOwner).get(first.flowId), undefined);
  assert.ok(storeFor(captionOwner).get(second.flowId));
  assert.equal(calls.schedules.filter((item) => item.sessionKey === exampleRepoOwner).length, 1);
  assert.equal(calls.schedules.filter((item) => item.sessionKey === captionOwner).length, 1);

  const exampleRepoTool = toolFor(calls, exampleRepoOwner);
  const captionTool = toolFor(calls, captionOwner);
  await exampleRepoTool.execute("start-example-repo", {
    action: "continue",
    flowId: first.flowId,
    expectedRevision: storeFor(exampleRepoOwner).get(first.flowId).revision,
  });
  await assert.rejects(
    () =>
      exampleRepoTool.execute("steal-sample-app", {
        action: "continue",
        flowId: second.flowId,
        expectedRevision: storeFor(captionOwner).get(second.flowId).revision,
      }),
    /controller_action_requires_owner_session/,
  );
  const output = details(
    await captionTool.execute("start-sample-app", {
      action: "continue",
      flowId: second.flowId,
      expectedRevision: storeFor(captionOwner).get(second.flowId).revision,
    }),
  );
  assert.equal(calls.subagents.length, 2);
  assert.equal(output.flow.repo, "example-org/sample-app");
  assert.equal(output.flow.activeWorker.kind, "review");
  assert.equal(calls.subagents[0].cwd, "/workspace/example-repo");
  assert.equal(calls.subagents[1].cwd, "/workspace/sample-app");
});

test("shared-workspace repos still serialize across distinct owner sessions", async () => {
  const exampleRepoOwner = "agent:owner-agent:dashboard:example-repo";
  const captionOwner = "agent:owner-agent:dashboard:sample-app";
  const policy = {
    enabled: true,
    mode: "active",
    workspace: "/workspace/shared",
    baseBranches: ["dev"],
    reviewActor: "broker",
    authorActor: "author-worker",
    mergeActor: "broker[bot]",
    reviewWorkerAgentId: "broker-review-launcher",
    authorWorkerAgentId: "author-worker",
    maxParallelPrs: 2,
    maxCycles: 2,
    maxRetries: 2,
    wallTimeMinutes: 120,
  };
  const { api, calls, storeFor } = makeApi(
    pluginConfig({
      repositories: {
        "example-org/example-repo": {
          ...policy,
          brokerRepoAlias: "example-repo",
          ownerSessionKey: exampleRepoOwner,
        },
        "example-org/sample-app": {
          ...policy,
          brokerRepoAlias: "sample-app",
          baseBranches: ["main"],
          ownerSessionKey: captionOwner,
        },
      },
    }),
  );
  registerPrLifecycleTaskflow(api);
  const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const first = await __testing.ingestPullRequest(api, config, prEvent());
  const second = await __testing.ingestPullRequest(
    api,
    config,
    prEvent({
      eventId: "github:event-bridge",
      repo: "example-org/sample-app",
      prNumber: 44,
      baseRef: "main",
      headRepo: "example-org/sample-app",
    }),
  );
  await toolFor(calls, exampleRepoOwner).execute("start-example-repo", {
    action: "continue",
    flowId: first.flowId,
    expectedRevision: storeFor(exampleRepoOwner).get(first.flowId).revision,
  });
  const output = details(
    await toolFor(calls, captionOwner).execute("start-sample-app", {
      action: "continue",
      flowId: second.flowId,
      expectedRevision: storeFor(captionOwner).get(second.flowId).revision,
    }),
  );
  assert.equal(calls.subagents.length, 1);
  assert.equal(output.flow.phase, PHASE.REVIEW_QUEUED);
  assert.equal(output.flow.activeWorker, null);
  assert.equal(output.flow.wait.scope, "shared_workspace");
  assert.equal(output.flow.wait.cap, 1);
});
