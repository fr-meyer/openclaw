import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { afterEach } from "node:test";
import { useAutoCleanupTempDirTracker } from "openclaw/plugin-sdk/test-temp-dir";
import { PHASE, createState } from "../src/controller.mjs";
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
  toolFor,
} from "./runtime-helpers-1.mjs";
import { createWorkspaceHeadMismatchBlock, details } from "./runtime-helpers-2.mjs";

const tempDirs = useAutoCleanupTempDirTracker(afterEach);

test("stale scheduled turns are fenced by expected TaskFlow revision", async () => {
  const { api, bound, calls } = makeApi();
  registerPrLifecycleTaskflow(api);
  const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const created = await __testing.ingestPullRequest(api, config, prEvent());
  const flow = bound.get(created.flowId);
  const ownerTool = toolFor(calls, OWNER);
  const output = details(
    await ownerTool.execute("call-1", {
      action: "continue",
      flowId: flow.flowId,
      expectedRevision: flow.revision + 1,
    }),
  );
  assert.equal(output.staleWake, true);
  assert.equal(calls.subagents.length, 0);
});

test("controller blocks before launch when the local workspace head is stale", async () => {
  const { api, bound, calls } = makeApi();
  api.__testReadWorkspaceHead = async () => SHA_C;
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
  assert.equal(output.flow.phase, PHASE.BLOCKED);
  assert.equal(output.flow.blocker, `workspace_head_mismatch:expected=${SHA_A}:actual=${SHA_C}`);
  assert.equal(output.flow.workspacePreflight, null);
  assert.equal(calls.subagents.length, 0);
});

test("owner admit independently revalidates and reopens a corrected workspace head", async () => {
  const { api, bound, calls } = makeApi();
  const blocked = await createWorkspaceHeadMismatchBlock(api, bound, calls);
  const stored = bound.flows.get(blocked.flowId);
  stored.stateJson = {
    ...stored.stateJson,
    flowWorkspace: {
      path: "/workspace/stale-recorded-path",
      headSha: SHA_C,
      provisionedAt: 1,
    },
    workspacePreflight: {
      workspace: "/workspace/stale-recorded-path",
      headSha: SHA_C,
      checkedAt: 1,
    },
  };
  const observedWorkspaces = [];
  api.testReadWorkspaceHead = async (workspace) => {
    observedWorkspaces.push(workspace);
    return SHA_A;
  };

  const output = details(
    await toolFor(calls, OWNER).execute("revalidate-workspace", {
      action: "admit",
      flowId: blocked.flowId,
      expectedRevision: blocked.revision,
      repo: "example-org/example-repo",
      prNumber: 42,
      headSha: SHA_A,
      baseSha: SHA_B,
      baseRef: "dev",
    }),
  );

  assert.equal(output.admit.reason, "owner_admit_reopen_workspace_head_mismatch");
  assert.equal(output.flow.phase, PHASE.REVIEW_QUEUED);
  assert.equal(output.flow.blocker, null);
  assert.deepEqual(observedWorkspaces, ["/workspace/example-repo"]);
  assert.equal(output.flow.flowWorkspace.path, "/workspace/example-repo");
  assert.equal(output.flow.flowWorkspace.headSha, SHA_A);
  assert.equal(output.flow.workspacePreflight.workspace, "/workspace/example-repo");
  assert.equal(output.flow.workspacePreflight.headSha, SHA_A);
  assert.equal(calls.subagents.length, 0);
});

test("owner admit leaves a workspace-head block unchanged when revalidation still fails", async (t) => {
  for (const scenario of [
    {
      name: "persistent head mismatch",
      identity: {
        topLevel: "/workspace/example-repo",
        headSha: SHA_C,
        repository: "example-org/example-repo",
        clean: true,
      },
      reason: `workspace_head_mismatch:expected=${SHA_A}:actual=${SHA_C}`,
    },
    {
      name: "dirty workspace",
      identity: {
        topLevel: "/workspace/example-repo",
        headSha: SHA_A,
        repository: "example-org/example-repo",
        clean: false,
      },
      reason: "workspace_dirty",
    },
    {
      name: "wrong repository",
      identity: {
        topLevel: "/workspace/example-repo",
        headSha: SHA_A,
        repository: "example-org/other",
        clean: true,
      },
      reason: "workspace_repository_mismatch",
    },
  ]) {
    await t.test(scenario.name, async () => {
      const { api, bound, calls } = makeApi();
      const blocked = await createWorkspaceHeadMismatchBlock(api, bound, calls);
      const before = bound.get(blocked.flowId);
      api.testReadWorkspaceIdentity = async () => scenario.identity;

      const output = details(
        await toolFor(calls, OWNER).execute("reject-workspace", {
          action: "admit",
          flowId: blocked.flowId,
          expectedRevision: blocked.revision,
          repo: "example-org/example-repo",
          prNumber: 42,
          headSha: SHA_A,
          baseSha: SHA_B,
          baseRef: "dev",
        }),
      );

      assert.equal(output.admit.accepted, false);
      assert.equal(
        output.admit.reason,
        `owner_admit_workspace_revalidation_failed:${scenario.reason}`,
      );
      assert.deepEqual(bound.get(blocked.flowId), before);
      assert.equal(calls.subagents.length, 0);
    });
  }
});

test("owner workspace revalidation refuses a stale revision without probing or mutation", async () => {
  const { api, bound, calls } = makeApi();
  const blocked = await createWorkspaceHeadMismatchBlock(api, bound, calls);
  const before = bound.get(blocked.flowId);
  let probes = 0;
  api.__testReadWorkspaceHead = async () => {
    probes += 1;
    return SHA_A;
  };

  const output = details(
    await toolFor(calls, OWNER).execute("stale-revalidate", {
      action: "admit",
      flowId: blocked.flowId,
      expectedRevision: blocked.revision - 1,
      repo: "example-org/example-repo",
      prNumber: 42,
      headSha: SHA_A,
      baseSha: SHA_B,
      baseRef: "dev",
    }),
  );

  assert.equal(output.staleWake, true);
  assert.equal(probes, 0);
  assert.deepEqual(bound.get(blocked.flowId), before);
});

test("owner workspace revalidation rejects a non-owner before probing or mutation", async () => {
  const { api, bound, calls } = makeApi();
  const blocked = await createWorkspaceHeadMismatchBlock(api, bound, calls);
  const before = bound.get(blocked.flowId);
  let probes = 0;
  api.__testReadWorkspaceHead = async () => {
    probes += 1;
    return SHA_A;
  };

  await assert.rejects(
    () =>
      toolFor(calls, "agent:intruder:main").execute("unauthorized-revalidate", {
        action: "admit",
        flowId: blocked.flowId,
        expectedRevision: blocked.revision,
        repo: "example-org/example-repo",
        prNumber: 42,
        headSha: SHA_A,
        baseSha: SHA_B,
        baseRef: "dev",
      }),
    /controller_action_requires_owner_session/,
  );
  assert.equal(probes, 0);
  assert.deepEqual(bound.get(blocked.flowId), before);
});

test("controller blocks before launch when the local workspace is dirty", async () => {
  const { api, bound, calls } = makeApi();
  api.__testReadWorkspaceHead = async () => {
    throw new Error("workspace_dirty");
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
  assert.equal(output.flow.phase, PHASE.BLOCKED);
  assert.equal(output.flow.blocker, "workspace_head_preflight_failed:workspace_dirty");
  assert.equal(output.flow.workspacePreflight, null);
  assert.equal(calls.subagents.length, 0);
});

test("controller blocks and cleans up when isolated worktree provisioning fails", async () => {
  const base = pluginConfig();
  const { api, bound, calls } = makeApi(
    pluginConfig({
      repositories: {
        "example-org/example-repo": {
          ...base.repositories["example-org/example-repo"],
          maxParallelPrs: 2,
        },
      },
    }),
  );
  api.testProvisionFlowWorktree = async () => {
    throw new Error("provisioning_failed");
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
  assert.equal(output.flow.phase, PHASE.BLOCKED);
  assert.match(output.flow.blocker, /workspace_head_preflight_failed:provisioning_failed/);
  assert.equal(output.flow.terminalCleanup.wakesCancelled, true);
  assert.equal(calls.subagents.length, 0);
});

test("parallel flow workspace advances a clean detached worktree to a synchronized head", async () => {
  const root = tempDirs.make("mprl-flow-worktree-", tmpdir());
  try {
    const seed = join(root, "seed");
    mkdirSync(seed);
    execFileSync("git", ["-C", seed, "init", "-q"]);
    execFileSync("git", [
      "-C",
      seed,
      "remote",
      "add",
      "origin",
      "https://github.com/example-org/example-repo.git",
    ]);
    writeFileSync(join(seed, "fixture.txt"), "first\n");
    execFileSync("git", ["-C", seed, "add", "fixture.txt"]);
    execFileSync("git", [
      "-C",
      seed,
      "-c",
      "user.name=TaskFlow Test",
      "-c",
      "user.email=taskflow@example.invalid",
      "commit",
      "-q",
      "-m",
      "first",
    ]);
    const firstHead = execFileSync("git", ["-C", seed, "rev-parse", "HEAD"], {
      encoding: "utf8",
    }).trim();
    const policy = {
      workspace: seed,
      maxParallelPrs: 2,
      remediatorProfile: { worktreeRoot: root },
    };
    const firstState = {
      repo: "example-org/example-repo",
      prNumber: 42,
      headSha: firstHead,
    };
    const flowWorkspace = await __testing.ensureFlowWorkspace({}, policy, firstState);
    assert.equal(
      execFileSync("git", ["-C", flowWorkspace, "rev-parse", "HEAD"], {
        encoding: "utf8",
      }).trim(),
      firstHead,
    );

    writeFileSync(join(seed, "fixture.txt"), "second\n");
    execFileSync("git", ["-C", seed, "add", "fixture.txt"]);
    execFileSync("git", [
      "-C",
      seed,
      "-c",
      "user.name=TaskFlow Test",
      "-c",
      "user.email=taskflow@example.invalid",
      "commit",
      "-q",
      "-m",
      "second",
    ]);
    const secondHead = execFileSync("git", ["-C", seed, "rev-parse", "HEAD"], {
      encoding: "utf8",
    }).trim();
    const reused = await __testing.ensureFlowWorkspace({}, policy, {
      ...firstState,
      headSha: secondHead,
      flowWorkspace: { path: flowWorkspace, headSha: firstHead, provisionedAt: 1 },
    });
    assert.equal(reused, flowWorkspace);
    assert.equal(
      execFileSync("git", ["-C", reused, "rev-parse", "HEAD"], { encoding: "utf8" }).trim(),
      secondHead,
    );
    assert.equal(
      execFileSync("git", ["-C", reused, "rev-parse", "--abbrev-ref", "HEAD"], {
        encoding: "utf8",
      }).trim(),
      "HEAD",
    );
    assert.equal(
      execFileSync("git", ["-C", reused, "status", "--porcelain=v1"], {
        encoding: "utf8",
      }),
      "",
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("remediator admission rejects identity, branch, and executable drift before model spend", async () => {
  const cases = [
    {
      label: "non-git scratch identity",
      configure(api) {
        api.testReadWorkspaceIdentity = async () => ({
          topLevel: "/tmp/scratch",
          headSha: SHA_A,
          repository: "example-org/example-repo",
          clean: true,
        });
      },
      blocker: /remediator_profile_git_identity_mismatch/,
    },
    {
      label: "wrong head branch",
      mutate(state) {
        state.headRef = "fix/outside-profile";
      },
      blocker: /remediator_profile_head_branch_mismatch/,
    },
    {
      label: "missing validation executable",
      configure(api) {
        api.testExecutableAvailable = () => false;
      },
      blocker: /remediator_profile_executable_unavailable:node/,
    },
  ];
  for (const item of cases) {
    const { api, bound, calls } = makeApi();
    item.configure?.(api);
    registerPrLifecycleTaskflow(api);
    const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
    const created = await __testing.ingestPullRequest(api, config, prEvent());
    const stored = bound.flows.get(created.flowId);
    stored.stateJson = {
      ...stored.stateJson,
      phase: PHASE.REMEDIATION_QUEUED,
      findings: [finding()],
      activeWorker: null,
      reviewLease: null,
      wait: null,
    };
    item.mutate?.(stored.stateJson);
    const output = details(
      await toolFor(calls, OWNER).execute(item.label, {
        action: "continue",
        flowId: created.flowId,
        expectedRevision: stored.revision,
      }),
    );
    assert.equal(output.flow.phase, PHASE.BLOCKED, item.label);
    assert.match(output.flow.blocker, item.blocker, item.label);
    assert.equal(calls.subagents.length, 0, item.label);
    assert.equal(output.flow.terminalCleanup?.wakesCancelled, true, item.label);
  }
});

test("legacy owner bindings remain operable from the current owner and status is allowlisted", async () => {
  const oldOwner = "agent:owner-agent:dashboard:old-owner";
  const newOwner = "agent:controller:main";
  const statusSession = "agent:owner-agent:dashboard:status-reader";
  const raw = pluginConfig({
    ownerSessionKey: newOwner,
    legacyOwnerSessionKeys: [oldOwner],
    statusAgentIds: ["owner-agent"],
    repositories: {
      "example-org/example-repo": {
        ...pluginConfig().repositories["example-org/example-repo"],
        ownerSessionKey: newOwner,
      },
    },
  });
  const { api, calls, storeFor } = makeApi(raw);
  const oldBound = storeFor(oldOwner);
  const state = createState(prEvent(), raw.repositories["example-org/example-repo"]);
  const legacyFlow = oldBound.createManaged({
    controllerId: "pr-lifecycle-taskflow/v1",
    goal: "legacy owner migration fixture",
    status: "running",
    stateJson: state,
  });
  registerPrLifecycleTaskflow(api);

  const reader = toolFor(calls, statusSession, "owner-agent");
  const visible = details(
    await reader.execute("status", {
      action: "status",
      flowId: legacyFlow.flowId,
    }),
  );
  assert.equal(visible.repo, "example-org/example-repo");
  await assert.rejects(
    () => reader.execute("continue-denied", { action: "continue", flowId: legacyFlow.flowId }),
    /requires_owner_session/,
  );

  const owner = toolFor(calls, newOwner);
  const continued = details(
    await owner.execute("continue-migrated", {
      action: "continue",
      flowId: legacyFlow.flowId,
      expectedRevision: legacyFlow.revision,
    }),
  );
  assert.equal(continued.flow.phase, PHASE.REVIEW_RUNNING);
  assert.equal(storeFor(oldOwner).get(legacyFlow.flowId).ownerKey, oldOwner);
  assert.equal(calls.schedules.length, 0);
  assert.deepEqual(
    new Set(calls.unschedules.slice(-2).map((call) => call.sessionKey)),
    new Set([oldOwner, newOwner]),
  );
});

test("an exact owner-ledger worker task wins over a mismatched worker-ledger projection", async () => {
  const { api, bound, calls, storeFor } = makeApi();
  api.runtime.subagent.run = async (params) => {
    calls.subagents.push(params);
    bound.tasks.set("owner-ghost", {
      taskId: "owner-ghost",
      parentFlowId: "legacy-owner-flow",
      runId: "run-mismatch",
      childSessionKey: params.sessionKey,
      agentId: "broker-review-launcher",
      status: "running",
    });
    const workerStore = storeFor(params.sessionKey);
    workerStore.tasks.set("wrong-task", {
      taskId: "wrong-task",
      parentFlowId: "canonical-wrong",
      runId: "run-mismatch",
      childSessionKey: "agent:someone-else:subagent:wrong",
      agentId: "someone-else",
      status: "running",
    });
    return { runId: "run-mismatch", sessionKey: params.sessionKey };
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
  assert.equal(output.flow.activeWorker.runId, "run-mismatch");
  assert.equal(output.flow.activeWorker.taskId, "owner-ghost");
  assert.equal(output.flow.infrastructureRetryCount, 0);
});

test("a worker-session identity mismatch retains and cancels the actual orphan", async () => {
  const { api, bound, calls, storeFor } = makeApi();
  let launchCount = 0;
  api.runtime.subagent.run = async (params) => {
    calls.subagents.push(params);
    launchCount += 1;
    if (launchCount > 1) {
      storeFor(params.sessionKey).tasks.set("replacement-task", {
        taskId: "replacement-task",
        parentFlowId: "replacement-flow",
        runId: "run-replacement",
        childSessionKey: params.sessionKey,
        agentId: "broker-review-launcher",
        status: "running",
      });
      return { runId: "run-replacement", sessionKey: params.sessionKey };
    }
    const actualSessionKey = "agent:broker-review-launcher:subagent:unexpected";
    storeFor(actualSessionKey).tasks.set("unexpected-task", {
      taskId: "unexpected-task",
      parentFlowId: "unexpected-flow",
      runId: "run-unexpected",
      childSessionKey: actualSessionKey,
      agentId: "broker-review-launcher",
      status: "running",
    });
    return { runId: "run-unexpected", sessionKey: actualSessionKey };
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
  const stored = bound.get(flow.flowId).stateJson;
  assert.equal(output.flow.activeWorker, null);
  assert.equal(output.flow.infrastructureRetryCount, 1);
  assert.match(output.flow.infrastructureLastFailure, /^worker_session_identity_mismatch:/);
  assert.equal(
    stored.orphanedWorker.sessionKey,
    "agent:broker-review-launcher:subagent:unexpected",
  );
  assert.equal(stored.orphanedWorker.runId, "run-unexpected");

  bound.flows.get(flow.flowId).stateJson.infrastructureRetryAt = Date.now() - 1;
  await toolFor(calls, OWNER).execute("recover", {
    action: "recover",
    flowId: flow.flowId,
    expectedRevision: bound.get(flow.flowId).revision,
  });
  assert.equal(
    storeFor(stored.orphanedWorker.sessionKey).getTask("unexpected-task").status,
    "cancelled",
  );
});

test("tasks without the exact worker session are rejected across all ledgers", async () => {
  const { api, bound, calls, storeFor } = makeApi();
  api.runtime.subagent.run = async (params) => {
    calls.subagents.push(params);
    for (const store of [bound, storeFor(params.sessionKey)]) {
      store.tasks.set(`wrong-${store.ownerKey}`, {
        taskId: `wrong-${store.ownerKey}`,
        parentFlowId: "wrong-flow",
        runId: "run-no-exact-session",
        childSessionKey: "agent:someone-else:subagent:wrong",
        agentId: "someone-else",
        status: "running",
      });
    }
    return { runId: "run-no-exact-session", sessionKey: params.sessionKey };
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
  assert.equal(output.flow.activeWorker, null);
  assert.equal(output.flow.infrastructureRetryCount, 1);
  assert.match(output.flow.infrastructureLastFailure, /^task_link_missing:/);
});

test("owner continuation resolves one canonical exact-head worker task", async () => {
  const { api, bound, calls, storeFor } = makeApi();
  registerPrLifecycleTaskflow(api);
  const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const created = await __testing.ingestPullRequest(api, config, prEvent());
  const flow = bound.get(created.flowId);
  const ownerTool = toolFor(calls, OWNER);
  const output = details(
    await ownerTool.execute("call-1", {
      action: "continue",
      flowId: flow.flowId,
      expectedRevision: flow.revision,
    }),
  );
  assert.equal(calls.subagents.length, 1);
  assert.match(calls.subagents[0].sessionKey, /^agent:broker-review-launcher:subagent:mprl-/);
  assert.match(calls.subagents[0].message, new RegExp(SHA_A));
  assert.match(calls.subagents[0].message, /Do not merge/);
  assert.match(calls.subagents[0].message, /one active Broker --apply/);
  assert.equal(calls.subagents[0].deliver, false);
  assert.deepEqual(calls.subagents[0].toolsAlsoAllow, ["pr_lifecycle_taskflow"]);
  assert.equal(bound.tasks.size, 0);
  const workerTasks = storeFor(calls.subagents[0].sessionKey).listTasks();
  assert.equal(workerTasks.length, 1);
  assert.equal(workerTasks[0].childSessionKey, calls.subagents[0].sessionKey);
  assert.equal(workerTasks[0].runId, "run-1");
  assert.equal(output.flow.phase, PHASE.REVIEW_RUNNING);
  assert.equal(output.flow.workspacePreflight.workspace, "/workspace/example-repo");
  assert.equal(output.flow.workspacePreflight.headSha, SHA_A);
  assert.equal(output.flow.activeWorker.runId, "run-1");
  assert.equal(output.flow.activeWorker.taskId, workerTasks[0].id);
  assert.match(output.flow.activeWorker.claimRef, /^mprl-review:/);
  const bindingLine = calls.subagents[0].message
    .split("\n")
    .find((line) => line.startsWith("Immutable binding: "));
  const binding = JSON.parse(bindingLine.slice("Immutable binding: ".length));
  assert.equal(binding.claimRef, output.flow.activeWorker.claimRef);
  const workerTool = toolFor(calls, output.flow.activeWorker.sessionKey);
  const waited = details(
    await workerTool.execute("report-waiting", {
      action: "report",
      flowId: output.flow.flowId,
      kind: "review",
      outcome: "waiting_review",
      headSha: SHA_A,
      cycle: 0,
      claimRef: binding.claimRef,
    }),
  );
  assert.equal(waited.flow.reviewLease.claimRef, binding.claimRef);
  assert.equal(waited.flow.activeWorker, null);
});
