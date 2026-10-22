import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { expect, it } from "vitest";
import {
  CONTROLLER_ID,
  PHASE,
  createState,
} from "../../scripts/docker/runtime-plugins/mergeguez-pr-lifecycle/src/controller.mjs";
import {
  __testing,
  registerMergeguezPrLifecycle,
} from "../../scripts/docker/runtime-plugins/mergeguez-pr-lifecycle/src/runtime.mjs";
import { createSubagentRunRecord } from "../agents/subagent-test-fixtures.test-helpers.js";
import { bindSubagentRunRecord } from "../agents/subagents/registry/subagent-registry.store.codec.js";
import type { OpenClawConfig } from "../config/types.openclaw.js";
import { PluginInstance } from "../plugins/plugin-instance.js";
import { createEmptyPluginRegistry } from "../plugins/registry-empty.js";
import { withPluginRuntimeGatewayRequestScope } from "../plugins/runtime/gateway-request-scope.js";
import { createPluginRecord } from "../plugins/status.test-helpers.js";
import { captureOpenClawStateWorkerContext } from "../state/openclaw-state-worker-context.js";
import { executeManagedTaskFlowFixtureWrite } from "../tasks/managed-task-flow.test-helpers.js";
import { withOpenClawTestState } from "../test-utils/openclaw-test-state.js";
import { createDirectChatContext } from "./server-chat.agent-events.test-helpers.js";
import { createGatewayManagedTaskFlowRuntime } from "./server-managed-task-flow-runtime.js";
import type { GatewayClient } from "./server-methods/client-types.js";

const pluginId = "mergeguez-pr-lifecycle";
const ownerKey = "agent:franck:main";
const statusKey = "agent:status:main";
const workerKey = "agent:reviewer:subagent:mergeguez-parity";
const repo = "fr-meyer/speculoos";
const headSha = "a".repeat(40);
const baseSha = "b".repeat(40);
const runtimePath = fileURLToPath(
  new URL(
    "../../scripts/docker/runtime-plugins/mergeguez-pr-lifecycle/src/runtime.mjs",
    import.meta.url,
  ),
);
const runtimeSha256 = createHash("sha256").update(readFileSync(runtimePath)).digest("hex");

function pluginConfig(overrides: Record<string, unknown> = {}) {
  return {
    enabled: true,
    ownerSessionKey: ownerKey,
    statusAgentIds: ["status"],
    expectedRuntimePath: runtimePath,
    expectedRuntimeSha256: runtimeSha256,
    githubWebhookSecret: "synthetic-github-only",
    mergeguezEventSecret: "synthetic-review-only",
    repositories: {
      [repo]: {
        enabled: true,
        mode: "active",
        workspace: "/inert/speculoos",
        baseBranches: ["dev"],
        reviewActor: "mergeguez",
        authorActor: "le-commis",
        reviewWorkerAgentId: "reviewer",
        authorWorkerAgentId: "le-commis",
        publisherBrokerId: "fixture-only",
        publisherAttestationRef: "proof:synthetic",
        maxCycles: 2,
        maxRetries: 2,
        wallTimeMinutes: 120,
      },
    },
    ...overrides,
  };
}

function clientFor(agentId: string, sessionKey: string, signal: AbortSignal, runId?: string) {
  return {
    connect: { scopes: [] },
    connectionSignal: signal,
    internal: {
      agentToolCaller: {
        agentId,
        sessionKey,
        assertCurrent: () => signal.throwIfAborted(),
      },
      ...(runId
        ? {
            agentRuntimeIdentity: {
              agentId,
              sessionKey,
              operationalRunInstance: { runId },
            },
          }
        : {}),
    },
  } as unknown as GatewayClient;
}

function registeredApi(
  config: ReturnType<typeof pluginConfig>,
  tasks: ReturnType<typeof createGatewayManagedTaskFlowRuntime>,
) {
  const tools: Array<{
    factory: (context: { sessionKey: string; agentId?: string }) => {
      execute: (
        callId: string,
        input: Record<string, unknown>,
      ) => Promise<{ details: Record<string, unknown> }>;
    };
    options: unknown;
  }> = [];
  const routes: unknown[] = [];
  const subscriptions: unknown[] = [];
  const services: unknown[] = [];
  const schedules: unknown[] = [];
  const unschedules: unknown[] = [];
  const launches: unknown[] = [];
  const api = {
    config: { plugins: { entries: { [pluginId]: { config } } } },
    pluginConfig: config,
    logger: { info() {}, warn() {}, error() {} },
    runtime: {
      tasks,
      agent: { session: { getSessionEntry: () => null } },
      subagent: {
        run: async (request: unknown) => {
          launches.push(request);
          throw new Error("fixture_forbids_worker_launch");
        },
      },
    },
    agent: {
      events: { registerAgentEventSubscription: (entry: unknown) => subscriptions.push(entry) },
    },
    session: {
      workflow: {
        scheduleSessionTurn: async (entry: unknown) => {
          schedules.push(entry);
          return { id: `synthetic-wake-${schedules.length}` };
        },
        unscheduleSessionTurnsByTag: async (entry: unknown) => {
          unschedules.push(entry);
          return { removed: 0, failed: 0 };
        },
      },
    },
    registerTool: (factory: (typeof tools)[number]["factory"], options: unknown) =>
      tools.push({ factory, options }),
    registerHttpRoute: (route: unknown) => routes.push(route),
    registerService: (service: unknown) => services.push(service),
  };
  registerMergeguezPrLifecycle(api);
  return { tools, routes, subscriptions, services, schedules, unschedules, launches };
}

it("keeps the actual packaged controller inert until real Gateway parity, owner and source pin agree", async () => {
  await withOpenClawTestState(
    { label: "mergeguez-parity-registration", layout: "state-only" },
    async () => {
      const tasks = createGatewayManagedTaskFlowRuntime();
      const unavailable = {
        ...tasks,
        availability: { ...tasks.availability, controllerParity: false },
      };
      const inert = registeredApi(pluginConfig(), unavailable);
      expect(inert.tools).toHaveLength(1);
      expect(inert.routes).toHaveLength(0);
      expect(inert.subscriptions).toHaveLength(0);
      expect(inert.services).toHaveLength(0);
      await expect(
        inert.tools[0].factory({ sessionKey: ownerKey }).execute("call", {
          action: "status",
          flowId: "absent",
        }),
      ).rejects.toThrow(/not_enabled/u);

      expect(tasks.availability.controllerParity).toBe(true);
      const active = registeredApi(pluginConfig(), tasks);
      expect(active.routes).toHaveLength(2);
      expect(active.subscriptions).toHaveLength(1);
      expect(active.services).toHaveLength(1);
      expect(active.tools).toHaveLength(1);
      for (const invalid of [
        pluginConfig({ expectedRuntimeSha256: "0".repeat(64) }),
        pluginConfig({ expectedRuntimePath: "/inert/wrong-runtime.mjs" }),
        pluginConfig({ ownerSessionKey: "" }),
      ]) {
        const refused = registeredApi(invalid, tasks);
        expect(refused.routes).toHaveLength(0);
        expect(refused.subscriptions).toHaveLength(0);
        expect(refused.services).toHaveLength(0);
      }
    },
  );
});

it("lets packaged recovery cancel only its exact native root and holds an unknown stop", async () => {
  const [embeddedRuns, embeddedFixtures, registryMemory, registryStores, registryFixtures] =
    await Promise.all([
      import("../agents/embedded-agent-runner/runs.js"),
      import("../agents/embedded-agent-runner/runs.test-support.js"),
      import("../agents/subagents/registry/subagent-registry-memory.js"),
      import("../agents/subagents/registry/subagent-registry.persistence.test-support.js"),
      import("../agents/subagents/registry/subagent-registry.test-helpers.js"),
    ]);
  const { clearActiveEmbeddedRun, setActiveEmbeddedRun } = embeddedRuns;
  const { createEmbeddedRunHandle } = embeddedFixtures;
  const { subagentRuns } = registryMemory;
  const { writeSubagentSessionEntry } = registryStores;
  const { addSubagentRunForTests, resetSubagentRegistryForTests } = registryFixtures;
  await withOpenClawTestState(
    { label: "mergeguez-parity-root-cancel", layout: "state-only" },
    async (state) => {
      await resetSubagentRegistryForTests({ persist: false });
      const config = pluginConfig();
      const cfg = {
        agents: { defaults: { workspace: state.stateDir } },
        plugins: { entries: { [pluginId]: { config } } },
      } as OpenClawConfig;
      await state.writeConfig(cfg);
      const context = createDirectChatContext({
        getRuntimeConfig: () => cfg,
        validateAgentRuntimeApprovalAuthority: () => true,
      });
      const resolveGatewayContext = () => context;
      const registry = createEmptyPluginRegistry();
      const record = createPluginRecord({ id: pluginId });
      registry.plugins.push(record);
      const instance = new PluginInstance(pluginId, { record, registry });
      const gatewayTasks = createGatewayManagedTaskFlowRuntime(resolveGatewayContext);
      // Exercise the real Gateway binding before the production availability flag is enabled.
      const tasks = {
        ...gatewayTasks,
        availability: { ...gatewayTasks.availability, controllerParity: true },
      };
      const registered = registeredApi(config, tasks);
      const nativeContext = captureOpenClawStateWorkerContext();
      const policy = __testing.normalizeRuntimeConfig(config).repositories.get(repo);
      const initial = createState(
        {
          eventId: "github:synthetic-cancel",
          action: "opened",
          repo,
          prNumber: 320,
          headSha,
          baseSha,
          baseRef: "dev",
          headRepo: repo,
        },
        policy,
      );
      const rootKey = "agent:reviewer:subagent:mergeguez-cancel-root";
      const rootRunId = "mergeguez-cancel-root-run";
      const sessionId = "mergeguez-cancel-root-session";
      await writeSubagentSessionEntry({
        stateDir: state.stateDir,
        agentId: "reviewer",
        sessionKey: rootKey,
        defaultSessionId: sessionId,
      });
      await addSubagentRunForTests({
        runId: rootRunId,
        childSessionKey: rootKey,
        requesterSessionKey: ownerKey,
        controllerSessionKey: ownerKey,
        label: `plugin:${pluginId}`,
        generation: 3,
        expectsCompletionMessage: false,
      });
      const root = subagentRuns.get(rootRunId);
      if (!root) {
        throw new Error("Native root fixture was not registered");
      }
      const rootTaskId = root.taskRunId ?? rootRunId;
      const descendantId = "mergeguez-cancel-descendant";
      await addSubagentRunForTests({
        runId: descendantId,
        childSessionKey: "agent:reviewer:subagent:mergeguez-cancel-descendant",
        requesterSessionKey: rootKey,
        controllerSessionKey: rootKey,
        generation: 3,
        expectsCompletionMessage: false,
      });
      const unclaimedRunId = "mergeguez-cancel-unclaimed-run";
      await addSubagentRunForTests({
        runId: unclaimedRunId,
        childSessionKey: "agent:reviewer:subagent:mergeguez-cancel-unclaimed",
        requesterSessionKey: ownerKey,
        controllerSessionKey: ownerKey,
        label: `plugin:${pluginId}`,
        generation: 3,
        expectsCompletionMessage: false,
      });
      const foreignRunId = "mergeguez-cancel-foreign-requester";
      await addSubagentRunForTests({
        runId: foreignRunId,
        childSessionKey: "agent:reviewer:subagent:mergeguez-cancel-foreign",
        requesterSessionKey: "agent:other:main",
        controllerSessionKey: "agent:other:main",
        label: `plugin:${pluginId}`,
        generation: 3,
        expectsCompletionMessage: false,
      });
      const replacedRunId = "mergeguez-cancel-replaced-generation";
      await addSubagentRunForTests({
        runId: replacedRunId,
        childSessionKey: "agent:reviewer:subagent:mergeguez-cancel-replaced",
        requesterSessionKey: ownerKey,
        controllerSessionKey: ownerKey,
        label: `plugin:${pluginId}`,
        generation: 4,
        expectsCompletionMessage: false,
      });
      const blocked = (runId: string, sessionKey: string, taskId = runId) => ({
        ...initial,
        phase: PHASE.BLOCKED,
        blocker: "synthetic_orphan_hold",
        workerGeneration: 3,
        activeWorker: null,
        orphanedWorker: {
          kind: "review",
          sessionKey,
          runId,
          taskId,
          headSha,
          cycle: 0,
          nativeGeneration: 3,
          launchOutcome: null,
        },
      });
      const rootFlow = await executeManagedTaskFlowFixtureWrite(nativeContext, {
        type: "tasks.managedFlows.create",
        input: {
          ownerKey,
          controllerId: CONTROLLER_ID,
          goal: "Cancel one exact held native root",
          status: "blocked",
          stateJson: blocked(rootRunId, rootKey, rootTaskId),
        },
      });
      const wrongTaskFlow = await executeManagedTaskFlowFixtureWrite(nativeContext, {
        type: "tasks.managedFlows.create",
        input: {
          ownerKey,
          controllerId: CONTROLLER_ID,
          goal: "Hold a stale task claim",
          status: "blocked",
          stateJson: blocked(rootRunId, rootKey, "stale-task-id"),
        },
      });
      const descendantFlow = await executeManagedTaskFlowFixtureWrite(nativeContext, {
        type: "tasks.managedFlows.create",
        input: {
          ownerKey,
          controllerId: CONTROLLER_ID,
          goal: "Hold a descendant-only stop",
          status: "blocked",
          stateJson: blocked(descendantId, "agent:reviewer:subagent:mergeguez-cancel-descendant"),
        },
      });
      const foreignFlow = await executeManagedTaskFlowFixtureWrite(nativeContext, {
        type: "tasks.managedFlows.create",
        input: {
          ownerKey,
          controllerId: CONTROLLER_ID,
          goal: "Hold a foreign requester",
          status: "blocked",
          stateJson: blocked(foreignRunId, "agent:reviewer:subagent:mergeguez-cancel-foreign"),
        },
      });
      const replacedFlow = await executeManagedTaskFlowFixtureWrite(nativeContext, {
        type: "tasks.managedFlows.create",
        input: {
          ownerKey,
          controllerId: CONTROLLER_ID,
          goal: "Hold a replaced native generation",
          status: "blocked",
          stateJson: blocked(replacedRunId, "agent:reviewer:subagent:mergeguez-cancel-replaced"),
        },
      });
      const unknownKey = "agent:reviewer:subagent:mergeguez-cancel-unknown";
      const unknownRunId = "mergeguez-cancel-unknown-run";
      const unknownRun = createSubagentRunRecord({
        runId: unknownRunId,
        childSessionKey: unknownKey,
        requesterSessionKey: ownerKey,
        controllerSessionKey: ownerKey,
        label: `plugin:${pluginId}`,
        generation: 3,
        expectsCompletionMessage: false,
      });
      await executeManagedTaskFlowFixtureWrite(nativeContext, {
        type: "subagents.persistChanges",
        input: {
          writeId: "mergeguez-cancel-unknown-native",
          values: [bindSubagentRunRecord(unknownRun)],
          deleteRunIds: [],
          versions: [{ runId: unknownRunId, version: null }],
        },
      });
      const unknownFlow = await executeManagedTaskFlowFixtureWrite(nativeContext, {
        type: "tasks.managedFlows.create",
        input: {
          ownerKey,
          controllerId: CONTROLLER_ID,
          goal: "Hold an unresolved root stop",
          status: "blocked",
          stateJson: blocked(unknownRunId, unknownKey),
        },
      });
      const callAs = async <T>(run: () => Promise<T>): Promise<T> =>
        withPluginRuntimeGatewayRequestScope(
          {
            context,
            resolveGatewayContext,
            client: null,
            isWebchatConnect: () => false,
          },
          () => instance.run(run),
        );
      const tool = registered.tools[0].factory({ sessionKey: ownerKey, agentId: "franck" });
      let abortCalls = 0;
      const handle = createEmbeddedRunHandle({
        runId: rootRunId,
        abort: () => {
          abortCalls += 1;
        },
      });
      setActiveEmbeddedRun(sessionId, handle, rootKey);
      try {
        await callAs(async () => {
          const runs = tasks.runs.bindSession({ sessionKey: ownerKey });
          try {
            for (const [taskId, flow] of [
              [unclaimedRunId, rootFlow],
              [foreignRunId, foreignFlow],
              [replacedRunId, replacedFlow],
            ] as const) {
              await expect(
                runs.cancel({
                  taskId,
                  cfg,
                  expectedFlow: { flowId: flow.flowId, revision: flow.revision },
                }),
              ).rejects.toThrow();
            }
          } finally {
            await runs.close();
          }
        });
        expect(subagentRuns.get(unclaimedRunId)?.killIntent).toBeUndefined();
        expect(subagentRuns.get(foreignRunId)?.killIntent).toBeUndefined();
        expect(subagentRuns.get(replacedRunId)?.killIntent).toBeUndefined();
        for (const flowId of [
          descendantFlow.flowId,
          wrongTaskFlow.flowId,
          foreignFlow.flowId,
          replacedFlow.flowId,
        ]) {
          const rejected = await callAs(() => tool.execute("call", { action: "recover", flowId }));
          expect(rejected.details, flowId).toMatchObject({
            ok: true,
            recovery: "blocked_orphan_still_unsettled",
          });
        }
        expect(abortCalls).toBe(0);
        let raced = false;
        const raceTasks = {
          ...tasks,
          runs: {
            ...tasks.runs,
            bindSession(binding: Parameters<typeof tasks.runs.bindSession>[0]) {
              const native = tasks.runs.bindSession(binding);
              return {
                ...native,
                async cancel(request: Parameters<typeof native.cancel>[0]) {
                  if (!raced && request.taskId === rootTaskId) {
                    raced = true;
                    const changed = await executeManagedTaskFlowFixtureWrite(nativeContext, {
                      type: "tasks.managedFlows.mutate",
                      input: {
                        ownerKey,
                        controllerId: CONTROLLER_ID,
                        flowId: rootFlow.flowId,
                        expectedRevision: rootFlow.revision,
                        mutation: "setWaiting",
                        stateJson: blocked(rootRunId, rootKey, rootTaskId),
                      },
                    });
                    expect(changed).toMatchObject({
                      applied: true,
                      flow: { revision: rootFlow.revision + 1 },
                    });
                  }
                  return native.cancel(request);
                },
              };
            },
          },
        };
        const racedTool = registeredApi(config, raceTasks).tools[0].factory({
          sessionKey: ownerKey,
          agentId: "franck",
        });
        const stale = await callAs(() =>
          racedTool.execute("call", { action: "recover", flowId: rootFlow.flowId }),
        );
        expect(raced).toBe(true);
        expect(stale.details).toMatchObject({
          ok: true,
          recovery: "blocked_orphan_still_unsettled",
        });
        expect(abortCalls).toBe(0);
        const accepted = await callAs(() =>
          tool.execute("call", { action: "recover", flowId: rootFlow.flowId }),
        );
        expect(accepted.details).toMatchObject({ ok: true, recovery: "blocked_orphan_reconciled" });
        expect(abortCalls).toBe(1);
        expect(subagentRuns.get(descendantId)?.killIntent).toBeUndefined();
        const unresolved = await callAs(() =>
          tool.execute("call", { action: "recover", flowId: unknownFlow.flowId }),
        );
        expect(unresolved.details).toMatchObject({
          ok: true,
          recovery: "blocked_orphan_still_unsettled",
        });
        await callAs(async () => {
          const bound = tasks.managedFlows.bindSession({ sessionKey: ownerKey });
          try {
            expect(await bound.get(rootFlow.flowId)).toMatchObject({
              revision: rootFlow.revision + 2,
              stateJson: { orphanedWorker: null, lastGhostCleanup: { runId: rootRunId } },
            });
            expect(await bound.get(unknownFlow.flowId)).toMatchObject({
              revision: unknownFlow.revision,
              stateJson: { orphanedWorker: { runId: unknownRunId } },
            });
            for (const [candidate, runId] of [
              [wrongTaskFlow, rootRunId],
              [descendantFlow, descendantId],
              [foreignFlow, foreignRunId],
              [replacedFlow, replacedRunId],
            ] as const) {
              expect(await bound.get(candidate.flowId)).toMatchObject({
                revision: candidate.revision,
                stateJson: { orphanedWorker: { runId } },
              });
            }
          } finally {
            await bound.close();
          }
        });
        expect(registered.launches).toHaveLength(0);
      } finally {
        clearActiveEmbeddedRun(sessionId, handle, rootKey);
        await instance.dispose();
        await resetSubagentRegistryForTests({ persist: false });
      }
    },
  );
});

it("binds packaged status and reviewer reports to the exact native SQLite flow and current client", async () => {
  await withOpenClawTestState(
    { label: "mergeguez-parity-worker", layout: "state-only" },
    async () => {
      const config = pluginConfig();
      const cfg = { plugins: { entries: { [pluginId]: { config } } } } as OpenClawConfig;
      const context = createDirectChatContext({
        getRuntimeConfig: () => cfg,
        validateAgentRuntimeApprovalAuthority: () => true,
      });
      const resolveGatewayContext = () => context;
      const registry = createEmptyPluginRegistry();
      const record = createPluginRecord({ id: pluginId });
      registry.plugins.push(record);
      const instance = new PluginInstance(pluginId, { record, registry });
      const gatewayTasks = createGatewayManagedTaskFlowRuntime(resolveGatewayContext);
      // Exercise the real Gateway binding before the production availability flag is enabled.
      const tasks = {
        ...gatewayTasks,
        availability: { ...gatewayTasks.availability, controllerParity: true },
      };
      const registered = registeredApi(config, tasks);
      const nativeContext = captureOpenClawStateWorkerContext();
      const policy = __testing.normalizeRuntimeConfig(config).repositories.get(repo);
      const initial = createState(
        {
          eventId: "github:synthetic-319",
          action: "opened",
          repo,
          prNumber: 319,
          headSha,
          baseSha,
          baseRef: "dev",
          headRepo: repo,
        },
        policy,
      );
      const nativeRun = createSubagentRunRecord({
        runId: "mergeguez-parity-native-run",
        childSessionKey: workerKey,
        requesterSessionKey: ownerKey,
        controllerSessionKey: ownerKey,
        label: `plugin:${pluginId}`,
        generation: 3,
        expectsCompletionMessage: false,
      });
      const nativeRow = bindSubagentRunRecord(nativeRun);
      await executeManagedTaskFlowFixtureWrite(nativeContext, {
        type: "subagents.persistChanges",
        input: {
          writeId: "mergeguez-parity-native",
          values: [nativeRow],
          deleteRunIds: [],
          versions: [{ runId: nativeRun.runId, version: null }],
        },
      });
      const activeWorker = {
        kind: "review",
        sessionKey: workerKey,
        runId: nativeRun.runId,
        taskId: nativeRun.runId,
        nativeGeneration: 3,
        headSha,
        cycle: 0,
      };
      const flow = await executeManagedTaskFlowFixtureWrite(nativeContext, {
        type: "tasks.managedFlows.create",
        input: {
          ownerKey,
          controllerId: CONTROLLER_ID,
          goal: "Review synthetic PR only",
          status: "running",
          stateJson: { ...initial, phase: PHASE.REVIEW_RUNNING, workerGeneration: 3, activeWorker },
        },
      });
      const unrelated = await executeManagedTaskFlowFixtureWrite(nativeContext, {
        type: "tasks.managedFlows.create",
        input: {
          ownerKey,
          controllerId: "unrelated/v1",
          goal: "Invisible controller",
          status: "queued",
        },
      });
      const otherOwner = await executeManagedTaskFlowFixtureWrite(nativeContext, {
        type: "tasks.managedFlows.create",
        input: {
          ownerKey: "agent:other:main",
          controllerId: CONTROLLER_ID,
          goal: "Invisible owner",
          status: "queued",
          stateJson: initial,
        },
      });
      const callAs = async <T>(
        client: GatewayClient,
        run: () => Promise<T>,
        revalidate?: () => Promise<void>,
      ): Promise<T> =>
        withPluginRuntimeGatewayRequestScope(
          {
            context,
            resolveGatewayContext,
            client,
            isWebchatConnect: () => false,
            hasCurrentClientAuthority: () => !client.connectionSignal?.aborted,
            ...(revalidate ? { revalidate } : {}),
          },
          () => instance.run(run),
        );
      const callBackground = async <T>(run: () => Promise<T>): Promise<T> =>
        withPluginRuntimeGatewayRequestScope(
          { context, resolveGatewayContext, client: null, isWebchatConnect: () => false },
          () => instance.run(run),
        );
      const tool = registered.tools[0].factory;
      try {
        const statusClient = clientFor("status", statusKey, new AbortController().signal);
        await callAs(statusClient, async () => {
          const result = await tool({ sessionKey: statusKey, agentId: "status" }).execute("call", {
            action: "status",
            flowId: flow.flowId,
          });
          expect(result.details).toMatchObject({
            flowId: flow.flowId,
            phase: PHASE.REVIEW_RUNNING,
          });
          const bound = tasks.managedFlows.bindSession({ sessionKey: ownerKey });
          try {
            expect((await bound.list()).map((item) => item.flowId)).toEqual([flow.flowId]);
            expect(await bound.get(unrelated.flowId)).toBeUndefined();
            expect(await bound.get(otherOwner.flowId)).toBeUndefined();
            await expect(
              bound.setWaiting({ flowId: flow.flowId, expectedRevision: flow.revision }),
            ).rejects.toThrow(/status agent/u);
            await expect(
              bound.captureNativeLaunch({
                flowId: flow.flowId,
                expectedRevision: flow.revision,
                childSessionKey: workerKey,
              }),
            ).rejects.toThrow(/owner actor/u);
          } finally {
            await bound.close();
          }
          expect(() => tasks.runs.bindSession({ sessionKey: ownerKey })).toThrow();
        });

        const unrelatedClient = clientFor(
          "intruder",
          "agent:intruder:main",
          new AbortController().signal,
        );
        await callAs(unrelatedClient, async () => {
          await expect(
            tool({ sessionKey: "agent:intruder:main", agentId: "intruder" }).execute("call", {
              action: "status",
              flowId: flow.flowId,
            }),
          ).rejects.toThrow();
        });

        const rejectedRun = async (
          suffix: string,
          requester: string,
          generation: number,
          persistNative = true,
        ) => {
          const run = createSubagentRunRecord({
            runId: `mergeguez-parity-${suffix}`,
            childSessionKey: workerKey,
            requesterSessionKey: requester,
            controllerSessionKey: requester,
            label: `plugin:${pluginId}`,
            generation,
            expectsCompletionMessage: false,
          });
          if (persistNative) {
            await executeManagedTaskFlowFixtureWrite(nativeContext, {
              type: "subagents.persistChanges",
              input: {
                writeId: `mergeguez-parity-${suffix}-native`,
                values: [bindSubagentRunRecord(run)],
                deleteRunIds: [],
                versions: [{ runId: run.runId, version: null }],
              },
            });
          }
          const candidate = await executeManagedTaskFlowFixtureWrite(nativeContext, {
            type: "tasks.managedFlows.create",
            input: {
              ownerKey,
              controllerId: CONTROLLER_ID,
              goal: `Reject ${suffix} native run`,
              status: "running",
              stateJson: {
                ...initial,
                phase: PHASE.REVIEW_RUNNING,
                workerGeneration: 3,
                activeWorker: { ...activeWorker, runId: run.runId, taskId: run.runId },
              },
            },
          });
          const candidateClient = clientFor(
            "reviewer",
            workerKey,
            new AbortController().signal,
            run.runId,
          );
          await callAs(candidateClient, async () => {
            await expect(
              tool({ sessionKey: workerKey, agentId: "reviewer" }).execute("call", {
                action: "report",
                flowId: candidate.flowId,
                kind: "review",
                outcome: "waiting_review",
                headSha,
                cycle: 0,
                claimRef: "claim:rejected",
              }),
            ).rejects.toThrow();
          });
          return candidate;
        };
        const wrongRequester = await rejectedRun("wrong-requester", "agent:other:main", 3);
        const replacedGeneration = await rejectedRun("replaced-generation", ownerKey, 4);
        const missingNative = await rejectedRun("missing-native", ownerKey, 3, false);

        const wrongRunClient = clientFor(
          "reviewer",
          workerKey,
          new AbortController().signal,
          "wrong-native-run",
        );
        await callAs(wrongRunClient, async () => {
          await expect(
            tool({ sessionKey: workerKey, agentId: "reviewer" }).execute("call", {
              action: "report",
              flowId: flow.flowId,
              kind: "review",
              outcome: "waiting_review",
              headSha,
              cycle: 0,
              claimRef: "claim:synthetic-319",
            }),
          ).rejects.toThrow();
        });

        const workerClient = clientFor(
          "reviewer",
          workerKey,
          new AbortController().signal,
          nativeRun.runId,
        );
        const report = await callAs(workerClient, () =>
          tool({ sessionKey: workerKey, agentId: "reviewer" }).execute("call", {
            action: "report",
            flowId: flow.flowId,
            kind: "review",
            outcome: "waiting_review",
            headSha,
            cycle: 0,
            claimRef: "claim:synthetic-319",
          }),
        );
        expect(report.details).toMatchObject({ ok: true, transition: "review_in_progress" });
        await callBackground(async () => {
          const bound = tasks.managedFlows.bindSession({ sessionKey: ownerKey });
          try {
            expect(await bound.get(flow.flowId)).toMatchObject({
              revision: flow.revision + 1,
              status: "waiting",
              stateJson: {
                phase: PHASE.REVIEW_WAITING,
                activeWorker: null,
                wait: { claimRef: "claim:synthetic-319" },
                orphanedWorker: { runId: nativeRun.runId, nativeGeneration: 3 },
              },
            });
          } finally {
            await bound.close();
          }
        });
        expect(registered.launches).toHaveLength(0);
        expect(registered.schedules).toHaveLength(1);

        await callAs(workerClient, async () => {
          await expect(
            tool({ sessionKey: workerKey, agentId: "reviewer" }).execute("call", {
              action: "report",
              flowId: flow.flowId,
              kind: "review",
              outcome: "waiting_review",
              headSha,
              cycle: 0,
              claimRef: "claim:stale",
            }),
          ).rejects.toThrow();
        });

        await callBackground(async () => {
          const bound = tasks.managedFlows.bindSession({ sessionKey: ownerKey });
          try {
            expect(await bound.get(wrongRequester.flowId)).toMatchObject({ revision: 0 });
            expect(await bound.get(replacedGeneration.flowId)).toMatchObject({ revision: 0 });
            expect(await bound.get(missingNative.flowId)).toMatchObject({ revision: 0 });
          } finally {
            await bound.close();
          }
        });

        const retired = new AbortController();
        let entered!: () => void;
        let release!: () => void;
        const enteredGate = new Promise<void>((resolve) => {
          entered = resolve;
        });
        const releaseGate = new Promise<void>((resolve) => {
          release = resolve;
        });
        await callAs(
          clientFor("status", statusKey, retired.signal),
          async () => {
            const bound = tasks.managedFlows.bindSession({ sessionKey: ownerKey });
            const pending = bound.get(flow.flowId);
            await enteredGate;
            retired.abort(new Error("client retired during state read"));
            release();
            await expect(pending).rejects.toThrow(/retired|closed|client/i);
            await bound.close();
          },
          async () => {
            entered();
            await releaseGate;
          },
        );
      } finally {
        await instance.dispose();
      }
    },
  );
});
