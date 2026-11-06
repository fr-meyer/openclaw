import { createHash, createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import { Readable } from "node:stream";
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
import { projectPackagedMergeguezTaskFlowRuntime } from "../plugins/registry-runtime-task-flow.js";
import { createTestPluginRegistry } from "../plugins/registry-runtime.test-helpers.js";
import {
  withPluginRuntimeGatewayRequestScope,
  withPluginRuntimePluginScope,
} from "../plugins/runtime/gateway-request-scope.js";
import type { PluginRuntime } from "../plugins/runtime/types.js";
import { createPluginRecord } from "../plugins/status.test-helpers.js";
import { executeExistingOpenClawStateRead } from "../state/openclaw-state-db-readonly.js";
import { captureOpenClawStateWorkerContext } from "../state/openclaw-state-worker-context.js";
import { executeManagedTaskFlowFixtureWrite } from "../tasks/managed-task-flow.test-helpers.js";
import { withOpenClawTestState } from "../test-utils/openclaw-test-state.js";
import { createDirectChatContext } from "./server-chat.agent-events.test-helpers.js";
import {
  consumeGatewayManagedFlowNativeLaunch,
  createGatewayManagedTaskFlowRuntime,
} from "./server-managed-task-flow-runtime.js";
import type { GatewayClient } from "./server-methods/client-types.js";

const pluginId = "mergeguez-pr-lifecycle";
const packagedRoot = "/app/runtime-plugins/mergeguez-pr-lifecycle";
const packagedEntry = "/app/runtime-plugins/mergeguez-pr-lifecycle/index.mjs";
const oldEntry = "/home/node/.openclaw/extensions/mergeguez-pr-lifecycle/index.mjs";
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
  options: {
    launch?: (request: unknown) => Promise<unknown>;
    readWorkspaceHead?: (workspace: string, expectedHeadSha: string) => Promise<string>;
    pluginSource?: string;
  } = {},
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
  const source = options.pluginSource ?? packagedEntry;
  const projectedTasks = projectPackagedMergeguezTaskFlowRuntime(tasks, {
    id: pluginId,
    origin: "config",
    rootDir: source.slice(0, source.lastIndexOf("/")),
    source,
  });
  const api = {
    config: { plugins: { entries: { [pluginId]: { config } } } },
    pluginConfig: config,
    logger: { info() {}, warn() {}, error() {} },
    runtime: {
      tasks: projectedTasks,
      agent: { session: { getSessionEntry: () => null } },
      subagent: {
        run: async (request: unknown) => {
          launches.push(request);
          if (options.launch) {
            return await options.launch(request);
          }
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
    registerTool: (factory: (typeof tools)[number]["factory"], toolOptions: unknown) =>
      tools.push({ factory, options: toolOptions }),
    registerHttpRoute: (route: unknown) => routes.push(route),
    registerService: (service: unknown) => services.push(service),
    ...(options.readWorkspaceHead ? { testReadWorkspaceHead: options.readWorkspaceHead } : {}),
  };
  withPluginRuntimePluginScope({ pluginId, pluginSource: source, pluginOrigin: "config" }, () =>
    registerMergeguezPrLifecycle(api),
  );
  return { tools, routes, subscriptions, services, schedules, unschedules, launches };
}

it("projects controller parity through the loaded plugin record, without changing the shared runtime", () => {
  const tasks = createGatewayManagedTaskFlowRuntime();
  const builder = createTestPluginRegistry({ tasks } as PluginRuntime);
  const availability = (
    id: string,
    source: string,
    origin: "config" | "global",
    rootDir: string,
  ) => {
    const record = createPluginRecord({ id, source, origin, rootDir });
    builder.registry.plugins.push(record);
    return builder.createApi(record, { config: {}, registrationMode: "full" }).runtime.tasks;
  };
  const packaged = availability(pluginId, packagedEntry, "config", packagedRoot);
  expect(tasks.availability.controllerParity).toBe(false);
  expect(packaged?.availability.controllerParity).toBe(true);
  expect(packaged?.managedFlows.bindSession).toBe(tasks.managedFlows.bindSession);
  expect(
    availability(pluginId, oldEntry, "config", oldEntry.slice(0, oldEntry.lastIndexOf("/")))
      ?.availability.controllerParity,
  ).toBe(false);
  expect(
    availability(pluginId, packagedEntry, "global", packagedRoot)?.availability.controllerParity,
  ).toBe(false);
  expect(
    availability(pluginId, packagedEntry, "config", "/tmp/forged")?.availability.controllerParity,
  ).toBe(false);
  expect(
    availability("unrelated", packagedEntry, "config", packagedRoot)?.availability.controllerParity,
  ).toBe(false);
});

it("activates the packaged controller only for the real Gateway owner and exact source pin", async () => {
  await withOpenClawTestState(
    { label: "mergeguez-parity-registration", layout: "state-only" },
    async () => {
      const tasks = createGatewayManagedTaskFlowRuntime();
      expect(tasks.availability.controllerParity).toBe(false);
      const projected = (
        source: string,
        origin: "config" | "global",
        rootDir: string,
        id = pluginId,
      ) => projectPackagedMergeguezTaskFlowRuntime(tasks, { id, origin, rootDir, source });
      expect(projected(packagedEntry, "config", packagedRoot)?.availability.controllerParity).toBe(
        true,
      );
      expect(
        projected(oldEntry, "config", oldEntry.slice(0, oldEntry.lastIndexOf("/")))?.availability
          .controllerParity,
      ).toBe(false);
      expect(projected(packagedEntry, "global", packagedRoot)?.availability.controllerParity).toBe(
        false,
      );
      expect(projected(packagedEntry, "config", "/tmp/forged")?.availability.controllerParity).toBe(
        false,
      );
      expect(
        projected(packagedEntry, "config", packagedRoot, "unrelated")?.availability
          .controllerParity,
      ).toBe(false);
      const inert = registeredApi(pluginConfig(), tasks, { pluginSource: oldEntry });
      expect(inert.tools).toHaveLength(1);
      expect(inert.routes).toHaveLength(0);
      expect(inert.subscriptions).toHaveLength(0);
      expect(inert.services).toHaveLength(0);
      const inertTool = inert.tools[0];
      if (inertTool === undefined) {
        throw new Error("Expected the inert Mergeguez tool registration");
      }
      await expect(
        inertTool.factory({ sessionKey: ownerKey }).execute("call", {
          action: "status",
          flowId: "absent",
        }),
      ).rejects.toThrow(/not_enabled/u);

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
      const tasks = createGatewayManagedTaskFlowRuntime(resolveGatewayContext);
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
      const registration = registered.tools[0];
      if (registration === undefined) {
        throw new Error("Expected the Mergeguez tool registration");
      }
      const tool = registration.factory;
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

        const recovery = registered.services[0] as { start: () => Promise<void> };
        await callBackground(() => recovery.start());
        await callBackground(async () => {
          const bound = tasks.managedFlows.bindSession({ sessionKey: ownerKey });
          try {
            expect(await bound.get(flow.flowId)).toMatchObject({
              status: "waiting",
              stateJson: {
                phase: PHASE.REVIEW_WAITING,
                wait: { claimRef: "claim:synthetic-319" },
              },
            });
          } finally {
            await bound.close();
          }
        });
        expect(registered.launches).toHaveLength(0);

        const reviewRoute = registered.routes[1] as {
          handler: (request: unknown, response: unknown) => Promise<boolean>;
        };
        expect(reviewRoute).toMatchObject({
          path: "/plugins/mergeguez-pr-lifecycle/mergeguez",
          auth: "plugin",
          match: "exact",
        });
        const signedReview = async (
          label: string,
          claimRef: string,
          reviewedBaseSha: string,
          validSignature = true,
        ) => {
          const body = Buffer.from(
            JSON.stringify({
              repository: repo,
              pullRequest: 319,
              headSha,
              baseSha: reviewedBaseSha,
              claimRef,
              outcome: "approved",
              coverageComplete: true,
              findings: [],
            }),
          );
          const signature = createHmac("sha256", "synthetic-review-only")
            .update(body)
            .digest("hex");
          const request = Object.assign(Readable.from([body]), {
            method: "POST",
            headers: {
              "content-type": "application/json",
              "x-mergeguez-event": "review.completed",
              "x-mergeguez-delivery": `synthetic-real-gateway-${label}`,
              "x-mergeguez-signature-256": `sha256=${validSignature ? signature : "0".repeat(64)}`,
            },
            socket: { remoteAddress: "127.0.0.1" },
          });
          let payload: Record<string, unknown> | undefined;
          const response = {
            statusCode: 200,
            setHeader() {},
            end(value: string) {
              payload = JSON.parse(value) as Record<string, unknown>;
            },
          };
          await callBackground(() => reviewRoute.handler(request, response));
          return { status: response.statusCode, payload };
        };

        expect(
          await signedReview("wrong-signature", "claim:synthetic-319", baseSha, false),
        ).toMatchObject({ status: 401 });
        expect(await signedReview("stale-claim", "claim:old", baseSha)).toMatchObject({
          status: 202,
          payload: { reason: "stale_claim_result" },
        });
        expect(
          await signedReview("stale-base", "claim:synthetic-319", "c".repeat(40)),
        ).toMatchObject({ status: 202, payload: { reason: "stale_base_result" } });
        await callBackground(async () => {
          const bound = tasks.managedFlows.bindSession({ sessionKey: ownerKey });
          try {
            expect(await bound.get(flow.flowId)).toMatchObject({
              revision: flow.revision + 1,
              status: "waiting",
              stateJson: { phase: PHASE.REVIEW_WAITING },
            });
          } finally {
            await bound.close();
          }
        });
        expect(await signedReview("matching", "claim:synthetic-319", baseSha)).toMatchObject({
          status: 202,
          payload: { accepted: true },
        });
        await callBackground(async () => {
          const bound = tasks.managedFlows.bindSession({ sessionKey: ownerKey });
          try {
            expect(await bound.get(flow.flowId)).toMatchObject({
              revision: flow.revision + 2,
              stateJson: { phase: PHASE.MERGE_READY },
            });
          } finally {
            await bound.close();
          }
        });
        expect(registered.launches).toHaveLength(0);

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

it("admits one packaged native root and never relaunches after a lost acknowledgement", async () => {
  await withOpenClawTestState(
    { label: "mergeguez-parity-launch-race", layout: "state-only" },
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
      const nativeContext = captureOpenClawStateWorkerContext();
      const tasks = createGatewayManagedTaskFlowRuntime(resolveGatewayContext);
      const policy = __testing.normalizeRuntimeConfig(config).repositories.get(repo);
      const initial = createState(
        {
          eventId: "github:synthetic-launch",
          action: "opened",
          repo,
          prNumber: 321,
          headSha,
          baseSha,
          baseRef: "dev",
          headRepo: repo,
        },
        policy,
      );
      const flow = await executeManagedTaskFlowFixtureWrite(nativeContext, {
        type: "tasks.managedFlows.create",
        input: {
          ownerKey,
          controllerId: CONTROLLER_ID,
          goal: "Launch one synthetic native review root",
          status: "queued",
          stateJson: initial,
        },
      });
      const nativeRunId = "mergeguez-parity-launched-root";
      const readPersistedRoot = async () => {
        const reply = await executeExistingOpenClawStateRead(
          { path: nativeContext.admission.databasePath, env: nativeContext.environment },
          { type: "subagents.runs", scope: { kind: "ids", runIds: [nativeRunId] } },
          { context: nativeContext, current: true },
        );
        if (!reply?.ok || reply.type !== "subagents.runs") {
          throw new Error("Persisted native root observation unavailable");
        }
        return reply.runs.get(nativeRunId);
      };
      let enteredLaunch!: () => void;
      let releaseLaunch!: () => void;
      const launched = new Promise<void>((resolve) => {
        enteredLaunch = resolve;
      });
      const release = new Promise<void>((resolve) => {
        releaseLaunch = resolve;
      });
      const registered = registeredApi(config, tasks, {
        readWorkspaceHead: async () => headSha,
        launch: async (request) => {
          const launch = request as { sessionKey: string; managedFlowLaunch: object };
          const admitted = consumeGatewayManagedFlowNativeLaunch(
            launch.managedFlowLaunch,
            pluginId,
            launch.sessionKey,
          );
          admitted.assertCurrent();
          expect(() =>
            consumeGatewayManagedFlowNativeLaunch(
              launch.managedFlowLaunch,
              pluginId,
              launch.sessionKey,
            ),
          ).toThrow(/exact current managed-flow capability/u);
          const native = createSubagentRunRecord({
            runId: nativeRunId,
            childSessionKey: launch.sessionKey,
            requesterSessionKey: ownerKey,
            controllerSessionKey: ownerKey,
            label: `plugin:${pluginId}`,
            generation: 1,
            expectsCompletionMessage: false,
          });
          const row = bindSubagentRunRecord(native);
          const saved = await executeManagedTaskFlowFixtureWrite(nativeContext, {
            type: "subagents.persistChanges",
            input: {
              writeId: "mergeguez-parity-one-launch",
              values: [row],
              deleteRunIds: [],
              versions: [{ runId: nativeRunId, version: null }],
              managedFlowLaunchClaim: {
                ownerKey: admitted.ownerKey,
                controllerId: admitted.controllerId,
                flowId: admitted.flowId,
                revision: admitted.revision,
                childSessionKey: admitted.childSessionKey,
              },
            },
          });
          expect(saved).toMatchObject({ writeId: "mergeguez-parity-one-launch" });
          expect(await readPersistedRoot()).toMatchObject({
            runId: nativeRunId,
            childSessionKey: launch.sessionKey,
            requesterSessionKey: ownerKey,
            controllerSessionKey: ownerKey,
            generation: 1,
            label: `plugin:${pluginId}`,
          });
          enteredLaunch();
          await release;
          throw new Error("synthetic_acknowledgement_lost_after_native_admission");
        },
      });
      const callBackground = async <T>(run: () => Promise<T>): Promise<T> =>
        withPluginRuntimeGatewayRequestScope(
          { context, resolveGatewayContext, client: null, isWebchatConnect: () => false },
          () => instance.run(run),
        );
      const registration = registered.tools[0];
      if (registration === undefined) {
        throw new Error("Expected the Mergeguez tool registration");
      }
      const tool = registration.factory({ sessionKey: ownerKey, agentId: "franck" });
      try {
        const first = callBackground(() =>
          tool.execute("first", { action: "continue", flowId: flow.flowId }),
        );
        await Promise.race([
          launched,
          first.then(() => {
            throw new Error("controller completed before entering the native launch stub");
          }),
        ]);
        const concurrent = await callBackground(() =>
          tool.execute("concurrent", { action: "continue", flowId: flow.flowId }),
        );
        expect(concurrent.details).toMatchObject({ ok: true });
        expect(registered.launches).toHaveLength(1);
        releaseLaunch();
        const uncertain = await first;
        expect(uncertain.details).toMatchObject({
          ok: true,
          flow: { blocker: "worker_launch_outcome_unknown" },
        });
        const recovery = registered.services[0] as { start: () => Promise<void> };
        await callBackground(() => recovery.start());
        expect(registered.launches).toHaveLength(1);
        await callBackground(async () => {
          const bound = tasks.managedFlows.bindSession({ sessionKey: ownerKey });
          try {
            expect(await bound.get(flow.flowId)).toMatchObject({
              status: "blocked",
              stateJson: {
                phase: PHASE.BLOCKED,
                blocker: "worker_launch_outcome_unknown",
                activeWorker: { runId: nativeRunId },
              },
            });
            expect(await readPersistedRoot()).toMatchObject({
              runId: nativeRunId,
              requesterSessionKey: ownerKey,
              controllerSessionKey: ownerKey,
              generation: 1,
              label: `plugin:${pluginId}`,
            });
          } finally {
            await bound.close();
          }
        });
      } finally {
        releaseLaunch();
        await instance.dispose();
      }
    },
  );
});
