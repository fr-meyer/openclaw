import { expect, it } from "vitest";
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

const ownerKey = "agent:main:publisher";
const childSessionKey = "agent:reviewer:subagent:managed-worker";
const statusSessionKey = "agent:status:main";
const controllerId = "publisher/v1";

it("binds status and worker views only to the current client actor and exact native run", async () => {
  await withOpenClawTestState(
    { label: "managed-flow-client-scope", layout: "state-only" },
    async () => {
      const cfg = {
        plugins: {
          entries: {
            publisher: {
              config: {
                ownerSessionKey: ownerKey,
                statusAgentIds: ["status"],
              },
            },
          },
        },
      } as OpenClawConfig;
      const context = createDirectChatContext({
        getRuntimeConfig: () => cfg,
        validateAgentRuntimeApprovalAuthority: () => true,
      });
      const resolveGatewayContext = () => context;
      const registry = createEmptyPluginRegistry();
      const record = createPluginRecord({ id: "publisher" });
      registry.plugins.push(record);
      const instance = new PluginInstance("publisher", { record, registry });
      const runtime = createGatewayManagedTaskFlowRuntime(resolveGatewayContext);
      const nativeContext = captureOpenClawStateWorkerContext();
      const statusFlow = await executeManagedTaskFlowFixtureWrite(nativeContext, {
        type: "tasks.managedFlows.create",
        input: { ownerKey, controllerId, goal: "Status may inspect", status: "queued" },
      });
      const nativeRun = createSubagentRunRecord({
        runId: "managed-worker-run",
        childSessionKey,
        requesterSessionKey: ownerKey,
        controllerSessionKey: ownerKey,
        label: "plugin:publisher",
        generation: 3,
        expectsCompletionMessage: false,
      });
      const nativeRow = bindSubagentRunRecord(nativeRun);
      await executeManagedTaskFlowFixtureWrite(nativeContext, {
        type: "subagents.persistChanges",
        input: {
          writeId: "managed-flow-client-worker",
          values: [nativeRow],
          deleteRunIds: [],
          versions: [{ runId: nativeRun.runId, version: null }],
        },
      });
      const activeWorker = {
        sessionKey: childSessionKey,
        runId: nativeRun.runId,
        taskId: nativeRun.runId,
        nativeGeneration: 3,
      };
      const workerFlow = await executeManagedTaskFlowFixtureWrite(nativeContext, {
        type: "tasks.managedFlows.create",
        input: {
          ownerKey,
          controllerId,
          goal: "Worker may report",
          status: "running",
          stateJson: { activeWorker },
        },
      });
      const clientFor = (
        agentId: string,
        sessionKey: string,
        signal: AbortSignal,
        runId?: string,
      ): GatewayClient =>
        ({
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
        }) as unknown as GatewayClient;
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
      try {
        const statusController = new AbortController();
        await callAs(clientFor("status", statusSessionKey, statusController.signal), async () => {
          const bound = runtime.managedFlows.bindSession({ sessionKey: ownerKey });
          try {
            expect(await bound.get(statusFlow.flowId)).toMatchObject({ flowId: statusFlow.flowId });
            expect((await bound.list()).map((flow) => flow.flowId)).toContain(workerFlow.flowId);
            await expect(
              bound.setWaiting({
                flowId: statusFlow.flowId,
                expectedRevision: statusFlow.revision,
              }),
            ).rejects.toThrow(/status agent/u);
            await expect(
              bound.captureNativeLaunch({
                flowId: workerFlow.flowId,
                expectedRevision: workerFlow.revision,
                childSessionKey,
              }),
            ).rejects.toThrow(/owner actor/u);
            expect(() => runtime.runs.bindSession({ sessionKey: ownerKey })).toThrow(
              /canonical bound set/u,
            );
          } finally {
            await bound.close();
          }
        });

        const workerController = new AbortController();
        await callAs(
          clientFor("reviewer", childSessionKey, workerController.signal, nativeRun.runId),
          async () => {
            const bound = runtime.managedFlows.bindSession({ sessionKey: ownerKey });
            try {
              expect(await bound.get(workerFlow.flowId)).toMatchObject({
                flowId: workerFlow.flowId,
              });
              expect(await bound.get(statusFlow.flowId)).toBeUndefined();
              await expect(bound.list()).rejects.toThrow(/exact current managed flow/u);
              expect(
                await bound.setWaiting({
                  flowId: workerFlow.flowId,
                  expectedRevision: workerFlow.revision,
                  stateJson: { activeWorker },
                }),
              ).toMatchObject({ applied: true, flow: { revision: workerFlow.revision + 1 } });
              await expect(
                bound.setWaiting({
                  flowId: statusFlow.flowId,
                  expectedRevision: statusFlow.revision,
                }),
              ).rejects.toThrow(/exact current native flow grant/u);
            } finally {
              await bound.close();
            }
          },
        );

        const revoked = new AbortController();
        let enterRevalidation!: () => void;
        let releaseRevalidation!: () => void;
        const entered = new Promise<void>((resolve) => {
          enterRevalidation = resolve;
        });
        const gate = new Promise<void>((resolve) => {
          releaseRevalidation = resolve;
        });
        await callAs(
          clientFor("status", statusSessionKey, revoked.signal),
          async () => {
            const bound = runtime.managedFlows.bindSession({ sessionKey: ownerKey });
            const pending = bound.get(statusFlow.flowId);
            await entered;
            revoked.abort(new Error("client retired during state read"));
            releaseRevalidation();
            await expect(pending).rejects.toThrow(/retired|closed|client/i);
            await bound.close();
          },
          async () => {
            enterRevalidation();
            await gate;
          },
        );
      } finally {
        await instance.dispose();
      }
    },
  );
});
