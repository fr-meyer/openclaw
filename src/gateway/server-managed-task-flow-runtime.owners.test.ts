import { expect, it } from "vitest";
import type { OpenClawConfig } from "../config/types.openclaw.js";
import { PluginInstance } from "../plugins/plugin-instance.js";
import { createEmptyPluginRegistry } from "../plugins/registry-empty.js";
import { withPluginRuntimeGatewayRequestScope } from "../plugins/runtime/gateway-request-scope.js";
import { createPluginRecord } from "../plugins/status.test-helpers.js";
import { captureOpenClawStateWorkerContext } from "../state/openclaw-state-worker-context.js";
import { executeManagedTaskFlowFixtureWrite } from "../tasks/managed-task-flow.test-helpers.js";
import { withOpenClawTestState } from "../test-utils/openclaw-test-state.js";
import { createDirectChatContext } from "./server-chat.agent-events.test-helpers.js";
import {
  configuredManagedFlowOwners,
  consumeGatewayManagedFlowNativeLaunch,
  createGatewayManagedTaskFlowRuntime,
  isClaimedManagedFlowNativeRun,
} from "./server-managed-task-flow-runtime.js";

const ownerKey = "agent:main:publisher";
const legacyKey = "agent:main:legacy";
const repoKey = "agent:main:repo-owner";

function config(pluginConfig: unknown): OpenClawConfig {
  return {
    plugins: { entries: { publisher: { config: pluginConfig } } },
  } as OpenClawConfig;
}

it("selects only the live publisher's configured owner roster", () => {
  const current = config({
    ownerSessionKey: ownerKey,
    legacyOwnerSessionKeys: [legacyKey],
    repositories: { "example/repo": { ownerSessionKey: repoKey } },
  });
  expect(configuredManagedFlowOwners(current, "publisher", ownerKey)).toEqual([
    ownerKey,
    legacyKey,
    repoKey,
  ]);
  expect(() => configuredManagedFlowOwners(current, "publisher", "agent:main:unrelated")).toThrow(
    /canonical bound set/u,
  );
  expect(configuredManagedFlowOwners(current, "other-plugin", ownerKey)).toEqual([ownerKey]);
  expect(
    configuredManagedFlowOwners(
      config({
        legacyOwnerSessionKeys: [legacyKey],
        repositories: { repo: { ownerSessionKey: repoKey } },
      }),
      "publisher",
      repoKey,
    ),
  ).toEqual([legacyKey, repoKey]);
});

it("fails closed for malformed or incognito configured owners", () => {
  expect(() =>
    configuredManagedFlowOwners(
      config({ ownerSessionKey: ownerKey, legacyOwnerSessionKeys: [42] }),
      "publisher",
      ownerKey,
    ),
  ).toThrow(/malformed/u);
  expect(() =>
    configuredManagedFlowOwners(
      config({
        ownerSessionKey: ownerKey,
        legacyOwnerSessionKeys: ["agent:main:dashboard:incognito-secret"],
      }),
      "publisher",
      ownerKey,
    ),
  ).toThrow(/canonical bound set/u);
});

it("observes only native runs claimed by the exact controller flow", () => {
  const childSessionKey = "agent:reviewer:subagent:current";
  const claim = {
    sessionKey: childSessionKey,
    runId: "run-current",
    taskId: "task-current",
    nativeGeneration: 4,
  };
  const flow = {
    flowId: "flow-current",
    ownerKey,
    controllerId: "publisher/v1",
    stateJson: { activeWorker: claim },
  };
  const run = {
    id: "task-current",
    runId: "run-current",
    childSessionKey,
    requesterSessionKey: ownerKey,
    generation: 4,
    observationSource: "native-subagent",
    label: "plugin:publisher",
  };
  const visible = (candidate: unknown, flows: readonly unknown[] = [flow]) =>
    isClaimedManagedFlowNativeRun(candidate, flows, ownerKey, "publisher/v1");

  expect(visible(run)).toBe(true);
  expect(visible(run, [{ ...flow, stateJson: { orphanedWorker: claim } }])).toBe(true);
  expect(visible({ ...run, label: "plugin:other" })).toBe(false);
  expect(visible({ ...run, requesterSessionKey: "agent:main:foreign" })).toBe(false);
  expect(visible({ ...run, observationSource: "legacy" })).toBe(false);
  expect(visible({ ...run, runId: "run-replaced" })).toBe(false);
  expect(visible({ ...run, id: "task-replaced" })).toBe(false);
  expect(visible({ ...run, childSessionKey: "agent:reviewer:subagent:other" })).toBe(false);
  expect(visible({ ...run, generation: 0 })).toBe(false);
  expect(visible({ ...run, generation: 5 })).toBe(false);
  expect(visible(run, [{ ...flow, ownerKey: "agent:main:other" }])).toBe(false);
  expect(visible(run, [{ ...flow, controllerId: "other/v1" }])).toBe(false);
  expect(
    visible(run, [{ ...flow, stateJson: { activeWorker: { ...claim, runId: "run-replaced" } } }]),
  ).toBe(false);
  expect(visible(run, [])).toBe(false);
});

it("mints a one-use launch only through the live plugin and exact owner-bound flow", async () => {
  await withOpenClawTestState({ label: "managed-flow-binding", layout: "state-only" }, async () => {
    const cfg = config({ ownerSessionKey: ownerKey });
    const context = createDirectChatContext({ getRuntimeConfig: () => cfg });
    const resolveGatewayContext = () => context;
    const registry = createEmptyPluginRegistry();
    const record = createPluginRecord({ id: "publisher" });
    registry.plugins.push(record);
    const instance = new PluginInstance("publisher", { record, registry });
    const nativeContext = captureOpenClawStateWorkerContext();
    const childSessionKey = "agent:reviewer:subagent:one-use-launch";
    const flow = await executeManagedTaskFlowFixtureWrite(nativeContext, {
      type: "tasks.managedFlows.create",
      input: {
        ownerKey,
        controllerId: "publisher/v1",
        goal: "Admit one native launch",
        status: "running",
        stateJson: {
          activeWorker: { sessionKey: childSessionKey, runId: null, taskId: null },
          launchOutcome: { status: "unknown", sessionKey: childSessionKey },
        },
      },
    });
    const runtime = createGatewayManagedTaskFlowRuntime(resolveGatewayContext);
    const scope = {
      context,
      resolveGatewayContext,
      isWebchatConnect: () => false,
    };
    try {
      expect(() =>
        withPluginRuntimeGatewayRequestScope({ ...scope, pluginId: "publisher" }, () =>
          runtime.managedFlows.bindSession({ sessionKey: ownerKey }),
        ),
      ).toThrow(/current plugin instance and original Gateway binding/u);
      // The admitted instance adds its identity to the existing Gateway request.
      await withPluginRuntimeGatewayRequestScope(scope, () =>
        instance.run(async () => {
          expect(() => runtime.runs.bindSession({ sessionKey: childSessionKey })).toThrow(
            /configured owner|canonical bound set/u,
          );
          const ownerRuns = runtime.runs.bindSession({ sessionKey: ownerKey });
          await ownerRuns.close();
          const bound = runtime.managedFlows.bindSession({ sessionKey: ownerKey });
          try {
            await expect(
              bound.captureNativeLaunch({
                flowId: flow.flowId,
                expectedRevision: flow.revision + 1,
                childSessionKey,
              }),
            ).rejects.toThrow(/exact prelaunch flow claim/u);
            const token = await bound.captureNativeLaunch({
              flowId: flow.flowId,
              expectedRevision: flow.revision,
              childSessionKey,
            });
            expect(() =>
              consumeGatewayManagedFlowNativeLaunch({}, "publisher", childSessionKey),
            ).toThrow(/exact current managed-flow capability/u);
            expect(() =>
              consumeGatewayManagedFlowNativeLaunch({ ...token }, "publisher", childSessionKey),
            ).toThrow(/exact current managed-flow capability/u);
            expect(() =>
              consumeGatewayManagedFlowNativeLaunch(token, "other-plugin", childSessionKey),
            ).toThrow(/exact current managed-flow capability/u);
            expect(() =>
              consumeGatewayManagedFlowNativeLaunch(
                token,
                "publisher",
                "agent:reviewer:subagent:other",
              ),
            ).toThrow(/exact current managed-flow capability/u);
            expect(
              consumeGatewayManagedFlowNativeLaunch(token, "publisher", childSessionKey),
            ).toMatchObject({
              ownerKey,
              controllerId: "publisher/v1",
              flowId: flow.flowId,
              revision: flow.revision,
              childSessionKey,
            });
            expect(() =>
              consumeGatewayManagedFlowNativeLaunch(token, "publisher", childSessionKey),
            ).toThrow(/exact current managed-flow capability/u);
            const stale = await bound.captureNativeLaunch({
              flowId: flow.flowId,
              expectedRevision: flow.revision,
              childSessionKey,
            });
            await bound.close();
            expect(() =>
              consumeGatewayManagedFlowNativeLaunch(stale, "publisher", childSessionKey),
            ).toThrow(/binding closed/u);
          } finally {
            await bound.close();
          }
        }),
      );
    } finally {
      await instance.dispose();
    }
  });
});
