import { expect, it } from "vitest";
import { createSubagentRunRecord } from "../agents/subagent-test-fixtures.test-helpers.js";
import { bindSubagentRunRecord } from "../agents/subagents/registry/subagent-registry.store.codec.js";
import { OPENCLAW_STATE_SCHEMA_VERSION } from "../state/openclaw-state-db-contract.js";
import { executeExistingOpenClawStateRead } from "../state/openclaw-state-db-readonly.js";
import { openOpenClawStateDatabase } from "../state/openclaw-state-db.js";
import { captureOpenClawStateWorkerContext } from "../state/openclaw-state-worker-context.js";
import { closeStateDatabaseForTest } from "../test-utils/database-cleanup.js";
import { withOpenClawTestState } from "../test-utils/openclaw-test-state.js";
import { executeManagedTaskFlowFixtureWrite } from "./managed-task-flow.test-helpers.js";

const ownerKey = "agent:main:publisher";
const foreignOwnerKey = "agent:main:foreign";
const controllerId = "publisher/v1";

it("persists managed flows and unknown native runs through the schema-20 state workers", async () => {
  await withOpenClawTestState(
    { label: "managed-flow-worker", layout: "state-only" },
    async (state) => {
      const database = openOpenClawStateDatabase({ env: state.env });
      expect(OPENCLAW_STATE_SCHEMA_VERSION).toBe(20);
      const context = captureOpenClawStateWorkerContext({ path: database.path, env: state.env });
      const read = async (command: Parameters<typeof executeExistingOpenClawStateRead>[1]) => {
        const reply = await executeExistingOpenClawStateRead(
          { path: database.path, env: state.env },
          command,
          { context, current: true },
        );
        expect(reply?.ok).toBe(true);
        return reply;
      };

      const created = await executeManagedTaskFlowFixtureWrite(context, {
        type: "tasks.managedFlows.create",
        input: {
          ownerKey,
          controllerId,
          goal: "Publish one exact head",
          stateJson: { repo: "example/repo", prNumber: 7 },
          dedupe: { stateFields: ["repo", "prNumber"] },
        },
      });
      const duplicate = await executeManagedTaskFlowFixtureWrite(context, {
        type: "tasks.managedFlows.create",
        input: {
          ownerKey,
          controllerId,
          goal: "Duplicate event",
          stateJson: { repo: "example/repo", prNumber: 7 },
          dedupe: { stateFields: ["repo", "prNumber"] },
        },
      });
      expect(duplicate).toMatchObject({ flowId: created.flowId, deduplicated: true });
      expect(
        await read({
          type: "tasks.managedFlows.get",
          input: { ownerKey: foreignOwnerKey, controllerId, flowId: created.flowId },
        }),
      ).toMatchObject({
        type: "tasks.managedFlows.get",
        value: undefined,
      });
      expect(
        await read({
          type: "tasks.managedFlows.get",
          input: { ownerKey, controllerId: "foreign/v1", flowId: created.flowId },
        }),
      ).toMatchObject({
        type: "tasks.managedFlows.get",
        value: undefined,
      });

      const firstCapacity = await read({
        type: "tasks.managedFlows.capacitySnapshot",
        input: { ownerKey, controllerId, ownerSessionKeys: [ownerKey] },
      });
      if (
        !firstCapacity ||
        firstCapacity.type !== "tasks.managedFlows.capacitySnapshot" ||
        !firstCapacity.ok
      ) {
        throw new Error("Missing admitted capacity snapshot");
      }
      await executeManagedTaskFlowFixtureWrite(context, {
        type: "tasks.managedFlows.create",
        input: { ownerKey, controllerId, goal: "Concurrent admitted flow" },
      });
      expect(
        await executeManagedTaskFlowFixtureWrite(context, {
          type: "tasks.managedFlows.reserve",
          input: {
            ownerKey,
            controllerId,
            flowId: created.flowId,
            expectedRevision: 0,
            mutation: "resume",
            status: "running",
            capacitySnapshot: firstCapacity.value,
          },
        }),
      ).toMatchObject({ applied: false, code: "capacity_snapshot_conflict" });
      const currentCapacity = await read({
        type: "tasks.managedFlows.capacitySnapshot",
        input: { ownerKey, controllerId, ownerSessionKeys: [ownerKey] },
      });
      if (
        !currentCapacity ||
        currentCapacity.type !== "tasks.managedFlows.capacitySnapshot" ||
        !currentCapacity.ok
      ) {
        throw new Error("Missing current capacity snapshot");
      }
      expect(
        await executeManagedTaskFlowFixtureWrite(context, {
          type: "tasks.managedFlows.reserve",
          input: {
            ownerKey,
            controllerId,
            flowId: created.flowId,
            expectedRevision: 0,
            mutation: "resume",
            status: "running",
            capacitySnapshot: currentCapacity.value,
          },
        }),
      ).toMatchObject({ applied: true, flow: { revision: 1, status: "running" } });
      expect(
        await executeManagedTaskFlowFixtureWrite(context, {
          type: "tasks.managedFlows.mutate",
          input: {
            ownerKey,
            controllerId,
            flowId: created.flowId,
            expectedRevision: 0,
            mutation: "finish",
          },
        }),
      ).toMatchObject({ applied: false, code: "revision_conflict", current: { revision: 1 } });

      // A native run with no proved terminal outcome must remain unknown. The bridge
      // observes the original row; it never changes delivery state or replays a send.
      const unknownRun = createSubagentRunRecord({
        runId: "unknown-native-send",
        childSessionKey: "agent:worker:subagent:unknown-native-send",
        requesterSessionKey: ownerKey,
        controllerSessionKey: ownerKey,
        label: "plugin:publisher",
        endedAt: Date.now(),
        delivery: { status: "pending" },
      });
      const row = bindSubagentRunRecord(unknownRun);
      await executeManagedTaskFlowFixtureWrite(context, {
        type: "subagents.persistChanges",
        input: {
          writeId: "managed-flow-native-observation",
          values: [row],
          deleteRunIds: [],
          versions: [{ runId: row.run_id, version: null }],
        },
      });
      const observed = await read({
        type: "tasks.runs.get",
        input: { ownerKey, controllerId, taskId: unknownRun.runId, legacyOwnerObservation: false },
      });
      expect(observed).toMatchObject({
        type: "tasks.runs.get",
        value: {
          id: unknownRun.runId,
          status: "unknown",
          deliveryStatus: "pending",
          observationSource: "native-subagent",
        },
      });
      expect(
        await read({
          type: "tasks.runs.get",
          input: {
            ownerKey: foreignOwnerKey,
            controllerId,
            taskId: unknownRun.runId,
            legacyOwnerObservation: false,
          },
        }),
      ).toMatchObject({ type: "tasks.runs.get", value: undefined });

      const liveChild = "agent:reviewer:subagent:live-native";
      const liveRun = createSubagentRunRecord({
        runId: "live-native",
        childSessionKey: liveChild,
        requesterSessionKey: ownerKey,
        controllerSessionKey: "agent:reviewer:main",
        label: "plugin:publisher",
        generation: 1,
      });
      const liveRow = bindSubagentRunRecord(liveRun);
      const livePersist = await executeManagedTaskFlowFixtureWrite(context, {
        type: "subagents.persistChanges",
        input: {
          writeId: "managed-flow-live-native",
          values: [liveRow],
          deleteRunIds: [],
          versions: [{ runId: liveRow.run_id, version: null }],
        },
      });
      if ("conflictRunIds" in livePersist) {
        throw new Error("Live native fixture unexpectedly conflicted");
      }
      const workerFlow = await executeManagedTaskFlowFixtureWrite(context, {
        type: "tasks.managedFlows.create",
        input: {
          ownerKey,
          controllerId,
          goal: "Prove worker transition",
          stateJson: {
            activeWorker: {
              sessionKey: liveChild,
              runId: liveRun.runId,
              taskId: liveRun.runId,
              nativeGeneration: 1,
            },
          },
        },
      });
      const mutation = {
        ownerKey,
        controllerId,
        flowId: workerFlow.flowId,
        expectedRevision: 0,
        mutation: "setWaiting" as const,
        nativeWorkerGrant: {
          childSessionKey: liveChild,
          runId: liveRun.runId,
          generation: 1,
          taskId: liveRun.runId,
        },
      };
      await expect(
        executeManagedTaskFlowFixtureWrite(context, {
          type: "tasks.managedFlows.mutate",
          input: {
            ...mutation,
            nativeWorkerGrant: { ...mutation.nativeWorkerGrant, generation: 2 },
          },
        }),
      ).rejects.toThrow("Worker flow mutation no longer targets its claimed active run");
      expect(
        await read({
          type: "tasks.managedFlows.get",
          input: { ownerKey, controllerId, flowId: workerFlow.flowId },
        }),
      ).toMatchObject({
        value: { revision: 0, status: "queued", stateJson: workerFlow.stateJson },
      });
      expect(
        await executeManagedTaskFlowFixtureWrite(context, {
          type: "tasks.managedFlows.mutate",
          input: mutation,
        }),
      ).toMatchObject({ applied: true, flow: { revision: 1 } });

      // Keep the flow's exact claim while the native owner advances its generation.
      // This reaches the native-row predicate after the flow-claim predicate passes.
      const replacedNative = await executeManagedTaskFlowFixtureWrite(context, {
        type: "subagents.persistChanges",
        input: {
          writeId: "managed-flow-native-generation-replaced",
          values: [bindSubagentRunRecord({ ...liveRun, generation: 2 })],
          deleteRunIds: [],
          versions: [
            { runId: liveRun.runId, version: livePersist.versions.get(liveRun.runId) ?? null },
          ],
        },
      });
      if ("conflictRunIds" in replacedNative) {
        throw new Error("Native generation replacement unexpectedly conflicted");
      }
      expect(
        await read({
          type: "tasks.runs.get",
          input: { ownerKey, controllerId, taskId: liveRun.runId, legacyOwnerObservation: false },
        }),
      ).toMatchObject({
        value: { runId: liveRun.runId, generation: 2, status: "running" },
      });
      await expect(
        executeManagedTaskFlowFixtureWrite(context, {
          type: "tasks.managedFlows.mutate",
          input: { ...mutation, expectedRevision: 1 },
        }),
      ).rejects.toThrow("Worker flow mutation native run generation has retired");
      expect(
        await read({
          type: "tasks.managedFlows.get",
          input: { ownerKey, controllerId, flowId: workerFlow.flowId },
        }),
      ).toMatchObject({
        value: { revision: 1, status: "waiting", stateJson: workerFlow.stateJson },
      });
      expect(
        await executeManagedTaskFlowFixtureWrite(context, {
          type: "tasks.managedFlows.mutate",
          input: {
            ownerKey,
            controllerId,
            flowId: workerFlow.flowId,
            expectedRevision: 1,
            mutation: "resume",
            stateJson: {
              activeWorker: {
                sessionKey: "agent:reviewer:subagent:replacement",
                runId: "replacement",
              },
            },
          },
        }),
      ).toMatchObject({ applied: true, flow: { revision: 2 } });
      await expect(
        executeManagedTaskFlowFixtureWrite(context, {
          type: "tasks.managedFlows.mutate",
          input: { ...mutation, expectedRevision: 2 },
        }),
      ).rejects.toThrow(/no longer targets its claimed active run/u);
      expect(
        await read({
          type: "tasks.managedFlows.get",
          input: { ownerKey, controllerId, flowId: workerFlow.flowId },
        }),
      ).toMatchObject({
        value: {
          revision: 2,
          status: "queued",
          stateJson: {
            activeWorker: {
              sessionKey: "agent:reviewer:subagent:replacement",
              runId: "replacement",
            },
          },
        },
      });

      const cancelRun = createSubagentRunRecord({
        runId: "native-cancel-root",
        childSessionKey: "agent:reviewer:subagent:native-cancel-root",
        requesterSessionKey: ownerKey,
        controllerSessionKey: "agent:reviewer:main",
        label: "plugin:publisher",
        generation: 7,
      });
      const cancelRow = bindSubagentRunRecord(cancelRun);
      const nativePersist = await executeManagedTaskFlowFixtureWrite(context, {
        type: "subagents.persistChanges",
        input: {
          writeId: "managed-flow-cancel-native",
          values: [cancelRow],
          deleteRunIds: [],
          versions: [{ runId: cancelRow.run_id, version: null }],
        },
      });
      if ("conflictRunIds" in nativePersist) {
        throw new Error("Native cancel fixture unexpectedly conflicted");
      }
      const cancelFlow = await executeManagedTaskFlowFixtureWrite(context, {
        type: "tasks.managedFlows.create",
        input: {
          ownerKey,
          controllerId,
          goal: "Cancel exact claimed native root",
          stateJson: {
            activeWorker: {
              sessionKey: cancelRun.childSessionKey,
              runId: cancelRun.runId,
              taskId: cancelRun.runId,
              nativeGeneration: cancelRun.generation,
            },
          },
        },
      });
      const claim = {
        ownerKey,
        controllerId,
        flowId: cancelFlow.flowId,
        revision: cancelFlow.revision,
        childSessionKey: cancelRun.childSessionKey,
        runId: cancelRun.runId,
        taskId: cancelRun.runId,
        generation: cancelRun.generation,
      };
      const killRow = bindSubagentRunRecord({
        ...cancelRun,
        killIntent: { requestedAt: Date.now(), reason: "killed" },
      });
      const killWrite = (suffix: string, managedFlowKillClaim: typeof claim) => ({
        type: "subagents.persistChanges" as const,
        input: {
          writeId: `managed-flow-cancel-${suffix}`,
          values: [killRow],
          deleteRunIds: [],
          versions: [
            {
              runId: cancelRun.runId,
              version: nativePersist.versions.get(cancelRun.runId) ?? null,
            },
          ],
          managedFlowKillClaim,
        },
      });
      await expect(
        executeManagedTaskFlowFixtureWrite(
          context,
          killWrite("stale-revision", {
            ...claim,
            revision: claim.revision + 1,
          }),
        ),
      ).rejects.toThrow(/changed before native admission/u);
      await expect(
        executeManagedTaskFlowFixtureWrite(
          context,
          killWrite("replaced-worker", {
            ...claim,
            runId: "replaced-run",
          }),
        ),
      ).rejects.toThrow(/exact native root|no longer names its worker/u);
      await expect(
        executeManagedTaskFlowFixtureWrite(
          context,
          killWrite("reused-generation", {
            ...claim,
            generation: claim.generation + 1,
          }),
        ),
      ).rejects.toThrow(/no longer names its worker/u);
      await expect(
        executeManagedTaskFlowFixtureWrite(
          context,
          killWrite("foreign-controller", {
            ...claim,
            controllerId: "other/v1",
          }),
        ),
      ).rejects.toThrow(/changed before native admission/u);

      const otherOwnerRun = createSubagentRunRecord({
        runId: "same-plugin-other-owner",
        childSessionKey: "agent:reviewer:subagent:other-owner",
        requesterSessionKey: foreignOwnerKey,
        controllerSessionKey: "agent:reviewer:main",
        label: "plugin:publisher",
        generation: 1,
      });
      const otherOwnerRow = bindSubagentRunRecord(otherOwnerRun);
      const otherOwnerPersist = await executeManagedTaskFlowFixtureWrite(context, {
        type: "subagents.persistChanges",
        input: {
          writeId: "managed-flow-other-owner-native",
          values: [otherOwnerRow],
          deleteRunIds: [],
          versions: [{ runId: otherOwnerRun.runId, version: null }],
        },
      });
      if ("conflictRunIds" in otherOwnerPersist) {
        throw new Error("Other-owner native fixture unexpectedly conflicted");
      }
      const claimedOtherOwnerFlow = await executeManagedTaskFlowFixtureWrite(context, {
        type: "tasks.managedFlows.create",
        input: {
          ownerKey,
          controllerId,
          goal: "Reject same-plugin cross-owner claim",
          stateJson: {
            activeWorker: {
              sessionKey: otherOwnerRun.childSessionKey,
              runId: otherOwnerRun.runId,
              taskId: otherOwnerRun.runId,
              nativeGeneration: otherOwnerRun.generation,
            },
          },
        },
      });
      await expect(
        executeManagedTaskFlowFixtureWrite(context, {
          type: "subagents.persistChanges",
          input: {
            writeId: "managed-flow-cross-owner-denied",
            values: [
              bindSubagentRunRecord({
                ...otherOwnerRun,
                killIntent: { requestedAt: Date.now(), reason: "killed" },
              }),
            ],
            deleteRunIds: [],
            versions: [
              {
                runId: otherOwnerRun.runId,
                version: otherOwnerPersist.versions.get(otherOwnerRun.runId) ?? null,
              },
            ],
            managedFlowKillClaim: {
              ownerKey,
              controllerId,
              flowId: claimedOtherOwnerFlow.flowId,
              revision: claimedOtherOwnerFlow.revision,
              childSessionKey: otherOwnerRun.childSessionKey,
              runId: otherOwnerRun.runId,
              taskId: otherOwnerRun.runId,
              generation: otherOwnerRun.generation,
            },
          },
        }),
      ).rejects.toThrow(/native run changed/u);
      expect(
        await executeManagedTaskFlowFixtureWrite(context, killWrite("accepted-root", claim)),
      ).toMatchObject({
        writeId: "managed-flow-cancel-accepted-root",
      });
      const claimedNative = await read({
        type: "subagents.runs",
        scope: { kind: "ids", runIds: [cancelRun.runId] },
      });
      if (!claimedNative || claimedNative.type !== "subagents.runs") {
        throw new Error("Native cancel claim observation unavailable");
      }
      expect(claimedNative.runs.get(cancelRun.runId)?.killIntent?.reason).toBe("killed");

      const launchChild = "agent:reviewer:subagent:launch-once";
      const prelaunch = await executeManagedTaskFlowFixtureWrite(context, {
        type: "tasks.managedFlows.create",
        input: {
          ownerKey,
          controllerId,
          goal: "Bind one exact native launch",
          status: "running",
          stateJson: {
            activeWorker: { sessionKey: launchChild, runId: null, taskId: null },
            launchOutcome: { status: "unknown", sessionKey: launchChild },
          },
        },
      });
      const launchClaim = {
        ownerKey,
        controllerId,
        flowId: prelaunch.flowId,
        revision: prelaunch.revision,
        childSessionKey: launchChild,
      };
      const firstLaunch = createSubagentRunRecord({
        runId: "launch-once-first",
        childSessionKey: launchChild,
        requesterSessionKey: ownerKey,
        controllerSessionKey: ownerKey,
        label: "plugin:publisher",
        generation: 1,
        expectsCompletionMessage: false,
      });
      const firstLaunchReceipt = await executeManagedTaskFlowFixtureWrite(context, {
        type: "subagents.persistChanges",
        input: {
          writeId: "managed-flow-launch-first",
          values: [bindSubagentRunRecord(firstLaunch)],
          deleteRunIds: [],
          versions: [{ runId: firstLaunch.runId, version: null }],
          managedFlowLaunchClaim: launchClaim,
        },
      });
      if ("conflictRunIds" in firstLaunchReceipt) {
        throw new Error("First managed native launch unexpectedly conflicted");
      }
      await expect(
        executeManagedTaskFlowFixtureWrite(context, {
          type: "subagents.persistChanges",
          input: {
            writeId: "managed-flow-launch-rewrite-denied",
            values: [bindSubagentRunRecord(firstLaunch)],
            deleteRunIds: [],
            versions: [
              {
                runId: firstLaunch.runId,
                version: firstLaunchReceipt.versions.get(firstLaunch.runId) ?? null,
              },
            ],
            managedFlowLaunchClaim: launchClaim,
          },
        }),
      ).rejects.toThrow(/register one exact native run/u);
      // Observe persisted facts as if the caller lost its registration reply.
      const attached = await read({
        type: "tasks.managedFlows.get",
        input: { ownerKey, controllerId, flowId: prelaunch.flowId },
      });
      expect(attached).toMatchObject({
        type: "tasks.managedFlows.get",
        value: {
          revision: prelaunch.revision + 1,
          stateJson: {
            activeWorker: { runId: firstLaunch.runId, nativeGeneration: 1 },
            launchOutcome: { status: "unknown" },
          },
        },
      });
      const secondLaunch = createSubagentRunRecord({
        ...firstLaunch,
        runId: "launch-once-second",
        generation: 2,
      });
      await expect(
        executeManagedTaskFlowFixtureWrite(context, {
          type: "subagents.persistChanges",
          input: {
            writeId: "managed-flow-launch-second",
            values: [bindSubagentRunRecord(secondLaunch)],
            deleteRunIds: [],
            versions: [{ runId: secondLaunch.runId, version: null }],
            managedFlowLaunchClaim: launchClaim,
          },
        }),
      ).rejects.toThrow(/changed before native registration/u);
      expect(
        await read({
          type: "subagents.runs",
          scope: {
            kind: "ids",
            runIds: [secondLaunch.runId],
          },
        }),
      ).toMatchObject({ type: "subagents.runs", runs: new Map() });
      expect(
        await read({
          type: "tasks.runs.get",
          input: {
            ownerKey,
            controllerId,
            taskId: firstLaunch.runId,
            legacyOwnerObservation: false,
          },
        }),
      ).toMatchObject({
        type: "tasks.runs.get",
        value: {
          runId: firstLaunch.runId,
          requesterSessionKey: ownerKey,
          childSessionKey: launchChild,
          observationSource: "native-subagent",
        },
      });
      expect(
        await read({
          type: "tasks.runs.get",
          input: {
            ownerKey: "agent:reviewer:main",
            controllerId,
            taskId: firstLaunch.runId,
            legacyOwnerObservation: false,
          },
        }),
      ).toMatchObject({ type: "tasks.runs.get", value: undefined });

      await closeStateDatabaseForTest();
      const reopened = openOpenClawStateDatabase({ env: state.env });
      const restoredContext = captureOpenClawStateWorkerContext({
        path: reopened.path,
        env: state.env,
      });
      expect(
        await executeExistingOpenClawStateRead(
          { path: reopened.path, env: state.env },
          {
            type: "tasks.managedFlows.get",
            input: {
              ownerKey,
              controllerId,
              flowId: prelaunch.flowId,
            },
          },
          { context: restoredContext, current: true },
        ),
      ).toMatchObject({
        ok: true,
        value: {
          revision: prelaunch.revision + 1,
          stateJson: {
            activeWorker: { runId: firstLaunch.runId, nativeGeneration: 1 },
            launchOutcome: { status: "unknown" },
          },
        },
      });
    },
  );
});
