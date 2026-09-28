import { expect, it } from "vitest";
import { createDeferred } from "../../../../test/helpers/promise.js";
import {
  createSessionEntry,
  waitForFast,
  type SubagentRegistryHarness,
} from "../../subagent-test-fixtures.test-helpers.js";
import { observeRootWork } from "./subagent-registry.browser-cleanup.test-support.js";
import type { createSubagentRegistryMockState } from "./subagent-registry.mock-state.test-support.js";
import type { SubagentRunRecord } from "./subagent-registry.types.js";

export function registerSubagentForcedCollectorYieldCompletionTests({
  getRegistry,
  mocks,
  mockPendingAgentWait,
  findRequesterRun,
  getLifecycleHandler,
}: {
  getRegistry: () => SubagentRegistryHarness;
  mocks: Pick<
    ReturnType<typeof createSubagentRegistryMockState>,
    "callGateway" | "captureSubagentCompletionReply" | "entries" | "runSubagentAnnounceFlow"
  >;
  mockPendingAgentWait: () => void;
  findRequesterRun: (runId: string) => SubagentRunRecord | undefined;
  getLifecycleHandler: () => (event: {
    runId: string;
    stream: string;
    data: Record<string, unknown>;
  }) => void;
}) {
  it.each([
    { observation: "lifecycle", schema: false, captured: false },
    { observation: "wait", schema: false, captured: false },
    { observation: "lifecycle", schema: true, captured: false },
    { observation: "wait", schema: true, captured: false },
    { observation: "lifecycle", schema: true, captured: true },
    { observation: "wait", schema: true, captured: true },
  ])(
    "settles forced collector yield through $observation (schema=$schema, captured=$captured)",
    async ({ observation, schema, captured }) => {
      const mod = getRegistry();
      const runId = "forced-collector-yield";
      const childSessionKey = "agent:main:subagent:forced-collector-yield";
      const terminal = {
        status: "ok",
        startedAt: 111,
        endedAt: 222,
        yielded: true,
        livenessState: "paused",
      };
      const waitResult = createDeferred<Record<string, unknown>>();
      let completionCaptureEntered = false;
      const settleRootWork = observeRootWork();
      try {
        mocks.captureSubagentCompletionReply.mockImplementation(async (...args: unknown[]) => {
          if (args[0] === childSessionKey) {
            completionCaptureEntered = true;
          }
          return "final completion reply";
        });
        if (observation === "wait") {
          mocks.callGateway.mockImplementation(async () => waitResult.promise);
        } else {
          mockPendingAgentWait();
        }
        mocks.entries = {
          [childSessionKey]: createSessionEntry({ lifecycleRevision: "forced-yield" }),
        };
        await mod.registerSubagentRun({
          runId,
          childSessionKey,
          task: "force the terminal boundary",
          collect: true,
          expectsCompletionMessage: false,
          swarmRequesterSessionKey: "agent:main:main",
          ...(schema ? { outputSchema: { type: "object" } } : {}),
        });
        if (captured) {
          mod.recordSwarmStructuredOutput(
            { runId, childSessionKey },
            { invalidAttempts: 0, structured: { answer: 42 } },
          );
        }
        if (observation === "wait") {
          waitResult.resolve(terminal);
        } else {
          getLifecycleHandler()({
            runId,
            stream: "lifecycle",
            data: { phase: "end", ...terminal },
          });
        }
        await waitForFast(() => {
          expect(completionCaptureEntered, "exact child completion capture admitted").toBe(true);
        });
        await settleRootWork(true);
        const entry = findRequesterRun(runId);
        expect(entry?.execution.status).toBe("terminal");
        expect(entry?.collectorCompletion?.status).toBe(schema && !captured ? "failed" : "done");
        expect(entry?.pauseReason).toBeUndefined();
        if (captured) {
          expect(entry?.collectorCompletion?.structured).toEqual({ answer: 42 });
        } else if (schema) {
          expect(entry?.collectorCompletion?.schemaError).toBe("structured_output was not called");
        }
        expect(mocks.runSubagentAnnounceFlow).not.toHaveBeenCalled();
      } finally {
        await settleRootWork();
      }
    },
  );
}
