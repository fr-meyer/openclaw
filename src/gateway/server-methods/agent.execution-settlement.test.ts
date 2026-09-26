// Preserve the admission harness before loading its consumers.
// oxfmt-ignore
import {
  describe0AfterEach0, getAgentTestMocks, makeContext, primeMainAgentRun,
} from "./agent.test-harness.js";
import { afterEach, describe, expect, it } from "vitest";
import { createDeferred } from "../../../test/helpers/promise.js";
import { withPluginRuntimeGatewayRequestScope } from "../../plugins/runtime/gateway-request-scope.js";
import { AsyncWorkScope } from "../../shared/async-work-scope.js";
import { ensureProfileForEmail } from "../../state/user-profiles.js";
import { withOpenClawTestState } from "../../test-utils/openclaw-test-state.js";
import { prepareAgentRequestPreflight } from "../agent-turn/agent-request-preflight.js";
import { createAgentTurnService } from "../agent-turn/agent-turn-service.js";
import type { AgentTurnExecutionOwner } from "../agent-turn/execution-settlement.js";
import { createInternalAgentTurnFacade } from "../agent-turn/internal-facade.js";
import type { AgentTurnIo } from "../agent-turn/types.js";
import { captureGatewayOperatorRunAuthority } from "../operator-run-authority.js";
import {
  createSyntheticPluginRuntimeClient,
  mergePluginRuntimeClientInternal,
} from "../server-plugin-runtime-client.js";
import { createGatewaySubagentRuntime } from "../server-plugin-subagent-runtime.js";
import { GatewayRequestEntryLifetime } from "../server-request-entry.js";

describe("accepted agent execution settlement", () => {
  afterEach(describe0AfterEach0);

  it.each([
    "completed",
    "cleanup failed",
    "acceptance callback failed",
    "cancelled before dispatch",
  ] as const)("observes the admitted producer when %s", async (outcome) => {
    primeMainAgentRun();
    const command = createDeferred();
    getAgentTestMocks().agentCommand.mockImplementation(async () => {
      await command.promise;
      return { payloads: [] };
    });
    const context = makeContext();
    const lifetime = new GatewayRequestEntryLifetime();
    context.requestEntryLifetime = lifetime;
    const executions: Promise<unknown>[] = [];
    const track = context.trackExecution;
    context.trackExecution = (run) => {
      const work = track(async () => {
        const result = await run();
        if (outcome === "cleanup failed") {
          throw new Error("host cleanup failed");
        }
        return result;
      });
      executions.push(work);
      return work;
    };
    let owner: AgentTurnExecutionOwner | undefined;
    let acceptanceState: string | undefined;
    const io: AgentTurnIo = {
      emitExecutionOwner: (value) => {
        owner = value;
      },
      emitAcceptance: (frame) => {
        if (frame[0]) {
          acceptanceState = owner?.observeSettlement();
          if (outcome === "acceptance callback failed") {
            throw new Error("acceptance callback failed");
          }
          if (outcome === "cancelled before dispatch") {
            context.chatAbortControllers.get("settlement-owner")?.controller.abort("rpc");
          }
        }
      },
      emitFinal: () => {},
    };
    const preflight = prepareAgentRequestPreflight({
      request: {
        message: "bounded synthetic worker",
        sessionKey: "agent:main:main",
        idempotencyKey: "settlement-owner",
      },
      context,
      client: null,
      io,
    });
    expect(preflight).toBeDefined();
    try {
      const admission = createAgentTurnService({
        context,
        isWebchatConnect: () => false,
      }).startTurn({
        preflight: preflight!,
        principal: null,
        io,
      });
      if (outcome === "acceptance callback failed") {
        await expect(admission).rejects.toThrow("acceptance callback failed");
        expect(owner?.observeSettlement()).toBe("unknown");
        return;
      }
      await admission;
      expect(acceptanceState).toBe("pending");
      expect(owner?.runId).toBe("settlement-owner");
      expect(owner?.sessionKey).toBe("agent:main:main");
      if (outcome === "cancelled before dispatch") {
        await Promise.allSettled(executions);
        expect(getAgentTestMocks().agentCommand).not.toHaveBeenCalled();
        expect(owner?.observeSettlement()).toBe("settled");
        return;
      }
      expect(owner?.observeSettlement()).toBe("pending");
      let replayOwner: AgentTurnExecutionOwner | undefined;
      const replayFrames: unknown[] = [];
      const replayIo: AgentTurnIo = {
        emitExecutionOwner: (value) => {
          replayOwner = value;
        },
        emitAcceptance: (frame) => {
          replayFrames.push(frame[1]);
        },
        emitFinal: () => {},
      };
      const replayPreflight = prepareAgentRequestPreflight({
        request: {
          message: "replay",
          sessionKey: "agent:main:main",
          idempotencyKey: "settlement-owner",
        },
        context,
        client: null,
        io: replayIo,
      });
      if (replayPreflight) {
        await createAgentTurnService({ context, isWebchatConnect: () => false }).startTurn({
          preflight: replayPreflight,
          principal: null,
          io: replayIo,
        });
      }
      expect(replayFrames).toContainEqual(expect.objectContaining({ status: "in_flight" }));
      expect(replayOwner).toBeUndefined();
      const original = context.chatAbortControllers.get("settlement-owner");
      expect(original).toBeDefined();
      context.chatAbortControllers.set("settlement-owner", { ...original! });
      expect(() => owner?.observeSettlement()).toThrow("owner was replaced");
      context.chatAbortControllers.set("settlement-owner", original!);
      command.resolve();
      await Promise.allSettled(executions);
      expect(owner?.observeSettlement()).toBe(outcome === "completed" ? "settled" : "unknown");
      lifetime.beginClose();
      expect(() => owner?.observeSettlement()).toThrow();
    } finally {
      command.resolve();
      await Promise.allSettled(executions);
    }
  });
  it("keeps SDK readback after a completed launch source is revoked", async () => {
    await withOpenClawTestState({ scenario: "minimal" }, async () => {
      primeMainAgentRun();
      const context = makeContext();
      const executionWork = new AsyncWorkScope();
      context.trackExecution = (run) => executionWork.track(run);
      let assertLaunchAuthority: (() => void) | undefined;
      context.createAgentTurnFacade = (options) => {
        assertLaunchAuthority = options.client.internal?.operatorRunAuthority?.assertCurrent;
        return createInternalAgentTurnFacade({ ...options, getContext: () => context });
      };
      const runtime = createGatewaySubagentRuntime(() => context);
      const profile = ensureProfileForEmail("settlement-operator@example.test");
      const client = createSyntheticPluginRuntimeClient({
        scopes: ["operator.write"],
        authenticatedUserProfile: {
          profileId: profile.id,
          displayName: "Synthetic operator",
          hasAvatar: false,
          updatedAt: 1,
        },
      });
      const source = new AbortController();
      const captured = await captureGatewayOperatorRunAuthority({
        client,
        context,
        sourceAuthority: {
          signal: source.signal,
          assertCurrent: () => source.signal.throwIfAborted(),
        },
      });
      expect(captured).toBeDefined();
      try {
        const run = await withPluginRuntimeGatewayRequestScope(
          {
            pluginId: "execution-test",
            client: mergePluginRuntimeClientInternal(client, {
              operatorRunAuthority: captured!.authority,
            }),
            isWebchatConnect: () => false,
          },
          async () =>
            await runtime.run({
              sessionKey: "agent:main:main",
              message: "authenticated synthetic worker",
              idempotencyKey: "authenticated-settlement",
            }),
        );
        await executionWork.runWhenIdle(() => {});
        expect(assertLaunchAuthority).toBeDefined();
        source.abort(new Error("operator source revoked"));
        expect(() => assertLaunchAuthority?.()).toThrow();
        expect(run.execution).toBeDefined();
        expect(run.execution?.observeSettlement()).toBe("settled");
      } finally {
        captured?.release();
      }
    });
  });
});
