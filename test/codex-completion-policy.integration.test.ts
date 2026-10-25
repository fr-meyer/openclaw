import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { loadCodexCompletionConnectionTestFixture } from "../extensions/codex/test-api.js";
import { resolveCompletionToolPolicy } from "../src/agents/command/attempt-execution.helpers.js";
import { withOpenClawTestState } from "../src/test-utils/openclaw-test-state.js";

const { createCodexCompletionConnectionTestFixture } =
  await loadCodexCompletionConnectionTestFixture();

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
});

describe("computed completion policy at the real Codex connection boundary", () => {
  it.each([true, false])(
    "preserves the computed no-tools contract with Computer Use enabled=%s",
    async (computerUseEnabled) => {
      await withOpenClawTestState({ label: "codex-computed-completion" }, async (state) => {
        // The caller did not opt in. The existing completion policy owns narrowing.
        const run = {
          sessionEntry: undefined,
          opts: { message: "Frozen child completion", toolsAllow: ["exec"] },
        };
        expect(run.opts).not.toHaveProperty("disableTools");
        const policy = resolveCompletionToolPolicy({
          run,
          trustedSubagentAnnounceHandoff: false,
          isSubagentAnnounceHandoff: true,
          isRawModelRun: false,
          isCliExecutionProvider: false,
          cliExecutionProvider: "",
          completionNeedsMessageDelivery: false,
        });
        expect(policy.disableTools).toBe(true);
        expect(policy.completionRetainsRequesterTools).toBe(false);
        expect(policy.runtimeToolsAllow).toBeUndefined();
        const fixture = await createCodexCompletionConnectionTestFixture({
          policy,
          computerUseEnabled,
          workspaceDir: state.workspaceDir,
          agentDir: state.agentDir("main"),
          storePath: path.join(state.sessionsDir("main"), "sessions.json"),
        });
        try {
          expect(fixture.params.disableTools).toBe(policy.disableTools);
          expect(fixture.params.toolsAllow).toBe(policy.runtimeToolsAllow);
          if (computerUseEnabled) {
            const message = "Explicit no-tools agent runs do not support enabled Codex Computer Use.";
            await expect(fixture.prepare()).rejects.toMatchObject({
              name: "AgentHarnessPreflightError",
              message,
              userMessage: message,
              scope: undefined,
            });
            for (const spy of Object.values(fixture.spies)) {
              expect(spy).not.toHaveBeenCalled();
            }
            expect(fixture.abortListenerCount()).toBe(fixture.listenersBefore);
            fixture.controller.abort("cancelled after refusal");
            expect(fixture.params.onAttemptAbort).not.toHaveBeenCalled();
          } else {
            const connection = await fixture.prepare();
            expect(connection.params.disableTools).toBe(true);
            expect(connection.computerUseConfig.enabled).toBe(false);
            expect(fixture.spies.workspace).toHaveBeenCalledWith(state.workspaceDir);
            expect(fixture.workspaceCacheContainsWorkspace()).toBe(true);
            expect(fixture.spies.clientFactory).not.toHaveBeenCalled();
            expect(() => connection.assertCurrent()).not.toThrow();
            // The real native session owner replaces this generation; the old
            // connection must not use its retained authority for another effect.
            await fixture.replaceSessionGeneration();
            const effect = vi.fn();
            await expect(connection.withCurrent(effect)).rejects.toThrow(
              "Codex session generation is no longer current",
            );
            expect(effect).not.toHaveBeenCalled();
            fixture.controller.abort("cancelled supported connection");
            expect(connection.runAbortController.signal.aborted).toBe(true);
            expect(fixture.params.onAttemptAbort).toHaveBeenCalledOnce();
          }
          expect(fixture.pluginConfig).toEqual(fixture.originalPluginConfig);
          expect(run.opts).not.toHaveProperty("disableTools");
          expect(fixture.params.disableTools).toBe(true);
        } finally {
          fixture.close();
        }
        expect(fixture.abortListenerCount()).toBe(fixture.listenersBefore);
        expect(fixture.workspaceCacheContainsWorkspace()).toBe(fixture.workspacePreviouslyCached);
      });
    },
  );
});
