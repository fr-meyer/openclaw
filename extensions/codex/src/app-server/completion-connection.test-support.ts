import { getEventListeners } from "node:events";
import path from "node:path";
import type { EmbeddedRunAttemptParamsV2 } from "openclaw/plugin-sdk/agent-harness-runtime";
import { patchSessionEntry } from "openclaw/plugin-sdk/session-store-runtime";
import { vi } from "vitest";
import * as authBridge from "./auth-bridge.js";
import * as bindingConnection from "./binding-connection.js";
import * as requirements from "./config-requirements.js";
import { prepareCodexAttemptConnection } from "./run-attempt-connection.js";
import * as attemptLifecycle from "./run-attempt-lifecycle.js";
import { createParams } from "./run-attempt-test-harness.js";
import { createCodexTestBindingStore } from "./session-binding.test-helpers.js";
import { codexWorkspaceDirCache } from "./workspace-dir-cache.js";

/** Plugin-owned half of the host policy-to-connection regression; never acquires a client. */
export async function createCodexCompletionConnectionTestFixture(input: {
  policy: { disableTools: boolean; runtimeToolsAllow?: EmbeddedRunAttemptParamsV2["toolsAllow"] };
  computerUseEnabled: boolean;
  workspaceDir: string;
  agentDir: string;
  storePath: string;
}) {
  const workspaceCacheKey = path.resolve(input.workspaceDir);
  const workspacePreviouslyCached = codexWorkspaceDirCache.has(workspaceCacheKey);
  const identity = {
    agentId: "main",
    sessionKey: "agent:main:direct:completion-policy",
    sessionId: "completion-policy-session",
  };
  const scope = {
    agentId: identity.agentId,
    sessionKey: identity.sessionKey,
    storePath: input.storePath,
  };
  const entry = { sessionId: identity.sessionId, updatedAt: Date.now() };
  await patchSessionEntry({
    ...scope,
    fallbackEntry: entry,
    replaceEntry: true,
    skipMaintenance: true,
    update: () => entry,
  });
  const params = createParams(
    path.join(path.dirname(input.storePath), "completion-policy.jsonl"),
    input.workspaceDir,
    {
      sessionId: identity.sessionId,
      sessionKey: identity.sessionKey,
      runId: "completion-policy-run",
    },
  );
  // Consume the actual policy result without reimplementing completion classification.
  params.disableTools = input.policy.disableTools;
  params.toolsAllow = input.policy.runtimeToolsAllow;
  params.agentId = identity.agentId;
  params.agentDir = input.agentDir;
  params.sessionTarget = { ...scope, sessionId: identity.sessionId };
  params.config = { ...params.config, session: { store: input.storePath } };
  const controller = new AbortController();
  params.abortSignal = controller.signal;
  params.onAttemptAbort = vi.fn();
  const listenersBefore = getEventListeners(controller.signal, "abort").length;
  const bindModelExecution = vi.fn(params.hostCapabilities.bindModelExecution);
  const preparedEnvironment = vi.fn(params.hostCapabilities.preparedEnvironment);
  params.hostCapabilities = {
    ...params.hostCapabilities,
    bindModelExecution,
    preparedEnvironment,
  };
  const bindingStore = createCodexTestBindingStore();
  const workspace = vi.spyOn(attemptLifecycle, "ensureCodexWorkspaceDirOnce");
  const connectionPolicy = vi.spyOn(bindingConnection, "resolveCodexBindingAppServerConnection");
  const authHandoff = vi.spyOn(authBridge, "resolveCodexAppServerPreparedAuthHandoff");
  const reclaim = vi.spyOn(bindingStore, "prepareSessionGenerationReclaim");
  // This synthetic test home has no operator requirements; avoid ambient native-home reads.
  const requirementsRead = vi
    .spyOn(requirements, "readCodexRequirementsToml")
    .mockReturnValue(undefined);
  const clientFactory = vi.fn(async () => {
    throw new Error("connection-only regression must not acquire an app-server client");
  });
  const pluginConfig = {
    appServer: { command: "codex" },
    computerUse: { enabled: input.computerUseEnabled, autoInstall: true, strictReadiness: true },
  };
  const originalPluginConfig = structuredClone(pluginConfig);
  let connection: Awaited<ReturnType<typeof prepareCodexAttemptConnection>> | undefined;
  return {
    params,
    controller,
    originalPluginConfig,
    pluginConfig,
    spies: {
      workspace,
      connectionPolicy,
      authHandoff,
      reclaim,
      clientFactory,
      bindModelExecution,
      preparedEnvironment,
    },
    abortListenerCount: () => getEventListeners(controller.signal, "abort").length,
    listenersBefore,
    workspacePreviouslyCached,
    workspaceCacheContainsWorkspace: () => codexWorkspaceDirCache.has(workspaceCacheKey),
    prepare: async () => {
      connection = await prepareCodexAttemptConnection({
        params,
        options: { pluginConfig, bindingStore, clientFactory },
      });
      return connection;
    },
    replaceSessionGeneration: async () => {
      await patchSessionEntry({
        ...scope,
        skipMaintenance: true,
        update: () => ({ sessionId: "completion-policy-successor", updatedAt: Date.now() }),
      });
    },
    close: () => {
      connection?.cancellation.dispose();
      connection?.releaseModelExecution();
      // The host deletes this synthetic workspace after close. Preserve prior
      // cache owners; retire only the key this fixture actually prepared.
      if (
        !workspacePreviouslyCached &&
        workspace.mock.calls.some(([directory]) => path.resolve(directory) === workspaceCacheKey)
      ) {
        codexWorkspaceDirCache.delete(workspaceCacheKey);
      }
      workspace.mockRestore();
      connectionPolicy.mockRestore();
      authHandoff.mockRestore();
      reclaim.mockRestore();
      requirementsRead.mockRestore();
    },
  };
}
