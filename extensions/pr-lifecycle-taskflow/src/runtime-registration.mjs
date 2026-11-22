import { blockState, isTerminalState } from "./controller-state.mjs";
import { CONTROLLER_ID, PHASE, recoverState, refreshPolicySnapshot } from "./controller.mjs";
import {
  bindFlowsForSession,
  normalizeRuntimeConfig,
  stateOf,
  uniqueOwnerSessionKeys,
} from "./runtime-config.mjs";
import {
  TERMINAL_FLOW_STATUSES,
  TOOL_NAME,
  requireLifecycleHost,
  withTaskBindings,
} from "./runtime-foundation.mjs";
import {
  createRouteHandler,
  ingestCheckSuite,
  ingestPullRequest,
  ingestReviewResult,
} from "./runtime-ingest.mjs";
import { runtimeSourceIntegrity } from "./runtime-integrity.mjs";
import {
  clearTerminalArtifacts,
  clearWake,
  notificationAlreadyRendered,
  notifyLifecycleOutcome,
  notifyMergeReady,
  persistState,
  persistTerminalCleanup,
  requireApplied,
  scheduleWake,
} from "./runtime-state-primitives.mjs";
import {
  currentWorkerTask,
  reconcileOrphanBeforeEffect,
  recoverExtras,
} from "./runtime-status-primitives.mjs";
import { reconcileTerminalWorkerEvent } from "./runtime-status.mjs";
import { createControllerTool } from "./runtime-tools.mjs";
import { reconcileGithubHead } from "./runtime-worker-orchestration.mjs";
export { processStartedAtMs } from "./runtime-state-primitives.mjs";

export async function reconcileAtStartup(api, config) {
  return await withTaskBindings(async () => {
    if (!config.enabled || !config.ownerSessionKey) {
      return;
    }
    for (const sessionKey of uniqueOwnerSessionKeys(config)) {
      const boundFlows = await bindFlowsForSession(api, sessionKey);
      for (let flow of (await boundFlows.list()).filter(
        (item) => item.controllerId === CONTROLLER_ID,
      )) {
        let state = stateOf(flow);
        if (!state) {
          continue;
        }
        if (state.orphanedWorker) {
          const reconciled = await reconcileOrphanBeforeEffect(
            api,
            config,
            boundFlows,
            flow,
            state,
          );
          if (!reconciled.safe) {
            continue;
          }
          flow = reconciled.flow;
          state = reconciled.state;
          if (isTerminalState(state)) {
            await clearWake(api, config, flow);
            continue;
          }
        }
        if (
          state.phase === PHASE.MERGE_READY &&
          (!TERMINAL_FLOW_STATUSES.has(flow.status) || flow.status === "succeeded")
        ) {
          if (flow.status === "succeeded") {
            flow = requireApplied(
              await persistState(boundFlows, flow, { ...state, updatedAt: Date.now() }),
            );
            state = stateOf(flow);
          }
          await clearWake(api, config, flow);
          if (!notificationAlreadyRendered(state, "approval_gate")) {
            await notifyMergeReady(api, config, flow, state);
          }
          continue;
        }
        if (TERMINAL_FLOW_STATUSES.has(flow.status) || isTerminalState(state)) {
          if (TERMINAL_FLOW_STATUSES.has(flow.status) && !isTerminalState(state)) {
            const blocked = blockState(state, `flow_status_terminal:${flow.status}`);
            flow = requireApplied(await persistState(boundFlows, flow, blocked.state));
            state = stateOf(flow);
          }
          const kind = state.phase === PHASE.MERGED ? "merged" : "blocked";
          if (!state.terminalCleanup) {
            flow = await persistTerminalCleanup(api, config, boundFlows, flow, state, kind);
            state = stateOf(flow);
          } else {
            await clearTerminalArtifacts(api, config, flow);
            if (!notificationAlreadyRendered(state, kind)) {
              await notifyLifecycleOutcome(api, config, flow, state, kind);
            }
          }
          continue;
        }
        const policy = config.repositories.get(state.repo);
        if (!policy || !policy.enabled) {
          await clearWake(api, config, flow);
          continue;
        }
        if (state.pendingGithubReconciliation) {
          const reconciled = await reconcileGithubHead(api, config, boundFlows, flow, state);
          if (!reconciled.resolved) {
            continue;
          }
          flow = reconciled.flow;
          state = reconciled.state;
        }
        const refreshed = refreshPolicySnapshot(state, policy);
        if (refreshed.changed) {
          flow = requireApplied(await persistState(boundFlows, flow, refreshed.state));
          state = refreshed.state;
        }
        if (state.mode === "observe") {
          await clearWake(api, config, flow);
          continue;
        }
        const transition = recoverState(
          state,
          await currentWorkerTask(api, sessionKey, state),
          Date.now(),
          120_000,
          recoverExtras(api, state),
        );
        if (transition.changed) {
          flow = requireApplied(await persistState(boundFlows, flow, transition.state));
          state = transition.state;
        }
        if (transition.effect === "continue") {
          await scheduleWake(api, config, flow, "continue");
        } else if (!isTerminalState(state) && state.phase !== PHASE.BLOCKED) {
          await scheduleWake(api, config, flow, "recover");
        } else if (state.phase === PHASE.BLOCKED) {
          if (!state.terminalCleanup) {
            await persistTerminalCleanup(api, config, boundFlows, flow, state, "blocked");
          } else {
            await clearTerminalArtifacts(api, config, flow);
            if (!notificationAlreadyRendered(state, "blocked")) {
              await notifyLifecycleOutcome(api, config, flow, state, "blocked");
            }
          }
        } else {
          await clearWake(api, config, flow);
        }
      }
    }
  });
}

export function registerPrLifecycleTaskflow(api) {
  const requestedConfig = normalizeRuntimeConfig(api.pluginConfig ?? {});
  const sourceIntegrity = runtimeSourceIntegrity(
    requestedConfig.expectedRuntimePath,
    requestedConfig.expectedRuntimeSha256,
    { allowDisposable: api.__testAllowDisposableRuntime === true },
  );
  let hostReady = false;
  try {
    requireLifecycleHost(api);
    hostReady = true;
  } catch {}
  const config =
    requestedConfig.enabled && (!sourceIntegrity.verified || !hostReady)
      ? { ...requestedConfig, enabled: false }
      : requestedConfig;
  api.registerTool((ctx) => createControllerTool(api, config, ctx), {
    names: [TOOL_NAME],
    optional: true,
  });

  if (requestedConfig.enabled && !sourceIntegrity.verified) {
    api.logger.error(
      `Broker PR lifecycle runtime source integrity failed; controller remains inert. ` +
        `Loaded ${sourceIntegrity.path} at sha256:${sourceIntegrity.sha256}; ` +
        `modules=${JSON.stringify(sourceIntegrity.modules ?? {})}; ` +
        `durable=${sourceIntegrity.durable}.`,
    );
    return;
  }
  if (requestedConfig.enabled && !hostReady) {
    api.logger.error("PR lifecycle host capability unavailable; controller remains inert.");
    return;
  }
  if (!config.enabled) {
    api.logger.info("Broker PR lifecycle controller is installed but disabled.");
    return;
  }
  if (!config.ownerSessionKey) {
    api.logger.error("Broker PR lifecycle enabled without ownerSessionKey; runtime remains inert.");
    return;
  }
  api.logger.info(
    `Broker PR lifecycle runtime source verified: ${sourceIntegrity.path} ` +
      `sha256:${sourceIntegrity.sha256} modules=${JSON.stringify(sourceIntegrity.modules ?? {})}.`,
  );

  if (config.githubWebhookSecret) {
    api.registerHttpRoute({
      path: config.githubWebhookPath,
      auth: "plugin",
      match: "exact",
      handler: createRouteHandler({
        kind: "github",
        secret: config.githubWebhookSecret,
        ingest: async (event) =>
          event.type === "check_suite"
            ? await ingestCheckSuite(api, config, event)
            : await ingestPullRequest(api, config, event),
      }),
    });
  } else {
    api.logger.warn("GitHub webhook route not registered because its secret is unavailable.");
  }

  if (config.brokerEventSecret) {
    api.registerHttpRoute({
      path: config.brokerEventPath,
      auth: "plugin",
      match: "exact",
      handler: createRouteHandler({
        kind: "broker",
        secret: config.brokerEventSecret,
        ingest: async (event) => await ingestReviewResult(api, config, event),
      }),
    });
  } else {
    api.logger.warn("Broker event route not registered because its secret is unavailable.");
  }

  api.agent.events.registerAgentEventSubscription({
    id: "worker-terminal-reconciliation",
    description:
      "Advance exact-head PR lifecycle flows from terminal worker events without chat polling.",
    streams: ["lifecycle"],
    async handle(event) {
      try {
        await reconcileTerminalWorkerEvent(api, config, event);
      } catch (error) {
        const detail = error instanceof Error ? error.message : "unknown";
        api.logger.error(`Broker PR lifecycle terminal reconciliation failed: ${detail}`);
      }
    },
  });

  api.registerService({
    id: "pr-lifecycle-taskflow-recovery",
    async start() {
      await reconcileAtStartup(api, config);
    },
  });
}
