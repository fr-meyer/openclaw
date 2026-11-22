import { isLifecycleState } from "./controller-state.mjs";
import {
  CONTROLLER_ID,
  PHASE,
  flowMatches,
  mergePolicyDigest,
  normalizePolicy,
} from "./controller.mjs";
import {
  DEFAULT_BROKER_COMMAND,
  DEFAULT_REMEDIATION_COMMAND,
  DEFAULT_REMEDIATION_ROOT,
  TERMINAL_FLOW_STATUSES,
  requireLifecycleHost,
  trackTaskBinding,
  withTaskBindings,
} from "./runtime-foundation.mjs";

export function result(value) {
  return {
    content: [{ type: "text", text: JSON.stringify(value) }],
    details: value,
  };
}

export function normalizePath(value, fallback) {
  const candidate = typeof value === "string" && value.trim() ? value.trim() : fallback;
  if (!candidate.startsWith("/") || candidate.includes("?") || candidate.includes("#")) {
    throw new Error("webhook path must be an absolute path without query or fragment");
  }
  return candidate.replace(/\/+$/, "") || "/";
}

export function normalizeStringArray(value, field, maxItems = 32) {
  if (value === undefined || value === null) {
    return [];
  }
  if (!Array.isArray(value) || value.length > maxItems) {
    throw new Error(`${field} must be an array with at most ${maxItems} entries`);
  }
  const normalized = value.map((item) => {
    if (typeof item !== "string" || !item.trim() || item.trim().length > 500) {
      throw new Error(`${field} contains an invalid entry`);
    }
    return item.trim();
  });
  return [...new Set(normalized)];
}

export function normalizeRuntimeConfig(input = {}) {
  const maxParallelPrs =
    Number.isInteger(input.maxParallelPrs) &&
    input.maxParallelPrs >= 1 &&
    input.maxParallelPrs <= 16
      ? input.maxParallelPrs
      : 1;
  const maxParallelPrsGlobal =
    Number.isInteger(input.maxParallelPrsGlobal) &&
    input.maxParallelPrsGlobal >= 1 &&
    input.maxParallelPrsGlobal <= 32
      ? input.maxParallelPrsGlobal
      : null;
  const repositories = new Map();
  const repositoriesByBrokerAlias = new Map();
  for (const [repo, policyInput] of Object.entries(input.repositories ?? {})) {
    if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo)) {
      throw new Error(`repository key is invalid: ${repo}`);
    }
    const policy = normalizePolicy({
      ...policyInput,
      maxParallelPrs: Number.isInteger(policyInput?.maxParallelPrs)
        ? policyInput.maxParallelPrs
        : maxParallelPrs,
    });
    if (
      policy.remediatorProfile &&
      (policy.remediatorProfile.repository !== repo ||
        policy.remediatorProfile.seedWorkspace !== policy.workspace ||
        policy.remediatorProfile.baseBranches.some(
          (baseRef) => !policy.baseBranches.includes(baseRef),
        ))
    ) {
      throw new Error(`remediator profile does not match repository policy: ${repo}`);
    }
    if (policy.mergeAuthorization && policy.mergeAuthorization.repository !== repo) {
      throw new Error(`merge authorization does not match repository policy: ${repo}`);
    }
    const existingAliasRepo = repositoriesByBrokerAlias.get(policy.brokerRepoAlias);
    if (existingAliasRepo && existingAliasRepo !== repo) {
      throw new Error(`Broker repository alias is duplicated: ${policy.brokerRepoAlias}`);
    }
    repositoriesByBrokerAlias.set(policy.brokerRepoAlias, repo);
    const currentMergePolicyDigest = mergePolicyDigest(policy, repo);
    if (
      policy.mergeAuthorization &&
      policy.mergeAuthorization.policyDigest !== currentMergePolicyDigest
    ) {
      throw new Error(
        `merge authorization policy digest does not match repository policy: ${repo}`,
      );
    }
    repositories.set(repo, { ...policy, mergePolicyDigest: currentMergePolicyDigest });
  }
  const githubWebhookPath = normalizePath(
    input.githubWebhookPath,
    "/plugins/pr-lifecycle-taskflow/github",
  );
  const brokerEventPath = normalizePath(
    input.brokerEventPath,
    "/plugins/pr-lifecycle-taskflow/broker",
  );
  if (githubWebhookPath === brokerEventPath) {
    throw new Error("GitHub and Broker event paths must be distinct");
  }
  return {
    enabled: input.enabled === true,
    ownerSessionKey:
      typeof input.ownerSessionKey === "string" && input.ownerSessionKey.trim()
        ? input.ownerSessionKey.trim()
        : null,
    notificationSessionKey:
      typeof input.notificationSessionKey === "string" && input.notificationSessionKey.trim()
        ? input.notificationSessionKey.trim()
        : null,
    legacyOwnerSessionKeys: normalizeStringArray(
      input.legacyOwnerSessionKeys,
      "legacyOwnerSessionKeys",
    ),
    statusAgentIds: normalizeStringArray(input.statusAgentIds, "statusAgentIds").map((value) => {
      if (!/^[A-Za-z0-9_.-]+$/.test(value)) {
        throw new Error("statusAgentIds contains an invalid agent id");
      }
      return value;
    }),
    expectedRuntimePath:
      typeof input.expectedRuntimePath === "string" && input.expectedRuntimePath.trim()
        ? input.expectedRuntimePath.trim()
        : null,
    expectedRuntimeSha256:
      typeof input.expectedRuntimeSha256 === "string" &&
      /^[0-9a-f]{64}$/.test(input.expectedRuntimeSha256)
        ? input.expectedRuntimeSha256
        : null,
    repositoryBrokerPath:
      typeof input.repositoryBrokerPath === "string" && input.repositoryBrokerPath.trim()
        ? input.repositoryBrokerPath.trim()
        : DEFAULT_BROKER_COMMAND,
    remediationCommandPath:
      typeof input.remediationCommandPath === "string" && input.remediationCommandPath.trim()
        ? input.remediationCommandPath.trim()
        : DEFAULT_REMEDIATION_COMMAND,
    remediationRoot:
      typeof input.remediationRoot === "string" && input.remediationRoot.trim()
        ? input.remediationRoot.trim()
        : DEFAULT_REMEDIATION_ROOT,
    githubWebhookPath,
    brokerEventPath,
    githubWebhookSecret:
      typeof input.githubWebhookSecret === "string" ? input.githubWebhookSecret : null,
    brokerEventSecret: typeof input.brokerEventSecret === "string" ? input.brokerEventSecret : null,
    recoveryDelayMinutes:
      Number.isInteger(input.recoveryDelayMinutes) && input.recoveryDelayMinutes >= 5
        ? input.recoveryDelayMinutes
        : 5,
    maxParallelPrs,
    maxParallelPrsGlobal,
    repositories,
  };
}

export async function bindFlowsForSession(api, sessionKey) {
  return await withTaskBindings(async () => {
    requireLifecycleHost(api);
    const bound = await trackTaskBinding(
      api.runtime.tasks.managedFlows.bindSession({ sessionKey }),
    );
    const required = [
      "get",
      "list",
      "createManaged",
      "finish",
      "fail",
      "setWaiting",
      "resume",
      "capacitySnapshot",
      "reserve",
      "captureNativeLaunch",
      "assertCurrent",
      "close",
    ];
    if (required.some((name) => typeof bound[name] !== "function")) {
      throw new Error("pr_lifecycle_host_flow_contract_unavailable");
    }
    return bound;
  });
}

export function ownerSessionKeyForRepo(config, repo) {
  if (!repo) {
    return config.ownerSessionKey;
  }
  const policy = config.repositories.get(repo);
  if (policy?.ownerSessionKey) {
    return policy.ownerSessionKey;
  }
  return config.ownerSessionKey;
}

export function uniqueOwnerSessionKeys(config) {
  const keys = [];
  const seen = new Set();
  const add = (value) => {
    if (typeof value === "string" && value && !seen.has(value)) {
      seen.add(value);
      keys.push(value);
    }
  };
  add(config.ownerSessionKey);
  for (const sessionKey of config.legacyOwnerSessionKeys) {
    add(sessionKey);
  }
  for (const policy of config.repositories.values()) {
    add(policy.ownerSessionKey);
  }
  return keys;
}

export async function collectLifecycleFlows(api, config) {
  return await withTaskBindings(async () => {
    const flows = [];
    const seen = new Set();
    for (const sessionKey of uniqueOwnerSessionKeys(config)) {
      for (const flow of await (await bindFlowsForSession(api, sessionKey)).list()) {
        if (seen.has(flow.flowId) || flow.controllerId !== CONTROLLER_ID) {
          continue;
        }
        seen.add(flow.flowId);
        flows.push(flow);
      }
    }
    return flows;
  });
}

export async function allBoundFlows(api, config) {
  return await withTaskBindings(async () => {
    return {
      async list() {
        return await collectLifecycleFlows(api, config);
      },
    };
  });
}

export async function resolveFlowBinding(api, config, flowId, preferredSessionKey) {
  return await withTaskBindings(async () => {
    const keys = uniqueOwnerSessionKeys(config);
    const ordered = preferredSessionKey
      ? [preferredSessionKey, ...keys.filter((key) => key !== preferredSessionKey)]
      : keys;
    for (const sessionKey of ordered) {
      if (!sessionKey) {
        continue;
      }
      const boundFlows = await bindFlowsForSession(api, sessionKey);
      const flow = await boundFlows.get(flowId);
      if (flow && flow.controllerId === CONTROLLER_ID && stateOf(flow)) {
        return { boundFlows, flow, sessionKey };
      }
    }
    throw new Error("flow_not_found");
  });
}

export async function findMatchingFlow(api, config, repo, prNumber, options = {}) {
  return await withTaskBindings(async () => {
    const preferred = ownerSessionKeyForRepo(config, repo);
    const keys = [preferred, ...uniqueOwnerSessionKeys(config).filter((key) => key !== preferred)];
    for (const sessionKey of keys) {
      if (!sessionKey) {
        continue;
      }
      const boundFlows = await bindFlowsForSession(api, sessionKey);
      const flow = latestMatchingFlow(await boundFlows.list(), repo, prNumber, options);
      if (flow) {
        return { boundFlows, flow, sessionKey };
      }
    }
    return null;
  });
}

export function stateOf(flow) {
  return isLifecycleState(flow?.stateJson) ? flow.stateJson : null;
}

export function latestMatchingFlow(flows, repo, prNumber, options = {}) {
  const matching = flows
    .filter((flow) => flow.controllerId === CONTROLLER_ID)
    .filter((flow) => flowMatches(stateOf(flow), repo, prNumber))
    .filter((flow) => (options.headSha ? stateOf(flow)?.headSha === options.headSha : true))
    .sort((left, right) => (right.updatedAt ?? 0) - (left.updatedAt ?? 0));
  if (options.nonTerminalOnly) {
    return matching.find((flow) => !TERMINAL_FLOW_STATUSES.has(flow.status));
  }
  return matching[0];
}

export function flowWaitJson(state) {
  if (state.phase === PHASE.MERGE_READY) {
    return {
      kind: "approval_gate",
      headSha: state.headSha,
      reviewId: state.mergeReady?.reviewId ?? null,
    };
  }
  return state.wait ?? { kind: "controller", phase: state.phase };
}
