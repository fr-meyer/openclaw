import { createHash, randomUUID } from "node:crypto";
import {
  CONTROLLER_ID,
  PHASE,
  holdsReviewLease,
  holdsWorkerLease,
  reserveWorker,
  workerKindForPhase,
} from "./controller.mjs";
import { stateOf, uniqueOwnerSessionKeys } from "./runtime-config.mjs";
import {
  CONTENTION_LOCK_NAMESPACE,
  CONTENTION_LOCK_TTL_MS,
  TERMINAL_FLOW_STATUSES,
  contentionStores,
  requireLifecycleHost,
  withTaskBindings,
} from "./runtime-foundation.mjs";
import {
  flowWorkspacePath,
  persistState,
  requireApplied,
  workerGenerationForState,
} from "./runtime-state-primitives.mjs";
export { workerGenerationForState } from "./runtime-state-primitives.mjs";

export function workerAgentId(policy, kind) {
  return kind === "review" ? policy.reviewWorkerAgentId : policy.authorWorkerAgentId;
}

export function createWorkerSessionKey(policy, flow, state, kind) {
  const agent = workerAgentId(policy, kind).replace(/[^a-zA-Z0-9_.-]/g, "-");
  const token = flow.flowId.replace(/[^a-zA-Z0-9]/g, "").slice(0, 16);
  const headToken = state.headSha.slice(0, 12);
  const retryCount = Number.isInteger(state.retryCount) ? state.retryCount : 0;
  const infrastructureRetryCount = Number.isInteger(state.infrastructureRetryCount)
    ? state.infrastructureRetryCount
    : 0;
  const generation = workerGenerationForState(state);
  return `agent:${agent}:subagent:mprl-${token}-${headToken}-${state.cycle}-g${generation}-${retryCount}-i${infrastructureRetryCount}-${kind}`;
}

export function contentionWorkspace(policies, repo) {
  if (!policies || typeof policies.get !== "function" || !repo) {
    return null;
  }
  const workspace = policies.get(repo)?.workspace;
  return typeof workspace === "string" && workspace.trim() ? workspace.trim() : null;
}

export function sharesReviewContentionDomain(left, right, policies) {
  if (!left?.repo || !right?.repo) {
    return false;
  }
  if (left.repo === right.repo) {
    return true;
  }
  const leftWorkspace = contentionWorkspace(policies, left.repo);
  const rightWorkspace = contentionWorkspace(policies, right.repo);
  return Boolean(leftWorkspace && rightWorkspace && leftWorkspace === rightWorkspace);
}

export async function activeReviewLeaseHolder(boundFlows, excludedFlowId, candidate, policies) {
  return await withTaskBindings(async () => {
    return (await boundFlows.list())
      .filter((flow) => flow.controllerId === CONTROLLER_ID && flow.flowId !== excludedFlowId)
      .filter((flow) => !TERMINAL_FLOW_STATUSES.has(flow.status))
      .find((flow) => {
        const other = stateOf(flow);
        if (!holdsReviewLease(other)) {
          return false;
        }
        return sharesReviewContentionDomain(other, candidate, policies);
      });
  });
}

export async function activeAuthorLeaseHolder(boundFlows, excludedFlowId, candidate, policies) {
  return await withTaskBindings(async () => {
    return (await boundFlows.list())
      .filter((flow) => flow.controllerId === CONTROLLER_ID && flow.flowId !== excludedFlowId)
      .filter((flow) => !TERMINAL_FLOW_STATUSES.has(flow.status))
      .find((flow) => {
        const other = stateOf(flow);
        if (other?.activeWorker?.kind !== "remediation") {
          return false;
        }
        return sharesReviewContentionDomain(other, candidate, policies);
      });
  });
}

export function occupyingWorkerKind(state) {
  const kind = state?.activeWorker?.kind;
  return kind === "review" || kind === "remediation" ? kind : null;
}

export async function lifecycleFlows(boundFlows) {
  return await withTaskBindings(async () => {
    return (await boundFlows.list())
      .filter((flow) => flow.controllerId === CONTROLLER_ID)
      .filter((flow) => !TERMINAL_FLOW_STATUSES.has(flow.status));
  });
}

export async function domainOccupants(boundFlows, excludedFlowId, candidate, policies) {
  return await withTaskBindings(async () => {
    return (await lifecycleFlows(boundFlows)).filter((flow) => {
      if (flow.flowId === excludedFlowId) {
        return false;
      }
      const other = stateOf(flow);
      if (!occupyingWorkerKind(other)) {
        return false;
      }
      return sharesReviewContentionDomain(other, candidate, policies);
    });
  });
}

export async function globalOccupants(boundFlows, excludedFlowId) {
  return await withTaskBindings(async () => {
    return (await lifecycleFlows(boundFlows)).filter((flow) => {
      if (flow.flowId === excludedFlowId) {
        return false;
      }
      return Boolean(occupyingWorkerKind(stateOf(flow)));
    });
  });
}

export function readySince(state) {
  if (Number.isFinite(state?.wait?.since)) {
    return state.wait.since;
  }
  return Number(state?.updatedAt) || 0;
}

export async function olderReadyWaiter(boundFlows, flow, state, policies) {
  return await withTaskBindings(async () => {
    const [olderWaiter] = (await lifecycleFlows(boundFlows))
      .filter((other) => other.flowId !== flow.flowId)
      .filter((other) => {
        const otherState = stateOf(other);
        if (!otherState || occupyingWorkerKind(otherState)) {
          return false;
        }
        if (
          otherState.phase !== PHASE.REVIEW_QUEUED &&
          otherState.phase !== PHASE.REMEDIATION_QUEUED
        ) {
          return false;
        }
        if (otherState.wait?.kind !== "parallel_slot") {
          return false;
        }
        if (!sharesReviewContentionDomain(otherState, state, policies)) {
          return false;
        }
        const otherReady = readySince(otherState);
        const selfReady = readySince(state);
        return otherReady < selfReady || (otherReady === selfReady && other.flowId < flow.flowId);
      });
    return olderWaiter;
  });
}

export function resolveMaxParallelPrs(config, repo) {
  const policy = config.repositories.get(repo);
  if (Number.isInteger(policy?.maxParallelPrs)) {
    return policy.maxParallelPrs;
  }
  return Number.isInteger(config.maxParallelPrs) ? config.maxParallelPrs : 1;
}

export async function evaluateParallelSlot(config, boundFlows, flow, state, kind) {
  return await withTaskBindings(async () => {
    const policies = config.repositories;
    const repoCap = resolveMaxParallelPrs(config, state.repo);
    const occupants = await domainOccupants(boundFlows, flow.flowId, state, policies);
    const sharedWorkspaceOtherRepo = occupants.find(
      (other) => stateOf(other)?.repo && stateOf(other).repo !== state.repo,
    );
    if (sharedWorkspaceOtherRepo) {
      return {
        ok: false,
        wait: {
          kind: "parallel_slot",
          since: state.wait?.kind === "parallel_slot" ? state.wait.since : Date.now(),
          position: 1,
          cap: 1,
          scope: "shared_workspace",
          aheadFlowId: sharedWorkspaceOtherRepo.flowId,
        },
      };
    }
    if (occupants.length >= repoCap) {
      return {
        ok: false,
        wait: {
          kind: "parallel_slot",
          since: state.wait?.kind === "parallel_slot" ? state.wait.since : Date.now(),
          position: occupants.length,
          cap: repoCap,
          scope: "repo",
        },
      };
    }
    if (Number.isInteger(config.maxParallelPrsGlobal)) {
      const global = await globalOccupants(boundFlows, flow.flowId);
      if (global.length >= config.maxParallelPrsGlobal) {
        return {
          ok: false,
          wait: {
            kind: "parallel_slot",
            since: state.wait?.kind === "parallel_slot" ? state.wait.since : Date.now(),
            position: global.length,
            cap: config.maxParallelPrsGlobal,
            scope: "global",
          },
        };
      }
    }
    if (
      kind === "review" &&
      (await activeReviewLeaseHolder(boundFlows, flow.flowId, state, policies))
    ) {
      return {
        ok: false,
        wait: {
          kind: "parallel_slot",
          since: state.wait?.kind === "parallel_slot" ? state.wait.since : Date.now(),
          position: occupants.length + 1,
          cap: repoCap,
          scope: "review_apply",
        },
      };
    }
    const older = await olderReadyWaiter(boundFlows, flow, state, policies);
    if (older) {
      return {
        ok: false,
        wait: {
          kind: "parallel_slot",
          since: state.wait?.kind === "parallel_slot" ? state.wait.since : Date.now(),
          position: occupants.length + 1,
          cap: repoCap,
          scope: "fifo",
          aheadFlowId: older.flowId,
        },
      };
    }
    return { ok: true };
  });
}

export async function activeWorkerLeaseHolder(boundFlows, excludedFlowId, candidate, policies) {
  return await withTaskBindings(async () => {
    return (await boundFlows.list())
      .filter((flow) => flow.controllerId === CONTROLLER_ID && flow.flowId !== excludedFlowId)
      .filter((flow) => {
        const state = stateOf(flow);
        return !TERMINAL_FLOW_STATUSES.has(flow.status) || Boolean(state?.orphanedWorker);
      })
      .find((flow) => {
        const other = stateOf(flow);
        return holdsWorkerLease(other) && sharesReviewContentionDomain(other, candidate, policies);
      });
  });
}

export function contentionLockStore(api) {
  const existing = contentionStores.get(api);
  if (existing) {
    return existing;
  }
  const openStore = api.runtime?.state?.openSyncKeyedStore;
  if (typeof openStore !== "function") {
    throw new Error("contention_lock_store_unavailable");
  }
  const store = openStore({
    namespace: CONTENTION_LOCK_NAMESPACE,
    maxEntries: 512,
    overflowPolicy: "reject-new",
  });
  if (
    !store ||
    typeof store.registerIfAbsent !== "function" ||
    typeof store.deleteIf !== "function"
  ) {
    throw new Error("contention_lock_store_is_not_atomic");
  }
  contentionStores.set(api, store);
  return store;
}

export function pullRequestAdmissionLockKey(repo, prNumber) {
  const digest = createHash("sha256").update(`admission:${repo}#${prNumber}`).digest("hex");
  return `admission:${digest}`;
}

export function acquirePullRequestAdmissionLock(api, repo, prNumber, now = Date.now()) {
  const store = contentionLockStore(api);
  const key = pullRequestAdmissionLockKey(repo, prNumber);
  const token = randomUUID();
  const acquired = store.registerIfAbsent(
    key,
    {
      schemaVersion: 1,
      token,
      repo,
      prNumber,
      acquiredAt: now,
    },
    { ttlMs: CONTENTION_LOCK_TTL_MS },
  );
  if (!acquired) {
    return null;
  }
  let released = false;
  return {
    key,
    token,
    release() {
      if (released) {
        return false;
      }
      released = true;
      return store.deleteIf(key, (current) => current?.token === token);
    },
  };
}

export function contentionLockKey(config, state) {
  const workspace = contentionWorkspace(config.repositories, state.repo);
  const domain = Number.isInteger(config.maxParallelPrsGlobal)
    ? `global:${CONTROLLER_ID}`
    : workspace
      ? `workspace:${workspace}`
      : `repo:${state.repo}`;
  const digest = createHash("sha256").update(domain).digest("hex");
  return `worker:${digest}`;
}

export function acquireContentionLock(api, config, flow, state, kind, now = Date.now()) {
  const store = contentionLockStore(api);
  const key = contentionLockKey(config, state);
  const token = randomUUID();
  const acquired = store.registerIfAbsent(
    key,
    {
      schemaVersion: 1,
      token,
      flowId: flow.flowId,
      ownerKey: flow.ownerKey,
      repo: state.repo,
      headSha: state.headSha,
      kind,
      acquiredAt: now,
    },
    { ttlMs: CONTENTION_LOCK_TTL_MS },
  );
  if (!acquired) {
    return null;
  }
  let released = false;
  return {
    key,
    token,
    release() {
      if (released) {
        return false;
      }
      released = true;
      return store.deleteIf(key, (current) => current?.token === token);
    },
  };
}

export async function reserveWorkerWithContentionLock(api, config, boundFlows, flow, kind) {
  return await withTaskBindings(async () => {
    const initialState = stateOf(flow);
    if (!initialState) {
      throw new Error("flow_state_invalid");
    }
    const lock = acquireContentionLock(api, config, flow, initialState, kind);
    if (!lock) {
      return { reserved: false, flow, reason: "contention_lock_held" };
    }
    try {
      let current = (await boundFlows.get(flow.flowId)) ?? flow;
      let state = stateOf(current);
      if (!state) {
        throw new Error("flow_state_invalid");
      }
      if (workerKindForPhase(state.phase) !== kind) {
        return { reserved: false, flow: current, reason: "phase_not_dispatchable" };
      }
      const policy = config.repositories.get(state.repo);
      const expectedWorkspace = flowWorkspacePath(policy, state);
      if (
        state.workspacePreflight?.workspace !== expectedWorkspace ||
        state.workspacePreflight?.headSha !== state.headSha
      ) {
        return { reserved: false, flow: current, reason: "workspace_preflight_stale" };
      }
      const capacitySnapshot = await boundFlows.capacitySnapshot({
        ownerSessionKeys: uniqueOwnerSessionKeys(config),
      });
      const slot = await evaluateParallelSlot(
        config,
        { list: async () => capacitySnapshot.flows },
        current,
        state,
        kind,
      );
      if (!slot.ok) {
        state = { ...state, wait: slot.wait, updatedAt: Date.now() };
        current = requireApplied(await persistState(boundFlows, current, state));
        return { reserved: false, flow: current, reason: "parallel_slot_held" };
      }
      const sessionKey = createWorkerSessionKey(policy, current, state, kind);
      const reserved = reserveWorker(state, kind, sessionKey, Date.now(), current.flowId);
      if (!reserved.changed || reserved.effect === "blocked") {
        const nextFlow = reserved.changed
          ? requireApplied(await persistState(boundFlows, current, reserved.state))
          : current;
        return {
          reserved: false,
          flow: nextFlow,
          reason: reserved.reason,
          effect: reserved.effect,
        };
      }
      requireLifecycleHost(api);
      const reservationMutation = await boundFlows.reserve({
        flowId: current.flowId,
        expectedRevision: current.revision,
        status: "running",
        currentStep: reserved.state.phase,
        stateJson: { ...reserved.state, flowId: current.flowId },
        updatedAt: reserved.state.updatedAt,
        capacitySnapshot,
      });
      if (!reservationMutation.applied) {
        return {
          reserved: false,
          flow: reservationMutation.current ?? current,
          reason: reservationMutation.code,
        };
      }
      const reservedFlow = reservationMutation.flow;
      return {
        reserved: true,
        flow: reservedFlow,
        state: reserved.state,
        sessionKey,
      };
    } finally {
      lock.release();
    }
  });
}
