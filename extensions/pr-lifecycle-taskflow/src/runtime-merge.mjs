import { blockState } from "./controller-state.mjs";
import { PHASE, isSha } from "./controller.mjs";
import { stateOf } from "./runtime-config.mjs";
import { withTaskBindings } from "./runtime-foundation.mjs";
import {
  AutoMergeGateError,
  AutoMergeRevisionChangedError,
  acquireMergeLock,
  brokerRepoAlias,
  mergeGateDiagnostics,
  requireAutoMergePolicy,
  runBroker,
} from "./runtime-merge-gates.mjs";
import {
  clearWake,
  notifyLifecycleOutcome,
  persistState,
  persistTerminalCleanup,
  requireApplied,
  scheduleWake,
} from "./runtime-state-primitives.mjs";

export function mergedState(state, receipt, now = Date.now()) {
  return {
    ...state,
    phase: PHASE.MERGED,
    activeWorker: null,
    wait: null,
    blocker: null,
    mergeGates: state.mergeGates ? { ...state.mergeGates, ready: true } : null,
    prEffects: "merged",
    latestExternalMilestone: {
      kind: "merged",
      headSha: state.headSha,
      observedAt: now,
      observedRevision: null,
      url: `https://github.com/${state.repo}/pull/${state.prNumber}`,
      receipt,
    },
    merged: {
      headSha: state.headSha,
      baseRef: state.baseRef,
      mergeMethod: state.autoMergeMethod ?? "merge",
      actor: receipt.merged_by?.login ?? null,
      authorization: state.mergeAuthorization,
      receipt,
      mergedAt: now,
    },
    terminalSupersession: {
      schemaVersion: 1,
      eventId: `terminal:${state.flowId ?? `${state.repo}#${state.prNumber}`}:${state.headSha}:merged`,
      flowId: state.flowId ?? null,
      repository: state.repo,
      prNumber: state.prNumber,
      headSha: state.headSha,
      phase: PHASE.MERGED,
      reason: "verified_merge_receipt",
      emittedAt: now,
    },
    updatedAt: now,
  };
}

export async function persistMergedReceipt(boundFlows, flow, state, receipt) {
  return await withTaskBindings(async () => {
    let currentFlow = await boundFlows.get(flow.flowId);
    for (let attempt = 0; attempt < 8; attempt += 1) {
      const currentState = stateOf(currentFlow);
      if (!currentFlow || !currentState) {
        throw new Error("automatic_merge_receipt_flow_missing");
      }
      if (currentState.phase === PHASE.MERGED) {
        if (
          currentState.headSha === state.headSha &&
          currentState.baseSha === state.baseSha &&
          currentState.merged?.receipt?.sha === receipt.sha
        ) {
          return currentFlow;
        }
        throw new Error("automatic_merge_receipt_conflict");
      }
      if (
        currentState.phase !== PHASE.MERGE_QUEUED ||
        currentState.repo !== state.repo ||
        currentState.prNumber !== state.prNumber ||
        currentState.headSha !== state.headSha ||
        currentState.baseSha !== state.baseSha ||
        currentState.baseRef !== state.baseRef ||
        currentState.mergePolicyDigest !== state.mergePolicyDigest ||
        currentState.mergeAuthorization?.digest !== state.mergeAuthorization?.digest ||
        currentState.mergeReady?.authorizationDigest !== state.mergeReady?.authorizationDigest
      ) {
        throw new Error("automatic_merge_receipt_state_conflict");
      }
      const mutation = await persistState(
        boundFlows,
        currentFlow,
        mergedState(currentState, receipt),
      );
      if (mutation.applied) {
        return mutation.flow;
      }
      if (mutation.code !== "revision_conflict") {
        return requireApplied(mutation);
      }
      currentFlow = mutation.current ?? (await boundFlows.get(flow.flowId));
    }
    throw new Error("automatic_merge_receipt_persistence_exhausted");
  });
}

export async function requireCurrentAutoMergeState(boundFlows, flow, state, policy) {
  return await withTaskBindings(async () => {
    const currentFlow = await boundFlows.get(flow.flowId);
    const currentState = stateOf(currentFlow);
    if (
      !currentFlow ||
      currentFlow.revision !== flow.revision ||
      !currentState ||
      currentState.phase !== PHASE.MERGE_QUEUED ||
      currentState.headSha !== state.headSha ||
      currentState.baseSha !== state.baseSha ||
      currentState.baseRef !== state.baseRef ||
      currentState.wait?.kind === "check_suite" ||
      currentState.mergePolicyDigest !== state.mergePolicyDigest ||
      currentState.mergeAuthorization?.digest !== state.mergeAuthorization?.digest ||
      currentState.mergeReady?.authorizationDigest !== state.mergeReady?.authorizationDigest
    ) {
      throw new AutoMergeRevisionChangedError(currentFlow);
    }
    requireAutoMergePolicy(currentState, policy);
    return currentState;
  });
}

export function reconciledMergeReceipt(state, remote, expectedActor) {
  const mergeCommitSha = remote?.merge_commit_sha;
  const mergedAt = remote?.merged_at;
  const mergedAtMs = typeof mergedAt === "string" ? Date.parse(mergedAt) : Number.NaN;
  const authorization = state.mergeAuthorization;
  if (
    remote?.repo !== state.repo ||
    Number(remote?.number) !== state.prNumber ||
    remote?.state !== "closed" ||
    remote?.merged !== true ||
    remote?.head?.repo !== state.repo ||
    remote?.head?.sha !== state.headSha ||
    remote?.base?.repo !== state.repo ||
    remote?.base?.ref !== state.baseRef ||
    remote?.base?.sha !== state.baseSha ||
    remote?.merged_by?.login !== expectedActor ||
    !isSha(mergeCommitSha) ||
    !Number.isFinite(mergedAtMs) ||
    !authorization ||
    mergedAtMs < authorization.authorizedAt ||
    mergedAtMs >= authorization.expiresAt
  ) {
    throw new Error("automatic_merge_reconciliation_identity_mismatch");
  }
  return {
    schemaVersion: 1,
    reconciled: true,
    reconciliationSource: "broker_pr_state",
    repo: state.repo,
    number: state.prNumber,
    merged: true,
    base: state.baseRef,
    head_ref: remote.head.ref ?? state.headRef ?? null,
    head_sha: state.headSha,
    sha: mergeCommitSha,
    merge_method: state.autoMergeMethod ?? "merge",
    actor_verification: "passed",
    merged_by: { login: expectedActor },
    merged_at: mergedAt,
    message: "Authoritative already-merged state reconciled",
    token_material: "not_reported",
  };
}

export async function autoMergeReceipt(
  api,
  state,
  policy,
  revalidate = null,
  assertMergeLock = null,
  config = {},
) {
  requireAutoMergePolicy(state, policy);
  const alias = brokerRepoAlias(policy);
  if (typeof assertMergeLock === "function") {
    assertMergeLock();
  }
  const remote = await runBroker(
    api,
    ["pr-state", alias, String(state.prNumber), "--expected-sha", state.headSha, "--json"],
    config,
  );
  if (typeof assertMergeLock === "function") {
    assertMergeLock();
  }
  if (remote.merged === true) {
    return reconciledMergeReceipt(state, remote, policy.mergeActor);
  }
  const diagnostics = mergeGateDiagnostics(state, remote);
  if (!diagnostics.ready) {
    throw new AutoMergeGateError(diagnostics);
  }
  const headRef = remote.head?.ref;
  if (typeof headRef !== "string" || !headRef.trim()) {
    throw new Error("automatic_merge_head_ref_missing");
  }
  const mergeState = typeof revalidate === "function" ? await revalidate() : state;
  if (typeof assertMergeLock === "function") {
    assertMergeLock();
  }
  const receipt = await runBroker(
    api,
    [
      "merge-pr",
      alias,
      String(state.prNumber),
      "--expected-base",
      mergeState.baseRef,
      "--expected-base-sha",
      mergeState.baseSha,
      "--expected-head-branch",
      headRef,
      "--expected-head-sha",
      mergeState.headSha,
      "--expected-actor-login",
      policy.mergeActor,
      "--merge-method",
      mergeState.autoMergeMethod ?? "merge",
      "--require-taskflow-gates",
      "--json",
    ],
    config,
  );
  // The external merge is the commit point. Lease ownership is checked immediately
  // before it; once the broker returns a receipt, validate and persist that receipt
  // even if the lease expired while GitHub completed the merge.
  const brokerAppId = receipt.taskflow_gates?.broker_check_app_id;
  const atomicEnforcement = receipt.taskflow_gates?.atomic_enforcement;
  const appBoundBrokerCheck = Array.isArray(atomicEnforcement?.required_status_checks)
    ? atomicEnforcement.required_status_checks.find(
        (check) => check?.context === "Broker review" && check?.app_id === brokerAppId,
      )
    : null;
  if (
    receipt.merged !== true ||
    receipt.base !== mergeState.baseRef ||
    receipt.head_sha !== mergeState.headSha ||
    receipt.actor_verification !== "passed" ||
    receipt.merged_by?.login !== policy.mergeActor ||
    receipt.taskflow_gates?.required_checks_ready !== true ||
    receipt.taskflow_gates?.broker_check_ready !== true ||
    !Number.isSafeInteger(brokerAppId) ||
    brokerAppId < 1 ||
    receipt.taskflow_gates?.exact_review_ready !== true ||
    receipt.taskflow_gates?.atomic_base_update !== true ||
    atomicEnforcement?.broker_app_id !== brokerAppId ||
    !appBoundBrokerCheck ||
    receipt.taskflow_gates?.reviewed_base_sha !== mergeState.baseSha ||
    receipt.taskflow_gates?.reviewed_head_sha !== mergeState.headSha ||
    !isSha(receipt.taskflow_gates?.synthetic_merge_commit_sha) ||
    receipt.taskflow_gates.synthetic_merge_commit_sha !== receipt.sha
  ) {
    throw new Error("automatic_merge_receipt_invalid");
  }
  return receipt;
}

export async function performAutoMerge(api, config, boundFlows, flow, state) {
  return await withTaskBindings(async () => {
    let mergeLock;
    try {
      mergeLock = acquireMergeLock(api, flow, state);
      if (!mergeLock) {
        const waiting = {
          ...state,
          wait: {
            kind: "merge_slot",
            since: Date.now(),
            repository: state.repo,
            baseRef: state.baseRef,
          },
          updatedAt: Date.now(),
        };
        const waitingFlow = requireApplied(await persistState(boundFlows, flow, waiting));
        await scheduleWake(api, config, waitingFlow, "recover");
        return waitingFlow;
      }
      const policy = config.repositories.get(state.repo);
      const receipt = await autoMergeReceipt(
        api,
        state,
        policy,
        async () => await requireCurrentAutoMergeState(boundFlows, flow, state, policy),
        () => {
          if (!mergeLock.assertAndRenew()) {
            throw new Error("merge_lock_lost");
          }
        },
        config,
      );
      const mergedFlow = await persistMergedReceipt(boundFlows, flow, state, receipt);
      return await persistTerminalCleanup(
        api,
        config,
        boundFlows,
        mergedFlow,
        stateOf(mergedFlow),
        "merged",
      );
    } catch (error) {
      const reason = error instanceof Error ? error.message : "unknown";
      if (error instanceof AutoMergeRevisionChangedError && error.currentFlow) {
        return error.currentFlow;
      }
      if (error instanceof AutoMergeGateError) {
        const diagnostics = error.diagnostics;
        if (error.waitForEvent) {
          const blockedChecks = [
            ...(diagnostics.gates.requiredChecks?.failed ?? []),
            ...(diagnostics.gates.requiredChecks?.pending ?? []),
          ];
          const latestCheck = blockedChecks.find((run) => run.url) ?? null;
          const next = {
            ...state,
            mergeGates: diagnostics,
            prEffects: latestCheck ? "check_published" : state.prEffects,
            latestExternalMilestone: latestCheck
              ? {
                  kind: "check_published",
                  headSha: state.headSha,
                  observedAt: diagnostics.observedAt,
                  observedRevision: null,
                  url: latestCheck.url,
                  receipt: { check: latestCheck },
                }
              : state.latestExternalMilestone,
            wait: {
              kind: "check_suite",
              origin: "gate_snapshot",
              since: Date.now(),
              headSha: state.headSha,
              failedChecks: diagnostics.gates.requiredChecks?.failed ?? [],
              pendingChecks: diagnostics.gates.requiredChecks?.pending ?? [],
            },
            updatedAt: Date.now(),
          };
          const waitingFlow = requireApplied(await persistState(boundFlows, flow, next));
          await clearWake(api, config, waitingFlow);
          if (state.wait?.kind !== "check_suite") {
            await notifyLifecycleOutcome(
              api,
              config,
              waitingFlow,
              stateOf(waitingFlow),
              "check_wait",
            );
          }
          return waitingFlow;
        }
        const failedGates = Object.entries(diagnostics.gates)
          .filter(([, gate]) => gate.ready !== true)
          .map(([name]) => name)
          .join(",");
        const blocked = blockState(state, `auto_merge_gate_blocked:${failedGates}`);
        const blockedState = {
          ...blocked.state,
          mergeReady: state.mergeReady,
          mergeGates: diagnostics,
        };
        const blockedFlow = requireApplied(await persistState(boundFlows, flow, blockedState));
        return await persistTerminalCleanup(
          api,
          config,
          boundFlows,
          blockedFlow,
          stateOf(blockedFlow),
          "blocked",
        );
      }
      const retryCount = Math.max(0, Number(state.infrastructureRetryCount) || 0);
      if (retryCount < state.maxRetries) {
        const next = {
          ...state,
          infrastructureRetryCount: retryCount + 1,
          infrastructureLastFailure: `auto_merge:${reason}`.slice(0, 500),
          wait: { kind: "auto_merge_retry", since: Date.now() },
          updatedAt: Date.now(),
        };
        const retryFlow = requireApplied(await persistState(boundFlows, flow, next));
        await scheduleWake(api, config, retryFlow, "recover");
        return retryFlow;
      }
      const blocked = blockState(state, `auto_merge_failed:${reason}`);
      const blockedState = { ...blocked.state, mergeReady: state.mergeReady };
      const blockedFlow = requireApplied(await persistState(boundFlows, flow, blockedState));
      return await persistTerminalCleanup(
        api,
        config,
        boundFlows,
        blockedFlow,
        stateOf(blockedFlow),
        "blocked",
      );
    } finally {
      mergeLock?.release?.();
    }
  });
}
