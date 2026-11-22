import { blockState } from "./controller-state.mjs";
import {
  PHASE,
  applyPullRequestEvent,
  applyWorkerFailure,
  attachWorkerRun,
  classifyWorkerFailure,
  workerKindForPhase,
} from "./controller.mjs";
import { allBoundFlows, stateOf } from "./runtime-config.mjs";
import { evaluateParallelSlot, reserveWorkerWithContentionLock } from "./runtime-contention.mjs";
import {
  DEFAULT_BROKER_COMMAND,
  DEFAULT_REMEDIATION_COMMAND,
  TOOL_NAME,
  requireLifecycleHost,
  withTaskBindings,
} from "./runtime-foundation.mjs";
import {
  brokerRepoAlias,
  readAuthoritativePullRequest,
  readWorkspaceHead,
} from "./runtime-merge-gates.mjs";
import { performAutoMerge } from "./runtime-merge.mjs";
import {
  prepareRemediationJob,
  readWorkspaceIdentity,
  validateRemediatorAdmission,
} from "./runtime-remediation-primitives.mjs";
import {
  clearWake,
  enforceModeGate,
  flowWorkspacePath,
  notifyMergeReady,
  persistState,
  persistTerminalCleanup,
  primaryFixerFailureGrant,
  requireApplied,
  scheduleWake,
  workerGenerationForState,
} from "./runtime-state-primitives.mjs";
import {
  reconcileOrphanBeforeEffect,
  reconcileOrphanedWorker,
  taskForWorker,
} from "./runtime-status-primitives.mjs";
import { ensureFlowWorkspace } from "./runtime-workspace-primitives.mjs";

export function workerBinding(flow, state, policy, kind) {
  const primaryFixerFailure = kind === "remediation" ? primaryFixerFailureGrant(flow, state) : null;
  return {
    flowId: flow.flowId,
    flowRevision: flow.revision,
    repository: state.repo,
    pullRequest: state.prNumber,
    exactHeadSha: state.headSha,
    baseSha: state.baseSha,
    baseRef: state.baseRef,
    cycle: state.cycle,
    mode: state.mode,
    kind,
    claimRef: kind === "review" ? (state.activeWorker?.claimRef ?? null) : undefined,
    reviewActor: state.reviewActor,
    authorActor: state.authorActor,
    publisherBoundary: kind === "remediation" ? state.publisherBoundary : undefined,
    fixerPolicy:
      kind === "remediation"
        ? {
            primaryModel: state.fixerModel,
            fallbackModel: state.fixerFallbackModel,
            forbidAuto: true,
            forbidFast: true,
          }
        : undefined,
    workspace: flowWorkspacePath(policy, state),
    workspacePreflight: state.workspacePreflight ?? null,
    remediationJob: kind === "remediation" ? (state.activeWorker?.remediationJob ?? null) : null,
    findingsCount: kind === "remediation" ? state.findings.length : 0,
    primaryFixerFailure,
  };
}

export function buildWorkerMessage(flow, state, policy, kind, config = {}) {
  const binding = workerBinding(flow, state, policy, kind);
  const common = [
    "You are one bounded worker in a native OpenClaw managed TaskFlow.",
    `Immutable binding: ${JSON.stringify(binding)}`,
    "The controller already verified the isolated workspace head at admission. Do not repeat that local workspace check with exec or another shell call.",
    `Immediately before any external effect, require the broker's authoritative remote PR-head readback to equal ${state.headSha}.`,
    "Use only approved brokered repository routes. Never use raw unauthenticated GitHub writes.",
    "Fail closed on a stale head, incomplete review coverage, lease conflict, ambiguous publication, or missing evidence.",
    "Do not merge. Merge-ready is a nonterminal approval gate and still requires separate human authorization.",
  ];
  if (kind === "review") {
    const repositoryAlias = brokerRepoAlias(policy);
    common.push(
      `Act only as reviewer/gatekeeper ${state.reviewActor}; do not author or modify commits.`,
      "Check the Broker contention-domain fence immediately before launch and preserve at most one active Broker --apply per repository. Different repositories may review in parallel unless they share a workspace.",
      `Use only the executable ${config.repositoryBrokerPath ?? DEFAULT_BROKER_COMMAND}. Do not call git, ls, find, head, cat, another executable, or a shell operator, and do not explore or recheck the local workspace.`,
      `First call exactly: ${config.repositoryBrokerPath ?? DEFAULT_BROKER_COMMAND} pr-state ${repositoryAlias} ${state.prNumber} --json`,
      `Accept existing review evidence only when it is terminal, coverage-complete, and bound to exact head ${state.headSha}.`,
      `If no such terminal review exists, call exactly: ${config.repositoryBrokerPath ?? DEFAULT_BROKER_COMMAND} broker-review ${repositoryAlias} ${state.prNumber} --expected-sha ${state.headSha} --apply --json`,
      "For that broker-review exec call, set timeoutSeconds=1800 and yieldMs=1000. If it yields a process session, poll it with timeout=30000 until the process is terminal.",
      `Call ${TOOL_NAME} exactly once with action=report, this flowId, kind=${kind}, headSha=${state.headSha}, and cycle=${state.cycle}.`,
      "After the report tool returns, perform no further repository or review action.",
      "Do not call lifecycle status, admit, continue, recover, or another owner action. The worker reports its result exactly once and never drives the controller.",
      "If completion is external, report outcome=waiting_review with a bounded claimRef.",
      "If authoritative review evidence is already terminal, report approved, changes_requested, failed_retryable, or failed_terminal with coverageComplete and sanitized findings.",
    );
  } else {
    const jobId = state.activeWorker?.remediationJob?.jobId;
    if (!jobId) {
      throw new Error("remediation_job_binding_missing");
    }
    common.push(
      `Act only as author/publisher ${state.authorActor}; never impersonate reviewer ${state.reviewActor}.`,
      `Publish only through attested broker ${state.publisherBoundary.brokerId} under evidence ${state.publisherBoundary.attestationRef}; never substitute another identity or raw GitHub write path.`,
      `Call exactly: ${config.remediationCommandPath ?? DEFAULT_REMEDIATION_COMMAND} run ${jobId}`,
      "Do not call git, gh, another code agent, a shell, another executable, a shell operator, or any file tool. The bounded command owns scratch isolation, model attestation, validation, commit, publication, and remote-head reconciliation.",
      `The command must attest the exact primary fixer selector ${state.fixerModel}; automatic or otherwise unpinned selectors are forbidden.`,
      "After the command returns, stop. The controller reads and verifies the immutable host evidence directly; do not probe for or call a lifecycle report tool.",
      "If the command fails, stop after accurately stating the returned failure; do not invent evidence or retry the command yourself.",
      binding.primaryFixerFailure
        ? `Controller-owned fallback grant ${binding.primaryFixerFailure.ref} is bound to this generation for reason ${binding.primaryFixerFailure.reason}; only the controlled wrapper may consume it.`
        : `The fallback selector ${state.fixerFallbackModel} is not authorized in this job; a fallback requires a new controller generation after a recorded primary infrastructure failure.`,
    );
  }
  return common.join("\n");
}

export async function resolveWorkerTask(api, ownerSessionKey, sessionKey, runId) {
  return await withTaskBindings(async () => {
    const worker = { sessionKey, runId, taskId: null };
    const existing = await taskForWorker(api, ownerSessionKey, worker);
    if (existing) {
      return { task: existing, reason: "canonical_worker_task_resolved" };
    }
    return {
      task: undefined,
      reason: "task_link_missing:canonical_worker_task_not_visible",
    };
  });
}

export async function dispatchWorker(api, config, boundFlows, flow) {
  return await withTaskBindings(async () => {
    let state = stateOf(flow);
    if (!state) {
      throw new Error("flow_state_invalid");
    }
    let workingFlow = flow;
    if (state.phase === PHASE.MERGE_QUEUED) {
      return await performAutoMerge(api, config, boundFlows, workingFlow, state);
    }
    const policy = config.repositories.get(state.repo);
    if (!policy || !policy.enabled) {
      const blocked = blockState(state, "repository_policy_missing_or_disabled");
      const blockedFlow = requireApplied(await persistState(boundFlows, flow, blocked.state));
      await applyEffect(api, config, boundFlows, blockedFlow, blocked.state, blocked.effect);
      return (await boundFlows.get(blockedFlow.flowId)) ?? blockedFlow;
    }
    const gate = enforceModeGate(state);
    if (gate.reason === "observe_mode") {
      return flow;
    }
    if (gate.changed) {
      const gatedFlow = requireApplied(await persistState(boundFlows, flow, gate.state));
      await applyEffect(api, config, boundFlows, gatedFlow, gate.state, gate.effect);
      return (await boundFlows.get(gatedFlow.flowId)) ?? gatedFlow;
    }
    const kind = workerKindForPhase(state.phase);
    if (!kind) {
      return workingFlow;
    }
    const now = Date.now();
    const preflightBudgetBlocker =
      now > state.deadlineAt
        ? "wall_time_budget_exhausted"
        : kind === "remediation" && state.cycle >= state.maxCycles
          ? "review_fix_cycle_budget_exhausted"
          : null;
    if (preflightBudgetBlocker) {
      const blocked = blockState(state, preflightBudgetBlocker, now);
      const blockedFlow = requireApplied(
        await persistState(boundFlows, workingFlow, blocked.state),
      );
      await applyEffect(api, config, boundFlows, blockedFlow, blocked.state, blocked.effect);
      return (await boundFlows.get(blockedFlow.flowId)) ?? blockedFlow;
    }
    if (state.orphanedWorker) {
      const orphan = await reconcileOrphanedWorker(
        api,
        workingFlow.ownerKey,
        state.orphanedWorker,
        { flowId: workingFlow.flowId, revision: workingFlow.revision },
      );
      if (!orphan.safe) {
        await scheduleWake(api, config, workingFlow, "recover");
        return workingFlow;
      }
      state = {
        ...state,
        orphanedWorker: null,
        lastGhostCleanup: {
          sessionKey: state.orphanedWorker.sessionKey,
          runId: state.orphanedWorker.runId ?? null,
          taskId: state.orphanedWorker.taskId ?? null,
          reason: orphan.reason,
          reconciledAt: Date.now(),
        },
        updatedAt: Date.now(),
      };
      workingFlow = requireApplied(await persistState(boundFlows, workingFlow, state));
    }
    const slot = await evaluateParallelSlot(
      config,
      await allBoundFlows(api, config),
      workingFlow,
      state,
      kind,
    );
    if (!slot.ok) {
      const queued = {
        ...state,
        wait: slot.wait,
        updatedAt: Date.now(),
      };
      workingFlow = requireApplied(await persistState(boundFlows, workingFlow, queued));
      await scheduleWake(api, config, workingFlow, "recover");
      return workingFlow;
    }
    let workerWorkspace;
    let workspaceHead;
    try {
      workerWorkspace = await ensureFlowWorkspace(api, policy, state);
      workspaceHead = await readWorkspaceHead(api, workerWorkspace, state.headSha);
    } catch (error) {
      const detail = error instanceof Error ? error.message : "unknown";
      const blocked = blockState(state, `workspace_head_preflight_failed:${detail.slice(0, 300)}`);
      const blockedFlow = requireApplied(
        await persistState(boundFlows, workingFlow, blocked.state),
      );
      await applyEffect(api, config, boundFlows, blockedFlow, blocked.state, blocked.effect);
      return (await boundFlows.get(blockedFlow.flowId)) ?? blockedFlow;
    }
    if (workspaceHead !== state.headSha) {
      const blocked = blockState(
        state,
        `workspace_head_mismatch:expected=${state.headSha}:actual=${workspaceHead}`,
      );
      const blockedFlow = requireApplied(
        await persistState(boundFlows, workingFlow, blocked.state),
      );
      await applyEffect(api, config, boundFlows, blockedFlow, blocked.state, blocked.effect);
      return (await boundFlows.get(blockedFlow.flowId)) ?? blockedFlow;
    }
    if (kind === "remediation") {
      try {
        const identity = await readWorkspaceIdentity(
          api,
          workerWorkspace,
          state.headSha,
          state.repo,
        );
        validateRemediatorAdmission(api, policy, state, workerWorkspace, identity);
      } catch (error) {
        const detail = error instanceof Error ? error.message : "unknown";
        const blocked = blockState(
          state,
          `remediator_profile_admission_failed:${detail.slice(0, 300)}`,
        );
        const blockedFlow = requireApplied(
          await persistState(boundFlows, workingFlow, blocked.state),
        );
        await applyEffect(api, config, boundFlows, blockedFlow, blocked.state, blocked.effect);
        return (await boundFlows.get(blockedFlow.flowId)) ?? blockedFlow;
      }
    }
    const checkedAt = Date.now();
    state = {
      ...state,
      wait: null,
      flowWorkspace: {
        path: workerWorkspace,
        headSha: workspaceHead,
        provisionedAt: state.flowWorkspace?.provisionedAt ?? checkedAt,
      },
      workspacePreflight: {
        workspace: workerWorkspace,
        headSha: workspaceHead,
        checkedAt,
      },
      updatedAt: checkedAt,
    };
    workingFlow = requireApplied(await persistState(boundFlows, workingFlow, state));
    const reservation = await reserveWorkerWithContentionLock(
      api,
      config,
      boundFlows,
      workingFlow,
      kind,
    );
    if (!reservation.reserved) {
      if (
        reservation.reason === "infrastructure_backoff" ||
        reservation.reason === "protocol_backoff" ||
        reservation.reason === "contention_lock_held" ||
        reservation.reason === "parallel_slot_held" ||
        reservation.reason === "capacity_snapshot_conflict" ||
        reservation.reason === "revision_conflict" ||
        reservation.reason === "prior_review_lease_held" ||
        reservation.reason === "workspace_preflight_stale"
      ) {
        await scheduleWake(api, config, reservation.flow, "recover");
      }
      return reservation.flow;
    }
    const sessionKey = reservation.sessionKey;
    const reserved = { state: reservation.state };
    let reservedFlow = reservation.flow;
    let launchedWorker = null;
    let launchInvoked = false;
    try {
      if (kind === "remediation") {
        const remediationJob = prepareRemediationJob(
          api,
          reservedFlow,
          reserved.state,
          policy,
          config,
        );
        const preparedState = {
          ...reserved.state,
          activeWorker: {
            ...reserved.state.activeWorker,
            remediationJob,
          },
          updatedAt: Date.now(),
        };
        reservedFlow = requireApplied(await persistState(boundFlows, reservedFlow, preparedState));
      }
      requireLifecycleHost(api);
      const prelaunchState = {
        ...stateOf(reservedFlow),
        launchOutcome: { status: "unknown", sessionKey, observedAt: Date.now() },
        updatedAt: Date.now(),
      };
      reservedFlow = requireApplied(await persistState(boundFlows, reservedFlow, prelaunchState));
      const managedFlowLaunch = await boundFlows.captureNativeLaunch({
        flowId: reservedFlow.flowId,
        expectedRevision: reservedFlow.revision,
        childSessionKey: sessionKey,
      });
      requireLifecycleHost(api);
      boundFlows.assertCurrent();
      launchInvoked = true;
      const run = await api.runtime.subagent.run({
        assertCurrent: () => {
          requireLifecycleHost(api);
          boundFlows.assertCurrent();
        },
        managedFlowLaunch,
        sessionKey,
        message: buildWorkerMessage(reservedFlow, stateOf(reservedFlow), policy, kind, config),
        ...(kind === "review" ? { toolsAlsoAllow: [TOOL_NAME] } : {}),
        lane: `pr-lifecycle-taskflow:${state.repo}:${state.prNumber}`,
        idempotencyKey:
          `mprl:${workingFlow.flowId}:${state.headSha}:${state.cycle}:` +
          `g${workerGenerationForState(state)}:${state.retryCount ?? 0}:` +
          `i${state.infrastructureRetryCount ?? 0}:${kind}`,
        lightContext: true,
        deliver: false,
        cwd: flowWorkspacePath(policy, stateOf(reservedFlow) ?? state),
        runTimeoutSeconds: 3600,
      });
      launchedWorker = {
        ...stateOf(reservedFlow).activeWorker,
        sessionKey:
          typeof run.sessionKey === "string" && run.sessionKey.trim()
            ? run.sessionKey.trim()
            : sessionKey,
        runId: typeof run.runId === "string" && run.runId.trim() ? run.runId.trim() : null,
        taskId: null,
      };
      if (run.sessionKey && run.sessionKey !== sessionKey) {
        throw new Error(`worker_session_identity_mismatch:${run.sessionKey}`);
      }
      let current = (await boundFlows.get(reservedFlow.flowId)) ?? reservedFlow;
      let currentState = stateOf(current);
      if (currentState?.activeWorker?.sessionKey !== sessionKey) {
        throw new Error("worker_reservation_changed_after_launch");
      }
      const attachedRun = attachWorkerRun(
        {
          ...currentState,
          launchOutcome: {
            status: "accepted",
            sessionKey,
            runId: run.runId,
            observedAt: Date.now(),
          },
        },
        sessionKey,
        run.runId,
        null,
      );
      if (attachedRun.changed) {
        reservedFlow = requireApplied(await persistState(boundFlows, current, attachedRun.state));
        current = reservedFlow;
        currentState = attachedRun.state;
      }
      const resolvedTask = await resolveWorkerTask(
        api,
        reservedFlow.ownerKey,
        sessionKey,
        run.runId,
      );
      if (!resolvedTask.task) {
        throw new Error(resolvedTask.reason);
      }
      const taskId = resolvedTask.task.id ?? resolvedTask.task.taskId ?? null;
      const attachedTask = attachWorkerRun(currentState, sessionKey, run.runId, taskId);
      if (attachedTask.changed) {
        reservedFlow = requireApplied(await persistState(boundFlows, current, attachedTask.state));
      }
      // Worker lifecycle events drive the next transition. A scheduled model turn here
      // would repeatedly wake a controller chat while the worker is legitimately active.
      await clearWake(api, config, reservedFlow);
      return reservedFlow;
    } catch (error) {
      const current = (await boundFlows.get(reservedFlow.flowId)) ?? reservedFlow;
      const currentState = stateOf(current);
      if (currentState?.activeWorker?.sessionKey !== sessionKey) {
        throw error;
      }
      if (launchInvoked && currentState?.launchOutcome?.status === "unknown") {
        // Never convert an uncertain accepted native launch into a fresh worker slot.
        await scheduleWake(api, config, current, "recover");
        throw error;
      }
      const errorMessage = error instanceof Error ? error.message : "unknown";
      const failureReason =
        classifyWorkerFailure(errorMessage) === "infrastructure"
          ? errorMessage
          : `worker_start_failed:${errorMessage}`;
      const failed = applyWorkerFailure(
        { ...currentState, launchOutcome: null },
        sessionKey,
        failureReason,
      );
      const failedState =
        failed.changed && launchedWorker?.sessionKey !== sessionKey
          ? {
              ...failed.state,
              orphanedWorker: {
                ...launchedWorker,
                reason: failureReason,
                clearedAt: Date.now(),
              },
            }
          : failed.state;
      const failedFlow = failed.changed
        ? requireApplied(await persistState(boundFlows, current, failedState))
        : current;
      await applyEffect(api, config, boundFlows, failedFlow, failedState, failed.effect);
      return failedFlow;
    }
  });
}

export async function reconcileGithubHead(api, config, boundFlows, flow, state) {
  return await withTaskBindings(async () => {
    if (!state?.pendingGithubReconciliation) {
      return { resolved: true, flow, state, effect: "none", reason: "no_reconciliation_pending" };
    }
    try {
      const policy = config.repositories.get(state.repo);
      if (!policy || !policy.enabled) {
        throw new Error("repository_policy_missing_or_disabled");
      }
      const event = await readAuthoritativePullRequest(api, config, state);
      const transition = applyPullRequestEvent(state, event, policy);
      if (!transition.changed) {
        throw new Error(`github_reconciliation_not_applied:${transition.reason}`);
      }
      const updated = requireApplied(await persistState(boundFlows, flow, transition.state));
      if (transition.effect !== "none") {
        await applyEffect(api, config, boundFlows, updated, transition.state, transition.effect);
      }
      return {
        resolved: true,
        flow: updated,
        state: transition.state,
        effect: transition.effect,
        reason: transition.reason,
      };
    } catch (error) {
      const detail = error instanceof Error ? error.message : "unknown";
      await scheduleWake(api, config, flow, "recover");
      return {
        resolved: false,
        flow,
        state,
        effect: "reconcile",
        reason: `github_head_reconciliation_pending:${detail.slice(0, 300)}`,
      };
    }
  });
}
export async function applyEffect(api, config, boundFlows, flow, state, effect, options = {}) {
  return await withTaskBindings(async () => {
    const reconciled = await reconcileOrphanBeforeEffect(api, config, boundFlows, flow, state);
    if (!reconciled.safe) {
      return;
    }
    flow = reconciled.flow;
    state = reconciled.state;
    if (effect === "reconcile") {
      await reconcileGithubHead(api, config, boundFlows, flow, state);
      return;
    }
    if (effect === "merge_ready") {
      if (state.phase === PHASE.MERGE_QUEUED) {
        await performAutoMerge(api, config, boundFlows, flow, state);
        return;
      }
      await clearWake(api, config, flow);
      await notifyMergeReady(api, config, flow, state);
      return;
    }
    if (effect === "continue") {
      const gate = enforceModeGate(state);
      if (gate.changed) {
        const gatedFlow = requireApplied(await persistState(boundFlows, flow, gate.state));
        await applyEffect(api, config, boundFlows, gatedFlow, gate.state, gate.effect, options);
        return;
      }
      if (gate.reason !== "observe_mode") {
        if (options.dispatchImmediately === true) {
          await clearWake(api, config, flow);
          await dispatchWorker(api, config, boundFlows, flow);
        } else {
          await scheduleWake(api, config, flow, "continue");
        }
      }
      return;
    }
    if (effect === "wait" || effect === "blocked") {
      if (effect === "blocked") {
        await persistTerminalCleanup(api, config, boundFlows, flow, state, "blocked");
      } else {
        await scheduleWake(api, config, flow, "recover");
      }
    }
  });
}
