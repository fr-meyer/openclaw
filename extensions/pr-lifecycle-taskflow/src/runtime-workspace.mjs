import { PHASE, refreshPolicySnapshot } from "./controller.mjs";
import { stateOf } from "./runtime-config.mjs";
import { withTaskBindings } from "./runtime-foundation.mjs";
import { readWorkspaceIdentity } from "./runtime-remediation-primitives.mjs";
import {
  persistState,
  requireApplied,
  workerGenerationForState,
} from "./runtime-state-primitives.mjs";
import { statusView } from "./runtime-status-primitives.mjs";
import { applyEffect } from "./runtime-worker-orchestration.mjs";
import {
  ensureFlowWorkspace,
  isWorkspaceHeadMismatchBlock,
} from "./runtime-workspace-primitives.mjs";
export { flowWorkspacePath } from "./runtime-state-primitives.mjs";
export {
  provisionedFlowWorkspacePath,
  addDetachedWorktree,
  refreshDetachedWorktree,
  ensureFlowWorkspace,
  isWorkspaceHeadMismatchBlock,
} from "./runtime-workspace-primitives.mjs";

export async function revalidateWorkspaceHeadBlock(api, config, resolved, input, event) {
  return await withTaskBindings(async () => {
    let flow = resolved.flow;
    const state = stateOf(flow);
    if (!isWorkspaceHeadMismatchBlock(state)) {
      return null;
    }
    if (input.expectedRevision === undefined) {
      throw new Error("workspace_revalidation_requires_expected_revision");
    }
    if (input.expectedRevision !== flow.revision) {
      return {
        ok: true,
        staleWake: true,
        expectedRevision: input.expectedRevision,
        flow: statusView(flow),
      };
    }
    if (
      event.repo !== state.repo ||
      event.prNumber !== state.prNumber ||
      event.headSha !== state.headSha ||
      event.baseSha !== state.baseSha ||
      event.baseRef !== state.baseRef
    ) {
      throw new Error("workspace_revalidation_scope_mismatch");
    }
    if (state.activeWorker || state.orphanedWorker) {
      throw new Error("workspace_revalidation_worker_not_quiescent");
    }
    const policy = config.repositories.get(state.repo);
    if (!policy || !policy.enabled) {
      throw new Error("repository_policy_missing_or_disabled");
    }

    let workspace;
    let identity;
    try {
      // Resolve from the current repository policy, never from the stale workspace
      // metadata that produced the persisted mismatch blocker.
      workspace = await ensureFlowWorkspace(api, policy, {
        ...state,
        flowWorkspace: null,
        workspacePreflight: null,
      });
      identity = await readWorkspaceIdentity(api, workspace, state.headSha, state.repo);
    } catch (error) {
      const detail = error instanceof Error ? error.message : "unknown";
      return {
        ok: true,
        admit: {
          accepted: false,
          created: false,
          flowId: flow.flowId,
          revision: flow.revision,
          reason: `owner_admit_workspace_revalidation_failed:${detail.slice(0, 300)}`,
        },
        flow: statusView(flow),
      };
    }
    const failure =
      identity?.topLevel !== workspace
        ? "workspace_top_level_mismatch"
        : identity?.repository !== state.repo
          ? "workspace_repository_mismatch"
          : identity?.clean !== true
            ? "workspace_dirty"
            : identity?.headSha !== state.headSha
              ? `workspace_head_mismatch:expected=${state.headSha}:actual=${identity?.headSha ?? "missing"}`
              : null;
    if (failure) {
      return {
        ok: true,
        admit: {
          accepted: false,
          created: false,
          flowId: flow.flowId,
          revision: flow.revision,
          reason: `owner_admit_workspace_revalidation_failed:${failure}`,
        },
        flow: statusView(flow),
      };
    }

    const now = Date.now();
    const refreshed = refreshPolicySnapshot(state, policy, now, { resetDeadline: true }).state;
    const next = {
      ...refreshed,
      phase:
        policy.mode === "active" && state.findings.length > 0
          ? PHASE.REMEDIATION_QUEUED
          : PHASE.REVIEW_QUEUED,
      workerGeneration: workerGenerationForState(state) + 1,
      activeWorker: null,
      orphanedWorker: null,
      wait: null,
      blocker: null,
      flowWorkspace: {
        path: workspace,
        headSha: identity.headSha,
        provisionedAt: now,
      },
      workspacePreflight: {
        workspace,
        headSha: identity.headSha,
        checkedAt: now,
      },
      updatedAt: now,
    };
    flow = requireApplied(await persistState(resolved.boundFlows, flow, next));
    await applyEffect(api, config, resolved.boundFlows, flow, next, "continue");
    return {
      ok: true,
      admit: {
        accepted: true,
        created: false,
        flowId: flow.flowId,
        revision: flow.revision,
        reason: "owner_admit_reopen_workspace_head_mismatch",
      },
      flow: statusView(flow),
    };
  });
}
