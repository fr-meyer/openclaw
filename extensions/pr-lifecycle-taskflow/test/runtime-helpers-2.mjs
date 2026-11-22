import assert from "node:assert/strict";
import { PHASE } from "../src/controller.mjs";
import { __testing, registerPrLifecycleTaskflow } from "../src/runtime.mjs";
import { OWNER, SHA_A, SHA_B, SHA_C, prEvent, toolFor } from "./runtime-helpers-1.mjs";

export async function ownerAuthorizeAndContinue(calls, bound, flowId) {
  const owner = toolFor(calls, OWNER);
  let flow = bound.get(flowId);
  const authorized = details(
    await owner.execute("authorize-after-review", {
      action: "authorize",
      flowId,
      expectedRevision: flow.revision,
    }),
  );
  assert.equal(authorized.queued, true);
  assert.equal(authorized.flow.phase, PHASE.MERGE_QUEUED);
  flow = bound.get(flowId);
  return details(
    await owner.execute("continue-after-authorization", {
      action: "continue",
      flowId,
      expectedRevision: flow.revision,
    }),
  );
}

export function bindQueuedReview(bound, flowId, claimRef = "claim:test") {
  const flow = bound.flows.get(flowId);
  flow.stateJson = {
    ...flow.stateJson,
    phase: PHASE.REVIEW_WAITING,
    reviewLease: {
      kind: "review",
      sessionKey: OWNER,
      headSha: flow.stateJson.headSha,
      cycle: flow.stateJson.cycle,
      claimRef,
      reviewId: null,
      reservedAt: 1,
      waitingSince: 1,
    },
  };
  return claimRef;
}

export async function launchWaitingReview(
  bound,
  calls,
  flowId,
  { headSha = SHA_A, cycle = 0, label = "review-wait" } = {},
) {
  const ownerTool = toolFor(calls, OWNER);
  let flow = bound.get(flowId);
  await ownerTool.execute(`${label}-start`, {
    action: "continue",
    flowId: flow.flowId,
    expectedRevision: flow.revision,
  });
  flow = bound.get(flow.flowId);
  const claimRef = flow.stateJson.activeWorker.claimRef;
  const workerTool = toolFor(calls, flow.stateJson.activeWorker.sessionKey);
  await workerTool.execute(label, {
    action: "report",
    flowId: flow.flowId,
    kind: "review",
    outcome: "waiting_review",
    headSha,
    cycle,
    claimRef,
  });
  return bound.get(flow.flowId);
}

export function details(toolResult) {
  return toolResult.details;
}

export function notificationCandidate(flow, kind) {
  const state = flow.stateJson;
  return {
    action: "notify",
    flowId: flow.flowId,
    expectedRevision: flow.revision,
    headSha: state.headSha,
    phase: state.phase,
    notificationKind: kind,
    notificationEventId: `mprn:${flow.flowId}:${flow.revision}:${state.headSha}:${state.phase}:${kind}`,
  };
}

export function assertScheduledNotificationAcknowledgesBeforeReply(message, candidate) {
  const notifyPayload = JSON.stringify({ action: "notify", ...candidate });
  const ackPayload = JSON.stringify({ action: "notify", ...candidate, acknowledge: true });
  const notifyAt = message.indexOf(notifyPayload);
  const ackAt = message.indexOf(ackPayload);
  const emitAt = message.indexOf(
    "Emit the returned message exactly and nothing else only after acknowledgement returns confirmed:true.",
  );
  assert.ok(notifyAt >= 0);
  assert.ok(ackAt > notifyAt);
  assert.ok(emitAt > ackAt);
  assert.match(
    message,
    /If acknowledgement is rejected or not confirmed, emit no user-facing text/,
  );
  assert.equal(
    message.includes("reply with the returned message exactly and nothing else, then call"),
    false,
  );
}

export async function createWorkspaceHeadMismatchBlock(api, bound, calls) {
  api.__testReadWorkspaceHead = async () => SHA_C;
  registerPrLifecycleTaskflow(api);
  const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const created = await __testing.ingestPullRequest(api, config, prEvent());
  const queued = bound.get(created.flowId);
  const output = details(
    await toolFor(calls, OWNER).execute("block-workspace", {
      action: "continue",
      flowId: queued.flowId,
      expectedRevision: queued.revision,
    }),
  );
  assert.equal(output.flow.phase, PHASE.BLOCKED);
  assert.equal(output.flow.blocker, `workspace_head_mismatch:expected=${SHA_A}:actual=${SHA_C}`);
  return bound.get(created.flowId);
}

export async function admitAndStartReview(tool) {
  const admitted = details(
    await tool.execute("admit-ghost", {
      action: "admit",
      repo: "example-org/example-repo",
      prNumber: 42,
      headSha: SHA_A,
      baseSha: SHA_B,
      baseRef: "dev",
    }),
  );
  const continued = details(
    await tool.execute("continue-ghost", {
      action: "continue",
      flowId: admitted.admit.flowId,
      expectedRevision: admitted.admit.revision,
    }),
  );
  return { admitted, continued };
}
