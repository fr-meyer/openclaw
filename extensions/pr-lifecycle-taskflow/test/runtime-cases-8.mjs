import assert from "node:assert/strict";
import test from "node:test";
import { PHASE } from "../src/controller.mjs";
import { __testing, registerPrLifecycleTaskflow } from "../src/runtime.mjs";
import {
  OWNER,
  SHA_A,
  SHA_C,
  finding,
  makeApi,
  pluginConfig,
  prEvent,
  reviewEvent,
  toolFor,
} from "./runtime-helpers-1.mjs";
import {
  assertScheduledNotificationAcknowledgesBeforeReply,
  details,
  launchWaitingReview,
  notificationCandidate,
} from "./runtime-helpers-2.mjs";

void test("notify renders each kind only in its truthful lifecycle phase", async () => {
  const { api, bound, calls } = makeApi(pluginConfig({ notificationSessionKey: OWNER }));
  registerPrLifecycleTaskflow(api);
  const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const created = await __testing.ingestPullRequest(api, config, prEvent());
  const sinkTool = toolFor(calls, OWNER);
  const patchLiveState = (patch) => {
    const live = bound.flows.get(created.flowId);
    live.stateJson = { ...live.stateJson, ...patch };
    return bound.get(created.flowId);
  };

  let current = patchLiveState({
    phase: PHASE.MERGED,
    wait: null,
  });
  await assert.rejects(
    () =>
      sinkTool.execute("approval-gate-in-merged", notificationCandidate(current, "approval_gate")),
    /notification_kind_phase_mismatch/,
  );
  const merged = details(
    await sinkTool.execute("merged-in-merged", notificationCandidate(current, "merged")),
  );
  assert.equal(merged.deliver, true);
  assert.match(merged.message, /merged into dev from exact reviewed head/);
  assert.equal(bound.get(created.flowId).stateJson.notificationDeliveries.at(-1).kind, "merged");

  current = patchLiveState({
    phase: PHASE.BLOCKED,
    wait: null,
    blocker: "manual intervention required",
  });
  await assert.rejects(
    () => sinkTool.execute("merged-in-blocked", notificationCandidate(current, "merged")),
    /notification_kind_phase_mismatch/,
  );
  const blocked = details(
    await sinkTool.execute("blocked-in-blocked", notificationCandidate(current, "blocked")),
  );
  assert.equal(blocked.deliver, true);
  assert.match(blocked.message, /blocked at exact head/);
  assert.equal(bound.get(created.flowId).stateJson.notificationDeliveries.at(-1).kind, "blocked");

  current = patchLiveState({
    phase: PHASE.MERGE_QUEUED,
    wait: null,
    blocker: null,
  });
  await assert.rejects(
    () => sinkTool.execute("check-wait-without-park", notificationCandidate(current, "check_wait")),
    /notification_kind_phase_mismatch/,
  );

  current = patchLiveState({
    phase: PHASE.MERGE_QUEUED,
    wait: { kind: "check_suite", since: 1, headSha: SHA_A },
  });
  await assert.rejects(
    () => sinkTool.execute("merged-while-check-wait", notificationCandidate(current, "merged")),
    /notification_kind_phase_mismatch/,
  );
  const checkWait = details(
    await sinkTool.execute("check-wait-while-parked", notificationCandidate(current, "check_wait")),
  );
  assert.equal(checkWait.deliver, true);
  assert.match(checkWait.message, /is waiting at exact head/);
  assert.equal(
    bound.get(created.flowId).stateJson.notificationDeliveries.at(-1).kind,
    "check_wait",
  );
});

void test("notification acknowledgement durably confirms the exact event across restart recovery", async () => {
  const { api, bound, calls } = makeApi(pluginConfig({ notificationSessionKey: OWNER }));
  registerPrLifecycleTaskflow(api);
  const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const created = await __testing.ingestPullRequest(api, config, prEvent());
  const waiting = await launchWaitingReview(bound, calls, created.flowId);
  await __testing.ingestReviewResult(
    api,
    config,
    reviewEvent({ claimRef: waiting.stateJson.reviewLease.claimRef }),
  );
  const ready = bound.get(created.flowId);
  assert.equal(ready.stateJson.phase, PHASE.MERGE_READY);
  const sinkTool = toolFor(calls, OWNER);
  const candidate = notificationCandidate(ready, "approval_gate");

  await assert.rejects(
    () => sinkTool.execute("ack-before-delivery", { ...candidate, acknowledge: true }),
    /notification_acknowledgement_missing_delivery/,
  );

  const delivered = details(await sinkTool.execute("first-notify", candidate));
  assert.equal(delivered.deliver, true);
  assert.equal(delivered.retry, false);
  let recorded = bound.get(created.flowId).stateJson.notificationDeliveries;
  assert.equal(recorded.length, 1);
  assert.equal(recorded[0].deliveryState, "pending");
  assert.equal(recorded[0].confirmedAt, undefined);

  const retry = details(await sinkTool.execute("retry-unconfirmed", candidate));
  assert.equal(retry.deliver, true);
  assert.equal(retry.retry, true);
  assert.equal(retry.eventId, delivered.eventId);
  assert.equal(retry.message, delivered.message);
  assert.equal(
    bound.get(created.flowId).stateJson.notificationDeliveries[0].deliveryState,
    "pending",
  );

  const rebuilt = notificationCandidate(bound.get(created.flowId), "approval_gate");
  assert.notEqual(rebuilt.notificationEventId, candidate.notificationEventId);
  const rebuiltRetry = details(await sinkTool.execute("rebuilt-event-retry", rebuilt));
  assert.equal(rebuiltRetry.deliver, true);
  assert.equal(rebuiltRetry.retry, true);
  assert.equal(rebuiltRetry.eventId, delivered.eventId);
  assert.equal(bound.get(created.flowId).stateJson.notificationDeliveries.length, 1);

  calls.schedules.length = 0;
  await __testing.reconcileAtStartup(api, config);
  const recovered = calls.schedules.find((item) => item.deliveryMode === "announce");
  assert.ok(recovered);
  assert.ok(recovered.message.includes(delivered.eventId));
  assertScheduledNotificationAcknowledgesBeforeReply(recovered.message, candidate);

  const staleAck = details(
    await sinkTool.execute("ack-wrong-revision", {
      ...candidate,
      expectedRevision: candidate.expectedRevision + 99,
      acknowledge: true,
    }),
  );
  assert.equal(staleAck.deliver, false);
  assert.equal(staleAck.confirmed, false);
  assert.equal(staleAck.superseded, true);
  assert.equal(
    bound.get(created.flowId).stateJson.notificationDeliveries[0].deliveryState,
    "pending",
  );

  const acknowledged = details(
    await sinkTool.execute("ack-exact-event", { ...candidate, acknowledge: true }),
  );
  assert.equal(acknowledged.deliver, false);
  assert.equal(acknowledged.confirmed, true);
  assert.equal(acknowledged.eventId, delivered.eventId);
  assert.equal(acknowledged.message, delivered.message);
  recorded = bound.get(created.flowId).stateJson.notificationDeliveries;
  assert.equal(recorded.length, 1);
  assert.equal(recorded[0].deliveryState, "confirmed");
  assert.equal(Number.isInteger(recorded[0].confirmedAt), true);
  assert.ok(recorded[0].confirmedAt >= recorded[0].renderedAt);
  const confirmedAt = recorded[0].confirmedAt;

  const duplicateDelivery = details(await sinkTool.execute("delivery-after-ack", candidate));
  assert.equal(duplicateDelivery.deliver, false);
  assert.equal(duplicateDelivery.duplicate, true);
  assert.equal(duplicateDelivery.confirmed, true);

  const duplicateAck = details(
    await sinkTool.execute("ack-after-confirmation", { ...candidate, acknowledge: true }),
  );
  assert.equal(duplicateAck.deliver, false);
  assert.equal(duplicateAck.duplicate, true);
  assert.equal(duplicateAck.confirmed, true);

  const rebuiltAfterAck = details(
    await sinkTool.execute(
      "rebuilt-after-confirmation",
      notificationCandidate(bound.get(created.flowId), "approval_gate"),
    ),
  );
  assert.equal(rebuiltAfterAck.deliver, false);
  assert.equal(rebuiltAfterAck.duplicate, true);
  assert.equal(rebuiltAfterAck.confirmed, true);

  calls.schedules.length = 0;
  await __testing.reconcileAtStartup(api, config);
  assert.equal(
    calls.schedules.some((item) => item.deliveryMode === "announce"),
    false,
  );
  recorded = bound.get(created.flowId).stateJson.notificationDeliveries;
  assert.equal(recorded.length, 1);
  assert.equal(recorded[0].deliveryState, "confirmed");
  assert.equal(recorded[0].confirmedAt, confirmedAt);
});

void test("scheduled notification instruction requires exact acknowledgement before the final reply", async () => {
  const { api, bound, calls } = makeApi(pluginConfig({ notificationSessionKey: OWNER }));
  registerPrLifecycleTaskflow(api);
  const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const created = await __testing.ingestPullRequest(api, config, prEvent());
  const waiting = await launchWaitingReview(bound, calls, created.flowId);
  await __testing.ingestReviewResult(
    api,
    config,
    reviewEvent({ claimRef: waiting.stateJson.reviewLease.claimRef }),
  );
  const ready = bound.get(created.flowId);
  assert.equal(ready.stateJson.phase, PHASE.MERGE_READY);
  const candidate = notificationCandidate(ready, "approval_gate");
  const sinkTool = toolFor(calls, OWNER);

  const delivered = details(await sinkTool.execute("first-notify", candidate));
  assert.equal(delivered.deliver, true);
  assert.equal(delivered.retry, false);
  assert.equal(delivered.eventId, candidate.notificationEventId);
  assert.equal(
    bound.get(created.flowId).stateJson.notificationDeliveries[0].deliveryState,
    "pending",
  );

  const rebuilt = notificationCandidate(bound.get(created.flowId), "approval_gate");
  assert.notEqual(rebuilt.notificationEventId, candidate.notificationEventId);
  assert.notEqual(rebuilt.expectedRevision, candidate.expectedRevision);

  calls.schedules.length = 0;
  await __testing.reconcileAtStartup(api, config);
  const scheduled = calls.schedules.find((item) => item.deliveryMode === "announce");
  assert.ok(scheduled);
  assertScheduledNotificationAcknowledgesBeforeReply(scheduled.message, candidate);
  assert.equal(scheduled.message.includes(JSON.stringify({ action: "notify", ...rebuilt })), false);
  assert.equal(
    scheduled.message.includes(JSON.stringify({ action: "notify", ...rebuilt, acknowledge: true })),
    false,
  );
  assert.match(scheduled.message, /before emitting any user-facing text/);
});

void test("same-repo N=1 queues the second PR with parallel_slot wait", async () => {
  const { api, bound, calls } = makeApi();
  registerPrLifecycleTaskflow(api);
  const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const first = await __testing.ingestPullRequest(api, config, prEvent());
  const second = await __testing.ingestPullRequest(
    api,
    config,
    prEvent({
      eventId: "github:event-43",
      prNumber: 43,
      headSha: SHA_C,
    }),
  );
  const tool = toolFor(calls, OWNER);
  await tool.execute("start-42", {
    action: "continue",
    flowId: first.flowId,
    expectedRevision: bound.get(first.flowId).revision,
  });
  assert.equal(calls.subagents.length, 1);
  assert.equal(calls.subagents[0].cwd, "/workspace/example-repo");
  const output = details(
    await tool.execute("start-43", {
      action: "continue",
      flowId: second.flowId,
      expectedRevision: bound.get(second.flowId).revision,
    }),
  );
  assert.equal(calls.subagents.length, 1);
  assert.equal(output.flow.phase, PHASE.REVIEW_QUEUED);
  assert.equal(output.flow.activeWorker, null);
  assert.equal(output.flow.wait.kind, "parallel_slot");
  assert.equal(output.flow.queuedPosition, 1);
});

void test("same-repo N=2 runs remediator and review on distinct flow worktrees", async () => {
  const { api, bound, calls } = makeApi(
    pluginConfig({
      maxParallelPrs: 2,
    }),
  );
  registerPrLifecycleTaskflow(api);
  const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
  assert.equal(config.repositories.get("example-org/example-repo").maxParallelPrs, 2);
  const first = await __testing.ingestPullRequest(api, config, prEvent());
  const second = await __testing.ingestPullRequest(
    api,
    config,
    prEvent({
      eventId: "github:event-43",
      prNumber: 43,
      headSha: SHA_C,
    }),
  );
  const tool = toolFor(calls, OWNER);
  await tool.execute("start-42-n2", {
    action: "continue",
    flowId: first.flowId,
    expectedRevision: bound.get(first.flowId).revision,
  });
  let firstFlow = bound.get(first.flowId);
  const reviewClaimRef = firstFlow.stateJson.activeWorker.claimRef;
  const workerTool = toolFor(calls, firstFlow.stateJson.activeWorker.sessionKey);
  await workerTool.execute("review-wait-42", {
    action: "report",
    flowId: first.flowId,
    kind: "review",
    outcome: "waiting_review",
    headSha: SHA_A,
    cycle: 0,
    claimRef: reviewClaimRef,
  });
  await __testing.ingestReviewResult(
    api,
    config,
    reviewEvent({
      outcome: "changes_requested",
      findings: [finding()],
      eventId: "broker:changes-42",
      claimRef: reviewClaimRef,
    }),
  );
  firstFlow = bound.get(first.flowId);
  assert.equal(firstFlow.stateJson.phase, PHASE.REMEDIATION_RUNNING);
  const output = details(
    await tool.execute("start-43-n2", {
      action: "continue",
      flowId: second.flowId,
      expectedRevision: bound.get(second.flowId).revision,
    }),
  );
  assert.equal(output.flow.phase, PHASE.REVIEW_RUNNING);
  assert.equal(output.flow.prNumber, 43);
  const kinds = calls.subagents.map((item) => [
    item.cwd,
    item.sessionKey.includes("remediation") ? "remediation" : "review",
  ]);
  const cwds = calls.subagents.map((item) => item.cwd);
  assert.ok(cwds.includes("/workspace/example-org-example-repo-99a40327-pr42"));
  assert.ok(cwds.includes("/workspace/example-org-example-repo-99a40327-pr43"));
  assert.notEqual(cwds.at(-1), cwds.at(-2));
  assert.equal(output.flow.activeWorker.kind, "review");
  assert.equal(firstFlow.stateJson.activeWorker.kind, "remediation");
  void kinds;
});

void test("same-repo N=2 still serializes two live Broker reviews", async () => {
  const { api, bound, calls } = makeApi(pluginConfig({ maxParallelPrs: 2 }));
  registerPrLifecycleTaskflow(api);
  const config = __testing.normalizeRuntimeConfig(api.pluginConfig);
  const first = await __testing.ingestPullRequest(api, config, prEvent());
  const second = await __testing.ingestPullRequest(
    api,
    config,
    prEvent({
      eventId: "github:event-43",
      prNumber: 43,
      headSha: SHA_C,
    }),
  );
  const tool = toolFor(calls, OWNER);
  await tool.execute("start-42-apply", {
    action: "continue",
    flowId: first.flowId,
    expectedRevision: bound.get(first.flowId).revision,
  });
  const output = details(
    await tool.execute("start-43-apply", {
      action: "continue",
      flowId: second.flowId,
      expectedRevision: bound.get(second.flowId).revision,
    }),
  );
  assert.equal(calls.subagents.length, 1);
  assert.equal(output.flow.phase, PHASE.REVIEW_QUEUED);
  assert.equal(output.flow.wait.kind, "parallel_slot");
  assert.equal(output.flow.wait.scope, "review_apply");
});
