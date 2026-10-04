import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { Readable } from "node:stream";
import test from "node:test";
import {
  PHASE,
  STATE_SCHEMA_VERSION,
  MAX_INFRASTRUCTURE_RETRIES,
  PRIMARY_FIXER_MODEL,
  FALLBACK_FIXER_MODEL,
  REVIEW_ACTOR,
  AUTHOR_ACTOR,
  applyWorkerFailure,
  findingsAreActionable,
  isSha,
  isRepo,
  sanitizeFindings,
} from "../src/controller.mjs";
import { BODY_TIMEOUT_MS, MAX_BODY_BYTES, readJsonBody } from "../src/http.mjs";
import * as runtime from "../src/runtime.mjs";
import {
  OWNER,
  REPO,
  SHA_A,
  SHA_B,
  fixture,
  pluginConfig,
  prEvent,
  assertAllClosed,
} from "./inert-parity-host.mjs";

const { __testing, proposeInstalledPublisherRuntimePinMigration, registerMergeguezPrLifecycle } =
  runtime;

const get = (f, id) => f.kernel.get(OWNER, id);
const details = (value) => value.details;
const continueFlow = (f, id, extra = {}) =>
  f.tool().execute("call", { action: "continue", flowId: id, ...extra });

void test("retained publisher policy exports govern persisted defaults and retry exhaustion", () => {
  const state = fixture().seed().stateJson;
  assert.equal(STATE_SCHEMA_VERSION, 1);
  assert.equal(state.schemaVersion, STATE_SCHEMA_VERSION);
  assert.equal(state.reviewActor, REVIEW_ACTOR);
  assert.equal(state.authorActor, AUTHOR_ACTOR);
  assert.equal(state.fixerModel, PRIMARY_FIXER_MODEL);
  assert.equal(state.fixerFallbackModel, FALLBACK_FIXER_MODEL);
  assert.equal(MAX_INFRASTRUCTURE_RETRIES, 8);
  const sessionKey = "agent:reviewer:subagent:policy-contract";
  const failure = (count) =>
    applyWorkerFailure(
      {
        ...state,
        activeWorker: { kind: "review", sessionKey },
        infrastructureRetryCount: count,
      },
      sessionKey,
      "worker_session_missing",
      state.startedAt,
    );
  const lastRetry = failure(MAX_INFRASTRUCTURE_RETRIES - 1);
  assert.equal(lastRetry.effect, "wait");
  assert.equal(lastRetry.state.infrastructureRetryCount, MAX_INFRASTRUCTURE_RETRIES);
  const exhausted = failure(MAX_INFRASTRUCTURE_RETRIES);
  assert.equal(exhausted.state.phase, PHASE.BLOCKED);
  assert.equal(exhausted.state.blocker, "infrastructure_retry_exhausted:worker_session_missing");
});

void test("retained review input exports normalize findings and require actionable scope", () => {
  assert.equal(isSha(SHA_A), true);
  assert.equal(isSha("a".repeat(39)), false);
  assert.equal(isRepo(REPO), true);
  assert.equal(isRepo("owner/repo/extra"), false);
  const findings = sanitizeFindings([
    { id: " issue ", severity: " HIGH ", summary: " Fix it ", path: " src/main.ts " },
    { id: "context", severity: "info", summary: "Additional context" },
  ]);
  assert.deepEqual(findings[0], {
    id: "issue",
    severity: "high",
    summary: "Fix it",
    path: "src/main.ts",
  });
  assert.equal(findingsAreActionable(findings), true);
  assert.equal(findingsAreActionable([{ ...findings[0], path: " " }]), false);
  assert.throws(
    () => sanitizeFindings([{ ...findings[0], unexpected: true }]),
    /unexpected is not allowed/,
  );
});

void test("retained HTTP body reader enforces its default size limit", async () => {
  assert.equal(MAX_BODY_BYTES, 256 * 1024);
  const overhead = Buffer.byteLength(JSON.stringify({ value: "" }));
  const atLimit = Buffer.from(JSON.stringify({ value: "x".repeat(MAX_BODY_BYTES - overhead) }));
  assert.equal(atLimit.length, MAX_BODY_BYTES);
  const tooLarge = Buffer.concat([atLimit, Buffer.from(" ")]);
  await assert.rejects(readJsonBody(Readable.from([tooLarge])), /request_body_too_large/);
  const accepted = await readJsonBody(Readable.from([atLimit]));
  assert.equal(accepted.json.value.length, MAX_BODY_BYTES - overhead);
});

void test("retained HTTP body reader expires an incomplete body at its default deadline", async (t) => {
  assert.equal(BODY_TIMEOUT_MS, 15_000);
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const request = new Readable({ read() {} });
  let settled = false;
  const pending = readJsonBody(request).finally(() => {
    settled = true;
  });
  const rejected = assert.rejects(pending, /request_body_timeout/);
  t.mock.timers.tick(BODY_TIMEOUT_MS - 1);
  await Promise.resolve();
  await Promise.resolve();
  assert.equal(settled, false);
  t.mock.timers.tick(1);
  await rejected;
  assert.equal(settled, true);
  request.destroy();
});

void test("async PR ingress awaits creation and preserves state, workflow and owner", async () => {
  const f = fixture();
  const outcome = await __testing.ingestPullRequest(f.api, f.config, prEvent());
  assert.equal(outcome.created, true);
  assert.equal(get(f, outcome.flowId).stateJson.headSha, SHA_A);
  assert.deepEqual(f.kernel.writes[0].input.dedupe, { stateFields: ["repo", "prNumber"] });
  assert.equal(f.calls.schedules.length, 1);
  assert.equal(f.calls.schedules[0].sessionKey, OWNER);
  assert.equal(f.calls.schedules[0].deleteAfterRun, true);
  assertAllClosed(assert, f.calls);
});

void test("concurrent Promise ingress converges in the inert native transaction without state overwrite", async () => {
  const f = fixture();
  // Both lookups suspend before their empty result, reproducing the original create race.
  const outcomes = await Promise.all([
    __testing.ingestPullRequest(f.api, f.config, prEvent({ eventId: "first" })),
    __testing.ingestPullRequest(
      f.api,
      f.config,
      prEvent({ eventId: "loser", headSha: "c".repeat(40) }),
    ),
  ]);
  assert.equal(f.kernel.flows.size, 1);
  assert.equal(outcomes.filter((value) => value.created).length, 1);
  assert.equal(outcomes[0].flowId, outcomes[1].flowId);
  assert.equal(get(f, outcomes[0].flowId).stateJson.headSha, SHA_A);
  assert.deepEqual(get(f, outcomes[0].flowId).stateJson.seenEventIds, ["first"]);
  assert.equal(f.calls.schedules.length, 1);
  assertAllClosed(assert, f.calls);
});

void test("terminal rows retain original reopen semantics and are not deduplicated", async () => {
  const f = fixture();
  f.seed({ phase: PHASE.MERGE_READY }, { status: "succeeded" });
  const outcome = await __testing.ingestPullRequest(
    f.api,
    f.config,
    prEvent({ eventId: "reopened", action: "reopened" }),
  );
  assert.equal(outcome.created, true);
  assert.equal(f.kernel.flows.size, 2);
  assertAllClosed(assert, f.calls);
});

void test("owner status and stale wake entrypoints await lookups and close the selected binding", async () => {
  const f = fixture();
  const flow = f.seed();
  const tool = f.tool();
  const status = details(await tool.execute("status", { action: "status", flowId: flow.flowId }));
  assert.equal(status.flowId, flow.flowId);
  const stale = details(
    await tool.execute("stale", { action: "continue", flowId: flow.flowId, expectedRevision: 99 }),
  );
  assert.equal(stale.staleWake, true);
  assert.equal(f.calls.launches.length, 0);
  assert.equal(f.kernel.writes.length, 1);
  assertAllClosed(assert, f.calls);
});

void test("normal launch keeps original timeout spelling, tool allowance and held guard until acknowledgement", async () => {
  const f = fixture();
  const flow = f.seed();
  const outcome = details(await continueFlow(f, flow.flowId));
  assert.equal(outcome.flow.activeWorker.runId, "native-1");
  assert.equal(outcome.flow.activeWorker.taskId, "observed-native-1");
  const request = f.calls.launches[0];
  assert.equal(request.runTimeoutSeconds, 3600);
  assert.equal("timeoutSeconds" in request, false);
  assert.deepEqual(request.toolsAlsoAllow, ["mergeguez_pr_lifecycle"]);
  assert.equal(request.deliver, false);
  assert.equal(request.lightContext, true);
  assert.equal(typeof request.assertCurrent, "function");
  assert.throws(() => request.assertCurrent(), /fixture_binding_closed/);
  assert.equal(f.calls.snapshots.length, 2);
  assert.ok(f.calls.snapshots[1].snapshot[0].revision > f.calls.snapshots[0].snapshot[0].revision);
  assertAllClosed(assert, f.calls);
});

void test("selected binding remains live until accepted async launch work has settled", async () => {
  const f = fixture();
  const flow = f.seed();
  let acknowledge;
  const pending = new Promise((resolve) => {
    acknowledge = resolve;
  });
  let entered;
  const started = new Promise((resolve) => {
    entered = resolve;
  });
  f.hooks.launch = async (request) => {
    entered(request);
    return await pending;
  };
  const operation = continueFlow(f, flow.flowId);
  const request = await Promise.race([
    started,
    operation.then(() => {
      throw new Error("launch completed without entering original subagent owner");
    }),
  ]);
  assert.doesNotThrow(() => request.assertCurrent());
  assert.ok(f.calls.bindings.some((binding) => binding.kind === "flows" && !binding.closed));
  acknowledge({ runId: "accepted-but-not-observed", sessionKey: request.sessionKey });
  const result = details(await operation);
  assert.equal(result.flow.blocker, "worker_launch_outcome_unknown");
  assertAllClosed(assert, f.calls);
});

void test("capacity is refreshed after preflight and an inserted occupant prevents launch", async () => {
  const f = fixture();
  const flow = f.seed();
  let snapshots = 0;
  f.hooks.operation = (_binding, name) => {
    if (name === "snapshot" && ++snapshots === 2) {
      f.seed({
        prNumber: 320,
        activeWorker: { kind: "review", sessionKey: "agent:other:subagent:x" },
        phase: PHASE.REVIEW_RUNNING,
      });
    }
  };
  await continueFlow(f, flow.flowId);
  assert.equal(f.calls.launches.length, 0);
  assert.equal(f.calls.reservations.length, 0);
  assert.equal(get(f, flow.flowId).stateJson.wait.kind, "parallel_slot");
  assertAllClosed(assert, f.calls);
});

void test("worker transaction rejects capacity snapshot changed after selection without launching", async () => {
  const f = fixture();
  const flow = f.seed();
  f.hooks.operation = (_binding, name) => {
    if (name === "reserve") {
      f.seed({ prNumber: 321 });
    }
  };
  await continueFlow(f, flow.flowId);
  assert.equal(f.calls.reservations.length, 1);
  assert.equal(f.calls.launches.length, 0);
  assert.equal(get(f, flow.flowId).stateJson.activeWorker, null);
  assertAllClosed(assert, f.calls);
});

void test("snapshot fence fields and flow values are detached before async reserve", () => {
  const original = {
    ownerSessionKeys: [OWNER],
    snapshot: [{ flowId: "flow", ownerKey: OWNER, revision: 1 }],
    flows: [{ stateJson: { repo: REPO } }],
  };
  const captured = __testing.captureCapacitySnapshot(original);
  original.snapshot[0].revision = 999;
  original.ownerSessionKeys[0] = "evil";
  original.flows[0].stateJson.repo = "evil";
  assert.equal(captured.snapshot[0].revision, 1);
  assert.equal(captured.ownerSessionKeys[0], OWNER);
  assert.equal(captured.flows[0].stateJson.repo, REPO);
  assert.throws(() => {
    captured.snapshot[0].revision = 10;
  }, TypeError);
  assert.throws(() => captured.ownerSessionKeys.push("evil"), TypeError);
});

void test("invocation throw is unknown launch, retains reservation, and startup never relaunches it", async () => {
  const f = fixture();
  const flow = f.seed();
  f.hooks.launch = async () => {
    throw new Error("ack transport lost after admission");
  };
  const outcome = details(await continueFlow(f, flow.flowId));
  assert.equal(outcome.flow.blocker, "worker_launch_outcome_unknown");
  const held = get(f, flow.flowId).stateJson;
  assert.ok(held.activeWorker);
  assert.equal(held.launchOutcome.status, "unknown");
  const count = f.kernel.writes.length;
  await __testing.reconcileAtStartup(f.api, f.config);
  await f.calls.tools[0]
    .factory({ sessionKey: OWNER })
    .execute("recover", { action: "recover", flowId: flow.flowId });
  assert.equal(f.calls.launches.length, 1);
  assert.equal(f.kernel.writes.length, count);
  assertAllClosed(assert, f.calls);
});

void test("mismatched session acknowledgement is held with exact observed session evidence", async () => {
  const f = fixture();
  const flow = f.seed();
  f.hooks.launch = async () => ({
    runId: "stray-run",
    sessionKey: "agent:reviewer:subagent:unexpected",
  });
  await continueFlow(f, flow.flowId);
  const state = get(f, flow.flowId).stateJson;
  assert.equal(state.blocker, "worker_launch_outcome_unknown");
  assert.equal(state.launchOutcome.observedSessionKey, "agent:reviewer:subagent:unexpected");
  assert.equal(state.launchOutcome.runId, "stray-run");
  assertAllClosed(assert, f.calls);
});

void test("terminal event awaits enumeration and native unknown overrides bare end plus absent session", async () => {
  const f = fixture();
  const flow = f.seed();
  await continueFlow(f, flow.flowId);
  const state = get(f, flow.flowId).stateJson;
  f.kernel.observations.get(state.activeWorker.taskId).status = "unknown";
  const before = get(f, flow.flowId).revision;
  const result = await __testing.reconcileTerminalWorkerEvent(f.api, f.config, {
    stream: "lifecycle",
    runId: state.activeWorker.runId,
    sessionKey: state.activeWorker.sessionKey,
    data: { phase: "end" },
  });
  assert.equal(result.reason, "native_worker_outcome_unknown");
  assert.equal(get(f, flow.flowId).revision, before);
  assert.equal(f.calls.launches.length, 1);
  assertAllClosed(assert, f.calls);
});

void test("bare terminal event with missing or still-running observation cannot credit success or retry work", async () => {
  for (const status of ["missing", "running"]) {
    const f = fixture();
    const flow = f.seed();
    await continueFlow(f, flow.flowId);
    const state = get(f, flow.flowId).stateJson;
    if (status === "missing") {
      f.kernel.observations.clear();
    }
    const before = get(f, flow.flowId).revision;
    const result = await __testing.reconcileTerminalWorkerEvent(f.api, f.config, {
      stream: "lifecycle",
      runId: state.activeWorker.runId,
      data: { phase: "end" },
    });
    assert.equal(result.reason, "worker_terminal_observation_pending");
    assert.equal(get(f, flow.flowId).revision, before);
    assert.equal(f.calls.launches.length, 1);
    assert.equal(f.calls.schedules.at(-1).deleteAfterRun, true);
    assertAllClosed(assert, f.calls);
  }
});

void test("unknown retained legacy observation stays held through startup, recover and terminal event", async () => {
  const f = fixture();
  const flow = f.seed();
  await continueFlow(f, flow.flowId);
  const state = get(f, flow.flowId).stateJson;
  const observation = f.kernel.observations.get(state.activeWorker.taskId);
  observation.observationSource = "legacy-task";
  observation.status = "unknown";
  const before = get(f, flow.flowId).revision;
  await __testing.reconcileAtStartup(f.api, f.config);
  const tool = f.calls.tools[0].factory({ sessionKey: OWNER });
  const recovered = details(
    await tool.execute("recover", { action: "recover", flowId: flow.flowId }),
  );
  assert.equal(recovered.recovery, "legacy_worker_outcome_unknown");
  const terminal = await __testing.reconcileTerminalWorkerEvent(f.api, f.config, {
    stream: "lifecycle",
    runId: state.activeWorker.runId,
    data: { phase: "end" },
  });
  assert.equal(terminal.reason, "legacy_worker_outcome_unknown");
  assert.equal(get(f, flow.flowId).revision, before);
  assert.equal(f.calls.launches.length, 1);
  assertAllClosed(assert, f.calls);
});

void test("known terminal observation drives original structured-report recovery without assuming lifecycle end success", async () => {
  const f = fixture();
  const flow = f.seed();
  await continueFlow(f, flow.flowId);
  const state = get(f, flow.flowId).stateJson;
  const observation = f.kernel.observations.get(state.activeWorker.taskId);
  observation.status = "failed";
  observation.error = "explicit worker error";
  const result = await __testing.reconcileTerminalWorkerEvent(f.api, f.config, {
    stream: "lifecycle",
    runId: state.activeWorker.runId,
    data: { phase: "end" },
  });
  assert.equal(result.handled, true);
  assert.ok(
    get(f, flow.flowId).stateJson.retryCount > 0 ||
      get(f, flow.flowId).stateJson.infrastructureRetryCount > 0,
  );
  assertAllClosed(assert, f.calls);
});

void test("startup leaves historical infrastructure block unchanged and removes its wake", async () => {
  const f = fixture();
  const flow = f.seed(
    { phase: PHASE.BLOCKED, blocker: "worker_start_failed:rate_limit" },
    { status: "blocked" },
  );
  const before = get(f, flow.flowId);
  await __testing.reconcileAtStartup(f.api, f.config);
  assert.deepEqual(get(f, flow.flowId), before);
  assert.equal(f.calls.schedules.length, 0);
  assert.ok(f.calls.unschedules.length);
  assertAllClosed(assert, f.calls);
});

void test("legacy exact task observation remains read-only and does not create or adopt a lease", async () => {
  const f = fixture();
  const worker = {
    sessionKey: "agent:reviewer:subagent:legacy",
    runId: "old-run",
    taskId: "old-id",
  };
  f.kernel.observations.set("old-id", {
    id: "old-id",
    observationSource: "legacy-task",
    requesterSessionKey: OWNER,
    childSessionKey: worker.sessionKey,
    agentId: "reviewer",
    runId: worker.runId,
    status: "running",
  });
  const task = await __testing.currentWorkerTask(f.api, OWNER, { activeWorker: worker });
  assert.equal(task.id, "old-id");
  assert.equal(task.observationSource, "legacy-task");
  assert.equal(f.kernel.flows.size, 0);
  assert.equal(f.calls.cancels.length, 0);
  assertAllClosed(assert, f.calls);
});

void test("one denied ledger does not hide an exact observation from the admitted owner", async () => {
  const f = fixture();
  const worker = {
    sessionKey: "agent:reviewer:subagent:legacy",
    runId: "old-run",
    taskId: "old-id",
  };
  f.hooks.bindRuns = (session) => {
    if (session !== OWNER) {
      throw new Error("fixture_denied");
    }
  };
  f.kernel.observations.set("old-id", {
    id: "old-id",
    requesterSessionKey: OWNER,
    childSessionKey: worker.sessionKey,
    observationSource: "legacy-task",
    agentId: "reviewer",
    runId: worker.runId,
    status: "running",
  });
  assert.equal(
    (await __testing.currentWorkerTask(f.api, OWNER, { activeWorker: worker })).id,
    "old-id",
  );
  assertAllClosed(assert, f.calls);
});

void test("native unknown orphan remains held even when session is absent", async () => {
  const f = fixture();
  const worker = {
    sessionKey: "agent:reviewer:subagent:unknown",
    runId: "run-u",
    taskId: "unknown-id",
  };
  f.kernel.observations.set("unknown-id", {
    id: "unknown-id",
    requesterSessionKey: OWNER,
    childSessionKey: worker.sessionKey,
    observationSource: "native-subagent",
    generation: 1,
    agentId: "reviewer",
    runId: worker.runId,
    status: "unknown",
  });
  const result = await __testing.reconcileOrphanedWorker(f.api, OWNER, worker);
  assert.equal(result.safe, false);
  assert.equal(result.reason, "orphan_native_outcome_unknown");
  assert.equal(f.calls.cancels.length, 0);
  assertAllClosed(assert, f.calls);
});

void test("native orphan cancellation awaits the existing owner and closes ephemeral ledgers", async () => {
  const f = fixture();
  const worker = {
    sessionKey: "agent:reviewer:subagent:orphan",
    runId: "run-o",
    taskId: "orphan-id",
  };
  f.kernel.observations.set("orphan-id", {
    id: "orphan-id",
    requesterSessionKey: OWNER,
    childSessionKey: worker.sessionKey,
    observationSource: "native-subagent",
    generation: 1,
    agentId: "reviewer",
    runId: worker.runId,
    status: "running",
  });
  const result = await __testing.reconcileOrphanedWorker(f.api, OWNER, worker);
  assert.equal(result.safe, true);
  assert.equal(result.reason, "orphan_task_cancelled");
  assert.equal(f.calls.cancels.length, 1);
  assertAllClosed(assert, f.calls);
});

void test("native cancellation error, nonacknowledgement and throw remain held despite absent session", async () => {
  for (const outcome of [
    { cancelled: false },
    { cancelled: true, error: "cleanup incomplete" },
    { killed: true },
    "throw",
  ]) {
    const f = fixture();
    const worker = {
      sessionKey: "agent:reviewer:subagent:orphan",
      runId: "run-o",
      taskId: "orphan-id",
    };
    f.kernel.observations.set("orphan-id", {
      id: "orphan-id",
      requesterSessionKey: OWNER,
      childSessionKey: worker.sessionKey,
      observationSource: "native-subagent",
      generation: 1,
      agentId: "reviewer",
      runId: worker.runId,
      status: "running",
    });
    f.hooks.cancel = () => {
      if (outcome === "throw") {
        throw new Error("unknown cancellation transport");
      }
      return outcome;
    };
    const result = await __testing.reconcileOrphanedWorker(f.api, OWNER, worker);
    assert.equal(result.safe, false);
    assert.equal(result.reason, "orphan_native_cancellation_unknown");
    assert.equal(f.calls.cancels.length, 1);
    assertAllClosed(assert, f.calls);
  }
});

void test("legacy active orphan cannot be adopted or declared cancelled from absent liveness", async () => {
  const f = fixture();
  const worker = {
    sessionKey: "agent:reviewer:subagent:legacy",
    runId: "old-run",
    taskId: "old-id",
  };
  f.kernel.observations.set("old-id", {
    id: "old-id",
    requesterSessionKey: OWNER,
    childSessionKey: worker.sessionKey,
    observationSource: "legacy-task",
    agentId: "reviewer",
    runId: worker.runId,
    status: "running",
  });
  const result = await __testing.reconcileOrphanedWorker(f.api, OWNER, worker);
  assert.equal(result.safe, false);
  assert.equal(result.reason, "orphan_legacy_cancellation_unavailable");
  assert.equal(f.calls.cancels.length, 0);
  assertAllClosed(assert, f.calls);
});

void test("async review ingestion retains merge-ready terminal semantics and explicit merge authorization", async () => {
  const f = fixture(pluginConfig({ notificationSessionKey: OWNER }));
  const flow = f.seed();
  await continueFlow(f, flow.flowId);
  const event = {
    eventId: "review-approved",
    repo: REPO,
    prNumber: 319,
    headSha: SHA_A,
    outcome: "approved",
    reviewId: "synthetic-review",
    coverageComplete: true,
    retryAllowed: false,
    findings: [],
  };
  const result = await __testing.ingestReviewResult(f.api, f.config, event);
  const stored = get(f, flow.flowId);
  assert.equal(result.accepted, true);
  assert.equal(stored.stateJson.phase, PHASE.MERGE_READY);
  assert.equal(stored.status, "succeeded");
  assert.ok(f.calls.schedules.some((wake) => wake.message.includes("explicit")));
  assert.equal(f.calls.launches.length, 1);
  assertAllClosed(assert, f.calls);
});

void test("worker report entrypoint awaits CAS and retains worker caller identity", async () => {
  const f = fixture();
  const flow = f.seed();
  await continueFlow(f, flow.flowId);
  const worker = get(f, flow.flowId).stateJson.activeWorker;
  const tool = f.calls.tools[0].factory({ sessionKey: worker.sessionKey });
  const result = details(
    await tool.execute("report", {
      action: "report",
      flowId: flow.flowId,
      kind: "review",
      outcome: "approved",
      headSha: SHA_A,
      cycle: 0,
      coverageComplete: true,
      reviewId: "synthetic-worker-report",
      findings: [],
    }),
  );
  assert.equal(result.ok, true);
  assert.equal(get(f, flow.flowId).stateJson.phase, PHASE.MERGE_READY);
  assertAllClosed(assert, f.calls);
});

void test("startup queued observation and owner recovery use async bindings without running work at startup", async () => {
  const f = fixture();
  const flow = f.seed();
  await __testing.reconcileAtStartup(f.api, f.config);
  assert.equal(f.calls.launches.length, 0);
  assert.equal(f.calls.schedules.length, 1);
  const result = details(
    await f.tool().execute("recover", { action: "recover", flowId: flow.flowId }),
  );
  assert.equal(result.ok, true);
  assert.equal(f.calls.launches.length, 1);
  assertAllClosed(assert, f.calls);
});

void test("primary native observation error survives cleanup errors and every allocated binding closes", async () => {
  const f = fixture();
  const primary = new Error("native observation unavailable");
  Object.freeze(primary);
  f.hooks.operation = (_binding, name) => {
    if (name === "runs.list") {
      throw primary;
    }
  };
  f.hooks.close = (binding) => {
    binding.closed = true;
    throw Object.assign(new Error("private close failure"), { code: "close_failed" });
  };
  await assert.rejects(
    __testing.currentWorkerTask(f.api, OWNER, {
      activeWorker: { sessionKey: "agent:reviewer:subagent:x", runId: "x" },
    }),
    (error) => error === primary,
  );
  assert.deepEqual(__testing.bindingCleanupFailureCodes(primary), [
    "close_failed",
    "close_failed",
    "close_failed",
  ]);
  assertAllClosed(assert, f.calls);
});

void test("binding cleanup preserves frozen primary, attempts all owners and exposes only bounded codes", async () => {
  const primary = new Error("primary-private-payload");
  Object.freeze(primary);
  const attempted = [];
  const f = fixture();
  const owners = Array.from({ length: 11 }, (_, index) => ({
    close: async () => {
      attempted.push(index);
      throw Object.assign(new Error("private failure payload"), {
        code: index === 1 ? "unsafe text\n" : `close_${index}`,
      });
    },
  }));
  await assert.rejects(
    __testing.withTaskBindingClosure(f.api, owners, async () => {
      throw primary;
    }),
    (error) => error === primary,
  );
  assert.equal(attempted.length, 11);
  assert.equal(__testing.bindingCleanupFailureCodes(primary).length, 8);
  assert.equal(__testing.bindingCleanupFailureCodes(primary)[1], "task_binding_close_failed");
  assert.ok(!JSON.stringify(f.calls.logs).includes("private failure payload"));
});

void test("successful operation with failed binding closure fails closed", async () => {
  const f = fixture();
  let secondClosed = false;
  await assert.rejects(
    __testing.withTaskBindingClosure(
      f.api,
      [
        {
          close: async () => {
            throw Object.assign(new Error("private"), { code: "custody_close" });
          },
        },
        {
          close: async () => {
            secondClosed = true;
          },
        },
      ],
      async () => "success",
    ),
    (error) =>
      error.code === "task_binding_close_failed" &&
      __testing.bindingCleanupFailureCodes(error)[0] === "custody_close",
  );
  assert.equal(secondClosed, true);
});

void test("advertised parity validates run port and closes already allocated owners on incompatibility", async () => {
  const f = fixture();
  const original = f.api.runtime.tasks.runs.bindSession;
  let calls = 0;
  f.api.runtime.tasks.runs.bindSession = async (input) => {
    const bound = await original(input);
    if (++calls === 2) {
      delete bound.cancel;
    }
    return bound;
  };
  await assert.rejects(
    __testing.currentWorkerTask(f.api, OWNER, {
      activeWorker: { sessionKey: "agent:reviewer:subagent:x", runId: "x" },
    }),
    /publisher_run_parity_port_unavailable/,
  );
  assertAllClosed(assert, f.calls);
});

void test("compatibility guard permits parity with canonical creation and private launch disabled", () => {
  const f = fixture();
  registerMergeguezPrLifecycle(f.api);
  assert.equal(f.calls.services.length, 1);
  assert.equal(f.calls.events.length, 1);
  for (const unavailable of ["version", "parity"]) {
    const other = fixture();
    if (unavailable === "version") {
      other.api.runtime.tasks.authorityVersion = 0;
    } else {
      other.api.runtime.tasks.availability.controllerParity = false;
    }
    registerMergeguezPrLifecycle(other.api);
    assert.equal(other.calls.services.length, 0);
    assert.equal(other.calls.events.length, 0);
  }
});

void test("old installed source pin remains fail-closed on changed runtime despite enabled config", () => {
  const f = fixture(
    pluginConfig({
      expectedRuntimeSha256: "7e6cbe8ab75213049fc21f85dc5df4b2c740ac9cfd35edd1d4aadc4a92167e74",
    }),
  );
  registerMergeguezPrLifecycle(f.api);
  assert.equal(f.calls.services.length, 0);
  assert.ok(f.calls.logs.some((log) => log.message.includes("source integrity failed")));
});

void test("pure pin migration requires exact installed preimage and same path, emits no authority or config writes", () => {
  const path = "/installed/mergeguez/runtime.mjs";
  const old = "7e6cbe8ab75213049fc21f85dc5df4b2c740ac9cfd35edd1d4aadc4a92167e74";
  const config = {
    enabled: true,
    expectedRuntimePath: path,
    expectedRuntimeSha256: old,
    privateSecret: "do-not-copy",
  };
  const transition = { fromPath: path, toPath: path, fromSha256: old, toSha256: "d".repeat(64) };
  const proposal = proposeInstalledPublisherRuntimePinMigration(config, transition);
  assert.equal(proposal.applied, false);
  assert.equal(proposal.requiresPluginOwnedDoctorRelease, true);
  assert.equal(config.expectedRuntimeSha256, old);
  assert.equal("privateSecret" in proposal.patch, false);
  transition.toSha256 = "e".repeat(64);
  assert.equal(proposal.patch.expectedRuntimeSha256, "d".repeat(64));
  for (const bad of [
    { fromPath: "/different" },
    { toPath: "/relocated" },
    { fromSha256: "a".repeat(64) },
    { toSha256: old },
    { toSha256: "bad" },
  ]) {
    assert.throws(() =>
      proposeInstalledPublisherRuntimePinMigration(config, { ...transition, ...bad }),
    );
  }
  assert.throws(
    () =>
      proposeInstalledPublisherRuntimePinMigration(
        { ...config, expectedRuntimeSha256: "d".repeat(64) },
        transition,
      ),
    /preimage_mismatch/,
  );
});

void test("signed HTTP webhook retains async ingestion and authentication with no external side effects", async () => {
  const f = fixture();
  const secret = "synthetic-only";
  const body = Buffer.from(
    JSON.stringify({
      action: "opened",
      repository: { full_name: REPO },
      pull_request: {
        number: 319,
        head: { sha: SHA_A, repo: { full_name: REPO } },
        base: { sha: SHA_B, ref: "dev" },
      },
    }),
  );
  const request = Readable.from([body]);
  request.method = "POST";
  request.headers = {
    "content-type": "application/json",
    "x-github-event": "pull_request",
    "x-github-delivery": "synthetic-delivery",
    "x-hub-signature-256": `sha256=${createHmac("sha256", secret).update(body).digest("hex")}`,
  };
  request.socket = { remoteAddress: "127.0.0.1" };
  let response;
  const res = {
    setHeader() {},
    end: (value) => {
      response = JSON.parse(value);
    },
  };
  await __testing.createRouteHandler({
    kind: "github",
    secret,
    ingest: (event) => __testing.ingestPullRequest(f.api, f.config, event),
  })(request, res);
  assert.equal(res.statusCode, 202);
  assert.equal(response.created, true);
  assert.equal(f.kernel.flows.size, 1);
  assertAllClosed(assert, f.calls);
});
