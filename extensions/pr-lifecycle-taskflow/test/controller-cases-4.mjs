import assert from "node:assert/strict";
import test from "node:test";
import {
  PHASE,
  applyWorkerFailure,
  createState,
  recoverState,
  refreshPolicySnapshot,
  reserveWorker,
} from "../src/controller.mjs";
import { NOW, policy, prEvent, reserve } from "./controller-helpers-1.mjs";

void test("infrastructure retries exhaust into a non-auto-requeued block", () => {
  let state = reserve(
    createState(prEvent(), policy({ maxRetries: 1, wallTimeMinutes: 10_080 }), NOW),
  );
  let now = NOW + 10;
  for (let attempt = 1; attempt <= 8; attempt += 1) {
    const failure = applyWorkerFailure(
      state,
      state.activeWorker.sessionKey,
      "worker_session_missing",
      now + 1,
    );
    assert.equal(failure.state.phase, PHASE.REVIEW_QUEUED);
    now = failure.state.infrastructureRetryAt;
    state = reserveWorker(
      failure.state,
      "review",
      `agent:owner-agent:subagent:cap-${attempt}`,
      now,
    ).state;
    assert.equal(state.phase, PHASE.REVIEW_RUNNING);
  }
  const exhausted = applyWorkerFailure(
    state,
    state.activeWorker.sessionKey,
    "worker_session_missing",
    now + 1,
  );
  assert.equal(exhausted.state.phase, PHASE.BLOCKED);
  assert.match(exhausted.state.blocker, /^infrastructure_retry_exhausted:/);
  assert.equal(recoverState(exhausted.state, undefined, NOW + 21).reason, "not_recoverable");
});

void test("owner recovery refreshes a stale policy snapshot without resetting an unchanged deadline", () => {
  const state = createState(prEvent(), policy({ maxCycles: 2, maxRetries: 1 }), NOW);
  const refreshed = refreshPolicySnapshot(
    state,
    policy({ mode: "dogfood", maxCycles: 2, maxRetries: 4, wallTimeMinutes: 180 }),
    NOW + 10,
  );
  assert.equal(refreshed.changed, true);
  assert.equal(refreshed.state.mode, "dogfood");
  assert.equal(refreshed.state.maxCycles, 2);
  assert.equal(refreshed.state.maxRetries, 4);
  assert.equal(refreshed.state.deadlineAt, state.deadlineAt);

  const unchanged = refreshPolicySnapshot(
    refreshed.state,
    policy({
      mode: "dogfood",
      maxCycles: 2,
      maxRetries: 4,
      wallTimeMinutes: 180,
    }),
    NOW + 20,
  );
  assert.equal(unchanged.changed, false);
  assert.equal(unchanged.state.deadlineAt, refreshed.state.deadlineAt);
});
