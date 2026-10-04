import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { CONTROLLER_ID, PHASE, createState } from "../src/controller.mjs";
import { __testing, registerMergeguezPrLifecycle } from "../src/runtime.mjs";

export const OWNER = "agent:franck:main";
export const REPO = "fr-meyer/speculoos";
export const SHA_A = "a".repeat(40);
export const SHA_B = "b".repeat(40);
const RUNTIME_PATH = fileURLToPath(new URL("../src/runtime.mjs", import.meta.url));
const copy = (value) => (value === undefined ? undefined : structuredClone(value));
export function prEvent(overrides = {}) {
  return {
    eventId: "github:1",
    action: "opened",
    repo: REPO,
    prNumber: 319,
    headSha: SHA_A,
    baseSha: SHA_B,
    baseRef: "dev",
    headRepo: REPO,
    ...overrides,
  };
}
export function pluginConfig(overrides = {}) {
  return {
    enabled: true,
    ownerSessionKey: OWNER,
    recoveryDelayMinutes: 5,
    expectedRuntimePath: RUNTIME_PATH,
    expectedRuntimeSha256: createHash("sha256").update(readFileSync(RUNTIME_PATH)).digest("hex"),
    repositories: {
      [REPO]: {
        enabled: true,
        mode: "active",
        workspace: "/inert/speculoos",
        baseBranches: ["dev"],
        reviewActor: "mergeguez",
        authorActor: "le-commis",
        reviewWorkerAgentId: "reviewer",
        authorWorkerAgentId: "le-commis",
        publisherBrokerId: "fixture-only",
        publisherAttestationRef: "proof:synthetic",
        maxCycles: 2,
        maxRetries: 2,
        wallTimeMinutes: 120,
      },
    },
    ...overrides,
  };
}

// Explicit inert canonical transaction port: no database, native worker, timer,
// broker or Gateway. Each body below is one synchronous in-memory transaction
// entered through an awaited async host operation, preserving real consumer ABI.
class InertCanonicalKernel {
  flows = new Map();
  observations = new Map();
  nextFlow = 1;
  writes = [];
  create(ownerKey, input) {
    if (input.dedupe) {
      const old = [...this.flows.values()].find(
        (flow) =>
          flow.ownerKey === ownerKey &&
          flow.controllerId === input.controllerId &&
          !["succeeded", "failed", "cancelled", "lost"].includes(flow.status) &&
          input.dedupe.stateFields.every(
            (field) => flow.stateJson?.[field] === input.stateJson?.[field],
          ),
      );
      if (old) return { ...copy(old), deduplicated: true };
    }
    const flow = {
      flowId: `flow-${this.nextFlow++}`,
      syncMode: "managed",
      ownerKey,
      controllerId: input.controllerId,
      goal: input.goal,
      status: input.status ?? "running",
      currentStep: input.currentStep ?? null,
      notifyPolicy: input.notifyPolicy ?? "silent",
      stateJson: copy(input.stateJson),
      waitJson: copy(input.waitJson ?? null),
      revision: 0,
      createdAt: input.createdAt ?? Date.now(),
      updatedAt: input.updatedAt ?? Date.now(),
      endedAt: null,
    };
    this.flows.set(flow.flowId, flow);
    this.writes.push({ kind: "create", flowId: flow.flowId, input: copy(input) });
    return copy(flow);
  }
  get(ownerKey, id) {
    const flow = this.flows.get(id);
    return flow?.ownerKey === ownerKey ? copy(flow) : undefined;
  }
  list(ownerKey) {
    return [...this.flows.values()].filter((flow) => flow.ownerKey === ownerKey).map(copy);
  }
  snapshot(ownerSessionKeys) {
    const flows = [...this.flows.values()]
      .filter(
        (flow) => ownerSessionKeys.includes(flow.ownerKey) && flow.controllerId === CONTROLLER_ID,
      )
      .map(copy);
    return {
      flows,
      ownerSessionKeys: [...ownerSessionKeys],
      snapshot: flows.map(({ flowId, ownerKey, revision }) => ({ flowId, ownerKey, revision })),
    };
  }
  mutate(ownerKey, input, status) {
    const current = this.flows.get(input.flowId);
    if (!current || current.ownerKey !== ownerKey) return { applied: false, code: "not_found" };
    if (current.revision !== input.expectedRevision)
      return { applied: false, code: "revision_conflict", current: copy(current) };
    const next = {
      ...current,
      status,
      revision: current.revision + 1,
      ...(input.stateJson !== undefined ? { stateJson: copy(input.stateJson) } : {}),
      ...(input.currentStep !== undefined ? { currentStep: input.currentStep } : {}),
      ...(input.waitJson !== undefined ? { waitJson: copy(input.waitJson) } : {}),
      updatedAt: input.updatedAt ?? Date.now(),
      ...(input.endedAt !== undefined ? { endedAt: input.endedAt } : {}),
    };
    this.flows.set(next.flowId, next);
    this.writes.push({ kind: "mutate", flowId: next.flowId, input: copy(input) });
    return { applied: true, flow: copy(next) };
  }
  reserve(ownerKey, input) {
    const actual = this.snapshot(input.capacitySnapshot.ownerSessionKeys);
    if (JSON.stringify(actual.snapshot) !== JSON.stringify(input.capacitySnapshot.snapshot)) {
      return {
        applied: false,
        code: "capacity_snapshot_conflict",
        current: this.get(ownerKey, input.flowId),
      };
    }
    return this.mutate(ownerKey, input, input.status ?? "running");
  }
}

export function fixture(configInput = pluginConfig()) {
  const kernel = new InertCanonicalKernel();
  const calls = {
    schedules: [],
    unschedules: [],
    launches: [],
    bindings: [],
    closes: [],
    tools: [],
    routes: [],
    services: [],
    events: [],
    logs: [],
    snapshots: [],
    reservations: [],
    cancels: [],
  };
  const hooks = {};
  let nextBinding = 1;
  const createBinding = (kind, ownerKey) => {
    const binding = { id: nextBinding++, kind, ownerKey, closed: false };
    calls.bindings.push(binding);
    return binding;
  };
  const assertBinding = (binding) => {
    if (binding.closed) throw new Error("fixture_binding_closed");
  };
  const close = async (binding) => {
    calls.closes.push(binding.id);
    if (hooks.close) await hooks.close(binding);
    binding.closed = true;
  };
  const operation = async (binding, name, input, body) => {
    assertBinding(binding);
    await Promise.resolve(); // Exercise the consumer's first suspension, not a synchronous stand-in.
    if (hooks.operation) await hooks.operation(binding, name, input);
    assertBinding(binding);
    return body();
  };
  const bindFlows = async ({ sessionKey }) => {
    await Promise.resolve();
    const binding = createBinding("flows", sessionKey);
    return {
      assertCurrent: () => assertBinding(binding),
      close: () => close(binding),
      get: (id) => operation(binding, "get", id, () => kernel.get(sessionKey, id)),
      list: () => operation(binding, "list", undefined, () => kernel.list(sessionKey)),
      createManaged: (input) =>
        operation(binding, "create", input, () => kernel.create(sessionKey, input)),
      resume: (input) =>
        operation(binding, "resume", input, () => kernel.mutate(sessionKey, input, "running")),
      setWaiting: (input) =>
        operation(binding, "setWaiting", input, () =>
          kernel.mutate(sessionKey, input, input.blockedSummary ? "blocked" : "waiting"),
        ),
      finish: (input) =>
        operation(binding, "finish", input, () => kernel.mutate(sessionKey, input, "succeeded")),
      fail: (input) =>
        operation(binding, "fail", input, () => kernel.mutate(sessionKey, input, "failed")),
      capacitySnapshot: (input) =>
        operation(binding, "snapshot", input, () => {
          const result = kernel.snapshot(input.ownerSessionKeys);
          calls.snapshots.push(copy(result));
          return result;
        }),
      reserve: (input) =>
        operation(binding, "reserve", input, () => {
          calls.reservations.push(copy(input));
          return kernel.reserve(sessionKey, input);
        }),
    };
  };
  const bindRuns = async ({ sessionKey }) => {
    await Promise.resolve();
    if (hooks.bindRuns) await hooks.bindRuns(sessionKey);
    const binding = createBinding("runs", sessionKey);
    const visible = (task) =>
      task.childSessionKey === sessionKey ||
      task.requesterSessionKey === sessionKey ||
      sessionKey === `agent:${task.agentId}:main`;
    return {
      close: () => close(binding),
      get: (id) =>
        operation(binding, "runs.get", id, () => {
          const task = kernel.observations.get(id);
          return task && visible(task) ? copy(task) : undefined;
        }),
      list: () =>
        operation(binding, "runs.list", undefined, () =>
          [...kernel.observations.values()].filter(visible).map(copy),
        ),
      cancel: (input) =>
        operation(binding, "cancel", input, () => {
          calls.cancels.push(input);
          const task = kernel.observations.get(input.taskId);
          if (hooks.cancel) return hooks.cancel(input, copy(task));
          if (!task || !visible(task)) return { found: false, cancelled: false };
          if (task.observationSource !== "native-subagent")
            return { found: true, cancelled: false, task: copy(task) };
          task.status = "cancelled";
          return { found: true, cancelled: true, task: copy(task) };
        }),
    };
  };
  const api = {
    testAllowDisposableRuntime: true,
    testReadWorkspaceHead: async (_workspace, head) => head,
    testProvisionFlowWorktree: async () => "/inert/no-git-worktree",
    testPrepareRemediationJob: (job) => ({ jobId: job.jobId, bindingSha256: job.bindingSha256 }),
    testVerifyRemediationEvidence: () => true,
    pluginConfig: configInput,
    logger: Object.fromEntries(
      ["info", "warn", "error"].map((level) => [
        level,
        (message) => calls.logs.push({ level, message }),
      ]),
    ),
    runtime: {
      tasks: {
        authorityVersion: 1,
        availability: { controllerParity: true, canonicalTaskCreate: false, workerLaunch: false },
        managedFlows: { bindSession: bindFlows },
        runs: { bindSession: bindRuns },
      },
      agent: { session: { getSessionEntry: () => null } },
      subagent: {
        run: async (request) => {
          request.assertCurrent();
          calls.launches.push(request);
          if (hooks.launch) return await hooks.launch(request);
          const runId = `native-${calls.launches.length}`;
          const id = `observed-${runId}`;
          kernel.observations.set(id, {
            id,
            taskId: id,
            observationSource: "native-subagent",
            generation: 1,
            requesterSessionKey: OWNER,
            childSessionKey: request.sessionKey,
            runId,
            agentId: request.sessionKey.split(":")[1],
            status: "running",
          });
          return { runId, sessionKey: request.sessionKey };
        },
      },
    },
    agent: { events: { registerAgentEventSubscription: (event) => calls.events.push(event) } },
    session: {
      workflow: {
        scheduleSessionTurn: async (input) => {
          calls.schedules.push(copy(input));
          return { id: `wake-${calls.schedules.length}` };
        },
        unscheduleSessionTurnsByTag: async (input) => {
          calls.unschedules.push(copy(input));
          return { removed: 0, failed: 0 };
        },
      },
    },
    registerTool: (factory, options) => calls.tools.push({ factory, options }),
    registerHttpRoute: (route) => calls.routes.push(route),
    registerService: (service) => calls.services.push(service),
  };
  const config = __testing.normalizeRuntimeConfig(configInput);
  const seed = (stateOverrides = {}, flowOverrides = {}) => {
    const state = { ...createState(prEvent(), config.repositories.get(REPO)), ...stateOverrides };
    const flow = kernel.create(OWNER, {
      controllerId: CONTROLLER_ID,
      stateJson: state,
      currentStep: state.phase,
      status: "running",
    });
    Object.assign(kernel.flows.get(flow.flowId), flowOverrides);
    return copy(kernel.flows.get(flow.flowId));
  };
  const tool = () => {
    registerMergeguezPrLifecycle(api);
    return calls.tools.at(-1).factory({ sessionKey: OWNER });
  };
  return { api, config, kernel, calls, hooks, seed, tool, PHASE };
}

export function assertAllClosed(assert, calls) {
  assert.equal(new Set(calls.closes).size, calls.bindings.length);
  assert.ok(calls.bindings.every((binding) => binding.closed));
}
