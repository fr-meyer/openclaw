import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { mergePolicyDigest, normalizePolicy } from "../src/controller.mjs";

export const SHA_A = "a".repeat(40);
export const SHA_B = "b".repeat(40);
export const SHA_C = "c".repeat(40);
export const OWNER = "agent:owner-agent:main";
export const INDEX_PATH = fileURLToPath(new URL("../index.mjs", import.meta.url));
export const RUNTIME_PATH = fileURLToPath(new URL("../src/runtime.mjs", import.meta.url));
export const CONTROLLER_PATH = fileURLToPath(new URL("../src/controller.mjs", import.meta.url));
export const HTTP_PATH = fileURLToPath(new URL("../src/http.mjs", import.meta.url));
export function sourceSetSha256(reader = readFileSync) {
  const modules = {
    index: createHash("sha256").update(reader(INDEX_PATH)).digest("hex"),
    runtime: createHash("sha256")
      .update(
        [
          fileURLToPath(new URL("../src/runtime.mjs", import.meta.url)),
          fileURLToPath(new URL("../src/runtime-foundation.mjs", import.meta.url)),
          fileURLToPath(new URL("../src/runtime-remediation.mjs", import.meta.url)),
          fileURLToPath(new URL("../src/runtime-integrity.mjs", import.meta.url)),
          fileURLToPath(new URL("../src/runtime-merge-gates.mjs", import.meta.url)),
          fileURLToPath(new URL("../src/runtime-merge.mjs", import.meta.url)),
          fileURLToPath(new URL("../src/runtime-config.mjs", import.meta.url)),
          fileURLToPath(new URL("../src/runtime-state-effects.mjs", import.meta.url)),
          fileURLToPath(new URL("../src/runtime-contention.mjs", import.meta.url)),
          fileURLToPath(new URL("../src/runtime-workspace.mjs", import.meta.url)),
          fileURLToPath(new URL("../src/runtime-dispatch.mjs", import.meta.url)),
          fileURLToPath(new URL("../src/runtime-ingest.mjs", import.meta.url)),
          fileURLToPath(new URL("../src/runtime-status.mjs", import.meta.url)),
          fileURLToPath(new URL("../src/runtime-tools.mjs", import.meta.url)),
          fileURLToPath(new URL("../src/runtime-registration.mjs", import.meta.url)),
          fileURLToPath(new URL("../src/runtime-testing.mjs", import.meta.url)),
        ]
          .map(
            (path) =>
              path.slice(path.lastIndexOf("/") + 1) +
              ":" +
              createHash("sha256").update(reader(path)).digest("hex") +
              "\n",
          )
          .join(""),
      )
      .digest("hex"),
    controller: createHash("sha256")
      .update(
        [
          fileURLToPath(new URL("../src/controller.mjs", import.meta.url)),
          fileURLToPath(new URL("../src/controller-constants.mjs", import.meta.url)),
          fileURLToPath(new URL("../src/controller-policy.mjs", import.meta.url)),
          fileURLToPath(new URL("../src/controller-validation.mjs", import.meta.url)),
          fileURLToPath(new URL("../src/controller-events.mjs", import.meta.url)),
          fileURLToPath(new URL("../src/controller-workers.mjs", import.meta.url)),
          fileURLToPath(new URL("../src/controller-recovery.mjs", import.meta.url)),
        ]
          .map(
            (path) =>
              path.slice(path.lastIndexOf("/") + 1) +
              ":" +
              createHash("sha256").update(reader(path)).digest("hex") +
              "\n",
          )
          .join(""),
      )
      .digest("hex"),
    http: createHash("sha256").update(reader(HTTP_PATH)).digest("hex"),
  };
  return createHash("sha256")
    .update(
      `index:${modules.index}\nruntime:${modules.runtime}\n` +
        `controller:${modules.controller}\nhttp:${modules.http}\n`,
    )
    .digest("hex");
}
export const RUNTIME_SHA256 = sourceSetSha256();

export function remediatorProfile(overrides = {}) {
  return {
    schemaVersion: 1,
    repository: "example-org/example-repo",
    pullRequests: [42],
    headBranchPattern: "^feat/",
    baseBranches: ["dev"],
    seedWorkspace: "/workspace/example-repo",
    worktreeRoot: "/workspace",
    allowedWritePaths: ["src/"],
    requiredTestPaths: ["src/"],
    validationCommands: [{ argv: ["node", "--version"], covers: ["src/"], timeoutSeconds: 30 }],
    publicationMode: "attested-broker",
    publicationRoute: "exact-lease",
    commitSubject: "fix: apply reviewed PR remediation",
    attestationPolicy: "required",
    ...overrides,
  };
}

export function mergeAuthorization(overrides = {}) {
  return {
    schemaVersion: 1,
    authorizationId: "auth-example-repo-42",
    authorizer: "owner-agent",
    authorizedAt: 1,
    expiresAt: 4_102_444_800_000,
    repository: "example-org/example-repo",
    prNumber: 42,
    baseRef: "dev",
    mergeMethod: "merge",
    sourceRef: "approval:2026-09-15T01:11:00+09:00",
    policyVersion: "pr-lifecycle-taskflow/v1",
    policyDigest: "e".repeat(64),
    revokedAt: null,
    supersededBy: null,
    ...overrides,
  };
}

export function prEvent(overrides = {}) {
  return {
    eventId: "github:event-1",
    action: "opened",
    repo: "example-org/example-repo",
    prNumber: 42,
    headSha: SHA_A,
    baseSha: SHA_B,
    baseRef: "dev",
    headRepo: "example-org/example-repo",
    headRef: "feat/example",
    updatedAt: "2026-09-05T00:00:01Z",
    ...overrides,
  };
}

export function reviewEvent(overrides = {}) {
  return {
    eventId: "broker:review-1",
    repo: "example-org/example-repo",
    prNumber: 42,
    headSha: SHA_A,
    outcome: "approved",
    reviewId: "9000000001",
    coverageComplete: true,
    retryAllowed: false,
    findings: [],
    ...overrides,
  };
}

export function finding(overrides = {}) {
  return {
    id: "finding-1",
    severity: "high",
    summary: "Wall-time projection can exceed its bound.",
    path: "src/supervisor.py",
    line: 42,
    ...overrides,
  };
}

export class FakeBoundFlows {
  static nextFlow = 1;
  static nextTask = 1;

  constructor(ownerKey = OWNER) {
    this.ownerKey = ownerKey;
    this.flows = new Map();
    this.tasks = new Map();
  }

  createManaged(params) {
    const flow = {
      flowId: `flow-${FakeBoundFlows.nextFlow++}`,
      syncMode: "managed",
      controllerId: params.controllerId,
      goal: params.goal,
      ownerKey: this.ownerKey,
      status: params.status ?? "queued",
      notifyPolicy: params.notifyPolicy ?? "silent",
      currentStep: params.currentStep ?? null,
      stateJson: params.stateJson ?? null,
      waitJson: params.waitJson ?? null,
      revision: 0,
      createdAt: params.createdAt ?? Date.now(),
      updatedAt: params.updatedAt ?? Date.now(),
      endedAt: params.endedAt ?? null,
    };
    this.flows.set(flow.flowId, flow);
    return structuredClone(flow);
  }

  get(flowId) {
    const flow = this.flows.get(flowId);
    return flow ? structuredClone(flow) : undefined;
  }

  list() {
    return [...this.flows.values()].map((flow) => structuredClone(flow));
  }

  findLatest() {
    return this.list().sort((a, b) => b.updatedAt - a.updatedAt)[0];
  }

  resolve(token) {
    return this.get(token);
  }

  mutate(params, status) {
    const current = this.flows.get(params.flowId);
    if (!current) return { applied: false, code: "not_found" };
    if (current.revision !== params.expectedRevision) {
      return { applied: false, code: "revision_conflict", current: structuredClone(current) };
    }
    const next = {
      ...current,
      ...(params.currentStep !== undefined ? { currentStep: params.currentStep } : {}),
      ...(params.stateJson !== undefined ? { stateJson: structuredClone(params.stateJson) } : {}),
      ...(params.waitJson !== undefined ? { waitJson: structuredClone(params.waitJson) } : {}),
      ...(params.blockedSummary !== undefined ? { blockedSummary: params.blockedSummary } : {}),
      status,
      revision: current.revision + 1,
      updatedAt: params.updatedAt ?? Date.now(),
      ...(params.endedAt !== undefined ? { endedAt: params.endedAt } : {}),
    };
    this.flows.set(next.flowId, next);
    return { applied: true, flow: structuredClone(next) };
  }

  setWaiting(params) {
    return this.mutate({ ...params, endedAt: null }, params.blockedSummary ? "blocked" : "waiting");
  }

  resume(params) {
    return this.mutate({ ...params, endedAt: null }, params.status ?? "running");
  }

  finish(params) {
    return this.mutate(params, "succeeded");
  }

  fail(params) {
    return this.mutate(params, "failed");
  }

  requestCancel(params) {
    return this.mutate(params, "running");
  }

  async cancel({ flowId }) {
    const flow = this.flows.get(flowId);
    if (!flow) return { found: false, cancelled: false };
    flow.status = "cancelled";
    flow.revision += 1;
    return { found: true, cancelled: true, flow: structuredClone(flow) };
  }

  runTask(params) {
    const flow = this.flows.get(params.flowId);
    if (!flow) return { created: false, found: false, reason: "Flow not found." };
    this.lastRunTask = params;
    const task = {
      taskId: `task-${FakeBoundFlows.nextTask++}`,
      parentFlowId: params.flowId,
      runId: params.runId,
      childSessionKey: params.childSessionKey,
      agentId: params.agentId,
      status: params.status ?? "queued",
    };
    this.tasks.set(task.taskId, task);
    return { created: true, flow: structuredClone(flow), task: structuredClone(task) };
  }

  getTaskSummary(flowId) {
    const tasks = [...this.tasks.values()].filter((task) => task.parentFlowId === flowId);
    return {
      total: tasks.length,
      active: tasks.filter((task) => ["queued", "running"].includes(task.status)).length,
      succeeded: tasks.filter((task) => task.status === "succeeded").length,
      failed: tasks.filter((task) => task.status === "failed").length,
      cancelled: tasks.filter((task) => task.status === "cancelled").length,
      timedOut: 0,
    };
  }

  taskView(task) {
    return task
      ? {
          id: task.taskId,
          taskId: task.taskId,
          runtime: "subagent",
          sessionKey: this.ownerKey,
          ownerKey: this.ownerKey,
          scope: "session",
          childSessionKey: task.childSessionKey,
          agentId: task.agentId,
          flowId: task.parentFlowId,
          runId: task.runId,
          title: "worker",
          status: task.status,
          deliveryStatus: "delivered",
          notifyPolicy: "silent",
          createdAt: 1,
        }
      : undefined;
  }

  getTask(taskId) {
    return this.taskView(this.tasks.get(taskId));
  }

  listTasks() {
    return [...this.tasks.values()].map((task) => this.taskView(task));
  }

  async cancelTask(taskId) {
    const task = this.tasks.get(taskId);
    if (!task) return { found: false, cancelled: false };
    if (["succeeded", "failed", "timed_out", "cancelled", "lost"].includes(task.status)) {
      return { found: true, cancelled: false, task: this.taskView(task) };
    }
    task.status = "cancelled";
    return { found: true, cancelled: true, task: this.taskView(task) };
  }
}

export function pluginConfig(overrides = {}) {
  return {
    enabled: true,
    ownerSessionKey: OWNER,
    recoveryDelayMinutes: 5,
    expectedRuntimePath: RUNTIME_PATH,
    expectedRuntimeSha256: RUNTIME_SHA256,
    repositories: {
      "example-org/example-repo": {
        enabled: true,
        mode: "active",
        workspace: "/workspace/example-repo",
        brokerRepoAlias: "example-repo",
        baseBranches: ["dev"],
        reviewActor: "broker",
        authorActor: "author-worker",
        mergeActor: "broker[bot]",
        reviewWorkerAgentId: "broker-review-launcher",
        authorWorkerAgentId: "author-worker",
        publisherBrokerId: "attested-broker/v1",
        publisherAttestationRef: "proof:author-worker-test-boundary",
        remediatorProfile: remediatorProfile(),
        maxCycles: 2,
        maxRetries: 2,
        wallTimeMinutes: 120,
      },
    },
    ...overrides,
  };
}

export function makeApi(configInput = pluginConfig()) {
  const stores = new Map();
  const keyedStores = new Map();
  const storeFor = (sessionKey) => {
    if (typeof sessionKey !== "string" || !sessionKey.trim()) {
      throw new Error("sessionKey required");
    }
    if (!stores.has(sessionKey)) {
      stores.set(sessionKey, new FakeBoundFlows(sessionKey));
    }
    return stores.get(sessionKey);
  };
  const bound = storeFor(OWNER);
  const calls = {
    tools: [],
    routes: [],
    services: [],
    schedules: [],
    unschedules: [],
    subagents: [],
    agentEventSubscriptions: [],
    preparedRemediationJobs: [],
    verifiedRemediationEvidence: [],
    logs: [],
  };
  let runCounter = 1;
  const sessionEntries = new Map();
  const syncStoreFor = (namespace, maxEntries) => {
    if (!keyedStores.has(namespace)) {
      const entries = new Map();
      const pruneExpired = () => {
        const now = Date.now();
        for (const [key, entry] of entries) {
          if (Number.isFinite(entry.expiresAt) && entry.expiresAt <= now) {
            entries.delete(key);
          }
        }
      };
      keyedStores.set(namespace, {
        register(key, value, opts = {}) {
          pruneExpired();
          if (!entries.has(key) && entries.size >= maxEntries) {
            throw new Error("store capacity exceeded");
          }
          entries.set(key, {
            value: structuredClone(value),
            createdAt: Date.now(),
            ...(opts.ttlMs ? { expiresAt: Date.now() + opts.ttlMs } : {}),
          });
        },
        registerIfAbsent(key, value, opts = {}) {
          pruneExpired();
          if (entries.has(key)) return false;
          if (entries.size >= maxEntries) throw new Error("store capacity exceeded");
          this.register(key, value, opts);
          return true;
        },
        update(key, updateValue, opts = {}) {
          pruneExpired();
          const entry = entries.get(key);
          const next = updateValue(entry ? structuredClone(entry.value) : undefined);
          if (next === undefined) return false;
          if (!entry && entries.size >= maxEntries) throw new Error("store capacity exceeded");
          this.register(key, next, opts);
          return true;
        },
        deleteIf(key, predicate) {
          pruneExpired();
          const entry = entries.get(key);
          if (!entry || !predicate(structuredClone(entry.value))) return false;
          entries.delete(key);
          return true;
        },
        lookup(key) {
          pruneExpired();
          const entry = entries.get(key);
          return entry ? structuredClone(entry.value) : undefined;
        },
        consume(key) {
          const value = this.lookup(key);
          if (value !== undefined) entries.delete(key);
          return value;
        },
        delete(key) {
          return entries.delete(key);
        },
        entries() {
          pruneExpired();
          return [...entries.entries()].map(([key, entry]) => ({
            key,
            value: structuredClone(entry.value),
            createdAt: entry.createdAt,
            ...(entry.expiresAt ? { expiresAt: entry.expiresAt } : {}),
          }));
        },
        clear() {
          entries.clear();
        },
      });
    }
    return keyedStores.get(namespace);
  };
  const api = {
    __testAllowDisposableRuntime: true,
    __testReadWorkspaceHead: async (_workspace, expectedHeadSha) => expectedHeadSha,
    testAllowDisposableRuntime: true,
    testReadWorkspaceHead: async (_workspace, expectedHeadSha) => expectedHeadSha,
    testPrepareRemediationJob: (job) => {
      calls.preparedRemediationJobs.push(job);
      return { jobId: job.jobId, bindingSha256: job.bindingSha256 };
    },
    testVerifyRemediationEvidence: (state, input) => {
      calls.verifiedRemediationEvidence.push({ state, input });
      return true;
    },
    pluginConfig: configInput,
    logger: {
      info: (message) => calls.logs.push(["info", message]),
      warn: (message) => calls.logs.push(["warn", message]),
      error: (message) => calls.logs.push(["error", message]),
    },
    runtime: {
      agent: {
        session: {
          getSessionEntry: ({ sessionKey }) => sessionEntries.get(sessionKey) ?? null,
        },
      },
      tasks: {
        runs: {
          bindSession: ({ sessionKey }) => {
            const store = storeFor(sessionKey);
            return {
              get: (taskId) => store.getTask(taskId),
              list: () => store.listTasks(),
              findLatest: () => store.listTasks().at(-1),
              resolve: (token) => store.getTask(token),
              cancel: ({ taskId }) => store.cancelTask(taskId),
            };
          },
        },
        managedFlows: {
          bindSession: ({ sessionKey }) => storeFor(sessionKey),
        },
      },
      state: {
        openSyncKeyedStore: ({ namespace, maxEntries }) => syncStoreFor(namespace, maxEntries),
      },
      subagent: {
        run: async (params) => {
          calls.subagents.push(params);
          const runId = `run-${runCounter++}`;
          const workerStore = storeFor(params.sessionKey);
          const taskId = `canonical-task-${FakeBoundFlows.nextTask++}`;
          workerStore.tasks.set(taskId, {
            taskId,
            parentFlowId: `canonical-flow-${runId}`,
            runId,
            childSessionKey: params.sessionKey,
            agentId: params.sessionKey.split(":")[1],
            status: "running",
          });
          return {
            runId,
            sessionKey: params.sessionKey,
            runtime: { harness: "native" },
          };
        },
      },
    },
    agent: {
      events: {
        registerAgentEventSubscription(subscription) {
          calls.agentEventSubscriptions.push(subscription);
        },
      },
    },
    session: {
      workflow: {
        scheduleSessionTurn: async (params) => {
          calls.schedules.push(params);
          return { id: `job-${calls.schedules.length}`, sessionKey: params.sessionKey };
        },
        unscheduleSessionTurnsByTag: async (params) => {
          calls.unschedules.push(params);
          return { removed: 0, failed: 0 };
        },
      },
    },
    registerTool(factory, options) {
      calls.tools.push({ factory, options });
    },
    registerHttpRoute(route) {
      calls.routes.push(route);
    },
    registerService(service) {
      calls.services.push(service);
    },
  };
  return { api, bound, calls, storeFor, sessionEntries, keyedStores };
}

export function authorizedAutoMergePolicy(overrides = {}) {
  const raw = {
    ...pluginConfig().repositories["example-org/example-repo"],
    autoMergeBaseBranches: ["dev"],
    autoMergeMethod: "merge",
    ...overrides,
  };
  delete raw.mergeAuthorization;
  return {
    ...raw,
    mergeAuthorization: mergeAuthorization({
      policyDigest: mergePolicyDigest(normalizePolicy(raw), "example-org/example-repo"),
    }),
  };
}

export function taskflowGateReceipt(overrides = {}) {
  return {
    required_checks_ready: true,
    broker_check_ready: true,
    broker_check_app_id: 12345,
    exact_review_ready: true,
    atomic_base_update: true,
    atomic_enforcement: {
      broker_app_id: 12345,
      required_status_checks: [
        { context: "Broker review", app_id: 12345 },
        { context: "git-identity", app_id: -1 },
      ],
    },
    reviewed_base_sha: SHA_B,
    reviewed_head_sha: SHA_A,
    synthetic_merge_commit_sha: SHA_C,
    ...overrides,
  };
}

export function toolFor(calls, sessionKey, agentId) {
  assert.equal(calls.tools.length, 1);
  return calls.tools[0].factory({ sessionKey, ...(agentId ? { agentId } : {}) });
}
