import { AsyncLocalStorage } from "node:async_hooks";
import { execFile as execFileCallback } from "node:child_process";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { PHASE } from "./controller.mjs";

export function requireLifecycleHost(api) {
  const tasks = api.runtime?.tasks;
  const capability = tasks?.lifecycleController;
  if (
    tasks?.authorityVersion !== 1 ||
    capability?.authorityVersion !== 1 ||
    capability.pluginId !== "pr-lifecycle-taskflow" ||
    capability.source !== api.source ||
    capability.rootDir !== api.rootDir ||
    capability.managedFlows !== true ||
    capability.taskRuns !== true ||
    capability.nativeLaunch !== true ||
    typeof tasks.managedFlows?.bindSession !== "function" ||
    typeof tasks.runs?.bindSession !== "function" ||
    typeof api.runtime?.subagent?.run !== "function"
  ) {
    throw new Error("pr_lifecycle_host_capability_unavailable");
  }
  return capability;
}
export const taskBindingScopes = new AsyncLocalStorage();
export const bindingCleanupFailures = new WeakMap();
export async function trackTaskBinding(pending) {
  const scope = taskBindingScopes.getStore();
  if (!scope || scope.closed) throw new Error("pr_lifecycle_binding_scope_unavailable");
  const binding = await pending;
  if (typeof binding?.close !== "function")
    throw new Error("pr_lifecycle_binding_close_unavailable");
  scope.bindings.add(binding);
  return binding;
}
export async function withTaskBindings(operation) {
  const existing = taskBindingScopes.getStore();
  if (existing && !existing.closed) return await operation();
  const scope = { bindings: new Set(), closed: false };
  return await taskBindingScopes.run(scope, async () => {
    let primary;
    let failed = false;
    try {
      return await operation();
    } catch (error) {
      failed = true;
      primary = error;
      throw error;
    } finally {
      scope.closed = true;
      const failures = [];
      for (const binding of scope.bindings) {
        try {
          await binding.close();
        } catch (error) {
          failures.push(error);
        }
      }
      if (
        failures.length &&
        failed &&
        primary &&
        (typeof primary === "object" || typeof primary === "function")
      ) {
        bindingCleanupFailures.set(primary, Object.freeze(failures));
      }
      if (failures.length && !failed) {
        throw new AggregateError(failures, "PR lifecycle binding cleanup failed");
      }
    }
  });
}
export const TOOL_NAME = "pr_lifecycle_taskflow";
export const TERMINAL_FLOW_STATUSES = new Set(["succeeded", "failed", "cancelled", "lost"]);
export const CONTENTION_LOCK_NAMESPACE = "pr-lifecycle-taskflow-dispatch-locks";
export const CONTENTION_LOCK_TTL_MS = 120_000;
export const contentionStores = new WeakMap();
export const INDEX_SOURCE_PATH = fileURLToPath(new URL("../index.mjs", import.meta.url));
export const RUNTIME_SOURCE_PATH = fileURLToPath(new URL("./runtime.mjs", import.meta.url));
export const CONTROLLER_SOURCE_PATH = fileURLToPath(new URL("./controller.mjs", import.meta.url));
export const HTTP_SOURCE_PATH = fileURLToPath(new URL("./http.mjs", import.meta.url));
export const execFile = promisify(execFileCallback);

export const DEFAULT_REMEDIATION_COMMAND = "/opt/openclaw/bin/pr-lifecycle-remediate";
export const DEFAULT_BROKER_COMMAND = "/opt/openclaw/bin/repository-broker";
export const BROKER_CALL_TIMEOUT_MS = 60_000;
export const DEFAULT_REMEDIATION_ROOT = "/var/lib/openclaw/pr-lifecycle/remediation";
export const MERGE_LOCK_NAMESPACE = "pr-lifecycle-taskflow-merge-locks";
export const MERGE_LOCK_TTL_MS = BROKER_CALL_TIMEOUT_MS + 60_000;
export const mergeLockStores = new WeakMap();
export const REMEDIATION_EVIDENCE_OUTCOME_CLASSES = new Set([
  "success",
  "preflight_failure",
  "policy_rejection",
  "test_failure",
  "publication_failure",
  "execution_failure",
  "protocol_violation",
]);

export const NOTIFICATION_KIND_PHASE_TRUTH = Object.freeze({
  merged: (state) => state.phase === PHASE.MERGED,
  blocked: (state) => state.phase === PHASE.BLOCKED,
  approval_gate: (state) => state.phase === PHASE.MERGE_READY,
  check_wait: (state) => state.wait?.kind === "check_suite",
});

export const ACTIVE_TASK_STATUSES = new Set(["queued", "running"]);
export const TERMINAL_TASK_STATUSES = new Set([
  "succeeded",
  "failed",
  "timed_out",
  "cancelled",
  "lost",
]);

export const DEAD_SESSION_STATUSES = new Set([
  "failed",
  "done",
  "cancelled",
  "aborted",
  "timeout",
  "timed_out",
]);
