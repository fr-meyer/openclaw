import { isMainThread } from "node:worker_threads";
import { executeSqliteQuerySync, getNodeSqliteKysely } from "../infra/kysely-sync.js";
import type { OpenClawStateDatabase } from "../state/openclaw-state-db-contract.js";
import type { DB } from "../state/openclaw-state-db.generated.js";

/** Internal native kill admission. IDs alone never create this claim. */
export type ManagedFlowNativeKillClaim = {
  ownerKey: string;
  controllerId: string;
  flowId: string;
  revision: number;
  childSessionKey: string;
  runId: string;
  taskId: string;
  generation: number;
};

export type ManagedFlowNativeLaunchClaim = Pick<
  ManagedFlowNativeKillClaim,
  "ownerKey" | "controllerId" | "flowId" | "revision" | "childSessionKey"
>;
export type ManagedFlowNativeLaunchAuthority = ManagedFlowNativeLaunchClaim & {
  assertCurrent(): void;
};

/** Admission for a newly registered native worker, before its model run starts. */
export function bindManagedFlowNativeLaunchInWorker(
  database: OpenClawStateDatabase,
  claim: ManagedFlowNativeLaunchClaim,
  runId: string,
  generation: number,
): void {
  if (isMainThread) {
    throw new Error("Managed flow launch admission requires the state worker");
  }
  if (
    !claim.ownerKey ||
    !claim.controllerId ||
    !claim.flowId ||
    !claim.childSessionKey ||
    !Number.isSafeInteger(claim.revision) ||
    claim.revision < 0 ||
    !runId ||
    !Number.isSafeInteger(generation) ||
    generation < 1
  ) {
    throw new Error("Managed flow launch claim lacks exact identity facts");
  }
  const query = getNodeSqliteKysely<Pick<DB, "flow_runs">>(database.db);
  const flow = executeSqliteQuerySync(
    database.db,
    query
      .selectFrom("flow_runs")
      .select(["owner_key", "controller_id", "sync_mode", "status", "revision", "state_json"])
      .where("flow_id", "=", claim.flowId),
  ).rows[0];
  if (
    !flow ||
    flow.owner_key !== claim.ownerKey ||
    flow.controller_id !== claim.controllerId ||
    flow.sync_mode !== "managed" ||
    flow.status !== "running" ||
    flow.revision !== claim.revision ||
    !flow.state_json
  ) {
    throw new Error("Managed flow launch claim changed before native registration");
  }
  let state: unknown;
  try {
    state = JSON.parse(flow.state_json);
  } catch {
    throw new Error("Managed flow launch claim has unreadable state");
  }
  const record =
    state && typeof state === "object" && !Array.isArray(state)
      ? (state as Record<string, unknown>)
      : undefined;
  const worker =
    record?.activeWorker &&
    typeof record.activeWorker === "object" &&
    !Array.isArray(record.activeWorker)
      ? (record.activeWorker as Record<string, unknown>)
      : undefined;
  const launch =
    record?.launchOutcome &&
    typeof record.launchOutcome === "object" &&
    !Array.isArray(record.launchOutcome)
      ? (record.launchOutcome as Record<string, unknown>)
      : undefined;
  if (
    !worker ||
    worker.sessionKey !== claim.childSessionKey ||
    worker.runId != null ||
    worker.taskId != null ||
    launch?.status !== "unknown" ||
    launch.sessionKey !== claim.childSessionKey
  ) {
    throw new Error("Managed flow launch claim no longer owns the prelaunch window");
  }
  const updated = executeSqliteQuerySync(
    database.db,
    query
      .updateTable("flow_runs")
      .set({
        state_json: JSON.stringify({
          ...record,
          activeWorker: { ...worker, runId, nativeGeneration: generation },
        }),
        revision: claim.revision + 1,
        updated_at: Date.now(),
      })
      .where("flow_id", "=", claim.flowId)
      .where("revision", "=", claim.revision)
      .returning("flow_id"),
  ).rows;
  if (updated.length !== 1) {
    throw new Error("Managed flow launch claim lost its flow revision");
  }
}

/** Called in the same SQLite transaction that persists the native kill intent. */
export function assertManagedFlowNativeKillClaimInWorker(
  database: OpenClawStateDatabase,
  claim: ManagedFlowNativeKillClaim,
): void {
  if (isMainThread) {
    throw new Error("Managed flow kill admission requires the state worker");
  }
  if (
    !claim.ownerKey ||
    !claim.controllerId ||
    !claim.flowId ||
    !claim.childSessionKey ||
    !claim.runId ||
    !claim.taskId ||
    !Number.isSafeInteger(claim.revision) ||
    claim.revision < 0 ||
    !Number.isSafeInteger(claim.generation) ||
    claim.generation < 1
  ) {
    throw new Error("Managed flow kill claim lacks exact identity facts");
  }
  const query = getNodeSqliteKysely<Pick<DB, "flow_runs" | "subagent_runs">>(database.db);
  const flow = executeSqliteQuerySync(
    database.db,
    query
      .selectFrom("flow_runs")
      .select(["owner_key", "controller_id", "sync_mode", "status", "revision", "state_json"])
      .where("flow_id", "=", claim.flowId),
  ).rows[0];
  if (
    !flow ||
    flow.owner_key !== claim.ownerKey ||
    flow.controller_id !== claim.controllerId ||
    flow.sync_mode !== "managed" ||
    ["succeeded", "failed", "cancelled", "lost"].includes(flow.status) ||
    flow.revision !== claim.revision ||
    !flow.state_json
  ) {
    throw new Error("Managed flow kill claim changed before native admission");
  }
  let state: unknown;
  try {
    state = JSON.parse(flow.state_json);
  } catch {
    throw new Error("Managed flow kill claim has unreadable state");
  }
  const record =
    state && typeof state === "object" && !Array.isArray(state)
      ? (state as Record<string, unknown>)
      : undefined;
  const matches = (value: unknown) => {
    const worker =
      value && typeof value === "object" && !Array.isArray(value)
        ? (value as Record<string, unknown>)
        : undefined;
    return (
      worker?.sessionKey === claim.childSessionKey &&
      worker.runId === claim.runId &&
      worker.taskId === claim.taskId &&
      worker.nativeGeneration === claim.generation
    );
  };
  if (!record || (!matches(record.activeWorker) && !matches(record.orphanedWorker))) {
    throw new Error("Managed flow kill claim no longer names its worker");
  }
  const native = executeSqliteQuerySync(
    database.db,
    query
      .selectFrom("subagent_runs")
      .select(["run_id", "child_session_key", "requester_session_key", "payload_json"])
      .where("run_id", "=", claim.runId),
  ).rows[0];
  if (
    !native ||
    native.child_session_key !== claim.childSessionKey ||
    native.requester_session_key !== claim.ownerKey
  ) {
    throw new Error("Managed flow kill claim native run changed");
  }
  let payload: unknown;
  try {
    payload = JSON.parse(native.payload_json);
  } catch {
    throw new Error("Managed flow kill claim native row is unreadable");
  }
  const run =
    payload && typeof payload === "object" && !Array.isArray(payload)
      ? (payload as Record<string, unknown>)
      : undefined;
  if (
    !run ||
    run.label !== `plugin:${claim.controllerId.replace(/\/v1$/, "")}` ||
    (run.taskRunId ?? native.run_id) !== claim.taskId ||
    run.generation !== claim.generation
  ) {
    throw new Error("Managed flow kill claim native generation changed");
  }
}
