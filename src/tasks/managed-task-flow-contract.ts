import type { SqliteWorkerCommand } from "../infra/sqlite-worker-contract.js";

export type ManagedTaskJson =
  | null
  | boolean
  | number
  | string
  | ManagedTaskJson[]
  | { [key: string]: ManagedTaskJson };

export const managedTaskFlowStatuses = [
  "queued",
  "running",
  "waiting",
  "blocked",
  "succeeded",
  "failed",
  "cancelled",
  "lost",
] as const;
type ManagedTaskFlowStatus = (typeof managedTaskFlowStatuses)[number];
type ManagedTaskNotifyPolicy = "done_only" | "state_changes" | "silent";

/** A recorded flow is an observation; neither its ID nor revision grants authority. */
export type ManagedTaskFlowRecord = {
  flowId: string;
  syncMode: "managed";
  ownerKey: string;
  controllerId?: string;
  revision: number;
  status: ManagedTaskFlowStatus;
  notifyPolicy: ManagedTaskNotifyPolicy;
  goal: string;
  currentStep?: string;
  blockedTaskId?: string;
  blockedSummary?: string;
  stateJson?: ManagedTaskJson;
  waitJson?: ManagedTaskJson;
  cancelRequestedAt?: number;
  createdAt: number;
  updatedAt: number;
  endedAt?: number;
};

export type ManagedTaskFlowCreate = {
  controllerId: string;
  goal: string;
  status?: ManagedTaskFlowStatus;
  notifyPolicy?: ManagedTaskNotifyPolicy;
  currentStep?: string | null;
  blockedTaskId?: string | null;
  blockedSummary?: string | null;
  stateJson?: ManagedTaskJson;
  waitJson?: ManagedTaskJson;
  createdAt?: number;
  updatedAt?: number;
  endedAt?: number | null;
  /** Primitive identity fields are compared inside this existing owner transaction. */
  dedupe?: { stateFields: string[] };
};

export type ManagedTaskFlowMutation = {
  flowId: string;
  expectedRevision: number;
  currentStep?: string | null;
  blockedTaskId?: string | null;
  blockedSummary?: string | null;
  stateJson?: ManagedTaskJson;
  waitJson?: ManagedTaskJson;
  updatedAt?: number;
  endedAt?: number | null;
};
export type ManagedTaskFlowResume = ManagedTaskFlowMutation & {
  status?: "queued" | "running";
};
type ManagedTaskFlowMutationResult =
  | { applied: true; flow: ManagedTaskFlowRecord }
  | {
      applied: false;
      code: "not_found" | "revision_conflict" | "capacity_snapshot_conflict" | "terminal_state";
      current?: ManagedTaskFlowRecord;
    };

/** Canonical task_id is exposed as id. This view supplies no launch/cancel authority. */
export type ManagedTaskRunRecord = {
  id: string;
  runtime: string;
  ownerKey: string;
  scopeKind: string;
  task: string;
  status: string;
  deliveryStatus: string;
  notifyPolicy: string;
  createdAt: number;
  taskKind?: string;
  sourceId?: string;
  requesterSessionKey?: string;
  childSessionKey?: string;
  parentFlowId?: string;
  parentTaskId?: string;
  agentId?: string;
  requesterAgentId?: string;
  runId?: string;
  label?: string;
  startedAt?: number;
  endedAt?: number;
  lastEventAt?: number;
  cleanupAfter?: number;
  toolUseCount?: number;
  lastToolName?: string;
  error?: string;
  progressSummary?: string;
  terminalSummary?: string;
  terminalOutcome?: string;
  detail?: ManagedTaskJson;
  observationSource?: "legacy-task" | "native-subagent";
  generation?: number;
};

type Owner = { ownerKey: string };
type FlowOwner = Owner & { controllerId: string };
export type ManagedTaskCapacitySnapshot = {
  ownerSessionKeys: string[];
  snapshot: Array<{ flowId: string; ownerKey: string; revision: number }>;
  flows: ManagedTaskFlowRecord[];
};
export type ManagedTaskFlowReadOperations = {
  "tasks.managedFlows.capacitySnapshot": {
    input: FlowOwner & { ownerSessionKeys: string[] };
    output: ManagedTaskCapacitySnapshot;
  };
  "tasks.managedFlows.get": {
    input: FlowOwner & { flowId: string };
    output: ManagedTaskFlowRecord | undefined;
  };
  "tasks.managedFlows.list": { input: FlowOwner; output: ManagedTaskFlowRecord[] };
  "tasks.runs.get": {
    input: FlowOwner & { taskId: string; legacyOwnerObservation: boolean };
    output: ManagedTaskRunRecord | undefined;
  };
  "tasks.runs.list": {
    input: FlowOwner & { legacyOwnerObservation: boolean };
    output: ManagedTaskRunRecord[];
  };
};
export type ManagedTaskFlowWriteOperations = {
  "tasks.managedFlows.reserve": {
    input: FlowOwner &
      ManagedTaskFlowResume & {
        mutation: "resume";
        capacitySnapshot: ManagedTaskCapacitySnapshot;
      };
    output: ManagedTaskFlowMutationResult;
  };
  "tasks.managedFlows.create": {
    input: Owner & ManagedTaskFlowCreate;
    output: ManagedTaskFlowRecord & { deduplicated?: true };
  };
  "tasks.managedFlows.mutate": {
    input: FlowOwner &
      ManagedTaskFlowResume & {
        mutation: "finish" | "fail" | "setWaiting" | "resume";
      };
    output: ManagedTaskFlowMutationResult;
  };
};
export type ManagedTaskFlowWorkerOperations = ManagedTaskFlowReadOperations &
  ManagedTaskFlowWriteOperations;
const readTypes = new Set([
  "tasks.managedFlows.capacitySnapshot",
  "tasks.managedFlows.get",
  "tasks.managedFlows.list",
  "tasks.runs.get",
  "tasks.runs.list",
]);
const writeTypes = new Set([
  "tasks.managedFlows.create",
  "tasks.managedFlows.mutate",
  "tasks.managedFlows.reserve",
]);

/** Dispatch classification only; the admitted transport owns input validation. */
export function isManagedTaskFlowReadCommand(
  command: unknown,
): command is SqliteWorkerCommand<ManagedTaskFlowReadOperations> {
  if (typeof command !== "object" || command === null || !("type" in command)) {
    return false;
  }
  if (typeof command.type !== "string") {
    return false;
  }
  return readTypes.has(command.type);
}
export function isManagedTaskFlowWriteCommand(command: {
  type: string;
}): command is SqliteWorkerCommand<ManagedTaskFlowWriteOperations> {
  return writeTypes.has(command.type);
}
/** The transport must carry this current check through native admission and settlement. */
export type ManagedTaskFlowExecute = <Key extends keyof ManagedTaskFlowWorkerOperations>(
  command: { type: Key; input: ManagedTaskFlowWorkerOperations[Key]["input"] },
  authority: { assertCurrent(): void },
) => Promise<ManagedTaskFlowWorkerOperations[Key]["output"]>;

/** Committed writes keep their native result after caller closure; observations need live authority. */
export function isManagedTaskFlowObservation(
  type: keyof ManagedTaskFlowWorkerOperations,
  result: unknown,
): boolean {
  if (type === "tasks.managedFlows.create") {
    return (
      typeof result === "object" &&
      result !== null &&
      "deduplicated" in result &&
      result.deduplicated === true
    );
  }
  if (type === "tasks.managedFlows.mutate" || type === "tasks.managedFlows.reserve") {
    return (
      typeof result === "object" &&
      result !== null &&
      "applied" in result &&
      result.applied === false
    );
  }
  return true;
}

export type BoundManagedTaskFlows = {
  sessionKey: string;
  assertCurrent(): void;
  close(): Promise<void>;
  capacitySnapshot(input: { ownerSessionKeys: string[] }): Promise<ManagedTaskCapacitySnapshot>;
  reserve(
    input: ManagedTaskFlowResume & { capacitySnapshot: ManagedTaskCapacitySnapshot },
  ): Promise<ManagedTaskFlowMutationResult>;
  get(flowId: string): Promise<ManagedTaskFlowRecord | undefined>;
  list(): Promise<ManagedTaskFlowRecord[]>;
  createManaged(
    input: ManagedTaskFlowCreate,
  ): Promise<ManagedTaskFlowWriteOperations["tasks.managedFlows.create"]["output"]>;
  finish(input: ManagedTaskFlowMutation): Promise<ManagedTaskFlowMutationResult>;
  fail(input: ManagedTaskFlowMutation): Promise<ManagedTaskFlowMutationResult>;
  setWaiting(input: ManagedTaskFlowMutation): Promise<ManagedTaskFlowMutationResult>;
  resume(input: ManagedTaskFlowResume): Promise<ManagedTaskFlowMutationResult>;
};
export type BoundManagedTaskRuns = {
  sessionKey: string;
  close(): Promise<void>;
  get(taskId: string): Promise<ManagedTaskRunRecord | undefined>;
  list(): Promise<ManagedTaskRunRecord[]>;
  cancel(input: { taskId: string; cfg?: unknown }): Promise<unknown>;
};
