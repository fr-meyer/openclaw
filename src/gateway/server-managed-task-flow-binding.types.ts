import type { captureSqliteReadOnlyWorkerScope } from "../infra/sqlite-readonly-worker-context.js";
import type { captureOpenClawStateWorkerContext } from "../state/openclaw-state-worker-context.js";
import type { ManagedFlowNativeLaunchClaim } from "../tasks/managed-task-flow-kill-claim.worker.js";
import type { GatewayContextResolver } from "./server-methods/types.js";

export type RetainedNativeLaunch = ManagedFlowNativeLaunchClaim & {
  pluginId: string;
  assertCurrent: () => void;
  used: boolean;
};
export type GatewayManagedTaskFlowBindingContext = {
  resolveGatewayContext: GatewayContextResolver | undefined;
  runWithReadOnlyWorkers: ReturnType<typeof captureSqliteReadOnlyWorkerScope>;
  stateContext: ReturnType<typeof captureOpenClawStateWorkerContext>;
  closers: Set<() => Promise<void>>;
  assertRuntimeCurrent: () => void;
  nativeLaunchClaims: WeakMap<object, RetainedNativeLaunch>;
};
