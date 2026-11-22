import {
  latestMatchingFlow,
  normalizeRuntimeConfig,
  ownerSessionKeyForRepo,
  resolveFlowBinding,
  uniqueOwnerSessionKeys,
} from "./runtime-config.mjs";
import {
  acquireContentionLock,
  acquirePullRequestAdmissionLock,
  activeAuthorLeaseHolder,
  activeReviewLeaseHolder,
  activeWorkerLeaseHolder,
  contentionLockKey,
  createWorkerSessionKey,
  evaluateParallelSlot,
  reserveWorkerWithContentionLock,
  resolveMaxParallelPrs,
  sharesReviewContentionDomain,
  workerAgentId,
} from "./runtime-contention.mjs";
import {
  createRouteHandler,
  ingestCheckSuite,
  ingestPullRequest,
  ingestReviewResult,
} from "./runtime-ingest.mjs";
import { isDisposableRuntimePath, runtimeSourceIntegrity } from "./runtime-integrity.mjs";
import { acquireMergeLock, readWorkspaceHead, runBroker } from "./runtime-merge-gates.mjs";
import { autoMergeReceipt, mergedState, persistMergedReceipt } from "./runtime-merge.mjs";
import { reconcileAtStartup } from "./runtime-registration.mjs";
import {
  prepareRemediationJob,
  remediationJobBinding,
  remediationJobId,
  remediationReportFromEvidence,
  verifyRemediationEvidence,
} from "./runtime-remediation-primitives.mjs";
import { reconcileRemediationEvidence } from "./runtime-remediation.mjs";
import { processStartedAtMs } from "./runtime-state-primitives.mjs";
import {
  enforceModeGate,
  notificationTag,
  persistState,
  recoveryTag,
} from "./runtime-state-primitives.mjs";
import { flowWorkspacePath } from "./runtime-state-primitives.mjs";
import {
  currentWorkerTask,
  recoverExtras,
  statusView,
  workerMatchesTerminalLifecycleEvent,
  workerSessionAlive,
} from "./runtime-status-primitives.mjs";
import { reconcileTerminalWorkerEvent } from "./runtime-status.mjs";
import { buildWorkerMessage, dispatchWorker } from "./runtime-worker-orchestration.mjs";
import { ensureFlowWorkspace } from "./runtime-workspace-primitives.mjs";

export const __testing = {
  normalizeRuntimeConfig,
  acquirePullRequestAdmissionLock,
  latestMatchingFlow,
  persistState,
  recoveryTag,
  notificationTag,
  enforceModeGate,
  createWorkerSessionKey,
  remediationJobId,
  remediationJobBinding,
  prepareRemediationJob,
  verifyRemediationEvidence,
  remediationReportFromEvidence,
  reconcileRemediationEvidence,
  buildWorkerMessage,
  statusView,
  createRouteHandler,
  ingestPullRequest,
  ingestReviewResult,
  ingestCheckSuite,
  dispatchWorker,
  reconcileAtStartup,
  processStartedAtMs,
  currentWorkerTask,
  workerMatchesTerminalLifecycleEvent,
  reconcileTerminalWorkerEvent,
  workerSessionAlive,
  recoverExtras,
  activeReviewLeaseHolder,
  activeAuthorLeaseHolder,
  activeWorkerLeaseHolder,
  sharesReviewContentionDomain,
  evaluateParallelSlot,
  flowWorkspacePath,
  ensureFlowWorkspace,
  resolveMaxParallelPrs,
  contentionLockKey,
  acquireContentionLock,
  reserveWorkerWithContentionLock,
  workerAgentId,
  ownerSessionKeyForRepo,
  uniqueOwnerSessionKeys,
  resolveFlowBinding,
  isDisposableRuntimePath,
  readWorkspaceHead,
  runBroker,
  acquireMergeLock,
  autoMergeReceipt,
  mergedState,
  persistMergedReceipt,
  runtimeSourceIntegrity,
};
