export const CONTROLLER_ID = "mergeguez-pr-lifecycle/v1";
export const STATE_SCHEMA_VERSION = 1;

export const PHASE = Object.freeze({
  REVIEW_QUEUED: "review_queued",
  REVIEW_RUNNING: "review_running",
  REVIEW_WAITING: "review_waiting",
  REMEDIATION_QUEUED: "remediation_queued",
  REMEDIATION_RUNNING: "remediation_running",
  WAITING_HEAD_EVENT: "waiting_head_event",
  MERGE_QUEUED: "merge_queued",
  MERGE_READY: "merge_ready",
  MERGED: "merged",
  BLOCKED: "blocked",
  FAILED: "failed",
  CANCELLED: "cancelled",
});

const INFRASTRUCTURE_BACKOFF_BASE_MS = 5 * 60_000;
const INFRASTRUCTURE_BACKOFF_MAX_MS = 2 * 60 * 60_000;
export const MAX_INFRASTRUCTURE_RETRIES = 8;
export const PRIMARY_FIXER_MODEL = "cursor-grok-4.6-high";
export const FALLBACK_FIXER_MODEL = "composer-2.5";
export const REVIEW_ACTOR = "mergeguez";
export const AUTHOR_ACTOR = "le-commis";
const FIXER_FALLBACK_INFRASTRUCTURE_REASONS = new Set([
  "primary_model_backend_unavailable",
  "primary_model_rate_limited",
  "primary_model_timeout",
  "primary_model_transport_unavailable",
]);
const INFRASTRUCTURE_FAILURE_PATTERNS = [
  /^worker_session_missing(?:$|:)/,
  /^worker_session_liveness_unknown(?:$|:)/,
  /^worker_session_identity_mismatch(?:$|:)/,
  /^worker_lost_after_process_restart(?:$|:)/,
  /^worker_not_active(?:$|:)/,
  /^worker_start_failed(?:$|:)/,
  /^worker_execution_failed:.*(?:worker_session_(?:missing|liveness_unknown)|gateway[ _-]restart|process[ _-]restart|task[_ ]link|task backing ownership|exec[_ ]approval)/,
  /^task_link_failed(?:$|:)/,
  /^task_link_missing(?:$|:)/,
  /^worker_handshake_timeout(?:$|:)/,
  /^exec_approval_(?:cancelled|denied|expired)(?:$|:)/,
  /^worker_completed_without_structured_report(?:$|:)/,
];

export function classifyWorkerFailure(reason) {
  const normalized = cleanText(reason, 500, "reason").toLowerCase();
  return INFRASTRUCTURE_FAILURE_PATTERNS.some((pattern) => pattern.test(normalized))
    ? "infrastructure"
    : "content";
}

function infrastructureBackoffMs(attempt) {
  const exponent = Math.max(0, Math.min(10, attempt - 1));
  return Math.min(INFRASTRUCTURE_BACKOFF_MAX_MS, INFRASTRUCTURE_BACKOFF_BASE_MS * 2 ** exponent);
}

function retryPhase(state, kind) {
  if (kind === "remediation") {
    return PHASE.REMEDIATION_QUEUED;
  }
  if (kind === "review") {
    return PHASE.REVIEW_QUEUED;
  }
  return Array.isArray(state.findings) && state.findings.length > 0
    ? PHASE.REMEDIATION_QUEUED
    : PHASE.REVIEW_QUEUED;
}

function publisherBoundaryFromPolicy(policy) {
  return {
    actor: policy.authorActor,
    brokerId: policy.publisherBrokerId ?? null,
    attestationRef: policy.publisherAttestationRef ?? null,
    ready: Boolean(policy.publisherBrokerId && policy.publisherAttestationRef),
  };
}

function infrastructureReasonFromBlocker(blocker) {
  if (typeof blocker !== "string" || blocker.length === 0) {
    return null;
  }
  if (blocker.startsWith("infrastructure_retry_exhausted:")) {
    return null;
  }
  const reason = blocker.startsWith("worker_failure_exhausted:")
    ? blocker.slice("worker_failure_exhausted:".length)
    : blocker;
  try {
    return classifyWorkerFailure(reason) === "infrastructure" ? reason : null;
  } catch {
    return null;
  }
}

export function findingsAreActionable(findings) {
  if (!Array.isArray(findings) || findings.length === 0) {
    return false;
  }
  const prioritized = findings.filter(
    (finding) => finding?.severity === "blocker" || finding?.severity === "high",
  );
  const targets = prioritized.length > 0 ? prioritized : findings;
  return targets.every(
    (finding) => typeof finding?.path === "string" && finding.path.trim().length > 0,
  );
}

export function refreshPolicySnapshot(state, policyInput, now = Date.now(), options = {}) {
  if (!isLifecycleState(state)) {
    throw new Error("stored lifecycle state is invalid");
  }
  const policy = normalizePolicy(policyInput);
  const legacySnapshot = !Number.isInteger(state.wallTimeMinutes);
  const wallTimeChanged = state.wallTimeMinutes !== policy.wallTimeMinutes;
  const resetDeadline = options.resetDeadline === true || legacySnapshot || wallTimeChanged;
  const publisherBoundary = publisherBoundaryFromPolicy(policy);
  const next = {
    ...state,
    mode: policy.mode,
    reviewActor: policy.reviewActor,
    authorActor: policy.authorActor,
    fixerModel: policy.fixerModel,
    fixerFallbackModel: policy.fixerFallbackModel,
    publisherBoundary,
    autoMergeBaseBranches: policy.autoMergeBaseBranches,
    autoMergeMethod: policy.autoMergeMethod,
    maxCycles: policy.maxCycles,
    maxRetries: policy.maxRetries,
    wallTimeMinutes: policy.wallTimeMinutes,
    deadlineAt: resetDeadline ? now + policy.wallTimeMinutes * 60_000 : state.deadlineAt,
    ...(resetDeadline ? { cycleStartedAt: now } : {}),
    updatedAt: now,
  };
  const changed =
    next.mode !== state.mode ||
    next.reviewActor !== state.reviewActor ||
    next.authorActor !== state.authorActor ||
    next.fixerModel !== state.fixerModel ||
    next.fixerFallbackModel !== state.fixerFallbackModel ||
    next.publisherBoundary.actor !== state.publisherBoundary?.actor ||
    next.publisherBoundary.brokerId !== state.publisherBoundary?.brokerId ||
    next.publisherBoundary.attestationRef !== state.publisherBoundary?.attestationRef ||
    next.publisherBoundary.ready !== state.publisherBoundary?.ready ||
    JSON.stringify(next.autoMergeBaseBranches) !== JSON.stringify(state.autoMergeBaseBranches) ||
    next.autoMergeMethod !== state.autoMergeMethod ||
    next.maxCycles !== state.maxCycles ||
    next.maxRetries !== state.maxRetries ||
    next.wallTimeMinutes !== state.wallTimeMinutes ||
    next.deadlineAt !== state.deadlineAt ||
    next.cycleStartedAt !== state.cycleStartedAt;
  return { changed, state: changed ? next : state };
}

const TERMINAL_PHASES = new Set([PHASE.MERGE_READY, PHASE.MERGED, PHASE.FAILED, PHASE.CANCELLED]);
const SHA_PATTERN = /^[0-9a-f]{40}$/;
const REPO_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
// oxlint-disable-next-line no-control-regex -- Reject control bytes in TaskFlow text fields.
const SAFE_TEXT_PATTERN = /^[^\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]*$/;
const MAX_SEEN_EVENTS = 64;
const MAX_FINDINGS = 50;

export function isSha(value) {
  return typeof value === "string" && SHA_PATTERN.test(value);
}

export function isRepo(value) {
  return typeof value === "string" && REPO_PATTERN.test(value);
}

function cleanText(value, maxLength, field) {
  if (typeof value !== "string") {
    throw new Error(`${field} must be a string`);
  }
  const normalized = value.trim();
  if (!normalized || normalized.length > maxLength || !SAFE_TEXT_PATTERN.test(normalized)) {
    throw new Error(`${field} is invalid`);
  }
  return normalized;
}

function optionalCleanText(value, maxLength, field) {
  if (value === undefined || value === null || value === "") {
    return undefined;
  }
  return cleanText(value, maxLength, field);
}

function positiveInteger(value, field) {
  if (!Number.isInteger(value) || value < 1) {
    throw new Error(`${field} must be a positive integer`);
  }
  return value;
}

function appendSeenEvent(state, eventId) {
  if (!eventId || state.seenEventIds.includes(eventId)) {
    return state;
  }
  return {
    ...state,
    seenEventIds: [...state.seenEventIds, eventId].slice(-MAX_SEEN_EVENTS),
  };
}

export function sanitizeFindings(input) {
  if (!Array.isArray(input) || input.length > MAX_FINDINGS) {
    throw new Error(`findings must contain at most ${MAX_FINDINGS} entries`);
  }
  return input.map((finding, index) => {
    if (!finding || typeof finding !== "object" || Array.isArray(finding)) {
      throw new Error(`findings[${index}] must be an object`);
    }
    const allowed = new Set(["id", "severity", "summary", "path", "line", "evidence"]);
    for (const key of Object.keys(finding)) {
      if (!allowed.has(key)) {
        throw new Error(`findings[${index}].${key} is not allowed`);
      }
    }
    const severity = cleanText(finding.severity, 16, `findings[${index}].severity`).toLowerCase();
    if (!new Set(["blocker", "high", "medium", "low", "info"]).has(severity)) {
      throw new Error(`findings[${index}].severity is invalid`);
    }
    const line = finding.line;
    if (line !== undefined && (!Number.isInteger(line) || line < 1 || line > 10_000_000)) {
      throw new Error(`findings[${index}].line is invalid`);
    }
    return {
      id: cleanText(finding.id, 100, `findings[${index}].id`),
      severity,
      summary: cleanText(finding.summary, 500, `findings[${index}].summary`),
      ...(finding.path ? { path: cleanText(finding.path, 300, `findings[${index}].path`) } : {}),
      ...(line !== undefined ? { line } : {}),
      ...(finding.evidence
        ? { evidence: cleanText(finding.evidence, 1000, `findings[${index}].evidence`) }
        : {}),
    };
  });
}

export function normalizePolicy(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("repository policy must be an object");
  }
  const reviewActor = cleanText(input.reviewActor, 80, "reviewActor");
  const authorActor = cleanText(input.authorActor, 80, "authorActor");
  if (reviewActor !== REVIEW_ACTOR) {
    throw new Error(`reviewActor must be ${REVIEW_ACTOR}`);
  }
  if (authorActor !== AUTHOR_ACTOR) {
    throw new Error(`authorActor must be ${AUTHOR_ACTOR}`);
  }
  if (reviewActor.toLowerCase() === authorActor.toLowerCase()) {
    throw new Error("reviewActor and authorActor must be distinct");
  }
  const reviewWorkerAgentId = cleanText(input.reviewWorkerAgentId, 80, "reviewWorkerAgentId");
  const authorWorkerAgentId = cleanText(input.authorWorkerAgentId, 80, "authorWorkerAgentId");
  if (reviewWorkerAgentId.toLowerCase() === authorWorkerAgentId.toLowerCase()) {
    throw new Error("reviewWorkerAgentId and authorWorkerAgentId must be distinct");
  }
  if (authorActor.toLowerCase() !== authorWorkerAgentId.toLowerCase()) {
    throw new Error("authorActor must match authorWorkerAgentId");
  }
  const fixerModel = cleanText(input.fixerModel ?? PRIMARY_FIXER_MODEL, 100, "fixerModel");
  if (fixerModel !== PRIMARY_FIXER_MODEL) {
    throw new Error(`fixerModel must be ${PRIMARY_FIXER_MODEL}`);
  }
  const fixerFallbackModel = cleanText(
    input.fixerFallbackModel ?? FALLBACK_FIXER_MODEL,
    100,
    "fixerFallbackModel",
  );
  if (fixerFallbackModel !== FALLBACK_FIXER_MODEL) {
    throw new Error(`fixerFallbackModel must be ${FALLBACK_FIXER_MODEL}`);
  }
  const publisherBrokerId = optionalCleanText(input.publisherBrokerId, 160, "publisherBrokerId");
  const publisherAttestationRef = optionalCleanText(
    input.publisherAttestationRef,
    500,
    "publisherAttestationRef",
  );
  if (Boolean(publisherBrokerId) !== Boolean(publisherAttestationRef)) {
    throw new Error("publisherBrokerId and publisherAttestationRef must be configured together");
  }
  const mode = input.mode ?? "observe";
  if (!new Set(["observe", "dogfood", "active"]).has(mode)) {
    throw new Error("mode is invalid");
  }
  if (!Array.isArray(input.baseBranches) || input.baseBranches.length === 0) {
    throw new Error("baseBranches must be a non-empty array");
  }
  const baseBranches = [
    ...new Set(input.baseBranches.map((value) => cleanText(value, 200, "baseBranch"))),
  ];
  const autoMergeBaseBranches = input.autoMergeBaseBranches ?? [];
  if (!Array.isArray(autoMergeBaseBranches)) {
    throw new Error("autoMergeBaseBranches must be an array");
  }
  const normalizedAutoMergeBaseBranches = [
    ...new Set(autoMergeBaseBranches.map((value) => cleanText(value, 200, "autoMergeBaseBranch"))),
  ];
  if (normalizedAutoMergeBaseBranches.some((value) => value !== "dev")) {
    throw new Error("automatic merge is allowed only for the exact dev base branch");
  }
  if (normalizedAutoMergeBaseBranches.some((value) => !baseBranches.includes(value))) {
    throw new Error("autoMergeBaseBranches must be a subset of baseBranches");
  }
  const autoMergeMethod = input.autoMergeMethod ?? "merge";
  if (!new Set(["merge", "squash", "rebase"]).has(autoMergeMethod)) {
    throw new Error("autoMergeMethod is invalid");
  }
  const maxCycles = input.maxCycles ?? 2;
  const maxRetries = input.maxRetries ?? 2;
  const wallTimeMinutes = input.wallTimeMinutes ?? 72 * 60;
  if (!Number.isInteger(maxCycles) || maxCycles < 1 || maxCycles > 7) {
    throw new Error("maxCycles must be an integer between 1 and 7");
  }
  if (!Number.isInteger(maxRetries) || maxRetries < 0 || maxRetries > 10) {
    throw new Error("maxRetries must be an integer between 0 and 10");
  }
  if (!Number.isInteger(wallTimeMinutes) || wallTimeMinutes < 5 || wallTimeMinutes > 10_080) {
    throw new Error("wallTimeMinutes must be an integer between 5 and 10080");
  }
  const maxParallelPrs = input.maxParallelPrs ?? 1;
  if (!Number.isInteger(maxParallelPrs) || maxParallelPrs < 1 || maxParallelPrs > 16) {
    throw new Error("maxParallelPrs must be an integer between 1 and 16");
  }
  const ownerSessionKey = optionalCleanText(input.ownerSessionKey, 500, "ownerSessionKey");
  return {
    enabled: input.enabled !== false,
    mode,
    workspace: cleanText(input.workspace, 1000, "workspace"),
    baseBranches,
    autoMergeBaseBranches: normalizedAutoMergeBaseBranches,
    autoMergeMethod,
    reviewActor,
    authorActor,
    reviewWorkerAgentId,
    authorWorkerAgentId,
    fixerModel,
    fixerFallbackModel,
    publisherBrokerId,
    publisherAttestationRef,
    maxCycles,
    maxRetries,
    wallTimeMinutes,
    maxParallelPrs,
    allowForks: input.allowForks === true,
    ...(ownerSessionKey ? { ownerSessionKey } : {}),
  };
}

export function normalizePullRequestEvent(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("pull request event must be an object");
  }
  const action = cleanText(input.action, 40, "action");
  if (!new Set(["opened", "reopened", "synchronize", "edited"]).has(action)) {
    throw new Error("pull request action is not handled");
  }
  const repo = cleanText(input.repo, 200, "repo");
  if (!isRepo(repo)) {
    throw new Error("repo is invalid");
  }
  const headSha = cleanText(input.headSha, 40, "headSha").toLowerCase();
  const baseSha = cleanText(input.baseSha, 40, "baseSha").toLowerCase();
  if (!isSha(headSha) || !isSha(baseSha)) {
    throw new Error("headSha and baseSha must be full lowercase commit SHAs");
  }
  return {
    type: "pull_request",
    eventId: cleanText(input.eventId, 160, "eventId"),
    action,
    repo,
    prNumber: positiveInteger(input.prNumber, "prNumber"),
    headSha,
    baseSha,
    baseRef: cleanText(input.baseRef, 200, "baseRef"),
    headRepo: cleanText(input.headRepo, 200, "headRepo"),
  };
}

export function normalizeReviewResult(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("review result must be an object");
  }
  const repo = cleanText(input.repo, 200, "repo");
  const headSha = cleanText(input.headSha, 40, "headSha").toLowerCase();
  const baseSha = optionalCleanText(input.baseSha, 40, "baseSha")?.toLowerCase();
  const outcome = cleanText(input.outcome, 40, "outcome");
  if (!isRepo(repo) || !isSha(headSha) || (baseSha !== undefined && !isSha(baseSha))) {
    throw new Error("review repo, headSha or baseSha is invalid");
  }
  if (
    !new Set(["approved", "changes_requested", "failed_retryable", "failed_terminal"]).has(outcome)
  ) {
    throw new Error("review outcome is invalid");
  }
  const findings = sanitizeFindings(input.findings ?? []);
  return {
    type: "review_result",
    eventId: cleanText(input.eventId, 160, "eventId"),
    repo,
    prNumber: positiveInteger(input.prNumber, "prNumber"),
    headSha,
    baseSha,
    outcome,
    reviewId: optionalCleanText(input.reviewId, 120, "reviewId"),
    coverageComplete: input.coverageComplete === true,
    retryAllowed: input.retryAllowed === true,
    findings,
    summary: optionalCleanText(input.summary, 1000, "summary"),
  };
}

export function createState(eventInput, policyInput, now = Date.now()) {
  const event = normalizePullRequestEvent(eventInput);
  const policy = normalizePolicy(policyInput);
  if (!policy.enabled) {
    throw new Error("repository policy is disabled");
  }
  if (!policy.baseBranches.includes(event.baseRef)) {
    throw new Error("pull request base branch is not allowlisted");
  }
  if (!policy.allowForks && event.headRepo !== event.repo) {
    throw new Error("fork pull requests are not allowed");
  }
  return {
    schemaVersion: STATE_SCHEMA_VERSION,
    repo: event.repo,
    prNumber: event.prNumber,
    headSha: event.headSha,
    baseSha: event.baseSha,
    baseRef: event.baseRef,
    phase: PHASE.REVIEW_QUEUED,
    cycle: 0,
    retryCount: 0,
    infrastructureRetryCount: 0,
    workerGeneration: 0,
    infrastructureRetryAt: null,
    infrastructureLastFailure: null,
    orphanedWorker: null,
    lastGhostCleanup: null,
    workspacePreflight: null,
    maxCycles: policy.maxCycles,
    maxRetries: policy.maxRetries,
    wallTimeMinutes: policy.wallTimeMinutes,
    startedAt: now,
    cycleStartedAt: now,
    deadlineAt: now + policy.wallTimeMinutes * 60_000,
    mode: policy.mode,
    reviewActor: policy.reviewActor,
    authorActor: policy.authorActor,
    fixerModel: policy.fixerModel,
    fixerFallbackModel: policy.fixerFallbackModel,
    publisherBoundary: publisherBoundaryFromPolicy(policy),
    autoMergeBaseBranches: policy.autoMergeBaseBranches,
    autoMergeMethod: policy.autoMergeMethod,
    activeWorker: null,
    fixerAttestation: null,
    review: null,
    findings: [],
    wait: null,
    blocker: null,
    mergeReady: null,
    seenEventIds: [event.eventId],
    updatedAt: now,
  };
}

export function isLifecycleState(value) {
  return Boolean(
    value &&
    typeof value === "object" &&
    value.schemaVersion === STATE_SCHEMA_VERSION &&
    isRepo(value.repo) &&
    Number.isInteger(value.prNumber) &&
    isSha(value.headSha) &&
    typeof value.phase === "string" &&
    Array.isArray(value.seenEventIds),
  );
}

export function isTerminalState(state) {
  return TERMINAL_PHASES.has(state.phase);
}

export function applyPullRequestEvent(state, eventInput, policyInput, now = Date.now()) {
  if (!isLifecycleState(state)) {
    throw new Error("stored lifecycle state is invalid");
  }
  const event = normalizePullRequestEvent(eventInput);
  const policy = normalizePolicy(policyInput);
  if (event.repo !== state.repo || event.prNumber !== state.prNumber) {
    throw new Error("pull request event does not match this flow");
  }
  if (state.seenEventIds.includes(event.eventId)) {
    return { changed: false, state, effect: "none", reason: "duplicate_event" };
  }
  if (!policy.baseBranches.includes(event.baseRef)) {
    return blockState(state, "base_branch_not_allowlisted", now, event.eventId);
  }
  if (!policy.allowForks && event.headRepo !== event.repo) {
    return blockState(state, "fork_not_allowed", now, event.eventId);
  }
  if (
    event.headSha === state.headSha &&
    event.baseSha === state.baseSha &&
    event.baseRef === state.baseRef
  ) {
    if (isTerminalState(state)) {
      return { changed: false, state, effect: "none", reason: "terminal_same_head" };
    }
    return {
      changed: true,
      state: appendSeenEvent({ ...state, updatedAt: now }, event.eventId),
      effect: "none",
      reason: "same_head_event",
    };
  }
  if (state.activeWorker && state.orphanedWorker) {
    throw new Error("new_head_has_multiple_unreconciled_workers");
  }
  const next = appendSeenEvent(
    {
      ...state,
      headSha: event.headSha,
      baseSha: event.baseSha,
      baseRef: event.baseRef,
      phase: PHASE.REVIEW_QUEUED,
      cycle: 0,
      retryCount: 0,
      infrastructureRetryCount: 0,
      workerGeneration: Math.max(0, Number(state.workerGeneration) || 0) + 1,
      infrastructureRetryAt: null,
      infrastructureLastFailure: null,
      // A prior run retains authority until its terminal outcome or exact
      // cancellation is observed. Dispatch reconciles this before reserving.
      orphanedWorker: state.activeWorker
        ? { ...state.activeWorker, launchOutcome: state.launchOutcome ?? null }
        : (state.orphanedWorker ?? null),
      launchOutcome: null,
      maxCycles: policy.maxCycles,
      maxRetries: policy.maxRetries,
      wallTimeMinutes: policy.wallTimeMinutes,
      startedAt: now,
      cycleStartedAt: now,
      deadlineAt: now + policy.wallTimeMinutes * 60_000,
      lastGhostCleanup: null,
      workspacePreflight: null,
      mode: policy.mode,
      reviewActor: policy.reviewActor,
      authorActor: policy.authorActor,
      fixerModel: policy.fixerModel,
      fixerFallbackModel: policy.fixerFallbackModel,
      publisherBoundary: publisherBoundaryFromPolicy(policy),
      autoMergeBaseBranches: policy.autoMergeBaseBranches,
      autoMergeMethod: policy.autoMergeMethod,
      activeWorker: null,
      fixerAttestation: null,
      review: null,
      findings: [],
      wait: null,
      blocker: null,
      mergeReady: null,
      updatedAt: now,
    },
    event.eventId,
  );
  return {
    changed: true,
    state: next,
    effect: "continue",
    reason: event.headSha === state.headSha ? "base_changed" : "new_head",
  };
}

function budgetBlock(state, now, eventId) {
  if (now > state.deadlineAt) {
    return blockState(state, "wall_time_budget_exhausted", now, eventId);
  }
  if (state.cycle > state.maxCycles) {
    return blockState(state, "review_fix_cycle_budget_exhausted", now, eventId);
  }
  return null;
}

export function applyReviewResult(state, resultInput, now = Date.now()) {
  if (!isLifecycleState(state)) {
    throw new Error("stored lifecycle state is invalid");
  }
  const result = normalizeReviewResult(resultInput);
  if (result.repo !== state.repo || result.prNumber !== state.prNumber) {
    throw new Error("review result does not match this flow");
  }
  if (state.seenEventIds.includes(result.eventId)) {
    return { changed: false, state, effect: "none", reason: "duplicate_event" };
  }
  if (result.headSha !== state.headSha) {
    return {
      changed: false,
      state,
      effect: "none",
      reason: "stale_head_result",
    };
  }
  if (!result.baseSha) {
    return { changed: false, state, effect: "none", reason: "review_base_identity_missing" };
  }
  if (result.baseSha !== state.baseSha) {
    return { changed: false, state, effect: "none", reason: "stale_base_result" };
  }
  if (
    !new Set([PHASE.REVIEW_QUEUED, PHASE.REVIEW_RUNNING, PHASE.REVIEW_WAITING]).has(state.phase)
  ) {
    return { changed: false, state, effect: "none", reason: "unexpected_review_phase" };
  }
  if (state.activeWorker && state.orphanedWorker) {
    throw new Error("review_result_has_multiple_unreconciled_workers");
  }
  const withEvent = appendSeenEvent(
    {
      ...state,
      orphanedWorker: state.activeWorker
        ? { ...state.activeWorker, launchOutcome: state.launchOutcome ?? null }
        : (state.orphanedWorker ?? null),
      activeWorker: null,
      launchOutcome: null,
    },
    result.eventId,
  );
  const review = {
    reviewId: result.reviewId ?? null,
    headSha: result.headSha,
    outcome: result.outcome,
    coverageComplete: result.coverageComplete,
    findingsCount: result.findings.length,
    summary: result.summary ?? null,
    observedAt: now,
  };
  if (result.outcome === "approved") {
    if (!result.coverageComplete || result.findings.length !== 0) {
      return blockState(withEvent, "approval_without_complete_zero_finding_coverage", now);
    }
    const automaticMerge =
      state.mode === "active" &&
      state.baseRef === "dev" &&
      Array.isArray(state.autoMergeBaseBranches) &&
      state.autoMergeBaseBranches.includes("dev");
    const next = {
      ...withEvent,
      phase: automaticMerge ? PHASE.MERGE_QUEUED : PHASE.MERGE_READY,
      activeWorker: null,
      infrastructureRetryCount: 0,
      infrastructureRetryAt: null,
      infrastructureLastFailure: null,
      review,
      findings: [],
      wait: null,
      blocker: null,
      mergeReady: {
        headSha: state.headSha,
        reviewId: result.reviewId ?? null,
        coverageComplete: true,
        findingsCount: 0,
        reachedAt: now,
        mergeAuthorized: automaticMerge,
        mergeMethod: state.autoMergeMethod ?? "merge",
      },
      updatedAt: now,
    };
    return {
      changed: true,
      state: next,
      effect: automaticMerge ? "continue" : "merge_ready",
      reason: automaticMerge ? "approved_auto_merge_queued" : "approved",
    };
  }
  if (result.outcome === "changes_requested") {
    if (!result.coverageComplete || result.findings.length === 0) {
      return blockState(withEvent, "changes_requested_without_complete_findings", now);
    }
    if (!findingsAreActionable(result.findings)) {
      return blockState(withEvent, "changes_requested_without_actionable_paths", now);
    }
    const reviewed = {
      ...withEvent,
      review,
      findings: result.findings,
    };
    const budget = budgetBlock(reviewed, now);
    if (budget) {
      return budget;
    }
    if (reviewed.cycle >= reviewed.maxCycles) {
      return blockState(reviewed, "review_fix_cycle_budget_exhausted", now);
    }
    const next = {
      ...reviewed,
      phase: PHASE.REMEDIATION_QUEUED,
      activeWorker: null,
      fixerAttestation: null,
      wait: null,
      blocker: null,
      retryCount: 0,
      infrastructureRetryCount: 0,
      infrastructureRetryAt: null,
      infrastructureLastFailure: null,
      updatedAt: now,
    };
    return { changed: true, state: next, effect: "continue", reason: "findings_ready" };
  }
  if (result.outcome === "failed_retryable") {
    if (!result.retryAllowed || state.retryCount >= state.maxRetries) {
      return blockState(withEvent, "review_retry_not_allowed_or_exhausted", now);
    }
    const budget = budgetBlock(withEvent, now);
    if (budget) {
      return budget;
    }
    const next = {
      ...withEvent,
      phase: PHASE.REVIEW_QUEUED,
      activeWorker: null,
      review,
      wait: null,
      blocker: null,
      retryCount: state.retryCount + 1,
      updatedAt: now,
    };
    return { changed: true, state: next, effect: "continue", reason: "retry_review" };
  }
  return blockState(withEvent, "review_failed_terminal", now);
}

export function workerKindForPhase(phase) {
  if (phase === PHASE.REVIEW_QUEUED) {
    return "review";
  }
  if (phase === PHASE.REMEDIATION_QUEUED) {
    return "remediation";
  }
  return null;
}

export function reserveWorker(state, kind, sessionKey, now = Date.now()) {
  if (!isLifecycleState(state)) {
    throw new Error("stored lifecycle state is invalid");
  }
  if (state.activeWorker) {
    return { changed: false, state, reason: "worker_already_reserved" };
  }
  const expectedKind = workerKindForPhase(state.phase);
  if (!expectedKind || expectedKind !== kind) {
    return { changed: false, state, reason: "phase_not_dispatchable" };
  }
  const infrastructureRetryAt = Number.isFinite(state.infrastructureRetryAt)
    ? state.infrastructureRetryAt
    : null;
  if (Number.isFinite(infrastructureRetryAt) && infrastructureRetryAt > now) {
    return { changed: false, state, effect: "wait", reason: "infrastructure_backoff" };
  }
  let baseState = Number.isFinite(infrastructureRetryAt)
    ? {
        ...state,
        infrastructureRetryAt: null,
        wait: null,
        cycleStartedAt: now,
        deadlineAt: Number.isInteger(state.wallTimeMinutes)
          ? now + state.wallTimeMinutes * 60_000
          : state.deadlineAt,
      }
    : state;
  // Queued idle wait must not consume the wall-time budget. Restart it only when
  // dispatching a worker after the previous deadline already elapsed with no active worker.
  if (
    now > baseState.deadlineAt &&
    Number.isInteger(baseState.wallTimeMinutes) &&
    !baseState.activeWorker
  ) {
    baseState = {
      ...baseState,
      cycleStartedAt: now,
      deadlineAt: now + baseState.wallTimeMinutes * 60_000,
    };
  }
  const budget = budgetBlock(baseState, now);
  if (budget) {
    return budget;
  }
  if (kind === "remediation" && baseState.cycle >= baseState.maxCycles) {
    return blockState(baseState, "review_fix_cycle_budget_exhausted", now);
  }
  const next = {
    ...baseState,
    phase: kind === "review" ? PHASE.REVIEW_RUNNING : PHASE.REMEDIATION_RUNNING,
    launchOutcome: { status: "not_invoked" },
    activeWorker: {
      kind,
      sessionKey: cleanText(sessionKey, 500, "sessionKey"),
      headSha: state.headSha,
      cycle: state.cycle,
      reservedAt: now,
      runId: null,
      taskId: null,
    },
    wait: null,
    blocker: null,
    updatedAt: now,
  };
  return { changed: true, state: next, effect: "start_worker", reason: "reserved" };
}

export function attachWorkerRun(state, sessionKey, runId, taskId, now = Date.now()) {
  const field =
    state.activeWorker?.sessionKey === sessionKey
      ? "activeWorker"
      : state.orphanedWorker?.sessionKey === sessionKey
        ? "orphanedWorker"
        : null;
  if (!field) {
    return { changed: false, state, reason: "worker_reservation_changed" };
  }
  const normalizedRunId = cleanText(runId, 200, "runId");
  if (state[field].runId && state[field].runId !== normalizedRunId) {
    throw new Error("worker_run_identity_changed");
  }
  if (taskId && state[field].taskId && state[field].taskId !== taskId) {
    throw new Error("worker_task_identity_changed");
  }
  return {
    changed: true,
    state: {
      ...state,
      ...(field === "activeWorker" ? { launchOutcome: null } : {}),
      [field]: {
        ...state[field],
        runId: normalizedRunId,
        taskId: taskId ? cleanText(taskId, 200, "taskId") : (state[field].taskId ?? null),
        ...(field === "orphanedWorker" ? { launchOutcome: { status: "accepted" } } : {}),
      },
      updatedAt: now,
    },
    effect: "none",
    reason: "worker_attached",
  };
}

function assertWorkerReportMatches(state, report, callerSessionKey) {
  const worker = state.activeWorker;
  if (!worker) {
    throw new Error("flow has no active worker");
  }
  if (worker.sessionKey !== callerSessionKey) {
    throw new Error("worker session does not own this step");
  }
  if (report.kind !== worker.kind) {
    throw new Error("worker report kind does not match the reserved step");
  }
  if (report.headSha !== worker.headSha || report.headSha !== state.headSha) {
    throw new Error("worker report is not bound to the current exact head");
  }
  if (report.cycle !== worker.cycle || report.cycle !== state.cycle) {
    throw new Error("worker report cycle is stale");
  }
}

function fixerAttestationFromReport(state, report, now) {
  if (!report.fixerAttested || !report.fixerModel || !report.fixerAttestationRef) {
    return null;
  }
  const primary = state.fixerModel ?? PRIMARY_FIXER_MODEL;
  const fallback = state.fixerFallbackModel ?? FALLBACK_FIXER_MODEL;
  if (report.fixerModel !== primary && report.fixerModel !== fallback) {
    return null;
  }
  if (
    report.fixerModel === primary &&
    (report.fixerFallbackReason || report.fixerPrimaryFailureRef)
  ) {
    return null;
  }
  if (report.fixerModel === fallback) {
    if (
      !FIXER_FALLBACK_INFRASTRUCTURE_REASONS.has(report.fixerFallbackReason) ||
      !report.fixerPrimaryFailureRef
    ) {
      return null;
    }
  }
  return {
    model: report.fixerModel,
    primaryModel: primary,
    fallbackUsed: report.fixerModel === fallback,
    fallbackReason: report.fixerFallbackReason ?? null,
    primaryFailureRef: report.fixerPrimaryFailureRef ?? null,
    ref: report.fixerAttestationRef,
    attestedAt: now,
  };
}

export function applyWorkerReport(state, reportInput, callerSessionKey, now = Date.now()) {
  if (!isLifecycleState(state)) {
    throw new Error("stored lifecycle state is invalid");
  }
  if (!reportInput || typeof reportInput !== "object" || Array.isArray(reportInput)) {
    throw new Error("worker report must be an object");
  }
  const report = {
    kind: cleanText(reportInput.kind, 20, "kind"),
    outcome: cleanText(reportInput.outcome, 80, "outcome"),
    headSha: cleanText(reportInput.headSha, 40, "headSha").toLowerCase(),
    baseSha: optionalCleanText(reportInput.baseSha, 40, "baseSha")?.toLowerCase(),
    cycle: reportInput.cycle,
    reviewId: optionalCleanText(reportInput.reviewId, 120, "reviewId"),
    summary: optionalCleanText(reportInput.summary, 1000, "summary"),
    claimRef: optionalCleanText(reportInput.claimRef, 500, "claimRef"),
    newHeadSha:
      reportInput.newHeadSha === undefined
        ? undefined
        : cleanText(reportInput.newHeadSha, 40, "newHeadSha").toLowerCase(),
    coverageComplete: reportInput.coverageComplete === true,
    retryAllowed: reportInput.retryAllowed === true,
    testsPassed: reportInput.testsPassed === true,
    publicationConfirmed: reportInput.publicationConfirmed === true,
    verificationComplete: reportInput.verificationComplete === true,
    fixerModel: optionalCleanText(reportInput.fixerModel, 100, "fixerModel"),
    fixerAttested: reportInput.fixerAttested === true,
    fixerAttestationRef: optionalCleanText(
      reportInput.fixerAttestationRef,
      500,
      "fixerAttestationRef",
    ),
    fixerFallbackReason: optionalCleanText(
      reportInput.fixerFallbackReason,
      500,
      "fixerFallbackReason",
    ),
    fixerPrimaryFailureRef: optionalCleanText(
      reportInput.fixerPrimaryFailureRef,
      500,
      "fixerPrimaryFailureRef",
    ),
    findings: sanitizeFindings(reportInput.findings ?? []),
  };
  assertWorkerReportMatches(state, report, callerSessionKey);
  if (
    report.kind === "review" &&
    ["approved", "changes_requested"].includes(report.outcome) &&
    report.baseSha !== state.baseSha
  ) {
    throw new Error("worker review result is not bound to the current reviewed base");
  }
  if (state.orphanedWorker) {
    throw new Error("worker_report_has_unreconciled_orphan");
  }
  const cleared = {
    ...state,
    ...(state.phase === PHASE.BLOCKED &&
    state.blocker === "worker_launch_outcome_unknown" &&
    report.kind === "review"
      ? { phase: PHASE.REVIEW_RUNNING, blocker: null, wait: null }
      : {}),
    activeWorker: null,
    infrastructureRetryCount: 0,
    infrastructureRetryAt: null,
    infrastructureLastFailure: null,
    orphanedWorker: { ...state.activeWorker, launchOutcome: state.launchOutcome ?? null },
    updatedAt: now,
  };

  if (report.kind === "review") {
    if (report.outcome === "waiting_review") {
      const next = {
        ...cleared,
        phase: PHASE.REVIEW_WAITING,
        wait: {
          kind: "mergeguez_review",
          headSha: state.headSha,
          reviewId: report.reviewId ?? null,
          claimRef: report.claimRef ?? null,
          since: now,
        },
        blocker: null,
      };
      return { changed: true, state: next, effect: "wait", reason: "review_in_progress" };
    }
    if (
      new Set(["approved", "changes_requested", "failed_retryable", "failed_terminal"]).has(
        report.outcome,
      )
    ) {
      return applyReviewResult(
        cleared,
        {
          eventId: `worker:${state.activeWorker.runId ?? state.activeWorker.sessionKey}:${report.outcome}`,
          repo: state.repo,
          prNumber: state.prNumber,
          headSha: state.headSha,
          baseSha: report.baseSha ?? state.baseSha,
          outcome: report.outcome,
          reviewId: report.reviewId,
          coverageComplete: report.coverageComplete,
          retryAllowed: report.retryAllowed,
          findings: report.findings,
          summary: report.summary,
        },
        now,
      );
    }
    return blockState(cleared, `unsupported_review_worker_outcome:${report.outcome}`, now);
  }

  if (report.kind !== "remediation") {
    throw new Error("worker report kind is invalid");
  }
  if (report.outcome === "fixed_and_published") {
    const fixerAttestation = fixerAttestationFromReport(state, report, now);
    if (
      !report.testsPassed ||
      !report.publicationConfirmed ||
      !isSha(report.newHeadSha) ||
      !fixerAttestation
    ) {
      return blockState(cleared, "remediation_missing_test_or_publication_evidence", now);
    }
    if (report.newHeadSha === state.headSha) {
      return blockState(cleared, "published_head_did_not_change", now);
    }
    const nextCycle = state.cycle + 1;
    if (nextCycle > state.maxCycles) {
      return blockState(cleared, "review_fix_cycle_budget_exhausted", now);
    }
    const next = {
      ...cleared,
      headSha: report.newHeadSha,
      phase: PHASE.REVIEW_QUEUED,
      cycle: nextCycle,
      retryCount: 0,
      cycleStartedAt: now,
      deadlineAt: Number.isInteger(state.wallTimeMinutes)
        ? now + state.wallTimeMinutes * 60_000
        : state.deadlineAt,
      review: null,
      findings: [],
      fixerAttestation,
      wait: null,
      blocker: null,
    };
    return { changed: true, state: next, effect: "continue", reason: "new_head_published" };
  }
  if (report.outcome === "re_review_same_head") {
    const fixerAttestation = fixerAttestationFromReport(state, report, now);
    if (!report.verificationComplete || !fixerAttestation) {
      return blockState(cleared, "same_head_rereview_without_verification", now);
    }
    const nextCycle = state.cycle + 1;
    if (nextCycle > state.maxCycles) {
      return blockState(cleared, "review_fix_cycle_budget_exhausted", now);
    }
    return {
      changed: true,
      state: {
        ...cleared,
        phase: PHASE.REVIEW_QUEUED,
        cycle: nextCycle,
        retryCount: 0,
        cycleStartedAt: now,
        deadlineAt: Number.isInteger(state.wallTimeMinutes)
          ? now + state.wallTimeMinutes * 60_000
          : state.deadlineAt,
        fixerAttestation,
        wait: null,
        blocker: null,
      },
      effect: "continue",
      reason: "same_head_rereview",
    };
  }
  if (report.outcome === "stale_head") {
    return {
      changed: true,
      state: {
        ...cleared,
        phase: PHASE.WAITING_HEAD_EVENT,
        wait: { kind: "pull_request_head", since: now },
        blocker: null,
      },
      effect: "wait",
      reason: "stale_head",
    };
  }
  if (report.outcome === "ambiguous_publication") {
    return blockState(cleared, "ambiguous_publication_requires_reconciliation", now);
  }
  return blockState(cleared, report.summary ?? `remediation_blocked:${report.outcome}`, now);
}

export function applyWorkerFailure(state, callerSessionKey, reason, now = Date.now()) {
  if (!state.activeWorker || state.activeWorker.sessionKey !== callerSessionKey) {
    return { changed: false, state, effect: "none", reason: "stale_worker_failure" };
  }
  const kind = state.activeWorker.kind;
  const normalizedReason = cleanText(reason, 500, "reason");
  if (state.orphanedWorker) {
    throw new Error("worker_failure_has_multiple_unreconciled_workers");
  }
  const cleared = {
    ...state,
    orphanedWorker: { ...state.activeWorker, launchOutcome: state.launchOutcome ?? null },
    activeWorker: null,
    launchOutcome: null,
    updatedAt: now,
  };
  if (classifyWorkerFailure(normalizedReason) === "infrastructure") {
    const attempt = Math.max(0, Number(state.infrastructureRetryCount) || 0) + 1;
    if (attempt > MAX_INFRASTRUCTURE_RETRIES) {
      return blockState(cleared, `infrastructure_retry_exhausted:${normalizedReason}`, now);
    }
    const retryAt = now + infrastructureBackoffMs(attempt);
    return {
      changed: true,
      state: {
        ...cleared,
        phase: retryPhase(state, kind),
        infrastructureRetryCount: attempt,
        infrastructureRetryAt: retryAt,
        infrastructureLastFailure: normalizedReason,
        orphanedWorker: {
          ...cleared.orphanedWorker,
          reason: normalizedReason,
          clearedAt: now,
        },
        wait: {
          kind: "infrastructure_backoff",
          reason: normalizedReason,
          attempt,
          retryAt,
        },
        blocker: null,
      },
      effect: "wait",
      reason: "retry_infrastructure",
    };
  }
  if (state.retryCount >= state.maxRetries || now > state.deadlineAt) {
    return blockState(cleared, `worker_failure_exhausted:${normalizedReason}`, now);
  }
  return {
    changed: true,
    state: {
      ...cleared,
      phase: retryPhase(state, kind),
      retryCount: state.retryCount + 1,
      wait: null,
      blocker: null,
    },
    effect: "continue",
    reason: "retry_worker",
  };
}

export function recoverState(
  state,
  workerTask,
  now = Date.now(),
  reservationGraceMs = 120_000,
  extras = {},
) {
  if (isTerminalState(state)) {
    return { changed: false, state, effect: "none", reason: "not_recoverable" };
  }
  if (state.phase === PHASE.BLOCKED) {
    if (
      state.blocker === "findings_unusable" ||
      state.blocker === "changes_requested_without_actionable_paths"
    ) {
      return { changed: false, state, effect: "none", reason: "not_recoverable" };
    }
    const infrastructureReason = infrastructureReasonFromBlocker(state.blocker);
    if (!infrastructureReason) {
      return { changed: false, state, effect: "none", reason: "not_recoverable" };
    }
    if (retryPhase(state) === PHASE.REMEDIATION_QUEUED && !findingsAreActionable(state.findings)) {
      return blockState(state, "findings_unusable", now);
    }
    const attempt = Math.max(1, Number(state.infrastructureRetryCount) || 0);
    const retryAt = now + infrastructureBackoffMs(attempt);
    return {
      changed: true,
      state: {
        ...state,
        phase: retryPhase(state),
        activeWorker: null,
        retryCount: 0,
        infrastructureRetryCount: attempt,
        infrastructureRetryAt: retryAt,
        infrastructureLastFailure: infrastructureReason,
        wait: {
          kind: "infrastructure_backoff",
          reason: infrastructureReason,
          attempt,
          retryAt,
        },
        blocker: null,
        updatedAt: now,
      },
      effect: "wait",
      reason: "legacy_infrastructure_block_requeued",
    };
  }
  if (!state.activeWorker) {
    if (state.phase === PHASE.MERGE_QUEUED) {
      return { changed: false, state, effect: "continue", reason: "queued_merge" };
    }
    if (workerKindForPhase(state.phase)) {
      const retryAt = Number.isFinite(state.infrastructureRetryAt)
        ? state.infrastructureRetryAt
        : null;
      if (Number.isFinite(retryAt) && retryAt > now) {
        return { changed: false, state, effect: "wait", reason: "infrastructure_backoff" };
      }
      if (Number.isFinite(retryAt)) {
        return {
          changed: true,
          state: {
            ...state,
            infrastructureRetryAt: null,
            wait: null,
            updatedAt: now,
          },
          effect: "continue",
          reason: "infrastructure_backoff_elapsed",
        };
      }
      return { changed: false, state, effect: "continue", reason: "queued_step" };
    }
    if (state.phase === PHASE.REVIEW_WAITING) {
      if (state.retryCount >= state.maxRetries || now > state.deadlineAt) {
        return blockState(state, "review_wait_reconciliation_budget_exhausted", now);
      }
      return {
        changed: true,
        state: {
          ...state,
          phase: PHASE.REVIEW_QUEUED,
          retryCount: state.retryCount + 1,
          wait: null,
          blocker: null,
          updatedAt: now,
        },
        effect: "continue",
        reason: "review_wait_reconcile",
      };
    }
    return { changed: false, state, effect: "wait", reason: "external_wait" };
  }
  if (workerTask?.status === "unavailable") {
    return { changed: false, state, effect: "hold", reason: "worker_observation_unavailable" };
  }
  const reservedAt = Number(state.activeWorker.reservedAt) || 0;
  const age = now - reservedAt;
  if (workerTask && new Set(["queued", "running"]).has(workerTask.status)) {
    const processStartedAt = Number(extras.processStartedAt);
    const sessionAlive = extras.sessionAlive;
    if (Number.isFinite(processStartedAt) && reservedAt < processStartedAt - 5_000) {
      return applyWorkerFailure(
        state,
        state.activeWorker.sessionKey,
        "worker_lost_after_process_restart",
        now,
      );
    }
    if (sessionAlive !== true && age >= reservationGraceMs) {
      return applyWorkerFailure(
        state,
        state.activeWorker.sessionKey,
        sessionAlive === false ? "worker_session_missing" : "worker_session_liveness_unknown",
        now,
      );
    }
    return {
      changed: false,
      state,
      effect: "wait",
      reason: sessionAlive === true ? "worker_active" : "worker_session_liveness_grace",
    };
  }
  if (!workerTask && age < reservationGraceMs) {
    return { changed: false, state, effect: "wait", reason: "worker_start_grace" };
  }
  if (!workerTask && (state.activeWorker.runId || state.activeWorker.taskId)) {
    return { changed: false, state, effect: "wait", reason: "worker_run_observation_missing" };
  }
  if (workerTask?.status === "succeeded") {
    if (state.activeWorker.kind === "remediation" && !findingsAreActionable(state.findings)) {
      return blockState(state, "findings_unusable", now);
    }
    return applyWorkerFailure(
      state,
      state.activeWorker.sessionKey,
      "worker_completed_without_structured_report",
      now,
    );
  }
  if (workerTask && new Set(["failed", "timed_out", "cancelled", "lost"]).has(workerTask.status)) {
    const detail =
      typeof workerTask.error === "string" && workerTask.error.trim()
        ? workerTask.error.trim().slice(0, 300)
        : workerTask.status;
    return applyWorkerFailure(
      state,
      state.activeWorker.sessionKey,
      `worker_execution_failed:${detail}`,
      now,
    );
  }
  return applyWorkerFailure(state, state.activeWorker.sessionKey, "worker_not_active", now);
}

// oxlint-disable-next-line default-param-last -- Existing plugin API keeps the trailing event id stable.
export function blockState(state, reason, now = Date.now(), eventId) {
  if (state.activeWorker && state.orphanedWorker) {
    // A single orphan slot cannot represent two live runs. Preserve the
    // original state rather than silently dropping either worker identity.
    throw new Error("block_has_multiple_unreconciled_workers");
  }
  const next = appendSeenEvent(
    {
      ...state,
      phase: PHASE.BLOCKED,
      orphanedWorker: state.activeWorker
        ? { ...state.activeWorker, launchOutcome: state.launchOutcome ?? null }
        : (state.orphanedWorker ?? null),
      activeWorker: null,
      wait: { kind: "manual_intervention", since: now },
      blocker: cleanText(reason, 1000, "blocker"),
      mergeReady: null,
      updatedAt: now,
    },
    eventId,
  );
  return { changed: true, state: next, effect: "blocked", reason: next.blocker };
}

export function flowMatches(state, repo, prNumber) {
  return isLifecycleState(state) && state.repo === repo && state.prNumber === prNumber;
}
